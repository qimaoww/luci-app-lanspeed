use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs, io,
    io::Read,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

const AF_BRIDGE: u8 = 7;
const NLMSG_HEADER_LEN: usize = 16;
const NDMSG_LEN: usize = 12;
const BRFORWARD_RECORD_LEN: usize = 16;
const RTM_NEWNEIGH: u16 = 28;
const RTM_DELNEIGH: u16 = 29;
const RTM_GETNEIGH: u16 = 30;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NDA_LLADDR: u16 = 2;
const NDA_VLAN: u16 = 5;
const NDA_IFINDEX: u16 = 8;
const NDA_MASTER: u16 = 9;
const NDA_FLAGS_EXT: u16 = 15;
const NLA_TYPE_MASK: u16 = 0x3fff;
const NTF_SELF: u8 = 0x02;
const NUD_PERMANENT: u16 = 0x80;
const MAX_DUMP_BYTES: usize = 4 * 1024 * 1024;
const MAX_RAW_FDB_ENTRIES: usize = 65_536;
const RTMGRP_NEIGH: u32 = 4;

/// Non-blocking bridge-neighbor event monitor. Events only mark the cached
/// topology dirty; callers still perform a complete, integrity-checked dump
/// before replacing attachment state.
#[derive(Debug)]
pub struct BridgeFdbEventMonitor {
    socket: OwnedFd,
}

impl BridgeFdbEventMonitor {
    pub fn open() -> io::Result<Self> {
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let mut local = SockAddrNl::new();
        local.groups = RTMGRP_NEIGH;
        syscall_zero(unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&local as *const SockAddrNl).cast(),
                size_of::<SockAddrNl>() as libc::socklen_t,
            )
        })?;
        Ok(Self { socket })
    }

    /// Returns true for a bridge FDB mutation or any loss/malformed condition.
    /// Loss is deliberately fail-safe: the next action is a full dump.
    pub fn topology_changed(&mut self) -> io::Result<bool> {
        let mut changed = false;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let received = unsafe {
                libc::recv(
                    self.socket.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error
                    .raw_os_error()
                    .is_some_and(|code| code == libc::EAGAIN || code == libc::EWOULDBLOCK)
                {
                    return Ok(changed);
                }
                if error.raw_os_error() == Some(libc::ENOBUFS) {
                    return Ok(true);
                }
                return Err(error);
            }
            if received == 0 || received as usize > buffer.len() {
                return Ok(true);
            }
            changed |= bridge_event_datagram_changed(&buffer[..received as usize]);
        }
    }
}

fn bridge_event_datagram_changed(bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let Some(length) = read_u32(bytes, offset).map(|value| value as usize) else {
            return true;
        };
        if length < NLMSG_HEADER_LEN || length > bytes.len() - offset {
            return true;
        }
        let kind = read_u16(bytes, offset + 4).unwrap_or_default();
        let flags = read_u16(bytes, offset + 6).unwrap_or_default();
        if kind == NLMSG_OVERRUN || flags & NLM_F_DUMP_INTR != 0 {
            return true;
        }
        if matches!(kind, RTM_NEWNEIGH | RTM_DELNEIGH) {
            let payload = &bytes[offset + NLMSG_HEADER_LEN..offset + length];
            if payload.first().copied() == Some(AF_BRIDGE) {
                return true;
            }
        }
        let aligned = align4(length);
        if aligned > bytes.len() - offset {
            return true;
        }
        offset += aligned;
    }
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdbSource {
    Rtnetlink,
    BridgeForward,
}

impl FdbSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rtnetlink => "rtnetlink_af_bridge",
            Self::BridgeForward => "sysfs_brforward_fallback",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FdbEntry {
    pub mac: [u8; 6],
    pub port_ifindex: u32,
    pub bridge_ifindex: Option<u32>,
    pub vlan_id: Option<u16>,
    pub state: u16,
    pub flags: u8,
    pub flags_ext: u32,
    pub entry_type: u8,
    pub local: bool,
    pub ageing_timer: Option<u32>,
}

impl FdbEntry {
    pub const fn is_local(&self) -> bool {
        self.local || self.flags & NTF_SELF != 0
    }

    pub const fn is_permanent(&self) -> bool {
        self.state & NUD_PERMANENT != 0
    }

    pub fn has_unicast_mac(&self) -> bool {
        self.mac != [0; 6] && self.mac != [0xff; 6] && self.mac[0] & 1 == 0
    }

    /// Conservative client filter. Static/permanent and local bridge entries
    /// cannot prove a currently attached client and are kept out of topology.
    pub fn is_client_candidate(&self) -> bool {
        self.has_unicast_mac() && !self.is_local() && !self.is_permanent()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeFdbSnapshot {
    pub bridge: String,
    pub bridge_ifindex: u32,
    pub entries: Vec<FdbEntry>,
    pub source: FdbSource,
    /// True only for a completed, non-interrupted rtnetlink dump.
    pub complete: bool,
    pub degraded_reason: Option<String>,
}

pub trait BridgeFdbProvider {
    fn dump_bridge(&mut self, bridge: &str, max_entries: usize) -> io::Result<BridgeFdbSnapshot>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemBridgeFdbProvider;

impl BridgeFdbProvider for SystemBridgeFdbProvider {
    fn dump_bridge(&mut self, bridge: &str, max_entries: usize) -> io::Result<BridgeFdbSnapshot> {
        read_bridge_fdb(bridge, max_entries)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum FdbParseError {
    TruncatedHeader,
    InvalidMessageLength(u32),
    TruncatedNeighbor,
    InvalidAttribute,
    DumpInterrupted,
    Overrun,
    Kernel(i32),
    EntryLimitExceeded,
}

impl fmt::Display for FdbParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => formatter.write_str("truncated rtnetlink message header"),
            Self::InvalidMessageLength(length) => {
                write!(formatter, "invalid rtnetlink message length {length}")
            }
            Self::TruncatedNeighbor => formatter.write_str("truncated bridge neighbor message"),
            Self::InvalidAttribute => formatter.write_str("invalid bridge neighbor attribute"),
            Self::DumpInterrupted => formatter.write_str("rtnetlink FDB dump was interrupted"),
            Self::Overrun => formatter.write_str("rtnetlink FDB dump overrun"),
            Self::Kernel(error) => write!(formatter, "rtnetlink kernel error {error}"),
            Self::EntryLimitExceeded => formatter.write_str("bridge FDB entry limit exceeded"),
        }
    }
}

impl std::error::Error for FdbParseError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedFdbMessages {
    pub entries: Vec<FdbEntry>,
    pub done: bool,
}

/// Parse one rtnetlink datagram. Multipart completeness is reported through
/// `done`; callers must discard all accumulated entries unless DONE is seen.
pub fn parse_bridge_fdb_messages(
    bytes: &[u8],
    expected_sequence: u32,
    max_entries: usize,
) -> Result<ParsedFdbMessages, FdbParseError> {
    if bytes.is_empty() {
        return Ok(ParsedFdbMessages::default());
    }
    if bytes.len() < NLMSG_HEADER_LEN {
        return Err(FdbParseError::TruncatedHeader);
    }

    let mut parsed = ParsedFdbMessages::default();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < NLMSG_HEADER_LEN {
            return Err(FdbParseError::TruncatedHeader);
        }
        let message_len = read_u32(bytes, offset).ok_or(FdbParseError::TruncatedHeader)?;
        let message_len_usize = message_len as usize;
        if message_len_usize < NLMSG_HEADER_LEN || message_len_usize > bytes.len() - offset {
            return Err(FdbParseError::InvalidMessageLength(message_len));
        }
        let message_type = read_u16(bytes, offset + 4).unwrap_or_default();
        let flags = read_u16(bytes, offset + 6).unwrap_or_default();
        let sequence = read_u32(bytes, offset + 8).unwrap_or_default();
        if sequence == expected_sequence {
            if flags & NLM_F_DUMP_INTR != 0 {
                return Err(FdbParseError::DumpInterrupted);
            }
            let payload = &bytes[offset + NLMSG_HEADER_LEN..offset + message_len_usize];
            match message_type {
                NLMSG_ERROR => {
                    let error = read_i32(payload, 0)
                        .ok_or(FdbParseError::InvalidMessageLength(message_len))?;
                    if error != 0 {
                        return Err(FdbParseError::Kernel(error));
                    }
                }
                NLMSG_DONE => {
                    if !payload.is_empty() && payload.len() < 4 {
                        return Err(FdbParseError::InvalidMessageLength(message_len));
                    }
                    if payload.len() >= 4 {
                        let error = read_i32(payload, 0)
                            .ok_or(FdbParseError::InvalidMessageLength(message_len))?;
                        if error != 0 {
                            return Err(FdbParseError::Kernel(error));
                        }
                    }
                    parsed.done = true;
                    break;
                }
                NLMSG_OVERRUN => return Err(FdbParseError::Overrun),
                RTM_NEWNEIGH => {
                    if let Some(entry) = parse_fdb_entry(payload)? {
                        if parsed.entries.len() == max_entries {
                            return Err(FdbParseError::EntryLimitExceeded);
                        }
                        parsed.entries.push(entry);
                    }
                }
                _ => {}
            }
        }
        offset = advance_message(bytes, offset, message_len, message_len_usize)?;
    }
    Ok(parsed)
}

fn parse_fdb_entry(payload: &[u8]) -> Result<Option<FdbEntry>, FdbParseError> {
    if payload.len() < NDMSG_LEN {
        return Err(FdbParseError::TruncatedNeighbor);
    }
    if payload[0] != AF_BRIDGE {
        return Ok(None);
    }
    let mut port_ifindex = read_i32(payload, 4).ok_or(FdbParseError::TruncatedNeighbor)?;
    let state = read_u16(payload, 8).ok_or(FdbParseError::TruncatedNeighbor)?;
    let flags = payload[10];
    let entry_type = payload[11];
    let mut mac = None;
    let mut vlan_id = None;
    let mut bridge_ifindex = None;
    let mut flags_ext = 0u32;

    let mut offset = NDMSG_LEN;
    while offset < payload.len() {
        if payload.len() - offset < 4 {
            return Err(FdbParseError::InvalidAttribute);
        }
        let length = read_u16(payload, offset).ok_or(FdbParseError::InvalidAttribute)? as usize;
        let kind =
            read_u16(payload, offset + 2).ok_or(FdbParseError::InvalidAttribute)? & NLA_TYPE_MASK;
        if length < 4 || length > payload.len() - offset {
            return Err(FdbParseError::InvalidAttribute);
        }
        let value = &payload[offset + 4..offset + length];
        match kind {
            NDA_LLADDR => {
                mac = Some(<[u8; 6]>::try_from(value).map_err(|_| FdbParseError::InvalidAttribute)?)
            }
            NDA_VLAN => {
                vlan_id = Some(read_exact_u16(value).ok_or(FdbParseError::InvalidAttribute)?)
            }
            NDA_IFINDEX => {
                port_ifindex = read_exact_i32(value).ok_or(FdbParseError::InvalidAttribute)?
            }
            NDA_MASTER => {
                bridge_ifindex = Some(read_exact_u32(value).ok_or(FdbParseError::InvalidAttribute)?)
            }
            NDA_FLAGS_EXT => {
                flags_ext = read_exact_u32(value).ok_or(FdbParseError::InvalidAttribute)?
            }
            _ => {}
        }
        let next = offset.saturating_add(align4(length));
        if next > payload.len() {
            return Err(FdbParseError::InvalidAttribute);
        }
        offset = next;
    }

    let Some(mac) = mac else {
        return Ok(None);
    };
    let Ok(port_ifindex) = u32::try_from(port_ifindex) else {
        return Ok(None);
    };
    if port_ifindex == 0 {
        return Ok(None);
    }
    Ok(Some(FdbEntry {
        mac,
        port_ifindex,
        bridge_ifindex,
        vlan_id,
        state,
        flags,
        flags_ext,
        entry_type,
        local: flags & NTF_SELF != 0,
        ageing_timer: None,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeForwardRecord {
    pub mac: [u8; 6],
    pub port_no: u16,
    pub local: bool,
    pub ageing_timer: u32,
}

pub fn parse_bridge_forward_records(
    bytes: &[u8],
    max_entries: usize,
) -> io::Result<Vec<BridgeForwardRecord>> {
    if bytes.len() % BRFORWARD_RECORD_LEN != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bridge brforward file has a partial record",
        ));
    }
    let count = bytes.len() / BRFORWARD_RECORD_LEN;
    if count > max_entries {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bridge brforward entry limit exceeded",
        ));
    }
    bytes
        .chunks_exact(BRFORWARD_RECORD_LEN)
        .map(|record| {
            let mac = <[u8; 6]>::try_from(&record[..6])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid brforward MAC"))?;
            Ok(BridgeForwardRecord {
                mac,
                port_no: u16::from(record[6]) | (u16::from(record[12]) << 8),
                local: record[7] != 0,
                ageing_timer: u32::from_ne_bytes(
                    record[8..12]
                        .try_into()
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid timer"))?,
                ),
            })
        })
        .collect()
}

pub fn read_bridge_fdb(bridge: &str, max_entries: usize) -> io::Result<BridgeFdbSnapshot> {
    validate_bridge_name(bridge)?;
    if max_entries == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bridge FDB max_entries must be non-zero",
        ));
    }
    match read_rtnetlink_bridge_fdb(bridge, max_entries) {
        Ok(snapshot) => Ok(snapshot),
        Err(netlink_error) => match read_brforward_bridge_fdb(Path::new("/sys/class/net"), bridge, max_entries) {
            Ok(mut snapshot) => {
                snapshot.degraded_reason = Some(format!(
                    "rtnetlink_failed_brforward_fallback: {netlink_error}"
                ));
                Ok(snapshot)
            }
            Err(fallback_error) => Err(io::Error::new(
                fallback_error.kind(),
                format!(
                    "bridge FDB rtnetlink failed ({netlink_error}); brforward fallback failed ({fallback_error})"
                ),
            )),
        },
    }
}

fn read_rtnetlink_bridge_fdb(bridge: &str, max_entries: usize) -> io::Result<BridgeFdbSnapshot> {
    let sysfs_root = Path::new("/sys/class/net");
    let bridge_ifindex = read_ifindex(&sysfs_root.join(bridge).join("ifindex"))?;
    let bridge_ports = read_bridge_ports(sysfs_root, bridge)?;
    let raw_limit = max_entries
        .saturating_mul(8)
        .max(4_096)
        .min(MAX_RAW_FDB_ENTRIES);
    let mut entries = read_all_rtnetlink_fdb(raw_limit)?;
    entries.retain(|entry| {
        entry.bridge_ifindex == Some(bridge_ifindex)
            || entry.port_ifindex == bridge_ifindex
            || bridge_ports.contains(&entry.port_ifindex)
    });
    entries.sort();
    entries.dedup();
    if entries.len() > max_entries {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bridge FDB entry limit exceeded",
        ));
    }
    Ok(BridgeFdbSnapshot {
        bridge: bridge.to_owned(),
        bridge_ifindex,
        entries,
        source: FdbSource::Rtnetlink,
        complete: true,
        degraded_reason: None,
    })
}

fn read_all_rtnetlink_fdb(max_entries: usize) -> io::Result<Vec<FdbEntry>> {
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let local = SockAddrNl::new();
    syscall_zero(unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&local as *const SockAddrNl).cast(),
            size_of::<SockAddrNl>() as libc::socklen_t,
        )
    })?;
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    syscall_zero(unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    })?;

    let sequence = monotonic_sequence();
    let request = bridge_fdb_dump_request(sequence);
    let kernel = SockAddrNl::new();
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&kernel as *const SockAddrNl).cast(),
            size_of::<SockAddrNl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != request.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short bridge FDB rtnetlink request",
        ));
    }

    let mut entries = Vec::new();
    let mut total_bytes = 0usize;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let mut sender = SockAddrNl::new();
        let mut sender_len = size_of::<SockAddrNl>() as libc::socklen_t;
        let received = unsafe {
            libc::recvfrom(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
                (&mut sender as *mut SockAddrNl).cast(),
                &mut sender_len,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "rtnetlink FDB dump ended before NLMSG_DONE",
            ));
        }
        let received = received as usize;
        if received > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rtnetlink FDB datagram was truncated",
            ));
        }
        if sender_len < size_of::<SockAddrNl>() as libc::socklen_t
            || sender.family != libc::AF_NETLINK as u16
            || sender.pid != 0
        {
            continue;
        }
        total_bytes = total_bytes.saturating_add(received);
        if total_bytes > MAX_DUMP_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rtnetlink FDB dump exceeds byte limit",
            ));
        }
        let remaining = max_entries.saturating_sub(entries.len());
        let parsed = parse_bridge_fdb_messages(&buffer[..received], sequence, remaining)
            .map_err(parse_error_to_io)?;
        entries.extend(parsed.entries);
        if parsed.done {
            return Ok(entries);
        }
    }
}

fn read_brforward_bridge_fdb(
    sysfs_root: &Path,
    bridge: &str,
    max_entries: usize,
) -> io::Result<BridgeFdbSnapshot> {
    let bridge_root = sysfs_root.join(bridge);
    let bridge_ifindex = read_ifindex(&bridge_root.join("ifindex"))?;
    let port_map = read_bridge_port_numbers(sysfs_root, bridge)?;
    let max_bytes = max_entries
        .checked_mul(BRFORWARD_RECORD_LEN)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "FDB limit overflow"))?;
    let bytes = read_limited(&bridge_root.join("brforward"), max_bytes)?;
    let records = parse_bridge_forward_records(&bytes, max_entries)?;
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        let port_ifindex = if record.local {
            port_map
                .get(&record.port_no)
                .copied()
                .unwrap_or(bridge_ifindex)
        } else {
            port_map.get(&record.port_no).copied().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "brforward port {} has no bridge-port mapping",
                        record.port_no
                    ),
                )
            })?
        };
        entries.push(FdbEntry {
            mac: record.mac,
            port_ifindex,
            bridge_ifindex: Some(bridge_ifindex),
            vlan_id: None,
            state: if record.local { NUD_PERMANENT } else { 0 },
            flags: if record.local { NTF_SELF } else { 0 },
            flags_ext: 0,
            entry_type: 0,
            local: record.local,
            ageing_timer: Some(record.ageing_timer),
        });
    }
    Ok(BridgeFdbSnapshot {
        bridge: bridge.to_owned(),
        bridge_ifindex,
        entries,
        source: FdbSource::BridgeForward,
        // brforward has no VLAN, dump-integrity or ASIC-completeness signal.
        complete: false,
        degraded_reason: Some("legacy_brforward_has_no_completeness_proof".to_owned()),
    })
}

fn read_bridge_ports(sysfs_root: &Path, bridge: &str) -> io::Result<BTreeSet<u32>> {
    Ok(read_bridge_port_numbers(sysfs_root, bridge)?
        .into_values()
        .collect())
}

fn read_bridge_port_numbers(sysfs_root: &Path, bridge: &str) -> io::Result<BTreeMap<u16, u32>> {
    let mut ports = BTreeMap::new();
    let brif = sysfs_root.join(bridge).join("brif");
    for entry in fs::read_dir(brif)? {
        let entry = entry?;
        let root = entry.path();
        let port_no = parse_port_number(&fs::read_to_string(root.join("port_no"))?)?;
        let ifindex = read_ifindex(&sysfs_root.join(entry.file_name()).join("ifindex"))?;
        if ports.insert(port_no, ifindex).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate bridge port number",
            ));
        }
    }
    Ok(ports)
}

fn parse_port_number(value: &str) -> io::Result<u16> {
    let value = value.trim();
    let parsed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(|| value.parse::<u16>(), |hex| u16::from_str_radix(hex, 16))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(parsed)
}

fn read_ifindex(path: &Path) -> io::Result<u32> {
    let value = fs::read_to_string(path)?
        .trim()
        .parse::<u32>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if value == 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "interface index must be non-zero",
        ))
    } else {
        Ok(value)
    }
}

fn read_limited(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file limit overflow"))?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bridge brforward entry limit exceeded",
        ));
    }
    Ok(bytes)
}

fn validate_bridge_name(bridge: &str) -> io::Result<()> {
    if bridge.is_empty()
        || bridge == "."
        || bridge == ".."
        || bridge.as_bytes().contains(&b'/')
        || bridge.as_bytes().contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid bridge interface name",
        ));
    }
    Ok(())
}

#[repr(C)]
struct SockAddrNl {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

impl SockAddrNl {
    const fn new() -> Self {
        Self {
            family: libc::AF_NETLINK as u16,
            pad: 0,
            pid: 0,
            groups: 0,
        }
    }
}

fn bridge_fdb_dump_request(sequence: u32) -> [u8; NLMSG_HEADER_LEN + NDMSG_LEN] {
    let mut request = [0u8; NLMSG_HEADER_LEN + NDMSG_LEN];
    let request_len = request.len() as u32;
    request[..4].copy_from_slice(&request_len.to_ne_bytes());
    request[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    request[NLMSG_HEADER_LEN] = AF_BRIDGE;
    request
}

fn monotonic_sequence() -> u32 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } == 0 {
        (now.tv_sec as u64 ^ now.tv_nsec as u64) as u32
    } else {
        0
    }
}

fn syscall_zero(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn parse_error_to_io(error: FdbParseError) -> io::Error {
    match error {
        FdbParseError::Kernel(error) if error < 0 => {
            io::Error::from_raw_os_error(error.checked_neg().unwrap_or(libc::EINVAL))
        }
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

fn advance_message(
    bytes: &[u8],
    offset: usize,
    message_len: u32,
    message_len_usize: usize,
) -> Result<usize, FdbParseError> {
    let aligned = align4(message_len_usize);
    if aligned > bytes.len() - offset {
        if message_len_usize == bytes.len() - offset {
            return Ok(bytes.len());
        }
        return Err(FdbParseError::InvalidMessageLength(message_len));
    }
    Ok(offset + aligned)
}

const fn align4(value: usize) -> usize {
    value.saturating_add(3) & !3
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_exact_u16(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 2 {
        return None;
    }
    Some(u16::from_ne_bytes(bytes.try_into().ok()?))
}

fn read_exact_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.len() != 4 {
        return None;
    }
    Some(u32::from_ne_bytes(bytes.try_into().ok()?))
}

fn read_exact_i32(bytes: &[u8]) -> Option<i32> {
    if bytes.len() != 4 {
        return None;
    }
    Some(i32::from_ne_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let mut bytes = Vec::from((length as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(align4(length), 0);
        bytes
    }

    fn message(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let mut bytes = Vec::from((length as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize(align4(length), 0);
        bytes
    }

    fn neighbor(sequence: u32) -> Vec<u8> {
        let mut payload = vec![0u8; NDMSG_LEN];
        payload[0] = AF_BRIDGE;
        payload[4..8].copy_from_slice(&7i32.to_ne_bytes());
        payload[8..10].copy_from_slice(&2u16.to_ne_bytes());
        payload.extend(attribute(NDA_LLADDR, &[0x02, 1, 2, 3, 4, 5]));
        payload.extend(attribute(NDA_VLAN, &123u16.to_ne_bytes()));
        payload.extend(attribute(NDA_MASTER, &11u32.to_ne_bytes()));
        payload.extend(attribute(NDA_FLAGS_EXT, &0x20u32.to_ne_bytes()));
        message(RTM_NEWNEIGH, 0, sequence, &payload)
    }

    #[test]
    fn bridge_dump_request_has_stable_wire_layout() {
        let request = bridge_fdb_dump_request(0x1234_5678);
        assert_eq!(request.len(), 28);
        assert_eq!(read_u32(&request, 0), Some(28));
        assert_eq!(read_u16(&request, 4), Some(RTM_GETNEIGH));
        assert_eq!(read_u16(&request, 6), Some(NLM_F_REQUEST | NLM_F_DUMP));
        assert_eq!(read_u32(&request, 8), Some(0x1234_5678));
        assert_eq!(request[NLMSG_HEADER_LEN], AF_BRIDGE);
    }

    #[test]
    fn parses_vlan_master_and_extended_flags_from_completed_dump() {
        let sequence = 9;
        let mut bytes = neighbor(sequence);
        bytes.extend(message(NLMSG_DONE, 0, sequence, &[]));
        let parsed = parse_bridge_fdb_messages(&bytes, sequence, 8).unwrap();
        assert!(parsed.done);
        assert_eq!(parsed.entries.len(), 1);
        let entry = &parsed.entries[0];
        assert_eq!(entry.mac, [0x02, 1, 2, 3, 4, 5]);
        assert_eq!(entry.port_ifindex, 7);
        assert_eq!(entry.bridge_ifindex, Some(11));
        assert_eq!(entry.vlan_id, Some(123));
        assert_eq!(entry.flags_ext, 0x20);
        assert!(entry.is_client_candidate());
    }

    #[test]
    fn dump_interrupt_and_overrun_are_fatal() {
        let sequence = 1;
        let interrupted = message(NLMSG_DONE, NLM_F_DUMP_INTR, sequence, &[]);
        assert_eq!(
            parse_bridge_fdb_messages(&interrupted, sequence, 8),
            Err(FdbParseError::DumpInterrupted)
        );
        let overrun = message(NLMSG_OVERRUN, 0, sequence, &[]);
        assert_eq!(
            parse_bridge_fdb_messages(&overrun, sequence, 8),
            Err(FdbParseError::Overrun)
        );
    }

    #[test]
    fn rejects_truncated_neighbor_attribute() {
        let sequence = 1;
        let mut payload = vec![0u8; NDMSG_LEN];
        payload[0] = AF_BRIDGE;
        payload[4..8].copy_from_slice(&7i32.to_ne_bytes());
        payload.extend_from_slice(&8u16.to_ne_bytes());
        payload.extend_from_slice(&NDA_LLADDR.to_ne_bytes());
        payload.extend_from_slice(&[1, 2]);
        let bytes = message(RTM_NEWNEIGH, 0, sequence, &payload);
        assert_eq!(
            parse_bridge_fdb_messages(&bytes, sequence, 8),
            Err(FdbParseError::InvalidAttribute)
        );
    }

    #[test]
    fn parses_legacy_high_port_and_local_flag_without_struct_cast() {
        let mut bytes = [0u8; BRFORWARD_RECORD_LEN];
        bytes[..6].copy_from_slice(&[0x02, 1, 2, 3, 4, 5]);
        bytes[6] = 0x34;
        bytes[7] = 1;
        bytes[8..12].copy_from_slice(&99u32.to_ne_bytes());
        bytes[12] = 0x12;
        let parsed = parse_bridge_forward_records(&bytes, 1).unwrap();
        assert_eq!(
            parsed,
            vec![BridgeForwardRecord {
                mac: [0x02, 1, 2, 3, 4, 5],
                port_no: 0x1234,
                local: true,
                ageing_timer: 99,
            }]
        );
    }

    #[test]
    fn rejects_partial_or_over_limit_legacy_dump() {
        assert_eq!(
            parse_bridge_forward_records(&[0; 15], 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            parse_bridge_forward_records(&[0; 32], 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
