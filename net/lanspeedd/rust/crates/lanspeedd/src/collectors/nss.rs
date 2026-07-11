use crate::{
    collectors::conntrack::aggregate::ClientSample,
    config::RateCollectorMode,
    identity::{ClientIdentity, IdentityTable, MacAddress},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fmt,
    fs::File,
    io::{self, BufRead, BufReader, Read},
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd},
    str::FromStr,
};

pub const ECM_STATE_DEBUGFS_DIR: &str = "/sys/kernel/debug/ecm/ecm_state";
pub const ECM_STATE_DEV_MAJOR_PATH: &str = "/sys/kernel/debug/ecm/ecm_state/state_dev_major";
pub const ECM_STATE_OUTPUT_MASK_PATH: &str =
    "/sys/kernel/debug/ecm/ecm_state/state_file_output_mask";
pub const ECM_STATE_DEV_PATH: &str = "/dev/ecm_state";
pub const ECM_STATE_TMP_DEV_PATH: &str = "/dev/lanspeed-ecm-state";
pub const ECM_STATE_LINE_MAX: usize = 1024;
pub const ECM_STATE_DEFAULT_LINE_LIMIT: usize = 131_072;
pub const ECM_STATE_DEFAULT_CONNECTION_LIMIT: usize = 4_096;
pub const ECM_STATE_DEFAULT_BYTE_LIMIT: usize = ECM_STATE_DEFAULT_LINE_LIMIT * ECM_STATE_LINE_MAX;
pub const ECM_DIRECT_COUNTER_SOURCE: &str = "ecm_state_adv_stats_from_to_data_total";
pub const NSS_DIRECT_SOURCE: &str = "nss_ecm_direct";
pub const NSS_SYNC_PRIMARY_SOURCE: &str = "nss_conntrack_sync";
pub const NSS_SYNC_COLLECTOR_MODE: &str = "conntrack_ecm_sync";

const ECM_STATE_MAJOR_MAX_BYTES: usize = 32;
const ECM_STATE_SERIAL_MAX: usize = 31;
const ECM_STATE_FIELD_MAX: usize = 95;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    pub max_lines: usize,
    pub max_connections: usize,
    pub max_bytes: usize,
}

impl ParseLimits {
    pub const fn new(max_lines: usize, max_connections: usize) -> Self {
        Self {
            max_lines,
            max_connections,
            max_bytes: ECM_STATE_DEFAULT_BYTE_LIMIT,
        }
    }

    pub const fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self::new(
            ECM_STATE_DEFAULT_LINE_LIMIT,
            ECM_STATE_DEFAULT_CONNECTION_LIMIT,
        )
    }
}

#[derive(Debug)]
pub enum NssParseError {
    Io(io::Error),
    ByteLimit(usize),
    LineLimit(usize),
    ConnectionLimit(usize),
}

impl PartialEq for NssParseError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(left), Self::Io(right)) => {
                left.kind() == right.kind() && left.raw_os_error() == right.raw_os_error()
            }
            (Self::ByteLimit(left), Self::ByteLimit(right)) => left == right,
            (Self::LineLimit(left), Self::LineLimit(right)) => left == right,
            (Self::ConnectionLimit(left), Self::ConnectionLimit(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for NssParseError {}

impl fmt::Display for NssParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "failed to read NSS ECM state: {error}"),
            Self::ByteLimit(limit) => {
                write!(formatter, "NSS ECM state exceeded {limit} consumed bytes")
            }
            Self::LineLimit(limit) => {
                write!(formatter, "NSS ECM state exceeded {limit} physical lines")
            }
            Self::ConnectionLimit(limit) => {
                write!(
                    formatter,
                    "NSS ECM state exceeded {limit} connection blocks"
                )
            }
        }
    }
}

impl std::error::Error for NssParseError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DirectStats {
    pub entries_seen: usize,
    pub entries_matched: usize,
    pub skipped_no_arp: usize,
    pub no_lan_flows: usize,
    pub both_lan_flows: usize,
    pub src_lan_flows: usize,
    pub dst_lan_flows: usize,
    pub ipv4_lan_flows: usize,
    pub ipv6_lan_flows: usize,
    pub malformed_lines: usize,
    pub clients_dropped: usize,
    pub current_clients: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectSnapshot {
    pub clients: Vec<ClientSample>,
    pub source_path: String,
    pub counter_source: &'static str,
    pub warnings: Vec<&'static str>,
    pub stats: DirectStats,
}

#[derive(Default)]
struct DirectFlow {
    serial: u64,
    sip_address: Option<IpAddr>,
    dip_address: Option<IpAddr>,
    sip_address_nat: Option<IpAddr>,
    dip_address_nat: Option<IpAddr>,
    snode_address: Option<MacAddress>,
    dnode_address: Option<MacAddress>,
    snode_address_nat: Option<MacAddress>,
    dnode_address_nat: Option<MacAddress>,
    from_data_total: Option<u64>,
    to_data_total: u64,
    protocol: u8,
    known_fields: u16,
    invalid: bool,
}

impl DirectFlow {
    fn new(serial: u64) -> Self {
        Self {
            serial,
            ..Self::default()
        }
    }

    fn apply(&mut self, field: &str, value: &str) -> bool {
        let bit = match field {
            "sip_address" => 1 << 0,
            "dip_address" => 1 << 1,
            "sip_address_nat" => 1 << 2,
            "dip_address_nat" => 1 << 3,
            "snode_address" => 1 << 4,
            "dnode_address" => 1 << 5,
            "snode_address_nat" => 1 << 6,
            "dnode_address_nat" => 1 << 7,
            "protocol" => 1 << 8,
            "adv_stats.from_data_total" => 1 << 9,
            "adv_stats.to_data_total" => 1 << 10,
            "serial" => 1 << 11,
            _ => return true,
        };
        if self.known_fields & bit != 0 {
            self.invalid = true;
            return false;
        }
        self.known_fields |= bit;
        let valid = match field {
            "sip_address" => assign_ip(&mut self.sip_address, value),
            "dip_address" => assign_ip(&mut self.dip_address, value),
            "sip_address_nat" => assign_ip(&mut self.sip_address_nat, value),
            "dip_address_nat" => assign_ip(&mut self.dip_address_nat, value),
            "snode_address" => assign_mac(&mut self.snode_address, value),
            "dnode_address" => assign_mac(&mut self.dnode_address, value),
            "snode_address_nat" => assign_mac(&mut self.snode_address_nat, value),
            "dnode_address_nat" => assign_mac(&mut self.dnode_address_nat, value),
            "protocol" => match value.parse::<u8>() {
                Ok(protocol) => {
                    self.protocol = protocol;
                    true
                }
                Err(_) => {
                    self.protocol = 0;
                    false
                }
            },
            "adv_stats.from_data_total" => match value.parse::<u64>() {
                Ok(bytes) => {
                    self.from_data_total = Some(bytes);
                    true
                }
                Err(_) => {
                    self.from_data_total = None;
                    false
                }
            },
            "adv_stats.to_data_total" => match value.parse::<u64>() {
                Ok(bytes) => {
                    self.to_data_total = bytes;
                    true
                }
                Err(_) => {
                    self.to_data_total = 0;
                    false
                }
            },
            "serial" => value.parse::<u64>() == Ok(self.serial),
            _ => true,
        };
        if !valid {
            self.invalid = true;
        }
        valid
    }
}

fn assign_ip(slot: &mut Option<IpAddr>, value: &str) -> bool {
    match value.parse::<IpAddr>() {
        Ok(address) => {
            *slot = Some(address);
            true
        }
        Err(_) => {
            *slot = None;
            false
        }
    }
}

fn assign_mac(slot: &mut Option<MacAddress>, value: &str) -> bool {
    match MacAddress::from_str(value) {
        Ok(address) => {
            *slot = Some(address);
            true
        }
        Err(_) => {
            *slot = None;
            true
        }
    }
}

pub fn parse_direct_reader<R: BufRead>(
    mut reader: R,
    source_path: &str,
    identities: &IdentityTable,
    now_ms: u64,
    max_clients: usize,
    limits: ParseLimits,
) -> Result<DirectSnapshot, NssParseError> {
    let mut clients = BTreeMap::new();
    let mut stats = DirectStats::default();
    let mut active: Option<DirectFlow> = None;
    let mut physical_lines = 0usize;
    let mut connections = 0usize;
    let mut consumed_bytes = 0usize;
    let mut completed = BTreeSet::new();

    while let Some((line, oversized)) =
        read_bounded_line(&mut reader, &mut consumed_bytes, limits.max_bytes)?
    {
        physical_lines = physical_lines.saturating_add(1);
        if physical_lines > limits.max_lines {
            return Err(NssParseError::LineLimit(limits.max_lines));
        }
        if oversized {
            stats.malformed_lines = stats.malformed_lines.saturating_add(1);
            continue;
        }
        let Some((serial, field, value)) = parse_state_line(&line) else {
            stats.malformed_lines = stats.malformed_lines.saturating_add(1);
            continue;
        };
        if active.as_ref().is_some_and(|flow| flow.serial != serial) {
            if let Some(flow) = active.take() {
                completed.insert(flow.serial);
                finish_flow(
                    flow,
                    identities,
                    now_ms,
                    max_clients,
                    &mut clients,
                    &mut stats,
                );
            }
        }
        if active.is_none() {
            if completed.contains(&serial) {
                stats.malformed_lines = stats.malformed_lines.saturating_add(1);
                continue;
            }
            connections = connections.saturating_add(1);
            if connections > limits.max_connections {
                return Err(NssParseError::ConnectionLimit(limits.max_connections));
            }
            active = Some(DirectFlow::new(serial));
        }
        if !active.as_mut().is_some_and(|flow| flow.apply(field, value)) {
            stats.malformed_lines = stats.malformed_lines.saturating_add(1);
        }
    }

    if let Some(flow) = active {
        finish_flow(
            flow,
            identities,
            now_ms,
            max_clients,
            &mut clients,
            &mut stats,
        );
    }
    let clients = clients.into_values().collect::<Vec<_>>();
    stats.current_clients = clients.len();
    let mut warnings = Vec::new();
    if stats.malformed_lines != 0 {
        warnings.push("nss_ecm_direct_parse_errors");
    }
    if stats.skipped_no_arp != 0 {
        warnings.push("skip_nss_ecm_direct_flow_without_lan_identity");
    }
    if clients.is_empty() {
        warnings.push("nss_direct_no_data");
    }
    Ok(DirectSnapshot {
        clients,
        source_path: source_path.to_owned(),
        counter_source: ECM_DIRECT_COUNTER_SOURCE,
        warnings,
        stats,
    })
}

fn finish_flow(
    flow: DirectFlow,
    identities: &IdentityTable,
    now_ms: u64,
    max_clients: usize,
    clients: &mut BTreeMap<String, ClientSample>,
    stats: &mut DirectStats,
) {
    stats.entries_seen = stats.entries_seen.saturating_add(1);
    if flow.invalid {
        return;
    }
    let Some(from_data_total) = flow.from_data_total else {
        return;
    };
    if flow.sip_address.is_none() && flow.sip_address_nat.is_none() {
        return;
    }
    let src = endpoint_owner(
        identities,
        flow.sip_address,
        flow.sip_address_nat,
        flow.snode_address.or(flow.snode_address_nat),
    );
    let dst = endpoint_owner(
        identities,
        flow.dip_address,
        flow.dip_address_nat,
        flow.dnode_address.or(flow.dnode_address_nat),
    );
    if src.is_some() && dst.is_some() {
        stats.both_lan_flows = stats.both_lan_flows.saturating_add(1);
        return;
    }
    let (endpoint, source_side) = match (src, dst) {
        (Some(endpoint), None) => (endpoint, true),
        (None, Some(endpoint)) => (endpoint, false),
        (None, None) => {
            stats.skipped_no_arp = stats.skipped_no_arp.saturating_add(1);
            stats.no_lan_flows = stats.no_lan_flows.saturating_add(1);
            return;
        }
        (Some(_), Some(_)) => return,
    };
    let identity = endpoint.identity;
    let key = identity.key.to_string();
    if !clients.contains_key(&key) && clients.len() >= max_clients {
        stats.clients_dropped = stats.clients_dropped.saturating_add(1);
        return;
    }
    let sample = clients.entry(key.clone()).or_insert_with(|| ClientSample {
        mac: identity.key.mac.to_string(),
        identity_key: key,
        zone: identity.key.zone.clone(),
        interface: identity.interface.clone(),
        ips: identity.ips.clone(),
        tx_bytes: 0,
        rx_bytes: 0,
        last_seen_ms: now_ms,
        tcp_conns: 0,
        udp_conns: 0,
        udp_dns_conns: 0,
        udp_other_conns: 0,
    });
    let (tx_bytes, rx_bytes) = if source_side {
        (from_data_total, flow.to_data_total)
    } else {
        (flow.to_data_total, from_data_total)
    };
    sample.tx_bytes = sample.tx_bytes.saturating_add(tx_bytes);
    sample.rx_bytes = sample.rx_bytes.saturating_add(rx_bytes);
    sample.last_seen_ms = now_ms;
    match flow.protocol {
        6 => sample.tcp_conns = sample.tcp_conns.saturating_add(1),
        17 => {
            sample.udp_conns = sample.udp_conns.saturating_add(1);
            sample.udp_other_conns = sample.udp_other_conns.saturating_add(1);
        }
        _ => {}
    }
    stats.entries_matched = stats.entries_matched.saturating_add(1);
    if source_side {
        stats.src_lan_flows = stats.src_lan_flows.saturating_add(1);
    } else {
        stats.dst_lan_flows = stats.dst_lan_flows.saturating_add(1);
    }
    let ipv6 = endpoint.address.is_some_and(|ip| ip.is_ipv6());
    if ipv6 {
        stats.ipv6_lan_flows = stats.ipv6_lan_flows.saturating_add(1);
    } else {
        stats.ipv4_lan_flows = stats.ipv4_lan_flows.saturating_add(1);
    }
}

struct EndpointOwner<'a> {
    identity: &'a ClientIdentity,
    address: Option<IpAddr>,
}

fn endpoint_owner<'a>(
    identities: &'a IdentityTable,
    address: Option<IpAddr>,
    nat_address: Option<IpAddr>,
    node_mac: Option<MacAddress>,
) -> Option<EndpointOwner<'a>> {
    if let Some(address) = address {
        if let Some(identity) = identities.by_ip(&address.to_string()) {
            return Some(EndpointOwner {
                identity,
                address: Some(address),
            });
        }
    }
    if let Some(address) = nat_address {
        if let Some(identity) = identities.by_ip(&address.to_string()) {
            return Some(EndpointOwner {
                identity,
                address: Some(address),
            });
        }
    }
    let identity =
        node_mac.and_then(|mac| identities.iter().find(|identity| identity.key.mac == mac))?;
    let address = identity.ips.iter().find_map(|ip| ip.parse::<IpAddr>().ok());
    Some(EndpointOwner { identity, address })
}

fn parse_state_line(bytes: &[u8]) -> Option<(u64, &str, &str)> {
    let line = std::str::from_utf8(bytes).ok()?;
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    let tail = key.strip_prefix("conns.conn.")?;
    let (serial, field) = tail.split_once('.')?;
    if serial.is_empty()
        || serial.len() > ECM_STATE_SERIAL_MAX
        || !serial.bytes().all(|byte| byte.is_ascii_digit())
        || field.is_empty()
        || field.len() > ECM_STATE_FIELD_MAX
    {
        return None;
    }
    Some((serial.parse::<u64>().ok()?, field, value))
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    consumed_bytes: &mut usize,
    max_bytes: usize,
) -> Result<Option<(Vec<u8>, bool)>, NssParseError> {
    let mut line = Vec::new();
    let mut oversized = false;
    let mut saw_data = false;
    loop {
        let available = reader.fill_buf().map_err(NssParseError::Io)?;
        if available.is_empty() {
            return Ok(saw_data.then_some((line, oversized)));
        }
        saw_data = true;
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if take > max_bytes.saturating_sub(*consumed_bytes) {
            return Err(NssParseError::ByteLimit(max_bytes));
        }
        *consumed_bytes = consumed_bytes.saturating_add(take);
        if !oversized {
            let room = ECM_STATE_LINE_MAX.saturating_sub(line.len());
            line.extend_from_slice(&available[..take.min(room)]);
            if take > room {
                oversized = true;
            }
        }
        let ended = available[..take].last() == Some(&b'\n');
        reader.consume(take);
        if ended {
            return Ok(Some((line, oversized)));
        }
    }
}

pub trait EcmStateFs {
    type Reader: Read;

    fn open(&mut self, path: &str, flags: i32) -> io::Result<Self::Reader>;
    fn mknod_char(&mut self, path: &str, mode: u32, major: u32, minor: u32) -> io::Result<()>;
    fn unlink(&mut self, path: &str) -> io::Result<()>;
    fn fstat(&mut self, reader: &Self::Reader) -> io::Result<EcmNodeMetadata>;
    fn lstat(&mut self, path: &str) -> io::Result<EcmNodeMetadata>;
    fn clear_nonblock(&mut self, reader: &Self::Reader) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcmNodeMetadata {
    pub mode: u32,
    pub dev: u64,
    pub ino: u64,
    pub rdev: u64,
}

impl EcmNodeMetadata {
    fn is_char(self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFCHR
    }

    fn same_owned_node(self, other: Self) -> bool {
        self.is_char()
            && other.is_char()
            && self.dev == other.dev
            && self.ino == other.ino
            && self.rdev == other.rdev
    }
}

#[derive(Debug)]
pub struct OpenedEcmState<R> {
    pub reader: R,
    pub source_path: String,
    pub state_major: u32,
}

#[derive(Debug)]
pub struct StateOpenError {
    error: io::Error,
    reported_errno: Option<i32>,
    pub primary_errno: Option<i32>,
    pub state_major: u32,
}

impl StateOpenError {
    pub fn errno(&self) -> Option<i32> {
        self.reported_errno
    }
}

impl fmt::Display for StateOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "failed to open NSS ECM state: {}", self.error)
    }
}

impl std::error::Error for StateOpenError {}

pub fn open_ecm_state_with<F: EcmStateFs>(
    fs: &mut F,
) -> Result<OpenedEcmState<F::Reader>, StateOpenError> {
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    match fs.open(ECM_STATE_DEV_PATH, flags) {
        Ok(reader) => {
            let metadata = fs
                .fstat(&reader)
                .map_err(|error| state_open_error(error, None, 0, None))?;
            if !metadata.is_char() {
                return Err(state_open_error(
                    io::Error::from_raw_os_error(libc::ENODEV),
                    None,
                    0,
                    None,
                ));
            }
            let state_major = match read_optional_state_major(fs, flags) {
                Ok(Some(major)) => {
                    if libc::major(metadata.rdev) != major {
                        return Err(state_open_error(
                            io::Error::from_raw_os_error(libc::ENODEV),
                            None,
                            major,
                            None,
                        ));
                    }
                    major
                }
                Ok(None) | Err(_) => 0,
            };
            fs.clear_nonblock(&reader)
                .map_err(|error| state_open_error(error, None, state_major, None))?;
            return Ok(OpenedEcmState {
                reader,
                source_path: ECM_STATE_DEV_PATH.to_owned(),
                state_major,
            });
        }
        Err(primary) => {
            let primary_errno = primary.raw_os_error();
            if primary_errno == Some(libc::ELOOP) {
                return Err(state_open_error(primary, primary_errno, 0, primary_errno));
            }
            let major = read_optional_state_major(fs, flags)
                .map_err(|error| state_open_error(error, primary_errno, 0, None))?
                .ok_or_else(|| {
                    state_open_error(
                        io::Error::from_raw_os_error(libc::ENOENT),
                        primary_errno,
                        0,
                        primary_errno,
                    )
                })?;
            fs.mknod_char(ECM_STATE_TMP_DEV_PATH, 0o600, major, 0)
                .map_err(|error| state_open_error(error, primary_errno, major, None))?;
            let owned = fs
                .lstat(ECM_STATE_TMP_DEV_PATH)
                .map_err(|error| state_open_error(error, primary_errno, major, None))?;
            if !metadata_matches_device(owned, major, 0) {
                return Err(state_open_error(
                    io::Error::from_raw_os_error(libc::ENODEV),
                    primary_errno,
                    major,
                    None,
                ));
            }
            let opened = fs.open(ECM_STATE_TMP_DEV_PATH, flags);
            match opened {
                Ok(reader) => {
                    let opened_metadata = match fs.fstat(&reader) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            let _ = cleanup_owned_temp(fs, owned);
                            return Err(state_open_error(error, primary_errno, major, None));
                        }
                    };
                    if !opened_metadata.same_owned_node(owned)
                        || !metadata_matches_device(opened_metadata, major, 0)
                    {
                        let _ = cleanup_owned_temp(fs, owned);
                        return Err(state_open_error(
                            io::Error::from_raw_os_error(libc::ENODEV),
                            primary_errno,
                            major,
                            None,
                        ));
                    }
                    if let Err(error) = fs.clear_nonblock(&reader) {
                        let _ = cleanup_owned_temp(fs, owned);
                        return Err(state_open_error(error, primary_errno, major, None));
                    }
                    cleanup_owned_temp(fs, owned)
                        .map_err(|error| state_open_error(error, primary_errno, major, None))?;
                    Ok(OpenedEcmState {
                        reader,
                        source_path: ECM_STATE_TMP_DEV_PATH.to_owned(),
                        state_major: major,
                    })
                }
                Err(error) => {
                    let _ = cleanup_owned_temp(fs, owned);
                    Err(state_open_error(error, primary_errno, major, None))
                }
            }
        }
    }
}

fn state_open_error(
    error: io::Error,
    primary_errno: Option<i32>,
    state_major: u32,
    reported_errno: Option<i32>,
) -> StateOpenError {
    let reported_errno = reported_errno.or_else(|| error.raw_os_error());
    StateOpenError {
        error,
        reported_errno,
        primary_errno,
        state_major,
    }
}

fn read_optional_state_major<F: EcmStateFs>(fs: &mut F, flags: i32) -> io::Result<Option<u32>> {
    match fs.open(ECM_STATE_DEV_MAJOR_PATH, flags) {
        Ok(mut reader) => read_state_major(&mut reader).map(Some),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(error),
    }
}

fn metadata_matches_device(metadata: EcmNodeMetadata, major: u32, minor: u32) -> bool {
    metadata.is_char() && libc::major(metadata.rdev) == major && libc::minor(metadata.rdev) == minor
}

fn cleanup_owned_temp<F: EcmStateFs>(fs: &mut F, owned: EcmNodeMetadata) -> io::Result<()> {
    match fs.lstat(ECM_STATE_TMP_DEV_PATH) {
        Ok(current) if owned.same_owned_node(current) => fs.unlink(ECM_STATE_TMP_DEV_PATH),
        Ok(_) => Err(io::Error::from_raw_os_error(libc::ESTALE)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(error) => Err(error),
    }
}

fn read_state_major(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = Vec::with_capacity(ECM_STATE_MAJOR_MAX_BYTES + 1);
    reader
        .take((ECM_STATE_MAJOR_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > ECM_STATE_MAJOR_MAX_BYTES {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let value = std::str::from_utf8(&bytes)
        .ok()
        .map(str::trim_ascii)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    Ok(value)
}

#[derive(Default)]
pub struct LibcEcmStateFs;

impl EcmStateFs for LibcEcmStateFs {
    type Reader = File;

    fn open(&mut self, path: &str, flags: i32) -> io::Result<Self::Reader> {
        let path = CString::new(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let fd = unsafe { libc::open(path.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn mknod_char(&mut self, path: &str, mode: u32, major: u32, minor: u32) -> io::Result<()> {
        let path = CString::new(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let device = libc::makedev(major, minor);
        let result = unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | mode, device) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn unlink(&mut self, path: &str) -> io::Result<()> {
        let path = CString::new(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let result = unsafe { libc::unlink(path.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn fstat(&mut self, reader: &Self::Reader) -> io::Result<EcmNodeMetadata> {
        let mut metadata = unsafe { core::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(reader.as_raw_fd(), &mut metadata) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(metadata_from_stat(&metadata))
    }

    fn lstat(&mut self, path: &str) -> io::Result<EcmNodeMetadata> {
        let path = CString::new(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let mut metadata = unsafe { core::mem::zeroed::<libc::stat>() };
        if unsafe { libc::lstat(path.as_ptr(), &mut metadata) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(metadata_from_stat(&metadata))
    }

    fn clear_nonblock(&mut self, reader: &Self::Reader) -> io::Result<()> {
        let fd = reader.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn metadata_from_stat(metadata: &libc::stat) -> EcmNodeMetadata {
    EcmNodeMetadata {
        mode: metadata.st_mode,
        dev: metadata.st_dev,
        ino: metadata.st_ino,
        rdev: metadata.st_rdev,
    }
}

pub fn open_ecm_state() -> Result<OpenedEcmState<File>, StateOpenError> {
    open_ecm_state_with(&mut LibcEcmStateFs)
}

#[derive(Debug)]
pub enum NssReadError {
    Open(StateOpenError),
    Parse(NssParseError),
}

impl fmt::Display for NssReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(error) => error.fmt(formatter),
            Self::Parse(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for NssReadError {}

pub fn read_direct_snapshot(
    identities: &IdentityTable,
    now_ms: u64,
    max_clients: usize,
    limits: ParseLimits,
) -> Result<DirectSnapshot, NssReadError> {
    let opened = open_ecm_state().map_err(NssReadError::Open)?;
    parse_direct_reader(
        BufReader::new(opened.reader),
        &opened.source_path,
        identities,
        now_ms,
        max_clients,
        limits,
    )
    .map_err(NssReadError::Parse)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncAvailability {
    pub enable_conntrack_fallback: bool,
    pub bpf_full_available: bool,
    pub nf_conntrack_acct: bool,
    pub nss_present: bool,
    pub nss_ecm_active: bool,
    pub nss_ppe_active: bool,
}

pub const fn nss_sync_reader_available(facts: SyncAvailability) -> bool {
    facts.enable_conntrack_fallback
        && facts.nf_conntrack_acct
        && facts.nss_present
        && (facts.nss_ecm_active || facts.nss_ppe_active)
}

pub fn nss_sync_warnings(facts: SyncAvailability) -> Vec<&'static str> {
    if !facts.nf_conntrack_acct {
        return vec!["conntrack_acct_disabled"];
    }
    if !nss_sync_reader_available(facts) {
        return Vec::new();
    }
    let mut warnings = vec!["nss_ecm_sync_cadence"];
    if facts.bpf_full_available {
        warnings.push("nss_prefers_conntrack_sync");
    }
    warnings
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectFallbackInput {
    pub state_readable: bool,
    pub overlay_enabled: bool,
    pub rate_mode: RateCollectorMode,
    pub nss_daed_prefers_bpf: bool,
}

pub const fn direct_fallback_reason(input: DirectFallbackInput) -> &'static str {
    if input.overlay_enabled {
        ""
    } else if !input.state_readable {
        "state_unavailable_or_unreadable"
    } else if matches!(input.rate_mode, RateCollectorMode::Bpf) {
        "collector_mode_bpf"
    } else if matches!(input.rate_mode, RateCollectorMode::NssConntrackSync) {
        "collector_mode_nss_conntrack_sync"
    } else if input.nss_daed_prefers_bpf {
        "nss_daed_prefers_bpf"
    } else {
        "not_selected"
    }
}
