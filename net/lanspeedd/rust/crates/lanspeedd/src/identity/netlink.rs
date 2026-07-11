use super::{filter::IdentityFilter, MacAddress, NeighborEntry};
use std::{
    collections::HashSet,
    ffi::CStr,
    fmt, io,
    net::Ipv6Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const NLMSG_HEADER_LEN: usize = 16;
const NDMSG_LEN: usize = 12;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NLA_TYPE_MASK: u16 = 0x3fff;
const NUD_NONE: u16 = 0;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;
const MAX_DUMP_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub enum NetlinkParseError {
    TruncatedHeader,
    InvalidMessageLength(u32),
}

impl fmt::Display for NetlinkParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => formatter.write_str("truncated rtnetlink message header"),
            Self::InvalidMessageLength(length) => {
                write!(formatter, "invalid rtnetlink message length {length}")
            }
        }
    }
}

impl std::error::Error for NetlinkParseError {}

pub fn parse_ipv6_neighbor_messages<F>(
    bytes: &[u8],
    max_entries: usize,
    mut interface_name: F,
) -> Result<Vec<NeighborEntry>, NetlinkParseError>
where
    F: FnMut(i32) -> Option<String>,
{
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < NLMSG_HEADER_LEN {
        return Err(NetlinkParseError::TruncatedHeader);
    }
    let mut entries = Vec::new();
    let mut seen_ips = HashSet::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < NLMSG_HEADER_LEN {
            return Err(NetlinkParseError::TruncatedHeader);
        }
        let message_len = read_u32(bytes, offset).ok_or(NetlinkParseError::TruncatedHeader)?;
        let message_len_usize = message_len as usize;
        if message_len_usize < NLMSG_HEADER_LEN || message_len_usize > bytes.len() - offset {
            return Err(NetlinkParseError::InvalidMessageLength(message_len));
        }
        let message_type = read_u16(bytes, offset + 4).unwrap_or_default();
        if message_type == NLMSG_DONE {
            break;
        }
        if message_type == RTM_NEWNEIGH && entries.len() < max_entries {
            let payload = &bytes[offset + NLMSG_HEADER_LEN..offset + message_len_usize];
            if let Some(entry) = parse_neighbor(payload, &mut interface_name) {
                if seen_ips.insert(entry.ip.clone()) {
                    entries.push(entry);
                }
            }
        }
        let aligned = align4(message_len_usize);
        if aligned > bytes.len() - offset {
            if message_len_usize == bytes.len() - offset {
                break;
            }
            return Err(NetlinkParseError::InvalidMessageLength(message_len));
        }
        offset += aligned;
    }
    Ok(entries)
}

fn parse_neighbor<F>(payload: &[u8], interface_name: &mut F) -> Option<NeighborEntry>
where
    F: FnMut(i32) -> Option<String>,
{
    if payload.len() < NDMSG_LEN || payload[0] != libc::AF_INET6 as u8 {
        return None;
    }
    let ifindex = read_i32(payload, 4)?;
    let state = read_u16(payload, 8)?;
    if ifindex <= 0 || matches!(state, NUD_NONE | NUD_FAILED | NUD_NOARP) {
        return None;
    }
    let mut dst = None;
    let mut lladdr = None;
    let mut offset = NDMSG_LEN;
    while payload.len().saturating_sub(offset) >= 4 {
        let length = read_u16(payload, offset)? as usize;
        let kind = read_u16(payload, offset + 2)? & NLA_TYPE_MASK;
        if length < 4 || length > payload.len() - offset {
            break;
        }
        let value = &payload[offset + 4..offset + length];
        match kind {
            NDA_DST if value.len() >= 16 => dst = Some(&value[..16]),
            NDA_LLADDR if value.len() >= 6 => lladdr = Some(&value[..6]),
            _ => {}
        }
        offset = offset.saturating_add(align4(length));
    }
    let address = Ipv6Addr::from(<[u8; 16]>::try_from(dst?).ok()?);
    let mac_bytes = <[u8; 6]>::try_from(lladdr?).ok()?;
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
    )
    .parse::<MacAddress>()
    .ok()?;
    let interface = interface_name(ifindex).unwrap_or_else(|| format!("if{ifindex}"));
    if super::filter::ifname_is_excluded_identity_source(&interface) {
        return None;
    }
    Some(NeighborEntry {
        ip: address.to_string(),
        mac,
        zone: super::filter::derive_zone_from_ifname(&interface),
        interface,
    })
}

pub fn read_ipv6_neighbor_table(
    max_entries: usize,
    filter: &IdentityFilter,
) -> io::Result<Vec<NeighborEntry>> {
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
    let request = neighbor_dump_request(sequence);
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
            "short rtnetlink request",
        ));
    }

    let mut dump = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received == 0 {
            break;
        }
        let packet = &buffer[..received as usize];
        if dump.len().saturating_add(packet.len()) > MAX_DUMP_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rtnetlink dump exceeds bound",
            ));
        }
        let done = packet_contains_type(packet, NLMSG_DONE)?;
        if packet_contains_type(packet, NLMSG_ERROR)? {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "rtnetlink returned NLMSG_ERROR",
            ));
        }
        dump.extend_from_slice(packet);
        if done {
            break;
        }
    }

    let entries = parse_ipv6_neighbor_messages(&dump, max_entries, interface_name_for_index)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(entries
        .into_iter()
        .filter(|entry| filter.allows(&entry.interface, &entry.ip))
        .collect())
}

#[repr(C)]
struct SockAddrNl {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

impl SockAddrNl {
    fn new() -> Self {
        Self {
            family: libc::AF_NETLINK as u16,
            pad: 0,
            pid: 0,
            groups: 0,
        }
    }
}

fn neighbor_dump_request(sequence: u32) -> [u8; NLMSG_HEADER_LEN + NDMSG_LEN] {
    let mut request = [0u8; NLMSG_HEADER_LEN + NDMSG_LEN];
    let request_len = request.len() as u32;
    request[..4].copy_from_slice(&request_len.to_ne_bytes());
    request[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    request[NLMSG_HEADER_LEN] = libc::AF_INET6 as u8;
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

fn interface_name_for_index(index: i32) -> Option<String> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    let pointer = unsafe { libc::if_indextoname(index as u32, name.as_mut_ptr()) };
    if pointer.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn packet_contains_type(bytes: &[u8], expected: u16) -> io::Result<bool> {
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes.len() - offset < NLMSG_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated rtnetlink packet",
            ));
        }
        let length = read_u32(bytes, offset).unwrap_or_default() as usize;
        if length < NLMSG_HEADER_LEN || length > bytes.len() - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid rtnetlink packet",
            ));
        }
        if read_u16(bytes, offset + 4) == Some(expected) {
            return Ok(true);
        }
        offset += align4(length);
    }
    Ok(false)
}

fn syscall_zero(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn align4(value: usize) -> usize {
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
