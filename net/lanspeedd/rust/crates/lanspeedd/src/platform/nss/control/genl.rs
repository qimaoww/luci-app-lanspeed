//! Read-only LANSPEED_NSS generic-netlink ABI.
//!
//! Module parameters remain available during the compatibility window, while
//! capability discovery uses the versioned family instead of duplicating NSS
//! limits or inferring feature support from filenames.

use std::{
    collections::BTreeMap,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU32, Ordering},
};

use serde_json::{json, Value};

const NETLINK_GENERIC: libc::c_int = 16;
const GENL_ID_CTRL: u16 = 0x10;
const NLMSG_HEADER_LEN: usize = 16;
const GENL_HEADER_LEN: usize = 4;
const NLM_F_REQUEST: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_OVERRUN: u16 = 4;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const LANSPEED_NSS_CMD_GET_CAPS: u8 = 1;
const LANSPEED_NSS_GENL_VERSION: u8 = 1;
const LANSPEED_NSS_A_ABI_VERSION: u16 = 1;
const LANSPEED_NSS_A_FEATURE_BITS: u16 = 2;
const LANSPEED_NSS_A_MAX_IGS: u16 = 3;
const LANSPEED_NSS_A_MAX_PEERS: u16 = 4;
const LANSPEED_NSS_A_MAX_CLIENT_TAGS: u16 = 5;
const LANSPEED_NSS_A_SUPPORTS_WIFI_PEER: u16 = 6;
const LANSPEED_NSS_A_SUPPORTS_IGS_STATS: u16 = 7;
const LANSPEED_NSS_A_SUPPORTS_PEER_QUERY: u16 = 8;
const NLA_TYPE_MASK: u16 = 0x3fff;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const FAMILY_NAME: &str = "LANSPEED_NSS";

static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
struct Caps {
    abi_version: u32,
    feature_bits: u32,
    max_igs: u32,
    max_peers: u32,
    max_client_tags: u32,
    supports_wifi_peer: bool,
    supports_igs_stats: bool,
    supports_peer_query: bool,
}

pub(super) fn read() -> Option<Value> {
    let socket = GenericNetlinkSocket::open().ok()?;
    let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed).max(1);
    socket.send(&family_request(sequence).ok()?).ok()?;
    let family_id = loop {
        let packet = socket.receive().ok()?;
        if let Some(id) = parse_family_id_messages(&packet, sequence).ok()? {
            break id;
        }
    };
    let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed).max(1);
    socket.send(&caps_request(family_id, sequence)).ok()?;
    let caps = loop {
        let packet = socket.receive().ok()?;
        if let Some(caps) = parse_caps_messages(&packet, sequence, family_id).ok()? {
            break caps;
        }
    };
    Some(caps_json(caps))
}

fn caps_json(caps: Caps) -> Value {
    json!({
        "state": "ready",
        "abi_version": caps.abi_version,
        "feature_bits": caps.feature_bits,
        "max_igs": caps.max_igs,
        "max_peers": caps.max_peers,
        "max_client_tags": caps.max_client_tags,
        "supports_wifi_peer": caps.supports_wifi_peer,
        "supports_igs_stats": caps.supports_igs_stats,
        "supports_peer_query": caps.supports_peer_query,
    })
}

fn family_request(sequence: u32) -> io::Result<Vec<u8>> {
    let mut name = FAMILY_NAME.as_bytes().to_vec();
    name.push(0);
    Ok(generic_request(
        GENL_ID_CTRL,
        sequence,
        CTRL_CMD_GETFAMILY,
        1,
        &encode_attribute(CTRL_ATTR_FAMILY_NAME, &name),
    ))
}

fn caps_request(family_id: u16, sequence: u32) -> Vec<u8> {
    generic_request(
        family_id,
        sequence,
        LANSPEED_NSS_CMD_GET_CAPS,
        LANSPEED_NSS_GENL_VERSION,
        &[],
    )
}

fn generic_request(
    family_id: u16,
    sequence: u32,
    command: u8,
    version: u8,
    attributes: &[u8],
) -> Vec<u8> {
    let length = NLMSG_HEADER_LEN + GENL_HEADER_LEN + attributes.len();
    let mut request = Vec::with_capacity(align4(length));
    request.extend_from_slice(&(length as u32).to_ne_bytes());
    request.extend_from_slice(&family_id.to_ne_bytes());
    request.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    request.extend_from_slice(&sequence.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.push(command);
    request.push(version);
    request.extend_from_slice(&0u16.to_ne_bytes());
    request.extend_from_slice(attributes);
    request.resize(align4(request.len()), 0);
    request
}

fn encode_attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let length = 4usize.saturating_add(value.len());
    let mut attribute = Vec::with_capacity(align4(length));
    attribute.extend_from_slice(&(length as u16).to_ne_bytes());
    attribute.extend_from_slice(&kind.to_ne_bytes());
    attribute.extend_from_slice(value);
    attribute.resize(align4(attribute.len()), 0);
    attribute
}

fn parse_family_id_messages(bytes: &[u8], sequence: u32) -> Result<Option<u16>, &'static str> {
    for message in messages(bytes, sequence)? {
        if message.kind == NLMSG_ERROR {
            parse_error(message.payload)?;
        } else if message.kind == GENL_ID_CTRL {
            let attributes = &message.payload[GENL_HEADER_LEN..];
            let mut family_id = None;
            for_each_attribute(attributes, |kind, value| {
                if kind == CTRL_ATTR_FAMILY_ID {
                    family_id = Some(read_u16(value).ok_or("short family id")?);
                }
                Ok(())
            })?;
            if family_id.is_some() {
                return Ok(family_id);
            }
        }
    }
    Ok(None)
}

fn parse_caps_messages(
    bytes: &[u8],
    sequence: u32,
    family_id: u16,
) -> Result<Option<Caps>, &'static str> {
    for message in messages(bytes, sequence)? {
        if message.kind == NLMSG_ERROR {
            parse_error(message.payload)?;
            continue;
        }
        if message.kind == NLMSG_OVERRUN || message.kind != family_id {
            continue;
        }
        if message.payload.len() < GENL_HEADER_LEN {
            return Err("truncated generic netlink header");
        }
        let mut values = BTreeMap::new();
        for_each_attribute(&message.payload[GENL_HEADER_LEN..], |kind, value| {
            let number = match kind {
                LANSPEED_NSS_A_ABI_VERSION
                | LANSPEED_NSS_A_FEATURE_BITS
                | LANSPEED_NSS_A_MAX_IGS
                | LANSPEED_NSS_A_MAX_PEERS
                | LANSPEED_NSS_A_MAX_CLIENT_TAGS => {
                    Value::from(read_u32(value).ok_or("short u32")?)
                }
                LANSPEED_NSS_A_SUPPORTS_WIFI_PEER
                | LANSPEED_NSS_A_SUPPORTS_IGS_STATS
                | LANSPEED_NSS_A_SUPPORTS_PEER_QUERY => {
                    Value::from(value.first().copied().ok_or("short u8")? != 0)
                }
                _ => return Ok(()),
            };
            values.insert(kind, number);
            Ok(())
        })?;
        return Ok(Some(Caps {
            abi_version: required_u32(&values, LANSPEED_NSS_A_ABI_VERSION)?,
            feature_bits: required_u32(&values, LANSPEED_NSS_A_FEATURE_BITS)?,
            max_igs: required_u32(&values, LANSPEED_NSS_A_MAX_IGS)?,
            max_peers: required_u32(&values, LANSPEED_NSS_A_MAX_PEERS)?,
            max_client_tags: required_u32(&values, LANSPEED_NSS_A_MAX_CLIENT_TAGS)?,
            supports_wifi_peer: required_bool(&values, LANSPEED_NSS_A_SUPPORTS_WIFI_PEER)?,
            supports_igs_stats: required_bool(&values, LANSPEED_NSS_A_SUPPORTS_IGS_STATS)?,
            supports_peer_query: required_bool(&values, LANSPEED_NSS_A_SUPPORTS_PEER_QUERY)?,
        }));
    }
    Ok(None)
}

fn required_u32(values: &BTreeMap<u16, Value>, kind: u16) -> Result<u32, &'static str> {
    values
        .get(&kind)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("missing u32 attribute")
}

fn required_bool(values: &BTreeMap<u16, Value>, kind: u16) -> Result<bool, &'static str> {
    values
        .get(&kind)
        .and_then(Value::as_bool)
        .ok_or("missing bool attribute")
}

struct Message<'a> {
    kind: u16,
    payload: &'a [u8],
}

fn messages(bytes: &[u8], sequence: u32) -> Result<Vec<Message<'_>>, &'static str> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err("generic netlink packet too large");
    }
    let mut offset = 0usize;
    let mut result = Vec::new();
    while offset < bytes.len() {
        if bytes.len().saturating_sub(offset) < NLMSG_HEADER_LEN {
            return Err("truncated netlink header");
        }
        let length =
            usize::try_from(read_u32(&bytes[offset..offset + 4]).ok_or("invalid netlink length")?)
                .map_err(|_| "invalid netlink length")?;
        let kind = read_u16(&bytes[offset + 4..offset + 6]).ok_or("invalid netlink kind")?;
        let message_sequence =
            read_u32(&bytes[offset + 8..offset + 12]).ok_or("invalid netlink sequence")?;
        if length < NLMSG_HEADER_LEN || offset.saturating_add(length) > bytes.len() {
            return Err("invalid netlink message length");
        }
        if message_sequence == sequence {
            result.push(Message {
                kind,
                payload: &bytes[offset + NLMSG_HEADER_LEN..offset + length],
            });
        }
        offset = offset.saturating_add(align4(length));
    }
    Ok(result)
}

fn parse_error(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < 4 {
        return Err("truncated netlink error");
    }
    let error = i32::from_ne_bytes(
        payload[..4]
            .try_into()
            .map_err(|_| "invalid netlink error")?,
    );
    if error == 0 {
        Ok(())
    } else {
        Err("kernel rejected generic netlink request")
    }
}

fn for_each_attribute(
    bytes: &[u8],
    mut visit: impl FnMut(u16, &[u8]) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len().saturating_sub(offset) < 4 {
            return Err("truncated netlink attribute");
        }
        let length =
            usize::from(read_u16(&bytes[offset..offset + 2]).ok_or("invalid attribute length")?);
        if !(4..=bytes.len().saturating_sub(offset)).contains(&length) {
            return Err("invalid netlink attribute length");
        }
        let kind = read_u16(&bytes[offset + 2..offset + 4]).ok_or("invalid attribute kind")?
            & NLA_TYPE_MASK;
        visit(kind, &bytes[offset + 4..offset + length])?;
        offset = offset.saturating_add(align4(length));
    }
    Ok(())
}

fn read_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?))
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

struct GenericNetlinkSocket {
    fd: OwnedFd,
}

impl GenericNetlinkSocket {
    fn open() -> io::Result<Self> {
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let local = SockAddrNl::new();
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&local as *const SockAddrNl).cast(),
                std::mem::size_of::<SockAddrNl>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    fn send(&self, request: &[u8]) -> io::Result<()> {
        let kernel = SockAddrNl::new();
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&kernel as *const SockAddrNl).cast(),
                std::mem::size_of::<SockAddrNl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != request.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short generic netlink request",
            ));
        }
        Ok(())
    }

    fn receive(&self) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; MAX_MESSAGE_BYTES];
        let mut sender = SockAddrNl::new();
        let mut sender_len = std::mem::size_of::<SockAddrNl>() as libc::socklen_t;
        let received = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
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
        if received as usize > buffer.len()
            || sender_len < std::mem::size_of::<SockAddrNl>() as libc::socklen_t
            || sender.family != libc::AF_NETLINK as u16
            || sender.pid != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid generic netlink reply",
            ));
        }
        buffer.truncate(received as usize);
        Ok(buffer)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let mut value = Vec::new();
        value.extend_from_slice(&(length as u32).to_ne_bytes());
        value.extend_from_slice(&kind.to_ne_bytes());
        value.extend_from_slice(&0u16.to_ne_bytes());
        value.extend_from_slice(&sequence.to_ne_bytes());
        value.extend_from_slice(&0u32.to_ne_bytes());
        value.extend_from_slice(payload);
        value.resize(align4(value.len()), 0);
        value
    }

    #[test]
    fn parses_caps_and_rejects_wrong_sequence() {
        let mut payload = vec![LANSPEED_NSS_CMD_GET_CAPS, LANSPEED_NSS_GENL_VERSION, 0, 0];
        for (kind, value) in [
            (LANSPEED_NSS_A_ABI_VERSION, 1u32.to_ne_bytes().to_vec()),
            (LANSPEED_NSS_A_FEATURE_BITS, 0x3fu32.to_ne_bytes().to_vec()),
            (LANSPEED_NSS_A_MAX_IGS, 64u32.to_ne_bytes().to_vec()),
            (LANSPEED_NSS_A_MAX_PEERS, 64u32.to_ne_bytes().to_vec()),
            (LANSPEED_NSS_A_MAX_CLIENT_TAGS, 64u32.to_ne_bytes().to_vec()),
        ] {
            payload.extend_from_slice(&encode_attribute(kind, &value));
        }
        for kind in [
            LANSPEED_NSS_A_SUPPORTS_WIFI_PEER,
            LANSPEED_NSS_A_SUPPORTS_IGS_STATS,
            LANSPEED_NSS_A_SUPPORTS_PEER_QUERY,
        ] {
            payload.extend_from_slice(&encode_attribute(kind, &[1]));
        }
        let packet = message(42, 7, &payload);
        assert_eq!(
            parse_caps_messages(&packet, 7, 42)
                .unwrap()
                .unwrap()
                .max_igs,
            64
        );
        assert!(parse_caps_messages(&packet, 8, 42).unwrap().is_none());
    }

    #[test]
    fn family_request_uses_the_versioned_family_name() {
        let request = family_request(9).unwrap();
        assert_eq!(
            &request[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + 4],
            [3, 1, 0, 0]
        );
        assert!(request
            .windows(FAMILY_NAME.len())
            .any(|window| window == FAMILY_NAME.as_bytes()));
    }
}
