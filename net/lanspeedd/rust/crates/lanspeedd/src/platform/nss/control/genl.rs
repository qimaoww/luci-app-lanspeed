//! Versioned LANSPEED_NSS generic-netlink ABI for read and control paths.
//!
//! Module parameters remain available during the compatibility window, while
//! the daemon prefers the versioned family for capability discovery and owned
//! control operations instead of duplicating NSS limits or inferring feature
//! support from filenames.

use std::{
    collections::BTreeMap,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU32, Ordering},
};

use lanspeed_common::nss_genl as abi;
use serde_json::{json, Value};

const NETLINK_GENERIC: libc::c_int = 16;
const GENL_ID_CTRL: u16 = 0x10;
const NLMSG_HEADER_LEN: usize = 16;
const GENL_HEADER_LEN: usize = 4;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const NLMSG_OVERRUN: u16 = 4;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NLA_TYPE_MASK: u16 = 0x3fff;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    staged: u32,
    published: u32,
    degraded: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Stats {
    control_generation: u64,
    hardware_generation: u64,
    peer_generation: u64,
    peer_reassert_count: u64,
    igs_sync_count: u64,
    igs_last_sync_ns: u64,
    igs_bytes: u64,
    igs_packets: u64,
    igs_drops: u64,
    igs_cadence_samples: Option<u64>,
    igs_cadence_last_ns: Option<u64>,
    igs_cadence_min_ns: Option<u64>,
    igs_cadence_max_ns: Option<u64>,
    igs_active_nodes: Option<u32>,
    ack_latency_last_ns: u64,
    ack_latency_max_ns: u64,
    ack_received: u64,
    ack_timeout: u64,
    ack_late: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Health {
    healthy: bool,
    control_generation: u64,
    hardware_generation: u64,
}

pub(super) fn read() -> Option<Value> {
    let (socket, family_id) = open_family()?;
    Some(caps_json(query_caps(&socket, family_id)?))
}

pub(super) fn read_runtime() -> Option<Value> {
    let (socket, family_id) = open_family()?;
    let caps = query_caps(&socket, family_id)?;
    let state = query_state(&socket, family_id)?;
    let stats = query_stats(&socket, family_id)?;
    let health = query_health(&socket, family_id)?;
    Some(json!({
        "caps": caps_json(caps),
        "state": state_json(state),
        "stats": stats_json(stats),
        "health": health_json(health),
    }))
}

pub(super) fn write_igs(
    operation: &str,
    ifb: &str,
    edge: Option<&str>,
) -> Option<Result<(), &'static str>> {
    let (command, attributes) = match operation {
        "stage" => (
            abi::CMD_IGS_STAGE,
            encode_string_attribute(abi::A_IFB_NAME, ifb).ok()?,
        ),
        "publish" => {
            let edge = edge?;
            let mut attributes = encode_string_attribute(abi::A_IFB_NAME, ifb).ok()?;
            attributes.extend_from_slice(&encode_string_attribute(abi::A_EDGE_NAME, edge).ok()?);
            (abi::CMD_IGS_PUBLISH, attributes)
        }
        "unpublish" => (
            abi::CMD_IGS_UNPUBLISH,
            encode_string_attribute(abi::A_IFB_NAME, ifb).ok()?,
        ),
        "unstage" => (
            abi::CMD_IGS_DELETE,
            encode_string_attribute(abi::A_IFB_NAME, ifb).ok()?,
        ),
        _ => return None,
    };
    write_command(command, attributes)
}

pub(super) fn write_peer_replace(config: &str) -> Option<Result<(), &'static str>> {
    let attributes = encode_string_attribute(abi::A_CONFIG, config).ok()?;
    write_command(abi::CMD_PEER_REPLACE, attributes)
}

pub(super) fn write_tag_replace(config: &str) -> Option<Result<(), &'static str>> {
    let attributes = encode_string_attribute(abi::A_CONFIG, config).ok()?;
    write_command(abi::CMD_TAG_REPLACE, attributes)
}

pub(super) fn write_trusted_ingress(config: &str) -> Option<Result<(), &'static str>> {
    let attributes = encode_string_attribute(abi::A_CONFIG, config).ok()?;
    write_command(abi::CMD_TRUSTED_INGRESS_REPLACE, attributes)
}

fn open_family() -> Option<(GenericNetlinkSocket, u16)> {
    let socket = GenericNetlinkSocket::open().ok()?;
    let sequence = next_sequence();
    socket.send(&family_request(sequence).ok()?).ok()?;
    let family_id = loop {
        let packet = socket.receive().ok()?;
        if let Some(id) = parse_family_id_messages(&packet, sequence).ok()? {
            break id;
        }
    };
    Some((socket, family_id))
}

fn query_caps(socket: &GenericNetlinkSocket, family_id: u16) -> Option<Caps> {
    let sequence = next_sequence();
    socket.send(&caps_request(family_id, sequence)).ok()?;
    loop {
        let packet = socket.receive().ok()?;
        if let Some(caps) = parse_caps_messages(&packet, sequence, family_id).ok()? {
            return Some(caps);
        }
    }
}

fn query_state(socket: &GenericNetlinkSocket, family_id: u16) -> Option<State> {
    let sequence = next_sequence();
    socket
        .send(&command_request(family_id, sequence, abi::CMD_GET_STATE))
        .ok()?;
    loop {
        let packet = socket.receive().ok()?;
        if let Some(state) = parse_state_messages(&packet, sequence, family_id).ok()? {
            return Some(state);
        }
    }
}

fn query_stats(socket: &GenericNetlinkSocket, family_id: u16) -> Option<Stats> {
    let sequence = next_sequence();
    socket
        .send(&command_request(family_id, sequence, abi::CMD_GET_STATS))
        .ok()?;
    loop {
        let packet = socket.receive().ok()?;
        if let Some(stats) = parse_stats_messages(&packet, sequence, family_id).ok()? {
            return Some(stats);
        }
    }
}

fn query_health(socket: &GenericNetlinkSocket, family_id: u16) -> Option<Health> {
    let sequence = next_sequence();
    socket
        .send(&command_request(family_id, sequence, abi::CMD_GET_HEALTH))
        .ok()?;
    loop {
        let packet = socket.receive().ok()?;
        if let Some(health) = parse_health_messages(&packet, sequence, family_id).ok()? {
            return Some(health);
        }
    }
}

fn next_sequence() -> u32 {
    NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed).max(1)
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

fn state_json(state: State) -> Value {
    json!({
        "state": "ready",
        "staged": state.staged,
        "published": state.published,
        "degraded": state.degraded,
    })
}

fn stats_json(stats: Stats) -> Value {
    json!({
        "state": "ready",
        "control_generation": stats.control_generation,
        "hardware_generation": stats.hardware_generation,
        "peer_generation": stats.peer_generation,
        "peer_reassert_count": stats.peer_reassert_count,
        "igs_sync_count": stats.igs_sync_count,
        "igs_last_sync_ns": stats.igs_last_sync_ns,
        "igs_bytes": stats.igs_bytes,
        "igs_packets": stats.igs_packets,
        "igs_drops": stats.igs_drops,
        "igs_cadence_samples": stats.igs_cadence_samples,
        "igs_cadence_last_ns": stats.igs_cadence_last_ns,
        "igs_cadence_min_ns": stats.igs_cadence_min_ns,
        "igs_cadence_max_ns": stats.igs_cadence_max_ns,
        "igs_active_nodes": stats.igs_active_nodes,
        "ack_latency_last_ns": stats.ack_latency_last_ns,
        "ack_latency_max_ns": stats.ack_latency_max_ns,
        "ack_received": stats.ack_received,
        "ack_timeout": stats.ack_timeout,
        "ack_late": stats.ack_late,
    })
}

fn health_json(health: Health) -> Value {
    json!({
        "state": "ready",
        "healthy": health.healthy,
        "control_generation": health.control_generation,
        "hardware_generation": health.hardware_generation,
    })
}

fn family_request(sequence: u32) -> io::Result<Vec<u8>> {
    let mut name = abi::FAMILY_NAME.as_bytes().to_vec();
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
    generic_request(family_id, sequence, abi::CMD_GET_CAPS, abi::VERSION, &[])
}

fn command_request(family_id: u16, sequence: u32, command: u8) -> Vec<u8> {
    generic_request(family_id, sequence, command, abi::VERSION, &[])
}

fn write_command(command: u8, attributes: Vec<u8>) -> Option<Result<(), &'static str>> {
    let (socket, family_id) = open_family()?;
    let sequence = next_sequence();
    let request = generic_request_flags(
        family_id,
        sequence,
        command,
        abi::VERSION,
        &attributes,
        NLM_F_REQUEST | NLM_F_ACK,
    );
    if socket.send(&request).is_err() {
        return Some(Err("generic netlink request failed"));
    }
    loop {
        let packet = match socket.receive() {
            Ok(packet) => packet,
            Err(_) => return Some(Err("generic netlink reply failed")),
        };
        match parse_ack_messages(&packet, sequence) {
            Ok(Some(())) => return Some(Ok(())),
            Ok(None) => {}
            Err(error) => return Some(Err(error)),
        }
    }
}

fn generic_request(
    family_id: u16,
    sequence: u32,
    command: u8,
    version: u8,
    attributes: &[u8],
) -> Vec<u8> {
    generic_request_flags(
        family_id,
        sequence,
        command,
        version,
        attributes,
        NLM_F_REQUEST,
    )
}

fn generic_request_flags(
    family_id: u16,
    sequence: u32,
    command: u8,
    version: u8,
    attributes: &[u8],
    flags: u16,
) -> Vec<u8> {
    let length = NLMSG_HEADER_LEN + GENL_HEADER_LEN + attributes.len();
    let mut request = Vec::with_capacity(align4(length));
    request.extend_from_slice(&(length as u32).to_ne_bytes());
    request.extend_from_slice(&family_id.to_ne_bytes());
    request.extend_from_slice(&flags.to_ne_bytes());
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

fn encode_string_attribute(kind: u16, value: &str) -> Result<Vec<u8>, &'static str> {
    if value.as_bytes().contains(&0) {
        return Err("generic netlink string contains NUL");
    }
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    Ok(encode_attribute(kind, &bytes))
}

fn parse_family_id_messages(bytes: &[u8], sequence: u32) -> Result<Option<u16>, &'static str> {
    for message in messages(bytes, sequence)? {
        if message.kind == NLMSG_ERROR {
            parse_error(message.payload)?;
        } else if message.kind == GENL_ID_CTRL {
            if message.payload.len() < GENL_HEADER_LEN {
                return Err("truncated generic netlink header");
            }
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
                abi::A_ABI_VERSION
                | abi::A_FEATURE_BITS
                | abi::A_MAX_IGS
                | abi::A_MAX_PEERS
                | abi::A_MAX_CLIENT_TAGS => Value::from(read_u32(value).ok_or("short u32")?),
                abi::A_SUPPORTS_WIFI_PEER
                | abi::A_SUPPORTS_IGS_STATS
                | abi::A_SUPPORTS_PEER_QUERY => {
                    Value::from(value.first().copied().ok_or("short u8")? != 0)
                }
                _ => return Ok(()),
            };
            values.insert(kind, number);
            Ok(())
        })?;
        return Ok(Some(Caps {
            abi_version: required_u32(&values, abi::A_ABI_VERSION)?,
            feature_bits: required_u32(&values, abi::A_FEATURE_BITS)?,
            max_igs: required_u32(&values, abi::A_MAX_IGS)?,
            max_peers: required_u32(&values, abi::A_MAX_PEERS)?,
            max_client_tags: required_u32(&values, abi::A_MAX_CLIENT_TAGS)?,
            supports_wifi_peer: required_bool(&values, abi::A_SUPPORTS_WIFI_PEER)?,
            supports_igs_stats: required_bool(&values, abi::A_SUPPORTS_IGS_STATS)?,
            supports_peer_query: required_bool(&values, abi::A_SUPPORTS_PEER_QUERY)?,
        }));
    }
    Ok(None)
}

fn parse_state_messages(
    bytes: &[u8],
    sequence: u32,
    family_id: u16,
) -> Result<Option<State>, &'static str> {
    let Some(attributes) = reply_attributes(bytes, sequence, family_id)? else {
        return Ok(None);
    };
    let mut values = BTreeMap::new();
    for_each_attribute(attributes, |kind, value| {
        if matches!(
            kind,
            abi::A_IGS_STAGED | abi::A_IGS_PUBLISHED | abi::A_IGS_DEGRADED
        ) {
            values.insert(kind, read_u32(value).ok_or("short u32")?);
        }
        Ok(())
    })?;
    Ok(Some(State {
        staged: required_u32_value(&values, abi::A_IGS_STAGED)?,
        published: required_u32_value(&values, abi::A_IGS_PUBLISHED)?,
        degraded: required_u32_value(&values, abi::A_IGS_DEGRADED)?,
    }))
}

fn parse_stats_messages(
    bytes: &[u8],
    sequence: u32,
    family_id: u16,
) -> Result<Option<Stats>, &'static str> {
    let Some(attributes) = reply_attributes(bytes, sequence, family_id)? else {
        return Ok(None);
    };
    let mut values = BTreeMap::new();
    let mut igs_active_nodes = None;
    for_each_attribute(attributes, |kind, value| {
        if kind == abi::A_IGS_ACTIVE_NODES {
            igs_active_nodes = Some(read_u32(value).ok_or("short u32")?);
            return Ok(());
        }
        if matches!(
            kind,
            abi::A_CONTROL_GENERATION
                | abi::A_HARDWARE_GENERATION
                | abi::A_PEER_GENERATION
                | abi::A_PEER_REASSERT_COUNT
                | abi::A_IGS_SYNC_COUNT
                | abi::A_IGS_LAST_SYNC_NS
                | abi::A_IGS_BYTES
                | abi::A_IGS_PACKETS
                | abi::A_IGS_DROPS
                | abi::A_IGS_CADENCE_SAMPLES
                | abi::A_IGS_CADENCE_LAST_NS
                | abi::A_IGS_CADENCE_MIN_NS
                | abi::A_IGS_CADENCE_MAX_NS
                | abi::A_ACK_LATENCY_LAST_NS
                | abi::A_ACK_LATENCY_MAX_NS
                | abi::A_ACK_RECEIVED
                | abi::A_ACK_TIMEOUT
                | abi::A_ACK_LATE
        ) {
            values.insert(kind, read_u64(value).ok_or("short u64")?);
        }
        Ok(())
    })?;
    Ok(Some(Stats {
        control_generation: required_u64(&values, abi::A_CONTROL_GENERATION)?,
        hardware_generation: required_u64(&values, abi::A_HARDWARE_GENERATION)?,
        peer_generation: required_u64(&values, abi::A_PEER_GENERATION)?,
        peer_reassert_count: required_u64(&values, abi::A_PEER_REASSERT_COUNT)?,
        igs_sync_count: required_u64(&values, abi::A_IGS_SYNC_COUNT)?,
        igs_last_sync_ns: required_u64(&values, abi::A_IGS_LAST_SYNC_NS)?,
        igs_bytes: required_u64(&values, abi::A_IGS_BYTES)?,
        igs_packets: required_u64(&values, abi::A_IGS_PACKETS)?,
        igs_drops: required_u64(&values, abi::A_IGS_DROPS)?,
        igs_cadence_samples: values.get(&abi::A_IGS_CADENCE_SAMPLES).copied(),
        igs_cadence_last_ns: values.get(&abi::A_IGS_CADENCE_LAST_NS).copied(),
        igs_cadence_min_ns: values.get(&abi::A_IGS_CADENCE_MIN_NS).copied(),
        igs_cadence_max_ns: values.get(&abi::A_IGS_CADENCE_MAX_NS).copied(),
        igs_active_nodes,
        ack_latency_last_ns: required_u64(&values, abi::A_ACK_LATENCY_LAST_NS)?,
        ack_latency_max_ns: required_u64(&values, abi::A_ACK_LATENCY_MAX_NS)?,
        ack_received: required_u64(&values, abi::A_ACK_RECEIVED)?,
        ack_timeout: required_u64(&values, abi::A_ACK_TIMEOUT)?,
        ack_late: required_u64(&values, abi::A_ACK_LATE)?,
    }))
}

fn parse_health_messages(
    bytes: &[u8],
    sequence: u32,
    family_id: u16,
) -> Result<Option<Health>, &'static str> {
    let Some(attributes) = reply_attributes(bytes, sequence, family_id)? else {
        return Ok(None);
    };
    let mut healthy = None;
    let mut values = BTreeMap::new();
    for_each_attribute(attributes, |kind, value| {
        match kind {
            abi::A_HEALTHY => healthy = Some(value.first().copied().ok_or("short u8")? != 0),
            abi::A_CONTROL_GENERATION | abi::A_HARDWARE_GENERATION => {
                values.insert(kind, read_u64(value).ok_or("short u64")?);
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(Some(Health {
        healthy: healthy.ok_or("missing health attribute")?,
        control_generation: required_u64(&values, abi::A_CONTROL_GENERATION)?,
        hardware_generation: required_u64(&values, abi::A_HARDWARE_GENERATION)?,
    }))
}

fn reply_attributes<'a>(
    bytes: &'a [u8],
    sequence: u32,
    family_id: u16,
) -> Result<Option<&'a [u8]>, &'static str> {
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
        return Ok(Some(&message.payload[GENL_HEADER_LEN..]));
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

fn required_u32_value(values: &BTreeMap<u16, u32>, kind: u16) -> Result<u32, &'static str> {
    values.get(&kind).copied().ok_or("missing u32 attribute")
}

fn required_u64(values: &BTreeMap<u16, u64>, kind: u16) -> Result<u64, &'static str> {
    values.get(&kind).copied().ok_or("missing u64 attribute")
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

fn parse_ack_messages(bytes: &[u8], sequence: u32) -> Result<Option<()>, &'static str> {
    for message in messages(bytes, sequence)? {
        if message.kind == NLMSG_ERROR {
            parse_error(message.payload)?;
            return Ok(Some(()));
        }
    }
    Ok(None)
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

fn read_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_ne_bytes(bytes.get(..8)?.try_into().ok()?))
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
            tv_sec: 0,
            tv_usec: 250_000,
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
        let mut payload = vec![abi::CMD_GET_CAPS, abi::VERSION, 0, 0];
        for (kind, value) in [
            (abi::A_ABI_VERSION, 1u32.to_ne_bytes().to_vec()),
            (abi::A_FEATURE_BITS, 0x3fu32.to_ne_bytes().to_vec()),
            (abi::A_MAX_IGS, 64u32.to_ne_bytes().to_vec()),
            (abi::A_MAX_PEERS, 64u32.to_ne_bytes().to_vec()),
            (abi::A_MAX_CLIENT_TAGS, 64u32.to_ne_bytes().to_vec()),
        ] {
            payload.extend_from_slice(&encode_attribute(kind, &value));
        }
        for kind in [
            abi::A_SUPPORTS_WIFI_PEER,
            abi::A_SUPPORTS_IGS_STATS,
            abi::A_SUPPORTS_PEER_QUERY,
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
            .windows(abi::FAMILY_NAME.len())
            .any(|window| window == abi::FAMILY_NAME.as_bytes()));
    }

    #[test]
    fn parses_state_stats_and_health_replies() {
        let mut state_payload = vec![abi::CMD_GET_STATE, abi::VERSION, 0, 0];
        for (kind, value) in [
            (abi::A_IGS_STAGED, 1u32),
            (abi::A_IGS_PUBLISHED, 2u32),
            (abi::A_IGS_DEGRADED, 3u32),
        ] {
            state_payload.extend_from_slice(&encode_attribute(kind, &value.to_ne_bytes()));
        }
        let state_packet = message(42, 7, &state_payload);
        assert_eq!(
            parse_state_messages(&state_packet, 7, 42).unwrap(),
            Some(State {
                staged: 1,
                published: 2,
                degraded: 3,
            })
        );

        let stat_values: [(u16, u64); 18] = [
            (abi::A_CONTROL_GENERATION, 10),
            (abi::A_HARDWARE_GENERATION, 11),
            (abi::A_PEER_GENERATION, 12),
            (abi::A_PEER_REASSERT_COUNT, 13),
            (abi::A_IGS_SYNC_COUNT, 14),
            (abi::A_IGS_LAST_SYNC_NS, 15),
            (abi::A_IGS_BYTES, 16),
            (abi::A_IGS_PACKETS, 17),
            (abi::A_IGS_DROPS, 18),
            (abi::A_IGS_CADENCE_SAMPLES, 24),
            (abi::A_IGS_CADENCE_LAST_NS, 25),
            (abi::A_IGS_CADENCE_MIN_NS, 26),
            (abi::A_IGS_CADENCE_MAX_NS, 27),
            (abi::A_ACK_LATENCY_LAST_NS, 19),
            (abi::A_ACK_LATENCY_MAX_NS, 20),
            (abi::A_ACK_RECEIVED, 21),
            (abi::A_ACK_TIMEOUT, 22),
            (abi::A_ACK_LATE, 23),
        ];
        let mut stats_payload = vec![abi::CMD_GET_STATS, abi::VERSION, 0, 0];
        for (kind, value) in stat_values {
            stats_payload.extend_from_slice(&encode_attribute(kind, &value.to_ne_bytes()));
        }
        stats_payload.extend_from_slice(&encode_attribute(
            abi::A_IGS_ACTIVE_NODES,
            &2u32.to_ne_bytes(),
        ));
        let stats_packet = message(42, 7, &stats_payload);
        let stats = parse_stats_messages(&stats_packet, 7, 42).unwrap().unwrap();
        assert_eq!(stats.control_generation, 10);
        assert_eq!(stats.peer_reassert_count, 13);
        assert_eq!(stats.ack_late, 23);
        assert_eq!(stats.igs_cadence_samples, Some(24));
        assert_eq!(stats.igs_cadence_last_ns, Some(25));
        assert_eq!(stats.igs_cadence_min_ns, Some(26));
        assert_eq!(stats.igs_cadence_max_ns, Some(27));
        assert_eq!(stats.igs_active_nodes, Some(2));

        let mut health_payload = vec![abi::CMD_GET_HEALTH, abi::VERSION, 0, 0];
        health_payload.extend_from_slice(&encode_attribute(abi::A_HEALTHY, &[1]));
        health_payload.extend_from_slice(&encode_attribute(
            abi::A_CONTROL_GENERATION,
            &10u64.to_ne_bytes(),
        ));
        health_payload.extend_from_slice(&encode_attribute(
            abi::A_HARDWARE_GENERATION,
            &11u64.to_ne_bytes(),
        ));
        let health_packet = message(42, 7, &health_payload);
        assert_eq!(
            parse_health_messages(&health_packet, 7, 42).unwrap(),
            Some(Health {
                healthy: true,
                control_generation: 10,
                hardware_generation: 11,
            })
        );
    }

    #[test]
    fn rejects_a_short_family_reply_without_panicking() {
        let packet = message(GENL_ID_CTRL, 9, &[abi::CMD_GET_CAPS]);
        assert_eq!(
            parse_family_id_messages(&packet, 9),
            Err("truncated generic netlink header")
        );
    }

    #[test]
    fn write_requests_use_ack_and_bounded_nul_strings() {
        let attribute = encode_string_attribute(abi::A_IFB_NAME, "lsuabcdef01").unwrap();
        assert_eq!(attribute.last(), Some(&0));
        assert!(encode_string_attribute(abi::A_IFB_NAME, "bad\0name").is_err());
        let request = generic_request_flags(
            42,
            9,
            abi::CMD_IGS_STAGE,
            abi::VERSION,
            &attribute,
            NLM_F_REQUEST | NLM_F_ACK,
        );
        assert_eq!(
            u16::from_ne_bytes(request[6..8].try_into().unwrap()),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert!(request
            .windows(attribute.len())
            .any(|window| window == attribute));
    }

    #[test]
    fn parses_a_successful_netlink_ack() {
        let packet = message(NLMSG_ERROR, 11, &0i32.to_ne_bytes());
        assert_eq!(parse_ack_messages(&packet, 11).unwrap(), Some(()));
        assert_eq!(parse_ack_messages(&packet, 12).unwrap(), None);
    }
}
