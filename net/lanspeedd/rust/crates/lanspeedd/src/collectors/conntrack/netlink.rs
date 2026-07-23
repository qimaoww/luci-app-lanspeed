use super::{
    aggregate::{AggregateSnapshot, AggregateState},
    FlowSample, Protocol, TcpState, NETLINK_COUNTER_SOURCE, NETLINK_SOURCE_PATH,
};
use crate::identity::IdentityTable;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLA_TYPE_MASK: u16 = 0x3fff;
const CTA_TUPLE_ORIG: usize = 1;
const CTA_TUPLE_REPLY: usize = 2;
const CTA_STATUS: usize = 3;
const CTA_PROTOINFO: usize = 4;
const CTA_COUNTERS_ORIG: usize = 9;
const CTA_COUNTERS_REPLY: usize = 10;
const CTA_ID: usize = 12;
const CTA_ZONE: usize = 18;
const IPS_ASSURED: u32 = 1 << 2;
const IPS_OFFLOAD: u32 = 1 << 14;
const IPS_HW_OFFLOAD: u32 = 1 << 15;
const TCP_CONNTRACK_ESTABLISHED: u8 = 3;
const IPCTNL_MSG_CT_NEW: u16 = 1 << 8;
const NETLINK_NETFILTER: i32 = 12;
const MAX_DUMP_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DATAGRAM_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Datagram {
    pub sender_pid: u32,
    pub bytes: Vec<u8>,
}

impl Datagram {
    pub fn kernel(bytes: Vec<u8>) -> Self {
        Self {
            sender_pid: 0,
            bytes,
        }
    }
}

#[derive(Debug)]
pub enum DumpError {
    UnexpectedSender(u32),
    UnexpectedPortId { expected: u32, actual: u32 },
    UnexpectedSequence { expected: u32, actual: u32 },
    Interrupted,
    Kernel(io::Error),
    Malformed(&'static str),
    MissingDone,
    LimitExceeded,
    TruncatedDatagram { reported: usize, capacity: usize },
}

impl std::fmt::Display for DumpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedSender(pid) => {
                write!(formatter, "conntrack dump came from netlink pid {pid}")
            }
            Self::UnexpectedSequence { expected, actual } => write!(
                formatter,
                "conntrack dump sequence {actual} did not match {expected}"
            ),
            Self::UnexpectedPortId { expected, actual } => write!(
                formatter,
                "conntrack header port id {actual} did not match local port id {expected}"
            ),
            Self::Interrupted => write!(formatter, "conntrack dump was interrupted"),
            Self::Kernel(error) => write!(formatter, "kernel rejected conntrack dump: {error}"),
            Self::Malformed(reason) => {
                write!(formatter, "malformed conntrack netlink message: {reason}")
            }
            Self::MissingDone => write!(
                formatter,
                "conntrack multipart dump ended without NLMSG_DONE"
            ),
            Self::LimitExceeded => write!(formatter, "conntrack dump exceeded its byte limit"),
            Self::TruncatedDatagram { reported, capacity } => write!(
                formatter,
                "conntrack datagram length {reported} exceeded receive capacity {capacity}"
            ),
        }
    }
}

impl std::error::Error for DumpError {}

pub fn parse_dump(datagrams: &[Datagram], expected_seq: u32) -> Result<Vec<FlowSample>, DumpError> {
    parse_dump_for_port(datagrams, expected_seq, 0)
}

pub fn parse_dump_for_port(
    datagrams: &[Datagram],
    expected_seq: u32,
    expected_port_id: u32,
) -> Result<Vec<FlowSample>, DumpError> {
    Ok(
        parse_dump_detailed_with_limit(datagrams, expected_seq, expected_port_id, MAX_DUMP_BYTES)?
            .flows,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedDump {
    pub flows: Vec<FlowSample>,
    pub malformed_entries: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetlinkSnapshot {
    pub flows: Vec<FlowSample>,
    pub source_path: &'static str,
    pub counter_source: &'static str,
    pub malformed_entries: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetlinkAggregateSnapshot {
    pub aggregate: AggregateSnapshot,
    pub source_path: &'static str,
    pub counter_source: &'static str,
    pub malformed_entries: usize,
    pub entries_seen: usize,
}

pub fn parse_dump_with_limit(
    datagrams: &[Datagram],
    expected_seq: u32,
    max_bytes: usize,
) -> Result<Vec<FlowSample>, DumpError> {
    Ok(parse_dump_detailed_with_limit(datagrams, expected_seq, 0, max_bytes)?.flows)
}

pub fn parse_dump_detailed(
    datagrams: &[Datagram],
    expected_seq: u32,
) -> Result<ParsedDump, DumpError> {
    parse_dump_detailed_with_limit(datagrams, expected_seq, 0, MAX_DUMP_BYTES)
}

fn parse_dump_detailed_with_limit(
    datagrams: &[Datagram],
    expected_seq: u32,
    expected_port_id: u32,
    max_bytes: usize,
) -> Result<ParsedDump, DumpError> {
    validate_dump_size(datagrams, max_bytes)?;
    let mut parser = DumpParser::new(expected_seq, expected_port_id, max_bytes);
    for datagram in datagrams {
        parser.push_datagram(datagram.sender_pid, &datagram.bytes)?;
    }
    parser.finish()
}

fn validate_dump_size(datagrams: &[Datagram], max_bytes: usize) -> Result<(), DumpError> {
    let total = datagrams.iter().try_fold(0usize, |total, datagram| {
        total
            .checked_add(datagram.bytes.len())
            .ok_or(DumpError::LimitExceeded)
    })?;
    if total > max_bytes {
        return Err(DumpError::LimitExceeded);
    }
    Ok(())
}

struct DumpParser {
    expected_seq: u32,
    expected_port_id: u32,
    max_bytes: usize,
    total_bytes: usize,
    flows: Vec<FlowSample>,
    malformed_entries: usize,
    done: bool,
}

impl DumpParser {
    fn new(expected_seq: u32, expected_port_id: u32, max_bytes: usize) -> Self {
        Self {
            expected_seq,
            expected_port_id,
            max_bytes,
            total_bytes: 0,
            flows: Vec::new(),
            malformed_entries: 0,
            done: false,
        }
    }

    fn push_datagram(&mut self, sender_pid: u32, bytes: &[u8]) -> Result<bool, DumpError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes.len())
            .ok_or(DumpError::LimitExceeded)?;
        if self.total_bytes > self.max_bytes {
            return Err(DumpError::LimitExceeded);
        }
        self.parse_datagram(sender_pid, bytes)?;
        Ok(self.done)
    }

    fn parse_datagram(&mut self, sender_pid: u32, bytes: &[u8]) -> Result<(), DumpError> {
        if sender_pid != 0 {
            return Err(DumpError::UnexpectedSender(sender_pid));
        }
        let mut offset = 0usize;
        while offset < bytes.len() {
            let header = bytes
                .get(offset..offset + 16)
                .ok_or(DumpError::Malformed("truncated nlmsghdr"))?;
            let len = u32::from_ne_bytes(
                header[0..4]
                    .try_into()
                    .map_err(|_| DumpError::Malformed("invalid nlmsg length"))?,
            ) as usize;
            if len < 16 || offset.checked_add(len).is_none_or(|end| end > bytes.len()) {
                return Err(DumpError::Malformed("invalid nlmsg length"));
            }
            let kind = u16::from_ne_bytes(
                header[4..6]
                    .try_into()
                    .map_err(|_| DumpError::Malformed("invalid nlmsg type"))?,
            );
            let flags = u16::from_ne_bytes(
                header[6..8]
                    .try_into()
                    .map_err(|_| DumpError::Malformed("invalid nlmsg flags"))?,
            );
            let seq = u32::from_ne_bytes(
                header[8..12]
                    .try_into()
                    .map_err(|_| DumpError::Malformed("invalid nlmsg sequence"))?,
            );
            let pid = u32::from_ne_bytes(
                header[12..16]
                    .try_into()
                    .map_err(|_| DumpError::Malformed("invalid nlmsg pid"))?,
            );
            if seq != self.expected_seq {
                return Err(DumpError::UnexpectedSequence {
                    expected: self.expected_seq,
                    actual: seq,
                });
            }
            if pid != self.expected_port_id {
                return Err(DumpError::UnexpectedPortId {
                    expected: self.expected_port_id,
                    actual: pid,
                });
            }
            if flags & NLM_F_DUMP_INTR != 0 {
                return Err(DumpError::Interrupted);
            }
            let payload = &bytes[offset + 16..offset + len];
            if self.done {
                return if kind == NLMSG_DONE {
                    Err(DumpError::Malformed("duplicate NLMSG_DONE"))
                } else {
                    Err(DumpError::Malformed("message after NLMSG_DONE"))
                };
            }
            match kind {
                NLMSG_DONE => {
                    if flags & NLM_F_MULTI == 0 {
                        return Err(DumpError::Malformed("NLMSG_DONE is not multipart"));
                    }
                    if (1..4).contains(&payload.len()) {
                        return Err(DumpError::Malformed("short NLMSG_DONE status"));
                    }
                    if payload.len() >= 4 {
                        let error = i32::from_ne_bytes(
                            payload[0..4]
                                .try_into()
                                .map_err(|_| DumpError::Malformed("invalid DONE status"))?,
                        );
                        if error < 0 {
                            return Err(DumpError::Kernel(io::Error::from_raw_os_error(
                                error.saturating_abs(),
                            )));
                        } else if error > 0 {
                            return Err(DumpError::Malformed("positive NLMSG_DONE status"));
                        }
                    }
                    self.done = true;
                }
                NLMSG_ERROR => parse_ack(payload)?,
                IPCTNL_MSG_CT_NEW => {
                    if flags & NLM_F_MULTI == 0 {
                        return Err(DumpError::Malformed("conntrack data is not multipart"));
                    }
                    match parse_flow(payload) {
                        Ok(flow) => self.flows.push(flow),
                        Err(DumpError::Malformed(_)) => {
                            self.malformed_entries = self.malformed_entries.saturating_add(1);
                        }
                        Err(error) => return Err(error),
                    }
                }
                _ => return Err(DumpError::Malformed("unexpected netlink message type")),
            }
            let aligned = align4(len).ok_or(DumpError::Malformed("nlmsg alignment overflow"))?;
            offset = offset
                .checked_add(aligned)
                .ok_or(DumpError::Malformed("nlmsg offset overflow"))?;
            if offset > bytes.len() {
                return Err(DumpError::Malformed("truncated nlmsg padding"));
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<ParsedDump, DumpError> {
        if !self.done {
            return Err(DumpError::MissingDone);
        }
        Ok(ParsedDump {
            flows: self.flows,
            malformed_entries: self.malformed_entries,
        })
    }
}

fn parse_ack(payload: &[u8]) -> Result<(), DumpError> {
    let error = payload
        .get(..20)
        .ok_or(DumpError::Malformed("short NLMSG_ERROR"))?;
    let error = i32::from_ne_bytes(
        error[..4]
            .try_into()
            .map_err(|_| DumpError::Malformed("invalid NLMSG_ERROR"))?,
    );
    if error == 0 {
        Ok(())
    } else if error < 0 {
        Err(DumpError::Kernel(io::Error::from_raw_os_error(
            error.saturating_abs(),
        )))
    } else {
        Err(DumpError::Malformed("positive NLMSG_ERROR errno"))
    }
}

fn parse_flow(payload: &[u8]) -> Result<FlowSample, DumpError> {
    let attrs = payload
        .get(4..)
        .ok_or(DumpError::Malformed("short nfgenmsg"))?;
    let attrs = attr_table(attrs, CTA_ZONE)?;
    let orig = attrs[CTA_TUPLE_ORIG].ok_or(DumpError::Malformed("missing original tuple"))?;
    let orig_counters =
        attrs[CTA_COUNTERS_ORIG].ok_or(DumpError::Malformed("missing original counters"))?;
    let mut flow = FlowSample::default();
    flow.conntrack_id = attrs[CTA_ID].map(|id| be_u32(id.payload)).transpose()?;
    flow.conntrack_zone = attrs[CTA_ZONE]
        .map(|zone| be_u16(zone.payload))
        .transpose()?;
    let orig_meta = parse_tuple(orig.payload, true, &mut flow)?;
    if let Some(reply) = attrs[CTA_TUPLE_REPLY] {
        let reply_meta = parse_tuple(reply.payload, false, &mut flow)?;
        if reply_meta != orig_meta {
            return Err(DumpError::Malformed(
                "reply tuple protocol or address family mismatch",
            ));
        }
    }
    flow.orig_bytes = parse_counters(orig_counters.payload)?;
    if let Some(reply) = attrs[CTA_COUNTERS_REPLY] {
        flow.reply_bytes = parse_counters(reply.payload)?;
    }
    let status = attrs[CTA_STATUS]
        .map(|status| be_u32(status.payload))
        .transpose()?
        .unwrap_or(0);
    flow.assured = status & IPS_ASSURED != 0;
    let protoinfo = attrs[CTA_PROTOINFO];
    if let Some(protoinfo) = protoinfo {
        parse_protoinfo(protoinfo.payload, &mut flow)?;
    }
    if flow.protocol == Protocol::Tcp
        && protoinfo.is_none()
        && status & (IPS_OFFLOAD | IPS_HW_OFFLOAD) != 0
    {
        flow.tcp_state = Some(TcpState::Established);
    }
    if flow.orig_src.is_none() {
        return Err(DumpError::Malformed("original tuple has no source address"));
    }
    Ok(flow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TupleMeta {
    protocol: Protocol,
    ipv6: bool,
}

fn parse_tuple(
    payload: &[u8],
    original: bool,
    flow: &mut FlowSample,
) -> Result<TupleMeta, DumpError> {
    let table = attr_table(payload, 2)?;
    let ip = attr_table(
        table[1]
            .ok_or(DumpError::Malformed("tuple missing IP attributes"))?
            .payload,
        4,
    )?;
    let proto = attr_table(
        table[2]
            .ok_or(DumpError::Malformed("tuple missing protocol attributes"))?
            .payload,
        3,
    )?;
    let src =
        parse_ip(ip[1], ip[3])?.ok_or(DumpError::Malformed("tuple missing source address"))?;
    let dst =
        parse_ip(ip[2], ip[4])?.ok_or(DumpError::Malformed("tuple missing destination address"))?;
    if src.is_ipv4() != dst.is_ipv4() {
        return Err(DumpError::Malformed("tuple address family mismatch"));
    }
    let number = exact(
        proto[1]
            .ok_or(DumpError::Malformed("tuple missing protocol number"))?
            .payload,
        1,
    )?[0];
    let parsed_protocol = protocol(number);
    if matches!(parsed_protocol, Protocol::Tcp | Protocol::Udp)
        && (proto[2].is_none() || proto[3].is_none())
    {
        return Err(DumpError::Malformed("TCP/UDP tuple missing ports"));
    }
    let sport = proto[2]
        .map(|attr| be_u16(attr.payload))
        .transpose()?
        .unwrap_or(0);
    let dport = proto[3]
        .map(|attr| be_u16(attr.payload))
        .transpose()?
        .unwrap_or(0);
    if original {
        flow.orig_src = Some(src);
        flow.orig_dst = Some(dst);
        flow.orig_sport = sport;
        flow.orig_dport = dport;
        flow.protocol = parsed_protocol;
    } else {
        flow.reply_src = Some(src);
        flow.reply_dst = Some(dst);
        flow.reply_sport = sport;
        flow.reply_dport = dport;
        if flow.protocol == Protocol::Other(0) {
            flow.protocol = parsed_protocol;
        }
    }
    Ok(TupleMeta {
        protocol: parsed_protocol,
        ipv6: src.is_ipv6(),
    })
}

fn parse_ip(v4: Option<AttrRef<'_>>, v6: Option<AttrRef<'_>>) -> Result<Option<IpAddr>, DumpError> {
    match (v4, v6) {
        (Some(_), Some(_)) => Err(DumpError::Malformed(
            "tuple contains both IPv4 and IPv6 address",
        )),
        (Some(attr), None) => Ok(Some(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(exact(attr.payload, 4)?)
                .map_err(|_| DumpError::Malformed("invalid IPv4 address"))?,
        )))),
        (None, Some(attr)) => Ok(Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(exact(attr.payload, 16)?)
                .map_err(|_| DumpError::Malformed("invalid IPv6 address"))?,
        )))),
        (None, None) => Ok(None),
    }
}

fn parse_counters(payload: &[u8]) -> Result<u64, DumpError> {
    let table = attr_table(payload, 4)?;
    if let Some(bytes) = table[2] {
        return Ok(u64::from_be_bytes(
            exact(bytes.payload, 8)?
                .try_into()
                .map_err(|_| DumpError::Malformed("invalid 64-bit byte counter"))?,
        ));
    }
    if let Some(bytes) = table[4] {
        return Ok(u32::from_be_bytes(
            exact(bytes.payload, 4)?
                .try_into()
                .map_err(|_| DumpError::Malformed("invalid 32-bit byte counter"))?,
        ) as u64);
    }
    Err(DumpError::Malformed("missing accounting byte counter"))
}

fn parse_protoinfo(payload: &[u8], flow: &mut FlowSample) -> Result<(), DumpError> {
    let table = attr_table(payload, 1)?;
    let Some(tcp) = table[1] else {
        return Ok(());
    };
    let tcp = attr_table(tcp.payload, 1)?;
    if let Some(state) = tcp[1] {
        flow.tcp_state = Some(tcp_state(exact(state.payload, 1)?[0]));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AttrRef<'a> {
    payload: &'a [u8],
}

fn attr_table(payload: &[u8], max: usize) -> Result<Vec<Option<AttrRef<'_>>>, DumpError> {
    let mut table = vec![None; max + 1];
    let mut offset = 0usize;
    while offset < payload.len() {
        if payload[offset..].iter().all(|byte| *byte == 0) {
            break;
        }
        let header = payload
            .get(offset..offset + 4)
            .ok_or(DumpError::Malformed("truncated nlattr"))?;
        let len = u16::from_ne_bytes(
            header[0..2]
                .try_into()
                .map_err(|_| DumpError::Malformed("invalid nlattr length"))?,
        ) as usize;
        let raw_kind = u16::from_ne_bytes(
            header[2..4]
                .try_into()
                .map_err(|_| DumpError::Malformed("invalid nlattr type"))?,
        );
        let kind = raw_kind & NLA_TYPE_MASK;
        if len < 4
            || offset
                .checked_add(len)
                .is_none_or(|end| end > payload.len())
        {
            return Err(DumpError::Malformed("invalid nlattr length"));
        }
        if usize::from(kind) <= max {
            let slot = &mut table[usize::from(kind)];
            if slot.is_some() {
                return Err(DumpError::Malformed("duplicate known attribute"));
            }
            *slot = Some(AttrRef {
                payload: &payload[offset + 4..offset + len],
            });
        }
        offset = offset
            .checked_add(align4(len).ok_or(DumpError::Malformed("nlattr alignment overflow"))?)
            .ok_or(DumpError::Malformed("nlattr offset overflow"))?;
        if offset > payload.len() {
            return Err(DumpError::Malformed("truncated nlattr padding"));
        }
    }
    Ok(table)
}

pub fn snapshot_from_datagrams(
    datagrams: &[Datagram],
    expected_seq: u32,
) -> Result<NetlinkSnapshot, DumpError> {
    let parsed = parse_dump_detailed(datagrams, expected_seq)?;
    Ok(NetlinkSnapshot {
        flows: parsed.flows,
        source_path: NETLINK_SOURCE_PATH,
        counter_source: NETLINK_COUNTER_SOURCE,
        malformed_entries: parsed.malformed_entries,
    })
}

pub fn aggregate_dump(
    datagrams: &[Datagram],
    expected_seq: u32,
    identities: &IdentityTable,
    now_ms: u64,
    max_clients: usize,
) -> Result<NetlinkAggregateSnapshot, DumpError> {
    validate_dump_size(datagrams, MAX_DUMP_BYTES)?;
    let mut parser = DumpParser::new(expected_seq, 0, MAX_DUMP_BYTES);
    let mut aggregate = AggregateState::new(identities, now_ms, max_clients);
    for datagram in datagrams {
        parser.push_datagram(datagram.sender_pid, &datagram.bytes)?;
        drain_new_flows(&mut parser, &mut aggregate);
    }
    let parsed = parser.finish()?;
    Ok(finish_aggregate_dump(aggregate, parsed))
}

fn drain_new_flows(parser: &mut DumpParser, aggregate: &mut AggregateState<'_>) {
    for flow in parser.flows.drain(..) {
        aggregate.push(&flow);
    }
}

fn finish_aggregate_dump(
    aggregate: AggregateState<'_>,
    parsed: ParsedDump,
) -> NetlinkAggregateSnapshot {
    debug_assert!(parsed.flows.is_empty());
    let aggregate = aggregate.finish();
    let entries_seen = aggregate
        .stats
        .entries_seen
        .saturating_add(parsed.malformed_entries);
    NetlinkAggregateSnapshot {
        aggregate,
        source_path: NETLINK_SOURCE_PATH,
        counter_source: NETLINK_COUNTER_SOURCE,
        malformed_entries: parsed.malformed_entries,
        entries_seen,
    }
}

pub fn build_dump_request(seq: u32, port_id: u32) -> [u8; 20] {
    let mut request = [0u8; 20];
    request[0..4].copy_from_slice(&20u32.to_ne_bytes());
    request[4..6].copy_from_slice(&((1u16 << 8) | 1).to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
    request[8..12].copy_from_slice(&seq.to_ne_bytes());
    request[12..16].copy_from_slice(&port_id.to_ne_bytes());
    request[16] = libc::AF_UNSPEC as u8;
    request
}

pub fn read_snapshot() -> Result<NetlinkSnapshot, DumpError> {
    let parsed = read_dump(|_| {})?;
    Ok(NetlinkSnapshot {
        flows: parsed.flows,
        source_path: NETLINK_SOURCE_PATH,
        counter_source: NETLINK_COUNTER_SOURCE,
        malformed_entries: parsed.malformed_entries,
    })
}

pub fn read_aggregate(
    identities: &IdentityTable,
    now_ms: u64,
    max_clients: usize,
) -> Result<NetlinkAggregateSnapshot, DumpError> {
    let mut aggregate = AggregateState::new(identities, now_ms, max_clients);
    let parsed = read_dump(|parser| drain_new_flows(parser, &mut aggregate))?;
    Ok(finish_aggregate_dump(aggregate, parsed))
}

fn read_dump(mut after_datagram: impl FnMut(&mut DumpParser)) -> Result<ParsedDump, DumpError> {
    let socket = open_socket().map_err(DumpError::Kernel)?;
    let port_id = socket_port_id(&socket).map_err(DumpError::Kernel)?;
    let seq = dump_sequence();
    let request = build_dump_request(seq, port_id);
    let mut kernel = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = retry_eintr(|| {
        let result = unsafe {
            libc::sendto(
                socket.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&raw const kernel).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        (result >= 0)
            .then_some(result)
            .ok_or_else(io::Error::last_os_error)
    })
    .map_err(DumpError::Kernel)?;
    if sent as usize != request.len() {
        return Err(DumpError::Kernel(io::Error::new(
            io::ErrorKind::WriteZero,
            "short conntrack netlink request",
        )));
    }
    let mut parser = DumpParser::new(seq, port_id, MAX_DUMP_BYTES);
    let mut bytes = vec![0u8; MAX_DATAGRAM_BYTES];
    loop {
        let mut sender = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
        let mut sender_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        let received = retry_eintr(|| {
            sender = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
            sender_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            let result = unsafe {
                libc::recvfrom(
                    socket.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_TRUNC,
                    (&raw mut sender).cast(),
                    &mut sender_len,
                )
            };
            (result >= 0)
                .then_some(result)
                .ok_or_else(io::Error::last_os_error)
        })
        .map_err(DumpError::Kernel)?;
        if sender_len < std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t {
            return Err(DumpError::Malformed("short netlink sender address"));
        }
        if sender.nl_family != libc::AF_NETLINK as libc::sa_family_t {
            return Err(DumpError::Malformed("unexpected netlink sender family"));
        }
        let received = validate_received_datagram_len(received as usize, bytes.len())?;
        let done = parser.push_datagram(sender.nl_pid, &bytes[..received])?;
        after_datagram(&mut parser);
        if done {
            return parser.finish();
        }
    }
}

pub fn validate_received_datagram_len(
    reported: usize,
    capacity: usize,
) -> Result<usize, DumpError> {
    if reported > capacity {
        Err(DumpError::TruncatedDatagram { reported, capacity })
    } else {
        Ok(reported)
    }
}

pub fn retry_eintr<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match operation() {
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => {}
            result => return result,
        }
    }
}

fn open_socket() -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_NETFILTER,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut local = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let bound = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const local).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(io::Error::last_os_error());
    }
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    };
    if set < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn socket_port_id(socket: &OwnedFd) -> io::Result<u32> {
    let mut local = unsafe { std::mem::zeroed::<libc::sockaddr_nl>() };
    let mut len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    let result =
        unsafe { libc::getsockname(socket.as_raw_fd(), (&raw mut local).cast(), &mut len) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if len < std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short netlink socket address",
        ));
    }
    Ok(local.nl_pid)
}

fn dump_sequence() -> u32 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    duration.subsec_nanos() ^ (std::process::id().rotate_left(13))
}

fn exact(bytes: &[u8], len: usize) -> Result<&[u8], DumpError> {
    (bytes.len() == len)
        .then_some(bytes)
        .ok_or(DumpError::Malformed("attribute payload has wrong length"))
}

fn be_u16(bytes: &[u8]) -> Result<u16, DumpError> {
    Ok(u16::from_be_bytes(exact(bytes, 2)?.try_into().map_err(
        |_| DumpError::Malformed("invalid u16 attribute"),
    )?))
}

fn be_u32(bytes: &[u8]) -> Result<u32, DumpError> {
    Ok(u32::from_be_bytes(exact(bytes, 4)?.try_into().map_err(
        |_| DumpError::Malformed("invalid u32 attribute"),
    )?))
}

fn protocol(number: u8) -> Protocol {
    match number {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        other => Protocol::Other(other),
    }
}

fn tcp_state(state: u8) -> TcpState {
    match state {
        1 => TcpState::SynSent,
        2 => TcpState::SynRecv,
        TCP_CONNTRACK_ESTABLISHED => TcpState::Established,
        4 => TcpState::FinWait,
        5 => TcpState::CloseWait,
        6 => TcpState::LastAck,
        7 => TcpState::TimeWait,
        8 => TcpState::Close,
        other => TcpState::Unknown(other),
    }
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}
