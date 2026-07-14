use super::{FlowSample, Protocol, TcpState, PROCFS_COUNTER_SOURCE};
use crate::{
    collectors::conntrack::aggregate::{AggregateSnapshot, AggregateState},
    identity::IdentityTable,
};
use std::{
    fs::File,
    io::{self, BufRead, BufReader},
};

pub const CONNTRACK_LINE_MAX: usize = 1024;
pub const CONNTRACK_PROCFS_PATH: &str = "/proc/net/nf_conntrack";
pub const CONNTRACK_LEGACY_PROCFS_PATH: &str = "/proc/net/ip_conntrack";
pub const PROCFS_PARSE_FLOW_CAP: usize = 4096;

#[derive(Debug)]
pub enum ProcfsError {
    Io(io::Error),
    FlowLimit(usize),
}

impl std::fmt::Display for ProcfsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "failed to read conntrack procfs: {error}"),
            Self::FlowLimit(limit) => write!(
                formatter,
                "conntrack procfs test snapshot exceeded {limit} flows"
            ),
        }
    }
}

impl std::error::Error for ProcfsError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcfsSnapshot {
    pub flows: Vec<FlowSample>,
    pub source_path: String,
    pub counter_source: &'static str,
    pub entries_seen: usize,
    pub malformed_lines: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcfsAggregateSnapshot {
    pub aggregate: AggregateSnapshot,
    pub source_path: String,
    pub counter_source: &'static str,
    pub entries_seen: usize,
    pub malformed_lines: usize,
}

pub fn parse_reader<R: BufRead>(
    mut reader: R,
    source_path: &str,
) -> Result<ProcfsSnapshot, ProcfsError> {
    let mut flows = Vec::new();
    let (entries_seen, malformed_lines) = visit_reader(&mut reader, |flow| {
        if flows.len() >= PROCFS_PARSE_FLOW_CAP {
            return Err(ProcfsError::FlowLimit(PROCFS_PARSE_FLOW_CAP));
        }
        flows.push(flow);
        Ok(())
    })?;
    Ok(ProcfsSnapshot {
        flows,
        source_path: source_path.to_owned(),
        counter_source: PROCFS_COUNTER_SOURCE,
        entries_seen,
        malformed_lines,
    })
}

pub fn aggregate_reader<R: BufRead>(
    mut reader: R,
    source_path: &str,
    identities: &IdentityTable,
    now_ms: u64,
    max_clients: usize,
) -> Result<ProcfsAggregateSnapshot, ProcfsError> {
    let mut aggregate = AggregateState::new(identities, now_ms, max_clients);
    let (entries_seen, malformed_lines) = visit_reader(&mut reader, |flow| {
        aggregate.push(&flow);
        Ok(())
    })?;
    Ok(ProcfsAggregateSnapshot {
        aggregate: aggregate.finish(),
        source_path: source_path.to_owned(),
        counter_source: PROCFS_COUNTER_SOURCE,
        entries_seen,
        malformed_lines,
    })
}

fn visit_reader<R: BufRead>(
    reader: &mut R,
    mut visit: impl FnMut(FlowSample) -> Result<(), ProcfsError>,
) -> Result<(usize, usize), ProcfsError> {
    let mut entries_seen = 0usize;
    let mut malformed_lines = 0usize;
    while let Some((line, oversized)) = read_bounded_line(reader)? {
        entries_seen = entries_seen.saturating_add(1);
        if oversized {
            malformed_lines = malformed_lines.saturating_add(1);
            continue;
        }
        match parse_line(&line) {
            Some(flow) => visit(flow)?,
            None => malformed_lines = malformed_lines.saturating_add(1),
        }
    }
    Ok((entries_seen, malformed_lines))
}

pub fn read_snapshot() -> Result<ProcfsSnapshot, ProcfsError> {
    match File::open(CONNTRACK_PROCFS_PATH) {
        Ok(file) => parse_reader(BufReader::new(file), CONNTRACK_PROCFS_PATH),
        Err(primary) => match File::open(CONNTRACK_LEGACY_PROCFS_PATH) {
            Ok(file) => parse_reader(BufReader::new(file), CONNTRACK_LEGACY_PROCFS_PATH),
            Err(_) => Err(ProcfsError::Io(primary)),
        },
    }
}

pub fn read_aggregate(
    identities: &IdentityTable,
    now_ms: u64,
    max_clients: usize,
) -> Result<ProcfsAggregateSnapshot, ProcfsError> {
    match File::open(CONNTRACK_PROCFS_PATH) {
        Ok(file) => aggregate_reader(
            BufReader::new(file),
            CONNTRACK_PROCFS_PATH,
            identities,
            now_ms,
            max_clients,
        ),
        Err(primary) => match File::open(CONNTRACK_LEGACY_PROCFS_PATH) {
            Ok(file) => aggregate_reader(
                BufReader::new(file),
                CONNTRACK_LEGACY_PROCFS_PATH,
                identities,
                now_ms,
                max_clients,
            ),
            Err(_) => Err(ProcfsError::Io(primary)),
        },
    }
}

fn read_bounded_line<R: BufRead>(reader: &mut R) -> Result<Option<(Vec<u8>, bool)>, ProcfsError> {
    let mut line = Vec::new();
    let mut oversized = false;
    let mut saw_data = false;
    loop {
        let available = reader.fill_buf().map_err(ProcfsError::Io)?;
        if available.is_empty() {
            return Ok(saw_data.then_some((line, oversized)));
        }
        saw_data = true;
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if !oversized {
            let room = CONNTRACK_LINE_MAX.saturating_sub(line.len());
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

fn parse_line(bytes: &[u8]) -> Option<FlowSample> {
    let line = std::str::from_utf8(bytes).ok()?;
    let tokens: Vec<&str> = line.split_ascii_whitespace().collect();
    let protocol = match *tokens.get(2)? {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => Protocol::Other(tokens.get(3)?.parse().ok()?),
    };
    let tcp_state = (protocol == Protocol::Tcp
        && tokens
            .get(4)
            .is_some_and(|value| value.parse::<u64>().is_ok()))
    .then(|| parse_tcp_state(tokens.get(5).copied().unwrap_or("")));
    let mut flow = FlowSample {
        protocol,
        tcp_state,
        ..FlowSample::default()
    };
    let mut src = 0usize;
    let mut dst = 0usize;
    let mut sport = 0usize;
    let mut dport = 0usize;
    let mut bytes_seen = 0usize;
    let mut has_orig_bytes = false;
    let mut offloaded = false;
    let mut unreplied = false;
    for token in tokens {
        if let Some(value) = token.strip_prefix("src=") {
            if let Ok(value) = value.parse() {
                if src == 0 {
                    flow.orig_src = Some(value);
                } else if src == 1 {
                    flow.reply_src = Some(value);
                }
            }
            src = src.saturating_add(1);
        } else if let Some(value) = token.strip_prefix("dst=") {
            if let Ok(value) = value.parse() {
                if dst == 0 {
                    flow.orig_dst = Some(value);
                } else if dst == 1 {
                    flow.reply_dst = Some(value);
                }
            }
            dst = dst.saturating_add(1);
        } else if let Some(value) = token.strip_prefix("sport=") {
            if let Ok(value) = value.parse::<u16>() {
                if sport == 0 {
                    flow.orig_sport = value;
                } else if sport == 1 {
                    flow.reply_sport = value;
                }
            }
            sport = sport.saturating_add(1);
        } else if let Some(value) = token.strip_prefix("dport=") {
            if let Ok(value) = value.parse::<u16>() {
                if dport == 0 {
                    flow.orig_dport = value;
                } else if dport == 1 {
                    flow.reply_dport = value;
                }
            }
            dport = dport.saturating_add(1);
        } else if let Some(value) = token.strip_prefix("bytes=") {
            if let Ok(value) = value.parse::<u64>() {
                if bytes_seen == 0 {
                    flow.orig_bytes = value;
                    has_orig_bytes = true;
                } else if bytes_seen == 1 {
                    flow.reply_bytes = value;
                }
            }
            bytes_seen = bytes_seen.saturating_add(1);
        } else if token == "[ASSURED]" {
            flow.assured = true;
        } else if token == "[UNREPLIED]" {
            unreplied = true;
        } else if matches!(token, "[OFFLOAD]" | "[HW_OFFLOAD]") {
            // For replied flow-offloaded entries, the kernel prints this
            // marker instead of ASSURED and suppresses the TCP state.
            offloaded = true;
        }
    }
    if unreplied {
        flow.assured = false;
    } else if offloaded {
        flow.assured = true;
    }
    if offloaded && !unreplied && protocol == Protocol::Tcp && flow.tcp_state.is_none() {
        flow.tcp_state = Some(TcpState::Established);
    }
    (flow.orig_src.is_some() && has_orig_bytes).then_some(flow)
}

fn parse_tcp_state(value: &str) -> TcpState {
    match value {
        "SYN_SENT" => TcpState::SynSent,
        "SYN_RECV" => TcpState::SynRecv,
        "ESTABLISHED" => TcpState::Established,
        "FIN_WAIT" => TcpState::FinWait,
        "CLOSE_WAIT" => TcpState::CloseWait,
        "LAST_ACK" => TcpState::LastAck,
        "TIME_WAIT" => TcpState::TimeWait,
        "CLOSE" => TcpState::Close,
        _ => TcpState::Unknown(u8::MAX),
    }
}
