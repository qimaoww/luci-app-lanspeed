use crate::{
    identity::{IdentityTable, MacAddress},
    platform::counters::TrafficCounters,
};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read},
    os::unix::{fs::FileTypeExt, fs::OpenOptionsExt},
    path::Path,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

pub const SOURCE: &str = "ecm_state_node_adv_stats";
const OUTPUT_MASK_PATH: &str = "/sys/kernel/debug/ecm/ecm_state/state_file_output_mask";
const DEVICE_MAJOR_PATH: &str = "/sys/kernel/debug/ecm/ecm_state/state_dev_major";
const DEVICE_PATH: &str = "/dev/ecm_state";
const NODE_OUTPUT_MASK: &str = "8\n";
const MAX_LINE_BYTES: usize = 256;
const MAX_LINES: usize = 65_536;
const MAX_NODES: usize = 16_384;
const SYNC_COUNTER_PATHS: [&str; 2] = [
    "/sys/kernel/debug/ecm/ecm_nss_ipv4/stats_request_counter",
    "/sys/kernel/debug/ecm/ecm_nss_ipv6/stats_request_counter",
];
const SYNC_COUNTER_MAX_BYTES: u64 = 256;
const SYNC_QUIET_MS: u64 = 20;
const SYNC_POLL_MS: u64 = 5;
const SYNC_SNAPSHOT_RETRIES: usize = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCounters {
    pub identity_key: String,
    pub generation: u64,
    pub counters: TrafficCounters,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ParseStats {
    pub nodes_seen: usize,
    pub nodes_matched: usize,
    pub malformed_lines: usize,
    pub ambiguous_macs: usize,
    pub sync_barrier_supported: bool,
    pub sync_barrier_wait_ms: u64,
    pub sync_snapshot_retries: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeSnapshot {
    pub sample_ms: u64,
    pub nodes: Vec<NodeCounters>,
    pub stats: ParseStats,
}

#[derive(Default)]
struct PendingNode {
    mac: Option<MacAddress>,
    generation: Option<u64>,
    tx_bytes: Option<u64>,
    rx_bytes: Option<u64>,
    tx_packets: Option<u64>,
    rx_packets: Option<u64>,
    malformed: bool,
}

pub fn parse<R: BufRead>(
    mut reader: R,
    identities: &IdentityTable,
    sample_ms: u64,
) -> io::Result<NodeSnapshot> {
    let owners = unique_mac_owners(identities);
    let mut aggregate = BTreeMap::<(String, u64), TrafficCounters>::new();
    let mut stats = ParseStats::default();
    let mut pending = PendingNode::default();
    let mut line = Vec::new();
    let mut lines = 0usize;

    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            finish_node(&mut pending, &owners, &mut aggregate, &mut stats);
            break;
        }
        lines = lines.saturating_add(1);
        if lines > MAX_LINES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ECM node snapshot line limit exceeded",
            ));
        }
        if line.len() > MAX_LINE_BYTES {
            stats.malformed_lines = stats.malformed_lines.saturating_add(1);
            pending.malformed = true;
            continue;
        }
        let Ok(text) = std::str::from_utf8(&line) else {
            stats.malformed_lines = stats.malformed_lines.saturating_add(1);
            pending.malformed = true;
            continue;
        };
        let Some((key, value)) = text.trim().split_once('=') else {
            if !text.trim().is_empty() {
                stats.malformed_lines = stats.malformed_lines.saturating_add(1);
                pending.malformed = true;
            }
            continue;
        };
        if key == "nodes.node.address" {
            finish_node(&mut pending, &owners, &mut aggregate, &mut stats);
            pending.mac = MacAddress::from_str(value).ok();
            if pending.mac.is_none() {
                pending.malformed = true;
            }
            continue;
        }
        let slot = match key {
            "nodes.node.time_added" => &mut pending.generation,
            "nodes.node.adv_stats.from_data_total" => &mut pending.tx_bytes,
            "nodes.node.adv_stats.to_data_total" => &mut pending.rx_bytes,
            "nodes.node.adv_stats.from_packet_total" => &mut pending.tx_packets,
            "nodes.node.adv_stats.to_packet_total" => &mut pending.rx_packets,
            _ => continue,
        };
        match value.parse::<u64>() {
            Ok(parsed) if slot.replace(parsed).is_none() => {}
            _ => {
                pending.malformed = true;
                stats.malformed_lines = stats.malformed_lines.saturating_add(1);
            }
        }
    }

    if aggregate.len() > MAX_NODES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ECM node snapshot node limit exceeded",
        ));
    }
    Ok(NodeSnapshot {
        sample_ms,
        nodes: aggregate
            .into_iter()
            .map(|((identity_key, generation), counters)| NodeCounters {
                identity_key,
                generation,
                counters,
            })
            .collect(),
        stats,
    })
}

fn unique_mac_owners(identities: &IdentityTable) -> BTreeMap<MacAddress, Option<String>> {
    let mut owners = BTreeMap::new();
    for identity in identities.iter() {
        owners
            .entry(identity.key.mac)
            .and_modify(|owner| *owner = None)
            .or_insert_with(|| Some(identity.key.to_string()));
    }
    owners
}

fn finish_node(
    pending: &mut PendingNode,
    owners: &BTreeMap<MacAddress, Option<String>>,
    aggregate: &mut BTreeMap<(String, u64), TrafficCounters>,
    stats: &mut ParseStats,
) {
    let current = std::mem::take(pending);
    let Some(mac) = current.mac else {
        return;
    };
    stats.nodes_seen = stats.nodes_seen.saturating_add(1);
    if current.malformed {
        return;
    }
    let Some(owner) = owners.get(&mac) else {
        return;
    };
    let Some(identity_key) = owner else {
        stats.ambiguous_macs = stats.ambiguous_macs.saturating_add(1);
        return;
    };
    let (Some(generation), Some(tx_bytes), Some(rx_bytes), Some(tx_packets), Some(rx_packets)) = (
        current.generation,
        current.tx_bytes,
        current.rx_bytes,
        current.tx_packets,
        current.rx_packets,
    ) else {
        stats.malformed_lines = stats.malformed_lines.saturating_add(1);
        return;
    };
    let totals = aggregate
        .entry((identity_key.clone(), generation))
        .or_default();
    totals.tx_bytes = totals.tx_bytes.saturating_add(tx_bytes);
    totals.rx_bytes = totals.rx_bytes.saturating_add(rx_bytes);
    totals.tx_packets = totals.tx_packets.saturating_add(tx_packets);
    totals.rx_packets = totals.rx_packets.saturating_add(rx_packets);
    stats.nodes_matched = stats.nodes_matched.saturating_add(1);
}

pub fn read(identities: &IdentityTable, sample_ms: u64) -> io::Result<NodeSnapshot> {
    let mut total_wait_ms = 0u64;
    for attempt in 0..=SYNC_SNAPSHOT_RETRIES {
        let barrier = wait_for_sync_boundary()?;
        total_wait_ms = total_wait_ms.saturating_add(barrier.wait_ms);
        let file = open_node_snapshot()?;
        let mut snapshot = parse(BufReader::new(file), identities, sample_ms)?;
        let after = read_sync_counters()?;
        if after == barrier.counters {
            snapshot.stats.sync_barrier_supported = barrier.counters.is_some();
            snapshot.stats.sync_barrier_wait_ms = total_wait_ms;
            snapshot.stats.sync_snapshot_retries = attempt;
            return Ok(snapshot);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "ECM stats synchronization changed during every node snapshot",
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SyncRequestCounter {
    success: u64,
    fail: u64,
    nack: u64,
}

type SyncCounters = [Option<SyncRequestCounter>; 2];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SyncBarrier {
    counters: Option<SyncCounters>,
    wait_ms: u64,
}

fn wait_for_sync_boundary() -> io::Result<SyncBarrier> {
    let started = Instant::now();
    let Some(previous) = read_sync_counters()? else {
        return Ok(SyncBarrier {
            counters: None,
            wait_ms: 0,
        });
    };
    loop {
        thread::sleep(Duration::from_millis(SYNC_POLL_MS));
        let Some(current) = read_sync_counters()? else {
            return Ok(SyncBarrier {
                counters: None,
                wait_ms: elapsed_ms(started),
            });
        };
        // ECM submits the next page only after the previous page callback has
        // finished. Its success counter is incremented immediately after that
        // submission, so an observed edge is the usable boundary on devices
        // whose full pagination round is longer than the one-second cadence.
        if current != previous {
            return Ok(SyncBarrier {
                counters: Some(current),
                wait_ms: elapsed_ms(started),
            });
        }
        if started.elapsed() >= Duration::from_millis(SYNC_QUIET_MS) {
            return Ok(SyncBarrier {
                counters: Some(current),
                wait_ms: elapsed_ms(started),
            });
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn read_sync_counters() -> io::Result<Option<SyncCounters>> {
    let counters = [
        read_sync_counter(SYNC_COUNTER_PATHS[0])?,
        read_sync_counter(SYNC_COUNTER_PATHS[1])?,
    ];
    Ok(counters.iter().any(Option::is_some).then_some(counters))
}

fn read_sync_counter(path: &str) -> io::Result<Option<SyncRequestCounter>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(SYNC_COUNTER_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > SYNC_COUNTER_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ECM stats request counter is too large",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    parse_sync_counter(text).map(Some)
}

fn parse_sync_counter(text: &str) -> io::Result<SyncRequestCounter> {
    let mut success = None;
    let mut fail = None;
    let mut nack = None;
    for field in text.split_whitespace() {
        let Some((name, value)) = field.split_once('=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ECM stats request counter field",
            ));
        };
        let slot = match name {
            "success" => &mut success,
            "fail" => &mut fail,
            "nack" => &mut nack,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown ECM stats request counter field",
                ))
            }
        };
        let parsed = value
            .parse::<u64>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if slot.replace(parsed).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate ECM stats request counter field",
            ));
        }
    }
    let (Some(success), Some(fail), Some(nack)) = (success, fail, nack) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete ECM stats request counter",
        ));
    };
    Ok(SyncRequestCounter {
        success,
        fail,
        nack,
    })
}

fn open_node_snapshot() -> io::Result<File> {
    let old_mask = fs::read_to_string(OUTPUT_MASK_PATH)?;
    fs::write(OUTPUT_MASK_PATH, NODE_OUTPUT_MASK)?;
    let opened = open_state_device();
    let restored = fs::write(OUTPUT_MASK_PATH, old_mask);
    match (opened, restored) {
        (Ok(file), Ok(())) => Ok(file),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn open_state_device() -> io::Result<File> {
    if Path::new(DEVICE_PATH).exists() {
        return open_char_device(Path::new(DEVICE_PATH));
    }
    let major = fs::read_to_string(DEVICE_MAJOR_PATH)?
        .trim()
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let path = format!("/dev/lanspeed-ecm-node-{}", std::process::id());
    let c_path = CString::new(path.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid ECM device path"))?;
    let device = libc::makedev(major as _, 0);
    let result = unsafe { libc::mknod(c_path.as_ptr(), libc::S_IFCHR | 0o600, device) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let opened = open_char_device(Path::new(&path));
    let removed = fs::remove_file(&path);
    match (opened, removed) {
        (Ok(file), Ok(())) => Ok(file),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn open_char_device(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.file_type().is_char_device() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ECM state path is not a character device",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityObservation, ObservationSource};
    use std::io::Cursor;

    fn identities() -> IdentityTable {
        let mut identities = IdentityTable::new(8);
        identities
            .observe(IdentityObservation {
                mac: "02:00:00:00:20:11",
                zone: Some("lan"),
                interface: "br-lan",
                ip: Some("192.0.2.11"),
                hostname: None,
                last_seen: 1,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
        identities
    }

    #[test]
    fn parses_real_node_byte_and_packet_fields() {
        let input = b"nodes.node.address=02:00:00:00:20:11\n\
nodes.node.time_added=253299\n\
nodes.node.adv_stats.from_data_total=76397571826\n\
nodes.node.adv_stats.to_data_total=214196693537\n\
nodes.node.adv_stats.from_packet_total=124040373\n\
nodes.node.adv_stats.to_packet_total=148402900\n";
        let snapshot = parse(Cursor::new(input), &identities(), 42).unwrap();
        assert_eq!(snapshot.stats.nodes_seen, 1);
        assert_eq!(snapshot.stats.nodes_matched, 1);
        assert_eq!(snapshot.nodes[0].generation, 253299);
        assert_eq!(snapshot.nodes[0].counters.tx_bytes, 76_397_571_826);
        assert_eq!(snapshot.nodes[0].counters.rx_packets, 148_402_900);
    }

    #[test]
    fn rejects_incomplete_node_without_fabricating_packets() {
        let input = b"nodes.node.address=02:00:00:00:20:11\n\
nodes.node.time_added=1\n\
nodes.node.adv_stats.from_data_total=10\n\
nodes.node.adv_stats.to_data_total=20\n";
        let snapshot = parse(Cursor::new(input), &identities(), 42).unwrap();
        assert!(snapshot.nodes.is_empty());
        assert_eq!(snapshot.stats.malformed_lines, 1);
    }

    #[test]
    fn parses_complete_sync_request_counter() {
        assert_eq!(
            parse_sync_counter("success=16700526\tfail=0\tnack=0\t\n").unwrap(),
            SyncRequestCounter {
                success: 16_700_526,
                fail: 0,
                nack: 0,
            }
        );
    }

    #[test]
    fn rejects_incomplete_sync_request_counter() {
        let error = parse_sync_counter("success=1 fail=0").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("incomplete"));
    }

    #[test]
    fn rejects_duplicate_sync_request_counter_field() {
        let error = parse_sync_counter("success=1 fail=0 nack=0 success=2").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn rejects_unknown_sync_request_counter_field() {
        let error = parse_sync_counter("success=1 fail=0 nack=0 pending=1").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unknown"));
    }
}
