use crate::connection_details::{ConnectionCountersSnapshot, ConnectionDetailsSnapshot};
use aggregate::{aggregate_flows, ClientSample};
use netlink::{DumpError, NetlinkAggregateSnapshot, NetlinkSnapshot};
use procfs::{ProcfsError, ProcfsSnapshot};
use std::net::IpAddr;

pub mod aggregate;
pub mod netlink;
pub mod procfs;

pub const NETLINK_SOURCE_PATH: &str = "netlink:ctnetlink";
pub const NETLINK_COUNTER_SOURCE: &str = "ctnetlink_conntrack_acct_orig_reply_bytes";
pub const PROCFS_COUNTER_SOURCE: &str = "procfs_conntrack_acct_orig_reply_bytes";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Other(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpState {
    SynSent,
    SynRecv,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    TimeWait,
    Close,
    Unknown(u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowSample {
    pub orig_src: Option<IpAddr>,
    pub orig_dst: Option<IpAddr>,
    pub reply_src: Option<IpAddr>,
    pub reply_dst: Option<IpAddr>,
    pub orig_bytes: u64,
    pub reply_bytes: u64,
    pub orig_sport: u16,
    pub orig_dport: u16,
    pub reply_sport: u16,
    pub reply_dport: u16,
    pub protocol: Protocol,
    pub tcp_state: Option<TcpState>,
    pub assured: bool,
}

impl Default for FlowSample {
    fn default() -> Self {
        Self {
            orig_src: None,
            orig_dst: None,
            reply_src: None,
            reply_dst: None,
            orig_bytes: 0,
            reply_bytes: 0,
            orig_sport: 0,
            orig_dport: 0,
            reply_sport: 0,
            reply_dport: 0,
            protocol: Protocol::Other(0),
            tcp_state: None,
            assured: false,
        }
    }
}

impl FlowSample {
    pub fn is_dns(&self) -> bool {
        self.protocol == Protocol::Udp
            && [
                self.orig_sport,
                self.orig_dport,
                self.reply_sport,
                self.reply_dport,
            ]
            .contains(&53)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorMode {
    Auto,
    Netlink,
    Procfs,
}

#[derive(Debug)]
pub enum CollectorReadError {
    Netlink(DumpError),
    Procfs(ProcfsError),
}

impl std::fmt::Display for CollectorReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Netlink(error) => error.fmt(formatter),
            Self::Procfs(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CollectorReadError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CollectStats {
    pub source_path: String,
    pub netlink_attempted: bool,
    pub netlink_read: bool,
    pub procfs_read: bool,
    pub netlink_errno: Option<i32>,
    pub current_clients: usize,
    pub emitted_clients: usize,
    pub snapshot_pending: bool,
    pub skipped_no_arp: usize,
    pub no_lan_flows: usize,
    pub both_lan_flows: usize,
    pub src_lan_flows: usize,
    pub dst_lan_flows: usize,
    pub ipv4_lan_flows: usize,
    pub ipv6_lan_flows: usize,
    pub malformed_lines: usize,
    pub entries_seen: usize,
    pub entries_matched: usize,
    pub clients_dropped: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectedSnapshot {
    pub clients: Vec<ClientSample>,
    pub sample_ms: u64,
    pub connection_details: ConnectionDetailsSnapshot,
    pub connection_counters: ConnectionCountersSnapshot,
    pub counter_source: &'static str,
    pub stats: CollectStats,
}

pub fn collect_with<N, P>(
    mode: CollectorMode,
    identities: &crate::identity::IdentityTable,
    now_ms: u64,
    max_clients: usize,
    netlink: N,
    procfs: P,
) -> Result<CollectedSnapshot, CollectorReadError>
where
    N: FnOnce() -> Result<NetlinkSnapshot, CollectorReadError>,
    P: FnOnce() -> Result<ProcfsSnapshot, CollectorReadError>,
{
    match mode {
        CollectorMode::Procfs => {
            finish_procfs(procfs()?, identities, now_ms, max_clients, false, None)
        }
        CollectorMode::Netlink => finish_netlink(netlink()?, identities, now_ms, max_clients),
        CollectorMode::Auto => match netlink() {
            Ok(snapshot) => finish_netlink(snapshot, identities, now_ms, max_clients),
            Err(netlink_error) => {
                let errno = netlink_errno(&netlink_error);
                match procfs() {
                    Ok(snapshot) => {
                        finish_procfs(snapshot, identities, now_ms, max_clients, true, errno)
                    }
                    Err(_) => Err(netlink_error),
                }
            }
        },
    }
}

pub fn collect(
    mode: CollectorMode,
    identities: &crate::identity::IdentityTable,
    now_ms: u64,
    max_clients: usize,
) -> Result<CollectedSnapshot, CollectorReadError> {
    collect_aggregate_with(
        mode,
        || {
            netlink::read_aggregate(identities, now_ms, max_clients)
                .map_err(CollectorReadError::Netlink)
        },
        || {
            procfs::read_aggregate(identities, now_ms, max_clients)
                .map_err(CollectorReadError::Procfs)
        },
    )
}

fn collect_aggregate_with<N, P>(
    mode: CollectorMode,
    netlink: N,
    procfs: P,
) -> Result<CollectedSnapshot, CollectorReadError>
where
    N: FnOnce() -> Result<NetlinkAggregateSnapshot, CollectorReadError>,
    P: FnOnce() -> Result<procfs::ProcfsAggregateSnapshot, CollectorReadError>,
{
    match mode {
        CollectorMode::Netlink => finish_netlink_aggregate(netlink()?),
        CollectorMode::Procfs => finish_procfs_aggregate(procfs()?, false, None),
        CollectorMode::Auto => match netlink() {
            Ok(snapshot) => finish_netlink_aggregate(snapshot),
            Err(netlink_error) => {
                let errno = netlink_errno(&netlink_error);
                match procfs() {
                    Ok(snapshot) => finish_procfs_aggregate(snapshot, true, errno),
                    Err(_) => Err(netlink_error),
                }
            }
        },
    }
}

fn finish_netlink_aggregate(
    snapshot: NetlinkAggregateSnapshot,
) -> Result<CollectedSnapshot, CollectorReadError> {
    let stats = stats_from_aggregate(
        &snapshot.aggregate,
        snapshot.source_path,
        true,
        true,
        false,
        None,
        snapshot.malformed_entries,
        snapshot.entries_seen,
    );
    Ok(finish_aggregate(
        snapshot.aggregate,
        snapshot.counter_source,
        stats,
    ))
}

fn finish_procfs_aggregate(
    snapshot: procfs::ProcfsAggregateSnapshot,
    netlink_attempted: bool,
    netlink_errno: Option<i32>,
) -> Result<CollectedSnapshot, CollectorReadError> {
    let stats = stats_from_aggregate(
        &snapshot.aggregate,
        &snapshot.source_path,
        netlink_attempted,
        false,
        true,
        netlink_errno,
        snapshot.malformed_lines,
        snapshot.entries_seen,
    );
    Ok(finish_aggregate(
        snapshot.aggregate,
        snapshot.counter_source,
        stats,
    ))
}

fn finish_netlink(
    snapshot: NetlinkSnapshot,
    identities: &crate::identity::IdentityTable,
    now_ms: u64,
    max_clients: usize,
) -> Result<CollectedSnapshot, CollectorReadError> {
    let entries_seen = snapshot
        .flows
        .len()
        .saturating_add(snapshot.malformed_entries);
    let aggregate = aggregate_flows(identities, snapshot.flows.iter(), now_ms, max_clients);
    let stats = stats_from_aggregate(
        &aggregate,
        snapshot.source_path,
        true,
        true,
        false,
        None,
        snapshot.malformed_entries,
        entries_seen,
    );
    Ok(finish_aggregate(aggregate, snapshot.counter_source, stats))
}

fn finish_procfs(
    snapshot: ProcfsSnapshot,
    identities: &crate::identity::IdentityTable,
    now_ms: u64,
    max_clients: usize,
    netlink_attempted: bool,
    netlink_errno: Option<i32>,
) -> Result<CollectedSnapshot, CollectorReadError> {
    let aggregate = aggregate_flows(identities, snapshot.flows.iter(), now_ms, max_clients);
    let stats = stats_from_aggregate(
        &aggregate,
        &snapshot.source_path,
        netlink_attempted,
        false,
        true,
        netlink_errno,
        snapshot.malformed_lines,
        snapshot.entries_seen,
    );
    Ok(finish_aggregate(aggregate, snapshot.counter_source, stats))
}

fn finish_aggregate(
    aggregate: aggregate::AggregateSnapshot,
    counter_source: &'static str,
    stats: CollectStats,
) -> CollectedSnapshot {
    CollectedSnapshot {
        clients: aggregate.clients,
        sample_ms: aggregate.sample_ms,
        connection_details: aggregate.connection_details,
        connection_counters: aggregate.connection_counters,
        counter_source,
        stats,
    }
}

fn stats_from_aggregate(
    snapshot: &aggregate::AggregateSnapshot,
    source_path: &str,
    netlink_attempted: bool,
    netlink_read: bool,
    procfs_read: bool,
    netlink_errno: Option<i32>,
    malformed_lines: usize,
    entries_seen: usize,
) -> CollectStats {
    CollectStats {
        source_path: source_path.to_owned(),
        netlink_attempted,
        netlink_read,
        procfs_read,
        netlink_errno,
        current_clients: snapshot.clients.len(),
        emitted_clients: 0,
        snapshot_pending: false,
        skipped_no_arp: snapshot.stats.skipped_no_arp,
        no_lan_flows: snapshot.stats.no_lan_flows,
        both_lan_flows: snapshot.stats.both_lan_flows,
        src_lan_flows: snapshot.stats.src_lan_flows,
        dst_lan_flows: snapshot.stats.dst_lan_flows,
        ipv4_lan_flows: snapshot.stats.ipv4_lan_flows,
        ipv6_lan_flows: snapshot.stats.ipv6_lan_flows,
        malformed_lines,
        entries_seen,
        entries_matched: snapshot.stats.entries_matched,
        clients_dropped: snapshot.stats.clients_dropped,
    }
}

fn netlink_errno(error: &CollectorReadError) -> Option<i32> {
    match error {
        CollectorReadError::Netlink(DumpError::Kernel(error)) => error.raw_os_error(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        collectors::conntrack::aggregate::{AggregateSnapshot, AggregateStats, ClientSample},
        connection_details::{
            ClientConnectionDetail, ConnectionDetailsIndex, ConnectionDirection,
            ConnectionProtocol, ConnectionState,
        },
        identity::{IdentityObservation, IdentityTable, ObservationSource},
    };
    use std::{cell::Cell, sync::Arc};

    #[test]
    fn production_netlink_modes_use_streaming_aggregate_and_match_vec_helper() {
        let mut identities = IdentityTable::new(4);
        identities
            .observe(IdentityObservation {
                mac: "02:00:00:00:00:01",
                zone: Some("lan"),
                interface: "br-lan",
                ip: Some("192.0.2.10"),
                hostname: None,
                last_seen: 1,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
        let flow = FlowSample {
            orig_src: Some("192.0.2.10".parse().unwrap()),
            orig_dst: Some("1.1.1.1".parse().unwrap()),
            reply_src: Some("1.1.1.1".parse().unwrap()),
            reply_dst: Some("192.0.2.10".parse().unwrap()),
            orig_bytes: 100,
            reply_bytes: 250,
            orig_sport: 50_123,
            orig_dport: 443,
            reply_sport: 443,
            reply_dport: 50_123,
            protocol: Protocol::Tcp,
            tcp_state: Some(TcpState::Established),
            assured: true,
        };
        let now_ms = 91_337;
        let expected = finish_netlink(
            NetlinkSnapshot {
                flows: vec![flow.clone()],
                source_path: NETLINK_SOURCE_PATH,
                counter_source: NETLINK_COUNTER_SOURCE,
                malformed_entries: 1,
            },
            &identities,
            now_ms,
            8,
        )
        .unwrap();
        let aggregate = aggregate_flows(&identities, [&flow], now_ms, 8);
        let streaming_snapshot = || NetlinkAggregateSnapshot {
            aggregate: aggregate.clone(),
            source_path: NETLINK_SOURCE_PATH,
            counter_source: NETLINK_COUNTER_SOURCE,
            malformed_entries: 1,
            entries_seen: 2,
        };

        let procfs_called = Cell::new(false);
        let netlink = collect_aggregate_with(
            CollectorMode::Netlink,
            || Ok(streaming_snapshot()),
            || {
                procfs_called.set(true);
                unreachable!()
            },
        )
        .unwrap();
        assert!(!procfs_called.get());
        assert_eq!(netlink, expected);

        let procfs_called = Cell::new(false);
        let automatic = collect_aggregate_with(
            CollectorMode::Auto,
            || Ok(streaming_snapshot()),
            || {
                procfs_called.set(true);
                unreachable!()
            },
        )
        .unwrap();
        assert!(!procfs_called.get());
        assert_eq!(automatic, expected);
        assert_eq!(automatic.connection_details, expected.connection_details);
        assert_eq!(automatic.connection_counters, expected.connection_counters);
        assert_eq!(automatic.stats, expected.stats);
    }

    #[test]
    fn streaming_procfs_finish_preserves_shared_details_timestamp_and_fallback_stats() {
        let mut details = ConnectionDetailsIndex::default();
        details.record(
            "02:00:00:00:00:01@lan",
            ClientConnectionDetail {
                client_ip: "192.0.2.10".parse().unwrap(),
                client_port: 50_123,
                remote_ip: "1.1.1.1".parse().unwrap(),
                remote_port: 443,
                protocol: ConnectionProtocol::Tcp,
                state: ConnectionState::Established,
                direction: ConnectionDirection::Outbound,
                tx_bps: 0,
                rx_bps: 0,
            },
        );
        let details = details.finish();
        let retained_details = Arc::clone(&details);
        let snapshot = procfs::ProcfsAggregateSnapshot {
            aggregate: AggregateSnapshot {
                clients: vec![ClientSample {
                    mac: "02:00:00:00:00:01".into(),
                    identity_key: "02:00:00:00:00:01@lan".into(),
                    zone: "lan".into(),
                    interface: "lan".into(),
                    ips: vec!["192.0.2.10".into()],
                    tx_bytes: 100,
                    rx_bytes: 250,
                    last_seen_ms: 91_337,
                    tcp_conns: 1,
                    udp_conns: 0,
                    udp_dns_conns: 0,
                    udp_other_conns: 0,
                }],
                stats: AggregateStats {
                    entries_seen: 1,
                    entries_matched: 1,
                    src_lan_flows: 1,
                    ipv4_lan_flows: 1,
                    ..AggregateStats::default()
                },
                sample_ms: 91_337,
                connection_details: details,
                connection_counters: Default::default(),
            },
            source_path: "/proc/net/nf_conntrack".into(),
            counter_source: PROCFS_COUNTER_SOURCE,
            entries_seen: 3,
            malformed_lines: 2,
        };

        let collected = finish_procfs_aggregate(snapshot, true, Some(libc::EPERM)).unwrap();

        assert_eq!(collected.sample_ms, 91_337);
        assert!(Arc::ptr_eq(
            &retained_details,
            &collected.connection_details
        ));
        assert_eq!(
            collected.connection_details["02:00:00:00:00:01@lan"].total_connections,
            1
        );
        assert_eq!(collected.counter_source, PROCFS_COUNTER_SOURCE);
        assert_eq!(collected.stats.source_path, "/proc/net/nf_conntrack");
        assert!(collected.stats.netlink_attempted);
        assert!(!collected.stats.netlink_read);
        assert!(collected.stats.procfs_read);
        assert_eq!(collected.stats.netlink_errno, Some(libc::EPERM));
        assert_eq!(collected.stats.current_clients, 1);
        assert_eq!(collected.stats.entries_seen, 3);
        assert_eq!(collected.stats.entries_matched, 1);
        assert_eq!(collected.stats.malformed_lines, 2);
        assert_eq!(collected.stats.src_lan_flows, 1);
        assert_eq!(collected.stats.ipv4_lan_flows, 1);
    }
}
