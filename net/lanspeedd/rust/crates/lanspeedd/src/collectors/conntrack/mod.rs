use aggregate::{aggregate_flows, ClientSample};
use netlink::{DumpError, NetlinkSnapshot};
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
    match mode {
        CollectorMode::Netlink => finish_netlink(
            netlink::read_snapshot().map_err(CollectorReadError::Netlink)?,
            identities,
            now_ms,
            max_clients,
        ),
        CollectorMode::Procfs => finish_procfs_aggregate(
            procfs::read_aggregate(identities, now_ms, max_clients)
                .map_err(CollectorReadError::Procfs)?,
            false,
            None,
        ),
        CollectorMode::Auto => match netlink::read_snapshot() {
            Ok(snapshot) => finish_netlink(snapshot, identities, now_ms, max_clients),
            Err(netlink_error) => {
                let errno = match &netlink_error {
                    DumpError::Kernel(error) => error.raw_os_error(),
                    _ => None,
                };
                match procfs::read_aggregate(identities, now_ms, max_clients) {
                    Ok(snapshot) => finish_procfs_aggregate(snapshot, true, errno),
                    Err(_) => Err(CollectorReadError::Netlink(netlink_error)),
                }
            }
        },
    }
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
    Ok(CollectedSnapshot {
        clients: snapshot.aggregate.clients,
        counter_source: snapshot.counter_source,
        stats,
    })
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
    Ok(CollectedSnapshot {
        clients: aggregate.clients,
        counter_source: snapshot.counter_source,
        stats,
    })
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
    Ok(CollectedSnapshot {
        clients: aggregate.clients,
        counter_source: snapshot.counter_source,
        stats,
    })
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
