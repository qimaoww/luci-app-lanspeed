use std::{collections::BTreeMap, sync::Arc};

use serde_json::Value;

use crate::{
    collectors::conntrack::CollectedSnapshot,
    model::{Client, ClientsResponse, OverviewSample},
    policy::RateCollector,
    probe::RuntimeHealth,
    state::{ResponseSnapshot, CONNECTION_SEMANTICS},
    ubus::Method,
};

pub(crate) const CONNECTION_ONLY_WARNING: &str = "conntrack_connection_only";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeriodicConntrackPlan {
    Skip,
    Read,
}

// Reuse concurrent requests, but do not carry a conntrack snapshot across the
// minimum LuCI refresh interval.
pub const CLIENT_CONNTRACK_CACHE_TTL_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientConntrackPlan {
    ReuseCached,
    Read,
}

pub const fn client_conntrack_plan(
    now_ms: u64,
    last_attempt_ms: Option<u64>,
    snapshot_available: bool,
) -> ClientConntrackPlan {
    let Some(last_attempt_ms) = last_attempt_ms else {
        return ClientConntrackPlan::Read;
    };
    if snapshot_available
        && now_ms >= last_attempt_ms
        && now_ms - last_attempt_ms < CLIENT_CONNTRACK_CACHE_TTL_MS
    {
        ClientConntrackPlan::ReuseCached
    } else {
        ClientConntrackPlan::Read
    }
}

pub const fn periodic_conntrack_plan(rate_collector: RateCollector) -> PeriodicConntrackPlan {
    match rate_collector {
        RateCollector::NssConntrackSync => PeriodicConntrackPlan::Read,
        RateCollector::Bpf | RateCollector::NssEcmDirect | RateCollector::Unsupported => {
            PeriodicConntrackPlan::Skip
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConntrackObservationState {
    #[default]
    Skipped,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConntrackObservation {
    pub state: ConntrackObservationState,
    pub last_attempt_ms: Option<u64>,
    pub netlink_read: bool,
    pub procfs_read: bool,
    pub error: Option<String>,
}

impl ConntrackObservation {
    pub fn apply_runtime_health(
        &self,
        snapshot_available: bool,
        runtime_health: &mut RuntimeHealth,
    ) {
        if self.state == ConntrackObservationState::Skipped && self.last_attempt_ms.is_none() {
            return;
        }

        runtime_health.conntrack_netlink_available = self.netlink_read;
        runtime_health.conntrack_procfs_available = self.procfs_read;
        runtime_health.nss_sync_read_ok = Some(match self.state {
            ConntrackObservationState::Succeeded => true,
            ConntrackObservationState::Failed => false,
            ConntrackObservationState::Skipped => snapshot_available,
        });
    }

    pub fn record_skipped(&mut self) {
        self.state = ConntrackObservationState::Skipped;
    }

    pub fn record_success(&mut self, now_ms: u64, netlink_read: bool, procfs_read: bool) {
        self.state = ConntrackObservationState::Succeeded;
        self.last_attempt_ms = Some(now_ms);
        self.netlink_read = netlink_read;
        self.procfs_read = procfs_read;
        self.error = None;
    }

    pub fn record_failure(
        &mut self,
        now_ms: u64,
        error: impl Into<String>,
        netlink_read: bool,
        procfs_read: bool,
    ) {
        self.state = ConntrackObservationState::Failed;
        self.last_attempt_ms = Some(now_ms);
        self.netlink_read = netlink_read;
        self.procfs_read = procfs_read;
        self.error = Some(error.into());
    }

    pub fn restore(&mut self, checkpoint: Self) {
        *self = checkpoint;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeforeReplyAction {
    None,
    RefreshConnections,
    Reload,
}

pub const fn before_reply_action(method: Method) -> BeforeReplyAction {
    match method {
        Method::Clients | Method::ClientConnections => BeforeReplyAction::RefreshConnections,
        Method::Reload => BeforeReplyAction::Reload,
        Method::Status
        | Method::Overview
        | Method::Health
        | Method::Interfaces
        | Method::Sysdevices
        | Method::Diagnostics => BeforeReplyAction::None,
    }
}

pub(crate) fn publish_connection_details(
    snapshot: &mut ResponseSnapshot,
    collected: Option<&CollectedSnapshot>,
) {
    match collected {
        Some(collected)
            if collected.stats.malformed_lines != 0 || collected.stats.clients_dropped != 0 =>
        {
            snapshot.replace_incomplete_connection_details(
                collected.sample_ms,
                conntrack_source(collected).to_owned(),
            );
        }
        Some(collected) => {
            snapshot.replace_connection_details(
                collected.sample_ms,
                conntrack_source(collected).to_owned(),
                Arc::clone(&collected.connection_details),
            );
        }
        None => snapshot.clear_connection_details(),
    }
}

pub fn apply_conntrack_success(
    snapshot: &ResponseSnapshot,
    collected: &CollectedSnapshot,
    collector_mode: &str,
) -> ResponseSnapshot {
    let mut overlaid = snapshot.clone();
    publish_connection_details(&mut overlaid, Some(collected));
    let by_identity = collected
        .clients
        .iter()
        .map(|client| (client.identity_key.as_str(), client))
        .collect::<BTreeMap<_, _>>();
    overlaid.clients.clients.retain(|client| {
        !is_connection_only(client)
            || by_identity
                .get(client.identity_key.as_str())
                .is_some_and(|sample| has_counted_connections(sample))
    });

    for client in &mut overlaid.clients.clients {
        let counts = by_identity.get(client.identity_key.as_str()).copied();
        client.tcp_conns = Some(counts.map_or(0, |sample| u64::from(sample.tcp_conns)));
        client.udp_conns = Some(counts.map_or(0, |sample| u64::from(sample.udp_conns)));
        client.udp_dns_conns = Some(counts.map_or(0, |sample| u64::from(sample.udp_dns_conns)));
        client.udp_other_conns = Some(counts.map_or(0, |sample| u64::from(sample.udp_other_conns)));
    }

    for sample in &collected.clients {
        if !has_counted_connections(sample)
            || overlaid
                .clients
                .clients
                .iter()
                .any(|client| client.identity_key == sample.identity_key)
        {
            continue;
        }
        overlaid.clients.clients.push(Client {
            mac: sample.mac.clone(),
            identity_key: sample.identity_key.clone(),
            zone: sample.zone.clone(),
            interface: sample.interface.clone(),
            ips: sample.ips.clone(),
            hostname: None,
            rx_bps: 0,
            tx_bps: 0,
            last_seen: sample.last_seen_ms,
            sample_ms: Some(sample.last_seen_ms),
            rx_bytes: None,
            tx_bytes: None,
            collector_mode: conntrack_source(collected).to_owned(),
            confidence: overlaid.status.confidence,
            warnings: vec![CONNECTION_ONLY_WARNING.to_owned()],
            tcp_conns: Some(u64::from(sample.tcp_conns)),
            udp_conns: Some(u64::from(sample.udp_conns)),
            udp_dns_conns: Some(u64::from(sample.udp_dns_conns)),
            udp_other_conns: Some(u64::from(sample.udp_other_conns)),
        });
    }
    overlaid
        .clients
        .clients
        .sort_by(|left, right| left.identity_key.cmp(&right.identity_key));

    // Keep the complete conntrack total stable when a connected client exits
    // the rate window. Such clients are retained above as zero-rate rows so the
    // displayed rows and totals use the same current-connection population.
    let totals = collected_connection_totals(collected);
    overlaid.clients.tcp_conns_total = Some(totals.0);
    overlaid.clients.udp_conns_total = Some(totals.1);
    overlaid.clients.udp_dns_conns_total = Some(totals.2);
    overlaid.clients.udp_other_conns_total = Some(totals.3);
    overlaid.clients.conntrack_entries_seen = Some(usize_to_u64(collected.stats.entries_seen));
    overlaid.clients.conntrack_entries_matched =
        Some(usize_to_u64(collected.stats.entries_matched));
    overlaid.clients.conntrack_parse_errors = Some(usize_to_u64(collected.stats.malformed_lines));
    overlaid.clients.conn_source = Some(conntrack_source(collected).to_owned());
    overlaid.clients.conn_collector_mode = Some(collector_mode.to_owned());
    overlaid.clients.conn_semantics = Some(CONNECTION_SEMANTICS.to_owned());
    if let Some(evidence) = overlaid.clients.evidence.as_mut() {
        evidence.details.remove("conntrack_status");
        evidence.details.remove("conntrack_error");
    }
    update_latest_overview(
        &mut overlaid.overview.samples,
        totals,
        overlaid.clients.clients.len(),
    );
    overlaid
}

pub fn apply_conntrack_failure(snapshot: &ResponseSnapshot, error: &str) -> ResponseSnapshot {
    let mut overlaid = snapshot.clone();
    publish_connection_details(&mut overlaid, None);
    remove_connection_only_clients(&mut overlaid.clients);
    for client in &mut overlaid.clients.clients {
        client.tcp_conns = None;
        client.udp_conns = None;
        client.udp_dns_conns = None;
        client.udp_other_conns = None;
    }
    clear_connection_fields(&mut overlaid.clients);
    update_latest_overview(
        &mut overlaid.overview.samples,
        (0, 0, 0, 0),
        overlaid.clients.clients.len(),
    );
    let evidence = overlaid.clients.evidence.get_or_insert_default();
    evidence.details.insert(
        "conntrack_status".to_owned(),
        Value::String("unavailable".to_owned()),
    );
    evidence.details.insert(
        "conntrack_error".to_owned(),
        Value::String(error.to_owned()),
    );
    overlaid
}

fn remove_connection_only_clients(clients: &mut ClientsResponse) {
    clients.clients.retain(|client| !is_connection_only(client));
}

fn is_connection_only(client: &Client) -> bool {
    client
        .warnings
        .iter()
        .any(|warning| warning == CONNECTION_ONLY_WARNING)
}

pub(crate) const fn has_counted_connections(
    client: &crate::collectors::conntrack::aggregate::ClientSample,
) -> bool {
    client.tcp_conns != 0 || client.udp_conns != 0
}

fn collected_connection_totals(collected: &CollectedSnapshot) -> (u64, u64, u64, u64) {
    collected
        .clients
        .iter()
        .fold((0, 0, 0, 0), |totals, client| {
            (
                totals.0.saturating_add(u64::from(client.tcp_conns)),
                totals.1.saturating_add(u64::from(client.udp_conns)),
                totals.2.saturating_add(u64::from(client.udp_dns_conns)),
                totals.3.saturating_add(u64::from(client.udp_other_conns)),
            )
        })
}

fn clear_connection_fields(clients: &mut ClientsResponse) {
    clients.tcp_conns_total = None;
    clients.udp_conns_total = None;
    clients.udp_dns_conns_total = None;
    clients.udp_other_conns_total = None;
    clients.conntrack_entries_seen = None;
    clients.conntrack_entries_matched = None;
    clients.conntrack_parse_errors = None;
    clients.conn_source = None;
    clients.conn_collector_mode = None;
    clients.conn_semantics = None;
}

fn update_latest_overview(
    samples: &mut [OverviewSample],
    totals: (u64, u64, u64, u64),
    client_count: usize,
) {
    let Some(latest) = samples.last_mut() else {
        return;
    };
    latest.client_count = saturating_u32(u64::try_from(client_count).unwrap_or(u64::MAX));
    latest.tcp_conns = Some(saturating_u32(totals.0));
    latest.udp_conns = Some(saturating_u32(totals.1));
    latest.udp_dns_conns = Some(saturating_u32(totals.2));
    latest.udp_other_conns = Some(saturating_u32(totals.3));
}

pub(crate) fn conntrack_source(collected: &CollectedSnapshot) -> &'static str {
    if collected.stats.netlink_read {
        "conntrack_netlink"
    } else {
        "conntrack_procfs"
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn saturating_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        collectors::conntrack::CollectStats,
        connection_details::{
            ClientConnectionDetail, ClientConnectionSet, ConnectionDirection, ConnectionProtocol,
            ConnectionState,
        },
        model::Confidence,
    };
    use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

    const DETAIL_KEY: &str = "aa:bb:cc:dd:ee:01@lan";

    fn snapshot_with_detail_client() -> ResponseSnapshot {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.clients.clients.push(Client {
            mac: "aa:bb:cc:dd:ee:01".into(),
            identity_key: DETAIL_KEY.into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.10".into()],
            hostname: Some("alpha".into()),
            rx_bps: 0,
            tx_bps: 0,
            last_seen: 0,
            sample_ms: Some(0),
            rx_bytes: None,
            tx_bytes: None,
            collector_mode: "bpf".into(),
            confidence: Confidence::High,
            warnings: Vec::new(),
            tcp_conns: None,
            udp_conns: None,
            udp_dns_conns: None,
            udp_other_conns: None,
        });
        snapshot
    }

    fn collected_with_detail() -> (
        CollectedSnapshot,
        Arc<BTreeMap<String, ClientConnectionSet>>,
    ) {
        let detail = ClientConnectionDetail {
            client_ip: "192.0.2.10".parse::<IpAddr>().unwrap(),
            client_port: 42_000,
            remote_ip: "198.51.100.10".parse::<IpAddr>().unwrap(),
            remote_port: 443,
            protocol: ConnectionProtocol::Tcp,
            state: ConnectionState::Established,
            direction: ConnectionDirection::Outbound,
            tx_bps: 0,
            rx_bps: 0,
        };
        let details = Arc::new(BTreeMap::from([(
            DETAIL_KEY.to_owned(),
            ClientConnectionSet {
                total_connections: 1,
                connections: vec![detail],
                truncated: false,
            },
        )]));
        (
            CollectedSnapshot {
                clients: Vec::new(),
                sample_ms: 4_321,
                connection_details: Arc::clone(&details),
                connection_counters: Default::default(),
                counter_source: "ctnetlink_conntrack_acct_orig_reply_bytes",
                stats: CollectStats {
                    netlink_read: true,
                    ..CollectStats::default()
                },
            },
            details,
        )
    }

    #[test]
    fn shared_detail_publisher_replaces_some_generation_and_clears_none() {
        let mut snapshot = snapshot_with_detail_client();
        let (collected, details) = collected_with_detail();
        assert_eq!(Arc::strong_count(&details), 2);

        publish_connection_details(&mut snapshot, Some(&collected));

        assert_eq!(Arc::strong_count(&details), 3);
        let published = snapshot.client_connections(DETAIL_KEY);
        assert!(published.available);
        assert_eq!(published.sample_ms, Some(4_321));
        assert_eq!(published.conn_source.as_deref(), Some("conntrack_netlink"));
        assert_eq!(published.total_connections, 1);
        assert_eq!(published.connections.len(), 1);

        publish_connection_details(&mut snapshot, None);

        assert_eq!(Arc::strong_count(&details), 2);
        let cleared = snapshot.client_connections(DETAIL_KEY);
        assert!(!cleared.available);
        assert_eq!(cleared.sample_ms, None);
        assert_eq!(cleared.conn_source, None);
        assert_eq!(cleared.total_connections, 0);
        assert!(cleared.connections.is_empty());
        assert_eq!(cleared.warnings, ["conntrack_unavailable"]);
    }

    #[test]
    fn cached_and_fresh_callers_publish_the_same_collected_generation_identically() {
        let (collected, _) = collected_with_detail();
        let mut cached = snapshot_with_detail_client();
        let mut fresh = snapshot_with_detail_client();

        publish_connection_details(&mut cached, Some(&collected));
        publish_connection_details(&mut fresh, Some(&collected));

        assert_eq!(
            cached.client_connections(DETAIL_KEY),
            fresh.client_connections(DETAIL_KEY)
        );
    }

    #[test]
    fn successful_overlay_preserves_independent_nss_diagnostics() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.clients.nss_ecm_direct_flows_seen = Some(3);
        snapshot.clients.nss_ecm_direct_flows_matched = Some(2);
        snapshot.clients.nss_ecm_direct_parse_errors = Some(1);
        let collected = CollectedSnapshot {
            clients: Vec::new(),
            sample_ms: 0,
            connection_details: Default::default(),
            connection_counters: Default::default(),
            counter_source: "ctnetlink_conntrack_acct_orig_reply_bytes",
            stats: CollectStats {
                netlink_read: true,
                ..CollectStats::default()
            },
        };

        let overlaid = apply_conntrack_success(&snapshot, &collected, "auto");

        assert_eq!(overlaid.clients.nss_ecm_direct_flows_seen, Some(3));
        assert_eq!(overlaid.clients.nss_ecm_direct_flows_matched, Some(2));
        assert_eq!(overlaid.clients.nss_ecm_direct_parse_errors, Some(1));
    }
}
