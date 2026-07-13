use std::collections::BTreeMap;

use serde_json::Value;

use crate::{
    collectors::conntrack::CollectedSnapshot,
    model::{ClientsResponse, OverviewSample},
    policy::RateCollector,
    probe::RuntimeHealth,
    state::{ResponseSnapshot, CONNECTION_SEMANTICS},
    ubus::Method,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeriodicConntrackPlan {
    Skip,
    Read,
}

pub const CLIENT_CONNTRACK_CACHE_TTL_MS: u64 = 5_000;

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
        Method::Clients => BeforeReplyAction::RefreshConnections,
        Method::Reload => BeforeReplyAction::Reload,
        Method::Status
        | Method::Overview
        | Method::Health
        | Method::Interfaces
        | Method::Sysdevices => BeforeReplyAction::None,
    }
}

pub fn apply_conntrack_success(
    snapshot: &ResponseSnapshot,
    collected: &CollectedSnapshot,
    collector_mode: &str,
) -> ResponseSnapshot {
    let mut overlaid = snapshot.clone();
    let by_identity = collected
        .clients
        .iter()
        .map(|client| (client.identity_key.as_str(), client))
        .collect::<BTreeMap<_, _>>();

    for client in &mut overlaid.clients.clients {
        let counts = by_identity.get(client.identity_key.as_str()).copied();
        client.tcp_conns = Some(counts.map_or(0, |sample| u64::from(sample.tcp_conns)));
        client.udp_conns = Some(counts.map_or(0, |sample| u64::from(sample.udp_conns)));
        client.udp_dns_conns = Some(counts.map_or(0, |sample| u64::from(sample.udp_dns_conns)));
        client.udp_other_conns = Some(counts.map_or(0, |sample| u64::from(sample.udp_other_conns)));
    }

    let totals = connection_totals(&overlaid.clients);
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
    update_latest_overview(&mut overlaid.overview.samples, totals);
    overlaid
}

pub fn apply_conntrack_failure(snapshot: &ResponseSnapshot, error: &str) -> ResponseSnapshot {
    let mut overlaid = snapshot.clone();
    for client in &mut overlaid.clients.clients {
        client.tcp_conns = None;
        client.udp_conns = None;
        client.udp_dns_conns = None;
        client.udp_other_conns = None;
    }
    clear_connection_fields(&mut overlaid.clients);
    update_latest_overview(&mut overlaid.overview.samples, (0, 0, 0, 0));
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

fn connection_totals(clients: &ClientsResponse) -> (u64, u64, u64, u64) {
    clients.clients.iter().fold((0, 0, 0, 0), |totals, client| {
        (
            totals.0.saturating_add(client.tcp_conns.unwrap_or(0)),
            totals.1.saturating_add(client.udp_conns.unwrap_or(0)),
            totals.2.saturating_add(client.udp_dns_conns.unwrap_or(0)),
            totals.3.saturating_add(client.udp_other_conns.unwrap_or(0)),
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

fn update_latest_overview(samples: &mut [OverviewSample], totals: (u64, u64, u64, u64)) {
    let Some(latest) = samples.last_mut() else {
        return;
    };
    latest.tcp_conns = Some(saturating_u32(totals.0));
    latest.udp_conns = Some(saturating_u32(totals.1));
    latest.udp_dns_conns = Some(saturating_u32(totals.2));
    latest.udp_other_conns = Some(saturating_u32(totals.3));
}

fn conntrack_source(collected: &CollectedSnapshot) -> &'static str {
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
    use crate::collectors::conntrack::CollectStats;

    #[test]
    fn successful_overlay_preserves_independent_nss_diagnostics() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.clients.nss_ecm_direct_flows_seen = Some(3);
        snapshot.clients.nss_ecm_direct_flows_matched = Some(2);
        snapshot.clients.nss_ecm_direct_parse_errors = Some(1);
        let collected = CollectedSnapshot {
            clients: Vec::new(),
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
