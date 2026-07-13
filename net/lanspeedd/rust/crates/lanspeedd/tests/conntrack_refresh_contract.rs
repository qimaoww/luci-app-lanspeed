use lanspeedd::{
    collectors::conntrack::{aggregate::ClientSample, CollectStats, CollectedSnapshot},
    connections::{
        apply_conntrack_failure, apply_conntrack_success, before_reply_action,
        client_conntrack_plan, periodic_conntrack_plan, BeforeReplyAction, ClientConntrackPlan,
        ConntrackObservation, ConntrackObservationState, PeriodicConntrackPlan,
        CLIENT_CONNTRACK_CACHE_TTL_MS,
    },
    model::{Client, OverviewResponse, OverviewSample},
    policy::RateCollector,
    probe::RuntimeHealth,
    state::ResponseSnapshot,
    ubus::Method,
};

fn client(identity_key: &str, tx_bps: u64) -> Client {
    Client {
        mac: identity_key.split('@').next().unwrap().to_owned(),
        identity_key: identity_key.to_owned(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec!["192.0.2.10".into()],
        hostname: Some("fixture".into()),
        rx_bps: tx_bps / 2,
        tx_bps,
        last_seen: 90,
        sample_ms: Some(100),
        rx_bytes: Some(1_000),
        tx_bytes: Some(2_000),
        collector_mode: "bpf".into(),
        confidence: lanspeedd::model::Confidence::High,
        warnings: vec![],
        tcp_conns: Some(9),
        udp_conns: Some(8),
        udp_dns_conns: Some(7),
        udp_other_conns: Some(6),
    }
}

fn base_snapshot() -> ResponseSnapshot {
    let mut snapshot = ResponseSnapshot::unsupported("test");
    snapshot.clients.clients = vec![
        client("aa:bb:cc:dd:ee:01@lan", 100),
        client("aa:bb:cc:dd:ee:02@lan", 200),
    ];
    snapshot.clients.tcp_conns_total = Some(18);
    snapshot.clients.udp_conns_total = Some(16);
    snapshot.clients.udp_dns_conns_total = Some(14);
    snapshot.clients.udp_other_conns_total = Some(12);
    snapshot.overview = OverviewResponse {
        samples: vec![OverviewSample {
            sample_ms: 100,
            tx_bps: 300,
            rx_bps: 150,
            client_count: 2,
            active_clients: 2,
            tcp_conns: Some(18),
            udp_conns: Some(16),
            udp_dns_conns: Some(14),
            udp_other_conns: Some(12),
        }],
        max_samples: 240,
        overview_window_samples: 240,
        active_client_window_ms: 10_000,
        active_client_min_bps: 1,
        sample_source: "clients_refresh_daemon_ring".into(),
        conn_semantics: lanspeedd::state::CONNECTION_SEMANTICS.into(),
    };
    snapshot
}

fn collected() -> CollectedSnapshot {
    let mut stats = CollectStats::default();
    stats.source_path = "ctnetlink".into();
    stats.netlink_read = true;
    stats.entries_seen = 7;
    stats.entries_matched = 3;
    stats.malformed_lines = 1;
    CollectedSnapshot {
        clients: vec![ClientSample {
            mac: "aa:bb:cc:dd:ee:01".into(),
            identity_key: "aa:bb:cc:dd:ee:01@lan".into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.10".into()],
            tx_bytes: 0,
            rx_bytes: 0,
            last_seen_ms: 100,
            tcp_conns: 2,
            udp_conns: 3,
            udp_dns_conns: 1,
            udp_other_conns: 2,
        }],
        counter_source: "ctnetlink_conntrack_acct_orig_reply_bytes",
        stats,
    }
}

#[test]
fn periodic_conntrack_is_only_required_by_sync_rate_source() {
    assert_eq!(
        periodic_conntrack_plan(RateCollector::Bpf),
        PeriodicConntrackPlan::Skip
    );
    assert_eq!(
        periodic_conntrack_plan(RateCollector::NssEcmDirect),
        PeriodicConntrackPlan::Skip
    );
    assert_eq!(
        periodic_conntrack_plan(RateCollector::Unsupported),
        PeriodicConntrackPlan::Skip
    );
    assert_eq!(
        periodic_conntrack_plan(RateCollector::NssConntrackSync),
        PeriodicConntrackPlan::Read
    );
}

#[test]
fn client_conntrack_cache_reuses_only_a_fresh_available_snapshot() {
    assert_eq!(CLIENT_CONNTRACK_CACHE_TTL_MS, 5_000);
    assert_eq!(
        client_conntrack_plan(14_999, Some(10_000), true),
        ClientConntrackPlan::ReuseCached
    );
    assert_eq!(
        client_conntrack_plan(15_000, Some(10_000), true),
        ClientConntrackPlan::Read
    );
    assert_eq!(
        client_conntrack_plan(14_999, Some(10_000), false),
        ClientConntrackPlan::Read
    );
    assert_eq!(
        client_conntrack_plan(9_999, Some(10_000), true),
        ClientConntrackPlan::Read
    );
    assert_eq!(
        client_conntrack_plan(10_000, None, true),
        ClientConntrackPlan::Read
    );
}

#[test]
fn production_checks_the_client_cache_before_reading_identities() {
    let source = include_str!("../src/production.rs");
    let refresh = source
        .split("fn refresh_connections(")
        .nth(1)
        .unwrap()
        .split("fn collect(")
        .next()
        .unwrap();
    let plan = refresh
        .find("client_conntrack_plan(")
        .expect("clients refresh must consult the conntrack cache policy");
    let identities = refresh
        .find("read_identities(")
        .expect("cache miss must still read identities before conntrack");

    assert!(
        plan < identities,
        "cache policy must run before identity IO"
    );
    assert!(refresh.contains("ClientConntrackPlan::ReuseCached"));
    assert!(refresh.contains("self.conntrack_snapshot.as_ref()"));
}

#[test]
fn successful_overlay_matches_identity_and_clears_unmatched_stale_counts() {
    let before = base_snapshot();
    let after = apply_conntrack_success(&before, &collected(), "auto");

    assert_eq!(after.clients.clients[0].tcp_conns, Some(2));
    assert_eq!(after.clients.clients[0].udp_conns, Some(3));
    assert_eq!(after.clients.clients[1].tcp_conns, Some(0));
    assert_eq!(after.clients.clients[1].udp_other_conns, Some(0));
    assert_eq!(after.clients.tcp_conns_total, Some(2));
    assert_eq!(after.clients.udp_conns_total, Some(3));
    assert_eq!(after.clients.udp_dns_conns_total, Some(1));
    assert_eq!(after.clients.udp_other_conns_total, Some(2));
    assert_eq!(after.clients.conntrack_entries_seen, Some(7));
    assert_eq!(after.clients.conntrack_entries_matched, Some(3));
    assert_eq!(after.clients.conntrack_parse_errors, Some(1));
    assert_eq!(
        after.clients.conn_source.as_deref(),
        Some("conntrack_netlink")
    );
    assert_eq!(after.clients.conn_collector_mode.as_deref(), Some("auto"));
    assert_eq!(
        after.clients.conn_semantics.as_deref(),
        Some(lanspeedd::state::CONNECTION_SEMANTICS)
    );
    assert_eq!(after.overview.samples.len(), 1);
    assert_eq!(after.overview.samples[0].sample_ms, 100);
    assert_eq!(after.overview.samples[0].tx_bps, 300);
    assert_eq!(after.overview.samples[0].tcp_conns, Some(2));
    assert_eq!(after.overview.samples[0].udp_conns, Some(3));
}

#[test]
fn failed_overlay_never_returns_stale_connection_counts() {
    let mut before = base_snapshot();
    before.clients.nss_ecm_direct_flows_seen = Some(11);
    before.clients.nss_ecm_direct_flows_matched = Some(7);
    before.clients.nss_ecm_direct_parse_errors = Some(2);
    let after = apply_conntrack_failure(&before, "netlink: permission denied");

    assert_eq!(
        after.clients.clients[0].rx_bps,
        before.clients.clients[0].rx_bps
    );
    assert_eq!(
        after.clients.clients[0].identity_key,
        before.clients.clients[0].identity_key
    );
    assert_eq!(after.clients.clients[0].tcp_conns, None);
    assert_eq!(after.clients.clients[1].udp_conns, None);
    assert_eq!(after.clients.tcp_conns_total, None);
    assert_eq!(after.clients.udp_conns_total, None);
    assert_eq!(after.clients.conntrack_entries_seen, None);
    assert_eq!(after.clients.conn_source, None);
    assert_eq!(after.clients.nss_ecm_direct_flows_seen, Some(11));
    assert_eq!(after.clients.nss_ecm_direct_flows_matched, Some(7));
    assert_eq!(after.clients.nss_ecm_direct_parse_errors, Some(2));
    assert_eq!(after.overview.samples[0].tcp_conns, Some(0));
    let evidence = after.clients.evidence.unwrap();
    assert_eq!(evidence.details["conntrack_status"], "unavailable");
    assert_eq!(
        evidence.details["conntrack_error"],
        "netlink: permission denied"
    );
}

#[test]
fn successful_overlay_preserves_independent_nss_direct_diagnostics() {
    let mut before = base_snapshot();
    before.clients.nss_ecm_direct_flows_seen = Some(11);
    before.clients.nss_ecm_direct_flows_matched = Some(7);
    before.clients.nss_ecm_direct_parse_errors = Some(2);

    let after = apply_conntrack_success(&before, &collected(), "auto");

    assert_eq!(after.clients.nss_ecm_direct_flows_seen, Some(11));
    assert_eq!(after.clients.nss_ecm_direct_flows_matched, Some(7));
    assert_eq!(after.clients.nss_ecm_direct_parse_errors, Some(2));
}

#[test]
fn observation_distinguishes_skipped_and_failed_and_round_trips_checkpoint() {
    let mut observation = ConntrackObservation::default();
    observation.record_skipped();
    assert_eq!(observation.state, ConntrackObservationState::Skipped);
    assert!(observation.last_attempt_ms.is_none());
    observation.record_failure(11, "dump failed", false, false);
    assert_eq!(observation.state, ConntrackObservationState::Failed);
    assert_eq!(observation.last_attempt_ms, Some(11));
    assert_eq!(observation.error.as_deref(), Some("dump failed"));
    let checkpoint = observation.clone();
    observation.record_success(12, true, false);
    observation.record_skipped();
    assert_eq!(observation.state, ConntrackObservationState::Skipped);
    assert_eq!(observation.last_attempt_ms, Some(12));
    assert!(observation.netlink_read);
    assert!(!observation.procfs_read);
    observation.restore(checkpoint.clone());
    assert_eq!(observation, checkpoint);
}

#[test]
fn unattempted_observation_preserves_default_conntrack_availability() {
    let observation = ConntrackObservation::default();
    let mut health = RuntimeHealth::default();

    observation.apply_runtime_health(false, &mut health);

    assert!(health.conntrack_netlink_available);
    assert!(health.conntrack_procfs_available);
    assert_eq!(health.nss_sync_read_ok, None);
}

#[test]
fn attempted_observation_propagates_success_failure_and_skipped_state() {
    let mut observation = ConntrackObservation::default();
    observation.record_success(10, true, false);
    let mut health = RuntimeHealth::default();
    observation.apply_runtime_health(true, &mut health);
    assert!(health.conntrack_netlink_available);
    assert!(!health.conntrack_procfs_available);
    assert_eq!(health.nss_sync_read_ok, Some(true));

    observation.record_skipped();
    let mut skipped = RuntimeHealth::default();
    observation.apply_runtime_health(true, &mut skipped);
    assert!(skipped.conntrack_netlink_available);
    assert!(!skipped.conntrack_procfs_available);
    assert_eq!(skipped.nss_sync_read_ok, Some(true));

    observation.record_failure(11, "dump failed", false, true);
    let mut failed = RuntimeHealth::default();
    observation.apply_runtime_health(false, &mut failed);
    assert!(!failed.conntrack_netlink_available);
    assert!(failed.conntrack_procfs_available);
    assert_eq!(failed.nss_sync_read_ok, Some(false));
}

#[test]
fn before_reply_policy_refreshes_only_clients_and_reload() {
    assert_eq!(
        before_reply_action(Method::Clients),
        BeforeReplyAction::RefreshConnections
    );
    assert_eq!(
        before_reply_action(Method::Reload),
        BeforeReplyAction::Reload
    );
    for method in [
        Method::Status,
        Method::Overview,
        Method::Health,
        Method::Interfaces,
        Method::Sysdevices,
    ] {
        assert_eq!(before_reply_action(method), BeforeReplyAction::None);
    }
}
