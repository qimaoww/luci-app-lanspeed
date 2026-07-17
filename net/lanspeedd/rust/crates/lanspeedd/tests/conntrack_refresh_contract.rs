use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use lanspeedd::{
    collectors::conntrack::{aggregate::ClientSample, CollectStats, CollectedSnapshot},
    connection_details::{
        ClientConnectionDetail, ClientConnectionSet, ConnectionDirection, ConnectionProtocol,
        ConnectionState, MAX_CLIENT_CONNECTION_DETAILS,
    },
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
    stats.malformed_lines = 0;
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
        sample_ms: 100,
        connection_details: Default::default(),
        connection_counters: Default::default(),
        counter_source: "ctnetlink_conntrack_acct_orig_reply_bytes",
        stats,
    }
}

fn connection_detail(remote_ip: &str, remote_port: u16) -> ClientConnectionDetail {
    ClientConnectionDetail {
        client_ip: "192.0.2.10".parse::<IpAddr>().unwrap(),
        client_port: 41_000,
        remote_ip: remote_ip.parse::<IpAddr>().unwrap(),
        remote_port,
        protocol: ConnectionProtocol::Tcp,
        state: ConnectionState::Established,
        direction: ConnectionDirection::Outbound,
        tx_bps: 0,
        rx_bps: 0,
    }
}

fn collected_with_details(
    sample_ms: u64,
    netlink_read: bool,
    identity_key: &str,
    set: ClientConnectionSet,
) -> CollectedSnapshot {
    let mut snapshot = collected();
    snapshot.sample_ms = sample_ms;
    snapshot.stats.netlink_read = netlink_read;
    snapshot.stats.procfs_read = !netlink_read;
    snapshot.connection_details = Arc::new(BTreeMap::from([(identity_key.to_owned(), set)]));
    snapshot
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
    assert_eq!(CLIENT_CONNTRACK_CACHE_TTL_MS, 1_000);
    assert_eq!(
        client_conntrack_plan(10_999, Some(10_000), true),
        ClientConntrackPlan::ReuseCached
    );
    assert_eq!(
        client_conntrack_plan(11_000, Some(10_000), true),
        ClientConntrackPlan::Read
    );
    assert_eq!(
        client_conntrack_plan(10_999, Some(10_000), false),
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
fn production_periodic_skip_reuses_the_existing_local_conntrack_snapshot() {
    let source = include_str!("../src/production.rs");
    let collect_inner = source
        .split("fn collect_inner(")
        .nth(1)
        .unwrap()
        .split("fn refresh_connections(")
        .next()
        .unwrap();
    let periodic = collect_inner
        .split("match periodic_conntrack_plan(decision.rate) {")
        .nth(1)
        .unwrap()
        .split("self.apply_conntrack_health")
        .next()
        .unwrap();
    let skip = periodic
        .split("PeriodicConntrackPlan::Skip =>")
        .nth(1)
        .unwrap();

    assert!(skip.contains("self.conntrack_observation.record_skipped();"));
    assert!(
        !skip.contains("self.conntrack_snapshot.clone()"),
        "Skip must retain the local snapshot cloned once at collect_inner entry"
    );
}

#[test]
fn successful_overlay_publishes_known_client_details_and_final_client_metadata() {
    let key = "aa:bb:cc:dd:ee:01@lan";
    let mut before = base_snapshot();
    before.clients.clients[0].hostname = Some("alpha".into());
    let detail = connection_detail("198.51.100.7", 443);
    let collected = collected_with_details(
        7_777,
        true,
        key,
        ClientConnectionSet {
            total_connections: 1,
            connections: vec![detail.clone()],
            truncated: false,
        },
    );

    let after = apply_conntrack_success(&before, &collected, "auto");
    let response = after.client_connections(key);

    assert!(response.available);
    assert_eq!(response.sample_ms, Some(7_777));
    assert_eq!(response.conn_source.as_deref(), Some("conntrack_netlink"));
    assert_eq!(
        response.conn_semantics,
        lanspeedd::state::CONNECTION_SEMANTICS
    );
    assert_eq!(response.total_connections, 1);
    assert_eq!(response.returned_connections, 1);
    assert!(!response.truncated);
    assert_eq!(response.limit, MAX_CLIENT_CONNECTION_DETAILS);
    assert_eq!(response.connections, [detail]);
    assert!(response.warnings.is_empty());

    let client = response.client.expect("known client metadata");
    assert_eq!(client.identity_key, key);
    assert_eq!(client.hostname.as_deref(), Some("alpha"));
    assert_eq!(client.mac, "aa:bb:cc:dd:ee:01");
    assert_eq!(client.ips, ["192.0.2.10"]);
    assert_eq!(client.interface, "br-lan");
    assert_eq!(client.zone, "lan");
}

fn assert_incomplete_connection_details(collected: CollectedSnapshot) {
    let key = "aa:bb:cc:dd:ee:01@lan";
    let sample_ms = collected.sample_ms;
    let after = apply_conntrack_success(&base_snapshot(), &collected, "auto");
    let response = after.client_connections(key);

    assert!(!response.available);
    assert_eq!(response.sample_ms, Some(sample_ms));
    assert_eq!(response.conn_source.as_deref(), Some("conntrack_netlink"));
    assert!(response.client.is_some());
    assert_eq!(response.total_connections, 0);
    assert_eq!(response.returned_connections, 0);
    assert!(!response.truncated);
    assert_eq!(response.limit, MAX_CLIENT_CONNECTION_DETAILS);
    assert!(response.connections.is_empty());
    assert_eq!(response.warnings, ["conntrack_snapshot_incomplete"]);
    assert_eq!(after.clients.tcp_conns_total, Some(2));
    assert_eq!(after.clients.udp_conns_total, Some(3));
}

#[test]
fn malformed_conntrack_snapshot_does_not_publish_definitive_connection_details() {
    let key = "aa:bb:cc:dd:ee:01@lan";
    let mut collected = collected_with_details(
        7_778,
        true,
        key,
        ClientConnectionSet {
            total_connections: 1,
            connections: vec![connection_detail("198.51.100.8", 443)],
            truncated: false,
        },
    );
    collected.stats.malformed_lines = 1;

    assert_incomplete_connection_details(collected);
}

#[test]
fn conntrack_snapshot_with_dropped_clients_does_not_publish_definitive_details() {
    let key = "aa:bb:cc:dd:ee:01@lan";
    let mut collected = collected_with_details(
        7_779,
        true,
        key,
        ClientConnectionSet {
            total_connections: 1,
            connections: vec![connection_detail("198.51.100.9", 443)],
            truncated: false,
        },
    );
    collected.stats.clients_dropped = 1;

    assert_incomplete_connection_details(collected);
}

#[test]
fn successful_empty_overlay_replaces_the_entire_previous_detail_generation() {
    let key = "aa:bb:cc:dd:ee:01@lan";
    let first = collected_with_details(
        111,
        true,
        key,
        ClientConnectionSet {
            total_connections: 1,
            connections: vec![connection_detail("198.51.100.1", 443)],
            truncated: false,
        },
    );
    let with_details = apply_conntrack_success(&base_snapshot(), &first, "auto");

    let mut empty = collected();
    empty.sample_ms = 222;
    empty.stats.netlink_read = false;
    empty.stats.procfs_read = true;
    empty.connection_details = Arc::new(BTreeMap::new());
    let refreshed = apply_conntrack_success(&with_details, &empty, "auto");
    let response = refreshed.client_connections(key);

    assert!(response.available);
    assert_eq!(response.sample_ms, Some(222));
    assert_eq!(response.conn_source.as_deref(), Some("conntrack_procfs"));
    assert!(response.client.is_some());
    assert_eq!(response.total_connections, 0);
    assert_eq!(response.returned_connections, 0);
    assert!(!response.truncated);
    assert!(response.connections.is_empty());
    assert!(response.warnings.is_empty());
}

#[test]
fn available_snapshot_never_leaks_an_orphan_detail_bucket() {
    let missing_key = "aa:bb:cc:dd:ee:99@lan";
    let collected = collected_with_details(
        333,
        true,
        missing_key,
        ClientConnectionSet {
            total_connections: 1,
            connections: vec![connection_detail("203.0.113.9", 80)],
            truncated: false,
        },
    );

    let after = apply_conntrack_success(&base_snapshot(), &collected, "auto");
    let response = after.client_connections(missing_key);

    assert!(response.available);
    assert_eq!(response.sample_ms, Some(333));
    assert_eq!(response.conn_source.as_deref(), Some("conntrack_netlink"));
    assert!(response.client.is_none());
    assert_eq!(response.total_connections, 0);
    assert_eq!(response.returned_connections, 0);
    assert!(!response.truncated);
    assert!(response.connections.is_empty());
    assert_eq!(response.warnings, ["client_not_found"]);
}

#[test]
fn failed_overlay_clears_published_details_instead_of_serving_stale_data() {
    let key = "aa:bb:cc:dd:ee:01@lan";
    let collected = collected_with_details(
        444,
        true,
        key,
        ClientConnectionSet {
            total_connections: 1,
            connections: vec![connection_detail("203.0.113.10", 443)],
            truncated: false,
        },
    );
    let after = apply_conntrack_success(&base_snapshot(), &collected, "auto");

    let failed = apply_conntrack_failure(&after, "netlink denied");
    let response = failed.client_connections(key);

    assert!(!response.available);
    assert_eq!(response.sample_ms, None);
    assert_eq!(response.conn_source, None);
    assert!(response.client.is_some());
    assert_eq!(response.total_connections, 0);
    assert_eq!(response.returned_connections, 0);
    assert!(!response.truncated);
    assert!(response.connections.is_empty());
    assert_eq!(response.warnings, ["conntrack_unavailable"]);

    let missing = failed.client_connections("aa:bb:cc:dd:ee:99@lan");
    assert_eq!(
        missing.warnings,
        ["client_not_found", "conntrack_unavailable"]
    );
}

#[test]
fn truncated_snapshot_reports_total_limit_and_the_exact_sorted_vector() {
    let key = "aa:bb:cc:dd:ee:01@lan";
    let expected = vec![
        connection_detail("198.51.100.1", 80),
        connection_detail("198.51.100.2", 443),
    ];
    let collected = collected_with_details(
        555,
        true,
        key,
        ClientConnectionSet {
            total_connections: 9,
            connections: expected.clone(),
            truncated: true,
        },
    );

    let after = apply_conntrack_success(&base_snapshot(), &collected, "auto");
    let response = after.client_connections(key);

    assert_eq!(response.total_connections, 9);
    assert_eq!(response.returned_connections, expected.len());
    assert!(response.truncated);
    assert_eq!(response.limit, MAX_CLIENT_CONNECTION_DETAILS);
    assert_eq!(response.connections, expected);
}

#[test]
fn response_snapshot_clones_share_the_published_arc_map() {
    let key = "aa:bb:cc:dd:ee:01@lan";
    let details = Arc::new(BTreeMap::from([(
        key.to_owned(),
        ClientConnectionSet {
            total_connections: 1,
            connections: vec![connection_detail("198.51.100.8", 443)],
            truncated: false,
        },
    )]));
    let mut collected = collected();
    collected.connection_details = Arc::clone(&details);
    assert_eq!(Arc::strong_count(&details), 2);

    let after = apply_conntrack_success(&base_snapshot(), &collected, "auto");
    assert_eq!(Arc::strong_count(&details), 3);
    drop(collected);
    assert_eq!(Arc::strong_count(&details), 2);

    let cloned = after.clone();
    assert_eq!(Arc::strong_count(&details), 3);
    assert_eq!(
        cloned.client_connections(key),
        after.client_connections(key)
    );
}

#[test]
fn successful_overlay_matches_identity_and_clears_unmatched_stale_counts() {
    let before = base_snapshot();
    let mut collected = collected();
    collected.stats.malformed_lines = 1;
    let after = apply_conntrack_success(&before, &collected, "auto");

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
fn successful_overlay_totals_include_clients_missing_from_the_rate_snapshot() {
    let before = base_snapshot();
    let mut conntrack = collected();
    conntrack.clients.push(ClientSample {
        mac: "aa:bb:cc:dd:ee:03".into(),
        identity_key: "aa:bb:cc:dd:ee:03@lan".into(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec!["192.0.2.30".into()],
        tx_bytes: 0,
        rx_bytes: 0,
        last_seen_ms: 100,
        tcp_conns: 4,
        udp_conns: 5,
        udp_dns_conns: 2,
        udp_other_conns: 3,
    });

    let after = apply_conntrack_success(&before, &conntrack, "auto");

    assert_eq!(after.clients.clients.len(), 3);
    assert_eq!(after.clients.clients[0].tcp_conns, Some(2));
    assert_eq!(after.clients.clients[1].tcp_conns, Some(0));
    assert_eq!(
        after.clients.clients[2].identity_key,
        "aa:bb:cc:dd:ee:03@lan"
    );
    assert_eq!(after.clients.clients[2].tx_bps, 0);
    assert_eq!(after.clients.clients[2].rx_bps, 0);
    assert_eq!(after.clients.clients[2].tcp_conns, Some(4));
    assert_eq!(after.clients.clients[2].udp_conns, Some(5));
    assert_eq!(after.clients.clients[2].collector_mode, "conntrack_netlink");
    assert_eq!(
        after.clients.clients[2].warnings,
        ["conntrack_connection_only"]
    );
    assert_eq!(after.clients.tcp_conns_total, Some(6));
    assert_eq!(after.clients.udp_conns_total, Some(8));
    assert_eq!(after.clients.udp_dns_conns_total, Some(3));
    assert_eq!(after.clients.udp_other_conns_total, Some(5));
    assert_eq!(after.overview.samples[0].client_count, 3);
    assert_eq!(after.overview.samples[0].tcp_conns, Some(6));
    assert_eq!(after.overview.samples[0].udp_conns, Some(8));

    let row_totals = after.clients.clients.iter().fold((0, 0), |totals, client| {
        (
            totals.0 + client.tcp_conns.unwrap_or(0),
            totals.1 + client.udp_conns.unwrap_or(0),
        )
    });
    assert_eq!(row_totals, (6, 8));
}

#[test]
fn refreshed_overlay_replaces_stale_connection_only_clients() {
    let before = base_snapshot();
    let mut first = collected();
    first.clients.push(ClientSample {
        mac: "aa:bb:cc:dd:ee:03".into(),
        identity_key: "aa:bb:cc:dd:ee:03@lan".into(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec!["192.0.2.30".into()],
        tx_bytes: 0,
        rx_bytes: 0,
        last_seen_ms: 100,
        tcp_conns: 4,
        udp_conns: 0,
        udp_dns_conns: 0,
        udp_other_conns: 0,
    });
    let with_connection_only = apply_conntrack_success(&before, &first, "auto");

    let refreshed = apply_conntrack_success(&with_connection_only, &collected(), "auto");

    assert_eq!(refreshed.clients.clients.len(), 2);
    assert!(refreshed
        .clients
        .clients
        .iter()
        .all(|client| client.identity_key != "aa:bb:cc:dd:ee:03@lan"));
    assert_eq!(refreshed.clients.tcp_conns_total, Some(2));
    assert_eq!(refreshed.overview.samples[0].client_count, 2);
}

#[test]
fn refreshed_overlay_preserves_current_connection_only_metadata() {
    let before = base_snapshot();
    let mut conntrack = collected();
    conntrack.clients.push(ClientSample {
        mac: "aa:bb:cc:dd:ee:03".into(),
        identity_key: "aa:bb:cc:dd:ee:03@lan".into(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec!["192.0.2.30".into()],
        tx_bytes: 0,
        rx_bytes: 0,
        last_seen_ms: 100,
        tcp_conns: 4,
        udp_conns: 0,
        udp_dns_conns: 0,
        udp_other_conns: 0,
    });
    let mut with_connection_only = apply_conntrack_success(&before, &conntrack, "auto");
    with_connection_only.clients.clients[2].hostname = Some("lease-name".into());

    let refreshed = apply_conntrack_success(&with_connection_only, &conntrack, "auto");

    assert_eq!(refreshed.clients.clients.len(), 3);
    assert_eq!(
        refreshed.clients.clients[2].hostname.as_deref(),
        Some("lease-name")
    );
    assert_eq!(refreshed.clients.clients[2].tcp_conns, Some(4));
}

#[test]
fn overlay_does_not_append_conntrack_only_clients_without_counted_connections() {
    let before = base_snapshot();
    let mut conntrack = collected();
    conntrack.clients.push(ClientSample {
        mac: "aa:bb:cc:dd:ee:03".into(),
        identity_key: "aa:bb:cc:dd:ee:03@lan".into(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec!["192.0.2.30".into()],
        tx_bytes: 0,
        rx_bytes: 0,
        last_seen_ms: 100,
        tcp_conns: 0,
        udp_conns: 0,
        udp_dns_conns: 0,
        udp_other_conns: 0,
    });

    let after = apply_conntrack_success(&before, &conntrack, "auto");

    assert_eq!(after.clients.clients.len(), 2);
    assert_eq!(after.clients.tcp_conns_total, Some(2));
    assert_eq!(after.clients.udp_conns_total, Some(3));
    assert_eq!(after.overview.samples[0].client_count, 2);
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
fn failed_overlay_removes_stale_connection_only_clients() {
    let before = base_snapshot();
    let mut conntrack = collected();
    conntrack.clients.push(ClientSample {
        mac: "aa:bb:cc:dd:ee:03".into(),
        identity_key: "aa:bb:cc:dd:ee:03@lan".into(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec!["192.0.2.30".into()],
        tx_bytes: 0,
        rx_bytes: 0,
        last_seen_ms: 100,
        tcp_conns: 4,
        udp_conns: 0,
        udp_dns_conns: 0,
        udp_other_conns: 0,
    });
    let with_connection_only = apply_conntrack_success(&before, &conntrack, "auto");

    let failed = apply_conntrack_failure(&with_connection_only, "dump failed");

    assert_eq!(failed.clients.clients.len(), 2);
    assert!(failed
        .clients
        .clients
        .iter()
        .all(|client| client.identity_key != "aa:bb:cc:dd:ee:03@lan"));
    assert_eq!(failed.overview.samples[0].client_count, 2);
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
