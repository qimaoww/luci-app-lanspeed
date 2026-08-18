use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use lanspeedd::{
    collectors::conntrack::{CollectStats, CollectedSnapshot},
    connection_details::{
        ClientConnectionDetail, ClientConnectionSet, ConnectionDirection, ConnectionProtocol,
        ConnectionState,
    },
    connections::{apply_conntrack_success, before_reply_action, BeforeReplyAction},
    model::{
        AttachmentKind, AttachmentTrust, ByteDomain, Capabilities, ClassificationState, Client,
        ClientRateMeta, ClientsResponse, Confidence, Conflict, Coverage, Evidence, HealthResponse,
        Interface, InterfaceRole, InterfaceStatus, InterfacesResponse, Mode, OverviewResponse,
        OverviewSample, RateAttachment, RateClassificationSummary, RateCoverage, RateDirectionMeta,
        RateScope, RateSource, ReloadResponse, StatusResponse, Sysdevice, SysdeviceLimits,
        SysdevicesResponse, CLIENT_RATE_META_VERSION,
    },
    state::ResponseSnapshot,
    ubus::{validated_identity_key, Method},
};
use serde_json::{json, Value};

const CAPABILITY_KEYS: [&str; 46] = [
    "bpf",
    "bpf_supported",
    "bpf_package",
    "bpf_object",
    "bpf_runtime_metrics",
    "conntrack_fallback",
    "live_metrics",
    "fw4",
    "nft",
    "software_flow_offload",
    "hardware_flow_offload",
    "nss",
    "nss_ecm_offload",
    "nss_ppe_offload",
    "nss_ecm_node",
    "nss_ecm_bpf",
    "nss_bridge_mgr",
    "nss_ifb",
    "nss_nsm",
    "nss_dp",
    "nss_mcs",
    "fullcone",
    "nf_conntrack_acct",
    "flowtable_counter",
    "tc",
    "tc_clsact",
    "existing_tc_filters",
    "ifb",
    "sqm",
    "qosify",
    "openclash",
    "openclash_fake_ip",
    "openclash_tun_mix",
    "openclash_redirect_dns",
    "openclash_dns_chain_complete",
    "openclash_router_self_proxy",
    "openclash_udp_proxy",
    "openclash_ipv6",
    "dae",
    "homeproxy",
    "lan_bridge",
    "vlan",
    "wlan",
    "lan_edge",
    "safe_attach",
    "map_full",
];

fn assert_exact_keys(value: &Value, expected: &[&str], label: &str) {
    let mut actual = value
        .as_object()
        .unwrap_or_else(|| panic!("{label} must be an object"))
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected, "{label} key set changed");
}

fn evidence(method: &str) -> Evidence {
    let mut details = BTreeMap::new();
    details.insert("source".into(), json!("rust_test"));
    details.insert("method".into(), json!(method));
    details.insert("read_only".into(), json!(true));
    if matches!(method, "health" | "status") {
        details.insert(
            "probe_failures".into(),
            json!({"items": [], "total": 0, "truncated": false}),
        );
    }
    Evidence { details }
}

fn fixture_snapshot() -> ResponseSnapshot {
    let capabilities = Capabilities {
        bpf: true,
        bpf_supported: true,
        bpf_package: true,
        bpf_object: true,
        conntrack_fallback: true,
        live_metrics: true,
        tc: true,
        tc_clsact: true,
        safe_attach: true,
        ..Capabilities::default()
    };
    let clients = ClientsResponse {
        clients: vec![Client {
            mac: "02:00:00:00:00:01".into(),
            identity_key: "02:00:00:00:00:01@lan".into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.10".into()],
            hostname: Some("fixture-client".into()),
            rx_bps: 2_000,
            tx_bps: 1_000,
            last_seen: 9_900,
            sample_ms: Some(10_000),
            rx_bytes: Some(20_000),
            tx_bytes: Some(10_000),
            collector_mode: "bpf".into(),
            confidence: Confidence::High,
            warnings: vec![],
            tcp_conns: Some(2),
            udp_conns: Some(1),
            udp_dns_conns: Some(1),
            udp_other_conns: Some(0),
            rate_meta: Some(ClientRateMeta {
                version: CLIENT_RATE_META_VERSION,
                scope: RateScope::AllFrames,
                tx: RateDirectionMeta {
                    source: RateSource::EdgePort,
                    coverage: RateCoverage::Partial,
                    byte_domain: Some(ByteDomain::L2NoFcs),
                    sample_ms: None,
                    window_ms: None,
                    stale: None,
                },
                rx: RateDirectionMeta {
                    source: RateSource::EdgePort,
                    coverage: RateCoverage::Partial,
                    byte_domain: Some(ByteDomain::L2NoFcs),
                    sample_ms: None,
                    window_ms: None,
                    stale: None,
                },
                attachment: Some(RateAttachment {
                    kind: AttachmentKind::Ethernet,
                    ifname: Some("lan2".into()),
                    trust: AttachmentTrust::ObservedExclusive,
                }),
                generation: 17,
                window_ms: Some(1_000),
                sample_ms: Some(10_000),
                stale: false,
                reason_codes: Vec::new(),
                classification: Some(RateClassificationSummary {
                    state: ClassificationState::Aligned,
                    tx_state: None,
                    rx_state: None,
                    sample_ms: Some(10_000),
                    window_ms: Some(2_000),
                    comparison_window_ms: Some(6_000),
                    tx_coverage_pct: Some(96),
                    rx_coverage_pct: Some(94),
                }),
            }),
            control: None,
        }],
        evidence: Some(evidence("clients")),
        tcp_conns_total: Some(2),
        udp_conns_total: Some(1),
        udp_dns_conns_total: Some(1),
        udp_other_conns_total: Some(0),
        conntrack_entries_seen: Some(3),
        conntrack_entries_matched: Some(3),
        conntrack_parse_errors: Some(0),
        conn_source: Some("conntrack_netlink".into()),
        nss_ecm_nodes_seen: Some(4),
        nss_ecm_nodes_matched: Some(3),
        nss_ecm_node_parse_errors: Some(1),
        conn_collector_mode: Some("auto".into()),
        conn_semantics: Some(
            "conntrack_current_tcp_established_assured_udp_assured_dns_split".into(),
        ),
    };
    ResponseSnapshot::from_responses(
        StatusResponse {
            mode: Mode::Full,
            confidence: Confidence::High,
            warnings: vec!["dae_detected".into()],
            evidence: evidence("status"),
            refresh_interval_ms: 1_000,
            active_client_window_ms: 10_000,
            active_client_min_bps: 1,
            overview_window_samples: 240,
            collector_mode: "auto".into(),
            rate_collector_mode: "auto".into(),
            internet_view_mode: "off".into(),
            access_edge_mode: "shadow".into(),
            conn_collector_mode: "auto".into(),
            version: "1.0.0-r1".into(),
            capabilities: capabilities.clone(),
            coverage: Some(Coverage {
                quality: "good".into(),
                samples: 4,
                window_ms: Some(3_000),
                tx_pct: Some(95),
                rx_pct: Some(94),
                denom_rx_bytes: Some(21_000),
                denom_tx_bytes: Some(11_000),
                numer_rx_bytes: Some(20_000),
                numer_tx_bytes: Some(10_000),
            }),
        },
        clients,
        OverviewResponse {
            samples: vec![OverviewSample {
                sample_ms: 10_000,
                tx_bps: 1_000,
                rx_bps: 2_000,
                client_count: 1,
                active_clients: 1,
                tcp_conns: Some(2),
                udp_conns: Some(1),
                udp_dns_conns: Some(1),
                udp_other_conns: Some(0),
            }],
            max_samples: 240,
            overview_window_samples: 240,
            active_client_window_ms: 10_000,
            active_client_min_bps: 1,
            sample_source: "clients_refresh_daemon_ring".into(),
            conn_semantics:
                "conntrack_current_tcp_established_assured_udp_assured_dns_split".into(),
        },
        HealthResponse {
            mode: Mode::Degraded,
            confidence: Confidence::Medium,
            capabilities,
            conflicts: vec![Conflict {
                id: "tc_filter_conflict".into(),
                severity: "warning".into(),
                message: "fixed lanspeed slot is occupied".into(),
                evidence: BTreeMap::new(),
            }],
            warnings: vec!["tc_filter_conflict".into()],
            evidence: evidence("health"),
        },
        ReloadResponse {
            ok: true,
            mode: Mode::Full,
            warnings: vec![],
            evidence: evidence("reload"),
            version: "1.0.0-r1".into(),
        },
        InterfacesResponse {
            interfaces: vec![Interface {
                name: "br-lan".into(),
                role: InterfaceRole::Lan,
                status: InterfaceStatus::Active,
                rx_bytes: Some(20_000),
                tx_bytes: Some(10_000),
                rx_bps: Some(2_000),
                tx_bps: Some(1_000),
                delta_ms: Some(1_000),
                sample_ms: Some(10_000),
                source: Some("sysfs".into()),
                coverage: Some("cpu_visible_lan_edge".into()),
                evidence: Some(evidence("interfaces")),
            }],
            monotonic_ms: Some(10_000),
            note: Some("Per-interface totals from kernel net device counters; reflect hardware-offloaded and hardware-switched traffic too.".into()),
            evidence: Some(evidence("interfaces")),
        },
        SysdevicesResponse {
            contract_version: 1,
            devices: vec![Sysdevice {
                name: "br-lan".into(),
                selected: true,
                observed: false,
                recommended_lan: true,
                collect_allowed: true,
                collect_reason: "eligible_bridge".into(),
                is_bridge: true,
                is_bridge_port: false,
                is_nss_ifb: false,
                speed_mbps: Some(1_000),
            }],
            current_ifnames: vec!["br-lan".into()],
            current_observed: vec![],
            current_excluded: vec![],
            configured_ifnames: vec!["br-lan".into()],
            configured_observed: vec![],
            configured_excluded: vec![],
            orphaned: vec![],
            limits: SysdeviceLimits { max_configured: 16, max_name_length: 31 },
        },
    )
}

fn minimal_optional_snapshot() -> ResponseSnapshot {
    let mut snapshot = fixture_snapshot();
    snapshot.status.coverage = None;

    let client = &mut snapshot.clients.clients[0];
    client.hostname = None;
    client.sample_ms = None;
    client.rx_bytes = None;
    client.tx_bytes = None;
    client.tcp_conns = None;
    client.udp_conns = None;
    client.udp_dns_conns = None;
    client.udp_other_conns = None;
    client.rate_meta = None;
    snapshot.clients.evidence = None;
    snapshot.clients.tcp_conns_total = None;
    snapshot.clients.udp_conns_total = None;
    snapshot.clients.udp_dns_conns_total = None;
    snapshot.clients.udp_other_conns_total = None;
    snapshot.clients.conntrack_entries_seen = None;
    snapshot.clients.conntrack_entries_matched = None;
    snapshot.clients.conntrack_parse_errors = None;
    snapshot.clients.conn_source = None;
    snapshot.clients.nss_ecm_nodes_seen = None;
    snapshot.clients.nss_ecm_nodes_matched = None;
    snapshot.clients.nss_ecm_node_parse_errors = None;
    snapshot.clients.conn_collector_mode = None;
    snapshot.clients.conn_semantics = None;

    let sample = &mut snapshot.overview.samples[0];
    sample.tcp_conns = None;
    sample.udp_conns = None;
    sample.udp_dns_conns = None;
    sample.udp_other_conns = None;

    let interface = &mut snapshot.interfaces.interfaces[0];
    interface.rx_bytes = None;
    interface.tx_bytes = None;
    interface.rx_bps = None;
    interface.tx_bps = None;
    interface.delta_ms = None;
    interface.sample_ms = None;
    interface.source = None;
    interface.coverage = None;
    interface.evidence = None;
    snapshot.interfaces.monotonic_ms = None;
    snapshot.interfaces.note = None;
    snapshot.interfaces.evidence = None;

    snapshot.sysdevices.devices[0].speed_mbps = None;
    snapshot
}

fn detail() -> ClientConnectionDetail {
    ClientConnectionDetail {
        client_ip: "192.0.2.10".parse::<IpAddr>().unwrap(),
        client_port: 42_001,
        remote_ip: "198.51.100.20".parse::<IpAddr>().unwrap(),
        remote_port: 443,
        protocol: ConnectionProtocol::Tcp,
        state: ConnectionState::Established,
        direction: ConnectionDirection::Outbound,
        tx_bps: 0,
        rx_bps: 0,
    }
}

fn publish_details(
    snapshot: &ResponseSnapshot,
    details: BTreeMap<String, ClientConnectionSet>,
) -> ResponseSnapshot {
    apply_conntrack_success(
        snapshot,
        &CollectedSnapshot {
            clients: Vec::new(),
            sample_ms: 12_345,
            connection_details: Arc::new(details),
            connection_counters: Default::default(),
            counter_source: "ctnetlink_conntrack_acct_orig_reply_bytes",
            stats: CollectStats {
                netlink_read: true,
                ..CollectStats::default()
            },
        },
        "auto",
    )
}

#[test]
fn client_connections_keeps_exact_envelope_summary_and_detail_key_sets() {
    let key = "02:00:00:00:00:01@lan";
    let snapshot = publish_details(
        &fixture_snapshot(),
        BTreeMap::from([(
            key.to_owned(),
            ClientConnectionSet {
                total_connections: 1,
                connections: vec![detail()],
                truncated: false,
            },
        )]),
    );
    let value = serde_json::to_value(snapshot.client_connections(key)).unwrap();

    assert_exact_keys(
        &value,
        &[
            "available",
            "sample_ms",
            "client",
            "total_connections",
            "returned_connections",
            "truncated",
            "limit",
            "conn_source",
            "conn_semantics",
            "connections",
            "warnings",
        ],
        "client_connections",
    );
    assert_exact_keys(
        &value["client"],
        &[
            "identity_key",
            "hostname",
            "mac",
            "ips",
            "interface",
            "zone",
            "rx_bps",
            "tx_bps",
            "rate_sample_ms",
            "rate_collector_mode",
            "rate_meta",
        ],
        "client_connections.client",
    );
    assert_exact_keys(
        &value["connections"][0],
        &[
            "client_ip",
            "client_port",
            "remote_ip",
            "remote_port",
            "protocol",
            "state",
            "direction",
            "tx_bps",
            "rx_bps",
        ],
        "client_connections.connections[]",
    );
    assert_eq!(value["available"], true);
    assert_eq!(value["sample_ms"], 12_345);
    assert_eq!(value["client"]["hostname"], "fixture-client");
    assert_eq!(value["client"]["rx_bps"], 2_000);
    assert_eq!(value["client"]["tx_bps"], 1_000);
    assert_eq!(value["client"]["rate_sample_ms"], 10_000);
    assert_eq!(value["client"]["rate_collector_mode"], "bpf");
    assert_eq!(value["client"]["rate_meta"]["version"], 1);
    assert_eq!(value["client"]["rate_meta"]["sample_ms"], 10_000);
    assert_eq!(value["conn_source"], "conntrack_netlink");
    assert_eq!(value["connections"][0]["remote_ip"], "198.51.100.20");
}

#[test]
fn incomplete_client_connections_keeps_the_existing_envelope_key_set() {
    let key = "02:00:00:00:00:01@lan";
    let snapshot = apply_conntrack_success(
        &fixture_snapshot(),
        &CollectedSnapshot {
            clients: Vec::new(),
            sample_ms: 12_346,
            connection_details: Arc::new(BTreeMap::from([(
                key.to_owned(),
                ClientConnectionSet {
                    total_connections: 1,
                    connections: vec![detail()],
                    truncated: false,
                },
            )])),
            connection_counters: Default::default(),
            counter_source: "ctnetlink_conntrack_acct_orig_reply_bytes",
            stats: CollectStats {
                netlink_read: true,
                malformed_lines: 1,
                ..CollectStats::default()
            },
        },
        "auto",
    );
    let value = serde_json::to_value(snapshot.client_connections(key)).unwrap();

    assert_exact_keys(
        &value,
        &[
            "available",
            "sample_ms",
            "client",
            "total_connections",
            "returned_connections",
            "truncated",
            "limit",
            "conn_source",
            "conn_semantics",
            "connections",
            "warnings",
        ],
        "incomplete client_connections",
    );
    assert_exact_keys(
        &value["client"],
        &[
            "identity_key",
            "hostname",
            "mac",
            "ips",
            "interface",
            "zone",
            "rx_bps",
            "tx_bps",
            "rate_sample_ms",
            "rate_collector_mode",
            "rate_meta",
        ],
        "incomplete client_connections.client",
    );
    assert_eq!(value["available"], false);
    assert_eq!(value["sample_ms"], 12_346);
    assert_eq!(value["conn_source"], "conntrack_netlink");
    assert_eq!(value["total_connections"], 0);
    assert_eq!(value["returned_connections"], 0);
    assert_eq!(value["connections"], json!([]));
    assert_eq!(value["warnings"], json!(["conntrack_snapshot_incomplete"]));
}

#[test]
fn client_connections_serializes_missing_options_as_null_without_skipping_keys() {
    let unavailable =
        serde_json::to_value(fixture_snapshot().client_connections("02:00:00:00:00:99@lan"))
            .unwrap();
    assert_exact_keys(
        &unavailable,
        &[
            "available",
            "sample_ms",
            "client",
            "total_connections",
            "returned_connections",
            "truncated",
            "limit",
            "conn_source",
            "conn_semantics",
            "connections",
            "warnings",
        ],
        "unavailable client_connections",
    );
    assert_eq!(unavailable["available"], false);
    assert!(unavailable["sample_ms"].is_null());
    assert!(unavailable["client"].is_null());
    assert!(unavailable["conn_source"].is_null());

    let available = publish_details(&minimal_optional_snapshot(), BTreeMap::new());
    let known =
        serde_json::to_value(available.client_connections("02:00:00:00:00:01@lan")).unwrap();
    assert_exact_keys(
        &known["client"],
        &[
            "identity_key",
            "hostname",
            "mac",
            "ips",
            "interface",
            "zone",
            "rx_bps",
            "tx_bps",
            "rate_sample_ms",
            "rate_collector_mode",
            "rate_meta",
        ],
        "client_connections.client without hostname",
    );
    assert!(known["client"]["hostname"].is_null());
}

#[test]
fn fixed_snapshot_methods_and_all_registered_methods_stay_distinct() {
    let snapshot = fixture_snapshot();
    let expected = [
        (Method::Realtime, "status"),
        (Method::Status, "mode"),
        (Method::Clients, "clients"),
        (Method::Overview, "samples"),
        (Method::Health, "conflicts"),
        (Method::Reload, "ok"),
        (Method::Interfaces, "interfaces"),
        (Method::Sysdevices, "devices"),
        (Method::Diagnostics, "contract_version"),
    ];
    assert_eq!(Method::FIXED.len(), 9);
    assert_eq!(Method::ALL.len(), 12);
    assert_eq!(Method::ALL[..Method::FIXED.len()], Method::FIXED);
    assert_eq!(Method::ALL[9], Method::ClientConnections);
    assert_eq!(Method::ALL[10], Method::ClientControlSet);
    assert_eq!(Method::ALL[11], Method::ClientControlDelete);
    assert_eq!(Method::Realtime.name(), "realtime");
    assert_eq!(Method::Diagnostics.name(), "diagnostics");
    assert_eq!(Method::ClientConnections.name(), "client_connections");
    assert_eq!(Method::ClientControlSet.name(), "client_control_set");
    assert_eq!(Method::ClientControlDelete.name(), "client_control_delete");
    assert_eq!(
        before_reply_action(Method::Realtime),
        BeforeReplyAction::CacheOnly
    );
    assert_eq!(
        before_reply_action(Method::ClientConnections),
        BeforeReplyAction::CacheOnly
    );
    assert_eq!(Method::FIXED, expected.map(|(method, _required)| method));
    for (method, required) in expected {
        let value = snapshot.response(method).expect("typed response");
        assert!(value.get(required).is_some(), "{method:?}.{required}");
    }
    assert!(snapshot.response(Method::ClientConnections).is_err());
    assert!(snapshot.response(Method::ClientControlSet).is_err());
    assert!(snapshot.response(Method::ClientControlDelete).is_err());
}

#[test]
fn client_connections_requires_bounded_identity_and_parameterized_dispatch() {
    assert_eq!(validated_identity_key(None), None);
    assert_eq!(validated_identity_key(Some(String::new())), None);
    assert_eq!(
        validated_identity_key(Some("a".repeat(255))),
        Some("a".repeat(255))
    );
    assert_eq!(validated_identity_key(Some("a".repeat(256))), None);
    assert_eq!(
        validated_identity_key(Some("界".repeat(85))),
        Some("界".repeat(85))
    );
    assert_eq!(
        validated_identity_key(Some(format!("{}a", "界".repeat(85)))),
        None
    );

    let key = "02:00:00:00:00:01@lan";
    let snapshot = publish_details(
        &fixture_snapshot(),
        BTreeMap::from([(
            key.to_owned(),
            ClientConnectionSet {
                total_connections: 1,
                connections: vec![detail()],
                truncated: false,
            },
        )]),
    );
    let value = snapshot
        .response_for_request(Method::ClientConnections, key)
        .expect("parameterized client connections response");
    assert_eq!(value["client"]["identity_key"], key);
    assert_eq!(value["connections"][0]["remote_ip"], "198.51.100.20");
}

#[test]
fn all_nine_fixed_methods_and_nested_models_keep_exact_maximal_key_sets() {
    let snapshot = fixture_snapshot();
    let status = snapshot.response(Method::Status).unwrap();
    let clients = snapshot.response(Method::Clients).unwrap();
    let overview = snapshot.response(Method::Overview).unwrap();
    let health = snapshot.response(Method::Health).unwrap();
    let reload = snapshot.response(Method::Reload).unwrap();
    let interfaces = snapshot.response(Method::Interfaces).unwrap();
    let sysdevices = snapshot.response(Method::Sysdevices).unwrap();
    let diagnostics = snapshot.response(Method::Diagnostics).unwrap();

    assert_exact_keys(
        &status,
        &[
            "mode",
            "confidence",
            "warnings",
            "evidence",
            "refresh_interval_ms",
            "active_client_window_ms",
            "active_client_min_bps",
            "overview_window_samples",
            "collector_mode",
            "rate_collector_mode",
            "internet_view_mode",
            "access_edge_mode",
            "conn_collector_mode",
            "version",
            "capabilities",
            "coverage",
        ],
        "status",
    );
    assert_exact_keys(
        &status["capabilities"],
        &CAPABILITY_KEYS,
        "status.capabilities",
    );
    assert_exact_keys(
        &status["coverage"],
        &[
            "quality",
            "samples",
            "window_ms",
            "tx_pct",
            "rx_pct",
            "denom_rx_bytes",
            "denom_tx_bytes",
            "numer_rx_bytes",
            "numer_tx_bytes",
        ],
        "status.coverage",
    );
    assert_exact_keys(
        &clients,
        &[
            "clients",
            "evidence",
            "tcp_conns_total",
            "udp_conns_total",
            "udp_dns_conns_total",
            "udp_other_conns_total",
            "conntrack_entries_seen",
            "conntrack_entries_matched",
            "conntrack_parse_errors",
            "conn_source",
            "nss_ecm_nodes_seen",
            "nss_ecm_nodes_matched",
            "nss_ecm_node_parse_errors",
            "conn_collector_mode",
            "conn_semantics",
        ],
        "clients",
    );
    assert_exact_keys(
        &clients["clients"][0],
        &[
            "mac",
            "identity_key",
            "zone",
            "interface",
            "ips",
            "hostname",
            "rx_bps",
            "tx_bps",
            "last_seen",
            "sample_ms",
            "rx_bytes",
            "tx_bytes",
            "collector_mode",
            "confidence",
            "warnings",
            "tcp_conns",
            "udp_conns",
            "udp_dns_conns",
            "udp_other_conns",
            "rate_meta",
        ],
        "clients.clients[]",
    );
    assert_exact_keys(
        &clients["clients"][0]["rate_meta"],
        &[
            "version",
            "scope",
            "tx",
            "rx",
            "attachment",
            "generation",
            "window_ms",
            "sample_ms",
            "stale",
            "reason_codes",
            "classification",
        ],
        "clients.clients[].rate_meta",
    );
    assert_exact_keys(
        &clients["clients"][0]["rate_meta"]["tx"],
        &["source", "coverage", "byte_domain"],
        "clients.clients[].rate_meta.tx",
    );
    assert_exact_keys(
        &clients["clients"][0]["rate_meta"]["attachment"],
        &["kind", "ifname", "trust"],
        "clients.clients[].rate_meta.attachment",
    );
    assert_exact_keys(
        &clients["clients"][0]["rate_meta"]["classification"],
        &[
            "state",
            "sample_ms",
            "window_ms",
            "comparison_window_ms",
            "tx_coverage_pct",
            "rx_coverage_pct",
        ],
        "clients.clients[].rate_meta.classification",
    );
    assert_exact_keys(
        &overview,
        &[
            "samples",
            "max_samples",
            "overview_window_samples",
            "active_client_window_ms",
            "active_client_min_bps",
            "sample_source",
            "conn_semantics",
        ],
        "overview",
    );
    assert_exact_keys(
        &overview["samples"][0],
        &[
            "sample_ms",
            "tx_bps",
            "rx_bps",
            "client_count",
            "active_clients",
            "tcp_conns",
            "udp_conns",
            "udp_dns_conns",
            "udp_other_conns",
        ],
        "overview.samples[]",
    );
    assert_exact_keys(
        &health,
        &[
            "mode",
            "confidence",
            "capabilities",
            "conflicts",
            "warnings",
            "evidence",
        ],
        "health",
    );
    assert_exact_keys(
        &health["capabilities"],
        &CAPABILITY_KEYS,
        "health.capabilities",
    );
    assert_exact_keys(
        &health["evidence"]["probe_failures"],
        &["items", "total", "truncated"],
        "health.evidence.probe_failures",
    );
    assert_eq!(health["evidence"]["probe_failures"]["items"], json!([]));
    assert_eq!(health["evidence"]["probe_failures"]["total"], 0);
    assert_eq!(health["evidence"]["probe_failures"]["truncated"], false);
    assert_exact_keys(
        &health["conflicts"][0],
        &["id", "severity", "message"],
        "health.conflicts[]",
    );
    assert_exact_keys(
        &reload,
        &["ok", "mode", "warnings", "evidence", "version"],
        "reload",
    );
    assert_exact_keys(
        &interfaces,
        &["interfaces", "monotonic_ms", "note", "evidence"],
        "interfaces",
    );
    assert_exact_keys(
        &interfaces["interfaces"][0],
        &[
            "name",
            "role",
            "status",
            "rx_bytes",
            "tx_bytes",
            "rx_bps",
            "tx_bps",
            "delta_ms",
            "sample_ms",
            "source",
            "coverage",
            "evidence",
        ],
        "interfaces.interfaces[]",
    );
    assert_exact_keys(
        &sysdevices,
        &[
            "contract_version",
            "devices",
            "current_ifnames",
            "current_observed",
            "current_excluded",
            "configured_ifnames",
            "configured_observed",
            "configured_excluded",
            "orphaned",
            "limits",
        ],
        "sysdevices",
    );
    assert_exact_keys(
        &sysdevices["devices"][0],
        &[
            "name",
            "selected",
            "observed",
            "recommended_lan",
            "collect_allowed",
            "collect_reason",
            "is_bridge",
            "is_bridge_port",
            "is_nss_ifb",
            "speed_mbps",
        ],
        "sysdevices.devices[]",
    );
    assert_exact_keys(
        &diagnostics,
        &[
            "contract_version",
            "service",
            "collection",
            "data_path",
            "interfaces",
            "connection",
            "subsystems",
            "versions",
            "alerts",
            "config_issues",
        ],
        "diagnostics",
    );
    assert_exact_keys(
        &diagnostics["collection"],
        &[
            "state",
            "generation",
            "last_attempt_ms",
            "last_success_ms",
            "age_ms",
            "refresh_interval_ms",
            "consecutive_failures",
            "retained",
            "last_error",
        ],
        "diagnostics.collection",
    );
    assert_exact_keys(
        &diagnostics["versions"],
        &["daemon", "package", "contract_version", "schema_version"],
        "diagnostics.versions",
    );
    assert_eq!(diagnostics["contract_version"], 1);
    assert_eq!(diagnostics["versions"]["contract_version"], 1);
    assert_eq!(diagnostics["versions"]["schema_version"], 1);
}

#[test]
fn optional_fields_are_omitted_without_changing_required_key_sets() {
    let snapshot = minimal_optional_snapshot();
    let status = snapshot.response(Method::Status).unwrap();
    let clients = snapshot.response(Method::Clients).unwrap();
    let overview = snapshot.response(Method::Overview).unwrap();
    let interfaces = snapshot.response(Method::Interfaces).unwrap();
    let sysdevices = snapshot.response(Method::Sysdevices).unwrap();

    assert_exact_keys(
        &status,
        &[
            "mode",
            "confidence",
            "warnings",
            "evidence",
            "refresh_interval_ms",
            "active_client_window_ms",
            "active_client_min_bps",
            "overview_window_samples",
            "collector_mode",
            "rate_collector_mode",
            "internet_view_mode",
            "access_edge_mode",
            "conn_collector_mode",
            "version",
            "capabilities",
        ],
        "minimal status",
    );
    assert_exact_keys(&clients, &["clients"], "minimal clients");
    assert_exact_keys(
        &clients["clients"][0],
        &[
            "mac",
            "identity_key",
            "zone",
            "interface",
            "ips",
            "hostname",
            "rx_bps",
            "tx_bps",
            "last_seen",
            "collector_mode",
            "confidence",
            "warnings",
        ],
        "minimal clients.clients[]",
    );
    assert!(clients["clients"][0]["hostname"].is_null());
    assert_exact_keys(
        &overview["samples"][0],
        &[
            "sample_ms",
            "tx_bps",
            "rx_bps",
            "client_count",
            "active_clients",
        ],
        "minimal overview.samples[]",
    );
    assert_exact_keys(&interfaces, &["interfaces"], "minimal interfaces");
    assert_exact_keys(
        &interfaces["interfaces"][0],
        &["name", "role", "status"],
        "minimal interfaces.interfaces[]",
    );
    assert_exact_keys(
        &sysdevices["devices"][0],
        &[
            "name",
            "selected",
            "observed",
            "recommended_lan",
            "collect_allowed",
            "collect_reason",
            "is_bridge",
            "is_bridge_port",
            "is_nss_ifb",
        ],
        "minimal sysdevices.devices[]",
    );
}

#[test]
fn unavailable_rate_meta_omits_unknown_numeric_and_attachment_fields() {
    let value = serde_json::to_value(ClientRateMeta::default()).unwrap();
    assert_exact_keys(
        &value,
        &[
            "version",
            "scope",
            "tx",
            "rx",
            "generation",
            "stale",
            "reason_codes",
        ],
        "default rate_meta",
    );
    assert_eq!(value["scope"], "none");
    assert_eq!(
        value["tx"],
        json!({"source": "none", "coverage": "unavailable"})
    );
    assert_eq!(
        value["rx"],
        json!({"source": "none", "coverage": "unavailable"})
    );
    assert!(value.get("window_ms").is_none());
    assert!(value.get("sample_ms").is_none());
    assert!(value.get("attachment").is_none());
    assert!(value.get("classification").is_none());
}

#[test]
fn main_clients_payload_stays_bounded_and_fast_at_2048_rate_metadata_rows() {
    let mut response = fixture_snapshot().clients;
    let template = response.clients[0].clone();
    response.clients = (0..2_048u32)
        .map(|index| {
            let mut client = template.clone();
            let mac = format!(
                "02:10:{:02x}:{:02x}:{:02x}:{:02x}",
                (index >> 24) & 0xff,
                (index >> 16) & 0xff,
                (index >> 8) & 0xff,
                index & 0xff
            );
            client.mac = mac.clone();
            client.identity_key = format!("{mac}@lan");
            client.hostname = Some(format!("client-{index}"));
            client
        })
        .collect();

    let started = Instant::now();
    let encoded = serde_json::to_vec(&response).unwrap();
    let _: Value = serde_json::from_slice(&encoded).unwrap();
    let elapsed = started.elapsed();
    assert!(encoded.len() < 4 * 1024 * 1024, "{} bytes", encoded.len());
    assert!(
        elapsed < Duration::from_secs(1),
        "serialization and parse took {elapsed:?}"
    );
    let encoded = std::str::from_utf8(&encoded).unwrap();
    assert!(!encoded.contains("\"nss_bps\""));
    assert!(!encoded.contains("\"slow_bps\""));
    assert!(!encoded.contains("\"unclassified_bps\""));
    assert!(encoded.contains("\"tx_coverage_pct\""));
}

#[test]
fn divergent_direction_state_is_serialized_sparsely() {
    let mut snapshot = fixture_snapshot();
    let classification = snapshot.clients.clients[0]
        .rate_meta
        .as_mut()
        .and_then(|meta| meta.classification.as_mut())
        .expect("fixture classification summary");
    classification.state = ClassificationState::CounterSkew;
    classification.tx_state = Some(ClassificationState::Aligned);
    classification.rx_state = None;

    let value = serde_json::to_value(snapshot.clients).unwrap();
    let summary = &value["clients"][0]["rate_meta"]["classification"];
    assert_eq!(summary["state"], "counter_skew");
    assert_eq!(summary["tx_state"], "aligned");
    assert!(summary.get("rx_state").is_none());
}

#[test]
fn divergent_direction_freshness_is_serialized_sparsely() {
    let mut snapshot = fixture_snapshot();
    let meta = snapshot.clients.clients[0]
        .rate_meta
        .as_mut()
        .expect("fixture rate metadata");
    meta.stale = true;
    meta.tx.sample_ms = Some(9_000);
    meta.tx.window_ms = Some(900);
    meta.tx.stale = Some(false);

    let value = serde_json::to_value(snapshot.clients).unwrap();
    let tx = &value["clients"][0]["rate_meta"]["tx"];
    let rx = &value["clients"][0]["rate_meta"]["rx"];
    assert_eq!(tx["sample_ms"], 9_000);
    assert_eq!(tx["window_ms"], 900);
    assert_eq!(tx["stale"], false);
    assert!(rx.get("sample_ms").is_none());
    assert!(rx.get("window_ms").is_none());
    assert!(rx.get("stale").is_none());
}

#[test]
fn json_names_enums_warnings_evidence_version_and_directions_are_stable() {
    let snapshot = fixture_snapshot();
    let status = snapshot.response(Method::Status).unwrap();
    assert_eq!(status["mode"], "Full");
    assert_eq!(status["confidence"], "high");
    assert_eq!(status["warnings"], json!(["dae_detected"]));
    assert_eq!(
        status["evidence"],
        json!({
            "source": "rust_test",
            "method": "status",
            "read_only": true,
            "probe_failures": {"items": [], "total": 0, "truncated": false}
        })
    );
    assert_eq!(status["version"], "1.0.0-r1");
    let mut capability_keys = status["capabilities"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    capability_keys.sort();
    let mut expected_capability_keys = vec![
        "bpf",
        "bpf_supported",
        "bpf_package",
        "bpf_object",
        "bpf_runtime_metrics",
        "conntrack_fallback",
        "live_metrics",
        "fw4",
        "nft",
        "software_flow_offload",
        "hardware_flow_offload",
        "nss",
        "nss_ecm_offload",
        "nss_ppe_offload",
        "nss_ecm_node",
        "nss_ecm_bpf",
        "nss_bridge_mgr",
        "nss_ifb",
        "nss_nsm",
        "nss_dp",
        "nss_mcs",
        "fullcone",
        "nf_conntrack_acct",
        "flowtable_counter",
        "tc",
        "tc_clsact",
        "existing_tc_filters",
        "ifb",
        "sqm",
        "qosify",
        "openclash",
        "openclash_fake_ip",
        "openclash_tun_mix",
        "openclash_redirect_dns",
        "openclash_dns_chain_complete",
        "openclash_router_self_proxy",
        "openclash_udp_proxy",
        "openclash_ipv6",
        "dae",
        "homeproxy",
        "lan_bridge",
        "vlan",
        "wlan",
        "lan_edge",
        "safe_attach",
        "map_full",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    expected_capability_keys.sort();
    assert_eq!(capability_keys, expected_capability_keys);
    assert_eq!(status["capabilities"]["bpf_runtime_metrics"], false);
    assert_eq!(status["capabilities"]["safe_attach"], true);
    let clients = snapshot.response(Method::Clients).unwrap();
    let client = &clients["clients"][0];
    assert_eq!(client["tx_bps"], 1_000, "tx is client upload");
    assert_eq!(client["rx_bps"], 2_000, "rx is client download");
    assert_eq!(client["identity_key"], "02:00:00:00:00:01@lan");
    assert_eq!(client["confidence"], "high");
    assert_eq!(client["rate_meta"]["version"], 1);
    assert_eq!(client["rate_meta"]["scope"], "all_frames");
    assert_eq!(client["rate_meta"]["tx"]["source"], "edge_port");
    assert_eq!(client["rate_meta"]["tx"]["coverage"], "partial");
    assert_eq!(client["rate_meta"]["tx"]["byte_domain"], "l2_no_fcs");
    assert_eq!(
        client["rate_meta"]["attachment"]["trust"],
        "observed_exclusive"
    );
    assert_eq!(client["rate_meta"]["classification"]["state"], "aligned");
    assert_eq!(client["rate_meta"]["classification"]["tx_coverage_pct"], 96);
    assert_eq!(clients["evidence"]["method"], "clients");
    let health = snapshot.response(Method::Health).unwrap();
    assert_eq!(health["mode"], "Degraded");
    assert_eq!(health["warnings"], json!(["tc_filter_conflict"]));
    assert_eq!(health["conflicts"][0]["severity"], "warning");
}

#[test]
fn overview_keeps_history_metadata_and_old_fixture_schema_names() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../..");
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(root.join("net/lanspeedd/files/usr/share/lanspeed/schema.json"))
            .unwrap(),
    )
    .unwrap();
    let legacy: Value = serde_json::from_str(
        &fs::read_to_string(root.join("tests/fixtures/lanspeed-api.json")).unwrap(),
    )
    .unwrap();
    let overview = fixture_snapshot().response(Method::Overview).unwrap();
    for field in [
        "samples",
        "max_samples",
        "overview_window_samples",
        "active_client_window_ms",
        "active_client_min_bps",
        "sample_source",
        "conn_semantics",
    ] {
        assert!(overview.get(field).is_some(), "missing overview.{field}");
        assert!(schema["$defs"]["overview"]["properties"]
            .get(field)
            .is_some());
        assert!(legacy["overview"].get(field).is_some());
    }
    assert_eq!(overview["sample_source"], "clients_refresh_daemon_ring");
    assert_eq!(overview["samples"][0]["tx_bps"], 1_000);
    assert_eq!(overview["samples"][0]["rx_bps"], 2_000);
}

#[test]
fn status_and_health_probe_failure_objects_match_schema_and_fallback_snapshot() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../..");
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(root.join("net/lanspeedd/files/usr/share/lanspeed/schema.json"))
            .unwrap(),
    )
    .unwrap();
    let snapshot = ResponseSnapshot::unsupported("test");
    let status = snapshot.response(Method::Status).unwrap();
    let health = snapshot.response(Method::Health).unwrap();
    let failures = &health["evidence"]["probe_failures"];

    assert_exact_keys(
        failures,
        &["items", "total", "truncated"],
        "fallback health.evidence.probe_failures",
    );
    assert_eq!(
        failures,
        &json!({"items": [], "total": 0, "truncated": false})
    );
    assert_eq!(&status["evidence"]["probe_failures"], failures);
    assert!(snapshot.response(Method::Clients).unwrap()["evidence"]
        .get("probe_failures")
        .is_none());
    assert!(snapshot.response(Method::Reload).unwrap()["evidence"]
        .get("probe_failures")
        .is_none());
    assert_eq!(
        schema["$defs"]["health"]["properties"]["evidence"]["$ref"],
        "#/$defs/healthEvidence"
    );
    assert_eq!(
        schema["$defs"]["status"]["properties"]["evidence"]["$ref"],
        "#/$defs/healthEvidence"
    );
    assert_eq!(
        schema["$defs"]["healthEvidence"]["properties"]["probe_failures"]["$ref"],
        "#/$defs/probeFailures"
    );
    assert_eq!(
        schema["$defs"]["probeFailures"]["properties"]["items"]["maxItems"],
        32
    );
    assert_eq!(
        schema["$defs"]["probeFailures"]["required"],
        json!(["items", "total", "truncated"])
    );
}

#[test]
fn diagnostics_omit_client_identity_and_untrusted_evidence_text() {
    let mut snapshot = fixture_snapshot();
    snapshot.clients.conn_source = Some("/proc/private/path token=secret".into());
    snapshot.status.evidence.details.insert(
        "effective_collector".into(),
        json!("/private/collector/path"),
    );
    snapshot
        .status
        .evidence
        .details
        .insert("runtime_error".into(), json!("token=secret"));

    let diagnostics = snapshot.response(Method::Diagnostics).unwrap();
    let serialized = diagnostics.to_string();
    for private in [
        "fixture-client",
        "02:00:00:00:00:01",
        "192.0.2.10",
        "/proc/private/path",
        "/private/collector/path",
        "token=secret",
    ] {
        assert!(!serialized.contains(private), "leaked {private}");
    }
    assert!(diagnostics["connection"]["source"].is_null());
    assert_eq!(diagnostics["data_path"]["effective_rate"], "unsupported");
}

#[test]
fn counters_saturate_at_json_signed_integer_limit() {
    let mut snapshot = fixture_snapshot();
    snapshot.clients.clients[0].rx_bytes = Some(u64::MAX);
    snapshot.clients.clients[0].tx_bps = u64::MAX;
    snapshot.interfaces.interfaces[0].rx_bytes = Some(u64::MAX);
    let clients = snapshot.response(Method::Clients).unwrap();
    let interfaces = snapshot.response(Method::Interfaces).unwrap();
    assert_eq!(clients["clients"][0]["rx_bytes"], i64::MAX);
    assert_eq!(clients["clients"][0]["tx_bps"], i64::MAX);
    assert_eq!(interfaces["interfaces"][0]["rx_bytes"], i64::MAX);
}
