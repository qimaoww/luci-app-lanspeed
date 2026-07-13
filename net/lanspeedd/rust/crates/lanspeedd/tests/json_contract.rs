use std::{collections::BTreeMap, fs, path::PathBuf};

use lanspeedd::{
    model::{
        Capabilities, Client, ClientsResponse, Confidence, Conflict, Coverage, Evidence,
        HealthResponse, Interface, InterfaceRole, InterfaceStatus, InterfacesResponse, Mode,
        OverviewResponse, OverviewSample, ReloadResponse, StatusResponse, Sysdevice,
        SysdevicesResponse,
    },
    state::ResponseSnapshot,
    ubus::Method,
};
use serde_json::{json, Value};

const CAPABILITY_KEYS: [&str; 44] = [
    "bpf",
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
    "nss_ecm_direct",
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
    Evidence { details }
}

fn fixture_snapshot() -> ResponseSnapshot {
    let capabilities = Capabilities {
        bpf: true,
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
        nss_ecm_direct_flows_seen: Some(4),
        nss_ecm_direct_flows_matched: Some(3),
        nss_ecm_direct_parse_errors: Some(1),
        conn_collector_mode: Some("auto".into()),
        conn_semantics: Some(
            "conntrack_current_tcp_established_assured_udp_assured_dns_split".into(),
        ),
    };
    ResponseSnapshot {
        status: StatusResponse {
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
        overview: OverviewResponse {
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
        health: HealthResponse {
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
        reload: ReloadResponse {
            ok: true,
            mode: Mode::Full,
            warnings: vec![],
            evidence: evidence("reload"),
            version: "1.0.0-r1".into(),
        },
        interfaces: InterfacesResponse {
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
        sysdevices: SysdevicesResponse {
            devices: vec![Sysdevice {
                name: "br-lan".into(),
                selected: true,
                observed: false,
                recommended_lan: true,
                is_bridge: true,
                is_bridge_port: false,
                is_nss_ifb: false,
                speed_mbps: Some(1_000),
            }],
            current_ifnames: vec!["br-lan".into()],
            current_observed: vec![],
        },
    }
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
    snapshot.clients.evidence = None;
    snapshot.clients.tcp_conns_total = None;
    snapshot.clients.udp_conns_total = None;
    snapshot.clients.udp_dns_conns_total = None;
    snapshot.clients.udp_other_conns_total = None;
    snapshot.clients.conntrack_entries_seen = None;
    snapshot.clients.conntrack_entries_matched = None;
    snapshot.clients.conntrack_parse_errors = None;
    snapshot.clients.conn_source = None;
    snapshot.clients.nss_ecm_direct_flows_seen = None;
    snapshot.clients.nss_ecm_direct_flows_matched = None;
    snapshot.clients.nss_ecm_direct_parse_errors = None;
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

#[test]
fn all_seven_methods_serialize_typed_complete_json() {
    let snapshot = fixture_snapshot();
    let expected = [
        (Method::Status, "mode"),
        (Method::Clients, "clients"),
        (Method::Overview, "samples"),
        (Method::Health, "conflicts"),
        (Method::Reload, "ok"),
        (Method::Interfaces, "interfaces"),
        (Method::Sysdevices, "devices"),
    ];
    assert_eq!(Method::ALL.len(), 7);
    for (method, required) in expected {
        let value = snapshot.response(method).expect("typed response");
        assert!(value.get(required).is_some(), "{method:?}.{required}");
    }
}

#[test]
fn all_seven_methods_and_nested_models_keep_exact_maximal_key_sets() {
    let snapshot = fixture_snapshot();
    let status = snapshot.response(Method::Status).unwrap();
    let clients = snapshot.response(Method::Clients).unwrap();
    let overview = snapshot.response(Method::Overview).unwrap();
    let health = snapshot.response(Method::Health).unwrap();
    let reload = snapshot.response(Method::Reload).unwrap();
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
            "nss_ecm_direct_flows_seen",
            "nss_ecm_direct_flows_matched",
            "nss_ecm_direct_parse_errors",
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
        ],
        "clients.clients[]",
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
        &["devices", "current_ifnames", "current_observed"],
        "sysdevices",
    );
    assert_exact_keys(
        &sysdevices["devices"][0],
        &[
            "name",
            "selected",
            "observed",
            "recommended_lan",
            "is_bridge",
            "is_bridge_port",
            "is_nss_ifb",
            "speed_mbps",
        ],
        "sysdevices.devices[]",
    );
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
            "is_bridge",
            "is_bridge_port",
            "is_nss_ifb",
        ],
        "minimal sysdevices.devices[]",
    );
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
        json!({"source":"rust_test","method":"status","read_only":true})
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
        "nss_ecm_direct",
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
