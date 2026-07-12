use std::{collections::BTreeMap, fs, path::PathBuf};

use lanspeedd::{
    model::{
        Capabilities, Client, ClientsResponse, Confidence, Conflict, Evidence, HealthResponse,
        Interface, InterfaceRole, InterfaceStatus, InterfacesResponse, Mode, OverviewResponse,
        OverviewSample, ReloadResponse, StatusResponse, Sysdevice, SysdevicesResponse,
    },
    state::ResponseSnapshot,
    ubus::Method,
};
use serde_json::{json, Value};

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
        nss_ecm_direct_flows_seen: None,
        nss_ecm_direct_flows_matched: None,
        nss_ecm_direct_parse_errors: None,
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
            version: "0.1.7-r2".into(),
            capabilities: capabilities.clone(),
            coverage: None,
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
            version: "0.1.7-r2".into(),
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
    assert_eq!(status["version"], "0.1.7-r2");
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
