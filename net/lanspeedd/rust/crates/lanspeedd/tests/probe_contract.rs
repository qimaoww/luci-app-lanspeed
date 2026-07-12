use lanspeedd::config::RuntimeConfig;
use lanspeedd::probe::commands::{validate_read_only_args, ReadOnlyCommand};
use lanspeedd::probe::tc::{
    dae_preempts_lan_ingress, has_owned_identity_collision, parse_filter_lines,
};
use lanspeedd::probe::{
    assess, BpfObservation, CommandObservations, FileObservations, NssObservation,
    OffloadObservation, ProbeCapabilities, ProbeObservations, ProbeRuntimeHealth, ProxyObservation,
    TcFilter, TcObservations, UbusObservations, UciObservations,
};
use serde_json::Value;
use std::{fs, path::PathBuf};

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../../tests/fixtures")
        .join(name);
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn flag(value: &Value, path: &[&str]) -> bool {
    path.iter()
        .try_fold(value, |value, key| value.get(*key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn text(value: &Value, path: &[&str]) -> Option<String> {
    path.iter()
        .try_fold(value, |value, key| value.get(*key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn number(value: &Value, path: &[&str], default: i64) -> i64 {
    path.iter()
        .try_fold(value, |value, key| value.get(*key))
        .and_then(Value::as_i64)
        .unwrap_or(default)
}

fn observations(value: &Value) -> (RuntimeConfig, ProbeObservations) {
    let mut config = RuntimeConfig::default();
    config.enable_bpf = flag(value, &["config", "enable_bpf"]);
    config.enable_conntrack_fallback = flag(value, &["config", "enable_conntrack_fallback"]);
    config.max_clients = number(value, &["config", "max_clients"], 512) as usize;

    let filters = value["tc"]["filters"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|filter| TcFilter {
            interface: filter
                .get("interface")
                .and_then(Value::as_str)
                .unwrap_or("br-lan")
                .into(),
            direction: filter
                .get("direction")
                .and_then(Value::as_str)
                .unwrap_or("ingress")
                .into(),
            pref: filter
                .get("pref")
                .and_then(Value::as_i64)
                .unwrap_or_default() as u32,
            handle: filter
                .get("handle")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .into(),
            owner: filter
                .get("owner")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .into(),
            source: filter
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("tc_filter_show")
                .into(),
        })
        .collect();
    let openclash_installed = flag(value, &["uci", "openclash"]);
    let redirect_dns = flag(value, &["openclash", "enable_redirect_dns"]);
    let dns_chain = flag(value, &["openclash", "dnsmasq_to_openclash_dns"]);
    let dae = value.get("dae").unwrap_or(&Value::Null);

    let observations = ProbeObservations {
        commands: CommandObservations {
            fw4: flag(value, &["commands", "fw4"]),
            nft: flag(value, &["commands", "nft"]),
            tc: flag(value, &["commands", "tc"]),
            ubus: flag(value, &["commands", "ubus"]),
            qosify: flag(value, &["commands", "qosify"]),
            flowtable_counter: flag(value, &["commands", "nft_ruleset_has_flowtable_counter"]),
            flowtable_exit_code: number(value, &["commands", "nft_ruleset_exit_code"], 0) as i32,
            tc_filter_help_exit_code: number(value, &["tc", "filter_help_exit_code"], 0) as i32,
            tc_qdisc_help_exit_code: number(value, &["tc", "qdisc_help_exit_code"], 0) as i32,
        },
        files: FileObservations {
            nf_conntrack_acct_present: flag(value, &["files", "nf_conntrack_acct", "present"]),
            nf_conntrack_acct_value: text(value, &["files", "nf_conntrack_acct", "value"]),
            flowtable_proc: flag(value, &["files", "flowtable_proc"]),
            flowtable_debug: flag(value, &["files", "flowtable_debug"]),
            ifb: flag(value, &["files", "ifb"]),
            lan_bridge: flag(value, &["files", "lan_bridge"]),
            vlan: flag(value, &["files", "vlan"]),
            wlan: flag(value, &["files", "wlan"]),
        },
        uci: UciObservations {
            firewall_loaded: flag(value, &["uci", "firewall", "loaded"]),
            sqm: flag(value, &["uci", "sqm"]),
            qosify: flag(value, &["uci", "qosify"]),
            openclash: openclash_installed,
            dae: flag(value, &["uci", "dae"]),
            daed: flag(value, &["uci", "daed"]),
            homeproxy: flag(value, &["uci", "homeproxy"]),
            nlbwmon: flag(value, &["uci", "nlbwmon"]),
        },
        ubus: UbusObservations {
            network_lan_attempted: flag(value, &["ubus", "network_lan", "attempted"]),
            network_lan_exit_code: number(value, &["ubus", "network_lan", "exit_code"], -1) as i32,
        },
        tc: TcObservations {
            clsact: flag(value, &["tc", "clsact"]),
            bpf: flag(value, &["tc", "bpf"]),
            existing_filters: flag(value, &["tc", "existing_filters"]),
            filters,
        },
        proxy: ProxyObservation {
            openclash_installed,
            openclash_en_mode: text(value, &["openclash", "en_mode"]),
            openclash_redirect_dns: redirect_dns,
            openclash_dnsmasq_chain: dns_chain,
            openclash_router_self_proxy: flag(value, &["openclash", "router_self_proxy"]),
            openclash_udp_proxy: flag(value, &["openclash", "enable_udp_proxy"]),
            openclash_stack_type: text(value, &["openclash", "stack_type"]),
            openclash_ipv6: flag(value, &["openclash", "ipv6_enable"]),
            dae_service: flag(dae, &["dae_service"]),
            daed_service: flag(dae, &["daed_service"]),
            dae_running: flag(dae, &["dae_running"]),
            daed_running: flag(dae, &["daed_running"]),
            dae_process: flag(dae, &["dae_process"]),
            daed_process: flag(dae, &["daed_process"]),
            dae_iface: flag(dae, &["dae0"]),
            dae_peer_iface: flag(dae, &["dae0peer"]),
            dae_fwmark: flag(dae, &["fwmark_detected"]),
            dae_route_table: flag(dae, &["route_table_detected"]),
            dae_dns_udp53: flag(dae, &["dns_udp53_detected"]),
        },
        offload: OffloadObservation {
            software: flag(value, &["uci", "firewall", "software_flow_offload"]),
            hardware: flag(value, &["uci", "firewall", "hardware_flow_offload"]),
            fullcone: flag(value, &["uci", "firewall", "fullcone"]),
        },
        nss: NssObservation::default(),
        bpf: BpfObservation {
            package: flag(value, &["files", "bpf_package"]),
            object: flag(value, &["files", "bpf_object"]),
            ..BpfObservation::default()
        },
    };
    (config, observations)
}

fn expected_capabilities(value: &Value, report_safe_attach: bool) -> ProbeCapabilities {
    let openclash = flag(value, &["uci", "openclash"]);
    let en_mode = text(value, &["openclash", "en_mode"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let stack_type = text(value, &["openclash", "stack_type"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let redirect_dns = openclash && flag(value, &["openclash", "enable_redirect_dns"]);
    let dae = flag(value, &["uci", "dae"])
        || flag(value, &["uci", "daed"])
        || value.get("dae").is_some()
        || value["tc"]["filters"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|filter| filter["owner"] == "dae");
    ProbeCapabilities {
        bpf: false,
        bpf_package: flag(value, &["files", "bpf_package"]),
        bpf_object: flag(value, &["files", "bpf_object"]),
        bpf_runtime_metrics: false,
        conntrack_fallback: false,
        live_metrics: false,
        fw4: flag(value, &["commands", "fw4"]),
        nft: flag(value, &["commands", "nft"]),
        software_flow_offload: flag(value, &["uci", "firewall", "software_flow_offload"]),
        hardware_flow_offload: flag(value, &["uci", "firewall", "hardware_flow_offload"]),
        fullcone: flag(value, &["uci", "firewall", "fullcone"]),
        nf_conntrack_acct: flag(value, &["files", "nf_conntrack_acct", "present"])
            && text(value, &["files", "nf_conntrack_acct", "value"]).as_deref() == Some("1"),
        flowtable_counter: flag(value, &["commands", "nft"])
            && number(value, &["commands", "nft_ruleset_exit_code"], 0) == 0
            && flag(value, &["commands", "nft_ruleset_has_flowtable_counter"]),
        tc: flag(value, &["commands", "tc"]),
        tc_clsact: flag(value, &["tc", "clsact"]),
        existing_tc_filters: flag(value, &["tc", "existing_filters"]),
        ifb: flag(value, &["files", "ifb"]),
        sqm: flag(value, &["uci", "sqm"]),
        qosify: flag(value, &["uci", "qosify"]) || flag(value, &["commands", "qosify"]),
        openclash,
        openclash_fake_ip: openclash
            && (en_mode.contains("fake-ip") || en_mode.contains("fake_ip")),
        openclash_tun_mix: openclash
            && (en_mode.contains("tun")
                || en_mode.contains("mix")
                || stack_type.contains("tun")
                || stack_type.contains("mix")),
        openclash_redirect_dns: redirect_dns,
        openclash_dns_chain_complete: !redirect_dns
            || flag(value, &["openclash", "dnsmasq_to_openclash_dns"]),
        openclash_router_self_proxy: openclash && flag(value, &["openclash", "router_self_proxy"]),
        openclash_udp_proxy: openclash && flag(value, &["openclash", "enable_udp_proxy"]),
        openclash_ipv6: openclash && flag(value, &["openclash", "ipv6_enable"]),
        dae,
        homeproxy: flag(value, &["uci", "homeproxy"]),
        lan_bridge: flag(value, &["files", "lan_bridge"]),
        vlan: flag(value, &["files", "vlan"]),
        wlan: flag(value, &["files", "wlan"]),
        lan_edge: flag(value, &["files", "lan_bridge"])
            || flag(value, &["files", "vlan"])
            || flag(value, &["files", "wlan"]),
        safe_attach: report_safe_attach,
        map_full: number(value, &["config", "max_clients"], 512) == 0,
    }
}

#[test]
fn every_legacy_probe_fixture_matches_the_production_rust_assessment() {
    let cases = [
        (
            "lanspeed-probe-base.json",
            "Degraded",
            "medium",
            vec!["bpf_runtime_loader_unavailable", "live_metrics_unavailable"],
            vec![],
        ),
        (
            "lanspeed-probe-conntrack-acct-disabled.json",
            "Degraded",
            "medium",
            vec![
                "bpf_object_missing",
                "nf_conntrack_acct_disabled",
                "conntrack_acct_disabled",
                "unsafe_attach",
                "live_metrics_unavailable",
            ],
            vec![],
        ),
        (
            "lanspeed-probe-dae-tc-conflict.json",
            "Degraded",
            "medium",
            vec![
                "existing_tc_filters_detected",
                "tc_filter_conflict",
                "dae_detected",
                "unsafe_attach",
                "live_metrics_unavailable",
            ],
            vec!["tc_filter_conflict", "proxy_stack"],
        ),
        (
            "lanspeed-probe-dae-tc-preserve.json",
            "Degraded",
            "medium",
            vec![
                "existing_tc_filters_detected",
                "dae_tc_preempts_bpf_ingress",
                "dae_detected",
                "bpf_runtime_loader_unavailable",
                "live_metrics_unavailable",
            ],
            vec!["proxy_stack"],
        ),
        (
            "lanspeed-probe-error.json",
            "Degraded",
            "low",
            vec![
                "probe_error",
                "lan_topology_probe_error",
                "bpf_runtime_loader_unavailable",
                "live_metrics_unavailable",
            ],
            vec![],
        ),
        (
            "lanspeed-probe-flowtable-missing-nlbwmon.json",
            "Degraded",
            "medium",
            vec![
                "bpf_object_missing",
                "flowtable_counter_missing",
                "nlbwmon_counter_conflict",
                "unsafe_attach",
                "live_metrics_unavailable",
            ],
            vec!["nlbwmon_counter_conflict"],
        ),
        (
            "lanspeed-probe-hardware-flow-offload.json",
            "Degraded",
            "medium",
            vec![
                "hardware_flow_offload_unsupported",
                "software_flow_offload_enabled",
                "bpf_runtime_loader_unavailable",
                "live_metrics_unavailable",
            ],
            vec!["hardware_flow_offload", "software_flow_offload"],
        ),
        (
            "lanspeed-probe-missing-tc.json",
            "Unsupported",
            "unsupported",
            vec!["tc_missing", "unsafe_attach", "live_metrics_unavailable"],
            vec![],
        ),
        (
            "lanspeed-probe-openclash-fakeip.json",
            "Degraded",
            "medium",
            vec![
                "openclash_detected",
                "openclash_fake_ip_low_remote_confidence",
                "bpf_runtime_loader_unavailable",
                "live_metrics_unavailable",
            ],
            vec!["proxy_stack"],
        ),
        (
            "lanspeed-probe-openclash-router-self.json",
            "Degraded",
            "medium",
            vec![
                "bpf_object_missing",
                "openclash_detected",
                "openclash_tun_conntrack_low_confidence",
                "openclash_dns_chain_incomplete",
                "openclash_router_self_proxy_detected",
                "unsafe_attach",
                "live_metrics_unavailable",
            ],
            vec!["proxy_stack"],
        ),
        (
            "lanspeed-probe-software-flow-offload.json",
            "Degraded",
            "medium",
            vec![
                "software_flow_offload_enabled",
                "fullcone_detected",
                "fullcone_nat_enabled",
                "bpf_runtime_loader_unavailable",
                "live_metrics_unavailable",
            ],
            vec!["software_flow_offload", "fullcone"],
        ),
    ];

    for (name, mode, confidence, warnings, conflicts) in cases {
        let fixture = fixture(name);
        let (config, observations) = observations(&fixture);
        let report = assess(&config, observations, &ProbeRuntimeHealth::default());
        assert_eq!(report.mode.as_str(), mode, "{name}");
        assert_eq!(report.confidence.as_str(), confidence, "{name}");
        assert_eq!(report.warnings, warnings, "{name}");
        assert_eq!(
            report.capabilities,
            expected_capabilities(&fixture, report.facts.tc.safe_attach),
            "{name}"
        );
        assert_eq!(
            report
                .conflicts
                .iter()
                .map(|item| item.id)
                .collect::<Vec<_>>(),
            conflicts,
            "{name}"
        );
        assert!(report.evidence.read_only, "{name}");
        assert!(!report.evidence.command.is_empty(), "{name}");
        assert!(!report.evidence.file.is_empty(), "{name}");
        assert!(!report.evidence.uci.is_empty(), "{name}");
        assert!(!report.evidence.ubus.is_empty(), "{name}");
        assert_eq!(report.evidence.tc.filters, report.facts.tc.filters);
        assert_eq!(
            report.evidence.proxy.openclash.installed,
            report.facts.proxy.openclash
        );
        assert_eq!(
            report.evidence.offload.hardware,
            report.facts.offload.hardware
        );
        assert_eq!(report.evidence.bpf.object_present, report.facts.bpf.object);
    }
}

#[test]
fn evidence_sources_are_typed_read_only_and_stable() {
    let (config, observations) =
        observations(&fixture("lanspeed-probe-openclash-router-self.json"));
    let report = assess(&config, observations, &ProbeRuntimeHealth::default());
    assert!(report
        .evidence
        .command
        .iter()
        .all(|item| item.source.starts_with("command:")));
    assert!(report
        .evidence
        .file
        .iter()
        .all(|item| item.source.starts_with("file:")));
    assert!(report
        .evidence
        .uci
        .iter()
        .all(|item| item.source.starts_with("uci:")));
    assert!(report
        .evidence
        .ubus
        .iter()
        .all(|item| item.source.starts_with("ubus:")));
    assert_eq!(
        report.evidence.proxy.openclash.router_self_bucket,
        "router_self"
    );
    assert_eq!(report.evidence.proxy.dae.fwmark, "0x8000000");
    assert_eq!(report.evidence.proxy.dae.route_table, "2023");
}

#[test]
fn command_and_tc_probes_are_bounded_read_only_parsers() {
    assert!(
        validate_read_only_args(ReadOnlyCommand::TcFilterShow, &["dev", "br-lan", "ingress"])
            .is_ok()
    );
    assert!(validate_read_only_args(
        ReadOnlyCommand::TcFilterShow,
        &["dev", "br-lan;reboot", "ingress"]
    )
    .is_err());

    let filters = parse_filter_lines(
        "eth1",
        "ingress",
        "filter protocol all pref 2 bpf chain 0 handle 0x20230005 dae direct-action\n\
         filter protocol all pref 49152 bpf chain 0 handle 0x1eed lanspeed_ingress direct-action\n",
    );
    assert!(dae_preempts_lan_ingress(&filters));
    assert!(!has_owned_identity_collision(&filters));
    let foreign = vec![TcFilter {
        owner: "dae".into(),
        ..filters[1].clone()
    }];
    assert!(has_owned_identity_collision(&foreign));
}
