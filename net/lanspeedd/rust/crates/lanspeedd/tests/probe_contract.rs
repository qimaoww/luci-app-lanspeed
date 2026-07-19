use lanspeedd::config::RuntimeConfig;
use lanspeedd::probe::collector::{
    probe_deadline, probe_due, CommandRunner, FilePresence, FileSource, NssStateProbe,
    ProbeCollector, ProbeMethod, UbusProbeResult, UbusQuery, UbusSource, UciOptionSnapshot,
    UciPackageSnapshot, UciSectionSnapshot, UciSource, PROBE_REFRESH_INTERVAL_MS,
};
use lanspeedd::probe::commands::{validate_read_only_args, ReadOnlyCommand};
use lanspeedd::probe::files::BoundedFile;
use lanspeedd::probe::tc::{
    dae_preempts_lan_ingress, has_foreign_filters, has_owned_identity_collision, parse_filter_lines,
};
use lanspeedd::probe::{
    assess, BpfObservation, CommandObservations, FileObservations, NssObservation,
    OffloadObservation, ProbeCapabilities, ProbeObservations, ProbeRuntimeHealth, ProxyObservation,
    TcFilter, TcObservations, UbusObservations, UciObservations,
};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

const REQUIRED_PROBE_FILES: [&str; 15] = [
    "/proc/sys/net/netfilter/nf_conntrack_acct",
    "/proc/net/nf_flowtable",
    "/sys/kernel/debug/netfilter/nf_flowtable",
    "/sys/class/net/ifb0",
    "any_configured_device/bridge",
    "/proc/net/vlan/config",
    "/sys/class/ieee80211",
    "/usr/share/lanspeed/bpf/collector-model.json",
    "/usr/lib/bpf/lanspeed-ebpf-kfunc",
    "/usr/lib/bpf/lanspeed-ebpf-fallback",
    "/etc/config/openclash",
    "/etc/config/dae",
    "/etc/config/daed",
    "/etc/config/homeproxy",
    "/etc/config/nlbwmon",
];

#[test]
fn production_probe_deadline_refreshes_every_thirty_seconds_and_on_reload() {
    assert_eq!(PROBE_REFRESH_INTERVAL_MS, 30_000);
    assert!(probe_due(0, 0, ProbeMethod::Status));
    assert!(!probe_due(29_999, 30_000, ProbeMethod::Status));
    assert!(probe_due(30_000, 30_000, ProbeMethod::Status));
    assert!(probe_due(1, u64::MAX, ProbeMethod::Reload));
    assert_eq!(probe_deadline(5), 30_005);
    assert_eq!(probe_deadline(u64::MAX - 1), u64::MAX);
}
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

    let filters: Vec<TcFilter> = value["tc"]["filters"]
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
    config.ifnames = filters
        .iter()
        .filter(|filter| filter.interface != "dae0" && filter.interface != "dae0peer")
        .map(|filter| filter.interface.clone())
        .collect();
    config.ifnames.sort();
    config.ifnames.dedup();
    // The legacy probe fixtures model an enabled LAN collection setup. Their
    // empty filter list means "no pre-existing TC filter", not "no configured
    // collection interface". Keep that distinction explicit so the fixtures
    // continue to exercise loader/map paths; no-target policy is covered by
    // its dedicated contract test.
    if config.enable_bpf && config.ifnames.is_empty() {
        config.interface_include.push("br-lan".into());
    }
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
            openclash_section: text(value, &["openclash", "section"]),
            dhcp_loaded: flag(value, &["openclash", "dhcp_loaded"]),
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
        probe_error: false,
        lan_probe_error: false,
        collected_evidence: Default::default(),
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
        let mut expected_commands = vec![
            "command:fw4".to_string(),
            "command:nft".into(),
            "command:tc".into(),
            "command:ubus".into(),
            "command:qosify".into(),
            "command:tc_filter_help".into(),
            "command:tc_qdisc_help".into(),
            "command:nft_list_flowtables".into(),
            "command:nft_list_ruleset".into(),
        ];
        let mut filter_sources = fixture["tc"]["filters"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|filter| {
                format!(
                    "command:tc_filter_show_{}_{}",
                    filter["interface"].as_str().unwrap().replace('-', "_"),
                    filter["direction"].as_str().unwrap()
                )
            })
            .collect::<Vec<_>>();
        filter_sources.dedup();
        if filter_sources.is_empty() {
            filter_sources.push("command:tc_filter_show_br_lan_ingress".into());
        }
        expected_commands.extend(filter_sources);
        assert_eq!(
            report.evidence.probe_sources.command, expected_commands,
            "{name}: command golden"
        );
        assert_eq!(
            report.evidence.probe_sources.file,
            REQUIRED_PROBE_FILES
                .iter()
                .map(|path| format!("file:{path}"))
                .collect::<Vec<_>>(),
            "{name}: file golden"
        );
        let mut expected_uci = [
            "firewall",
            "sqm",
            "qosify",
            "openclash",
            "dae",
            "daed",
            "homeproxy",
            "nlbwmon",
        ]
        .into_iter()
        .map(|package| format!("uci:{package}"))
        .collect::<Vec<_>>();
        if flag(&fixture, &["uci", "openclash"]) {
            let section = text(&fixture, &["openclash", "section"]).unwrap();
            expected_uci.extend(
                [
                    "en_mode",
                    "enable_redirect_dns",
                    "router_self_proxy",
                    "enable_udp_proxy",
                    "stack_type",
                    "ipv6_enable",
                ]
                .into_iter()
                .map(|option| format!("uci:openclash.{section}.{option}")),
            );
            expected_uci.push("uci:dhcp".into());
        }
        assert_eq!(
            report.evidence.probe_sources.uci, expected_uci,
            "{name}: uci golden"
        );
        let mut expected_ubus = vec!["ubus:network.interface.lan".to_string()];
        if flag(&fixture, &["uci", "dae"]) || flag(&fixture, &["uci", "daed"]) {
            expected_ubus.extend(["ubus:service.dae".into(), "ubus:service.daed".into()]);
        }
        assert_eq!(
            report.evidence.probe_sources.ubus, expected_ubus,
            "{name}: ubus golden"
        );
        for sources in [
            &report.evidence.probe_sources.command,
            &report.evidence.probe_sources.file,
            &report.evidence.probe_sources.uci,
            &report.evidence.probe_sources.ubus,
        ] {
            let unique = sources.iter().collect::<std::collections::BTreeSet<_>>();
            assert_eq!(unique.len(), sources.len(), "{name}: duplicate source");
        }
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
        for conflict in &report.conflicts {
            assert!(!conflict.severity.is_empty(), "{name}:{}", conflict.id);
            assert!(!conflict.message.is_empty(), "{name}:{}", conflict.id);
        }
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
fn every_fixture_has_complete_typed_evidence_and_an_explicit_flowtable_alias() {
    let names = [
        "lanspeed-probe-base.json",
        "lanspeed-probe-conntrack-acct-disabled.json",
        "lanspeed-probe-dae-tc-conflict.json",
        "lanspeed-probe-dae-tc-preserve.json",
        "lanspeed-probe-error.json",
        "lanspeed-probe-flowtable-missing-nlbwmon.json",
        "lanspeed-probe-hardware-flow-offload.json",
        "lanspeed-probe-missing-tc.json",
        "lanspeed-probe-openclash-fakeip.json",
        "lanspeed-probe-openclash-router-self.json",
        "lanspeed-probe-software-flow-offload.json",
    ];
    let required_files = [
        "/proc/sys/net/netfilter/nf_conntrack_acct",
        "/proc/net/nf_flowtable",
        "/sys/kernel/debug/netfilter/nf_flowtable",
        "/sys/class/net/ifb0",
        "any_configured_device/bridge",
        "/proc/net/vlan/config",
        "/sys/class/ieee80211",
        "/usr/share/lanspeed/bpf/collector-model.json",
        "/usr/lib/bpf/lanspeed-ebpf-kfunc",
        "/usr/lib/bpf/lanspeed-ebpf-fallback",
        "/etc/config/openclash",
        "/etc/config/dae",
        "/etc/config/daed",
        "/etc/config/homeproxy",
        "/etc/config/nlbwmon",
    ];
    for name in names {
        let fixture = fixture(name);
        let (config, observations) = observations(&fixture);
        let report = assess(&config, observations, &ProbeRuntimeHealth::default());
        for path in required_files {
            assert!(
                report.evidence.file.iter().any(|entry| entry.path == path),
                "{name}:{path}"
            );
        }
        for package in [
            "firewall",
            "sqm",
            "qosify",
            "openclash",
            "dae",
            "daed",
            "homeproxy",
            "nlbwmon",
        ] {
            assert!(
                report
                    .evidence
                    .uci
                    .iter()
                    .any(|entry| entry.package == package && entry.section.is_none()),
                "{name}:{package}"
            );
        }
        let canonical = report
            .evidence
            .command
            .iter()
            .find(|entry| entry.source == "command:nft_list_flowtables")
            .unwrap();
        let alias = report
            .evidence
            .command
            .iter()
            .find(|entry| entry.source == "command:nft_list_ruleset")
            .unwrap();
        assert_eq!(canonical.command, "nft list flowtables");
        assert_eq!(alias.command, "nft list flowtables");
        assert!(alias
            .summary
            .as_deref()
            .unwrap()
            .contains("legacy evidence alias"));
        assert_eq!(report.evidence.collector.mode, report.mode.as_str());
        assert_eq!(
            report.evidence.collector.confidence,
            report.confidence.as_str()
        );
        assert_eq!(report.evidence.tc.owner, "lanspeed");
        assert!(!report.evidence.tc.delete_existing);
        assert!(!report.evidence.tc.reorder_existing);
        assert_eq!(report.evidence.probe_error, report.facts.probe_error);
        assert_eq!(
            report.evidence.lan_probe_error,
            report.facts.lan_probe_error
        );
        if flag(&fixture, &["uci", "openclash"]) {
            let section = text(&fixture, &["openclash", "section"]).unwrap();
            for option in [
                "en_mode",
                "enable_redirect_dns",
                "router_self_proxy",
                "enable_udp_proxy",
                "stack_type",
                "ipv6_enable",
            ] {
                assert!(
                    report
                        .evidence
                        .uci
                        .iter()
                        .any(|entry| entry.section.as_deref() == Some(&section)
                            && entry.option.as_deref() == Some(option)),
                    "{name}:{option}"
                );
            }
            assert!(report
                .evidence
                .uci
                .iter()
                .any(|entry| entry.package == "dhcp"
                    && entry.loaded == flag(&fixture, &["openclash", "dhcp_loaded"])));
        }
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
    assert!(validate_read_only_args(ReadOnlyCommand::TcQdiscShow, &["dev", "br-lan"]).is_ok());
    assert!(
        validate_read_only_args(ReadOnlyCommand::TcQdiscShow, &["dev", "br-lan;reboot"]).is_err()
    );
    assert!(validate_read_only_args(
        ReadOnlyCommand::TcFilterShow,
        &["dev", "br-lan;reboot", "ingress"]
    )
    .is_err());
    assert!(validate_read_only_args(ReadOnlyCommand::UbusNetworkLanStatus, &[]).is_ok());
    assert!(validate_read_only_args(ReadOnlyCommand::UbusServiceDae, &[]).is_ok());
    assert!(validate_read_only_args(ReadOnlyCommand::UbusServiceDaed, &[]).is_ok());
    assert!(validate_read_only_args(ReadOnlyCommand::UbusServiceDae, &["start"]).is_err());
    assert_eq!(
        ReadOnlyCommand::NftListFlowtables.evidence_key(&[]),
        "nft_list_flowtables"
    );
    assert_eq!(
        ReadOnlyCommand::NftDaeDnsUdp53.evidence_key(&[]),
        "nft_dae_dns_udp53"
    );
    assert_eq!(
        ReadOnlyCommand::TcFilterShow.evidence_key(&["dev", "br-lan", "ingress"]),
        "tc_filter_show_br_lan_ingress"
    );
    assert_eq!(
        ReadOnlyCommand::TcQdiscShow.evidence_key(&["dev", "br-lan"]),
        "tc_qdisc_show_br_lan"
    );
    assert!(ReadOnlyCommand::NftDaeDnsUdp53.output_cap() >= 64 * 1024);
    assert_eq!(ReadOnlyCommand::NftListFlowtables.output_cap(), 4_096);
    assert!(ReadOnlyCommand::TcFilterShow.nonzero_exit_is_absence());
    assert!(ReadOnlyCommand::IpRouteShow.nonzero_exit_is_absence());
    assert!(!ReadOnlyCommand::IpRuleShow.nonzero_exit_is_absence());

    let filters = parse_filter_lines(
        "eth1",
        "ingress",
        "filter protocol all pref 2 bpf chain 0\n\
         filter protocol all pref 2 bpf chain 0 handle 0x20230005 dae direct-action\n\
         filter protocol all pref 49152 bpf chain 0\n\
         filter protocol all pref 49152 bpf chain 0 handle 0x1eed lanspeed_ingress direct-action\n",
    );
    assert_eq!(filters.len(), 2);
    assert!(dae_preempts_lan_ingress(&filters, &["eth1".into()]));
    assert!(!dae_preempts_lan_ingress(&filters, &["br-lan".into()]));
    assert!(!has_owned_identity_collision(&filters));
    assert!(has_foreign_filters(&filters));

    let owned_only = parse_filter_lines(
        "eth1",
        "ingress",
        "filter protocol all pref 49152 bpf chain 0\n\
         filter protocol all pref 49152 bpf chain 0 handle 0x1eed lanspeed_ingress direct-action\n",
    );
    assert_eq!(owned_only.len(), 1);
    assert!(!has_foreign_filters(&owned_only));
    let foreign = vec![TcFilter {
        owner: "dae".into(),
        ..filters[1].clone()
    }];
    assert!(has_owned_identity_collision(&foreign));
}

#[test]
fn missing_optional_dae_route_table_is_not_a_probe_failure() {
    let commands = FakeCommands {
        ip_route_exit_code: 1,
        ..FakeCommands::default()
    };
    let mut collector = ProbeCollector::new(
        commands,
        FakeFiles::default(),
        FakeUci::default(),
        FakeUbus::default(),
    );

    let report = collector.collect(
        &RuntimeConfig::default(),
        &ProbeRuntimeHealth::default(),
        ProbeMethod::Health,
    );

    assert!(!report.evidence.probe_error);
    assert!(!report.warnings.contains(&"probe_error"));
    assert!(!report.evidence.probe_failures.iter().any(|failure| {
        failure.source == "command:ip_route_table_2023"
    }));
    let route = report
        .evidence
        .command
        .iter()
        .find(|entry| entry.source == "command:ip_route_table_2023")
        .unwrap();
    assert_eq!(route.exit_code, Some(1));
    assert_eq!(route.supported, Some(true));
    assert_eq!(route.summary.as_deref(), Some("optional state not present"));
}

#[test]
fn command_availability_requires_an_executable_file() {
    use std::os::unix::fs::PermissionsExt;
    let directory =
        std::env::temp_dir().join(format!("lanspeed-probe-path-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let command = directory.join("probe-command");
    fs::write(&command, b"not executed").unwrap();
    fs::set_permissions(&command, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!lanspeedd::probe::commands::command_available(
        command.to_str().unwrap()
    ));
    fs::set_permissions(&command, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(lanspeedd::probe::commands::command_available(
        command.to_str().unwrap()
    ));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn report_mode_confidence_and_capabilities_come_from_the_single_policy_decision() {
    let mut config = RuntimeConfig::default();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut observations = ProbeObservations::default();
    observations.commands.tc = true;
    observations.tc.clsact = true;
    observations.tc.bpf = true;
    observations.files.lan_bridge = true;
    observations.files.nf_conntrack_acct_present = true;
    observations.bpf.package = true;
    observations.bpf.object = true;
    observations.nss.present = true;
    observations.nss.ecm_active = true;
    observations.nss.direct_state_present = true;
    observations.nss.direct_state_readable = true;

    let direct = assess(
        &config,
        observations.clone(),
        &ProbeRuntimeHealth::default(),
    );
    assert_eq!(direct.mode.as_str(), "Full");
    assert_eq!(direct.confidence.as_str(), "high");
    assert!(direct.capabilities.live_metrics);
    assert!(!direct.capabilities.bpf);
    assert!(!direct.capabilities.conntrack_fallback);

    observations.files.nf_conntrack_acct_value = Some("1".into());
    let sync = assess(
        &config,
        observations.clone(),
        &ProbeRuntimeHealth::default(),
    );
    assert_eq!(sync.mode.as_str(), "Degraded");
    assert!(sync.capabilities.live_metrics);
    assert!(sync.capabilities.conntrack_fallback);
    assert!(!sync.capabilities.bpf);

    observations.commands.tc = false;
    let no_tc_sync = assess(&config, observations, &ProbeRuntimeHealth::default());
    assert_eq!(no_tc_sync.mode.as_str(), "Degraded");
    assert!(no_tc_sync.capabilities.live_metrics);
}

#[test]
fn nss_presence_does_not_invent_the_firewall_hardware_offload_flag() {
    let mut config = RuntimeConfig::default();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    config.interface_include.push("br-lan".into());
    let mut observations = ProbeObservations::default();
    observations.commands.tc = true;
    observations.tc.clsact = true;
    observations.tc.bpf = true;
    observations.files.lan_bridge = true;
    observations.files.nf_conntrack_acct_present = true;
    observations.files.nf_conntrack_acct_value = Some("1".into());
    observations.bpf.package = true;
    observations.bpf.object = true;
    observations.nss.present = true;
    observations.nss.ecm_active = true;
    observations.proxy.daed_running = true;
    observations.proxy.daed_process = true;
    let runtime = ProbeRuntimeHealth {
        bpf_object_loaded: true,
        bpf_attached: true,
        bpf_map_read_attempted: true,
        bpf_map_read_ok: true,
        ..ProbeRuntimeHealth::default()
    };
    let report = assess(&config, observations, &runtime);
    assert!(report.capabilities.bpf);
    assert!(!report.capabilities.hardware_flow_offload);
    assert!(!report
        .warnings
        .contains(&"hardware_flow_offload_unsupported"));
    assert!(report.warnings.contains(&"dae_runtime_prefers_bpf"));
}

#[test]
fn runtime_bpf_capacity_and_self_heal_failures_are_visible_warnings() {
    let config = RuntimeConfig::default();
    let mut observations = ProbeObservations::default();
    observations.bpf.map_full_observed = true;
    let runtime = ProbeRuntimeHealth {
        bpf_self_heal_failures: 1,
        bpf_self_heal_last_failure: Some("attach failed".into()),
        ..ProbeRuntimeHealth::default()
    };
    let report = assess(&config, observations, &runtime);
    assert!(report.warnings.contains(&"map_full"));
    assert!(report.warnings.contains(&"bpf_tc_self_heal_failed"));
}

#[derive(Default)]
struct FakeCommands {
    calls: Vec<(ReadOnlyCommand, Vec<String>)>,
    timeout: bool,
    truncated: bool,
    tc_help_stderr_only: bool,
    ruleset_truncated_only: bool,
    ip_route_exit_code: i32,
}

impl CommandRunner for FakeCommands {
    type Error = String;
    fn available(&mut self, command: ReadOnlyCommand) -> Result<bool, Self::Error> {
        let _ = command;
        Ok(true)
    }
    fn run(
        &mut self,
        command: ReadOnlyCommand,
        args: &[&str],
    ) -> Result<lanspeedd::probe::commands::CommandResult, Self::Error> {
        self.calls
            .push((command, args.iter().map(|arg| (*arg).into()).collect()));
        let stdout = match command {
            ReadOnlyCommand::TcFilterHelp if !self.tc_help_stderr_only => {
                "Usage: tc ... bpf".into()
            }
            ReadOnlyCommand::TcQdiscHelp if !self.tc_help_stderr_only => {
                "Usage: tc ... clsact".into()
            }
            ReadOnlyCommand::NftListFlowtables => "flowtable ft { counter; }".into(),
            _ => String::new(),
        };
        Ok(lanspeedd::probe::commands::CommandResult {
            source: format!("command:{command:?}"),
            program: command.program().into(),
            args: args.iter().map(|arg| (*arg).into()).collect(),
            exit_code: Some(if command == ReadOnlyCommand::IpRouteShow {
                self.ip_route_exit_code
            } else {
                0
            }),
            stdout,
            stderr: match command {
                ReadOnlyCommand::TcFilterHelp if self.tc_help_stderr_only => {
                    "Usage: tc ... bpf".into()
                }
                ReadOnlyCommand::TcQdiscHelp if self.tc_help_stderr_only => {
                    "Usage: tc ... clsact".into()
                }
                _ => String::new(),
            },
            timed_out: self.timeout,
            output_truncated: self.truncated
                || (self.ruleset_truncated_only && command == ReadOnlyCommand::NftDaeDnsUdp53),
        })
    }
}

#[derive(Default)]
struct FakeFiles {
    entries: BTreeMap<String, BoundedFile>,
    errors: BTreeSet<String>,
    reads: Rc<RefCell<Vec<(String, usize)>>>,
    nss_state_error: bool,
    nss_state: NssStateProbe,
}
impl FileSource for FakeFiles {
    type Error = String;
    fn read(&mut self, path: &str, cap: usize) -> Result<BoundedFile, Self::Error> {
        self.reads.borrow_mut().push((path.into(), cap));
        if self.errors.contains(path) {
            return Err("permission denied".into());
        }
        Ok(self.entries.get(path).cloned().unwrap_or(BoundedFile {
            source: format!("file:{path}"),
            path: path.into(),
            present: false,
            value: None,
            truncated: false,
        }))
    }
    fn exists(&mut self, path: &str) -> Result<FilePresence, Self::Error> {
        if self.errors.contains(path) {
            return Err("symlink loop".into());
        }
        Ok(
            if self.entries.get(path).is_some_and(|entry| entry.present) {
                FilePresence::Present
            } else {
                FilePresence::Absent
            },
        )
    }
    fn dir_has_entries(&mut self, path: &str) -> Result<bool, Self::Error> {
        Ok(self.exists(path)? == FilePresence::Present)
    }
    fn probe_nss_state(&mut self) -> Result<NssStateProbe, Self::Error> {
        if self.nss_state_error {
            Err("raw nss state error".into())
        } else {
            Ok(self.nss_state.clone())
        }
    }
}

#[derive(Default)]
struct FakeUci(BTreeMap<String, UciPackageSnapshot>);
impl UciSource for FakeUci {
    type Error = String;
    fn load(&mut self, package: &'static str) -> Result<Option<UciPackageSnapshot>, Self::Error> {
        Ok(self.0.get(package).cloned())
    }
}

struct FailingUci;
impl UciSource for FailingUci {
    type Error = String;
    fn load(&mut self, _package: &'static str) -> Result<Option<UciPackageSnapshot>, Self::Error> {
        Err("raw uci secret value".into())
    }
}

#[derive(Default)]
struct FakeUbus {
    fail: bool,
    timed_out: bool,
    truncated: bool,
    exit_code: Option<i32>,
}
impl UbusSource for FakeUbus {
    type Error = String;
    fn query(&mut self, query: UbusQuery) -> Result<UbusProbeResult, Self::Error> {
        if self.fail {
            return Err("ubus unavailable".into());
        }
        Ok(UbusProbeResult {
            query,
            exit_code: self.exit_code.unwrap_or(0),
            summary: "status available".into(),
            output: "{}".into(),
            timed_out: self.timed_out,
            truncated: self.truncated || self.timed_out,
        })
    }
}

#[test]
fn injectable_production_collector_records_every_read_only_source_and_error() {
    let commands = FakeCommands {
        tc_help_stderr_only: true,
        ..FakeCommands::default()
    };
    let mut files = FakeFiles::default();
    for path in [
        "/proc/sys/net/netfilter/nf_conntrack_acct",
        "/proc/net/nf_flowtable",
        "/sys/class/net/br-lan/bridge",
        "/usr/share/lanspeed/bpf/collector-model.json",
        "/usr/lib/bpf/lanspeed-ebpf-kfunc",
        "/usr/lib/bpf/lanspeed-ebpf-fallback",
    ] {
        files.entries.insert(
            path.into(),
            BoundedFile {
                source: format!("file:{path}"),
                path: path.into(),
                present: true,
                value: (path.contains("acct")).then(|| "1".into()),
                truncated: false,
            },
        );
    }
    let mut uci = FakeUci::default();
    uci.0.insert(
        "firewall".into(),
        UciPackageSnapshot {
            name: "firewall".into(),
            sections: vec![UciSectionSnapshot {
                name: "defaults".into(),
                kind: "defaults".into(),
                options: vec![UciOptionSnapshot {
                    name: "flow_offloading".into(),
                    values: vec!["0".into()],
                }],
            }],
        },
    );
    uci.0.insert(
        "openclash".into(),
        UciPackageSnapshot {
            name: "openclash".into(),
            sections: vec![UciSectionSnapshot {
                name: "config".into(),
                kind: "config".into(),
                options: vec![
                    UciOptionSnapshot {
                        name: "en_mode".into(),
                        values: vec!["fake-ip".into()],
                    },
                    UciOptionSnapshot {
                        name: "enable_redirect_dns".into(),
                        values: vec!["1".into()],
                    },
                ],
            }],
        },
    );
    uci.0.insert(
        "dhcp".into(),
        UciPackageSnapshot {
            name: "dhcp".into(),
            sections: vec![UciSectionSnapshot {
                name: "dnsmasq".into(),
                kind: "dnsmasq".into(),
                options: vec![UciOptionSnapshot {
                    name: "server".into(),
                    values: vec!["127.0.0.1#7874".into()],
                }],
            }],
        },
    );
    let mut config = RuntimeConfig::default();
    config.enable_bpf = true;
    config.ifnames = vec!["br-lan".into()];
    let mut runtime = ProbeRuntimeHealth::default();
    runtime.bpf_object_loaded = true;
    runtime.bpf_attached = true;
    runtime.bpf_map_read_attempted = true;
    runtime.bpf_map_read_ok = true;

    let mut collector = ProbeCollector::new(commands, files, uci, FakeUbus::default());
    let report = collector.collect(&config, &runtime, ProbeMethod::Health);
    assert_eq!(report.mode.as_str(), "Full");
    assert!(report
        .evidence
        .probe_sources
        .command
        .contains(&"command:nft_list_flowtables".into()));
    assert!(report
        .evidence
        .probe_sources
        .command
        .iter()
        .any(|source| source == "command:nft_list_ruleset"));
    assert!(report
        .evidence
        .probe_sources
        .command
        .iter()
        .any(|source| source == "command:nft_dae_dns_udp53"));
    let legacy_alias = report
        .evidence
        .command
        .iter()
        .find(|entry| entry.source == "command:nft_list_ruleset")
        .unwrap();
    assert_eq!(legacy_alias.command, "nft list flowtables");
    let dae_scan = report
        .evidence
        .command
        .iter()
        .find(|entry| entry.source == "command:nft_dae_dns_udp53")
        .unwrap();
    assert_eq!(dae_scan.command, "nft list ruleset");
    assert!(report.evidence.command.iter().all(|entry| {
        entry.source.strip_prefix("command:").is_some_and(|key| {
            key.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
    }));
    assert!(report.facts.tc.bpf && report.facts.tc.clsact);
    assert!(report
        .evidence
        .uci
        .iter()
        .any(|entry| entry.package == "firewall" && entry.loaded));
    assert!(report
        .evidence
        .ubus
        .iter()
        .any(|entry| entry.object == "network.interface.lan"));
    assert!(report.facts.proxy.openclash_fake_ip);
    assert!(report.facts.proxy.openclash_dns_chain_complete);

    let (mut commands, files, uci, ubus) = collector.into_parts();
    commands.tc_help_stderr_only = false;
    commands.ruleset_truncated_only = true;
    let mut large_ruleset = ProbeCollector::new(commands, files, uci, ubus);
    let large_ruleset_report = large_ruleset.collect(&config, &runtime, ProbeMethod::Health);
    assert!(!large_ruleset_report.evidence.probe_error);

    let (mut commands, files, uci, mut ubus) = large_ruleset.into_parts();
    commands.ruleset_truncated_only = false;
    commands.timeout = true;
    commands.truncated = true;
    ubus.fail = true;
    let mut failed = ProbeCollector::new(commands, files, uci, ubus);
    let failed_report = failed.collect(&config, &runtime, ProbeMethod::Health);
    assert!(failed_report.evidence.probe_error);
    assert!(failed_report.warnings.contains(&"probe_error"));
    assert!(failed_report.evidence.probe_failures.iter().any(|failure| {
        failure.kind == "command"
            && failure.reason == "timeout"
            && failure.source.starts_with("command:")
    }));
    assert!(failed_report.evidence.probe_failures.iter().any(|failure| {
        failure.kind == "ubus"
            && failure.reason == "query_failed"
            && failure.source == "ubus:network.interface.lan"
    }));
}

#[test]
fn openclash_uses_one_relevant_section_without_cross_section_splicing() {
    let mut uci = FakeUci::default();
    uci.0.insert(
        "openclash".into(),
        UciPackageSnapshot {
            name: "openclash".into(),
            sections: vec![
                UciSectionSnapshot {
                    name: "irrelevant".into(),
                    kind: "config".into(),
                    options: vec![UciOptionSnapshot {
                        name: "enabled".into(),
                        values: vec!["1".into()],
                    }],
                },
                UciSectionSnapshot {
                    name: "first".into(),
                    kind: "config".into(),
                    options: vec![UciOptionSnapshot {
                        name: "en_mode".into(),
                        values: vec!["fake-ip".into()],
                    }],
                },
                UciSectionSnapshot {
                    name: "second".into(),
                    kind: "config".into(),
                    options: vec![UciOptionSnapshot {
                        name: "enable_redirect_dns".into(),
                        values: vec!["1".into()],
                    }],
                },
            ],
        },
    );
    let mut collector = ProbeCollector::new(
        FakeCommands::default(),
        FakeFiles::default(),
        uci,
        FakeUbus::default(),
    );
    let report = collector.collect(
        &RuntimeConfig::default(),
        &ProbeRuntimeHealth::default(),
        ProbeMethod::Health,
    );
    assert!(report
        .evidence
        .uci
        .iter()
        .any(|entry| entry.source == "uci:openclash.first.en_mode"));
    assert!(report.facts.proxy.openclash_fake_ip);
    assert!(!report.facts.proxy.openclash_redirect_dns);
}

#[test]
fn file_io_errors_are_probe_errors_while_not_found_is_only_missing() {
    let acct = "/proc/sys/net/netfilter/nf_conntrack_acct";
    let loop_path = "/proc/net/nf_flowtable";
    let directory = "/sys/class/ieee80211";
    let mut files = FakeFiles::default();
    files.errors.insert(acct.into());
    files.errors.insert(loop_path.into());
    files.errors.insert(directory.into());
    let mut collector = ProbeCollector::new(
        FakeCommands::default(),
        files,
        FakeUci::default(),
        FakeUbus::default(),
    );
    let report = collector.collect(
        &RuntimeConfig::default(),
        &ProbeRuntimeHealth::default(),
        ProbeMethod::Health,
    );
    assert!(report.evidence.probe_error);
    assert!(report.evidence.file.iter().any(|entry| entry.path == acct
        && entry.status == "error"
        && entry.error.as_deref() == Some("permission denied")));
    assert!(report
        .evidence
        .file
        .iter()
        .any(|entry| entry.path == loop_path
            && entry.status == "error"
            && entry.error.as_deref() == Some("symlink loop")));
    assert!(report
        .evidence
        .file
        .iter()
        .any(|entry| entry.path == directory
            && entry.status == "error"
            && entry.error.as_deref() == Some("symlink loop")));
    assert!(report
        .evidence
        .file
        .iter()
        .any(|entry| entry.path == "/sys/class/net/ifb0"
            && entry.source == "file:/sys/class/net/ifb0"
            && !entry.present));
    assert!(report.evidence.probe_failures.iter().any(|failure| {
        failure.kind == "file"
            && failure.source == format!("file:{acct}")
            && failure.reason == "read_failed"
            && failure.exit_code.is_none()
    }));
}

#[test]
fn uci_and_nss_failures_are_classified_without_storing_raw_error_text() {
    let mut files = FakeFiles::default();
    files.nss_state_error = true;
    let mut collector = ProbeCollector::new(
        FakeCommands::default(),
        files,
        FailingUci,
        FakeUbus::default(),
    );

    let report = collector.collect(
        &RuntimeConfig::default(),
        &ProbeRuntimeHealth::default(),
        ProbeMethod::Health,
    );

    assert!(report.evidence.probe_error);
    assert!(report.evidence.probe_failures.iter().any(|failure| {
        failure.kind == "uci"
            && failure.source == "uci:firewall"
            && failure.reason == "load_failed"
            && failure.exit_code.is_none()
    }));
    assert!(report.evidence.probe_failures.iter().any(|failure| {
        failure.kind == "nss"
            && failure.source == "nss:ecm_state"
            && failure.reason == "state_probe_failed"
            && failure.exit_code.is_none()
    }));
    assert!(report
        .evidence
        .probe_failures
        .iter()
        .all(|failure| !failure.source.contains("raw") && !failure.source.contains("secret")));
}

#[test]
fn ubus_timeout_and_present_unreadable_nss_state_have_distinct_reasons() {
    let files = FakeFiles {
        nss_state: NssStateProbe {
            present: true,
            readable: false,
            errno: 13,
            state_major: 0,
            source_path: None,
        },
        ..FakeFiles::default()
    };
    let ubus = FakeUbus {
        timed_out: true,
        ..FakeUbus::default()
    };
    let mut collector =
        ProbeCollector::new(FakeCommands::default(), files, FakeUci::default(), ubus);

    let report = collector.collect(
        &RuntimeConfig::default(),
        &ProbeRuntimeHealth::default(),
        ProbeMethod::Health,
    );

    assert!(report.evidence.probe_failures.iter().any(|failure| {
        failure.kind == "nss"
            && failure.source == "nss:ecm_state"
            && failure.reason == "state_unreadable"
    }));
    assert!(report.evidence.probe_failures.iter().any(|failure| {
        failure.kind == "ubus"
            && failure.source == "ubus:network.interface.lan"
            && failure.reason == "timeout"
    }));
    assert!(!report
        .evidence
        .probe_failures
        .iter()
        .any(|failure| { failure.kind == "ubus" && failure.reason == "output_truncated" }));
}

#[test]
fn production_collector_honors_every_legacy_nss_alternative_path() {
    let cases = [
        ("present", "/sys/bus/platform/drivers/qca-nss"),
        ("present", "/sys/kernel/debug/qca-nss-drv"),
        ("present", "/proc/sys/dev/nss"),
        ("ecm", "/sys/kernel/debug/ecm"),
        ("ppe", "/sys/module/ppe_drv"),
        ("ppe", "/sys/kernel/debug/qca-nss-ppe"),
        ("ppe", "/sys/kernel/debug/ppe_drv"),
        ("nsm", "/sys/module/nss_nsm"),
        ("nsm", "/sys/kernel/debug/qca-nss-nsm"),
        ("dp", "/sys/module/nss_dp"),
        ("mcs", "/sys/module/mc_snooping"),
        ("bridge", "/sys/module/qca_nss_bridge_mgr"),
        ("ifb", "/sys/module/nss_ifb"),
        ("ifb", "/sys/module/nss-ifb"),
    ];
    for (kind, path) in cases {
        let mut files = FakeFiles::default();
        files.entries.insert(
            path.into(),
            BoundedFile {
                source: format!("file:{path}"),
                path: path.into(),
                present: true,
                value: None,
                truncated: false,
            },
        );
        let mut collector = ProbeCollector::new(
            FakeCommands::default(),
            files,
            FakeUci::default(),
            FakeUbus::default(),
        );
        let report = collector.collect(
            &RuntimeConfig::default(),
            &ProbeRuntimeHealth::default(),
            ProbeMethod::Health,
        );
        match kind {
            "present" => assert!(report.facts.nss.present, "{path}"),
            "ecm" => assert!(report.facts.nss.ecm_active, "{path}"),
            "ppe" => assert!(report.facts.nss.ppe_active, "{path}"),
            "nsm" => assert!(report.evidence.nss.nsm_active, "{path}"),
            "dp" => {
                assert!(report.evidence.nss.dp_active, "{path}");
                assert!(report.facts.nss.present, "{path}");
            }
            "mcs" => assert!(report.evidence.nss.mcs_active, "{path}"),
            "bridge" => assert!(report.evidence.nss.bridge_mgr, "{path}"),
            "ifb" => assert!(report.evidence.nss.ifb_active, "{path}"),
            _ => unreachable!(),
        }
    }
}

const ECM_CONNECTION_COUNT: &str = "/sys/kernel/debug/ecm/ecm_db/connection_count";
const ECM_CONNECTION_COUNT_SIMPLE: &str = "/sys/kernel/debug/ecm/ecm_db/connection_count_simple";
const ECM_HOST_COUNT: &str = "/sys/kernel/debug/ecm/ecm_db/host_count";
const ECM_MAPPING_COUNT: &str = "/sys/kernel/debug/ecm/ecm_db/mapping_count";

fn fake_file(path: &str, value: &str) -> BoundedFile {
    BoundedFile {
        source: format!("file:{path}"),
        path: path.into(),
        present: true,
        value: Some(value.into()),
        truncated: false,
    }
}

fn collect_with_files(files: FakeFiles) -> lanspeedd::probe::ProbeReport {
    ProbeCollector::new(
        FakeCommands::default(),
        files,
        FakeUci::default(),
        FakeUbus::default(),
    )
    .collect(
        &RuntimeConfig::default(),
        &ProbeRuntimeHealth::default(),
        ProbeMethod::Health,
    )
}

#[test]
fn nss_debugfs_counts_are_bounded_and_primary_total_wins_over_simple_total() {
    let mut files = FakeFiles::default();
    let reads = files.reads.clone();
    for (path, value) in [
        (ECM_CONNECTION_COUNT, "99"),
        (
            ECM_CONNECTION_COUNT_SIMPLE,
            "tcp 12 udp 34 other 5 total 51",
        ),
        (ECM_HOST_COUNT, "7"),
        (ECM_MAPPING_COUNT, "8"),
    ] {
        files.entries.insert(path.into(), fake_file(path, value));
    }

    let report = collect_with_files(files);

    assert_eq!(report.evidence.nss.accelerated_connections, Some(99));
    assert_eq!(report.evidence.nss.accelerated_tcp, Some(12));
    assert_eq!(report.evidence.nss.accelerated_udp, Some(34));
    assert_eq!(report.evidence.nss.accelerated_other, Some(5));
    assert_eq!(report.evidence.nss.host_count, Some(7));
    assert_eq!(report.evidence.nss.mapping_count, Some(8));
    let debugfs_reads = reads
        .borrow()
        .iter()
        .filter(|(path, _)| {
            matches!(
                path.as_str(),
                ECM_CONNECTION_COUNT
                    | ECM_CONNECTION_COUNT_SIMPLE
                    | ECM_HOST_COUNT
                    | ECM_MAPPING_COUNT
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        debugfs_reads,
        [
            (ECM_CONNECTION_COUNT.into(), 4_096),
            (ECM_CONNECTION_COUNT_SIMPLE.into(), 4_096),
            (ECM_HOST_COUNT.into(), 4_096),
            (ECM_MAPPING_COUNT.into(), 4_096),
        ]
    );
    for path in [
        ECM_CONNECTION_COUNT,
        ECM_CONNECTION_COUNT_SIMPLE,
        ECM_HOST_COUNT,
        ECM_MAPPING_COUNT,
    ] {
        assert!(report.evidence.file.iter().any(|entry| {
            entry.path == path
                && entry.present
                && entry.status == "present"
                && entry.error.is_none()
        }));
    }
}

#[test]
fn nss_debugfs_simple_counts_reject_the_entire_line_when_any_number_is_invalid() {
    let mut files = FakeFiles::default();
    files.entries.insert(
        ECM_CONNECTION_COUNT.into(),
        fake_file(ECM_CONNECTION_COUNT, "18446744073709551616"),
    );
    files.entries.insert(
        ECM_CONNECTION_COUNT_SIMPLE.into(),
        fake_file(
            ECM_CONNECTION_COUNT_SIMPLE,
            "tcp -1 udp 34 other 18446744073709551616 total 51",
        ),
    );

    let report = collect_with_files(files);

    assert_eq!(report.evidence.nss.accelerated_connections, None);
    assert_eq!(report.evidence.nss.accelerated_tcp, None);
    assert_eq!(report.evidence.nss.accelerated_udp, None);
    assert_eq!(report.evidence.nss.accelerated_other, None);
}

#[test]
fn nss_debugfs_missing_or_malformed_files_do_not_invent_counts() {
    let mut files = FakeFiles::default();
    files.entries.insert(
        ECM_CONNECTION_COUNT_SIMPLE.into(),
        fake_file(
            ECM_CONNECTION_COUNT_SIMPLE,
            "udp 12 tcp 34 other 5 total 51",
        ),
    );
    files.entries.insert(
        ECM_HOST_COUNT.into(),
        fake_file(ECM_HOST_COUNT, "not-a-number"),
    );

    let report = collect_with_files(files);

    assert_eq!(report.evidence.nss.accelerated_connections, None);
    assert_eq!(report.evidence.nss.accelerated_tcp, None);
    assert_eq!(report.evidence.nss.accelerated_udp, None);
    assert_eq!(report.evidence.nss.accelerated_other, None);
    assert_eq!(report.evidence.nss.host_count, None);
    assert_eq!(report.evidence.nss.mapping_count, None);
    assert!(!report.evidence.probe_error);
}

#[test]
fn nss_debugfs_io_and_truncation_errors_are_evidence_without_losing_valid_fallbacks() {
    let mut files = FakeFiles::default();
    files.errors.insert(ECM_CONNECTION_COUNT.into());
    files.entries.insert(
        ECM_CONNECTION_COUNT_SIMPLE.into(),
        fake_file(
            ECM_CONNECTION_COUNT_SIMPLE,
            "tcp 12 udp 34 other 5 total 51",
        ),
    );
    let mut host = fake_file(ECM_HOST_COUNT, "7");
    host.truncated = true;
    files.entries.insert(ECM_HOST_COUNT.into(), host);

    let report = collect_with_files(files);

    assert!(report.evidence.probe_error);
    assert_eq!(report.evidence.nss.accelerated_connections, Some(51));
    assert_eq!(report.evidence.nss.accelerated_tcp, Some(12));
    assert_eq!(report.evidence.nss.host_count, None);
    assert!(report.evidence.file.iter().any(|entry| {
        entry.path == ECM_CONNECTION_COUNT
            && entry.status == "error"
            && entry.error.as_deref() == Some("permission denied")
    }));
    assert!(report.evidence.file.iter().any(|entry| {
        entry.path == ECM_HOST_COUNT && entry.status == "truncated" && entry.error.is_none()
    }));
}
