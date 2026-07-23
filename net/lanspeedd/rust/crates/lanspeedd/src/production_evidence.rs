use std::collections::HashSet;

use serde_json::{json, Map, Value};

use crate::{
    collectors::nss,
    config::RuntimeConfig,
    policy::{PolicyDecision, RateCollector},
    probe::{ProbeFailure, ProbeReport, RuntimeHealth},
};

const PROBE_FAILURE_LIMIT: usize = 32;
const PROBE_SOURCE_LIMIT: usize = 160;
const PROBE_FAILURE_KINDS: [&str; 6] = ["probe", "command", "file", "uci", "ubus", "nss"];

const PUBLIC_COMMAND_SOURCES: [&str; 11] = [
    "command:tc",
    "command:nft",
    "command:ubus",
    "command:fw4",
    "command:qosify",
    "command:tc_filter_help",
    "command:tc_qdisc_help",
    "command:nft_list_flowtables",
    "command:nft_dae_dns_udp53",
    "command:ip_rule_show",
    "command:ip_route_table_2023",
];

const PUBLIC_FILE_SOURCES: [&str; 39] = [
    "file:/proc/sys/net/netfilter/nf_conntrack_acct",
    "file:/proc/net/nf_flowtable",
    "file:/sys/kernel/debug/netfilter/nf_flowtable",
    "file:/sys/class/net/ifb0",
    "file:/proc/net/vlan/config",
    "file:/usr/share/lanspeed/bpf/collector-model.json",
    "file:/usr/lib/bpf/lanspeed-ebpf-kfunc",
    "file:/usr/lib/bpf/lanspeed-ebpf-fallback",
    "file:/etc/config/openclash",
    "file:/etc/config/dae",
    "file:/etc/config/daed",
    "file:/etc/config/homeproxy",
    "file:/etc/config/nlbwmon",
    "file:/sys/class/ieee80211",
    "file:/sys/module/qca_nss_drv",
    "file:/sys/bus/platform/drivers/qca-nss",
    "file:/sys/kernel/debug/qca-nss-drv",
    "file:/proc/sys/dev/nss",
    "file:/sys/module/ecm",
    "file:/sys/kernel/debug/ecm",
    "file:/sys/module/qca_nss_ppe",
    "file:/sys/module/ppe_drv",
    "file:/sys/kernel/debug/qca-nss-ppe",
    "file:/sys/kernel/debug/ppe_drv",
    "file:/sys/module/qca_nss_bridge_mgr",
    "file:/sys/class/net/nssifb",
    "file:/sys/module/nss_ifb",
    "file:/sys/module/nss-ifb",
    "file:/sys/module/qca_nss_nsm",
    "file:/sys/module/nss_nsm",
    "file:/sys/kernel/debug/qca-nss-nsm",
    "file:/sys/module/qca_nss_dp",
    "file:/sys/module/nss_dp",
    "file:/sys/module/qca_mcs",
    "file:/sys/module/mc_snooping",
    "file:/sys/kernel/debug/ecm/ecm_db/connection_count",
    "file:/sys/kernel/debug/ecm/ecm_db/connection_count_simple",
    "file:/sys/kernel/debug/ecm/ecm_db/host_count",
    "file:/sys/kernel/debug/ecm/ecm_db/mapping_count",
];

const PUBLIC_UCI_SOURCES: [&str; 9] = [
    "uci:firewall",
    "uci:sqm",
    "uci:qosify",
    "uci:openclash",
    "uci:dae",
    "uci:daed",
    "uci:homeproxy",
    "uci:nlbwmon",
    "uci:dhcp",
];

const PUBLIC_UBUS_SOURCES: [&str; 3] = [
    "ubus:network.interface.lan",
    "ubus:service.dae",
    "ubus:service.daed",
];

pub(crate) fn bpf_details(
    config: &RuntimeConfig,
    report: &ProbeReport,
    runtime: &RuntimeHealth,
    error_stage: Option<&'static str>,
) -> Value {
    let collect_target_count = config.runtime_collect_ifnames().len();
    let intended_hook_count = collect_target_count.saturating_mul(2);
    let expected_hook_count = runtime.bpf_expected_hook_count.max(intended_hook_count);
    let attached_hook_count = runtime.bpf_attached_hook_count.min(expected_hook_count);
    let retained_fresh_snapshot = !runtime.bpf_map_read_ok
        && runtime
            .bpf_last_complete_snapshot_ms
            .is_some_and(|sample_ms| {
                crate::is_fresh(runtime.now_ms, sample_ms, runtime.bpf_freshness_ms)
            });
    let bpf_supported =
        report.capabilities.tc && report.capabilities.tc_clsact && report.facts.tc.bpf;
    let attach_state =
        if !config.enable_bpf || collect_target_count == 0 || !runtime.bpf_object_loaded {
            "not_attempted"
        } else if runtime.bpf_attached
            && expected_hook_count > 0
            && attached_hook_count == expected_hook_count
        {
            "ready"
        } else if attached_hook_count > 0 {
            "partial"
        } else {
            "failed"
        };
    let map_state = if attach_state != "ready" {
        "not_attempted"
    } else if runtime.bpf_map_read_ok {
        "ready"
    } else if retained_fresh_snapshot {
        "retained"
    } else if runtime.bpf_map_read_attempted {
        "failed"
    } else {
        "not_attempted"
    };
    let reason_code = if !config.enable_bpf {
        "disabled"
    } else if collect_target_count == 0 {
        "no_collect_interface"
    } else if !report.capabilities.bpf_package {
        "package_missing"
    } else if !report.capabilities.bpf_object {
        "object_missing"
    } else if !report.capabilities.tc {
        "tc_unavailable"
    } else if !bpf_supported {
        "tc_unsupported"
    } else if report.facts.tc.conflict {
        "tc_conflict"
    } else if let Some(stage) = error_stage {
        stage
    } else if !runtime.bpf_object_loaded {
        "object_load_failed"
    } else if attach_state == "partial" || attach_state == "failed" {
        "tc_attach_failed"
    } else if map_state == "failed" || map_state == "retained" {
        "map_read_failed"
    } else if attach_state == "ready" && map_state == "ready" {
        "ready"
    } else {
        "runtime_not_ready"
    };
    json!({
        "enabled": config.enable_bpf,
        "collect_target_count": collect_target_count,
        "expected_hook_count": expected_hook_count,
        "attached_hook_count": attached_hook_count,
        "object_loaded": runtime.bpf_object_loaded,
        "attach_state": attach_state,
        "map_state": map_state,
        "last_complete_snapshot_ms": runtime.bpf_last_complete_snapshot_ms,
        "retained_fresh_snapshot": retained_fresh_snapshot,
        "reason_code": reason_code,
    })
}

pub(crate) fn probe_failure_details(failures: &[ProbeFailure]) -> Value {
    let mut seen = HashSet::new();
    let normalized = failures
        .iter()
        .map(|failure| PublicProbeFailure {
            kind: public_failure_kind(failure.kind),
            source: safe_probe_source(public_failure_kind(failure.kind), &failure.source),
            reason: public_failure_reason(failure.reason),
            exit_code: failure.exit_code,
        })
        .filter(|failure| seen.insert(failure.clone()))
        .collect::<Vec<_>>();
    let mut selected = Vec::new();
    for kind in PROBE_FAILURE_KINDS {
        if let Some(failure) = normalized.iter().find(|failure| failure.kind == kind) {
            selected.push(failure);
        }
    }
    for failure in &normalized {
        if selected.len() >= PROBE_FAILURE_LIMIT {
            break;
        }
        if !selected.iter().any(|selected| *selected == failure) {
            selected.push(failure);
        }
    }
    let items = selected
        .iter()
        .take(PROBE_FAILURE_LIMIT)
        .map(|failure| {
            let mut item = Map::new();
            item.insert("kind".into(), json!(failure.kind));
            item.insert("source".into(), json!(failure.source));
            item.insert("reason".into(), json!(failure.reason));
            if let Some(exit_code) = failure.exit_code {
                item.insert("exit_code".into(), json!(exit_code));
            }
            Value::Object(item)
        })
        .collect::<Vec<_>>();
    json!({
        "items": items,
        "total": normalized.len(),
        "truncated": normalized.len() > PROBE_FAILURE_LIMIT,
    })
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PublicProbeFailure {
    kind: &'static str,
    source: String,
    reason: &'static str,
    exit_code: Option<i32>,
}

fn public_failure_kind(kind: &str) -> &'static str {
    match kind {
        "command" => "command",
        "file" => "file",
        "uci" => "uci",
        "ubus" => "ubus",
        "nss" => "nss",
        _ => "probe",
    }
}

fn public_failure_reason(reason: &str) -> &'static str {
    match reason {
        "availability_failed" => "availability_failed",
        "execution_failed" => "execution_failed",
        "nonzero_exit" => "nonzero_exit",
        "timeout" => "timeout",
        "output_truncated" => "output_truncated",
        "read_failed" => "read_failed",
        "load_failed" => "load_failed",
        "query_failed" => "query_failed",
        "state_probe_failed" => "state_probe_failed",
        "state_unreadable" => "state_unreadable",
        _ => "failed",
    }
}

fn safe_probe_source(kind: &str, source: &str) -> String {
    let safe = match kind {
        "command" => safe_command_source(source),
        "file" => safe_file_source(source),
        "uci" => PUBLIC_UCI_SOURCES
            .contains(&source)
            .then(|| source.to_owned()),
        "ubus" => PUBLIC_UBUS_SOURCES
            .contains(&source)
            .then(|| source.to_owned()),
        "nss" => (source == "nss:ecm_state").then(|| source.to_owned()),
        _ => None,
    };
    safe.unwrap_or_else(|| format!("{kind}:unknown"))
        .chars()
        .take(PROBE_SOURCE_LIMIT)
        .collect()
}

fn safe_command_source(source: &str) -> Option<String> {
    if PUBLIC_COMMAND_SOURCES.contains(&source) {
        return Some(source.to_owned());
    }
    let key = source.strip_prefix("command:")?;
    if key == "tc_filter_show" {
        return Some("command:tc_filter_show".into());
    }
    if key == "tc_qdisc_show" {
        return Some("command:tc_qdisc_show".into());
    }
    if let Some(interface) = key
        .strip_prefix("tc_filter_show_")
        .and_then(|value| value.strip_suffix("_ingress"))
    {
        if safe_source_component(interface) {
            return Some("command:tc_filter_show_<if>_ingress".into());
        }
    }
    if let Some(interface) = key
        .strip_prefix("tc_filter_show_")
        .and_then(|value| value.strip_suffix("_egress"))
    {
        if safe_source_component(interface) {
            return Some("command:tc_filter_show_<if>_egress".into());
        }
    }
    if let Some(interface) = key.strip_prefix("tc_qdisc_show_") {
        if safe_source_component(interface) {
            return Some("command:tc_qdisc_show_<if>".into());
        }
    }
    None
}

fn safe_source_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn safe_file_source(source: &str) -> Option<String> {
    if PUBLIC_FILE_SOURCES.contains(&source) {
        return Some(source.to_owned());
    }
    if source.starts_with("file:/sys/class/net/") && source.ends_with("/bridge") {
        return Some("file:/sys/class/net/<if>/bridge".into());
    }
    None
}

pub(crate) fn nss_details(
    config: &RuntimeConfig,
    report: &ProbeReport,
    decision: &PolicyDecision,
) -> Value {
    let direct_enabled =
        decision.rate == RateCollector::NssEcmDirect || decision.nss_direct_overlay;
    let direct_supported = report.evidence.nss.present
        && report.evidence.nss.ecm_active
        && report.evidence.nss.direct_state_readable;
    let fallback_reason = if decision.rate == RateCollector::NssConntrackSync {
        "nss_conntrack_sync_primary"
    } else {
        nss::direct_fallback_reason(nss::DirectFallbackInput {
            state_readable: direct_supported,
            overlay_enabled: direct_enabled,
            rate_mode: config.rate_collector_mode,
            dae_runtime_prefers_bpf: decision.evidence.rate_reason == "dae_runtime_prefers_bpf",
        })
    };
    let offload_active = report.evidence.nss.ecm_active || report.evidence.nss.ppe_active;
    let mut value = json!({
        "present": report.evidence.nss.present,
        "ecm_active": report.evidence.nss.ecm_active,
        "ecm_offload_active": report.evidence.nss.ecm_active,
        "ppe_active": report.evidence.nss.ppe_active,
        "ppe_offload_active": report.evidence.nss.ppe_active,
        "direct_state_present": report.evidence.nss.direct_state_present,
        "direct_state_readable": report.evidence.nss.direct_state_readable,
        "direct_supported": direct_supported,
        "direct_enabled": direct_enabled,
        "direct_source": nss::NSS_DIRECT_SOURCE,
        "fallback_reason": fallback_reason,
        "direct_state_errno": report.evidence.nss.direct_state_errno,
        "direct_state_major": report.evidence.nss.direct_state_major,
        "direct_source_path": report.evidence.nss.direct_source_path.as_deref().unwrap_or_default(),
        "bridge_mgr": report.evidence.nss.bridge_mgr,
        "ifb_active": report.evidence.nss.ifb_active,
        "nsm_active": report.evidence.nss.nsm_active,
        "dp_active": report.evidence.nss.dp_active,
        "mcs_active": report.evidence.nss.mcs_active,
        "subsystems": report.evidence.nss.subsystems,
        "counter_source": counter_source(decision, report),
        "counter_cadence_seconds": if offload_active { 2 } else { 0 },
        "counter_merge_policy": if decision.rate == RateCollector::NssConntrackSync {
            "conntrack_sync_authoritative_no_bpf_addition"
        } else {
            "single_source"
        },
        "counter_delta_scope": if decision.rate == RateCollector::NssConntrackSync {
            "per_conntrack_flow_before_client_aggregation"
        } else {
            "single_source_client_snapshot"
        },
        "bpf_visibility": if offload_active {
            "slow_path_only_until_deceleration"
        } else {
            "full_when_nss_not_offloading"
        },
        "interface_counters_accurate": true,
        "nssifb_policy": if report.evidence.nss.ifb_active {
            "mirror_of_physical_ingress_not_a_real_client_source"
        } else {
            "not_present"
        },
    });
    let object = value.as_object_mut().expect("NSS evidence object");
    for (name, count) in [
        (
            "accelerated_connections",
            report.evidence.nss.accelerated_connections,
        ),
        ("accelerated_tcp", report.evidence.nss.accelerated_tcp),
        ("accelerated_udp", report.evidence.nss.accelerated_udp),
        ("accelerated_other", report.evidence.nss.accelerated_other),
        ("host_count", report.evidence.nss.host_count),
        ("mapping_count", report.evidence.nss.mapping_count),
    ] {
        if let Some(count) = count {
            object.insert(name.into(), json!(count));
        }
    }
    value
}

fn counter_source(decision: &PolicyDecision, report: &ProbeReport) -> &'static str {
    if decision.rate == RateCollector::NssConntrackSync || decision.nss_sync_secondary {
        "ecm_conntrack_sync"
    } else if decision.rate == RateCollector::NssEcmDirect || decision.nss_direct_overlay {
        "ecm_state_direct"
    } else if report.evidence.nss.ppe_active {
        "ppe_conntrack_sync"
    } else if report.evidence.nss.ecm_active {
        "ecm_conntrack_sync"
    } else {
        "netdev_counters_only"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured_bpf() -> RuntimeConfig {
        let mut config = RuntimeConfig::default();
        config.enable_bpf = true;
        config.interface_include.push("eth1".into());
        config
    }

    fn bpf_report(config: &RuntimeConfig, runtime: &RuntimeHealth) -> ProbeReport {
        let mut observations = crate::probe::ProbeObservations::default();
        observations.commands.tc = true;
        observations.tc.clsact = true;
        observations.tc.bpf = true;
        observations.files.lan_bridge = true;
        observations.bpf.package = true;
        observations.bpf.object = true;
        crate::probe::assess(config, observations, runtime)
    }

    #[test]
    fn bpf_details_distinguishes_no_target_attach_and_map_failures_without_raw_errors() {
        let mut no_target = RuntimeConfig::default();
        no_target.enable_bpf = true;
        let runtime = RuntimeHealth::default();
        let report = bpf_report(&no_target, &runtime);
        let evidence = bpf_details(&no_target, &report, &runtime, None);
        assert_eq!(evidence["reason_code"], "no_collect_interface");
        assert_eq!(evidence["attach_state"], "not_attempted");
        assert_eq!(evidence["map_state"], "not_attempted");
        assert_eq!(evidence["expected_hook_count"], 0);

        let config = configured_bpf();
        let mut runtime = RuntimeHealth {
            bpf_object_loaded: true,
            bpf_expected_hook_count: 2,
            ..RuntimeHealth::default()
        };
        let report = bpf_report(&config, &runtime);
        let evidence = bpf_details(&config, &report, &runtime, Some("tc_attach_failed"));
        assert_eq!(evidence["reason_code"], "tc_attach_failed");
        assert_eq!(evidence["attach_state"], "failed");
        assert_eq!(evidence["map_state"], "not_attempted");

        runtime.bpf_attached = true;
        runtime.bpf_attached_hook_count = 2;
        runtime.bpf_map_read_attempted = true;
        runtime.runtime_error = Some("map /private/path token=secret".into());
        let report = bpf_report(&config, &runtime);
        let evidence = bpf_details(&config, &report, &runtime, Some("map_read_failed"));
        assert_eq!(evidence["reason_code"], "map_read_failed");
        assert_eq!(evidence["attach_state"], "ready");
        assert_eq!(evidence["map_state"], "failed");
        let serialized = evidence.to_string();
        assert!(!serialized.contains("/private/path"));
        assert!(!serialized.contains("token=secret"));
        assert!(!serialized.contains("runtime_error"));
    }

    #[test]
    fn bpf_details_retains_only_fresh_snapshots_and_recovers() {
        let config = configured_bpf();
        let mut runtime = RuntimeHealth {
            bpf_object_loaded: true,
            bpf_attached: true,
            bpf_expected_hook_count: 2,
            bpf_attached_hook_count: 2,
            bpf_map_read_attempted: true,
            bpf_map_read_ok: false,
            bpf_last_complete_snapshot_ms: Some(9_000),
            bpf_freshness_ms: 2_000,
            now_ms: 10_000,
            ..RuntimeHealth::default()
        };
        let report = bpf_report(&config, &runtime);
        let retained = bpf_details(&config, &report, &runtime, Some("map_read_failed"));
        assert_eq!(retained["map_state"], "retained");
        assert_eq!(retained["retained_fresh_snapshot"], true);
        assert_eq!(retained["reason_code"], "map_read_failed");

        runtime.now_ms = 11_001;
        let report = bpf_report(&config, &runtime);
        let expired = bpf_details(&config, &report, &runtime, Some("map_read_failed"));
        assert_eq!(expired["map_state"], "failed");
        assert_eq!(expired["retained_fresh_snapshot"], false);

        runtime.bpf_map_read_ok = true;
        runtime.bpf_last_complete_snapshot_ms = Some(runtime.now_ms);
        let report = bpf_report(&config, &runtime);
        let recovered = bpf_details(&config, &report, &runtime, None);
        assert_eq!(recovered["attach_state"], "ready");
        assert_eq!(recovered["map_state"], "ready");
        assert_eq!(recovered["reason_code"], "ready");
        assert_eq!(recovered["retained_fresh_snapshot"], false);
    }

    #[test]
    fn probe_failure_details_are_whitelisted_sanitized_and_bounded() {
        let mut failures = (0..35)
            .map(|index| ProbeFailure {
                kind: if index == 0 { "private-kind" } else { "file" },
                source: if index == 0 {
                    format!("file:/sys/class/net/{}\n", "x".repeat(200))
                } else {
                    format!("file:/safe/{index}")
                },
                reason: if index == 0 {
                    "raw secret error"
                } else {
                    "read_failed"
                },
                exit_code: (index > 1).then_some(index),
            })
            .collect::<Vec<_>>();
        failures[1] = ProbeFailure {
            kind: "command",
            source: "command:nft_list_flowtables".into(),
            reason: "nonzero_exit",
            exit_code: Some(2),
        };

        let details = probe_failure_details(&failures);
        let items = details["items"].as_array().unwrap();

        assert_eq!(
            details
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["items", "total", "truncated"]
        );
        assert_eq!(details["total"], 35);
        assert_eq!(details["truncated"], true);
        assert_eq!(items.len(), PROBE_FAILURE_LIMIT);
        assert_eq!(items[0]["kind"], "probe");
        assert_eq!(items[0]["reason"], "failed");
        assert_eq!(items[0]["source"], "probe:unknown");
        assert!(items[0].get("exit_code").is_none());
        assert!(items[0]["source"].as_str().unwrap().len() <= PROBE_SOURCE_LIMIT);
        assert!(!items[0]["source"].as_str().unwrap().contains('\n'));
        assert_eq!(items[1]["exit_code"], 2);
        let rendered = serde_json::to_string(&details).unwrap();
        assert!(!rendered.contains("private-kind"));
        assert!(!rendered.contains("raw secret error"));
        assert!(!rendered.contains("error\""));
        assert!(!rendered.contains("value\""));
        assert!(!rendered.contains("stdout\""));
    }

    #[test]
    fn normalized_probe_failures_do_not_starve_later_categories() {
        let mut failures = (0..40)
            .map(|index| ProbeFailure {
                kind: "command",
                source: if index % 2 == 0 {
                    format!("command:tc_filter_show_lan{index}_ingress")
                } else {
                    format!("command:tc_filter_show_lan{index}_egress")
                },
                reason: "timeout",
                exit_code: None,
            })
            .collect::<Vec<_>>();
        failures.extend([
            ProbeFailure {
                kind: "file",
                source: "file:/proc/net/nf_flowtable".into(),
                reason: "read_failed",
                exit_code: None,
            },
            ProbeFailure {
                kind: "uci",
                source: "uci:firewall".into(),
                reason: "load_failed",
                exit_code: None,
            },
            ProbeFailure {
                kind: "ubus",
                source: "ubus:network.interface.lan".into(),
                reason: "query_failed",
                exit_code: None,
            },
            ProbeFailure {
                kind: "nss",
                source: "nss:ecm_state".into(),
                reason: "state_probe_failed",
                exit_code: None,
            },
        ]);

        let details = probe_failure_details(&failures);
        let items = details["items"].as_array().unwrap();
        assert_eq!(details["total"], 6);
        assert_eq!(details["truncated"], false);
        for kind in ["command", "file", "uci", "ubus", "nss"] {
            assert!(items.iter().any(|item| item["kind"] == kind));
        }
        assert_eq!(
            items
                .iter()
                .filter(|item| item["kind"] == "command")
                .count(),
            2
        );
    }

    #[test]
    fn probe_failure_sources_and_reasons_use_only_public_contract_values() {
        let failures = vec![
            ProbeFailure {
                kind: "command",
                source: "command:tc_filter_show_br_lan_ingress".into(),
                reason: "timeout",
                exit_code: Some(143),
            },
            ProbeFailure {
                kind: "file",
                source: "file:/sys/class/net/br-lan/bridge".into(),
                reason: "state_unreadable",
                exit_code: None,
            },
            ProbeFailure {
                kind: "uci",
                source: "uci:firewall".into(),
                reason: "load_failed",
                exit_code: None,
            },
            ProbeFailure {
                kind: "ubus",
                source: "ubus:network.interface.lan".into(),
                reason: "output_truncated",
                exit_code: Some(1),
            },
            ProbeFailure {
                kind: "nss",
                source: "nss:ecm_state".into(),
                reason: "state_probe_failed",
                exit_code: None,
            },
            ProbeFailure {
                kind: "command",
                source: "command:tc_filter_show_br-lan;secret_ingress".into(),
                reason: "raw private error",
                exit_code: None,
            },
        ];
        let details = probe_failure_details(&failures);
        let items = details["items"].as_array().unwrap();

        assert_eq!(items[0]["source"], "command:tc_filter_show_<if>_ingress");
        assert_eq!(items[1]["source"], "file:/sys/class/net/<if>/bridge");
        assert_eq!(items[2]["source"], "uci:firewall");
        assert_eq!(items[3]["source"], "ubus:network.interface.lan");
        assert_eq!(items[4]["source"], "nss:ecm_state");
        assert_eq!(items[5]["source"], "command:unknown");
        assert_eq!(items[5]["reason"], "failed");
        let rendered = serde_json::to_string(&details).unwrap();
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("raw private error"));
        assert!(!rendered.contains("br-lan"));
    }

    fn rendered_nss_evidence(
        config: &RuntimeConfig,
        observations: crate::probe::ProbeObservations,
    ) -> Value {
        let runtime = crate::probe::RuntimeHealth::default();
        let report = crate::probe::assess(config, observations, &runtime);
        let decision = crate::policy::select_collectors(config, &report.facts, &runtime);
        nss_details(config, &report, &decision)
    }

    #[test]
    fn production_nss_evidence_keeps_the_complete_legacy_c_contract_and_values() {
        let mut config = RuntimeConfig::default();
        config.enable_conntrack_fallback = true;
        let mut observations = crate::probe::ProbeObservations::default();
        observations.files.nf_conntrack_acct_present = true;
        observations.files.nf_conntrack_acct_value = Some("1".into());
        observations.nss.present = true;
        observations.nss.ecm_active = true;
        observations.nss.ppe_active = true;
        observations.nss.direct_state_present = true;
        observations.nss.direct_state_readable = true;
        observations.nss.bridge_mgr = true;
        observations.nss.ifb_active = true;
        observations.nss.nsm_active = true;
        observations.nss.dp_active = true;
        observations.nss.mcs_active = true;
        observations.nss.direct_state_errno = 13;
        observations.nss.direct_state_major = 241;
        observations.nss.direct_source_path = Some("/dev/ecm_state".into());
        observations.nss.accelerated_connections = Some(99);
        observations.nss.accelerated_tcp = Some(12);
        observations.nss.accelerated_udp = Some(34);
        observations.nss.accelerated_other = Some(5);
        observations.nss.host_count = Some(7);
        observations.nss.mapping_count = Some(8);

        let nss = rendered_nss_evidence(&config, observations);

        assert_eq!(
            nss,
            json!({
                "present": true,
                "ecm_active": true,
                "ecm_offload_active": true,
                "ppe_active": true,
                "ppe_offload_active": true,
                "direct_state_present": true,
                "direct_state_readable": true,
                "direct_supported": true,
                "direct_enabled": false,
                "direct_source": "nss_ecm_direct",
                "fallback_reason": "nss_conntrack_sync_primary",
                "direct_state_errno": 13,
                "direct_state_major": 241,
                "direct_source_path": "/dev/ecm_state",
                "bridge_mgr": true,
                "ifb_active": true,
                "nsm_active": true,
                "dp_active": true,
                "mcs_active": true,
                "subsystems": ["drv", "dp", "ecm", "ppe", "nsm", "bridge_mgr", "ifb", "mcs"],
                "accelerated_connections": 99,
                "accelerated_tcp": 12,
                "accelerated_udp": 34,
                "accelerated_other": 5,
                "host_count": 7,
                "mapping_count": 8,
                "counter_source": "ecm_conntrack_sync",
                "counter_cadence_seconds": 2,
                "counter_merge_policy": "conntrack_sync_authoritative_no_bpf_addition",
                "counter_delta_scope": "per_conntrack_flow_before_client_aggregation",
                "bpf_visibility": "slow_path_only_until_deceleration",
                "interface_counters_accurate": true,
                "nssifb_policy": "mirror_of_physical_ingress_not_a_real_client_source",
            })
        );
    }

    #[test]
    fn readable_direct_state_without_nss_and_ecm_is_not_legacy_supported() {
        let mut observations = crate::probe::ProbeObservations::default();
        observations.nss.direct_state_present = true;
        observations.nss.direct_state_readable = true;

        let nss = rendered_nss_evidence(&RuntimeConfig::default(), observations);

        assert_eq!(nss["direct_state_readable"], true);
        assert_eq!(nss["direct_supported"], false);
        assert_eq!(nss["direct_enabled"], false);
        assert_eq!(nss["fallback_reason"], "state_unavailable_or_unreadable");
    }

    #[test]
    fn production_nss_evidence_omits_unknown_counts_but_keeps_other_compatibility_fields() {
        let nss = rendered_nss_evidence(
            &RuntimeConfig::default(),
            crate::probe::ProbeObservations::default(),
        );

        for key in [
            "accelerated_connections",
            "accelerated_tcp",
            "accelerated_udp",
            "accelerated_other",
            "host_count",
            "mapping_count",
        ] {
            assert!(nss.get(key).is_none(), "{key} must be omitted");
        }
        assert_eq!(nss["direct_source_path"], "");
        assert_eq!(nss["direct_source"], "nss_ecm_direct");
        assert_eq!(nss["counter_source"], "netdev_counters_only");
        assert_eq!(nss["counter_cadence_seconds"], 0);
        assert_eq!(nss["bpf_visibility"], "full_when_nss_not_offloading");
        assert_eq!(nss["interface_counters_accurate"], true);
        assert_eq!(nss["nssifb_policy"], "not_present");
    }

    #[test]
    fn production_nss_counter_source_follows_decision_priority() {
        let mut forced_direct_with_sync = RuntimeConfig::default();
        forced_direct_with_sync.enable_conntrack_fallback = true;
        forced_direct_with_sync.rate_collector_mode =
            crate::config::RateCollectorMode::NssEcmDirect;
        let mut sync = crate::probe::ProbeObservations::default();
        sync.files.nf_conntrack_acct_present = true;
        sync.files.nf_conntrack_acct_value = Some("1".into());
        sync.nss.present = true;
        sync.nss.ecm_active = true;
        sync.nss.direct_state_readable = true;

        let mut direct = crate::probe::ProbeObservations::default();
        direct.nss.present = true;
        direct.nss.ecm_active = true;
        direct.nss.direct_state_readable = true;

        let mut ppe = crate::probe::ProbeObservations::default();
        ppe.nss.ppe_active = true;

        let mut ecm = crate::probe::ProbeObservations::default();
        ecm.nss.ecm_active = true;

        for (config, observations, expected) in [
            (&forced_direct_with_sync, sync, "ecm_conntrack_sync"),
            (&RuntimeConfig::default(), direct, "ecm_state_direct"),
            (&RuntimeConfig::default(), ppe, "ppe_conntrack_sync"),
            (&RuntimeConfig::default(), ecm, "ecm_conntrack_sync"),
            (
                &RuntimeConfig::default(),
                crate::probe::ProbeObservations::default(),
                "netdev_counters_only",
            ),
        ] {
            let nss = rendered_nss_evidence(config, observations);
            assert_eq!(nss["counter_source"], expected);
        }
    }
}
