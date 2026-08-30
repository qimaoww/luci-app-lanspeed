use super::*;

pub(super) fn evidence(report: &ProbeReport, method: &str) -> Evidence {
    let mut details = BTreeMap::new();
    details.insert("source".into(), json!(report.evidence.source));
    details.insert("method".into(), json!(method));
    details.insert("read_only".into(), json!(true));
    details.insert("probe_error".into(), json!(report.evidence.probe_error));
    details.insert(
        "lan_probe_error".into(),
        json!(report.evidence.lan_probe_error),
    );
    details.insert(
        "probe_failures".into(),
        crate::production_evidence::probe_failure_details(&report.evidence.probe_failures),
    );
    details.insert(
        "effective_collector".into(),
        json!(report.evidence.collector.effective_rate_collector),
    );
    details.insert(
        "platform".into(),
        json!({
            "target_arch": std::env::consts::ARCH,
            "profile": if crate::platform::profile::COMPILED_PROFILE.uses_nss() {
                "nss_aarch64"
            } else {
                "x86_tc_bpf"
            },
            "nss_compiled": cfg!(feature = "nss-platform"),
            "access_edge_compiled": cfg!(feature = "nss-platform"),
            "nss_modes_exposed": crate::platform::profile::COMPILED_PROFILE.uses_nss()
                && report.facts.nss.present,
        }),
    );
    details.insert("collector".into(), json!({"rate_reason":report.evidence.collector.rate_reason,"connection_reason":report.evidence.collector.connection_reason,
        "primary_source":report.evidence.collector.effective_rate_collector,"mode":report.evidence.collector.mode,"confidence":report.evidence.collector.confidence}));
    details.insert(
        "dae".into(),
        json!({
            "running": report.evidence.proxy.dae.dae_running
                || report.evidence.proxy.dae.daed_running,
            "process": report.evidence.proxy.dae.dae_process
                || report.evidence.proxy.dae.daed_process,
            "runtime_active": report.evidence.proxy.dae.runtime_active,
            "process_probe_error": report.evidence.proxy.dae.process_probe_error,
            "dae_running": report.evidence.proxy.dae.dae_running,
            "daed_running": report.evidence.proxy.dae.daed_running,
            "dae_process": report.evidence.proxy.dae.dae_process,
            "daed_process": report.evidence.proxy.dae.daed_process,
        }),
    );
    Evidence { details }
}

pub(super) fn runtime_evidence(
    report: &ProbeReport,
    method: &str,
    config: &RuntimeConfig,
    runtime: &RuntimeHealth,
    bpf_error_stage: Option<&'static str>,
) -> Evidence {
    let mut public = evidence(report, method);
    if method == "health" {
        public.details.insert(
            "tc_status".into(),
            serde_json::to_value(&report.facts.tc.host_status).unwrap_or_else(|_| {
                json!({
                    "state": "unavailable",
                    "scan_complete": false,
                    "qdisc_scan": false,
                    "class_scan": false,
                    "filter_scan": false,
                    "command_output_truncated": false,
                    "objects_truncated": false,
                    "parse_errors": 1,
                    "interface_count": 0,
                    "qdisc_count": 0,
                    "class_count": 0,
                    "filter_count": 0,
                    "lanspeed_objects": 0,
                    "foreign_objects": 0,
                    "qdiscs": [],
                    "classes": [],
                    "filters": [],
                    "conflicts": [],
                })
            }),
        );
    }
    public.details.insert(
        "bpf".into(),
        crate::production_evidence::bpf_details(config, report, runtime, bpf_error_stage),
    );
    public
}

pub(super) fn conntrack_generation_evidence(snapshot: &CollectedSnapshot) -> Value {
    let parsed_entries = snapshot
        .stats
        .entries_seen
        .saturating_sub(snapshot.stats.malformed_lines);
    let flow_id_coverage_pct = (parsed_entries > 0)
        .then(|| snapshot.stats.conntrack_ids_present as f64 * 100.0 / parsed_entries as f64);
    json!({
        "counter_generation_key": if snapshot.stats.netlink_read {
            "ctnetlink_cta_id_with_zone_tuple_fallback"
        } else {
            "procfs_zone_tuple_fallback"
        },
        "parsed_entries": parsed_entries,
        "conntrack_ids_present": snapshot.stats.conntrack_ids_present,
        "conntrack_zones_present": snapshot.stats.conntrack_zones_present,
        "flow_id_coverage_pct": flow_id_coverage_pct,
    })
}

pub(super) fn apply_decision_evidence(
    evidence: &mut Evidence,
    decision: &policy::PolicyDecision,
    config: &RuntimeConfig,
    _report: &ProbeReport,
) {
    let effective = decision.rate.as_str();
    evidence
        .details
        .insert("effective_collector".into(), json!(effective));
    let effective_interval_ms = effective_collection_interval_ms(
        config.access_edge_mode,
        config.internet_view_mode,
        Some(decision.rate),
        config.refresh_interval_ms,
    );
    if let Some(collector) = evidence
        .details
        .get_mut("collector")
        .and_then(Value::as_object_mut)
    {
        collector.insert("primary_source".into(), json!(effective));
        collector.insert(
            "effective_connection_collector".into(),
            json!(decision.connection.as_str()),
        );
        collector.insert("rate_reason".into(), json!(decision.evidence.rate_reason));
        collector.insert(
            "connection_reason".into(),
            json!(decision.evidence.connection_reason),
        );
        collector.insert("mode".into(), json!(decision.mode.as_str()));
        collector.insert("confidence".into(), json!(decision.confidence.as_str()));
        collector.insert("warnings".into(), json!(decision.warnings));
        collector.insert("effective_interval_ms".into(), json!(effective_interval_ms));
    }
    #[cfg(feature = "nss-platform")]
    evidence.details.insert(
        "nss".into(),
        crate::production_evidence::nss_details(config, _report, decision),
    );
}

pub(super) fn capabilities(value: &ProbeCapabilities, report: &ProbeReport) -> Capabilities {
    Capabilities {
        // `bpf_supported` is a platform/configuration capability. Keep it
        // independent from the compatibility `bpf` capability field.
        bpf_supported: value.tc && value.tc_clsact && report.facts.tc.bpf,
        bpf: value.bpf,
        bpf_package: value.bpf_package,
        bpf_object: value.bpf_object,
        bpf_runtime_metrics: value.bpf_runtime_metrics,
        conntrack_fallback: value.conntrack_fallback,
        live_metrics: value.live_metrics,
        fw4: value.fw4,
        nft: value.nft,
        software_flow_offload: value.software_flow_offload,
        hardware_flow_offload: value.hardware_flow_offload,
        nss: report.facts.nss.present,
        nss_ecm_offload: report.facts.nss.ecm_active,
        nss_ppe_offload: report.facts.nss.ppe_active,
        nss_ecm_node: report.facts.nss.direct_state_readable,
        nss_ecm_bpf: value.nss_ecm_bpf,
        nss_bridge_mgr: report.evidence.nss.bridge_mgr,
        nss_ifb: report.evidence.nss.ifb_active,
        nss_nsm: report.evidence.nss.nsm_active,
        nss_dp: report.evidence.nss.dp_active,
        nss_mcs: report.evidence.nss.mcs_active,
        fullcone: value.fullcone,
        nf_conntrack_acct: value.nf_conntrack_acct,
        flowtable_counter: value.flowtable_counter,
        tc: value.tc,
        tc_clsact: value.tc_clsact,
        existing_tc_filters: value.existing_tc_filters,
        ifb: value.ifb,
        sqm: value.sqm,
        qosify: value.qosify,
        openclash: value.openclash,
        openclash_fake_ip: value.openclash_fake_ip,
        openclash_tun_mix: value.openclash_tun_mix,
        openclash_redirect_dns: value.openclash_redirect_dns,
        openclash_dns_chain_complete: value.openclash_dns_chain_complete,
        openclash_router_self_proxy: value.openclash_router_self_proxy,
        openclash_udp_proxy: value.openclash_udp_proxy,
        openclash_ipv6: value.openclash_ipv6,
        dae: value.dae,
        homeproxy: value.homeproxy,
        lan_bridge: value.lan_bridge,
        vlan: value.vlan,
        wlan: value.wlan,
        lan_edge: value.lan_edge,
        safe_attach: value.safe_attach,
        map_full: value.map_full,
    }
}

pub(super) fn mode(value: ProbeMode) -> Mode {
    match value {
        ProbeMode::Full => Mode::Full,
        ProbeMode::Degraded => Mode::Degraded,
        ProbeMode::Unsupported => Mode::Unsupported,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn conntrack_mode(value: ConnectionCollectorMode) -> ConntrackMode {
    match value {
        ConnectionCollectorMode::Auto => ConntrackMode::Auto,
        ConnectionCollectorMode::ConntrackNetlink => ConntrackMode::Netlink,
        ConnectionCollectorMode::ConntrackProcfs => ConntrackMode::Procfs,
    }
}
