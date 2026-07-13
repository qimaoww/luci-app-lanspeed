use serde_json::{json, Value};

use crate::{
    collectors::nss,
    config::RuntimeConfig,
    policy::{PolicyDecision, RateCollector},
    probe::ProbeReport,
};

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
    let fallback_reason = nss::direct_fallback_reason(nss::DirectFallbackInput {
        state_readable: direct_supported,
        overlay_enabled: direct_enabled,
        rate_mode: config.rate_collector_mode,
        dae_runtime_prefers_bpf: decision.evidence.rate_reason == "dae_runtime_prefers_bpf",
    });
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
                "direct_enabled": true,
                "direct_source": "nss_ecm_direct",
                "fallback_reason": "",
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
