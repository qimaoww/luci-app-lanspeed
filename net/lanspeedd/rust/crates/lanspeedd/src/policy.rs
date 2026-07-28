use crate::{
    config::{ConnectionCollectorMode, RateCollectorMode, RuntimeConfig},
    probe::{push_unique, Confidence, Mode, ProbeFacts, RuntimeHealth},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateCollector {
    Bpf,
    NssEcmNode,
    NssEcmBpf,
    Unsupported,
}
impl RateCollector {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bpf => "bpf",
            Self::NssEcmNode => "nss_ecm_node",
            Self::NssEcmBpf => "nss_ecm_bpf",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionCollector {
    Netlink,
    Procfs,
    Unsupported,
}
impl ConnectionCollector {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Netlink => "conntrack_netlink",
            Self::Procfs => "conntrack_procfs",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyEvidence {
    pub rate_reason: &'static str,
    pub connection_reason: &'static str,
    pub dae_early_bpf: bool,
    pub runtime_error: Option<String>,
    pub retained_fresh_snapshot: bool,
    pub bpf_snapshot_clients: usize,
    pub ecm_bpf_retained_fresh_snapshot: bool,
    pub ecm_bpf_snapshot_clients: usize,
    pub ecm_bpf_map_entries: usize,
    pub ecm_bpf_matched_entries: usize,
    pub ecm_bpf_error_stage: Option<String>,
    pub ecm_bpf_runtime_error: Option<String>,
    pub bpf_self_heal_recoveries: u64,
    pub bpf_self_heal_failures: u64,
    pub bpf_self_heal_last_reason: Option<String>,
    pub bpf_self_heal_last_failure: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub rate: RateCollector,
    pub connection: ConnectionCollector,
    pub mode: Mode,
    pub confidence: Confidence,
    pub warnings: Vec<&'static str>,
    pub evidence: PolicyEvidence,
}

pub fn select_collectors(
    config: &RuntimeConfig,
    facts: &ProbeFacts,
    runtime: &RuntimeHealth,
) -> PolicyDecision {
    let mut warnings = Vec::new();
    let has_collect_target = !config.runtime_collect_ifnames().is_empty();
    let tc_bpf_requested = matches!(
        config.rate_collector_mode,
        RateCollectorMode::Auto | RateCollectorMode::Bpf | RateCollectorMode::NssEcmBpf
    );
    let ecm_bpf_requested = matches!(
        config.rate_collector_mode,
        RateCollectorMode::Auto | RateCollectorMode::NssEcmBpf
    );
    if !config.enable_bpf && (tc_bpf_requested || ecm_bpf_requested) {
        push_unique(&mut warnings, "bpf_disabled");
    }
    if config.enable_bpf && tc_bpf_requested && !has_collect_target {
        push_unique(&mut warnings, "no_collect_interface");
    }
    if (tc_bpf_requested || ecm_bpf_requested)
        && !facts.bpf.package
        && !runtime.bpf_object_loaded
        && !runtime.ecm_bpf_object_loaded
    {
        push_unique(&mut warnings, "bpf_optional_package_missing");
    }
    if (tc_bpf_requested || ecm_bpf_requested)
        && !facts.bpf.object
        && !runtime.bpf_object_loaded
        && !runtime.ecm_bpf_object_loaded
    {
        push_unique(&mut warnings, "bpf_object_missing");
    }
    if config.enable_bpf
        && tc_bpf_requested
        && has_collect_target
        && !facts.tc.safe_attach
        && !runtime.bpf_attached
    {
        push_unique(&mut warnings, "unsafe_attach");
    }
    if !facts.files.nf_conntrack_acct
        && (facts.files.nf_conntrack_acct_present
            || (facts.nss.present && (facts.nss.ecm_active || facts.nss.ppe_active)))
    {
        push_unique(&mut warnings, "nf_conntrack_acct_disabled");
        push_unique(&mut warnings, "conntrack_acct_disabled");
    }
    if facts.offload.hardware {
        push_unique(&mut warnings, "hardware_flow_offload_unsupported");
    }

    let bpf_prerequisites = config.enable_bpf
        && has_collect_target
        && runtime.bpf_object_loaded
        && runtime.bpf_attached;
    // NSS ECM/PPE moves accelerated packets below the CPU tc hooks.  BPF must
    // remain attached for slow-path visibility, but it cannot claim complete
    // client coverage while NSS offload is active.
    let nss_offload_active = facts.nss.present && (facts.nss.ecm_active || facts.nss.ppe_active);
    let retained_fresh_snapshot = !runtime.bpf_map_read_ok
        && runtime
            .bpf_last_complete_snapshot_ms
            .is_some_and(|sample_ms| {
                crate::is_fresh(runtime.now_ms, sample_ms, runtime.bpf_freshness_ms)
            });
    let bpf_ready = bpf_prerequisites
        && (runtime.bpf_map_read_ok || retained_fresh_snapshot)
        && !facts.offload.hardware;
    let bpf_full = bpf_ready && !nss_offload_active;
    let ecm_bpf_retained_fresh_snapshot = !runtime.ecm_bpf_map_read_ok
        && runtime
            .ecm_bpf_last_complete_snapshot_ms
            .is_some_and(|sample_ms| {
                crate::is_fresh(runtime.now_ms, sample_ms, runtime.ecm_bpf_freshness_ms)
            });
    let ecm_bpf_ready = config.enable_bpf
        && facts.nss.present
        && facts.nss.ecm_active
        && runtime.ecm_bpf_object_loaded
        && runtime.ecm_bpf_attached
        && (runtime.ecm_bpf_map_read_ok || ecm_bpf_retained_fresh_snapshot);
    let nss_node = facts.nss.present
        && facts.nss.ecm_active
        && facts.nss.direct_state_readable
        && runtime.nss_node_read_ok.unwrap_or(true);
    let dae_active = facts.proxy.runtime_active;
    let dae_prefers_bpf =
        config.rate_collector_mode == RateCollectorMode::Auto && dae_active && bpf_ready;

    let (rate, rate_reason) = match config.rate_collector_mode {
        RateCollectorMode::Bpf => {
            // A forced pure-BPF mode is an explicit request for the Linux TC
            // view. NSS offload makes that view incomplete, not unavailable.
            if bpf_ready {
                (RateCollector::Bpf, "forced_bpf")
            } else if !has_collect_target {
                (RateCollector::Unsupported, "no_collect_interface")
            } else {
                (RateCollector::Unsupported, "forced_bpf_unavailable")
            }
        }
        RateCollectorMode::NssEcmNode => {
            if nss_node {
                (RateCollector::NssEcmNode, "forced_nss_ecm_node")
            } else {
                (
                    RateCollector::Unsupported,
                    "forced_nss_ecm_node_unavailable",
                )
            }
        }
        RateCollectorMode::NssEcmBpf => {
            if ecm_bpf_ready {
                (RateCollector::NssEcmBpf, "forced_nss_ecm_bpf")
            } else {
                (RateCollector::Unsupported, "forced_nss_ecm_bpf_unavailable")
            }
        }
        RateCollectorMode::Auto => {
            if ecm_bpf_ready {
                (RateCollector::NssEcmBpf, "nss_ecm_bpf_primary")
            } else if nss_node {
                (RateCollector::NssEcmNode, "nss_ecm_node_fallback")
            } else if dae_prefers_bpf {
                (RateCollector::Bpf, "dae_runtime_prefers_bpf")
            } else if bpf_ready {
                (
                    RateCollector::Bpf,
                    if nss_offload_active {
                        "nss_collectors_unavailable_bpf_fallback"
                    } else {
                        "bpf_available"
                    },
                )
            } else {
                (RateCollector::Unsupported, "no_live_rate_collector")
            }
        }
    };
    match rate {
        RateCollector::NssEcmNode => {
            push_unique(&mut warnings, "nss_ecm_node_active");
            push_unique(&mut warnings, "nss_ecm_node_ecm_flows_only");
        }
        RateCollector::NssEcmBpf => {
            push_unique(&mut warnings, "nss_ecm_bpf_active");
            push_unique(&mut warnings, "nss_ecm_bpf_disjoint_ownership");
            if !bpf_ready {
                push_unique(&mut warnings, "nss_ecm_bpf_tc_degraded");
            }
        }
        RateCollector::Bpf if nss_offload_active => {
            push_unique(&mut warnings, "nss_bpf_slow_path_only");
        }
        RateCollector::Bpf if dae_prefers_bpf => {
            push_unique(&mut warnings, "dae_runtime_prefers_bpf")
        }
        _ => {}
    }
    if bpf_prerequisites && runtime.bpf_map_read_attempted && !runtime.bpf_map_read_ok {
        push_unique(&mut warnings, "map_read_failed");
    }
    if ecm_bpf_requested
        && runtime.ecm_bpf_map_read_attempted
        && !runtime.ecm_bpf_map_read_ok
        && !ecm_bpf_retained_fresh_snapshot
    {
        push_unique(&mut warnings, "nss_ecm_bpf_map_read_failed");
    }
    if config.rate_collector_mode == RateCollectorMode::NssEcmBpf && !ecm_bpf_ready {
        push_unique(&mut warnings, "nss_ecm_bpf_runtime_unavailable");
    }
    let bpf_mode_allowed = matches!(
        config.rate_collector_mode,
        RateCollectorMode::Auto | RateCollectorMode::Bpf | RateCollectorMode::NssEcmBpf
    );
    let bpf_runtime_failed = runtime.bpf_object_loaded == false
        || runtime.bpf_attached == false
        || (runtime.bpf_map_read_attempted && !runtime.bpf_map_read_ok && !retained_fresh_snapshot);
    if rate == RateCollector::Unsupported
        && bpf_mode_allowed
        && config.enable_bpf
        && has_collect_target
        && (facts.tc.safe_attach || runtime.bpf_object_loaded)
        && bpf_runtime_failed
    {
        push_unique(&mut warnings, "bpf_runtime_loader_unavailable");
    }

    let (connection, connection_reason) = match config.conn_collector_mode {
        ConnectionCollectorMode::ConntrackNetlink => {
            if runtime.conntrack_netlink_available {
                (ConnectionCollector::Netlink, "forced_conntrack_netlink")
            } else {
                (
                    ConnectionCollector::Unsupported,
                    "forced_conntrack_netlink_unavailable",
                )
            }
        }
        ConnectionCollectorMode::ConntrackProcfs => {
            if runtime.conntrack_procfs_available {
                (ConnectionCollector::Procfs, "forced_conntrack_procfs")
            } else {
                (
                    ConnectionCollector::Unsupported,
                    "forced_conntrack_procfs_unavailable",
                )
            }
        }
        ConnectionCollectorMode::Auto => {
            if runtime.conntrack_netlink_available {
                (ConnectionCollector::Netlink, "netlink_preferred")
            } else if runtime.conntrack_procfs_available {
                (ConnectionCollector::Procfs, "procfs_fallback")
            } else {
                (ConnectionCollector::Unsupported, "conntrack_unavailable")
            }
        }
    };
    if connection == ConnectionCollector::Unsupported {
        push_unique(&mut warnings, "conntrack_unavailable");
    }

    let mode = match rate {
        RateCollector::Bpf if bpf_full => Mode::Full,
        RateCollector::NssEcmBpf if bpf_ready => Mode::Full,
        RateCollector::NssEcmBpf => Mode::Degraded,
        // ECM direct exposes accelerated flows only. CPU slow-path traffic can
        // be absent even when the state reader is healthy, so this source must
        // never claim complete client coverage.
        RateCollector::NssEcmNode | RateCollector::Bpf => Mode::Degraded,
        _ if !facts.tc.available && !nss_node && !ecm_bpf_ready => Mode::Unsupported,
        _ => Mode::Degraded,
    };
    if rate == RateCollector::Unsupported {
        push_unique(&mut warnings, "live_metrics_unavailable");
    }
    let confidence = match (mode, rate) {
        (Mode::Full, _) => Confidence::High,
        _ if facts.probe_error || facts.lan_probe_error => Confidence::Low,
        (Mode::Unsupported, _) => Confidence::Unsupported,
        _ => Confidence::Medium,
    };
    PolicyDecision {
        rate,
        connection,
        mode,
        confidence,
        warnings,
        evidence: PolicyEvidence {
            rate_reason,
            connection_reason,
            dae_early_bpf: (facts.tc.dae_preempts_lan_ingress || dae_active)
                && runtime.dae_early_bpf,
            runtime_error: runtime.runtime_error.clone(),
            retained_fresh_snapshot,
            bpf_snapshot_clients: runtime.bpf_snapshot_clients,
            ecm_bpf_retained_fresh_snapshot,
            ecm_bpf_snapshot_clients: runtime.ecm_bpf_snapshot_clients,
            ecm_bpf_map_entries: runtime.ecm_bpf_map_entries,
            ecm_bpf_matched_entries: runtime.ecm_bpf_matched_entries,
            ecm_bpf_error_stage: runtime.ecm_bpf_error_stage.clone(),
            ecm_bpf_runtime_error: runtime.ecm_bpf_runtime_error.clone(),
            bpf_self_heal_recoveries: runtime.bpf_self_heal_recoveries,
            bpf_self_heal_failures: runtime.bpf_self_heal_failures,
            bpf_self_heal_last_reason: runtime.bpf_self_heal_last_reason.clone(),
            bpf_self_heal_last_failure: runtime.bpf_self_heal_last_failure.clone(),
        },
    }
}
