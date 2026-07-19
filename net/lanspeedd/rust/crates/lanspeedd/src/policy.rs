use crate::{
    config::{ConnectionCollectorMode, RateCollectorMode, RuntimeConfig},
    probe::{push_unique, Confidence, Mode, ProbeFacts, RuntimeHealth},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateCollector {
    Bpf,
    NssEcmDirect,
    NssConntrackSync,
    Unsupported,
}
impl RateCollector {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bpf => "bpf",
            Self::NssEcmDirect => "nss_ecm_direct",
            Self::NssConntrackSync => "nss_conntrack_sync",
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
    pub bpf_self_heal_recoveries: u64,
    pub bpf_self_heal_failures: u64,
    pub bpf_self_heal_last_reason: Option<String>,
    pub bpf_self_heal_last_failure: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub rate: RateCollector,
    pub connection: ConnectionCollector,
    pub nss_direct_overlay: bool,
    pub nss_sync_secondary: bool,
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
    if !config.enable_bpf {
        push_unique(&mut warnings, "bpf_disabled");
    }
    if config.enable_bpf && !has_collect_target {
        push_unique(&mut warnings, "no_collect_interface");
    }
    if !facts.bpf.package {
        push_unique(&mut warnings, "bpf_optional_package_missing");
    }
    if !facts.bpf.object {
        push_unique(&mut warnings, "bpf_object_missing");
    }
    if config.enable_bpf && has_collect_target && !facts.tc.safe_attach {
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
        && facts.tc.safe_attach
        && facts.bpf.package
        && facts.bpf.object
        && runtime.bpf_object_loaded
        && runtime.bpf_attached;
    let retained_fresh_snapshot = !runtime.bpf_map_read_ok
        && runtime
            .bpf_last_complete_snapshot_ms
            .is_some_and(|sample_ms| {
                crate::is_fresh(runtime.now_ms, sample_ms, runtime.bpf_freshness_ms)
            });
    let bpf_full = bpf_prerequisites
        && (runtime.bpf_map_read_ok || retained_fresh_snapshot)
        && !facts.offload.hardware;
    let nss_sync = config.enable_conntrack_fallback
        && facts.files.nf_conntrack_acct
        && facts.nss.present
        && (facts.nss.ecm_active || facts.nss.ppe_active)
        && runtime.nss_sync_read_ok.unwrap_or(true);
    let nss_direct = facts.nss.present
        && facts.nss.ecm_active
        && facts.nss.direct_state_readable
        && runtime.nss_direct_read_ok.unwrap_or(true);
    let dae_active = facts.proxy.runtime_active;
    let dae_prefers_bpf =
        config.rate_collector_mode == RateCollectorMode::Auto && dae_active && bpf_full;

    let (rate, rate_reason) = match config.rate_collector_mode {
        RateCollectorMode::Bpf => {
            if bpf_full {
                (RateCollector::Bpf, "forced_bpf")
            } else if !has_collect_target {
                (RateCollector::Unsupported, "no_collect_interface")
            } else {
                (RateCollector::Unsupported, "forced_bpf_unavailable")
            }
        }
        RateCollectorMode::NssEcmDirect => {
            if nss_direct {
                (RateCollector::NssEcmDirect, "forced_nss_ecm_direct")
            } else if nss_sync {
                (
                    RateCollector::NssConntrackSync,
                    "forced_direct_fallback_to_sync",
                )
            } else {
                (
                    RateCollector::Unsupported,
                    "forced_nss_ecm_direct_unavailable",
                )
            }
        }
        RateCollectorMode::NssConntrackSync => {
            if nss_sync {
                (RateCollector::NssConntrackSync, "forced_nss_conntrack_sync")
            } else {
                (
                    RateCollector::Unsupported,
                    "forced_nss_conntrack_sync_unavailable",
                )
            }
        }
        RateCollectorMode::Auto => {
            if dae_prefers_bpf {
                (RateCollector::Bpf, "dae_runtime_prefers_bpf")
            } else if bpf_full {
                (RateCollector::Bpf, "bpf_available")
            } else if nss_sync {
                (
                    RateCollector::NssConntrackSync,
                    "bpf_unavailable_nss_sync_fallback",
                )
            } else if nss_direct {
                (
                    RateCollector::NssEcmDirect,
                    "bpf_unavailable_nss_direct_fallback",
                )
            } else {
                (RateCollector::Unsupported, "no_live_rate_collector")
            }
        }
    };
    let nss_direct_overlay = nss_direct
        && rate == RateCollector::NssConntrackSync
        && config.rate_collector_mode == RateCollectorMode::Auto
        && !dae_prefers_bpf;
    let nss_sync_secondary = rate == RateCollector::NssEcmDirect && nss_sync;

    match rate {
        RateCollector::NssEcmDirect => push_unique(&mut warnings, "nss_ecm_direct_active"),
        RateCollector::NssConntrackSync => {
            push_unique(&mut warnings, "nss_ecm_sync_cadence");
            if bpf_full {
                push_unique(&mut warnings, "nss_prefers_conntrack_sync");
            }
            if facts.nss.present && dae_active && !bpf_full {
                push_unique(&mut warnings, "nss_dae_bpf_fallback_may_be_inaccurate");
            }
        }
        RateCollector::Bpf if dae_prefers_bpf => {
            push_unique(&mut warnings, "dae_runtime_prefers_bpf")
        }
        _ => {}
    }
    if nss_direct_overlay {
        push_unique(&mut warnings, "nss_ecm_direct_active");
    }
    if bpf_prerequisites && runtime.bpf_map_read_attempted && !runtime.bpf_map_read_ok {
        push_unique(&mut warnings, "map_read_failed");
    }
    let bpf_mode_allowed = matches!(
        config.rate_collector_mode,
        RateCollectorMode::Auto | RateCollectorMode::Bpf
    );
    let bpf_runtime_failed = runtime.bpf_object_loaded == false
        || runtime.bpf_attached == false
        || (runtime.bpf_map_read_attempted && !runtime.bpf_map_read_ok && !retained_fresh_snapshot);
    if rate == RateCollector::Unsupported
        && bpf_mode_allowed
        && config.enable_bpf
        && has_collect_target
        && facts.tc.safe_attach
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
        RateCollector::NssEcmDirect => Mode::Full,
        RateCollector::NssConntrackSync => Mode::Degraded,
        _ if !facts.tc.available && !nss_sync => Mode::Unsupported,
        _ => Mode::Degraded,
    };
    if rate == RateCollector::Unsupported {
        push_unique(&mut warnings, "live_metrics_unavailable");
    }
    let confidence = match (mode, rate) {
        (Mode::Full, _) => Confidence::High,
        _ if facts.probe_error || facts.lan_probe_error => Confidence::Low,
        (Mode::Unsupported, _) => Confidence::Unsupported,
        (_, RateCollector::NssConntrackSync) if low_conntrack_confidence(facts) => Confidence::Low,
        _ => Confidence::Medium,
    };
    PolicyDecision {
        rate,
        connection,
        nss_direct_overlay,
        nss_sync_secondary,
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
            bpf_self_heal_recoveries: runtime.bpf_self_heal_recoveries,
            bpf_self_heal_failures: runtime.bpf_self_heal_failures,
            bpf_self_heal_last_reason: runtime.bpf_self_heal_last_reason.clone(),
            bpf_self_heal_last_failure: runtime.bpf_self_heal_last_failure.clone(),
        },
    }
}

fn low_conntrack_confidence(facts: &ProbeFacts) -> bool {
    !facts.files.flowtable_counter
        || facts.offload.software
        || facts.proxy.openclash_fake_ip
        || facts.proxy.openclash_tun_mix
        || facts.proxy.openclash_router_self_proxy
        || facts.proxy.openclash_udp_proxy
        || facts.proxy.dae
        || facts.homeproxy
        || facts.sqm
        || facts.qosify
        || facts.files.ifb
        || facts.nlbwmon
        || facts.probe_error
        || facts.lan_probe_error
}
