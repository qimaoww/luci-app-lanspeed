use lanspeedd::{
    config::{ConnectionCollectorMode, RateCollectorMode, RuntimeConfig},
    policy::{select_collectors, ConnectionCollector, RateCollector},
    probe::{Mode, ProbeFacts, RuntimeHealth},
};

fn healthy() -> RuntimeHealth {
    RuntimeHealth {
        bpf_object_loaded: true,
        bpf_attached: true,
        bpf_map_read_ok: true,
        conntrack_netlink_available: true,
        conntrack_procfs_available: true,
        ..RuntimeHealth::default()
    }
}

fn bpf_facts() -> ProbeFacts {
    let mut facts = ProbeFacts::default();
    facts.tc.available = true;
    facts.tc.clsact = true;
    facts.tc.bpf = true;
    facts.tc.safe_attach = true;
    facts.bpf.package = true;
    facts.bpf.object = true;
    facts.lan_edge = true;
    facts.files.nf_conntrack_acct = true;
    facts
}

fn bpf_config() -> RuntimeConfig {
    let mut config = RuntimeConfig::default();
    config.interface_include.push("eth1".into());
    config
}

#[test]
fn forced_and_auto_rate_modes_preserve_task10_selection_contract() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut facts = bpf_facts();

    let auto_bpf = select_collectors(&config, &facts, &healthy());
    assert_eq!(auto_bpf.rate, RateCollector::Bpf);
    assert_eq!(auto_bpf.mode, Mode::Full);

    facts.nss.present = true;
    facts.nss.ecm_active = true;
    facts.nss.direct_state_readable = true;
    let auto_nss = select_collectors(&config, &facts, &healthy());
    assert_eq!(auto_nss.rate, RateCollector::Bpf);
    assert!(!auto_nss.nss_direct_overlay);
    assert!(!auto_nss.nss_sync_secondary);
    assert_eq!(auto_nss.evidence.rate_reason, "bpf_available");
    assert!(!auto_nss.warnings.contains(&"nss_prefers_conntrack_sync"));

    facts.proxy.daed_running = true;
    facts.proxy.runtime_active = true;
    let daed_auto = select_collectors(&config, &facts, &healthy());
    assert_eq!(daed_auto.rate, RateCollector::Bpf);
    assert!(daed_auto.warnings.contains(&"dae_runtime_prefers_bpf"));

    config.rate_collector_mode = RateCollectorMode::NssEcmDirect;
    let forced_direct = select_collectors(&config, &facts, &healthy());
    assert_eq!(forced_direct.rate, RateCollector::NssEcmDirect);
    assert!(!forced_direct.nss_direct_overlay);
    assert!(forced_direct.nss_sync_secondary);
    assert!(!forced_direct.warnings.contains(&"dae_runtime_prefers_bpf"));

    facts.nss.direct_state_readable = false;
    let direct_fallback = select_collectors(&config, &facts, &healthy());
    assert_eq!(direct_fallback.rate, RateCollector::NssConntrackSync);
    assert!(!direct_fallback.nss_direct_overlay);
    assert!(!direct_fallback.nss_sync_secondary);

    facts.nss.direct_state_readable = true;
    config.rate_collector_mode = RateCollectorMode::NssConntrackSync;
    assert_eq!(
        select_collectors(&config, &facts, &healthy()).rate,
        RateCollector::NssConntrackSync
    );

    config.rate_collector_mode = RateCollectorMode::Bpf;
    assert_eq!(
        select_collectors(&config, &facts, &healthy()).rate,
        RateCollector::Bpf
    );
}

#[test]
fn only_fresh_runtime_active_state_controls_dae_collector_policy() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut facts = bpf_facts();
    facts.nss.present = true;
    facts.nss.ecm_active = true;
    facts.nss.direct_state_readable = true;
    facts.proxy.dae_running = true;
    facts.proxy.daed_running = true;
    facts.proxy.dae_process = true;
    facts.proxy.daed_process = true;
    facts.proxy.runtime_active = false;

    let stale = select_collectors(&config, &facts, &healthy());
    assert_eq!(stale.rate, RateCollector::Bpf);
    assert_eq!(stale.evidence.rate_reason, "bpf_available");
    assert!(!stale.warnings.contains(&"dae_runtime_prefers_bpf"));
    assert!(!stale
        .warnings
        .contains(&"nss_dae_bpf_fallback_may_be_inaccurate"));

    facts.proxy.runtime_active = true;
    let fresh = select_collectors(&config, &facts, &healthy());
    assert_eq!(fresh.rate, RateCollector::Bpf);
    assert_eq!(fresh.evidence.rate_reason, "dae_runtime_prefers_bpf");
    assert!(fresh.warnings.contains(&"dae_runtime_prefers_bpf"));

    config.rate_collector_mode = RateCollectorMode::NssEcmDirect;
    let forced = select_collectors(&config, &facts, &healthy());
    assert_eq!(forced.rate, RateCollector::NssEcmDirect);
    assert!(!forced.warnings.contains(&"dae_runtime_prefers_bpf"));
}

#[test]
fn auto_keeps_bpf_first_and_uses_readable_nss_direct_only_when_bpf_is_unavailable() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut facts = bpf_facts();
    facts.files.nf_conntrack_acct = false;
    facts.files.nf_conntrack_acct_present = true;
    facts.nss.present = true;
    facts.nss.ecm_active = true;
    facts.nss.direct_state_present = true;
    facts.nss.direct_state_readable = true;

    let with_bpf = select_collectors(&config, &facts, &healthy());
    assert_eq!(with_bpf.rate, RateCollector::Bpf);
    assert!(!with_bpf.nss_direct_overlay);
    assert_eq!(
        with_bpf.warnings,
        vec!["nf_conntrack_acct_disabled", "conntrack_acct_disabled"]
    );

    let mut no_bpf = healthy();
    no_bpf.bpf_attached = false;
    assert_eq!(
        select_collectors(&config, &facts, &no_bpf).rate,
        RateCollector::NssEcmDirect
    );
}

#[test]
fn dae_runtime_prefers_early_bpf_in_auto_mode_on_non_nss_devices() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut facts = bpf_facts();
    facts.proxy.dae_process = true;
    facts.proxy.runtime_active = true;
    let mut runtime = healthy();
    runtime.dae_early_bpf = true;

    let decision = select_collectors(&config, &facts, &runtime);
    assert_eq!(decision.rate, RateCollector::Bpf);
    assert_eq!(decision.evidence.rate_reason, "dae_runtime_prefers_bpf");
    assert!(decision.warnings.contains(&"dae_runtime_prefers_bpf"));
    assert!(decision.evidence.dae_early_bpf);
}

#[test]
fn nss_fallback_uses_the_dae_runtime_warning_when_bpf_is_unavailable() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut facts = bpf_facts();
    facts.proxy.daed_process = true;
    facts.proxy.runtime_active = true;
    facts.nss.present = true;
    facts.nss.ecm_active = true;
    let mut runtime = healthy();
    runtime.bpf_attached = false;
    runtime.bpf_map_read_ok = false;
    runtime.nss_sync_read_ok = Some(true);

    let decision = select_collectors(&config, &facts, &runtime);
    assert_eq!(decision.rate, RateCollector::NssConntrackSync);
    assert!(decision
        .warnings
        .contains(&"nss_dae_bpf_fallback_may_be_inaccurate"));
    assert!(!decision
        .warnings
        .contains(&"nss_daed_nss_fallback_may_be_inaccurate"));
}

#[test]
fn unsafe_attach_missing_object_map_failure_and_recovery_are_honest() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut facts = bpf_facts();

    facts.tc.safe_attach = false;
    let unsafe_decision = select_collectors(&config, &facts, &healthy());
    assert_eq!(unsafe_decision.rate, RateCollector::Unsupported);
    assert!(unsafe_decision.warnings.contains(&"unsafe_attach"));

    facts.tc.safe_attach = true;
    facts.bpf.object = false;
    let missing = select_collectors(&config, &facts, &healthy());
    assert_eq!(missing.rate, RateCollector::Unsupported);
    assert!(missing.warnings.contains(&"bpf_object_missing"));

    facts.bpf.object = true;
    let mut failed = healthy();
    failed.bpf_map_read_attempted = true;
    failed.bpf_map_read_ok = false;
    failed.runtime_error = Some("map lookup failed".into());
    let map_failure = select_collectors(&config, &facts, &failed);
    assert_eq!(map_failure.mode, Mode::Degraded);
    assert!(map_failure.warnings.contains(&"map_read_failed"));
    assert!(map_failure
        .warnings
        .contains(&"bpf_runtime_loader_unavailable"));
    assert_eq!(
        map_failure.evidence.runtime_error.as_deref(),
        Some("map lookup failed")
    );

    let recovered = select_collectors(&config, &facts, &healthy());
    assert_eq!(recovered.rate, RateCollector::Bpf);
    assert_eq!(recovered.mode, Mode::Full);
    assert!(!recovered.warnings.contains(&"map_read_failed"));
}

#[test]
fn map_failure_keeps_a_fresh_complete_snapshot_then_expires_and_recovers() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    let facts = bpf_facts();
    let mut runtime = healthy();
    runtime.bpf_map_read_attempted = true;
    runtime.bpf_map_read_ok = false;
    runtime.bpf_last_complete_snapshot_ms = Some(9_000);
    runtime.now_ms = 10_000;
    runtime.bpf_freshness_ms = 3_000;
    runtime.bpf_snapshot_clients = 4;
    runtime.bpf_self_heal_recoveries = 2;
    runtime.bpf_self_heal_failures = 1;
    runtime.bpf_self_heal_last_reason = Some("network_reload".into());

    let retained = select_collectors(&config, &facts, &runtime);
    assert_eq!(retained.rate, RateCollector::Bpf);
    assert_eq!(retained.mode, Mode::Full);
    assert!(retained.warnings.contains(&"map_read_failed"));
    assert!(retained.evidence.retained_fresh_snapshot);
    assert_eq!(retained.evidence.bpf_snapshot_clients, 4);

    runtime.bpf_last_complete_snapshot_ms = Some(10_001);
    let future = select_collectors(&config, &facts, &runtime);
    assert_eq!(future.mode, Mode::Degraded);
    assert!(!future.evidence.retained_fresh_snapshot);
    runtime.bpf_last_complete_snapshot_ms = Some(9_000);

    runtime.now_ms = 13_001;
    let stale = select_collectors(&config, &facts, &runtime);
    assert_eq!(stale.mode, Mode::Degraded);
    assert!(!stale.evidence.retained_fresh_snapshot);

    runtime.bpf_map_read_ok = true;
    runtime.bpf_last_complete_snapshot_ms = Some(runtime.now_ms);
    let recovered = select_collectors(&config, &facts, &runtime);
    assert_eq!(recovered.mode, Mode::Full);
    assert!(!recovered
        .warnings
        .contains(&"bpf_runtime_loader_unavailable"));
}

#[test]
fn forced_nss_does_not_report_a_bpf_runtime_failure() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    config.rate_collector_mode = RateCollectorMode::NssEcmDirect;
    let facts = bpf_facts();
    let decision = select_collectors(&config, &facts, &RuntimeHealth::default());
    assert_eq!(decision.rate, RateCollector::Unsupported);
    assert!(!decision
        .warnings
        .contains(&"bpf_runtime_loader_unavailable"));
}

#[test]
fn empty_collect_plan_is_not_misreported_as_an_attach_or_map_failure() {
    let mut config = RuntimeConfig::default();
    config.enable_bpf = true;
    config.rate_collector_mode = RateCollectorMode::Bpf;
    config.ifnames.clear();
    config.interface_include.clear();
    let decision = select_collectors(&config, &bpf_facts(), &RuntimeHealth::default());
    assert_eq!(decision.rate, RateCollector::Unsupported);
    assert_eq!(decision.evidence.rate_reason, "no_collect_interface");
    assert!(decision.warnings.contains(&"no_collect_interface"));
    assert!(!decision.warnings.contains(&"unsafe_attach"));
    assert!(!decision
        .warnings
        .contains(&"bpf_runtime_loader_unavailable"));
    assert!(!decision.warnings.contains(&"map_read_failed"));
}

#[test]
fn live_nss_fallback_is_degraded_but_not_reported_as_missing_live_metrics() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut facts = bpf_facts();
    facts.nss.present = true;
    facts.nss.ecm_active = true;
    facts.files.nf_conntrack_acct = true;
    let decision = select_collectors(&config, &facts, &RuntimeHealth::default());
    assert_eq!(decision.rate, RateCollector::NssConntrackSync);
    assert_eq!(decision.mode, Mode::Degraded);
    assert!(!decision.warnings.contains(&"live_metrics_unavailable"));
}

#[test]
fn conntrack_accounting_and_connection_collector_are_independent_of_rate_policy() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut facts = bpf_facts();
    facts.nss.present = true;
    facts.nss.ecm_active = true;

    facts.files.nf_conntrack_acct = false;
    let disabled = select_collectors(&config, &facts, &healthy());
    assert_eq!(disabled.rate, RateCollector::Bpf);
    assert!(disabled.warnings.contains(&"conntrack_acct_disabled"));

    facts.files.nf_conntrack_acct = true;
    assert_eq!(
        select_collectors(&config, &facts, &healthy()).connection,
        ConnectionCollector::Netlink
    );

    config.conn_collector_mode = ConnectionCollectorMode::ConntrackProcfs;
    assert_eq!(
        select_collectors(&config, &facts, &healthy()).connection,
        ConnectionCollector::Procfs
    );

    config.conn_collector_mode = ConnectionCollectorMode::ConntrackNetlink;
    let mut procfs_only = healthy();
    procfs_only.conntrack_netlink_available = false;
    assert_eq!(
        select_collectors(&config, &facts, &procfs_only).connection,
        ConnectionCollector::Unsupported
    );
}

#[test]
fn ppe_and_dae_early_bpf_policy_remain_explicit() {
    let mut config = bpf_config();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut facts = bpf_facts();
    facts.nss.present = true;
    facts.nss.ppe_active = true;
    assert_eq!(
        select_collectors(&config, &facts, &healthy()).rate,
        RateCollector::Bpf
    );

    facts.nss = Default::default();
    facts.tc.dae_preempts_lan_ingress = true;
    let mut runtime = healthy();
    runtime.dae_early_bpf = true;
    let decision = select_collectors(&config, &facts, &runtime);
    assert_eq!(decision.rate, RateCollector::Bpf);
    assert!(decision.evidence.dae_early_bpf);
}

#[test]
fn probe_error_keeps_legacy_low_confidence_even_when_mode_is_unsupported() {
    let config = RuntimeConfig::default();
    let mut facts = ProbeFacts::default();
    facts.probe_error = true;
    let decision = select_collectors(&config, &facts, &RuntimeHealth::default());
    assert_eq!(decision.mode, Mode::Unsupported);
    assert_eq!(decision.confidence, lanspeedd::probe::Confidence::Low);
}
