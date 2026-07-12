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

#[test]
fn forced_and_auto_rate_modes_preserve_task10_selection_contract() {
    let mut config = RuntimeConfig::default();
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
    assert_eq!(auto_nss.rate, RateCollector::NssConntrackSync);
    assert!(auto_nss.nss_direct_overlay);
    assert!(auto_nss.warnings.contains(&"nss_prefers_conntrack_sync"));

    facts.proxy.daed_running = true;
    let daed_auto = select_collectors(&config, &facts, &healthy());
    assert_eq!(daed_auto.rate, RateCollector::Bpf);
    assert!(daed_auto.warnings.contains(&"nss_daed_prefers_bpf"));

    config.rate_collector_mode = RateCollectorMode::NssEcmDirect;
    let forced_direct = select_collectors(&config, &facts, &healthy());
    assert_eq!(forced_direct.rate, RateCollector::NssEcmDirect);
    assert!(!forced_direct.warnings.contains(&"nss_daed_prefers_bpf"));

    facts.nss.direct_state_readable = false;
    let direct_fallback = select_collectors(&config, &facts, &healthy());
    assert_eq!(direct_fallback.rate, RateCollector::NssConntrackSync);

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
fn unsafe_attach_missing_object_map_failure_and_recovery_are_honest() {
    let mut config = RuntimeConfig::default();
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
fn conntrack_accounting_and_connection_collector_are_independent_of_rate_policy() {
    let mut config = RuntimeConfig::default();
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
    let mut config = RuntimeConfig::default();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    let mut facts = bpf_facts();
    facts.nss.present = true;
    facts.nss.ppe_active = true;
    assert_eq!(
        select_collectors(&config, &facts, &healthy()).rate,
        RateCollector::NssConntrackSync
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
