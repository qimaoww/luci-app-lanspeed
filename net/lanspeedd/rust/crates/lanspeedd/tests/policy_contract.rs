use lanspeedd::{
    config::{RateCollectorMode, RuntimeConfig},
    policy::{select_collectors, RateCollector},
    probe::{Mode, ProbeFacts, RuntimeHealth},
};

fn config() -> RuntimeConfig {
    let mut config = RuntimeConfig::default();
    config.interface_include.push("br-lan".into());
    config.enable_bpf = true;
    config
}

fn healthy_bpf() -> RuntimeHealth {
    RuntimeHealth {
        bpf_object_loaded: true,
        bpf_attached: true,
        bpf_map_read_ok: true,
        ..RuntimeHealth::default()
    }
}

fn healthy_ecm_bpf() -> RuntimeHealth {
    RuntimeHealth {
        ecm_bpf_object_loaded: true,
        ecm_bpf_attached: true,
        ecm_bpf_map_read_attempted: true,
        ecm_bpf_map_read_ok: true,
        ..healthy_bpf()
    }
}

fn bpf_facts() -> ProbeFacts {
    let mut facts = ProbeFacts::default();
    facts.tc.available = true;
    facts.tc.safe_attach = true;
    facts.bpf.package = true;
    facts.bpf.object = true;
    facts
}

#[test]
fn auto_uses_bpf_without_nss_then_ecm_node_and_ecm_bpf_in_order() {
    let config = config();
    let mut facts = bpf_facts();
    let bpf = select_collectors(&config, &facts, &healthy_bpf());
    assert_eq!(bpf.rate, RateCollector::Bpf);
    assert_eq!(bpf.mode, Mode::Full);

    facts.nss.present = true;
    facts.nss.ecm_active = true;
    facts.nss.direct_state_readable = true;
    let node = select_collectors(&config, &facts, &healthy_bpf());
    assert_eq!(node.rate, RateCollector::NssEcmNode);
    assert_eq!(node.evidence.rate_reason, "nss_ecm_node_fallback");
    assert!(node.warnings.contains(&"nss_ecm_node_active"));

    let combined = select_collectors(&config, &facts, &healthy_ecm_bpf());
    assert_eq!(combined.rate, RateCollector::NssEcmBpf);
    assert_eq!(combined.evidence.rate_reason, "nss_ecm_bpf_primary");
    assert!(combined.warnings.contains(&"nss_ecm_bpf_active"));
}

#[test]
fn forced_ecm_bpf_requires_both_hardware_kprobe_and_tc_slow_path_runtime() {
    let mut config = config();
    config.rate_collector_mode = RateCollectorMode::NssEcmBpf;
    let mut facts = bpf_facts();
    facts.nss.present = true;
    facts.nss.ecm_active = true;
    facts.nss.direct_state_readable = true;

    let unavailable = select_collectors(&config, &facts, &healthy_bpf());
    assert_eq!(unavailable.rate, RateCollector::Unsupported);
    assert_eq!(
        unavailable.evidence.rate_reason,
        "forced_nss_ecm_bpf_unavailable"
    );
    assert!(unavailable
        .warnings
        .contains(&"nss_ecm_bpf_runtime_unavailable"));

    let available = select_collectors(&config, &facts, &healthy_ecm_bpf());
    assert_eq!(available.rate, RateCollector::NssEcmBpf);
    assert_eq!(available.evidence.rate_reason, "forced_nss_ecm_bpf");
    assert_eq!(available.mode, Mode::Full);

    let mut ecm_only = healthy_ecm_bpf();
    ecm_only.bpf_object_loaded = false;
    ecm_only.bpf_attached = false;
    ecm_only.bpf_map_read_ok = false;
    let degraded = select_collectors(&config, &facts, &ecm_only);
    assert_eq!(degraded.rate, RateCollector::NssEcmBpf);
    assert_eq!(degraded.mode, Mode::Degraded);
    assert!(degraded.warnings.contains(&"nss_ecm_bpf_tc_degraded"));
}

#[test]
fn forced_pure_bpf_remains_selectable_on_nss_but_reports_slow_path_coverage() {
    let mut config = config();
    config.rate_collector_mode = RateCollectorMode::Bpf;
    let mut facts = bpf_facts();
    facts.nss.present = true;
    facts.nss.ecm_active = true;
    let decision = select_collectors(&config, &facts, &healthy_bpf());
    assert_eq!(decision.rate, RateCollector::Bpf);
    assert_eq!(decision.mode, Mode::Degraded);
    assert!(decision.warnings.contains(&"nss_bpf_slow_path_only"));
}

#[test]
fn forced_node_fails_closed_when_state_is_unreadable() {
    let mut config = config();
    config.rate_collector_mode = RateCollectorMode::NssEcmNode;
    let mut facts = bpf_facts();
    facts.nss.present = true;
    facts.nss.ecm_active = true;
    let unavailable = select_collectors(&config, &facts, &healthy_bpf());
    assert_eq!(unavailable.rate, RateCollector::Unsupported);
    assert_eq!(
        unavailable.evidence.rate_reason,
        "forced_nss_ecm_node_unavailable"
    );

    facts.nss.direct_state_readable = true;
    let available = select_collectors(&config, &facts, &healthy_bpf());
    assert_eq!(available.rate, RateCollector::NssEcmNode);
    assert_eq!(available.evidence.rate_reason, "forced_nss_ecm_node");
    assert!(available.warnings.contains(&"nss_ecm_node_ecm_flows_only"));
    assert!(!available.warnings.contains(&"nss_bpf_slow_path_only"));
}

#[test]
fn nss_node_does_not_depend_on_conntrack_accounting() {
    let config = config();
    let mut facts = bpf_facts();
    facts.nss.present = true;
    facts.nss.ecm_active = true;
    facts.nss.direct_state_readable = true;
    facts.files.nf_conntrack_acct = false;
    facts.files.nf_conntrack_acct_present = true;
    let decision = select_collectors(&config, &facts, &healthy_bpf());
    assert_eq!(decision.rate, RateCollector::NssEcmNode);
    assert!(decision.warnings.contains(&"nf_conntrack_acct_disabled"));
}
