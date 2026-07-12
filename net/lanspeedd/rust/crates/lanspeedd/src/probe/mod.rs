pub mod commands;
pub mod files;
pub mod proxy;
pub mod tc;

use crate::config::RuntimeConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Full,
    Degraded,
    Unsupported,
}
impl Mode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "Full",
            Self::Degraded => "Degraded",
            Self::Unsupported => "Unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Confidence {
    High,
    Medium,
    Low,
    Unsupported,
}
impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeHealth {
    pub bpf_object_loaded: bool,
    pub bpf_attached: bool,
    pub bpf_map_read_ok: bool,
    pub conntrack_netlink_available: bool,
    pub conntrack_procfs_available: bool,
    pub dae_early_bpf: bool,
    pub runtime_error: Option<String>,
}
pub type ProbeRuntimeHealth = RuntimeHealth;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommandObservations {
    pub fw4: bool,
    pub nft: bool,
    pub tc: bool,
    pub ubus: bool,
    pub qosify: bool,
    pub flowtable_counter: bool,
    pub flowtable_exit_code: i32,
    pub tc_filter_help_exit_code: i32,
    pub tc_qdisc_help_exit_code: i32,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FileObservations {
    pub nf_conntrack_acct_present: bool,
    pub nf_conntrack_acct_value: Option<String>,
    pub flowtable_proc: bool,
    pub flowtable_debug: bool,
    pub ifb: bool,
    pub lan_bridge: bool,
    pub vlan: bool,
    pub wlan: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UciObservations {
    pub firewall_loaded: bool,
    pub sqm: bool,
    pub qosify: bool,
    pub openclash: bool,
    pub dae: bool,
    pub daed: bool,
    pub homeproxy: bool,
    pub nlbwmon: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UbusObservations {
    pub network_lan_attempted: bool,
    pub network_lan_exit_code: i32,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcObservations {
    pub clsact: bool,
    pub bpf: bool,
    pub existing_filters: bool,
    pub filters: Vec<TcFilter>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyObservation {
    pub openclash_installed: bool,
    pub openclash_en_mode: Option<String>,
    pub openclash_redirect_dns: bool,
    pub openclash_dnsmasq_chain: bool,
    pub openclash_router_self_proxy: bool,
    pub openclash_udp_proxy: bool,
    pub openclash_stack_type: Option<String>,
    pub openclash_ipv6: bool,
    pub dae_service: bool,
    pub daed_service: bool,
    pub dae_running: bool,
    pub daed_running: bool,
    pub dae_process: bool,
    pub daed_process: bool,
    pub dae_iface: bool,
    pub dae_peer_iface: bool,
    pub dae_fwmark: bool,
    pub dae_route_table: bool,
    pub dae_dns_udp53: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OffloadObservation {
    pub software: bool,
    pub hardware: bool,
    pub fullcone: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NssObservation {
    pub present: bool,
    pub ecm_active: bool,
    pub ppe_active: bool,
    pub direct_state_present: bool,
    pub direct_state_readable: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BpfObservation {
    pub package: bool,
    pub object: bool,
    pub map_full_observed: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProbeObservations {
    pub commands: CommandObservations,
    pub files: FileObservations,
    pub uci: UciObservations,
    pub ubus: UbusObservations,
    pub tc: TcObservations,
    pub proxy: ProxyObservation,
    pub offload: OffloadObservation,
    pub nss: NssObservation,
    pub bpf: BpfObservation,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcFilter {
    pub interface: String,
    pub direction: String,
    pub pref: u32,
    pub handle: String,
    pub owner: String,
    pub source: String,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcFacts {
    pub available: bool,
    pub clsact: bool,
    pub bpf: bool,
    pub existing_filters: bool,
    pub conflict: bool,
    pub dae_preempts_lan_ingress: bool,
    pub safe_attach: bool,
    pub filters: Vec<TcFilter>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FileFacts {
    pub nf_conntrack_acct_present: bool,
    pub nf_conntrack_acct: bool,
    pub flowtable_counter: bool,
    pub ifb: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyFacts {
    pub openclash: bool,
    pub openclash_fake_ip: bool,
    pub openclash_tun_mix: bool,
    pub openclash_redirect_dns: bool,
    pub openclash_dns_chain_complete: bool,
    pub openclash_router_self_proxy: bool,
    pub openclash_udp_proxy: bool,
    pub openclash_ipv6: bool,
    pub dae: bool,
    pub dae_running: bool,
    pub daed_running: bool,
    pub dae_process: bool,
    pub daed_process: bool,
    pub runtime_active: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OffloadFacts {
    pub software: bool,
    pub hardware: bool,
    pub fullcone: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NssFacts {
    pub present: bool,
    pub ecm_active: bool,
    pub ppe_active: bool,
    pub direct_state_present: bool,
    pub direct_state_readable: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BpfFacts {
    pub package: bool,
    pub object: bool,
    pub map_full_observed: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProbeFacts {
    pub fw4: bool,
    pub nft: bool,
    pub lan_edge: bool,
    pub probe_error: bool,
    pub lan_probe_error: bool,
    pub tc: TcFacts,
    pub files: FileFacts,
    pub proxy: ProxyFacts,
    pub offload: OffloadFacts,
    pub nss: NssFacts,
    pub bpf: BpfFacts,
    pub sqm: bool,
    pub qosify: bool,
    pub homeproxy: bool,
    pub nlbwmon: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProbeCapabilities {
    pub bpf: bool,
    pub bpf_package: bool,
    pub bpf_object: bool,
    pub bpf_runtime_metrics: bool,
    pub conntrack_fallback: bool,
    pub live_metrics: bool,
    pub fw4: bool,
    pub nft: bool,
    pub software_flow_offload: bool,
    pub hardware_flow_offload: bool,
    pub fullcone: bool,
    pub nf_conntrack_acct: bool,
    pub flowtable_counter: bool,
    pub tc: bool,
    pub tc_clsact: bool,
    pub existing_tc_filters: bool,
    pub ifb: bool,
    pub sqm: bool,
    pub qosify: bool,
    pub openclash: bool,
    pub openclash_fake_ip: bool,
    pub openclash_tun_mix: bool,
    pub openclash_redirect_dns: bool,
    pub openclash_dns_chain_complete: bool,
    pub openclash_router_self_proxy: bool,
    pub openclash_udp_proxy: bool,
    pub openclash_ipv6: bool,
    pub dae: bool,
    pub homeproxy: bool,
    pub lan_bridge: bool,
    pub vlan: bool,
    pub wlan: bool,
    pub lan_edge: bool,
    pub safe_attach: bool,
    pub map_full: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Conflict {
    pub id: &'static str,
    pub severity: &'static str,
    pub message: &'static str,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandEvidence {
    pub source: String,
    pub available: bool,
    pub exit_code: Option<i32>,
    pub supported: Option<bool>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileEvidence {
    pub source: String,
    pub path: String,
    pub present: bool,
    pub value: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UciEvidence {
    pub source: String,
    pub package: String,
    pub loaded: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UbusEvidence {
    pub source: String,
    pub object: String,
    pub attempted: bool,
    pub exit_code: i32,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcEvidence {
    pub filters: Vec<TcFilter>,
    pub conflict: bool,
    pub dae_preempts_bpf_ingress: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenClashEvidence {
    pub installed: bool,
    pub en_mode: String,
    pub fake_ip: bool,
    pub tun_mix: bool,
    pub enable_redirect_dns: bool,
    pub dnsmasq_to_127_0_0_1_7874: bool,
    pub dns_chain_complete: bool,
    pub router_self_proxy: bool,
    pub enable_udp_proxy: bool,
    pub stack_type: String,
    pub ipv6_enable: bool,
    pub remote_identity_policy: &'static str,
    pub primary_bpf_policy: &'static str,
    pub router_self_bucket: &'static str,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaeEvidence {
    pub installed: bool,
    pub dae_config: bool,
    pub daed_config: bool,
    pub dae_service: bool,
    pub daed_service: bool,
    pub dae_running: bool,
    pub daed_running: bool,
    pub dae_process: bool,
    pub daed_process: bool,
    pub runtime_active: bool,
    pub dae0: bool,
    pub dae0peer: bool,
    pub tc_filters: Vec<TcFilter>,
    pub fwmark: &'static str,
    pub fwmark_detected: bool,
    pub route_table: &'static str,
    pub route_table_detected: bool,
    pub dns_udp53_detected: bool,
    pub uplink_evidence_policy: &'static str,
    pub identity_policy: &'static str,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyEvidence {
    pub openclash: OpenClashEvidence,
    pub dae: DaeEvidence,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OffloadEvidence {
    pub software: bool,
    pub hardware: bool,
    pub fullcone: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NssEvidence {
    pub present: bool,
    pub ecm_active: bool,
    pub ppe_active: bool,
    pub direct_state_present: bool,
    pub direct_state_readable: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BpfEvidence {
    pub package_present: bool,
    pub object_present: bool,
    pub runtime_attach_map_read_success: bool,
    pub map_full_observed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeEvidence {
    pub source: &'static str,
    pub method: &'static str,
    pub read_only: bool,
    pub command: Vec<CommandEvidence>,
    pub file: Vec<FileEvidence>,
    pub uci: Vec<UciEvidence>,
    pub ubus: Vec<UbusEvidence>,
    pub tc: TcEvidence,
    pub proxy: ProxyEvidence,
    pub offload: OffloadEvidence,
    pub nss: NssEvidence,
    pub bpf: BpfEvidence,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeReport {
    pub mode: Mode,
    pub confidence: Confidence,
    pub capabilities: ProbeCapabilities,
    pub facts: ProbeFacts,
    pub warnings: Vec<&'static str>,
    pub conflicts: Vec<Conflict>,
    pub evidence: ProbeEvidence,
}

pub fn assess(
    config: &RuntimeConfig,
    observations: ProbeObservations,
    runtime: &RuntimeHealth,
) -> ProbeReport {
    let conflict = tc::has_owned_identity_collision(&observations.tc.filters);
    let dae_preempts = tc::dae_preempts_lan_ingress(&observations.tc.filters);
    let (proxy_facts, proxy_evidence) = proxy::evaluate(
        &observations.proxy,
        observations.uci.dae,
        observations.uci.daed,
        &observations.tc.filters,
    );
    let lan_edge =
        observations.files.lan_bridge || observations.files.vlan || observations.files.wlan;
    let nf_acct = observations.files.nf_conntrack_acct_present
        && observations.files.nf_conntrack_acct_value.as_deref() == Some("1");
    let map_full = config.max_clients < 1;
    let safe_attach = config.enable_bpf
        && observations.commands.tc
        && observations.tc.clsact
        && observations.tc.bpf
        && observations.bpf.package
        && observations.bpf.object
        && lan_edge
        && !map_full
        && !conflict;
    let bpf_runtime = config.enable_bpf
        && safe_attach
        && runtime.bpf_object_loaded
        && runtime.bpf_attached
        && runtime.bpf_map_read_ok;
    let probe_error = observations.commands.flowtable_exit_code != 0
        || observations.commands.tc_filter_help_exit_code != 0
        || observations.commands.tc_qdisc_help_exit_code != 0
        || observations.ubus.network_lan_exit_code != 0;
    let lan_probe_error = observations.ubus.network_lan_exit_code != 0;
    let facts = ProbeFacts {
        fw4: observations.commands.fw4,
        nft: observations.commands.nft,
        lan_edge,
        probe_error,
        lan_probe_error,
        tc: TcFacts {
            available: observations.commands.tc,
            clsact: observations.tc.clsact,
            bpf: observations.tc.bpf,
            existing_filters: observations.tc.existing_filters,
            conflict,
            dae_preempts_lan_ingress: dae_preempts,
            safe_attach,
            filters: observations.tc.filters.clone(),
        },
        files: FileFacts {
            nf_conntrack_acct_present: observations.files.nf_conntrack_acct_present,
            nf_conntrack_acct: nf_acct,
            flowtable_counter: observations.commands.nft
                && observations.commands.flowtable_exit_code == 0
                && observations.commands.flowtable_counter,
            ifb: observations.files.ifb,
        },
        proxy: proxy_facts,
        offload: OffloadFacts {
            software: observations.offload.software,
            hardware: observations.offload.hardware,
            fullcone: observations.offload.fullcone,
        },
        nss: NssFacts {
            present: observations.nss.present,
            ecm_active: observations.nss.ecm_active,
            ppe_active: observations.nss.ppe_active,
            direct_state_present: observations.nss.direct_state_present,
            direct_state_readable: observations.nss.direct_state_readable,
        },
        bpf: BpfFacts {
            package: observations.bpf.package,
            object: observations.bpf.object,
            map_full_observed: observations.bpf.map_full_observed,
        },
        sqm: observations.uci.sqm,
        qosify: observations.uci.qosify || observations.commands.qosify,
        homeproxy: observations.uci.homeproxy,
        nlbwmon: observations.uci.nlbwmon,
    };
    let mut warnings = Vec::new();
    if !facts.tc.available {
        push_unique(&mut warnings, "tc_missing");
    }
    if facts.tc.available && !facts.tc.bpf {
        push_unique(&mut warnings, "bpf_unsupported");
    }
    if facts.tc.available && !facts.tc.clsact {
        push_unique(&mut warnings, "tc_clsact_unsupported");
    }
    if facts.tc.existing_filters {
        push_unique(&mut warnings, "existing_tc_filters_detected");
    }
    if conflict {
        push_unique(&mut warnings, "tc_filter_conflict");
    }
    if dae_preempts {
        push_unique(&mut warnings, "dae_tc_preempts_bpf_ingress");
    }
    if !config.enable_bpf {
        push_unique(&mut warnings, "bpf_disabled");
    }
    if !facts.bpf.package {
        push_unique(&mut warnings, "bpf_optional_package_missing");
    }
    if !facts.bpf.object {
        push_unique(&mut warnings, "bpf_object_missing");
    }
    if !observations.commands.nft {
        push_unique(&mut warnings, "flowtable_counter_probe_unavailable");
        push_unique(&mut warnings, "flowtable_counter_missing");
    } else if observations.commands.flowtable_exit_code == 0 && !facts.files.flowtable_counter {
        push_unique(&mut warnings, "flowtable_counter_missing");
    }
    if facts.files.nf_conntrack_acct_present && !facts.files.nf_conntrack_acct {
        push_unique(&mut warnings, "nf_conntrack_acct_disabled");
        push_unique(&mut warnings, "conntrack_acct_disabled");
    }
    if facts.nlbwmon {
        push_unique(&mut warnings, "nlbwmon_counter_conflict");
    }
    if facts.offload.hardware {
        push_unique(&mut warnings, "hardware_flow_offload_unsupported");
    }
    if facts.offload.software {
        push_unique(&mut warnings, "software_flow_offload_enabled");
    }
    if facts.offload.fullcone {
        push_unique(&mut warnings, "fullcone_detected");
        push_unique(&mut warnings, "fullcone_nat_enabled");
    }
    if facts.proxy.openclash {
        push_unique(&mut warnings, "openclash_detected");
    }
    if facts.proxy.openclash_fake_ip {
        push_unique(&mut warnings, "openclash_fake_ip_low_remote_confidence");
    }
    if facts.proxy.openclash_tun_mix {
        push_unique(&mut warnings, "openclash_tun_conntrack_low_confidence");
    }
    if !facts.proxy.openclash_dns_chain_complete {
        push_unique(&mut warnings, "openclash_dns_chain_incomplete");
    }
    if facts.proxy.openclash_router_self_proxy {
        push_unique(&mut warnings, "openclash_router_self_proxy_detected");
    }
    if facts.proxy.dae {
        push_unique(&mut warnings, "dae_detected");
    }
    if probe_error {
        push_unique(&mut warnings, "probe_error");
    }
    if lan_probe_error {
        push_unique(&mut warnings, "lan_topology_probe_error");
    }
    if !lan_edge {
        push_unique(&mut warnings, "lan_edge_missing");
    }
    if map_full {
        push_unique(&mut warnings, "map_full");
    }
    if config.enable_bpf && !safe_attach {
        push_unique(&mut warnings, "unsafe_attach");
    }
    if config.enable_bpf && safe_attach && !bpf_runtime {
        push_unique(&mut warnings, "bpf_runtime_loader_unavailable");
    }
    let mode = if !facts.tc.available {
        Mode::Unsupported
    } else if !bpf_runtime || probe_error || facts.offload.hardware {
        Mode::Degraded
    } else {
        Mode::Full
    };
    if mode != Mode::Full {
        push_unique(&mut warnings, "live_metrics_unavailable");
    }
    let confidence = if mode == Mode::Full {
        Confidence::High
    } else if probe_error || lan_probe_error {
        Confidence::Low
    } else if mode == Mode::Unsupported {
        Confidence::Unsupported
    } else {
        Confidence::Medium
    };
    let mut conflicts = Vec::new();
    if conflict {
        conflicts.push(conflict_item("tc_filter_conflict"));
    }
    if facts.nlbwmon {
        conflicts.push(conflict_item("nlbwmon_counter_conflict"));
    }
    if facts.offload.hardware {
        conflicts.push(conflict_item("hardware_flow_offload"));
    }
    if facts.offload.software {
        conflicts.push(conflict_item("software_flow_offload"));
    }
    if facts.offload.fullcone {
        conflicts.push(conflict_item("fullcone"));
    }
    if facts.sqm || facts.qosify || facts.files.ifb {
        conflicts.push(conflict_item("existing_qos"));
    }
    if facts.proxy.openclash || facts.proxy.dae || facts.homeproxy {
        conflicts.push(conflict_item("proxy_stack"));
    }
    let evidence = build_evidence(&observations, &facts, proxy_evidence, bpf_runtime);
    let capabilities = ProbeCapabilities {
        bpf: bpf_runtime,
        bpf_package: facts.bpf.package,
        bpf_object: facts.bpf.object,
        bpf_runtime_metrics: bpf_runtime,
        conntrack_fallback: false,
        live_metrics: bpf_runtime,
        fw4: facts.fw4,
        nft: facts.nft,
        software_flow_offload: facts.offload.software,
        hardware_flow_offload: facts.offload.hardware,
        fullcone: facts.offload.fullcone,
        nf_conntrack_acct: facts.files.nf_conntrack_acct,
        flowtable_counter: facts.files.flowtable_counter,
        tc: facts.tc.available,
        tc_clsact: facts.tc.clsact,
        existing_tc_filters: facts.tc.existing_filters,
        ifb: facts.files.ifb,
        sqm: facts.sqm,
        qosify: facts.qosify,
        openclash: facts.proxy.openclash,
        openclash_fake_ip: facts.proxy.openclash_fake_ip,
        openclash_tun_mix: facts.proxy.openclash_tun_mix,
        openclash_redirect_dns: facts.proxy.openclash_redirect_dns,
        openclash_dns_chain_complete: facts.proxy.openclash_dns_chain_complete,
        openclash_router_self_proxy: facts.proxy.openclash_router_self_proxy,
        openclash_udp_proxy: facts.proxy.openclash_udp_proxy,
        openclash_ipv6: facts.proxy.openclash_ipv6,
        dae: facts.proxy.dae,
        homeproxy: facts.homeproxy,
        lan_bridge: observations.files.lan_bridge,
        vlan: observations.files.vlan,
        wlan: observations.files.wlan,
        lan_edge,
        safe_attach,
        map_full,
    };
    ProbeReport {
        mode,
        confidence,
        capabilities,
        facts,
        warnings,
        conflicts,
        evidence,
    }
}

fn build_evidence(
    o: &ProbeObservations,
    facts: &ProbeFacts,
    proxy: ProxyEvidence,
    bpf_runtime: bool,
) -> ProbeEvidence {
    let command = [
        ("fw4", o.commands.fw4),
        ("nft", o.commands.nft),
        ("tc", o.commands.tc),
        ("ubus", o.commands.ubus),
        ("qosify", o.commands.qosify),
    ]
    .into_iter()
    .map(|(name, available)| CommandEvidence {
        source: format!("command:{name}"),
        available,
        exit_code: None,
        supported: None,
    })
    .chain([
        CommandEvidence {
            source: "command:tc_filter_help".into(),
            available: o.commands.tc,
            exit_code: Some(o.commands.tc_filter_help_exit_code),
            supported: Some(o.tc.bpf),
        },
        CommandEvidence {
            source: "command:tc_qdisc_help".into(),
            available: o.commands.tc,
            exit_code: Some(o.commands.tc_qdisc_help_exit_code),
            supported: Some(o.tc.clsact),
        },
        CommandEvidence {
            source: "command:nft_list_flowtables".into(),
            available: o.commands.nft,
            exit_code: Some(o.commands.flowtable_exit_code),
            supported: Some(facts.files.flowtable_counter),
        },
    ])
    .collect();
    let file = [
        (
            "/proc/sys/net/netfilter/nf_conntrack_acct",
            o.files.nf_conntrack_acct_present,
            o.files.nf_conntrack_acct_value.clone(),
        ),
        ("/proc/net/nf_flowtable", o.files.flowtable_proc, None),
        (
            "/sys/kernel/debug/netfilter/nf_flowtable",
            o.files.flowtable_debug,
            None,
        ),
        ("/sys/class/net/ifb0", o.files.ifb, None),
        ("any_configured_device/bridge", o.files.lan_bridge, None),
        ("/proc/net/vlan/config", o.files.vlan, None),
        ("/sys/class/ieee80211", o.files.wlan, None),
        (
            "/usr/share/lanspeed/bpf/collector-model.json",
            o.bpf.package,
            None,
        ),
        ("/usr/lib/bpf/lanspeed_tc.o", o.bpf.object, None),
    ]
    .into_iter()
    .map(|(path, present, value)| FileEvidence {
        source: format!("file:{path}"),
        path: path.into(),
        present,
        value,
    })
    .collect();
    let uci = [
        ("firewall", o.uci.firewall_loaded),
        ("sqm", o.uci.sqm),
        ("qosify", o.uci.qosify),
        ("openclash", o.uci.openclash),
        ("dae", o.uci.dae),
        ("daed", o.uci.daed),
        ("homeproxy", o.uci.homeproxy),
        ("nlbwmon", o.uci.nlbwmon),
    ]
    .into_iter()
    .map(|(package, loaded)| UciEvidence {
        source: format!("uci:{package}"),
        package: package.into(),
        loaded,
    })
    .collect();
    let ubus = vec![UbusEvidence {
        source: "ubus:network.interface.lan".into(),
        object: "network.interface.lan".into(),
        attempted: o.ubus.network_lan_attempted,
        exit_code: o.ubus.network_lan_exit_code,
    }];
    ProbeEvidence {
        source: "lanspeedd_runtime_probe",
        method: "health",
        read_only: true,
        command,
        file,
        uci,
        ubus,
        tc: TcEvidence {
            filters: facts.tc.filters.clone(),
            conflict: facts.tc.conflict,
            dae_preempts_bpf_ingress: facts.tc.dae_preempts_lan_ingress,
        },
        proxy,
        offload: OffloadEvidence {
            software: facts.offload.software,
            hardware: facts.offload.hardware,
            fullcone: facts.offload.fullcone,
        },
        nss: NssEvidence {
            present: facts.nss.present,
            ecm_active: facts.nss.ecm_active,
            ppe_active: facts.nss.ppe_active,
            direct_state_present: facts.nss.direct_state_present,
            direct_state_readable: facts.nss.direct_state_readable,
        },
        bpf: BpfEvidence {
            package_present: facts.bpf.package,
            object_present: facts.bpf.object,
            runtime_attach_map_read_success: bpf_runtime,
            map_full_observed: facts.bpf.map_full_observed,
        },
    }
}

pub(crate) fn push_unique(values: &mut Vec<&'static str>, value: &'static str) {
    if !values.contains(&value) {
        values.push(value);
    }
}
fn conflict_item(id: &'static str) -> Conflict {
    match id {
    "hardware_flow_offload" => Conflict { id, severity: "warning", message: "Hardware flow offload hides traffic from CPU-visible collectors." },
    "software_flow_offload" => Conflict { id, severity: "info", message: "Software flow offload may reduce counter confidence for some flows." },
    "fullcone" => Conflict { id, severity: "info", message: "Fullcone NAT is present and should be considered when interpreting flow ownership." },
    "existing_qos" => Conflict { id, severity: "warning", message: "Existing QoS/IFB components may already own tc hooks." },
    "proxy_stack" => Conflict { id, severity: "info", message: "Local proxy stacks can alter LAN/WAN flow paths." },
    "nlbwmon_counter_conflict" => Conflict { id, severity: "warning", message: "nlbwmon may use zero-on-read counters; lanspeedd does not read or disturb nlbwmon counters." },
    "tc_filter_conflict" => Conflict { id, severity: "warning", message: "An existing tc filter already uses lanspeed pref/handle; lanspeedd will not overwrite it." },
    _ => unreachable!(),
}
}
