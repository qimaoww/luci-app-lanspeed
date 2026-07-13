use super::{
    DaeEvidence, OpenClashEvidence, ProxyEvidence, ProxyFacts, ProxyObservation, TcFilter,
};

pub const DAE_FWMARK: &str = "0x8000000";
pub const DAE_ROUTE_TABLE: &str = "2023";

pub fn evaluate(
    observation: &ProxyObservation,
    uci_dae: bool,
    uci_daed: bool,
    filters: &[TcFilter],
) -> (ProxyFacts, ProxyEvidence) {
    let en_mode = observation
        .openclash_en_mode
        .as_deref()
        .unwrap_or("unknown");
    let stack_type = observation
        .openclash_stack_type
        .as_deref()
        .unwrap_or("unknown");
    let fake_ip = observation.openclash_installed
        && (en_mode.contains("fake-ip") || en_mode.contains("fake_ip"));
    let lower_mode = en_mode.to_ascii_lowercase();
    let lower_stack = stack_type.to_ascii_lowercase();
    let tun_mix = observation.openclash_installed
        && (lower_mode.contains("tun")
            || lower_mode.contains("mix")
            || lower_stack.contains("tun")
            || lower_stack.contains("mix"));
    let dae_filter = filters.iter().any(|filter| filter.owner == "dae");
    let dae = uci_dae
        || uci_daed
        || observation.dae_service
        || observation.daed_service
        || observation.dae_running
        || observation.daed_running
        || observation.dae_process
        || observation.daed_process
        || observation.dae_iface
        || observation.dae_peer_iface
        || observation.dae_fwmark
        || observation.dae_route_table
        || observation.dae_dns_udp53
        || dae_filter;
    let runtime_active = observation.dae_process || observation.daed_process;
    let facts = ProxyFacts {
        openclash: observation.openclash_installed,
        openclash_fake_ip: fake_ip,
        openclash_tun_mix: tun_mix,
        openclash_redirect_dns: observation.openclash_installed
            && observation.openclash_redirect_dns,
        openclash_dns_chain_complete: !observation.openclash_installed
            || !observation.openclash_redirect_dns
            || observation.openclash_dnsmasq_chain,
        openclash_router_self_proxy: observation.openclash_installed
            && observation.openclash_router_self_proxy,
        openclash_udp_proxy: observation.openclash_installed && observation.openclash_udp_proxy,
        openclash_ipv6: observation.openclash_installed && observation.openclash_ipv6,
        dae,
        dae_running: observation.dae_running,
        daed_running: observation.daed_running,
        dae_process: observation.dae_process,
        daed_process: observation.daed_process,
        runtime_active,
    };
    let evidence = ProxyEvidence {
        openclash: OpenClashEvidence {
            installed: facts.openclash,
            en_mode: en_mode.into(),
            fake_ip,
            tun_mix,
            enable_redirect_dns: facts.openclash_redirect_dns,
            dnsmasq_to_127_0_0_1_7874: observation.openclash_installed && observation.openclash_dnsmasq_chain,
            dns_chain_complete: facts.openclash_dns_chain_complete,
            router_self_proxy: facts.openclash_router_self_proxy,
            enable_udp_proxy: facts.openclash_udp_proxy,
            stack_type: stack_type.into(),
            ipv6_enable: facts.openclash_ipv6,
            remote_identity_policy: "fake-ip and proxy remote addresses are metadata only, never LAN client identity",
            primary_bpf_policy: "do_not_disable_lan_edge_bpf_when_openclash_is_present",
            router_self_bucket: "router_self",
        },
        dae: DaeEvidence {
            installed: dae,
            dae_config: uci_dae,
            daed_config: uci_daed,
            dae_service: observation.dae_service,
            daed_service: observation.daed_service,
            dae_running: observation.dae_running,
            daed_running: observation.daed_running,
            dae_process: observation.dae_process,
            daed_process: observation.daed_process,
            runtime_active,
            process_probe_error: None,
            dae0: observation.dae_iface,
            dae0peer: observation.dae_peer_iface,
            tc_filters: filters.iter().filter(|filter| filter.owner == "dae").cloned().collect(),
            fwmark: DAE_FWMARK,
            fwmark_detected: observation.dae_fwmark,
            route_table: DAE_ROUTE_TABLE,
            route_table_detected: observation.dae_route_table,
            dns_udp53_detected: observation.dae_dns_udp53,
            uplink_evidence_policy: "TUN/PPP/WG/dae interfaces are proxy/uplink evidence only, never LAN client identity sources",
            identity_policy: "dae0 and dae0peer MAC/IP observations are excluded from LAN clients",
        },
    };
    (facts, evidence)
}
