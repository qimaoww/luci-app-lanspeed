use crate::{
    collectors::conntrack::CollectedSnapshot,
    connections::{conntrack_source, has_counted_connections, CONNECTION_ONLY_WARNING},
    identity::IdentityTable,
    model::{Client, ClientsResponse},
    platform::confidence,
    platform::x86::snapshot::BpfClientSample,
    probe::Confidence as ProbeConfidence,
    state::CONNECTION_SEMANTICS,
};

pub(crate) fn clients_response(
    bpf: Option<&[BpfClientSample]>,
    conntrack: Option<&CollectedSnapshot>,
    identities: &IdentityTable,
    client_confidence: ProbeConfidence,
) -> ClientsResponse {
    let bpf_available = bpf.is_some();
    let mut clients = if let Some(bpf) = bpf {
        bpf.iter()
            .map(|sample| Client {
                mac: sample.mac.clone(),
                identity_key: sample.identity_key.clone(),
                zone: sample.zone.clone(),
                interface: sample.interface.clone(),
                ips: sample.ips.clone(),
                hostname: identities
                    .by_mac_zone(&sample.mac, &sample.zone)
                    .and_then(|identity| identity.hostname.clone()),
                rx_bps: sample.rx_bps,
                tx_bps: sample.tx_bps,
                last_seen: sample.last_seen_ms,
                sample_ms: Some(sample.sample_ms),
                rx_bytes: Some(sample.rx_bytes),
                tx_bytes: Some(sample.tx_bytes),
                collector_mode: "bpf".into(),
                confidence: confidence(client_confidence),
                warnings: vec![],
                tcp_conns: sample.tcp_conns.map(u64::from),
                udp_conns: sample.udp_conns.map(u64::from),
                udp_dns_conns: sample.udp_dns_conns.map(u64::from),
                udp_other_conns: sample.udp_other_conns.map(u64::from),
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if let Some(snapshot) = conntrack {
        for sample in &snapshot.clients {
            if !has_counted_connections(sample)
                || clients
                    .iter()
                    .any(|client| client.identity_key == sample.identity_key)
            {
                continue;
            }
            let mut warnings = vec![CONNECTION_ONLY_WARNING.to_owned()];
            if !bpf_available {
                warnings.push("conntrack_routed_nat_only".into());
            }
            clients.push(Client {
                mac: sample.mac.clone(),
                identity_key: sample.identity_key.clone(),
                zone: sample.zone.clone(),
                interface: sample.interface.clone(),
                ips: sample.ips.clone(),
                hostname: identities
                    .by_mac_zone(&sample.mac, &sample.zone)
                    .and_then(|identity| identity.hostname.clone()),
                rx_bps: 0,
                tx_bps: 0,
                last_seen: sample.last_seen_ms,
                sample_ms: Some(sample.last_seen_ms),
                rx_bytes: None,
                tx_bytes: None,
                collector_mode: conntrack_source(snapshot).into(),
                confidence: confidence(client_confidence),
                warnings,
                tcp_conns: Some(u64::from(sample.tcp_conns)),
                udp_conns: Some(u64::from(sample.udp_conns)),
                udp_dns_conns: Some(u64::from(sample.udp_dns_conns)),
                udp_other_conns: Some(u64::from(sample.udp_other_conns)),
            });
        }
    }
    clients.sort_by(|left, right| left.identity_key.cmp(&right.identity_key));
    let totals = clients
        .iter()
        .fold((0u64, 0u64, 0u64, 0u64), |totals, client| {
            (
                totals.0.saturating_add(client.tcp_conns.unwrap_or(0)),
                totals.1.saturating_add(client.udp_conns.unwrap_or(0)),
                totals.2.saturating_add(client.udp_dns_conns.unwrap_or(0)),
                totals.3.saturating_add(client.udp_other_conns.unwrap_or(0)),
            )
        });
    ClientsResponse {
        clients,
        evidence: None,
        tcp_conns_total: Some(totals.0),
        udp_conns_total: Some(totals.1),
        udp_dns_conns_total: Some(totals.2),
        udp_other_conns_total: Some(totals.3),
        conntrack_entries_seen: conntrack.map(|value| value.stats.entries_seen as u64),
        conntrack_entries_matched: conntrack.map(|value| value.stats.entries_matched as u64),
        conntrack_parse_errors: conntrack.map(|value| value.stats.malformed_lines as u64),
        conn_source: conntrack.map(|value| {
            if value.stats.netlink_read {
                "conntrack_netlink"
            } else {
                "conntrack_procfs"
            }
            .into()
        }),
        nss_ecm_nodes_seen: None,
        nss_ecm_nodes_matched: None,
        nss_ecm_node_parse_errors: None,
        conn_collector_mode: None,
        conn_semantics: Some(CONNECTION_SEMANTICS.into()),
    }
}
