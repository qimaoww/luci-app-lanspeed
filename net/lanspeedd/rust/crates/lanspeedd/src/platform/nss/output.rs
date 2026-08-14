use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::{
    collectors::conntrack::CollectedSnapshot,
    connections::{conntrack_source, has_counted_connections, CONNECTION_ONLY_WARNING},
    identity::IdentityTable,
    model::{
        Client, ClientsResponse, Coverage, InterfaceRole, InterfaceStatus, InterfacesResponse,
    },
    platform::{
        confidence,
        counters::TrafficCounters,
        nss::{
            ecm_bpf::EcmBpfSnapshot,
            ecm_node,
            fusion::{
                fused_client_rate, EcmBpfClientRate, EcmBpfCoverageMerge,
                ECM_BPF_COVERAGE_CLOCK_SKEW_MS,
            },
            tc_snapshot::NssTcSnapshot,
            window::{
                CoverageWindow, EcmBpfRateBatch, RateWindowInterfaceCounter, RateWindowValue,
                WindowOutput, WindowQuality, ECM_BPF_HIGH_RATE_CONFIRMATION_MS,
            },
        },
    },
    probe::{Confidence as ProbeConfidence, ProbeReport},
    state::CONNECTION_SEMANTICS,
};

use super::COLLECTION_INTERVAL_MS;

const NSS_RATE_COVERAGE_MIN_BYTES: u64 = 128 * 1024;

pub(crate) fn ecm_bpf_clients_response(
    ecm_snapshot: Option<&EcmBpfSnapshot>,
    bpf_snapshot: Option<&NssTcSnapshot>,
    bpf_fresh: bool,
    batch_ms: u64,
    conntrack: Option<&CollectedSnapshot>,
    identities: &IdentityTable,
    client_confidence: ProbeConfidence,
) -> ClientsResponse {
    let rate_available = ecm_snapshot.is_some() || bpf_snapshot.is_some();
    let samples = ecm_snapshot
        .map(|snapshot| snapshot.clients.as_slice())
        .unwrap_or_default();
    let bpf_samples = bpf_snapshot
        .map(|snapshot| snapshot.clients.as_slice())
        .unwrap_or_default();
    let connection_counts = conntrack
        .into_iter()
        .flat_map(|snapshot| snapshot.clients.iter())
        .map(|sample| (sample.identity_key.as_str(), sample))
        .collect::<BTreeMap<_, _>>();
    let mut clients = samples
        .iter()
        .map(|sample| {
            let counts = connection_counts.get(sample.identity_key.as_str()).copied();
            let fused =
                fused_client_rate(&sample.identity_key, ecm_snapshot, bpf_snapshot, bpf_fresh)
                    .unwrap_or(EcmBpfClientRate {
                        tx_bps: sample.tx_bps,
                        rx_bps: sample.rx_bps,
                        tx_bytes: sample.tx_bytes,
                        rx_bytes: sample.rx_bytes,
                        last_seen_ms: sample.last_seen_ms,
                    });
            Client {
                mac: sample.mac.clone(),
                identity_key: sample.identity_key.clone(),
                zone: sample.zone.clone(),
                interface: sample.interface.clone(),
                ips: sample.ips.clone(),
                hostname: identities
                    .by_mac_zone(&sample.mac, &sample.zone)
                    .and_then(|identity| identity.hostname.clone()),
                rx_bps: fused.rx_bps,
                tx_bps: fused.tx_bps,
                last_seen: fused.last_seen_ms,
                sample_ms: Some(batch_ms),
                rx_bytes: Some(fused.rx_bytes),
                tx_bytes: Some(fused.tx_bytes),
                collector_mode: "nss_ecm_bpf".into(),
                confidence: confidence(client_confidence),
                warnings: vec![],
                tcp_conns: counts.map(|sample| u64::from(sample.tcp_conns)),
                udp_conns: counts.map(|sample| u64::from(sample.udp_conns)),
                udp_dns_conns: counts.map(|sample| u64::from(sample.udp_dns_conns)),
                udp_other_conns: counts.map(|sample| u64::from(sample.udp_other_conns)),
                rate_meta: None,
                control: None,
            }
        })
        .collect::<Vec<_>>();
    for sample in bpf_samples {
        if let Some(client) = clients
            .iter_mut()
            .find(|client| client.identity_key == sample.identity_key)
        {
            if let Some(fused) =
                fused_client_rate(&sample.identity_key, ecm_snapshot, bpf_snapshot, bpf_fresh)
            {
                client.tx_bps = fused.tx_bps;
                client.rx_bps = fused.rx_bps;
                client.tx_bytes = Some(fused.tx_bytes);
                client.rx_bytes = Some(fused.rx_bytes);
                client.last_seen = fused.last_seen_ms;
            }
            client.sample_ms = Some(batch_ms);
            continue;
        }
        let counts = connection_counts.get(sample.identity_key.as_str()).copied();
        let fused = fused_client_rate(&sample.identity_key, ecm_snapshot, bpf_snapshot, bpf_fresh)
            .unwrap_or(EcmBpfClientRate {
                tx_bps: sample.tx_bps,
                rx_bps: sample.rx_bps,
                tx_bytes: sample.tx_bytes,
                rx_bytes: sample.rx_bytes,
                last_seen_ms: sample.last_seen_ms,
            });
        clients.push(Client {
            mac: sample.mac.clone(),
            identity_key: sample.identity_key.clone(),
            zone: sample.zone.clone(),
            interface: sample.interface.clone(),
            ips: sample.ips.clone(),
            hostname: identities
                .by_mac_zone(&sample.mac, &sample.zone)
                .and_then(|identity| identity.hostname.clone()),
            rx_bps: fused.rx_bps,
            tx_bps: fused.tx_bps,
            last_seen: fused.last_seen_ms,
            sample_ms: Some(batch_ms),
            rx_bytes: Some(fused.rx_bytes),
            tx_bytes: Some(fused.tx_bytes),
            collector_mode: "nss_ecm_bpf".into(),
            confidence: confidence(client_confidence),
            warnings: vec![],
            tcp_conns: counts.map(|sample| u64::from(sample.tcp_conns)),
            udp_conns: counts.map(|sample| u64::from(sample.udp_conns)),
            udp_dns_conns: counts.map(|sample| u64::from(sample.udp_dns_conns)),
            udp_other_conns: counts.map(|sample| u64::from(sample.udp_other_conns)),
            rate_meta: None,
            control: None,
        });
    }
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
            if !rate_available {
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
                rate_meta: None,
                control: None,
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

pub(crate) fn window_clients(
    window: &WindowOutput,
    identities: &IdentityTable,
    conntrack: Option<&CollectedSnapshot>,
    client_confidence: ProbeConfidence,
    _report: &ProbeReport,
) -> ClientsResponse {
    let connection_counts = conntrack
        .into_iter()
        .flat_map(|snapshot| snapshot.clients.iter())
        .map(|sample| (sample.identity_key.as_str(), sample))
        .collect::<BTreeMap<_, _>>();
    let warning = (!matches!(
        window.quality,
        WindowQuality::Ok
            | WindowQuality::Idle
            | WindowQuality::LowTraffic
            | WindowQuality::Pending
    ))
    .then(|| window.quality.as_str().to_owned());
    let clients = window
        .clients
        .iter()
        .filter_map(|rate| {
            let identity = identities
                .iter()
                .find(|identity| identity.key.to_string() == rate.identity_key)?;
            let counts = connection_counts.get(rate.identity_key.as_str()).copied();
            Some(Client {
                mac: identity.key.mac.to_string(),
                identity_key: rate.identity_key.clone(),
                zone: identity.key.zone.clone(),
                interface: identity.interface.clone(),
                ips: identity.ips.clone(),
                hostname: identity.hostname.clone(),
                rx_bps: rate.rx_bps,
                tx_bps: rate.tx_bps,
                last_seen: identity.last_seen,
                sample_ms: Some(window.end_ms),
                rx_bytes: Some(rate.total.rx_bytes),
                tx_bytes: Some(rate.total.tx_bytes),
                collector_mode: "nss_ecm_node".into(),
                confidence: confidence(client_confidence),
                warnings: warning.iter().cloned().collect(),
                tcp_conns: counts.map(|sample| u64::from(sample.tcp_conns)),
                udp_conns: counts.map(|sample| u64::from(sample.udp_conns)),
                udp_dns_conns: counts.map(|sample| u64::from(sample.udp_dns_conns)),
                udp_other_conns: counts.map(|sample| u64::from(sample.udp_other_conns)),
                rate_meta: None,
                control: None,
            })
        })
        .collect::<Vec<_>>();
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
        conntrack_entries_seen: None,
        conntrack_entries_matched: None,
        conntrack_parse_errors: None,
        conn_source: conntrack.map(|snapshot| conntrack_source(snapshot).into()),
        nss_ecm_nodes_seen: None,
        nss_ecm_nodes_matched: None,
        nss_ecm_node_parse_errors: None,
        conn_collector_mode: None,
        conn_semantics: Some(CONNECTION_SEMANTICS.into()),
    }
}

#[cfg(test)]
pub(crate) fn coverage_response(coverage: &CoverageWindow) -> Coverage {
    let waiting_for_aligned_batch = !coverage.aligned
        && matches!(
            (coverage.quality, coverage.reason),
            (WindowQuality::CounterSkew, "lan_coverage_timeout")
                | (WindowQuality::LowTraffic, "low_traffic_coverage_rebaseline")
        );
    let public_quality = if waiting_for_aligned_batch {
        WindowQuality::Pending
    } else {
        coverage.quality
    };
    let aligned = coverage.aligned
        && matches!(
            public_quality,
            WindowQuality::Ok | WindowQuality::Idle | WindowQuality::LowTraffic
        );
    let current = aligned
        || (matches!(
            public_quality,
            WindowQuality::Pending | WindowQuality::CounterSkew
        ) && (coverage.tx_pct.is_some() || coverage.rx_pct.is_some()));
    let retained = !current
        && matches!(
            public_quality,
            WindowQuality::Pending | WindowQuality::CounterSkew
        )
        && (coverage.retained_tx_pct.is_some() || coverage.retained_rx_pct.is_some());
    Coverage {
        quality: public_quality.as_str().into(),
        samples: u64::from(current || retained),
        window_ms: Some(coverage.window_ms()),
        tx_pct: if current {
            coverage.tx_pct
        } else if retained {
            coverage.retained_tx_pct
        } else {
            None
        },
        rx_pct: if current {
            coverage.rx_pct
        } else if retained {
            coverage.retained_rx_pct
        } else {
            None
        },
        denom_rx_bytes: Some(coverage.lan_normalized.rx_bytes),
        denom_tx_bytes: Some(coverage.lan_normalized.tx_bytes),
        numer_rx_bytes: Some(coverage.client_normalized.rx_bytes),
        numer_tx_bytes: Some(coverage.client_normalized.tx_bytes),
    }
}

pub(crate) fn rate_window_interface_counters(
    interfaces: &InterfacesResponse,
) -> BTreeMap<String, RateWindowInterfaceCounter> {
    interfaces
        .interfaces
        .iter()
        .filter_map(|interface| {
            if interface.status != InterfaceStatus::Available {
                return None;
            }
            Some((
                interface.name.clone(),
                RateWindowInterfaceCounter {
                    rx_bytes: interface.rx_bytes?,
                    tx_bytes: interface.tx_bytes?,
                },
            ))
        })
        .collect()
}

pub(crate) fn apply_ecm_bpf_rate_batch(
    clients: &mut ClientsResponse,
    interfaces: &mut InterfacesResponse,
    batch: &EcmBpfRateBatch,
) {
    for client in &mut clients.clients {
        let rate = batch
            .clients
            .get(&client.identity_key)
            .copied()
            .unwrap_or_default();
        client.rx_bps = rate.rx_bps;
        client.tx_bps = rate.tx_bps;
        client.sample_ms = Some(batch.end_ms);
    }
    let client_rates_by_interface = clients.clients.iter().fold(
        BTreeMap::<String, RateWindowValue>::new(),
        |mut rates, client| {
            let rate = rates.entry(client.interface.clone()).or_default();
            rate.rx_bps = rate.rx_bps.saturating_add(client.rx_bps);
            rate.tx_bps = rate.tx_bps.saturating_add(client.tx_bps);
            rates
        },
    );
    for interface in &mut interfaces.interfaces {
        if interface.status != InterfaceStatus::Available {
            continue;
        }
        let Some(rate) = batch.interfaces.get(&interface.name) else {
            continue;
        };
        let mut rx_bps = rate.rx_bps;
        let mut tx_bps = rate.tx_bps;
        if !batch.low_rate && interface.role == InterfaceRole::Lan {
            if let Some(client_rate) = client_rates_by_interface.get(&interface.name) {
                let lifted_rx = rx_bps.max(client_rate.tx_bps);
                let lifted_tx = tx_bps.max(client_rate.rx_bps);
                if lifted_rx != rx_bps || lifted_tx != tx_bps {
                    interface.source = Some(format!(
                        "{} + ECM+BPF high-rate client floor",
                        interface
                            .source
                            .as_deref()
                            .unwrap_or("kernel net-device counters")
                    ));
                }
                rx_bps = lifted_rx;
                tx_bps = lifted_tx;
            }
        }
        interface.rx_bps = Some(rx_bps);
        interface.tx_bps = Some(tx_bps);
        interface.delta_ms = Some(batch.window_ms());
        interface.sample_ms = Some(batch.end_ms);
    }
    interfaces.monotonic_ms = Some(batch.end_ms);
}

pub(crate) fn nss_rate_coverage(
    clients: &ClientsResponse,
    interfaces: &InterfacesResponse,
    sample_skew_ms: u64,
) -> Coverage {
    let sample_ms = interfaces.monotonic_ms;
    let client_clocks_aligned = clients
        .clients
        .iter()
        .all(|client| sample_clock_within(client.sample_ms, sample_ms, sample_skew_ms));
    let mut lan_rx_bps = 0u64;
    let mut lan_tx_bps = 0u64;
    let mut window_ms = None;
    let mut lan_boundaries = 0usize;
    for interface in &interfaces.interfaces {
        if interface.role != InterfaceRole::Lan || interface.status != InterfaceStatus::Available {
            continue;
        }
        let (Some(rx_bps), Some(tx_bps), Some(delta_ms)) =
            (interface.rx_bps, interface.tx_bps, interface.delta_ms)
        else {
            continue;
        };
        if delta_ms == 0
            || !sample_clock_within(interface.sample_ms, sample_ms, sample_skew_ms)
            || window_ms.is_some_and(|current| current != delta_ms)
        {
            return empty_nss_rate_coverage("warmup");
        }
        lan_rx_bps = lan_rx_bps.saturating_add(rx_bps);
        lan_tx_bps = lan_tx_bps.saturating_add(tx_bps);
        window_ms = Some(delta_ms);
        lan_boundaries += 1;
    }
    let (Some(window_ms), true) = (window_ms, client_clocks_aligned && lan_boundaries != 0) else {
        return empty_nss_rate_coverage("warmup");
    };
    let (client_tx_bps, client_rx_bps) =
        clients
            .clients
            .iter()
            .fold((0u64, 0u64), |(tx_total, rx_total), client| {
                (
                    tx_total.saturating_add(client.tx_bps),
                    rx_total.saturating_add(client.rx_bps),
                )
            });
    nss_rate_coverage_values(
        window_ms,
        client_tx_bps,
        client_rx_bps,
        lan_rx_bps,
        lan_tx_bps,
    )
}

fn sample_clock_within(sample_ms: Option<u64>, anchor_ms: Option<u64>, max_skew_ms: u64) -> bool {
    match (sample_ms, anchor_ms) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(sample), Some(anchor)) => sample.abs_diff(anchor) <= max_skew_ms,
    }
}

pub(crate) fn nss_rate_coverage_values(
    window_ms: u64,
    client_tx_bps: u64,
    client_rx_bps: u64,
    lan_rx_bps: u64,
    lan_tx_bps: u64,
) -> Coverage {
    let denom_rx_bytes = rate_equivalent_bytes(lan_rx_bps, window_ms);
    let denom_tx_bytes = rate_equivalent_bytes(lan_tx_bps, window_ms);
    let numer_rx_bytes = rate_equivalent_bytes(client_rx_bps, window_ms);
    let numer_tx_bytes = rate_equivalent_bytes(client_tx_bps, window_ms);
    let tx_pct = percentage(client_tx_bps, lan_rx_bps);
    let rx_pct = percentage(client_rx_bps, lan_tx_bps);
    let denominator = denom_rx_bytes.saturating_add(denom_tx_bytes);
    let client_ahead = client_tx_bps > lan_rx_bps || client_rx_bps > lan_tx_bps;
    let quality = if denominator == 0 {
        if client_tx_bps == 0 && client_rx_bps == 0 {
            "idle"
        } else {
            "pending"
        }
    } else if client_ahead {
        "pending"
    } else if denominator < NSS_RATE_COVERAGE_MIN_BYTES {
        "low_traffic"
    } else {
        "ok"
    };
    Coverage {
        quality: quality.into(),
        samples: 1,
        window_ms: Some(window_ms),
        tx_pct,
        rx_pct,
        denom_rx_bytes: Some(denom_rx_bytes),
        denom_tx_bytes: Some(denom_tx_bytes),
        numer_rx_bytes: Some(numer_rx_bytes),
        numer_tx_bytes: Some(numer_tx_bytes),
    }
}

fn empty_nss_rate_coverage(quality: &str) -> Coverage {
    Coverage {
        quality: quality.into(),
        samples: 0,
        window_ms: Some(0),
        tx_pct: None,
        rx_pct: None,
        denom_rx_bytes: Some(0),
        denom_tx_bytes: Some(0),
        numer_rx_bytes: Some(0),
        numer_tx_bytes: Some(0),
    }
}

fn rate_equivalent_bytes(bps: u64, window_ms: u64) -> u64 {
    let bytes = u128::from(bps).saturating_mul(u128::from(window_ms)) / 8_000;
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

fn percentage(numerator: u64, denominator: u64) -> Option<u8> {
    if denominator == 0 || numerator > denominator {
        return None;
    }
    let value = u128::from(numerator).saturating_mul(100) / u128::from(denominator);
    u8::try_from(value).ok()
}

pub(crate) fn coverage_evidence(coverage: &CoverageWindow, source: &str) -> Value {
    json!({
        "source": source,
        "rate_and_coverage_decoupled": true,
        "fcs_bytes_per_packet": 4,
        "raw": {
            "client": traffic_evidence(coverage.client_raw),
            "lan": traffic_evidence(coverage.lan_raw),
        },
        "fcs_normalized": {
            "client": traffic_evidence(coverage.client_normalized),
            "lan": traffic_evidence(coverage.lan_normalized),
        },
        "directions": {
            "tx": {
                "client_bytes": coverage.client_normalized.tx_bytes,
                "client_packets": coverage.client_normalized.tx_packets,
                "lan_bytes": coverage.lan_normalized.rx_bytes,
                "lan_packets": coverage.lan_normalized.rx_packets,
            },
            "rx": {
                "client_bytes": coverage.client_normalized.rx_bytes,
                "client_packets": coverage.client_normalized.rx_packets,
                "lan_bytes": coverage.lan_normalized.tx_bytes,
                "lan_packets": coverage.lan_normalized.tx_packets,
            },
        },
        "coverage": {
            "state": coverage.quality.as_str(),
            "reason": coverage.reason,
            "window_start_ms": coverage.start_ms,
            "window_end_ms": coverage.end_ms,
            "window_ms": coverage.window_ms(),
            "aligned": coverage.aligned,
            "tx_pct": coverage.tx_pct,
            "rx_pct": coverage.rx_pct,
            "retained_tx_pct": coverage.retained_tx_pct,
            "retained_rx_pct": coverage.retained_rx_pct,
        },
    })
}

pub(crate) fn ecm_bpf_rate_batch_evidence(batch: &EcmBpfRateBatch) -> Value {
    json!({
        "source": "shared_client_interface_rate_window",
        "window_start_ms": batch.start_ms,
        "window_end_ms": batch.end_ms,
        "window_ms": batch.window_ms(),
        "fresh": batch.fresh,
        "held_age_ms": batch.held_age_ms,
        "client_count": batch.clients.len(),
        "interface_count": batch.interfaces.len(),
        "raw_aligned": batch.raw_aligned,
        "fallback_event_gap_filled": batch.fallback_event_gap_filled,
        "previous_direction_gap_filled": batch.previous_direction_gap_filled,
        "previous_high_direction_gap_filled": batch.previous_high_direction_gap_filled,
        "fallback_lan_reconciled": batch.fallback_lan_reconciled,
        "low_rate_rolling": batch.low_rate,
        "high_rate_interface_floor": !batch.low_rate,
        "high_rate_quiet_confirmation_ms": ECM_BPF_HIGH_RATE_CONFIRMATION_MS,
        "high_rate_lan_guard": "valid_physical_lan_budget_directional_reconciliation",
        "high_rate_interface_guard": "identity_to_discovered_interface_directional_budget",
        "client_rate_source": if batch.previous_high_direction_gap_filled && batch.fallback_event_gap_filled {
            "event_clock_and_previous_complete_high_direction_current_lan_replacement_no_sum"
        } else if batch.previous_high_direction_gap_filled {
            "previous_complete_high_direction_current_lan_replacement_no_sum"
        } else if batch.previous_direction_gap_filled && batch.fallback_event_gap_filled {
            "event_clock_and_previous_complete_direction_gap_repair_no_sum"
        } else if batch.previous_direction_gap_filled {
            "previous_complete_low_direction_gap_repair_with_current_lan_budget"
        } else if batch.raw_aligned && batch.fallback_event_gap_filled {
            "aligned_raw_deltas_with_event_clock_nss_sync_gap_repair"
        } else if batch.raw_aligned {
            "aligned_ecm_nss_hardware_plus_tc_slow_path_raw_deltas"
        } else if batch.low_rate {
            "shared_raw_deltas_with_event_gap_fill_and_lan_reconciliation"
        } else {
            "event_clock_preferred_raw_when_event_missing_high_rate_with_interface_floor"
        },
        "fallback_aggregation": "raw_delta_preferred_event_gap_elapsed_ms_weighted_mean",
        "previous_direction_policy": "one_complete_adjacent_batch_directional_replacement_current_lan_budget_no_sum_no_chain",
        "fallback_priority": if batch.low_rate {
            "raw_delta_first_event_gap_uses_remaining_lan_budget"
        } else {
            "event_clock_first_raw_only_when_event_missing_or_implausible_no_sum"
        },
        "publish_policy": "high_rate_event_clock_valid_lan_budget_and_10s_quiet_confirmation_then_2s_18s_low_rate_rolling",
        "client_interface_sample_clock": "shared",
    })
}

pub(crate) fn window_evidence(window: &WindowOutput) -> Value {
    let coverage = &window.coverage;
    json!({
        "state": window.quality.as_str(),
        "reason": window.reason,
        "source": ecm_node::SOURCE,
        "window_start_ms": window.start_ms,
        "window_end_ms": window.end_ms,
        "window_ms": window.window_ms(),
        "collector_min_interval_ms": COLLECTION_INTERVAL_MS,
        "rate_filter": "per_node_generation_median_last_3_windows",
        "fresh_rate_sample": window.fresh_rate_sample,
        "held_rate_age_ms": window.held_rate_age_ms,
        "rate_and_coverage_decoupled": true,
        "aligned_snapshot_retained": coverage.aligned,
        "fcs_bytes_per_packet": 4,
        "raw": {
            "client": traffic_evidence(coverage.client_raw),
            "lan": traffic_evidence(coverage.lan_raw),
        },
        "fcs_normalized": {
            "client": traffic_evidence(coverage.client_normalized),
            "lan": traffic_evidence(coverage.lan_normalized),
        },
        "directions": {
            "tx": {
                "client_bytes": coverage.client_normalized.tx_bytes,
                "client_packets": coverage.client_normalized.tx_packets,
                "lan_bytes": coverage.lan_normalized.rx_bytes,
                "lan_packets": coverage.lan_normalized.rx_packets,
            },
            "rx": {
                "client_bytes": coverage.client_normalized.rx_bytes,
                "client_packets": coverage.client_normalized.rx_packets,
                "lan_bytes": coverage.lan_normalized.tx_bytes,
                "lan_packets": coverage.lan_normalized.tx_packets,
            },
        },
        "coverage": {
            "state": coverage.quality.as_str(),
            "reason": coverage.reason,
            "window_start_ms": coverage.start_ms,
            "window_end_ms": coverage.end_ms,
            "window_ms": coverage.window_ms(),
            "aligned": coverage.aligned,
            "tx_pct": coverage.tx_pct,
            "rx_pct": coverage.rx_pct,
        },
    })
}

pub(crate) fn traffic_evidence(value: TrafficCounters) -> Value {
    json!({
        "tx_bytes": value.tx_bytes,
        "rx_bytes": value.rx_bytes,
        "tx_packets": value.tx_packets,
        "rx_packets": value.rx_packets,
    })
}

pub(crate) fn ecm_bpf_coverage_merge_evidence(value: EcmBpfCoverageMerge) -> Value {
    json!({
        "source": value.source,
        "reason": value.reason,
        "tc_contributed": value.tc_contributed,
        "clock_skew_limit_ms": ECM_BPF_COVERAGE_CLOCK_SKEW_MS,
        "nss_hardware_raw": traffic_evidence(value.ecm),
        "tc_slow_path_raw": traffic_evidence(value.tc),
        "merged_raw": traffic_evidence(value.merged),
        "merge": "aligned_source_disjoint_raw_delta_sum",
    })
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod tests;
