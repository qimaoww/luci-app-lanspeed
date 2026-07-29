use std::collections::BTreeMap;

use crate::platform::{
    counters::TrafficCounters,
    nss::{ecm_bpf::EcmBpfSnapshot, tc_snapshot::NssTcSnapshot, window::RateWindowValue},
};

pub(crate) const ECM_BPF_COVERAGE_CLOCK_SKEW_MS: u64 = 250;
pub(crate) const ECM_BPF_RATE_CLOCK_SKEW_MS: u64 = 250;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EcmBpfCoverageMerge {
    pub(crate) merged: TrafficCounters,
    pub(crate) ecm: TrafficCounters,
    pub(crate) tc: TrafficCounters,
    pub(crate) source: &'static str,
    pub(crate) reason: &'static str,
    pub(crate) tc_contributed: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EcmBpfClientRate {
    pub(crate) tx_bps: u64,
    pub(crate) rx_bps: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) last_seen_ms: u64,
}

pub(crate) fn aligned_ecm_bpf_window(
    ecm: &EcmBpfSnapshot,
    bpf: Option<&NssTcSnapshot>,
    bpf_fresh: bool,
    skew_limit_ms: u64,
) -> Option<(u64, u64)> {
    if !bpf_fresh {
        return None;
    }
    let bpf = bpf.filter(|snapshot| snapshot.coverage_ready)?;
    let (Some(ecm_start), Some(bpf_start)) = (ecm.coverage_start_ms, bpf.coverage_start_ms) else {
        return None;
    };
    if ecm_start.abs_diff(bpf_start) > skew_limit_ms
        || ecm.coverage_end_ms.abs_diff(bpf.coverage_end_ms) > skew_limit_ms
    {
        return None;
    }
    let start = ecm_start.min(bpf_start);
    let end = ecm.coverage_end_ms.max(bpf.coverage_end_ms);
    (end > start).then_some((start, end))
}

fn has_traffic(value: TrafficCounters) -> bool {
    value.tx_bytes != 0 || value.rx_bytes != 0 || value.tx_packets != 0 || value.rx_packets != 0
}

fn wire_bytes(bytes: u64, packets: u64) -> u64 {
    bytes.saturating_add(packets.saturating_mul(4))
}

pub(crate) fn directional_bps(bytes: u64, packets: u64, window_ms: u64) -> u64 {
    if window_ms == 0 {
        return 0;
    }
    let scaled =
        u128::from(wire_bytes(bytes, packets)).saturating_mul(8_000) / u128::from(window_ms);
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

pub(crate) fn fused_client_rate(
    identity_key: &str,
    ecm: Option<&EcmBpfSnapshot>,
    bpf: Option<&NssTcSnapshot>,
    bpf_fresh: bool,
) -> Option<EcmBpfClientRate> {
    let ecm_sample = ecm.and_then(|snapshot| {
        snapshot
            .clients
            .iter()
            .find(|sample| sample.identity_key == identity_key)
    });
    let bpf_sample = bpf.and_then(|snapshot| {
        snapshot
            .clients
            .iter()
            .find(|sample| sample.identity_key == identity_key)
    });

    if let Some(ecm_snapshot) = ecm {
        if let Some((start, end)) =
            aligned_ecm_bpf_window(ecm_snapshot, bpf, bpf_fresh, ECM_BPF_RATE_CLOCK_SKEW_MS)
        {
            let ecm_delta = ecm_snapshot
                .coverage_deltas
                .get(identity_key)
                .copied()
                .unwrap_or_default();
            let bpf_delta = bpf
                .and_then(|snapshot| snapshot.coverage_deltas.get(identity_key))
                .copied()
                .unwrap_or_default();
            if has_traffic(ecm_delta) || has_traffic(bpf_delta) {
                let mut merged = ecm_delta;
                add_traffic_counters(&mut merged, bpf_delta);
                let window_ms = end.saturating_sub(start);
                return Some(EcmBpfClientRate {
                    tx_bps: directional_bps(merged.tx_bytes, merged.tx_packets, window_ms),
                    rx_bps: directional_bps(merged.rx_bytes, merged.rx_packets, window_ms),
                    tx_bytes: ecm_sample.map_or_else(
                        || bpf_sample.map_or(0, |sample| sample.tx_bytes),
                        |sample| sample.tx_bytes,
                    ),
                    rx_bytes: ecm_sample.map_or_else(
                        || bpf_sample.map_or(0, |sample| sample.rx_bytes),
                        |sample| sample.rx_bytes,
                    ),
                    last_seen_ms: ecm_sample
                        .map_or(0, |sample| sample.last_seen_ms)
                        .max(bpf_sample.map_or(0, |sample| sample.last_seen_ms)),
                });
            }
        }
    }

    match (ecm_sample, bpf_sample) {
        (Some(ecm), Some(bpf)) => Some(EcmBpfClientRate {
            // Without a shared raw window, choose one source per direction.
            // Adding precomputed rates here would count an unknown overlap.
            tx_bps: ecm.tx_bps.max(bpf.tx_bps),
            rx_bps: ecm.rx_bps.max(bpf.rx_bps),
            tx_bytes: ecm.tx_bytes,
            rx_bytes: ecm.rx_bytes,
            last_seen_ms: ecm.last_seen_ms.max(bpf.last_seen_ms),
        }),
        (Some(ecm), None) => Some(EcmBpfClientRate {
            tx_bps: ecm.tx_bps,
            rx_bps: ecm.rx_bps,
            tx_bytes: ecm.tx_bytes,
            rx_bytes: ecm.rx_bytes,
            last_seen_ms: ecm.last_seen_ms,
        }),
        (None, Some(bpf)) => Some(EcmBpfClientRate {
            tx_bps: bpf.tx_bps,
            rx_bps: bpf.rx_bps,
            tx_bytes: bpf.tx_bytes,
            rx_bytes: bpf.rx_bytes,
            last_seen_ms: bpf.last_seen_ms,
        }),
        (None, None) => None,
    }
}

pub(crate) fn merge_ecm_bpf_coverage_delta(
    ecm: &EcmBpfSnapshot,
    bpf: Option<&NssTcSnapshot>,
    bpf_fresh: bool,
) -> EcmBpfCoverageMerge {
    let fallback = |reason: &'static str| EcmBpfCoverageMerge {
        merged: ecm.coverage_delta,
        ecm: ecm.coverage_delta,
        tc: TrafficCounters::default(),
        source: "ecm_nss_hardware_delta",
        reason,
        tc_contributed: false,
    };
    let Some((_start_ms, _end_ms)) =
        aligned_ecm_bpf_window(ecm, bpf, bpf_fresh, ECM_BPF_COVERAGE_CLOCK_SKEW_MS)
    else {
        let reason = if !bpf_fresh {
            "tc_snapshot_not_fresh"
        } else if bpf.is_none() {
            "tc_snapshot_missing"
        } else if !bpf.is_some_and(|snapshot| snapshot.coverage_ready) {
            "tc_coverage_warmup_or_reset"
        } else if ecm.coverage_start_ms.is_none()
            || !bpf.is_some_and(|snapshot| snapshot.coverage_start_ms.is_some())
        {
            "coverage_window_missing"
        } else {
            "coverage_window_mismatch"
        };
        return fallback(reason);
    };

    let Some(bpf) = bpf else {
        return fallback("tc_snapshot_missing");
    };
    let tc = bpf.coverage_deltas.values().copied().fold(
        TrafficCounters::default(),
        |mut total, value| {
            add_traffic_counters(&mut total, value);
            total
        },
    );
    // The ECM object publishes only calls made inside NSS hardware-stat
    // callbacks. TC-BPF owns CPU-visible slow-path frames, so these counters
    // are source-disjoint and can be added without heuristic overlap tests.
    let mut merged = ecm.coverage_delta;
    add_traffic_counters(&mut merged, tc);
    EcmBpfCoverageMerge {
        merged,
        ecm: ecm.coverage_delta,
        tc,
        source: "ecm_nss_hardware_plus_tc_slow_path",
        reason: "sample_windows_aligned_source_disjoint",
        tc_contributed: tc.tx_bytes != 0
            || tc.rx_bytes != 0
            || tc.tx_packets != 0
            || tc.rx_packets != 0,
    }
}

pub(crate) fn merge_ecm_bpf_client_deltas(
    ecm: &EcmBpfSnapshot,
    bpf: Option<&NssTcSnapshot>,
    bpf_fresh: bool,
) -> BTreeMap<String, TrafficCounters> {
    let mut merged = ecm.coverage_deltas.clone();
    if aligned_ecm_bpf_window(ecm, bpf, bpf_fresh, ECM_BPF_COVERAGE_CLOCK_SKEW_MS).is_none() {
        return merged;
    }
    let Some(bpf) = bpf else {
        return merged;
    };
    for (identity_key, delta) in &bpf.coverage_deltas {
        add_traffic_counters(merged.entry(identity_key.clone()).or_default(), *delta);
    }
    merged
}

pub(crate) fn ecm_bpf_fallback_client_rates(
    ecm: &EcmBpfSnapshot,
    bpf: Option<&NssTcSnapshot>,
    bpf_fresh: bool,
) -> BTreeMap<String, RateWindowValue> {
    let bpf = bpf.filter(|_| bpf_fresh);
    let mut rates = BTreeMap::new();
    for identity_key in ecm
        .clients
        .iter()
        .map(|sample| sample.identity_key.as_str())
        .chain(
            bpf.into_iter()
                .flat_map(|snapshot| snapshot.clients.iter())
                .map(|sample| sample.identity_key.as_str()),
        )
    {
        if rates.contains_key(identity_key) {
            continue;
        }
        let Some(rate) = fused_client_rate(identity_key, Some(ecm), bpf, false) else {
            continue;
        };
        rates.insert(
            identity_key.to_owned(),
            RateWindowValue {
                rx_bps: rate.rx_bps,
                tx_bps: rate.tx_bps,
            },
        );
    }
    rates
}

pub(crate) fn ecm_bpf_client_interfaces(
    ecm: &EcmBpfSnapshot,
    bpf: Option<&NssTcSnapshot>,
    bpf_fresh: bool,
) -> BTreeMap<String, String> {
    let mut interfaces = BTreeMap::new();
    for sample in &ecm.clients {
        interfaces
            .entry(sample.identity_key.clone())
            .or_insert_with(|| sample.interface.clone());
    }
    if let Some(bpf) = bpf.filter(|_| bpf_fresh) {
        for sample in &bpf.clients {
            interfaces
                .entry(sample.identity_key.clone())
                .or_insert_with(|| sample.interface.clone());
        }
    }
    interfaces
}

pub(crate) fn add_traffic_counters(total: &mut TrafficCounters, value: TrafficCounters) {
    total.tx_bytes = total.tx_bytes.saturating_add(value.tx_bytes);
    total.rx_bytes = total.rx_bytes.saturating_add(value.rx_bytes);
    total.tx_packets = total.tx_packets.saturating_add(value.tx_packets);
    total.rx_packets = total.rx_packets.saturating_add(value.rx_packets);
}
