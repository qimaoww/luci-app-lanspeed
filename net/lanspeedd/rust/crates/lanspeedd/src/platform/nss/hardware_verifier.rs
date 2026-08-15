//! Read-only BPF/IGS hardware-path cross verification.
//!
//! ECM-BPF remains the client-accounting owner. This module only compares an
//! upload delta with the aggregate counters reported by the LAN Speed IGS
//! nodes. It never supplies a rate candidate and never changes control state.

use serde_json::{json, Value};

use super::{
    control::{hardware_telemetry_sample, HardwareTelemetrySample},
    ecm_bpf::EcmBpfSnapshot,
};

const MIN_PROOF_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerificationState {
    Unavailable,
    Warmup,
    Idle,
    Aligned,
    BpfOnly,
    IgsOnly,
    Divergent,
    Reset,
}

impl VerificationState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Warmup => "warmup",
            Self::Idle => "idle",
            Self::Aligned => "aligned",
            Self::BpfOnly => "bpf_only",
            Self::IgsOnly => "igs_only",
            Self::Divergent => "divergent",
            Self::Reset => "reset",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Baseline {
    control_generation: u64,
    hardware_generation: u64,
    sync_count: u64,
    igs_bytes: u64,
    igs_packets: u64,
    igs_drops: u64,
    sample_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Comparison {
    state: VerificationState,
    sample_ms: u64,
    window_ms: u64,
    bpf_delta_bytes: u64,
    igs_delta_bytes: u64,
    igs_delta_packets: u64,
    igs_delta_drops: u64,
    absolute_delta_bytes: u64,
    ratio_per_mille: Option<u64>,
    control_generation: u64,
    hardware_generation: u64,
    sync_count: u64,
    last_sync_ns: u64,
    igs_active_nodes: u32,
    igs_drops: u64,
    reason_code: Option<&'static str>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct HardwareVerifier {
    baseline: Option<Baseline>,
    latest: Option<Comparison>,
    valid_windows: u64,
    invalid_windows: u64,
    reset_windows: u64,
}

impl HardwareVerifier {
    pub(crate) fn observe(&mut self, nss: Option<&EcmBpfSnapshot>, sample_ms: u64, fresh: bool) {
        self.observe_sample(nss, hardware_telemetry_sample(), sample_ms, fresh);
    }

    fn observe_sample(
        &mut self,
        nss: Option<&EcmBpfSnapshot>,
        hardware: Option<HardwareTelemetrySample>,
        sample_ms: u64,
        fresh: bool,
    ) {
        let Some(hardware) = hardware else {
            self.invalid_windows = self.invalid_windows.saturating_add(1);
            self.latest = Some(Comparison {
                state: VerificationState::Unavailable,
                sample_ms,
                window_ms: 0,
                bpf_delta_bytes: 0,
                igs_delta_bytes: 0,
                igs_delta_packets: 0,
                igs_delta_drops: 0,
                absolute_delta_bytes: 0,
                ratio_per_mille: None,
                control_generation: 0,
                hardware_generation: 0,
                sync_count: 0,
                last_sync_ns: 0,
                igs_active_nodes: 0,
                igs_drops: 0,
                reason_code: Some("hardware_telemetry_unavailable"),
            });
            return;
        };
        if !fresh {
            return;
        }
        let Some(nss) = nss.filter(|snapshot| {
            snapshot.coverage_ready && !snapshot.truncated && snapshot.coverage_end_ms != 0
        }) else {
            self.invalid_windows = self.invalid_windows.saturating_add(1);
            self.latest = Some(Comparison {
                state: VerificationState::Unavailable,
                sample_ms,
                window_ms: 0,
                bpf_delta_bytes: 0,
                igs_delta_bytes: 0,
                igs_delta_packets: 0,
                igs_delta_drops: 0,
                absolute_delta_bytes: 0,
                ratio_per_mille: None,
                control_generation: hardware.control_generation,
                hardware_generation: hardware.hardware_generation,
                sync_count: hardware.igs_sync_count,
                last_sync_ns: hardware.igs_last_sync_ns,
                igs_active_nodes: hardware.igs_active_nodes,
                igs_drops: hardware.igs_drops,
                reason_code: Some("ecm_bpf_window_unavailable"),
            });
            return;
        };
        if hardware.igs_active_nodes == 0 || hardware.igs_sync_count == 0 {
            self.latest = Some(Comparison {
                state: VerificationState::Warmup,
                sample_ms,
                window_ms: 0,
                bpf_delta_bytes: 0,
                igs_delta_bytes: 0,
                igs_delta_packets: 0,
                igs_delta_drops: 0,
                absolute_delta_bytes: 0,
                ratio_per_mille: None,
                control_generation: hardware.control_generation,
                hardware_generation: hardware.hardware_generation,
                sync_count: hardware.igs_sync_count,
                last_sync_ns: hardware.igs_last_sync_ns,
                igs_active_nodes: hardware.igs_active_nodes,
                igs_drops: hardware.igs_drops,
                reason_code: Some("igs_sync_warmup"),
            });
            self.baseline = None;
            return;
        }

        let current = Baseline {
            control_generation: hardware.control_generation,
            hardware_generation: hardware.hardware_generation,
            sync_count: hardware.igs_sync_count,
            igs_bytes: hardware.igs_bytes,
            igs_packets: hardware.igs_packets,
            igs_drops: hardware.igs_drops,
            sample_ms,
        };
        let Some(previous) = self.baseline.replace(current) else {
            self.latest = Some(Comparison {
                state: VerificationState::Warmup,
                sample_ms,
                window_ms: 0,
                bpf_delta_bytes: 0,
                igs_delta_bytes: 0,
                igs_delta_packets: 0,
                igs_delta_drops: 0,
                absolute_delta_bytes: 0,
                ratio_per_mille: None,
                control_generation: current.control_generation,
                hardware_generation: current.hardware_generation,
                sync_count: current.sync_count,
                last_sync_ns: hardware.igs_last_sync_ns,
                igs_active_nodes: hardware.igs_active_nodes,
                igs_drops: hardware.igs_drops,
                reason_code: Some("verifier_baseline"),
            });
            return;
        };
        if previous.control_generation != current.control_generation
            || previous.hardware_generation != current.hardware_generation
            || current.sync_count <= previous.sync_count
            || current.igs_bytes < previous.igs_bytes
        {
            self.reset_windows = self.reset_windows.saturating_add(1);
            let reason_code = if previous.control_generation != current.control_generation
                || previous.hardware_generation != current.hardware_generation
            {
                "hardware_generation_changed"
            } else if current.sync_count <= previous.sync_count {
                "igs_sync_stalled"
            } else {
                "igs_counter_reset"
            };
            self.latest = Some(Comparison {
                state: VerificationState::Reset,
                sample_ms,
                window_ms: 0,
                bpf_delta_bytes: 0,
                igs_delta_bytes: 0,
                igs_delta_packets: 0,
                igs_delta_drops: 0,
                absolute_delta_bytes: 0,
                ratio_per_mille: None,
                control_generation: current.control_generation,
                hardware_generation: current.hardware_generation,
                sync_count: current.sync_count,
                last_sync_ns: hardware.igs_last_sync_ns,
                igs_active_nodes: hardware.igs_active_nodes,
                igs_drops: hardware.igs_drops,
                reason_code: Some(reason_code),
            });
            return;
        }

        let bpf_delta = nss.coverage_delta.tx_bytes;
        let igs_delta = current.igs_bytes.saturating_sub(previous.igs_bytes);
        let igs_delta_packets = current.igs_packets.saturating_sub(previous.igs_packets);
        let igs_delta_drops = current.igs_drops.saturating_sub(previous.igs_drops);
        let state = classify(bpf_delta, igs_delta);
        let ratio_per_mille = (igs_delta != 0).then(|| {
            u128::from(bpf_delta)
                .saturating_mul(1_000)
                .checked_div(u128::from(igs_delta))
                .and_then(|ratio| u64::try_from(ratio).ok())
                .unwrap_or(u64::MAX)
        });
        self.valid_windows = self.valid_windows.saturating_add(1);
        self.latest = Some(Comparison {
            state,
            sample_ms,
            window_ms: sample_ms.saturating_sub(previous.sample_ms),
            bpf_delta_bytes: bpf_delta,
            igs_delta_bytes: igs_delta,
            igs_delta_packets,
            igs_delta_drops,
            absolute_delta_bytes: bpf_delta.abs_diff(igs_delta),
            ratio_per_mille,
            control_generation: current.control_generation,
            hardware_generation: current.hardware_generation,
            sync_count: current.sync_count,
            last_sync_ns: hardware.igs_last_sync_ns,
            igs_active_nodes: hardware.igs_active_nodes,
            igs_drops: hardware.igs_drops,
            reason_code: None,
        });
    }

    pub(crate) fn evidence(&self) -> Value {
        let Some(comparison) = self.latest else {
            return json!({
                "state": "unavailable",
                "formal_rate_owner": false,
                "scope": "ecm_bpf_upload_vs_aggregate_igs",
                "reason_code": "no_sample",
                "valid_windows": self.valid_windows,
                "invalid_windows": self.invalid_windows,
                "reset_windows": self.reset_windows,
            });
        };
        json!({
            "state": comparison.state.as_str(),
            "formal_rate_owner": false,
            "scope": "ecm_bpf_upload_vs_aggregate_igs",
            "sample_ms": comparison.sample_ms,
            "window_ms": comparison.window_ms,
            "bpf_delta_bytes": comparison.bpf_delta_bytes,
            "igs_delta_bytes": comparison.igs_delta_bytes,
            "igs_delta_packets": comparison.igs_delta_packets,
            "igs_delta_drops": comparison.igs_delta_drops,
            "absolute_delta_bytes": comparison.absolute_delta_bytes,
            "ratio_per_mille": comparison.ratio_per_mille,
            "control_generation": comparison.control_generation,
            "hardware_generation": comparison.hardware_generation,
            "igs_sync_count": comparison.sync_count,
            "igs_last_sync_ns": comparison.last_sync_ns,
            "igs_active_nodes": comparison.igs_active_nodes,
            "igs_drops": comparison.igs_drops,
            "reason_code": comparison.reason_code,
            "valid_windows": self.valid_windows,
            "invalid_windows": self.invalid_windows,
            "reset_windows": self.reset_windows,
        })
    }
}

fn classify(bpf_bytes: u64, igs_bytes: u64) -> VerificationState {
    match (bpf_bytes >= MIN_PROOF_BYTES, igs_bytes >= MIN_PROOF_BYTES) {
        (false, false) if bpf_bytes == 0 && igs_bytes == 0 => VerificationState::Idle,
        (false, false) => VerificationState::Warmup,
        (true, false) => VerificationState::BpfOnly,
        (false, true) => VerificationState::IgsOnly,
        (true, true)
            if u128::from(bpf_bytes).saturating_mul(2) >= u128::from(igs_bytes)
                && u128::from(igs_bytes).saturating_mul(2) >= u128::from(bpf_bytes) =>
        {
            VerificationState::Aligned
        }
        (true, true) => VerificationState::Divergent,
    }
}

#[cfg(test)]
mod tests {
    use crate::platform::counters::TrafficCounters;

    use super::{
        classify, EcmBpfSnapshot, HardwareTelemetrySample, HardwareVerifier, VerificationState,
        MIN_PROOF_BYTES,
    };

    fn nss(tx_bytes: u64, sample_ms: u64) -> EcmBpfSnapshot {
        EcmBpfSnapshot {
            coverage_delta: TrafficCounters {
                tx_bytes,
                ..TrafficCounters::default()
            },
            coverage_ready: true,
            coverage_end_ms: sample_ms,
            sample_ms,
            ..EcmBpfSnapshot::default()
        }
    }

    fn hardware(sync_count: u64, bytes: u64) -> HardwareTelemetrySample {
        HardwareTelemetrySample {
            control_generation: 1,
            hardware_generation: 1,
            igs_sync_count: sync_count,
            igs_last_sync_ns: sync_count.saturating_mul(1_000_000_000),
            igs_bytes: bytes,
            igs_packets: bytes / 1_000,
            igs_drops: 0,
            igs_active_nodes: 1,
        }
    }

    #[test]
    fn classifies_independent_counter_outcomes_without_rate_ownership() {
        assert_eq!(classify(0, 0), VerificationState::Idle);
        assert_eq!(classify(MIN_PROOF_BYTES, 0), VerificationState::BpfOnly);
        assert_eq!(classify(0, MIN_PROOF_BYTES), VerificationState::IgsOnly);
        assert_eq!(
            classify(MIN_PROOF_BYTES, MIN_PROOF_BYTES),
            VerificationState::Aligned
        );
        assert_eq!(
            classify(MIN_PROOF_BYTES * 8, MIN_PROOF_BYTES),
            VerificationState::Divergent
        );
    }

    #[test]
    fn empty_verifier_is_explicitly_non_owner() {
        let verifier = HardwareVerifier::default();
        let evidence = verifier.evidence();
        assert_eq!(evidence["formal_rate_owner"], false);
        assert_eq!(evidence["scope"], "ecm_bpf_upload_vs_aggregate_igs");
    }

    #[test]
    fn compares_only_consecutive_fresh_generation_stable_windows() {
        let mut verifier = HardwareVerifier::default();
        verifier.observe_sample(
            Some(&nss(100, 1_000)),
            Some(hardware(1, 1_000)),
            1_000,
            true,
        );
        assert_eq!(verifier.evidence()["state"], "warmup");
        verifier.observe_sample(
            Some(&nss(MIN_PROOF_BYTES, 2_000)),
            Some(hardware(2, 1_000 + MIN_PROOF_BYTES)),
            2_000,
            true,
        );
        let evidence = verifier.evidence();
        assert_eq!(evidence["state"], "aligned");
        assert_eq!(evidence["bpf_delta_bytes"], MIN_PROOF_BYTES);
        assert_eq!(evidence["igs_delta_bytes"], MIN_PROOF_BYTES);
        assert_eq!(evidence["formal_rate_owner"], false);
    }

    #[test]
    fn generation_change_and_stalled_sync_rebaseline_without_a_false_verdict() {
        let mut verifier = HardwareVerifier::default();
        verifier.observe_sample(
            Some(&nss(100, 1_000)),
            Some(hardware(1, 1_000)),
            1_000,
            true,
        );
        let mut changed = hardware(2, 2_000);
        changed.control_generation = 2;
        verifier.observe_sample(Some(&nss(1_000, 2_000)), Some(changed), 2_000, true);
        assert_eq!(
            verifier.evidence()["reason_code"],
            "hardware_generation_changed"
        );
        let mut stalled = hardware(2, 3_000);
        stalled.control_generation = 2;
        verifier.observe_sample(Some(&nss(1_000, 3_000)), Some(stalled), 3_000, true);
        assert_eq!(verifier.evidence()["reason_code"], "igs_sync_stalled");
    }

    #[test]
    fn traffic_counters_keep_upload_scope_documented() {
        let counters = TrafficCounters {
            tx_bytes: MIN_PROOF_BYTES,
            ..TrafficCounters::default()
        };
        assert_eq!(counters.tx_bytes, MIN_PROOF_BYTES);
        assert_eq!(counters.rx_bytes, 0);
    }
}
