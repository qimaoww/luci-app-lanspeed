//! Same-window FastN/FastS shadow aggregation.
//!
//! The shadow plane consumes ECM hardware deltas and the independent FastS
//! cumulative map. It never selects a production rate owner; it only records
//! windows that passed the coordinator's generation and skew checks.

use super::{
    ecm_bpf::EcmBpfSnapshot,
    fast_rate::{FastCounterSample, FastRateCoordinator, FastWindowError},
    fast_rate_store::{FastRateSample, FastRateStore, FastRateTelemetry},
    fast_s_runtime::FastSSnapshot,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastRateShadow {
    coordinator: FastRateCoordinator,
    store: FastRateStore,
    n_bytes: u64,
    n_packets: u64,
    n_reset_generation: u32,
    n_ready: bool,
    last_error: Option<FastWindowError>,
}

impl FastRateShadow {
    pub(crate) fn new() -> Self {
        Self {
            n_reset_generation: 1,
            ..Self::default()
        }
    }

    pub(crate) const fn latest(&self) -> Option<FastRateSample> {
        self.store.latest()
    }

    pub(crate) const fn telemetry(&self) -> FastRateTelemetry {
        self.store.telemetry()
    }

    pub(crate) const fn last_error(&self) -> Option<FastWindowError> {
        self.last_error
    }

    pub(crate) fn observe(
        &mut self,
        nss: Option<&EcmBpfSnapshot>,
        fast_s: Option<&FastSSnapshot>,
        n_read_begin_ms: u64,
        n_read_end_ms: u64,
        s_read_begin_ms: u64,
        s_read_end_ms: u64,
    ) {
        let Some(nss) = nss else {
            return;
        };
        let Some(fast_s) = fast_s else {
            return;
        };
        if nss.truncated || !nss.coverage_ready || fast_s.truncated || fast_s.invalid_entries != 0 {
            self.invalidate(
                nss.coverage_end_ms.max(fast_s.sample_ms),
                fast_s.reset_generation,
            );
            return;
        }

        if !self.n_ready {
            self.n_ready = true;
        }
        self.n_bytes = self
            .n_bytes
            .saturating_add(nss.coverage_delta.tx_bytes)
            .saturating_add(nss.coverage_delta.rx_bytes);
        self.n_packets = self
            .n_packets
            .saturating_add(nss.coverage_delta.tx_packets)
            .saturating_add(nss.coverage_delta.rx_packets);

        let n = FastCounterSample {
            sample_ms: nss.coverage_end_ms,
            read_begin_ms: n_read_begin_ms,
            read_end_ms: n_read_end_ms,
            attachment_generation: 0,
            reset_generation: self.n_reset_generation,
            bytes: self.n_bytes,
            packets: self.n_packets,
        };
        let s = FastCounterSample {
            sample_ms: fast_s.sample_ms,
            read_begin_ms: s_read_begin_ms,
            read_end_ms: s_read_end_ms,
            attachment_generation: 0,
            reset_generation: fast_s.reset_generation,
            bytes: fast_s.bytes,
            packets: fast_s.packets,
        };
        self.observe_pair(n, s);
    }

    fn observe_pair(&mut self, n: FastCounterSample, s: FastCounterSample) {
        if !self.coordinator.has_start() && self.coordinator.begin(n, s).is_ok() {
            return;
        }
        match self.coordinator.finish(n, s) {
            Ok(window) => {
                self.store.publish(window);
                self.last_error = None;
                let _ = self.coordinator.begin(n, s);
            }
            Err(error) => {
                self.last_error = Some(error);
                self.store.record_invalid(n.sample_ms.max(s.sample_ms));
                self.coordinator.clear();
                let _ = self.coordinator.begin(n, s);
            }
        }
    }

    fn invalidate(&mut self, sample_ms: u64, reset_generation: u32) {
        self.n_reset_generation = reset_generation.max(1);
        if self.n_ready {
            self.n_ready = false;
            self.n_bytes = 0;
            self.n_packets = 0;
        }
        self.coordinator.clear();
        self.last_error = None;
        self.store.record_invalid(sample_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::FastRateShadow;
    use crate::platform::counters::TrafficCounters;
    use crate::platform::nss::{ecm_bpf::EcmBpfSnapshot, fast_s_runtime::FastSSnapshot};

    fn nss(end_ms: u64, bytes: u64) -> EcmBpfSnapshot {
        EcmBpfSnapshot {
            coverage_delta: TrafficCounters {
                tx_bytes: bytes,
                ..TrafficCounters::default()
            },
            coverage_start_ms: Some(end_ms.saturating_sub(1_000)),
            coverage_end_ms: end_ms,
            coverage_ready: true,
            sample_ms: end_ms,
            ..EcmBpfSnapshot::default()
        }
    }

    fn fast_s(sample_ms: u64, bytes: u64) -> FastSSnapshot {
        FastSSnapshot {
            sample_ms,
            valid_entries: 1,
            reset_generation: 1,
            bytes,
            packets: bytes / 10,
            ..FastSSnapshot::default()
        }
    }

    #[test]
    fn publishes_only_same_window_shadow_samples() {
        let mut shadow = FastRateShadow::new();
        shadow.observe(
            Some(&nss(1_000, 100)),
            Some(&fast_s(1_000, 50)),
            990,
            1_010,
            991,
            1_011,
        );
        assert!(shadow.latest().is_none());
        shadow.observe(
            Some(&nss(2_000, 200)),
            Some(&fast_s(2_000, 250)),
            1_990,
            2_010,
            1_991,
            2_011,
        );
        let sample = shadow.latest().unwrap();
        assert_eq!(sample.fast_n_bps, 1_600);
        assert_eq!(sample.fast_s_bps, 1_600);
        assert_eq!(sample.fast_total_bps, 3_200);
    }

    #[test]
    fn invalid_fast_s_read_does_not_reuse_previous_window() {
        let mut shadow = FastRateShadow::new();
        shadow.observe(
            Some(&nss(1_000, 100)),
            Some(&fast_s(1_000, 50)),
            990,
            1_010,
            991,
            1_011,
        );
        shadow.observe(
            Some(&nss(2_000, 200)),
            Some(&FastSSnapshot {
                invalid_entries: 1,
                ..fast_s(2_000, 150)
            }),
            1_990,
            2_010,
            1_991,
            2_011,
        );
        assert!(shadow.latest().is_none());
        assert_eq!(shadow.telemetry().invalid_windows, 1);
    }

    #[test]
    fn invalidation_rewarms_without_permanent_generation_skew() {
        let mut shadow = FastRateShadow::new();
        shadow.observe(
            Some(&nss(1_000, 100)),
            Some(&fast_s(1_000, 50)),
            990,
            1_010,
            991,
            1_011,
        );
        shadow.observe(
            Some(&nss(2_000, 200)),
            Some(&FastSSnapshot {
                invalid_entries: 1,
                reset_generation: 2,
                ..fast_s(2_000, 150)
            }),
            1_990,
            2_010,
            1_991,
            2_011,
        );
        shadow.observe(
            Some(&nss(3_000, 300)),
            Some(&FastSSnapshot {
                reset_generation: 2,
                ..fast_s(3_000, 250)
            }),
            2_990,
            3_010,
            2_991,
            3_011,
        );
        shadow.observe(
            Some(&nss(4_000, 400)),
            Some(&FastSSnapshot {
                reset_generation: 2,
                ..fast_s(4_000, 350)
            }),
            3_990,
            4_010,
            3_991,
            4_011,
        );
        assert!(shadow.latest().is_some());
    }
}
