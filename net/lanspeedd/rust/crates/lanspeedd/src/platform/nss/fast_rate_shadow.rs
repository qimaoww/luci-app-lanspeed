//! Same-window FastN/FastS shadow aggregation.
//!
//! The shadow plane consumes the independent FastN and FastS cumulative maps.
//! It never selects a production rate owner; it only records windows that
//! passed the coordinator's generation and skew checks.

use super::{
    fast_n_runtime::FastNSnapshot,
    fast_rate::{FastCounterSample, FastRateCoordinator, FastWindowError},
    fast_rate_store::{FastRateSample, FastRateStore, FastRateTelemetry, FastShadowComparison},
    fast_s_runtime::FastSSnapshot,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastRateShadow {
    coordinator: FastRateCoordinator,
    store: FastRateStore,
    edge_bps: Option<u64>,
    comparison: Option<FastShadowComparison>,
    last_error: Option<FastWindowError>,
}

impl FastRateShadow {
    pub(crate) fn new() -> Self {
        Self { ..Self::default() }
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

    pub(crate) const fn comparison(&self) -> Option<FastShadowComparison> {
        self.comparison
    }

    pub(crate) fn observe(
        &mut self,
        fast_n: Option<&FastNSnapshot>,
        fast_s: Option<&FastSSnapshot>,
        n_read_begin_ms: u64,
        n_read_end_ms: u64,
        s_read_begin_ms: u64,
        s_read_end_ms: u64,
        edge_bps: Option<u64>,
    ) {
        self.edge_bps = edge_bps;
        let Some(fast_n) = fast_n else {
            return;
        };
        let Some(fast_s) = fast_s else {
            return;
        };
        if fast_n.truncated
            || fast_n.invalid_entries != 0
            || fast_s.truncated
            || fast_s.invalid_entries != 0
        {
            self.invalidate(fast_n.sample_ms.max(fast_s.sample_ms));
            return;
        }

        let n = FastCounterSample {
            sample_ms: fast_n.sample_ms,
            read_begin_ms: n_read_begin_ms,
            read_end_ms: n_read_end_ms,
            attachment_generation: 0,
            reset_generation: fast_n.reset_generation,
            bytes: fast_n.bytes,
            packets: fast_n.packets,
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
                self.comparison = self.store.compare_with_edge(self.edge_bps);
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

    fn invalidate(&mut self, sample_ms: u64) {
        self.coordinator.clear();
        self.last_error = None;
        self.store.record_invalid(sample_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::FastRateShadow;
    use crate::platform::nss::{fast_n_runtime::FastNSnapshot, fast_s_runtime::FastSSnapshot};

    fn fast_n(end_ms: u64, bytes: u64) -> FastNSnapshot {
        FastNSnapshot {
            bytes,
            packets: bytes / 10,
            reset_generation: 1,
            sample_ms: end_ms,
            valid_entries: 1,
            ..FastNSnapshot::default()
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
            Some(&fast_n(1_000, 100)),
            Some(&fast_s(1_000, 50)),
            990,
            1_010,
            991,
            1_011,
            None,
        );
        assert!(shadow.latest().is_none());
        shadow.observe(
            Some(&fast_n(2_000, 300)),
            Some(&fast_s(2_000, 250)),
            1_990,
            2_010,
            1_991,
            2_011,
            Some(3_200),
        );
        let sample = shadow.latest().unwrap();
        assert_eq!(sample.fast_n_bps, 1_600);
        assert_eq!(sample.fast_s_bps, 1_600);
        assert_eq!(sample.fast_total_bps, 3_200);
        assert_eq!(
            shadow.comparison().and_then(|value| value.edge_bps),
            Some(3_200)
        );
        assert_eq!(
            shadow
                .comparison()
                .and_then(|value| value.absolute_delta_bps),
            Some(0)
        );
    }

    #[test]
    fn invalid_fast_s_read_does_not_reuse_previous_window() {
        let mut shadow = FastRateShadow::new();
        shadow.observe(
            Some(&fast_n(1_000, 100)),
            Some(&fast_s(1_000, 50)),
            990,
            1_010,
            991,
            1_011,
            None,
        );
        shadow.observe(
            Some(&fast_n(2_000, 200)),
            Some(&FastSSnapshot {
                invalid_entries: 1,
                ..fast_s(2_000, 150)
            }),
            1_990,
            2_010,
            1_991,
            2_011,
            None,
        );
        assert!(shadow.latest().is_none());
        assert_eq!(shadow.telemetry().invalid_windows, 1);
    }

    #[test]
    fn invalidation_rewarms_without_permanent_generation_skew() {
        let mut shadow = FastRateShadow::new();
        shadow.observe(
            Some(&fast_n(1_000, 100)),
            Some(&fast_s(1_000, 50)),
            990,
            1_010,
            991,
            1_011,
            None,
        );
        shadow.observe(
            Some(&fast_n(2_000, 200)),
            Some(&FastSSnapshot {
                invalid_entries: 1,
                reset_generation: 2,
                ..fast_s(2_000, 150)
            }),
            1_990,
            2_010,
            1_991,
            2_011,
            None,
        );
        shadow.observe(
            Some(&fast_n(3_000, 300)),
            Some(&FastSSnapshot {
                reset_generation: 2,
                ..fast_s(3_000, 250)
            }),
            2_990,
            3_010,
            2_991,
            3_011,
            None,
        );
        shadow.observe(
            Some(&fast_n(4_000, 400)),
            Some(&FastSSnapshot {
                reset_generation: 2,
                ..fast_s(4_000, 350)
            }),
            3_990,
            4_010,
            3_991,
            4_011,
            None,
        );
        assert!(shadow.latest().is_some());
    }
}
