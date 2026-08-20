//! Same-window FastN/FastS shadow aggregation.
//!
//! This worker-internal plane consumes independent FastN and FastS cumulative
//! maps and records only windows that passed generation and skew checks. The
//! RateMux decides whether a published client direction may consume a window.

use super::{
    fast_n_runtime::FastNSnapshot,
    fast_rate::{
        FastCounterSample, FastRateCoordinator, FastWindowError, FAST_WINDOW_QUIET_CONFIRM_MS,
    },
    fast_rate_clients::{FastClientKey, FastClientRateBook, FastClientSample},
    fast_rate_contract::FastRateBaseContract,
    fast_rate_store::{FastRateSample, FastRateStore, FastRateTelemetry, FastShadowComparison},
    fast_s_runtime::FastSSnapshot,
};

fn retain_aggregate_baseline(
    current: FastCounterSample,
    previous: Option<FastCounterSample>,
) -> FastCounterSample {
    if current.source_present {
        return current;
    }
    let Some(previous) = previous else {
        return current;
    };
    // An empty valid map is a quiet observation, not a counter reset. Keep
    // the last cumulative aggregate and advance only the read clock; the
    // coordinator can publish a real zero after quiet confirmation. A
    // non-zero reset generation from the current source still wins, so a
    // genuine reload/reset is re-warmed instead of crossing generations.
    FastCounterSample {
        sample_ms: current.sample_ms,
        progress_ms: 0,
        source_present: false,
        read_begin_ms: current.read_begin_ms,
        read_end_ms: current.read_end_ms,
        attachment_generation: current.attachment_generation,
        reset_generation: if current.reset_generation == 0 {
            previous.reset_generation
        } else {
            current.reset_generation
        },
        bytes: previous.bytes,
        packets: previous.packets,
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastRateShadow {
    coordinator: FastRateCoordinator,
    store: FastRateStore,
    client_rates: FastClientRateBook,
    last_n: Option<FastCounterSample>,
    last_s: Option<FastCounterSample>,
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
        self.observe_inner(
            fast_n,
            fast_s,
            n_read_begin_ms,
            n_read_end_ms,
            s_read_begin_ms,
            s_read_end_ms,
            edge_bps,
            None,
        );
    }

    pub(crate) fn observe_with_contract(
        &mut self,
        fast_n: Option<&FastNSnapshot>,
        fast_s: Option<&FastSSnapshot>,
        n_read_begin_ms: u64,
        n_read_end_ms: u64,
        s_read_begin_ms: u64,
        s_read_end_ms: u64,
        edge_bps: Option<u64>,
        contract: &FastRateBaseContract,
    ) {
        self.observe_inner(
            fast_n,
            fast_s,
            n_read_begin_ms,
            n_read_end_ms,
            s_read_begin_ms,
            s_read_end_ms,
            edge_bps,
            Some(contract),
        );
    }

    fn observe_inner(
        &mut self,
        fast_n: Option<&FastNSnapshot>,
        fast_s: Option<&FastSSnapshot>,
        n_read_begin_ms: u64,
        n_read_end_ms: u64,
        s_read_begin_ms: u64,
        s_read_end_ms: u64,
        edge_bps: Option<u64>,
        contract: Option<&FastRateBaseContract>,
    ) {
        self.edge_bps = edge_bps;
        let (Some(fast_n), Some(fast_s)) = (fast_n, fast_s) else {
            self.invalidate_unavailable(
                fast_n
                    .map(|snapshot| snapshot.sample_ms)
                    .or_else(|| fast_s.map(|snapshot| snapshot.sample_ms))
                    .unwrap_or_default(),
            );
            return;
        };
        if fast_n.truncated
            || fast_n.invalid_entries != 0
            || fast_s.truncated
            || fast_s.invalid_entries != 0
        {
            self.client_rates.observe(
                fast_n,
                fast_s,
                n_read_begin_ms,
                n_read_end_ms,
                s_read_begin_ms,
                s_read_end_ms,
            );
            self.invalidate(fast_n.sample_ms.max(fast_s.sample_ms));
            return;
        }

        match contract {
            Some(contract) => self.client_rates.observe_with_contract(
                fast_n,
                fast_s,
                n_read_begin_ms,
                n_read_end_ms,
                s_read_begin_ms,
                s_read_end_ms,
                contract,
            ),
            None => self.client_rates.observe(
                fast_n,
                fast_s,
                n_read_begin_ms,
                n_read_end_ms,
                s_read_begin_ms,
                s_read_end_ms,
            ),
        }

        let common_progress_ms = fast_n.progress_ms.max(fast_s.progress_ms);
        let sample_ms = if common_progress_ms == 0 {
            fast_n.sample_ms.max(fast_s.sample_ms)
        } else {
            common_progress_ms
        };
        let n = retain_aggregate_baseline(
            FastCounterSample {
                sample_ms,
                progress_ms: fast_n.progress_ms,
                source_present: fast_n.valid_entries != 0,
                read_begin_ms: n_read_begin_ms,
                read_end_ms: n_read_end_ms,
                attachment_generation: 0,
                reset_generation: fast_n.reset_generation,
                bytes: fast_n.bytes,
                packets: fast_n.packets,
            },
            self.last_n,
        );
        let s = retain_aggregate_baseline(
            FastCounterSample {
                sample_ms,
                progress_ms: fast_s.progress_ms,
                source_present: fast_s.valid_entries != 0,
                read_begin_ms: s_read_begin_ms,
                read_end_ms: s_read_end_ms,
                attachment_generation: 0,
                reset_generation: fast_s.reset_generation,
                bytes: fast_s.bytes,
                packets: fast_s.packets,
            },
            self.last_s,
        );
        self.last_n = Some(n);
        self.last_s = Some(s);
        self.observe_pair(n, s);
    }

    fn observe_pair(&mut self, n: FastCounterSample, s: FastCounterSample) {
        if !self.coordinator.has_start() && self.coordinator.begin(n, s).is_ok() {
            return;
        }
        if !self.coordinator.has_progress(n, s) {
            match self
                .coordinator
                .confirmed_quiet_window(n, s, FAST_WINDOW_QUIET_CONFIRM_MS)
            {
                Ok(Some(window)) => {
                    self.store.publish(window);
                    self.comparison = self.store.compare_with_edge(self.edge_bps);
                    self.last_error = None;
                }
                Ok(None) => {}
                Err(error) => {
                    self.last_error = Some(error);
                    self.store.record_invalid(n.sample_ms.max(s.sample_ms));
                    self.coordinator.clear();
                    let _ = self.coordinator.begin(n, s);
                }
            }
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
        self.last_n = None;
        self.last_s = None;
        self.last_error = None;
        self.store.record_invalid(sample_ms);
    }

    pub(crate) fn invalidate_unavailable(&mut self, sample_ms: u64) {
        self.client_rates.clear();
        self.invalidate(sample_ms);
    }

    pub(crate) fn client_rate(&self, mac: [u8; 6], direction: u8) -> Option<FastClientSample> {
        self.client_rates.get(mac, direction)
    }

    pub(crate) fn client_samples(&self) -> Vec<(FastClientKey, FastClientSample)> {
        self.client_rates.samples()
    }

    pub(crate) const fn client_invalid_windows(&self) -> u64 {
        self.client_rates.invalid_windows()
    }

    pub(crate) fn client_count(&self) -> usize {
        self.client_rates.len()
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
        assert_eq!(
            shadow
                .client_rate([2, 0, 0, 0, 0, 1], lanspeed_common::DIR_TX)
                .map(|value| value.fast_total_bps),
            None
        );
    }

    #[test]
    fn holds_a_valid_event_window_when_a_read_sees_no_new_progress() {
        let mut shadow = FastRateShadow::new();
        let mut first_n = fast_n(1_100, 100);
        first_n.progress_ms = 1_000;
        let mut first_s = fast_s(1_100, 50);
        first_s.progress_ms = 1_000;
        shadow.observe(
            Some(&first_n),
            Some(&first_s),
            1_090,
            1_100,
            1_091,
            1_101,
            None,
        );

        let mut next_n = fast_n(2_100, 300);
        next_n.progress_ms = 3_000;
        let mut next_s = fast_s(2_100, 250);
        next_s.progress_ms = 3_000;
        shadow.observe(
            Some(&next_n),
            Some(&next_s),
            3_090,
            3_100,
            3_091,
            3_101,
            None,
        );
        let published = shadow.latest().unwrap();
        assert_eq!(published.sample_ms, 3_000);
        assert_eq!(published.window_ms, 2_000);
        assert_eq!(published.fast_total_bps, 1_600);

        let mut held_n = next_n;
        held_n.sample_ms = 3_100;
        let mut held_s = next_s;
        held_s.sample_ms = 3_100;
        shadow.observe(
            Some(&held_n),
            Some(&held_s),
            3_090,
            3_100,
            3_091,
            3_101,
            None,
        );
        assert_eq!(shadow.latest(), Some(published));
        assert_eq!(shadow.telemetry().zero_windows, 0);
    }

    #[test]
    fn fixed_timer_publishes_zero_after_quiet_confirmation() {
        let mut shadow = FastRateShadow::new();
        let mut first_n = fast_n(1_100, 100);
        first_n.progress_ms = 1_000;
        let mut first_s = fast_s(1_100, 50);
        first_s.progress_ms = 1_000;
        shadow.observe(
            Some(&first_n),
            Some(&first_s),
            1_090,
            1_100,
            1_091,
            1_101,
            None,
        );

        let mut early_n = first_n.clone();
        early_n.sample_ms = 2_100;
        let mut early_s = first_s.clone();
        early_s.sample_ms = 2_100;
        shadow.observe(
            Some(&early_n),
            Some(&early_s),
            2_090,
            2_100,
            2_091,
            2_101,
            None,
        );
        assert!(shadow.latest().is_none());

        let mut quiet_n = first_n.clone();
        quiet_n.sample_ms = 4_100;
        let mut quiet_s = first_s.clone();
        quiet_s.sample_ms = 4_100;
        shadow.observe(
            Some(&quiet_n),
            Some(&quiet_s),
            4_090,
            4_100,
            4_091,
            4_101,
            None,
        );
        let zero = shadow.latest().expect("confirmed aggregate zero");
        assert_eq!(zero.sample_ms, 4_100);
        assert_eq!(zero.fast_total_bps, 0);
        assert_eq!(shadow.telemetry().zero_windows, 1);

        let mut resumed_n = fast_n(5_100, 300);
        resumed_n.progress_ms = 5_000;
        let mut resumed_s = fast_s(5_100, 250);
        resumed_s.progress_ms = 5_000;
        shadow.observe(
            Some(&resumed_n),
            Some(&resumed_s),
            5_090,
            5_100,
            5_091,
            5_101,
            None,
        );
        assert!(shadow.latest().unwrap().fast_total_bps > 0);
    }

    #[test]
    fn empty_valid_maps_confirm_a_global_zero_without_reusing_a_short_window() {
        let mut shadow = FastRateShadow::new();
        let mut first_n = fast_n(1_100, 100);
        first_n.progress_ms = 1_000;
        let mut first_s = fast_s(1_100, 50);
        first_s.progress_ms = 1_000;
        shadow.observe(
            Some(&first_n),
            Some(&first_s),
            1_090,
            1_100,
            1_091,
            1_101,
            None,
        );

        let mut empty_n = FastNSnapshot {
            sample_ms: 4_100,
            reset_generation: 1,
            ..FastNSnapshot::default()
        };
        let mut empty_s = FastSSnapshot {
            sample_ms: 4_100,
            reset_generation: 1,
            ..FastSSnapshot::default()
        };
        shadow.observe(
            Some(&empty_n),
            Some(&empty_s),
            4_090,
            4_100,
            4_091,
            4_101,
            None,
        );
        let zero = shadow.latest().expect("empty maps become a confirmed zero");
        assert_eq!(zero.fast_total_bps, 0);
        assert_eq!(shadow.telemetry().invalid_windows, 0);

        empty_n.sample_ms = 5_100;
        empty_s.sample_ms = 5_100;
        shadow.observe(
            Some(&empty_n),
            Some(&empty_s),
            5_090,
            5_100,
            5_091,
            5_101,
            None,
        );
        assert_eq!(shadow.latest().unwrap().fast_total_bps, 0);
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
