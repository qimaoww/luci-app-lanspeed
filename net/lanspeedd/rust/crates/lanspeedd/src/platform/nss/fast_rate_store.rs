//! Worker-owned storage and telemetry for same-window FastRate samples.

use super::fast_rate::FastWindow;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastRateSample {
    pub sample_ms: u64,
    pub window_ms: u64,
    pub read_end_skew_ms: u64,
    pub fast_n_bps: u64,
    pub fast_s_bps: u64,
    pub fast_total_bps: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastShadowComparison {
    pub edge_bps: Option<u64>,
    pub fast_n_bps: u64,
    pub fast_s_bps: u64,
    pub fast_total_bps: u64,
    pub absolute_delta_bps: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastRateTelemetry {
    pub valid_windows: u64,
    pub invalid_windows: u64,
    pub zero_windows: u64,
    pub last_sample_ms: Option<u64>,
    pub last_invalid_ms: Option<u64>,
    pub last_zero_latency_ms: Option<u64>,
    pub last_rise_latency_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastRateStore {
    latest: Option<FastRateSample>,
    telemetry: FastRateTelemetry,
}

impl FastRateStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) const fn latest(&self) -> Option<FastRateSample> {
        self.latest
    }

    pub(crate) const fn telemetry(&self) -> FastRateTelemetry {
        self.telemetry
    }

    pub(crate) fn publish(&mut self, window: FastWindow) -> FastRateSample {
        let sample = FastRateSample {
            sample_ms: window.end_ms,
            window_ms: window.duration_ms(),
            read_end_skew_ms: window.read_end_skew_ms,
            fast_n_bps: bytes_to_bps(window.n_bytes, window.duration_ms()),
            fast_s_bps: bytes_to_bps(window.s_bytes, window.duration_ms()),
            fast_total_bps: bytes_to_bps(window.total_bytes(), window.duration_ms()),
        };
        if let Some(previous) = self.latest {
            if previous.fast_total_bps != 0 && sample.fast_total_bps == 0 {
                self.telemetry.last_zero_latency_ms =
                    Some(sample.sample_ms.saturating_sub(previous.sample_ms));
            }
            if previous.fast_total_bps == 0 && sample.fast_total_bps != 0 {
                self.telemetry.last_rise_latency_ms =
                    Some(sample.sample_ms.saturating_sub(previous.sample_ms));
            }
        }
        self.telemetry.valid_windows = self.telemetry.valid_windows.saturating_add(1);
        if sample.fast_total_bps == 0 {
            self.telemetry.zero_windows = self.telemetry.zero_windows.saturating_add(1);
        }
        self.telemetry.last_sample_ms = Some(sample.sample_ms);
        self.latest = Some(sample);
        sample
    }

    pub(crate) fn record_invalid(&mut self, sample_ms: u64) {
        self.telemetry.invalid_windows = self.telemetry.invalid_windows.saturating_add(1);
        self.telemetry.last_invalid_ms = Some(sample_ms);
        self.latest = None;
    }

    pub(crate) fn compare_with_edge(&self, edge_bps: Option<u64>) -> Option<FastShadowComparison> {
        self.latest.map(|sample| FastShadowComparison {
            edge_bps,
            fast_n_bps: sample.fast_n_bps,
            fast_s_bps: sample.fast_s_bps,
            fast_total_bps: sample.fast_total_bps,
            absolute_delta_bps: edge_bps.map(|edge| edge.abs_diff(sample.fast_total_bps)),
        })
    }
}

fn bytes_to_bps(bytes: u64, window_ms: u64) -> u64 {
    if window_ms == 0 {
        return 0;
    }
    u128::from(bytes)
        .saturating_mul(8_000)
        .checked_div(u128::from(window_ms))
        .and_then(|bps| u64::try_from(bps).ok())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{FastRateStore, FastShadowComparison};
    use crate::platform::nss::fast_rate::FastWindow;

    fn window(end_ms: u64, n_bytes: u64, s_bytes: u64) -> FastWindow {
        FastWindow {
            start_ms: end_ms - 1_000,
            end_ms,
            read_end_skew_ms: 5,
            n_bytes,
            n_packets: n_bytes / 10,
            s_bytes,
            s_packets: s_bytes / 10,
            n_window_ms: 1_000,
            s_window_ms: 1_000,
        }
    }

    #[test]
    fn publishes_n_s_and_combined_rates_from_the_same_window() {
        let mut store = FastRateStore::new();
        let sample = store.publish(window(2_000, 1_000, 500));
        assert_eq!(sample.fast_n_bps, 8_000);
        assert_eq!(sample.fast_s_bps, 4_000);
        assert_eq!(sample.fast_total_bps, 12_000);
        assert_eq!(sample.window_ms, 1_000);
        assert_eq!(store.telemetry().valid_windows, 1);
    }

    #[test]
    fn invalid_and_zero_windows_are_telemetried_without_reusing_old_data() {
        let mut store = FastRateStore::new();
        store.record_invalid(900);
        assert_eq!(store.telemetry().invalid_windows, 1);
        assert!(store.latest().is_none());
        store.publish(window(1_000, 100, 0));
        store.publish(window(2_000, 0, 0));
        let telemetry = store.telemetry();
        assert_eq!(telemetry.zero_windows, 1);
        assert_eq!(telemetry.last_zero_latency_ms, Some(1_000));
    }

    #[test]
    fn edge_comparison_is_explicit_and_never_changes_the_stored_sample() {
        let mut store = FastRateStore::new();
        store.publish(window(1_000, 1_000, 500));
        assert_eq!(
            store.compare_with_edge(Some(10_000)),
            Some(FastShadowComparison {
                edge_bps: Some(10_000),
                fast_n_bps: 8_000,
                fast_s_bps: 4_000,
                fast_total_bps: 12_000,
                absolute_delta_bps: Some(2_000),
            })
        );
        assert_eq!(store.latest().unwrap().fast_total_bps, 12_000);
    }
}
