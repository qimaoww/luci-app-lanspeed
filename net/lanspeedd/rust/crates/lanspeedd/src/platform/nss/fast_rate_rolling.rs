//! Bounded rolling windows for routed FastN+FastS client rates.
//!
//! NSS publishes FastN counters in hardware batches. The timestamp of the
//! last counter touched inside a batch is useful evidence of progress, but it
//! is not a stable rate denominator. This book keeps cumulative counter pairs
//! on the completed userspace read clock and publishes their difference
//! across a bounded rolling interval.

use std::collections::VecDeque;

use super::fast_rate::{
    FastCounterSample, FastWindow, FastWindowError, FAST_WINDOW_MAX_READ_END_SKEW_MS,
    FAST_WINDOW_QUIET_CONFIRM_MS,
};

pub(crate) const FAST_RATE_ROLLING_WINDOW_MS: u64 = 2_000;
const FAST_RATE_ROLLING_MAX_SAMPLES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CounterPair {
    n: FastCounterSample,
    s: FastCounterSample,
}

impl CounterPair {
    const fn end_ms(self) -> u64 {
        if self.n.read_end_ms < self.s.read_end_ms {
            self.n.read_end_ms
        } else {
            self.s.read_end_ms
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastRateRollingWindow {
    history: VecDeque<CounterPair>,
}

impl FastRateRollingWindow {
    pub(crate) fn observe(
        &mut self,
        n: FastCounterSample,
        s: FastCounterSample,
    ) -> Result<Option<FastWindow>, FastWindowError> {
        validate_pair(n, s)?;
        let current = CounterPair { n, s };
        if self
            .history
            .back()
            .is_some_and(|previous| current.end_ms() <= previous.end_ms())
        {
            return Err(FastWindowError::TimeDidNotAdvance);
        }
        self.history.push_back(current);
        while self.history.len() > FAST_RATE_ROLLING_MAX_SAMPLES {
            self.history.pop_front();
        }

        let target_ms = current.end_ms().saturating_sub(FAST_RATE_ROLLING_WINDOW_MS);
        let Some(mut start_index) = self
            .history
            .iter()
            .rposition(|sample| sample.end_ms() <= target_ms)
        else {
            return Ok(None);
        };
        let mut window = finish(self.history[start_index], current);
        if window.as_ref().is_ok_and(|window| {
            window.total_bytes() == 0
                && window.total_packets() == 0
                && window.duration_ms() < FAST_WINDOW_QUIET_CONFIRM_MS
        }) {
            // Two unchanged one-second reads are not sufficient proof of zero
            // on a batched NSS counter plane. Extend the rolling baseline to
            // the existing quiet guard before replacing the last valid rate.
            let quiet_target_ms = current
                .end_ms()
                .saturating_sub(FAST_WINDOW_QUIET_CONFIRM_MS);
            let Some(quiet_start_index) = self
                .history
                .iter()
                .rposition(|sample| sample.end_ms() <= quiet_target_ms)
            else {
                return Ok(None);
            };
            start_index = quiet_start_index;
            window = finish(self.history[start_index], current);
        }
        match window {
            Ok(window) => {
                for _ in 0..start_index {
                    self.history.pop_front();
                }
                Ok(Some(window))
            }
            Err(error) => {
                self.history.clear();
                self.history.push_back(current);
                Err(error)
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        self.history.clear();
    }
}

fn validate_pair(n: FastCounterSample, s: FastCounterSample) -> Result<(), FastWindowError> {
    if n.read_end_ms < n.read_begin_ms || s.read_end_ms < s.read_begin_ms {
        return Err(FastWindowError::InvalidReadInterval);
    }
    let skew_ms = n.read_end_ms.abs_diff(s.read_end_ms);
    if skew_ms > FAST_WINDOW_MAX_READ_END_SKEW_MS {
        return Err(FastWindowError::ReadEndSkew {
            skew_ms,
            max_ms: FAST_WINDOW_MAX_READ_END_SKEW_MS,
        });
    }
    Ok(())
}

fn finish(start: CounterPair, end: CounterPair) -> Result<FastWindow, FastWindowError> {
    if end.n.attachment_generation != start.n.attachment_generation
        || end.s.attachment_generation != start.s.attachment_generation
        || end.n.attachment_generation != end.s.attachment_generation
    {
        return Err(FastWindowError::AttachmentGenerationChanged);
    }
    if end.n.reset_generation != start.n.reset_generation
        || end.s.reset_generation != start.s.reset_generation
    {
        return Err(FastWindowError::ResetGenerationChanged);
    }
    if end.n.bytes < start.n.bytes
        || end.n.packets < start.n.packets
        || end.s.bytes < start.s.bytes
        || end.s.packets < start.s.packets
    {
        return Err(FastWindowError::CounterReset);
    }

    let start_ms = start.n.read_end_ms.max(start.s.read_end_ms);
    let end_ms = end.n.read_end_ms.min(end.s.read_end_ms);
    let n_window_ms = end.n.read_end_ms.saturating_sub(start.n.read_end_ms);
    let s_window_ms = end.s.read_end_ms.saturating_sub(start.s.read_end_ms);
    if end_ms <= start_ms || n_window_ms == 0 || s_window_ms == 0 {
        return Err(FastWindowError::TimeDidNotAdvance);
    }
    Ok(FastWindow {
        start_ms,
        end_ms,
        read_end_skew_ms: start
            .n
            .read_end_ms
            .abs_diff(start.s.read_end_ms)
            .max(end.n.read_end_ms.abs_diff(end.s.read_end_ms)),
        n_bytes: end.n.bytes - start.n.bytes,
        n_packets: end.n.packets - start.n.packets,
        s_bytes: end.s.bytes - start.s.bytes,
        s_packets: end.s.packets - start.s.packets,
        n_window_ms,
        s_window_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::{FastRateRollingWindow, FAST_RATE_ROLLING_WINDOW_MS};
    use crate::platform::nss::fast_rate::{FastCounterSample, FastWindowError};

    fn sample(read_end_ms: u64, bytes: u64) -> FastCounterSample {
        FastCounterSample {
            sample_ms: read_end_ms,
            progress_ms: read_end_ms,
            source_present: true,
            read_begin_ms: read_end_ms.saturating_sub(5),
            read_end_ms,
            attachment_generation: 7,
            reset_generation: 1,
            bytes,
            packets: bytes / 100,
        }
    }

    #[test]
    fn publishes_over_a_completed_two_second_read_window() {
        let mut rolling = FastRateRollingWindow::default();
        assert_eq!(FAST_RATE_ROLLING_WINDOW_MS, 2_000);
        assert_eq!(
            rolling.observe(sample(1_000, 100), sample(1_001, 50)),
            Ok(None)
        );
        assert_eq!(
            rolling.observe(sample(2_000, 200), sample(2_001, 100)),
            Ok(None)
        );
        let window = rolling
            .observe(sample(3_000, 500), sample(3_001, 250))
            .unwrap()
            .expect("complete rolling window");
        assert_eq!(window.duration_ms(), 2_000);
        assert_eq!(window.n_bytes, 400);
        assert_eq!(window.s_bytes, 200);
    }

    #[test]
    fn adjacent_publications_overlap_instead_of_resetting_the_baseline() {
        let mut rolling = FastRateRollingWindow::default();
        rolling
            .observe(sample(1_000, 100), sample(1_001, 50))
            .unwrap();
        rolling
            .observe(sample(2_000, 200), sample(2_001, 100))
            .unwrap();
        rolling
            .observe(sample(3_000, 500), sample(3_001, 250))
            .unwrap();
        let window = rolling
            .observe(sample(4_000, 700), sample(4_001, 350))
            .unwrap()
            .expect("second rolling window");
        assert_eq!(window.duration_ms(), 2_000);
        assert_eq!(window.n_bytes, 500);
        assert_eq!(window.s_bytes, 250);
    }

    #[test]
    fn unchanged_counters_wait_for_quiet_confirmation() {
        let mut rolling = FastRateRollingWindow::default();
        rolling
            .observe(sample(1_000, 100), sample(1_001, 50))
            .unwrap();
        rolling
            .observe(sample(2_000, 100), sample(2_001, 50))
            .unwrap();
        assert_eq!(
            rolling.observe(sample(3_000, 100), sample(3_001, 50)),
            Ok(None)
        );
        let zero = rolling
            .observe(sample(4_000, 100), sample(4_001, 50))
            .unwrap()
            .expect("confirmed rolling zero");
        assert_eq!(zero.duration_ms(), 3_000);
        assert_eq!(zero.total_bytes(), 0);
    }

    #[test]
    fn generation_change_rewarms_from_the_current_pair() {
        let mut rolling = FastRateRollingWindow::default();
        rolling
            .observe(sample(1_000, 100), sample(1_001, 50))
            .unwrap();
        rolling
            .observe(sample(2_000, 200), sample(2_001, 100))
            .unwrap();
        let mut reset_n = sample(3_000, 10);
        let mut reset_s = sample(3_001, 5);
        reset_n.reset_generation = 2;
        reset_s.reset_generation = 2;
        assert_eq!(
            rolling.observe(reset_n, reset_s),
            Err(FastWindowError::ResetGenerationChanged)
        );

        let mut next_n = sample(5_000, 210);
        let mut next_s = sample(5_001, 105);
        next_n.reset_generation = 2;
        next_s.reset_generation = 2;
        let window = rolling
            .observe(next_n, next_s)
            .unwrap()
            .expect("new generation rolling window");
        assert_eq!(window.n_bytes, 200);
        assert_eq!(window.s_bytes, 100);
    }
}
