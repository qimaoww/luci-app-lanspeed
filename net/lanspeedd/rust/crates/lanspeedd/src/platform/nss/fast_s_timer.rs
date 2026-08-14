//! Fixed-cadence wakeups for the NSS FastS path.
//!
//! The timer is intentionally independent from ECM RingBuf hints. A hint can
//! wake the rate worker earlier, but it cannot suppress this fixed cadence:
//! CPU/proxy traffic may have no NSS callback at all.

pub(crate) const FAST_S_INTERVAL_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastSTick {
    /// The fixed schedule point that caused this tick.
    pub scheduled_ms: u64,
    /// The monotonic time at which the worker observed the tick.
    pub observed_ms: u64,
    /// Number of schedule points skipped before this tick was observed.
    pub missed_ticks: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastSTimer {
    interval_ms: u64,
    next_deadline_ms: Option<u64>,
    last_observed_ms: Option<u64>,
}

impl Default for FastSTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl FastSTimer {
    pub(crate) const fn new() -> Self {
        Self {
            interval_ms: FAST_S_INTERVAL_MS,
            next_deadline_ms: None,
            last_observed_ms: None,
        }
    }

    /// Start from an immediate tick. The first sample must not wait for the
    /// first full interval after the rate worker starts.
    pub(crate) fn start(&mut self, now_ms: u64) {
        self.next_deadline_ms = Some(now_ms);
        self.last_observed_ms = None;
    }

    pub(crate) fn reset(&mut self) {
        self.next_deadline_ms = None;
        self.last_observed_ms = None;
    }

    pub(crate) const fn last_observed_ms(&self) -> Option<u64> {
        self.last_observed_ms
    }

    pub(crate) fn due(&self, now_ms: u64) -> bool {
        self.next_deadline_ms
            .is_some_and(|deadline_ms| now_ms >= deadline_ms)
    }

    /// Consume at most one tick and advance by whole fixed intervals.
    ///
    /// Advancing from the scheduled deadline (rather than from `now_ms`)
    /// preserves cadence after a delayed worker wakeup. Missed intervals are
    /// reported to telemetry but are never replayed as a burst of samples.
    pub(crate) fn poll(&mut self, now_ms: u64) -> Option<FastSTick> {
        let scheduled_ms = self.next_deadline_ms?;
        if now_ms < scheduled_ms {
            return None;
        }

        let elapsed_ms = now_ms.saturating_sub(scheduled_ms);
        let missed_ticks = elapsed_ms / self.interval_ms;
        let advance_ms = missed_ticks
            .saturating_add(1)
            .saturating_mul(self.interval_ms);
        self.next_deadline_ms = Some(scheduled_ms.saturating_add(advance_ms));
        self.last_observed_ms = Some(now_ms);
        Some(FastSTick {
            scheduled_ms,
            observed_ms: now_ms,
            missed_ticks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{FastSTick, FastSTimer, FAST_S_INTERVAL_MS};

    #[test]
    fn starts_with_an_immediate_fixed_tick() {
        let mut timer = FastSTimer::new();
        timer.start(10_000);
        assert!(timer.due(10_000));
        assert_eq!(
            timer.poll(10_000).unwrap(),
            FastSTick {
                scheduled_ms: 10_000,
                observed_ms: 10_000,
                missed_ticks: 0,
            }
        );
        assert!(!timer.due(10_000 + FAST_S_INTERVAL_MS - 1));
        assert_eq!(timer.last_observed_ms(), Some(10_000));
    }

    #[test]
    fn delayed_wakeup_reports_missed_ticks_without_bursting() {
        let mut timer = FastSTimer::new();
        timer.start(0);
        let _ = timer.poll(0);
        let tick = timer.poll(3_501).unwrap();
        assert_eq!(tick.scheduled_ms, FAST_S_INTERVAL_MS);
        assert_eq!(tick.observed_ms, 3_501);
        assert_eq!(tick.missed_ticks, 2);
        assert!(!timer.due(3_501));
        assert!(timer.due(4_000));
    }

    #[test]
    fn reset_requires_an_explicit_restart() {
        let mut timer = FastSTimer::new();
        timer.start(5);
        let _ = timer.poll(5);
        timer.reset();
        assert!(!timer.due(u64::MAX));
        assert!(timer.poll(u64::MAX).is_none());
        timer.start(20);
        assert_eq!(timer.poll(20).unwrap().scheduled_ms, 20);
    }
}
