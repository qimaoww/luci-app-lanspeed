//! Bounded FastRate wakeup coalescing.

pub(crate) const FAST_RATE_DEBOUNCE_MS: u64 = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastRateWakeup {
    pub event_hint: bool,
    pub fixed_timer: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastRateWakeupTelemetry {
    pub event_received: u64,
    pub event_coalesced: u64,
    pub fixed_timer_wakeups: u64,
    pub last_event_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastRateWakeupBook {
    debounce_ms: u64,
    event_deadline_ms: Option<u64>,
    fixed_timer_deadline_ms: Option<u64>,
    telemetry: FastRateWakeupTelemetry,
}

impl Default for FastRateWakeupBook {
    fn default() -> Self {
        Self::new(FAST_RATE_DEBOUNCE_MS)
    }
}

impl FastRateWakeupBook {
    pub(crate) const fn new(debounce_ms: u64) -> Self {
        Self {
            debounce_ms,
            event_deadline_ms: None,
            fixed_timer_deadline_ms: None,
            telemetry: FastRateWakeupTelemetry {
                event_received: 0,
                event_coalesced: 0,
                fixed_timer_wakeups: 0,
                last_event_ms: None,
            },
        }
    }

    pub(crate) const fn telemetry(&self) -> FastRateWakeupTelemetry {
        self.telemetry
    }

    pub(crate) fn on_event_hint(&mut self, now_ms: u64) {
        self.on_event_hints(now_ms, 1);
    }

    pub(crate) fn on_event_hints(&mut self, now_ms: u64, count: u64) {
        if count == 0 {
            return;
        }
        self.telemetry.event_received = self.telemetry.event_received.saturating_add(count);
        self.telemetry.last_event_ms = Some(now_ms);
        if self.event_deadline_ms.is_some() {
            self.telemetry.event_coalesced = self.telemetry.event_coalesced.saturating_add(count);
            return;
        }
        self.event_deadline_ms = Some(now_ms.saturating_add(self.debounce_ms));
        self.telemetry.event_coalesced = self
            .telemetry
            .event_coalesced
            .saturating_add(count.saturating_sub(1));
    }

    pub(crate) fn on_fixed_timer(&mut self, now_ms: u64) {
        self.fixed_timer_deadline_ms = Some(
            self.fixed_timer_deadline_ms
                .map_or(now_ms, |deadline| deadline.min(now_ms)),
        );
        self.telemetry.fixed_timer_wakeups = self.telemetry.fixed_timer_wakeups.saturating_add(1);
    }

    pub(crate) fn defer_event_until(&mut self, deadline_ms: u64) {
        self.event_deadline_ms = Some(deadline_ms);
    }

    pub(crate) fn defer_fixed_until(&mut self, deadline_ms: u64) {
        self.fixed_timer_deadline_ms = Some(deadline_ms);
    }

    pub(crate) fn poll(&mut self, now_ms: u64) -> Option<FastRateWakeup> {
        let event_hint = self
            .event_deadline_ms
            .is_some_and(|deadline| now_ms >= deadline);
        let fixed_timer = self
            .fixed_timer_deadline_ms
            .is_some_and(|deadline| now_ms >= deadline);
        if !event_hint && !fixed_timer {
            return None;
        }

        if event_hint || fixed_timer {
            // A fixed read performed after an event arrived covers that hint
            // even when its debounce deadline has not elapsed yet.
            self.event_deadline_ms = None;
        }
        if fixed_timer {
            self.fixed_timer_deadline_ms = None;
        }
        Some(FastRateWakeup {
            event_hint,
            fixed_timer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{FastRateWakeup, FastRateWakeupBook, FAST_RATE_DEBOUNCE_MS};

    #[test]
    fn event_hints_are_debounced_and_coalesced() {
        let mut book = FastRateWakeupBook::default();
        book.on_event_hint(100);
        book.on_event_hint(105);
        assert!(book.poll(119).is_none());
        assert_eq!(
            book.poll(120),
            Some(FastRateWakeup {
                event_hint: true,
                fixed_timer: false,
            })
        );
        let telemetry = book.telemetry();
        assert_eq!(telemetry.event_received, 2);
        assert_eq!(telemetry.event_coalesced, 1);
        assert_eq!(telemetry.last_event_ms, Some(105));
    }

    #[test]
    fn event_batch_counts_every_hint_but_arms_one_deadline() {
        let mut book = FastRateWakeupBook::default();
        book.on_event_hints(100, 4);
        assert!(book.poll(119).is_none());
        assert_eq!(
            book.poll(120),
            Some(FastRateWakeup {
                event_hint: true,
                fixed_timer: false,
            })
        );
        let telemetry = book.telemetry();
        assert_eq!(telemetry.event_received, 4);
        assert_eq!(telemetry.event_coalesced, 3);
    }

    #[test]
    fn deferred_event_keeps_coalescing_until_the_rate_window_is_eligible() {
        let mut book = FastRateWakeupBook::default();
        book.on_event_hint(100);
        assert!(book.poll(120).is_some());
        book.defer_event_until(1_000);
        book.on_event_hints(500, 3);
        assert!(book.poll(999).is_none());
        assert_eq!(
            book.poll(1_000),
            Some(FastRateWakeup {
                event_hint: true,
                fixed_timer: false,
            })
        );
        let telemetry = book.telemetry();
        assert_eq!(telemetry.event_received, 4);
        assert_eq!(telemetry.event_coalesced, 3);
    }

    #[test]
    fn fixed_timer_wakes_without_an_event_and_merges_with_a_pending_hint() {
        let mut book = FastRateWakeupBook::new(FAST_RATE_DEBOUNCE_MS);
        book.on_fixed_timer(0);
        assert_eq!(
            book.poll(0),
            Some(FastRateWakeup {
                event_hint: false,
                fixed_timer: true,
            })
        );

        book.on_event_hint(100);
        book.on_fixed_timer(100);
        assert_eq!(
            book.poll(100),
            Some(FastRateWakeup {
                event_hint: false,
                fixed_timer: true,
            })
        );
        assert!(book.poll(120).is_none());
        assert_eq!(book.telemetry().fixed_timer_wakeups, 2);
    }

    #[test]
    fn deferred_fixed_timer_waits_without_counting_a_second_tick() {
        let mut book = FastRateWakeupBook::default();
        book.on_fixed_timer(1_000);
        assert!(book.poll(1_000).is_some());
        book.defer_fixed_until(1_100);
        assert!(book.poll(1_099).is_none());
        assert_eq!(
            book.poll(1_100),
            Some(FastRateWakeup {
                event_hint: false,
                fixed_timer: true,
            })
        );
        assert_eq!(book.telemetry().fixed_timer_wakeups, 1);
    }

    #[test]
    fn event_poll_does_not_remove_a_future_fixed_timer() {
        let mut book = FastRateWakeupBook::default();
        book.on_fixed_timer(1_000);
        book.on_event_hint(100);
        assert_eq!(
            book.poll(120),
            Some(FastRateWakeup {
                event_hint: true,
                fixed_timer: false,
            })
        );
        assert_eq!(
            book.poll(1_000),
            Some(FastRateWakeup {
                event_hint: false,
                fixed_timer: true,
            })
        );
    }

    #[test]
    fn no_wakeup_is_returned_before_either_deadline() {
        let mut book = FastRateWakeupBook::default();
        book.on_event_hint(u64::MAX - 1);
        assert!(book.poll(u64::MAX - 2).is_none());
        assert!(book.poll(u64::MAX).is_some());
    }
}
