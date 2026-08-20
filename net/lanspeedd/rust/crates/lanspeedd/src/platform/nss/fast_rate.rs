//! Same-window FastN/FastS coordination.
//!
//! The coordinator consumes cumulative samples only after their individual
//! stable-read protocol has succeeded. It never adds two independently
//! computed rates; both deltas must come from one shared start/end window.

pub(crate) const FAST_WINDOW_MAX_READ_END_SKEW_MS: u64 = 250;
/// FastN is normally published in roughly two-second hardware batches.  A
/// single unchanged one-second read is therefore not proof of zero traffic.
/// Once the same stable cumulative pair remains unchanged beyond this guard,
/// the fixed timer may publish a real zero window without consuming the raw
/// baseline used by the next counter batch.
pub(crate) const FAST_WINDOW_QUIET_CONFIRM_MS: u64 = 2_500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastCounterSample {
    /// Common event clock used to validate that the two maps were read as one
    /// publication.  The worker sets this to the latest progress observed in
    /// either source so N/S skew is checked independently from the rate
    /// denominator.
    pub sample_ms: u64,
    /// Counter-progress clock belonging to this source.  FastN and FastS do
    /// not necessarily update at the same cadence; keeping their clocks
    /// separate prevents a faster source from shrinking the denominator for
    /// a batched source.
    pub progress_ms: u64,
    /// Whether this source has a real cumulative counter for the key.  A
    /// missing FastN/FastS key is represented by a synthetic zero source and
    /// is allowed to participate in an N-only or S-only window.
    pub source_present: bool,
    pub read_begin_ms: u64,
    pub read_end_ms: u64,
    pub attachment_generation: u64,
    pub reset_generation: u32,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastWindow {
    pub start_ms: u64,
    pub end_ms: u64,
    pub read_end_skew_ms: u64,
    pub n_bytes: u64,
    pub n_packets: u64,
    pub s_bytes: u64,
    pub s_packets: u64,
    pub n_window_ms: u64,
    pub s_window_ms: u64,
}

impl FastWindow {
    pub(crate) const fn total_bytes(self) -> u64 {
        self.n_bytes.saturating_add(self.s_bytes)
    }

    pub(crate) const fn total_packets(self) -> u64 {
        self.n_packets.saturating_add(self.s_packets)
    }

    pub(crate) const fn duration_ms(self) -> u64 {
        let source_window = if self.n_window_ms > self.s_window_ms {
            self.n_window_ms
        } else {
            self.s_window_ms
        };
        if source_window != 0 {
            source_window
        } else {
            self.end_ms.saturating_sub(self.start_ms)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FastWindowError {
    InvalidReadInterval,
    ReadEndSkew { skew_ms: u64, max_ms: u64 },
    SampleSkew { skew_ms: u64, max_ms: u64 },
    AttachmentGenerationChanged,
    ResetGenerationChanged,
    TimeDidNotAdvance,
    CounterReset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FastCounterPair {
    n: FastCounterSample,
    s: FastCounterSample,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastRateCoordinator {
    max_read_end_skew_ms: u64,
    start: Option<FastCounterPair>,
}

impl Default for FastRateCoordinator {
    fn default() -> Self {
        Self::new(FAST_WINDOW_MAX_READ_END_SKEW_MS)
    }
}

impl FastRateCoordinator {
    pub(crate) const fn new(max_read_end_skew_ms: u64) -> Self {
        Self {
            max_read_end_skew_ms,
            start: None,
        }
    }

    pub(crate) const fn max_read_end_skew_ms(&self) -> u64 {
        self.max_read_end_skew_ms
    }

    pub(crate) const fn has_start(&self) -> bool {
        self.start.is_some()
    }

    /// Return whether the current pair can produce a new counter window.
    ///
    /// ECM may publish a cumulative map in bursts. Re-reading an unchanged
    /// pair must keep the last valid rate alive instead of turning the burst
    /// cadence into alternating zero and spike windows. Generation changes
    /// still force a validation pass so resets cannot be hidden by the hold.
    pub(crate) fn has_progress(&self, n: FastCounterSample, s: FastCounterSample) -> bool {
        let Some(start) = self.start else {
            return true;
        };
        if n.reset_generation != start.n.reset_generation
            || s.reset_generation != start.s.reset_generation
        {
            return true;
        }
        let n_progress = source_progressed(n, start.n);
        let s_progress = source_progressed(s, start.s);
        // FastN is the batched routed plane. When it exists, its progress
        // closes the shared raw N+S window; an unchanged FastS counter is a
        // valid zero contribution to that same window. FastS-only progress
        // must not cut a pending FastN batch into alternating low/high rates.
        // If no FastN key exists, the fixed timer still lets pure CPU/proxy
        // FastS traffic close and publish the shared window on its own.
        match (n.source_present, s.source_present) {
            (true, true) => n_progress,
            (true, false) => n_progress,
            (false, true) => s_progress,
            (false, false) => false,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.start = None;
    }

    /// Return a same-window zero after both stable cumulative counters have
    /// remained unchanged for the quiet-confirmation interval.
    ///
    /// This deliberately borrows the coordinator start instead of consuming
    /// it.  The next non-zero FastN/FastS batch must still be calculated from
    /// the original raw counter baseline; rebasing on a synthetic timer clock
    /// would shorten its denominator and create a spike.
    pub(crate) fn confirmed_quiet_window(
        &self,
        n: FastCounterSample,
        s: FastCounterSample,
        min_quiet_ms: u64,
    ) -> Result<Option<FastWindow>, FastWindowError> {
        let Some(start) = self.start else {
            return Ok(None);
        };
        if n.bytes < start.n.bytes
            || n.packets < start.n.packets
            || s.bytes < start.s.bytes
            || s.packets < start.s.packets
        {
            return Err(FastWindowError::CounterReset);
        }
        if n.bytes != start.n.bytes
            || n.packets != start.n.packets
            || s.bytes != start.s.bytes
            || s.packets != start.s.packets
        {
            return Ok(None);
        }

        let start_ms = start.n.read_end_ms.max(start.s.read_end_ms);
        let end_ms = n.read_end_ms.min(s.read_end_ms);
        let window_ms = end_ms.saturating_sub(start_ms);
        if window_ms < min_quiet_ms || window_ms == 0 {
            return Ok(None);
        }
        validate_pair(n, s, self.max_read_end_skew_ms)?;
        if n.attachment_generation != start.n.attachment_generation
            || s.attachment_generation != start.s.attachment_generation
            || n.attachment_generation != s.attachment_generation
        {
            return Err(FastWindowError::AttachmentGenerationChanged);
        }
        if n.reset_generation != start.n.reset_generation
            || s.reset_generation != start.s.reset_generation
        {
            return Err(FastWindowError::ResetGenerationChanged);
        }

        let start_read_end_skew_ms = read_end_skew(start.n.read_end_ms, start.s.read_end_ms);
        let end_read_end_skew_ms = read_end_skew(n.read_end_ms, s.read_end_ms);
        Ok(Some(FastWindow {
            start_ms,
            end_ms,
            read_end_skew_ms: start_read_end_skew_ms.max(end_read_end_skew_ms),
            n_bytes: 0,
            n_packets: 0,
            s_bytes: 0,
            s_packets: 0,
            n_window_ms: window_ms,
            s_window_ms: window_ms,
        }))
    }

    pub(crate) fn begin(
        &mut self,
        n: FastCounterSample,
        s: FastCounterSample,
    ) -> Result<(), FastWindowError> {
        validate_pair(n, s, self.max_read_end_skew_ms)?;
        self.start = Some(FastCounterPair { n, s });
        Ok(())
    }

    pub(crate) fn finish(
        &mut self,
        n: FastCounterSample,
        s: FastCounterSample,
    ) -> Result<FastWindow, FastWindowError> {
        let Some(start) = self.start.take() else {
            return Err(FastWindowError::TimeDidNotAdvance);
        };
        if let Err(error) = validate_pair(n, s, self.max_read_end_skew_ms) {
            return Err(error);
        }
        if n.attachment_generation != start.n.attachment_generation
            || s.attachment_generation != start.s.attachment_generation
            || n.attachment_generation != s.attachment_generation
        {
            return Err(FastWindowError::AttachmentGenerationChanged);
        }
        // FastN and FastS are independent maps, so their reset counters are
        // intentionally not required to have the same numeric value. A
        // window is valid only when each source remains on its own generation
        // from start to end.
        if n.reset_generation != start.n.reset_generation
            || s.reset_generation != start.s.reset_generation
        {
            return Err(FastWindowError::ResetGenerationChanged);
        }
        let n_progress_ms = effective_progress_ms(n);
        let s_progress_ms = effective_progress_ms(s);
        let start_n_progress_ms = effective_progress_ms(start.n);
        let start_s_progress_ms = effective_progress_ms(start.s);
        let n_progressed = effective_progress_ms(n) > effective_progress_ms(start.n);
        let s_progressed = effective_progress_ms(s) > effective_progress_ms(start.s);
        if n_progress_ms < start_n_progress_ms || s_progress_ms < start_s_progress_ms {
            return Err(FastWindowError::CounterReset);
        }
        // Some NSS map producers update cumulative bytes before refreshing
        // their last-seen timestamp.  A timestamp-only gate would then hold
        // a valid one-second delta until the next hardware batch.  When both
        // sources advance only by counters, use the completed map-read clock
        // for the publication timestamp; the per-source denominator below
        // already retains the progress clock whenever it is available.
        let progress_clock_advanced = n_progressed || s_progressed;
        let start_ms = if progress_clock_advanced {
            start.n.sample_ms.max(start.s.sample_ms)
        } else {
            start.n.read_end_ms.max(start.s.read_end_ms)
        };
        let end_ms = if progress_clock_advanced {
            n.sample_ms.min(s.sample_ms)
        } else {
            n.read_end_ms.min(s.read_end_ms)
        };
        // `last_seen_ns` is a progress hint, not an aggregate rate clock:
        // taking the maximum across CPUs can let a tiny packet on one CPU
        // shorten the denominator for a much larger batch on another CPU.
        // The counter progress clock describes the interval represented by a
        // batched ECM/NSS update. Stable map read ends are only an observation
        // fallback for synthetic inputs that do not carry progress timestamps;
        // using them first would spread one batch over an unrelated 1-3 second
        // userspace scheduling interval.
        let n_window_ms = elapsed_or_progress(
            n.read_end_ms,
            start.n.read_end_ms,
            n_progress_ms,
            start_n_progress_ms,
        );
        let s_window_ms = elapsed_or_progress(
            s.read_end_ms,
            start.s.read_end_ms,
            s_progress_ms,
            start_s_progress_ms,
        );
        if end_ms <= start_ms && n_window_ms == 0 && s_window_ms == 0 {
            return Err(FastWindowError::TimeDidNotAdvance);
        }
        if n.bytes < start.n.bytes
            || n.packets < start.n.packets
            || s.bytes < start.s.bytes
            || s.packets < start.s.packets
        {
            return Err(FastWindowError::CounterReset);
        }
        let start_read_end_skew_ms = read_end_skew(start.n.read_end_ms, start.s.read_end_ms);
        let end_read_end_skew_ms = read_end_skew(n.read_end_ms, s.read_end_ms);
        Ok(FastWindow {
            start_ms,
            end_ms,
            read_end_skew_ms: start_read_end_skew_ms.max(end_read_end_skew_ms),
            n_bytes: n.bytes - start.n.bytes,
            n_packets: n.packets - start.n.packets,
            s_bytes: s.bytes - start.s.bytes,
            s_packets: s.packets - start.s.packets,
            n_window_ms,
            s_window_ms,
        })
    }
}

fn effective_progress_ms(sample: FastCounterSample) -> u64 {
    if sample.progress_ms == 0 {
        sample.sample_ms
    } else {
        sample.progress_ms
    }
}

fn source_progressed(current: FastCounterSample, start: FastCounterSample) -> bool {
    effective_progress_ms(current) > effective_progress_ms(start)
        || current.bytes > start.bytes
        || current.packets > start.packets
}

fn elapsed_or_progress(
    end_read_ms: u64,
    start_read_ms: u64,
    end_progress_ms: u64,
    start_progress_ms: u64,
) -> u64 {
    let progress_elapsed = end_progress_ms.saturating_sub(start_progress_ms);
    if progress_elapsed != 0 {
        progress_elapsed
    } else {
        end_read_ms.saturating_sub(start_read_ms)
    }
}

fn validate_pair(
    n: FastCounterSample,
    s: FastCounterSample,
    max_skew_ms: u64,
) -> Result<(), FastWindowError> {
    if n.read_end_ms < n.read_begin_ms || s.read_end_ms < s.read_begin_ms {
        return Err(FastWindowError::InvalidReadInterval);
    }
    let read_end_skew_ms = read_end_skew(n.read_end_ms, s.read_end_ms);
    if read_end_skew_ms > max_skew_ms {
        return Err(FastWindowError::ReadEndSkew {
            skew_ms: read_end_skew_ms,
            max_ms: max_skew_ms,
        });
    }
    let sample_skew_ms = n.sample_ms.abs_diff(s.sample_ms);
    if sample_skew_ms > max_skew_ms {
        return Err(FastWindowError::SampleSkew {
            skew_ms: sample_skew_ms,
            max_ms: max_skew_ms,
        });
    }
    Ok(())
}

fn read_end_skew(n_end_ms: u64, s_end_ms: u64) -> u64 {
    n_end_ms.abs_diff(s_end_ms)
}

#[cfg(test)]
mod tests {
    use super::{
        FastCounterSample, FastRateCoordinator, FastWindowError, FAST_WINDOW_MAX_READ_END_SKEW_MS,
    };

    fn sample(sample_ms: u64, read_end_ms: u64, bytes: u64, packets: u64) -> FastCounterSample {
        FastCounterSample {
            sample_ms,
            progress_ms: sample_ms,
            source_present: true,
            read_begin_ms: read_end_ms.saturating_sub(10),
            read_end_ms,
            attachment_generation: 4,
            reset_generation: 2,
            bytes,
            packets,
        }
    }

    #[test]
    fn produces_n_and_s_deltas_from_one_shared_window() {
        let mut coordinator = FastRateCoordinator::default();
        coordinator
            .begin(sample(1_000, 1_010, 100, 10), sample(1_004, 1_014, 50, 5))
            .unwrap();
        let window = coordinator
            .finish(sample(2_000, 2_010, 700, 70), sample(2_004, 2_014, 350, 35))
            .unwrap();
        assert_eq!(window.start_ms, 1_004);
        assert_eq!(window.end_ms, 2_000);
        assert_eq!(window.read_end_skew_ms, 4);
        assert_eq!(window.n_bytes, 600);
        assert_eq!(window.s_bytes, 300);
        assert_eq!(window.total_bytes(), 900);
        assert_eq!(window.total_packets(), 90);
        assert_eq!(window.duration_ms(), 1_000);
        assert_eq!(window.n_window_ms, 1_000);
        assert_eq!(window.s_window_ms, 1_000);
    }

    #[test]
    fn encloses_fastn_batches_without_using_fast_s_short_interval() {
        let mut coordinator = FastRateCoordinator::default();
        let mut first_n = sample(1_000, 1_010, 100, 10);
        first_n.progress_ms = 1_000;
        let mut first_s = sample(1_000, 1_014, 50, 5);
        first_s.progress_ms = 1_000;
        coordinator.begin(first_n, first_s).unwrap();

        let mut next_n = sample(2_000, 4_010, 300, 30);
        next_n.progress_ms = 3_000;
        let mut next_s = sample(2_000, 4_014, 70, 7);
        next_s.progress_ms = 2_200;
        let window = coordinator.finish(next_n, next_s).unwrap();

        assert_eq!(window.n_window_ms, 2_000);
        assert_eq!(window.s_window_ms, 1_200);
        assert_eq!(window.duration_ms(), 2_000);
        assert_eq!(window.n_bytes, 200);
        assert_eq!(window.s_bytes, 20);
    }

    #[test]
    fn fastn_progress_closes_a_window_when_fasts_is_unchanged() {
        let mut coordinator = FastRateCoordinator::default();
        let first_n = sample(1_000, 1_010, 100, 10);
        let first_s = sample(1_000, 1_014, 50, 5);
        coordinator.begin(first_n, first_s).unwrap();

        let next_n = sample(2_000, 2_010, 300, 30);
        let mut unchanged_s = first_s;
        unchanged_s.sample_ms = 2_000;
        unchanged_s.read_begin_ms = 2_004;
        unchanged_s.read_end_ms = 2_014;

        assert!(coordinator.has_progress(next_n, unchanged_s));
        let window = coordinator.finish(next_n, unchanged_s).unwrap();
        assert_eq!(window.n_bytes, 200);
        assert_eq!(window.s_bytes, 0);
        assert_eq!(window.duration_ms(), 1_000);
    }

    #[test]
    fn counter_progress_closes_a_window_when_last_seen_clock_is_unchanged() {
        let mut coordinator = FastRateCoordinator::default();
        let mut first = sample(1_000, 1_010, 100, 10);
        first.progress_ms = 777;
        let mut second = sample(1_000, 2_010, 300, 30);
        second.progress_ms = 777;
        coordinator.begin(first, first).unwrap();

        assert!(coordinator.has_progress(second, second));
        let window = coordinator.finish(second, second).unwrap();
        assert_eq!(window.start_ms, 1_010);
        assert_eq!(window.end_ms, 2_010);
        assert_eq!(window.n_bytes, 200);
        assert_eq!(window.duration_ms(), 1_000);
    }

    #[test]
    fn rejects_large_start_or_end_read_skew() {
        let mut coordinator = FastRateCoordinator::new(10);
        assert_eq!(
            coordinator.begin(sample(1_000, 1_010, 0, 0), sample(1_100, 1_100, 0, 0)),
            Err(FastWindowError::ReadEndSkew {
                skew_ms: 90,
                max_ms: 10,
            })
        );
        coordinator
            .begin(sample(1_000, 1_010, 0, 0), sample(1_004, 1_014, 0, 0))
            .unwrap();
        assert_eq!(
            coordinator.finish(sample(2_000, 2_010, 1, 1), sample(2_004, 2_030, 1, 1)),
            Err(FastWindowError::ReadEndSkew {
                skew_ms: 20,
                max_ms: 10,
            })
        );
    }

    #[test]
    fn rejects_generation_reset_and_counter_decrease() {
        let mut coordinator = FastRateCoordinator::default();
        coordinator
            .begin(sample(1_000, 1_010, 100, 10), sample(1_000, 1_010, 50, 5))
            .unwrap();
        let mut generation = sample(2_000, 2_010, 200, 20);
        generation.attachment_generation += 1;
        assert_eq!(
            coordinator.finish(generation, sample(2_000, 2_010, 100, 10)),
            Err(FastWindowError::AttachmentGenerationChanged)
        );

        coordinator
            .begin(sample(3_000, 3_010, 100, 10), sample(3_000, 3_010, 50, 5))
            .unwrap();
        let mut reset = sample(4_000, 4_010, 200, 20);
        reset.reset_generation += 1;
        assert_eq!(
            coordinator.finish(reset, sample(4_000, 4_010, 100, 10)),
            Err(FastWindowError::ResetGenerationChanged)
        );

        coordinator
            .begin(sample(5_000, 5_010, 100, 10), sample(5_000, 5_010, 50, 5))
            .unwrap();
        assert_eq!(
            coordinator.finish(sample(6_000, 6_010, 99, 10), sample(6_000, 6_010, 50, 5)),
            Err(FastWindowError::CounterReset)
        );
    }

    #[test]
    fn clear_and_missing_start_do_not_reuse_a_previous_window() {
        let mut coordinator = FastRateCoordinator::default();
        assert_eq!(
            coordinator.finish(sample(1_000, 1_010, 1, 1), sample(1_000, 1_010, 1, 1)),
            Err(FastWindowError::TimeDidNotAdvance)
        );
        coordinator
            .begin(sample(1_000, 1_010, 0, 0), sample(1_000, 1_010, 0, 0))
            .unwrap();
        coordinator.clear();
        assert_eq!(
            coordinator.finish(sample(2_000, 2_010, 1, 1), sample(2_000, 2_010, 1, 1)),
            Err(FastWindowError::TimeDidNotAdvance)
        );
        assert_eq!(
            coordinator.max_read_end_skew_ms(),
            FAST_WINDOW_MAX_READ_END_SKEW_MS
        );
    }

    #[test]
    fn unchanged_pair_requires_quiet_confirmation_before_a_zero_window() {
        let mut coordinator = FastRateCoordinator::default();
        let first = sample(1_000, 1_010, 100, 10);
        coordinator.begin(first, first).unwrap();
        assert!(!coordinator.has_progress(first, first));

        let mut early = first;
        early.sample_ms = 2_000;
        early.read_begin_ms = 1_990;
        early.read_end_ms = 2_000;
        assert_eq!(
            coordinator.confirmed_quiet_window(early, early, 2_500),
            Ok(None)
        );

        let mut confirmed = early;
        confirmed.sample_ms = 4_000;
        confirmed.read_begin_ms = 3_990;
        confirmed.read_end_ms = 4_000;
        let zero = coordinator
            .confirmed_quiet_window(confirmed, confirmed, 2_500)
            .unwrap()
            .expect("confirmed quiet window");
        assert_eq!(zero.total_bytes(), 0);
        assert_eq!(zero.total_packets(), 0);
        assert_eq!(zero.start_ms, 1_010);
        assert_eq!(zero.end_ms, 4_000);
        assert_eq!(zero.duration_ms(), 2_990);

        // Quiet publication borrows rather than consumes the raw baseline.
        let progressed = sample(5_000, 5_010, 300, 30);
        let resumed = coordinator.finish(progressed, progressed).unwrap();
        assert_eq!(resumed.total_bytes(), 400);
        assert_eq!(resumed.duration_ms(), 4_000);
    }

    #[test]
    fn reset_generation_is_progress_for_validation() {
        let mut coordinator = FastRateCoordinator::default();
        let first = sample(1_000, 1_010, 100, 10);
        coordinator.begin(first, first).unwrap();
        let mut reset = first;
        reset.reset_generation += 1;
        assert!(coordinator.has_progress(reset, first));
    }
}
