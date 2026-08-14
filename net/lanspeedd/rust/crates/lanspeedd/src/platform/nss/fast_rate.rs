//! Same-window FastN/FastS coordination.
//!
//! The coordinator consumes cumulative samples only after their individual
//! stable-read protocol has succeeded. It never adds two independently
//! computed rates; both deltas must come from one shared start/end window.

pub(crate) const FAST_WINDOW_MAX_READ_END_SKEW_MS: u64 = 250;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastCounterSample {
    pub sample_ms: u64,
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
}

impl FastWindow {
    pub(crate) const fn total_bytes(self) -> u64 {
        self.n_bytes.saturating_add(self.s_bytes)
    }

    pub(crate) const fn total_packets(self) -> u64 {
        self.n_packets.saturating_add(self.s_packets)
    }

    pub(crate) const fn duration_ms(self) -> u64 {
        self.end_ms.saturating_sub(self.start_ms)
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

    pub(crate) fn clear(&mut self) {
        self.start = None;
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
        if n.reset_generation != start.n.reset_generation
            || s.reset_generation != start.s.reset_generation
            || n.reset_generation != s.reset_generation
        {
            return Err(FastWindowError::ResetGenerationChanged);
        }
        let start_ms = start.n.sample_ms.max(start.s.sample_ms);
        let end_ms = n.sample_ms.min(s.sample_ms);
        if end_ms <= start_ms {
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
        })
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
        assert_eq!(window.duration_ms(), 996);
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
}
