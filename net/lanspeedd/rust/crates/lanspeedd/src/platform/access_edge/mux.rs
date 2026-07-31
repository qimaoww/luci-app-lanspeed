use super::types::{ByteDomain, Coverage, RateSource, TrafficScope};

const PROMOTION_WINDOWS: u8 = 2;
const SOFT_FAILURE_WINDOWS: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateCandidate {
    pub source: RateSource,
    pub bps: u64,
    pub coverage: Coverage,
    pub scope: TrafficScope,
    pub byte_domain: ByteDomain,
    pub sample_ms: u64,
    pub window_ms: u64,
    pub cadence_ms: u64,
    pub attachment_generation: u64,
    pub fresh: bool,
}

impl RateCandidate {
    const fn is_usable_for(self, attachment_generation: u64, now_ms: u64) -> bool {
        self.fresh
            && self.attachment_generation == attachment_generation
            && self.window_ms != 0
            && self.cadence_ms != 0
            && self.sample_ms <= now_ms
            && now_ms.saturating_sub(self.sample_ms) <= self.cadence_ms.saturating_mul(5) / 2
            && !matches!(self.coverage, Coverage::Unavailable)
            && !matches!(self.scope, TrafficScope::None)
    }

    const fn expired_at(self, now_ms: u64) -> bool {
        self.cadence_ms == 0
            || self.sample_ms > now_ms
            || now_ms.saturating_sub(self.sample_ms) > self.cadence_ms.saturating_mul(5) / 2
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MuxFailure {
    CounterReset,
    AttachmentAmbiguous,
    MapLoss,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MuxState {
    Available,
    Stale,
    Warmup,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedRate {
    pub candidate: RateCandidate,
    pub stale: bool,
    pub transition_seq: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MuxResult {
    pub state: MuxState,
    pub selected: Option<SelectedRate>,
    pub owner: Option<RateSource>,
    pub transition_seq: u64,
    pub consecutive_failures: u8,
}

/// Source selector for one client direction.
///
/// Every direction owns an independent instance. Candidates have already been
/// converted from their own cumulative baselines, so this state machine never
/// subtracts values from different sources.
#[derive(Clone, Debug, Default)]
pub struct DirectionRateMux {
    owner: Option<RateSource>,
    attachment_generation: Option<u64>,
    // (source, attachment generation, newest distinct sample, good windows).
    // The mux can be polled faster than a classifier, so repeated reads of the
    // same sample must not satisfy the two-window promotion requirement.
    challenger: Option<(RateSource, u64, u64, u8)>,
    consecutive_failures: u8,
    transition_seq: u64,
    last_selected: Option<RateCandidate>,
}

impl DirectionRateMux {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn owner(&self) -> Option<RateSource> {
        self.owner
    }

    pub const fn transition_seq(&self) -> u64 {
        self.transition_seq
    }

    pub fn update(
        &mut self,
        now_ms: u64,
        attachment_generation: u64,
        candidates: &[RateCandidate],
        failure: Option<MuxFailure>,
    ) -> MuxResult {
        if self
            .attachment_generation
            .is_some_and(|old| old != attachment_generation)
        {
            self.hard_demote();
        }
        self.attachment_generation = Some(attachment_generation);

        if failure.is_some() {
            self.hard_demote();
            return self.result(MuxState::Unavailable, None);
        }

        let best = candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.is_usable_for(attachment_generation, now_ms))
            .min_by_key(|candidate| candidate.source.priority());
        let owner_candidate = self.owner.and_then(|owner| {
            candidates.iter().copied().find(|candidate| {
                candidate.source == owner && candidate.is_usable_for(attachment_generation, now_ms)
            })
        });

        if let Some(current) = owner_candidate {
            self.consecutive_failures = 0;
            self.last_selected = Some(current);
            if best.is_some_and(|candidate| candidate.source.priority() < current.source.priority())
            {
                let challenger = best.expect("checked above");
                if self.record_challenger(challenger) {
                    return self.promote(challenger);
                }
            } else {
                self.challenger = None;
            }
            return self.result(
                MuxState::Available,
                Some(SelectedRate {
                    candidate: current,
                    stale: false,
                    transition_seq: self.transition_seq,
                }),
            );
        }

        if self.owner.is_some() {
            if self
                .last_selected
                .is_some_and(|candidate| candidate.expired_at(now_ms))
            {
                self.hard_demote();
                return self.result(MuxState::Unavailable, None);
            }
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            if let Some(candidate) = best {
                if self.record_challenger(candidate) {
                    return self.promote(candidate);
                }
            } else {
                self.challenger = None;
            }

            if self.consecutive_failures < SOFT_FAILURE_WINDOWS {
                let selected = self.last_selected.map(|candidate| SelectedRate {
                    candidate,
                    stale: true,
                    transition_seq: self.transition_seq,
                });
                return self.result(MuxState::Stale, selected);
            }
            self.soft_demote();
            return self.result(MuxState::Unavailable, None);
        }

        let Some(candidate) = best else {
            self.challenger = None;
            return self.result(MuxState::Unavailable, None);
        };
        if self.record_challenger(candidate) {
            return self.promote(candidate);
        }
        self.result(MuxState::Warmup, None)
    }

    fn record_challenger(&mut self, candidate: RateCandidate) -> bool {
        let (sample_ms, count) = match self.challenger {
            Some((source, generation, previous_sample_ms, count))
                if source == candidate.source
                    && generation == candidate.attachment_generation
                    && candidate.sample_ms > previous_sample_ms =>
            {
                (candidate.sample_ms, count.saturating_add(1))
            }
            Some((source, generation, previous_sample_ms, count))
                if source == candidate.source && generation == candidate.attachment_generation =>
            {
                (previous_sample_ms, count)
            }
            _ => (candidate.sample_ms, 1),
        };
        self.challenger = Some((
            candidate.source,
            candidate.attachment_generation,
            sample_ms,
            count,
        ));
        count >= PROMOTION_WINDOWS
    }

    fn promote(&mut self, candidate: RateCandidate) -> MuxResult {
        if self.owner != Some(candidate.source) {
            self.transition_seq = self.transition_seq.saturating_add(1);
        }
        self.owner = Some(candidate.source);
        self.attachment_generation = Some(candidate.attachment_generation);
        self.challenger = None;
        self.consecutive_failures = 0;
        self.last_selected = Some(candidate);
        self.result(
            MuxState::Available,
            Some(SelectedRate {
                candidate,
                stale: false,
                transition_seq: self.transition_seq,
            }),
        )
    }

    fn hard_demote(&mut self) {
        if self.owner.take().is_some() {
            self.transition_seq = self.transition_seq.saturating_add(1);
        }
        self.challenger = None;
        self.consecutive_failures = 0;
        self.last_selected = None;
    }

    fn soft_demote(&mut self) {
        self.hard_demote();
    }

    const fn result(&self, state: MuxState, selected: Option<SelectedRate>) -> MuxResult {
        MuxResult {
            state,
            selected,
            owner: self.owner,
            transition_seq: self.transition_seq,
            consecutive_failures: self.consecutive_failures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate_at(
        source: RateSource,
        generation: u64,
        bps: u64,
        sample_ms: u64,
    ) -> RateCandidate {
        RateCandidate {
            source,
            bps,
            coverage: Coverage::Full,
            scope: TrafficScope::AllFrames,
            byte_domain: ByteDomain::L2NoFcs,
            sample_ms,
            window_ms: 1_000,
            cadence_ms: 1_000,
            attachment_generation: generation,
            fresh: true,
        }
    }

    fn candidate(source: RateSource, generation: u64, bps: u64) -> RateCandidate {
        candidate_at(source, generation, bps, 1_000)
    }

    #[test]
    fn requires_two_good_windows_before_promotion() {
        let mut mux = DirectionRateMux::new();
        let edge = candidate(RateSource::EdgePort, 1, 8_000);
        assert_eq!(mux.update(1_000, 1, &[edge], None).state, MuxState::Warmup);
        assert_eq!(mux.update(1_000, 1, &[edge], None).state, MuxState::Warmup);
        let edge_next = candidate_at(RateSource::EdgePort, 1, 8_000, 2_000);
        let result = mux.update(2_000, 1, &[edge_next], None);
        assert_eq!(result.state, MuxState::Available);
        assert_eq!(result.owner, Some(RateSource::EdgePort));
        assert_eq!(result.selected.unwrap().candidate.bps, 8_000);
    }

    #[test]
    fn first_soft_failure_holds_stale_and_second_demotes() {
        let mut mux = DirectionRateMux::new();
        let edge = candidate(RateSource::EdgePort, 1, 8_000);
        mux.update(1_000, 1, &[edge], None);
        mux.update(
            2_000,
            1,
            &[candidate_at(RateSource::EdgePort, 1, 8_000, 2_000)],
            None,
        );

        let first = mux.update(3_000, 1, &[], None);
        assert_eq!(first.state, MuxState::Stale);
        assert!(first.selected.unwrap().stale);
        assert_eq!(first.owner, Some(RateSource::EdgePort));

        let second = mux.update(4_000, 1, &[], None);
        assert_eq!(second.state, MuxState::Unavailable);
        assert_eq!(second.owner, None);
    }

    #[test]
    fn generation_change_and_reset_demote_immediately() {
        let mut mux = DirectionRateMux::new();
        let edge = candidate(RateSource::EdgePort, 1, 8_000);
        mux.update(1_000, 1, &[edge], None);
        mux.update(
            2_000,
            1,
            &[candidate_at(RateSource::EdgePort, 1, 8_000, 2_000)],
            None,
        );

        let moved = candidate(RateSource::EdgePort, 2, 9_000);
        assert_eq!(mux.update(2_000, 2, &[moved], None).state, MuxState::Warmup);
        assert_eq!(mux.owner(), None);
        assert_eq!(
            mux.update(3_000, 2, &[], Some(MuxFailure::CounterReset))
                .state,
            MuxState::Unavailable
        );
        assert_eq!(mux.owner(), None);
    }

    #[test]
    fn higher_priority_edge_replaces_fallback_after_two_windows() {
        let mut mux = DirectionRateMux::new();
        let fallback = candidate(RateSource::EcmBpfFallback, 1, 4_000);
        mux.update(1_000, 1, &[fallback], None);
        let fallback_next = candidate_at(RateSource::EcmBpfFallback, 1, 4_000, 2_000);
        mux.update(2_000, 1, &[fallback_next], None);
        assert_eq!(mux.owner(), Some(RateSource::EcmBpfFallback));

        let edge = candidate(RateSource::EdgePort, 1, 8_000);
        assert_eq!(
            mux.update(2_000, 1, &[fallback_next, edge], None).owner,
            Some(RateSource::EcmBpfFallback)
        );
        let edge_next = candidate_at(RateSource::EdgePort, 1, 8_000, 2_000);
        assert_eq!(
            mux.update(2_000, 1, &[fallback_next, edge_next], None)
                .owner,
            Some(RateSource::EdgePort)
        );
    }

    #[test]
    fn unavailable_candidate_cannot_become_an_owner() {
        let mut mux = DirectionRateMux::new();
        let mut edge = candidate(RateSource::EdgePort, 1, 8_000);
        edge.coverage = Coverage::Unavailable;
        assert_eq!(
            mux.update(1_000, 1, &[edge], None).state,
            MuxState::Unavailable
        );
        assert_eq!(mux.update(1_000, 1, &[edge], None).owner, None);
    }

    #[test]
    fn retained_classifier_sample_stays_owned_until_its_cadence_age_expires() {
        let mut mux = DirectionRateMux::new();
        let mut first = candidate(RateSource::EcmBpfFallback, 1, 4_000);
        first.cadence_ms = 2_000;
        let mut second = candidate_at(RateSource::EcmBpfFallback, 1, 5_000, 3_000);
        second.cadence_ms = 2_000;
        mux.update(1_000, 1, &[first], None);
        assert_eq!(
            mux.update(3_000, 1, &[second], None).owner,
            Some(RateSource::EcmBpfFallback)
        );

        assert_eq!(
            mux.update(7_000, 1, &[second], None).state,
            MuxState::Available
        );
        assert_eq!(
            mux.update(8_001, 1, &[second], None).state,
            MuxState::Unavailable
        );
        assert_eq!(mux.owner(), None);
    }
}
