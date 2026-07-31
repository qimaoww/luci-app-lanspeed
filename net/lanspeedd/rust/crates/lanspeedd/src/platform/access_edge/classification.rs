use std::collections::{BTreeMap, VecDeque};

use crate::model::ClassificationState;

use super::types::{ByteDomain, RateSource};

pub const CLASSIFIER_READ_END_SKEW_MS: u64 = 50;
pub const COMPARISON_EPOCH_COUNT: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedDelta {
    pub source: RateSource,
    pub bytes: u64,
    pub packets: u64,
    pub byte_domain: ByteDomain,
    pub read_end_ms: u64,
}

impl ObservedDelta {
    const fn has_traffic(self) -> bool {
        self.bytes != 0 || self.packets != 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectionEpoch {
    pub edge: Option<ObservedDelta>,
    pub nss: Option<ObservedDelta>,
    pub slow: Option<ObservedDelta>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationEpoch {
    pub epoch_id: u64,
    pub start_ms: u64,
    pub end_ms: u64,
    pub attachment_generation: u64,
    pub attachment_stable: bool,
    pub map_complete: bool,
    pub sources_complete: bool,
    pub classifier_window_aligned: bool,
    pub tx: DirectionEpoch,
    pub rx: DirectionEpoch,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectionClassification {
    pub nss_bps: Option<u64>,
    pub slow_bps: Option<u64>,
    pub unclassified_bps: Option<u64>,
    pub coverage_pct: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationResult {
    pub state: ClassificationState,
    pub window_start_ms: Option<u64>,
    pub window_end_ms: Option<u64>,
    /// The actual classifier epoch represented by the latest N/S sample.
    pub classifier_window_ms: Option<u64>,
    /// Present only after the complete multi-epoch comparison window exists.
    pub comparison_window_ms: Option<u64>,
    pub tx: DirectionClassification,
    pub rx: DirectionClassification,
}

impl ClassificationResult {
    pub fn state(state: ClassificationState) -> Self {
        Self {
            state,
            window_start_ms: None,
            window_end_ms: None,
            classifier_window_ms: None,
            comparison_window_ms: None,
            tx: DirectionClassification::default(),
            rx: DirectionClassification::default(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ClassificationBook {
    epochs: BTreeMap<String, VecDeque<ClassificationEpoch>>,
}

impl ClassificationBook {
    pub fn clear(&mut self) {
        self.epochs.clear();
    }

    pub fn remove(&mut self, identity_key: &str) {
        self.epochs.remove(identity_key);
    }

    pub fn update(
        &mut self,
        identity_key: &str,
        epoch: ClassificationEpoch,
    ) -> ClassificationResult {
        if !epoch.map_complete {
            self.epochs.remove(identity_key);
            return single_epoch_result(&epoch, ClassificationState::MapLoss);
        }
        if !epoch.attachment_stable {
            self.epochs.remove(identity_key);
            return single_epoch_result(&epoch, ClassificationState::Partial);
        }
        if !epoch.sources_complete {
            self.epochs.remove(identity_key);
            return single_epoch_result(&epoch, ClassificationState::Partial);
        }
        if !epoch.classifier_window_aligned
            || epoch.end_ms <= epoch.start_ms
            || !classifier_sources_aligned(&epoch)
        {
            self.epochs.remove(identity_key);
            return single_epoch_result(&epoch, ClassificationState::WindowMismatch);
        }

        let epochs = self.epochs.entry(identity_key.to_owned()).or_default();
        let continuous = epochs.back().is_none_or(|previous| {
            previous.end_ms == epoch.start_ms
                && previous.epoch_id.checked_add(1) == Some(epoch.epoch_id)
                && previous.attachment_generation == epoch.attachment_generation
                && stable_direction_contract(previous.tx, epoch.tx)
                && stable_direction_contract(previous.rx, epoch.rx)
        });
        if !continuous {
            epochs.clear();
        }
        epochs.push_back(epoch);
        while epochs.len() > COMPARISON_EPOCH_COUNT {
            epochs.pop_front();
        }
        if epochs.len() < COMPARISON_EPOCH_COUNT {
            return single_epoch_result(
                epochs.back().expect("just inserted classifier epoch"),
                ClassificationState::Warmup,
            );
        }
        classify_window(epochs)
    }
}

fn classifier_sources_aligned(epoch: &ClassificationEpoch) -> bool {
    [epoch.tx, epoch.rx]
        .into_iter()
        .all(|direction| match (direction.nss, direction.slow) {
            (Some(nss), Some(slow)) => {
                nss.read_end_ms.abs_diff(slow.read_end_ms) <= CLASSIFIER_READ_END_SKEW_MS
            }
            _ => true,
        })
}

fn stable_direction_contract(previous: DirectionEpoch, current: DirectionEpoch) -> bool {
    stable_observation(previous.edge, current.edge)
        && stable_observation(previous.nss, current.nss)
        && stable_observation(previous.slow, current.slow)
}

fn stable_observation(previous: Option<ObservedDelta>, current: Option<ObservedDelta>) -> bool {
    match (previous, current) {
        (Some(previous), Some(current)) => {
            previous.source == current.source && previous.byte_domain == current.byte_domain
        }
        (None, None) => true,
        _ => false,
    }
}

fn single_epoch_result(
    epoch: &ClassificationEpoch,
    state: ClassificationState,
) -> ClassificationResult {
    let window_ms = epoch.end_ms.checked_sub(epoch.start_ms);
    ClassificationResult {
        state,
        window_start_ms: Some(epoch.start_ms),
        window_end_ms: Some(epoch.end_ms),
        classifier_window_ms: window_ms,
        comparison_window_ms: None,
        tx: observed_only(epoch.tx, window_ms.unwrap_or(0)),
        rx: observed_only(epoch.rx, window_ms.unwrap_or(0)),
    }
}

fn observed_only(epoch: DirectionEpoch, window_ms: u64) -> DirectionClassification {
    DirectionClassification {
        nss_bps: epoch.nss.map(|value| bps(value.bytes, window_ms)),
        slow_bps: epoch.slow.map(|value| bps(value.bytes, window_ms)),
        unclassified_bps: None,
        coverage_pct: None,
    }
}

fn classify_window(epochs: &VecDeque<ClassificationEpoch>) -> ClassificationResult {
    let first = epochs.front().expect("comparison window is non-empty");
    let last = epochs.back().expect("comparison window is non-empty");
    let window_ms = last.end_ms.saturating_sub(first.start_ms);
    if window_ms == 0 {
        return single_epoch_result(last, ClassificationState::WindowMismatch);
    }
    let (tx, tx_state) = classify_direction(epochs.iter().map(|epoch| epoch.tx), window_ms);
    let (rx, rx_state) = classify_direction(epochs.iter().map(|epoch| epoch.rx), window_ms);
    let state = merge_states(tx_state, rx_state);
    ClassificationResult {
        state,
        window_start_ms: Some(first.start_ms),
        window_end_ms: Some(last.end_ms),
        classifier_window_ms: last.end_ms.checked_sub(last.start_ms),
        comparison_window_ms: Some(window_ms),
        tx,
        rx,
    }
}

fn classify_direction(
    epochs: impl Iterator<Item = DirectionEpoch>,
    window_ms: u64,
) -> (DirectionClassification, ClassificationState) {
    let mut edge = 0u64;
    let mut nss = 0u64;
    let mut slow = 0u64;
    let mut edge_domain = None;
    let mut nss_domain = None;
    let mut slow_domain = None;
    let mut edge_present = true;
    let mut nss_present = true;
    let mut slow_present = true;
    for epoch in epochs {
        fold_observation(epoch.edge, &mut edge, &mut edge_domain, &mut edge_present);
        fold_observation(epoch.nss, &mut nss, &mut nss_domain, &mut nss_present);
        fold_observation(epoch.slow, &mut slow, &mut slow_domain, &mut slow_present);
    }

    let mut result = DirectionClassification {
        nss_bps: nss_present.then(|| bps(nss, window_ms)),
        slow_bps: slow_present.then(|| bps(slow, window_ms)),
        unclassified_bps: None,
        coverage_pct: None,
    };
    if !edge_present {
        return (result, ClassificationState::Unavailable);
    }

    // A zero-byte source adds nothing and therefore does not force its byte
    // domain onto the subtraction. A non-zero source must match every other
    // contributor and the Access Edge owner exactly.
    let classified_domain = match (
        (nss != 0).then_some(nss_domain).flatten(),
        (slow != 0).then_some(slow_domain).flatten(),
    ) {
        (Some(left), Some(right)) if left != right => {
            return (result, ClassificationState::DomainMismatch)
        }
        (Some(domain), _) | (_, Some(domain)) => Some(domain),
        (None, None) => edge_domain,
    };
    if classified_domain != edge_domain {
        return (result, ClassificationState::DomainMismatch);
    }

    let classified = nss.saturating_add(slow);
    if classified > edge {
        return (result, ClassificationState::CounterSkew);
    }
    let unclassified = edge - classified;
    result.unclassified_bps = Some(bps(unclassified, window_ms));
    result.coverage_pct = if edge == 0 {
        None
    } else {
        // `classified > edge` returned CounterSkew above, so this quotient is
        // already proven to be in 0..=100.  Do not clamp invalid evidence into
        // an apparently valid percentage.
        Some((u128::from(classified) * 100 / u128::from(edge)) as u8)
    };
    (result, ClassificationState::Aligned)
}

fn fold_observation(
    value: Option<ObservedDelta>,
    bytes: &mut u64,
    domain: &mut Option<ByteDomain>,
    present: &mut bool,
) {
    let Some(value) = value else {
        *present = false;
        return;
    };
    *bytes = bytes.saturating_add(value.bytes);
    if value.has_traffic() || domain.is_none() {
        *domain = Some(value.byte_domain);
    }
}

const fn bps(bytes: u64, window_ms: u64) -> u64 {
    if window_ms == 0 {
        return 0;
    }
    let scaled = (bytes as u128).saturating_mul(8_000) / window_ms as u128;
    if scaled > u64::MAX as u128 {
        u64::MAX
    } else {
        scaled as u64
    }
}

const fn state_rank(state: ClassificationState) -> u8 {
    match state {
        ClassificationState::MapLoss => 8,
        ClassificationState::CounterSkew => 7,
        ClassificationState::DomainMismatch => 6,
        ClassificationState::WindowMismatch => 5,
        ClassificationState::Stale => 4,
        ClassificationState::Partial => 3,
        ClassificationState::Unavailable => 2,
        ClassificationState::Warmup => 1,
        ClassificationState::Aligned => 0,
    }
}

fn merge_states(left: ClassificationState, right: ClassificationState) -> ClassificationState {
    if state_rank(left) >= state_rank(right) {
        left
    } else {
        right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(source: RateSource, bytes: u64, domain: ByteDomain, end_ms: u64) -> ObservedDelta {
        ObservedDelta {
            source,
            bytes,
            packets: bytes / 1_000,
            byte_domain: domain,
            read_end_ms: end_ms,
        }
    }

    fn epoch(id: u64, edge: u64, nss: u64, slow: u64) -> ClassificationEpoch {
        let start = (id - 1) * 2_000;
        let end = id * 2_000;
        let direction = DirectionEpoch {
            edge: Some(observed(
                RateSource::EdgePort,
                edge,
                ByteDomain::L2NoFcs,
                end,
            )),
            nss: Some(observed(
                RateSource::EcmNssLowerBound,
                nss,
                ByteDomain::L2NoFcs,
                end,
            )),
            slow: Some(observed(
                RateSource::TcBpfLowerBound,
                slow,
                ByteDomain::L2NoFcs,
                end + 20,
            )),
        };
        ClassificationEpoch {
            epoch_id: id,
            start_ms: start,
            end_ms: end,
            attachment_generation: 4,
            attachment_stable: true,
            map_complete: true,
            sources_complete: true,
            classifier_window_aligned: true,
            tx: direction,
            rx: direction,
        }
    }

    #[test]
    fn three_epochs_publish_six_second_unclassified_without_clamping() {
        let mut book = ClassificationBook::default();
        assert_eq!(
            book.update("client", epoch(1, 1_000, 600, 200)).state,
            ClassificationState::Warmup
        );
        assert_eq!(
            book.update("client", epoch(2, 1_000, 600, 200)).state,
            ClassificationState::Warmup
        );
        let result = book.update("client", epoch(3, 1_000, 600, 200));
        assert_eq!(result.state, ClassificationState::Aligned);
        assert_eq!(result.classifier_window_ms, Some(2_000));
        assert_eq!(result.comparison_window_ms, Some(6_000));
        assert_eq!(result.tx.coverage_pct, Some(80));
        assert_eq!(result.tx.unclassified_bps, Some(800));
    }

    #[test]
    fn counter_skew_omits_unknown_and_coverage() {
        let mut book = ClassificationBook::default();
        book.update("client", epoch(1, 100, 80, 40));
        book.update("client", epoch(2, 100, 80, 40));
        let result = book.update("client", epoch(3, 100, 80, 40));
        assert_eq!(result.state, ClassificationState::CounterSkew);
        assert_eq!(result.tx.unclassified_bps, None);
        assert_eq!(result.tx.coverage_pct, None);
    }

    #[test]
    fn incompatible_ecm_domain_remains_observable_but_not_subtractable() {
        let mut book = ClassificationBook::default();
        for id in 1..=2 {
            book.update("client", epoch(id, 1_000, 0, 100));
        }
        let mut third = epoch(3, 1_000, 100, 100);
        third.tx.nss.as_mut().unwrap().byte_domain = ByteDomain::EcmData;
        third.rx.nss.as_mut().unwrap().byte_domain = ByteDomain::EcmData;
        // A source/domain change restarts the stable comparison window.
        assert_eq!(
            book.update("client", third).state,
            ClassificationState::Warmup
        );
        for id in 4..=5 {
            let mut value = epoch(id, 1_000, 100, 100);
            value.tx.nss.as_mut().unwrap().byte_domain = ByteDomain::EcmData;
            value.rx.nss.as_mut().unwrap().byte_domain = ByteDomain::EcmData;
            let result = book.update("client", value);
            if id == 5 {
                assert_eq!(result.state, ClassificationState::DomainMismatch);
                assert!(result.tx.nss_bps.is_some());
                assert_eq!(result.tx.unclassified_bps, None);
            }
        }
    }

    #[test]
    fn map_loss_and_read_skew_invalidate_immediately() {
        let mut book = ClassificationBook::default();
        let mut lost = epoch(1, 1_000, 600, 200);
        lost.map_complete = false;
        assert_eq!(
            book.update("client", lost).state,
            ClassificationState::MapLoss
        );

        let mut skewed = epoch(2, 1_000, 600, 200);
        skewed.tx.slow.as_mut().unwrap().read_end_ms += 100;
        assert_eq!(
            book.update("client", skewed).state,
            ClassificationState::WindowMismatch
        );

        let mut boundary_skewed = epoch(3, 1_000, 600, 200);
        boundary_skewed.classifier_window_aligned = false;
        assert_eq!(
            book.update("client", boundary_skewed).state,
            ClassificationState::WindowMismatch
        );
    }

    #[test]
    fn complete_reads_after_map_loss_rewarm_before_realigning() {
        let mut book = ClassificationBook::default();
        for id in 1..=3 {
            book.update("client", epoch(id, 1_000, 600, 200));
        }

        let mut lost = epoch(4, 1_000, 600, 200);
        lost.map_complete = false;
        assert_eq!(
            book.update("client", lost).state,
            ClassificationState::MapLoss
        );

        for id in 5..=6 {
            let result = book.update("client", epoch(id, 1_000, 600, 200));
            assert_eq!(result.state, ClassificationState::Warmup);
            assert_eq!(result.classifier_window_ms, Some(2_000));
            assert_eq!(result.comparison_window_ms, None);
        }
        let recovered = book.update("client", epoch(7, 1_000, 600, 200));
        assert_eq!(recovered.state, ClassificationState::Aligned);
        assert_eq!(recovered.comparison_window_ms, Some(6_000));
    }
}
