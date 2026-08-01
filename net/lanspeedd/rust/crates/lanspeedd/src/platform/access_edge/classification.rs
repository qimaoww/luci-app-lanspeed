use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::model::ClassificationState;

use super::types::{ByteDomain, RateSource};

pub const CLASSIFIER_READ_END_SKEW_MS: u64 = 50;
pub const COMPARISON_EPOCH_COUNT: usize = 3;
const ETHERNET_HEADER_BYTES: u64 = 14;
const ETHERNET_FCS_BYTES: u64 = 4;

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

/// Convert byte counters that describe the routed Ethernet data path into one
/// explicit, comparable wire domain. NSS ECM sync bytes are the network-layer
/// byte count also fed into conntrack accounting, while TC and Ethernet Edge
/// counters already include the Ethernet header but exclude FCS. Packet
/// counters let both sources be normalized without estimating packet counts.
///
/// Wi-Fi station counters describe 802.11 frames and cannot be converted to an
/// Ethernet wire total from NL80211 alone, so callers must retain their raw
/// `StationData` observation and let the domain check reject subtraction.
pub fn normalize_l2_with_fcs(mut value: ObservedDelta) -> Option<ObservedDelta> {
    let overhead_per_packet = match value.byte_domain {
        ByteDomain::EcmData => ETHERNET_HEADER_BYTES + ETHERNET_FCS_BYTES,
        ByteDomain::L2NoFcs => ETHERNET_FCS_BYTES,
        ByteDomain::L2WithFcs => 0,
        ByteDomain::StationData => return None,
    };
    value.bytes = value
        .bytes
        .saturating_add(value.packets.saturating_mul(overhead_per_packet));
    value.byte_domain = ByteDomain::L2WithFcs;
    Some(value)
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
    /// Access Edge bytes projected onto this exact comparison window. This
    /// remains observable when N+S exceeds Edge so diagnostics can explain
    /// `counter_skew` without turning the value into another rate owner.
    pub edge_bps: Option<u64>,
    pub nss_bps: Option<u64>,
    pub slow_bps: Option<u64>,
    pub unclassified_bps: Option<u64>,
    pub coverage_pct: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationResult {
    pub state: ClassificationState,
    pub tx_state: ClassificationState,
    pub rx_state: ClassificationState,
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
            tx_state: state,
            rx_state: state,
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

    pub fn is_empty(&self) -> bool {
        self.epochs.is_empty()
    }

    pub fn remove(&mut self, identity_key: &str) {
        self.epochs.remove(identity_key);
    }

    pub fn retain_identities(&mut self, identity_keys: &BTreeSet<String>) {
        self.epochs
            .retain(|identity_key, _| identity_keys.contains(identity_key));
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
        tx_state: state,
        rx_state: state,
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
        edge_bps: epoch.edge.map(|value| bps(value.bytes, window_ms)),
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
        tx_state,
        rx_state,
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
        edge_bps: edge_present.then(|| bps(edge, window_ms)),
        nss_bps: nss_present.then(|| bps(nss, window_ms)),
        slow_bps: slow_present.then(|| bps(slow, window_ms)),
        unclassified_bps: None,
        coverage_pct: None,
    };
    if !edge_present {
        return (result, ClassificationState::Unavailable);
    }

    // Comparison is a statement about counter semantics, not just the current
    // numeric delta. Even a zero-byte classifier sample cannot prove coverage
    // against a different Edge byte domain (notably NL80211 station_data).
    let classified_domain = match (nss_domain, slow_domain) {
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

    fn observed_packets(
        source: RateSource,
        bytes: u64,
        packets: u64,
        domain: ByteDomain,
        end_ms: u64,
    ) -> ObservedDelta {
        ObservedDelta {
            source,
            bytes,
            packets,
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
        assert_eq!(result.tx.edge_bps, Some(4_000));
        assert_eq!(result.tx.coverage_pct, Some(80));
        assert_eq!(result.tx.unclassified_bps, Some(800));
    }

    #[test]
    fn ethernet_sources_normalize_to_one_exact_comparison_domain() {
        let edge = normalize_l2_with_fcs(observed_packets(
            RateSource::EdgePort,
            1_000,
            10,
            ByteDomain::L2NoFcs,
            2_000,
        ))
        .unwrap();
        let nss = normalize_l2_with_fcs(observed_packets(
            RateSource::EcmNssLowerBound,
            500,
            10,
            ByteDomain::EcmData,
            2_000,
        ))
        .unwrap();
        let slow = normalize_l2_with_fcs(observed_packets(
            RateSource::TcBpfLowerBound,
            340,
            5,
            ByteDomain::L2NoFcs,
            2_020,
        ))
        .unwrap();
        assert_eq!(edge.bytes, 1_040);
        assert_eq!(nss.bytes, 680);
        assert_eq!(slow.bytes, 360);
        assert_eq!(edge.byte_domain, ByteDomain::L2WithFcs);
        assert_eq!(nss.byte_domain, ByteDomain::L2WithFcs);
        assert_eq!(slow.byte_domain, ByteDomain::L2WithFcs);

        let mut book = ClassificationBook::default();
        for id in 1..=3 {
            let start_ms = (id - 1) * 2_000;
            let end_ms = id * 2_000;
            let retime = |mut value: ObservedDelta| {
                value.read_end_ms = end_ms;
                value
            };
            let result = book.update(
                "client",
                ClassificationEpoch {
                    epoch_id: id,
                    start_ms,
                    end_ms,
                    attachment_generation: 1,
                    attachment_stable: true,
                    map_complete: true,
                    sources_complete: true,
                    classifier_window_aligned: true,
                    tx: DirectionEpoch {
                        edge: Some(retime(edge)),
                        nss: Some(retime(nss)),
                        slow: Some(retime(slow)),
                    },
                    rx: DirectionEpoch {
                        edge: Some(retime(edge)),
                        nss: Some(retime(nss)),
                        slow: Some(retime(slow)),
                    },
                },
            );
            if id == 3 {
                assert_eq!(result.state, ClassificationState::Aligned);
                assert_eq!(result.tx.coverage_pct, Some(100));
                assert_eq!(result.tx.unclassified_bps, Some(0));
            }
        }
    }

    #[test]
    fn wifi_station_domain_is_never_guessed_into_ethernet_bytes() {
        assert_eq!(
            normalize_l2_with_fcs(observed_packets(
                RateSource::EdgeWifi,
                1_000,
                10,
                ByteDomain::StationData,
                2_000,
            )),
            None
        );
    }

    #[test]
    fn wifi_station_domain_never_publishes_aligned_coverage() {
        let mut book = ClassificationBook::default();
        for id in 1..=3 {
            let mut value = epoch(id, 1_000, 0, 0);
            for direction in [&mut value.tx, &mut value.rx] {
                direction.edge.as_mut().unwrap().byte_domain = ByteDomain::StationData;
                direction.nss.as_mut().unwrap().byte_domain = ByteDomain::L2WithFcs;
                direction.slow.as_mut().unwrap().byte_domain = ByteDomain::L2WithFcs;
            }
            let result = book.update("wifi-client", value);
            if id == 3 {
                assert_eq!(result.state, ClassificationState::DomainMismatch);
                assert_eq!(result.tx.coverage_pct, None);
                assert_eq!(result.tx.unclassified_bps, None);
            }
        }
    }

    #[test]
    fn counter_skew_omits_unknown_and_coverage() {
        let mut book = ClassificationBook::default();
        book.update("client", epoch(1, 100, 80, 40));
        book.update("client", epoch(2, 100, 80, 40));
        let result = book.update("client", epoch(3, 100, 80, 40));
        assert_eq!(result.state, ClassificationState::CounterSkew);
        assert_eq!(result.tx_state, ClassificationState::CounterSkew);
        assert_eq!(result.rx_state, ClassificationState::CounterSkew);
        assert_eq!(result.tx.edge_bps, Some(400));
        assert_eq!(result.tx.unclassified_bps, None);
        assert_eq!(result.tx.coverage_pct, None);
    }

    #[test]
    fn merged_result_preserves_each_direction_state() {
        let mut book = ClassificationBook::default();
        for id in 1..=3 {
            let mut value = epoch(id, 100, 80, 40);
            value.rx = DirectionEpoch {
                edge: Some(observed(
                    RateSource::EdgePort,
                    100,
                    ByteDomain::L2NoFcs,
                    value.end_ms,
                )),
                nss: Some(observed(
                    RateSource::EcmNssLowerBound,
                    60,
                    ByteDomain::L2NoFcs,
                    value.end_ms,
                )),
                slow: Some(observed(
                    RateSource::TcBpfLowerBound,
                    20,
                    ByteDomain::L2NoFcs,
                    value.end_ms + 20,
                )),
            };
            let result = book.update("client", value);
            if id == 3 {
                assert_eq!(result.state, ClassificationState::CounterSkew);
                assert_eq!(result.tx_state, ClassificationState::CounterSkew);
                assert_eq!(result.rx_state, ClassificationState::Aligned);
                assert_eq!(result.tx.coverage_pct, None);
                assert_eq!(result.rx.coverage_pct, Some(80));
            }
        }
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

    #[test]
    fn invalid_window_clears_an_aligned_history_immediately() {
        let mut book = ClassificationBook::default();
        for id in 1..=3 {
            book.update("client", epoch(id, 1_000, 600, 200));
        }

        let mut invalid = epoch(4, 1_000, 600, 200);
        invalid.start_ms = invalid.end_ms;
        assert_eq!(
            book.update("client", invalid).state,
            ClassificationState::WindowMismatch
        );
        assert_eq!(
            book.update("client", epoch(5, 1_000, 600, 200)).state,
            ClassificationState::Warmup
        );
    }

    #[test]
    fn retain_identities_bounds_classifier_history_during_churn() {
        let mut book = ClassificationBook::default();
        for index in 0..1_024 {
            book.update(&format!("client-{index}"), epoch(1, 1_000, 600, 200));
        }
        let retained = BTreeSet::from(["client-1023".to_owned()]);
        book.retain_identities(&retained);
        assert_eq!(book.epochs.len(), 1);
        assert!(book.epochs.contains_key("client-1023"));
    }
}
