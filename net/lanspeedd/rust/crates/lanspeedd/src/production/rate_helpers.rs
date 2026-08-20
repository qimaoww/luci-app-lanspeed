use super::*;
use crate::config::InternetViewMode;

#[derive(Clone, Copy, Debug)]
#[cfg(feature = "nss-platform")]
pub(super) struct PublishedRateDirection {
    pub(super) bps: u64,
    pub(super) source: ModelRateSource,
    pub(super) coverage: ModelRateCoverage,
    pub(super) scope: ModelRateScope,
    pub(super) byte_domain: Option<ModelByteDomain>,
    pub(super) sample_ms: Option<u64>,
    pub(super) window_ms: Option<u64>,
    pub(super) stale: bool,
    pub(super) mux_owner: bool,
}

#[cfg(feature = "nss-platform")]
impl PublishedRateDirection {
    pub(super) fn unavailable(bps: u64) -> Self {
        Self {
            bps,
            source: ModelRateSource::None,
            coverage: ModelRateCoverage::Unavailable,
            scope: ModelRateScope::None,
            byte_domain: None,
            sample_ms: None,
            window_ms: None,
            stale: false,
            mux_owner: false,
        }
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn retain_collector_warnings(warnings: &mut Vec<String>, rate: RateCollector) {
    if rate == RateCollector::NssEcmBpf {
        warnings.retain(|warning| {
            !matches!(
                warning.as_str(),
                "flowtable_counter_probe_unavailable" | "flowtable_counter_missing"
            )
        });
    }
}

pub(super) type Bpf = BpfRuntime<SystemAyaLink>;

#[cfg(feature = "nss-platform")]
pub(super) fn nss_tc_snapshot(snapshot: &BpfSnapshot) -> NssTcSnapshot {
    NssTcSnapshot {
        clients: snapshot
            .clients
            .iter()
            .map(|sample| NssTcClientSample {
                mac: sample.mac.clone(),
                identity_key: sample.identity_key.clone(),
                zone: sample.zone.clone(),
                interface: sample.interface.clone(),
                ips: sample.ips.clone(),
                tx_bytes: sample.tx_bytes,
                rx_bytes: sample.rx_bytes,
                tx_bps: sample.tx_bps,
                rx_bps: sample.rx_bps,
                last_seen_ms: sample.last_seen_ms,
            })
            .collect(),
        coverage_deltas: snapshot.coverage_deltas.clone(),
        coverage_start_ms: snapshot.coverage_start_ms,
        coverage_end_ms: snapshot.coverage_end_ms,
        coverage_ready: snapshot.coverage_ready,
        map_complete: !snapshot.map_read_truncated,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn format_edge_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(feature = "nss-platform")]
pub(super) fn mac_lookup_key(value: &str) -> String {
    value.to_ascii_lowercase()
}

/// One-pass MAC index used by the hot client-rate path. A MAC that appears in
/// more than one attachment/identity is deliberately removed from `unique` so
/// the index preserves the old fail-closed attribution rule.
#[cfg(feature = "nss-platform")]
pub(super) struct MacIndex<'a, T> {
    pub(super) unique: BTreeMap<String, &'a T>,
    pub(super) ambiguous: BTreeSet<String>,
}

#[cfg(feature = "nss-platform")]
impl<T> Default for MacIndex<'_, T> {
    fn default() -> Self {
        Self {
            unique: BTreeMap::new(),
            ambiguous: BTreeSet::new(),
        }
    }
}

#[cfg(feature = "nss-platform")]
impl<'a, T> MacIndex<'a, T> {
    pub(super) fn insert(&mut self, key: String, value: &'a T) {
        if self.ambiguous.contains(&key) {
            return;
        }
        if self.unique.remove(&key).is_some() {
            self.ambiguous.insert(key);
        } else {
            self.unique.insert(key, value);
        }
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn edge_mac_index<'a>(
    clients: &'a [EdgeClientObservation],
) -> MacIndex<'a, EdgeClientObservation> {
    let mut index = MacIndex::default();
    for client in clients {
        index.insert(format_edge_mac(client.attachment.key.mac), client);
    }
    index
}

#[cfg(feature = "nss-platform")]
pub(super) fn identity_mac_index<'a>(
    identities: &'a IdentityTable,
) -> MacIndex<'a, ClientIdentity> {
    let mut index = MacIndex::default();
    for identity in identities.iter() {
        index.insert(identity.key.mac.to_string(), identity);
    }
    index
}

#[cfg(feature = "nss-platform")]
pub(super) fn response_mac_index<'a>(clients: &'a [Client]) -> MacIndex<'a, Client> {
    let mut index = MacIndex::default();
    for client in clients {
        index.insert(mac_lookup_key(&client.mac), client);
    }
    index
}

#[cfg(feature = "nss-platform")]
pub(super) fn observed_traffic_delta(
    source: EdgeRateSource,
    byte_domain: EdgeByteDomain,
    counters: TrafficCounters,
    direction: EdgeDirection,
    read_end_ms: u64,
) -> ObservedDelta {
    let (bytes, packets) = match direction {
        EdgeDirection::Tx => (counters.tx_bytes, counters.tx_packets),
        EdgeDirection::Rx => (counters.rx_bytes, counters.rx_packets),
    };
    ObservedDelta {
        source,
        bytes,
        packets,
        byte_domain,
        read_end_ms,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn comparable_l2_with_fcs(value: ObservedDelta) -> ObservedDelta {
    normalize_l2_with_fcs(value).unwrap_or(value)
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "nss-platform")]
pub(super) fn classifier_rate_candidates(
    identity_key: &str,
    direction: EdgeDirection,
    attachment_generation: u64,
    ecm: Option<&EcmBpfSnapshot>,
    ecm_read_end_ms: Option<u64>,
    slow: Option<&NssTcSnapshot>,
    slow_read_end_ms: Option<u64>,
    runtime: &RuntimeHealth,
) -> Vec<RateCandidate> {
    let mut candidates = Vec::new();
    let ecm_value = ecm
        .filter(|snapshot| {
            runtime.ecm_bpf_map_read_ok
                && !snapshot.truncated
                && snapshot.coverage_ready
                && classifier_sample_fresh(runtime.now_ms, snapshot.coverage_end_ms)
        })
        .and_then(|snapshot| {
            let start = snapshot.coverage_start_ms?;
            let window_ms = snapshot.coverage_end_ms.checked_sub(start)?;
            if window_ms == 0 {
                return None;
            }
            let delta = snapshot.coverage_deltas.get(identity_key).copied()?;
            let observed = normalize_l2_with_fcs(observed_traffic_delta(
                EdgeRateSource::EcmNssLowerBound,
                EdgeByteDomain::EcmData,
                delta,
                direction,
                ecm_read_end_ms.unwrap_or(snapshot.coverage_end_ms),
            ))?;
            let bytes = observed.bytes;
            Some((
                RateCandidate {
                    source: EdgeRateSource::EcmNssLowerBound,
                    bps: bytes_to_bps(bytes, window_ms),
                    coverage: crate::platform::access_edge::Coverage::Degraded,
                    scope: EdgeTrafficScope::LowerBound,
                    byte_domain: observed.byte_domain,
                    sample_ms: snapshot.coverage_end_ms,
                    window_ms,
                    cadence_ms: CLASSIFIER_INTERVAL_MS,
                    attachment_generation,
                    fresh: true,
                },
                start,
                snapshot.coverage_end_ms,
                bytes,
            ))
        });
    let slow_value = slow
        .filter(|snapshot| {
            snapshot.coverage_ready
                && snapshot.map_complete
                && runtime.bpf_map_read_ok
                && classifier_sample_fresh(runtime.now_ms, snapshot.coverage_end_ms)
        })
        .and_then(|snapshot| {
            let start = snapshot.coverage_start_ms?;
            let window_ms = snapshot.coverage_end_ms.checked_sub(start)?;
            if window_ms == 0 {
                return None;
            }
            let delta = snapshot.coverage_deltas.get(identity_key).copied()?;
            let observed = normalize_l2_with_fcs(observed_traffic_delta(
                EdgeRateSource::TcBpfLowerBound,
                EdgeByteDomain::L2NoFcs,
                delta,
                direction,
                slow_read_end_ms.unwrap_or(snapshot.coverage_end_ms),
            ))?;
            let bytes = observed.bytes;
            Some((
                RateCandidate {
                    source: EdgeRateSource::TcBpfLowerBound,
                    bps: bytes_to_bps(bytes, window_ms),
                    coverage: crate::platform::access_edge::Coverage::Degraded,
                    scope: EdgeTrafficScope::LowerBound,
                    byte_domain: observed.byte_domain,
                    sample_ms: snapshot.coverage_end_ms,
                    window_ms,
                    cadence_ms: CLASSIFIER_INTERVAL_MS,
                    attachment_generation,
                    fresh: true,
                },
                start,
                snapshot.coverage_end_ms,
                bytes,
            ))
        });
    if let Some((candidate, ..)) = ecm_value {
        candidates.push(candidate);
    }
    if let Some((candidate, ..)) = slow_value {
        candidates.push(candidate);
    }
    if let (
        Some((ecm_candidate, ecm_start, ecm_end, ecm_bytes)),
        Some((slow_candidate, slow_start, slow_end, slow_bytes)),
    ) = (ecm_value, slow_value)
    {
        if ecm_candidate.byte_domain == slow_candidate.byte_domain
            && ecm_start.abs_diff(slow_start) <= CLASSIFIER_READ_END_SKEW_MS
            && ecm_end.abs_diff(slow_end) <= CLASSIFIER_READ_END_SKEW_MS
            && ecm_read_end_ms
                .zip(slow_read_end_ms)
                .is_some_and(|(ecm_read, slow_read)| {
                    ecm_read.abs_diff(slow_read) <= CLASSIFIER_READ_END_SKEW_MS
                })
        {
            let start = ecm_start.min(slow_start);
            let end = ecm_end.max(slow_end);
            let window_ms = end.saturating_sub(start);
            candidates.push(RateCandidate {
                source: EdgeRateSource::EcmBpfFallback,
                bps: bytes_to_bps(ecm_bytes.saturating_add(slow_bytes), window_ms),
                coverage: crate::platform::access_edge::Coverage::Degraded,
                scope: EdgeTrafficScope::RoutedObserved,
                byte_domain: ecm_candidate.byte_domain,
                sample_ms: end,
                window_ms,
                cadence_ms: CLASSIFIER_INTERVAL_MS,
                attachment_generation,
                fresh: true,
            });
        }
    }
    candidates
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "nss-platform")]
pub(super) enum ClassifierWindowSelection {
    Unavailable,
    Invalid,
    Ready {
        start_ms: u64,
        end_ms: u64,
        aligned: bool,
    },
}

#[cfg(feature = "nss-platform")]
pub(super) fn select_classifier_window(
    ecm: Option<(u64, u64)>,
    slow: Option<(u64, u64)>,
) -> ClassifierWindowSelection {
    if ecm.is_some_and(|(start, end)| end <= start) || slow.is_some_and(|(start, end)| end <= start)
    {
        return ClassifierWindowSelection::Invalid;
    }
    match (ecm, slow) {
        (Some(ecm), Some(slow)) => ClassifierWindowSelection::Ready {
            start_ms: ecm.0,
            end_ms: ecm.1,
            aligned: ecm.0.abs_diff(slow.0) <= CLASSIFIER_READ_END_SKEW_MS
                && ecm.1.abs_diff(slow.1) <= CLASSIFIER_READ_END_SKEW_MS,
        },
        (Some(window), None) | (None, Some(window)) => ClassifierWindowSelection::Ready {
            start_ms: window.0,
            end_ms: window.1,
            aligned: true,
        },
        (None, None) => ClassifierWindowSelection::Unavailable,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) const fn classifier_sample_fresh(now_ms: u64, sample_ms: u64) -> bool {
    sample_ms <= now_ms
        && now_ms.saturating_sub(sample_ms) <= CLASSIFIER_INTERVAL_MS.saturating_mul(5) / 2
}

// ECM is sampled at the classifier cadence, which can be slower than the
// response cadence. A skipped map read therefore means "no new epoch", not
// "the last complete map became unusable". Keep status health tied to the
// retained snapshot's actual freshness; classification itself still consumes
// only newly collected epochs.
#[cfg(feature = "nss-platform")]
pub(super) fn ecm_bpf_snapshot_current(
    snapshot: Option<&EcmBpfSnapshot>,
    runtime: &RuntimeHealth,
) -> bool {
    snapshot.is_some_and(|snapshot| !snapshot.truncated)
        && runtime
            .ecm_bpf_last_complete_snapshot_ms
            .is_some_and(|sample_ms| {
                crate::is_fresh(runtime.now_ms, sample_ms, runtime.ecm_bpf_freshness_ms)
            })
}

/// An Edge segment is usable only when its end is at or before the completed
/// Edge snapshot. `saturating_sub` alone would treat a segment from a clock
/// anomaly in the future as fresh (the subtraction would become zero), which
/// can briefly publish a rate from an invalid window.
#[cfg(feature = "nss-platform")]
pub(super) const fn edge_segment_fresh(
    snapshot_ms: u64,
    segment_end_ms: u64,
    cadence_ms: u64,
) -> bool {
    segment_end_ms <= snapshot_ms
        && snapshot_ms.saturating_sub(segment_end_ms) <= cadence_ms.saturating_mul(5) / 2
}

#[cfg(feature = "nss-platform")]
pub(super) const fn classifier_map_loss_invalidates_owner(
    owner: Option<EdgeRateSource>,
    has_edge_candidate: bool,
    has_classifier_candidate: bool,
    classifier_loss: bool,
) -> bool {
    // A valid Edge or remaining classifier candidate keeps the rate path alive
    // while one map is being rebuilt. Dropping the current owner in that case
    // would create an avoidable zero/warmup gap before the mux can promote the
    // surviving source. The map-loss state is still published by classification.
    if !classifier_loss || has_edge_candidate || has_classifier_candidate {
        return false;
    }
    match owner {
        Some(
            EdgeRateSource::EcmBpfFallback
            | EdgeRateSource::EcmNssLowerBound
            | EdgeRateSource::TcBpfLowerBound,
        ) => true,
        Some(EdgeRateSource::EdgePort | EdgeRateSource::EdgeWifi) => false,
        None => true,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn remove_failed_edge_candidates(
    candidates: &mut Vec<RateCandidate>,
    edge_failure: Option<MuxFailure>,
) {
    if edge_failure.is_some() {
        candidates.retain(|candidate| {
            !matches!(
                candidate.source,
                EdgeRateSource::EdgePort | EdgeRateSource::EdgeWifi
            )
        });
    }
}

#[cfg(feature = "nss-platform")]
pub(super) const fn bytes_to_bps(bytes: u64, window_ms: u64) -> u64 {
    if window_ms == 0 {
        return 0;
    }
    let value = (bytes as u128).saturating_mul(8_000) / window_ms as u128;
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn published_from_candidate(
    candidate: RateCandidate,
    stale: bool,
) -> PublishedRateDirection {
    PublishedRateDirection {
        bps: candidate.bps,
        source: model_rate_source(candidate.source),
        coverage: model_rate_coverage(candidate.coverage),
        scope: model_rate_scope(candidate.scope),
        byte_domain: Some(model_byte_domain(candidate.byte_domain)),
        sample_ms: Some(candidate.sample_ms),
        window_ms: Some(candidate.window_ms),
        stale,
        mux_owner: true,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn fast_client_sample_current(now_ms: u64, sample: FastClientSample) -> bool {
    // NSS FastN publishes in hardware batches that can be longer than the
    // one-second UI cadence. Keep one complete window usable through the next
    // expected publication instead of dropping it between two batch notices;
    // short FastS-only windows remain usable through the 2.5-second quiet
    // confirmation interval plus one fixed-timer scheduling slot. Without
    // that slot the old value can expire one tick before the worker publishes
    // its confirmed zero, producing a false one-frame unavailable/0 gap.
    let freshness_ms = crate::platform::nss::fast_rate::FAST_WINDOW_QUIET_CONFIRM_MS
        .saturating_add(ACCESS_EDGE_INTERVAL_MS)
        .max(sample.window_ms.saturating_add(ACCESS_EDGE_INTERVAL_MS));
    sample.window_ms != 0
        && sample.read_end_skew_ms
            <= crate::platform::nss::fast_rate::FAST_WINDOW_MAX_READ_END_SKEW_MS
        && sample.sample_ms <= now_ms
        && now_ms.saturating_sub(sample.sample_ms) <= freshness_ms
}

#[cfg(feature = "nss-platform")]
pub(super) fn active_rate_direction(
    view: RateView,
    edge: Option<RateCandidate>,
    fast: Option<FastClientSample>,
) -> PublishedRateDirection {
    match view {
        RateView::EAuthority => edge
            .filter(|candidate| candidate.fresh)
            .map(|candidate| published_from_candidate(candidate, false))
            .unwrap_or_else(|| PublishedRateDirection::unavailable(0)),
        RateView::RoutedLeaseSubstitute => fast
            .map(published_from_fast_lease)
            .unwrap_or_else(|| PublishedRateDirection::unavailable(0)),
        RateView::RoutedInternet => fast
            .map(published_from_fast_internet)
            .unwrap_or_else(|| PublishedRateDirection::unavailable(0)),
        RateView::Unavailable => PublishedRateDirection::unavailable(0),
    }
}

#[cfg(feature = "nss-platform")]
fn published_from_fast_lease(sample: FastClientSample) -> PublishedRateDirection {
    PublishedRateDirection {
        bps: sample.routed_l2_with_fcs_bps,
        source: ModelRateSource::FastRoutedLease,
        coverage: ModelRateCoverage::Degraded,
        scope: ModelRateScope::RoutedObserved,
        byte_domain: Some(ModelByteDomain::L2WithFcs),
        sample_ms: Some(sample.sample_ms),
        window_ms: Some(sample.window_ms),
        stale: false,
        mux_owner: true,
    }
}

#[cfg(feature = "nss-platform")]
fn published_from_fast_internet(sample: FastClientSample) -> PublishedRateDirection {
    PublishedRateDirection {
        bps: sample.routed_l2_with_fcs_bps,
        source: ModelRateSource::FastRoutedInternet,
        coverage: ModelRateCoverage::Degraded,
        scope: ModelRateScope::RoutedObserved,
        byte_domain: Some(ModelByteDomain::L2WithFcs),
        sample_ms: Some(sample.sample_ms),
        window_ms: Some(sample.window_ms),
        stale: false,
        mux_owner: true,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn rate_direction_meta(
    direction: PublishedRateDirection,
    summary_sample_ms: Option<u64>,
    summary_window_ms: Option<u64>,
    summary_stale: bool,
) -> RateDirectionMeta {
    RateDirectionMeta {
        source: direction.source,
        coverage: direction.coverage,
        byte_domain: direction.byte_domain,
        sample_ms: (direction.sample_ms != summary_sample_ms)
            .then_some(direction.sample_ms)
            .flatten(),
        window_ms: (direction.window_ms != summary_window_ms)
            .then_some(direction.window_ms)
            .flatten(),
        stale: (direction.stale != summary_stale).then_some(direction.stale),
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn compact_rate_sample_ms(
    tx_sample_ms: Option<u64>,
    rx_sample_ms: Option<u64>,
) -> Option<u64> {
    match (tx_sample_ms, rx_sample_ms) {
        (Some(tx), Some(rx)) => Some(tx.max(rx)),
        // A client-level value cannot represent which direction is missing.
        // Keep the summary absent and let the sampled direction emit its
        // sparse override instead of making the missing direction inherit a
        // timestamp it never had.
        _ => None,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn pipeline_direction(
    pipeline: RateCollector,
    bps: u64,
    sample_ms: Option<u64>,
    refresh_interval_ms: u32,
    connection_only: bool,
) -> PublishedRateDirection {
    if connection_only {
        return PublishedRateDirection::unavailable(bps);
    }
    if pipeline == RateCollector::Unsupported {
        return PublishedRateDirection::unavailable(bps);
    }
    let (source, byte_domain) = match pipeline {
        RateCollector::Bpf => (
            ModelRateSource::TcBpfLowerBound,
            Some(ModelByteDomain::L2NoFcs),
        ),
        RateCollector::NssEcmNode => (
            ModelRateSource::EcmNssLowerBound,
            Some(ModelByteDomain::EcmData),
        ),
        RateCollector::NssEcmBpf => (ModelRateSource::EcmBpfFallback, None),
        RateCollector::Unsupported => unreachable!("handled above"),
    };
    PublishedRateDirection {
        bps,
        source,
        coverage: ModelRateCoverage::Degraded,
        scope: ModelRateScope::RoutedObserved,
        byte_domain,
        sample_ms,
        window_ms: Some(u64::from(refresh_interval_ms)),
        stale: false,
        mux_owner: false,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) const fn model_rate_source(source: EdgeRateSource) -> ModelRateSource {
    match source {
        EdgeRateSource::EdgePort => ModelRateSource::EdgePort,
        EdgeRateSource::EdgeWifi => ModelRateSource::EdgeWifi,
        EdgeRateSource::EcmBpfFallback => ModelRateSource::EcmBpfFallback,
        EdgeRateSource::EcmNssLowerBound => ModelRateSource::EcmNssLowerBound,
        EdgeRateSource::TcBpfLowerBound => ModelRateSource::TcBpfLowerBound,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) const fn model_rate_coverage(
    value: crate::platform::access_edge::Coverage,
) -> ModelRateCoverage {
    match value {
        crate::platform::access_edge::Coverage::Full => ModelRateCoverage::Full,
        crate::platform::access_edge::Coverage::Partial => ModelRateCoverage::Partial,
        crate::platform::access_edge::Coverage::Degraded => ModelRateCoverage::Degraded,
        crate::platform::access_edge::Coverage::Unavailable => ModelRateCoverage::Unavailable,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) const fn model_rate_scope(value: EdgeTrafficScope) -> ModelRateScope {
    match value {
        EdgeTrafficScope::AllFrames => ModelRateScope::AllFrames,
        EdgeTrafficScope::Unicast => ModelRateScope::Unicast,
        EdgeTrafficScope::RoutedObserved => ModelRateScope::RoutedObserved,
        EdgeTrafficScope::LowerBound => ModelRateScope::LowerBound,
        EdgeTrafficScope::None => ModelRateScope::None,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) const fn model_byte_domain(value: EdgeByteDomain) -> ModelByteDomain {
    match value {
        EdgeByteDomain::L2NoFcs => ModelByteDomain::L2NoFcs,
        EdgeByteDomain::L2WithFcs => ModelByteDomain::L2WithFcs,
        EdgeByteDomain::StationData => ModelByteDomain::StationData,
        EdgeByteDomain::EcmData => ModelByteDomain::EcmData,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn conservative_scope(left: ModelRateScope, right: ModelRateScope) -> ModelRateScope {
    let rank = |value| match value {
        ModelRateScope::None => 0,
        ModelRateScope::LowerBound => 1,
        ModelRateScope::RoutedObserved => 2,
        ModelRateScope::Unicast => 3,
        ModelRateScope::AllFrames => 4,
    };
    if rank(left) <= rank(right) {
        left
    } else {
        right
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn model_attachment(attachment: &EdgeAttachment) -> RateAttachment {
    RateAttachment {
        kind: match attachment.point.kind {
            EdgeAttachmentKind::Ethernet => ModelAttachmentKind::Ethernet,
            EdgeAttachmentKind::Wifi => ModelAttachmentKind::Wifi,
        },
        ifname: Some(attachment.point.ifname.clone()),
        trust: match attachment.trust {
            EdgeAttachmentTrust::AssociatedStation => ModelAttachmentTrust::AssociatedStation,
            EdgeAttachmentTrust::ObservedExclusive => ModelAttachmentTrust::ObservedExclusive,
            EdgeAttachmentTrust::Shared => ModelAttachmentTrust::Shared,
            EdgeAttachmentTrust::Unknown => ModelAttachmentTrust::Unknown,
        },
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn classification_summary(result: &ClassificationResult) -> RateClassificationSummary {
    RateClassificationSummary {
        state: result.state,
        tx_state: (result.tx_state != result.state).then_some(result.tx_state),
        rx_state: (result.rx_state != result.state).then_some(result.rx_state),
        sample_ms: result.window_end_ms,
        window_ms: result.classifier_window_ms,
        comparison_window_ms: result.comparison_window_ms,
        tx_coverage_pct: result.tx.coverage_pct,
        rx_coverage_pct: result.rx.coverage_pct,
    }
}

#[cfg(feature = "nss-platform")]
pub(super) fn traffic_classification(result: &ClassificationResult) -> TrafficClassification {
    let direction = |state, value: crate::platform::access_edge::DirectionClassification| {
        TrafficClassificationDirection {
            state,
            edge_bps: value.edge_bps,
            nss_bps: value.nss_bps,
            slow_bps: value.slow_bps,
            unclassified_bps: value.unclassified_bps,
            coverage_pct: value.coverage_pct,
        }
    };
    TrafficClassification {
        state: result.state,
        window_start_ms: result.window_start_ms,
        window_end_ms: result.window_end_ms,
        comparison_window_ms: result.comparison_window_ms,
        tx: direction(result.tx_state, result.tx),
        rx: direction(result.rx_state, result.rx),
    }
}

#[cfg(feature = "nss-platform")]
pub(super) const fn classification_state_code(state: ClassificationState) -> &'static str {
    match state {
        ClassificationState::Warmup => "warmup",
        ClassificationState::Aligned => "aligned",
        ClassificationState::Partial => "partial",
        ClassificationState::Stale => "stale",
        ClassificationState::DomainMismatch => "domain_mismatch",
        ClassificationState::WindowMismatch => "window_mismatch",
        ClassificationState::CounterSkew => "counter_skew",
        ClassificationState::MapLoss => "map_loss",
        ClassificationState::Unavailable => "unavailable",
    }
}

pub(super) fn bpf_error_stage(kind: AdapterErrorKind) -> &'static str {
    match kind {
        AdapterErrorKind::ObjectMissing
        | AdapterErrorKind::KfuncIncompatible
        | AdapterErrorKind::LoadFailed => "object_load_failed",
        AdapterErrorKind::OwnershipConflict => "tc_conflict",
        AdapterErrorKind::AttachFailed | AdapterErrorKind::DetachFailed => "tc_attach_failed",
        AdapterErrorKind::MapReadFailed => "map_read_failed",
    }
}

pub(super) fn interface_master(ifname: &str) -> Option<String> {
    fs::read_link(Path::new("/sys/class/net").join(ifname).join("master"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
}

pub(super) fn interface_masters() -> BTreeMap<String, String> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return BTreeMap::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| interface_master(&name).map(|master| (name, master)))
        .collect()
}

pub(super) fn independent_lan_boundaries(
    roots: &[String],
    masters: &BTreeMap<String, String>,
) -> Option<Vec<String>> {
    fn expand(
        name: &str,
        masters: &BTreeMap<String, String>,
        visiting: &mut std::collections::BTreeSet<String>,
        boundaries: &mut std::collections::BTreeSet<String>,
    ) -> bool {
        if !visiting.insert(name.to_owned()) {
            return false;
        }
        let children = masters
            .iter()
            .filter_map(|(child, master)| (master == name).then_some(child.as_str()))
            .collect::<Vec<_>>();
        let valid = if children.is_empty() {
            boundaries.insert(name.to_owned());
            true
        } else {
            children
                .into_iter()
                .all(|child| expand(child, masters, visiting, boundaries))
        };
        visiting.remove(name);
        valid
    }

    let mut boundaries = std::collections::BTreeSet::new();
    let mut visiting = std::collections::BTreeSet::new();
    for root in roots {
        if !expand(root, masters, &mut visiting, &mut boundaries) {
            return None;
        }
    }
    (!boundaries.is_empty()).then(|| boundaries.into_iter().collect())
}

pub(super) fn sum_interface_counters(
    names: &[String],
    counters: &BTreeMap<String, InterfaceCounters>,
) -> Option<InterfaceCounters> {
    names
        .iter()
        .try_fold(InterfaceCounters::default(), |mut total, name| {
            let value = counters.get(name)?;
            total.rx_bytes = total.rx_bytes.checked_add(value.rx_bytes)?;
            total.tx_bytes = total.tx_bytes.checked_add(value.tx_bytes)?;
            total.rx_packets = total.rx_packets.checked_add(value.rx_packets)?;
            total.tx_packets = total.tx_packets.checked_add(value.tx_packets)?;
            Some(total)
        })
}

pub(super) fn interface_display_counters(
    name: &str,
    role: InterfaceRole,
    boundary_names: Option<&[String]>,
    counters: &BTreeMap<String, InterfaceCounters>,
) -> Option<InterfaceCounters> {
    let counters = if role == InterfaceRole::Lan {
        match boundary_names {
            Some(names) => sum_interface_counters(names, counters)?,
            None => counters.get(name).copied()?,
        }
    } else {
        counters.get(name).copied()?
    };
    Some(if role == InterfaceRole::Lan {
        InterfaceCounters {
            rx_bytes: counters
                .rx_bytes
                .saturating_add(counters.rx_packets.saturating_mul(4)),
            tx_bytes: counters
                .tx_bytes
                .saturating_add(counters.tx_packets.saturating_mul(4)),
            ..counters
        }
    } else {
        counters
    })
}

pub(super) fn effective_collection_interval_ms(
    access_edge_mode: AccessEdgeMode,
    internet_view_mode: InternetViewMode,
    owner: Option<RateCollector>,
    configured_ms: u32,
) -> u32 {
    if access_edge_mode != AccessEdgeMode::Off || internet_view_mode.uses_fast_rate() {
        return ACCESS_EDGE_INTERVAL_MS as u32;
    }
    if matches!(
        owner,
        Some(RateCollector::NssEcmNode | RateCollector::NssEcmBpf)
    ) {
        configured_ms.max(CLASSIFIER_INTERVAL_MS as u32)
    } else {
        configured_ms
    }
}

#[cfg(feature = "nss-platform")]
pub(super) const fn active_access_edge_owns_display_rate(
    access_edge_mode: AccessEdgeMode,
    rate_collector_mode: RateCollectorMode,
) -> bool {
    matches!(access_edge_mode, AccessEdgeMode::Active)
        && matches!(rate_collector_mode, RateCollectorMode::Auto)
}

#[cfg(feature = "nss-platform")]
pub(super) const fn explicit_internet_rate_view(internet_view_mode: InternetViewMode) -> bool {
    matches!(internet_view_mode, InternetViewMode::Routed)
}

#[cfg(feature = "nss-platform")]
pub(super) const fn rate_mux_owns_display_rate(
    access_edge_mode: AccessEdgeMode,
    rate_collector_mode: RateCollectorMode,
    internet_view_mode: InternetViewMode,
) -> bool {
    active_access_edge_owns_display_rate(access_edge_mode, rate_collector_mode)
        || explicit_internet_rate_view(internet_view_mode)
}

#[cfg(feature = "nss-platform")]
pub(super) const fn published_rate_collector_mode<'a>(
    active_auto: bool,
    legacy: &'a str,
) -> &'a str {
    if active_auto {
        "access_edge"
    } else {
        legacy
    }
}

#[cfg(feature = "nss-platform")]
pub(super) const fn legacy_nss_rate_window_enabled(
    access_edge_mode: AccessEdgeMode,
    rate_collector_mode: RateCollectorMode,
    internet_view_mode: InternetViewMode,
) -> bool {
    !rate_mux_owns_display_rate(access_edge_mode, rate_collector_mode, internet_view_mode)
}

/// Advance an absolute monotonic deadline to the first slot strictly after
/// `now_ms`. Missed slots are skipped in one step, so a slow collection cannot
/// trigger a burst of catch-up callbacks.
pub(super) fn next_absolute_collection_slot(
    previous_deadline_ms: u64,
    now_ms: u64,
    cadence_ms: u32,
) -> (u64, u32) {
    let cadence_ms = u64::from(cadence_ms.max(1));
    let deadline_ms = if previous_deadline_ms == 0 {
        now_ms.saturating_add(cadence_ms)
    } else if previous_deadline_ms > now_ms {
        previous_deadline_ms
    } else {
        let missed = now_ms
            .saturating_sub(previous_deadline_ms)
            .checked_div(cadence_ms)
            .unwrap_or(0)
            .saturating_add(1);
        previous_deadline_ms.saturating_add(missed.saturating_mul(cadence_ms))
    };
    let delay_ms = deadline_ms
        .saturating_sub(now_ms)
        .max(1)
        .min(u64::from(u32::MAX)) as u32;
    (deadline_ms, delay_ms)
}

#[cfg(feature = "nss-platform")]
pub(super) fn periodic_deadline_due(
    next_deadline_ms: &mut u64,
    now_ms: u64,
    cadence_ms: u64,
) -> bool {
    let cadence_ms = cadence_ms.max(1);
    if *next_deadline_ms == 0 {
        *next_deadline_ms = now_ms.saturating_add(cadence_ms);
        return true;
    }
    if now_ms < *next_deadline_ms {
        return false;
    }
    let missed = now_ms
        .saturating_sub(*next_deadline_ms)
        .checked_div(cadence_ms)
        .unwrap_or(0)
        .saturating_add(1);
    *next_deadline_ms = next_deadline_ms.saturating_add(missed.saturating_mul(cadence_ms));
    true
}

pub(super) fn schedule_absolute_collection(
    timer: &Timer,
    deadline: &Cell<u64>,
    cadence_ms: u32,
) -> Result<(), DaemonError> {
    let now_ms = production_now_ms()?;
    let (next_deadline_ms, delay_ms) =
        next_absolute_collection_slot(deadline.get(), now_ms, cadence_ms);
    timer
        .schedule(delay_ms)
        .map_err(|error| DaemonError::transport(error.to_string()))?;
    deadline.set(next_deadline_ms);
    Ok(())
}

#[cfg(feature = "nss-platform")]
pub(super) fn nss_snapshot_freshness_ms(configured_ms: u32) -> u64 {
    u64::from(configured_ms.max(CLASSIFIER_INTERVAL_MS as u32)).saturating_mul(3)
}

#[cfg(feature = "nss-platform")]
pub(super) fn classifier_map_metrics(
    entries: usize,
    capacity: usize,
    truncated_observed: bool,
    current_truncated: Option<bool>,
    read_attempted: bool,
    read_ok: bool,
) -> Value {
    let occupancy_pct = (capacity > 0)
        .then(|| ((entries as u128).saturating_mul(100) / capacity as u128).min(100) as u8);
    json!({
        "entries": entries,
        "capacity": capacity,
        "occupancy_pct": occupancy_pct,
        "pressure": occupancy_pct.is_some_and(|value| value >= 90),
        "truncated": truncated_observed,
        "current_truncated": current_truncated,
        "map_loss": current_truncated == Some(true) || (read_attempted && !read_ok),
    })
}

#[cfg(feature = "nss-platform")]
pub(super) fn classifier_map_evidence(
    runtime: &RuntimeHealth,
    ecm: Option<&EcmBpfSnapshot>,
    ecm_new: bool,
    slow: Option<&NssTcSnapshot>,
    slow_new: bool,
) -> Value {
    json!({
        "tc_bpf": classifier_map_metrics(
            runtime.bpf_map_entries,
            runtime.bpf_map_capacity,
            runtime.bpf_map_iteration_truncated,
            slow.filter(|_| slow_new).map(|snapshot| !snapshot.map_complete),
            runtime.bpf_map_read_attempted,
            runtime.bpf_map_read_ok,
        ),
        "ecm_nss": classifier_map_metrics(
            runtime.ecm_bpf_map_entries,
            runtime.ecm_bpf_map_capacity,
            runtime.ecm_bpf_map_iteration_truncated,
            ecm.filter(|_| ecm_new).map(|snapshot| snapshot.truncated),
            runtime.ecm_bpf_map_read_attempted,
            runtime.ecm_bpf_map_read_ok,
        ),
    })
}

#[cfg(feature = "nss-platform")]
pub(super) fn access_edge_global_evidence(
    snapshot: &crate::platform::access_edge::AccessEdgeSnapshot,
    clients: &ClientsResponse,
    mode: AccessEdgeMode,
) -> Value {
    let mut reasons = snapshot.reason_codes.clone();
    let mut published = 0usize;
    let mut seen_macs = BTreeSet::new();
    let edge_index = edge_mac_index(&snapshot.clients);
    let client_index = response_mac_index(&clients.clients);
    for edge in &snapshot.clients {
        let mac = format_edge_mac(edge.attachment.key.mac);
        if !seen_macs.insert(mac.clone()) || edge_index.ambiguous.contains(&mac) {
            reasons.push("duplicate_mac_attachment".to_owned());
            continue;
        }
        if client_index.ambiguous.contains(&mac) {
            reasons.push("duplicate_client_identity".to_owned());
            continue;
        }
        let Some(client) = client_index.unique.get(&mac).copied() else {
            reasons.push("active_attachment_unpublished".to_owned());
            continue;
        };
        published = published.saturating_add(1);
        let Some(meta) = client.rate_meta.as_ref() else {
            reasons.push("rate_owner_unavailable".to_owned());
            continue;
        };
        let expected_source = match edge.attachment.point.kind {
            EdgeAttachmentKind::Ethernet => ModelRateSource::EdgePort,
            EdgeAttachmentKind::Wifi => ModelRateSource::EdgeWifi,
        };
        let tx_stale = meta.tx.stale.unwrap_or(meta.stale);
        let rx_stale = meta.rx.stale.unwrap_or(meta.stale);
        let fresh_edge_owner = !tx_stale
            && !rx_stale
            && meta.generation == edge.attachment.generation
            && meta.tx.source == expected_source
            && meta.rx.source == expected_source;
        if !fresh_edge_owner {
            reasons.push("fresh_edge_owner_missing".to_owned());
        }
        match edge.attachment.point.kind {
            EdgeAttachmentKind::Wifi => {
                // Station counters prove unicast ownership only. Broadcast and
                // multicast cannot yet be attributed per receiver.
                reasons.push("wifi_group_traffic_unattributed".to_owned());
            }
            EdgeAttachmentKind::Ethernet => {
                // A standard FDB dump observes learned identities, but cannot
                // prove that no silent shared device exists behind the port.
                // Keep the Edge-Port owner while refusing a synthetic Full
                // claim even if an inconsistent caller supplies one.
                if fresh_edge_owner {
                    reasons.push("ethernet_full_scope_unproven".to_owned());
                }
            }
        }
    }
    if !snapshot.topology_complete {
        reasons.push("topology_incomplete".to_owned());
    }
    if mode != AccessEdgeMode::Active {
        reasons.push("shadow_not_rate_owner".to_owned());
    }
    reasons.sort();
    reasons.dedup();
    reasons.truncate(16);
    json!({
        "coverage": if snapshot.clients.is_empty() {
            "unavailable"
        } else {
            // Without a manual direct-port assertion, standard FDB and Wi-Fi
            // station data cannot prove per-client ownership of every frame.
            "partial"
        },
        "scope": if snapshot.clients.is_empty() { "none" } else { "all_frames" },
        "active_attachments": snapshot.clients.len(),
        "published_attachments": published,
        "topology_complete": snapshot.topology_complete,
        "fdb_source": snapshot.fdb_source,
        "sample_ms": snapshot.sample_ms,
        "reason_codes": reasons,
    })
}
