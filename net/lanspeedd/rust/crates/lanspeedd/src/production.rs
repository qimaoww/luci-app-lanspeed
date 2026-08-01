use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    path::Path,
    rc::Rc,
    sync::Arc,
};

use lanspeed_openwrt_sys::{Timer, UbusConnection, UloopGuard};
use serde_json::{json, Value};

use crate::{
    clock::monotonic_millis,
    collectors::conntrack::{self, CollectedSnapshot, CollectorMode as ConntrackMode},
    config::{
        is_sysdevice_candidate, AccessEdgeMode, ConnectionCollectorMode, InterfaceEligibility,
        RuntimeConfig, SysfsInterfaceEligibility, MAX_INTERFACE_NAMES, MAX_INTERFACE_NAME_LEN,
    },
    connection_details::ConnectionRateBook,
    connections::{
        apply_conntrack_failure, apply_conntrack_success, before_reply_action,
        client_conntrack_plan, periodic_conntrack_plan, publish_connection_details,
        BeforeReplyAction, ClientConntrackPlan, ConntrackObservation, PeriodicConntrackPlan,
        CLIENT_CONNTRACK_CACHE_TTL_MS, NSS_CLIENT_CONNTRACK_CACHE_TTL_MS,
    },
    daemon::{
        abort_reload_after_timer_failure, abort_reload_candidate, activate_runtime,
        collect_and_reschedule, commit_reload, install_control_or_shutdown, reconnect_and_register,
        shutdown_runtime, CoordinatorState, Runtime, UloopSignalBridge,
    },
    error::DaemonError,
    history::overview::{
        ConnectionTotals, ConnectionTotalsOverride, OverviewClient, OverviewConfig, OverviewRing,
    },
    identity::{
        arp,
        filter::IdentityFilter,
        hostname::{HostnameCache, HostnamePaths},
        netlink, IdentityObservation, IdentityTable, LegacyZoneResolver, ObservationSource,
    },
    interfaces::{
        read_interface_counter_snapshot, InterfaceCounterSnapshot, InterfaceCounters,
        InterfaceRateBook, MIXED_INTERFACE_SOURCE,
    },
    model::{
        Capabilities, ClientsResponse, Confidence, Conflict, Evidence, HealthResponse, Interface,
        InterfaceRole, InterfaceStatus, InterfacesResponse, Mode, OverviewResponse, OverviewSample,
        ReloadResponse, StatusResponse, Sysdevice, SysdeviceLimits, SysdevicesResponse,
    },
    platform::{
        confidence,
        x86::{
            coverage_state::X86Coverage,
            output::clients_response,
            runtime::{
                AdapterError, AdapterErrorKind, AttachMode, BpfCollectionCheckpoint,
                BpfPostCommitCleanup, BpfReconfigureTxn, BpfRuntime, ReconfigureRateBaseline,
                ReconfigureStrategy, SystemAyaAdapter, SystemAyaLink, FALLBACK_OBJECT_PATH,
            },
            snapshot::{BpfSnapshotCollector, ConnectionCounts, ConnectionOverlay},
        },
    },
    policy::{self, RateCollector},
    probe::{
        collector::{self, probe_deadline, probe_due, ProbeMethod, SystemProbeCollector},
        process::{
            run_dae_mode_tick, DaeModeReloadLatch, DaeModeTickOutcome, DaeModeTickSignals,
            DaeProcessTracker,
        },
        Mode as ProbeMode, ProbeCapabilities, ProbeReport, RuntimeHealth,
    },
    state::{ResponseSnapshot, CONNECTION_SEMANTICS, OVERVIEW_SAMPLE_SOURCE},
    ubus,
};

#[cfg(feature = "nss-platform")]
use crate::config::RateCollectorMode;

#[cfg(feature = "nss-platform")]
use crate::platform::x86::snapshot::BpfSnapshot;
#[cfg(feature = "nss-platform")]
use crate::{
    connection_details::{TrafficClassification, TrafficClassificationDirection},
    identity::{filter, ClientIdentity},
    model::{
        AttachmentKind as ModelAttachmentKind, AttachmentTrust as ModelAttachmentTrust,
        ByteDomain as ModelByteDomain, ClassificationState, Client, ClientRateMeta, RateAttachment,
        RateClassificationSummary, RateCoverage as ModelRateCoverage, RateDirectionMeta,
        RateScope as ModelRateScope, RateSource as ModelRateSource,
    },
    platform::{
        access_edge::{
            normalize_l2_with_fcs, AccessEdgeCheckpoint, AccessEdgeRuntime,
            Attachment as EdgeAttachment, AttachmentKind as EdgeAttachmentKind,
            AttachmentTrust as EdgeAttachmentTrust, ByteDomain as EdgeByteDomain,
            ClassificationEpoch, ClassificationResult, Direction as EdgeDirection, DirectionEpoch,
            EdgeClientObservation, MuxFailure, ObservedDelta, RateCandidate,
            RateSource as EdgeRateSource, TrafficScope as EdgeTrafficScope,
            CLASSIFIER_READ_END_SKEW_MS,
        },
        counters::TrafficCounters,
        nss::{
            bpf_coverage::NssBpfCoverage,
            ecm_bpf::EcmBpfSnapshot,
            evidence::{apply_ecm_bpf_evidence, apply_nss_snapshot_evidence},
            fusion::{
                ecm_bpf_client_interfaces, ecm_bpf_fallback_client_rates,
                merge_ecm_bpf_client_deltas, merge_ecm_bpf_coverage_delta,
            },
            output::{
                apply_ecm_bpf_rate_batch, coverage_evidence, ecm_bpf_clients_response,
                ecm_bpf_coverage_merge_evidence, ecm_bpf_rate_batch_evidence, nss_rate_coverage,
                rate_window_interface_counters, window_clients, window_evidence,
            },
            runtime::{NssRuntime, NssRuntimeCheckpoint},
            tc_snapshot::{NssTcClientSample, NssTcSnapshot},
            window::{LanClock, WindowQuality},
        },
    },
};
#[cfg(feature = "nss-platform")]
use std::collections::BTreeSet;

#[cfg(all(test, feature = "nss-platform"))]
use crate::platform::nss::fusion::add_traffic_counters;
#[cfg(all(test, feature = "nss-platform"))]
use crate::platform::nss::{
    output::{coverage_response, nss_rate_coverage_values},
    window::{CoverageWindow, EcmBpfRateBatch, RateWindowValue},
};
#[cfg(all(test, feature = "nss-platform"))]
use crate::probe::Confidence as ProbeConfidence;

const RECONNECT_MS: u32 = 1_000;
// Kept as a policy/timer constant so the x86 build does not need to link the
// NSS platform module merely to compile common scheduling code.
const ACCESS_EDGE_INTERVAL_MS: u64 = 1_000;
const CLASSIFIER_INTERVAL_MS: u64 = 2_000;
const INTERNAL_BPF_SELF_HEAL_REASON: &str = "production.collect.internal";
const EXTERNAL_BPF_SELF_HEAL_REASON: &str = "production.collect.external";
const INTERFACE_NOTE: &str = "Per-interface totals from one kernel net-device pass with sysfs fallback; reflect hardware-offloaded and hardware-switched traffic too.";

#[derive(Clone, Copy, Debug)]
#[cfg(feature = "nss-platform")]
struct PublishedRateDirection {
    bps: u64,
    source: ModelRateSource,
    coverage: ModelRateCoverage,
    scope: ModelRateScope,
    byte_domain: Option<ModelByteDomain>,
    sample_ms: Option<u64>,
    window_ms: Option<u64>,
    stale: bool,
    mux_owner: bool,
}

#[cfg(feature = "nss-platform")]
impl PublishedRateDirection {
    fn unavailable(bps: u64) -> Self {
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
fn retain_collector_warnings(warnings: &mut Vec<String>, rate: RateCollector) {
    if rate == RateCollector::NssEcmBpf {
        warnings.retain(|warning| {
            !matches!(
                warning.as_str(),
                "flowtable_counter_probe_unavailable" | "flowtable_counter_missing"
            )
        });
    }
}

type Bpf = BpfRuntime<SystemAyaLink>;

#[cfg(feature = "nss-platform")]
fn nss_tc_snapshot(snapshot: &BpfSnapshot) -> NssTcSnapshot {
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
fn format_edge_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(feature = "nss-platform")]
fn mac_lookup_key(value: &str) -> String {
    value.to_ascii_lowercase()
}

/// One-pass MAC index used by the hot client-rate path. A MAC that appears in
/// more than one attachment/identity is deliberately removed from `unique` so
/// the index preserves the old fail-closed attribution rule.
#[cfg(feature = "nss-platform")]
struct MacIndex<'a, T> {
    unique: BTreeMap<String, &'a T>,
    ambiguous: BTreeSet<String>,
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
    fn insert(&mut self, key: String, value: &'a T) {
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
fn edge_mac_index<'a>(clients: &'a [EdgeClientObservation]) -> MacIndex<'a, EdgeClientObservation> {
    let mut index = MacIndex::default();
    for client in clients {
        index.insert(format_edge_mac(client.attachment.key.mac), client);
    }
    index
}

#[cfg(feature = "nss-platform")]
fn identity_mac_index<'a>(identities: &'a IdentityTable) -> MacIndex<'a, ClientIdentity> {
    let mut index = MacIndex::default();
    for identity in identities.iter() {
        index.insert(identity.key.mac.to_string(), identity);
    }
    index
}

#[cfg(feature = "nss-platform")]
fn response_mac_index<'a>(clients: &'a [Client]) -> MacIndex<'a, Client> {
    let mut index = MacIndex::default();
    for client in clients {
        index.insert(mac_lookup_key(&client.mac), client);
    }
    index
}

#[cfg(feature = "nss-platform")]
fn observed_traffic_delta(
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
fn comparable_l2_with_fcs(value: ObservedDelta) -> ObservedDelta {
    normalize_l2_with_fcs(value).unwrap_or(value)
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "nss-platform")]
fn classifier_rate_candidates(
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
enum ClassifierWindowSelection {
    Unavailable,
    Invalid,
    Ready {
        start_ms: u64,
        end_ms: u64,
        aligned: bool,
    },
}

#[cfg(feature = "nss-platform")]
fn select_classifier_window(
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
const fn classifier_sample_fresh(now_ms: u64, sample_ms: u64) -> bool {
    sample_ms <= now_ms
        && now_ms.saturating_sub(sample_ms) <= CLASSIFIER_INTERVAL_MS.saturating_mul(5) / 2
}

// ECM is sampled at the classifier cadence, which can be slower than the
// response cadence. A skipped map read therefore means "no new epoch", not
// "the last complete map became unusable". Keep status health tied to the
// retained snapshot's actual freshness; classification itself still consumes
// only newly collected epochs.
#[cfg(feature = "nss-platform")]
fn ecm_bpf_snapshot_current(snapshot: Option<&EcmBpfSnapshot>, runtime: &RuntimeHealth) -> bool {
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
const fn edge_segment_fresh(snapshot_ms: u64, segment_end_ms: u64, cadence_ms: u64) -> bool {
    segment_end_ms <= snapshot_ms
        && snapshot_ms.saturating_sub(segment_end_ms) <= cadence_ms.saturating_mul(5) / 2
}

#[cfg(feature = "nss-platform")]
const fn classifier_map_loss_invalidates_owner(
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
fn remove_failed_edge_candidates(
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
const fn bytes_to_bps(bytes: u64, window_ms: u64) -> u64 {
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
fn published_from_candidate(candidate: RateCandidate, stale: bool) -> PublishedRateDirection {
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
fn rate_direction_meta(
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
fn compact_rate_sample_ms(tx_sample_ms: Option<u64>, rx_sample_ms: Option<u64>) -> Option<u64> {
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
fn pipeline_direction(
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
const fn model_rate_source(source: EdgeRateSource) -> ModelRateSource {
    match source {
        EdgeRateSource::EdgePort => ModelRateSource::EdgePort,
        EdgeRateSource::EdgeWifi => ModelRateSource::EdgeWifi,
        EdgeRateSource::EcmBpfFallback => ModelRateSource::EcmBpfFallback,
        EdgeRateSource::EcmNssLowerBound => ModelRateSource::EcmNssLowerBound,
        EdgeRateSource::TcBpfLowerBound => ModelRateSource::TcBpfLowerBound,
    }
}

#[cfg(feature = "nss-platform")]
const fn model_rate_coverage(value: crate::platform::access_edge::Coverage) -> ModelRateCoverage {
    match value {
        crate::platform::access_edge::Coverage::Full => ModelRateCoverage::Full,
        crate::platform::access_edge::Coverage::Partial => ModelRateCoverage::Partial,
        crate::platform::access_edge::Coverage::Degraded => ModelRateCoverage::Degraded,
        crate::platform::access_edge::Coverage::Unavailable => ModelRateCoverage::Unavailable,
    }
}

#[cfg(feature = "nss-platform")]
const fn model_rate_scope(value: EdgeTrafficScope) -> ModelRateScope {
    match value {
        EdgeTrafficScope::AllFrames => ModelRateScope::AllFrames,
        EdgeTrafficScope::Unicast => ModelRateScope::Unicast,
        EdgeTrafficScope::RoutedObserved => ModelRateScope::RoutedObserved,
        EdgeTrafficScope::LowerBound => ModelRateScope::LowerBound,
        EdgeTrafficScope::None => ModelRateScope::None,
    }
}

#[cfg(feature = "nss-platform")]
const fn model_byte_domain(value: EdgeByteDomain) -> ModelByteDomain {
    match value {
        EdgeByteDomain::L2NoFcs => ModelByteDomain::L2NoFcs,
        EdgeByteDomain::L2WithFcs => ModelByteDomain::L2WithFcs,
        EdgeByteDomain::StationData => ModelByteDomain::StationData,
        EdgeByteDomain::EcmData => ModelByteDomain::EcmData,
    }
}

#[cfg(feature = "nss-platform")]
fn conservative_scope(left: ModelRateScope, right: ModelRateScope) -> ModelRateScope {
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
fn model_attachment(attachment: &EdgeAttachment) -> RateAttachment {
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
fn classification_summary(result: &ClassificationResult) -> RateClassificationSummary {
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
fn traffic_classification(result: &ClassificationResult) -> TrafficClassification {
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
const fn classification_state_code(state: ClassificationState) -> &'static str {
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

fn bpf_error_stage(kind: AdapterErrorKind) -> &'static str {
    match kind {
        AdapterErrorKind::ObjectMissing
        | AdapterErrorKind::KfuncIncompatible
        | AdapterErrorKind::LoadFailed => "object_load_failed",
        AdapterErrorKind::OwnershipConflict => "tc_conflict",
        AdapterErrorKind::AttachFailed | AdapterErrorKind::DetachFailed => "tc_attach_failed",
        AdapterErrorKind::MapReadFailed => "map_read_failed",
    }
}

fn interface_master(ifname: &str) -> Option<String> {
    fs::read_link(Path::new("/sys/class/net").join(ifname).join("master"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
}

fn interface_masters() -> BTreeMap<String, String> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return BTreeMap::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| interface_master(&name).map(|master| (name, master)))
        .collect()
}

fn independent_lan_boundaries(
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

fn sum_interface_counters(
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

fn effective_collection_interval_ms(
    access_edge_mode: AccessEdgeMode,
    owner: Option<RateCollector>,
    configured_ms: u32,
) -> u32 {
    if access_edge_mode != AccessEdgeMode::Off {
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
const fn active_access_edge_owns_display_rate(
    access_edge_mode: AccessEdgeMode,
    rate_collector_mode: RateCollectorMode,
) -> bool {
    matches!(access_edge_mode, AccessEdgeMode::Active)
        && matches!(rate_collector_mode, RateCollectorMode::Auto)
}

#[cfg(feature = "nss-platform")]
const fn published_rate_collector_mode<'a>(active_auto: bool, legacy: &'a str) -> &'a str {
    if active_auto {
        "access_edge"
    } else {
        legacy
    }
}

#[cfg(feature = "nss-platform")]
const fn legacy_nss_rate_window_enabled(
    access_edge_mode: AccessEdgeMode,
    rate_collector_mode: RateCollectorMode,
) -> bool {
    !active_access_edge_owns_display_rate(access_edge_mode, rate_collector_mode)
}

/// Advance an absolute monotonic deadline to the first slot strictly after
/// `now_ms`. Missed slots are skipped in one step, so a slow collection cannot
/// trigger a burst of catch-up callbacks.
fn next_absolute_collection_slot(
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
fn periodic_deadline_due(next_deadline_ms: &mut u64, now_ms: u64, cadence_ms: u64) -> bool {
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

fn schedule_absolute_collection(
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
fn nss_snapshot_freshness_ms(configured_ms: u32) -> u64 {
    u64::from(configured_ms.max(CLASSIFIER_INTERVAL_MS as u32)).saturating_mul(3)
}

#[cfg(feature = "nss-platform")]
fn classifier_map_metrics(
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
fn classifier_map_evidence(
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
fn access_edge_global_evidence(
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

fn production_now_ms() -> Result<u64, DaemonError> {
    monotonic_millis()
        .map_err(|error| DaemonError::collection(format!("read CLOCK_MONOTONIC: {error}")))
}

struct ProductionRuntime {
    config: RuntimeConfig,
    adapter: SystemAyaAdapter,
    bpf: Option<Bpf>,
    bpf_error: Option<String>,
    /// Stable internal classification for the last BPF failure. The public
    /// evidence exposes this code, while `bpf_error` remains private detail.
    bpf_error_stage: Option<&'static str>,
    bpf_collector: BpfSnapshotCollector,
    #[cfg(feature = "nss-platform")]
    nss: NssRuntime,
    #[cfg(feature = "nss-platform")]
    access_edge: AccessEdgeRuntime,
    #[cfg(feature = "nss-platform")]
    classification_results: BTreeMap<String, ClassificationResult>,
    #[cfg(feature = "nss-platform")]
    classifier_epoch_id: u64,
    #[cfg(feature = "nss-platform")]
    next_classifier_deadline_ms: u64,
    conntrack_snapshot: Option<Arc<CollectedSnapshot>>,
    connection_rates: ConnectionRateBook,
    conntrack_observation: ConntrackObservation,
    probe: SystemProbeCollector,
    process_tracker: DaeProcessTracker,
    probe_report: Arc<ProbeReport>,
    next_probe_ms: u64,
    overview: OverviewRing,
    x86_coverage: X86Coverage,
    #[cfg(feature = "nss-platform")]
    nss_bpf_coverage: NssBpfCoverage,
    interface_rates: InterfaceRateBook,
    rate_owner: Option<RateCollector>,
    hostnames: HostnameCache,
    shutdown_complete: bool,
}

struct RuntimeCheckpoint {
    bpf: Option<BpfCollectionCheckpoint>,
    #[cfg(feature = "nss-platform")]
    nss: NssRuntimeCheckpoint,
    #[cfg(feature = "nss-platform")]
    access_edge: AccessEdgeCheckpoint,
    #[cfg(feature = "nss-platform")]
    classification_results: BTreeMap<String, ClassificationResult>,
    #[cfg(feature = "nss-platform")]
    classifier_epoch_id: u64,
    #[cfg(feature = "nss-platform")]
    next_classifier_deadline_ms: u64,
    overview: OverviewRing,
    x86_coverage: X86Coverage,
    #[cfg(feature = "nss-platform")]
    nss_bpf_coverage: NssBpfCoverage,
    interface_rates: InterfaceRateBook,
    rate_owner: Option<RateCollector>,
    hostnames: HostnameCache,
    conntrack_snapshot: Option<Arc<CollectedSnapshot>>,
    connection_rates: ConnectionRateBook,
    conntrack_observation: ConntrackObservation,
    probe_report: Arc<ProbeReport>,
    next_probe_ms: u64,
    bpf_error: Option<String>,
    bpf_error_stage: Option<&'static str>,
}

impl ProductionRuntime {
    fn stage(config: RuntimeConfig) -> Result<Self, DaemonError> {
        let mut runtime = Self::prepare(config)?;
        runtime.activate_new_bpf()?;
        #[cfg(feature = "nss-platform")]
        runtime.nss.activate(&runtime.config, &runtime.probe_report);
        Ok(runtime)
    }

    fn prepare(config: RuntimeConfig) -> Result<Self, DaemonError> {
        Self::prepare_with_process_tracker(config, DaeProcessTracker::default())
    }

    fn prepare_with_process_tracker(
        mut config: RuntimeConfig,
        mut process_tracker: DaeProcessTracker,
    ) -> Result<Self, DaemonError> {
        config.enforce_platform_profile();
        let mut probe = collector::system_collector()
            .map_err(|error| DaemonError::platform(error.to_string()))?;
        process_tracker.refresh_if_due("/proc", production_now_ms()?);
        let mut preflight = probe.collect(&config, &RuntimeHealth::default(), ProbeMethod::Health);
        process_tracker.overlay_report(&mut preflight);
        Ok(Self {
            bpf_collector: BpfSnapshotCollector::new(
                config.max_clients,
                config.active_client_window_ms,
            ),
            #[cfg(feature = "nss-platform")]
            nss: NssRuntime::default(),
            #[cfg(feature = "nss-platform")]
            access_edge: AccessEdgeRuntime::new(config.max_clients),
            #[cfg(feature = "nss-platform")]
            classification_results: BTreeMap::new(),
            #[cfg(feature = "nss-platform")]
            classifier_epoch_id: 0,
            #[cfg(feature = "nss-platform")]
            next_classifier_deadline_ms: 0,
            conntrack_snapshot: None,
            connection_rates: ConnectionRateBook::default(),
            conntrack_observation: ConntrackObservation::default(),
            probe,
            process_tracker,
            probe_report: Arc::new(preflight),
            next_probe_ms: 0,
            rate_owner: None,
            hostnames: HostnameCache::new(),
            adapter: SystemAyaAdapter::with_max_clients(config.max_clients),
            config,
            bpf: None,
            bpf_error: None,
            bpf_error_stage: None,
            overview: OverviewRing::new(),
            x86_coverage: X86Coverage::default(),
            #[cfg(feature = "nss-platform")]
            nss_bpf_coverage: NssBpfCoverage::default(),
            interface_rates: InterfaceRateBook::default(),
            shutdown_complete: false,
        })
    }

    fn desired_attach_mode(&self) -> AttachMode {
        if self.probe_report.facts.tc.dae_preempts_lan_ingress
            || self.probe_report.facts.proxy.runtime_active
        {
            AttachMode::EarlyPassthrough
        } else {
            AttachMode::Normal
        }
    }

    fn refresh_dae_process_state(&mut self) -> bool {
        let Ok(now_ms) = production_now_ms() else {
            return false;
        };
        let Some(activity_changed) = self.process_tracker.refresh_if_due("/proc", now_ms) else {
            return false;
        };
        self.process_tracker
            .overlay_report(Arc::make_mut(&mut self.probe_report));
        activity_changed
    }

    fn bpf_attach_mode_mismatch(&self) -> bool {
        self.bpf
            .as_ref()
            .and_then(BpfRuntime::attach_mode)
            .is_some_and(|mode| mode != self.desired_attach_mode())
    }

    fn activate_new_bpf(&mut self) -> Result<(), DaemonError> {
        if !self.config.enable_bpf
            || !matches!(
                self.config.rate_collector_mode,
                crate::config::RateCollectorMode::Auto
                    | crate::config::RateCollectorMode::Bpf
                    | crate::config::RateCollectorMode::NssEcmBpf
            )
            || !self.probe_report.facts.tc.safe_attach
        {
            return Ok(());
        }
        let interfaces = collect_ifnames(&self.config);
        if interfaces.is_empty() {
            self.bpf_error = None;
            self.bpf_error_stage = None;
            return Ok(());
        }
        let mut loaded = match BpfRuntime::load_byte_only(&mut self.adapter, FALLBACK_OBJECT_PATH) {
            Ok(runtime) => runtime,
            Err(error) => {
                self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
                self.bpf_error = Some(error.to_string());
                return Ok(());
            }
        };
        let mode = self.desired_attach_mode();
        if let Err(error) = loaded.attach_interfaces(&mut self.adapter, &interfaces, mode) {
            self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
            if let Err(cleanup) = loaded.shutdown(&mut self.adapter) {
                return Err(DaemonError::collection(format!(
                    "{error}; BPF cleanup failed: {cleanup}"
                )));
            }
            self.bpf_error = Some(error.to_string());
            self.adapter = SystemAyaAdapter::with_max_clients(self.config.max_clients);
            return Ok(());
        }
        self.bpf = Some(loaded);
        self.bpf_error = None;
        self.bpf_error_stage = None;
        Ok(())
    }

    fn checkpoint(&self) -> RuntimeCheckpoint {
        RuntimeCheckpoint {
            bpf: self
                .bpf
                .as_ref()
                .map(|runtime| runtime.collection_checkpoint(&self.bpf_collector)),
            #[cfg(feature = "nss-platform")]
            nss: self.nss.checkpoint(),
            #[cfg(feature = "nss-platform")]
            access_edge: self.access_edge.checkpoint(),
            #[cfg(feature = "nss-platform")]
            classification_results: self.classification_results.clone(),
            #[cfg(feature = "nss-platform")]
            classifier_epoch_id: self.classifier_epoch_id,
            #[cfg(feature = "nss-platform")]
            next_classifier_deadline_ms: self.next_classifier_deadline_ms,
            overview: self.overview.clone(),
            x86_coverage: self.x86_coverage.clone(),
            #[cfg(feature = "nss-platform")]
            nss_bpf_coverage: self.nss_bpf_coverage.clone(),
            interface_rates: self.interface_rates.clone(),
            rate_owner: self.rate_owner,
            hostnames: self.hostnames.clone(),
            conntrack_snapshot: self.conntrack_snapshot.clone(),
            connection_rates: self.connection_rates.clone(),
            conntrack_observation: self.conntrack_observation.clone(),
            probe_report: self.probe_report.clone(),
            next_probe_ms: self.next_probe_ms,
            bpf_error: self.bpf_error.clone(),
            bpf_error_stage: self.bpf_error_stage,
        }
    }

    fn restore(&mut self, checkpoint: RuntimeCheckpoint) {
        if let (Some(runtime), Some(checkpoint)) = (self.bpf.as_mut(), checkpoint.bpf) {
            runtime.restore_collection_checkpoint(&mut self.bpf_collector, checkpoint);
        }
        #[cfg(feature = "nss-platform")]
        {
            self.nss.restore(checkpoint.nss);
            self.access_edge.restore(checkpoint.access_edge);
            self.classification_results = checkpoint.classification_results;
            self.classifier_epoch_id = checkpoint.classifier_epoch_id;
            self.next_classifier_deadline_ms = checkpoint.next_classifier_deadline_ms;
        }
        self.overview = checkpoint.overview;
        self.x86_coverage = checkpoint.x86_coverage;
        #[cfg(feature = "nss-platform")]
        {
            self.nss_bpf_coverage = checkpoint.nss_bpf_coverage;
        }
        self.interface_rates = checkpoint.interface_rates;
        self.rate_owner = checkpoint.rate_owner;
        self.hostnames = checkpoint.hostnames;
        self.conntrack_snapshot = checkpoint.conntrack_snapshot;
        self.connection_rates = checkpoint.connection_rates;
        self.conntrack_observation = checkpoint.conntrack_observation;
        self.probe_report = checkpoint.probe_report;
        self.next_probe_ms = checkpoint.next_probe_ms;
        self.bpf_error = checkpoint.bpf_error;
        self.bpf_error_stage = checkpoint.bpf_error_stage;
    }

    fn read_conntrack(
        &mut self,
        identities: &IdentityTable,
        now_ms: u64,
        defer_connection_rates: bool,
    ) -> Result<Arc<CollectedSnapshot>, String> {
        match conntrack::collect(
            conntrack_mode(self.config.conn_collector_mode),
            identities,
            now_ms,
            self.config.max_clients,
        ) {
            Ok(mut snapshot) => {
                if defer_connection_rates {
                    self.connection_rates.update_deferred(
                        snapshot.sample_ms,
                        &snapshot.connection_counters,
                        &mut snapshot.connection_details,
                    );
                } else {
                    self.connection_rates.update(
                        snapshot.sample_ms,
                        &snapshot.connection_counters,
                        &mut snapshot.connection_details,
                    );
                }
                self.conntrack_observation.record_success(
                    now_ms,
                    snapshot.stats.netlink_read,
                    snapshot.stats.procfs_read,
                );
                let snapshot = Arc::new(snapshot);
                self.conntrack_snapshot = Some(Arc::clone(&snapshot));
                Ok(snapshot)
            }
            Err(error) => {
                let message = error.to_string();
                self.connection_rates.clear();
                self.conntrack_observation
                    .record_failure(now_ms, message.clone(), false, false);
                self.conntrack_snapshot = None;
                Err(message)
            }
        }
    }

    fn apply_conntrack_health(&self, runtime_health: &mut RuntimeHealth) {
        self.conntrack_observation
            .apply_runtime_health(self.conntrack_snapshot.is_some(), runtime_health);
    }

    fn refresh_connections(
        &mut self,
        base: &ResponseSnapshot,
    ) -> Result<ResponseSnapshot, DaemonError> {
        let now_ms = production_now_ms()?;
        let defer_connection_rates = matches!(
            self.rate_owner,
            Some(RateCollector::NssEcmNode | RateCollector::NssEcmBpf)
        );
        let plan = client_conntrack_plan(
            now_ms,
            self.conntrack_observation.last_attempt_ms,
            self.conntrack_snapshot.is_some(),
            if defer_connection_rates {
                NSS_CLIENT_CONNTRACK_CACHE_TTL_MS
            } else {
                CLIENT_CONNTRACK_CACHE_TTL_MS
            },
        );
        let cached = if plan == ClientConntrackPlan::ReuseCached {
            self.conntrack_snapshot.as_ref().map(|collected| {
                apply_conntrack_success(base, collected, self.config.conn_collector_mode.as_str())
            })
        } else {
            None
        };
        let (mut snapshot, identity_errors) = if let Some(snapshot) = cached {
            (snapshot, Vec::new())
        } else {
            let (identities, identity_errors) = read_identities(&self.config, now_ms);
            let snapshot = match self.read_conntrack(&identities, now_ms, defer_connection_rates) {
                Ok(collected) => apply_conntrack_success(
                    base,
                    &collected,
                    self.config.conn_collector_mode.as_str(),
                ),
                Err(error) => apply_conntrack_failure(base, &error),
            };
            (snapshot, identity_errors)
        };
        if !identity_errors.is_empty() {
            snapshot
                .clients
                .evidence
                .get_or_insert_default()
                .details
                .insert("identity_errors".into(), json!(identity_errors));
        }
        let totals = ConnectionTotals::new(
            snapshot.clients.tcp_conns_total.unwrap_or(0),
            snapshot.clients.udp_conns_total.unwrap_or(0),
            snapshot.clients.udp_dns_conns_total.unwrap_or(0),
            snapshot.clients.udp_other_conns_total.unwrap_or(0),
        );
        self.overview
            .replace_latest_connections_and_client_count(totals, snapshot.clients.clients.len());
        Ok(snapshot)
    }

    fn collect(&mut self, method: ProbeMethod) -> Result<ResponseSnapshot, DaemonError> {
        let checkpoint = self.checkpoint();
        let result = self.collect_inner(method, None).and_then(|snapshot| {
            for method in ubus::Method::FIXED {
                snapshot.response(method)?;
            }
            Ok(snapshot)
        });
        match result {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                self.restore(checkpoint);
                Err(error)
            }
        }
    }

    fn collect_with_external_bpf(
        &mut self,
        runtime: &mut Bpf,
        adapter: &mut SystemAyaAdapter,
        method: ProbeMethod,
    ) -> Result<(ResponseSnapshot, BpfCollectionCheckpoint), DaemonError> {
        let checkpoint = self.checkpoint();
        let bpf_checkpoint = runtime.collection_checkpoint(&self.bpf_collector);
        let result = self
            .collect_inner(method, Some((&mut *runtime, &mut *adapter)))
            .and_then(|snapshot| {
                for method in ubus::Method::FIXED {
                    snapshot.response(method)?;
                }
                Ok(snapshot)
            });
        match result {
            Ok(snapshot) => Ok((snapshot, bpf_checkpoint)),
            Err(error) => {
                runtime.restore_collection_checkpoint(&mut self.bpf_collector, bpf_checkpoint);
                self.restore(checkpoint);
                Err(error)
            }
        }
    }

    // x86 is intentionally a separate production path. It reads the native
    // TC-BPF client map and publishes that single source directly; no NSS map,
    // Access Edge topology, classifier window, or RateMux state is reachable
    // from this build.
    #[cfg(not(feature = "nss-platform"))]
    fn collect_inner(
        &mut self,
        method: ProbeMethod,
        external_bpf: Option<(&mut Bpf, &mut SystemAyaAdapter)>,
    ) -> Result<ResponseSnapshot, DaemonError> {
        let mut now_ms = production_now_ms()?;
        let (identities, identity_errors) = read_identities(&self.config, now_ms);
        let conntrack = self.conntrack_snapshot.clone();
        let overlay = connection_overlay(conntrack.as_deref());
        let freshness_ms = u64::from(self.config.refresh_interval_ms).saturating_mul(3);
        let (bpf_snapshot, mut runtime_health, bpf_snapshot_fresh) = match external_bpf {
            Some((runtime, adapter)) => match runtime.collect_snapshot_self_healing(
                adapter,
                &mut self.bpf_collector,
                &identities,
                &overlay,
                now_ms,
                EXTERNAL_BPF_SELF_HEAL_REASON,
            ) {
                Ok(snapshot) => {
                    self.bpf_error = None;
                    self.bpf_error_stage = None;
                    let health_now_ms = now_ms.max(snapshot.sample_ms);
                    let health = runtime.runtime_health(health_now_ms, freshness_ms);
                    (Some(snapshot), health, true)
                }
                Err(error) => {
                    self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
                    self.bpf_error = Some(error.to_string());
                    let snapshot = self.bpf_collector.last_complete().cloned();
                    let health_now_ms = snapshot
                        .as_ref()
                        .map_or(now_ms, |value| now_ms.max(value.sample_ms));
                    let health = runtime.runtime_health(health_now_ms, freshness_ms);
                    (snapshot, health, false)
                }
            },
            None => match self.bpf.as_mut() {
                Some(runtime) => match runtime.collect_snapshot_self_healing(
                    &mut self.adapter,
                    &mut self.bpf_collector,
                    &identities,
                    &overlay,
                    now_ms,
                    INTERNAL_BPF_SELF_HEAL_REASON,
                ) {
                    Ok(snapshot) => {
                        self.bpf_error = None;
                        self.bpf_error_stage = None;
                        let health_now_ms = now_ms.max(snapshot.sample_ms);
                        let health = runtime.runtime_health(health_now_ms, freshness_ms);
                        (Some(snapshot), health, true)
                    }
                    Err(error) => {
                        self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
                        self.bpf_error = Some(error.to_string());
                        let snapshot = self.bpf_collector.last_complete().cloned();
                        let health_now_ms = snapshot
                            .as_ref()
                            .map_or(now_ms, |value| now_ms.max(value.sample_ms));
                        let health = runtime.runtime_health(health_now_ms, freshness_ms);
                        (snapshot, health, false)
                    }
                },
                None => (None, RuntimeHealth::default(), false),
            },
        };
        if runtime_health.bpf_object_loaded {
            runtime_health.bpf_map_capacity = self.config.max_clients.saturating_mul(4);
        }
        if let Some(snapshot) = bpf_snapshot.as_ref() {
            now_ms = now_ms.max(snapshot.sample_ms);
        }
        runtime_health.now_ms = now_ms;
        self.apply_conntrack_health(&mut runtime_health);
        if runtime_health.runtime_error.is_none() {
            runtime_health.runtime_error = self.bpf_error.clone();
        }
        if probe_due(now_ms, self.next_probe_ms, method) {
            let mut report = self.probe.collect(&self.config, &runtime_health, method);
            self.process_tracker.overlay_report(&mut report);
            self.probe_report = Arc::new(report);
            self.next_probe_ms = probe_deadline(now_ms);
        }
        let report = Arc::clone(&self.probe_report);
        let mut decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        if matches!(
            periodic_conntrack_plan(decision.rate),
            PeriodicConntrackPlan::Skip
        ) {
            self.conntrack_observation.record_skipped();
        }
        self.apply_conntrack_health(&mut runtime_health);
        decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        let (interfaces, counter_snapshot) = self.interfaces_x86(now_ms);
        let mut clients = if decision.rate == RateCollector::Bpf {
            clients_response(
                bpf_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.clients.as_slice()),
                conntrack.as_deref(),
                &identities,
                decision.confidence,
            )
        } else {
            ClientsResponse::empty(evidence(&report, "clients"))
        };
        let actual_live = decision.rate == RateCollector::Bpf && bpf_snapshot.is_some();
        let actual_degraded = !actual_live;
        self.hostnames.refresh_from_paths(
            &HostnamePaths::default(),
            now_ms,
            method == ProbeMethod::Reload,
        );
        for client in &mut clients.clients {
            let ips = client.ips.iter().map(String::as_str).collect::<Vec<_>>();
            client.hostname = self.hostnames.lookup(&client.mac, &ips).map(str::to_owned);
        }
        if let Some(snapshot) = conntrack.as_ref() {
            clients.conntrack_entries_seen = Some(snapshot.stats.entries_seen as u64);
            clients.conntrack_entries_matched = Some(snapshot.stats.entries_matched as u64);
            clients.conntrack_parse_errors = Some(snapshot.stats.malformed_lines as u64);
            clients.conn_source = Some(
                if snapshot.stats.netlink_read {
                    "conntrack_netlink"
                } else {
                    "conntrack_procfs"
                }
                .into(),
            );
            clients.conn_collector_mode = Some(self.config.conn_collector_mode.as_str().into());
        }
        if clients.evidence.is_none() {
            clients.evidence = Some(evidence(&report, "clients"));
        }
        if let Some(client_evidence) = clients.evidence.as_mut() {
            apply_decision_evidence(client_evidence, &decision, &self.config, &report);
            client_evidence.details.insert(
                "x86_rate_path".into(),
                json!({
                    "profile": "tc_bpf",
                    "source": "platform::x86::output::clients_response",
                }),
            );
            if let Some(snapshot) = conntrack.as_deref() {
                client_evidence.details.insert(
                    "conntrack_generation".into(),
                    conntrack_generation_evidence(snapshot),
                );
            }
        }
        let overview = self.update_overview(now_ms, &clients);
        let coverage = self
            .x86_coverage
            .update(now_ms, &clients, &interfaces, bpf_snapshot_fresh);
        let sysdevices = sysdevices(&self.config)?;
        let mut capabilities = capabilities(&report.capabilities, &report);
        capabilities.nss = false;
        capabilities.nss_ecm_offload = false;
        capabilities.nss_ppe_offload = false;
        capabilities.nss_ecm_node = false;
        capabilities.nss_ecm_bpf = false;
        capabilities.nss_bridge_mgr = false;
        capabilities.nss_ifb = false;
        capabilities.nss_nsm = false;
        capabilities.nss_dp = false;
        capabilities.nss_mcs = false;
        capabilities.live_metrics = actual_live;
        capabilities.conntrack_fallback = false;
        capabilities.bpf_runtime_metrics = runtime_health.bpf_object_loaded
            && runtime_health.bpf_attached
            && bpf_snapshot.is_some()
            && (runtime_health.bpf_map_read_ok || decision.evidence.retained_fresh_snapshot);
        capabilities.bpf = capabilities.bpf_runtime_metrics;
        if capabilities.bpf_runtime_metrics {
            capabilities.bpf_supported = true;
            capabilities.bpf_package = true;
            capabilities.bpf_object = true;
            capabilities.tc = true;
            capabilities.tc_clsact = true;
        }
        let mode = if decision.mode == ProbeMode::Unsupported {
            Mode::Unsupported
        } else if !actual_live || actual_degraded || !identity_errors.is_empty() {
            Mode::Degraded
        } else {
            mode(decision.mode)
        };
        let confidence = if mode == Mode::Unsupported {
            Confidence::Unsupported
        } else if !actual_live || !identity_errors.is_empty() {
            Confidence::Low
        } else {
            confidence(decision.confidence)
        };
        let mut status_evidence = runtime_evidence(
            &report,
            method.as_str(),
            &self.config,
            &runtime_health,
            self.bpf_error_stage,
        );
        apply_decision_evidence(&mut status_evidence, &decision, &self.config, &report);
        status_evidence.details.insert(
            "x86_rate_path".into(),
            json!({
                "profile": "tc_bpf",
                "counter_snapshot_interfaces": counter_snapshot.counters.len(),
            }),
        );
        let mut warnings = report
            .warnings
            .iter()
            .map(|warning| (*warning).to_owned())
            .collect::<Vec<_>>();
        for warning in &decision.warnings {
            if !warnings.iter().any(|value| value == warning) {
                warnings.push((*warning).into());
            }
        }
        if capabilities.bpf_runtime_metrics {
            warnings.retain(|warning| {
                !matches!(
                    warning.as_str(),
                    "bpf_unsupported"
                        | "tc_clsact_unsupported"
                        | "unsafe_attach"
                        | "bpf_runtime_loader_unavailable"
                        | "bpf_optional_package_missing"
                        | "bpf_object_missing"
                )
            });
        }
        if !actual_live
            && !warnings
                .iter()
                .any(|warning| warning == "live_metrics_unavailable")
        {
            warnings.push("live_metrics_unavailable".into());
        }
        if !identity_errors.is_empty()
            && !warnings
                .iter()
                .any(|warning| warning == "lan_topology_probe_error")
        {
            warnings.push("lan_topology_probe_error".into());
            status_evidence
                .details
                .insert("identity_errors".into(), json!(identity_errors));
        }
        let version = version();
        let status = StatusResponse {
            mode,
            confidence,
            warnings: warnings.clone(),
            evidence: status_evidence.clone(),
            refresh_interval_ms: self.config.refresh_interval_ms,
            active_client_window_ms: self.config.active_client_window_ms,
            active_client_min_bps: self.config.active_client_min_bps,
            overview_window_samples: self.config.overview_window_samples,
            collector_mode: decision.rate.as_str().into(),
            rate_collector_mode: self.config.rate_collector_mode.as_str().into(),
            access_edge_mode: "off".into(),
            conn_collector_mode: self.config.conn_collector_mode.as_str().into(),
            version: version.clone(),
            capabilities: capabilities.clone(),
            coverage: Some(coverage),
        };
        let mut health_evidence = runtime_evidence(
            &report,
            "health",
            &self.config,
            &runtime_health,
            self.bpf_error_stage,
        );
        apply_decision_evidence(&mut health_evidence, &decision, &self.config, &report);
        health_evidence.details.insert(
            "x86_rate_path".into(),
            json!({
                "profile": "tc_bpf",
            }),
        );
        let health = HealthResponse {
            mode,
            confidence,
            capabilities,
            conflicts: report
                .conflicts
                .iter()
                .map(|item| Conflict {
                    id: item.id.into(),
                    severity: item.severity.into(),
                    message: item.message.into(),
                    evidence: BTreeMap::new(),
                })
                .collect(),
            warnings: warnings.clone(),
            evidence: health_evidence,
        };
        let mut reload_evidence = evidence(&report, "reload");
        apply_decision_evidence(&mut reload_evidence, &decision, &self.config, &report);
        let reload = ReloadResponse {
            ok: true,
            mode,
            warnings,
            evidence: reload_evidence,
            version,
        };
        let mut response = ResponseSnapshot::from_responses(
            status, clients, overview, health, reload, interfaces, sysdevices,
        );
        publish_connection_details(&mut response, conntrack.as_deref());
        Ok(response)
    }

    #[cfg(feature = "nss-platform")]
    fn collect_inner(
        &mut self,
        method: ProbeMethod,
        external_bpf: Option<(&mut Bpf, &mut SystemAyaAdapter)>,
    ) -> Result<ResponseSnapshot, DaemonError> {
        let mut now_ms = production_now_ms()?;
        let access_edge_enabled = self.config.access_edge_mode != AccessEdgeMode::Off;
        if !access_edge_enabled {
            self.access_edge.reset_for_disabled_mode();
        }
        let classifier_due = access_edge_enabled
            && periodic_deadline_due(
                &mut self.next_classifier_deadline_ms,
                now_ms,
                CLASSIFIER_INTERVAL_MS,
            );
        let throttle_classifier_maps = access_edge_enabled
            && self.probe_report.facts.nss.present
            && matches!(
                self.config.rate_collector_mode,
                RateCollectorMode::Auto | RateCollectorMode::NssEcmBpf
            );
        let classifier_map_read_due = !throttle_classifier_maps || classifier_due;
        let (mut identities, mut identity_errors) = read_identities(&self.config, now_ms);
        if access_edge_enabled {
            let bridges = access_edge_bridges(&self.config);
            self.access_edge.collect_topology(
                &bridges,
                self.config.max_clients.saturating_mul(4),
                now_ms,
            );
        }
        if access_edge_enabled {
            for hint in self.access_edge.identity_hints() {
                let zone = filter::derive_zone_from_ifname(&hint.logical_interface);
                if let Err(error) = identities.observe(IdentityObservation {
                    mac: &hint.mac,
                    zone: Some(&zone),
                    interface: &hint.logical_interface,
                    ip: None,
                    hostname: None,
                    last_seen: now_ms,
                    source: if hint.wireless {
                        ObservationSource::Wireless
                    } else {
                        ObservationSource::Netifd
                    },
                }) {
                    identity_errors.push(format!("Access Edge identity: {error}"));
                }
            }
        }
        let mut conntrack = self.conntrack_snapshot.clone();
        let overlay = connection_overlay(conntrack.as_deref());
        // Sample the authoritative Edge counters immediately before the two
        // classifier maps. Keeping this read group adjacent makes the actual
        // 1s Edge segments comparable to the 2s ECM/TC epochs without assigning
        // a synthetic timestamp to any source.
        let edge_port_names = if access_edge_enabled {
            self.access_edge.port_ifnames()
        } else {
            BTreeSet::new()
        };
        let edge_read_begin_ms = production_now_ms()?;
        let (mut interfaces, lan_clock, interface_counter_snapshot) =
            self.interfaces(now_ms, &edge_port_names);
        let edge_read_end_ms = production_now_ms()?;
        now_ms = now_ms.max(edge_read_end_ms);
        if access_edge_enabled {
            self.access_edge.update_rates(
                &interface_counter_snapshot,
                edge_read_begin_ms,
                edge_read_end_ms,
                edge_read_end_ms,
            );
        }
        // Keep the x86 BPF freshness contract tied to its configured cadence.
        // NSS has a dedicated two-second floor, so its retained ECM snapshot
        // must use that effective cadence rather than the one-second default.
        let bpf_freshness_ms = if throttle_classifier_maps {
            CLASSIFIER_INTERVAL_MS.saturating_mul(3)
        } else {
            u64::from(self.config.refresh_interval_ms).saturating_mul(3)
        };
        let nss_freshness_ms = nss_snapshot_freshness_ms(self.config.refresh_interval_ms);
        let (bpf_snapshot, mut runtime_health, bpf_snapshot_fresh) = match external_bpf {
            Some((runtime, adapter)) => {
                let (snapshot, fresh) = if classifier_map_read_due {
                    match runtime.collect_snapshot_self_healing(
                        adapter,
                        &mut self.bpf_collector,
                        &identities,
                        &overlay,
                        now_ms,
                        EXTERNAL_BPF_SELF_HEAL_REASON,
                    ) {
                        Ok(snapshot) => {
                            self.bpf_error = None;
                            self.bpf_error_stage = None;
                            (Some(snapshot), true)
                        }
                        Err(error) => {
                            self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
                            self.bpf_error = Some(error.to_string());
                            (self.bpf_collector.last_complete().cloned(), false)
                        }
                    }
                } else {
                    (self.bpf_collector.last_complete().cloned(), false)
                };
                let health_now_ms = snapshot
                    .as_ref()
                    .map_or(now_ms, |snapshot| now_ms.max(snapshot.sample_ms));
                (
                    snapshot,
                    runtime.runtime_health(health_now_ms, bpf_freshness_ms),
                    fresh,
                )
            }
            None => match self.bpf.as_mut() {
                Some(runtime) => {
                    let (snapshot, fresh) = if classifier_map_read_due {
                        match runtime.collect_snapshot_self_healing(
                            &mut self.adapter,
                            &mut self.bpf_collector,
                            &identities,
                            &overlay,
                            now_ms,
                            INTERNAL_BPF_SELF_HEAL_REASON,
                        ) {
                            Ok(snapshot) => {
                                self.bpf_error = None;
                                self.bpf_error_stage = None;
                                (Some(snapshot), true)
                            }
                            Err(error) => {
                                self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
                                self.bpf_error = Some(error.to_string());
                                (self.bpf_collector.last_complete().cloned(), false)
                            }
                        }
                    } else {
                        (self.bpf_collector.last_complete().cloned(), false)
                    };
                    let health_now_ms = snapshot
                        .as_ref()
                        .map_or(now_ms, |snapshot| now_ms.max(snapshot.sample_ms));
                    (
                        snapshot,
                        runtime.runtime_health(health_now_ms, bpf_freshness_ms),
                        fresh,
                    )
                }
                None => (None, RuntimeHealth::default(), false),
            },
        };
        if runtime_health.bpf_object_loaded {
            runtime_health.bpf_map_capacity = self.config.max_clients.saturating_mul(4);
        }
        let bpf_classifier_read_end_ms = if bpf_snapshot_fresh {
            Some(production_now_ms()?)
        } else {
            None
        };
        if let Some(snapshot) = bpf_snapshot.as_ref() {
            now_ms = now_ms.max(snapshot.sample_ms);
        }
        let (ecm_bpf_snapshot, ecm_bpf_snapshot_fresh) = self.nss.collect_ecm_bpf(
            &identities,
            &mut now_ms,
            nss_freshness_ms,
            &mut runtime_health,
            classifier_map_read_due,
        );
        let ecm_classifier_read_end_ms = if ecm_bpf_snapshot_fresh {
            Some(production_now_ms()?)
        } else {
            None
        };
        for read_end_ms in [bpf_classifier_read_end_ms, ecm_classifier_read_end_ms]
            .into_iter()
            .flatten()
        {
            now_ms = now_ms.max(read_end_ms);
        }
        runtime_health.now_ms = now_ms;
        self.apply_conntrack_health(&mut runtime_health);
        if runtime_health.runtime_error.is_none() {
            runtime_health.runtime_error = self.bpf_error.clone();
        }
        if probe_due(now_ms, self.next_probe_ms, method) {
            let mut report = self.probe.collect(&self.config, &runtime_health, method);
            self.process_tracker.overlay_report(&mut report);
            self.probe_report = Arc::new(report);
            self.next_probe_ms = probe_deadline(now_ms);
        }
        let report = Arc::clone(&self.probe_report);
        let mut decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        let node_snapshot = if decision.rate == RateCollector::NssEcmNode {
            self.nss.read_node(&identities, now_ms, &mut runtime_health)
        } else {
            None
        };
        decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        match periodic_conntrack_plan(decision.rate) {
            PeriodicConntrackPlan::Read => {
                let defer_connection_rates = matches!(
                    decision.rate,
                    RateCollector::NssEcmNode | RateCollector::NssEcmBpf
                );
                conntrack = self
                    .read_conntrack(&identities, now_ms, defer_connection_rates)
                    .ok();
            }
            PeriodicConntrackPlan::Skip => {
                self.conntrack_observation.record_skipped();
            }
        }
        self.apply_conntrack_health(&mut runtime_health);
        decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        let nss_tc_snapshot = report
            .facts
            .nss
            .present
            .then(|| bpf_snapshot.as_ref().map(nss_tc_snapshot))
            .flatten();
        if classifier_due {
            self.update_access_classification(
                &identities,
                ecm_bpf_snapshot.as_ref(),
                ecm_bpf_snapshot_fresh,
                ecm_classifier_read_end_ms,
                nss_tc_snapshot.as_ref(),
                bpf_snapshot_fresh,
                bpf_classifier_read_end_ms,
                &runtime_health,
            );
        }
        self.nss
            .transition_rate_owner(&mut self.rate_owner, decision.rate);
        let legacy_nss_rate_window_enabled = legacy_nss_rate_window_enabled(
            self.config.access_edge_mode,
            self.config.rate_collector_mode,
        );
        let mut nss_window = None;
        let mut ecm_bpf_coverage_window = None;
        let mut ecm_bpf_coverage_merge = None;
        let mut ecm_bpf_rate_batch = None;
        let (mut clients, actual_live, actual_degraded, coverage_fresh) =
            if decision.rate == RateCollector::Bpf {
                (
                    clients_response(
                        bpf_snapshot
                            .as_ref()
                            .map(|snapshot| snapshot.clients.as_slice()),
                        conntrack.as_deref(),
                        &identities,
                        decision.confidence,
                    ),
                    bpf_snapshot.is_some(),
                    bpf_snapshot.is_none(),
                    bpf_snapshot_fresh,
                )
            } else if decision.rate == RateCollector::NssEcmNode {
                match (node_snapshot.as_ref(), lan_clock) {
                    (Some(snapshot), Some(lan)) => {
                        let window = self.nss.node_windows.update(snapshot, lan);
                        let live = !matches!(
                            window.quality,
                            WindowQuality::CounterReset | WindowQuality::CounterSkew
                        );
                        let degraded = matches!(
                            window.quality,
                            WindowQuality::Warmup
                                | WindowQuality::CounterReset
                                | WindowQuality::CounterSkew
                        );
                        let response = window_clients(
                            &window,
                            &identities,
                            conntrack.as_deref(),
                            decision.confidence,
                            &report,
                        );
                        nss_window = Some(window);
                        (response, live, degraded, true)
                    }
                    _ => (
                        ClientsResponse::empty(evidence(&report, "clients")),
                        false,
                        true,
                        false,
                    ),
                }
            } else if decision.rate == RateCollector::NssEcmBpf {
                let ecm_bpf_current =
                    ecm_bpf_snapshot_current(ecm_bpf_snapshot.as_ref(), &runtime_health);
                if ecm_bpf_snapshot_fresh {
                    match (ecm_bpf_snapshot.as_ref(), lan_clock.as_ref()) {
                        (Some(snapshot), Some(lan)) if !snapshot.truncated => {
                            let merged = merge_ecm_bpf_coverage_delta(
                                snapshot,
                                nss_tc_snapshot.as_ref(),
                                bpf_snapshot_fresh,
                            );
                            ecm_bpf_coverage_window =
                                Some(self.nss.ecm_bpf_coverage.update(merged.merged, lan));
                            if legacy_nss_rate_window_enabled {
                                let client_deltas = merge_ecm_bpf_client_deltas(
                                    snapshot,
                                    nss_tc_snapshot.as_ref(),
                                    bpf_snapshot_fresh,
                                );
                                let fallback_rates = ecm_bpf_fallback_client_rates(
                                    snapshot,
                                    nss_tc_snapshot.as_ref(),
                                    bpf_snapshot_fresh,
                                );
                                let client_interfaces = ecm_bpf_client_interfaces(
                                    snapshot,
                                    nss_tc_snapshot.as_ref(),
                                    bpf_snapshot_fresh,
                                );
                                ecm_bpf_rate_batch =
                                    self.nss.ecm_bpf_rates.update_with_client_interfaces(
                                        &client_deltas,
                                        &fallback_rates,
                                        &client_interfaces,
                                        lan,
                                        &rate_window_interface_counters(&interfaces),
                                    );
                            } else {
                                self.nss.ecm_bpf_rates = Default::default();
                            }
                            ecm_bpf_coverage_merge = Some(merged);
                        }
                        _ => {
                            self.nss.ecm_bpf_coverage = Default::default();
                            self.nss.ecm_bpf_rates = Default::default();
                        }
                    }
                }
                if legacy_nss_rate_window_enabled
                    && ecm_bpf_rate_batch.is_none()
                    && !ecm_bpf_snapshot_fresh
                {
                    ecm_bpf_rate_batch = lan_clock
                        .as_ref()
                        .and_then(|lan| self.nss.ecm_bpf_rates.held_at(lan.sample_ms));
                }
                (
                    ecm_bpf_clients_response(
                        ecm_bpf_snapshot.as_ref(),
                        nss_tc_snapshot.as_ref().and_then(|snapshot| {
                            (bpf_snapshot_fresh || decision.evidence.retained_fresh_snapshot)
                                .then_some(snapshot)
                        }),
                        bpf_snapshot_fresh
                            && ecm_bpf_coverage_window
                                .as_ref()
                                .is_some_and(|coverage| coverage.aligned),
                        lan_clock.as_ref().map_or(now_ms, |lan| lan.sample_ms),
                        conntrack.as_deref(),
                        &identities,
                        decision.confidence,
                    ),
                    ecm_bpf_current,
                    !ecm_bpf_current,
                    false,
                )
            } else {
                (
                    ClientsResponse::empty(evidence(&report, "clients")),
                    false,
                    true,
                    false,
                )
            };
        if legacy_nss_rate_window_enabled {
            if let Some(batch) = ecm_bpf_rate_batch.as_ref() {
                apply_ecm_bpf_rate_batch(&mut clients, &mut interfaces, batch);
            }
        }
        self.apply_access_edge_rates(
            &mut clients,
            &identities,
            conntrack.as_deref(),
            decision.rate,
            decision.confidence,
            ecm_bpf_snapshot.as_ref(),
            ecm_classifier_read_end_ms,
            nss_tc_snapshot.as_ref(),
            bpf_classifier_read_end_ms,
            &runtime_health,
        );
        if access_edge_enabled {
            let edge_evidence = access_edge_global_evidence(
                self.access_edge.latest(),
                &clients,
                self.config.access_edge_mode,
            );
            clients
                .evidence
                .get_or_insert_default()
                .details
                .insert("access_edge".into(), edge_evidence);
        }
        self.hostnames.refresh_from_paths(
            &HostnamePaths::default(),
            now_ms,
            method == ProbeMethod::Reload,
        );
        for client in &mut clients.clients {
            let ips = client.ips.iter().map(String::as_str).collect::<Vec<_>>();
            client.hostname = self.hostnames.lookup(&client.mac, &ips).map(str::to_owned);
        }
        if let Some(snapshot) = conntrack.as_ref() {
            clients.conntrack_entries_seen = Some(snapshot.stats.entries_seen as u64);
            clients.conntrack_entries_matched = Some(snapshot.stats.entries_matched as u64);
            clients.conntrack_parse_errors = Some(snapshot.stats.malformed_lines as u64);
            clients.conn_source = Some(
                if snapshot.stats.netlink_read {
                    "conntrack_netlink"
                } else {
                    "conntrack_procfs"
                }
                .into(),
            );
            clients.conn_collector_mode = Some(self.config.conn_collector_mode.as_str().into());
        }
        if let Some(snapshot) = node_snapshot.as_ref() {
            clients.nss_ecm_nodes_seen = Some(snapshot.stats.nodes_seen as u64);
            clients.nss_ecm_nodes_matched = Some(snapshot.stats.nodes_matched as u64);
            clients.nss_ecm_node_parse_errors = Some(snapshot.stats.malformed_lines as u64);
        }
        if clients.evidence.is_none() {
            clients.evidence = Some(evidence(&report, "clients"));
        }
        if let Some(client_evidence) = clients.evidence.as_mut() {
            apply_decision_evidence(client_evidence, &decision, &self.config, &report);
            apply_nss_snapshot_evidence(client_evidence, node_snapshot.as_ref());
            apply_ecm_bpf_evidence(client_evidence, &runtime_health, ecm_bpf_snapshot.as_ref());
            client_evidence.details.insert(
                "classifier_maps".into(),
                classifier_map_evidence(
                    &runtime_health,
                    ecm_bpf_snapshot.as_ref(),
                    ecm_bpf_snapshot_fresh,
                    nss_tc_snapshot.as_ref(),
                    bpf_snapshot_fresh,
                ),
            );
            if let Some(snapshot) = conntrack.as_deref() {
                client_evidence.details.insert(
                    "conntrack_generation".into(),
                    conntrack_generation_evidence(snapshot),
                );
            }
            if let Some(window) = nss_window.as_ref() {
                client_evidence
                    .details
                    .insert("nss_window".into(), window_evidence(window));
            }
            if let Some(coverage) = ecm_bpf_coverage_window.as_ref() {
                client_evidence.details.insert(
                    "ecm_bpf_coverage_window".into(),
                    coverage_evidence(
                        coverage,
                        ecm_bpf_coverage_merge
                            .map_or("ecm_nss_hardware_delta", |value| value.source),
                    ),
                );
                if let Some(merged) = ecm_bpf_coverage_merge {
                    client_evidence.details.insert(
                        "ecm_bpf_coverage_merge".into(),
                        ecm_bpf_coverage_merge_evidence(merged),
                    );
                }
            }
            if let Some(batch) = ecm_bpf_rate_batch.as_ref() {
                client_evidence.details.insert(
                    "ecm_bpf_rate_window".into(),
                    ecm_bpf_rate_batch_evidence(batch),
                );
            }
        }
        let overview = self.update_overview(now_ms, &clients);
        let coverage = match decision.rate {
            RateCollector::NssEcmNode | RateCollector::NssEcmBpf => {
                let sample_skew_ms = active_access_edge_owns_display_rate(
                    self.config.access_edge_mode,
                    self.config.rate_collector_mode,
                )
                .then_some(CLASSIFIER_READ_END_SKEW_MS)
                .unwrap_or(0);
                nss_rate_coverage(&clients, &interfaces, sample_skew_ms)
            }
            RateCollector::Bpf if report.facts.nss.present => {
                self.nss_bpf_coverage
                    .update(now_ms, &clients, &interfaces, coverage_fresh)
            }
            _ => self
                .x86_coverage
                .update(now_ms, &clients, &interfaces, coverage_fresh),
        };
        let sysdevices = sysdevices(&self.config)?;
        let mut capabilities = capabilities(&report.capabilities, &report);
        capabilities.live_metrics = actual_live;
        capabilities.conntrack_fallback = false;
        // BPF remains an active slow-path observer on NSS even when conntrack
        // sync is the authoritative rate source.  Runtime capability must
        // describe the healthy attachment/map, not whether BPF is primary.
        capabilities.bpf_runtime_metrics = runtime_health.bpf_object_loaded
            && runtime_health.bpf_attached
            && bpf_snapshot.is_some()
            && (runtime_health.bpf_map_read_ok || decision.evidence.retained_fresh_snapshot);
        capabilities.bpf = capabilities.bpf_runtime_metrics;
        if capabilities.bpf_runtime_metrics {
            // A loaded object, attached hooks, and a readable map are stronger
            // evidence than the wording/exit status of `tc help`.
            capabilities.bpf_supported = true;
            capabilities.bpf_package = true;
            capabilities.bpf_object = true;
            capabilities.tc = true;
            capabilities.tc_clsact = true;
        }
        let mode = if decision.mode == ProbeMode::Unsupported {
            Mode::Unsupported
        } else if !actual_live || actual_degraded || !identity_errors.is_empty() {
            Mode::Degraded
        } else {
            mode(decision.mode)
        };
        let confidence = if mode == Mode::Unsupported {
            Confidence::Unsupported
        } else if !actual_live || !identity_errors.is_empty() {
            Confidence::Low
        } else {
            confidence(decision.confidence)
        };
        let mut status_evidence = runtime_evidence(
            &report,
            method.as_str(),
            &self.config,
            &runtime_health,
            self.bpf_error_stage,
        );
        if matches!(
            decision.rate,
            RateCollector::NssEcmNode | RateCollector::NssEcmBpf
        ) {
            status_evidence.details.insert(
                "coverage_alignment".into(),
                json!({
                    "source": "same_snapshot_displayed_client_and_lan_rates",
                    "sample_ms": interfaces.monotonic_ms,
                    "window_ms": coverage.window_ms,
                    "raw_counter_window_role": if decision.rate == RateCollector::NssEcmBpf {
                        "client_interface_rate_alignment_and_fusion"
                    } else {
                        "diagnostic_and_rate_fusion_guard_only"
                    },
                    "percentage_clamp": false,
                }),
            );
        }
        apply_decision_evidence(&mut status_evidence, &decision, &self.config, &report);
        apply_nss_snapshot_evidence(&mut status_evidence, node_snapshot.as_ref());
        apply_ecm_bpf_evidence(
            &mut status_evidence,
            &runtime_health,
            ecm_bpf_snapshot.as_ref(),
        );
        status_evidence.details.insert(
            "classifier_maps".into(),
            classifier_map_evidence(
                &runtime_health,
                ecm_bpf_snapshot.as_ref(),
                ecm_bpf_snapshot_fresh,
                nss_tc_snapshot.as_ref(),
                bpf_snapshot_fresh,
            ),
        );
        if let Some(window) = nss_window.as_ref() {
            status_evidence
                .details
                .insert("nss_window".into(), window_evidence(window));
        }
        if let Some(coverage) = ecm_bpf_coverage_window.as_ref() {
            status_evidence.details.insert(
                "ecm_bpf_coverage_window".into(),
                coverage_evidence(
                    coverage,
                    ecm_bpf_coverage_merge.map_or("ecm_nss_hardware_delta", |value| value.source),
                ),
            );
            if let Some(merged) = ecm_bpf_coverage_merge {
                status_evidence.details.insert(
                    "ecm_bpf_coverage_merge".into(),
                    ecm_bpf_coverage_merge_evidence(merged),
                );
            }
        }
        if let Some(batch) = ecm_bpf_rate_batch.as_ref() {
            status_evidence.details.insert(
                "ecm_bpf_rate_window".into(),
                ecm_bpf_rate_batch_evidence(batch),
            );
        }
        let mut warnings = report
            .warnings
            .iter()
            .map(|warning| (*warning).to_owned())
            .collect::<Vec<_>>();
        for warning in &decision.warnings {
            if !warnings.iter().any(|value| value == warning) {
                warnings.push((*warning).into());
            }
        }
        retain_collector_warnings(&mut warnings, decision.rate);
        if capabilities.bpf_runtime_metrics {
            warnings.retain(|warning| {
                !matches!(
                    warning.as_str(),
                    "bpf_unsupported"
                        | "tc_clsact_unsupported"
                        | "unsafe_attach"
                        | "bpf_runtime_loader_unavailable"
                        | "bpf_optional_package_missing"
                        | "bpf_object_missing"
                )
            });
        }
        if let Some(error) = &self.nss.node_error {
            status_evidence
                .details
                .insert("nss_runtime_error".into(), json!(error));
        }
        if !actual_live
            && !warnings
                .iter()
                .any(|warning| warning == "live_metrics_unavailable")
        {
            warnings.push("live_metrics_unavailable".into());
        }
        if !identity_errors.is_empty()
            && !warnings
                .iter()
                .any(|warning| warning == "lan_topology_probe_error")
        {
            warnings.push("lan_topology_probe_error".into());
            status_evidence
                .details
                .insert("identity_errors".into(), json!(identity_errors));
        }
        if let Some(snapshot) = conntrack.as_deref() {
            status_evidence.details.insert(
                "conntrack_generation".into(),
                conntrack_generation_evidence(snapshot),
            );
        }
        let version = version();
        let status = StatusResponse {
            mode,
            confidence,
            warnings: warnings.clone(),
            evidence: status_evidence.clone(),
            refresh_interval_ms: self.config.refresh_interval_ms,
            active_client_window_ms: self.config.active_client_window_ms,
            active_client_min_bps: self.config.active_client_min_bps,
            overview_window_samples: self.config.overview_window_samples,
            collector_mode: self.config.rate_collector_mode.as_str().into(),
            rate_collector_mode: self.config.rate_collector_mode.as_str().into(),
            access_edge_mode: self.config.access_edge_mode.as_str().into(),
            conn_collector_mode: self.config.conn_collector_mode.as_str().into(),
            version: version.clone(),
            capabilities: capabilities.clone(),
            coverage: Some(coverage),
        };
        let mut health_evidence = runtime_evidence(
            &report,
            "health",
            &self.config,
            &runtime_health,
            self.bpf_error_stage,
        );
        apply_decision_evidence(&mut health_evidence, &decision, &self.config, &report);
        apply_nss_snapshot_evidence(&mut health_evidence, node_snapshot.as_ref());
        apply_ecm_bpf_evidence(
            &mut health_evidence,
            &runtime_health,
            ecm_bpf_snapshot.as_ref(),
        );
        health_evidence.details.insert(
            "classifier_maps".into(),
            classifier_map_evidence(
                &runtime_health,
                ecm_bpf_snapshot.as_ref(),
                ecm_bpf_snapshot_fresh,
                nss_tc_snapshot.as_ref(),
                bpf_snapshot_fresh,
            ),
        );
        if let Some(window) = nss_window.as_ref() {
            health_evidence
                .details
                .insert("nss_window".into(), window_evidence(window));
        }
        if let Some(coverage) = ecm_bpf_coverage_window.as_ref() {
            health_evidence.details.insert(
                "ecm_bpf_coverage_window".into(),
                coverage_evidence(
                    coverage,
                    ecm_bpf_coverage_merge.map_or("ecm_nss_hardware_delta", |value| value.source),
                ),
            );
            if let Some(merged) = ecm_bpf_coverage_merge {
                health_evidence.details.insert(
                    "ecm_bpf_coverage_merge".into(),
                    ecm_bpf_coverage_merge_evidence(merged),
                );
            }
        }
        if let Some(batch) = ecm_bpf_rate_batch.as_ref() {
            health_evidence.details.insert(
                "ecm_bpf_rate_window".into(),
                ecm_bpf_rate_batch_evidence(batch),
            );
        }
        if let Some(error) = &self.nss.node_error {
            health_evidence
                .details
                .insert("nss_runtime_error".into(), json!(error));
        }
        if !identity_errors.is_empty() {
            health_evidence
                .details
                .insert("identity_errors".into(), json!(identity_errors));
        }
        if let Some(snapshot) = conntrack.as_deref() {
            health_evidence.details.insert(
                "conntrack_generation".into(),
                conntrack_generation_evidence(snapshot),
            );
        }
        let health = HealthResponse {
            mode,
            confidence,
            capabilities,
            conflicts: report
                .conflicts
                .iter()
                .map(|item| Conflict {
                    id: item.id.into(),
                    severity: item.severity.into(),
                    message: item.message.into(),
                    evidence: BTreeMap::new(),
                })
                .collect(),
            warnings: warnings.clone(),
            evidence: health_evidence,
        };
        let mut reload_evidence = evidence(&report, "reload");
        apply_decision_evidence(&mut reload_evidence, &decision, &self.config, &report);
        apply_nss_snapshot_evidence(&mut reload_evidence, node_snapshot.as_ref());
        apply_ecm_bpf_evidence(
            &mut reload_evidence,
            &runtime_health,
            ecm_bpf_snapshot.as_ref(),
        );
        let reload = ReloadResponse {
            ok: true,
            mode,
            warnings,
            evidence: reload_evidence,
            version,
        };
        let mut response = ResponseSnapshot::from_responses(
            status, clients, overview, health, reload, interfaces, sysdevices,
        );
        response.replace_traffic_classification(
            self.classification_results
                .iter()
                .map(|(identity, result)| (identity.clone(), traffic_classification(result)))
                .collect(),
        );
        publish_connection_details(&mut response, conntrack.as_deref());
        Ok(response)
    }

    #[cfg(feature = "nss-platform")]
    fn update_access_classification(
        &mut self,
        identities: &IdentityTable,
        ecm: Option<&EcmBpfSnapshot>,
        ecm_new: bool,
        ecm_read_end_ms: Option<u64>,
        slow: Option<&NssTcSnapshot>,
        slow_new: bool,
        slow_read_end_ms: Option<u64>,
        runtime_health: &RuntimeHealth,
    ) {
        if self.config.access_edge_mode == AccessEdgeMode::Off {
            self.access_edge.clear_classification();
            self.classification_results.clear();
            return;
        }
        let ecm_map_loss = ecm
            .filter(|_| ecm_new)
            .is_some_and(|snapshot| snapshot.truncated)
            || (runtime_health.ecm_bpf_map_read_attempted
                && !runtime_health.ecm_bpf_map_read_ok
                && !ecm_new);
        let slow_map_loss = slow
            .filter(|_| slow_new)
            .is_some_and(|snapshot| !snapshot.map_complete)
            || (runtime_health.bpf_map_read_attempted
                && !runtime_health.bpf_map_read_ok
                && !slow_new);
        let map_loss = ecm_map_loss || slow_map_loss;
        let ecm_window = ecm
            .filter(|snapshot| ecm_new && !snapshot.truncated && snapshot.coverage_ready)
            .and_then(|snapshot| {
                snapshot
                    .coverage_start_ms
                    .map(|start| (start, snapshot.coverage_end_ms))
            });
        let slow_window = slow
            .filter(|snapshot| slow_new && snapshot.map_complete && snapshot.coverage_ready)
            .and_then(|snapshot| {
                snapshot
                    .coverage_start_ms
                    .map(|start| (start, snapshot.coverage_end_ms))
            });
        let (start_ms, end_ms, classifier_window_aligned) =
            match select_classifier_window(ecm_window, slow_window) {
                ClassifierWindowSelection::Ready {
                    start_ms,
                    end_ms,
                    aligned,
                } => (start_ms, end_ms, aligned),
                state => {
                    let state = match state {
                        ClassifierWindowSelection::Invalid => ClassificationState::WindowMismatch,
                        ClassifierWindowSelection::Unavailable if map_loss => {
                            ClassificationState::MapLoss
                        }
                        ClassifierWindowSelection::Unavailable if ecm_new || slow_new => {
                            ClassificationState::Warmup
                        }
                        ClassifierWindowSelection::Unavailable => ClassificationState::Unavailable,
                        ClassifierWindowSelection::Ready { .. } => unreachable!(),
                    };
                    // Invalid or unavailable current windows are negative
                    // evidence, not permission to retain an older Aligned
                    // comparison. The next valid epoch must warm up again.
                    self.access_edge.clear_classification();
                    let mut identity_keys = identities
                        .iter()
                        .map(|identity| identity.key.to_string())
                        .collect::<BTreeSet<_>>();
                    identity_keys.extend(self.classification_results.keys().cloned());
                    if let Some(snapshot) = ecm.filter(|_| ecm_new) {
                        identity_keys.extend(snapshot.coverage_deltas.keys().cloned());
                    }
                    if let Some(snapshot) = slow.filter(|_| slow_new) {
                        identity_keys.extend(snapshot.coverage_deltas.keys().cloned());
                    }
                    self.classification_results = identity_keys
                        .into_iter()
                        .map(|identity_key| (identity_key, ClassificationResult::state(state)))
                        .collect();
                    return;
                }
            };
        self.classifier_epoch_id = self.classifier_epoch_id.saturating_add(1);
        let sources_complete = ecm_window.is_some() && slow_window.is_some();
        let edge_clients = self.access_edge.latest().clients.clone();
        let edge_index = edge_mac_index(&edge_clients);
        let identities_by_key = identities
            .iter()
            .map(|identity| (identity.key.to_string(), identity))
            .collect::<BTreeMap<_, _>>();
        let mut identity_keys = identities
            .iter()
            .map(|identity| identity.key.to_string())
            .collect::<BTreeSet<_>>();
        if let Some(snapshot) = ecm.filter(|_| ecm_new) {
            identity_keys.extend(snapshot.coverage_deltas.keys().cloned());
        }
        if let Some(snapshot) = slow.filter(|_| slow_new) {
            identity_keys.extend(snapshot.coverage_deltas.keys().cloned());
        }

        let mut active_results = BTreeMap::new();
        for identity_key in identity_keys {
            let identity = identities_by_key.get(&identity_key).copied();
            let edge = identity.and_then(|identity| {
                edge_index
                    .unique
                    .get(&identity.key.mac.to_string())
                    .copied()
            });
            let ecm_delta = ecm.filter(|_| ecm_new).map(|snapshot| {
                snapshot
                    .coverage_deltas
                    .get(&identity_key)
                    .copied()
                    .unwrap_or_default()
            });
            let slow_delta = slow.filter(|_| slow_new).map(|snapshot| {
                snapshot
                    .coverage_deltas
                    .get(&identity_key)
                    .copied()
                    .unwrap_or_default()
            });
            let attachment_generation = edge.map_or(0, |sample| sample.attachment.generation);
            let attachment_stable = edge.is_none_or(|sample| {
                !sample.attachment.ambiguous
                    && sample.attachment.stable_observations >= 2
                    && self
                        .access_edge
                        .attachment_topology_complete(&sample.attachment)
            });
            let direction = |direction| DirectionEpoch {
                edge: edge.and_then(|sample| {
                    self.access_edge
                        .aggregate_edge(sample.attachment.key, direction, start_ms, end_ms)
                        .map(comparable_l2_with_fcs)
                }),
                nss: ecm_delta.map(|delta| {
                    comparable_l2_with_fcs(observed_traffic_delta(
                        EdgeRateSource::EcmNssLowerBound,
                        EdgeByteDomain::EcmData,
                        delta,
                        direction,
                        ecm_read_end_ms
                            .or_else(|| ecm.map(|snapshot| snapshot.coverage_end_ms))
                            .unwrap_or(end_ms),
                    ))
                }),
                slow: slow_delta.map(|delta| {
                    comparable_l2_with_fcs(observed_traffic_delta(
                        EdgeRateSource::TcBpfLowerBound,
                        EdgeByteDomain::L2NoFcs,
                        delta,
                        direction,
                        slow_read_end_ms
                            .or_else(|| slow.map(|snapshot| snapshot.coverage_end_ms))
                            .unwrap_or(end_ms),
                    ))
                }),
            };
            let epoch = ClassificationEpoch {
                epoch_id: self.classifier_epoch_id,
                start_ms,
                end_ms,
                attachment_generation,
                attachment_stable,
                map_complete: !map_loss,
                sources_complete,
                classifier_window_aligned,
                tx: direction(EdgeDirection::Tx),
                rx: direction(EdgeDirection::Rx),
            };
            let result = self.access_edge.update_classification(&identity_key, epoch);
            active_results.insert(identity_key, result);
        }
        self.classification_results = active_results;
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "nss-platform")]
    fn apply_access_edge_rates(
        &mut self,
        clients: &mut ClientsResponse,
        identities: &IdentityTable,
        conntrack: Option<&CollectedSnapshot>,
        pipeline: RateCollector,
        client_confidence: crate::probe::Confidence,
        ecm: Option<&EcmBpfSnapshot>,
        ecm_read_end_ms: Option<u64>,
        slow: Option<&NssTcSnapshot>,
        slow_read_end_ms: Option<u64>,
        runtime_health: &RuntimeHealth,
    ) {
        if self.config.access_edge_mode == AccessEdgeMode::Off {
            self.access_edge
                .retain_published_identities(&BTreeSet::new());
            self.classification_results.clear();
            return;
        }
        let active_auto = active_access_edge_owns_display_rate(
            self.config.access_edge_mode,
            self.config.rate_collector_mode,
        );
        let edge_snapshot = self.access_edge.latest().clone();
        let edge_index = edge_mac_index(&edge_snapshot.clients);
        let identity_index = identity_mac_index(identities);
        let mut published_identity_keys = clients
            .clients
            .iter()
            .map(|client| client.identity_key.clone())
            .collect::<BTreeSet<_>>();
        let conntrack_by_identity = conntrack.map(|snapshot| {
            let mut index = BTreeMap::new();
            for sample in &snapshot.clients {
                index.entry(sample.identity_key.as_str()).or_insert(sample);
            }
            index
        });

        if active_auto {
            for edge in &edge_snapshot.clients {
                let mac = format_edge_mac(edge.attachment.key.mac);
                let Some(identity) = identity_index.unique.get(&mac).copied() else {
                    continue;
                };
                let identity_key = identity.key.to_string();
                if published_identity_keys.contains(&identity_key)
                    || clients.clients.len() >= self.config.max_clients
                {
                    continue;
                }
                let counts = conntrack_by_identity
                    .as_ref()
                    .and_then(|index| index.get(identity_key.as_str()).copied());
                clients.clients.push(Client {
                    mac: identity.key.mac.to_string(),
                    identity_key: identity_key.clone(),
                    zone: identity.key.zone.clone(),
                    interface: identity.interface.clone(),
                    ips: identity.ips.clone(),
                    hostname: identity.hostname.clone(),
                    rx_bps: 0,
                    tx_bps: 0,
                    last_seen: edge_snapshot.sample_ms,
                    sample_ms: Some(edge_snapshot.sample_ms),
                    rx_bytes: None,
                    tx_bytes: None,
                    collector_mode: pipeline.as_str().to_owned(),
                    confidence: confidence(client_confidence),
                    warnings: Vec::new(),
                    tcp_conns: counts.map(|sample| u64::from(sample.tcp_conns)),
                    udp_conns: counts.map(|sample| u64::from(sample.udp_conns)),
                    udp_dns_conns: counts.map(|sample| u64::from(sample.udp_dns_conns)),
                    udp_other_conns: counts.map(|sample| u64::from(sample.udp_other_conns)),
                    rate_meta: None,
                });
                published_identity_keys.insert(identity_key);
            }
        }

        for client in &mut clients.clients {
            let connection_only = client
                .warnings
                .iter()
                .any(|warning| warning == "conntrack_connection_only");
            let client_mac_key = mac_lookup_key(&client.mac);
            let edge = identity_index
                .unique
                .get(&client_mac_key)
                .and_then(|_| edge_index.unique.get(&client_mac_key))
                .copied();
            let attachment_generation = edge.map_or(0, |sample| sample.attachment.generation);
            let mut reasons = edge
                .into_iter()
                .flat_map(|sample| {
                    sample
                        .tx
                        .reason_codes
                        .iter()
                        .chain(sample.rx.reason_codes.iter())
                })
                .cloned()
                .collect::<Vec<_>>();
            reasons.extend(edge_snapshot.reason_codes.iter().cloned());
            let attachment_topology_complete =
                edge.map_or(edge_snapshot.topology_complete, |sample| {
                    self.access_edge
                        .attachment_topology_complete(&sample.attachment)
                });
            if !attachment_topology_complete {
                reasons.push("topology_incomplete".to_owned());
            }
            if edge_index.ambiguous.contains(&client_mac_key) {
                reasons.push("duplicate_mac_attachment".to_owned());
            }
            if self.config.access_edge_mode == AccessEdgeMode::Shadow {
                reasons.push("access_edge_shadow".to_owned());
            }

            let mut select_direction = |direction: EdgeDirection, old_bps: u64| {
                let edge_direction = edge.map(|sample| match direction {
                    EdgeDirection::Tx => &sample.tx,
                    EdgeDirection::Rx => &sample.rx,
                });
                let mut candidates = Vec::new();
                if let Some(observation) = edge_direction {
                    if let Some(segment) = observation.segment {
                        if let (Some(bps), Some(window_ms)) = (segment.bps(), segment.window_ms()) {
                            candidates.push(RateCandidate {
                                source: segment.source,
                                bps,
                                coverage: observation.coverage,
                                scope: observation.scope,
                                byte_domain: segment.byte_domain,
                                sample_ms: segment.end_ms,
                                window_ms,
                                cadence_ms: ACCESS_EDGE_INTERVAL_MS,
                                attachment_generation,
                                fresh: edge_segment_fresh(
                                    edge_snapshot.sample_ms,
                                    segment.end_ms,
                                    ACCESS_EDGE_INTERVAL_MS,
                                ),
                            });
                        }
                    }
                }
                candidates.extend(classifier_rate_candidates(
                    &client.identity_key,
                    direction,
                    attachment_generation,
                    ecm,
                    ecm_read_end_ms,
                    slow,
                    slow_read_end_ms,
                    runtime_health,
                ));
                let edge_failure = edge_direction.and_then(|observation| observation.failure);
                // Keep the failure boundary explicit even though current Edge
                // observations make `segment` and `failure` mutually exclusive.
                // A future collector change must not allow a failed, higher-
                // priority Edge candidate to re-enter promotion ahead of the
                // independent classifier fallback.
                remove_failed_edge_candidates(&mut candidates, edge_failure);
                let classifier_loss = ecm.is_some_and(|snapshot| snapshot.truncated)
                    || slow.is_some_and(|snapshot| !snapshot.map_complete)
                    || (runtime_health.ecm_bpf_map_read_attempted
                        && !runtime_health.ecm_bpf_map_read_ok)
                    || (runtime_health.bpf_map_read_attempted && !runtime_health.bpf_map_read_ok);
                let has_edge_candidate = candidates.iter().any(|candidate| {
                    matches!(
                        candidate.source,
                        EdgeRateSource::EdgePort | EdgeRateSource::EdgeWifi
                    )
                });
                let has_classifier_candidate = candidates.iter().any(|candidate| {
                    matches!(
                        candidate.source,
                        EdgeRateSource::EcmBpfFallback
                            | EdgeRateSource::EcmNssLowerBound
                            | EdgeRateSource::TcBpfLowerBound
                    )
                });
                // Edge failures are source-scoped. They invalidate an Edge
                // owner or challenger immediately, while an independent
                // classifier owner on the same attachment continues under its
                // own freshness policy. A generation change still demotes all
                // paths inside the mux.
                if edge_failure.is_some() {
                    self.access_edge.invalidate_edge_mux(
                        &client.identity_key,
                        direction,
                        attachment_generation,
                    );
                }
                let mut failure = None;
                let mux_owner = self.access_edge.mux_owner(&client.identity_key, direction);
                if failure.is_none()
                    && classifier_map_loss_invalidates_owner(
                        mux_owner,
                        has_edge_candidate,
                        has_classifier_candidate,
                        classifier_loss,
                    )
                {
                    failure = Some(MuxFailure::MapLoss);
                }
                let selected = self.access_edge.update_mux(
                    &client.identity_key,
                    direction,
                    // ECM/TC are sampled immediately after Edge and can have a
                    // later read-end timestamp. Use the completed collection's
                    // monotonic time for freshness; using the earlier Edge time
                    // would reject a valid classifier fallback as "future".
                    runtime_health.now_ms,
                    attachment_generation,
                    &candidates,
                    failure,
                );
                if active_auto {
                    if let Some(selected) = selected.selected {
                        return published_from_candidate(selected.candidate, selected.stale);
                    }
                    // Active Access Edge never falls through to the legacy NSS
                    // rate window. Warmup or unavailable means exactly that;
                    // no LAN allocation, previous distribution, directional
                    // max, interface floor, or smoothed rate may become E.
                    return PublishedRateDirection::unavailable(0);
                }
                pipeline_direction(
                    pipeline,
                    old_bps,
                    client.sample_ms,
                    self.config.refresh_interval_ms,
                    connection_only,
                )
            };

            let tx = select_direction(EdgeDirection::Tx, client.tx_bps);
            let rx = select_direction(EdgeDirection::Rx, client.rx_bps);
            if active_auto {
                client.tx_bps = tx.bps;
                client.rx_bps = rx.bps;
                // `collector_mode` names the pipeline that owns the published
                // total. Directional ownership remains in rate_meta; retaining
                // the identity's legacy conntrack/NSS origin here makes the
                // response internally contradictory and can hide the row from
                // clients that align batches by collector.
                client.collector_mode =
                    published_rate_collector_mode(active_auto, &client.collector_mode).to_owned();
                client.sample_ms = match (tx.sample_ms, rx.sample_ms) {
                    (Some(left), Some(right)) => Some(left.max(right)),
                    (Some(value), None) | (None, Some(value)) => Some(value),
                    (None, None) => client.sample_ms,
                };
                if tx.mux_owner || rx.mux_owner {
                    // The legacy pipeline may have introduced this identity as
                    // conntrack-only before Access Edge supplied a real owner.
                    // Once either direction is measured it is no longer a
                    // connection-only client in the published contract.
                    client
                        .warnings
                        .retain(|warning| warning != "conntrack_connection_only");
                }
                // Active-auto rates are owned exclusively by RateMux. Neither
                // a selected Edge/classifier source nor an unavailable/warmup
                // state may expose cumulative totals from the displaced legacy
                // pipeline as if they belonged to the current rate source.
                client.tx_bytes = None;
                client.rx_bytes = None;
            }
            let classification = self
                .classification_results
                .get(&client.identity_key)
                .map(classification_summary);
            if let Some(classification) = classification.as_ref() {
                if classification.state != ClassificationState::Aligned {
                    reasons.push(format!(
                        "classification_{}",
                        classification_state_code(classification.state)
                    ));
                }
            }
            let common_window = (tx.window_ms == rx.window_ms)
                .then_some(tx.window_ms)
                .flatten();
            let summary_sample_ms = compact_rate_sample_ms(tx.sample_ms, rx.sample_ms);
            let summary_stale = tx.stale || rx.stale;
            if tx.window_ms != rx.window_ms {
                reasons.push("direction_window_mismatch".to_owned());
            }
            reasons.sort();
            reasons.dedup();
            reasons.truncate(16);
            client.rate_meta = Some(ClientRateMeta {
                version: 1,
                scope: conservative_scope(tx.scope, rx.scope),
                tx: rate_direction_meta(tx, summary_sample_ms, common_window, summary_stale),
                rx: rate_direction_meta(rx, summary_sample_ms, common_window, summary_stale),
                attachment: edge.map(|sample| model_attachment(&sample.attachment)),
                generation: attachment_generation,
                window_ms: common_window,
                sample_ms: summary_sample_ms,
                stale: summary_stale,
                reason_codes: reasons,
                classification,
            });
        }

        self.access_edge
            .retain_published_identities(&published_identity_keys);
        self.classification_results
            .retain(|identity_key, _| published_identity_keys.contains(identity_key));
    }

    fn update_overview(&mut self, now_ms: u64, response: &ClientsResponse) -> OverviewResponse {
        let clients = response
            .clients
            .iter()
            .map(|client| OverviewClient {
                tx_bps: client.tx_bps,
                rx_bps: client.rx_bps,
                sample_ms: client.sample_ms.unwrap_or(now_ms),
                last_seen_ms: client.last_seen,
                nss_activity: matches!(
                    client.collector_mode.as_str(),
                    "access_edge" | "nss_ecm_node" | "nss_ecm_bpf"
                ),
                connections: ConnectionTotals::new(
                    client.tcp_conns.unwrap_or(0),
                    client.udp_conns.unwrap_or(0),
                    client.udp_dns_conns.unwrap_or(0),
                    client.udp_other_conns.unwrap_or(0),
                ),
            })
            .collect::<Vec<_>>();
        let config = OverviewConfig {
            window_samples: self.config.overview_window_samples,
            active_client_window_ms: self.config.active_client_window_ms,
            active_client_min_bps: self.config.active_client_min_bps,
        };
        self.overview.push(
            now_ms,
            &clients,
            ConnectionTotalsOverride::default(),
            &config,
        );
        let value = self.overview.to_json(&config);
        OverviewResponse {
            samples: value["samples"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .map(|sample| OverviewSample {
                    sample_ms: sample["sample_ms"].as_u64().unwrap_or(0),
                    tx_bps: sample["tx_bps"].as_u64().unwrap_or(0),
                    rx_bps: sample["rx_bps"].as_u64().unwrap_or(0),
                    client_count: sample["client_count"].as_u64().unwrap_or(0) as u32,
                    active_clients: sample["active_clients"].as_u64().unwrap_or(0) as u32,
                    tcp_conns: sample
                        .get("tcp_conns")
                        .and_then(Value::as_u64)
                        .map(|v| v as u32),
                    udp_conns: sample
                        .get("udp_conns")
                        .and_then(Value::as_u64)
                        .map(|v| v as u32),
                    udp_dns_conns: sample
                        .get("udp_dns_conns")
                        .and_then(Value::as_u64)
                        .map(|v| v as u32),
                    udp_other_conns: sample
                        .get("udp_other_conns")
                        .and_then(Value::as_u64)
                        .map(|v| v as u32),
                })
                .collect(),
            max_samples: 240,
            overview_window_samples: self.config.overview_window_samples,
            active_client_window_ms: self.config.active_client_window_ms,
            active_client_min_bps: self.config.active_client_min_bps,
            sample_source: OVERVIEW_SAMPLE_SOURCE.into(),
            conn_semantics: CONNECTION_SEMANTICS.into(),
        }
    }

    #[cfg(feature = "nss-platform")]
    fn interfaces(
        &mut self,
        now_ms: u64,
        extra_names: &BTreeSet<String>,
    ) -> (
        InterfacesResponse,
        Option<LanClock>,
        InterfaceCounterSnapshot,
    ) {
        let roles = collect_ifnames_with_roles(&self.config);
        let lan_roots = roles
            .iter()
            .filter_map(|(name, role)| (*role == InterfaceRole::Lan).then_some(name.clone()))
            .collect::<Vec<_>>();
        let masters = interface_masters();
        let lan_boundaries = independent_lan_boundaries(&lan_roots, &masters);
        let mut names_to_read = roles
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(boundaries) = lan_boundaries.as_ref() {
            names_to_read.extend(boundaries.iter().cloned());
        }
        names_to_read.extend(extra_names.iter().cloned());
        let counter_snapshot = read_interface_counter_snapshot(&names_to_read);
        let raw_counters = &counter_snapshot.counters;
        let mut interfaces = Vec::new();
        for (name, role) in roles {
            let boundary_names = (role == InterfaceRole::Lan)
                .then(|| independent_lan_boundaries(std::slice::from_ref(&name), &masters))
                .flatten();
            let sampled = if let Some(boundaries) = boundary_names.as_ref() {
                sum_interface_counters(boundaries, &raw_counters)
            } else {
                raw_counters.get(&name).copied()
            };
            let interface = match sampled {
                Some(counters) => {
                    let sampled_names = boundary_names
                        .as_deref()
                        .unwrap_or_else(|| std::slice::from_ref(&name));
                    let counter_source = counter_snapshot
                        .source_for(sampled_names.iter().map(String::as_str))
                        .unwrap_or(MIXED_INTERFACE_SOURCE);
                    let display = if role == InterfaceRole::Lan {
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
                    };
                    let (rx_bps, tx_bps, delta_ms) =
                        self.interface_rates.update(&name, display, now_ms);
                    Interface {
                        name,
                        role,
                        status: InterfaceStatus::Available,
                        rx_bytes: Some(display.rx_bytes),
                        tx_bytes: Some(display.tx_bytes),
                        rx_bps: Some(rx_bps),
                        tx_bps: Some(tx_bps),
                        delta_ms: Some(delta_ms),
                        sample_ms: Some(now_ms),
                        source: Some(if role == InterfaceRole::Lan {
                            format!("{counter_source} + real packets * 4-byte FCS")
                        } else {
                            counter_source.into()
                        }),
                        coverage: Some(if role == InterfaceRole::Lan {
                            format!(
                                "independent_lan_boundary:{}",
                                boundary_names.as_deref().unwrap_or_default().join("+")
                            )
                        } else {
                            "kernel_netdev_statistics".into()
                        }),
                        evidence: None,
                    }
                }
                None => Interface {
                    name,
                    role,
                    status: InterfaceStatus::Missing,
                    rx_bytes: Some(0),
                    tx_bytes: Some(0),
                    rx_bps: Some(0),
                    tx_bps: Some(0),
                    delta_ms: Some(0),
                    sample_ms: Some(now_ms),
                    source: Some(
                        "counter unavailable after /proc/net/dev and sysfs fallback".into(),
                    ),
                    coverage: Some("includes_hardware_offload_and_switch_bridge".into()),
                    evidence: None,
                },
            };
            interfaces.push(interface);
        }
        let lan_clock = lan_boundaries.and_then(|boundaries| {
            let counters = sum_interface_counters(&boundaries, &raw_counters)?;
            Some(LanClock {
                interface: boundaries.join("+"),
                sample_ms: now_ms,
                counters: TrafficCounters {
                    tx_bytes: counters.tx_bytes,
                    rx_bytes: counters.rx_bytes,
                    tx_packets: counters.tx_packets,
                    rx_packets: counters.rx_packets,
                },
            })
        });
        (
            InterfacesResponse {
                interfaces,
                monotonic_ms: Some(now_ms),
                note: Some(INTERFACE_NOTE.into()),
                evidence: None,
            },
            lan_clock,
            counter_snapshot,
        )
    }

    #[cfg(not(feature = "nss-platform"))]
    fn interfaces_x86(&mut self, now_ms: u64) -> (InterfacesResponse, InterfaceCounterSnapshot) {
        let roles = collect_ifnames_with_roles(&self.config);
        let lan_roots = roles
            .iter()
            .filter_map(|(name, role)| (*role == InterfaceRole::Lan).then_some(name.clone()))
            .collect::<Vec<_>>();
        let masters = interface_masters();
        let lan_boundaries = independent_lan_boundaries(&lan_roots, &masters);
        let mut names_to_read = roles
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(boundaries) = lan_boundaries.as_ref() {
            names_to_read.extend(boundaries.iter().cloned());
        }
        let counter_snapshot = read_interface_counter_snapshot(&names_to_read);
        let raw_counters = &counter_snapshot.counters;
        let interfaces = roles
            .into_iter()
            .map(|(name, role)| {
                let boundary_names = (role == InterfaceRole::Lan)
                    .then(|| independent_lan_boundaries(std::slice::from_ref(&name), &masters))
                    .flatten();
                let sampled = if let Some(boundaries) = boundary_names.as_ref() {
                    sum_interface_counters(boundaries, raw_counters)
                } else {
                    raw_counters.get(&name).copied()
                };
                match sampled {
                    Some(counters) => {
                        let sampled_names = boundary_names
                            .as_deref()
                            .unwrap_or_else(|| std::slice::from_ref(&name));
                        let counter_source = counter_snapshot
                            .source_for(sampled_names.iter().map(String::as_str))
                            .unwrap_or(MIXED_INTERFACE_SOURCE);
                        let display = if role == InterfaceRole::Lan {
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
                        };
                        let (rx_bps, tx_bps, delta_ms) =
                            self.interface_rates.update(&name, display, now_ms);
                        Interface {
                            name,
                            role,
                            status: InterfaceStatus::Available,
                            rx_bytes: Some(display.rx_bytes),
                            tx_bytes: Some(display.tx_bytes),
                            rx_bps: Some(rx_bps),
                            tx_bps: Some(tx_bps),
                            delta_ms: Some(delta_ms),
                            sample_ms: Some(now_ms),
                            source: Some(if role == InterfaceRole::Lan {
                                format!("{counter_source} + real packets * 4-byte FCS")
                            } else {
                                counter_source.into()
                            }),
                            coverage: Some(if role == InterfaceRole::Lan {
                                format!(
                                    "independent_lan_boundary:{}",
                                    boundary_names.as_deref().unwrap_or_default().join("+")
                                )
                            } else {
                                "kernel_netdev_statistics".into()
                            }),
                            evidence: None,
                        }
                    }
                    None => Interface {
                        name,
                        role,
                        status: InterfaceStatus::Missing,
                        rx_bytes: Some(0),
                        tx_bytes: Some(0),
                        rx_bps: Some(0),
                        tx_bps: Some(0),
                        delta_ms: Some(0),
                        sample_ms: Some(now_ms),
                        source: Some(
                            "counter unavailable after /proc/net/dev and sysfs fallback".into(),
                        ),
                        coverage: Some("includes_hardware_offload_and_switch_bridge".into()),
                        evidence: None,
                    },
                }
            })
            .collect();
        (
            InterfacesResponse {
                interfaces,
                monotonic_ms: Some(now_ms),
                note: Some(INTERFACE_NOTE.into()),
                evidence: None,
            },
            counter_snapshot,
        )
    }

    fn shutdown(&mut self) -> Result<(), DaemonError> {
        if self.shutdown_complete {
            return Ok(());
        }
        let mut failures = Vec::new();
        if let Some(runtime) = self.bpf.as_mut() {
            if let Err(error) = runtime.shutdown(&mut self.adapter) {
                failures.push(format!("TC-BPF shutdown: {error}"));
            }
        }
        #[cfg(feature = "nss-platform")]
        if let Err(error) = self.nss.shutdown() {
            failures.push(format!("ECM+BPF shutdown: {error}"));
        }
        if !failures.is_empty() {
            return Err(DaemonError::collection(failures.join("; ")));
        }
        self.shutdown_complete = true;
        Ok(())
    }
}

impl Drop for ProductionRuntime {
    fn drop(&mut self) {
        if !self.shutdown_complete {
            let _ = self.shutdown();
        }
    }
}

impl Runtime for ProductionRuntime {
    type Checkpoint = RuntimeCheckpoint;

    fn checkpoint(&self) -> Self::Checkpoint {
        ProductionRuntime::checkpoint(self)
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        ProductionRuntime::restore(self, checkpoint);
    }

    fn collect(&mut self) -> Result<ResponseSnapshot, DaemonError> {
        // collect_and_reschedule owns the hot-cycle transaction. Candidate reload
        // collection uses ProductionRuntime::collect and keeps its local rollback.
        self.collect_inner(ProbeMethod::Status, None)
    }

    fn collection_interval_ms(&self, configured_ms: u32) -> u32 {
        effective_collection_interval_ms(
            self.config.access_edge_mode,
            self.rate_owner,
            configured_ms,
        )
    }

    fn shutdown(&mut self) -> Result<(), DaemonError> {
        ProductionRuntime::shutdown(self)
    }
}

struct App {
    state: CoordinatorState,
    runtime: Option<ProductionRuntime>,
    ubus: Option<UbusConnection>,
    collection_timer: Option<Timer>,
    collection_deadline_ms: Cell<u64>,
    reconnect_timer: Option<Timer>,
    reconnect_pending: Cell<bool>,
    mode_reload: DaeModeReloadLatch,
    last_error: Option<String>,
}

struct PreparedBpfReload {
    transaction: BpfReconfigureTxn,
    collection_checkpoint: BpfCollectionCheckpoint,
}

impl App {
    fn collection_tick(&mut self) {
        let (has_bpf, process_activity_changed, attach_mode_mismatch) = {
            let runtime = self
                .runtime
                .as_mut()
                .expect("collection timer requires a staged runtime");
            let process_activity_changed = runtime.refresh_dae_process_state();
            (
                runtime.bpf.is_some(),
                process_activity_changed,
                runtime.bpf_attach_mode_mismatch(),
            )
        };
        let signals =
            DaeModeTickSignals::new(has_bpf, process_activity_changed, attach_mode_mismatch);
        let retry_delay = self
            .runtime
            .as_ref()
            .map_or(self.state.config().refresh_interval_ms, |runtime| {
                runtime.collection_interval_ms(self.state.config().refresh_interval_ms)
            });
        let mut mode_reload = std::mem::take(&mut self.mode_reload);
        let outcome = run_dae_mode_tick(
            &mut mode_reload,
            self,
            signals,
            |app| app.reload_inner().map_err(|error| error.to_string()),
            |app| app.state.fatal_error().is_some(),
            |app| {
                schedule_absolute_collection(
                    app.collection_timer.as_ref().unwrap(),
                    &app.collection_deadline_ms,
                    retry_delay,
                )
                .map_err(|error| error.to_string())
            },
            Self::collect_current_tick,
        );
        self.mode_reload = mode_reload;
        match outcome {
            DaeModeTickOutcome::Collected | DaeModeTickOutcome::Reloaded => {}
            DaeModeTickOutcome::RetryScheduled { reload_error } => {
                self.last_error = Some(reload_error);
            }
            DaeModeTickOutcome::FatalReload { reload_error } => {
                self.last_error = Some(reload_error);
                UloopGuard::request_stop();
            }
            DaeModeTickOutcome::RetryScheduleFailed {
                reload_error,
                timer_error,
            } => {
                let message = format!(
                    "dynamic BPF mode reload failed: {reload_error}; collection timer rearm failed: {timer_error}"
                );
                self.last_error = Some(message.clone());
                *self.state.fatal_cell().borrow_mut() = Some(message);
                UloopGuard::request_stop();
            }
        }
    }

    fn collect_current_tick(&mut self) {
        let timer = self.collection_timer.as_ref().unwrap();
        let deadline = &self.collection_deadline_ms;
        let runtime = self
            .runtime
            .as_mut()
            .expect("collection timer requires a staged runtime");
        if let Err(error) = collect_and_reschedule(
            &self.state,
            runtime,
            |delay| schedule_absolute_collection(timer, deadline, delay),
            UloopGuard::request_stop,
        ) {
            self.last_error = Some(error.to_string());
        }
    }
    fn refresh_clients_connections(&mut self) -> Result<(), DaemonError> {
        let base = self.state.snapshot();
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| DaemonError::collection("runtime is not started"))?;
        let checkpoint = runtime.checkpoint();
        let snapshot = match runtime.refresh_connections(&base) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                runtime.restore(checkpoint);
                return Err(error);
            }
        };
        self.state.publish_runtime_snapshot(snapshot);
        Ok(())
    }
    fn before_reply(&mut self, method: ubus::Method) -> Result<(), DaemonError> {
        match before_reply_action(method) {
            BeforeReplyAction::None => Ok(()),
            BeforeReplyAction::RefreshConnections => self.refresh_clients_connections(),
            BeforeReplyAction::Reload => self.reload(),
        }
    }
    fn schedule_reconnect(&self) {
        if !self.reconnect_pending.replace(true)
            && self
                .reconnect_timer
                .as_ref()
                .unwrap()
                .schedule(RECONNECT_MS)
                .is_err()
        {
            self.reconnect_pending.set(false);
            *self.state.fatal_cell().borrow_mut() =
                Some("failed to schedule ubus reconnect".into());
            UloopGuard::request_stop();
        }
    }
    fn reconnect(&mut self) {
        self.reconnect_pending.set(false);
        let connection = self.ubus.as_mut().unwrap();
        let timer = self.reconnect_timer.as_ref().unwrap();
        let mut context = (connection, timer);
        let result = reconnect_and_register(
            &self.state,
            &mut context,
            |(connection, _)| {
                connection
                    .reconnect(None)
                    .map_err(|error| DaemonError::transport(error.to_string()))?;
                connection
                    .reregister_objects()
                    .map_err(|error| DaemonError::transport(error.to_string()))
            },
            |(_, timer), delay| {
                timer
                    .schedule(delay)
                    .map_err(|error| DaemonError::transport(error.to_string()))
            },
            UloopGuard::request_stop,
        );
        if let Err(error) = result {
            self.last_error = Some(error.to_string());
        }
    }
    fn reload(&mut self) -> Result<(), DaemonError> {
        let result = self.reload_inner();
        if result.is_ok() {
            self.mode_reload.complete();
        }
        result
    }

    fn reload_inner(&mut self) -> Result<(), DaemonError> {
        if self.runtime.is_none() {
            return Err(DaemonError::reload("runtime is not started"));
        }
        let config = load_config()?;
        let current = self.runtime.as_ref().unwrap();
        let process_tracker = current.process_tracker.clone();
        #[cfg(feature = "nss-platform")]
        let attachment_generation_floor = current.access_edge.attachment_generation_watermark();
        let mut candidate =
            ProductionRuntime::prepare_with_process_tracker(config.clone(), process_tracker)?;
        #[cfg(feature = "nss-platform")]
        candidate
            .access_edge
            .advance_attachment_generation_floor(attachment_generation_floor);
        #[cfg(feature = "nss-platform")]
        candidate
            .nss
            .activate(&candidate.config, &candidate.probe_report);
        let wants_bpf = config.enable_bpf
            && matches!(
                config.rate_collector_mode,
                crate::config::RateCollectorMode::Auto
                    | crate::config::RateCollectorMode::Bpf
                    | crate::config::RateCollectorMode::NssEcmBpf
            )
            && candidate.probe_report.facts.tc.safe_attach;
        let desired_mode = candidate.desired_attach_mode();
        let current_has_bpf = self
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.bpf.is_some());
        let reconfigure_strategy = if wants_bpf && current_has_bpf {
            let current_bpf = self.runtime.as_ref().unwrap().bpf.as_ref().unwrap();
            if current_bpf.attach_mode().is_none() {
                return Err(DaemonError::reload(
                    "current BPF topology is not healthy enough to reload",
                ));
            }
            Some(current_bpf.reconfigure_strategy(desired_mode))
        } else {
            None
        };
        let reuse_bpf = reconfigure_strategy == Some(ReconfigureStrategy::InPlace);
        let suspended_mode_switch =
            reconfigure_strategy == Some(ReconfigureStrategy::SuspendThenAttach);
        let mut prepared_bpf = None;
        let mut mode_switch_checkpoint = None;
        let mut snapshot = if reuse_bpf {
            let current = self.runtime.as_mut().unwrap();
            if current.config.max_clients == config.max_clients
                && current.config.active_client_window_ms == config.active_client_window_ms
            {
                candidate.bpf_collector = current.bpf_collector.clone();
            }
            candidate.bpf_error = current.bpf_error.clone();
            candidate.bpf_error_stage = current.bpf_error_stage;
            let runtime = current.bpf.as_mut().unwrap();
            let transaction = match runtime.prepare_reconfigure(
                &mut current.adapter,
                &collect_ifnames(&config),
                desired_mode,
            ) {
                Ok(transaction) => transaction,
                Err(error) => {
                    if error.kind() == AdapterErrorKind::DetachFailed {
                        *self.state.fatal_cell().borrow_mut() =
                            Some(format!("BPF reconfigure prepare cleanup failed: {error}"));
                        UloopGuard::request_stop();
                    }
                    return Err(DaemonError::reload(error.to_string()));
                }
            };
            if transaction.topology_changed() {
                candidate.bpf_collector.reset_rates();
            }
            match candidate.collect_with_external_bpf(
                runtime,
                &mut current.adapter,
                ProbeMethod::Reload,
            ) {
                Ok((snapshot, collection_checkpoint)) => {
                    prepared_bpf = Some(PreparedBpfReload {
                        transaction,
                        collection_checkpoint,
                    });
                    snapshot
                }
                Err(error) => {
                    if let Err(rollback) =
                        runtime.abort_reconfigure(&mut current.adapter, transaction)
                    {
                        return Err(record_fatal_cleanup(
                            "BPF reconfigure abort",
                            &error.to_string(),
                            &rollback.to_string(),
                            self.state.fatal_cell(),
                        ));
                    }
                    return Err(abort_reload_candidate(
                        &self.state,
                        &mut candidate,
                        error,
                        UloopGuard::request_stop,
                    ));
                }
            }
        } else {
            if suspended_mode_switch {
                let current = self.runtime.as_ref().unwrap();
                if current.config.max_clients == config.max_clients
                    && current.config.active_client_window_ms == config.active_client_window_ms
                {
                    candidate.bpf_collector = current.bpf_collector.clone();
                }
                candidate.bpf_error = current.bpf_error.clone();
                candidate.bpf_error_stage = current.bpf_error_stage;
                mode_switch_checkpoint = Some(candidate.checkpoint());
            } else if wants_bpf {
                if let Err(error) = candidate.activate_new_bpf() {
                    *self.state.fatal_cell().borrow_mut() = Some(error.to_string());
                    UloopGuard::request_stop();
                    return Err(error);
                }
            }
            match candidate.collect(ProbeMethod::Reload) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return Err(abort_reload_candidate(
                        &self.state,
                        &mut candidate,
                        error,
                        UloopGuard::request_stop,
                    ));
                }
            }
        };
        let old_interval = self
            .runtime
            .as_ref()
            .map_or(self.state.config().refresh_interval_ms, |runtime| {
                runtime.collection_interval_ms(self.state.config().refresh_interval_ms)
            });
        let new_interval = candidate.collection_interval_ms(config.refresh_interval_ms);
        if let Err(error) = schedule_absolute_collection(
            self.collection_timer.as_ref().unwrap(),
            &self.collection_deadline_ms,
            new_interval,
        ) {
            let bpf_rollback = prepared_bpf.take().and_then(|prepared| {
                let current = self.runtime.as_mut().unwrap();
                let runtime = current.bpf.as_mut().unwrap();
                runtime.restore_collection_checkpoint(
                    &mut candidate.bpf_collector,
                    prepared.collection_checkpoint,
                );
                runtime
                    .abort_reconfigure(&mut current.adapter, prepared.transaction)
                    .err()
            });
            let bpf_rollback_failed = bpf_rollback.is_some();
            let primary = match bpf_rollback {
                Some(rollback) => {
                    DaemonError::reload(format!("{error}; BPF rollback failed: {rollback}"))
                }
                None => DaemonError::reload(error.to_string()),
            };
            let timer = self.collection_timer.as_ref().unwrap();
            let deadline = &self.collection_deadline_ms;
            let failure = abort_reload_after_timer_failure(
                &self.state,
                &mut candidate,
                primary,
                || schedule_absolute_collection(timer, deadline, old_interval),
                UloopGuard::request_stop,
            );
            if bpf_rollback_failed && self.state.fatal_error().is_none() {
                *self.state.fatal_cell().borrow_mut() = Some(failure.to_string());
                UloopGuard::request_stop();
            }
            return Err(failure);
        }
        if suspended_mode_switch {
            let suspended = match {
                let current = self.runtime.as_mut().unwrap();
                let runtime = current.bpf.as_mut().unwrap();
                match runtime.suspend_for_replacement(&mut current.adapter) {
                    Ok(suspended) => Ok(suspended),
                    Err(error) => {
                        let old_topology_intact = runtime.is_attached();
                        Err((error, old_topology_intact))
                    }
                }
            } {
                Ok(suspended) => suspended,
                Err((error, old_topology_intact)) => {
                    let primary =
                        DaemonError::reload(format!("BPF mode-switch suspend failed: {error}"));
                    let timer = self.collection_timer.as_ref().unwrap();
                    let deadline = &self.collection_deadline_ms;
                    let restore_timer =
                        || schedule_absolute_collection(timer, deadline, old_interval);
                    let failure = finish_mode_switch_suspend_failure(
                        &self.state,
                        &mut candidate,
                        primary,
                        old_topology_intact,
                        restore_timer,
                        UloopGuard::request_stop,
                    );
                    return Err(failure);
                }
            };
            candidate.restore(
                mode_switch_checkpoint
                    .take()
                    .expect("suspended mode switch checkpointed before collection"),
            );
            candidate.bpf_collector.reset_rates();
            let interfaces = collect_ifnames(&config);
            let attach_result = {
                let current = self.runtime.as_mut().unwrap();
                current.bpf.as_mut().unwrap().attach_suspended(
                    &mut current.adapter,
                    &suspended,
                    &interfaces,
                    desired_mode,
                )
            };
            if let Err(error) = attach_result {
                let restore = {
                    let current = self.runtime.as_mut().unwrap();
                    current
                        .bpf
                        .as_mut()
                        .unwrap()
                        .resume_suspended(&mut current.adapter, suspended)
                };
                let timer = self.collection_timer.as_ref().unwrap();
                let deadline = &self.collection_deadline_ms;
                return Err(finish_mode_switch_rollback(
                    &self.state,
                    &mut candidate,
                    DaemonError::reload(error.to_string()),
                    restore,
                    || schedule_absolute_collection(timer, deadline, old_interval),
                    UloopGuard::request_stop,
                ));
            }
            let collected = {
                let current = self.runtime.as_mut().unwrap();
                candidate.collect_with_external_bpf(
                    current.bpf.as_mut().unwrap(),
                    &mut current.adapter,
                    ProbeMethod::Reload,
                )
            };
            snapshot = match collected {
                Ok((snapshot, _)) => snapshot,
                Err(error) => {
                    let restore = {
                        let current = self.runtime.as_mut().unwrap();
                        let runtime = current.bpf.as_mut().unwrap();
                        runtime
                            .suspend_for_replacement(&mut current.adapter)
                            .and_then(|_| runtime.resume_suspended(&mut current.adapter, suspended))
                    };
                    let timer = self.collection_timer.as_ref().unwrap();
                    let deadline = &self.collection_deadline_ms;
                    return Err(finish_mode_switch_rollback(
                        &self.state,
                        &mut candidate,
                        error,
                        restore,
                        || schedule_absolute_collection(timer, deadline, old_interval),
                        UloopGuard::request_stop,
                    ));
                }
            };
            let current = self.runtime.as_mut().unwrap();
            candidate.adapter = std::mem::take(&mut current.adapter);
            candidate.bpf = current.bpf.take();
        }
        let postcommit_cleanup: Option<BpfPostCommitCleanup<SystemAyaLink>> =
            prepared_bpf.take().map(|prepared| {
                let current = self.runtime.as_mut().unwrap();
                let runtime = current.bpf.as_mut().unwrap();
                let cleanup = runtime
                    .commit_reconfigure(prepared.transaction, ReconfigureRateBaseline::Prepared);
                candidate.adapter = std::mem::take(&mut current.adapter);
                candidate.bpf = current.bpf.take();
                cleanup
            });
        commit_reload(
            &mut self.state,
            &mut self.runtime,
            candidate,
            config,
            snapshot,
            UloopGuard::request_stop,
        );
        if let Some(cleanup) = postcommit_cleanup {
            let current = self.runtime.as_mut().unwrap();
            let runtime = current.bpf.as_mut().unwrap();
            if let Err(error) = runtime.run_postcommit_cleanup(&mut current.adapter, cleanup) {
                let message = format!("reload committed; postcommit BPF cleanup failed: {error}");
                *self.state.fatal_cell().borrow_mut() = Some(message);
                UloopGuard::request_stop();
            }
        }
        Ok(())
    }
}

fn finish_mode_switch_suspend_failure<R: Runtime>(
    state: &CoordinatorState,
    candidate: &mut R,
    primary: DaemonError,
    old_topology_intact: bool,
    restore_timer: impl FnOnce() -> Result<(), DaemonError>,
    request_stop: impl FnOnce(),
) -> DaemonError {
    if old_topology_intact {
        abort_reload_after_timer_failure(state, candidate, primary, restore_timer, request_stop)
    } else {
        abort_unrecoverable_mode_switch(state, candidate, primary, restore_timer, request_stop)
    }
}

fn abort_unrecoverable_mode_switch<R: Runtime>(
    state: &CoordinatorState,
    candidate: &mut R,
    primary: DaemonError,
    restore_timer: impl FnOnce() -> Result<(), DaemonError>,
    request_stop: impl FnOnce(),
) -> DaemonError {
    let candidate_cleanup = candidate.shutdown().err();
    let timer_rollback = restore_timer().err();
    let mut message = primary.to_string();
    if let Some(error) = candidate_cleanup {
        message.push_str(&format!("; candidate cleanup failed: {error}"));
    }
    if let Some(error) = timer_rollback {
        message.push_str(&format!("; timer rollback failed: {error}"));
    }
    *state.fatal_cell().borrow_mut() = Some(message.clone());
    request_stop();
    DaemonError::reload(message)
}

fn finish_mode_switch_rollback<R: Runtime>(
    state: &CoordinatorState,
    candidate: &mut R,
    primary: DaemonError,
    bpf_restore: Result<(), AdapterError>,
    restore_timer: impl FnOnce() -> Result<(), DaemonError>,
    request_stop: impl FnOnce(),
) -> DaemonError {
    let candidate_cleanup = candidate.shutdown().err();
    let old_restore = bpf_restore.err();
    let timer_rollback = restore_timer().err();
    if candidate_cleanup.is_none() && old_restore.is_none() && timer_rollback.is_none() {
        return primary;
    }

    let mut message = primary.to_string();
    if let Some(error) = candidate_cleanup {
        message.push_str(&format!("; candidate cleanup failed: {error}"));
    }
    if let Some(error) = old_restore {
        message.push_str(&format!("; old BPF restore failed: {error}"));
    }
    if let Some(error) = timer_rollback {
        message.push_str(&format!("; timer rollback failed: {error}"));
    }
    *state.fatal_cell().borrow_mut() = Some(message.clone());
    request_stop();
    DaemonError::reload(message)
}

pub fn run() -> Result<(), DaemonError> {
    let config = load_config()?;
    let mut event_loop =
        UloopGuard::init().map_err(|error| DaemonError::platform(error.to_string()))?;
    let state = CoordinatorState::new(
        config.clone(),
        Arc::new(ResponseSnapshot::unsupported("starting")),
    );
    let snapshots = state.snapshot_store();
    let app = Rc::new(RefCell::new(App {
        state,
        runtime: None,
        ubus: None,
        collection_timer: None,
        collection_deadline_ms: Cell::new(0),
        reconnect_timer: None,
        reconnect_pending: Cell::new(false),
        mode_reload: DaeModeReloadLatch::default(),
        last_error: None,
    }));
    let weak = Rc::downgrade(&app);
    app.borrow_mut().collection_timer = Some(Timer::new(move || {
        if let Some(app) = weak.upgrade() {
            app.borrow_mut().collection_tick();
        }
    }));
    let weak = Rc::downgrade(&app);
    app.borrow_mut().reconnect_timer = Some(Timer::new(move || {
        if let Some(app) = weak.upgrade() {
            app.borrow_mut().reconnect();
        }
    }));

    let weak = Rc::downgrade(&app);
    let object = ubus::object(snapshots, move |method| {
        weak.upgrade()
            .ok_or_else(|| DaemonError::reload("daemon stopped"))?
            .borrow_mut()
            .before_reply(method)
    })?;
    let mut connection =
        UbusConnection::connect(None).map_err(|error| DaemonError::transport(error.to_string()))?;
    connection
        .attach_uloop()
        .map_err(|error| DaemonError::transport(error.to_string()))?;
    connection
        .register_object(object)
        .map_err(|error| DaemonError::transport(error.to_string()))?;
    let weak = Rc::downgrade(&app);
    connection.set_connection_lost_handler(move || {
        if let Some(app) = weak.upgrade() {
            app.borrow().schedule_reconnect();
        }
    });
    app.borrow_mut().ubus = Some(connection);

    let runtime = ProductionRuntime::stage(config.clone())?;
    let runtime = {
        let app = app.borrow();
        let timer = app.collection_timer.as_ref().unwrap();
        let deadline = &app.collection_deadline_ms;
        activate_runtime(
            &app.state,
            runtime,
            |delay| schedule_absolute_collection(timer, deadline, delay),
            UloopGuard::request_stop,
        )?
    };
    app.borrow_mut().runtime = Some(runtime);
    let _signals = {
        let mut app = app.borrow_mut();
        let App { runtime, ubus, .. } = &mut *app;
        install_control_or_shutdown(runtime.as_mut(), UloopSignalBridge::install, || {
            ubus.take();
            Ok(())
        })?
    };
    let run_result = event_loop
        .run()
        .map_err(|error| DaemonError::platform(error.to_string()));
    let shutdown_result = {
        let mut app = app.borrow_mut();
        let _connection = app.ubus.take();
        shutdown_runtime(app.runtime.as_mut(), || Ok(()))
    };
    let fatal = app.borrow().state.fatal_error();
    if let Some(error) = fatal {
        return Err(DaemonError::platform(error));
    }
    run_result.and(shutdown_result)
}

fn load_config() -> Result<RuntimeConfig, DaemonError> {
    let mut source = lanspeed_openwrt_sys::UciContext::new()
        .map_err(|error| DaemonError::reload(error.to_string()))?;
    RuntimeConfig::load(&mut source, &SysfsInterfaceEligibility::default())
        .map_err(|error| DaemonError::reload(error.to_string()))
}

fn read_identities(config: &RuntimeConfig, now_ms: u64) -> (IdentityTable, Vec<String>) {
    let collect_names = collect_ifnames(config);
    let filter = IdentityFilter::from_uci_values(collect_names.iter().map(String::as_str));
    let mut table = IdentityTable::new(config.max_clients);
    let mut errors = Vec::new();
    let mut entries = match arp::read_arp_table(
        arp::ARP_PROCFS_PATH,
        config.max_clients,
        &filter,
        &LegacyZoneResolver,
    ) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(format!("ARP: {error}"));
            Vec::new()
        }
    };
    match netlink::read_ipv6_neighbor_table(
        config.max_clients.saturating_sub(entries.len()),
        &filter,
        &LegacyZoneResolver,
    ) {
        Ok(ipv6) => entries.extend(ipv6),
        Err(error) => errors.push(format!("IPv6 neighbor: {error}")),
    }
    for entry in entries {
        let _ = table.observe(IdentityObservation {
            mac: &entry.mac.to_string(),
            zone: Some(&entry.zone),
            interface: &entry.interface,
            ip: Some(&entry.ip),
            hostname: None,
            last_seen: now_ms,
            source: ObservationSource::Neighbor,
        });
    }
    (table, errors)
}

fn connection_overlay(snapshot: Option<&CollectedSnapshot>) -> ConnectionOverlay {
    let mut overlay = ConnectionOverlay::available();
    if let Some(snapshot) = snapshot {
        for client in &snapshot.clients {
            overlay.insert(
                client.identity_key.clone(),
                ConnectionCounts {
                    tcp: client.tcp_conns,
                    udp: client.udp_conns,
                    udp_dns: client.udp_dns_conns,
                    udp_other: client.udp_other_conns,
                },
            );
        }
    } else {
        return ConnectionOverlay::unavailable("conntrack unavailable");
    }
    overlay
}

fn evidence(report: &ProbeReport, method: &str) -> Evidence {
    let mut details = BTreeMap::new();
    details.insert("source".into(), json!(report.evidence.source));
    details.insert("method".into(), json!(method));
    details.insert("read_only".into(), json!(true));
    details.insert("probe_error".into(), json!(report.evidence.probe_error));
    details.insert(
        "lan_probe_error".into(),
        json!(report.evidence.lan_probe_error),
    );
    details.insert(
        "probe_failures".into(),
        crate::production_evidence::probe_failure_details(&report.evidence.probe_failures),
    );
    details.insert(
        "effective_collector".into(),
        json!(report.evidence.collector.effective_rate_collector),
    );
    details.insert(
        "platform".into(),
        json!({
            "target_arch": std::env::consts::ARCH,
            "profile": if crate::platform::profile::COMPILED_PROFILE.uses_nss() {
                "nss_aarch64"
            } else {
                "x86_tc_bpf"
            },
            "nss_compiled": cfg!(feature = "nss-platform"),
            "access_edge_compiled": cfg!(feature = "nss-platform"),
            "nss_modes_exposed": crate::platform::profile::COMPILED_PROFILE.uses_nss()
                && report.facts.nss.present,
        }),
    );
    details.insert("collector".into(), json!({"rate_reason":report.evidence.collector.rate_reason,"connection_reason":report.evidence.collector.connection_reason,
        "primary_source":report.evidence.collector.effective_rate_collector,"mode":report.evidence.collector.mode,"confidence":report.evidence.collector.confidence}));
    details.insert(
        "dae".into(),
        json!({
            "running": report.evidence.proxy.dae.dae_running
                || report.evidence.proxy.dae.daed_running,
            "process": report.evidence.proxy.dae.dae_process
                || report.evidence.proxy.dae.daed_process,
            "runtime_active": report.evidence.proxy.dae.runtime_active,
            "process_probe_error": report.evidence.proxy.dae.process_probe_error,
            "dae_running": report.evidence.proxy.dae.dae_running,
            "daed_running": report.evidence.proxy.dae.daed_running,
            "dae_process": report.evidence.proxy.dae.dae_process,
            "daed_process": report.evidence.proxy.dae.daed_process,
        }),
    );
    Evidence { details }
}

fn runtime_evidence(
    report: &ProbeReport,
    method: &str,
    config: &RuntimeConfig,
    runtime: &RuntimeHealth,
    bpf_error_stage: Option<&'static str>,
) -> Evidence {
    let mut public = evidence(report, method);
    public.details.insert(
        "bpf".into(),
        crate::production_evidence::bpf_details(config, report, runtime, bpf_error_stage),
    );
    public
}

#[cfg(test)]
mod shared_evidence_tests {
    use super::*;

    #[test]
    fn status_and_health_share_the_required_probe_failure_contract() {
        let report = crate::probe::assess(
            &RuntimeConfig::default(),
            crate::probe::ProbeObservations::default(),
            &RuntimeHealth::default(),
        );

        for method in ["status", "health"] {
            let public = runtime_evidence(
                &report,
                method,
                &RuntimeConfig::default(),
                &RuntimeHealth::default(),
                None,
            );
            let failures = &public.details["probe_failures"];
            assert_eq!(failures["items"], json!([]));
            assert_eq!(failures["total"], 0);
            assert_eq!(failures["truncated"], false);
            assert!(public.details["bpf"].is_object());
        }
    }
}

fn conntrack_generation_evidence(snapshot: &CollectedSnapshot) -> Value {
    let parsed_entries = snapshot
        .stats
        .entries_seen
        .saturating_sub(snapshot.stats.malformed_lines);
    let flow_id_coverage_pct = (parsed_entries > 0)
        .then(|| snapshot.stats.conntrack_ids_present as f64 * 100.0 / parsed_entries as f64);
    json!({
        "counter_generation_key": if snapshot.stats.netlink_read {
            "ctnetlink_cta_id_with_zone_tuple_fallback"
        } else {
            "procfs_zone_tuple_fallback"
        },
        "parsed_entries": parsed_entries,
        "conntrack_ids_present": snapshot.stats.conntrack_ids_present,
        "conntrack_zones_present": snapshot.stats.conntrack_zones_present,
        "flow_id_coverage_pct": flow_id_coverage_pct,
    })
}

fn apply_decision_evidence(
    evidence: &mut Evidence,
    decision: &policy::PolicyDecision,
    config: &RuntimeConfig,
    _report: &ProbeReport,
) {
    let effective = decision.rate.as_str();
    evidence
        .details
        .insert("effective_collector".into(), json!(effective));
    let effective_interval_ms = effective_collection_interval_ms(
        config.access_edge_mode,
        Some(decision.rate),
        config.refresh_interval_ms,
    );
    if let Some(collector) = evidence
        .details
        .get_mut("collector")
        .and_then(Value::as_object_mut)
    {
        collector.insert("primary_source".into(), json!(effective));
        collector.insert(
            "effective_connection_collector".into(),
            json!(decision.connection.as_str()),
        );
        collector.insert("rate_reason".into(), json!(decision.evidence.rate_reason));
        collector.insert(
            "connection_reason".into(),
            json!(decision.evidence.connection_reason),
        );
        collector.insert("mode".into(), json!(decision.mode.as_str()));
        collector.insert("confidence".into(), json!(decision.confidence.as_str()));
        collector.insert("warnings".into(), json!(decision.warnings));
        collector.insert("effective_interval_ms".into(), json!(effective_interval_ms));
    }
    #[cfg(feature = "nss-platform")]
    evidence.details.insert(
        "nss".into(),
        crate::production_evidence::nss_details(config, _report, decision),
    );
}

fn capabilities(value: &ProbeCapabilities, report: &ProbeReport) -> Capabilities {
    Capabilities {
        // `bpf_supported` is a platform/configuration capability. Keep it
        // independent from the compatibility `bpf` capability field.
        bpf_supported: value.tc && value.tc_clsact && report.facts.tc.bpf,
        bpf: value.bpf,
        bpf_package: value.bpf_package,
        bpf_object: value.bpf_object,
        bpf_runtime_metrics: value.bpf_runtime_metrics,
        conntrack_fallback: value.conntrack_fallback,
        live_metrics: value.live_metrics,
        fw4: value.fw4,
        nft: value.nft,
        software_flow_offload: value.software_flow_offload,
        hardware_flow_offload: value.hardware_flow_offload,
        nss: report.facts.nss.present,
        nss_ecm_offload: report.facts.nss.ecm_active,
        nss_ppe_offload: report.facts.nss.ppe_active,
        nss_ecm_node: report.facts.nss.direct_state_readable,
        nss_ecm_bpf: value.nss_ecm_bpf,
        nss_bridge_mgr: report.evidence.nss.bridge_mgr,
        nss_ifb: report.evidence.nss.ifb_active,
        nss_nsm: report.evidence.nss.nsm_active,
        nss_dp: report.evidence.nss.dp_active,
        nss_mcs: report.evidence.nss.mcs_active,
        fullcone: value.fullcone,
        nf_conntrack_acct: value.nf_conntrack_acct,
        flowtable_counter: value.flowtable_counter,
        tc: value.tc,
        tc_clsact: value.tc_clsact,
        existing_tc_filters: value.existing_tc_filters,
        ifb: value.ifb,
        sqm: value.sqm,
        qosify: value.qosify,
        openclash: value.openclash,
        openclash_fake_ip: value.openclash_fake_ip,
        openclash_tun_mix: value.openclash_tun_mix,
        openclash_redirect_dns: value.openclash_redirect_dns,
        openclash_dns_chain_complete: value.openclash_dns_chain_complete,
        openclash_router_self_proxy: value.openclash_router_self_proxy,
        openclash_udp_proxy: value.openclash_udp_proxy,
        openclash_ipv6: value.openclash_ipv6,
        dae: value.dae,
        homeproxy: value.homeproxy,
        lan_bridge: value.lan_bridge,
        vlan: value.vlan,
        wlan: value.wlan,
        lan_edge: value.lan_edge,
        safe_attach: value.safe_attach,
        map_full: value.map_full,
    }
}

fn mode(value: ProbeMode) -> Mode {
    match value {
        ProbeMode::Full => Mode::Full,
        ProbeMode::Degraded => Mode::Degraded,
        ProbeMode::Unsupported => Mode::Unsupported,
    }
}
fn conntrack_mode(value: ConnectionCollectorMode) -> ConntrackMode {
    match value {
        ConnectionCollectorMode::Auto => ConntrackMode::Auto,
        ConnectionCollectorMode::ConntrackNetlink => ConntrackMode::Netlink,
        ConnectionCollectorMode::ConntrackProcfs => ConntrackMode::Procfs,
    }
}
fn collect_ifnames(config: &RuntimeConfig) -> Vec<String> {
    config.runtime_collect_ifnames()
}
fn collect_ifnames_with_roles(config: &RuntimeConfig) -> Vec<(String, InterfaceRole)> {
    collect_ifnames(config)
        .into_iter()
        .map(|name| (name, InterfaceRole::Lan))
        .chain(
            config
                .runtime_observe_ifnames()
                .into_iter()
                .map(|name| (name, InterfaceRole::Observe)),
        )
        .collect()
}

#[cfg(feature = "nss-platform")]
fn access_edge_bridges(config: &RuntimeConfig) -> Vec<String> {
    collect_ifnames(config)
        .into_iter()
        .filter(|name| {
            Path::new("/sys/class/net")
                .join(name)
                .join("bridge")
                .is_dir()
        })
        .collect()
}

fn sysdevices(config: &RuntimeConfig) -> Result<SysdevicesResponse, DaemonError> {
    let selected = collect_ifnames(config);
    let observed = config.runtime_observe_ifnames();
    let configured_ifnames = if config.configured_ifnames.is_empty() {
        let mut names = Vec::new();
        for name in config.ifnames.iter().chain(config.interface_include.iter()) {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    } else {
        config.configured_ifnames.clone()
    };
    let configured_observed = if config.configured_observed.is_empty() {
        config.observe_ifnames.clone()
    } else {
        config.configured_observed.clone()
    };
    let configured_excluded = if config.configured_excluded.is_empty() {
        config.interface_exclude.clone()
    } else {
        config.configured_excluded.clone()
    };
    let eligibility = SysfsInterfaceEligibility::default();
    let mut devices = Vec::new();
    for entry in fs::read_dir("/sys/class/net")
        .map_err(|error| DaemonError::collection(error.to_string()))?
    {
        let name = entry
            .map_err(|error| DaemonError::collection(error.to_string()))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if !is_sysdevice_candidate(&name) {
            continue;
        }
        let root = Path::new("/sys/class/net").join(&name);
        let speed = fs::read_to_string(root.join("speed"))
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v > 0 && *v < (1 << 31));
        let recommended = eligibility.is_collect_eligible(&name);
        let is_bridge = root.join("bridge").is_dir();
        let is_bridge_port = root.join("brport").is_dir();
        let is_nss_ifb = name == "nssifb";
        let collect_allowed = recommended && !is_nss_ifb;
        let collect_reason = if collect_allowed && is_bridge {
            "eligible_bridge"
        } else if collect_allowed && is_bridge_port {
            "eligible_bridge_port"
        } else if collect_allowed {
            "eligible_ethernet"
        } else if is_nss_ifb {
            "nssifb_observe_only"
        } else {
            "unsupported_link_type"
        };
        devices.push(Sysdevice {
            name: name.clone(),
            selected: selected.contains(&name),
            observed: observed.contains(&name),
            recommended_lan: recommended,
            collect_allowed,
            collect_reason: collect_reason.into(),
            is_bridge,
            is_bridge_port,
            is_nss_ifb,
            speed_mbps: speed,
        });
    }
    let discovered = devices
        .iter()
        .map(|device| device.name.as_str())
        .collect::<Vec<_>>();
    let mut orphaned = Vec::new();
    for name in configured_ifnames
        .iter()
        .chain(configured_observed.iter())
        .chain(configured_excluded.iter())
    {
        if !discovered.contains(&name.as_str()) && !orphaned.contains(name) {
            orphaned.push(name.clone());
        }
    }
    Ok(SysdevicesResponse {
        contract_version: 1,
        devices,
        current_ifnames: selected,
        current_observed: observed,
        // `interface_exclude` is compatibility-only and does not alter the
        // runtime attach set, so no exclusion is currently effective.
        current_excluded: Vec::new(),
        configured_ifnames,
        configured_observed,
        configured_excluded,
        orphaned,
        limits: SysdeviceLimits {
            max_configured: MAX_INTERFACE_NAMES,
            max_name_length: MAX_INTERFACE_NAME_LEN.saturating_sub(1),
        },
    })
}

fn version() -> String {
    version_from(
        option_env!("LANSPEED_VERSION"),
        option_env!("LANSPEED_RELEASE"),
    )
}

fn version_from(version: Option<&str>, release: Option<&str>) -> String {
    match (version, release) {
        (Some(version), Some(release)) => format!("{version}-r{release}"),
        _ => "unconfigured".into(),
    }
}

fn record_fatal_cleanup(
    context: &str,
    primary: &str,
    cleanup: &str,
    fatal: &RefCell<Option<String>>,
) -> DaemonError {
    let combined = format!("{context}: {primary}; cleanup failed: {cleanup}");
    *fatal.borrow_mut() = Some(combined.clone());
    UloopGuard::request_stop();
    DaemonError::reload(combined)
}

#[cfg(all(test, feature = "nss-platform"))]
mod tests {
    use super::*;
    use crate::platform::nss::ecm_bpf::EcmBpfClientSample;

    #[derive(Default)]
    struct FakeRuntime {
        shutdowns: usize,
        fail_shutdown: bool,
    }

    impl Runtime for FakeRuntime {
        type Checkpoint = ();

        fn checkpoint(&self) -> Self::Checkpoint {}

        fn restore(&mut self, _checkpoint: Self::Checkpoint) {}

        fn collect(&mut self) -> Result<ResponseSnapshot, DaemonError> {
            unreachable!("mode-switch failure tests do not collect")
        }

        fn shutdown(&mut self) -> Result<(), DaemonError> {
            self.shutdowns += 1;
            if self.fail_shutdown {
                Err(DaemonError::collection("candidate shutdown failed"))
            } else {
                Ok(())
            }
        }
    }

    fn test_state() -> CoordinatorState {
        CoordinatorState::new(
            RuntimeConfig::default(),
            Arc::new(ResponseSnapshot::unsupported("test")),
        )
    }

    #[test]
    fn ecm_bpf_ignores_flowtable_warnings_owned_by_other_offload_paths() {
        let original = vec![
            "flowtable_counter_probe_unavailable".to_owned(),
            "flowtable_counter_missing".to_owned(),
            "nss_ecm_bpf_active".to_owned(),
        ];
        let mut ecm_bpf = original.clone();
        retain_collector_warnings(&mut ecm_bpf, RateCollector::NssEcmBpf);
        assert_eq!(ecm_bpf, ["nss_ecm_bpf_active"]);

        let mut bpf = original.clone();
        retain_collector_warnings(&mut bpf, RateCollector::Bpf);
        assert_eq!(bpf, original);
    }

    #[test]
    fn intact_suspend_failure_restores_timer_without_fatal_stop() {
        let state = test_state();
        let mut candidate = FakeRuntime::default();
        let timer_restores = Cell::new(0);
        let stopped = Cell::new(false);

        let error = finish_mode_switch_suspend_failure(
            &state,
            &mut candidate,
            DaemonError::reload("inspect failed"),
            true,
            || {
                timer_restores.set(timer_restores.get() + 1);
                Ok(())
            },
            || stopped.set(true),
        );

        assert!(error.to_string().contains("inspect failed"));
        assert_eq!(candidate.shutdowns, 1);
        assert_eq!(timer_restores.get(), 1);
        assert!(!stopped.get());
        assert!(state.fatal_error().is_none());
    }

    #[test]
    fn mutated_suspend_failure_is_fatal_even_when_cleanup_succeeds() {
        let state = test_state();
        let mut candidate = FakeRuntime::default();
        let timer_restores = Cell::new(0);
        let stopped = Cell::new(false);

        finish_mode_switch_suspend_failure(
            &state,
            &mut candidate,
            DaemonError::reload("detach failed"),
            false,
            || {
                timer_restores.set(timer_restores.get() + 1);
                Ok(())
            },
            || stopped.set(true),
        );

        assert_eq!(candidate.shutdowns, 1);
        assert_eq!(timer_restores.get(), 1);
        assert!(stopped.get());
        assert!(state
            .fatal_error()
            .is_some_and(|error| error.contains("detach failed")));
    }

    #[test]
    fn failed_old_topology_restore_is_fatal_and_preserves_both_causes() {
        let state = test_state();
        let mut candidate = FakeRuntime::default();
        let stopped = Cell::new(false);

        let error = finish_mode_switch_rollback(
            &state,
            &mut candidate,
            DaemonError::reload("candidate collect failed"),
            Err(AdapterError::new(
                AdapterErrorKind::DetachFailed,
                "old restore failed",
            )),
            || Ok(()),
            || stopped.set(true),
        );

        assert!(error.to_string().contains("candidate collect failed"));
        assert!(error.to_string().contains("old restore failed"));
        assert!(stopped.get());
        assert!(state.fatal_error().is_some());
    }

    #[test]
    fn successful_old_topology_restore_returns_plain_reload_error() {
        let state = test_state();
        let mut candidate = FakeRuntime::default();
        let stopped = Cell::new(false);

        let error = finish_mode_switch_rollback(
            &state,
            &mut candidate,
            DaemonError::reload("candidate collect failed"),
            Ok(()),
            || Ok(()),
            || stopped.set(true),
        );

        assert!(error.to_string().contains("candidate collect failed"));
        assert_eq!(candidate.shutdowns, 1);
        assert!(!stopped.get());
        assert!(state.fatal_error().is_none());
    }

    #[test]
    fn cleanup_failures_are_fatal_and_preserve_both_causes() {
        for context in [
            "candidate cleanup",
            "postcommit old runtime cleanup",
            "BPF switch rollback",
            "multi-interface activation rollback",
        ] {
            let fatal = RefCell::new(None);
            let error = record_fatal_cleanup(context, "primary", "cleanup", &fatal);
            let message = error.to_string();
            assert!(message.contains(context));
            assert!(message.contains("primary"));
            assert!(message.contains("cleanup"));
            assert_eq!(
                fatal.borrow().as_deref(),
                Some(message.trim_start_matches("reload: "))
            );
        }
    }

    #[test]
    fn production_version_requires_package_version_and_release() {
        assert_eq!(version_from(Some("1.0.0"), Some("1")), "1.0.0-r1");
        assert_eq!(version_from(Some("1.0.0"), None), "unconfigured");
        assert_eq!(version_from(None, Some("1")), "unconfigured");
    }

    #[test]
    fn conntrack_generation_evidence_reports_real_cta_id_coverage() {
        let snapshot = CollectedSnapshot {
            clients: Vec::new(),
            sample_ms: 1,
            connection_details: Arc::default(),
            connection_counters: Arc::default(),
            counter_source: conntrack::NETLINK_COUNTER_SOURCE,
            stats: conntrack::CollectStats {
                netlink_read: true,
                entries_seen: 5,
                malformed_lines: 1,
                conntrack_ids_present: 3,
                conntrack_zones_present: 4,
                ..conntrack::CollectStats::default()
            },
        };

        let evidence = conntrack_generation_evidence(&snapshot);
        assert_eq!(
            evidence["counter_generation_key"],
            "ctnetlink_cta_id_with_zone_tuple_fallback"
        );
        assert_eq!(evidence["parsed_entries"], 4);
        assert_eq!(evidence["conntrack_ids_present"], 3);
        assert_eq!(evidence["conntrack_zones_present"], 4);
        assert_eq!(evidence["flow_id_coverage_pct"], 75.0);
    }

    #[test]
    fn periodic_collection_does_not_run_blocking_system_probe() {
        assert!(probe_due(0, 0, ProbeMethod::Status));
        assert!(!probe_due(29_999, 30_000, ProbeMethod::Status));
        assert!(probe_due(30_000, 30_000, ProbeMethod::Status));
        assert!(probe_due(1, u64::MAX, ProbeMethod::Reload));
    }

    #[test]
    fn lan_clock_replaces_a_batched_bridge_with_its_physical_members() {
        let masters = BTreeMap::from([
            ("lan1".into(), "br-lan".into()),
            ("lan2".into(), "br-lan".into()),
            ("wlan0".into(), "br-lan".into()),
        ]);

        let selected = independent_lan_boundaries(&["br-lan".into()], &masters).unwrap();

        assert_eq!(selected, vec!["lan1", "lan2", "wlan0"]);
    }

    #[test]
    fn lan_clock_deduplicates_overlapping_roots_and_sums_disjoint_boundaries() {
        let masters = BTreeMap::from([
            ("lan1".into(), "br-lan".into()),
            ("lan2".into(), "br-lan".into()),
        ]);
        let selected = independent_lan_boundaries(
            &["br-lan".into(), "lan2".into(), "br-guest".into()],
            &masters,
        )
        .unwrap();
        assert_eq!(selected, vec!["br-guest", "lan1", "lan2"]);

        let counters = BTreeMap::from([
            (
                "lan1".into(),
                InterfaceCounters {
                    rx_bytes: 100,
                    tx_bytes: 200,
                    rx_packets: 1,
                    tx_packets: 2,
                },
            ),
            (
                "lan2".into(),
                InterfaceCounters {
                    rx_bytes: 300,
                    tx_bytes: 400,
                    rx_packets: 3,
                    tx_packets: 4,
                },
            ),
            (
                "br-guest".into(),
                InterfaceCounters {
                    rx_bytes: 500,
                    tx_bytes: 600,
                    rx_packets: 5,
                    tx_packets: 6,
                },
            ),
        ]);
        assert_eq!(
            sum_interface_counters(&selected, &counters),
            Some(InterfaceCounters {
                rx_bytes: 900,
                tx_bytes: 1_200,
                rx_packets: 9,
                tx_packets: 12,
            })
        );
    }

    #[test]
    fn effective_collector_controls_only_the_nss_timer_floor() {
        assert_eq!(
            effective_collection_interval_ms(AccessEdgeMode::Off, None, 500),
            500
        );
        assert_eq!(
            effective_collection_interval_ms(AccessEdgeMode::Off, Some(RateCollector::Bpf), 500,),
            500
        );
        assert_eq!(
            effective_collection_interval_ms(
                AccessEdgeMode::Off,
                Some(RateCollector::NssEcmNode),
                500,
            ),
            2_000
        );
        assert_eq!(
            effective_collection_interval_ms(
                AccessEdgeMode::Off,
                Some(RateCollector::NssEcmBpf),
                1_000,
            ),
            2_000
        );
        assert_eq!(
            effective_collection_interval_ms(
                AccessEdgeMode::Off,
                Some(RateCollector::NssEcmBpf),
                3_000,
            ),
            3_000
        );
        assert_eq!(
            effective_collection_interval_ms(
                AccessEdgeMode::Shadow,
                Some(RateCollector::NssEcmBpf),
                3_000,
            ),
            1_000
        );
        assert_eq!(
            effective_collection_interval_ms(AccessEdgeMode::Active, Some(RateCollector::Bpf), 500,),
            1_000
        );
    }

    #[test]
    fn active_auto_never_executes_the_legacy_inference_rate_window() {
        assert!(active_access_edge_owns_display_rate(
            AccessEdgeMode::Active,
            RateCollectorMode::Auto
        ));
        assert!(!legacy_nss_rate_window_enabled(
            AccessEdgeMode::Active,
            RateCollectorMode::Auto
        ));
        assert_eq!(
            published_rate_collector_mode(true, "conntrack_netlink"),
            "access_edge"
        );
        assert_eq!(
            published_rate_collector_mode(false, "nss_ecm_bpf"),
            "nss_ecm_bpf"
        );

        for (edge, rate) in [
            (AccessEdgeMode::Off, RateCollectorMode::Auto),
            (AccessEdgeMode::Shadow, RateCollectorMode::Auto),
            (AccessEdgeMode::Active, RateCollectorMode::Bpf),
            (AccessEdgeMode::Active, RateCollectorMode::NssEcmNode),
            (AccessEdgeMode::Active, RateCollectorMode::NssEcmBpf),
        ] {
            assert!(!active_access_edge_owns_display_rate(edge, rate));
            assert!(legacy_nss_rate_window_enabled(edge, rate));
        }
    }

    #[test]
    fn direction_rate_meta_emits_only_summary_overrides() {
        let direction = PublishedRateDirection {
            bps: 1_000,
            source: ModelRateSource::EdgePort,
            coverage: ModelRateCoverage::Full,
            scope: ModelRateScope::AllFrames,
            byte_domain: Some(ModelByteDomain::L2NoFcs),
            sample_ms: Some(9_000),
            window_ms: Some(900),
            stale: false,
            mux_owner: true,
        };

        let exact = rate_direction_meta(direction, Some(9_000), Some(900), false);
        assert_eq!(exact.sample_ms, None);
        assert_eq!(exact.window_ms, None);
        assert_eq!(exact.stale, None);

        let override_meta = rate_direction_meta(direction, Some(10_000), None, true);
        assert_eq!(override_meta.sample_ms, Some(9_000));
        assert_eq!(override_meta.window_ms, Some(900));
        assert_eq!(override_meta.stale, Some(false));

        assert_eq!(
            compact_rate_sample_ms(Some(9_000), Some(10_000)),
            Some(10_000)
        );
        assert_eq!(compact_rate_sample_ms(Some(9_000), None), None);
        assert_eq!(compact_rate_sample_ms(None, Some(10_000)), None);
    }

    #[test]
    fn either_invalid_classifier_window_blocks_the_combined_epoch() {
        let valid = Some((1_000, 3_000));
        for invalid in [Some((3_000, 3_000)), Some((4_000, 3_000))] {
            assert_eq!(
                select_classifier_window(valid, invalid),
                ClassifierWindowSelection::Invalid
            );
            assert_eq!(
                select_classifier_window(invalid, valid),
                ClassifierWindowSelection::Invalid
            );
        }

        assert_eq!(
            select_classifier_window(valid, Some((1_020, 3_020))),
            ClassifierWindowSelection::Ready {
                start_ms: 1_000,
                end_ms: 3_000,
                aligned: true,
            }
        );
        assert_eq!(
            select_classifier_window(valid, Some((1_100, 3_100))),
            ClassifierWindowSelection::Ready {
                start_ms: 1_000,
                end_ms: 3_000,
                aligned: false,
            }
        );
    }

    #[test]
    fn classifier_map_loss_only_invalidates_classifier_owners() {
        for owner in [EdgeRateSource::EdgePort, EdgeRateSource::EdgeWifi] {
            assert!(!classifier_map_loss_invalidates_owner(
                Some(owner),
                false,
                false,
                true
            ));
        }
        for owner in [
            EdgeRateSource::EcmBpfFallback,
            EdgeRateSource::EcmNssLowerBound,
            EdgeRateSource::TcBpfLowerBound,
        ] {
            assert!(classifier_map_loss_invalidates_owner(
                Some(owner),
                false,
                false,
                true
            ));
            assert!(!classifier_map_loss_invalidates_owner(
                Some(owner),
                true,
                false,
                true
            ));
            assert!(!classifier_map_loss_invalidates_owner(
                Some(owner),
                false,
                true,
                true
            ));
        }
        assert!(!classifier_map_loss_invalidates_owner(
            None, true, false, true
        ));
        assert!(!classifier_map_loss_invalidates_owner(
            None, false, true, true
        ));
        assert!(classifier_map_loss_invalidates_owner(
            None, false, false, true
        ));
        assert!(!classifier_map_loss_invalidates_owner(
            None, false, false, false
        ));
    }

    #[test]
    fn mac_index_keeps_unique_entries_and_fails_closed_on_duplicates() {
        let values = [11, 22, 33];
        let mut index = MacIndex::default();
        index.insert(mac_lookup_key("AA:BB:CC:DD:EE:01"), &values[0]);
        index.insert(mac_lookup_key("aa:bb:cc:dd:ee:02"), &values[1]);
        assert_eq!(index.unique.get("aa:bb:cc:dd:ee:01"), Some(&&11));

        index.insert(mac_lookup_key("aa:bb:cc:dd:ee:01"), &values[2]);
        assert!(!index.unique.contains_key("aa:bb:cc:dd:ee:01"));
        assert!(index.ambiguous.contains("aa:bb:cc:dd:ee:01"));
        assert_eq!(index.unique.get("aa:bb:cc:dd:ee:02"), Some(&&22));
    }

    #[test]
    fn edge_segment_freshness_rejects_future_and_expired_samples() {
        assert!(edge_segment_fresh(10_000, 9_000, 1_000));
        assert!(!edge_segment_fresh(10_000, 10_001, 1_000));
        assert!(!edge_segment_fresh(10_000, 7_499, 1_000));
        assert!(edge_segment_fresh(10_000, 7_500, 1_000));
    }

    #[test]
    fn ecm_bpf_retained_snapshot_stays_current_between_classifier_reads() {
        let snapshot = coverage_snapshot(2_000, 4_000, &[]);
        let mut runtime = RuntimeHealth {
            now_ms: 5_000,
            ecm_bpf_map_read_ok: true,
            ecm_bpf_last_complete_snapshot_ms: Some(4_000),
            ecm_bpf_freshness_ms: 6_000,
            ..RuntimeHealth::default()
        };

        assert!(ecm_bpf_snapshot_current(Some(&snapshot), &runtime));

        // The map is intentionally not read on this response tick. The last
        // complete snapshot is still within its own cadence-derived window.
        runtime.ecm_bpf_map_read_ok = false;
        assert!(ecm_bpf_snapshot_current(Some(&snapshot), &runtime));

        runtime.now_ms = 10_001;
        assert!(!ecm_bpf_snapshot_current(Some(&snapshot), &runtime));

        let mut truncated = snapshot;
        truncated.truncated = true;
        runtime.now_ms = 5_000;
        assert!(!ecm_bpf_snapshot_current(Some(&truncated), &runtime));
    }

    #[test]
    fn hard_edge_failure_removes_only_edge_candidates_before_fallback() {
        let base = RateCandidate {
            source: EdgeRateSource::EdgePort,
            bps: 8_000,
            coverage: crate::platform::access_edge::Coverage::Partial,
            scope: EdgeTrafficScope::AllFrames,
            byte_domain: EdgeByteDomain::L2NoFcs,
            sample_ms: 2_000,
            window_ms: 1_000,
            cadence_ms: 1_000,
            attachment_generation: 7,
            fresh: true,
        };
        let mut candidates = vec![
            base,
            RateCandidate {
                source: EdgeRateSource::EdgeWifi,
                ..base
            },
            RateCandidate {
                source: EdgeRateSource::EcmBpfFallback,
                ..base
            },
        ];

        remove_failed_edge_candidates(&mut candidates, Some(MuxFailure::CounterReset));

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].source, EdgeRateSource::EcmBpfFallback);
    }

    #[test]
    fn global_evidence_separates_fresh_edge_owner_from_unprovable_frame_scope() {
        use crate::platform::access_edge::{
            AccessEdgeSnapshot, AttachmentKey, AttachmentPoint, Coverage as EdgeCoverage,
            EdgeDirectionObservation, TrafficScope,
        };

        let mac_bytes = [0x02, 1, 2, 3, 4, 5];
        let mac = format_edge_mac(mac_bytes);
        let attachment = EdgeAttachment {
            key: AttachmentKey {
                mac: mac_bytes,
                bridge_ifindex: Some(10),
                vlan_id: None,
            },
            point: AttachmentPoint {
                kind: EdgeAttachmentKind::Ethernet,
                ifindex: 6,
                ifname: "lan2".into(),
                bridge_ifindex: Some(10),
                vlan_id: None,
            },
            trust: EdgeAttachmentTrust::ObservedExclusive,
            generation: 17,
            source_generation: 0,
            stable_observations: 2,
            ambiguous: false,
        };
        let direction = EdgeDirectionObservation {
            segment: None,
            coverage: EdgeCoverage::Full,
            scope: TrafficScope::AllFrames,
            failure: None,
            reason_codes: Vec::new(),
        };
        let snapshot = AccessEdgeSnapshot {
            sample_ms: 2_000,
            clients: vec![EdgeClientObservation {
                attachment: attachment.clone(),
                tx: direction.clone(),
                rx: direction,
            }],
            topology_complete: true,
            fdb_source: Some("rtnetlink_af_bridge"),
            reason_codes: Vec::new(),
        };
        let rate_meta = ClientRateMeta {
            version: 1,
            scope: ModelRateScope::AllFrames,
            tx: RateDirectionMeta {
                source: ModelRateSource::EdgePort,
                coverage: ModelRateCoverage::Full,
                byte_domain: Some(ModelByteDomain::L2NoFcs),
                sample_ms: None,
                window_ms: None,
                stale: None,
            },
            rx: RateDirectionMeta {
                source: ModelRateSource::EdgePort,
                coverage: ModelRateCoverage::Full,
                byte_domain: Some(ModelByteDomain::L2NoFcs),
                sample_ms: None,
                window_ms: None,
                stale: None,
            },
            attachment: Some(model_attachment(&attachment)),
            generation: 17,
            window_ms: Some(1_000),
            sample_ms: Some(2_000),
            stale: false,
            reason_codes: Vec::new(),
            classification: None,
        };
        let client = Client {
            mac: mac.clone(),
            identity_key: format!("{mac}@lan"),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: Vec::new(),
            hostname: None,
            rx_bps: 1,
            tx_bps: 1,
            last_seen: 2_000,
            sample_ms: Some(2_000),
            rx_bytes: None,
            tx_bytes: None,
            collector_mode: "nss_ecm_bpf".into(),
            confidence: Confidence::High,
            warnings: Vec::new(),
            tcp_conns: None,
            udp_conns: None,
            udp_dns_conns: None,
            udp_other_conns: None,
            rate_meta: Some(rate_meta),
        };
        let clients = ClientsResponse {
            clients: vec![client.clone()],
            evidence: None,
            tcp_conns_total: None,
            udp_conns_total: None,
            udp_dns_conns_total: None,
            udp_other_conns_total: None,
            conntrack_entries_seen: None,
            conntrack_entries_matched: None,
            conntrack_parse_errors: None,
            conn_source: None,
            nss_ecm_nodes_seen: None,
            nss_ecm_nodes_matched: None,
            nss_ecm_node_parse_errors: None,
            conn_collector_mode: None,
            conn_semantics: None,
        };

        // Even an inconsistent caller cannot promote Ethernet all-frame
        // evidence to Full by supplying forged per-direction coverage.
        let forged_full = access_edge_global_evidence(&snapshot, &clients, AccessEdgeMode::Active);
        assert_eq!(forged_full["coverage"], "partial");
        assert_eq!(forged_full["published_attachments"], 1);
        let forged_reasons = forged_full["reason_codes"]
            .as_array()
            .expect("reason codes are an array");
        assert!(forged_reasons
            .iter()
            .any(|value| value == "ethernet_full_scope_unproven"));
        assert!(!forged_reasons
            .iter()
            .any(|value| value == "fresh_edge_owner_missing"));

        let mut fallback_clients = clients.clone();
        let fallback_meta = fallback_clients.clients[0]
            .rate_meta
            .as_mut()
            .expect("test client has rate metadata");
        fallback_meta.tx.source = ModelRateSource::EcmBpfFallback;
        fallback_meta.rx.source = ModelRateSource::EcmBpfFallback;
        let fallback =
            access_edge_global_evidence(&snapshot, &fallback_clients, AccessEdgeMode::Active);
        let fallback_reasons = fallback["reason_codes"]
            .as_array()
            .expect("reason codes are an array");
        assert!(fallback_reasons
            .iter()
            .any(|value| value == "fresh_edge_owner_missing"));
        assert!(!fallback_reasons
            .iter()
            .any(|value| value == "ethernet_full_scope_unproven"));

        let mut wifi_snapshot = snapshot;
        wifi_snapshot.clients[0].attachment.point.kind = EdgeAttachmentKind::Wifi;
        wifi_snapshot.clients[0].attachment.point.ifname = "phy1-ap0".into();
        wifi_snapshot.clients[0].attachment.trust = EdgeAttachmentTrust::AssociatedStation;
        let mut wifi_clients = clients;
        let wifi_meta = wifi_clients.clients[0]
            .rate_meta
            .as_mut()
            .expect("test client has rate metadata");
        wifi_meta.tx.source = ModelRateSource::EdgeWifi;
        wifi_meta.rx.source = ModelRateSource::EdgeWifi;
        wifi_meta.scope = ModelRateScope::Unicast;
        wifi_meta.attachment = Some(model_attachment(&wifi_snapshot.clients[0].attachment));

        let wifi =
            access_edge_global_evidence(&wifi_snapshot, &wifi_clients, AccessEdgeMode::Active);
        assert_eq!(wifi["coverage"], "partial");
        assert!(wifi["reason_codes"].as_array().is_some_and(|values| values
            .iter()
            .any(|value| value == "wifi_group_traffic_unattributed")));
    }

    #[test]
    fn classifier_map_evidence_separates_historical_pressure_from_current_loss() {
        let recovered = classifier_map_metrics(10, 100, true, Some(false), true, true);
        assert_eq!(recovered["truncated"], true);
        assert_eq!(recovered["current_truncated"], false);
        assert_eq!(recovered["map_loss"], false);

        let current = classifier_map_metrics(100, 100, true, Some(true), true, true);
        assert_eq!(current["pressure"], true);
        assert_eq!(current["map_loss"], true);

        let failed = classifier_map_metrics(0, 100, false, None, true, false);
        assert_eq!(failed["map_loss"], true);
    }

    #[test]
    fn absent_classifier_delta_cannot_become_a_zero_rate_owner() {
        let ecm = coverage_snapshot(1_000, 3_000, &[]);
        let slow = tc_coverage_snapshot(1_000, 3_000, &[]);
        let runtime = RuntimeHealth {
            now_ms: 3_000,
            ecm_bpf_map_read_ok: true,
            bpf_map_read_ok: true,
            ..RuntimeHealth::default()
        };

        let candidates = classifier_rate_candidates(
            "02:00:00:00:00:01@lan",
            EdgeDirection::Tx,
            0,
            Some(&ecm),
            Some(3_010),
            Some(&slow),
            Some(3_020),
            &runtime,
        );

        assert!(candidates.is_empty());
    }

    #[test]
    fn aligned_classifier_sources_normalize_and_fuse_as_one_fallback() {
        let identity_key = "02:00:00:00:00:01@lan";
        let ecm = coverage_snapshot(
            1_000,
            3_000,
            &[(
                identity_key,
                TrafficCounters {
                    tx_bytes: 1_000,
                    tx_packets: 10,
                    ..TrafficCounters::default()
                },
            )],
        );
        let slow = tc_coverage_snapshot(
            1_000,
            3_000,
            &[(
                identity_key,
                TrafficCounters {
                    tx_bytes: 500,
                    tx_packets: 5,
                    ..TrafficCounters::default()
                },
            )],
        );
        let runtime = RuntimeHealth {
            now_ms: 3_000,
            ecm_bpf_map_read_ok: true,
            bpf_map_read_ok: true,
            ..RuntimeHealth::default()
        };

        let candidates = classifier_rate_candidates(
            identity_key,
            EdgeDirection::Tx,
            7,
            Some(&ecm),
            Some(3_010),
            Some(&slow),
            Some(3_020),
            &runtime,
        );

        assert_eq!(candidates.len(), 3);
        assert!(candidates
            .iter()
            .all(|candidate| candidate.byte_domain == EdgeByteDomain::L2WithFcs));
        let fallback = candidates
            .iter()
            .find(|candidate| candidate.source == EdgeRateSource::EcmBpfFallback)
            .unwrap();
        // ECM: 1000 + 10 * (14 + 4), TC: 500 + 5 * 4.
        assert_eq!(fallback.bps, 6_800);
        assert_eq!(fallback.scope, EdgeTrafficScope::RoutedObserved);
    }

    #[test]
    fn absolute_collection_slots_skip_missed_deadlines_without_catch_up() {
        assert_eq!(
            next_absolute_collection_slot(0, 10_250, 1_000),
            (11_250, 1_000)
        );
        assert_eq!(
            next_absolute_collection_slot(11_250, 11_400, 1_000),
            (12_250, 850)
        );
        assert_eq!(
            next_absolute_collection_slot(12_250, 15_900, 1_000),
            (16_250, 350)
        );
        assert_eq!(
            next_absolute_collection_slot(16_250, 16_000, 1_000),
            (16_250, 250)
        );
    }

    #[test]
    fn classifier_deadline_reads_once_and_skips_expired_slots() {
        let mut deadline = 0;
        assert!(periodic_deadline_due(&mut deadline, 10_000, 2_000));
        assert_eq!(deadline, 12_000);
        assert!(!periodic_deadline_due(&mut deadline, 11_999, 2_000));
        assert!(periodic_deadline_due(&mut deadline, 12_050, 2_000));
        assert_eq!(deadline, 14_000);
        assert!(periodic_deadline_due(&mut deadline, 19_100, 2_000));
        assert_eq!(deadline, 20_000);
        assert!(!periodic_deadline_due(&mut deadline, 19_101, 2_000));
    }

    #[test]
    fn nss_snapshot_freshness_uses_the_effective_two_second_cadence() {
        assert_eq!(nss_snapshot_freshness_ms(500), 6_000);
        assert_eq!(nss_snapshot_freshness_ms(1_000), 6_000);
        assert_eq!(nss_snapshot_freshness_ms(2_000), 6_000);
        assert_eq!(nss_snapshot_freshness_ms(3_000), 9_000);
    }

    #[test]
    fn nss_rate_coverage_publishes_each_current_reportable_direction() {
        let coverage = nss_rate_coverage_values(2_000, 18_000, 34_000, 12_000, 89_000);

        assert_eq!(coverage.quality, "pending");
        assert_eq!(coverage.samples, 1);
        assert_eq!(coverage.window_ms, Some(2_000));
        assert_eq!(coverage.tx_pct, None);
        assert_eq!(coverage.rx_pct, Some(38));
        assert_eq!(coverage.denom_rx_bytes, Some(3_000));
        assert_eq!(coverage.denom_tx_bytes, Some(22_250));
        assert_eq!(coverage.numer_tx_bytes, Some(4_500));
        assert_eq!(coverage.numer_rx_bytes, Some(8_500));
    }

    #[test]
    fn nss_rate_coverage_uses_the_current_interface_window_without_clamping() {
        let coverage =
            nss_rate_coverage_values(2_000, 980_000_000, 970_000_000, 1_000_000_000, 990_000_000);

        assert_eq!(coverage.quality, "ok");
        assert_eq!(coverage.tx_pct, Some(98));
        assert_eq!(coverage.rx_pct, Some(97));

        let idle = nss_rate_coverage_values(2_000, 0, 0, 0, 0);
        assert_eq!(idle.quality, "idle");
        assert_eq!(idle.tx_pct, None);
        assert_eq!(idle.rx_pct, None);
    }

    #[test]
    fn ecm_bpf_high_rate_floor_uses_the_discovered_client_interface() {
        let identity_key = "02:00:00:00:00:01@lan";
        let mut snapshot = coverage_snapshot(1_000, 3_000, &[]);
        snapshot.clients.push(EcmBpfClientSample {
            mac: "02:00:00:00:00:01".into(),
            identity_key: identity_key.into(),
            zone: "lan".into(),
            interface: "bridge-dynamic".into(),
            ips: vec!["192.0.2.1".into()],
            tx_bytes: 0,
            rx_bytes: 0,
            tx_bps: 0,
            rx_bps: 0,
            sample_ms: 3_000,
            last_seen_ms: 3_000,
        });
        let mut clients = ecm_bpf_clients_response(
            Some(&snapshot),
            None,
            false,
            3_000,
            None,
            &IdentityTable::new(4),
            ProbeConfidence::High,
        );
        let mut interfaces = InterfacesResponse {
            interfaces: vec![
                Interface {
                    name: "bridge-dynamic".into(),
                    role: InterfaceRole::Lan,
                    status: InterfaceStatus::Available,
                    rx_bytes: Some(100),
                    tx_bytes: Some(200),
                    rx_bps: Some(0),
                    tx_bps: Some(0),
                    delta_ms: Some(2_000),
                    sample_ms: Some(3_000),
                    source: Some("kernel counters".into()),
                    coverage: None,
                    evidence: None,
                },
                Interface {
                    name: "member-dynamic".into(),
                    role: InterfaceRole::Observe,
                    status: InterfaceStatus::Available,
                    rx_bytes: Some(300),
                    tx_bytes: Some(400),
                    rx_bps: Some(0),
                    tx_bps: Some(0),
                    delta_ms: Some(2_000),
                    sample_ms: Some(3_000),
                    source: Some("kernel counters".into()),
                    coverage: None,
                    evidence: None,
                },
            ],
            monotonic_ms: Some(3_000),
            note: None,
            evidence: None,
        };
        let batch = EcmBpfRateBatch {
            start_ms: 3_000,
            end_ms: 5_000,
            clients: BTreeMap::from([(
                identity_key.into(),
                RateWindowValue {
                    tx_bps: 100_000_000,
                    rx_bps: 50_000_000,
                },
            )]),
            interfaces: BTreeMap::from([
                (
                    "bridge-dynamic".into(),
                    RateWindowValue {
                        rx_bps: 10_000_000,
                        tx_bps: 20_000_000,
                    },
                ),
                (
                    "member-dynamic".into(),
                    RateWindowValue {
                        rx_bps: 30_000_000,
                        tx_bps: 40_000_000,
                    },
                ),
            ]),
            raw_aligned: false,
            fallback_event_gap_filled: true,
            previous_direction_gap_filled: false,
            previous_high_direction_gap_filled: false,
            fallback_lan_reconciled: false,
            low_rate: false,
            fresh: true,
            held_age_ms: None,
        };

        apply_ecm_bpf_rate_batch(&mut clients, &mut interfaces, &batch);

        assert_eq!(clients.clients[0].tx_bps, 100_000_000);
        assert_eq!(clients.clients[0].rx_bps, 50_000_000);
        assert_eq!(clients.clients[0].sample_ms, Some(5_000));
        let bridge = &interfaces.interfaces[0];
        assert_eq!(bridge.rx_bps, Some(100_000_000));
        assert_eq!(bridge.tx_bps, Some(50_000_000));
        assert!(bridge
            .source
            .as_deref()
            .is_some_and(|source| source.contains("ECM+BPF high-rate client floor")));
        let member = &interfaces.interfaces[1];
        assert_eq!(member.rx_bps, Some(30_000_000));
        assert_eq!(member.tx_bps, Some(40_000_000));
        assert_eq!(interfaces.monotonic_ms, Some(5_000));
    }

    #[test]
    fn ecm_bpf_computes_one_rate_from_aligned_raw_deltas() {
        let ecm = EcmBpfClientSample {
            mac: "02:00:00:00:00:01".into(),
            identity_key: "02:00:00:00:00:01@lan".into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.1".into()],
            tx_bytes: 10_000,
            rx_bytes: 20_000,
            tx_bps: 100,
            rx_bps: 200,
            sample_ms: 2_000,
            last_seen_ms: 1_900,
        };
        let tc = NssTcClientSample {
            mac: ecm.mac.clone(),
            identity_key: ecm.identity_key.clone(),
            zone: ecm.zone.clone(),
            interface: ecm.interface.clone(),
            ips: ecm.ips.clone(),
            tx_bytes: 3_000,
            rx_bytes: 4_000,
            tx_bps: 150,
            rx_bps: 50,
            last_seen_ms: 2_000,
        };
        let tc_only = NssTcClientSample {
            mac: "02:00:00:00:00:02".into(),
            identity_key: "02:00:00:00:00:02@lan".into(),
            tx_bps: 300,
            rx_bps: 400,
            ..tc.clone()
        };

        let mut ecm_snapshot = coverage_snapshot(
            1_000,
            2_000,
            &[(
                &ecm.identity_key,
                TrafficCounters {
                    tx_bytes: 10_000,
                    rx_bytes: 20_000,
                    tx_packets: 100,
                    rx_packets: 200,
                },
            )],
        );
        ecm_snapshot.clients.push(ecm);
        let mut tc_snapshot = tc_coverage_snapshot(
            1_000,
            2_000,
            &[
                (
                    &tc.identity_key,
                    TrafficCounters {
                        tx_bytes: 3_000,
                        rx_bytes: 4_000,
                        tx_packets: 30,
                        rx_packets: 40,
                    },
                ),
                (
                    &tc_only.identity_key,
                    TrafficCounters {
                        tx_bytes: 5_000,
                        rx_bytes: 6_000,
                        tx_packets: 50,
                        rx_packets: 60,
                    },
                ),
            ],
        );
        tc_snapshot.clients = vec![tc, tc_only];

        let response = ecm_bpf_clients_response(
            Some(&ecm_snapshot),
            Some(&tc_snapshot),
            true,
            2_000,
            None,
            &IdentityTable::new(4),
            ProbeConfidence::High,
        );

        let merged = &response.clients[0];
        assert_eq!((merged.tx_bps, merged.rx_bps), (108_160, 199_680));
        assert_eq!(
            (merged.tx_bytes, merged.rx_bytes),
            (Some(10_000), Some(20_000))
        );
        assert_eq!(merged.sample_ms, Some(2_000));
        assert!(merged.warnings.is_empty());

        let leading = &response.clients[1];
        assert_eq!((leading.tx_bps, leading.rx_bps), (41_600, 49_920));
        assert!(leading.warnings.is_empty());
    }

    fn coverage_snapshot(
        start_ms: u64,
        end_ms: u64,
        values: &[(&str, TrafficCounters)],
    ) -> EcmBpfSnapshot {
        let coverage_deltas = values
            .iter()
            .map(|(identity, counters)| ((*identity).to_owned(), *counters))
            .collect::<BTreeMap<_, _>>();
        let coverage_delta = coverage_deltas.values().copied().fold(
            TrafficCounters::default(),
            |mut total, value| {
                add_traffic_counters(&mut total, value);
                total
            },
        );
        EcmBpfSnapshot {
            coverage_delta,
            coverage_deltas,
            coverage_start_ms: Some(start_ms),
            coverage_end_ms: end_ms,
            coverage_ready: true,
            sample_ms: end_ms,
            ..EcmBpfSnapshot::default()
        }
    }

    fn tc_coverage_snapshot(
        start_ms: u64,
        end_ms: u64,
        values: &[(&str, TrafficCounters)],
    ) -> NssTcSnapshot {
        NssTcSnapshot {
            coverage_deltas: values
                .iter()
                .map(|(identity, counters)| ((*identity).to_owned(), *counters))
                .collect(),
            coverage_start_ms: Some(start_ms),
            coverage_end_ms: end_ms,
            coverage_ready: true,
            map_complete: true,
            ..NssTcSnapshot::default()
        }
    }

    #[test]
    fn ecm_bpf_misaligned_windows_choose_one_source_per_direction_without_sum() {
        let identity_key = "02:00:00:00:00:01@lan";
        let ecm_client = EcmBpfClientSample {
            mac: "02:00:00:00:00:01".into(),
            identity_key: identity_key.into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.1".into()],
            tx_bytes: 10_000,
            rx_bytes: 20_000,
            tx_bps: 100,
            rx_bps: 200,
            sample_ms: 3_000,
            last_seen_ms: 2_900,
        };
        let tc_client = NssTcClientSample {
            mac: ecm_client.mac.clone(),
            identity_key: identity_key.into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.1".into()],
            tx_bytes: 3_000,
            rx_bytes: 4_000,
            tx_bps: 150,
            rx_bps: 50,
            last_seen_ms: 5_900,
        };
        let mut ecm =
            coverage_snapshot(1_000, 3_000, &[(identity_key, TrafficCounters::default())]);
        ecm.clients.push(ecm_client);
        let mut tc =
            tc_coverage_snapshot(4_000, 6_000, &[(identity_key, TrafficCounters::default())]);
        tc.clients.push(tc_client);

        let response = ecm_bpf_clients_response(
            Some(&ecm),
            Some(&tc),
            true,
            6_000,
            None,
            &IdentityTable::new(4),
            ProbeConfidence::High,
        );

        let client = &response.clients[0];
        assert_eq!((client.tx_bps, client.rx_bps), (150, 200));
        assert_eq!(
            (client.tx_bytes, client.rx_bytes),
            (Some(10_000), Some(20_000))
        );
        assert_eq!(client.sample_ms, Some(6_000));
    }

    #[test]
    fn ecm_bpf_coverage_adds_source_disjoint_hardware_and_slow_path_deltas() {
        let ecm = coverage_snapshot(
            1_000,
            3_000,
            &[(
                "client@lan",
                TrafficCounters {
                    tx_bytes: 10_000,
                    rx_bytes: 20_000,
                    tx_packets: 100,
                    rx_packets: 200,
                },
            )],
        );
        let tc = tc_coverage_snapshot(
            1_010,
            3_010,
            &[(
                "client@lan",
                TrafficCounters {
                    tx_bytes: 9_000,
                    rx_bytes: 22_000,
                    tx_packets: 90,
                    rx_packets: 220,
                },
            )],
        );

        let merged = merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), true);

        assert_eq!(
            merged.merged,
            TrafficCounters {
                tx_bytes: 19_000,
                rx_bytes: 42_000,
                tx_packets: 190,
                rx_packets: 420,
            }
        );
        assert!(merged.tc_contributed);
    }

    #[test]
    fn ecm_bpf_coverage_includes_tc_only_low_traffic_clients() {
        let ecm = coverage_snapshot(
            1_000,
            3_000,
            &[(
                "routed@lan",
                TrafficCounters {
                    tx_bytes: 1_000,
                    tx_packets: 10,
                    ..TrafficCounters::default()
                },
            )],
        );
        let tc = tc_coverage_snapshot(
            1_000,
            3_000,
            &[
                (
                    "routed@lan",
                    TrafficCounters {
                        tx_bytes: 900,
                        tx_packets: 9,
                        ..TrafficCounters::default()
                    },
                ),
                (
                    "slow-path@lan",
                    TrafficCounters {
                        rx_bytes: 2_000,
                        rx_packets: 20,
                        ..TrafficCounters::default()
                    },
                ),
            ],
        );

        let merged = merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), true);

        assert_eq!(merged.merged.tx_bytes, 1_900);
        assert_eq!(merged.merged.tx_packets, 19);
        assert_eq!(merged.merged.rx_bytes, 2_000);
        assert_eq!(merged.merged.rx_packets, 20);
        assert!(merged.tc_contributed);
    }

    #[test]
    fn ecm_bpf_coverage_rejects_stale_or_misaligned_tc_windows() {
        let ecm = coverage_snapshot(
            2_000,
            4_000,
            &[(
                "client@lan",
                TrafficCounters {
                    tx_bytes: 1_000,
                    tx_packets: 10,
                    ..TrafficCounters::default()
                },
            )],
        );
        let tc = tc_coverage_snapshot(
            1_000,
            3_000,
            &[(
                "client@lan",
                TrafficCounters {
                    tx_bytes: 50_000,
                    tx_packets: 500,
                    ..TrafficCounters::default()
                },
            )],
        );

        for merged in [
            merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), false),
            merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), true),
        ] {
            assert_eq!(merged.merged, ecm.coverage_delta);
            assert_eq!(merged.source, "ecm_nss_hardware_delta");
            assert!(!merged.tc_contributed);
        }
    }

    #[test]
    fn pending_coverage_response_uses_the_last_aligned_percentage_without_a_current_direction() {
        let response = coverage_response(&CoverageWindow {
            quality: WindowQuality::Pending,
            reason: "lan_coverage_pending",
            start_ms: 1_000,
            end_ms: 3_000,
            client_raw: TrafficCounters::default(),
            client_normalized: TrafficCounters::default(),
            lan_raw: TrafficCounters::default(),
            lan_normalized: TrafficCounters::default(),
            tx_pct: None,
            rx_pct: None,
            retained_tx_pct: Some(91),
            retained_rx_pct: Some(97),
            aligned: false,
        });

        assert_eq!(response.quality, "pending");
        assert_eq!(response.samples, 1);
        assert_eq!(response.tx_pct, Some(91));
        assert_eq!(response.rx_pct, Some(97));

        let timed_out = coverage_response(&CoverageWindow {
            quality: WindowQuality::CounterSkew,
            reason: "lan_coverage_timeout",
            start_ms: 3_000,
            end_ms: 9_000,
            client_raw: TrafficCounters::default(),
            client_normalized: TrafficCounters::default(),
            lan_raw: TrafficCounters::default(),
            lan_normalized: TrafficCounters::default(),
            tx_pct: None,
            rx_pct: None,
            retained_tx_pct: Some(91),
            retained_rx_pct: Some(97),
            aligned: false,
        });
        assert_eq!(timed_out.quality, "pending");
        assert_eq!(timed_out.tx_pct, Some(91));
        assert_eq!(timed_out.rx_pct, Some(97));

        let low_traffic_wait = coverage_response(&CoverageWindow {
            quality: WindowQuality::LowTraffic,
            reason: "low_traffic_coverage_rebaseline",
            start_ms: 9_000,
            end_ms: 15_000,
            client_raw: TrafficCounters::default(),
            client_normalized: TrafficCounters::default(),
            lan_raw: TrafficCounters::default(),
            lan_normalized: TrafficCounters::default(),
            tx_pct: None,
            rx_pct: None,
            retained_tx_pct: Some(91),
            retained_rx_pct: Some(97),
            aligned: false,
        });
        assert_eq!(low_traffic_wait.quality, "pending");
        assert_eq!(low_traffic_wait.tx_pct, Some(91));
        assert_eq!(low_traffic_wait.rx_pct, Some(97));
    }

    #[test]
    fn pending_coverage_response_prefers_the_current_reportable_direction() {
        let response = coverage_response(&CoverageWindow {
            quality: WindowQuality::Pending,
            reason: "lan_coverage_pending",
            start_ms: 1_000,
            end_ms: 3_000,
            client_raw: TrafficCounters::default(),
            client_normalized: TrafficCounters::default(),
            lan_raw: TrafficCounters::default(),
            lan_normalized: TrafficCounters::default(),
            tx_pct: Some(73),
            rx_pct: None,
            retained_tx_pct: Some(91),
            retained_rx_pct: Some(97),
            aligned: false,
        });

        assert_eq!(response.quality, "pending");
        assert_eq!(response.samples, 1);
        assert_eq!(response.tx_pct, Some(73));
        assert_eq!(response.rx_pct, None);
    }

    #[test]
    fn nss_bpf_handoff_rewarms_without_republishing_the_old_owner_interval() {
        use crate::platform::nss::ecm_node::{NodeCounters, NodeSnapshot, ParseStats};

        let snapshot = |sample_ms, tx_bytes, rx_bytes| NodeSnapshot {
            sample_ms,
            nodes: vec![NodeCounters {
                identity_key: "02:00:00:00:20:11@lan".into(),
                generation: 7,
                counters: TrafficCounters {
                    tx_bytes,
                    rx_bytes,
                    tx_packets: tx_bytes / 1_000,
                    rx_packets: rx_bytes / 1_000,
                },
            }],
            stats: ParseStats::default(),
        };
        let lan = |sample_ms, rx_bytes, tx_bytes| LanClock {
            interface: "br-lan".into(),
            sample_ms,
            counters: TrafficCounters {
                tx_bytes,
                rx_bytes,
                tx_packets: tx_bytes / 1_000,
                rx_packets: rx_bytes / 1_000,
            },
        };
        let mut owner = None;
        let mut nss = NssRuntime::default();

        nss.transition_rate_owner(&mut owner, RateCollector::NssEcmNode);
        assert_eq!(
            nss.node_windows
                .update(&snapshot(1_000, 10_000, 20_000), lan(1_000, 10_000, 20_000))
                .quality,
            WindowQuality::Warmup
        );
        nss.transition_rate_owner(&mut owner, RateCollector::Bpf);

        nss.transition_rate_owner(&mut owner, RateCollector::NssEcmNode);
        let reentry = nss.node_windows.update(
            &snapshot(5_000, 4_010_000, 8_020_000),
            lan(5_000, 4_010_000, 8_020_000),
        );

        assert_eq!(reentry.quality, WindowQuality::Warmup);
        assert!(reentry
            .clients
            .iter()
            .all(|client| client.tx_bps == 0 && client.rx_bps == 0));
        assert_eq!(reentry.coverage.tx_pct, None);
        assert_eq!(reentry.coverage.rx_pct, None);
    }
}
