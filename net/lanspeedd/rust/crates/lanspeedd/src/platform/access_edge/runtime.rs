use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::interfaces::InterfaceCounterSnapshot;

use super::{
    classification::{
        ClassificationBook, ClassificationEpoch, ClassificationResult, ObservedDelta,
        CLASSIFIER_READ_END_SKEW_MS,
    },
    fdb::{BridgeFdbEventMonitor, BridgeFdbProvider, FdbSource, SystemBridgeFdbProvider},
    mux::{DirectionRateMux, MuxFailure, MuxResult, RateCandidate},
    nl80211::{StationCounterSnapshot, SystemNl80211StationProvider, WifiStationCounterProvider},
    rate::{CounterRateBook, CounterUpdate, CumulativeCounterSample, LinkCounters},
    topology::{
        observations_from_fdb, observations_from_stations, Attachment, AttachmentKey,
        AttachmentKind, AttachmentObservation, AttachmentTrust, TopologyTable,
    },
    types::{ByteDomain, CounterSegment, Coverage, Direction, RateSource, TrafficScope},
};

pub const FDB_FULL_SYNC_MS: u64 = 30_000;
const FDB_INITIAL_STABLE_SYNC_MS: u64 = 1_000;
const EDGE_HISTORY_SEGMENTS: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeIdentityHint {
    pub mac: String,
    pub logical_interface: String,
    pub wireless: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeDirectionObservation {
    pub segment: Option<CounterSegment>,
    pub coverage: Coverage,
    pub scope: TrafficScope,
    pub failure: Option<MuxFailure>,
    pub reason_codes: Vec<String>,
}

impl EdgeDirectionObservation {
    fn unavailable(reason: &'static str) -> Self {
        Self {
            segment: None,
            coverage: Coverage::Unavailable,
            scope: TrafficScope::None,
            failure: None,
            reason_codes: vec![reason.to_owned()],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeClientObservation {
    pub attachment: Attachment,
    pub tx: EdgeDirectionObservation,
    pub rx: EdgeDirectionObservation,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessEdgeSnapshot {
    pub sample_ms: u64,
    pub clients: Vec<EdgeClientObservation>,
    pub topology_complete: bool,
    pub fdb_source: Option<&'static str>,
    pub reason_codes: Vec<String>,
}

#[derive(Clone, Debug)]
struct CachedBridge {
    observations: Vec<AttachmentObservation>,
    source: FdbSource,
    complete: bool,
}

#[derive(Clone, Debug)]
pub struct AccessEdgeCheckpoint {
    wifi_provider: SystemNl80211StationProvider,
    topology: TopologyTable,
    cached_bridges: BTreeMap<String, CachedBridge>,
    bridge_names: BTreeMap<u32, String>,
    latest_wifi: Option<StationCounterSnapshot>,
    wifi_fresh: bool,
    topology_complete: bool,
    next_fdb_sync_ms: u64,
    initial_syncs: u8,
    epoch_id: u64,
    rates: CounterRateBook<(AttachmentKey, RateSource, Direction)>,
    muxes: BTreeMap<(String, Direction), DirectionRateMux>,
    histories: BTreeMap<(AttachmentKey, Direction), VecDeque<CounterSegment>>,
    classification: ClassificationBook,
    latest: AccessEdgeSnapshot,
    event_monitor_failed: bool,
}

#[derive(Debug)]
pub struct AccessEdgeRuntime {
    fdb_provider: SystemBridgeFdbProvider,
    event_monitor: Option<BridgeFdbEventMonitor>,
    wifi_provider: SystemNl80211StationProvider,
    topology: TopologyTable,
    cached_bridges: BTreeMap<String, CachedBridge>,
    bridge_names: BTreeMap<u32, String>,
    latest_wifi: Option<StationCounterSnapshot>,
    wifi_fresh: bool,
    topology_complete: bool,
    next_fdb_sync_ms: u64,
    initial_syncs: u8,
    epoch_id: u64,
    rates: CounterRateBook<(AttachmentKey, RateSource, Direction)>,
    muxes: BTreeMap<(String, Direction), DirectionRateMux>,
    histories: BTreeMap<(AttachmentKey, Direction), VecDeque<CounterSegment>>,
    classification: ClassificationBook,
    latest: AccessEdgeSnapshot,
    event_monitor_failed: bool,
}

impl AccessEdgeRuntime {
    pub fn new(max_clients: usize) -> Self {
        let event_monitor = BridgeFdbEventMonitor::open().ok();
        let event_monitor_failed = event_monitor.is_none();
        Self {
            fdb_provider: SystemBridgeFdbProvider,
            event_monitor,
            wifi_provider: SystemNl80211StationProvider::new(max_clients.max(1)),
            topology: TopologyTable::new(),
            cached_bridges: BTreeMap::new(),
            bridge_names: BTreeMap::new(),
            latest_wifi: None,
            wifi_fresh: false,
            topology_complete: false,
            next_fdb_sync_ms: 0,
            initial_syncs: 0,
            epoch_id: 0,
            rates: CounterRateBook::new(),
            muxes: BTreeMap::new(),
            histories: BTreeMap::new(),
            classification: ClassificationBook::default(),
            latest: AccessEdgeSnapshot::default(),
            event_monitor_failed,
        }
    }

    pub fn checkpoint(&self) -> AccessEdgeCheckpoint {
        AccessEdgeCheckpoint {
            wifi_provider: self.wifi_provider.clone(),
            topology: self.topology.clone(),
            cached_bridges: self.cached_bridges.clone(),
            bridge_names: self.bridge_names.clone(),
            latest_wifi: self.latest_wifi.clone(),
            wifi_fresh: self.wifi_fresh,
            topology_complete: self.topology_complete,
            next_fdb_sync_ms: self.next_fdb_sync_ms,
            initial_syncs: self.initial_syncs,
            epoch_id: self.epoch_id,
            rates: self.rates.clone(),
            muxes: self.muxes.clone(),
            histories: self.histories.clone(),
            classification: self.classification.clone(),
            latest: self.latest.clone(),
            event_monitor_failed: self.event_monitor_failed,
        }
    }

    pub fn restore(&mut self, checkpoint: AccessEdgeCheckpoint) {
        self.wifi_provider = checkpoint.wifi_provider;
        self.topology = checkpoint.topology;
        self.cached_bridges = checkpoint.cached_bridges;
        self.bridge_names = checkpoint.bridge_names;
        self.latest_wifi = checkpoint.latest_wifi;
        self.wifi_fresh = checkpoint.wifi_fresh;
        self.topology_complete = checkpoint.topology_complete;
        self.next_fdb_sync_ms = checkpoint.next_fdb_sync_ms;
        self.initial_syncs = checkpoint.initial_syncs;
        self.epoch_id = checkpoint.epoch_id;
        self.rates = checkpoint.rates;
        self.muxes = checkpoint.muxes;
        self.histories = checkpoint.histories;
        self.classification = checkpoint.classification;
        self.latest = checkpoint.latest;
        self.event_monitor_failed = checkpoint.event_monitor_failed;
    }

    pub const fn attachment_generation_watermark(&self) -> u64 {
        self.topology.generation_watermark()
    }

    pub fn advance_attachment_generation_floor(&mut self, floor: u64) {
        self.topology.advance_generation_floor(floor);
    }

    /// Access Edge is deliberately cold-started after being disabled.  A
    /// counter read made before the mode switch cannot be compared with the
    /// first read after it, and retaining that segment would turn the entire
    /// disabled interval into a misleading long average.
    pub fn reset_for_disabled_mode(&mut self) {
        self.rates.clear();
        self.histories.clear();
        self.muxes.clear();
        self.classification.clear();
        self.topology.clear_active();
        self.cached_bridges.clear();
        self.bridge_names.clear();
        self.latest = AccessEdgeSnapshot::default();
        self.latest_wifi = None;
        self.wifi_fresh = false;
        self.topology_complete = false;
        self.next_fdb_sync_ms = 0;
        self.initial_syncs = 0;
    }

    pub fn collect_topology(&mut self, bridges: &[String], max_entries: usize, now_ms: u64) {
        let mut reasons = Vec::new();
        let event_changed = match self.event_monitor.as_mut() {
            Some(monitor) => match monitor.topology_changed() {
                Ok(changed) => changed,
                Err(_) => {
                    self.event_monitor_failed = true;
                    self.event_monitor = None;
                    reasons.push("fdb_event_monitor_failed".to_owned());
                    true
                }
            },
            None => false,
        };
        if self.event_monitor_failed {
            reasons.push("fdb_event_monitor_unavailable".to_owned());
        }
        let bridge_set = bridges.iter().cloned().collect::<BTreeSet<_>>();
        let bridge_inventory_changed = bridge_inventory_changed(&self.cached_bridges, &bridge_set);
        self.cached_bridges
            .retain(|bridge, _| bridge_set.contains(bridge));
        self.bridge_names
            .retain(|_, bridge| bridge_set.contains(bridge));
        let fdb_due = bridge_inventory_changed || event_changed || now_ms >= self.next_fdb_sync_ms;
        let mut refreshed_bridges = BTreeSet::new();
        if fdb_due {
            let mut all_complete = !bridges.is_empty();
            for bridge in bridges {
                match self.fdb_provider.dump_bridge(bridge, max_entries.max(1)) {
                    Ok(snapshot) => {
                        let observations = observations_from_fdb(&snapshot, ifindex_name);
                        self.bridge_names
                            .insert(snapshot.bridge_ifindex, snapshot.bridge.clone());
                        all_complete &= snapshot.complete;
                        if !snapshot.complete {
                            reasons.push("fdb_fallback_incomplete".to_owned());
                        }
                        self.cached_bridges.insert(
                            bridge.clone(),
                            CachedBridge {
                                observations,
                                source: snapshot.source,
                                complete: snapshot.complete,
                            },
                        );
                        refreshed_bridges.insert(bridge.clone());
                    }
                    Err(_) => {
                        all_complete = false;
                        reasons.push("fdb_dump_failed".to_owned());
                        if let Some(cached) = self.cached_bridges.get_mut(bridge) {
                            cached.complete = false;
                        }
                    }
                }
            }
            self.initial_syncs = self.initial_syncs.saturating_add(1).min(2);
            self.next_fdb_sync_ms = now_ms.saturating_add(if self.initial_syncs < 2 {
                FDB_INITIAL_STABLE_SYNC_MS
            } else {
                FDB_FULL_SYNC_MS
            });
            self.topology_complete = all_complete
                && bridges.iter().all(|bridge| {
                    self.cached_bridges
                        .get(bridge)
                        .is_some_and(|cached| cached.complete)
                });
        }

        self.wifi_fresh = false;
        match self.wifi_provider.read_stations() {
            Ok(snapshot) => {
                self.wifi_fresh = snapshot.complete;
                if !snapshot.complete {
                    reasons.push("nl80211_dump_incomplete".to_owned());
                }
                self.latest_wifi = Some(snapshot);
            }
            Err(_) => {
                reasons.push("nl80211_dump_failed".to_owned());
            }
        }

        let mut observations = Vec::new();
        for (bridge, cached) in &self.cached_bridges {
            let fresh_frame = refreshed_bridges.contains(bridge) && cached.complete;
            observations.extend(cached.observations.iter().cloned().map(|mut observation| {
                observation.fresh_frame = fresh_frame;
                observation.provider_complete = cached.complete;
                observation
            }));
        }
        let fdb_observation_count = observations.len();
        if let Some(stations) = self.latest_wifi.as_ref() {
            for mut observation in observations_from_stations(stations) {
                inherit_unambiguous_fdb_vlan(
                    &observations[..fdb_observation_count],
                    &mut observation,
                );
                observation.fresh_frame = self.wifi_fresh;
                observation.provider_complete = self.wifi_fresh;
                observations.push(observation);
            }
        }
        // Ethernet trust is proved by the FDB source alone. Keep the public
        // snapshot conservative when Wi-Fi is stale, but do not demote an
        // independent wired attachment because an NL80211 dump failed.
        let update = self
            .topology
            .reconcile(observations, self.topology_complete);
        for key in update.removed.iter().chain(update.changed.iter()) {
            for direction in [Direction::Tx, Direction::Rx] {
                for source in [RateSource::EdgePort, RateSource::EdgeWifi] {
                    self.rates.remove(&(*key, source, direction));
                }
                self.histories.remove(&(*key, direction));
            }
        }
        reasons.sort();
        reasons.dedup();
        self.latest.reason_codes = reasons;
        self.latest.topology_complete = self.topology_complete
            && wifi_topology_complete(self.latest_wifi.as_ref(), self.wifi_fresh);
        self.latest.fdb_source = common_fdb_source(&self.cached_bridges);
    }

    pub fn identity_hints(&self) -> Vec<EdgeIdentityHint> {
        self.topology
            .active()
            .filter_map(|attachment| {
                let bridge_ifindex = attachment.point.bridge_ifindex?;
                let logical_interface = self
                    .bridge_names
                    .get(&bridge_ifindex)
                    .cloned()
                    .or_else(|| ifindex_name(bridge_ifindex))?;
                Some(EdgeIdentityHint {
                    mac: format_mac(attachment.key.mac),
                    logical_interface,
                    wireless: attachment.point.kind == AttachmentKind::Wifi,
                })
            })
            .collect()
    }

    pub fn port_ifnames(&self) -> BTreeSet<String> {
        self.topology
            .active()
            .filter(|attachment| attachment.point.kind == AttachmentKind::Ethernet)
            .map(|attachment| attachment.point.ifname.clone())
            .collect()
    }

    pub fn update_rates(
        &mut self,
        counters: &InterfaceCounterSnapshot,
        read_begin_ms: u64,
        read_end_ms: u64,
        sample_ms: u64,
    ) -> &AccessEdgeSnapshot {
        self.epoch_id = self.epoch_id.saturating_add(1);
        let stations = self.wifi_fresh.then(|| self.latest_wifi.clone()).flatten();
        let mut clients = Vec::new();
        for attachment in self.topology.active().cloned().collect::<Vec<_>>() {
            let (tx, rx) = match attachment.point.kind {
                AttachmentKind::Wifi => {
                    let station = stations.as_ref().and_then(|snapshot| {
                        snapshot.stations.iter().find(|station| {
                            station.mac == attachment.key.mac
                                && station.ifindex == attachment.point.ifindex
                                && station.association_generation == attachment.source_generation
                        })
                    });
                    match station {
                        Some(station) => {
                            let coverage = if station.proves_direct_client_interface() {
                                Coverage::Full
                            } else {
                                Coverage::Partial
                            };
                            let read_times = station
                                .read_times(stations.as_ref().expect("station snapshot exists"));
                            let mut tx = self.update_direction(
                                &attachment,
                                Direction::Tx,
                                station.counters,
                                read_times,
                                RateSource::EdgeWifi,
                                ByteDomain::StationData,
                                coverage,
                                TrafficScope::Unicast,
                            );
                            let mut rx = self.update_direction(
                                &attachment,
                                Direction::Rx,
                                station.counters,
                                read_times,
                                RateSource::EdgeWifi,
                                ByteDomain::StationData,
                                coverage,
                                TrafficScope::Unicast,
                            );
                            if coverage == Coverage::Partial {
                                tx.reason_codes
                                    .push("wifi_shared_or_unproven_interface".to_owned());
                                rx.reason_codes
                                    .push("wifi_shared_or_unproven_interface".to_owned());
                            }
                            (tx, rx)
                        }
                        None => (
                            EdgeDirectionObservation::unavailable("nl80211_station_sample_missing"),
                            EdgeDirectionObservation::unavailable("nl80211_station_sample_missing"),
                        ),
                    }
                }
                AttachmentKind::Ethernet => {
                    let sampled = counters.counters.get(&attachment.point.ifname).copied();
                    match sampled {
                        Some(value)
                            if !attachment.ambiguous
                                && !matches!(attachment.trust, AttachmentTrust::Shared)
                                && !matches!(attachment.trust, AttachmentTrust::Unknown) =>
                        {
                            // A complete FDB frame can prove that one MAC is
                            // currently visible on the port, but cannot prove
                            // there is no silent AP, switch, Mesh or WDS peer
                            // behind it. Edge-Port remains the unique total-rate
                            // owner while its attribution proof stays Partial.
                            let coverage = Coverage::Partial;
                            let link = LinkCounters {
                                rx_bytes: value.rx_bytes,
                                tx_bytes: value.tx_bytes,
                                rx_packets: value.rx_packets,
                                tx_packets: value.tx_packets,
                            };
                            (
                                self.update_direction(
                                    &attachment,
                                    Direction::Tx,
                                    link,
                                    (read_begin_ms, read_end_ms, sample_ms),
                                    RateSource::EdgePort,
                                    ByteDomain::L2NoFcs,
                                    coverage,
                                    TrafficScope::AllFrames,
                                ),
                                self.update_direction(
                                    &attachment,
                                    Direction::Rx,
                                    link,
                                    (read_begin_ms, read_end_ms, sample_ms),
                                    RateSource::EdgePort,
                                    ByteDomain::L2NoFcs,
                                    coverage,
                                    TrafficScope::AllFrames,
                                ),
                            )
                        }
                        Some(_) => {
                            let mut unavailable =
                                EdgeDirectionObservation::unavailable(if attachment.ambiguous {
                                    "attachment_ambiguous"
                                } else {
                                    "shared_or_unproven_port"
                                });
                            unavailable.coverage = Coverage::Partial;
                            unavailable.scope = TrafficScope::AllFrames;
                            unavailable.failure = attachment
                                .ambiguous
                                .then_some(MuxFailure::AttachmentAmbiguous);
                            (unavailable.clone(), unavailable)
                        }
                        None => (
                            EdgeDirectionObservation::unavailable("port_counter_missing"),
                            EdgeDirectionObservation::unavailable("port_counter_missing"),
                        ),
                    }
                }
            };
            clients.push(EdgeClientObservation { attachment, tx, rx });
        }
        self.latest.sample_ms = sample_ms;
        self.latest.clients = clients;
        &self.latest
    }

    #[allow(clippy::too_many_arguments)]
    fn update_direction(
        &mut self,
        attachment: &Attachment,
        direction: Direction,
        counters: LinkCounters,
        read_times: (u64, u64, u64),
        source: RateSource,
        byte_domain: ByteDomain,
        coverage: Coverage,
        scope: TrafficScope,
    ) -> EdgeDirectionObservation {
        let (read_begin_ms, read_end_ms, sample_ms) = read_times;
        let current = CumulativeCounterSample::from_link(
            self.epoch_id,
            sample_ms,
            read_begin_ms,
            read_end_ms,
            source,
            direction,
            counters,
            attachment.generation,
            byte_domain,
            read_end_ms.saturating_sub(read_begin_ms),
        );
        match self
            .rates
            .update((attachment.key, source, direction), current)
        {
            CounterUpdate::Warmup => EdgeDirectionObservation {
                segment: None,
                coverage,
                scope,
                failure: None,
                reason_codes: vec!["warmup".to_owned()],
            },
            CounterUpdate::Reset(_) => {
                // A reset breaks comparability with every accumulated segment
                // for this attachment direction. Start classification history
                // from the next valid delta.
                self.histories.remove(&(attachment.key, direction));
                EdgeDirectionObservation {
                    segment: None,
                    coverage,
                    scope,
                    failure: Some(MuxFailure::CounterReset),
                    reason_codes: vec!["counter_reset".to_owned()],
                }
            }
            CounterUpdate::Segment(segment) => {
                let history = self
                    .histories
                    .entry((attachment.key, direction))
                    .or_default();
                history.push_back(segment);
                while history.len() > EDGE_HISTORY_SEGMENTS {
                    history.pop_front();
                }
                EdgeDirectionObservation {
                    segment: Some(segment),
                    coverage,
                    scope,
                    failure: None,
                    reason_codes: Vec::new(),
                }
            }
        }
    }

    pub fn latest(&self) -> &AccessEdgeSnapshot {
        &self.latest
    }

    /// Return completeness for the provider that proves this attachment. The
    /// snapshot-level flag remains conservative for global diagnostics, while
    /// ownership and classifier warmup stay independent across Ethernet/Wi-Fi.
    pub fn attachment_topology_complete(&self, attachment: &Attachment) -> bool {
        match attachment.point.kind {
            AttachmentKind::Ethernet => attachment
                .point
                .bridge_ifindex
                .and_then(|ifindex| self.bridge_names.get(&ifindex))
                .and_then(|bridge| self.cached_bridges.get(bridge))
                .is_some_and(|snapshot| snapshot.complete),
            AttachmentKind::Wifi => {
                wifi_topology_complete(self.latest_wifi.as_ref(), self.wifi_fresh)
            }
        }
    }

    pub fn update_mux(
        &mut self,
        identity_key: &str,
        direction: Direction,
        now_ms: u64,
        attachment_generation: u64,
        candidates: &[RateCandidate],
        failure: Option<MuxFailure>,
    ) -> MuxResult {
        self.muxes
            .entry((identity_key.to_owned(), direction))
            .or_default()
            .update(now_ms, attachment_generation, candidates, failure)
    }

    pub fn mux_owner(&self, identity_key: &str, direction: Direction) -> Option<RateSource> {
        self.muxes
            .get(&(identity_key.to_owned(), direction))
            .and_then(DirectionRateMux::owner)
    }

    pub fn invalidate_edge_mux(
        &mut self,
        identity_key: &str,
        direction: Direction,
        attachment_generation: u64,
    ) {
        self.muxes
            .entry((identity_key.to_owned(), direction))
            .or_default()
            .invalidate_edge(attachment_generation);
    }

    pub fn aggregate_edge(
        &self,
        key: AttachmentKey,
        direction: Direction,
        start_ms: u64,
        end_ms: u64,
    ) -> Option<ObservedDelta> {
        let history = self.histories.get(&(key, direction))?;
        aggregate_history(history, start_ms, end_ms)
    }

    pub fn update_classification(
        &mut self,
        identity_key: &str,
        epoch: ClassificationEpoch,
    ) -> ClassificationResult {
        self.classification.update(identity_key, epoch)
    }

    pub fn clear_classification(&mut self) {
        self.classification.clear();
    }

    /// Drop per-identity state after a publication pass.  Topology/rate
    /// ledgers are keyed by active attachments and are reclaimed during
    /// reconcile; mux and classifier ledgers need the published identity set
    /// because their keys may outlive both conntrack and FDB observations.
    pub fn retain_published_identities(&mut self, identity_keys: &BTreeSet<String>) {
        self.muxes
            .retain(|(identity_key, _), _| identity_keys.contains(identity_key));
        self.classification.retain_identities(identity_keys);
    }
}

fn bridge_inventory_changed<T>(cached: &BTreeMap<String, T>, requested: &BTreeSet<String>) -> bool {
    cached.len() != requested.len() || cached.keys().any(|bridge| !requested.contains(bridge))
}

fn wifi_topology_complete(snapshot: Option<&StationCounterSnapshot>, fresh: bool) -> bool {
    fresh && snapshot.is_some_and(|value| value.complete)
}

fn aggregate_history(
    history: &VecDeque<CounterSegment>,
    start_ms: u64,
    end_ms: u64,
) -> Option<ObservedDelta> {
    let selected = history
        .iter()
        .copied()
        .filter(|segment| {
            segment.start_ms >= start_ms.saturating_sub(CLASSIFIER_READ_END_SKEW_MS)
                && segment.end_ms <= end_ms.saturating_add(CLASSIFIER_READ_END_SKEW_MS)
        })
        .collect::<Vec<_>>();
    let first = selected.first()?;
    let last = selected.last()?;
    if first.start_ms.abs_diff(start_ms) > CLASSIFIER_READ_END_SKEW_MS
        || last.end_ms.abs_diff(end_ms) > CLASSIFIER_READ_END_SKEW_MS
        || selected
            .windows(2)
            .any(|pair| pair[0].end_ms != pair[1].start_ms)
        || selected.iter().any(|segment| {
            segment.source != first.source
                || segment.byte_domain != first.byte_domain
                || segment.attachment_generation != first.attachment_generation
        })
    {
        return None;
    }
    Some(ObservedDelta {
        source: first.source,
        bytes: selected
            .iter()
            .fold(0u64, |total, segment| total.saturating_add(segment.bytes)),
        packets: selected
            .iter()
            .fold(0u64, |total, segment| total.saturating_add(segment.packets)),
        byte_domain: first.byte_domain,
        read_end_ms: last.read_end_ms,
    })
}

trait StationReadTimes {
    fn read_times(&self, snapshot: &StationCounterSnapshot) -> (u64, u64, u64);
}

impl StationReadTimes for super::nl80211::StationCounterSample {
    fn read_times(&self, snapshot: &StationCounterSnapshot) -> (u64, u64, u64) {
        (
            snapshot.read_begin_ms,
            snapshot.read_end_ms,
            snapshot.read_end_ms,
        )
    }
}

fn common_fdb_source(bridges: &BTreeMap<String, CachedBridge>) -> Option<&'static str> {
    let mut values = bridges.values();
    let first = values.next()?.source;
    values
        .all(|bridge| bridge.source == first)
        .then_some(first.as_str())
}

/// NL80211 station dumps do not carry a bridge VID. A VLAN-aware bridge FDB
/// does, so inherit it only when the same MAC is present on the same AP port
/// with exactly one VID. Multiple VIDs remain separate/ambiguous because one
/// station counter cannot prove their per-VLAN ownership.
fn inherit_unambiguous_fdb_vlan(
    fdb: &[AttachmentObservation],
    station: &mut AttachmentObservation,
) {
    if station.point.kind != AttachmentKind::Wifi || station.key.vlan_id.is_some() {
        return;
    }
    let vlans = fdb
        .iter()
        .filter(|observation| {
            observation.point.kind == AttachmentKind::Ethernet
                && observation.key.mac == station.key.mac
                && observation.key.bridge_ifindex == station.key.bridge_ifindex
                && observation.point.ifindex == station.point.ifindex
        })
        .map(|observation| observation.key.vlan_id)
        .collect::<BTreeSet<_>>();
    if vlans.len() == 1 {
        let vlan_id = *vlans.iter().next().expect("one FDB VLAN was proven");
        station.key.vlan_id = vlan_id;
        station.point.vlan_id = vlan_id;
    }
}

fn ifindex_name(ifindex: u32) -> Option<String> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    let value = unsafe { libc::if_indextoname(ifindex, name.as_mut_ptr()) };
    if value.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(value) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
include!("runtime_tests.rs");
