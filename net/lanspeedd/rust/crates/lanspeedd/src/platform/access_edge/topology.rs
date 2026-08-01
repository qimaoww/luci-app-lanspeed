use std::collections::{BTreeMap, BTreeSet};

use super::{fdb::BridgeFdbSnapshot, nl80211::StationCounterSnapshot};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AttachmentKind {
    Ethernet,
    Wifi,
}

impl AttachmentKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet => "ethernet",
            Self::Wifi => "wifi",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AttachmentTrust {
    AssociatedStation,
    ObservedExclusive,
    Shared,
    Unknown,
}

impl AttachmentTrust {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AssociatedStation => "associated_station",
            Self::ObservedExclusive => "observed_exclusive",
            Self::Shared => "shared",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttachmentKey {
    pub mac: [u8; 6],
    pub bridge_ifindex: Option<u32>,
    pub vlan_id: Option<u16>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AttachmentPoint {
    pub kind: AttachmentKind,
    pub ifindex: u32,
    pub ifname: String,
    pub bridge_ifindex: Option<u32>,
    pub vlan_id: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentObservation {
    pub key: AttachmentKey,
    pub point: AttachmentPoint,
    /// Provider-owned generation, e.g. a Wi-Fi reassociation sequence.
    pub source_generation: u64,
    /// True only for a new complete provider frame. Reusing cached topology
    /// must not satisfy the two-frame stability requirement.
    pub fresh_frame: bool,
    /// Completeness belongs to the provider frame that contains this
    /// attachment. One failed bridge dump must not demote attachments proved
    /// by another complete bridge dump.
    pub provider_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attachment {
    pub key: AttachmentKey,
    pub point: AttachmentPoint,
    pub trust: AttachmentTrust,
    pub generation: u64,
    pub source_generation: u64,
    pub stable_observations: u32,
    pub ambiguous: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TopologyUpdate {
    pub active: Vec<Attachment>,
    pub changed: Vec<AttachmentKey>,
    pub removed: Vec<AttachmentKey>,
    pub source_complete: bool,
}

#[derive(Clone, Debug, Default)]
pub struct TopologyTable {
    active: BTreeMap<AttachmentKey, Attachment>,
    /// One process-wide monotonic allocator is enough to invalidate every
    /// counter/rate ledger when an attachment changes.  Keeping the last
    /// generation for every historical key would otherwise grow forever as
    /// clients churn through the network.
    last_generation: u64,
}

impl TopologyTable {
    pub fn new() -> Self {
        Self {
            active: BTreeMap::new(),
            last_generation: 0,
        }
    }

    pub fn get(&self, key: &AttachmentKey) -> Option<&Attachment> {
        self.active.get(key)
    }

    pub fn active(&self) -> impl Iterator<Item = &Attachment> {
        self.active.values()
    }

    /// Drop observed attachments while retaining the monotonic allocator.
    /// Re-enabling the feature must produce fresh attachment generations
    /// instead of recovering a disabled-mode topology as if it were current.
    pub fn clear_active(&mut self) {
        self.active.clear();
    }

    pub const fn generation_watermark(&self) -> u64 {
        self.last_generation
    }

    pub fn advance_generation_floor(&mut self, floor: u64) {
        self.last_generation = self.last_generation.max(floor);
    }

    /// Atomically replace the observed topology. An incomplete source remains
    /// usable for attachment hints, but Ethernet trust is forced to Unknown.
    pub fn reconcile(
        &mut self,
        observations: impl IntoIterator<Item = AttachmentObservation>,
        source_complete: bool,
    ) -> TopologyUpdate {
        let mut grouped = BTreeMap::<AttachmentKey, Vec<AttachmentObservation>>::new();
        for observation in observations {
            if valid_client_mac(observation.key.mac) && observation.point.ifindex != 0 {
                grouped
                    .entry(observation.key)
                    .or_default()
                    .push(observation);
            }
        }

        // Full ownership is a property of the physical attachment, not of one
        // VLAN/FID bucket. Seeing a second dynamic identity tuple anywhere on
        // the same ifindex proves that the port is a shared downlink or trunk.
        // Counting only within (bridge, VID, ifindex) would incorrectly grant
        // `all_frames/full` to one client per VLAN on a trunk.
        let mut occupancy = BTreeMap::<u32, BTreeSet<(Option<u32>, Option<u16>, [u8; 6])>>::new();
        for values in grouped.values() {
            for observation in values {
                if observation.point.kind == AttachmentKind::Ethernet {
                    occupancy
                        .entry(observation.point.ifindex)
                        .or_default()
                        .insert((
                            observation.point.bridge_ifindex,
                            observation.point.vlan_id,
                            observation.key.mac,
                        ));
                }
            }
        }

        let previous = std::mem::take(&mut self.active);
        let mut next = BTreeMap::new();
        let mut changed = Vec::new();
        for (key, mut values) in grouped {
            values.sort_by_key(|observation| {
                (
                    kind_priority(observation.point.kind),
                    observation.point.ifindex,
                    observation.source_generation,
                )
            });
            values.dedup();
            let selected = values
                .first()
                .expect("grouped topology observations are non-empty");
            // FDB and NL80211 may report the same Wi-Fi attachment. Different
            // ifindices, however, are a real ambiguity and must demote now.
            let ambiguous = values
                .iter()
                .any(|value| value.point.ifindex != selected.point.ifindex);
            let source_generation = values
                .iter()
                .filter(|value| value.point.ifindex == selected.point.ifindex)
                .map(|value| value.source_generation)
                .max()
                .unwrap_or(selected.source_generation);
            let selected_fresh = values.iter().any(|value| {
                value.point.kind == selected.point.kind
                    && value.point.ifindex == selected.point.ifindex
                    && value.fresh_frame
            });
            let trust = attachment_trust(selected, ambiguous, &occupancy);

            let material_matches = previous.get(&key).is_some_and(|old| {
                old.point == selected.point
                    && old.trust == trust
                    && old.source_generation == source_generation
                    && old.ambiguous == ambiguous
            });
            let (generation, stable_observations) = if material_matches {
                let old = previous.get(&key).expect("checked above");
                (
                    old.generation,
                    old.stable_observations
                        .saturating_add(u32::from(selected_fresh)),
                )
            } else {
                self.last_generation = self.last_generation.saturating_add(1);
                let generation = self.last_generation;
                changed.push(key);
                (generation, u32::from(selected_fresh))
            };
            next.insert(
                key,
                Attachment {
                    key,
                    point: selected.point.clone(),
                    trust,
                    generation,
                    source_generation,
                    stable_observations,
                    ambiguous,
                },
            );
        }

        let mut removed = Vec::new();
        for (key, _) in previous {
            if !next.contains_key(&key) {
                removed.push(key);
            }
        }
        self.active = next;
        TopologyUpdate {
            active: self.active.values().cloned().collect(),
            changed,
            removed,
            source_complete,
        }
    }
}

pub fn observations_from_fdb<F>(
    snapshot: &BridgeFdbSnapshot,
    mut interface_name: F,
) -> Vec<AttachmentObservation>
where
    F: FnMut(u32) -> Option<String>,
{
    snapshot
        .entries
        .iter()
        .filter(|entry| entry.is_client_candidate())
        .map(|entry| {
            let bridge_ifindex = entry.bridge_ifindex.or(Some(snapshot.bridge_ifindex));
            AttachmentObservation {
                key: AttachmentKey {
                    mac: entry.mac,
                    bridge_ifindex,
                    vlan_id: entry.vlan_id,
                },
                point: AttachmentPoint {
                    kind: AttachmentKind::Ethernet,
                    ifindex: entry.port_ifindex,
                    ifname: interface_name(entry.port_ifindex)
                        .unwrap_or_else(|| format!("if{}", entry.port_ifindex)),
                    bridge_ifindex,
                    vlan_id: entry.vlan_id,
                },
                source_generation: 0,
                fresh_frame: true,
                provider_complete: snapshot.complete,
            }
        })
        .collect()
}

pub fn observations_from_stations(snapshot: &StationCounterSnapshot) -> Vec<AttachmentObservation> {
    snapshot
        .stations
        .iter()
        .map(|station| AttachmentObservation {
            key: AttachmentKey {
                mac: station.mac,
                bridge_ifindex: station.bridge_ifindex,
                vlan_id: station.vlan_id,
            },
            point: AttachmentPoint {
                kind: AttachmentKind::Wifi,
                ifindex: station.ifindex,
                ifname: station.ifname.clone(),
                bridge_ifindex: station.bridge_ifindex,
                vlan_id: station.vlan_id,
            },
            source_generation: station.association_generation,
            fresh_frame: true,
            provider_complete: snapshot.complete,
        })
        .collect()
}

fn attachment_trust(
    selected: &AttachmentObservation,
    ambiguous: bool,
    occupancy: &BTreeMap<u32, BTreeSet<(Option<u32>, Option<u16>, [u8; 6])>>,
) -> AttachmentTrust {
    if ambiguous {
        return AttachmentTrust::Unknown;
    }
    if selected.point.kind == AttachmentKind::Wifi {
        return AttachmentTrust::AssociatedStation;
    }
    if !selected.provider_complete {
        return AttachmentTrust::Unknown;
    }
    if occupancy
        .get(&selected.point.ifindex)
        .is_some_and(|identities| identities.len() > 1)
    {
        AttachmentTrust::Shared
    } else {
        AttachmentTrust::ObservedExclusive
    }
}

const fn kind_priority(kind: AttachmentKind) -> u8 {
    match kind {
        AttachmentKind::Wifi => 0,
        AttachmentKind::Ethernet => 1,
    }
}

fn valid_client_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac != [0xff; 6] && mac[0] & 1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::access_edge::{
        fdb::{BridgeFdbSnapshot, FdbEntry, FdbSource},
        nl80211::{StationByteCounterWidth, StationCounterSample},
        rate::LinkCounters,
    };

    fn fdb_entry(mac: [u8; 6], ifindex: u32) -> FdbEntry {
        FdbEntry {
            mac,
            port_ifindex: ifindex,
            bridge_ifindex: Some(10),
            vlan_id: None,
            state: 2,
            flags: 0,
            flags_ext: 0,
            entry_type: 0,
            local: false,
            ageing_timer: None,
        }
    }

    fn fdb(entries: Vec<FdbEntry>, complete: bool) -> BridgeFdbSnapshot {
        BridgeFdbSnapshot {
            bridge: "br-lan".into(),
            bridge_ifindex: 10,
            entries,
            source: FdbSource::Rtnetlink,
            complete,
            degraded_reason: None,
        }
    }

    fn ifname(index: u32) -> Option<String> {
        Some(format!("lan{}", index - 4))
    }

    #[test]
    fn single_client_port_remains_observed_exclusive_while_stability_advances() {
        let mac = [0x02, 1, 2, 3, 4, 5];
        let snapshot = fdb(vec![fdb_entry(mac, 6)], true);
        let mut table = TopologyTable::new();
        let first = table.reconcile(observations_from_fdb(&snapshot, ifname), snapshot.complete);
        assert_eq!(first.active[0].trust, AttachmentTrust::ObservedExclusive);
        assert_eq!(first.active[0].stable_observations, 1);
        let generation = first.active[0].generation;

        let second = table.reconcile(observations_from_fdb(&snapshot, ifname), snapshot.complete);
        assert_eq!(second.active[0].generation, generation);
        assert_eq!(second.active[0].stable_observations, 2);
        assert_eq!(second.active[0].trust, AttachmentTrust::ObservedExclusive);
        assert!(second.changed.is_empty());
    }

    #[test]
    fn reusing_one_cached_fdb_frame_does_not_advance_stability() {
        let mac = [0x02, 1, 2, 3, 4, 5];
        let snapshot = fdb(vec![fdb_entry(mac, 6)], true);
        let mut table = TopologyTable::new();
        let first = table.reconcile(observations_from_fdb(&snapshot, ifname), true);
        assert_eq!(first.active[0].stable_observations, 1);

        let mut cached = observations_from_fdb(&snapshot, ifname);
        cached
            .iter_mut()
            .for_each(|observation| observation.fresh_frame = false);
        let reused = table.reconcile(cached, true);
        assert_eq!(reused.active[0].stable_observations, 1);

        let next = table.reconcile(observations_from_fdb(&snapshot, ifname), true);
        assert_eq!(next.active[0].stable_observations, 2);
    }

    #[test]
    fn shared_port_demotes_every_client_and_changes_generation() {
        let first_mac = [0x02, 1, 2, 3, 4, 5];
        let second_mac = [0x02, 6, 7, 8, 9, 10];
        let mut table = TopologyTable::new();
        let one = fdb(vec![fdb_entry(first_mac, 6)], true);
        let old_generation = table
            .reconcile(observations_from_fdb(&one, ifname), true)
            .active[0]
            .generation;

        let shared = fdb(
            vec![fdb_entry(first_mac, 6), fdb_entry(second_mac, 6)],
            true,
        );
        let update = table.reconcile(observations_from_fdb(&shared, ifname), true);
        assert!(update
            .active
            .iter()
            .all(|attachment| attachment.trust == AttachmentTrust::Shared));
        assert!(update
            .active
            .iter()
            .find(|attachment| attachment.key.mac == first_mac)
            .is_some_and(|attachment| attachment.generation > old_generation));
    }

    #[test]
    fn one_client_per_vlan_is_still_a_shared_trunk() {
        let first_mac = [0x02, 1, 2, 3, 4, 5];
        let second_mac = [0x02, 6, 7, 8, 9, 10];
        let mut first = fdb_entry(first_mac, 6);
        first.vlan_id = Some(10);
        let mut second = fdb_entry(second_mac, 6);
        second.vlan_id = Some(20);
        let snapshot = fdb(vec![first, second], true);
        let mut table = TopologyTable::new();

        let update = table.reconcile(observations_from_fdb(&snapshot, ifname), true);

        assert_eq!(update.active.len(), 2);
        assert!(update
            .active
            .iter()
            .all(|attachment| attachment.trust == AttachmentTrust::Shared));
    }

    #[test]
    fn incomplete_fdb_can_only_create_unknown_attachment() {
        let snapshot = fdb(vec![fdb_entry([0x02, 1, 2, 3, 4, 5], 6)], false);
        let mut table = TopologyTable::new();
        let update = table.reconcile(observations_from_fdb(&snapshot, ifname), false);
        assert_eq!(update.active[0].trust, AttachmentTrust::Unknown);
    }

    #[test]
    fn incomplete_unrelated_bridge_does_not_demote_a_complete_bridge() {
        let healthy_mac = [0x02, 1, 2, 3, 4, 5];
        let broken_mac = [0x02, 6, 7, 8, 9, 10];
        let mut healthy = fdb(vec![fdb_entry(healthy_mac, 6)], true);
        healthy.bridge = "br-lan".into();
        let mut broken_entry = fdb_entry(broken_mac, 8);
        broken_entry.bridge_ifindex = Some(20);
        let mut broken = fdb(vec![broken_entry], false);
        broken.bridge = "br-guest".into();
        broken.bridge_ifindex = 20;
        let mut observations = observations_from_fdb(&healthy, ifname);
        observations.extend(observations_from_fdb(&broken, ifname));

        let update = TopologyTable::new().reconcile(observations, false);
        let healthy = update
            .active
            .iter()
            .find(|attachment| attachment.key.mac == healthy_mac)
            .expect("healthy bridge attachment");
        let broken = update
            .active
            .iter()
            .find(|attachment| attachment.key.mac == broken_mac)
            .expect("incomplete bridge attachment");
        assert_eq!(healthy.trust, AttachmentTrust::ObservedExclusive);
        assert_eq!(broken.trust, AttachmentTrust::Unknown);
    }

    #[test]
    fn station_observation_supersedes_fdb_on_same_ifindex() {
        let mac = [0x02, 1, 2, 3, 4, 5];
        let bridge = fdb(vec![fdb_entry(mac, 7)], true);
        let stations = StationCounterSnapshot {
            stations: vec![StationCounterSample {
                mac,
                ifindex: 7,
                ifname: "phy1-ap0".into(),
                bridge_ifindex: Some(10),
                vlan_id: None,
                iftype: Some(crate::platform::access_edge::nl80211::NL80211_IFTYPE_AP),
                association_generation: 3,
                association_started_ns: Some(1_000),
                connected_time_s: Some(5),
                counters: LinkCounters::default(),
                rx_byte_width: StationByteCounterWidth::Bits64,
                tx_byte_width: StationByteCounterWidth::Bits64,
            }],
            read_begin_ms: 1,
            read_end_ms: 2,
            complete: true,
        };
        let mut observations = observations_from_fdb(&bridge, |_| Some("phy1-ap0".into()));
        observations.extend(observations_from_stations(&stations));
        let mut table = TopologyTable::new();
        let update = table.reconcile(observations, true);
        assert_eq!(update.active.len(), 1);
        assert_eq!(update.active[0].point.kind, AttachmentKind::Wifi);
        assert_eq!(update.active[0].trust, AttachmentTrust::AssociatedStation);
        assert!(!update.active[0].ambiguous);
        assert_eq!(update.active[0].source_generation, 3);
    }

    #[test]
    fn moving_between_ports_advances_attachment_generation() {
        let mac = [0x02, 1, 2, 3, 4, 5];
        let mut table = TopologyTable::new();
        let first = fdb(vec![fdb_entry(mac, 6)], true);
        let first_generation = table
            .reconcile(observations_from_fdb(&first, ifname), true)
            .active[0]
            .generation;
        let moved = fdb(vec![fdb_entry(mac, 7)], true);
        let second_generation = table
            .reconcile(observations_from_fdb(&moved, ifname), true)
            .active[0]
            .generation;
        assert!(second_generation > first_generation);
    }

    #[test]
    fn churn_uses_one_bounded_generation_allocator_and_reentry_is_new() {
        let mut table = TopologyTable::new();
        let first_mac = [0x02, 0, 0, 0, 0, 1];
        let first_generation = table
            .reconcile(
                observations_from_fdb(&fdb(vec![fdb_entry(first_mac, 6)], true), ifname),
                true,
            )
            .active[0]
            .generation;

        for value in 2u16..=1_024 {
            let mac = [0x02, 0, 0, (value >> 8) as u8, value as u8, 1];
            let update = table.reconcile(
                observations_from_fdb(&fdb(vec![fdb_entry(mac, 6)], true), ifname),
                true,
            );
            assert_eq!(update.active.len(), 1);
        }
        assert_eq!(table.active.len(), 1);
        assert_eq!(table.last_generation, 1_024);

        let reentered = table.reconcile(
            observations_from_fdb(&fdb(vec![fdb_entry(first_mac, 6)], true), ifname),
            true,
        );
        assert!(reentered.active[0].generation > first_generation);
        assert_eq!(table.last_generation, 1_025);
    }

    #[test]
    fn reload_candidate_allocates_after_the_previous_runtime_watermark() {
        let mut table = TopologyTable::new();
        table.advance_generation_floor(41);
        let mac = [0x02, 0, 0, 0, 0, 1];
        let update = table.reconcile(
            observations_from_fdb(&fdb(vec![fdb_entry(mac, 6)], true), ifname),
            true,
        );

        assert_eq!(update.active[0].generation, 42);
        assert_eq!(table.generation_watermark(), 42);
    }
}
