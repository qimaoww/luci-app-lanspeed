//! Per-client same-window FastN+FastS shadow rates.
//!
//! The aggregate shadow is useful for diagnostics, but a routed substitute
//! must be keyed by the client MAC and direction. This book keeps one bounded
//! coordinator per MAC/direction and drops a window when either source or its
//! reset generation disappears.

use std::collections::{BTreeMap, BTreeSet};

use lanspeed_common::{DIR_RX, DIR_TX};

use super::{
    fast_n_runtime::FastNSnapshot,
    fast_rate::{FastCounterSample, FastRateCoordinator, FastWindow, FAST_WINDOW_QUIET_CONFIRM_MS},
    fast_rate_contract::FastRateBaseContract,
    fast_s_runtime::FastSSnapshot,
};

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FastClientKey {
    pub mac: [u8; 6],
    pub direction: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastClientSample {
    pub sample_ms: u64,
    pub window_ms: u64,
    pub read_end_skew_ms: u64,
    pub fast_n_bps: u64,
    pub fast_s_bps: u64,
    pub fast_total_bps: u64,
    /// FastN is ECM/network-layer data (+ Ethernet header + FCS) while
    /// FastS is TC L2 data (+ FCS). This is the only combined value eligible
    /// for comparison with a wired Access Edge authority.
    pub routed_l2_with_fcs_bps: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastClientRateBook {
    coordinators: BTreeMap<FastClientKey, FastRateCoordinator>,
    last_counters: BTreeMap<FastClientKey, ClientCounterPair>,
    bindings: BTreeMap<FastClientKey, ClientBinding>,
    latest: BTreeMap<FastClientKey, FastClientSample>,
    invalid_windows: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ClientCounterPair {
    n: Option<Aggregate>,
    s: Option<Aggregate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientBinding {
    identity_key: String,
    attachment_generation: u64,
}

impl FastClientRateBook {
    pub(crate) fn observe(
        &mut self,
        fast_n: &FastNSnapshot,
        fast_s: &FastSSnapshot,
        n_read_begin_ms: u64,
        n_read_end_ms: u64,
        s_read_begin_ms: u64,
        s_read_end_ms: u64,
    ) {
        self.observe_inner(
            fast_n,
            fast_s,
            n_read_begin_ms,
            n_read_end_ms,
            s_read_begin_ms,
            s_read_end_ms,
            None,
        );
    }

    /// Observe a window while binding every retained client key to the base
    /// snapshot's identity and attachment generation.  A map entry may
    /// disappear during a quiet interval when its connection has no fresh
    /// hardware update; retaining its last cumulative baseline lets the same
    /// client publish a confirmed numeric zero and resume from the original
    /// counter baseline.  The contract prunes departed/re-attached identities
    /// so this hold can never cross an attachment generation.
    pub(crate) fn observe_with_contract(
        &mut self,
        fast_n: &FastNSnapshot,
        fast_s: &FastSSnapshot,
        n_read_begin_ms: u64,
        n_read_end_ms: u64,
        s_read_begin_ms: u64,
        s_read_end_ms: u64,
        contract: &FastRateBaseContract,
    ) {
        self.reconcile_contract(contract);
        self.observe_inner(
            fast_n,
            fast_s,
            n_read_begin_ms,
            n_read_end_ms,
            s_read_begin_ms,
            s_read_end_ms,
            Some(contract),
        );
    }

    fn observe_inner(
        &mut self,
        fast_n: &FastNSnapshot,
        fast_s: &FastSSnapshot,
        n_read_begin_ms: u64,
        n_read_end_ms: u64,
        s_read_begin_ms: u64,
        s_read_end_ms: u64,
        contract: Option<&FastRateBaseContract>,
    ) {
        if fast_n.truncated
            || fast_n.invalid_entries != 0
            || fast_s.truncated
            || fast_s.invalid_entries != 0
        {
            self.coordinators.values_mut().for_each(|book| book.clear());
            self.last_counters.clear();
            self.bindings.clear();
            self.latest.clear();
            self.invalid_windows = self.invalid_windows.saturating_add(1);
            return;
        }

        let n = aggregate_n(fast_n);
        let s = aggregate_s(fast_s);
        let mut keys = n.keys().chain(s.keys()).copied().collect::<BTreeSet<_>>();
        keys.extend(self.coordinators.keys().copied());
        if let Some(contract) = contract {
            // Once either direction of a client has been observed, keep a
            // paired key for the opposite direction as well.  A quiet
            // direction is a real numeric zero after confirmation; leaving
            // it absent would make the UI oscillate between 0 and
            // unavailable even though the attachment is still valid.
            let mut seen_macs = keys.iter().map(|key| key.mac).collect::<BTreeSet<_>>();
            // A valid NSS map can legitimately contain no entry yet for a
            // newly attached but idle client.  Seed both directions from the
            // identity-bound contract so that, after the normal quiet
            // confirmation interval, that client publishes an explicit 0
            // instead of oscillating between a number and unavailable.
            seen_macs.extend(contract.client_macs());
            for mac in seen_macs {
                keys.insert(FastClientKey {
                    mac,
                    direction: DIR_TX,
                });
                keys.insert(FastClientKey {
                    mac,
                    direction: DIR_RX,
                });
            }
            keys.retain(|key| contract.client(key.mac).is_some());
        }

        for key in keys {
            if let Some(contract) = contract {
                let Some(client) = contract.client(key.mac) else {
                    continue;
                };
                self.bindings.entry(key).or_insert_with(|| ClientBinding {
                    identity_key: client.identity_key.clone(),
                    attachment_generation: client.attachment_generation,
                });
            }
            // N and S are intentionally disjoint paths. A client may be
            // present in only one map during a perfectly valid window; the
            // absent source contributes a zero cumulative counter until it
            // appears. If both source entries disappear after a key has been
            // observed, retain their last cumulative values with no progress
            // marker; the coordinator can then confirm a real quiet zero
            // without shortening the next resumed window. A real counter
            // rollback still fails in the coordinator and rewarms the key.
            let previous = self.last_counters.get(&key).copied().unwrap_or_default();
            let n = current_or_retained(n.get(&key).copied(), previous.n, fast_n.reset_generation);
            let s = current_or_retained(s.get(&key).copied(), previous.s, fast_s.reset_generation);
            let n = n.unwrap_or(Aggregate {
                reset_generation: fast_n.reset_generation.max(1),
                ..Aggregate::default()
            });
            let s = s.unwrap_or(Aggregate {
                reset_generation: fast_s.reset_generation.max(1),
                ..Aggregate::default()
            });
            self.last_counters.insert(
                key,
                ClientCounterPair {
                    n: Some(n),
                    s: Some(s),
                },
            );
            let coordinator = self.coordinators.entry(key).or_default();
            let common_progress_ms = n.progress_ms.max(s.progress_ms);
            let sample_ms = if common_progress_ms == 0 {
                fast_n.sample_ms.max(fast_s.sample_ms)
            } else {
                common_progress_ms
            };
            let n_sample = FastCounterSample {
                sample_ms,
                progress_ms: n.progress_ms,
                source_present: n.source_present,
                read_begin_ms: n_read_begin_ms,
                read_end_ms: n_read_end_ms,
                attachment_generation: 0,
                reset_generation: n.reset_generation,
                bytes: n.bytes,
                packets: n.packets,
            };
            let s_sample = FastCounterSample {
                sample_ms,
                progress_ms: s.progress_ms,
                source_present: s.source_present,
                read_begin_ms: s_read_begin_ms,
                read_end_ms: s_read_end_ms,
                attachment_generation: 0,
                reset_generation: s.reset_generation,
                bytes: s.bytes,
                packets: s.packets,
            };
            if !coordinator.has_start() && coordinator.begin(n_sample, s_sample).is_ok() {
                continue;
            }
            if !coordinator.has_progress(n_sample, s_sample) {
                match coordinator.confirmed_quiet_window(
                    n_sample,
                    s_sample,
                    FAST_WINDOW_QUIET_CONFIRM_MS,
                ) {
                    Ok(Some(window)) => {
                        self.latest.insert(key, client_sample(window));
                    }
                    Ok(None) => {}
                    Err(_) => {
                        self.latest.remove(&key);
                        self.invalid_windows = self.invalid_windows.saturating_add(1);
                        coordinator.clear();
                        let _ = coordinator.begin(n_sample, s_sample);
                    }
                }
                continue;
            }
            match coordinator.finish(n_sample, s_sample) {
                Ok(window) => {
                    self.latest.insert(key, client_sample(window));
                    let _ = coordinator.begin(n_sample, s_sample);
                }
                Err(_) => {
                    self.latest.remove(&key);
                    self.invalid_windows = self.invalid_windows.saturating_add(1);
                    coordinator.clear();
                    let _ = coordinator.begin(n_sample, s_sample);
                }
            }
        }
    }

    pub(crate) const fn invalid_windows(&self) -> u64 {
        self.invalid_windows
    }

    pub(crate) fn clear(&mut self) {
        self.coordinators.clear();
        self.last_counters.clear();
        self.bindings.clear();
        self.latest.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.latest.len()
    }

    pub(crate) fn get(&self, mac: [u8; 6], direction: u8) -> Option<FastClientSample> {
        self.latest.get(&FastClientKey { mac, direction }).copied()
    }

    pub(crate) fn samples(&self) -> Vec<(FastClientKey, FastClientSample)> {
        self.latest
            .iter()
            .map(|(key, sample)| (*key, *sample))
            .collect()
    }

    fn reconcile_contract(&mut self, contract: &FastRateBaseContract) {
        let mut remove = BTreeSet::new();
        for (key, binding) in &self.bindings {
            let matches = contract.client(key.mac).is_some_and(|client| {
                client.identity_key == binding.identity_key
                    && client.attachment_generation == binding.attachment_generation
            });
            if !matches {
                remove.insert(*key);
            }
        }
        for key in remove {
            self.coordinators.remove(&key);
            self.last_counters.remove(&key);
            self.bindings.remove(&key);
            self.latest.remove(&key);
        }
    }
}

fn current_or_retained(
    current: Option<Aggregate>,
    previous: Option<Aggregate>,
    reset_generation: u32,
) -> Option<Aggregate> {
    current.or_else(|| {
        previous.map(|value| Aggregate {
            source_present: false,
            progress_ms: 0,
            reset_generation: if value.reset_generation == 0 {
                reset_generation.max(1)
            } else {
                value.reset_generation
            },
            ..value
        })
    })
}

fn client_sample(window: FastWindow) -> FastClientSample {
    FastClientSample {
        sample_ms: window.end_ms,
        window_ms: window.duration_ms(),
        read_end_skew_ms: window.read_end_skew_ms,
        fast_n_bps: bytes_to_bps(window.n_bytes, window.duration_ms()),
        fast_s_bps: bytes_to_bps(window.s_bytes, window.duration_ms()),
        fast_total_bps: bytes_to_bps(window.total_bytes(), window.duration_ms()),
        routed_l2_with_fcs_bps: bytes_to_bps(l2_with_fcs_bytes(window), window.duration_ms()),
    }
}

fn l2_with_fcs_bytes(window: FastWindow) -> u64 {
    const ECM_TO_L2_WITH_FCS_BYTES_PER_PACKET: u64 = 18;
    const L2_FCS_BYTES_PER_PACKET: u64 = 4;
    window
        .n_bytes
        .saturating_add(
            window
                .n_packets
                .saturating_mul(ECM_TO_L2_WITH_FCS_BYTES_PER_PACKET),
        )
        .saturating_add(window.s_bytes)
        .saturating_add(window.s_packets.saturating_mul(L2_FCS_BYTES_PER_PACKET))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Aggregate {
    bytes: u64,
    packets: u64,
    reset_generation: u32,
    progress_ms: u64,
    source_present: bool,
}

fn aggregate_n(snapshot: &FastNSnapshot) -> BTreeMap<FastClientKey, Aggregate> {
    let mut result = BTreeMap::new();
    for entry in &snapshot.entries {
        if !matches!(entry.key.direction, DIR_TX | DIR_RX) {
            continue;
        }
        let key = FastClientKey {
            mac: entry.key.mac,
            direction: entry.key.direction,
        };
        add_aggregate(
            &mut result,
            key,
            entry.aggregate.bytes,
            entry.aggregate.packets,
            entry.aggregate.reset_generation,
            entry.sample_ms,
        );
    }
    result
}

fn aggregate_s(snapshot: &FastSSnapshot) -> BTreeMap<FastClientKey, Aggregate> {
    let mut result = BTreeMap::new();
    for entry in &snapshot.entries {
        if !matches!(entry.key.direction, DIR_TX | DIR_RX) {
            continue;
        }
        let key = FastClientKey {
            mac: entry.key.mac,
            direction: entry.key.direction,
        };
        add_aggregate(
            &mut result,
            key,
            entry.aggregate.bytes,
            entry.aggregate.packets,
            entry.aggregate.reset_generation,
            entry.sample_ms,
        );
    }
    result
}

fn add_aggregate(
    result: &mut BTreeMap<FastClientKey, Aggregate>,
    key: FastClientKey,
    bytes: u64,
    packets: u64,
    reset_generation: u32,
    progress_ms: u64,
) {
    result
        .entry(key)
        .and_modify(|value| {
            value.bytes = value.bytes.saturating_add(bytes);
            value.packets = value.packets.saturating_add(packets);
            value.progress_ms = value.progress_ms.max(progress_ms);
            value.source_present = true;
            if value.reset_generation != reset_generation {
                value.reset_generation = 0;
            }
        })
        .or_insert(Aggregate {
            bytes,
            packets,
            reset_generation,
            progress_ms,
            source_present: true,
        });
}

fn bytes_to_bps(bytes: u64, window_ms: u64) -> u64 {
    if window_ms == 0 {
        return 0;
    }
    u128::from(bytes)
        .saturating_mul(8_000)
        .checked_div(u128::from(window_ms))
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::FastClientRateBook;
    use crate::platform::nss::{
        fast_n_runtime::{FastNKey, FastNSample, FastNSnapshot},
        fast_rate_contract::{FastRateBaseContract, FastRateClientContract},
        fast_s_runtime::{FastSKey, FastSSample},
    };
    use lanspeed_common::{DIR_TX, FAST_COUNTER_ABI_VERSION};

    fn n(bytes: u64) -> FastNSnapshot {
        FastNSnapshot {
            sample_ms: 1_000,
            valid_entries: 1,
            reset_generation: 1,
            entries: vec![FastNSample {
                key: FastNKey {
                    mac: [2, 0, 0, 0, 0, 1],
                    direction: DIR_TX,
                    ..FastNKey::default()
                },
                aggregate: crate::platform::nss::fast_counter::FastCounterAggregate {
                    abi_version: FAST_COUNTER_ABI_VERSION,
                    reset_generation: 1,
                    bytes,
                    packets: bytes / 10,
                    last_seen_ns: 1_000_000_000,
                },
                sample_ms: 1_000,
            }],
            ..FastNSnapshot::default()
        }
    }

    fn s(bytes: u64) -> crate::platform::nss::fast_s_runtime::FastSSnapshot {
        crate::platform::nss::fast_s_runtime::FastSSnapshot {
            sample_ms: 1_000,
            valid_entries: 1,
            reset_generation: 2,
            entries: vec![FastSSample {
                key: FastSKey {
                    mac: [2, 0, 0, 0, 0, 1],
                    direction: DIR_TX,
                    ..FastSKey::default()
                },
                aggregate: crate::platform::nss::fast_counter::FastCounterAggregate {
                    abi_version: FAST_COUNTER_ABI_VERSION,
                    reset_generation: 2,
                    bytes,
                    packets: bytes / 10,
                    last_seen_ns: 1_000_000_000,
                },
                sample_ms: 1_000,
            }],
            ..crate::platform::nss::fast_s_runtime::FastSSnapshot::default()
        }
    }

    fn contract(generation: u64) -> FastRateBaseContract {
        FastRateBaseContract::new(
            1,
            [FastRateClientContract {
                mac: [2, 0, 0, 0, 0, 1],
                identity_key: "client@lan".into(),
                attachment_generation: generation,
            }],
        )
    }

    #[test]
    fn publishes_only_mac_direction_rates_from_a_shared_window() {
        let mut book = FastClientRateBook::default();
        book.observe(&n(100), &s(50), 990, 1_010, 991, 1_011);
        let mut next_n = n(300);
        next_n.sample_ms = 2_000;
        next_n.entries[0].sample_ms = 2_000;
        let mut next_s = s(250);
        next_s.sample_ms = 2_000;
        next_s.entries[0].sample_ms = 2_000;
        book.observe(&next_n, &next_s, 1_990, 2_010, 1_991, 2_011);
        let sample = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(sample.fast_n_bps, 1_600);
        assert_eq!(sample.fast_s_bps, 1_600);
        assert_eq!(sample.fast_total_bps, 3_200);
        assert_eq!(sample.routed_l2_with_fcs_bps, 6_720);
        assert!(book.get([2, 0, 0, 0, 0, 2], DIR_TX).is_none());
        assert_eq!(book.invalid_windows(), 0);
    }

    #[test]
    fn uses_counter_progress_time_instead_of_batched_read_time() {
        let mut book = FastClientRateBook::default();
        let mut first_n = n(100);
        first_n.sample_ms = 1_100;
        first_n.entries[0].sample_ms = 1_000;
        let mut first_s = s(50);
        first_s.sample_ms = 1_100;
        first_s.entries[0].sample_ms = 1_000;
        book.observe(&first_n, &first_s, 1_090, 1_100, 1_091, 1_101);

        let mut next_n = n(300);
        next_n.sample_ms = 2_100;
        next_n.entries[0].sample_ms = 3_000;
        let mut next_s = s(250);
        next_s.sample_ms = 2_100;
        next_s.entries[0].sample_ms = 3_000;
        book.observe(&next_n, &next_s, 3_090, 3_100, 3_091, 3_101);

        let sample = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(sample.sample_ms, 3_000);
        assert_eq!(sample.window_ms, 2_000);
        assert_eq!(sample.fast_n_bps, 800);
        assert_eq!(sample.fast_s_bps, 800);
        assert_eq!(sample.fast_total_bps, 1_600);

        // A read that sees no new counter progress holds the valid event-rate
        // window instead of publishing a synthetic zero window.
        let mut held_n = next_n;
        held_n.sample_ms = 3_100;
        let mut held_s = next_s;
        held_s.sample_ms = 3_100;
        book.observe(&held_n, &held_s, 3_090, 3_100, 3_091, 3_101);
        assert_eq!(book.get([2, 0, 0, 0, 0, 1], DIR_TX), Some(sample));
        assert_eq!(book.invalid_windows(), 0);
    }

    #[test]
    fn fasts_only_progress_does_not_cut_a_pending_fastn_batch() {
        let mut book = FastClientRateBook::default();
        let mut first_n = n(100);
        first_n.entries[0].sample_ms = 1_000;
        let mut first_s = s(50);
        first_s.entries[0].sample_ms = 1_000;
        book.observe(&first_n, &first_s, 990, 1_000, 991, 1_001);

        let mut next_n = n(300);
        next_n.entries[0].sample_ms = 3_000;
        let mut next_s = s(250);
        next_s.entries[0].sample_ms = 2_000;
        book.observe(&next_n, &next_s, 2_990, 3_000, 2_991, 3_001);
        let published = book
            .get([2, 0, 0, 0, 0, 1], DIR_TX)
            .expect("first complete window");

        // FastS can advance between two batched FastN updates. That partial
        // read must not replace the completed combined window with a zero-N
        // or short-denominator sample.
        let mut s_only = next_s;
        s_only.sample_ms = 2_500;
        s_only.entries[0].sample_ms = 2_500;
        book.observe(&next_n, &s_only, 3_490, 3_500, 2_490, 2_501);
        assert_eq!(book.get([2, 0, 0, 0, 0, 1], DIR_TX), Some(published));
    }

    #[test]
    fn publishes_fastn_progress_with_an_unchanged_fasts_contribution() {
        let mut book = FastClientRateBook::default();
        let mut first_n = n(100);
        first_n.entries[0].sample_ms = 1_000;
        let mut first_s = s(50);
        first_s.entries[0].sample_ms = 1_000;
        book.observe(&first_n, &first_s, 990, 1_000, 991, 1_001);

        let mut next_n = n(300);
        next_n.sample_ms = 2_000;
        next_n.entries[0].sample_ms = 2_000;
        let mut unchanged_s = first_s;
        unchanged_s.sample_ms = 2_000;
        book.observe(&next_n, &unchanged_s, 1_990, 2_000, 1_991, 2_001);

        let sample = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(sample.fast_n_bps, 1_600);
        assert_eq!(sample.fast_s_bps, 0);
        assert_eq!(sample.fast_total_bps, 1_600);
    }

    #[test]
    fn publishes_confirmed_quiet_zero_without_rebasing_the_next_batch() {
        let mut book = FastClientRateBook::default();
        let first_n = n(100);
        let first_s = s(50);
        book.observe(&first_n, &first_s, 990, 1_000, 991, 1_001);

        let mut quiet_n = first_n.clone();
        quiet_n.sample_ms = 4_000;
        let mut quiet_s = first_s.clone();
        quiet_s.sample_ms = 4_000;
        book.observe(&quiet_n, &quiet_s, 3_990, 4_000, 3_991, 4_001);

        let zero = book
            .get([2, 0, 0, 0, 0, 1], DIR_TX)
            .expect("confirmed quiet zero");
        assert_eq!(zero.sample_ms, 4_000);
        assert_eq!(zero.window_ms, 2_999);
        assert_eq!(zero.fast_n_bps, 0);
        assert_eq!(zero.fast_s_bps, 0);
        assert_eq!(zero.fast_total_bps, 0);

        let mut resumed_n = n(500);
        resumed_n.sample_ms = 5_000;
        resumed_n.entries[0].sample_ms = 5_000;
        let mut resumed_s = s(250);
        resumed_s.sample_ms = 5_000;
        resumed_s.entries[0].sample_ms = 5_000;
        book.observe(&resumed_n, &resumed_s, 4_990, 5_000, 4_991, 5_001);
        let resumed = book
            .get([2, 0, 0, 0, 0, 1], DIR_TX)
            .expect("resumed non-zero window");
        assert!(resumed.fast_total_bps > 0);
    }

    #[test]
    fn publishes_a_fast_n_only_client_without_a_fast_s_key() {
        let mut book = FastClientRateBook::default();
        let mut first_n = n(100);
        first_n.entries[0].sample_ms = 1_000;
        book.observe(
            &first_n,
            &crate::platform::nss::fast_s_runtime::FastSSnapshot::default(),
            990,
            1_000,
            991,
            1_001,
        );
        let mut next_n = n(300);
        next_n.entries[0].sample_ms = 2_000;
        book.observe(
            &next_n,
            &crate::platform::nss::fast_s_runtime::FastSSnapshot::default(),
            1_990,
            2_000,
            1_991,
            2_001,
        );
        let sample = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(sample.fast_n_bps, 1_600);
        assert_eq!(sample.fast_s_bps, 0);
    }

    #[test]
    fn publishes_a_fast_s_only_client_without_a_fast_n_key() {
        let mut book = FastClientRateBook::default();
        let empty_n = FastNSnapshot::default();
        let mut first_s = s(100);
        first_s.entries[0].sample_ms = 1_000;
        book.observe(&empty_n, &first_s, 990, 1_000, 991, 1_001);
        let mut next_s = s(300);
        next_s.entries[0].sample_ms = 2_000;
        book.observe(
            &FastNSnapshot::default(),
            &next_s,
            1_990,
            2_000,
            1_991,
            2_001,
        );
        let sample = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(sample.fast_n_bps, 0);
        assert_eq!(sample.fast_s_bps, 1_600);
    }

    #[test]
    fn retains_a_seen_client_when_both_maps_are_quiet_then_publishes_zero_and_resumes() {
        let mut book = FastClientRateBook::default();
        let contract = contract(7);
        let first_n = n(100);
        let first_s = s(50);
        book.observe_with_contract(&first_n, &first_s, 990, 1_000, 991, 1_001, &contract);

        let mut empty_n = FastNSnapshot {
            sample_ms: 2_000,
            reset_generation: 1,
            ..FastNSnapshot::default()
        };
        let mut empty_s = crate::platform::nss::fast_s_runtime::FastSSnapshot {
            sample_ms: 2_000,
            reset_generation: 2,
            ..crate::platform::nss::fast_s_runtime::FastSSnapshot::default()
        };
        book.observe_with_contract(&empty_n, &empty_s, 1_990, 2_000, 1_991, 2_001, &contract);
        assert_eq!(book.get([2, 0, 0, 0, 0, 1], DIR_TX), None);

        empty_n.sample_ms = 4_000;
        empty_s.sample_ms = 4_000;
        book.observe_with_contract(&empty_n, &empty_s, 3_990, 4_000, 3_991, 4_001, &contract);
        let zero = book
            .get([2, 0, 0, 0, 0, 1], DIR_TX)
            .expect("quiet client keeps a numeric zero window");
        assert_eq!(zero.fast_total_bps, 0);

        let mut resumed_n = n(500);
        resumed_n.sample_ms = 5_000;
        resumed_n.entries[0].sample_ms = 5_000;
        let mut resumed_s = s(250);
        resumed_s.sample_ms = 5_000;
        resumed_s.entries[0].sample_ms = 5_000;
        book.observe_with_contract(
            &resumed_n, &resumed_s, 4_990, 5_000, 4_991, 5_001, &contract,
        );
        assert!(
            book.get([2, 0, 0, 0, 0, 1], DIR_TX)
                .expect("same attachment resumes from retained baseline")
                .fast_total_bps
                > 0
        );
    }

    #[test]
    fn observed_client_gets_a_confirmed_zero_for_the_never_seen_direction() {
        let mut book = FastClientRateBook::default();
        let contract = contract(7);
        let empty_s = crate::platform::nss::fast_s_runtime::FastSSnapshot {
            sample_ms: 1_000,
            reset_generation: 2,
            ..crate::platform::nss::fast_s_runtime::FastSSnapshot::default()
        };
        book.observe_with_contract(&n(100), &empty_s, 990, 1_000, 991, 1_001, &contract);

        let mut quiet_n = n(100);
        quiet_n.sample_ms = 4_000;
        quiet_n.entries[0].sample_ms = 1_000;
        let quiet_s = crate::platform::nss::fast_s_runtime::FastSSnapshot {
            sample_ms: 4_000,
            reset_generation: 2,
            ..crate::platform::nss::fast_s_runtime::FastSSnapshot::default()
        };
        book.observe_with_contract(&quiet_n, &quiet_s, 3_990, 4_000, 3_991, 4_001, &contract);

        let rx = book
            .get([2, 0, 0, 0, 0, 1], lanspeed_common::DIR_RX)
            .expect("opposite direction publishes numeric zero");
        assert_eq!(rx.fast_total_bps, 0);
        assert_eq!(rx.routed_l2_with_fcs_bps, 0);
    }

    #[test]
    fn idle_contract_client_gets_zero_even_when_never_present_in_either_map() {
        let mut book = FastClientRateBook::default();
        let mut clients = vec![FastRateClientContract {
            mac: [2, 0, 0, 0, 0, 1],
            identity_key: "client@lan".into(),
            attachment_generation: 7,
        }];
        clients.push(FastRateClientContract {
            mac: [2, 0, 0, 0, 0, 2],
            identity_key: "idle@lan".into(),
            attachment_generation: 3,
        });
        let contract = FastRateBaseContract::new(1, clients);
        let mut first_n = n(100);
        first_n.entries[0].sample_ms = 1_000;
        let mut first_s = s(50);
        first_s.entries[0].sample_ms = 1_000;
        book.observe_with_contract(&first_n, &first_s, 990, 1_000, 991, 1_001, &contract);

        let quiet_n = FastNSnapshot {
            sample_ms: 4_000,
            reset_generation: 1,
            ..FastNSnapshot::default()
        };
        let quiet_s = crate::platform::nss::fast_s_runtime::FastSSnapshot {
            sample_ms: 4_000,
            reset_generation: 2,
            ..crate::platform::nss::fast_s_runtime::FastSSnapshot::default()
        };
        book.observe_with_contract(&quiet_n, &quiet_s, 3_990, 4_000, 3_991, 4_001, &contract);
        assert_eq!(
            book.get([2, 0, 0, 0, 0, 2], lanspeed_common::DIR_TX)
                .expect("idle contract client zero")
                .fast_total_bps,
            0
        );
        assert_eq!(
            book.get([2, 0, 0, 0, 0, 2], lanspeed_common::DIR_RX)
                .expect("idle contract client rx zero")
                .fast_total_bps,
            0
        );
    }

    #[test]
    fn retained_client_baseline_is_dropped_when_attachment_changes() {
        let mut book = FastClientRateBook::default();
        let first = contract(7);
        book.observe_with_contract(&n(100), &s(50), 990, 1_000, 991, 1_001, &first);

        let replacement = FastRateBaseContract::new(
            2,
            [FastRateClientContract {
                mac: [2, 0, 0, 0, 0, 1],
                identity_key: "replacement@lan".into(),
                attachment_generation: 8,
            }],
        );
        let mut empty_n = FastNSnapshot {
            sample_ms: 4_000,
            reset_generation: 1,
            ..FastNSnapshot::default()
        };
        let mut empty_s = crate::platform::nss::fast_s_runtime::FastSSnapshot {
            sample_ms: 4_000,
            reset_generation: 2,
            ..crate::platform::nss::fast_s_runtime::FastSSnapshot::default()
        };
        book.observe_with_contract(&empty_n, &empty_s, 3_990, 4_000, 3_991, 4_001, &replacement);
        assert!(book.get([2, 0, 0, 0, 0, 1], DIR_TX).is_none());

        // A new counter baseline is required before the replacement can
        // publish a rate; the old attachment's bytes must never be reused.
        empty_n.sample_ms = 5_000;
        empty_s.sample_ms = 5_000;
        book.observe_with_contract(&empty_n, &empty_s, 4_990, 5_000, 4_991, 5_001, &replacement);
        assert!(book.get([2, 0, 0, 0, 0, 1], DIR_TX).is_none());
    }
}
