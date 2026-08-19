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
    fast_rate::{FastCounterSample, FastRateCoordinator},
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
    latest: BTreeMap<FastClientKey, FastClientSample>,
    invalid_windows: u64,
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
        if fast_n.truncated
            || fast_n.invalid_entries != 0
            || fast_s.truncated
            || fast_s.invalid_entries != 0
        {
            self.coordinators.values_mut().for_each(|book| book.clear());
            self.latest.clear();
            self.invalid_windows = self.invalid_windows.saturating_add(1);
            return;
        }

        let n = aggregate_n(fast_n);
        let s = aggregate_s(fast_s);
        let keys = n.keys().chain(s.keys()).copied().collect::<BTreeSet<_>>();
        self.coordinators.retain(|key, coordinator| {
            if keys.contains(key) {
                true
            } else {
                coordinator.clear();
                self.latest.remove(key);
                false
            }
        });

        for key in keys {
            // N and S are intentionally disjoint paths. A client may be
            // present in only one map during a perfectly valid window; the
            // absent source contributes a zero cumulative counter until it
            // appears. A real counter rollback still fails in the coordinator
            // and rewarms the key before publishing again.
            let n = n.get(&key).copied().unwrap_or(Aggregate {
                reset_generation: fast_n.reset_generation.max(1),
                ..Aggregate::default()
            });
            let s = s.get(&key).copied().unwrap_or(Aggregate {
                reset_generation: fast_s.reset_generation.max(1),
                ..Aggregate::default()
            });
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
                continue;
            }
            match coordinator.finish(n_sample, s_sample) {
                Ok(window) => {
                    self.latest.insert(
                        key,
                        FastClientSample {
                            sample_ms: window.end_ms,
                            window_ms: window.duration_ms(),
                            read_end_skew_ms: window.read_end_skew_ms,
                            fast_n_bps: bytes_to_bps(window.n_bytes, window.duration_ms()),
                            fast_s_bps: bytes_to_bps(window.s_bytes, window.duration_ms()),
                            fast_total_bps: bytes_to_bps(
                                window.total_bytes(),
                                window.duration_ms(),
                            ),
                            routed_l2_with_fcs_bps: bytes_to_bps(
                                l2_with_fcs_bytes(window),
                                window.duration_ms(),
                            ),
                        },
                    );
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
}

fn l2_with_fcs_bytes(window: super::fast_rate::FastWindow) -> u64 {
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

#[derive(Clone, Copy, Debug, Default)]
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
}
