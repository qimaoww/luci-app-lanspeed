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
            let (Some(n), Some(s)) = (n.get(&key), s.get(&key)) else {
                self.coordinators.entry(key).or_default().clear();
                self.latest.remove(&key);
                continue;
            };
            let coordinator = self.coordinators.entry(key).or_default();
            let n_sample = FastCounterSample {
                sample_ms: fast_n.sample_ms,
                read_begin_ms: n_read_begin_ms,
                read_end_ms: n_read_end_ms,
                attachment_generation: 0,
                reset_generation: n.2,
                bytes: n.0,
                packets: n.1,
            };
            let s_sample = FastCounterSample {
                sample_ms: fast_s.sample_ms,
                read_begin_ms: s_read_begin_ms,
                read_end_ms: s_read_end_ms,
                attachment_generation: 0,
                reset_generation: s.2,
                bytes: s.0,
                packets: s.1,
            };
            if !coordinator.has_start() && coordinator.begin(n_sample, s_sample).is_ok() {
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

type Aggregate = (u64, u64, u32);

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
) {
    result
        .entry(key)
        .and_modify(|value| {
            value.0 = value.0.saturating_add(bytes);
            value.1 = value.1.saturating_add(packets);
            if value.2 != reset_generation {
                value.2 = 0;
            }
        })
        .or_insert((bytes, packets, reset_generation));
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
}
