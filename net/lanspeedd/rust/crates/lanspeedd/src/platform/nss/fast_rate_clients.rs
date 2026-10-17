//! Per-client same-window FastN+FastS shadow rates.
//!
//! The aggregate shadow is useful for diagnostics, but a routed substitute
//! must be keyed by the client MAC and direction. This book keeps one bounded
//! rolling counter history per MAC/direction and drops a window when either
//! source or its reset generation becomes invalid.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicU64, Ordering},
};

use lanspeed_common::{DIR_RX, DIR_TX};

use super::{
    fast_n_runtime::{FastNKey, FastNSnapshot},
    fast_rate::{FastCounterSample, FastWindow, FAST_WINDOW_MAX_READ_END_SKEW_MS},
    fast_rate_contract::FastRateBaseContract,
    fast_rate_rolling::FastRateRollingWindow,
    fast_s_runtime::{FastSKey, FastSSnapshot},
};

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FastClientKey {
    pub mac: [u8; 6],
    pub direction: u8,
}

/// Exact, non-overlapping raw counter deltas accumulated independently of
/// the overlapping display-rate window. Consumers compare cumulative totals
/// only within one epoch and attachment; skipped publications lose no bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastClientAccounting {
    pub total_bytes: u64,
    pub epoch: u64,
    pub start_ms: u64,
    pub end_ms: u64,
    pub attachment_generation: u64,
    pub byte_domain: crate::model::ByteDomain,
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
    pub accounting: Option<FastClientAccounting>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastClientRateBook {
    rolling: BTreeMap<FastClientKey, FastRateRollingWindow>,
    last_counters: BTreeMap<FastClientKey, ClientCounterPair>,
    bindings: BTreeMap<FastClientKey, ClientBinding>,
    latest: BTreeMap<FastClientKey, FastClientSample>,
    invalid_windows: u64,
    accounting: FastClientAccountingBook,
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
        self.accounting.observe(
            fast_n,
            fast_s,
            n_read_begin_ms,
            n_read_end_ms,
            s_read_begin_ms,
            s_read_end_ms,
            contract,
        );
        if fast_n.truncated
            || fast_n.invalid_entries != 0
            || fast_s.truncated
            || fast_s.invalid_entries != 0
        {
            self.rolling
                .values_mut()
                .for_each(FastRateRollingWindow::clear);
            self.last_counters.clear();
            self.bindings.clear();
            self.latest.clear();
            self.invalid_windows = self.invalid_windows.saturating_add(1);
            return;
        }

        let n = aggregate_n(fast_n);
        let s = aggregate_s(fast_s);
        let mut keys = n.keys().chain(s.keys()).copied().collect::<BTreeSet<_>>();
        keys.extend(self.rolling.keys().copied());
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
            // marker; the rolling book can then confirm a real quiet zero
            // without losing the cumulative baseline. A real counter rollback
            // still fails the rolling window and rewarms the key.
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
            let rolling = self.rolling.entry(key).or_default();
            let common_progress_ms = n.progress_ms.max(s.progress_ms);
            let sample_ms = if common_progress_ms == 0 {
                fast_n.sample_ms.max(fast_s.sample_ms)
            } else {
                common_progress_ms
            };
            let attachment_generation = contract
                .and_then(|contract| contract.client(key.mac))
                .map_or(0, |client| client.attachment_generation);
            let n_sample = FastCounterSample {
                sample_ms,
                progress_ms: n.progress_ms,
                source_present: n.source_present,
                read_begin_ms: n_read_begin_ms,
                read_end_ms: n_read_end_ms,
                attachment_generation,
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
                attachment_generation,
                reset_generation: s.reset_generation,
                bytes: s.bytes,
                packets: s.packets,
            };
            match rolling.observe(n_sample, s_sample) {
                Ok(window) => {
                    if let Some(window) = window {
                        self.latest.insert(key, client_sample(window));
                    }
                }
                Err(_) => {
                    self.latest.remove(&key);
                    self.invalid_windows = self.invalid_windows.saturating_add(1);
                }
            }
        }
    }

    pub(crate) const fn invalid_windows(&self) -> u64 {
        self.invalid_windows
    }

    pub(crate) fn clear(&mut self) {
        self.accounting.invalidate();
        self.rolling.clear();
        self.last_counters.clear();
        self.bindings.clear();
        self.latest.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.latest.len()
    }

    pub(crate) fn get(&self, mac: [u8; 6], direction: u8) -> Option<FastClientSample> {
        let key = FastClientKey { mac, direction };
        self.latest.get(&key).map(|sample| FastClientSample {
            accounting: self.accounting.get(key),
            ..*sample
        })
    }

    pub(crate) fn samples(&self) -> Vec<(FastClientKey, FastClientSample)> {
        self.latest
            .iter()
            .map(|(key, sample)| {
                (
                    *key,
                    FastClientSample {
                        accounting: self.accounting.get(*key),
                        ..*sample
                    },
                )
            })
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
            self.rolling.remove(&key);
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
        accounting: None,
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

// Raw keys must remain distinct: adding/removing an ECM connection changes a
// MAC aggregate even when no traffic moved. Only one key's consecutive stable
// cumulative observations can provide an exact byte delta.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum AccountingRawKey {
    N(FastNKey),
    S(FastSKey),
}

impl AccountingRawKey {
    fn packet_overhead(self) -> u64 {
        match self {
            Self::N(_) => 18,
            Self::S(_) => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AccountingRawCounter {
    bytes: u64,
    packets: u64,
    generation: u32,
    seen_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AccountingClient {
    binding: ClientBinding,
    value: FastClientAccounting,
    counters: BTreeMap<AccountingRawKey, AccountingRawCounter>,
    n_generation: u32,
    s_generation: u32,
}

// Epochs remain unique even when a worker is replaced within one daemon.
static NEXT_ACCOUNTING_EPOCH: AtomicU64 = AtomicU64::new(1);
// FastN keys contain an ECM connection generation; retain them until a
// bounded key-count eviction. FastS keys lack a per-entry incarnation, so a
// briefly missing key is retained for only this grace period.
const ACCOUNTING_MISSING_S_KEY_GRACE_MS: u64 = 30_000;
const ACCOUNTING_RAW_KEY_LIMIT: usize = lanspeed_common::ECM_FAST_COUNTERS_MAP_CAPACITY as usize
    + lanspeed_common::FAST_COUNTERS_MAP_CAPACITY as usize;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct FastClientAccountingBook {
    available: bool,
    clients: BTreeMap<FastClientKey, AccountingClient>,
}

impl FastClientAccountingBook {
    fn invalidate(&mut self) {
        self.available = false;
    }

    fn get(&self, key: FastClientKey) -> Option<FastClientAccounting> {
        self.available
            .then(|| self.clients.get(&key).map(|client| client.value))
            .flatten()
    }

    fn observe(
        &mut self,
        fast_n: &FastNSnapshot,
        fast_s: &FastSSnapshot,
        n_begin: u64,
        n_end: u64,
        s_begin: u64,
        s_end: u64,
        contract: Option<&FastRateBaseContract>,
    ) {
        if fast_n.truncated
            || fast_s.truncated
            || fast_n.invalid_entries != 0
            || fast_s.invalid_entries != 0
            || n_end < n_begin
            || s_end < s_begin
            || n_end.abs_diff(s_end) > FAST_WINDOW_MAX_READ_END_SKEW_MS
            || fast_n.sample_ms.abs_diff(fast_s.sample_ms) > FAST_WINDOW_MAX_READ_END_SKEW_MS
        {
            self.invalidate();
            return;
        }
        self.available = true;
        let now_ms = n_end.max(s_end).max(fast_n.sample_ms).max(fast_s.sample_ms);
        let mut current =
            BTreeMap::<FastClientKey, BTreeMap<AccountingRawKey, AccountingRawCounter>>::new();
        for entry in &fast_n.entries {
            if !matches!(entry.key.direction, DIR_TX | DIR_RX) {
                continue;
            }
            current
                .entry(FastClientKey {
                    mac: entry.key.mac,
                    direction: entry.key.direction,
                })
                .or_default()
                .insert(
                    AccountingRawKey::N(entry.key),
                    AccountingRawCounter {
                        bytes: entry.aggregate.bytes,
                        packets: entry.aggregate.packets,
                        generation: entry.aggregate.reset_generation,
                        seen_ms: now_ms,
                    },
                );
        }
        for entry in &fast_s.entries {
            if !matches!(entry.key.direction, DIR_TX | DIR_RX) {
                continue;
            }
            current
                .entry(FastClientKey {
                    mac: entry.key.mac,
                    direction: entry.key.direction,
                })
                .or_default()
                .insert(
                    AccountingRawKey::S(entry.key),
                    AccountingRawCounter {
                        bytes: entry.aggregate.bytes,
                        packets: entry.aggregate.packets,
                        generation: entry.aggregate.reset_generation,
                        seen_ms: now_ms,
                    },
                );
        }
        if let Some(contract) = contract {
            self.clients.retain(|key, value| {
                contract.client_matches(
                    key.mac,
                    &value.binding.identity_key,
                    value.binding.attachment_generation,
                )
            });
            current.retain(|key, _| contract.client(key.mac).is_some());
            for mac in contract.client_macs() {
                for direction in [DIR_TX, DIR_RX] {
                    current.entry(FastClientKey { mac, direction }).or_default();
                }
            }
        } else {
            // Tests and standalone shadow readers have no identity contract.
            self.clients.retain(|key, _| current.contains_key(key));
        }
        for (key, counters) in current {
            if counters.values().any(|counter| counter.generation == 0) {
                self.clients.remove(&key);
                continue;
            }
            let binding = contract.and_then(|value| value.client(key.mac)).map_or(
                ClientBinding {
                    identity_key: String::new(),
                    attachment_generation: 0,
                },
                |client| ClientBinding {
                    identity_key: client.identity_key.clone(),
                    attachment_generation: client.attachment_generation,
                },
            );
            let reset = self.clients.get(&key).is_none_or(|previous| {
                binding != previous.binding
                    || now_ms < previous.value.end_ms
                    || (fast_n.reset_generation != 0
                        && previous.n_generation != 0
                        && fast_n.reset_generation != previous.n_generation)
                    || (fast_s.reset_generation != 0
                        && previous.s_generation != 0
                        && fast_s.reset_generation != previous.s_generation)
                    || counters.iter().any(|(raw_key, counter)| {
                        previous.counters.get(raw_key).is_some_and(|old| {
                            counter.generation != old.generation
                                || counter.bytes < old.bytes
                                || counter.packets < old.packets
                        })
                    })
            });
            if reset {
                self.clients.insert(
                    key,
                    AccountingClient {
                        binding: binding.clone(),
                        value: FastClientAccounting {
                            total_bytes: 0,
                            epoch: NEXT_ACCOUNTING_EPOCH.fetch_add(1, Ordering::Relaxed),
                            start_ms: now_ms,
                            end_ms: now_ms,
                            attachment_generation: binding.attachment_generation,
                            byte_domain: crate::model::ByteDomain::L2WithFcs,
                        },
                        counters,
                        n_generation: fast_n.reset_generation,
                        s_generation: fast_s.reset_generation,
                    },
                );
                continue;
            }
            let previous = self.clients.get_mut(&key).expect("accounting baseline");
            if now_ms == previous.value.end_ms {
                continue;
            }
            let mut delta = Some(0u64);
            for (raw_key, counter) in &counters {
                if let Some(old) = previous.counters.get(raw_key).filter(|old| {
                    matches!(raw_key, AccountingRawKey::N(_))
                        || now_ms.saturating_sub(old.seen_ms) <= ACCOUNTING_MISSING_S_KEY_GRACE_MS
                }) {
                    delta = delta.and_then(|sum| {
                        let bytes = counter.bytes.checked_sub(old.bytes)?;
                        let overhead = counter
                            .packets
                            .checked_sub(old.packets)?
                            .checked_mul(raw_key.packet_overhead())?;
                        sum.checked_add(bytes)?.checked_add(overhead)
                    });
                }
            }
            if let Some(total) =
                delta.and_then(|delta| previous.value.total_bytes.checked_add(delta))
            {
                previous.value.total_bytes = total;
            } else {
                // Saturation must not masquerade as an exact delta.
                previous.value.epoch = NEXT_ACCOUNTING_EPOCH.fetch_add(1, Ordering::Relaxed);
                previous.value.total_bytes = 0;
                previous.value.start_ms = now_ms;
            }
            previous.value.end_ms = now_ms;
            previous.counters.retain(|raw_key, counter| {
                matches!(raw_key, AccountingRawKey::N(_))
                    || now_ms.saturating_sub(counter.seen_ms) <= ACCOUNTING_MISSING_S_KEY_GRACE_MS
            });
            previous.counters.extend(counters);
            if fast_n.reset_generation != 0 {
                previous.n_generation = fast_n.reset_generation;
            }
            if fast_s.reset_generation != 0 {
                previous.s_generation = fast_s.reset_generation;
            }
        }
        let count: usize = self
            .clients
            .values()
            .map(|client| client.counters.len())
            .sum();
        if count > ACCOUNTING_RAW_KEY_LIMIT {
            let mut retained = self
                .clients
                .iter()
                .flat_map(|(client_key, client)| {
                    client
                        .counters
                        .iter()
                        .map(move |(raw_key, counter)| (counter.seen_ms, *client_key, *raw_key))
                })
                .collect::<Vec<_>>();
            retained.sort_unstable();
            for (_, client_key, raw_key) in
                retained.into_iter().take(count - ACCOUNTING_RAW_KEY_LIMIT)
            {
                if let Some(client) = self.clients.get_mut(&client_key) {
                    client.counters.remove(&raw_key);
                }
            }
        }
    }
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

    fn accounting_observe(
        book: &mut super::FastClientAccountingBook,
        mut fast_n: FastNSnapshot,
        mut fast_s: crate::platform::nss::fast_s_runtime::FastSSnapshot,
        now_ms: u64,
        attachment: u64,
    ) -> super::FastClientAccounting {
        fast_n.sample_ms = now_ms;
        fast_s.sample_ms = now_ms;
        book.observe(
            &fast_n,
            &fast_s,
            now_ms,
            now_ms,
            now_ms,
            now_ms,
            Some(&contract(attachment)),
        );
        book.get(super::FastClientKey {
            mac: [2, 0, 0, 0, 0, 1],
            direction: DIR_TX,
        })
        .expect("bound accounting")
    }

    #[test]
    fn accounting_uses_adjacent_raw_deltas_without_integrating_rolling_rates() {
        let mut book = super::FastClientAccountingBook::default();
        let first = accounting_observe(&mut book, n(100), s(50), 1_000, 7);
        assert_eq!(first.total_bytes, 0);
        let second = accounting_observe(&mut book, n(300), s(250), 2_000, 7);
        assert_eq!(second.total_bytes, 200 + 20 * 18 + 200 + 20 * 4);
        let repeated = accounting_observe(&mut book, n(300), s(250), 2_000, 7);
        assert_eq!(repeated, second);
        let unchanged = accounting_observe(&mut book, n(300), s(250), 3_000, 7);
        assert_eq!(unchanged.total_bytes, second.total_bytes);
        let third = accounting_observe(&mut book, n(500), s(450), 4_000, 7);
        assert_eq!(
            third.total_bytes - first.total_bytes,
            2 * second.total_bytes
        );
        assert_eq!(third.epoch, first.epoch);
        assert_eq!(third.start_ms, 1_000);
        assert_eq!(third.end_ms, 4_000);
        assert_eq!(third.byte_domain, crate::model::ByteDomain::L2WithFcs);
    }

    #[test]
    fn accounting_connection_churn_does_not_count_an_added_keys_historical_bytes() {
        let mut book = super::FastClientAccountingBook::default();
        accounting_observe(&mut book, n(100), s(50), 1_000, 7);
        let mut with_new_connection = n(200);
        let mut new_key = n(100_000).entries[0];
        new_key.key.connection = 123;
        with_new_connection.entries.push(new_key);
        let second = accounting_observe(&mut book, with_new_connection.clone(), s(50), 2_000, 7);
        assert_eq!(second.total_bytes, 100 + 10 * 18);
        with_new_connection.entries.remove(0);
        with_new_connection.entries[0].aggregate.bytes += 100;
        with_new_connection.entries[0].aggregate.packets += 10;
        let third = accounting_observe(&mut book, with_new_connection, s(50), 3_000, 7);
        assert_eq!(third.epoch, second.epoch);
        assert_eq!(third.total_bytes - second.total_bytes, 100 + 10 * 18);
    }

    #[test]
    fn accounting_reset_and_attachment_change_rebaseline_in_a_new_epoch() {
        let mut book = super::FastClientAccountingBook::default();
        accounting_observe(&mut book, n(100), s(50), 1_000, 7);
        let before = accounting_observe(&mut book, n(300), s(250), 2_000, 7);
        let reset = accounting_observe(&mut book, n(20), s(10), 3_000, 7);
        assert_ne!(reset.epoch, before.epoch);
        assert_eq!(reset.total_bytes, 0);
        let moved = accounting_observe(&mut book, n(500), s(450), 4_000, 8);
        assert_ne!(moved.epoch, reset.epoch);
        assert_eq!(moved.total_bytes, 0);
        assert_eq!(moved.attachment_generation, 8);
        let mut new_epoch = n(700);
        new_epoch.reset_generation = 5;
        new_epoch.entries[0].aggregate.reset_generation = 5;
        let generation = accounting_observe(&mut book, new_epoch, s(650), 5_000, 8);
        assert_ne!(generation.epoch, moved.epoch);
        assert_eq!(generation.total_bytes, 0);
        let mut restarted_worker = super::FastClientAccountingBook::default();
        let restarted = accounting_observe(&mut restarted_worker, n(800), s(700), 6_000, 8);
        assert_ne!(restarted.epoch, generation.epoch);
    }

    #[test]
    fn accounting_invalid_read_hides_output_then_catches_up_from_confirmed_baseline() {
        let mut book = super::FastClientAccountingBook::default();
        let first = accounting_observe(&mut book, n(100), s(50), 1_000, 7);
        let mut invalid = s(250);
        invalid.invalid_entries = 1;
        book.observe(
            &n(300),
            &invalid,
            2_000,
            2_000,
            2_000,
            2_000,
            Some(&contract(7)),
        );
        assert!(!book.available);
        let recovered = accounting_observe(&mut book, n(500), s(450), 3_000, 7);
        assert_eq!(recovered.epoch, first.epoch);
        assert_eq!(recovered.total_bytes, 1_680);
        book.observe(
            &n(600),
            &s(550),
            4_000,
            4_000,
            4_500,
            4_500,
            Some(&contract(7)),
        );
        assert!(
            !book.available,
            "skewed read must not become accounting evidence"
        );
    }

    #[test]
    fn accounting_holds_quiet_keys_without_double_counting_and_bounds_missing_keys() {
        let mut book = super::FastClientAccountingBook::default();
        accounting_observe(&mut book, n(100), s(50), 1_000, 7);
        let mut empty_n = n(100);
        empty_n.entries.clear();
        let mut empty_s = s(50);
        empty_s.entries.clear();
        let held = accounting_observe(&mut book, empty_n.clone(), empty_s.clone(), 2_000, 7);
        assert_eq!(held.total_bytes, 0);
        let resumed = accounting_observe(&mut book, n(300), s(250), 3_000, 7);
        assert_eq!(resumed.total_bytes, 840);
        accounting_observe(&mut book, empty_n, empty_s, 34_000, 7);
        let expired = accounting_observe(&mut book, n(900), s(850), 35_000, 7);
        assert_eq!(
            expired.total_bytes,
            resumed.total_bytes + 600 + 60 * 18,
            "FastN generation-bound key catches up while expired FastS rebaselines"
        );
    }

    #[test]
    fn published_sample_carries_catchup_accounting_independent_of_rolling_hold() {
        let mut book = FastClientRateBook::default();
        let mut fast_n = n(100);
        let mut fast_s = s(50);
        book.observe_with_contract(&fast_n, &fast_s, 1_000, 1_000, 1_000, 1_000, &contract(7));
        fast_n.sample_ms = 3_000;
        fast_n.entries[0].aggregate.bytes = 300;
        fast_n.entries[0].aggregate.packets = 30;
        fast_n.entries[0].sample_ms = 3_000;
        fast_s.sample_ms = 3_000;
        fast_s.entries[0].aggregate.bytes = 250;
        fast_s.entries[0].aggregate.packets = 25;
        fast_s.entries[0].sample_ms = 3_000;
        book.observe_with_contract(&fast_n, &fast_s, 3_000, 3_000, 3_000, 3_000, &contract(7));
        let published = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(published.accounting.unwrap().total_bytes, 840);
        fast_n.sample_ms = 4_000;
        fast_s.sample_ms = 4_000;
        fast_s.entries[0].aggregate.bytes += 100;
        fast_s.entries[0].aggregate.packets += 10;
        fast_s.entries[0].sample_ms = 4_000;
        book.observe_with_contract(&fast_n, &fast_s, 4_000, 4_000, 4_000, 4_000, &contract(7));
        let next = book
            .samples()
            .into_iter()
            .find(|(key, _)| key.direction == DIR_TX)
            .unwrap()
            .1;
        let accounting = next.accounting.unwrap();
        assert_eq!(accounting.total_bytes, 980);
        assert_eq!(accounting.epoch, published.accounting.unwrap().epoch);
        assert_eq!(accounting.end_ms, 4_000);
        // A lost intermediate worker notice is recovered by subtracting the
        // last consumed accounting total, never by integrating either rate.
        assert_eq!(accounting.total_bytes - 0, 980);
    }

    #[test]
    fn publishes_only_mac_direction_rates_from_a_shared_window() {
        let mut book = FastClientRateBook::default();
        book.observe(&n(100), &s(50), 990, 1_010, 991, 1_011);
        let mut next_n = n(300);
        next_n.sample_ms = 3_000;
        next_n.entries[0].sample_ms = 3_000;
        let mut next_s = s(250);
        next_s.sample_ms = 3_000;
        next_s.entries[0].sample_ms = 3_000;
        book.observe(&next_n, &next_s, 2_990, 3_010, 2_991, 3_011);
        let sample = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(sample.window_ms, 2_000);
        assert_eq!(sample.fast_n_bps, 800);
        assert_eq!(sample.fast_s_bps, 800);
        assert_eq!(sample.fast_total_bps, 1_600);
        assert_eq!(sample.routed_l2_with_fcs_bps, 3_360);
        assert!(book.get([2, 0, 0, 0, 0, 2], DIR_TX).is_none());
        assert_eq!(book.invalid_windows(), 0);
    }

    #[test]
    fn uses_completed_read_time_instead_of_batched_progress_time() {
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
        assert_eq!(sample.sample_ms, 3_100);
        assert_eq!(sample.window_ms, 2_000);
        assert_eq!(sample.fast_n_bps, 800);
        assert_eq!(sample.fast_s_bps, 800);
        assert_eq!(sample.fast_total_bps, 1_600);

        // A read that sees no new counter progress keeps the bytes in an
        // overlapping read-clock window instead of republishing a short
        // event-clock spike.
        let mut held_n = next_n;
        held_n.sample_ms = 4_100;
        let mut held_s = next_s;
        held_s.sample_ms = 4_100;
        book.observe(&held_n, &held_s, 4_090, 4_100, 4_091, 4_101);
        let held = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(held.window_ms, 3_000);
        assert!(held.fast_total_bps < sample.fast_total_bps);
        assert!(held.fast_total_bps > 0);
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

        // FastS can advance between two batched FastN updates. Both maps are
        // still read together, so the rolling denominator must grow instead
        // of being shortened to the FastS progress timestamp.
        let mut s_only = next_s;
        s_only.sample_ms = 2_500;
        s_only.entries[0].sample_ms = 2_500;
        book.observe(&next_n, &s_only, 3_490, 3_500, 3_491, 3_501);
        let rolled = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(rolled.window_ms, 2_500);
        assert!(rolled.fast_total_bps < published.fast_total_bps);
        assert!(rolled.fast_total_bps > 0);
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
        next_n.sample_ms = 3_000;
        next_n.entries[0].sample_ms = 3_000;
        let mut unchanged_s = first_s;
        unchanged_s.sample_ms = 3_000;
        book.observe(&next_n, &unchanged_s, 2_990, 3_000, 2_991, 3_001);

        let sample = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(sample.fast_n_bps, 800);
        assert_eq!(sample.fast_s_bps, 0);
        assert_eq!(sample.fast_total_bps, 800);
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
        assert_eq!(zero.window_ms, 3_000);
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
        next_n.entries[0].sample_ms = 3_000;
        book.observe(
            &next_n,
            &crate::platform::nss::fast_s_runtime::FastSSnapshot::default(),
            2_990,
            3_000,
            2_991,
            3_001,
        );
        let sample = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(sample.fast_n_bps, 800);
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
        next_s.entries[0].sample_ms = 3_000;
        book.observe(
            &FastNSnapshot::default(),
            &next_s,
            2_990,
            3_000,
            2_991,
            3_001,
        );
        let sample = book.get([2, 0, 0, 0, 0, 1], DIR_TX).unwrap();
        assert_eq!(sample.fast_n_bps, 0);
        assert_eq!(sample.fast_s_bps, 800);
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
