use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs, io,
    mem::size_of,
    os::fd::AsFd,
    path::Path,
    ptr,
};

use aya::{
    maps::{Array, HashMap, IterableMap, Map, MapData, PerCpuHashMap, RingBuf},
    programs::{kprobe::KProbeLinkId, KProbe},
    Ebpf, EbpfLoader, Pod,
};
use lanspeed_common::{
    EcmCounters, EcmCountersUpdatedEvent, EcmEventStats, EcmKey, EcmLayout, EcmSourceStats,
    FastCounterValue, DIR_RX, DIR_TX, ECM_CLIENTS_MAP_NAME, ECM_EVENT_RINGBUF_MAP_NAME,
    ECM_EVENT_STATS_MAP_NAME, ECM_FAST_COUNTERS_MAP_CAPACITY, ECM_FAST_COUNTERS_MAP_NAME,
    ECM_LAYOUT_MAP_NAME, ECM_NSS_ENTER_NETDEV_V4_PROGRAM_NAME,
    ECM_NSS_ENTER_NETDEV_V6_PROGRAM_NAME, ECM_NSS_ENTER_SYNC_MANY_V4_PROGRAM_NAME,
    ECM_NSS_ENTER_SYNC_MANY_V6_PROGRAM_NAME, ECM_NSS_EXIT_NETDEV_V4_PROGRAM_NAME,
    ECM_NSS_EXIT_NETDEV_V6_PROGRAM_NAME, ECM_NSS_EXIT_SYNC_MANY_V4_PROGRAM_NAME,
    ECM_NSS_EXIT_SYNC_MANY_V6_PROGRAM_NAME, ECM_SOURCE_STATS_MAP_NAME, ECM_UPDATE_PROGRAM_NAME,
    MAX_CLIENTS,
};

use crate::{
    identity::{ClientIdentity, IdentityTable},
    merge_split_btf,
    platform::counters::TrafficCounters,
};

use crate::platform::fast_counter_map::{stable_fast_counter_pair, FAST_COUNTER_MAP_READ_RETRIES};

pub const ECM_BTF_PATH: &str = "/sys/kernel/btf/ecm";
pub const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
pub const ECM_UPDATE_FUNCTION: &str = "ecm_db_connection_data_totals_update";
pub const ECM_BPF_OBJECT_LOAD_STAGE: &str = "ecm_bpf_object_load";
pub const ECM_BPF_OBJECT_PATH: &str = "/usr/lib/bpf/lanspeed-ebpf-ecm";
pub const ECM_BPF_LAYOUT_STAGE: &str = "ecm_bpf_btf_layout";
pub const ECM_BPF_PROGRAM_LOAD_STAGE: &str = "ecm_bpf_program_load";
pub const ECM_BPF_ATTACH_STAGE: &str = "ecm_bpf_kprobe_attach";
pub const ECM_BPF_MAP_READ_STAGE: &str = "ecm_bpf_map_read";
pub const ECM_BPF_DETACH_STAGE: &str = "ecm_bpf_kprobe_detach";
pub const KALLSYMS_PATH: &str = "/proc/kallsyms";
pub const ECM_RATE_HOLD_MS: u64 = 2_500;
const FLOW_RETENTION_MS: u64 = 60_000;
pub const ECM_EVENT_CLOCK_MAX_LAG_MS: u64 = 1_500;
pub const ECM_EVENT_RATE_MAX_WINDOW_MS: u64 = 5_000;
const RATE_MEDIAN_SAMPLES: usize = 3;
const ECM_MAP_STABLE_READ_ATTEMPTS: usize = 3;
const EVENT_SOURCE_BUCKETS: usize = 5;
const EVENT_INTERVAL_BUCKETS: usize = 5;
const BTF_KIND_INT: u32 = 1;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_DECL_TAG: u32 = 17;
const BTF_KIND_ENUM64: u32 = 19;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NssCallbackSpec {
    symbol: &'static str,
    enter_program: &'static str,
    exit_program: &'static str,
}

const NSS_CALLBACK_SPECS: [NssCallbackSpec; 4] = [
    NssCallbackSpec {
        symbol: "ecm_nss_ipv4_connection_sync_many_callback",
        enter_program: ECM_NSS_ENTER_SYNC_MANY_V4_PROGRAM_NAME,
        exit_program: ECM_NSS_EXIT_SYNC_MANY_V4_PROGRAM_NAME,
    },
    NssCallbackSpec {
        symbol: "ecm_nss_ipv6_connection_sync_many_callback",
        enter_program: ECM_NSS_ENTER_SYNC_MANY_V6_PROGRAM_NAME,
        exit_program: ECM_NSS_EXIT_SYNC_MANY_V6_PROGRAM_NAME,
    },
    NssCallbackSpec {
        symbol: "ecm_nss_ipv4_net_dev_callback",
        enter_program: ECM_NSS_ENTER_NETDEV_V4_PROGRAM_NAME,
        exit_program: ECM_NSS_EXIT_NETDEV_V4_PROGRAM_NAME,
    },
    NssCallbackSpec {
        symbol: "ecm_nss_ipv6_net_dev_callback",
        enter_program: ECM_NSS_ENTER_NETDEV_V6_PROGRAM_NAME,
        exit_program: ECM_NSS_EXIT_NETDEV_V6_PROGRAM_NAME,
    },
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawEcmSample {
    pub key: EcmKey,
    pub counters: EcmCounters,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EcmMapRead {
    pub entries: Vec<RawEcmSample>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawEcmFastCounterSample {
    pub key: EcmKey,
    pub first: Vec<FastCounterValue>,
    pub second: Vec<FastCounterValue>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EcmFastCounterMapRead {
    pub entries: Vec<RawEcmFastCounterSample>,
    pub truncated: bool,
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct EcmFastCounterKey(EcmKey);

#[derive(Clone, Copy)]
#[repr(transparent)]
struct EcmFastCounterValue(FastCounterValue);

unsafe impl Pod for EcmFastCounterKey {}
unsafe impl Pod for EcmFastCounterValue {}

/// Read-only duplicate of the ECM FastN map for the bounded rate worker.
pub struct EcmFastCounterMapReader {
    counters: PerCpuHashMap<MapData, EcmFastCounterKey, EcmFastCounterValue>,
}

impl EcmFastCounterMapReader {
    pub fn read(&self) -> Result<EcmFastCounterMapRead, EcmBpfRuntimeError> {
        let mut entries = Vec::new();
        let mut truncated = false;
        for key in self.counters.keys() {
            let key = match key {
                Ok(key) => key,
                Err(aya::maps::MapError::KeyNotFound) => continue,
                Err(error) => {
                    return Err(EcmBpfRuntimeError::new(
                        ECM_BPF_MAP_READ_STAGE,
                        error.to_string(),
                    ));
                }
            };
            if entries.len() >= ECM_FAST_COUNTERS_MAP_CAPACITY as usize {
                truncated = true;
                break;
            }
            let mut first = Vec::new();
            let mut second = Vec::new();
            for _ in 0..FAST_COUNTER_MAP_READ_RETRIES {
                first = self
                    .counters
                    .get(&key, 0)
                    .map_err(|error| {
                        EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string())
                    })?
                    .iter()
                    .map(|value| value.0)
                    .collect();
                second = self
                    .counters
                    .get(&key, 0)
                    .map_err(|error| {
                        EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string())
                    })?
                    .iter()
                    .map(|value| value.0)
                    .collect();
                if stable_fast_counter_pair(&first, &second) {
                    break;
                }
            }
            entries.push(RawEcmFastCounterSample {
                key: key.0,
                first,
                second,
            });
        }
        truncated |= entries.len() == ECM_FAST_COUNTERS_MAP_CAPACITY as usize;
        Ok(EcmFastCounterMapRead { entries, truncated })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcmBpfClientSample {
    pub mac: String,
    pub identity_key: String,
    pub zone: String,
    pub interface: String,
    pub ips: Vec<String>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_bps: u64,
    pub rx_bps: u64,
    pub sample_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EcmBpfFreshRate {
    pub tx_bps: u64,
    pub rx_bps: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EcmBpfSnapshot {
    pub clients: Vec<EcmBpfClientSample>,
    /// Event-clock rates produced by counters that progressed in this map
    /// snapshot. Held rates deliberately stay in `clients` only.
    pub fresh_rates: BTreeMap<String, EcmBpfFreshRate>,
    pub coverage_delta: TrafficCounters,
    pub coverage_deltas: BTreeMap<String, TrafficCounters>,
    pub coverage_start_ms: Option<u64>,
    pub coverage_end_ms: u64,
    pub coverage_ready: bool,
    pub sample_ms: u64,
    pub map_entries: usize,
    pub matched_entries: usize,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
struct FlowKey {
    connection: u64,
    generation: u32,
    direction: u8,
    mac: [u8; 6],
}

impl From<EcmKey> for FlowKey {
    fn from(value: EcmKey) -> Self {
        Self {
            connection: value.connection,
            generation: value.generation,
            direction: value.direction,
            mac: value.mac,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct FlowBaseline {
    identity_key: Option<String>,
    bytes: u64,
    packets: u64,
    last_progress_sample_ms: u64,
    last_progress_event_ms: u64,
    event_clock_valid: bool,
    last_seen_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct PublishedRate {
    bps: u64,
    end_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct FlowRateHistory {
    samples: [u64; RATE_MEDIAN_SAMPLES],
    len: u8,
    next: u8,
}

impl FlowRateHistory {
    fn push(&mut self, bps: u64) -> u64 {
        self.samples[usize::from(self.next)] = bps;
        self.next = (self.next + 1) % RATE_MEDIAN_SAMPLES as u8;
        if usize::from(self.len) < RATE_MEDIAN_SAMPLES {
            self.len += 1;
        }
        if usize::from(self.len) < RATE_MEDIAN_SAMPLES {
            return bps;
        }
        let mut ordered = self.samples;
        ordered.sort_unstable();
        ordered[RATE_MEDIAN_SAMPLES / 2]
    }
}

#[derive(Clone, Debug, Default)]
struct FoldedClient {
    tx_bytes: u64,
    rx_bytes: u64,
    tx_bps: u64,
    rx_bps: u64,
    fresh_tx_bps: u64,
    fresh_rx_bps: u64,
    last_seen_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct EcmBpfSnapshotCollector {
    baselines: BTreeMap<FlowKey, FlowBaseline>,
    published: BTreeMap<FlowKey, PublishedRate>,
    rate_histories: BTreeMap<FlowKey, FlowRateHistory>,
    last_complete: Option<EcmBpfSnapshot>,
}

impl EcmBpfSnapshotCollector {
    pub fn reset(&mut self) {
        self.baselines.clear();
        self.published.clear();
        self.rate_histories.clear();
        self.last_complete = None;
    }

    pub fn last_complete(&self) -> Option<&EcmBpfSnapshot> {
        self.last_complete.as_ref()
    }

    pub fn convert(
        &mut self,
        read: EcmMapRead,
        identities: &IdentityTable,
        now_ms: u64,
    ) -> EcmBpfSnapshot {
        let map_entries = read.entries.len();
        if read.truncated {
            // A partial traversal cannot become a cumulative baseline: doing so
            // would make omitted keys look like new lifetime bytes on the next
            // read. Invalidate rates now, require one complete read to warm a
            // new baseline, and only publish deltas from the following read.
            self.baselines.clear();
            self.published.clear();
            self.rate_histories.clear();
            self.last_complete = None;
            return EcmBpfSnapshot {
                coverage_end_ms: now_ms,
                sample_ms: now_ms,
                map_entries,
                truncated: true,
                ..EcmBpfSnapshot::default()
            };
        }
        let previous_sample_ms = self
            .last_complete
            .as_ref()
            .map(|snapshot| snapshot.sample_ms);
        let mut coverage_ready = previous_sample_ms.is_some();
        let mut current = BTreeMap::<FlowKey, (EcmCounters, Option<String>)>::new();
        let mut coverage_delta = TrafficCounters::default();
        let mut coverage_deltas = BTreeMap::<String, TrafficCounters>::new();
        for raw in read.entries {
            if raw.key.direction != DIR_TX && raw.key.direction != DIR_RX {
                continue;
            }
            let identity_key = unique_identity_for_mac(identities, raw.key.mac)
                .map(|identity| identity.key.to_string());
            current.insert(raw.key.into(), (raw.counters, identity_key));
        }

        for (key, (counters, identity_key)) in &current {
            let event_ms = (counters.last_seen / 1_000_000).min(now_ms);
            let previous = self.baselines.get(key).cloned();
            let delta = match previous.as_ref() {
                Some(previous)
                    if previous.identity_key.as_ref() == identity_key.as_ref()
                        && counters.bytes >= previous.bytes
                        && counters.packets >= previous.packets =>
                {
                    Some((
                        counters.bytes - previous.bytes,
                        counters.packets - previous.packets,
                        previous.last_progress_sample_ms,
                        Some((previous.last_progress_event_ms, previous.event_clock_valid)),
                    ))
                }
                Some(_) => {
                    coverage_ready = false;
                    self.published.remove(key);
                    self.rate_histories.remove(key);
                    None
                }
                // This runtime owns the map and every entry starts at zero. The
                // first complete read is an unknown-time baseline; a later new
                // generation contains traffic since the preceding map snapshot.
                None => previous_sample_ms
                    .map(|sample_ms| (counters.bytes, counters.packets, sample_ms, None)),
            };
            if let Some((delta_bytes, delta_packets, delta_start_ms, previous_event_ms)) = delta {
                if (delta_bytes != 0 || delta_packets != 0) && identity_key.is_some() {
                    let client_delta = coverage_deltas
                        .entry(identity_key.as_ref().expect("identity checked").clone())
                        .or_default();
                    if key.direction == DIR_TX {
                        coverage_delta.tx_bytes =
                            coverage_delta.tx_bytes.saturating_add(delta_bytes);
                        coverage_delta.tx_packets =
                            coverage_delta.tx_packets.saturating_add(delta_packets);
                        client_delta.tx_bytes = client_delta.tx_bytes.saturating_add(delta_bytes);
                        client_delta.tx_packets =
                            client_delta.tx_packets.saturating_add(delta_packets);
                    } else {
                        coverage_delta.rx_bytes =
                            coverage_delta.rx_bytes.saturating_add(delta_bytes);
                        coverage_delta.rx_packets =
                            coverage_delta.rx_packets.saturating_add(delta_packets);
                        client_delta.rx_bytes = client_delta.rx_bytes.saturating_add(delta_bytes);
                        client_delta.rx_packets =
                            client_delta.rx_packets.saturating_add(delta_packets);
                    }
                    // ECM emits cumulative increments roughly once per NSS
                    // sync round. Its kprobe timestamp gives the actual delta
                    // window even when the daemon poll cuts two connections at
                    // different points in that round. A map lookup can observe
                    // counters and last_seen from adjacent writes, so only use
                    // the event clock while it is monotonic and fresh.
                    let collector_window_ms = now_ms.saturating_sub(delta_start_ms);
                    let event_window_ms = previous_event_ms
                        .filter(|(previous, valid)| {
                            *valid && *previous != 0 && event_ms > *previous
                        })
                        .map(|(previous, _)| event_ms - previous)
                        .filter(|window| *window <= ECM_EVENT_RATE_MAX_WINDOW_MS)
                        .filter(|_| now_ms.saturating_sub(event_ms) < ECM_EVENT_CLOCK_MAX_LAG_MS);
                    let window_ms = event_window_ms.unwrap_or(collector_window_ms);
                    if window_ms != 0 {
                        let wire_bytes =
                            delta_bytes.saturating_add(delta_packets.saturating_mul(4));
                        let raw_bps = bits_per_second(wire_bytes, window_ms);
                        let bps = self.rate_histories.entry(*key).or_default().push(raw_bps);
                        self.published.insert(
                            *key,
                            PublishedRate {
                                bps,
                                end_ms: now_ms,
                            },
                        );
                    }
                }
            }
            if identity_key.is_none() {
                self.published.remove(key);
                self.rate_histories.remove(key);
            }
            let progressed = previous.as_ref().is_none_or(|value| {
                value.bytes != counters.bytes || value.packets != counters.packets
            });
            let current_event_clock_valid = event_ms != 0
                && now_ms.saturating_sub(event_ms) < ECM_EVENT_CLOCK_MAX_LAG_MS
                && previous
                    .as_ref()
                    .is_none_or(|value| event_ms > value.last_progress_event_ms);
            self.baselines.insert(
                *key,
                FlowBaseline {
                    identity_key: identity_key.clone(),
                    bytes: counters.bytes,
                    packets: counters.packets,
                    last_progress_sample_ms: if progressed {
                        now_ms
                    } else {
                        previous
                            .as_ref()
                            .map_or(now_ms, |value| value.last_progress_sample_ms)
                    },
                    last_progress_event_ms: if progressed && current_event_clock_valid {
                        event_ms
                    } else {
                        previous
                            .as_ref()
                            .map_or(event_ms, |value| value.last_progress_event_ms)
                    },
                    event_clock_valid: if progressed {
                        current_event_clock_valid
                    } else {
                        previous
                            .as_ref()
                            .is_none_or(|value| value.event_clock_valid)
                    },
                    last_seen_ms: event_ms,
                },
            );
        }

        self.baselines.retain(|key, baseline| {
            current.contains_key(key)
                || now_ms.saturating_sub(baseline.last_seen_ms) <= FLOW_RETENTION_MS
        });
        self.published.retain(|key, rate| {
            self.baselines.contains_key(key)
                && now_ms.saturating_sub(rate.end_ms) <= ECM_RATE_HOLD_MS
        });
        self.rate_histories
            .retain(|key, _| self.baselines.contains_key(key));

        let mut folded = BTreeMap::<String, FoldedClient>::new();
        for (key, (counters, identity_key)) in &current {
            let Some(identity_key) = identity_key else {
                continue;
            };
            let client = folded.entry(identity_key.clone()).or_default();
            let total = counters
                .bytes
                .saturating_add(counters.packets.saturating_mul(4));
            let rate = self.published.get(key).map_or(0, |value| value.bps);
            let fresh_rate = self
                .published
                .get(key)
                .filter(|value| value.end_ms == now_ms)
                .map_or(0, |value| value.bps);
            if key.direction == DIR_TX {
                client.tx_bytes = client.tx_bytes.saturating_add(total);
                client.tx_bps = client.tx_bps.saturating_add(rate);
                client.fresh_tx_bps = client.fresh_tx_bps.saturating_add(fresh_rate);
            } else {
                client.rx_bytes = client.rx_bytes.saturating_add(total);
                client.rx_bps = client.rx_bps.saturating_add(rate);
                client.fresh_rx_bps = client.fresh_rx_bps.saturating_add(fresh_rate);
            }
            client.last_seen_ms = client
                .last_seen_ms
                .max((counters.last_seen / 1_000_000).min(now_ms));
        }

        let fresh_rates = folded
            .iter()
            .filter_map(|(identity_key, folded)| {
                (folded.fresh_tx_bps != 0 || folded.fresh_rx_bps != 0).then(|| {
                    (
                        identity_key.clone(),
                        EcmBpfFreshRate {
                            tx_bps: folded.fresh_tx_bps,
                            rx_bps: folded.fresh_rx_bps,
                        },
                    )
                })
            })
            .collect();
        let clients = folded
            .into_iter()
            .filter_map(|(identity_key, folded)| {
                let identity = identities
                    .iter()
                    .find(|identity| identity.key.to_string() == identity_key)?;
                Some(client_sample(identity, identity_key, folded, now_ms))
            })
            .collect::<Vec<_>>();
        let snapshot = EcmBpfSnapshot {
            matched_entries: current
                .values()
                .filter(|(_, identity_key)| identity_key.is_some())
                .count(),
            clients,
            fresh_rates,
            coverage_delta,
            coverage_deltas,
            coverage_start_ms: coverage_ready.then_some(previous_sample_ms).flatten(),
            coverage_end_ms: now_ms,
            coverage_ready,
            sample_ms: now_ms,
            map_entries,
            truncated: read.truncated,
        };
        self.last_complete = Some(snapshot.clone());
        snapshot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcmBpfRuntimeError {
    stage: &'static str,
    message: String,
}

impl EcmBpfRuntimeError {
    fn new(stage: &'static str, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
        }
    }

    pub const fn stage(&self) -> &'static str {
        self.stage
    }
}

impl fmt::Display for EcmBpfRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EcmBpfRuntimeError {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct LayoutValue(EcmLayout);

#[derive(Clone, Copy)]
#[repr(transparent)]
struct MapKey(EcmKey);

#[derive(Clone, Copy)]
#[repr(transparent)]
struct MapValue(EcmCounters);

unsafe impl Pod for LayoutValue {}
unsafe impl Pod for MapKey {}
unsafe impl Pod for MapValue {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct SourceStatsValue(EcmSourceStats);

unsafe impl Pod for SourceStatsValue {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct EventStatsValue(EcmEventStats);

unsafe impl Pod for EventStatsValue {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EcmEventHintTelemetry {
    pub(crate) event_received: u64,
    pub(crate) event_coalesced: u64,
    pub(crate) event_invalid: u64,
    pub(crate) event_source_counts: [u64; EVENT_SOURCE_BUCKETS],
    pub(crate) event_interval_histogram: [u64; EVENT_INTERVAL_BUCKETS],
    pub(crate) event_last_timestamp_ns: Option<u64>,
    pub(crate) event_last_sequence: Option<u64>,
}

pub(crate) struct EcmEventHintReader {
    ringbuf: RingBuf<MapData>,
    telemetry: EcmEventHintTelemetry,
}

impl EcmEventHintReader {
    pub(crate) fn drain(&mut self, budget: usize) -> u64 {
        let mut received = 0u64;
        for _ in 0..budget {
            let Some(item) = self.ringbuf.next() else {
                break;
            };
            let event = decode_event_hint(&item);
            drop(item);
            let Some(event) = event else {
                self.telemetry.event_invalid = self.telemetry.event_invalid.saturating_add(1);
                continue;
            };
            received = received.saturating_add(1);
            self.telemetry.event_received = self.telemetry.event_received.saturating_add(1);
            let source_bucket = event_source_bucket(event.source);
            self.telemetry.event_source_counts[source_bucket] =
                self.telemetry.event_source_counts[source_bucket].saturating_add(1);
            if let Some(previous) = self.telemetry.event_last_timestamp_ns {
                if event.timestamp_ns > previous {
                    let interval_bucket =
                        event_interval_bucket(event.timestamp_ns.saturating_sub(previous));
                    self.telemetry.event_interval_histogram[interval_bucket] =
                        self.telemetry.event_interval_histogram[interval_bucket].saturating_add(1);
                }
            }
            self.telemetry.event_last_timestamp_ns = Some(event.timestamp_ns);
            self.telemetry.event_last_sequence = Some(event.sequence);
        }
        received
    }

    pub(crate) const fn telemetry(&self) -> EcmEventHintTelemetry {
        self.telemetry
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EcmBpfHealth {
    pub object_loaded: bool,
    pub attached: bool,
    pub map_read_attempted: bool,
    pub map_read_ok: bool,
    pub fresh_snapshot: bool,
    pub last_complete_snapshot_ms: Option<u64>,
    pub snapshot_clients: usize,
    pub map_entries: usize,
    pub map_capacity: usize,
    pub matched_entries: usize,
    pub map_iteration_truncated: bool,
    pub nss_context_callbacks: Vec<String>,
    pub source_stats: EcmSourceStats,
    pub event_stats: EcmEventStats,
    pub event_received: u64,
    pub event_coalesced: u64,
    pub event_invalid: u64,
    pub event_source_counts: [u64; EVENT_SOURCE_BUCKETS],
    pub event_interval_histogram: [u64; EVENT_INTERVAL_BUCKETS],
    pub event_last_timestamp_ns: Option<u64>,
    pub event_last_sequence: Option<u64>,
    pub event_last_age_ms: Option<u64>,
    pub layout: Option<EcmLayout>,
    pub error_stage: Option<&'static str>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct EcmBpfCollectionCheckpoint {
    map_read_attempted: bool,
    last_map_read_ok: bool,
    last_complete_snapshot_ms: Option<u64>,
    snapshot_clients: usize,
    map_entries: usize,
    matched_entries: usize,
    map_iteration_truncated: bool,
    source_stats: EcmSourceStats,
    event_stats: EcmEventStats,
    event_received: u64,
    event_coalesced: u64,
    event_invalid: u64,
    event_source_counts: [u64; EVENT_SOURCE_BUCKETS],
    event_interval_histogram: [u64; EVENT_INTERVAL_BUCKETS],
    event_last_timestamp_ns: Option<u64>,
    event_last_sequence: Option<u64>,
    last_error_stage: Option<&'static str>,
    last_error: Option<String>,
    collector: EcmBpfSnapshotCollector,
}

/// A dedicated ECM-update kprobe runtime.
///
/// The NSS callback entry/return probes mark hardware-stat update context on
/// each CPU. The totals-update probe publishes only those hardware increments;
/// ordinary ECM slow-path calls remain diagnostic evidence because TC-BPF owns
/// that disjoint traffic domain in ECM+BPF mode.
pub struct EcmBpfRuntime {
    ebpf: Option<Ebpf>,
    update_link: Option<KProbeLinkId>,
    nss_enter_links: Vec<(String, KProbeLinkId)>,
    nss_exit_links: Vec<(String, KProbeLinkId)>,
    nss_context_callbacks: Vec<String>,
    event_ringbuf: Option<RingBuf<MapData>>,
    layout: EcmLayout,
    map_read_attempted: bool,
    last_map_read_ok: bool,
    last_complete_snapshot_ms: Option<u64>,
    snapshot_clients: usize,
    map_entries: usize,
    map_capacity: usize,
    matched_entries: usize,
    map_iteration_truncated: bool,
    source_stats: EcmSourceStats,
    event_stats: EcmEventStats,
    event_received: u64,
    event_coalesced: u64,
    event_invalid: u64,
    event_source_counts: [u64; EVENT_SOURCE_BUCKETS],
    event_interval_histogram: [u64; EVENT_INTERVAL_BUCKETS],
    event_last_timestamp_ns: Option<u64>,
    event_last_sequence: Option<u64>,
    last_error_stage: Option<&'static str>,
    last_error: Option<String>,
}

pub fn available_nss_context_callbacks(path: impl AsRef<Path>) -> Result<Vec<String>, String> {
    Ok(available_nss_callback_specs(path)?
        .into_iter()
        .map(|spec| spec.symbol.to_owned())
        .collect())
}

fn available_nss_callback_specs(path: impl AsRef<Path>) -> Result<Vec<NssCallbackSpec>, String> {
    let contents = fs::read_to_string(path.as_ref())
        .map_err(|error| format!("read {}: {error}", path.as_ref().display()))?;
    let available = contents
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .collect::<BTreeSet<_>>();
    let callbacks = NSS_CALLBACK_SPECS
        .iter()
        .copied()
        .filter(|spec| available.contains(spec.symbol))
        .collect::<Vec<_>>();
    if callbacks.is_empty() {
        return Err("no supported ECM NSS callback symbol found".into());
    }
    Ok(callbacks)
}

impl EcmBpfRuntime {
    pub fn load_and_attach(path: impl AsRef<Path>) -> Result<Self, EcmBpfRuntimeError> {
        Self::load_and_attach_with_max_clients(path, MAX_CLIENTS as usize)
    }

    pub fn load_and_attach_with_max_clients(
        path: impl AsRef<Path>,
        max_clients: usize,
    ) -> Result<Self, EcmBpfRuntimeError> {
        let layout = resolve_ecm_layout().map_err(|error| {
            EcmBpfRuntimeError::new(
                ECM_BPF_LAYOUT_STAGE,
                format!("resolve ECM BTF layout: {error}"),
            )
        })?;
        let requested = max_clients.max(1).saturating_mul(2);
        let map_capacity = u32::try_from(requested).unwrap_or(u32::MAX);
        Self::load_and_attach_with_layout(path, layout, map_capacity)
    }

    fn load_and_attach_with_layout(
        path: impl AsRef<Path>,
        layout: EcmLayout,
        map_capacity: u32,
    ) -> Result<Self, EcmBpfRuntimeError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|error| {
            let detail = if error.kind() == io::ErrorKind::NotFound {
                "object missing"
            } else {
                "object read failed"
            };
            EcmBpfRuntimeError::new(
                ECM_BPF_OBJECT_LOAD_STAGE,
                format!("ECM+BPF {detail} at {}: {error}", path.display()),
            )
        })?;
        let mut loader = EbpfLoader::new();
        loader.map_max_entries(ECM_CLIENTS_MAP_NAME, map_capacity);
        let mut ebpf = loader.load(&bytes).map_err(|error| {
            EcmBpfRuntimeError::new(
                ECM_BPF_OBJECT_LOAD_STAGE,
                format!("load ECM+BPF object {}: {error}", path.display()),
            )
        })?;
        {
            let map = ebpf.map_mut(ECM_LAYOUT_MAP_NAME).ok_or_else(|| {
                EcmBpfRuntimeError::new(
                    ECM_BPF_LAYOUT_STAGE,
                    format!("{ECM_LAYOUT_MAP_NAME} missing"),
                )
            })?;
            let mut layouts = Array::<_, LayoutValue>::try_from(map).map_err(|error| {
                EcmBpfRuntimeError::new(ECM_BPF_LAYOUT_STAGE, error.to_string())
            })?;
            layouts.set(0, LayoutValue(layout), 0).map_err(|error| {
                EcmBpfRuntimeError::new(
                    ECM_BPF_LAYOUT_STAGE,
                    format!("write ECM BTF layout: {error}"),
                )
            })?;
        }
        let event_ringbuf = ebpf
            .take_map(ECM_EVENT_RINGBUF_MAP_NAME)
            .map(|map| {
                RingBuf::try_from(map).map_err(|error| {
                    EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string())
                })
            })
            .transpose()?;
        let nss_callback_specs = available_nss_callback_specs(KALLSYMS_PATH).map_err(|error| {
            EcmBpfRuntimeError::new(
                ECM_BPF_ATTACH_STAGE,
                format!("resolve NSS callback symbols: {error}"),
            )
        })?;
        let nss_context_callbacks = nss_callback_specs
            .iter()
            .map(|spec| spec.symbol.to_owned())
            .collect::<Vec<_>>();
        let nss_exit_links = attach_nss_context_links(&mut ebpf, &nss_callback_specs, false)?;
        let nss_enter_links = attach_nss_context_links(&mut ebpf, &nss_callback_specs, true)?;
        let update_link = {
            let program: &mut KProbe = ebpf
                .program_mut(ECM_UPDATE_PROGRAM_NAME)
                .ok_or_else(|| {
                    EcmBpfRuntimeError::new(
                        ECM_BPF_PROGRAM_LOAD_STAGE,
                        format!("{ECM_UPDATE_PROGRAM_NAME} missing"),
                    )
                })?
                .try_into()
                .map_err(|error: aya::programs::ProgramError| {
                    EcmBpfRuntimeError::new(ECM_BPF_PROGRAM_LOAD_STAGE, error.to_string())
                })?;
            program.load().map_err(|error| {
                EcmBpfRuntimeError::new(
                    ECM_BPF_PROGRAM_LOAD_STAGE,
                    format!("load {ECM_UPDATE_PROGRAM_NAME}: {error}"),
                )
            })?;
            program.attach(ECM_UPDATE_FUNCTION, 0).map_err(|error| {
                EcmBpfRuntimeError::new(
                    ECM_BPF_ATTACH_STAGE,
                    format!("attach {ECM_UPDATE_PROGRAM_NAME} to {ECM_UPDATE_FUNCTION}: {error}"),
                )
            })?
        };
        Ok(Self {
            ebpf: Some(ebpf),
            update_link: Some(update_link),
            nss_enter_links,
            nss_exit_links,
            nss_context_callbacks,
            event_ringbuf,
            layout,
            map_read_attempted: false,
            last_map_read_ok: false,
            last_complete_snapshot_ms: None,
            snapshot_clients: 0,
            map_entries: 0,
            map_capacity: map_capacity as usize,
            matched_entries: 0,
            map_iteration_truncated: false,
            source_stats: EcmSourceStats::default(),
            event_stats: EcmEventStats::default(),
            event_received: 0,
            event_coalesced: 0,
            event_invalid: 0,
            event_source_counts: [0; EVENT_SOURCE_BUCKETS],
            event_interval_histogram: [0; EVENT_INTERVAL_BUCKETS],
            event_last_timestamp_ns: None,
            event_last_sequence: None,
            last_error_stage: None,
            last_error: None,
        })
    }

    pub fn collection_checkpoint(
        &self,
        collector: &EcmBpfSnapshotCollector,
    ) -> EcmBpfCollectionCheckpoint {
        EcmBpfCollectionCheckpoint {
            map_read_attempted: self.map_read_attempted,
            last_map_read_ok: self.last_map_read_ok,
            last_complete_snapshot_ms: self.last_complete_snapshot_ms,
            snapshot_clients: self.snapshot_clients,
            map_entries: self.map_entries,
            matched_entries: self.matched_entries,
            map_iteration_truncated: self.map_iteration_truncated,
            source_stats: self.source_stats,
            event_stats: self.event_stats,
            event_received: self.event_received,
            event_coalesced: self.event_coalesced,
            event_invalid: self.event_invalid,
            event_source_counts: self.event_source_counts,
            event_interval_histogram: self.event_interval_histogram,
            event_last_timestamp_ns: self.event_last_timestamp_ns,
            event_last_sequence: self.event_last_sequence,
            last_error_stage: self.last_error_stage,
            last_error: self.last_error.clone(),
            collector: collector.clone(),
        }
    }

    pub fn restore_collection_checkpoint(
        &mut self,
        collector: &mut EcmBpfSnapshotCollector,
        checkpoint: EcmBpfCollectionCheckpoint,
    ) {
        self.map_read_attempted = checkpoint.map_read_attempted;
        self.last_map_read_ok = checkpoint.last_map_read_ok;
        self.last_complete_snapshot_ms = checkpoint.last_complete_snapshot_ms;
        self.snapshot_clients = checkpoint.snapshot_clients;
        self.map_entries = checkpoint.map_entries;
        self.matched_entries = checkpoint.matched_entries;
        self.map_iteration_truncated = checkpoint.map_iteration_truncated;
        self.source_stats = checkpoint.source_stats;
        self.event_stats = checkpoint.event_stats;
        self.event_received = checkpoint.event_received;
        self.event_coalesced = checkpoint.event_coalesced;
        self.event_invalid = checkpoint.event_invalid;
        self.event_source_counts = checkpoint.event_source_counts;
        self.event_interval_histogram = checkpoint.event_interval_histogram;
        self.event_last_timestamp_ns = checkpoint.event_last_timestamp_ns;
        self.event_last_sequence = checkpoint.event_last_sequence;
        self.last_error_stage = checkpoint.last_error_stage;
        self.last_error = checkpoint.last_error;
        *collector = checkpoint.collector;
    }

    pub fn collect_snapshot(
        &mut self,
        collector: &mut EcmBpfSnapshotCollector,
        identities: &IdentityTable,
        now_ms: u64,
    ) -> Result<EcmBpfSnapshot, EcmBpfRuntimeError> {
        self.map_read_attempted = true;
        self.drain_event_hints();
        self.event_stats = self.read_event_stats();
        let (read, source_stats) = match self.read_maps() {
            Ok(read) => read,
            Err(error) => {
                self.last_map_read_ok = false;
                self.last_error_stage = Some(error.stage());
                self.last_error = Some(error.to_string());
                return Err(error);
            }
        };
        self.source_stats = source_stats;
        self.map_iteration_truncated |= read.truncated;
        let snapshot = collector.convert(read, identities, now_ms);
        self.last_map_read_ok = true;
        self.last_complete_snapshot_ms = Some(snapshot.sample_ms);
        self.snapshot_clients = snapshot.clients.len();
        self.map_entries = snapshot.map_entries;
        self.matched_entries = snapshot.matched_entries;
        self.last_error_stage = None;
        self.last_error = None;
        Ok(snapshot)
    }

    fn read_maps(&self) -> Result<(EcmMapRead, EcmSourceStats), EcmBpfRuntimeError> {
        for _ in 0..ECM_MAP_STABLE_READ_ATTEMPTS {
            let before = self.read_source_stats()?;
            let read = self.read_client_map()?;
            let after = self.read_source_stats()?;
            if same_nss_source_generation(before, after) {
                return Ok((read, after));
            }
        }
        // Never publish a traversal that crossed an NSS callback generation:
        // its entries belong to different hardware-sync windows. The runtime
        // retains the last complete batch and retries on the next collection.
        Err(EcmBpfRuntimeError::new(
            ECM_BPF_MAP_READ_STAGE,
            "ECM NSS counters changed during every bounded map snapshot attempt",
        ))
    }

    /// Read the independent PerCPU FastN map. This is deliberately separate
    /// from `collect_snapshot`: Evidence map traversal and one-second FastRate
    /// windows must never share a partially read ledger or a slow retry loop.
    pub fn read_fast_n_counters(&self) -> Result<EcmFastCounterMapRead, EcmBpfRuntimeError> {
        let map = self
            .ebpf
            .as_ref()
            .and_then(|ebpf| ebpf.map(ECM_FAST_COUNTERS_MAP_NAME))
            .ok_or_else(|| {
                EcmBpfRuntimeError::new(
                    ECM_BPF_MAP_READ_STAGE,
                    format!("{ECM_FAST_COUNTERS_MAP_NAME} missing"),
                )
            })?;
        let counters = PerCpuHashMap::<_, EcmFastCounterKey, EcmFastCounterValue>::try_from(map)
            .map_err(|error| EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string()))?;
        let mut entries = Vec::new();
        let mut truncated = false;
        for key in counters.keys() {
            let key = match key {
                Ok(key) => key,
                Err(aya::maps::MapError::KeyNotFound) => continue,
                Err(error) => {
                    return Err(EcmBpfRuntimeError::new(
                        ECM_BPF_MAP_READ_STAGE,
                        error.to_string(),
                    ));
                }
            };
            if entries.len() >= ECM_FAST_COUNTERS_MAP_CAPACITY as usize {
                truncated = true;
                break;
            }
            let mut first = Vec::new();
            let mut second = Vec::new();
            for _ in 0..FAST_COUNTER_MAP_READ_RETRIES {
                first = counters
                    .get(&key, 0)
                    .map_err(|error| {
                        EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string())
                    })?
                    .iter()
                    .map(|value| value.0)
                    .collect();
                second = counters
                    .get(&key, 0)
                    .map_err(|error| {
                        EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string())
                    })?
                    .iter()
                    .map(|value| value.0)
                    .collect();
                if stable_fast_counter_pair(&first, &second) {
                    break;
                }
            }
            entries.push(RawEcmFastCounterSample {
                key: key.0,
                first,
                second,
            });
        }
        truncated |= entries.len() == ECM_FAST_COUNTERS_MAP_CAPACITY as usize;
        Ok(EcmFastCounterMapRead { entries, truncated })
    }

    pub fn fast_n_reader(&self) -> Result<EcmFastCounterMapReader, EcmBpfRuntimeError> {
        let map = self
            .ebpf
            .as_ref()
            .and_then(|ebpf| ebpf.map(ECM_FAST_COUNTERS_MAP_NAME))
            .ok_or_else(|| {
                EcmBpfRuntimeError::new(
                    ECM_BPF_MAP_READ_STAGE,
                    format!("{ECM_FAST_COUNTERS_MAP_NAME} missing"),
                )
            })?;
        let counters = PerCpuHashMap::<_, EcmFastCounterKey, EcmFastCounterValue>::try_from(map)
            .map_err(|error| EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string()))?;
        let fd = counters
            .map()
            .fd()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string()))?;
        let map_data = MapData::from_fd(fd)
            .map_err(|error| EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string()))?;
        let map = Map::from_map_data(map_data)
            .map_err(|error| EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string()))?;
        let counters = PerCpuHashMap::try_from(map)
            .map_err(|error| EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string()))?;
        Ok(EcmFastCounterMapReader { counters })
    }

    pub(crate) fn take_event_hint_reader(&mut self) -> Option<EcmEventHintReader> {
        let ringbuf = self.event_ringbuf.take()?;
        Some(EcmEventHintReader {
            ringbuf,
            telemetry: EcmEventHintTelemetry {
                event_received: self.event_received,
                event_coalesced: self.event_coalesced,
                event_invalid: self.event_invalid,
                event_source_counts: self.event_source_counts,
                event_interval_histogram: self.event_interval_histogram,
                event_last_timestamp_ns: self.event_last_timestamp_ns,
                event_last_sequence: self.event_last_sequence,
            },
        })
    }

    pub(crate) fn apply_event_hint_telemetry(&mut self, telemetry: EcmEventHintTelemetry) {
        self.event_received = telemetry.event_received;
        self.event_coalesced = telemetry.event_coalesced;
        self.event_invalid = telemetry.event_invalid;
        self.event_source_counts = telemetry.event_source_counts;
        self.event_interval_histogram = telemetry.event_interval_histogram;
        self.event_last_timestamp_ns = telemetry.event_last_timestamp_ns;
        self.event_last_sequence = telemetry.event_last_sequence;
    }

    fn read_client_map(&self) -> Result<EcmMapRead, EcmBpfRuntimeError> {
        let map = self
            .ebpf
            .as_ref()
            .and_then(|ebpf| ebpf.map(ECM_CLIENTS_MAP_NAME))
            .ok_or_else(|| {
                EcmBpfRuntimeError::new(
                    ECM_BPF_MAP_READ_STAGE,
                    format!("{ECM_CLIENTS_MAP_NAME} missing"),
                )
            })?;
        let clients = HashMap::<_, MapKey, MapValue>::try_from(map)
            .map_err(|error| EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string()))?;
        let mut entries = Vec::new();
        let mut truncated = false;
        for entry in clients.iter() {
            match entry {
                Ok((key, value)) => {
                    if entries.len() >= self.map_capacity {
                        truncated = true;
                        break;
                    }
                    entries.push(RawEcmSample {
                        key: key.0,
                        counters: value.0,
                    });
                }
                Err(aya::maps::MapError::KeyNotFound) => continue,
                Err(error) => {
                    return Err(EcmBpfRuntimeError::new(
                        ECM_BPF_MAP_READ_STAGE,
                        error.to_string(),
                    ));
                }
            }
        }
        truncated |= entries.len() == self.map_capacity;
        Ok(EcmMapRead { entries, truncated })
    }

    fn read_source_stats(&self) -> Result<EcmSourceStats, EcmBpfRuntimeError> {
        let source_map = self
            .ebpf
            .as_ref()
            .and_then(|ebpf| ebpf.map(ECM_SOURCE_STATS_MAP_NAME))
            .ok_or_else(|| {
                EcmBpfRuntimeError::new(
                    ECM_BPF_MAP_READ_STAGE,
                    format!("{ECM_SOURCE_STATS_MAP_NAME} missing"),
                )
            })?;
        let source_stats = Array::<_, SourceStatsValue>::try_from(source_map)
            .map_err(|error| EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string()))?
            .get(&0, 0)
            .map_err(|error| EcmBpfRuntimeError::new(ECM_BPF_MAP_READ_STAGE, error.to_string()))?
            .0;
        Ok(source_stats)
    }

    fn read_event_stats(&self) -> EcmEventStats {
        let Some(event_map) = self
            .ebpf
            .as_ref()
            .and_then(|ebpf| ebpf.map(ECM_EVENT_STATS_MAP_NAME))
        else {
            return EcmEventStats::default();
        };
        Array::<_, EventStatsValue>::try_from(event_map)
            .ok()
            .and_then(|stats| stats.get(&0, 0).ok())
            .map_or(EcmEventStats::default(), |value| value.0)
    }

    fn drain_event_hints(&mut self) {
        let mut received = 0u64;
        let mut invalid = 0u64;
        let mut coalesced = 0u64;
        let mut source_counts = [0u64; EVENT_SOURCE_BUCKETS];
        let mut interval_histogram = [0u64; EVENT_INTERVAL_BUCKETS];
        let mut previous_timestamp_ns = self.event_last_timestamp_ns;
        let mut last = None;
        if let Some(ringbuf) = self.event_ringbuf.as_mut() {
            while let Some(item) = ringbuf.next() {
                // RingBufItem is a byte slice whose lifetime is tied to the
                // consumer position. Copy before dropping it so the ring can
                // immediately advance to the next hint.
                let event = decode_event_hint(&item);
                drop(item);
                let Some(event) = event else {
                    invalid = invalid.saturating_add(1);
                    continue;
                };
                received = received.saturating_add(1);
                if received > 1 {
                    coalesced = coalesced.saturating_add(1);
                }
                source_counts[event_source_bucket(event.source)] =
                    source_counts[event_source_bucket(event.source)].saturating_add(1);
                if let Some(previous) = previous_timestamp_ns {
                    if event.timestamp_ns > previous {
                        interval_histogram[event_interval_bucket(event.timestamp_ns - previous)] =
                            interval_histogram
                                [event_interval_bucket(event.timestamp_ns - previous)]
                            .saturating_add(1);
                    }
                }
                previous_timestamp_ns = Some(event.timestamp_ns);
                last = Some(event);
            }
        }
        self.event_received = self.event_received.saturating_add(received);
        self.event_coalesced = self.event_coalesced.saturating_add(coalesced);
        self.event_invalid = self.event_invalid.saturating_add(invalid);
        for (current, added) in self.event_source_counts.iter_mut().zip(source_counts) {
            *current = current.saturating_add(added);
        }
        for (current, added) in self
            .event_interval_histogram
            .iter_mut()
            .zip(interval_histogram)
        {
            *current = current.saturating_add(added);
        }
        if let Some(event) = last {
            self.event_last_timestamp_ns = Some(event.timestamp_ns);
            self.event_last_sequence = Some(event.sequence);
        }
    }

    pub fn health(&self, now_ms: u64, freshness_ms: u64) -> EcmBpfHealth {
        let fresh_snapshot = self.last_complete_snapshot_ms.is_some_and(|sample_ms| {
            sample_ms <= now_ms && (freshness_ms == 0 || now_ms - sample_ms <= freshness_ms)
        });
        EcmBpfHealth {
            object_loaded: self.ebpf.is_some(),
            attached: self.update_link.is_some()
                && !self.nss_context_callbacks.is_empty()
                && self.nss_enter_links.len() == self.nss_context_callbacks.len()
                && self.nss_exit_links.len() == self.nss_context_callbacks.len(),
            map_read_attempted: self.map_read_attempted,
            map_read_ok: self.last_map_read_ok && fresh_snapshot,
            fresh_snapshot,
            last_complete_snapshot_ms: self.last_complete_snapshot_ms,
            snapshot_clients: self.snapshot_clients,
            map_entries: self.map_entries,
            map_capacity: self.map_capacity,
            matched_entries: self.matched_entries,
            map_iteration_truncated: self.map_iteration_truncated,
            nss_context_callbacks: self.nss_context_callbacks.clone(),
            source_stats: self.source_stats,
            event_stats: self.event_stats,
            event_received: self.event_received,
            event_coalesced: self.event_coalesced,
            event_invalid: self.event_invalid,
            event_source_counts: self.event_source_counts,
            event_interval_histogram: self.event_interval_histogram,
            event_last_timestamp_ns: self.event_last_timestamp_ns,
            event_last_sequence: self.event_last_sequence,
            event_last_age_ms: self
                .event_last_timestamp_ns
                .map(|timestamp_ns| now_ms.saturating_sub(timestamp_ns.saturating_div(1_000_000))),
            layout: Some(self.layout),
            error_stage: self.last_error_stage,
            error: self.last_error.clone(),
        }
    }

    pub fn apply_runtime_health(
        &self,
        runtime: &mut crate::probe::RuntimeHealth,
        now_ms: u64,
        freshness_ms: u64,
    ) {
        let health = self.health(now_ms, freshness_ms);
        runtime.ecm_bpf_object_loaded = health.object_loaded;
        runtime.ecm_bpf_attached = health.attached;
        runtime.ecm_bpf_map_read_attempted = health.map_read_attempted;
        runtime.ecm_bpf_map_read_ok = health.map_read_ok;
        runtime.ecm_bpf_last_complete_snapshot_ms = health.last_complete_snapshot_ms;
        runtime.ecm_bpf_freshness_ms = freshness_ms;
        runtime.ecm_bpf_snapshot_clients = health.snapshot_clients;
        runtime.ecm_bpf_map_entries = health.map_entries;
        runtime.ecm_bpf_map_capacity = health.map_capacity;
        runtime.ecm_bpf_matched_entries = health.matched_entries;
        runtime.ecm_bpf_map_iteration_truncated = health.map_iteration_truncated;
        runtime.ecm_bpf_nss_context_callbacks = health.nss_context_callbacks;
        runtime.ecm_bpf_source_stats = health.source_stats;
        runtime.ecm_bpf_event_stats = health.event_stats;
        runtime.ecm_bpf_event_received = health.event_received;
        runtime.ecm_bpf_event_coalesced = health.event_coalesced;
        runtime.ecm_bpf_event_invalid = health.event_invalid;
        runtime.ecm_bpf_event_source_counts = health.event_source_counts;
        runtime.ecm_bpf_event_interval_histogram = health.event_interval_histogram;
        runtime.ecm_bpf_event_last_timestamp_ns = health.event_last_timestamp_ns;
        runtime.ecm_bpf_event_last_sequence = health.event_last_sequence;
        runtime.ecm_bpf_event_last_age_ms = health.event_last_age_ms;
        runtime.ecm_bpf_layout = health.layout;
        runtime.ecm_bpf_error_stage = health.error_stage.map(str::to_owned);
        runtime.ecm_bpf_runtime_error = health.error;
    }

    pub fn shutdown(&mut self) -> Result<(), EcmBpfRuntimeError> {
        let Some(ebpf) = self.ebpf.as_mut() else {
            self.update_link = None;
            self.nss_enter_links.clear();
            self.nss_exit_links.clear();
            self.nss_context_callbacks.clear();
            return Ok(());
        };
        let mut first_error = None;
        for (program_name, link) in std::mem::take(&mut self.nss_enter_links) {
            if let Err(error) = detach_kprobe_links(ebpf, &program_name, vec![link]) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if let Some(link) = self.update_link.take() {
            if let Err(error) = detach_kprobe_links(ebpf, ECM_UPDATE_PROGRAM_NAME, vec![link]) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        for (program_name, link) in std::mem::take(&mut self.nss_exit_links) {
            if let Err(error) = detach_kprobe_links(ebpf, &program_name, vec![link]) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        self.nss_context_callbacks.clear();
        self.ebpf = None;
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

fn attach_nss_context_links(
    ebpf: &mut Ebpf,
    specs: &[NssCallbackSpec],
    entering: bool,
) -> Result<Vec<(String, KProbeLinkId)>, EcmBpfRuntimeError> {
    let mut links = Vec::with_capacity(specs.len());
    for spec in specs {
        let program_name = if entering {
            spec.enter_program
        } else {
            spec.exit_program
        };
        let program: &mut KProbe = ebpf
            .program_mut(program_name)
            .ok_or_else(|| {
                EcmBpfRuntimeError::new(
                    ECM_BPF_PROGRAM_LOAD_STAGE,
                    format!("{program_name} missing"),
                )
            })?
            .try_into()
            .map_err(|error: aya::programs::ProgramError| {
                EcmBpfRuntimeError::new(ECM_BPF_PROGRAM_LOAD_STAGE, error.to_string())
            })?;
        program.load().map_err(|error| {
            EcmBpfRuntimeError::new(
                ECM_BPF_PROGRAM_LOAD_STAGE,
                format!("load {program_name}: {error}"),
            )
        })?;
        let link = program.attach(spec.symbol, 0).map_err(|error| {
            EcmBpfRuntimeError::new(
                ECM_BPF_ATTACH_STAGE,
                format!("attach {program_name} to {}: {error}", spec.symbol),
            )
        })?;
        links.push((program_name.to_owned(), link));
    }
    Ok(links)
}

fn same_nss_source_generation(before: EcmSourceStats, after: EcmSourceStats) -> bool {
    before.nss_updates == after.nss_updates
        && before.nss_bytes == after.nss_bytes
        && before.nss_packets == after.nss_packets
}

fn decode_event_hint(bytes: &[u8]) -> Option<EcmCountersUpdatedEvent> {
    if bytes.len() != size_of::<EcmCountersUpdatedEvent>() {
        return None;
    }
    // The callback boundary cannot prove a complete vendor sync round.
    let event = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<EcmCountersUpdatedEvent>()) };
    (event.round_end == 0).then_some(event)
}

fn event_source_bucket(source: u8) -> usize {
    let source = usize::from(source);
    (source < EVENT_SOURCE_BUCKETS)
        .then_some(source)
        .unwrap_or(0)
}

fn event_interval_bucket(interval_ns: u64) -> usize {
    match interval_ns {
        0..=250_000_000 => 0,
        250_000_001..=500_000_000 => 1,
        500_000_001..=1_000_000_000 => 2,
        1_000_000_001..=2_000_000_000 => 3,
        _ => 4,
    }
}

fn detach_kprobe_links(
    ebpf: &mut Ebpf,
    program_name: &str,
    links: Vec<KProbeLinkId>,
) -> Result<(), EcmBpfRuntimeError> {
    if links.is_empty() {
        return Ok(());
    }
    let Some(program) = ebpf.program_mut(program_name) else {
        return Err(EcmBpfRuntimeError::new(
            ECM_BPF_DETACH_STAGE,
            format!("{program_name} missing during detach"),
        ));
    };
    let program: &mut KProbe =
        program
            .try_into()
            .map_err(|error: aya::programs::ProgramError| {
                EcmBpfRuntimeError::new(ECM_BPF_DETACH_STAGE, error.to_string())
            })?;
    let mut first_error = None;
    for link in links {
        if let Err(error) = program.detach(link) {
            if first_error.is_none() {
                first_error = Some(EcmBpfRuntimeError::new(
                    ECM_BPF_DETACH_STAGE,
                    format!("detach {program_name}: {error}"),
                ));
            }
        }
    }
    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(())
    }
}

impl Drop for EcmBpfRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn client_sample(
    identity: &ClientIdentity,
    identity_key: String,
    folded: FoldedClient,
    now_ms: u64,
) -> EcmBpfClientSample {
    EcmBpfClientSample {
        mac: identity.key.mac.to_string(),
        identity_key,
        zone: identity.key.zone.clone(),
        interface: identity.interface.clone(),
        ips: identity.ips.iter().take(4).cloned().collect(),
        tx_bytes: folded.tx_bytes,
        rx_bytes: folded.rx_bytes,
        tx_bps: folded.tx_bps,
        rx_bps: folded.rx_bps,
        sample_ms: now_ms,
        last_seen_ms: folded.last_seen_ms,
    }
}

fn unique_identity_for_mac(identities: &IdentityTable, mac: [u8; 6]) -> Option<&ClientIdentity> {
    let mac = format_mac(mac);
    let mut matches = identities
        .iter()
        .filter(|identity| identity.key.mac.to_string() == mac);
    let value = matches.next()?;
    matches.next().is_none().then_some(value)
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn bits_per_second(bytes: u64, window_ms: u64) -> u64 {
    if window_ms == 0 {
        return 0;
    }
    let scaled = u128::from(bytes).saturating_mul(8_000) / u128::from(window_ms);
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

pub fn resolve_ecm_layout() -> Result<EcmLayout, String> {
    resolve_ecm_layout_from_paths(VMLINUX_BTF_PATH, ECM_BTF_PATH)
}

pub fn resolve_ecm_layout_from_paths(
    vmlinux: impl AsRef<Path>,
    module: impl AsRef<Path>,
) -> Result<EcmLayout, String> {
    let base = fs::read(vmlinux.as_ref())
        .map_err(|error| format!("read {}: {error}", vmlinux.as_ref().display()))?;
    let split = fs::read(module.as_ref())
        .map_err(|error| format!("read {}: {error}", module.as_ref().display()))?;
    let merged = merge_split_btf(&base, &split).map_err(|error| error.to_string())?;
    resolve_ecm_layout_from_btf(&merged)
}

pub fn resolve_ecm_layout_from_btf(bytes: &[u8]) -> Result<EcmLayout, String> {
    let header_len = read_u32(bytes, 4)? as usize;
    let type_off = read_u32(bytes, 8)? as usize;
    let type_len = read_u32(bytes, 12)? as usize;
    let string_off = read_u32(bytes, 16)? as usize;
    let string_len = read_u32(bytes, 20)? as usize;
    if read_u16(bytes, 0)? != 0xeb9f {
        return Err("invalid BTF magic".into());
    }
    let types_start = header_len
        .checked_add(type_off)
        .ok_or("BTF type offset overflow")?;
    let types_end = types_start
        .checked_add(type_len)
        .ok_or("BTF type length overflow")?;
    let strings_start = header_len
        .checked_add(string_off)
        .ok_or("BTF string offset overflow")?;
    let strings_end = strings_start
        .checked_add(string_len)
        .ok_or("BTF string length overflow")?;
    let types = bytes
        .get(types_start..types_end)
        .ok_or("truncated BTF type section")?;
    let strings = bytes
        .get(strings_start..strings_end)
        .ok_or("truncated BTF string section")?;

    let mut connection_node = None;
    let mut connection_generation = None;
    let mut node_address = None;
    let mut cursor = 0usize;
    while cursor < types.len() {
        let name_offset = read_u32(types, cursor)?;
        let info = read_u32(types, cursor + 4)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let kind_flag = info >> 31 != 0;
        let record_len = btf_record_len(kind, vlen)?;
        let record = types
            .get(cursor..cursor + record_len)
            .ok_or("truncated BTF type record")?;
        if kind == BTF_KIND_STRUCT {
            let name = btf_string(strings, name_offset)?;
            if name == "ecm_db_connection_instance" {
                connection_node = struct_member_offset(record, strings, vlen, kind_flag, "node")?;
                connection_generation =
                    struct_member_offset(record, strings, vlen, kind_flag, "time_added")?;
            } else if name == "ecm_db_node_instance" {
                node_address = struct_member_offset(record, strings, vlen, kind_flag, "address")?;
            }
        }
        cursor = cursor
            .checked_add(record_len)
            .ok_or("BTF record offset overflow")?;
    }
    if cursor != types.len() {
        return Err("invalid BTF type section length".into());
    }

    let layout = EcmLayout {
        connection_node_offset: connection_node.ok_or("ECM connection.node missing")?,
        connection_generation_offset: connection_generation
            .ok_or("ECM connection.time_added missing")?,
        node_address_offset: node_address.ok_or("ECM node.address missing")?,
        pointer_size: std::mem::size_of::<usize>() as u8,
        from_index: 0,
        to_index: 1,
        ready: 1,
    };
    if layout.pointer_size != 8
        || layout.connection_node_offset > 4096
        || layout.connection_generation_offset > 4096
        || layout.node_address_offset > 1024
    {
        return Err("unsupported ECM BTF layout".into());
    }
    Ok(layout)
}

fn struct_member_offset(
    record: &[u8],
    strings: &[u8],
    vlen: usize,
    kind_flag: bool,
    wanted: &str,
) -> Result<Option<u32>, String> {
    for index in 0..vlen {
        let offset = 12usize
            .checked_add(index.checked_mul(12).ok_or("BTF member overflow")?)
            .ok_or("BTF member overflow")?;
        let name_offset = read_u32(record, offset)?;
        if btf_string(strings, name_offset)? != wanted {
            continue;
        }
        let raw = read_u32(record, offset + 8)?;
        let bit_offset = if kind_flag { raw & 0x00ff_ffff } else { raw };
        if bit_offset % 8 != 0 {
            return Err(format!("ECM {wanted} is not byte aligned"));
        }
        return Ok(Some(bit_offset / 8));
    }
    Ok(None)
}

fn btf_record_len(kind: u32, vlen: usize) -> Result<usize, String> {
    let extra = match kind {
        BTF_KIND_INT | BTF_KIND_VAR | BTF_KIND_DECL_TAG => 4,
        BTF_KIND_ARRAY => 12,
        BTF_KIND_STRUCT | BTF_KIND_UNION | BTF_KIND_DATASEC => {
            vlen.checked_mul(12).ok_or("BTF record length overflow")?
        }
        BTF_KIND_ENUM | BTF_KIND_FUNC_PROTO => {
            vlen.checked_mul(8).ok_or("BTF record length overflow")?
        }
        BTF_KIND_ENUM64 => vlen.checked_mul(12).ok_or("BTF record length overflow")?,
        0 | 2 | 7..=12 | 16 | 18 => 0,
        _ => return Err(format!("unsupported BTF kind {kind}")),
    };
    12usize
        .checked_add(extra)
        .ok_or_else(|| "BTF record length overflow".into())
}

fn btf_string(strings: &[u8], offset: u32) -> Result<&str, String> {
    let offset = offset as usize;
    let tail = strings.get(offset..).ok_or("invalid BTF string offset")?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("unterminated BTF string")?;
    std::str::from_utf8(&tail[..end]).map_err(|error| format!("invalid BTF string: {error}"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or("truncated BTF integer")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or("truncated BTF integer")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(test)]
include!("ecm_bpf/tests.rs");
