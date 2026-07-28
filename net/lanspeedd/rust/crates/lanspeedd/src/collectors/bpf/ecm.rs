use std::{collections::BTreeMap, fmt, fs, io, path::Path};

use aya::{
    maps::{Array, HashMap},
    programs::{kprobe::KProbeLinkId, KProbe},
    Ebpf, EbpfLoader, Pod,
};
use lanspeed_common::{
    EcmCounters, EcmKey, EcmLayout, DIR_RX, DIR_TX, ECM_CLIENTS_MAP_NAME, ECM_LAYOUT_MAP_NAME,
    ECM_UPDATE_PROGRAM_NAME, MAX_CLIENTS,
};

use crate::{
    collectors::ecm_node::TrafficCounters,
    identity::{ClientIdentity, IdentityTable},
    merge_split_btf,
};

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
pub const ECM_RATE_HOLD_MS: u64 = 2_500;
const FLOW_RETENTION_MS: u64 = 60_000;
const RATE_MEDIAN_SAMPLES: usize = 3;
const MAX_ECM_MAP_ENTRIES: usize = MAX_CLIENTS as usize * 4;
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EcmBpfSnapshot {
    pub clients: Vec<EcmBpfClientSample>,
    pub coverage_delta: TrafficCounters,
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

#[derive(Clone, Copy, Debug, Default)]
struct FlowBaseline {
    bytes: u64,
    packets: u64,
    last_progress_sample_ms: u64,
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
        let previous_sample_ms = self
            .last_complete
            .as_ref()
            .map(|snapshot| snapshot.sample_ms);
        let mut current = BTreeMap::<FlowKey, (EcmCounters, Option<String>)>::new();
        let mut coverage_delta = TrafficCounters::default();
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
            let previous = self.baselines.get(key).copied();
            let delta = match previous {
                Some(previous)
                    if counters.bytes >= previous.bytes && counters.packets >= previous.packets =>
                {
                    Some((
                        counters.bytes - previous.bytes,
                        counters.packets - previous.packets,
                        previous.last_progress_sample_ms,
                    ))
                }
                Some(_) => {
                    self.published.remove(key);
                    self.rate_histories.remove(key);
                    None
                }
                // This runtime owns the map and every entry starts at zero. The
                // first complete read is an unknown-time baseline; a later new
                // generation contains traffic since the preceding map snapshot.
                None => previous_sample_ms
                    .map(|sample_ms| (counters.bytes, counters.packets, sample_ms)),
            };
            if let Some((delta_bytes, delta_packets, delta_start_ms)) = delta {
                if (delta_bytes != 0 || delta_packets != 0) && identity_key.is_some() {
                    if key.direction == DIR_TX {
                        coverage_delta.tx_bytes =
                            coverage_delta.tx_bytes.saturating_add(delta_bytes);
                        coverage_delta.tx_packets =
                            coverage_delta.tx_packets.saturating_add(delta_packets);
                    } else {
                        coverage_delta.rx_bytes =
                            coverage_delta.rx_bytes.saturating_add(delta_bytes);
                        coverage_delta.rx_packets =
                            coverage_delta.rx_packets.saturating_add(delta_packets);
                    }
                    // Counters and last_seen are separate map-value stores, so
                    // a concurrent read can observe them from different ECM
                    // updates. Use the coherent daemon sample clock for rates;
                    // last_seen remains freshness evidence only.
                    let window_ms = now_ms.saturating_sub(delta_start_ms);
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
            let progressed = previous.is_none_or(|value| {
                value.bytes != counters.bytes || value.packets != counters.packets
            });
            self.baselines.insert(
                *key,
                FlowBaseline {
                    bytes: counters.bytes,
                    packets: counters.packets,
                    last_progress_sample_ms: if progressed {
                        now_ms
                    } else {
                        previous.map_or(now_ms, |value| value.last_progress_sample_ms)
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
            if key.direction == DIR_TX {
                client.tx_bytes = client.tx_bytes.saturating_add(total);
                client.tx_bps = client.tx_bps.saturating_add(rate);
            } else {
                client.rx_bytes = client.rx_bytes.saturating_add(total);
                client.rx_bps = client.rx_bps.saturating_add(rate);
            }
            client.last_seen_ms = client
                .last_seen_ms
                .max((counters.last_seen / 1_000_000).min(now_ms));
        }

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
            coverage_delta,
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
    pub matched_entries: usize,
    pub map_iteration_truncated: bool,
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
    last_error_stage: Option<&'static str>,
    last_error: Option<String>,
    collector: EcmBpfSnapshotCollector,
}

/// A dedicated ECM-update kprobe runtime.
///
/// This intentionally loads a second copy of the fallback object. Its ECM map
/// is therefore disjoint from the TC maps used by pure BPF, and production
/// never adds those two sources together. Every value in this runtime comes
/// from the single ECM totals-update call chain, which receives both slow-path
/// packet updates and NSS sync deltas.
pub struct EcmBpfRuntime {
    ebpf: Option<Ebpf>,
    link: Option<KProbeLinkId>,
    layout: EcmLayout,
    map_read_attempted: bool,
    last_map_read_ok: bool,
    last_complete_snapshot_ms: Option<u64>,
    snapshot_clients: usize,
    map_entries: usize,
    matched_entries: usize,
    map_iteration_truncated: bool,
    last_error_stage: Option<&'static str>,
    last_error: Option<String>,
}

impl EcmBpfRuntime {
    pub fn load_and_attach(path: impl AsRef<Path>) -> Result<Self, EcmBpfRuntimeError> {
        let layout = resolve_ecm_layout().map_err(|error| {
            EcmBpfRuntimeError::new(
                ECM_BPF_LAYOUT_STAGE,
                format!("resolve ECM BTF layout: {error}"),
            )
        })?;
        Self::load_and_attach_with_layout(path, layout)
    }

    fn load_and_attach_with_layout(
        path: impl AsRef<Path>,
        layout: EcmLayout,
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
        let mut ebpf = EbpfLoader::new().load(&bytes).map_err(|error| {
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
        let link = {
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
            link: Some(link),
            layout,
            map_read_attempted: false,
            last_map_read_ok: false,
            last_complete_snapshot_ms: None,
            snapshot_clients: 0,
            map_entries: 0,
            matched_entries: 0,
            map_iteration_truncated: false,
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
        let read = match self.read_map() {
            Ok(read) => read,
            Err(error) => {
                self.last_map_read_ok = false;
                self.last_error_stage = Some(error.stage());
                self.last_error = Some(error.to_string());
                return Err(error);
            }
        };
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

    fn read_map(&self) -> Result<EcmMapRead, EcmBpfRuntimeError> {
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
                    if entries.len() >= MAX_ECM_MAP_ENTRIES {
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
        truncated |= entries.len() == MAX_ECM_MAP_ENTRIES;
        Ok(EcmMapRead { entries, truncated })
    }

    pub fn health(&self, now_ms: u64, freshness_ms: u64) -> EcmBpfHealth {
        let fresh_snapshot = self.last_complete_snapshot_ms.is_some_and(|sample_ms| {
            sample_ms <= now_ms && (freshness_ms == 0 || now_ms - sample_ms <= freshness_ms)
        });
        EcmBpfHealth {
            object_loaded: self.ebpf.is_some(),
            attached: self.link.is_some(),
            map_read_attempted: self.map_read_attempted,
            map_read_ok: self.last_map_read_ok && fresh_snapshot,
            fresh_snapshot,
            last_complete_snapshot_ms: self.last_complete_snapshot_ms,
            snapshot_clients: self.snapshot_clients,
            map_entries: self.map_entries,
            matched_entries: self.matched_entries,
            map_iteration_truncated: self.map_iteration_truncated,
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
        runtime.ecm_bpf_matched_entries = health.matched_entries;
        runtime.ecm_bpf_map_iteration_truncated = health.map_iteration_truncated;
        runtime.ecm_bpf_layout = health.layout;
        runtime.ecm_bpf_error_stage = health.error_stage.map(str::to_owned);
        runtime.ecm_bpf_runtime_error = health.error;
    }

    pub fn shutdown(&mut self) -> Result<(), EcmBpfRuntimeError> {
        let Some(link) = self.link.take() else {
            self.ebpf = None;
            return Ok(());
        };
        let result = self
            .ebpf
            .as_mut()
            .and_then(|ebpf| ebpf.program_mut(ECM_UPDATE_PROGRAM_NAME))
            .ok_or_else(|| {
                EcmBpfRuntimeError::new(
                    ECM_BPF_DETACH_STAGE,
                    format!("{ECM_UPDATE_PROGRAM_NAME} missing during detach"),
                )
            })
            .and_then(|program| {
                let program: &mut KProbe =
                    program
                        .try_into()
                        .map_err(|error: aya::programs::ProgramError| {
                            EcmBpfRuntimeError::new(ECM_BPF_DETACH_STAGE, error.to_string())
                        })?;
                program.detach(link).map_err(|error| {
                    EcmBpfRuntimeError::new(ECM_BPF_DETACH_STAGE, error.to_string())
                })
            });
        self.ebpf = None;
        result
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
mod tests {
    use super::*;
    use crate::identity::{IdentityObservation, ObservationSource};

    fn identities() -> IdentityTable {
        let mut identities = IdentityTable::new(4);
        identities
            .observe(IdentityObservation {
                mac: "02:00:00:00:00:01",
                zone: Some("lan"),
                interface: "br-lan",
                ip: Some("192.0.2.2"),
                hostname: Some("client"),
                last_seen: 1,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
        identities
    }

    fn raw(
        connection: u64,
        generation: u32,
        direction: u8,
        bytes: u64,
        packets: u64,
        last_seen_ms: u64,
    ) -> RawEcmSample {
        RawEcmSample {
            key: EcmKey {
                connection,
                generation,
                direction,
                reserved: 0,
                mac: [0x02, 0, 0, 0, 0, 1],
                padding: [0; 4],
            },
            counters: EcmCounters {
                bytes,
                packets,
                last_seen: last_seen_ms * 1_000_000,
            },
        }
    }

    #[test]
    fn rates_are_windowed_per_connection_generation_before_client_folding() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        let first = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 1_000, 10, 1_000),
                    raw(2, 20, DIR_TX, 500, 5, 1_000),
                ],
                truncated: false,
            },
            &identities,
            1_000,
        );
        assert_eq!(first.clients[0].tx_bps, 0);

        let second = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 3_000, 30, 3_000),
                    raw(2, 20, DIR_TX, 500, 5, 1_000),
                ],
                truncated: false,
            },
            &identities,
            3_000,
        );
        assert_eq!(second.clients[0].tx_bps, 8_320);

        let third = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 3_000, 30, 3_000),
                    raw(2, 20, DIR_TX, 2_500, 25, 5_000),
                ],
                truncated: false,
            },
            &identities,
            5_000,
        );
        assert_eq!(third.clients[0].tx_bps, 8_320 + 4_160);

        let fourth = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 3_000, 30, 3_000),
                    raw(2, 20, DIR_TX, 2_500, 25, 5_000),
                ],
                truncated: false,
            },
            &identities,
            6_001,
        );
        assert_eq!(fourth.clients[0].tx_bps, 4_160);
    }

    #[test]
    fn rate_clock_uses_collector_elapsed_time_when_event_timestamp_is_torn() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 1_000, 10, 1_000)],
                truncated: false,
            },
            &identities,
            1_000,
        );

        let snapshot = collector.convert(
            EcmMapRead {
                // Model a concurrent read that sees new counters while
                // last_seen still contains an earlier ECM timestamp.
                entries: vec![raw(1, 10, DIR_TX, 3_000, 30, 1_500)],
                truncated: false,
            },
            &identities,
            3_000,
        );

        assert_eq!(snapshot.clients[0].tx_bps, 8_320);
    }

    #[test]
    fn one_destroy_batch_outlier_does_not_spike_a_connection_rate() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 0, 0, 0)],
                truncated: false,
            },
            &identities,
            0,
        );

        for (now_ms, bytes) in [(2_000, 2_000), (4_000, 4_000), (6_000, 6_000)] {
            let snapshot = collector.convert(
                EcmMapRead {
                    entries: vec![raw(1, 10, DIR_TX, bytes, 0, now_ms)],
                    truncated: false,
                },
                &identities,
                now_ms,
            );
            assert_eq!(snapshot.clients[0].tx_bps, 8_000);
        }

        let destroy = collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 10_000, 0, 8_000)],
                truncated: false,
            },
            &identities,
            8_000,
        );
        assert_eq!(destroy.clients[0].tx_bps, 8_000);
    }

    #[test]
    fn a_reused_connection_generation_rebaselines_without_resetting_other_flows() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 100, 1, 1_000),
                    raw(2, 20, DIR_RX, 100, 1, 1_000),
                ],
                truncated: false,
            },
            &identities,
            1_000,
        );
        let snapshot = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 11, DIR_TX, 50, 1, 3_000),
                    raw(2, 20, DIR_RX, 2_100, 21, 3_000),
                ],
                truncated: false,
            },
            &identities,
            3_000,
        );
        assert_eq!(snapshot.clients[0].tx_bps, 216);
        assert_eq!(snapshot.clients[0].rx_bps, 8_320);
    }

    #[test]
    fn coverage_delta_uses_raw_bytes_and_packets_without_generation_regression() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 1_000, 10, 1_000),
                    raw(2, 20, DIR_RX, 2_000, 20, 1_000),
                ],
                truncated: false,
            },
            &identities,
            1_000,
        );

        let progressed = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 3_000, 30, 3_000),
                    raw(2, 20, DIR_RX, 6_000, 60, 3_000),
                ],
                truncated: false,
            },
            &identities,
            3_000,
        );
        assert_eq!(
            progressed.coverage_delta,
            TrafficCounters {
                tx_bytes: 2_000,
                rx_bytes: 4_000,
                tx_packets: 20,
                rx_packets: 40,
            }
        );

        let disappeared = collector.convert(
            EcmMapRead {
                entries: vec![raw(2, 20, DIR_RX, 6_000, 60, 3_000)],
                truncated: false,
            },
            &identities,
            4_000,
        );
        assert_eq!(disappeared.coverage_delta, TrafficCounters::default());

        let returned = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 4_000, 40, 5_000),
                    raw(2, 20, DIR_RX, 6_000, 60, 3_000),
                    raw(1, 11, DIR_TX, 50_000, 500, 5_000),
                ],
                truncated: false,
            },
            &identities,
            5_000,
        );
        assert_eq!(
            returned.coverage_delta,
            TrafficCounters {
                tx_bytes: 51_000,
                rx_bytes: 0,
                tx_packets: 510,
                rx_packets: 0,
            }
        );
    }

    #[test]
    fn real_router_btf_copy_resolves_when_available() {
        let base = Path::new("/tmp/lanspeed-vmlinux.btf");
        let module = Path::new("/tmp/lanspeed-ecm.btf");
        if !base.exists() || !module.exists() {
            return;
        }
        let layout = resolve_ecm_layout_from_paths(base, module).unwrap();
        assert_eq!(layout.pointer_size, 8);
        assert_eq!(layout.from_index, 0);
        assert_eq!(layout.to_index, 1);
        assert_eq!(layout.ready, 1);
        assert!(layout.connection_node_offset > layout.connection_generation_offset);
    }
}
