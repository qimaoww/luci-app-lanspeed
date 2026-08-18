//! Stable per-client FastN aggregation from the ECM PerCPU counter map.
//!
//! FastN uses the same PerCPU seq/read protocol as FastS, but its key is the
//! ECM MAC+direction identity rather than a TC interface key. The snapshot is
//! published only after the rate worker supplies a shared N/S window.

use std::collections::BTreeMap;

use lanspeed_common::EcmKey;

use super::{
    ecm_bpf::EcmFastCounterMapRead,
    fast_counter::{FastCounterAggregate, FastSReadError, FastSReader},
};

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FastNKey {
    pub connection: u64,
    pub generation: u32,
    pub direction: u8,
    pub mac: [u8; 6],
}

impl From<EcmKey> for FastNKey {
    fn from(value: EcmKey) -> Self {
        Self {
            connection: value.connection,
            generation: value.generation,
            direction: value.direction,
            mac: value.mac,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastNSample {
    pub key: FastNKey,
    pub aggregate: FastCounterAggregate,
    pub sample_ms: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastNSnapshot {
    pub sample_ms: u64,
    /// Latest counter update timestamp observed in this map. This is kept
    /// separate from `sample_ms`, which is the completed userspace read time.
    pub progress_ms: u64,
    pub map_entries: usize,
    pub valid_entries: usize,
    pub invalid_entries: usize,
    pub truncated: bool,
    pub reset_generation: u32,
    pub bytes: u64,
    pub packets: u64,
    pub entries: Vec<FastNSample>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastNRuntime {
    readers: BTreeMap<FastNKey, FastSReader>,
    last_snapshot: Option<FastNSnapshot>,
    invalid_reads: u64,
    truncated_reads: u64,
    reset_generation_changes: u64,
    read_failures: u64,
}

impl FastNRuntime {
    pub(crate) fn collect(&mut self, read: EcmFastCounterMapRead, now_ms: u64) -> FastNSnapshot {
        if read.truncated {
            self.readers.clear();
            self.truncated_reads = self.truncated_reads.saturating_add(1);
            let snapshot = FastNSnapshot {
                sample_ms: now_ms,
                map_entries: read.entries.len(),
                truncated: true,
                ..FastNSnapshot::default()
            };
            self.last_snapshot = Some(snapshot.clone());
            return snapshot;
        }

        let map_entries = read.entries.len();
        let mut entries = Vec::new();
        let mut invalid_entries = 0;
        let mut sample_ms = now_ms;
        let mut progress_ms = 0;
        let mut bytes: u64 = 0;
        let mut packets: u64 = 0;
        let mut reset_generation: u32 = 0;
        for raw in read.entries {
            let key = FastNKey::from(raw.key);
            let reader = self.readers.entry(key).or_default();
            match reader.read(&raw.first, &raw.second) {
                Ok(aggregate) => {
                    let entry_sample_ms = (aggregate.last_seen_ns / 1_000_000).min(now_ms);
                    sample_ms = sample_ms.max(entry_sample_ms);
                    progress_ms = progress_ms.max(entry_sample_ms);
                    reset_generation = if reset_generation == 0 {
                        aggregate.reset_generation
                    } else if reset_generation != aggregate.reset_generation {
                        invalid_entries += 1;
                        self.invalid_reads = self.invalid_reads.saturating_add(1);
                        continue;
                    } else {
                        reset_generation
                    };
                    bytes = bytes.saturating_add(aggregate.bytes);
                    packets = packets.saturating_add(aggregate.packets);
                    entries.push(FastNSample {
                        key,
                        aggregate,
                        sample_ms: entry_sample_ms,
                    });
                }
                Err(error) => {
                    invalid_entries += 1;
                    self.invalid_reads = self.invalid_reads.saturating_add(1);
                    if matches!(error, FastSReadError::ResetGenerationChanged { .. }) {
                        self.reset_generation_changes =
                            self.reset_generation_changes.saturating_add(1);
                    }
                }
            }
        }

        let snapshot = FastNSnapshot {
            sample_ms,
            progress_ms,
            map_entries,
            valid_entries: entries.len(),
            invalid_entries,
            truncated: false,
            reset_generation,
            bytes,
            packets,
            entries,
        };
        self.last_snapshot = Some(snapshot.clone());
        snapshot
    }

    pub(crate) fn last_snapshot(&self) -> Option<&FastNSnapshot> {
        self.last_snapshot.as_ref()
    }

    pub(crate) const fn invalid_reads(&self) -> u64 {
        self.invalid_reads
    }

    pub(crate) const fn truncated_reads(&self) -> u64 {
        self.truncated_reads
    }

    pub(crate) const fn reset_generation_changes(&self) -> u64 {
        self.reset_generation_changes
    }

    pub(crate) const fn read_failures(&self) -> u64 {
        self.read_failures
    }

    pub(crate) fn record_read_failure(&mut self) {
        self.read_failures = self.read_failures.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{FastNKey, FastNRuntime};
    use crate::platform::nss::ecm_bpf::{EcmFastCounterMapRead, RawEcmFastCounterSample};
    use lanspeed_common::{EcmKey, FastCounterValue, DIR_TX, FAST_COUNTER_ABI_VERSION};

    fn value(bytes: u64, seq: u64) -> FastCounterValue {
        FastCounterValue {
            abi_version: FAST_COUNTER_ABI_VERSION,
            reset_generation: 1,
            seq,
            bytes,
            packets: bytes / 10,
            last_seen_ns: 2_000_000_000,
        }
    }

    fn read(bytes: u64) -> EcmFastCounterMapRead {
        EcmFastCounterMapRead {
            entries: vec![RawEcmFastCounterSample {
                key: EcmKey {
                    mac: [2, 0, 0, 0, 0, 1],
                    direction: DIR_TX,
                    ..EcmKey::default()
                },
                first: vec![value(bytes, 2)],
                second: vec![value(bytes, 2)],
            }],
            truncated: false,
        }
    }

    #[test]
    fn aggregates_stable_ecm_percpu_values_without_reusing_torn_reads() {
        let mut runtime = FastNRuntime::default();
        let first = runtime.collect(read(100), 2_000);
        assert_eq!(first.valid_entries, 1);
        assert_eq!(first.bytes, 100);
        assert_eq!(
            first.entries[0].key,
            FastNKey {
                connection: 0,
                generation: 0,
                direction: DIR_TX,
                mac: [2, 0, 0, 0, 0, 1],
            }
        );

        let mut torn = read(200);
        torn.entries[0].second[0].seq = 4;
        let second = runtime.collect(torn, 3_000);
        assert_eq!(second.valid_entries, 0);
        assert_eq!(second.invalid_entries, 1);
        assert_eq!(runtime.invalid_reads(), 1);
        assert_eq!(runtime.reset_generation_changes(), 0);
    }

    #[test]
    fn truncated_ecm_fast_map_rewarms_the_reader() {
        let mut runtime = FastNRuntime::default();
        let mut truncated = read(100);
        truncated.truncated = true;
        let snapshot = runtime.collect(truncated, 2_000);
        assert!(snapshot.truncated);
        assert_eq!(runtime.truncated_reads(), 1);
        assert!(runtime.last_snapshot().unwrap().entries.is_empty());
    }
}
