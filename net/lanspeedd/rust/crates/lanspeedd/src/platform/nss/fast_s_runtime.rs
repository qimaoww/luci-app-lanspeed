//! Shadow-only FastS aggregation over the platform-neutral FastCounter map.

use std::collections::BTreeMap;

use lanspeed_common::LanspeedKey;

use crate::platform::fast_counter_map::FastCounterMapRead;

use super::fast_counter::{FastCounterAggregate, FastSReadError, FastSReader};

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FastSKey {
    pub ifindex: u32,
    pub vlan_or_zone: u16,
    pub direction: u8,
    pub mac: [u8; 6],
}

impl From<LanspeedKey> for FastSKey {
    fn from(value: LanspeedKey) -> Self {
        Self {
            ifindex: value.ifindex,
            vlan_or_zone: value.vlan_or_zone,
            direction: value.direction,
            mac: value.mac,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastSSample {
    pub key: FastSKey,
    pub aggregate: FastCounterAggregate,
    pub sample_ms: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastSSnapshot {
    pub sample_ms: u64,
    pub map_entries: usize,
    pub valid_entries: usize,
    pub invalid_entries: usize,
    pub truncated: bool,
    pub reset_generation: u32,
    pub bytes: u64,
    pub packets: u64,
    pub entries: Vec<FastSSample>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FastSRuntime {
    readers: BTreeMap<FastSKey, FastSReader>,
    last_snapshot: Option<FastSSnapshot>,
    reset_generation: u32,
    invalid_reads: u64,
    truncated_reads: u64,
    read_failures: u64,
}

impl Default for FastSRuntime {
    fn default() -> Self {
        Self {
            readers: BTreeMap::new(),
            last_snapshot: None,
            reset_generation: 1,
            invalid_reads: 0,
            truncated_reads: 0,
            read_failures: 0,
        }
    }
}

impl FastSRuntime {
    pub(crate) fn collect(&mut self, read: FastCounterMapRead, now_ms: u64) -> FastSSnapshot {
        if read.truncated {
            self.readers.clear();
            self.reset_generation = self.reset_generation.saturating_add(1).max(1);
            self.truncated_reads = self.truncated_reads.saturating_add(1);
            let snapshot = FastSSnapshot {
                sample_ms: now_ms,
                map_entries: read.entries.len(),
                truncated: true,
                reset_generation: self.reset_generation,
                ..FastSSnapshot::default()
            };
            self.last_snapshot = Some(snapshot.clone());
            return snapshot;
        }

        let map_entries = read.entries.len();
        let mut entries = Vec::new();
        let mut invalid_entries = 0;
        let mut sample_ms = now_ms;
        let mut bytes: u64 = 0;
        let mut packets: u64 = 0;
        for raw in read.entries {
            let key = FastSKey::from(raw.key);
            let reader = self.readers.entry(key).or_default();
            match reader.read(&raw.first, &raw.second) {
                Ok(aggregate) => {
                    let entry_sample_ms = (aggregate.last_seen_ns / 1_000_000).min(now_ms);
                    sample_ms = sample_ms.max(entry_sample_ms);
                    bytes = bytes.saturating_add(aggregate.bytes);
                    packets = packets.saturating_add(aggregate.packets);
                    entries.push(FastSSample {
                        key,
                        aggregate,
                        sample_ms: entry_sample_ms,
                    });
                }
                Err(error) => {
                    if matches!(error, FastSReadError::ResetGenerationChanged { .. }) {
                        self.reset_generation = self.reset_generation.saturating_add(1).max(1);
                    }
                    invalid_entries += 1;
                    self.invalid_reads = self.invalid_reads.saturating_add(1);
                }
            }
        }

        let snapshot = FastSSnapshot {
            sample_ms,
            map_entries,
            valid_entries: entries.len(),
            invalid_entries,
            truncated: false,
            reset_generation: self.reset_generation.max(1),
            bytes,
            packets,
            entries,
        };
        self.last_snapshot = Some(snapshot.clone());
        snapshot
    }

    pub(crate) fn last_snapshot(&self) -> Option<&FastSSnapshot> {
        self.last_snapshot.as_ref()
    }

    pub(crate) const fn invalid_reads(&self) -> u64 {
        self.invalid_reads
    }

    pub(crate) const fn truncated_reads(&self) -> u64 {
        self.truncated_reads
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
    use super::{FastSKey, FastSRuntime};
    use crate::platform::fast_counter_map::{FastCounterMapRead, RawFastCounterSample};
    use lanspeed_common::{FastCounterValue, LanspeedKey, FAST_COUNTER_ABI_VERSION};

    fn key(direction: u8) -> LanspeedKey {
        LanspeedKey {
            ifindex: 3,
            vlan_or_zone: 4,
            direction,
            mac: [1, 2, 3, 4, 5, 6],
            ..LanspeedKey::default()
        }
    }

    fn value(bytes: u64, generation: u32) -> FastCounterValue {
        FastCounterValue {
            abi_version: FAST_COUNTER_ABI_VERSION,
            reset_generation: generation,
            seq: 2,
            bytes,
            packets: bytes / 10,
            last_seen_ns: 1_000_000_000,
        }
    }

    fn read(bytes: u64, generation: u32, truncated: bool) -> FastCounterMapRead {
        FastCounterMapRead {
            entries: vec![RawFastCounterSample {
                key: key(1),
                first: vec![value(bytes, generation)],
                second: vec![value(bytes, generation)],
            }],
            truncated,
        }
    }

    #[test]
    fn stable_entry_is_published_and_torn_entry_is_telemetried() {
        let mut runtime = FastSRuntime::default();
        let snapshot = runtime.collect(read(10, 1, false), 1_500);
        assert_eq!(snapshot.valid_entries, 1);
        assert_eq!(snapshot.entries[0].key, FastSKey::from(key(1)));

        let mut invalid = read(11, 1, false);
        invalid.entries[0].second[0].seq = 4;
        let snapshot = runtime.collect(invalid, 2_500);
        assert_eq!(snapshot.invalid_entries, 1);
        assert_eq!(runtime.invalid_reads(), 1);
    }

    #[test]
    fn truncated_read_rewarms_readers() {
        let mut runtime = FastSRuntime::default();
        runtime.collect(read(10, 1, false), 1_000);
        let snapshot = runtime.collect(read(10, 1, true), 2_000);
        assert!(snapshot.truncated);
        assert_eq!(runtime.truncated_reads(), 1);
        let snapshot = runtime.collect(read(20, 1, false), 3_000);
        assert_eq!(snapshot.valid_entries, 1);
    }

    #[test]
    fn unavailable_reads_are_counted_separately() {
        let mut runtime = FastSRuntime::default();
        runtime.record_read_failure();
        assert_eq!(runtime.read_failures(), 1);
    }
}
