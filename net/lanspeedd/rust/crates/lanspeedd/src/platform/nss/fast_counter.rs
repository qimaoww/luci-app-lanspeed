//! Stable FastCounter reads shared by the NSS FastN/FastS readers.
//!
//! This module only validates the ABI and read protocol. It does not choose a
//! rate owner and it does not publish a UI snapshot.

use lanspeed_common::{FastCounterValue, FAST_COUNTER_ABI_VERSION};

pub(crate) const FAST_COUNTER_READ_RETRIES: usize = 3;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum StableReadError {
    AbiMismatch { first: u32, second: u32 },
    ResetGenerationMismatch { first: u32, second: u32 },
    SequenceUnstable { first: u64, second: u64 },
    ValueChanged,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FastSReadError {
    NoCpuValues,
    CpuCountChanged { first: usize, second: usize },
    CpuValueUnstable { cpu: usize, error: StableReadError },
    CpuGenerationMismatch { expected: u32, actual: u32 },
    ResetGenerationChanged { previous: u32, current: u32 },
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FastNReadError {
    Unstable(StableReadError),
    ResetGenerationChanged { previous: u32, current: u32 },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastCounterAggregate {
    pub abi_version: u32,
    pub reset_generation: u32,
    pub bytes: u64,
    pub packets: u64,
    pub last_seen_ns: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastSReader {
    last_reset_generation: Option<u32>,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct FastNReader {
    last_reset_generation: Option<u32>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FastCounterReadError<E> {
    Source(E),
    Unstable {
        attempts: usize,
        last: StableReadError,
    },
}

/// Validate two reads of one counter value.
pub(crate) fn validate_stable_pair(
    first: FastCounterValue,
    second: FastCounterValue,
) -> Result<FastCounterValue, StableReadError> {
    if first.abi_version != FAST_COUNTER_ABI_VERSION
        || second.abi_version != FAST_COUNTER_ABI_VERSION
    {
        return Err(StableReadError::AbiMismatch {
            first: first.abi_version,
            second: second.abi_version,
        });
    }
    if first.reset_generation != second.reset_generation {
        return Err(StableReadError::ResetGenerationMismatch {
            first: first.reset_generation,
            second: second.reset_generation,
        });
    }
    if first.seq != second.seq || first.seq & 1 != 0 {
        return Err(StableReadError::SequenceUnstable {
            first: first.seq,
            second: second.seq,
        });
    }
    if first.bytes != second.bytes
        || first.packets != second.packets
        || first.last_seen_ns != second.last_seen_ns
    {
        return Err(StableReadError::ValueChanged);
    }
    Ok(second)
}

/// Read a source twice per attempt and reject torn snapshots after bounded
/// retries. A retry never sleeps, so this cannot block the rate worker behind
/// a slow producer.
pub(crate) fn read_stable<E>(
    attempts: usize,
    mut read: impl FnMut() -> Result<FastCounterValue, E>,
) -> Result<FastCounterValue, FastCounterReadError<E>> {
    let attempts = attempts.max(1);
    let mut last = None;
    for _ in 0..attempts {
        let first = read().map_err(FastCounterReadError::Source)?;
        let second = read().map_err(FastCounterReadError::Source)?;
        match validate_stable_pair(first, second) {
            Ok(value) => return Ok(value),
            Err(error) => last = Some(error),
        }
    }
    Err(FastCounterReadError::Unstable {
        attempts,
        last: last.expect("at least one stable-read attempt must run"),
    })
}

/// Aggregate two PerCPU snapshots only after every CPU has a stable pair.
/// `first` and `second` represent the two kernel lookups of the same key.
pub(crate) fn aggregate_per_cpu(
    first: &[FastCounterValue],
    second: &[FastCounterValue],
) -> Result<FastCounterAggregate, FastSReadError> {
    if first.is_empty() {
        return Err(FastSReadError::NoCpuValues);
    }
    if first.len() != second.len() {
        return Err(FastSReadError::CpuCountChanged {
            first: first.len(),
            second: second.len(),
        });
    }
    let mut aggregate = FastCounterAggregate::default();
    let mut initialized_cpus = 0;
    for (cpu, (before, after)) in first.iter().zip(second).enumerate() {
        if *before == FastCounterValue::default() && *after == FastCounterValue::default() {
            continue;
        }
        let value = validate_stable_pair(*before, *after)
            .map_err(|error| FastSReadError::CpuValueUnstable { cpu, error })?;
        if initialized_cpus == 0 {
            aggregate.abi_version = value.abi_version;
            aggregate.reset_generation = value.reset_generation;
        } else if value.reset_generation != aggregate.reset_generation {
            return Err(FastSReadError::CpuGenerationMismatch {
                expected: aggregate.reset_generation,
                actual: value.reset_generation,
            });
        }
        initialized_cpus += 1;
        aggregate.bytes = aggregate.bytes.saturating_add(value.bytes);
        aggregate.packets = aggregate.packets.saturating_add(value.packets);
        aggregate.last_seen_ns = aggregate.last_seen_ns.max(value.last_seen_ns);
    }
    if initialized_cpus == 0 {
        return Err(FastSReadError::NoCpuValues);
    }
    Ok(aggregate)
}

impl FastSReader {
    pub(crate) fn read(
        &mut self,
        first: &[FastCounterValue],
        second: &[FastCounterValue],
    ) -> Result<FastCounterAggregate, FastSReadError> {
        let aggregate = aggregate_per_cpu(first, second)?;
        if let Some(previous) = self.last_reset_generation {
            if previous != aggregate.reset_generation {
                self.last_reset_generation = Some(aggregate.reset_generation);
                return Err(FastSReadError::ResetGenerationChanged {
                    previous,
                    current: aggregate.reset_generation,
                });
            }
        } else {
            self.last_reset_generation = Some(aggregate.reset_generation);
        }
        Ok(aggregate)
    }
}

impl FastNReader {
    pub(crate) fn read(
        &mut self,
        first: FastCounterValue,
        second: FastCounterValue,
    ) -> Result<FastCounterAggregate, FastNReadError> {
        let value = validate_stable_pair(first, second).map_err(FastNReadError::Unstable)?;
        if let Some(previous) = self.last_reset_generation {
            if previous != value.reset_generation {
                self.last_reset_generation = Some(value.reset_generation);
                return Err(FastNReadError::ResetGenerationChanged {
                    previous,
                    current: value.reset_generation,
                });
            }
        } else {
            self.last_reset_generation = Some(value.reset_generation);
        }
        Ok(FastCounterAggregate {
            abi_version: value.abi_version,
            reset_generation: value.reset_generation,
            bytes: value.bytes,
            packets: value.packets,
            last_seen_ns: value.last_seen_ns,
        })
    }
}

pub(crate) fn generation_changed(previous: Option<u32>, current: u32) -> bool {
    previous.is_some_and(|generation| generation != current)
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_per_cpu, generation_changed, read_stable, validate_stable_pair,
        FastCounterAggregate, FastCounterReadError, FastNReadError, FastNReader, FastSReadError,
        FastSReader, StableReadError, FAST_COUNTER_READ_RETRIES,
    };
    use lanspeed_common::{FastCounterValue, FAST_COUNTER_ABI_VERSION};

    fn value(seq: u64) -> FastCounterValue {
        FastCounterValue {
            abi_version: FAST_COUNTER_ABI_VERSION,
            reset_generation: 7,
            seq,
            bytes: 10,
            packets: 2,
            last_seen_ns: 50,
        }
    }

    #[test]
    fn accepts_an_even_sequence_and_rejects_odd_or_mismatched_reads() {
        assert_eq!(validate_stable_pair(value(4), value(4)), Ok(value(4)));
        assert_eq!(
            validate_stable_pair(value(3), value(3)),
            Err(StableReadError::SequenceUnstable {
                first: 3,
                second: 3,
            })
        );
        assert_eq!(
            validate_stable_pair(value(4), value(6)),
            Err(StableReadError::SequenceUnstable {
                first: 4,
                second: 6,
            })
        );
    }

    #[test]
    fn accepts_a_wrapped_even_sequence() {
        assert!(validate_stable_pair(value(u64::MAX - 1), value(u64::MAX - 1)).is_ok());
        assert!(validate_stable_pair(value(0), value(0)).is_ok());
    }

    #[test]
    fn rejects_abi_reset_and_value_mismatch() {
        let mut abi = value(4);
        abi.abi_version += 1;
        assert!(matches!(
            validate_stable_pair(abi, value(4)),
            Err(StableReadError::AbiMismatch { .. })
        ));
        let mut reset = value(4);
        reset.reset_generation += 1;
        assert!(matches!(
            validate_stable_pair(reset, value(4)),
            Err(StableReadError::ResetGenerationMismatch { .. })
        ));
        let mut changed = value(4);
        changed.bytes += 1;
        assert_eq!(
            validate_stable_pair(value(4), changed),
            Err(StableReadError::ValueChanged)
        );
    }

    #[test]
    fn retries_are_bounded_and_do_not_accept_a_torn_value() {
        let mut reads = vec![value(1), value(2), value(3), value(5), value(6), value(7)];
        let error =
            read_stable(FAST_COUNTER_READ_RETRIES, || Ok::<_, ()>(reads.remove(0))).unwrap_err();
        assert_eq!(
            error,
            FastCounterReadError::Unstable {
                attempts: FAST_COUNTER_READ_RETRIES,
                last: StableReadError::SequenceUnstable {
                    first: 6,
                    second: 7,
                },
            }
        );
    }

    #[test]
    fn source_failure_is_returned_without_retrying_forever() {
        let mut calls = 0;
        let error = read_stable(FAST_COUNTER_READ_RETRIES, || {
            calls += 1;
            Err::<FastCounterValue, _>("read failed")
        })
        .unwrap_err();
        assert_eq!(error, FastCounterReadError::Source("read failed"));
        assert_eq!(calls, 1);
    }

    #[test]
    fn generation_changes_are_explicit() {
        assert!(!generation_changed(None, 3));
        assert!(!generation_changed(Some(3), 3));
        assert!(generation_changed(Some(3), 4));
    }

    #[test]
    fn aggregates_each_cpu_and_takes_the_latest_seen_timestamp() {
        let mut first = [value(2), value(4)];
        first[0].bytes = 20;
        first[0].packets = 4;
        first[0].last_seen_ns = 100;
        first[1].bytes = 30;
        first[1].packets = 6;
        first[1].last_seen_ns = 90;
        let second = first;
        let aggregate = aggregate_per_cpu(&first, &second).unwrap();
        assert_eq!(
            aggregate,
            FastCounterAggregate {
                abi_version: FAST_COUNTER_ABI_VERSION,
                reset_generation: 7,
                bytes: 50,
                packets: 10,
                last_seen_ns: 100,
            }
        );
    }

    #[test]
    fn rejects_partial_cpu_reads_and_cross_cpu_generation_mismatch() {
        assert_eq!(
            aggregate_per_cpu(&[value(2)], &[]),
            Err(FastSReadError::CpuCountChanged {
                first: 1,
                second: 0,
            })
        );
        let mut first = [value(2), value(4)];
        first[1].reset_generation = 8;
        let second = first;
        assert_eq!(
            aggregate_per_cpu(&first, &second),
            Err(FastSReadError::CpuGenerationMismatch {
                expected: 7,
                actual: 8,
            })
        );
    }

    #[test]
    fn skips_uninitialized_per_cpu_slots_but_rejects_one_sided_presence() {
        let active = value(2);
        let aggregate = aggregate_per_cpu(
            &[
                FastCounterValue::default(),
                active,
                FastCounterValue::default(),
            ],
            &[
                FastCounterValue::default(),
                active,
                FastCounterValue::default(),
            ],
        )
        .unwrap();
        assert_eq!(aggregate.bytes, active.bytes);
        assert_eq!(
            aggregate_per_cpu(&[FastCounterValue::default()], &[active],),
            Err(FastSReadError::CpuValueUnstable {
                cpu: 0,
                error: StableReadError::AbiMismatch {
                    first: 0,
                    second: FAST_COUNTER_ABI_VERSION,
                },
            })
        );
    }

    #[test]
    fn reader_rebaselines_after_a_reset_generation_change() {
        let first = [value(2)];
        let second = [value(2)];
        let mut reader = FastSReader::default();
        assert!(reader.read(&first, &second).is_ok());
        let mut reset = value(2);
        reset.reset_generation = 8;
        assert_eq!(
            reader.read(&[reset], &[reset]),
            Err(FastSReadError::ResetGenerationChanged {
                previous: 7,
                current: 8,
            })
        );
        assert!(reader.read(&[reset], &[reset]).is_ok());
    }

    #[test]
    fn fast_n_reader_uses_the_same_stable_protocol_and_rebaselines() {
        let mut reader = FastNReader::default();
        assert_eq!(
            reader.read(value(3), value(3)),
            Err(FastNReadError::Unstable(
                StableReadError::SequenceUnstable {
                    first: 3,
                    second: 3,
                }
            ))
        );
        assert_eq!(
            reader.read(value(4), value(4)).unwrap(),
            FastCounterAggregate {
                abi_version: FAST_COUNTER_ABI_VERSION,
                reset_generation: 7,
                bytes: 10,
                packets: 2,
                last_seen_ns: 50,
            }
        );
        let mut reset = value(4);
        reset.reset_generation = 9;
        assert_eq!(
            reader.read(reset, reset),
            Err(FastNReadError::ResetGenerationChanged {
                previous: 7,
                current: 9,
            })
        );
    }
}
