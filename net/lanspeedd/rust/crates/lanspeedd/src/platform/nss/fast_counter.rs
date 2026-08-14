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

pub(crate) fn generation_changed(previous: Option<u32>, current: u32) -> bool {
    previous.is_some_and(|generation| generation != current)
}

#[cfg(test)]
mod tests {
    use super::{
        generation_changed, read_stable, validate_stable_pair, FastCounterReadError,
        StableReadError, FAST_COUNTER_READ_RETRIES,
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
        let error = read_stable(FAST_COUNTER_READ_RETRIES, || Ok::<_, ()>(reads.remove(0)))
            .unwrap_err();
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
}
