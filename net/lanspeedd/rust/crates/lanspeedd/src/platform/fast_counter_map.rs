use lanspeed_common::{FastCounterValue, LanspeedKey};

pub const FAST_COUNTER_MAP_READ_RETRIES: usize = 3;

/// Two bounded PerCPU lookups of one FastCounter key. Platform adapters own
/// the map access; consumers own stable-read validation and aggregation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FastCounterMapRead {
    pub entries: Vec<RawFastCounterSample>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawFastCounterSample {
    pub key: LanspeedKey,
    pub first: Vec<FastCounterValue>,
    pub second: Vec<FastCounterValue>,
}

pub fn stable_fast_counter_pair(first: &[FastCounterValue], second: &[FastCounterValue]) -> bool {
    first.len() == second.len()
        && first.iter().zip(second).all(|(before, after)| {
            (*before == FastCounterValue::default() && *after == FastCounterValue::default())
                || (*before == *after && after.seq & 1 == 0)
        })
}

#[cfg(test)]
mod tests {
    use super::stable_fast_counter_pair;
    use lanspeed_common::{FastCounterValue, FAST_COUNTER_ABI_VERSION};

    fn value(seq: u64) -> FastCounterValue {
        FastCounterValue {
            abi_version: FAST_COUNTER_ABI_VERSION,
            reset_generation: 1,
            seq,
            bytes: 10,
            packets: 1,
            last_seen_ns: 20,
        }
    }

    #[test]
    fn accepts_matching_initialized_and_uninitialized_cpu_slots() {
        assert!(stable_fast_counter_pair(
            &[value(2), FastCounterValue::default()],
            &[value(2), FastCounterValue::default()]
        ));
    }

    #[test]
    fn rejects_one_sided_or_odd_cpu_slots() {
        assert!(!stable_fast_counter_pair(
            &[FastCounterValue::default()],
            &[value(2)]
        ));
        assert!(!stable_fast_counter_pair(&[value(3)], &[value(3)]));
    }
}
