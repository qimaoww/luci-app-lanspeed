use lanspeed_common::{FastCounterValue, LanspeedKey};

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
