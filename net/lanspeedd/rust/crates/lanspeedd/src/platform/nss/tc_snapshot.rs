use std::collections::BTreeMap;

use crate::platform::counters::TrafficCounters;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NssTcClientSample {
    pub(crate) mac: String,
    pub(crate) identity_key: String,
    pub(crate) zone: String,
    pub(crate) interface: String,
    pub(crate) ips: Vec<String>,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) tx_bps: u64,
    pub(crate) rx_bps: u64,
    pub(crate) last_seen_ms: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NssTcSnapshot {
    pub(crate) clients: Vec<NssTcClientSample>,
    pub(crate) coverage_deltas: BTreeMap<String, TrafficCounters>,
    pub(crate) coverage_start_ms: Option<u64>,
    pub(crate) coverage_end_ms: u64,
    pub(crate) coverage_ready: bool,
    pub(crate) map_complete: bool,
}
