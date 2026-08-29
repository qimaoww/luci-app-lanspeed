pub(crate) mod bpf_coverage;
#[cfg(feature = "nss-platform")]
pub(crate) mod control;
pub mod ecm_bpf;
pub mod ecm_node;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod evidence;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod evidence_lease;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fast_counter;
pub(crate) mod fast_n_runtime;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fast_rate;
pub(crate) mod fast_rate_clients;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fast_rate_contract;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fast_rate_rolling;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fast_rate_shadow;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fast_rate_store;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fast_rate_wakeup;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fast_rate_worker;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fast_s_runtime;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fast_s_timer;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fusion;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod hardware_verifier;
#[cfg(any(feature = "nss-platform", test))]
pub(crate) mod interface_rate;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod low_rate_window;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod output;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod rate_mux;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod runtime;
pub(crate) mod tc_bpf_runtime;
pub(crate) mod tc_bpf_snapshot;
pub(crate) mod tc_snapshot;
#[cfg(any(feature = "openwrt", test))]
pub mod window;

pub const COLLECTION_INTERVAL_MS: u32 = 2_000;
