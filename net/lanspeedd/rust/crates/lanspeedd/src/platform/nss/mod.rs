pub(crate) mod bpf_coverage;
#[cfg(feature = "nss-platform")]
pub(crate) mod control;
pub mod ecm_bpf;
pub mod ecm_node;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod evidence;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod fusion;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod output;
#[cfg(any(feature = "openwrt", test))]
pub(crate) mod runtime;
pub(crate) mod tc_snapshot;
#[cfg(any(feature = "openwrt", test))]
pub mod window;

pub const COLLECTION_INTERVAL_MS: u32 = 2_000;
