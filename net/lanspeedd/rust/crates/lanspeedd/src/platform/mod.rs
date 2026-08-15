#[cfg(feature = "nss-platform")]
pub mod access_edge;
pub mod counters;
pub(crate) mod fast_counter_map;
#[cfg(feature = "nss-platform")]
pub mod nss;
pub mod profile;
pub(crate) mod tc_bpf_monitor;
pub(crate) mod tc_bpf_runtime;
pub(crate) mod tc_bpf_snapshot;
pub mod x86;

pub(crate) const fn confidence(value: crate::probe::Confidence) -> crate::model::Confidence {
    match value {
        crate::probe::Confidence::High => crate::model::Confidence::High,
        crate::probe::Confidence::Medium => crate::model::Confidence::Medium,
        crate::probe::Confidence::Low => crate::model::Confidence::Low,
        crate::probe::Confidence::Unsupported => crate::model::Confidence::Unsupported,
    }
}
