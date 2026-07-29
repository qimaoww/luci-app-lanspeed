pub mod counters;
pub mod nss;
pub mod x86;

pub(crate) const fn confidence(value: crate::probe::Confidence) -> crate::model::Confidence {
    match value {
        crate::probe::Confidence::High => crate::model::Confidence::High,
        crate::probe::Confidence::Medium => crate::model::Confidence::Medium,
        crate::probe::Confidence::Low => crate::model::Confidence::Low,
        crate::probe::Confidence::Unsupported => crate::model::Confidence::Unsupported,
    }
}
