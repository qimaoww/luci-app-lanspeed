use super::{ApplyResult, ControlPlan};

#[cfg(feature = "nss-platform")]
use super::NSS_MAX_RATE_BPS;
#[cfg(not(feature = "nss-platform"))]
use super::X86_MAX_RATE_BPS;

#[cfg(not(feature = "nss-platform"))]
pub(super) fn apply(plan: &ControlPlan) -> Result<ApplyResult, String> {
    crate::platform::x86::control::apply(plan)
}

#[cfg(not(feature = "nss-platform"))]
pub(super) fn observe(plan: &ControlPlan, previous: &ApplyResult) -> ApplyResult {
    crate::platform::x86::control::observe(plan, previous)
}

#[cfg(not(feature = "nss-platform"))]
pub(super) fn cleanup(plan: &ControlPlan) -> Result<(), String> {
    crate::platform::x86::control::cleanup(plan)
}

#[cfg(not(feature = "nss-platform"))]
pub(super) fn quiesce_prefix_loss(_plan: &ControlPlan) -> Result<(), String> {
    Ok(())
}

#[cfg(not(feature = "nss-platform"))]
pub(super) fn max_rate_bps() -> u64 {
    crate::platform::x86::control::max_rate_bps()
}

#[cfg(not(feature = "nss-platform"))]
pub(super) const HARD_MAX_RATE_BPS: u64 = X86_MAX_RATE_BPS;

#[cfg(not(feature = "nss-platform"))]
pub(super) const REQUIRES_SHAPING_ADDRESS: bool = false;

#[cfg(feature = "nss-platform")]
pub(super) fn apply(plan: &ControlPlan) -> Result<ApplyResult, String> {
    crate::platform::nss::control::apply(plan)
}

#[cfg(feature = "nss-platform")]
pub(super) fn observe(plan: &ControlPlan, previous: &ApplyResult) -> ApplyResult {
    crate::platform::nss::control::observe(plan, previous)
}

#[cfg(feature = "nss-platform")]
pub(super) fn cleanup(plan: &ControlPlan) -> Result<(), String> {
    crate::platform::nss::control::cleanup(plan)
}

#[cfg(feature = "nss-platform")]
pub(super) fn quiesce_prefix_loss(plan: &ControlPlan) -> Result<(), String> {
    crate::platform::nss::control::quiesce_prefix_loss(plan)
}

#[cfg(feature = "nss-platform")]
pub(super) fn max_rate_bps() -> u64 {
    crate::platform::nss::control::max_rate_bps()
}

#[cfg(feature = "nss-platform")]
pub(super) const HARD_MAX_RATE_BPS: u64 = NSS_MAX_RATE_BPS;

#[cfg(feature = "nss-platform")]
pub(super) const REQUIRES_SHAPING_ADDRESS: bool = true;
