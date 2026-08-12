use crate::control::ControlPlan;

use super::firewall;

pub(super) fn preflight(plan: &ControlPlan) -> Result<(), String> {
    firewall::preflight(plan)
}

pub(super) fn quiesce(plan: &ControlPlan) -> Result<(), String> {
    firewall::quiesce(plan)
}

pub(super) fn commit(plan: &ControlPlan) -> Result<(), String> {
    firewall::apply(plan)
}

pub(super) fn refresh_connections(plan: &ControlPlan) -> Result<(), String> {
    firewall::clear_controlled_connections(plan)
}

pub(super) fn has_conntrack_identities(plan: &ControlPlan) -> bool {
    firewall::has_conntrack_identities(plan)
}

pub(super) fn cleanup() -> Result<(), String> {
    firewall::cleanup()
}
