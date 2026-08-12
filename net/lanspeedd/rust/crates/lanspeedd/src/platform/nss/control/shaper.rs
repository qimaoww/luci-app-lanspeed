use crate::control::ControlPlan;

use super::{qdisc, topology::Topology};

pub(super) fn preflight(topology: &Topology) -> Result<(), String> {
    qdisc::preflight(topology)
}

pub(super) fn stage(plan: &ControlPlan, topology: &Topology) -> Result<(), String> {
    qdisc::apply(plan, topology)
}

pub(super) fn cleanup() -> Result<(), String> {
    qdisc::cleanup()
}

pub(super) fn passthrough() -> Result<(), String> {
    qdisc::passthrough()
}

pub(super) fn owned_tree_present() -> Result<bool, String> {
    qdisc::owned_tree_present()
}
