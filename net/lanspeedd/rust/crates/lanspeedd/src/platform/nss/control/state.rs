use std::collections::BTreeMap;

use crate::control::{ApplyResult, ControlPlan};

use super::{cpu_path, telemetry, topology::Topology};

pub(super) fn initial_counters(
    plan: &ControlPlan,
    topology: &Topology,
) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
    let mut drops = telemetry::drop_snapshot(plan, topology).unwrap_or_default();
    drops.extend(cpu_path::drop_snapshot(plan).unwrap_or_default());
    let mut classes = telemetry::class_snapshot(plan, topology).unwrap_or_default();
    classes.extend(cpu_path::class_snapshot(plan).unwrap_or_default());
    (drops, classes)
}

pub(super) fn observe(plan: &ControlPlan, previous: &ApplyResult) -> ApplyResult {
    telemetry::observe(plan, previous)
}
