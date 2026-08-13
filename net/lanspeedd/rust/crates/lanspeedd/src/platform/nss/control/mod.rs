mod capability;
mod classifier;
mod cpu_path;
mod ecm_qos;
mod firewall;
mod legacy;
mod qdisc;
mod rollback;
mod shaper;
mod state;
mod system;
mod telemetry;
mod topology;

use crate::control::{ApplyResult, ControlPlan, NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD};

pub(crate) use cpu_path::{
    PathProbeBook, PathProbeDirectionWindow, PathProbeSnapshot, PathProbeWindow,
};

pub(crate) fn apply(plan: &ControlPlan) -> Result<ApplyResult, String> {
    if let Err(error) = legacy::cleanup() {
        return fail_with_rollback(plan, error);
    }
    if plan.rules.is_empty() {
        // An explicitly deleted, uniquely-owned identity carries its former
        // addresses in `conntrack_cleanup_ips`.  Once those addresses are
        // proven safe to clear, remove the complete LAN Speed tree as part of
        // the same transaction.  A plan with no such evidence is a topology
        // or identity-loss transition: keep the physical root as passthrough
        // rather than deleting a shared edge queue speculatively.
        if plan_has_explicit_cleanup(plan) {
            rollback::cleanup(plan)?;
        } else {
            rollback::deactivate(plan)?;
        }
        return Ok(capability::probe());
    }
    if plan.rules.iter().any(|rule| {
        (rule.upload_bps != 0 || rule.download_bps != 0 || rule.internet_disabled)
            && rule.ips.is_empty()
    }) {
        return fail_with_rollback(plan, "identity_address_unavailable".into());
    }

    if let Err(error) = classifier::preflight(plan) {
        return fail_with_rollback(plan, error);
    }
    if let Err(error) = cpu_path::preflight(plan) {
        return fail_with_rollback(plan, error);
    }
    let shaping = plan
        .rules
        .iter()
        .any(|rule| rule.upload_bps != 0 || rule.download_bps != 0);
    let topology = if shaping {
        match capability::preflight_shaping(plan) {
            Ok(topology) => Some(topology),
            Err(error) => return fail_with_rollback(plan, error),
        }
    } else {
        None
    };
    if let Some(topology) = topology.as_ref() {
        if let Err(error) = shaper::preflight(topology) {
            return fail_with_rollback(plan, error);
        }
    }

    // Existing mappings may refer to a queue that is about to change. Keep
    // block rules but withdraw QoS tags until every new NSS tree is verified.
    if let Err(error) = classifier::quiesce(plan) {
        return fail_with_rollback(plan, error);
    }
    if let Err(error) = cpu_path::quiesce(plan) {
        return fail_with_rollback(plan, error);
    }
    if let Err(error) = classifier::refresh_connections(plan) {
        return fail_with_rollback(plan, error);
    }
    if let Some(topology) = topology.as_ref() {
        if let Err(error) = shaper::stage(plan, topology) {
            return fail_with_rollback(plan, error);
        }
    }
    if let Err(error) = cpu_path::stage(plan) {
        return fail_with_rollback(plan, error);
    }
    if let Err(error) = classifier::commit(plan) {
        return fail_with_rollback(plan, error);
    }
    if let Err(error) = classifier::refresh_connections(plan) {
        return fail_with_rollback(plan, error);
    }

    let (drops, classes) = topology.as_ref().map_or_else(
        || (Default::default(), Default::default()),
        |topology| state::initial_counters(plan, topology),
    );
    let path_pending = plan.rules.iter().any(|rule| {
        (rule.upload_bps != 0 && !plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD))
            || (rule.download_bps != 0
                && !plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD))
    });
    Ok(ApplyResult {
        state: if shaping {
            "pending_new_connections"
        } else {
            "applied"
        }
        .into(),
        reason: shaping.then(|| {
            if path_pending {
                "nss_path_identity_pending".into()
            } else {
                "traffic_verification_pending".into()
            }
        }),
        shaping_supported: capability::shaping_supported_for(plan),
        blocking_supported: capability::blocking_supported(),
        queue_overflow: false,
        queue_drop_counters: drops,
        class_counter_baselines: classes,
        verified_directions: Default::default(),
        nss_verified_directions: Default::default(),
        cpu_verified_directions: Default::default(),
        verification_failures: Default::default(),
    })
}

/// Recover exact LAN Speed classifier slots left by a prior NSS daemon
/// process. This is intentionally NSS-only and never adopts a foreign hook.
pub(crate) fn recover_classifier_slots(interfaces: &[String]) -> Result<bool, String> {
    cpu_path::recover_classifier_slots(interfaces)
}

pub(crate) fn path_probe_snapshot(
    plan: &ControlPlan,
    epoch_end_ms: u64,
) -> Result<PathProbeSnapshot, String> {
    cpu_path::path_probe_snapshot(plan, epoch_end_ms)
}

fn fail_with_rollback(plan: &ControlPlan, error: String) -> Result<ApplyResult, String> {
    match rollback::quiesce(plan) {
        Err(rollback_error) => {
            eprintln!(
                "lanspeedd: NSS control apply failed: {error}; rollback failed: {rollback_error}"
            );
            Err("nss_control_rollback_failed".into())
        }
        Ok(()) => Err(error),
    }
}

pub(crate) fn observe(plan: &ControlPlan, previous: &ApplyResult) -> ApplyResult {
    // A structural audit deliberately asks several owners about the same TC
    // device. Reuse identical read results inside this observation only; the
    // cache is discarded before any transactional rebuild can begin.
    system::with_observation_cache(|| state::observe(plan, previous))
}

pub(crate) fn cleanup(plan: &ControlPlan) -> Result<(), String> {
    let legacy_result = legacy::cleanup();
    let control_result = rollback::cleanup(plan);
    legacy_result.and(control_result)
}

pub(crate) fn quiesce_prefix_loss(plan: &ControlPlan) -> Result<(), String> {
    rollback::deactivate(plan)
}

pub(crate) const fn max_rate_bps() -> u64 {
    capability::max_rate_bps()
}

fn plan_has_explicit_cleanup(plan: &ControlPlan) -> bool {
    !plan.conntrack_cleanup_ips.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_plan() -> ControlPlan {
        ControlPlan {
            lan_device: "lan".into(),
            control_devices: Vec::new(),
            dae_upload_devices: Vec::new(),
            local_prefixes: Vec::new(),
            rules: Vec::new(),
            nss: crate::control::nss_state::NssControlPlan::default(),
        }
    }

    #[test]
    fn empty_plan_without_unique_cleanup_evidence_preserves_edge_tree() {
        assert!(!plan_has_explicit_cleanup(&empty_plan()));
    }

    #[test]
    fn empty_plan_with_unique_cleanup_address_removes_edge_tree() {
        let mut plan = empty_plan();
        plan.conntrack_cleanup_ips
            .insert("192.0.2.9".parse().unwrap());
        assert!(plan_has_explicit_cleanup(&plan));
    }
}
