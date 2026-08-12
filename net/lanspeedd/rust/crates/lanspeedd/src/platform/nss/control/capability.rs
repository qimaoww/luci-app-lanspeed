use crate::control::{
    ApplyResult, ControlPlan, NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD, NSS_MAX_RATE_BPS,
};

use super::{system, topology};

pub(super) fn preflight_shaping(plan: &ControlPlan) -> Result<topology::Topology, String> {
    for program in ["tc", "ip", "nft"] {
        system::require_program(program)?;
    }
    if needs_aggregate_executor(plan) {
        // Re-tagging an accelerated flow requires clearing only the uniquely
        // owned client's conntrack entries after the NSS tree and maps commit.
        for program in ["ubus", "conntrack"] {
            system::require_program(program)?;
        }
        if !system::ecm_dscp_enabled() {
            return Err("nss_ecm_dscp_unavailable".into());
        }
        system::load_module("qca_nss_qdisc", "nss_qdisc_unavailable")?;
    }
    topology::discover(plan)
}

fn needs_aggregate_executor(plan: &ControlPlan) -> bool {
    plan.rules.iter().any(|rule| {
        (rule.upload_bps != 0 && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD))
            || (rule.download_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD))
    })
}

pub(super) fn shaping_supported() -> bool {
    aggregate_shaping_supported()
}

pub(super) fn shaping_supported_for(plan: &ControlPlan) -> bool {
    if !needs_aggregate_executor(plan) {
        return shaping_supported();
    }
    aggregate_shaping_supported()
}

fn aggregate_shaping_supported() -> bool {
    ["tc", "ip", "nft", "ubus", "conntrack"]
        .into_iter()
        .all(system::command_available)
        && [
            "ifb",
            "qca_nss_qdisc",
            "cls_u32",
            "cls_matchall",
            "act_gact",
            "act_mirred",
            "act_nssmirred",
            "act_skbedit",
            "lanspeed_nss_control",
        ]
        .into_iter()
        .all(system::module_available)
        && system::ecm_dscp_enabled()
}

pub(super) fn blocking_supported() -> bool {
    ["nft", "conntrack", "tc", "ip"]
        .into_iter()
        .all(system::command_available)
        && ["cls_u32", "cls_matchall", "act_gact"]
            .into_iter()
            .all(system::module_available)
}

pub(super) fn probe() -> ApplyResult {
    let shaping = shaping_supported();
    let blocking = blocking_supported();
    ApplyResult {
        state: if shaping || blocking {
            "inactive"
        } else {
            "unsupported"
        }
        .into(),
        reason: (!shaping && !blocking).then(|| "nss_client_control_unavailable".into()),
        shaping_supported: shaping,
        blocking_supported: blocking,
        queue_overflow: false,
        queue_drop_counters: Default::default(),
        class_counter_baselines: Default::default(),
        verified_directions: Default::default(),
        nss_verified_directions: Default::default(),
        cpu_verified_directions: Default::default(),
        verification_failures: Default::default(),
    }
}

pub(super) const fn max_rate_bps() -> u64 {
    NSS_MAX_RATE_BPS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nss_rate_ceiling_remains_u32_safe() {
        assert!(max_rate_bps() <= u32::MAX as u64);
        assert_eq!(max_rate_bps(), 4_000_000_000);
    }
}
