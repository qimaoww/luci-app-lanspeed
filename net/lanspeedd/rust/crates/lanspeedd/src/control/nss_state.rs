use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    ops::{Deref, DerefMut},
};

use super::{ControlManager, ControlPlan};
use crate::config::{
    RuntimeConfig, DEFAULT_NSS_FIFO_MIN_QUEUE_PACKETS, DEFAULT_NSS_FIFO_TARGET_DELAY_MS,
    DEFAULT_NSS_RATE_COMPENSATION_BASIS_POINTS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NssShapingPolicy {
    pub(crate) fifo_target_delay_ms: u32,
    pub(crate) fifo_min_queue_packets: u32,
    pub(crate) rate_compensation_basis_points: u16,
}

impl Default for NssShapingPolicy {
    fn default() -> Self {
        Self {
            fifo_target_delay_ms: DEFAULT_NSS_FIFO_TARGET_DELAY_MS,
            fifo_min_queue_packets: DEFAULT_NSS_FIFO_MIN_QUEUE_PACKETS,
            rate_compensation_basis_points: DEFAULT_NSS_RATE_COMPENSATION_BASIS_POINTS,
        }
    }
}

impl NssShapingPolicy {
    pub(crate) fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            fifo_target_delay_ms: config.nss_fifo_target_delay_ms,
            fifo_min_queue_packets: config.nss_fifo_min_queue_packets,
            rate_compensation_basis_points: config.nss_rate_compensation_basis_points,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct NssControlState {
    pub(crate) shaping: NssShapingPolicy,
    pub(crate) nss_proven_directions: BTreeMap<String, u8>,
    pub(crate) nss_path_ready_directions: BTreeMap<String, u8>,
    pub(crate) nss_cpu_directions: BTreeMap<String, u8>,
    pub(crate) nss_active_nss_directions: BTreeMap<String, u8>,
    pub(crate) nss_active_cpu_directions: BTreeMap<String, u8>,
    pub(crate) nss_attachment_generations: BTreeMap<String, (String, u64)>,
    pub(crate) nss_reload_attachment_rebase_pending: bool,
    /// Existing flows that must be reclassified after a classifier-contract
    /// transition or deletion. Pure rate changes retain their live flows.
    pub(crate) conntrack_cleanup_ips: BTreeSet<IpAddr>,
    pub(crate) pending_conntrack_identities: BTreeSet<String>,
}

impl NssControlState {
    pub(super) fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            shaping: NssShapingPolicy::from_config(config),
            ..Self::default()
        }
    }

    pub(super) fn plan(&self) -> NssControlPlan {
        NssControlPlan {
            shaping: self.shaping,
            nss_proven_directions: self.nss_proven_directions.clone(),
            nss_path_ready_directions: self.nss_path_ready_directions.clone(),
            nss_cpu_directions: self.nss_cpu_directions.clone(),
            nss_active_nss_directions: self.nss_active_nss_directions.clone(),
            nss_active_cpu_directions: self.nss_active_cpu_directions.clone(),
            conntrack_cleanup_ips: self.conntrack_cleanup_ips.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NssControlPlan {
    pub(crate) shaping: NssShapingPolicy,
    pub(crate) nss_proven_directions: BTreeMap<String, u8>,
    pub(crate) nss_path_ready_directions: BTreeMap<String, u8>,
    pub(crate) nss_cpu_directions: BTreeMap<String, u8>,
    pub(crate) nss_active_nss_directions: BTreeMap<String, u8>,
    pub(crate) nss_active_cpu_directions: BTreeMap<String, u8>,
    pub(crate) conntrack_cleanup_ips: BTreeSet<IpAddr>,
}

impl NssControlPlan {
    pub(crate) const fn shaping(&self) -> NssShapingPolicy {
        self.shaping
    }

    pub fn direction_proven(&self, identity_key: &str, direction: u8) -> bool {
        self.nss_proven_directions
            .get(identity_key)
            .is_some_and(|value| value & direction != 0)
    }

    pub fn direction_path_ready(&self, identity_key: &str, direction: u8) -> bool {
        self.nss_path_ready_directions
            .get(identity_key)
            .is_some_and(|value| value & direction != 0)
    }

    pub fn direction_uses_cpu(&self, identity_key: &str, direction: u8) -> bool {
        self.nss_cpu_directions
            .get(identity_key)
            .is_some_and(|value| value & direction != 0)
    }

    pub fn direction_active_nss(&self, identity_key: &str, direction: u8) -> bool {
        self.nss_active_nss_directions
            .get(identity_key)
            .is_some_and(|value| value & direction != 0)
    }

    pub fn direction_active_cpu(&self, identity_key: &str, direction: u8) -> bool {
        self.nss_active_cpu_directions
            .get(identity_key)
            .is_some_and(|value| value & direction != 0)
    }

    pub fn conntrack_cleanup_ips(&self) -> &BTreeSet<IpAddr> {
        &self.conntrack_cleanup_ips
    }
}

impl Deref for ControlManager {
    type Target = NssControlState;

    fn deref(&self) -> &Self::Target {
        &self.nss
    }
}

impl DerefMut for ControlManager {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.nss
    }
}

impl Deref for ControlPlan {
    type Target = NssControlPlan;

    fn deref(&self) -> &Self::Target {
        &self.nss
    }
}

impl DerefMut for ControlPlan {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.nss
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shaping_policy_is_copied_from_runtime_config_into_each_plan() {
        let mut config = RuntimeConfig::default();
        config.nss_fifo_target_delay_ms = 30;
        config.nss_fifo_min_queue_packets = 4;
        config.nss_rate_compensation_basis_points = 100;

        let state = NssControlState::from_config(&config);
        let plan = state.plan();

        assert_eq!(plan.shaping().fifo_target_delay_ms, 30);
        assert_eq!(plan.shaping().fifo_min_queue_packets, 4);
        assert_eq!(plan.shaping().rate_compensation_basis_points, 100);
    }
}
