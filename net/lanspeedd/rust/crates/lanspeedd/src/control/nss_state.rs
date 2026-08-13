use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    ops::{Deref, DerefMut},
};

use super::{ControlManager, ControlPlan};

#[derive(Clone, Debug, Default)]
pub struct NssControlState {
    pub(crate) nss_proven_directions: BTreeMap<String, u8>,
    pub(crate) nss_path_ready_directions: BTreeMap<String, u8>,
    pub(crate) nss_cpu_directions: BTreeMap<String, u8>,
    pub(crate) nss_active_nss_directions: BTreeMap<String, u8>,
    pub(crate) nss_active_cpu_directions: BTreeMap<String, u8>,
    pub(crate) nss_attachment_generations: BTreeMap<String, (String, u64)>,
    pub(crate) nss_reload_attachment_rebase_pending: bool,
    pub(crate) conntrack_cleanup_ips: BTreeSet<IpAddr>,
    pub(crate) pending_conntrack_identities: BTreeSet<String>,
}

impl NssControlState {
    pub(super) fn plan(&self) -> NssControlPlan {
        NssControlPlan {
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
    pub(crate) nss_proven_directions: BTreeMap<String, u8>,
    pub(crate) nss_path_ready_directions: BTreeMap<String, u8>,
    pub(crate) nss_cpu_directions: BTreeMap<String, u8>,
    pub(crate) nss_active_nss_directions: BTreeMap<String, u8>,
    pub(crate) nss_active_cpu_directions: BTreeMap<String, u8>,
    pub(crate) conntrack_cleanup_ips: BTreeSet<IpAddr>,
}

impl NssControlPlan {
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
