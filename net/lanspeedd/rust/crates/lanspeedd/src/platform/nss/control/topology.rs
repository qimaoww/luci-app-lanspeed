use std::collections::{BTreeMap, BTreeSet};

use crate::control::{ControlPlan, NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD};

use super::system;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Topology {
    pub download_devices: BTreeMap<String, String>,
}

impl Topology {
    pub(super) fn download_device(&self, identity_key: &str) -> Option<&str> {
        self.download_devices.get(identity_key).map(String::as_str)
    }

    pub(super) fn all_shaper_devices(&self) -> BTreeSet<String> {
        self.download_devices.values().cloned().collect()
    }
}

pub(super) fn discover(plan: &ControlPlan) -> Result<Topology, String> {
    let need_upload = plan.rules.iter().any(|rule| {
        rule.upload_bps != 0 && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD)
    });
    let need_download = plan.rules.iter().any(|rule| {
        rule.download_bps != 0
            && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
    });
    if need_upload {
        for rule in plan.rules.iter().filter(|rule| {
            rule.upload_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD)
        }) {
            let device = rule.interface.as_str();
            if !nss_edge_device(device) {
                return Err("nss_upload_edge_unavailable".into());
            }
        }
    }
    let mut download_devices = BTreeMap::new();
    if need_download {
        for rule in plan.rules.iter().filter(|rule| {
            rule.download_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
        }) {
            let device = rule.interface.as_str();
            if !nss_edge_device(device) {
                return Err("nss_download_edge_unavailable".into());
            }
            download_devices.insert(rule.identity_key.clone(), device.to_owned());
        }
    }
    Ok(Topology { download_devices })
}

fn nss_edge_device(device: &str) -> bool {
    system::interface_exists(device)
        && !is_bridge(device)
        && (std::fs::metadata(format!("/sys/class/net/{device}/device")).is_ok()
            || std::fs::metadata(format!("/sys/class/net/{device}/phy80211")).is_ok())
}

fn is_bridge(device: &str) -> bool {
    std::fs::metadata(format!("/sys/class/net/{device}/bridge")).is_ok()
}
