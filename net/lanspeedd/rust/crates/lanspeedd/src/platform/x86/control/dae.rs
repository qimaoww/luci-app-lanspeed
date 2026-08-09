use std::{collections::BTreeSet, fs};

use super::{classifier, shaper, system};

/// Resolve every bridge slave that feeds a DAE-preempted LAN bridge. Upload
/// shaping runs on these ingress devices, before the packet reaches DAE's
/// bridge-master hook. If even one bridge cannot be resolved, fail closed so
/// the UI never claims that only part of the client's upload is controlled.
pub(super) fn upload_devices(bridges: &BTreeSet<String>) -> BTreeSet<String> {
    resolve_upload_devices(bridges, bridge_members)
}

/// Remove the two rejected DAE upload implementations from upgrades without
/// assuming the proxy interface name. A device is touched only after its
/// exact LAN Speed egress jump or terminal chain marker is observed.
pub(super) fn cleanup_legacy_objects() -> Result<(), String> {
    for device in network_devices()? {
        if !classifier::legacy_dae_egress_owned(&device)? {
            continue;
        }
        classifier::cleanup_legacy_dae_egress(&device)?;
        shaper::cleanup_owned_root(&device, shaper::UPLOAD_HANDLE)?;
    }
    Ok(())
}

/// Remove upload classifiers left on an interface that is no longer part of
/// the resolved direct or pre-DAE path. Ownership is proven from the exact
/// jump and terminal marker before anything is deleted; interface names are
/// discovered at runtime and never guessed.
pub(super) fn cleanup_obsolete_ingress_objects(
    active_devices: &BTreeSet<String>,
) -> Result<(), String> {
    for device in network_devices()? {
        if active_devices.contains(&device) || !classifier::ingress_owned(&device)? {
            continue;
        }
        classifier::cleanup(&device)?;
        shaper::cleanup_owned_root(&device, shaper::UPLOAD_HANDLE)?;
    }
    Ok(())
}

fn network_devices() -> Result<Vec<String>, String> {
    let entries = fs::read_dir("/sys/class/net")
        .map_err(|_| "ingress_filter_inspection_failed".to_owned())?;
    let mut devices = Vec::new();
    for entry in entries {
        let device = entry
            .map_err(|_| "ingress_filter_inspection_failed".to_owned())?
            .file_name()
            .into_string()
            .map_err(|_| "ingress_filter_inspection_failed".to_owned())?;
        if system::valid_interface_name(&device) {
            devices.push(device);
        }
    }
    devices.sort();
    Ok(devices)
}

fn bridge_members(bridge: &str) -> Option<Vec<String>> {
    if !system::valid_interface_name(bridge) || !system::interface_exists(bridge) {
        return None;
    }
    let entries = fs::read_dir(format!("/sys/class/net/{bridge}/brif")).ok()?;
    let mut members = Vec::new();
    for entry in entries {
        let name = entry.ok()?.file_name().into_string().ok()?;
        if !system::valid_interface_name(&name) || !system::interface_exists(&name) {
            return None;
        }
        members.push(name);
    }
    members.sort();
    members.dedup();
    (!members.is_empty()).then_some(members)
}

fn resolve_upload_devices<F>(bridges: &BTreeSet<String>, mut members: F) -> BTreeSet<String>
where
    F: FnMut(&str) -> Option<Vec<String>>,
{
    if bridges.is_empty() {
        return BTreeSet::new();
    }
    let mut devices = BTreeSet::new();
    for bridge in bridges {
        let Some(current) = members(bridge) else {
            return BTreeSet::new();
        };
        let current = current
            .into_iter()
            .filter(|device| system::valid_interface_name(device))
            .collect::<BTreeSet<_>>();
        if current.is_empty() {
            return BTreeSet::new();
        }
        devices.extend(current);
    }
    devices
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn every_preempted_bridge_must_have_a_safe_ingress_device() {
        let bridges = BTreeSet::from(["br-guest".into(), "br-lan".into()]);
        let complete = BTreeMap::from([
            ("br-lan", vec!["eth1".into()]),
            ("br-guest", vec!["wlan0".into(), "eth2".into()]),
        ]);
        assert_eq!(
            resolve_upload_devices(&bridges, |bridge| complete.get(bridge).cloned()),
            BTreeSet::from(["eth1".into(), "eth2".into(), "wlan0".into()])
        );

        let incomplete = BTreeMap::from([("br-lan", vec!["eth1".into()])]);
        assert!(
            resolve_upload_devices(&bridges, |bridge| incomplete.get(bridge).cloned()).is_empty()
        );
    }

    #[test]
    fn direct_dae_device_and_invalid_names_fail_closed() {
        let bridges = BTreeSet::from(["br-lan".into()]);
        assert!(resolve_upload_devices(&bridges, |_| Some(vec!["dae0/peer".into()])).is_empty());
        assert!(resolve_upload_devices(&BTreeSet::new(), |_| unreachable!()).is_empty());
    }
}
