mod classifier;
mod dae;
mod firewall;
mod ifb;
mod shaper;
mod system;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

use crate::control::{ApplyResult, ControlPlan, X86_MAX_RATE_BPS};

/// Resolve bridge-slave ingress devices that run before DAE's bridge-master
/// redirect. An empty set means the complete pre-DAE path was not proven.
pub fn dae_upload_devices(bridges: &BTreeSet<String>) -> BTreeSet<String> {
    dae::upload_devices(bridges)
}

pub fn apply(plan: &ControlPlan) -> Result<ApplyResult, String> {
    if plan.rules.is_empty() {
        cleanup(plan)?;
        return Ok(probe(&plan.lan_device));
    }
    if !system::valid_interface_name(&plan.lan_device)
        || !system::interface_exists(&plan.lan_device)
    {
        return Err("lan_control_interface_unavailable".into());
    }
    if plan.rules.iter().any(|rule| {
        (rule.upload_bps != 0 || rule.download_bps != 0 || rule.internet_disabled)
            && rule.ips.is_empty()
    }) {
        return Err("identity_address_unavailable".into());
    }

    let upload = plan
        .rules
        .iter()
        .filter(|rule| rule.upload_bps != 0 && !rule.upload_preempted)
        .collect::<Vec<_>>();
    let upload_by_device = upload_rules_by_device(plan, &upload);
    let active_upload_devices = upload_by_device
        .keys()
        .map(|device| (*device).to_owned())
        .collect::<BTreeSet<_>>();
    let download = plan
        .rules
        .iter()
        .filter(|rule| rule.download_bps != 0)
        .collect::<Vec<_>>();
    let shaping = !upload.is_empty() || !download.is_empty();
    if shaping {
        system::require_program("tc")?;
        system::require_program("ip")?;
        shaper::preflight(&plan.lan_device, &upload, &download, &plan.local_prefixes)?;
    }
    for (device, rules) in &upload_by_device {
        classifier::preflight(device, &plan.local_prefixes, rules)?;
    }
    firewall::preflight(plan)?;

    // Deactivate redirection before changing the IFB tree. The new jump is
    // installed only after every queue and filter has been verified.
    for device in control_devices(plan) {
        classifier::deactivate(&device)?;
    }
    // A proxy mode or bridge topology change can move the pre-proxy hook.
    // Remove only classifiers carrying our exact ownership marker from
    // devices that are no longer in the resolved upload path.
    cleanup_obsolete_upload_classifiers(&active_upload_devices)?;
    // Remove the rejected legacy dae0->IFB redirect before touching queues.
    // This is upgrade cleanup only; no DAE egress redirect is installed.
    cleanup_legacy_dae_upload_objects()?;
    let staged = (|| {
        if upload.is_empty() {
            cleanup_upload_classifiers(plan)?;
            shaper::cleanup_upload()?;
            ifb::cleanup()?;
        } else {
            shaper::stage_upload(&upload)?;
        }
        if download.is_empty() {
            shaper::cleanup_download(&plan.lan_device)?;
        } else {
            shaper::stage_download(&plan.lan_device, &download)?;
        }
        firewall::install(plan)?;
        if !download.is_empty() {
            shaper::activate_download(&plan.lan_device, &download, &plan.local_prefixes)?;
        }
        if !upload.is_empty() {
            for (device, rules) in &upload_by_device {
                classifier::install(device, &plan.local_prefixes, rules)?;
            }
            for device in control_devices(plan) {
                if !upload_by_device.contains_key(device.as_str()) {
                    classifier::cleanup(&device)?;
                }
            }
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = staged {
        rollback(plan);
        return Err(error);
    }

    let capability = probe(&plan.lan_device);
    Ok(ApplyResult {
        state: if shaping {
            "pending_new_connections"
        } else {
            "applied"
        }
        .into(),
        reason: if shaping {
            Some("traffic_verification_pending".into())
        } else {
            capability.reason
        },
        shaping_supported: shaping || capability.shaping_supported,
        blocking_supported: capability.blocking_supported,
        queue_overflow: false,
        queue_drop_counters: queue_drop_snapshot(plan),
        class_counter_baselines: verification_snapshot(plan),
        verified_directions: BTreeMap::new(),
        verification_failures: BTreeMap::new(),
    })
}

pub fn observe(plan: &ControlPlan, previous: &ApplyResult) -> ApplyResult {
    let mut next = previous.clone();
    next.verification_failures
        .retain(|_, reason| reason != "queue_overflow");

    let current_drops = queue_drop_snapshot(plan);
    let topology_changed = plan.rules.iter().any(|rule| rule.upload_bps != 0)
        && previous
            .queue_drop_counters
            .keys()
            .filter(|key| key.contains("/upload_queue_drops"))
            .collect::<BTreeSet<_>>()
            != current_drops
                .keys()
                .filter(|key| key.contains("/upload_queue_drops"))
                .collect::<BTreeSet<_>>();
    if topology_changed {
        next.queue_drop_counters = current_drops;
        next.queue_overflow = false;
        next.state = "pending".into();
        next.reason = Some("control_topology_changed".into());
        return next;
    }

    let overflow = queue_overflow_identities(&previous.queue_drop_counters, &current_drops);
    next.queue_drop_counters = current_drops;
    next.queue_overflow = !overflow.is_empty();
    for identity_key in overflow {
        next.verification_failures
            .insert(identity_key, "queue_overflow".into());
    }

    let current = verification_snapshot(plan);
    let expected = plan.rules.iter().fold(0usize, |count, rule| {
        count
            + usize::from(rule.upload_bps != 0 && !rule.upload_preempted)
            + usize::from(rule.download_bps != 0)
    });
    let mut verified = 0usize;
    for rule in &plan.rules {
        let previous_directions = previous
            .verified_directions
            .get(&rule.identity_key)
            .copied()
            .unwrap_or(0);
        let upload_verified = rule.upload_bps != 0
            && !rule.upload_preempted
            && (previous_directions & 1 != 0
                || verification_delta(
                    previous,
                    &current,
                    &rule.identity_key,
                    "upload_class_bytes",
                ) > 0);
        let download_verified = rule.download_bps != 0
            && (previous_directions & 2 != 0
                || verification_delta(
                    previous,
                    &current,
                    &rule.identity_key,
                    "download_class_bytes",
                ) > 0);
        verified += usize::from(upload_verified) + usize::from(download_verified);
        let directions = u8::from(upload_verified) | (u8::from(download_verified) << 1);
        if directions == 0 {
            next.verified_directions.remove(&rule.identity_key);
        } else {
            next.verified_directions
                .insert(rule.identity_key.clone(), directions);
        }
    }
    next.class_counter_baselines = current;
    if expected != 0 && verified == expected {
        next.state = "verified".into();
        next.reason = None;
    } else if expected != 0 {
        next.state = "pending_new_connections".into();
        next.reason = Some(
            if verified == 0 {
                "traffic_verification_pending"
            } else {
                "direction_verification_pending"
            }
            .into(),
        );
    }
    next
}

pub fn cleanup(plan: &ControlPlan) -> Result<(), String> {
    let mut errors = Vec::new();
    for device in control_devices(plan) {
        if let Err(error) = classifier::cleanup(&device) {
            errors.push(error);
        }
    }
    if let Err(error) = cleanup_legacy_dae_upload_objects() {
        errors.push(error);
    }
    if let Err(error) = cleanup_obsolete_upload_classifiers(&BTreeSet::new()) {
        errors.push(error);
    }
    for result in [
        firewall::cleanup(&plan.lan_device),
        shaper::cleanup_download(&plan.lan_device),
        shaper::cleanup_upload(),
        ifb::cleanup(),
    ] {
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(";"))
    }
}

pub fn max_rate_bps() -> u64 {
    fs::read_dir("/sys/class/net")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("device").exists())
        .filter_map(|entry| fs::read_to_string(entry.path().join("speed")).ok())
        .filter_map(|speed| speed.trim().parse::<u64>().ok())
        .filter(|speed| *speed > 0 && *speed <= 100_000)
        .filter_map(|speed| speed.checked_mul(1_000_000))
        .max()
        .unwrap_or(X86_MAX_RATE_BPS)
        .min(X86_MAX_RATE_BPS)
}

fn probe(lan_device: &str) -> ApplyResult {
    let shaping_reason = ["tc", "ip"]
        .into_iter()
        .find(|program| !system::command_available(program))
        .map(|program| format!("missing_{program}"))
        .or_else(|| {
            ["sch_htb", "sch_fq", "cls_u32", "cls_matchall", "act_mirred"]
                .into_iter()
                .find(|module| !system::module_available(module))
                .map(|module| format!("{module}_unavailable"))
        })
        .or_else(|| ifb::preflight().err())
        .or_else(|| {
            (!system::interface_exists(lan_device))
                .then(|| "lan_control_interface_unavailable".to_owned())
        })
        .or_else(|| system::ensure_replaceable_root(lan_device, shaper::DOWNLOAD_HANDLE).err());
    let blocking_supported = system::command_available("nft")
        && system::command_available("conntrack")
        && system::module_available("act_gact");
    ApplyResult {
        state: "inactive".into(),
        shaping_supported: shaping_reason.is_none(),
        reason: shaping_reason
            .or_else(|| (!blocking_supported).then(|| "conntrack_control_unavailable".into())),
        blocking_supported,
        queue_overflow: false,
        queue_drop_counters: BTreeMap::new(),
        class_counter_baselines: BTreeMap::new(),
        verified_directions: BTreeMap::new(),
        verification_failures: BTreeMap::new(),
    }
}

fn rollback(plan: &ControlPlan) {
    let _ = cleanup_upload_classifiers(plan);
    let _ = cleanup_obsolete_upload_classifiers(&BTreeSet::new());
    let _ = cleanup_legacy_dae_upload_objects();
    let _ = firewall::cleanup(&plan.lan_device);
    let _ = shaper::cleanup_download(&plan.lan_device);
    let _ = shaper::cleanup_upload();
    let _ = ifb::cleanup();
}

fn upload_rules_by_device<'a>(
    plan: &'a ControlPlan,
    rules: &[&'a crate::control::ActiveRule],
) -> BTreeMap<&'a str, Vec<&'a crate::control::ActiveRule>> {
    let mut grouped = BTreeMap::<&str, Vec<_>>::new();
    for rule in rules {
        if rule.upload_before_proxy {
            for device in &plan.dae_upload_devices {
                grouped.entry(device.as_str()).or_default().push(*rule);
            }
        } else {
            grouped
                .entry(rule.interface.as_str())
                .or_default()
                .push(*rule);
        }
    }
    grouped
}

fn control_devices(plan: &ControlPlan) -> BTreeSet<String> {
    plan.control_devices
        .iter()
        .chain(plan.rules.iter().map(|rule| &rule.interface))
        .chain(plan.dae_upload_devices.iter())
        .filter(|device| system::valid_interface_name(device))
        .cloned()
        .collect()
}

fn cleanup_upload_classifiers(plan: &ControlPlan) -> Result<(), String> {
    let mut errors = Vec::new();
    for device in control_devices(plan) {
        if let Err(error) = classifier::cleanup(&device) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(";"))
    }
}

fn cleanup_legacy_dae_upload_objects() -> Result<(), String> {
    dae::cleanup_legacy_objects()
}

fn cleanup_obsolete_upload_classifiers(active_devices: &BTreeSet<String>) -> Result<(), String> {
    dae::cleanup_obsolete_ingress_objects(active_devices)
}

fn queue_drop_snapshot(plan: &ControlPlan) -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    if let Ok(upload) = shaper::queue_drops(ifb::DEVICE) {
        for rule in plan
            .rules
            .iter()
            .filter(|rule| rule.upload_bps != 0 && !rule.upload_preempted)
        {
            if let Some(count) = upload.get(&format!("{:x}:", rule.class_minor)) {
                counters.insert(
                    verification_key(&rule.identity_key, "upload_queue_drops"),
                    *count,
                );
            }
        }
    }
    if let Ok(download) = shaper::queue_drops(&plan.lan_device) {
        for rule in plan.rules.iter().filter(|rule| rule.download_bps != 0) {
            if let Some(count) = download.get(&format!("{:x}:", rule.class_minor)) {
                counters.insert(
                    verification_key(&rule.identity_key, "download_queue_drops"),
                    *count,
                );
            }
        }
    }
    counters
}

fn verification_snapshot(plan: &ControlPlan) -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    if let Ok(upload) = shaper::class_bytes(ifb::DEVICE) {
        for rule in plan
            .rules
            .iter()
            .filter(|rule| rule.upload_bps != 0 && !rule.upload_preempted)
        {
            if let Some(bytes) = upload.get(&format!("7a20:{:x}", rule.class_minor)) {
                counters.insert(
                    verification_key(&rule.identity_key, "upload_class_bytes"),
                    *bytes,
                );
            }
        }
    }
    if let Ok(download) = shaper::class_bytes(&plan.lan_device) {
        for rule in plan.rules.iter().filter(|rule| rule.download_bps != 0) {
            if let Some(bytes) = download.get(&format!("7a10:{:x}", rule.class_minor)) {
                counters.insert(
                    verification_key(&rule.identity_key, "download_class_bytes"),
                    *bytes,
                );
            }
        }
    }
    counters
}

fn verification_delta(
    previous: &ApplyResult,
    current: &BTreeMap<String, u64>,
    identity_key: &str,
    metric: &str,
) -> u64 {
    let key = verification_key(identity_key, metric);
    current.get(&key).copied().unwrap_or(0).saturating_sub(
        previous
            .class_counter_baselines
            .get(&key)
            .copied()
            .unwrap_or(0),
    )
}

fn verification_key(identity_key: &str, metric: &str) -> String {
    format!("{identity_key}/{metric}")
}

fn queue_overflow_identities(
    previous: &BTreeMap<String, u64>,
    current: &BTreeMap<String, u64>,
) -> BTreeSet<String> {
    current
        .iter()
        .filter(|(key, count)| {
            key.contains("_queue_drops") && **count > previous.get(*key).copied().unwrap_or(**count)
        })
        .filter_map(|(key, _)| key.split_once('/').map(|(identity, _)| identity.to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upload_rule(identity: &str, interface: &str, minor: u16) -> crate::control::ActiveRule {
        crate::control::ActiveRule {
            identity_key: identity.into(),
            mac: identity.split('@').next().unwrap().parse().unwrap(),
            interface: interface.into(),
            upload_before_proxy: false,
            upload_preempted: false,
            ips: vec!["192.0.2.9".parse().unwrap()],
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: minor,
        }
    }

    #[test]
    fn upload_rules_are_grouped_by_their_observed_interfaces() {
        let first = upload_rule("02:00:00:00:00:01@lan", "br-lan", 0x101);
        let second = upload_rule("02:00:00:00:00:02@guest", "br-guest", 0x102);
        let third = upload_rule("02:00:00:00:00:03@guest", "br-guest", 0x103);
        let plan = ControlPlan {
            lan_device: "br-lan".into(),
            control_devices: Vec::new(),
            dae_upload_devices: Vec::new(),
            local_prefixes: Vec::new(),
            rules: Vec::new(),
        };
        let grouped = upload_rules_by_device(&plan, &[&first, &second, &third]);

        assert_eq!(grouped["br-lan"].len(), 1);
        assert_eq!(grouped["br-guest"].len(), 2);
    }

    #[test]
    fn dae_upload_uses_bridge_slaves_before_the_proxy_hook() {
        let mut rule = upload_rule("02:00:00:00:00:01@lan", "br-lan", 0x101);
        rule.upload_before_proxy = true;
        let plan = ControlPlan {
            lan_device: "br-lan".into(),
            control_devices: vec!["br-lan".into()],
            dae_upload_devices: vec!["eth1".into(), "wlan0".into()],
            local_prefixes: Vec::new(),
            rules: vec![rule.clone()],
        };
        let grouped = upload_rules_by_device(&plan, &[&rule]);

        assert!(!grouped.contains_key("br-lan"));
        assert_eq!(grouped["eth1"].len(), 1);
        assert_eq!(grouped["wlan0"].len(), 1);
        assert!(control_devices(&plan).contains("eth1"));
        assert!(control_devices(&plan).contains("wlan0"));
    }

    #[test]
    fn cleanup_devices_include_configured_and_live_edges() {
        let rule = upload_rule("02:00:00:00:00:01@guest", "br-guest", 0x101);
        let plan = ControlPlan {
            lan_device: "br-lan".into(),
            control_devices: vec!["br-lan".into(), "br-iot".into()],
            dae_upload_devices: Vec::new(),
            local_prefixes: Vec::new(),
            rules: vec![rule],
        };

        assert_eq!(
            control_devices(&plan),
            BTreeSet::from(["br-guest".into(), "br-iot".into(), "br-lan".into()])
        );
    }

    #[test]
    fn queue_overflow_is_scoped_to_the_changed_client() {
        let first = "02:00:00:00:00:01@lan/upload_queue_drops";
        let second = "02:00:00:00:00:02@lan/download_queue_drops";
        let previous = BTreeMap::from([(first.into(), 4), (second.into(), 7)]);
        let current = BTreeMap::from([(first.into(), 4), (second.into(), 8)]);
        assert_eq!(
            queue_overflow_identities(&previous, &current),
            BTreeSet::from(["02:00:00:00:00:02@lan".into()])
        );
    }

    #[test]
    fn verification_delta_never_wraps_after_reinstall() {
        let identity = "02:00:00:00:00:01@lan";
        let key = verification_key(identity, "upload_class_bytes");
        let previous = ApplyResult {
            state: "pending".into(),
            reason: None,
            shaping_supported: true,
            blocking_supported: true,
            queue_overflow: false,
            queue_drop_counters: BTreeMap::new(),
            class_counter_baselines: BTreeMap::from([(key.clone(), 100)]),
            verified_directions: BTreeMap::new(),
            verification_failures: BTreeMap::new(),
        };
        assert_eq!(
            verification_delta(
                &previous,
                &BTreeMap::from([(key, 10)]),
                identity,
                "upload_class_bytes"
            ),
            0
        );
    }
}
