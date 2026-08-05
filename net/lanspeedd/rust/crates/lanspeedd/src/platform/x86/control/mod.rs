mod classifier;
mod firewall;
mod ifb;
mod shaper;
mod system;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

use crate::control::{ApplyResult, ControlPlan, X86_MAX_RATE_BPS};

pub fn apply(plan: &ControlPlan) -> Result<ApplyResult, String> {
    if plan.rules.is_empty() {
        cleanup(&plan.lan_device)?;
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
        .filter(|rule| rule.upload_bps != 0)
        .collect::<Vec<_>>();
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
    if !upload.is_empty() {
        classifier::preflight(&plan.lan_device, &plan.local_prefixes, &upload)?;
    }
    firewall::preflight(plan)?;

    // Deactivate redirection before changing the IFB tree. The new jump is
    // installed only after every queue and filter has been verified.
    classifier::deactivate(&plan.lan_device)?;
    let staged = (|| {
        if upload.is_empty() {
            classifier::cleanup(&plan.lan_device)?;
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
            classifier::install(&plan.lan_device, &plan.local_prefixes, &upload)?;
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = staged {
        rollback(&plan.lan_device);
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
        count + usize::from(rule.upload_bps != 0) + usize::from(rule.download_bps != 0)
    });
    let mut verified = 0usize;
    for rule in &plan.rules {
        let previous_directions = previous
            .verified_directions
            .get(&rule.identity_key)
            .copied()
            .unwrap_or(0);
        let upload_verified = rule.upload_bps != 0
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

pub fn cleanup(lan_device: &str) -> Result<(), String> {
    let mut errors = Vec::new();
    for result in [
        classifier::cleanup(lan_device),
        firewall::cleanup(lan_device),
        shaper::cleanup_download(lan_device),
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

fn rollback(lan_device: &str) {
    let _ = classifier::cleanup(lan_device);
    let _ = firewall::cleanup(lan_device);
    let _ = shaper::cleanup_download(lan_device);
    let _ = shaper::cleanup_upload();
    let _ = ifb::cleanup();
}

fn queue_drop_snapshot(plan: &ControlPlan) -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    if let Ok(upload) = shaper::queue_drops(ifb::DEVICE) {
        for rule in plan.rules.iter().filter(|rule| rule.upload_bps != 0) {
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
        for rule in plan.rules.iter().filter(|rule| rule.upload_bps != 0) {
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
