use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    process::{Command, Stdio},
};

use serde_json::Value;

use crate::control::{
    clear_conntrack_address, queue_bytes, queue_drops_increased, ActiveRule, ApplyResult,
    ControlPlan, NSS_MAX_RATE_BPS,
};

const DOWNLOAD_HANDLE: &str = "7b10:";
const UPLOAD_HANDLE: &str = "7b20:";

pub fn apply(plan: &ControlPlan) -> Result<ApplyResult, String> {
    if plan.rules.is_empty() {
        cleanup(&plan.lan_device)?;
        return Ok(probe(&plan.lan_device));
    }
    require_program("nft")?;
    if plan.rules.iter().any(|rule| rule.internet_disabled) {
        require_program("conntrack")?;
    }
    if plan.rules.iter().any(|rule| {
        (rule.upload_bps != 0 || rule.download_bps != 0 || rule.internet_disabled)
            && rule.ips.is_empty()
    }) {
        return Err("identity_address_unavailable".into());
    }
    let uploads = plan
        .rules
        .iter()
        .filter(|rule| rule.upload_bps != 0)
        .collect::<Vec<_>>();
    let downloads = plan
        .rules
        .iter()
        .filter(|rule| rule.download_bps != 0)
        .collect::<Vec<_>>();
    let shaping = !uploads.is_empty() || !downloads.is_empty();
    if shaping {
        require_program("tc")?;
        require_nss_qdisc_module()?;
    }
    let wan = wan_device()?;
    let default_rate = if shaping {
        require_ecm_dscp()?;
        let rate = link_rate_bps(&wan)?;
        default_high_rate(rate)?
    } else {
        NSS_MAX_RATE_BPS
    };

    if !uploads.is_empty() {
        ensure_nss_replaceable_root(&wan, UPLOAD_HANDLE, true)?;
    }
    if !downloads.is_empty() {
        ensure_nss_replaceable_root(&plan.lan_device, DOWNLOAD_HANDLE, false)?;
    }

    let stage_result = (|| {
        if uploads.is_empty() {
            restore_default_root(&wan, UPLOAD_HANDLE, "mq")?;
        } else {
            ensure_nss_replaceable_root(&wan, UPLOAD_HANDLE, true)?;
            install_nss_tree(&wan, UPLOAD_HANDLE, &uploads, true, default_rate)?;
        }
        if downloads.is_empty() {
            restore_default_root(&plan.lan_device, DOWNLOAD_HANDLE, "noqueue")
        } else {
            ensure_nss_replaceable_root(&plan.lan_device, DOWNLOAD_HANDLE, false)?;
            install_nss_tree(
                &plan.lan_device,
                DOWNLOAD_HANDLE,
                &downloads,
                false,
                default_rate,
            )
        }
    })();
    if let Err(error) = stage_result {
        let _ = run("nft", &["delete", "table", "inet", "lanspeed_control"]);
        let _ = restore_default_root(&wan, UPLOAD_HANDLE, "mq");
        let _ = restore_default_root(&plan.lan_device, DOWNLOAD_HANDLE, "noqueue");
        return Err(error);
    }

    if let Err(error) = install_nft(plan, "7b20", "7b10") {
        let _ = run("nft", &["delete", "table", "inet", "lanspeed_control"]);
        let _ = restore_default_root(&wan, UPLOAD_HANDLE, "mq");
        let _ = restore_default_root(&plan.lan_device, DOWNLOAD_HANDLE, "noqueue");
        return Err(error);
    }
    if let Err(error) = clear_disabled_conntrack(&plan.rules) {
        let _ = run("nft", &["delete", "table", "inet", "lanspeed_control"]);
        let _ = restore_default_root(&wan, UPLOAD_HANDLE, "mq");
        let _ = restore_default_root(&plan.lan_device, DOWNLOAD_HANDLE, "noqueue");
        return Err(error);
    }
    let capability = probe(&plan.lan_device);
    let queue_drop_counters = queue_drop_snapshot(&wan, &plan.lan_device);
    let class_counter_baselines = class_counter_snapshot(plan, &wan);
    Ok(ApplyResult {
        state: if plan.rules.is_empty() {
            "inactive"
        } else if shaping {
            "pending_new_connections"
        } else {
            "applied"
        }
        .into(),
        reason: if shaping {
            Some("new_connections_only".into())
        } else {
            capability.reason
        },
        shaping_supported: shaping || capability.shaping_supported,
        blocking_supported: true,
        queue_overflow: false,
        queue_drop_counters,
        class_counter_baselines,
        verified_directions: Default::default(),
    })
}

fn probe(lan_device: &str) -> ApplyResult {
    let blocking_supported = crate::probe::commands::command_available("nft")
        && crate::probe::commands::command_available("conntrack");
    let shaping_reason = if !crate::probe::commands::command_available("tc") {
        Some("missing_tc".into())
    } else if !crate::probe::commands::command_available("nft") {
        Some("missing_nft".into())
    } else if !nss_qdisc_available() {
        Some("nss_qdisc_module_unavailable".into())
    } else if let Err(reason) = require_ecm_dscp() {
        Some(reason)
    } else if !fs::metadata(format!("/sys/class/net/{lan_device}")).is_ok() {
        Some("lan_control_interface_unavailable".into())
    } else if ensure_nss_replaceable_root(lan_device, DOWNLOAD_HANDLE, false).is_err() {
        Some("qdisc_owned_by_external_service".into())
    } else {
        wan_device()
            .and_then(|wan| {
                ensure_nss_replaceable_root(&wan, UPLOAD_HANDLE, true)?;
                link_rate_bps(&wan)
            })
            .and_then(default_high_rate)
            .map(|_| ())
            .err()
    };
    ApplyResult {
        state: "inactive".into(),
        reason: shaping_reason
            .clone()
            .or_else(|| (!blocking_supported).then(|| "conntrack_control_unavailable".into())),
        shaping_supported: shaping_reason.is_none(),
        blocking_supported,
        queue_overflow: false,
        queue_drop_counters: Default::default(),
        class_counter_baselines: Default::default(),
        verified_directions: Default::default(),
    }
}

pub fn cleanup(lan_device: &str) -> Result<(), String> {
    let _ = run("nft", &["delete", "table", "inet", "lanspeed_control"]);
    if let Ok(wan) = wan_device() {
        restore_default_root(&wan, UPLOAD_HANDLE, "mq")?;
    }
    restore_default_root(lan_device, DOWNLOAD_HANDLE, "noqueue")
}

pub fn observe(plan: &ControlPlan, previous: &ApplyResult) -> ApplyResult {
    let mut next = previous.clone();
    if plan.rules.is_empty() || next.state == "error" || next.state == "unsupported" {
        return next;
    }
    let Ok(wan) = wan_device() else {
        return next;
    };
    let current = queue_drop_snapshot(&wan, &plan.lan_device);
    let increased = queue_drops_increased(&previous.queue_drop_counters, &current);
    next.queue_drop_counters = current;
    if increased {
        next.queue_overflow = true;
        next.state = "error".into();
        next.reason = Some("queue_overflow".into());
        return next;
    }
    let upload = class_counters(&wan).unwrap_or_default();
    let download = class_counters(&plan.lan_device).unwrap_or_default();
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
                || class_counter_grew(
                    previous,
                    &rule.identity_key,
                    "upload",
                    upload.get(&format!("7b20:{:x}", rule.class_minor)).copied(),
                ));
        let download_verified = rule.download_bps != 0
            && (previous_directions & 2 != 0
                || class_counter_grew(
                    previous,
                    &rule.identity_key,
                    "download",
                    download
                        .get(&format!("7b10:{:x}", rule.class_minor))
                        .copied(),
                ));
        verified += usize::from(upload_verified) + usize::from(download_verified);
        let directions = u8::from(upload_verified) | (u8::from(download_verified) << 1);
        if directions != 0 {
            next.verified_directions
                .insert(rule.identity_key.clone(), directions);
        }
    }
    if expected != 0 && verified == expected {
        next.state = "verified".into();
        next.reason = None;
    } else if expected != 0 {
        next.state = "pending_new_connections".into();
        next.reason = Some(
            if verified == 0 {
                "new_connections_only"
            } else {
                "direction_verification_pending"
            }
            .into(),
        );
    }
    next
}

fn class_counter_key(identity_key: &str, direction: &str) -> String {
    format!("{identity_key}/{direction}")
}

fn class_counter_snapshot(plan: &ControlPlan, wan_device: &str) -> BTreeMap<String, u64> {
    let upload = class_counters(wan_device).unwrap_or_default();
    let download = class_counters(&plan.lan_device).unwrap_or_default();
    let mut counters = BTreeMap::new();
    for rule in &plan.rules {
        if rule.upload_bps != 0 {
            if let Some(value) = upload.get(&format!("7b20:{:x}", rule.class_minor)) {
                counters.insert(class_counter_key(&rule.identity_key, "upload"), *value);
            }
        }
        if rule.download_bps != 0 {
            if let Some(value) = download.get(&format!("7b10:{:x}", rule.class_minor)) {
                counters.insert(class_counter_key(&rule.identity_key, "download"), *value);
            }
        }
    }
    counters
}

fn class_counter_grew(
    previous: &ApplyResult,
    identity_key: &str,
    direction: &str,
    current: Option<u64>,
) -> bool {
    previous
        .class_counter_baselines
        .get(&class_counter_key(identity_key, direction))
        .zip(current)
        .is_some_and(|(baseline, current)| current > *baseline)
}

fn install_nss_tree(
    device: &str,
    handle: &str,
    rules: &[&ActiveRule],
    upload: bool,
    physical_rate: u64,
) -> Result<(), String> {
    let major = handle.trim_end_matches(':');
    run(
        "tc",
        &[
            "qdisc",
            "replace",
            "dev",
            device,
            "root",
            "handle",
            handle,
            "nsshtb",
            "accel_mode",
            "0",
        ],
    )?;
    let root = format!("{major}:1");
    let default = format!("{major}:2");
    let physical_rate = physical_rate.to_string();
    let default_burst = queue_bytes(physical_rate.parse().unwrap_or(0)).to_string();
    run(
        "tc",
        &[
            "class",
            "replace",
            "dev",
            device,
            "parent",
            handle,
            "classid",
            &root,
            "nsshtb",
            "priority",
            "0",
            "rate",
            &physical_rate,
            "burst",
            &default_burst,
            "crate",
            &physical_rate,
            "cburst",
            &default_burst,
        ],
    )?;
    run(
        "tc",
        &[
            "class",
            "replace",
            "dev",
            device,
            "parent",
            &root,
            "classid",
            &default,
            "nsshtb",
            "priority",
            "1",
            "rate",
            &physical_rate,
            "burst",
            &default_burst,
            "crate",
            &physical_rate,
            "cburst",
            &default_burst,
        ],
    )?;
    run(
        "tc",
        &[
            "qdisc",
            "replace",
            "dev",
            device,
            "parent",
            &default,
            "handle",
            "1000:",
            "nssbfifo",
            "limit",
            &crate::control::MAX_QUEUE_BYTES.to_string(),
            "set_default",
            "accel_mode",
            "0",
        ],
    )?;
    for rule in rules {
        let rate = if upload {
            rule.upload_bps
        } else {
            rule.download_bps
        };
        let rate_text = rate.to_string();
        let burst = queue_bytes(rate).to_string();
        let classid = format!("{major}:{:x}", rule.class_minor);
        run(
            "tc",
            &[
                "class", "replace", "dev", device, "parent", &root, "classid", &classid, "nsshtb",
                "priority", "1", "rate", &rate_text, "burst", &burst, "crate", &rate_text,
                "cburst", &burst,
            ],
        )?;
        let leaf = format!("{:x}:", u32::from(rule.class_minor));
        run(
            "tc",
            &[
                "qdisc",
                "replace",
                "dev",
                device,
                "parent",
                &classid,
                "handle",
                &leaf,
                "nssbfifo",
                "limit",
                &queue_bytes(rate).to_string(),
                "accel_mode",
                "0",
            ],
        )?;
    }
    verify_classes(device, major, rules)
}

fn install_nft(plan: &ControlPlan, upload_major: &str, download_major: &str) -> Result<(), String> {
    let exists = Command::new("nft")
        .args(["list", "table", "inet", "lanspeed_control"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    run_script(
        "nft",
        &["-f", "-"],
        &build_nft_script(plan, upload_major, download_major, exists),
    )
}

fn build_nft_script(
    plan: &ControlPlan,
    upload_major: &str,
    download_major: &str,
    exists: bool,
) -> String {
    let mut script = if exists {
        "delete table inet lanspeed_control\nadd table inet lanspeed_control\n".to_owned()
    } else {
        "add table inet lanspeed_control\n".to_owned()
    };
    for definition in [
        "add set inet lanspeed_control blocked4 { type ipv4_addr; }",
        "add set inet lanspeed_control blocked6 { type ipv6_addr; }",
        "add set inet lanspeed_control local4 { type ipv4_addr; flags interval; }",
        "add set inet lanspeed_control local6 { type ipv6_addr; flags interval; }",
        "add map inet lanspeed_control up4 { type ipv4_addr : classid; }",
        "add map inet lanspeed_control up6 { type ipv6_addr : classid; }",
        "add map inet lanspeed_control down4 { type ipv4_addr : classid; }",
        "add map inet lanspeed_control down6 { type ipv6_addr : classid; }",
    ] {
        script.push_str(definition);
        script.push('\n');
    }
    add_elements(
        &mut script,
        "blocked4",
        &addresses(&plan.rules, true, |rule| rule.internet_disabled),
    );
    add_elements(
        &mut script,
        "blocked6",
        &addresses(&plan.rules, false, |rule| rule.internet_disabled),
    );
    add_elements(&mut script, "local4", &prefixes(&plan.local_prefixes, true));
    add_elements(
        &mut script,
        "local6",
        &prefixes(&plan.local_prefixes, false),
    );
    add_elements(
        &mut script,
        "up4",
        &classes(&plan.rules, true, upload_major, true),
    );
    add_elements(
        &mut script,
        "up6",
        &classes(&plan.rules, false, upload_major, true),
    );
    add_elements(
        &mut script,
        "down4",
        &classes(&plan.rules, true, download_major, false),
    );
    add_elements(
        &mut script,
        "down6",
        &classes(&plan.rules, false, download_major, false),
    );
    script.push_str("add chain inet lanspeed_control forward { type filter hook forward priority mangle - 5; policy accept; }\n");
    script.push_str("add rule inet lanspeed_control forward fib daddr type local return\n");
    script.push_str(
        "add rule inet lanspeed_control forward ip saddr @local4 ip daddr @local4 return\n",
    );
    script.push_str(
        "add rule inet lanspeed_control forward ip6 saddr @local6 ip6 daddr @local6 return\n",
    );
    script.push_str("add rule inet lanspeed_control forward ip saddr @blocked4 reject with icmp type admin-prohibited\n");
    script.push_str("add rule inet lanspeed_control forward ip daddr @blocked4 reject with icmp type admin-prohibited\n");
    script.push_str("add rule inet lanspeed_control forward ip6 saddr @blocked6 reject with icmpv6 type admin-prohibited\n");
    script.push_str("add rule inet lanspeed_control forward ip6 daddr @blocked6 reject with icmpv6 type admin-prohibited\n");
    script.push_str("add rule inet lanspeed_control forward meta priority set ip saddr map @up4\n");
    script
        .push_str("add rule inet lanspeed_control forward meta priority set ip6 saddr map @up6\n");
    script.push_str(&format!(
        "add rule inet lanspeed_control forward oifname \"{}\" meta priority set ip daddr map @down4\n",
        plan.lan_device
    ));
    script.push_str(&format!(
        "add rule inet lanspeed_control forward oifname \"{}\" meta priority set ip6 daddr map @down6\n",
        plan.lan_device
    ));
    script
}

fn addresses(
    rules: &[ActiveRule],
    ipv4: bool,
    include: impl Fn(&ActiveRule) -> bool,
) -> Vec<String> {
    rules
        .iter()
        .filter(|rule| include(rule))
        .flat_map(|rule| rule.ips.iter())
        .filter(|ip| ip.is_ipv4() == ipv4)
        .map(ToString::to_string)
        .collect()
}

fn prefixes(values: &[(std::net::IpAddr, u8)], ipv4: bool) -> Vec<String> {
    values
        .iter()
        .filter(|(ip, _)| ip.is_ipv4() == ipv4)
        .map(|(ip, mask)| format!("{ip}/{mask}"))
        .collect()
}

fn classes(rules: &[ActiveRule], ipv4: bool, major: &str, upload: bool) -> Vec<String> {
    rules
        .iter()
        .filter(|rule| {
            if upload {
                rule.upload_bps != 0
            } else {
                rule.download_bps != 0
            }
        })
        .flat_map(|rule| {
            rule.ips
                .iter()
                .filter(move |ip| ip.is_ipv4() == ipv4)
                .map(move |ip| format!("{} : {}:{:x}", ip, major, rule.class_minor))
        })
        .collect()
}

fn add_elements(script: &mut String, set: &str, values: &[String]) {
    if !values.is_empty() {
        script.push_str(&format!(
            "add element inet lanspeed_control {set} {{ {} }}\n",
            values.join(", ")
        ));
    }
}

fn require_ecm_dscp() -> Result<(), String> {
    let path = "/sys/kernel/debug/ecm/ecm_classifier_dscp/enabled";
    if fs::read_to_string(path).is_ok_and(|value| value.trim() == "1") {
        Ok(())
    } else {
        Err("ecm_dscp_classifier_unavailable".into())
    }
}

fn wan_device() -> Result<String, String> {
    let output = Command::new("ubus")
        .args(["call", "network.interface.wan", "status"])
        .output()
        .map_err(|_| "wan_status_unavailable")?;
    if !output.status.success() {
        return Err("wan_status_unavailable".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| "wan_status_invalid")?;
    let device = value
        // NSSHTB belongs on the physical WAN egress. With PPPoE, l3_device is
        // the virtual session while device retains the accelerated lower link.
        .get("device")
        .or_else(|| value.get("l3_device"))
        .and_then(Value::as_str)
        .filter(|value| valid_interface_name(value))
        .ok_or("wan_device_unavailable")?;
    Ok(device.to_owned())
}

fn link_rate_bps(device: &str) -> Result<u64, String> {
    let speed = fs::read_to_string(format!("/sys/class/net/{device}/speed"))
        .map_err(|_| "link_speed_unavailable")?
        .trim()
        .parse::<u64>()
        .map_err(|_| "link_speed_invalid")?;
    let bps = speed.saturating_mul(1_000_000);
    if bps == 0 {
        Err("link_speed_invalid".into())
    } else {
        Ok(bps)
    }
}

fn default_high_rate(physical_rate: u64) -> Result<u64, String> {
    let headroom = physical_rate.saturating_div(10).max(1);
    physical_rate
        .checked_add(headroom)
        .filter(|rate| *rate <= NSS_MAX_RATE_BPS)
        .ok_or_else(|| "nss_default_class_below_physical_link".into())
}

fn ensure_nss_replaceable_root(device: &str, handle: &str, wan: bool) -> Result<(), String> {
    let qdiscs = qdiscs(device)?;
    let roots = root_qdiscs_from(&qdiscs);
    let allowed = !roots.is_empty()
        && roots.iter().all(|(kind, current)| {
            (kind == "nsshtb" && current == handle)
                || (!wan && kind == "noqueue")
                || (wan && kind == "mq")
        })
        && (!wan
            || system_mq_tree(&qdiscs, handle)
            || roots
                .iter()
                .any(|(kind, current)| kind == "nsshtb" && current == handle));
    if allowed {
        Ok(())
    } else {
        Err("qdisc_owned_by_external_service".into())
    }
}

fn restore_default_root(device: &str, handle: &str, default: &str) -> Result<(), String> {
    if !fs::metadata(format!("/sys/class/net/{device}")).is_ok() {
        return Ok(());
    }
    if root_qdiscs(device)?
        .iter()
        .any(|(kind, current)| kind == "nsshtb" && current == handle)
    {
        run("tc", &["qdisc", "del", "dev", device, "root"])?;
        if default == "mq" {
            run("tc", &["qdisc", "replace", "dev", device, "root", "mq"])?;
        }
    }
    Ok(())
}

fn root_qdiscs(device: &str) -> Result<Vec<(String, String)>, String> {
    qdiscs(device).map(|values| root_qdiscs_from(&values))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QdiscInfo {
    kind: String,
    handle: String,
    root: bool,
}

fn qdiscs(device: &str) -> Result<Vec<QdiscInfo>, String> {
    let output = Command::new("tc")
        .args(["qdisc", "show", "dev", device])
        .output()
        .map_err(|_| "qdisc_inspection_failed")?;
    if !output.status.success() {
        return Err("qdisc_inspection_failed".into());
    }
    let values = parse_qdiscs(&String::from_utf8_lossy(&output.stdout));
    if values.is_empty() {
        Err("qdisc_inspection_invalid".into())
    } else {
        Ok(values)
    }
}

fn parse_qdiscs(text: &str) -> Vec<QdiscInfo> {
    text.lines()
        .filter_map(|line| {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            (fields.first() == Some(&"qdisc") && fields.len() >= 3).then(|| QdiscInfo {
                kind: fields[1].to_owned(),
                handle: fields[2].to_owned(),
                root: fields.contains(&"root"),
            })
        })
        .collect()
}

fn root_qdiscs_from(values: &[QdiscInfo]) -> Vec<(String, String)> {
    values
        .iter()
        .filter(|value| value.root)
        .map(|value| (value.kind.clone(), value.handle.clone()))
        .collect()
}

fn system_mq_tree(values: &[QdiscInfo], owned_handle: &str) -> bool {
    values.iter().any(|value| value.root && value.kind == "mq")
        && values.iter().all(|value| {
            matches!(
                value.kind.as_str(),
                "mq" | "fq" | "fq_codel" | "clsact" | "ingress"
            ) && value.handle != owned_handle
        })
}

fn verify_classes(device: &str, major: &str, rules: &[&ActiveRule]) -> Result<(), String> {
    let output = Command::new("tc")
        .args(["class", "show", "dev", device])
        .output()
        .map_err(|_| "queue_tree_verification_failed")?;
    if !output.status.success() {
        return Err("queue_tree_verification_failed".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if text.contains(&format!("{major}:1"))
        && text.contains(&format!("{major}:2"))
        && rules
            .iter()
            .all(|rule| text.contains(&format!("{major}:{:x}", rule.class_minor)))
    {
        Ok(())
    } else {
        Err("queue_tree_verification_failed".into())
    }
}

fn queue_drop_snapshot(wan_device: &str, lan_device: &str) -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    if let Ok(count) = queue_drop_count(wan_device, UPLOAD_HANDLE) {
        counters.insert("upload".into(), count);
    }
    if let Ok(count) = queue_drop_count(lan_device, DOWNLOAD_HANDLE) {
        counters.insert("download".into(), count);
    }
    counters
}

fn queue_drop_count(device: &str, root_handle: &str) -> Result<u64, String> {
    let output = Command::new("tc")
        .args(["-s", "qdisc", "show", "dev", device])
        .output()
        .map_err(|_| "queue_stats_unavailable")?;
    if !output.status.success() {
        return Err("queue_stats_unavailable".into());
    }
    Ok(
        parse_tc_stats(&String::from_utf8_lossy(&output.stdout), "qdisc")
            .into_iter()
            .filter(|(kind, handle, _, _)| kind == "nssbfifo" && handle != root_handle)
            .map(|(_, _, _, drops)| drops)
            .sum(),
    )
}

fn class_counters(device: &str) -> Result<BTreeMap<String, u64>, String> {
    let output = Command::new("tc")
        .args(["-s", "class", "show", "dev", device])
        .output()
        .map_err(|_| "class_stats_unavailable")?;
    if !output.status.success() {
        return Err("class_stats_unavailable".into());
    }
    Ok(
        parse_tc_stats(&String::from_utf8_lossy(&output.stdout), "class")
            .into_iter()
            .filter(|(kind, _, _, _)| kind == "nsshtb")
            .map(|(_, handle, bytes, _)| (handle, bytes))
            .collect(),
    )
}

fn parse_tc_stats(text: &str, record_type: &str) -> Vec<(String, String, u64, u64)> {
    let mut records = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.first() == Some(&record_type) && fields.len() >= 3 {
            current = Some((fields[1].to_owned(), fields[2].to_owned()));
            continue;
        }
        let trimmed = line.trim_start();
        if !trimmed.starts_with("Sent ") {
            continue;
        }
        let Some((kind, handle)) = current.take() else {
            continue;
        };
        let bytes = trimmed
            .split_ascii_whitespace()
            .nth(1)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let drops = trimmed
            .split_once("dropped ")
            .and_then(|(_, rest)| rest.split([',', ' ']).next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        records.push((kind, handle, bytes, drops));
    }
    records
}

fn nss_qdisc_available() -> bool {
    fs::metadata("/sys/module/qca_nss_qdisc").is_ok()
        || fs::read_dir("/lib/modules")
            .ok()
            .into_iter()
            .flatten()
            .any(|entry| {
                entry
                    .ok()
                    .is_some_and(|entry| entry.path().join("qca-nss-qdisc.ko").is_file())
            })
}

fn require_nss_qdisc_module() -> Result<(), String> {
    if fs::metadata("/sys/module/qca_nss_qdisc").is_ok() {
        return Ok(());
    }
    if !nss_qdisc_available() || !crate::probe::commands::command_available("modprobe") {
        return Err("nss_qdisc_module_unavailable".into());
    }
    run("modprobe", &["qca-nss-qdisc"]).map_err(|_| "nss_qdisc_module_unavailable".to_owned())?;
    fs::metadata("/sys/module/qca_nss_qdisc")
        .map(|_| ())
        .map_err(|_| "nss_qdisc_module_unavailable".to_owned())
}

fn clear_disabled_conntrack(rules: &[ActiveRule]) -> Result<(), String> {
    if !crate::probe::commands::command_available("conntrack") {
        return Err("missing_conntrack".into());
    }
    for ip in rules
        .iter()
        .filter(|rule| rule.internet_disabled)
        .flat_map(|rule| rule.ips.iter())
    {
        clear_conntrack_address(*ip)?;
    }
    Ok(())
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn require_program(program: &str) -> Result<(), String> {
    crate::probe::commands::command_available(program)
        .then_some(())
        .ok_or_else(|| format!("missing_{program}"))
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program}_failed:{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_script(program: &str, args: &[&str], script: &str) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    child
        .stdin
        .as_mut()
        .ok_or("command_stdin_missing")?
        .write_all(script.as_bytes())
        .map_err(|error| error.to_string())?;
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program}_failed:{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ControlPlan {
        ControlPlan {
            lan_device: "br-lan".into(),
            local_prefixes: vec![
                ("192.0.2.0".parse().unwrap(), 24),
                ("2001:db8::".parse().unwrap(), 64),
            ],
            rules: vec![ActiveRule {
                identity_key: "02:00:00:00:00:01@lan".into(),
                ips: vec!["192.0.2.9".parse().unwrap(), "2001:db8::9".parse().unwrap()],
                upload_bps: 10_000_000,
                download_bps: 20_000_000,
                internet_disabled: true,
                class_minor: 0x123,
            }],
        }
    }

    #[test]
    fn nft_qos_tags_keep_full_directional_classids() {
        let script = build_nft_script(&plan(), "7b20", "7b10", false);
        assert!(script.contains("192.0.2.9 : 7b20:123"));
        assert!(script.contains("192.0.2.9 : 7b10:123"));
        assert!(script.contains("ip saddr @local4 ip daddr @local4 return"));
        assert!(script.contains("ip daddr @blocked4 reject"));
        assert!(script.contains("ip6 daddr @blocked6 reject"));
        for forbidden in [" police ", " blackhole ", " fq_codel ", " drop\n"] {
            assert!(!script.contains(forbidden));
        }
    }

    #[test]
    fn default_nss_class_requires_headroom_below_u32_limit() {
        assert_eq!(default_high_rate(1_000_000_000).unwrap(), 1_100_000_000);
        assert!(default_high_rate(NSS_MAX_RATE_BPS).is_err());
        assert!(default_high_rate(NSS_MAX_RATE_BPS - 1).is_err());
    }

    #[test]
    fn qdisc_text_reads_nss_stats_and_rejects_foreign_mq_leaves() {
        let stats = parse_tc_stats(
            "qdisc nssbfifo 25d8: parent 7b10:25d8 limit 16Mb\n Sent 123 bytes 4 pkt (dropped 3, overlimits 9 requeues 0)\n",
            "qdisc",
        );
        assert_eq!(stats, vec![("nssbfifo".into(), "25d8:".into(), 123, 3)]);
        let default = parse_qdiscs(
            "qdisc mq 8001: root\nqdisc fq_codel 0: parent 8001:1 limit 10240p\nqdisc clsact ffff: parent ffff:fff1\n",
        );
        assert!(system_mq_tree(&default, UPLOAD_HANDLE));
        let foreign =
            parse_qdiscs("qdisc mq 8001: root\nqdisc cake 9000: parent 8001:1 bandwidth 100Mbit\n");
        assert!(!system_mq_tree(&foreign, UPLOAD_HANDLE));
        let handle_collision = parse_qdiscs("qdisc cake 7b20: root bandwidth 100Mbit\n");
        assert!(!root_qdiscs_from(&handle_collision)
            .iter()
            .all(|(kind, current)| kind == "nsshtb" && current == UPLOAD_HANDLE));
        let owned = parse_qdiscs("qdisc nsshtb 7b20: root refcnt 5 accel_mode 0\n");
        assert_eq!(
            root_qdiscs_from(&owned),
            vec![("nsshtb".into(), UPLOAD_HANDLE.into())]
        );
    }

    #[test]
    fn class_text_reads_nss_counter_bytes() {
        let stats = parse_tc_stats(
            "class nsshtb 7b20:25d8 root leaf 25d8: burst 16Mb rate 900Mbit\n Sent 678 bytes 5 pkt (dropped 0, overlimits 2 requeues 0)\n",
            "class",
        );
        assert_eq!(stats, vec![("nsshtb".into(), "7b20:25d8".into(), 678, 0)]);
    }

    #[test]
    fn verification_requires_growth_after_the_apply_baseline() {
        let identity = "02:00:00:00:00:01@lan";
        let mut result = ApplyResult {
            state: "pending_new_connections".into(),
            reason: Some("new_connections_only".into()),
            shaping_supported: true,
            blocking_supported: true,
            queue_overflow: false,
            queue_drop_counters: Default::default(),
            class_counter_baselines: BTreeMap::from([
                (class_counter_key(identity, "upload"), 100),
                (class_counter_key(identity, "download"), 200),
            ]),
            verified_directions: Default::default(),
        };
        assert!(!class_counter_grew(&result, identity, "upload", Some(100)));
        assert!(class_counter_grew(&result, identity, "upload", Some(101)));
        result.verified_directions.insert(identity.into(), 1);
        assert_eq!(result.verified_directions.get(identity), Some(&1));
    }
}
