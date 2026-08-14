use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::control::{ActiveRule, ControlPlan, NSS_CPU_UPLOAD};

use super::{ifb, system};
use crate::platform::nss::control::qdisc;

const ROOT: &str = "7d00:";
const FILTER_CHAIN: u32 = 0x7e60;
const FILTER_JUMP_PREF: u32 = 0xd060;
const FILTER_LOCAL_PREF_START: u32 = 100;
const FILTER_TERMINAL_PREF: u32 = 65_534;
const NSS_IGS_STATS: &str = "/sys/kernel/debug/qca-nss-drv/stats/igs";

pub(super) fn preflight(plan: &ControlPlan) -> Result<(), String> {
    let grouped = grouped_rules(plan);
    if grouped.is_empty() {
        return Ok(());
    }
    for module in [
        "ifb",
        "qca_nss_qdisc",
        "act_nssmirred",
        "lanspeed_nss_control",
        "cls_u32",
        "cls_matchall",
        "act_gact",
    ] {
        if !system::module_available(module) {
            return Err(format!("{module}_unavailable"));
        }
    }
    let edges = grouped.keys().cloned().collect::<BTreeSet<_>>();
    ifb::preflight(&edges)
}

pub(super) fn stage(plan: &ControlPlan) -> Result<(), String> {
    let grouped = grouped_rules(plan);
    if grouped.is_empty() {
        return Ok(());
    }
    system::load_module("ifb", "ifb_module_unavailable")?;
    system::load_module("act_nssmirred", "act_nssmirred_unavailable")?;
    system::load_module("lanspeed_nss_control", "lanspeed_nss_control_unavailable")?;
    system::load_module("qca_nss_qdisc", "nss_qdisc_unavailable")?;
    for (edge, rules) in &grouped {
        let staged = (|| {
            let device = ifb::ensure(edge)?;
            ifb::stage(edge)?;
            cleanup_filters(&device)?;
            qdisc::sync_igs_tree(&device, rules)?;
            Ok(())
        })();
        if let Err(error) = staged {
            return match cleanup_unpublished() {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!("{error};{cleanup_error}")),
            };
        }
    }
    Ok(())
}

pub(super) fn cleanup_stale(plan: &ControlPlan) -> Result<(), String> {
    let active = grouped_rules(plan).keys().cloned().collect();
    cleanup_obsolete(&active)?;
    cleanup_legacy_ifbs()
}

pub(super) fn cleanup_unpublished() -> Result<(), String> {
    let mut errors = Vec::new();
    for (device, edge) in ifb::owned_interfaces()? {
        if ifb::state(&device)? != Some(ifb::IgsState::Staged) {
            continue;
        }
        if let Err(error) = cleanup_filters(&device) {
            errors.push(error);
            continue;
        }
        if system::owned_root(&device).unwrap_or(false) {
            if let Err(error) = qdisc::remove_igs_tree(&device) {
                errors.push(error);
                continue;
            }
        }
        if let Err(error) = ifb::cleanup(&edge) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(";"))
    }
}

pub(super) fn verify(plan: &ControlPlan) -> Result<(), String> {
    let grouped = grouped_rules(plan);
    let active = grouped.keys().cloned().collect::<BTreeSet<_>>();
    for (edge, rules) in &grouped {
        if !ifb::owned(edge)? {
            return Err("nss_igs_ifb_missing".into());
        }
        let device = ifb::device(edge);
        qdisc::verify_igs_tree(&device, rules)?;
        let peers = rules.iter().map(|rule| rule.mac).collect::<BTreeSet<_>>();
        ifb::verify_peers(edge, &peers)?;
    }
    for (_, edge) in ifb::owned_interfaces()? {
        if !active.contains(&edge) {
            return Err("nss_igs_ifb_stale".into());
        }
    }
    Ok(())
}

pub(super) fn cleanup() -> Result<(), String> {
    cleanup_obsolete(&BTreeSet::new())?;
    cleanup_legacy_ifbs()
}

pub(super) fn class_bytes(plan: &ControlPlan) -> Result<BTreeMap<String, u64>, String> {
    let mut snapshot = BTreeMap::new();
    for (edge, rules) in grouped_rules(plan) {
        let device = ifb::device(&edge);
        let output = system::output("tc", &["-s", "class", "show", "dev", &device])?;
        if !output.status.success() {
            return Err("queue_stats_unavailable".into());
        }
        let text = String::from_utf8(output.stdout).map_err(|_| "queue_stats_unavailable")?;
        for rule in rules {
            let class = qdisc::classid(rule.class_minor);
            let bytes = block_counter(
                &text,
                |fields| {
                    fields.len() >= 3
                        && fields[0] == "class"
                        && fields[1] == "nsshtb"
                        && fields[2] == class
                },
                "Sent",
            )
            .ok_or_else(|| "queue_stats_unavailable".to_owned())?;
            snapshot.insert(
                format!(
                    "{}/upload/aggregate/{device}/class_bytes",
                    rule.identity_key
                ),
                bytes,
            );
        }
    }
    Ok(snapshot)
}

/// NSS IGS receive bytes prove that the physical edge actually entered the
/// hardware ingress shaper. These counters are verification-only.
pub(super) fn nss_input_bytes(plan: &ControlPlan) -> Result<BTreeMap<String, u64>, String> {
    let text = std::fs::read_to_string(NSS_IGS_STATS)
        .map_err(|_| "nss_igs_counter_unavailable".to_owned())?;
    let mut snapshot = BTreeMap::new();
    for (edge, rules) in grouped_rules(plan) {
        let device = ifb::device(&edge);
        let bytes =
            igs_rx_bytes(&text, &device).ok_or_else(|| "nss_igs_counter_unavailable".to_owned())?;
        for rule in rules {
            snapshot.insert(
                format!("{}/upload/nss/{device}/input_bytes", rule.identity_key),
                bytes,
            );
        }
    }
    Ok(snapshot)
}

fn igs_rx_bytes(text: &str, device: &str) -> Option<u64> {
    let mut selected = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some((_, netdevice)) = trimmed.split_once("netdevice=") {
            selected = netdevice.trim() == device;
            continue;
        }
        if !selected || !trimmed.contains("_rx_byts") {
            continue;
        }
        return trimmed
            .split_once('=')?
            .1
            .split_ascii_whitespace()
            .next()?
            .parse()
            .ok();
    }
    None
}

pub(super) fn queue_drops(plan: &ControlPlan) -> Result<BTreeMap<String, u64>, String> {
    let mut snapshot = BTreeMap::new();
    for (edge, rules) in grouped_rules(plan) {
        let device = ifb::device(&edge);
        let output = system::output("tc", &["-s", "qdisc", "show", "dev", &device])?;
        if !output.status.success() {
            return Err("queue_stats_unavailable".into());
        }
        let text = String::from_utf8(output.stdout).map_err(|_| "queue_stats_unavailable")?;
        for rule in rules {
            let parent = qdisc::classid(rule.class_minor);
            let handle = qdisc::leaf_handle(rule.class_minor);
            let drops = block_counter(
                &text,
                |fields| {
                    fields.len() >= 3
                        && fields[0] == "qdisc"
                        && fields[1] == "nssbfifo"
                        && fields[2] == handle
                        && fields
                            .windows(2)
                            .any(|pair| pair[0] == "parent" && pair[1] == parent)
                },
                "dropped",
            )
            .ok_or_else(|| "queue_stats_unavailable".to_owned())?;
            snapshot.insert(
                format!(
                    "{}/upload/aggregate/{device}/queue_drops",
                    rule.identity_key
                ),
                drops,
            );
        }
    }
    Ok(snapshot)
}

fn grouped_rules(plan: &ControlPlan) -> BTreeMap<String, Vec<&ActiveRule>> {
    let mut grouped = BTreeMap::<String, Vec<&ActiveRule>>::new();
    for rule in plan.rules.iter().filter(|rule| {
        rule.upload_bps != 0 && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD)
    }) {
        grouped
            .entry(rule.interface.clone())
            .or_default()
            .push(rule);
    }
    grouped
}

#[cfg(test)]
mod counter_tests {
    use super::igs_rx_bytes;

    #[test]
    fn parses_igs_bytes_for_the_exact_dynamic_device() {
        let text = "0. nss interface id=34, netdevice=lsu11111111\n\
                    \tigs[0]_rx_byts = 123 common\n\
                    1. nss interface id=35, netdevice=lsu22222222\n\
                    \tigs[1]_rx_byts = 456 common\n";
        assert_eq!(igs_rx_bytes(text, "lsu22222222"), Some(456));
        assert_eq!(igs_rx_bytes(text, "lsu33333333"), None);
    }
}

fn cleanup_obsolete(active: &BTreeSet<String>) -> Result<(), String> {
    let mut errors = Vec::new();
    for (device, edge) in ifb::owned_interfaces()? {
        if active.contains(&edge) {
            continue;
        }
        if let Err(error) = cleanup_filters(&device) {
            errors.push(error);
            continue;
        }
        if system::owned_root(&device).unwrap_or(false) {
            if let Err(error) = qdisc::remove_igs_tree(&device) {
                errors.push(error);
                continue;
            }
        }
        if let Err(error) = ifb::cleanup(&edge) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(";"))
    }
}

fn cleanup_legacy_ifbs() -> Result<(), String> {
    for (device, alias, root) in [
        ("ifb-nss-lsu", "lanspeedd:nss-cpu-upload:v2", "7e20:"),
        ("ifb-nss-lsd", "lanspeedd:nss-cpu-download:v2", "7e30:"),
    ] {
        if !system::interface_exists(device) {
            continue;
        }
        let current_alias =
            std::fs::read_to_string(format!("/sys/class/net/{device}/ifalias")).unwrap_or_default();
        if current_alias.trim() != alias {
            return Err("cpu_path_qdisc_owned_by_external_service".into());
        }
        let roots = system::qdiscs(device)?;
        if roots
            .iter()
            .any(|qdisc| qdisc.root && !(qdisc.kind == "htb" && qdisc.handle == root))
        {
            return Err("cpu_path_qdisc_owned_by_external_service".into());
        }
        if roots
            .iter()
            .any(|qdisc| qdisc.root && qdisc.kind == "htb" && qdisc.handle == root)
        {
            system::run(
                "tc",
                &["qdisc", "del", "dev", device, "root", "handle", root],
            )?;
        }
        system::run("ip", &["link", "delete", "dev", device])?;
    }
    Ok(())
}

fn ensure_filters_owned_or_absent(device: &str) -> Result<(), String> {
    let values = filter_values(device)?;
    let jumps = jump_values(device)?;
    let chain_owned = values.is_empty()
        || (values.iter().any(filter_marker) && values.iter().all(owned_chain_entry));
    let jump_owned = jumps.is_empty() || (jumps.len() == 1 && jump_marker(&jumps[0]));
    if chain_owned && jump_owned {
        Ok(())
    } else {
        Err("nss_igs_filter_owned_by_external_service".into())
    }
}

fn cleanup_filters(device: &str) -> Result<(), String> {
    ensure_filters_owned_or_absent(device)?;
    if !jump_values(device)?.is_empty() {
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                device,
                "parent",
                ROOT,
                "pref",
                &FILTER_JUMP_PREF.to_string(),
            ],
        )?;
    }
    if !filter_values(device)?.is_empty() {
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                device,
                "parent",
                ROOT,
                "chain",
                &FILTER_CHAIN.to_string(),
            ],
        )?;
    }
    Ok(())
}

fn filter_values(device: &str) -> Result<Vec<Value>, String> {
    if !system::interface_exists(device) || !system::owned_root(device)? {
        return Ok(Vec::new());
    }
    let output = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            device,
            "parent",
            ROOT,
            "chain",
            &FILTER_CHAIN.to_string(),
        ],
    )?;
    if !output.status.success() {
        return Err("nss_igs_filter_inspection_failed".into());
    }
    system::tc_filter_values(&output.stdout, "nss_igs_filter_inspection_failed")
}

fn jump_values(device: &str) -> Result<Vec<Value>, String> {
    if !system::interface_exists(device) || !system::owned_root(device)? {
        return Ok(Vec::new());
    }
    let output = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            device,
            "parent",
            ROOT,
            "pref",
            &FILTER_JUMP_PREF.to_string(),
        ],
    )?;
    if !output.status.success() {
        return Err("nss_igs_filter_inspection_failed".into());
    }
    system::tc_filter_values_at_pref(
        &output.stdout,
        FILTER_JUMP_PREF,
        "nss_igs_filter_inspection_failed",
    )
}

fn filter_marker(value: &Value) -> bool {
    exact_matchall_action(
        value,
        FILTER_TERMINAL_PREF,
        Some(FILTER_CHAIN),
        "pass",
        None,
    )
}

fn jump_marker(value: &Value) -> bool {
    exact_matchall_action(value, FILTER_JUMP_PREF, None, "goto", Some(FILTER_CHAIN))
}

fn owned_chain_entry(value: &Value) -> bool {
    match (
        value.get("kind").and_then(Value::as_str),
        value.get("pref").and_then(Value::as_u64),
    ) {
        (Some("matchall"), Some(pref)) => pref == u64::from(FILTER_TERMINAL_PREF),
        (Some("u32"), Some(pref)) => {
            (u64::from(FILTER_LOCAL_PREF_START)..u64::from(FILTER_TERMINAL_PREF)).contains(&pref)
                && matches!(
                    value.get("protocol").and_then(Value::as_str),
                    Some("ip" | "ipv6")
                )
        }
        _ => false,
    }
}

fn exact_matchall_action(
    value: &Value,
    pref: u32,
    handle: Option<u32>,
    action_type: &str,
    goto_chain: Option<u32>,
) -> bool {
    if value.get("kind").and_then(Value::as_str) != Some("matchall")
        || value.get("protocol").and_then(Value::as_str) != Some("all")
        || value.get("pref").and_then(Value::as_u64) != Some(u64::from(pref))
    {
        return false;
    }
    let Some(options) = value.get("options") else {
        return false;
    };
    if handle.is_some_and(|handle| {
        options.get("handle").and_then(Value::as_u64) != Some(u64::from(handle))
    }) {
        return false;
    }
    let Some(actions) = options.get("actions").and_then(Value::as_array) else {
        return false;
    };
    if actions.len() != 1 || actions[0].get("kind").and_then(Value::as_str) != Some("gact") {
        return false;
    }
    let Some(control) = actions[0].get("control_action") else {
        return false;
    };
    control.get("type").and_then(Value::as_str) == Some(action_type)
        && goto_chain.is_none_or(|chain| {
            control.get("chain").and_then(Value::as_u64) == Some(u64::from(chain))
        })
}

fn block_counter(
    text: &str,
    header_matches: impl Fn(&[&str]) -> bool,
    counter: &str,
) -> Option<u64> {
    let mut selected = false;
    for line in text.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if matches!(fields.first().copied(), Some("class" | "qdisc")) {
            selected = header_matches(&fields);
            continue;
        }
        if !selected {
            continue;
        }
        if counter == "Sent" && fields.first().copied() == Some("Sent") {
            return fields.get(1)?.parse().ok();
        }
        if counter == "dropped" {
            let value = fields
                .iter()
                .position(|field| *field == "(dropped")
                .and_then(|index| fields.get(index + 1))?;
            return value.trim_end_matches(',').parse().ok();
        }
    }
    None
}

#[cfg(test)]
include!("shaper_tests.rs");
