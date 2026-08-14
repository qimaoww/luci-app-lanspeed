use std::net::IpAddr;

use serde_json::Value;

use crate::control::ActiveRule;

use super::{ifb, system};

const CHAIN: u32 = 0x7a20;
// The rate-monitor BPF owns normal priority 0xc000.  Control must run after
// it so redirecting a controlled upload cannot hide bytes from RateMux.
const JUMP_PREF: u32 = 0xd020;
const LOCAL_PREF_START: u32 = 100;
const CLIENT_PREF_START: u32 = 10_000;
const TERMINAL_PREF: u32 = 65_534;
const CONTROL_PROTOCOLS: [&str; 2] = ["ip", "ipv6"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Hook {
    Ingress,
    Egress,
}

impl Hook {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }

    const fn jump_pref(self) -> u32 {
        match self {
            // Keep accounting first, then apply direct-LAN control.
            Self::Ingress => JUMP_PREF,
            // Upgrade cleanup for the rejected dae0->IFB redirect.  New code
            // must never install this egress jump because mirred steals the
            // packet from DAE's veth delivery path.
            Self::Egress => 100,
        }
    }
}

pub(crate) fn preflight(
    lan_device: &str,
    local_prefixes: &[(IpAddr, u8)],
    rules: &[&ActiveRule],
) -> Result<(), String> {
    preflight_on(Hook::Ingress, lan_device, local_prefixes, rules)
}

fn preflight_on(
    hook: Hook,
    lan_device: &str,
    local_prefixes: &[(IpAddr, u8)],
    rules: &[&ActiveRule],
) -> Result<(), String> {
    if !system::interface_exists(lan_device) {
        return Err("lan_control_interface_unavailable".into());
    }
    for module in ["cls_u32", "cls_matchall", "act_mirred"] {
        if !system::module_available(module) {
            return Err(format!("{module}_unavailable"));
        }
    }
    validate_capacity(local_prefixes, rules)?;
    ensure_jump_owned_or_absent(hook, lan_device)?;
    ensure_chain_owned_or_absent(hook, lan_device)
}

pub(crate) fn install(
    lan_device: &str,
    local_prefixes: &[(IpAddr, u8)],
    rules: &[&ActiveRule],
) -> Result<(), String> {
    install_on(Hook::Ingress, lan_device, local_prefixes, rules)
}

fn install_on(
    hook: Hook,
    lan_device: &str,
    local_prefixes: &[(IpAddr, u8)],
    rules: &[&ActiveRule],
) -> Result<(), String> {
    preflight_on(hook, lan_device, local_prefixes, rules)?;
    system::ensure_clsact(lan_device)?;
    deactivate_on(hook, lan_device)?;
    clear_chain(hook, lan_device)?;

    // Create the ownership marker before staging filters so a failure in any
    // later command remains exactly and safely rollback-able.
    let chain = CHAIN.to_string();
    let terminal = TERMINAL_PREF.to_string();
    let marker = format!("0x{CHAIN:x}");
    system::run(
        "tc",
        &[
            "filter",
            "add",
            "dev",
            lan_device,
            hook.as_str(),
            "chain",
            &chain,
            "protocol",
            "all",
            "pref",
            &terminal,
            "handle",
            &marker,
            "matchall",
            "action",
            "pass",
        ],
    )?;

    let mut preference = LOCAL_PREF_START;
    for (address, prefix_len) in local_prefixes {
        add_u32(
            hook,
            lan_device,
            preference,
            *address,
            *prefix_len,
            "dst",
            &["action", "pass"],
        )?;
        preference += 1;
    }

    preference = CLIENT_PREF_START;
    for rule in rules {
        for protocol in CONTROL_PROTOCOLS {
            add_mac(
                hook,
                lan_device,
                preference,
                protocol,
                "src",
                &rule.mac.to_string(),
                &["action", "mirred", "egress", "redirect", "dev", ifb::DEVICE],
            )?;
            preference += 1;
        }
    }

    verify_chain(hook, lan_device, rules)?;
    activate_on(hook, lan_device)
}

fn deactivate_on(hook: Hook, lan_device: &str) -> Result<(), String> {
    if !system::interface_exists(lan_device) || !system::has_qdisc(lan_device, "clsact", None) {
        return Ok(());
    }
    ensure_jump_owned_or_absent(hook, lan_device)?;
    let preference = hook.jump_pref().to_string();
    system::run_ignore_missing(
        "tc",
        &[
            "filter",
            "del",
            "dev",
            lan_device,
            hook.as_str(),
            "pref",
            &preference,
        ],
    );
    Ok(())
}

pub(crate) fn cleanup(lan_device: &str) -> Result<(), String> {
    cleanup_on(Hook::Ingress, lan_device)
}

pub(crate) fn cleanup_legacy_dae_egress(device: &str) -> Result<(), String> {
    cleanup_on(Hook::Egress, device)
}

pub(crate) fn ingress_owned(device: &str) -> Result<bool, String> {
    owned_on(Hook::Ingress, device)
}

pub(crate) fn legacy_dae_egress_owned(device: &str) -> Result<bool, String> {
    owned_on(Hook::Egress, device)
}

fn owned_on(hook: Hook, device: &str) -> Result<bool, String> {
    if !system::interface_exists(device) || !system::has_qdisc(device, "clsact", None) {
        return Ok(false);
    }
    let preference = hook.jump_pref().to_string();
    let jump = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            device,
            hook.as_str(),
            "pref",
            &preference,
        ],
    )?;
    if !jump.status.success() {
        return Err("ingress_filter_inspection_failed".into());
    }
    let jump: Vec<Value> = serde_json::from_slice(&jump.stdout)
        .map_err(|_| "ingress_filter_inspection_failed".to_owned())?;
    if jump.iter().any(|value| contains_goto_chain(value, CHAIN)) {
        return Ok(true);
    }

    let chain = CHAIN.to_string();
    let marker = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            device,
            hook.as_str(),
            "chain",
            &chain,
        ],
    )?;
    if !marker.status.success() {
        return Err("ingress_filter_inspection_failed".into());
    }
    let marker: Vec<Value> = serde_json::from_slice(&marker.stdout)
        .map_err(|_| "ingress_filter_inspection_failed".to_owned())?;
    Ok(marker.iter().any(contains_owned_chain_marker))
}

fn cleanup_on(hook: Hook, lan_device: &str) -> Result<(), String> {
    if !system::interface_exists(lan_device) || !system::has_qdisc(lan_device, "clsact", None) {
        return Ok(());
    }
    deactivate_on(hook, lan_device)?;
    clear_chain(hook, lan_device)?;
    if owned_on(hook, lan_device)? {
        Err("ingress_filter_cleanup_failed".into())
    } else {
        Ok(())
    }
}

fn activate_on(hook: Hook, lan_device: &str) -> Result<(), String> {
    let preference = hook.jump_pref().to_string();
    let chain = CHAIN.to_string();
    system::run(
        "tc",
        &[
            "filter",
            "add",
            "dev",
            lan_device,
            hook.as_str(),
            "protocol",
            "all",
            "pref",
            &preference,
            "matchall",
            "action",
            "goto",
            "chain",
            &chain,
        ],
    )
}

fn clear_chain(hook: Hook, lan_device: &str) -> Result<(), String> {
    ensure_chain_owned_or_absent(hook, lan_device)?;
    let chain = CHAIN.to_string();
    system::run_ignore_missing(
        "tc",
        &[
            "filter",
            "del",
            "dev",
            lan_device,
            hook.as_str(),
            "chain",
            &chain,
        ],
    );
    Ok(())
}

fn ensure_jump_owned_or_absent(hook: Hook, lan_device: &str) -> Result<(), String> {
    let preference = hook.jump_pref().to_string();
    let output = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            lan_device,
            hook.as_str(),
            "pref",
            &preference,
        ],
    )?;
    if !output.status.success() {
        return Err("ingress_filter_inspection_failed".into());
    }
    if output.stdout == b"[]\n" || output.stdout == b"[]" {
        return Ok(());
    }
    let values: Vec<Value> = serde_json::from_slice(&output.stdout)
        .map_err(|_| "ingress_filter_inspection_failed".to_owned())?;
    if values.iter().any(|value| contains_goto_chain(value, CHAIN)) {
        Ok(())
    } else {
        Err("ingress_filter_owned_by_external_service".into())
    }
}

fn ensure_chain_owned_or_absent(hook: Hook, lan_device: &str) -> Result<(), String> {
    let chain = CHAIN.to_string();
    let output = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            lan_device,
            hook.as_str(),
            "chain",
            &chain,
        ],
    )?;
    if !output.status.success() {
        return Err("ingress_filter_inspection_failed".into());
    }
    if output.stdout == b"[]\n" || output.stdout == b"[]" {
        return Ok(());
    }
    let values: Vec<Value> = serde_json::from_slice(&output.stdout)
        .map_err(|_| "ingress_filter_inspection_failed".to_owned())?;
    if values.iter().any(contains_owned_chain_marker) {
        Ok(())
    } else {
        Err("ingress_chain_owned_by_external_service".into())
    }
}

fn contains_owned_chain_marker(value: &Value) -> bool {
    value.get("kind").and_then(Value::as_str) == Some("matchall")
        && value
            .get("options")
            .and_then(|options| options.get("handle"))
            .and_then(Value::as_u64)
            == Some(u64::from(CHAIN))
}

fn contains_goto_chain(value: &Value, chain: u32) -> bool {
    match value {
        Value::Object(values) => {
            values.get("type").and_then(Value::as_str) == Some("goto")
                && values.get("chain").and_then(Value::as_u64) == Some(u64::from(chain))
                || values
                    .values()
                    .any(|value| contains_goto_chain(value, chain))
        }
        Value::Array(values) => values.iter().any(|value| contains_goto_chain(value, chain)),
        _ => false,
    }
}

fn add_u32(
    hook: Hook,
    device: &str,
    preference: u32,
    address: IpAddr,
    prefix_len: u8,
    field: &str,
    action: &[&str],
) -> Result<(), String> {
    let chain = CHAIN.to_string();
    let preference = preference.to_string();
    let cidr = format!("{address}/{prefix_len}");
    let (protocol, family) = if address.is_ipv4() {
        ("ip", "ip")
    } else {
        ("ipv6", "ip6")
    };
    let mut args = vec![
        "filter",
        "add",
        "dev",
        device,
        hook.as_str(),
        "chain",
        &chain,
        "protocol",
        protocol,
        "pref",
        &preference,
        "u32",
        "match",
        family,
        field,
        &cidr,
    ];
    args.extend_from_slice(action);
    system::run("tc", &args)
}

fn add_mac(
    hook: Hook,
    device: &str,
    preference: u32,
    protocol: &str,
    field: &str,
    mac: &str,
    action: &[&str],
) -> Result<(), String> {
    let chain = CHAIN.to_string();
    let preference = preference.to_string();
    let mut args = vec![
        "filter",
        "add",
        "dev",
        device,
        hook.as_str(),
        "chain",
        &chain,
        "protocol",
        protocol,
        "pref",
        &preference,
        "u32",
        "match",
        "ether",
        field,
        mac,
    ];
    args.extend_from_slice(action);
    system::run("tc", &args)
}

fn validate_capacity(local_prefixes: &[(IpAddr, u8)], rules: &[&ActiveRule]) -> Result<(), String> {
    let client_filters =
        u32::try_from(rules.len().saturating_mul(CONTROL_PROTOCOLS.len())).unwrap_or(u32::MAX);
    if LOCAL_PREF_START + local_prefixes.len() as u32 >= CLIENT_PREF_START
        || CLIENT_PREF_START.saturating_add(client_filters) >= TERMINAL_PREF
    {
        Err("control_filter_capacity".into())
    } else {
        Ok(())
    }
}

fn verify_chain(hook: Hook, lan_device: &str, rules: &[&ActiveRule]) -> Result<(), String> {
    let chain = CHAIN.to_string();
    let output = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            lan_device,
            hook.as_str(),
            "chain",
            &chain,
        ],
    )?;
    if !output.status.success() {
        return Err("ingress_filter_verification_failed".into());
    }
    let values: Vec<Value> = serde_json::from_slice(&output.stdout)
        .map_err(|_| "ingress_filter_verification_failed".to_owned())?;
    let expected = rules.len().saturating_mul(CONTROL_PROTOCOLS.len());
    let redirects = values
        .iter()
        .map(|value| count_ifb_redirects(value, ifb::DEVICE))
        .sum::<usize>();
    if redirects == expected {
        Ok(())
    } else {
        Err("ingress_filter_verification_failed".into())
    }
}

fn count_ifb_redirects(value: &Value, device: &str) -> usize {
    match value {
        Value::Object(values) => {
            let current = usize::from(
                values.get("kind").and_then(Value::as_str) == Some("mirred")
                    && values.get("mirred_action").and_then(Value::as_str) == Some("redirect")
                    && values.get("direction").and_then(Value::as_str) == Some("egress")
                    && values.get("to_dev").and_then(Value::as_str) == Some(device),
            );
            current
                + values
                    .values()
                    .map(|value| count_ifb_redirects(value, device))
                    .sum::<usize>()
        }
        Value::Array(values) => values
            .iter()
            .map(|value| count_ifb_redirects(value, device))
            .sum(),
        _ => 0,
    }
}

#[cfg(test)]
include!("classifier_tests.rs");
