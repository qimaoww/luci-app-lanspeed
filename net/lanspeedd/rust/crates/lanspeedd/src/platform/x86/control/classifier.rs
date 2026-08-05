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

pub(crate) fn preflight(
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
    ensure_jump_owned_or_absent(lan_device)?;
    ensure_chain_owned_or_absent(lan_device)
}

pub(crate) fn install(
    lan_device: &str,
    local_prefixes: &[(IpAddr, u8)],
    rules: &[&ActiveRule],
) -> Result<(), String> {
    preflight(lan_device, local_prefixes, rules)?;
    system::ensure_clsact(lan_device)?;
    deactivate(lan_device)?;
    clear_chain(lan_device)?;

    let mut preference = LOCAL_PREF_START;
    for (address, prefix_len) in local_prefixes {
        add_u32(
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
        for address in &rule.ips {
            add_u32(
                lan_device,
                preference,
                *address,
                if address.is_ipv4() { 32 } else { 128 },
                "src",
                &["action", "mirred", "egress", "redirect", "dev", ifb::DEVICE],
            )?;
            preference += 1;
        }
    }

    let chain = CHAIN.to_string();
    let terminal = TERMINAL_PREF.to_string();
    let marker = format!("0x{CHAIN:x}");
    system::run(
        "tc",
        &[
            "filter", "add", "dev", lan_device, "ingress", "chain", &chain, "protocol", "all",
            "pref", &terminal, "handle", &marker, "matchall", "action", "pass",
        ],
    )?;
    verify_chain(lan_device, rules)?;
    activate(lan_device)
}

pub(crate) fn deactivate(lan_device: &str) -> Result<(), String> {
    if !system::interface_exists(lan_device) || !system::has_qdisc(lan_device, "clsact", None) {
        return Ok(());
    }
    ensure_jump_owned_or_absent(lan_device)?;
    let preference = JUMP_PREF.to_string();
    system::run_ignore_missing(
        "tc",
        &[
            "filter",
            "del",
            "dev",
            lan_device,
            "ingress",
            "pref",
            &preference,
        ],
    );
    Ok(())
}

pub(crate) fn cleanup(lan_device: &str) -> Result<(), String> {
    if !system::interface_exists(lan_device) || !system::has_qdisc(lan_device, "clsact", None) {
        return Ok(());
    }
    deactivate(lan_device)?;
    clear_chain(lan_device)
}

fn activate(lan_device: &str) -> Result<(), String> {
    let preference = JUMP_PREF.to_string();
    let chain = CHAIN.to_string();
    system::run(
        "tc",
        &[
            "filter",
            "add",
            "dev",
            lan_device,
            "ingress",
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

fn clear_chain(lan_device: &str) -> Result<(), String> {
    ensure_chain_owned_or_absent(lan_device)?;
    let chain = CHAIN.to_string();
    system::run_ignore_missing(
        "tc",
        &[
            "filter", "del", "dev", lan_device, "ingress", "chain", &chain,
        ],
    );
    Ok(())
}

fn ensure_jump_owned_or_absent(lan_device: &str) -> Result<(), String> {
    let preference = JUMP_PREF.to_string();
    let output = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            lan_device,
            "ingress",
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

fn ensure_chain_owned_or_absent(lan_device: &str) -> Result<(), String> {
    let chain = CHAIN.to_string();
    let output = system::output(
        "tc",
        &[
            "-j", "-d", "filter", "show", "dev", lan_device, "ingress", "chain", &chain,
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
    if values.iter().any(|value| {
        value.get("kind").and_then(Value::as_str) == Some("matchall")
            && value
                .get("options")
                .and_then(|options| options.get("handle"))
                .and_then(Value::as_u64)
                == Some(u64::from(CHAIN))
    }) {
        Ok(())
    } else {
        Err("ingress_chain_owned_by_external_service".into())
    }
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
        "ingress",
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

fn validate_capacity(local_prefixes: &[(IpAddr, u8)], rules: &[&ActiveRule]) -> Result<(), String> {
    let addresses = rules.iter().map(|rule| rule.ips.len()).sum::<usize>();
    if LOCAL_PREF_START + local_prefixes.len() as u32 >= CLIENT_PREF_START
        || CLIENT_PREF_START + addresses as u32 >= TERMINAL_PREF
    {
        Err("control_filter_capacity".into())
    } else {
        Ok(())
    }
}

fn verify_chain(lan_device: &str, rules: &[&ActiveRule]) -> Result<(), String> {
    let chain = CHAIN.to_string();
    let output = system::output(
        "tc",
        &[
            "-j", "-d", "filter", "show", "dev", lan_device, "ingress", "chain", &chain,
        ],
    )?;
    if !output.status.success() {
        return Err("ingress_filter_verification_failed".into());
    }
    let values: Vec<Value> = serde_json::from_slice(&output.stdout)
        .map_err(|_| "ingress_filter_verification_failed".to_owned())?;
    let expected = rules.iter().map(|rule| rule.ips.len()).sum::<usize>();
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
mod tests {
    use super::*;

    #[test]
    fn goto_chain_is_detected_structurally() {
        let value = serde_json::json!({
            "options": { "actions": [
                { "control_action": { "type": "goto", "chain": CHAIN } }
            ] }
        });
        assert!(contains_goto_chain(&value, CHAIN));
        assert!(!contains_goto_chain(&value, CHAIN + 1));
    }

    #[test]
    fn capacity_keeps_local_and_client_ranges_separate() {
        let rule = ActiveRule {
            identity_key: "02:00:00:00:00:01@lan".into(),
            ips: vec!["192.0.2.8".parse().unwrap()],
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: 0x123,
        };
        assert_eq!(
            validate_capacity(&[("192.0.2.0".parse().unwrap(), 24)], &[&rule]),
            Ok(())
        );
    }

    #[test]
    fn redirect_verification_is_address_format_independent() {
        let value = serde_json::json!({
            "actions": [{
                "kind": "mirred",
                "mirred_action": "redirect",
                "direction": "egress",
                "to_dev": ifb::DEVICE
            }]
        });
        assert_eq!(count_ifb_redirects(&value, ifb::DEVICE), 1);
        assert_eq!(count_ifb_redirects(&value, "ifb-foreign"), 0);
    }
}
