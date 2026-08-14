use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde_json::Value;

use crate::control::{clear_conntrack_address, ActiveRule, ControlPlan};

use super::system;

const NFT_TABLE: &str = "lanspeed_control";
const NFT_OWNER_COMMENT: &str = "lanspeedd:x86-client-control:v1";
const CHAIN: u32 = 0x7a1f;
// Run after the rate-monitor BPF (normal priority 0xc000), but immediately
// before the upload redirect at 0xd020.
const JUMP_PREF: u32 = 0xd01f;
const LOCAL_PREF_START: u32 = 100;
const CLIENT_PREF_START: u32 = 10_000;
const TERMINAL_PREF: u32 = 65_534;
const CONTROL_PROTOCOLS: [&str; 2] = ["ip", "ipv6"];

#[derive(Clone, Copy)]
enum Hook {
    Ingress,
    Egress,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Ownership {
    Absent,
    Owned,
    Foreign,
}

impl Hook {
    fn name(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }

    fn local_field(self) -> &'static str {
        match self {
            Self::Ingress => "dst",
            Self::Egress => "src",
        }
    }

    fn client_field(self) -> &'static str {
        match self {
            Self::Ingress => "src",
            Self::Egress => "dst",
        }
    }
}

pub(crate) fn preflight(plan: &ControlPlan) -> Result<(), String> {
    if !has_blocked_rules(&plan.rules) {
        return Ok(());
    }
    system::require_program("nft")?;
    system::require_program("conntrack")?;
    for module in ["cls_u32", "cls_matchall", "act_gact"] {
        if !system::module_available(module) {
            return Err(format!("{module}_unavailable"));
        }
    }
    ensure_nft_table_owned_or_absent()?;
    for (device, rules) in ingress_rules_by_device(plan) {
        preflight_tc_hook(device, Hook::Ingress, &plan.local_prefixes, &rules)?;
    }
    for (device, rules) in egress_rules_by_device(plan) {
        preflight_tc_hook(device, Hook::Egress, &plan.local_prefixes, &rules)?;
    }
    Ok(())
}

pub(crate) fn install(plan: &ControlPlan) -> Result<(), String> {
    if !has_blocked_rules(&plan.rules) {
        return cleanup(&control_devices(plan));
    }
    preflight(plan)?;
    let ingress = ingress_rules_by_device(plan);
    let egress = egress_rules_by_device(plan);
    for (device, rules) in &ingress {
        system::ensure_clsact(device)?;
        install_tc_hook(device, Hook::Ingress, &plan.local_prefixes, rules)?;
    }
    for (device, rules) in &egress {
        system::ensure_clsact(device)?;
        install_tc_hook(device, Hook::Egress, &plan.local_prefixes, rules)?;
    }
    for device in control_devices(plan) {
        if !ingress.contains_key(device.as_str()) {
            cleanup_tc_hook(&device, Hook::Ingress)?;
        }
        if !egress.contains_key(device.as_str()) {
            cleanup_tc_hook(&device, Hook::Egress)?;
        }
    }
    if let Err(error) = install_nft(plan) {
        let _ = cleanup(&control_devices(plan));
        return Err(error);
    }
    clear_disabled_conntrack(&plan.rules)
}

pub(crate) fn cleanup(devices: &BTreeSet<String>) -> Result<(), String> {
    let mut errors = Vec::new();
    for device in devices {
        for hook in [Hook::Ingress, Hook::Egress] {
            if let Err(error) = cleanup_tc_hook(device, hook) {
                errors.push(error);
            }
        }
    }
    if let Err(error) = cleanup_nft_table() {
        errors.push(error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(";"))
    }
}

fn preflight_tc_hook(
    device: &str,
    hook: Hook,
    local_prefixes: &[(IpAddr, u8)],
    rules: &[&ActiveRule],
) -> Result<(), String> {
    if !system::valid_interface_name(device) || !system::interface_exists(device) {
        return Err("lan_control_interface_unavailable".into());
    }
    validate_capacity(local_prefixes, rules)?;
    ensure_jump_owned_or_absent(device, hook)?;
    ensure_chain_owned_or_absent(device, hook)
}

fn install_tc_hook(
    device: &str,
    hook: Hook,
    local_prefixes: &[(IpAddr, u8)],
    rules: &[&ActiveRule],
) -> Result<(), String> {
    cleanup_tc_hook(device, hook)?;
    // Publish the ownership marker before staging any rule. If a later
    // command fails, rollback can still prove and remove the partial chain.
    let chain = CHAIN.to_string();
    let terminal = TERMINAL_PREF.to_string();
    let marker = format!("0x{CHAIN:x}");
    system::run(
        "tc",
        &[
            "filter",
            "add",
            "dev",
            device,
            hook.name(),
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
            device,
            hook,
            preference,
            *address,
            *prefix_len,
            hook.local_field(),
            "pass",
        )?;
        preference += 1;
    }
    preference = CLIENT_PREF_START;
    for rule in rules.iter().filter(|rule| rule.internet_disabled) {
        for protocol in CONTROL_PROTOCOLS {
            add_mac(
                device,
                hook,
                preference,
                protocol,
                &rule.mac.to_string(),
                hook.client_field(),
                "drop",
            )?;
            preference += 1;
        }
    }
    let jump = JUMP_PREF.to_string();
    system::run(
        "tc",
        &[
            "filter",
            "add",
            "dev",
            device,
            hook.name(),
            "protocol",
            "all",
            "pref",
            &jump,
            "matchall",
            "action",
            "goto",
            "chain",
            &chain,
        ],
    )?;
    if jump_ownership(device, hook)? == Ownership::Owned
        && chain_ownership(device, hook)? == Ownership::Owned
    {
        Ok(())
    } else {
        Err("block_filter_verification_failed".into())
    }
}

fn cleanup_tc_hook(device: &str, hook: Hook) -> Result<(), String> {
    if !system::interface_exists(device) || !system::has_qdisc(device, "clsact", None) {
        return Ok(());
    }
    let jump_state = jump_ownership(device, hook)?;
    let chain_state = chain_ownership(device, hook)?;
    if jump_state != Ownership::Owned && chain_state != Ownership::Owned {
        return Ok(());
    }
    if jump_state == Ownership::Foreign || chain_state == Ownership::Foreign {
        return Err("block_filter_owned_by_external_service".into());
    }
    let jump = JUMP_PREF.to_string();
    let chain = CHAIN.to_string();
    system::run_ignore_missing(
        "tc",
        &["filter", "del", "dev", device, hook.name(), "pref", &jump],
    );
    system::run_ignore_missing(
        "tc",
        &["filter", "del", "dev", device, hook.name(), "chain", &chain],
    );
    if jump_ownership(device, hook)? == Ownership::Owned
        || chain_ownership(device, hook)? == Ownership::Owned
    {
        Err("block_filter_cleanup_failed".into())
    } else {
        Ok(())
    }
}

fn ensure_jump_owned_or_absent(device: &str, hook: Hook) -> Result<(), String> {
    match jump_ownership(device, hook)? {
        Ownership::Absent | Ownership::Owned => Ok(()),
        Ownership::Foreign => Err("block_filter_owned_by_external_service".into()),
    }
}

fn jump_ownership(device: &str, hook: Hook) -> Result<Ownership, String> {
    let preference = JUMP_PREF.to_string();
    let output = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            device,
            hook.name(),
            "pref",
            &preference,
        ],
    )?;
    if !output.status.success() {
        return Err("block_filter_inspection_failed".into());
    }
    if output.stdout == b"[]\n" || output.stdout == b"[]" {
        return Ok(Ownership::Absent);
    }
    let values: Vec<Value> = serde_json::from_slice(&output.stdout)
        .map_err(|_| "block_filter_inspection_failed".to_owned())?;
    if values.iter().any(|value| contains_goto_chain(value, CHAIN)) {
        Ok(Ownership::Owned)
    } else {
        Ok(Ownership::Foreign)
    }
}

fn ensure_chain_owned_or_absent(device: &str, hook: Hook) -> Result<(), String> {
    match chain_ownership(device, hook)? {
        Ownership::Absent | Ownership::Owned => Ok(()),
        Ownership::Foreign => Err("block_chain_owned_by_external_service".into()),
    }
}

fn chain_ownership(device: &str, hook: Hook) -> Result<Ownership, String> {
    let chain = CHAIN.to_string();
    let output = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            device,
            hook.name(),
            "chain",
            &chain,
        ],
    )?;
    if !output.status.success() {
        return Err("block_filter_inspection_failed".into());
    }
    if output.stdout == b"[]\n" || output.stdout == b"[]" {
        return Ok(Ownership::Absent);
    }
    let values: Vec<Value> = serde_json::from_slice(&output.stdout)
        .map_err(|_| "block_filter_inspection_failed".to_owned())?;
    if values.iter().any(|value| {
        value.get("kind").and_then(Value::as_str) == Some("matchall")
            && value
                .get("options")
                .and_then(|options| options.get("handle"))
                .and_then(Value::as_u64)
                == Some(u64::from(CHAIN))
    }) {
        Ok(Ownership::Owned)
    } else {
        Ok(Ownership::Foreign)
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
    hook: Hook,
    preference: u32,
    address: IpAddr,
    prefix_len: u8,
    field: &str,
    verdict: &str,
) -> Result<(), String> {
    let chain = CHAIN.to_string();
    let preference = preference.to_string();
    let cidr = format!("{address}/{prefix_len}");
    let (protocol, family) = if address.is_ipv4() {
        ("ip", "ip")
    } else {
        ("ipv6", "ip6")
    };
    system::run(
        "tc",
        &[
            "filter",
            "add",
            "dev",
            device,
            hook.name(),
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
            "action",
            verdict,
        ],
    )
}

fn add_mac(
    device: &str,
    hook: Hook,
    preference: u32,
    protocol: &str,
    mac: &str,
    field: &str,
    verdict: &str,
) -> Result<(), String> {
    let chain = CHAIN.to_string();
    let preference = preference.to_string();
    system::run(
        "tc",
        &[
            "filter",
            "add",
            "dev",
            device,
            hook.name(),
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
            "action",
            verdict,
        ],
    )
}

fn install_nft(plan: &ControlPlan) -> Result<(), String> {
    let script = build_nft_script(plan, ensure_nft_table_owned_or_absent()?);
    system::run_script("nft", &["-f", "-"], &script)
}

fn build_nft_script(plan: &ControlPlan, table_exists: bool) -> String {
    let mut script = if table_exists {
        format!(
            "delete table inet {NFT_TABLE}\nadd table inet {NFT_TABLE} {{ comment \"{NFT_OWNER_COMMENT}\"; }}\n"
        )
    } else {
        format!("add table inet {NFT_TABLE} {{ comment \"{NFT_OWNER_COMMENT}\"; }}\n")
    };
    for (name, data_type) in [
        ("blocked4", "ipv4_addr"),
        ("blocked6", "ipv6_addr"),
        ("local4", "ipv4_addr"),
        ("local6", "ipv6_addr"),
    ] {
        script.push_str(&format!(
            "add set inet {NFT_TABLE} {name} {{ type {data_type}; flags interval; }}\n"
        ));
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
    script.push_str(&format!(
        "add chain inet {NFT_TABLE} forward {{ type filter hook forward priority mangle - 5; policy accept; }}\n\
         add rule inet {NFT_TABLE} forward fib daddr type local return\n\
         add rule inet {NFT_TABLE} forward ip saddr @local4 ip daddr @local4 return\n\
         add rule inet {NFT_TABLE} forward ip6 saddr @local6 ip6 daddr @local6 return\n\
         add rule inet {NFT_TABLE} forward ip saddr @blocked4 reject with icmp type admin-prohibited\n\
         add rule inet {NFT_TABLE} forward ip daddr @blocked4 reject with icmp type admin-prohibited\n\
         add rule inet {NFT_TABLE} forward ip6 saddr @blocked6 reject with icmpv6 type admin-prohibited\n\
         add rule inet {NFT_TABLE} forward ip6 daddr @blocked6 reject with icmpv6 type admin-prohibited\n"
    ));
    script
}

fn ensure_nft_table_owned_or_absent() -> Result<bool, String> {
    let tables = system::json_output(
        "nft",
        &["-j", "list", "tables"],
        "block_nft_inspection_failed",
    )?;
    if !nft_table_present(&tables, "inet", NFT_TABLE) {
        return Ok(false);
    }
    let table = system::json_output(
        "nft",
        &["-j", "list", "table", "inet", NFT_TABLE],
        "block_nft_inspection_failed",
    )?;
    if nft_table_owned(&table) {
        Ok(true)
    } else {
        Err("block_nft_owned_by_external_service".into())
    }
}

fn cleanup_nft_table() -> Result<(), String> {
    if ensure_nft_table_owned_or_absent()? {
        system::run("nft", &["delete", "table", "inet", NFT_TABLE])?;
    }
    Ok(())
}

fn nft_table_present(value: &Value, family: &str, name: &str) -> bool {
    match value {
        Value::Object(values) => {
            values.get("family").and_then(Value::as_str) == Some(family)
                && values.get("name").and_then(Value::as_str) == Some(name)
                || values
                    .values()
                    .any(|value| nft_table_present(value, family, name))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| nft_table_present(value, family, name)),
        _ => false,
    }
}

fn nft_table_owned(value: &Value) -> bool {
    match value {
        Value::Object(values) => {
            values.get("family").and_then(Value::as_str) == Some("inet")
                && values.get("name").and_then(Value::as_str) == Some(NFT_TABLE)
                && values.get("comment").and_then(Value::as_str) == Some(NFT_OWNER_COMMENT)
                || values.values().any(nft_table_owned)
        }
        Value::Array(values) => values.iter().any(nft_table_owned),
        _ => false,
    }
}

fn add_elements(script: &mut String, set: &str, values: &[String]) {
    if !values.is_empty() {
        script.push_str(&format!(
            "add element inet {NFT_TABLE} {set} {{ {} }}\n",
            values.join(", ")
        ));
    }
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
        .filter(|address| address.is_ipv4() == ipv4)
        .map(ToString::to_string)
        .collect()
}

fn prefixes(values: &[(IpAddr, u8)], ipv4: bool) -> Vec<String> {
    values
        .iter()
        .filter(|(address, _)| address.is_ipv4() == ipv4)
        .map(|(address, mask)| format!("{address}/{mask}"))
        .collect()
}

fn clear_disabled_conntrack(rules: &[ActiveRule]) -> Result<(), String> {
    for address in rules
        .iter()
        .filter(|rule| rule.internet_disabled)
        .flat_map(|rule| rule.ips.iter())
    {
        clear_conntrack_address(*address)?;
    }
    Ok(())
}

fn ingress_rules_by_device(plan: &ControlPlan) -> BTreeMap<&str, Vec<&ActiveRule>> {
    let mut grouped = BTreeMap::<&str, Vec<_>>::new();
    for rule in plan.rules.iter().filter(|rule| rule.internet_disabled) {
        if rule.upload_before_proxy {
            for device in &plan.dae_upload_devices {
                grouped.entry(device.as_str()).or_default().push(rule);
            }
        } else {
            grouped
                .entry(rule.interface.as_str())
                .or_default()
                .push(rule);
        }
    }
    grouped
}

fn egress_rules_by_device(plan: &ControlPlan) -> BTreeMap<&str, Vec<&ActiveRule>> {
    let mut grouped = BTreeMap::<&str, Vec<_>>::new();
    for rule in plan.rules.iter().filter(|rule| rule.internet_disabled) {
        grouped
            .entry(rule.interface.as_str())
            .or_default()
            .push(rule);
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

fn has_blocked_rules(rules: &[ActiveRule]) -> bool {
    rules.iter().any(|rule| rule.internet_disabled)
}

fn validate_capacity(local_prefixes: &[(IpAddr, u8)], rules: &[&ActiveRule]) -> Result<(), String> {
    let clients = rules.iter().filter(|rule| rule.internet_disabled).count();
    if LOCAL_PREF_START + local_prefixes.len() as u32 >= CLIENT_PREF_START
        || CLIENT_PREF_START + clients.saturating_mul(CONTROL_PROTOCOLS.len()) as u32
            >= TERMINAL_PREF
    {
        Err("control_filter_capacity".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
include!("firewall_tests.rs");
