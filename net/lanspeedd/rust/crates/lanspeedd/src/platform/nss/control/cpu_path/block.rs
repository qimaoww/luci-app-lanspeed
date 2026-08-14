use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::control::ControlPlan;

use super::{system, Direction};

const TABLE: &str = "lanspeed_nss_cpu_block";
const OWNER_COMMENT: &str = "lanspeedd:nss-cpu-path-block:v1";
const UPLOAD_CHAIN: &str = "upload";
const DOWNLOAD_CHAIN: &str = "download";

pub(super) fn preflight(plan: &ControlPlan) -> Result<(), String> {
    if !requires_block(plan) {
        return Ok(());
    }
    system::require_program("nft")?;
    ensure_owned_or_absent()?;
    for rule in plan.rules.iter().filter(|rule| rule.internet_disabled) {
        if !system::interface_exists(&rule.interface)
            || std::fs::metadata(format!("/sys/class/net/{}/brport", rule.interface)).is_err()
        {
            return Err("cpu_path_block_interface_unavailable".into());
        }
    }
    Ok(())
}

pub(super) fn sync(plan: &ControlPlan) -> Result<(), String> {
    if !requires_block(plan) {
        return cleanup();
    }
    let exists = ensure_owned_or_absent()?;
    if exists && verify(plan).is_ok() {
        return Ok(());
    }
    system::run_script("nft", &["-f", "-"], &build_script(plan, exists))
        .map_err(|_| "cpu_path_block_apply_failed".to_owned())?;
    verify(plan)
}

pub(super) fn verify(plan: &ControlPlan) -> Result<(), String> {
    if !requires_block(plan) {
        return ensure_owned_or_absent().and_then(|present| {
            (!present)
                .then_some(())
                .ok_or_else(|| "cpu_path_block_stale".into())
        });
    }
    let value = table_json("cpu_path_block_missing")?;
    let expected_rules = expected_rule_fingerprints(plan);
    if !table_owned(&value)
        || !exact_inventory(&value, expected_rules.len())
        || !chain_owned(&value, UPLOAD_CHAIN, "prerouting")
        || !chain_owned(&value, DOWNLOAD_CHAIN, "postrouting")
        || set_elements(&value, "local4") != Some(expected_prefixes(plan, true))
        || set_elements(&value, "local6") != Some(expected_prefixes(plan, false))
        || set_elements(&value, "blocked4") != Some(blocked_addresses(plan, true))
        || set_elements(&value, "blocked6") != Some(blocked_addresses(plan, false))
        || rule_fingerprints(&value) != expected_rules
    {
        return Err("cpu_path_block_missing".into());
    }
    Ok(())
}

pub(super) fn cleanup() -> Result<(), String> {
    match ensure_owned_or_absent() {
        Ok(true) => system::run("nft", &["delete", "table", "bridge", TABLE])
            .map_err(|_| "cpu_path_block_cleanup_failed".to_owned()),
        Ok(false) => Ok(()),
        Err(ref error) if error == "cpu_path_block_owned_by_external_service" => Ok(()),
        Err(error) => Err(error),
    }
}

fn requires_block(plan: &ControlPlan) -> bool {
    plan.rules.iter().any(|rule| rule.internet_disabled)
}

fn build_script(plan: &ControlPlan, exists: bool) -> String {
    let mut script = if exists {
        format!(
            "delete table bridge {TABLE}\nadd table bridge {TABLE} {{ comment \"{OWNER_COMMENT}\"; }}\n"
        )
    } else {
        format!("add table bridge {TABLE} {{ comment \"{OWNER_COMMENT}\"; }}\n")
    };
    for (name, data_type) in [
        ("local4", "ipv4_addr"),
        ("local6", "ipv6_addr"),
        ("blocked4", "ipv4_addr"),
        ("blocked6", "ipv6_addr"),
    ] {
        script.push_str(&format!(
            "add set bridge {TABLE} {name} {{ type {data_type}; flags interval; }}\n"
        ));
    }
    add_elements(
        &mut script,
        "local4",
        expected_prefixes(plan, true).into_iter(),
    );
    add_elements(
        &mut script,
        "local6",
        expected_prefixes(plan, false).into_iter(),
    );
    add_elements(
        &mut script,
        "blocked4",
        blocked_addresses(plan, true).into_iter(),
    );
    add_elements(
        &mut script,
        "blocked6",
        blocked_addresses(plan, false).into_iter(),
    );
    script.push_str(&format!(
        "add chain bridge {TABLE} {UPLOAD_CHAIN} {{ type filter hook prerouting priority -30; policy accept; }}\n\
         add chain bridge {TABLE} {DOWNLOAD_CHAIN} {{ type filter hook postrouting priority -30; policy accept; }}\n\
         add rule bridge {TABLE} {UPLOAD_CHAIN} ip daddr @local4 return\n\
         add rule bridge {TABLE} {UPLOAD_CHAIN} ip6 daddr @local6 return\n\
         add rule bridge {TABLE} {DOWNLOAD_CHAIN} ip saddr @local4 return\n\
         add rule bridge {TABLE} {DOWNLOAD_CHAIN} ip6 saddr @local6 return\n"
    ));
    for rule in plan.rules.iter().filter(|rule| rule.internet_disabled) {
        for (direction, protocol, address_set) in [
            (Direction::Upload, "ip", "@blocked4"),
            (Direction::Upload, "ip6", "@blocked6"),
            (Direction::Download, "ip", "@blocked4"),
            (Direction::Download, "ip6", "@blocked6"),
        ] {
            let (chain, interface_field, mac_field, address_field) = direction_fields(direction);
            script.push_str(&format!(
                "add rule bridge {TABLE} {chain} {interface_field} \"{}\" ether {mac_field} {} meta protocol {protocol} {protocol} {address_field} {address_set} counter drop comment \"{}\"\n",
                rule.interface,
                rule.mac,
                rule_comment(direction, protocol),
            ));
        }
    }
    script
}

fn add_elements(script: &mut String, set: &str, values: impl Iterator<Item = String>) {
    let values = values.collect::<Vec<_>>();
    if !values.is_empty() {
        script.push_str(&format!(
            "add element bridge {TABLE} {set} {{ {} }}\n",
            values.join(", ")
        ));
    }
}

fn expected_prefixes(plan: &ControlPlan, ipv4: bool) -> BTreeSet<String> {
    plan.local_prefixes
        .iter()
        .filter(|(address, _)| address.is_ipv4() == ipv4)
        .map(|(address, mask)| normalize_host_prefix(format!("{address}/{mask}")))
        .collect()
}

fn blocked_addresses(plan: &ControlPlan, ipv4: bool) -> BTreeSet<String> {
    plan.rules
        .iter()
        .filter(|rule| rule.internet_disabled)
        .flat_map(|rule| rule.ips.iter())
        .filter(|address| address.is_ipv4() == ipv4)
        .map(ToString::to_string)
        .collect()
}

fn normalize_host_prefix(value: String) -> String {
    if let Some((address, mask)) = value.rsplit_once('/') {
        let host_mask = if address.contains(':') { "128" } else { "32" };
        if mask == host_mask {
            return address.to_owned();
        }
    }
    value
}

fn direction_fields(
    direction: Direction,
) -> (&'static str, &'static str, &'static str, &'static str) {
    match direction {
        Direction::Upload => (UPLOAD_CHAIN, "iifname", "saddr", "saddr"),
        Direction::Download => (DOWNLOAD_CHAIN, "oifname", "daddr", "daddr"),
    }
}

fn rule_comment(direction: Direction, protocol: &str) -> String {
    format!("{OWNER_COMMENT}:{}:{protocol}", direction.name())
}

fn ensure_owned_or_absent() -> Result<bool, String> {
    let tables = system::json_output(
        "nft",
        &["-j", "list", "tables"],
        "cpu_path_block_inspection_failed",
    )?;
    if !table_present(&tables) {
        return Ok(false);
    }
    let table = table_json("cpu_path_block_inspection_failed")?;
    table_owned(&table)
        .then_some(true)
        .ok_or_else(|| "cpu_path_block_owned_by_external_service".into())
}

fn table_json(reason: &str) -> Result<Value, String> {
    system::json_output("nft", &["-j", "list", "table", "bridge", TABLE], reason)
}

fn table_present(value: &Value) -> bool {
    walk_objects(value).any(|object| {
        object.get("family").and_then(Value::as_str) == Some("bridge")
            && object.get("name").and_then(Value::as_str) == Some(TABLE)
    })
}

fn table_owned(value: &Value) -> bool {
    walk_objects(value).any(|object| {
        object.get("family").and_then(Value::as_str) == Some("bridge")
            && object.get("name").and_then(Value::as_str) == Some(TABLE)
            && object.get("comment").and_then(Value::as_str) == Some(OWNER_COMMENT)
    })
}

fn exact_inventory(value: &Value, expected_rules: usize) -> bool {
    let Some(entries) = value.get("nftables").and_then(Value::as_array) else {
        return false;
    };
    let mut tables = BTreeSet::new();
    let mut chains = BTreeSet::new();
    let mut sets = BTreeSet::new();
    let mut rules = 0usize;
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            return false;
        };
        if entry.len() != 1 {
            return false;
        }
        if entry.contains_key("metainfo") {
            continue;
        }
        let Some((kind, object)) = entry.iter().next() else {
            return false;
        };
        let Some(object) = object.as_object() else {
            return false;
        };
        if object.get("family").and_then(Value::as_str) != Some("bridge") {
            return false;
        }
        if kind == "table" {
            let Some(name) = object.get("name").and_then(Value::as_str) else {
                return false;
            };
            tables.insert(name.to_owned());
            continue;
        }
        if object.get("table").and_then(Value::as_str) != Some(TABLE) {
            return false;
        }
        match kind.as_str() {
            "chain" | "set" => {
                let Some(name) = object.get("name").and_then(Value::as_str) else {
                    return false;
                };
                if kind == "chain" {
                    chains.insert(name.to_owned());
                } else {
                    sets.insert(name.to_owned());
                }
            }
            "rule" => rules = rules.saturating_add(1),
            _ => return false,
        }
    }
    tables == BTreeSet::from([TABLE.to_owned()])
        && chains == BTreeSet::from([UPLOAD_CHAIN.to_owned(), DOWNLOAD_CHAIN.to_owned()])
        && sets
            == BTreeSet::from([
                "local4".to_owned(),
                "local6".to_owned(),
                "blocked4".to_owned(),
                "blocked6".to_owned(),
            ])
        && rules == expected_rules
}

fn chain_owned(value: &Value, name: &str, hook: &str) -> bool {
    value
        .get("nftables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("chain"))
        .filter(|chain| chain.get("family").and_then(Value::as_str) == Some("bridge"))
        .filter(|chain| chain.get("table").and_then(Value::as_str) == Some(TABLE))
        .filter(|chain| chain.get("name").and_then(Value::as_str) == Some(name))
        .filter(|chain| chain.get("type").and_then(Value::as_str) == Some("filter"))
        .filter(|chain| chain.get("hook").and_then(Value::as_str) == Some(hook))
        .filter(|chain| chain.get("prio").and_then(Value::as_i64) == Some(-30))
        .filter(|chain| chain.get("policy").and_then(Value::as_str) == Some("accept"))
        .count()
        == 1
}

fn set_elements(value: &Value, name: &str) -> Option<BTreeSet<String>> {
    let object = value
        .get("nftables")?
        .as_array()?
        .iter()
        .filter_map(|entry| entry.get("set"))
        .find(|set| {
            set.get("family").and_then(Value::as_str) == Some("bridge")
                && set.get("table").and_then(Value::as_str) == Some(TABLE)
                && set.get("name").and_then(Value::as_str) == Some(name)
        })?;
    if object
        .get("flags")
        .and_then(Value::as_array)
        .is_none_or(|flags| !flags.iter().any(|flag| flag.as_str() == Some("interval")))
    {
        return None;
    }
    let Some(elements) = object.get("elem") else {
        return Some(BTreeSet::new());
    };
    elements.as_array()?.iter().map(nft_set_element).collect()
}

fn nft_set_element(value: &Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        return Some(value.to_owned());
    }
    let prefix = value.get("prefix")?;
    Some(format!(
        "{}/{}",
        prefix.get("addr")?.as_str()?,
        prefix.get("len")?.as_u64()?
    ))
}

fn rule_fingerprints(value: &Value) -> Vec<String> {
    let mut values = value
        .get("nftables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("rule"))
        .filter(|rule| rule.get("family").and_then(Value::as_str) == Some("bridge"))
        .filter(|rule| rule.get("table").and_then(Value::as_str) == Some(TABLE))
        .filter_map(rule_fingerprint)
        .collect::<Vec<_>>();
    values.sort_unstable();
    values
}

fn rule_fingerprint(rule: &Value) -> Option<String> {
    let mut expressions = rule.get("expr")?.clone();
    for expression in expressions.as_array_mut()? {
        if expression.get("counter").is_some() {
            *expression = json!({"counter": null});
        }
    }
    serde_json::to_string(&json!({
        "chain": rule.get("chain")?.as_str()?,
        "comment": rule.get("comment").and_then(Value::as_str),
        "expr": expressions,
    }))
    .ok()
}

fn expected_rule_fingerprints(plan: &ControlPlan) -> Vec<String> {
    let mut values = vec![
        expected_local_rule(UPLOAD_CHAIN, "ip", "daddr", "@local4"),
        expected_local_rule(UPLOAD_CHAIN, "ip6", "daddr", "@local6"),
        expected_local_rule(DOWNLOAD_CHAIN, "ip", "saddr", "@local4"),
        expected_local_rule(DOWNLOAD_CHAIN, "ip6", "saddr", "@local6"),
    ];
    for rule in plan.rules.iter().filter(|rule| rule.internet_disabled) {
        for (direction, protocol, address_set) in [
            (Direction::Upload, "ip", "@blocked4"),
            (Direction::Upload, "ip6", "@blocked6"),
            (Direction::Download, "ip", "@blocked4"),
            (Direction::Download, "ip6", "@blocked6"),
        ] {
            let (chain, interface_field, mac_field, address_field) = direction_fields(direction);
            values.push(
                serde_json::to_string(&json!({
                    "chain": chain,
                    "comment": rule_comment(direction, protocol),
                    "expr": [
                        {"match":{"op":"==","left":{"meta":{"key":interface_field}},"right":rule.interface}},
                        {"match":{"op":"==","left":{"payload":{"protocol":"ether","field":mac_field}},"right":rule.mac.to_string()}},
                        {"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":address_field}},"right":address_set}},
                        {"counter":null},
                        {"drop":null}
                    ]
                }))
                .expect("block fingerprint is serializable"),
            );
        }
    }
    values.sort_unstable();
    values
}

fn expected_local_rule(chain: &str, protocol: &str, field: &str, set: &str) -> String {
    serde_json::to_string(&json!({
        "chain": chain,
        "comment": Value::Null,
        "expr": [
            {"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":field}},"right":set}},
            {"return":null}
        ]
    }))
    .expect("block fingerprint is serializable")
}

fn walk_objects(value: &Value) -> Box<dyn Iterator<Item = &serde_json::Map<String, Value>> + '_> {
    match value {
        Value::Object(object) => Box::new(
            std::iter::once(object).chain(object.values().flat_map(|value| walk_objects(value))),
        ),
        Value::Array(values) => Box::new(values.iter().flat_map(|value| walk_objects(value))),
        _ => Box::new(std::iter::empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(disabled: bool) -> ControlPlan {
        ControlPlan {
            lan_device: "bridge-a".into(),
            control_devices: vec!["edge-a".into()],
            dae_upload_devices: Vec::new(),
            local_prefixes: vec![
                ("192.168.0.0".parse().unwrap(), 16),
                ("fd00::".parse().unwrap(), 8),
            ],
            rules: vec![crate::control::ActiveRule {
                identity_key: "02:00:00:00:00:01@lan".into(),
                mac: "02:00:00:00:00:01".parse().unwrap(),
                interface: "edge-a".into(),
                ips: vec![
                    "192.168.1.2".parse().unwrap(),
                    "2001:db8::2".parse().unwrap(),
                ],
                upload_bps: 10_000_000,
                download_bps: 20_000_000,
                internet_disabled: disabled,
                class_minor: 0x123,
                upload_before_proxy: false,
                upload_preempted: false,
            }],
            nss: crate::control::nss_state::NssControlPlan::default(),
        }
    }

    #[test]
    fn bridge_block_covers_both_sides_of_transparent_proxy_and_keeps_local_first() {
        let script = build_script(&plan(true), false);
        assert!(script.contains("hook prerouting priority -30"));
        assert!(script.contains("hook postrouting priority -30"));
        assert!(script.contains("iifname \"edge-a\" ether saddr 02:00:00:00:00:01"));
        assert!(script.contains("oifname \"edge-a\" ether daddr 02:00:00:00:00:01"));
        assert!(script.contains("meta protocol ip ip saddr @blocked4 counter drop"));
        assert!(script.contains("meta protocol ip6 ip6 daddr @blocked6 counter drop"));
        assert!(
            script.find("ip daddr @local4 return").unwrap() < script.find("counter drop").unwrap()
        );
        assert!(
            script.find("ip saddr @local4 return").unwrap() < script.find("counter drop").unwrap()
        );
        assert!(!script.contains(" reject"));
        assert!(!script.contains(" redirect"));
        assert!(!script.contains(" limit"));
        assert!(!script.contains("classid"));
    }

    #[test]
    fn block_is_absent_without_an_enabled_client() {
        assert!(!requires_block(&plan(false)));
    }

    #[test]
    fn verifier_accepts_nft_normalized_ip_match_without_redundant_meta_protocol() {
        let rule = json!({
            "chain": UPLOAD_CHAIN,
            "comment": rule_comment(Direction::Upload, "ip"),
            "expr": [
                {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"edge-a"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"ether","field":"saddr"}},"right":"02:00:00:00:00:01"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@blocked4"}},
                {"counter":{"packets":8,"bytes":540}},
                {"drop":null}
            ]
        });
        let fingerprint = rule_fingerprint(&rule).unwrap();
        assert!(expected_rule_fingerprints(&plan(true)).contains(&fingerprint));
    }
}
