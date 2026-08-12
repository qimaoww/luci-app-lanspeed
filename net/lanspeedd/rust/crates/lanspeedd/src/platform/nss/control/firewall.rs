use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde_json::{json, Map, Value};

use crate::control::{clear_conntrack_address, ActiveRule, ControlPlan, NSS_CPU_DOWNLOAD};

use super::{
    qdisc::{leaf_tag, Direction},
    system,
};

const TABLE: &str = "lanspeed_nss_control";
const OWNER_COMMENT: &str = "lanspeedd:nss-client-control:v2";

pub(super) fn preflight(plan: &ControlPlan) -> Result<(), String> {
    system::require_program("nft")?;
    if requires_conntrack(plan) {
        system::require_program("conntrack")?;
    }
    ensure_owned_or_absent().map(|_| ())
}

fn requires_conntrack(plan: &ControlPlan) -> bool {
    plan.rules
        .iter()
        .any(|rule| rule.internet_disabled || rule.upload_bps != 0 || rule.download_bps != 0)
        || !plan.conntrack_cleanup_ips.is_empty()
}

pub(super) fn apply(plan: &ControlPlan) -> Result<(), String> {
    if plan.rules.is_empty() {
        return cleanup();
    }
    let exists = ensure_owned_or_absent()?;
    system::run_script("nft", &["-f", "-"], &build_script(plan, exists, true))?;
    verify(plan, true)
}

pub(super) fn quiesce(plan: &ControlPlan) -> Result<(), String> {
    let exists = ensure_owned_or_absent()?;
    system::run_script("nft", &["-f", "-"], &build_script(plan, exists, false))?;
    verify(plan, false)
}

pub(super) fn clear_controlled_connections(plan: &ControlPlan) -> Result<(), String> {
    let mut addresses = plan.conntrack_cleanup_ips.clone();
    addresses.extend(
        plan.rules
            .iter()
            .filter(|rule| rule.internet_disabled || rule.upload_bps != 0 || rule.download_bps != 0)
            .flat_map(|rule| rule.ips.iter())
            .copied(),
    );
    for address in addresses {
        clear_conntrack_address(address)?;
    }
    Ok(())
}

pub(super) fn has_conntrack_identities(plan: &ControlPlan) -> bool {
    requires_conntrack(plan)
}

pub(super) fn cleanup() -> Result<(), String> {
    match ensure_owned_or_absent() {
        Ok(true) => system::run("nft", &["delete", "table", "inet", TABLE])?,
        Ok(false) => {}
        Err(ref error) if error == "nss_control_firewall_owned_by_external_service" => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn build_script(plan: &ControlPlan, exists: bool, include_shaping: bool) -> String {
    let mut script = if exists {
        format!(
            "delete table inet {TABLE}\nadd table inet {TABLE} {{ comment \"{OWNER_COMMENT}\"; }}\n"
        )
    } else {
        format!("add table inet {TABLE} {{ comment \"{OWNER_COMMENT}\"; }}\n")
    };
    for (name, data_type) in [
        ("blocked4", "ipv4_addr"),
        ("blocked6", "ipv6_addr"),
        ("local4", "ipv4_addr"),
        ("local6", "ipv6_addr"),
    ] {
        script.push_str(&format!(
            "add set inet {TABLE} {name} {{ type {data_type}; flags interval; }}\n"
        ));
    }
    for (name, key_type) in [
        ("upload4", "ipv4_addr"),
        ("upload6", "ipv6_addr"),
        ("download4", "ipv4_addr"),
        ("download6", "ipv6_addr"),
    ] {
        script.push_str(&format!(
            "add map inet {TABLE} {name} {{ type {key_type} : classid; }}\n"
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
    for (name, ipv4, direction) in [
        ("upload4", true, Direction::Upload),
        ("upload6", false, Direction::Upload),
        ("download4", true, Direction::Download),
        ("download6", false, Direction::Download),
    ] {
        if include_shaping {
            add_map_elements(&mut script, name, &class_entries(plan, ipv4, direction));
        }
    }
    script.push_str(&format!(
        "add chain inet {TABLE} forward {{ type filter hook forward priority mangle - 5; policy accept; }}\n\
         add rule inet {TABLE} forward fib daddr type local return\n\
         add rule inet {TABLE} forward ip saddr @local4 ip daddr @local4 return\n\
         add rule inet {TABLE} forward ip6 saddr @local6 ip6 daddr @local6 return\n\
         add rule inet {TABLE} forward ip saddr @blocked4 reject with icmp type admin-prohibited\n\
         add rule inet {TABLE} forward ip daddr @blocked4 reject with icmp type admin-prohibited\n\
         add rule inet {TABLE} forward ip6 saddr @blocked6 reject with icmpv6 type admin-prohibited\n\
         add rule inet {TABLE} forward ip6 daddr @blocked6 reject with icmpv6 type admin-prohibited\n\
         add rule inet {TABLE} forward meta priority set ip saddr map @upload4\n\
         add rule inet {TABLE} forward meta priority set ip6 saddr map @upload6\n\
         add rule inet {TABLE} forward meta priority set ip daddr map @download4\n\
         add rule inet {TABLE} forward meta priority set ip6 daddr map @download6\n"
    ));
    script
}

pub(super) fn verify(plan: &ControlPlan, include_shaping: bool) -> Result<(), String> {
    let value = system::json_output(
        "nft",
        &["-j", "list", "table", "inet", TABLE],
        "nss_control_firewall_failed",
    )?;
    if !table_owned(&value) || !exact_table_inventory(&value) {
        return Err("nss_control_firewall_failed".into());
    }
    let Some(chain) = named_object(&value, "forward") else {
        return Err("nss_control_firewall_failed".into());
    };
    if chain.get("family").and_then(Value::as_str) != Some("inet")
        || chain.get("table").and_then(Value::as_str) != Some(TABLE)
        || chain.get("type").and_then(Value::as_str) != Some("filter")
        || chain.get("hook").and_then(Value::as_str) != Some("forward")
        || chain.get("prio").and_then(Value::as_i64) != Some(-155)
        || chain.get("policy").and_then(Value::as_str) != Some("accept")
        || forward_rule_fingerprints(&value) != expected_forward_rule_fingerprints()
    {
        return Err("nss_control_firewall_failed".into());
    }
    for (name, data_type) in [
        ("blocked4", "ipv4_addr"),
        ("blocked6", "ipv6_addr"),
        ("local4", "ipv4_addr"),
        ("local6", "ipv6_addr"),
    ] {
        let Some(object) = named_object(&value, name) else {
            return Err("nss_control_firewall_failed".into());
        };
        if object.get("family").and_then(Value::as_str) != Some("inet")
            || object.get("table").and_then(Value::as_str) != Some(TABLE)
            || object.get("type").and_then(Value::as_str) != Some(data_type)
            || !object
                .get("flags")
                .and_then(Value::as_array)
                .is_some_and(|flags| flags.iter().any(|flag| flag == "interval"))
        {
            return Err("nss_control_firewall_failed".into());
        }
    }
    for (name, key_type) in [
        ("upload4", "ipv4_addr"),
        ("upload6", "ipv6_addr"),
        ("download4", "ipv4_addr"),
        ("download6", "ipv6_addr"),
    ] {
        let Some(object) = named_object(&value, name) else {
            return Err("nss_control_firewall_failed".into());
        };
        if object.get("family").and_then(Value::as_str) != Some("inet")
            || object.get("table").and_then(Value::as_str) != Some(TABLE)
            || object.get("type").and_then(Value::as_str) != Some(key_type)
            || object.get("map").and_then(Value::as_str) != Some("classid")
        {
            return Err("nss_control_firewall_failed".into());
        }
    }

    let blocked4 = addresses(&plan.rules, true, |rule| rule.internet_disabled)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let blocked6 = addresses(&plan.rules, false, |rule| rule.internet_disabled)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let local4 = prefixes(&plan.local_prefixes, true)
        .into_iter()
        .map(normalize_host_prefix)
        .collect::<BTreeSet<_>>();
    let local6 = prefixes(&plan.local_prefixes, false)
        .into_iter()
        .map(normalize_host_prefix)
        .collect::<BTreeSet<_>>();
    if set_elements(&value, "blocked4").as_ref() != Some(&blocked4)
        || set_elements(&value, "blocked6").as_ref() != Some(&blocked6)
        || set_elements(&value, "local4").as_ref() != Some(&local4)
        || set_elements(&value, "local6").as_ref() != Some(&local6)
    {
        return Err("nss_control_firewall_failed".into());
    }
    for (name, ipv4, direction) in [
        ("upload4", true, Direction::Upload),
        ("upload6", false, Direction::Upload),
        ("download4", true, Direction::Download),
        ("download6", false, Direction::Download),
    ] {
        let expected = if include_shaping {
            class_entries(plan, ipv4, direction)
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        } else {
            BTreeMap::new()
        };
        if map_elements(&value, name).as_ref() != Some(&expected) {
            return Err("nss_control_firewall_failed".into());
        }
    }
    Ok(())
}

fn exact_table_inventory(value: &Value) -> bool {
    let Some(entries) = value.get("nftables").and_then(Value::as_array) else {
        return false;
    };
    let mut tables = BTreeSet::new();
    let mut chains = BTreeSet::new();
    let mut sets = BTreeSet::new();
    let mut maps = BTreeSet::new();
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
        if object.get("family").and_then(Value::as_str) != Some("inet") {
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
            "chain" | "set" | "map" => {
                let Some(name) = object.get("name").and_then(Value::as_str) else {
                    return false;
                };
                match kind.as_str() {
                    "chain" => &mut chains,
                    "set" => &mut sets,
                    "map" => &mut maps,
                    _ => unreachable!(),
                }
                .insert(name.to_owned());
            }
            "rule" => rules = rules.saturating_add(1),
            _ => return false,
        }
    }
    tables == BTreeSet::from([TABLE.to_owned()])
        && chains == BTreeSet::from(["forward".to_owned()])
        && sets
            == BTreeSet::from([
                "blocked4".to_owned(),
                "blocked6".to_owned(),
                "local4".to_owned(),
                "local6".to_owned(),
            ])
        && maps
            == BTreeSet::from([
                "download4".to_owned(),
                "download6".to_owned(),
                "upload4".to_owned(),
                "upload6".to_owned(),
            ])
        && rules == 11
}

fn ensure_owned_or_absent() -> Result<bool, String> {
    let tables = system::json_output(
        "nft",
        &["-j", "list", "tables"],
        "nss_control_firewall_inspection_failed",
    )?;
    if !table_present(&tables) {
        return Ok(false);
    }
    let table = system::json_output(
        "nft",
        &["-j", "list", "table", "inet", TABLE],
        "nss_control_firewall_inspection_failed",
    )?;
    table_owned(&table)
        .then_some(true)
        .ok_or_else(|| "nss_control_firewall_owned_by_external_service".into())
}

fn table_present(value: &Value) -> bool {
    match value {
        Value::Object(values) => {
            values.get("family").and_then(Value::as_str) == Some("inet")
                && values.get("name").and_then(Value::as_str) == Some(TABLE)
                || values.values().any(table_present)
        }
        Value::Array(values) => values.iter().any(table_present),
        _ => false,
    }
}

fn table_owned(value: &Value) -> bool {
    match value {
        Value::Object(values) => {
            values.get("family").and_then(Value::as_str) == Some("inet")
                && values.get("name").and_then(Value::as_str) == Some(TABLE)
                && values.get("comment").and_then(Value::as_str) == Some(OWNER_COMMENT)
                || values.values().any(table_owned)
        }
        Value::Array(values) => values.iter().any(table_owned),
        _ => false,
    }
}

fn add_elements(script: &mut String, set: &str, values: &[String]) {
    if !values.is_empty() {
        script.push_str(&format!(
            "add element inet {TABLE} {set} {{ {} }}\n",
            values.join(", ")
        ));
    }
}

fn add_map_elements(script: &mut String, map: &str, values: &[(String, String)]) {
    if !values.is_empty() {
        script.push_str(&format!(
            "add element inet {TABLE} {map} {{ {} }}\n",
            values
                .iter()
                .map(|(address, class)| format!("{address} : {class}"))
                .collect::<Vec<_>>()
                .join(", ")
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

fn class_entries(plan: &ControlPlan, ipv4: bool, direction: Direction) -> Vec<(String, String)> {
    plan.rules
        .iter()
        .filter(|rule| nss_direction_enabled(plan, rule, direction))
        .flat_map(|rule| {
            rule.ips
                .iter()
                .filter(move |address| address.is_ipv4() == ipv4)
                .map(move |address| (address.to_string(), leaf_tag(rule.class_minor)))
        })
        .collect()
}

fn nss_direction_enabled(plan: &ControlPlan, rule: &ActiveRule, direction: Direction) -> bool {
    direction_enabled(plan, rule, direction)
}

fn direction_enabled(plan: &ControlPlan, rule: &ActiveRule, direction: Direction) -> bool {
    let bit = match direction {
        // Upload is classified before routing by the NSS IGS IFB. Publishing
        // a forward-path priority here would create a second WAN executor.
        Direction::Upload => return false,
        Direction::Download => NSS_CPU_DOWNLOAD,
    };
    direction.rate(rule) != 0 && plan.nss_direction_path_ready(&rule.identity_key, bit)
}

fn named_object<'a>(value: &'a Value, name: &str) -> Option<&'a Map<String, Value>> {
    match value {
        Value::Object(values) => {
            if values.get("name").and_then(Value::as_str) == Some(name) {
                return Some(values);
            }
            values.values().find_map(|value| named_object(value, name))
        }
        Value::Array(values) => values.iter().find_map(|value| named_object(value, name)),
        _ => None,
    }
}

fn set_elements(value: &Value, name: &str) -> Option<BTreeSet<String>> {
    let object = named_object(value, name)?;
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

fn map_elements(value: &Value, name: &str) -> Option<BTreeMap<String, String>> {
    let object = named_object(value, name)?;
    let Some(elements) = object.get("elem") else {
        return Some(BTreeMap::new());
    };
    let mut result = BTreeMap::new();
    for element in elements.as_array()? {
        let pair = element.as_array()?;
        if pair.len() != 2 {
            return None;
        }
        let key = pair[0].as_str()?.to_owned();
        let classid = pair[1].as_str()?.to_owned();
        if result.insert(key, classid).is_some() {
            return None;
        }
    }
    Some(result)
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

fn forward_rule_fingerprints(value: &Value) -> Vec<String> {
    let mut expressions = Vec::new();
    collect_forward_rule_expressions(value, &mut expressions);
    let mut fingerprints = expressions
        .into_iter()
        .filter_map(|expression| serde_json::to_string(expression).ok())
        .collect::<Vec<_>>();
    fingerprints.sort_unstable();
    fingerprints
}

fn collect_forward_rule_expressions<'a>(value: &'a Value, expressions: &mut Vec<&'a Value>) {
    match value {
        Value::Object(values) => {
            if let Some(rule) = values.get("rule").filter(|rule| {
                rule.get("table").and_then(Value::as_str) == Some(TABLE)
                    && rule.get("chain").and_then(Value::as_str) == Some("forward")
            }) {
                if let Some(expression) = rule.get("expr") {
                    expressions.push(expression);
                }
            }
            for value in values.values() {
                collect_forward_rule_expressions(value, expressions);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_forward_rule_expressions(value, expressions);
            }
        }
        _ => {}
    }
}

fn expected_forward_rule_fingerprints() -> Vec<String> {
    let mut expressions = vec![
        json!([
            {"match":{"op":"==","left":{"fib":{"result":"type","flags":["daddr"]}},"right":"local"}},
            {"return":null}
        ]),
        json!([
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@local4"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"@local4"}},
            {"return":null}
        ]),
        json!([
            {"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":"@local6"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":"@local6"}},
            {"return":null}
        ]),
    ];
    for (protocol, field, set, reject_type) in [
        ("ip", "saddr", "@blocked4", "icmp"),
        ("ip", "daddr", "@blocked4", "icmp"),
        ("ip6", "saddr", "@blocked6", "icmpv6"),
        ("ip6", "daddr", "@blocked6", "icmpv6"),
    ] {
        expressions.push(json!([
            {"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":field}},"right":set}},
            {"reject":{"type":reject_type,"expr":"admin-prohibited"}}
        ]));
    }
    for (protocol, field, map) in [
        ("ip", "saddr", "@upload4"),
        ("ip6", "saddr", "@upload6"),
        ("ip", "daddr", "@download4"),
        ("ip6", "daddr", "@download6"),
    ] {
        expressions.push(json!([{"mangle":{
            "key":{"meta":{"key":"priority"}},
            "value":{"map":{"key":{"payload":{"protocol":protocol,"field":field}},"data":map}}
        }}]));
    }
    let mut fingerprints = expressions
        .into_iter()
        .map(|expression| serde_json::to_string(&expression).unwrap())
        .collect::<Vec<_>>();
    fingerprints.sort_unstable();
    fingerprints
}

fn prefixes(values: &[(IpAddr, u8)], ipv4: bool) -> Vec<String> {
    values
        .iter()
        .filter(|(address, _)| address.is_ipv4() == ipv4)
        .map(|(address, mask)| format!("{address}/{mask}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ControlPlan {
        ControlPlan {
            lan_device: "router-lan".into(),
            control_devices: vec!["router-lan".into(), "edge-test0".into()],
            dae_upload_devices: Vec::new(),
            local_prefixes: vec![("192.0.2.0".parse().unwrap(), 24)],
            nss_proven_directions: std::collections::BTreeMap::from([(
                "02:00:00:00:00:01@lan".into(),
                NSS_CPU_DOWNLOAD,
            )]),
            nss_path_ready_directions: std::collections::BTreeMap::from([(
                "02:00:00:00:00:01@lan".into(),
                NSS_CPU_DOWNLOAD,
            )]),
            nss_cpu_directions: Default::default(),
            nss_active_nss_directions: Default::default(),
            nss_active_cpu_directions: Default::default(),
            conntrack_cleanup_ips: Default::default(),
            rules: vec![ActiveRule {
                identity_key: "02:00:00:00:00:01@lan".into(),
                mac: "02:00:00:00:00:01".parse().unwrap(),
                interface: "edge-test0".into(),
                upload_before_proxy: false,
                upload_preempted: false,
                ips: vec!["192.0.2.9".parse().unwrap()],
                upload_bps: 0,
                download_bps: 20_000_000,
                internet_disabled: true,
                class_minor: 0x7c23,
            }],
        }
    }

    #[test]
    fn one_way_limit_only_populates_its_directional_map() {
        let script = build_script(&plan(), false, true);
        assert!(script
            .contains("add element inet lanspeed_nss_control download4 { 192.0.2.9 : 7c23:0 }"));
        assert!(!script.contains("add element inet lanspeed_nss_control upload4"));
        assert!(script.contains("meta priority set ip saddr map @upload4"));
        assert!(script.contains("meta priority set ip daddr map @download4"));
    }

    #[test]
    fn cpu_path_proof_keeps_the_shared_download_nss_priority_map() {
        let mut plan = plan();
        plan.nss_cpu_directions
            .insert("02:00:00:00:00:01@lan".into(), NSS_CPU_DOWNLOAD);
        let script = build_script(&plan, false, true);
        assert!(script
            .contains("add element inet lanspeed_nss_control download4 { 192.0.2.9 : 7c23:0 }"));
        assert!(requires_conntrack(&plan));
    }

    #[test]
    fn local_bypass_precedes_block_and_classification() {
        let script = build_script(&plan(), false, true);
        assert!(
            script
                .find("ip saddr @local4 ip daddr @local4 return")
                .unwrap()
                < script.find("ip saddr @blocked4 reject").unwrap()
        );
        assert!(
            script.find("ip saddr @blocked4 reject").unwrap()
                < script
                    .find("meta priority set ip daddr map @download4")
                    .unwrap()
        );
    }

    #[test]
    fn shaping_only_plan_preflights_conntrack_before_touching_qdisc() {
        let mut plan = plan();
        plan.rules[0].internet_disabled = false;
        assert_eq!(plan.rules[0].upload_bps, 0);
        assert_ne!(plan.rules[0].download_bps, 0);
        assert!(requires_conntrack(&plan));
    }

    #[test]
    fn nft_element_parsers_preserve_exact_prefixes_and_class_pairs() {
        let value = json!({"nftables": [
            {"set": {"name": "local4", "elem": [
                {"prefix": {"addr": "192.0.2.0", "len": 24}},
                "198.51.100.9"
            ]}},
            {"map": {"name": "download4", "elem": [
                ["192.0.2.9", "7c23:0"],
                ["192.0.2.10", "7c24:0"]
            ]}}
        ]});
        assert_eq!(
            set_elements(&value, "local4").unwrap(),
            BTreeSet::from(["192.0.2.0/24".into(), "198.51.100.9".into()])
        );
        assert_eq!(
            map_elements(&value, "download4").unwrap(),
            BTreeMap::from([
                ("192.0.2.9".into(), "7c23:0".into()),
                ("192.0.2.10".into(), "7c24:0".into()),
            ])
        );
    }

    #[test]
    fn nft_forward_contract_contains_exactly_eleven_distinct_rules() {
        let expected = expected_forward_rule_fingerprints();
        assert_eq!(expected.len(), 11);
        assert_eq!(expected.iter().collect::<BTreeSet<_>>().len(), 11);
    }

    #[test]
    fn nft_table_inventory_rejects_extra_owned_table_objects() {
        let mut entries = vec![
            json!({"metainfo": {}}),
            json!({
                "table": {"family": "inet", "name": TABLE}
            }),
        ];
        for name in ["blocked4", "blocked6", "local4", "local6"] {
            entries.push(json!({"set": {"family": "inet", "table": TABLE, "name": name}}));
        }
        for name in ["download4", "download6", "upload4", "upload6"] {
            entries.push(json!({"map": {"family": "inet", "table": TABLE, "name": name}}));
        }
        entries.push(json!({
            "chain": {"family": "inet", "table": TABLE, "name": "forward"}
        }));
        for _ in 0..11 {
            entries.push(json!({"rule": {"family": "inet", "table": TABLE}}));
        }
        let mut value = json!({"nftables": entries});
        assert!(exact_table_inventory(&value));
        value["nftables"].as_array_mut().unwrap().push(json!({
            "chain": {"family": "inet", "table": TABLE, "name": "foreign"}
        }));
        assert!(!exact_table_inventory(&value));
    }
}
