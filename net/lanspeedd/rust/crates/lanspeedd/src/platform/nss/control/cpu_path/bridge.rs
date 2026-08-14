use std::{collections::BTreeSet, net::IpAddr};

use serde_json::{json, Value};

use crate::control::{ActiveRule, ControlPlan, NSS_CPU_DOWNLOAD};

use crate::platform::nss::control::qdisc;

use super::system;

const TABLE: &str = "lanspeed_nss_cpu_egress";
const OWNER_COMMENT: &str = "lanspeedd:nss-cpu-egress:v1";
const DOWNLOAD_CHAIN: &str = "download";

pub(super) fn preflight(plan: &ControlPlan) -> Result<(), String> {
    if !requires(plan) {
        return Ok(());
    }
    system::require_program("nft")?;
    ensure_owned_or_absent().map(|_| ())
}

pub(super) fn sync(plan: &ControlPlan) -> Result<(), String> {
    if !requires(plan) {
        return cleanup();
    }
    let exists = ensure_owned_or_absent()?;
    if exists && verify(plan).is_ok() {
        return Ok(());
    }
    system::run_script("nft", &["-f", "-"], &build_script(plan, exists))
        .map_err(|_| "cpu_egress_classifier_apply_failed".to_owned())?;
    verify(plan)
}

pub(super) fn verify(plan: &ControlPlan) -> Result<(), String> {
    if !requires(plan) {
        return ensure_owned_or_absent().and_then(|present| {
            (!present)
                .then_some(())
                .ok_or_else(|| "cpu_egress_classifier_stale".into())
        });
    }
    let value = system::json_output(
        "nft",
        &["-j", "list", "table", "bridge", TABLE],
        "cpu_egress_classifier_inspection_failed",
    )?;
    if !table_owned(&value)
        || chain_inventory(&value) != BTreeSet::from([DOWNLOAD_CHAIN.to_owned()])
        || rule_fingerprints(&value) != expected_rule_fingerprints(plan)
    {
        return Err("cpu_egress_classifier_missing".into());
    }
    Ok(())
}

pub(super) fn cleanup() -> Result<(), String> {
    match ensure_owned_or_absent() {
        Ok(true) => system::run("nft", &["delete", "table", "bridge", TABLE])
            .map_err(|_| "cpu_egress_classifier_cleanup_failed".to_owned()),
        Ok(false) => Ok(()),
        Err(ref error) if error == "cpu_egress_classifier_owned_by_external_service" => Ok(()),
        Err(error) => Err(error),
    }
}

fn requires(plan: &ControlPlan) -> bool {
    plan.rules.iter().any(|rule| {
        rule.download_bps != 0
            && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
    })
}

fn build_script(plan: &ControlPlan, exists: bool) -> String {
    let mut script = if exists {
        format!(
            "delete table bridge {TABLE}\nadd table bridge {TABLE} {{ comment \"{OWNER_COMMENT}\"; }}\n"
        )
    } else {
        format!("add table bridge {TABLE} {{ comment \"{OWNER_COMMENT}\"; }}\n")
    };
    script.push_str(&format!(
        "add set bridge {TABLE} local4 {{ type ipv4_addr; flags interval; }}\n\
         add set bridge {TABLE} local6 {{ type ipv6_addr; flags interval; }}\n"
    ));
    add_elements(&mut script, "local4", &prefixes(&plan.local_prefixes, true));
    add_elements(
        &mut script,
        "local6",
        &prefixes(&plan.local_prefixes, false),
    );
    script.push_str(&format!(
        "add chain bridge {TABLE} {DOWNLOAD_CHAIN} {{ type filter hook postrouting priority -15; policy accept; }}\n\
         add rule bridge {TABLE} {DOWNLOAD_CHAIN} ip saddr @local4 ip daddr @local4 return\n\
         add rule bridge {TABLE} {DOWNLOAD_CHAIN} ip6 saddr @local6 ip6 daddr @local6 return\n"
    ));
    for rule in download_rules(plan) {
        for address in &rule.ips {
            let (protocol, family) = if address.is_ipv4() {
                ("ip", "ip")
            } else {
                ("ip6", "ip6")
            };
            script.push_str(&format!(
                "add rule bridge {TABLE} {DOWNLOAD_CHAIN} oifname \"{}\" {protocol} daddr {} meta priority set {} counter comment \"{}:{}\"\n",
                rule.interface,
                address,
                qdisc::leaf_tag(rule.class_minor),
                OWNER_COMMENT,
                family,
            ));
        }
    }
    script
}

fn add_elements(script: &mut String, name: &str, values: &[String]) {
    if !values.is_empty() {
        script.push_str(&format!(
            "add element bridge {TABLE} {name} {{ {} }}\n",
            values.join(", ")
        ));
    }
}

fn prefixes(values: &[(IpAddr, u8)], ipv4: bool) -> Vec<String> {
    values
        .iter()
        .filter(|(address, _)| address.is_ipv4() == ipv4)
        .map(|(address, mask)| format!("{address}/{mask}"))
        .collect()
}

fn download_rules(plan: &ControlPlan) -> Vec<&ActiveRule> {
    plan.rules
        .iter()
        .filter(|rule| {
            rule.download_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
        })
        .collect()
}

fn ensure_owned_or_absent() -> Result<bool, String> {
    let tables = system::json_output(
        "nft",
        &["-j", "list", "tables"],
        "cpu_egress_classifier_inspection_failed",
    )?;
    if !table_present(&tables) {
        return Ok(false);
    }
    let table = system::json_output(
        "nft",
        &["-j", "list", "table", "bridge", TABLE],
        "cpu_egress_classifier_inspection_failed",
    )?;
    table_owned(&table)
        .then_some(true)
        .ok_or_else(|| "cpu_egress_classifier_owned_by_external_service".into())
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

fn chain_inventory(value: &Value) -> BTreeSet<String> {
    value
        .get("nftables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("chain"))
        .filter(|chain| {
            chain.get("family").and_then(Value::as_str) == Some("bridge")
                && chain.get("table").and_then(Value::as_str) == Some(TABLE)
        })
        .filter_map(|chain| chain.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn rule_fingerprints(value: &Value) -> Vec<String> {
    let mut rules = value
        .get("nftables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("rule"))
        .filter(|rule| {
            rule.get("family").and_then(Value::as_str) == Some("bridge")
                && rule.get("table").and_then(Value::as_str) == Some(TABLE)
        })
        .filter_map(rule_fingerprint)
        .collect::<Vec<_>>();
    rules.sort_unstable();
    rules
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
        serde_json::to_string(&json!({
            "chain": DOWNLOAD_CHAIN,
            "comment": Value::Null,
            "expr": [
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@local4"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"@local4"}},
                {"return":null}
            ]
        }))
        .expect("CPU egress local rule is serializable"),
        serde_json::to_string(&json!({
            "chain": DOWNLOAD_CHAIN,
            "comment": Value::Null,
            "expr": [
                {"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":"@local6"}},
                {"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":"@local6"}},
                {"return":null}
            ]
        }))
        .expect("CPU egress local IPv6 rule is serializable"),
    ];
    for rule in download_rules(plan) {
        for address in &rule.ips {
            let (protocol, family) = if address.is_ipv4() {
                ("ip", "ip")
            } else {
                ("ip6", "ip6")
            };
            values.push(
                serde_json::to_string(&json!({
                    "chain": DOWNLOAD_CHAIN,
                    "comment": format!("{OWNER_COMMENT}:{family}"),
                    "expr": [
                        {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":rule.interface}},
                        {"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":"daddr"}},"right":address.to_string()}},
                        {"mangle":{"key":{"meta":{"key":"priority"}},"value":qdisc::leaf_tag(rule.class_minor)}},
                        {"counter":null}
                    ]
                }))
                .expect("CPU egress rule is serializable"),
            );
        }
    }
    values.sort_unstable();
    values
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
    use std::collections::BTreeMap;

    use super::*;

    fn plan() -> ControlPlan {
        ControlPlan {
            lan_device: "br-lan".into(),
            control_devices: vec!["lan2".into()],
            dae_upload_devices: Vec::new(),
            local_prefixes: vec![("192.168.0.0".parse().unwrap(), 16)],
            rules: vec![ActiveRule {
                identity_key: "30:c5:99:a7:bb:2d@lan".into(),
                mac: "30:c5:99:a7:bb:2d".parse().unwrap(),
                interface: "lan2".into(),
                upload_before_proxy: false,
                upload_preempted: false,
                ips: vec!["192.168.2.11".parse().unwrap()],
                upload_bps: 10_000_000,
                download_bps: 100_000_000,
                internet_disabled: false,
                class_minor: 0x7cf7,
            }],
            nss: crate::control::nss_state::NssControlPlan {
                nss_path_ready_directions: BTreeMap::new(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn egress_script_has_local_bypass_and_client_class() {
        let mut plan = plan();
        plan.nss_path_ready_directions
            .insert("30:c5:99:a7:bb:2d@lan".into(), NSS_CPU_DOWNLOAD);
        let script = build_script(&plan, false);
        assert!(script.contains("hook postrouting priority -15"));
        assert!(script.contains("ip saddr @local4 ip daddr @local4 return"));
        assert!(script.contains("oifname \"lan2\" ip daddr 192.168.2.11"));
        assert!(script.contains("meta priority set 7cf7:0"));
    }

    #[test]
    fn egress_script_maps_both_ip_families_to_one_client_class() {
        let mut plan = plan();
        plan.rules[0].ips.push("2001:db8::11".parse().unwrap());
        plan.nss_path_ready_directions
            .insert("30:c5:99:a7:bb:2d@lan".into(), NSS_CPU_DOWNLOAD);
        let script = build_script(&plan, false);
        assert!(script.contains("ip daddr 192.168.2.11 meta priority set 7cf7:0"));
        assert!(script.contains("ip6 daddr 2001:db8::11 meta priority set 7cf7:0"));
        assert_eq!(script.matches("meta priority set 7cf7:0").count(), 2);
    }
}
