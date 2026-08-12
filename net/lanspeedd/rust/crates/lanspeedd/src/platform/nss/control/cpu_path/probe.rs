use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::{json, Value};

use crate::{clock::monotonic_millis, control::ControlPlan};

use super::{system, Direction};

const TABLE: &str = "lanspeed_nss_cpu_probe";
const OWNER_COMMENT: &str = "lanspeedd:nss-cpu-path-probe:v1";
const UPLOAD_CHAIN: &str = "upload";
const DOWNLOAD_CHAIN: &str = "download";
const HISTORY_LIMIT: usize = 8;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProbeKey {
    interface: String,
    mac: String,
    direction: Direction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PathProbeSnapshot {
    epoch_end_ms: u64,
    read_end_ms: u64,
    table_handle: u64,
    counters: BTreeMap<ProbeKey, u64>,
}

impl PathProbeSnapshot {
    pub(crate) const fn read_end_ms(&self) -> u64 {
        self.read_end_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PathProbeDirectionWindow {
    pub(crate) bytes: u64,
    pub(crate) bps: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PathProbeWindow {
    pub(crate) upload: Option<PathProbeDirectionWindow>,
    pub(crate) download: Option<PathProbeDirectionWindow>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PathProbeBook {
    snapshots: VecDeque<PathProbeSnapshot>,
}

impl PathProbeBook {
    pub(crate) fn clear(&mut self) {
        self.snapshots.clear();
    }

    pub(crate) fn push(&mut self, snapshot: PathProbeSnapshot) {
        let invalid = self.snapshots.back().is_some_and(|previous| {
            snapshot.epoch_end_ms <= previous.epoch_end_ms
                || snapshot.table_handle != previous.table_handle
                || snapshot.counters.keys().ne(previous.counters.keys())
                || snapshot.counters.iter().any(|(key, value)| {
                    previous
                        .counters
                        .get(key)
                        .is_some_and(|previous| value < previous)
                })
        });
        if invalid {
            self.clear();
        }
        self.snapshots.push_back(snapshot);
        while self.snapshots.len() > HISTORY_LIMIT {
            self.snapshots.pop_front();
        }
    }

    pub(crate) fn window(
        &self,
        interface: &str,
        mac: &str,
        start_ms: u64,
        end_ms: u64,
    ) -> Option<PathProbeWindow> {
        let start = self
            .snapshots
            .iter()
            .find(|snapshot| snapshot.epoch_end_ms == start_ms)?;
        let end = self
            .snapshots
            .iter()
            .find(|snapshot| snapshot.epoch_end_ms == end_ms)?;
        let window_ms = end_ms.checked_sub(start_ms).filter(|value| *value != 0)?;
        let direction = |direction| {
            let key = ProbeKey {
                interface: interface.to_owned(),
                mac: mac.to_ascii_lowercase(),
                direction,
            };
            let start = start.counters.get(&key)?;
            let end = end.counters.get(&key)?;
            let bytes = end.checked_sub(*start)?;
            Some(PathProbeDirectionWindow {
                bytes,
                bps: rate(bytes, window_ms),
            })
        };
        Some(PathProbeWindow {
            upload: direction(Direction::Upload),
            download: direction(Direction::Download),
        })
    }
}

pub(super) fn preflight(plan: &ControlPlan) -> Result<(), String> {
    if !requires_probe(plan) {
        return Ok(());
    }
    system::require_program("nft")?;
    ensure_owned_or_absent()?;
    for rule in plan
        .rules
        .iter()
        .filter(|rule| rule.upload_bps != 0 || rule.download_bps != 0)
    {
        if !system::interface_exists(&rule.interface)
            || std::fs::metadata(format!("/sys/class/net/{}/brport", rule.interface)).is_err()
        {
            return Err("cpu_path_probe_interface_unavailable".into());
        }
    }
    Ok(())
}

pub(super) fn sync(plan: &ControlPlan) -> Result<(), String> {
    if !requires_probe(plan) {
        return cleanup();
    }
    let exists = ensure_owned_or_absent()?;
    if exists && verify(plan).is_ok() {
        return Ok(());
    }
    system::run_script("nft", &["-f", "-"], &build_script(plan, exists))
        .map_err(|_| "cpu_path_probe_apply_failed".to_owned())?;
    verify(plan)
}

pub(super) fn verify(plan: &ControlPlan) -> Result<(), String> {
    if !requires_probe(plan) {
        return ensure_owned_or_absent().and_then(|present| {
            (!present)
                .then_some(())
                .ok_or_else(|| "cpu_path_probe_stale".into())
        });
    }
    let value = table_json("cpu_path_probe_missing")?;
    if !table_owned(&value)
        || table_handle(&value).is_none()
        || chain_inventory(&value)
            != BTreeSet::from([UPLOAD_CHAIN.to_owned(), DOWNLOAD_CHAIN.to_owned()])
        || set_inventory(&value) != BTreeSet::from(["local4".to_owned(), "local6".to_owned()])
        || !chain_owned(&value, UPLOAD_CHAIN, "prerouting")
        || !chain_owned(&value, DOWNLOAD_CHAIN, "postrouting")
        || set_elements(&value, "local4")
            != Some(
                prefixes(&plan.local_prefixes, true)
                    .into_iter()
                    .map(normalize_host_prefix)
                    .collect(),
            )
        || set_elements(&value, "local6")
            != Some(
                prefixes(&plan.local_prefixes, false)
                    .into_iter()
                    .map(normalize_host_prefix)
                    .collect(),
            )
        || rule_fingerprints(&value) != expected_rule_fingerprints(plan)
    {
        return Err("cpu_path_probe_missing".into());
    }
    Ok(())
}

pub(super) fn snapshot(plan: &ControlPlan, epoch_end_ms: u64) -> Result<PathProbeSnapshot, String> {
    verify(plan)?;
    let value = table_json("cpu_path_probe_inspection_failed")?;
    let counters = counter_values(&value).ok_or_else(|| "cpu_path_probe_inspection_failed")?;
    Ok(PathProbeSnapshot {
        epoch_end_ms,
        read_end_ms: monotonic_millis().map_err(|_| "cpu_path_probe_inspection_failed")?,
        table_handle: table_handle(&value).ok_or_else(|| "cpu_path_probe_inspection_failed")?,
        counters,
    })
}

pub(super) fn cleanup() -> Result<(), String> {
    match ensure_owned_or_absent() {
        Ok(true) => system::run("nft", &["delete", "table", "bridge", TABLE])
            .map_err(|_| "cpu_path_probe_cleanup_failed".to_owned()),
        Ok(false) => Ok(()),
        Err(ref error) if error == "cpu_path_probe_owned_by_external_service" => Ok(()),
        Err(error) => Err(error),
    }
}

fn requires_probe(plan: &ControlPlan) -> bool {
    plan.rules
        .iter()
        .any(|rule| rule.upload_bps != 0 || rule.download_bps != 0)
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
        "add chain bridge {TABLE} {UPLOAD_CHAIN} {{ type filter hook prerouting priority -20; policy accept; }}\n\
         add chain bridge {TABLE} {DOWNLOAD_CHAIN} {{ type filter hook postrouting priority -20; policy accept; }}\n\
         add rule bridge {TABLE} {UPLOAD_CHAIN} ip daddr @local4 return\n\
         add rule bridge {TABLE} {UPLOAD_CHAIN} ip6 daddr @local6 return\n\
         add rule bridge {TABLE} {DOWNLOAD_CHAIN} ip saddr @local4 return\n\
         add rule bridge {TABLE} {DOWNLOAD_CHAIN} ip6 saddr @local6 return\n"
    ));
    for rule in &plan.rules {
        for (direction, protocol) in [
            (Direction::Upload, "ip"),
            (Direction::Upload, "ip6"),
            (Direction::Download, "ip"),
            (Direction::Download, "ip6"),
        ] {
            if direction.configured_rate(rule) == 0 {
                continue;
            }
            let (chain, interface_field, mac_field) = direction_fields(direction);
            script.push_str(&format!(
                "add rule bridge {TABLE} {chain} {interface_field} \"{}\" ether {mac_field} {} meta protocol {protocol} counter comment \"{}\"\n",
                rule.interface,
                rule.mac,
                rule_comment(direction, protocol),
            ));
        }
    }
    script
}

fn add_elements(script: &mut String, set: &str, values: &[String]) {
    if !values.is_empty() {
        script.push_str(&format!(
            "add element bridge {TABLE} {set} {{ {} }}\n",
            values.join(", ")
        ));
    }
}

fn prefixes(values: &[(std::net::IpAddr, u8)], ipv4: bool) -> Vec<String> {
    values
        .iter()
        .filter(|(address, _)| address.is_ipv4() == ipv4)
        .map(|(address, mask)| format!("{address}/{mask}"))
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

fn direction_fields(direction: Direction) -> (&'static str, &'static str, &'static str) {
    match direction {
        Direction::Upload => (UPLOAD_CHAIN, "iifname", "saddr"),
        Direction::Download => (DOWNLOAD_CHAIN, "oifname", "daddr"),
    }
}

fn rule_comment(direction: Direction, protocol: &str) -> String {
    format!("{OWNER_COMMENT}:{}:{protocol}", direction.name())
}

fn ensure_owned_or_absent() -> Result<bool, String> {
    let tables = system::json_output(
        "nft",
        &["-j", "list", "tables"],
        "cpu_path_probe_inspection_failed",
    )?;
    if !table_present(&tables) {
        return Ok(false);
    }
    let table = table_json("cpu_path_probe_inspection_failed")?;
    table_owned(&table)
        .then_some(true)
        .ok_or_else(|| "cpu_path_probe_owned_by_external_service".into())
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

fn table_handle(value: &Value) -> Option<u64> {
    walk_objects(value).find_map(|object| {
        (object.get("family").and_then(Value::as_str) == Some("bridge")
            && object.get("name").and_then(Value::as_str) == Some(TABLE)
            && object.get("comment").and_then(Value::as_str) == Some(OWNER_COMMENT))
        .then(|| object.get("handle").and_then(Value::as_u64))
        .flatten()
    })
}

fn chain_inventory(value: &Value) -> BTreeSet<String> {
    named_inventory(value, "chain")
}

fn set_inventory(value: &Value) -> BTreeSet<String> {
    named_inventory(value, "set")
}

fn named_inventory(value: &Value, kind: &str) -> BTreeSet<String> {
    value
        .get("nftables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get(kind))
        .filter(|object| object.get("family").and_then(Value::as_str) == Some("bridge"))
        .filter(|object| object.get("table").and_then(Value::as_str) == Some(TABLE))
        .filter_map(|object| object.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn chain_owned(value: &Value, name: &str, hook: &str) -> bool {
    value
        .get("nftables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("chain"))
        .filter(|chain| chain.get("name").and_then(Value::as_str) == Some(name))
        .filter(|chain| chain.get("table").and_then(Value::as_str) == Some(TABLE))
        .filter(|chain| chain.get("family").and_then(Value::as_str) == Some("bridge"))
        .filter(|chain| chain.get("type").and_then(Value::as_str) == Some("filter"))
        .filter(|chain| chain.get("hook").and_then(Value::as_str) == Some(hook))
        .filter(|chain| chain.get("prio").and_then(Value::as_i64) == Some(-20))
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
    for rule in &plan.rules {
        for (direction, protocol) in [
            (Direction::Upload, "ip"),
            (Direction::Upload, "ip6"),
            (Direction::Download, "ip"),
            (Direction::Download, "ip6"),
        ] {
            if direction.configured_rate(rule) == 0 {
                continue;
            }
            let (chain, interface_field, mac_field) = direction_fields(direction);
            values.push(
                serde_json::to_string(&json!({
                    "chain": chain,
                    "comment": rule_comment(direction, protocol),
                    "expr": [
                        {"match":{"op":"==","left":{"meta":{"key":interface_field}},"right":rule.interface}},
                        {"match":{"op":"==","left":{"payload":{"protocol":"ether","field":mac_field}},"right":rule.mac.to_string()}},
                        {"match":{"op":"==","left":{"meta":{"key":"protocol"}},"right":protocol}},
                        {"counter":null}
                    ]
                }))
                .expect("probe fingerprint is serializable"),
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
    .expect("probe fingerprint is serializable")
}

fn counter_values(value: &Value) -> Option<BTreeMap<ProbeKey, u64>> {
    let mut counters = BTreeMap::<ProbeKey, u64>::new();
    let mut protocols = BTreeSet::new();
    for rule in value
        .get("nftables")?
        .as_array()?
        .iter()
        .filter_map(|entry| entry.get("rule"))
        .filter(|rule| rule.get("table").and_then(Value::as_str) == Some(TABLE))
        .filter(|rule| rule.get("comment").is_some())
    {
        let chain = rule.get("chain")?.as_str()?;
        let direction = match chain {
            UPLOAD_CHAIN => Direction::Upload,
            DOWNLOAD_CHAIN => Direction::Download,
            _ => return None,
        };
        let expected_comment_prefix = format!("{OWNER_COMMENT}:{}:", direction.name());
        let protocol = rule
            .get("comment")?
            .as_str()?
            .strip_prefix(&expected_comment_prefix)?;
        if !matches!(protocol, "ip" | "ip6") {
            return None;
        }
        let expressions = rule.get("expr")?.as_array()?;
        let interface = match_right(expressions, "meta", direction_fields(direction).1)?;
        let mac = payload_match_right(expressions, "ether", direction_fields(direction).2)?
            .to_ascii_lowercase();
        let bytes = expressions
            .iter()
            .find_map(|expression| expression.get("counter"))?
            .get("bytes")?
            .as_u64()?;
        let key = ProbeKey {
            interface,
            mac,
            direction,
        };
        if !protocols.insert((key.clone(), protocol.to_owned())) {
            return None;
        }
        let value = counters.entry(key).or_default();
        *value = value.checked_add(bytes)?;
    }
    protocols
        .iter()
        .all(|(key, protocol)| {
            let other = if protocol == "ip" { "ip6" } else { "ip" };
            protocols.contains(&(key.clone(), other.to_owned()))
        })
        .then_some(counters)
}

fn match_right(expressions: &[Value], source: &str, key: &str) -> Option<String> {
    expressions.iter().find_map(|expression| {
        let value = expression.get("match")?;
        let left = value.get("left")?.get(source)?;
        (left.get("key").and_then(Value::as_str) == Some(key))
            .then(|| value.get("right")?.as_str().map(str::to_owned))
            .flatten()
    })
}

fn payload_match_right(expressions: &[Value], protocol: &str, field: &str) -> Option<String> {
    expressions.iter().find_map(|expression| {
        let value = expression.get("match")?;
        let left = value.get("left")?.get("payload")?;
        (left.get("protocol").and_then(Value::as_str) == Some(protocol)
            && left.get("field").and_then(Value::as_str) == Some(field))
        .then(|| value.get("right")?.as_str().map(str::to_owned))
        .flatten()
    })
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

fn rate(bytes: u64, window_ms: u64) -> u64 {
    let value = u128::from(bytes).saturating_mul(8_000) / u128::from(window_ms.max(1));
    value.min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(sample_ms: u64, handle: u64, upload: u64, download: u64) -> PathProbeSnapshot {
        PathProbeSnapshot {
            epoch_end_ms: sample_ms,
            read_end_ms: sample_ms,
            table_handle: handle,
            counters: BTreeMap::from([
                (
                    ProbeKey {
                        interface: "edge-a".into(),
                        mac: "02:00:00:00:00:01".into(),
                        direction: Direction::Upload,
                    },
                    upload,
                ),
                (
                    ProbeKey {
                        interface: "edge-a".into(),
                        mac: "02:00:00:00:00:01".into(),
                        direction: Direction::Download,
                    },
                    download,
                ),
            ]),
        }
    }

    #[test]
    fn probe_book_returns_only_exact_continuous_counter_windows() {
        let mut book = PathProbeBook::default();
        book.push(snapshot(1_000, 7, 10, 20));
        book.push(snapshot(7_000, 7, 610, 1_220));
        let window = book
            .window("edge-a", "02:00:00:00:00:01", 1_000, 7_000)
            .unwrap();
        assert_eq!(window.upload.unwrap().bytes, 600);
        assert_eq!(window.upload.unwrap().bps, 800);
        assert_eq!(window.download.unwrap().bytes, 1_200);
        assert_eq!(window.download.unwrap().bps, 1_600);
        assert!(book
            .window("edge-a", "02:00:00:00:00:01", 2_000, 7_000)
            .is_none());
    }

    #[test]
    fn probe_book_discards_table_reloads_and_counter_resets() {
        let mut book = PathProbeBook::default();
        book.push(snapshot(1_000, 7, 100, 200));
        book.push(snapshot(2_000, 8, 110, 220));
        assert_eq!(book.snapshots.len(), 1);
        book.push(snapshot(3_000, 8, 1, 2));
        assert_eq!(book.snapshots.len(), 1);
    }

    #[test]
    fn nft_counter_parser_requires_both_ip_families() {
        let value = json!({"nftables": [
            {"rule": {"table": TABLE, "chain": UPLOAD_CHAIN,
                "comment": format!("{OWNER_COMMENT}:upload:ip"),
                "expr": [
                    {"match":{"left":{"meta":{"key":"iifname"}},"right":"edge-a"}},
                    {"match":{"left":{"payload":{"protocol":"ether","field":"saddr"}},"right":"02:00:00:00:00:01"}},
                    {"counter":{"packets":1,"bytes":100}}
                ]}},
            {"rule": {"table": TABLE, "chain": UPLOAD_CHAIN,
                "comment": format!("{OWNER_COMMENT}:upload:ip6"),
                "expr": [
                    {"match":{"left":{"meta":{"key":"iifname"}},"right":"edge-a"}},
                    {"match":{"left":{"payload":{"protocol":"ether","field":"saddr"}},"right":"02:00:00:00:00:01"}},
                    {"counter":{"packets":2,"bytes":200}}
                ]}}
        ]});
        let values = counter_values(&value).unwrap();
        assert_eq!(values.values().copied().collect::<Vec<_>>(), vec![300]);
    }

    #[test]
    fn path_probe_is_nss_only_and_uses_bridge_hooks_without_a_verdict() {
        let script = build_script(
            &ControlPlan {
                lan_device: "bridge-a".into(),
                control_devices: vec!["edge-a".into()],
                dae_upload_devices: Vec::new(),
                local_prefixes: vec![("192.168.0.0".parse().unwrap(), 16)],
                rules: vec![crate::control::ActiveRule {
                    identity_key: "02:00:00:00:00:01@lan".into(),
                    mac: "02:00:00:00:00:01".parse().unwrap(),
                    interface: "edge-a".into(),
                    ips: vec!["192.168.1.2".parse().unwrap()],
                    upload_bps: 10_000_000,
                    download_bps: 20_000_000,
                    internet_disabled: false,
                    class_minor: 0x123,
                    upload_before_proxy: false,
                    upload_preempted: false,
                }],
                nss_proven_directions: BTreeMap::new(),
                nss_path_ready_directions: BTreeMap::new(),
                nss_cpu_directions: BTreeMap::new(),
                nss_active_nss_directions: BTreeMap::new(),
                nss_active_cpu_directions: BTreeMap::new(),
                conntrack_cleanup_ips: BTreeSet::new(),
            },
            false,
        );
        assert!(script.contains("hook prerouting"));
        assert!(script.contains("hook postrouting"));
        assert!(script.contains("ip daddr @local4 return"));
        assert!(script.contains("ip saddr @local4 return"));
        assert!(script.contains("counter comment"));
        assert!(!script.contains(" redirect "));
        assert!(!script.contains(" drop"));
        assert!(!script.contains(" reject"));
    }

    #[test]
    fn configured_direction_bits_match_probe_selection() {
        use crate::control::{NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD};

        assert_eq!(Direction::Upload.bit(), NSS_CPU_UPLOAD);
        assert_eq!(Direction::Download.bit(), NSS_CPU_DOWNLOAD);
    }
}
