use std::{collections::BTreeMap, fs, net::IpAddr};

use serde_json::Value;

use crate::control::{queue_bytes, ActiveRule, MAX_QUEUE_BYTES, X86_MAX_RATE_BPS};

use super::{ifb, system};

pub(crate) const DOWNLOAD_HANDLE: &str = "7a10:";
pub(crate) const UPLOAD_HANDLE: &str = "7a20:";
const DEFAULT_LEAF_HANDLE: &str = "1000:";
const ETHERNET_HEADER_BYTES: u64 = 14;
const MIN_QUANTUM_BYTES: u64 = 1_514;
const MAX_QUANTUM_BYTES: u64 = 60_000;
const MIN_FQ_PACKETS: u64 = 256;
const MAX_FQ_PACKETS: u64 = 65_535;
const MAX_FLOW_PACKETS: u64 = 4_096;
const LOCAL_FILTER_PREF_START: u32 = 40_000;
const CLIENT_FILTER_PREF_START: u32 = 50_000;
const FILTER_PREF_END: u32 = 65_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Upload,
    Download,
}

impl Direction {
    fn handle(self) -> &'static str {
        match self {
            Self::Upload => UPLOAD_HANDLE,
            Self::Download => DOWNLOAD_HANDLE,
        }
    }

    fn rate(self, rule: &ActiveRule) -> u64 {
        match self {
            Self::Upload => rule.upload_bps,
            Self::Download => rule.download_bps,
        }
    }

    fn address_field(self) -> &'static str {
        match self {
            Self::Upload => "src",
            Self::Download => "dst",
        }
    }
}

pub(crate) fn preflight(
    lan_device: &str,
    upload: &[&ActiveRule],
    download: &[&ActiveRule],
    local_prefixes: &[(IpAddr, u8)],
) -> Result<(), String> {
    for module in ["sch_htb", "sch_fq", "cls_u32"] {
        if !system::module_available(module) {
            return Err(format!("{module}_unavailable"));
        }
    }
    validate_filter_capacity(local_prefixes, upload, download)?;
    if !upload.is_empty() {
        ifb::preflight()?;
        if system::interface_exists(ifb::DEVICE) {
            system::ensure_owned_virtual_root(ifb::DEVICE, UPLOAD_HANDLE)?;
        }
    }
    if !download.is_empty() {
        system::ensure_replaceable_root(lan_device, DOWNLOAD_HANDLE)
            .map_err(|error| contextual_qdisc_error(error, "download_qdisc_preflight_conflict"))?;
    }
    Ok(())
}

pub(crate) fn stage_upload(rules: &[&ActiveRule]) -> Result<(), String> {
    ifb::ensure()?;
    if !ifb::owned()? {
        return Err("ifb_owned_by_external_service".into());
    }
    install_tree(ifb::DEVICE, rules, Direction::Upload)
}

pub(crate) fn stage_download(lan_device: &str, rules: &[&ActiveRule]) -> Result<(), String> {
    install_tree(lan_device, rules, Direction::Download)
}

pub(crate) fn activate_download(
    lan_device: &str,
    rules: &[&ActiveRule],
    local_prefixes: &[(IpAddr, u8)],
) -> Result<(), String> {
    install_class_filters(
        lan_device,
        DOWNLOAD_HANDLE.trim_end_matches(':'),
        rules,
        Direction::Download,
        local_prefixes,
    )?;
    verify_class_filters(lan_device, DOWNLOAD_HANDLE.trim_end_matches(':'), rules)
}

fn install_tree(device: &str, rules: &[&ActiveRule], direction: Direction) -> Result<(), String> {
    let handle = direction.handle();
    let root_operation = match direction {
        Direction::Upload => {
            system::ensure_owned_virtual_root(device, handle)?;
            // `tc qdisc replace` keeps the existing HTB classes when the
            // root kind and handle do not change.  A later `class add` then
            // fails with EEXIST while updating an active client's rate.
            // Redirection is already deactivated by the caller, so remove
            // only our verified root tree before rebuilding it.
            cleanup_owned_root(device, handle)?;
            "replace"
        }
        Direction::Download => {
            system::ensure_replaceable_root(device, handle)
                .map_err(|error| contextual_qdisc_error(error, "download_qdisc_stage_conflict"))?;
            cleanup_owned_root(device, handle)?;
            "add"
        }
    };

    let major = handle.trim_end_matches(':');
    system::run(
        "tc",
        &[
            "qdisc",
            root_operation,
            "dev",
            device,
            "root",
            "handle",
            handle,
            "htb",
            "default",
            "1",
        ],
    )?;
    let high = X86_MAX_RATE_BPS.to_string();
    let default_class = format!("{major}:1");
    let default_quantum = MAX_QUANTUM_BYTES.to_string();
    system::run(
        "tc",
        &[
            "class",
            "add",
            "dev",
            device,
            "parent",
            handle,
            "classid",
            &default_class,
            "htb",
            "rate",
            &high,
            "ceil",
            &high,
            "quantum",
            &default_quantum,
        ],
    )?;
    install_fq_leaf(device, &default_class, DEFAULT_LEAF_HANDLE, MAX_QUEUE_BYTES)?;

    let quantum = control_quantum_bytes(device);
    let quantum_text = quantum.to_string();
    for rule in rules {
        let rate = direction.rate(rule);
        let rate_text = rate.to_string();
        let classid = format!("{major}:{:x}", rule.class_minor);
        system::run(
            "tc",
            &[
                "class",
                "add",
                "dev",
                device,
                "parent",
                handle,
                "classid",
                &classid,
                "htb",
                "rate",
                &rate_text,
                "ceil",
                &rate_text,
                "quantum",
                &quantum_text,
            ],
        )?;
        let leaf_handle = format!("{:x}:", u32::from(rule.class_minor));
        let bytes = match direction {
            Direction::Upload => MAX_QUEUE_BYTES,
            Direction::Download => queue_bytes(rate),
        };
        install_fq_leaf(device, &classid, &leaf_handle, bytes)?;
    }

    if direction == Direction::Upload {
        install_class_filters(device, major, rules, direction, &[])?;
    }
    verify_tree(device, major, rules)
}

fn contextual_qdisc_error(error: String, conflict: &str) -> String {
    if error == "qdisc_owned_by_external_service" {
        conflict.into()
    } else {
        error
    }
}

fn install_fq_leaf(
    device: &str,
    parent: &str,
    handle: &str,
    queue_limit_bytes: u64,
) -> Result<(), String> {
    let quantum = control_quantum_bytes(device);
    let packets = queue_limit_bytes
        .saturating_add(quantum - 1)
        .saturating_div(quantum)
        .clamp(MIN_FQ_PACKETS, MAX_FQ_PACKETS);
    let flow_packets = packets.min(MAX_FLOW_PACKETS);
    let packets = packets.to_string();
    let flow_packets = flow_packets.to_string();
    let quantum = quantum.to_string();
    system::run(
        "tc",
        &[
            "qdisc",
            "add",
            "dev",
            device,
            "parent",
            parent,
            "handle",
            handle,
            "fq",
            "limit",
            &packets,
            "flow_limit",
            &flow_packets,
            "quantum",
            &quantum,
        ],
    )
}

fn install_class_filters(
    device: &str,
    major: &str,
    rules: &[&ActiveRule],
    direction: Direction,
    local_prefixes: &[(IpAddr, u8)],
) -> Result<(), String> {
    let parent = format!("{major}:");
    if direction == Direction::Download {
        let default_class = format!("{major}:1");
        let mut preference = LOCAL_FILTER_PREF_START;
        for (address, prefix_len) in local_prefixes {
            add_u32_filter(
                device,
                &parent,
                preference,
                *address,
                *prefix_len,
                "src",
                &default_class,
            )?;
            preference += 1;
        }
    }

    let mut preference = CLIENT_FILTER_PREF_START;
    for rule in rules {
        let classid = format!("{major}:{:x}", rule.class_minor);
        for address in &rule.ips {
            add_u32_filter(
                device,
                &parent,
                preference,
                *address,
                if address.is_ipv4() { 32 } else { 128 },
                direction.address_field(),
                &classid,
            )?;
            preference += 1;
        }
    }
    Ok(())
}

fn add_u32_filter(
    device: &str,
    parent: &str,
    preference: u32,
    address: IpAddr,
    prefix_len: u8,
    field: &str,
    flowid: &str,
) -> Result<(), String> {
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
            "parent",
            parent,
            "protocol",
            protocol,
            "pref",
            &preference,
            "u32",
            "match",
            family,
            field,
            &cidr,
            "flowid",
            flowid,
        ],
    )
}

pub(crate) fn cleanup_upload() -> Result<(), String> {
    if !system::interface_exists(ifb::DEVICE) {
        return Ok(());
    }
    if !ifb::owned()? {
        return Err("ifb_owned_by_external_service".into());
    }
    cleanup_owned_root(ifb::DEVICE, UPLOAD_HANDLE)
}

pub(crate) fn cleanup_download(lan_device: &str) -> Result<(), String> {
    cleanup_owned_root(lan_device, DOWNLOAD_HANDLE)
}

pub(crate) fn cleanup_owned_root(device: &str, handle: &str) -> Result<(), String> {
    if !system::interface_exists(device) {
        return Ok(());
    }
    if system::root_qdiscs(device)?
        .iter()
        .any(|(kind, current)| kind == "htb" && current == handle)
    {
        system::run("tc", &["qdisc", "del", "dev", device, "root"])?;
    }
    Ok(())
}

pub(crate) fn class_bytes(device: &str) -> Result<BTreeMap<String, u64>, String> {
    if !system::interface_exists(device) {
        return Ok(BTreeMap::new());
    }
    let output = system::output("tc", &["-s", "-j", "class", "show", "dev", device])?;
    if !output.status.success() {
        return Err("queue_stats_unavailable".into());
    }
    let values: Vec<Value> =
        serde_json::from_slice(&output.stdout).map_err(|_| "queue_stats_unavailable")?;
    Ok(values
        .iter()
        .filter_map(|value| {
            Some((
                value.get("handle")?.as_str()?.to_owned(),
                system::counter(value, "bytes"),
            ))
        })
        .collect())
}

pub(crate) fn queue_drops(device: &str) -> Result<BTreeMap<String, u64>, String> {
    if !system::interface_exists(device) {
        return Ok(BTreeMap::new());
    }
    let output = system::output("tc", &["-s", "-j", "qdisc", "show", "dev", device])?;
    if !output.status.success() {
        return Err("queue_stats_unavailable".into());
    }
    let values: Vec<Value> =
        serde_json::from_slice(&output.stdout).map_err(|_| "queue_stats_unavailable")?;
    Ok(values
        .iter()
        .filter_map(|value| {
            Some((
                value.get("handle")?.as_str()?.to_owned(),
                system::counter(value, "drops"),
            ))
        })
        .collect())
}

fn verify_tree(device: &str, major: &str, rules: &[&ActiveRule]) -> Result<(), String> {
    let classes = system::output("tc", &["-j", "class", "show", "dev", device])?;
    let qdiscs = system::output("tc", &["-j", "qdisc", "show", "dev", device])?;
    if !classes.status.success() || !qdiscs.status.success() {
        return Err("queue_tree_verification_failed".into());
    }
    let classes = String::from_utf8_lossy(&classes.stdout);
    let qdiscs = String::from_utf8_lossy(&qdiscs.stdout);
    if rules
        .iter()
        .all(|rule| classes.contains(&format!("{major}:{:x}", rule.class_minor)))
        && qdiscs.contains("\"kind\":\"fq\"")
    {
        Ok(())
    } else {
        Err("queue_tree_verification_failed".into())
    }
}

fn verify_class_filters(device: &str, major: &str, rules: &[&ActiveRule]) -> Result<(), String> {
    let parent = format!("{major}:");
    let output = system::output(
        "tc",
        &[
            "-j", "-d", "filter", "show", "dev", device, "parent", &parent,
        ],
    )?;
    if !output.status.success() {
        return Err("queue_filter_verification_failed".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "queue_filter_verification_failed".to_owned())?;
    if rules
        .iter()
        .all(|rule| json_contains_string(&value, &format!("{major}:{:x}", rule.class_minor)))
    {
        Ok(())
    } else {
        Err("queue_filter_verification_failed".into())
    }
}

fn json_contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values
            .iter()
            .any(|value| json_contains_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| json_contains_string(value, expected)),
        _ => false,
    }
}

fn validate_filter_capacity(
    local_prefixes: &[(IpAddr, u8)],
    upload: &[&ActiveRule],
    download: &[&ActiveRule],
) -> Result<(), String> {
    let upload_addresses = upload.iter().map(|rule| rule.ips.len()).sum::<usize>();
    let download_addresses = download.iter().map(|rule| rule.ips.len()).sum::<usize>();
    if LOCAL_FILTER_PREF_START + local_prefixes.len() as u32 >= CLIENT_FILTER_PREF_START
        || CLIENT_FILTER_PREF_START + upload_addresses.max(download_addresses) as u32
            >= FILTER_PREF_END
    {
        Err("control_filter_capacity".into())
    } else {
        Ok(())
    }
}

fn control_quantum_bytes(device: &str) -> u64 {
    let mtu = fs::read_to_string(format!("/sys/class/net/{device}/mtu"))
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok());
    control_quantum_from_mtu(mtu)
}

fn control_quantum_from_mtu(mtu: Option<u64>) -> u64 {
    mtu.unwrap_or(MIN_QUANTUM_BYTES - ETHERNET_HEADER_BYTES)
        .saturating_add(ETHERNET_HEADER_BYTES)
        .clamp(MIN_QUANTUM_BYTES, MAX_QUANTUM_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_is_one_frame_and_jumbo_safe() {
        assert_eq!(control_quantum_from_mtu(Some(1_500)), 1_514);
        assert_eq!(control_quantum_from_mtu(Some(9_000)), 9_014);
        assert_eq!(control_quantum_from_mtu(Some(u64::MAX)), 60_000);
        assert_eq!(control_quantum_from_mtu(None), 1_514);
    }

    #[test]
    fn upload_and_download_use_distinct_owned_roots() {
        assert_eq!(Direction::Upload.handle(), "7a20:");
        assert_eq!(Direction::Download.handle(), "7a10:");
    }

    #[test]
    fn filter_verification_matches_exact_classids_only() {
        let value = serde_json::json!({
            "options": { "flowid": "7a10:123" }
        });
        assert!(json_contains_string(&value, "7a10:123"));
        assert!(!json_contains_string(&value, "7a10:12"));
    }

    #[test]
    fn download_qdisc_context_does_not_hide_inspection_failures() {
        assert_eq!(
            contextual_qdisc_error(
                "qdisc_owned_by_external_service".into(),
                "download_qdisc_stage_conflict"
            ),
            "download_qdisc_stage_conflict"
        );
        assert_eq!(
            contextual_qdisc_error(
                "qdisc_inspection_invalid".into(),
                "download_qdisc_stage_conflict"
            ),
            "qdisc_inspection_invalid"
        );
    }
}
