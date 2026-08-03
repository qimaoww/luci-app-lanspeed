use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    process::{Command, Stdio},
};

use serde_json::Value;

use crate::control::{
    clear_conntrack_address, queue_bytes, queue_drops_increased, ActiveRule, ApplyResult,
    ControlPlan, X86_MAX_RATE_BPS,
};

const DOWNLOAD_HANDLE: &str = "7a10:";
const UPLOAD_HANDLE: &str = "7a20:";
const CONTROL_INET_TABLE: &str = "lanspeed_control";
const CONTROL_NETDEV_TABLE: &str = "lanspeed_control_io";
const LOCAL_FILTER_PREF_START: u32 = 40_000;
const CLIENT_FILTER_PREF_START: u32 = 50_000;
const FILTER_PREF_END: u32 = 65_000;
const ETHERNET_HEADER_BYTES: u64 = 14;
const MIN_CONTROL_QUANTUM_BYTES: u64 = 1_514;
const MAX_CONTROL_QUANTUM_BYTES: u64 = 60_000;
const UPLOAD_QUEUE_WINDOW_SECONDS: u64 = 4;
const UPLOAD_MARK_MASK: u32 = 0x00ff_0000;
const UPLOAD_MARK_SHIFT: u32 = 16;

pub fn apply(plan: &ControlPlan) -> Result<ApplyResult, String> {
    if plan.rules.is_empty() {
        cleanup(&plan.lan_device)?;
        return Ok(probe(&plan.lan_device));
    }
    if !valid_interface_name(&plan.lan_device) {
        return Err("lan_control_interface_unavailable".into());
    }
    require_program("nft")?;
    let shaping = plan
        .rules
        .iter()
        .any(|rule| rule.upload_bps != 0 || rule.download_bps != 0);
    if shaping {
        require_program("tc")?;
        require_htb()?;
    }
    if plan.rules.iter().any(|rule| rule.internet_disabled) {
        require_program("conntrack")?;
    }
    if plan.rules.iter().any(|rule| {
        (rule.upload_bps != 0 || rule.download_bps != 0 || rule.internet_disabled)
            && rule.ips.is_empty()
    }) {
        return Err("identity_address_unavailable".into());
    }

    let upload = plan
        .rules
        .iter()
        .filter(|rule| rule.upload_bps != 0)
        .collect::<Vec<_>>();
    let download = plan
        .rules
        .iter()
        .filter(|rule| rule.download_bps != 0)
        .collect::<Vec<_>>();
    validate_download_filter_capacity(&plan.local_prefixes, &download)?;
    let wan = if upload.is_empty() {
        Vec::new()
    } else {
        nft_ingress_supported(&plan.lan_device)?;
        wan_devices(&plan.lan_device)?
    };

    preflight_upload(&wan)?;
    if !download.is_empty() {
        ensure_replaceable_root(&plan.lan_device, DOWNLOAD_HANDLE)?;
    }

    let stage_result = (|| {
        if upload.is_empty() {
            cleanup_upload()?;
        } else {
            stage_upload(&wan, &upload)?;
        }
        if download.is_empty() {
            cleanup_owned_root(&plan.lan_device, DOWNLOAD_HANDLE)
        } else {
            stage_download(&plan.lan_device, &download, &plan.local_prefixes)
        }
    })();
    if let Err(error) = stage_result {
        let _ = delete_nft_tables();
        let _ = cleanup_owned_root(&plan.lan_device, DOWNLOAD_HANDLE);
        let _ = cleanup_upload();
        return Err(error);
    }

    if let Err(error) = install_nft(plan) {
        let _ = delete_nft_tables();
        let _ = cleanup_owned_root(&plan.lan_device, DOWNLOAD_HANDLE);
        let _ = cleanup_upload();
        return Err(error);
    }
    if let Err(error) = clear_disabled_conntrack(&plan.rules) {
        let _ = delete_nft_tables();
        let _ = cleanup_owned_root(&plan.lan_device, DOWNLOAD_HANDLE);
        let _ = cleanup_upload();
        return Err(error);
    }
    let capability = probe(&plan.lan_device);
    let queue_drop_counters = queue_drop_snapshot(&wan, &plan.lan_device);
    Ok(ApplyResult {
        state: if plan.rules.is_empty() {
            "inactive"
        } else {
            "applied"
        }
        .into(),
        reason: (!shaping).then_some(capability.reason).flatten(),
        shaping_supported: shaping || capability.shaping_supported,
        blocking_supported: true,
        queue_overflow: false,
        queue_drop_counters,
        class_counter_baselines: Default::default(),
        verified_directions: Default::default(),
    })
}

fn probe(lan_device: &str) -> ApplyResult {
    let missing = ["tc", "nft"]
        .into_iter()
        .find(|program| !crate::probe::commands::command_available(program));
    let shaping_reason = missing
        .map(|program| format!("missing_{program}"))
        .or_else(|| (!htb_available()).then(|| "htb_qdisc_unavailable".to_owned()))
        .or_else(|| {
            (!interface_exists(lan_device)).then(|| "lan_control_interface_unavailable".to_owned())
        })
        .or_else(|| {
            nft_ingress_supported(lan_device)
                .err()
                .map(|_| "nft_ingress_hook_unavailable".to_owned())
        })
        .or_else(|| {
            ensure_replaceable_root(lan_device, DOWNLOAD_HANDLE)
                .err()
                .map(|_| "qdisc_owned_by_external_service".to_owned())
        })
        .or_else(|| {
            wan_devices(lan_device)
                .and_then(|wan| preflight_upload(&wan))
                .err()
        });
    let blocking_supported = crate::probe::commands::command_available("nft")
        && crate::probe::commands::command_available("conntrack");
    ApplyResult {
        state: "inactive".into(),
        shaping_supported: shaping_reason.is_none(),
        reason: shaping_reason
            .or_else(|| (!blocking_supported).then(|| "conntrack_control_unavailable".into())),
        blocking_supported,
        queue_overflow: false,
        queue_drop_counters: Default::default(),
        class_counter_baselines: Default::default(),
        verified_directions: Default::default(),
    }
}

pub fn cleanup(lan_device: &str) -> Result<(), String> {
    let _ = delete_nft_tables();
    let download = cleanup_owned_root(lan_device, DOWNLOAD_HANDLE);
    let upload = cleanup_upload();
    match (download, upload) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(download), Err(upload)) => Err(format!("{download};{upload}")),
    }
}

pub fn observe(plan: &ControlPlan, previous: &ApplyResult) -> ApplyResult {
    let mut next = previous.clone();
    let upload_active = plan.rules.iter().any(|rule| rule.upload_bps != 0);
    let wan = if upload_active {
        wan_devices(&plan.lan_device).unwrap_or_default()
    } else {
        Vec::new()
    };
    let current = queue_drop_snapshot(&wan, &plan.lan_device);
    let previous_uploads = previous
        .queue_drop_counters
        .keys()
        .filter(|key| key.starts_with("upload:"))
        .cloned()
        .collect::<BTreeSet<_>>();
    let current_uploads = current
        .keys()
        .filter(|key| key.starts_with("upload:"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if upload_active && previous_uploads != current_uploads {
        next.queue_drop_counters = current;
        next.state = "pending".into();
        next.reason = Some("control_topology_changed".into());
        return next;
    }
    let increased = queue_drops_increased(&previous.queue_drop_counters, &current);
    next.queue_drop_counters = current;
    if increased {
        next.queue_overflow = true;
        next.state = "error".into();
        next.reason = Some("queue_overflow".into());
    }
    next
}

pub fn max_rate_bps() -> u64 {
    fs::read_dir("/sys/class/net")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("device").exists())
        .filter_map(|entry| fs::read_to_string(entry.path().join("speed")).ok())
        .filter_map(|speed| speed.trim().parse::<u64>().ok())
        .filter(|speed| *speed > 0 && *speed <= 100_000)
        .filter_map(|speed| speed.checked_mul(1_000_000))
        .max()
        .unwrap_or(X86_MAX_RATE_BPS)
        .min(X86_MAX_RATE_BPS)
}

fn preflight_upload(devices: &[String]) -> Result<(), String> {
    for device in devices {
        ensure_replaceable_root(device, UPLOAD_HANDLE)?;
    }
    Ok(())
}

fn stage_upload(devices: &[String], rules: &[&ActiveRule]) -> Result<(), String> {
    cleanup_upload_except(devices)?;
    for device in devices {
        ensure_replaceable_root(device, UPLOAD_HANDLE)?;
        install_linux_tree(device, UPLOAD_HANDLE, rules, true, &[])?;
    }
    Ok(())
}

fn stage_download(
    device: &str,
    rules: &[&ActiveRule],
    local_prefixes: &[(std::net::IpAddr, u8)],
) -> Result<(), String> {
    ensure_replaceable_root(device, DOWNLOAD_HANDLE)?;
    install_linux_tree(device, DOWNLOAD_HANDLE, rules, false, local_prefixes)
}

fn install_linux_tree(
    device: &str,
    handle: &str,
    rules: &[&ActiveRule],
    upload: bool,
    local_prefixes: &[(std::net::IpAddr, u8)],
) -> Result<(), String> {
    let major = handle.trim_end_matches(':');
    let quantum = control_quantum_bytes(device);
    let owned = root_qdiscs(device)?
        .iter()
        .any(|(kind, current)| kind == "htb" && current == handle);
    if !owned || !linux_tree_matches(device, handle, major, rules, upload, quantum) {
        if owned {
            run("tc", &["qdisc", "del", "dev", device, "root"])?;
        }
        run(
            "tc",
            &[
                "qdisc", "add", "dev", device, "root", "handle", handle, "htb", "default", "1",
            ],
        )?;
        let high = X86_MAX_RATE_BPS.to_string();
        let root = format!("{major}:1");
        run(
            "tc",
            &[
                "class", "replace", "dev", device, "parent", handle, "classid", &root, "htb",
                "rate", &high, "ceil", &high,
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
                &root,
                "handle",
                "1000:",
                "bfifo",
                "limit",
                &crate::control::MAX_QUEUE_BYTES.to_string(),
            ],
        )?;
        let quantum = quantum.to_string();
        for rule in rules {
            let rate = if upload {
                rule.upload_bps
            } else {
                rule.download_bps
            };
            let rate = rate.to_string();
            let classid = format!("{major}:{:x}", rule.class_minor);
            run(
                "tc",
                &[
                    "class", "replace", "dev", device, "parent", handle, "classid", &classid,
                    "htb", "rate", &rate, "ceil", &rate, "quantum", &quantum,
                ],
            )?;
            let leaf_handle = format!("{:x}:", u32::from(rule.class_minor));
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
                    &leaf_handle,
                    "bfifo",
                    "limit",
                    &x86_queue_bytes(rate.parse().unwrap_or(0), upload).to_string(),
                ],
            )?;
        }
    }
    clear_owned_filters(device, handle)?;
    if upload {
        install_upload_filters(device, major, rules)?;
    } else {
        install_download_filters(device, major, rules, local_prefixes)?;
    }
    verify_classes(device, major, rules)
}

fn linux_tree_matches(
    device: &str,
    handle: &str,
    major: &str,
    rules: &[&ActiveRule],
    upload: bool,
    quantum: u64,
) -> bool {
    let classes = Command::new("tc")
        .args(["-j", "-d", "class", "show", "dev", device])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| serde_json::from_slice::<Vec<Value>>(&output.stdout).ok());
    let qdiscs = Command::new("tc")
        .args(["-j", "-d", "qdisc", "show", "dev", device])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| serde_json::from_slice::<Vec<Value>>(&output.stdout).ok());
    classes.zip(qdiscs).is_some_and(|(classes, qdiscs)| {
        linux_tree_values_match(&classes, &qdiscs, handle, major, rules, upload, quantum)
    })
}

fn linux_tree_values_match(
    classes: &[Value],
    qdiscs: &[Value],
    handle: &str,
    major: &str,
    rules: &[&ActiveRule],
    upload: bool,
    quantum: u64,
) -> bool {
    let root_class = format!("{major}:1");
    let mut expected_classes = BTreeSet::from([root_class.clone()]);
    expected_classes.extend(
        rules
            .iter()
            .map(|rule| format!("{major}:{:x}", rule.class_minor)),
    );
    let actual_classes = classes
        .iter()
        .filter(|value| {
            value
                .get("class")
                .or_else(|| value.get("kind"))
                .and_then(Value::as_str)
                == Some("htb")
        })
        .filter_map(|value| {
            value
                .get("handle")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    if actual_classes != expected_classes {
        return false;
    }
    let Some(default) = classes
        .iter()
        .find(|value| value.get("handle").and_then(Value::as_str) == Some(root_class.as_str()))
    else {
        return false;
    };
    if default.get("rate").and_then(Value::as_u64) != Some(X86_MAX_RATE_BPS / 8)
        || default.get("ceil").and_then(Value::as_u64) != Some(X86_MAX_RATE_BPS / 8)
    {
        return false;
    }
    for rule in rules {
        let classid = format!("{major}:{:x}", rule.class_minor);
        let Some(value) = classes
            .iter()
            .find(|value| value.get("handle").and_then(Value::as_str) == Some(classid.as_str()))
        else {
            return false;
        };
        let rate = if upload {
            rule.upload_bps
        } else {
            rule.download_bps
        } / 8;
        if value.get("rate").and_then(Value::as_u64) != Some(rate)
            || value.get("ceil").and_then(Value::as_u64) != Some(rate)
            || value.get("quantum").and_then(Value::as_u64) != Some(quantum)
        {
            return false;
        }
    }
    if !qdiscs.iter().any(|value| {
        value.get("kind").and_then(Value::as_str) == Some("htb")
            && value.get("handle").and_then(Value::as_str) == Some(handle)
            && value.get("root").and_then(Value::as_bool) == Some(true)
    }) {
        return false;
    }
    let mut expected_leaves = BTreeMap::from([(
        root_class,
        ("1000:".to_owned(), crate::control::MAX_QUEUE_BYTES),
    )]);
    expected_leaves.extend(rules.iter().map(|rule| {
        let classid = format!("{major}:{:x}", rule.class_minor);
        let leaf = format!("{:x}:", u32::from(rule.class_minor));
        let rate = if upload {
            rule.upload_bps
        } else {
            rule.download_bps
        };
        (classid, (leaf, x86_queue_bytes(rate, upload)))
    }));
    let actual_leaves = qdiscs
        .iter()
        .filter(|value| value.get("kind").and_then(Value::as_str) == Some("bfifo"))
        .filter_map(|value| {
            let parent = value.get("parent").and_then(Value::as_str)?;
            if !parent.starts_with(&format!("{major}:")) {
                return None;
            }
            Some((
                parent.to_owned(),
                (
                    value.get("handle").and_then(Value::as_str)?.to_owned(),
                    value
                        .get("options")
                        .and_then(|options| options.get("limit"))
                        .and_then(Value::as_u64)?,
                ),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    actual_leaves == expected_leaves
}

fn clear_owned_filters(device: &str, parent: &str) -> Result<(), String> {
    let output = Command::new("tc")
        .args(["-j", "filter", "show", "dev", device, "parent", parent])
        .output()
        .map_err(|_| "control_filter_verification_failed")?;
    if !output.status.success() {
        return Err("control_filter_verification_failed".into());
    }
    let filters: Vec<Value> =
        serde_json::from_slice(&output.stdout).map_err(|_| "control_filter_verification_failed")?;
    if filters.is_empty() {
        Ok(())
    } else {
        run("tc", &["filter", "del", "dev", device, "parent", parent])
    }
}

fn control_quantum_bytes(device: &str) -> u64 {
    let mtu = fs::read_to_string(format!("/sys/class/net/{device}/mtu"))
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok());
    control_quantum_from_mtu(mtu)
}

fn x86_queue_bytes(rate_bps: u64, upload: bool) -> u64 {
    if upload {
        rate_bps
            .saturating_mul(UPLOAD_QUEUE_WINDOW_SECONDS)
            .saturating_div(8)
            .clamp(
                crate::control::MIN_QUEUE_BYTES,
                crate::control::MAX_QUEUE_BYTES,
            )
    } else {
        queue_bytes(rate_bps)
    }
}

fn control_quantum_from_mtu(mtu: Option<u64>) -> u64 {
    mtu.unwrap_or(MIN_CONTROL_QUANTUM_BYTES - ETHERNET_HEADER_BYTES)
        .saturating_add(ETHERNET_HEADER_BYTES)
        .clamp(MIN_CONTROL_QUANTUM_BYTES, MAX_CONTROL_QUANTUM_BYTES)
}

fn validate_download_filter_capacity(
    local_prefixes: &[(std::net::IpAddr, u8)],
    rules: &[&ActiveRule],
) -> Result<(), String> {
    let client_addresses = rules.iter().map(|rule| rule.ips.len()).sum::<usize>();
    if LOCAL_FILTER_PREF_START + local_prefixes.len() as u32 >= CLIENT_FILTER_PREF_START
        || CLIENT_FILTER_PREF_START + client_addresses as u32 >= FILTER_PREF_END
    {
        Err("control_filter_capacity".into())
    } else {
        Ok(())
    }
}

fn upload_mark(index: usize) -> u32 {
    ((index + 1) as u32) << UPLOAD_MARK_SHIFT
}

fn install_upload_filters(device: &str, major: &str, rules: &[&ActiveRule]) -> Result<(), String> {
    let parent = format!("{major}:");
    for (index, rule) in rules.iter().enumerate() {
        let preference = CLIENT_FILTER_PREF_START + index as u32;
        let classid = format!("{major}:{:x}", rule.class_minor);
        add_mark_filter(device, &parent, preference, upload_mark(index), &classid)?;
    }
    verify_client_filters(device, &parent, major, rules)
}

fn add_mark_filter(
    device: &str,
    parent: &str,
    preference: u32,
    mark: u32,
    flowid: &str,
) -> Result<(), String> {
    let preference = preference.to_string();
    let mark = format!("0x{mark:08x}");
    let mask = format!("0x{UPLOAD_MARK_MASK:08x}");
    run(
        "tc",
        &[
            "filter",
            "add",
            "dev",
            device,
            "parent",
            parent,
            "protocol",
            "all",
            "pref",
            &preference,
            "u32",
            "match",
            "mark",
            &mark,
            &mask,
            "flowid",
            flowid,
        ],
    )
}

fn install_download_filters(
    device: &str,
    major: &str,
    rules: &[&ActiveRule],
    local_prefixes: &[(std::net::IpAddr, u8)],
) -> Result<(), String> {
    let parent = format!("{major}:");
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
    preference = CLIENT_FILTER_PREF_START;
    for rule in rules {
        let classid = format!("{major}:{:x}", rule.class_minor);
        for address in &rule.ips {
            add_u32_filter(
                device,
                &parent,
                preference,
                *address,
                if address.is_ipv4() { 32 } else { 128 },
                "dst",
                &classid,
            )?;
            preference += 1;
        }
    }
    verify_client_filters(device, &parent, major, rules)
}

fn add_u32_filter(
    device: &str,
    parent: &str,
    preference: u32,
    address: std::net::IpAddr,
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
    run(
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

fn verify_client_filters(
    device: &str,
    parent: &str,
    major: &str,
    rules: &[&ActiveRule],
) -> Result<(), String> {
    let output = Command::new("tc")
        .args(["-j", "filter", "show", "dev", device, "parent", parent])
        .output()
        .map_err(|_| "control_filter_verification_failed")?;
    if !output.status.success() {
        return Err("control_filter_verification_failed".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if rules
        .iter()
        .all(|rule| text.contains(&format!("{major}:{:x}", rule.class_minor)))
    {
        Ok(())
    } else {
        Err("control_filter_verification_failed".into())
    }
}

fn install_nft(plan: &ControlPlan) -> Result<(), String> {
    let inet_exists = table_exists("inet", CONTROL_INET_TABLE);
    let netdev_exists = table_exists("netdev", CONTROL_NETDEV_TABLE);
    run_script(
        "nft",
        &["-f", "-"],
        &build_nft_script(plan, inet_exists, netdev_exists),
    )
}

fn table_exists(family: &str, table: &str) -> bool {
    Command::new("nft")
        .args(["list", "table", family, table])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn build_nft_script(plan: &ControlPlan, inet_exists: bool, netdev_exists: bool) -> String {
    let mut script = if inet_exists {
        format!("delete table inet {CONTROL_INET_TABLE}\nadd table inet {CONTROL_INET_TABLE}\n")
    } else {
        format!("add table inet {CONTROL_INET_TABLE}\n")
    };
    if netdev_exists {
        script.push_str(&format!("delete table netdev {CONTROL_NETDEV_TABLE}\n"));
    }
    script.push_str(&format!(
        "add set inet {CONTROL_INET_TABLE} blocked4 {{ type ipv4_addr; }}\n"
    ));
    script.push_str(&format!(
        "add set inet {CONTROL_INET_TABLE} blocked6 {{ type ipv6_addr; }}\n"
    ));
    script.push_str(&format!(
        "add set inet {CONTROL_INET_TABLE} local4 {{ type ipv4_addr; flags interval; }}\n"
    ));
    script.push_str(&format!(
        "add set inet {CONTROL_INET_TABLE} local6 {{ type ipv6_addr; flags interval; }}\n"
    ));
    let blocked4 = addresses(&plan.rules, true, |rule| rule.internet_disabled);
    let blocked6 = addresses(&plan.rules, false, |rule| rule.internet_disabled);
    let local4 = prefixes(&plan.local_prefixes, true);
    let local6 = prefixes(&plan.local_prefixes, false);
    add_elements(
        &mut script,
        &format!("inet {CONTROL_INET_TABLE}"),
        "blocked4",
        &blocked4,
    );
    add_elements(
        &mut script,
        &format!("inet {CONTROL_INET_TABLE}"),
        "blocked6",
        &blocked6,
    );
    add_elements(
        &mut script,
        &format!("inet {CONTROL_INET_TABLE}"),
        "local4",
        &local4,
    );
    add_elements(
        &mut script,
        &format!("inet {CONTROL_INET_TABLE}"),
        "local6",
        &local6,
    );
    script.push_str(&format!(
        "add chain inet {CONTROL_INET_TABLE} forward {{ type filter hook forward priority mangle - 5; policy accept; }}\n\
         add rule inet {CONTROL_INET_TABLE} forward fib daddr type local return\n\
         add rule inet {CONTROL_INET_TABLE} forward ip saddr @local4 ip daddr @local4 return\n\
         add rule inet {CONTROL_INET_TABLE} forward ip6 saddr @local6 ip6 daddr @local6 return\n\
         add rule inet {CONTROL_INET_TABLE} forward ip saddr @blocked4 reject with icmp type admin-prohibited\n\
         add rule inet {CONTROL_INET_TABLE} forward ip daddr @blocked4 reject with icmp type admin-prohibited\n\
         add rule inet {CONTROL_INET_TABLE} forward ip6 saddr @blocked6 reject with icmpv6 type admin-prohibited\n\
         add rule inet {CONTROL_INET_TABLE} forward ip6 daddr @blocked6 reject with icmpv6 type admin-prohibited\n"
    ));
    if plan.rules.iter().any(|rule| rule.upload_bps != 0) {
        script.push_str(&format!(
            "add table netdev {CONTROL_NETDEV_TABLE}\n\
             add set netdev {CONTROL_NETDEV_TABLE} local4 {{ type ipv4_addr; flags interval; }}\n\
             add set netdev {CONTROL_NETDEV_TABLE} local6 {{ type ipv6_addr; flags interval; }}\n"
        ));
        add_elements(
            &mut script,
            &format!("netdev {CONTROL_NETDEV_TABLE}"),
            "local4",
            &local4,
        );
        add_elements(
            &mut script,
            &format!("netdev {CONTROL_NETDEV_TABLE}"),
            "local6",
            &local6,
        );
        script.push_str(&format!(
            "add chain netdev {CONTROL_NETDEV_TABLE} upload_ingress {{ type filter hook ingress device \"{}\" priority filter - 5; policy accept; }}\n\
             add rule netdev {CONTROL_NETDEV_TABLE} upload_ingress ip daddr @local4 return\n\
             add rule netdev {CONTROL_NETDEV_TABLE} upload_ingress ip6 daddr @local6 return\n",
            plan.lan_device
        ));
        append_upload_mark_rules(&mut script, &plan.rules);
    }
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

fn append_upload_mark_rules(script: &mut String, rules: &[ActiveRule]) {
    for (index, rule) in rules.iter().filter(|rule| rule.upload_bps != 0).enumerate() {
        let mark = upload_mark(index);
        for address in &rule.ips {
            let family = if address.is_ipv4() { "ip" } else { "ip6" };
            script.push_str(&format!(
                "add rule netdev {CONTROL_NETDEV_TABLE} upload_ingress meta mark 0 {family} saddr {address} meta mark set 0x{mark:08x}\n"
            ));
        }
    }
}

fn add_elements(script: &mut String, table: &str, set: &str, values: &[String]) {
    if !values.is_empty() {
        script.push_str(&format!(
            "add element {table} {set} {{ {} }}\n",
            values.join(", ")
        ));
    }
}

fn clear_disabled_conntrack(rules: &[ActiveRule]) -> Result<(), String> {
    let addresses = rules
        .iter()
        .filter(|rule| rule.internet_disabled)
        .flat_map(|rule| rule.ips.iter())
        .copied()
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Ok(());
    }
    if !crate::probe::commands::command_available("conntrack") {
        return Err("missing_conntrack".into());
    }
    for ip in addresses {
        clear_conntrack_address(ip)?;
    }
    Ok(())
}

fn ensure_replaceable_root(device: &str, owned_handle: &str) -> Result<(), String> {
    let qdiscs = qdiscs(device)?;
    let roots = root_qdiscs_from(&qdiscs);
    if !roots.is_empty()
        && (roots
            .iter()
            .all(|(kind, handle)| kind == "noqueue" || (kind == "htb" && handle == owned_handle))
            || system_mq_tree(&qdiscs, owned_handle))
    {
        Ok(())
    } else {
        Err("qdisc_owned_by_external_service".into())
    }
}

fn root_qdiscs(device: &str) -> Result<Vec<(String, String)>, String> {
    qdiscs(device).map(|values| root_qdiscs_from(&values))
}

fn qdiscs(device: &str) -> Result<Vec<Value>, String> {
    let output = Command::new("tc")
        .args(["-j", "qdisc", "show", "dev", device])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("qdisc_inspection_failed".into());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "qdisc_inspection_invalid".into())
}

fn root_qdiscs_from(values: &[Value]) -> Vec<(String, String)> {
    values
        .iter()
        .filter(|value| value.get("root").and_then(Value::as_bool) == Some(true))
        .map(|value| {
            (
                value
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                value
                    .get("handle")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            )
        })
        .collect()
}

fn system_mq_tree(values: &[Value], owned_handle: &str) -> bool {
    values.iter().any(|value| {
        value.get("root").and_then(Value::as_bool) == Some(true)
            && value.get("kind").and_then(Value::as_str) == Some("mq")
    }) && values.iter().all(|value| {
        matches!(
            value.get("kind").and_then(Value::as_str).unwrap_or(""),
            "mq" | "fq" | "fq_codel" | "clsact" | "ingress"
        ) && value.get("handle").and_then(Value::as_str) != Some(owned_handle)
    })
}

fn verify_classes(device: &str, major: &str, rules: &[&ActiveRule]) -> Result<(), String> {
    let output = Command::new("tc")
        .args(["-j", "class", "show", "dev", device])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("queue_tree_verification_failed".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if rules
        .iter()
        .all(|rule| text.contains(&format!("{major}:{:x}", rule.class_minor)))
    {
        Ok(())
    } else {
        Err("queue_tree_verification_failed".into())
    }
}

fn queue_drop_snapshot(wan_devices: &[String], lan_device: &str) -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    if let Ok(count) = queue_drop_count(lan_device, DOWNLOAD_HANDLE) {
        counters.insert("download".into(), count);
    }
    for device in wan_devices {
        if let Ok(count) = queue_drop_count(device, UPLOAD_HANDLE) {
            counters.insert(format!("upload:{device}"), count);
        }
    }
    counters
}

fn queue_drop_count(device: &str, root_handle: &str) -> Result<u64, String> {
    if !interface_exists(device) {
        return Ok(0);
    }
    let output = Command::new("tc")
        .args(["-s", "-j", "qdisc", "show", "dev", device])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("queue_stats_unavailable".into());
    }
    let values: Vec<Value> =
        serde_json::from_slice(&output.stdout).map_err(|_| "queue_stats_unavailable".to_owned())?;
    Ok(values
        .iter()
        .filter(|value| value.get("handle").and_then(Value::as_str) != Some(root_handle))
        .map(|value| counter(value, "drops"))
        .sum())
}

fn counter(value: &Value, name: &str) -> u64 {
    value
        .get(name)
        .and_then(Value::as_u64)
        .or_else(|| {
            value
                .get("stats")
                .and_then(|stats| stats.get(name))
                .and_then(Value::as_u64)
        })
        .or_else(|| {
            value
                .get("stats2")
                .and_then(|stats| stats.get(name))
                .and_then(Value::as_u64)
        })
        .unwrap_or(0)
}

fn cleanup_upload() -> Result<(), String> {
    cleanup_upload_except(&[])
}

fn cleanup_upload_except(keep: &[String]) -> Result<(), String> {
    let keep = keep.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let entries = fs::read_dir("/sys/class/net").map_err(|_| "wan_status_unavailable")?;
    for entry in entries.flatten() {
        let Some(device) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if keep.contains(device.as_str()) || !valid_interface_name(&device) {
            continue;
        }
        let Ok(roots) = root_qdiscs(&device) else {
            continue;
        };
        if roots
            .iter()
            .any(|(kind, handle)| kind == "htb" && handle == UPLOAD_HANDLE)
        {
            run("tc", &["qdisc", "del", "dev", &device, "root"])?;
        }
    }
    Ok(())
}

fn cleanup_owned_root(device: &str, handle: &str) -> Result<(), String> {
    if !interface_exists(device) {
        return Ok(());
    }
    if root_qdiscs(device)?
        .iter()
        .any(|(kind, current)| kind == "htb" && current == handle)
    {
        run("tc", &["qdisc", "del", "dev", device, "root"])?;
    }
    Ok(())
}

fn delete_nft_tables() -> Result<(), String> {
    let inet = run("nft", &["delete", "table", "inet", CONTROL_INET_TABLE]);
    let netdev = run("nft", &["delete", "table", "netdev", CONTROL_NETDEV_TABLE]);
    match (inet, netdev) {
        (Ok(()), _) | (_, Ok(())) => Ok(()),
        (Err(inet), Err(netdev)) => Err(format!("{inet};{netdev}")),
    }
}

fn interface_exists(device: &str) -> bool {
    fs::metadata(format!("/sys/class/net/{device}")).is_ok()
}

fn wan_devices(lan_device: &str) -> Result<Vec<String>, String> {
    let output = Command::new("ubus")
        .args(["call", "network.interface", "dump"])
        .output()
        .map_err(|_| "wan_status_unavailable")?;
    if !output.status.success() {
        return Err("wan_status_unavailable".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| "wan_status_invalid")?;
    let devices = wan_devices_from(&value, lan_device)
        .into_iter()
        .filter(|device| interface_exists(device))
        .collect::<Vec<_>>();
    if devices.is_empty() {
        Err("wan_device_unavailable".into())
    } else {
        Ok(devices)
    }
}

fn wan_devices_from(value: &Value, lan_device: &str) -> Vec<String> {
    value
        .get("interface")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|interface| interface.get("up").and_then(Value::as_bool) == Some(true))
        .filter(|interface| {
            interface
                .get("route")
                .and_then(Value::as_array)
                .is_some_and(|routes| routes.iter().any(default_route))
        })
        .filter_map(|interface| {
            interface
                .get("l3_device")
                .or_else(|| interface.get("device"))
                .and_then(Value::as_str)
        })
        .filter(|device| *device != lan_device && valid_interface_name(device))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn default_route(route: &Value) -> bool {
    let mask_is_default = route.get("mask").and_then(Value::as_u64) == Some(0);
    let target_is_default = matches!(
        route.get("target").and_then(Value::as_str),
        Some("0.0.0.0" | "::" | "0:0:0:0:0:0:0:0")
    );
    mask_is_default && target_is_default
}

fn nft_ingress_supported(lan_device: &str) -> Result<(), String> {
    let script = format!(
        "add table netdev lanspeed_control_probe\n\
         add chain netdev lanspeed_control_probe ingress {{ type filter hook ingress device \"{lan_device}\" priority filter - 5; policy accept; }}\n\
         delete table netdev lanspeed_control_probe\n"
    );
    run_script("nft", &["-c", "-f", "-"], &script)
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn require_htb() -> Result<(), String> {
    htb_available()
        .then_some(())
        .ok_or_else(|| "htb_qdisc_unavailable".to_owned())
}

fn htb_available() -> bool {
    fs::metadata("/sys/module/sch_htb").is_ok()
        || fs::read_dir("/lib/modules")
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .any(|version| {
                fs::read_dir(version.path())
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
                    .any(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with("sch_htb.ko")
                    })
            })
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
    fn nft_rules_bypass_only_lan_to_lan_and_block_both_directions() {
        let script = build_nft_script(&plan(), false, false);
        let bypass = script
            .find("ip saddr @local4 ip daddr @local4 return")
            .unwrap();
        let block = script.find("ip saddr @blocked4 reject").unwrap();
        assert!(bypass < block);
        assert!(script.contains("ip daddr @blocked4 reject"));
        assert!(script.contains("ip6 daddr @blocked6 reject"));
        assert!(script.contains("add table netdev lanspeed_control_io"));
        assert!(script.contains("hook ingress device \"br-lan\" priority filter - 5"));
        assert!(script.contains("meta mark 0 ip saddr 192.0.2.9 meta mark set 0x00010000"));
        assert!(script.contains("meta mark 0 ip6 saddr 2001:db8::9 meta mark set 0x00010000"));
        assert!(!script.contains("meta priority set"));
        for forbidden in [" police ", " blackhole ", " fq_codel ", " drop\n"] {
            assert!(!script.contains(forbidden));
        }
    }

    #[test]
    fn wan_discovery_deduplicates_dual_stack_default_routes_and_excludes_lan() {
        let value = serde_json::json!({
            "interface": [
                { "up": true, "l3_device": "br-lan", "route": [
                    { "target": "0.0.0.0", "mask": 0 }
                ] },
                { "up": true, "l3_device": "pppoe-wan", "route": [
                    { "target": "0.0.0.0", "mask": 0 }
                ] },
                { "up": true, "l3_device": "pppoe-wan", "route": [
                    { "target": "::", "mask": 0 }
                ] },
                { "up": true, "l3_device": "pppoe-wan_cmcc", "route": [
                    { "target": "::", "mask": 0 }
                ] },
                { "up": false, "l3_device": "pppoe-down", "route": [
                    { "target": "0.0.0.0", "mask": 0 }
                ] }
            ]
        });
        assert_eq!(
            wan_devices_from(&value, "br-lan"),
            vec!["pppoe-wan".to_owned(), "pppoe-wan_cmcc".to_owned()]
        );
    }

    #[test]
    fn nft_interface_names_are_restricted_before_script_generation() {
        assert!(valid_interface_name("br-lan"));
        assert!(valid_interface_name("pppoe-wan_cmcc"));
        assert!(!valid_interface_name("br-lan\";flush"));
        assert!(!valid_interface_name("bad/interface"));
    }

    #[test]
    fn controlled_class_quantum_is_one_frame_and_jumbo_safe() {
        assert_eq!(control_quantum_from_mtu(Some(1_500)), 1_514);
        assert_eq!(control_quantum_from_mtu(Some(1_492)), 1_514);
        assert_eq!(control_quantum_from_mtu(Some(9_000)), 9_014);
        assert_eq!(control_quantum_from_mtu(Some(u64::MAX)), 60_000);
        assert_eq!(control_quantum_from_mtu(None), 1_514);
    }

    #[test]
    fn matching_owned_tree_is_reused_without_resetting_queue_counters() {
        let plan = plan();
        let rules = plan.rules.iter().collect::<Vec<_>>();
        let classes = vec![
            serde_json::json!({
                "class": "htb", "handle": "7a20:123",
                "rate": 1_250_000, "ceil": 1_250_000, "quantum": 1_514
            }),
            serde_json::json!({
                "class": "htb", "handle": "7a20:1",
                "rate": 12_500_000_000u64, "ceil": 12_500_000_000u64
            }),
        ];
        let qdiscs = vec![
            serde_json::json!({ "kind": "htb", "handle": "7a20:", "root": true }),
            serde_json::json!({
                "kind": "bfifo", "handle": "123:", "parent": "7a20:123",
                "options": { "limit": 5_000_000 }
            }),
            serde_json::json!({
                "kind": "bfifo", "handle": "1000:", "parent": "7a20:1",
                "options": { "limit": crate::control::MAX_QUEUE_BYTES }
            }),
            serde_json::json!({ "kind": "clsact", "handle": "ffff:" }),
        ];

        assert!(linux_tree_values_match(
            &classes,
            &qdiscs,
            UPLOAD_HANDLE,
            "7a20",
            &rules,
            true,
            1_514,
        ));
        let mut changed = classes.clone();
        changed[0]["rate"] = serde_json::json!(1_000_000);
        assert!(!linux_tree_values_match(
            &changed,
            &qdiscs,
            UPLOAD_HANDLE,
            "7a20",
            &rules,
            true,
            1_514,
        ));
    }

    #[test]
    fn upload_marks_use_a_bounded_byte() {
        assert_eq!(UPLOAD_MARK_MASK, 0x00ff_0000);
        assert_eq!(upload_mark(0), 0x0001_0000);
        assert_eq!(
            upload_mark(crate::control::MAX_CONTROL_RULES - 1),
            0x0040_0000
        );
    }

    #[test]
    fn upload_queue_absorbs_startup_bursts_without_changing_download_policy() {
        assert_eq!(x86_queue_bytes(10_000_000, true), 5_000_000);
        assert_eq!(x86_queue_bytes(10_000_000, false), 625_000);
        assert_eq!(
            x86_queue_bytes(100_000_000, true),
            crate::control::MAX_QUEUE_BYTES
        );
    }

    #[test]
    fn qdisc_json_reads_top_level_drops_and_rejects_foreign_mq_leaves() {
        let stats = serde_json::json!({ "drops": 2 });
        assert_eq!(counter(&stats, "drops"), 2);
        let default = vec![
            serde_json::json!({ "kind": "mq", "handle": "0:", "root": true }),
            serde_json::json!({ "kind": "fq_codel", "handle": "0:", "parent": ":1" }),
        ];
        assert!(system_mq_tree(&default, DOWNLOAD_HANDLE));
        let foreign = vec![
            serde_json::json!({ "kind": "mq", "handle": "0:", "root": true }),
            serde_json::json!({ "kind": "cake", "handle": "8001:", "parent": ":1" }),
        ];
        assert!(!system_mq_tree(&foreign, DOWNLOAD_HANDLE));
        let handle_collision =
            vec![serde_json::json!({ "kind": "cake", "handle": DOWNLOAD_HANDLE, "root": true })];
        assert!(!root_qdiscs_from(&handle_collision)
            .iter()
            .all(
                |(kind, handle)| kind == "noqueue" || (kind == "htb" && handle == DOWNLOAD_HANDLE)
            ));
    }
}
