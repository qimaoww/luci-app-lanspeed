use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::control::{queue_bytes, ActiveRule, ControlPlan, NSS_CPU_DOWNLOAD, NSS_MAX_RATE_BPS};

use super::{cpu_path, system, topology::Topology};

const MAJOR: &str = "7d00";
const ROOT_CLASS_MINOR: u16 = 1;
const DEFAULT_CLASS_MINOR: u16 = 2;
const DEFAULT_FIFO_HANDLE: &str = "7d02:";
const DEFAULT_QUEUE_BYTES: u64 = 16 * 1024 * 1024;
const MIN_BURST_BYTES: u64 = 6 * 1514;
const MAX_BURST_BYTES: u64 = 1024 * 1024;
const PAYLOAD_RATE_NUMERATOR: u64 = 110;
const PAYLOAD_RATE_DENOMINATOR: u64 = 100;
const BURST_WINDOW_MILLIS: u64 = 10;
const BITS_PER_MILLISECOND_BYTE: u64 = 8_000;

#[derive(Debug, Eq, PartialEq)]
struct NssQdiscDetail {
    kind: String,
    handle: String,
    parent: Option<String>,
    root: bool,
    r2q: Option<u32>,
    accel_mode: Option<u8>,
    limit: Option<String>,
    set_default: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct NssClassDetail {
    handle: String,
    leaf: Option<String>,
    burst: String,
    rate: String,
    cburst: String,
    crate_rate: String,
    priority: u8,
    quantum: String,
    overhead: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Direction {
    Upload,
    Download,
}

impl Direction {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }

    pub(super) fn rate(self, rule: &ActiveRule) -> u64 {
        let configured = match self {
            Self::Upload => rule.upload_bps,
            Self::Download => rule.download_bps,
        };
        payload_rate(configured)
    }
}

pub(super) fn preflight(topology: &Topology) -> Result<(), String> {
    for device in topology.all_shaper_devices() {
        system::ensure_replaceable_root(&device)?;
        let _ = default_class_rate_bps(&device)?;
    }
    Ok(())
}

pub(super) fn apply(plan: &ControlPlan, topology: &Topology) -> Result<(), String> {
    let mut download_by_device = BTreeMap::<String, Vec<&ActiveRule>>::new();
    for rule in plan.rules.iter().filter(|rule| {
        rule.download_bps != 0
            && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
    }) {
        let device = topology
            .download_device(&rule.identity_key)
            .ok_or_else(|| "nss_download_edge_unavailable".to_owned())?;
        download_by_device
            .entry(device.to_owned())
            .or_default()
            .push(rule);
    }
    let existing = owned_devices()?;
    if download_by_device.is_empty() && existing.is_empty() {
        return Ok(());
    }
    system::load_module("qca_nss_qdisc", "nss_qdisc_unavailable")?;
    for (device, rules) in &download_by_device {
        sync_tree(
            device,
            Direction::Download,
            rules,
            default_class_rate_bps(device)?,
        )?;
    }

    let desired = download_by_device.keys().cloned().collect::<BTreeSet<_>>();
    for device in existing {
        if !desired.contains(&device) {
            // A root replacement is observable by every client sharing the
            // physical edge. Keep an exact LAN Speed root as a default-only
            // pass-through tree while path identity is pending or the edge is
            // no longer the client's proven aggregate hook. Classifier
            // quiesce runs before this stage, so removing stale client leaves
            // cannot select an obsolete class. A real service shutdown still
            // removes the owned root through cleanup().
            sync_passthrough_tree(&device)?;
        }
    }
    Ok(())
}

pub(super) fn cleanup() -> Result<(), String> {
    if !system::command_available("tc") {
        return Ok(());
    }
    for device in owned_devices()? {
        remove_owned_tree(&device)?;
    }
    Ok(())
}

pub(super) fn passthrough() -> Result<(), String> {
    if !system::command_available("tc") {
        return Ok(());
    }
    for device in owned_devices()? {
        sync_passthrough_tree(&device)?;
    }
    Ok(())
}

pub(super) fn owned_tree_present() -> Result<bool, String> {
    Ok(!owned_devices()?.is_empty())
}

pub(super) fn verify_plan(plan: &ControlPlan, topology: &Topology) -> Result<(), String> {
    let mut desired = BTreeSet::new();
    let mut by_device = BTreeMap::<String, Vec<&ActiveRule>>::new();
    for rule in plan.rules.iter().filter(|rule| {
        rule.download_bps != 0
            && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
    }) {
        let device = topology
            .download_device(&rule.identity_key)
            .ok_or_else(|| "nss_download_edge_unavailable".to_owned())?;
        by_device.entry(device.to_owned()).or_default().push(rule);
    }
    for (device, rules) in by_device {
        verify_tree(
            &device,
            Direction::Download,
            &rules,
            default_class_rate_bps(&device)?,
        )?;
        desired.insert(device);
    }
    let owned = owned_devices()?;
    if !desired.is_subset(&owned) {
        return Err("nss_qdisc_verification_failed".into());
    }
    for device in owned.difference(&desired) {
        verify_tree(
            device,
            Direction::Upload,
            &[],
            default_class_rate_bps(device)?,
        )?;
    }
    Ok(())
}

fn owned_devices() -> Result<BTreeSet<String>, String> {
    let mut devices = BTreeSet::new();
    let cpu_path_devices = cpu_path::owned_shaper_devices()?;
    for device in system::interface_names()? {
        if direct_shaper_candidate(&device, &cpu_path_devices) && system::owned_root(&device)? {
            devices.insert(device);
        }
    }
    Ok(devices)
}

fn direct_shaper_candidate(device: &str, cpu_path_devices: &BTreeSet<String>) -> bool {
    !cpu_path_devices.contains(device)
}

fn sync_tree(
    device: &str,
    direction: Direction,
    rules: &[&ActiveRule],
    default_rate: u64,
) -> Result<(), String> {
    system::ensure_replaceable_root(device)?;
    let mut created = !system::owned_root(device)?;
    if created {
        install_base_tree(device, default_rate)?;
    } else {
        verify_base_tree(device)?;
        if !verify_base_options(device, default_rate)? {
            remove_owned_tree(device)?;
            install_base_tree(device, default_rate)?;
            created = true;
        }
    }
    let staged = (|| {
        for rule in rules {
            replace_client_class(device, rule.class_minor, direction.rate(rule))?;
            ensure_client_fifo(device, rule.class_minor, direction.rate(rule))?;
        }
        remove_stale_classes(device, rules)?;
        // qca_nss_qdisc rejects TC filters on an NSSHTB root. nft sets skb
        // priority before egress, while ECM supplies the same classid to
        // accelerated flows, so both directions select classes without a
        // second classifier on the qdisc itself.
        verify_tree(device, direction, rules, default_rate)
    })();
    if staged.is_err() && created {
        let _ = delete_created_root(device);
    }
    staged
}

pub(super) fn sync_igs_tree(device: &str, rules: &[&ActiveRule]) -> Result<(), String> {
    system::ensure_replaceable_root(device)?;
    let mut created = !system::owned_root(device)?;
    if created {
        install_base_tree(device, NSS_MAX_RATE_BPS)?;
    } else {
        verify_base_tree(device)?;
        if !verify_base_options(device, NSS_MAX_RATE_BPS)? {
            remove_owned_tree(device)?;
            install_base_tree(device, NSS_MAX_RATE_BPS)?;
            created = true;
        }
    }
    let staged = (|| {
        for rule in rules {
            replace_client_class(device, rule.class_minor, Direction::Upload.rate(rule))?;
            ensure_client_fifo(device, rule.class_minor, Direction::Upload.rate(rule))?;
        }
        remove_stale_classes(device, rules)?;
        verify_tree_inventory(device, Direction::Upload, rules, NSS_MAX_RATE_BPS, false)
    })();
    if staged.is_err() && created {
        let _ = delete_created_root(device);
    }
    staged
}

pub(super) fn verify_igs_tree(device: &str, rules: &[&ActiveRule]) -> Result<(), String> {
    verify_tree_inventory(device, Direction::Upload, rules, NSS_MAX_RATE_BPS, false)
}

pub(super) fn remove_igs_tree(device: &str) -> Result<(), String> {
    remove_owned_tree(device)
}

fn sync_passthrough_tree(device: &str) -> Result<(), String> {
    sync_tree(
        device,
        Direction::Upload,
        &[],
        default_class_rate_bps(device)?,
    )
}

fn install_base_tree(device: &str, default_rate: u64) -> Result<(), String> {
    system::run(
        "tc",
        &[
            "qdisc",
            "replace",
            "dev",
            device,
            "root",
            "handle",
            system::ROOT_HANDLE,
            "nsshtb",
            "r2q",
            "10",
            "accel_mode",
            "0",
        ],
    )?;
    let staged = (|| {
        replace_class(
            device,
            system::ROOT_HANDLE,
            ROOT_CLASS_MINOR,
            0,
            default_rate,
            0,
        )?;
        replace_class(
            device,
            &classid(ROOT_CLASS_MINOR),
            DEFAULT_CLASS_MINOR,
            0,
            default_rate,
            2,
        )?;
        system::run(
            "tc",
            &[
                "qdisc",
                "add",
                "dev",
                device,
                "parent",
                &classid(DEFAULT_CLASS_MINOR),
                "handle",
                DEFAULT_FIFO_HANDLE,
                "nssbfifo",
                "limit",
                &format!("{DEFAULT_QUEUE_BYTES}b"),
                "set_default",
                "accel_mode",
                "0",
            ],
        )?;
        verify_base_tree(device)
    })();
    if staged.is_err() {
        let _ = delete_created_root(device);
    }
    staged
}

fn replace_client_class(device: &str, minor: u16, rate_bps: u64) -> Result<(), String> {
    replace_class(
        device,
        &classid(ROOT_CLASS_MINOR),
        minor,
        rate_bps,
        rate_bps,
        1,
    )
}

fn replace_class(
    device: &str,
    parent: &str,
    minor: u16,
    rate_bps: u64,
    crate_bps: u64,
    priority: u8,
) -> Result<(), String> {
    let class = classid(minor);
    let rate = format!("{rate_bps}bit");
    let crate_rate = format!("{crate_bps}bit");
    let burst = format!("{}b", burst_bytes(rate_bps.max(crate_bps)));
    let priority = priority.to_string();
    system::run(
        "tc",
        &[
            "class",
            "replace",
            "dev",
            device,
            "parent",
            parent,
            "classid",
            &class,
            "nsshtb",
            "rate",
            &rate,
            "burst",
            &burst,
            "crate",
            &crate_rate,
            "cburst",
            &burst,
            "priority",
            &priority,
            "quantum",
            "1514",
        ],
    )
}

fn ensure_client_fifo(device: &str, minor: u16, rate_bps: u64) -> Result<(), String> {
    let parent = classid(minor);
    let handle = leaf_handle(minor);
    let leaves = leaf_qdiscs(device)?;
    let operation = if leaves.get(&parent).is_some_and(|value| value == &handle) {
        // NSSBFIFO implements qdisc change, so replace updates the bounded
        // queue when a client rate changes without detaching the live leaf.
        "replace"
    } else {
        // A different leaf under a LAN Speed class can only be a partial
        // object from our own failed transaction. Remove that exact parent;
        // never delete a qdisc by interface name alone.
        if leaves.contains_key(&parent) {
            system::run("tc", &["qdisc", "del", "dev", device, "parent", &parent])?;
        }
        "add"
    };
    system::run(
        "tc",
        &[
            "qdisc",
            operation,
            "dev",
            device,
            "parent",
            &parent,
            "handle",
            &handle,
            "nssbfifo",
            "limit",
            &format!("{}b", queue_bytes(rate_bps)),
            "accel_mode",
            "0",
        ],
    )
}

fn remove_stale_classes(device: &str, desired: &[&ActiveRule]) -> Result<(), String> {
    let desired = desired
        .iter()
        .map(|rule| rule.class_minor)
        .collect::<BTreeSet<_>>();
    for minor in client_classes(device)? {
        if !desired.contains(&minor) {
            let parent = classid(minor);
            if leaf_qdiscs(device)?.contains_key(&parent) {
                system::run("tc", &["qdisc", "del", "dev", device, "parent", &parent])?;
            }
            system::run("tc", &["class", "del", "dev", device, "classid", &parent])?;
        }
    }
    Ok(())
}

fn verify_base_tree(device: &str) -> Result<(), String> {
    if !system::owned_root(device)? {
        return Err("nss_qdisc_verification_failed".into());
    }
    let roots = class_handles(device, system::ROOT_HANDLE)?;
    let children = class_handles(device, &classid(ROOT_CLASS_MINOR))?;
    if !roots.contains(&classid(ROOT_CLASS_MINOR))
        || !children.contains(&classid(DEFAULT_CLASS_MINOR))
        || leaf_qdiscs(device)?
            .get(&classid(DEFAULT_CLASS_MINOR))
            .map(String::as_str)
            != Some(DEFAULT_FIFO_HANDLE)
    {
        return Err("nss_qdisc_verification_failed".into());
    }
    Ok(())
}

fn verify_tree(
    device: &str,
    direction: Direction,
    rules: &[&ActiveRule],
    default_rate: u64,
) -> Result<(), String> {
    verify_tree_inventory(device, direction, rules, default_rate, false)
}

fn verify_tree_inventory(
    device: &str,
    direction: Direction,
    rules: &[&ActiveRule],
    default_rate: u64,
    allow_root_filters: bool,
) -> Result<(), String> {
    verify_base_tree(device)?;
    if !allow_root_filters {
        ensure_no_root_filters(device)?;
    }
    let roots = class_handles(device, system::ROOT_HANDLE)?;
    let classes = class_handles(device, &classid(ROOT_CLASS_MINOR))?;
    let leaves = leaf_qdiscs(device)?;
    let expected_roots = BTreeSet::from([classid(ROOT_CLASS_MINOR)]);
    let mut expected_classes = BTreeSet::from([classid(DEFAULT_CLASS_MINOR)]);
    let mut expected_leaves =
        BTreeMap::from([(classid(DEFAULT_CLASS_MINOR), DEFAULT_FIFO_HANDLE.to_owned())]);
    for rule in rules {
        expected_classes.insert(classid(rule.class_minor));
        expected_leaves.insert(classid(rule.class_minor), leaf_handle(rule.class_minor));
    }
    let qdiscs = system::qdiscs(device)?;
    let foreign_leaf = qdiscs.iter().any(|value| {
        value.parent.as_deref().is_some_and(|parent| {
            parent
                .split_once(':')
                .is_some_and(|(major, _)| major == MAJOR)
        }) && value.kind != "nssbfifo"
    });
    if roots == expected_roots
        && classes == expected_classes
        && leaves == expected_leaves
        && !foreign_leaf
    {
        verify_nss_options(device, direction, rules, default_rate)
    } else {
        Err("nss_qdisc_verification_failed".into())
    }
}

fn verify_nss_options(
    device: &str,
    direction: Direction,
    rules: &[&ActiveRule],
    default_rate: u64,
) -> Result<(), String> {
    let qdiscs = nss_qdisc_details(device)?
        .into_iter()
        .filter(|value| {
            value.handle == system::ROOT_HANDLE
                || value
                    .parent
                    .as_deref()
                    .is_some_and(|parent| parent_major(parent) == Some(MAJOR))
        })
        .collect::<Vec<_>>();
    let classes = nss_class_details(device)?
        .into_iter()
        .filter(|value| parent_major(&value.handle) == Some(MAJOR))
        .collect::<Vec<_>>();
    if qdiscs.len() != 2usize.saturating_add(rules.len())
        || classes.len() != 2usize.saturating_add(rules.len())
    {
        return Err("nss_qdisc_verification_failed".into());
    }

    let (expected_root_qdisc, expected_default_qdisc) = expected_base_qdiscs();
    let (expected_root_class, expected_default_class) = expected_base_classes(default_rate);
    if exact_detail_count(&qdiscs, &expected_root_qdisc) != 1
        || exact_detail_count(&qdiscs, &expected_default_qdisc) != 1
        || exact_detail_count(&classes, &expected_root_class) != 1
        || exact_detail_count(&classes, &expected_default_class) != 1
    {
        return Err("nss_qdisc_verification_failed".into());
    }

    for rule in rules {
        let rate = direction.rate(rule);
        let burst = tc_size_text(burst_bytes(rate));
        let leaf = leaf_handle(rule.class_minor);
        let expected_qdisc = NssQdiscDetail {
            kind: "nssbfifo".into(),
            handle: leaf.clone(),
            parent: Some(classid(rule.class_minor)),
            root: false,
            r2q: None,
            accel_mode: Some(0),
            limit: Some(tc_size_text(queue_bytes(rate))),
            set_default: false,
        };
        let expected_class = NssClassDetail {
            handle: classid(rule.class_minor),
            leaf: Some(leaf),
            burst: burst.clone(),
            rate: tc_rate_text(rate),
            cburst: burst,
            crate_rate: tc_rate_text(rate),
            priority: 1,
            quantum: tc_size_text(1514),
            overhead: tc_size_text(0),
        };
        if exact_detail_count(&qdiscs, &expected_qdisc) != 1
            || exact_detail_count(&classes, &expected_class) != 1
        {
            return Err("nss_qdisc_verification_failed".into());
        }
    }
    Ok(())
}

fn verify_base_options(device: &str, default_rate: u64) -> Result<bool, String> {
    let qdiscs = nss_qdisc_details(device)?;
    let classes = nss_class_details(device)?;
    let (expected_root_qdisc, expected_default_qdisc) = expected_base_qdiscs();
    let (expected_root_class, expected_default_class) = expected_base_classes(default_rate);
    Ok(exact_detail_count(&qdiscs, &expected_root_qdisc) == 1
        && exact_detail_count(&qdiscs, &expected_default_qdisc) == 1
        && exact_detail_count(&classes, &expected_root_class) == 1
        && exact_detail_count(&classes, &expected_default_class) == 1)
}

fn expected_base_qdiscs() -> (NssQdiscDetail, NssQdiscDetail) {
    (
        NssQdiscDetail {
            kind: "nsshtb".into(),
            handle: system::ROOT_HANDLE.into(),
            parent: None,
            root: true,
            r2q: Some(10),
            accel_mode: Some(0),
            limit: None,
            set_default: false,
        },
        NssQdiscDetail {
            kind: "nssbfifo".into(),
            handle: DEFAULT_FIFO_HANDLE.into(),
            parent: Some(classid(DEFAULT_CLASS_MINOR)),
            root: false,
            r2q: None,
            accel_mode: Some(0),
            limit: Some(tc_size_text(DEFAULT_QUEUE_BYTES)),
            set_default: true,
        },
    )
}

fn expected_base_classes(default_rate: u64) -> (NssClassDetail, NssClassDetail) {
    let burst = tc_size_text(burst_bytes(default_rate));
    let crate_rate = tc_rate_text(default_rate);
    (
        NssClassDetail {
            handle: classid(ROOT_CLASS_MINOR),
            leaf: None,
            burst: burst.clone(),
            rate: tc_rate_text(0),
            cburst: burst.clone(),
            crate_rate: crate_rate.clone(),
            priority: 0,
            quantum: tc_size_text(1514),
            overhead: tc_size_text(0),
        },
        NssClassDetail {
            handle: classid(DEFAULT_CLASS_MINOR),
            leaf: Some(DEFAULT_FIFO_HANDLE.into()),
            burst: burst.clone(),
            rate: tc_rate_text(0),
            cburst: burst,
            crate_rate,
            priority: 2,
            quantum: tc_size_text(1514),
            overhead: tc_size_text(0),
        },
    )
}

fn exact_detail_count<T: PartialEq>(values: &[T], expected: &T) -> usize {
    values.iter().filter(|value| *value == expected).count()
}

fn nss_qdisc_details(device: &str) -> Result<Vec<NssQdiscDetail>, String> {
    let output = system::output("tc", &["qdisc", "show", "dev", device])?;
    if !output.status.success() {
        return Err("nss_qdisc_inspection_failed".into());
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "nss_qdisc_inspection_failed")?;
    parse_nss_qdisc_details(&text)
}

fn nss_class_details(device: &str) -> Result<Vec<NssClassDetail>, String> {
    let output = system::output("tc", &["class", "show", "dev", device])?;
    if !output.status.success() {
        return Err("nss_qdisc_inspection_failed".into());
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "nss_qdisc_inspection_failed")?;
    parse_nss_class_details(&text)
}

fn parse_nss_qdisc_details(text: &str) -> Result<Vec<NssQdiscDetail>, String> {
    let mut values = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 3 || fields[0] != "qdisc" {
            return Err("nss_qdisc_inspection_failed".into());
        }
        if !matches!(fields[1], "nsshtb" | "nssbfifo") {
            continue;
        }
        values.push(NssQdiscDetail {
            kind: fields[1].into(),
            handle: fields[2].into(),
            parent: token_after(&fields, "parent").map(str::to_owned),
            root: fields.contains(&"root"),
            r2q: parsed_token_after(&fields, "r2q")?,
            accel_mode: parsed_token_after(&fields, "accel_mode")?,
            limit: token_after(&fields, "limit").map(str::to_owned),
            set_default: fields.contains(&"set_default"),
        });
    }
    Ok(values)
}

fn parse_nss_class_details(text: &str) -> Result<Vec<NssClassDetail>, String> {
    let mut values = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 3 || fields[0] != "class" {
            return Err("nss_qdisc_inspection_failed".into());
        }
        if fields[1] != "nsshtb" {
            continue;
        }
        values.push(NssClassDetail {
            handle: fields[2].into(),
            leaf: token_after(&fields, "leaf").map(str::to_owned),
            burst: required_token_after(&fields, "burst")?.into(),
            rate: required_token_after(&fields, "rate")?.into(),
            cburst: required_token_after(&fields, "cburst")?.into(),
            crate_rate: required_token_after(&fields, "crate")?.into(),
            priority: required_token_after(&fields, "priority")?
                .parse()
                .map_err(|_| "nss_qdisc_inspection_failed")?,
            quantum: required_token_after(&fields, "quantum")?.into(),
            overhead: required_token_after(&fields, "overhead")?.into(),
        });
    }
    Ok(values)
}

fn token_after<'a>(fields: &[&'a str], token: &str) -> Option<&'a str> {
    fields
        .iter()
        .position(|field| *field == token)
        .and_then(|index| fields.get(index.saturating_add(1)))
        .copied()
}

fn required_token_after<'a>(fields: &[&'a str], token: &str) -> Result<&'a str, String> {
    token_after(fields, token).ok_or_else(|| "nss_qdisc_inspection_failed".into())
}

fn parsed_token_after<T>(fields: &[&str], token: &str) -> Result<Option<T>, String>
where
    T: std::str::FromStr,
{
    token_after(fields, token)
        .map(|value| {
            value
                .parse()
                .map_err(|_| "nss_qdisc_inspection_failed".to_owned())
        })
        .transpose()
}

fn parent_major(value: &str) -> Option<&str> {
    value.split_once(':').map(|(major, _)| major)
}

fn class_handles(device: &str, parent: &str) -> Result<BTreeSet<String>, String> {
    let output = system::output("tc", &["class", "show", "dev", device, "parent", parent])?;
    if !output.status.success() {
        return Err("nss_qdisc_inspection_failed".into());
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "nss_qdisc_inspection_failed")?;
    let handles = parse_class_handles(&text)?;
    // The target qca_nss_qdisc renderer prints every class as `root` and
    // ignores the parent selector. Reconstruct the one-level firmware tree
    // from the stable LAN Speed root class instead of trusting that wording.
    if parent == system::ROOT_HANDLE {
        Ok(handles
            .into_iter()
            .filter(|handle| handle == &classid(ROOT_CLASS_MINOR))
            .collect())
    } else {
        Ok(handles
            .into_iter()
            .filter(|handle| handle != &classid(ROOT_CLASS_MINOR))
            .collect())
    }
}

fn leaf_qdiscs(device: &str) -> Result<BTreeMap<String, String>, String> {
    Ok(system::qdiscs(device)?
        .into_iter()
        .filter(|value| value.kind == "nssbfifo")
        .filter_map(|value| value.parent.map(|parent| (parent, value.handle)))
        .collect())
}

fn remove_owned_tree(device: &str) -> Result<(), String> {
    if !system::interface_exists(device) || !system::owned_root(device)? {
        return Ok(());
    }
    verify_base_tree(device)?;
    ensure_no_root_filters(device)?;
    let qdiscs = system::qdiscs(device)?;
    if qdiscs.iter().any(|value| {
        value.parent.as_deref().is_some_and(|parent| {
            parent
                .split_once(':')
                .is_some_and(|(major, _)| major == MAJOR)
        }) && value.kind != "nssbfifo"
    }) {
        return Err("nss_qdisc_owned_by_external_service".into());
    }
    let parents = qdiscs
        .into_iter()
        .filter(|value| {
            value.kind == "nssbfifo"
                && value.parent.as_deref().is_some_and(|parent| {
                    parent
                        .split_once(':')
                        .is_some_and(|(major, _)| major == MAJOR)
                })
        })
        .filter_map(|value| value.parent)
        .collect::<BTreeSet<_>>();
    for parent in parents {
        system::run("tc", &["qdisc", "del", "dev", device, "parent", &parent])?;
    }
    system::run(
        "tc",
        &[
            "qdisc",
            "del",
            "dev",
            device,
            "root",
            "handle",
            system::ROOT_HANDLE,
        ],
    )
}

fn ensure_no_root_filters(device: &str) -> Result<(), String> {
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
            system::ROOT_HANDLE,
        ],
    )?;
    if !output.status.success() {
        return Err("nss_qdisc_inspection_failed".into());
    }
    let values = serde_json::from_slice::<Vec<Value>>(&output.stdout)
        .map_err(|_| "nss_qdisc_inspection_failed".to_owned())?;
    if values.is_empty() {
        Ok(())
    } else {
        Err("nss_qdisc_owned_by_external_service".into())
    }
}

fn delete_created_root(device: &str) -> Result<(), String> {
    if system::owned_root(device)? {
        system::run(
            "tc",
            &[
                "qdisc",
                "del",
                "dev",
                device,
                "root",
                "handle",
                system::ROOT_HANDLE,
            ],
        )?;
    }
    Ok(())
}

fn client_classes(device: &str) -> Result<Vec<u16>, String> {
    Ok(class_handles(device, &classid(ROOT_CLASS_MINOR))?
        .into_iter()
        .filter_map(|handle| {
            let (major, minor) = handle.split_once(':')?;
            (major == MAJOR)
                .then(|| u16::from_str_radix(minor, 16).ok())
                .flatten()
        })
        .filter(|minor| *minor >= 0x100)
        .collect())
}

fn parse_class_handles(text: &str) -> Result<BTreeSet<String>, String> {
    let mut handles = BTreeSet::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 3 || fields[0] != "class" || fields[1] != "nsshtb" {
            return Err("nss_qdisc_inspection_failed".into());
        }
        handles.insert(fields[2].to_owned());
    }
    Ok(handles)
}

fn default_class_rate_bps(device: &str) -> Result<u64, String> {
    if std::fs::metadata(format!("/sys/class/net/{device}/phy80211")).is_ok() {
        return Ok(NSS_MAX_RATE_BPS);
    }
    let physical_rate = std::fs::read_to_string(format!("/sys/class/net/{device}/speed"))
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .and_then(|speed_mbps| speed_mbps.checked_mul(1_000_000))
        .filter(|rate| *rate != 0 && *rate < NSS_MAX_RATE_BPS)
        .ok_or_else(|| "nss_default_class_capacity_exceeded".to_owned())?;
    debug_assert!(NSS_MAX_RATE_BPS > physical_rate);
    Ok(NSS_MAX_RATE_BPS)
}

pub(super) fn classid(minor: u16) -> String {
    format!("{MAJOR}:{minor:x}")
}

pub(super) fn leaf_handle(minor: u16) -> String {
    format!("{minor:x}:")
}

pub(super) fn leaf_tag(minor: u16) -> String {
    format!("{minor:x}:0")
}

fn burst_bytes(rate_bps: u64) -> u64 {
    rate_bps
        .saturating_mul(BURST_WINDOW_MILLIS)
        .saturating_add(BITS_PER_MILLISECOND_BYTE - 1)
        .saturating_div(BITS_PER_MILLISECOND_BYTE)
        .clamp(MIN_BURST_BYTES, MAX_BURST_BYTES)
}

fn payload_rate(configured_bps: u64) -> u64 {
    configured_bps
        .saturating_mul(PAYLOAD_RATE_NUMERATOR)
        .saturating_add(PAYLOAD_RATE_DENOMINATOR - 1)
        .saturating_div(PAYLOAD_RATE_DENOMINATOR)
        .min(NSS_MAX_RATE_BPS)
}

fn tc_rate_text(rate_bps: u64) -> String {
    // qca_nss_qdisc stores bytes per second in a u32. iproute2 truncates the
    // requested bit rate to whole bytes before rendering it back in SI units.
    let mut bits = rate_bps.saturating_div(8).saturating_mul(8);
    let units = ["", "K", "M", "G", "T"];
    let mut unit = 0;
    while unit < units.len() - 1 {
        if bits < 1_000 {
            break;
        }
        if bits % 1_000 != 0 && bits < 1_000_000 {
            break;
        }
        bits /= 1_000;
        unit += 1;
    }
    format!("{bits}{}bit", units[unit])
}

fn tc_size_text(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * KIB;
    const GIB: u64 = MIB * KIB;

    for (unit, suffix, tolerance) in [(GIB, "Gb", 1024), (MIB, "Mb", 1024), (KIB, "Kb", 16)] {
        if bytes >= unit {
            let rounded = round_ties_even(bytes, unit);
            if rounded.saturating_mul(unit).abs_diff(bytes) < tolerance {
                return format!("{rounded}{suffix}");
            }
        }
    }
    format!("{bytes}b")
}

fn round_ties_even(value: u64, unit: u64) -> u64 {
    let quotient = value / unit;
    let remainder = value % unit;
    if remainder > unit / 2 || (remainder == unit / 2 && quotient % 2 == 1) {
        quotient.saturating_add(1)
    } else {
        quotient
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nss_tree_has_one_firmware_root_group() {
        assert_eq!(classid(ROOT_CLASS_MINOR), "7d00:1");
        assert_eq!(classid(DEFAULT_CLASS_MINOR), "7d00:2");
        assert_eq!(classid(0x123), "7d00:123");
        assert_eq!(leaf_handle(0x7c23), "7c23:");
        assert_eq!(leaf_tag(0x7c23), "7c23:0");
    }

    #[test]
    fn direct_inventory_excludes_owned_cpu_path_executor() {
        let cpu_path_devices = BTreeSet::from(["lsu12345678".to_owned()]);
        assert!(direct_shaper_candidate("edge0", &cpu_path_devices));
        assert!(!direct_shaper_candidate("lsu12345678", &cpu_path_devices));
    }

    #[test]
    fn nss_class_parser_accepts_libwrt_non_json_output() {
        let handles = parse_class_handles(
            "class nsshtb 7d00:123 root leaf 8001: burst 9072b\n\
             class nsshtb 7d00:2 root leaf 7d02: burst 536870b\n",
        )
        .unwrap();
        assert!(handles.contains("7d00:123"));
        assert!(handles.contains("7d00:2"));
    }

    #[test]
    fn nss_qdisc_detail_parser_preserves_firmware_options() {
        let values = parse_nss_qdisc_details(
            "qdisc nsshtb 7d00: root refcnt 5 r2q 10 accel_mode 0\n\
             qdisc nssbfifo 7d02: parent 7d00:2 limit 16Mb set_default accel_mode 0\n\
             qdisc nssbfifo 7c23: parent 7d00:7c23 limit 687500b accel_mode 0\n\
             qdisc clsact ffff: parent ffff:fff1\n",
        )
        .unwrap();
        assert_eq!(
            values,
            vec![
                NssQdiscDetail {
                    kind: "nsshtb".into(),
                    handle: "7d00:".into(),
                    parent: None,
                    root: true,
                    r2q: Some(10),
                    accel_mode: Some(0),
                    limit: None,
                    set_default: false,
                },
                NssQdiscDetail {
                    kind: "nssbfifo".into(),
                    handle: "7d02:".into(),
                    parent: Some("7d00:2".into()),
                    root: false,
                    r2q: None,
                    accel_mode: Some(0),
                    limit: Some("16Mb".into()),
                    set_default: true,
                },
                NssQdiscDetail {
                    kind: "nssbfifo".into(),
                    handle: "7c23:".into(),
                    parent: Some("7d00:7c23".into()),
                    root: false,
                    r2q: None,
                    accel_mode: Some(0),
                    limit: Some("687500b".into()),
                    set_default: false,
                },
            ]
        );
    }

    #[test]
    fn nss_class_detail_parser_preserves_firmware_options() {
        let values = parse_nss_class_details(
            "class nsshtb 7d00:1 root burst 1Mb rate 0bit cburst 1Mb crate 4Gbit priority 0 quantum 1514b overhead 0b\n\
             class nsshtb 7d00:7c23 root leaf 7c23: burst 13750b rate 11Mbit cburst 13750b crate 11Mbit priority 1 quantum 1514b overhead 0b\n",
        )
        .unwrap();
        assert_eq!(
            values[1],
            NssClassDetail {
                handle: "7d00:7c23".into(),
                leaf: Some("7c23:".into()),
                burst: "13750b".into(),
                rate: "11Mbit".into(),
                cburst: "13750b".into(),
                crate_rate: "11Mbit".into(),
                priority: 1,
                quantum: "1514b".into(),
                overhead: "0b".into(),
            }
        );
    }

    #[test]
    fn nss_text_format_matches_target_iproute2() {
        assert_eq!(tc_rate_text(0), "0bit");
        assert_eq!(tc_rate_text(11_000_000), "11Mbit");
        assert_eq!(tc_rate_text(110_000_000), "110Mbit");
        assert_eq!(tc_rate_text(NSS_MAX_RATE_BPS), "4Gbit");
        assert_eq!(tc_rate_text(11_000_007), "11Mbit");
        assert_eq!(tc_size_text(16 * 1024 * 1024), "16Mb");
        assert_eq!(tc_size_text(1024 * 1024), "1Mb");
        assert_eq!(tc_size_text(1514), "1514b");
        assert_eq!(tc_size_text(687_500), "687500b");
    }

    #[test]
    fn nss_base_fingerprint_detects_default_queue_drift() {
        let qdiscs = parse_nss_qdisc_details(
            "qdisc nsshtb 7d00: root refcnt 5 r2q 10 accel_mode 0\n\
             qdisc nssbfifo 7d02: parent 7d00:2 limit 16Mb set_default accel_mode 0\n",
        )
        .unwrap();
        let classes = parse_nss_class_details(
            "class nsshtb 7d00:1 root burst 1Mb rate 0bit cburst 1Mb crate 4Gbit priority 0 quantum 1514b overhead 0b\n\
             class nsshtb 7d00:2 root leaf 7d02: burst 1Mb rate 0bit cburst 1Mb crate 4Gbit priority 2 quantum 1514b overhead 0b\n",
        )
        .unwrap();
        let (root_qdisc, default_qdisc) = expected_base_qdiscs();
        let (root_class, default_class) = expected_base_classes(NSS_MAX_RATE_BPS);
        assert_eq!(exact_detail_count(&qdiscs, &root_qdisc), 1);
        assert_eq!(exact_detail_count(&qdiscs, &default_qdisc), 1);
        assert_eq!(exact_detail_count(&classes, &root_class), 1);
        assert_eq!(exact_detail_count(&classes, &default_class), 1);

        let mut changed = default_qdisc;
        changed.limit = Some("8Mb".into());
        assert_eq!(exact_detail_count(&qdiscs, &changed), 0);
    }

    #[test]
    fn nss_payload_rate_has_independent_l2_headroom_and_stays_u32_safe() {
        assert_eq!(payload_rate(10_000_000), 11_000_000);
        assert_eq!(payload_rate(100_000_000), 110_000_000);
        assert_eq!(payload_rate(NSS_MAX_RATE_BPS), NSS_MAX_RATE_BPS);
    }

    #[test]
    fn nss_burst_covers_ten_milliseconds_and_is_bounded() {
        assert_eq!(burst_bytes(8_000), MIN_BURST_BYTES);
        assert_eq!(burst_bytes(11_000_000), 13_750);
        assert_eq!(burst_bytes(110_000_000), 137_500);
        assert_eq!(burst_bytes(NSS_MAX_RATE_BPS), MAX_BURST_BYTES);
    }
}
