use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    str,
};

use serde_json::Value;

use lanspeed_common::{
    EGRESS_EARLY_PROGRAM_NAME, EGRESS_PROGRAM_NAME, INGRESS_EARLY_PROGRAM_NAME,
    INGRESS_PROGRAM_NAME,
};

use crate::control::{ActiveRule, ControlPlan, NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD};

use super::{exact_u32_match_count, ifb, mac_u32_matches, prefix_u32_matches, system, Direction};

const IGS_PREF: u32 = 0xd080;
const IGS_HANDLE: &str = "0x7e80";
const UPLOAD_CHAIN: u32 = 0x7e22;
const UPLOAD_JUMP_PREF: u32 = 0xd021;
const DOWNLOAD_CHAIN: u32 = 0x7e21;
const DOWNLOAD_JUMP_PREF: u32 = 0xd020;
const UPLOAD_LOCAL_PREF_START: u32 = 10_000;
const UPLOAD_BLOCK_PREF_START: u32 = 12_000;
const UPLOAD_CLIENT_PREF_START: u32 = 14_000;
const UPLOAD_TERMINAL_PREF: u32 = 19_999;
const LOCAL_PREF_START: u32 = 20_000;
const BLOCK_PREF_START: u32 = 25_000;
const CLIENT_PREF_START: u32 = 30_000;
const TERMINAL_PREF: u32 = 65_534;
const LEGACY_UPLOAD_CHAIN: u32 = 0x7e20;
const LEGACY_UPLOAD_ALIAS: &str = "lanspeedd:nss-cpu-upload:v2";
const PROTOCOLS: [&str; 2] = ["ip", "ipv6"];

pub(super) fn recover_classifier_slots(interfaces: &[String]) -> Result<bool, String> {
    let mut recovered = false;
    for interface in interfaces {
        if !system::interface_exists(interface) {
            continue;
        }
        for direction in ["ingress", "egress"] {
            let output = system::output(
                "tc",
                &["-j", "-d", "filter", "show", "dev", interface, direction],
            )?;
            if !output.status.success() {
                return Err("tc_classifier_inspection_failed".into());
            }
            let text = str::from_utf8(&output.stdout)
                .map_err(|_| "tc_classifier_inspection_failed".to_owned())?;
            let filters = crate::probe::tc::parse_filter_json(interface, direction, text)
                .map_err(|_| "tc_classifier_inspection_failed".to_owned())?;
            for (pref, handle, program) in [
                (
                    crate::probe::tc::LANSPEED_PREF,
                    crate::probe::tc::LANSPEED_HANDLE,
                    if direction == "ingress" {
                        INGRESS_PROGRAM_NAME
                    } else {
                        EGRESS_PROGRAM_NAME
                    },
                ),
                (
                    crate::probe::tc::LANSPEED_EARLY_PREF,
                    crate::probe::tc::LANSPEED_EARLY_HANDLE,
                    if direction == "ingress" {
                        INGRESS_EARLY_PROGRAM_NAME
                    } else {
                        EGRESS_EARLY_PROGRAM_NAME
                    },
                ),
            ] {
                let slot = filters
                    .iter()
                    .filter(|filter| {
                        filter.filter.chain == 0
                            && filter.filter.pref == pref
                            && crate::probe::tc::handles_equal(&filter.filter.handle, handle)
                    })
                    .collect::<Vec<_>>();
                if slot.len() > 1 {
                    return Err("tc_classifier_ownership_ambiguous".into());
                }
                if slot
                    .first()
                    .is_some_and(|filter| orphan_slot_owned(filter, program))
                {
                    system::run(
                        "tc",
                        &[
                            "filter",
                            "del",
                            "dev",
                            interface,
                            direction,
                            "pref",
                            &pref.to_string(),
                            "handle",
                            handle,
                            "bpf",
                        ],
                    )?;
                    recovered = true;
                }
            }
        }
    }
    Ok(recovered)
}

fn orphan_slot_owned(filter: &crate::probe::tc::TcFilterDetails, program: &str) -> bool {
    filter.kind.as_deref() == Some("bpf")
        && filter.protocol.as_deref().is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "all" | "3" | "0x3" | "0x0003"
            )
        })
        && filter.program_name.as_deref() == Some(kernel_program_name(program))
        && filter.direct_action == Some(true)
        && filter.not_in_hw == Some(true)
        && filter.in_hw != Some(true)
}

fn kernel_program_name(program: &str) -> &str {
    &program[..program.len().min(15)]
}

pub(super) fn preflight(plan: &ControlPlan) -> Result<(), String> {
    let uploads = upload_rules(plan);
    let downloads = download_rules(plan);
    if uploads.is_empty() && downloads.is_empty() {
        return Ok(());
    }
    for module in ["cls_u32", "cls_matchall", "act_gact"] {
        if !system::module_available(module) {
            return Err(format!("{module}_unavailable"));
        }
    }
    let upload_shaping = uploads.values().flatten().any(|rule| {
        rule.upload_bps != 0 && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD)
    });
    let download_shaping = downloads.values().flatten().any(|rule| {
        rule.download_bps != 0
            && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
    });
    if upload_shaping || download_shaping {
        if !system::module_available("act_skbedit") {
            return Err("act_skbedit_unavailable".into());
        }
    }
    if upload_shaping && !system::module_available("act_mirred") {
        return Err("act_mirred_unavailable".into());
    }
    for edge in uploads.keys().chain(downloads.keys()) {
        if !system::interface_exists(edge) {
            return Err("lan_control_interface_unavailable".into());
        }
    }
    validate_filter_capacity(plan, &uploads, &downloads)?;
    Ok(())
}

pub(super) fn install(plan: &ControlPlan) -> Result<(), String> {
    cleanup_legacy_upload_hooks()?;
    stage_upload_hooks(plan, false)?;
    let mut published = Vec::new();
    let result = (|| {
        sync_download_hooks(plan, false)?;
        published = sync_upload_mappings(plan)?;
        activate_upload_hooks(plan, false)?;
        verify(plan)
    })();
    if let Err(error) = result {
        let mut errors = vec![error];
        if let Err(cleanup_error) = deactivate_upload_hooks() {
            errors.push(cleanup_error);
        };
        if let Err(cleanup_error) = rollback_publications(&published) {
            errors.push(cleanup_error);
        }
        return Err(errors.join(";"));
    }
    Ok(())
}

pub(super) fn quiesce(plan: &ControlPlan) -> Result<(), String> {
    // Keep an existing transactional IGS mapping alive while replacement
    // queues are staged. Removing it would expose every client on that edge.
    stage_upload_hooks(plan, true)?;
    activate_upload_hooks(plan, true)?;
    sync_download_hooks(plan, true)
}

pub(super) fn verify(plan: &ControlPlan) -> Result<(), String> {
    let uploads = upload_edges(plan);
    for (edge, device) in &uploads {
        if !ifb::owned(edge)?
            || ifb::state(device)? != Some(ifb::IgsState::Published)
            || ifb::published_edge(device)?.as_deref() != Some(edge)
            || ifb::device(edge) != *device
        {
            return Err("nss_igs_mapping_missing".into());
        }
    }
    for (device, edge) in ifb::owned_interfaces()? {
        if let Some(target) = ifb::published_edge(&device)? {
            if uploads.get(&edge) != Some(&device) || target != edge {
                return Err("nss_igs_mapping_stale".into());
            }
        }
    }
    verify_upload_hooks(plan, false)?;
    verify_download_hooks(plan)
}

pub(super) fn cleanup() -> Result<(), String> {
    cleanup_legacy_upload_hooks()?;
    cleanup_legacy_igs_mappings()?;
    for edge in system::interface_names()? {
        cleanup_upload_hook(&edge)?;
        cleanup_download_hook(&edge)?;
    }
    for (_, edge) in ifb::owned_interfaces()? {
        ifb::unpublish(&edge)?;
    }
    Ok(())
}

/// Per-client Internet classifier counters prove CPU-path participation only.
/// They are control evidence and must never be merged into RateMux.
pub(super) fn input_bytes(plan: &ControlPlan) -> Result<BTreeMap<String, u64>, String> {
    let mut snapshot = BTreeMap::new();
    for (edge, rules) in upload_rules(plan) {
        let values = counter_values(&edge, "ingress", UPLOAD_CHAIN)?;
        let mut pref = UPLOAD_CLIENT_PREF_START;
        for rule in rules.iter().filter(|rule| {
            rule.upload_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD)
        }) {
            let bytes = protocol_action_bytes(&values, &mut pref, "skbedit")?;
            snapshot.insert(
                format!("{}/upload/cpu/{edge}/input_bytes", rule.identity_key),
                bytes,
            );
        }
    }
    for (edge, rules) in download_rules(plan) {
        let values = counter_values(&edge, "egress", DOWNLOAD_CHAIN)?;
        let mut pref = CLIENT_PREF_START;
        for rule in rules.iter().filter(|rule| {
            rule.download_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
        }) {
            let bytes = protocol_action_bytes(&values, &mut pref, "skbedit")?;
            snapshot.insert(
                format!("{}/download/cpu/{edge}/input_bytes", rule.identity_key),
                bytes,
            );
        }
    }
    Ok(snapshot)
}

fn counter_values(edge: &str, hook: &str, chain: u32) -> Result<Vec<Value>, String> {
    if !system::interface_exists(edge) || !system::has_qdisc(edge, "clsact", None)? {
        return Err("cpu_path_counter_unavailable".into());
    }
    let output = system::output(
        "tc",
        &[
            "-j",
            "-s",
            "-d",
            "filter",
            "show",
            "dev",
            edge,
            hook,
            "chain",
            &chain.to_string(),
        ],
    )?;
    if !output.status.success() {
        return Err("cpu_path_counter_unavailable".into());
    }
    system::tc_filter_values(&output.stdout, "cpu_path_counter_unavailable")
}

fn protocol_action_bytes(
    values: &[Value],
    pref: &mut u32,
    action_kind: &str,
) -> Result<u64, String> {
    let mut total = 0u64;
    for protocol in PROTOCOLS {
        let matches = values
            .iter()
            .filter(|value| {
                value.get("kind").and_then(Value::as_str) == Some("u32")
                    && value.get("pref").and_then(Value::as_u64) == Some(u64::from(*pref))
                    && value.get("protocol").and_then(Value::as_str) == Some(protocol)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err("cpu_path_counter_unavailable".into());
        }
        let actions = matches[0]
            .get("options")
            .and_then(|options| options.get("actions"))
            .and_then(Value::as_array)
            .ok_or_else(|| "cpu_path_counter_unavailable".to_owned())?;
        let matching = actions
            .iter()
            .filter(|action| action.get("kind").and_then(Value::as_str) == Some(action_kind))
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err("cpu_path_counter_unavailable".into());
        }
        let bytes = matching[0]
            .get("stats")
            .and_then(|stats| stats.get("bytes"))
            .and_then(Value::as_u64)
            .ok_or_else(|| "cpu_path_counter_unavailable".to_owned())?;
        total = total.saturating_add(bytes);
        *pref = pref.saturating_add(1);
    }
    Ok(total)
}

fn upload_edges(plan: &ControlPlan) -> BTreeMap<String, String> {
    plan.rules
        .iter()
        .filter(|rule| {
            rule.upload_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD)
        })
        .map(|rule| (rule.interface.clone(), ifb::device(&rule.interface)))
        .collect()
}

fn upload_rules(plan: &ControlPlan) -> BTreeMap<String, Vec<&ActiveRule>> {
    let mut grouped = BTreeMap::<String, Vec<&ActiveRule>>::new();
    for rule in plan.rules.iter().filter(|rule| {
        (rule.upload_bps != 0 && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD))
            || rule.internet_disabled
    }) {
        grouped
            .entry(rule.interface.clone())
            .or_default()
            .push(rule);
    }
    grouped
}

fn validate_filter_capacity(
    plan: &ControlPlan,
    uploads: &BTreeMap<String, Vec<&ActiveRule>>,
    downloads: &BTreeMap<String, Vec<&ActiveRule>>,
) -> Result<(), String> {
    let fits = |rules: &[&ActiveRule], direction: Direction| {
        let blocked = rules
            .iter()
            .filter(|rule| rule.internet_disabled)
            .count()
            .saturating_mul(PROTOCOLS.len());
        let shaped = rules
            .iter()
            .filter(|rule| {
                direction.configured_rate(rule) != 0
                    && plan.nss_direction_path_ready(&rule.identity_key, direction.bit())
            })
            .count()
            .saturating_mul(PROTOCOLS.len());
        let (local_start, block_start, client_start, terminal) = match direction {
            Direction::Upload => (
                UPLOAD_LOCAL_PREF_START,
                UPLOAD_BLOCK_PREF_START,
                UPLOAD_CLIENT_PREF_START,
                UPLOAD_TERMINAL_PREF,
            ),
            Direction::Download => (
                LOCAL_PREF_START,
                BLOCK_PREF_START,
                CLIENT_PREF_START,
                TERMINAL_PREF,
            ),
        };
        local_start.saturating_add(plan.local_prefixes.len() as u32) < block_start
            && block_start.saturating_add(blocked as u32) < client_start
            && client_start.saturating_add(shaped as u32) < terminal
    };
    if uploads
        .values()
        .any(|rules| !fits(rules, Direction::Upload))
        || downloads
            .values()
            .any(|rules| !fits(rules, Direction::Download))
    {
        Err("control_filter_capacity".into())
    } else {
        Ok(())
    }
}

fn download_rules(plan: &ControlPlan) -> BTreeMap<String, Vec<&ActiveRule>> {
    let mut grouped = BTreeMap::<String, Vec<&ActiveRule>>::new();
    for rule in plan.rules.iter().filter(|rule| {
        (rule.download_bps != 0
            && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD))
            || rule.internet_disabled
    }) {
        grouped
            .entry(rule.interface.clone())
            .or_default()
            .push(rule);
    }
    grouped
}

fn sync_upload_mappings(plan: &ControlPlan) -> Result<Vec<String>, String> {
    cleanup_legacy_igs_mappings()?;
    let desired = upload_edges(plan);
    for (device, edge) in ifb::owned_interfaces()? {
        if !desired.contains_key(&edge)
            && !matches!(ifb::state(&device)?, Some(ifb::IgsState::Staged) | None)
        {
            ifb::unpublish(&edge)?;
        }
    }
    if desired.is_empty() {
        return Ok(Vec::new());
    }
    let mut published = Vec::new();
    for (edge, device) in desired {
        let peers = upload_peer_macs(plan, &edge);
        let operation = (|| {
            if ifb::device(&edge) != device {
                return Err("nss_igs_mapping_verification_failed".to_owned());
            }
            ensure_no_external_igs_mapping(&edge)?;
            let was_published = ifb::state(&device)? == Some(ifb::IgsState::Published);
            let result = ifb::publish(&edge);
            if !was_published {
                published.push(edge.clone());
            }
            result?;
            if let Err(error) = ifb::sync_peers(&edge, &peers) {
                return match ifb::unpublish(&edge) {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(format!("{error};{cleanup_error}")),
                };
            }
            Ok(())
        })();
        if let Err(error) = operation {
            return match rollback_publications(&published) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!("{error};{cleanup_error}")),
            };
        }
    }
    Ok(published)
}

fn upload_peer_macs(plan: &ControlPlan, edge: &str) -> BTreeSet<crate::identity::MacAddress> {
    plan.rules
        .iter()
        .filter(|rule| {
            rule.interface == edge
                && rule.upload_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD)
        })
        .map(|rule| rule.mac)
        .collect()
}

fn rollback_publications(edges: &[String]) -> Result<(), String> {
    let mut errors = Vec::new();
    for edge in edges {
        if let Err(error) = ifb::unpublish(edge) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(";"))
    }
}

fn ensure_no_external_igs_mapping(edge: &str) -> Result<(), String> {
    if !system::interface_exists(edge) || !system::has_qdisc(edge, "clsact", None)? {
        return Ok(());
    }
    let output = system::output("tc", &["-d", "filter", "show", "dev", edge, "ingress"])?;
    if !output.status.success() {
        return Err("nss_igs_mapping_inspection_failed".into());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "nss_igs_mapping_inspection_failed".to_owned())?;
    if text.lines().any(|line| line.contains("nssmirred")) {
        return Err("nss_igs_mapping_owned_by_external_service".into());
    }
    Ok(())
}

fn cleanup_legacy_igs_mappings() -> Result<(), String> {
    for edge in system::interface_names()? {
        let Some(target) = igs_mapping_target(&edge)? else {
            continue;
        };
        let alias =
            std::fs::read_to_string(format!("/sys/class/net/{target}/ifalias")).unwrap_or_default();
        if alias.trim() != LEGACY_UPLOAD_ALIAS {
            return Err("nss_igs_mapping_owned_by_external_service".into());
        }
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                &edge,
                "ingress",
                "pref",
                &IGS_PREF.to_string(),
                "handle",
                IGS_HANDLE,
                "matchall",
            ],
        )?;
    }
    Ok(())
}

fn igs_mapping_target(edge: &str) -> Result<Option<String>, String> {
    if !system::interface_exists(edge) || !system::has_qdisc(edge, "clsact", None)? {
        return Ok(None);
    }
    let output = system::output(
        "tc",
        &[
            "-d",
            "filter",
            "show",
            "dev",
            edge,
            "ingress",
            "pref",
            &IGS_PREF.to_string(),
        ],
    )?;
    if !output.status.success() {
        return Err("nss_igs_mapping_inspection_failed".into());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "nss_igs_mapping_inspection_failed".to_owned())?;
    parse_igs_mapping(&text, edge)
}

fn parse_igs_mapping(text: &str, edge: &str) -> Result<Option<String>, String> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let header_count = text
        .lines()
        .filter(|line| line.trim_start().starts_with("filter "))
        .count();
    if header_count != 1
        || !text.contains("matchall")
        || !text.lines().any(|line| {
            line.split_ascii_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| {
                    pair[0] == "handle"
                        && (pair[1] == IGS_HANDLE
                            || pair[1].strip_prefix(IGS_HANDLE).is_some_and(|rest| {
                                rest.starts_with('/')
                                    && rest.len() > 1
                                    && rest[1..].bytes().all(|byte| {
                                        byte.is_ascii_hexdigit() || matches!(byte, b'x' | b'X')
                                    })
                            }))
                })
        })
    {
        return Err("nss_igs_mapping_owned_by_external_service".into());
    }
    let prefix = format!("nssmirred ({edge} to device ");
    let Some(rest) = text.split_once(&prefix).map(|(_, rest)| rest) else {
        return Err("nss_igs_mapping_owned_by_external_service".into());
    };
    let Some((target, _)) = rest.split_once(") stolen") else {
        return Err("nss_igs_mapping_owned_by_external_service".into());
    };
    if !system::valid_interface_name(target) {
        return Err("nss_igs_mapping_inspection_failed".into());
    }
    Ok(Some(target.to_owned()))
}

fn stage_upload_hooks(plan: &ControlPlan, blocked_only: bool) -> Result<(), String> {
    let grouped = upload_rules(plan);
    for edge in system::interface_names()? {
        if upload_objects_present(&edge)? && !grouped.contains_key(&edge) {
            cleanup_upload_hook(&edge)?;
        }
    }
    for (edge, rules) in grouped {
        system::ensure_clsact(&edge)?;
        let values = upload_chain_values(&edge)?;
        let jumps = upload_jump_values(&edge)?;
        let device = ifb::device(&edge);
        if (!values.is_empty() || !jumps.is_empty())
            && (!upload_chain_owned(&values, &device)
                || (!jumps.is_empty() && !upload_jump_owned(&jumps)))
        {
            cleanup_upload_hook(&edge)?;
        }
        install_upload_chain(plan, &edge, &rules, blocked_only)?;
        verify_upload_chain(plan, &edge, &rules, blocked_only)?;
    }
    Ok(())
}

fn install_upload_chain(
    plan: &ControlPlan,
    edge: &str,
    rules: &[&ActiveRule],
    blocked_only: bool,
) -> Result<(), String> {
    let values = upload_chain_values(edge)?;
    let matches = upload_match_sets(edge)?;
    let mut desired = BTreeSet::<(u32, String)>::new();
    let chain = UPLOAD_CHAIN.to_string();
    if values.iter().filter(|value| upload_marker(value)).count() != 1 {
        system::run(
            "tc",
            &[
                "filter",
                "replace",
                "dev",
                edge,
                "ingress",
                "chain",
                &chain,
                "protocol",
                "all",
                "pref",
                &UPLOAD_TERMINAL_PREF.to_string(),
                "handle",
                &format!("0x{UPLOAD_CHAIN:x}"),
                "matchall",
                "action",
                "pass",
            ],
        )?;
    }

    let mut pref = UPLOAD_LOCAL_PREF_START;
    for (address, mask) in &plan.local_prefixes {
        let protocol = if address.is_ipv4() { "ip" } else { "ipv6" };
        desired.insert((pref, protocol.into()));
        if filter_action_count(&values, pref, protocol, "gact", "pass", None) != 1
            || exact_u32_match_count(
                &matches,
                pref,
                protocol,
                prefix_u32_matches(Direction::Upload, *address, *mask),
            ) != 1
        {
            replace_upload_prefix_pass(edge, pref, *address, *mask)?;
        }
        pref += 1;
    }
    pref = UPLOAD_BLOCK_PREF_START;
    for rule in rules.iter().filter(|rule| rule.internet_disabled) {
        for protocol in PROTOCOLS {
            desired.insert((pref, protocol.into()));
            if filter_action_count(&values, pref, protocol, "gact", "drop", None) != 1
                || exact_u32_match_count(&matches, pref, protocol, edge_ingress_mac_matches(rule))
                    != 1
            {
                replace_upload_drop(edge, pref, protocol, rule)?;
            }
            pref += 1;
        }
    }
    if !blocked_only {
        pref = UPLOAD_CLIENT_PREF_START;
        for rule in rules.iter().filter(|rule| {
            rule.upload_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD)
        }) {
            for protocol in PROTOCOLS {
                desired.insert((pref, protocol.into()));
                let priority = qdisc_classid(rule.class_minor);
                let target = ifb::device(edge);
                if upload_redirect_action_count(&values, pref, protocol, &priority, &target) != 1
                    || exact_u32_match_count(
                        &matches,
                        pref,
                        protocol,
                        edge_ingress_mac_matches(rule),
                    ) != 1
                {
                    replace_upload_redirect(edge, pref, protocol, rule)?;
                }
                pref += 1;
            }
        }
    }
    remove_stale_u32_slots(edge, "ingress", UPLOAD_CHAIN, &values, &desired)
}

fn replace_upload_prefix_pass(
    edge: &str,
    pref: u32,
    address: IpAddr,
    mask: u8,
) -> Result<(), String> {
    let cidr = format!("{address}/{mask}");
    let (protocol, family) = if address.is_ipv4() {
        ("ip", "ip")
    } else {
        ("ipv6", "ip6")
    };
    system::run(
        "tc",
        &[
            "filter",
            "replace",
            "dev",
            edge,
            "ingress",
            "chain",
            &UPLOAD_CHAIN.to_string(),
            "protocol",
            protocol,
            "pref",
            &pref.to_string(),
            "u32",
            "match",
            family,
            "dst",
            &cidr,
            "action",
            "pass",
        ],
    )
}

fn replace_upload_drop(
    edge: &str,
    pref: u32,
    protocol: &str,
    rule: &ActiveRule,
) -> Result<(), String> {
    add_upload_mac_action(edge, pref, protocol, rule, &["action", "gact", "drop"])
}

fn replace_upload_redirect(
    edge: &str,
    pref: u32,
    protocol: &str,
    rule: &ActiveRule,
) -> Result<(), String> {
    let priority = qdisc_classid(rule.class_minor);
    let target = ifb::device(edge);
    add_upload_mac_action(
        edge,
        pref,
        protocol,
        rule,
        &[
            "action", "skbedit", "priority", &priority, "pipe", "action", "mirred", "egress",
            "redirect", "dev", &target,
        ],
    )
}

fn add_upload_mac_action(
    edge: &str,
    pref: u32,
    protocol: &str,
    rule: &ActiveRule,
    action: &[&str],
) -> Result<(), String> {
    let mut args = vec![
        "filter".to_owned(),
        "replace".to_owned(),
        "dev".to_owned(),
        edge.to_owned(),
        "ingress".to_owned(),
        "chain".to_owned(),
        UPLOAD_CHAIN.to_string(),
        "protocol".to_owned(),
        protocol.to_owned(),
        "pref".to_owned(),
        pref.to_string(),
        "u32".to_owned(),
    ];
    // QCA's `match ether src` expansion does not retain both selector words
    // with subsequent actions. Use the raw physical-edge ingress source-MAC
    // layout so every selector word and the full action list stay in one u32
    // filter.
    for value in edge_ingress_mac_matches(rule) {
        args.extend([
            "match".to_owned(),
            "u32".to_owned(),
            format!("0x{}", value.value),
            format!("0x{}", value.mask),
            "at".to_owned(),
            value.offset.to_string(),
        ]);
    }
    args.extend(action.iter().map(|value| (*value).to_owned()));
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    system::run("tc", &refs)
}

fn edge_ingress_mac_matches(rule: &ActiveRule) -> Vec<system::TcU32Match> {
    mac_u32_matches(Direction::Upload, rule.mac)
}

fn activate_upload_hooks(plan: &ControlPlan, blocked_only: bool) -> Result<(), String> {
    let grouped = upload_rules(plan);
    for edge in grouped.keys() {
        let jumps = upload_jump_values(edge)?;
        if !jumps.is_empty() {
            if !upload_jump_owned(&jumps) {
                return Err("cpu_path_classifier_owned_by_external_service".into());
            }
            continue;
        }
        system::run(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                edge,
                "ingress",
                "protocol",
                "all",
                "pref",
                &UPLOAD_JUMP_PREF.to_string(),
                "handle",
                &format!("0x{UPLOAD_CHAIN:x}"),
                "matchall",
                "action",
                "goto",
                "chain",
                &UPLOAD_CHAIN.to_string(),
            ],
        )?;
    }
    verify_upload_hooks(plan, blocked_only)
}

fn deactivate_upload_hooks() -> Result<(), String> {
    for edge in system::interface_names()? {
        let jumps = upload_jump_values(&edge)?;
        if jumps.is_empty() {
            continue;
        }
        if !upload_jump_owned(&jumps) {
            return Err("cpu_path_classifier_owned_by_external_service".into());
        }
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                &edge,
                "ingress",
                "pref",
                &UPLOAD_JUMP_PREF.to_string(),
                "handle",
                &format!("0x{UPLOAD_CHAIN:x}"),
                "matchall",
            ],
        )?;
    }
    Ok(())
}

fn verify_upload_hooks(plan: &ControlPlan, blocked_only: bool) -> Result<(), String> {
    let grouped = upload_rules(plan);
    for (edge, rules) in &grouped {
        verify_upload_chain(plan, edge, rules, blocked_only)?;
        let jumps = upload_jump_values(edge)?;
        if !upload_jump_owned(&jumps) {
            return Err("cpu_path_classifier_missing".into());
        }
    }
    for edge in system::interface_names()? {
        if upload_objects_present(&edge)? && !grouped.contains_key(&edge) {
            return Err("cpu_path_classifier_stale".into());
        }
    }
    Ok(())
}

fn verify_upload_chain(
    plan: &ControlPlan,
    edge: &str,
    rules: &[&ActiveRule],
    blocked_only: bool,
) -> Result<(), String> {
    let values = upload_chain_values(edge)?;
    let matches = upload_match_sets(edge)?;
    let shaped = if blocked_only {
        0
    } else {
        rules
            .iter()
            .filter(|rule| {
                rule.upload_bps != 0
                    && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD)
            })
            .count()
    };
    let blocked = rules.iter().filter(|rule| rule.internet_disabled).count();
    let expected = 1usize
        .saturating_add(plan.local_prefixes.len())
        .saturating_add(blocked.saturating_mul(PROTOCOLS.len()))
        .saturating_add(shaped.saturating_mul(PROTOCOLS.len()));
    if values.len() != expected
        || matches.len() != expected.saturating_sub(1)
        || values.iter().filter(|value| upload_marker(value)).count() != 1
    {
        return Err("cpu_path_classifier_missing".into());
    }
    let mut pref = UPLOAD_LOCAL_PREF_START;
    for (address, mask) in &plan.local_prefixes {
        let protocol = if address.is_ipv4() { "ip" } else { "ipv6" };
        if filter_action_count(&values, pref, protocol, "gact", "pass", None) != 1
            || exact_u32_match_count(
                &matches,
                pref,
                protocol,
                prefix_u32_matches(Direction::Upload, *address, *mask),
            ) != 1
        {
            return Err("cpu_path_classifier_missing".into());
        }
        pref += 1;
    }
    pref = UPLOAD_BLOCK_PREF_START;
    for rule in rules.iter().filter(|rule| rule.internet_disabled) {
        for protocol in PROTOCOLS {
            if filter_action_count(&values, pref, protocol, "gact", "drop", None) != 1
                || exact_u32_match_count(&matches, pref, protocol, edge_ingress_mac_matches(rule))
                    != 1
            {
                return Err("cpu_path_classifier_missing".into());
            }
            pref += 1;
        }
    }
    if !blocked_only {
        pref = UPLOAD_CLIENT_PREF_START;
        let target = ifb::device(edge);
        for rule in rules.iter().filter(|rule| {
            rule.upload_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD)
        }) {
            let priority = qdisc_classid(rule.class_minor);
            for protocol in PROTOCOLS {
                if upload_redirect_action_count(&values, pref, protocol, &priority, &target) != 1
                    || exact_u32_match_count(
                        &matches,
                        pref,
                        protocol,
                        edge_ingress_mac_matches(rule),
                    ) != 1
                {
                    return Err("cpu_path_classifier_missing".into());
                }
                pref += 1;
            }
        }
    }
    Ok(())
}

fn cleanup_upload_hook(edge: &str) -> Result<(), String> {
    if !system::interface_exists(edge) || !system::has_qdisc(edge, "clsact", None)? {
        return Ok(());
    }
    let values = upload_chain_values(edge)?;
    let jumps = upload_jump_values(edge)?;
    if values.is_empty() && jumps.is_empty() {
        return Ok(());
    }
    let device = ifb::device(edge);
    if (!values.is_empty()
        && !upload_chain_owned(&values, &device)
        && !legacy_colliding_upload_chain_owned(&values, &device))
        || (!jumps.is_empty() && !upload_jump_owned(&jumps))
    {
        return Err("cpu_path_classifier_owned_by_external_service".into());
    }
    if !jumps.is_empty() {
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                edge,
                "ingress",
                "pref",
                &UPLOAD_JUMP_PREF.to_string(),
                "handle",
                &format!("0x{UPLOAD_CHAIN:x}"),
                "matchall",
            ],
        )?;
    }
    if !values.is_empty() {
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                edge,
                "ingress",
                "chain",
                &UPLOAD_CHAIN.to_string(),
            ],
        )?;
    }
    Ok(())
}

fn upload_objects_present(edge: &str) -> Result<bool, String> {
    let values = upload_chain_values(edge)?;
    let jumps = upload_jump_values(edge)?;
    if values.is_empty() && jumps.is_empty() {
        return Ok(false);
    }
    let device = ifb::device(edge);
    if (values.is_empty()
        || upload_chain_owned(&values, &device)
        || legacy_colliding_upload_chain_owned(&values, &device))
        && (jumps.is_empty() || upload_jump_owned(&jumps))
    {
        Ok(true)
    } else {
        Err("cpu_path_classifier_owned_by_external_service".into())
    }
}

fn upload_chain_owned(values: &[Value], device: &str) -> bool {
    values.iter().filter(|value| upload_marker(value)).count() == 1
        && values
            .iter()
            .all(|value| upload_cleanup_owned_entry(value, device))
}

fn legacy_colliding_upload_chain_owned(values: &[Value], device: &str) -> bool {
    values
        .iter()
        .filter(|value| {
            exact_matchall_action(value, TERMINAL_PREF, Some(UPLOAD_CHAIN), "pass", None)
        })
        .count()
        == 1
        && values.iter().all(|value| {
            if exact_matchall_action(value, TERMINAL_PREF, Some(UPLOAD_CHAIN), "pass", None) {
                return true;
            }
            legacy_colliding_upload_entry(value, device)
        })
}

fn legacy_colliding_upload_entry(value: &Value, device: &str) -> bool {
    if !matches!(
        value.get("protocol").and_then(Value::as_str),
        Some("ip" | "ipv6")
    ) || value.get("kind").and_then(Value::as_str) != Some("u32")
    {
        return false;
    }
    let Some(pref) = value.get("pref").and_then(Value::as_u64) else {
        return false;
    };
    let Some(actions) = value
        .get("options")
        .and_then(Value::as_object)
        .and_then(|options| options.get("actions"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    if (u64::from(LOCAL_PREF_START)..u64::from(BLOCK_PREF_START)).contains(&pref) {
        return exact_gact_actions(actions, "pass");
    }
    if (u64::from(BLOCK_PREF_START)..u64::from(CLIENT_PREF_START)).contains(&pref) {
        return exact_gact_actions(actions, "drop");
    }
    (u64::from(CLIENT_PREF_START)..u64::from(TERMINAL_PREF)).contains(&pref)
        && exact_upload_redirect_actions(actions, None, device)
}

fn upload_jump_owned(values: &[Value]) -> bool {
    values.len() == 1 && upload_jump_marker(&values[0])
}

fn upload_cleanup_owned_entry(value: &Value, device: &str) -> bool {
    if upload_marker(value) {
        return true;
    }
    if !matches!(
        value.get("protocol").and_then(Value::as_str),
        Some("ip" | "ipv6")
    ) || value.get("kind").and_then(Value::as_str) != Some("u32")
    {
        return false;
    }
    let Some(pref) = value.get("pref").and_then(Value::as_u64) else {
        return false;
    };
    let Some(actions) = value
        .get("options")
        .and_then(Value::as_object)
        .and_then(|options| options.get("actions"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    if (u64::from(UPLOAD_LOCAL_PREF_START)..u64::from(UPLOAD_BLOCK_PREF_START)).contains(&pref) {
        return exact_gact_actions(actions, "pass");
    }
    if (u64::from(UPLOAD_BLOCK_PREF_START)..u64::from(UPLOAD_CLIENT_PREF_START)).contains(&pref) {
        return exact_gact_actions(actions, "drop");
    }
    (u64::from(UPLOAD_CLIENT_PREF_START)..u64::from(UPLOAD_TERMINAL_PREF)).contains(&pref)
        && exact_upload_redirect_actions(actions, None, device)
}

fn exact_gact_actions(actions: &[Value], action_type: &str) -> bool {
    actions.len() == 1
        && actions[0].get("kind").and_then(Value::as_str) == Some("gact")
        && actions[0]
            .get("control_action")
            .and_then(|control| control.get("type"))
            .and_then(Value::as_str)
            == Some(action_type)
}

fn exact_upload_redirect_actions(actions: &[Value], priority: Option<&str>, device: &str) -> bool {
    actions.len() == 2
        && actions[0].get("kind").and_then(Value::as_str) == Some("skbedit")
        && actions[0]
            .get("control_action")
            .and_then(|control| control.get("type"))
            .and_then(Value::as_str)
            == Some("pipe")
        && actions[0]
            .get("priority")
            .and_then(Value::as_str)
            .is_some_and(|actual| {
                priority.is_none_or(|expected| tc_classids_equal(actual, expected))
            })
        && actions[1].get("kind").and_then(Value::as_str) == Some("mirred")
        && actions[1].get("mirred_action").and_then(Value::as_str) == Some("redirect")
        && actions[1].get("direction").and_then(Value::as_str) == Some("egress")
        && actions[1]
            .get("to_dev")
            .and_then(Value::as_str)
            .is_some_and(|actual| {
                /* qca_nss_qdisc hides an offloaded mirred target as `*` in
                 * tc -j output. The surrounding LAN Speed marker and the
                 * deterministic lsu IFB ownership check still identify this
                 * chain; rejecting the hidden target makes every retry look
                 * like a foreign classifier and prevents rollback. */
                actual == device || (actual == "*" && is_lanspeed_ifb_name(device))
            })
        && actions[1]
            .get("control_action")
            .and_then(|control| control.get("type"))
            .and_then(Value::as_str)
            == Some("stolen")
}

fn is_lanspeed_ifb_name(device: &str) -> bool {
    let Some(suffix) = device.strip_prefix("lsu") else {
        return false;
    };
    suffix.len() == 8 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn upload_redirect_action_count(
    values: &[Value],
    pref: u32,
    protocol: &str,
    priority: &str,
    device: &str,
) -> usize {
    values
        .iter()
        .filter(|value| {
            value.get("kind").and_then(Value::as_str) == Some("u32")
                && value.get("pref").and_then(Value::as_u64) == Some(u64::from(pref))
                && value.get("protocol").and_then(Value::as_str) == Some(protocol)
                && value
                    .get("options")
                    .and_then(|options| options.get("actions"))
                    .and_then(Value::as_array)
                    .is_some_and(|actions| {
                        exact_upload_redirect_actions(actions, Some(priority), device)
                    })
        })
        .count()
}

fn upload_chain_values(edge: &str) -> Result<Vec<Value>, String> {
    filter_values(edge, "ingress", Some(UPLOAD_CHAIN), None)
}

fn upload_match_sets(edge: &str) -> Result<Vec<system::TcU32MatchSet>, String> {
    if !system::interface_exists(edge) || !system::has_qdisc(edge, "clsact", None)? {
        return Ok(Vec::new());
    }
    let output = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            edge,
            "ingress",
            "chain",
            &UPLOAD_CHAIN.to_string(),
        ],
    )?;
    if !output.status.success() {
        return Err("cpu_path_classifier_inspection_failed".into());
    }
    system::tc_u32_match_sets(&output.stdout, "cpu_path_classifier_inspection_failed")
}

fn upload_jump_values(edge: &str) -> Result<Vec<Value>, String> {
    filter_values(edge, "ingress", None, Some(UPLOAD_JUMP_PREF))
}

fn upload_marker(value: &Value) -> bool {
    exact_matchall_action(
        value,
        UPLOAD_TERMINAL_PREF,
        Some(UPLOAD_CHAIN),
        "pass",
        None,
    )
}

fn upload_jump_marker(value: &Value) -> bool {
    exact_matchall_action(
        value,
        UPLOAD_JUMP_PREF,
        Some(UPLOAD_CHAIN),
        "goto",
        Some(UPLOAD_CHAIN),
    )
}

fn sync_download_hooks(plan: &ControlPlan, blocked_only: bool) -> Result<(), String> {
    let grouped = download_rules(plan);
    for edge in system::interface_names()? {
        if download_owned(&edge)? && !grouped.contains_key(&edge) {
            cleanup_download_hook(&edge)?;
        }
    }
    for (edge, rules) in grouped {
        system::ensure_clsact(&edge)?;
        let values = download_chain_values(&edge)?;
        let jumps = download_jump_values(&edge)?;
        if (!values.is_empty() || !jumps.is_empty())
            && (!download_chain_owned(&values) || !download_jump_owned(&jumps))
        {
            cleanup_download_hook(&edge)?;
        }
        install_download_hook(plan, &edge, &rules, blocked_only)?;
    }
    Ok(())
}

fn install_download_hook(
    plan: &ControlPlan,
    edge: &str,
    rules: &[&ActiveRule],
    blocked_only: bool,
) -> Result<(), String> {
    let values = download_chain_values(edge)?;
    let matches = download_match_sets(edge)?;
    let jumps = download_jump_values(edge)?;
    let mut desired = BTreeSet::<(u32, String)>::new();
    let chain = DOWNLOAD_CHAIN.to_string();
    if values.iter().filter(|value| download_marker(value)).count() != 1 {
        system::run(
            "tc",
            &[
                "filter",
                "replace",
                "dev",
                edge,
                "egress",
                "chain",
                &chain,
                "protocol",
                "all",
                "pref",
                &TERMINAL_PREF.to_string(),
                "handle",
                &format!("0x{DOWNLOAD_CHAIN:x}"),
                "matchall",
                "action",
                "pass",
            ],
        )?;
    }
    let mut pref = LOCAL_PREF_START;
    for (address, mask) in &plan.local_prefixes {
        let protocol = if address.is_ipv4() { "ip" } else { "ipv6" };
        desired.insert((pref, protocol.into()));
        if filter_action_count(&values, pref, protocol, "gact", "pass", None) != 1
            || exact_u32_match_count(
                &matches,
                pref,
                protocol,
                prefix_u32_matches(Direction::Download, *address, *mask),
            ) != 1
        {
            replace_download_prefix_pass(edge, pref, *address, *mask)?;
        }
        pref += 1;
    }
    pref = BLOCK_PREF_START;
    for rule in rules.iter().filter(|rule| rule.internet_disabled) {
        for protocol in PROTOCOLS {
            desired.insert((pref, protocol.into()));
            if filter_action_count(&values, pref, protocol, "gact", "drop", None) != 1
                || exact_u32_match_count(
                    &matches,
                    pref,
                    protocol,
                    mac_u32_matches(Direction::Download, rule.mac),
                ) != 1
            {
                replace_download_drop(edge, pref, protocol, rule)?;
            }
            pref += 1;
        }
    }
    if !blocked_only {
        pref = CLIENT_PREF_START;
        for rule in rules.iter().filter(|rule| {
            rule.download_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
        }) {
            for protocol in PROTOCOLS {
                desired.insert((pref, protocol.into()));
                let priority = qdisc_classid(rule.class_minor);
                if filter_action_count(&values, pref, protocol, "skbedit", "pipe", Some(&priority))
                    != 1
                    || exact_u32_match_count(
                        &matches,
                        pref,
                        protocol,
                        mac_u32_matches(Direction::Download, rule.mac),
                    ) != 1
                {
                    replace_download_priority(edge, pref, protocol, rule)?;
                }
                pref += 1;
            }
        }
    }
    remove_stale_u32_slots(edge, "egress", DOWNLOAD_CHAIN, &values, &desired)?;
    if !download_jump_owned(&jumps) {
        system::run(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                edge,
                "egress",
                "protocol",
                "all",
                "pref",
                &DOWNLOAD_JUMP_PREF.to_string(),
                "handle",
                &format!("0x{DOWNLOAD_CHAIN:x}"),
                "matchall",
                "action",
                "goto",
                "chain",
                &chain,
            ],
        )?;
    }
    Ok(())
}

fn replace_download_prefix_pass(
    edge: &str,
    pref: u32,
    address: IpAddr,
    mask: u8,
) -> Result<(), String> {
    let cidr = format!("{address}/{mask}");
    let (protocol, family) = if address.is_ipv4() {
        ("ip", "ip")
    } else {
        ("ipv6", "ip6")
    };
    system::run(
        "tc",
        &[
            "filter",
            "replace",
            "dev",
            edge,
            "egress",
            "chain",
            &DOWNLOAD_CHAIN.to_string(),
            "protocol",
            protocol,
            "pref",
            &pref.to_string(),
            "u32",
            "match",
            family,
            "src",
            &cidr,
            "action",
            "pass",
        ],
    )
}

fn replace_download_drop(
    edge: &str,
    pref: u32,
    protocol: &str,
    rule: &ActiveRule,
) -> Result<(), String> {
    system::run(
        "tc",
        &[
            "filter",
            "replace",
            "dev",
            edge,
            "egress",
            "chain",
            &DOWNLOAD_CHAIN.to_string(),
            "protocol",
            protocol,
            "pref",
            &pref.to_string(),
            "u32",
            "match",
            "ether",
            "dst",
            &rule.mac.to_string(),
            "action",
            "gact",
            "drop",
        ],
    )
}

fn replace_download_priority(
    edge: &str,
    pref: u32,
    protocol: &str,
    rule: &ActiveRule,
) -> Result<(), String> {
    system::run(
        "tc",
        &[
            "filter",
            "replace",
            "dev",
            edge,
            "egress",
            "chain",
            &DOWNLOAD_CHAIN.to_string(),
            "protocol",
            protocol,
            "pref",
            &pref.to_string(),
            "u32",
            "match",
            "ether",
            "dst",
            &rule.mac.to_string(),
            "action",
            "skbedit",
            "priority",
            &qdisc_classid(rule.class_minor),
        ],
    )
}

fn verify_download_hooks(plan: &ControlPlan) -> Result<(), String> {
    let grouped = download_rules(plan);
    for (edge, rules) in &grouped {
        let values = download_chain_values(edge)?;
        let matches = download_match_sets(edge)?;
        let jumps = download_jump_values(edge)?;
        let shaped = rules
            .iter()
            .filter(|rule| {
                rule.download_bps != 0
                    && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
            })
            .count();
        let blocked = rules.iter().filter(|rule| rule.internet_disabled).count();
        let expected = 1usize
            .saturating_add(plan.local_prefixes.len())
            .saturating_add(blocked.saturating_mul(PROTOCOLS.len()))
            .saturating_add(shaped.saturating_mul(PROTOCOLS.len()));
        if values.len() != expected
            || matches.len() != expected.saturating_sub(1)
            || values.iter().filter(|value| download_marker(value)).count() != 1
            || jumps.len() != 1
            || !download_jump_marker(&jumps[0])
        {
            return Err("cpu_path_classifier_missing".into());
        }
        let mut pref = LOCAL_PREF_START;
        for (address, mask) in &plan.local_prefixes {
            let protocol = if address.is_ipv4() { "ip" } else { "ipv6" };
            if filter_action_count(&values, pref, protocol, "gact", "pass", None) != 1
                || exact_u32_match_count(
                    &matches,
                    pref,
                    protocol,
                    prefix_u32_matches(Direction::Download, *address, *mask),
                ) != 1
            {
                return Err("cpu_path_classifier_missing".into());
            }
            pref += 1;
        }
        pref = BLOCK_PREF_START;
        for rule in rules.iter().filter(|rule| rule.internet_disabled) {
            for protocol in PROTOCOLS {
                if filter_action_count(&values, pref, protocol, "gact", "drop", None) != 1
                    || exact_u32_match_count(
                        &matches,
                        pref,
                        protocol,
                        mac_u32_matches(Direction::Download, rule.mac),
                    ) != 1
                {
                    return Err("cpu_path_classifier_missing".into());
                }
                pref += 1;
            }
        }
        pref = CLIENT_PREF_START;
        for rule in rules.iter().filter(|rule| {
            rule.download_bps != 0
                && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
        }) {
            let priority = qdisc_classid(rule.class_minor);
            for protocol in PROTOCOLS {
                if filter_action_count(&values, pref, protocol, "skbedit", "pipe", Some(&priority))
                    != 1
                    || exact_u32_match_count(
                        &matches,
                        pref,
                        protocol,
                        mac_u32_matches(Direction::Download, rule.mac),
                    ) != 1
                {
                    return Err("cpu_path_classifier_missing".into());
                }
                pref += 1;
            }
        }
    }
    for edge in system::interface_names()? {
        if download_owned(&edge)? && !grouped.contains_key(&edge) {
            return Err("cpu_path_classifier_stale".into());
        }
    }
    Ok(())
}

fn cleanup_download_hook(edge: &str) -> Result<(), String> {
    if !system::interface_exists(edge) || !system::has_qdisc(edge, "clsact", None)? {
        return Ok(());
    }
    let values = download_chain_values(edge)?;
    let jumps = download_jump_values(edge)?;
    if values.is_empty() && jumps.is_empty() {
        return Ok(());
    }
    let chain_owned = values.is_empty() || download_chain_owned(&values);
    let jump_owned = jumps.is_empty() || download_jump_owned(&jumps);
    // A daemon crash can leave the exact LAN Speed chain after its entry
    // jump has disappeared. Reclaim only a complete, kernel-reported LAN
    // Speed chain or jump; any unknown entry remains external ownership.
    if !chain_owned || !jump_owned {
        return Err("cpu_path_classifier_owned_by_external_service".into());
    }
    if !jumps.is_empty() {
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                edge,
                "egress",
                "pref",
                &DOWNLOAD_JUMP_PREF.to_string(),
                "handle",
                &format!("0x{DOWNLOAD_CHAIN:x}"),
                "matchall",
            ],
        )?;
    }
    if !values.is_empty() {
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                edge,
                "egress",
                "chain",
                &DOWNLOAD_CHAIN.to_string(),
            ],
        )?;
    }
    Ok(())
}

fn download_owned(edge: &str) -> Result<bool, String> {
    let values = download_chain_values(edge)?;
    let jumps = download_jump_values(edge)?;
    Ok(download_chain_owned(&values) && download_jump_owned(&jumps))
}

fn download_chain_owned(values: &[Value]) -> bool {
    values.iter().filter(|value| download_marker(value)).count() == 1
        && values.iter().all(download_cleanup_owned_entry)
}

fn download_jump_owned(values: &[Value]) -> bool {
    values.len() == 1 && download_jump_marker(&values[0])
}

fn download_cleanup_owned_entry(value: &Value) -> bool {
    if download_marker(value) {
        return true;
    }
    let protocol = value.get("protocol").and_then(Value::as_str);
    if !matches!(protocol, Some("ip" | "ipv6"))
        || value.get("kind").and_then(Value::as_str) != Some("u32")
    {
        return false;
    }
    let Some(pref) = value.get("pref").and_then(Value::as_u64) else {
        return false;
    };
    let Some(actions) = value
        .get("options")
        .and_then(Value::as_object)
        .and_then(|options| options.get("actions"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    if actions.len() != 1 {
        return false;
    }
    let action = &actions[0];
    let kind = action.get("kind").and_then(Value::as_str);
    let action_type = action
        .get("control_action")
        .and_then(|control| control.get("type"))
        .and_then(Value::as_str);
    match (kind, action_type) {
        (Some("gact"), Some("pass")) => {
            (u64::from(LOCAL_PREF_START)..u64::from(BLOCK_PREF_START)).contains(&pref)
        }
        (Some("gact"), Some("drop")) => {
            (u64::from(BLOCK_PREF_START)..u64::from(CLIENT_PREF_START)).contains(&pref)
        }
        (Some("skbedit"), Some("pipe")) => {
            (u64::from(CLIENT_PREF_START)..u64::from(TERMINAL_PREF)).contains(&pref)
        }
        (Some("mirred"), Some("stolen")) => {
            (u64::from(CLIENT_PREF_START)..u64::from(TERMINAL_PREF)).contains(&pref)
                && action.get("mirred_action").and_then(Value::as_str) == Some("redirect")
        }
        _ => false,
    }
}

fn download_chain_values(edge: &str) -> Result<Vec<Value>, String> {
    filter_values(edge, "egress", Some(DOWNLOAD_CHAIN), None)
}

fn download_match_sets(edge: &str) -> Result<Vec<system::TcU32MatchSet>, String> {
    if !system::interface_exists(edge) || !system::has_qdisc(edge, "clsact", None)? {
        return Ok(Vec::new());
    }
    let output = system::output(
        "tc",
        &[
            "-j",
            "-d",
            "filter",
            "show",
            "dev",
            edge,
            "egress",
            "chain",
            &DOWNLOAD_CHAIN.to_string(),
        ],
    )?;
    if !output.status.success() {
        return Err("cpu_path_classifier_inspection_failed".into());
    }
    system::tc_u32_match_sets(&output.stdout, "cpu_path_classifier_inspection_failed")
}

fn download_jump_values(edge: &str) -> Result<Vec<Value>, String> {
    filter_values(edge, "egress", None, Some(DOWNLOAD_JUMP_PREF))
}

fn filter_values(
    edge: &str,
    hook: &str,
    chain: Option<u32>,
    pref: Option<u32>,
) -> Result<Vec<Value>, String> {
    if !system::interface_exists(edge) || !system::has_qdisc(edge, "clsact", None)? {
        return Ok(Vec::new());
    }
    let mut args = vec!["-j", "-d", "filter", "show", "dev", edge, hook];
    let chain_text;
    if let Some(chain) = chain {
        chain_text = chain.to_string();
        args.extend(["chain", &chain_text]);
    }
    let pref_text;
    if let Some(pref) = pref {
        pref_text = pref.to_string();
        args.extend(["pref", &pref_text]);
    }
    let output = system::output("tc", &args)?;
    if !output.status.success() {
        return Err("cpu_path_classifier_inspection_failed".into());
    }
    if let Some(pref) = pref {
        system::tc_filter_values_at_pref(
            &output.stdout,
            pref,
            "cpu_path_classifier_inspection_failed",
        )
    } else {
        system::tc_filter_values(&output.stdout, "cpu_path_classifier_inspection_failed")
    }
}

fn remove_stale_u32_slots(
    edge: &str,
    hook: &str,
    chain: u32,
    previous: &[Value],
    desired: &BTreeSet<(u32, String)>,
) -> Result<(), String> {
    for (pref, protocol) in stale_u32_slots(previous, desired) {
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                edge,
                hook,
                "chain",
                &chain.to_string(),
                "protocol",
                &protocol,
                "pref",
                &pref.to_string(),
                "u32",
            ],
        )?;
    }
    Ok(())
}

fn stale_u32_slots(
    previous: &[Value],
    desired: &BTreeSet<(u32, String)>,
) -> BTreeSet<(u32, String)> {
    previous
        .iter()
        .filter(|value| value.get("kind").and_then(Value::as_str) == Some("u32"))
        .filter_map(|value| {
            let pref = value.get("pref")?.as_u64()?.try_into().ok()?;
            let protocol = value.get("protocol")?.as_str()?.to_owned();
            (!desired.contains(&(pref, protocol.clone()))).then_some((pref, protocol))
        })
        .collect()
}

fn download_marker(value: &Value) -> bool {
    exact_matchall_action(value, TERMINAL_PREF, Some(DOWNLOAD_CHAIN), "pass", None)
}

fn download_jump_marker(value: &Value) -> bool {
    exact_matchall_action(
        value,
        DOWNLOAD_JUMP_PREF,
        Some(DOWNLOAD_CHAIN),
        "goto",
        Some(DOWNLOAD_CHAIN),
    )
}

fn cleanup_legacy_upload_hooks() -> Result<(), String> {
    for edge in system::interface_names()? {
        let values = filter_values(&edge, "ingress", Some(LEGACY_UPLOAD_CHAIN), None)?;
        let jumps = filter_values(&edge, "ingress", None, Some(DOWNLOAD_JUMP_PREF))?;
        let marker = values.iter().any(|value| {
            exact_matchall_action(
                value,
                TERMINAL_PREF,
                Some(LEGACY_UPLOAD_CHAIN),
                "pass",
                None,
            )
        });
        let jump = jumps.iter().any(|value| {
            exact_matchall_action(
                value,
                DOWNLOAD_JUMP_PREF,
                Some(LEGACY_UPLOAD_CHAIN),
                "goto",
                Some(LEGACY_UPLOAD_CHAIN),
            )
        });
        if !marker && !jump {
            continue;
        }
        if !marker || !jump {
            return Err("cpu_path_classifier_owned_by_external_service".into());
        }
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                &edge,
                "ingress",
                "pref",
                &DOWNLOAD_JUMP_PREF.to_string(),
                "handle",
                &format!("0x{LEGACY_UPLOAD_CHAIN:x}"),
                "matchall",
            ],
        )?;
        system::run(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                &edge,
                "ingress",
                "chain",
                &LEGACY_UPLOAD_CHAIN.to_string(),
            ],
        )?;
    }
    Ok(())
}

fn qdisc_classid(minor: u16) -> String {
    format!("{minor:x}:0")
}

fn exact_matchall_action(
    value: &Value,
    pref: u32,
    handle: Option<u32>,
    action_type: &str,
    goto_chain: Option<u32>,
) -> bool {
    if value.get("kind").and_then(Value::as_str) != Some("matchall")
        || value.get("protocol").and_then(Value::as_str) != Some("all")
        || value.get("pref").and_then(Value::as_u64) != Some(u64::from(pref))
    {
        return false;
    }
    let Some(options) = value.get("options") else {
        return false;
    };
    if handle.is_some_and(|handle| {
        options.get("handle").and_then(Value::as_u64) != Some(u64::from(handle))
    }) {
        return false;
    }
    let Some(actions) = options.get("actions").and_then(Value::as_array) else {
        return false;
    };
    if actions.len() != 1 || actions[0].get("kind").and_then(Value::as_str) != Some("gact") {
        return false;
    }
    let Some(control) = actions[0].get("control_action") else {
        return false;
    };
    control.get("type").and_then(Value::as_str) == Some(action_type)
        && goto_chain.is_none_or(|chain| {
            control.get("chain").and_then(Value::as_u64) == Some(u64::from(chain))
        })
}

fn filter_action_count(
    values: &[Value],
    pref: u32,
    protocol: &str,
    kind: &str,
    action_type: &str,
    priority: Option<&str>,
) -> usize {
    values
        .iter()
        .filter(|value| {
            value.get("kind").and_then(Value::as_str) == Some("u32")
                && value.get("pref").and_then(Value::as_u64) == Some(u64::from(pref))
                && value.get("protocol").and_then(Value::as_str) == Some(protocol)
                && value.get("options").is_some_and(|options| {
                    options
                        .get("actions")
                        .and_then(Value::as_array)
                        .is_some_and(|actions| {
                            actions.len() == 1
                                && actions[0].get("kind").and_then(Value::as_str) == Some(kind)
                                && serde_json::to_string(&actions[0]).is_ok_and(|text| {
                                    text.contains(action_type)
                                        && priority.is_none_or(|priority| {
                                            actions[0]
                                                .get("priority")
                                                .and_then(Value::as_str)
                                                .is_some_and(|actual| {
                                                    tc_classids_equal(actual, priority)
                                                })
                                        })
                                })
                        })
                })
        })
        .count()
}

fn tc_classids_equal(left: &str, right: &str) -> bool {
    fn parse(value: &str) -> Option<(u16, u16)> {
        let (major, minor) = value.split_once(':')?;
        let major = u16::from_str_radix(major.trim_start_matches("0x"), 16).ok()?;
        let minor = if minor.is_empty() {
            0
        } else {
            u16::from_str_radix(minor.trim_start_matches("0x"), 16).ok()?
        };
        Some((major, minor))
    }
    parse(left).is_some_and(|left| Some(left) == parse(right))
}

#[cfg(test)]
include!("classifier/tests.rs");
