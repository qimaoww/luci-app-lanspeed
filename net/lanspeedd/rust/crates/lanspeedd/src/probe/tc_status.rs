use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Map, Value};

use super::tc::{
    handles_equal, LANSPEED_EARLY_HANDLE, LANSPEED_EARLY_PREF, LANSPEED_HANDLE, LANSPEED_PREF,
};

const MAX_TC_OBJECTS: usize = 2_048;
const LANSPEED_ROOT_MAJORS: [&str; 5] = ["7a10", "7a20", "7d00", "7e20", "7e30"];
const LANSPEED_STATIC_IFBS: [&str; 3] = ["ifb-lanspeed", "ifb-nss-lsu", "ifb-nss-lsd"];

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TcCounters {
    pub bytes: Option<u64>,
    pub packets: Option<u64>,
    pub drops: Option<u64>,
    pub overlimits: Option<u64>,
    pub backlog: Option<u64>,
    pub requeues: Option<u64>,
    pub qlen: Option<u64>,
    pub maxpacket: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TcQdiscStatus {
    pub interface: String,
    pub kind: String,
    pub handle: String,
    pub parent: Option<String>,
    pub root: bool,
    pub ingress_block: Option<u32>,
    pub egress_block: Option<u32>,
    pub owner: String,
    pub detail: Option<String>,
    pub counters: TcCounters,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TcClassStatus {
    pub interface: String,
    pub kind: String,
    pub handle: String,
    pub parent: Option<String>,
    pub owner: String,
    pub detail: Option<String>,
    pub counters: TcCounters,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TcFilterStatus {
    pub interface: String,
    pub direction: String,
    pub parent: Option<String>,
    pub chain: u32,
    pub pref: u32,
    pub handle: String,
    pub kind: String,
    pub protocol: Option<String>,
    pub owner: String,
    pub program_name: Option<String>,
    pub program_id: Option<u32>,
    pub direct_action: Option<bool>,
    pub in_hw: Option<bool>,
    pub action: Option<String>,
    pub terminal_action: bool,
    pub counters: TcCounters,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct TcStatusConflict {
    pub id: String,
    pub severity: String,
    pub interface: String,
    pub direction: String,
    pub object: String,
    pub owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TcHostStatus {
    pub state: String,
    pub scan_complete: bool,
    pub qdisc_scan: bool,
    pub class_scan: bool,
    pub filter_scan: bool,
    pub command_output_truncated: bool,
    pub objects_truncated: bool,
    pub parse_errors: usize,
    pub interface_count: usize,
    pub qdisc_count: usize,
    pub class_count: usize,
    pub filter_count: usize,
    pub lanspeed_objects: usize,
    pub foreign_objects: usize,
    pub qdiscs: Vec<TcQdiscStatus>,
    pub classes: Vec<TcClassStatus>,
    pub filters: Vec<TcFilterStatus>,
    pub conflicts: Vec<TcStatusConflict>,
}

impl Default for TcHostStatus {
    fn default() -> Self {
        Self {
            state: "unavailable".into(),
            scan_complete: false,
            qdisc_scan: false,
            class_scan: false,
            filter_scan: false,
            command_output_truncated: false,
            objects_truncated: false,
            parse_errors: 0,
            interface_count: 0,
            qdisc_count: 0,
            class_count: 0,
            filter_count: 0,
            lanspeed_objects: 0,
            foreign_objects: 0,
            qdiscs: Vec::new(),
            classes: Vec::new(),
            filters: Vec::new(),
            conflicts: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcDumpPart<T> {
    pub ok: bool,
    pub command_output_truncated: bool,
    pub objects_truncated: bool,
    pub parse_errors: usize,
    pub objects: Vec<T>,
}

impl<T> Default for TcDumpPart<T> {
    fn default() -> Self {
        Self {
            ok: false,
            command_output_truncated: false,
            objects_truncated: false,
            parse_errors: 0,
            objects: Vec::new(),
        }
    }
}

pub fn qdiscs(output: &str, command_output_truncated: bool) -> TcDumpPart<TcQdiscStatus> {
    parse_array(output, command_output_truncated, |object| {
        let interface = required_interface(object)?;
        let kind = required_string(object, "kind")?;
        let handle = string_value(object.get("handle")).unwrap_or_else(|| "unknown".into());
        let parent = string_value(object.get("parent"));
        let root = object.get("root").and_then(Value::as_bool).unwrap_or(false);
        let options = object.get("options").and_then(Value::as_object);
        let owner = qdisc_owner(&kind, &handle, parent.as_deref(), root).into();
        Ok(TcQdiscStatus {
            interface,
            kind,
            handle,
            parent,
            root,
            ingress_block: options
                .and_then(|value| value.get("ingress_block"))
                .and_then(value_u32),
            egress_block: options
                .and_then(|value| value.get("egress_block"))
                .and_then(value_u32),
            owner,
            detail: option_detail(
                options,
                &[
                    "default",
                    "limit",
                    "rate",
                    "ceil",
                    "target",
                    "interval",
                    "ecn",
                    "accel_mode",
                    "r2q",
                    "refcnt",
                    "set_default",
                    "flow",
                    "flows",
                    "quantum",
                    "memory_limit",
                    "drop_batch",
                    "bands",
                    "priomap",
                    "mpu",
                    "overhead",
                    "linklayer",
                    "split_gso",
                    "nat",
                    "besteffort",
                    "wash",
                ],
            ),
            counters: counters(object),
        })
    })
}

pub fn classes(output: &str, command_output_truncated: bool) -> TcDumpPart<TcClassStatus> {
    parse_array(output, command_output_truncated, |object| {
        let interface = required_interface(object)?;
        let kind = required_string(object, "kind")?;
        let handle = string_value(object.get("handle")).unwrap_or_else(|| "unknown".into());
        let parent = string_value(object.get("parent"));
        let options = object.get("options").and_then(Value::as_object);
        Ok(TcClassStatus {
            interface,
            kind,
            owner: hierarchy_owner(&handle, parent.as_deref()).into(),
            handle,
            parent,
            detail: option_detail(
                options,
                &[
                    "rate", "ceil", "burst", "cburst", "crate", "quantum", "prio", "priority",
                    "overhead", "mpu", "leaf", "level", "hash",
                ],
            ),
            counters: counters(object),
        })
    })
}

pub fn filters(output: &str, command_output_truncated: bool) -> TcDumpPart<TcFilterStatus> {
    parse_array(output, command_output_truncated, |object| {
        let interface = required_interface(object)?;
        let pref = object.get("pref").and_then(value_u32).ok_or(())?;
        let options = object.get("options").and_then(Value::as_object);
        let bpf = options
            .and_then(|value| value.get("bpf"))
            .and_then(Value::as_object);
        let prog = options
            .and_then(|value| value.get("prog"))
            .and_then(Value::as_object);
        let parent = string_value(object.get("parent"));
        let chain = object.get("chain").and_then(value_u32).unwrap_or(0);
        let handle = object
            .get("handle")
            .or_else(|| options.and_then(|value| value.get("handle")))
            .and_then(handle_value)
            .unwrap_or_else(|| "unknown".into());
        let program_name = options
            .and_then(|value| string_field(value, "bpf_name"))
            .or_else(|| bpf.and_then(|value| string_field(value, "name")))
            .or_else(|| prog.and_then(|value| string_field(value, "name")))
            .or_else(|| options.and_then(|value| string_field(value, "name")))
            .or_else(|| string_field(object, "name"));
        let program_id = bpf
            .and_then(|value| value.get("id"))
            .and_then(value_u32)
            .or_else(|| prog.and_then(|value| value.get("id")).and_then(value_u32))
            .or_else(|| {
                options
                    .and_then(|value| value.get("id"))
                    .and_then(value_u32)
            });
        let direct_action = bool_detail(
            object,
            options,
            bpf,
            prog,
            &["direct-action", "direct_action"],
        );
        let in_hw = bool_detail(object, options, bpf, prog, &["in_hw", "in-hw"]);
        let kind = object
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let (action, action_is_terminal, lanspeed_goto) = action_summary(object);
        let terminal_action = action_is_terminal || kind == "bpf" && direct_action != Some(false);
        let direction = filter_direction(parent.as_deref()).into();
        let owner = filter_owner(
            program_name.as_deref(),
            parent.as_deref(),
            chain,
            lanspeed_goto,
        )
        .into();
        Ok(TcFilterStatus {
            interface,
            direction,
            parent,
            chain,
            pref,
            handle,
            kind,
            protocol: object.get("protocol").and_then(string_value_from_value),
            owner,
            program_name,
            program_id,
            direct_action,
            in_hw,
            action,
            terminal_action,
            counters: recursive_counters(object),
        })
    })
}

pub fn build(
    qdiscs: TcDumpPart<TcQdiscStatus>,
    classes: TcDumpPart<TcClassStatus>,
    filters: TcDumpPart<TcFilterStatus>,
    target_interfaces: &[String],
) -> TcHostStatus {
    let scan_complete = qdiscs.ok
        && classes.ok
        && filters.ok
        && !qdiscs.command_output_truncated
        && !classes.command_output_truncated
        && !filters.command_output_truncated
        && !qdiscs.objects_truncated
        && !classes.objects_truncated
        && !filters.objects_truncated
        && qdiscs.parse_errors == 0
        && classes.parse_errors == 0
        && filters.parse_errors == 0;
    let mut status = TcHostStatus {
        state: String::new(),
        scan_complete,
        qdisc_scan: qdiscs.ok,
        class_scan: classes.ok,
        filter_scan: filters.ok,
        command_output_truncated: qdiscs.command_output_truncated
            || classes.command_output_truncated
            || filters.command_output_truncated,
        objects_truncated: qdiscs.objects_truncated
            || classes.objects_truncated
            || filters.objects_truncated,
        parse_errors: qdiscs.parse_errors + classes.parse_errors + filters.parse_errors,
        interface_count: 0,
        qdisc_count: qdiscs.objects.len(),
        class_count: classes.objects.len(),
        filter_count: filters.objects.len(),
        lanspeed_objects: 0,
        foreign_objects: 0,
        qdiscs: qdiscs.objects,
        classes: classes.objects,
        filters: filters.objects,
        conflicts: Vec::new(),
    };
    let interfaces = status
        .qdiscs
        .iter()
        .map(|value| value.interface.as_str())
        .chain(status.classes.iter().map(|value| value.interface.as_str()))
        .chain(status.filters.iter().map(|value| value.interface.as_str()))
        .collect::<BTreeSet<_>>();
    status.interface_count = interfaces.len();
    status.lanspeed_objects = status
        .qdiscs
        .iter()
        .map(|value| value.owner.as_str())
        .chain(status.classes.iter().map(|value| value.owner.as_str()))
        .chain(status.filters.iter().map(|value| value.owner.as_str()))
        .filter(|owner| *owner == "lanspeed")
        .count();
    status.foreign_objects = status
        .qdiscs
        .iter()
        .map(|value| value.owner.as_str())
        .chain(status.classes.iter().map(|value| value.owner.as_str()))
        .chain(status.filters.iter().map(|value| value.owner.as_str()))
        .filter(|owner| !matches!(*owner, "lanspeed" | "kernel" | "shared"))
        .count();
    status.conflicts = conflicts(&status, target_interfaces);
    status.state = if !qdiscs.ok && !classes.ok && !filters.ok {
        "unavailable"
    } else if !status.conflicts.is_empty() {
        "conflict"
    } else if !status.scan_complete {
        "partial"
    } else if status.foreign_objects > 0 {
        "coexisting"
    } else {
        "clean"
    }
    .into();
    status
}

fn conflicts(status: &TcHostStatus, target_interfaces: &[String]) -> Vec<TcStatusConflict> {
    let mut targets = target_interfaces
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    targets.extend(
        status
            .qdiscs
            .iter()
            .map(|value| value.interface.as_str())
            .chain(status.classes.iter().map(|value| value.interface.as_str()))
            .chain(status.filters.iter().map(|value| value.interface.as_str()))
            .filter(|value| lanspeed_internal_interface(value)),
    );
    targets.extend(
        status
            .qdiscs
            .iter()
            .filter(|value| value.owner == "lanspeed")
            .map(|value| value.interface.as_str()),
    );
    targets.extend(
        status
            .classes
            .iter()
            .filter(|value| value.owner == "lanspeed")
            .map(|value| value.interface.as_str()),
    );
    targets.extend(
        status
            .filters
            .iter()
            .filter(|value| value.owner == "lanspeed")
            .map(|value| value.interface.as_str()),
    );
    let mut values = Vec::new();
    let mut seen = BTreeSet::new();
    for filter in &status.filters {
        if targets.contains(filter.interface.as_str())
            && filter.owner != "lanspeed"
            && filter.chain == 0
            && ((filter.pref == LANSPEED_PREF && handles_equal(&filter.handle, LANSPEED_HANDLE))
                || (filter.pref == LANSPEED_EARLY_PREF
                    && handles_equal(&filter.handle, LANSPEED_EARLY_HANDLE)))
        {
            push_conflict(
                &mut values,
                &mut seen,
                "reserved_filter_slot",
                "critical",
                &filter.interface,
                &filter.direction,
                &format!("pref {} / {}", filter.pref, filter.handle),
                &filter.owner,
            );
        }
    }

    let mut owned_pref = BTreeMap::<(&str, &str), u32>::new();
    for filter in status
        .filters
        .iter()
        .filter(|value| value.owner == "lanspeed" && value.chain == 0)
    {
        owned_pref
            .entry((&filter.interface, &filter.direction))
            .and_modify(|pref| *pref = (*pref).min(filter.pref))
            .or_insert(filter.pref);
    }
    for filter in status.filters.iter().filter(|value| {
        value.owner != "lanspeed" && value.chain == 0 && targets.contains(value.interface.as_str())
    }) {
        let expected = owned_pref
            .get(&(filter.interface.as_str(), filter.direction.as_str()))
            .copied()
            .unwrap_or(if filter.owner == "dae" {
                LANSPEED_EARLY_PREF
            } else {
                LANSPEED_PREF
            });
        if filter.pref < expected {
            push_conflict(
                &mut values,
                &mut seen,
                if filter.terminal_action {
                    "foreign_filter_preemption"
                } else {
                    "foreign_filter_precedes_lanspeed"
                },
                "warning",
                &filter.interface,
                &filter.direction,
                &format!("pref {} / {}", filter.pref, filter.handle),
                &filter.owner,
            );
        }
    }

    for qdisc in &status.qdiscs {
        if targets.contains(qdisc.interface.as_str())
            && reserved_root_handle(&qdisc.handle)
            && qdisc.owner != "lanspeed"
        {
            push_conflict(
                &mut values,
                &mut seen,
                "reserved_qdisc_handle",
                "critical",
                &qdisc.interface,
                if qdisc.root { "root" } else { "child" },
                &format!("{} / {}", qdisc.kind, qdisc.handle),
                &qdisc.owner,
            );
        }
        if !targets.contains(qdisc.interface.as_str()) {
            continue;
        }
        if qdisc.root && qdisc.owner != "lanspeed" && !replaceable_default_root(qdisc) {
            push_conflict(
                &mut values,
                &mut seen,
                "foreign_root_qdisc",
                "warning",
                &qdisc.interface,
                "root",
                &format!("{} / {}", qdisc.kind, qdisc.handle),
                &qdisc.owner,
            );
        }
        if qdisc.kind == "ingress"
            && !status
                .qdiscs
                .iter()
                .any(|value| value.interface == qdisc.interface && value.kind == "clsact")
        {
            push_conflict(
                &mut values,
                &mut seen,
                "ingress_qdisc_blocks_clsact",
                "warning",
                &qdisc.interface,
                "ingress",
                &format!("{} / {}", qdisc.kind, qdisc.handle),
                &qdisc.owner,
            );
        }
    }
    values
}

#[allow(clippy::too_many_arguments)]
fn push_conflict(
    output: &mut Vec<TcStatusConflict>,
    seen: &mut BTreeSet<(String, String, String)>,
    id: &str,
    severity: &str,
    interface: &str,
    direction: &str,
    object: &str,
    owner: &str,
) {
    let key = (id.to_owned(), interface.to_owned(), direction.to_owned());
    if seen.insert(key) {
        output.push(TcStatusConflict {
            id: id.into(),
            severity: severity.into(),
            interface: interface.into(),
            direction: direction.into(),
            object: object.into(),
            owner: owner.into(),
        });
    }
}

fn parse_array<T>(
    output: &str,
    command_output_truncated: bool,
    mut parse: impl FnMut(&Map<String, Value>) -> Result<T, ()>,
) -> TcDumpPart<T> {
    let Ok(value) = serde_json::from_str::<Value>(output) else {
        return TcDumpPart {
            command_output_truncated,
            parse_errors: 1,
            ..TcDumpPart::default()
        };
    };
    let Some(entries) = value.as_array() else {
        return TcDumpPart {
            command_output_truncated,
            parse_errors: 1,
            ..TcDumpPart::default()
        };
    };
    let mut result = TcDumpPart {
        ok: true,
        command_output_truncated,
        objects_truncated: entries.len() > MAX_TC_OBJECTS,
        ..TcDumpPart::default()
    };
    for entry in entries.iter().take(MAX_TC_OBJECTS) {
        match entry.as_object().ok_or(()).and_then(&mut parse) {
            Ok(value) => result.objects.push(value),
            Err(()) => result.parse_errors += 1,
        }
    }
    result
}

fn required_string(object: &Map<String, Value>, name: &str) -> Result<String, ()> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .map(str::to_owned)
        .ok_or(())
}

fn required_interface(object: &Map<String, Value>) -> Result<String, ()> {
    ["dev", "ifname", "interface"]
        .iter()
        .find_map(|name| required_string(object, name).ok())
        .ok_or(())
}

fn string_value(value: Option<&Value>) -> Option<String> {
    value.and_then(string_value_from_value)
}

fn string_value_from_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.is_empty() => Some(value.chars().take(96).collect()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn handle_value(value: &Value) -> Option<String> {
    value
        .as_u64()
        .map(|value| format!("0x{value:x}"))
        .or_else(|| string_value_from_value(value))
}

fn value_u32(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| value.as_str()?.parse().ok())
}

fn value_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse().ok())
        .map(|value| value.min(i64::MAX as u64))
}

fn string_field(object: &Map<String, Value>, name: &str) -> Option<String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(|value| value.chars().take(96).collect())
}

fn counters(object: &Map<String, Value>) -> TcCounters {
    TcCounters {
        bytes: object.get("bytes").and_then(value_u64),
        packets: object.get("packets").and_then(value_u64),
        drops: object.get("drops").and_then(value_u64),
        overlimits: object.get("overlimits").and_then(value_u64),
        backlog: object.get("backlog").and_then(value_u64),
        requeues: object.get("requeues").and_then(value_u64),
        qlen: object.get("qlen").and_then(value_u64),
        maxpacket: object.get("maxpacket").and_then(value_u64),
    }
}

fn recursive_counters(object: &Map<String, Value>) -> TcCounters {
    let direct = counters(object);
    if has_counter(&direct) {
        return direct;
    }
    object
        .values()
        .find_map(|value| match value {
            Value::Object(value) => {
                let found = recursive_counters(value);
                has_counter(&found).then_some(found)
            }
            Value::Array(values) => values.iter().find_map(|value| {
                let value = value.as_object()?;
                let found = recursive_counters(value);
                has_counter(&found).then_some(found)
            }),
            _ => None,
        })
        .unwrap_or_default()
}

fn has_counter(value: &TcCounters) -> bool {
    value.bytes.is_some()
        || value.packets.is_some()
        || value.drops.is_some()
        || value.overlimits.is_some()
        || value.backlog.is_some()
        || value.requeues.is_some()
        || value.qlen.is_some()
        || value.maxpacket.is_some()
}

fn option_detail(options: Option<&Map<String, Value>>, names: &[&str]) -> Option<String> {
    let options = options?;
    let values = names
        .iter()
        .filter_map(|name| string_value(options.get(*name)).map(|value| format!("{name}={value}")))
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.join(" · "))
}

fn bool_detail(
    object: &Map<String, Value>,
    options: Option<&Map<String, Value>>,
    bpf: Option<&Map<String, Value>>,
    prog: Option<&Map<String, Value>>,
    names: &[&str],
) -> Option<bool> {
    names.iter().find_map(|name| {
        options
            .and_then(|value| value.get(*name))
            .or_else(|| bpf.and_then(|value| value.get(*name)))
            .or_else(|| prog.and_then(|value| value.get(*name)))
            .or_else(|| object.get(*name))
            .and_then(Value::as_bool)
    })
}

fn action_summary(object: &Map<String, Value>) -> (Option<String>, bool, bool) {
    let mut actions = Vec::new();
    let mut terminal = false;
    let mut lanspeed_goto = false;
    collect_actions(
        &Value::Object(object.clone()),
        &mut actions,
        &mut terminal,
        &mut lanspeed_goto,
    );
    actions.sort();
    actions.dedup();
    (
        (!actions.is_empty()).then(|| actions.join(", ")),
        terminal,
        lanspeed_goto,
    )
}

fn collect_actions(
    value: &Value,
    output: &mut Vec<String>,
    terminal: &mut bool,
    lanspeed_goto: &mut bool,
) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_actions(value, output, terminal, lanspeed_goto);
            }
        }
        Value::Object(object) => {
            let top_level_filter = object.contains_key("pref") && object.contains_key("kind");
            if !top_level_filter && object.get("type").and_then(Value::as_str) == Some("goto") {
                *terminal = true;
                let chain = object.get("chain").and_then(value_u32);
                if chain.is_some_and(|chain| {
                    matches!(chain, 0x7a20 | 0x7e20 | 0x7e21 | 0x7e22 | 0x7e60)
                }) {
                    *lanspeed_goto = true;
                }
                output.push(chain.map_or_else(|| "goto".into(), |chain| format!("goto:{chain}")));
            }
            if !top_level_filter {
                let kind = object.get("kind").and_then(Value::as_str);
                let action = object
                    .get("control_action")
                    .or_else(|| object.get("action"))
                    .or_else(|| object.get("eaction"))
                    .and_then(Value::as_str);
                if let Some(kind) =
                    kind.filter(|kind| matches!(*kind, "gact" | "mirred" | "police" | "bpf"))
                {
                    let label =
                        action.map_or_else(|| kind.to_owned(), |action| format!("{kind}:{action}"));
                    if kind == "police"
                        || action.is_some_and(|action| {
                            matches!(action, "drop" | "shot" | "redirect" | "stolen" | "goto")
                        })
                    {
                        *terminal = true;
                    }
                    output.push(label);
                }
            }
            for value in object.values() {
                collect_actions(value, output, terminal, lanspeed_goto);
            }
        }
        _ => {}
    }
}

fn filter_direction(parent: Option<&str>) -> &'static str {
    let parent = parent.unwrap_or_default().to_ascii_lowercase();
    if parent.ends_with("fff2") {
        "ingress"
    } else if parent.ends_with("fff3") {
        "egress"
    } else if parent.is_empty() {
        "unknown"
    } else {
        "root"
    }
}

fn qdisc_owner(kind: &str, handle: &str, parent: Option<&str>, root: bool) -> &'static str {
    if kind == "clsact" || kind == "ingress" {
        "shared"
    } else if parent.and_then(handle_major).is_some_and(is_lanspeed_major)
        || root
            && matches!(
                (handle_major(handle), kind),
                (Some("7a10" | "7a20"), "htb")
                    | (Some("7d00"), "nsshtb")
                    | (Some("7e20" | "7e30"), "htb" | "nsshtb")
            )
    {
        "lanspeed"
    } else if root
        && handle == "0:"
        && matches!(kind, "noqueue" | "mq" | "fq" | "fq_codel" | "pfifo_fast")
    {
        "kernel"
    } else {
        "other"
    }
}

fn hierarchy_owner(handle: &str, parent: Option<&str>) -> &'static str {
    if handle_major(handle).is_some_and(is_lanspeed_major)
        || parent.and_then(handle_major).is_some_and(is_lanspeed_major)
    {
        "lanspeed"
    } else {
        "other"
    }
}

fn filter_owner(
    program_name: Option<&str>,
    parent: Option<&str>,
    chain: u32,
    lanspeed_goto: bool,
) -> &'static str {
    let name = program_name.unwrap_or_default().to_ascii_lowercase();
    if name.contains("lanspeed_ingres")
        || name.contains("lanspeed_egress")
        || lanspeed_goto
        || matches!(chain, 0x7a20 | 0x7e20 | 0x7e21 | 0x7e22 | 0x7e60)
        || parent.and_then(handle_major).is_some_and(is_lanspeed_major)
    {
        "lanspeed"
    } else if name.contains("dae") || name.contains("daed") || name.contains("dae0") {
        "dae"
    } else if name.contains("sqm") {
        "sqm"
    } else if name.contains("qosify") {
        "qosify"
    } else {
        "unknown"
    }
}

fn handle_major(value: &str) -> Option<&str> {
    value.split_once(':').map(|value| value.0)
}

fn is_lanspeed_major(value: &str) -> bool {
    LANSPEED_ROOT_MAJORS.contains(&value.trim_start_matches("0x").to_ascii_lowercase().as_str())
}

fn lanspeed_internal_interface(value: &str) -> bool {
    if LANSPEED_STATIC_IFBS.contains(&value) {
        return true;
    }
    value.strip_prefix("lsu").is_some_and(|suffix| {
        suffix.len() == 8 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn reserved_root_handle(handle: &str) -> bool {
    handle_major(handle).is_some_and(is_lanspeed_major)
}

fn replaceable_default_root(qdisc: &TcQdiscStatus) -> bool {
    qdisc.handle == "0:"
        && matches!(
            qdisc.kind.as_str(),
            "noqueue" | "mq" | "fq" | "fq_codel" | "pfifo_fast"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_three_tc_object_families_and_preserves_counters() {
        let qdisc = qdiscs(
            r#"[{"kind":"clsact","handle":"ffff:","dev":"br-lan","parent":"ffff:fff1","bytes":12,"packets":2,"drops":1,"requeues":3,"qlen":4,"maxpacket":1500},{"kind":"htb","handle":"7a10:","dev":"br-lan","root":true,"options":{"default":"0x1"}}]"#,
            false,
        );
        let class = classes(
            r#"[{"kind":"htb","handle":"7a10:1","dev":"br-lan","parent":"7a10:","options":{"rate":1000000},"bytes":44,"packets":4}]"#,
            false,
        );
        let filter = filters(
            r#"[{"protocol":"all","pref":49152,"kind":"bpf","dev":"br-lan","parent":"ffff:fff2","chain":0,"options":{"handle":7917,"bpf_name":"lanspeed_ingress","direct-action":true,"id":7}}]"#,
            false,
        );
        let status = build(qdisc, class, filter, &["br-lan".into()]);
        assert_eq!(status.state, "clean");
        assert!(status.scan_complete);
        assert_eq!(status.qdisc_count, 2);
        assert_eq!(status.class_count, 1);
        assert_eq!(status.filter_count, 1);
        assert_eq!(status.qdiscs[0].counters.drops, Some(1));
        assert_eq!(status.qdiscs[0].counters.requeues, Some(3));
        assert_eq!(status.qdiscs[0].counters.qlen, Some(4));
        assert_eq!(status.qdiscs[0].counters.maxpacket, Some(1500));
        assert_eq!(status.filters[0].direction, "ingress");
        assert_eq!(status.filters[0].owner, "lanspeed");
        assert_eq!(status.filters[0].action, None);
    }

    #[test]
    fn reports_reserved_slots_root_ownership_and_preemption_separately() {
        let qdisc = qdiscs(
            r#"[{"kind":"cake","handle":"8000:","dev":"br-lan","root":true},{"kind":"cake","handle":"7a10:","dev":"br-lan","root":true},{"kind":"cake","handle":"7a10:","dev":"wan","root":true}]"#,
            false,
        );
        let filter = filters(
            r#"[{"protocol":"all","pref":10,"kind":"bpf","dev":"br-lan","parent":"ffff:fff2","chain":0,"handle":"0xbeef","options":{"bpf_name":"dae_lan_ingress","actions":[{"kind":"mirred","eaction":"redirect"}]}},{"protocol":"all","pref":1,"kind":"bpf","dev":"br-lan","parent":"ffff:fff2","chain":0,"handle":"0x1eee","options":{"bpf_name":"foreign_reserved"}},{"protocol":"all","pref":49152,"kind":"bpf","dev":"br-lan","parent":"ffff:fff2","chain":0,"handle":"0x1eed","options":{"bpf_name":"lanspeed_ingress"}},{"protocol":"all","pref":49152,"kind":"bpf","dev":"wan","parent":"ffff:fff2","chain":0,"handle":"0x1eed","options":{"bpf_name":"foreign"}}]"#,
            false,
        );
        let status = build(qdisc, classes("[]", false), filter, &["br-lan".into()]);
        let ids = status
            .conflicts
            .iter()
            .map(|value| value.id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(status.state, "conflict");
        assert!(ids.contains("foreign_root_qdisc"));
        assert!(ids.contains("foreign_filter_preemption"));
        assert!(ids.contains("reserved_filter_slot"));
        assert!(ids.contains("reserved_qdisc_handle"));
        assert!(!status
            .conflicts
            .iter()
            .any(|value| value.interface == "wan"));
    }

    #[test]
    fn recognizes_lanspeed_chain_jumps_without_a_bpf_program_name() {
        let values = filters(
            r#"[{"protocol":"all","pref":53280,"kind":"matchall","dev":"br-lan","parent":"ffff:fff2","chain":0,"options":{"actions":[{"kind":"gact","control_action":{"type":"goto","chain":31264}}]}}]"#,
            false,
        );
        assert_eq!(values.objects.len(), 1);
        assert_eq!(values.objects[0].owner, "lanspeed");
        assert!(values.objects[0].terminal_action);
        assert!(values.objects[0]
            .action
            .as_deref()
            .unwrap()
            .contains("goto"));
    }

    #[test]
    fn dae_is_coexistence_when_lanspeed_can_take_the_reserved_early_slot() {
        let values = filters(
            r#"[{"protocol":"all","pref":10,"kind":"bpf","dev":"br-lan","parent":"ffff:fff2","chain":0,"handle":"0xbeef","options":{"bpf_name":"dae_lan_ingress","actions":[{"kind":"mirred","eaction":"redirect"}]}}]"#,
            false,
        );
        let status = build(
            qdiscs("[]", false),
            classes("[]", false),
            values,
            &["br-lan".into()],
        );
        assert_eq!(status.state, "coexisting");
        assert!(status.conflicts.is_empty());
    }

    #[test]
    fn marks_invalid_or_bounded_dumps_incomplete_without_hiding_valid_objects() {
        let qdisc = qdiscs("not-json", false);
        let status = build(qdisc, classes("[]", false), filters("[]", true), &[]);
        assert_eq!(status.state, "partial");
        assert!(!status.scan_complete);
        assert_eq!(status.parse_errors, 1);
        assert!(status.command_output_truncated);
    }

    #[test]
    fn recognizes_nss_roots_and_conflicts_on_owned_ifb_names() {
        let qdisc = qdiscs(
            r#"[{"kind":"nsshtb","handle":"7d00:","dev":"lsu1234abcd","root":true},{"kind":"cake","handle":"8000:","dev":"lsu8765dcba","root":true},{"kind":"cake","handle":"8001:","dev":"ifb-nss-lsu","root":true},{"kind":"cake","handle":"8002:","dev":"lsu-invalid","root":true}]"#,
            false,
        );
        let class = classes(
            r#"[{"kind":"nsshtb","handle":"7d00:1","dev":"lsu1234abcd","parent":"7d00:","options":{"rate":4000000000}}]"#,
            false,
        );
        let status = build(qdisc, class, filters("[]", false), &[]);

        assert_eq!(status.qdiscs[0].owner, "lanspeed");
        assert_eq!(status.classes[0].owner, "lanspeed");
        assert!(status
            .conflicts
            .iter()
            .any(|value| { value.id == "foreign_root_qdisc" && value.interface == "lsu8765dcba" }));
        assert!(status
            .conflicts
            .iter()
            .any(|value| { value.id == "foreign_root_qdisc" && value.interface == "ifb-nss-lsu" }));
        assert!(!status
            .conflicts
            .iter()
            .any(|value| value.interface == "lsu-invalid"));
    }

    #[test]
    fn accepts_legacy_interface_field_names_from_tc_json() {
        let status = build(
            qdiscs(
                r#"[{"kind":"fq_codel","handle":"0:","ifname":"br-lan","root":true}]"#,
                false,
            ),
            classes("[]", false),
            filters("[]", false),
            &["br-lan".into()],
        );
        assert_eq!(status.qdiscs[0].interface, "br-lan");
        assert_eq!(status.state, "clean");
    }
}
