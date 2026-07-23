use serde_json::{Map, Value};

use super::TcFilter;

pub const LANSPEED_PREF: u32 = 49_152;
pub const LANSPEED_HANDLE: &str = "0x1eed";
pub const LANSPEED_EARLY_PREF: u32 = 1;
pub const LANSPEED_EARLY_HANDLE: &str = "0x1eee";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcFilterDetails {
    pub filter: TcFilter,
    pub kind: Option<String>,
    pub protocol: Option<String>,
    pub program_name: Option<String>,
    pub program_id: Option<u32>,
    pub direct_action: Option<bool>,
    pub in_hw: Option<bool>,
    pub not_in_hw: Option<bool>,
}

pub fn has_owned_identity_collision(filters: &[TcFilter]) -> bool {
    filters.iter().any(|filter| {
        filter.chain == 0
            && filter.owner != "lanspeed"
            && ((filter.pref == LANSPEED_PREF && handles_equal(&filter.handle, LANSPEED_HANDLE))
                || (filter.pref == LANSPEED_EARLY_PREF
                    && handles_equal(&filter.handle, LANSPEED_EARLY_HANDLE)))
    })
}

pub fn has_foreign_filters(filters: &[TcFilter]) -> bool {
    filters.iter().any(|filter| filter.owner != "lanspeed")
}

/// Validate the execution properties that make a cls_bpf hook suitable for
/// exact software-path accounting. Older iproute2 builds may omit these
/// details, so only explicit contradictions are rejected.
pub fn has_software_direct_action_semantics(filter: &TcFilterDetails) -> bool {
    filter.protocol.as_deref().is_none_or(protocol_is_all)
        && filter.direct_action != Some(false)
        && filter.in_hw != Some(true)
        && filter.not_in_hw != Some(false)
}

pub fn dae_preempts_lan_ingress(filters: &[TcFilter], attach_ifnames: &[String]) -> bool {
    filters.iter().any(|filter| {
        filter.owner == "dae"
            && filter.chain == 0
            && filter.direction == "ingress"
            && filter.pref > 0
            && filter.pref < LANSPEED_PREF
            && attach_ifnames
                .iter()
                .any(|ifname| ifname == &filter.interface)
    })
}

pub fn parse_filter_json(
    interface: &str,
    direction: &str,
    output: &str,
) -> Result<Vec<TcFilterDetails>, String> {
    let value: Value =
        serde_json::from_str(output).map_err(|error| format!("invalid tc filter JSON: {error}"))?;
    let entries = value
        .as_array()
        .ok_or_else(|| "tc filter JSON root is not an array".to_owned())?;

    let mut details = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let object = entry
                .as_object()
                .ok_or_else(|| format!("tc filter JSON entry {index} is not an object"))?;
            let options = object.get("options").and_then(Value::as_object);
            let pref = object
                .get("pref")
                .and_then(value_u32)
                .ok_or_else(|| format!("tc filter JSON entry {index} has no numeric pref"))?;
            let handle = object
                .get("handle")
                .or_else(|| options.and_then(|item| item.get("handle")))
                .and_then(value_handle)
                .unwrap_or_else(|| "unknown".to_owned());
            let bpf = options
                .and_then(|item| item.get("bpf"))
                .and_then(Value::as_object);
            let prog = options
                .and_then(|item| item.get("prog"))
                .and_then(Value::as_object);
            let program_name = bpf
                .and_then(|item| string_field(item, "name"))
                .or_else(|| prog.and_then(|item| string_field(item, "name")))
                .or_else(|| options.and_then(|item| string_field(item, "bpf_name")))
                .or_else(|| options.and_then(|item| string_field(item, "name")))
                .or_else(|| string_field(object, "name"));
            let program_id = bpf
                .and_then(|item| item.get("id"))
                .and_then(value_u32)
                .or_else(|| prog.and_then(|item| item.get("id")).and_then(value_u32))
                .or_else(|| options.and_then(|item| item.get("id")).and_then(value_u32));
            let detail_bool = |names: &[&str]| {
                names.iter().find_map(|name| {
                    options
                        .and_then(|item| item.get(*name))
                        .or_else(|| bpf.and_then(|item| item.get(*name)))
                        .or_else(|| prog.and_then(|item| item.get(*name)))
                        .or_else(|| object.get(*name))
                        .and_then(Value::as_bool)
                })
            };
            let owner = owner(program_name.as_deref().unwrap_or_default());
            let chain = object.get("chain").and_then(value_u32).unwrap_or(0);

            Ok(TcFilterDetails {
                filter: TcFilter {
                    interface: interface.into(),
                    direction: direction.into(),
                    chain,
                    pref,
                    handle,
                    owner: owner.into(),
                    source: "tc_filter_show".into(),
                },
                kind: object
                    .get("kind")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                protocol: object.get("protocol").map(value_protocol),
                program_name,
                program_id,
                direct_action: detail_bool(&["direct-action", "direct_action"]),
                in_hw: detail_bool(&["in_hw", "in-hw"]),
                not_in_hw: detail_bool(&["not_in_hw", "not-in-hw"]),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    /*
     * Some tc-full builds emit a header object immediately before the full
     * filter object. Keep a lone sparse object conservative, but discard it
     * when a detailed object for the same slot is present so one kernel
     * filter cannot be misreported as an additional foreign filter.
     */
    let detailed_slots = details
        .iter()
        .filter(|detail| detail.filter.handle != "unknown")
        .map(|detail| {
            (
                detail.filter.chain,
                detail.filter.pref,
                detail.kind.clone(),
                detail.protocol.clone(),
            )
        })
        .collect::<Vec<_>>();
    details.retain(|detail| {
        let sparse = detail.filter.handle == "unknown"
            && detail.program_name.is_none()
            && detail.program_id.is_none();
        !sparse
            || !detailed_slots.iter().any(|slot| {
                slot.0 == detail.filter.chain
                    && slot.1 == detail.filter.pref
                    && slot.2 == detail.kind
                    && slot.3 == detail.protocol
            })
    });
    Ok(details)
}

pub fn qdisc_json_has_clsact(output: &str) -> Result<bool, String> {
    let value: Value =
        serde_json::from_str(output).map_err(|error| format!("invalid tc qdisc JSON: {error}"))?;
    let entries = value
        .as_array()
        .ok_or_else(|| "tc qdisc JSON root is not an array".to_owned())?;
    Ok(entries.iter().any(|entry| {
        entry
            .as_object()
            .and_then(|object| object.get("kind"))
            .and_then(Value::as_str)
            == Some("clsact")
    }))
}

pub fn handles_equal(left: &str, right: &str) -> bool {
    canonical_handle(left) == canonical_handle(right)
}

fn value_u32(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| value.as_str()?.parse().ok())
}

fn value_handle(value: &Value) -> Option<String> {
    if let Some(number) = value.as_u64() {
        return Some(format!("0x{number:x}"));
    }
    let value = value.as_str()?;
    if value.is_empty() {
        return None;
    }
    let canonical = canonical_handle(value);
    Some(if canonical == "unknown" || canonical.contains(':') {
        canonical
    } else {
        format!("0x{canonical}")
    })
}

fn value_protocol(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        _ => "invalid".into(),
    }
}

fn protocol_is_all(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("all")
        || matches!(
            protocol.to_ascii_lowercase().as_str(),
            "3" | "0x3" | "0x0003"
        )
}

fn canonical_handle(handle: &str) -> String {
    let handle = handle
        .strip_prefix("0x")
        .or_else(|| handle.strip_prefix("0X"))
        .unwrap_or(handle)
        .to_ascii_lowercase();
    if handle.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let trimmed = handle.trim_start_matches('0');
        if trimmed.is_empty() {
            "0".into()
        } else {
            trimmed.into()
        }
    } else {
        handle
    }
}

fn string_field(object: &Map<String, Value>, name: &str) -> Option<String> {
    object.get(name)?.as_str().map(str::to_owned)
}

fn owner(program_name: &str) -> &'static str {
    let name = program_name.to_ascii_lowercase();
    if name.contains("lanspeed_ingres") || name.contains("lanspeed_egress") {
        "lanspeed"
    } else if name.contains("dae") || name.contains("daed") || name.contains("dae0") {
        "dae"
    } else if name.contains("sqm") {
        "sqm"
    } else if name.contains("qosify") {
        "qosify"
    } else if name.contains("ifb") {
        "ifb"
    } else {
        "unknown"
    }
}
