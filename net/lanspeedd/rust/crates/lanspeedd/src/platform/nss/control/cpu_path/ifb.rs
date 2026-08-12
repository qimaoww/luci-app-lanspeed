use std::{collections::BTreeSet, fs};

use serde_json::Value;

use super::system;

const DEVICE_PREFIX: &str = "lsu";
const ALIAS_PREFIX: &str = "lanspeedd:nss-igs-upload:v3:";
const CONTROL_ROOT: &str = "/sys/module/lanspeed_nss_control/parameters";
const MAX_IGS_EDGES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IgsState {
    Staged,
    Published,
    Degraded,
}

pub(super) fn device(edge: &str) -> String {
    format!("{DEVICE_PREFIX}{:08x}", fnv1a(edge.as_bytes()))
}

fn alias(edge: &str) -> String {
    format!("{ALIAS_PREFIX}{edge}")
}

pub(super) fn preflight(edges: &BTreeSet<String>) -> Result<(), String> {
    if edges.len() > MAX_IGS_EDGES {
        return Err("nss_igs_capacity_exceeded".into());
    }
    if !system::module_available("ifb") {
        return Err("ifb_module_unavailable".into());
    }
    if !system::module_available("lanspeed_nss_control") {
        return Err("lanspeed_nss_control_unavailable".into());
    }
    let names = edges
        .iter()
        .map(|edge| device(edge))
        .collect::<BTreeSet<_>>();
    if names.len() != edges.len() {
        return Err("nss_igs_ifb_name_collision".into());
    }
    for edge in edges {
        let name = device(edge);
        if system::interface_exists(&name) && !owned_link(edge)? {
            return Err("nss_igs_ifb_owned_by_external_service".into());
        }
    }
    Ok(())
}

pub(super) fn ensure(edge: &str) -> Result<String, String> {
    let edges = BTreeSet::from([edge.to_owned()]);
    preflight(&edges)?;
    let name = device(edge);
    if !system::interface_exists(&name) {
        system::run("ip", &["link", "add", "name", &name, "type", "ifb"])?;
        if let Err(error) = system::run("ip", &["link", "set", "dev", &name, "alias", &alias(edge)])
        {
            system::run_ignore_missing("ip", &["link", "delete", "dev", &name]);
            return Err(error);
        }
    }
    if !owned_link(edge)? {
        return Err("nss_igs_ifb_owned_by_external_service".into());
    }
    system::run("ip", &["link", "set", "dev", &name, "up"])?;
    if !owned(edge)? {
        return Err("nss_igs_ifb_inspection_failed".into());
    }
    Ok(name)
}

pub(super) fn owned_interfaces() -> Result<Vec<(String, String)>, String> {
    let mut interfaces = Vec::new();
    for name in system::interface_names()? {
        let current_alias = interface_alias(&name);
        let Some(edge) = current_alias.strip_prefix(ALIAS_PREFIX) else {
            continue;
        };
        if !is_ifb(&name)? || name != device(edge) {
            return Err("nss_igs_ifb_owned_by_external_service".into());
        }
        interfaces.push((name, edge.to_owned()));
    }
    Ok(interfaces)
}

pub(super) fn cleanup(edge: &str) -> Result<(), String> {
    let name = device(edge);
    if !system::interface_exists(&name) {
        return Ok(());
    }
    if !owned_link(edge)? {
        return Err("nss_igs_ifb_owned_by_external_service".into());
    }
    match state(&name)? {
        Some(IgsState::Published | IgsState::Degraded) => control("unpublish", &name)?,
        Some(IgsState::Staged) => {}
        None => return Err("nss_igs_stage_inspection_failed".into()),
    }
    if state(&name)? != Some(IgsState::Staged) {
        return Err("nss_igs_unpublish_failed".into());
    }
    control("unstage", &name)?;
    system::run("ip", &["link", "delete", "dev", &name])
}

pub(super) fn stage(edge: &str) -> Result<(), String> {
    let name = device(edge);
    match state(&name)? {
        Some(IgsState::Staged | IgsState::Published) => Ok(()),
        Some(IgsState::Degraded) => {
            control("unpublish", &name)?;
            if state(&name)? == Some(IgsState::Staged) {
                Ok(())
            } else {
                Err("nss_igs_unpublish_failed".into())
            }
        }
        None => control("stage", &name),
    }
}

pub(super) fn publish(edge: &str) -> Result<(), String> {
    let name = device(edge);
    match state(&name)? {
        Some(IgsState::Published) => {
            if published_edge(&name)?.as_deref() == Some(edge) {
                Ok(())
            } else {
                Err("nss_igs_mapping_owned_by_external_service".into())
            }
        }
        Some(IgsState::Staged) => control("publish", &format!("{name} {edge}")),
        Some(IgsState::Degraded) => Err("nss_igs_unpublish_failed".into()),
        None => Err("nss_igs_stage_missing".into()),
    }
}

pub(super) fn unpublish(edge: &str) -> Result<(), String> {
    let name = device(edge);
    match state(&name)? {
        Some(IgsState::Published | IgsState::Degraded) => control("unpublish", &name),
        Some(IgsState::Staged) | None => Ok(()),
    }
}

pub(super) fn state(name: &str) -> Result<Option<IgsState>, String> {
    let text = fs::read_to_string(format!("{CONTROL_ROOT}/status"))
        .map_err(|_| "nss_igs_stage_inspection_failed".to_owned())?;
    parse_state(&text, name)
}

fn parse_state(text: &str, name: &str) -> Result<Option<IgsState>, String> {
    let mut found = None;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if (fields.len() != 3 && fields.len() != 4)
            || !system::valid_interface_name(fields[0])
            || fields[2].parse::<u32>().ok().is_none_or(|value| value == 0)
        {
            return Err("nss_igs_stage_inspection_failed".into());
        }
        let current = match fields[1] {
            "staged" if fields.len() == 3 => IgsState::Staged,
            "published" if fields.len() == 4 && system::valid_interface_name(fields[3]) => {
                IgsState::Published
            }
            "degraded" if fields.len() == 4 && system::valid_interface_name(fields[3]) => {
                IgsState::Degraded
            }
            _ => return Err("nss_igs_stage_inspection_failed".into()),
        };
        if fields[0] == name {
            if found.replace(current).is_some() {
                return Err("nss_igs_stage_inspection_failed".into());
            }
        }
    }
    Ok(found)
}

pub(super) fn published_edge(name: &str) -> Result<Option<String>, String> {
    let text = fs::read_to_string(format!("{CONTROL_ROOT}/status"))
        .map_err(|_| "nss_igs_stage_inspection_failed".to_owned())?;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() == 4 && fields[0] == name && matches!(fields[1], "published" | "degraded") {
            if !system::valid_interface_name(fields[3]) {
                return Err("nss_igs_stage_inspection_failed".into());
            }
            return Ok(Some(fields[3].to_owned()));
        }
    }
    Ok(None)
}

fn control(operation: &str, name: &str) -> Result<(), String> {
    fs::write(format!("{CONTROL_ROOT}/{operation}"), format!("{name}\n"))
        .map_err(|_| format!("nss_igs_{operation}_failed"))
}

pub(super) fn owned(edge: &str) -> Result<bool, String> {
    Ok(owned_link(edge)? && interface_up(&device(edge))?)
}

fn owned_link(edge: &str) -> Result<bool, String> {
    let name = device(edge);
    if !system::interface_exists(&name) || interface_alias(&name) != alias(edge) {
        return Ok(false);
    }
    is_ifb(&name)
}

fn interface_up(name: &str) -> Result<bool, String> {
    let flags = fs::read_to_string(format!("/sys/class/net/{name}/flags"))
        .map_err(|_| "nss_igs_ifb_inspection_failed".to_owned())?;
    let flags = flags.trim().strip_prefix("0x").unwrap_or(flags.trim());
    let flags =
        u32::from_str_radix(flags, 16).map_err(|_| "nss_igs_ifb_inspection_failed".to_owned())?;
    Ok(flags & 1 != 0)
}

fn interface_alias(name: &str) -> String {
    fs::read_to_string(format!("/sys/class/net/{name}/ifalias"))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn is_ifb(name: &str) -> Result<bool, String> {
    let value = system::json_output(
        "ip",
        &["-j", "-d", "link", "show", "dev", name],
        "nss_igs_ifb_inspection_failed",
    )?;
    Ok(value.as_array().into_iter().flatten().any(|value| {
        value
            .get("linkinfo")
            .and_then(|linkinfo| linkinfo.get("info_kind"))
            .and_then(Value::as_str)
            == Some("ifb")
    }))
}

fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_ifb_name_is_stable_short_and_not_a_conventional_interface() {
        assert_eq!(device("edge0"), device("edge0"));
        assert_ne!(device("edge0"), device("edge1"));
        assert!(device("an-interface").len() <= 15);
        assert!(device("edge0").starts_with(DEVICE_PREFIX));
    }

    #[test]
    fn staged_state_parser_is_exact_and_rejects_duplicate_ownership() {
        assert_eq!(
            parse_state("lsu12345678 staged 70\n", "lsu12345678").unwrap(),
            Some(IgsState::Staged)
        );
        assert_eq!(
            parse_state("lsu12345678 published 70 edge0\n", "other0").unwrap(),
            None
        );
        assert!(parse_state(
            "lsu12345678 staged 70\nlsu12345678 adopted 70\n",
            "lsu12345678"
        )
        .is_err());
        assert_eq!(
            parse_state("lsu12345678 published 70 edge0\n", "lsu12345678").unwrap(),
            Some(IgsState::Published)
        );
        assert_eq!(
            parse_state("lsu12345678 degraded 70 edge0\n", "lsu12345678").unwrap(),
            Some(IgsState::Degraded)
        );
        assert!(parse_state("lsu12345678 published 70\n", "lsu12345678").is_err());
    }
}
