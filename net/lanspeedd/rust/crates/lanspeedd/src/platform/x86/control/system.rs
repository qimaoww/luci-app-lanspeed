use std::{
    fs,
    io::Write,
    process::{Command, Output, Stdio},
    thread,
    time::Duration,
};

use serde_json::Value;

pub(crate) fn command_available(program: &str) -> bool {
    crate::probe::commands::command_available(program)
}

pub(crate) fn require_program(program: &str) -> Result<(), String> {
    command_available(program)
        .then_some(())
        .ok_or_else(|| format!("missing_{program}"))
}

pub(crate) fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

pub(crate) fn interface_exists(device: &str) -> bool {
    valid_interface_name(device) && fs::metadata(format!("/sys/class/net/{device}")).is_ok()
}

pub(crate) fn module_available(prefix: &str) -> bool {
    fs::metadata(format!("/sys/module/{prefix}")).is_ok()
        || fs::read_dir("/lib/modules")
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .any(|version| module_tree_contains(&version.path(), prefix))
}

fn module_tree_contains(root: &std::path::Path, prefix: &str) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if module_tree_contains(&path, prefix) {
                return true;
            }
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == format!("{prefix}.ko") || name.starts_with(&format!("{prefix}.ko.")) {
            return true;
        }
    }
    false
}

pub(crate) fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let output = output(program, args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(program, &output))
    }
}

pub(crate) fn run_ignore_missing(program: &str, args: &[&str]) {
    let _ = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub(crate) fn output(program: &str, args: &[&str]) -> Result<Output, String> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| error.to_string())
}

pub(crate) fn json_output(program: &str, args: &[&str], reason: &str) -> Result<Value, String> {
    let output = output(program, args)?;
    if !output.status.success() {
        return Err(reason.into());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| reason.into())
}

pub(crate) fn run_script(program: &str, args: &[&str], script: &str) -> Result<(), String> {
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
        Err(command_error(program, &output))
    }
}

fn command_error(program: &str, output: &Output) -> String {
    format!(
        "{program}_failed:{}",
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

pub(crate) fn qdiscs(device: &str) -> Result<Vec<Value>, String> {
    let value = json_output(
        "tc",
        &["-j", "qdisc", "show", "dev", device],
        "qdisc_inspection_invalid",
    )?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| "qdisc_inspection_invalid".into())
}

pub(crate) fn root_qdiscs(device: &str) -> Result<Vec<(String, String)>, String> {
    Ok(root_qdiscs_from(&qdiscs(device)?))
}

pub(crate) fn root_qdiscs_from(values: &[Value]) -> Vec<(String, String)> {
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

pub(crate) fn ensure_replaceable_root(device: &str, owned_handle: &str) -> Result<(), String> {
    let qdiscs = qdiscs(device)?;
    if replaceable_root(&qdiscs, owned_handle) {
        Ok(())
    } else {
        eprintln!(
            "lanspeedd: LAN qdisc conflict: {}",
            qdisc_signature(&qdiscs)
        );
        Err("qdisc_owned_by_external_service".into())
    }
}

pub(crate) fn ensure_owned_virtual_root(device: &str, owned_handle: &str) -> Result<(), String> {
    let mut last = Vec::new();
    for attempt in 0..5 {
        last = qdiscs(device)?;
        if replaceable_root(&last, owned_handle) || default_virtual_root(&last) {
            return Ok(());
        }
        if attempt != 4 {
            thread::sleep(Duration::from_millis(20));
        }
    }
    eprintln!(
        "lanspeedd: owned IFB qdisc conflict: {}",
        qdisc_signature(&last)
    );
    Err("ifb_qdisc_owned_by_external_service".into())
}

fn qdisc_signature(values: &[Value]) -> String {
    let mut parts = values
        .iter()
        .take(8)
        .map(|value| {
            let kind = value.get("kind").and_then(Value::as_str).unwrap_or("?");
            let handle = value.get("handle").and_then(Value::as_str).unwrap_or("?");
            let location = if value.get("root").and_then(Value::as_bool) == Some(true) {
                "root"
            } else {
                "aux"
            };
            format!("{kind}/{handle}/{location}")
        })
        .collect::<Vec<_>>();
    if values.len() > parts.len() {
        parts.push("truncated".into());
    }
    parts.join(",")
}

fn replaceable_root(values: &[Value], owned_handle: &str) -> bool {
    let roots = root_qdiscs_from(values);
    roots.is_empty()
        || roots
            .iter()
            .all(|(kind, handle)| kind == "noqueue" || (kind == "htb" && handle == owned_handle))
        || system_mq_tree(values, owned_handle)
}

fn default_virtual_root(values: &[Value]) -> bool {
    let roots = values
        .iter()
        .filter(|value| value.get("root").and_then(Value::as_bool) == Some(true))
        .collect::<Vec<_>>();
    roots.len() == 1
        && matches!(
            roots[0].get("kind").and_then(Value::as_str),
            Some("fq" | "fq_codel")
        )
        && roots[0].get("handle").and_then(Value::as_str) == Some("0:")
        && values.iter().all(|value| {
            value.get("root").and_then(Value::as_bool) == Some(true)
                || matches!(
                    value.get("kind").and_then(Value::as_str),
                    Some("clsact" | "ingress")
                )
        })
}

pub(crate) fn system_mq_tree(values: &[Value], owned_handle: &str) -> bool {
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

pub(crate) fn has_qdisc(device: &str, kind: &str, handle: Option<&str>) -> bool {
    qdiscs(device).is_ok_and(|values| {
        values.iter().any(|value| {
            value.get("kind").and_then(Value::as_str) == Some(kind)
                && handle.is_none_or(|handle| {
                    value.get("handle").and_then(Value::as_str) == Some(handle)
                })
        })
    })
}

pub(crate) fn ensure_clsact(device: &str) -> Result<(), String> {
    if has_qdisc(device, "clsact", None) {
        return Ok(());
    }
    if has_qdisc(device, "ingress", None) {
        return Err("ingress_qdisc_owned_by_external_service".into());
    }
    run("tc", &["qdisc", "add", "dev", device, "clsact"])
}

pub(crate) fn counter(value: &Value, name: &str) -> u64 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names_reject_shell_and_path_syntax() {
        assert!(valid_interface_name("br-lan"));
        assert!(valid_interface_name("ifb-lanspeed"));
        assert!(!valid_interface_name("br-lan\";flush"));
        assert!(!valid_interface_name("bad/interface"));
        assert!(!valid_interface_name("this-interface-name-is-too-long"));
    }

    #[test]
    fn only_default_mq_trees_are_replaceable() {
        let default = vec![
            serde_json::json!({ "kind": "mq", "handle": "0:", "root": true }),
            serde_json::json!({ "kind": "fq_codel", "handle": "0:", "parent": ":1" }),
        ];
        assert!(system_mq_tree(&default, "7a10:"));
        let foreign = vec![
            serde_json::json!({ "kind": "mq", "handle": "0:", "root": true }),
            serde_json::json!({ "kind": "cake", "handle": "8001:", "parent": ":1" }),
        ];
        assert!(!system_mq_tree(&foreign, "7a10:"));
    }

    #[test]
    fn standalone_default_leaf_is_only_replaceable_on_an_owned_virtual_link() {
        let default = vec![serde_json::json!({
            "kind": "fq_codel",
            "handle": "0:",
            "root": true
        })];
        assert!(default_virtual_root(&default));
        assert!(!replaceable_root(&default, "7a20:"));

        let foreign_handle = vec![serde_json::json!({
            "kind": "fq_codel",
            "handle": "8001:",
            "root": true
        })];
        assert!(!default_virtual_root(&foreign_handle));

        let extra_qdisc = vec![
            serde_json::json!({ "kind": "fq", "handle": "0:", "root": true }),
            serde_json::json!({ "kind": "clsact", "handle": "ffff:" }),
        ];
        assert!(default_virtual_root(&extra_qdisc));

        let foreign_leaf = vec![
            serde_json::json!({ "kind": "fq", "handle": "0:", "root": true }),
            serde_json::json!({ "kind": "cake", "handle": "8001:", "parent": "ffff:fff1" }),
        ];
        assert!(!default_virtual_root(&foreign_leaf));
    }

    #[test]
    fn qdisc_signature_is_bounded_and_contains_no_options() {
        let values = (0..12)
            .map(|index| {
                serde_json::json!({
                    "kind": "fq_codel",
                    "handle": format!("{index}:"),
                    "root": index == 0,
                    "options": { "private": "must-not-appear" }
                })
            })
            .collect::<Vec<_>>();
        let signature = qdisc_signature(&values);
        assert!(signature.ends_with(",truncated"));
        assert!(!signature.contains("private"));
        assert!(!signature.contains("must-not-appear"));
    }
}
