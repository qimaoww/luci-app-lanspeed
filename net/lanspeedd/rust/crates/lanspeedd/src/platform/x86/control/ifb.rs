use std::fs;

use serde_json::Value;

use super::system;

pub(crate) const DEVICE: &str = "ifb-lanspeed";
const OWNER_ALIAS: &str = "lanspeedd:x86-client-control:v1";

pub(crate) fn preflight() -> Result<(), String> {
    if !system::module_available("ifb") {
        return Err("ifb_module_unavailable".into());
    }
    if system::interface_exists(DEVICE) && !owned()? {
        return Err("ifb_owned_by_external_service".into());
    }
    Ok(())
}

pub(crate) fn ensure() -> Result<(), String> {
    preflight()?;
    if !system::interface_exists(DEVICE) {
        system::run("ip", &["link", "add", "name", DEVICE, "type", "ifb"])?;
        if let Err(error) = system::run("ip", &["link", "set", "dev", DEVICE, "alias", OWNER_ALIAS])
        {
            system::run_ignore_missing("ip", &["link", "delete", "dev", DEVICE]);
            return Err(error);
        }
    }
    if !owned()? {
        return Err("ifb_owned_by_external_service".into());
    }
    system::run("ip", &["link", "set", "dev", DEVICE, "up"])
}

pub(crate) fn cleanup() -> Result<(), String> {
    if !system::interface_exists(DEVICE) {
        return Ok(());
    }
    if !owned()? {
        return Err("ifb_owned_by_external_service".into());
    }
    system::run("ip", &["link", "delete", "dev", DEVICE])
}

pub(crate) fn owned() -> Result<bool, String> {
    if !system::interface_exists(DEVICE) {
        return Ok(false);
    }
    let alias = fs::read_to_string(format!("/sys/class/net/{DEVICE}/ifalias")).unwrap_or_default();
    if alias.trim() != OWNER_ALIAS {
        return Ok(false);
    }
    let value = system::json_output(
        "ip",
        &["-j", "-d", "link", "show", "dev", DEVICE],
        "ifb_inspection_failed",
    )?;
    Ok(value.as_array().into_iter().flatten().any(is_ifb_link))
}

fn is_ifb_link(value: &Value) -> bool {
    value
        .get("linkinfo")
        .and_then(|linkinfo| linkinfo.get("info_kind"))
        .and_then(Value::as_str)
        == Some("ifb")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_requires_the_ifb_link_kind() {
        assert!(is_ifb_link(&serde_json::json!({
            "linkinfo": { "info_kind": "ifb" }
        })));
        assert!(!is_ifb_link(&serde_json::json!({
            "linkinfo": { "info_kind": "dummy" }
        })));
        assert!(!is_ifb_link(&serde_json::json!({})));
    }
}
