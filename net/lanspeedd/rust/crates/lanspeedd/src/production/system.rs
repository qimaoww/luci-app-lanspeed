use std::{cell::RefCell, fs, path::Path};

use lanspeed_openwrt_sys::UloopGuard;

use crate::{
    config::{
        is_sysdevice_candidate, InterfaceEligibility, RuntimeConfig, SysfsInterfaceEligibility,
        MAX_INTERFACE_NAMES, MAX_INTERFACE_NAME_LEN,
    },
    error::DaemonError,
    model::{InterfaceRole, Sysdevice, SysdeviceLimits, SysdevicesResponse},
};

pub(crate) fn collect_ifnames(config: &RuntimeConfig) -> Vec<String> {
    config.runtime_collect_ifnames()
}

pub(crate) fn collect_ifnames_with_roles(config: &RuntimeConfig) -> Vec<(String, InterfaceRole)> {
    collect_ifnames(config)
        .into_iter()
        .map(|name| (name, InterfaceRole::Lan))
        .chain(
            config
                .runtime_observe_ifnames()
                .into_iter()
                .map(|name| (name, InterfaceRole::Observe)),
        )
        .collect()
}

#[cfg(feature = "nss-platform")]
pub(crate) fn access_edge_bridges(config: &RuntimeConfig) -> Vec<String> {
    collect_ifnames(config)
        .into_iter()
        .filter(|name| {
            Path::new("/sys/class/net")
                .join(name)
                .join("bridge")
                .is_dir()
        })
        .collect()
}

pub(crate) fn sysdevices(config: &RuntimeConfig) -> Result<SysdevicesResponse, DaemonError> {
    let selected = collect_ifnames(config);
    let observed = config.runtime_observe_ifnames();
    let configured_ifnames = if config.configured_ifnames.is_empty() {
        let mut names = Vec::new();
        for name in config.ifnames.iter().chain(config.interface_include.iter()) {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    } else {
        config.configured_ifnames.clone()
    };
    let configured_observed = if config.configured_observed.is_empty() {
        config.observe_ifnames.clone()
    } else {
        config.configured_observed.clone()
    };
    let configured_excluded = if config.configured_excluded.is_empty() {
        config.interface_exclude.clone()
    } else {
        config.configured_excluded.clone()
    };
    let eligibility = SysfsInterfaceEligibility::default();
    let mut devices = Vec::new();
    for entry in fs::read_dir("/sys/class/net")
        .map_err(|error| DaemonError::collection(error.to_string()))?
    {
        let name = entry
            .map_err(|error| DaemonError::collection(error.to_string()))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if !is_sysdevice_candidate(&name) {
            continue;
        }
        let root = Path::new("/sys/class/net").join(&name);
        let speed = fs::read_to_string(root.join("speed"))
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0 && *value < (1 << 31));
        let recommended = eligibility.is_collect_eligible(&name);
        let is_bridge = root.join("bridge").is_dir();
        let is_bridge_port = root.join("brport").is_dir();
        let is_nss_ifb = name == "nssifb";
        let collect_allowed = recommended && !is_nss_ifb;
        let collect_reason = if collect_allowed && is_bridge {
            "eligible_bridge"
        } else if collect_allowed && is_bridge_port {
            "eligible_bridge_port"
        } else if collect_allowed {
            "eligible_ethernet"
        } else if is_nss_ifb {
            "nssifb_observe_only"
        } else {
            "unsupported_link_type"
        };
        devices.push(Sysdevice {
            name: name.clone(),
            selected: selected.contains(&name),
            observed: observed.contains(&name),
            recommended_lan: recommended,
            collect_allowed,
            collect_reason: collect_reason.into(),
            is_bridge,
            is_bridge_port,
            is_nss_ifb,
            speed_mbps: speed,
        });
    }
    let discovered = devices
        .iter()
        .map(|device| device.name.as_str())
        .collect::<Vec<_>>();
    let mut orphaned = Vec::new();
    for name in configured_ifnames
        .iter()
        .chain(configured_observed.iter())
        .chain(configured_excluded.iter())
    {
        if !discovered.contains(&name.as_str()) && !orphaned.contains(name) {
            orphaned.push(name.clone());
        }
    }
    Ok(SysdevicesResponse {
        contract_version: 1,
        devices,
        current_ifnames: selected,
        current_observed: observed,
        current_excluded: Vec::new(),
        configured_ifnames,
        configured_observed,
        configured_excluded,
        orphaned,
        limits: SysdeviceLimits {
            max_configured: MAX_INTERFACE_NAMES,
            max_name_length: MAX_INTERFACE_NAME_LEN.saturating_sub(1),
        },
    })
}

pub(crate) fn version() -> String {
    version_from(
        option_env!("LANSPEED_VERSION"),
        option_env!("LANSPEED_RELEASE"),
    )
}

pub(crate) fn version_from(version: Option<&str>, release: Option<&str>) -> String {
    match (version, release) {
        (Some(version), Some(release)) => format!("{version}-r{release}"),
        _ => "unconfigured".into(),
    }
}

pub(crate) fn record_fatal_cleanup(
    context: &str,
    primary: &str,
    cleanup: &str,
    fatal: &RefCell<Option<String>>,
) -> DaemonError {
    let combined = format!("{context}: {primary}; cleanup failed: {cleanup}");
    *fatal.borrow_mut() = Some(combined.clone());
    UloopGuard::request_stop();
    DaemonError::reload(combined)
}
