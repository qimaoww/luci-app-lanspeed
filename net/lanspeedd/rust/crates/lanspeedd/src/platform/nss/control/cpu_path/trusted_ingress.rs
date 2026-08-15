use std::collections::BTreeSet;

use crate::control::ControlPlan;

use super::system;

const MAX_TRUSTED_INGRESS: usize = 64;

pub(super) fn sync(plan: &ControlPlan) -> Result<(), String> {
    let config = render(plan)?;
    if let Some(result) = super::super::genl::write_trusted_ingress(&config) {
        result.map_err(|_| "nss_trusted_ingress_replace_failed".to_owned())?;
    }
    Ok(())
}

pub(super) fn cleanup() -> Result<(), String> {
    if let Some(result) = super::super::genl::write_trusted_ingress("v1\n") {
        result.map_err(|_| "nss_trusted_ingress_cleanup_failed".to_owned())?;
    }
    Ok(())
}

fn render(plan: &ControlPlan) -> Result<String, String> {
    let mut devices = BTreeSet::new();
    devices.extend(plan.control_devices.iter().cloned());
    devices.extend(plan.dae_upload_devices.iter().cloned());
    devices.extend(plan.rules.iter().map(|rule| rule.interface.clone()));
    if devices.len() > MAX_TRUSTED_INGRESS {
        return Err("nss_trusted_ingress_capacity_exceeded".into());
    }
    if devices
        .iter()
        .any(|device| !system::valid_interface_name(device))
    {
        return Err("nss_trusted_ingress_interface_invalid".into());
    }
    let mut config = String::from("v1");
    for device in devices {
        config.push(' ');
        config.push_str(&device);
    }
    config.push('\n');
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::control::{ActiveRule, ControlPlan};
    use crate::identity::MacAddress;
    use std::net::IpAddr;

    fn plan() -> ControlPlan {
        ControlPlan {
            lan_device: "br-lan".into(),
            control_devices: vec!["br-lan".into(), "br-lan".into()],
            dae_upload_devices: vec!["lan1".into()],
            local_prefixes: Vec::new(),
            rules: vec![ActiveRule {
                identity_key: "client".into(),
                mac: "02:00:00:00:00:01".parse::<MacAddress>().unwrap(),
                interface: "lan1".into(),
                upload_before_proxy: false,
                upload_preempted: false,
                ips: vec!["192.0.2.10".parse::<IpAddr>().unwrap()],
                upload_bps: 1,
                download_bps: 0,
                internet_disabled: false,
                class_minor: 1,
            }],
            #[cfg(feature = "nss-platform")]
            nss: Default::default(),
        }
    }

    #[test]
    fn render_deduplicates_proven_ingress_devices() {
        assert_eq!(render(&plan()).unwrap(), "v1 br-lan lan1\n");
    }

    #[test]
    fn render_rejects_invalid_interface_names() {
        let mut value = plan();
        value.control_devices = vec!["br lan".into()];
        assert_eq!(
            render(&value),
            Err("nss_trusted_ingress_interface_invalid".into())
        );
    }

    #[test]
    fn render_is_bounded() {
        let mut value = plan();
        value.control_devices = (0..65).map(|index| format!("lan{index}")).collect();
        assert_eq!(
            render(&value),
            Err("nss_trusted_ingress_capacity_exceeded".into())
        );
    }
}
