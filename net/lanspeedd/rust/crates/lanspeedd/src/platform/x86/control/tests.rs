#[cfg(test)]
mod tests {
    use super::*;

    fn upload_rule(identity: &str, interface: &str, minor: u16) -> crate::control::ActiveRule {
        crate::control::ActiveRule {
            identity_key: identity.into(),
            mac: identity.split('@').next().unwrap().parse().unwrap(),
            interface: interface.into(),
            upload_before_proxy: false,
            upload_preempted: false,
            ips: vec!["192.0.2.9".parse().unwrap()],
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: minor,
        }
    }

    #[test]
    fn upload_rules_are_grouped_by_their_observed_interfaces() {
        let first = upload_rule("02:00:00:00:00:01@lan", "br-lan", 0x101);
        let second = upload_rule("02:00:00:00:00:02@guest", "br-guest", 0x102);
        let third = upload_rule("02:00:00:00:00:03@guest", "br-guest", 0x103);
        let plan = ControlPlan {
            lan_device: "br-lan".into(),
            control_devices: Vec::new(),
            dae_upload_devices: Vec::new(),
            local_prefixes: Vec::new(),
            rules: Vec::new(),
        };
        let grouped = upload_rules_by_device(&plan, &[&first, &second, &third]);

        assert_eq!(grouped["br-lan"].len(), 1);
        assert_eq!(grouped["br-guest"].len(), 2);
    }

    #[test]
    fn download_rules_are_grouped_by_their_observed_interfaces() {
        let mut first = upload_rule("02:00:00:00:00:01@lan", "br-lan", 0x101);
        first.download_bps = 20_000_000;
        let mut second = upload_rule("02:00:00:00:00:02@guest", "br-guest", 0x102);
        second.download_bps = 30_000_000;
        let grouped = download_rules_by_device(&[&first, &second]);
        assert_eq!(grouped["br-lan"][0].identity_key, first.identity_key);
        assert_eq!(grouped["br-guest"][0].identity_key, second.identity_key);
    }

    #[test]
    fn dae_upload_uses_bridge_slaves_before_the_proxy_hook() {
        let mut rule = upload_rule("02:00:00:00:00:01@lan", "br-lan", 0x101);
        rule.upload_before_proxy = true;
        let plan = ControlPlan {
            lan_device: "br-lan".into(),
            control_devices: vec!["br-lan".into()],
            dae_upload_devices: vec!["eth1".into(), "wlan0".into()],
            local_prefixes: Vec::new(),
            rules: vec![rule.clone()],
        };
        let grouped = upload_rules_by_device(&plan, &[&rule]);

        assert!(!grouped.contains_key("br-lan"));
        assert_eq!(grouped["eth1"].len(), 1);
        assert_eq!(grouped["wlan0"].len(), 1);
        assert!(control_devices(&plan).contains("eth1"));
        assert!(control_devices(&plan).contains("wlan0"));
    }

    #[test]
    fn cleanup_devices_include_configured_and_live_edges() {
        let rule = upload_rule("02:00:00:00:00:01@guest", "br-guest", 0x101);
        let plan = ControlPlan {
            lan_device: "br-lan".into(),
            control_devices: vec!["br-lan".into(), "br-iot".into()],
            dae_upload_devices: Vec::new(),
            local_prefixes: Vec::new(),
            rules: vec![rule],
        };

        assert_eq!(
            control_devices(&plan),
            BTreeSet::from(["br-guest".into(), "br-iot".into(), "br-lan".into()])
        );
    }

    #[test]
    fn queue_overflow_is_scoped_to_the_changed_client() {
        let first = "02:00:00:00:00:01@lan/upload_queue_drops";
        let second = "02:00:00:00:00:02@lan/download_queue_drops";
        let previous = BTreeMap::from([(first.into(), 4), (second.into(), 7)]);
        let current = BTreeMap::from([(first.into(), 4), (second.into(), 8)]);
        assert_eq!(
            queue_overflow_identities(&previous, &current),
            BTreeSet::from(["02:00:00:00:00:02@lan".into()])
        );
    }

    #[test]
    fn verification_delta_never_wraps_after_reinstall() {
        let identity = "02:00:00:00:00:01@lan";
        let key = verification_key(identity, "upload_class_bytes");
        let previous = ApplyResult {
            state: "pending".into(),
            reason: None,
            shaping_supported: true,
            blocking_supported: true,
            queue_overflow: false,
            queue_drop_counters: BTreeMap::new(),
            class_counter_baselines: BTreeMap::from([(key.clone(), 100)]),
            verified_directions: BTreeMap::new(),
            verification_failures: BTreeMap::new(),
        };
        assert_eq!(
            verification_delta(
                &previous,
                &BTreeMap::from([(key, 10)]),
                identity,
                "upload_class_bytes"
            ),
            0
        );
    }
}
