#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ControlPlan {
        ControlPlan {
            lan_device: "router-lan".into(),
            control_devices: vec!["router-lan".into(), "edge-test0".into()],
            dae_upload_devices: Vec::new(),
            local_prefixes: vec![("192.0.2.0".parse().unwrap(), 24)],
            nss: crate::control::nss_state::NssControlPlan {
                nss_proven_directions: std::collections::BTreeMap::from([(
                    "02:00:00:00:00:01@lan".into(),
                    NSS_CPU_DOWNLOAD,
                )]),
                nss_path_ready_directions: std::collections::BTreeMap::from([(
                    "02:00:00:00:00:01@lan".into(),
                    NSS_CPU_DOWNLOAD,
                )]),
                ..Default::default()
            },
            rules: vec![ActiveRule {
                identity_key: "02:00:00:00:00:01@lan".into(),
                mac: "02:00:00:00:00:01".parse().unwrap(),
                interface: "edge-test0".into(),
                upload_before_proxy: false,
                upload_preempted: false,
                ips: vec!["192.0.2.9".parse().unwrap()],
                upload_bps: 0,
                download_bps: 20_000_000,
                internet_disabled: true,
                class_minor: 0x7c23,
            }],
        }
    }

    #[test]
    fn one_way_limit_only_populates_its_directional_map() {
        let script = build_script(&plan(), false, true);
        assert!(script
            .contains("add element inet lanspeed_nss_control download4 { 192.0.2.9 : 7c23:0 }"));
        assert!(!script.contains("add element inet lanspeed_nss_control upload4"));
        assert!(script.contains("meta priority set ip saddr map @upload4"));
        assert!(script.contains("meta priority set ip daddr map @download4"));
    }

    #[test]
    fn cpu_path_proof_keeps_the_shared_download_nss_priority_map() {
        let mut plan = plan();
        plan.nss_cpu_directions
            .insert("02:00:00:00:00:01@lan".into(), NSS_CPU_DOWNLOAD);
        let script = build_script(&plan, false, true);
        assert!(script
            .contains("add element inet lanspeed_nss_control download4 { 192.0.2.9 : 7c23:0 }"));
        assert!(requires_conntrack(&plan));
    }

    #[test]
    fn local_bypass_precedes_block_and_classification() {
        let script = build_script(&plan(), false, true);
        assert!(
            script
                .find("ip saddr @local4 ip daddr @local4 return")
                .unwrap()
                < script.find("ip saddr @blocked4 reject").unwrap()
        );
        assert!(
            script.find("ip saddr @blocked4 reject").unwrap()
                < script
                    .find("meta priority set ip daddr map @download4")
                    .unwrap()
        );
    }

    #[test]
    fn shaping_only_plan_preflights_conntrack_before_touching_qdisc() {
        let mut plan = plan();
        plan.rules[0].internet_disabled = false;
        assert_eq!(plan.rules[0].upload_bps, 0);
        assert_ne!(plan.rules[0].download_bps, 0);
        assert!(requires_conntrack(&plan));
    }

    #[test]
    fn nft_element_parsers_preserve_exact_prefixes_and_class_pairs() {
        let value = json!({"nftables": [
            {"set": {"name": "local4", "elem": [
                {"prefix": {"addr": "192.0.2.0", "len": 24}},
                "198.51.100.9"
            ]}},
            {"map": {"name": "download4", "elem": [
                ["192.0.2.9", "7c23:0"],
                ["192.0.2.10", "7c24:0"]
            ]}}
        ]});
        assert_eq!(
            set_elements(&value, "local4").unwrap(),
            BTreeSet::from(["192.0.2.0/24".into(), "198.51.100.9".into()])
        );
        assert_eq!(
            map_elements(&value, "download4").unwrap(),
            BTreeMap::from([
                ("192.0.2.9".into(), "7c23:0".into()),
                ("192.0.2.10".into(), "7c24:0".into()),
            ])
        );
    }

    #[test]
    fn nft_forward_contract_contains_exactly_eleven_distinct_rules() {
        let expected = expected_forward_rule_fingerprints();
        assert_eq!(expected.len(), 11);
        assert_eq!(expected.iter().collect::<BTreeSet<_>>().len(), 11);
    }

    #[test]
    fn nft_table_inventory_rejects_extra_owned_table_objects() {
        let mut entries = vec![
            json!({"metainfo": {}}),
            json!({
                "table": {"family": "inet", "name": TABLE}
            }),
        ];
        for name in ["blocked4", "blocked6", "local4", "local6"] {
            entries.push(json!({"set": {"family": "inet", "table": TABLE, "name": name}}));
        }
        for name in ["download4", "download6", "upload4", "upload6"] {
            entries.push(json!({"map": {"family": "inet", "table": TABLE, "name": name}}));
        }
        entries.push(json!({
            "chain": {"family": "inet", "table": TABLE, "name": "forward"}
        }));
        for _ in 0..11 {
            entries.push(json!({"rule": {"family": "inet", "table": TABLE}}));
        }
        let mut value = json!({"nftables": entries});
        assert!(exact_table_inventory(&value));
        value["nftables"].as_array_mut().unwrap().push(json!({
            "chain": {"family": "inet", "table": TABLE, "name": "foreign"}
        }));
        assert!(!exact_table_inventory(&value));
    }
}
