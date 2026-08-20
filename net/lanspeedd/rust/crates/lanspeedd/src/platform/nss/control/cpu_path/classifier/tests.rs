#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn upload_rule() -> ActiveRule {
        ActiveRule {
            identity_key: "30:c5:99:a7:bb:2d@lan".into(),
            mac: "30:c5:99:a7:bb:2d".parse().unwrap(),
            interface: "edge0".into(),
            upload_before_proxy: true,
            upload_preempted: true,
            ips: vec!["192.0.2.11".parse().unwrap()],
            upload_bps: 10_000_000,
            download_bps: 100_000_000,
            internet_disabled: false,
            class_minor: 0x7cf7,
        }
    }

    #[test]
    fn download_cpu_packets_use_the_physical_nss_classid() {
        assert_eq!(qdisc_classid(0x7cf7), "7cf7:0");
        assert!(tc_classids_equal("7cf7:", "7cf7:0"));
        assert!(tc_classids_equal("0x7cf7:0000", "7cf7:"));
        assert!(!tc_classids_equal("7cf7:1", "7cf7:0"));
    }

    #[test]
    fn upload_mapping_is_one_per_dynamic_edge() {
        let edge = "edge0";
        assert_eq!(
            upload_edges(&ControlPlan {
                lan_device: String::new(),
                control_devices: Vec::new(),
                dae_upload_devices: Vec::new(),
                local_prefixes: Vec::new(),
                rules: Vec::new(),
                nss: crate::control::nss_state::NssControlPlan::default(),
            })
            .get(edge),
            None
        );
    }

    #[test]
    fn physical_edge_ingress_uses_the_target_proven_source_mac_layout() {
        assert_eq!(
            edge_ingress_mac_matches(&upload_rule()),
            vec![
                system::TcU32Match {
                    offset: -8,
                    value: "30c599a7".into(),
                    mask: "ffffffff".into(),
                },
                system::TcU32Match {
                    offset: -4,
                    value: "bb2d0000".into(),
                    mask: "ffff0000".into(),
                },
            ]
        );
    }

    #[test]
    fn upload_redirect_requires_one_class_assignment_and_the_owned_igs_target() {
        let actions = vec![
            json!({
                "kind": "skbedit",
                "priority": "7cf7:",
                "control_action": {"type": "pipe"}
            }),
            json!({
                "kind": "mirred",
                "mirred_action": "redirect",
                "direction": "egress",
                "to_dev": "lsu12345678",
                "control_action": {"type": "stolen"}
            }),
        ];
        assert!(exact_upload_redirect_actions(
            &actions,
            Some("7cf7:0"),
            "lsu12345678"
        ));
        assert!(!exact_upload_redirect_actions(
            &actions,
            Some("7cf8:0"),
            "lsu12345678"
        ));
        assert!(!exact_upload_redirect_actions(
            &actions,
            Some("7cf7:0"),
            "ifb-foreign"
        ));

        let mut offloaded = actions;
        offloaded[1]["to_dev"] = json!("*");
        assert!(exact_upload_redirect_actions(
            &offloaded,
            Some("7cf7:0"),
            "lsu12345678"
        ));
        assert!(!exact_upload_redirect_actions(
            &offloaded,
            Some("7cf7:0"),
            "ifb-foreign"
        ));
    }

    #[test]
    fn upload_chain_cleanup_requires_the_terminal_marker_and_exact_actions() {
        let values = vec![
            json!({
                "protocol": "ip",
                "pref": UPLOAD_LOCAL_PREF_START,
                "kind": "u32",
                "options": {"actions": [{
                    "kind": "gact",
                    "control_action": {"type": "pass"}
                }]}
            }),
            json!({
                "protocol": "ipv6",
                "pref": UPLOAD_CLIENT_PREF_START,
                "kind": "u32",
                "options": {"actions": [
                    {
                        "kind": "skbedit",
                        "priority": "7cf7:",
                        "control_action": {"type": "pipe"}
                    },
                    {
                        "kind": "mirred",
                        "mirred_action": "redirect",
                        "direction": "egress",
                        "to_dev": "lsu12345678",
                        "control_action": {"type": "stolen"}
                    }
                ]}
            }),
            json!({
                "protocol": "all",
                "pref": UPLOAD_TERMINAL_PREF,
                "kind": "matchall",
                "chain": UPLOAD_CHAIN,
                "options": {"handle": UPLOAD_CHAIN, "actions": [{
                    "kind": "gact",
                    "control_action": {"type": "pass"}
                }]}
            }),
        ];
        assert!(upload_chain_owned(&values, "lsu12345678"));

        let mut foreign = values.clone();
        foreign[1]["options"]["actions"][1]["to_dev"] = json!("ifb-foreign");
        assert!(!upload_chain_owned(&foreign, "lsu12345678"));

        assert!(!upload_chain_owned(&values[..2], "lsu12345678"));
    }

    #[test]
    fn upload_and_download_use_disjoint_qca_u32_preferences() {
        let upload = [
            UPLOAD_LOCAL_PREF_START,
            UPLOAD_BLOCK_PREF_START,
            UPLOAD_CLIENT_PREF_START,
            UPLOAD_TERMINAL_PREF,
        ];
        let download = [
            LOCAL_PREF_START,
            BLOCK_PREF_START,
            CLIENT_PREF_START,
            TERMINAL_PREF,
        ];
        assert!(upload.iter().all(|pref| !download.contains(pref)));
        assert!(UPLOAD_TERMINAL_PREF < LOCAL_PREF_START);
    }

    #[test]
    fn old_colliding_upload_chain_is_reclaimed_only_with_its_exact_marker() {
        let values = vec![
            json!({
                "protocol": "ip",
                "pref": LOCAL_PREF_START,
                "kind": "u32",
                "options": {"actions": [{
                    "kind": "gact",
                    "control_action": {"type": "pass"}
                }]}
            }),
            json!({
                "protocol": "all",
                "pref": TERMINAL_PREF,
                "kind": "matchall",
                "chain": UPLOAD_CHAIN,
                "options": {"handle": UPLOAD_CHAIN, "actions": [{
                    "kind": "gact",
                    "control_action": {"type": "pass"}
                }]}
            }),
        ];
        assert!(legacy_colliding_upload_chain_owned(&values, "lsu12345678"));

        let mut foreign = values.clone();
        foreign[0]["options"]["actions"][0]["kind"] = json!("police");
        assert!(!legacy_colliding_upload_chain_owned(
            &foreign,
            "lsu12345678"
        ));

        let mut wrong_marker = values;
        wrong_marker[1]["options"]["handle"] = json!(DOWNLOAD_CHAIN);
        assert!(!legacy_colliding_upload_chain_owned(
            &wrong_marker,
            "lsu12345678"
        ));
    }

    #[test]
    fn nssmirred_text_parser_requires_exact_from_and_target_interfaces() {
        let text = "filter protocol all pref 53376 matchall chain 0 handle 0x7e80\n\
                    \taction order 1: nssmirred (edge0 to device lsu12345678) stolen\n\
                    \tindex 1 ref 1 bind 1\n";
        assert_eq!(
            parse_igs_mapping(text, "edge0").unwrap().as_deref(),
            Some("lsu12345678")
        );
        assert!(parse_igs_mapping(text, "edge1").is_err());
    }

    #[test]
    fn cpu_input_counter_sums_ipv4_and_ipv6_action_bytes() {
        let values = vec![
            json!({
                "protocol": "ip",
                "pref": UPLOAD_CLIENT_PREF_START,
                "kind": "u32",
                "options": {"actions": [{"kind": "skbedit", "stats": {"bytes": 123}}]}
            }),
            json!({
                "protocol": "ipv6",
                "pref": UPLOAD_CLIENT_PREF_START + 1,
                "kind": "u32",
                "options": {"actions": [{"kind": "skbedit", "stats": {"bytes": 456}}]}
            }),
        ];
        let mut pref = UPLOAD_CLIENT_PREF_START;
        assert_eq!(
            protocol_action_bytes(&values, &mut pref, "skbedit").unwrap(),
            579
        );
        assert_eq!(pref, UPLOAD_CLIENT_PREF_START + 2);
    }

    #[test]
    fn differential_chain_sync_removes_only_slots_outside_the_desired_plan() {
        let values = vec![
            json!({ "protocol": "ip", "pref": 12000, "kind": "u32" }),
            json!({ "protocol": "ipv6", "pref": 12001, "kind": "u32" }),
            json!({ "protocol": "ip", "pref": 14000, "kind": "u32" }),
            json!({ "protocol": "all", "pref": 19999, "kind": "matchall" }),
        ];
        let desired = BTreeSet::from([
            (12000, "ip".to_owned()),
            (12001, "ipv6".to_owned()),
        ]);
        assert_eq!(
            stale_u32_slots(&values, &desired),
            BTreeSet::from([(14000, "ip".to_owned())])
        );
    }

    #[test]
    fn orphaned_download_chain_requires_only_lanspeed_entries() {
        let values = vec![
            json!({
                "protocol": "ip",
                "pref": 20000,
                "kind": "u32",
                "options": {"actions": [{"kind": "gact", "control_action": {"type": "pass"}}]}
            }),
            json!({
                "protocol": "ip",
                "pref": 30000,
                "kind": "u32",
                "options": {"actions": [{
                    "kind": "mirred",
                    "mirred_action": "redirect",
                    "control_action": {"type": "stolen"}
                }]}
            }),
            json!({
                "protocol": "all",
                "pref": 65534,
                "kind": "matchall",
                "chain": 32289,
                "options": {"handle": 32289, "actions": [{"kind": "gact", "control_action": {"type": "pass"}}]}
            }),
        ];
        assert!(download_chain_owned(&values));

        let mut foreign = values;
        foreign[1]["options"]["actions"][0]["kind"] = json!("police");
        assert!(!download_chain_owned(&foreign));
    }
}
