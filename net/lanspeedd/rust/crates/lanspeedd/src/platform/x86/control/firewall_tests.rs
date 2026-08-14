#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ControlPlan {
        ControlPlan {
            lan_device: "br-lan".into(),
            control_devices: vec!["br-lan".into()],
            dae_upload_devices: Vec::new(),
            local_prefixes: vec![
                ("192.0.2.0".parse().unwrap(), 24),
                ("2001:db8::".parse().unwrap(), 64),
            ],
            rules: vec![ActiveRule {
                identity_key: "02:00:00:00:00:01@lan".into(),
                mac: "02:00:00:00:00:01".parse().unwrap(),
                interface: "br-lan".into(),
                upload_before_proxy: false,
                upload_preempted: false,
                ips: vec!["192.0.2.9".parse().unwrap(), "2001:db8::9".parse().unwrap()],
                upload_bps: 0,
                download_bps: 0,
                internet_disabled: true,
                class_minor: 0x123,
            }],
        }
    }

    #[test]
    fn nft_fallback_preserves_local_traffic_and_blocks_both_directions() {
        let script = build_nft_script(&plan(), false);
        assert!(script.contains(NFT_OWNER_COMMENT));
        assert!(
            script
                .find("ip saddr @local4 ip daddr @local4 return")
                .unwrap()
                < script.find("ip saddr @blocked4 reject").unwrap()
        );
        assert!(script.contains("ip daddr @blocked4 reject"));
        assert!(script.contains("ip6 daddr @blocked6 reject"));
    }

    #[test]
    fn tc_blocking_matches_only_ipv4_and_ipv6_never_arp() {
        assert_eq!(CONTROL_PROTOCOLS, ["ip", "ipv6"]);
        assert!(!CONTROL_PROTOCOLS.contains(&"all"));
    }

    #[test]
    fn tc_blocking_is_grouped_by_the_actual_client_edge() {
        let mut plan = plan();
        let mut guest = plan.rules[0].clone();
        guest.identity_key = "02:00:00:00:00:02@guest".into();
        guest.mac = "02:00:00:00:00:02".parse().unwrap();
        guest.interface = "br-guest".into();
        plan.rules.push(guest);
        let ingress = ingress_rules_by_device(&plan);
        let egress = egress_rules_by_device(&plan);
        assert_eq!(ingress["br-lan"].len(), 1);
        assert_eq!(ingress["br-guest"].len(), 1);
        assert_eq!(egress["br-guest"].len(), 1);
    }

    #[test]
    fn nft_ownership_requires_family_name_and_comment() {
        let owned = serde_json::json!({
            "nftables": [{ "table": {
                "family": "inet",
                "name": NFT_TABLE,
                "comment": NFT_OWNER_COMMENT
            }}]
        });
        assert!(nft_table_present(&owned, "inet", NFT_TABLE));
        assert!(nft_table_owned(&owned));

        let foreign = serde_json::json!({
            "nftables": [{ "table": {
                "family": "inet",
                "name": NFT_TABLE,
                "comment": "external-service"
            }}]
        });
        assert!(nft_table_present(&foreign, "inet", NFT_TABLE));
        assert!(!nft_table_owned(&foreign));
    }
}
