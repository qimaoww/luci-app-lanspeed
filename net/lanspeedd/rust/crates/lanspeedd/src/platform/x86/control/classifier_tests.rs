#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goto_chain_is_detected_structurally() {
        let value = serde_json::json!({
            "options": { "actions": [
                { "control_action": { "type": "goto", "chain": CHAIN } }
            ] }
        });
        assert!(contains_goto_chain(&value, CHAIN));
        assert!(!contains_goto_chain(&value, CHAIN + 1));
        assert!(contains_owned_chain_marker(&serde_json::json!({
            "kind": "matchall",
            "options": { "handle": CHAIN }
        })));
        assert!(!contains_owned_chain_marker(&serde_json::json!({
            "kind": "matchall",
            "options": { "handle": CHAIN + 1 }
        })));
    }

    #[test]
    fn capacity_keeps_local_and_client_ranges_separate() {
        let rule = ActiveRule {
            identity_key: "02:00:00:00:00:01@lan".into(),
            mac: "02:00:00:00:00:01".parse().unwrap(),
            interface: "br-lan".into(),
            upload_before_proxy: false,
            upload_preempted: false,
            ips: vec!["192.0.2.8".parse().unwrap()],
            upload_bps: 10_000_000,
            download_bps: 0,
            internet_disabled: false,
            class_minor: 0x123,
        };
        assert_eq!(
            validate_capacity(&[("192.0.2.0".parse().unwrap(), 24)], &[&rule]),
            Ok(())
        );
    }

    #[test]
    fn redirect_verification_is_address_format_independent() {
        let value = serde_json::json!({
            "actions": [{
                "kind": "mirred",
                "mirred_action": "redirect",
                "direction": "egress",
                "to_dev": ifb::DEVICE
            }]
        });
        assert_eq!(count_ifb_redirects(&value, ifb::DEVICE), 1);
        assert_eq!(count_ifb_redirects(&value, "ifb-foreign"), 0);
    }

    #[test]
    fn client_redirects_are_l3_only() {
        assert_eq!(CONTROL_PROTOCOLS, ["ip", "ipv6"]);
        assert!(!CONTROL_PROTOCOLS.contains(&"all"));
    }
}
