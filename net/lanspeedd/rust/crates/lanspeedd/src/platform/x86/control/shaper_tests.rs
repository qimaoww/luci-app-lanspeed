#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_is_one_frame_and_jumbo_safe() {
        assert_eq!(control_quantum_from_mtu(Some(1_500)), 1_514);
        assert_eq!(control_quantum_from_mtu(Some(9_000)), 9_014);
        assert_eq!(control_quantum_from_mtu(Some(u64::MAX)), 60_000);
        assert_eq!(control_quantum_from_mtu(None), 1_514);
    }

    #[test]
    fn upload_and_download_use_distinct_owned_roots() {
        assert_eq!(Direction::Upload.handle(), "7a20:");
        assert_eq!(Direction::Download.handle(), "7a10:");
    }

    fn rule(upload_before_proxy: bool, upload_bps: u64, download_bps: u64) -> ActiveRule {
        ActiveRule {
            identity_key: "02:00:00:00:00:01@lan".into(),
            mac: "02:00:00:00:00:01".parse().unwrap(),
            interface: "br-lan".into(),
            upload_before_proxy,
            upload_preempted: false,
            ips: Vec::new(),
            upload_bps,
            download_bps,
            internet_disabled: false,
            class_minor: 0x123,
        }
    }

    #[test]
    fn application_rate_compensation_is_direction_and_proxy_independent() {
        let dae = rule(true, 10_000_000, 10_000_000);
        let direct = rule(false, 10_000_000, 10_000_000);
        assert_eq!(Direction::Upload.rate(&dae), 11_000_000);
        assert_eq!(Direction::Upload.rate(&direct), 11_000_000);
        assert_eq!(Direction::Download.rate(&dae), 11_000_000);
    }

    #[test]
    fn application_rate_compensation_clamps_to_x86_limit() {
        let rule = rule(true, X86_MAX_RATE_BPS, 0);
        assert_eq!(Direction::Upload.rate(&rule), X86_MAX_RATE_BPS);
    }

    #[test]
    fn htb_burst_covers_ten_milliseconds_and_stays_bounded() {
        assert_eq!(htb_burst_bytes(11_000_000, 1_514), 13_750);
        assert_eq!(htb_burst_bytes(550_000_000, 1_514), 687_500);
        assert_eq!(htb_burst_bytes(8_800, 1_514), 1_514);
        assert_eq!(htb_burst_bytes(X86_MAX_RATE_BPS, 60_000), MAX_QUEUE_BYTES);
    }

    #[test]
    fn class_filters_are_l3_only() {
        assert_eq!(CONTROL_PROTOCOLS, ["ip", "ipv6"]);
        assert!(!CONTROL_PROTOCOLS.contains(&"all"));
    }

    #[test]
    fn filter_verification_matches_exact_classids_only() {
        let value = serde_json::json!({
            "options": { "flowid": "7a10:123" }
        });
        assert!(json_contains_string(&value, "7a10:123"));
        assert!(!json_contains_string(&value, "7a10:12"));
    }

    #[test]
    fn download_qdisc_context_does_not_hide_inspection_failures() {
        assert_eq!(
            contextual_qdisc_error(
                "qdisc_owned_by_external_service".into(),
                "download_qdisc_stage_conflict"
            ),
            "download_qdisc_stage_conflict"
        );
        assert_eq!(
            contextual_qdisc_error(
                "qdisc_inspection_invalid".into(),
                "download_qdisc_stage_conflict"
            ),
            "qdisc_inspection_invalid"
        );
    }
}
