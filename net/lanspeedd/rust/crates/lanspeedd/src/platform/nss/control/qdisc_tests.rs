#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nss_tree_has_one_firmware_root_group() {
        assert_eq!(classid(ROOT_CLASS_MINOR), "7d00:1");
        assert_eq!(classid(DEFAULT_CLASS_MINOR), "7d00:2");
        assert_eq!(classid(0x123), "7d00:123");
        assert_eq!(leaf_handle(0x7c23), "7c23:");
        assert_eq!(leaf_tag(0x7c23), "7c23:0");
    }

    #[test]
    fn direct_inventory_excludes_owned_cpu_path_executor() {
        let cpu_path_devices = BTreeSet::from(["lsu12345678".to_owned()]);
        assert!(direct_shaper_candidate("edge0", &cpu_path_devices));
        assert!(!direct_shaper_candidate("lsu12345678", &cpu_path_devices));
    }

    #[test]
    fn nss_class_parser_accepts_libwrt_non_json_output() {
        let handles = parse_class_handles(
            "class nsshtb 7d00:123 root leaf 8001: burst 9072b\n\
             class nsshtb 7d00:2 root leaf 7d02: burst 536870b\n",
        )
        .unwrap();
        assert!(handles.contains("7d00:123"));
        assert!(handles.contains("7d00:2"));
    }

    #[test]
    fn nss_qdisc_detail_parser_preserves_firmware_options() {
        let values = parse_nss_qdisc_details(
            "qdisc nsshtb 7d00: root refcnt 5 r2q 10 accel_mode 0\n\
             qdisc nssbfifo 7d02: parent 7d00:2 limit 16Mb set_default accel_mode 0\n\
             qdisc nssbfifo 7c23: parent 7d00:7c23 limit 687500b accel_mode 0\n\
             qdisc clsact ffff: parent ffff:fff1\n",
        )
        .unwrap();
        assert_eq!(
            values,
            vec![
                NssQdiscDetail {
                    kind: "nsshtb".into(),
                    handle: "7d00:".into(),
                    parent: None,
                    root: true,
                    r2q: Some(10),
                    accel_mode: Some(0),
                    limit: None,
                    set_default: false,
                },
                NssQdiscDetail {
                    kind: "nssbfifo".into(),
                    handle: "7d02:".into(),
                    parent: Some("7d00:2".into()),
                    root: false,
                    r2q: None,
                    accel_mode: Some(0),
                    limit: Some("16Mb".into()),
                    set_default: true,
                },
                NssQdiscDetail {
                    kind: "nssbfifo".into(),
                    handle: "7c23:".into(),
                    parent: Some("7d00:7c23".into()),
                    root: false,
                    r2q: None,
                    accel_mode: Some(0),
                    limit: Some("687500b".into()),
                    set_default: false,
                },
            ]
        );
    }

    #[test]
    fn nss_class_detail_parser_preserves_firmware_options() {
        let values = parse_nss_class_details(
            "class nsshtb 7d00:1 root burst 1Mb rate 0bit cburst 1Mb crate 4Gbit priority 0 quantum 1514b overhead 0b\n\
             class nsshtb 7d00:7c23 root leaf 7c23: burst 13750b rate 11Mbit cburst 13750b crate 11Mbit priority 1 quantum 1514b overhead 0b\n",
        )
        .unwrap();
        assert_eq!(
            values[1],
            NssClassDetail {
                handle: "7d00:7c23".into(),
                leaf: Some("7c23:".into()),
                burst: "13750b".into(),
                rate: "11Mbit".into(),
                cburst: "13750b".into(),
                crate_rate: "11Mbit".into(),
                priority: 1,
                quantum: "1514b".into(),
                overhead: "0b".into(),
            }
        );
    }

    #[test]
    fn nss_text_format_matches_target_iproute2() {
        assert_eq!(tc_rate_text(0), "0bit");
        assert_eq!(tc_rate_text(11_000_000), "11Mbit");
        assert_eq!(tc_rate_text(110_000_000), "110Mbit");
        assert_eq!(tc_rate_text(NSS_MAX_RATE_BPS), "4Gbit");
        assert_eq!(tc_rate_text(11_000_007), "11Mbit");
        assert_eq!(tc_size_text(16 * 1024 * 1024), "16Mb");
        assert_eq!(tc_size_text(1024 * 1024), "1Mb");
        assert_eq!(tc_size_text(1514), "1514b");
        assert_eq!(tc_size_text(687_500), "687500b");
    }

    #[test]
    fn nss_base_fingerprint_detects_default_queue_drift() {
        let qdiscs = parse_nss_qdisc_details(
            "qdisc nsshtb 7d00: root refcnt 5 r2q 10 accel_mode 0\n\
             qdisc nssbfifo 7d02: parent 7d00:2 limit 16Mb set_default accel_mode 0\n",
        )
        .unwrap();
        let classes = parse_nss_class_details(
            "class nsshtb 7d00:1 root burst 1Mb rate 0bit cburst 1Mb crate 4Gbit priority 0 quantum 1514b overhead 0b\n\
             class nsshtb 7d00:2 root leaf 7d02: burst 1Mb rate 0bit cburst 1Mb crate 4Gbit priority 2 quantum 1514b overhead 0b\n",
        )
        .unwrap();
        let (root_qdisc, default_qdisc) = expected_base_qdiscs();
        let (root_class, default_class) = expected_base_classes(NSS_MAX_RATE_BPS);
        assert_eq!(exact_detail_count(&qdiscs, &root_qdisc), 1);
        assert_eq!(exact_detail_count(&qdiscs, &default_qdisc), 1);
        assert_eq!(exact_detail_count(&classes, &root_class), 1);
        assert_eq!(exact_detail_count(&classes, &default_class), 1);

        let mut changed = default_qdisc;
        changed.limit = Some("8Mb".into());
        assert_eq!(exact_detail_count(&qdiscs, &changed), 0);
    }

    #[test]
    fn nss_payload_rate_has_independent_l2_headroom_and_stays_u32_safe() {
        assert_eq!(payload_rate(10_000_000), 11_000_000);
        assert_eq!(payload_rate(100_000_000), 110_000_000);
        assert_eq!(payload_rate(NSS_MAX_RATE_BPS), NSS_MAX_RATE_BPS);
    }

    #[test]
    fn unknown_edge_speed_keeps_default_class_available() {
        assert_eq!(default_class_rate_for_speed(Some(-1)), Ok(NSS_MAX_RATE_BPS));
        assert_eq!(default_class_rate_for_speed(None), Ok(NSS_MAX_RATE_BPS));
        assert_eq!(
            default_class_rate_for_speed(Some(10_000)),
            Err("nss_default_class_capacity_exceeded".into())
        );
    }

    #[test]
    fn nss_burst_covers_ten_milliseconds_and_is_bounded() {
        assert_eq!(burst_bytes(8_000), MIN_BURST_BYTES);
        assert_eq!(burst_bytes(11_000_000), 13_750);
        assert_eq!(burst_bytes(110_000_000), 137_500);
        assert_eq!(burst_bytes(NSS_MAX_RATE_BPS), MAX_BURST_BYTES);
    }
}
