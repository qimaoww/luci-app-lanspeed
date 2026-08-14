#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(sample_ms: u64, handle: u64, upload: u64, download: u64) -> PathProbeSnapshot {
        PathProbeSnapshot {
            epoch_end_ms: sample_ms,
            read_end_ms: sample_ms,
            table_handle: handle,
            counters: BTreeMap::from([
                (
                    ProbeKey {
                        interface: "edge-a".into(),
                        mac: "02:00:00:00:00:01".into(),
                        direction: Direction::Upload,
                    },
                    upload,
                ),
                (
                    ProbeKey {
                        interface: "edge-a".into(),
                        mac: "02:00:00:00:00:01".into(),
                        direction: Direction::Download,
                    },
                    download,
                ),
            ]),
        }
    }

    #[test]
    fn probe_book_returns_only_exact_continuous_counter_windows() {
        let mut book = PathProbeBook::default();
        book.push(snapshot(1_000, 7, 10, 20));
        book.push(snapshot(7_000, 7, 610, 1_220));
        let window = book
            .window("edge-a", "02:00:00:00:00:01", 1_000, 7_000)
            .unwrap();
        assert_eq!(window.upload.unwrap().bytes, 600);
        assert_eq!(window.upload.unwrap().bps, 800);
        assert_eq!(window.download.unwrap().bytes, 1_200);
        assert_eq!(window.download.unwrap().bps, 1_600);
        assert!(book
            .window("edge-a", "02:00:00:00:00:01", 2_000, 7_000)
            .is_none());
    }

    #[test]
    fn probe_book_discards_table_reloads_and_counter_resets() {
        let mut book = PathProbeBook::default();
        book.push(snapshot(1_000, 7, 100, 200));
        book.push(snapshot(2_000, 8, 110, 220));
        assert_eq!(book.snapshots.len(), 1);
        book.push(snapshot(3_000, 8, 1, 2));
        assert_eq!(book.snapshots.len(), 1);
    }

    #[test]
    fn nft_counter_parser_requires_both_ip_families() {
        let value = json!({"nftables": [
            {"rule": {"table": TABLE, "chain": UPLOAD_CHAIN,
                "comment": format!("{OWNER_COMMENT}:upload:ip"),
                "expr": [
                    {"match":{"left":{"meta":{"key":"iifname"}},"right":"edge-a"}},
                    {"match":{"left":{"payload":{"protocol":"ether","field":"saddr"}},"right":"02:00:00:00:00:01"}},
                    {"counter":{"packets":1,"bytes":100}}
                ]}},
            {"rule": {"table": TABLE, "chain": UPLOAD_CHAIN,
                "comment": format!("{OWNER_COMMENT}:upload:ip6"),
                "expr": [
                    {"match":{"left":{"meta":{"key":"iifname"}},"right":"edge-a"}},
                    {"match":{"left":{"payload":{"protocol":"ether","field":"saddr"}},"right":"02:00:00:00:00:01"}},
                    {"counter":{"packets":2,"bytes":200}}
                ]}}
        ]});
        let values = counter_values(&value).unwrap();
        assert_eq!(values.values().copied().collect::<Vec<_>>(), vec![300]);
    }

    #[test]
    fn path_probe_is_nss_only_and_uses_bridge_hooks_without_a_verdict() {
        let script = build_script(
            &ControlPlan {
                lan_device: "bridge-a".into(),
                control_devices: vec!["edge-a".into()],
                dae_upload_devices: Vec::new(),
                local_prefixes: vec![("192.168.0.0".parse().unwrap(), 16)],
                rules: vec![crate::control::ActiveRule {
                    identity_key: "02:00:00:00:00:01@lan".into(),
                    mac: "02:00:00:00:00:01".parse().unwrap(),
                    interface: "edge-a".into(),
                    ips: vec!["192.168.1.2".parse().unwrap()],
                    upload_bps: 10_000_000,
                    download_bps: 20_000_000,
                    internet_disabled: false,
                    class_minor: 0x123,
                    upload_before_proxy: false,
                    upload_preempted: false,
                }],
                nss: crate::control::nss_state::NssControlPlan::default(),
            },
            false,
        );
        assert!(script.contains("hook prerouting"));
        assert!(script.contains("hook postrouting"));
        assert!(script.contains("ip daddr @local4 return"));
        assert!(script.contains("ip saddr @local4 return"));
        assert!(script.contains("counter comment"));
        assert!(!script.contains(" redirect "));
        assert!(!script.contains(" drop"));
        assert!(!script.contains(" reject"));
    }

    #[test]
    fn configured_direction_bits_match_probe_selection() {
        use crate::control::{NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD};

        assert_eq!(Direction::Upload.bit(), NSS_CPU_UPLOAD);
        assert_eq!(Direction::Download.bit(), NSS_CPU_DOWNLOAD);
    }
}
