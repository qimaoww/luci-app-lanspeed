#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityObservation, ObservationSource};

    fn identities() -> IdentityTable {
        let mut identities = IdentityTable::new(4);
        identities
            .observe(IdentityObservation {
                mac: "02:00:00:00:00:01",
                zone: Some("lan"),
                interface: "br-lan",
                ip: Some("192.0.2.2"),
                hostname: Some("client"),
                last_seen: 1,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
        identities
    }

    fn raw(
        connection: u64,
        generation: u32,
        direction: u8,
        bytes: u64,
        packets: u64,
        last_seen_ms: u64,
    ) -> RawEcmSample {
        RawEcmSample {
            key: EcmKey {
                connection,
                generation,
                direction,
                reserved: 0,
                mac: [0x02, 0, 0, 0, 0, 1],
                padding: [0; 4],
            },
            counters: EcmCounters {
                bytes,
                packets,
                last_seen: last_seen_ms * 1_000_000,
            },
        }
    }

    #[test]
    fn kallsyms_selection_attaches_only_supported_nss_callback_boundaries() {
        let path =
            std::env::temp_dir().join(format!("lanspeed-ecm-kallsyms-{}", std::process::id()));
        fs::write(
            &path,
            concat!(
                "0000000000001000 t ecm_nss_ipv4_net_dev_callback [ecm]\n",
                "0000000000002000 t unrelated_callback [ecm]\n",
                "0000000000003000 t ecm_nss_ipv6_connection_sync_many_callback [ecm]\n",
            ),
        )
        .unwrap();

        let callbacks = available_nss_context_callbacks(&path).unwrap();
        fs::remove_file(path).unwrap();

        assert_eq!(
            callbacks,
            [
                "ecm_nss_ipv4_net_dev_callback",
                "ecm_nss_ipv6_connection_sync_many_callback",
            ]
        );
    }

    #[test]
    fn stable_map_read_generation_ignores_slow_path_but_rejects_nss_progress() {
        let before = EcmSourceStats {
            nss_bytes: 1_000,
            nss_packets: 10,
            nss_updates: 2,
            slow_path_bytes: 100,
            slow_path_packets: 1,
            slow_path_updates: 1,
        };
        let mut after = before;
        after.slow_path_bytes += 100;
        after.slow_path_packets += 1;
        after.slow_path_updates += 1;
        assert!(same_nss_source_generation(before, after));

        after.nss_bytes += 1_500;
        after.nss_packets += 2;
        after.nss_updates += 1;
        assert!(!same_nss_source_generation(before, after));
    }

    #[test]
    fn rates_are_windowed_per_connection_generation_before_client_folding() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        let first = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 1_000, 10, 1_000),
                    raw(2, 20, DIR_TX, 500, 5, 1_000),
                ],
                truncated: false,
            },
            &identities,
            1_000,
        );
        assert_eq!(first.clients[0].tx_bps, 0);
        assert!(first.fresh_rates.is_empty());

        let second = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 3_000, 30, 3_000),
                    raw(2, 20, DIR_TX, 500, 5, 1_000),
                ],
                truncated: false,
            },
            &identities,
            3_000,
        );
        assert_eq!(second.clients[0].tx_bps, 8_320);
        assert_eq!(
            second.fresh_rates[&second.clients[0].identity_key].tx_bps,
            8_320
        );

        let third = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 3_000, 30, 3_000),
                    raw(2, 20, DIR_TX, 2_500, 25, 5_000),
                ],
                truncated: false,
            },
            &identities,
            5_000,
        );
        assert_eq!(third.clients[0].tx_bps, 8_320 + 4_160);
        assert_eq!(
            third.fresh_rates[&third.clients[0].identity_key].tx_bps,
            4_160
        );

        let fourth = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 3_000, 30, 3_000),
                    raw(2, 20, DIR_TX, 2_500, 25, 5_000),
                ],
                truncated: false,
            },
            &identities,
            6_001,
        );
        assert_eq!(fourth.clients[0].tx_bps, 4_160);
        assert!(fourth.fresh_rates.is_empty());
    }

    #[test]
    fn rate_clock_uses_collector_elapsed_time_when_event_timestamp_is_torn() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 1_000, 10, 1_000)],
                truncated: false,
            },
            &identities,
            1_000,
        );

        let snapshot = collector.convert(
            EcmMapRead {
                // Model a concurrent read that sees new counters while
                // last_seen still contains an earlier ECM timestamp.
                entries: vec![raw(1, 10, DIR_TX, 3_000, 30, 1_500)],
                truncated: false,
            },
            &identities,
            3_000,
        );

        assert_eq!(snapshot.clients[0].tx_bps, 8_320);

        let recovery = collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 5_000, 50, 5_000)],
                truncated: false,
            },
            &identities,
            5_000,
        );
        assert_eq!(recovery.clients[0].tx_bps, 8_320);

        let event_clock_restored = collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 7_000, 70, 7_000)],
                truncated: false,
            },
            &identities,
            7_000,
        );
        assert_eq!(event_clock_restored.clients[0].tx_bps, 8_320);
    }

    #[test]
    fn staggered_ecm_updates_keep_a_stable_client_aggregate() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 0, 0, 1_000),
                    raw(2, 20, DIR_TX, 0, 0, 1_000),
                ],
                truncated: false,
            },
            &identities,
            1_000,
        );

        let first = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 2_000, 0, 3_000),
                    raw(2, 20, DIR_TX, 1_000, 0, 2_000),
                ],
                truncated: false,
            },
            &identities,
            3_000,
        );
        assert_eq!(first.clients[0].tx_bps, 16_000);

        let second = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 3_000, 0, 4_000),
                    raw(2, 20, DIR_TX, 4_000, 0, 5_000),
                ],
                truncated: false,
            },
            &identities,
            5_000,
        );
        assert_eq!(second.clients[0].tx_bps, 16_000);
    }

    #[test]
    fn one_destroy_batch_outlier_does_not_spike_a_connection_rate() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 0, 0, 0)],
                truncated: false,
            },
            &identities,
            0,
        );

        for (now_ms, bytes) in [(2_000, 2_000), (4_000, 4_000), (6_000, 6_000)] {
            let snapshot = collector.convert(
                EcmMapRead {
                    entries: vec![raw(1, 10, DIR_TX, bytes, 0, now_ms)],
                    truncated: false,
                },
                &identities,
                now_ms,
            );
            assert_eq!(snapshot.clients[0].tx_bps, 8_000);
        }

        let destroy = collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 10_000, 0, 8_000)],
                truncated: false,
            },
            &identities,
            8_000,
        );
        assert_eq!(destroy.clients[0].tx_bps, 8_000);
    }

    #[test]
    fn a_reused_connection_generation_rebaselines_without_resetting_other_flows() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 100, 1, 1_000),
                    raw(2, 20, DIR_RX, 100, 1, 1_000),
                ],
                truncated: false,
            },
            &identities,
            1_000,
        );
        let snapshot = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 11, DIR_TX, 50, 1, 3_000),
                    raw(2, 20, DIR_RX, 2_100, 21, 3_000),
                ],
                truncated: false,
            },
            &identities,
            3_000,
        );
        assert_eq!(snapshot.clients[0].tx_bps, 216);
        assert_eq!(snapshot.clients[0].rx_bps, 8_320);
    }

    #[test]
    fn coverage_delta_uses_raw_bytes_and_packets_without_generation_regression() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 1_000, 10, 1_000),
                    raw(2, 20, DIR_RX, 2_000, 20, 1_000),
                ],
                truncated: false,
            },
            &identities,
            1_000,
        );

        let progressed = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 3_000, 30, 3_000),
                    raw(2, 20, DIR_RX, 6_000, 60, 3_000),
                ],
                truncated: false,
            },
            &identities,
            3_000,
        );
        assert_eq!(
            progressed.coverage_delta,
            TrafficCounters {
                tx_bytes: 2_000,
                rx_bytes: 4_000,
                tx_packets: 20,
                rx_packets: 40,
            }
        );
        assert_eq!(progressed.coverage_start_ms, Some(1_000));
        assert_eq!(progressed.coverage_end_ms, 3_000);
        assert_eq!(
            progressed.coverage_deltas.get("02:00:00:00:00:01@lan"),
            Some(&progressed.coverage_delta)
        );

        let disappeared = collector.convert(
            EcmMapRead {
                entries: vec![raw(2, 20, DIR_RX, 6_000, 60, 3_000)],
                truncated: false,
            },
            &identities,
            4_000,
        );
        assert_eq!(disappeared.coverage_delta, TrafficCounters::default());
        assert!(disappeared
            .coverage_deltas
            .get("02:00:00:00:00:01@lan")
            .is_none());

        let returned = collector.convert(
            EcmMapRead {
                entries: vec![
                    raw(1, 10, DIR_TX, 4_000, 40, 5_000),
                    raw(2, 20, DIR_RX, 6_000, 60, 3_000),
                    raw(1, 11, DIR_TX, 50_000, 500, 5_000),
                ],
                truncated: false,
            },
            &identities,
            5_000,
        );
        assert_eq!(
            returned.coverage_delta,
            TrafficCounters {
                tx_bytes: 51_000,
                rx_bytes: 0,
                tx_packets: 510,
                rx_packets: 0,
            }
        );
        assert_eq!(
            returned.coverage_deltas.get("02:00:00:00:00:01@lan"),
            Some(&returned.coverage_delta)
        );
    }

    #[test]
    fn identity_zone_change_rebaselines_the_aggregated_mac_counter() {
        let first_identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![raw(0, 0, DIR_TX, 1_000, 10, 1_000)],
                truncated: false,
            },
            &first_identities,
            1_000,
        );

        let mut moved_identities = IdentityTable::new(4);
        moved_identities
            .observe(IdentityObservation {
                mac: "02:00:00:00:00:01",
                zone: Some("guest"),
                interface: "br-guest",
                ip: Some("198.51.100.2"),
                hostname: Some("client"),
                last_seen: 2,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
        let moved = collector.convert(
            EcmMapRead {
                entries: vec![raw(0, 0, DIR_TX, 3_000, 30, 3_000)],
                truncated: false,
            },
            &moved_identities,
            3_000,
        );
        assert_eq!(moved.clients[0].identity_key, "02:00:00:00:00:01@guest");
        assert_eq!(moved.clients[0].tx_bps, 0);
        assert!(!moved.coverage_ready);
        assert_eq!(moved.coverage_start_ms, None);
        assert_eq!(moved.coverage_delta, TrafficCounters::default());

        let recovered = collector.convert(
            EcmMapRead {
                entries: vec![raw(0, 0, DIR_TX, 4_000, 40, 4_000)],
                truncated: false,
            },
            &moved_identities,
            4_000,
        );
        assert!(recovered.coverage_ready);
        assert_eq!(recovered.coverage_delta.tx_bytes, 1_000);
        assert!(recovered
            .coverage_deltas
            .contains_key("02:00:00:00:00:01@guest"));
    }

    #[test]
    fn truncated_map_read_requires_a_complete_rewarm_before_publishing_deltas() {
        let identities = identities();
        let mut collector = EcmBpfSnapshotCollector::default();
        collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 1_000, 10, 1_000)],
                truncated: false,
            },
            &identities,
            1_000,
        );
        let lost = collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 2_000, 20, 2_000)],
                truncated: true,
            },
            &identities,
            2_000,
        );
        assert!(lost.truncated);
        assert!(collector.last_complete().is_none());

        let warmup = collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 3_000, 30, 3_000)],
                truncated: false,
            },
            &identities,
            3_000,
        );
        assert_eq!(warmup.coverage_start_ms, None);
        assert_eq!(warmup.coverage_delta, TrafficCounters::default());
        let recovered = collector.convert(
            EcmMapRead {
                entries: vec![raw(1, 10, DIR_TX, 4_000, 40, 4_000)],
                truncated: false,
            },
            &identities,
            4_000,
        );
        assert_eq!(recovered.coverage_start_ms, Some(3_000));
        assert_eq!(recovered.coverage_delta.tx_bytes, 1_000);
        assert_eq!(recovered.coverage_delta.tx_packets, 10);
    }

    #[test]
    fn real_router_btf_copy_resolves_when_available() {
        let base = Path::new("/tmp/lanspeed-vmlinux.btf");
        let module = Path::new("/tmp/lanspeed-ecm.btf");
        if !base.exists() || !module.exists() {
            return;
        }
        let layout = resolve_ecm_layout_from_paths(base, module).unwrap();
        assert_eq!(layout.pointer_size, 8);
        assert_eq!(layout.from_index, 0);
        assert_eq!(layout.to_index, 1);
        assert_eq!(layout.ready, 1);
        assert!(layout.connection_node_offset > layout.connection_generation_offset);
    }
}
