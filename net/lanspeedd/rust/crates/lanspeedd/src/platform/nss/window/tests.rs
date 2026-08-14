#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::nss::ecm_node::{NodeCounters, ParseStats};

    fn traffic(tx_bytes: u64, rx_bytes: u64, tx_packets: u64, rx_packets: u64) -> TrafficCounters {
        TrafficCounters {
            tx_bytes,
            rx_bytes,
            tx_packets,
            rx_packets,
        }
    }

    fn nodes(ms: u64, counters: TrafficCounters) -> NodeSnapshot {
        NodeSnapshot {
            sample_ms: ms,
            nodes: vec![NodeCounters {
                identity_key: "02:00:00:00:20:11@lan".into(),
                generation: 7,
                counters,
            }],
            stats: ParseStats::default(),
        }
    }

    fn two_nodes(ms: u64, first: TrafficCounters, second: TrafficCounters) -> NodeSnapshot {
        NodeSnapshot {
            sample_ms: ms,
            nodes: vec![
                NodeCounters {
                    identity_key: "02:00:00:00:20:11@lan".into(),
                    generation: 7,
                    counters: first,
                },
                NodeCounters {
                    identity_key: "02:00:00:00:20:12@lan".into(),
                    generation: 8,
                    counters: second,
                },
            ],
            stats: ParseStats::default(),
        }
    }

    fn lan(ms: u64, counters: TrafficCounters) -> LanClock {
        LanClock {
            interface: "lan2".into(),
            sample_ms: ms,
            counters,
        }
    }

    fn interface_counters(
        rx_bytes: u64,
        tx_bytes: u64,
    ) -> BTreeMap<String, RateWindowInterfaceCounter> {
        BTreeMap::from([(
            "br-lan".into(),
            RateWindowInterfaceCounter { rx_bytes, tx_bytes },
        )])
    }

    #[test]
    fn ecm_bpf_low_rate_warms_for_six_seconds_then_rolls_every_two() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let delta = traffic(10_000, 20_000, 10, 20);
        let mut book = EcmBpfRateWindowBook::default();
        assert_eq!(
            book.update(
                &BTreeMap::new(),
                &BTreeMap::new(),
                &lan(0, TrafficCounters::default()),
                &interface_counters(0, 0),
            ),
            None
        );

        for step in 1u64..3 {
            let clients = BTreeMap::from([(identity.clone(), delta)]);
            let output = book.update(
                &clients,
                &BTreeMap::new(),
                &lan(
                    step * 2_000,
                    traffic(22_000 * step, 12_000 * step, 22 * step, 12 * step),
                ),
                &interface_counters(12_048 * step, 22_088 * step),
            );
            assert_eq!(output, None);
        }

        let published = book
            .update(
                &BTreeMap::from([(identity.clone(), delta)]),
                &BTreeMap::new(),
                &lan(6_000, traffic(66_000, 36_000, 66, 36)),
                &interface_counters(36_144, 66_264),
            )
            .expect("six-second low-rate batch");
        assert!(published.fresh);
        assert_eq!(published.window_ms(), 6_000);
        assert_eq!(published.end_ms, 6_000);
        assert_eq!(published.clients[&identity].tx_bps, rate(30_120, 6_000));
        assert_eq!(published.clients[&identity].rx_bps, rate(60_240, 6_000));
        assert_eq!(published.interfaces["br-lan"].rx_bps, rate(36_144, 6_000));
        assert!(!published.fallback_event_gap_filled);
        assert!(!published.fallback_lan_reconciled);

        let held = book.held_at(7_000).expect("previous complete batch");
        assert!(!held.fresh);
        assert_eq!(held.end_ms, 6_000);
        assert_eq!(held.held_age_ms, Some(1_000));
        assert_eq!(held.clients, published.clients);
        assert_eq!(held.interfaces, published.interfaces);

        let rolled = book
            .update(
                &BTreeMap::from([(identity, delta)]),
                &BTreeMap::new(),
                &lan(8_000, traffic(88_000, 48_000, 88, 48)),
                &interface_counters(48_192, 88_352),
            )
            .expect("two-second rolling batch");
        assert!(rolled.fresh);
        assert_eq!(rolled.start_ms, 0);
        assert_eq!(rolled.end_ms, 8_000);
        assert_eq!(rolled.window_ms(), 8_000);
        assert_eq!(rolled.clients, published.clients);
        assert_eq!(rolled.interfaces, published.interfaces);
    }

    #[test]
    fn ecm_bpf_low_rate_rolling_window_weights_bursts_and_trims_to_eighteen_seconds() {
        let segment = |start_ms, end_ms, tx_bps, rx_bps| EcmBpfRateBatch {
            start_ms,
            end_ms,
            clients: BTreeMap::from([("client".into(), RateWindowValue { tx_bps, rx_bps })]),
            interfaces: BTreeMap::from([(
                "br-lan".into(),
                RateWindowValue {
                    rx_bps: tx_bps,
                    tx_bps: rx_bps,
                },
            )]),
            raw_aligned: true,
            fallback_event_gap_filled: false,
            previous_direction_gap_filled: false,
            previous_high_direction_gap_filled: false,
            fallback_lan_reconciled: false,
            low_rate: true,
            fresh: true,
            held_age_ms: None,
        };
        let mut book = EcmBpfRateWindowBook::default();
        let first = book.publish_rate_segment(segment(0, 6_000, 15_000, 10_000), true);
        assert_eq!(first.window_ms(), 6_000);
        let second = book.publish_rate_segment(segment(6_000, 8_000, 31_000, 20_000), true);
        assert_eq!(second.window_ms(), 8_000);
        assert_eq!(
            second.clients["client"].tx_bps,
            (15_000 * 6_000 + 31_000 * 2_000) / 8_000
        );

        for (start_ms, end_ms, tx_bps) in [
            (8_000, 10_000, 1_000),
            (10_000, 12_000, 2_000),
            (12_000, 14_000, 3_000),
            (14_000, 16_000, 4_000),
            (16_000, 18_000, 5_000),
            (18_000, 20_000, 6_000),
        ] {
            book.publish_rate_segment(segment(start_ms, end_ms, tx_bps, tx_bps), true);
        }
        let trimmed = book.published.as_ref().expect("rolling publication");
        assert_eq!(trimmed.start_ms, 2_000);
        assert_eq!(trimmed.end_ms, 20_000);
        assert_eq!(trimmed.window_ms(), ECM_BPF_LOW_RATE_ROLLING_WINDOW_MS);
    }

    #[test]
    fn ecm_bpf_burst_waits_for_the_lan_counter_then_publishes_once() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        let pending = book.update(
            &BTreeMap::from([(identity.clone(), traffic(200_000, 0, 200, 0))]),
            &BTreeMap::new(),
            &lan(2_000, traffic(0, 100_000, 0, 100)),
            &interface_counters(100_400, 0),
        );
        assert_eq!(pending, None);

        let still_warming = book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(4_000, traffic(0, 250_000, 0, 250)),
            &interface_counters(251_000, 0),
        );
        assert_eq!(still_warming, None);

        let aligned = book
            .update(
                &BTreeMap::new(),
                &BTreeMap::new(),
                &lan(6_000, traffic(0, 250_000, 0, 250)),
                &interface_counters(251_000, 0),
            )
            .expect("paced low-rate burst window");
        assert!(aligned.low_rate);
        assert_eq!(aligned.window_ms(), 6_000);
        assert_eq!(aligned.clients[&identity].tx_bps, rate(200_800, 6_000));
        assert!(aligned.clients[&identity].tx_bps < aligned.interfaces["br-lan"].rx_bps);
        assert!(aligned.raw_aligned);
        assert!(!aligned.fallback_event_gap_filled);
        assert!(!aligned.fallback_lan_reconciled);
    }

    #[test]
    fn ecm_bpf_low_rate_prefers_shared_raw_and_reconciles_to_lan() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback = |tx_bps, rx_bps| {
            BTreeMap::from([(identity.clone(), RateWindowValue { tx_bps, rx_bps })])
        };
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        for step in 1u64..3 {
            let output = book.update(
                &BTreeMap::from([(identity.clone(), traffic(5_000, 10_000, 5, 10))]),
                &fallback(1_000_000, 2_000_000),
                &lan(
                    step * 2_000,
                    traffic(9_000 * step, 6_000 * step, 9 * step, 6 * step),
                ),
                &interface_counters(6_024 * step, 9_036 * step),
            );
            assert_eq!(output, None);
        }

        let published = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(5_000, 10_000, 5, 10))]),
                &fallback(1_000_000, 2_000_000),
                &lan(6_000, traffic(27_000, 18_000, 27, 18)),
                &interface_counters(18_072, 27_108),
            )
            .expect("raw-preferred fallback batch");
        assert!(published.fresh);
        assert!(!published.raw_aligned);
        assert_eq!(published.window_ms(), 6_000);
        assert_eq!(published.clients[&identity].tx_bps, rate(15_060, 6_000));
        assert_eq!(published.clients[&identity].rx_bps, rate(27_108, 6_000));
        assert_eq!(published.interfaces["br-lan"].rx_bps, rate(18_072, 6_000));
        assert!(!published.fallback_event_gap_filled);
        assert!(published.fallback_lan_reconciled);
    }

    #[test]
    fn ecm_bpf_low_rate_uses_event_rate_only_for_a_missing_raw_direction() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 1_000_000,
                rx_bps: 12_000,
            },
        )]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        for step in 1u64..=3 {
            let output = book.update(
                &BTreeMap::from([(identity.clone(), traffic(5_000, 0, 5, 0))]),
                &fallback,
                &lan(
                    step * 2_000,
                    traffic(3_000 * step, 6_000 * step, 3 * step, 4 * step),
                ),
                &interface_counters(6_016 * step, 3_012 * step),
            );
            if step < 3 {
                assert_eq!(output, None);
                continue;
            }
            let published = output.expect("event gap-fill batch");
            assert_eq!(published.clients[&identity].tx_bps, rate(15_060, 6_000));
            assert_eq!(published.clients[&identity].rx_bps, 12_000);
            assert!(published.fallback_event_gap_filled);
            assert!(!published.fallback_lan_reconciled);
        }
    }

    #[test]
    fn ecm_bpf_aligned_high_rate_repairs_a_missed_nss_sync_round() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback =
            |tx_bps| BTreeMap::from([(identity.clone(), RateWindowValue { tx_bps, rx_bps: 0 })]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        let steady = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(12_500_000, 0, 10_000, 0))]),
                &fallback(46_000_000),
                &lan(2_000, traffic(0, 13_000_000, 0, 11_000)),
                &interface_counters(13_000_000, 0),
            )
            .expect("initial aligned high-rate batch");
        assert!(steady.raw_aligned);
        assert!(!steady.fallback_event_gap_filled);
        assert_eq!(steady.clients[&identity].tx_bps, 50_160_000);

        let repaired = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(1_000, 0, 1, 0))]),
                &fallback(50_000_000),
                &lan(4_000, traffic(0, 26_000_000, 0, 22_000)),
                &interface_counters(26_000_000, 0),
            )
            .expect("event-clock repair for a missed NSS sync round");

        assert!(repaired.raw_aligned);
        assert!(repaired.fallback_event_gap_filled);
        assert!(!repaired.fallback_lan_reconciled);
        assert_eq!(repaired.window_ms(), 2_000);
        assert_eq!(repaired.clients[&identity].tx_bps, 50_000_000);
        assert_eq!(repaired.interfaces["br-lan"].rx_bps, 52_000_000);
    }

    #[test]
    fn ecm_bpf_high_to_low_confirmation_rolls_real_segments_before_commit() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        let high = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(12_500_000, 0, 10_000, 0))]),
                &BTreeMap::from([(
                    identity.clone(),
                    RateWindowValue {
                        tx_bps: 50_000_000,
                        rx_bps: 0,
                    },
                )]),
                &lan(2_000, traffic(0, 13_000_000, 0, 11_000)),
                &interface_counters(13_000_000, 0),
            )
            .expect("initial high-rate batch");
        assert!(!high.low_rate);

        for (sample_ms, lan_bytes, lan_packets) in
            [(4_000, 13_060_000, 11_050), (6_000, 13_120_000, 11_100)]
        {
            let current = book
                .update(
                    &BTreeMap::from([(identity.clone(), traffic(50_000, 0, 50, 0))]),
                    &BTreeMap::new(),
                    &lan(sample_ms, traffic(0, lan_bytes, 0, lan_packets)),
                    &interface_counters(lan_bytes, 0),
                )
                .expect("current low-rate confirmation segment");
            assert!(current.fresh);
            assert!(current.low_rate);
            assert_eq!(current.end_ms, sample_ms);
        }

        let delayed_sync = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(10_000, 0, 10, 0))]),
                &BTreeMap::new(),
                &lan(8_000, traffic(0, 13_180_000, 0, 11_150)),
                &interface_counters(13_180_000, 0),
            )
            .expect("rolling transition batch");

        let steady_bps = rate(50_200, 2_000);
        let delayed_bps = rate(10_040, 2_000);
        assert!(delayed_sync.fresh);
        assert!(delayed_sync.low_rate);
        assert_eq!(delayed_sync.end_ms, 8_000);
        assert_eq!(delayed_sync.window_ms(), 6_000);
        assert_eq!(
            delayed_sync.clients[&identity].tx_bps,
            (steady_bps * 2 + delayed_bps) / 3
        );
        assert!(delayed_sync.clients[&identity].tx_bps > delayed_bps);
    }

    #[test]
    fn ecm_bpf_mixed_high_low_window_repairs_one_adjacent_low_direction_gap() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        let complete = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(50_000, 5_000_000, 50, 3_500))]),
                &BTreeMap::new(),
                &lan(2_000, traffic(5_100_000, 60_000, 3_600, 60)),
                &interface_counters(60_000, 5_100_000),
            )
            .expect("complete mixed-direction high-rate batch");
        assert!(!complete.low_rate);
        assert!(!complete.previous_direction_gap_filled);

        let repaired = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(2_000, 5_000_000, 2, 3_500))]),
                &BTreeMap::new(),
                &lan(4_000, traffic(10_200_000, 120_000, 7_200, 120)),
                &interface_counters(120_000, 10_200_000),
            )
            .expect("previous complete low direction repair");
        assert!(repaired.fresh);
        assert!(!repaired.low_rate);
        assert!(repaired.previous_direction_gap_filled);
        assert!(!repaired.fallback_event_gap_filled);
        assert_eq!(
            repaired.clients[&identity].tx_bps,
            complete.clients[&identity].tx_bps
        );
        assert!(repaired.clients[&identity].rx_bps >= ECM_BPF_EVENT_HIGH_RATE_BPS);

        let not_chained = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(2_000, 5_000_000, 2, 3_500))]),
                &BTreeMap::new(),
                &lan(6_000, traffic(15_300_000, 180_000, 10_800, 180)),
                &interface_counters(180_000, 15_300_000),
            )
            .expect("current raw direction after one bounded repair");
        assert!(!not_chained.previous_direction_gap_filled);
        assert!(not_chained.clients[&identity].tx_bps < repaired.clients[&identity].tx_bps);
    }

    #[test]
    fn high_rate_gap_guard_tolerates_poll_edge_skew_but_rejects_major_loss() {
        assert!(!high_rate_raw_gap(7_500_000, 10_000_000));
        assert!(high_rate_raw_gap(7_499_999, 10_000_000));
        assert!(!high_rate_raw_gap(0, ECM_BPF_EVENT_HIGH_RATE_BPS - 1));
    }

    #[test]
    fn ecm_bpf_missing_current_event_repairs_only_the_current_high_direction() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback =
            |tx_bps| BTreeMap::from([(identity.clone(), RateWindowValue { tx_bps, rx_bps: 0 })]);
        let client_interfaces = BTreeMap::from([(identity.clone(), "br-lan".to_owned())]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        let steady = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(12_500_000, 0, 10_000, 0))]),
                &fallback(50_000_000),
                &lan(2_000, traffic(0, 13_000_000, 0, 11_000)),
                &interface_counters(13_000_000, 0),
            )
            .expect("initial complete batch");
        assert!(steady.fresh);

        let repaired = book
            .update_with_client_interfaces(
                &BTreeMap::from([(identity.clone(), traffic(1_000, 0, 1, 0))]),
                &BTreeMap::new(),
                &client_interfaces,
                &lan(4_000, traffic(0, 26_000_000, 0, 22_000)),
                &interface_counters(26_000_000, 0),
            )
            .expect("current high direction repaired from adjacent ownership");
        assert!(repaired.fresh);
        assert_eq!(repaired.held_age_ms, None);
        assert_eq!(repaired.start_ms, 2_000);
        assert_eq!(repaired.end_ms, 4_000);
        assert!(repaired.previous_direction_gap_filled);
        assert!(repaired.previous_high_direction_gap_filled);
        assert!(!repaired.fallback_event_gap_filled);
        assert_eq!(repaired.clients[&identity].tx_bps, 52_000_000);
        assert_eq!(repaired.interfaces["br-lan"].rx_bps, 52_000_000);

        let recovered = book
            .update_with_client_interfaces(
                &BTreeMap::from([(identity.clone(), traffic(12_500_000, 0, 10_000, 0))]),
                &fallback(50_000_000),
                &client_interfaces,
                &lan(6_000, traffic(0, 39_000_000, 0, 33_000)),
                &interface_counters(39_000_000, 0),
            )
            .expect("next current NSS event");
        assert!(recovered.fresh);
        assert_eq!(recovered.start_ms, 4_000);
        assert_eq!(recovered.end_ms, 6_000);
        assert!(!recovered.previous_direction_gap_filled);
        assert!(!recovered.previous_high_direction_gap_filled);
        assert_eq!(recovered.clients[&identity].tx_bps, 50_160_000);
        assert_eq!(recovered.interfaces["br-lan"].rx_bps, 52_000_000);
    }

    #[test]
    fn ecm_bpf_high_direction_repair_keeps_the_current_low_direction() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let client_interfaces = BTreeMap::from([(identity.clone(), "br-lan".to_owned())]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        book.update(
            &BTreeMap::from([(identity.clone(), traffic(50_000, 5_000_000, 50, 3_500))]),
            &BTreeMap::new(),
            &lan(2_000, traffic(5_100_000, 60_000, 3_600, 60)),
            &interface_counters(60_000, 5_100_000),
        )
        .expect("initial complete mixed-direction batch");

        let repaired = book
            .update_with_client_interfaces(
                &BTreeMap::from([(identity.clone(), traffic(55_000, 1_000, 55, 1))]),
                &BTreeMap::new(),
                &client_interfaces,
                &lan(4_000, traffic(10_200_000, 120_000, 7_200, 120)),
                &interface_counters(120_000, 10_200_000),
            )
            .expect("current mixed batch with one repaired high direction");

        assert!(repaired.fresh);
        assert!(repaired.previous_high_direction_gap_filled);
        assert_eq!(repaired.clients[&identity].tx_bps, rate(55_220, 2_000));
        assert_eq!(repaired.clients[&identity].rx_bps, 20_400_000);
        assert_eq!(repaired.interfaces["br-lan"].rx_bps, 240_000);
        assert_eq!(repaired.interfaces["br-lan"].tx_bps, 20_400_000);
    }

    #[test]
    fn ecm_bpf_high_rate_prefers_the_single_event_source_without_summing() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 100_000_000,
                rx_bps: 0,
            },
        )]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        for step in 1u64..=4 {
            let output = book.update(
                &BTreeMap::from([(identity.clone(), traffic(10_000, 0, 10, 0))]),
                &fallback,
                &lan(step * 2_000, traffic(0, 100 * step, 0, step)),
                &interface_counters(104 * step, 0),
            );
            if step < 3 {
                assert_eq!(output, None);
                continue;
            }
            let published = output.expect("high event-rate batch");
            assert!(!published.low_rate);
            assert!(!published.raw_aligned);
            assert_eq!(published.clients[&identity].tx_bps, 100_000_000);
            assert!(published.fallback_event_gap_filled);
            assert!(!published.fallback_lan_reconciled);
            if step == 4 {
                assert_eq!(published.window_ms(), 2_000);
            }
        }
    }

    #[test]
    fn ecm_bpf_high_rate_uses_event_clock_for_a_batched_raw_delta() {
        let identity = "client@lan".to_owned();
        let pending = BTreeMap::from([(identity.clone(), traffic(500_000_000, 0, 0, 0))]);
        let fallback = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 1_000_000_000,
                rx_bps: 0,
            },
        )]);

        let (clients, event_selected, reconciled) = high_rate_window_clients(
            &pending,
            &fallback,
            TrafficCounters::default(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            2_000,
        );

        assert_eq!(rate(500_000_000, 2_000), 2_000_000_000);
        assert_eq!(clients[&identity].tx_bps, 1_000_000_000);
        assert!(event_selected);
        assert!(!reconciled);
    }

    #[test]
    fn ecm_bpf_high_rate_caps_event_overage_to_a_valid_lan_budget() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 140_000_000,
                rx_bps: 0,
            },
        )]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        for step in 1u64..=3 {
            let output = book.update(
                &BTreeMap::from([(identity.clone(), traffic(10_000, 0, 10, 0))]),
                &fallback,
                &lan(step * 2_000, traffic(0, 15_000_000 * step, 0, 0)),
                &interface_counters(15_000_000 * step, 0),
            );
            if step < 3 {
                assert_eq!(output, None);
                continue;
            }
            let published = output.expect("high event-rate batch");
            assert_eq!(published.clients[&identity].tx_bps, 60_000_000);
            assert!(published.fallback_event_gap_filled);
            assert!(published.fallback_lan_reconciled);
        }
    }

    #[test]
    fn ecm_bpf_high_rate_publishes_current_windows_while_confirming_quiet() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 100_000_000,
                rx_bps: 0,
            },
        )]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );
        for step in 1u64..=3 {
            let output = book.update(
                &BTreeMap::from([(identity.clone(), traffic(10_000, 0, 10, 0))]),
                &fallback,
                &lan(step * 2_000, traffic(0, 1_000 * step, 0, 0)),
                &interface_counters(1_000 * step, 0),
            );
            if step < 3 {
                assert_eq!(output, None);
                continue;
            }
            assert_eq!(
                output.expect("initial high batch").clients[&identity].tx_bps,
                100_000_000
            );
        }

        for sample_ms in [8_000, 10_000] {
            let current = book
                .update(
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &lan(sample_ms, traffic(0, 3_000, 0, 0)),
                    &interface_counters(3_000, 0),
                )
                .expect("current quiet-confirmation batch");
            assert!(current.fresh);
            assert_eq!(current.end_ms, sample_ms);
            assert_eq!(current.held_age_ms, None);
            assert_eq!(current.clients.get(&identity), None);
        }

        let held = book.held_at(11_000).expect("most recent emitted batch");
        assert!(!held.fresh);
        assert_eq!(held.end_ms, 10_000);
        assert_eq!(held.held_age_ms, Some(1_000));
        assert_eq!(held.clients.get(&identity), None);

        let recovered = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(10_000, 0, 10, 0))]),
                &fallback,
                &lan(12_000, traffic(0, 4_000, 0, 0)),
                &interface_counters(4_000, 0),
            )
            .expect("recovered high batch");
        assert!(recovered.fresh);
        assert!(!recovered.low_rate);
        assert_eq!(recovered.clients[&identity].tx_bps, 100_000_000);

        for sample_ms in [14_000, 16_000, 18_000, 20_000, 22_000] {
            let current = book
                .update(
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &lan(sample_ms, traffic(0, 4_000, 0, 0)),
                    &interface_counters(4_000, 0),
                )
                .expect("current batch during quiet confirmation");
            assert!(current.fresh);
            assert_eq!(current.end_ms, sample_ms);
            assert_eq!(current.held_age_ms, None);
            assert_eq!(current.clients.get(&identity), None);
        }
        let low = book
            .update(
                &BTreeMap::new(),
                &BTreeMap::new(),
                &lan(24_000, traffic(0, 4_000, 0, 0)),
                &interface_counters(4_000, 0),
            )
            .expect("confirmed low-rate batch");
        assert!(low.fresh);
        assert!(low.low_rate);
        assert_eq!(low.clients.get(&identity), None);

        let continued_low = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(100, 200, 1, 2))]),
                &BTreeMap::new(),
                &lan(26_000, traffic(200, 4_100, 2, 1)),
                &interface_counters(4_104, 208),
            )
            .expect("two-second low-rate batch after the confirmed transition");
        assert!(continued_low.fresh);
        assert!(continued_low.low_rate);
        assert_eq!(continued_low.end_ms, 26_000);
        assert_eq!(continued_low.held_age_ms, None);
        assert!(continued_low.clients[&identity].tx_bps > 0);
        assert!(continued_low.clients[&identity].rx_bps > 0);

        let continued_burst = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(300_000, 0, 100, 0))]),
                &BTreeMap::new(),
                &lan(28_000, traffic(200, 204_100, 2, 1_001)),
                &interface_counters(204_104, 208),
            )
            .expect("sub-megabit burst stays in the rolling low-rate mode");
        assert!(continued_burst.fresh);
        assert!(continued_burst.low_rate);
        assert!(!continued_burst.raw_aligned);
        assert_eq!(continued_burst.end_ms, 28_000);
        assert_eq!(continued_burst.held_age_ms, None);
        assert!(continued_burst.clients[&identity].tx_bps > 0);
    }

    #[test]
    fn ecm_bpf_high_rate_liveness_is_relative_for_midrate_traffic() {
        let batch = |tx_bps, low_rate| EcmBpfRateBatch {
            start_ms: 0,
            end_ms: 2_000,
            clients: BTreeMap::from([("client".into(), RateWindowValue { tx_bps, rx_bps: 0 })]),
            interfaces: BTreeMap::new(),
            raw_aligned: true,
            fallback_event_gap_filled: false,
            previous_direction_gap_filled: false,
            previous_high_direction_gap_filled: false,
            fallback_lan_reconciled: false,
            low_rate,
            fresh: true,
            held_age_ms: None,
        };
        let previous = batch(5_000_000, false);

        assert!(high_rate_candidate_is_live(
            &batch(5_000_000, false),
            &previous
        ));
        assert!(!high_rate_candidate_is_live(
            &batch(10_000, false),
            &previous
        ));
        assert!(!high_rate_candidate_is_live(
            &batch(5_000_000, true),
            &previous
        ));
    }

    #[test]
    fn ecm_bpf_lan_reconciliation_preserves_client_proportions() {
        let mut clients = BTreeMap::from([
            (
                "first".into(),
                RateWindowValue {
                    tx_bps: 100,
                    rx_bps: 10,
                },
            ),
            (
                "second".into(),
                RateWindowValue {
                    tx_bps: 300,
                    rx_bps: 20,
                },
            ),
        ]);
        assert!(reconcile_rate_direction(&mut clients, 200, false));
        assert_eq!(clients["first"].tx_bps, 50);
        assert_eq!(clients["second"].tx_bps, 150);
        assert!(!reconcile_rate_direction(&mut clients, 30, true));
    }

    #[test]
    fn ecm_bpf_high_rate_uses_the_discovered_interface_budget() {
        let identity = "client@lan".to_owned();
        let mut clients = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 1_898_000_000,
                rx_bps: 2_000_000,
            },
        )]);
        let client_interfaces = BTreeMap::from([(identity.clone(), "bridge-dynamic".to_owned())]);
        let interface_rates = BTreeMap::from([(
            "bridge-dynamic".to_owned(),
            RateWindowValue {
                rx_bps: 989_000_000,
                tx_bps: 3_000_000,
            },
        )]);

        assert!(reconcile_high_rate_interfaces(
            &mut clients,
            &client_interfaces,
            &interface_rates,
        ));
        assert_eq!(clients[&identity].tx_bps, 989_000_000);
        assert_eq!(clients[&identity].rx_bps, 2_000_000);
    }

    #[test]
    fn ecm_bpf_event_gap_fill_uses_only_the_remaining_lan_budget() {
        let mut clients = BTreeMap::from([
            (
                "raw".into(),
                RateWindowValue {
                    tx_bps: 80,
                    rx_bps: 0,
                },
            ),
            ("gap".into(), RateWindowValue::default()),
        ]);
        let fallback = BTreeMap::from([(
            "gap".into(),
            RateWindowValue {
                tx_bps: 100,
                rx_bps: 0,
            },
        )]);
        let (filled, limited) = fill_fallback_direction(&mut clients, &fallback, 100, false);
        assert!(filled);
        assert!(limited);
        assert_eq!(clients["raw"].tx_bps, 80);
        assert_eq!(clients["gap"].tx_bps, 20);
    }

    #[test]
    fn first_delta_after_cold_start_publishes_without_a_second_settle_cycle() {
        let mut book = NssWindowBook::default();
        let warmup = book.update(&nodes(0, traffic(0, 0, 0, 0)), lan(0, traffic(0, 0, 0, 0)));
        assert_eq!(warmup.quality, WindowQuality::Warmup);

        let published = book.update(
            &nodes(1_000, traffic(100_000, 200_000, 100, 200)),
            lan(1_000, traffic(200_000, 100_000, 200, 100)),
        );
        assert_eq!(published.quality, WindowQuality::Ok);
        assert_eq!(published.reason, "ecm_node_delta_published");
        assert_eq!(published.window_ms(), 1_000);
        assert_eq!(published.clients[0].tx_bps, (100_000 + 400) * 8);
        assert_eq!(published.coverage.quality, WindowQuality::Ok);
    }

    #[test]
    fn one_node_destroy_batch_outlier_does_not_spike_the_client_rate() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );

        for (sample_ms, bytes) in [(2_000, 2_000), (4_000, 4_000), (6_000, 6_000)] {
            let output = book.update(
                &nodes(sample_ms, traffic(bytes, 0, 0, 0)),
                lan(sample_ms, traffic(0, bytes, 0, 0)),
            );
            assert_eq!(output.clients[0].tx_bps, 8_000);
        }

        let destroy = book.update(
            &nodes(8_000, traffic(10_000, 0, 0, 0)),
            lan(8_000, traffic(0, 10_000, 0, 0)),
        );
        assert_eq!(destroy.clients[0].tx_bps, 8_000);
    }

    #[test]
    fn two_second_node_progress_uses_the_real_counter_window_not_the_last_poll() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        let idle = book.update(
            &nodes(1_000, TrafficCounters::default()),
            lan(1_000, TrafficCounters::default()),
        );
        assert_eq!(idle.quality, WindowQuality::Idle);

        let first = book.update(
            &nodes(2_000, traffic(200_000_000, 100_000_000, 200_000, 100_000)),
            lan(2_000, traffic(100_000_000, 200_000_000, 100_000, 200_000)),
        );
        assert_eq!(first.window_ms(), 2_000);
        assert_eq!(first.clients[0].tx_bps, rate(200_000_000 + 800_000, 2_000));
        assert_eq!(first.clients[0].rx_bps, rate(100_000_000 + 400_000, 2_000));

        let held = book.update(
            &nodes(3_000, traffic(200_000_000, 100_000_000, 200_000, 100_000)),
            lan(3_000, traffic(100_000_000, 200_000_000, 100_000, 200_000)),
        );
        assert_eq!(held.reason, "ecm_node_batch_pending");
        assert_eq!(held.clients[0].tx_bps, first.clients[0].tx_bps);

        let second = book.update(
            &nodes(4_000, traffic(400_000_000, 200_000_000, 400_000, 200_000)),
            lan(4_000, traffic(200_000_000, 400_000_000, 200_000, 400_000)),
        );
        assert_eq!(second.window_ms(), 2_000);
        assert_eq!(second.clients[0].tx_bps, first.clients[0].tx_bps);
        assert_eq!(second.clients[0].rx_bps, first.clients[0].rx_bps);
    }

    #[test]
    fn another_nodes_fresh_batch_does_not_zero_a_client_waiting_for_its_batch() {
        let mut book = NssWindowBook::default();
        book.update(
            &two_nodes(0, TrafficCounters::default(), TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        let first = book.update(
            &two_nodes(
                1_000,
                traffic(100_000_000, 50_000_000, 100_000, 50_000),
                TrafficCounters::default(),
            ),
            lan(1_000, traffic(50_000_000, 100_000_000, 50_000, 100_000)),
        );
        let first_rate = first
            .clients
            .iter()
            .find(|client| client.identity_key == "02:00:00:00:20:11@lan")
            .unwrap()
            .tx_bps;
        assert!(first_rate > 0);

        let second = book.update(
            &two_nodes(
                2_000,
                traffic(100_000_000, 50_000_000, 100_000, 50_000),
                traffic(200_000_000, 100_000_000, 200_000, 100_000),
            ),
            lan(2_000, traffic(150_000_000, 300_000_000, 150_000, 300_000)),
        );
        assert_eq!(second.reason, "ecm_node_delta_published");
        assert_eq!(
            second
                .clients
                .iter()
                .find(|client| client.identity_key == "02:00:00:00:20:11@lan")
                .unwrap()
                .tx_bps,
            first_rate
        );
        assert!(
            second
                .clients
                .iter()
                .find(|client| client.identity_key == "02:00:00:00:20:12@lan")
                .unwrap()
                .tx_bps
                > 0
        );
    }

    #[test]
    fn newly_observed_generation_baselines_once_then_publishes_its_next_delta() {
        let mut book = NssWindowBook::default();
        let empty = NodeSnapshot {
            sample_ms: 0,
            nodes: Vec::new(),
            stats: ParseStats::default(),
        };
        book.update(&empty, lan(0, TrafficCounters::default()));

        let baseline = book.update(
            &nodes(1_000, traffic(900_000, 1_800_000, 900, 1_800)),
            lan(1_000, traffic(10_000, 10_000, 10, 10)),
        );
        assert_eq!(baseline.quality, WindowQuality::Idle);

        let published = book.update(
            &nodes(2_000, traffic(910_000, 1_820_000, 910, 1_820)),
            lan(2_000, traffic(30_000, 20_000, 30, 20)),
        );
        assert_eq!(published.reason, "ecm_node_delta_published");
        assert_eq!(published.clients[0].delta, traffic(10_040, 20_080, 10, 20));
        assert!(published.clients[0].tx_bps > 0);
    }

    #[test]
    fn lan_clock_lag_never_blocks_a_fresh_client_rate() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );

        let output = book.update(
            &nodes(1_000, traffic(1_000_000, 2_000_000, 1_000, 2_000)),
            lan(1_000, traffic(500_000, 250_000, 500, 250)),
        );
        assert_eq!(output.quality, WindowQuality::Ok);
        assert!(output.clients[0].rx_bps > 0);
        assert_eq!(output.coverage.quality, WindowQuality::Pending);
        assert_eq!(output.coverage.reason, "lan_coverage_pending");
    }

    #[test]
    fn continuous_node_progress_cannot_restart_the_coverage_timeout() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        let mut last = None;
        for second in 1..=7 {
            let value = second * 1_000_000;
            last = Some(book.update(
                &nodes(
                    second * 1_000,
                    traffic(value, value, second * 1_000, second * 1_000),
                ),
                lan(second * 1_000, traffic(100_000, 100_000, 100, 100)),
            ));
        }
        let output = last.unwrap();
        assert_eq!(output.quality, WindowQuality::Ok);
        assert_eq!(output.coverage.quality, WindowQuality::CounterSkew);
        assert_eq!(output.coverage.reason, "lan_coverage_timeout");
    }

    #[test]
    fn old_rate_is_held_for_one_ecm_cycle_then_becomes_zero() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        let published = book.update(
            &nodes(1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
            lan(1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        let held = book.update(
            &nodes(2_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
            lan(2_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        assert_eq!(held.quality, WindowQuality::Pending);
        assert_eq!(held.clients, published.clients);
        assert_eq!(held.held_rate_age_ms, Some(1_000));

        let idle = book.update(
            &nodes(3_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
            lan(3_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        assert_eq!(idle.quality, WindowQuality::Idle);
        assert_eq!(idle.clients[0].tx_bps, 0);
        assert_eq!(idle.clients[0].rx_bps, 0);
    }

    #[test]
    fn traffic_after_a_long_idle_uses_only_the_adjacent_poll_interval() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        book.update(
            &nodes(1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
            lan(1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        for second in 2..=119 {
            book.update(
                &nodes(second * 1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
                lan(second * 1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
            );
        }
        let resumed = book.update(
            &nodes(120_000, traffic(2_000_000, 2_000_000, 2_000, 2_000)),
            lan(120_000, traffic(2_000_000, 2_000_000, 2_000, 2_000)),
        );
        assert_eq!(resumed.start_ms, 119_000);
        assert_eq!(resumed.window_ms(), 1_000);
        assert_eq!(resumed.clients[0].tx_bps, (1_000_000 + 4_000) * 8);
    }

    #[test]
    fn a_collection_gap_rebaselines_instead_of_publishing_a_long_average() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        let gap = book.update(
            &nodes(120_000, traffic(100_000_000, 100_000_000, 100_000, 100_000)),
            lan(120_000, traffic(100_000_000, 100_000_000, 100_000, 100_000)),
        );
        assert_eq!(gap.quality, WindowQuality::CounterReset);
        assert_eq!(gap.reason, "ecm_sample_gap");
        assert_eq!(gap.window_ms(), 0);
        assert!(gap.clients.iter().all(|client| client.tx_bps == 0));
    }

    #[test]
    fn partial_client_batches_publish_partial_coverage_without_waiting_for_full_ownership() {
        let snapshot = |sample_ms, first: TrafficCounters, second: TrafficCounters| NodeSnapshot {
            sample_ms,
            nodes: vec![
                NodeCounters {
                    identity_key: "02:00:00:00:20:11@lan".into(),
                    generation: 7,
                    counters: first,
                },
                NodeCounters {
                    identity_key: "02:00:00:00:20:12@lan".into(),
                    generation: 8,
                    counters: second,
                },
            ],
            stats: ParseStats::default(),
        };
        let mut book = NssWindowBook::default();
        book.update(
            &snapshot(0, TrafficCounters::default(), TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );

        let first = book.update(
            &snapshot(
                1_000,
                traffic(100_000, 100_000, 100, 100),
                TrafficCounters::default(),
            ),
            lan(1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        assert!(first.clients.iter().any(|client| client.tx_bps > 0));
        assert_eq!(first.coverage.quality, WindowQuality::Ok);
        assert_eq!(first.coverage.tx_pct, Some(10));
        assert_eq!(first.coverage.rx_pct, Some(10));

        let second = book.update(
            &snapshot(
                2_000,
                traffic(100_000, 100_000, 100, 100),
                traffic(900_000, 900_000, 900, 900),
            ),
            lan(2_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        assert_eq!(second.coverage.quality, WindowQuality::Ok);
        assert_eq!(second.coverage.start_ms, 0);
        assert_eq!(second.coverage.tx_pct, Some(100));
        assert_eq!(second.coverage.rx_pct, Some(100));
    }

    #[test]
    fn packet_aware_low_traffic_reports_a_real_percentage() {
        let mut coverage = NssCoverageBook::default();
        let warmup = coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );
        assert_eq!(warmup.quality, WindowQuality::Warmup);

        let output = coverage.update(
            traffic(10_000, 20_000, 2_500, 5_000),
            &lan(2_000, traffic(20_000, 10_000, 5_000, 2_500)),
        );

        assert_eq!(output.quality, WindowQuality::LowTraffic);
        assert!(output.aligned);
        assert_eq!(
            output.client_normalized,
            traffic(20_000, 40_000, 2_500, 5_000)
        );
        assert_eq!(
            output.client_normalized.tx_bytes,
            output.lan_normalized.rx_bytes
        );
        assert_eq!(
            output.client_normalized.rx_bytes,
            output.lan_normalized.tx_bytes
        );
        assert_eq!(
            output.client_normalized.tx_packets,
            output.lan_normalized.rx_packets
        );
        assert_eq!(
            output.client_normalized.rx_packets,
            output.lan_normalized.tx_packets
        );
        assert_eq!(output.tx_pct, Some(100));
        assert_eq!(output.rx_pct, Some(100));
    }

    #[test]
    fn coverage_waits_for_a_late_lan_batch_then_aligns_the_original_window() {
        let mut coverage = NssCoverageBook::default();
        coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );

        let pending = coverage.update(
            traffic(200_000, 400_000, 200, 400),
            &lan(2_000, traffic(200_000, 100_000, 200, 100)),
        );
        assert_eq!(pending.quality, WindowQuality::Pending);
        assert_eq!(pending.start_ms, 0);

        let aligned = coverage.update(
            TrafficCounters::default(),
            &lan(4_000, traffic(400_000, 200_000, 400, 200)),
        );
        assert_eq!(aligned.quality, WindowQuality::Ok);
        assert_eq!(aligned.start_ms, 0);
        assert_eq!(aligned.end_ms, 4_000);
        assert_eq!(aligned.tx_pct, Some(100));
        assert_eq!(aligned.rx_pct, Some(100));
    }

    #[test]
    fn pending_window_retains_only_the_last_aligned_percentage_for_display() {
        let mut coverage = NssCoverageBook::default();
        coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );

        let published = coverage.update(
            traffic(200_000, 400_000, 200, 400),
            &lan(2_000, traffic(400_000, 200_000, 400, 200)),
        );
        assert_eq!(published.quality, WindowQuality::Ok);
        assert_eq!(published.tx_pct, Some(100));
        assert_eq!(published.rx_pct, Some(100));

        let pending = coverage.update(
            traffic(400_000, 400_000, 400, 400),
            &lan(4_000, traffic(500_000, 300_000, 500, 300)),
        );
        assert_eq!(pending.quality, WindowQuality::Pending);
        assert_eq!(pending.tx_pct, None);
        assert_eq!(pending.rx_pct, None);
        assert_eq!(pending.retained_tx_pct, Some(100));
        assert_eq!(pending.retained_rx_pct, Some(100));

        let aligned = coverage.update(
            TrafficCounters::default(),
            &lan(6_000, traffic(800_000, 600_000, 800, 600)),
        );
        assert_eq!(aligned.quality, WindowQuality::Ok);
        assert_eq!(aligned.tx_pct, Some(100));
        assert_eq!(aligned.rx_pct, Some(100));
        assert_eq!(aligned.retained_tx_pct, None);
        assert_eq!(aligned.retained_rx_pct, None);
    }

    #[test]
    fn pending_window_publishes_the_current_reportable_direction_without_clamping() {
        let mut coverage = NssCoverageBook::default();
        coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );
        coverage.update(
            traffic(200_000, 400_000, 200, 400),
            &lan(2_000, traffic(400_000, 200_000, 400, 200)),
        );

        let pending = coverage.update(
            traffic(50_000, 200_000, 50, 200),
            &lan(4_000, traffic(500_000, 300_000, 500, 300)),
        );

        assert_eq!(pending.quality, WindowQuality::Pending);
        assert_eq!(pending.tx_pct, Some(50));
        assert_eq!(pending.rx_pct, None);
        assert_eq!(pending.retained_tx_pct, Some(100));
        assert_eq!(pending.retained_rx_pct, Some(100));
    }

    #[test]
    fn low_volume_unowned_lan_traffic_remains_visible_as_low_coverage() {
        let mut coverage = NssCoverageBook::default();
        coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );

        let output = coverage.update(
            traffic(10_000, 0, 100, 0),
            &lan(2_000, traffic(0, 20_000, 0, 200)),
        );

        assert_eq!(output.quality, WindowQuality::LowTraffic);
        assert!(output.aligned);
        assert_eq!(output.tx_pct, Some(50));
        assert_eq!(output.rx_pct, None);
    }

    #[test]
    fn packet_fcs_is_exact_and_counter_reset_rewarms() {
        assert_eq!(
            traffic(1_000, 2_000, 3, 5).fcs_normalized(),
            Some(traffic(1_012, 2_020, 3, 5))
        );
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, traffic(1_000, 1_000, 10, 10)),
            lan(0, traffic(1_000, 1_000, 10, 10)),
        );
        let reset = book.update(
            &nodes(1_000, traffic(100, 100, 1, 1)),
            lan(1_000, traffic(100, 100, 1, 1)),
        );
        assert_eq!(reset.quality, WindowQuality::CounterReset);
        assert_eq!(reset.reason, "lan_counter_reset");
    }

    #[test]
    fn physical_boundary_change_rewarms_without_reusing_old_rate() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, traffic(1_000, 1_000, 10, 10)),
            lan(0, traffic(1_000, 1_000, 10, 10)),
        );
        let changed = book.update(
            &nodes(1_000, traffic(2_000, 2_000, 20, 20)),
            LanClock {
                interface: "lan1+lan2".into(),
                sample_ms: 1_000,
                counters: traffic(50_000, 50_000, 500, 500),
            },
        );
        assert_eq!(changed.quality, WindowQuality::CounterReset);
        assert_eq!(changed.reason, "lan_boundary_changed");
        assert!(changed.clients.iter().all(|client| client.tx_bps == 0));
    }

    #[test]
    fn asymmetric_high_traffic_uses_aggregate_byte_and_packet_ownership() {
        let client = traffic(3_763_764, 109_645_207, 39_568, 75_590);
        let lan = traffic(109_940_744, 3_033_545, 75_542, 38_478);
        assert!(fits_lan_clock(client, lan));
        assert!(!directional_coverage_ready(client, lan));
        let client_normalized = client.fcs_normalized().unwrap();
        let lan_normalized = lan.fcs_normalized().unwrap();
        assert!(ownership_ready(client_normalized, lan_normalized));
        assert_eq!(
            percentage(client_normalized.tx_bytes, lan_normalized.rx_bytes),
            None
        );
        assert_eq!(
            percentage(client_normalized.rx_bytes, lan_normalized.tx_bytes),
            Some(99)
        );
    }

    #[test]
    fn aggregate_overlap_waits_until_each_coverage_direction_is_reportable() {
        let mut coverage = NssCoverageBook::default();
        coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );
        let client = traffic(3_763_764, 109_645_207, 39_568, 75_590);
        let pending = coverage.update(
            client,
            &lan(1_000, traffic(109_940_744, 3_033_545, 75_542, 38_478)),
        );
        assert_eq!(pending.quality, WindowQuality::Pending);

        let aligned = coverage.update(
            TrafficCounters::default(),
            &lan(3_000, traffic(109_940_744, 3_763_764, 75_590, 39_568)),
        );
        assert_eq!(aligned.quality, WindowQuality::Ok);
        assert!(aligned.tx_pct.is_some());
        assert!(aligned.rx_pct.is_some());
    }
}
