use super::*;
use crate::config::InternetViewMode;

#[test]
fn fast_rate_notices_wait_for_runtime_collection_ownership_to_return() {
    assert!(!fast_rate_notices_can_drain(false));
    assert!(fast_rate_notices_can_drain(true));
}

#[test]
fn nss_control_path_requires_a_current_nonempty_classifier_epoch() {
    use crate::platform::access_edge::DirectionClassification;
    use crate::platform::nss::control::PathProbeDirectionWindow;

    let direction = DirectionClassification {
        edge_bps: Some(10_000_000),
        nss_bps: Some(9_900_000),
        slow_bps: Some(100_000),
        unclassified_bps: Some(0),
        coverage_pct: Some(100),
    };
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Aligned,
            Some(2_000),
            Some(6_000),
            direction,
            Some(PathProbeDirectionWindow {
                bytes: 100_000,
                bps: 100_000,
            }),
        ),
        (true, true, true, true, true)
    );
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Warmup,
            Some(2_000),
            Some(6_000),
            direction,
            None,
        ),
        (false, false, false, false, false)
    );

    let quiet = DirectionClassification {
        edge_bps: Some(120_000),
        nss_bps: Some(100_000),
        slow_bps: Some(20_000),
        unclassified_bps: Some(0),
        coverage_pct: Some(100),
    };
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Aligned,
            Some(2_000),
            Some(6_000),
            quiet,
            Some(PathProbeDirectionWindow {
                bytes: 80_000,
                bps: 20_000,
            }),
        ),
        (true, true, true, true, true)
    );

    let incomplete = DirectionClassification {
        edge_bps: Some(10_000_000),
        nss_bps: Some(7_000_000),
        slow_bps: Some(1_000_000),
        unclassified_bps: Some(2_000_000),
        coverage_pct: Some(80),
    };
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Aligned,
            Some(2_000),
            Some(6_000),
            incomplete,
            None,
        ),
        (false, false, false, false, false)
    );
}

#[test]
fn nss_control_path_requires_internet_probe_for_mixed_sources() {
    use crate::platform::access_edge::DirectionClassification;
    use crate::platform::nss::control::PathProbeDirectionWindow;

    let direction = DirectionClassification {
        edge_bps: Some(20_000_000),
        nss_bps: Some(18_000_000),
        slow_bps: Some(2_000_000),
        unclassified_bps: Some(0),
        coverage_pct: Some(100),
    };
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Aligned,
            Some(2_000),
            Some(6_000),
            direction,
            Some(PathProbeDirectionWindow {
                bytes: 2_000_000,
                bps: 2_000_000,
            }),
        ),
        (true, true, true, true, true)
    );

    let cpu = DirectionClassification {
        edge_bps: Some(10_000_000),
        nss_bps: Some(5_000_000),
        slow_bps: Some(5_000_000),
        unclassified_bps: Some(0),
        coverage_pct: Some(100),
    };
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Aligned,
            Some(2_000),
            Some(6_000),
            cpu,
            Some(PathProbeDirectionWindow {
                bytes: 4_000_000,
                bps: 5_000_000,
            }),
        ),
        (true, true, true, true, true)
    );

    let pure_cpu = DirectionClassification {
        edge_bps: Some(10_000_000),
        nss_bps: Some(0),
        slow_bps: Some(10_000_000),
        unclassified_bps: Some(0),
        coverage_pct: Some(100),
    };
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Aligned,
            Some(2_000),
            Some(6_000),
            pure_cpu,
            Some(PathProbeDirectionWindow {
                bytes: 7_500_000,
                bps: 10_000_000,
            }),
        ),
        (true, true, true, false, true)
    );
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Warmup,
            Some(2_000),
            None,
            pure_cpu,
            Some(PathProbeDirectionWindow {
                bytes: 2_500_000,
                bps: 10_000_000,
            }),
        ),
        (true, true, true, false, true)
    );

    let rounded_cpu = DirectionClassification {
        edge_bps: Some(100_000_000),
        nss_bps: Some(0),
        slow_bps: Some(99_500_000),
        unclassified_bps: Some(500_000),
        coverage_pct: Some(99),
    };
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Aligned,
            Some(2_000),
            Some(6_000),
            rounded_cpu,
            Some(PathProbeDirectionWindow {
                bytes: 74_625_000,
                bps: 99_500_000,
            }),
        ),
        (true, true, true, false, true)
    );
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Aligned,
            Some(2_000),
            Some(6_000),
            DirectionClassification {
                slow_bps: Some(97_000_000),
                unclassified_bps: Some(3_000_000),
                coverage_pct: Some(97),
                ..rounded_cpu
            },
            Some(PathProbeDirectionWindow {
                bytes: 72_750_000,
                bps: 97_000_000,
            }),
        ),
        (true, true, true, false, true)
    );

    let duplicated_proxy = DirectionClassification {
        edge_bps: Some(100_000_000),
        nss_bps: Some(100_000_000),
        slow_bps: Some(100_000_000),
        unclassified_bps: None,
        coverage_pct: None,
    };
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::CounterSkew,
            Some(2_000),
            Some(6_000),
            duplicated_proxy,
            Some(PathProbeDirectionWindow {
                bytes: 75_000_000,
                bps: 100_000_000,
            }),
        ),
        (true, true, true, false, true)
    );
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::CounterSkew,
            Some(2_000),
            Some(6_000),
            duplicated_proxy,
            Some(PathProbeDirectionWindow {
                bytes: 7_500_000,
                bps: 10_000_000,
            }),
        ),
        (true, true, false, false, false)
    );

    let direct = DirectionClassification {
        edge_bps: Some(20_000_000),
        nss_bps: Some(20_000_000),
        slow_bps: Some(0),
        unclassified_bps: Some(0),
        coverage_pct: Some(100),
    };
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Aligned,
            Some(2_000),
            Some(6_000),
            direct,
            Some(PathProbeDirectionWindow { bytes: 0, bps: 0 }),
        ),
        (true, true, true, true, false)
    );
}

#[test]
fn nss_control_startup_proof_excludes_unclassified_local_edge_traffic() {
    use crate::platform::access_edge::DirectionClassification;
    use crate::platform::nss::control::PathProbeDirectionWindow;

    // The edge also carries 70 Mbps of LAN/NAS/router-local traffic. It
    // must not prevent the independently Internet-only CPU probe and ECM
    // hardware sample from proving the shared edge executor.
    let with_local_traffic = DirectionClassification {
        edge_bps: Some(100_000_000),
        nss_bps: Some(20_000_000),
        slow_bps: Some(10_000_000),
        unclassified_bps: Some(70_000_000),
        coverage_pct: Some(30),
    };
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Warmup,
            Some(2_000),
            None,
            with_local_traffic,
            Some(PathProbeDirectionWindow {
                bytes: 2_500_000,
                bps: 10_000_000,
            }),
        ),
        (true, true, true, true, true)
    );

    // A structural hook with no new Internet bytes is not path proof.
    assert_eq!(
        nss_control_direction_path(
            ClassificationState::Warmup,
            Some(2_000),
            None,
            DirectionClassification {
                nss_bps: Some(0),
                slow_bps: Some(0),
                ..with_local_traffic
            },
            Some(PathProbeDirectionWindow { bytes: 0, bps: 0 }),
        ),
        (true, true, false, false, false)
    );
}

#[test]
fn nss_control_path_proves_wifi_identity_without_cross_domain_subtraction() {
    use crate::platform::access_edge::DirectionClassification;
    use crate::platform::nss::control::PathProbeDirectionWindow;

    let direct = DirectionClassification {
        edge_bps: Some(100_000_000),
        nss_bps: Some(90_000_000),
        slow_bps: Some(10_000_000),
        unclassified_bps: None,
        coverage_pct: None,
    };
    assert_eq!(
        nss_control_direction_path_for_attachment(
            ClassificationState::DomainMismatch,
            Some(2_000),
            Some(6_000),
            direct,
            None,
            true,
        ),
        (true, true, true, true, false)
    );

    let cpu = DirectionClassification {
        edge_bps: Some(100_000_000),
        nss_bps: Some(0),
        slow_bps: Some(100_000_000),
        unclassified_bps: None,
        coverage_pct: None,
    };
    assert_eq!(
        nss_control_direction_path_for_attachment(
            ClassificationState::DomainMismatch,
            Some(2_000),
            Some(6_000),
            cpu,
            Some(PathProbeDirectionWindow {
                bytes: 75_000_000,
                bps: 100_000_000,
            }),
            true,
        ),
        (true, true, true, false, true)
    );
}
use crate::platform::nss::ecm_bpf::EcmBpfClientSample;

#[test]
fn ecm_bpf_ignores_flowtable_warnings_owned_by_other_offload_paths() {
    let original = vec![
        "flowtable_counter_probe_unavailable".to_owned(),
        "flowtable_counter_missing".to_owned(),
        "nss_ecm_bpf_active".to_owned(),
    ];
    let mut ecm_bpf = original.clone();
    retain_collector_warnings(&mut ecm_bpf, RateCollector::NssEcmBpf);
    assert_eq!(ecm_bpf, ["nss_ecm_bpf_active"]);

    let mut bpf = original.clone();
    retain_collector_warnings(&mut bpf, RateCollector::Bpf);
    assert_eq!(bpf, original);
}

#[test]
fn cleanup_failures_are_fatal_and_preserve_both_causes() {
    for context in [
        "candidate cleanup",
        "postcommit old runtime cleanup",
        "BPF switch rollback",
        "multi-interface activation rollback",
    ] {
        let fatal = RefCell::new(None);
        let error = record_fatal_cleanup(context, "primary", "cleanup", &fatal);
        let message = error.to_string();
        assert!(message.contains(context));
        assert!(message.contains("primary"));
        assert!(message.contains("cleanup"));
        assert_eq!(
            fatal.borrow().as_deref(),
            Some(message.trim_start_matches("reload: "))
        );
    }
}

#[test]
fn production_version_requires_package_version_and_release() {
    assert_eq!(version_from(Some("1.0.0"), Some("1")), "1.0.0-r1");
    assert_eq!(version_from(Some("1.0.0"), None), "unconfigured");
    assert_eq!(version_from(None, Some("1")), "unconfigured");
}

#[test]
fn conntrack_generation_evidence_reports_real_cta_id_coverage() {
    let snapshot = CollectedSnapshot {
        clients: Vec::new(),
        sample_ms: 1,
        connection_details: Arc::default(),
        connection_counters: Arc::default(),
        counter_source: conntrack::NETLINK_COUNTER_SOURCE,
        stats: conntrack::CollectStats {
            netlink_read: true,
            entries_seen: 5,
            malformed_lines: 1,
            conntrack_ids_present: 3,
            conntrack_zones_present: 4,
            ..conntrack::CollectStats::default()
        },
    };

    let evidence = conntrack_generation_evidence(&snapshot);
    assert_eq!(
        evidence["counter_generation_key"],
        "ctnetlink_cta_id_with_zone_tuple_fallback"
    );
    assert_eq!(evidence["parsed_entries"], 4);
    assert_eq!(evidence["conntrack_ids_present"], 3);
    assert_eq!(evidence["conntrack_zones_present"], 4);
    assert_eq!(evidence["flow_id_coverage_pct"], 75.0);
}

#[test]
fn periodic_collection_does_not_run_blocking_system_probe() {
    assert!(probe_due(0, 0, ProbeMethod::Status));
    assert!(!probe_due(29_999, 30_000, ProbeMethod::Status));
    assert!(probe_due(30_000, 30_000, ProbeMethod::Status));
    assert!(probe_due(1, u64::MAX, ProbeMethod::Reload));
}

#[test]
fn lan_clock_replaces_a_batched_bridge_with_its_physical_members() {
    let masters = BTreeMap::from([
        ("lan1".into(), "br-lan".into()),
        ("lan2".into(), "br-lan".into()),
        ("wlan0".into(), "br-lan".into()),
    ]);

    let selected = independent_lan_boundaries(&["br-lan".into()], &masters).unwrap();

    assert_eq!(selected, vec!["lan1", "lan2", "wlan0"]);
}

#[test]
fn lan_clock_deduplicates_overlapping_roots_and_sums_disjoint_boundaries() {
    let masters = BTreeMap::from([
        ("lan1".into(), "br-lan".into()),
        ("lan2".into(), "br-lan".into()),
    ]);
    let selected = independent_lan_boundaries(
        &["br-lan".into(), "lan2".into(), "br-guest".into()],
        &masters,
    )
    .unwrap();
    assert_eq!(selected, vec!["br-guest", "lan1", "lan2"]);

    let counters = BTreeMap::from([
        (
            "lan1".into(),
            InterfaceCounters {
                rx_bytes: 100,
                tx_bytes: 200,
                rx_packets: 1,
                tx_packets: 2,
            },
        ),
        (
            "lan2".into(),
            InterfaceCounters {
                rx_bytes: 300,
                tx_bytes: 400,
                rx_packets: 3,
                tx_packets: 4,
            },
        ),
        (
            "br-guest".into(),
            InterfaceCounters {
                rx_bytes: 500,
                tx_bytes: 600,
                rx_packets: 5,
                tx_packets: 6,
            },
        ),
    ]);
    assert_eq!(
        sum_interface_counters(&selected, &counters),
        Some(InterfaceCounters {
            rx_bytes: 900,
            tx_bytes: 1_200,
            rx_packets: 9,
            tx_packets: 12,
        })
    );
}

#[test]
fn interface_display_uses_independent_members_and_fcs() {
    let counters = BTreeMap::from([
        (
            "br-lan".into(),
            InterfaceCounters {
                rx_bytes: 1_000,
                tx_bytes: 2_000,
                rx_packets: 10,
                tx_packets: 20,
            },
        ),
        (
            "phy1-ap0".into(),
            InterfaceCounters {
                rx_bytes: 2_000,
                tx_bytes: 4_000,
                rx_packets: 20,
                tx_packets: 40,
            },
        ),
    ]);

    let boundaries = vec!["phy1-ap0".into()];
    let display =
        interface_display_counters("br-lan", InterfaceRole::Lan, Some(&boundaries), &counters)
            .unwrap();

    assert_eq!(display.rx_bytes, 2_080);
    assert_eq!(display.tx_bytes, 4_160);
}

#[test]
fn effective_collector_controls_only_the_nss_timer_floor() {
    assert_eq!(
        effective_collection_interval_ms(AccessEdgeMode::Off, InternetViewMode::Off, None, 500),
        500
    );
    assert_eq!(
        effective_collection_interval_ms(
            AccessEdgeMode::Off,
            InternetViewMode::Off,
            Some(RateCollector::Bpf),
            500,
        ),
        500
    );
    assert_eq!(
        effective_collection_interval_ms(
            AccessEdgeMode::Off,
            InternetViewMode::Off,
            Some(RateCollector::NssEcmNode),
            500,
        ),
        2_000
    );
    assert_eq!(
        effective_collection_interval_ms(
            AccessEdgeMode::Off,
            InternetViewMode::Off,
            Some(RateCollector::NssEcmBpf),
            1_000,
        ),
        2_000
    );
    assert_eq!(
        effective_collection_interval_ms(
            AccessEdgeMode::Off,
            InternetViewMode::Off,
            Some(RateCollector::NssEcmBpf),
            3_000,
        ),
        3_000
    );
    assert_eq!(
        effective_collection_interval_ms(
            AccessEdgeMode::Shadow,
            InternetViewMode::Off,
            Some(RateCollector::NssEcmBpf),
            3_000,
        ),
        1_000
    );
    assert_eq!(
        effective_collection_interval_ms(
            AccessEdgeMode::Active,
            InternetViewMode::Off,
            Some(RateCollector::Bpf),
            500,
        ),
        1_000
    );
    assert_eq!(
        effective_collection_interval_ms(
            AccessEdgeMode::Off,
            InternetViewMode::Routed,
            Some(RateCollector::NssEcmNode),
            3_000,
        ),
        1_000
    );
}

#[test]
fn active_auto_never_executes_the_legacy_inference_rate_window() {
    assert!(active_access_edge_owns_display_rate(
        AccessEdgeMode::Active,
        RateCollectorMode::Auto
    ));
    assert!(!legacy_nss_rate_window_enabled(
        AccessEdgeMode::Active,
        RateCollectorMode::Auto,
        InternetViewMode::Off
    ));
    assert_eq!(
        published_rate_collector_mode(true, "conntrack_netlink"),
        "access_edge"
    );
    assert_eq!(
        published_rate_collector_mode(false, "nss_ecm_bpf"),
        "nss_ecm_bpf"
    );

    for (edge, rate) in [
        (AccessEdgeMode::Off, RateCollectorMode::Auto),
        (AccessEdgeMode::Shadow, RateCollectorMode::Auto),
        (AccessEdgeMode::Active, RateCollectorMode::Bpf),
        (AccessEdgeMode::Active, RateCollectorMode::NssEcmNode),
    ] {
        assert!(!active_access_edge_owns_display_rate(edge, rate));
        assert!(legacy_nss_rate_window_enabled(
            edge,
            rate,
            InternetViewMode::Off
        ));
    }
    assert!(!active_access_edge_owns_display_rate(
        AccessEdgeMode::Active,
        RateCollectorMode::NssEcmBpf
    ));
    assert!(legacy_nss_rate_window_enabled(
        AccessEdgeMode::Active,
        RateCollectorMode::NssEcmBpf,
        InternetViewMode::Off
    ));
    assert!(!legacy_nss_rate_window_enabled(
        AccessEdgeMode::Off,
        RateCollectorMode::Auto,
        InternetViewMode::Routed
    ));
}

#[test]
fn direction_rate_meta_emits_only_summary_overrides() {
    let direction = PublishedRateDirection {
        bps: 1_000,
        source: ModelRateSource::EdgePort,
        coverage: ModelRateCoverage::Full,
        scope: ModelRateScope::AllFrames,
        byte_domain: Some(ModelByteDomain::L2NoFcs),
        sample_ms: Some(9_000),
        window_ms: Some(900),
        stale: false,
        mux_owner: true,
    };

    let exact = rate_direction_meta(direction, Some(9_000), Some(900), false);
    assert_eq!(exact.sample_ms, None);
    assert_eq!(exact.window_ms, None);
    assert_eq!(exact.stale, None);

    let override_meta = rate_direction_meta(direction, Some(10_000), None, true);
    assert_eq!(override_meta.sample_ms, Some(9_000));
    assert_eq!(override_meta.window_ms, Some(900));
    assert_eq!(override_meta.stale, Some(false));

    assert_eq!(
        compact_rate_sample_ms(Some(9_000), Some(10_000)),
        Some(10_000)
    );
    assert_eq!(compact_rate_sample_ms(Some(9_000), None), None);
    assert_eq!(compact_rate_sample_ms(None, Some(10_000)), None);
}

#[test]
fn active_rate_mux_never_treats_a_classifier_candidate_as_edge_authority() {
    let classifier = RateCandidate {
        source: EdgeRateSource::EcmBpfFallback,
        bps: 8_000,
        coverage: crate::platform::access_edge::Coverage::Degraded,
        scope: EdgeTrafficScope::RoutedObserved,
        byte_domain: EdgeByteDomain::L2WithFcs,
        sample_ms: 2_000,
        window_ms: 1_000,
        cadence_ms: 2_000,
        attachment_generation: 7,
        fresh: true,
    };
    let unavailable = active_rate_direction(RateView::Unavailable, Some(classifier), None);
    assert_eq!(unavailable.source, ModelRateSource::None);
    assert_eq!(unavailable.bps, 0);

    let e_without_edge = active_rate_direction(RateView::EAuthority, None, None);
    assert_eq!(e_without_edge.source, ModelRateSource::None);
}

#[test]
fn active_rate_mux_publishes_only_current_normalized_leased_fast_window() {
    let sample = FastClientSample {
        sample_ms: 10_000,
        window_ms: 1_000,
        read_end_skew_ms: 5,
        fast_n_bps: 1_000,
        fast_s_bps: 500,
        fast_total_bps: 1_500,
        routed_l2_with_fcs_bps: 1_800,
    };
    assert!(fast_client_sample_current(13_500, sample));
    assert!(!fast_client_sample_current(13_501, sample));
    let long_window = FastClientSample {
        window_ms: 2_000,
        ..sample
    };
    assert!(fast_client_sample_current(13_500, long_window));
    assert!(!fast_client_sample_current(13_501, long_window));
    let published = active_rate_direction(RateView::RoutedLeaseSubstitute, None, Some(sample));
    assert_eq!(published.bps, 1_800);
    assert_eq!(published.source, ModelRateSource::FastRoutedLease);
    assert_eq!(published.scope, ModelRateScope::RoutedObserved);
    assert_eq!(published.byte_domain, Some(ModelByteDomain::L2WithFcs));
    assert!(published.mux_owner);
}

#[test]
fn explicit_internet_view_publishes_routed_fast_window_without_a_lease() {
    let sample = FastClientSample {
        sample_ms: 10_000,
        window_ms: 1_000,
        read_end_skew_ms: 5,
        fast_n_bps: 2_000,
        fast_s_bps: 700,
        fast_total_bps: 2_700,
        routed_l2_with_fcs_bps: 3_000,
    };
    let published = active_rate_direction(RateView::RoutedInternet, None, Some(sample));
    assert_eq!(published.bps, 3_000);
    assert_eq!(published.source, ModelRateSource::FastRoutedInternet);
    assert_eq!(published.scope, ModelRateScope::RoutedObserved);
    assert_eq!(published.byte_domain, Some(ModelByteDomain::L2WithFcs));
    assert!(published.mux_owner);
}

#[test]
fn either_invalid_classifier_window_blocks_the_combined_epoch() {
    let valid = Some((1_000, 3_000));
    for invalid in [Some((3_000, 3_000)), Some((4_000, 3_000))] {
        assert_eq!(
            select_classifier_window(valid, invalid),
            ClassifierWindowSelection::Invalid
        );
        assert_eq!(
            select_classifier_window(invalid, valid),
            ClassifierWindowSelection::Invalid
        );
    }

    assert_eq!(
        select_classifier_window(valid, Some((1_020, 3_020))),
        ClassifierWindowSelection::Ready {
            start_ms: 1_000,
            end_ms: 3_000,
            aligned: true,
        }
    );
    assert_eq!(
        select_classifier_window(valid, Some((1_100, 3_100))),
        ClassifierWindowSelection::Ready {
            start_ms: 1_000,
            end_ms: 3_000,
            aligned: false,
        }
    );
}

#[test]
fn classifier_map_loss_only_invalidates_classifier_owners() {
    for owner in [EdgeRateSource::EdgePort, EdgeRateSource::EdgeWifi] {
        assert!(!classifier_map_loss_invalidates_owner(
            Some(owner),
            false,
            false,
            true
        ));
    }
    for owner in [
        EdgeRateSource::EcmBpfFallback,
        EdgeRateSource::EcmNssLowerBound,
        EdgeRateSource::TcBpfLowerBound,
    ] {
        assert!(classifier_map_loss_invalidates_owner(
            Some(owner),
            false,
            false,
            true
        ));
        assert!(!classifier_map_loss_invalidates_owner(
            Some(owner),
            true,
            false,
            true
        ));
        assert!(!classifier_map_loss_invalidates_owner(
            Some(owner),
            false,
            true,
            true
        ));
    }
    assert!(!classifier_map_loss_invalidates_owner(
        None, true, false, true
    ));
    assert!(!classifier_map_loss_invalidates_owner(
        None, false, true, true
    ));
    assert!(classifier_map_loss_invalidates_owner(
        None, false, false, true
    ));
    assert!(!classifier_map_loss_invalidates_owner(
        None, false, false, false
    ));
}

#[test]
fn mac_index_keeps_unique_entries_and_fails_closed_on_duplicates() {
    let values = [11, 22, 33];
    let mut index = MacIndex::default();
    index.insert(mac_lookup_key("AA:BB:CC:DD:EE:01"), &values[0]);
    index.insert(mac_lookup_key("aa:bb:cc:dd:ee:02"), &values[1]);
    assert_eq!(index.unique.get("aa:bb:cc:dd:ee:01"), Some(&&11));

    index.insert(mac_lookup_key("aa:bb:cc:dd:ee:01"), &values[2]);
    assert!(!index.unique.contains_key("aa:bb:cc:dd:ee:01"));
    assert!(index.ambiguous.contains("aa:bb:cc:dd:ee:01"));
    assert_eq!(index.unique.get("aa:bb:cc:dd:ee:02"), Some(&&22));
}

#[test]
fn edge_segment_freshness_rejects_future_and_expired_samples() {
    assert!(edge_segment_fresh(10_000, 9_000, 1_000));
    assert!(!edge_segment_fresh(10_000, 10_001, 1_000));
    assert!(!edge_segment_fresh(10_000, 7_499, 1_000));
    assert!(edge_segment_fresh(10_000, 7_500, 1_000));
}

#[test]
fn ecm_bpf_retained_snapshot_stays_current_between_classifier_reads() {
    let snapshot = coverage_snapshot(2_000, 4_000, &[]);
    let mut runtime = RuntimeHealth {
        now_ms: 5_000,
        ecm_bpf_map_read_ok: true,
        ecm_bpf_last_complete_snapshot_ms: Some(4_000),
        ecm_bpf_freshness_ms: 6_000,
        ..RuntimeHealth::default()
    };

    assert!(ecm_bpf_snapshot_current(Some(&snapshot), &runtime));

    // The map is intentionally not read on this response tick. The last
    // complete snapshot is still within its own cadence-derived window.
    runtime.ecm_bpf_map_read_ok = false;
    assert!(ecm_bpf_snapshot_current(Some(&snapshot), &runtime));

    runtime.now_ms = 10_001;
    assert!(!ecm_bpf_snapshot_current(Some(&snapshot), &runtime));

    let mut truncated = snapshot;
    truncated.truncated = true;
    runtime.now_ms = 5_000;
    assert!(!ecm_bpf_snapshot_current(Some(&truncated), &runtime));
}

#[test]
fn hard_edge_failure_removes_only_edge_candidates_before_fallback() {
    let base = RateCandidate {
        source: EdgeRateSource::EdgePort,
        bps: 8_000,
        coverage: crate::platform::access_edge::Coverage::Partial,
        scope: EdgeTrafficScope::AllFrames,
        byte_domain: EdgeByteDomain::L2NoFcs,
        sample_ms: 2_000,
        window_ms: 1_000,
        cadence_ms: 1_000,
        attachment_generation: 7,
        fresh: true,
    };
    let mut candidates = vec![
        base,
        RateCandidate {
            source: EdgeRateSource::EdgeWifi,
            ..base
        },
        RateCandidate {
            source: EdgeRateSource::EcmBpfFallback,
            ..base
        },
    ];

    remove_failed_edge_candidates(&mut candidates, Some(MuxFailure::CounterReset));

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].source, EdgeRateSource::EcmBpfFallback);
}

#[test]
fn global_evidence_separates_fresh_edge_owner_from_unprovable_frame_scope() {
    use crate::platform::access_edge::{
        AccessEdgeSnapshot, AttachmentKey, AttachmentPoint, Coverage as EdgeCoverage,
        EdgeDirectionObservation, TrafficScope,
    };

    let mac_bytes = [0x02, 1, 2, 3, 4, 5];
    let mac = format_edge_mac(mac_bytes);
    let attachment = EdgeAttachment {
        key: AttachmentKey {
            mac: mac_bytes,
            bridge_ifindex: Some(10),
            vlan_id: None,
        },
        point: AttachmentPoint {
            kind: EdgeAttachmentKind::Ethernet,
            ifindex: 6,
            ifname: "lan2".into(),
            bridge_ifindex: Some(10),
            vlan_id: None,
        },
        trust: EdgeAttachmentTrust::ObservedExclusive,
        generation: 17,
        source_generation: 0,
        stable_observations: 2,
        ambiguous: false,
    };
    let direction = EdgeDirectionObservation {
        segment: None,
        coverage: EdgeCoverage::Full,
        scope: TrafficScope::AllFrames,
        failure: None,
        reason_codes: Vec::new(),
    };
    let snapshot = AccessEdgeSnapshot {
        sample_ms: 2_000,
        clients: vec![EdgeClientObservation {
            attachment: attachment.clone(),
            tx: direction.clone(),
            rx: direction,
        }],
        topology_complete: true,
        fdb_source: Some("rtnetlink_af_bridge"),
        reason_codes: Vec::new(),
    };
    let rate_meta = ClientRateMeta {
        version: 1,
        scope: ModelRateScope::AllFrames,
        tx: RateDirectionMeta {
            source: ModelRateSource::EdgePort,
            coverage: ModelRateCoverage::Full,
            byte_domain: Some(ModelByteDomain::L2NoFcs),
            sample_ms: None,
            window_ms: None,
            stale: None,
        },
        rx: RateDirectionMeta {
            source: ModelRateSource::EdgePort,
            coverage: ModelRateCoverage::Full,
            byte_domain: Some(ModelByteDomain::L2NoFcs),
            sample_ms: None,
            window_ms: None,
            stale: None,
        },
        attachment: Some(model_attachment(&attachment)),
        generation: 17,
        window_ms: Some(1_000),
        sample_ms: Some(2_000),
        stale: false,
        reason_codes: Vec::new(),
        classification: None,
    };
    let client = Client {
        mac: mac.clone(),
        identity_key: format!("{mac}@lan"),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: Vec::new(),
        hostname: None,
        rx_bps: 1,
        tx_bps: 1,
        last_seen: 2_000,
        sample_ms: Some(2_000),
        rx_bytes: None,
        tx_bytes: None,
        collector_mode: "nss_ecm_bpf".into(),
        confidence: Confidence::High,
        warnings: Vec::new(),
        tcp_conns: None,
        udp_conns: None,
        udp_dns_conns: None,
        udp_other_conns: None,
        rate_meta: Some(rate_meta),
        control: None,
    };
    let clients = ClientsResponse {
        clients: vec![client.clone()],
        evidence: None,
        tcp_conns_total: None,
        udp_conns_total: None,
        udp_dns_conns_total: None,
        udp_other_conns_total: None,
        conntrack_entries_seen: None,
        conntrack_entries_matched: None,
        conntrack_parse_errors: None,
        conn_source: None,
        nss_ecm_nodes_seen: None,
        nss_ecm_nodes_matched: None,
        nss_ecm_node_parse_errors: None,
        conn_collector_mode: None,
        conn_semantics: None,
    };

    // Even an inconsistent caller cannot promote Ethernet all-frame
    // evidence to Full by supplying forged per-direction coverage.
    let forged_full = access_edge_global_evidence(&snapshot, &clients, AccessEdgeMode::Active);
    assert_eq!(forged_full["coverage"], "partial");
    assert_eq!(forged_full["published_attachments"], 1);
    let forged_reasons = forged_full["reason_codes"]
        .as_array()
        .expect("reason codes are an array");
    assert!(forged_reasons
        .iter()
        .any(|value| value == "ethernet_full_scope_unproven"));
    assert!(!forged_reasons
        .iter()
        .any(|value| value == "fresh_edge_owner_missing"));

    let mut fallback_clients = clients.clone();
    let fallback_meta = fallback_clients.clients[0]
        .rate_meta
        .as_mut()
        .expect("test client has rate metadata");
    fallback_meta.tx.source = ModelRateSource::EcmBpfFallback;
    fallback_meta.rx.source = ModelRateSource::EcmBpfFallback;
    let fallback =
        access_edge_global_evidence(&snapshot, &fallback_clients, AccessEdgeMode::Active);
    let fallback_reasons = fallback["reason_codes"]
        .as_array()
        .expect("reason codes are an array");
    assert!(fallback_reasons
        .iter()
        .any(|value| value == "fresh_edge_owner_missing"));
    assert!(!fallback_reasons
        .iter()
        .any(|value| value == "ethernet_full_scope_unproven"));

    let mut wifi_snapshot = snapshot;
    wifi_snapshot.clients[0].attachment.point.kind = EdgeAttachmentKind::Wifi;
    wifi_snapshot.clients[0].attachment.point.ifname = "phy1-ap0".into();
    wifi_snapshot.clients[0].attachment.trust = EdgeAttachmentTrust::AssociatedStation;
    let mut wifi_clients = clients;
    let wifi_meta = wifi_clients.clients[0]
        .rate_meta
        .as_mut()
        .expect("test client has rate metadata");
    wifi_meta.tx.source = ModelRateSource::EdgeWifi;
    wifi_meta.rx.source = ModelRateSource::EdgeWifi;
    wifi_meta.scope = ModelRateScope::Unicast;
    wifi_meta.attachment = Some(model_attachment(&wifi_snapshot.clients[0].attachment));

    let wifi = access_edge_global_evidence(&wifi_snapshot, &wifi_clients, AccessEdgeMode::Active);
    assert_eq!(wifi["coverage"], "partial");
    assert!(wifi["reason_codes"].as_array().is_some_and(|values| values
        .iter()
        .any(|value| value == "wifi_group_traffic_unattributed")));
}

#[test]
fn classifier_map_evidence_separates_historical_pressure_from_current_loss() {
    let recovered = classifier_map_metrics(10, 100, true, Some(false), true, true);
    assert_eq!(recovered["truncated"], true);
    assert_eq!(recovered["current_truncated"], false);
    assert_eq!(recovered["map_loss"], false);

    let current = classifier_map_metrics(100, 100, true, Some(true), true, true);
    assert_eq!(current["pressure"], true);
    assert_eq!(current["map_loss"], true);

    let failed = classifier_map_metrics(0, 100, false, None, true, false);
    assert_eq!(failed["map_loss"], true);
}

#[test]
fn absent_classifier_delta_cannot_become_a_zero_rate_owner() {
    let ecm = coverage_snapshot(1_000, 3_000, &[]);
    let slow = tc_coverage_snapshot(1_000, 3_000, &[]);
    let runtime = RuntimeHealth {
        now_ms: 3_000,
        ecm_bpf_map_read_ok: true,
        bpf_map_read_ok: true,
        ..RuntimeHealth::default()
    };

    let candidates = classifier_rate_candidates(
        "02:00:00:00:00:01@lan",
        EdgeDirection::Tx,
        0,
        Some(&ecm),
        Some(3_010),
        Some(&slow),
        Some(3_020),
        &runtime,
    );

    assert!(candidates.is_empty());
}

#[test]
fn aligned_classifier_sources_normalize_and_fuse_as_one_fallback() {
    let identity_key = "02:00:00:00:00:01@lan";
    let ecm = coverage_snapshot(
        1_000,
        3_000,
        &[(
            identity_key,
            TrafficCounters {
                tx_bytes: 1_000,
                tx_packets: 10,
                ..TrafficCounters::default()
            },
        )],
    );
    let slow = tc_coverage_snapshot(
        1_000,
        3_000,
        &[(
            identity_key,
            TrafficCounters {
                tx_bytes: 500,
                tx_packets: 5,
                ..TrafficCounters::default()
            },
        )],
    );
    let runtime = RuntimeHealth {
        now_ms: 3_000,
        ecm_bpf_map_read_ok: true,
        bpf_map_read_ok: true,
        ..RuntimeHealth::default()
    };

    let candidates = classifier_rate_candidates(
        identity_key,
        EdgeDirection::Tx,
        7,
        Some(&ecm),
        Some(3_010),
        Some(&slow),
        Some(3_020),
        &runtime,
    );

    assert_eq!(candidates.len(), 3);
    assert!(candidates
        .iter()
        .all(|candidate| candidate.byte_domain == EdgeByteDomain::L2WithFcs));
    let fallback = candidates
        .iter()
        .find(|candidate| candidate.source == EdgeRateSource::EcmBpfFallback)
        .unwrap();
    // ECM: 1000 + 10 * (14 + 4), TC: 500 + 5 * 4.
    assert_eq!(fallback.bps, 6_800);
    assert_eq!(fallback.scope, EdgeTrafficScope::RoutedObserved);
}

#[test]
fn absolute_collection_slots_skip_missed_deadlines_without_catch_up() {
    assert_eq!(
        next_absolute_collection_slot(0, 10_250, 1_000),
        (11_250, 1_000)
    );
    assert_eq!(
        next_absolute_collection_slot(11_250, 11_400, 1_000),
        (12_250, 850)
    );
    assert_eq!(
        next_absolute_collection_slot(12_250, 15_900, 1_000),
        (16_250, 350)
    );
    assert_eq!(
        next_absolute_collection_slot(16_250, 16_000, 1_000),
        (16_250, 250)
    );
}

#[test]
fn classifier_deadline_reads_once_and_skips_expired_slots() {
    let mut deadline = 0;
    assert!(periodic_deadline_due(&mut deadline, 10_000, 2_000));
    assert_eq!(deadline, 12_000);
    assert!(!periodic_deadline_due(&mut deadline, 11_999, 2_000));
    assert!(periodic_deadline_due(&mut deadline, 12_050, 2_000));
    assert_eq!(deadline, 14_000);
    assert!(periodic_deadline_due(&mut deadline, 19_100, 2_000));
    assert_eq!(deadline, 20_000);
    assert!(!periodic_deadline_due(&mut deadline, 19_101, 2_000));
}

#[test]
fn nss_snapshot_freshness_uses_the_effective_two_second_cadence() {
    assert_eq!(nss_snapshot_freshness_ms(500), 6_000);
    assert_eq!(nss_snapshot_freshness_ms(1_000), 6_000);
    assert_eq!(nss_snapshot_freshness_ms(2_000), 6_000);
    assert_eq!(nss_snapshot_freshness_ms(3_000), 9_000);
}

#[test]
fn nss_rate_coverage_publishes_each_current_reportable_direction() {
    let coverage = nss_rate_coverage_values(2_000, 18_000, 34_000, 12_000, 89_000);

    assert_eq!(coverage.quality, "pending");
    assert_eq!(coverage.samples, 1);
    assert_eq!(coverage.window_ms, Some(2_000));
    assert_eq!(coverage.tx_pct, None);
    assert_eq!(coverage.rx_pct, Some(38));
    assert_eq!(coverage.denom_rx_bytes, Some(3_000));
    assert_eq!(coverage.denom_tx_bytes, Some(22_250));
    assert_eq!(coverage.numer_tx_bytes, Some(4_500));
    assert_eq!(coverage.numer_rx_bytes, Some(8_500));
}

#[test]
fn nss_rate_coverage_uses_the_current_interface_window_without_clamping() {
    let coverage =
        nss_rate_coverage_values(2_000, 980_000_000, 970_000_000, 1_000_000_000, 990_000_000);

    assert_eq!(coverage.quality, "ok");
    assert_eq!(coverage.tx_pct, Some(98));
    assert_eq!(coverage.rx_pct, Some(97));

    let idle = nss_rate_coverage_values(2_000, 0, 0, 0, 0);
    assert_eq!(idle.quality, "idle");
    assert_eq!(idle.tx_pct, None);
    assert_eq!(idle.rx_pct, None);
}

#[test]
fn ecm_bpf_high_rate_floor_uses_the_discovered_client_interface() {
    let identity_key = "02:00:00:00:00:01@lan";
    let mut snapshot = coverage_snapshot(1_000, 3_000, &[]);
    snapshot.clients.push(EcmBpfClientSample {
        mac: "02:00:00:00:00:01".into(),
        identity_key: identity_key.into(),
        zone: "lan".into(),
        interface: "bridge-dynamic".into(),
        ips: vec!["192.0.2.1".into()],
        tx_bytes: 0,
        rx_bytes: 0,
        tx_bps: 0,
        rx_bps: 0,
        sample_ms: 3_000,
        last_seen_ms: 3_000,
    });
    let mut clients = ecm_bpf_clients_response(
        Some(&snapshot),
        None,
        false,
        3_000,
        None,
        &IdentityTable::new(4),
        ProbeConfidence::High,
    );
    let mut interfaces = InterfacesResponse {
        interfaces: vec![
            Interface {
                name: "bridge-dynamic".into(),
                role: InterfaceRole::Lan,
                status: InterfaceStatus::Available,
                rx_bytes: Some(100),
                tx_bytes: Some(200),
                rx_bps: Some(0),
                tx_bps: Some(0),
                delta_ms: Some(2_000),
                sample_ms: Some(3_000),
                source: Some("kernel counters".into()),
                coverage: None,
                evidence: None,
            },
            Interface {
                name: "member-dynamic".into(),
                role: InterfaceRole::Observe,
                status: InterfaceStatus::Available,
                rx_bytes: Some(300),
                tx_bytes: Some(400),
                rx_bps: Some(0),
                tx_bps: Some(0),
                delta_ms: Some(2_000),
                sample_ms: Some(3_000),
                source: Some("kernel counters".into()),
                coverage: None,
                evidence: None,
            },
        ],
        monotonic_ms: Some(3_000),
        note: None,
        evidence: None,
    };
    let batch = EcmBpfRateBatch {
        start_ms: 3_000,
        end_ms: 5_000,
        clients: BTreeMap::from([(
            identity_key.into(),
            RateWindowValue {
                tx_bps: 100_000_000,
                rx_bps: 50_000_000,
            },
        )]),
        interfaces: BTreeMap::from([
            (
                "bridge-dynamic".into(),
                RateWindowValue {
                    rx_bps: 10_000_000,
                    tx_bps: 20_000_000,
                },
            ),
            (
                "member-dynamic".into(),
                RateWindowValue {
                    rx_bps: 30_000_000,
                    tx_bps: 40_000_000,
                },
            ),
        ]),
        raw_aligned: false,
        fallback_event_gap_filled: true,
        previous_direction_gap_filled: false,
        previous_high_direction_gap_filled: false,
        fallback_lan_reconciled: false,
        low_rate: false,
        fresh: true,
        held_age_ms: None,
    };

    apply_ecm_bpf_rate_batch(&mut clients, &mut interfaces, &batch);

    assert_eq!(clients.clients[0].tx_bps, 100_000_000);
    assert_eq!(clients.clients[0].rx_bps, 50_000_000);
    assert_eq!(clients.clients[0].sample_ms, Some(5_000));
    let bridge = &interfaces.interfaces[0];
    assert_eq!(bridge.rx_bps, Some(100_000_000));
    assert_eq!(bridge.tx_bps, Some(50_000_000));
    assert!(bridge
        .source
        .as_deref()
        .is_some_and(|source| source.contains("ECM+BPF high-rate client floor")));
    let member = &interfaces.interfaces[1];
    assert_eq!(member.rx_bps, Some(30_000_000));
    assert_eq!(member.tx_bps, Some(40_000_000));
    assert_eq!(interfaces.monotonic_ms, Some(5_000));
}

#[test]
fn ecm_bpf_computes_one_rate_from_aligned_raw_deltas() {
    let ecm = EcmBpfClientSample {
        mac: "02:00:00:00:00:01".into(),
        identity_key: "02:00:00:00:00:01@lan".into(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec!["192.0.2.1".into()],
        tx_bytes: 10_000,
        rx_bytes: 20_000,
        tx_bps: 100,
        rx_bps: 200,
        sample_ms: 2_000,
        last_seen_ms: 1_900,
    };
    let tc = NssTcClientSample {
        mac: ecm.mac.clone(),
        identity_key: ecm.identity_key.clone(),
        zone: ecm.zone.clone(),
        interface: ecm.interface.clone(),
        ips: ecm.ips.clone(),
        tx_bytes: 3_000,
        rx_bytes: 4_000,
        tx_bps: 150,
        rx_bps: 50,
        last_seen_ms: 2_000,
    };
    let tc_only = NssTcClientSample {
        mac: "02:00:00:00:00:02".into(),
        identity_key: "02:00:00:00:00:02@lan".into(),
        tx_bps: 300,
        rx_bps: 400,
        ..tc.clone()
    };

    let mut ecm_snapshot = coverage_snapshot(
        1_000,
        2_000,
        &[(
            &ecm.identity_key,
            TrafficCounters {
                tx_bytes: 10_000,
                rx_bytes: 20_000,
                tx_packets: 100,
                rx_packets: 200,
            },
        )],
    );
    ecm_snapshot.clients.push(ecm);
    let mut tc_snapshot = tc_coverage_snapshot(
        1_000,
        2_000,
        &[
            (
                &tc.identity_key,
                TrafficCounters {
                    tx_bytes: 3_000,
                    rx_bytes: 4_000,
                    tx_packets: 30,
                    rx_packets: 40,
                },
            ),
            (
                &tc_only.identity_key,
                TrafficCounters {
                    tx_bytes: 5_000,
                    rx_bytes: 6_000,
                    tx_packets: 50,
                    rx_packets: 60,
                },
            ),
        ],
    );
    tc_snapshot.clients = vec![tc, tc_only];

    let response = ecm_bpf_clients_response(
        Some(&ecm_snapshot),
        Some(&tc_snapshot),
        true,
        2_000,
        None,
        &IdentityTable::new(4),
        ProbeConfidence::High,
    );

    let merged = &response.clients[0];
    assert_eq!((merged.tx_bps, merged.rx_bps), (108_160, 199_680));
    assert_eq!(
        (merged.tx_bytes, merged.rx_bytes),
        (Some(10_000), Some(20_000))
    );
    assert_eq!(merged.sample_ms, Some(2_000));
    assert!(merged.warnings.is_empty());

    let leading = &response.clients[1];
    assert_eq!((leading.tx_bps, leading.rx_bps), (41_600, 49_920));
    assert!(leading.warnings.is_empty());
}

fn coverage_snapshot(
    start_ms: u64,
    end_ms: u64,
    values: &[(&str, TrafficCounters)],
) -> EcmBpfSnapshot {
    let coverage_deltas = values
        .iter()
        .map(|(identity, counters)| ((*identity).to_owned(), *counters))
        .collect::<BTreeMap<_, _>>();
    let coverage_delta =
        coverage_deltas
            .values()
            .copied()
            .fold(TrafficCounters::default(), |mut total, value| {
                add_traffic_counters(&mut total, value);
                total
            });
    EcmBpfSnapshot {
        coverage_delta,
        coverage_deltas,
        coverage_start_ms: Some(start_ms),
        coverage_end_ms: end_ms,
        coverage_ready: true,
        sample_ms: end_ms,
        ..EcmBpfSnapshot::default()
    }
}

fn tc_coverage_snapshot(
    start_ms: u64,
    end_ms: u64,
    values: &[(&str, TrafficCounters)],
) -> NssTcSnapshot {
    NssTcSnapshot {
        coverage_deltas: values
            .iter()
            .map(|(identity, counters)| ((*identity).to_owned(), *counters))
            .collect(),
        coverage_start_ms: Some(start_ms),
        coverage_end_ms: end_ms,
        coverage_ready: true,
        map_complete: true,
        ..NssTcSnapshot::default()
    }
}

#[test]
fn ecm_bpf_misaligned_windows_choose_one_source_per_direction_without_sum() {
    let identity_key = "02:00:00:00:00:01@lan";
    let ecm_client = EcmBpfClientSample {
        mac: "02:00:00:00:00:01".into(),
        identity_key: identity_key.into(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec!["192.0.2.1".into()],
        tx_bytes: 10_000,
        rx_bytes: 20_000,
        tx_bps: 100,
        rx_bps: 200,
        sample_ms: 3_000,
        last_seen_ms: 2_900,
    };
    let tc_client = NssTcClientSample {
        mac: ecm_client.mac.clone(),
        identity_key: identity_key.into(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec!["192.0.2.1".into()],
        tx_bytes: 3_000,
        rx_bytes: 4_000,
        tx_bps: 150,
        rx_bps: 50,
        last_seen_ms: 5_900,
    };
    let mut ecm = coverage_snapshot(1_000, 3_000, &[(identity_key, TrafficCounters::default())]);
    ecm.clients.push(ecm_client);
    let mut tc = tc_coverage_snapshot(4_000, 6_000, &[(identity_key, TrafficCounters::default())]);
    tc.clients.push(tc_client);

    let response = ecm_bpf_clients_response(
        Some(&ecm),
        Some(&tc),
        true,
        6_000,
        None,
        &IdentityTable::new(4),
        ProbeConfidence::High,
    );

    let client = &response.clients[0];
    assert_eq!((client.tx_bps, client.rx_bps), (150, 200));
    assert_eq!(
        (client.tx_bytes, client.rx_bytes),
        (Some(10_000), Some(20_000))
    );
    assert_eq!(client.sample_ms, Some(6_000));
}

#[test]
fn ecm_bpf_coverage_adds_source_disjoint_hardware_and_slow_path_deltas() {
    let ecm = coverage_snapshot(
        1_000,
        3_000,
        &[(
            "client@lan",
            TrafficCounters {
                tx_bytes: 10_000,
                rx_bytes: 20_000,
                tx_packets: 100,
                rx_packets: 200,
            },
        )],
    );
    let tc = tc_coverage_snapshot(
        1_010,
        3_010,
        &[(
            "client@lan",
            TrafficCounters {
                tx_bytes: 9_000,
                rx_bytes: 22_000,
                tx_packets: 90,
                rx_packets: 220,
            },
        )],
    );

    let merged = merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), true);

    assert_eq!(
        merged.merged,
        TrafficCounters {
            tx_bytes: 19_000,
            rx_bytes: 42_000,
            tx_packets: 190,
            rx_packets: 420,
        }
    );
    assert!(merged.tc_contributed);
}

#[test]
fn ecm_bpf_coverage_includes_tc_only_low_traffic_clients() {
    let ecm = coverage_snapshot(
        1_000,
        3_000,
        &[(
            "routed@lan",
            TrafficCounters {
                tx_bytes: 1_000,
                tx_packets: 10,
                ..TrafficCounters::default()
            },
        )],
    );
    let tc = tc_coverage_snapshot(
        1_000,
        3_000,
        &[
            (
                "routed@lan",
                TrafficCounters {
                    tx_bytes: 900,
                    tx_packets: 9,
                    ..TrafficCounters::default()
                },
            ),
            (
                "slow-path@lan",
                TrafficCounters {
                    rx_bytes: 2_000,
                    rx_packets: 20,
                    ..TrafficCounters::default()
                },
            ),
        ],
    );

    let merged = merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), true);

    assert_eq!(merged.merged.tx_bytes, 1_900);
    assert_eq!(merged.merged.tx_packets, 19);
    assert_eq!(merged.merged.rx_bytes, 2_000);
    assert_eq!(merged.merged.rx_packets, 20);
    assert!(merged.tc_contributed);
}

#[test]
fn ecm_bpf_coverage_rejects_stale_or_misaligned_tc_windows() {
    let ecm = coverage_snapshot(
        2_000,
        4_000,
        &[(
            "client@lan",
            TrafficCounters {
                tx_bytes: 1_000,
                tx_packets: 10,
                ..TrafficCounters::default()
            },
        )],
    );
    let tc = tc_coverage_snapshot(
        1_000,
        3_000,
        &[(
            "client@lan",
            TrafficCounters {
                tx_bytes: 50_000,
                tx_packets: 500,
                ..TrafficCounters::default()
            },
        )],
    );

    for merged in [
        merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), false),
        merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), true),
    ] {
        assert_eq!(merged.merged, ecm.coverage_delta);
        assert_eq!(merged.source, "ecm_nss_hardware_delta");
        assert!(!merged.tc_contributed);
    }
}

#[test]
fn pending_coverage_response_uses_the_last_aligned_percentage_without_a_current_direction() {
    let response = coverage_response(&CoverageWindow {
        quality: WindowQuality::Pending,
        reason: "lan_coverage_pending",
        start_ms: 1_000,
        end_ms: 3_000,
        client_raw: TrafficCounters::default(),
        client_normalized: TrafficCounters::default(),
        lan_raw: TrafficCounters::default(),
        lan_normalized: TrafficCounters::default(),
        tx_pct: None,
        rx_pct: None,
        retained_tx_pct: Some(91),
        retained_rx_pct: Some(97),
        aligned: false,
    });

    assert_eq!(response.quality, "pending");
    assert_eq!(response.samples, 1);
    assert_eq!(response.tx_pct, Some(91));
    assert_eq!(response.rx_pct, Some(97));

    let timed_out = coverage_response(&CoverageWindow {
        quality: WindowQuality::CounterSkew,
        reason: "lan_coverage_timeout",
        start_ms: 3_000,
        end_ms: 9_000,
        client_raw: TrafficCounters::default(),
        client_normalized: TrafficCounters::default(),
        lan_raw: TrafficCounters::default(),
        lan_normalized: TrafficCounters::default(),
        tx_pct: None,
        rx_pct: None,
        retained_tx_pct: Some(91),
        retained_rx_pct: Some(97),
        aligned: false,
    });
    assert_eq!(timed_out.quality, "pending");
    assert_eq!(timed_out.tx_pct, Some(91));
    assert_eq!(timed_out.rx_pct, Some(97));

    let low_traffic_wait = coverage_response(&CoverageWindow {
        quality: WindowQuality::LowTraffic,
        reason: "low_traffic_coverage_rebaseline",
        start_ms: 9_000,
        end_ms: 15_000,
        client_raw: TrafficCounters::default(),
        client_normalized: TrafficCounters::default(),
        lan_raw: TrafficCounters::default(),
        lan_normalized: TrafficCounters::default(),
        tx_pct: None,
        rx_pct: None,
        retained_tx_pct: Some(91),
        retained_rx_pct: Some(97),
        aligned: false,
    });
    assert_eq!(low_traffic_wait.quality, "pending");
    assert_eq!(low_traffic_wait.tx_pct, Some(91));
    assert_eq!(low_traffic_wait.rx_pct, Some(97));
}

#[test]
fn pending_coverage_response_prefers_the_current_reportable_direction() {
    let response = coverage_response(&CoverageWindow {
        quality: WindowQuality::Pending,
        reason: "lan_coverage_pending",
        start_ms: 1_000,
        end_ms: 3_000,
        client_raw: TrafficCounters::default(),
        client_normalized: TrafficCounters::default(),
        lan_raw: TrafficCounters::default(),
        lan_normalized: TrafficCounters::default(),
        tx_pct: Some(73),
        rx_pct: None,
        retained_tx_pct: Some(91),
        retained_rx_pct: Some(97),
        aligned: false,
    });

    assert_eq!(response.quality, "pending");
    assert_eq!(response.samples, 1);
    assert_eq!(response.tx_pct, Some(73));
    assert_eq!(response.rx_pct, None);
}

#[test]
fn nss_bpf_handoff_rewarms_without_republishing_the_old_owner_interval() {
    use crate::platform::nss::ecm_node::{NodeCounters, NodeSnapshot, ParseStats};

    let snapshot = |sample_ms, tx_bytes, rx_bytes| NodeSnapshot {
        sample_ms,
        nodes: vec![NodeCounters {
            identity_key: "02:00:00:00:20:11@lan".into(),
            generation: 7,
            counters: TrafficCounters {
                tx_bytes,
                rx_bytes,
                tx_packets: tx_bytes / 1_000,
                rx_packets: rx_bytes / 1_000,
            },
        }],
        stats: ParseStats::default(),
    };
    let lan = |sample_ms, rx_bytes, tx_bytes| LanClock {
        interface: "br-lan".into(),
        sample_ms,
        counters: TrafficCounters {
            tx_bytes,
            rx_bytes,
            tx_packets: tx_bytes / 1_000,
            rx_packets: rx_bytes / 1_000,
        },
    };
    let mut owner = None;
    let mut nss = NssRuntime::default();

    nss.transition_rate_owner(&mut owner, RateCollector::NssEcmNode);
    assert_eq!(
        nss.node_windows
            .update(&snapshot(1_000, 10_000, 20_000), lan(1_000, 10_000, 20_000))
            .quality,
        WindowQuality::Warmup
    );
    nss.transition_rate_owner(&mut owner, RateCollector::Bpf);

    nss.transition_rate_owner(&mut owner, RateCollector::NssEcmNode);
    let reentry = nss.node_windows.update(
        &snapshot(5_000, 4_010_000, 8_020_000),
        lan(5_000, 4_010_000, 8_020_000),
    );

    assert_eq!(reentry.quality, WindowQuality::Warmup);
    assert!(reentry
        .clients
        .iter()
        .all(|client| client.tx_bps == 0 && client.rx_bps == 0));
    assert_eq!(reentry.coverage.tx_pct, None);
    assert_eq!(reentry.coverage.rx_pct, None);
}
