#[cfg(test)]
mod tests {
    use super::*;

    fn observation(kind: AttachmentKind, vlan_id: Option<u16>) -> AttachmentObservation {
        AttachmentObservation {
            key: AttachmentKey {
                mac: [0x02, 1, 2, 3, 4, 5],
                bridge_ifindex: Some(10),
                vlan_id,
            },
            point: super::super::topology::AttachmentPoint {
                kind,
                ifindex: 7,
                ifname: "phy1-ap0".into(),
                bridge_ifindex: Some(10),
                vlan_id,
            },
            source_generation: 1,
            fresh_frame: true,
            provider_complete: true,
            direct_client: kind == AttachmentKind::Wifi,
        }
    }

    #[test]
    fn station_inherits_only_one_proven_fdb_vlan_on_the_same_ap_port() {
        let mut station = observation(AttachmentKind::Wifi, None);
        inherit_unambiguous_fdb_vlan(
            &[observation(AttachmentKind::Ethernet, Some(20))],
            &mut station,
        );
        assert_eq!(station.key.vlan_id, Some(20));
        assert_eq!(station.point.vlan_id, Some(20));

        let mut ambiguous = observation(AttachmentKind::Wifi, None);
        inherit_unambiguous_fdb_vlan(
            &[
                observation(AttachmentKind::Ethernet, Some(20)),
                observation(AttachmentKind::Ethernet, Some(30)),
            ],
            &mut ambiguous,
        );
        assert_eq!(ambiguous.key.vlan_id, None);
        assert_eq!(ambiguous.point.vlan_id, None);
    }

    #[test]
    fn classifier_window_excludes_adjacent_edge_segments_inside_the_skew_margin() {
        let segment = |epoch_id, start_ms, end_ms, bytes| CounterSegment {
            epoch_id,
            start_ms,
            end_ms,
            read_begin_ms: end_ms,
            read_end_ms: end_ms,
            source: RateSource::EdgePort,
            direction: Direction::Tx,
            bytes,
            packets: bytes / 10,
            attachment_generation: 7,
            byte_domain: ByteDomain::L2NoFcs,
            uncertainty_ms: 4,
        };
        let history = VecDeque::from([
            segment(1, 1_000, 2_000, 10),
            segment(2, 2_000, 3_000, 20),
            segment(3, 3_000, 4_000, 30),
            segment(4, 4_000, 5_000, 40),
        ]);

        let observed = aggregate_history(&history, 2_004, 4_004)
            .expect("two complete Edge segments should match the skewed classifier window");
        assert_eq!(observed.bytes, 50);
        assert_eq!(observed.packets, 5);
        assert_eq!(observed.read_end_ms, 4_000);
    }

    #[test]
    fn publication_reclaims_mux_state_for_departed_identities() {
        let mut runtime = AccessEdgeRuntime::new(1);
        for index in 0..1_024 {
            let identity = format!("client-{index}");
            for direction in [Direction::Tx, Direction::Rx] {
                runtime.update_mux(&identity, direction, 1_000, 1, &[], None);
            }
        }
        assert_eq!(runtime.muxes.len(), 2_048);

        runtime.retain_published_identities(&BTreeSet::from(["client-1023".to_owned()]));
        assert_eq!(runtime.muxes.len(), 2);
        assert!(runtime
            .muxes
            .keys()
            .all(|(identity, _)| identity == "client-1023"));
    }

    #[test]
    fn cached_wifi_snapshot_cannot_prove_the_current_topology_after_a_read_failure() {
        let snapshot = StationCounterSnapshot {
            complete: true,
            ..StationCounterSnapshot::default()
        };

        assert!(!wifi_topology_complete(None, false));
        assert!(wifi_topology_complete(Some(&snapshot), true));
        assert!(!wifi_topology_complete(Some(&snapshot), false));
    }

    #[test]
    fn wifi_failure_does_not_demote_wired_attachment_completeness() {
        let mut runtime = AccessEdgeRuntime::new(1);
        runtime.topology_complete = true;
        runtime.bridge_names.insert(10, "br-lan".into());
        runtime.cached_bridges.insert(
            "br-lan".into(),
            CachedBridge {
                observations: Vec::new(),
                source: FdbSource::Rtnetlink,
                complete: true,
            },
        );
        runtime.latest_wifi = Some(StationCounterSnapshot {
            complete: true,
            ..StationCounterSnapshot::default()
        });
        runtime.wifi_fresh = false;
        let ethernet = Attachment {
            key: AttachmentKey {
                mac: [0x02, 1, 2, 3, 4, 5],
                bridge_ifindex: Some(10),
                vlan_id: None,
            },
            point: super::super::topology::AttachmentPoint {
                kind: AttachmentKind::Ethernet,
                ifindex: 7,
                ifname: "lan2".into(),
                bridge_ifindex: Some(10),
                vlan_id: None,
            },
            trust: AttachmentTrust::ObservedExclusive,
            generation: 1,
            source_generation: 0,
            stable_observations: 2,
            ambiguous: false,
        };
        let wifi = Attachment {
            point: super::super::topology::AttachmentPoint {
                kind: AttachmentKind::Wifi,
                ifname: "phy1-ap0".into(),
                ..ethernet.point.clone()
            },
            ..ethernet.clone()
        };
        assert!(runtime.attachment_topology_complete(&ethernet));
        assert!(!runtime.attachment_topology_complete(&wifi));
    }

    #[test]
    fn failed_bridge_does_not_demote_attachment_on_an_independent_complete_bridge() {
        let mut runtime = AccessEdgeRuntime::new(1);
        runtime.bridge_names.insert(10, "br-lan".into());
        runtime.bridge_names.insert(20, "br-guest".into());
        runtime.cached_bridges.insert(
            "br-lan".into(),
            CachedBridge {
                observations: Vec::new(),
                source: FdbSource::Rtnetlink,
                complete: true,
            },
        );
        runtime.cached_bridges.insert(
            "br-guest".into(),
            CachedBridge {
                observations: Vec::new(),
                source: FdbSource::Rtnetlink,
                complete: false,
            },
        );
        let attachment = Attachment {
            key: AttachmentKey {
                mac: [0x02, 1, 2, 3, 4, 5],
                bridge_ifindex: Some(10),
                vlan_id: None,
            },
            point: super::super::topology::AttachmentPoint {
                kind: AttachmentKind::Ethernet,
                ifindex: 7,
                ifname: "lan2".into(),
                bridge_ifindex: Some(10),
                vlan_id: None,
            },
            trust: AttachmentTrust::ObservedExclusive,
            generation: 1,
            source_generation: 0,
            stable_observations: 2,
            ambiguous: false,
        };

        assert!(runtime.attachment_topology_complete(&attachment));
        assert!(!runtime.topology_complete);
    }

    #[test]
    fn counter_reset_clears_edge_history_before_the_next_delta() {
        let mut runtime = AccessEdgeRuntime::new(1);
        let attachment = Attachment {
            key: AttachmentKey {
                mac: [0x02, 1, 2, 3, 4, 5],
                bridge_ifindex: Some(10),
                vlan_id: None,
            },
            point: super::super::topology::AttachmentPoint {
                kind: AttachmentKind::Ethernet,
                ifindex: 7,
                ifname: "lan2".into(),
                bridge_ifindex: Some(10),
                vlan_id: None,
            },
            trust: AttachmentTrust::ObservedExclusive,
            generation: 1,
            source_generation: 0,
            stable_observations: 2,
            ambiguous: false,
        };
        let counters = |rx_bytes| LinkCounters {
            rx_bytes,
            tx_bytes: 0,
            rx_packets: rx_bytes / 10,
            tx_packets: 0,
        };
        assert!(runtime
            .update_direction(
                &attachment,
                Direction::Tx,
                counters(100),
                (990, 1_000, 1_000),
                RateSource::EdgePort,
                ByteDomain::L2NoFcs,
                Coverage::Partial,
                TrafficScope::AllFrames,
            )
            .segment
            .is_none());
        assert!(runtime
            .update_direction(
                &attachment,
                Direction::Tx,
                counters(200),
                (1_990, 2_000, 2_000),
                RateSource::EdgePort,
                ByteDomain::L2NoFcs,
                Coverage::Partial,
                TrafficScope::AllFrames,
            )
            .segment
            .is_some());
        assert_eq!(runtime.histories.len(), 1);
        assert!(runtime
            .update_direction(
                &attachment,
                Direction::Tx,
                counters(50),
                (2_990, 3_000, 3_000),
                RateSource::EdgePort,
                ByteDomain::L2NoFcs,
                Coverage::Partial,
                TrafficScope::AllFrames,
            )
            .failure
            .is_some());
        assert!(runtime.histories.is_empty());
    }

    #[test]
    fn bridge_inventory_changes_force_an_immediate_fdb_refresh() {
        let cached = BTreeMap::from([("br-lan".to_owned(), ())]);
        assert!(!bridge_inventory_changed(
            &cached,
            &BTreeSet::from(["br-lan".to_owned()])
        ));
        assert!(bridge_inventory_changed(
            &cached,
            &BTreeSet::from(["br-guest".to_owned()])
        ));
        assert!(bridge_inventory_changed(
            &cached,
            &BTreeSet::from(["br-lan".to_owned(), "br-guest".to_owned()])
        ));
    }

    #[test]
    fn disabled_mode_reset_drops_rate_history_and_forces_a_fresh_topology() {
        let mut runtime = AccessEdgeRuntime::new(1);
        runtime.next_fdb_sync_ms = 99_000;
        runtime.initial_syncs = 2;
        runtime.topology_complete = true;
        runtime.latest.sample_ms = 42_000;
        runtime.histories.insert(
            (
                AttachmentKey {
                    mac: [0x02, 1, 2, 3, 4, 5],
                    bridge_ifindex: Some(10),
                    vlan_id: None,
                },
                Direction::Tx,
            ),
            VecDeque::new(),
        );
        runtime.reset_for_disabled_mode();

        assert!(runtime.rates.is_empty());
        assert!(runtime.histories.is_empty());
        assert!(runtime.muxes.is_empty());
        assert!(runtime.classification.is_empty());
        assert_eq!(runtime.topology.active().count(), 0);
        assert!(runtime.cached_bridges.is_empty());
        assert!(runtime.bridge_names.is_empty());
        assert_eq!(runtime.latest.sample_ms, 0);
        assert!(!runtime.topology_complete);
        assert!(!runtime.wifi_fresh);
        assert_eq!(runtime.next_fdb_sync_ms, 0);
        assert_eq!(runtime.initial_syncs, 0);
    }
}
