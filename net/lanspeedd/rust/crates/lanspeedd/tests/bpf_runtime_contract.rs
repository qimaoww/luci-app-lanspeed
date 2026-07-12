use std::{collections::BTreeMap, path::Path};

use lanspeed_common::{LanspeedCounters, LanspeedKey, DIR_RX, DIR_TX};
use lanspeedd::{
    collectors::bpf::{
        runtime::{
            AdapterError, AdapterErrorKind, AttachMode, AyaAdapter, BpfRuntime, HookState,
            LinkDirection, LinkSpec, ObjectFlavor,
        },
        snapshot::{
            BpfSnapshotCollector, ConnectionCounts, ConnectionOverlay, MapRead, RawMapSample,
            SnapshotWarning,
        },
    },
    identity::{IdentityObservation, IdentityTable, ObservationSource},
    rate::RateWarning,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct FakeLink(usize);

#[derive(Default)]
struct FakeAya {
    loads: Vec<ObjectFlavor>,
    fail_load: Option<(ObjectFlavor, AdapterErrorKind)>,
    hooks: BTreeMap<LinkSpec, HookState>,
    attached: Vec<LinkSpec>,
    detached: Vec<LinkSpec>,
    forgotten: Vec<LinkSpec>,
    fail_attach_at: Option<usize>,
    fail_detach: bool,
    fail_inspect: bool,
    events: Vec<String>,
    clsact: Vec<String>,
    map_read: Option<Result<MapRead, AdapterError>>,
    unloaded: bool,
}

impl AyaAdapter for FakeAya {
    type Link = FakeLink;

    fn load_object(&mut self, path: &Path, flavor: ObjectFlavor) -> Result<(), AdapterError> {
        self.loads.push(flavor);
        if path.as_os_str().is_empty() {
            return Err(AdapterError::new(
                AdapterErrorKind::ObjectMissing,
                "empty object path",
            ));
        }
        if self.fail_load == Some((flavor, AdapterErrorKind::ObjectMissing)) {
            return Err(AdapterError::new(
                AdapterErrorKind::ObjectMissing,
                "object missing",
            ));
        }
        if self.fail_load == Some((flavor, AdapterErrorKind::KfuncIncompatible)) {
            return Err(AdapterError::new(
                AdapterErrorKind::KfuncIncompatible,
                "kernel kfunc metadata incompatible",
            ));
        }
        if self.fail_load == Some((flavor, AdapterErrorKind::LoadFailed)) {
            return Err(AdapterError::new(
                AdapterErrorKind::LoadFailed,
                "verifier rejected object",
            ));
        }
        Ok(())
    }

    fn ensure_clsact(&mut self, interface: &str) -> Result<(), AdapterError> {
        self.clsact.push(interface.to_owned());
        Ok(())
    }

    fn inspect_hook(&mut self, spec: &LinkSpec) -> Result<HookState, AdapterError> {
        if self.fail_inspect {
            return Err(AdapterError::new(
                AdapterErrorKind::AttachFailed,
                "injected inspect failure",
            ));
        }
        Ok(self.hooks.get(spec).copied().unwrap_or(HookState::Absent))
    }

    fn attach_netlink(&mut self, spec: &LinkSpec) -> Result<Self::Link, AdapterError> {
        if self.fail_attach_at == Some(self.attached.len()) {
            return Err(AdapterError::new(
                AdapterErrorKind::AttachFailed,
                "injected attach failure",
            ));
        }
        self.attached.push(spec.clone());
        self.events.push(format!("attach:{}", spec.program));
        self.hooks.insert(spec.clone(), HookState::Owned);
        Ok(FakeLink(self.attached.len()))
    }

    fn replace_owned_netlink_atomic(
        &mut self,
        spec: &LinkSpec,
    ) -> Result<Self::Link, AdapterError> {
        self.events.push(format!("replace:{}", spec.program));
        self.attach_netlink(spec)
    }

    fn detach_link(&mut self, spec: &LinkSpec, _link: Self::Link) -> Result<(), AdapterError> {
        self.detached.push(spec.clone());
        self.events.push(format!("detach:{}", spec.program));
        self.hooks.remove(spec);
        if self.fail_detach {
            return Err(AdapterError::new(
                AdapterErrorKind::DetachFailed,
                "injected detach failure",
            ));
        }
        Ok(())
    }

    fn detach_exact(&mut self, spec: &LinkSpec) -> Result<(), AdapterError> {
        self.detached.push(spec.clone());
        self.hooks.remove(spec);
        Ok(())
    }

    fn forget_link(&mut self, spec: &LinkSpec, _link: Self::Link) -> Result<(), AdapterError> {
        self.forgotten.push(spec.clone());
        Ok(())
    }

    fn read_clients(&mut self) -> Result<MapRead, AdapterError> {
        self.map_read.take().unwrap_or_else(|| {
            Ok(MapRead {
                entries: Vec::new(),
                truncated: false,
            })
        })
    }

    fn interface_name(&mut self, ifindex: u32) -> Option<String> {
        (ifindex == 7).then(|| "br-lan".to_owned())
    }

    fn unload(&mut self) {
        self.unloaded = true;
    }
}

#[test]
fn production_adapter_uses_only_explicit_legacy_netlink_attach() {
    let source = include_str!("../src/collectors/bpf/runtime.rs");
    assert!(source.contains("attach_with_options"));
    assert!(source.contains("TcAttachOptions::Netlink"));
    assert!(!source.contains(".attach("));
}

#[test]
fn object_missing_and_load_failure_do_not_silently_fallback() {
    for kind in [
        AdapterErrorKind::ObjectMissing,
        AdapterErrorKind::LoadFailed,
    ] {
        let mut adapter = FakeAya {
            fail_load: Some((ObjectFlavor::PrimaryKfunc, kind)),
            ..FakeAya::default()
        };
        let error = BpfRuntime::load(&mut adapter, "primary.o", "fallback.o").unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(adapter.loads, [ObjectFlavor::PrimaryKfunc]);
    }
}

#[test]
fn only_primary_kfunc_incompatibility_selects_the_fallback_object() {
    let mut adapter = FakeAya {
        fail_load: Some((
            ObjectFlavor::PrimaryKfunc,
            AdapterErrorKind::KfuncIncompatible,
        )),
        ..FakeAya::default()
    };
    let runtime = BpfRuntime::load(&mut adapter, "primary.o", "fallback.o").unwrap();
    assert_eq!(
        adapter.loads,
        [ObjectFlavor::PrimaryKfunc, ObjectFlavor::BytePacketFallback]
    );
    assert!(runtime.primary_kfunc_incompatibility().is_some());
}

#[test]
fn fixed_normal_and_early_netlink_links_are_exact() {
    let normal = LinkSpec::pair("br-lan", AttachMode::Normal);
    assert_eq!(normal[0].direction, LinkDirection::Ingress);
    assert_eq!(normal[0].program, "lanspeed_ingress");
    assert_eq!((normal[0].priority, normal[0].handle), (49_152, 0x1eed));
    assert_eq!(normal[1].direction, LinkDirection::Egress);
    assert_eq!(normal[1].program, "lanspeed_egress");

    let early = LinkSpec::pair("br-lan", AttachMode::EarlyPassthrough);
    assert_eq!(early[0].program, "lanspeed_ingress_early");
    assert_eq!((early[0].priority, early[0].handle), (1, 0x1eee));
    assert_eq!(early[1].program, "lanspeed_egress_early");
    assert_eq!(early[0].kernel_program_name(), "lanspeed_ingres");
    assert_eq!(early[1].kernel_program_name(), "lanspeed_egress");
}

#[test]
fn partial_attach_rolls_back_only_the_owned_ingress_filter() {
    let mut adapter = FakeAya {
        fail_attach_at: Some(1),
        ..FakeAya::default()
    };
    let mut runtime = BpfRuntime::loaded_for_test();
    assert!(runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .is_err());
    assert_eq!(adapter.clsact, ["br-lan"]);
    assert_eq!(
        adapter.attached,
        [LinkSpec::pair("br-lan", AttachMode::Normal)[0].clone()]
    );
    assert_eq!(adapter.detached, adapter.attached);
    assert!(!runtime.is_attached());
}

#[test]
fn multi_interface_attach_is_one_transaction() {
    let mut adapter = FakeAya {
        fail_attach_at: Some(3),
        ..FakeAya::default()
    };
    let mut runtime = BpfRuntime::loaded_for_test();
    assert!(runtime
        .attach_interfaces(
            &mut adapter,
            &["br-lan".to_owned(), "wlan0".to_owned()],
            AttachMode::Normal,
        )
        .is_err());
    assert_eq!(adapter.detached.len(), 3);
    assert!(!runtime.is_attached());
}

#[test]
fn mode_switch_failure_cleans_new_links_and_preserves_the_old_pair() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    adapter.fail_attach_at = Some(3);
    assert!(runtime
        .switch_mode(
            &mut adapter,
            &["br-lan".to_owned()],
            AttachMode::EarlyPassthrough,
        )
        .is_err());
    for spec in LinkSpec::pair("br-lan", AttachMode::Normal) {
        assert_eq!(adapter.hooks.get(&spec), Some(&HookState::Owned));
    }
    for spec in LinkSpec::pair("br-lan", AttachMode::EarlyPassthrough) {
        assert_ne!(adapter.hooks.get(&spec), Some(&HookState::Owned));
    }
    assert!(runtime.is_attached());
}

#[test]
fn mode_switch_detach_failure_enters_inconsistent_state_and_blocks_snapshots() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    adapter.fail_detach = true;
    assert!(runtime
        .switch_mode(
            &mut adapter,
            &["br-lan".to_owned()],
            AttachMode::EarlyPassthrough,
        )
        .is_err());
    assert!(!runtime.is_attached());
    assert_eq!(runtime.health(10_000, 3_000).mode, None);
    let mixed_health = runtime.runtime_health(10_000, 3_000);
    assert!(!mixed_health.dae_early_bpf);
    assert!(mixed_health.runtime_error.is_some());
    let reconcile_event_start = adapter.events.len();
    adapter.fail_detach = false;
    assert!(runtime.ensure_attached(&mut adapter, "reconcile").is_ok());
    let reconcile_events = &adapter.events[reconcile_event_start..];
    let first_restore = reconcile_events
        .iter()
        .position(|event| event == "replace:lanspeed_ingress" || event == "attach:lanspeed_ingress")
        .unwrap();
    let first_new_detach = reconcile_events
        .iter()
        .position(|event| event == "detach:lanspeed_ingress_early")
        .unwrap();
    assert!(first_restore < first_new_detach);
    assert!(runtime.is_attached());
    adapter.map_read = Some(Ok(read(Vec::new())));
    let mut collector = BpfSnapshotCollector::new(16, 5_000);
    assert!(runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities(),
            &ConnectionOverlay::available(),
            10_000,
        )
        .is_ok());
}

#[test]
fn a_foreign_filter_in_the_fixed_slot_is_never_replaced() {
    let mut adapter = FakeAya::default();
    let ingress = LinkSpec::pair("br-lan", AttachMode::Normal)[0].clone();
    adapter.hooks.insert(ingress, HookState::Foreign);
    let mut runtime = BpfRuntime::loaded_for_test();
    let error = runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap_err();
    assert_eq!(error.kind(), AdapterErrorKind::OwnershipConflict);
    assert!(adapter.attached.is_empty());
    assert!(adapter.detached.is_empty());
}

#[test]
fn an_existing_owned_orphan_is_atomically_replaced_without_a_detach_gap() {
    let mut adapter = FakeAya::default();
    for spec in LinkSpec::pair("br-lan", AttachMode::Normal) {
        adapter.hooks.insert(spec, HookState::Owned);
    }
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    assert_eq!(adapter.attached.len(), 2);
    assert!(adapter.detached.is_empty());
    assert!(runtime.is_attached());
}

#[test]
fn repeated_attach_of_the_same_mode_is_idempotent() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    assert_eq!(adapter.attached.len(), 2);
    assert!(adapter.detached.is_empty());
    assert!(runtime.is_attached());
}

#[test]
fn self_heal_restores_only_missing_owned_specs_and_shutdown_leaves_clsact_alone() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::EarlyPassthrough)
        .unwrap();
    let missing = LinkSpec::pair("br-lan", AttachMode::EarlyPassthrough)[1].clone();
    adapter.hooks.remove(&missing);

    assert_eq!(runtime.ensure_attached(&mut adapter, "reload").unwrap(), 1);
    assert_eq!(runtime.self_heal_recoveries(), 1);
    assert_eq!(runtime.last_self_heal_reason(), Some("reload"));
    runtime.shutdown(&mut adapter).unwrap();

    assert_eq!(adapter.forgotten, [missing]);
    assert_eq!(adapter.detached.len(), 2);
    assert!(adapter.unloaded);
    assert_eq!(adapter.clsact, ["br-lan"]);
}

#[test]
fn freshness_expires_at_limit_plus_one_and_rejects_future_timestamps() {
    let identities = identities();
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let mut collector = BpfSnapshotCollector::new(16, 5_000);
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 1_000, 10_000_000_000)])));
    runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
        )
        .unwrap();
    assert!(runtime.health(13_000, 3_000).map_read_ok);
    assert!(!runtime.health(13_001, 3_000).map_read_ok);
    assert!(!runtime.health(9_999, 3_000).map_read_ok);
    let probe = runtime.runtime_health(13_001, 3_000);
    assert!(!probe.bpf_map_read_ok);
    assert_eq!(probe.bpf_last_complete_snapshot_ms, Some(10_000));
    assert_eq!(probe.bpf_snapshot_clients, 1);
}

#[test]
fn self_heal_failure_is_counted_and_does_not_claim_complete_attachment() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let missing = LinkSpec::pair("br-lan", AttachMode::Normal)[0].clone();
    adapter.hooks.remove(&missing);
    adapter.fail_attach_at = Some(adapter.attached.len());
    assert!(runtime.ensure_attached(&mut adapter, "reload").is_err());
    assert_eq!(runtime.self_heal_failures(), 1);
    assert_eq!(runtime.last_self_heal_reason(), Some("reload"));
    assert!(runtime.last_self_heal_failure().is_some());
    assert!(!runtime.is_attached());
    adapter.fail_attach_at = None;
    assert_eq!(runtime.ensure_attached(&mut adapter, "retry").unwrap(), 1);
    assert!(runtime.is_attached());
}

#[test]
fn inspect_failure_is_recorded_in_self_heal_and_runtime_health() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    adapter.fail_inspect = true;
    assert!(runtime.ensure_attached(&mut adapter, "inspect").is_err());
    assert_eq!(runtime.self_heal_failures(), 1);
    assert_eq!(runtime.last_self_heal_reason(), Some("inspect"));
    assert!(runtime
        .runtime_health(10_000, 3_000)
        .runtime_error
        .is_some());
}

#[test]
fn exact_physical_map_capacity_is_reported_as_at_capacity() {
    let identities = identities();
    let entries = (0..lanspeed_common::MAX_CLIENTS)
        .map(|_| raw(DIR_TX, 1, 10_000_000_000))
        .collect();
    let mut adapter = FakeAya {
        map_read: Some(Ok(MapRead {
            entries,
            truncated: false,
        })),
        ..FakeAya::default()
    };
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let mut collector = BpfSnapshotCollector::new(16, 5_000);
    runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
        )
        .unwrap();
    assert!(runtime.map_iteration_truncated_observed());
}

#[test]
fn shutdown_attempts_every_owned_detach_even_after_the_first_error() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    adapter.fail_detach = true;
    assert!(runtime.shutdown(&mut adapter).is_err());
    assert_eq!(adapter.detached.len(), 2);
    assert!(adapter.unloaded);
    assert!(!runtime.is_attached());
}

#[test]
fn map_read_failure_retains_the_last_complete_snapshot_but_marks_health_failed() {
    let identities = identities();
    let mut adapter = FakeAya::default();
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 1_000, 10_000_000_000)])));
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let mut collector = BpfSnapshotCollector::new(16, 5_000);
    let first = runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
        )
        .unwrap();
    assert_eq!(first.clients.len(), 1);

    adapter.map_read = Some(Err(AdapterError::new(
        AdapterErrorKind::MapReadFailed,
        "lookup failed",
    )));
    assert!(runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            11_000,
        )
        .is_err());
    assert_eq!(collector.last_complete(), Some(&first));
    let health = runtime.health(11_000, 3_000);
    assert!(health.map_read_attempted);
    assert!(!health.map_read_ok);
    assert!(health.fresh_snapshot);
}

#[test]
fn unavailable_connection_overlay_keeps_rates_and_omits_stable_counts() {
    let identities = identities();
    let mut adapter = FakeAya::default();
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 1_000, 10_000_000_000)])));
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let mut collector = BpfSnapshotCollector::new(16, 5_000);
    runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
        )
        .unwrap();
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 2_000, 11_000_000_000)])));
    let snapshot = runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::unavailable("conntrack dump failed"),
            11_000,
        )
        .unwrap();
    assert_eq!(snapshot.clients[0].tcp_conns, None);
    assert!(snapshot
        .warnings
        .contains(&SnapshotWarning::ConnectionOverlayUnavailable));
}

#[test]
fn client_cap_is_deterministic_after_complete_identity_folding() {
    let identities = two_identities();
    let mut adapter = FakeAya::default();
    adapter.map_read = Some(Ok(read(vec![
        raw_for([0x02, 0, 0, 0, 0, 2], DIR_TX, 2_000, 10_000_000_000),
        raw_for([0x02, 0, 0, 0, 0, 1], DIR_TX, 1_000, 10_000_000_000),
    ])));
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let mut collector = BpfSnapshotCollector::new(1, 5_000);
    let snapshot = runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
        )
        .unwrap();
    assert_eq!(snapshot.clients[0].identity_key, "02:00:00:00:00:01@lan");
    assert!(snapshot
        .warnings
        .contains(&SnapshotWarning::ClientLimitExceeded));
}

#[test]
fn snapshot_merges_directions_resolves_identity_computes_rates_and_overlays_connections() {
    let identities = identities();
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let mut collector = BpfSnapshotCollector::new(16, 5_000);
    adapter.map_read = Some(Ok(read(vec![
        raw(DIR_TX, 1_000, 10_000_000_000),
        raw(DIR_RX, 2_000, 10_000_000_000),
    ])));
    runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
        )
        .unwrap();

    adapter.map_read = Some(Ok(read(vec![
        raw(DIR_TX, 2_000, 11_000_000_000),
        raw(DIR_RX, 4_000, 11_000_000_000),
    ])));
    let mut overlay = ConnectionOverlay::available();
    overlay.insert(
        "02:00:00:00:00:01@lan",
        ConnectionCounts {
            tcp: 7,
            udp: 5,
            udp_dns: 2,
            udp_other: 3,
        },
    );
    let snapshot = runtime
        .collect_snapshot(&mut adapter, &mut collector, &identities, &overlay, 11_000)
        .unwrap();
    let client = &snapshot.clients[0];
    assert_eq!(client.identity_key, "02:00:00:00:00:01@lan");
    assert_eq!((client.tx_bps, client.rx_bps), (8_000, 16_000));
    assert_eq!(
        (client.bpf_approx_tcp_tuples, client.bpf_approx_udp_tuples),
        (3, 4)
    );
    assert_eq!((client.tcp_conns, client.udp_conns), (Some(7), Some(5)));
    assert_eq!(
        (client.udp_dns_conns, client.udp_other_conns),
        (Some(2), Some(3))
    );
}

#[test]
fn truncation_client_cap_counter_rollback_and_time_rollback_are_typed_warnings() {
    let identities = identities();
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let mut collector = BpfSnapshotCollector::new(1, 5_000);
    adapter.map_read = Some(Ok(MapRead {
        entries: vec![raw(DIR_TX, 2_000, 10_000_000_000)],
        truncated: true,
    }));
    runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
        )
        .unwrap();
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 1_000, 9_000_000_000)])));
    let snapshot = runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            9_000,
        )
        .unwrap();
    assert!(runtime.map_iteration_truncated_observed());
    assert!(snapshot
        .warnings
        .contains(&SnapshotWarning::MapIterationTruncated));
    assert!(snapshot.rate_warnings.contains(&RateWarning::TimeRollback));
    assert!(snapshot
        .rate_warnings
        .contains(&RateWarning::CounterAnomaly));
}

fn identities() -> IdentityTable {
    let mut table = IdentityTable::new(16);
    assert!(table
        .observe(IdentityObservation {
            mac: "02:00:00:00:00:01",
            zone: Some("lan"),
            interface: "br-lan",
            ip: Some("192.168.1.2"),
            hostname: Some("client"),
            last_seen: 1,
            source: ObservationSource::Neighbor,
        })
        .unwrap());
    table
}

fn two_identities() -> IdentityTable {
    let mut table = identities();
    assert!(table
        .observe(IdentityObservation {
            mac: "02:00:00:00:00:02",
            zone: Some("lan"),
            interface: "br-lan",
            ip: Some("192.168.1.3"),
            hostname: Some("client-2"),
            last_seen: 1,
            source: ObservationSource::Neighbor,
        })
        .unwrap());
    table
}

fn raw(direction: u8, bytes: u64, last_seen_ns: u64) -> RawMapSample {
    raw_for([0x02, 0, 0, 0, 0, 1], direction, bytes, last_seen_ns)
}

fn raw_for(mac: [u8; 6], direction: u8, bytes: u64, last_seen_ns: u64) -> RawMapSample {
    RawMapSample {
        key: LanspeedKey {
            ifindex: 7,
            direction,
            mac,
            ..LanspeedKey::default()
        },
        counters: LanspeedCounters {
            bytes,
            packets: 1,
            last_seen: last_seen_ns,
            tcp_conns: 3,
            udp_conns: 4,
        },
    }
}

fn read(entries: Vec<RawMapSample>) -> MapRead {
    MapRead {
        entries,
        truncated: false,
    }
}
