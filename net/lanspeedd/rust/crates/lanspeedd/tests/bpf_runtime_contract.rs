use std::{collections::BTreeMap, path::Path};

use lanspeed_common::{LanspeedCounters, LanspeedKey, DIR_RX, DIR_TX};
use lanspeedd::{
    collectors::bpf::{
        runtime::{
            AdapterError, AdapterErrorKind, AttachMode, AyaAdapter, BpfRuntime, HookState,
            LinkDirection, LinkSpec, ObjectFlavor, ReconfigureRateBaseline, ReconfigureStrategy,
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
    fail_detach_at: Option<usize>,
    fail_detach_after_mutation: bool,
    fail_inspect: bool,
    fail_inspect_at: Option<usize>,
    inspect_count: usize,
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
        let inspect_index = self.inspect_count;
        self.inspect_count += 1;
        if self.fail_inspect || self.fail_inspect_at == Some(inspect_index) {
            return Err(AdapterError::new(
                AdapterErrorKind::AttachFailed,
                "injected inspect failure",
            ));
        }
        Ok(self.hooks.get(spec).copied().unwrap_or(HookState::Absent))
    }

    fn attach_netlink(&mut self, spec: &LinkSpec) -> Result<Self::Link, AdapterError> {
        if !self
            .clsact
            .iter()
            .any(|interface| interface == &spec.interface)
        {
            return Err(AdapterError::new(
                AdapterErrorKind::AttachFailed,
                "injected missing clsact",
            ));
        }
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
        let detach_index = self.detached.len();
        self.detached.push(spec.clone());
        self.events.push(format!("detach:{}", spec.program));
        if self.fail_detach_after_mutation {
            self.hooks.remove(spec);
            return Err(AdapterError::new(
                AdapterErrorKind::DetachFailed,
                "injected detach failure after mutation",
            ));
        }
        if self.fail_detach {
            return Err(AdapterError::new(
                AdapterErrorKind::DetachFailed,
                "injected detach failure",
            ));
        }
        if self.fail_detach_at == Some(detach_index) {
            return Err(AdapterError::new(
                AdapterErrorKind::DetachFailed,
                "injected indexed detach failure",
            ));
        }
        self.hooks.remove(spec);
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

    fn abandon_link(&mut self, spec: &LinkSpec, _link: Self::Link) -> Result<(), AdapterError> {
        self.forgotten.push(spec.clone());
        Ok(())
    }

    fn read_clients(&mut self) -> Result<MapRead, AdapterError> {
        self.events.push("read_clients".to_owned());
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
fn production_sampling_uses_the_same_boot_monotonic_epoch_as_bpf() {
    let production = include_str!("../src/production.rs");
    let ebpf = include_str!("../../lanspeed-ebpf/src/account.rs");

    assert!(
        ebpf.contains("bpf_ktime_get_ns()"),
        "BPF last_seen must remain based on the kernel boot-monotonic clock"
    );
    assert!(
        !production.contains("started.elapsed()"),
        "process-relative elapsed time cannot be compared with BPF boot-monotonic last_seen"
    );
    assert!(
        production.contains("monotonic_millis"),
        "production samples must use the shared boot-monotonic millisecond clock"
    );
}

#[test]
fn production_refreshes_dae_processes_before_bpf_map_reads_and_reloads_mode_transactionally() {
    let source = include_str!("../src/production.rs");
    let tick = source
        .split("fn collection_tick(&mut self)")
        .nth(1)
        .unwrap()
        .split("fn refresh_clients_connections")
        .next()
        .unwrap();
    let refresh = tick.find("refresh_dae_process_state").unwrap();
    let collect = tick.find("collect_and_reschedule").unwrap();

    assert!(
        refresh < collect,
        "the fast /proc scan must precede collection/map reads"
    );
    assert!(tick.contains("process_activity_changed"));
    assert!(tick.contains("runtime.bpf_attach_mode_mismatch()"));
    assert_eq!(tick.matches("run_dae_mode_tick(").count(), 1);
    assert!(tick.contains("reload_inner()"));
    assert!(
        tick.contains("schedule("),
        "a failed non-fatal reload must re-arm the timer"
    );
    assert!(!source.contains(".switch_mode("));

    let reload = source
        .split("fn reload_inner(&mut self)")
        .nth(1)
        .unwrap()
        .split("fn finish_mode_switch_suspend_failure")
        .next()
        .unwrap();
    assert!(reload.contains("process_tracker.clone()"));
    assert!(reload.contains("prepare_with_process_tracker"));
    assert!(reload.contains("suspend_for_replacement"));
    assert!(reload.contains("attach_suspended"));
    assert!(reload.contains("finish_mode_switch_rollback"));
}

#[test]
fn production_rust_has_no_pidof_probe_path_and_publishes_dae_and_nss_alias_evidence() {
    let commands = include_str!("../src/probe/commands.rs");
    let collector = include_str!("../src/probe/collector.rs");
    let production = include_str!("../src/production.rs");
    let nss_evidence = include_str!("../src/production_evidence.rs");

    assert!(!commands.contains("Pidof"));
    assert!(!commands.contains("pidof"));
    assert!(!collector.contains("Pidof"));
    assert!(!collector.contains("pidof"));
    for field in [
        "\"running\"",
        "\"process\"",
        "\"runtime_active\"",
        "\"process_probe_error\"",
    ] {
        assert!(
            production.contains(field),
            "missing production evidence field {field}"
        );
    }
    for field in [
        "\"present\"",
        "\"ecm_active\"",
        "\"ecm_offload_active\"",
        "\"ppe_active\"",
        "\"ppe_offload_active\"",
        "\"direct_state_present\"",
        "\"direct_state_readable\"",
        "\"direct_supported\"",
        "\"direct_enabled\"",
        "\"direct_source\"",
        "\"fallback_reason\"",
        "\"direct_state_errno\"",
        "\"direct_state_major\"",
        "\"direct_source_path\"",
        "\"bridge_mgr\"",
        "\"ifb_active\"",
        "\"nsm_active\"",
        "\"dp_active\"",
        "\"mcs_active\"",
        "\"subsystems\"",
        "\"accelerated_connections\"",
        "\"accelerated_tcp\"",
        "\"accelerated_udp\"",
        "\"accelerated_other\"",
        "\"host_count\"",
        "\"mapping_count\"",
        "\"counter_source\"",
        "\"counter_cadence_seconds\"",
        "\"counter_delta_scope\"",
        "\"bpf_visibility\"",
        "\"interface_counters_accurate\"",
        "\"nssifb_policy\"",
    ] {
        assert!(
            nss_evidence.contains(field),
            "missing production evidence field {field}"
        );
    }
    assert!(production.contains("production_evidence::nss_details("));
    assert!(nss_evidence.contains("direct_fallback_reason("));
}

#[test]
fn production_mode_switch_suspends_before_attaching_on_the_same_bpf_object() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();

    assert_eq!(
        runtime.reconfigure_strategy(AttachMode::Normal),
        ReconfigureStrategy::InPlace
    );
    assert_eq!(
        runtime.reconfigure_strategy(AttachMode::EarlyPassthrough),
        ReconfigureStrategy::SuspendThenAttach
    );
    let source = include_str!("../src/production.rs");
    assert!(source.contains("ReconfigureStrategy::SuspendThenAttach"));
    assert!(!source.contains("load_independent_bpf"));
    let mode_switch = source
        .split("let suspended = match {")
        .nth(1)
        .unwrap()
        .split("commit_reload(")
        .next()
        .unwrap();
    assert!(mode_switch.contains("suspend_for_replacement"));
    assert!(mode_switch.contains("attach_suspended"));
    assert!(mode_switch.contains("collect_with_external_bpf"));
    assert!(mode_switch.contains("candidate.bpf = current.bpf.take()"));
    assert!(mode_switch.contains("finish_mode_switch_rollback"));
    let rollback = source
        .split("fn finish_mode_switch_rollback")
        .nth(1)
        .unwrap()
        .split("pub fn run")
        .next()
        .unwrap();
    assert!(rollback.contains("old BPF restore failed"));
    assert!(mode_switch.contains("let old_topology_intact = runtime.is_attached()"));
    assert!(mode_switch.contains("finish_mode_switch_suspend_failure"));
}

fn assert_suspended_mode_switch_abort_is_rate_safe(old_mode: AttachMode, new_mode: AttachMode) {
    let identities = identities();
    let mut old_adapter = FakeAya::default();
    let mut old_runtime = BpfRuntime::loaded_for_test();
    old_runtime
        .attach_interface(&mut old_adapter, "br-lan", old_mode)
        .unwrap();
    let mut old_collector = BpfSnapshotCollector::new(16, 5_000);
    old_adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 1_000, 10_000_000_000)])));
    old_runtime
        .collect_snapshot(
            &mut old_adapter,
            &mut old_collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
        )
        .unwrap();
    let suspended = old_runtime
        .suspend_for_replacement(&mut old_adapter)
        .unwrap();
    assert_eq!(old_adapter.detached, LinkSpec::pair("br-lan", old_mode));

    old_runtime
        .attach_suspended(&mut old_adapter, &suspended, &["br-lan".into()], new_mode)
        .unwrap();
    old_adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 50_000, 11_000_000_000)])));
    let mut candidate_collector = BpfSnapshotCollector::new(16, 5_000);
    let candidate = old_runtime
        .collect_snapshot(
            &mut old_adapter,
            &mut candidate_collector,
            &identities,
            &ConnectionOverlay::available(),
            11_000,
        )
        .unwrap();
    assert_eq!(candidate.clients[0].tx_bytes, 50_000);

    let suspended_candidate = old_runtime
        .suspend_for_replacement(&mut old_adapter)
        .unwrap();
    drop(suspended_candidate);
    old_runtime
        .resume_suspended(&mut old_adapter, suspended)
        .unwrap();
    old_adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 52_000, 12_000_000_000)])));
    let old = old_runtime
        .collect_snapshot(
            &mut old_adapter,
            &mut old_collector,
            &identities,
            &ConnectionOverlay::available(),
            12_000,
        )
        .unwrap();
    assert_eq!(old.clients[0].tx_bytes, 52_000);
    assert_eq!(old.clients[0].tx_bps, 0);
    assert_eq!(old_adapter.detached.len(), 4);
}

#[test]
fn normal_to_early_abort_keeps_the_old_map_and_ratebook_exact() {
    assert_suspended_mode_switch_abort_is_rate_safe(
        AttachMode::Normal,
        AttachMode::EarlyPassthrough,
    );
}

#[test]
fn early_to_normal_abort_keeps_the_old_map_and_ratebook_exact() {
    assert_suspended_mode_switch_abort_is_rate_safe(
        AttachMode::EarlyPassthrough,
        AttachMode::Normal,
    );
}

#[test]
fn committed_suspended_mode_switch_detaches_each_hook_once() {
    for (old_mode, new_mode) in [
        (AttachMode::Normal, AttachMode::EarlyPassthrough),
        (AttachMode::EarlyPassthrough, AttachMode::Normal),
    ] {
        let mut adapter = FakeAya::default();
        let mut runtime = BpfRuntime::loaded_for_test();
        runtime
            .attach_interface(&mut adapter, "br-lan", old_mode)
            .unwrap();
        let suspended = runtime.suspend_for_replacement(&mut adapter).unwrap();
        runtime
            .attach_suspended(&mut adapter, &suspended, &["br-lan".into()], new_mode)
            .unwrap();
        drop(suspended);

        runtime.shutdown(&mut adapter).unwrap();
        let mut expected = LinkSpec::pair("br-lan", old_mode).to_vec();
        expected.extend(LinkSpec::pair("br-lan", new_mode));
        assert_eq!(adapter.detached, expected);
    }
}

#[test]
fn suspended_attach_rolls_back_when_a_later_hook_inspection_fails() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let suspended = runtime.suspend_for_replacement(&mut adapter).unwrap();
    adapter.inspect_count = 0;
    adapter.fail_inspect_at = Some(1);

    let error = runtime
        .attach_suspended(
            &mut adapter,
            &suspended,
            &["br-lan".into()],
            AttachMode::EarlyPassthrough,
        )
        .unwrap_err();

    assert_eq!(error.kind(), AdapterErrorKind::AttachFailed);
    assert_eq!(adapter.detached.len(), 3);
    assert_eq!(
        adapter
            .hooks
            .values()
            .filter(|state| **state == HookState::Owned)
            .count(),
        0
    );
    adapter.fail_inspect_at = None;
    runtime.resume_suspended(&mut adapter, suspended).unwrap();
    assert_eq!(runtime.attach_mode(), Some(AttachMode::Normal));
}

#[test]
fn suspend_inspection_failure_preserves_hooks_but_invalidates_attachment_health() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let hooks_before = adapter.hooks.clone();
    let detached_before = adapter.detached.clone();
    adapter.fail_inspect_at = Some(adapter.inspect_count);

    let error = match runtime.suspend_for_replacement(&mut adapter) {
        Ok(_) => panic!("suspend inspection unexpectedly succeeded"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), AdapterErrorKind::AttachFailed);
    assert_eq!(adapter.hooks, hooks_before);
    assert_eq!(adapter.detached, detached_before);
    assert_eq!(runtime.attach_mode(), Some(AttachMode::Normal));
    assert!(!runtime.is_attached());
    assert!(!runtime.runtime_health(10_000, 3_000).bpf_attached);

    adapter.fail_inspect_at = None;
    runtime.ensure_attached(&mut adapter, "retry").unwrap();
    assert!(runtime.is_attached());
}

#[test]
fn suspended_attach_rollback_detach_failure_blocks_resume() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let suspended = runtime.suspend_for_replacement(&mut adapter).unwrap();
    adapter.inspect_count = 0;
    adapter.fail_inspect_at = Some(1);
    adapter.fail_detach_at = Some(2);

    let error = runtime
        .attach_suspended(
            &mut adapter,
            &suspended,
            &["br-lan".into()],
            AttachMode::EarlyPassthrough,
        )
        .unwrap_err();

    assert_eq!(error.kind(), AdapterErrorKind::DetachFailed);
    assert!(!runtime.is_attached());
    assert_eq!(
        adapter
            .hooks
            .values()
            .filter(|state| **state == HookState::Owned)
            .count(),
        1
    );
    adapter.fail_inspect_at = None;
    adapter.fail_detach_at = None;
    let resume_error = runtime
        .resume_suspended(&mut adapter, suspended)
        .unwrap_err();
    assert_eq!(resume_error.kind(), AdapterErrorKind::AttachFailed);
    assert_eq!(
        adapter
            .hooks
            .values()
            .filter(|state| **state == HookState::Owned)
            .count(),
        1
    );
}

#[test]
fn suspended_mode_switch_creates_clsact_only_for_new_interfaces() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interfaces(
            &mut adapter,
            &["br-lan".into(), "lan2".into()],
            AttachMode::Normal,
        )
        .unwrap();
    let suspended = runtime.suspend_for_replacement(&mut adapter).unwrap();

    runtime
        .attach_suspended(
            &mut adapter,
            &suspended,
            &["lan2".into(), "lan3".into()],
            AttachMode::EarlyPassthrough,
        )
        .unwrap();

    assert_eq!(adapter.clsact, ["br-lan", "lan2", "lan3"]);
    assert_eq!(adapter.attached.len(), 8);
    drop(suspended);
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
fn byte_only_loader_never_attempts_the_kfunc_object() {
    let mut adapter = FakeAya::default();

    let runtime = BpfRuntime::load_byte_only(&mut adapter, "fallback.o").unwrap();

    assert_eq!(adapter.loads, [ObjectFlavor::BytePacketFallback]);
    assert!(runtime.primary_kfunc_incompatibility().is_none());
}

#[test]
fn production_uses_byte_only_accounting_on_the_packet_hot_path() {
    let production = include_str!("../src/production.rs");
    let activation = production
        .split("fn activate_new_bpf")
        .nth(1)
        .unwrap()
        .split("fn checkpoint")
        .next()
        .unwrap();

    assert!(activation.contains("BpfRuntime::load_byte_only"));
    assert!(activation.contains("FALLBACK_OBJECT_PATH"));
    assert!(!activation.contains("PRIMARY_OBJECT_PATH"));
    assert!(!activation.contains("BpfRuntime::load("));
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
fn aborted_reconfigure_preserves_the_exact_old_topology_and_mode() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let old_hooks = adapter.hooks.clone();
    let old_health = runtime.health(10_000, 3_000);

    let transaction = runtime
        .prepare_reconfigure(
            &mut adapter,
            &["br-lan".into(), "lan2".into()],
            AttachMode::EarlyPassthrough,
        )
        .unwrap();
    runtime
        .abort_reconfigure(&mut adapter, transaction)
        .unwrap();

    assert_eq!(adapter.hooks, old_hooks);
    assert_eq!(runtime.health(10_000, 3_000), old_health);
    assert!(runtime.is_attached());
}

#[test]
fn reconfigure_rejects_a_stale_tracked_hook_without_mutating_topology() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let missing = LinkSpec::pair("br-lan", AttachMode::Normal)[0].clone();
    adapter.hooks.remove(&missing);
    let attached_before = adapter.attached.clone();
    let detached_before = adapter.detached.clone();

    let error = runtime
        .prepare_reconfigure(&mut adapter, &["br-lan".into()], AttachMode::Normal)
        .unwrap_err();

    assert_eq!(error.kind(), AdapterErrorKind::AttachFailed);
    assert_eq!(adapter.attached, attached_before);
    assert_eq!(adapter.detached, detached_before);
    assert_eq!(runtime.health(10_000, 3_000).mode, Some(AttachMode::Normal));
}

#[test]
fn committed_reconfigure_detaches_each_obsolete_hook_once_without_rollback() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let old_specs = LinkSpec::pair("br-lan", AttachMode::Normal);

    let transaction = runtime
        .prepare_reconfigure(
            &mut adapter,
            &["br-lan".into()],
            AttachMode::EarlyPassthrough,
        )
        .unwrap();
    let cleanup =
        runtime.commit_reconfigure(transaction, ReconfigureRateBaseline::ResetOnNextCollection);
    runtime
        .run_postcommit_cleanup(&mut adapter, cleanup)
        .unwrap();

    assert_eq!(
        runtime.health(10_000, 3_000).mode,
        Some(AttachMode::EarlyPassthrough)
    );
    for spec in old_specs {
        assert_eq!(
            adapter
                .detached
                .iter()
                .filter(|value| **value == spec)
                .count(),
            1
        );
    }
    assert!(runtime.is_attached());
}

#[test]
fn postcommit_cleanup_error_keeps_the_committed_topology() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();

    let transaction = runtime
        .prepare_reconfigure(
            &mut adapter,
            &["br-lan".into()],
            AttachMode::EarlyPassthrough,
        )
        .unwrap();
    let cleanup =
        runtime.commit_reconfigure(transaction, ReconfigureRateBaseline::ResetOnNextCollection);
    adapter.fail_detach_after_mutation = true;
    assert!(runtime
        .run_postcommit_cleanup(&mut adapter, cleanup)
        .is_err());

    assert_eq!(
        runtime.health(10_000, 3_000).mode,
        Some(AttachMode::EarlyPassthrough)
    );
    for spec in LinkSpec::pair("br-lan", AttachMode::EarlyPassthrough) {
        assert_eq!(adapter.hooks.get(&spec), Some(&HookState::Owned));
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
fn same_generation_reconfigure_retains_overlap_and_only_changes_interface_diff() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let original_attaches = adapter.attached.len();
    runtime
        .switch_mode(&mut adapter, &["br-lan".into()], AttachMode::Normal)
        .unwrap();
    assert_eq!(adapter.attached.len(), original_attaches);
    assert!(adapter.detached.is_empty());

    runtime
        .switch_mode(
            &mut adapter,
            &["br-lan".into(), "lan2".into()],
            AttachMode::Normal,
        )
        .unwrap();
    assert_eq!(adapter.attached.len(), original_attaches + 2);
    assert!(adapter.detached.is_empty(), "overlap must remain attached");
    runtime
        .switch_mode(&mut adapter, &["lan2".into()], AttachMode::Normal)
        .unwrap();
    assert_eq!(
        adapter.detached.len(),
        2,
        "only removed br-lan hooks detach"
    );
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
fn self_healing_collection_restores_a_missing_hook_before_reading_the_map() {
    let identities = identities();
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let missing = LinkSpec::pair("br-lan", AttachMode::Normal)[0].clone();
    adapter.hooks.remove(&missing);
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 1_000, 10_000_000_000)])));
    let event_start = adapter.events.len();
    let mut collector = BpfSnapshotCollector::new(16, 5_000);

    let snapshot = runtime
        .collect_snapshot_self_healing(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
            "production.collect.internal",
        )
        .unwrap();

    assert_eq!(snapshot.clients.len(), 1);
    assert_eq!(
        &adapter.events[event_start..],
        [
            format!("attach:{}", missing.program),
            "read_clients".to_owned(),
        ]
    );
    assert_eq!(runtime.self_heal_recoveries(), 1);
    assert_eq!(
        runtime.last_self_heal_reason(),
        Some("production.collect.internal")
    );
}

#[test]
fn self_healing_collection_skips_map_read_when_hook_inspection_fails() {
    let identities = identities();
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 1_000, 9_000_000_000)])));
    let mut collector = BpfSnapshotCollector::new(16, 5_000);
    runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            9_000,
        )
        .unwrap();
    adapter.fail_inspect = true;
    adapter.map_read = Some(Ok(read(Vec::new())));

    let error = runtime
        .collect_snapshot_self_healing(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
            "production.collect.external",
        )
        .unwrap_err();

    assert_eq!(error.kind(), AdapterErrorKind::AttachFailed);
    assert!(adapter.map_read.is_some(), "map read must not be consumed");
    let health = runtime.runtime_health(10_000, 3_000);
    assert!(health.bpf_map_read_attempted);
    assert!(!health.bpf_map_read_ok);
    assert_eq!(health.bpf_last_complete_snapshot_ms, Some(9_000));
    assert_eq!(health.bpf_self_heal_failures, 1);
    assert_eq!(
        health.bpf_self_heal_last_reason.as_deref(),
        Some("production.collect.external")
    );
    assert_eq!(
        health.bpf_self_heal_last_failure.as_deref(),
        Some("injected inspect failure")
    );
    assert_eq!(
        health.runtime_error.as_deref(),
        Some("injected inspect failure")
    );
}

#[test]
fn self_healing_collection_skips_map_read_when_hook_reattach_fails() {
    let identities = identities();
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 1_000, 9_000_000_000)])));
    let mut collector = BpfSnapshotCollector::new(16, 5_000);
    runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            9_000,
        )
        .unwrap();
    let missing = LinkSpec::pair("br-lan", AttachMode::Normal)[0].clone();
    adapter.hooks.remove(&missing);
    adapter.fail_attach_at = Some(adapter.attached.len());
    adapter.map_read = Some(Ok(read(Vec::new())));

    let error = runtime
        .collect_snapshot_self_healing(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
            "production.collect.internal",
        )
        .unwrap_err();

    assert_eq!(error.kind(), AdapterErrorKind::AttachFailed);
    assert!(adapter.map_read.is_some(), "map read must not be consumed");
    let health = runtime.runtime_health(10_000, 3_000);
    assert!(!health.bpf_attached);
    assert!(health.bpf_map_read_attempted);
    assert!(!health.bpf_map_read_ok);
    assert_eq!(health.bpf_last_complete_snapshot_ms, Some(9_000));
    assert_eq!(health.bpf_self_heal_failures, 1);
    assert_eq!(
        health.bpf_self_heal_last_reason.as_deref(),
        Some("production.collect.internal")
    );
    assert_eq!(
        health.bpf_self_heal_last_failure.as_deref(),
        Some("injected attach failure")
    );
    assert_eq!(
        health.runtime_error.as_deref(),
        Some("injected attach failure")
    );
}

#[test]
fn production_bpf_sampling_paths_use_stable_self_heal_reasons() {
    let source = include_str!("../src/production.rs");
    assert_eq!(source.matches("collect_snapshot_self_healing(").count(), 2);
    assert!(source
        .contains("const INTERNAL_BPF_SELF_HEAL_REASON: &str = \"production.collect.internal\";"));
    assert!(source
        .contains("const EXTERNAL_BPF_SELF_HEAL_REASON: &str = \"production.collect.external\";"));
    assert!(source.contains("bpf_snapshot_fresh"));
    assert!(source.contains("(self.bpf_collector.last_complete().cloned(), false)"));
    assert!(source.contains("update_coverage(now_ms, &clients, &interfaces, coverage_fresh)"));
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
fn map_updates_during_iteration_advance_the_snapshot_watermark() {
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

    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 2_000, 11_004_000_000)])));
    let snapshot = runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            11_000,
        )
        .unwrap();
    let client = &snapshot.clients[0];

    assert_eq!(snapshot.sample_ms, 11_004);
    assert_eq!(client.sample_ms, 11_004);
    assert_eq!(client.last_seen_ms, 11_004);
    assert!(client.tx_bps > 0);
    assert_eq!(
        runtime.health(11_004, 3_000).last_complete_snapshot_ms,
        Some(11_004)
    );
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
    let failed = runtime.runtime_health(10_000, 3_000);
    assert!(!runtime.is_attached());
    assert!(!failed.bpf_attached);
    assert!(failed.runtime_error.is_some());

    adapter.fail_inspect = false;
    assert_eq!(runtime.ensure_attached(&mut adapter, "retry").unwrap(), 0);
    assert!(runtime.is_attached());
}

#[test]
fn foreign_replacement_invalidates_health_and_is_never_overwritten() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let foreign = LinkSpec::pair("br-lan", AttachMode::Normal)[0].clone();
    let attached_before = adapter.attached.len();
    adapter.hooks.insert(foreign.clone(), HookState::Foreign);

    let error = runtime
        .ensure_attached(&mut adapter, "foreign")
        .unwrap_err();

    assert_eq!(error.kind(), AdapterErrorKind::OwnershipConflict);
    assert!(!runtime.is_attached());
    assert!(!runtime.runtime_health(10_000, 3_000).bpf_attached);
    assert_eq!(adapter.hooks.get(&foreign), Some(&HookState::Foreign));
    assert_eq!(adapter.attached.len(), attached_before);
    assert!(!adapter.detached.contains(&foreign));

    adapter.hooks.remove(&foreign);
    runtime.ensure_attached(&mut adapter, "retry").unwrap();
    assert!(runtime.is_attached());
    assert_eq!(adapter.hooks.get(&foreign), Some(&HookState::Owned));
    assert_eq!(adapter.attached.len(), attached_before + 1);
    assert!(adapter.forgotten.contains(&foreign));
    assert!(!adapter.detached.contains(&foreign));
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
fn shutdown_detach_failure_retains_cleanup_state_for_a_second_retry() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    adapter.fail_detach = true;
    assert!(runtime.shutdown(&mut adapter).is_err());
    assert_eq!(adapter.detached.len(), 2);
    assert!(!adapter.unloaded);
    assert!(runtime.runtime_health(10_000, 3_000).bpf_object_loaded);
    assert!(!runtime.is_attached());
    adapter.fail_detach = false;
    runtime.shutdown(&mut adapter).unwrap();
    assert_eq!(adapter.detached.len(), 4);
    assert!(adapter.unloaded);
    assert!(!runtime.runtime_health(10_000, 3_000).bpf_object_loaded);
}

#[test]
fn shutdown_never_detaches_a_fixed_slot_replaced_by_a_foreign_filter() {
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let foreign = LinkSpec::pair("br-lan", AttachMode::Normal)[0].clone();
    adapter.hooks.insert(foreign.clone(), HookState::Foreign);
    runtime.shutdown(&mut adapter).unwrap();
    assert_eq!(adapter.hooks.get(&foreign), Some(&HookState::Foreign));
    assert!(!adapter.detached.contains(&foreign));
    assert!(adapter.forgotten.contains(&foreign));
    assert!(adapter.unloaded);
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
fn unpublished_late_cycle_can_restore_bpf_rate_and_health_baselines() {
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

    let checkpoint = runtime.collection_checkpoint(&collector);
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 2_000, 11_000_000_000)])));
    let unpublished = runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            11_000,
        )
        .unwrap();
    assert_eq!(unpublished.clients[0].tx_bps, 8_000);
    runtime.restore_collection_checkpoint(&mut collector, checkpoint);
    assert_eq!(
        runtime.health(11_000, 3_000).last_complete_snapshot_ms,
        Some(10_000)
    );

    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 2_000, 12_000_000_000)])));
    let published = runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            12_000,
        )
        .unwrap();
    assert_eq!(
        published.clients[0].tx_bps, 4_000,
        "rate baseline must ignore the unpublished 11s cycle"
    );
}

#[test]
fn aborted_reconfigure_restores_the_old_ratebook_baseline() {
    let identities = identities();
    let mut adapter = FakeAya::default();
    let mut runtime = BpfRuntime::loaded_for_test();
    runtime
        .attach_interface(&mut adapter, "br-lan", AttachMode::Normal)
        .unwrap();
    let mut old_collector = BpfSnapshotCollector::new(16, 5_000);
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 1_000, 10_000_000_000)])));
    runtime
        .collect_snapshot(
            &mut adapter,
            &mut old_collector,
            &identities,
            &ConnectionOverlay::available(),
            10_000,
        )
        .unwrap();
    let old_hooks = adapter.hooks.clone();

    let transaction = runtime
        .prepare_reconfigure(
            &mut adapter,
            &["br-lan".into()],
            AttachMode::EarlyPassthrough,
        )
        .unwrap();
    let mut candidate_collector = old_collector.clone();
    candidate_collector.reset_rates();
    let checkpoint = runtime.collection_checkpoint(&candidate_collector);
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 2_000, 11_000_000_000)])));
    let staged = runtime
        .collect_snapshot(
            &mut adapter,
            &mut candidate_collector,
            &identities,
            &ConnectionOverlay::available(),
            11_000,
        )
        .unwrap();
    assert_eq!(staged.clients[0].tx_bps, 0);

    runtime.restore_collection_checkpoint(&mut candidate_collector, checkpoint);
    runtime
        .abort_reconfigure(&mut adapter, transaction)
        .unwrap();
    assert_eq!(adapter.hooks, old_hooks);
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 2_000, 12_000_000_000)])));
    let published = runtime
        .collect_snapshot(
            &mut adapter,
            &mut old_collector,
            &identities,
            &ConnectionOverlay::available(),
            12_000,
        )
        .unwrap();
    assert_eq!(published.clients[0].tx_bps, 4_000);
}

#[test]
fn prepared_reconfigure_baseline_is_not_reset_again_after_commit() {
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

    let transaction = runtime
        .prepare_reconfigure(
            &mut adapter,
            &["br-lan".into()],
            AttachMode::EarlyPassthrough,
        )
        .unwrap();
    collector.reset_rates();
    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 2_000, 11_000_000_000)])));
    runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            11_000,
        )
        .unwrap();
    let cleanup = runtime.commit_reconfigure(transaction, ReconfigureRateBaseline::Prepared);
    runtime
        .run_postcommit_cleanup(&mut adapter, cleanup)
        .unwrap();

    adapter.map_read = Some(Ok(read(vec![raw(DIR_TX, 3_000, 12_000_000_000)])));
    let next = runtime
        .collect_snapshot(
            &mut adapter,
            &mut collector,
            &identities,
            &ConnectionOverlay::available(),
            12_000,
        )
        .unwrap();
    assert_eq!(next.clients[0].tx_bps, 8_000);
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
