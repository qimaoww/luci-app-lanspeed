use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::Arc,
};

use lanspeedd::{
    config::RuntimeConfig,
    daemon::{
        abort_reload_after_timer_failure, activate_runtime, collect_and_reschedule,
        install_control_or_shutdown, reconnect_and_register, CoordinatorState,
        ProductionCoordinator, Runtime, RuntimeFactory, SignalBridge, Transport,
    },
    error::DaemonError,
    model::{Client, Confidence, StatusResponse},
    state::{ResponseSnapshot, SnapshotStore},
    ubus::{client_connections_response, Method},
};

#[derive(Clone, Default)]
struct Events(Rc<RefCell<Vec<String>>>);
impl Events {
    fn push(&self, event: impl Into<String>) {
        self.0.borrow_mut().push(event.into());
    }
    fn values(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

struct FakeTransport {
    events: Events,
    fail_connect: bool,
    fail_register: bool,
    fail_reconnect: bool,
    fail_collection_timer: bool,
    fail_shutdown: bool,
}
impl Transport for FakeTransport {
    fn connect(&mut self) -> Result<(), DaemonError> {
        self.events.push("connect");
        if self.fail_connect {
            Err(DaemonError::transport("connect failed"))
        } else {
            Ok(())
        }
    }
    fn register(&mut self, methods: &[Method]) -> Result<(), DaemonError> {
        self.events.push(format!("register:{}", methods.len()));
        if self.fail_register {
            Err(DaemonError::transport("register failed"))
        } else {
            Ok(())
        }
    }
    fn schedule_collection(&mut self, delay_ms: u32) -> Result<(), DaemonError> {
        self.events.push(format!("collection_timer:{delay_ms}"));
        if self.fail_collection_timer {
            Err(DaemonError::transport("timer failed"))
        } else {
            Ok(())
        }
    }
    fn schedule_reconnect(&mut self, delay_ms: u32) -> Result<(), DaemonError> {
        self.events.push(format!("reconnect_timer:{delay_ms}"));
        Ok(())
    }
    fn reconnect(&mut self) -> Result<(), DaemonError> {
        self.events.push("reconnect");
        if self.fail_reconnect {
            Err(DaemonError::transport("reconnect failed"))
        } else {
            Ok(())
        }
    }
    fn shutdown(&mut self) -> Result<(), DaemonError> {
        self.events.push("transport_shutdown");
        if self.fail_shutdown {
            Err(DaemonError::transport("shutdown failed"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
struct FakeRuntime {
    generation: u64,
    events: Events,
    fail_collect: bool,
    fail_shutdown: bool,
    cycles: u64,
}
impl Runtime for FakeRuntime {
    type Checkpoint = u64;
    fn checkpoint(&self) -> Self::Checkpoint {
        self.cycles
    }
    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        self.cycles = checkpoint;
    }
    fn collect(&mut self) -> Result<ResponseSnapshot, DaemonError> {
        self.cycles += 1;
        self.events.push(format!("collect:{}", self.generation));
        if self.fail_collect {
            return Err(DaemonError::collection("incomplete cycle"));
        }
        let mut snapshot = ResponseSnapshot::unsupported(format!("v{}", self.generation));
        snapshot.status.refresh_interval_ms = 500 + self.generation as u32;
        Ok(snapshot)
    }
    fn shutdown(&mut self) -> Result<(), DaemonError> {
        self.events
            .push(format!("runtime_shutdown:{}", self.generation));
        if self.fail_shutdown {
            Err(DaemonError::collection("runtime shutdown failed"))
        } else {
            Ok(())
        }
    }
}

struct FakeFactory {
    events: Events,
    next_generation: u64,
    fail_stage: bool,
    next_fail_collect: bool,
    next_fail_shutdown: bool,
}

#[derive(Clone)]
struct MutableRuntimeHandle {
    generation: u64,
    hooks: Rc<RefCell<Vec<String>>>,
    shutdowns: Rc<Cell<u64>>,
}

struct MutableRuntime {
    handle: MutableRuntimeHandle,
    fail_collect: bool,
    fail_shutdown: bool,
    cycles: u64,
}

impl Runtime for MutableRuntime {
    type Checkpoint = u64;

    fn checkpoint(&self) -> Self::Checkpoint {
        self.cycles
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        self.cycles = checkpoint;
    }

    fn collect(&mut self) -> Result<ResponseSnapshot, DaemonError> {
        self.cycles += 1;
        if self.fail_collect {
            return Err(DaemonError::collection("incomplete mutable cycle"));
        }
        let mut snapshot = ResponseSnapshot::unsupported(format!("v{}", self.handle.generation));
        snapshot.status.refresh_interval_ms = 500 + self.handle.generation as u32;
        Ok(snapshot)
    }

    fn shutdown(&mut self) -> Result<(), DaemonError> {
        self.handle
            .shutdowns
            .set(self.handle.shutdowns.get().saturating_add(1));
        self.handle.hooks.borrow_mut().clear();
        if self.fail_shutdown {
            Err(DaemonError::collection(
                "mutable shutdown failed after detaching hooks",
            ))
        } else {
            Ok(())
        }
    }
}

struct MutableFactory {
    handles: Rc<RefCell<Vec<MutableRuntimeHandle>>>,
    next_generation: u64,
    first_fail_shutdown: bool,
    next_fail_collect: bool,
}

impl RuntimeFactory for MutableFactory {
    type Runtime = MutableRuntime;

    fn stage(&mut self, _config: &RuntimeConfig) -> Result<Self::Runtime, DaemonError> {
        let generation = self.next_generation;
        self.next_generation += 1;
        let handle = MutableRuntimeHandle {
            generation,
            hooks: Rc::new(RefCell::new(vec![
                format!("generation-{generation}-ingress"),
                format!("generation-{generation}-egress"),
            ])),
            shutdowns: Rc::new(Cell::new(0)),
        };
        self.handles.borrow_mut().push(handle.clone());
        let fail_collect = self.next_fail_collect;
        self.next_fail_collect = false;
        Ok(MutableRuntime {
            handle,
            fail_collect,
            fail_shutdown: generation == 1 && self.first_fail_shutdown,
            cycles: 0,
        })
    }
}

fn mutable_daemon(
    handles: Rc<RefCell<Vec<MutableRuntimeHandle>>>,
    first_fail_shutdown: bool,
) -> ProductionCoordinator<FakeTransport, MutableFactory> {
    ProductionCoordinator::new(
        FakeTransport {
            events: Events::default(),
            fail_connect: false,
            fail_register: false,
            fail_reconnect: false,
            fail_collection_timer: false,
            fail_shutdown: false,
        },
        MutableFactory {
            handles,
            next_generation: 1,
            first_fail_shutdown,
            next_fail_collect: false,
        },
        RuntimeConfig::default(),
        Arc::new(ResponseSnapshot::unsupported("boot")),
    )
}
impl RuntimeFactory for FakeFactory {
    type Runtime = FakeRuntime;
    fn stage(&mut self, _config: &RuntimeConfig) -> Result<Self::Runtime, DaemonError> {
        self.events.push(format!("stage:{}", self.next_generation));
        if self.fail_stage {
            return Err(DaemonError::reload("stage failed"));
        }
        let runtime = FakeRuntime {
            generation: self.next_generation,
            events: self.events.clone(),
            fail_collect: self.next_fail_collect,
            fail_shutdown: self.next_fail_shutdown,
            cycles: 0,
        };
        self.next_fail_collect = false;
        self.next_fail_shutdown = false;
        self.next_generation += 1;
        Ok(runtime)
    }
}

fn daemon(events: Events) -> ProductionCoordinator<FakeTransport, FakeFactory> {
    ProductionCoordinator::new(
        FakeTransport {
            events: events.clone(),
            fail_connect: false,
            fail_register: false,
            fail_reconnect: false,
            fail_collection_timer: false,
            fail_shutdown: false,
        },
        FakeFactory {
            events,
            next_generation: 1,
            fail_stage: false,
            next_fail_collect: false,
            next_fail_shutdown: false,
        },
        RuntimeConfig::default(),
        Arc::new(ResponseSnapshot::unsupported("boot")),
    )
}

fn snapshot_content(snapshot: &Arc<ResponseSnapshot>) -> Vec<serde_json::Value> {
    let mut content = Method::FIXED
        .into_iter()
        .map(|method| snapshot.response(method).unwrap())
        .collect::<Vec<_>>();
    // Diagnostics deliberately recomputes freshness from CLOCK_MONOTONIC for
    // every response. A failed reload must preserve the underlying snapshot,
    // while this derived age may legitimately advance across two serializes.
    if let Some(collection) = content
        .last_mut()
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|value| value.get_mut("collection"))
        .and_then(serde_json::Value::as_object_mut)
    {
        collection.remove("age_ms");
    }
    content
}

#[test]
fn startup_connects_and_registers_before_stage_collect_publish_and_timer() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    assert_eq!(
        events.values(),
        [
            "connect",
            "register:9",
            "stage:1",
            "collect:1",
            "collection_timer:1000"
        ]
    );
}

#[test]
fn client_connections_refreshes_before_loading_the_latest_snapshot() {
    const IDENTITY_KEY: &str = "02:00:00:00:00:01@lan";
    let snapshots = SnapshotStore::new(Arc::new(ResponseSnapshot::unsupported("stale")));
    let mut refreshed = ResponseSnapshot::unsupported("refreshed");
    refreshed.clients.clients.push(Client {
        mac: "02:00:00:00:00:01".into(),
        identity_key: IDENTITY_KEY.into(),
        zone: "lan".into(),
        interface: "br-lan".into(),
        ips: vec!["192.0.2.10".into()],
        hostname: Some("refreshed-client".into()),
        rx_bps: 0,
        tx_bps: 0,
        last_seen: 0,
        sample_ms: None,
        rx_bytes: None,
        tx_bytes: None,
        collector_mode: "stub".into(),
        confidence: Confidence::Unsupported,
        warnings: Vec::new(),
        tcp_conns: None,
        udp_conns: None,
        udp_dns_conns: None,
        udp_other_conns: None,
    });
    let refreshed = Arc::new(refreshed);
    let callback_snapshots = snapshots.clone();
    let events = Events::default();
    let callback_events = events.clone();

    let response = client_connections_response(&snapshots, IDENTITY_KEY, move |method| {
        assert_eq!(method, Method::ClientConnections);
        callback_events.push("before_reply:client_connections");
        callback_snapshots.publish(Arc::clone(&refreshed));
        Ok(())
    })
    .unwrap();

    assert_eq!(events.values(), ["before_reply:client_connections"]);
    assert_eq!(response["client"]["identity_key"], IDENTITY_KEY);
    assert_eq!(response["client"]["hostname"], "refreshed-client");
}

#[test]
fn activation_publishes_before_timer_and_rolls_back_exact_arc_on_timer_failure() {
    let events = Events::default();
    let initial = Arc::new(ResponseSnapshot::unsupported("boot"));
    let state = CoordinatorState::new(RuntimeConfig::default(), initial.clone());
    let runtime = FakeRuntime {
        generation: 1,
        events: events.clone(),
        fail_collect: false,
        fail_shutdown: false,
        cycles: 0,
    };
    let error = activate_runtime(
        &state,
        runtime,
        |_| {
            assert_eq!(state.snapshot().status.version, "v1");
            events.push("timer_after_publish");
            Err(DaemonError::transport("timer failed"))
        },
        SignalBridge::request_for_test,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("timer failed"));
    assert!(Arc::ptr_eq(&initial, &state.snapshot()));
    assert_eq!(
        events.values(),
        ["collect:1", "timer_after_publish", "runtime_shutdown:1"]
    );
}

#[test]
fn signal_install_failure_cleans_runtime_then_transport_and_combines_cleanup_errors() {
    let events = Events::default();
    let mut runtime = FakeRuntime {
        generation: 1,
        events: events.clone(),
        fail_collect: false,
        fail_shutdown: false,
        cycles: 0,
    };
    let error = install_control_or_shutdown(
        Some(&mut runtime),
        || Err::<(), _>(DaemonError::platform("signal install failed")),
        || {
            events.push("transport_shutdown");
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("signal install failed"));
    assert_eq!(
        events.values(),
        ["runtime_shutdown:1", "transport_shutdown"]
    );

    let mut runtime = FakeRuntime {
        generation: 2,
        events: Events::default(),
        fail_collect: false,
        fail_shutdown: true,
        cycles: 0,
    };
    let error = install_control_or_shutdown(
        Some(&mut runtime),
        || Err::<(), _>(DaemonError::platform("signal install failed")),
        || Err(DaemonError::transport("transport cleanup failed")),
    )
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("signal install failed"));
    assert!(message.contains("runtime shutdown failed"));
    assert!(message.contains("transport cleanup failed"));
}

#[test]
fn startup_register_or_stage_failure_cleans_transport_in_reverse_order() {
    let events = Events::default();
    let mut coordinator = daemon(events.clone());
    coordinator.transport_mut().fail_register = true;
    assert!(coordinator.start().is_err());
    assert_eq!(
        events.values(),
        ["connect", "register:9", "transport_shutdown"]
    );

    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.factory_mut().fail_stage = true;
    assert!(daemon.start().is_err());
    assert_eq!(
        events.values(),
        ["connect", "register:9", "stage:1", "transport_shutdown"]
    );
}

#[test]
fn failed_startup_cleans_staged_runtime_and_partial_transport() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    let initial = daemon.snapshot();
    daemon.transport_mut().fail_collection_timer = true;
    assert!(daemon.start().is_err());
    assert!(Arc::ptr_eq(&initial, &daemon.snapshot()));
    assert!(events.values().ends_with(&[
        "collection_timer:1000".into(),
        "runtime_shutdown:1".into(),
        "transport_shutdown".into()
    ]));
    daemon.transport_mut().fail_collection_timer = false;
    daemon.start().unwrap();
    assert_eq!(daemon.snapshot().status.version, "v2");
}

#[test]
fn collection_tick_retains_payload_and_publishes_degraded_diagnostics_on_failure() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    let before = daemon.snapshot();
    daemon.runtime_mut().unwrap().fail_collect = true;
    assert!(daemon.on_collection_tick().is_err());
    let retained = daemon.snapshot();
    assert!(!Arc::ptr_eq(&before, &retained));
    assert_eq!(retained.status, before.status);
    let diagnostics = retained.response(Method::Diagnostics).unwrap();
    assert_eq!(diagnostics["collection"]["state"], "degraded");
    assert_eq!(diagnostics["collection"]["generation"], 1);
    assert_eq!(diagnostics["collection"]["consecutive_failures"], 1);
    assert_eq!(diagnostics["collection"]["retained"], true);
    assert_eq!(
        diagnostics["collection"]["last_error"]["code"],
        "collection_error"
    );
    assert!(!diagnostics.to_string().contains("incomplete cycle"));
    assert_eq!(
        daemon.runtime_mut().unwrap().cycles,
        1,
        "failed second cycle must roll back to the startup baseline"
    );
    daemon.runtime_mut().unwrap().fail_collect = false;
    daemon.on_collection_tick().unwrap();
    assert_eq!(daemon.snapshot().status.refresh_interval_ms, 501);
    let recovered = daemon.response(Method::Diagnostics).unwrap();
    assert_eq!(recovered["collection"]["state"], "fresh");
    assert_eq!(recovered["collection"]["generation"], 2);
    assert_eq!(recovered["collection"]["consecutive_failures"], 0);
    assert_eq!(recovered["collection"]["retained"], false);
    assert!(recovered["collection"]["last_error"].is_null());
    assert!(events
        .values()
        .ends_with(&["collect:1".into(), "collection_timer:1000".into()]));
}

#[test]
fn hot_collection_uses_one_outer_checkpoint_and_moves_the_unvalidated_snapshot() {
    let daemon = include_str!("../src/daemon.rs");
    let hot_path = daemon
        .split("pub fn collect_and_reschedule")
        .nth(1)
        .unwrap()
        .split("pub fn reconnect_and_register")
        .next()
        .unwrap();
    assert_eq!(hot_path.matches("runtime.checkpoint()").count(), 1);
    assert!(!hot_path.contains("validate_snapshot"));
    assert!(hot_path.contains("state.publish_collection_success(snapshot"));
    assert!(hot_path.contains("state.publish_collection_failure("));
    assert!(!hot_path.contains("snapshot.clone()"));

    let production = include_str!("../src/production.rs");
    let runtime_impl = production
        .split("impl Runtime for ProductionRuntime")
        .nth(1)
        .unwrap()
        .split("struct App")
        .next()
        .unwrap();
    assert!(runtime_impl.contains("self.collect_inner(ProbeMethod::Status, None)"));
    assert!(!runtime_impl.contains("ProductionRuntime::collect("));
}

#[test]
fn request_refresh_skips_serialization_while_startup_and_reload_still_validate() {
    let production = include_str!("../src/production.rs");
    let request_refresh = production
        .split("fn refresh_clients_connections(&mut self)")
        .nth(1)
        .unwrap()
        .split("fn before_reply")
        .next()
        .unwrap();
    assert_eq!(request_refresh.matches("runtime.checkpoint()").count(), 1);
    assert!(request_refresh.contains("runtime.restore(checkpoint)"));
    assert!(request_refresh.contains("self.state.publish_runtime_snapshot(snapshot)"));
    assert!(!request_refresh.contains("Method::FIXED"));
    assert!(!request_refresh.contains("snapshot.response("));

    let reload_collect = production
        .split("fn collect(&mut self, method: ProbeMethod)")
        .nth(1)
        .unwrap()
        .split("fn collect_with_external_bpf")
        .next()
        .unwrap();
    assert!(reload_collect.contains("ubus::Method::FIXED"));
    assert!(reload_collect.contains("snapshot.response(method)"));

    let external_reload_collect = production
        .split("fn collect_with_external_bpf")
        .nth(1)
        .unwrap()
        .split("fn collect_inner")
        .next()
        .unwrap();
    assert!(external_reload_collect.contains("ubus::Method::FIXED"));
    assert!(external_reload_collect.contains("snapshot.response(method)"));

    let daemon = include_str!("../src/daemon.rs");
    let startup = daemon
        .split("pub fn activate_runtime")
        .nth(1)
        .unwrap()
        .split("pub fn collect_and_reschedule")
        .next()
        .unwrap();
    assert!(startup.contains("validate_snapshot(&snapshot)"));

    let reload = daemon
        .split("pub fn reload(&mut self, config: RuntimeConfig)")
        .nth(1)
        .unwrap()
        .split("pub fn on_signal_shutdown")
        .next()
        .unwrap();
    assert!(reload.contains("validate_snapshot(&snapshot)"));
}

#[test]
fn shared_collection_path_makes_timer_failure_fatal_without_masking_collection_error() {
    let events = Events::default();
    let state = CoordinatorState::new(
        RuntimeConfig::default(),
        Arc::new(ResponseSnapshot::unsupported("boot")),
    );
    let mut runtime = FakeRuntime {
        generation: 1,
        events: events.clone(),
        fail_collect: true,
        fail_shutdown: false,
        cycles: 0,
    };
    let stop_requested = Cell::new(false);

    let error = collect_and_reschedule(
        &state,
        &mut runtime,
        |delay| {
            events.push(format!("collection_timer:{delay}"));
            Err(DaemonError::transport("timer failed"))
        },
        || stop_requested.set(true),
    )
    .unwrap_err();

    let message = error.to_string();
    assert!(message.contains("incomplete cycle"), "{message}");
    assert!(message.contains("timer failed"), "{message}");
    assert_eq!(
        state.fatal_error().as_deref(),
        message.strip_prefix("transport: ")
    );
    assert!(stop_requested.get());
    assert_eq!(
        runtime.cycles, 0,
        "failed collection must restore checkpoint"
    );
    assert_eq!(events.values(), ["collect:1", "collection_timer:1000"]);
}

#[test]
fn signal_shutdown_stops_runtime_then_transport_once() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    daemon.on_signal_shutdown().unwrap();
    daemon.on_signal_shutdown().unwrap();
    assert!(events
        .values()
        .ends_with(&["runtime_shutdown:1".into(), "transport_shutdown".into()]));
    assert_eq!(
        events
            .values()
            .iter()
            .filter(|v| *v == "transport_shutdown")
            .count(),
        1
    );
}

#[test]
fn disconnect_reconnects_after_one_second_and_reregisters_all_methods() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    daemon.on_ubus_disconnect().unwrap();
    assert_eq!(events.values().last().unwrap(), "reconnect_timer:1000");
    daemon.on_reconnect_tick().unwrap();
    assert!(events
        .values()
        .ends_with(&["reconnect".into(), "register:9".into()]));
}

#[test]
fn failed_reconnect_schedules_another_one_second_retry() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    daemon.transport_mut().fail_reconnect = true;
    assert!(daemon.on_reconnect_tick().is_err());
    assert!(events
        .values()
        .ends_with(&["reconnect".into(), "reconnect_timer:1000".into()]));
}

#[test]
fn shared_reconnect_path_makes_retry_timer_failure_fatal_and_preserves_both_errors() {
    let state = CoordinatorState::new(
        RuntimeConfig::default(),
        Arc::new(ResponseSnapshot::unsupported("boot")),
    );
    let events = Events::default();
    let stop_requested = Cell::new(false);

    let error = reconnect_and_register(
        &state,
        &mut (),
        |_| {
            events.push("reconnect");
            Err(DaemonError::transport("reconnect failed"))
        },
        |_, delay| {
            events.push(format!("reconnect_timer:{delay}"));
            Err(DaemonError::transport("retry timer failed"))
        },
        || stop_requested.set(true),
    )
    .unwrap_err();

    let message = error.to_string();
    assert!(message.contains("reconnect failed"), "{message}");
    assert!(message.contains("retry timer failed"), "{message}");
    assert_eq!(
        state.fatal_error().as_deref(),
        message.strip_prefix("transport: ")
    );
    assert!(stop_requested.get());
    assert_eq!(events.values(), ["reconnect", "reconnect_timer:1000"]);
}

#[test]
fn reload_stages_collects_then_atomically_swaps_runtime_config_and_snapshot() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    let old = daemon.snapshot();
    let mut next = RuntimeConfig::default();
    next.refresh_interval_ms = 2_000;
    daemon.reload(next.clone()).unwrap();
    assert_eq!(daemon.config(), &next);
    assert_eq!(daemon.snapshot().status.refresh_interval_ms, 502);
    assert!(!Arc::ptr_eq(&old, &daemon.snapshot()));
    assert!(events.values().ends_with(&[
        "stage:2".into(),
        "collect:2".into(),
        "collection_timer:2000".into(),
        "runtime_shutdown:1".into()
    ]));
}

#[test]
fn reload_timer_failure_cleans_candidate_and_retains_old_state() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    let old_snapshot = daemon.snapshot();
    daemon.transport_mut().fail_collection_timer = true;
    assert!(daemon
        .reload(RuntimeConfig {
            refresh_interval_ms: 2_000,
            ..RuntimeConfig::default()
        })
        .is_err());
    assert!(Arc::ptr_eq(&old_snapshot, &daemon.snapshot()));
    assert_eq!(daemon.config().refresh_interval_ms, 1_000);
    assert!(events.values().ends_with(&[
        "collection_timer:2000".into(),
        "collection_timer:1000".into(),
        "runtime_shutdown:2".into(),
    ]));
}

#[test]
fn shared_reload_abort_path_restores_old_timer_and_combines_cleanup_failures() {
    let events = Events::default();
    let state = CoordinatorState::new(
        RuntimeConfig::default(),
        Arc::new(ResponseSnapshot::unsupported("boot")),
    );
    let mut candidate = FakeRuntime {
        generation: 2,
        events: events.clone(),
        fail_collect: false,
        fail_shutdown: true,
        cycles: 0,
    };
    let stop_requested = Cell::new(false);

    let error = abort_reload_after_timer_failure(
        &state,
        &mut candidate,
        DaemonError::transport("new timer failed"),
        || {
            events.push("collection_timer:1000");
            Err(DaemonError::transport("old timer failed"))
        },
        || stop_requested.set(true),
    );

    let message = error.to_string();
    assert!(message.contains("new timer failed"), "{message}");
    assert!(message.contains("runtime shutdown failed"), "{message}");
    assert!(message.contains("old timer failed"), "{message}");
    assert_eq!(
        state.fatal_error().as_deref(),
        Some(message.trim_start_matches("reload: "))
    );
    assert!(stop_requested.get());
    assert_eq!(
        events.values(),
        ["collection_timer:1000", "runtime_shutdown:2"]
    );
}

#[test]
fn postcommit_cleanup_failure_is_fatal_but_reports_the_committed_reload() {
    let handles = Rc::new(RefCell::new(Vec::new()));
    let mut daemon = mutable_daemon(Rc::clone(&handles), true);
    daemon.start().unwrap();
    let old_snapshot = daemon.snapshot();
    let old = handles.borrow()[0].clone();
    SignalBridge::clear();
    assert!(daemon
        .reload(RuntimeConfig {
            refresh_interval_ms: 2_000,
            ..RuntimeConfig::default()
        })
        .is_ok());
    assert_eq!(daemon.config().refresh_interval_ms, 2_000);
    assert!(!Arc::ptr_eq(&old_snapshot, &daemon.snapshot()));
    assert_eq!(daemon.snapshot().status.version, "v2");
    assert_eq!(daemon.runtime_mut().unwrap().handle.generation, 2);
    assert_eq!(old.shutdowns.get(), 1);
    assert!(old.hooks.borrow().is_empty());
    assert!(daemon.fatal_error().is_some());
    assert!(SignalBridge::take_requested());
}

#[test]
fn candidate_collect_failure_preserves_old_runtime_identity_hooks_arc_and_content() {
    let handles = Rc::new(RefCell::new(Vec::new()));
    let mut daemon = mutable_daemon(Rc::clone(&handles), false);
    daemon.start().unwrap();
    let old = handles.borrow()[0].clone();
    let old_hooks = old.hooks.borrow().clone();
    let old_snapshot = daemon.snapshot();
    let old_content = snapshot_content(&old_snapshot);
    let old_config = daemon.config().clone();
    daemon.factory_mut().next_fail_collect = true;
    assert!(daemon
        .reload(RuntimeConfig {
            refresh_interval_ms: 2_000,
            ..RuntimeConfig::default()
        })
        .is_err());
    assert_eq!(daemon.config(), &old_config);
    assert!(Arc::ptr_eq(&old_snapshot, &daemon.snapshot()));
    assert_eq!(snapshot_content(&daemon.snapshot()), old_content);
    assert_eq!(daemon.runtime_mut().unwrap().handle.generation, 1);
    assert_eq!(old.shutdowns.get(), 0);
    assert_eq!(*old.hooks.borrow(), old_hooks);
    let candidate = handles.borrow()[1].clone();
    assert_eq!(candidate.shutdowns.get(), 1);
    assert!(candidate.hooks.borrow().is_empty());
}

#[test]
fn candidate_cleanup_failure_is_fatal_and_preserves_old_state() {
    let events = Events::default();
    let mut daemon = daemon(events);
    daemon.start().unwrap();
    let old_snapshot = daemon.snapshot();
    let old_config = daemon.config().clone();
    daemon.factory_mut().next_fail_collect = true;
    daemon.factory_mut().next_fail_shutdown = true;
    SignalBridge::clear();
    assert!(daemon
        .reload(RuntimeConfig {
            refresh_interval_ms: 2_000,
            ..RuntimeConfig::default()
        })
        .is_err());
    assert_eq!(daemon.config(), &old_config);
    assert!(Arc::ptr_eq(&old_snapshot, &daemon.snapshot()));
    assert!(daemon.fatal_error().is_some());
    assert!(SignalBridge::take_requested());
}

#[test]
fn failed_reload_retains_old_runtime_config_and_snapshot() {
    let events = Events::default();
    let mut daemon = daemon(events);
    daemon.start().unwrap();
    let old_snapshot = daemon.snapshot();
    let old_config = daemon.config().clone();
    daemon.factory_mut().fail_stage = true;
    assert!(daemon
        .reload(RuntimeConfig {
            refresh_interval_ms: 2_000,
            ..RuntimeConfig::default()
        })
        .is_err());
    assert_eq!(daemon.config(), &old_config);
    assert!(Arc::ptr_eq(&old_snapshot, &daemon.snapshot()));
    assert_eq!(daemon.response(Method::Status).unwrap()["version"], "v1");
}

#[test]
fn shutdown_attempts_transport_cleanup_when_runtime_shutdown_fails() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    daemon.runtime_mut().unwrap().fail_shutdown = true;
    assert!(daemon.on_signal_shutdown().is_err());
    assert!(events
        .values()
        .ends_with(&["runtime_shutdown:1".into(), "transport_shutdown".into()]));
}

#[test]
fn handlers_read_the_shared_snapshot_without_mutating_runtime() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    let before = events.values();
    let status = daemon.response(Method::Status).unwrap();
    let clients = daemon.response(Method::Clients).unwrap();
    assert_eq!(status["version"], "v1");
    assert!(clients["clients"].is_array());
    assert_eq!(events.values(), before);
    let _: &StatusResponse = &daemon.snapshot().status;
}

#[test]
fn signal_bridge_only_records_a_stop_request_for_normal_control_flow() {
    SignalBridge::clear();
    SignalBridge::request_for_test();
    assert!(SignalBridge::take_requested());
    assert!(!SignalBridge::take_requested());
}
