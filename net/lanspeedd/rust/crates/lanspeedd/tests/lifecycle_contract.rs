use std::{cell::RefCell, rc::Rc, sync::Arc};

use lanspeedd::{
    config::RuntimeConfig,
    daemon::{Daemon, Runtime, RuntimeFactory, SignalBridge, Transport},
    error::DaemonError,
    model::StatusResponse,
    state::ResponseSnapshot,
    ubus::Method,
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
    fail_reconnect: bool,
    fail_collection_timer: bool,
    fail_shutdown: bool,
}
impl Transport for FakeTransport {
    fn connect(&mut self) -> Result<(), DaemonError> {
        self.events.push("connect");
        Ok(())
    }
    fn register(&mut self, methods: &[Method]) -> Result<(), DaemonError> {
        self.events.push(format!("register:{}", methods.len()));
        Ok(())
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
            fail_collect: false,
            fail_shutdown: false,
            cycles: 0,
        };
        self.next_generation += 1;
        Ok(runtime)
    }
}

fn daemon(events: Events) -> Daemon<FakeTransport, FakeFactory> {
    Daemon::new(
        FakeTransport {
            events: events.clone(),
            fail_reconnect: false,
            fail_collection_timer: false,
            fail_shutdown: false,
        },
        FakeFactory {
            events,
            next_generation: 1,
            fail_stage: false,
        },
        RuntimeConfig::default(),
        Arc::new(ResponseSnapshot::unsupported("boot")),
    )
}

#[test]
fn startup_stages_before_connect_register_collect_and_timer() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    assert_eq!(
        events.values(),
        [
            "stage:1",
            "connect",
            "register:7",
            "collect:1",
            "collection_timer:1000"
        ]
    );
}

#[test]
fn failed_startup_cleans_staged_runtime_and_partial_transport() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.transport_mut().fail_collection_timer = true;
    assert!(daemon.start().is_err());
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
fn collection_tick_publishes_only_a_complete_snapshot_and_reschedules() {
    let events = Events::default();
    let mut daemon = daemon(events.clone());
    daemon.start().unwrap();
    let before = daemon.snapshot();
    daemon.runtime_mut().unwrap().fail_collect = true;
    assert!(daemon.on_collection_tick().is_err());
    assert!(Arc::ptr_eq(&before, &daemon.snapshot()));
    assert_eq!(
        daemon.runtime_mut().unwrap().cycles,
        1,
        "failed second cycle must roll back to the startup baseline"
    );
    daemon.runtime_mut().unwrap().fail_collect = false;
    daemon.on_collection_tick().unwrap();
    assert_eq!(daemon.snapshot().status.refresh_interval_ms, 501);
    assert!(events
        .values()
        .ends_with(&["collect:1".into(), "collection_timer:1000".into()]));
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
        .ends_with(&["reconnect".into(), "register:7".into()]));
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
    assert!(events
        .values()
        .ends_with(&["collection_timer:2000".into(), "runtime_shutdown:2".into()]));
}

#[test]
fn committed_reload_is_successful_even_when_old_runtime_cleanup_fails() {
    let events = Events::default();
    let mut daemon = daemon(events);
    daemon.start().unwrap();
    daemon.runtime_mut().unwrap().fail_shutdown = true;
    daemon
        .reload(RuntimeConfig {
            refresh_interval_ms: 2_000,
            ..RuntimeConfig::default()
        })
        .unwrap();
    assert_eq!(daemon.snapshot().status.version, "v2");
    assert_eq!(daemon.maintenance_errors().len(), 1);
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
