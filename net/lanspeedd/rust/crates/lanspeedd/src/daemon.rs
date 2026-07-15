use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use crate::{
    config::RuntimeConfig,
    error::DaemonError,
    state::{ResponseSnapshot, SnapshotStore},
    ubus::Method,
};

pub const UBUS_RECONNECT_DELAY_MS: u32 = 1_000;
static SIGNAL_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

pub struct SignalBridge;

impl SignalBridge {
    pub fn install() -> Result<(), DaemonError> {
        unsafe extern "C" fn request_stop(_signal: libc::c_int) {
            SIGNAL_STOP_REQUESTED.store(true, Ordering::Release);
        }
        let mut action = unsafe { core::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = request_stop as *const () as usize;
        action.sa_flags = 0;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if unsafe { libc::sigaction(signal, &action, core::ptr::null_mut()) } != 0 {
                return Err(DaemonError::platform(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn take_requested() -> bool {
        SIGNAL_STOP_REQUESTED.swap(false, Ordering::AcqRel)
    }
    pub fn clear() {
        SIGNAL_STOP_REQUESTED.store(false, Ordering::Release);
    }
    #[doc(hidden)]
    pub fn request_for_test() {
        SIGNAL_STOP_REQUESTED.store(true, Ordering::Release);
    }
}

#[cfg(feature = "openwrt")]
pub struct UloopSignalBridge {
    _sigint: lanspeed_openwrt_sys::Signal,
    _sigterm: lanspeed_openwrt_sys::Signal,
}

#[cfg(feature = "openwrt")]
impl UloopSignalBridge {
    pub fn install() -> Result<Self, DaemonError> {
        let sigint = lanspeed_openwrt_sys::Signal::new(
            libc::SIGINT,
            lanspeed_openwrt_sys::UloopGuard::request_stop,
        )
        .map_err(|error| DaemonError::platform(error.to_string()))?;
        let sigterm = lanspeed_openwrt_sys::Signal::new(
            libc::SIGTERM,
            lanspeed_openwrt_sys::UloopGuard::request_stop,
        )
        .map_err(|error| DaemonError::platform(error.to_string()))?;
        Ok(Self {
            _sigint: sigint,
            _sigterm: sigterm,
        })
    }
}

pub trait Transport {
    fn connect(&mut self) -> Result<(), DaemonError>;
    fn register(&mut self, methods: &[Method]) -> Result<(), DaemonError>;
    fn schedule_collection(&mut self, delay_ms: u32) -> Result<(), DaemonError>;
    fn schedule_reconnect(&mut self, delay_ms: u32) -> Result<(), DaemonError>;
    fn reconnect(&mut self) -> Result<(), DaemonError>;
    fn shutdown(&mut self) -> Result<(), DaemonError>;
}

pub trait Runtime {
    type Checkpoint;
    fn checkpoint(&self) -> Self::Checkpoint;
    fn restore(&mut self, checkpoint: Self::Checkpoint);
    fn collect(&mut self) -> Result<ResponseSnapshot, DaemonError>;
    fn shutdown(&mut self) -> Result<(), DaemonError>;
}

pub trait RuntimeFactory {
    type Runtime: Runtime;
    fn stage(&mut self, config: &RuntimeConfig) -> Result<Self::Runtime, DaemonError>;
}

pub struct CoordinatorState {
    config: RuntimeConfig,
    snapshots: SnapshotStore,
    fatal_error: RefCell<Option<String>>,
}

impl CoordinatorState {
    pub fn new(config: RuntimeConfig, initial: Arc<ResponseSnapshot>) -> Self {
        Self {
            config,
            snapshots: SnapshotStore::new(initial),
            fatal_error: RefCell::new(None),
        }
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    pub fn snapshot(&self) -> Arc<ResponseSnapshot> {
        self.snapshots.load()
    }

    pub fn snapshot_store(&self) -> SnapshotStore {
        self.snapshots.clone()
    }

    pub fn publish(&self, snapshot: Arc<ResponseSnapshot>) {
        self.snapshots.publish(snapshot);
    }

    pub fn commit(&mut self, config: RuntimeConfig, snapshot: Arc<ResponseSnapshot>) {
        self.config = config;
        self.snapshots.publish(snapshot);
    }

    pub fn fatal_error(&self) -> Option<String> {
        self.fatal_error.borrow().clone()
    }

    pub fn fatal_cell(&self) -> &RefCell<Option<String>> {
        &self.fatal_error
    }

    fn record_fatal(&self, message: String) {
        *self.fatal_error.borrow_mut() = Some(message);
    }
}

pub fn abort_reload_candidate<R: Runtime>(
    state: &CoordinatorState,
    candidate: &mut R,
    primary: DaemonError,
    request_stop: impl FnOnce(),
) -> DaemonError {
    match candidate.shutdown() {
        Ok(()) => primary,
        Err(cleanup) => {
            let message = format!("candidate cleanup: {primary}; cleanup failed: {cleanup}");
            state.record_fatal(message.clone());
            request_stop();
            DaemonError::reload(message)
        }
    }
}

pub fn abort_reload_after_timer_failure<R: Runtime>(
    state: &CoordinatorState,
    candidate: &mut R,
    primary: DaemonError,
    restore_timer: impl FnOnce() -> Result<(), DaemonError>,
    request_stop: impl FnOnce(),
) -> DaemonError {
    let timer_rollback = restore_timer().err();
    let candidate_cleanup = candidate.shutdown().err();
    if candidate_cleanup.is_none() && timer_rollback.is_none() {
        return primary;
    }

    let mut message = primary.to_string();
    if let Some(error) = candidate_cleanup {
        message.push_str(&format!("; candidate cleanup failed: {error}"));
    }
    if let Some(error) = timer_rollback {
        message.push_str(&format!("; timer rollback failed: {error}"));
    }
    state.record_fatal(message.clone());
    request_stop();
    DaemonError::reload(message)
}

pub fn activate_runtime<R: Runtime>(
    state: &CoordinatorState,
    mut runtime: R,
    schedule_collection: impl FnOnce(u32) -> Result<(), DaemonError>,
    request_stop: impl FnOnce(),
) -> Result<R, DaemonError> {
    let startup = runtime.collect().and_then(|snapshot| {
        validate_snapshot(&snapshot)?;
        Ok(snapshot)
    });
    match startup {
        Ok(snapshot) => {
            let previous = state.snapshot();
            state.publish(Arc::new(snapshot));
            if let Err(error) = schedule_collection(state.config().refresh_interval_ms) {
                state.publish(previous);
                return match runtime.shutdown() {
                    Ok(()) => Err(error),
                    Err(cleanup) => {
                        let message =
                            format!("startup cleanup: {error}; cleanup failed: {cleanup}");
                        state.record_fatal(message.clone());
                        request_stop();
                        Err(DaemonError::reload(message))
                    }
                };
            }
            Ok(runtime)
        }
        Err(error) => match runtime.shutdown() {
            Ok(()) => Err(error),
            Err(cleanup) => {
                let message = format!("startup cleanup: {error}; cleanup failed: {cleanup}");
                state.record_fatal(message.clone());
                request_stop();
                Err(DaemonError::reload(message))
            }
        },
    }
}

pub fn collect_and_reschedule<R: Runtime>(
    state: &CoordinatorState,
    runtime: &mut R,
    schedule_collection: impl FnOnce(u32) -> Result<(), DaemonError>,
    request_stop: impl FnOnce(),
) -> Result<(), DaemonError> {
    let checkpoint = runtime.checkpoint();
    let result = runtime.collect().and_then(|snapshot| {
        validate_snapshot(&snapshot)?;
        Ok(snapshot)
    });
    match &result {
        Ok(snapshot) => state.publish(Arc::new(snapshot.clone())),
        Err(_) => runtime.restore(checkpoint),
    }
    if let Err(schedule) = schedule_collection(state.config().refresh_interval_ms) {
        let message = match result {
            Ok(_) => format!("collection timer failed: {schedule}"),
            Err(collection) => {
                format!("{collection}; collection timer failed: {schedule}")
            }
        };
        state.record_fatal(message.clone());
        request_stop();
        return Err(DaemonError::transport(message));
    }
    result.map(|_| ())
}

pub fn reconnect_and_register<C>(
    state: &CoordinatorState,
    context: &mut C,
    reconnect_and_register: impl FnOnce(&mut C) -> Result<(), DaemonError>,
    schedule_retry: impl FnOnce(&mut C, u32) -> Result<(), DaemonError>,
    request_stop: impl FnOnce(),
) -> Result<(), DaemonError> {
    if let Err(error) = reconnect_and_register(context) {
        if let Err(schedule) = schedule_retry(context, UBUS_RECONNECT_DELAY_MS) {
            let message = format!("{error}; reconnect timer failed: {schedule}");
            state.record_fatal(message.clone());
            request_stop();
            return Err(DaemonError::transport(message));
        }
        return Err(error);
    }
    Ok(())
}

pub fn shutdown_runtime<R: Runtime>(
    runtime: Option<&mut R>,
    shutdown_transport: impl FnOnce() -> Result<(), DaemonError>,
) -> Result<(), DaemonError> {
    let runtime_error = runtime.and_then(|runtime| runtime.shutdown().err());
    let transport_error = shutdown_transport().err();
    match (runtime_error, transport_error) {
        (None, None) => Ok(()),
        (Some(error), None) | (None, Some(error)) => Err(error),
        (Some(runtime), Some(transport)) => Err(DaemonError::platform(format!(
            "{runtime}; transport cleanup failed: {transport}"
        ))),
    }
}

pub fn install_control_or_shutdown<R: Runtime, C>(
    runtime: Option<&mut R>,
    install: impl FnOnce() -> Result<C, DaemonError>,
    shutdown_transport: impl FnOnce() -> Result<(), DaemonError>,
) -> Result<C, DaemonError> {
    match install() {
        Ok(control) => Ok(control),
        Err(error) => match shutdown_runtime(runtime, shutdown_transport) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(DaemonError::platform(format!(
                "{error}; startup cleanup failed: {cleanup}"
            ))),
        },
    }
}

pub fn commit_reload<R: Runtime>(
    state: &mut CoordinatorState,
    runtime: &mut Option<R>,
    candidate: R,
    config: RuntimeConfig,
    snapshot: ResponseSnapshot,
    request_stop: impl FnOnce(),
) {
    let mut old = runtime
        .take()
        .expect("runtime checked before reload staging");
    *runtime = Some(candidate);
    state.commit(config, Arc::new(snapshot));
    if let Err(cleanup) = old.shutdown() {
        let message = format!("reload committed; postcommit old runtime cleanup failed: {cleanup}");
        state.record_fatal(message.clone());
        request_stop();
    }
}

pub struct ProductionCoordinator<T: Transport, F: RuntimeFactory> {
    transport: T,
    factory: F,
    state: CoordinatorState,
    runtime: Option<F::Runtime>,
    started: bool,
    stopped: bool,
}

impl<T: Transport, F: RuntimeFactory> ProductionCoordinator<T, F> {
    pub fn new(
        transport: T,
        factory: F,
        config: RuntimeConfig,
        initial: Arc<ResponseSnapshot>,
    ) -> Self {
        Self {
            transport,
            factory,
            state: CoordinatorState::new(config, initial),
            runtime: None,
            started: false,
            stopped: false,
        }
    }

    pub fn start(&mut self) -> Result<(), DaemonError> {
        if self.started {
            return Ok(());
        }
        self.transport.connect()?;
        if let Err(error) = self.transport.register(&Method::ALL) {
            let _ = self.transport.shutdown();
            return Err(error);
        }
        let mut runtime = match self.factory.stage(self.state.config()) {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = self.transport.shutdown();
                return Err(error);
            }
        };
        runtime = match activate_runtime(
            &self.state,
            runtime,
            |delay| self.transport.schedule_collection(delay),
            SignalBridge::request_for_test,
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                if let Err(cleanup) = self.transport.shutdown() {
                    let message = format!("startup cleanup: {error}; cleanup failed: {cleanup}");
                    self.state.record_fatal(message.clone());
                    SignalBridge::request_for_test();
                    return Err(DaemonError::reload(message));
                }
                return Err(error);
            }
        };
        self.runtime = Some(runtime);
        self.started = true;
        Ok(())
    }

    pub fn on_collection_tick(&mut self) -> Result<(), DaemonError> {
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| DaemonError::collection("runtime is not started"))?;
        collect_and_reschedule(
            &self.state,
            runtime,
            |delay| self.transport.schedule_collection(delay),
            SignalBridge::request_for_test,
        )
    }

    pub fn on_ubus_disconnect(&mut self) -> Result<(), DaemonError> {
        self.transport.schedule_reconnect(UBUS_RECONNECT_DELAY_MS)
    }

    pub fn on_reconnect_tick(&mut self) -> Result<(), DaemonError> {
        reconnect_and_register(
            &self.state,
            &mut self.transport,
            |transport| {
                transport.reconnect()?;
                transport.register(&Method::ALL)
            },
            |transport, delay| transport.schedule_reconnect(delay),
            SignalBridge::request_for_test,
        )
    }

    pub fn reload(&mut self, config: RuntimeConfig) -> Result<(), DaemonError> {
        if self.runtime.is_none() {
            return Err(DaemonError::reload("runtime is not started"));
        }
        let mut candidate = self.factory.stage(&config)?;
        let snapshot = match candidate.collect() {
            Ok(snapshot) => {
                if let Err(error) = validate_snapshot(&snapshot) {
                    return Err(abort_reload_candidate(
                        &self.state,
                        &mut candidate,
                        error,
                        SignalBridge::request_for_test,
                    ));
                }
                snapshot
            }
            Err(error) => {
                return Err(abort_reload_candidate(
                    &self.state,
                    &mut candidate,
                    error,
                    SignalBridge::request_for_test,
                ));
            }
        };
        if let Err(error) = self
            .transport
            .schedule_collection(config.refresh_interval_ms)
        {
            let old_interval = self.state.config().refresh_interval_ms;
            return Err(abort_reload_after_timer_failure(
                &self.state,
                &mut candidate,
                error,
                || self.transport.schedule_collection(old_interval),
                SignalBridge::request_for_test,
            ));
        }
        commit_reload(
            &mut self.state,
            &mut self.runtime,
            candidate,
            config,
            snapshot,
            SignalBridge::request_for_test,
        );
        Ok(())
    }

    pub fn on_signal_shutdown(&mut self) -> Result<(), DaemonError> {
        if self.stopped {
            return Ok(());
        }
        let result = shutdown_runtime(self.runtime.as_mut(), || self.transport.shutdown());
        self.stopped = true;
        result
    }

    pub fn response(&self, method: Method) -> Result<serde_json::Value, DaemonError> {
        self.state.snapshot().response(method)
    }
    pub fn snapshot(&self) -> Arc<ResponseSnapshot> {
        self.state.snapshot()
    }
    pub fn snapshot_store(&self) -> SnapshotStore {
        self.state.snapshot_store()
    }
    pub fn config(&self) -> &RuntimeConfig {
        self.state.config()
    }
    pub fn runtime_mut(&mut self) -> Option<&mut F::Runtime> {
        self.runtime.as_mut()
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    pub fn factory_mut(&mut self) -> &mut F {
        &mut self.factory
    }
    pub fn fatal_error(&self) -> Option<String> {
        self.state.fatal_error()
    }
}

fn validate_snapshot(snapshot: &ResponseSnapshot) -> Result<(), DaemonError> {
    for method in Method::FIXED {
        snapshot.response(method)?;
    }
    Ok(())
}

impl<T: Transport, F: RuntimeFactory> Drop for ProductionCoordinator<T, F> {
    fn drop(&mut self) {
        if !self.stopped {
            if let Some(runtime) = self.runtime.as_mut() {
                let _ = runtime.shutdown();
            }
            let _ = self.transport.shutdown();
            self.stopped = true;
        }
    }
}
