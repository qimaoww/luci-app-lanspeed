use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
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

pub struct Daemon<T: Transport, F: RuntimeFactory> {
    transport: T,
    factory: F,
    config: RuntimeConfig,
    runtime: Option<F::Runtime>,
    snapshots: SnapshotStore,
    maintenance_errors: Vec<DaemonError>,
    started: bool,
    stopped: bool,
}

impl<T: Transport, F: RuntimeFactory> Daemon<T, F> {
    pub fn new(
        transport: T,
        factory: F,
        config: RuntimeConfig,
        initial: Arc<ResponseSnapshot>,
    ) -> Self {
        Self {
            transport,
            factory,
            config,
            runtime: None,
            snapshots: SnapshotStore::new(initial),
            maintenance_errors: Vec::new(),
            started: false,
            stopped: false,
        }
    }

    pub fn start(&mut self) -> Result<(), DaemonError> {
        if self.started {
            return Ok(());
        }
        let mut runtime = self.factory.stage(&self.config)?;
        let startup = (|| {
            self.transport.connect()?;
            self.transport.register(&Method::ALL)?;
            let snapshot = runtime.collect()?;
            validate_snapshot(&snapshot)?;
            self.transport
                .schedule_collection(self.config.refresh_interval_ms)?;
            Ok(snapshot)
        })();
        let snapshot = match startup {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let _ = runtime.shutdown();
                let _ = self.transport.shutdown();
                return Err(error);
            }
        };
        self.snapshots.publish(Arc::new(snapshot));
        self.runtime = Some(runtime);
        self.started = true;
        Ok(())
    }

    pub fn on_collection_tick(&mut self) -> Result<(), DaemonError> {
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| DaemonError::collection("runtime is not started"))?;
        let checkpoint = runtime.checkpoint();
        let result = runtime.collect().and_then(|snapshot| {
            validate_snapshot(&snapshot)?;
            Ok(snapshot)
        });
        match &result {
            Ok(snapshot) => self.snapshots.publish(Arc::new(snapshot.clone())),
            Err(_) => runtime.restore(checkpoint),
        }
        let schedule = self
            .transport
            .schedule_collection(self.config.refresh_interval_ms);
        result.and(schedule)
    }

    pub fn on_ubus_disconnect(&mut self) -> Result<(), DaemonError> {
        self.transport.schedule_reconnect(UBUS_RECONNECT_DELAY_MS)
    }

    pub fn on_reconnect_tick(&mut self) -> Result<(), DaemonError> {
        if let Err(error) = self.transport.reconnect() {
            let _ = self.transport.schedule_reconnect(UBUS_RECONNECT_DELAY_MS);
            return Err(error);
        }
        if let Err(error) = self.transport.register(&Method::ALL) {
            let _ = self.transport.schedule_reconnect(UBUS_RECONNECT_DELAY_MS);
            return Err(error);
        }
        Ok(())
    }

    pub fn reload(&mut self, config: RuntimeConfig) -> Result<(), DaemonError> {
        let mut candidate = self.factory.stage(&config)?;
        let snapshot = match candidate.collect() {
            Ok(snapshot) => {
                if let Err(error) = validate_snapshot(&snapshot) {
                    let _ = candidate.shutdown();
                    return Err(error);
                }
                snapshot
            }
            Err(error) => {
                let _ = candidate.shutdown();
                return Err(error);
            }
        };
        if let Err(error) = self
            .transport
            .schedule_collection(config.refresh_interval_ms)
        {
            let _ = candidate.shutdown();
            return Err(error);
        }
        let old = self.runtime.replace(candidate);
        self.config = config;
        self.snapshots.publish(Arc::new(snapshot));
        if let Some(mut old) = old {
            if let Err(error) = old.shutdown() {
                self.maintenance_errors.push(error);
            }
        }
        Ok(())
    }

    pub fn on_signal_shutdown(&mut self) -> Result<(), DaemonError> {
        if self.stopped {
            return Ok(());
        }
        let runtime_error = self
            .runtime
            .as_mut()
            .and_then(|runtime| runtime.shutdown().err());
        let transport_error = self.transport.shutdown().err();
        self.stopped = true;
        runtime_error.or(transport_error).map_or(Ok(()), Err)
    }

    pub fn response(&self, method: Method) -> Result<serde_json::Value, DaemonError> {
        self.snapshots.load().response(method)
    }
    pub fn snapshot(&self) -> Arc<ResponseSnapshot> {
        self.snapshots.load()
    }
    pub fn snapshot_store(&self) -> SnapshotStore {
        self.snapshots.clone()
    }
    pub const fn config(&self) -> &RuntimeConfig {
        &self.config
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
    pub fn maintenance_errors(&self) -> &[DaemonError] {
        &self.maintenance_errors
    }
}

fn validate_snapshot(snapshot: &ResponseSnapshot) -> Result<(), DaemonError> {
    for method in Method::ALL {
        snapshot.response(method)?;
    }
    Ok(())
}

impl<T: Transport, F: RuntimeFactory> Drop for Daemon<T, F> {
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
