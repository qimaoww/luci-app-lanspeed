use crate::{raw, Error, Result};
use std::cell::{Cell, RefCell, UnsafeCell};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy)]
struct UloopOps {
    init: unsafe fn() -> libc::c_int,
    run: unsafe fn() -> libc::c_int,
    stop: unsafe fn(),
    done: unsafe fn(),
}

unsafe fn real_init() -> libc::c_int {
    unsafe { raw::uloop_init() }
}

unsafe fn real_run() -> libc::c_int {
    unsafe { raw::uloop_run_timeout(-1) }
}

unsafe fn real_stop() {
    unsafe { raw::uloop_cancelled = true };
}

unsafe fn real_done() {
    unsafe { raw::uloop_done() };
}

const REAL_ULOOP_OPS: UloopOps = UloopOps {
    init: real_init,
    run: real_run,
    stop: real_stop,
    done: real_done,
};

static ULOOP_ACTIVE: AtomicBool = AtomicBool::new(false);

thread_local! {
    static TIMER_REGISTRY: RefCell<HashMap<usize, std::rc::Weak<TimerInner>>> =
        RefCell::new(HashMap::new());
    static SIGNAL_REGISTRY: RefCell<HashMap<usize, std::rc::Weak<SignalInner>>> =
        RefCell::new(HashMap::new());
}

pub struct UloopGuard {
    ops: UloopOps,
    stopped: bool,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl UloopGuard {
    pub fn init() -> Result<Self> {
        Self::init_with(REAL_ULOOP_OPS)
    }

    fn init_with(ops: UloopOps) -> Result<Self> {
        if ULOOP_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::InvalidData("uloop is already initialized"));
        }
        let result = unsafe { (ops.init)() };
        if result != 0 {
            ULOOP_ACTIVE.store(false, Ordering::Release);
            return Err(Error::Platform {
                operation: "uloop_init",
                code: result,
            });
        }
        Ok(Self {
            ops,
            stopped: false,
            _not_send_or_sync: PhantomData,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        let result = unsafe { (self.ops.run)() };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::Platform {
                operation: "uloop_run_timeout",
                code: result,
            })
        }
    }

    pub fn stop(&mut self) {
        if !self.stopped {
            unsafe { (self.ops.stop)() };
            self.stopped = true;
        }
    }

    pub fn request_stop() {
        unsafe { (REAL_ULOOP_OPS.stop)() };
    }
}

impl Drop for UloopGuard {
    fn drop(&mut self) {
        unsafe { (self.ops.done)() };
        ULOOP_ACTIVE.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy)]
struct TimerOps {
    set: unsafe extern "C" fn(*mut raw::uloop_timeout, libc::c_int) -> libc::c_int,
    cancel: unsafe extern "C" fn(*mut raw::uloop_timeout) -> libc::c_int,
}

const REAL_TIMER_OPS: TimerOps = TimerOps {
    set: raw::uloop_timeout_set,
    cancel: raw::uloop_timeout_cancel,
};

#[repr(C)]
pub struct Timer {
    inner: Rc<TimerInner>,
}

#[repr(C)]
struct TimerInner {
    raw: UnsafeCell<raw::uloop_timeout>,
    callback: RefCell<Option<Box<dyn FnMut()>>>,
    callback_panicked: Cell<bool>,
    ops: TimerOps,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl Timer {
    pub fn new(callback: impl FnMut() + 'static) -> Self {
        Self::new_with(callback, REAL_TIMER_OPS)
    }

    fn new_with(callback: impl FnMut() + 'static, ops: TimerOps) -> Self {
        let mut raw = raw::uloop_timeout::default();
        raw.cb = Some(timer_trampoline);
        let inner = Rc::new(TimerInner {
            raw: UnsafeCell::new(raw),
            callback: RefCell::new(Some(Box::new(callback))),
            callback_panicked: Cell::new(false),
            ops,
            _not_send_or_sync: PhantomData,
        });
        TIMER_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .insert(inner.raw.get() as usize, Rc::downgrade(&inner));
        });
        Self { inner }
    }

    pub fn schedule(&self, milliseconds: u32) -> Result<()> {
        let milliseconds = libc::c_int::try_from(milliseconds)
            .map_err(|_| Error::InvalidData("timer delay exceeds c_int"))?;
        let result = unsafe { (self.inner.ops.set)(self.inner.raw.get(), milliseconds) };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::Platform {
                operation: "uloop_timeout_set",
                code: result,
            })
        }
    }

    pub fn cancel(&self) -> Result<()> {
        let raw = unsafe { &mut *self.inner.raw.get() };
        if !raw.pending {
            return Ok(());
        }
        let result = unsafe { (self.inner.ops.cancel)(raw) };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::Platform {
                operation: "uloop_timeout_cancel",
                code: result,
            })
        }
    }

    pub fn callback_panicked(&self) -> bool {
        self.inner.callback_panicked.get()
    }

    #[cfg(test)]
    fn raw_ptr(&self) -> *mut raw::uloop_timeout {
        self.inner.raw.get()
    }

    #[cfg(test)]
    fn invoke_for_test(&self) {
        unsafe { Self::invoke_raw_for_test(self.raw_ptr()) };
    }

    #[cfg(test)]
    unsafe fn invoke_raw_for_test(pointer: *mut raw::uloop_timeout) {
        unsafe { timer_trampoline(pointer) };
    }

    #[cfg(test)]
    fn downgrade_for_test(&self) -> std::rc::Weak<TimerInner> {
        Rc::downgrade(&self.inner)
    }

    #[cfg(test)]
    fn from_inner_for_test(inner: Rc<TimerInner>) -> Self {
        Self { inner }
    }
}

unsafe extern "C" fn timer_trampoline(timeout: *mut raw::uloop_timeout) {
    if timeout.is_null() {
        return;
    }
    // The registry is populated from the original `Rc`, so upgrading its Weak
    // pointer preserves provenance and keeps the timer alive during user code.
    let Some(inner) = TIMER_REGISTRY.with(|registry| {
        registry
            .borrow()
            .get(&(timeout as usize))
            .and_then(std::rc::Weak::upgrade)
    }) else {
        return;
    };
    let Some(mut callback) = inner.callback.borrow_mut().take() else {
        return;
    };
    if catch_unwind(AssertUnwindSafe(|| callback())).is_err() {
        inner.callback_panicked.set(true);
    }
    *inner.callback.borrow_mut() = Some(callback);
}

impl Drop for TimerInner {
    fn drop(&mut self) {
        let _ = TIMER_REGISTRY.try_with(|registry| {
            registry.borrow_mut().remove(&(self.raw.get() as usize));
        });
        let raw = self.raw.get_mut();
        if raw.pending {
            let _ = unsafe { (self.ops.cancel)(raw) };
        }
    }
}

pub struct Signal {
    inner: Rc<SignalInner>,
}

struct SignalInner {
    raw: UnsafeCell<raw::uloop_signal>,
    callback: RefCell<Option<Box<dyn FnMut()>>>,
    registered: Cell<bool>,
    callback_panicked: Cell<bool>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl Signal {
    pub fn new(signo: libc::c_int, callback: impl FnMut() + 'static) -> Result<Self> {
        let mut raw = raw::uloop_signal::default();
        raw.cb = Some(signal_trampoline);
        raw.signo = signo;
        let inner = Rc::new(SignalInner {
            raw: UnsafeCell::new(raw),
            callback: RefCell::new(Some(Box::new(callback))),
            registered: Cell::new(false),
            callback_panicked: Cell::new(false),
            _not_send_or_sync: PhantomData,
        });
        SIGNAL_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .insert(inner.raw.get() as usize, Rc::downgrade(&inner));
        });
        let result = unsafe { raw::uloop_signal_add(inner.raw.get()) };
        if result != 0 {
            return Err(Error::Platform {
                operation: "uloop_signal_add",
                code: result,
            });
        }
        inner.registered.set(true);
        Ok(Self { inner })
    }

    pub fn callback_panicked(&self) -> bool {
        self.inner.callback_panicked.get()
    }
}

unsafe extern "C" fn signal_trampoline(signal: *mut raw::uloop_signal) {
    if signal.is_null() {
        return;
    }
    let Some(inner) = SIGNAL_REGISTRY.with(|registry| {
        registry
            .borrow()
            .get(&(signal as usize))
            .and_then(std::rc::Weak::upgrade)
    }) else {
        return;
    };
    let Some(mut callback) = inner.callback.borrow_mut().take() else {
        return;
    };
    if catch_unwind(AssertUnwindSafe(|| callback())).is_err() {
        inner.callback_panicked.set(true);
    }
    *inner.callback.borrow_mut() = Some(callback);
}

impl Drop for SignalInner {
    fn drop(&mut self) {
        let _ = SIGNAL_REGISTRY
            .try_with(|registry| registry.borrow_mut().remove(&(self.raw.get() as usize)));
        if self.registered.get() {
            let _ = unsafe { raw::uloop_signal_delete(self.raw.get()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    static SET_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CANCEL_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe fn init() -> libc::c_int {
        EVENTS.lock().unwrap().push("init");
        0
    }

    unsafe fn run() -> libc::c_int {
        EVENTS.lock().unwrap().push("run");
        0
    }

    unsafe fn stop() {
        EVENTS.lock().unwrap().push("stop");
    }

    unsafe fn done() {
        EVENTS.lock().unwrap().push("done");
    }

    unsafe extern "C" fn set_timer(
        timeout: *mut crate::raw::uloop_timeout,
        _milliseconds: libc::c_int,
    ) -> libc::c_int {
        SET_CALLS.fetch_add(1, Ordering::SeqCst);
        unsafe { (*timeout).pending = true };
        0
    }

    unsafe extern "C" fn cancel_timer(timeout: *mut crate::raw::uloop_timeout) -> libc::c_int {
        CANCEL_CALLS.fetch_add(1, Ordering::SeqCst);
        unsafe { (*timeout).pending = false };
        0
    }

    #[test]
    fn guard_runs_stops_and_finishes_global_loop_in_order() {
        EVENTS.lock().unwrap().clear();
        {
            let mut guard = UloopGuard::init_with(UloopOps {
                init,
                run,
                stop,
                done,
            })
            .unwrap();
            guard.run().unwrap();
            guard.stop();
        }
        assert_eq!(&*EVENTS.lock().unwrap(), &["init", "run", "stop", "done"]);
    }

    #[test]
    fn timer_self_drop_is_deferred_until_callback_returns() {
        SET_CALLS.store(0, Ordering::SeqCst);
        CANCEL_CALLS.store(0, Ordering::SeqCst);
        let completed = Rc::new(Cell::new(false));
        let slot = Rc::new(RefCell::new(None));
        let callback_slot = Rc::clone(&slot);
        let callback_completed = Rc::clone(&completed);
        let timer = Timer::new_with(
            move || {
                drop(callback_slot.borrow_mut().take().unwrap());
                assert_eq!(CANCEL_CALLS.load(Ordering::SeqCst), 0);
                callback_completed.set(true);
            },
            TimerOps {
                set: set_timer,
                cancel: cancel_timer,
            },
        );
        timer.schedule(25).unwrap();
        let raw = timer.raw_ptr();
        *slot.borrow_mut() = Some(timer);

        unsafe { Timer::invoke_raw_for_test(raw) };

        assert!(slot.borrow().is_none());
        assert!(completed.get());
        assert_eq!(CANCEL_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn timer_callback_can_reentrantly_schedule_and_cancel_without_double_cancel() {
        SET_CALLS.store(0, Ordering::SeqCst);
        CANCEL_CALLS.store(0, Ordering::SeqCst);
        let weak = Rc::new(RefCell::new(None));
        let callback_weak = Rc::clone(&weak);
        let timer = Timer::new_with(
            move || {
                let timer = callback_weak
                    .borrow()
                    .as_ref()
                    .and_then(std::rc::Weak::upgrade)
                    .map(Timer::from_inner_for_test)
                    .unwrap();
                timer.schedule(10).unwrap();
                timer.cancel().unwrap();
            },
            TimerOps {
                set: set_timer,
                cancel: cancel_timer,
            },
        );
        *weak.borrow_mut() = Some(timer.downgrade_for_test());

        timer.invoke_for_test();
        drop(timer);

        assert_eq!(SET_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(CANCEL_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn timer_callback_panic_is_caught_at_ffi_boundary() {
        let timer = Timer::new_with(
            || panic!("callback failure"),
            TimerOps {
                set: set_timer,
                cancel: cancel_timer,
            },
        );

        timer.invoke_for_test();

        assert!(timer.callback_panicked());
    }

    #[test]
    fn sigterm_wakes_a_blocking_real_uloop_and_returns_to_normal_cleanup() {
        const CHILD: &str = "LANSPEED_ULOOP_SIGNAL_CHILD";
        const READY: &str = "LANSPEED_ULOOP_SIGNAL_READY";
        if std::env::var_os(CHILD).is_some() {
            let mut guard = UloopGuard::init().unwrap();
            let _signal = Signal::new(libc::SIGTERM, UloopGuard::request_stop).unwrap();
            std::fs::write(std::env::var_os(READY).unwrap(), b"ready").unwrap();
            guard.run().unwrap();
            return;
        }

        let ready =
            std::env::temp_dir().join(format!("lanspeed-uloop-signal-{}", std::process::id()));
        let _ = std::fs::remove_file(&ready);
        let executable = std::env::var_os("LANSPEED_TEST_BINARY")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::current_exe().unwrap());
        let mut command = if let Some(loader) = std::env::var_os("LANSPEED_TEST_MUSL_LOADER") {
            let mut command = std::process::Command::new(loader);
            command
                .arg("--library-path")
                .arg(std::env::var_os("LANSPEED_TEST_LIBRARY_PATH").unwrap());
            command.arg(executable);
            command
        } else {
            std::process::Command::new(executable)
        };
        let mut child = command
            .args([
                "--exact",
                "uloop::tests::sigterm_wakes_a_blocking_real_uloop_and_returns_to_normal_cleanup",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env(READY, &ready)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !ready.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists(), "child did not enter blocking uloop");
        assert_eq!(
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
            0
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGKILL) };
                panic!("SIGTERM did not wake blocking uloop");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let _ = std::fs::remove_file(ready);
        assert!(status.success(), "signal child exited with {status}");
    }
}
