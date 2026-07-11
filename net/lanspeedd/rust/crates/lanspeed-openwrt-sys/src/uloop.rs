use crate::{raw, Error, Result};
use std::marker::{PhantomData, PhantomPinned};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
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
    raw: raw::uloop_timeout,
    callback: Box<dyn FnMut()>,
    callback_panicked: bool,
    ops: TimerOps,
    _not_send_or_sync: PhantomData<Rc<()>>,
    _pinned: PhantomPinned,
}

impl Timer {
    pub fn new(callback: impl FnMut() + 'static) -> Pin<Box<Self>> {
        Self::new_with(callback, REAL_TIMER_OPS)
    }

    fn new_with(callback: impl FnMut() + 'static, ops: TimerOps) -> Pin<Box<Self>> {
        let mut raw = raw::uloop_timeout::default();
        raw.cb = Some(timer_trampoline);
        Box::pin(Self {
            raw,
            callback: Box::new(callback),
            callback_panicked: false,
            ops,
            _not_send_or_sync: PhantomData,
            _pinned: PhantomPinned,
        })
    }

    pub fn schedule(self: Pin<&mut Self>, milliseconds: u32) -> Result<()> {
        let milliseconds = libc::c_int::try_from(milliseconds)
            .map_err(|_| Error::InvalidData("timer delay exceeds c_int"))?;
        let this = unsafe { self.get_unchecked_mut() };
        let result = unsafe { (this.ops.set)(&mut this.raw, milliseconds) };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::Platform {
                operation: "uloop_timeout_set",
                code: result,
            })
        }
    }

    pub fn cancel(self: Pin<&mut Self>) -> Result<()> {
        let this = unsafe { self.get_unchecked_mut() };
        if !this.raw.pending {
            return Ok(());
        }
        let result = unsafe { (this.ops.cancel)(&mut this.raw) };
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
        self.callback_panicked
    }

    #[cfg(test)]
    fn raw_ptr(self: Pin<&Self>) -> *const raw::uloop_timeout {
        &self.get_ref().raw
    }

    #[cfg(test)]
    fn invoke_for_test(self: Pin<&mut Self>) {
        let pointer = unsafe { &mut self.get_unchecked_mut().raw as *mut raw::uloop_timeout };
        unsafe { timer_trampoline(pointer) };
    }
}

unsafe extern "C" fn timer_trampoline(timeout: *mut raw::uloop_timeout) {
    if timeout.is_null() {
        return;
    }
    let timer = unsafe { &mut *timeout.cast::<Timer>() };
    if catch_unwind(AssertUnwindSafe(|| (timer.callback)())).is_err() {
        timer.callback_panicked = true;
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if self.raw.pending {
            let _ = unsafe { (self.ops.cancel)(&mut self.raw) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
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

    struct DropProbe(Rc<Cell<usize>>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn pinned_timer_keeps_callback_alive_and_cancels_before_drop() {
        CANCEL_CALLS.store(0, Ordering::SeqCst);
        let calls = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));
        let callback_calls = Rc::clone(&calls);
        let probe = DropProbe(Rc::clone(&drops));
        let mut timer = Timer::new_with(
            move || {
                let _keep_alive = &probe;
                callback_calls.set(callback_calls.get() + 1);
            },
            TimerOps {
                set: set_timer,
                cancel: cancel_timer,
            },
        );

        let before = Timer::raw_ptr(Pin::as_ref(&timer));
        timer.as_mut().schedule(25).unwrap();
        Timer::invoke_for_test(Pin::as_mut(&mut timer));
        let after = Timer::raw_ptr(Pin::as_ref(&timer));

        assert_eq!(before, after);
        assert_eq!(calls.get(), 1);
        assert_eq!(drops.get(), 0);
        drop(timer);
        assert_eq!(CANCEL_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn timer_callback_panic_is_caught_at_ffi_boundary() {
        let mut timer = Timer::new_with(
            || panic!("callback failure"),
            TimerOps {
                set: set_timer,
                cancel: cancel_timer,
            },
        );

        Timer::invoke_for_test(Pin::as_mut(&mut timer));

        assert!(timer.callback_panicked());
    }
}
