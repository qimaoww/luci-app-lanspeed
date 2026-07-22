use crate::{Error, Result};
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
    panic::{catch_unwind, AssertUnwindSafe},
    rc::{Rc, Weak},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};

static ACTIVE: AtomicBool = AtomicBool::new(false);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGNAL_PENDING: AtomicU64 = AtomicU64::new(0);
static CALLBACK_PANICKED: AtomicBool = AtomicBool::new(false);

thread_local! {
    static TIMERS: RefCell<Vec<Weak<TimerInner>>> = const { RefCell::new(Vec::new()) };
    static SIGNALS: RefCell<Vec<Weak<SignalInner>>> = const { RefCell::new(Vec::new()) };
}

pub struct UloopGuard {
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl UloopGuard {
    pub fn init() -> Result<Self> {
        if ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::InvalidData("event loop is already initialized"));
        }
        STOP_REQUESTED.store(false, Ordering::Release);
        SIGNAL_PENDING.store(0, Ordering::Release);
        CALLBACK_PANICKED.store(false, Ordering::Release);
        Ok(Self {
            _not_send_or_sync: PhantomData,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        while !STOP_REQUESTED.load(Ordering::Acquire) {
            dispatch_pending_signals();
            callback_result()?;
            fire_due_timers();
            callback_result()?;
            if STOP_REQUESTED.load(Ordering::Acquire) {
                break;
            }
            let timeout = next_timeout_ms();
            crate::pure_ubus::poll_connections(timeout)?;
        }
        callback_result()
    }

    pub fn stop(&mut self) {
        Self::request_stop();
    }

    pub fn request_stop() {
        STOP_REQUESTED.store(true, Ordering::Release);
    }
}

fn callback_result() -> Result<()> {
    if CALLBACK_PANICKED.load(Ordering::Acquire) {
        Err(Error::InvalidData("event loop callback panicked"))
    } else {
        Ok(())
    }
}

impl Drop for UloopGuard {
    fn drop(&mut self) {
        STOP_REQUESTED.store(false, Ordering::Release);
        ACTIVE.store(false, Ordering::Release);
    }
}

pub struct Timer {
    inner: Rc<TimerInner>,
}

struct TimerInner {
    deadline: Cell<Option<Instant>>,
    callback: RefCell<Option<Box<dyn FnMut()>>>,
    callback_panicked: Cell<bool>,
}

impl Timer {
    pub fn new(callback: impl FnMut() + 'static) -> Self {
        let inner = Rc::new(TimerInner {
            deadline: Cell::new(None),
            callback: RefCell::new(Some(Box::new(callback))),
            callback_panicked: Cell::new(false),
        });
        TIMERS.with(|timers| timers.borrow_mut().push(Rc::downgrade(&inner)));
        Self { inner }
    }

    pub fn schedule(&self, milliseconds: u32) -> Result<()> {
        self.inner.deadline.set(Some(
            Instant::now() + Duration::from_millis(u64::from(milliseconds)),
        ));
        Ok(())
    }

    pub fn cancel(&self) -> Result<()> {
        self.inner.deadline.set(None);
        Ok(())
    }

    pub fn callback_panicked(&self) -> bool {
        self.inner.callback_panicked.get()
    }
}

fn live_timers() -> Vec<Rc<TimerInner>> {
    TIMERS.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.retain(|timer| timer.strong_count() > 0);
        registry.iter().filter_map(Weak::upgrade).collect()
    })
}

fn fire_due_timers() {
    let now = Instant::now();
    let due = live_timers()
        .into_iter()
        .filter(|timer| timer.deadline.get().is_some_and(|deadline| deadline <= now))
        .collect::<Vec<_>>();
    for timer in due {
        timer.deadline.set(None);
        let Some(mut callback) = timer.callback.borrow_mut().take() else {
            continue;
        };
        if catch_unwind(AssertUnwindSafe(|| callback())).is_err() {
            timer.callback_panicked.set(true);
            CALLBACK_PANICKED.store(true, Ordering::Release);
            UloopGuard::request_stop();
        }
        *timer.callback.borrow_mut() = Some(callback);
    }
}

fn next_timeout_ms() -> libc::c_int {
    let now = Instant::now();
    let next = live_timers()
        .into_iter()
        .filter_map(|timer| timer.deadline.get())
        .min();
    match next {
        Some(deadline) if deadline <= now => 0,
        Some(deadline) => deadline.duration_since(now).as_millis().min(1_000) as libc::c_int,
        None => 1_000,
    }
}

pub struct Signal {
    inner: Rc<SignalInner>,
    previous: libc::sigaction,
}

struct SignalInner {
    signo: libc::c_int,
    callback: RefCell<Option<Box<dyn FnMut()>>>,
    callback_panicked: Cell<bool>,
}

unsafe extern "C" fn signal_handler(signo: libc::c_int) {
    if (0..64).contains(&signo) {
        SIGNAL_PENDING.fetch_or(1u64 << signo, Ordering::Release);
    }
}

impl Signal {
    pub fn new(signo: libc::c_int, callback: impl FnMut() + 'static) -> Result<Self> {
        if !(0..64).contains(&signo) {
            return Err(Error::InvalidData("signal number is out of range"));
        }
        let inner = Rc::new(SignalInner {
            signo,
            callback: RefCell::new(Some(Box::new(callback))),
            callback_panicked: Cell::new(false),
        });
        let mut action = unsafe { core::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = signal_handler as *const () as usize;
        action.sa_flags = 0;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        let mut previous = unsafe { core::mem::zeroed::<libc::sigaction>() };
        if unsafe { libc::sigaction(signo, &action, &mut previous) } != 0 {
            return Err(Error::Platform {
                operation: "sigaction",
                code: std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            });
        }
        SIGNALS.with(|signals| signals.borrow_mut().push(Rc::downgrade(&inner)));
        Ok(Self { inner, previous })
    }

    pub fn callback_panicked(&self) -> bool {
        self.inner.callback_panicked.get()
    }
}

fn dispatch_pending_signals() {
    let pending = SIGNAL_PENDING.swap(0, Ordering::AcqRel);
    if pending == 0 {
        return;
    }
    let signals = SIGNALS.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.retain(|signal| signal.strong_count() > 0);
        registry
            .iter()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>()
    });
    for signal in signals {
        if pending & (1u64 << signal.signo) == 0 {
            continue;
        }
        let Some(mut callback) = signal.callback.borrow_mut().take() else {
            continue;
        };
        if catch_unwind(AssertUnwindSafe(|| callback())).is_err() {
            signal.callback_panicked.set(true);
            CALLBACK_PANICKED.store(true, Ordering::Release);
            UloopGuard::request_stop();
        }
        *signal.callback.borrow_mut() = Some(callback);
    }
}

impl Drop for Signal {
    fn drop(&mut self) {
        unsafe { libc::sigaction(self.inner.signo, &self.previous, core::ptr::null_mut()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn zero_delay_timer_runs_and_stops_loop() {
        let _lock = test_lock();
        let fired = Rc::new(Cell::new(false));
        let seen = Rc::clone(&fired);
        let timer = Timer::new(move || {
            seen.set(true);
            UloopGuard::request_stop();
        });
        timer.schedule(0).unwrap();
        let mut guard = UloopGuard::init().unwrap();
        guard.run().unwrap();
        assert!(fired.get());
    }

    #[test]
    fn canceled_timer_stays_idle_and_can_be_rearmed() {
        let _lock = test_lock();
        let fired = Rc::new(Cell::new(0));
        let seen = Rc::clone(&fired);
        let timer = Timer::new(move || {
            seen.set(seen.get() + 1);
            UloopGuard::request_stop();
        });
        timer.schedule(0).unwrap();
        timer.cancel().unwrap();
        let stopper = Timer::new(UloopGuard::request_stop);
        stopper.schedule(1).unwrap();

        let mut first_loop = UloopGuard::init().unwrap();
        first_loop.run().unwrap();
        assert_eq!(fired.get(), 0);
        drop(first_loop);

        timer.schedule(0).unwrap();
        let mut second_loop = UloopGuard::init().unwrap();
        second_loop.run().unwrap();
        assert_eq!(fired.get(), 1);
    }

    #[test]
    fn timer_panic_is_returned_as_event_loop_error_and_state_resets() {
        let _lock = test_lock();
        let timer = Timer::new(|| panic!("timer failure"));
        timer.schedule(0).unwrap();
        let mut guard = UloopGuard::init().unwrap();
        assert_eq!(
            guard.run().unwrap_err(),
            Error::InvalidData("event loop callback panicked")
        );
        assert!(timer.callback_panicked());
        drop(guard);

        let recovered = Rc::new(Cell::new(false));
        let seen = Rc::clone(&recovered);
        let recovery_timer = Timer::new(move || {
            seen.set(true);
            UloopGuard::request_stop();
        });
        recovery_timer.schedule(0).unwrap();
        let mut recovered_guard = UloopGuard::init().unwrap();
        recovered_guard.run().unwrap();
        assert!(recovered.get());
    }

    #[test]
    fn sigusr1_callback_is_dispatched() {
        let _lock = test_lock();
        let fired = Rc::new(Cell::new(false));
        let seen = Rc::clone(&fired);
        let _signal = Signal::new(libc::SIGUSR1, move || {
            seen.set(true);
            UloopGuard::request_stop();
        })
        .unwrap();
        let mut guard = UloopGuard::init().unwrap();
        assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
        guard.run().unwrap();
        assert!(fired.get());
    }

    #[test]
    fn signal_panic_is_returned_as_event_loop_error() {
        let _lock = test_lock();
        let signal = Signal::new(libc::SIGUSR1, || panic!("signal failure")).unwrap();
        let mut guard = UloopGuard::init().unwrap();
        assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
        assert_eq!(
            guard.run().unwrap_err(),
            Error::InvalidData("event loop callback panicked")
        );
        assert!(signal.callback_panicked());
    }
}
