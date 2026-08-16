//! Bounded worker primitives for the daemon's fast and slow planes.
//!
//! The queue is deliberately small and non-blocking at the caller. A full
//! queue is observable as backpressure; it never makes the uloop/UBus caller
//! wait behind a slow runtime task.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const STOP_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    Full,
    Disconnected,
}

pub struct WorkerQueue<T> {
    sender: SyncSender<T>,
}

impl<T> Clone for WorkerQueue<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<T> WorkerQueue<T> {
    pub fn try_send(&self, task: T) -> Result<(), QueueError> {
        self.try_send_recover(task).map_err(|(error, _)| error)
    }

    pub fn try_send_recover(&self, task: T) -> Result<(), (QueueError, T)> {
        self.sender.try_send(task).map_err(|error| match error {
            TrySendError::Full(task) => (QueueError::Full, task),
            TrySendError::Disconnected(task) => (QueueError::Disconnected, task),
        })
    }
}

pub struct Worker<T> {
    queue: WorkerQueue<T>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl<T: Send + 'static> Worker<T> {
    pub fn spawn(
        name: &'static str,
        capacity: usize,
        mut handler: impl FnMut(T) + Send + 'static,
    ) -> Result<Self, std::io::Error> {
        Self::spawn_with_tick(name, capacity, STOP_POLL_INTERVAL, move |task| {
            if let Some(task) = task {
                handler(task);
            }
        })
    }

    fn spawn_with_tick(
        name: &'static str,
        capacity: usize,
        tick_interval: Duration,
        handler: impl FnMut(Option<T>) + Send + 'static,
    ) -> Result<Self, std::io::Error> {
        let (sender, receiver) = mpsc::sync_channel(capacity.max(1));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let join = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || run_worker_with_tick(receiver, worker_stop, tick_interval, handler))?;
        Ok(Self {
            queue: WorkerQueue { sender },
            stop,
            join: Some(join),
        })
    }

    pub fn queue(&self) -> WorkerQueue<T> {
        self.queue.clone()
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    pub fn join(mut self) -> thread::Result<()> {
        self.request_stop();
        self.join
            .take()
            .expect("worker join handle must exist")
            .join()
    }
}

impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub type RateWorker<T> = Worker<T>;
pub type RuntimeWorker<T> = Worker<T>;

pub fn spawn_rate_worker<T: Send + 'static>(
    capacity: usize,
    handler: impl FnMut(T) + Send + 'static,
) -> Result<RateWorker<T>, std::io::Error> {
    Worker::spawn("lanspeed-rate", capacity, handler)
}

pub fn spawn_rate_worker_with_tick<T: Send + 'static>(
    capacity: usize,
    tick_interval: Duration,
    handler: impl FnMut(Option<T>) + Send + 'static,
) -> Result<RateWorker<T>, std::io::Error> {
    Worker::spawn_with_tick("lanspeed-rate", capacity, tick_interval, handler)
}

pub fn spawn_runtime_worker<T: Send + 'static>(
    capacity: usize,
    handler: impl FnMut(T) + Send + 'static,
) -> Result<RuntimeWorker<T>, std::io::Error> {
    Worker::spawn("lanspeed-runtime", capacity, handler)
}

fn run_worker_with_tick<T>(
    receiver: Receiver<T>,
    stop: Arc<AtomicBool>,
    tick_interval: Duration,
    mut handler: impl FnMut(Option<T>),
) {
    while !stop.load(Ordering::Acquire) {
        match receiver.recv_timeout(tick_interval) {
            Ok(task) => handler(Some(task)),
            Err(mpsc::RecvTimeoutError::Timeout) => handler(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{mpsc, Arc, Mutex},
        thread,
        time::Duration,
    };

    use super::{spawn_rate_worker, spawn_rate_worker_with_tick, spawn_runtime_worker, QueueError};

    #[test]
    fn bounded_queue_reports_full_without_blocking_the_caller() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let worker_gate = Arc::clone(&gate);
        let worker = spawn_rate_worker(1, move |task: u8| {
            if task == 1 {
                let (lock, ready) = &*worker_gate;
                *lock.lock().unwrap() = true;
                ready.notify_one();
                thread::sleep(Duration::from_millis(40));
            }
        })
        .unwrap();
        let queue = worker.queue();
        queue.try_send(1).unwrap();
        let (lock, ready) = &*gate;
        let mut started = lock.lock().unwrap();
        while !*started {
            started = ready.wait(started).unwrap();
        }
        drop(started);
        queue.try_send(2).unwrap();
        assert_eq!(queue.try_send(3), Err(QueueError::Full));
        worker.join().unwrap();
    }

    #[test]
    fn rate_and_runtime_workers_run_on_distinct_named_threads() {
        let (sender, receiver) = mpsc::channel();
        let rate_sender = sender.clone();
        let rate = spawn_rate_worker(2, move |()| {
            rate_sender
                .send(("rate", thread::current().name().unwrap_or("").to_owned()))
                .unwrap();
        })
        .unwrap();
        let runtime_sender = sender;
        let runtime = spawn_runtime_worker(2, move |()| {
            runtime_sender
                .send(("runtime", thread::current().name().unwrap_or("").to_owned()))
                .unwrap();
        })
        .unwrap();
        rate.queue().try_send(()).unwrap();
        runtime.queue().try_send(()).unwrap();
        let first = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        let second = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_ne!(first.1, second.1);
        assert!(matches!(first.0, "rate" | "runtime"));
        assert!(matches!(second.0, "rate" | "runtime"));
        rate.join().unwrap();
        runtime.join().unwrap();
    }

    #[test]
    fn ticking_rate_worker_runs_idle_work_without_a_command() {
        let (sender, receiver) = mpsc::channel();
        let worker =
            spawn_rate_worker_with_tick(1, Duration::from_millis(5), move |task: Option<()>| {
                if task.is_none() {
                    let _ = sender.send(());
                }
            })
            .unwrap();
        receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }
}
