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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    Full,
    Disconnected,
}

enum Work<T> {
    Task(T),
    Stop,
}

pub struct WorkerQueue<T> {
    sender: SyncSender<Work<T>>,
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
        self.sender
            .try_send(Work::Task(task))
            .map_err(|error| match error {
                TrySendError::Full(Work::Task(task)) => (QueueError::Full, task),
                TrySendError::Disconnected(Work::Task(task)) => (QueueError::Disconnected, task),
                _ => unreachable!("only tasks are sent through WorkerQueue"),
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
        Self::spawn_inner(name, capacity, None, move |task| {
            if let Some(task) = task {
                handler(task);
            }
        })
    }

    fn spawn_inner(
        name: &'static str,
        capacity: usize,
        tick_interval: Option<Duration>,
        handler: impl FnMut(Option<T>) + Send + 'static,
    ) -> Result<Self, std::io::Error> {
        let (sender, receiver) = mpsc::sync_channel(capacity.max(1));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let join = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || run_worker(receiver, worker_stop, tick_interval, handler))?;
        Ok(Self {
            queue: WorkerQueue { sender },
            stop,
            join: Some(join),
        })
    }

    pub fn queue(&self) -> WorkerQueue<T> {
        self.queue.clone()
    }

    pub fn join(mut self) -> thread::Result<()> {
        self.request_stop();
        self.join
            .take()
            .expect("worker join handle must exist")
            .join()
    }
}

impl<T> Worker<T> {
    pub fn request_stop(&self) {
        if !self.stop.swap(true, Ordering::AcqRel) {
            // Wake an idle receiver. A full channel already has work to wake it.
            let _ = self.queue.sender.try_send(Work::Stop);
        }
    }
}

impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        self.request_stop();
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
    Worker::spawn_inner("lanspeed-rate", capacity, Some(tick_interval), handler)
}

pub fn spawn_runtime_worker<T: Send + 'static>(
    capacity: usize,
    handler: impl FnMut(T) + Send + 'static,
) -> Result<RuntimeWorker<T>, std::io::Error> {
    Worker::spawn("lanspeed-runtime", capacity, handler)
}

fn run_worker<T>(
    receiver: Receiver<Work<T>>,
    stop: Arc<AtomicBool>,
    tick_interval: Option<Duration>,
    mut handler: impl FnMut(Option<T>),
) {
    while !stop.load(Ordering::Acquire) {
        let received = match tick_interval {
            Some(interval) => receiver.recv_timeout(interval),
            None => receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
        };
        if stop.load(Ordering::Acquire) {
            break;
        }
        match received {
            Ok(Work::Task(task)) => handler(Some(task)),
            Err(mpsc::RecvTimeoutError::Timeout) => handler(None),
            Ok(Work::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
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

    #[test]
    fn stop_wakes_a_ticking_worker_without_waiting_for_its_period() {
        let (started, running) = mpsc::channel();
        let worker = spawn_rate_worker_with_tick(1, Duration::from_secs(10), move |task| {
            assert_eq!(task, Some(()));
            started.send(()).unwrap();
        })
        .unwrap();
        let queue = worker.queue();
        queue.try_send(()).unwrap();
        running.recv_timeout(Duration::from_secs(1)).unwrap();
        let (joined, done) = mpsc::channel();
        thread::spawn(move || joined.send(worker.join()).unwrap());
        done.recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(queue.try_send(()), Err(QueueError::Disconnected));
    }
}
