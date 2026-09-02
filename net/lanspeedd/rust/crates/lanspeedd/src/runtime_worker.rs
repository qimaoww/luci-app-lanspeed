//! Dedicated owner thread for slow runtime collection.
//!
//! A runtime cannot be borrowed by the uloop thread while it is collecting.
//! The task therefore transfers ownership into this worker and every queue or
//! notice failure returns or shuts down that exact runtime.

use std::sync::mpsc::{Receiver, SyncSender};

use crate::{
    daemon::{Runtime, RuntimeCollectionSignals},
    error::DaemonError,
    state::ResponseSnapshot,
    workers::{spawn_runtime_worker, QueueError, RuntimeWorker},
};

struct RuntimeCollectionTask<R> {
    runtime: R,
    configured_interval_ms: u32,
}

pub(crate) struct RuntimeCollectionNotice<R> {
    pub(crate) runtime: R,
    pub(crate) result: Result<ResponseSnapshot, DaemonError>,
    pub(crate) collection_interval_ms: u32,
    pub(crate) signals: RuntimeCollectionSignals,
}

pub(crate) struct RuntimeCollectionWorker<R> {
    worker: RuntimeWorker<RuntimeCollectionTask<R>>,
}

impl<R> RuntimeCollectionWorker<R>
where
    R: Runtime + Send + 'static,
{
    pub(crate) fn spawn(
        capacity: usize,
        notices: SyncSender<RuntimeCollectionNotice<R>>,
    ) -> Result<Self, std::io::Error> {
        let worker = spawn_runtime_worker(capacity, move |mut task: RuntimeCollectionTask<R>| {
            let signals = task.runtime.collection_signals();
            let checkpoint = task.runtime.checkpoint();
            let result = task.runtime.collect();
            if result.is_err() {
                task.runtime.restore(checkpoint);
            } else {
                task.runtime.collection_committed();
            }
            let collection_interval_ms = task
                .runtime
                .collection_interval_ms(task.configured_interval_ms);
            let notice = RuntimeCollectionNotice {
                runtime: task.runtime,
                result,
                collection_interval_ms,
                signals,
            };
            if let Err(error) = notices.send(notice) {
                let mut notice = error.0;
                let _ = notice.runtime.shutdown();
            }
        })?;
        Ok(Self { worker })
    }

    pub(crate) fn try_collect(
        &self,
        runtime: R,
        configured_interval_ms: u32,
    ) -> Result<(), (QueueError, R)> {
        self.worker
            .queue()
            .try_send_recover(RuntimeCollectionTask {
                runtime,
                configured_interval_ms,
            })
            .map_err(|(error, task)| (error, task.runtime))
    }

    pub(crate) fn join(self) -> std::thread::Result<()> {
        self.worker.join()
    }
}

pub(crate) fn notice_channel<R>(
    capacity: usize,
) -> (
    SyncSender<RuntimeCollectionNotice<R>>,
    Receiver<RuntimeCollectionNotice<R>>,
) {
    std::sync::mpsc::sync_channel(capacity.max(1))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        time::Duration,
    };

    use super::{notice_channel, RuntimeCollectionWorker};
    use crate::{
        daemon::{Runtime, RuntimeCollectionSignals},
        error::DaemonError,
        state::ResponseSnapshot,
        workers::QueueError,
    };

    #[derive(Debug)]
    struct TestRuntime {
        generation: u64,
        fail: bool,
        started: Option<mpsc::Sender<()>>,
        gate: Option<mpsc::Receiver<()>>,
        stopped: Arc<AtomicBool>,
    }

    impl TestRuntime {
        fn new(generation: u64) -> Self {
            Self {
                generation,
                fail: false,
                started: None,
                gate: None,
                stopped: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl Runtime for TestRuntime {
        type Checkpoint = u64;

        fn checkpoint(&self) -> Self::Checkpoint {
            self.generation
        }

        fn restore(&mut self, checkpoint: Self::Checkpoint) {
            self.generation = checkpoint;
        }

        fn collection_signals(&mut self) -> RuntimeCollectionSignals {
            RuntimeCollectionSignals {
                has_bpf: true,
                process_activity_changed: self.generation == 4,
                attach_mode_mismatch: false,
            }
        }

        fn collect(&mut self) -> Result<ResponseSnapshot, DaemonError> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            if let Some(gate) = self.gate.take() {
                let _ = gate.recv_timeout(Duration::from_secs(1));
            }
            self.generation = self.generation.saturating_add(1);
            if self.fail {
                Err(DaemonError::collection("injected failure"))
            } else {
                Ok(ResponseSnapshot::unsupported("runtime worker test"))
            }
        }

        fn collection_interval_ms(&self, configured_ms: u32) -> u32 {
            configured_ms.saturating_add(self.generation as u32)
        }

        fn shutdown(&mut self) -> Result<(), DaemonError> {
            self.stopped.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[test]
    fn collection_returns_runtime_ownership_and_computed_interval() {
        let (sender, receiver) = notice_channel(1);
        let worker = RuntimeCollectionWorker::spawn(1, sender).unwrap();
        worker.try_collect(TestRuntime::new(4), 1_000).unwrap();

        let notice = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(notice.result.is_ok());
        assert_eq!(notice.runtime.generation, 5);
        assert_eq!(notice.collection_interval_ms, 1_005);
        assert_eq!(
            notice.signals,
            RuntimeCollectionSignals {
                has_bpf: true,
                process_activity_changed: true,
                attach_mode_mismatch: false,
            }
        );
        worker.join().unwrap();
    }

    #[test]
    fn failed_collection_restores_the_runtime_checkpoint() {
        let (sender, receiver) = notice_channel(1);
        let worker = RuntimeCollectionWorker::spawn(1, sender).unwrap();
        let mut runtime = TestRuntime::new(7);
        runtime.fail = true;
        worker.try_collect(runtime, 1_000).unwrap();

        let notice = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(notice.result.is_err());
        assert_eq!(notice.runtime.generation, 7);
        assert_eq!(notice.collection_interval_ms, 1_007);
        worker.join().unwrap();
    }

    #[test]
    fn full_queue_returns_the_unqueued_runtime_to_the_caller() {
        let (notices, _receiver) = notice_channel(2);
        let worker = RuntimeCollectionWorker::spawn(1, notices).unwrap();
        let (started, started_rx) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let mut running = TestRuntime::new(1);
        running.started = Some(started);
        running.gate = Some(gate);
        worker.try_collect(running, 1_000).unwrap();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.try_collect(TestRuntime::new(2), 1_000).unwrap();

        let (error, runtime) = worker
            .try_collect(TestRuntime::new(3), 1_000)
            .expect_err("third runtime must be returned when the queue is full");
        assert_eq!(error, QueueError::Full);
        assert_eq!(runtime.generation, 3);
        release.send(()).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn disconnected_notice_receiver_shuts_down_the_owned_runtime() {
        let (sender, receiver) = notice_channel(1);
        drop(receiver);
        let stopped = Arc::new(AtomicBool::new(false));
        let (started, started_rx) = mpsc::channel();
        let runtime = TestRuntime {
            generation: 1,
            fail: false,
            started: Some(started),
            gate: None,
            stopped: Arc::clone(&stopped),
        };
        let worker = RuntimeCollectionWorker::spawn(1, sender).unwrap();
        worker.try_collect(runtime, 1_000).unwrap();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        assert!(stopped.load(Ordering::Acquire));
    }
}
