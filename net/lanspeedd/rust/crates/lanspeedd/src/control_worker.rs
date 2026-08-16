//! Bounded worker for platform control apply and verification.

use std::sync::mpsc::SyncSender;

use crate::{
    control::{execute_reconcile, ControlReconcileOutcome, ControlReconcileWork},
    workers::{spawn_runtime_worker, QueueError, RuntimeWorker, WorkerQueue},
};

#[derive(Clone, Debug)]
pub(crate) struct ControlWorkerTask {
    pub(crate) generation: u64,
    pub(crate) work: ControlReconcileWork,
}

#[derive(Clone, Debug)]
pub(crate) struct ControlWorkerNotice {
    pub(crate) generation: u64,
    pub(crate) outcome: ControlReconcileOutcome,
}

pub(crate) struct ControlWorker {
    worker: RuntimeWorker<ControlWorkerTask>,
}

impl ControlWorker {
    pub(crate) fn spawn(
        capacity: usize,
        notices: SyncSender<ControlWorkerNotice>,
    ) -> Result<Self, std::io::Error> {
        Self::spawn_with(capacity, notices, execute_reconcile)
    }

    fn spawn_with(
        capacity: usize,
        notices: SyncSender<ControlWorkerNotice>,
        execute: impl Fn(ControlReconcileWork) -> ControlReconcileOutcome + Send + 'static,
    ) -> Result<Self, std::io::Error> {
        let worker = spawn_runtime_worker(capacity, move |task: ControlWorkerTask| {
            let outcome = execute(task.work);
            let _ = notices.try_send(ControlWorkerNotice {
                generation: task.generation,
                outcome,
            });
        })?;
        Ok(Self { worker })
    }

    pub(crate) fn queue(&self) -> WorkerQueue<ControlWorkerTask> {
        self.worker.queue()
    }

    pub(crate) fn join(self) -> std::thread::Result<()> {
        self.worker.join()
    }
}

pub(crate) fn try_queue(
    queue: &WorkerQueue<ControlWorkerTask>,
    task: ControlWorkerTask,
) -> Result<(), QueueError> {
    queue.try_send(task)
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, time::Duration};

    use super::{try_queue, ControlWorker, ControlWorkerNotice, ControlWorkerTask};
    use crate::control::{test_reconcile_outcome, test_reconcile_work};

    #[test]
    fn worker_returns_the_exact_generation_without_blocking_the_caller() {
        let (sender, receiver) = mpsc::sync_channel::<ControlWorkerNotice>(2);
        let worker = ControlWorker::spawn_with(1, sender, |work| {
            std::thread::sleep(Duration::from_millis(20));
            test_reconcile_outcome(work.kind)
        })
        .unwrap();
        try_queue(
            &worker.queue(),
            ControlWorkerTask {
                generation: 7,
                work: test_reconcile_work(),
            },
        )
        .unwrap();
        let notice = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(notice.generation, 7);
        worker.join().unwrap();
    }
}
