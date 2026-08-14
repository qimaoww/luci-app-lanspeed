//! NSS FastRate worker boundary.

use std::sync::mpsc::SyncSender;

use crate::workers::{spawn_rate_worker, QueueError, RateWorker, WorkerQueue};

use super::fast_rate_wakeup::{FastRateWakeup, FastRateWakeupBook};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FastRateCommand {
    EventHint { now_ms: u64 },
    FixedTimer { now_ms: u64 },
    Poll { now_ms: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastRateWakeupNotice {
    pub observed_ms: u64,
    pub wakeup: FastRateWakeup,
}

pub(crate) struct FastRateWorker {
    worker: RateWorker<FastRateCommand>,
}

impl FastRateWorker {
    pub(crate) fn spawn(
        capacity: usize,
        notices: SyncSender<FastRateWakeupNotice>,
    ) -> Result<Self, std::io::Error> {
        let worker = spawn_rate_worker(capacity, move |command| {
            // The worker owns the debounce state, so callers never need to
            // coordinate event and fixed-timer timing through a shared lock.
            thread_command(&notices, command);
        })?;
        Ok(Self { worker })
    }

    pub(crate) fn queue(&self) -> WorkerQueue<FastRateCommand> {
        self.worker.queue()
    }

    pub(crate) fn join(self) -> std::thread::Result<()> {
        self.worker.join()
    }
}

fn thread_command(notices: &SyncSender<FastRateWakeupNotice>, command: FastRateCommand) {
    thread_local! {
        static WAKEUPS: std::cell::RefCell<FastRateWakeupBook> =
            std::cell::RefCell::new(FastRateWakeupBook::default());
    }
    let now_ms = match command {
        FastRateCommand::EventHint { now_ms } => {
            WAKEUPS.with(|book| book.borrow_mut().on_event_hint(now_ms));
            now_ms
        }
        FastRateCommand::FixedTimer { now_ms } => {
            WAKEUPS.with(|book| book.borrow_mut().on_fixed_timer());
            now_ms
        }
        FastRateCommand::Poll { now_ms } => now_ms,
    };
    let notice = WAKEUPS.with(|book| book.borrow_mut().poll(now_ms));
    if let Some(wakeup) = notice {
        let _ = notices.try_send(FastRateWakeupNotice {
            observed_ms: now_ms,
            wakeup,
        });
    }
}

pub(crate) fn try_queue(
    queue: &WorkerQueue<FastRateCommand>,
    command: FastRateCommand,
) -> Result<(), QueueError> {
    queue.try_send(command)
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::{try_queue, FastRateCommand, FastRateWorker};

    #[test]
    fn worker_debounces_events_and_keeps_fixed_timer_independent() {
        let (notices, receiver) = mpsc::sync_channel(4);
        let worker = FastRateWorker::spawn(8, notices).unwrap();
        let queue = worker.queue();
        try_queue(&queue, FastRateCommand::EventHint { now_ms: 100 }).unwrap();
        try_queue(&queue, FastRateCommand::EventHint { now_ms: 105 }).unwrap();
        try_queue(&queue, FastRateCommand::Poll { now_ms: 119 }).unwrap();
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        try_queue(&queue, FastRateCommand::Poll { now_ms: 120 }).unwrap();
        let notice = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(notice.observed_ms, 120);
        assert!(notice.wakeup.event_hint);
        assert!(!notice.wakeup.fixed_timer);

        try_queue(&queue, FastRateCommand::FixedTimer { now_ms: 1_000 }).unwrap();
        let notice = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(notice.observed_ms, 1_000);
        assert!(!notice.wakeup.event_hint);
        assert!(notice.wakeup.fixed_timer);
        worker.join().unwrap();
    }
}
