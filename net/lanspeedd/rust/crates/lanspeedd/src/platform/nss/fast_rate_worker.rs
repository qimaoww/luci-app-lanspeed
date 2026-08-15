//! NSS FastRate worker boundary.

use std::sync::mpsc::SyncSender;

use crate::workers::{spawn_rate_worker, QueueError, RateWorker, WorkerQueue};

use super::{
    fast_n_runtime::FastNSnapshot,
    fast_rate_shadow::FastRateShadow,
    fast_rate_store::{FastRateSample, FastRateTelemetry},
    fast_rate_wakeup::{FastRateWakeup, FastRateWakeupBook},
    fast_s_runtime::FastSSnapshot,
};

#[derive(Clone, Debug)]
pub(crate) enum FastRateCommand {
    EventHint { now_ms: u64 },
    FixedTimer { now_ms: u64 },
    Poll { now_ms: u64 },
    Sample(FastRateSampleInput),
}

#[derive(Clone, Debug)]
pub(crate) struct FastRateSampleInput {
    pub base_generation: u64,
    pub fast_n: FastNSnapshot,
    pub fast_s: FastSSnapshot,
    pub n_read_begin_ms: u64,
    pub n_read_end_ms: u64,
    pub s_read_begin_ms: u64,
    pub s_read_end_ms: u64,
    pub edge_bps: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FastRateWakeupNotice {
    pub base_generation: u64,
    pub observed_ms: u64,
    pub wakeup: FastRateWakeup,
    pub sample: Option<FastRateSample>,
    pub telemetry: FastRateTelemetry,
    pub client_shadow_entries: usize,
    pub client_shadow_invalid_windows: u64,
    pub sample_attempted: bool,
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
    thread_local! {
        static SHADOW: std::cell::RefCell<FastRateShadow> =
            std::cell::RefCell::new(FastRateShadow::new());
    }
    let (
        base_generation,
        now_ms,
        sample,
        telemetry,
        client_shadow_entries,
        client_shadow_invalid_windows,
        sample_attempted,
    ) = match command {
        FastRateCommand::EventHint { now_ms } => {
            WAKEUPS.with(|book| book.borrow_mut().on_event_hint(now_ms));
            (0, now_ms, None, FastRateTelemetry::default(), 0, 0, false)
        }
        FastRateCommand::FixedTimer { now_ms } => {
            WAKEUPS.with(|book| book.borrow_mut().on_fixed_timer());
            (0, now_ms, None, FastRateTelemetry::default(), 0, 0, false)
        }
        FastRateCommand::Poll { now_ms } => {
            (0, now_ms, None, FastRateTelemetry::default(), 0, 0, false)
        }
        FastRateCommand::Sample(input) => {
            let now_ms = input
                .n_read_end_ms
                .max(input.s_read_end_ms)
                .max(input.fast_n.sample_ms)
                .max(input.fast_s.sample_ms);
            SHADOW.with(|shadow| {
                shadow.borrow_mut().observe(
                    Some(&input.fast_n),
                    Some(&input.fast_s),
                    input.n_read_begin_ms,
                    input.n_read_end_ms,
                    input.s_read_begin_ms,
                    input.s_read_end_ms,
                    input.edge_bps,
                );
                let shadow = shadow.borrow();
                (
                    input.base_generation,
                    now_ms,
                    shadow.latest(),
                    shadow.telemetry(),
                    shadow.client_count(),
                    shadow.client_invalid_windows(),
                    true,
                )
            })
        }
    };
    let notice = WAKEUPS.with(|book| book.borrow_mut().poll(now_ms));
    if let Some(wakeup) = notice.or_else(|| {
        sample_attempted.then_some(FastRateWakeup {
            event_hint: false,
            fixed_timer: false,
        })
    }) {
        let _ = notices.try_send(FastRateWakeupNotice {
            base_generation,
            observed_ms: now_ms,
            wakeup,
            sample,
            telemetry,
            client_shadow_entries,
            client_shadow_invalid_windows,
            sample_attempted,
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

    use super::{try_queue, FastRateCommand, FastRateSampleInput, FastRateWorker};
    use crate::platform::nss::{fast_n_runtime::FastNSnapshot, fast_s_runtime::FastSSnapshot};

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
        assert!(notice.sample.is_none());

        try_queue(&queue, FastRateCommand::FixedTimer { now_ms: 1_000 }).unwrap();
        let notice = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(notice.observed_ms, 1_000);
        assert!(!notice.wakeup.event_hint);
        assert!(notice.wakeup.fixed_timer);
        assert!(notice.sample.is_none());
        worker.join().unwrap();
    }

    #[test]
    fn worker_publishes_only_a_completed_same_window_sample() {
        let (notices, receiver) = mpsc::sync_channel(4);
        let worker = FastRateWorker::spawn(8, notices).unwrap();
        let queue = worker.queue();
        let input = |n_bytes, s_bytes, sample_ms| FastRateSampleInput {
            fast_n: FastNSnapshot {
                sample_ms,
                valid_entries: 1,
                reset_generation: 1,
                bytes: n_bytes,
                packets: n_bytes / 10,
                ..FastNSnapshot::default()
            },
            base_generation: 1,
            fast_s: FastSSnapshot {
                sample_ms,
                valid_entries: 1,
                reset_generation: 2,
                bytes: s_bytes,
                packets: s_bytes / 10,
                ..FastSSnapshot::default()
            },
            n_read_begin_ms: sample_ms.saturating_sub(10),
            n_read_end_ms: sample_ms,
            s_read_begin_ms: sample_ms.saturating_sub(9),
            s_read_end_ms: sample_ms.saturating_add(1),
            edge_bps: None,
        };
        try_queue(&queue, FastRateCommand::Sample(input(100, 50, 1_000))).unwrap();
        let first = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(first.sample.is_none());
        try_queue(&queue, FastRateCommand::Sample(input(300, 250, 2_000))).unwrap();
        let second = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(second.sample.unwrap().fast_total_bps, 3_200);
        worker.join().unwrap();
    }
}
