//! NSS FastRate worker boundary.

use std::{sync::mpsc::SyncSender, time::Duration};

use crate::{
    clock::monotonic_millis,
    platform::{
        nss::ecm_bpf::{EcmEventHintReader, EcmEventHintTelemetry, EcmFastCounterMapReader},
        tc_bpf_runtime::FastCounterMapReader,
    },
    workers::{spawn_rate_worker_with_tick, QueueError, RateWorker, WorkerQueue},
};

use super::{
    fast_n_runtime::FastNRuntime,
    fast_n_runtime::FastNSnapshot,
    fast_rate_shadow::FastRateShadow,
    fast_rate_store::{FastRateSample, FastRateTelemetry},
    fast_rate_wakeup::{FastRateWakeup, FastRateWakeupBook, FastRateWakeupTelemetry},
    fast_s_runtime::FastSRuntime,
    fast_s_runtime::FastSSnapshot,
};

const FAST_RATE_SAMPLE_INTERVAL_MS: u64 = 1_000;
const FAST_RATE_EVENT_MIN_INTERVAL_MS: u64 = 900;
const FAST_RATE_EVENT_POLL_MS: u64 = 20;
const FAST_RATE_EVENT_DRAIN_BUDGET: usize = 4_096;

#[derive(Clone, Debug)]
pub(crate) enum FastRateCommand {
    EventHint {
        now_ms: u64,
        base_generation: u64,
        edge_bps: Option<u64>,
    },
    FixedTimer {
        now_ms: u64,
        base_generation: u64,
        edge_bps: Option<u64>,
    },
    Poll {
        now_ms: u64,
        base_generation: u64,
        edge_bps: Option<u64>,
    },
    Sample(FastRateSampleInput),
}

pub(crate) struct FastRateSources {
    n: EcmFastCounterMapReader,
    s: FastCounterMapReader,
    events: Option<EcmEventHintReader>,
}

impl FastRateSources {
    pub(crate) fn new(
        n: EcmFastCounterMapReader,
        s: FastCounterMapReader,
        events: Option<EcmEventHintReader>,
    ) -> Self {
        Self { n, s, events }
    }
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
    pub wakeup_telemetry: FastRateWakeupTelemetry,
    pub event_telemetry: Option<EcmEventHintTelemetry>,
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
        Self::spawn_with_sources(capacity, notices, None)
    }

    pub(crate) fn spawn_with_sources(
        capacity: usize,
        notices: SyncSender<FastRateWakeupNotice>,
        sources: Option<FastRateSources>,
    ) -> Result<Self, std::io::Error> {
        let mut state = FastRateWorkerState::new(sources);
        let worker = spawn_rate_worker_with_tick(
            capacity,
            Duration::from_millis(FAST_RATE_EVENT_POLL_MS),
            move |command| {
                // The worker owns debounce, map readers, stable-read aggregation,
                // and the same-window shadow. The uloop thread only supplies the
                // immutable base generation and receives a completed notice.
                match command {
                    Some(command) => state.handle(&notices, command),
                    None => state.tick(&notices),
                }
            },
        )?;
        Ok(Self { worker })
    }

    pub(crate) fn queue(&self) -> WorkerQueue<FastRateCommand> {
        self.worker.queue()
    }

    pub(crate) fn join(self) -> std::thread::Result<()> {
        self.worker.join()
    }
}

struct FastRateWorkerState {
    sources: Option<FastRateSources>,
    fast_n: FastNRuntime,
    fast_s: FastSRuntime,
    wakeups: FastRateWakeupBook,
    shadow: FastRateShadow,
    last_sample_ms: Option<u64>,
    context: Option<(u64, Option<u64>)>,
    next_fixed_ms: Option<u64>,
}

impl FastRateWorkerState {
    fn new(sources: Option<FastRateSources>) -> Self {
        Self {
            sources,
            fast_n: FastNRuntime::default(),
            fast_s: FastSRuntime::default(),
            wakeups: FastRateWakeupBook::default(),
            shadow: FastRateShadow::new(),
            last_sample_ms: None,
            context: None,
            next_fixed_ms: None,
        }
    }

    fn handle(&mut self, notices: &SyncSender<FastRateWakeupNotice>, command: FastRateCommand) {
        match command {
            FastRateCommand::EventHint {
                now_ms,
                base_generation,
                edge_bps,
            } => {
                self.context = Some((base_generation, edge_bps));
                self.wakeups.on_event_hint(now_ms);
                self.sample_if_due(notices, now_ms, base_generation, edge_bps);
            }
            FastRateCommand::FixedTimer {
                now_ms,
                base_generation,
                edge_bps,
            } => {
                self.context = Some((base_generation, edge_bps));
                self.wakeups.on_fixed_timer();
                self.sample_if_due(notices, now_ms, base_generation, edge_bps);
            }
            FastRateCommand::Poll {
                now_ms,
                base_generation,
                edge_bps,
            } => {
                self.context = Some((base_generation, edge_bps));
                if self.sources.is_some() {
                    self.tick_at(notices, now_ms);
                } else {
                    self.sample_if_due(notices, now_ms, base_generation, edge_bps);
                }
            }
            FastRateCommand::Sample(input) => {
                let now_ms = input
                    .n_read_end_ms
                    .max(input.s_read_end_ms)
                    .max(input.fast_n.sample_ms)
                    .max(input.fast_s.sample_ms);
                self.observe_input(&input);
                self.send_notice(
                    notices,
                    input.base_generation,
                    now_ms,
                    FastRateWakeup {
                        event_hint: false,
                        fixed_timer: false,
                    },
                    true,
                );
            }
        }
    }

    fn tick(&mut self, notices: &SyncSender<FastRateWakeupNotice>) {
        if self.sources.is_none() {
            return;
        }
        let Ok(now_ms) = monotonic_millis() else {
            return;
        };
        self.tick_at(notices, now_ms);
    }

    fn tick_at(&mut self, notices: &SyncSender<FastRateWakeupNotice>, now_ms: u64) {
        let event_count = self
            .sources
            .as_mut()
            .and_then(|sources| sources.events.as_mut())
            .map_or(0, |events| events.drain(FAST_RATE_EVENT_DRAIN_BUDGET));
        self.wakeups.on_event_hints(now_ms, event_count);

        let Some((base_generation, edge_bps)) = self.context else {
            return;
        };
        let next_fixed_ms = self
            .next_fixed_ms
            .get_or_insert_with(|| now_ms.saturating_add(FAST_RATE_SAMPLE_INTERVAL_MS));
        if now_ms >= *next_fixed_ms {
            self.wakeups.on_fixed_timer();
            *next_fixed_ms = now_ms.saturating_add(FAST_RATE_SAMPLE_INTERVAL_MS);
        }
        self.sample_if_due(notices, now_ms, base_generation, edge_bps);
    }

    fn sample_if_due(
        &mut self,
        notices: &SyncSender<FastRateWakeupNotice>,
        now_ms: u64,
        base_generation: u64,
        edge_bps: Option<u64>,
    ) {
        let Some(wakeup) = self.wakeups.poll(now_ms) else {
            return;
        };
        if self.sources.is_some() {
            if let Some(last_sample_ms) = self.last_sample_ms {
                let min_interval_ms = if wakeup.event_hint {
                    FAST_RATE_EVENT_MIN_INTERVAL_MS
                } else {
                    FAST_RATE_SAMPLE_INTERVAL_MS
                };
                if now_ms.saturating_sub(last_sample_ms) < min_interval_ms {
                    if wakeup.event_hint {
                        self.wakeups
                            .defer_event_until(last_sample_ms.saturating_add(min_interval_ms));
                    }
                    return;
                }
            }
        }
        let sample_attempted = self.sources.is_some();
        if sample_attempted {
            match self.read_sources(now_ms, base_generation, edge_bps) {
                Ok(input) => {
                    self.last_sample_ms = Some(input.fast_n.sample_ms.max(input.fast_s.sample_ms));
                    self.observe_input(&input);
                }
                Err(()) => {
                    self.last_sample_ms = Some(now_ms);
                    self.shadow.invalidate_unavailable(now_ms);
                }
            }
        }
        self.send_notice(notices, base_generation, now_ms, wakeup, sample_attempted);
    }

    fn read_sources(
        &mut self,
        now_ms: u64,
        base_generation: u64,
        edge_bps: Option<u64>,
    ) -> Result<FastRateSampleInput, ()> {
        let sources = self.sources.as_ref().ok_or(())?;
        let n_read_begin_ms = monotonic_millis().map_err(|_| ())?;
        let n_read = sources.n.read().map_err(|_| ())?;
        let n_read_end_ms = monotonic_millis().map_err(|_| ())?;
        let s_read_begin_ms = monotonic_millis().map_err(|_| ())?;
        let s_read = sources.s.read().map_err(|_| ())?;
        let s_read_end_ms = monotonic_millis().map_err(|_| ())?;
        let sample_ms = now_ms.max(n_read_end_ms).max(s_read_end_ms);
        Ok(FastRateSampleInput {
            base_generation,
            fast_n: self.fast_n.collect(n_read, sample_ms),
            fast_s: self.fast_s.collect(s_read, sample_ms),
            n_read_begin_ms,
            n_read_end_ms,
            s_read_begin_ms,
            s_read_end_ms,
            edge_bps,
        })
    }

    fn observe_input(&mut self, input: &FastRateSampleInput) {
        self.shadow.observe(
            Some(&input.fast_n),
            Some(&input.fast_s),
            input.n_read_begin_ms,
            input.n_read_end_ms,
            input.s_read_begin_ms,
            input.s_read_end_ms,
            input.edge_bps,
        );
    }

    fn send_notice(
        &self,
        notices: &SyncSender<FastRateWakeupNotice>,
        base_generation: u64,
        observed_ms: u64,
        wakeup: FastRateWakeup,
        sample_attempted: bool,
    ) {
        let _ = notices.try_send(FastRateWakeupNotice {
            base_generation,
            observed_ms,
            wakeup,
            wakeup_telemetry: self.wakeups.telemetry(),
            event_telemetry: self.sources.as_ref().and_then(|sources| {
                sources.events.as_ref().map(|events| {
                    let mut telemetry = events.telemetry();
                    telemetry.event_coalesced = self.wakeups.telemetry().event_coalesced;
                    telemetry
                })
            }),
            sample: self.shadow.latest(),
            telemetry: self.shadow.telemetry(),
            client_shadow_entries: self.shadow.client_count(),
            client_shadow_invalid_windows: self.shadow.client_invalid_windows(),
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
        let context = |now_ms| FastRateCommand::EventHint {
            now_ms,
            base_generation: 1,
            edge_bps: None,
        };
        try_queue(&queue, context(100)).unwrap();
        try_queue(&queue, context(105)).unwrap();
        try_queue(
            &queue,
            FastRateCommand::Poll {
                now_ms: 119,
                base_generation: 1,
                edge_bps: None,
            },
        )
        .unwrap();
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        try_queue(
            &queue,
            FastRateCommand::Poll {
                now_ms: 120,
                base_generation: 1,
                edge_bps: None,
            },
        )
        .unwrap();
        let notice = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(notice.observed_ms, 120);
        assert!(notice.wakeup.event_hint);
        assert!(!notice.wakeup.fixed_timer);
        assert!(notice.sample.is_none());

        try_queue(
            &queue,
            FastRateCommand::FixedTimer {
                now_ms: 1_000,
                base_generation: 1,
                edge_bps: None,
            },
        )
        .unwrap();
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
