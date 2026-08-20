//! NSS FastRate worker boundary.

use std::{
    sync::{mpsc::SyncSender, Arc},
    time::Duration,
};

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
    fast_rate::FastWindowError,
    fast_rate_clients::{FastClientKey, FastClientSample},
    fast_rate_contract::FastRateBaseContract,
    fast_rate_shadow::FastRateShadow,
    fast_rate_store::{FastRateSample, FastRateTelemetry, FastShadowComparison},
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
        base_contract: Arc<FastRateBaseContract>,
        edge_bps: Option<u64>,
    },
    FixedTimer {
        now_ms: u64,
        base_generation: u64,
        base_contract: Arc<FastRateBaseContract>,
        edge_bps: Option<u64>,
    },
    Poll {
        now_ms: u64,
        base_generation: u64,
        base_contract: Arc<FastRateBaseContract>,
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
    pub base_contract: Arc<FastRateBaseContract>,
    pub fast_n: FastNSnapshot,
    pub fast_s: FastSSnapshot,
    pub n_read_begin_ms: u64,
    pub n_read_end_ms: u64,
    pub s_read_begin_ms: u64,
    pub s_read_end_ms: u64,
    pub edge_bps: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastRatePublication {
    pub observed_ms: u64,
    pub read_valid: bool,
    pub fast_n: Option<FastNSnapshot>,
    pub fast_s: Option<FastSSnapshot>,
    pub fast_n_read_failures: u64,
    pub fast_s_read_failures: u64,
    pub fast_s_invalid_reads: u64,
    pub fast_s_truncated_reads: u64,
    pub fast_s_invalid_abi: u64,
    pub fast_s_invalid_sequence: u64,
    pub fast_s_invalid_generation_mismatch: u64,
    pub fast_s_invalid_value: u64,
    pub fast_s_invalid_cpu: u64,
    pub fast_s_invalid_no_cpu: u64,
    pub fast_s_invalid_cpu_count: u64,
    pub fast_s_invalid_cpu_generation: u64,
    pub fast_s_last_cpu_generation_expected: Option<u32>,
    pub fast_s_last_cpu_generation_actual: Option<u32>,
    pub fast_s_reset_generation_changes: u64,
    pub sample: Option<FastRateSample>,
    pub telemetry: FastRateTelemetry,
    pub comparison: Option<FastShadowComparison>,
    pub last_error: Option<FastWindowError>,
    pub client_samples: Vec<(FastClientKey, FastClientSample)>,
    pub client_invalid_windows: u64,
}

impl FastRatePublication {
    pub(crate) fn client_rate(&self, mac: [u8; 6], direction: u8) -> Option<FastClientSample> {
        self.client_samples.iter().find_map(|(key, sample)| {
            (key.mac == mac && key.direction == direction).then_some(*sample)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FastRateWakeupNotice {
    pub base_generation: u64,
    pub base_contract: Arc<FastRateBaseContract>,
    pub observed_ms: u64,
    pub wakeup: FastRateWakeup,
    pub wakeup_telemetry: FastRateWakeupTelemetry,
    pub event_telemetry: Option<EcmEventHintTelemetry>,
    pub publication: FastRatePublication,
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
    context: Option<(u64, Arc<FastRateBaseContract>, Option<u64>)>,
    next_fixed_ms: Option<u64>,
    last_input: Option<(FastNSnapshot, FastSSnapshot)>,
    last_read_valid: bool,
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
            last_input: None,
            last_read_valid: false,
        }
    }

    fn handle(&mut self, notices: &SyncSender<FastRateWakeupNotice>, command: FastRateCommand) {
        match command {
            FastRateCommand::EventHint {
                now_ms,
                base_generation,
                base_contract,
                edge_bps,
            } => {
                let base_contract = self.merge_context_contract(base_contract);
                self.context = Some((base_generation, base_contract.clone(), edge_bps));
                self.wakeups.on_event_hint(now_ms);
                self.sample_if_due(notices, now_ms, base_generation, base_contract, edge_bps);
            }
            FastRateCommand::FixedTimer {
                now_ms,
                base_generation,
                base_contract,
                edge_bps,
            } => {
                let base_contract = self.merge_context_contract(base_contract);
                self.context = Some((base_generation, base_contract.clone(), edge_bps));
                self.wakeups.on_fixed_timer(now_ms);
                self.sample_if_due(notices, now_ms, base_generation, base_contract, edge_bps);
            }
            FastRateCommand::Poll {
                now_ms,
                base_generation,
                base_contract,
                edge_bps,
            } => {
                let base_contract = self.merge_context_contract(base_contract);
                self.context = Some((base_generation, base_contract.clone(), edge_bps));
                if self.sources.is_some() {
                    self.tick_at(notices, now_ms);
                } else {
                    self.sample_if_due(notices, now_ms, base_generation, base_contract, edge_bps);
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
                    input.base_contract.clone(),
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

    /// A collection snapshot can briefly omit one or more otherwise stable
    /// clients while FDB/identity observations settle.  Do not make that
    /// transient omission reset the per-client FastRate coordinators: retain
    /// the previous identity-bound contract, while letting the current
    /// snapshot replace a MAC whose identity or attachment generation
    /// changed.  The overlay still iterates only the current snapshot, so a
    /// departed client can never be rendered; this cache only protects a
    /// client that reappears with the same binding on the next collection.
    fn merge_context_contract(
        &self,
        current: Arc<FastRateBaseContract>,
    ) -> Arc<FastRateBaseContract> {
        self.context
            .as_ref()
            .map_or(current.clone(), |(_, previous, _)| {
                Arc::new(previous.retain_missing_from(&current))
            })
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

        let Some((base_generation, base_contract, edge_bps)) = self.context.clone() else {
            return;
        };
        let next_fixed_ms = self
            .next_fixed_ms
            .get_or_insert_with(|| now_ms.saturating_add(FAST_RATE_SAMPLE_INTERVAL_MS));
        if now_ms >= *next_fixed_ms {
            self.wakeups.on_fixed_timer(now_ms);
            *next_fixed_ms = now_ms.saturating_add(FAST_RATE_SAMPLE_INTERVAL_MS);
        }
        self.sample_if_due(notices, now_ms, base_generation, base_contract, edge_bps);
    }

    fn sample_if_due(
        &mut self,
        notices: &SyncSender<FastRateWakeupNotice>,
        now_ms: u64,
        base_generation: u64,
        base_contract: Arc<FastRateBaseContract>,
        edge_bps: Option<u64>,
    ) {
        let Some(wakeup) = self.wakeups.poll(now_ms) else {
            return;
        };
        if self.sources.is_some() {
            if let Some(last_sample_ms) = self.last_sample_ms {
                if defer_rate_limited_wakeup(&mut self.wakeups, wakeup, last_sample_ms, now_ms) {
                    return;
                }
            }
        }
        let sample_attempted = self.sources.is_some();
        if sample_attempted {
            match self.read_sources(now_ms, base_generation, base_contract.clone(), edge_bps) {
                Ok(input) => {
                    self.last_sample_ms = Some(input.fast_n.sample_ms.max(input.fast_s.sample_ms));
                    self.observe_input(&input);
                }
                Err(()) => {
                    self.last_sample_ms = Some(now_ms);
                    self.last_input = None;
                    self.last_read_valid = false;
                    self.shadow.invalidate_unavailable(now_ms);
                }
            }
        }
        // `read_sources` timestamps the snapshots at the end of the map
        // reads.  Using the wakeup time here can make a valid sample look as
        // if it came from the future whenever either lookup crosses a
        // millisecond boundary; the overlay then drops the newest window.
        let observed_ms = publication_observed_ms(
            now_ms,
            sample_attempted,
            self.last_input
                .as_ref()
                .map(|(fast_n, fast_s)| (fast_n, fast_s)),
        );
        self.send_notice(
            notices,
            base_generation,
            base_contract,
            observed_ms,
            wakeup,
            sample_attempted,
        );
    }

    fn read_sources(
        &mut self,
        now_ms: u64,
        base_generation: u64,
        base_contract: Arc<FastRateBaseContract>,
        edge_bps: Option<u64>,
    ) -> Result<FastRateSampleInput, ()> {
        let sources = self.sources.as_ref().ok_or(())?;
        let n_read_begin_ms = monotonic_millis().map_err(|_| ())?;
        let n_read = match sources.n.read() {
            Ok(read) => read,
            Err(_) => {
                self.fast_n.record_read_failure();
                return Err(());
            }
        };
        let n_read_end_ms = monotonic_millis().map_err(|_| ())?;
        let s_read_begin_ms = monotonic_millis().map_err(|_| ())?;
        let s_read = match sources.s.read() {
            Ok(read) => read,
            Err(_) => {
                self.fast_s.record_read_failure();
                return Err(());
            }
        };
        let s_read_end_ms = monotonic_millis().map_err(|_| ())?;
        let sample_ms = now_ms.max(n_read_end_ms).max(s_read_end_ms);
        Ok(FastRateSampleInput {
            base_generation,
            base_contract,
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
        self.shadow.observe_with_contract(
            Some(&input.fast_n),
            Some(&input.fast_s),
            input.n_read_begin_ms,
            input.n_read_end_ms,
            input.s_read_begin_ms,
            input.s_read_end_ms,
            input.edge_bps,
            &input.base_contract,
        );
        self.last_input = Some((input.fast_n.clone(), input.fast_s.clone()));
        self.last_read_valid = !input.fast_n.truncated
            && input.fast_n.invalid_entries == 0
            && !input.fast_s.truncated
            && input.fast_s.invalid_entries == 0;
    }

    fn send_notice(
        &self,
        notices: &SyncSender<FastRateWakeupNotice>,
        base_generation: u64,
        base_contract: Arc<FastRateBaseContract>,
        observed_ms: u64,
        wakeup: FastRateWakeup,
        sample_attempted: bool,
    ) {
        let _ = notices.try_send(FastRateWakeupNotice {
            base_generation,
            base_contract,
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
            publication: FastRatePublication {
                observed_ms,
                read_valid: self.last_read_valid,
                fast_n: self.last_input.as_ref().map(|value| value.0.clone()),
                fast_s: self.last_input.as_ref().map(|value| value.1.clone()),
                fast_n_read_failures: self.fast_n.read_failures(),
                fast_s_read_failures: self.fast_s.read_failures(),
                fast_s_invalid_reads: self.fast_s.invalid_reads(),
                fast_s_truncated_reads: self.fast_s.truncated_reads(),
                fast_s_invalid_abi: self.fast_s.invalid_abi(),
                fast_s_invalid_sequence: self.fast_s.invalid_sequence(),
                fast_s_invalid_generation_mismatch: self.fast_s.invalid_generation_mismatch(),
                fast_s_invalid_value: self.fast_s.invalid_value(),
                fast_s_invalid_cpu: self.fast_s.invalid_cpu(),
                fast_s_invalid_no_cpu: self.fast_s.invalid_no_cpu(),
                fast_s_invalid_cpu_count: self.fast_s.invalid_cpu_count(),
                fast_s_invalid_cpu_generation: self.fast_s.invalid_cpu_generation(),
                fast_s_last_cpu_generation_expected: self.fast_s.last_cpu_generation_expected(),
                fast_s_last_cpu_generation_actual: self.fast_s.last_cpu_generation_actual(),
                fast_s_reset_generation_changes: self.fast_s.reset_generation_changes(),
                sample: self.shadow.latest(),
                telemetry: self.shadow.telemetry(),
                comparison: self.shadow.comparison(),
                last_error: self.shadow.last_error(),
                client_samples: self.shadow.client_samples(),
                client_invalid_windows: self.shadow.client_invalid_windows(),
            },
            sample_attempted,
        });
    }
}

fn defer_rate_limited_wakeup(
    wakeups: &mut FastRateWakeupBook,
    wakeup: FastRateWakeup,
    last_sample_ms: u64,
    now_ms: u64,
) -> bool {
    let min_interval_ms = if wakeup.fixed_timer {
        FAST_RATE_SAMPLE_INTERVAL_MS
    } else {
        FAST_RATE_EVENT_MIN_INTERVAL_MS
    };
    if now_ms.saturating_sub(last_sample_ms) >= min_interval_ms {
        return false;
    }

    let deadline_ms = last_sample_ms.saturating_add(min_interval_ms);
    if wakeup.event_hint {
        wakeups.defer_event_until(deadline_ms);
    }
    if wakeup.fixed_timer {
        wakeups.defer_fixed_until(deadline_ms);
    }
    true
}

fn publication_observed_ms(
    now_ms: u64,
    sample_attempted: bool,
    last_input: Option<(&FastNSnapshot, &FastSSnapshot)>,
) -> u64 {
    if !sample_attempted {
        return now_ms;
    }
    last_input.map_or(now_ms, |(fast_n, fast_s)| {
        now_ms.max(fast_n.sample_ms).max(fast_s.sample_ms)
    })
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
    use std::sync::Arc;
    use std::time::Duration;

    use super::{
        defer_rate_limited_wakeup, publication_observed_ms, try_queue, FastRateCommand,
        FastRateSampleInput, FastRateWorker,
    };
    use crate::platform::nss::{
        fast_n_runtime::FastNSnapshot,
        fast_rate_contract::FastRateBaseContract,
        fast_rate_wakeup::{FastRateWakeup, FastRateWakeupBook},
        fast_s_runtime::FastSSnapshot,
    };

    fn contract() -> Arc<FastRateBaseContract> {
        Arc::new(FastRateBaseContract::default())
    }

    #[test]
    fn rate_limited_fixed_tick_is_retried_at_the_full_interval() {
        let mut wakeups = FastRateWakeupBook::default();
        let fixed = FastRateWakeup {
            event_hint: true,
            fixed_timer: true,
        };
        assert!(defer_rate_limited_wakeup(&mut wakeups, fixed, 100, 1_000));
        assert!(wakeups.poll(1_099).is_none());
        assert_eq!(wakeup_at(&mut wakeups, 1_100), fixed);
    }

    #[test]
    fn eligible_event_is_not_rearmed() {
        let mut wakeups = FastRateWakeupBook::default();
        assert!(!defer_rate_limited_wakeup(
            &mut wakeups,
            FastRateWakeup {
                event_hint: true,
                fixed_timer: false,
            },
            100,
            1_000
        ));
        assert!(wakeups.poll(u64::MAX).is_none());
    }

    fn wakeup_at(wakeups: &mut FastRateWakeupBook, now_ms: u64) -> FastRateWakeup {
        wakeups.poll(now_ms).expect("deferred wakeup")
    }

    #[test]
    fn publication_clock_uses_the_completed_map_read_timestamp() {
        let fast_n = FastNSnapshot {
            sample_ms: 1_005,
            ..FastNSnapshot::default()
        };
        let fast_s = FastSSnapshot {
            sample_ms: 1_007,
            ..FastSSnapshot::default()
        };
        assert_eq!(
            publication_observed_ms(1_000, true, Some((&fast_n, &fast_s))),
            1_007
        );
        assert_eq!(
            publication_observed_ms(1_000, false, Some((&fast_n, &fast_s))),
            1_000
        );
    }

    #[test]
    fn worker_debounces_events_and_keeps_fixed_timer_independent() {
        let (notices, receiver) = mpsc::sync_channel(4);
        let worker = FastRateWorker::spawn(8, notices).unwrap();
        let queue = worker.queue();
        let context = |now_ms| FastRateCommand::EventHint {
            now_ms,
            base_generation: 1,
            base_contract: contract(),
            edge_bps: None,
        };
        try_queue(&queue, context(100)).unwrap();
        try_queue(&queue, context(105)).unwrap();
        try_queue(
            &queue,
            FastRateCommand::Poll {
                now_ms: 119,
                base_generation: 1,
                base_contract: contract(),
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
                base_contract: contract(),
                edge_bps: None,
            },
        )
        .unwrap();
        let notice = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(notice.observed_ms, 120);
        assert!(notice.wakeup.event_hint);
        assert!(!notice.wakeup.fixed_timer);
        assert!(notice.publication.sample.is_none());

        try_queue(
            &queue,
            FastRateCommand::FixedTimer {
                now_ms: 1_000,
                base_generation: 1,
                base_contract: contract(),
                edge_bps: None,
            },
        )
        .unwrap();
        let notice = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(notice.observed_ms, 1_000);
        assert!(!notice.wakeup.event_hint);
        assert!(notice.wakeup.fixed_timer);
        assert!(notice.publication.sample.is_none());
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
            base_contract: contract(),
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
        assert!(first.publication.sample.is_none());
        try_queue(&queue, FastRateCommand::Sample(input(300, 250, 2_000))).unwrap();
        let second = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        let second_sample = second.publication.sample.expect("completed sample");
        assert_eq!(second_sample.fast_total_bps, 3_200);
        assert!(second.observed_ms >= second_sample.sample_ms);
        assert!(second.publication.read_valid);
        assert!(second.publication.fast_n.is_some());
        assert!(second.publication.fast_s.is_some());

        let mut invalid = input(400, 350, 3_000);
        invalid.fast_s.invalid_entries = 1;
        try_queue(&queue, FastRateCommand::Sample(invalid)).unwrap();
        let invalid = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!invalid.publication.read_valid);
        assert!(invalid.publication.sample.is_none());
        assert!(invalid.publication.client_samples.is_empty());
        worker.join().unwrap();
    }
}
