use crate::platform::{counters::TrafficCounters, nss::ecm_node::NodeSnapshot};
use std::collections::{BTreeMap, VecDeque};

const NODE_BASELINE_RETENTION_MS: u64 = 60_000;
const RATE_HOLD_MS: u64 = 1_500;
const NODE_RATE_MEDIAN_SAMPLES: usize = 3;
const MAX_RATE_WINDOW_MS: u64 = 5_000;
const COVERAGE_CATCHUP_TIMEOUT_MS: u64 = 5_000;
const UNOWNED_SETTLE_MS: u64 = 2_500;
const MIN_COVERAGE_BYTES: u64 = 128 * 1024;
const MIN_OWNERSHIP_PERCENT: u64 = 90;
pub(crate) const ECM_BPF_LOW_RATE_WINDOW_MS: u64 = 6_000;
pub(crate) const ECM_BPF_LOW_RATE_STEP_MS: u64 = 2_000;
pub(crate) const ECM_BPF_LOW_RATE_ROLLING_WINDOW_MS: u64 = 18_000;
pub(crate) const ECM_BPF_EVENT_HIGH_RATE_BPS: u64 = 8_000_000;
pub(crate) const ECM_BPF_HIGH_RATE_CONFIRMATION_MS: u64 = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LanClock {
    pub interface: String,
    pub sample_ms: u64,
    pub counters: TrafficCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowQuality {
    Warmup,
    Pending,
    Ok,
    Idle,
    LowTraffic,
    CounterReset,
    CounterSkew,
}

impl WindowQuality {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warmup => "warmup",
            Self::Pending => "pending",
            Self::Ok => "ok",
            Self::Idle => "idle",
            Self::LowTraffic => "low_traffic",
            Self::CounterReset => "counter_reset",
            Self::CounterSkew => "counter_skew",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct WindowClient {
    pub identity_key: String,
    pub delta: TrafficCounters,
    pub total: TrafficCounters,
    pub tx_bps: u64,
    pub rx_bps: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoverageWindow {
    pub quality: WindowQuality,
    pub reason: &'static str,
    pub start_ms: u64,
    pub end_ms: u64,
    pub client_raw: TrafficCounters,
    pub client_normalized: TrafficCounters,
    pub lan_raw: TrafficCounters,
    pub lan_normalized: TrafficCounters,
    pub tx_pct: Option<u8>,
    pub rx_pct: Option<u8>,
    pub retained_tx_pct: Option<u8>,
    pub retained_rx_pct: Option<u8>,
    pub aligned: bool,
}

impl CoverageWindow {
    pub fn window_ms(&self) -> u64 {
        self.end_ms.saturating_sub(self.start_ms)
    }

    fn empty(quality: WindowQuality, reason: &'static str, sample_ms: u64) -> Self {
        Self {
            quality,
            reason,
            start_ms: sample_ms,
            end_ms: sample_ms,
            client_raw: TrafficCounters::default(),
            client_normalized: TrafficCounters::default(),
            lan_raw: TrafficCounters::default(),
            lan_normalized: TrafficCounters::default(),
            tx_pct: None,
            rx_pct: None,
            retained_tx_pct: None,
            retained_rx_pct: None,
            aligned: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublishedClientRate {
    start_ms: u64,
    end_ms: u64,
    delta: TrafficCounters,
    tx_bps: u64,
    rx_bps: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ClientDelta {
    raw: TrafficCounters,
    normalized: TrafficCounters,
    start_ms: Option<u64>,
    tx_bps: u64,
    rx_bps: u64,
}

impl ClientDelta {
    fn progressed(&self) -> bool {
        self.start_ms.is_some()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowOutput {
    pub quality: WindowQuality,
    pub reason: &'static str,
    pub start_ms: u64,
    pub end_ms: u64,
    pub clients: Vec<WindowClient>,
    pub fresh_rate_sample: bool,
    pub held_rate_age_ms: Option<u64>,
    pub coverage: CoverageWindow,
}

impl WindowOutput {
    pub fn window_ms(&self) -> u64 {
        self.end_ms.saturating_sub(self.start_ms)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NodeKey {
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeBaseline {
    counters: TrafficCounters,
    last_seen_ms: u64,
    last_progress_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct NodeRateHistory {
    samples: [u64; NODE_RATE_MEDIAN_SAMPLES],
    len: u8,
    next: u8,
}

impl NodeRateHistory {
    fn push(&mut self, bps: u64) -> u64 {
        self.samples[usize::from(self.next)] = bps;
        self.next = (self.next + 1) % NODE_RATE_MEDIAN_SAMPLES as u8;
        if usize::from(self.len) < NODE_RATE_MEDIAN_SAMPLES {
            self.len += 1;
        }
        if usize::from(self.len) < NODE_RATE_MEDIAN_SAMPLES {
            return bps;
        }
        let mut ordered = self.samples;
        ordered.sort_unstable();
        ordered[NODE_RATE_MEDIAN_SAMPLES / 2]
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NssCoverageBook {
    start: Option<LanClock>,
    pending_since_ms: Option<u64>,
    pending_client: TrafficCounters,
    last_reported: Option<(Option<u8>, Option<u8>)>,
}

impl NssCoverageBook {
    pub fn update(&mut self, client_delta: TrafficCounters, lan: &LanClock) -> CoverageWindow {
        let Some(start) = self.start.clone() else {
            self.clear(lan.clone());
            return CoverageWindow::empty(WindowQuality::Warmup, "cold_start", lan.sample_ms);
        };
        if start.interface != lan.interface {
            self.clear(lan.clone());
            return CoverageWindow::empty(
                WindowQuality::CounterReset,
                "lan_boundary_changed",
                lan.sample_ms,
            );
        }
        if lan.sample_ms <= start.sample_ms {
            self.clear(lan.clone());
            return CoverageWindow::empty(
                WindowQuality::CounterReset,
                "sample_clock_reset",
                lan.sample_ms,
            );
        }

        add_assign(&mut self.pending_client, client_delta);
        let client_raw = self.pending_client;
        let Some(lan_raw) = checked_delta(lan.counters, start.counters) else {
            self.clear(lan.clone());
            return CoverageWindow::empty(
                WindowQuality::CounterReset,
                "lan_coverage_counter_reset",
                lan.sample_ms,
            );
        };
        let Some(client_normalized) = client_raw.fcs_normalized() else {
            self.clear(lan.clone());
            return coverage_window(
                WindowQuality::CounterSkew,
                "client_fcs_overflow",
                &start,
                lan,
                client_raw,
                TrafficCounters::default(),
                lan_raw,
                lan_raw.fcs_normalized().unwrap_or_default(),
                false,
                false,
            );
        };
        let Some(lan_normalized) = lan_raw.fcs_normalized() else {
            self.clear(lan.clone());
            return coverage_window(
                WindowQuality::CounterSkew,
                "lan_fcs_overflow",
                &start,
                lan,
                client_raw,
                client_normalized,
                lan_raw,
                TrafficCounters::default(),
                false,
                false,
            );
        };

        let aligned = fits_lan_clock(client_raw, lan_raw)
            && fits_lan_clock(client_normalized, lan_normalized)
            && directional_coverage_ready(client_raw, lan_raw)
            && directional_coverage_ready(client_normalized, lan_normalized);
        if aligned {
            let ownership_complete = ownership_ready(client_normalized, lan_normalized);
            let denominator = lan_normalized
                .rx_bytes
                .saturating_add(lan_normalized.tx_bytes);
            let quality = if denominator == 0 {
                WindowQuality::Idle
            } else if denominator < MIN_COVERAGE_BYTES {
                WindowQuality::LowTraffic
            } else {
                WindowQuality::Ok
            };
            let timeout = if !has_traffic(&client_raw) && has_traffic(&lan_raw) {
                UNOWNED_SETTLE_MS
            } else {
                COVERAGE_CATCHUP_TIMEOUT_MS
            };
            let partial_since =
                (!ownership_complete).then(|| *self.pending_since_ms.get_or_insert(lan.sample_ms));
            let partial_timed_out =
                partial_since.is_some_and(|since| lan.sample_ms.saturating_sub(since) > timeout);
            let reason = if ownership_complete {
                "lan_coverage_aligned"
            } else if partial_timed_out {
                "lan_coverage_unowned"
            } else {
                "lan_coverage_partial"
            };
            let output = coverage_window(
                quality,
                reason,
                &start,
                lan,
                client_raw,
                client_normalized,
                lan_raw,
                lan_normalized,
                true,
                true,
            );
            if quality == WindowQuality::Idle {
                self.last_reported = None;
            } else if output.tx_pct.is_some() || output.rx_pct.is_some() {
                self.last_reported = Some((output.tx_pct, output.rx_pct));
            }
            if ownership_complete || partial_timed_out {
                self.rebaseline(lan.clone());
            }
            return output;
        }

        let pending_since = *self.pending_since_ms.get_or_insert(lan.sample_ms);
        let timeout = if !has_traffic(&client_raw) && has_traffic(&lan_raw) {
            UNOWNED_SETTLE_MS
        } else {
            COVERAGE_CATCHUP_TIMEOUT_MS
        };
        if lan.sample_ms.saturating_sub(pending_since) <= timeout {
            return self.with_last_reported(coverage_window(
                WindowQuality::Pending,
                "lan_coverage_pending",
                &start,
                lan,
                client_raw,
                client_normalized,
                lan_raw,
                lan_normalized,
                false,
                true,
            ));
        }

        let (quality, reason) = if is_low_traffic_pair(client_raw, lan_raw) {
            (WindowQuality::LowTraffic, "low_traffic_coverage_rebaseline")
        } else {
            (WindowQuality::CounterSkew, "lan_coverage_timeout")
        };
        let output = self.with_last_reported(coverage_window(
            quality,
            reason,
            &start,
            lan,
            client_raw,
            client_normalized,
            lan_raw,
            lan_normalized,
            false,
            true,
        ));
        self.rebaseline(lan.clone());
        output
    }

    fn with_last_reported(&self, mut coverage: CoverageWindow) -> CoverageWindow {
        if let Some((tx_pct, rx_pct)) = self.last_reported {
            coverage.retained_tx_pct = tx_pct;
            coverage.retained_rx_pct = rx_pct;
        }
        coverage
    }

    fn clear(&mut self, lan: LanClock) {
        self.rebaseline(lan);
        self.last_reported = None;
    }

    fn rebaseline(&mut self, lan: LanClock) {
        self.start = Some(lan);
        self.pending_since_ms = None;
        self.pending_client = TrafficCounters::default();
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RateWindowInterfaceCounter {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RateWindowValue {
    pub rx_bps: u64,
    pub tx_bps: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EcmBpfRateBatch {
    pub start_ms: u64,
    pub end_ms: u64,
    pub clients: BTreeMap<String, RateWindowValue>,
    pub interfaces: BTreeMap<String, RateWindowValue>,
    pub raw_aligned: bool,
    pub fallback_event_gap_filled: bool,
    pub fallback_lan_reconciled: bool,
    pub low_rate: bool,
    pub fresh: bool,
    pub held_age_ms: Option<u64>,
}

impl EcmBpfRateBatch {
    pub fn window_ms(&self) -> u64 {
        self.end_ms.saturating_sub(self.start_ms)
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EcmBpfRateWindowBook {
    baseline_lan: Option<LanClock>,
    baseline_interfaces: BTreeMap<String, RateWindowInterfaceCounter>,
    pending_clients: BTreeMap<String, TrafficCounters>,
    pending_fallback_rates: BTreeMap<String, FallbackRateIntegral>,
    last_fallback_sample_ms: Option<u64>,
    low_rate_history: VecDeque<EcmBpfRateBatch>,
    published: Option<EcmBpfRateBatch>,
    high_rate_quiet_since_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
struct FallbackRateIntegral {
    rx_bps_ms: u128,
    tx_bps_ms: u128,
}

impl EcmBpfRateWindowBook {
    #[cfg(test)]
    pub fn update(
        &mut self,
        client_deltas: &BTreeMap<String, TrafficCounters>,
        fallback_rates: &BTreeMap<String, RateWindowValue>,
        lan: &LanClock,
        interfaces: &BTreeMap<String, RateWindowInterfaceCounter>,
    ) -> Option<EcmBpfRateBatch> {
        self.update_with_client_interfaces(
            client_deltas,
            fallback_rates,
            &BTreeMap::new(),
            lan,
            interfaces,
        )
    }

    pub fn update_with_client_interfaces(
        &mut self,
        client_deltas: &BTreeMap<String, TrafficCounters>,
        fallback_rates: &BTreeMap<String, RateWindowValue>,
        client_interfaces: &BTreeMap<String, String>,
        lan: &LanClock,
        interfaces: &BTreeMap<String, RateWindowInterfaceCounter>,
    ) -> Option<EcmBpfRateBatch> {
        let Some(start) = self.baseline_lan.as_ref() else {
            self.rebaseline(lan.clone(), interfaces.clone(), true);
            return None;
        };
        if start.interface != lan.interface
            || lan.sample_ms <= start.sample_ms
            || interfaces.keys().ne(self.baseline_interfaces.keys())
        {
            self.rebaseline(lan.clone(), interfaces.clone(), true);
            return None;
        }

        let window_ms = lan.sample_ms.saturating_sub(start.sample_ms);
        let fallback_segment_ms = lan
            .sample_ms
            .saturating_sub(self.last_fallback_sample_ms.unwrap_or(start.sample_ms));
        let Some(lan_raw) = checked_delta(lan.counters, start.counters) else {
            self.rebaseline(lan.clone(), interfaces.clone(), true);
            return None;
        };
        let Some(interface_deltas) =
            checked_interface_deltas(interfaces, &self.baseline_interfaces)
        else {
            self.rebaseline(lan.clone(), interfaces.clone(), true);
            return None;
        };
        let interface_rates = rate_window_interfaces(&interface_deltas, window_ms);

        for (identity_key, delta) in client_deltas {
            add_assign(
                self.pending_clients
                    .entry(identity_key.clone())
                    .or_default(),
                *delta,
            );
        }
        accumulate_fallback_rates(
            &mut self.pending_fallback_rates,
            fallback_rates,
            fallback_segment_ms,
        );
        self.last_fallback_sample_ms = Some(lan.sample_ms);
        let client_raw = sum(self.pending_clients.values().copied());
        let client_normalized = client_raw.fcs_normalized();
        let lan_normalized = lan_raw.fcs_normalized();
        let fallback_average = averaged_fallback_rates(&self.pending_fallback_rates, window_ms);
        let event_high_rate = fallback_average.values().any(|value| {
            value.rx_bps >= ECM_BPF_EVENT_HIGH_RATE_BPS
                || value.tx_bps >= ECM_BPF_EVENT_HIGH_RATE_BPS
        });
        let aligned = client_normalized.is_some_and(|client| {
            lan_normalized.is_some_and(|lan| {
                directional_coverage_ready(client_raw, lan_raw)
                    && directional_coverage_ready(client, lan)
            })
        });
        let total_bytes = lan_normalized.map_or(u64::MAX, |value| {
            value.tx_bytes.saturating_add(value.rx_bytes)
        });
        let idle = !has_traffic(&client_raw) && !has_traffic(&lan_raw);
        let low_rate = total_bytes < MIN_COVERAGE_BYTES && !event_high_rate;
        let history_ready = self.low_rate_history_ms() >= ECM_BPF_LOW_RATE_WINDOW_MS;
        let published_high = self.published.as_ref().is_some_and(|batch| !batch.low_rate);
        let low_rate_ready = idle
            || window_ms >= ECM_BPF_LOW_RATE_WINDOW_MS
            || ((history_ready || published_high) && window_ms >= ECM_BPF_LOW_RATE_STEP_MS);
        let aligned_ready = if low_rate { low_rate_ready } else { true };

        if aligned && aligned_ready {
            let Some(clients) = rate_window_clients(&self.pending_clients, window_ms) else {
                self.rebaseline(lan.clone(), interfaces.clone(), true);
                return None;
            };
            let batch = EcmBpfRateBatch {
                start_ms: start.sample_ms,
                end_ms: lan.sample_ms,
                clients,
                interfaces: interface_rates,
                raw_aligned: true,
                fallback_event_gap_filled: false,
                fallback_lan_reconciled: false,
                low_rate,
                fresh: true,
                held_age_ms: None,
            };
            let batch = self.publish_candidate(batch);
            if batch.is_some() {
                self.rebaseline(lan.clone(), interfaces.clone(), false);
            }
            return batch;
        }

        let fallback_ready = if low_rate {
            low_rate_ready
        } else {
            window_ms >= ECM_BPF_LOW_RATE_WINDOW_MS
                || (published_high && window_ms >= ECM_BPF_LOW_RATE_STEP_MS)
        };
        if fallback_ready {
            let (clients, event_gap_filled, lan_reconciled) = if low_rate {
                fallback_rate_window_clients(
                    &self.pending_clients,
                    &fallback_average,
                    lan_raw,
                    window_ms,
                )
            } else {
                high_rate_window_clients(
                    &self.pending_clients,
                    &fallback_average,
                    lan_raw,
                    client_interfaces,
                    &interface_rates,
                    window_ms,
                )
            };
            let batch = EcmBpfRateBatch {
                start_ms: start.sample_ms,
                end_ms: lan.sample_ms,
                clients,
                interfaces: interface_rates,
                raw_aligned: false,
                fallback_event_gap_filled: event_gap_filled,
                fallback_lan_reconciled: lan_reconciled,
                low_rate,
                fresh: true,
                held_age_ms: None,
            };
            let batch = self.publish_candidate(batch);
            if batch.is_some() {
                self.rebaseline(lan.clone(), interfaces.clone(), false);
            }
            return batch;
        }
        self.held_at(lan.sample_ms)
    }

    fn low_rate_history_ms(&self) -> u64 {
        self.low_rate_history
            .iter()
            .fold(0u64, |total, batch| total.saturating_add(batch.window_ms()))
    }

    fn publish_candidate(&mut self, mut candidate: EcmBpfRateBatch) -> Option<EcmBpfRateBatch> {
        let previous_high = self.published.as_ref().filter(|batch| !batch.low_rate);
        let candidate_is_live =
            previous_high.is_none_or(|previous| high_rate_candidate_is_live(&candidate, previous));
        if previous_high.is_some() && !candidate_is_live {
            let quiet_since = *self
                .high_rate_quiet_since_ms
                .get_or_insert(candidate.end_ms);
            if candidate.end_ms.saturating_sub(quiet_since) < ECM_BPF_HIGH_RATE_CONFIRMATION_MS {
                return self.held_at(candidate.end_ms);
            }
            candidate.low_rate = true;
        }

        self.high_rate_quiet_since_ms = None;
        let low_rate = candidate.low_rate;
        Some(self.publish_rate_segment(candidate, low_rate))
    }

    fn publish_rate_segment(
        &mut self,
        segment: EcmBpfRateBatch,
        low_rate: bool,
    ) -> EcmBpfRateBatch {
        if !low_rate {
            self.low_rate_history.clear();
            self.published = Some(segment.clone());
            return segment;
        }

        self.low_rate_history.push_back(segment);
        trim_low_rate_history(&mut self.low_rate_history);
        let batch = aggregate_low_rate_history(&self.low_rate_history);
        self.published = Some(batch.clone());
        batch
    }

    pub fn held_at(&self, sample_ms: u64) -> Option<EcmBpfRateBatch> {
        self.published.clone().map(|mut batch| {
            batch.fresh = false;
            batch.held_age_ms = Some(sample_ms.saturating_sub(batch.end_ms));
            batch
        })
    }

    fn rebaseline(
        &mut self,
        lan: LanClock,
        interfaces: BTreeMap<String, RateWindowInterfaceCounter>,
        clear_published: bool,
    ) {
        let sample_ms = lan.sample_ms;
        self.baseline_lan = Some(lan);
        self.baseline_interfaces = interfaces;
        self.pending_clients.clear();
        self.pending_fallback_rates.clear();
        self.last_fallback_sample_ms = Some(sample_ms);
        if clear_published {
            self.low_rate_history.clear();
            self.published = None;
            self.high_rate_quiet_since_ms = None;
        }
    }
}

fn trim_low_rate_history(history: &mut VecDeque<EcmBpfRateBatch>) {
    let mut total_ms = history
        .iter()
        .fold(0u64, |total, batch| total.saturating_add(batch.window_ms()));
    while total_ms > ECM_BPF_LOW_RATE_ROLLING_WINDOW_MS {
        let excess = total_ms - ECM_BPF_LOW_RATE_ROLLING_WINDOW_MS;
        let Some(front) = history.front_mut() else {
            break;
        };
        let front_ms = front.window_ms();
        if front_ms <= excess {
            total_ms = total_ms.saturating_sub(front_ms);
            history.pop_front();
            continue;
        }
        front.start_ms = front.start_ms.saturating_add(excess);
        total_ms = total_ms.saturating_sub(excess);
    }
}

fn aggregate_low_rate_history(history: &VecDeque<EcmBpfRateBatch>) -> EcmBpfRateBatch {
    let last = history.back().expect("low-rate history is not empty");
    let window_ms = history
        .iter()
        .fold(0u64, |total, batch| total.saturating_add(batch.window_ms()));
    EcmBpfRateBatch {
        start_ms: last.end_ms.saturating_sub(window_ms),
        end_ms: last.end_ms,
        clients: weighted_rate_values(
            history
                .iter()
                .map(|batch| (&batch.clients, batch.window_ms())),
            window_ms,
        ),
        interfaces: weighted_rate_values(
            history
                .iter()
                .map(|batch| (&batch.interfaces, batch.window_ms())),
            window_ms,
        ),
        raw_aligned: history.iter().all(|batch| batch.raw_aligned),
        fallback_event_gap_filled: history.iter().any(|batch| batch.fallback_event_gap_filled),
        fallback_lan_reconciled: history.iter().any(|batch| batch.fallback_lan_reconciled),
        low_rate: true,
        fresh: true,
        held_age_ms: None,
    }
}

fn weighted_rate_values<'a>(
    maps: impl Iterator<Item = (&'a BTreeMap<String, RateWindowValue>, u64)>,
    window_ms: u64,
) -> BTreeMap<String, RateWindowValue> {
    if window_ms == 0 {
        return BTreeMap::new();
    }
    let mut integrals = BTreeMap::<String, (u128, u128)>::new();
    for (values, segment_ms) in maps {
        for (key, value) in values {
            let integral = integrals.entry(key.clone()).or_default();
            integral.0 = integral
                .0
                .saturating_add(u128::from(value.rx_bps).saturating_mul(u128::from(segment_ms)));
            integral.1 = integral
                .1
                .saturating_add(u128::from(value.tx_bps).saturating_mul(u128::from(segment_ms)));
        }
    }
    integrals
        .into_iter()
        .map(|(key, (rx_bps_ms, tx_bps_ms))| {
            let rx_bps = rx_bps_ms / u128::from(window_ms);
            let tx_bps = tx_bps_ms / u128::from(window_ms);
            (
                key,
                RateWindowValue {
                    rx_bps: u64::try_from(rx_bps).unwrap_or(u64::MAX),
                    tx_bps: u64::try_from(tx_bps).unwrap_or(u64::MAX),
                },
            )
        })
        .collect()
}

fn checked_interface_deltas(
    current: &BTreeMap<String, RateWindowInterfaceCounter>,
    previous: &BTreeMap<String, RateWindowInterfaceCounter>,
) -> Option<BTreeMap<String, RateWindowInterfaceCounter>> {
    current
        .iter()
        .map(|(name, current)| {
            let previous = previous.get(name)?;
            Some((
                name.clone(),
                RateWindowInterfaceCounter {
                    rx_bytes: current.rx_bytes.checked_sub(previous.rx_bytes)?,
                    tx_bytes: current.tx_bytes.checked_sub(previous.tx_bytes)?,
                },
            ))
        })
        .collect()
}

fn rate_window_clients(
    pending: &BTreeMap<String, TrafficCounters>,
    window_ms: u64,
) -> Option<BTreeMap<String, RateWindowValue>> {
    pending
        .iter()
        .map(|(identity_key, counters)| {
            let counters = counters.fcs_normalized()?;
            Some((
                identity_key.clone(),
                RateWindowValue {
                    rx_bps: rate(counters.rx_bytes, window_ms),
                    tx_bps: rate(counters.tx_bytes, window_ms),
                },
            ))
        })
        .collect()
}

fn rate_window_interfaces(
    counters: &BTreeMap<String, RateWindowInterfaceCounter>,
    window_ms: u64,
) -> BTreeMap<String, RateWindowValue> {
    counters
        .iter()
        .map(|(name, counters)| {
            (
                name.clone(),
                RateWindowValue {
                    rx_bps: rate(counters.rx_bytes, window_ms),
                    tx_bps: rate(counters.tx_bytes, window_ms),
                },
            )
        })
        .collect()
}

fn accumulate_fallback_rates(
    pending: &mut BTreeMap<String, FallbackRateIntegral>,
    rates: &BTreeMap<String, RateWindowValue>,
    segment_ms: u64,
) {
    for (identity_key, rate) in rates {
        let integral = pending.entry(identity_key.clone()).or_default();
        integral.rx_bps_ms = integral
            .rx_bps_ms
            .saturating_add(u128::from(rate.rx_bps).saturating_mul(u128::from(segment_ms)));
        integral.tx_bps_ms = integral
            .tx_bps_ms
            .saturating_add(u128::from(rate.tx_bps).saturating_mul(u128::from(segment_ms)));
    }
}

fn averaged_fallback_rates(
    pending: &BTreeMap<String, FallbackRateIntegral>,
    window_ms: u64,
) -> BTreeMap<String, RateWindowValue> {
    if window_ms == 0 {
        return BTreeMap::new();
    }
    pending
        .iter()
        .map(|(identity_key, integral)| {
            let rx_bps = integral.rx_bps_ms / u128::from(window_ms);
            let tx_bps = integral.tx_bps_ms / u128::from(window_ms);
            (
                identity_key.clone(),
                RateWindowValue {
                    rx_bps: u64::try_from(rx_bps).unwrap_or(u64::MAX),
                    tx_bps: u64::try_from(tx_bps).unwrap_or(u64::MAX),
                },
            )
        })
        .collect()
}

fn fallback_rate_window_clients(
    pending_raw: &BTreeMap<String, TrafficCounters>,
    fallback: &BTreeMap<String, RateWindowValue>,
    lan_raw: TrafficCounters,
    window_ms: u64,
) -> (BTreeMap<String, RateWindowValue>, bool, bool) {
    let mut clients = rate_window_clients(pending_raw, window_ms).unwrap_or_default();
    let lan_rate = lan_raw
        .fcs_normalized()
        .map(|counters| RateWindowValue {
            rx_bps: rate(counters.rx_bytes, window_ms),
            tx_bps: rate(counters.tx_bytes, window_ms),
        })
        .unwrap_or_default();
    let tx_reconciled = reconcile_rate_direction(&mut clients, lan_rate.rx_bps, false);
    let rx_reconciled = reconcile_rate_direction(&mut clients, lan_rate.tx_bps, true);
    let (tx_gap_filled, tx_gap_limited) =
        fill_fallback_direction(&mut clients, fallback, lan_rate.rx_bps, false);
    let (rx_gap_filled, rx_gap_limited) =
        fill_fallback_direction(&mut clients, fallback, lan_rate.tx_bps, true);
    (
        clients,
        tx_gap_filled || rx_gap_filled,
        tx_reconciled || rx_reconciled || tx_gap_limited || rx_gap_limited,
    )
}

fn high_rate_window_clients(
    pending_raw: &BTreeMap<String, TrafficCounters>,
    fallback: &BTreeMap<String, RateWindowValue>,
    lan_raw: TrafficCounters,
    client_interfaces: &BTreeMap<String, String>,
    interface_rates: &BTreeMap<String, RateWindowValue>,
    window_ms: u64,
) -> (BTreeMap<String, RateWindowValue>, bool, bool) {
    let mut clients = rate_window_clients(pending_raw, window_ms).unwrap_or_default();
    let raw_total = sum_rate_values(clients.values());
    let mut event_rate_selected = false;
    for (identity_key, fallback_rate) in fallback {
        let rate = clients.entry(identity_key.clone()).or_default();
        let (rx_bps, rx_event) = high_rate_direction(rate.rx_bps, fallback_rate.rx_bps);
        let (tx_bps, tx_event) = high_rate_direction(rate.tx_bps, fallback_rate.tx_bps);
        rate.rx_bps = rx_bps;
        rate.tx_bps = tx_bps;
        event_rate_selected |= rx_event || tx_event;
    }
    let lan_rate = lan_raw
        .fcs_normalized()
        .map(|counters| RateWindowValue {
            rx_bps: rate(counters.rx_bytes, window_ms),
            tx_bps: rate(counters.tx_bytes, window_ms),
        })
        .unwrap_or_default();
    let tx_reconciled =
        reconcile_high_rate_direction(&mut clients, lan_rate.rx_bps, raw_total.tx_bps, false);
    let rx_reconciled =
        reconcile_high_rate_direction(&mut clients, lan_rate.tx_bps, raw_total.rx_bps, true);
    let interface_reconciled =
        reconcile_high_rate_interfaces(&mut clients, client_interfaces, interface_rates);
    (
        clients,
        event_rate_selected,
        tx_reconciled || rx_reconciled || interface_reconciled,
    )
}

fn high_rate_direction(raw_bps: u64, event_bps: u64) -> (u64, bool) {
    if event_bps == 0 {
        return (raw_bps, false);
    }
    let raw = u128::from(raw_bps);
    let event = u128::from(event_bps);
    let comparable = event.saturating_mul(4) >= raw && raw.saturating_mul(4) >= event;
    let raw_missing =
        raw_bps < ECM_BPF_EVENT_HIGH_RATE_BPS && event_bps >= ECM_BPF_EVENT_HIGH_RATE_BPS;
    if raw_bps == 0 || comparable || raw_missing {
        (event_bps, true)
    } else {
        (raw_bps, false)
    }
}

fn high_rate_candidate_is_live(candidate: &EcmBpfRateBatch, previous: &EcmBpfRateBatch) -> bool {
    let candidate_rates = sum_rate_values(candidate.clients.values());
    let previous_rates = sum_rate_values(previous.clients.values());
    let candidate_peak = candidate_rates.tx_bps.max(candidate_rates.rx_bps);
    let previous_peak = previous_rates.tx_bps.max(previous_rates.rx_bps);
    if candidate.low_rate && candidate_peak < ECM_BPF_EVENT_HIGH_RATE_BPS {
        return false;
    }
    previous_peak == 0 || u128::from(candidate_peak).saturating_mul(2) >= u128::from(previous_peak)
}

fn sum_rate_values<'a>(values: impl Iterator<Item = &'a RateWindowValue>) -> RateWindowValue {
    values.fold(RateWindowValue::default(), |mut total, value| {
        total.rx_bps = total.rx_bps.saturating_add(value.rx_bps);
        total.tx_bps = total.tx_bps.saturating_add(value.tx_bps);
        total
    })
}

fn reconcile_high_rate_direction(
    clients: &mut BTreeMap<String, RateWindowValue>,
    lan_bps: u64,
    raw_client_bps: u64,
    receive: bool,
) -> bool {
    let physical_budget_valid = lan_bps >= ECM_BPF_EVENT_HIGH_RATE_BPS
        && (raw_client_bps == 0
            || u128::from(lan_bps).saturating_mul(2) >= u128::from(raw_client_bps));
    physical_budget_valid && reconcile_rate_direction(clients, lan_bps, receive)
}

fn reconcile_high_rate_interfaces(
    clients: &mut BTreeMap<String, RateWindowValue>,
    client_interfaces: &BTreeMap<String, String>,
    interface_rates: &BTreeMap<String, RateWindowValue>,
) -> bool {
    let mut groups = BTreeMap::<&str, Vec<&str>>::new();
    for (identity_key, interface) in client_interfaces {
        if clients.contains_key(identity_key) {
            groups
                .entry(interface.as_str())
                .or_default()
                .push(identity_key.as_str());
        }
    }

    let mut reconciled = false;
    for (interface, identity_keys) in groups {
        let Some(interface_rate) = interface_rates.get(interface) else {
            continue;
        };
        reconciled |=
            reconcile_high_rate_subset(clients, &identity_keys, interface_rate.rx_bps, false);
        reconciled |=
            reconcile_high_rate_subset(clients, &identity_keys, interface_rate.tx_bps, true);
    }
    reconciled
}

fn reconcile_high_rate_subset(
    clients: &mut BTreeMap<String, RateWindowValue>,
    identity_keys: &[&str],
    interface_bps: u64,
    receive: bool,
) -> bool {
    let total = identity_keys.iter().fold(0u128, |sum, identity_key| {
        let value = clients.get(*identity_key).copied().unwrap_or_default();
        sum.saturating_add(u128::from(if receive {
            value.rx_bps
        } else {
            value.tx_bps
        }))
    });
    let budget = u128::from(interface_bps);
    let budget_valid = interface_bps >= ECM_BPF_EVENT_HIGH_RATE_BPS
        && total > budget
        && budget.saturating_mul(5) >= total.saturating_mul(2);
    if !budget_valid {
        return false;
    }

    for identity_key in identity_keys {
        let Some(value) = clients.get_mut(*identity_key) else {
            continue;
        };
        let client_bps = if receive {
            &mut value.rx_bps
        } else {
            &mut value.tx_bps
        };
        let scaled = u128::from(*client_bps).saturating_mul(budget) / total;
        *client_bps = u64::try_from(scaled).unwrap_or(interface_bps);
    }
    true
}

fn reconcile_rate_direction(
    clients: &mut BTreeMap<String, RateWindowValue>,
    lan_bps: u64,
    receive: bool,
) -> bool {
    let total = clients.values().fold(0u128, |sum, value| {
        sum.saturating_add(u128::from(if receive {
            value.rx_bps
        } else {
            value.tx_bps
        }))
    });
    if total <= u128::from(lan_bps) {
        return false;
    }
    for value in clients.values_mut() {
        let client_bps = if receive {
            &mut value.rx_bps
        } else {
            &mut value.tx_bps
        };
        let scaled = u128::from(*client_bps).saturating_mul(u128::from(lan_bps)) / total;
        *client_bps = u64::try_from(scaled).unwrap_or(lan_bps);
    }
    true
}

fn fill_fallback_direction(
    clients: &mut BTreeMap<String, RateWindowValue>,
    fallback: &BTreeMap<String, RateWindowValue>,
    lan_bps: u64,
    receive: bool,
) -> (bool, bool) {
    let used = clients.values().fold(0u128, |sum, value| {
        sum.saturating_add(u128::from(if receive {
            value.rx_bps
        } else {
            value.tx_bps
        }))
    });
    let budget = u128::from(lan_bps).saturating_sub(used);
    let candidates = fallback
        .iter()
        .filter_map(|(identity_key, value)| {
            let current = clients.get(identity_key).map_or(0, |current| {
                if receive {
                    current.rx_bps
                } else {
                    current.tx_bps
                }
            });
            let fallback_bps = if receive { value.rx_bps } else { value.tx_bps };
            (current == 0 && fallback_bps != 0).then(|| (identity_key.clone(), fallback_bps))
        })
        .collect::<Vec<_>>();
    let total = candidates.iter().fold(0u128, |sum, (_, value)| {
        sum.saturating_add(u128::from(*value))
    });
    if total == 0 {
        return (false, false);
    }
    let limited = total > budget;
    let mut filled = false;
    for (identity_key, fallback_bps) in candidates {
        let assigned = if limited {
            u128::from(fallback_bps).saturating_mul(budget) / total
        } else {
            u128::from(fallback_bps)
        };
        let assigned = u64::try_from(assigned).unwrap_or(lan_bps);
        if assigned == 0 {
            continue;
        }
        let value = clients.entry(identity_key).or_default();
        if receive {
            value.rx_bps = assigned;
        } else {
            value.tx_bps = assigned;
        }
        filled = true;
    }
    (filled, limited)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NssWindowBook {
    initialized: bool,
    previous_sample_ms: Option<u64>,
    previous_lan: Option<LanClock>,
    previous_nodes: BTreeMap<(String, NodeKey), NodeBaseline>,
    tx_rate_histories: BTreeMap<(String, NodeKey), NodeRateHistory>,
    rx_rate_histories: BTreeMap<(String, NodeKey), NodeRateHistory>,
    committed_totals: BTreeMap<String, TrafficCounters>,
    published_rates: BTreeMap<String, PublishedClientRate>,
    coverage: NssCoverageBook,
}

impl NssWindowBook {
    pub fn update(&mut self, nodes: &NodeSnapshot, lan: LanClock) -> WindowOutput {
        if !self.initialized {
            self.rebaseline(nodes, lan.clone());
            return self.zero_output(
                WindowQuality::Warmup,
                "cold_start",
                nodes.sample_ms,
                CoverageWindow::empty(WindowQuality::Warmup, "cold_start", lan.sample_ms),
            );
        }

        let (Some(previous_sample_ms), Some(previous_lan)) =
            (self.previous_sample_ms, self.previous_lan.as_ref())
        else {
            self.rebaseline(nodes, lan.clone());
            return self.zero_output(
                WindowQuality::CounterReset,
                "missing_baseline",
                nodes.sample_ms,
                CoverageWindow::empty(
                    WindowQuality::CounterReset,
                    "missing_baseline",
                    lan.sample_ms,
                ),
            );
        };

        let reset_reason = if lan.interface != previous_lan.interface {
            Some("lan_boundary_changed")
        } else if nodes.sample_ms <= previous_sample_ms || lan.sample_ms <= previous_lan.sample_ms {
            Some("sample_clock_reset")
        } else if nodes.sample_ms.saturating_sub(previous_sample_ms) > MAX_RATE_WINDOW_MS {
            Some("ecm_sample_gap")
        } else if checked_delta(lan.counters, previous_lan.counters).is_none() {
            Some("lan_counter_reset")
        } else {
            None
        };
        if let Some(reason) = reset_reason {
            self.rebaseline(nodes, lan.clone());
            return self.zero_output(
                WindowQuality::CounterReset,
                reason,
                nodes.sample_ms,
                CoverageWindow::empty(WindowQuality::CounterReset, reason, lan.sample_ms),
            );
        }

        let node_deltas = match self.node_deltas(nodes, previous_sample_ms) {
            Ok(value) => value,
            Err(reason) => {
                self.rebaseline(nodes, lan.clone());
                return self.zero_output(
                    WindowQuality::CounterReset,
                    reason,
                    nodes.sample_ms,
                    CoverageWindow::empty(WindowQuality::CounterReset, reason, lan.sample_ms),
                );
            }
        };

        let coverage_delta = sum(node_deltas.values().map(|delta| delta.raw));
        self.previous_sample_ms = Some(nodes.sample_ms);
        self.previous_lan = Some(lan.clone());
        let coverage = self.coverage.update(coverage_delta, &lan);

        if node_deltas.values().any(ClientDelta::progressed) {
            self.publish_rate(nodes.sample_ms, node_deltas, coverage)
        } else {
            self.without_rate_progress(nodes.sample_ms, previous_sample_ms, coverage)
        }
    }

    fn node_deltas(
        &mut self,
        snapshot: &NodeSnapshot,
        previous_sample_ms: u64,
    ) -> Result<BTreeMap<String, ClientDelta>, &'static str> {
        self.previous_nodes.retain(|_, baseline| {
            snapshot
                .sample_ms
                .checked_sub(baseline.last_seen_ms)
                .is_none_or(|age| age <= NODE_BASELINE_RETENTION_MS)
        });
        let mut deltas = BTreeMap::<String, ClientDelta>::new();
        for node in &snapshot.nodes {
            let key = (
                node.identity_key.clone(),
                NodeKey {
                    generation: node.generation,
                },
            );
            let previous = self.previous_nodes.get(&key).copied();
            let delta = match previous {
                Some(previous) => checked_delta(node.counters, previous.counters)
                    .ok_or("ecm_node_counter_reset")?,
                // A new generation can already contain lifetime traffic. Its
                // first observation is a baseline; the next delta is valid.
                None => TrafficCounters::default(),
            };
            let mut last_progress_ms = previous
                .map(|baseline| baseline.last_progress_ms)
                .unwrap_or(snapshot.sample_ms);
            let client_delta = deltas.entry(node.identity_key.clone()).or_default();
            add_assign(&mut client_delta.raw, delta);
            if has_traffic(&delta) {
                let raw_start_ms = last_progress_ms;
                let start_ms =
                    if snapshot.sample_ms.saturating_sub(raw_start_ms) > MAX_RATE_WINDOW_MS {
                        // After a long idle period the counters do not reveal when
                        // traffic resumed. Use the adjacent collector poll rather
                        // than diluting the first live sample over the whole idle.
                        previous_sample_ms
                    } else {
                        raw_start_ms
                    };
                let window_ms = snapshot.sample_ms.saturating_sub(start_ms);
                let normalized = delta.fcs_normalized().ok_or("ecm_node_fcs_overflow")?;
                add_assign(&mut client_delta.normalized, normalized);
                client_delta.start_ms = Some(
                    client_delta
                        .start_ms
                        .map_or(start_ms, |current| current.min(start_ms)),
                );
                if normalized.tx_bytes != 0 {
                    let tx_bps = self
                        .tx_rate_histories
                        .entry(key.clone())
                        .or_default()
                        .push(rate(normalized.tx_bytes, window_ms));
                    client_delta.tx_bps = client_delta.tx_bps.saturating_add(tx_bps);
                }
                if normalized.rx_bytes != 0 {
                    let rx_bps = self
                        .rx_rate_histories
                        .entry(key.clone())
                        .or_default()
                        .push(rate(normalized.rx_bytes, window_ms));
                    client_delta.rx_bps = client_delta.rx_bps.saturating_add(rx_bps);
                }
                last_progress_ms = snapshot.sample_ms;
            }
            self.previous_nodes.insert(
                key,
                NodeBaseline {
                    counters: node.counters,
                    last_seen_ms: snapshot.sample_ms,
                    last_progress_ms,
                },
            );
        }
        self.tx_rate_histories
            .retain(|key, _| self.previous_nodes.contains_key(key));
        self.rx_rate_histories
            .retain(|key, _| self.previous_nodes.contains_key(key));
        Ok(deltas)
    }

    fn publish_rate(
        &mut self,
        end_ms: u64,
        deltas: BTreeMap<String, ClientDelta>,
        coverage: CoverageWindow,
    ) -> WindowOutput {
        let mut start_ms = end_ms;
        let mut sample_total = TrafficCounters::default();
        for (identity, delta) in deltas {
            add_assign(
                self.committed_totals.entry(identity.clone()).or_default(),
                delta.normalized,
            );
            if let Some(client_start_ms) = delta.start_ms {
                start_ms = start_ms.min(client_start_ms);
                add_assign(&mut sample_total, delta.normalized);
                self.published_rates.insert(
                    identity,
                    PublishedClientRate {
                        start_ms: client_start_ms,
                        end_ms,
                        delta: delta.normalized,
                        tx_bps: delta.tx_bps,
                        rx_bps: delta.rx_bps,
                    },
                );
            }
        }
        self.expire_published_rates(end_ms);
        let clients = self.visible_rate_clients();
        let quality =
            if sample_total.tx_bytes.saturating_add(sample_total.rx_bytes) < MIN_COVERAGE_BYTES {
                WindowQuality::LowTraffic
            } else {
                WindowQuality::Ok
            };
        WindowOutput {
            quality,
            reason: "ecm_node_delta_published",
            start_ms,
            end_ms,
            clients,
            fresh_rate_sample: true,
            held_rate_age_ms: None,
            coverage,
        }
    }

    fn without_rate_progress(
        &mut self,
        sample_ms: u64,
        previous_sample_ms: u64,
        coverage: CoverageWindow,
    ) -> WindowOutput {
        self.expire_published_rates(sample_ms);
        if !self.published_rates.is_empty() {
            let start_ms = self
                .published_rates
                .values()
                .map(|published| published.start_ms)
                .min()
                .unwrap_or(sample_ms);
            let end_ms = self
                .published_rates
                .values()
                .map(|published| published.end_ms)
                .max()
                .unwrap_or(sample_ms);
            let age = self
                .published_rates
                .values()
                .map(|published| sample_ms.saturating_sub(published.end_ms))
                .max()
                .unwrap_or_default();
            return WindowOutput {
                quality: WindowQuality::Pending,
                reason: "ecm_node_batch_pending",
                start_ms,
                end_ms,
                clients: self.visible_rate_clients(),
                fresh_rate_sample: false,
                held_rate_age_ms: Some(age),
                coverage,
            };
        }
        self.zero_output(
            WindowQuality::Idle,
            "ecm_node_idle",
            previous_sample_ms.min(sample_ms),
            coverage,
        )
    }

    fn expire_published_rates(&mut self, sample_ms: u64) {
        self.published_rates
            .retain(|_, published| sample_ms.saturating_sub(published.end_ms) <= RATE_HOLD_MS);
    }

    fn visible_rate_clients(&self) -> Vec<WindowClient> {
        self.committed_totals
            .iter()
            .map(|(identity_key, total)| {
                let published = self.published_rates.get(identity_key);
                WindowClient {
                    identity_key: identity_key.clone(),
                    delta: published.map_or_else(TrafficCounters::default, |rate| rate.delta),
                    total: *total,
                    tx_bps: published.map_or(0, |rate| rate.tx_bps),
                    rx_bps: published.map_or(0, |rate| rate.rx_bps),
                }
            })
            .collect()
    }

    fn rebaseline(&mut self, nodes: &NodeSnapshot, lan: LanClock) {
        self.initialized = true;
        self.previous_sample_ms = Some(nodes.sample_ms);
        self.previous_lan = Some(lan.clone());
        self.previous_nodes.clear();
        self.tx_rate_histories.clear();
        self.rx_rate_histories.clear();
        self.committed_totals.clear();
        for node in &nodes.nodes {
            self.previous_nodes.insert(
                (
                    node.identity_key.clone(),
                    NodeKey {
                        generation: node.generation,
                    },
                ),
                NodeBaseline {
                    counters: node.counters,
                    last_seen_ms: nodes.sample_ms,
                    last_progress_ms: nodes.sample_ms,
                },
            );
            if let Some(normalized) = node.counters.fcs_normalized() {
                add_assign(
                    self.committed_totals
                        .entry(node.identity_key.clone())
                        .or_default(),
                    normalized,
                );
            }
        }
        self.published_rates.clear();
        self.coverage.clear(lan);
    }

    fn zero_output(
        &self,
        quality: WindowQuality,
        reason: &'static str,
        sample_ms: u64,
        coverage: CoverageWindow,
    ) -> WindowOutput {
        WindowOutput {
            quality,
            reason,
            start_ms: sample_ms,
            end_ms: sample_ms,
            clients: self.visible_zero_clients(),
            fresh_rate_sample: true,
            held_rate_age_ms: None,
            coverage,
        }
    }

    fn visible_zero_clients(&self) -> Vec<WindowClient> {
        self.committed_totals
            .iter()
            .map(|(identity_key, total)| WindowClient {
                identity_key: identity_key.clone(),
                delta: TrafficCounters::default(),
                total: *total,
                tx_bps: 0,
                rx_bps: 0,
            })
            .collect()
    }
}

fn coverage_window(
    quality: WindowQuality,
    reason: &'static str,
    start: &LanClock,
    end: &LanClock,
    client_raw: TrafficCounters,
    client_normalized: TrafficCounters,
    lan_raw: TrafficCounters,
    lan_normalized: TrafficCounters,
    aligned: bool,
    percentages_available: bool,
) -> CoverageWindow {
    CoverageWindow {
        quality,
        reason,
        start_ms: start.sample_ms,
        end_ms: end.sample_ms,
        client_raw,
        client_normalized,
        lan_raw,
        lan_normalized,
        tx_pct: percentages_available
            .then(|| percentage(client_normalized.tx_bytes, lan_normalized.rx_bytes))
            .flatten(),
        rx_pct: percentages_available
            .then(|| percentage(client_normalized.rx_bytes, lan_normalized.tx_bytes))
            .flatten(),
        retained_tx_pct: None,
        retained_rx_pct: None,
        aligned,
    }
}

fn checked_delta(current: TrafficCounters, previous: TrafficCounters) -> Option<TrafficCounters> {
    Some(TrafficCounters {
        tx_bytes: current.tx_bytes.checked_sub(previous.tx_bytes)?,
        rx_bytes: current.rx_bytes.checked_sub(previous.rx_bytes)?,
        tx_packets: current.tx_packets.checked_sub(previous.tx_packets)?,
        rx_packets: current.rx_packets.checked_sub(previous.rx_packets)?,
    })
}

fn add_assign(total: &mut TrafficCounters, value: TrafficCounters) {
    total.tx_bytes = total.tx_bytes.saturating_add(value.tx_bytes);
    total.rx_bytes = total.rx_bytes.saturating_add(value.rx_bytes);
    total.tx_packets = total.tx_packets.saturating_add(value.tx_packets);
    total.rx_packets = total.rx_packets.saturating_add(value.rx_packets);
}

fn sum(values: impl IntoIterator<Item = TrafficCounters>) -> TrafficCounters {
    values
        .into_iter()
        .fold(TrafficCounters::default(), |mut total, value| {
            add_assign(&mut total, value);
            total
        })
}

fn has_traffic(value: &TrafficCounters) -> bool {
    value.tx_bytes != 0 || value.rx_bytes != 0 || value.tx_packets != 0 || value.rx_packets != 0
}

fn fits_lan_clock(client: TrafficCounters, lan: TrafficCounters) -> bool {
    if is_low_traffic_pair(client, lan) {
        return client.tx_bytes <= lan.rx_bytes
            && client.tx_packets <= lan.rx_packets
            && client.rx_bytes <= lan.tx_bytes
            && client.rx_packets <= lan.tx_packets;
    }
    aggregate_client_clock_ready(client, lan)
}

fn ownership_ready(client: TrafficCounters, lan: TrafficCounters) -> bool {
    is_low_traffic_pair(client, lan)
        || (aggregate_client_clock_ready(client, lan) && aggregate_lan_ownership_ready(client, lan))
}

fn directional_coverage_ready(client: TrafficCounters, lan: TrafficCounters) -> bool {
    client.tx_bytes <= lan.rx_bytes
        && client.tx_packets <= lan.rx_packets
        && client.rx_bytes <= lan.tx_bytes
        && client.rx_packets <= lan.tx_packets
}

fn aggregate_client_clock_ready(client: TrafficCounters, lan: TrafficCounters) -> bool {
    overlap_percent_ready(
        client.tx_bytes,
        client.rx_bytes,
        lan.rx_bytes,
        lan.tx_bytes,
        true,
    ) && overlap_percent_ready(
        client.tx_packets,
        client.rx_packets,
        lan.rx_packets,
        lan.tx_packets,
        true,
    )
}

fn aggregate_lan_ownership_ready(client: TrafficCounters, lan: TrafficCounters) -> bool {
    overlap_percent_ready(
        client.tx_bytes,
        client.rx_bytes,
        lan.rx_bytes,
        lan.tx_bytes,
        false,
    ) && overlap_percent_ready(
        client.tx_packets,
        client.rx_packets,
        lan.rx_packets,
        lan.tx_packets,
        false,
    )
}

fn overlap_percent_ready(
    client_tx: u64,
    client_rx: u64,
    lan_rx: u64,
    lan_tx: u64,
    against_client: bool,
) -> bool {
    let matched = client_tx.min(lan_rx).saturating_add(client_rx.min(lan_tx));
    let denominator = if against_client {
        client_tx.saturating_add(client_rx)
    } else {
        lan_rx.saturating_add(lan_tx)
    };
    u128::from(matched).saturating_mul(100)
        >= u128::from(denominator).saturating_mul(u128::from(MIN_OWNERSHIP_PERCENT))
}

fn is_low_traffic_pair(client: TrafficCounters, lan: TrafficCounters) -> bool {
    let total_bytes = |value: TrafficCounters| {
        value
            .fcs_normalized()
            .map(|value| value.tx_bytes.saturating_add(value.rx_bytes))
            .unwrap_or(u64::MAX)
    };
    total_bytes(client).max(total_bytes(lan)) < MIN_COVERAGE_BYTES
}

fn rate(bytes: u64, window_ms: u64) -> u64 {
    if window_ms == 0 {
        return 0;
    }
    let scaled = u128::from(bytes).saturating_mul(8_000) / u128::from(window_ms);
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

fn percentage(numerator: u64, denominator: u64) -> Option<u8> {
    if denominator == 0 || numerator > denominator {
        return None;
    }
    let value = u128::from(numerator).saturating_mul(100) / u128::from(denominator);
    u8::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::nss::ecm_node::{NodeCounters, ParseStats};

    fn traffic(tx_bytes: u64, rx_bytes: u64, tx_packets: u64, rx_packets: u64) -> TrafficCounters {
        TrafficCounters {
            tx_bytes,
            rx_bytes,
            tx_packets,
            rx_packets,
        }
    }

    fn nodes(ms: u64, counters: TrafficCounters) -> NodeSnapshot {
        NodeSnapshot {
            sample_ms: ms,
            nodes: vec![NodeCounters {
                identity_key: "02:00:00:00:20:11@lan".into(),
                generation: 7,
                counters,
            }],
            stats: ParseStats::default(),
        }
    }

    fn two_nodes(ms: u64, first: TrafficCounters, second: TrafficCounters) -> NodeSnapshot {
        NodeSnapshot {
            sample_ms: ms,
            nodes: vec![
                NodeCounters {
                    identity_key: "02:00:00:00:20:11@lan".into(),
                    generation: 7,
                    counters: first,
                },
                NodeCounters {
                    identity_key: "02:00:00:00:20:12@lan".into(),
                    generation: 8,
                    counters: second,
                },
            ],
            stats: ParseStats::default(),
        }
    }

    fn lan(ms: u64, counters: TrafficCounters) -> LanClock {
        LanClock {
            interface: "lan2".into(),
            sample_ms: ms,
            counters,
        }
    }

    fn interface_counters(
        rx_bytes: u64,
        tx_bytes: u64,
    ) -> BTreeMap<String, RateWindowInterfaceCounter> {
        BTreeMap::from([(
            "br-lan".into(),
            RateWindowInterfaceCounter { rx_bytes, tx_bytes },
        )])
    }

    #[test]
    fn ecm_bpf_low_rate_warms_for_six_seconds_then_rolls_every_two() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let delta = traffic(10_000, 20_000, 10, 20);
        let mut book = EcmBpfRateWindowBook::default();
        assert_eq!(
            book.update(
                &BTreeMap::new(),
                &BTreeMap::new(),
                &lan(0, TrafficCounters::default()),
                &interface_counters(0, 0),
            ),
            None
        );

        for step in 1u64..3 {
            let clients = BTreeMap::from([(identity.clone(), delta)]);
            let output = book.update(
                &clients,
                &BTreeMap::new(),
                &lan(
                    step * 2_000,
                    traffic(22_000 * step, 12_000 * step, 22 * step, 12 * step),
                ),
                &interface_counters(12_048 * step, 22_088 * step),
            );
            assert_eq!(output, None);
        }

        let published = book
            .update(
                &BTreeMap::from([(identity.clone(), delta)]),
                &BTreeMap::new(),
                &lan(6_000, traffic(66_000, 36_000, 66, 36)),
                &interface_counters(36_144, 66_264),
            )
            .expect("six-second low-rate batch");
        assert!(published.fresh);
        assert_eq!(published.window_ms(), 6_000);
        assert_eq!(published.end_ms, 6_000);
        assert_eq!(published.clients[&identity].tx_bps, rate(30_120, 6_000));
        assert_eq!(published.clients[&identity].rx_bps, rate(60_240, 6_000));
        assert_eq!(published.interfaces["br-lan"].rx_bps, rate(36_144, 6_000));
        assert!(!published.fallback_event_gap_filled);
        assert!(!published.fallback_lan_reconciled);

        let held = book.held_at(7_000).expect("previous complete batch");
        assert!(!held.fresh);
        assert_eq!(held.end_ms, 6_000);
        assert_eq!(held.held_age_ms, Some(1_000));
        assert_eq!(held.clients, published.clients);
        assert_eq!(held.interfaces, published.interfaces);

        let rolled = book
            .update(
                &BTreeMap::from([(identity, delta)]),
                &BTreeMap::new(),
                &lan(8_000, traffic(88_000, 48_000, 88, 48)),
                &interface_counters(48_192, 88_352),
            )
            .expect("two-second rolling batch");
        assert!(rolled.fresh);
        assert_eq!(rolled.start_ms, 0);
        assert_eq!(rolled.end_ms, 8_000);
        assert_eq!(rolled.window_ms(), 8_000);
        assert_eq!(rolled.clients, published.clients);
        assert_eq!(rolled.interfaces, published.interfaces);
    }

    #[test]
    fn ecm_bpf_low_rate_rolling_window_weights_bursts_and_trims_to_eighteen_seconds() {
        let segment = |start_ms, end_ms, tx_bps, rx_bps| EcmBpfRateBatch {
            start_ms,
            end_ms,
            clients: BTreeMap::from([("client".into(), RateWindowValue { tx_bps, rx_bps })]),
            interfaces: BTreeMap::from([(
                "br-lan".into(),
                RateWindowValue {
                    rx_bps: tx_bps,
                    tx_bps: rx_bps,
                },
            )]),
            raw_aligned: true,
            fallback_event_gap_filled: false,
            fallback_lan_reconciled: false,
            low_rate: true,
            fresh: true,
            held_age_ms: None,
        };
        let mut book = EcmBpfRateWindowBook::default();
        let first = book.publish_rate_segment(segment(0, 6_000, 15_000, 10_000), true);
        assert_eq!(first.window_ms(), 6_000);
        let second = book.publish_rate_segment(segment(6_000, 8_000, 31_000, 20_000), true);
        assert_eq!(second.window_ms(), 8_000);
        assert_eq!(
            second.clients["client"].tx_bps,
            (15_000 * 6_000 + 31_000 * 2_000) / 8_000
        );

        for (start_ms, end_ms, tx_bps) in [
            (8_000, 10_000, 1_000),
            (10_000, 12_000, 2_000),
            (12_000, 14_000, 3_000),
            (14_000, 16_000, 4_000),
            (16_000, 18_000, 5_000),
            (18_000, 20_000, 6_000),
        ] {
            book.publish_rate_segment(segment(start_ms, end_ms, tx_bps, tx_bps), true);
        }
        let trimmed = book.published.as_ref().expect("rolling publication");
        assert_eq!(trimmed.start_ms, 2_000);
        assert_eq!(trimmed.end_ms, 20_000);
        assert_eq!(trimmed.window_ms(), ECM_BPF_LOW_RATE_ROLLING_WINDOW_MS);
    }

    #[test]
    fn ecm_bpf_burst_waits_for_the_lan_counter_then_publishes_once() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        let pending = book.update(
            &BTreeMap::from([(identity.clone(), traffic(200_000, 0, 200, 0))]),
            &BTreeMap::new(),
            &lan(2_000, traffic(0, 100_000, 0, 100)),
            &interface_counters(100_400, 0),
        );
        assert_eq!(pending, None);

        let aligned = book
            .update(
                &BTreeMap::new(),
                &BTreeMap::new(),
                &lan(4_000, traffic(0, 250_000, 0, 250)),
                &interface_counters(251_000, 0),
            )
            .expect("LAN counter catch-up");
        assert_eq!(aligned.window_ms(), 4_000);
        assert_eq!(aligned.clients[&identity].tx_bps, rate(200_800, 4_000));
        assert!(aligned.clients[&identity].tx_bps < aligned.interfaces["br-lan"].rx_bps);
        assert!(aligned.raw_aligned);
        assert!(!aligned.fallback_event_gap_filled);
        assert!(!aligned.fallback_lan_reconciled);
    }

    #[test]
    fn ecm_bpf_low_rate_prefers_shared_raw_and_reconciles_to_lan() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback = |tx_bps, rx_bps| {
            BTreeMap::from([(identity.clone(), RateWindowValue { tx_bps, rx_bps })])
        };
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        for step in 1u64..3 {
            let output = book.update(
                &BTreeMap::from([(identity.clone(), traffic(5_000, 10_000, 5, 10))]),
                &fallback(1_000_000, 2_000_000),
                &lan(
                    step * 2_000,
                    traffic(9_000 * step, 6_000 * step, 9 * step, 6 * step),
                ),
                &interface_counters(6_024 * step, 9_036 * step),
            );
            assert_eq!(output, None);
        }

        let published = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(5_000, 10_000, 5, 10))]),
                &fallback(1_000_000, 2_000_000),
                &lan(6_000, traffic(27_000, 18_000, 27, 18)),
                &interface_counters(18_072, 27_108),
            )
            .expect("raw-preferred fallback batch");
        assert!(published.fresh);
        assert!(!published.raw_aligned);
        assert_eq!(published.window_ms(), 6_000);
        assert_eq!(published.clients[&identity].tx_bps, rate(15_060, 6_000));
        assert_eq!(published.clients[&identity].rx_bps, rate(27_108, 6_000));
        assert_eq!(published.interfaces["br-lan"].rx_bps, rate(18_072, 6_000));
        assert!(!published.fallback_event_gap_filled);
        assert!(published.fallback_lan_reconciled);
    }

    #[test]
    fn ecm_bpf_low_rate_uses_event_rate_only_for_a_missing_raw_direction() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 1_000_000,
                rx_bps: 12_000,
            },
        )]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        for step in 1u64..=3 {
            let output = book.update(
                &BTreeMap::from([(identity.clone(), traffic(5_000, 0, 5, 0))]),
                &fallback,
                &lan(
                    step * 2_000,
                    traffic(3_000 * step, 6_000 * step, 3 * step, 4 * step),
                ),
                &interface_counters(6_016 * step, 3_012 * step),
            );
            if step < 3 {
                assert_eq!(output, None);
                continue;
            }
            let published = output.expect("event gap-fill batch");
            assert_eq!(published.clients[&identity].tx_bps, rate(15_060, 6_000));
            assert_eq!(published.clients[&identity].rx_bps, 12_000);
            assert!(published.fallback_event_gap_filled);
            assert!(!published.fallback_lan_reconciled);
        }
    }

    #[test]
    fn ecm_bpf_high_rate_prefers_the_single_event_source_without_summing() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 100_000_000,
                rx_bps: 0,
            },
        )]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        for step in 1u64..=4 {
            let output = book.update(
                &BTreeMap::from([(identity.clone(), traffic(10_000, 0, 10, 0))]),
                &fallback,
                &lan(step * 2_000, traffic(0, 100 * step, 0, step)),
                &interface_counters(104 * step, 0),
            );
            if step < 3 {
                assert_eq!(output, None);
                continue;
            }
            let published = output.expect("high event-rate batch");
            assert!(!published.low_rate);
            assert!(!published.raw_aligned);
            assert_eq!(published.clients[&identity].tx_bps, 100_000_000);
            assert!(published.fallback_event_gap_filled);
            assert!(!published.fallback_lan_reconciled);
            if step == 4 {
                assert_eq!(published.window_ms(), 2_000);
            }
        }
    }

    #[test]
    fn ecm_bpf_high_rate_uses_event_clock_for_a_batched_raw_delta() {
        let identity = "client@lan".to_owned();
        let pending = BTreeMap::from([(identity.clone(), traffic(500_000_000, 0, 0, 0))]);
        let fallback = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 1_000_000_000,
                rx_bps: 0,
            },
        )]);

        let (clients, event_selected, reconciled) = high_rate_window_clients(
            &pending,
            &fallback,
            TrafficCounters::default(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            2_000,
        );

        assert_eq!(rate(500_000_000, 2_000), 2_000_000_000);
        assert_eq!(clients[&identity].tx_bps, 1_000_000_000);
        assert!(event_selected);
        assert!(!reconciled);
    }

    #[test]
    fn ecm_bpf_high_rate_caps_event_overage_to_a_valid_lan_budget() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 140_000_000,
                rx_bps: 0,
            },
        )]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );

        for step in 1u64..=3 {
            let output = book.update(
                &BTreeMap::from([(identity.clone(), traffic(10_000, 0, 10, 0))]),
                &fallback,
                &lan(step * 2_000, traffic(0, 15_000_000 * step, 0, 0)),
                &interface_counters(15_000_000 * step, 0),
            );
            if step < 3 {
                assert_eq!(output, None);
                continue;
            }
            let published = output.expect("high event-rate batch");
            assert_eq!(published.clients[&identity].tx_bps, 60_000_000);
            assert!(published.fallback_event_gap_filled);
            assert!(published.fallback_lan_reconciled);
        }
    }

    #[test]
    fn ecm_bpf_high_rate_holds_through_a_transient_empty_window() {
        let identity = "02:00:00:00:20:11@lan".to_owned();
        let fallback = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 100_000_000,
                rx_bps: 0,
            },
        )]);
        let mut book = EcmBpfRateWindowBook::default();
        book.update(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &lan(0, TrafficCounters::default()),
            &interface_counters(0, 0),
        );
        for step in 1u64..=3 {
            let output = book.update(
                &BTreeMap::from([(identity.clone(), traffic(10_000, 0, 10, 0))]),
                &fallback,
                &lan(step * 2_000, traffic(0, 1_000 * step, 0, 0)),
                &interface_counters(1_000 * step, 0),
            );
            if step < 3 {
                assert_eq!(output, None);
                continue;
            }
            assert_eq!(
                output.expect("initial high batch").clients[&identity].tx_bps,
                100_000_000
            );
        }

        for (sample_ms, expected_age) in [(8_000, 2_000), (10_000, 4_000)] {
            let held = book
                .update(
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &lan(sample_ms, traffic(0, 3_000, 0, 0)),
                    &interface_counters(3_000, 0),
                )
                .expect("previous high batch");
            assert!(!held.fresh);
            assert_eq!(held.held_age_ms, Some(expected_age));
            assert_eq!(held.clients[&identity].tx_bps, 100_000_000);
        }

        let recovered = book
            .update(
                &BTreeMap::from([(identity.clone(), traffic(10_000, 0, 10, 0))]),
                &fallback,
                &lan(12_000, traffic(0, 4_000, 0, 0)),
                &interface_counters(4_000, 0),
            )
            .expect("recovered high batch");
        assert!(recovered.fresh);
        assert!(!recovered.low_rate);
        assert_eq!(recovered.clients[&identity].tx_bps, 100_000_000);

        for sample_ms in [14_000, 16_000, 18_000, 20_000, 22_000] {
            let held = book
                .update(
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    &lan(sample_ms, traffic(0, 4_000, 0, 0)),
                    &interface_counters(4_000, 0),
                )
                .expect("high batch during quiet confirmation");
            assert!(!held.fresh);
            assert_eq!(held.clients[&identity].tx_bps, 100_000_000);
        }
        let low = book
            .update(
                &BTreeMap::new(),
                &BTreeMap::new(),
                &lan(24_000, traffic(0, 4_000, 0, 0)),
                &interface_counters(4_000, 0),
            )
            .expect("confirmed low-rate batch");
        assert!(low.fresh);
        assert!(low.low_rate);
        assert_eq!(low.clients.get(&identity), None);
    }

    #[test]
    fn ecm_bpf_high_rate_liveness_is_relative_for_midrate_traffic() {
        let batch = |tx_bps, low_rate| EcmBpfRateBatch {
            start_ms: 0,
            end_ms: 2_000,
            clients: BTreeMap::from([("client".into(), RateWindowValue { tx_bps, rx_bps: 0 })]),
            interfaces: BTreeMap::new(),
            raw_aligned: true,
            fallback_event_gap_filled: false,
            fallback_lan_reconciled: false,
            low_rate,
            fresh: true,
            held_age_ms: None,
        };
        let previous = batch(5_000_000, false);

        assert!(high_rate_candidate_is_live(
            &batch(5_000_000, false),
            &previous
        ));
        assert!(!high_rate_candidate_is_live(
            &batch(10_000, false),
            &previous
        ));
        assert!(!high_rate_candidate_is_live(
            &batch(5_000_000, true),
            &previous
        ));
    }

    #[test]
    fn ecm_bpf_lan_reconciliation_preserves_client_proportions() {
        let mut clients = BTreeMap::from([
            (
                "first".into(),
                RateWindowValue {
                    tx_bps: 100,
                    rx_bps: 10,
                },
            ),
            (
                "second".into(),
                RateWindowValue {
                    tx_bps: 300,
                    rx_bps: 20,
                },
            ),
        ]);
        assert!(reconcile_rate_direction(&mut clients, 200, false));
        assert_eq!(clients["first"].tx_bps, 50);
        assert_eq!(clients["second"].tx_bps, 150);
        assert!(!reconcile_rate_direction(&mut clients, 30, true));
    }

    #[test]
    fn ecm_bpf_high_rate_uses_the_discovered_interface_budget() {
        let identity = "client@lan".to_owned();
        let mut clients = BTreeMap::from([(
            identity.clone(),
            RateWindowValue {
                tx_bps: 1_898_000_000,
                rx_bps: 2_000_000,
            },
        )]);
        let client_interfaces = BTreeMap::from([(identity.clone(), "bridge-dynamic".to_owned())]);
        let interface_rates = BTreeMap::from([(
            "bridge-dynamic".to_owned(),
            RateWindowValue {
                rx_bps: 989_000_000,
                tx_bps: 3_000_000,
            },
        )]);

        assert!(reconcile_high_rate_interfaces(
            &mut clients,
            &client_interfaces,
            &interface_rates,
        ));
        assert_eq!(clients[&identity].tx_bps, 989_000_000);
        assert_eq!(clients[&identity].rx_bps, 2_000_000);
    }

    #[test]
    fn ecm_bpf_event_gap_fill_uses_only_the_remaining_lan_budget() {
        let mut clients = BTreeMap::from([
            (
                "raw".into(),
                RateWindowValue {
                    tx_bps: 80,
                    rx_bps: 0,
                },
            ),
            ("gap".into(), RateWindowValue::default()),
        ]);
        let fallback = BTreeMap::from([(
            "gap".into(),
            RateWindowValue {
                tx_bps: 100,
                rx_bps: 0,
            },
        )]);
        let (filled, limited) = fill_fallback_direction(&mut clients, &fallback, 100, false);
        assert!(filled);
        assert!(limited);
        assert_eq!(clients["raw"].tx_bps, 80);
        assert_eq!(clients["gap"].tx_bps, 20);
    }

    #[test]
    fn first_delta_after_cold_start_publishes_without_a_second_settle_cycle() {
        let mut book = NssWindowBook::default();
        let warmup = book.update(&nodes(0, traffic(0, 0, 0, 0)), lan(0, traffic(0, 0, 0, 0)));
        assert_eq!(warmup.quality, WindowQuality::Warmup);

        let published = book.update(
            &nodes(1_000, traffic(100_000, 200_000, 100, 200)),
            lan(1_000, traffic(200_000, 100_000, 200, 100)),
        );
        assert_eq!(published.quality, WindowQuality::Ok);
        assert_eq!(published.reason, "ecm_node_delta_published");
        assert_eq!(published.window_ms(), 1_000);
        assert_eq!(published.clients[0].tx_bps, (100_000 + 400) * 8);
        assert_eq!(published.coverage.quality, WindowQuality::Ok);
    }

    #[test]
    fn one_node_destroy_batch_outlier_does_not_spike_the_client_rate() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );

        for (sample_ms, bytes) in [(2_000, 2_000), (4_000, 4_000), (6_000, 6_000)] {
            let output = book.update(
                &nodes(sample_ms, traffic(bytes, 0, 0, 0)),
                lan(sample_ms, traffic(0, bytes, 0, 0)),
            );
            assert_eq!(output.clients[0].tx_bps, 8_000);
        }

        let destroy = book.update(
            &nodes(8_000, traffic(10_000, 0, 0, 0)),
            lan(8_000, traffic(0, 10_000, 0, 0)),
        );
        assert_eq!(destroy.clients[0].tx_bps, 8_000);
    }

    #[test]
    fn two_second_node_progress_uses_the_real_counter_window_not_the_last_poll() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        let idle = book.update(
            &nodes(1_000, TrafficCounters::default()),
            lan(1_000, TrafficCounters::default()),
        );
        assert_eq!(idle.quality, WindowQuality::Idle);

        let first = book.update(
            &nodes(2_000, traffic(200_000_000, 100_000_000, 200_000, 100_000)),
            lan(2_000, traffic(100_000_000, 200_000_000, 100_000, 200_000)),
        );
        assert_eq!(first.window_ms(), 2_000);
        assert_eq!(first.clients[0].tx_bps, rate(200_000_000 + 800_000, 2_000));
        assert_eq!(first.clients[0].rx_bps, rate(100_000_000 + 400_000, 2_000));

        let held = book.update(
            &nodes(3_000, traffic(200_000_000, 100_000_000, 200_000, 100_000)),
            lan(3_000, traffic(100_000_000, 200_000_000, 100_000, 200_000)),
        );
        assert_eq!(held.reason, "ecm_node_batch_pending");
        assert_eq!(held.clients[0].tx_bps, first.clients[0].tx_bps);

        let second = book.update(
            &nodes(4_000, traffic(400_000_000, 200_000_000, 400_000, 200_000)),
            lan(4_000, traffic(200_000_000, 400_000_000, 200_000, 400_000)),
        );
        assert_eq!(second.window_ms(), 2_000);
        assert_eq!(second.clients[0].tx_bps, first.clients[0].tx_bps);
        assert_eq!(second.clients[0].rx_bps, first.clients[0].rx_bps);
    }

    #[test]
    fn another_nodes_fresh_batch_does_not_zero_a_client_waiting_for_its_batch() {
        let mut book = NssWindowBook::default();
        book.update(
            &two_nodes(0, TrafficCounters::default(), TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        let first = book.update(
            &two_nodes(
                1_000,
                traffic(100_000_000, 50_000_000, 100_000, 50_000),
                TrafficCounters::default(),
            ),
            lan(1_000, traffic(50_000_000, 100_000_000, 50_000, 100_000)),
        );
        let first_rate = first
            .clients
            .iter()
            .find(|client| client.identity_key == "02:00:00:00:20:11@lan")
            .unwrap()
            .tx_bps;
        assert!(first_rate > 0);

        let second = book.update(
            &two_nodes(
                2_000,
                traffic(100_000_000, 50_000_000, 100_000, 50_000),
                traffic(200_000_000, 100_000_000, 200_000, 100_000),
            ),
            lan(2_000, traffic(150_000_000, 300_000_000, 150_000, 300_000)),
        );
        assert_eq!(second.reason, "ecm_node_delta_published");
        assert_eq!(
            second
                .clients
                .iter()
                .find(|client| client.identity_key == "02:00:00:00:20:11@lan")
                .unwrap()
                .tx_bps,
            first_rate
        );
        assert!(
            second
                .clients
                .iter()
                .find(|client| client.identity_key == "02:00:00:00:20:12@lan")
                .unwrap()
                .tx_bps
                > 0
        );
    }

    #[test]
    fn newly_observed_generation_baselines_once_then_publishes_its_next_delta() {
        let mut book = NssWindowBook::default();
        let empty = NodeSnapshot {
            sample_ms: 0,
            nodes: Vec::new(),
            stats: ParseStats::default(),
        };
        book.update(&empty, lan(0, TrafficCounters::default()));

        let baseline = book.update(
            &nodes(1_000, traffic(900_000, 1_800_000, 900, 1_800)),
            lan(1_000, traffic(10_000, 10_000, 10, 10)),
        );
        assert_eq!(baseline.quality, WindowQuality::Idle);

        let published = book.update(
            &nodes(2_000, traffic(910_000, 1_820_000, 910, 1_820)),
            lan(2_000, traffic(30_000, 20_000, 30, 20)),
        );
        assert_eq!(published.reason, "ecm_node_delta_published");
        assert_eq!(published.clients[0].delta, traffic(10_040, 20_080, 10, 20));
        assert!(published.clients[0].tx_bps > 0);
    }

    #[test]
    fn lan_clock_lag_never_blocks_a_fresh_client_rate() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );

        let output = book.update(
            &nodes(1_000, traffic(1_000_000, 2_000_000, 1_000, 2_000)),
            lan(1_000, traffic(500_000, 250_000, 500, 250)),
        );
        assert_eq!(output.quality, WindowQuality::Ok);
        assert!(output.clients[0].rx_bps > 0);
        assert_eq!(output.coverage.quality, WindowQuality::Pending);
        assert_eq!(output.coverage.reason, "lan_coverage_pending");
    }

    #[test]
    fn continuous_node_progress_cannot_restart_the_coverage_timeout() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        let mut last = None;
        for second in 1..=7 {
            let value = second * 1_000_000;
            last = Some(book.update(
                &nodes(
                    second * 1_000,
                    traffic(value, value, second * 1_000, second * 1_000),
                ),
                lan(second * 1_000, traffic(100_000, 100_000, 100, 100)),
            ));
        }
        let output = last.unwrap();
        assert_eq!(output.quality, WindowQuality::Ok);
        assert_eq!(output.coverage.quality, WindowQuality::CounterSkew);
        assert_eq!(output.coverage.reason, "lan_coverage_timeout");
    }

    #[test]
    fn old_rate_is_held_for_one_ecm_cycle_then_becomes_zero() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        let published = book.update(
            &nodes(1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
            lan(1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        let held = book.update(
            &nodes(2_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
            lan(2_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        assert_eq!(held.quality, WindowQuality::Pending);
        assert_eq!(held.clients, published.clients);
        assert_eq!(held.held_rate_age_ms, Some(1_000));

        let idle = book.update(
            &nodes(3_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
            lan(3_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        assert_eq!(idle.quality, WindowQuality::Idle);
        assert_eq!(idle.clients[0].tx_bps, 0);
        assert_eq!(idle.clients[0].rx_bps, 0);
    }

    #[test]
    fn traffic_after_a_long_idle_uses_only_the_adjacent_poll_interval() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        book.update(
            &nodes(1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
            lan(1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        for second in 2..=119 {
            book.update(
                &nodes(second * 1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
                lan(second * 1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
            );
        }
        let resumed = book.update(
            &nodes(120_000, traffic(2_000_000, 2_000_000, 2_000, 2_000)),
            lan(120_000, traffic(2_000_000, 2_000_000, 2_000, 2_000)),
        );
        assert_eq!(resumed.start_ms, 119_000);
        assert_eq!(resumed.window_ms(), 1_000);
        assert_eq!(resumed.clients[0].tx_bps, (1_000_000 + 4_000) * 8);
    }

    #[test]
    fn a_collection_gap_rebaselines_instead_of_publishing_a_long_average() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );
        let gap = book.update(
            &nodes(120_000, traffic(100_000_000, 100_000_000, 100_000, 100_000)),
            lan(120_000, traffic(100_000_000, 100_000_000, 100_000, 100_000)),
        );
        assert_eq!(gap.quality, WindowQuality::CounterReset);
        assert_eq!(gap.reason, "ecm_sample_gap");
        assert_eq!(gap.window_ms(), 0);
        assert!(gap.clients.iter().all(|client| client.tx_bps == 0));
    }

    #[test]
    fn partial_client_batches_publish_partial_coverage_without_waiting_for_full_ownership() {
        let snapshot = |sample_ms, first: TrafficCounters, second: TrafficCounters| NodeSnapshot {
            sample_ms,
            nodes: vec![
                NodeCounters {
                    identity_key: "02:00:00:00:20:11@lan".into(),
                    generation: 7,
                    counters: first,
                },
                NodeCounters {
                    identity_key: "02:00:00:00:20:12@lan".into(),
                    generation: 8,
                    counters: second,
                },
            ],
            stats: ParseStats::default(),
        };
        let mut book = NssWindowBook::default();
        book.update(
            &snapshot(0, TrafficCounters::default(), TrafficCounters::default()),
            lan(0, TrafficCounters::default()),
        );

        let first = book.update(
            &snapshot(
                1_000,
                traffic(100_000, 100_000, 100, 100),
                TrafficCounters::default(),
            ),
            lan(1_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        assert!(first.clients.iter().any(|client| client.tx_bps > 0));
        assert_eq!(first.coverage.quality, WindowQuality::Ok);
        assert_eq!(first.coverage.tx_pct, Some(10));
        assert_eq!(first.coverage.rx_pct, Some(10));

        let second = book.update(
            &snapshot(
                2_000,
                traffic(100_000, 100_000, 100, 100),
                traffic(900_000, 900_000, 900, 900),
            ),
            lan(2_000, traffic(1_000_000, 1_000_000, 1_000, 1_000)),
        );
        assert_eq!(second.coverage.quality, WindowQuality::Ok);
        assert_eq!(second.coverage.start_ms, 0);
        assert_eq!(second.coverage.tx_pct, Some(100));
        assert_eq!(second.coverage.rx_pct, Some(100));
    }

    #[test]
    fn packet_aware_low_traffic_reports_a_real_percentage() {
        let mut coverage = NssCoverageBook::default();
        let warmup = coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );
        assert_eq!(warmup.quality, WindowQuality::Warmup);

        let output = coverage.update(
            traffic(10_000, 20_000, 2_500, 5_000),
            &lan(2_000, traffic(20_000, 10_000, 5_000, 2_500)),
        );

        assert_eq!(output.quality, WindowQuality::LowTraffic);
        assert!(output.aligned);
        assert_eq!(
            output.client_normalized,
            traffic(20_000, 40_000, 2_500, 5_000)
        );
        assert_eq!(
            output.client_normalized.tx_bytes,
            output.lan_normalized.rx_bytes
        );
        assert_eq!(
            output.client_normalized.rx_bytes,
            output.lan_normalized.tx_bytes
        );
        assert_eq!(
            output.client_normalized.tx_packets,
            output.lan_normalized.rx_packets
        );
        assert_eq!(
            output.client_normalized.rx_packets,
            output.lan_normalized.tx_packets
        );
        assert_eq!(output.tx_pct, Some(100));
        assert_eq!(output.rx_pct, Some(100));
    }

    #[test]
    fn coverage_waits_for_a_late_lan_batch_then_aligns_the_original_window() {
        let mut coverage = NssCoverageBook::default();
        coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );

        let pending = coverage.update(
            traffic(200_000, 400_000, 200, 400),
            &lan(2_000, traffic(200_000, 100_000, 200, 100)),
        );
        assert_eq!(pending.quality, WindowQuality::Pending);
        assert_eq!(pending.start_ms, 0);

        let aligned = coverage.update(
            TrafficCounters::default(),
            &lan(4_000, traffic(400_000, 200_000, 400, 200)),
        );
        assert_eq!(aligned.quality, WindowQuality::Ok);
        assert_eq!(aligned.start_ms, 0);
        assert_eq!(aligned.end_ms, 4_000);
        assert_eq!(aligned.tx_pct, Some(100));
        assert_eq!(aligned.rx_pct, Some(100));
    }

    #[test]
    fn pending_window_retains_only_the_last_aligned_percentage_for_display() {
        let mut coverage = NssCoverageBook::default();
        coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );

        let published = coverage.update(
            traffic(200_000, 400_000, 200, 400),
            &lan(2_000, traffic(400_000, 200_000, 400, 200)),
        );
        assert_eq!(published.quality, WindowQuality::Ok);
        assert_eq!(published.tx_pct, Some(100));
        assert_eq!(published.rx_pct, Some(100));

        let pending = coverage.update(
            traffic(400_000, 400_000, 400, 400),
            &lan(4_000, traffic(500_000, 300_000, 500, 300)),
        );
        assert_eq!(pending.quality, WindowQuality::Pending);
        assert_eq!(pending.tx_pct, None);
        assert_eq!(pending.rx_pct, None);
        assert_eq!(pending.retained_tx_pct, Some(100));
        assert_eq!(pending.retained_rx_pct, Some(100));

        let aligned = coverage.update(
            TrafficCounters::default(),
            &lan(6_000, traffic(800_000, 600_000, 800, 600)),
        );
        assert_eq!(aligned.quality, WindowQuality::Ok);
        assert_eq!(aligned.tx_pct, Some(100));
        assert_eq!(aligned.rx_pct, Some(100));
        assert_eq!(aligned.retained_tx_pct, None);
        assert_eq!(aligned.retained_rx_pct, None);
    }

    #[test]
    fn pending_window_publishes_the_current_reportable_direction_without_clamping() {
        let mut coverage = NssCoverageBook::default();
        coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );
        coverage.update(
            traffic(200_000, 400_000, 200, 400),
            &lan(2_000, traffic(400_000, 200_000, 400, 200)),
        );

        let pending = coverage.update(
            traffic(50_000, 200_000, 50, 200),
            &lan(4_000, traffic(500_000, 300_000, 500, 300)),
        );

        assert_eq!(pending.quality, WindowQuality::Pending);
        assert_eq!(pending.tx_pct, Some(50));
        assert_eq!(pending.rx_pct, None);
        assert_eq!(pending.retained_tx_pct, Some(100));
        assert_eq!(pending.retained_rx_pct, Some(100));
    }

    #[test]
    fn low_volume_unowned_lan_traffic_remains_visible_as_low_coverage() {
        let mut coverage = NssCoverageBook::default();
        coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );

        let output = coverage.update(
            traffic(10_000, 0, 100, 0),
            &lan(2_000, traffic(0, 20_000, 0, 200)),
        );

        assert_eq!(output.quality, WindowQuality::LowTraffic);
        assert!(output.aligned);
        assert_eq!(output.tx_pct, Some(50));
        assert_eq!(output.rx_pct, None);
    }

    #[test]
    fn packet_fcs_is_exact_and_counter_reset_rewarms() {
        assert_eq!(
            traffic(1_000, 2_000, 3, 5).fcs_normalized(),
            Some(traffic(1_012, 2_020, 3, 5))
        );
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, traffic(1_000, 1_000, 10, 10)),
            lan(0, traffic(1_000, 1_000, 10, 10)),
        );
        let reset = book.update(
            &nodes(1_000, traffic(100, 100, 1, 1)),
            lan(1_000, traffic(100, 100, 1, 1)),
        );
        assert_eq!(reset.quality, WindowQuality::CounterReset);
        assert_eq!(reset.reason, "lan_counter_reset");
    }

    #[test]
    fn physical_boundary_change_rewarms_without_reusing_old_rate() {
        let mut book = NssWindowBook::default();
        book.update(
            &nodes(0, traffic(1_000, 1_000, 10, 10)),
            lan(0, traffic(1_000, 1_000, 10, 10)),
        );
        let changed = book.update(
            &nodes(1_000, traffic(2_000, 2_000, 20, 20)),
            LanClock {
                interface: "lan1+lan2".into(),
                sample_ms: 1_000,
                counters: traffic(50_000, 50_000, 500, 500),
            },
        );
        assert_eq!(changed.quality, WindowQuality::CounterReset);
        assert_eq!(changed.reason, "lan_boundary_changed");
        assert!(changed.clients.iter().all(|client| client.tx_bps == 0));
    }

    #[test]
    fn asymmetric_high_traffic_uses_aggregate_byte_and_packet_ownership() {
        let client = traffic(3_763_764, 109_645_207, 39_568, 75_590);
        let lan = traffic(109_940_744, 3_033_545, 75_542, 38_478);
        assert!(fits_lan_clock(client, lan));
        assert!(!directional_coverage_ready(client, lan));
        let client_normalized = client.fcs_normalized().unwrap();
        let lan_normalized = lan.fcs_normalized().unwrap();
        assert!(ownership_ready(client_normalized, lan_normalized));
        assert_eq!(
            percentage(client_normalized.tx_bytes, lan_normalized.rx_bytes),
            None
        );
        assert_eq!(
            percentage(client_normalized.rx_bytes, lan_normalized.tx_bytes),
            Some(99)
        );
    }

    #[test]
    fn aggregate_overlap_waits_until_each_coverage_direction_is_reportable() {
        let mut coverage = NssCoverageBook::default();
        coverage.update(
            TrafficCounters::default(),
            &lan(0, TrafficCounters::default()),
        );
        let client = traffic(3_763_764, 109_645_207, 39_568, 75_590);
        let pending = coverage.update(
            client,
            &lan(1_000, traffic(109_940_744, 3_033_545, 75_542, 38_478)),
        );
        assert_eq!(pending.quality, WindowQuality::Pending);

        let aligned = coverage.update(
            TrafficCounters::default(),
            &lan(3_000, traffic(109_940_744, 3_763_764, 75_590, 39_568)),
        );
        assert_eq!(aligned.quality, WindowQuality::Ok);
        assert!(aligned.tx_pct.is_some());
        assert!(aligned.rx_pct.is_some());
    }
}
