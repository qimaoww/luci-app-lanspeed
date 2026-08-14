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
// A two-second LAN/TC window can straddle the allowed 250 ms fusion skew.
// Treat only a major directional deficit as a missing high-rate source; a
// normal startup edge must publish its current partial window instead of
// freezing the previous batch for another poll.
const HIGH_RATE_RAW_GAP_PERCENT: u64 = 75;
const PREVIOUS_DIRECTION_MIN_LAN_PERCENT: u64 = 75;
const PREVIOUS_DIRECTION_MAX_LAN_PERCENT: u64 = 200;
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
    pub previous_direction_gap_filled: bool,
    pub previous_high_direction_gap_filled: bool,
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
    last_emitted: Option<EcmBpfRateBatch>,
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
        // `MIN_COVERAGE_BYTES` is a reporting-confidence threshold, not a
        // rate-mode boundary. A paced low-rate TCP stream can emit one 128 KiB
        // batch followed by several empty two-second polls; classifying that
        // batch as high-rate clears the rolling history on every burst.
        let lan_peak_bps = lan_normalized.map_or(u64::MAX, |value| {
            rate(value.rx_bytes, window_ms).max(rate(value.tx_bytes, window_ms))
        });
        let idle = !has_traffic(&client_raw) && !has_traffic(&lan_raw);
        let low_rate = lan_peak_bps < ECM_BPF_EVENT_HIGH_RATE_BPS && !event_high_rate;
        let history_ready = self.low_rate_history_ms() >= ECM_BPF_LOW_RATE_WINDOW_MS;
        let has_published_batch = self.published.is_some();
        let low_rate_ready = idle
            || window_ms >= ECM_BPF_LOW_RATE_WINDOW_MS
            // Six seconds are required only for the first low-rate result.
            // A confirmed high-to-low transition may commit a two-second
            // segment; do not warm up for another six seconds afterwards.
            || ((history_ready || has_published_batch)
                && window_ms >= ECM_BPF_LOW_RATE_STEP_MS);
        let aligned_ready = if low_rate { low_rate_ready } else { true };

        if aligned && aligned_ready {
            let (
                clients,
                event_gap_filled,
                previous_direction_gap_filled,
                previous_high_direction_gap_filled,
                lan_reconciled,
            ) = if low_rate {
                let Some(clients) = rate_window_clients(&self.pending_clients, window_ms) else {
                    self.rebaseline(lan.clone(), interfaces.clone(), true);
                    return None;
                };
                (clients, false, false, false, false)
            } else {
                // `aligned` only proves that the raw client delta does not run
                // ahead of the physical LAN clock.  NSS may skip one stats-sync
                // round while the net-device counter keeps advancing, leaving a
                // tiny but technically valid raw delta.  Use the still-live ECM
                // event rate for that direction and constrain it to the same LAN
                // and discovered-interface budgets.  Each direction still picks
                // one source; raw and event rates are never added.
                let (
                    mut clients,
                    event_gap_filled,
                    previous_high_direction_gap_filled,
                    mut lan_reconciled,
                ) = match aligned_high_rate_window_clients(
                    &self.pending_clients,
                    &fallback_average,
                    lan_raw,
                    client_interfaces,
                    &interface_rates,
                    window_ms,
                    self.last_emitted.as_ref().or(self.published.as_ref()),
                    start.sample_ms,
                ) {
                    Some(repaired) => repaired,
                    None => {
                        if let Some(held) = self.held_at(lan.sample_ms) {
                            if held
                                .held_age_ms
                                .is_some_and(|age| age <= ECM_BPF_HIGH_RATE_CONFIRMATION_MS)
                            {
                                // The LAN clock advanced but this snapshot contains
                                // no current NSS event for the high-rate direction.
                                // Retain the entire previous client/interface batch;
                                // never pair its event rate with this LAN window.
                                self.rebaseline(lan.clone(), interfaces.clone(), false);
                                return Some(held);
                            }
                        } else {
                            self.rebaseline(lan.clone(), interfaces.clone(), false);
                            return None;
                        }
                        let Some(clients) = rate_window_clients(&self.pending_clients, window_ms)
                        else {
                            self.rebaseline(lan.clone(), interfaces.clone(), true);
                            return None;
                        };
                        (clients, false, false, false)
                    }
                };
                let previous_low_direction_gap_filled = repair_previous_complete_low_directions(
                    &mut clients,
                    self.last_emitted.as_ref().or(self.published.as_ref()),
                    start.sample_ms,
                    lan_raw,
                    window_ms,
                );
                let previous_direction_gap_filled =
                    previous_high_direction_gap_filled || previous_low_direction_gap_filled;
                if previous_direction_gap_filled {
                    lan_reconciled |= reconcile_high_rate_interfaces(
                        &mut clients,
                        client_interfaces,
                        &interface_rates,
                    );
                }
                (
                    clients,
                    event_gap_filled,
                    previous_direction_gap_filled,
                    previous_high_direction_gap_filled,
                    lan_reconciled,
                )
            };
            let batch = EcmBpfRateBatch {
                start_ms: start.sample_ms,
                end_ms: lan.sample_ms,
                clients,
                interfaces: interface_rates,
                raw_aligned: true,
                fallback_event_gap_filled: event_gap_filled,
                previous_direction_gap_filled,
                previous_high_direction_gap_filled,
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

        let fallback_ready = if low_rate {
            low_rate_ready
        } else {
            window_ms >= ECM_BPF_LOW_RATE_WINDOW_MS
                // An unaligned low-to-high transition already has a trusted
                // shared baseline. Publish its current fallback window at the
                // regular step instead of starting another six-second warmup.
                || (has_published_batch && window_ms >= ECM_BPF_LOW_RATE_STEP_MS)
        };
        if fallback_ready {
            let (mut clients, event_gap_filled, mut lan_reconciled) = if low_rate {
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
            let previous_direction_gap_filled = !low_rate
                && repair_previous_complete_low_directions(
                    &mut clients,
                    self.last_emitted.as_ref().or(self.published.as_ref()),
                    start.sample_ms,
                    lan_raw,
                    window_ms,
                );
            if previous_direction_gap_filled {
                lan_reconciled |= reconcile_high_rate_interfaces(
                    &mut clients,
                    client_interfaces,
                    &interface_rates,
                );
            }
            let batch = EcmBpfRateBatch {
                start_ms: start.sample_ms,
                end_ms: lan.sample_ms,
                clients,
                interfaces: interface_rates,
                raw_aligned: false,
                fallback_event_gap_filled: event_gap_filled,
                previous_direction_gap_filled,
                previous_high_direction_gap_filled: false,
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
        if previous_high.is_some() && !candidate_is_live && candidate.low_rate {
            let quiet_since = *self
                .high_rate_quiet_since_ms
                .get_or_insert(candidate.end_ms);
            if candidate.end_ms.saturating_sub(quiet_since) < ECM_BPF_HIGH_RATE_CONFIRMATION_MS {
                // Keep the committed high-rate state while confirming the
                // transition, but retain every real low-rate segment in the
                // rolling window.  Publishing only the latest segment made a
                // single delayed NSS sync look like a deep low-speed drop; the
                // weighted history smooths that gap without adding sources or
                // inventing bytes. A still-high candidate falls through to the
                // normal high-rate publication path and clears this history.
                self.low_rate_history.push_back(candidate);
                trim_low_rate_history(&mut self.low_rate_history);
                let emitted = aggregate_low_rate_history(&self.low_rate_history);
                self.last_emitted = Some(emitted.clone());
                return Some(emitted);
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
            self.last_emitted = Some(segment.clone());
            return segment;
        }

        self.low_rate_history.push_back(segment);
        trim_low_rate_history(&mut self.low_rate_history);
        let batch = aggregate_low_rate_history(&self.low_rate_history);
        self.published = Some(batch.clone());
        self.last_emitted = Some(batch.clone());
        batch
    }

    pub fn held_at(&self, sample_ms: u64) -> Option<EcmBpfRateBatch> {
        self.last_emitted
            .as_ref()
            .or(self.published.as_ref())
            .cloned()
            .map(|mut batch| {
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
            self.last_emitted = None;
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
        previous_direction_gap_filled: history
            .iter()
            .any(|batch| batch.previous_direction_gap_filled),
        previous_high_direction_gap_filled: history
            .iter()
            .any(|batch| batch.previous_high_direction_gap_filled),
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

fn aligned_high_rate_window_clients(
    pending_raw: &BTreeMap<String, TrafficCounters>,
    fallback: &BTreeMap<String, RateWindowValue>,
    lan_raw: TrafficCounters,
    client_interfaces: &BTreeMap<String, String>,
    interface_rates: &BTreeMap<String, RateWindowValue>,
    window_ms: u64,
    previous: Option<&EcmBpfRateBatch>,
    current_start_ms: u64,
) -> Option<(BTreeMap<String, RateWindowValue>, bool, bool, bool)> {
    let mut clients = rate_window_clients(pending_raw, window_ms)?;
    let raw_total = sum_rate_values(clients.values());
    let fallback_total = sum_rate_values(fallback.values());
    let lan_rate = lan_raw
        .fcs_normalized()
        .map(|counters| RateWindowValue {
            rx_bps: rate(counters.rx_bytes, window_ms),
            tx_bps: rate(counters.tx_bytes, window_ms),
        })
        .unwrap_or_default();
    let repair_tx =
        aligned_event_repair_ready(raw_total.tx_bps, fallback_total.tx_bps, lan_rate.rx_bps);
    let repair_rx =
        aligned_event_repair_ready(raw_total.rx_bps, fallback_total.rx_bps, lan_rate.tx_bps);
    let missing_tx = high_rate_raw_gap(raw_total.tx_bps, lan_rate.rx_bps) && !repair_tx;
    let missing_rx = high_rate_raw_gap(raw_total.rx_bps, lan_rate.tx_bps) && !repair_rx;
    let mut event_rate_selected = false;
    for (identity_key, fallback_rate) in fallback {
        let current = clients.entry(identity_key.clone()).or_default();
        if repair_tx && fallback_rate.tx_bps > current.tx_bps {
            current.tx_bps = fallback_rate.tx_bps;
            event_rate_selected = true;
        }
        if repair_rx && fallback_rate.rx_bps > current.rx_bps {
            current.rx_bps = fallback_rate.rx_bps;
            event_rate_selected = true;
        }
    }
    let (previous_tx_repaired, previous_rx_repaired) = repair_previous_complete_high_directions(
        &mut clients,
        previous,
        current_start_ms,
        lan_rate,
        missing_tx,
        missing_rx,
    );
    if missing_tx && !previous_tx_repaired || missing_rx && !previous_rx_repaired {
        return None;
    }
    let previous_high_direction_gap_filled = previous_tx_repaired || previous_rx_repaired;
    let tx_reconciled =
        reconcile_high_rate_direction(&mut clients, lan_rate.rx_bps, raw_total.tx_bps, false);
    let rx_reconciled =
        reconcile_high_rate_direction(&mut clients, lan_rate.tx_bps, raw_total.rx_bps, true);
    let interface_reconciled =
        reconcile_high_rate_interfaces(&mut clients, client_interfaces, interface_rates);
    Some((
        clients,
        event_rate_selected,
        previous_high_direction_gap_filled,
        tx_reconciled || rx_reconciled || interface_reconciled,
    ))
}

fn aligned_event_repair_ready(raw_bps: u64, event_bps: u64, lan_bps: u64) -> bool {
    high_rate_raw_gap(raw_bps, lan_bps) && event_bps > raw_bps
}

fn high_rate_raw_gap(raw_bps: u64, lan_bps: u64) -> bool {
    lan_bps >= ECM_BPF_EVENT_HIGH_RATE_BPS
        && u128::from(raw_bps).saturating_mul(100)
            < u128::from(lan_bps).saturating_mul(u128::from(HIGH_RATE_RAW_GAP_PERCENT))
}

fn repair_previous_complete_high_directions(
    clients: &mut BTreeMap<String, RateWindowValue>,
    previous: Option<&EcmBpfRateBatch>,
    current_start_ms: u64,
    lan_rate: RateWindowValue,
    repair_tx: bool,
    repair_rx: bool,
) -> (bool, bool) {
    let Some(previous) = previous.filter(|batch| {
        batch.fresh
            && batch.held_age_ms.is_none()
            && !batch.previous_direction_gap_filled
            && batch.end_ms == current_start_ms
    }) else {
        return (false, false);
    };

    let repaired_tx = repair_tx
        && replace_direction_from_previous_distribution(
            clients,
            &previous.clients,
            lan_rate.rx_bps,
            false,
        );
    let repaired_rx = repair_rx
        && replace_direction_from_previous_distribution(
            clients,
            &previous.clients,
            lan_rate.tx_bps,
            true,
        );
    (repaired_tx, repaired_rx)
}

fn replace_direction_from_previous_distribution(
    clients: &mut BTreeMap<String, RateWindowValue>,
    previous: &BTreeMap<String, RateWindowValue>,
    lan_bps: u64,
    receive: bool,
) -> bool {
    if lan_bps < ECM_BPF_EVENT_HIGH_RATE_BPS {
        return false;
    }
    let direction = |value: &RateWindowValue| {
        if receive {
            value.rx_bps
        } else {
            value.tx_bps
        }
    };
    let previous_total = previous.values().fold(0u128, |total, value| {
        total.saturating_add(u128::from(direction(value)))
    });
    if previous_total == 0 {
        return false;
    }

    for value in clients.values_mut() {
        if receive {
            value.rx_bps = 0;
        } else {
            value.tx_bps = 0;
        }
    }
    let mut assigned_any = false;
    for (identity_key, previous_value) in previous {
        let previous_bps = direction(previous_value);
        if previous_bps == 0 {
            continue;
        }
        let assigned =
            u128::from(previous_bps).saturating_mul(u128::from(lan_bps)) / previous_total;
        let assigned = u64::try_from(assigned).unwrap_or(lan_bps);
        if assigned == 0 {
            continue;
        }
        let value = clients.entry(identity_key.clone()).or_default();
        if receive {
            value.rx_bps = assigned;
        } else {
            value.tx_bps = assigned;
        }
        assigned_any = true;
    }
    assigned_any
}

fn repair_previous_complete_low_directions(
    clients: &mut BTreeMap<String, RateWindowValue>,
    previous: Option<&EcmBpfRateBatch>,
    current_start_ms: u64,
    lan_raw: TrafficCounters,
    window_ms: u64,
) -> bool {
    let Some(previous) = previous.filter(|batch| {
        batch.fresh
            && batch.held_age_ms.is_none()
            && !batch.previous_direction_gap_filled
            && batch.end_ms == current_start_ms
    }) else {
        return false;
    };
    let Some(lan) = lan_raw.fcs_normalized() else {
        return false;
    };
    let lan_rate = RateWindowValue {
        rx_bps: rate(lan.rx_bytes, window_ms),
        tx_bps: rate(lan.tx_bytes, window_ms),
    };
    let repaired_tx =
        repair_previous_complete_low_direction(clients, &previous.clients, lan_rate.rx_bps, false);
    let repaired_rx =
        repair_previous_complete_low_direction(clients, &previous.clients, lan_rate.tx_bps, true);
    repaired_tx || repaired_rx
}

fn repair_previous_complete_low_direction(
    clients: &mut BTreeMap<String, RateWindowValue>,
    previous: &BTreeMap<String, RateWindowValue>,
    lan_bps: u64,
    receive: bool,
) -> bool {
    if lan_bps == 0 || lan_bps >= ECM_BPF_EVENT_HIGH_RATE_BPS {
        return false;
    }
    let direction = |value: &RateWindowValue| {
        if receive {
            value.rx_bps
        } else {
            value.tx_bps
        }
    };
    let current_total = clients.values().fold(0u128, |total, value| {
        total.saturating_add(u128::from(direction(value)))
    });
    let previous_total = previous.values().fold(0u128, |total, value| {
        total.saturating_add(u128::from(direction(value)))
    });
    let lan_total = u128::from(lan_bps);
    if previous_total <= current_total
        || current_total.saturating_mul(100)
            >= lan_total.saturating_mul(u128::from(MIN_OWNERSHIP_PERCENT))
        || previous_total.saturating_mul(100)
            < lan_total.saturating_mul(u128::from(PREVIOUS_DIRECTION_MIN_LAN_PERCENT))
        || previous_total.saturating_mul(100)
            > lan_total.saturating_mul(u128::from(PREVIOUS_DIRECTION_MAX_LAN_PERCENT))
    {
        return false;
    }

    let selected_total = previous_total.min(lan_total);
    for value in clients.values_mut() {
        if receive {
            value.rx_bps = 0;
        } else {
            value.tx_bps = 0;
        }
    }
    let mut assigned_any = false;
    for (identity_key, previous_value) in previous {
        let previous_bps = direction(previous_value);
        if previous_bps == 0 {
            continue;
        }
        let assigned = u128::from(previous_bps).saturating_mul(selected_total) / previous_total;
        let assigned = u64::try_from(assigned).unwrap_or(lan_bps);
        if assigned == 0 {
            continue;
        }
        let value = clients.entry(identity_key.clone()).or_default();
        if receive {
            value.rx_bps = assigned;
        } else {
            value.tx_bps = assigned;
        }
        assigned_any = true;
    }
    assigned_any
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
include!("window/tests.rs");
