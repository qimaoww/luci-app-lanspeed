use crate::collectors::ecm_node::{NodeSnapshot, TrafficCounters};
use std::collections::BTreeMap;

const NODE_BASELINE_RETENTION_MS: u64 = 60_000;
const RATE_HOLD_MS: u64 = 1_500;
const NODE_RATE_MEDIAN_SAMPLES: usize = 3;
const MAX_RATE_WINDOW_MS: u64 = 5_000;
const COVERAGE_CATCHUP_TIMEOUT_MS: u64 = 5_000;
const UNOWNED_SETTLE_MS: u64 = 2_500;
const MIN_COVERAGE_BYTES: u64 = 128 * 1024;
const MIN_OWNERSHIP_PERCENT: u64 = 90;

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
            );
        };

        let aligned = fits_lan_clock(client_raw, lan_raw)
            && fits_lan_clock(client_normalized, lan_normalized)
            && ownership_ready(client_normalized, lan_normalized)
            && directional_coverage_ready(client_raw, lan_raw)
            && directional_coverage_ready(client_normalized, lan_normalized);
        if aligned {
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
            let output = coverage_window(
                quality,
                "lan_coverage_aligned",
                &start,
                lan,
                client_raw,
                client_normalized,
                lan_raw,
                lan_normalized,
                true,
            );
            if quality == WindowQuality::Idle {
                self.last_reported = None;
            } else if output.tx_pct.is_some() || output.rx_pct.is_some() {
                self.last_reported = Some((output.tx_pct, output.rx_pct));
            }
            self.rebaseline(lan.clone());
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
        tx_pct: aligned
            .then(|| percentage(client_normalized.tx_bytes, lan_normalized.rx_bytes))
            .flatten(),
        rx_pct: aligned
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
    use crate::collectors::ecm_node::{NodeCounters, ParseStats};

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
    fn partial_client_batches_accumulate_for_coverage_but_publish_rates_independently() {
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
        assert_eq!(first.coverage.quality, WindowQuality::Pending);

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
