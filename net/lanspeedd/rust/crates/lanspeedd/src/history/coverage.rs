use crate::rate::json_u64;
use serde_json::{Map, Value};

pub const COVERAGE_WINDOW: usize = 32;
pub const COVERAGE_MIN_WINDOW_MS: u64 = 3_000;
pub const COVERAGE_MIN_DENOM_BYTES: u64 = 524_288;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ByteTotals {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoverageRateAccumulator {
    totals: ByteTotals,
    last_sample_ms: Option<u64>,
    rx_remainder: u64,
    tx_remainder: u64,
}

impl CoverageRateAccumulator {
    pub fn update(&mut self, now_ms: u64, rx_bps: u64, tx_bps: u64) -> ByteTotals {
        if let Some(delta_ms) = self
            .last_sample_ms
            .and_then(|previous_ms| now_ms.checked_sub(previous_ms))
            .filter(|delta_ms| *delta_ms > 0)
        {
            let (rx_bytes, rx_remainder) = rate_bytes(rx_bps, delta_ms, self.rx_remainder);
            let (tx_bytes, tx_remainder) = rate_bytes(tx_bps, delta_ms, self.tx_remainder);
            self.totals.rx_bytes = self.totals.rx_bytes.saturating_add(rx_bytes);
            self.totals.tx_bytes = self.totals.tx_bytes.saturating_add(tx_bytes);
            self.rx_remainder = rx_remainder;
            self.tx_remainder = tx_remainder;
        }
        self.last_sample_ms = Some(now_ms);
        self.totals
    }

    pub fn pause(&mut self) {
        self.last_sample_ms = None;
        self.rx_remainder = 0;
        self.tx_remainder = 0;
    }

    pub const fn totals(&self) -> ByteTotals {
        self.totals
    }
}

impl ByteTotals {
    pub const fn new(rx_bytes: u64, tx_bytes: u64) -> Self {
        Self { rx_bytes, tx_bytes }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageSample {
    pub ts_ms: u64,
    pub interface: Option<ByteTotals>,
    pub clients: Option<ByteTotals>,
}

impl CoverageSample {
    pub const fn valid(ts_ms: u64, interface: ByteTotals, clients: ByteTotals) -> Self {
        Self {
            ts_ms,
            interface: Some(interface),
            clients: Some(clients),
        }
    }

    pub const fn invalid(ts_ms: u64) -> Self {
        Self {
            ts_ms,
            interface: None,
            clients: None,
        }
    }

    fn is_valid(self) -> bool {
        self.interface.is_some() && self.clients.is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageQuality {
    Warmup,
    Idle,
    LowTraffic,
    CounterReset,
    Ok,
    Unsupported,
}

impl CoverageQuality {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warmup => "warmup",
            Self::Idle => "idle",
            Self::LowTraffic => "low_traffic",
            Self::CounterReset => "counter_reset",
            Self::Ok => "ok",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageReport {
    pub quality: CoverageQuality,
    pub samples: usize,
    pub window_ms: u64,
    pub tx_pct: Option<u8>,
    pub rx_pct: Option<u8>,
    pub denom_rx_bytes: u64,
    pub denom_tx_bytes: u64,
    pub numer_rx_bytes: u64,
    pub numer_tx_bytes: u64,
}

impl CoverageReport {
    fn empty(quality: CoverageQuality, samples: usize) -> Self {
        Self {
            quality,
            samples,
            window_ms: 0,
            tx_pct: None,
            rx_pct: None,
            denom_rx_bytes: 0,
            denom_tx_bytes: 0,
            numer_rx_bytes: 0,
            numer_tx_bytes: 0,
        }
    }

    pub fn to_json(self) -> Value {
        let mut object = Map::new();
        object.insert(
            "quality".to_owned(),
            Value::String(self.quality.as_str().to_owned()),
        );
        object.insert("samples".to_owned(), json_u64(self.samples as u64));
        if self.quality == CoverageQuality::Unsupported {
            return Value::Object(object);
        }
        object.insert("window_ms".to_owned(), json_u64(self.window_ms));
        if let Some(tx_pct) = self.tx_pct {
            object.insert("tx_pct".to_owned(), Value::from(tx_pct));
        }
        if let Some(rx_pct) = self.rx_pct {
            object.insert("rx_pct".to_owned(), Value::from(rx_pct));
        }
        object.insert("denom_rx_bytes".to_owned(), json_u64(self.denom_rx_bytes));
        object.insert("denom_tx_bytes".to_owned(), json_u64(self.denom_tx_bytes));
        object.insert("numer_rx_bytes".to_owned(), json_u64(self.numer_rx_bytes));
        object.insert("numer_tx_bytes".to_owned(), json_u64(self.numer_tx_bytes));
        Value::Object(object)
    }
}

#[derive(Clone, Debug)]
pub struct CoverageRing {
    samples: [Option<CoverageSample>; COVERAGE_WINDOW],
    head: usize,
    count: usize,
}

impl CoverageRing {
    pub fn new() -> Self {
        Self {
            samples: [None; COVERAGE_WINDOW],
            head: 0,
            count: 0,
        }
    }

    pub const fn capacity(&self) -> usize {
        COVERAGE_WINDOW
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn reset(&mut self) {
        self.samples = [None; COVERAGE_WINDOW];
        self.head = 0;
        self.count = 0;
    }

    pub fn push(&mut self, sample: CoverageSample) {
        self.samples[self.head] = Some(sample);
        self.head = (self.head + 1) % COVERAGE_WINDOW;
        self.count = self.count.saturating_add(1).min(COVERAGE_WINDOW);
    }

    pub fn report(&mut self, supported: bool) -> CoverageReport {
        if !supported {
            return CoverageReport::empty(CoverageQuality::Unsupported, self.count);
        }

        let mut report = CoverageReport::empty(CoverageQuality::Warmup, self.count);
        let newest = self.sample_at(0);
        let oldest = (0..self.count)
            .rev()
            .filter_map(|index| self.sample_at(index))
            .find(|sample| sample.is_valid());
        let (Some(newest), Some(oldest)) = (newest, oldest) else {
            return report;
        };
        if newest == oldest || !newest.is_valid() || newest.ts_ms <= oldest.ts_ms {
            return report;
        }

        report.window_ms = newest.ts_ms - oldest.ts_ms;
        let (
            Some(newest_interface),
            Some(oldest_interface),
            Some(newest_clients),
            Some(oldest_clients),
        ) = (
            newest.interface,
            oldest.interface,
            newest.clients,
            oldest.clients,
        )
        else {
            return report;
        };
        let deltas = (
            newest_interface
                .rx_bytes
                .checked_sub(oldest_interface.rx_bytes),
            newest_interface
                .tx_bytes
                .checked_sub(oldest_interface.tx_bytes),
            newest_clients.rx_bytes.checked_sub(oldest_clients.rx_bytes),
            newest_clients.tx_bytes.checked_sub(oldest_clients.tx_bytes),
        );
        let (Some(di_rx), Some(di_tx), Some(dc_rx), Some(dc_tx)) = deltas else {
            report.quality = CoverageQuality::CounterReset;
            report.samples = 0;
            self.reset();
            return report;
        };
        report.denom_rx_bytes = di_rx;
        report.denom_tx_bytes = di_tx;
        report.numer_rx_bytes = dc_rx;
        report.numer_tx_bytes = dc_tx;

        if report.window_ms < COVERAGE_MIN_WINDOW_MS {
            return report;
        }
        let denominator = di_rx.checked_add(di_tx).unwrap_or(u64::MAX);
        if denominator == 0 {
            report.quality = CoverageQuality::Idle;
            return report;
        }
        if denominator < COVERAGE_MIN_DENOM_BYTES {
            report.quality = CoverageQuality::LowTraffic;
            return report;
        }

        report.quality = CoverageQuality::Ok;
        report.tx_pct = percentage(dc_tx, di_rx);
        report.rx_pct = percentage(dc_rx, di_tx);
        report
    }

    fn sample_at(&self, index_back: usize) -> Option<CoverageSample> {
        if index_back >= self.count {
            return None;
        }
        self.samples[(self.head + COVERAGE_WINDOW - 1 - index_back) % COVERAGE_WINDOW]
    }
}

impl Default for CoverageRing {
    fn default() -> Self {
        Self::new()
    }
}

fn percentage(numerator: u64, denominator: u64) -> Option<u8> {
    if denominator == 0 {
        return None;
    }
    let value =
        u128::from(numerator).checked_mul(100).unwrap_or(u128::MAX) / u128::from(denominator);
    Some(value.min(100) as u8)
}

fn rate_bytes(bps: u64, delta_ms: u64, remainder: u64) -> (u64, u64) {
    let scaled = u128::from(bps)
        .saturating_mul(u128::from(delta_ms))
        .saturating_add(u128::from(remainder));
    let bytes = scaled / 8_000;
    let remainder = scaled % 8_000;
    (
        u64::try_from(bytes).unwrap_or(u64::MAX),
        u64::try_from(remainder).unwrap_or(0),
    )
}
