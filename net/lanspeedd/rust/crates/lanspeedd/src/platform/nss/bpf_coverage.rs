use std::collections::BTreeSet;

use crate::model::{
    ClientsResponse, Coverage, Interface, InterfaceRole, InterfaceStatus, InterfacesResponse,
};

pub const COVERAGE_WINDOW: usize = 32;
pub const COVERAGE_MIN_WINDOW_MS: u64 = 3_000;
pub const COVERAGE_MIN_DENOM_BYTES: u64 = 524_288;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ByteTotals {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl ByteTotals {
    pub const fn new(rx_bytes: u64, tx_bytes: u64) -> Self {
        Self { rx_bytes, tx_bytes }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NssBpfCoverage {
    ring: CoverageRing,
}

impl NssBpfCoverage {
    pub(crate) fn update(
        &mut self,
        now_ms: u64,
        clients: &ClientsResponse,
        interfaces: &InterfacesResponse,
        supported: bool,
    ) -> Coverage {
        if supported {
            let interface = interface_totals(&interfaces.interfaces);
            let client = clients
                .clients
                .iter()
                .fold(ByteTotals::new(0, 0), |total, value| {
                    ByteTotals::new(
                        total.rx_bytes.saturating_add(value.rx_bytes.unwrap_or(0)),
                        total.tx_bytes.saturating_add(value.tx_bytes.unwrap_or(0)),
                    )
                });
            self.ring
                .push(CoverageSample::valid(now_ms, interface, client));
        } else {
            self.ring.reset();
            self.ring.push(CoverageSample::invalid(now_ms));
        }
        coverage_response(self.ring.report(supported))
    }
}

fn interface_totals(interfaces: &[Interface]) -> ByteTotals {
    let mut names = BTreeSet::new();
    interfaces
        .iter()
        .filter(|interface| {
            interface.role == InterfaceRole::Lan
                && interface.status == InterfaceStatus::Available
                && names.insert(interface.name.as_str())
        })
        .fold(ByteTotals::new(0, 0), |totals, interface| {
            ByteTotals::new(
                totals
                    .rx_bytes
                    .saturating_add(interface.rx_bytes.unwrap_or(0)),
                totals
                    .tx_bytes
                    .saturating_add(interface.tx_bytes.unwrap_or(0)),
            )
        })
}

fn coverage_response(report: CoverageReport) -> Coverage {
    let supported = report.quality != CoverageQuality::Unsupported;
    Coverage {
        quality: report.quality.as_str().into(),
        samples: report.samples as u64,
        window_ms: supported.then_some(report.window_ms),
        tx_pct: report.tx_pct,
        rx_pct: report.rx_pct,
        denom_rx_bytes: supported.then_some(report.denom_rx_bytes),
        denom_tx_bytes: supported.then_some(report.denom_tx_bytes),
        numer_rx_bytes: supported.then_some(report.numer_rx_bytes),
        numer_tx_bytes: supported.then_some(report.numer_tx_bytes),
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
    CounterSkew,
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
            Self::CounterSkew => "counter_skew",
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
        if dc_tx > di_rx || dc_rx > di_tx {
            report.quality = CoverageQuality::CounterSkew;
            return report;
        }
        report.tx_pct = percentage(dc_tx, di_rx);
        report.rx_pct = percentage(dc_rx, di_tx);
        report.quality = if denominator < COVERAGE_MIN_DENOM_BYTES {
            CoverageQuality::LowTraffic
        } else {
            CoverageQuality::Ok
        };
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
    u8::try_from(value).ok()
}
