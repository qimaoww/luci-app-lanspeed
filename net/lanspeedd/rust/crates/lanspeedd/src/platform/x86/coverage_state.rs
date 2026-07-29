use std::collections::BTreeSet;

use crate::model::{
    ClientsResponse, Coverage, Interface, InterfaceRole, InterfaceStatus, InterfacesResponse,
};

use super::coverage::{
    ByteTotals, CoverageQuality, CoverageRateAccumulator, CoverageRing, CoverageSample,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct X86Coverage {
    ring: CoverageRing,
    clients: CoverageRateAccumulator,
}

impl X86Coverage {
    pub(crate) fn update(
        &mut self,
        now_ms: u64,
        clients: &ClientsResponse,
        interfaces: &InterfacesResponse,
        supported: bool,
    ) -> Coverage {
        if supported {
            let interface = interface_totals(&interfaces.interfaces);
            let rates = clients
                .clients
                .iter()
                .fold(ByteTotals::new(0, 0), |total, value| {
                    ByteTotals::new(
                        total.rx_bytes.saturating_add(value.rx_bps),
                        total.tx_bytes.saturating_add(value.tx_bps),
                    )
                });
            let client = self.clients.update(now_ms, rates.rx_bytes, rates.tx_bytes);
            self.ring
                .push(CoverageSample::valid(now_ms, interface, client));
        } else {
            self.clients.pause();
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

fn coverage_response(report: super::coverage::CoverageReport) -> Coverage {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(
        name: &str,
        role: InterfaceRole,
        status: InterfaceStatus,
        rx_bytes: u64,
        tx_bytes: u64,
    ) -> Interface {
        Interface {
            name: name.into(),
            role,
            status,
            rx_bytes: Some(rx_bytes),
            tx_bytes: Some(tx_bytes),
            rx_bps: Some(0),
            tx_bps: Some(0),
            delta_ms: Some(1_000),
            sample_ms: Some(1_000),
            source: None,
            coverage: None,
            evidence: None,
        }
    }

    #[test]
    fn denominator_uses_unique_available_lan_interfaces_only() {
        let interfaces = vec![
            interface(
                "br-lan",
                InterfaceRole::Lan,
                InterfaceStatus::Available,
                100,
                200,
            ),
            interface(
                "br-lan",
                InterfaceRole::Lan,
                InterfaceStatus::Available,
                100,
                200,
            ),
            interface(
                "pppoe-wan",
                InterfaceRole::Observe,
                InterfaceStatus::Available,
                10_000,
                20_000,
            ),
            interface(
                "eth2",
                InterfaceRole::Lan,
                InterfaceStatus::Missing,
                50_000,
                60_000,
            ),
        ];

        assert_eq!(interface_totals(&interfaces), ByteTotals::new(100, 200));
    }

    #[test]
    fn denominator_saturates_and_treats_missing_counters_as_zero() {
        let mut first = interface(
            "lan0",
            InterfaceRole::Lan,
            InterfaceStatus::Available,
            u64::MAX,
            7,
        );
        first.tx_bytes = None;
        let second = interface(
            "lan1",
            InterfaceRole::Lan,
            InterfaceStatus::Available,
            1,
            u64::MAX,
        );

        assert_eq!(
            interface_totals(&[first, second]),
            ByteTotals::new(u64::MAX, u64::MAX)
        );
    }
}
