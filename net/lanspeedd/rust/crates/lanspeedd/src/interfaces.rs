use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::Path,
};

use crate::{
    history::coverage::ByteTotals,
    model::{Interface, InterfaceRole, InterfaceStatus},
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InterfaceCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub trait InterfaceCounterReader {
    fn read(&mut self, name: &str) -> io::Result<InterfaceCounters>;
}

#[derive(Default)]
pub struct SysfsInterfaceCounterReader;

impl InterfaceCounterReader for SysfsInterfaceCounterReader {
    fn read(&mut self, name: &str) -> io::Result<InterfaceCounters> {
        let root = Path::new("/sys/class/net").join(name).join("statistics");
        Ok(InterfaceCounters {
            rx_bytes: read_counter(root.join("rx_bytes"))?,
            tx_bytes: read_counter(root.join("tx_bytes"))?,
        })
    }
}

fn read_counter(path: impl AsRef<Path>) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[derive(Clone, Default)]
pub struct InterfaceRateBook {
    previous: BTreeMap<String, (InterfaceCounters, u64)>,
}

impl InterfaceRateBook {
    pub fn update(
        &mut self,
        name: &str,
        counters: InterfaceCounters,
        now_ms: u64,
    ) -> (u64, u64, u64) {
        let rates = self
            .previous
            .get(name)
            .and_then(|(old, old_ms)| {
                let delta_ms = now_ms.checked_sub(*old_ms)?;
                if delta_ms == 0
                    || counters.rx_bytes < old.rx_bytes
                    || counters.tx_bytes < old.tx_bytes
                {
                    return None;
                }
                Some((
                    (counters.rx_bytes - old.rx_bytes).saturating_mul(8_000) / delta_ms,
                    (counters.tx_bytes - old.tx_bytes).saturating_mul(8_000) / delta_ms,
                    delta_ms,
                ))
            })
            .unwrap_or((0, 0, 0));
        self.previous.insert(name.to_owned(), (counters, now_ms));
        rates
    }
}

pub fn lan_coverage_totals(interfaces: &[Interface]) -> ByteTotals {
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
