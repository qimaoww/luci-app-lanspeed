use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs, io,
    path::Path,
};

pub const LAN_INTERFACE_RATE_WINDOW_MS: u64 = 2_000;

pub const PROC_NET_DEV_SOURCE: &str = "/proc/net/dev single-pass snapshot";
pub const SYSFS_INTERFACE_SOURCE: &str = "/sys/class/net/<if>/statistics fallback";
pub const MIXED_INTERFACE_SOURCE: &str = "/proc/net/dev with sysfs fallback";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InterfaceCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceCounterSource {
    ProcNetDev,
    Sysfs,
}

impl InterfaceCounterSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcNetDev => PROC_NET_DEV_SOURCE,
            Self::Sysfs => SYSFS_INTERFACE_SOURCE,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InterfaceCounterSnapshot {
    pub counters: BTreeMap<String, InterfaceCounters>,
    sources: BTreeMap<String, InterfaceCounterSource>,
}

impl InterfaceCounterSnapshot {
    pub fn source_for<'a>(&self, names: impl IntoIterator<Item = &'a str>) -> Option<&'static str> {
        let mut source = None;
        for name in names {
            let current = *self.sources.get(name)?;
            if source.is_some_and(|value| value != current) {
                return Some(MIXED_INTERFACE_SOURCE);
            }
            source = Some(current);
        }
        source.map(InterfaceCounterSource::as_str)
    }

    #[cfg(all(test, feature = "nss-platform"))]
    pub(crate) fn from_test_counters(counters: BTreeMap<String, InterfaceCounters>) -> Self {
        Self {
            counters,
            sources: BTreeMap::new(),
        }
    }
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
            rx_packets: read_counter(root.join("rx_packets"))?,
            tx_packets: read_counter(root.join("tx_packets"))?,
        })
    }
}

fn read_counter(path: impl AsRef<Path>) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn read_interface_counter_snapshot(names: &BTreeSet<String>) -> InterfaceCounterSnapshot {
    let mut snapshot = InterfaceCounterSnapshot::default();
    if let Ok(contents) = fs::read_to_string("/proc/net/dev") {
        if let Ok(counters) = parse_proc_net_dev(&contents) {
            for name in names {
                if let Some(value) = counters.get(name) {
                    snapshot.counters.insert(name.clone(), *value);
                    snapshot
                        .sources
                        .insert(name.clone(), InterfaceCounterSource::ProcNetDev);
                }
            }
        }
    }

    let mut fallback = SysfsInterfaceCounterReader;
    for name in names {
        if snapshot.counters.contains_key(name) {
            continue;
        }
        if let Ok(counters) = fallback.read(name) {
            snapshot.counters.insert(name.clone(), counters);
            snapshot
                .sources
                .insert(name.clone(), InterfaceCounterSource::Sysfs);
        }
    }
    snapshot
}

fn parse_proc_net_dev(contents: &str) -> io::Result<BTreeMap<String, InterfaceCounters>> {
    let mut interfaces = BTreeMap::new();
    for line in contents.lines() {
        let Some((name, fields)) = line.rsplit_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let values = fields
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if values.len() < 10 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated /proc/net/dev interface row",
            ));
        }
        interfaces.insert(
            name.to_owned(),
            InterfaceCounters {
                rx_bytes: values[0],
                rx_packets: values[1],
                tx_bytes: values[8],
                tx_packets: values[9],
            },
        );
    }
    if interfaces.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no interfaces in /proc/net/dev",
        ));
    }
    Ok(interfaces)
}

#[derive(Clone, Default)]
pub struct InterfaceRateBook {
    history: BTreeMap<String, VecDeque<(InterfaceCounters, u64)>>,
}

impl InterfaceRateBook {
    pub fn update(
        &mut self,
        name: &str,
        counters: InterfaceCounters,
        now_ms: u64,
    ) -> (u64, u64, u64) {
        self.update_windowed(name, counters, now_ms, 0)
    }

    pub fn update_windowed(
        &mut self,
        name: &str,
        counters: InterfaceCounters,
        now_ms: u64,
        minimum_window_ms: u64,
    ) -> (u64, u64, u64) {
        let history = self.history.entry(name.to_owned()).or_default();
        if history.back().is_some_and(|(previous, previous_ms)| {
            now_ms <= *previous_ms
                || counters.rx_bytes < previous.rx_bytes
                || counters.tx_bytes < previous.tx_bytes
        }) {
            history.clear();
        }
        history.push_back((counters, now_ms));
        while history.len() > 2 && now_ms.saturating_sub(history[1].1) >= minimum_window_ms {
            history.pop_front();
        }

        history
            .front()
            .and_then(|(old, old_ms)| {
                let delta_ms = now_ms.checked_sub(*old_ms)?;
                if delta_ms < minimum_window_ms || delta_ms == 0 {
                    return None;
                }
                Some((
                    (counters.rx_bytes - old.rx_bytes).saturating_mul(8_000) / delta_ms,
                    (counters.tx_bytes - old.tx_bytes).saturating_mul(8_000) / delta_ms,
                    delta_ms,
                ))
            })
            .unwrap_or((0, 0, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_dev_maps_bytes_and_packets_from_one_row() {
        let parsed = parse_proc_net_dev(
            "Inter-| Receive | Transmit\n\
             face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n\
             lan2: 287139099249 1700170484 0 479 0 0 0 34185 3789255529777 2656521506 0 0 0 0 0 0\n\
             br-lan: 84996854770 64044756 0 0 0 0 0 2442 21798991050 17413033 0 3 0 0 0 0\n",
        )
        .unwrap();

        assert_eq!(
            parsed.get("lan2"),
            Some(&InterfaceCounters {
                rx_bytes: 287_139_099_249,
                tx_bytes: 3_789_255_529_777,
                rx_packets: 1_700_170_484,
                tx_packets: 2_656_521_506,
            })
        );
        assert!(parsed.contains_key("br-lan"));
    }

    #[test]
    fn proc_net_dev_rejects_truncated_rows() {
        let error = parse_proc_net_dev("lan2: 1 2 3 4\n").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn snapshot_reports_single_and_mixed_counter_sources() {
        let snapshot = InterfaceCounterSnapshot {
            counters: BTreeMap::new(),
            sources: BTreeMap::from([
                ("lan1".into(), InterfaceCounterSource::ProcNetDev),
                ("lan2".into(), InterfaceCounterSource::ProcNetDev),
                ("wlan0".into(), InterfaceCounterSource::Sysfs),
            ]),
        };

        assert_eq!(
            snapshot.source_for(["lan1", "lan2"]),
            Some(PROC_NET_DEV_SOURCE)
        );
        assert_eq!(
            snapshot.source_for(["lan1", "wlan0"]),
            Some(MIXED_INTERFACE_SOURCE)
        );
        assert_eq!(snapshot.source_for(["missing"]), None);
    }

    #[test]
    fn two_second_window_smooths_batched_bridge_counters() {
        let mut rates = InterfaceRateBook::default();
        let counters = |rx_bytes, tx_bytes| InterfaceCounters {
            rx_bytes,
            tx_bytes,
            ..InterfaceCounters::default()
        };

        assert_eq!(
            rates.update_windowed("br-lan", counters(0, 0), 0, 2_000),
            (0, 0, 0)
        );
        assert_eq!(
            rates.update_windowed("br-lan", counters(0, 0), 1_000, 2_000),
            (0, 0, 0)
        );
        assert_eq!(
            rates.update_windowed("br-lan", counters(2_000, 4_000), 2_000, 2_000),
            (8_000, 16_000, 2_000)
        );
        assert_eq!(
            rates.update_windowed("br-lan", counters(2_000, 4_000), 3_000, 2_000),
            (8_000, 16_000, 2_000)
        );
        assert_eq!(
            rates.update_windowed("br-lan", counters(4_000, 8_000), 4_000, 2_000),
            (8_000, 16_000, 2_000)
        );
    }

    #[test]
    fn counter_rollback_rewarms_the_window() {
        let mut rates = InterfaceRateBook::default();
        let counters = |bytes| InterfaceCounters {
            rx_bytes: bytes,
            tx_bytes: bytes,
            ..InterfaceCounters::default()
        };

        rates.update_windowed("br-lan", counters(1_000), 0, 2_000);
        assert_eq!(
            rates.update_windowed("br-lan", counters(3_000), 2_000, 2_000),
            (8_000, 8_000, 2_000)
        );
        assert_eq!(
            rates.update_windowed("br-lan", counters(10), 3_000, 2_000),
            (0, 0, 0)
        );
    }
}
