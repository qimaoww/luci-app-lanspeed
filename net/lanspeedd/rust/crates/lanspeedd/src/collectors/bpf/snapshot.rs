use std::collections::BTreeMap;

use lanspeed_common::{LanspeedCounters, LanspeedKey, DIR_RX, DIR_TX};

use crate::{
    identity::{filter, IdentityTable},
    rate::{ClientCounters, RateBook, RateWarning},
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawMapSample {
    pub key: LanspeedKey,
    pub counters: LanspeedCounters,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MapRead {
    pub entries: Vec<RawMapSample>,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionCounts {
    pub tcp: u32,
    pub udp: u32,
    pub udp_dns: u32,
    pub udp_other: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionOverlay {
    Available(BTreeMap<String, ConnectionCounts>),
    Unavailable(String),
}

impl ConnectionOverlay {
    pub fn available() -> Self {
        Self::Available(BTreeMap::new())
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable(reason.into())
    }

    pub fn insert(&mut self, identity_key: impl Into<String>, counts: ConnectionCounts) {
        if let Self::Available(values) = self {
            values.insert(identity_key.into(), counts);
        }
    }

    pub fn get(&self, identity_key: &str) -> Option<ConnectionCounts> {
        match self {
            Self::Available(values) => values.get(identity_key).copied(),
            Self::Unavailable(_) => None,
        }
    }

    pub fn unavailable_reason(&self) -> Option<&str> {
        match self {
            Self::Available(_) => None,
            Self::Unavailable(reason) => Some(reason),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotWarning {
    MapIterationTruncated,
    ClientLimitExceeded,
    ConnectionOverlayUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BpfClientSample {
    pub mac: String,
    pub identity_key: String,
    pub zone: String,
    pub interface: String,
    pub ips: Vec<String>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_bps: u64,
    pub rx_bps: u64,
    pub sample_ms: u64,
    pub last_seen_ms: u64,
    pub bpf_approx_tcp_tuples: u32,
    pub bpf_approx_udp_tuples: u32,
    pub tcp_conns: Option<u32>,
    pub udp_conns: Option<u32>,
    pub udp_dns_conns: Option<u32>,
    pub udp_other_conns: Option<u32>,
    pub warnings: Vec<RateWarning>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BpfSnapshot {
    pub clients: Vec<BpfClientSample>,
    pub warnings: Vec<SnapshotWarning>,
    pub rate_warnings: Vec<RateWarning>,
    pub sample_ms: u64,
}

#[derive(Clone, Debug)]
struct FoldedClient {
    mac: String,
    identity_key: String,
    zone: String,
    interface: String,
    ips: Vec<String>,
    tx_bytes: u64,
    rx_bytes: u64,
    last_seen_ms: u64,
    bpf_approx_tcp_tuples: u32,
    bpf_approx_udp_tuples: u32,
}

#[derive(Clone)]
pub struct BpfSnapshotCollector {
    rate_book: RateBook,
    max_clients: usize,
    stale_client_ms: u64,
    last_complete: Option<BpfSnapshot>,
}

impl BpfSnapshotCollector {
    pub fn new(max_clients: usize, stale_client_ms: u64) -> Self {
        Self {
            rate_book: RateBook::new(max_clients, stale_client_ms),
            max_clients,
            stale_client_ms,
            last_complete: None,
        }
    }

    pub fn last_complete(&self) -> Option<&BpfSnapshot> {
        self.last_complete.as_ref()
    }

    pub fn reset_rates(&mut self) {
        self.rate_book = RateBook::new(self.max_clients, self.stale_client_ms);
    }

    pub(crate) fn convert<F>(
        &mut self,
        read: MapRead,
        mut interface_name: F,
        identities: &IdentityTable,
        connections: &ConnectionOverlay,
        now_ms: u64,
        sticky_truncation: bool,
    ) -> BpfSnapshot
    where
        F: FnMut(u32) -> Option<String>,
    {
        let mut folded = BTreeMap::<String, FoldedClient>::new();
        let mut sample_ms = now_ms;
        let mut client_limit_exceeded = false;
        for raw in read.entries {
            if raw.key.direction != DIR_TX && raw.key.direction != DIR_RX {
                continue;
            }
            let interface =
                interface_name(raw.key.ifindex).unwrap_or_else(|| format!("if{}", raw.key.ifindex));
            if filter::ifname_is_excluded_identity_source(&interface) {
                continue;
            }
            let zone = filter::derive_zone_from_ifname(&interface);
            let mac = format_mac(raw.key.mac);
            let Some(identity) = identities.by_mac_zone(&mac, &zone) else {
                continue;
            };
            let identity_key = identity.key.to_string();
            let client = folded
                .entry(identity_key.clone())
                .or_insert_with(|| FoldedClient {
                    mac: identity.key.mac.to_string(),
                    identity_key,
                    zone: identity.key.zone.clone(),
                    interface: interface.clone(),
                    ips: identity.ips.iter().take(4).cloned().collect(),
                    tx_bytes: 0,
                    rx_bytes: 0,
                    last_seen_ms: 0,
                    bpf_approx_tcp_tuples: 0,
                    bpf_approx_udp_tuples: 0,
                });
            if raw.key.direction == DIR_TX {
                client.tx_bytes = client.tx_bytes.saturating_add(raw.counters.bytes);
                client.bpf_approx_tcp_tuples = client
                    .bpf_approx_tcp_tuples
                    .saturating_add(raw.counters.tcp_conns);
                client.bpf_approx_udp_tuples = client
                    .bpf_approx_udp_tuples
                    .saturating_add(raw.counters.udp_conns);
            } else {
                client.rx_bytes = client.rx_bytes.saturating_add(raw.counters.bytes);
            }
            let last_seen_ms = raw.counters.last_seen / 1_000_000;
            let last_seen_ms = if last_seen_ms == 0 {
                now_ms
            } else {
                last_seen_ms
            };
            sample_ms = sample_ms.max(last_seen_ms);
            client.last_seen_ms = client.last_seen_ms.max(last_seen_ms);
        }

        if folded.len() > self.max_clients {
            client_limit_exceeded = true;
            while folded.len() > self.max_clients {
                folded.pop_last();
            }
        }

        let rates = self.rate_book.update(
            sample_ms,
            folded.values().map(|client| ClientCounters {
                identity_key: client.identity_key.clone(),
                tx_bytes: client.tx_bytes,
                rx_bytes: client.rx_bytes,
                last_seen_ms: client.last_seen_ms,
            }),
        );
        let mut clients = Vec::with_capacity(rates.clients.len());
        for rate in rates.clients {
            let Some(client) = folded.get(&rate.identity_key) else {
                continue;
            };
            let counts = connections.get(&rate.identity_key);
            clients.push(BpfClientSample {
                mac: client.mac.clone(),
                identity_key: client.identity_key.clone(),
                zone: client.zone.clone(),
                interface: client.interface.clone(),
                ips: client.ips.clone(),
                tx_bytes: rate.tx_bytes,
                rx_bytes: rate.rx_bytes,
                tx_bps: rate.tx_bps,
                rx_bps: rate.rx_bps,
                sample_ms: rate.sample_ms,
                last_seen_ms: rate.last_seen_ms,
                bpf_approx_tcp_tuples: client.bpf_approx_tcp_tuples,
                bpf_approx_udp_tuples: client.bpf_approx_udp_tuples,
                tcp_conns: counts.map(|counts| counts.tcp),
                udp_conns: counts.map(|counts| counts.udp),
                udp_dns_conns: counts.map(|counts| counts.udp_dns),
                udp_other_conns: counts.map(|counts| counts.udp_other),
                warnings: rate.warnings,
            });
        }
        let mut warnings = Vec::new();
        if read.truncated || sticky_truncation {
            warnings.push(SnapshotWarning::MapIterationTruncated);
        }
        if client_limit_exceeded || !rates.rejected_clients.is_empty() {
            warnings.push(SnapshotWarning::ClientLimitExceeded);
        }
        if connections.unavailable_reason().is_some() {
            warnings.push(SnapshotWarning::ConnectionOverlayUnavailable);
        }
        let snapshot = BpfSnapshot {
            clients,
            warnings,
            rate_warnings: rates.warnings,
            sample_ms,
        };
        self.last_complete = Some(snapshot.clone());
        snapshot
    }
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
