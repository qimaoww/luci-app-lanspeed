//! x86-only logical connection recovery for transparent proxy processes.
//!
//! TC-BPF sees the complete LAN-edge byte stream, while conntrack may expose
//! only the client-to-proxy half after a transparent proxy takes ownership of
//! the socket. Mihomo supplies its logical connection ledger through the
//! loopback external-controller API. dae/daed does not expose an equivalent
//! per-connection API, so active TCP sockets are recovered from its dedicated
//! `daens` network namespace, TCP byte counters from SOCK_DIAG, and UDP tuples
//! from its timer-backed eBPF state map. Neither adapter is compiled into the
//! NSS backend.

mod dae;
mod http;
mod mihomo;

use crate::{
    collectors::conntrack::{aggregate::ClientSample, CollectedSnapshot},
    connection_details::{
        sort_connection_details, ClientConnectionDetail, ConnectionDirection, ConnectionProtocol,
        ConnectionState, MAX_CLIENT_CONNECTION_DETAILS, MAX_STORED_CONNECTION_DETAILS,
    },
    identity::{ClientIdentity, IdentityTable},
};
use lanspeed_openwrt_sys::{UciContext, UciValue};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    sync::Arc,
};

const DEFAULT_PROXY_CONNECTIONS_ENABLED: bool = true;
const MAX_MIHOMO_SECRET_LEN: usize = 1_024;

#[derive(Clone, Eq, PartialEq)]
struct ProxyConnectionSettings {
    enabled: bool,
    mihomo_controller_port: Option<u16>,
    mihomo_controller_secret: Option<String>,
}

impl Default for ProxyConnectionSettings {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_PROXY_CONNECTIONS_ENABLED,
            mihomo_controller_port: None,
            mihomo_controller_secret: None,
        }
    }
}

impl ProxyConnectionSettings {
    fn read() -> io::Result<Self> {
        let mut uci = UciContext::new().map_err(uci_error)?;
        let enabled = match lookup_string(&mut uci, "lanspeed.main.enable_proxy_connections")? {
            None => DEFAULT_PROXY_CONNECTIONS_ENABLED,
            Some(value) if value == "1" || value == "true" => true,
            Some(value) if value == "0" || value == "false" => false,
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid proxy connection enable option",
                ));
            }
        };
        let mihomo_controller_port =
            match lookup_string(&mut uci, "lanspeed.main.mihomo_controller_port")? {
                None => None,
                Some(value) if value.is_empty() || value == "0" => None,
                Some(value) => Some(
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|port| *port != 0)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid Mihomo controller port",
                            )
                        })?,
                ),
            };
        let mihomo_controller_secret =
            lookup_string(&mut uci, "lanspeed.main.mihomo_controller_secret")?
                .filter(|value| !value.is_empty())
                .map(|value| {
                    if value.len() > MAX_MIHOMO_SECRET_LEN
                        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid Mihomo authentication secret",
                        ));
                    }
                    Ok(value)
                })
                .transpose()?;
        Ok(Self {
            enabled,
            mihomo_controller_port,
            mihomo_controller_secret,
        })
    }
}

fn lookup_string(uci: &mut UciContext, path: &str) -> io::Result<Option<String>> {
    match uci.lookup(path).map_err(uci_error)? {
        Some(UciValue::String(value)) => Ok(Some(value)),
        Some(UciValue::List(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy connection option must be a string",
        )),
        None => Ok(None),
    }
}

fn uci_error(error: lanspeed_openwrt_sys::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ProxySource {
    Mihomo,
    Dae,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProxyConnectionSample {
    source: ProxySource,
    generation: String,
    client_ip: IpAddr,
    client_port: u16,
    remote_ip: Option<IpAddr>,
    remote_port: u16,
    protocol: ConnectionProtocol,
    tx_bytes: Option<u64>,
    rx_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RatedProxyConnection {
    sample: ProxyConnectionSample,
    tx_bps: Option<u64>,
    rx_bps: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CounterPoint {
    sample_ms: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ProxyRateBook {
    previous: BTreeMap<ProxySource, BTreeMap<String, CounterPoint>>,
}

impl ProxyRateBook {
    fn update(
        &mut self,
        source: ProxySource,
        sample_ms: u64,
        samples: Vec<ProxyConnectionSample>,
    ) -> Vec<RatedProxyConnection> {
        let previous = self.previous.get(&source);
        let mut current = BTreeMap::new();
        let mut rated = Vec::with_capacity(samples.len());
        for sample in samples {
            debug_assert_eq!(sample.source, source);
            let counters = sample.tx_bytes.zip(sample.rx_bytes);
            let rates = counters.and_then(|(tx_bytes, rx_bytes)| {
                current.insert(
                    sample.generation.clone(),
                    CounterPoint {
                        sample_ms,
                        tx_bytes,
                        rx_bytes,
                    },
                );
                let prior = previous?.get(&sample.generation)?;
                let delta_ms = sample_ms.checked_sub(prior.sample_ms)?;
                Some((
                    counter_rate(tx_bytes, prior.tx_bytes, delta_ms),
                    counter_rate(rx_bytes, prior.rx_bytes, delta_ms),
                ))
            });
            rated.push(RatedProxyConnection {
                sample,
                tx_bps: rates.map(|value| value.0),
                rx_bps: rates.map(|value| value.1),
            });
        }
        self.previous.insert(source, current);
        rated
    }
}

fn counter_rate(current: u64, previous: u64, delta_ms: u64) -> u64 {
    if delta_ms == 0 || current < previous {
        return 0;
    }
    u128::from(current - previous)
        .saturating_mul(8_000)
        .checked_div(u128::from(delta_ms))
        .unwrap_or(0)
        .min(u128::from(u64::MAX)) as u64
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MergeStats {
    pub mihomo_samples: usize,
    pub dae_samples: usize,
    pub replaced: usize,
    pub added: usize,
    pub omitted: usize,
}

#[derive(Default)]
pub(crate) struct ProxyConnectionCollector {
    rates: ProxyRateBook,
}

impl ProxyConnectionCollector {
    /// Enrich a successful conntrack snapshot. Proxy adapter failures are
    /// intentionally isolated: conntrack remains available even when either
    /// optional local data source is absent or temporarily unreadable.
    pub(crate) fn enrich(
        &mut self,
        identities: &IdentityTable,
        now_ms: u64,
        max_clients: usize,
        collected: &mut CollectedSnapshot,
    ) -> MergeStats {
        let mut stats = MergeStats::default();
        let Ok(settings) = ProxyConnectionSettings::read() else {
            return stats;
        };
        if !settings.enabled {
            self.rates = ProxyRateBook::default();
            return stats;
        }
        let mut samples = Vec::new();
        if let Ok(current) = mihomo::read_samples(&settings) {
            stats.mihomo_samples = current.len();
            samples.extend(self.rates.update(ProxySource::Mihomo, now_ms, current));
        }
        if let Ok(current) = dae::read_samples(identities) {
            stats.dae_samples = current.len();
            samples.extend(self.rates.update(ProxySource::Dae, now_ms, current));
        }
        let merged = merge_samples(collected, identities, max_clients, samples);
        stats.replaced = merged.replaced;
        stats.added = merged.added;
        stats.omitted = merged.omitted;
        stats
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct MergeResult {
    replaced: usize,
    added: usize,
    omitted: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LogicalKey {
    identity_key: String,
    client_ip: IpAddr,
    client_port: u16,
    remote_ip: Option<IpAddr>,
    remote_port: Option<u16>,
    protocol: ConnectionProtocol,
}

fn merge_samples(
    collected: &mut CollectedSnapshot,
    identities: &IdentityTable,
    max_clients: usize,
    samples: Vec<RatedProxyConnection>,
) -> MergeResult {
    let mut result = MergeResult::default();
    let mut seen = BTreeSet::new();
    let now_ms = collected.sample_ms;
    let mut stored = collected
        .connection_details
        .values()
        .map(|set| set.connections.len())
        .sum::<usize>();
    let sets = Arc::make_mut(&mut collected.connection_details);

    for rated in samples {
        let sample = &rated.sample;
        let Some(identity) = identities.by_ip(&sample.client_ip.to_string()) else {
            continue;
        };
        let identity_key = identity.key.to_string();
        let logical_key = LogicalKey {
            identity_key: identity_key.clone(),
            client_ip: sample.client_ip,
            client_port: sample.client_port,
            remote_ip: (sample.protocol == ConnectionProtocol::Udp)
                .then_some(sample.remote_ip)
                .flatten(),
            remote_port: (sample.protocol == ConnectionProtocol::Udp).then_some(sample.remote_port),
            protocol: sample.protocol,
        };
        if !seen.insert(logical_key) {
            continue;
        }

        let set = sets.entry(identity_key.clone()).or_default();
        if let Some(detail) = set
            .connections
            .iter_mut()
            .find(|detail| detail_matches(detail, sample))
        {
            if let Some(remote_ip) = sample.remote_ip {
                detail.remote_ip = remote_ip;
                detail.remote_port = sample.remote_port;
            }
            if let Some(tx_bps) = rated.tx_bps {
                detail.tx_bps = tx_bps;
            }
            if let Some(rx_bps) = rated.rx_bps {
                detail.rx_bps = rx_bps;
            }
            result.replaced = result.replaced.saturating_add(1);
            continue;
        }

        let Some(remote_ip) = sample.remote_ip else {
            result.omitted = result.omitted.saturating_add(1);
            continue;
        };
        set.total_connections = set.total_connections.saturating_add(1);
        add_connection_count(
            &mut collected.clients,
            identity,
            sample.protocol,
            sample.remote_port,
            now_ms,
            max_clients,
        );
        if set.connections.len() >= MAX_CLIENT_CONNECTION_DETAILS
            || stored >= MAX_STORED_CONNECTION_DETAILS
        {
            set.truncated = true;
            result.omitted = result.omitted.saturating_add(1);
            continue;
        }
        set.connections.push(ClientConnectionDetail {
            client_ip: sample.client_ip,
            client_port: sample.client_port,
            remote_ip,
            remote_port: sample.remote_port,
            protocol: sample.protocol,
            state: match sample.protocol {
                ConnectionProtocol::Tcp => ConnectionState::Established,
                ConnectionProtocol::Udp => ConnectionState::Assured,
            },
            direction: ConnectionDirection::Outbound,
            tx_bps: rated.tx_bps.unwrap_or(0),
            rx_bps: rated.rx_bps.unwrap_or(0),
        });
        stored = stored.saturating_add(1);
        result.added = result.added.saturating_add(1);
    }

    for set in sets.values_mut() {
        sort_connection_details(&mut set.connections);
        set.truncated |= set.connections.len() as u64 != set.total_connections;
    }
    collected.stats.current_clients = collected.clients.len();
    result
}

fn detail_matches(detail: &ClientConnectionDetail, sample: &ProxyConnectionSample) -> bool {
    if detail.direction != ConnectionDirection::Outbound
        || detail.client_ip != sample.client_ip
        || detail.client_port != sample.client_port
        || detail.protocol != sample.protocol
    {
        return false;
    }
    match sample.protocol {
        // A live TCP source port identifies one client socket. This fallback
        // is required when REDIRECT makes conntrack and the proxy API expose
        // different destination addresses for the same logical connection.
        ConnectionProtocol::Tcp => true,
        ConnectionProtocol::Udp => {
            detail.remote_port == sample.remote_port
                && sample
                    .remote_ip
                    .is_none_or(|remote| detail.remote_ip == remote)
        }
    }
}

fn add_connection_count(
    clients: &mut Vec<ClientSample>,
    identity: &ClientIdentity,
    protocol: ConnectionProtocol,
    remote_port: u16,
    now_ms: u64,
    max_clients: usize,
) {
    let identity_key = identity.key.to_string();
    let position = clients
        .iter()
        .position(|client| client.identity_key == identity_key)
        .or_else(|| {
            if clients.len() >= max_clients {
                return None;
            }
            clients.push(ClientSample {
                mac: identity.key.mac.to_string(),
                identity_key: identity_key.clone(),
                zone: identity.key.zone.clone(),
                interface: identity.interface.clone(),
                ips: identity.ips.clone(),
                tx_bytes: 0,
                rx_bytes: 0,
                last_seen_ms: now_ms,
                tcp_conns: 0,
                udp_conns: 0,
                udp_dns_conns: 0,
                udp_other_conns: 0,
            });
            clients.len().checked_sub(1)
        });
    let Some(position) = position else {
        return;
    };
    let client = &mut clients[position];
    match protocol {
        ConnectionProtocol::Tcp => client.tcp_conns = client.tcp_conns.saturating_add(1),
        ConnectionProtocol::Udp => {
            client.udp_conns = client.udp_conns.saturating_add(1);
            if remote_port == 53 {
                client.udp_dns_conns = client.udp_dns_conns.saturating_add(1);
            } else {
                client.udp_other_conns = client.udp_other_conns.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        collectors::conntrack::{CollectStats, NETLINK_COUNTER_SOURCE},
        connection_details::ClientConnectionSet,
        identity::{IdentityObservation, ObservationSource},
    };

    const IDENTITY_KEY: &str = "02:00:00:00:00:01@lan";

    fn identities() -> IdentityTable {
        let mut table = IdentityTable::new(4);
        table
            .observe(IdentityObservation {
                mac: "02:00:00:00:00:01",
                zone: Some("lan"),
                interface: "br-lan",
                ip: Some("192.0.2.10"),
                hostname: None,
                last_seen: 1,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
        table
    }

    fn collected(detail: Option<ClientConnectionDetail>) -> CollectedSnapshot {
        let connection_details = detail.map_or_else(BTreeMap::new, |detail| {
            BTreeMap::from([(
                IDENTITY_KEY.into(),
                ClientConnectionSet {
                    total_connections: 1,
                    connections: vec![detail],
                    truncated: false,
                },
            )])
        });
        CollectedSnapshot {
            clients: Vec::new(),
            sample_ms: 2_000,
            connection_details: Arc::new(connection_details),
            connection_counters: Arc::default(),
            counter_source: NETLINK_COUNTER_SOURCE,
            stats: CollectStats::default(),
        }
    }

    fn sample(source: ProxySource, generation: &str) -> ProxyConnectionSample {
        ProxyConnectionSample {
            source,
            generation: generation.into(),
            client_ip: "192.0.2.10".parse().unwrap(),
            client_port: 50_123,
            remote_ip: Some("198.51.100.20".parse().unwrap()),
            remote_port: 443,
            protocol: ConnectionProtocol::Tcp,
            tx_bytes: Some(400),
            rx_bytes: Some(900),
        }
    }

    #[test]
    fn proxy_rate_book_uses_adjacent_cumulative_samples() {
        let mut rates = ProxyRateBook::default();
        let first = rates.update(
            ProxySource::Mihomo,
            1_000,
            vec![sample(ProxySource::Mihomo, "a")],
        );
        assert_eq!((first[0].tx_bps, first[0].rx_bps), (None, None));
        let mut second = sample(ProxySource::Mihomo, "a");
        second.tx_bytes = Some(1_400);
        second.rx_bytes = Some(2_900);
        let second = rates.update(ProxySource::Mihomo, 2_000, vec![second]);
        assert_eq!(
            (second[0].tx_bps, second[0].rx_bps),
            (Some(8_000), Some(16_000))
        );
    }

    #[test]
    fn proxy_connection_settings_default_to_openclash_auto_detection() {
        let settings = ProxyConnectionSettings::default();
        assert!(settings.enabled);
        assert_eq!(settings.mihomo_controller_port, None);
        assert_eq!(settings.mihomo_controller_secret, None);
    }

    #[test]
    fn proxy_sample_replaces_redirect_detail_rate_and_adds_missing_flow() {
        let existing = ClientConnectionDetail {
            client_ip: "192.0.2.10".parse().unwrap(),
            client_port: 50_123,
            remote_ip: "192.0.2.1".parse().unwrap(),
            remote_port: 7892,
            protocol: ConnectionProtocol::Tcp,
            state: ConnectionState::Established,
            direction: ConnectionDirection::Outbound,
            tx_bps: 7,
            rx_bps: 9,
        };
        let mut snapshot = collected(Some(existing));
        let replacement = RatedProxyConnection {
            sample: sample(ProxySource::Mihomo, "a"),
            tx_bps: Some(80_000),
            rx_bps: Some(160_000),
        };
        let mut missing = sample(ProxySource::Dae, "b");
        missing.client_port = 50_124;
        missing.remote_ip = Some("203.0.113.30".parse().unwrap());
        let result = merge_samples(
            &mut snapshot,
            &identities(),
            4,
            vec![
                replacement,
                RatedProxyConnection {
                    sample: missing,
                    tx_bps: None,
                    rx_bps: None,
                },
            ],
        );
        assert_eq!((result.replaced, result.added, result.omitted), (1, 1, 0));
        let set = &snapshot.connection_details[IDENTITY_KEY];
        assert_eq!(set.total_connections, 2);
        assert_eq!(set.connections.len(), 2);
        let replaced = set
            .connections
            .iter()
            .find(|detail| detail.client_port == 50_123)
            .unwrap();
        assert_eq!(
            replaced.remote_ip,
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!((replaced.tx_bps, replaced.rx_bps), (80_000, 160_000));
        assert_eq!(snapshot.clients[0].tcp_conns, 1);
    }

    #[test]
    fn duplicate_proxy_sources_and_unresolved_targets_do_not_inflate_counts() {
        let mut snapshot = collected(None);
        let first = sample(ProxySource::Mihomo, "a");
        let mut duplicate = sample(ProxySource::Dae, "b");
        duplicate.remote_ip = Some("203.0.113.40".parse().unwrap());
        duplicate.remote_port = 8_443;
        let mut unresolved = sample(ProxySource::Dae, "c");
        unresolved.client_port = 50_124;
        unresolved.remote_ip = None;
        let result = merge_samples(
            &mut snapshot,
            &identities(),
            4,
            vec![
                RatedProxyConnection {
                    sample: first,
                    tx_bps: None,
                    rx_bps: None,
                },
                RatedProxyConnection {
                    sample: duplicate,
                    tx_bps: None,
                    rx_bps: None,
                },
                RatedProxyConnection {
                    sample: unresolved,
                    tx_bps: None,
                    rx_bps: None,
                },
            ],
        );
        assert_eq!((result.added, result.omitted), (1, 1));
        assert_eq!(
            snapshot.connection_details[IDENTITY_KEY].total_connections,
            1
        );
        assert_eq!(
            snapshot.connection_details[IDENTITY_KEY].connections[0].remote_ip,
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            snapshot.connection_details[IDENTITY_KEY].connections[0].remote_port,
            443
        );
        assert_eq!(snapshot.clients[0].tcp_conns, 1);
    }
}
