//! Logical connection recovery for transparent proxy processes.
//!
//! Conntrack may expose only the client-to-proxy half after a transparent proxy
//! takes ownership of the socket. Mihomo supplies its logical connection ledger
//! through the loopback external-controller API. dae/daed does not expose an equivalent
//! per-connection API, so active TCP sockets are recovered from its dedicated
//! `daens` network namespace, TCP byte counters from SOCK_DIAG, and UDP tuples
//! from its timer-backed eBPF state map. The recovered entries enrich connection
//! metadata only; they do not contribute to either platform's total rate.

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
    remote_port: u16,
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
    let original_lengths = sets
        .iter()
        .map(|(identity, set)| (identity.clone(), set.connections.len()))
        .collect::<BTreeMap<_, _>>();
    let original_tcp_details = sets
        .values()
        .flat_map(|set| &set.connections)
        .filter(|detail| {
            detail.direction == ConnectionDirection::Outbound
                && detail.protocol == ConnectionProtocol::Tcp
        })
        .map(|detail| {
            (
                detail.client_ip,
                detail.client_port,
                detail.remote_ip,
                detail.remote_port,
            )
        })
        .collect::<BTreeSet<_>>();
    let claimed_tcp_details = samples
        .iter()
        .filter(|rated| rated.sample.protocol == ConnectionProtocol::Tcp)
        .filter_map(|rated| {
            let sample = &rated.sample;
            sample.remote_ip.map(|remote_ip| {
                (
                    sample.client_ip,
                    sample.client_port,
                    remote_ip,
                    sample.remote_port,
                )
            })
        })
        .collect::<BTreeSet<_>>();
    let unmatched_tcp_targets = samples
        .iter()
        .filter(|rated| rated.sample.protocol == ConnectionProtocol::Tcp)
        .filter(|rated| {
            let sample = &rated.sample;
            sample.remote_ip.is_none_or(|remote_ip| {
                !original_tcp_details.contains(&(
                    sample.client_ip,
                    sample.client_port,
                    remote_ip,
                    sample.remote_port,
                ))
            })
        })
        .fold(BTreeMap::<_, BTreeSet<_>>::new(), |mut targets, rated| {
            let sample = &rated.sample;
            targets
                .entry((sample.client_ip, sample.client_port))
                .or_default()
                .insert((sample.remote_ip, sample.remote_port));
            targets
        });

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
            remote_ip: sample.remote_ip,
            remote_port: sample.remote_port,
            protocol: sample.protocol,
        };
        if !seen.insert(logical_key) {
            continue;
        }

        let set = sets.entry(identity_key.clone()).or_default();
        let original_len = original_lengths.get(&identity_key).copied().unwrap_or(0);
        let unique_unmatched_tcp_target = unmatched_tcp_targets
            .get(&(sample.client_ip, sample.client_port))
            .is_some_and(|targets| targets.len() == 1);
        if let Some(index) = matching_detail_index(
            &set.connections,
            sample,
            original_len,
            unique_unmatched_tcp_target,
            &claimed_tcp_details,
        ) {
            let detail = &mut set.connections[index];
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

fn matching_detail_index(
    details: &[ClientConnectionDetail],
    sample: &ProxyConnectionSample,
    original_len: usize,
    unique_unmatched_tcp_target: bool,
    claimed_tcp_details: &BTreeSet<(IpAddr, u16, IpAddr, u16)>,
) -> Option<usize> {
    let same_client_socket = |detail: &ClientConnectionDetail| {
        detail.direction == ConnectionDirection::Outbound
            && detail.client_ip == sample.client_ip
            && detail.client_port == sample.client_port
            && detail.protocol == sample.protocol
    };
    match sample.protocol {
        ConnectionProtocol::Tcp => {
            if let Some(remote_ip) = sample.remote_ip {
                if let Some(index) = details.iter().position(|detail| {
                    same_client_socket(detail)
                        && detail.remote_ip == remote_ip
                        && detail.remote_port == sample.remote_port
                }) {
                    return Some(index);
                }
            }
            if !unique_unmatched_tcp_target {
                return None;
            }
            // A mismatched destination is safe to relabel only when conntrack
            // shows a loopback REDIRECT endpoint. A router-interface address
            // could instead be an unrelated direct connection to the router.
            // With an unresolved proxy destination, keep a unique same-port
            // conntrack endpoint and update its rate without relabeling it.
            let mut candidates =
                details
                    .iter()
                    .take(original_len)
                    .enumerate()
                    .filter(|(_, detail)| {
                        same_client_socket(detail)
                            && !claimed_tcp_details.contains(&(
                                detail.client_ip,
                                detail.client_port,
                                detail.remote_ip,
                                detail.remote_port,
                            ))
                            && match sample.remote_ip {
                                Some(_) => detail.remote_ip.is_loopback(),
                                None => detail.remote_port == sample.remote_port,
                            }
                    });
            let (index, _) = candidates.next()?;
            candidates.next().is_none().then_some(index)
        }
        ConnectionProtocol::Udp => details.iter().position(|detail| {
            same_client_socket(detail)
                && detail.remote_port == sample.remote_port
                && sample
                    .remote_ip
                    .is_none_or(|remote| detail.remote_ip == remote)
        }),
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
        connections::apply_conntrack_success,
        identity::{IdentityObservation, ObservationSource},
        model::{Client, Confidence},
        state::ResponseSnapshot,
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
        collected_with_details(detail.into_iter().collect())
    }

    fn collected_with_details(details: Vec<ClientConnectionDetail>) -> CollectedSnapshot {
        let connection_details = if details.is_empty() {
            BTreeMap::new()
        } else {
            BTreeMap::from([(
                IDENTITY_KEY.into(),
                ClientConnectionSet {
                    total_connections: details.len() as u64,
                    connections: details,
                    truncated: false,
                },
            )])
        };
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

    fn tcp_detail(remote_ip: &str, remote_port: u16) -> ClientConnectionDetail {
        ClientConnectionDetail {
            client_ip: "192.0.2.10".parse().unwrap(),
            client_port: 50_123,
            remote_ip: remote_ip.parse().unwrap(),
            remote_port,
            protocol: ConnectionProtocol::Tcp,
            state: ConnectionState::Established,
            direction: ConnectionDirection::Outbound,
            tx_bps: 7,
            rx_bps: 9,
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
        let existing = tcp_detail("127.0.0.1", 7892);
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
        let duplicate = sample(ProxySource::Dae, "b");
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

    #[test]
    fn distinct_tcp_destinations_with_same_client_source_port_are_retained() {
        let mut snapshot = collected(None);
        let first = sample(ProxySource::Mihomo, "a");
        let mut second = sample(ProxySource::Dae, "b");
        second.remote_ip = Some("203.0.113.40".parse().unwrap());
        second.remote_port = 8_443;
        let result = merge_samples(
            &mut snapshot,
            &identities(),
            4,
            vec![
                RatedProxyConnection {
                    sample: first,
                    tx_bps: Some(8_000),
                    rx_bps: Some(16_000),
                },
                RatedProxyConnection {
                    sample: second,
                    tx_bps: Some(24_000),
                    rx_bps: Some(32_000),
                },
            ],
        );
        assert_eq!((result.replaced, result.added, result.omitted), (0, 2, 0));
        let set = &snapshot.connection_details[IDENTITY_KEY];
        assert_eq!(set.total_connections, 2);
        assert_eq!(set.connections.len(), 2);
        assert!(set.connections.iter().any(|detail| {
            detail.remote_ip == "198.51.100.20".parse::<IpAddr>().unwrap()
                && detail.remote_port == 443
                && detail.tx_bps == 8_000
        }));
        assert!(set.connections.iter().any(|detail| {
            detail.remote_ip == "203.0.113.40".parse::<IpAddr>().unwrap()
                && detail.remote_port == 8_443
                && detail.tx_bps == 24_000
        }));
        assert_eq!(snapshot.clients[0].tcp_conns, 2);
    }

    #[test]
    fn proxy_sample_does_not_replace_unrelated_direct_tcp_detail() {
        let direct = tcp_detail("203.0.113.40", 443);
        let mut snapshot = collected(Some(direct.clone()));
        let result = merge_samples(
            &mut snapshot,
            &identities(),
            4,
            vec![RatedProxyConnection {
                sample: sample(ProxySource::Mihomo, "proxy"),
                tx_bps: Some(80_000),
                rx_bps: Some(160_000),
            }],
        );
        assert_eq!((result.replaced, result.added), (0, 1));
        let set = &snapshot.connection_details[IDENTITY_KEY];
        assert_eq!(set.total_connections, 2);
        assert!(set.connections.contains(&direct));
        assert!(set.connections.iter().any(|detail| {
            detail.remote_ip == "198.51.100.20".parse::<IpAddr>().unwrap()
                && detail.tx_bps == 80_000
        }));
    }

    #[test]
    fn exact_tcp_tuple_wins_when_a_proxy_sample_arrives_first() {
        let direct = tcp_detail("203.0.113.40", 443);
        let mut snapshot = collected(Some(direct));
        let mut exact = sample(ProxySource::Dae, "direct");
        exact.remote_ip = Some("203.0.113.40".parse().unwrap());
        let result = merge_samples(
            &mut snapshot,
            &identities(),
            4,
            vec![
                RatedProxyConnection {
                    sample: sample(ProxySource::Mihomo, "proxy"),
                    tx_bps: Some(80_000),
                    rx_bps: Some(160_000),
                },
                RatedProxyConnection {
                    sample: exact,
                    tx_bps: Some(8_000),
                    rx_bps: Some(16_000),
                },
            ],
        );
        assert_eq!((result.replaced, result.added), (1, 1));
        let set = &snapshot.connection_details[IDENTITY_KEY];
        let direct = set
            .connections
            .iter()
            .find(|detail| detail.remote_ip == "203.0.113.40".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!((direct.tx_bps, direct.rx_bps), (8_000, 16_000));
        let proxy = set
            .connections
            .iter()
            .find(|detail| detail.remote_ip == "198.51.100.20".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!((proxy.tx_bps, proxy.rx_bps), (80_000, 160_000));
    }

    #[test]
    fn redirect_fallback_preserves_colliding_exact_direct_flow() {
        let direct = tcp_detail("203.0.113.40", 443);
        let redirect = tcp_detail("127.0.0.1", 7892);
        let mut snapshot = collected_with_details(vec![direct, redirect]);
        let mut exact = sample(ProxySource::Dae, "direct");
        exact.remote_ip = Some("203.0.113.40".parse().unwrap());
        let result = merge_samples(
            &mut snapshot,
            &identities(),
            4,
            vec![
                RatedProxyConnection {
                    sample: sample(ProxySource::Mihomo, "proxy"),
                    tx_bps: Some(80_000),
                    rx_bps: Some(160_000),
                },
                RatedProxyConnection {
                    sample: exact,
                    tx_bps: Some(8_000),
                    rx_bps: Some(16_000),
                },
            ],
        );
        assert_eq!((result.replaced, result.added), (2, 0));
        let set = &snapshot.connection_details[IDENTITY_KEY];
        assert_eq!(set.total_connections, 2);
        let direct = set
            .connections
            .iter()
            .find(|detail| detail.remote_ip == "203.0.113.40".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!((direct.tx_bps, direct.rx_bps), (8_000, 16_000));
        let proxy = set
            .connections
            .iter()
            .find(|detail| detail.remote_ip == "198.51.100.20".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!((proxy.tx_bps, proxy.rx_bps), (80_000, 160_000));
    }

    #[test]
    fn router_address_mismatch_remains_separate_without_redirect_evidence() {
        let router_service = tcp_detail("192.0.2.1", 7892);
        let mut snapshot = collected(Some(router_service.clone()));
        let result = merge_samples(
            &mut snapshot,
            &identities(),
            4,
            vec![RatedProxyConnection {
                sample: sample(ProxySource::Mihomo, "proxy"),
                tx_bps: Some(80_000),
                rx_bps: Some(160_000),
            }],
        );
        assert_eq!((result.replaced, result.added), (0, 1));
        let set = &snapshot.connection_details[IDENTITY_KEY];
        assert_eq!(set.total_connections, 2);
        assert!(set.connections.contains(&router_service));
    }

    #[test]
    fn ambiguous_redirect_candidates_are_not_replaced() {
        let first = tcp_detail("127.0.0.1", 7892);
        let second = tcp_detail("127.0.0.2", 7893);
        let mut snapshot = collected_with_details(vec![first.clone(), second.clone()]);
        let result = merge_samples(
            &mut snapshot,
            &identities(),
            4,
            vec![RatedProxyConnection {
                sample: sample(ProxySource::Mihomo, "proxy"),
                tx_bps: Some(80_000),
                rx_bps: Some(160_000),
            }],
        );
        assert_eq!((result.replaced, result.added), (0, 1));
        let set = &snapshot.connection_details[IDENTITY_KEY];
        assert_eq!(set.total_connections, 3);
        assert!(set.connections.contains(&first));
        assert!(set.connections.contains(&second));
    }

    #[test]
    fn unresolved_tcp_target_updates_only_unique_same_port_detail() {
        let existing = tcp_detail("203.0.113.40", 443);
        let mut snapshot = collected(Some(existing.clone()));
        let mut unresolved = sample(ProxySource::Mihomo, "unknown");
        unresolved.remote_ip = None;
        let result = merge_samples(
            &mut snapshot,
            &identities(),
            4,
            vec![RatedProxyConnection {
                sample: unresolved,
                tx_bps: Some(80_000),
                rx_bps: Some(160_000),
            }],
        );
        assert_eq!((result.replaced, result.added, result.omitted), (1, 0, 0));
        let set = &snapshot.connection_details[IDENTITY_KEY];
        assert_eq!(set.total_connections, 1);
        assert_eq!(set.connections[0].remote_ip, existing.remote_ip);
        assert_eq!(set.connections[0].remote_port, existing.remote_port);
        assert_eq!(
            (set.connections[0].tx_bps, set.connections[0].rx_bps),
            (80_000, 160_000)
        );
    }

    #[test]
    fn proxy_enrichment_does_not_change_published_client_rate_or_bytes() {
        let mut published = ResponseSnapshot::unsupported("test");
        published.clients.clients.push(Client {
            mac: "02:00:00:00:00:01".into(),
            identity_key: IDENTITY_KEY.into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.10".into()],
            hostname: None,
            rx_bps: 88_000,
            tx_bps: 44_000,
            last_seen: 1_000,
            sample_ms: Some(1_000),
            rx_bytes: Some(800_000),
            tx_bytes: Some(400_000),
            collector_mode: "edge_authority".into(),
            confidence: Confidence::High,
            warnings: Vec::new(),
            tcp_conns: None,
            udp_conns: None,
            udp_dns_conns: None,
            udp_other_conns: None,
            rate_meta: None,
            control: None,
        });
        let mut snapshot = collected(None);
        let result = merge_samples(
            &mut snapshot,
            &identities(),
            4,
            vec![RatedProxyConnection {
                sample: sample(ProxySource::Mihomo, "proxy-flow"),
                tx_bps: Some(1_000_000),
                rx_bps: Some(2_000_000),
            }],
        );
        assert_eq!(result.added, 1);
        let overlaid = apply_conntrack_success(&published, &snapshot, "auto");
        let client = &overlaid.clients.clients[0];
        assert_eq!((client.tx_bps, client.rx_bps), (44_000, 88_000));
        assert_eq!(
            (client.tx_bytes, client.rx_bytes),
            (Some(400_000), Some(800_000))
        );
        assert_eq!(client.collector_mode, "edge_authority");
        assert_eq!(client.tcp_conns, Some(1));
        assert_eq!(
            overlaid.client_connections(IDENTITY_KEY).connections[0].tx_bps,
            1_000_000
        );
    }
}
