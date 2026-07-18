use crate::{
    collectors::conntrack::{FlowSample, Protocol, TcpState},
    identity::{ClientIdentity, IdentityTable},
};
use serde::Serialize;
use std::{cmp::Ordering, collections::BTreeMap, net::IpAddr, sync::Arc};

pub const MAX_STORED_CONNECTION_DETAILS: usize = 16_384;
// Keep a single response bounded for ubus/LuCI while covering high-connection clients.
pub const MAX_CLIENT_CONNECTION_DETAILS: usize = 2_048;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientConnectionSummary {
    pub identity_key: String,
    pub hostname: Option<String>,
    pub mac: String,
    pub ips: Vec<String>,
    pub interface: String,
    pub zone: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientConnectionsResponse {
    pub available: bool,
    pub sample_ms: Option<u64>,
    pub client: Option<ClientConnectionSummary>,
    pub total_connections: u64,
    pub returned_connections: usize,
    pub truncated: bool,
    pub limit: usize,
    pub conn_source: Option<String>,
    pub conn_semantics: String,
    pub connections: Vec<ClientConnectionDetail>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    Established,
    Assured,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionDirection {
    Outbound,
    Inbound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientConnectionDetail {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: ConnectionProtocol,
    pub state: ConnectionState,
    pub direction: ConnectionDirection,
    pub tx_bps: u64,
    pub rx_bps: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ClientConnectionSet {
    pub total_connections: u64,
    pub connections: Vec<ClientConnectionDetail>,
    pub truncated: bool,
}

pub type ConnectionDetailsSnapshot = Arc<BTreeMap<String, ClientConnectionSet>>;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectionRateKey {
    pub identity_key: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: ConnectionProtocol,
    pub direction: ConnectionDirection,
}

impl ConnectionRateKey {
    pub fn new(identity_key: &str, detail: &ClientConnectionDetail) -> Self {
        Self {
            identity_key: identity_key.to_owned(),
            client_ip: detail.client_ip,
            client_port: detail.client_port,
            remote_ip: detail.remote_ip,
            remote_port: detail.remote_port,
            protocol: detail.protocol,
            direction: detail.direction,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionCounters {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

pub type ConnectionCountersSnapshot = Arc<BTreeMap<ConnectionRateKey, ConnectionCounters>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConnectionCounterPoint {
    sample_ms: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectionRateBook {
    last_sample_ms: Option<u64>,
    previous: Arc<BTreeMap<ConnectionRateKey, ConnectionCounterPoint>>,
}

impl ConnectionRateBook {
    pub fn update(
        &mut self,
        sample_ms: u64,
        counters: &ConnectionCountersSnapshot,
        details: &mut ConnectionDetailsSnapshot,
    ) {
        if self.last_sample_ms == Some(sample_ms) {
            return;
        }

        let mut current = BTreeMap::new();
        for (key, counters) in counters.iter() {
            current.insert(
                key.clone(),
                ConnectionCounterPoint {
                    sample_ms,
                    tx_bytes: counters.tx_bytes,
                    rx_bytes: counters.rx_bytes,
                },
            );
        }

        for (identity_key, set) in Arc::make_mut(details) {
            for detail in &mut set.connections {
                detail.tx_bps = 0;
                detail.rx_bps = 0;
                let key = ConnectionRateKey::new(identity_key, detail);
                let Some(point) = current.get(&key) else {
                    continue;
                };
                let Some(previous) = self.previous.get(&key) else {
                    continue;
                };
                let Some(delta_ms) = point.sample_ms.checked_sub(previous.sample_ms) else {
                    continue;
                };
                detail.tx_bps = rate_from_counters(point.tx_bytes, previous.tx_bytes, delta_ms);
                detail.rx_bps = rate_from_counters(point.rx_bytes, previous.rx_bytes, delta_ms);
            }
        }

        self.previous = Arc::new(current);
        self.last_sample_ms = Some(sample_ms);
    }

    pub fn clear(&mut self) {
        self.last_sample_ms = None;
        self.previous = Arc::default();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PublishedConnectionDetails {
    Unavailable,
    Incomplete {
        sample_ms: u64,
        conn_source: String,
    },
    Available {
        sample_ms: u64,
        conn_source: String,
        by_identity: ConnectionDetailsSnapshot,
    },
}

#[derive(Debug, Default)]
pub struct ConnectionDetailsIndex {
    sets: BTreeMap<String, ClientConnectionSet>,
    counters: BTreeMap<ConnectionRateKey, ConnectionCounters>,
    stored_connections: usize,
}

impl ConnectionDetailsIndex {
    pub fn record(&mut self, identity_key: &str, detail: ClientConnectionDetail) {
        self.record_inner(identity_key, detail, None);
    }

    pub fn record_with_counters(
        &mut self,
        identity_key: &str,
        detail: ClientConnectionDetail,
        counters: ConnectionCounters,
    ) {
        self.record_inner(identity_key, detail, Some(counters));
    }

    fn record_inner(
        &mut self,
        identity_key: &str,
        detail: ClientConnectionDetail,
        counters: Option<ConnectionCounters>,
    ) {
        let set = self.sets.entry(identity_key.to_owned()).or_default();
        set.total_connections = set.total_connections.saturating_add(1);
        if set.connections.len() < MAX_CLIENT_CONNECTION_DETAILS
            && self.stored_connections < MAX_STORED_CONNECTION_DETAILS
        {
            if let Some(counters) = counters {
                self.counters
                    .insert(ConnectionRateKey::new(identity_key, &detail), counters);
            }
            set.connections.push(detail);
            self.stored_connections = self.stored_connections.saturating_add(1);
        } else {
            set.truncated = true;
        }
    }

    pub fn record_omitted(&mut self, identity_key: &str) {
        let set = self.sets.entry(identity_key.to_owned()).or_default();
        set.total_connections = set.total_connections.saturating_add(1);
        set.truncated = true;
    }

    pub fn finish(self) -> ConnectionDetailsSnapshot {
        self.finish_with_counters().0
    }

    pub fn finish_with_counters(
        mut self,
    ) -> (ConnectionDetailsSnapshot, ConnectionCountersSnapshot) {
        for set in self.sets.values_mut() {
            sort_connection_details(&mut set.connections);
            set.truncated |= set.connections.len() as u64 != set.total_connections;
        }
        (Arc::new(self.sets), Arc::new(self.counters))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedFlowEndpoints {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedFlow<'a> {
    pub identity: &'a ClientIdentity,
    pub endpoints: OwnedFlowEndpoints,
    pub direction: ConnectionDirection,
    pub source_side: bool,
}

impl OwnedFlow<'_> {
    pub fn detail(
        self,
        protocol: ConnectionProtocol,
        state: ConnectionState,
    ) -> Option<ClientConnectionDetail> {
        Some(ClientConnectionDetail {
            client_ip: self.endpoints.client_ip,
            client_port: self.endpoints.client_port,
            remote_ip: self.endpoints.remote_ip?,
            remote_port: self.endpoints.remote_port,
            protocol,
            state,
            direction: self.direction,
            tx_bps: 0,
            rx_bps: 0,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowOwnership<'a> {
    BothLan,
    NoLan,
    Owned(OwnedFlow<'a>),
}

pub fn classify_flow_ownership<'a>(
    identities: &'a IdentityTable,
    flow: &FlowSample,
) -> FlowOwnership<'a> {
    let orig_src = owner(identities, flow.orig_src);
    let orig_dst = owner(identities, flow.orig_dst);
    let reply_src = owner(identities, flow.reply_src);
    let reply_dst = owner(identities, flow.reply_dst);

    if (orig_src.is_some() && orig_dst.is_some()) || (reply_src.is_some() && reply_dst.is_some()) {
        return FlowOwnership::BothLan;
    }

    if let Some((identity, client_ip)) = orig_src {
        return FlowOwnership::Owned(OwnedFlow {
            identity,
            endpoints: OwnedFlowEndpoints {
                client_ip,
                client_port: flow.orig_sport,
                remote_ip: flow.orig_dst,
                remote_port: flow.orig_dport,
            },
            direction: ConnectionDirection::Outbound,
            source_side: true,
        });
    }
    if let Some((identity, client_ip)) = orig_dst {
        return FlowOwnership::Owned(OwnedFlow {
            identity,
            endpoints: OwnedFlowEndpoints {
                client_ip,
                client_port: flow.orig_dport,
                remote_ip: flow.orig_src,
                remote_port: flow.orig_sport,
            },
            direction: ConnectionDirection::Inbound,
            source_side: false,
        });
    }
    if let Some((identity, client_ip)) = reply_src {
        return FlowOwnership::Owned(OwnedFlow {
            identity,
            endpoints: OwnedFlowEndpoints {
                client_ip,
                client_port: flow.reply_sport,
                remote_ip: flow.reply_dst,
                remote_port: flow.reply_dport,
            },
            direction: ConnectionDirection::Inbound,
            source_side: false,
        });
    }
    if let Some((identity, client_ip)) = reply_dst {
        return FlowOwnership::Owned(OwnedFlow {
            identity,
            endpoints: OwnedFlowEndpoints {
                client_ip,
                client_port: flow.reply_dport,
                remote_ip: flow.reply_src,
                remote_port: flow.reply_sport,
            },
            direction: ConnectionDirection::Outbound,
            source_side: true,
        });
    }

    FlowOwnership::NoLan
}

pub fn classify_connection(flow: &FlowSample) -> Option<(ConnectionProtocol, ConnectionState)> {
    match flow.protocol {
        Protocol::Tcp if flow.tcp_state == Some(TcpState::Established) && flow.assured => {
            Some((ConnectionProtocol::Tcp, ConnectionState::Established))
        }
        Protocol::Udp if flow.assured => Some((ConnectionProtocol::Udp, ConnectionState::Assured)),
        Protocol::Tcp | Protocol::Udp | Protocol::Other(_) => None,
    }
}

fn sort_connection_details(details: &mut [ClientConnectionDetail]) {
    details.sort_by(compare_connection_details);
}

fn owner(table: &IdentityTable, address: Option<IpAddr>) -> Option<(&ClientIdentity, IpAddr)> {
    let address = address?;
    table
        .by_ip(&address.to_string())
        .map(|identity| (identity, address))
}

fn compare_connection_details(
    left: &ClientConnectionDetail,
    right: &ClientConnectionDetail,
) -> Ordering {
    compare_ip(left.remote_ip, right.remote_ip)
        .then_with(|| left.remote_port.cmp(&right.remote_port))
        .then_with(|| protocol_rank(left.protocol).cmp(&protocol_rank(right.protocol)))
        .then_with(|| compare_ip(left.client_ip, right.client_ip))
        .then_with(|| left.client_port.cmp(&right.client_port))
        .then_with(|| direction_rank(left.direction).cmp(&direction_rank(right.direction)))
}

fn rate_from_counters(current: u64, previous: u64, delta_ms: u64) -> u64 {
    let Some(delta_bytes) = current.checked_sub(previous) else {
        return 0;
    };
    if delta_ms == 0 {
        return 0;
    }
    let scaled = u128::from(delta_bytes)
        .saturating_mul(8)
        .saturating_mul(1_000);
    u64::try_from(scaled / u128::from(delta_ms)).unwrap_or(u64::MAX)
}

fn compare_ip(left: IpAddr, right: IpAddr) -> Ordering {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
    }
}

const fn protocol_rank(protocol: ConnectionProtocol) -> u8 {
    match protocol {
        ConnectionProtocol::Tcp => 0,
        ConnectionProtocol::Udp => 1,
    }
}

const fn direction_rank(direction: ConnectionDirection) -> u8 {
    match direction {
        ConnectionDirection::Outbound => 0,
        ConnectionDirection::Inbound => 1,
    }
}

#[cfg(test)]
mod rate_book_tests {
    use super::*;

    #[test]
    fn checkpoint_clone_shares_the_previous_counter_map() {
        let key = ConnectionRateKey {
            identity_key: "client".into(),
            client_ip: "192.0.2.2".parse().unwrap(),
            client_port: 12_345,
            remote_ip: "198.51.100.2".parse().unwrap(),
            remote_port: 443,
            protocol: ConnectionProtocol::Tcp,
            direction: ConnectionDirection::Outbound,
        };
        let mut book = ConnectionRateBook {
            last_sample_ms: Some(1_000),
            previous: Arc::new(BTreeMap::from([(
                key,
                ConnectionCounterPoint {
                    sample_ms: 1_000,
                    tx_bytes: 100,
                    rx_bytes: 200,
                },
            )])),
        };

        let checkpoint = book.clone();

        assert!(Arc::ptr_eq(&book.previous, &checkpoint.previous));

        let counters = Arc::default();
        let mut details = Arc::default();
        book.update(2_000, &counters, &mut details);

        assert!(!Arc::ptr_eq(&book.previous, &checkpoint.previous));
        assert!(book.previous.is_empty());
        assert_eq!(checkpoint.previous.len(), 1);
    }
}
