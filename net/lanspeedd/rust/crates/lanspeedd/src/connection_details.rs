use crate::{
    collectors::conntrack::{FlowSample, Protocol, TcpState},
    identity::{ClientIdentity, IdentityTable},
};
use serde::Serialize;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::Arc,
};

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

/// Protocol identity used by the conntrack rate ledger.  Connection details
/// intentionally expose only TCP/UDP, while the client byte ledger must keep
/// accounting for every IP protocol (for example ICMP, ESP, or GRE).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RateProtocol {
    Tcp,
    Udp,
    Other(u8),
}

impl From<ConnectionProtocol> for RateProtocol {
    fn from(protocol: ConnectionProtocol) -> Self {
        match protocol {
            ConnectionProtocol::Tcp => Self::Tcp,
            ConnectionProtocol::Udp => Self::Udp,
        }
    }
}

impl From<Protocol> for RateProtocol {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Tcp => Self::Tcp,
            Protocol::Udp => Self::Udp,
            Protocol::Other(number) => Self::Other(number),
        }
    }
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
    pub conntrack_id: Option<u32>,
    pub conntrack_zone: Option<u16>,
    pub identity_key: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: u16,
    pub protocol: RateProtocol,
    pub direction: ConnectionDirection,
}

impl ConnectionRateKey {
    pub fn new(identity_key: &str, detail: &ClientConnectionDetail) -> Self {
        Self {
            conntrack_id: None,
            conntrack_zone: None,
            identity_key: identity_key.to_owned(),
            client_ip: detail.client_ip,
            client_port: detail.client_port,
            remote_ip: Some(detail.remote_ip),
            remote_port: detail.remote_port,
            protocol: detail.protocol.into(),
            direction: detail.direction,
        }
    }

    pub fn from_owned_flow(
        identity_key: &str,
        flow: OwnedFlow<'_>,
        protocol: Protocol,
        conntrack_id: Option<u32>,
        conntrack_zone: Option<u16>,
    ) -> Self {
        Self {
            conntrack_id,
            conntrack_zone,
            identity_key: identity_key.to_owned(),
            client_ip: flow.endpoints.client_ip,
            client_port: flow.endpoints.client_port,
            remote_ip: flow.endpoints.remote_ip,
            remote_port: flow.endpoints.remote_port,
            protocol: protocol.into(),
            direction: flow.direction,
        }
    }

    fn without_generation(mut self) -> Self {
        self.conntrack_id = None;
        self.conntrack_zone = None;
        self
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

        // Connection details intentionally do not expose kernel generation
        // metadata. Fold generations only for this presentation index; the
        // authoritative client ledger below keeps the full CTA_ID/zone key.
        let mut folded = BTreeMap::<ConnectionRateKey, ConnectionCounters>::new();
        for (key, counters) in counters.iter() {
            let value = folded.entry(key.clone().without_generation()).or_default();
            value.tx_bytes = value.tx_bytes.saturating_add(counters.tx_bytes);
            value.rx_bytes = value.rx_bytes.saturating_add(counters.rx_bytes);
        }
        let current = folded
            .into_iter()
            .map(|(key, counters)| {
                (
                    key,
                    ConnectionCounterPoint {
                        sample_ms,
                        tx_bytes: counters.tx_bytes,
                        rx_bytes: counters.rx_bytes,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientCounterTotals {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// Converts per-flow conntrack counters into monotonic per-client totals.
///
/// Conntrack snapshots contain only currently alive flows. Differencing an
/// already-aggregated client total therefore loses traffic whenever one flow
/// expires. Keeping the baseline per kernel flow generation makes flow removal
/// a no-op while allowing every surviving flow to contribute its own delta.
/// Ctnetlink generations are retained across transient snapshot/identity gaps;
/// tuple-only procfs baselines use a much shorter retention window because a
/// reused five-tuple cannot otherwise be distinguished safely.
pub const CT_ID_BASELINE_RETENTION_MS: u64 = 60_000;
pub const TUPLE_BASELINE_RETENTION_MS: u64 = 2_000;
pub const MAX_RETAINED_FLOW_BASELINES: usize = 32_768;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConntrackClientRateBook {
    initialized: bool,
    last_sample_ms: Option<u64>,
    previous: Arc<BTreeMap<ConnectionRateKey, ConnectionCounterPoint>>,
    totals: BTreeMap<String, ClientCounterTotals>,
}

impl ConntrackClientRateBook {
    pub fn update(
        &mut self,
        sample_ms: u64,
        counters: &ConnectionCountersSnapshot,
    ) -> BTreeMap<String, ClientCounterTotals> {
        if self.last_sample_ms == Some(sample_ms) {
            return current_client_totals(counters, &self.totals);
        }

        let time_rollback = self.last_sample_ms.is_some_and(|last| sample_ms < last);
        let have_baseline = self.initialized && !time_rollback;
        if time_rollback {
            self.previous = Arc::default();
        }
        let previous = Arc::make_mut(&mut self.previous);
        previous.retain(|key, point| {
            sample_ms.checked_sub(point.sample_ms).is_none_or(|age| {
                age <= if key.conntrack_id.is_some() {
                    CT_ID_BASELINE_RETENTION_MS
                } else {
                    TUPLE_BASELINE_RETENTION_MS
                }
            })
        });
        let mut active_clients = BTreeSet::new();
        let mut active_keys = BTreeSet::new();
        for (key, counters) in counters.iter() {
            active_clients.insert(key.identity_key.clone());
            active_keys.insert(key.clone());
            let point = ConnectionCounterPoint {
                sample_ms,
                tx_bytes: counters.tx_bytes,
                rx_bytes: counters.rx_bytes,
            };
            if have_baseline {
                let (tx_delta, rx_delta) =
                    previous
                        .get(key)
                        .map_or((point.tx_bytes, point.rx_bytes), |previous| {
                            if point.tx_bytes < previous.tx_bytes
                                || point.rx_bytes < previous.rx_bytes
                            {
                                // A direction rollback means the conntrack entry
                                // was reset or replaced. Treat both directions as
                                // the new generation so counters from two flow
                                // lifetimes are never mixed.
                                (point.tx_bytes, point.rx_bytes)
                            } else {
                                (
                                    point.tx_bytes - previous.tx_bytes,
                                    point.rx_bytes - previous.rx_bytes,
                                )
                            }
                        });
                let totals = self.totals.entry(key.identity_key.clone()).or_default();
                totals.tx_bytes = totals.tx_bytes.saturating_add(tx_delta);
                totals.rx_bytes = totals.rx_bytes.saturating_add(rx_delta);
            }
            self.totals.entry(key.identity_key.clone()).or_default();
            previous.insert(key.clone(), point);
        }

        if previous.len() > MAX_RETAINED_FLOW_BASELINES {
            let mut retired = previous
                .iter()
                .filter(|(key, _)| !active_keys.contains(*key))
                .map(|(key, point)| (point.sample_ms, key.clone()))
                .collect::<Vec<_>>();
            retired.sort_by_key(|(last_seen_ms, _)| *last_seen_ms);
            let remove = previous.len().saturating_sub(MAX_RETAINED_FLOW_BASELINES);
            for (_, key) in retired.into_iter().take(remove) {
                previous.remove(&key);
            }
        }
        self.last_sample_ms = Some(sample_ms);
        self.initialized = true;
        active_clients
            .into_iter()
            .filter_map(|identity_key| {
                self.totals
                    .get(&identity_key)
                    .copied()
                    .map(|totals| (identity_key, totals))
            })
            .collect()
    }

    pub fn clear_baseline(&mut self) {
        self.initialized = false;
        self.last_sample_ms = None;
        self.previous = Arc::default();
    }
}

fn current_client_totals(
    counters: &ConnectionCountersSnapshot,
    totals: &BTreeMap<String, ClientCounterTotals>,
) -> BTreeMap<String, ClientCounterTotals> {
    counters
        .keys()
        .filter_map(|key| {
            totals
                .get(&key.identity_key)
                .copied()
                .map(|value| (key.identity_key.clone(), value))
        })
        .collect()
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

    pub fn record_flow_rate_counters(
        &mut self,
        key: ConnectionRateKey,
        counters: ConnectionCounters,
    ) {
        self.counters.insert(key, counters);
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

    fn rate_key(conntrack_id: Option<u32>) -> ConnectionRateKey {
        ConnectionRateKey {
            conntrack_id,
            conntrack_zone: Some(0),
            identity_key: "client".into(),
            client_ip: "192.0.2.2".parse().unwrap(),
            client_port: 12_345,
            remote_ip: Some("198.51.100.2".parse().unwrap()),
            remote_port: 443,
            protocol: RateProtocol::Tcp,
            direction: ConnectionDirection::Outbound,
        }
    }

    fn counters(
        key: ConnectionRateKey,
        tx_bytes: u64,
        rx_bytes: u64,
    ) -> ConnectionCountersSnapshot {
        Arc::new(BTreeMap::from([(
            key,
            ConnectionCounters { tx_bytes, rx_bytes },
        )]))
    }

    #[test]
    fn checkpoint_clone_shares_the_previous_counter_map() {
        let key = rate_key(None);
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

    #[test]
    fn conntrack_checkpoint_clone_is_copy_on_write() {
        let key = rate_key(Some(1));
        let mut book = ConntrackClientRateBook::default();
        book.update(1_000, &counters(key.clone(), 100, 200));
        let checkpoint = book.clone();
        assert!(Arc::ptr_eq(&book.previous, &checkpoint.previous));

        book.update(2_000, &counters(key, 150, 275));

        assert!(!Arc::ptr_eq(&book.previous, &checkpoint.previous));
        assert_eq!(checkpoint.previous.values().next().unwrap().tx_bytes, 100);
        assert_eq!(book.totals["client"].tx_bytes, 50);
        assert_eq!(checkpoint.totals["client"].tx_bytes, 0);
    }

    #[test]
    fn conntrack_time_rollback_rebuilds_the_baseline_without_replaying_bytes() {
        let key = rate_key(Some(2));
        let mut book = ConntrackClientRateBook::default();
        book.update(2_000, &counters(key.clone(), 100, 200));
        let rollback = book.update(1_000, &counters(key.clone(), 500, 700));
        assert_eq!(rollback["client"], ClientCounterTotals::default());

        let resumed = book.update(2_000, &counters(key, 550, 775));
        assert_eq!(resumed["client"].tx_bytes, 50);
        assert_eq!(resumed["client"].rx_bytes, 75);
    }

    #[test]
    fn expired_cta_id_baseline_treats_reappearance_as_a_new_generation() {
        let key = rate_key(Some(3));
        let mut book = ConntrackClientRateBook::default();
        book.update(1_000, &counters(key.clone(), 100, 200));
        book.update(1_000 + CT_ID_BASELINE_RETENTION_MS + 1, &Arc::default());
        let totals = book.update(
            1_000 + CT_ID_BASELINE_RETENTION_MS + 2,
            &counters(key, 500, 700),
        );
        assert_eq!(totals["client"].tx_bytes, 500);
        assert_eq!(totals["client"].rx_bytes, 700);
    }

    #[test]
    fn tuple_only_baseline_expires_quickly_to_avoid_cross_generation_deltas() {
        let key = rate_key(None);
        let mut book = ConntrackClientRateBook::default();
        book.update(1_000, &counters(key.clone(), 100, 200));
        book.update(1_000 + TUPLE_BASELINE_RETENTION_MS + 1, &Arc::default());
        let totals = book.update(
            1_000 + TUPLE_BASELINE_RETENTION_MS + 2,
            &counters(key, 500, 700),
        );
        assert_eq!(totals["client"].tx_bytes, 500);
        assert_eq!(totals["client"].rx_bytes, 700);
    }

    #[test]
    fn retired_flow_baseline_count_is_bounded() {
        let previous = (0..MAX_RETAINED_FLOW_BASELINES + 2)
            .map(|index| {
                let key = rate_key(Some(index as u32));
                (
                    key,
                    ConnectionCounterPoint {
                        sample_ms: 1,
                        tx_bytes: 1,
                        rx_bytes: 1,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut book = ConntrackClientRateBook {
            initialized: true,
            last_sample_ms: Some(1),
            previous: Arc::new(previous),
            totals: BTreeMap::new(),
        };

        book.update(2, &Arc::default());

        assert_eq!(book.previous.len(), MAX_RETAINED_FLOW_BASELINES);
    }
}
