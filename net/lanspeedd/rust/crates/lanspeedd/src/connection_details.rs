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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeferredCounterRate {
    sample_ms: u64,
    bytes: u64,
    bps: u64,
    held_once: bool,
    history: DeferredRateHistory,
}

const DEFERRED_RATE_MEDIAN_SAMPLES: usize = 3;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DeferredRateHistory {
    samples: [u64; DEFERRED_RATE_MEDIAN_SAMPLES],
    len: u8,
    next: u8,
}

impl DeferredRateHistory {
    fn push(&mut self, bps: u64) -> u64 {
        self.samples[usize::from(self.next)] = bps;
        self.next = (self.next + 1) % DEFERRED_RATE_MEDIAN_SAMPLES as u8;
        if usize::from(self.len) < DEFERRED_RATE_MEDIAN_SAMPLES {
            self.len += 1;
        }
        if usize::from(self.len) < DEFERRED_RATE_MEDIAN_SAMPLES {
            return bps;
        }
        let mut ordered = self.samples;
        ordered.sort_unstable();
        ordered[DEFERRED_RATE_MEDIAN_SAMPLES / 2]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeferredConnectionRate {
    tx: DeferredCounterRate,
    rx: DeferredCounterRate,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectionRateBook {
    last_sample_ms: Option<u64>,
    previous: Arc<BTreeMap<ConnectionRateKey, ConnectionCounterPoint>>,
    last_deferred_sample_ms: Option<u64>,
    deferred: Arc<BTreeMap<ConnectionRateKey, DeferredConnectionRate>>,
}

impl ConnectionRateBook {
    pub fn update(
        &mut self,
        sample_ms: u64,
        counters: &ConnectionCountersSnapshot,
        details: &mut ConnectionDetailsSnapshot,
    ) {
        if self.last_deferred_sample_ms.is_some() || !self.deferred.is_empty() {
            self.last_deferred_sample_ms = None;
            self.deferred = Arc::default();
        }
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

    /// NSS may defer conntrack counter synchronization for one or more daemon
    /// samples. Keep each direction anchored to the last counter progress so a
    /// later multi-sample delta is divided by its real elapsed time. Until that
    /// progress arrives, retain the last complete rate for one NSS cycle
    /// instead of publishing a synthetic zero followed by a multiplied spike.
    pub fn update_deferred(
        &mut self,
        sample_ms: u64,
        counters: &ConnectionCountersSnapshot,
        details: &mut ConnectionDetailsSnapshot,
    ) {
        if self.last_sample_ms.is_some() || !self.previous.is_empty() {
            self.last_sample_ms = None;
            self.previous = Arc::default();
        }
        if self.last_deferred_sample_ms == Some(sample_ms) {
            return;
        }

        let mut folded = BTreeMap::<ConnectionRateKey, ConnectionCounters>::new();
        for (key, counters) in counters.iter() {
            let value = folded.entry(key.clone().without_generation()).or_default();
            value.tx_bytes = value.tx_bytes.saturating_add(counters.tx_bytes);
            value.rx_bytes = value.rx_bytes.saturating_add(counters.rx_bytes);
        }
        let current = folded
            .into_iter()
            .map(|(key, counters)| {
                let previous = self.deferred.get(&key);
                (
                    key,
                    DeferredConnectionRate {
                        tx: deferred_counter_rate(
                            sample_ms,
                            counters.tx_bytes,
                            previous.map(|value| value.tx),
                        ),
                        rx: deferred_counter_rate(
                            sample_ms,
                            counters.rx_bytes,
                            previous.map(|value| value.rx),
                        ),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        for (identity_key, set) in Arc::make_mut(details) {
            for detail in &mut set.connections {
                detail.tx_bps = 0;
                detail.rx_bps = 0;
                let key = ConnectionRateKey::new(identity_key, detail);
                let Some(rate) = current.get(&key) else {
                    continue;
                };
                detail.tx_bps = rate.tx.bps;
                detail.rx_bps = rate.rx.bps;
            }
        }

        self.deferred = Arc::new(current);
        self.last_deferred_sample_ms = Some(sample_ms);
    }

    pub fn clear(&mut self) {
        self.last_sample_ms = None;
        self.previous = Arc::default();
        self.last_deferred_sample_ms = None;
        self.deferred = Arc::default();
    }
}

fn deferred_counter_rate(
    sample_ms: u64,
    bytes: u64,
    previous: Option<DeferredCounterRate>,
) -> DeferredCounterRate {
    let Some(previous) = previous else {
        return DeferredCounterRate {
            sample_ms,
            bytes,
            bps: 0,
            held_once: false,
            history: DeferredRateHistory::default(),
        };
    };
    if bytes == previous.bytes {
        if previous.bps > 0 && !previous.held_once {
            return DeferredCounterRate {
                held_once: true,
                ..previous
            };
        }
        return DeferredCounterRate {
            sample_ms,
            bytes,
            bps: 0,
            held_once: false,
            history: DeferredRateHistory::default(),
        };
    }
    let Some(delta_ms) = sample_ms.checked_sub(previous.sample_ms) else {
        return DeferredCounterRate {
            sample_ms,
            bytes,
            bps: 0,
            held_once: false,
            history: DeferredRateHistory::default(),
        };
    };
    if bytes < previous.bytes || delta_ms == 0 {
        return DeferredCounterRate {
            sample_ms,
            bytes,
            bps: 0,
            held_once: false,
            history: DeferredRateHistory::default(),
        };
    }
    let mut history = previous.history;
    let bps = history.push(rate_from_counters(bytes, previous.bytes, delta_ms));
    DeferredCounterRate {
        sample_ms,
        bytes,
        bps,
        held_once: false,
        history,
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

    fn counters(tx_bytes: u64, rx_bytes: u64) -> ConnectionCountersSnapshot {
        Arc::new(BTreeMap::from([(
            rate_key(Some(7)),
            ConnectionCounters { tx_bytes, rx_bytes },
        )]))
    }

    fn details() -> ConnectionDetailsSnapshot {
        Arc::new(BTreeMap::from([(
            "client".into(),
            ClientConnectionSet {
                total_connections: 1,
                connections: vec![ClientConnectionDetail {
                    client_ip: "192.0.2.2".parse().unwrap(),
                    client_port: 12_345,
                    remote_ip: "198.51.100.2".parse().unwrap(),
                    remote_port: 443,
                    protocol: ConnectionProtocol::Tcp,
                    state: ConnectionState::Established,
                    direction: ConnectionDirection::Outbound,
                    tx_bps: 0,
                    rx_bps: 0,
                }],
                truncated: false,
            },
        )]))
    }

    fn rates(details: &ConnectionDetailsSnapshot) -> (u64, u64) {
        let detail = &details["client"].connections[0];
        (detail.tx_bps, detail.rx_bps)
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
            ..ConnectionRateBook::default()
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
    fn immediate_mode_keeps_advancing_the_baseline_on_stalled_counters() {
        let mut book = ConnectionRateBook::default();
        let mut first = details();
        book.update(1_000, &counters(100, 200), &mut first);

        let mut stalled = details();
        book.update(3_000, &counters(100, 200), &mut stalled);
        assert_eq!(rates(&stalled), (0, 0));

        let mut progressed = details();
        book.update(5_000, &counters(25_000_100, 2_500_200), &mut progressed);
        assert_eq!(rates(&progressed), (100_000_000, 10_000_000));
    }

    #[test]
    fn deferred_mode_uses_each_directions_real_progress_window() {
        let mut book = ConnectionRateBook::default();
        let mut warmup = details();
        book.update_deferred(1_000, &counters(100, 200), &mut warmup);
        assert_eq!(rates(&warmup), (0, 0));

        let mut first = details();
        book.update_deferred(3_000, &counters(25_000_100, 2_500_200), &mut first);
        assert_eq!(rates(&first), (100_000_000, 10_000_000));

        // TX is waiting for an NSS conntrack synchronization while RX moves.
        let mut tx_stalled = details();
        book.update_deferred(5_000, &counters(25_000_100, 5_000_200), &mut tx_stalled);
        assert_eq!(rates(&tx_stalled), (100_000_000, 10_000_000));

        // The next TX counter contains four seconds of traffic. It must use
        // the four-second progress window, not the latest two-second sample.
        let mut tx_progressed = details();
        book.update_deferred(7_000, &counters(75_000_100, 5_000_200), &mut tx_progressed);
        assert_eq!(rates(&tx_progressed), (100_000_000, 10_000_000));
    }

    #[test]
    fn deferred_mode_holds_once_then_rebaselines_a_genuinely_idle_flow() {
        let mut book = ConnectionRateBook::default();
        let mut warmup = details();
        book.update_deferred(1_000, &counters(100, 200), &mut warmup);
        let mut first = details();
        book.update_deferred(3_000, &counters(25_000_100, 2_500_200), &mut first);
        assert_eq!(rates(&first), (100_000_000, 10_000_000));

        let mut held = details();
        book.update_deferred(5_000, &counters(25_000_100, 2_500_200), &mut held);
        assert_eq!(rates(&held), rates(&first));

        let mut idle = details();
        book.update_deferred(7_000, &counters(25_000_100, 2_500_200), &mut idle);
        assert_eq!(rates(&idle), (0, 0));

        let mut resumed = details();
        book.update_deferred(9_000, &counters(50_000_100, 5_000_200), &mut resumed);
        assert_eq!(rates(&resumed), (100_000_000, 10_000_000));
    }

    #[test]
    fn deferred_mode_rejects_a_paired_low_high_sync_alias_without_clamping() {
        let mut book = ConnectionRateBook::default();
        let mut details_at = |sample_ms, tx_bytes, rx_bytes| {
            let mut value = details();
            book.update_deferred(sample_ms, &counters(tx_bytes, rx_bytes), &mut value);
            rates(&value)
        };

        assert_eq!(details_at(1_000, 100, 200), (0, 0));
        assert_eq!(
            details_at(3_000, 25_000_100, 2_500_200),
            (100_000_000, 10_000_000)
        );
        assert_eq!(
            details_at(5_000, 50_000_100, 5_000_200),
            (100_000_000, 10_000_000)
        );
        assert_eq!(
            details_at(7_000, 75_000_100, 7_500_200),
            (100_000_000, 10_000_000)
        );

        // One empty poll followed by a late partial sync produces a 0.5x raw
        // window; the next catch-up produces a 1.5x raw window. The median of
        // three real progress windows publishes neither alias and never sums
        // or clamps counters.
        assert_eq!(
            details_at(9_000, 75_000_100, 7_500_200),
            (100_000_000, 10_000_000)
        );
        assert_eq!(
            details_at(11_000, 100_000_100, 10_000_200),
            (100_000_000, 10_000_000)
        );
        assert_eq!(
            details_at(13_000, 137_500_100, 13_750_200),
            (100_000_000, 10_000_000)
        );
    }

    #[test]
    fn switching_modes_rewarms_instead_of_reusing_an_old_baseline() {
        let mut book = ConnectionRateBook::default();
        let mut warmup = details();
        book.update_deferred(1_000, &counters(100, 200), &mut warmup);
        let mut deferred = details();
        book.update_deferred(3_000, &counters(25_000_100, 2_500_200), &mut deferred);
        assert_eq!(rates(&deferred), (100_000_000, 10_000_000));

        let mut immediate = details();
        book.update(5_000, &counters(50_000_100, 5_000_200), &mut immediate);
        assert_eq!(rates(&immediate), (0, 0));
        assert!(book.deferred.is_empty());
    }
}
