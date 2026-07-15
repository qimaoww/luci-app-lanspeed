use crate::{
    collectors::conntrack::{FlowSample, Protocol, TcpState},
    identity::{ClientIdentity, IdentityTable},
};
use serde::Serialize;
use std::{cmp::Ordering, collections::BTreeMap, net::IpAddr, sync::Arc};

pub const MAX_STORED_CONNECTION_DETAILS: usize = 16_384;
pub const MAX_CLIENT_CONNECTION_DETAILS: usize = 512;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ClientConnectionSet {
    pub total_connections: u64,
    pub connections: Vec<ClientConnectionDetail>,
    pub truncated: bool,
}

pub type ConnectionDetailsSnapshot = Arc<BTreeMap<String, ClientConnectionSet>>;

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
    stored_connections: usize,
}

impl ConnectionDetailsIndex {
    pub fn record(&mut self, identity_key: &str, detail: ClientConnectionDetail) {
        let set = self.sets.entry(identity_key.to_owned()).or_default();
        set.total_connections = set.total_connections.saturating_add(1);
        if set.connections.len() < MAX_CLIENT_CONNECTION_DETAILS
            && self.stored_connections < MAX_STORED_CONNECTION_DETAILS
        {
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

    pub fn finish(mut self) -> ConnectionDetailsSnapshot {
        for set in self.sets.values_mut() {
            sort_connection_details(&mut set.connections);
            set.truncated |= set.connections.len() as u64 != set.total_connections;
        }
        Arc::new(self.sets)
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
