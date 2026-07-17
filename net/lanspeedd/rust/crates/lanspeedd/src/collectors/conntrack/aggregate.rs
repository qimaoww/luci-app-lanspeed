use super::FlowSample;
use crate::{
    connection_details::{
        classify_connection, classify_flow_ownership, ConnectionCounters,
        ConnectionCountersSnapshot, ConnectionDetailsIndex, ConnectionDetailsSnapshot,
        ConnectionProtocol, FlowOwnership,
    },
    identity::IdentityTable,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientSample {
    pub mac: String,
    pub identity_key: String,
    pub zone: String,
    pub interface: String,
    pub ips: Vec<String>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_seen_ms: u64,
    pub tcp_conns: u32,
    pub udp_conns: u32,
    pub udp_dns_conns: u32,
    pub udp_other_conns: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AggregateStats {
    pub entries_seen: usize,
    pub entries_matched: usize,
    pub skipped_no_arp: usize,
    pub no_lan_flows: usize,
    pub both_lan_flows: usize,
    pub src_lan_flows: usize,
    pub dst_lan_flows: usize,
    pub ipv4_lan_flows: usize,
    pub ipv6_lan_flows: usize,
    pub clients_dropped: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AggregateSnapshot {
    pub clients: Vec<ClientSample>,
    pub stats: AggregateStats,
    pub sample_ms: u64,
    pub connection_details: ConnectionDetailsSnapshot,
    pub connection_counters: ConnectionCountersSnapshot,
}

pub struct AggregateState<'a> {
    identities: &'a IdentityTable,
    clients: BTreeMap<String, ClientSample>,
    connection_details: ConnectionDetailsIndex,
    stats: AggregateStats,
    now_ms: u64,
    max_clients: usize,
}

impl<'a> AggregateState<'a> {
    pub fn new(identities: &'a IdentityTable, now_ms: u64, max_clients: usize) -> Self {
        Self {
            identities,
            clients: BTreeMap::new(),
            connection_details: ConnectionDetailsIndex::default(),
            stats: AggregateStats::default(),
            now_ms,
            max_clients,
        }
    }

    pub fn push(&mut self, flow: &FlowSample) {
        self.stats.entries_seen = self.stats.entries_seen.saturating_add(1);
        let owned = match classify_flow_ownership(self.identities, flow) {
            FlowOwnership::BothLan => {
                self.stats.both_lan_flows = self.stats.both_lan_flows.saturating_add(1);
                return;
            }
            FlowOwnership::NoLan => {
                self.stats.skipped_no_arp = self.stats.skipped_no_arp.saturating_add(1);
                self.stats.no_lan_flows = self.stats.no_lan_flows.saturating_add(1);
                return;
            }
            FlowOwnership::Owned(owned) => owned,
        };
        let key = owned.identity.key.to_string();
        if !self.clients.contains_key(&key) && self.clients.len() >= self.max_clients {
            self.stats.clients_dropped = self.stats.clients_dropped.saturating_add(1);
            return;
        }
        let qualification = classify_connection(flow);
        let (tx, rx) = if owned.source_side {
            (flow.orig_bytes, flow.reply_bytes)
        } else {
            (flow.reply_bytes, flow.orig_bytes)
        };
        {
            let sample = self
                .clients
                .entry(key.clone())
                .or_insert_with(|| ClientSample {
                    mac: owned.identity.key.mac.to_string(),
                    identity_key: key.clone(),
                    zone: owned.identity.key.zone.clone(),
                    interface: owned.identity.interface.clone(),
                    ips: owned.identity.ips.clone(),
                    tx_bytes: 0,
                    rx_bytes: 0,
                    last_seen_ms: self.now_ms,
                    tcp_conns: 0,
                    udp_conns: 0,
                    udp_dns_conns: 0,
                    udp_other_conns: 0,
                });
            sample.tx_bytes = sample.tx_bytes.saturating_add(tx);
            sample.rx_bytes = sample.rx_bytes.saturating_add(rx);
            sample.last_seen_ms = self.now_ms;
            if let Some((protocol, _)) = qualification {
                add_connection_count(sample, flow, protocol);
            }
        }
        self.stats.entries_matched = self.stats.entries_matched.saturating_add(1);
        if owned.source_side {
            self.stats.src_lan_flows = self.stats.src_lan_flows.saturating_add(1);
        } else {
            self.stats.dst_lan_flows = self.stats.dst_lan_flows.saturating_add(1);
        }
        if owned.endpoints.client_ip.is_ipv6() {
            self.stats.ipv6_lan_flows = self.stats.ipv6_lan_flows.saturating_add(1);
        } else {
            self.stats.ipv4_lan_flows = self.stats.ipv4_lan_flows.saturating_add(1);
        }
        if let Some((protocol, state)) = qualification {
            match owned.detail(protocol, state) {
                Some(detail) => self.connection_details.record_with_counters(
                    &key,
                    detail,
                    ConnectionCounters {
                        tx_bytes: tx,
                        rx_bytes: rx,
                    },
                ),
                None => self.connection_details.record_omitted(&key),
            }
        }
    }

    pub fn finish(self) -> AggregateSnapshot {
        let (connection_details, connection_counters) =
            self.connection_details.finish_with_counters();
        AggregateSnapshot {
            clients: self.clients.into_values().collect(),
            stats: self.stats,
            sample_ms: self.now_ms,
            connection_details,
            connection_counters,
        }
    }
}

pub fn aggregate_flows<'a>(
    identities: &IdentityTable,
    flows: impl IntoIterator<Item = &'a FlowSample>,
    now_ms: u64,
    max_clients: usize,
) -> AggregateSnapshot {
    let mut state = AggregateState::new(identities, now_ms, max_clients);
    for flow in flows {
        state.push(flow);
    }
    state.finish()
}

fn add_connection_count(
    sample: &mut ClientSample,
    flow: &FlowSample,
    protocol: ConnectionProtocol,
) {
    match protocol {
        ConnectionProtocol::Tcp => {
            sample.tcp_conns = sample.tcp_conns.saturating_add(1);
        }
        ConnectionProtocol::Udp => {
            sample.udp_conns = sample.udp_conns.saturating_add(1);
            if flow.is_dns() {
                sample.udp_dns_conns = sample.udp_dns_conns.saturating_add(1);
            } else {
                sample.udp_other_conns = sample.udp_other_conns.saturating_add(1);
            }
        }
    }
}
