use super::{FlowSample, Protocol, TcpState};
use crate::identity::{ClientIdentity, IdentityTable};
use std::{collections::BTreeMap, net::IpAddr};

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
}

pub struct AggregateState<'a> {
    identities: &'a IdentityTable,
    clients: BTreeMap<String, ClientSample>,
    stats: AggregateStats,
    now_ms: u64,
    max_clients: usize,
}

impl<'a> AggregateState<'a> {
    pub fn new(identities: &'a IdentityTable, now_ms: u64, max_clients: usize) -> Self {
        Self {
            identities,
            clients: BTreeMap::new(),
            stats: AggregateStats::default(),
            now_ms,
            max_clients,
        }
    }

    pub fn push(&mut self, flow: &FlowSample) {
        self.stats.entries_seen = self.stats.entries_seen.saturating_add(1);
        let orig_src = owner(self.identities, flow.orig_src);
        let orig_dst = owner(self.identities, flow.orig_dst);
        let reply_src = owner(self.identities, flow.reply_src);
        let reply_dst = owner(self.identities, flow.reply_dst);
        if (orig_src.is_some() && orig_dst.is_some())
            || (reply_src.is_some() && reply_dst.is_some())
        {
            self.stats.both_lan_flows = self.stats.both_lan_flows.saturating_add(1);
            return;
        }
        let endpoint = if let Some(identity) = orig_src {
            Some((identity, true, flow.orig_src))
        } else if let Some(identity) = orig_dst {
            Some((identity, false, flow.orig_dst))
        } else if let Some(identity) = reply_src {
            Some((identity, false, flow.reply_src))
        } else {
            reply_dst.map(|identity| (identity, true, flow.reply_dst))
        };
        let Some((identity, source_side, endpoint_ip)) = endpoint else {
            self.stats.skipped_no_arp = self.stats.skipped_no_arp.saturating_add(1);
            self.stats.no_lan_flows = self.stats.no_lan_flows.saturating_add(1);
            return;
        };
        let key = identity.key.to_string();
        if !self.clients.contains_key(&key) && self.clients.len() >= self.max_clients {
            self.stats.clients_dropped = self.stats.clients_dropped.saturating_add(1);
            return;
        }
        let sample = self
            .clients
            .entry(key.clone())
            .or_insert_with(|| ClientSample {
                mac: identity.key.mac.to_string(),
                identity_key: key,
                zone: identity.key.zone.clone(),
                interface: identity.interface.clone(),
                ips: identity.ips.clone(),
                tx_bytes: 0,
                rx_bytes: 0,
                last_seen_ms: self.now_ms,
                tcp_conns: 0,
                udp_conns: 0,
                udp_dns_conns: 0,
                udp_other_conns: 0,
            });
        let (tx, rx) = if source_side {
            (flow.orig_bytes, flow.reply_bytes)
        } else {
            (flow.reply_bytes, flow.orig_bytes)
        };
        sample.tx_bytes = sample.tx_bytes.saturating_add(tx);
        sample.rx_bytes = sample.rx_bytes.saturating_add(rx);
        sample.last_seen_ms = self.now_ms;
        add_connection_count(sample, flow);
        self.stats.entries_matched = self.stats.entries_matched.saturating_add(1);
        if source_side {
            self.stats.src_lan_flows = self.stats.src_lan_flows.saturating_add(1);
        } else {
            self.stats.dst_lan_flows = self.stats.dst_lan_flows.saturating_add(1);
        }
        if endpoint_ip.is_some_and(|ip| ip.is_ipv6()) {
            self.stats.ipv6_lan_flows = self.stats.ipv6_lan_flows.saturating_add(1);
        } else {
            self.stats.ipv4_lan_flows = self.stats.ipv4_lan_flows.saturating_add(1);
        }
    }

    pub fn finish(self) -> AggregateSnapshot {
        AggregateSnapshot {
            clients: self.clients.into_values().collect(),
            stats: self.stats,
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

fn owner(table: &IdentityTable, address: Option<IpAddr>) -> Option<&ClientIdentity> {
    table.by_ip(&address?.to_string())
}

fn add_connection_count(sample: &mut ClientSample, flow: &FlowSample) {
    if flow.protocol == Protocol::Tcp
        && flow.tcp_state == Some(TcpState::Established)
        && flow.assured
    {
        sample.tcp_conns = sample.tcp_conns.saturating_add(1);
    } else if flow.protocol == Protocol::Udp && flow.assured {
        sample.udp_conns = sample.udp_conns.saturating_add(1);
        if flow.is_dns() {
            sample.udp_dns_conns = sample.udp_dns_conns.saturating_add(1);
        } else {
            sample.udp_other_conns = sample.udp_other_conns.saturating_add(1);
        }
    }
}
