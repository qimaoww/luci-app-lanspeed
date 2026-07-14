use crate::rate::json_u64;
use serde_json::{Map, Value};

pub const OVERVIEW_WINDOW: usize = 240;
pub const OVERVIEW_SAMPLE_SOURCE: &str = "clients_refresh_daemon_ring";
pub const OVERVIEW_CONN_SEMANTICS: &str =
    "conntrack_current_tcp_established_assured_udp_assured_dns_split";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionTotals {
    pub tcp_conns: u64,
    pub udp_conns: u64,
    pub udp_dns_conns: u64,
    pub udp_other_conns: u64,
}

impl ConnectionTotals {
    pub const fn new(
        tcp_conns: u64,
        udp_conns: u64,
        udp_dns_conns: u64,
        udp_other_conns: u64,
    ) -> Self {
        Self {
            tcp_conns,
            udp_conns,
            udp_dns_conns,
            udp_other_conns,
        }
    }

    fn add_assign_saturating(&mut self, other: Self) {
        self.tcp_conns = self.tcp_conns.saturating_add(other.tcp_conns);
        self.udp_conns = self.udp_conns.saturating_add(other.udp_conns);
        self.udp_dns_conns = self.udp_dns_conns.saturating_add(other.udp_dns_conns);
        self.udp_other_conns = self.udp_other_conns.saturating_add(other.udp_other_conns);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionTotalsOverride {
    pub tcp_conns: Option<u64>,
    pub udp_conns: Option<u64>,
    pub udp_dns_conns: Option<u64>,
    pub udp_other_conns: Option<u64>,
}

impl ConnectionTotalsOverride {
    fn apply(self, totals: &mut ConnectionTotals) {
        if let Some(value) = self.tcp_conns {
            totals.tcp_conns = value;
        }
        if let Some(value) = self.udp_conns {
            totals.udp_conns = value;
        }
        if let Some(value) = self.udp_dns_conns {
            totals.udp_dns_conns = value;
        }
        if let Some(value) = self.udp_other_conns {
            totals.udp_other_conns = value;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverviewClient {
    pub tx_bps: u64,
    pub rx_bps: u64,
    pub sample_ms: u64,
    pub last_seen_ms: u64,
    pub connections: ConnectionTotals,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverviewConfig {
    pub window_samples: usize,
    pub active_client_window_ms: u64,
    pub active_client_min_bps: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OverviewSample {
    pub sample_ms: u64,
    pub tx_bps: u64,
    pub rx_bps: u64,
    pub client_count: u32,
    pub active_clients: u32,
    pub tcp_conns: u32,
    pub udp_conns: u32,
    pub udp_dns_conns: u32,
    pub udp_other_conns: u32,
}

impl OverviewSample {
    fn to_json(self) -> Value {
        let mut object = Map::new();
        object.insert("sample_ms".to_owned(), json_u64(self.sample_ms));
        object.insert("tx_bps".to_owned(), json_u64(self.tx_bps));
        object.insert("rx_bps".to_owned(), json_u64(self.rx_bps));
        object.insert("client_count".to_owned(), Value::from(self.client_count));
        object.insert(
            "active_clients".to_owned(),
            Value::from(self.active_clients),
        );
        object.insert("tcp_conns".to_owned(), Value::from(self.tcp_conns));
        object.insert("udp_conns".to_owned(), Value::from(self.udp_conns));
        object.insert("udp_dns_conns".to_owned(), Value::from(self.udp_dns_conns));
        object.insert(
            "udp_other_conns".to_owned(),
            Value::from(self.udp_other_conns),
        );
        Value::Object(object)
    }
}

#[derive(Clone, Debug)]
pub struct OverviewRing {
    samples: [Option<OverviewSample>; OVERVIEW_WINDOW],
    head: usize,
    count: usize,
}

impl OverviewRing {
    pub fn new() -> Self {
        Self {
            samples: [None; OVERVIEW_WINDOW],
            head: 0,
            count: 0,
        }
    }

    pub const fn capacity(&self) -> usize {
        OVERVIEW_WINDOW
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn latest(&self) -> Option<&OverviewSample> {
        if self.count == 0 {
            None
        } else {
            self.samples[(self.head + OVERVIEW_WINDOW - 1) % OVERVIEW_WINDOW].as_ref()
        }
    }

    pub fn replace_latest_connections_and_client_count(
        &mut self,
        connections: ConnectionTotals,
        client_count: usize,
    ) -> bool {
        let Some(latest) = self.count.checked_sub(1).and_then(|_| {
            self.samples[(self.head + OVERVIEW_WINDOW - 1) % OVERVIEW_WINDOW].as_mut()
        }) else {
            return false;
        };
        latest.tcp_conns = u32::try_from(connections.tcp_conns).unwrap_or(u32::MAX);
        latest.udp_conns = u32::try_from(connections.udp_conns).unwrap_or(u32::MAX);
        latest.udp_dns_conns = u32::try_from(connections.udp_dns_conns).unwrap_or(u32::MAX);
        latest.udp_other_conns = u32::try_from(connections.udp_other_conns).unwrap_or(u32::MAX);
        latest.client_count = u32::try_from(client_count).unwrap_or(u32::MAX);
        true
    }

    pub fn push(
        &mut self,
        now_ms: u64,
        clients: &[OverviewClient],
        overrides: ConnectionTotalsOverride,
        config: &OverviewConfig,
    ) {
        let mut sample = OverviewSample {
            sample_ms: now_ms,
            client_count: u32::try_from(clients.len()).unwrap_or(u32::MAX),
            ..OverviewSample::default()
        };
        let mut connections = ConnectionTotals::default();
        for client in clients {
            sample.tx_bps = sample.tx_bps.saturating_add(client.tx_bps);
            sample.rx_bps = sample.rx_bps.saturating_add(client.rx_bps);
            connections.add_assign_saturating(client.connections);
            if client_is_active(client, config) {
                sample.active_clients = sample.active_clients.saturating_add(1);
            }
        }
        overrides.apply(&mut connections);
        sample.tcp_conns = u32::try_from(connections.tcp_conns).unwrap_or(u32::MAX);
        sample.udp_conns = u32::try_from(connections.udp_conns).unwrap_or(u32::MAX);
        sample.udp_dns_conns = u32::try_from(connections.udp_dns_conns).unwrap_or(u32::MAX);
        sample.udp_other_conns = u32::try_from(connections.udp_other_conns).unwrap_or(u32::MAX);

        self.samples[self.head] = Some(sample);
        self.head = (self.head + 1) % OVERVIEW_WINDOW;
        self.count = self.count.saturating_add(1).min(OVERVIEW_WINDOW);
    }

    pub fn to_json(&self, config: &OverviewConfig) -> Value {
        let mut serialized = Vec::new();
        for index in (1..=self.count).rev() {
            if index > config.window_samples {
                continue;
            }
            if let Some(sample) = self.sample_at(index - 1) {
                serialized.push(sample.to_json());
            }
        }

        let mut object = Map::new();
        object.insert("samples".to_owned(), Value::Array(serialized));
        object.insert(
            "max_samples".to_owned(),
            Value::from(OVERVIEW_WINDOW as u64),
        );
        object.insert(
            "overview_window_samples".to_owned(),
            json_u64(config.window_samples as u64),
        );
        object.insert(
            "active_client_window_ms".to_owned(),
            json_u64(config.active_client_window_ms),
        );
        object.insert(
            "active_client_min_bps".to_owned(),
            json_u64(config.active_client_min_bps),
        );
        object.insert(
            "sample_source".to_owned(),
            Value::String(OVERVIEW_SAMPLE_SOURCE.to_owned()),
        );
        object.insert(
            "conn_semantics".to_owned(),
            Value::String(OVERVIEW_CONN_SEMANTICS.to_owned()),
        );
        Value::Object(object)
    }

    fn sample_at(&self, index_back: usize) -> Option<OverviewSample> {
        if index_back >= self.count {
            return None;
        }
        self.samples[(self.head + OVERVIEW_WINDOW - 1 - index_back) % OVERVIEW_WINDOW]
    }
}

impl Default for OverviewRing {
    fn default() -> Self {
        Self::new()
    }
}

fn client_is_active(client: &OverviewClient, config: &OverviewConfig) -> bool {
    if client.sample_ms == 0 || client.last_seen_ms == 0 || client.last_seen_ms > client.sample_ms {
        return false;
    }
    let recent = client.sample_ms - client.last_seen_ms <= config.active_client_window_ms;
    let rate = client.tx_bps.saturating_add(client.rx_bps);
    recent && rate >= config.active_client_min_bps
}
