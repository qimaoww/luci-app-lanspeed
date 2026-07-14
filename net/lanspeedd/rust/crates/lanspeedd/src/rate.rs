use crate::config::DEFAULT_MAX_CLIENTS;
use serde_json::{Map, Value};

pub const RATE_WINDOW_COUNT: usize = 3;
pub const STALE_CLIENT_MS: u64 = 5_000;
pub const RATE_BASELINE_RETENTION_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateWarning {
    CounterAnomaly,
    TimeRollback,
    ClientLimitExceeded,
    MapReadFailed,
}

impl RateWarning {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CounterAnomaly => "counter_anomaly",
            Self::TimeRollback => "time_rollback",
            Self::ClientLimitExceeded => "client_limit_exceeded",
            Self::MapReadFailed => "map_read_failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientCounters {
    pub identity_key: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_seen_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateDelta {
    pub bps: u64,
    pub warning: Option<RateWarning>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientRate {
    pub identity_key: String,
    pub tx_bps: u64,
    pub rx_bps: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub sample_ms: u64,
    pub last_seen_ms: u64,
    pub warnings: Vec<RateWarning>,
}

impl ClientRate {
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert(
            "identity_key".to_owned(),
            Value::String(self.identity_key.clone()),
        );
        object.insert("tx_bps".to_owned(), json_u64(self.tx_bps));
        object.insert("rx_bps".to_owned(), json_u64(self.rx_bps));
        object.insert("tx_bytes".to_owned(), json_u64(self.tx_bytes));
        object.insert("rx_bytes".to_owned(), json_u64(self.rx_bytes));
        object.insert("sample_ms".to_owned(), json_u64(self.sample_ms));
        object.insert("last_seen".to_owned(), json_u64(self.last_seen_ms));
        object.insert(
            "warnings".to_owned(),
            Value::Array(
                self.warnings
                    .iter()
                    .map(|warning| Value::String(warning.as_str().to_owned()))
                    .collect(),
            ),
        );
        Value::Object(object)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RateUpdate {
    pub clients: Vec<ClientRate>,
    pub rejected_clients: Vec<String>,
    pub warnings: Vec<RateWarning>,
}

impl RateUpdate {
    pub fn client(&self, identity_key: &str) -> Option<&ClientRate> {
        self.clients
            .iter()
            .find(|client| client.identity_key == identity_key)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CounterPoint {
    sample_ms: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    last_seen_ms: u64,
}

#[derive(Clone, Debug)]
struct ClientState {
    identity_key: String,
    history: [Option<CounterPoint>; RATE_WINDOW_COUNT],
    head: usize,
    count: usize,
}

impl ClientState {
    fn new(identity_key: String) -> Self {
        Self {
            identity_key,
            history: [None; RATE_WINDOW_COUNT],
            head: 0,
            count: 0,
        }
    }

    fn latest(&self) -> Option<CounterPoint> {
        if self.count == 0 {
            None
        } else {
            self.history[(self.head + RATE_WINDOW_COUNT - 1) % RATE_WINDOW_COUNT]
        }
    }

    fn push(&mut self, point: CounterPoint) {
        self.history[self.head] = Some(point);
        self.head = (self.head + 1) % RATE_WINDOW_COUNT;
        self.count = self.count.saturating_add(1).min(RATE_WINDOW_COUNT);
    }
}

#[derive(Clone, Debug)]
pub struct RateBook {
    max_clients: usize,
    stale_client_ms: u64,
    last_snapshot_ms: Option<u64>,
    clients: Vec<ClientState>,
}

impl RateBook {
    pub fn new(max_clients: usize, stale_client_ms: u64) -> Self {
        let max_clients = if max_clients > 0 && max_clients < DEFAULT_MAX_CLIENTS {
            max_clients
        } else {
            DEFAULT_MAX_CLIENTS
        };
        Self {
            max_clients,
            stale_client_ms,
            last_snapshot_ms: None,
            clients: Vec::new(),
        }
    }

    pub fn rate_from_delta(current: u64, previous: u64, delta_ms: u64) -> RateDelta {
        let Some(delta_bytes) = current.checked_sub(previous) else {
            return RateDelta {
                bps: 0,
                warning: Some(RateWarning::CounterAnomaly),
            };
        };
        if delta_ms == 0 {
            return RateDelta {
                bps: 0,
                warning: None,
            };
        }

        let scaled = u128::from(delta_bytes)
            .checked_mul(8)
            .and_then(|value| value.checked_mul(1_000))
            .unwrap_or(u128::MAX);
        let bps = scaled / u128::from(delta_ms);
        RateDelta {
            bps: u64::try_from(bps).unwrap_or(u64::MAX),
            warning: None,
        }
    }

    pub fn update(
        &mut self,
        now_ms: u64,
        samples: impl IntoIterator<Item = ClientCounters>,
    ) -> RateUpdate {
        let retention_ms = self.stale_client_ms.max(RATE_BASELINE_RETENTION_MS);
        self.clients.retain(|client| {
            client
                .latest()
                .is_some_and(|point| !is_stale(now_ms, point.sample_ms, retention_ms))
        });

        let time_rollback = self
            .last_snapshot_ms
            .is_some_and(|previous_ms| now_ms < previous_ms);
        let mut update = RateUpdate::default();
        if time_rollback {
            push_unique(&mut update.warnings, RateWarning::TimeRollback);
        }

        for sample in samples {
            let stale_for_output = is_stale(now_ms, sample.last_seen_ms, self.stale_client_ms);
            let existing_index = self
                .clients
                .iter()
                .position(|client| client.identity_key == sample.identity_key);
            if stale_for_output
                && existing_index.is_none()
                && self.clients.len() == self.max_clients
            {
                continue;
            }

            let state_index = if let Some(index) = existing_index {
                index
            } else {
                if self.clients.len() == self.max_clients {
                    let evict = self
                        .clients
                        .iter()
                        .enumerate()
                        .filter_map(|(index, client)| {
                            let point = client.latest()?;
                            is_stale(now_ms, point.last_seen_ms, self.stale_client_ms)
                                .then_some((index, point.last_seen_ms))
                        })
                        .min_by_key(|(_, last_seen_ms)| *last_seen_ms)
                        .map(|(index, _)| index);
                    if let Some(index) = evict {
                        self.clients.remove(index);
                    }
                }
                if self.clients.len() == self.max_clients {
                    update.rejected_clients.push(sample.identity_key);
                    push_unique(&mut update.warnings, RateWarning::ClientLimitExceeded);
                    continue;
                }
                self.clients
                    .push(ClientState::new(sample.identity_key.clone()));
                self.clients.len() - 1
            };

            let state = &mut self.clients[state_index];
            let previous = state.latest();
            let client_time_rollback = previous.is_some_and(|point| now_ms < point.sample_ms);
            let rate_time_rollback = time_rollback || client_time_rollback;
            let effective_last_seen = previous
                .filter(|point| {
                    point.tx_bytes == sample.tx_bytes && point.rx_bytes == sample.rx_bytes
                })
                .map_or(sample.last_seen_ms, |point| point.last_seen_ms);
            let point = CounterPoint {
                sample_ms: now_ms,
                tx_bytes: sample.tx_bytes,
                rx_bytes: sample.rx_bytes,
                last_seen_ms: effective_last_seen,
            };
            if stale_for_output {
                state.push(point);
                continue;
            }
            let mut client = ClientRate {
                identity_key: sample.identity_key,
                tx_bps: 0,
                rx_bps: 0,
                tx_bytes: sample.tx_bytes,
                rx_bytes: sample.rx_bytes,
                sample_ms: now_ms,
                last_seen_ms: effective_last_seen,
                warnings: Vec::new(),
            };
            if rate_time_rollback {
                push_unique(&mut client.warnings, RateWarning::TimeRollback);
                push_unique(&mut update.warnings, RateWarning::TimeRollback);
            }
            if let Some(previous) = previous {
                let delta_ms = if rate_time_rollback {
                    0
                } else {
                    now_ms.checked_sub(previous.sample_ms).unwrap_or(0)
                };
                let tx = Self::rate_from_delta(sample.tx_bytes, previous.tx_bytes, delta_ms);
                let rx = Self::rate_from_delta(sample.rx_bytes, previous.rx_bytes, delta_ms);
                client.tx_bps = tx.bps;
                client.rx_bps = rx.bps;
                for warning in [tx.warning, rx.warning].into_iter().flatten() {
                    push_unique(&mut client.warnings, warning);
                    push_unique(&mut update.warnings, warning);
                }
            }
            state.push(point);
            update.clients.push(client);
        }

        self.last_snapshot_ms = Some(now_ms);
        update
    }

    pub fn map_read_failed(&self) -> RateUpdate {
        RateUpdate {
            warnings: vec![RateWarning::MapReadFailed],
            ..RateUpdate::default()
        }
    }

    pub fn contains(&self, identity_key: &str) -> bool {
        self.clients
            .iter()
            .any(|client| client.identity_key == identity_key)
    }

    pub fn identity_keys(&self) -> impl Iterator<Item = String> + '_ {
        self.clients
            .iter()
            .map(|client| client.identity_key.clone())
    }

    pub fn window_len(&self, identity_key: &str) -> Option<usize> {
        self.clients
            .iter()
            .find(|client| client.identity_key == identity_key)
            .map(|client| client.count)
    }
}

fn is_stale(now_ms: u64, last_seen_ms: u64, stale_client_ms: u64) -> bool {
    now_ms
        .checked_sub(last_seen_ms)
        .is_some_and(|age| age > stale_client_ms)
}

fn push_unique(warnings: &mut Vec<RateWarning>, warning: RateWarning) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
}

pub(crate) fn json_u64(value: u64) -> Value {
    Value::from(i64::try_from(value).unwrap_or(i64::MAX))
}
