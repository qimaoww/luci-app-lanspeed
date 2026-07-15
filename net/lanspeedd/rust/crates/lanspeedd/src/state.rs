use std::{cell::RefCell, rc::Rc, sync::Arc};

use serde_json::Value;

use crate::{
    connection_details::{
        ClientConnectionSummary, ClientConnectionsResponse, ConnectionDetailsSnapshot,
        PublishedConnectionDetails, MAX_CLIENT_CONNECTION_DETAILS,
    },
    error::DaemonError,
    model::{
        Capabilities, ClientsResponse, Confidence, Evidence, HealthResponse, InterfacesResponse,
        Mode, OverviewResponse, ReloadResponse, StatusResponse, SysdevicesResponse,
    },
    ubus::Method,
};

pub const OVERVIEW_SAMPLE_SOURCE: &str = "clients_refresh_daemon_ring";
pub const CONNECTION_SEMANTICS: &str =
    "conntrack_current_tcp_established_assured_udp_assured_dns_split";

#[derive(Clone, Debug, PartialEq)]
pub struct ResponseSnapshot {
    pub status: StatusResponse,
    pub clients: ClientsResponse,
    pub overview: OverviewResponse,
    pub health: HealthResponse,
    pub reload: ReloadResponse,
    pub interfaces: InterfacesResponse,
    pub sysdevices: SysdevicesResponse,
    connection_details: PublishedConnectionDetails,
}

impl ResponseSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn from_responses(
        status: StatusResponse,
        clients: ClientsResponse,
        overview: OverviewResponse,
        health: HealthResponse,
        reload: ReloadResponse,
        interfaces: InterfacesResponse,
        sysdevices: SysdevicesResponse,
    ) -> Self {
        Self {
            status,
            clients,
            overview,
            health,
            reload,
            interfaces,
            sysdevices,
            connection_details: PublishedConnectionDetails::Unavailable,
        }
    }

    pub fn unsupported(version: impl Into<String>) -> Self {
        let version = version.into();
        let mut evidence = Evidence::default();
        evidence
            .details
            .insert("source".into(), Value::String("lanspeedd_rust".into()));
        evidence
            .details
            .insert("read_only".into(), Value::Bool(true));
        let capabilities = Capabilities {
            conntrack_fallback: true,
            ..Capabilities::default()
        };
        Self {
            status: StatusResponse {
                mode: Mode::Unsupported,
                confidence: Confidence::Unsupported,
                warnings: vec!["live_metrics_unavailable".into()],
                evidence: evidence.clone(),
                refresh_interval_ms: 1_000,
                active_client_window_ms: 10_000,
                active_client_min_bps: 1,
                overview_window_samples: 240,
                collector_mode: "auto".into(),
                rate_collector_mode: "auto".into(),
                conn_collector_mode: "auto".into(),
                version: version.clone(),
                capabilities: capabilities.clone(),
                coverage: None,
            },
            clients: ClientsResponse {
                clients: vec![], evidence: Some(evidence.clone()), tcp_conns_total: None,
                udp_conns_total: None, udp_dns_conns_total: None, udp_other_conns_total: None,
                conntrack_entries_seen: None, conntrack_entries_matched: None,
                conntrack_parse_errors: None, conn_source: None,
                nss_ecm_direct_flows_seen: None, nss_ecm_direct_flows_matched: None,
                nss_ecm_direct_parse_errors: None, conn_collector_mode: None,
                conn_semantics: None,
            },
            overview: OverviewResponse {
                samples: vec![], max_samples: 240, overview_window_samples: 240,
                active_client_window_ms: 10_000, active_client_min_bps: 1,
                sample_source: OVERVIEW_SAMPLE_SOURCE.into(),
                conn_semantics: CONNECTION_SEMANTICS.into(),
            },
            health: HealthResponse {
                mode: Mode::Unsupported, confidence: Confidence::Unsupported,
                capabilities, conflicts: vec![], warnings: vec!["live_metrics_unavailable".into()],
                evidence: evidence.clone(),
            },
            reload: ReloadResponse {
                ok: true, mode: Mode::Unsupported, warnings: vec!["live_metrics_unavailable".into()],
                evidence, version,
            },
            interfaces: InterfacesResponse {
                interfaces: vec![], monotonic_ms: Some(0),
                note: Some("Per-interface totals from kernel net device counters; reflect hardware-offloaded and hardware-switched traffic too.".into()),
                evidence: None,
            },
            sysdevices: SysdevicesResponse {
                devices: vec![], current_ifnames: vec![], current_observed: vec![],
            },
            connection_details: PublishedConnectionDetails::Unavailable,
        }
    }

    pub fn client_connections(&self, identity_key: &str) -> ClientConnectionsResponse {
        let current_client = self
            .clients
            .clients
            .iter()
            .find(|client| client.identity_key == identity_key);
        let client = current_client.map(|client| ClientConnectionSummary {
            identity_key: client.identity_key.clone(),
            hostname: client.hostname.clone(),
            mac: client.mac.clone(),
            ips: client.ips.clone(),
            interface: client.interface.clone(),
            zone: client.zone.clone(),
        });
        let mut warnings = Vec::new();
        if current_client.is_none() {
            warnings.push("client_not_found".to_owned());
        }

        match &self.connection_details {
            PublishedConnectionDetails::Unavailable => {
                warnings.push("conntrack_unavailable".to_owned());
                ClientConnectionsResponse {
                    available: false,
                    sample_ms: None,
                    client,
                    total_connections: 0,
                    returned_connections: 0,
                    truncated: false,
                    limit: MAX_CLIENT_CONNECTION_DETAILS,
                    conn_source: None,
                    conn_semantics: CONNECTION_SEMANTICS.to_owned(),
                    connections: Vec::new(),
                    warnings,
                }
            }
            PublishedConnectionDetails::Incomplete {
                sample_ms,
                conn_source,
            } => {
                warnings.push("conntrack_snapshot_incomplete".to_owned());
                ClientConnectionsResponse {
                    available: false,
                    sample_ms: Some(*sample_ms),
                    client,
                    total_connections: 0,
                    returned_connections: 0,
                    truncated: false,
                    limit: MAX_CLIENT_CONNECTION_DETAILS,
                    conn_source: Some(conn_source.clone()),
                    conn_semantics: CONNECTION_SEMANTICS.to_owned(),
                    connections: Vec::new(),
                    warnings,
                }
            }
            PublishedConnectionDetails::Available {
                sample_ms,
                conn_source,
                by_identity,
            } => {
                let set = current_client.and_then(|_| by_identity.get(identity_key));
                let total_connections = set.map_or(0, |set| set.total_connections);
                let connections = set.map_or_else(Vec::new, |set| set.connections.clone());
                let returned_connections = connections.len();
                ClientConnectionsResponse {
                    available: true,
                    sample_ms: Some(*sample_ms),
                    client,
                    total_connections,
                    returned_connections,
                    truncated: set.is_some_and(|set| set.truncated),
                    limit: MAX_CLIENT_CONNECTION_DETAILS,
                    conn_source: Some(conn_source.clone()),
                    conn_semantics: CONNECTION_SEMANTICS.to_owned(),
                    connections,
                    warnings,
                }
            }
        }
    }

    pub(crate) fn replace_connection_details(
        &mut self,
        sample_ms: u64,
        conn_source: String,
        by_identity: ConnectionDetailsSnapshot,
    ) {
        self.connection_details = PublishedConnectionDetails::Available {
            sample_ms,
            conn_source,
            by_identity,
        };
    }

    pub(crate) fn replace_incomplete_connection_details(
        &mut self,
        sample_ms: u64,
        conn_source: String,
    ) {
        self.connection_details = PublishedConnectionDetails::Incomplete {
            sample_ms,
            conn_source,
        };
    }

    pub(crate) fn clear_connection_details(&mut self) {
        self.connection_details = PublishedConnectionDetails::Unavailable;
    }

    pub fn response(&self, method: Method) -> Result<Value, DaemonError> {
        Ok(match method {
            Method::Status => serde_json::to_value(&self.status)?,
            Method::Clients => serde_json::to_value(&self.clients)?,
            Method::Overview => serde_json::to_value(&self.overview)?,
            Method::Health => serde_json::to_value(&self.health)?,
            Method::Reload => serde_json::to_value(&self.reload)?,
            Method::Interfaces => serde_json::to_value(&self.interfaces)?,
            Method::Sysdevices => serde_json::to_value(&self.sysdevices)?,
            Method::ClientConnections => {
                return Err(DaemonError::transport(
                    "client_connections requires an identity_key request parameter",
                ));
            }
        })
    }

    pub fn response_for_request(
        &self,
        method: Method,
        identity_key: &str,
    ) -> Result<Value, DaemonError> {
        match method {
            Method::ClientConnections => {
                Ok(serde_json::to_value(self.client_connections(identity_key))?)
            }
            _ => Err(DaemonError::transport(format!(
                "{} does not accept request parameters",
                method.name()
            ))),
        }
    }
}

#[derive(Clone)]
pub struct SnapshotStore(Rc<RefCell<Arc<ResponseSnapshot>>>);

impl SnapshotStore {
    pub fn new(snapshot: Arc<ResponseSnapshot>) -> Self {
        Self(Rc::new(RefCell::new(snapshot)))
    }
    pub fn load(&self) -> Arc<ResponseSnapshot> {
        Arc::clone(&self.0.borrow())
    }
    pub fn publish(&self, snapshot: Arc<ResponseSnapshot>) {
        *self.0.borrow_mut() = snapshot;
    }
}
