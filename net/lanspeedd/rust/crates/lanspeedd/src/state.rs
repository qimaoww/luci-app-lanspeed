use std::{cell::RefCell, rc::Rc, sync::Arc};

use serde_json::Value;

use crate::{
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
}

impl ResponseSnapshot {
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
        }
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
        })
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
