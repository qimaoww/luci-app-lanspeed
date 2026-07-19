use std::{cell::RefCell, mem::MaybeUninit, rc::Rc, sync::Arc};

use serde_json::{json, Value};

use crate::{
    config::{RateCollectorMode, RuntimeConfig},
    connection_details::{
        ClientConnectionSummary, ClientConnectionsResponse, ConnectionDetailsSnapshot,
        PublishedConnectionDetails, MAX_CLIENT_CONNECTION_DETAILS,
    },
    error::DaemonError,
    model::{
        Capabilities, ClientsResponse, Confidence, DiagnosticAlert, DiagnosticCollection,
        DiagnosticCollectionState, DiagnosticConfigIssue, DiagnosticConnection, DiagnosticDataPath,
        DiagnosticHealthState, DiagnosticInterfaces, DiagnosticPublicError, DiagnosticService,
        DiagnosticServiceState, DiagnosticSubsystem, DiagnosticVersions, DiagnosticsResponse,
        Evidence, HealthResponse, InterfaceStatus, InterfacesResponse, Mode, OverviewResponse,
        ReloadResponse, StatusResponse, SysdeviceLimits, SysdevicesResponse,
        DIAGNOSTICS_CONTRACT_VERSION, DIAGNOSTICS_SCHEMA_VERSION,
    },
    ubus::Method,
};

pub const OVERVIEW_SAMPLE_SOURCE: &str = "clients_refresh_daemon_ring";
pub const CONNECTION_SEMANTICS: &str =
    "conntrack_current_tcp_established_assured_udp_assured_dns_split";

pub(crate) fn diagnostic_now_ms(fallback: u64) -> u64 {
    let mut value = MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
        return fallback;
    }
    // SAFETY: clock_gettime returned success and initialized the output value.
    let value = unsafe { value.assume_init() };
    let Ok(seconds) = u64::try_from(value.tv_sec) else {
        return fallback;
    };
    let Ok(nanoseconds) = u64::try_from(value.tv_nsec) else {
        return fallback;
    };
    seconds
        .checked_mul(1_000)
        .and_then(|millis| millis.checked_add(nanoseconds / 1_000_000))
        .unwrap_or(fallback)
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResponseSnapshot {
    pub status: StatusResponse,
    pub clients: ClientsResponse,
    pub overview: OverviewResponse,
    pub health: HealthResponse,
    pub reload: ReloadResponse,
    pub interfaces: InterfacesResponse,
    pub sysdevices: SysdevicesResponse,
    diagnostics_collection: DiagnosticCollection,
    config_issues: Vec<DiagnosticConfigIssue>,
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
        let refresh_interval_ms = status.refresh_interval_ms;
        Self {
            status,
            clients,
            overview,
            health,
            reload,
            interfaces,
            sysdevices,
            diagnostics_collection: DiagnosticCollection::unavailable(refresh_interval_ms),
            config_issues: Vec::new(),
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
        let mut diagnostic_evidence = evidence.clone();
        diagnostic_evidence.details.insert(
            "probe_failures".into(),
            json!({"items": [], "total": 0, "truncated": false}),
        );
        diagnostic_evidence.details.insert(
            "bpf".into(),
            json!({
                "enabled": false,
                "collect_target_count": 0,
                "expected_hook_count": 0,
                "attached_hook_count": 0,
                "object_loaded": false,
                "attach_state": "not_attempted",
                "map_state": "not_attempted",
                "last_complete_snapshot_ms": null,
                "retained_fresh_snapshot": false,
                "reason_code": "disabled",
            }),
        );
        let capabilities = Capabilities {
            conntrack_fallback: true,
            ..Capabilities::default()
        };
        Self {
            status: StatusResponse {
                mode: Mode::Unsupported,
                confidence: Confidence::Unsupported,
                warnings: vec!["live_metrics_unavailable".into()],
                evidence: diagnostic_evidence.clone(),
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
                evidence: diagnostic_evidence,
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
                contract_version: 1,
                devices: vec![],
                current_ifnames: vec![],
                current_observed: vec![],
                current_excluded: vec![],
                configured_ifnames: vec![],
                configured_observed: vec![],
                configured_excluded: vec![],
                orphaned: vec![],
                limits: SysdeviceLimits { max_configured: 16, max_name_length: 31 },
            },
            diagnostics_collection: DiagnosticCollection::unavailable(1_000),
            config_issues: Vec::new(),
            connection_details: PublishedConnectionDetails::Unavailable,
        }
    }

    pub(crate) fn mark_collection_success(
        &mut self,
        generation: u64,
        now_ms: u64,
        refresh_interval_ms: u32,
    ) {
        self.diagnostics_collection = DiagnosticCollection {
            state: DiagnosticCollectionState::Fresh,
            generation,
            last_attempt_ms: Some(now_ms),
            last_success_ms: Some(now_ms),
            age_ms: Some(0),
            refresh_interval_ms,
            consecutive_failures: 0,
            retained: false,
            last_error: None,
        };
    }

    pub(crate) fn mark_collection_failure(
        &mut self,
        now_ms: u64,
        refresh_interval_ms: u32,
        error: &DaemonError,
    ) {
        let last_success_ms = self.diagnostics_collection.last_success_ms;
        let consecutive_failures = self
            .diagnostics_collection
            .consecutive_failures
            .saturating_add(1);
        self.diagnostics_collection = DiagnosticCollection {
            state: if last_success_ms.is_some() {
                DiagnosticCollectionState::Degraded
            } else {
                DiagnosticCollectionState::Unavailable
            },
            generation: self.diagnostics_collection.generation,
            last_attempt_ms: Some(now_ms),
            last_success_ms,
            age_ms: last_success_ms.map(|value| now_ms.saturating_sub(value)),
            refresh_interval_ms,
            consecutive_failures,
            retained: last_success_ms.is_some(),
            last_error: Some(public_error(error)),
        };
    }

    pub(crate) fn set_config_issues(&mut self, config: &RuntimeConfig) {
        self.config_issues = config_issues(config);
    }

    pub(crate) fn diagnostic_generation(&self) -> u64 {
        self.diagnostics_collection.generation
    }

    pub fn diagnostics(&self) -> DiagnosticsResponse {
        let fallback = self
            .diagnostics_collection
            .last_attempt_ms
            .or(self.diagnostics_collection.last_success_ms)
            .or(self.interfaces.monotonic_ms)
            .unwrap_or(0);
        self.diagnostics_at(diagnostic_now_ms(fallback))
    }

    fn diagnostics_at(&self, now_ms: u64) -> DiagnosticsResponse {
        let mut collection = self.diagnostics_collection.clone();
        if let Some(last_success_ms) = collection.last_success_ms {
            collection.age_ms = Some(now_ms.saturating_sub(last_success_ms));
            let stale_after_ms = u64::from(collection.refresh_interval_ms).saturating_mul(3);
            if collection.state == DiagnosticCollectionState::Fresh
                && collection.age_ms.is_some_and(|age| age > stale_after_ms)
            {
                collection.state = DiagnosticCollectionState::Stale;
            }
        }
        let effective_rate = evidence_code(&self.status.evidence, "effective_collector")
            .unwrap_or_else(|| "unsupported".into());
        let reason_code = nested_evidence_code(&self.status.evidence, "collector", "rate_reason");
        let effective_connection = self
            .clients
            .conn_source
            .as_deref()
            .and_then(safe_code)
            .or_else(|| {
                nested_evidence_code(
                    &self.status.evidence,
                    "collector",
                    "effective_connection_collector",
                )
            })
            .unwrap_or_else(|| "unsupported".into());
        let fallback_active = reason_code
            .as_deref()
            .is_some_and(|value| value.contains("fallback"));
        let interfaces = diagnostic_interfaces(&self.interfaces);
        let connection = diagnostic_connection(&self.clients);
        let collection_state = collection.state;
        let service = DiagnosticService {
            state: match collection_state {
                DiagnosticCollectionState::Fresh if self.diagnostics_collection.generation > 0 => {
                    DiagnosticServiceState::Running
                }
                DiagnosticCollectionState::Fresh => DiagnosticServiceState::Starting,
                DiagnosticCollectionState::Stale
                | DiagnosticCollectionState::Degraded
                | DiagnosticCollectionState::Unavailable => DiagnosticServiceState::Degraded,
            },
            ubus_connected: true,
        };
        DiagnosticsResponse {
            contract_version: DIAGNOSTICS_CONTRACT_VERSION,
            service,
            collection: collection.clone(),
            data_path: DiagnosticDataPath {
                configured_rate: self.status.rate_collector_mode.clone(),
                effective_rate,
                configured_connection: self.status.conn_collector_mode.clone(),
                effective_connection,
                fallback_active,
                reason_code,
            },
            interfaces,
            connection,
            subsystems: diagnostic_subsystems(self),
            versions: DiagnosticVersions {
                daemon: self.status.version.clone(),
                package: self.reload.version.clone(),
                contract_version: DIAGNOSTICS_CONTRACT_VERSION,
                schema_version: DIAGNOSTICS_SCHEMA_VERSION,
            },
            alerts: diagnostic_alerts(self, &collection),
            config_issues: self.config_issues.clone(),
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
            Method::Diagnostics => serde_json::to_value(self.diagnostics())?,
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

fn public_error(error: &DaemonError) -> DiagnosticPublicError {
    let (category, code, retriable) = match error {
        DaemonError::Transport(_) => ("transport", "transport_error", true),
        DaemonError::Collection(_) => ("collection", "collection_error", true),
        DaemonError::Reload(_) => ("reload", "reload_error", false),
        DaemonError::Serialization(_) => ("serialization", "serialization_error", false),
        DaemonError::Platform(_) => ("platform", "platform_error", false),
    };
    DiagnosticPublicError {
        code: code.into(),
        category: category.into(),
        stage: category.into(),
        retriable,
        message_public: "The latest LAN Speed collection did not complete.".into(),
    }
}

fn safe_code(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return None;
    }
    Some(value.to_owned())
}

fn evidence_code(evidence: &Evidence, key: &str) -> Option<String> {
    evidence
        .details
        .get(key)
        .and_then(Value::as_str)
        .and_then(safe_code)
}

fn nested_evidence_code(evidence: &Evidence, object: &str, key: &str) -> Option<String> {
    evidence
        .details
        .get(object)
        .and_then(Value::as_object)
        .and_then(|value| value.get(key))
        .and_then(Value::as_str)
        .and_then(safe_code)
}

fn nested_evidence_bool(evidence: &Evidence, object: &str, key: &str) -> Option<bool> {
    evidence
        .details
        .get(object)
        .and_then(Value::as_object)
        .and_then(|value| value.get(key))
        .and_then(Value::as_bool)
}

fn nested_evidence_u64(evidence: &Evidence, object: &str, key: &str) -> Option<u64> {
    evidence
        .details
        .get(object)
        .and_then(Value::as_object)
        .and_then(|value| value.get(key))
        .and_then(Value::as_u64)
}

fn diagnostic_interfaces(response: &InterfacesResponse) -> DiagnosticInterfaces {
    let total = response.interfaces.len();
    let available = response
        .interfaces
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                InterfaceStatus::Active | InterfaceStatus::Available
            )
        })
        .count();
    let missing = response
        .interfaces
        .iter()
        .filter(|item| item.status == InterfaceStatus::Missing)
        .count();
    let state = if total == 0 {
        DiagnosticHealthState::Unavailable
    } else if available == total {
        DiagnosticHealthState::Healthy
    } else {
        DiagnosticHealthState::Degraded
    };
    DiagnosticInterfaces {
        state,
        total,
        available,
        missing,
        sample_ms: response.monotonic_ms,
    }
}

fn diagnostic_connection(response: &ClientsResponse) -> DiagnosticConnection {
    let source = response.conn_source.as_deref().and_then(safe_code);
    let direct = source.as_deref() == Some("nss_ecm_direct");
    let entries_seen = if direct {
        response.nss_ecm_direct_flows_seen
    } else {
        response.conntrack_entries_seen
    };
    let entries_matched = if direct {
        response.nss_ecm_direct_flows_matched
    } else {
        response.conntrack_entries_matched
    };
    let parse_errors = if direct {
        response.nss_ecm_direct_parse_errors
    } else {
        response.conntrack_parse_errors
    };
    let state = match source.as_deref() {
        Some(_) if parse_errors.unwrap_or(0) > 0 => DiagnosticHealthState::Degraded,
        Some(_) => DiagnosticHealthState::Healthy,
        None => DiagnosticHealthState::Unavailable,
    };
    DiagnosticConnection {
        state,
        source,
        entries_seen,
        entries_matched,
        parse_errors,
    }
}

fn diagnostic_subsystems(snapshot: &ResponseSnapshot) -> Vec<DiagnosticSubsystem> {
    let evidence = &snapshot.status.evidence;
    let rate =
        evidence_code(evidence, "effective_collector").unwrap_or_else(|| "unsupported".into());
    let reason = nested_evidence_code(evidence, "bpf", "reason_code");
    let attach_state = nested_evidence_code(evidence, "bpf", "attach_state");
    let map_state = nested_evidence_code(evidence, "bpf", "map_state");
    let enabled = nested_evidence_bool(evidence, "bpf", "enabled").unwrap_or(true);
    let collect_targets = nested_evidence_u64(evidence, "bpf", "collect_target_count")
        .unwrap_or_else(|| u64::from(snapshot.status.capabilities.lan_edge));
    let disabled = !enabled || reason.as_deref() == Some("disabled");
    let no_target = collect_targets == 0 || reason.as_deref() == Some("no_collect_interface");
    let unavailable_reason = matches!(
        reason.as_deref(),
        Some(
            "package_missing"
                | "object_missing"
                | "object_load_failed"
                | "tc_unavailable"
                | "tc_unsupported"
        )
    );
    let bpf = if disabled {
        (DiagnosticHealthState::Disabled, Some("bpf_disabled".into()))
    } else if no_target {
        (
            DiagnosticHealthState::Disabled,
            Some("no_collect_interface".into()),
        )
    } else if unavailable_reason
        || !snapshot.status.capabilities.bpf_package
        || !snapshot.status.capabilities.bpf_object
        || !snapshot.status.capabilities.bpf_supported
    {
        (
            DiagnosticHealthState::Unavailable,
            Some(reason.clone().unwrap_or_else(|| "bpf_unavailable".into())),
        )
    } else if attach_state.as_deref() == Some("ready")
        && matches!(map_state.as_deref(), Some("ready") | Some("retained"))
    {
        if map_state.as_deref() == Some("retained") {
            (
                DiagnosticHealthState::Degraded,
                Some("map_read_failed".into()),
            )
        } else {
            (DiagnosticHealthState::Healthy, None)
        }
    } else if attach_state.as_deref() == Some("partial")
        || attach_state.as_deref() == Some("failed")
        || map_state.as_deref() == Some("failed")
    {
        (
            DiagnosticHealthState::Degraded,
            Some(
                reason
                    .clone()
                    .unwrap_or_else(|| "bpf_runtime_not_ready".into()),
            ),
        )
    } else if rate == "bpf" && snapshot.status.capabilities.live_metrics {
        (DiagnosticHealthState::Healthy, None)
    } else {
        (
            DiagnosticHealthState::Disabled,
            Some("bpf_not_selected".into()),
        )
    };
    let tc = if disabled {
        (DiagnosticHealthState::Disabled, Some("bpf_disabled".into()))
    } else if no_target {
        (
            DiagnosticHealthState::Disabled,
            Some("no_collect_interface".into()),
        )
    } else if !snapshot.status.capabilities.tc
        || !snapshot.status.capabilities.tc_clsact
        || !snapshot.status.capabilities.bpf_supported
    {
        (
            DiagnosticHealthState::Unavailable,
            Some(reason.clone().unwrap_or_else(|| "tc_unavailable".into())),
        )
    } else if attach_state.as_deref() == Some("ready") {
        (DiagnosticHealthState::Healthy, None)
    } else {
        (
            DiagnosticHealthState::Degraded,
            Some(
                reason
                    .clone()
                    .unwrap_or_else(|| "tc_attach_not_ready".into()),
            ),
        )
    };
    let bpf_map = if disabled {
        (DiagnosticHealthState::Disabled, Some("bpf_disabled".into()))
    } else if no_target {
        (
            DiagnosticHealthState::Disabled,
            Some("no_collect_interface".into()),
        )
    } else {
        match map_state.as_deref() {
            Some("ready") => (DiagnosticHealthState::Healthy, None),
            Some("retained") => (
                DiagnosticHealthState::Degraded,
                Some("map_read_failed".into()),
            ),
            Some("failed") => (
                DiagnosticHealthState::Unavailable,
                Some("map_read_failed".into()),
            ),
            _ if attach_state.as_deref() == Some("failed")
                || attach_state.as_deref() == Some("partial") =>
            {
                (
                    DiagnosticHealthState::Unavailable,
                    Some("map_not_started".into()),
                )
            }
            _ => (
                DiagnosticHealthState::Disabled,
                Some("bpf_not_selected".into()),
            ),
        }
    };
    let connection = diagnostic_connection(&snapshot.clients);
    let conntrack = match connection.state {
        DiagnosticHealthState::Healthy => (DiagnosticHealthState::Healthy, None),
        DiagnosticHealthState::Degraded => (
            DiagnosticHealthState::Degraded,
            Some(
                if connection.source.as_deref() == Some("nss_ecm_direct") {
                    "nss_ecm_direct_parse_errors"
                } else {
                    "conntrack_parse_errors"
                }
                .into(),
            ),
        ),
        _ => (
            DiagnosticHealthState::Unavailable,
            Some("conntrack_unavailable".into()),
        ),
    };
    let nss = if snapshot.status.capabilities.nss {
        (DiagnosticHealthState::Healthy, None)
    } else {
        (
            DiagnosticHealthState::Disabled,
            Some("nss_not_present".into()),
        )
    };
    let identity = if snapshot
        .status
        .warnings
        .iter()
        .any(|warning| warning == "lan_topology_probe_error")
    {
        (
            DiagnosticHealthState::Degraded,
            Some("lan_topology_probe_error".into()),
        )
    } else {
        (DiagnosticHealthState::Healthy, None)
    };
    vec![
        subsystem("bpf", bpf),
        subsystem("tc", tc),
        subsystem("bpf_map", bpf_map),
        subsystem("conntrack", conntrack),
        subsystem("nss", nss),
        subsystem("identity", identity),
        subsystem("ubus", (DiagnosticHealthState::Healthy, None)),
    ]
}

fn subsystem(id: &str, value: (DiagnosticHealthState, Option<String>)) -> DiagnosticSubsystem {
    DiagnosticSubsystem {
        id: id.into(),
        state: value.0,
        code: value.1,
    }
}

fn diagnostic_alerts(
    snapshot: &ResponseSnapshot,
    collection: &DiagnosticCollection,
) -> Vec<DiagnosticAlert> {
    let mut alerts = Vec::new();
    if collection.state == DiagnosticCollectionState::Unavailable {
        alerts.push(DiagnosticAlert {
            id: "collection_unavailable".into(),
            severity: "critical".into(),
            component: "collection".into(),
            state: "active".into(),
            message_public: "No successful collection result is currently available.".into(),
        });
    } else if collection.retained || collection.state == DiagnosticCollectionState::Stale {
        alerts.push(DiagnosticAlert {
            id: "collection_stale".into(),
            severity: "warning".into(),
            component: "collection".into(),
            state: "active".into(),
            message_public: if collection.retained {
                "The latest collection failed; the last successful data is retained."
            } else {
                "Collection data is older than the expected refresh window."
            }
            .into(),
        });
    }
    let bpf_reason = nested_evidence_code(&snapshot.status.evidence, "bpf", "reason_code");
    if let Some(id) = bpf_reason
        .as_deref()
        .filter(|id| !matches!(*id, "ready" | "disabled" | "runtime_not_ready"))
    {
        alerts.push(DiagnosticAlert {
            id: id.into(),
            severity: alert_severity(id, snapshot.status.capabilities.live_metrics).into(),
            component: alert_component(id).into(),
            state: "active".into(),
            message_public: alert_public_message(id).into(),
        });
    }
    for warning in &snapshot.status.warnings {
        let Some(id) = safe_code(warning) else {
            continue;
        };
        if id == "bpf_runtime_loader_unavailable"
            && bpf_reason
                .as_deref()
                .is_some_and(|reason| !matches!(reason, "ready" | "disabled" | "runtime_not_ready"))
        {
            continue;
        }
        if alerts.iter().any(|alert: &DiagnosticAlert| alert.id == id) {
            continue;
        }
        alerts.push(DiagnosticAlert {
            component: alert_component(&id).into(),
            severity: alert_severity(&id, snapshot.status.capabilities.live_metrics).into(),
            message_public: alert_public_message(&id).into(),
            id,
            state: "active".into(),
        });
        if alerts.len() >= 64 {
            return alerts;
        }
    }
    for conflict in &snapshot.health.conflicts {
        let Some(id) = safe_code(&conflict.id) else {
            continue;
        };
        if alerts.iter().any(|alert: &DiagnosticAlert| alert.id == id) {
            continue;
        }
        alerts.push(DiagnosticAlert {
            message_public: alert_public_message(&id).into(),
            id,
            severity: match conflict.severity.as_str() {
                "critical" => "critical",
                "info" => "info",
                _ => "warning",
            }
            .into(),
            component: "health".into(),
            state: "active".into(),
        });
        if alerts.len() >= 64 {
            break;
        }
    }
    alerts
}

fn alert_public_message(id: &str) -> &'static str {
    match id {
        "live_metrics_unavailable" => {
            "No supported live-rate collector is currently producing data."
        }
        "bpf_unavailable" => "The required BPF collection path is unavailable.",
        "no_collect_interface" => "No LAN interface is assigned to client collection.",
        "package_missing" | "bpf_optional_package_missing" => {
            "The required BPF runtime package is not installed."
        }
        "object_missing" | "bpf_object_missing" => "The required BPF object is not installed.",
        "object_load_failed" => "The installed BPF object could not be loaded.",
        "tc_unavailable" | "tc_missing" => {
            "Traffic control is unavailable, so BPF hooks cannot be attached."
        }
        "tc_unsupported" | "tc_clsact_unsupported" => {
            "The current traffic-control stack does not support the required BPF hooks."
        }
        "tc_conflict" | "tc_attach_failed" | "tc_attach_not_ready" => {
            "The BPF traffic-control hooks are not fully attached."
        }
        "map_read_failed" => "The BPF client map could not be read completely.",
        "map_not_started" => "The BPF client map is unavailable until TC hooks attach.",
        "bpf_runtime_loader_unavailable" => "The installed BPF runtime did not become ready.",
        "bpf_tc_self_heal_failed" => {
            "The BPF traffic-control attachment could not recover automatically."
        }
        "map_full" => "The BPF client map reached its configured capacity.",
        "probe_error" => "One or more environment probes did not complete.",
        "tc_filter_conflict" | "existing_tc_filters_detected" => {
            "Another traffic-control filter may affect LAN Speed collection."
        }
        "software_flow_offload_enabled" => {
            "Software flow offload may bypass part of the CPU-visible traffic path."
        }
        "hardware_flow_offload_unsupported" => {
            "Hardware flow offload may bypass the selected collection path."
        }
        "fullcone_detected" | "fullcone_nat_enabled" => {
            "Fullcone NAT may change connection attribution at the LAN edge."
        }
        "openclash_detected"
        | "openclash_fake_ip_low_remote_confidence"
        | "openclash_tun_conntrack_low_confidence"
        | "openclash_router_self_proxy_detected" => {
            "The active proxy path may reduce connection or remote-endpoint confidence."
        }
        "dae_detected" => "The active dae/daed path may change traffic visibility.",
        "conntrack_unavailable" => "No supported conntrack source is currently available.",
        "conntrack_parse_errors" => "Some conntrack entries could not be parsed.",
        "lan_topology_probe_error" => "LAN topology evidence is incomplete.",
        "asymmetric_path_possible" => "The observed traffic path may be asymmetric.",
        _ => "A structured LAN Speed diagnostic condition is active.",
    }
}

fn alert_component(id: &str) -> &'static str {
    if id.contains("conntrack") || id.contains("nf_") {
        "connection"
    } else if id.contains("bpf")
        || id.contains("tc_")
        || id.contains("attach")
        || id.contains("map_")
        || id == "no_collect_interface"
    {
        "collector"
    } else if id.contains("identity") || id.contains("topology") || id.contains("lan_edge") {
        "identity"
    } else {
        "runtime"
    }
}

fn alert_severity(id: &str, live_metrics: bool) -> &'static str {
    match id {
        "live_metrics_unavailable"
        | "no_collect_interface"
        | "package_missing"
        | "object_missing"
        | "object_load_failed"
        | "tc_unavailable"
        | "tc_unsupported"
        | "bpf_optional_package_missing"
        | "bpf_object_missing"
        | "tc_missing"
        | "tc_clsact_unsupported"
        | "map_full"
        | "bpf_tc_self_heal_failed"
        | "probe_error" => "critical",
        "tc_conflict" | "tc_attach_failed" | "map_read_failed" if !live_metrics => "critical",
        _ => "warning",
    }
}

fn config_issues(config: &RuntimeConfig) -> Vec<DiagnosticConfigIssue> {
    let mut issues = Vec::new();
    let mut push = |id: &str, severity: &str, option: &str, state: &str, message: &str| {
        issues.push(DiagnosticConfigIssue {
            id: id.into(),
            severity: severity.into(),
            option: option.into(),
            state: state.into(),
            message_public: message.into(),
        });
    };
    if config.enable_bpf
        && config.rate_collector_mode == RateCollectorMode::Bpf
        && config.runtime_collect_ifnames().is_empty()
    {
        push(
            "no_collect_interface",
            "critical",
            "interface_include",
            "required",
            "Forced BPF collection requires at least one LAN interface assigned to collect.",
        );
    }
    if config.refresh_interval_clamped {
        push(
            "refresh_interval_clamped",
            "warning",
            "refresh_interval_ms",
            "adjusted",
            "The refresh interval was adjusted to a supported range.",
        );
    }
    if config.active_client_window_clamped {
        push(
            "active_client_window_clamped",
            "warning",
            "active_client_window_ms",
            "adjusted",
            "The active-client window was adjusted to a supported range.",
        );
    }
    if config.active_client_min_bps_clamped {
        push(
            "active_client_min_bps_clamped",
            "warning",
            "active_client_min_bps",
            "adjusted",
            "The active-client threshold was adjusted to a supported range.",
        );
    }
    if config.overview_window_samples_clamped {
        push(
            "overview_window_samples_clamped",
            "warning",
            "overview_window_samples",
            "adjusted",
            "The overview history length was adjusted to a supported range.",
        );
    }
    if config.max_clients_clamped {
        push(
            "max_clients_clamped",
            "warning",
            "max_clients",
            "adjusted",
            "The client limit was adjusted to a supported range.",
        );
    }
    if !config.interface_exclude.is_empty() {
        push(
            "interface_exclude_compatibility_only",
            "info",
            "interface_exclude",
            "compatibility_only",
            "interface_exclude is retained for compatibility and does not change the attach set.",
        );
    }
    issues
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

#[cfg(test)]
mod diagnostics_tests {
    use super::*;

    fn set_bpf_evidence(snapshot: &mut ResponseSnapshot, value: Value, live_metrics: bool) {
        snapshot
            .status
            .evidence
            .details
            .insert("bpf".into(), value.clone());
        snapshot.health.evidence.details.insert("bpf".into(), value);
        snapshot.status.capabilities.bpf_supported = true;
        snapshot.status.capabilities.bpf_package = true;
        snapshot.status.capabilities.bpf_object = true;
        snapshot.status.capabilities.tc = true;
        snapshot.status.capabilities.tc_clsact = true;
        snapshot.status.capabilities.live_metrics = live_metrics;
    }

    #[test]
    fn age_is_recomputed_and_fresh_data_becomes_stale_without_an_error_tick() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.mark_collection_success(7, 1_000, 500);

        let fresh = snapshot.diagnostics_at(2_500);
        assert_eq!(fresh.collection.state, DiagnosticCollectionState::Fresh);
        assert_eq!(fresh.collection.age_ms, Some(1_500));

        let stale = snapshot.diagnostics_at(2_501);
        assert_eq!(stale.collection.state, DiagnosticCollectionState::Stale);
        assert_eq!(stale.collection.generation, 7);
        assert_eq!(stale.service.state, DiagnosticServiceState::Degraded);
        assert!(stale
            .alerts
            .iter()
            .any(|alert| alert.id == "collection_stale"));
    }

    #[test]
    fn repeated_failures_keep_generation_and_never_publish_the_raw_error() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.mark_collection_success(3, 1_000, 500);
        let error = DaemonError::collection("/private/path token=secret");
        snapshot.mark_collection_failure(1_500, 500, &error);
        snapshot.mark_collection_failure(2_000, 500, &error);

        let diagnostics = snapshot.diagnostics_at(2_000);
        assert_eq!(diagnostics.collection.generation, 3);
        assert_eq!(diagnostics.collection.consecutive_failures, 2);
        assert_eq!(diagnostics.collection.retained, true);
        assert_eq!(
            diagnostics.collection.last_error.as_ref().unwrap().code,
            "collection_error"
        );
        let serialized = serde_json::to_string(&diagnostics).unwrap();
        assert!(!serialized.contains("/private/path"));
        assert!(!serialized.contains("token=secret"));
    }

    #[test]
    fn first_collection_failure_publishes_a_critical_unavailable_alert() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.mark_collection_failure(
            1_000,
            500,
            &DaemonError::collection("/private/path token=secret"),
        );

        let diagnostics = snapshot.diagnostics_at(1_000);
        let alert = diagnostics
            .alerts
            .iter()
            .find(|alert| alert.id == "collection_unavailable")
            .expect("missing collection_unavailable alert");
        assert_eq!(alert.severity, "critical");
        assert_eq!(alert.component, "collection");
        assert!(!alert.message_public.contains("/private/path"));
        assert!(!alert.message_public.contains("token=secret"));
    }

    #[test]
    fn nss_direct_connection_health_uses_direct_counters_and_reason() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.clients.conn_source = Some("nss_ecm_direct".into());
        snapshot.clients.nss_ecm_direct_flows_seen = Some(12);
        snapshot.clients.nss_ecm_direct_flows_matched = Some(9);
        snapshot.clients.nss_ecm_direct_parse_errors = Some(2);

        let diagnostics = snapshot.diagnostics_at(0);
        assert_eq!(
            diagnostics.connection.state,
            DiagnosticHealthState::Degraded
        );
        assert_eq!(
            diagnostics.connection.source.as_deref(),
            Some("nss_ecm_direct")
        );
        assert_eq!(diagnostics.connection.entries_seen, Some(12));
        assert_eq!(diagnostics.connection.entries_matched, Some(9));
        assert_eq!(diagnostics.connection.parse_errors, Some(2));
        let subsystem = diagnostics
            .subsystems
            .iter()
            .find(|subsystem| subsystem.id == "conntrack")
            .expect("missing connection subsystem");
        assert_eq!(subsystem.state, DiagnosticHealthState::Degraded);
        assert_eq!(
            subsystem.code.as_deref(),
            Some("nss_ecm_direct_parse_errors")
        );
    }

    #[test]
    fn direct_counters_without_source_metadata_remain_unavailable() {
        let mut response = ClientsResponse::empty(Evidence::default());
        response.nss_ecm_direct_flows_seen = Some(4);
        response.nss_ecm_direct_flows_matched = Some(3);
        response.nss_ecm_direct_parse_errors = Some(0);

        let connection = diagnostic_connection(&response);
        assert_eq!(connection.state, DiagnosticHealthState::Unavailable);
        assert_eq!(connection.source, None);
        assert_eq!(connection.entries_seen, None);
        assert_eq!(connection.entries_matched, None);
        assert_eq!(connection.parse_errors, None);
    }

    #[test]
    fn bpf_map_failure_severity_tracks_retained_or_missing_live_data() {
        let mut retained = ResponseSnapshot::unsupported("test");
        set_bpf_evidence(
            &mut retained,
            json!({
                "enabled": true, "collect_target_count": 1,
                "expected_hook_count": 2, "attached_hook_count": 2,
                "object_loaded": true, "attach_state": "ready",
                "map_state": "retained", "last_complete_snapshot_ms": 9_000,
                "retained_fresh_snapshot": true, "reason_code": "map_read_failed"
            }),
            true,
        );
        let diagnostics = retained.diagnostics_at(10_000);
        let alert = diagnostics
            .alerts
            .iter()
            .find(|alert| alert.id == "map_read_failed")
            .expect("missing retained map alert");
        assert_eq!(alert.severity, "warning");
        let map = diagnostics
            .subsystems
            .iter()
            .find(|item| item.id == "bpf_map")
            .expect("missing BPF map subsystem");
        assert_eq!(map.state, DiagnosticHealthState::Degraded);

        let mut failed = retained.clone();
        set_bpf_evidence(
            &mut failed,
            json!({
                "enabled": true, "collect_target_count": 1,
                "expected_hook_count": 2, "attached_hook_count": 2,
                "object_loaded": true, "attach_state": "ready",
                "map_state": "failed", "last_complete_snapshot_ms": null,
                "retained_fresh_snapshot": false, "reason_code": "map_read_failed"
            }),
            false,
        );
        let diagnostics = failed.diagnostics_at(10_000);
        let alert = diagnostics
            .alerts
            .iter()
            .find(|alert| alert.id == "map_read_failed")
            .expect("missing failed map alert");
        assert_eq!(alert.severity, "critical");
        let map = diagnostics
            .subsystems
            .iter()
            .find(|item| item.id == "bpf_map")
            .expect("missing BPF map subsystem");
        assert_eq!(map.state, DiagnosticHealthState::Unavailable);
    }

    #[test]
    fn live_nss_fallback_deduplicates_bpf_failure_without_missing_live_metrics() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        set_bpf_evidence(
            &mut snapshot,
            json!({
                "enabled": true, "collect_target_count": 1,
                "expected_hook_count": 2, "attached_hook_count": 0,
                "object_loaded": true, "attach_state": "failed",
                "map_state": "not_attempted", "last_complete_snapshot_ms": null,
                "retained_fresh_snapshot": false, "reason_code": "tc_attach_failed"
            }),
            true,
        );
        snapshot.status.warnings = vec![
            "tc_attach_failed".into(),
            "bpf_runtime_loader_unavailable".into(),
        ];
        let diagnostics = snapshot.diagnostics_at(0);
        assert_eq!(
            diagnostics
                .alerts
                .iter()
                .filter(|alert| alert.id == "tc_attach_failed")
                .count(),
            1
        );
        assert!(!diagnostics
            .alerts
            .iter()
            .any(|alert| alert.id == "bpf_runtime_loader_unavailable"));
        assert!(!diagnostics
            .alerts
            .iter()
            .any(|alert| alert.id == "live_metrics_unavailable"));
    }
}
