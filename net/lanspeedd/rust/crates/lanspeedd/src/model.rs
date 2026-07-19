use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

fn saturated_u64<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_i64((*value).min(i64::MAX as u64) as i64)
}

fn saturated_option_u64<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(&((*value).min(i64::MAX as u64) as i64)),
        None => serializer.serialize_none(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Mode {
    Full,
    Degraded,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
    Unsupported,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Evidence {
    #[serde(flatten)]
    pub details: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Capabilities {
    /// Stable platform capability: the kernel/userspace TC-BPF path can be
    /// configured. This deliberately does not mean that the current runtime
    /// has successfully attached hooks or read a map.
    pub bpf_supported: bool,
    /// Legacy runtime alias retained for clients that still consume `bpf`.
    /// Production sets it to the current BPF live-metrics state.
    pub bpf: bool,
    pub bpf_package: bool,
    pub bpf_object: bool,
    pub bpf_runtime_metrics: bool,
    pub conntrack_fallback: bool,
    pub live_metrics: bool,
    pub fw4: bool,
    pub nft: bool,
    pub software_flow_offload: bool,
    pub hardware_flow_offload: bool,
    pub nss: bool,
    pub nss_ecm_offload: bool,
    pub nss_ppe_offload: bool,
    pub nss_ecm_direct: bool,
    pub nss_bridge_mgr: bool,
    pub nss_ifb: bool,
    pub nss_nsm: bool,
    pub nss_dp: bool,
    pub nss_mcs: bool,
    pub fullcone: bool,
    pub nf_conntrack_acct: bool,
    pub flowtable_counter: bool,
    pub tc: bool,
    pub tc_clsact: bool,
    pub existing_tc_filters: bool,
    pub ifb: bool,
    pub sqm: bool,
    pub qosify: bool,
    pub openclash: bool,
    pub openclash_fake_ip: bool,
    pub openclash_tun_mix: bool,
    pub openclash_redirect_dns: bool,
    pub openclash_dns_chain_complete: bool,
    pub openclash_router_self_proxy: bool,
    pub openclash_udp_proxy: bool,
    pub openclash_ipv6: bool,
    pub dae: bool,
    pub homeproxy: bool,
    pub lan_bridge: bool,
    pub vlan: bool,
    pub wlan: bool,
    pub lan_edge: bool,
    pub safe_attach: bool,
    pub map_full: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Coverage {
    pub quality: String,
    #[serde(serialize_with = "saturated_u64")]
    pub samples: u64,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub window_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_pct: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_pct: Option<u8>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub denom_rx_bytes: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub denom_tx_bytes: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub numer_rx_bytes: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub numer_tx_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StatusResponse {
    pub mode: Mode,
    pub confidence: Confidence,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
    pub refresh_interval_ms: u32,
    #[serde(serialize_with = "saturated_u64")]
    pub active_client_window_ms: u64,
    #[serde(serialize_with = "saturated_u64")]
    pub active_client_min_bps: u64,
    pub overview_window_samples: usize,
    pub collector_mode: String,
    pub rate_collector_mode: String,
    pub conn_collector_mode: String,
    pub version: String,
    pub capabilities: Capabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Coverage>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Client {
    pub mac: String,
    pub identity_key: String,
    pub zone: String,
    pub interface: String,
    pub ips: Vec<String>,
    pub hostname: Option<String>,
    #[serde(serialize_with = "saturated_u64")]
    pub rx_bps: u64,
    #[serde(serialize_with = "saturated_u64")]
    pub tx_bps: u64,
    #[serde(serialize_with = "saturated_u64")]
    pub last_seen: u64,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub sample_ms: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub rx_bytes: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub tx_bytes: Option<u64>,
    pub collector_mode: String,
    pub confidence: Confidence,
    pub warnings: Vec<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub tcp_conns: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub udp_conns: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub udp_dns_conns: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub udp_other_conns: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ClientsResponse {
    pub clients: Vec<Client>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub tcp_conns_total: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub udp_conns_total: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub udp_dns_conns_total: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub udp_other_conns_total: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub conntrack_entries_seen: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub conntrack_entries_matched: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub conntrack_parse_errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn_source: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub nss_ecm_direct_flows_seen: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub nss_ecm_direct_flows_matched: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub nss_ecm_direct_parse_errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn_collector_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn_semantics: Option<String>,
}

impl ClientsResponse {
    pub fn empty(evidence: Evidence) -> Self {
        Self {
            clients: Vec::new(),
            evidence: Some(evidence),
            tcp_conns_total: Some(0),
            udp_conns_total: Some(0),
            udp_dns_conns_total: Some(0),
            udp_other_conns_total: Some(0),
            conntrack_entries_seen: None,
            conntrack_entries_matched: None,
            conntrack_parse_errors: None,
            conn_source: None,
            nss_ecm_direct_flows_seen: None,
            nss_ecm_direct_flows_matched: None,
            nss_ecm_direct_parse_errors: None,
            conn_collector_mode: None,
            conn_semantics: Some(crate::state::CONNECTION_SEMANTICS.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OverviewSample {
    #[serde(serialize_with = "saturated_u64")]
    pub sample_ms: u64,
    #[serde(serialize_with = "saturated_u64")]
    pub tx_bps: u64,
    #[serde(serialize_with = "saturated_u64")]
    pub rx_bps: u64,
    pub client_count: u32,
    pub active_clients: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_conns: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_conns: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_dns_conns: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_other_conns: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OverviewResponse {
    pub samples: Vec<OverviewSample>,
    pub max_samples: usize,
    pub overview_window_samples: usize,
    #[serde(serialize_with = "saturated_u64")]
    pub active_client_window_ms: u64,
    #[serde(serialize_with = "saturated_u64")]
    pub active_client_min_bps: u64,
    pub sample_source: String,
    pub conn_semantics: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Conflict {
    pub id: String,
    pub severity: String,
    pub message: String,
    #[serde(flatten)]
    pub evidence: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HealthResponse {
    pub mode: Mode,
    pub confidence: Confidence,
    pub capabilities: Capabilities,
    pub conflicts: Vec<Conflict>,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReloadResponse {
    pub ok: bool,
    pub mode: Mode,
    pub warnings: Vec<String>,
    pub evidence: Evidence,
    pub version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceRole {
    Lan,
    Observe,
    Wan,
    Excluded,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceStatus {
    Pending,
    Active,
    Available,
    Missing,
    Excluded,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Interface {
    pub name: String,
    pub role: InterfaceRole,
    pub status: InterfaceStatus,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub rx_bytes: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub tx_bytes: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub rx_bps: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub tx_bps: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub delta_ms: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub sample_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct InterfacesResponse {
    pub interfaces: Vec<Interface>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub monotonic_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Sysdevice {
    pub name: String,
    pub selected: bool,
    pub observed: bool,
    pub recommended_lan: bool,
    pub collect_allowed: bool,
    pub collect_reason: String,
    pub is_bridge: bool,
    pub is_bridge_port: bool,
    pub is_nss_ifb: bool,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "saturated_option_u64"
    )]
    pub speed_mbps: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SysdeviceLimits {
    pub max_configured: usize,
    pub max_name_length: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SysdevicesResponse {
    pub contract_version: u32,
    pub devices: Vec<Sysdevice>,
    pub current_ifnames: Vec<String>,
    pub current_observed: Vec<String>,
    pub current_excluded: Vec<String>,
    pub configured_ifnames: Vec<String>,
    pub configured_observed: Vec<String>,
    pub configured_excluded: Vec<String>,
    pub orphaned: Vec<String>,
    pub limits: SysdeviceLimits,
}

pub const DIAGNOSTICS_CONTRACT_VERSION: u32 = 1;
pub const DIAGNOSTICS_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticServiceState {
    Starting,
    Running,
    Degraded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticCollectionState {
    Fresh,
    Stale,
    Degraded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticHealthState {
    Healthy,
    Degraded,
    Unavailable,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticPublicError {
    pub code: String,
    pub category: String,
    pub stage: String,
    pub retriable: bool,
    pub message_public: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticService {
    pub state: DiagnosticServiceState,
    pub ubus_connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticCollection {
    pub state: DiagnosticCollectionState,
    #[serde(serialize_with = "saturated_u64")]
    pub generation: u64,
    #[serde(serialize_with = "saturated_option_u64")]
    pub last_attempt_ms: Option<u64>,
    #[serde(serialize_with = "saturated_option_u64")]
    pub last_success_ms: Option<u64>,
    #[serde(serialize_with = "saturated_option_u64")]
    pub age_ms: Option<u64>,
    pub refresh_interval_ms: u32,
    pub consecutive_failures: u32,
    pub retained: bool,
    pub last_error: Option<DiagnosticPublicError>,
}

impl DiagnosticCollection {
    pub fn unavailable(refresh_interval_ms: u32) -> Self {
        Self {
            state: DiagnosticCollectionState::Unavailable,
            generation: 0,
            last_attempt_ms: None,
            last_success_ms: None,
            age_ms: None,
            refresh_interval_ms,
            consecutive_failures: 0,
            retained: false,
            last_error: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticDataPath {
    pub configured_rate: String,
    pub effective_rate: String,
    pub configured_connection: String,
    pub effective_connection: String,
    pub fallback_active: bool,
    pub reason_code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticInterfaces {
    pub state: DiagnosticHealthState,
    pub total: usize,
    pub available: usize,
    pub missing: usize,
    #[serde(serialize_with = "saturated_option_u64")]
    pub sample_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticConnection {
    pub state: DiagnosticHealthState,
    pub source: Option<String>,
    #[serde(serialize_with = "saturated_option_u64")]
    pub entries_seen: Option<u64>,
    #[serde(serialize_with = "saturated_option_u64")]
    pub entries_matched: Option<u64>,
    #[serde(serialize_with = "saturated_option_u64")]
    pub parse_errors: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticSubsystem {
    pub id: String,
    pub state: DiagnosticHealthState,
    pub code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticVersions {
    pub daemon: String,
    pub package: String,
    pub contract_version: u32,
    pub schema_version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticAlert {
    pub id: String,
    pub severity: String,
    pub component: String,
    pub state: String,
    pub message_public: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticConfigIssue {
    pub id: String,
    pub severity: String,
    pub option: String,
    pub state: String,
    pub message_public: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticsResponse {
    pub contract_version: u32,
    pub service: DiagnosticService,
    pub collection: DiagnosticCollection,
    pub data_path: DiagnosticDataPath,
    pub interfaces: DiagnosticInterfaces,
    pub connection: DiagnosticConnection,
    pub subsystems: Vec<DiagnosticSubsystem>,
    pub versions: DiagnosticVersions,
    pub alerts: Vec<DiagnosticAlert>,
    pub config_issues: Vec<DiagnosticConfigIssue>,
}
