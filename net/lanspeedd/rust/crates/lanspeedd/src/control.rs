use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    config::RuntimeConfig,
    error::DaemonError,
    identity::MacAddress,
    model::{Client, ClientControlSummary},
};

pub const X86_MAX_RATE_BPS: u64 = 100_000_000_000;
pub const MIN_RATE_BPS: u64 = 8_000;
pub const MAX_CONTROL_RULES: usize = 64;
pub const MIN_QUEUE_BYTES: u64 = 256 * 1024;
pub const MAX_QUEUE_BYTES: u64 = 16 * 1024 * 1024;
const CONTROL_DHCP_LEASES_PATH: &str = "/tmp/dhcp.leases";
const CONTROL_DHCP_LEASE_MAX_BYTES: u64 = 1024 * 1024;
const CONTROL_DHCP_LEASE_MAX_LINES: usize = 4096;
const CONTROL_DHCP_LEASE_MAX_LINE_BYTES: usize = 512;
const FIRST_CLASS_MINOR: u16 = 0x100;
const LAST_CLASS_MINOR: u16 = 0xfffe;
const DEFAULT_FIFO_HANDLE_MINOR: u16 = 0x1000;
static UCI_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientControlRequest {
    pub identity_key: String,
    pub upload_bps: u64,
    pub download_bps: u64,
    pub internet_disabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientControlDeleteRequest {
    pub identity_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlCommand {
    Set(ClientControlRequest),
    Delete(ClientControlDeleteRequest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlRule {
    pub identity_key: String,
    pub mac: MacAddress,
    pub upload_bps: u64,
    pub download_bps: u64,
    pub internet_disabled: bool,
    pub class_minor: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveClient {
    pub identity_key: String,
    /// The actual LAN-side interface that produced this client sample.  A
    /// single `network.interface.lan` device is not sufficient on routers
    /// collecting multiple VLAN/bridge edges.
    pub interface: Option<String>,
    pub ips: Vec<IpAddr>,
    pub ambiguous: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlPlan {
    pub lan_device: String,
    pub control_devices: Vec<String>,
    /// Bridge-slave ingress devices that feed a DAE-preempted LAN bridge.
    /// Upload is shaped here before both DAE's direct and proxy branches.
    pub dae_upload_devices: Vec<String>,
    pub local_prefixes: Vec<(IpAddr, u8)>,
    pub rules: Vec<ActiveRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveRule {
    pub identity_key: String,
    pub mac: MacAddress,
    pub interface: String,
    pub upload_before_proxy: bool,
    pub upload_preempted: bool,
    pub ips: Vec<IpAddr>,
    pub upload_bps: u64,
    pub download_bps: u64,
    pub internet_disabled: bool,
    pub class_minor: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyResult {
    pub state: String,
    pub reason: Option<String>,
    pub shaping_supported: bool,
    pub blocking_supported: bool,
    pub queue_overflow: bool,
    pub queue_drop_counters: BTreeMap<String, u64>,
    pub class_counter_baselines: BTreeMap<String, u64>,
    pub verified_directions: BTreeMap<String, u8>,
    pub verification_failures: BTreeMap<String, String>,
}

impl ApplyResult {
    fn ready() -> Self {
        Self {
            state: "inactive".into(),
            reason: None,
            shaping_supported: true,
            blocking_supported: true,
            queue_overflow: false,
            queue_drop_counters: BTreeMap::new(),
            class_counter_baselines: BTreeMap::new(),
            verified_directions: BTreeMap::new(),
            verification_failures: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ControlRpcResponse {
    pub ok: bool,
    pub control: ClientControlSummary,
}

pub struct ControlManager {
    rules: BTreeMap<String, ControlRule>,
    live: BTreeMap<String, LiveClient>,
    result: ApplyResult,
    lan_device: String,
    control_devices: BTreeSet<String>,
    preempted_upload_devices: BTreeSet<String>,
    dae_upload_devices: BTreeSet<String>,
    dirty: bool,
}

impl ControlManager {
    pub fn load(config: &RuntimeConfig) -> Result<Self, DaemonError> {
        let lan_device = resolve_lan_device(config);
        if !valid_interface_name(&lan_device) {
            return Err(DaemonError::reload("invalid LAN control interface"));
        }
        let mut control_devices = config
            .runtime_collect_ifnames()
            .into_iter()
            .filter(|device| valid_interface_name(device))
            .collect::<BTreeSet<_>>();
        control_devices.insert(lan_device.clone());
        Ok(Self {
            rules: load_rules()?,
            live: BTreeMap::new(),
            result: ApplyResult::ready(),
            lan_device,
            control_devices,
            preempted_upload_devices: BTreeSet::new(),
            dae_upload_devices: BTreeSet::new(),
            dirty: true,
        })
    }

    pub fn observe_clients(&mut self, clients: &[Client]) {
        let previous_rules = self.active_rules();
        let parsed = clients
            .iter()
            .filter_map(|client| {
                parse_identity_key(&client.identity_key).ok()?;
                let mut ips = client
                    .ips
                    .iter()
                    .filter_map(|ip| IpAddr::from_str(ip).ok())
                    .collect::<Vec<_>>();
                ips.sort_unstable();
                ips.dedup();
                Some(LiveClient {
                    identity_key: client.identity_key.clone(),
                    interface: valid_control_interface(&client.interface),
                    ips,
                    ambiguous: false,
                })
            })
            .collect::<Vec<_>>();
        let mut next = BTreeMap::new();
        for client in parsed {
            if let Some(interface) = &client.interface {
                self.control_devices.insert(interface.clone());
            }
            next.insert(client.identity_key.clone(), client);
        }
        merge_control_lease_addresses(&mut next, control_lease_addresses(&self.rules));
        let mut owners = BTreeMap::<IpAddr, BTreeSet<String>>::new();
        for client in next.values() {
            for ip in &client.ips {
                owners
                    .entry(*ip)
                    .or_default()
                    .insert(client.identity_key.clone());
            }
        }
        for client in next.values_mut() {
            client.ambiguous = client
                .ips
                .iter()
                .any(|ip| owners.get(ip).is_some_and(|values| values.len() != 1));
        }
        self.live = next;
        if previous_rules != self.active_rules() {
            self.dirty = true;
        }
    }

    pub fn observe_preempted_upload_devices(&mut self, devices: BTreeSet<String>) {
        if self.preempted_upload_devices != devices {
            self.preempted_upload_devices = devices;
            self.dirty = true;
        }
    }

    pub fn observe_dae_upload_devices(&mut self, devices: BTreeSet<String>) {
        let devices = devices
            .into_iter()
            .filter(|device| valid_interface_name(device))
            .collect::<BTreeSet<_>>();
        if self.dae_upload_devices != devices {
            self.dae_upload_devices = devices;
            self.dirty = true;
        }
    }

    pub fn reconcile(&mut self) {
        let plan = self.plan();
        if !self.dirty {
            // Observing absent counters after an apply rollback must not turn
            // a concrete failure into a misleading "waiting for traffic"
            // state.  Keep the error sticky until a topology change, reload,
            // or explicit rule update marks the desired plan dirty again.
            if self.result.state == "error" {
                return;
            }
            self.result = platform_observe(&plan, &self.result);
            if self.result.reason.as_deref() == Some("control_topology_changed") {
                self.dirty = true;
            }
            return;
        }
        self.result = platform_apply(&plan).unwrap_or_else(|error| ApplyResult {
            state: "error".into(),
            reason: Some(public_control_error(&error)),
            shaping_supported: false,
            blocking_supported: false,
            queue_overflow: false,
            queue_drop_counters: BTreeMap::new(),
            class_counter_baselines: BTreeMap::new(),
            verified_directions: BTreeMap::new(),
            verification_failures: BTreeMap::new(),
        });
        self.dirty = false;
    }

    pub fn decorate_clients(&self, clients: &mut [Client]) {
        for client in clients {
            client.control = Some(self.summary(&client.identity_key));
        }
    }

    pub fn set(&mut self, request: ClientControlRequest) -> Result<Value, DaemonError> {
        let (mac, _) = parse_identity_key(&request.identity_key)
            .map_err(|reason| DaemonError::reload(reason))?;
        validate_rate(request.upload_bps)?;
        validate_rate(request.download_bps)?;
        let live = self
            .live
            .get(&request.identity_key)
            .ok_or_else(|| DaemonError::reload("unknown_identity"))?;
        if !self.rules.contains_key(&request.identity_key) && self.rules.len() >= MAX_CONTROL_RULES
        {
            return Err(DaemonError::reload("control_rule_limit"));
        }
        if live.ambiguous {
            return Err(DaemonError::reload("ambiguous_identity"));
        }
        if live.ips.is_empty()
            && control_requires_address(
                request.upload_bps,
                request.download_bps,
                request.internet_disabled,
            )
        {
            return Err(DaemonError::reload("identity_address_unavailable"));
        }
        let class_minor = self
            .rules
            .get(&request.identity_key)
            .map(|rule| rule.class_minor)
            .unwrap_or_else(|| allocate_class_minor(&self.rules, &request.identity_key));
        let rule = ControlRule {
            identity_key: request.identity_key.clone(),
            mac,
            upload_bps: request.upload_bps,
            download_bps: request.download_bps,
            internet_disabled: request.internet_disabled,
            class_minor,
        };
        if rule.upload_bps == 0 && rule.download_bps == 0 && !rule.internet_disabled {
            return self.delete(ClientControlDeleteRequest {
                identity_key: request.identity_key,
            });
        }
        persist_rule(&rule)?;
        self.rules.insert(rule.identity_key.clone(), rule);
        self.dirty = true;
        Ok(json!(ControlRpcResponse {
            ok: self.result.state != "error",
            control: self.summary(&request.identity_key),
        }))
    }

    pub fn delete(&mut self, request: ClientControlDeleteRequest) -> Result<Value, DaemonError> {
        parse_identity_key(&request.identity_key).map_err(DaemonError::reload)?;
        delete_rule(&request.identity_key)?;
        self.rules.remove(&request.identity_key);
        self.dirty = true;
        Ok(json!(ControlRpcResponse {
            ok: self.result.state != "error",
            control: self.summary(&request.identity_key),
        }))
    }

    pub fn cleanup(&mut self) -> Result<(), DaemonError> {
        platform_cleanup(&self.plan()).map_err(DaemonError::collection)
    }

    pub fn response(&self, identity_key: &str) -> Value {
        json!(ControlRpcResponse {
            ok: self.result.state != "error",
            control: self.summary(identity_key),
        })
    }

    fn plan(&self) -> ControlPlan {
        let rules = self.active_rules();
        let mut control_devices = self.control_devices.clone();
        control_devices.extend(rules.iter().map(|rule| rule.interface.clone()));
        ControlPlan {
            lan_device: self.lan_device.clone(),
            control_devices: control_devices.into_iter().collect(),
            dae_upload_devices: self.dae_upload_devices.iter().cloned().collect(),
            local_prefixes: local_prefixes().unwrap_or_default(),
            rules,
        }
    }

    fn active_rules(&self) -> Vec<ActiveRule> {
        self.rules
            .values()
            .filter_map(|rule| {
                let live = self.live.get(&rule.identity_key)?;
                if live.ambiguous
                    || (live.ips.is_empty()
                        && control_requires_address(
                            rule.upload_bps,
                            rule.download_bps,
                            rule.internet_disabled,
                        ))
                {
                    return None;
                }
                let interface = live
                    .interface
                    .clone()
                    .unwrap_or_else(|| self.lan_device.clone());
                if rule.upload_bps != 0 && live.interface.is_none() {
                    return None;
                }
                Some(ActiveRule {
                    identity_key: rule.identity_key.clone(),
                    mac: rule.mac,
                    upload_before_proxy: rule.upload_bps != 0
                        && self.preempted_upload_devices.contains(&interface)
                        && !self.dae_upload_devices.is_empty(),
                    upload_preempted: rule.upload_bps != 0
                        && self.preempted_upload_devices.contains(&interface)
                        && self.dae_upload_devices.is_empty(),
                    interface,
                    ips: live.ips.clone(),
                    upload_bps: rule.upload_bps,
                    download_bps: rule.download_bps,
                    internet_disabled: rule.internet_disabled,
                    class_minor: rule.class_minor,
                })
            })
            .collect()
    }

    fn summary(&self, identity_key: &str) -> ClientControlSummary {
        let rule = self.rules.get(identity_key);
        let ambiguous = self
            .live
            .get(identity_key)
            .is_some_and(|client| client.ambiguous);
        let configured = rule.is_some();
        let address_unavailable = rule.is_some_and(|rule| {
            self.live.get(identity_key).is_some_and(|client| {
                client.ips.is_empty()
                    && control_requires_address(
                        rule.upload_bps,
                        rule.download_bps,
                        rule.internet_disabled,
                    )
            })
        });
        let interface_unavailable = rule.is_some_and(|rule| {
            rule.upload_bps != 0
                && self
                    .live
                    .get(identity_key)
                    .is_some_and(|client| client.interface.is_none())
        });
        let upload_preempted = rule.is_some_and(|rule| {
            rule.upload_bps != 0
                && self.dae_upload_devices.is_empty()
                && self.live.get(identity_key).is_some_and(|client| {
                    client
                        .interface
                        .as_ref()
                        .is_some_and(|device| self.preempted_upload_devices.contains(device))
                })
        });
        let mut state = if configured {
            self.result.state.clone()
        } else {
            "inactive".into()
        };
        // A disabled control action still needs an actionable explanation on
        // every live row, including rows without a persisted rule yet.
        let mut reason = self.result.reason.clone();
        if reason.is_none() {
            reason = if !self.result.shaping_supported {
                Some("control_apply_failed".into())
            } else if !self.result.blocking_supported {
                Some("conntrack_control_unavailable".into())
            } else {
                None
            };
        }
        if let Some(rule) = rule {
            let required = u8::from(rule.upload_bps != 0) | (u8::from(rule.download_bps != 0) << 1);
            let verified = self
                .result
                .verified_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0);
            if required == 0
                && rule.internet_disabled
                && matches!(
                    self.result.state.as_str(),
                    "pending_new_connections" | "verified"
                )
            {
                state = "applied".into();
                reason = None;
            } else if required != 0 && self.result.state == "pending_new_connections" {
                if verified & required == required {
                    state = "verified".into();
                    reason = None;
                } else if verified != 0 {
                    reason = Some("direction_verification_pending".into());
                }
            }
        }
        let verification_failure = self.result.verification_failures.get(identity_key);
        if let Some(failure) = verification_failure {
            state = "error".into();
            reason = Some(failure.clone());
        }
        if ambiguous {
            state = "error".into();
            reason = Some("ambiguous_identity".into());
        } else if address_unavailable {
            state = "error".into();
            reason = Some("identity_address_unavailable".into());
        } else if interface_unavailable {
            state = "error".into();
            reason = Some("identity_interface_unavailable".into());
        } else if upload_preempted {
            state = "error".into();
            reason = Some("dae_upload_preempts_control".into());
        }
        ClientControlSummary {
            configured,
            upload_bps: rule.map_or(0, |rule| rule.upload_bps),
            download_bps: rule.map_or(0, |rule| rule.download_bps),
            internet_disabled: rule.is_some_and(|rule| rule.internet_disabled),
            shaping_supported: self.result.shaping_supported && !ambiguous,
            blocking_supported: self.result.blocking_supported && !ambiguous,
            max_rate_bps: platform_max_rate_bps(),
            state,
            reason,
            queue_overflow: verification_failure.map(String::as_str) == Some("queue_overflow"),
        }
    }
}

fn public_control_error(error: &str) -> String {
    [
        "identity_address_unavailable",
        "identity_interface_unavailable",
        "ambiguous_identity",
        "missing_tc",
        "missing_ip",
        "missing_nft",
        "missing_conntrack",
        "conntrack_cleanup_failed",
        "ifb_qdisc_owned_by_external_service",
        "download_qdisc_preflight_conflict",
        "download_qdisc_stage_conflict",
        "qdisc_owned_by_external_service",
        "qdisc_inspection_failed",
        "qdisc_inspection_invalid",
        "lan_control_interface_unavailable",
        "ifb_module_unavailable",
        "ifb_owned_by_external_service",
        "ifb_inspection_failed",
        "sch_htb_unavailable",
        "sch_fq_unavailable",
        "cls_u32_unavailable",
        "cls_matchall_unavailable",
        "act_mirred_unavailable",
        "act_gact_unavailable",
        "ingress_qdisc_owned_by_external_service",
        "ingress_filter_owned_by_external_service",
        "ingress_chain_owned_by_external_service",
        "ingress_filter_inspection_failed",
        "ingress_filter_verification_failed",
        "dae_upload_preempts_control",
        "block_filter_owned_by_external_service",
        "block_chain_owned_by_external_service",
        "block_filter_inspection_failed",
        "block_nft_owned_by_external_service",
        "block_nft_inspection_failed",
        "interface_status_unavailable",
        "queue_tree_verification_failed",
        "queue_filter_verification_failed",
        "control_filter_capacity",
        "queue_stats_unavailable",
        "queue_overflow",
    ]
    .into_iter()
    .find(|code| error.contains(code))
    .unwrap_or("control_apply_failed")
    .to_owned()
}

fn control_lease_addresses(rules: &BTreeMap<String, ControlRule>) -> BTreeMap<String, Vec<IpAddr>> {
    let Ok(metadata) = fs::metadata(CONTROL_DHCP_LEASES_PATH) else {
        return BTreeMap::new();
    };
    if metadata.len() > CONTROL_DHCP_LEASE_MAX_BYTES {
        return BTreeMap::new();
    }
    let Ok(contents) = fs::read_to_string(CONTROL_DHCP_LEASES_PATH) else {
        return BTreeMap::new();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    lease_addresses_from(&contents, rules, now)
}

fn merge_control_lease_addresses(
    clients: &mut BTreeMap<String, LiveClient>,
    leases: BTreeMap<String, Vec<IpAddr>>,
) {
    for (identity_key, addresses) in leases {
        let client = clients.entry(identity_key.clone()).or_insert(LiveClient {
            identity_key,
            interface: None,
            ips: Vec::new(),
            ambiguous: false,
        });
        for address in addresses {
            if !client
                .ips
                .iter()
                .any(|current| current.is_ipv4() == address.is_ipv4())
            {
                client.ips.push(address);
            }
        }
        client.ips.sort_unstable();
        client.ips.dedup();
    }
}

fn lease_addresses_from(
    contents: &str,
    rules: &BTreeMap<String, ControlRule>,
    now: u64,
) -> BTreeMap<String, Vec<IpAddr>> {
    let mut addresses = BTreeMap::<String, Vec<IpAddr>>::new();
    for line in contents.lines().take(CONTROL_DHCP_LEASE_MAX_LINES) {
        if line.len() > CONTROL_DHCP_LEASE_MAX_LINE_BYTES {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let Some(expiry) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        if expiry != 0 && expiry <= now {
            continue;
        }
        let Some(mac) = fields
            .next()
            .and_then(|value| MacAddress::from_str(value).ok())
        else {
            continue;
        };
        let Some(address) = fields.next().and_then(|value| IpAddr::from_str(value).ok()) else {
            continue;
        };
        for rule in rules.values().filter(|rule| rule.mac == mac) {
            addresses
                .entry(rule.identity_key.clone())
                .or_default()
                .push(address);
        }
    }
    for values in addresses.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    addresses
}

pub fn queue_bytes(rate_bps: u64) -> u64 {
    rate_bps
        .saturating_div(16)
        .clamp(MIN_QUEUE_BYTES, MAX_QUEUE_BYTES)
}

pub fn parse_rate(value: Option<String>) -> Result<u64, DaemonError> {
    let value = value.ok_or_else(|| DaemonError::reload("missing_rate"))?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DaemonError::reload("invalid_rate"));
    }
    let rate = value
        .parse::<u64>()
        .map_err(|_| DaemonError::reload("invalid_rate"))?;
    validate_rate(rate)?;
    Ok(rate)
}

pub fn parse_switch(value: Option<String>) -> Result<bool, DaemonError> {
    match value.as_deref() {
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err(DaemonError::reload("invalid_switch")),
    }
}

fn validate_rate(rate: u64) -> Result<(), DaemonError> {
    if rate != 0 && rate < MIN_RATE_BPS {
        return Err(DaemonError::reload("rate_below_minimum"));
    }
    if rate % 8 != 0 {
        return Err(DaemonError::reload("invalid_rate_resolution"));
    }
    if rate > platform_max_rate_bps() {
        return Err(DaemonError::reload("rate_above_platform_maximum"));
    }
    Ok(())
}

fn validate_persisted_rate(rate: u64) -> Result<(), DaemonError> {
    if rate != 0 && rate < MIN_RATE_BPS {
        return Err(DaemonError::reload("rate_below_minimum"));
    }
    if rate % 8 != 0 {
        return Err(DaemonError::reload("invalid_rate_resolution"));
    }
    if rate > platform_hard_max_rate_bps() {
        return Err(DaemonError::reload("rate_above_platform_maximum"));
    }
    Ok(())
}

fn parse_identity_key(value: &str) -> Result<(MacAddress, &str), String> {
    if value.is_empty() || value.len() > 255 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("invalid_identity_key".into());
    }
    let (mac, zone) = value
        .split_once('@')
        .ok_or_else(|| "invalid_identity_key".to_owned())?;
    if zone.is_empty()
        || zone.len() > 64
        || !zone
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err("invalid_identity_key".into());
    }
    let mac = MacAddress::from_str(mac).map_err(|_| "invalid_identity_key".to_owned())?;
    Ok((mac, zone))
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn valid_control_interface(value: &str) -> Option<String> {
    (valid_interface_name(value)
        && !crate::identity::filter::ifname_is_excluded_identity_source(value))
    .then(|| value.to_owned())
}

fn control_requires_address(upload_bps: u64, download_bps: u64, _internet_disabled: bool) -> bool {
    platform_requires_shaping_address() && (upload_bps != 0 || download_bps != 0)
}

fn resolve_lan_device(config: &RuntimeConfig) -> String {
    let discovered = Command::new("ubus")
        .args(["call", "network.interface.lan", "status"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| serde_json::from_slice::<Value>(&output.stdout).ok())
        .and_then(|value| {
            value
                .get("l3_device")
                .or_else(|| value.get("device"))
                .and_then(Value::as_str)
                .filter(|device| valid_interface_name(device))
                .map(str::to_owned)
        });
    discovered
        .or_else(|| {
            config
                .runtime_collect_ifnames()
                .into_iter()
                .find(|device| valid_interface_name(device))
        })
        .unwrap_or_else(|| "br-lan".into())
}

fn section_name(identity_key: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in identity_key.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("control_{hash:016x}")
}

fn allocate_class_minor(rules: &BTreeMap<String, ControlRule>, identity_key: &str) -> u16 {
    let used = rules
        .values()
        .map(|rule| rule.class_minor)
        .collect::<BTreeSet<_>>();
    let span = u32::from(LAST_CLASS_MINOR - FIRST_CLASS_MINOR) + 1;
    let mut hash = 0x811c9dc5u32;
    for byte in identity_key.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    let start = u32::from(FIRST_CLASS_MINOR) + hash % span;
    for offset in 0..span {
        let minor =
            FIRST_CLASS_MINOR + ((start - u32::from(FIRST_CLASS_MINOR) + offset) % span) as u16;
        if minor != DEFAULT_FIFO_HANDLE_MINOR && !used.contains(&minor) {
            return minor;
        }
    }
    LAST_CLASS_MINOR
}

fn load_rules() -> Result<BTreeMap<String, ControlRule>, DaemonError> {
    let mut context = lanspeed_openwrt_sys::UciContext::new()
        .map_err(|error| DaemonError::reload(error.to_string()))?;
    let package = match context.load_package("lanspeed") {
        Ok(package) => package,
        Err(_) => return Ok(BTreeMap::new()),
    };
    let mut rules = BTreeMap::<String, ControlRule>::new();
    for section in package.sections {
        if rules.len() >= MAX_CONTROL_RULES {
            break;
        }
        if section.kind != "client_control" {
            continue;
        }
        let values = section
            .options
            .into_iter()
            .filter_map(|option| match option.value {
                lanspeed_openwrt_sys::UciValue::String(value) => Some((option.name, value)),
                lanspeed_openwrt_sys::UciValue::List(_) => None,
            })
            .collect::<BTreeMap<_, _>>();
        let Some(identity_key) = values.get("identity_key").cloned() else {
            continue;
        };
        let Ok((mac, _)) = parse_identity_key(&identity_key) else {
            continue;
        };
        let upload_bps = values
            .get("upload_bps")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let download_bps = values
            .get("download_bps")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        if validate_persisted_rate(upload_bps).is_err()
            || validate_persisted_rate(download_bps).is_err()
        {
            continue;
        }
        let internet_disabled = values
            .get("internet_disabled")
            .is_some_and(|value| value == "1");
        let configured_minor = values
            .get("class_minor")
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| {
                (*value >= FIRST_CLASS_MINOR)
                    && (*value <= LAST_CLASS_MINOR)
                    && *value != DEFAULT_FIFO_HANDLE_MINOR
            });
        let class_minor = configured_minor
            .filter(|value| !rules.values().any(|rule| rule.class_minor == *value))
            .unwrap_or_else(|| allocate_class_minor(&rules, &identity_key));
        if upload_bps == 0 && download_bps == 0 && !internet_disabled {
            continue;
        }
        rules.insert(
            identity_key.clone(),
            ControlRule {
                identity_key,
                mac,
                upload_bps,
                download_bps,
                internet_disabled,
                class_minor,
            },
        );
    }
    Ok(rules)
}

fn persist_rule(rule: &ControlRule) -> Result<(), DaemonError> {
    let section = section_name(&rule.identity_key);
    let assignments = [
        format!("lanspeed.{section}=client_control"),
        format!("lanspeed.{section}.identity_key={}", rule.identity_key),
        format!("lanspeed.{section}.upload_bps={}", rule.upload_bps),
        format!("lanspeed.{section}.download_bps={}", rule.download_bps),
        format!(
            "lanspeed.{section}.internet_disabled={}",
            u8::from(rule.internet_disabled)
        ),
        format!("lanspeed.{section}.class_minor={}", rule.class_minor),
    ];
    with_private_uci(|save_dir, override_dir| {
        for assignment in &assignments {
            run_checked(
                "uci",
                &["-q", "-C", override_dir, "-t", save_dir, "set", assignment],
            )?;
        }
        run_checked(
            "uci",
            &[
                "-q",
                "-C",
                override_dir,
                "-t",
                save_dir,
                "commit",
                "lanspeed",
            ],
        )
    })
}

fn delete_rule(identity_key: &str) -> Result<(), DaemonError> {
    let section = format!("lanspeed.{}", section_name(identity_key));
    with_private_uci(|save_dir, override_dir| {
        let _ = run_checked(
            "uci",
            &["-q", "-C", override_dir, "-t", save_dir, "delete", &section],
        );
        run_checked(
            "uci",
            &[
                "-q",
                "-C",
                override_dir,
                "-t",
                save_dir,
                "commit",
                "lanspeed",
            ],
        )
    })
}

fn with_private_uci(
    operation: impl FnOnce(&str, &str) -> Result<(), DaemonError>,
) -> Result<(), DaemonError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut path = None;
    for _ in 0..16 {
        let sequence = UCI_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = PathBuf::from(format!(
            "/tmp/lanspeed-control-{}-{nonce:x}-{sequence:x}",
            std::process::id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                path = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(DaemonError::reload(error.to_string())),
        }
    }
    let path = path.ok_or_else(|| DaemonError::reload("uci_temp_directory_unavailable"))?;
    if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o700)) {
        let _ = fs::remove_dir(&path);
        return Err(DaemonError::reload(error.to_string()));
    }
    let save = path.join("save");
    let overrides = path.join("override");
    if let Err(error) = fs::create_dir(&save).and_then(|()| fs::create_dir(&overrides)) {
        let _ = fs::remove_dir_all(&path);
        return Err(DaemonError::reload(error.to_string()));
    }
    let save = save.to_string_lossy().into_owned();
    let overrides = overrides.to_string_lossy().into_owned();
    let result = operation(&save, &overrides);
    let _ = fs::remove_dir_all(path);
    result
}

pub(crate) fn run_checked(program: &str, args: &[&str]) -> Result<(), DaemonError> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| DaemonError::platform(format!("{program}: {error}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(DaemonError::platform(format!(
        "{program} exited {}: {}",
        output.status.code().unwrap_or(-1),
        stderr.trim()
    )))
}

#[cfg(not(feature = "nss-platform"))]
pub(crate) fn clear_conntrack_address(ip: IpAddr) -> Result<(), String> {
    let value = ip.to_string();
    let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
    for selector in ["-s", "-d"] {
        let output = Command::new("conntrack")
            .args(["-D", "-f", family, selector, &value])
            .stdin(Stdio::null())
            .output()
            .map_err(|_| "conntrack_cleanup_failed".to_owned())?;
        let mut diagnostic = output.stdout;
        diagnostic.extend_from_slice(&output.stderr);
        if !conntrack_delete_succeeded(output.status.success(), output.status.code(), &diagnostic) {
            return Err("conntrack_cleanup_failed".into());
        }
    }
    Ok(())
}

#[cfg(any(not(feature = "nss-platform"), test))]
fn conntrack_delete_succeeded(success: bool, code: Option<i32>, diagnostic: &[u8]) -> bool {
    success
        || (code == Some(1)
            && String::from_utf8_lossy(diagnostic)
                .to_ascii_lowercase()
                .contains("0 flow entries"))
}

#[cfg(test)]
pub(crate) fn queue_drops_increased(
    previous: &BTreeMap<String, u64>,
    current: &BTreeMap<String, u64>,
) -> bool {
    current.iter().any(|(name, count)| {
        previous
            .get(name)
            .is_some_and(|previous_count| count > previous_count)
    })
}

fn local_prefixes() -> Result<Vec<(IpAddr, u8)>, String> {
    let output = Command::new("ubus")
        .args(["call", "network.interface.lan", "status"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("lan_status_unavailable".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| "lan_status_invalid")?;
    let mut prefixes = Vec::new();
    for key in [
        "ipv4-address",
        "ipv6-address",
        "ipv6-prefix",
        "ipv6-prefix-assignment",
    ] {
        for item in value
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(address) = item
                .get("address")
                .or_else(|| {
                    item.get("local-address")
                        .and_then(|value| value.get("address"))
                })
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<IpAddr>().ok())
            else {
                continue;
            };
            let max = if address.is_ipv4() { 32 } else { 128 };
            let mask = item
                .get("mask")
                .or_else(|| {
                    item.get("local-address")
                        .and_then(|value| value.get("mask"))
                })
                .and_then(Value::as_u64)
                .unwrap_or(max)
                .min(max) as u8;
            prefixes.push((address, mask));
        }
    }
    // Static routes published by the LAN interface are local destinations too.
    // In particular, routed NAS/secondary-LAN traffic must not be mistaken for
    // Internet traffic merely because it crosses the router's forward hook.
    for route in value
        .get("route")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(address) = route
            .get("target")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<IpAddr>().ok())
        else {
            continue;
        };
        let max = if address.is_ipv4() { 32 } else { 128 };
        let Some(mask) = route.get("mask").and_then(Value::as_u64) else {
            continue;
        };
        if mask != 0 && mask <= max {
            prefixes.push((address, mask as u8));
        }
    }
    prefixes.push(("127.0.0.0".parse().unwrap(), 8));
    prefixes.push(("169.254.0.0".parse().unwrap(), 16));
    // Link-local multicast (ARP is non-IP and is excluded by the x86
    // classifiers themselves). Keep IPv4/IPv6 discovery, router
    // advertisements, mDNS and other LAN multicast out of client shaping.
    prefixes.push(("224.0.0.0".parse().unwrap(), 4));
    prefixes.push(("::1".parse().unwrap(), 128));
    prefixes.push(("fe80::".parse().unwrap(), 10));
    prefixes.push(("ff00::".parse().unwrap(), 8));
    if let Ok(output) = Command::new("ip").args(["-j", "address", "show"]).output() {
        if output.status.success() {
            if let Ok(interfaces) = serde_json::from_slice::<Vec<Value>>(&output.stdout) {
                for address in interfaces.iter().flat_map(|interface| {
                    interface
                        .get("addr_info")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                }) {
                    let Some(ip) = address
                        .get("local")
                        .and_then(Value::as_str)
                        .and_then(|value| value.parse::<IpAddr>().ok())
                    else {
                        continue;
                    };
                    prefixes.push((ip, if ip.is_ipv4() { 32 } else { 128 }));
                }
            }
        }
    }
    Ok(collapse_prefixes(prefixes))
}

fn collapse_prefixes(prefixes: Vec<(IpAddr, u8)>) -> Vec<(IpAddr, u8)> {
    let mut normalized = prefixes
        .into_iter()
        .filter_map(|(address, mask)| normalize_prefix(address, mask))
        .collect::<Vec<_>>();
    normalized.sort_by(|(left_ip, left_mask), (right_ip, right_mask)| {
        let left_family = u8::from(left_ip.is_ipv6());
        let right_family = u8::from(right_ip.is_ipv6());
        (left_family, *left_mask, *left_ip).cmp(&(right_family, *right_mask, *right_ip))
    });
    normalized.dedup();
    let mut collapsed = Vec::new();
    for candidate in normalized {
        if collapsed
            .iter()
            .any(|existing| prefix_contains(*existing, candidate.0))
        {
            continue;
        }
        collapsed.push(candidate);
    }
    collapsed
}

fn normalize_prefix(address: IpAddr, mask: u8) -> Option<(IpAddr, u8)> {
    match address {
        IpAddr::V4(address) if mask <= 32 => {
            let bits = if mask == 0 {
                0
            } else {
                u32::MAX << (32 - mask)
            };
            Some((IpAddr::V4(Ipv4Addr::from(u32::from(address) & bits)), mask))
        }
        IpAddr::V6(address) if mask <= 128 => {
            let bits = if mask == 0 {
                0
            } else {
                u128::MAX << (128 - mask)
            };
            Some((IpAddr::V6(Ipv6Addr::from(u128::from(address) & bits)), mask))
        }
        _ => None,
    }
}

fn prefix_contains(prefix: (IpAddr, u8), address: IpAddr) -> bool {
    let Some((network, _)) = normalize_prefix(address, prefix.1) else {
        return false;
    };
    network == prefix.0
}

#[cfg(not(feature = "nss-platform"))]
fn platform_apply(plan: &ControlPlan) -> Result<ApplyResult, String> {
    crate::platform::x86::control::apply(plan)
}

#[cfg(not(feature = "nss-platform"))]
fn platform_observe(plan: &ControlPlan, previous: &ApplyResult) -> ApplyResult {
    crate::platform::x86::control::observe(plan, previous)
}

#[cfg(feature = "nss-platform")]
fn platform_observe(_plan: &ControlPlan, previous: &ApplyResult) -> ApplyResult {
    previous.clone()
}

#[cfg(feature = "nss-platform")]
fn platform_apply(_plan: &ControlPlan) -> Result<ApplyResult, String> {
    Err("client_control_x86_only".into())
}

#[cfg(not(feature = "nss-platform"))]
fn platform_cleanup(plan: &ControlPlan) -> Result<(), String> {
    crate::platform::x86::control::cleanup(plan)
}

#[cfg(feature = "nss-platform")]
fn platform_cleanup(_plan: &ControlPlan) -> Result<(), String> {
    Ok(())
}

#[cfg(not(feature = "nss-platform"))]
fn platform_max_rate_bps() -> u64 {
    crate::platform::x86::control::max_rate_bps()
}

#[cfg(not(feature = "nss-platform"))]
const fn platform_hard_max_rate_bps() -> u64 {
    X86_MAX_RATE_BPS
}

#[cfg(not(feature = "nss-platform"))]
const fn platform_requires_shaping_address() -> bool {
    false
}

#[cfg(feature = "nss-platform")]
const fn platform_max_rate_bps() -> u64 {
    0
}

#[cfg(feature = "nss-platform")]
const fn platform_hard_max_rate_bps() -> u64 {
    0
}

#[cfg(feature = "nss-platform")]
const fn platform_requires_shaping_address() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(identity_key: &str, ip: &str) -> Client {
        Client {
            mac: identity_key.split('@').next().unwrap().into(),
            identity_key: identity_key.into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec![ip.into()],
            hostname: None,
            rx_bps: 0,
            tx_bps: 0,
            last_seen: 0,
            sample_ms: None,
            rx_bytes: None,
            tx_bytes: None,
            collector_mode: "bpf".into(),
            confidence: crate::model::Confidence::High,
            warnings: vec![],
            tcp_conns: None,
            udp_conns: None,
            udp_dns_conns: None,
            udp_other_conns: None,
            rate_meta: None,
            control: None,
        }
    }

    fn manager() -> ControlManager {
        ControlManager {
            rules: BTreeMap::new(),
            live: BTreeMap::new(),
            result: ApplyResult::ready(),
            lan_device: "br-lan".into(),
            control_devices: BTreeSet::from(["br-lan".into()]),
            preempted_upload_devices: BTreeSet::new(),
            dae_upload_devices: BTreeSet::new(),
            dirty: false,
        }
    }

    #[test]
    fn queue_is_half_second_and_bounded() {
        assert_eq!(queue_bytes(8_000), MIN_QUEUE_BYTES);
        assert_eq!(queue_bytes(80_000_000), 5_000_000);
        assert_eq!(queue_bytes(u64::MAX), MAX_QUEUE_BYTES);
    }

    #[test]
    fn identity_parser_rejects_command_text() {
        assert!(parse_identity_key("aa:bb:cc:dd:ee:01@lan;reboot").is_err());
        assert!(parse_identity_key("$(reboot)@lan").is_err());
        assert!(parse_identity_key("aa:bb:cc:dd:ee:01@lan").is_ok());
    }

    #[cfg(not(feature = "nss-platform"))]
    #[test]
    fn decimal_rate_parser_is_strict() {
        assert_eq!(parse_rate(Some("8000".into())).unwrap(), 8_000);
        assert!(parse_rate(Some("8mbit".into())).is_err());
        assert!(parse_rate(Some("8000;reboot".into())).is_err());
        assert!(parse_rate(Some("8001".into())).is_err());
    }

    #[cfg(feature = "nss-platform")]
    #[test]
    fn nss_build_rejects_x86_only_control_rates() {
        assert_eq!(parse_rate(Some("0".into())).unwrap(), 0);
        assert!(parse_rate(Some("8000".into())).is_err());
    }

    #[test]
    fn duplicate_ipv4_or_ipv6_ownership_fails_closed() {
        for ip in ["192.0.2.9", "2001:db8::9"] {
            let mut manager = manager();
            manager.observe_clients(&[
                client("02:00:00:00:00:01@lan", ip),
                client("02:00:00:00:00:02@lan", ip),
            ]);
            assert!(manager.live.values().all(|client| client.ambiguous));
        }
    }

    #[test]
    fn unique_dual_stack_ownership_remains_usable() {
        let mut first = client("02:00:00:00:00:01@lan", "192.0.2.9");
        first.ips.push("2001:db8::9".into());
        let mut manager = manager();
        manager.observe_clients(&[first]);
        assert!(!manager.live.values().next().unwrap().ambiguous);
    }

    #[test]
    fn unrelated_client_changes_do_not_dirty_the_active_control_plan() {
        let identity = "02:00:00:00:00:01@lan";
        let mut manager = manager();
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 10_000_000,
                download_bps: 0,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR,
            },
        );
        let controlled = client(identity, "192.0.2.9");
        manager.observe_clients(std::slice::from_ref(&controlled));
        manager.dirty = false;

        manager.observe_clients(&[controlled, client("02:00:00:00:00:02@lan", "192.0.2.10")]);

        assert!(!manager.dirty);
    }

    #[test]
    fn upload_rule_follows_the_clients_observed_interface() {
        let identity = "02:00:00:00:00:01@guest";
        let mut observed = client(identity, "192.0.2.9");
        observed.zone = "guest".into();
        observed.interface = "br-guest".into();
        let mut manager = manager();
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 10_000_000,
                download_bps: 0,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR,
            },
        );

        manager.observe_clients(&[observed]);
        let plan = manager.plan();

        assert_eq!(plan.rules[0].interface, "br-guest");
        assert!(plan.control_devices.contains(&"br-lan".into()));
        assert!(plan.control_devices.contains(&"br-guest".into()));
    }

    #[test]
    fn controlled_client_interface_change_dirties_the_plan() {
        let identity = "02:00:00:00:00:01@guest";
        let mut observed = client(identity, "192.0.2.9");
        observed.interface = "br-guest".into();
        let mut manager = manager();
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 10_000_000,
                download_bps: 0,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR,
            },
        );
        manager.observe_clients(std::slice::from_ref(&observed));
        manager.dirty = false;

        observed.interface = "br-iot".into();
        manager.observe_clients(&[observed]);

        assert!(manager.dirty);
        assert_eq!(manager.plan().rules[0].interface, "br-iot");
    }

    #[test]
    fn excluded_upload_interface_fails_closed() {
        let identity = "02:00:00:00:00:01@lan";
        let mut observed = client(identity, "192.0.2.9");
        observed.interface = "dae0".into();
        let mut manager = manager();
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 10_000_000,
                download_bps: 0,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR,
            },
        );

        manager.observe_clients(&[observed]);

        assert!(manager.plan().rules.is_empty());
        assert_eq!(
            manager.summary(identity).reason.as_deref(),
            Some("identity_interface_unavailable")
        );
    }

    #[test]
    fn early_bpf_mode_marks_control_topology_dirty() {
        let mut manager = manager();
        manager.observe_preempted_upload_devices(BTreeSet::from(["br-guest".into()]));
        assert!(manager.dirty);
        let identity = "02:00:00:00:00:01@lan";
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 10_000_000,
                download_bps: 0,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR,
            },
        );
        manager.observe_clients(&[client(identity, "192.0.2.9")]);
        manager.live.get_mut(identity).unwrap().interface = Some("br-guest".into());
        assert!(manager.plan().rules[0].upload_preempted);
    }

    #[test]
    fn supported_dae_bridge_slave_path_keeps_upload_rule_active() {
        let identity = "02:00:00:00:00:01@lan";
        let mut manager = manager();
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 10_000_000,
                download_bps: 0,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR,
            },
        );
        manager.observe_clients(&[client(identity, "192.0.2.9")]);
        manager.observe_preempted_upload_devices(BTreeSet::from(["br-lan".into()]));
        assert!(manager.plan().rules[0].upload_preempted);

        manager.observe_dae_upload_devices(BTreeSet::from(["eth1".into()]));
        let plan = manager.plan();
        assert_eq!(plan.dae_upload_devices, vec!["eth1"]);
        assert!(!plan.rules[0].upload_preempted);
        assert!(plan.rules[0].upload_before_proxy);
    }

    #[test]
    fn active_ip_order_is_canonical_but_address_changes_dirty_the_plan() {
        let identity = "02:00:00:00:00:01@lan";
        let mut manager = manager();
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 10_000_000,
                download_bps: 0,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR,
            },
        );
        let mut first = client(identity, "192.0.2.9");
        first.ips.push("2001:db8::9".into());
        manager.observe_clients(std::slice::from_ref(&first));
        manager.dirty = false;

        first.ips.reverse();
        manager.observe_clients(std::slice::from_ref(&first));
        assert!(!manager.dirty);

        first.ips.push("2001:db8::10".into());
        manager.observe_clients(&[first]);
        assert!(manager.dirty);
    }

    #[test]
    fn unexpired_dhcp_lease_preinstalls_a_persistent_control_rule() {
        let identity = "02:00:00:00:00:01@lan";
        let mut manager = manager();
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 0,
                download_bps: 10_000_000,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR,
            },
        );
        let leases = lease_addresses_from(
            "99 02:00:00:00:00:01 192.0.2.8 expired *\n\
             200 02:00:00:00:00:01 192.0.2.9 active *\n\
             200 02:00:00:00:00:02 192.0.2.10 other *\n",
            &manager.rules,
            100,
        );

        merge_control_lease_addresses(&mut manager.live, leases);

        assert_eq!(manager.plan().rules.len(), 1);
        assert_eq!(
            manager.plan().rules[0].ips,
            vec!["192.0.2.9".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn mac_block_rule_remains_active_without_an_ip_address() {
        let identity = "02:00:00:00:00:01@lan";
        let mut live = client(identity, "192.0.2.9");
        live.ips.clear();
        let mut manager = manager();
        manager.observe_clients(&[live]);
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 0,
                download_bps: 0,
                internet_disabled: true,
                class_minor: FIRST_CLASS_MINOR,
            },
        );
        let plan = manager.plan();
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.rules[0].mac.to_string(), "02:00:00:00:00:01");
        assert!(plan.rules[0].ips.is_empty());
        assert_ne!(manager.summary(identity).state, "error");
    }

    #[test]
    fn mac_shaping_rule_remains_active_without_an_ip_address() {
        let identity = "02:00:00:00:00:01@lan";
        let mut live = client(identity, "192.0.2.9");
        live.ips.clear();
        let mut manager = manager();
        manager.observe_clients(&[live]);
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 8_000,
                download_bps: 8_000,
                internet_disabled: false,
                class_minor: FIRST_CLASS_MINOR,
            },
        );
        let plan = manager.plan();
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.rules[0].mac.to_string(), "02:00:00:00:00:01");
        assert!(plan.rules[0].ips.is_empty());
        assert_ne!(manager.summary(identity).state, "error");
    }

    #[test]
    fn unsupported_shaping_exposes_reason_before_rule_configuration() {
        let mut manager = manager();
        manager.result.shaping_supported = false;
        manager.result.reason = Some("htb_qdisc_unavailable".into());
        let summary = manager.summary("02:00:00:00:00:01@lan");
        assert!(!summary.configured);
        assert!(!summary.shaping_supported);
        assert!(summary.blocking_supported);
        assert_eq!(summary.reason.as_deref(), Some("htb_qdisc_unavailable"));
    }

    #[test]
    fn uci_section_names_are_stable_and_contain_no_identity_text() {
        let identity = "02:00:00:00:00:01@lan";
        let name = section_name(identity);
        assert_eq!(name, section_name(identity));
        assert!(name.starts_with("control_"));
        assert!(!name.contains("02:00"));
        assert_ne!(name, section_name("02:00:00:00:00:02@lan"));
    }

    #[test]
    fn class_allocator_never_collides_with_default_fifo_handle() {
        let mut rules = BTreeMap::new();
        for index in 0..512u16 {
            let identity = format!("02:00:00:00:{:02x}:{:02x}@lan", index >> 8, index & 0xff);
            let minor = allocate_class_minor(&rules, &identity);
            assert_ne!(minor, DEFAULT_FIFO_HANDLE_MINOR);
            rules.insert(
                identity.clone(),
                ControlRule {
                    identity_key: identity,
                    mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                    upload_bps: 8_000,
                    download_bps: 8_000,
                    internet_disabled: false,
                    class_minor: minor,
                },
            );
        }
    }

    #[test]
    fn local_prefixes_are_normalized_and_overlaps_collapsed_for_nft_intervals() {
        let collapsed = collapse_prefixes(vec![
            ("192.0.2.9".parse().unwrap(), 24),
            ("192.0.2.1".parse().unwrap(), 32),
            ("127.0.0.1".parse().unwrap(), 32),
            ("127.0.0.0".parse().unwrap(), 8),
            ("2001:db8::9".parse().unwrap(), 64),
            ("2001:db8::1".parse().unwrap(), 128),
        ]);
        assert_eq!(
            collapsed,
            vec![
                ("127.0.0.0".parse().unwrap(), 8),
                ("192.0.2.0".parse().unwrap(), 24),
                ("2001:db8::".parse().unwrap(), 64),
            ]
        );
    }

    #[test]
    fn multicast_prefixes_normalize_to_lan_control_domains() {
        assert_eq!(
            normalize_prefix("224.0.0.1".parse().unwrap(), 4),
            Some(("224.0.0.0".parse().unwrap(), 4))
        );
        assert_eq!(
            normalize_prefix("ff02::1".parse().unwrap(), 8),
            Some(("ff00::".parse().unwrap(), 8))
        );
    }

    #[test]
    fn platform_errors_never_publish_raw_command_or_address_text() {
        let raw = "tc_failed: device private0 at 192.0.2.99: qdisc_inspection_failed";
        assert_eq!(public_control_error(raw), "qdisc_inspection_failed");
        assert_eq!(
            public_control_error("secret unexpected stderr"),
            "control_apply_failed"
        );
    }

    #[test]
    fn empty_conntrack_delete_is_success_but_real_errors_are_not() {
        assert!(conntrack_delete_succeeded(true, Some(0), b""));
        assert!(conntrack_delete_succeeded(
            false,
            Some(1),
            b"conntrack: 0 flow entries have been deleted"
        ));
        assert!(!conntrack_delete_succeeded(
            false,
            Some(1),
            b"operation not permitted"
        ));
    }

    #[test]
    fn queue_overflow_requires_an_observed_drop_increment() {
        let previous = BTreeMap::from([("upload".into(), 3), ("download".into(), 7)]);
        assert!(!queue_drops_increased(
            &BTreeMap::new(),
            &BTreeMap::from([("upload".into(), 9)])
        ));
        assert!(!queue_drops_increased(
            &previous,
            &BTreeMap::from([("upload".into(), 3), ("download".into(), 6)])
        ));
        assert!(queue_drops_increased(
            &previous,
            &BTreeMap::from([("upload".into(), 4), ("download".into(), 7)])
        ));
    }

    #[test]
    fn queue_overflow_is_not_reported_on_another_client() {
        let first = "02:00:00:00:00:01@lan";
        let second = "02:00:00:00:00:02@lan";
        let mut manager = manager();
        for (index, identity) in [first, second].into_iter().enumerate() {
            manager.rules.insert(
                identity.into(),
                ControlRule {
                    identity_key: identity.into(),
                    mac: MacAddress::from_str(identity.split_once('@').unwrap().0).unwrap(),
                    upload_bps: 10_000_000,
                    download_bps: 0,
                    internet_disabled: false,
                    class_minor: FIRST_CLASS_MINOR + index as u16,
                },
            );
        }
        manager.result.state = "verified".into();
        manager.result.reason = None;
        manager.result.queue_overflow = true;
        manager
            .result
            .verification_failures
            .insert(first.into(), "queue_overflow".into());

        let failed = manager.summary(first);
        assert_eq!(failed.state, "error");
        assert_eq!(failed.reason.as_deref(), Some("queue_overflow"));
        assert!(failed.queue_overflow);

        let unaffected = manager.summary(second);
        assert_eq!(unaffected.state, "verified");
        assert_eq!(unaffected.reason, None);
        assert!(!unaffected.queue_overflow);
    }

    #[test]
    fn failed_apply_state_is_not_hidden_by_counter_observation() {
        let mut manager = manager();
        manager.dirty = false;
        manager.result.state = "error".into();
        manager.result.reason = Some("queue_tree_verification_failed".into());

        manager.reconcile();

        assert_eq!(manager.result.state, "error");
        assert_eq!(
            manager.result.reason.as_deref(),
            Some("queue_tree_verification_failed")
        );
    }

    #[test]
    fn block_only_rule_does_not_inherit_another_clients_pending_state() {
        let identity = "02:00:00:00:00:01@lan";
        let mut manager = manager();
        manager.rules.insert(
            identity.into(),
            ControlRule {
                identity_key: identity.into(),
                mac: MacAddress::from_str("02:00:00:00:00:01").unwrap(),
                upload_bps: 0,
                download_bps: 0,
                internet_disabled: true,
                class_minor: FIRST_CLASS_MINOR,
            },
        );
        manager.result.state = "pending_new_connections".into();
        manager.result.reason = Some("traffic_verification_pending".into());
        let summary = manager.summary(identity);
        assert_eq!(summary.state, "applied");
        assert_eq!(summary.reason, None);
    }
}
