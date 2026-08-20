use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    config::RuntimeConfig,
    error::DaemonError,
    identity::MacAddress,
    model::{Client, ClientControlSummary, ClientsResponse},
};

#[cfg(feature = "nss-platform")]
pub(crate) mod nss_state;
mod platform;

#[cfg(feature = "nss-platform")]
use nss_state::{NssControlPlan, NssControlState};

pub const X86_MAX_RATE_BPS: u64 = 100_000_000_000;
#[cfg(feature = "nss-platform")]
pub const NSS_MAX_RATE_BPS: u64 = 4_000_000_000;
pub const MIN_RATE_BPS: u64 = 8_000;
pub const MAX_CONTROL_RULES: usize = 64;
pub const MIN_QUEUE_BYTES: u64 = 256 * 1024;
pub const MAX_QUEUE_BYTES: u64 = 16 * 1024 * 1024;
const CONTROL_DHCP_LEASES_PATH: &str = "/tmp/dhcp.leases";
const CONTROL_DHCP_LEASE_MAX_BYTES: u64 = 1024 * 1024;
const CONTROL_DHCP_LEASE_MAX_LINES: usize = 4096;
const CONTROL_DHCP_LEASE_MAX_LINE_BYTES: usize = 512;
const LOCAL_PREFIX_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(not(feature = "nss-platform"))]
const FIRST_CLASS_MINOR: u16 = 0x100;
#[cfg(not(feature = "nss-platform"))]
const LAST_CLASS_MINOR: u16 = 0xfffe;
#[cfg(feature = "nss-platform")]
const FIRST_CLASS_MINOR: u16 = 0x7c00;
#[cfg(feature = "nss-platform")]
const LAST_CLASS_MINOR: u16 = 0x7cff;
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
    #[cfg(feature = "nss-platform")]
    pub nss: NssControlPlan,
}

#[cfg(feature = "nss-platform")]
impl ControlPlan {
    pub fn nss_direction_proven(&self, identity_key: &str, direction: u8) -> bool {
        self.nss.direction_proven(identity_key, direction)
    }

    pub fn nss_direction_path_ready(&self, identity_key: &str, direction: u8) -> bool {
        self.nss.direction_path_ready(identity_key, direction)
    }

    pub fn nss_direction_uses_cpu(&self, identity_key: &str, direction: u8) -> bool {
        self.nss.direction_uses_cpu(identity_key, direction)
    }

    pub fn nss_direction_active_nss(&self, identity_key: &str, direction: u8) -> bool {
        self.nss.direction_active_nss(identity_key, direction)
    }

    pub fn nss_direction_active_cpu(&self, identity_key: &str, direction: u8) -> bool {
        self.nss.direction_active_cpu(identity_key, direction)
    }
}

#[cfg(feature = "nss-platform")]
pub const NSS_CPU_UPLOAD: u8 = 1;
#[cfg(feature = "nss-platform")]
pub const NSS_CPU_DOWNLOAD: u8 = 2;

#[cfg(feature = "nss-platform")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NssPathObservation {
    /// Directions backed by a current source-aligned path observation. NSS
    /// startup may use one complete classifier epoch; it still requires an
    /// independently installed Internet-only edge probe and fresh bytes.
    pub valid_directions: u8,
    /// Valid directions that carried Internet traffic in the current window.
    pub active_directions: u8,
    /// Active directions whose observed traffic is fully assigned to the
    /// independently proven NSS and/or CPU paths.
    pub proven_directions: u8,
    /// Active traffic proven on the NSS accelerated path.
    pub nss_directions: u8,
    /// Active traffic proven on the trusted CPU path.
    pub cpu_directions: u8,
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
    #[cfg(feature = "nss-platform")]
    pub nss_verified_directions: BTreeMap<String, u8>,
    #[cfg(feature = "nss-platform")]
    pub cpu_verified_directions: BTreeMap<String, u8>,
    pub verification_failures: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlReconcileKind {
    Apply,
    Observe,
    QuiescePrefixLoss,
}

#[derive(Clone, Debug)]
pub(crate) struct ControlReconcileWork {
    pub(crate) kind: ControlReconcileKind,
    plan: ControlPlan,
    #[cfg(feature = "nss-platform")]
    previous_plan: Option<ControlPlan>,
    previous: ApplyResult,
    prefix_error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ControlReconcileOutcome {
    pub(crate) kind: ControlReconcileKind,
    result: Result<ApplyResult, String>,
    #[cfg(feature = "nss-platform")]
    reconciled_plan: Option<ControlPlan>,
    #[cfg(feature = "nss-platform")]
    processed_conntrack_cleanup_ips: BTreeSet<IpAddr>,
}

impl ControlReconcileOutcome {
    pub(crate) fn failed(kind: ControlReconcileKind, error: impl Into<String>) -> Self {
        Self {
            kind,
            result: Err(error.into()),
            #[cfg(feature = "nss-platform")]
            reconciled_plan: None,
            #[cfg(feature = "nss-platform")]
            processed_conntrack_cleanup_ips: BTreeSet::new(),
        }
    }
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
            #[cfg(feature = "nss-platform")]
            nss_verified_directions: BTreeMap::new(),
            #[cfg(feature = "nss-platform")]
            cpu_verified_directions: BTreeMap::new(),
            verification_failures: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ControlRpcResponse {
    pub ok: bool,
    pub control: ClientControlSummary,
}

#[derive(Clone)]
pub struct ControlManager {
    rules: BTreeMap<String, ControlRule>,
    live: BTreeMap<String, LiveClient>,
    result: ApplyResult,
    #[cfg(feature = "nss-platform")]
    applied_plan: Option<ControlPlan>,
    lan_device: String,
    control_devices: BTreeSet<String>,
    preempted_upload_devices: BTreeSet<String>,
    dae_upload_devices: BTreeSet<String>,
    dae_topology_known: bool,
    dae_active: bool,
    local_prefixes: Vec<(IpAddr, u8)>,
    local_prefixes_ready: bool,
    last_local_prefix_refresh: Option<Instant>,
    max_rate_bps: u64,
    dirty: bool,
    #[cfg(feature = "nss-platform")]
    nss: NssControlState,
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
            #[cfg(feature = "nss-platform")]
            applied_plan: None,
            lan_device,
            control_devices,
            preempted_upload_devices: BTreeSet::new(),
            dae_upload_devices: BTreeSet::new(),
            dae_topology_known: false,
            dae_active: false,
            local_prefixes: Vec::new(),
            local_prefixes_ready: false,
            last_local_prefix_refresh: None,
            max_rate_bps: platform::max_rate_bps(),
            dirty: true,
            #[cfg(feature = "nss-platform")]
            nss: NssControlState::from_config(config),
        })
    }

    /// Seed a read-only NSS reload candidate from the runtime that currently
    /// owns the platform objects.  Path proof and verification are reusable
    /// only when the persisted rules and LAN anchor are unchanged; the
    /// candidate still runs a complete structural observation before commit.
    #[cfg(feature = "nss-platform")]
    pub(crate) fn inherit_nss_reload_state(&mut self, current: &Self) {
        if self.rules != current.rules || self.lan_device != current.lan_device {
            return;
        }
        self.live = current.live.clone();
        self.result = current.result.clone();
        self.applied_plan = current.applied_plan.clone();
        self.control_devices
            .extend(current.control_devices.iter().cloned());
        self.preempted_upload_devices = current.preempted_upload_devices.clone();
        self.dae_upload_devices = current.dae_upload_devices.clone();
        self.dae_topology_known = current.dae_topology_known;
        self.dae_active = current.dae_active;
        self.local_prefixes = current.local_prefixes.clone();
        self.local_prefixes_ready = current.local_prefixes_ready;
        self.last_local_prefix_refresh = current.last_local_prefix_refresh;
        self.dirty = current.dirty;
        self.nss_proven_directions = current.nss_proven_directions.clone();
        self.nss_path_ready_directions = current.nss_path_ready_directions.clone();
        self.nss_cpu_directions = current.nss_cpu_directions.clone();
        self.nss_active_nss_directions = current.nss_active_nss_directions.clone();
        self.nss_active_cpu_directions = current.nss_active_cpu_directions.clone();
        self.nss_attachment_generations = current.nss_attachment_generations.clone();
        self.nss_reload_attachment_rebase_pending = true;
        self.conntrack_cleanup_ips = current.conntrack_cleanup_ips.clone();
        self.pending_conntrack_identities = current.pending_conntrack_identities.clone();
    }

    #[cfg(feature = "nss-platform")]
    pub fn observe_nss_paths(&mut self, observations: BTreeMap<String, NssPathObservation>) {
        let mut proven_next = BTreeMap::new();
        let mut ready_next = BTreeMap::new();
        let mut cpu_next = BTreeMap::new();
        let mut active_nss_next = BTreeMap::new();
        let mut active_cpu_next = BTreeMap::new();
        for (identity_key, rule) in &self.rules {
            let configured = (if rule.upload_bps != 0 {
                NSS_CPU_UPLOAD
            } else {
                0
            }) | (if rule.download_bps != 0 {
                NSS_CPU_DOWNLOAD
            } else {
                0
            });
            let proven = self
                .nss_proven_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & configured;
            let ready = self
                .nss_path_ready_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & configured;
            let cpu = self
                .nss_cpu_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & configured;
            if proven != 0 {
                proven_next.insert(identity_key.clone(), proven);
            }
            let ready = ready & (proven | cpu);
            if ready != 0 {
                ready_next.insert(identity_key.clone(), ready);
            }
            if cpu != 0 {
                cpu_next.insert(identity_key.clone(), cpu);
            }
            let nss_verified = self
                .result
                .nss_verified_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0);
            let cpu_verified = self
                .result
                .cpu_verified_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0);
            let pending_nss = self
                .nss_active_nss_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & configured
                & !nss_verified;
            let pending_cpu = self
                .nss_active_cpu_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & configured
                & !cpu_verified;
            if pending_nss != 0 {
                active_nss_next.insert(identity_key.clone(), pending_nss);
            }
            if pending_cpu != 0 {
                active_cpu_next.insert(identity_key.clone(), pending_cpu);
            }
        }
        for (identity_key, rule) in &self.rules {
            let Some(observation) = observations.get(identity_key) else {
                // No current probe window means no traffic to classify. Keep
                // a previously proven executor ready; structural observation
                // still invalidates it when its owned objects disappear.
                continue;
            };
            let configured = (if rule.upload_bps != 0 {
                NSS_CPU_UPLOAD
            } else {
                0
            }) | (if rule.download_bps != 0 {
                NSS_CPU_DOWNLOAD
            } else {
                0
            });
            let valid = observation.valid_directions & (NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD);
            let active = observation.active_directions & valid & configured;
            let newly_proven = observation.proven_directions & active;
            let newly_nss = observation.nss_directions & active;
            let newly_cpu = observation.cpu_directions & active;
            let proven = proven_next.get(identity_key).copied().unwrap_or(0);
            let mut cpu = cpu_next.get(identity_key).copied().unwrap_or(0);
            // Keep independently proven paths for the rule lifetime. A
            // transparent-proxy flow and an accelerated direct flow can
            // coexist, but both feed the same edge executor.
            cpu |= newly_cpu;
            cpu &= configured;
            let mut direct = proven;
            direct |= newly_nss;
            direct &= configured;
            let mut ready = ready_next.get(identity_key).copied().unwrap_or(0);
            // Installing the queue changes the next edge-rate window by
            // design. A post-shaping ratio can no longer disprove the hook
            // identity that was established before publication. Attachment
            // generation changes and complete structural observation are the
            // authoritative invalidation signals.
            ready |= newly_proven;
            ready &= direct | cpu;
            proven_next.remove(identity_key);
            ready_next.remove(identity_key);
            cpu_next.remove(identity_key);
            if direct != 0 {
                proven_next.insert(identity_key.clone(), direct);
            }
            if ready != 0 {
                ready_next.insert(identity_key.clone(), ready);
            }
            if cpu != 0 {
                cpu_next.insert(identity_key.clone(), cpu);
            }
            let nss_verified = self
                .result
                .nss_verified_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0);
            let cpu_verified = self
                .result
                .cpu_verified_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0);
            let active_nss = active_nss_next.get(identity_key).copied().unwrap_or(0)
                | (newly_nss & !nss_verified);
            let active_cpu = active_cpu_next.get(identity_key).copied().unwrap_or(0)
                | (newly_cpu & !cpu_verified);
            if active_nss != 0 {
                active_nss_next.insert(identity_key.clone(), active_nss);
            } else {
                active_nss_next.remove(identity_key);
            }
            if active_cpu != 0 {
                active_cpu_next.insert(identity_key.clone(), active_cpu);
            } else {
                active_cpu_next.remove(identity_key);
            }
        }
        let executor_changed =
            self.nss_proven_directions != proven_next || self.nss_cpu_directions != cpu_next;
        self.nss_path_ready_directions = ready_next;
        self.nss_active_nss_directions = active_nss_next;
        self.nss_active_cpu_directions = active_cpu_next;
        if executor_changed {
            self.nss_proven_directions = proven_next;
            self.nss_cpu_directions = cpu_next;
            self.dirty = true;
        }
    }

    pub fn observe_clients(&mut self, clients: &[Client]) {
        let previous_rules = self.active_rules();
        #[cfg(feature = "nss-platform")]
        let attachment_generations = clients
            .iter()
            .filter_map(|client| {
                parse_identity_key(&client.identity_key).ok()?;
                let meta = client.rate_meta.as_ref()?;
                let attachment = meta.attachment.as_ref()?;
                if !matches!(
                    attachment.trust,
                    crate::model::AttachmentTrust::AssociatedStation
                        | crate::model::AttachmentTrust::ObservedExclusive
                ) {
                    return None;
                }
                Some((
                    client.identity_key.clone(),
                    (attachment.ifname.clone()?, meta.generation),
                ))
            })
            .collect::<BTreeMap<_, _>>();
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
                #[cfg(feature = "nss-platform")]
                let interface = client
                    .rate_meta
                    .as_ref()
                    .and_then(|meta| meta.attachment.as_ref())
                    .filter(|attachment| {
                        matches!(
                            attachment.trust,
                            crate::model::AttachmentTrust::AssociatedStation
                                | crate::model::AttachmentTrust::ObservedExclusive
                        )
                    })
                    .and_then(|attachment| attachment.ifname.clone());
                #[cfg(not(feature = "nss-platform"))]
                let interface = valid_control_interface(&client.interface);
                Some(LiveClient {
                    identity_key: client.identity_key.clone(),
                    interface,
                    ips,
                    ambiguous: false,
                })
            })
            .collect::<Vec<_>>();
        let mut next = BTreeMap::new();
        for client in parsed {
            if let Some(interface) = &client.interface {
                if self.control_devices.insert(interface.clone()) {
                    #[cfg(feature = "nss-platform")]
                    {
                        // A new trusted edge may carry a LAN/NAS prefix that
                        // is absent from the cached bypass set. Reprobe it
                        // before publishing any existing control again.
                        self.local_prefixes_ready = false;
                        self.last_local_prefix_refresh = None;
                    }
                }
            }
            next.insert(client.identity_key.clone(), client);
        }
        if !self.rules.is_empty() {
            merge_control_lease_addresses(&mut next, control_lease_addresses(&self.rules));
        }
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
        #[cfg(feature = "nss-platform")]
        self.observe_nss_attachment_generations(attachment_generations);
        self.live = next;
        #[cfg(feature = "nss-platform")]
        let retired_identity_resolved = self.resolve_pending_conntrack_identities();
        #[cfg(not(feature = "nss-platform"))]
        let retired_identity_resolved = false;
        if previous_rules != self.active_rules() || retired_identity_resolved {
            self.dirty = true;
        }
    }

    #[cfg(feature = "nss-platform")]
    fn observe_nss_attachment_generations(&mut self, next: BTreeMap<String, (String, u64)>) {
        let rebase = self.nss_reload_attachment_rebase_pending;
        let changed = self
            .rules
            .keys()
            .filter(|identity_key| {
                let previous = self.nss_attachment_generations.get(*identity_key);
                let current = next.get(*identity_key);
                let reload_generation_only = rebase
                    && previous.zip(current).is_some_and(
                        |((previous_edge, _), (current_edge, _))| previous_edge == current_edge,
                    );
                previous != current
                    && !reload_generation_only
                    && (self.nss_proven_directions.contains_key(*identity_key)
                        || self.nss_path_ready_directions.contains_key(*identity_key)
                        || self.nss_cpu_directions.contains_key(*identity_key)
                        || self.result.verified_directions.contains_key(*identity_key))
            })
            .cloned()
            .collect::<Vec<_>>();
        for identity_key in changed {
            self.nss_proven_directions.remove(&identity_key);
            self.nss_path_ready_directions.remove(&identity_key);
            self.nss_cpu_directions.remove(&identity_key);
            self.nss_active_nss_directions.remove(&identity_key);
            self.nss_active_cpu_directions.remove(&identity_key);
            self.result.verified_directions.remove(&identity_key);
            self.result.nss_verified_directions.remove(&identity_key);
            self.result.cpu_verified_directions.remove(&identity_key);
            self.dirty = true;
        }
        self.nss_reload_attachment_rebase_pending = false;
        self.nss_attachment_generations = next;
    }

    /// Structural observation clears queue verification before rebuilding the
    /// owned objects. Re-arm only executors whose path and current attachment
    /// were already proven, so fresh class-counter growth can verify the
    /// rebuilt queue without inventing new path identity.
    #[cfg(feature = "nss-platform")]
    fn rearm_nss_executor_verification(&mut self) {
        let mut active_nss = BTreeMap::new();
        let mut active_cpu = BTreeMap::new();
        for (identity_key, rule) in &self.rules {
            let configured = (if rule.upload_bps != 0 {
                NSS_CPU_UPLOAD
            } else {
                0
            }) | (if rule.download_bps != 0 {
                NSS_CPU_DOWNLOAD
            } else {
                0
            });
            let ready = self
                .nss_path_ready_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & configured;
            let nss = self
                .nss_proven_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & ready;
            let cpu = self
                .nss_cpu_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & ready;
            if nss != 0 {
                active_nss.insert(identity_key.clone(), nss);
            }
            if cpu != 0 {
                active_cpu.insert(identity_key.clone(), cpu);
            }
        }
        self.nss_active_nss_directions = active_nss;
        self.nss_active_cpu_directions = active_cpu;
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

    pub fn observe_dae_topology(
        &mut self,
        dae_active: bool,
        preempted_devices: BTreeSet<String>,
        upload_devices: BTreeSet<String>,
    ) {
        self.dae_topology_known = true;
        self.dae_active = dae_active;
        self.observe_preempted_upload_devices(preempted_devices);
        self.observe_dae_upload_devices(upload_devices);
    }

    /// A failed read-only TC probe must not erase a previously proven DAE
    /// topology. On the first failed probe, fail closed for DAE rather than
    /// silently moving upload control behind its redirect.
    pub fn observe_dae_topology_failure(
        &mut self,
        dae_active: bool,
        candidate_devices: BTreeSet<String>,
    ) {
        if !dae_active {
            return;
        }
        if self.dae_topology_known && self.dae_active {
            return;
        }
        self.dae_active = true;
        self.dae_topology_known = false;
        self.observe_preempted_upload_devices(candidate_devices);
        self.observe_dae_upload_devices(BTreeSet::new());
    }

    pub fn reconcile(&mut self) {
        let Some(work) = self.begin_reconcile() else {
            return;
        };
        self.finish_reconcile(execute_reconcile(work));
    }

    pub(crate) fn begin_reconcile(&mut self) -> Option<ControlReconcileWork> {
        let has_active_rules = !self.active_rules().is_empty();
        let prefix_error = if has_active_rules {
            self.refresh_local_prefixes().err()
        } else {
            None
        };
        let plan = self.plan();
        let kind = if let Some(error) = prefix_error.as_deref() {
            if !prefix_loss_needs_quiesce(&self.result, error) {
                self.dirty = false;
                return None;
            }
            ControlReconcileKind::QuiescePrefixLoss
        } else if self.dirty {
            ControlReconcileKind::Apply
        } else if self.result.state == "error" {
            // Keep an apply error sticky until a rule or topology change marks
            // the desired plan dirty again.
            return None;
        } else {
            ControlReconcileKind::Observe
        };
        self.dirty = false;
        Some(ControlReconcileWork {
            kind,
            plan,
            #[cfg(feature = "nss-platform")]
            previous_plan: self.applied_plan.clone(),
            previous: self.result.clone(),
            prefix_error,
        })
    }

    pub(crate) fn finish_reconcile(&mut self, outcome: ControlReconcileOutcome) {
        let kind = outcome.kind;
        #[cfg(feature = "nss-platform")]
        let reconciled_plan = outcome.reconciled_plan;
        #[cfg(feature = "nss-platform")]
        let processed_conntrack_cleanup_ips = outcome.processed_conntrack_cleanup_ips;
        match outcome.result {
            Ok(result) => {
                if matches!(
                    kind,
                    ControlReconcileKind::Apply | ControlReconcileKind::Observe
                ) {
                    #[cfg(feature = "nss-platform")]
                    {
                        self.applied_plan = reconciled_plan;
                    }
                }
                if kind == ControlReconcileKind::Apply {
                    #[cfg(feature = "nss-platform")]
                    self.conntrack_cleanup_ips
                        .retain(|ip| !processed_conntrack_cleanup_ips.contains(ip));
                } else if kind == ControlReconcileKind::QuiescePrefixLoss {
                    #[cfg(feature = "nss-platform")]
                    {
                        self.applied_plan = None;
                    }
                }
                if kind == ControlReconcileKind::Observe
                    && result.reason.as_deref() == Some("control_topology_changed")
                {
                    #[cfg(feature = "nss-platform")]
                    {
                        self.applied_plan = None;
                    }
                    #[cfg(feature = "nss-platform")]
                    self.rearm_nss_executor_verification();
                    self.dirty = true;
                }
                self.result = result;
            }
            Err(error) => {
                #[cfg(feature = "nss-platform")]
                {
                    self.applied_plan = None;
                }
                self.result = ApplyResult {
                    state: "error".into(),
                    reason: Some(public_control_error(&error)),
                    shaping_supported: self.result.shaping_supported,
                    blocking_supported: self.result.blocking_supported,
                    queue_overflow: false,
                    queue_drop_counters: BTreeMap::new(),
                    class_counter_baselines: BTreeMap::new(),
                    verified_directions: BTreeMap::new(),
                    #[cfg(feature = "nss-platform")]
                    nss_verified_directions: BTreeMap::new(),
                    #[cfg(feature = "nss-platform")]
                    cpu_verified_directions: BTreeMap::new(),
                    verification_failures: BTreeMap::new(),
                };
            }
        }
    }

    /// Reload candidates must prove that every inherited NSS object still
    /// exists without changing the live dataplane before the transaction is
    /// committed.  A missing queue, filter, or nft object clears verification
    /// and leaves the desired plan dirty for the new owner to rebuild.
    #[cfg(feature = "nss-platform")]
    pub(crate) fn observe_existing_nss_control(&mut self) {
        let has_active_rules = !self.active_rules().is_empty();
        if has_active_rules {
            if let Err(error) = self.refresh_local_prefixes() {
                self.result = failed_apply_result(&error, &self.result);
                self.dirty = true;
                return;
            }
        }
        let observed = platform::observe(&self.plan(), &self.result);
        if observed.reason.as_deref() == Some("control_topology_changed") {
            self.rearm_nss_executor_verification();
            self.dirty = true;
        }
        self.result = observed;
    }

    pub fn decorate_clients(&self, clients: &mut [Client]) {
        for client in clients {
            client.control = Some(self.summary(&client.identity_key));
        }
    }

    pub fn decorate_response(&self, response: &mut ClientsResponse) {
        self.decorate_clients(&mut response.clients);
        #[cfg(feature = "nss-platform")]
        response
            .evidence
            .get_or_insert_default()
            .details
            .insert("nss_control".into(), self.nss_control_diagnostics());
    }

    #[cfg(feature = "nss-platform")]
    fn nss_control_diagnostics(&self) -> Value {
        let mut active_clients = 0usize;
        let mut effective_clients = 0usize;
        let mut pending_clients = 0usize;
        let mut error_clients = 0usize;
        let mut queue_overflow_clients = 0usize;
        let mut rate_limited_clients = 0usize;
        let mut internet_disabled_clients = 0usize;
        let mut block_active_clients = 0usize;
        let mut required_directions = 0u32;
        let mut verified_directions = 0u32;
        let mut nss_verified_directions = 0u32;
        let mut cpu_verified_directions = 0u32;
        let mut pending_reason = None;
        let mut error_detail = None;

        for (identity_key, rule) in &self.rules {
            rate_limited_clients += usize::from(rule.upload_bps != 0 || rule.download_bps != 0);
            internet_disabled_clients += usize::from(rule.internet_disabled);
            let Some(_) = self.live.get(identity_key) else {
                continue;
            };
            active_clients += 1;
            let summary = self.summary(identity_key);
            let required = u8::from(rule.upload_bps != 0) | (u8::from(rule.download_bps != 0) << 1);
            let verified = self
                .result
                .verified_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & required;
            required_directions += required.count_ones();
            verified_directions += verified.count_ones();
            nss_verified_directions += (self
                .result
                .nss_verified_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & required)
                .count_ones();
            cpu_verified_directions += (self
                .result
                .cpu_verified_directions
                .get(identity_key)
                .copied()
                .unwrap_or(0)
                & required)
                .count_ones();
            if rule.internet_disabled
                && matches!(
                    summary.state.as_str(),
                    "applied" | "verified" | "pending_new_connections"
                )
            {
                block_active_clients += 1;
            }
            if summary.queue_overflow {
                queue_overflow_clients += 1;
            }
            match summary.state.as_str() {
                "verified" | "applied" => effective_clients += 1,
                "error" | "unsupported" => {
                    error_clients += 1;
                    if error_detail.is_none() {
                        error_detail = summary.reason.clone();
                    }
                }
                _ => {
                    pending_clients += 1;
                    if pending_reason.is_none() {
                        pending_reason = summary.reason.clone();
                    }
                }
            }
        }

        let configured_clients = self.rules.len();
        let supported = self.result.shaping_supported || self.result.blocking_supported;
        let (state, reason_code) = if !supported {
            ("unavailable", Some("nss_client_control_unavailable"))
        } else if configured_clients == 0 {
            ("inactive", Some("nss_control_not_configured"))
        } else if error_clients != 0 {
            ("error", Some("nss_control_executor_failed"))
        } else if active_clients == 0 {
            ("inactive", Some("nss_control_no_active_client"))
        } else if pending_clients != 0 || verified_directions < required_directions {
            (
                "pending",
                pending_reason
                    .as_deref()
                    .and_then(safe_control_diagnostic_code)
                    .or(Some("nss_control_verification_pending")),
            )
        } else {
            ("verified", None)
        };
        json!({
            "state": state,
            "reason_code": reason_code,
            "detail_code": error_detail.as_deref().and_then(safe_control_diagnostic_code),
            "shaping_supported": self.result.shaping_supported,
            "blocking_supported": self.result.blocking_supported,
            "configured_clients": configured_clients,
            "active_clients": active_clients,
            "effective_clients": effective_clients,
            "pending_clients": pending_clients,
            "error_clients": error_clients,
            "queue_overflow_clients": queue_overflow_clients,
            "rate_limited_clients": rate_limited_clients,
            "internet_disabled_clients": internet_disabled_clients,
            "block_active_clients": block_active_clients,
            "required_directions": required_directions,
            "verified_directions": verified_directions,
            "nss_verified_directions": nss_verified_directions,
            "cpu_verified_directions": cpu_verified_directions,
            "hardware_telemetry": crate::platform::nss::control::hardware_telemetry(),
        })
    }

    pub fn set(&mut self, request: ClientControlRequest) -> Result<Value, DaemonError> {
        let (mac, _) = parse_identity_key(&request.identity_key)
            .map_err(|reason| DaemonError::reload(reason))?;
        validate_rate(request.upload_bps)?;
        validate_rate(request.download_bps)?;
        #[cfg(feature = "nss-platform")]
        let previous_rule = self.rules.get(&request.identity_key).cloned();
        let live = self
            .live
            .get(&request.identity_key)
            .ok_or_else(|| DaemonError::reload("unknown_identity"))?;
        #[cfg(feature = "nss-platform")]
        let conntrack_ips = live.ips.clone();
        if !self.rules.contains_key(&request.identity_key) && self.rules.len() >= MAX_CONTROL_RULES
        {
            return Err(DaemonError::reload("control_rule_limit"));
        }
        let relaxing_ambiguous_control = self
            .rules
            .get(&request.identity_key)
            .is_some_and(|old| control_update_is_not_more_restrictive(old, &request));
        if live.ambiguous && !relaxing_ambiguous_control {
            return Err(DaemonError::reload("ambiguous_identity"));
        }
        #[cfg(feature = "nss-platform")]
        let requires_control =
            request.upload_bps != 0 || request.download_bps != 0 || request.internet_disabled;
        #[cfg(feature = "nss-platform")]
        if requires_control && live.interface.is_none() && !relaxing_ambiguous_control {
            /* A persisted rule without a trusted attachment is intentionally
             * kept inactive by active_rules(). Rejecting a new restrictive
             * request here prevents it from dirtying the global NSS plan and
             * attempting to tear down an unrelated stale IGS edge. */
            return Err(DaemonError::reload("identity_interface_unavailable"));
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
        #[cfg(feature = "nss-platform")]
        let refresh_connections =
            nss_control_update_requires_conntrack_refresh(previous_rule.as_ref(), &rule);
        persist_rule(&rule)?;
        self.rules.insert(rule.identity_key.clone(), rule);
        // A pure rate change keeps the same class and classifier contract, so
        // NSSHTB/NSSBFIFO can be replaced in place without deleting live
        // conntrack entries. Reclassify only transitions that change which
        // executor owns an existing flow.
        #[cfg(feature = "nss-platform")]
        if refresh_connections {
            self.conntrack_cleanup_ips.extend(conntrack_ips);
        }
        self.dirty = true;
        Ok(json!(ControlRpcResponse {
            ok: self.result.state != "error",
            control: self.summary(&request.identity_key),
        }))
    }

    pub fn delete(&mut self, request: ClientControlDeleteRequest) -> Result<Value, DaemonError> {
        parse_identity_key(&request.identity_key).map_err(DaemonError::reload)?;
        delete_rule(&request.identity_key)?;
        #[cfg(feature = "nss-platform")]
        if self.rules.contains_key(&request.identity_key) {
            self.pending_conntrack_identities
                .insert(request.identity_key.clone());
            self.resolve_pending_conntrack_identities();
        }
        self.rules.remove(&request.identity_key);
        self.dirty = true;
        Ok(json!(ControlRpcResponse {
            ok: self.result.state != "error",
            control: self.summary(&request.identity_key),
        }))
    }

    pub fn cleanup(&mut self) -> Result<(), DaemonError> {
        platform::cleanup(&self.plan()).map_err(DaemonError::collection)
    }

    #[cfg(feature = "nss-platform")]
    pub(crate) fn nss_path_probe_snapshot(
        &self,
        epoch_end_ms: u64,
    ) -> Result<crate::platform::nss::control::PathProbeSnapshot, String> {
        crate::platform::nss::control::path_probe_snapshot(&self.plan(), epoch_end_ms)
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
            local_prefixes: self.local_prefixes.clone(),
            rules,
            #[cfg(feature = "nss-platform")]
            nss: self.nss.plan(),
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
                let requires_control_interface =
                    rule.upload_bps != 0 || rule.download_bps != 0 || rule.internet_disabled;
                if requires_control_interface && live.interface.is_none() {
                    return None;
                }
                let interface = live
                    .interface
                    .clone()
                    .unwrap_or_else(|| self.lan_device.clone());
                let requires_upload_control = rule.upload_bps != 0 || rule.internet_disabled;
                Some(ActiveRule {
                    identity_key: rule.identity_key.clone(),
                    mac: rule.mac,
                    upload_before_proxy: requires_upload_control
                        && self.preempted_upload_devices.contains(&interface)
                        && !self.dae_upload_devices.is_empty(),
                    upload_preempted: requires_upload_control
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

    #[cfg(feature = "nss-platform")]
    fn resolve_pending_conntrack_identities(&mut self) -> bool {
        let resolved = self
            .pending_conntrack_identities
            .iter()
            .filter_map(|identity_key| {
                let ips = deleted_rule_conntrack_ips(self.live.get(identity_key));
                (!ips.is_empty()).then(|| (identity_key.clone(), ips))
            })
            .collect::<Vec<_>>();
        for (identity_key, ips) in &resolved {
            self.pending_conntrack_identities.remove(identity_key);
            self.conntrack_cleanup_ips.extend(ips.iter().copied());
        }
        !resolved.is_empty()
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
            (rule.upload_bps != 0 || rule.download_bps != 0 || rule.internet_disabled)
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
            max_rate_bps: self.max_rate_bps,
            state,
            reason,
            queue_overflow: verification_failure.map(String::as_str) == Some("queue_overflow"),
        }
    }

    fn refresh_local_prefixes(&mut self) -> Result<(), String> {
        let now = Instant::now();
        if self
            .last_local_prefix_refresh
            .is_some_and(|last| now.saturating_duration_since(last) < LOCAL_PREFIX_REFRESH_INTERVAL)
        {
            return if self.local_prefixes_ready {
                Ok(())
            } else {
                Err("local_network_unavailable".into())
            };
        }
        self.last_local_prefix_refresh = Some(now);
        match local_prefixes(&self.control_devices) {
            Ok(prefixes) => {
                #[cfg(feature = "nss-platform")]
                let recovered_after_probe_failure = !self.local_prefixes_ready;
                #[cfg(not(feature = "nss-platform"))]
                let recovered_after_probe_failure = false;
                if self.local_prefixes != prefixes || recovered_after_probe_failure {
                    self.local_prefixes = prefixes;
                    self.dirty = true;
                }
                self.local_prefixes_ready = true;
                Ok(())
            }
            Err(_) => {
                self.local_prefixes_ready = false;
                Err("local_network_unavailable".into())
            }
        }
    }
}

#[cfg(feature = "nss-platform")]
fn preserve_unchanged_nss_verification(
    previous_plan: Option<&ControlPlan>,
    plan: &ControlPlan,
    previous: &ApplyResult,
    mut next: ApplyResult,
) -> ApplyResult {
    let Some(previous_plan) = previous_plan else {
        return next;
    };
    if previous_plan.lan_device != plan.lan_device
        || previous_plan.control_devices != plan.control_devices
        || previous_plan.dae_upload_devices != plan.dae_upload_devices
        || previous_plan.local_prefixes != plan.local_prefixes
    {
        return next;
    }

    let previous_rules = previous_plan
        .rules
        .iter()
        .map(|rule| (rule.identity_key.as_str(), rule))
        .collect::<BTreeMap<_, _>>();
    for rule in &plan.rules {
        if !previous_rules
            .get(rule.identity_key.as_str())
            .is_some_and(|previous| nss_flow_contract_unchanged(previous, rule))
            || !nss_identity_plan_unchanged(previous_plan, plan, &rule.identity_key)
        {
            continue;
        }
        let required = u8::from(rule.upload_bps != 0) | (u8::from(rule.download_bps != 0) << 1);
        copy_direction_evidence(
            &previous.verified_directions,
            &mut next.verified_directions,
            &rule.identity_key,
            required,
        );
        copy_direction_evidence(
            &previous.nss_verified_directions,
            &mut next.nss_verified_directions,
            &rule.identity_key,
            required,
        );
        copy_direction_evidence(
            &previous.cpu_verified_directions,
            &mut next.cpu_verified_directions,
            &rule.identity_key,
            required,
        );
        if let Some(reason) = previous.verification_failures.get(&rule.identity_key) {
            next.verification_failures
                .insert(rule.identity_key.clone(), reason.clone());
        }
    }
    next.queue_overflow = next
        .verification_failures
        .values()
        .any(|reason| reason == "queue_overflow");
    refresh_nss_apply_state(plan, &mut next);
    next
}

#[cfg(feature = "nss-platform")]
fn nss_flow_contract_unchanged(previous: &ActiveRule, next: &ActiveRule) -> bool {
    previous.identity_key == next.identity_key
        && previous.mac == next.mac
        && previous.interface == next.interface
        && previous.upload_before_proxy == next.upload_before_proxy
        && previous.upload_preempted == next.upload_preempted
        && previous.ips.iter().collect::<BTreeSet<_>>() == next.ips.iter().collect::<BTreeSet<_>>()
        && previous.internet_disabled == next.internet_disabled
        && previous.class_minor == next.class_minor
        && (previous.upload_bps == 0) == (next.upload_bps == 0)
        && (previous.download_bps == 0) == (next.download_bps == 0)
}

#[cfg(feature = "nss-platform")]
fn nss_identity_plan_unchanged(previous: &ControlPlan, next: &ControlPlan, identity: &str) -> bool {
    // Proven/active executor maps are rolling traffic evidence and can
    // change while an existing flow remains on the same classifier path.
    // Only path readiness is structural for retaining a verified rate-only
    // update; a lost ready direction still forces fresh verification.
    previous.nss_path_ready_directions.get(identity) == next.nss_path_ready_directions.get(identity)
}

#[cfg(feature = "nss-platform")]
fn copy_direction_evidence(
    previous: &BTreeMap<String, u8>,
    next: &mut BTreeMap<String, u8>,
    identity: &str,
    required: u8,
) {
    let directions = previous.get(identity).copied().unwrap_or(0) & required;
    if directions != 0 {
        next.insert(identity.to_owned(), directions);
    }
}

#[cfg(feature = "nss-platform")]
fn refresh_nss_apply_state(plan: &ControlPlan, result: &mut ApplyResult) {
    let expected = plan.rules.iter().fold(0usize, |count, rule| {
        count + usize::from(rule.upload_bps != 0) + usize::from(rule.download_bps != 0)
    });
    if expected == 0 {
        return;
    }
    let verified = plan
        .rules
        .iter()
        .map(|rule| {
            let directions = result
                .verified_directions
                .get(&rule.identity_key)
                .copied()
                .unwrap_or(0);
            usize::from(rule.upload_bps != 0 && directions & NSS_CPU_UPLOAD != 0)
                + usize::from(rule.download_bps != 0 && directions & NSS_CPU_DOWNLOAD != 0)
        })
        .sum::<usize>();
    let path_pending = plan.rules.iter().any(|rule| {
        (rule.upload_bps != 0 && !plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD))
            || (rule.download_bps != 0
                && !plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD))
    });
    if verified == expected && !result.queue_overflow && !path_pending {
        result.state = "verified".into();
        result.reason = None;
    } else {
        result.state = "pending_new_connections".into();
        result.reason = Some(
            if path_pending {
                "nss_path_identity_pending"
            } else if verified == 0 {
                "traffic_verification_pending"
            } else {
                "direction_verification_pending"
            }
            .into(),
        );
    }
}

pub(crate) fn execute_reconcile(work: ControlReconcileWork) -> ControlReconcileOutcome {
    let kind = work.kind;
    #[cfg(feature = "nss-platform")]
    let processed_conntrack_cleanup_ips = work.plan.nss.conntrack_cleanup_ips().clone();
    let result = match kind {
        ControlReconcileKind::Apply => platform::apply(&work.plan).map(|result| {
            #[cfg(feature = "nss-platform")]
            {
                preserve_unchanged_nss_verification(
                    work.previous_plan.as_ref(),
                    &work.plan,
                    &work.previous,
                    result,
                )
            }
            #[cfg(not(feature = "nss-platform"))]
            {
                result
            }
        }),
        ControlReconcileKind::Observe => Ok(platform::observe(&work.plan, &work.previous)),
        ControlReconcileKind::QuiescePrefixLoss => {
            let primary = work
                .prefix_error
                .as_deref()
                .unwrap_or("local_network_unavailable");
            let cleanup_error = platform::quiesce_prefix_loss(&work.plan).err();
            Ok(failed_apply_result(
                cleanup_error.as_deref().unwrap_or(primary),
                &work.previous,
            ))
        }
    };
    #[cfg(feature = "nss-platform")]
    let reconciled_plan = result.as_ref().ok().and_then(|result| match kind {
        ControlReconcileKind::Apply => Some(work.plan.clone()),
        ControlReconcileKind::Observe
            if result.reason.as_deref() != Some("control_topology_changed") =>
        {
            Some(work.plan.clone())
        }
        ControlReconcileKind::Observe | ControlReconcileKind::QuiescePrefixLoss => None,
    });
    ControlReconcileOutcome {
        kind,
        result,
        #[cfg(feature = "nss-platform")]
        reconciled_plan,
        #[cfg(feature = "nss-platform")]
        processed_conntrack_cleanup_ips,
    }
}

#[cfg(test)]
pub(crate) fn test_reconcile_work() -> ControlReconcileWork {
    ControlReconcileWork {
        kind: ControlReconcileKind::Observe,
        plan: ControlPlan {
            lan_device: "br-lan".into(),
            control_devices: vec!["br-lan".into()],
            dae_upload_devices: Vec::new(),
            local_prefixes: Vec::new(),
            rules: Vec::new(),
            #[cfg(feature = "nss-platform")]
            nss: NssControlPlan::default(),
        },
        #[cfg(feature = "nss-platform")]
        previous_plan: None,
        previous: ApplyResult::ready(),
        prefix_error: None,
    }
}

#[cfg(test)]
pub(crate) fn test_reconcile_outcome(kind: ControlReconcileKind) -> ControlReconcileOutcome {
    ControlReconcileOutcome {
        kind,
        result: Ok(ApplyResult::ready()),
        #[cfg(feature = "nss-platform")]
        reconciled_plan: None,
        #[cfg(feature = "nss-platform")]
        processed_conntrack_cleanup_ips: BTreeSet::new(),
    }
}

#[cfg(feature = "nss-platform")]
fn deleted_rule_conntrack_ips(client: Option<&LiveClient>) -> Vec<IpAddr> {
    client
        .filter(|client| !client.ambiguous)
        .map(|client| client.ips.clone())
        .unwrap_or_default()
}

#[cfg(feature = "nss-platform")]
fn nss_control_update_requires_conntrack_refresh(
    previous: Option<&ControlRule>,
    next: &ControlRule,
) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    previous.identity_key != next.identity_key
        || previous.mac != next.mac
        || previous.class_minor != next.class_minor
        || previous.internet_disabled != next.internet_disabled
        || (previous.upload_bps == 0) != (next.upload_bps == 0)
        || (previous.download_bps == 0) != (next.download_bps == 0)
}

fn control_update_is_not_more_restrictive(
    previous: &ControlRule,
    request: &ClientControlRequest,
) -> bool {
    fn rate_relaxes(previous: u64, requested: u64) -> bool {
        requested == 0 || (previous != 0 && requested >= previous)
    }
    (!request.internet_disabled || previous.internet_disabled)
        && rate_relaxes(previous.upload_bps, request.upload_bps)
        && rate_relaxes(previous.download_bps, request.download_bps)
}

fn failed_apply_result(error: &str, previous: &ApplyResult) -> ApplyResult {
    ApplyResult {
        state: "error".into(),
        reason: Some(public_control_error(error)),
        shaping_supported: previous.shaping_supported,
        blocking_supported: previous.blocking_supported,
        queue_overflow: false,
        queue_drop_counters: BTreeMap::new(),
        class_counter_baselines: BTreeMap::new(),
        verified_directions: BTreeMap::new(),
        #[cfg(feature = "nss-platform")]
        nss_verified_directions: BTreeMap::new(),
        #[cfg(feature = "nss-platform")]
        cpu_verified_directions: BTreeMap::new(),
        verification_failures: BTreeMap::new(),
    }
}

fn prefix_loss_needs_quiesce(previous: &ApplyResult, error: &str) -> bool {
    let reason = public_control_error(error);
    previous.state != "error" || previous.reason.as_deref() != Some(reason.as_str())
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
        "missing_ubus",
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
        "ingress_filter_cleanup_failed",
        "dae_upload_preempts_control",
        "block_filter_owned_by_external_service",
        "block_chain_owned_by_external_service",
        "block_filter_inspection_failed",
        "block_filter_verification_failed",
        "block_filter_cleanup_failed",
        "block_nft_owned_by_external_service",
        "block_nft_inspection_failed",
        "interface_status_unavailable",
        "queue_tree_verification_failed",
        "queue_filter_verification_failed",
        "control_filter_capacity",
        "queue_stats_unavailable",
        "queue_overflow",
        "local_network_unavailable",
        "control_rollback_failed",
        "nss_control_rollback_failed",
        "nss_control_command_timeout",
        "nss_ecm_dscp_unavailable",
        "nss_qdisc_unavailable",
        "nss_wan_topology_invalid",
        "nss_netifd_topology_unavailable",
        "nss_fw4_topology_unavailable",
        "nss_wan_interface_unavailable",
        "nss_upload_edge_unavailable",
        "nss_download_edge_unavailable",
        "nss_download_edge_invalid",
        "nss_default_class_capacity_exceeded",
        "nss_qdisc_owned_by_external_service",
        "nss_qdisc_apply_failed",
        "nss_qdisc_inspection_failed",
        "nss_qdisc_verification_failed",
        "nss_control_firewall_owned_by_external_service",
        "nss_control_firewall_inspection_failed",
        "nss_control_firewall_failed",
        "cpu_path_block_interface_unavailable",
        "cpu_path_block_owned_by_external_service",
        "cpu_path_block_inspection_failed",
        "cpu_path_block_apply_failed",
        "cpu_path_block_missing",
        "cpu_path_block_stale",
        "cpu_path_block_cleanup_failed",
        "cpu_path_probe_interface_unavailable",
        "cpu_path_probe_owned_by_external_service",
        "cpu_path_probe_inspection_failed",
        "cpu_path_probe_apply_failed",
        "cpu_path_probe_missing",
        "cpu_path_probe_stale",
        "cpu_path_probe_cleanup_failed",
        "cpu_path_classifier_owned_by_external_service",
        "cpu_path_classifier_inspection_failed",
        "cpu_path_classifier_verification_failed",
        "cpu_path_classifier_cleanup_failed",
        "cpu_path_classifier_missing",
        "cpu_path_classifier_stale",
        "cpu_path_qdisc_owned_by_external_service",
        "cpu_path_qdisc_verification_failed",
        "cpu_path_qdisc_inspection_failed",
        "cpu_path_class_inspection_failed",
        "cpu_path_filter_owned_by_external_service",
        "cpu_path_filter_inspection_failed",
        "cpu_path_filter_verification_failed",
        "cpu_path_filter_cleanup_failed",
        "act_nssmirred_unavailable",
        "act_skbedit_unavailable",
        "nss_igs_ifb_name_collision",
        "nss_igs_capacity_exceeded",
        "nss_igs_tag_capacity_exceeded",
        "nss_igs_tag_config_failed",
        "nss_igs_tag_config_inspection_failed",
        "nss_igs_tag_config_verification_failed",
        "nss_igs_ifb_owned_by_external_service",
        "nss_igs_ifb_inspection_failed",
        "nss_igs_ifb_missing",
        "nss_igs_ifb_stale",
        "nss_igs_mapping_owned_by_external_service",
        "nss_igs_mapping_inspection_failed",
        "nss_igs_mapping_verification_failed",
        "nss_igs_mapping_missing",
        "nss_igs_mapping_stale",
        "nss_igs_filter_owned_by_external_service",
        "nss_igs_filter_inspection_failed",
        "nss_igs_filter_verification_failed",
        "lanspeed_nss_control_unavailable",
        "nss_igs_stage_missing",
        "nss_igs_stage_inspection_failed",
        "nss_igs_stage_failed",
        "nss_igs_publish_failed",
        "nss_igs_unpublish_failed",
        "nss_igs_unstage_failed",
    ]
    .into_iter()
    .filter(|code| error.contains(code))
    .max_by_key(|code| code.len())
    .unwrap_or("control_apply_failed")
    .to_owned()
}

#[cfg(feature = "nss-platform")]
fn safe_control_diagnostic_code(code: &str) -> Option<&str> {
    let code = safe_control_reason(code)?;
    Some(code)
}

#[cfg(feature = "nss-platform")]
fn safe_control_reason(code: &str) -> Option<&str> {
    (!code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    .then_some(code)
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
    if rate > platform::max_rate_bps() {
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
    if rate > platform::HARD_MAX_RATE_BPS {
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

#[cfg(not(feature = "nss-platform"))]
fn valid_control_interface(value: &str) -> Option<String> {
    (valid_interface_name(value)
        && !crate::identity::filter::ifname_is_excluded_identity_source(value))
    .then(|| value.to_owned())
}

fn control_requires_address(upload_bps: u64, download_bps: u64, internet_disabled: bool) -> bool {
    internet_disabled
        || (platform::REQUIRES_SHAPING_ADDRESS && (upload_bps != 0 || download_bps != 0))
}

#[cfg(not(feature = "nss-platform"))]
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

#[cfg(feature = "nss-platform")]
fn resolve_lan_device(config: &RuntimeConfig) -> String {
    // NSS control never guesses a conventional LAN name. Active rules use a
    // trusted Access Edge attachment; this value only seeds prefix discovery
    // before the first live client snapshot arrives.
    config
        .runtime_collect_ifnames()
        .into_iter()
        .find(|device| valid_interface_name(device))
        .unwrap_or_default()
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

#[cfg(not(feature = "nss-platform"))]
fn local_prefixes(control_devices: &BTreeSet<String>) -> Result<Vec<(IpAddr, u8)>, String> {
    let output = Command::new("ubus")
        .args(["call", "network.interface.lan", "status"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("lan_status_unavailable".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| "lan_status_invalid")?;
    let mut prefixes = Vec::new();
    append_netifd_prefixes(&mut prefixes, &value);
    finish_local_prefixes(prefixes, control_devices)
}

#[cfg(feature = "nss-platform")]
fn local_prefixes(control_devices: &BTreeSet<String>) -> Result<Vec<(IpAddr, u8)>, String> {
    let output = Command::new("ubus")
        .args(["call", "network.interface", "dump"])
        .output()
        .map_err(|_| "lan_status_unavailable".to_owned())?;
    if !output.status.success() {
        return Err("lan_status_unavailable".into());
    }
    let value: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "lan_status_invalid".to_owned())?;
    let prefix_devices = nss_prefix_devices(control_devices);
    let mut prefixes = Vec::new();
    let mut matched = false;
    for interface in value
        .get("interface")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let controlled = ["device", "l3_device"].into_iter().any(|key| {
            interface
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|device| prefix_devices.contains(device))
        });
        if controlled {
            append_netifd_prefixes(&mut prefixes, interface);
            matched = true;
        }
    }
    if !matched {
        return Err("local_network_unavailable".into());
    }
    append_nss_private_prefixes(&mut prefixes);
    finish_local_prefixes(prefixes, control_devices)
}

#[cfg(feature = "nss-platform")]
fn nss_prefix_devices(control_devices: &BTreeSet<String>) -> BTreeSet<String> {
    let mut devices = control_devices.clone();
    for device in control_devices {
        let Some(master) = fs::read_link(format!("/sys/class/net/{device}/master"))
            .ok()
            .and_then(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .filter(|master| valid_interface_name(master))
        else {
            continue;
        };
        devices.insert(master);
    }
    devices
}

#[cfg(feature = "nss-platform")]
fn append_nss_private_prefixes(prefixes: &mut Vec<(IpAddr, u8)>) {
    // A private upstream subnet is still LAN/NAS, even when netifd exposes it
    // through an Internet-zone interface. The nft rule requires both ends to
    // be local, so these prefixes do not bypass control for public traffic.
    prefixes.extend([
        ("10.0.0.0".parse().unwrap(), 8),
        ("172.16.0.0".parse().unwrap(), 12),
        ("192.168.0.0".parse().unwrap(), 16),
        ("fc00::".parse().unwrap(), 7),
    ]);
}

fn append_netifd_prefixes(prefixes: &mut Vec<(IpAddr, u8)>, value: &Value) {
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
}

fn finish_local_prefixes(
    mut prefixes: Vec<(IpAddr, u8)>,
    control_devices: &BTreeSet<String>,
) -> Result<Vec<(IpAddr, u8)>, String> {
    prefixes.push(("127.0.0.0".parse().unwrap(), 8));
    prefixes.push(("169.254.0.0".parse().unwrap(), 16));
    // Link-local multicast (ARP is non-IP and is excluded by the x86
    // classifiers themselves). Keep IPv4/IPv6 discovery, router
    // advertisements, mDNS and other LAN multicast out of client shaping.
    prefixes.push(("224.0.0.0".parse().unwrap(), 4));
    prefixes.push(("255.255.255.255".parse().unwrap(), 32));
    prefixes.push(("::1".parse().unwrap(), 128));
    prefixes.push(("fe80::".parse().unwrap(), 10));
    prefixes.push(("ff00::".parse().unwrap(), 8));
    let output = Command::new("ip")
        .args(["-j", "address", "show"])
        .output()
        .map_err(|_| "interface_status_unavailable".to_owned())?;
    if !output.status.success() {
        return Err("interface_status_unavailable".into());
    }
    let interfaces = serde_json::from_slice::<Vec<Value>>(&output.stdout)
        .map_err(|_| "interface_status_unavailable".to_owned())?;
    append_interface_prefixes(&mut prefixes, &interfaces, control_devices);
    Ok(collapse_prefixes(prefixes))
}

fn append_interface_prefixes(
    prefixes: &mut Vec<(IpAddr, u8)>,
    interfaces: &[Value],
    control_devices: &BTreeSet<String>,
) {
    for interface in interfaces {
        let controlled = interface
            .get("ifname")
            .and_then(Value::as_str)
            .is_some_and(|name| control_devices.contains(name));
        for address in interface
            .get("addr_info")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(ip) = address
                .get("local")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<IpAddr>().ok())
            else {
                continue;
            };
            let max = if ip.is_ipv4() { 32u64 } else { 128u64 };
            // Every router address itself is local. For an observed LAN edge,
            // the complete connected prefix is local too, so guest/VLAN NAS
            // traffic never enters Internet shaping or blocking.
            prefixes.push((ip, max as u8));
            if controlled {
                let prefix_len = address
                    .get("prefixlen")
                    .and_then(Value::as_u64)
                    .unwrap_or(max)
                    .min(max) as u8;
                prefixes.push((ip, prefix_len));
            }
        }
    }
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

#[cfg(test)]
#[path = "control/tests.rs"]
mod tests;
