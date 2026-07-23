use std::{ffi::CString, fmt, fs, io, os::fd::OwnedFd, path::Path};

use aya::{
    maps::HashMap,
    programs::{
        links::Link,
        tc::{
            self, NlOptions, SchedClassifierLink, SchedClassifierLinkId, TcAttachOptions, TcHandle,
        },
        SchedClassifier, TcAttachType, TcError,
    },
    Ebpf, EbpfLoader, Pod,
};

use lanspeed_common::{
    LanspeedCounters, LanspeedKey, CLIENTS_MAP_NAME, EGRESS_EARLY_PROGRAM_NAME,
    EGRESS_PROGRAM_NAME, INGRESS_EARLY_PROGRAM_NAME, INGRESS_PROGRAM_NAME, MAX_CLIENTS,
};

use crate::{
    identity::IdentityTable,
    is_known_kfunc_metadata_incompatibility, patch_conntrack_kfunc_calls,
    probe::{
        commands::{run_read_only, ReadOnlyCommand, DEFAULT_TIMEOUT},
        tc as tc_probe,
    },
    KfuncPatchError,
};

pub const PRIMARY_OBJECT_PATH: &str = "/usr/lib/bpf/lanspeed-ebpf-kfunc";
pub const FALLBACK_OBJECT_PATH: &str = "/usr/lib/bpf/lanspeed-ebpf-fallback";

use super::snapshot::{BpfSnapshot, BpfSnapshotCollector, ConnectionOverlay, MapRead};
use super::tc_monitor::TcTopologyMonitor;

pub const NORMAL_PRIORITY: u16 = 49_152;
pub const NORMAL_HANDLE: u16 = 0x1eed;
pub const EARLY_PRIORITY: u16 = 1;
pub const EARLY_HANDLE: u16 = 0x1eee;
pub const HOOK_AUDIT_INTERVAL_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectFlavor {
    PrimaryKfunc,
    BytePacketFallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterErrorKind {
    ObjectMissing,
    KfuncIncompatible,
    LoadFailed,
    OwnershipConflict,
    AttachFailed,
    DetachFailed,
    MapReadFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterError {
    kind: AdapterErrorKind,
    message: String,
}

impl AdapterError {
    pub fn new(kind: AdapterErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub const fn kind(&self) -> AdapterErrorKind {
        self.kind
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AdapterError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachMode {
    Normal,
    EarlyPassthrough,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LinkDirection {
    Ingress,
    Egress,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct LinkSpec {
    pub interface: String,
    pub direction: LinkDirection,
    pub program: &'static str,
    pub priority: u16,
    pub handle: u16,
}

impl LinkSpec {
    pub fn pair(interface: &str, mode: AttachMode) -> [Self; 2] {
        let (ingress, egress, priority, handle) = match mode {
            AttachMode::Normal => (
                INGRESS_PROGRAM_NAME,
                EGRESS_PROGRAM_NAME,
                NORMAL_PRIORITY,
                NORMAL_HANDLE,
            ),
            AttachMode::EarlyPassthrough => (
                INGRESS_EARLY_PROGRAM_NAME,
                EGRESS_EARLY_PROGRAM_NAME,
                EARLY_PRIORITY,
                EARLY_HANDLE,
            ),
        };
        [
            Self {
                interface: interface.to_owned(),
                direction: LinkDirection::Ingress,
                program: ingress,
                priority,
                handle,
            },
            Self {
                interface: interface.to_owned(),
                direction: LinkDirection::Egress,
                program: egress,
                priority,
                handle,
            },
        ]
    }

    pub fn kernel_program_name(&self) -> &str {
        &self.program[..self.program.len().min(15)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookState {
    Absent,
    Owned,
    Foreign,
}

pub trait AyaAdapter {
    type Link;

    fn load_object(&mut self, path: &Path, flavor: ObjectFlavor) -> Result<(), AdapterError>;
    fn ensure_clsact(&mut self, interface: &str) -> Result<(), AdapterError>;
    fn inspect_hook(&mut self, spec: &LinkSpec) -> Result<HookState, AdapterError>;
    /// Report whether TC topology may have changed since the previous call.
    ///
    /// The conservative default preserves correctness for adapters without an
    /// event source: they continue to run the exact hook audit every cycle.
    fn tc_topology_changed(&mut self, _specs: &[LinkSpec]) -> bool {
        true
    }
    fn attach_netlink(&mut self, spec: &LinkSpec) -> Result<Self::Link, AdapterError>;
    fn replace_owned_netlink_atomic(&mut self, spec: &LinkSpec)
        -> Result<Self::Link, AdapterError>;
    fn detach_link(&mut self, spec: &LinkSpec, link: Self::Link) -> Result<(), AdapterError>;
    fn detach_exact(&mut self, spec: &LinkSpec) -> Result<(), AdapterError>;
    fn forget_link(&mut self, spec: &LinkSpec, link: Self::Link) -> Result<(), AdapterError>;
    fn abandon_link(&mut self, spec: &LinkSpec, link: Self::Link) -> Result<(), AdapterError>;
    fn read_clients(&mut self) -> Result<MapRead, AdapterError>;
    fn interface_name(&mut self, ifindex: u32) -> Option<String>;
    fn unload(&mut self);
}

#[derive(Debug)]
struct OwnedLink<L> {
    spec: LinkSpec,
    link: L,
}

#[derive(Debug)]
pub struct BpfReconfigureTxn {
    desired_specs: Vec<LinkSpec>,
    desired_mode: AttachMode,
    added_specs: Vec<LinkSpec>,
    topology_changed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconfigureRateBaseline {
    ResetOnNextCollection,
    Prepared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconfigureStrategy {
    InPlace,
    SuspendThenAttach,
}

impl BpfReconfigureTxn {
    pub const fn topology_changed(&self) -> bool {
        self.topology_changed
    }
}

#[derive(Debug)]
pub struct BpfPostCommitCleanup<L> {
    obsolete: Vec<OwnedLink<L>>,
}

pub struct BpfSuspendedTopology {
    retained_interfaces: Vec<String>,
    mode: AttachMode,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BpfHealth {
    pub object_loaded: bool,
    pub all_expected_hooks_attached: bool,
    pub expected_hook_count: usize,
    pub attached_hook_count: usize,
    pub map_read_attempted: bool,
    pub map_read_ok: bool,
    pub fresh_snapshot: bool,
    pub last_complete_snapshot_ms: Option<u64>,
    pub snapshot_clients: usize,
    pub mode: Option<AttachMode>,
}

#[derive(Debug)]
pub struct BpfRuntime<L> {
    object_loaded: bool,
    primary_kfunc_incompatibility: Option<String>,
    links: Vec<OwnedLink<L>>,
    expected_specs: Vec<LinkSpec>,
    unresolved_specs: Vec<LinkSpec>,
    reconcile_required: bool,
    next_hook_audit_ms: u64,
    current_mode: Option<AttachMode>,
    recovery_mode: Option<AttachMode>,
    recovery_specs: Option<Vec<LinkSpec>>,
    rate_reset_required: bool,
    map_read_attempted: bool,
    last_map_read_ok: bool,
    last_complete_snapshot_ms: Option<u64>,
    snapshot_clients: usize,
    map_iteration_truncated_observed: bool,
    self_heal_recoveries: u64,
    self_heal_failures: u64,
    last_self_heal_reason: Option<String>,
    last_self_heal_failure: Option<String>,
    last_runtime_error: Option<String>,
}

#[derive(Clone)]
pub struct BpfCollectionCheckpoint {
    rate_reset_required: bool,
    map_read_attempted: bool,
    last_map_read_ok: bool,
    last_complete_snapshot_ms: Option<u64>,
    snapshot_clients: usize,
    map_iteration_truncated_observed: bool,
    last_runtime_error: Option<String>,
    next_hook_audit_ms: u64,
    collector: BpfSnapshotCollector,
}

impl<L> BpfRuntime<L> {
    pub fn collection_checkpoint(
        &self,
        collector: &BpfSnapshotCollector,
    ) -> BpfCollectionCheckpoint {
        BpfCollectionCheckpoint {
            rate_reset_required: self.rate_reset_required,
            map_read_attempted: self.map_read_attempted,
            last_map_read_ok: self.last_map_read_ok,
            last_complete_snapshot_ms: self.last_complete_snapshot_ms,
            snapshot_clients: self.snapshot_clients,
            map_iteration_truncated_observed: self.map_iteration_truncated_observed,
            last_runtime_error: self.last_runtime_error.clone(),
            next_hook_audit_ms: self.next_hook_audit_ms,
            collector: collector.clone(),
        }
    }

    pub fn restore_collection_checkpoint(
        &mut self,
        collector: &mut BpfSnapshotCollector,
        checkpoint: BpfCollectionCheckpoint,
    ) {
        self.rate_reset_required = checkpoint.rate_reset_required;
        self.map_read_attempted = checkpoint.map_read_attempted;
        self.last_map_read_ok = checkpoint.last_map_read_ok;
        self.last_complete_snapshot_ms = checkpoint.last_complete_snapshot_ms;
        self.snapshot_clients = checkpoint.snapshot_clients;
        self.map_iteration_truncated_observed = checkpoint.map_iteration_truncated_observed;
        self.last_runtime_error = checkpoint.last_runtime_error;
        self.next_hook_audit_ms = checkpoint.next_hook_audit_ms;
        *collector = checkpoint.collector;
    }

    pub fn load<A: AyaAdapter<Link = L>>(
        adapter: &mut A,
        primary_path: impl AsRef<Path>,
        fallback_path: impl AsRef<Path>,
    ) -> Result<Self, AdapterError> {
        let primary_error = match adapter
            .load_object(primary_path.as_ref(), ObjectFlavor::PrimaryKfunc)
        {
            Ok(()) => None,
            Err(error) if error.kind() == AdapterErrorKind::KfuncIncompatible => {
                let message = error.to_string();
                adapter.load_object(fallback_path.as_ref(), ObjectFlavor::BytePacketFallback)?;
                Some(message)
            }
            Err(error) => return Err(error),
        };
        Ok(Self::new_loaded(primary_error))
    }

    /// Load the byte-accounting object directly.
    ///
    /// Production connection totals come from the conntrack snapshot overlay,
    /// so the kfunc object's per-packet approximate connection bookkeeping is
    /// unnecessary on the hot forwarding path. Keep [`Self::load`] for explicit
    /// kfunc compatibility checks, while normal sampling uses this lower-cost
    /// object.
    pub fn load_byte_only<A: AyaAdapter<Link = L>>(
        adapter: &mut A,
        path: impl AsRef<Path>,
    ) -> Result<Self, AdapterError> {
        adapter.load_object(path.as_ref(), ObjectFlavor::BytePacketFallback)?;
        Ok(Self::new_loaded(None))
    }

    fn new_loaded(primary_kfunc_incompatibility: Option<String>) -> Self {
        Self {
            object_loaded: true,
            primary_kfunc_incompatibility,
            links: Vec::new(),
            expected_specs: Vec::new(),
            unresolved_specs: Vec::new(),
            reconcile_required: false,
            next_hook_audit_ms: 0,
            current_mode: None,
            recovery_mode: None,
            recovery_specs: None,
            rate_reset_required: false,
            map_read_attempted: false,
            last_map_read_ok: false,
            last_complete_snapshot_ms: None,
            snapshot_clients: 0,
            map_iteration_truncated_observed: false,
            self_heal_recoveries: 0,
            self_heal_failures: 0,
            last_self_heal_reason: None,
            last_self_heal_failure: None,
            last_runtime_error: None,
        }
    }

    pub fn loaded_for_test() -> Self {
        Self::new_loaded(None)
    }

    pub fn primary_kfunc_incompatibility(&self) -> Option<&str> {
        self.primary_kfunc_incompatibility.as_deref()
    }

    pub const fn attach_mode(&self) -> Option<AttachMode> {
        self.current_mode
    }

    pub fn reconfigure_strategy(&self, desired_mode: AttachMode) -> ReconfigureStrategy {
        if self.current_mode == Some(desired_mode) {
            ReconfigureStrategy::InPlace
        } else {
            ReconfigureStrategy::SuspendThenAttach
        }
    }

    pub fn suspend_for_replacement<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
    ) -> Result<BpfSuspendedTopology, AdapterError> {
        if !self.is_attached() {
            return Err(AdapterError::new(
                AdapterErrorKind::DetachFailed,
                "BPF topology is not healthy enough to suspend",
            ));
        }
        let desired_specs = self.expected_specs.clone();
        let mut retained_interfaces = desired_specs
            .iter()
            .map(|spec| spec.interface.clone())
            .collect::<Vec<_>>();
        retained_interfaces.dedup();
        let mode = self.current_mode.expect("is_attached requires a mode");
        let tracked_specs = self
            .links
            .iter()
            .map(|owned| owned.spec.clone())
            .collect::<Vec<_>>();
        for spec in tracked_specs {
            match adapter.inspect_hook(&spec) {
                Ok(HookState::Owned) => {}
                Ok(HookState::Absent | HookState::Foreign) => {
                    let error = AdapterError::new(
                        AdapterErrorKind::OwnershipConflict,
                        format!(
                            "owned filter changed before suspend {} {:?}",
                            spec.interface, spec.direction
                        ),
                    );
                    self.require_reconciliation();
                    self.last_runtime_error = Some(error.to_string());
                    return Err(error);
                }
                Err(error) => {
                    self.require_reconciliation();
                    self.last_runtime_error = Some(error.to_string());
                    return Err(error);
                }
            }
        }

        let mut tracked = core::mem::take(&mut self.links).into_iter();
        while let Some(owned) = tracked.next() {
            if let Err(error) = adapter.detach_link(&owned.spec, owned.link) {
                push_unique_spec(&mut self.unresolved_specs, owned.spec);
                self.links.extend(tracked);
                self.reconcile_required = true;
                self.recovery_specs = Some(desired_specs);
                self.recovery_mode = Some(mode);
                self.last_runtime_error = Some(error.to_string());
                return Err(error);
            }
        }
        self.expected_specs.clear();
        self.current_mode = None;
        self.last_runtime_error = None;
        Ok(BpfSuspendedTopology {
            retained_interfaces,
            mode,
        })
    }

    pub fn resume_suspended<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        suspended: BpfSuspendedTopology,
    ) -> Result<(), AdapterError> {
        let interfaces = suspended.retained_interfaces.clone();
        self.attach_suspended(adapter, &suspended, &interfaces, suspended.mode)
    }

    pub fn attach_suspended<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        suspended: &BpfSuspendedTopology,
        interfaces: &[String],
        mode: AttachMode,
    ) -> Result<(), AdapterError> {
        if !self.object_loaded
            || !self.links.is_empty()
            || !self.expected_specs.is_empty()
            || self.reconcile_required
            || !self.unresolved_specs.is_empty()
        {
            return Err(AdapterError::new(
                AdapterErrorKind::AttachFailed,
                "BPF runtime is not in a suspended state",
            ));
        }
        let desired_interfaces = interfaces.iter().fold(Vec::new(), |mut unique, interface| {
            if !unique.contains(interface) {
                unique.push(interface.clone());
            }
            unique
        });
        let mut attached = Vec::new();
        for interface in &desired_interfaces {
            if !suspended.retained_interfaces.contains(interface) {
                if let Err(error) = adapter.ensure_clsact(interface) {
                    return Err(self.abort_prepared_specs(adapter, attached, error));
                }
            }
        }
        let desired_specs = desired_interfaces
            .iter()
            .flat_map(|interface| LinkSpec::pair(interface, mode))
            .collect::<Vec<_>>();
        for spec in &desired_specs {
            let state = match adapter.inspect_hook(spec) {
                Ok(state) => state,
                Err(error) => return Err(self.abort_prepared_specs(adapter, attached, error)),
            };
            match state {
                HookState::Absent => {}
                HookState::Owned | HookState::Foreign => {
                    let error = AdapterError::new(
                        AdapterErrorKind::OwnershipConflict,
                        format!(
                            "cannot attach suspended topology over occupied filter {} {:?}",
                            spec.interface, spec.direction
                        ),
                    );
                    return Err(self.abort_prepared_specs(adapter, attached, error));
                }
            }

            match adapter.attach_netlink(spec) {
                Ok(link) => {
                    self.links.push(OwnedLink {
                        spec: spec.clone(),
                        link,
                    });
                    attached.push(spec.clone());
                }
                Err(error) => return Err(self.abort_prepared_specs(adapter, attached, error)),
            }
        }
        self.expected_specs = desired_specs;
        self.current_mode = Some(mode);
        self.rate_reset_required = true;
        self.last_runtime_error = None;
        Ok(())
    }

    pub fn is_attached(&self) -> bool {
        !self.reconcile_required
            && !self.expected_specs.is_empty()
            && self
                .expected_specs
                .iter()
                .all(|expected| self.links.iter().any(|owned| owned.spec == *expected))
    }

    fn require_reconciliation(&mut self) {
        if self.expected_specs.is_empty() || self.current_mode.is_none() {
            return;
        }
        self.reconcile_required = true;
        self.recovery_specs = Some(self.expected_specs.clone());
        self.recovery_mode = self.current_mode;
    }

    pub fn attach_interface<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        interface: &str,
        mode: AttachMode,
    ) -> Result<(), AdapterError> {
        let previous_specs = self.expected_specs.clone();
        let previous_mode = self.current_mode;
        adapter.ensure_clsact(interface)?;
        let specs = LinkSpec::pair(interface, mode);
        let states = specs
            .iter()
            .map(|spec| adapter.inspect_hook(spec))
            .collect::<Result<Vec<_>, _>>()?;
        for (spec, state) in specs.iter().zip(&states) {
            if *state == HookState::Foreign {
                return Err(AdapterError::new(
                    AdapterErrorKind::OwnershipConflict,
                    format!("foreign filter occupies {} {:?}", interface, spec.direction),
                ));
            }
        }
        if specs.iter().zip(&states).all(|(spec, state)| {
            *state == HookState::Owned && self.links.iter().any(|owned| owned.spec == *spec)
        }) {
            return Ok(());
        }
        let start = self.links.len();
        for (spec, state) in specs.into_iter().zip(states) {
            if state == HookState::Owned && self.links.iter().any(|owned| owned.spec == spec) {
                continue;
            }
            let attached = if state == HookState::Owned {
                adapter.replace_owned_netlink_atomic(&spec)
            } else {
                adapter.attach_netlink(&spec)
            };
            match attached {
                Ok(link) => self.links.push(OwnedLink { spec, link }),
                Err(error) => {
                    while self.links.len() > start {
                        let owned = self.links.pop().expect("length checked");
                        if let Err(rollback) = adapter.detach_link(&owned.spec, owned.link) {
                            self.reconcile_required = true;
                            self.recovery_specs = Some(previous_specs.clone());
                            self.recovery_mode = previous_mode;
                            push_unique_spec(&mut self.unresolved_specs, owned.spec);
                            self.last_runtime_error =
                                Some(format!("{error}; rollback detach failed: {rollback}"));
                        }
                    }
                    self.last_runtime_error
                        .get_or_insert_with(|| error.to_string());
                    return Err(error);
                }
            }
        }
        for spec in LinkSpec::pair(interface, mode) {
            if !self.expected_specs.contains(&spec) {
                self.expected_specs.push(spec);
            }
        }
        self.current_mode = Some(mode);
        self.last_runtime_error = None;
        Ok(())
    }

    pub fn attach_interfaces<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        interfaces: &[String],
        mode: AttachMode,
    ) -> Result<(), AdapterError> {
        let start = self.links.len();
        let previous_expected = self.expected_specs.len();
        let previous_mode = self.current_mode;
        for interface in interfaces {
            if let Err(error) = self.attach_interface(adapter, interface, mode) {
                while self.links.len() > start {
                    let owned = self.links.pop().expect("length checked");
                    if let Err(rollback) = adapter.detach_link(&owned.spec, owned.link) {
                        self.reconcile_required = true;
                        self.recovery_specs =
                            Some(self.expected_specs[..previous_expected].to_vec());
                        self.recovery_mode = previous_mode;
                        push_unique_spec(&mut self.unresolved_specs, owned.spec);
                        self.last_runtime_error =
                            Some(format!("{error}; rollback detach failed: {rollback}"));
                    }
                }
                self.expected_specs.truncate(previous_expected);
                self.current_mode = previous_mode;
                return Err(error);
            }
        }
        Ok(())
    }

    pub fn switch_mode<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        interfaces: &[String],
        new_mode: AttachMode,
    ) -> Result<(), AdapterError> {
        let desired = interfaces
            .iter()
            .flat_map(|interface| LinkSpec::pair(interface, new_mode))
            .collect::<Vec<_>>();
        if self.current_mode == Some(new_mode)
            && self.expected_specs.len() == desired.len()
            && self
                .expected_specs
                .iter()
                .all(|spec| desired.contains(spec))
        {
            return Ok(());
        }
        let old_count = self.links.len();
        let old_specs = self.expected_specs.clone();
        let old_mode = self.current_mode;
        if let Err(error) = self.attach_interfaces(adapter, interfaces, new_mode) {
            self.current_mode = old_mode;
            return Err(error);
        }
        let obsolete = (0..old_count)
            .filter(|index| !desired.contains(&self.links[*index].spec))
            .collect::<Vec<_>>();
        let mut old_links = Vec::with_capacity(obsolete.len());
        for index in obsolete.into_iter().rev() {
            old_links.push(self.links.remove(index));
        }
        let mut first_error = None;
        for owned in old_links {
            if let Err(error) = adapter.detach_link(&owned.spec, owned.link) {
                first_error.get_or_insert(error);
                push_unique_spec(&mut self.unresolved_specs, owned.spec.clone());
            } else {
                self.expected_specs.retain(|spec| spec != &owned.spec);
            }
        }
        if let Some(error) = first_error {
            self.reconcile_required = true;
            self.recovery_specs = Some(old_specs.clone());
            self.recovery_mode = old_mode;
            self.expected_specs = old_specs
                .into_iter()
                .chain(self.expected_specs.clone())
                .collect();
            self.current_mode = None;
            self.last_runtime_error = Some(error.to_string());
            Err(error)
        } else {
            self.expected_specs = desired;
            self.current_mode = Some(new_mode);
            self.rate_reset_required = true;
            self.last_runtime_error = None;
            Ok(())
        }
    }

    pub fn prepare_reconfigure<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        interfaces: &[String],
        desired_mode: AttachMode,
    ) -> Result<BpfReconfigureTxn, AdapterError> {
        if self.reconcile_required {
            return Err(AdapterError::new(
                AdapterErrorKind::AttachFailed,
                "BPF hooks require reconciliation before reconfigure",
            ));
        }
        let mut desired_specs = interfaces
            .iter()
            .flat_map(|interface| LinkSpec::pair(interface, desired_mode))
            .collect::<Vec<_>>();
        desired_specs.sort();
        desired_specs.dedup();
        let mut old_specs = self.expected_specs.clone();
        old_specs.sort();
        old_specs.dedup();
        let topology_changed =
            self.current_mode != Some(desired_mode) || old_specs != desired_specs;
        let mut added_specs = Vec::new();

        for interface in interfaces {
            if let Err(error) = adapter.ensure_clsact(interface) {
                return Err(self.abort_prepared_specs(adapter, added_specs, error));
            }
        }
        for spec in &desired_specs {
            let tracked = self.links.iter().any(|owned| owned.spec == *spec);
            let state = match adapter.inspect_hook(spec) {
                Ok(state) => state,
                Err(error) => {
                    return Err(self.abort_prepared_specs(adapter, added_specs, error));
                }
            };
            if tracked {
                match state {
                    HookState::Owned => continue,
                    HookState::Absent => {
                        let error = AdapterError::new(
                            AdapterErrorKind::AttachFailed,
                            format!(
                                "tracked filter is absent before reconfigure {} {:?}",
                                spec.interface, spec.direction
                            ),
                        );
                        return Err(self.abort_prepared_specs(adapter, added_specs, error));
                    }
                    HookState::Foreign => {
                        let error = AdapterError::new(
                            AdapterErrorKind::OwnershipConflict,
                            format!(
                                "foreign filter replaced tracked slot {} {:?}",
                                spec.interface, spec.direction
                            ),
                        );
                        return Err(self.abort_prepared_specs(adapter, added_specs, error));
                    }
                }
            }
            if state != HookState::Absent {
                let error = AdapterError::new(
                    AdapterErrorKind::OwnershipConflict,
                    format!(
                        "cannot transactionally adopt occupied filter {} {:?}",
                        spec.interface, spec.direction
                    ),
                );
                return Err(self.abort_prepared_specs(adapter, added_specs, error));
            }
            match adapter.attach_netlink(spec) {
                Ok(link) => {
                    self.links.push(OwnedLink {
                        spec: spec.clone(),
                        link,
                    });
                    added_specs.push(spec.clone());
                }
                Err(error) => {
                    return Err(self.abort_prepared_specs(adapter, added_specs, error));
                }
            }
        }

        Ok(BpfReconfigureTxn {
            desired_specs,
            desired_mode,
            added_specs,
            topology_changed,
        })
    }

    pub fn abort_reconfigure<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        transaction: BpfReconfigureTxn,
    ) -> Result<(), AdapterError> {
        self.detach_prepared_specs(adapter, transaction.added_specs)
    }

    pub fn commit_reconfigure(
        &mut self,
        transaction: BpfReconfigureTxn,
        rate_baseline: ReconfigureRateBaseline,
    ) -> BpfPostCommitCleanup<L> {
        let mut obsolete = Vec::new();
        let mut index = 0;
        while index < self.links.len() {
            if transaction.desired_specs.contains(&self.links[index].spec) {
                index += 1;
            } else {
                obsolete.push(self.links.remove(index));
            }
        }
        self.expected_specs = transaction.desired_specs;
        self.current_mode = Some(transaction.desired_mode);
        match rate_baseline {
            ReconfigureRateBaseline::ResetOnNextCollection => {
                self.rate_reset_required |= transaction.topology_changed;
            }
            ReconfigureRateBaseline::Prepared => self.rate_reset_required = false,
        }
        self.last_runtime_error = None;
        BpfPostCommitCleanup { obsolete }
    }

    pub fn run_postcommit_cleanup<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        cleanup: BpfPostCommitCleanup<L>,
    ) -> Result<(), AdapterError> {
        let mut first_error = None;
        for owned in cleanup.obsolete {
            let spec = owned.spec;
            if let Err(error) = adapter.detach_link(&spec, owned.link) {
                first_error.get_or_insert(error);
                push_unique_spec(&mut self.unresolved_specs, spec);
            }
        }
        if let Some(error) = first_error {
            self.last_runtime_error = Some(error.to_string());
            Err(error)
        } else {
            self.last_runtime_error = None;
            Ok(())
        }
    }

    fn abort_prepared_specs<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        added_specs: Vec<LinkSpec>,
        primary: AdapterError,
    ) -> AdapterError {
        match self.detach_prepared_specs(adapter, added_specs) {
            Ok(()) => primary,
            Err(cleanup) => {
                let error = AdapterError::new(
                    AdapterErrorKind::DetachFailed,
                    format!("{primary}; prepared hook cleanup failed: {cleanup}"),
                );
                self.last_runtime_error = Some(error.to_string());
                error
            }
        }
    }

    fn detach_prepared_specs<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        added_specs: Vec<LinkSpec>,
    ) -> Result<(), AdapterError> {
        let mut first_error = None;
        for spec in added_specs.into_iter().rev() {
            let Some(index) = self.links.iter().position(|owned| owned.spec == spec) else {
                continue;
            };
            let owned = self.links.remove(index);
            if let Err(error) = adapter.detach_link(&owned.spec, owned.link) {
                first_error.get_or_insert(error);
                push_unique_spec(&mut self.unresolved_specs, owned.spec);
            }
        }
        if let Some(error) = first_error {
            self.reconcile_required = true;
            if !self.expected_specs.is_empty() && self.current_mode.is_some() {
                self.recovery_specs = Some(self.expected_specs.clone());
                self.recovery_mode = self.current_mode;
            }
            self.last_runtime_error = Some(error.to_string());
            Err(error)
        } else {
            Ok(())
        }
    }

    pub fn ensure_attached<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        reason: &str,
    ) -> Result<usize, AdapterError> {
        if self.reconcile_required {
            self.reconcile(adapter)?;
        }
        let mut restored = 0;
        for spec in self.expected_specs.clone() {
            let state = match adapter.inspect_hook(&spec) {
                Ok(state) => state,
                Err(error) => {
                    self.require_reconciliation();
                    self.record_self_heal_failure(reason, &error);
                    return Err(error);
                }
            };
            if state == HookState::Foreign {
                let error = AdapterError::new(
                    AdapterErrorKind::OwnershipConflict,
                    "foreign filter replaced an owned slot",
                );
                self.require_reconciliation();
                self.record_self_heal_failure(reason, &error);
                return Err(error);
            }
            if state == HookState::Absent {
                if let Some(index) = self.links.iter().position(|owned| owned.spec == spec) {
                    let stale = self.links.remove(index);
                    if let Err(error) = adapter.forget_link(&spec, stale.link) {
                        self.record_self_heal_failure(reason, &error);
                        return Err(error);
                    }
                }
                match adapter.attach_netlink(&spec) {
                    Ok(link) => {
                        self.links.push(OwnedLink { spec, link });
                        restored += 1;
                    }
                    Err(error) => {
                        self.record_self_heal_failure(reason, &error);
                        return Err(error);
                    }
                }
            }
        }
        if restored > 0 {
            self.self_heal_recoveries = self.self_heal_recoveries.saturating_add(1);
            self.last_self_heal_reason = Some(reason.to_owned());
            self.last_self_heal_failure = None;
            self.rate_reset_required = true;
            self.last_runtime_error = None;
        }
        Ok(restored)
    }

    fn reconcile<A: AyaAdapter<Link = L>>(&mut self, adapter: &mut A) -> Result<(), AdapterError> {
        let mode = self.recovery_mode.ok_or_else(|| {
            AdapterError::new(
                AdapterErrorKind::AttachFailed,
                "missing mode for reconciliation",
            )
        })?;
        let desired = self.recovery_specs.clone().ok_or_else(|| {
            AdapterError::new(
                AdapterErrorKind::AttachFailed,
                "missing expected hooks for reconciliation",
            )
        })?;
        let mut first_error = None;
        for spec in &desired {
            let live_index = self.links.iter().position(|owned| owned.spec == *spec);
            match adapter.inspect_hook(spec) {
                Ok(HookState::Owned) if live_index.is_some() => {}
                Ok(HookState::Owned) => match adapter.replace_owned_netlink_atomic(spec) {
                    Ok(link) => self.links.push(OwnedLink {
                        spec: spec.clone(),
                        link,
                    }),
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                },
                Ok(HookState::Absent) => {
                    if let Some(index) = live_index {
                        let stale = self.links.remove(index);
                        if let Err(error) = adapter.forget_link(spec, stale.link) {
                            first_error.get_or_insert(error);
                            continue;
                        }
                    }
                    match adapter.attach_netlink(spec) {
                        Ok(link) => self.links.push(OwnedLink {
                            spec: spec.clone(),
                            link,
                        }),
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    }
                }
                Ok(HookState::Foreign) => {
                    first_error.get_or_insert_with(|| {
                        AdapterError::new(
                            AdapterErrorKind::OwnershipConflict,
                            "foreign filter occupies a reconciliation slot",
                        )
                    });
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }

        if let Some(error) = first_error {
            self.last_runtime_error = Some(error.to_string());
            return Err(error);
        }

        let mut index = 0;
        while index < self.links.len() {
            if desired.contains(&self.links[index].spec) {
                index += 1;
                continue;
            }
            let owned = self.links.remove(index);
            if let Err(error) = adapter.detach_link(&owned.spec, owned.link) {
                first_error.get_or_insert(error);
                push_unique_spec(&mut self.unresolved_specs, owned.spec);
            }
        }
        let unresolved = core::mem::take(&mut self.unresolved_specs);
        for spec in unresolved {
            if desired.contains(&spec) {
                continue;
            }
            match adapter.inspect_hook(&spec) {
                Ok(HookState::Absent) => {}
                Ok(HookState::Owned) => {
                    if let Err(error) = adapter.detach_exact(&spec) {
                        first_error.get_or_insert(error);
                        push_unique_spec(&mut self.unresolved_specs, spec);
                    }
                }
                Ok(HookState::Foreign) => {
                    let error = AdapterError::new(
                        AdapterErrorKind::OwnershipConflict,
                        "foreign filter occupies a reconciliation slot",
                    );
                    first_error.get_or_insert(error);
                    push_unique_spec(&mut self.unresolved_specs, spec);
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                    push_unique_spec(&mut self.unresolved_specs, spec);
                }
            }
        }
        if let Some(error) = first_error {
            self.last_runtime_error = Some(error.to_string());
            return Err(error);
        }
        self.expected_specs = desired;
        self.reconcile_required = false;
        self.current_mode = Some(mode);
        self.recovery_mode = None;
        self.recovery_specs = None;
        self.unresolved_specs.clear();
        self.rate_reset_required = true;
        self.last_runtime_error = None;
        Ok(())
    }

    fn record_self_heal_failure(&mut self, reason: &str, error: &AdapterError) {
        self.self_heal_failures = self.self_heal_failures.saturating_add(1);
        self.last_self_heal_reason = Some(reason.to_owned());
        self.last_self_heal_failure = Some(error.to_string());
        self.last_runtime_error = Some(error.to_string());
    }

    pub fn collect_snapshot_self_healing<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        collector: &mut BpfSnapshotCollector,
        identities: &IdentityTable,
        connections: &ConnectionOverlay,
        now_ms: u64,
        reason: &str,
    ) -> Result<BpfSnapshot, AdapterError> {
        let topology_changed = adapter.tc_topology_changed(&self.expected_specs);
        if self.reconcile_required || topology_changed || now_ms >= self.next_hook_audit_ms {
            if let Err(error) = self.ensure_attached(adapter, reason) {
                self.last_map_read_ok = false;
                return Err(error);
            }
            self.next_hook_audit_ms = now_ms.saturating_add(HOOK_AUDIT_INTERVAL_MS);
        }
        self.collect_snapshot(adapter, collector, identities, connections, now_ms)
    }

    pub fn collect_snapshot<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
        collector: &mut BpfSnapshotCollector,
        identities: &IdentityTable,
        connections: &ConnectionOverlay,
        now_ms: u64,
    ) -> Result<BpfSnapshot, AdapterError> {
        if self.reconcile_required {
            let error = AdapterError::new(
                AdapterErrorKind::AttachFailed,
                "BPF hooks require reconciliation before collecting",
            );
            self.last_runtime_error = Some(error.to_string());
            return Err(error);
        }
        self.map_read_attempted = true;
        let read = match adapter.read_clients() {
            Ok(read) => read,
            Err(error) => {
                self.last_map_read_ok = false;
                self.last_runtime_error = Some(error.to_string());
                return Err(error);
            }
        };
        self.map_iteration_truncated_observed |=
            read.truncated || read.entries.len() >= MAX_CLIENTS as usize;
        let sticky = self.map_iteration_truncated_observed;
        if self.rate_reset_required {
            collector.reset_rates();
            self.rate_reset_required = false;
        }
        let snapshot = collector.convert(
            read,
            |ifindex| adapter.interface_name(ifindex),
            identities,
            connections,
            now_ms,
            sticky,
        );
        self.last_map_read_ok = true;
        self.last_complete_snapshot_ms = Some(snapshot.sample_ms);
        self.snapshot_clients = snapshot.clients.len();
        self.last_runtime_error = None;
        Ok(snapshot)
    }

    pub fn health(&self, now_ms: u64, freshness_ms: u64) -> BpfHealth {
        let fresh_snapshot = self.last_complete_snapshot_ms.is_some_and(|sample_ms| {
            sample_ms <= now_ms && (freshness_ms == 0 || now_ms - sample_ms <= freshness_ms)
        });
        BpfHealth {
            object_loaded: self.object_loaded,
            all_expected_hooks_attached: self.is_attached(),
            expected_hook_count: self.expected_specs.len(),
            attached_hook_count: self
                .expected_specs
                .iter()
                .filter(|expected| self.links.iter().any(|owned| owned.spec == **expected))
                .count(),
            map_read_attempted: self.map_read_attempted,
            map_read_ok: self.last_map_read_ok && fresh_snapshot,
            fresh_snapshot,
            last_complete_snapshot_ms: self.last_complete_snapshot_ms,
            snapshot_clients: self.snapshot_clients,
            mode: if self.reconcile_required {
                None
            } else {
                self.current_mode
            },
        }
    }

    pub fn runtime_health(&self, now_ms: u64, freshness_ms: u64) -> crate::probe::RuntimeHealth {
        let health = self.health(now_ms, freshness_ms);
        crate::probe::RuntimeHealth {
            bpf_object_loaded: health.object_loaded,
            bpf_attached: health.all_expected_hooks_attached,
            bpf_expected_hook_count: health.expected_hook_count,
            bpf_attached_hook_count: health.attached_hook_count,
            bpf_map_read_attempted: health.map_read_attempted,
            bpf_map_read_ok: health.map_read_ok,
            bpf_last_complete_snapshot_ms: health.last_complete_snapshot_ms,
            bpf_freshness_ms: freshness_ms,
            now_ms,
            bpf_snapshot_clients: health.snapshot_clients,
            bpf_self_heal_recoveries: self.self_heal_recoveries,
            bpf_self_heal_failures: self.self_heal_failures,
            bpf_self_heal_last_reason: self.last_self_heal_reason.clone(),
            bpf_self_heal_last_failure: self.last_self_heal_failure.clone(),
            dae_early_bpf: health.mode == Some(AttachMode::EarlyPassthrough),
            runtime_error: self.last_runtime_error.clone(),
            ..crate::probe::RuntimeHealth::default()
        }
    }

    pub const fn map_iteration_truncated_observed(&self) -> bool {
        self.map_iteration_truncated_observed
    }

    pub const fn self_heal_recoveries(&self) -> u64 {
        self.self_heal_recoveries
    }

    pub const fn self_heal_failures(&self) -> u64 {
        self.self_heal_failures
    }

    pub fn last_self_heal_reason(&self) -> Option<&str> {
        self.last_self_heal_reason.as_deref()
    }

    pub fn last_self_heal_failure(&self) -> Option<&str> {
        self.last_self_heal_failure.as_deref()
    }

    pub fn shutdown<A: AyaAdapter<Link = L>>(
        &mut self,
        adapter: &mut A,
    ) -> Result<(), AdapterError> {
        let mut first_error = None;
        let pending = core::mem::take(&mut self.unresolved_specs);
        for spec in pending {
            match adapter.inspect_hook(&spec) {
                Ok(HookState::Absent) => {}
                Ok(HookState::Foreign) => {
                    self.last_runtime_error = Some(format!(
                        "foreign filter replaced owned shutdown slot {} {:?}",
                        spec.interface, spec.direction
                    ));
                }
                Ok(HookState::Owned) => {
                    if let Err(error) = adapter.detach_exact(&spec) {
                        first_error.get_or_insert(error);
                        push_unique_spec(&mut self.unresolved_specs, spec);
                    }
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                    push_unique_spec(&mut self.unresolved_specs, spec);
                }
            }
        }

        let tracked = core::mem::take(&mut self.links);
        for owned in tracked {
            match adapter.inspect_hook(&owned.spec) {
                Ok(HookState::Foreign) => {
                    let spec = owned.spec;
                    match adapter.abandon_link(&spec, owned.link) {
                        Ok(()) => {
                            self.last_runtime_error = Some(format!(
                                "foreign filter replaced owned shutdown slot {} {:?}",
                                spec.interface, spec.direction
                            ));
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                            push_unique_spec(&mut self.unresolved_specs, spec);
                        }
                    }
                }
                Ok(HookState::Absent) => {
                    let spec = owned.spec;
                    if let Err(error) = adapter.forget_link(&spec, owned.link) {
                        first_error.get_or_insert(error);
                        push_unique_spec(&mut self.unresolved_specs, spec);
                    }
                }
                Ok(HookState::Owned) => {
                    let spec = owned.spec;
                    if let Err(error) = adapter.detach_link(&spec, owned.link) {
                        first_error.get_or_insert(error);
                        push_unique_spec(&mut self.unresolved_specs, spec);
                    }
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                    self.links.push(owned);
                }
            }
        }

        if let Some(error) = first_error {
            self.last_runtime_error = Some(error.to_string());
            return Err(error);
        }
        self.expected_specs.clear();
        self.reconcile_required = false;
        self.current_mode = None;
        self.recovery_mode = None;
        self.recovery_specs = None;
        self.object_loaded = false;
        adapter.unload();
        Ok(())
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct ClientKey(LanspeedKey);

#[derive(Clone, Copy)]
#[repr(transparent)]
struct ClientValue(LanspeedCounters);

unsafe impl Pod for ClientKey {}
unsafe impl Pod for ClientValue {}

#[derive(Debug)]
pub struct SystemAyaLink {
    program: &'static str,
    id: SchedClassifierLinkId,
}

pub struct SystemAyaAdapter {
    ebpf: Option<Ebpf>,
    tc_monitor: TcTopologyMonitor,
}

impl Default for SystemAyaAdapter {
    fn default() -> Self {
        Self {
            ebpf: None,
            tc_monitor: TcTopologyMonitor::new(),
        }
    }
}

impl SystemAyaAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    fn classifier(&mut self, name: &str) -> Result<&mut SchedClassifier, AdapterError> {
        self.ebpf
            .as_mut()
            .and_then(|ebpf| ebpf.program_mut(name))
            .ok_or_else(|| {
                AdapterError::new(AdapterErrorKind::LoadFailed, format!("{name} missing"))
            })?
            .try_into()
            .map_err(|error: aya::programs::ProgramError| {
                AdapterError::new(AdapterErrorKind::LoadFailed, error.to_string())
            })
    }

    fn load_program_object(
        &mut self,
        bytes: &[u8],
        module_btf_fds: Vec<OwnedFd>,
    ) -> Result<(), AdapterError> {
        let mut loader = EbpfLoader::new();
        loader.kfunc_btf_fds(module_btf_fds);
        let mut ebpf = loader.load(bytes).map_err(classify_aya_load_error)?;
        for name in [
            INGRESS_PROGRAM_NAME,
            EGRESS_PROGRAM_NAME,
            INGRESS_EARLY_PROGRAM_NAME,
            EGRESS_EARLY_PROGRAM_NAME,
        ] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(name)
                .ok_or_else(|| {
                    AdapterError::new(AdapterErrorKind::LoadFailed, format!("{name} missing"))
                })?
                .try_into()
                .map_err(|error: aya::programs::ProgramError| {
                    AdapterError::new(AdapterErrorKind::LoadFailed, error.to_string())
                })?;
            program.load().map_err(classify_program_load_error)?;
        }
        self.ebpf = Some(ebpf);
        Ok(())
    }
}

impl AyaAdapter for SystemAyaAdapter {
    type Link = SystemAyaLink;

    fn load_object(&mut self, path: &Path, flavor: ObjectFlavor) -> Result<(), AdapterError> {
        let mut bytes = fs::read(path).map_err(|error| {
            AdapterError::new(
                if error.kind() == io::ErrorKind::NotFound {
                    AdapterErrorKind::ObjectMissing
                } else {
                    AdapterErrorKind::LoadFailed
                },
                format!("failed to read {}: {error}", path.display()),
            )
        })?;
        let module_btf_fds = if flavor == ObjectFlavor::PrimaryKfunc {
            patch_conntrack_kfunc_calls(&mut bytes).map_err(classify_kfunc_patch_error)?
        } else {
            Vec::new()
        };
        self.load_program_object(&bytes, module_btf_fds)
    }

    fn ensure_clsact(&mut self, interface: &str) -> Result<(), AdapterError> {
        let clsact_present = || -> Result<bool, AdapterError> {
            let output = run_read_only(
                ReadOnlyCommand::TcQdiscShow,
                &["dev", interface],
                DEFAULT_TIMEOUT,
                ReadOnlyCommand::TcQdiscShow.output_cap(),
            )
            .map_err(|error| {
                AdapterError::new(
                    AdapterErrorKind::AttachFailed,
                    format!("tc qdisc inspection failed: {error}"),
                )
            })?;
            if output.exit_code != Some(0) || output.timed_out {
                return Err(AdapterError::new(
                    AdapterErrorKind::AttachFailed,
                    format!("tc qdisc inspection failed: {}", output.stderr.trim()),
                ));
            }
            tc_probe::qdisc_json_has_clsact(&output.stdout).map_err(|error| {
                AdapterError::new(
                    AdapterErrorKind::AttachFailed,
                    format!("tc qdisc inspection failed: {error}"),
                )
            })
        };

        if clsact_present()? {
            return Ok(());
        }
        match tc::qdisc_add_clsact(interface) {
            Ok(()) | Err(TcError::AlreadyAttached) => Ok(()),
            Err(_error) if clsact_present()? => Ok(()),
            Err(error) => Err(AdapterError::new(
                AdapterErrorKind::AttachFailed,
                error.to_string(),
            )),
        }
    }

    fn inspect_hook(&mut self, spec: &LinkSpec) -> Result<HookState, AdapterError> {
        let expected_program_id = self
            .classifier(spec.program)?
            .info()
            .map_err(|error| AdapterError::new(AdapterErrorKind::AttachFailed, error.to_string()))?
            .id();
        let direction = match spec.direction {
            LinkDirection::Ingress => "ingress",
            LinkDirection::Egress => "egress",
        };
        let output = run_read_only(
            ReadOnlyCommand::TcFilterShow,
            &["dev", &spec.interface, direction],
            DEFAULT_TIMEOUT,
            ReadOnlyCommand::TcFilterShow.output_cap(),
        )
        .map_err(|error| {
            AdapterError::new(
                AdapterErrorKind::AttachFailed,
                format!("tc filter inspection failed: {error}"),
            )
        })?;
        if output.exit_code != Some(0) || output.timed_out || output.output_truncated {
            return Err(AdapterError::new(
                AdapterErrorKind::AttachFailed,
                format!("tc filter inspection failed: {}", output.stderr.trim()),
            ));
        }
        let filters = tc_probe::parse_filter_json(&spec.interface, direction, &output.stdout)
            .map_err(|error| {
                AdapterError::new(
                    AdapterErrorKind::AttachFailed,
                    format!("tc filter inspection failed: {error}"),
                )
            })?;
        let expected_handle = format!("0x{:x}", spec.handle);
        for filter in filters {
            if filter.filter.chain == 0
                && filter.filter.pref == u32::from(spec.priority)
                && tc_probe::handles_equal(&filter.filter.handle, &expected_handle)
            {
                let program_owned = filter.program_id.map_or_else(
                    || filter.program_name.as_deref() == Some(spec.kernel_program_name()),
                    |program_id| program_id == expected_program_id,
                );
                let execution_owned = tc_probe::has_software_direct_action_semantics(&filter);
                return Ok(
                    if filter.kind.as_deref() == Some("bpf") && program_owned && execution_owned {
                        HookState::Owned
                    } else {
                        HookState::Foreign
                    },
                );
            }
        }
        Ok(HookState::Absent)
    }

    fn tc_topology_changed(&mut self, specs: &[LinkSpec]) -> bool {
        let mut ifindices = Vec::new();
        let mut interfaces = Vec::new();
        for spec in specs {
            if interfaces.contains(&spec.interface.as_str()) {
                continue;
            }
            interfaces.push(spec.interface.as_str());
            let Ok(interface) = CString::new(spec.interface.as_bytes()) else {
                return true;
            };
            let ifindex = unsafe { libc::if_nametoindex(interface.as_ptr()) };
            let Ok(ifindex) = i32::try_from(ifindex) else {
                return true;
            };
            if ifindex == 0 {
                return true;
            }
            if !ifindices.contains(&ifindex) {
                ifindices.push(ifindex);
            }
        }
        self.tc_monitor.topology_changed(&ifindices)
    }

    fn attach_netlink(&mut self, spec: &LinkSpec) -> Result<Self::Link, AdapterError> {
        let attach_type = attach_type(spec.direction);
        let options = TcAttachOptions::Netlink(NlOptions {
            priority: spec.priority,
            handle: TcHandle::new(0, spec.handle),
            classid: None,
        });
        let id = self
            .classifier(spec.program)?
            .attach_with_options(&spec.interface, attach_type, options)
            .map_err(|error| {
                AdapterError::new(AdapterErrorKind::AttachFailed, error.to_string())
            })?;
        Ok(SystemAyaLink {
            program: spec.program,
            id,
        })
    }

    fn replace_owned_netlink_atomic(
        &mut self,
        spec: &LinkSpec,
    ) -> Result<Self::Link, AdapterError> {
        let link = SchedClassifierLink::attached(
            &spec.interface,
            attach_type(spec.direction),
            spec.priority,
            TcHandle::new(0, spec.handle),
            None,
        )
        .map_err(|error| AdapterError::new(AdapterErrorKind::AttachFailed, error.to_string()))?;
        let id = self
            .classifier(spec.program)?
            .attach_to_link(link)
            .map_err(|error| {
                AdapterError::new(AdapterErrorKind::AttachFailed, error.to_string())
            })?;
        Ok(SystemAyaLink {
            program: spec.program,
            id,
        })
    }

    fn detach_link(&mut self, _spec: &LinkSpec, link: Self::Link) -> Result<(), AdapterError> {
        self.classifier(link.program)?
            .detach(link.id)
            .map_err(|error| AdapterError::new(AdapterErrorKind::DetachFailed, error.to_string()))
    }

    fn detach_exact(&mut self, spec: &LinkSpec) -> Result<(), AdapterError> {
        let link = SchedClassifierLink::attached(
            &spec.interface,
            attach_type(spec.direction),
            spec.priority,
            TcHandle::new(0, spec.handle),
            None,
        )
        .map_err(|error| AdapterError::new(AdapterErrorKind::DetachFailed, error.to_string()))?;
        link.detach()
            .map_err(|error| AdapterError::new(AdapterErrorKind::DetachFailed, error.to_string()))
    }

    fn forget_link(&mut self, _spec: &LinkSpec, link: Self::Link) -> Result<(), AdapterError> {
        let stale = self
            .classifier(link.program)?
            .take_link(link.id)
            .map_err(|error| {
                AdapterError::new(AdapterErrorKind::DetachFailed, error.to_string())
            })?;
        drop(stale);
        Ok(())
    }

    fn abandon_link(&mut self, _spec: &LinkSpec, link: Self::Link) -> Result<(), AdapterError> {
        let stale = self
            .classifier(link.program)?
            .take_link(link.id)
            .map_err(|error| {
                AdapterError::new(AdapterErrorKind::DetachFailed, error.to_string())
            })?;
        core::mem::forget(stale);
        Ok(())
    }

    fn read_clients(&mut self) -> Result<MapRead, AdapterError> {
        let map = self
            .ebpf
            .as_ref()
            .and_then(|ebpf| ebpf.map(CLIENTS_MAP_NAME))
            .ok_or_else(|| {
                AdapterError::new(AdapterErrorKind::MapReadFailed, "lanspeed_clients missing")
            })?;
        let clients = HashMap::<_, ClientKey, ClientValue>::try_from(map).map_err(|error| {
            AdapterError::new(AdapterErrorKind::MapReadFailed, error.to_string())
        })?;
        let mut entries = Vec::new();
        let mut truncated = false;
        for entry in clients.iter() {
            match entry {
                Ok((key, value)) => {
                    if entries.len() >= MAX_CLIENTS as usize {
                        truncated = true;
                        break;
                    }
                    entries.push(super::snapshot::RawMapSample {
                        key: key.0,
                        counters: value.0,
                    });
                }
                Err(aya::maps::MapError::KeyNotFound) => continue,
                Err(error) => {
                    return Err(AdapterError::new(
                        AdapterErrorKind::MapReadFailed,
                        error.to_string(),
                    ));
                }
            }
        }
        truncated |= entries.len() == MAX_CLIENTS as usize;
        Ok(MapRead { entries, truncated })
    }

    fn interface_name(&mut self, ifindex: u32) -> Option<String> {
        let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
        let result = unsafe { libc::if_indextoname(ifindex, name.as_mut_ptr()) };
        if result.is_null() {
            return None;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(result) };
        name.to_str().ok().map(str::to_owned)
    }

    fn unload(&mut self) {
        self.ebpf = None;
    }
}

fn push_unique_spec(specs: &mut Vec<LinkSpec>, spec: LinkSpec) {
    if !specs.contains(&spec) {
        specs.push(spec);
    }
}

fn attach_type(direction: LinkDirection) -> TcAttachType {
    match direction {
        LinkDirection::Ingress => TcAttachType::Ingress,
        LinkDirection::Egress => TcAttachType::Egress,
    }
}

fn classify_kfunc_patch_error(error: KfuncPatchError) -> AdapterError {
    AdapterError::new(
        if error.is_kernel_incompatibility() {
            AdapterErrorKind::KfuncIncompatible
        } else {
            AdapterErrorKind::LoadFailed
        },
        error.to_string(),
    )
}

fn classify_aya_load_error(error: aya::EbpfError) -> AdapterError {
    AdapterError::new(AdapterErrorKind::LoadFailed, error.to_string())
}

fn classify_program_load_error(error: aya::programs::ProgramError) -> AdapterError {
    let kind = match &error {
        aya::programs::ProgramError::LoadError { verifier_log, .. }
            if is_known_kfunc_metadata_incompatibility(&verifier_log.to_string()) =>
        {
            AdapterErrorKind::KfuncIncompatible
        }
        _ => AdapterErrorKind::LoadFailed,
    };
    AdapterError::new(kind, error.to_string())
}
