use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    rc::Rc,
    sync::{mpsc, mpsc::Receiver, Arc},
    time::{Duration, Instant},
};

use lanspeed_openwrt_sys::{Timer, UbusConnection, UloopGuard};
use serde_json::{json, Value};

use crate::{
    clock::monotonic_millis,
    collectors::conntrack::CollectedSnapshot,
    config::{AccessEdgeMode, RuntimeConfig, SysfsInterfaceEligibility},
    connection_details::ConnectionRateBook,
    connections::{
        periodic_conntrack_plan, publish_connection_details, ConntrackObservation,
        PeriodicConntrackPlan,
    },
    control::{
        ClientControlDeleteRequest, ClientControlRequest, ControlCommand, ControlReconcileOutcome,
        ControlReconcileWork,
    },
    daemon::{
        activate_runtime, install_control_or_shutdown, reconnect_and_register, shutdown_runtime,
        CoordinatorState, Runtime, RuntimeCollectionSignals, UloopSignalBridge,
    },
    error::DaemonError,
    history::overview::{
        ConnectionTotals, ConnectionTotalsOverride, OverviewClient, OverviewConfig, OverviewRing,
    },
    identity::{
        arp,
        filter::IdentityFilter,
        hostname::{HostnameCache, HostnamePaths},
        netlink, IdentityObservation, IdentityTable, LegacyZoneResolver, ObservationSource,
    },
    interfaces::{
        read_interface_counter_snapshot, InterfaceCounterSnapshot, InterfaceCounters,
        InterfaceRateBook, LAN_INTERFACE_RATE_WINDOW_MS, MIXED_INTERFACE_SOURCE,
    },
    model::{
        Capabilities, ClientsResponse, Confidence, Conflict, Evidence, HealthResponse, Interface,
        InterfaceRole, InterfaceStatus, InterfacesResponse, Mode, OverviewResponse, OverviewSample,
        ReloadResponse, StatusResponse, SysdevicesResponse,
    },
    platform::{
        confidence,
        x86::{coverage_state::X86Coverage, output::clients_response},
    },
    policy::{self, RateCollector},
    probe::{
        collector::{self, probe_deadline, probe_due, ProbeMethod, SystemProbeCollector},
        process::{DaeModeReloadLatch, DaeProcessTracker},
        Mode as ProbeMode, ProbeCapabilities, ProbeReport, RuntimeHealth,
    },
    runtime_worker::{self, RuntimeCollectionNotice, RuntimeCollectionWorker},
    state::{diagnostic_now_ms, ResponseSnapshot, CONNECTION_SEMANTICS, OVERVIEW_SAMPLE_SOURCE},
    ubus,
};

use crate::conntrack_worker::{self, ConntrackTask, CONNTRACK_WORK_INTERVAL_MS};
use crate::control::ControlManager;
use crate::control_worker::{self, ControlWorkerNotice, ControlWorkerTask};
use crate::workers::{QueueError, RuntimeWorker};

#[cfg(not(feature = "nss-platform"))]
use crate::platform::x86::{
    runtime::{
        AdapterErrorKind, AttachMode, BpfCollectionCheckpoint, BpfPostCommitCleanup,
        BpfReconfigureTxn, BpfRuntime, ReconfigureRateBaseline, ReconfigureStrategy,
        SystemAyaAdapter, SystemAyaLink, FALLBACK_OBJECT_PATH,
    },
    snapshot::{BpfSnapshotCollector, ConnectionCounts, ConnectionOverlay},
};

#[cfg(feature = "nss-platform")]
use crate::platform::nss::{
    tc_bpf_runtime::{
        AdapterErrorKind, AttachMode, BpfCollectionCheckpoint, BpfPostCommitCleanup,
        BpfReconfigureTxn, BpfRuntime, ReconfigureRateBaseline, ReconfigureStrategy,
        SystemAyaAdapter, SystemAyaLink, FALLBACK_OBJECT_PATH,
    },
    tc_bpf_snapshot::{BpfSnapshotCollector, ConnectionCounts, ConnectionOverlay},
};

#[cfg(feature = "nss-platform")]
use crate::config::ConnectionCollectorMode;

#[cfg(feature = "nss-platform")]
use crate::collectors::conntrack::{self, CollectorMode as ConntrackMode};

mod evidence;
#[cfg(feature = "nss-platform")]
mod fast_rate_overlay;
mod rate_helpers;
mod reload_worker;
mod system;
#[cfg(all(test, feature = "nss-platform"))]
mod tests;
use evidence::*;
use rate_helpers::*;
use reload_worker::{ProductionReloadWorker, ReloadNotice, ReloadOutcome};

#[cfg(feature = "nss-platform")]
use crate::control::{NssPathObservation, NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD};

#[cfg(feature = "nss-platform")]
use crate::config::RateCollectorMode;

#[cfg(all(test, feature = "nss-platform"))]
use crate::platform::nss::fusion::add_traffic_counters;
#[cfg(feature = "nss-platform")]
use crate::platform::nss::tc_bpf_snapshot::BpfSnapshot;
#[cfg(all(test, feature = "nss-platform"))]
use crate::platform::nss::{
    output::{coverage_response, nss_rate_coverage_values},
    window::{CoverageWindow, EcmBpfRateBatch, RateWindowValue},
};
#[cfg(all(test, feature = "nss-platform"))]
use crate::probe::Confidence as ProbeConfidence;
#[cfg(feature = "nss-platform")]
use crate::{
    connection_details::{TrafficClassification, TrafficClassificationDirection},
    identity::{filter, ClientIdentity, MacAddress},
    model::{
        AttachmentKind as ModelAttachmentKind, AttachmentTrust as ModelAttachmentTrust,
        ByteDomain as ModelByteDomain, ClassificationState, Client, ClientRateMeta, RateAttachment,
        RateClassificationSummary, RateCoverage as ModelRateCoverage, RateDirectionMeta,
        RateScope as ModelRateScope, RateSource as ModelRateSource,
    },
    platform::{
        access_edge::{
            normalize_l2_with_fcs, AccessEdgeCheckpoint, AccessEdgeRuntime, AccessEdgeSnapshot,
            Attachment as EdgeAttachment, AttachmentKind as EdgeAttachmentKind,
            AttachmentTrust as EdgeAttachmentTrust, ByteDomain as EdgeByteDomain,
            ClassificationEpoch, ClassificationResult, Direction as EdgeDirection, DirectionEpoch,
            EdgeClientObservation, MuxFailure, ObservedDelta, RateCandidate,
            RateSource as EdgeRateSource, TrafficScope as EdgeTrafficScope,
            CLASSIFIER_READ_END_SKEW_MS,
        },
        counters::TrafficCounters,
        nss::{
            bpf_coverage::NssBpfCoverage,
            control::{PathProbeBook, PathProbeWindow},
            ecm_bpf::EcmBpfSnapshot,
            evidence::{apply_ecm_bpf_evidence, apply_nss_snapshot_evidence},
            evidence_lease::{e_usability, EUsability, LeaseClientObservation},
            fast_rate_clients::FastClientSample,
            fast_rate_worker::{self, FastRateCommand, FastRateSources, FastRateWakeupNotice},
            fusion::{
                ecm_bpf_client_interfaces, ecm_bpf_fallback_client_rates,
                merge_ecm_bpf_client_deltas, merge_ecm_bpf_coverage_delta,
            },
            interface_rate::NssInterfaceRates,
            output::{
                apply_ecm_bpf_rate_batch, coverage_evidence, ecm_bpf_clients_response,
                ecm_bpf_coverage_merge_evidence, ecm_bpf_rate_batch_evidence, nss_rate_coverage,
                rate_window_interface_counters, window_clients, window_evidence,
            },
            rate_mux::RateView,
            runtime::{NssRuntime, NssRuntimeCheckpoint},
            tc_snapshot::{NssTcClientSample, NssTcSnapshot},
            window::{LanClock, WindowQuality},
        },
    },
};

const RECONNECT_MS: u32 = 1_000;
const RUNTIME_NOTICE_POLL_MS: u32 = 20;
const RELOAD_WAIT_MS: u64 = 7_500;
// Kept as a policy/timer constant so the x86 build does not need to link the
// NSS platform module merely to compile common scheduling code.
const ACCESS_EDGE_INTERVAL_MS: u64 = 1_000;
const CLASSIFIER_INTERVAL_MS: u64 = 2_000;
#[cfg(feature = "nss-platform")]
const CPU_PATH_PROBE_READ_END_SKEW_MS: u64 = 250;
const INTERNAL_BPF_SELF_HEAL_REASON: &str = "production.collect.internal";
const EXTERNAL_BPF_SELF_HEAL_REASON: &str = "production.collect.external";
const INTERFACE_NOTE: &str = "LAN interface totals use independent physical boundaries from one kernel net-device pass and a two-second rolling window to smooth batched counter updates.";

fn production_now_ms() -> Result<u64, DaemonError> {
    monotonic_millis()
        .map_err(|error| DaemonError::collection(format!("read CLOCK_MONOTONIC: {error}")))
}

struct ProductionRuntime {
    config: RuntimeConfig,
    control: ControlManager,
    control_work: Option<ControlReconcileWork>,
    control_reconcile_pending: bool,
    adapter: SystemAyaAdapter,
    bpf: Option<Bpf>,
    bpf_error: Option<String>,
    /// Stable internal classification for the last BPF failure. The public
    /// evidence exposes this code, while `bpf_error` remains private detail.
    bpf_error_stage: Option<&'static str>,
    bpf_collector: BpfSnapshotCollector,
    #[cfg(feature = "nss-platform")]
    nss: NssRuntime,
    #[cfg(feature = "nss-platform")]
    access_edge: AccessEdgeRuntime,
    #[cfg(feature = "nss-platform")]
    classification_results: BTreeMap<String, ClassificationResult>,
    #[cfg(feature = "nss-platform")]
    classifier_epoch_id: u64,
    #[cfg(feature = "nss-platform")]
    next_classifier_deadline_ms: u64,
    #[cfg(feature = "nss-platform")]
    cpu_path_probe_book: PathProbeBook,
    #[cfg(feature = "nss-platform")]
    cpu_path_probe_windows: BTreeMap<String, PathProbeWindow>,
    conntrack_snapshot: Option<Arc<CollectedSnapshot>>,
    connection_rates: ConnectionRateBook,
    conntrack_observation: ConntrackObservation,
    probe: SystemProbeCollector,
    process_tracker: DaeProcessTracker,
    probe_report: Arc<ProbeReport>,
    next_probe_ms: u64,
    overview: OverviewRing,
    x86_coverage: X86Coverage,
    #[cfg(feature = "nss-platform")]
    nss_bpf_coverage: NssBpfCoverage,
    interface_rates: InterfaceRateBook,
    rate_owner: Option<RateCollector>,
    hostnames: HostnameCache,
    /// Only the committed NSS runtime may mutate or remove shared client
    /// control objects. Reload candidates inspect them read-only until the
    /// ownership handoff is committed.
    #[cfg(feature = "nss-platform")]
    control_platform_owner: bool,
    shutdown_complete: bool,
}

struct RuntimeCheckpoint {
    control: ControlManager,
    control_work: Option<ControlReconcileWork>,
    control_reconcile_pending: bool,
    bpf: Option<BpfCollectionCheckpoint>,
    #[cfg(feature = "nss-platform")]
    nss: NssRuntimeCheckpoint,
    #[cfg(feature = "nss-platform")]
    access_edge: AccessEdgeCheckpoint,
    #[cfg(feature = "nss-platform")]
    classification_results: BTreeMap<String, ClassificationResult>,
    #[cfg(feature = "nss-platform")]
    classifier_epoch_id: u64,
    #[cfg(feature = "nss-platform")]
    next_classifier_deadline_ms: u64,
    #[cfg(feature = "nss-platform")]
    cpu_path_probe_book: PathProbeBook,
    #[cfg(feature = "nss-platform")]
    cpu_path_probe_windows: BTreeMap<String, PathProbeWindow>,
    overview: OverviewRing,
    x86_coverage: X86Coverage,
    #[cfg(feature = "nss-platform")]
    nss_bpf_coverage: NssBpfCoverage,
    interface_rates: InterfaceRateBook,
    rate_owner: Option<RateCollector>,
    hostnames: HostnameCache,
    conntrack_snapshot: Option<Arc<CollectedSnapshot>>,
    connection_rates: ConnectionRateBook,
    conntrack_observation: ConntrackObservation,
    probe_report: Arc<ProbeReport>,
    next_probe_ms: u64,
    bpf_error: Option<String>,
    bpf_error_stage: Option<&'static str>,
}

impl ProductionRuntime {
    fn stage(config: RuntimeConfig) -> Result<Self, DaemonError> {
        let mut runtime = Self::prepare(config)?;
        runtime.activate_new_bpf()?;
        #[cfg(feature = "nss-platform")]
        runtime.nss.activate(&runtime.config, &runtime.probe_report);
        Ok(runtime)
    }

    fn prepare(config: RuntimeConfig) -> Result<Self, DaemonError> {
        Self::prepare_with_process_tracker(config, DaeProcessTracker::default())
    }

    fn prepare_with_process_tracker(
        mut config: RuntimeConfig,
        mut process_tracker: DaeProcessTracker,
    ) -> Result<Self, DaemonError> {
        config.enforce_platform_profile();
        let mut probe = collector::system_collector()
            .map_err(|error| DaemonError::platform(error.to_string()))?;
        process_tracker.refresh_if_due("/proc", production_now_ms()?);
        let mut preflight = probe.collect(&config, &RuntimeHealth::default(), ProbeMethod::Health);
        process_tracker.overlay_report(&mut preflight);
        #[cfg(feature = "nss-platform")]
        let _nss_genl_caps = crate::platform::nss::control::startup_caps();
        let control = ControlManager::load(&config)?;
        Ok(Self {
            bpf_collector: BpfSnapshotCollector::new(
                config.max_clients,
                config.active_client_window_ms,
            ),
            #[cfg(feature = "nss-platform")]
            nss: NssRuntime::default(),
            #[cfg(feature = "nss-platform")]
            access_edge: AccessEdgeRuntime::new(config.max_clients),
            #[cfg(feature = "nss-platform")]
            classification_results: BTreeMap::new(),
            #[cfg(feature = "nss-platform")]
            classifier_epoch_id: 0,
            #[cfg(feature = "nss-platform")]
            next_classifier_deadline_ms: 0,
            #[cfg(feature = "nss-platform")]
            cpu_path_probe_book: PathProbeBook::default(),
            #[cfg(feature = "nss-platform")]
            cpu_path_probe_windows: BTreeMap::new(),
            conntrack_snapshot: None,
            connection_rates: ConnectionRateBook::default(),
            conntrack_observation: ConntrackObservation::default(),
            probe,
            process_tracker,
            probe_report: Arc::new(preflight),
            next_probe_ms: 0,
            rate_owner: None,
            hostnames: HostnameCache::new(),
            adapter: SystemAyaAdapter::with_max_clients(config.max_clients),
            control,
            control_work: None,
            control_reconcile_pending: false,
            config,
            bpf: None,
            bpf_error: None,
            bpf_error_stage: None,
            #[cfg(feature = "nss-platform")]
            control_platform_owner: true,
            overview: OverviewRing::new(),
            x86_coverage: X86Coverage::default(),
            #[cfg(feature = "nss-platform")]
            nss_bpf_coverage: NssBpfCoverage::default(),
            interface_rates: InterfaceRateBook::default(),
            shutdown_complete: false,
        })
    }

    fn desired_attach_mode(&self) -> AttachMode {
        if self.probe_report.facts.tc.dae_preempts_lan_ingress
            || self.probe_report.facts.proxy.runtime_active
        {
            AttachMode::EarlyPassthrough
        } else {
            AttachMode::Normal
        }
    }

    fn refresh_dae_process_state(&mut self) -> bool {
        let Ok(now_ms) = production_now_ms() else {
            return false;
        };
        let Some(activity_changed) = self.process_tracker.refresh_if_due("/proc", now_ms) else {
            return false;
        };
        self.process_tracker
            .overlay_report(Arc::make_mut(&mut self.probe_report));
        activity_changed
    }

    fn bpf_attach_mode_mismatch(&self) -> bool {
        self.bpf
            .as_ref()
            .and_then(BpfRuntime::attach_mode)
            .is_some_and(|mode| mode != self.desired_attach_mode())
    }

    fn activate_new_bpf(&mut self) -> Result<(), DaemonError> {
        let interfaces = collect_ifnames(&self.config);
        #[cfg(feature = "nss-platform")]
        let recovered_orphan_slots = if self.config.enable_bpf && !interfaces.is_empty() {
            crate::platform::nss::control::recover_classifier_slots(&interfaces)
                .map_err(DaemonError::platform)?
        } else {
            false
        };
        #[cfg(not(feature = "nss-platform"))]
        let recovered_orphan_slots = false;
        if recovered_orphan_slots {
            let mut report =
                self.probe
                    .collect(&self.config, &RuntimeHealth::default(), ProbeMethod::Health);
            self.process_tracker.overlay_report(&mut report);
            self.probe_report = Arc::new(report);
        }
        if !self.config.enable_bpf
            || (!matches!(
                self.config.rate_collector_mode,
                crate::config::RateCollectorMode::Auto
                    | crate::config::RateCollectorMode::Bpf
                    | crate::config::RateCollectorMode::NssEcmBpf
            ) && !self.config.internet_view_mode.uses_fast_rate())
            || (!self.probe_report.facts.tc.safe_attach && !recovered_orphan_slots)
        {
            return Ok(());
        }
        if interfaces.is_empty() {
            self.bpf_error = None;
            self.bpf_error_stage = None;
            return Ok(());
        }
        let mut loaded = match BpfRuntime::load_byte_only(&mut self.adapter, FALLBACK_OBJECT_PATH) {
            Ok(runtime) => runtime,
            Err(error) => {
                self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
                self.bpf_error = Some(error.to_string());
                return Ok(());
            }
        };
        let mode = self.desired_attach_mode();
        if let Err(error) = loaded.attach_interfaces(&mut self.adapter, &interfaces, mode) {
            self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
            if let Err(cleanup) = loaded.shutdown(&mut self.adapter) {
                return Err(DaemonError::collection(format!(
                    "{error}; BPF cleanup failed: {cleanup}"
                )));
            }
            self.bpf_error = Some(error.to_string());
            self.adapter = SystemAyaAdapter::with_max_clients(self.config.max_clients);
            return Ok(());
        }
        self.bpf = Some(loaded);
        self.bpf_error = None;
        self.bpf_error_stage = None;
        Ok(())
    }

    fn checkpoint(&self) -> RuntimeCheckpoint {
        RuntimeCheckpoint {
            control: self.control.clone(),
            control_work: self.control_work.clone(),
            control_reconcile_pending: self.control_reconcile_pending,
            bpf: self
                .bpf
                .as_ref()
                .map(|runtime| runtime.collection_checkpoint(&self.bpf_collector)),
            #[cfg(feature = "nss-platform")]
            nss: self.nss.checkpoint(),
            #[cfg(feature = "nss-platform")]
            access_edge: self.access_edge.checkpoint(),
            #[cfg(feature = "nss-platform")]
            classification_results: self.classification_results.clone(),
            #[cfg(feature = "nss-platform")]
            classifier_epoch_id: self.classifier_epoch_id,
            #[cfg(feature = "nss-platform")]
            next_classifier_deadline_ms: self.next_classifier_deadline_ms,
            #[cfg(feature = "nss-platform")]
            cpu_path_probe_book: self.cpu_path_probe_book.clone(),
            #[cfg(feature = "nss-platform")]
            cpu_path_probe_windows: self.cpu_path_probe_windows.clone(),
            overview: self.overview.clone(),
            x86_coverage: self.x86_coverage.clone(),
            #[cfg(feature = "nss-platform")]
            nss_bpf_coverage: self.nss_bpf_coverage.clone(),
            interface_rates: self.interface_rates.clone(),
            rate_owner: self.rate_owner,
            hostnames: self.hostnames.clone(),
            conntrack_snapshot: self.conntrack_snapshot.clone(),
            connection_rates: self.connection_rates.clone(),
            conntrack_observation: self.conntrack_observation.clone(),
            probe_report: self.probe_report.clone(),
            next_probe_ms: self.next_probe_ms,
            bpf_error: self.bpf_error.clone(),
            bpf_error_stage: self.bpf_error_stage,
        }
    }

    fn restore(&mut self, checkpoint: RuntimeCheckpoint) {
        self.control = checkpoint.control;
        self.control_work = checkpoint.control_work;
        self.control_reconcile_pending = checkpoint.control_reconcile_pending;
        if let (Some(runtime), Some(checkpoint)) = (self.bpf.as_mut(), checkpoint.bpf) {
            runtime.restore_collection_checkpoint(&mut self.bpf_collector, checkpoint);
        }
        #[cfg(feature = "nss-platform")]
        {
            self.nss.restore(checkpoint.nss);
            self.access_edge.restore(checkpoint.access_edge);
            self.classification_results = checkpoint.classification_results;
            self.classifier_epoch_id = checkpoint.classifier_epoch_id;
            self.next_classifier_deadline_ms = checkpoint.next_classifier_deadline_ms;
            self.cpu_path_probe_book = checkpoint.cpu_path_probe_book;
            self.cpu_path_probe_windows = checkpoint.cpu_path_probe_windows;
        }
        self.overview = checkpoint.overview;
        self.x86_coverage = checkpoint.x86_coverage;
        #[cfg(feature = "nss-platform")]
        {
            self.nss_bpf_coverage = checkpoint.nss_bpf_coverage;
        }
        self.interface_rates = checkpoint.interface_rates;
        self.rate_owner = checkpoint.rate_owner;
        self.hostnames = checkpoint.hostnames;
        self.conntrack_snapshot = checkpoint.conntrack_snapshot;
        self.connection_rates = checkpoint.connection_rates;
        self.conntrack_observation = checkpoint.conntrack_observation;
        self.probe_report = checkpoint.probe_report;
        self.next_probe_ms = checkpoint.next_probe_ms;
        self.bpf_error = checkpoint.bpf_error;
        self.bpf_error_stage = checkpoint.bpf_error_stage;
    }

    #[cfg(feature = "nss-platform")]
    fn read_conntrack(
        &mut self,
        identities: &IdentityTable,
        now_ms: u64,
        defer_connection_rates: bool,
    ) -> Result<Arc<CollectedSnapshot>, String> {
        match conntrack::collect(
            conntrack_mode(self.config.conn_collector_mode),
            identities,
            now_ms,
            self.config.max_clients,
        ) {
            Ok(mut snapshot) => {
                if defer_connection_rates {
                    self.connection_rates.update_deferred(
                        snapshot.sample_ms,
                        &snapshot.connection_counters,
                        &mut snapshot.connection_details,
                    );
                } else {
                    self.connection_rates.update(
                        snapshot.sample_ms,
                        &snapshot.connection_counters,
                        &mut snapshot.connection_details,
                    );
                }
                self.conntrack_observation.record_success(
                    now_ms,
                    snapshot.stats.netlink_read,
                    snapshot.stats.procfs_read,
                );
                let snapshot = Arc::new(snapshot);
                self.conntrack_snapshot = Some(Arc::clone(&snapshot));
                Ok(snapshot)
            }
            Err(error) => {
                let message = error.to_string();
                self.connection_rates.clear();
                self.conntrack_observation
                    .record_failure(now_ms, message.clone(), false, false);
                self.conntrack_snapshot = None;
                Err(message)
            }
        }
    }

    fn apply_conntrack_health(&self, runtime_health: &mut RuntimeHealth) {
        self.conntrack_observation
            .apply_runtime_health(self.conntrack_snapshot.is_some(), runtime_health);
    }

    fn collect(&mut self, method: ProbeMethod) -> Result<ResponseSnapshot, DaemonError> {
        let checkpoint = self.checkpoint();
        let result = self.collect_inner(method, None).and_then(|snapshot| {
            for method in ubus::Method::FIXED {
                snapshot.response(method)?;
            }
            Ok(snapshot)
        });
        match result {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                self.restore(checkpoint);
                Err(error)
            }
        }
    }

    fn collect_with_external_bpf(
        &mut self,
        runtime: &mut Bpf,
        adapter: &mut SystemAyaAdapter,
        method: ProbeMethod,
    ) -> Result<(ResponseSnapshot, BpfCollectionCheckpoint), DaemonError> {
        let checkpoint = self.checkpoint();
        let bpf_checkpoint = runtime.collection_checkpoint(&self.bpf_collector);
        let result = self
            .collect_inner(method, Some((&mut *runtime, &mut *adapter)))
            .and_then(|snapshot| {
                for method in ubus::Method::FIXED {
                    snapshot.response(method)?;
                }
                Ok(snapshot)
            });
        match result {
            Ok(snapshot) => Ok((snapshot, bpf_checkpoint)),
            Err(error) => {
                runtime.restore_collection_checkpoint(&mut self.bpf_collector, bpf_checkpoint);
                self.restore(checkpoint);
                Err(error)
            }
        }
    }

    // x86 is intentionally a separate production path. It reads the native
    // TC-BPF client map and publishes that single source directly; no NSS map,
    // Access Edge topology, classifier window, or RateMux state is reachable
    // from this build.
    #[cfg(not(feature = "nss-platform"))]
    fn collect_inner(
        &mut self,
        method: ProbeMethod,
        mut external_bpf: Option<(&mut Bpf, &mut SystemAyaAdapter)>,
    ) -> Result<ResponseSnapshot, DaemonError> {
        let mut now_ms = production_now_ms()?;
        let (identities, identity_errors) = read_identities(&self.config, now_ms);
        let conntrack = self.conntrack_snapshot.clone();
        let overlay = connection_overlay(conntrack.as_deref());
        let freshness_ms = u64::from(self.config.refresh_interval_ms).saturating_mul(3);
        let (bpf_snapshot, mut runtime_health, bpf_snapshot_fresh) = match external_bpf.as_mut() {
            Some((runtime, adapter)) => match runtime.collect_snapshot_self_healing(
                &mut **adapter,
                &mut self.bpf_collector,
                &identities,
                &overlay,
                now_ms,
                EXTERNAL_BPF_SELF_HEAL_REASON,
            ) {
                Ok(snapshot) => {
                    self.bpf_error = None;
                    self.bpf_error_stage = None;
                    let health_now_ms = now_ms.max(snapshot.sample_ms);
                    let health = runtime.runtime_health(health_now_ms, freshness_ms);
                    (Some(snapshot), health, true)
                }
                Err(error) => {
                    self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
                    self.bpf_error = Some(error.to_string());
                    let snapshot = self.bpf_collector.last_complete().cloned();
                    let health_now_ms = snapshot
                        .as_ref()
                        .map_or(now_ms, |value| now_ms.max(value.sample_ms));
                    let health = runtime.runtime_health(health_now_ms, freshness_ms);
                    (snapshot, health, false)
                }
            },
            None => match self.bpf.as_mut() {
                Some(runtime) => match runtime.collect_snapshot_self_healing(
                    &mut self.adapter,
                    &mut self.bpf_collector,
                    &identities,
                    &overlay,
                    now_ms,
                    INTERNAL_BPF_SELF_HEAL_REASON,
                ) {
                    Ok(snapshot) => {
                        self.bpf_error = None;
                        self.bpf_error_stage = None;
                        let health_now_ms = now_ms.max(snapshot.sample_ms);
                        let health = runtime.runtime_health(health_now_ms, freshness_ms);
                        (Some(snapshot), health, true)
                    }
                    Err(error) => {
                        self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
                        self.bpf_error = Some(error.to_string());
                        let snapshot = self.bpf_collector.last_complete().cloned();
                        let health_now_ms = snapshot
                            .as_ref()
                            .map_or(now_ms, |value| now_ms.max(value.sample_ms));
                        let health = runtime.runtime_health(health_now_ms, freshness_ms);
                        (snapshot, health, false)
                    }
                },
                None => (None, RuntimeHealth::default(), false),
            },
        };
        if runtime_health.bpf_object_loaded {
            runtime_health.bpf_map_capacity = self.config.max_clients.saturating_mul(4);
        }
        if let Some(snapshot) = bpf_snapshot.as_ref() {
            now_ms = now_ms.max(snapshot.sample_ms);
        }
        runtime_health.now_ms = now_ms;
        self.apply_conntrack_health(&mut runtime_health);
        if runtime_health.runtime_error.is_none() {
            runtime_health.runtime_error = self.bpf_error.clone();
        }
        if probe_due(now_ms, self.next_probe_ms, method) {
            let mut report = self.probe.collect(&self.config, &runtime_health, method);
            self.process_tracker.overlay_report(&mut report);
            self.probe_report = Arc::new(report);
            self.next_probe_ms = probe_deadline(now_ms);
        }
        let report = Arc::clone(&self.probe_report);
        let mut decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        if matches!(
            periodic_conntrack_plan(decision.rate),
            PeriodicConntrackPlan::Skip
        ) {
            self.conntrack_observation.record_skipped();
        }
        self.apply_conntrack_health(&mut runtime_health);
        decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        let (interfaces, counter_snapshot) = self.interfaces_x86(now_ms);
        let mut clients = if decision.rate == RateCollector::Bpf {
            clients_response(
                bpf_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.clients.as_slice()),
                conntrack.as_deref(),
                &identities,
                decision.confidence,
            )
        } else {
            ClientsResponse::empty(evidence(&report, "clients"))
        };
        let actual_live = decision.rate == RateCollector::Bpf && bpf_snapshot.is_some();
        let actual_degraded = !actual_live;
        self.hostnames.refresh_from_paths(
            &HostnamePaths::default(),
            now_ms,
            method == ProbeMethod::Reload,
        );
        for client in &mut clients.clients {
            let ips = client.ips.iter().map(String::as_str).collect::<Vec<_>>();
            client.hostname = self.hostnames.lookup(&client.mac, &ips).map(str::to_owned);
        }
        if let Some(snapshot) = conntrack.as_ref() {
            clients.conntrack_entries_seen = Some(snapshot.stats.entries_seen as u64);
            clients.conntrack_entries_matched = Some(snapshot.stats.entries_matched as u64);
            clients.conntrack_parse_errors = Some(snapshot.stats.malformed_lines as u64);
            clients.conn_source = Some(
                if snapshot.stats.netlink_read {
                    "conntrack_netlink"
                } else {
                    "conntrack_procfs"
                }
                .into(),
            );
            clients.conn_collector_mode = Some(self.config.conn_collector_mode.as_str().into());
        }
        if clients.evidence.is_none() {
            clients.evidence = Some(evidence(&report, "clients"));
        }
        if let Some(client_evidence) = clients.evidence.as_mut() {
            apply_decision_evidence(client_evidence, &decision, &self.config, &report);
            client_evidence.details.insert(
                "x86_rate_path".into(),
                json!({
                    "profile": "tc_bpf",
                    "source": "platform::x86::output::clients_response",
                }),
            );
            if let Some(snapshot) = conntrack.as_deref() {
                client_evidence.details.insert(
                    "conntrack_generation".into(),
                    conntrack_generation_evidence(snapshot),
                );
            }
        }
        self.refresh_controls(&mut clients);
        let overview = self.update_overview(now_ms, &clients);
        let coverage = self
            .x86_coverage
            .update(now_ms, &clients, &interfaces, bpf_snapshot_fresh);
        let sysdevices = sysdevices(&self.config)?;
        let mut capabilities = capabilities(&report.capabilities, &report);
        capabilities.nss = false;
        capabilities.nss_ecm_offload = false;
        capabilities.nss_ppe_offload = false;
        capabilities.nss_ecm_node = false;
        capabilities.nss_ecm_bpf = false;
        capabilities.nss_bridge_mgr = false;
        capabilities.nss_ifb = false;
        capabilities.nss_nsm = false;
        capabilities.nss_dp = false;
        capabilities.nss_mcs = false;
        capabilities.live_metrics = actual_live;
        capabilities.conntrack_fallback = false;
        capabilities.bpf_runtime_metrics = runtime_health.bpf_object_loaded
            && runtime_health.bpf_attached
            && bpf_snapshot.is_some()
            && (runtime_health.bpf_map_read_ok || decision.evidence.retained_fresh_snapshot);
        capabilities.bpf = capabilities.bpf_runtime_metrics;
        if capabilities.bpf_runtime_metrics {
            capabilities.bpf_supported = true;
            capabilities.bpf_package = true;
            capabilities.bpf_object = true;
            capabilities.tc = true;
            capabilities.tc_clsact = true;
        }
        let mode = if decision.mode == ProbeMode::Unsupported {
            Mode::Unsupported
        } else if !actual_live || actual_degraded || !identity_errors.is_empty() {
            Mode::Degraded
        } else {
            mode(decision.mode)
        };
        let confidence = if mode == Mode::Unsupported {
            Confidence::Unsupported
        } else if !actual_live || !identity_errors.is_empty() {
            Confidence::Low
        } else {
            confidence(decision.confidence)
        };
        let mut status_evidence = runtime_evidence(
            &report,
            method.as_str(),
            &self.config,
            &runtime_health,
            self.bpf_error_stage,
        );
        apply_decision_evidence(&mut status_evidence, &decision, &self.config, &report);
        status_evidence.details.insert(
            "x86_rate_path".into(),
            json!({
                "profile": "tc_bpf",
                "counter_snapshot_interfaces": counter_snapshot.counters.len(),
            }),
        );
        let mut warnings = report
            .warnings
            .iter()
            .map(|warning| (*warning).to_owned())
            .collect::<Vec<_>>();
        for warning in &decision.warnings {
            if !warnings.iter().any(|value| value == warning) {
                warnings.push((*warning).into());
            }
        }
        if capabilities.bpf_runtime_metrics {
            warnings.retain(|warning| {
                !matches!(
                    warning.as_str(),
                    "bpf_unsupported"
                        | "tc_clsact_unsupported"
                        | "unsafe_attach"
                        | "bpf_runtime_loader_unavailable"
                        | "bpf_optional_package_missing"
                        | "bpf_object_missing"
                )
            });
        }
        if !actual_live
            && !warnings
                .iter()
                .any(|warning| warning == "live_metrics_unavailable")
        {
            warnings.push("live_metrics_unavailable".into());
        }
        if !identity_errors.is_empty()
            && !warnings
                .iter()
                .any(|warning| warning == "lan_topology_probe_error")
        {
            warnings.push("lan_topology_probe_error".into());
            status_evidence
                .details
                .insert("identity_errors".into(), json!(identity_errors));
        }
        let version = version();
        let status = StatusResponse {
            mode,
            confidence,
            warnings: warnings.clone(),
            evidence: status_evidence.clone(),
            refresh_interval_ms: self.config.refresh_interval_ms,
            active_client_window_ms: self.config.active_client_window_ms,
            active_client_min_bps: self.config.active_client_min_bps,
            overview_window_samples: self.config.overview_window_samples,
            collector_mode: decision.rate.as_str().into(),
            rate_collector_mode: self.config.rate_collector_mode.as_str().into(),
            internet_view_mode: self.config.internet_view_mode.as_str().into(),
            access_edge_mode: "off".into(),
            conn_collector_mode: self.config.conn_collector_mode.as_str().into(),
            version: version.clone(),
            capabilities: capabilities.clone(),
            coverage: Some(coverage),
        };
        let mut health_evidence = runtime_evidence(
            &report,
            "health",
            &self.config,
            &runtime_health,
            self.bpf_error_stage,
        );
        apply_decision_evidence(&mut health_evidence, &decision, &self.config, &report);
        health_evidence.details.insert(
            "x86_rate_path".into(),
            json!({
                "profile": "tc_bpf",
            }),
        );
        let health = HealthResponse {
            mode,
            confidence,
            capabilities,
            conflicts: report
                .conflicts
                .iter()
                .map(|item| Conflict {
                    id: item.id.into(),
                    severity: item.severity.into(),
                    message: item.message.into(),
                    evidence: BTreeMap::new(),
                })
                .collect(),
            warnings: warnings.clone(),
            evidence: health_evidence,
        };
        let mut reload_evidence = evidence(&report, "reload");
        apply_decision_evidence(&mut reload_evidence, &decision, &self.config, &report);
        let reload = ReloadResponse {
            ok: true,
            mode,
            warnings,
            evidence: reload_evidence,
            version,
        };
        let mut response = ResponseSnapshot::from_responses(
            status, clients, overview, health, reload, interfaces, sysdevices,
        );
        publish_connection_details(&mut response, conntrack.as_deref());
        Ok(response)
    }

    #[cfg(feature = "nss-platform")]
    fn collect_inner(
        &mut self,
        method: ProbeMethod,
        external_bpf: Option<(&mut Bpf, &mut SystemAyaAdapter)>,
    ) -> Result<ResponseSnapshot, DaemonError> {
        let mut now_ms = production_now_ms()?;
        let access_edge_enabled = self.config.access_edge_mode != AccessEdgeMode::Off;
        if !access_edge_enabled {
            self.access_edge.reset_for_disabled_mode();
        }
        let classifier_due = access_edge_enabled
            && periodic_deadline_due(
                &mut self.next_classifier_deadline_ms,
                now_ms,
                CLASSIFIER_INTERVAL_MS,
            );
        let throttle_classifier_maps = access_edge_enabled
            && self.probe_report.facts.nss.present
            && matches!(
                self.config.rate_collector_mode,
                RateCollectorMode::Auto | RateCollectorMode::NssEcmBpf
            );
        let classifier_map_read_due = !throttle_classifier_maps || classifier_due;
        let (mut identities, mut identity_errors) = read_identities(&self.config, now_ms);
        if access_edge_enabled {
            let bridges = access_edge_bridges(&self.config);
            self.access_edge.collect_topology(
                &bridges,
                self.config.max_clients.saturating_mul(4),
                now_ms,
            );
        }
        if access_edge_enabled {
            for hint in self.access_edge.identity_hints() {
                let zone = filter::derive_zone_from_ifname(&hint.logical_interface);
                if let Err(error) = identities.observe(IdentityObservation {
                    mac: &hint.mac,
                    zone: Some(&zone),
                    interface: &hint.logical_interface,
                    ip: None,
                    hostname: None,
                    last_seen: now_ms,
                    source: if hint.wireless {
                        ObservationSource::Wireless
                    } else {
                        ObservationSource::Netifd
                    },
                }) {
                    identity_errors.push(format!("Access Edge identity: {error}"));
                }
            }
        }
        let mut conntrack = self.conntrack_snapshot.clone();
        let overlay = connection_overlay(conntrack.as_deref());
        // Sample the authoritative Edge counters immediately before the two
        // classifier maps. Keeping this read group adjacent makes the actual
        // 1s Edge segments comparable to the 2s ECM/TC epochs without assigning
        // a synthetic timestamp to any source.
        let edge_port_names = if access_edge_enabled {
            self.access_edge.port_ifnames()
        } else {
            BTreeSet::new()
        };
        let edge_read_begin_ms = production_now_ms()?;
        let (mut interfaces, lan_clock, interface_counter_snapshot) =
            self.interfaces(now_ms, &edge_port_names);
        let edge_read_end_ms = production_now_ms()?;
        now_ms = now_ms.max(edge_read_end_ms);
        if access_edge_enabled {
            self.access_edge.update_rates(
                &interface_counter_snapshot,
                edge_read_begin_ms,
                edge_read_end_ms,
                edge_read_end_ms,
            );
        }
        let published_edge = if access_edge_enabled {
            self.nss.low_rate_window.observe(
                self.access_edge.latest(),
                &interface_counter_snapshot,
                edge_read_end_ms,
                self.config.nss_low_rate_window_ms,
                self.config.nss_low_rate_high_watermark_bps,
            )
        } else {
            self.nss.low_rate_window.reset();
            self.access_edge.latest().clone()
        };
        self.nss
            .low_rate_window
            .apply_observe_rates(&mut interfaces);
        // Keep the x86 BPF freshness contract tied to its configured cadence.
        // NSS has a dedicated two-second floor, so its retained ECM snapshot
        // must use that effective cadence rather than the one-second default.
        let bpf_freshness_ms = if throttle_classifier_maps {
            CLASSIFIER_INTERVAL_MS.saturating_mul(3)
        } else {
            u64::from(self.config.refresh_interval_ms).saturating_mul(3)
        };
        let nss_freshness_ms = nss_snapshot_freshness_ms(self.config.refresh_interval_ms);
        let (bpf_snapshot, mut runtime_health, bpf_snapshot_fresh) = match external_bpf {
            Some((runtime, adapter)) => {
                let (snapshot, fresh) = if classifier_map_read_due {
                    match runtime.collect_snapshot_self_healing(
                        adapter,
                        &mut self.bpf_collector,
                        &identities,
                        &overlay,
                        now_ms,
                        EXTERNAL_BPF_SELF_HEAL_REASON,
                    ) {
                        Ok(snapshot) => {
                            self.bpf_error = None;
                            self.bpf_error_stage = None;
                            (Some(snapshot), true)
                        }
                        Err(error) => {
                            self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
                            self.bpf_error = Some(error.to_string());
                            (self.bpf_collector.last_complete().cloned(), false)
                        }
                    }
                } else {
                    (self.bpf_collector.last_complete().cloned(), false)
                };
                let health_now_ms = snapshot
                    .as_ref()
                    .map_or(now_ms, |snapshot| now_ms.max(snapshot.sample_ms));
                (
                    snapshot,
                    runtime.runtime_health(health_now_ms, bpf_freshness_ms),
                    fresh,
                )
            }
            None => match self.bpf.as_mut() {
                Some(runtime) => {
                    let (snapshot, fresh) = if classifier_map_read_due {
                        match runtime.collect_snapshot_self_healing(
                            &mut self.adapter,
                            &mut self.bpf_collector,
                            &identities,
                            &overlay,
                            now_ms,
                            INTERNAL_BPF_SELF_HEAL_REASON,
                        ) {
                            Ok(snapshot) => {
                                self.bpf_error = None;
                                self.bpf_error_stage = None;
                                (Some(snapshot), true)
                            }
                            Err(error) => {
                                self.bpf_error_stage = Some(bpf_error_stage(error.kind()));
                                self.bpf_error = Some(error.to_string());
                                (self.bpf_collector.last_complete().cloned(), false)
                            }
                        }
                    } else {
                        (self.bpf_collector.last_complete().cloned(), false)
                    };
                    let health_now_ms = snapshot
                        .as_ref()
                        .map_or(now_ms, |snapshot| now_ms.max(snapshot.sample_ms));
                    (
                        snapshot,
                        runtime.runtime_health(health_now_ms, bpf_freshness_ms),
                        fresh,
                    )
                }
                None => (None, RuntimeHealth::default(), false),
            },
        };
        if runtime_health.bpf_object_loaded {
            runtime_health.bpf_map_capacity = self.config.max_clients.saturating_mul(4);
        }
        let bpf_classifier_read_end_ms = if bpf_snapshot_fresh {
            Some(production_now_ms()?)
        } else {
            None
        };
        if let Some(snapshot) = bpf_snapshot.as_ref() {
            now_ms = now_ms.max(snapshot.sample_ms);
        }
        let ecm_read_begin_ms = production_now_ms().unwrap_or(now_ms);
        let (ecm_bpf_snapshot, ecm_bpf_snapshot_fresh) = self.nss.collect_ecm_bpf(
            &identities,
            &mut now_ms,
            nss_freshness_ms,
            &mut runtime_health,
            classifier_map_read_due,
        );
        let ecm_read_end_ms = production_now_ms().unwrap_or(ecm_read_begin_ms.max(now_ms));
        self.nss.observe_hardware_verifier(
            ecm_bpf_snapshot.as_ref(),
            ecm_read_end_ms,
            ecm_bpf_snapshot_fresh,
        );
        let ecm_classifier_read_end_ms = if ecm_bpf_snapshot_fresh {
            Some(production_now_ms()?)
        } else {
            None
        };
        for read_end_ms in [bpf_classifier_read_end_ms, ecm_classifier_read_end_ms]
            .into_iter()
            .flatten()
        {
            now_ms = now_ms.max(read_end_ms);
        }
        runtime_health.now_ms = now_ms;
        self.apply_conntrack_health(&mut runtime_health);
        if runtime_health.runtime_error.is_none() {
            runtime_health.runtime_error = self.bpf_error.clone();
        }
        if probe_due(now_ms, self.next_probe_ms, method) {
            let mut report = self.probe.collect(&self.config, &runtime_health, method);
            self.process_tracker.overlay_report(&mut report);
            self.probe_report = Arc::new(report);
            self.next_probe_ms = probe_deadline(now_ms);
        }
        let report = Arc::clone(&self.probe_report);
        let mut decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        let node_snapshot = if decision.rate == RateCollector::NssEcmNode {
            self.nss.read_node(&identities, now_ms, &mut runtime_health)
        } else {
            None
        };
        decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        match periodic_conntrack_plan(decision.rate) {
            PeriodicConntrackPlan::Read => {
                let defer_connection_rates = matches!(
                    decision.rate,
                    RateCollector::NssEcmNode | RateCollector::NssEcmBpf
                );
                conntrack = self
                    .read_conntrack(&identities, now_ms, defer_connection_rates)
                    .ok();
            }
            PeriodicConntrackPlan::Skip => {
                self.conntrack_observation.record_skipped();
            }
        }
        self.apply_conntrack_health(&mut runtime_health);
        decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        let nss_tc_snapshot = report
            .facts
            .nss
            .present
            .then(|| bpf_snapshot.as_ref().map(nss_tc_snapshot))
            .flatten();
        if classifier_due {
            self.update_access_classification(
                &identities,
                ecm_bpf_snapshot.as_ref(),
                ecm_bpf_snapshot_fresh,
                ecm_classifier_read_end_ms,
                nss_tc_snapshot.as_ref(),
                bpf_snapshot_fresh,
                bpf_classifier_read_end_ms,
                &runtime_health,
            );
        }
        let fast_reads_ready = self.nss.fast_rate_reads_ready(now_ms);
        self.reconcile_evidence_leases(
            &identities,
            &runtime_health,
            fast_reads_ready,
            classifier_due && ecm_bpf_snapshot_fresh && bpf_snapshot_fresh,
        );
        self.nss
            .transition_rate_owner(&mut self.rate_owner, decision.rate);
        let legacy_nss_rate_window_enabled = legacy_nss_rate_window_enabled(
            self.config.access_edge_mode,
            self.config.rate_collector_mode,
            self.config.internet_view_mode,
        );
        let mut nss_window = None;
        let mut ecm_bpf_coverage_window = None;
        let mut ecm_bpf_coverage_merge = None;
        let mut ecm_bpf_rate_batch = None;
        let (mut clients, actual_live, actual_degraded, coverage_fresh) =
            if decision.rate == RateCollector::Bpf {
                (
                    clients_response(
                        bpf_snapshot
                            .as_ref()
                            .map(|snapshot| snapshot.clients.as_slice()),
                        conntrack.as_deref(),
                        &identities,
                        decision.confidence,
                    ),
                    bpf_snapshot.is_some(),
                    bpf_snapshot.is_none(),
                    bpf_snapshot_fresh,
                )
            } else if decision.rate == RateCollector::NssEcmNode {
                match (node_snapshot.as_ref(), lan_clock) {
                    (Some(snapshot), Some(lan)) => {
                        let window = self.nss.node_windows.update(snapshot, lan);
                        let live = !matches!(
                            window.quality,
                            WindowQuality::CounterReset | WindowQuality::CounterSkew
                        );
                        let degraded = matches!(
                            window.quality,
                            WindowQuality::Warmup
                                | WindowQuality::CounterReset
                                | WindowQuality::CounterSkew
                        );
                        let response = window_clients(
                            &window,
                            &identities,
                            conntrack.as_deref(),
                            decision.confidence,
                            &report,
                        );
                        nss_window = Some(window);
                        (response, live, degraded, true)
                    }
                    _ => (
                        ClientsResponse::empty(evidence(&report, "clients")),
                        false,
                        true,
                        false,
                    ),
                }
            } else if decision.rate == RateCollector::NssEcmBpf {
                let ecm_bpf_current =
                    ecm_bpf_snapshot_current(ecm_bpf_snapshot.as_ref(), &runtime_health);
                if ecm_bpf_snapshot_fresh {
                    match (ecm_bpf_snapshot.as_ref(), lan_clock.as_ref()) {
                        (Some(snapshot), Some(lan)) if !snapshot.truncated => {
                            let merged = merge_ecm_bpf_coverage_delta(
                                snapshot,
                                nss_tc_snapshot.as_ref(),
                                bpf_snapshot_fresh,
                            );
                            ecm_bpf_coverage_window =
                                Some(self.nss.ecm_bpf_coverage.update(merged.merged, lan));
                            if legacy_nss_rate_window_enabled {
                                let client_deltas = merge_ecm_bpf_client_deltas(
                                    snapshot,
                                    nss_tc_snapshot.as_ref(),
                                    bpf_snapshot_fresh,
                                );
                                let fallback_rates = ecm_bpf_fallback_client_rates(
                                    snapshot,
                                    nss_tc_snapshot.as_ref(),
                                    bpf_snapshot_fresh,
                                );
                                let client_interfaces = ecm_bpf_client_interfaces(
                                    snapshot,
                                    nss_tc_snapshot.as_ref(),
                                    bpf_snapshot_fresh,
                                );
                                ecm_bpf_rate_batch =
                                    self.nss.ecm_bpf_rates.update_with_client_interfaces(
                                        &client_deltas,
                                        &fallback_rates,
                                        &client_interfaces,
                                        lan,
                                        &rate_window_interface_counters(&interfaces),
                                    );
                            } else {
                                self.nss.ecm_bpf_rates = Default::default();
                            }
                            ecm_bpf_coverage_merge = Some(merged);
                        }
                        _ => {
                            self.nss.ecm_bpf_coverage = Default::default();
                            self.nss.ecm_bpf_rates = Default::default();
                        }
                    }
                }
                if legacy_nss_rate_window_enabled
                    && ecm_bpf_rate_batch.is_none()
                    && !ecm_bpf_snapshot_fresh
                {
                    ecm_bpf_rate_batch = lan_clock
                        .as_ref()
                        .and_then(|lan| self.nss.ecm_bpf_rates.held_at(lan.sample_ms));
                }
                (
                    ecm_bpf_clients_response(
                        ecm_bpf_snapshot.as_ref(),
                        nss_tc_snapshot.as_ref().and_then(|snapshot| {
                            (bpf_snapshot_fresh || decision.evidence.retained_fresh_snapshot)
                                .then_some(snapshot)
                        }),
                        bpf_snapshot_fresh
                            && ecm_bpf_coverage_window
                                .as_ref()
                                .is_some_and(|coverage| coverage.aligned),
                        lan_clock.as_ref().map_or(now_ms, |lan| lan.sample_ms),
                        conntrack.as_deref(),
                        &identities,
                        decision.confidence,
                    ),
                    ecm_bpf_current,
                    !ecm_bpf_current,
                    false,
                )
            } else {
                (
                    ClientsResponse::empty(evidence(&report, "clients")),
                    false,
                    true,
                    false,
                )
            };
        if legacy_nss_rate_window_enabled {
            if let Some(batch) = ecm_bpf_rate_batch.as_ref() {
                apply_ecm_bpf_rate_batch(&mut clients, &mut interfaces, batch);
            }
        }
        self.apply_access_edge_rates(
            &mut clients,
            &published_edge,
            &identities,
            conntrack.as_deref(),
            decision.rate,
            decision.confidence,
            ecm_bpf_snapshot.as_ref(),
            ecm_classifier_read_end_ms,
            nss_tc_snapshot.as_ref(),
            bpf_classifier_read_end_ms,
            &runtime_health,
        );
        if explicit_internet_rate_view(self.config.internet_view_mode) {
            // The explicit routed view is owned by the FastRate publication.
            // Do not let the independent Access Edge/kernel interface sample
            // leak into the page while that publication is between windows.
            fast_rate_overlay::apply_routed_interface_rates_from_clients(
                &mut interfaces,
                &clients,
                now_ms,
            );
        } else if active_access_edge_owns_display_rate(
            self.config.access_edge_mode,
            self.config.rate_collector_mode,
        ) {
            NssInterfaceRates::from_published_snapshot(&self.access_edge, &published_edge)
                .apply(&mut interfaces);
        }
        if access_edge_enabled {
            let edge_evidence = access_edge_global_evidence(
                &published_edge,
                &clients,
                self.config.access_edge_mode,
            );
            clients
                .evidence
                .get_or_insert_default()
                .details
                .insert("access_edge".into(), edge_evidence);
        }
        self.hostnames.refresh_from_paths(
            &HostnamePaths::default(),
            now_ms,
            method == ProbeMethod::Reload,
        );
        for client in &mut clients.clients {
            let ips = client.ips.iter().map(String::as_str).collect::<Vec<_>>();
            client.hostname = self.hostnames.lookup(&client.mac, &ips).map(str::to_owned);
        }
        if let Some(snapshot) = conntrack.as_ref() {
            clients.conntrack_entries_seen = Some(snapshot.stats.entries_seen as u64);
            clients.conntrack_entries_matched = Some(snapshot.stats.entries_matched as u64);
            clients.conntrack_parse_errors = Some(snapshot.stats.malformed_lines as u64);
            clients.conn_source = Some(
                if snapshot.stats.netlink_read {
                    "conntrack_netlink"
                } else {
                    "conntrack_procfs"
                }
                .into(),
            );
            clients.conn_collector_mode = Some(self.config.conn_collector_mode.as_str().into());
        }
        if let Some(snapshot) = node_snapshot.as_ref() {
            clients.nss_ecm_nodes_seen = Some(snapshot.stats.nodes_seen as u64);
            clients.nss_ecm_nodes_matched = Some(snapshot.stats.nodes_matched as u64);
            clients.nss_ecm_node_parse_errors = Some(snapshot.stats.malformed_lines as u64);
        }
        if clients.evidence.is_none() {
            clients.evidence = Some(evidence(&report, "clients"));
        }
        if let Some(client_evidence) = clients.evidence.as_mut() {
            apply_decision_evidence(client_evidence, &decision, &self.config, &report);
            apply_nss_snapshot_evidence(client_evidence, node_snapshot.as_ref());
            apply_ecm_bpf_evidence(client_evidence, &runtime_health, ecm_bpf_snapshot.as_ref());
            client_evidence.details.insert(
                "classifier_maps".into(),
                classifier_map_evidence(
                    &runtime_health,
                    ecm_bpf_snapshot.as_ref(),
                    ecm_bpf_snapshot_fresh,
                    nss_tc_snapshot.as_ref(),
                    bpf_snapshot_fresh,
                ),
            );
            client_evidence
                .details
                .insert("evidence_lease".into(), self.nss.evidence_lease_evidence());
            client_evidence
                .details
                .insert("rate_mux".into(), self.nss.rate_mux_evidence());
            if let Some(snapshot) = conntrack.as_deref() {
                client_evidence.details.insert(
                    "conntrack_generation".into(),
                    conntrack_generation_evidence(snapshot),
                );
            }
            if let Some(window) = nss_window.as_ref() {
                client_evidence
                    .details
                    .insert("nss_window".into(), window_evidence(window));
            }
            if let Some(coverage) = ecm_bpf_coverage_window.as_ref() {
                client_evidence.details.insert(
                    "ecm_bpf_coverage_window".into(),
                    coverage_evidence(
                        coverage,
                        ecm_bpf_coverage_merge
                            .map_or("ecm_nss_hardware_delta", |value| value.source),
                    ),
                );
                if let Some(merged) = ecm_bpf_coverage_merge {
                    client_evidence.details.insert(
                        "ecm_bpf_coverage_merge".into(),
                        ecm_bpf_coverage_merge_evidence(merged),
                    );
                }
            }
            if let Some(batch) = ecm_bpf_rate_batch.as_ref() {
                client_evidence.details.insert(
                    "ecm_bpf_rate_window".into(),
                    ecm_bpf_rate_batch_evidence(batch),
                );
            }
        }
        self.refresh_controls(&mut clients);
        let overview = self.update_overview(now_ms, &clients);
        let coverage = match decision.rate {
            RateCollector::NssEcmNode | RateCollector::NssEcmBpf => {
                let sample_skew_ms = active_access_edge_owns_display_rate(
                    self.config.access_edge_mode,
                    self.config.rate_collector_mode,
                )
                .then_some(CLASSIFIER_READ_END_SKEW_MS)
                .unwrap_or(0);
                nss_rate_coverage(&clients, &interfaces, sample_skew_ms)
            }
            RateCollector::Bpf if report.facts.nss.present => {
                self.nss_bpf_coverage
                    .update(now_ms, &clients, &interfaces, coverage_fresh)
            }
            _ => self
                .x86_coverage
                .update(now_ms, &clients, &interfaces, coverage_fresh),
        };
        let sysdevices = sysdevices(&self.config)?;
        let mut capabilities = capabilities(&report.capabilities, &report);
        capabilities.live_metrics = actual_live;
        capabilities.conntrack_fallback = false;
        // BPF remains an active slow-path observer on NSS even when conntrack
        // sync is the authoritative rate source.  Runtime capability must
        // describe the healthy attachment/map, not whether BPF is primary.
        capabilities.bpf_runtime_metrics = runtime_health.bpf_object_loaded
            && runtime_health.bpf_attached
            && bpf_snapshot.is_some()
            && (runtime_health.bpf_map_read_ok || decision.evidence.retained_fresh_snapshot);
        capabilities.bpf = capabilities.bpf_runtime_metrics;
        if capabilities.bpf_runtime_metrics {
            // A loaded object, attached hooks, and a readable map are stronger
            // evidence than the wording/exit status of `tc help`.
            capabilities.bpf_supported = true;
            capabilities.bpf_package = true;
            capabilities.bpf_object = true;
            capabilities.tc = true;
            capabilities.tc_clsact = true;
        }
        let mode = if decision.mode == ProbeMode::Unsupported {
            Mode::Unsupported
        } else if !actual_live || actual_degraded || !identity_errors.is_empty() {
            Mode::Degraded
        } else {
            mode(decision.mode)
        };
        let confidence = if mode == Mode::Unsupported {
            Confidence::Unsupported
        } else if !actual_live || !identity_errors.is_empty() {
            Confidence::Low
        } else {
            confidence(decision.confidence)
        };
        let mut status_evidence = runtime_evidence(
            &report,
            method.as_str(),
            &self.config,
            &runtime_health,
            self.bpf_error_stage,
        );
        if matches!(
            decision.rate,
            RateCollector::NssEcmNode | RateCollector::NssEcmBpf
        ) {
            status_evidence.details.insert(
                "coverage_alignment".into(),
                json!({
                    "source": "same_snapshot_displayed_client_and_lan_rates",
                    "sample_ms": interfaces.monotonic_ms,
                    "window_ms": coverage.window_ms,
                    "raw_counter_window_role": if decision.rate == RateCollector::NssEcmBpf {
                        "client_interface_rate_alignment_and_fusion"
                    } else {
                        "diagnostic_and_rate_fusion_guard_only"
                    },
                    "percentage_clamp": false,
                }),
            );
        }
        apply_decision_evidence(&mut status_evidence, &decision, &self.config, &report);
        apply_nss_snapshot_evidence(&mut status_evidence, node_snapshot.as_ref());
        apply_ecm_bpf_evidence(
            &mut status_evidence,
            &runtime_health,
            ecm_bpf_snapshot.as_ref(),
        );
        status_evidence.details.insert(
            "classifier_maps".into(),
            classifier_map_evidence(
                &runtime_health,
                ecm_bpf_snapshot.as_ref(),
                ecm_bpf_snapshot_fresh,
                nss_tc_snapshot.as_ref(),
                bpf_snapshot_fresh,
            ),
        );
        status_evidence
            .details
            .insert("evidence_lease".into(), self.nss.evidence_lease_evidence());
        status_evidence
            .details
            .insert("rate_mux".into(), self.nss.rate_mux_evidence());
        if let Some(window) = nss_window.as_ref() {
            status_evidence
                .details
                .insert("nss_window".into(), window_evidence(window));
        }
        if let Some(coverage) = ecm_bpf_coverage_window.as_ref() {
            status_evidence.details.insert(
                "ecm_bpf_coverage_window".into(),
                coverage_evidence(
                    coverage,
                    ecm_bpf_coverage_merge.map_or("ecm_nss_hardware_delta", |value| value.source),
                ),
            );
            if let Some(merged) = ecm_bpf_coverage_merge {
                status_evidence.details.insert(
                    "ecm_bpf_coverage_merge".into(),
                    ecm_bpf_coverage_merge_evidence(merged),
                );
            }
        }
        if let Some(batch) = ecm_bpf_rate_batch.as_ref() {
            status_evidence.details.insert(
                "ecm_bpf_rate_window".into(),
                ecm_bpf_rate_batch_evidence(batch),
            );
        }
        let mut warnings = report
            .warnings
            .iter()
            .map(|warning| (*warning).to_owned())
            .collect::<Vec<_>>();
        for warning in &decision.warnings {
            if !warnings.iter().any(|value| value == warning) {
                warnings.push((*warning).into());
            }
        }
        retain_collector_warnings(&mut warnings, decision.rate);
        if capabilities.bpf_runtime_metrics {
            warnings.retain(|warning| {
                !matches!(
                    warning.as_str(),
                    "bpf_unsupported"
                        | "tc_clsact_unsupported"
                        | "unsafe_attach"
                        | "bpf_runtime_loader_unavailable"
                        | "bpf_optional_package_missing"
                        | "bpf_object_missing"
                )
            });
        }
        if let Some(error) = &self.nss.node_error {
            status_evidence
                .details
                .insert("nss_runtime_error".into(), json!(error));
        }
        if !actual_live
            && !warnings
                .iter()
                .any(|warning| warning == "live_metrics_unavailable")
        {
            warnings.push("live_metrics_unavailable".into());
        }
        if !identity_errors.is_empty()
            && !warnings
                .iter()
                .any(|warning| warning == "lan_topology_probe_error")
        {
            warnings.push("lan_topology_probe_error".into());
            status_evidence
                .details
                .insert("identity_errors".into(), json!(identity_errors));
        }
        if let Some(snapshot) = conntrack.as_deref() {
            status_evidence.details.insert(
                "conntrack_generation".into(),
                conntrack_generation_evidence(snapshot),
            );
        }
        status_evidence.details.insert(
            "nss_hardware_verifier".into(),
            self.nss.hardware_verifier_evidence(),
        );
        if let Some(fast_s) = self.nss.fast_s_snapshot() {
            status_evidence.details.insert(
                "fast_s_shadow".into(),
                json!({
                    "sample_ms": fast_s.sample_ms,
                    "map_entries": fast_s.map_entries,
                    "valid_entries": fast_s.valid_entries,
                    "invalid_entries": fast_s.invalid_entries,
                    "truncated": fast_s.truncated,
                    "invalid_reads": self.nss.fast_s_invalid_reads(),
                    "invalid_abi": self.nss.fast_s_invalid_abi(),
                    "invalid_generation_mismatch": self.nss.fast_s_invalid_generation_mismatch(),
                    "invalid_sequence": self.nss.fast_s_invalid_sequence(),
                    "invalid_value": self.nss.fast_s_invalid_value(),
                    "invalid_cpu": self.nss.fast_s_invalid_cpu(),
                    "invalid_no_cpu": self.nss.fast_s_invalid_no_cpu(),
                    "invalid_cpu_count": self.nss.fast_s_invalid_cpu_count(),
                    "invalid_cpu_generation": self.nss.fast_s_invalid_cpu_generation(),
                    "last_cpu_generation_expected": self.nss.fast_s_last_cpu_generation_expected(),
                    "last_cpu_generation_actual": self.nss.fast_s_last_cpu_generation_actual(),
                    "reset_generation_changes": self.nss.fast_s_reset_generation_changes(),
                    "truncated_reads": self.nss.fast_s_truncated_reads(),
                    "read_failures": self.nss.fast_s_read_failures(),
                    "owner": "nss_rate_worker",
                    "formal_rate_owner": true,
                }),
            );
        }
        if let Some(fast_n) = self.nss.fast_n_snapshot() {
            status_evidence.details.insert(
                "fast_n_shadow".into(),
                json!({
                    "sample_ms": fast_n.sample_ms,
                    "map_entries": fast_n.map_entries,
                    "valid_entries": fast_n.valid_entries,
                    "invalid_entries": fast_n.invalid_entries,
                    "truncated": fast_n.truncated,
                    "bytes": fast_n.bytes,
                    "packets": fast_n.packets,
                    "reset_generation": fast_n.reset_generation,
                    "owner": "nss_rate_worker",
                    "formal_rate_owner": true,
                }),
            );
        } else if self.nss.fast_n_read_failures() != 0 {
            status_evidence.details.insert(
                "fast_n_shadow".into(),
                json!({
                    "sample_ms": Value::Null,
                    "map_entries": 0,
                    "valid_entries": 0,
                    "invalid_entries": 0,
                    "truncated": false,
                    "read_failures": self.nss.fast_n_read_failures(),
                }),
            );
        }
        let mut fast_client_shadow_entries = 0u64;
        let mut fast_client_shadow_tx_bps = 0u64;
        let mut fast_client_shadow_rx_bps = 0u64;
        let mut fast_client_shadow_routed_tx_bps = 0u64;
        let mut fast_client_shadow_routed_rx_bps = 0u64;
        for client in &clients.clients {
            let Ok(mac) = client.mac.parse::<MacAddress>() else {
                continue;
            };
            let attachment_generation = client.rate_meta.as_ref().map_or(0, |meta| meta.generation);
            if let Some(sample) = self.nss.fast_rate_shadow_client_rate(
                mac.octets(),
                lanspeed_common::DIR_TX,
                &client.identity_key,
                attachment_generation,
            ) {
                fast_client_shadow_entries = fast_client_shadow_entries.saturating_add(1);
                fast_client_shadow_tx_bps =
                    fast_client_shadow_tx_bps.saturating_add(sample.fast_total_bps);
                fast_client_shadow_routed_tx_bps =
                    fast_client_shadow_routed_tx_bps.saturating_add(sample.routed_l2_with_fcs_bps);
            }
            if let Some(sample) = self.nss.fast_rate_shadow_client_rate(
                mac.octets(),
                lanspeed_common::DIR_RX,
                &client.identity_key,
                attachment_generation,
            ) {
                fast_client_shadow_entries = fast_client_shadow_entries.saturating_add(1);
                fast_client_shadow_rx_bps =
                    fast_client_shadow_rx_bps.saturating_add(sample.fast_total_bps);
                fast_client_shadow_routed_rx_bps =
                    fast_client_shadow_routed_rx_bps.saturating_add(sample.routed_l2_with_fcs_bps);
            }
        }
        let fast_rate_telemetry = self.nss.fast_rate_shadow_telemetry();
        if let Some(fast_rate) = self.nss.fast_rate_shadow_latest() {
            let comparison = self.nss.fast_rate_shadow_comparison();
            status_evidence.details.insert(
                "fast_rate_shadow".into(),
                json!({
                    "sample_ms": fast_rate.sample_ms,
                    "window_ms": fast_rate.window_ms,
                    "read_end_skew_ms": fast_rate.read_end_skew_ms,
                    "fast_n_bps": fast_rate.fast_n_bps,
                    "fast_s_bps": fast_rate.fast_s_bps,
                    "fast_total_bps": fast_rate.fast_total_bps,
                    "edge_bps": comparison.and_then(|value| value.edge_bps),
                    "absolute_delta_bps": comparison.and_then(|value| value.absolute_delta_bps),
                    "valid_windows": fast_rate_telemetry.valid_windows,
                    "invalid_windows": fast_rate_telemetry.invalid_windows,
                    "zero_windows": fast_rate_telemetry.zero_windows,
                    "last_invalid_ms": fast_rate_telemetry.last_invalid_ms,
                    "last_zero_latency_ms": fast_rate_telemetry.last_zero_latency_ms,
                    "last_rise_latency_ms": fast_rate_telemetry.last_rise_latency_ms,
                    "last_error": self.nss.fast_rate_shadow_last_error_code(),
                    "client_shadow_entries": fast_client_shadow_entries,
                    "client_shadow_tx_bps": fast_client_shadow_tx_bps,
                    "client_shadow_rx_bps": fast_client_shadow_rx_bps,
                    "client_shadow_routed_l2_with_fcs_tx_bps": fast_client_shadow_routed_tx_bps,
                    "client_shadow_routed_l2_with_fcs_rx_bps": fast_client_shadow_routed_rx_bps,
                    "client_shadow_invalid_windows": self.nss.fast_rate_shadow_client_invalid_windows(),
                    "owner": "nss_rate_worker",
                    "formal_rate_owner": true,
                }),
            );
        } else if fast_rate_telemetry.invalid_windows != 0 {
            status_evidence.details.insert(
                "fast_rate_shadow".into(),
                json!({
                    "sample_ms": Value::Null,
                    "window_ms": Value::Null,
                    "read_end_skew_ms": Value::Null,
                    "fast_n_bps": Value::Null,
                    "fast_s_bps": Value::Null,
                    "fast_total_bps": Value::Null,
                    "valid_windows": fast_rate_telemetry.valid_windows,
                    "invalid_windows": fast_rate_telemetry.invalid_windows,
                    "zero_windows": fast_rate_telemetry.zero_windows,
                    "last_invalid_ms": fast_rate_telemetry.last_invalid_ms,
                    "last_error": self.nss.fast_rate_shadow_last_error_code(),
                    "client_shadow_entries": fast_client_shadow_entries,
                    "client_shadow_tx_bps": fast_client_shadow_tx_bps,
                    "client_shadow_rx_bps": fast_client_shadow_rx_bps,
                    "client_shadow_routed_l2_with_fcs_tx_bps": fast_client_shadow_routed_tx_bps,
                    "client_shadow_routed_l2_with_fcs_rx_bps": fast_client_shadow_routed_rx_bps,
                    "client_shadow_invalid_windows": self.nss.fast_rate_shadow_client_invalid_windows(),
                    "owner": "nss_rate_worker",
                    "formal_rate_owner": true,
                }),
            );
        }
        let version = version();
        let status = StatusResponse {
            mode,
            confidence,
            warnings: warnings.clone(),
            evidence: status_evidence.clone(),
            refresh_interval_ms: self.config.refresh_interval_ms,
            active_client_window_ms: self.config.active_client_window_ms,
            active_client_min_bps: self.config.active_client_min_bps,
            overview_window_samples: self.config.overview_window_samples,
            collector_mode: self.config.rate_collector_mode.as_str().into(),
            rate_collector_mode: self.config.rate_collector_mode.as_str().into(),
            internet_view_mode: self.config.internet_view_mode.as_str().into(),
            access_edge_mode: self.config.access_edge_mode.as_str().into(),
            conn_collector_mode: self.config.conn_collector_mode.as_str().into(),
            version: version.clone(),
            capabilities: capabilities.clone(),
            coverage: Some(coverage),
        };
        let mut health_evidence = runtime_evidence(
            &report,
            "health",
            &self.config,
            &runtime_health,
            self.bpf_error_stage,
        );
        apply_decision_evidence(&mut health_evidence, &decision, &self.config, &report);
        apply_nss_snapshot_evidence(&mut health_evidence, node_snapshot.as_ref());
        apply_ecm_bpf_evidence(
            &mut health_evidence,
            &runtime_health,
            ecm_bpf_snapshot.as_ref(),
        );
        health_evidence.details.insert(
            "classifier_maps".into(),
            classifier_map_evidence(
                &runtime_health,
                ecm_bpf_snapshot.as_ref(),
                ecm_bpf_snapshot_fresh,
                nss_tc_snapshot.as_ref(),
                bpf_snapshot_fresh,
            ),
        );
        health_evidence
            .details
            .insert("evidence_lease".into(), self.nss.evidence_lease_evidence());
        health_evidence
            .details
            .insert("rate_mux".into(), self.nss.rate_mux_evidence());
        if let Some(window) = nss_window.as_ref() {
            health_evidence
                .details
                .insert("nss_window".into(), window_evidence(window));
        }
        if let Some(coverage) = ecm_bpf_coverage_window.as_ref() {
            health_evidence.details.insert(
                "ecm_bpf_coverage_window".into(),
                coverage_evidence(
                    coverage,
                    ecm_bpf_coverage_merge.map_or("ecm_nss_hardware_delta", |value| value.source),
                ),
            );
            if let Some(merged) = ecm_bpf_coverage_merge {
                health_evidence.details.insert(
                    "ecm_bpf_coverage_merge".into(),
                    ecm_bpf_coverage_merge_evidence(merged),
                );
            }
        }
        if let Some(batch) = ecm_bpf_rate_batch.as_ref() {
            health_evidence.details.insert(
                "ecm_bpf_rate_window".into(),
                ecm_bpf_rate_batch_evidence(batch),
            );
        }
        if let Some(error) = &self.nss.node_error {
            health_evidence
                .details
                .insert("nss_runtime_error".into(), json!(error));
        }
        if !identity_errors.is_empty() {
            health_evidence
                .details
                .insert("identity_errors".into(), json!(identity_errors));
        }
        if let Some(snapshot) = conntrack.as_deref() {
            health_evidence.details.insert(
                "conntrack_generation".into(),
                conntrack_generation_evidence(snapshot),
            );
        }
        let health = HealthResponse {
            mode,
            confidence,
            capabilities,
            conflicts: report
                .conflicts
                .iter()
                .map(|item| Conflict {
                    id: item.id.into(),
                    severity: item.severity.into(),
                    message: item.message.into(),
                    evidence: BTreeMap::new(),
                })
                .collect(),
            warnings: warnings.clone(),
            evidence: health_evidence,
        };
        let mut reload_evidence = evidence(&report, "reload");
        apply_decision_evidence(&mut reload_evidence, &decision, &self.config, &report);
        apply_nss_snapshot_evidence(&mut reload_evidence, node_snapshot.as_ref());
        apply_ecm_bpf_evidence(
            &mut reload_evidence,
            &runtime_health,
            ecm_bpf_snapshot.as_ref(),
        );
        let reload = ReloadResponse {
            ok: true,
            mode,
            warnings,
            evidence: reload_evidence,
            version,
        };
        let mut response = ResponseSnapshot::from_responses(
            status, clients, overview, health, reload, interfaces, sysdevices,
        );
        response.replace_traffic_classification(
            self.classification_results
                .iter()
                .map(|(identity, result)| (identity.clone(), traffic_classification(result)))
                .collect(),
        );
        publish_connection_details(&mut response, conntrack.as_deref());
        Ok(response)
    }

    #[cfg(feature = "nss-platform")]
    fn update_access_classification(
        &mut self,
        identities: &IdentityTable,
        ecm: Option<&EcmBpfSnapshot>,
        ecm_new: bool,
        ecm_read_end_ms: Option<u64>,
        slow: Option<&NssTcSnapshot>,
        slow_new: bool,
        slow_read_end_ms: Option<u64>,
        runtime_health: &RuntimeHealth,
    ) {
        if self.config.access_edge_mode == AccessEdgeMode::Off {
            self.access_edge.clear_classification();
            self.classification_results.clear();
            self.cpu_path_probe_book.clear();
            self.cpu_path_probe_windows.clear();
            return;
        }
        let ecm_map_loss = ecm
            .filter(|_| ecm_new)
            .is_some_and(|snapshot| snapshot.truncated)
            || (runtime_health.ecm_bpf_map_read_attempted
                && !runtime_health.ecm_bpf_map_read_ok
                && !ecm_new);
        let slow_map_loss = slow
            .filter(|_| slow_new)
            .is_some_and(|snapshot| !snapshot.map_complete)
            || (runtime_health.bpf_map_read_attempted
                && !runtime_health.bpf_map_read_ok
                && !slow_new);
        let map_loss = ecm_map_loss || slow_map_loss;
        let ecm_window = ecm
            .filter(|snapshot| ecm_new && !snapshot.truncated && snapshot.coverage_ready)
            .and_then(|snapshot| {
                snapshot
                    .coverage_start_ms
                    .map(|start| (start, snapshot.coverage_end_ms))
            });
        let slow_window = slow
            .filter(|snapshot| slow_new && snapshot.map_complete && snapshot.coverage_ready)
            .and_then(|snapshot| {
                snapshot
                    .coverage_start_ms
                    .map(|start| (start, snapshot.coverage_end_ms))
            });
        let (start_ms, end_ms, classifier_window_aligned) =
            match select_classifier_window(ecm_window, slow_window) {
                ClassifierWindowSelection::Ready {
                    start_ms,
                    end_ms,
                    aligned,
                } => (start_ms, end_ms, aligned),
                state => {
                    let state = match state {
                        ClassifierWindowSelection::Invalid => ClassificationState::WindowMismatch,
                        ClassifierWindowSelection::Unavailable if map_loss => {
                            ClassificationState::MapLoss
                        }
                        ClassifierWindowSelection::Unavailable if ecm_new || slow_new => {
                            ClassificationState::Warmup
                        }
                        ClassifierWindowSelection::Unavailable => ClassificationState::Unavailable,
                        ClassifierWindowSelection::Ready { .. } => unreachable!(),
                    };
                    // Invalid or unavailable current windows are negative
                    // evidence, not permission to retain an older Aligned
                    // comparison. The next valid epoch must warm up again.
                    self.access_edge.clear_classification();
                    self.cpu_path_probe_book.clear();
                    self.cpu_path_probe_windows.clear();
                    let mut identity_keys = identities
                        .iter()
                        .map(|identity| identity.key.to_string())
                        .collect::<BTreeSet<_>>();
                    identity_keys.extend(self.classification_results.keys().cloned());
                    if let Some(snapshot) = ecm.filter(|_| ecm_new) {
                        identity_keys.extend(snapshot.coverage_deltas.keys().cloned());
                    }
                    if let Some(snapshot) = slow.filter(|_| slow_new) {
                        identity_keys.extend(snapshot.coverage_deltas.keys().cloned());
                    }
                    self.classification_results = identity_keys
                        .into_iter()
                        .map(|identity_key| (identity_key, ClassificationResult::state(state)))
                        .collect();
                    return;
                }
            };
        let probe_reference_end_ms = slow_read_end_ms.or(ecm_read_end_ms).unwrap_or(end_ms);
        match self.control.nss_path_probe_snapshot(end_ms) {
            Ok(snapshot)
                if snapshot.read_end_ms().abs_diff(probe_reference_end_ms)
                    <= CPU_PATH_PROBE_READ_END_SKEW_MS =>
            {
                self.cpu_path_probe_book.push(snapshot);
            }
            _ => {
                self.cpu_path_probe_book.clear();
                self.cpu_path_probe_windows.clear();
            }
        }
        self.classifier_epoch_id = self.classifier_epoch_id.saturating_add(1);
        let sources_complete = ecm_window.is_some() && slow_window.is_some();
        let edge_clients = self.access_edge.latest().clients.clone();
        let edge_index = edge_mac_index(&edge_clients);
        let identities_by_key = identities
            .iter()
            .map(|identity| (identity.key.to_string(), identity))
            .collect::<BTreeMap<_, _>>();
        let mut identity_keys = identities
            .iter()
            .map(|identity| identity.key.to_string())
            .collect::<BTreeSet<_>>();
        if let Some(snapshot) = ecm.filter(|_| ecm_new) {
            identity_keys.extend(snapshot.coverage_deltas.keys().cloned());
        }
        if let Some(snapshot) = slow.filter(|_| slow_new) {
            identity_keys.extend(snapshot.coverage_deltas.keys().cloned());
        }

        let mut active_results = BTreeMap::new();
        let mut active_probe_windows = BTreeMap::new();
        for identity_key in identity_keys {
            let identity = identities_by_key.get(&identity_key).copied();
            let edge = identity.and_then(|identity| {
                edge_index
                    .unique
                    .get(&identity.key.mac.to_string())
                    .copied()
            });
            let ecm_delta = ecm.filter(|_| ecm_new).map(|snapshot| {
                snapshot
                    .coverage_deltas
                    .get(&identity_key)
                    .copied()
                    .unwrap_or_default()
            });
            let slow_delta = slow.filter(|_| slow_new).map(|snapshot| {
                snapshot
                    .coverage_deltas
                    .get(&identity_key)
                    .copied()
                    .unwrap_or_default()
            });
            let attachment_generation = edge.map_or(0, |sample| sample.attachment.generation);
            let attachment_stable = edge.is_none_or(|sample| {
                !sample.attachment.ambiguous
                    && sample.attachment.stable_observations >= 2
                    && self
                        .access_edge
                        .attachment_topology_complete(&sample.attachment)
            });
            let direction = |direction| DirectionEpoch {
                edge: edge.and_then(|sample| {
                    self.access_edge
                        .aggregate_edge(sample.attachment.key, direction, start_ms, end_ms)
                        .map(comparable_l2_with_fcs)
                }),
                nss: ecm_delta.map(|delta| {
                    comparable_l2_with_fcs(observed_traffic_delta(
                        EdgeRateSource::EcmNssLowerBound,
                        EdgeByteDomain::EcmData,
                        delta,
                        direction,
                        ecm_read_end_ms
                            .or_else(|| ecm.map(|snapshot| snapshot.coverage_end_ms))
                            .unwrap_or(end_ms),
                    ))
                }),
                slow: slow_delta.map(|delta| {
                    comparable_l2_with_fcs(observed_traffic_delta(
                        EdgeRateSource::TcBpfLowerBound,
                        EdgeByteDomain::L2NoFcs,
                        delta,
                        direction,
                        slow_read_end_ms
                            .or_else(|| slow.map(|snapshot| snapshot.coverage_end_ms))
                            .unwrap_or(end_ms),
                    ))
                }),
            };
            let epoch = ClassificationEpoch {
                epoch_id: self.classifier_epoch_id,
                start_ms,
                end_ms,
                attachment_generation,
                attachment_stable,
                map_complete: !map_loss,
                sources_complete,
                classifier_window_aligned,
                tx: direction(EdgeDirection::Tx),
                rx: direction(EdgeDirection::Rx),
            };
            let result = self.access_edge.update_classification(&identity_key, epoch);
            if let (Some(identity), Some(edge), Some(window_start_ms), Some(window_end_ms)) =
                (identity, edge, result.window_start_ms, result.window_end_ms)
            {
                if let Some(window) = self.cpu_path_probe_book.window(
                    &edge.attachment.point.ifname,
                    &identity.key.mac.to_string(),
                    window_start_ms,
                    window_end_ms,
                ) {
                    active_probe_windows.insert(identity_key.clone(), window);
                }
            }
            active_results.insert(identity_key, result);
        }
        self.classification_results = active_results;
        self.cpu_path_probe_windows = active_probe_windows;
    }

    #[cfg(feature = "nss-platform")]
    fn reconcile_evidence_leases(
        &mut self,
        identities: &IdentityTable,
        runtime_health: &RuntimeHealth,
        fast_reads_ready: bool,
        proof_cycle_ready: bool,
    ) {
        let identities = identity_mac_index(identities);
        let observations = self
            .access_edge
            .latest()
            .clients
            .iter()
            .filter_map(|edge| {
                let mac = format_edge_mac(edge.attachment.key.mac);
                let identity = identities.unique.get(&mac)?;
                let identity_key = identity.key.to_string();
                Some(LeaseClientObservation::from_edge(
                    &identity_key,
                    edge,
                    self.classification_results.get(&identity_key),
                    self.access_edge
                        .attachment_topology_complete(&edge.attachment),
                ))
            })
            .collect::<Vec<_>>();
        self.nss.reconcile_evidence_leases(
            runtime_health.now_ms,
            runtime_health,
            fast_reads_ready,
            proof_cycle_ready,
            &observations,
        );
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "nss-platform")]
    fn apply_access_edge_rates(
        &mut self,
        clients: &mut ClientsResponse,
        edge_snapshot: &AccessEdgeSnapshot,
        identities: &IdentityTable,
        conntrack: Option<&CollectedSnapshot>,
        pipeline: RateCollector,
        client_confidence: crate::probe::Confidence,
        ecm: Option<&EcmBpfSnapshot>,
        ecm_read_end_ms: Option<u64>,
        slow: Option<&NssTcSnapshot>,
        slow_read_end_ms: Option<u64>,
        runtime_health: &RuntimeHealth,
    ) {
        let active_auto = active_access_edge_owns_display_rate(
            self.config.access_edge_mode,
            self.config.rate_collector_mode,
        );
        let explicit_internet = explicit_internet_rate_view(self.config.internet_view_mode);
        let rate_mux_active = active_auto || explicit_internet;
        self.nss.begin_rate_mux_cycle(rate_mux_active);
        if self.config.access_edge_mode == AccessEdgeMode::Off && !explicit_internet {
            self.access_edge
                .retain_published_identities(&BTreeSet::new());
            self.classification_results.clear();
            return;
        }
        let edge_index = edge_mac_index(&edge_snapshot.clients);
        let identity_index = identity_mac_index(identities);
        let mut published_identity_keys = clients
            .clients
            .iter()
            .map(|client| client.identity_key.clone())
            .collect::<BTreeSet<_>>();
        let conntrack_by_identity = conntrack.map(|snapshot| {
            let mut index = BTreeMap::new();
            for sample in &snapshot.clients {
                index.entry(sample.identity_key.as_str()).or_insert(sample);
            }
            index
        });

        if rate_mux_active {
            for edge in &edge_snapshot.clients {
                let mac = format_edge_mac(edge.attachment.key.mac);
                let Some(identity) = identity_index.unique.get(&mac).copied() else {
                    continue;
                };
                let identity_key = identity.key.to_string();
                if published_identity_keys.contains(&identity_key)
                    || clients.clients.len() >= self.config.max_clients
                {
                    continue;
                }
                let counts = conntrack_by_identity
                    .as_ref()
                    .and_then(|index| index.get(identity_key.as_str()).copied());
                clients.clients.push(Client {
                    mac: identity.key.mac.to_string(),
                    identity_key: identity_key.clone(),
                    zone: identity.key.zone.clone(),
                    interface: identity.interface.clone(),
                    ips: identity.ips.clone(),
                    hostname: identity.hostname.clone(),
                    rx_bps: 0,
                    tx_bps: 0,
                    last_seen: edge_snapshot.sample_ms,
                    sample_ms: Some(edge_snapshot.sample_ms),
                    rx_bytes: None,
                    tx_bytes: None,
                    collector_mode: pipeline.as_str().to_owned(),
                    confidence: confidence(client_confidence),
                    warnings: Vec::new(),
                    tcp_conns: counts.map(|sample| u64::from(sample.tcp_conns)),
                    udp_conns: counts.map(|sample| u64::from(sample.udp_conns)),
                    udp_dns_conns: counts.map(|sample| u64::from(sample.udp_dns_conns)),
                    udp_other_conns: counts.map(|sample| u64::from(sample.udp_other_conns)),
                    rate_meta: None,
                    control: None,
                });
                published_identity_keys.insert(identity_key);
            }
        }

        for client in &mut clients.clients {
            let connection_only = client
                .warnings
                .iter()
                .any(|warning| warning == "conntrack_connection_only");
            let client_mac_key = mac_lookup_key(&client.mac);
            let edge = identity_index
                .unique
                .get(&client_mac_key)
                .and_then(|_| edge_index.unique.get(&client_mac_key))
                .copied();
            let attachment_generation = edge.map_or(0, |sample| sample.attachment.generation);
            let mut reasons = edge
                .into_iter()
                .flat_map(|sample| {
                    sample
                        .tx
                        .reason_codes
                        .iter()
                        .chain(sample.rx.reason_codes.iter())
                })
                .cloned()
                .collect::<Vec<_>>();
            reasons.extend(edge_snapshot.reason_codes.iter().cloned());
            let attachment_topology_complete =
                edge.map_or(edge_snapshot.topology_complete, |sample| {
                    self.access_edge
                        .attachment_topology_complete(&sample.attachment)
                });
            if !attachment_topology_complete {
                reasons.push("topology_incomplete".to_owned());
            }
            if edge_index.ambiguous.contains(&client_mac_key) {
                reasons.push("duplicate_mac_attachment".to_owned());
            }
            if self.config.access_edge_mode == AccessEdgeMode::Shadow {
                reasons.push("access_edge_shadow".to_owned());
            }
            let lease_observation = edge.map(|edge| {
                LeaseClientObservation::from_edge(
                    &client.identity_key,
                    edge,
                    self.classification_results.get(&client.identity_key),
                    attachment_topology_complete,
                )
            });
            let fast_mac = client
                .mac
                .parse::<MacAddress>()
                .ok()
                .map(MacAddress::octets);
            // FastRate map reads run independently of the collection worker.
            // Its publication timestamp can therefore be a few milliseconds
            // newer than this cycle's health clock; use the publication clock
            // for freshness instead of discarding the completed window.
            let fast_reference_ms = runtime_health
                .now_ms
                .max(self.nss.fast_rate_observed_ms().unwrap_or_default());

            let mut select_direction = |direction: EdgeDirection, old_bps: u64| {
                let edge_direction = edge.map(|sample| match direction {
                    EdgeDirection::Tx => &sample.tx,
                    EdgeDirection::Rx => &sample.rx,
                });
                let edge_candidate = edge_direction.and_then(|observation| {
                    observation.segment.and_then(|segment| {
                        segment
                            .bps()
                            .zip(segment.window_ms())
                            .map(|(bps, window_ms)| RateCandidate {
                                source: segment.source,
                                bps,
                                coverage: observation.coverage,
                                scope: observation.scope,
                                byte_domain: segment.byte_domain,
                                sample_ms: segment.end_ms,
                                window_ms,
                                cadence_ms: ACCESS_EDGE_INTERVAL_MS,
                                attachment_generation,
                                fresh: edge_segment_fresh(
                                    edge_snapshot.sample_ms,
                                    segment.end_ms,
                                    ACCESS_EDGE_INTERVAL_MS,
                                ),
                            })
                    })
                });
                if rate_mux_active {
                    // Formal RateMux never falls through to the legacy NSS rate
                    // window. Automatic mode selects Edge authority or a
                    // lease-authorized same-window FastN+FastS substitute;
                    // the explicit Internet view selects only routed FastN+FastS.
                    // No displaced legacy total may become E: no LAN allocation, previous distribution, directional
                    // max, interface floor, or smoothed rate may become E.
                    let lease_direction =
                        lease_observation
                            .as_ref()
                            .map(|observation| match direction {
                                EdgeDirection::Tx => observation.tx,
                                EdgeDirection::Rx => observation.rx,
                            });
                    let e = lease_direction
                        .map(|observation| e_usability(observation.e))
                        .unwrap_or(EUsability::StructuralEUnavailable);
                    let fast_direction = match direction {
                        EdgeDirection::Tx => lanspeed_common::DIR_TX,
                        EdgeDirection::Rx => lanspeed_common::DIR_RX,
                    };
                    let fast = fast_mac
                        .and_then(|mac| {
                            self.nss.fast_rate_shadow_client_rate(
                                mac,
                                fast_direction,
                                &client.identity_key,
                                attachment_generation,
                            )
                        })
                        .filter(|sample| fast_client_sample_current(fast_reference_ms, *sample));
                    let view = self.nss.select_rate_view(
                        &client.identity_key,
                        direction,
                        e,
                        fast.is_some(),
                        explicit_internet,
                    );
                    return active_rate_direction(view, edge_candidate, fast);
                }
                let mut candidates = edge_candidate.into_iter().collect::<Vec<_>>();
                candidates.extend(classifier_rate_candidates(
                    &client.identity_key,
                    direction,
                    attachment_generation,
                    ecm,
                    ecm_read_end_ms,
                    slow,
                    slow_read_end_ms,
                    runtime_health,
                ));
                let edge_failure = edge_direction.and_then(|observation| observation.failure);
                // Keep the failure boundary explicit even though current Edge
                // observations make `segment` and `failure` mutually exclusive.
                // A future collector change must not allow a failed, higher-
                // priority Edge candidate to re-enter promotion ahead of the
                // independent classifier fallback.
                remove_failed_edge_candidates(&mut candidates, edge_failure);
                let classifier_loss = ecm.is_some_and(|snapshot| snapshot.truncated)
                    || slow.is_some_and(|snapshot| !snapshot.map_complete)
                    || (runtime_health.ecm_bpf_map_read_attempted
                        && !runtime_health.ecm_bpf_map_read_ok)
                    || (runtime_health.bpf_map_read_attempted && !runtime_health.bpf_map_read_ok);
                let has_edge_candidate = candidates.iter().any(|candidate| {
                    matches!(
                        candidate.source,
                        EdgeRateSource::EdgePort | EdgeRateSource::EdgeWifi
                    )
                });
                let has_classifier_candidate = candidates.iter().any(|candidate| {
                    matches!(
                        candidate.source,
                        EdgeRateSource::EcmBpfFallback
                            | EdgeRateSource::EcmNssLowerBound
                            | EdgeRateSource::TcBpfLowerBound
                    )
                });
                // Edge failures are source-scoped. They invalidate an Edge
                // owner or challenger immediately, while an independent
                // classifier owner on the same attachment continues under its
                // own freshness policy. A generation change still demotes all
                // paths inside the mux.
                if edge_failure.is_some() {
                    self.access_edge.invalidate_edge_mux(
                        &client.identity_key,
                        direction,
                        attachment_generation,
                    );
                }
                let mut failure = None;
                let mux_owner = self.access_edge.mux_owner(&client.identity_key, direction);
                if failure.is_none()
                    && classifier_map_loss_invalidates_owner(
                        mux_owner,
                        has_edge_candidate,
                        has_classifier_candidate,
                        classifier_loss,
                    )
                {
                    failure = Some(MuxFailure::MapLoss);
                }
                let selected = self.access_edge.update_mux(
                    &client.identity_key,
                    direction,
                    // ECM/TC are sampled immediately after Edge and can have a
                    // later read-end timestamp. Use the completed collection's
                    // monotonic time for freshness; using the earlier Edge time
                    // would reject a valid classifier fallback as "future".
                    runtime_health.now_ms,
                    attachment_generation,
                    &candidates,
                    failure,
                );
                let _ = selected;
                pipeline_direction(
                    pipeline,
                    old_bps,
                    client.sample_ms,
                    self.config.refresh_interval_ms,
                    connection_only,
                )
            };

            let tx = select_direction(EdgeDirection::Tx, client.tx_bps);
            let rx = select_direction(EdgeDirection::Rx, client.rx_bps);
            if tx.source == ModelRateSource::FastRoutedLease {
                reasons.push("tx_transient_evidence_lease_substitute".to_owned());
            }
            if rx.source == ModelRateSource::FastRoutedLease {
                reasons.push("rx_transient_evidence_lease_substitute".to_owned());
            }
            if tx.source == ModelRateSource::FastRoutedInternet {
                reasons.push("tx_explicit_internet_routed_view".to_owned());
            }
            if rx.source == ModelRateSource::FastRoutedInternet {
                reasons.push("rx_explicit_internet_routed_view".to_owned());
            }
            replace_displaced_nss_rate_reason(&mut reasons, tx.source, rx.source);
            if rate_mux_active {
                client.tx_bps = tx.bps;
                client.rx_bps = rx.bps;
                // `collector_mode` names the pipeline that owns the published
                // total. Directional ownership remains in rate_meta; retaining
                // the identity's legacy conntrack/NSS origin here makes the
                // response internally contradictory and can hide the row from
                // clients that align batches by collector.
                client.collector_mode =
                    published_rate_collector_mode(active_auto, &client.collector_mode).to_owned();
                client.sample_ms = match (tx.sample_ms, rx.sample_ms) {
                    (Some(left), Some(right)) => Some(left.max(right)),
                    (Some(value), None) | (None, Some(value)) => Some(value),
                    (None, None) => client.sample_ms,
                };
                if tx.mux_owner || rx.mux_owner {
                    // The legacy pipeline may have introduced this identity as
                    // conntrack-only before Access Edge supplied a real owner.
                    // Once either direction is measured it is no longer a
                    // connection-only client in the published contract.
                    client
                        .warnings
                        .retain(|warning| warning != "conntrack_connection_only");
                }
                // Formal RateMux rates are owned exclusively by the selected
                // view. Neither a selected legacy source nor an unavailable /
                // warmup state may expose displaced cumulative totals.
                client.tx_bytes = None;
                client.rx_bytes = None;
            }
            let classification = self
                .classification_results
                .get(&client.identity_key)
                .map(classification_summary);
            if let Some(classification) = classification.as_ref() {
                if classification.state != ClassificationState::Aligned {
                    reasons.push(format!(
                        "classification_{}",
                        classification_state_code(classification.state)
                    ));
                }
            }
            let common_window = (tx.window_ms == rx.window_ms)
                .then_some(tx.window_ms)
                .flatten();
            let summary_sample_ms = compact_rate_sample_ms(tx.sample_ms, rx.sample_ms);
            let summary_stale = tx.stale || rx.stale;
            if tx.window_ms != rx.window_ms {
                reasons.push("direction_window_mismatch".to_owned());
            }
            reasons.sort();
            reasons.dedup();
            reasons.truncate(16);
            client.rate_meta = Some(ClientRateMeta {
                version: 1,
                scope: conservative_scope(tx.scope, rx.scope),
                tx: rate_direction_meta(tx, summary_sample_ms, common_window, summary_stale),
                rx: rate_direction_meta(rx, summary_sample_ms, common_window, summary_stale),
                attachment: edge.map(|sample| model_attachment(&sample.attachment)),
                generation: attachment_generation,
                window_ms: common_window,
                sample_ms: summary_sample_ms,
                stale: summary_stale,
                reason_codes: reasons,
                classification,
            });
        }

        self.access_edge
            .retain_published_identities(&published_identity_keys);
        self.classification_results
            .retain(|identity_key, _| published_identity_keys.contains(identity_key));
    }

    fn update_overview(&mut self, now_ms: u64, response: &ClientsResponse) -> OverviewResponse {
        let clients = response
            .clients
            .iter()
            .map(|client| OverviewClient {
                tx_bps: client.tx_bps,
                rx_bps: client.rx_bps,
                sample_ms: client.sample_ms.unwrap_or(now_ms),
                last_seen_ms: client.last_seen,
                nss_activity: matches!(
                    client.collector_mode.as_str(),
                    "access_edge" | "nss_ecm_node" | "nss_ecm_bpf"
                ),
                connections: ConnectionTotals::new(
                    client.tcp_conns.unwrap_or(0),
                    client.udp_conns.unwrap_or(0),
                    client.udp_dns_conns.unwrap_or(0),
                    client.udp_other_conns.unwrap_or(0),
                ),
            })
            .collect::<Vec<_>>();
        let config = OverviewConfig {
            window_samples: self.config.overview_window_samples,
            active_client_window_ms: self.config.active_client_window_ms,
            active_client_min_bps: self.config.active_client_min_bps,
        };
        self.overview.push(
            now_ms,
            &clients,
            ConnectionTotalsOverride::default(),
            &config,
        );
        let value = self.overview.to_json(&config);
        OverviewResponse {
            samples: value["samples"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .map(|sample| OverviewSample {
                    sample_ms: sample["sample_ms"].as_u64().unwrap_or(0),
                    tx_bps: sample["tx_bps"].as_u64().unwrap_or(0),
                    rx_bps: sample["rx_bps"].as_u64().unwrap_or(0),
                    client_count: sample["client_count"].as_u64().unwrap_or(0) as u32,
                    active_clients: sample["active_clients"].as_u64().unwrap_or(0) as u32,
                    tcp_conns: sample
                        .get("tcp_conns")
                        .and_then(Value::as_u64)
                        .map(|v| v as u32),
                    udp_conns: sample
                        .get("udp_conns")
                        .and_then(Value::as_u64)
                        .map(|v| v as u32),
                    udp_dns_conns: sample
                        .get("udp_dns_conns")
                        .and_then(Value::as_u64)
                        .map(|v| v as u32),
                    udp_other_conns: sample
                        .get("udp_other_conns")
                        .and_then(Value::as_u64)
                        .map(|v| v as u32),
                })
                .collect(),
            max_samples: 240,
            overview_window_samples: self.config.overview_window_samples,
            active_client_window_ms: self.config.active_client_window_ms,
            active_client_min_bps: self.config.active_client_min_bps,
            sample_source: OVERVIEW_SAMPLE_SOURCE.into(),
            conn_semantics: CONNECTION_SEMANTICS.into(),
        }
    }

    #[cfg(feature = "nss-platform")]
    fn interfaces(
        &mut self,
        now_ms: u64,
        extra_names: &BTreeSet<String>,
    ) -> (
        InterfacesResponse,
        Option<LanClock>,
        InterfaceCounterSnapshot,
    ) {
        let roles = collect_ifnames_with_roles(&self.config);
        let lan_roots = roles
            .iter()
            .filter_map(|(name, role)| (*role == InterfaceRole::Lan).then_some(name.clone()))
            .collect::<Vec<_>>();
        let masters = interface_masters();
        let lan_boundaries = independent_lan_boundaries(&lan_roots, &masters);
        let mut names_to_read = roles
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(boundaries) = lan_boundaries.as_ref() {
            names_to_read.extend(boundaries.iter().cloned());
        }
        names_to_read.extend(extra_names.iter().cloned());
        let counter_snapshot = read_interface_counter_snapshot(&names_to_read);
        let raw_counters = &counter_snapshot.counters;
        let mut interfaces = Vec::new();
        for (name, role) in roles {
            let boundary_names = (role == InterfaceRole::Lan)
                .then(|| independent_lan_boundaries(std::slice::from_ref(&name), &masters))
                .flatten();
            let interface = match interface_display_counters(
                &name,
                role,
                boundary_names.as_deref(),
                raw_counters,
            ) {
                Some(display) => {
                    let sampled_names = boundary_names
                        .as_deref()
                        .unwrap_or_else(|| std::slice::from_ref(&name));
                    let counter_source = counter_snapshot
                        .source_for(sampled_names.iter().map(String::as_str))
                        .unwrap_or(MIXED_INTERFACE_SOURCE);
                    let (rx_bps, tx_bps, delta_ms) = if role == InterfaceRole::Lan {
                        self.interface_rates.update_windowed(
                            &name,
                            display,
                            now_ms,
                            LAN_INTERFACE_RATE_WINDOW_MS,
                        )
                    } else {
                        self.interface_rates.update(&name, display, now_ms)
                    };
                    Interface {
                        name,
                        role,
                        status: InterfaceStatus::Available,
                        rx_bytes: Some(display.rx_bytes),
                        tx_bytes: Some(display.tx_bytes),
                        rx_bps: Some(rx_bps),
                        tx_bps: Some(tx_bps),
                        delta_ms: Some(delta_ms),
                        sample_ms: Some(now_ms),
                        source: Some(if role == InterfaceRole::Lan {
                            format!("{counter_source} + real packets * 4-byte FCS")
                        } else {
                            counter_source.into()
                        }),
                        coverage: Some(if role == InterfaceRole::Lan {
                            format!(
                                "independent_lan_boundary:{}",
                                boundary_names.as_deref().unwrap_or_default().join("+")
                            )
                        } else {
                            "kernel_netdev_statistics".into()
                        }),
                        evidence: None,
                    }
                }
                None => Interface {
                    name,
                    role,
                    status: InterfaceStatus::Missing,
                    rx_bytes: Some(0),
                    tx_bytes: Some(0),
                    rx_bps: Some(0),
                    tx_bps: Some(0),
                    delta_ms: Some(0),
                    sample_ms: Some(now_ms),
                    source: Some(
                        "counter unavailable after /proc/net/dev and sysfs fallback".into(),
                    ),
                    coverage: Some("includes_hardware_offload_and_switch_bridge".into()),
                    evidence: None,
                },
            };
            interfaces.push(interface);
        }
        let lan_clock = lan_boundaries.and_then(|boundaries| {
            let counters = sum_interface_counters(&boundaries, &raw_counters)?;
            Some(LanClock {
                interface: boundaries.join("+"),
                sample_ms: now_ms,
                counters: TrafficCounters {
                    tx_bytes: counters.tx_bytes,
                    rx_bytes: counters.rx_bytes,
                    tx_packets: counters.tx_packets,
                    rx_packets: counters.rx_packets,
                },
            })
        });
        (
            InterfacesResponse {
                interfaces,
                monotonic_ms: Some(now_ms),
                note: Some(INTERFACE_NOTE.into()),
                evidence: None,
            },
            lan_clock,
            counter_snapshot,
        )
    }

    #[cfg(not(feature = "nss-platform"))]
    fn interfaces_x86(&mut self, now_ms: u64) -> (InterfacesResponse, InterfaceCounterSnapshot) {
        let roles = collect_ifnames_with_roles(&self.config);
        let lan_roots = roles
            .iter()
            .filter_map(|(name, role)| (*role == InterfaceRole::Lan).then_some(name.clone()))
            .collect::<Vec<_>>();
        let masters = interface_masters();
        let lan_boundaries = independent_lan_boundaries(&lan_roots, &masters);
        let mut names_to_read = roles
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(boundaries) = lan_boundaries.as_ref() {
            names_to_read.extend(boundaries.iter().cloned());
        }
        let counter_snapshot = read_interface_counter_snapshot(&names_to_read);
        let raw_counters = &counter_snapshot.counters;
        let interfaces = roles
            .into_iter()
            .map(|(name, role)| {
                let boundary_names = (role == InterfaceRole::Lan)
                    .then(|| independent_lan_boundaries(std::slice::from_ref(&name), &masters))
                    .flatten();
                match interface_display_counters(
                    &name,
                    role,
                    boundary_names.as_deref(),
                    raw_counters,
                ) {
                    Some(display) => {
                        let sampled_names = boundary_names
                            .as_deref()
                            .unwrap_or_else(|| std::slice::from_ref(&name));
                        let counter_source = counter_snapshot
                            .source_for(sampled_names.iter().map(String::as_str))
                            .unwrap_or(MIXED_INTERFACE_SOURCE);
                        let (rx_bps, tx_bps, delta_ms) = if role == InterfaceRole::Lan {
                            self.interface_rates.update_windowed(
                                &name,
                                display,
                                now_ms,
                                LAN_INTERFACE_RATE_WINDOW_MS,
                            )
                        } else {
                            self.interface_rates.update(&name, display, now_ms)
                        };
                        Interface {
                            name,
                            role,
                            status: InterfaceStatus::Available,
                            rx_bytes: Some(display.rx_bytes),
                            tx_bytes: Some(display.tx_bytes),
                            rx_bps: Some(rx_bps),
                            tx_bps: Some(tx_bps),
                            delta_ms: Some(delta_ms),
                            sample_ms: Some(now_ms),
                            source: Some(if role == InterfaceRole::Lan {
                                format!("{counter_source} + real packets * 4-byte FCS")
                            } else {
                                counter_source.into()
                            }),
                            coverage: Some(if role == InterfaceRole::Lan {
                                format!(
                                    "independent_lan_boundary:{}",
                                    boundary_names.as_deref().unwrap_or_default().join("+")
                                )
                            } else {
                                "kernel_netdev_statistics".into()
                            }),
                            evidence: None,
                        }
                    }
                    None => Interface {
                        name,
                        role,
                        status: InterfaceStatus::Missing,
                        rx_bytes: Some(0),
                        tx_bytes: Some(0),
                        rx_bps: Some(0),
                        tx_bps: Some(0),
                        delta_ms: Some(0),
                        sample_ms: Some(now_ms),
                        source: Some(
                            "counter unavailable after /proc/net/dev and sysfs fallback".into(),
                        ),
                        coverage: Some("includes_hardware_offload_and_switch_bridge".into()),
                        evidence: None,
                    },
                }
            })
            .collect();
        (
            InterfacesResponse {
                interfaces,
                monotonic_ms: Some(now_ms),
                note: Some(INTERFACE_NOTE.into()),
                evidence: None,
            },
            counter_snapshot,
        )
    }

    #[cfg(not(feature = "nss-platform"))]
    fn refresh_controls(&mut self, clients: &mut ClientsResponse) {
        let tc_topology_probe_failed = self
            .probe_report
            .evidence
            .probe_failures
            .iter()
            .any(|failure| failure.source.starts_with("command:tc_filter_show"));
        if tc_topology_probe_failed {
            self.control.observe_dae_topology_failure(
                self.probe_report.facts.proxy.dae,
                self.config.runtime_collect_ifnames().into_iter().collect(),
            );
        } else {
            let dae_preempted_devices = crate::probe::tc::dae_preempted_lan_ingress_interfaces(
                &self.probe_report.facts.tc.filters,
                &self.config.runtime_collect_ifnames(),
            );
            let dae_upload_devices =
                if !dae_preempted_devices.is_empty() && self.probe_report.facts.proxy.dae {
                    crate::platform::x86::control::dae_upload_devices(&dae_preempted_devices)
                } else {
                    BTreeSet::new()
                };
            self.control.observe_dae_topology(
                self.probe_report.facts.proxy.dae,
                dae_preempted_devices,
                dae_upload_devices,
            );
        }
        self.control.observe_clients(&clients.clients);
        self.reconcile_control_state();
        self.control.decorate_response(clients);
    }

    #[cfg(feature = "nss-platform")]
    fn refresh_controls(&mut self, clients: &mut ClientsResponse) {
        self.control
            .observe_nss_paths(nss_control_path_observations(
                &clients.clients,
                &self.classification_results,
                &self.cpu_path_probe_windows,
            ));
        self.control.observe_clients(&clients.clients);
        self.reconcile_control_state();
        self.control.decorate_response(clients);
    }

    fn reconcile_control_state(&mut self) {
        if self.control_reconcile_pending {
            return;
        }
        #[cfg(feature = "nss-platform")]
        if !self.control_platform_owner {
            self.control.observe_existing_nss_control();
            return;
        }
        self.control_work = self.control.begin_reconcile();
        self.control_reconcile_pending = self.control_work.is_some();
    }

    fn take_control_work(&mut self) -> Option<ControlReconcileWork> {
        self.control_work.take()
    }

    fn restore_control_work(&mut self, work: ControlReconcileWork) {
        debug_assert!(self.control_reconcile_pending);
        debug_assert!(self.control_work.is_none());
        self.control_work = Some(work);
    }

    fn finish_control_work(&mut self, outcome: ControlReconcileOutcome, continue_reconcile: bool) {
        if !self.control_reconcile_pending {
            return;
        }
        self.control.finish_reconcile(outcome);
        self.control_reconcile_pending = false;
        if continue_reconcile {
            self.reconcile_control_state();
        }
    }

    fn client_control_set(&mut self, request: ClientControlRequest) -> Result<Value, DaemonError> {
        let identity_key = request.identity_key.clone();
        let _ = self.control.set(request)?;
        self.reconcile_control_state();
        Ok(self.control.response(&identity_key))
    }

    fn client_control_delete(
        &mut self,
        request: ClientControlDeleteRequest,
    ) -> Result<Value, DaemonError> {
        let identity_key = request.identity_key.clone();
        let _ = self.control.delete(request)?;
        self.reconcile_control_state();
        Ok(self.control.response(&identity_key))
    }

    #[cfg(feature = "nss-platform")]
    fn fast_rate_sources(&mut self) -> Result<Option<FastRateSources>, String> {
        let Some(ecm_bpf) = self.nss.ecm_bpf.as_mut() else {
            return Ok(None);
        };
        let s_reader = self
            .adapter
            .routed_fast_counter_reader()
            .map_err(|error| error.to_string())?;
        let n_reader = ecm_bpf.fast_n_reader().map_err(|error| error.to_string())?;
        let event_reader = ecm_bpf.take_event_hint_reader();
        Ok(Some(FastRateSources::new(n_reader, s_reader, event_reader)))
    }

    #[cfg(feature = "nss-platform")]
    fn apply_fast_event_telemetry(
        &mut self,
        telemetry: crate::platform::nss::ecm_bpf::EcmEventHintTelemetry,
    ) {
        if let Some(ecm_bpf) = self.nss.ecm_bpf.as_mut() {
            ecm_bpf.apply_event_hint_telemetry(telemetry);
        }
    }

    fn shutdown(&mut self) -> Result<(), DaemonError> {
        if self.shutdown_complete {
            return Ok(());
        }
        let mut failures = Vec::new();
        if let Some(runtime) = self.bpf.as_mut() {
            if let Err(error) = runtime.shutdown(&mut self.adapter) {
                failures.push(format!("TC-BPF shutdown: {error}"));
            }
        }
        #[cfg(not(feature = "nss-platform"))]
        if let Err(error) = self.control.cleanup() {
            failures.push(format!("client control shutdown: {error}"));
        }
        #[cfg(feature = "nss-platform")]
        if self.control_platform_owner {
            if let Err(error) = self.control.cleanup() {
                failures.push(format!("client control shutdown: {error}"));
            }
        }
        #[cfg(feature = "nss-platform")]
        if let Err(error) = self.nss.shutdown() {
            failures.push(format!("ECM+BPF shutdown: {error}"));
        }
        if !failures.is_empty() {
            return Err(DaemonError::collection(failures.join("; ")));
        }
        self.shutdown_complete = true;
        Ok(())
    }
}

#[cfg(feature = "nss-platform")]
fn replace_displaced_nss_rate_reason(
    reasons: &mut Vec<String>,
    tx: ModelRateSource,
    rx: ModelRateSource,
) {
    let fast_rate_selected = [tx, rx].into_iter().any(|source| {
        matches!(
            source,
            ModelRateSource::FastRoutedInternet | ModelRateSource::FastRoutedLease
        )
    });
    if !fast_rate_selected {
        return;
    }
    reasons.retain(|reason| reason != "nss_low_rate_rolling_window");
    reasons.push("nss_fast_rate_rolling_window".to_owned());
}

#[cfg(feature = "nss-platform")]
fn nss_control_path_observations(
    clients: &[Client],
    results: &BTreeMap<String, ClassificationResult>,
    probe_windows: &BTreeMap<String, PathProbeWindow>,
) -> BTreeMap<String, NssPathObservation> {
    clients
        .iter()
        .filter(|client| {
            client
                .rate_meta
                .as_ref()
                .and_then(|meta| meta.attachment.as_ref())
                .is_some_and(|attachment| {
                    attachment.ifname.is_some()
                        && matches!(
                            attachment.trust,
                            ModelAttachmentTrust::AssociatedStation
                                | ModelAttachmentTrust::ObservedExclusive
                        )
                })
        })
        .filter_map(|client| {
            let result = results.get(&client.identity_key)?;
            let wifi_attachment = client
                .rate_meta
                .as_ref()
                .and_then(|meta| meta.attachment.as_ref())
                .is_some_and(|attachment| attachment.kind == ModelAttachmentKind::Wifi);
            let mut observation = NssPathObservation::default();
            for (bit, state, direction, probe) in [
                (
                    NSS_CPU_UPLOAD,
                    result.tx_state,
                    result.tx,
                    probe_windows
                        .get(&client.identity_key)
                        .and_then(|window| window.upload),
                ),
                (
                    NSS_CPU_DOWNLOAD,
                    result.rx_state,
                    result.rx,
                    probe_windows
                        .get(&client.identity_key)
                        .and_then(|window| window.download),
                ),
            ] {
                let (valid, active, proven, nss, cpu) = nss_control_direction_path_for_attachment(
                    state,
                    result.classifier_window_ms,
                    result.comparison_window_ms,
                    direction,
                    probe,
                    wifi_attachment,
                );
                if valid {
                    observation.valid_directions |= bit;
                }
                if active {
                    observation.active_directions |= bit;
                }
                if proven {
                    observation.proven_directions |= bit;
                }
                if nss {
                    observation.nss_directions |= bit;
                }
                if cpu {
                    observation.cpu_directions |= bit;
                }
            }
            Some((client.identity_key.clone(), observation))
        })
        .collect()
}

#[cfg(all(feature = "nss-platform", test))]
fn nss_control_direction_path(
    state: ClassificationState,
    classifier_window_ms: Option<u64>,
    comparison_window_ms: Option<u64>,
    direction: crate::platform::access_edge::DirectionClassification,
    probe: Option<crate::platform::nss::control::PathProbeDirectionWindow>,
) -> (bool, bool, bool, bool, bool) {
    nss_control_direction_path_for_attachment(
        state,
        classifier_window_ms,
        comparison_window_ms,
        direction,
        probe,
        false,
    )
}

#[cfg(feature = "nss-platform")]
fn nss_control_direction_path_for_attachment(
    state: ClassificationState,
    classifier_window_ms: Option<u64>,
    comparison_window_ms: Option<u64>,
    direction: crate::platform::access_edge::DirectionClassification,
    probe: Option<crate::platform::nss::control::PathProbeDirectionWindow>,
    wifi_attachment: bool,
) -> (bool, bool, bool, bool, bool) {
    let complete_window = matches!(
        state,
        ClassificationState::Aligned | ClassificationState::CounterSkew
    ) && comparison_window_ms.is_some();
    let wifi_domain_window = wifi_attachment
        && state == ClassificationState::DomainMismatch
        && comparison_window_ms.is_some();
    let complete_warmup_epoch = state == ClassificationState::Warmup
        && comparison_window_ms.is_none()
        && classifier_window_ms.is_some_and(|window| window != 0)
        && direction.edge_bps.is_some();
    if (!complete_window && !wifi_domain_window && !complete_warmup_epoch)
        || direction.edge_bps.is_none()
    {
        return (false, false, false, false, false);
    }
    let (Some(edge), Some(nss), Some(slow)) =
        (direction.edge_bps, direction.nss_bps, direction.slow_bps)
    else {
        return (false, false, false, false, false);
    };
    if !wifi_attachment && probe.is_none() {
        return (false, false, false, false, false);
    }
    let probe_bps = probe.map_or(0, |value| value.bps);
    let probe_bytes = probe.map_or(0, |value| value.bytes);
    let active = edge != 0 || nss != 0 || slow != 0 || probe_bps != 0;
    if !active {
        return (true, false, false, false, false);
    }
    const MIN_PROBE_BYTES: u64 = 64 * 1024;
    const MIN_PROBE_SLOW_PERCENT: u64 = 75;
    const MAX_PROBE_SLOW_PERCENT: u64 = 125;
    const MAX_PATH_SHARE_PERCENT: u64 = 125;
    let evidence_window_ms = comparison_window_ms.or(classifier_window_ms).unwrap_or(0);
    let probe_matches_cpu_path = probe_bytes >= MIN_PROBE_BYTES
        && edge != 0
        && slow != 0
        && u128::from(probe_bps).saturating_mul(100)
            >= u128::from(slow).saturating_mul(MIN_PROBE_SLOW_PERCENT as u128)
        && u128::from(probe_bps).saturating_mul(100)
            <= u128::from(slow).saturating_mul(MAX_PROBE_SLOW_PERCENT as u128)
        && (wifi_attachment
            || u128::from(slow).saturating_mul(100)
                <= u128::from(edge).saturating_mul(MAX_PATH_SHARE_PERCENT as u128));

    // Access Edge deliberately includes LAN/NAS and router-local frames, while
    // the CPU probe below counts Internet traffic only. Requiring N+S to cover
    // the complete edge therefore deadlocks startup whenever local traffic is
    // active. A current, source-aligned epoch is sufficient to prove each
    // independently observed Internet executor: the bridge probe proves the
    // CPU hook and an ECM hardware delta proves the NSS path. Both are later
    // published into the same aggregate edge queue, never separate buckets.
    // CounterSkew is excluded from NSS proof because it may duplicate proxy
    // bytes; it remains acceptable for independently probed CPU-only traffic.
    let nss_matches_direct_path = if wifi_domain_window {
        edge != 0 && nss != 0 && observed_bytes(nss, evidence_window_ms) >= MIN_PROBE_BYTES
    } else {
        (complete_window || complete_warmup_epoch)
            && matches!(
                state,
                ClassificationState::Aligned | ClassificationState::Warmup
            )
            && edge != 0
            && nss != 0
            && observed_bytes(nss, evidence_window_ms) >= MIN_PROBE_BYTES
            && u128::from(nss).saturating_mul(100)
                <= u128::from(edge).saturating_mul(MAX_PATH_SHARE_PERCENT as u128)
    };

    // A direction becomes publishable after at least one actual Internet
    // executor is proven. If the other executor appears later, ControlManager
    // adds it to this same direction, reapplies transactionally, and requires
    // fresh aggregate class growth before returning to `verified`.
    let fully_proven = probe_matches_cpu_path || nss_matches_direct_path;

    (
        true,
        true,
        fully_proven,
        nss_matches_direct_path,
        probe_matches_cpu_path,
    )
}

#[cfg(feature = "nss-platform")]
fn observed_bytes(bps: u64, window_ms: u64) -> u64 {
    let bytes = u128::from(bps).saturating_mul(u128::from(window_ms)) / 8_000;
    bytes.min(u128::from(u64::MAX)) as u64
}

impl Drop for ProductionRuntime {
    fn drop(&mut self) {
        if !self.shutdown_complete {
            let _ = self.shutdown();
        }
    }
}

impl Runtime for ProductionRuntime {
    type Checkpoint = RuntimeCheckpoint;

    fn checkpoint(&self) -> Self::Checkpoint {
        ProductionRuntime::checkpoint(self)
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        ProductionRuntime::restore(self, checkpoint);
    }

    fn collection_signals(&mut self) -> RuntimeCollectionSignals {
        let process_activity_changed = self.refresh_dae_process_state();
        RuntimeCollectionSignals {
            has_bpf: self.bpf.is_some(),
            process_activity_changed,
            attach_mode_mismatch: self.bpf_attach_mode_mismatch(),
        }
    }

    fn collect(&mut self) -> Result<ResponseSnapshot, DaemonError> {
        // The runtime worker owns the hot-cycle transaction. Candidate reload
        // collection keeps its separate local rollback path.
        self.collect_inner(ProbeMethod::Status, None)
    }

    fn collection_interval_ms(&self, configured_ms: u32) -> u32 {
        effective_collection_interval_ms(
            self.config.access_edge_mode,
            self.config.internet_view_mode,
            self.rate_owner,
            configured_ms,
        )
    }

    fn shutdown(&mut self) -> Result<(), DaemonError> {
        ProductionRuntime::shutdown(self)
    }
}

struct App {
    state: CoordinatorState,
    runtime: Option<ProductionRuntime>,
    ubus: Option<UbusConnection>,
    collection_timer: Option<Timer>,
    collection_deadline_ms: Cell<u64>,
    runtime_worker: Option<RuntimeCollectionWorker<ProductionRuntime>>,
    runtime_notices: Receiver<RuntimeCollectionNotice<ProductionRuntime>>,
    runtime_collection_pending: bool,
    reload_worker: Option<ProductionReloadWorker>,
    reload_notices: Receiver<ReloadNotice>,
    reload_requested: bool,
    reload_pending: bool,
    runtime_notice_timer: Option<Timer>,
    reconnect_timer: Option<Timer>,
    reconnect_pending: Cell<bool>,
    mode_reload: DaeModeReloadLatch,
    last_error: Option<String>,
    conntrack_worker: Option<RuntimeWorker<ConntrackTask>>,
    last_conntrack_request_ms: Cell<u64>,
    control_worker: Option<control_worker::ControlWorker>,
    control_notices: Receiver<ControlWorkerNotice>,
    control_generation: u64,
    control_pending_generation: Option<u64>,
    #[cfg(feature = "nss-platform")]
    fast_rate_worker: Option<fast_rate_worker::FastRateWorker>,
    #[cfg(feature = "nss-platform")]
    fast_rate_notices: Receiver<FastRateWakeupNotice>,
    #[cfg(feature = "nss-platform")]
    fast_rate_timer: Option<Timer>,
}

#[cfg(feature = "nss-platform")]
const fn fast_rate_notices_can_drain(runtime_available: bool) -> bool {
    runtime_available
}

impl App {
    fn collection_tick(&mut self) {
        self.collect_current_tick();
    }

    fn collect_current_tick(&mut self) {
        self.drain_control_notices();
        #[cfg(feature = "nss-platform")]
        self.drain_fast_rate_notices();
        self.drain_runtime_notices();
        self.drain_reload_notices();
        if self.runtime_collection_pending || self.reload_pending {
            self.schedule_runtime_notice_poll();
            return;
        }
        let Some(runtime) = self.runtime.take() else {
            self.last_error = Some("runtime collection ownership unavailable".into());
            self.schedule_collection_retry();
            return;
        };
        let Some(worker) = self.runtime_worker.as_ref() else {
            self.runtime = Some(runtime);
            self.last_error = Some("runtime collection worker unavailable".into());
            self.schedule_collection_retry();
            return;
        };
        match worker.try_collect(runtime, self.state.config().refresh_interval_ms) {
            Ok(()) => {
                self.runtime_collection_pending = true;
                self.schedule_runtime_notice_poll();
            }
            Err((error, runtime)) => {
                self.runtime = Some(runtime);
                self.last_error = Some(match error {
                    QueueError::Full => "runtime collection worker queue full".into(),
                    QueueError::Disconnected => "runtime collection worker disconnected".into(),
                });
                self.schedule_collection_retry();
            }
        }
    }

    fn runtime_notice_tick(&mut self) {
        self.drain_runtime_notices();
        self.drain_reload_notices();
        if self.runtime_collection_pending || self.reload_pending {
            self.schedule_runtime_notice_poll();
        }
    }

    fn drain_runtime_notices(&mut self) {
        while let Ok(notice) = self.runtime_notices.try_recv() {
            if !self.runtime_collection_pending || self.runtime.is_some() {
                let mut runtime = notice.runtime;
                let _ = runtime.shutdown();
                self.last_error = Some("unexpected runtime collection notice".into());
                continue;
            }
            let RuntimeCollectionNotice {
                runtime,
                result,
                collection_interval_ms,
                signals,
            } = notice;
            self.runtime_collection_pending = false;
            self.runtime = Some(runtime);
            let collection_ok = match result {
                Ok(snapshot) => {
                    let now_ms = diagnostic_now_ms(snapshot.interfaces.monotonic_ms.unwrap_or(0));
                    self.state
                        .publish_collection_success(snapshot, now_ms, collection_interval_ms);
                    true
                }
                Err(error) => {
                    let fallback = self.state.snapshot().interfaces.monotonic_ms.unwrap_or(0);
                    self.state.publish_collection_failure(
                        diagnostic_now_ms(fallback),
                        collection_interval_ms,
                        &error,
                    );
                    self.last_error = Some(error.to_string());
                    false
                }
            };
            if let Err(error) = schedule_absolute_collection(
                self.collection_timer
                    .as_ref()
                    .expect("collection timer must be installed"),
                &self.collection_deadline_ms,
                collection_interval_ms,
            ) {
                let message = format!("collection timer failed: {error}");
                self.last_error = Some(message.clone());
                *self.state.fatal_cell().borrow_mut() = Some(message);
                UloopGuard::request_stop();
                return;
            }
            let mode_ready = self.handle_collection_signals(signals);
            if collection_ok && mode_ready && !self.reload_requested {
                self.queue_control_work();
            }
            self.drain_control_notices();
            #[cfg(feature = "nss-platform")]
            self.drain_fast_rate_notices();
            self.schedule_conntrack(false);
        }
    }

    fn handle_collection_signals(&mut self, signals: RuntimeCollectionSignals) -> bool {
        if !self.mode_reload.observe(
            signals.has_bpf,
            signals.process_activity_changed,
            signals.attach_mode_mismatch,
        ) {
            return true;
        }
        if self.reload_requested {
            return false;
        }
        match self.queue_reload() {
            Ok(()) => false,
            Err(error) => {
                self.last_error = Some(error.to_string());
                if self.state.fatal_error().is_some() {
                    UloopGuard::request_stop();
                }
                false
            }
        }
    }

    fn recover_runtime_worker_notice(&mut self) {
        while let Ok(notice) = self.runtime_notices.try_recv() {
            if self.runtime.is_none() {
                self.runtime_collection_pending = false;
                self.runtime = Some(notice.runtime);
            } else {
                let mut runtime = notice.runtime;
                let _ = runtime.shutdown();
            }
        }
    }

    fn recover_reload_worker_notice(&mut self) {
        while let Ok(notice) = self.reload_notices.try_recv() {
            self.reload_pending = false;
            let mut recovered = notice.outcome.into_runtime();
            if self.runtime.is_none() {
                self.runtime = Some(recovered);
            } else {
                let _ = recovered.shutdown();
            }
        }
    }

    fn queue_reload(&mut self) -> Result<(), DaemonError> {
        self.drain_control_notices();
        if self.reload_pending {
            return Err(DaemonError::reload("runtime reload pending"));
        }
        if self.runtime_collection_pending {
            return Err(DaemonError::reload("runtime collection pending"));
        }
        if self.control_pending_generation.is_some()
            || self
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.control_reconcile_pending)
        {
            return Err(DaemonError::reload("control transaction pending"));
        }
        let runtime = self
            .runtime
            .take()
            .ok_or_else(|| DaemonError::reload("runtime is not started"))?;
        let Some(worker) = self.reload_worker.as_ref() else {
            self.runtime = Some(runtime);
            return Err(DaemonError::reload("runtime reload worker unavailable"));
        };
        match worker.try_reload(runtime) {
            Ok(()) => {
                self.reload_pending = true;
                self.schedule_runtime_notice_poll();
                Ok(())
            }
            Err((error, runtime)) => {
                self.runtime = Some(runtime);
                Err(DaemonError::reload(match error {
                    QueueError::Full => "runtime reload worker queue full",
                    QueueError::Disconnected => "runtime reload worker disconnected",
                }))
            }
        }
    }

    fn reload_bounded(&mut self) -> Result<(), DaemonError> {
        if self.reload_requested || self.reload_pending {
            return Err(DaemonError::reload("runtime reload pending"));
        }
        self.reload_requested = true;
        let deadline = Instant::now() + Duration::from_millis(RELOAD_WAIT_MS);
        if let Err(error) = self.wait_for_runtime_ownership(deadline) {
            self.reload_requested = false;
            self.schedule_runtime_notice_poll();
            return Err(error);
        }
        self.reload_requested = false;
        if let Err(error) = self.queue_reload() {
            if let Some(runtime) = self.runtime.as_mut() {
                runtime.reconcile_control_state();
            }
            self.queue_control_work();
            return Err(error);
        }
        if let Ok(notice) = self.reload_notices.try_recv() {
            return self.finish_reload_notice(notice);
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            self.schedule_runtime_notice_poll();
            return Err(DaemonError::reload("runtime reload pending"));
        };
        match self.reload_notices.recv_timeout(remaining) {
            Ok(notice) => self.finish_reload_notice(notice),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.schedule_runtime_notice_poll();
                Err(DaemonError::reload("runtime reload pending"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.reload_pending = false;
                let message = "runtime reload worker disconnected";
                self.last_error = Some(message.into());
                *self.state.fatal_cell().borrow_mut() = Some(message.into());
                UloopGuard::request_stop();
                Err(DaemonError::reload(message))
            }
        }
    }

    fn wait_for_runtime_ownership(&mut self, deadline: Instant) -> Result<(), DaemonError> {
        while self.runtime_collection_pending || self.control_pending_generation.is_some() {
            self.drain_runtime_notices();
            self.drain_control_notices();
            if !self.runtime_collection_pending && self.control_pending_generation.is_none() {
                break;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(DaemonError::reload("runtime collection pending"));
            };
            std::thread::sleep(
                remaining.min(Duration::from_millis(u64::from(RUNTIME_NOTICE_POLL_MS))),
            );
        }
        Ok(())
    }

    fn drain_reload_notices(&mut self) {
        while let Ok(notice) = self.reload_notices.try_recv() {
            if let Err(error) = self.finish_reload_notice(notice) {
                self.last_error = Some(error.to_string());
            }
        }
    }

    fn finish_reload_notice(&mut self, notice: ReloadNotice) -> Result<(), DaemonError> {
        if !self.reload_pending || self.runtime.is_some() {
            let mut runtime = notice.outcome.into_runtime();
            let _ = runtime.shutdown();
            return Err(DaemonError::reload("unexpected runtime reload notice"));
        }
        self.reload_pending = false;
        match notice.outcome {
            ReloadOutcome::Success(success) => {
                let interval = success
                    .runtime
                    .collection_interval_ms(success.config.refresh_interval_ms);
                if let Err(error) = schedule_absolute_collection(
                    self.collection_timer
                        .as_ref()
                        .expect("collection timer must be installed"),
                    &self.collection_deadline_ms,
                    interval,
                ) {
                    let message = format!("reload committed; collection timer failed: {error}");
                    self.runtime = Some(success.runtime);
                    self.last_error = Some(message.clone());
                    *self.state.fatal_cell().borrow_mut() = Some(message.clone());
                    UloopGuard::request_stop();
                    return Err(DaemonError::reload(message));
                }
                let now_ms =
                    diagnostic_now_ms(success.snapshot.interfaces.monotonic_ms.unwrap_or(0));
                self.state
                    .commit_collection(success.config, success.snapshot, now_ms, interval);
                self.runtime = Some(success.runtime);
                self.mode_reload.complete();
                #[cfg(feature = "nss-platform")]
                self.restart_fast_rate_worker();
                self.queue_control_work();
                self.schedule_conntrack(true);
                if let Some(message) = success.fatal_error {
                    self.last_error = Some(message.clone());
                    *self.state.fatal_cell().borrow_mut() = Some(message.clone());
                    UloopGuard::request_stop();
                    return Err(DaemonError::reload(message));
                }
                Ok(())
            }
            ReloadOutcome::Failure(failure) => {
                let error = failure.error;
                self.runtime = Some(failure.runtime);
                self.schedule_collection_retry();
                if failure.fatal {
                    let message = error.to_string();
                    *self.state.fatal_cell().borrow_mut() = Some(message);
                    UloopGuard::request_stop();
                }
                Err(error)
            }
        }
    }

    fn schedule_runtime_notice_poll(&mut self) {
        let result = self
            .runtime_notice_timer
            .as_ref()
            .expect("runtime notice timer must be installed")
            .schedule(RUNTIME_NOTICE_POLL_MS);
        if let Err(error) = result {
            let message = format!("runtime notice timer failed: {error}");
            self.last_error = Some(message.clone());
            *self.state.fatal_cell().borrow_mut() = Some(message);
            UloopGuard::request_stop();
        }
    }

    fn schedule_collection_retry(&mut self) {
        let interval = self
            .runtime
            .as_ref()
            .map_or(self.state.config().refresh_interval_ms, |runtime| {
                runtime.collection_interval_ms(self.state.config().refresh_interval_ms)
            });
        if let Err(error) = schedule_absolute_collection(
            self.collection_timer
                .as_ref()
                .expect("collection timer must be installed"),
            &self.collection_deadline_ms,
            interval,
        ) {
            let message = format!("collection retry timer failed: {error}");
            self.last_error = Some(message.clone());
            *self.state.fatal_cell().borrow_mut() = Some(message);
            UloopGuard::request_stop();
        }
    }

    #[cfg(feature = "nss-platform")]
    fn drain_fast_rate_notices(&mut self) {
        // Runtime collection temporarily owns `ProductionRuntime` on its
        // worker thread. Consuming a FastRate notice while `self.runtime` is
        // absent would update only the published Arc: the in-flight base
        // result would then overwrite that overlay with its older FastRate
        // state. Leave the bounded notices queued until runtime ownership
        // returns; `drain_runtime_notices()` publishes the new base and then
        // calls this method, allowing the newest compatible window to be
        // installed into both runtime state and the same base generation.
        if !fast_rate_notices_can_drain(self.runtime.is_some()) {
            return;
        }
        loop {
            let Ok(notice) = self.fast_rate_notices.try_recv() else {
                break;
            };
            if let Some(telemetry) = notice.event_telemetry {
                if let Some(runtime) = self.runtime.as_mut() {
                    runtime.apply_fast_event_telemetry(telemetry);
                }
            }
            if !notice.sample_attempted || notice.base_generation == 0 {
                continue;
            }
            let snapshots = self.state.snapshot_store();
            let (current_snapshot, current_generations) = snapshots.load_with_generations();
            if notice.base_contract.base_generation != notice.base_generation {
                continue;
            }
            let exact_generation = current_generations.base_generation == notice.base_generation;
            let compatible_retarget = !exact_generation
                && fast_rate_overlay::publication_matches_snapshot(
                    &current_snapshot,
                    &notice.publication,
                    &notice.base_contract,
                );
            if !exact_generation && !compatible_retarget {
                continue;
            }
            if let Some(runtime) = self.runtime.as_mut() {
                runtime.nss.install_fast_rate_publication(
                    notice.publication.clone(),
                    notice.base_contract.clone(),
                );
            }
            let sample = notice.publication.sample.map(|value| {
                serde_json::json!({
                    "sample_ms": value.sample_ms,
                    "window_ms": value.window_ms,
                    "read_end_skew_ms": value.read_end_skew_ms,
                    "fast_n_bps": value.fast_n_bps,
                    "fast_s_bps": value.fast_s_bps,
                    "fast_total_bps": value.fast_total_bps,
                })
            });
            let telemetry = notice.publication.telemetry;
            let worker_evidence = serde_json::json!({
                "sample": sample,
                "observed_ms": notice.observed_ms,
                "valid_windows": telemetry.valid_windows,
                "invalid_windows": telemetry.invalid_windows,
                "zero_windows": telemetry.zero_windows,
                "last_sample_ms": telemetry.last_sample_ms,
                "last_invalid_ms": telemetry.last_invalid_ms,
                "last_zero_latency_ms": telemetry.last_zero_latency_ms,
                "last_rise_latency_ms": telemetry.last_rise_latency_ms,
                "client_shadow_entries": notice.publication.client_samples.len(),
                "client_shadow_invalid_windows": notice.publication.client_invalid_windows,
                "event_received": notice.wakeup_telemetry.event_received,
                "event_coalesced": notice.wakeup_telemetry.event_coalesced,
                "fixed_timer_wakeups": notice.wakeup_telemetry.fixed_timer_wakeups,
                "last_event_ms": notice.wakeup_telemetry.last_event_ms,
                "last_wakeup_event": notice.wakeup.event_hint,
                "last_wakeup_fixed": notice.wakeup.fixed_timer,
                "read_valid": notice.publication.read_valid,
                "sampled_base_generation": notice.base_generation,
                "published_base_generation": current_generations.base_generation,
                "retargeted_compatible_base": compatible_retarget,
                "formal_rate_owner": true,
            });
            let _ = snapshots.publish_fast(current_generations.base_generation, |snapshot| {
                let overlay = fast_rate_overlay::apply_fast_rate_overlay(
                    snapshot,
                    &notice.publication,
                    &notice.base_contract,
                );
                let mut evidence = worker_evidence.clone();
                evidence["overlay_clients"] = serde_json::json!(overlay.clients);
                evidence["overlay_directions"] = serde_json::json!(overlay.directions);
                snapshot
                    .status
                    .evidence
                    .details
                    .insert("fast_rate_worker".into(), evidence.clone());
                snapshot
                    .health
                    .evidence
                    .details
                    .insert("fast_rate_worker".into(), evidence);
            });
        }
    }

    #[cfg(feature = "nss-platform")]
    fn restart_fast_rate_worker(&mut self) {
        self.drain_fast_rate_notices();
        if let Some(worker) = self.fast_rate_worker.take() {
            if worker.join().is_err() {
                self.last_error = Some("NSS FastRate worker panicked".into());
            }
        }
        let (sender, receiver) = mpsc::sync_channel(8);
        let sources = match self
            .runtime
            .as_mut()
            .map(ProductionRuntime::fast_rate_sources)
        {
            Some(Ok(sources)) => sources,
            Some(Err(error)) => {
                self.last_error = Some(format!("NSS FastRate sources: {error}"));
                None
            }
            None => None,
        };
        match fast_rate_worker::FastRateWorker::spawn_with_sources(4, sender, sources) {
            Ok(worker) => self.fast_rate_worker = Some(worker),
            Err(error) => {
                self.last_error = Some(format!("NSS FastRate worker: {error}"));
            }
        }
        self.fast_rate_notices = receiver;
    }

    #[cfg(feature = "nss-platform")]
    fn fast_rate_timer_tick(&mut self) {
        let now_ms = production_now_ms().unwrap_or(0);
        let snapshots = self.state.snapshot_store();
        let (base_snapshot, generations) = snapshots.load_with_generations();
        let base_generation = generations.base_generation;
        let base_contract = Arc::new(fast_rate_overlay::base_contract(
            &base_snapshot,
            base_generation,
        ));
        let edge_bps = self
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.access_edge.authority_bps());
        if let Some(worker) = self.fast_rate_worker.as_ref() {
            match fast_rate_worker::try_queue(
                &worker.queue(),
                FastRateCommand::Poll {
                    now_ms,
                    base_generation,
                    base_contract,
                    edge_bps,
                },
            ) {
                Ok(()) | Err(QueueError::Full) => {}
                Err(QueueError::Disconnected) => {
                    self.last_error = Some("NSS FastRate worker disconnected".into());
                }
            }
        }
        self.drain_fast_rate_notices();
        if let Some(timer) = self.fast_rate_timer.as_ref() {
            if let Err(error) = timer.schedule(250) {
                self.last_error = Some(format!("NSS FastRate timer: {error}"));
            }
        }
    }
    fn before_reply(&mut self, method: ubus::Method) -> Result<(), DaemonError> {
        self.drain_runtime_notices();
        #[cfg(feature = "nss-platform")]
        // The fixed FastRate worker is independent from the slower runtime
        // collection. Drain its newest notice immediately before live RPCs
        // so a 1s LuCI poll cannot observe the previous base snapshot while a
        // valid FastN+FastS publication is already queued.
        self.drain_fast_rate_notices();
        self.drain_reload_notices();
        self.drain_control_notices();
        if method == ubus::Method::Reload {
            self.reload_bounded()
        } else {
            if matches!(
                method,
                ubus::Method::Realtime
                    | ubus::Method::Clients
                    | ubus::Method::ClientConnections
                    | ubus::Method::Diagnostics
            ) {
                self.schedule_conntrack(false);
            }
            Ok(())
        }
    }

    fn queue_control_work(&mut self) {
        if self.control_pending_generation.is_some() {
            return;
        }
        let Some(work) = self
            .runtime
            .as_mut()
            .and_then(ProductionRuntime::take_control_work)
        else {
            return;
        };
        self.control_generation = self.control_generation.wrapping_add(1).max(1);
        let generation = self.control_generation;
        let Some(worker) = self.control_worker.as_ref() else {
            self.runtime
                .as_mut()
                .expect("control work requires a runtime")
                .restore_control_work(work);
            return;
        };
        match control_worker::try_queue(
            &worker.queue(),
            ControlWorkerTask {
                generation,
                work: work.clone(),
            },
        ) {
            Ok(()) => self.control_pending_generation = Some(generation),
            Err(QueueError::Full) => {
                self.runtime
                    .as_mut()
                    .expect("control work requires a runtime")
                    .restore_control_work(work);
            }
            Err(QueueError::Disconnected) => {
                let kind = work.kind;
                self.runtime
                    .as_mut()
                    .expect("control work requires a runtime")
                    .finish_control_work(
                        ControlReconcileOutcome::failed(
                            kind,
                            "control runtime worker disconnected",
                        ),
                        true,
                    );
                self.last_error = Some("control runtime worker disconnected".into());
            }
        }
    }

    fn drain_control_notices(&mut self) {
        if self.runtime.is_none() {
            return;
        }
        while let Ok(notice) = self.control_notices.try_recv() {
            if self.control_pending_generation != Some(notice.generation) {
                continue;
            }
            self.control_pending_generation = None;
            if let Some(runtime) = self.runtime.as_mut() {
                runtime.finish_control_work(notice.outcome, !self.reload_requested);
            }
            if !self.reload_requested {
                self.queue_control_work();
            }
        }
    }

    fn schedule_conntrack(&mut self, force: bool) {
        let Ok(now_ms) = production_now_ms() else {
            return;
        };
        if !force
            && now_ms.saturating_sub(self.last_conntrack_request_ms.get())
                < CONNTRACK_WORK_INTERVAL_MS
        {
            return;
        }
        let task = ConntrackTask {
            now_ms,
            max_clients: self.state.config().max_clients,
            mode: self.state.config().conn_collector_mode,
            defer_connection_rates: matches!(
                self.state.snapshot().status.collector_mode.as_str(),
                "nss_ecm_node" | "nss_ecm_bpf"
            ),
        };
        let Some(worker) = self.conntrack_worker.as_ref() else {
            return;
        };
        match worker.queue().try_send(task) {
            Ok(()) => self.last_conntrack_request_ms.set(now_ms),
            Err(QueueError::Full) => {}
            Err(QueueError::Disconnected) => {
                self.last_error = Some("conntrack runtime worker disconnected".into());
            }
        }
    }
    fn handle_control(&mut self, command: ControlCommand) -> Result<Value, DaemonError> {
        self.drain_runtime_notices();
        self.drain_reload_notices();
        self.drain_control_notices();
        if self.runtime_collection_pending || self.reload_pending {
            return Err(DaemonError::collection("runtime collection pending"));
        }
        let result = {
            let runtime = self
                .runtime
                .as_mut()
                .ok_or_else(|| DaemonError::collection("runtime is not started"))?;
            match command {
                ControlCommand::Set(request) => runtime.client_control_set(request),
                ControlCommand::Delete(request) => runtime.client_control_delete(request),
            }
        };
        if result.is_ok() {
            self.queue_control_work();
        }
        result
    }
    fn schedule_reconnect(&self) {
        if !self.reconnect_pending.replace(true)
            && self
                .reconnect_timer
                .as_ref()
                .unwrap()
                .schedule(RECONNECT_MS)
                .is_err()
        {
            self.reconnect_pending.set(false);
            *self.state.fatal_cell().borrow_mut() =
                Some("failed to schedule ubus reconnect".into());
            UloopGuard::request_stop();
        }
    }
    fn reconnect(&mut self) {
        self.reconnect_pending.set(false);
        let connection = self.ubus.as_mut().unwrap();
        let timer = self.reconnect_timer.as_ref().unwrap();
        let mut context = (connection, timer);
        let result = reconnect_and_register(
            &self.state,
            &mut context,
            |(connection, _)| {
                connection
                    .reconnect(None)
                    .map_err(|error| DaemonError::transport(error.to_string()))?;
                connection
                    .reregister_objects()
                    .map_err(|error| DaemonError::transport(error.to_string()))
            },
            |(_, timer), delay| {
                timer
                    .schedule(delay)
                    .map_err(|error| DaemonError::transport(error.to_string()))
            },
            UloopGuard::request_stop,
        );
        if let Err(error) = result {
            self.last_error = Some(error.to_string());
        }
    }
}

pub fn run() -> Result<(), DaemonError> {
    let config = load_config()?;
    let mut event_loop =
        UloopGuard::init().map_err(|error| DaemonError::platform(error.to_string()))?;
    let state = CoordinatorState::new(
        config.clone(),
        Arc::new(ResponseSnapshot::unsupported("starting")),
    );
    let snapshots = state.snapshot_store();
    let conntrack_worker = conntrack_worker::spawn(snapshots.clone())
        .map_err(|error| DaemonError::platform(format!("conntrack worker: {error}")))?;
    let (runtime_notice_sender, runtime_notices) = runtime_worker::notice_channel(1);
    let runtime_worker = RuntimeCollectionWorker::spawn(1, runtime_notice_sender)
        .map_err(|error| DaemonError::platform(format!("runtime worker: {error}")))?;
    let (reload_notice_sender, reload_notices) = reload_worker::notice_channel(1);
    let reload_worker = ProductionReloadWorker::spawn(1, reload_notice_sender)
        .map_err(|error| DaemonError::platform(format!("reload worker: {error}")))?;
    let (control_worker, control_notices) = {
        let (sender, receiver) = mpsc::sync_channel(4);
        let worker = control_worker::ControlWorker::spawn(1, sender)
            .map_err(|error| DaemonError::platform(format!("control worker: {error}")))?;
        (Some(worker), receiver)
    };
    #[cfg(feature = "nss-platform")]
    let (fast_rate_worker, fast_rate_notices) = {
        let (sender, receiver) = mpsc::sync_channel(8);
        let worker = fast_rate_worker::FastRateWorker::spawn(4, sender)
            .map_err(|error| DaemonError::platform(format!("NSS FastRate worker: {error}")))?;
        (Some(worker), receiver)
    };
    let app = Rc::new(RefCell::new(App {
        state,
        runtime: None,
        ubus: None,
        collection_timer: None,
        collection_deadline_ms: Cell::new(0),
        runtime_worker: Some(runtime_worker),
        runtime_notices,
        runtime_collection_pending: false,
        reload_worker: Some(reload_worker),
        reload_notices,
        reload_requested: false,
        reload_pending: false,
        runtime_notice_timer: None,
        reconnect_timer: None,
        reconnect_pending: Cell::new(false),
        mode_reload: DaeModeReloadLatch::default(),
        last_error: None,
        conntrack_worker: Some(conntrack_worker),
        last_conntrack_request_ms: Cell::new(0),
        control_worker,
        control_notices,
        control_generation: 0,
        control_pending_generation: None,
        #[cfg(feature = "nss-platform")]
        fast_rate_worker,
        #[cfg(feature = "nss-platform")]
        fast_rate_notices,
        #[cfg(feature = "nss-platform")]
        fast_rate_timer: None,
    }));
    let weak = Rc::downgrade(&app);
    app.borrow_mut().collection_timer = Some(Timer::new(move || {
        if let Some(app) = weak.upgrade() {
            app.borrow_mut().collection_tick();
        }
    }));
    let weak = Rc::downgrade(&app);
    app.borrow_mut().runtime_notice_timer = Some(Timer::new(move || {
        if let Some(app) = weak.upgrade() {
            app.borrow_mut().runtime_notice_tick();
        }
    }));
    let weak = Rc::downgrade(&app);
    app.borrow_mut().reconnect_timer = Some(Timer::new(move || {
        if let Some(app) = weak.upgrade() {
            app.borrow_mut().reconnect();
        }
    }));
    #[cfg(feature = "nss-platform")]
    {
        let weak = Rc::downgrade(&app);
        app.borrow_mut().fast_rate_timer = Some(Timer::new(move || {
            if let Some(app) = weak.upgrade() {
                app.borrow_mut().fast_rate_timer_tick();
            }
        }));
    }

    let weak = Rc::downgrade(&app);
    let control_weak = Rc::downgrade(&app);
    let object = ubus::object(
        snapshots,
        move |method| {
            weak.upgrade()
                .ok_or_else(|| DaemonError::reload("daemon stopped"))?
                .borrow_mut()
                .before_reply(method)
        },
        move |command| {
            control_weak
                .upgrade()
                .ok_or_else(|| DaemonError::reload("daemon stopped"))?
                .borrow_mut()
                .handle_control(command)
        },
    )?;
    let mut connection =
        UbusConnection::connect(None).map_err(|error| DaemonError::transport(error.to_string()))?;
    connection
        .attach_uloop()
        .map_err(|error| DaemonError::transport(error.to_string()))?;
    connection
        .register_object(object)
        .map_err(|error| DaemonError::transport(error.to_string()))?;
    let weak = Rc::downgrade(&app);
    connection.set_connection_lost_handler(move || {
        if let Some(app) = weak.upgrade() {
            app.borrow().schedule_reconnect();
        }
    });
    app.borrow_mut().ubus = Some(connection);

    let runtime = ProductionRuntime::stage(config.clone())?;
    let runtime = {
        let app = app.borrow();
        let timer = app.collection_timer.as_ref().unwrap();
        let deadline = &app.collection_deadline_ms;
        activate_runtime(
            &app.state,
            runtime,
            |delay| schedule_absolute_collection(timer, deadline, delay),
            UloopGuard::request_stop,
        )?
    };
    app.borrow_mut().runtime = Some(runtime);
    app.borrow_mut().queue_control_work();
    #[cfg(feature = "nss-platform")]
    app.borrow_mut().restart_fast_rate_worker();
    #[cfg(feature = "nss-platform")]
    app.borrow()
        .fast_rate_timer
        .as_ref()
        .expect("NSS FastRate timer must be installed")
        // The worker owns the 20 ms event poll/debounce and 1 s fixed timer.
        // This timer only refreshes generation context and drains notices.
        .schedule(250)
        .map_err(|error| DaemonError::platform(format!("NSS FastRate timer: {error}")))?;
    app.borrow_mut().schedule_conntrack(true);
    let _signals = {
        let mut app = app.borrow_mut();
        let App { runtime, ubus, .. } = &mut *app;
        install_control_or_shutdown(runtime.as_mut(), UloopSignalBridge::install, || {
            ubus.take();
            Ok(())
        })?
    };
    let run_result = event_loop
        .run()
        .map_err(|error| DaemonError::platform(error.to_string()));
    let runtime_worker = app.borrow_mut().runtime_worker.take();
    let runtime_worker_result = runtime_worker.map_or(Ok(()), |worker| {
        worker
            .join()
            .map_err(|_| DaemonError::platform("runtime worker panicked"))
    });
    app.borrow_mut().recover_runtime_worker_notice();
    let reload_worker = app.borrow_mut().reload_worker.take();
    let reload_worker_result = reload_worker.map_or(Ok(()), |worker| {
        worker
            .join()
            .map_err(|_| DaemonError::platform("reload worker panicked"))
    });
    app.borrow_mut().recover_reload_worker_notice();
    let control_worker = app.borrow_mut().control_worker.take();
    let control_worker_result = control_worker.map_or(Ok(()), |worker| {
        worker
            .join()
            .map_err(|_| DaemonError::platform("control worker panicked"))
    });
    app.borrow_mut().drain_control_notices();
    let shutdown_result = {
        let mut app = app.borrow_mut();
        let _connection = app.ubus.take();
        shutdown_runtime(app.runtime.as_mut(), || Ok(()))
    };
    let fatal = app.borrow().state.fatal_error();
    if let Some(error) = fatal {
        return Err(DaemonError::platform(error));
    }
    run_result
        .and(runtime_worker_result)
        .and(reload_worker_result)
        .and(control_worker_result)
        .and(shutdown_result)
}

fn load_config() -> Result<RuntimeConfig, DaemonError> {
    let mut source = lanspeed_openwrt_sys::UciContext::new()
        .map_err(|error| DaemonError::reload(error.to_string()))?;
    RuntimeConfig::load(&mut source, &SysfsInterfaceEligibility::default())
        .map_err(|error| DaemonError::reload(error.to_string()))
}

fn read_identities(config: &RuntimeConfig, now_ms: u64) -> (IdentityTable, Vec<String>) {
    let collect_names = collect_ifnames(config);
    let filter = IdentityFilter::from_uci_values(collect_names.iter().map(String::as_str));
    let mut table = IdentityTable::new(config.max_clients);
    let mut errors = Vec::new();
    let mut entries = match arp::read_arp_table(
        arp::ARP_PROCFS_PATH,
        config.max_clients,
        &filter,
        &LegacyZoneResolver,
    ) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(format!("ARP: {error}"));
            Vec::new()
        }
    };
    match netlink::read_ipv6_neighbor_table(
        config.max_clients.saturating_sub(entries.len()),
        &filter,
        &LegacyZoneResolver,
    ) {
        Ok(ipv6) => entries.extend(ipv6),
        Err(error) => errors.push(format!("IPv6 neighbor: {error}")),
    }
    for entry in entries {
        let _ = table.observe(IdentityObservation {
            mac: &entry.mac.to_string(),
            zone: Some(&entry.zone),
            interface: &entry.interface,
            ip: Some(&entry.ip),
            hostname: None,
            last_seen: now_ms,
            source: ObservationSource::Neighbor,
        });
    }
    (table, errors)
}

fn connection_overlay(snapshot: Option<&CollectedSnapshot>) -> ConnectionOverlay {
    let mut overlay = ConnectionOverlay::available();
    if let Some(snapshot) = snapshot {
        for client in &snapshot.clients {
            overlay.insert(
                client.identity_key.clone(),
                ConnectionCounts {
                    tcp: client.tcp_conns,
                    udp: client.udp_conns,
                    udp_dns: client.udp_dns_conns,
                    udp_other: client.udp_other_conns,
                },
            );
        }
    } else {
        return ConnectionOverlay::unavailable("conntrack unavailable");
    }
    overlay
}

fn collect_ifnames(config: &RuntimeConfig) -> Vec<String> {
    system::collect_ifnames(config)
}

fn collect_ifnames_with_roles(config: &RuntimeConfig) -> Vec<(String, InterfaceRole)> {
    system::collect_ifnames_with_roles(config)
}

#[cfg(feature = "nss-platform")]
fn access_edge_bridges(config: &RuntimeConfig) -> Vec<String> {
    system::access_edge_bridges(config)
}

fn sysdevices(config: &RuntimeConfig) -> Result<SysdevicesResponse, DaemonError> {
    system::sysdevices(config)
}

fn version() -> String {
    system::version()
}

#[cfg(all(test, feature = "nss-platform"))]
fn version_from(version: Option<&str>, release: Option<&str>) -> String {
    system::version_from(version, release)
}

#[cfg(all(test, feature = "nss-platform"))]
fn record_fatal_cleanup(
    context: &str,
    primary: &str,
    cleanup: &str,
    fatal: &RefCell<Option<String>>,
) -> DaemonError {
    system::record_fatal_cleanup(context, primary, cleanup, fatal)
}
