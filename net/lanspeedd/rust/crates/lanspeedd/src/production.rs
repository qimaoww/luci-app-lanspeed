use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    rc::Rc,
    sync::Arc,
};

use lanspeed_openwrt_sys::{Timer, UbusConnection, UloopGuard};
use serde_json::{json, Value};

use crate::{
    clock::monotonic_millis,
    collectors::conntrack::{self, CollectedSnapshot, CollectorMode as ConntrackMode},
    config::{AccessEdgeMode, ConnectionCollectorMode, RuntimeConfig, SysfsInterfaceEligibility},
    connection_details::ConnectionRateBook,
    connections::{
        apply_conntrack_failure, apply_conntrack_success, before_reply_action,
        client_conntrack_plan, periodic_conntrack_plan, publish_connection_details,
        BeforeReplyAction, ClientConntrackPlan, ConntrackObservation, PeriodicConntrackPlan,
        CLIENT_CONNTRACK_CACHE_TTL_MS, NSS_CLIENT_CONNTRACK_CACHE_TTL_MS,
    },
    control::{ClientControlDeleteRequest, ClientControlRequest, ControlCommand},
    daemon::{
        abort_reload_after_timer_failure, abort_reload_candidate, activate_runtime,
        collect_and_reschedule, commit_reload, install_control_or_shutdown, reconnect_and_register,
        shutdown_runtime, CoordinatorState, Runtime, UloopSignalBridge,
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
        InterfaceRateBook, MIXED_INTERFACE_SOURCE,
    },
    model::{
        Capabilities, ClientsResponse, Confidence, Conflict, Evidence, HealthResponse, Interface,
        InterfaceRole, InterfaceStatus, InterfacesResponse, Mode, OverviewResponse, OverviewSample,
        ReloadResponse, StatusResponse, SysdevicesResponse,
    },
    platform::{
        confidence,
        x86::{
            coverage_state::X86Coverage,
            output::clients_response,
            runtime::{
                AdapterError, AdapterErrorKind, AttachMode, BpfCollectionCheckpoint,
                BpfPostCommitCleanup, BpfReconfigureTxn, BpfRuntime, ReconfigureRateBaseline,
                ReconfigureStrategy, SystemAyaAdapter, SystemAyaLink, FALLBACK_OBJECT_PATH,
            },
            snapshot::{BpfSnapshotCollector, ConnectionCounts, ConnectionOverlay},
        },
    },
    policy::{self, RateCollector},
    probe::{
        collector::{self, probe_deadline, probe_due, ProbeMethod, SystemProbeCollector},
        process::{
            run_dae_mode_tick, DaeModeReloadLatch, DaeModeTickOutcome, DaeModeTickSignals,
            DaeProcessTracker,
        },
        Mode as ProbeMode, ProbeCapabilities, ProbeReport, RuntimeHealth,
    },
    state::{ResponseSnapshot, CONNECTION_SEMANTICS, OVERVIEW_SAMPLE_SOURCE},
    ubus,
};

use crate::control::ControlManager;

mod evidence;
mod rate_helpers;
mod system;
#[cfg(all(test, feature = "nss-platform"))]
mod tests;
use evidence::*;
use rate_helpers::*;

#[cfg(feature = "nss-platform")]
use crate::control::{NssPathObservation, NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD};

#[cfg(feature = "nss-platform")]
use crate::config::RateCollectorMode;

#[cfg(all(test, feature = "nss-platform"))]
use crate::platform::nss::fusion::add_traffic_counters;
#[cfg(all(test, feature = "nss-platform"))]
use crate::platform::nss::{
    output::{coverage_response, nss_rate_coverage_values},
    window::{CoverageWindow, EcmBpfRateBatch, RateWindowValue},
};
#[cfg(feature = "nss-platform")]
use crate::platform::x86::snapshot::BpfSnapshot;
#[cfg(all(test, feature = "nss-platform"))]
use crate::probe::Confidence as ProbeConfidence;
#[cfg(feature = "nss-platform")]
use crate::{
    connection_details::{TrafficClassification, TrafficClassificationDirection},
    identity::{filter, ClientIdentity},
    model::{
        AttachmentKind as ModelAttachmentKind, AttachmentTrust as ModelAttachmentTrust,
        ByteDomain as ModelByteDomain, ClassificationState, Client, ClientRateMeta, RateAttachment,
        RateClassificationSummary, RateCoverage as ModelRateCoverage, RateDirectionMeta,
        RateScope as ModelRateScope, RateSource as ModelRateSource,
    },
    platform::{
        access_edge::{
            normalize_l2_with_fcs, AccessEdgeCheckpoint, AccessEdgeRuntime,
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
            fusion::{
                ecm_bpf_client_interfaces, ecm_bpf_fallback_client_rates,
                merge_ecm_bpf_client_deltas, merge_ecm_bpf_coverage_delta,
            },
            output::{
                apply_ecm_bpf_rate_batch, coverage_evidence, ecm_bpf_clients_response,
                ecm_bpf_coverage_merge_evidence, ecm_bpf_rate_batch_evidence, nss_rate_coverage,
                rate_window_interface_counters, window_clients, window_evidence,
            },
            runtime::{NssRuntime, NssRuntimeCheckpoint},
            tc_snapshot::{NssTcClientSample, NssTcSnapshot},
            window::{LanClock, WindowQuality},
        },
    },
};

const RECONNECT_MS: u32 = 1_000;
// Kept as a policy/timer constant so the x86 build does not need to link the
// NSS platform module merely to compile common scheduling code.
const ACCESS_EDGE_INTERVAL_MS: u64 = 1_000;
const CLASSIFIER_INTERVAL_MS: u64 = 2_000;
#[cfg(feature = "nss-platform")]
const CPU_PATH_PROBE_READ_END_SKEW_MS: u64 = 250;
const INTERNAL_BPF_SELF_HEAL_REASON: &str = "production.collect.internal";
const EXTERNAL_BPF_SELF_HEAL_REASON: &str = "production.collect.external";
const INTERFACE_NOTE: &str = "Per-interface totals from one kernel net-device pass with sysfs fallback; reflect hardware-offloaded and hardware-switched traffic too.";

fn production_now_ms() -> Result<u64, DaemonError> {
    monotonic_millis()
        .map_err(|error| DaemonError::collection(format!("read CLOCK_MONOTONIC: {error}")))
}

struct ProductionRuntime {
    config: RuntimeConfig,
    control: ControlManager,
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
            || !matches!(
                self.config.rate_collector_mode,
                crate::config::RateCollectorMode::Auto
                    | crate::config::RateCollectorMode::Bpf
                    | crate::config::RateCollectorMode::NssEcmBpf
            )
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

    fn refresh_connections(
        &mut self,
        base: &ResponseSnapshot,
    ) -> Result<ResponseSnapshot, DaemonError> {
        let now_ms = production_now_ms()?;
        let defer_connection_rates = matches!(
            self.rate_owner,
            Some(RateCollector::NssEcmNode | RateCollector::NssEcmBpf)
        );
        let plan = client_conntrack_plan(
            now_ms,
            self.conntrack_observation.last_attempt_ms,
            self.conntrack_snapshot.is_some(),
            if defer_connection_rates {
                NSS_CLIENT_CONNTRACK_CACHE_TTL_MS
            } else {
                CLIENT_CONNTRACK_CACHE_TTL_MS
            },
        );
        let cached = if plan == ClientConntrackPlan::ReuseCached {
            self.conntrack_snapshot.as_ref().map(|collected| {
                apply_conntrack_success(base, collected, self.config.conn_collector_mode.as_str())
            })
        } else {
            None
        };
        let (mut snapshot, identity_errors) = if let Some(snapshot) = cached {
            (snapshot, Vec::new())
        } else {
            let (identities, identity_errors) = read_identities(&self.config, now_ms);
            let snapshot = match self.read_conntrack(&identities, now_ms, defer_connection_rates) {
                Ok(collected) => apply_conntrack_success(
                    base,
                    &collected,
                    self.config.conn_collector_mode.as_str(),
                ),
                Err(error) => apply_conntrack_failure(base, &error),
            };
            (snapshot, identity_errors)
        };
        if !identity_errors.is_empty() {
            snapshot
                .clients
                .evidence
                .get_or_insert_default()
                .details
                .insert("identity_errors".into(), json!(identity_errors));
        }
        #[cfg(feature = "nss-platform")]
        {
            // A hot clients/client_connections RPC is also a control
            // observation. Audit every owned NSS queue, filter, nft object,
            // and IGS mapping before copying control state into this response.
            // Use the last authoritative client/attachment inventory: the
            // conntrack overlay below may contain transient connection-only
            // rows and must not become topology authority. If an owned object
            // disappeared, reconcile clears verification and transactionally
            // rebuilds it in this same request, so stale `verified` is never
            // returned for one extra polling interval.
            self.reconcile_control_state();
        }
        // The hot clients RPC overlays fresh conntrack-only identities after
        // the normal collection snapshot. It is not an authoritative identity
        // inventory: decorating those rows must never withdraw a persistent
        // rule or rebuild qdiscs between normal collection generations.
        self.decorate_controls(&mut snapshot.clients);
        let totals = ConnectionTotals::new(
            snapshot.clients.tcp_conns_total.unwrap_or(0),
            snapshot.clients.udp_conns_total.unwrap_or(0),
            snapshot.clients.udp_dns_conns_total.unwrap_or(0),
            snapshot.clients.udp_other_conns_total.unwrap_or(0),
        );
        self.overview
            .replace_latest_connections_and_client_count(totals, snapshot.clients.clients.len());
        Ok(snapshot)
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
        let (ecm_bpf_snapshot, ecm_bpf_snapshot_fresh) = self.nss.collect_ecm_bpf(
            &identities,
            &mut now_ms,
            nss_freshness_ms,
            &mut runtime_health,
            classifier_map_read_due,
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
        self.nss
            .transition_rate_owner(&mut self.rate_owner, decision.rate);
        let legacy_nss_rate_window_enabled = legacy_nss_rate_window_enabled(
            self.config.access_edge_mode,
            self.config.rate_collector_mode,
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
        if access_edge_enabled {
            let edge_evidence = access_edge_global_evidence(
                self.access_edge.latest(),
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

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "nss-platform")]
    fn apply_access_edge_rates(
        &mut self,
        clients: &mut ClientsResponse,
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
        if self.config.access_edge_mode == AccessEdgeMode::Off {
            self.access_edge
                .retain_published_identities(&BTreeSet::new());
            self.classification_results.clear();
            return;
        }
        let active_auto = active_access_edge_owns_display_rate(
            self.config.access_edge_mode,
            self.config.rate_collector_mode,
        );
        let edge_snapshot = self.access_edge.latest().clone();
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

        if active_auto {
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

            let mut select_direction = |direction: EdgeDirection, old_bps: u64| {
                let edge_direction = edge.map(|sample| match direction {
                    EdgeDirection::Tx => &sample.tx,
                    EdgeDirection::Rx => &sample.rx,
                });
                let mut candidates = Vec::new();
                if let Some(observation) = edge_direction {
                    if let Some(segment) = observation.segment {
                        if let (Some(bps), Some(window_ms)) = (segment.bps(), segment.window_ms()) {
                            candidates.push(RateCandidate {
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
                            });
                        }
                    }
                }
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
                if active_auto {
                    if let Some(selected) = selected.selected {
                        return published_from_candidate(selected.candidate, selected.stale);
                    }
                    // Active Access Edge never falls through to the legacy NSS
                    // rate window. Warmup or unavailable means exactly that;
                    // no LAN allocation, previous distribution, directional
                    // max, interface floor, or smoothed rate may become E.
                    return PublishedRateDirection::unavailable(0);
                }
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
            if active_auto {
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
                // Active-auto rates are owned exclusively by RateMux. Neither
                // a selected Edge/classifier source nor an unavailable/warmup
                // state may expose cumulative totals from the displaced legacy
                // pipeline as if they belonged to the current rate source.
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
            let sampled = if let Some(boundaries) = boundary_names.as_ref() {
                sum_interface_counters(boundaries, &raw_counters)
            } else {
                raw_counters.get(&name).copied()
            };
            let interface = match sampled {
                Some(counters) => {
                    let sampled_names = boundary_names
                        .as_deref()
                        .unwrap_or_else(|| std::slice::from_ref(&name));
                    let counter_source = counter_snapshot
                        .source_for(sampled_names.iter().map(String::as_str))
                        .unwrap_or(MIXED_INTERFACE_SOURCE);
                    let display = if role == InterfaceRole::Lan {
                        InterfaceCounters {
                            rx_bytes: counters
                                .rx_bytes
                                .saturating_add(counters.rx_packets.saturating_mul(4)),
                            tx_bytes: counters
                                .tx_bytes
                                .saturating_add(counters.tx_packets.saturating_mul(4)),
                            ..counters
                        }
                    } else {
                        counters
                    };
                    let (rx_bps, tx_bps, delta_ms) =
                        self.interface_rates.update(&name, display, now_ms);
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
                let sampled = if let Some(boundaries) = boundary_names.as_ref() {
                    sum_interface_counters(boundaries, raw_counters)
                } else {
                    raw_counters.get(&name).copied()
                };
                match sampled {
                    Some(counters) => {
                        let sampled_names = boundary_names
                            .as_deref()
                            .unwrap_or_else(|| std::slice::from_ref(&name));
                        let counter_source = counter_snapshot
                            .source_for(sampled_names.iter().map(String::as_str))
                            .unwrap_or(MIXED_INTERFACE_SOURCE);
                        let display = if role == InterfaceRole::Lan {
                            InterfaceCounters {
                                rx_bytes: counters
                                    .rx_bytes
                                    .saturating_add(counters.rx_packets.saturating_mul(4)),
                                tx_bytes: counters
                                    .tx_bytes
                                    .saturating_add(counters.tx_packets.saturating_mul(4)),
                                ..counters
                            }
                        } else {
                            counters
                        };
                        let (rx_bps, tx_bps, delta_ms) =
                            self.interface_rates.update(&name, display, now_ms);
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

    fn decorate_controls(&self, clients: &mut ClientsResponse) {
        self.control.decorate_response(clients);
    }

    fn reconcile_control_state(&mut self) {
        #[cfg(feature = "nss-platform")]
        if !self.control_platform_owner {
            self.control.observe_existing_nss_control();
            return;
        }
        self.control.reconcile();
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

    fn collect(&mut self) -> Result<ResponseSnapshot, DaemonError> {
        // collect_and_reschedule owns the hot-cycle transaction. Candidate reload
        // collection uses ProductionRuntime::collect and keeps its local rollback.
        self.collect_inner(ProbeMethod::Status, None)
    }

    fn collection_interval_ms(&self, configured_ms: u32) -> u32 {
        effective_collection_interval_ms(
            self.config.access_edge_mode,
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
    reconnect_timer: Option<Timer>,
    reconnect_pending: Cell<bool>,
    mode_reload: DaeModeReloadLatch,
    last_error: Option<String>,
}

struct PreparedBpfReload {
    transaction: BpfReconfigureTxn,
    collection_checkpoint: BpfCollectionCheckpoint,
}

impl App {
    fn collection_tick(&mut self) {
        let (has_bpf, process_activity_changed, attach_mode_mismatch) = {
            let runtime = self
                .runtime
                .as_mut()
                .expect("collection timer requires a staged runtime");
            let process_activity_changed = runtime.refresh_dae_process_state();
            (
                runtime.bpf.is_some(),
                process_activity_changed,
                runtime.bpf_attach_mode_mismatch(),
            )
        };
        let signals =
            DaeModeTickSignals::new(has_bpf, process_activity_changed, attach_mode_mismatch);
        let retry_delay = self
            .runtime
            .as_ref()
            .map_or(self.state.config().refresh_interval_ms, |runtime| {
                runtime.collection_interval_ms(self.state.config().refresh_interval_ms)
            });
        let mut mode_reload = std::mem::take(&mut self.mode_reload);
        let outcome = run_dae_mode_tick(
            &mut mode_reload,
            self,
            signals,
            |app| app.reload_inner().map_err(|error| error.to_string()),
            |app| app.state.fatal_error().is_some(),
            |app| {
                schedule_absolute_collection(
                    app.collection_timer.as_ref().unwrap(),
                    &app.collection_deadline_ms,
                    retry_delay,
                )
                .map_err(|error| error.to_string())
            },
            Self::collect_current_tick,
        );
        self.mode_reload = mode_reload;
        match outcome {
            DaeModeTickOutcome::Collected | DaeModeTickOutcome::Reloaded => {}
            DaeModeTickOutcome::RetryScheduled { reload_error } => {
                self.last_error = Some(reload_error);
            }
            DaeModeTickOutcome::FatalReload { reload_error } => {
                self.last_error = Some(reload_error);
                UloopGuard::request_stop();
            }
            DaeModeTickOutcome::RetryScheduleFailed {
                reload_error,
                timer_error,
            } => {
                let message = format!(
                    "dynamic BPF mode reload failed: {reload_error}; collection timer rearm failed: {timer_error}"
                );
                self.last_error = Some(message.clone());
                *self.state.fatal_cell().borrow_mut() = Some(message);
                UloopGuard::request_stop();
            }
        }
    }

    fn collect_current_tick(&mut self) {
        let timer = self.collection_timer.as_ref().unwrap();
        let deadline = &self.collection_deadline_ms;
        let runtime = self
            .runtime
            .as_mut()
            .expect("collection timer requires a staged runtime");
        if let Err(error) = collect_and_reschedule(
            &self.state,
            runtime,
            |delay| schedule_absolute_collection(timer, deadline, delay),
            UloopGuard::request_stop,
        ) {
            self.last_error = Some(error.to_string());
        }
    }
    fn refresh_clients_connections(&mut self) -> Result<(), DaemonError> {
        let base = self.state.snapshot();
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| DaemonError::collection("runtime is not started"))?;
        let checkpoint = runtime.checkpoint();
        let snapshot = match runtime.refresh_connections(&base) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                runtime.restore(checkpoint);
                return Err(error);
            }
        };
        self.state.publish_runtime_snapshot(snapshot);
        Ok(())
    }
    #[cfg(feature = "nss-platform")]
    fn refresh_clients_control_state(&mut self) -> Result<(), DaemonError> {
        let mut snapshot = (*self.state.snapshot()).clone();
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| DaemonError::collection("runtime is not started"))?;
        // Keep the clients RPC as a structural control observation, but do not
        // publish a second conntrack overlay between the status and interfaces
        // reads that form one LuCI refresh. Connection details retain their
        // explicit hot refresh path below.
        runtime.reconcile_control_state();
        runtime.decorate_controls(&mut snapshot.clients);
        self.state.publish_runtime_snapshot(snapshot);
        Ok(())
    }
    fn before_reply(&mut self, method: ubus::Method) -> Result<(), DaemonError> {
        #[cfg(feature = "nss-platform")]
        if method == ubus::Method::Diagnostics {
            // NSS intentionally skips periodic conntrack reads so conntrack
            // never becomes a client-rate owner.  Diagnostics still needs an
            // explicit, cached read-only snapshot to distinguish "not part of
            // the NSS rate loop" from an actually unavailable conntrack
            // source.  The existing refresh path is cache-coalesced and does
            // not touch the NSS/CPU RateMux.
            self.refresh_clients_connections()?;
            return self.refresh_clients_control_state();
        }
        match before_reply_action(method) {
            BeforeReplyAction::None => Ok(()),
            BeforeReplyAction::RefreshConnections => {
                #[cfg(feature = "nss-platform")]
                if method == ubus::Method::Clients {
                    return self.refresh_clients_control_state();
                }
                self.refresh_clients_connections()
            }
            BeforeReplyAction::Reload => self.reload(),
        }
    }
    fn handle_control(&mut self, command: ControlCommand) -> Result<Value, DaemonError> {
        let runtime = self
            .runtime
            .as_mut()
            .ok_or_else(|| DaemonError::collection("runtime is not started"))?;
        match command {
            ControlCommand::Set(request) => runtime.client_control_set(request),
            ControlCommand::Delete(request) => runtime.client_control_delete(request),
        }
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
    fn reload(&mut self) -> Result<(), DaemonError> {
        let result = self.reload_inner();
        if result.is_ok() {
            self.mode_reload.complete();
        }
        result
    }

    fn reload_inner(&mut self) -> Result<(), DaemonError> {
        if self.runtime.is_none() {
            return Err(DaemonError::reload("runtime is not started"));
        }
        let config = load_config()?;
        let current = self.runtime.as_ref().unwrap();
        let process_tracker = current.process_tracker.clone();
        #[cfg(feature = "nss-platform")]
        let attachment_generation_floor = current.access_edge.attachment_generation_watermark();
        let mut candidate =
            ProductionRuntime::prepare_with_process_tracker(config.clone(), process_tracker)?;
        #[cfg(feature = "nss-platform")]
        {
            let current = self.runtime.as_ref().unwrap();
            candidate.control.inherit_nss_reload_state(&current.control);
            candidate.control_platform_owner = false;
            candidate
                .access_edge
                .advance_attachment_generation_floor(attachment_generation_floor);
        }
        #[cfg(feature = "nss-platform")]
        candidate
            .nss
            .activate(&candidate.config, &candidate.probe_report);
        let wants_bpf = config.enable_bpf
            && matches!(
                config.rate_collector_mode,
                crate::config::RateCollectorMode::Auto
                    | crate::config::RateCollectorMode::Bpf
                    | crate::config::RateCollectorMode::NssEcmBpf
            )
            && candidate.probe_report.facts.tc.safe_attach;
        let desired_mode = candidate.desired_attach_mode();
        let current_has_bpf = self
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.bpf.is_some());
        let reconfigure_strategy = if wants_bpf && current_has_bpf {
            let current_bpf = self.runtime.as_ref().unwrap().bpf.as_ref().unwrap();
            if current_bpf.attach_mode().is_none() {
                return Err(DaemonError::reload(
                    "current BPF topology is not healthy enough to reload",
                ));
            }
            Some(current_bpf.reconfigure_strategy(desired_mode))
        } else {
            None
        };
        let reuse_bpf = reconfigure_strategy == Some(ReconfigureStrategy::InPlace);
        let suspended_mode_switch =
            reconfigure_strategy == Some(ReconfigureStrategy::SuspendThenAttach);
        let mut prepared_bpf = None;
        let mut mode_switch_checkpoint = None;
        let mut snapshot = if reuse_bpf {
            let current = self.runtime.as_mut().unwrap();
            if current.config.max_clients == config.max_clients
                && current.config.active_client_window_ms == config.active_client_window_ms
            {
                candidate.bpf_collector = current.bpf_collector.clone();
            }
            candidate.bpf_error = current.bpf_error.clone();
            candidate.bpf_error_stage = current.bpf_error_stage;
            let runtime = current.bpf.as_mut().unwrap();
            let transaction = match runtime.prepare_reconfigure(
                &mut current.adapter,
                &collect_ifnames(&config),
                desired_mode,
            ) {
                Ok(transaction) => transaction,
                Err(error) => {
                    if error.kind() == AdapterErrorKind::DetachFailed {
                        *self.state.fatal_cell().borrow_mut() =
                            Some(format!("BPF reconfigure prepare cleanup failed: {error}"));
                        UloopGuard::request_stop();
                    }
                    return Err(DaemonError::reload(error.to_string()));
                }
            };
            if transaction.topology_changed() {
                candidate.bpf_collector.reset_rates();
            }
            match candidate.collect_with_external_bpf(
                runtime,
                &mut current.adapter,
                ProbeMethod::Reload,
            ) {
                Ok((snapshot, collection_checkpoint)) => {
                    prepared_bpf = Some(PreparedBpfReload {
                        transaction,
                        collection_checkpoint,
                    });
                    snapshot
                }
                Err(error) => {
                    if let Err(rollback) =
                        runtime.abort_reconfigure(&mut current.adapter, transaction)
                    {
                        return Err(record_fatal_cleanup(
                            "BPF reconfigure abort",
                            &error.to_string(),
                            &rollback.to_string(),
                            self.state.fatal_cell(),
                        ));
                    }
                    return Err(abort_reload_candidate(
                        &self.state,
                        &mut candidate,
                        error,
                        UloopGuard::request_stop,
                    ));
                }
            }
        } else {
            if suspended_mode_switch {
                let current = self.runtime.as_ref().unwrap();
                if current.config.max_clients == config.max_clients
                    && current.config.active_client_window_ms == config.active_client_window_ms
                {
                    candidate.bpf_collector = current.bpf_collector.clone();
                }
                candidate.bpf_error = current.bpf_error.clone();
                candidate.bpf_error_stage = current.bpf_error_stage;
                mode_switch_checkpoint = Some(candidate.checkpoint());
            } else if wants_bpf {
                if let Err(error) = candidate.activate_new_bpf() {
                    *self.state.fatal_cell().borrow_mut() = Some(error.to_string());
                    UloopGuard::request_stop();
                    return Err(error);
                }
            }
            match candidate.collect(ProbeMethod::Reload) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return Err(abort_reload_candidate(
                        &self.state,
                        &mut candidate,
                        error,
                        UloopGuard::request_stop,
                    ));
                }
            }
        };
        let old_interval = self
            .runtime
            .as_ref()
            .map_or(self.state.config().refresh_interval_ms, |runtime| {
                runtime.collection_interval_ms(self.state.config().refresh_interval_ms)
            });
        let new_interval = candidate.collection_interval_ms(config.refresh_interval_ms);
        if let Err(error) = schedule_absolute_collection(
            self.collection_timer.as_ref().unwrap(),
            &self.collection_deadline_ms,
            new_interval,
        ) {
            let bpf_rollback = prepared_bpf.take().and_then(|prepared| {
                let current = self.runtime.as_mut().unwrap();
                let runtime = current.bpf.as_mut().unwrap();
                runtime.restore_collection_checkpoint(
                    &mut candidate.bpf_collector,
                    prepared.collection_checkpoint,
                );
                runtime
                    .abort_reconfigure(&mut current.adapter, prepared.transaction)
                    .err()
            });
            let bpf_rollback_failed = bpf_rollback.is_some();
            let primary = match bpf_rollback {
                Some(rollback) => {
                    DaemonError::reload(format!("{error}; BPF rollback failed: {rollback}"))
                }
                None => DaemonError::reload(error.to_string()),
            };
            let timer = self.collection_timer.as_ref().unwrap();
            let deadline = &self.collection_deadline_ms;
            let failure = abort_reload_after_timer_failure(
                &self.state,
                &mut candidate,
                primary,
                || schedule_absolute_collection(timer, deadline, old_interval),
                UloopGuard::request_stop,
            );
            if bpf_rollback_failed && self.state.fatal_error().is_none() {
                *self.state.fatal_cell().borrow_mut() = Some(failure.to_string());
                UloopGuard::request_stop();
            }
            return Err(failure);
        }
        if suspended_mode_switch {
            let suspended = match {
                let current = self.runtime.as_mut().unwrap();
                let runtime = current.bpf.as_mut().unwrap();
                match runtime.suspend_for_replacement(&mut current.adapter) {
                    Ok(suspended) => Ok(suspended),
                    Err(error) => {
                        let old_topology_intact = runtime.is_attached();
                        Err((error, old_topology_intact))
                    }
                }
            } {
                Ok(suspended) => suspended,
                Err((error, old_topology_intact)) => {
                    let primary =
                        DaemonError::reload(format!("BPF mode-switch suspend failed: {error}"));
                    let timer = self.collection_timer.as_ref().unwrap();
                    let deadline = &self.collection_deadline_ms;
                    let restore_timer =
                        || schedule_absolute_collection(timer, deadline, old_interval);
                    let failure = finish_mode_switch_suspend_failure(
                        &self.state,
                        &mut candidate,
                        primary,
                        old_topology_intact,
                        restore_timer,
                        UloopGuard::request_stop,
                    );
                    return Err(failure);
                }
            };
            candidate.restore(
                mode_switch_checkpoint
                    .take()
                    .expect("suspended mode switch checkpointed before collection"),
            );
            candidate.bpf_collector.reset_rates();
            let interfaces = collect_ifnames(&config);
            let attach_result = {
                let current = self.runtime.as_mut().unwrap();
                current.bpf.as_mut().unwrap().attach_suspended(
                    &mut current.adapter,
                    &suspended,
                    &interfaces,
                    desired_mode,
                )
            };
            if let Err(error) = attach_result {
                let restore = {
                    let current = self.runtime.as_mut().unwrap();
                    current
                        .bpf
                        .as_mut()
                        .unwrap()
                        .resume_suspended(&mut current.adapter, suspended)
                };
                let timer = self.collection_timer.as_ref().unwrap();
                let deadline = &self.collection_deadline_ms;
                return Err(finish_mode_switch_rollback(
                    &self.state,
                    &mut candidate,
                    DaemonError::reload(error.to_string()),
                    restore,
                    || schedule_absolute_collection(timer, deadline, old_interval),
                    UloopGuard::request_stop,
                ));
            }
            let collected = {
                let current = self.runtime.as_mut().unwrap();
                candidate.collect_with_external_bpf(
                    current.bpf.as_mut().unwrap(),
                    &mut current.adapter,
                    ProbeMethod::Reload,
                )
            };
            snapshot = match collected {
                Ok((snapshot, _)) => snapshot,
                Err(error) => {
                    let restore = {
                        let current = self.runtime.as_mut().unwrap();
                        let runtime = current.bpf.as_mut().unwrap();
                        runtime
                            .suspend_for_replacement(&mut current.adapter)
                            .and_then(|_| runtime.resume_suspended(&mut current.adapter, suspended))
                    };
                    let timer = self.collection_timer.as_ref().unwrap();
                    let deadline = &self.collection_deadline_ms;
                    return Err(finish_mode_switch_rollback(
                        &self.state,
                        &mut candidate,
                        error,
                        restore,
                        || schedule_absolute_collection(timer, deadline, old_interval),
                        UloopGuard::request_stop,
                    ));
                }
            };
            let current = self.runtime.as_mut().unwrap();
            candidate.adapter = std::mem::take(&mut current.adapter);
            candidate.bpf = current.bpf.take();
        }
        let postcommit_cleanup: Option<BpfPostCommitCleanup<SystemAyaLink>> =
            prepared_bpf.take().map(|prepared| {
                let current = self.runtime.as_mut().unwrap();
                let runtime = current.bpf.as_mut().unwrap();
                let cleanup = runtime
                    .commit_reconfigure(prepared.transaction, ReconfigureRateBaseline::Prepared);
                candidate.adapter = std::mem::take(&mut current.adapter);
                candidate.bpf = current.bpf.take();
                cleanup
            });
        #[cfg(feature = "nss-platform")]
        {
            // From this point commit_reload cannot reject the candidate. Give
            // it cleanup authority before the old runtime is retired, and
            // make the old shutdown preserve the shared dataplane objects.
            candidate.control_platform_owner = true;
            self.runtime.as_mut().unwrap().control_platform_owner = false;
        }
        commit_reload(
            &mut self.state,
            &mut self.runtime,
            candidate,
            config,
            snapshot,
            UloopGuard::request_stop,
        );
        if let Some(cleanup) = postcommit_cleanup {
            let current = self.runtime.as_mut().unwrap();
            let runtime = current.bpf.as_mut().unwrap();
            if let Err(error) = runtime.run_postcommit_cleanup(&mut current.adapter, cleanup) {
                let message = format!("reload committed; postcommit BPF cleanup failed: {error}");
                *self.state.fatal_cell().borrow_mut() = Some(message);
                UloopGuard::request_stop();
            }
        }
        Ok(())
    }
}

fn finish_mode_switch_suspend_failure<R: Runtime>(
    state: &CoordinatorState,
    candidate: &mut R,
    primary: DaemonError,
    old_topology_intact: bool,
    restore_timer: impl FnOnce() -> Result<(), DaemonError>,
    request_stop: impl FnOnce(),
) -> DaemonError {
    if old_topology_intact {
        abort_reload_after_timer_failure(state, candidate, primary, restore_timer, request_stop)
    } else {
        abort_unrecoverable_mode_switch(state, candidate, primary, restore_timer, request_stop)
    }
}

fn abort_unrecoverable_mode_switch<R: Runtime>(
    state: &CoordinatorState,
    candidate: &mut R,
    primary: DaemonError,
    restore_timer: impl FnOnce() -> Result<(), DaemonError>,
    request_stop: impl FnOnce(),
) -> DaemonError {
    let candidate_cleanup = candidate.shutdown().err();
    let timer_rollback = restore_timer().err();
    let mut message = primary.to_string();
    if let Some(error) = candidate_cleanup {
        message.push_str(&format!("; candidate cleanup failed: {error}"));
    }
    if let Some(error) = timer_rollback {
        message.push_str(&format!("; timer rollback failed: {error}"));
    }
    *state.fatal_cell().borrow_mut() = Some(message.clone());
    request_stop();
    DaemonError::reload(message)
}

fn finish_mode_switch_rollback<R: Runtime>(
    state: &CoordinatorState,
    candidate: &mut R,
    primary: DaemonError,
    bpf_restore: Result<(), AdapterError>,
    restore_timer: impl FnOnce() -> Result<(), DaemonError>,
    request_stop: impl FnOnce(),
) -> DaemonError {
    let candidate_cleanup = candidate.shutdown().err();
    let old_restore = bpf_restore.err();
    let timer_rollback = restore_timer().err();
    if candidate_cleanup.is_none() && old_restore.is_none() && timer_rollback.is_none() {
        return primary;
    }

    let mut message = primary.to_string();
    if let Some(error) = candidate_cleanup {
        message.push_str(&format!("; candidate cleanup failed: {error}"));
    }
    if let Some(error) = old_restore {
        message.push_str(&format!("; old BPF restore failed: {error}"));
    }
    if let Some(error) = timer_rollback {
        message.push_str(&format!("; timer rollback failed: {error}"));
    }
    *state.fatal_cell().borrow_mut() = Some(message.clone());
    request_stop();
    DaemonError::reload(message)
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
    let app = Rc::new(RefCell::new(App {
        state,
        runtime: None,
        ubus: None,
        collection_timer: None,
        collection_deadline_ms: Cell::new(0),
        reconnect_timer: None,
        reconnect_pending: Cell::new(false),
        mode_reload: DaeModeReloadLatch::default(),
        last_error: None,
    }));
    let weak = Rc::downgrade(&app);
    app.borrow_mut().collection_timer = Some(Timer::new(move || {
        if let Some(app) = weak.upgrade() {
            app.borrow_mut().collection_tick();
        }
    }));
    let weak = Rc::downgrade(&app);
    app.borrow_mut().reconnect_timer = Some(Timer::new(move || {
        if let Some(app) = weak.upgrade() {
            app.borrow_mut().reconnect();
        }
    }));

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
    let shutdown_result = {
        let mut app = app.borrow_mut();
        let _connection = app.ubus.take();
        shutdown_runtime(app.runtime.as_mut(), || Ok(()))
    };
    let fatal = app.borrow().state.fatal_error();
    if let Some(error) = fatal {
        return Err(DaemonError::platform(error));
    }
    run_result.and(shutdown_result)
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

#[cfg(test)]
fn version_from(version: Option<&str>, release: Option<&str>) -> String {
    system::version_from(version, release)
}

fn record_fatal_cleanup(
    context: &str,
    primary: &str,
    cleanup: &str,
    fatal: &RefCell<Option<String>>,
) -> DaemonError {
    system::record_fatal_cleanup(context, primary, cleanup, fatal)
}
