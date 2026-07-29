use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
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
    config::{
        is_sysdevice_candidate, ConnectionCollectorMode, InterfaceEligibility, RuntimeConfig,
        SysfsInterfaceEligibility, MAX_INTERFACE_NAMES, MAX_INTERFACE_NAME_LEN,
    },
    connection_details::ConnectionRateBook,
    connections::{
        apply_conntrack_failure, apply_conntrack_success, before_reply_action,
        client_conntrack_plan, periodic_conntrack_plan, publish_connection_details,
        BeforeReplyAction, ClientConntrackPlan, ConntrackObservation, PeriodicConntrackPlan,
        CLIENT_CONNTRACK_CACHE_TTL_MS, NSS_CLIENT_CONNTRACK_CACHE_TTL_MS,
    },
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
        read_interface_counter_snapshot, InterfaceCounters, InterfaceRateBook,
        MIXED_INTERFACE_SOURCE,
    },
    model::{
        Capabilities, ClientsResponse, Confidence, Conflict, Evidence, HealthResponse, Interface,
        InterfaceRole, InterfaceStatus, InterfacesResponse, Mode, OverviewResponse, OverviewSample,
        ReloadResponse, StatusResponse, Sysdevice, SysdeviceLimits, SysdevicesResponse,
    },
    platform::{
        confidence,
        counters::TrafficCounters,
        nss::{
            bpf_coverage::NssBpfCoverage,
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
            COLLECTION_INTERVAL_MS as NSS_COLLECTION_INTERVAL_MS,
        },
        x86::{
            coverage_state::X86Coverage,
            output::clients_response,
            runtime::{
                AdapterError, AdapterErrorKind, AttachMode, BpfCollectionCheckpoint,
                BpfPostCommitCleanup, BpfReconfigureTxn, BpfRuntime, ReconfigureRateBaseline,
                ReconfigureStrategy, SystemAyaAdapter, SystemAyaLink, FALLBACK_OBJECT_PATH,
            },
            snapshot::{BpfSnapshot, BpfSnapshotCollector, ConnectionCounts, ConnectionOverlay},
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

#[cfg(test)]
use crate::platform::nss::fusion::add_traffic_counters;
#[cfg(test)]
use crate::platform::nss::{
    output::{coverage_response, nss_rate_coverage_values},
    window::{CoverageWindow, EcmBpfRateBatch, RateWindowValue},
};
#[cfg(test)]
use crate::{platform::nss::ecm_bpf::EcmBpfSnapshot, probe::Confidence as ProbeConfidence};

const RECONNECT_MS: u32 = 1_000;
const INTERNAL_BPF_SELF_HEAL_REASON: &str = "production.collect.internal";
const EXTERNAL_BPF_SELF_HEAL_REASON: &str = "production.collect.external";
const INTERFACE_NOTE: &str = "Per-interface totals from one kernel net-device pass with sysfs fallback; reflect hardware-offloaded and hardware-switched traffic too.";

fn retain_collector_warnings(warnings: &mut Vec<String>, rate: RateCollector) {
    if rate == RateCollector::NssEcmBpf {
        warnings.retain(|warning| {
            !matches!(
                warning.as_str(),
                "flowtable_counter_probe_unavailable" | "flowtable_counter_missing"
            )
        });
    }
}

type Bpf = BpfRuntime<SystemAyaLink>;

fn nss_tc_snapshot(snapshot: &BpfSnapshot) -> NssTcSnapshot {
    NssTcSnapshot {
        clients: snapshot
            .clients
            .iter()
            .map(|sample| NssTcClientSample {
                mac: sample.mac.clone(),
                identity_key: sample.identity_key.clone(),
                zone: sample.zone.clone(),
                interface: sample.interface.clone(),
                ips: sample.ips.clone(),
                tx_bytes: sample.tx_bytes,
                rx_bytes: sample.rx_bytes,
                tx_bps: sample.tx_bps,
                rx_bps: sample.rx_bps,
                last_seen_ms: sample.last_seen_ms,
            })
            .collect(),
        coverage_deltas: snapshot.coverage_deltas.clone(),
        coverage_start_ms: snapshot.coverage_start_ms,
        coverage_end_ms: snapshot.coverage_end_ms,
        coverage_ready: snapshot.coverage_ready,
    }
}

fn bpf_error_stage(kind: AdapterErrorKind) -> &'static str {
    match kind {
        AdapterErrorKind::ObjectMissing
        | AdapterErrorKind::KfuncIncompatible
        | AdapterErrorKind::LoadFailed => "object_load_failed",
        AdapterErrorKind::OwnershipConflict => "tc_conflict",
        AdapterErrorKind::AttachFailed | AdapterErrorKind::DetachFailed => "tc_attach_failed",
        AdapterErrorKind::MapReadFailed => "map_read_failed",
    }
}

fn interface_master(ifname: &str) -> Option<String> {
    fs::read_link(Path::new("/sys/class/net").join(ifname).join("master"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
}

fn interface_masters() -> BTreeMap<String, String> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return BTreeMap::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| interface_master(&name).map(|master| (name, master)))
        .collect()
}

fn independent_lan_boundaries(
    roots: &[String],
    masters: &BTreeMap<String, String>,
) -> Option<Vec<String>> {
    fn expand(
        name: &str,
        masters: &BTreeMap<String, String>,
        visiting: &mut std::collections::BTreeSet<String>,
        boundaries: &mut std::collections::BTreeSet<String>,
    ) -> bool {
        if !visiting.insert(name.to_owned()) {
            return false;
        }
        let children = masters
            .iter()
            .filter_map(|(child, master)| (master == name).then_some(child.as_str()))
            .collect::<Vec<_>>();
        let valid = if children.is_empty() {
            boundaries.insert(name.to_owned());
            true
        } else {
            children
                .into_iter()
                .all(|child| expand(child, masters, visiting, boundaries))
        };
        visiting.remove(name);
        valid
    }

    let mut boundaries = std::collections::BTreeSet::new();
    let mut visiting = std::collections::BTreeSet::new();
    for root in roots {
        if !expand(root, masters, &mut visiting, &mut boundaries) {
            return None;
        }
    }
    (!boundaries.is_empty()).then(|| boundaries.into_iter().collect())
}

fn sum_interface_counters(
    names: &[String],
    counters: &BTreeMap<String, InterfaceCounters>,
) -> Option<InterfaceCounters> {
    names
        .iter()
        .try_fold(InterfaceCounters::default(), |mut total, name| {
            let value = counters.get(name)?;
            total.rx_bytes = total.rx_bytes.checked_add(value.rx_bytes)?;
            total.tx_bytes = total.tx_bytes.checked_add(value.tx_bytes)?;
            total.rx_packets = total.rx_packets.checked_add(value.rx_packets)?;
            total.tx_packets = total.tx_packets.checked_add(value.tx_packets)?;
            Some(total)
        })
}

fn effective_collection_interval_ms(owner: Option<RateCollector>, configured_ms: u32) -> u32 {
    if matches!(
        owner,
        Some(RateCollector::NssEcmNode | RateCollector::NssEcmBpf)
    ) {
        configured_ms.max(NSS_COLLECTION_INTERVAL_MS)
    } else {
        configured_ms
    }
}

fn production_now_ms() -> Result<u64, DaemonError> {
    monotonic_millis()
        .map_err(|error| DaemonError::collection(format!("read CLOCK_MONOTONIC: {error}")))
}

struct ProductionRuntime {
    config: RuntimeConfig,
    adapter: SystemAyaAdapter,
    bpf: Option<Bpf>,
    bpf_error: Option<String>,
    /// Stable internal classification for the last BPF failure. The public
    /// evidence exposes this code, while `bpf_error` remains private detail.
    bpf_error_stage: Option<&'static str>,
    bpf_collector: BpfSnapshotCollector,
    nss: NssRuntime,
    conntrack_snapshot: Option<Arc<CollectedSnapshot>>,
    connection_rates: ConnectionRateBook,
    conntrack_observation: ConntrackObservation,
    probe: SystemProbeCollector,
    process_tracker: DaeProcessTracker,
    probe_report: Arc<ProbeReport>,
    next_probe_ms: u64,
    overview: OverviewRing,
    x86_coverage: X86Coverage,
    nss_bpf_coverage: NssBpfCoverage,
    interface_rates: InterfaceRateBook,
    rate_owner: Option<RateCollector>,
    hostnames: HostnameCache,
    shutdown_complete: bool,
}

struct RuntimeCheckpoint {
    bpf: Option<BpfCollectionCheckpoint>,
    nss: NssRuntimeCheckpoint,
    overview: OverviewRing,
    x86_coverage: X86Coverage,
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
        runtime.nss.activate(&runtime.config, &runtime.probe_report);
        Ok(runtime)
    }

    fn prepare(config: RuntimeConfig) -> Result<Self, DaemonError> {
        Self::prepare_with_process_tracker(config, DaeProcessTracker::default())
    }

    fn prepare_with_process_tracker(
        config: RuntimeConfig,
        mut process_tracker: DaeProcessTracker,
    ) -> Result<Self, DaemonError> {
        let mut probe = collector::system_collector()
            .map_err(|error| DaemonError::platform(error.to_string()))?;
        process_tracker.refresh_if_due("/proc", production_now_ms()?);
        let mut preflight = probe.collect(&config, &RuntimeHealth::default(), ProbeMethod::Health);
        process_tracker.overlay_report(&mut preflight);
        Ok(Self {
            bpf_collector: BpfSnapshotCollector::new(
                config.max_clients,
                config.active_client_window_ms,
            ),
            nss: NssRuntime::default(),
            conntrack_snapshot: None,
            connection_rates: ConnectionRateBook::default(),
            conntrack_observation: ConntrackObservation::default(),
            probe,
            process_tracker,
            probe_report: Arc::new(preflight),
            next_probe_ms: 0,
            rate_owner: None,
            hostnames: HostnameCache::new(),
            config,
            adapter: SystemAyaAdapter::new(),
            bpf: None,
            bpf_error: None,
            bpf_error_stage: None,
            overview: OverviewRing::new(),
            x86_coverage: X86Coverage::default(),
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
        if !self.config.enable_bpf
            || !matches!(
                self.config.rate_collector_mode,
                crate::config::RateCollectorMode::Auto
                    | crate::config::RateCollectorMode::Bpf
                    | crate::config::RateCollectorMode::NssEcmBpf
            )
            || !self.probe_report.facts.tc.safe_attach
        {
            return Ok(());
        }
        let interfaces = collect_ifnames(&self.config);
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
            self.adapter = SystemAyaAdapter::new();
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
            nss: self.nss.checkpoint(),
            overview: self.overview.clone(),
            x86_coverage: self.x86_coverage.clone(),
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
        self.nss.restore(checkpoint.nss);
        self.overview = checkpoint.overview;
        self.x86_coverage = checkpoint.x86_coverage;
        self.nss_bpf_coverage = checkpoint.nss_bpf_coverage;
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

    fn collect_inner(
        &mut self,
        method: ProbeMethod,
        external_bpf: Option<(&mut Bpf, &mut SystemAyaAdapter)>,
    ) -> Result<ResponseSnapshot, DaemonError> {
        let mut now_ms = production_now_ms()?;
        let (identities, identity_errors) = read_identities(&self.config, now_ms);
        let mut conntrack = self.conntrack_snapshot.clone();
        let overlay = connection_overlay(conntrack.as_deref());
        let freshness_ms = u64::from(self.config.refresh_interval_ms) * 3;
        let (bpf_snapshot, mut runtime_health, bpf_snapshot_fresh) = match external_bpf {
            Some((runtime, adapter)) => {
                let (snapshot, fresh) = match runtime.collect_snapshot_self_healing(
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
                };
                let health_now_ms = snapshot
                    .as_ref()
                    .map_or(now_ms, |snapshot| now_ms.max(snapshot.sample_ms));
                (
                    snapshot,
                    runtime.runtime_health(health_now_ms, freshness_ms),
                    fresh,
                )
            }
            None => match self.bpf.as_mut() {
                Some(runtime) => {
                    let (snapshot, fresh) = match runtime.collect_snapshot_self_healing(
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
                    };
                    let health_now_ms = snapshot
                        .as_ref()
                        .map_or(now_ms, |snapshot| now_ms.max(snapshot.sample_ms));
                    (
                        snapshot,
                        runtime.runtime_health(health_now_ms, freshness_ms),
                        fresh,
                    )
                }
                None => (None, RuntimeHealth::default(), false),
            },
        };
        if let Some(snapshot) = bpf_snapshot.as_ref() {
            now_ms = now_ms.max(snapshot.sample_ms);
        }
        let (ecm_bpf_snapshot, ecm_bpf_snapshot_fresh) =
            self.nss
                .collect_ecm_bpf(&identities, &mut now_ms, freshness_ms, &mut runtime_health);
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
        let (mut interfaces, lan_clock) = self.interfaces(now_ms);
        let nss_tc_snapshot = report
            .facts
            .nss
            .present
            .then(|| bpf_snapshot.as_ref().map(nss_tc_snapshot))
            .flatten();
        self.nss
            .transition_rate_owner(&mut self.rate_owner, decision.rate);
        let mut nss_window = None;
        let mut ecm_bpf_coverage_window = None;
        let mut ecm_bpf_coverage_merge = None;
        let mut ecm_bpf_rate_batch = None;
        let (mut clients, actual_live, actual_degraded, coverage_fresh) = if decision.rate
            == RateCollector::Bpf
        {
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
            if ecm_bpf_snapshot_fresh {
                match (ecm_bpf_snapshot.as_ref(), lan_clock.as_ref()) {
                    (Some(snapshot), Some(lan)) if !snapshot.truncated => {
                        let merged = merge_ecm_bpf_coverage_delta(
                            snapshot,
                            nss_tc_snapshot.as_ref(),
                            bpf_snapshot_fresh,
                        );
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
                        ecm_bpf_coverage_window =
                            Some(self.nss.ecm_bpf_coverage.update(merged.merged, lan));
                        ecm_bpf_rate_batch = self.nss.ecm_bpf_rates.update_with_client_interfaces(
                            &client_deltas,
                            &fallback_rates,
                            &client_interfaces,
                            lan,
                            &rate_window_interface_counters(&interfaces),
                        );
                        ecm_bpf_coverage_merge = Some(merged);
                    }
                    _ => {
                        self.nss.ecm_bpf_coverage = Default::default();
                        self.nss.ecm_bpf_rates = Default::default();
                    }
                }
            }
            if ecm_bpf_rate_batch.is_none() && !ecm_bpf_snapshot_fresh {
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
                ecm_bpf_snapshot.is_some(),
                !ecm_bpf_snapshot_fresh,
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
        if let Some(batch) = ecm_bpf_rate_batch.as_ref() {
            apply_ecm_bpf_rate_batch(&mut clients, &mut interfaces, batch);
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
        let overview = self.update_overview(now_ms, &clients);
        let coverage = match decision.rate {
            RateCollector::NssEcmNode | RateCollector::NssEcmBpf => {
                nss_rate_coverage(&clients, &interfaces)
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
        let mut status_evidence = evidence(&report, method.as_str());
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
        status_evidence.details.insert(
            "bpf".into(),
            crate::production_evidence::bpf_details(
                &self.config,
                &report,
                &runtime_health,
                self.bpf_error_stage,
            ),
        );
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
        status_evidence.details.insert(
            "probe_failures".into(),
            crate::production_evidence::probe_failure_details(&report.evidence.probe_failures),
        );
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
            conn_collector_mode: self.config.conn_collector_mode.as_str().into(),
            version: version.clone(),
            capabilities: capabilities.clone(),
            coverage: Some(coverage),
        };
        let mut health_evidence = evidence(&report, "health");
        apply_decision_evidence(&mut health_evidence, &decision, &self.config, &report);
        apply_nss_snapshot_evidence(&mut health_evidence, node_snapshot.as_ref());
        apply_ecm_bpf_evidence(
            &mut health_evidence,
            &runtime_health,
            ecm_bpf_snapshot.as_ref(),
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
        health_evidence.details.insert(
            "bpf".into(),
            crate::production_evidence::bpf_details(
                &self.config,
                &report,
                &runtime_health,
                self.bpf_error_stage,
            ),
        );
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
        health_evidence.details.insert(
            "probe_failures".into(),
            crate::production_evidence::probe_failure_details(&report.evidence.probe_failures),
        );
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
        publish_connection_details(&mut response, conntrack.as_deref());
        Ok(response)
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

    fn interfaces(&mut self, now_ms: u64) -> (InterfacesResponse, Option<LanClock>) {
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
        )
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
        effective_collection_interval_ms(self.rate_owner, configured_ms)
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
                app.collection_timer
                    .as_ref()
                    .unwrap()
                    .schedule(retry_delay)
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
        let runtime = self
            .runtime
            .as_mut()
            .expect("collection timer requires a staged runtime");
        if let Err(error) = collect_and_reschedule(
            &self.state,
            runtime,
            |delay| {
                timer
                    .schedule(delay)
                    .map_err(|error| DaemonError::transport(error.to_string()))
            },
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
    fn before_reply(&mut self, method: ubus::Method) -> Result<(), DaemonError> {
        match before_reply_action(method) {
            BeforeReplyAction::None => Ok(()),
            BeforeReplyAction::RefreshConnections => self.refresh_clients_connections(),
            BeforeReplyAction::Reload => self.reload(),
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
        let process_tracker = self.runtime.as_ref().unwrap().process_tracker.clone();
        let mut candidate =
            ProductionRuntime::prepare_with_process_tracker(config.clone(), process_tracker)?;
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
        if let Err(error) = self
            .collection_timer
            .as_ref()
            .unwrap()
            .schedule(new_interval)
        {
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
            let failure = abort_reload_after_timer_failure(
                &self.state,
                &mut candidate,
                primary,
                || {
                    timer
                        .schedule(old_interval)
                        .map_err(|error| DaemonError::transport(error.to_string()))
                },
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
                    let restore_timer = || {
                        timer
                            .schedule(old_interval)
                            .map_err(|error| DaemonError::transport(error.to_string()))
                    };
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
                return Err(finish_mode_switch_rollback(
                    &self.state,
                    &mut candidate,
                    DaemonError::reload(error.to_string()),
                    restore,
                    || {
                        timer
                            .schedule(old_interval)
                            .map_err(|error| DaemonError::transport(error.to_string()))
                    },
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
                    return Err(finish_mode_switch_rollback(
                        &self.state,
                        &mut candidate,
                        error,
                        restore,
                        || {
                            timer
                                .schedule(old_interval)
                                .map_err(|error| DaemonError::transport(error.to_string()))
                        },
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
    let object = ubus::object(snapshots, move |method| {
        weak.upgrade()
            .ok_or_else(|| DaemonError::reload("daemon stopped"))?
            .borrow_mut()
            .before_reply(method)
    })?;
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
        activate_runtime(
            &app.state,
            runtime,
            |delay| {
                timer
                    .schedule(delay)
                    .map_err(|error| DaemonError::transport(error.to_string()))
            },
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

fn evidence(report: &ProbeReport, method: &str) -> Evidence {
    let mut details = BTreeMap::new();
    details.insert("source".into(), json!(report.evidence.source));
    details.insert("method".into(), json!(method));
    details.insert("read_only".into(), json!(true));
    details.insert("probe_error".into(), json!(report.evidence.probe_error));
    details.insert(
        "lan_probe_error".into(),
        json!(report.evidence.lan_probe_error),
    );
    details.insert(
        "effective_collector".into(),
        json!(report.evidence.collector.effective_rate_collector),
    );
    details.insert(
        "platform".into(),
        json!({
            "target_arch": std::env::consts::ARCH,
            "nss_modes_exposed": cfg!(target_arch = "aarch64") && report.facts.nss.present,
        }),
    );
    details.insert("collector".into(), json!({"rate_reason":report.evidence.collector.rate_reason,"connection_reason":report.evidence.collector.connection_reason,
        "primary_source":report.evidence.collector.effective_rate_collector,"mode":report.evidence.collector.mode,"confidence":report.evidence.collector.confidence}));
    details.insert(
        "dae".into(),
        json!({
            "running": report.evidence.proxy.dae.dae_running
                || report.evidence.proxy.dae.daed_running,
            "process": report.evidence.proxy.dae.dae_process
                || report.evidence.proxy.dae.daed_process,
            "runtime_active": report.evidence.proxy.dae.runtime_active,
            "process_probe_error": report.evidence.proxy.dae.process_probe_error,
            "dae_running": report.evidence.proxy.dae.dae_running,
            "daed_running": report.evidence.proxy.dae.daed_running,
            "dae_process": report.evidence.proxy.dae.dae_process,
            "daed_process": report.evidence.proxy.dae.daed_process,
        }),
    );
    Evidence { details }
}

fn conntrack_generation_evidence(snapshot: &CollectedSnapshot) -> Value {
    let parsed_entries = snapshot
        .stats
        .entries_seen
        .saturating_sub(snapshot.stats.malformed_lines);
    let flow_id_coverage_pct = (parsed_entries > 0)
        .then(|| snapshot.stats.conntrack_ids_present as f64 * 100.0 / parsed_entries as f64);
    json!({
        "counter_generation_key": if snapshot.stats.netlink_read {
            "ctnetlink_cta_id_with_zone_tuple_fallback"
        } else {
            "procfs_zone_tuple_fallback"
        },
        "parsed_entries": parsed_entries,
        "conntrack_ids_present": snapshot.stats.conntrack_ids_present,
        "conntrack_zones_present": snapshot.stats.conntrack_zones_present,
        "flow_id_coverage_pct": flow_id_coverage_pct,
    })
}

fn apply_decision_evidence(
    evidence: &mut Evidence,
    decision: &policy::PolicyDecision,
    config: &RuntimeConfig,
    report: &ProbeReport,
) {
    let effective = decision.rate.as_str();
    evidence
        .details
        .insert("effective_collector".into(), json!(effective));
    let effective_interval_ms =
        effective_collection_interval_ms(Some(decision.rate), config.refresh_interval_ms);
    if let Some(collector) = evidence
        .details
        .get_mut("collector")
        .and_then(Value::as_object_mut)
    {
        collector.insert("primary_source".into(), json!(effective));
        collector.insert(
            "effective_connection_collector".into(),
            json!(decision.connection.as_str()),
        );
        collector.insert("rate_reason".into(), json!(decision.evidence.rate_reason));
        collector.insert(
            "connection_reason".into(),
            json!(decision.evidence.connection_reason),
        );
        collector.insert("mode".into(), json!(decision.mode.as_str()));
        collector.insert("confidence".into(), json!(decision.confidence.as_str()));
        collector.insert("warnings".into(), json!(decision.warnings));
        collector.insert("effective_interval_ms".into(), json!(effective_interval_ms));
    }
    evidence.details.insert(
        "nss".into(),
        crate::production_evidence::nss_details(config, report, decision),
    );
}

fn capabilities(value: &ProbeCapabilities, report: &ProbeReport) -> Capabilities {
    Capabilities {
        // `bpf_supported` is a platform/configuration capability. Keep it
        // independent from the compatibility `bpf` capability field.
        bpf_supported: value.tc && value.tc_clsact && report.facts.tc.bpf,
        bpf: value.bpf,
        bpf_package: value.bpf_package,
        bpf_object: value.bpf_object,
        bpf_runtime_metrics: value.bpf_runtime_metrics,
        conntrack_fallback: value.conntrack_fallback,
        live_metrics: value.live_metrics,
        fw4: value.fw4,
        nft: value.nft,
        software_flow_offload: value.software_flow_offload,
        hardware_flow_offload: value.hardware_flow_offload,
        nss: report.facts.nss.present,
        nss_ecm_offload: report.facts.nss.ecm_active,
        nss_ppe_offload: report.facts.nss.ppe_active,
        nss_ecm_node: report.facts.nss.direct_state_readable,
        nss_ecm_bpf: value.nss_ecm_bpf,
        nss_bridge_mgr: report.evidence.nss.bridge_mgr,
        nss_ifb: report.evidence.nss.ifb_active,
        nss_nsm: report.evidence.nss.nsm_active,
        nss_dp: report.evidence.nss.dp_active,
        nss_mcs: report.evidence.nss.mcs_active,
        fullcone: value.fullcone,
        nf_conntrack_acct: value.nf_conntrack_acct,
        flowtable_counter: value.flowtable_counter,
        tc: value.tc,
        tc_clsact: value.tc_clsact,
        existing_tc_filters: value.existing_tc_filters,
        ifb: value.ifb,
        sqm: value.sqm,
        qosify: value.qosify,
        openclash: value.openclash,
        openclash_fake_ip: value.openclash_fake_ip,
        openclash_tun_mix: value.openclash_tun_mix,
        openclash_redirect_dns: value.openclash_redirect_dns,
        openclash_dns_chain_complete: value.openclash_dns_chain_complete,
        openclash_router_self_proxy: value.openclash_router_self_proxy,
        openclash_udp_proxy: value.openclash_udp_proxy,
        openclash_ipv6: value.openclash_ipv6,
        dae: value.dae,
        homeproxy: value.homeproxy,
        lan_bridge: value.lan_bridge,
        vlan: value.vlan,
        wlan: value.wlan,
        lan_edge: value.lan_edge,
        safe_attach: value.safe_attach,
        map_full: value.map_full,
    }
}

fn mode(value: ProbeMode) -> Mode {
    match value {
        ProbeMode::Full => Mode::Full,
        ProbeMode::Degraded => Mode::Degraded,
        ProbeMode::Unsupported => Mode::Unsupported,
    }
}
fn conntrack_mode(value: ConnectionCollectorMode) -> ConntrackMode {
    match value {
        ConnectionCollectorMode::Auto => ConntrackMode::Auto,
        ConnectionCollectorMode::ConntrackNetlink => ConntrackMode::Netlink,
        ConnectionCollectorMode::ConntrackProcfs => ConntrackMode::Procfs,
    }
}
fn collect_ifnames(config: &RuntimeConfig) -> Vec<String> {
    config.runtime_collect_ifnames()
}
fn collect_ifnames_with_roles(config: &RuntimeConfig) -> Vec<(String, InterfaceRole)> {
    collect_ifnames(config)
        .into_iter()
        .map(|name| (name, InterfaceRole::Lan))
        .chain(
            config
                .runtime_observe_ifnames()
                .into_iter()
                .map(|name| (name, InterfaceRole::Observe)),
        )
        .collect()
}

fn sysdevices(config: &RuntimeConfig) -> Result<SysdevicesResponse, DaemonError> {
    let selected = collect_ifnames(config);
    let observed = config.runtime_observe_ifnames();
    let configured_ifnames = if config.configured_ifnames.is_empty() {
        let mut names = Vec::new();
        for name in config.ifnames.iter().chain(config.interface_include.iter()) {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    } else {
        config.configured_ifnames.clone()
    };
    let configured_observed = if config.configured_observed.is_empty() {
        config.observe_ifnames.clone()
    } else {
        config.configured_observed.clone()
    };
    let configured_excluded = if config.configured_excluded.is_empty() {
        config.interface_exclude.clone()
    } else {
        config.configured_excluded.clone()
    };
    let eligibility = SysfsInterfaceEligibility::default();
    let mut devices = Vec::new();
    for entry in fs::read_dir("/sys/class/net")
        .map_err(|error| DaemonError::collection(error.to_string()))?
    {
        let name = entry
            .map_err(|error| DaemonError::collection(error.to_string()))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if !is_sysdevice_candidate(&name) {
            continue;
        }
        let root = Path::new("/sys/class/net").join(&name);
        let speed = fs::read_to_string(root.join("speed"))
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v > 0 && *v < (1 << 31));
        let recommended = eligibility.is_collect_eligible(&name);
        let is_bridge = root.join("bridge").is_dir();
        let is_bridge_port = root.join("brport").is_dir();
        let is_nss_ifb = name == "nssifb";
        let collect_allowed = recommended && !is_nss_ifb;
        let collect_reason = if collect_allowed && is_bridge {
            "eligible_bridge"
        } else if collect_allowed && is_bridge_port {
            "eligible_bridge_port"
        } else if collect_allowed {
            "eligible_ethernet"
        } else if is_nss_ifb {
            "nssifb_observe_only"
        } else {
            "unsupported_link_type"
        };
        devices.push(Sysdevice {
            name: name.clone(),
            selected: selected.contains(&name),
            observed: observed.contains(&name),
            recommended_lan: recommended,
            collect_allowed,
            collect_reason: collect_reason.into(),
            is_bridge,
            is_bridge_port,
            is_nss_ifb,
            speed_mbps: speed,
        });
    }
    let discovered = devices
        .iter()
        .map(|device| device.name.as_str())
        .collect::<Vec<_>>();
    let mut orphaned = Vec::new();
    for name in configured_ifnames
        .iter()
        .chain(configured_observed.iter())
        .chain(configured_excluded.iter())
    {
        if !discovered.contains(&name.as_str()) && !orphaned.contains(name) {
            orphaned.push(name.clone());
        }
    }
    Ok(SysdevicesResponse {
        contract_version: 1,
        devices,
        current_ifnames: selected,
        current_observed: observed,
        // `interface_exclude` is compatibility-only and does not alter the
        // runtime attach set, so no exclusion is currently effective.
        current_excluded: Vec::new(),
        configured_ifnames,
        configured_observed,
        configured_excluded,
        orphaned,
        limits: SysdeviceLimits {
            max_configured: MAX_INTERFACE_NAMES,
            max_name_length: MAX_INTERFACE_NAME_LEN.saturating_sub(1),
        },
    })
}

fn version() -> String {
    version_from(
        option_env!("LANSPEED_VERSION"),
        option_env!("LANSPEED_RELEASE"),
    )
}

fn version_from(version: Option<&str>, release: Option<&str>) -> String {
    match (version, release) {
        (Some(version), Some(release)) => format!("{version}-r{release}"),
        _ => "unconfigured".into(),
    }
}

fn record_fatal_cleanup(
    context: &str,
    primary: &str,
    cleanup: &str,
    fatal: &RefCell<Option<String>>,
) -> DaemonError {
    let combined = format!("{context}: {primary}; cleanup failed: {cleanup}");
    *fatal.borrow_mut() = Some(combined.clone());
    UloopGuard::request_stop();
    DaemonError::reload(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::nss::ecm_bpf::EcmBpfClientSample;

    #[derive(Default)]
    struct FakeRuntime {
        shutdowns: usize,
        fail_shutdown: bool,
    }

    impl Runtime for FakeRuntime {
        type Checkpoint = ();

        fn checkpoint(&self) -> Self::Checkpoint {}

        fn restore(&mut self, _checkpoint: Self::Checkpoint) {}

        fn collect(&mut self) -> Result<ResponseSnapshot, DaemonError> {
            unreachable!("mode-switch failure tests do not collect")
        }

        fn shutdown(&mut self) -> Result<(), DaemonError> {
            self.shutdowns += 1;
            if self.fail_shutdown {
                Err(DaemonError::collection("candidate shutdown failed"))
            } else {
                Ok(())
            }
        }
    }

    fn test_state() -> CoordinatorState {
        CoordinatorState::new(
            RuntimeConfig::default(),
            Arc::new(ResponseSnapshot::unsupported("test")),
        )
    }

    #[test]
    fn ecm_bpf_ignores_flowtable_warnings_owned_by_other_offload_paths() {
        let original = vec![
            "flowtable_counter_probe_unavailable".to_owned(),
            "flowtable_counter_missing".to_owned(),
            "nss_ecm_bpf_active".to_owned(),
        ];
        let mut ecm_bpf = original.clone();
        retain_collector_warnings(&mut ecm_bpf, RateCollector::NssEcmBpf);
        assert_eq!(ecm_bpf, ["nss_ecm_bpf_active"]);

        let mut bpf = original.clone();
        retain_collector_warnings(&mut bpf, RateCollector::Bpf);
        assert_eq!(bpf, original);
    }

    #[test]
    fn intact_suspend_failure_restores_timer_without_fatal_stop() {
        let state = test_state();
        let mut candidate = FakeRuntime::default();
        let timer_restores = Cell::new(0);
        let stopped = Cell::new(false);

        let error = finish_mode_switch_suspend_failure(
            &state,
            &mut candidate,
            DaemonError::reload("inspect failed"),
            true,
            || {
                timer_restores.set(timer_restores.get() + 1);
                Ok(())
            },
            || stopped.set(true),
        );

        assert!(error.to_string().contains("inspect failed"));
        assert_eq!(candidate.shutdowns, 1);
        assert_eq!(timer_restores.get(), 1);
        assert!(!stopped.get());
        assert!(state.fatal_error().is_none());
    }

    #[test]
    fn mutated_suspend_failure_is_fatal_even_when_cleanup_succeeds() {
        let state = test_state();
        let mut candidate = FakeRuntime::default();
        let timer_restores = Cell::new(0);
        let stopped = Cell::new(false);

        finish_mode_switch_suspend_failure(
            &state,
            &mut candidate,
            DaemonError::reload("detach failed"),
            false,
            || {
                timer_restores.set(timer_restores.get() + 1);
                Ok(())
            },
            || stopped.set(true),
        );

        assert_eq!(candidate.shutdowns, 1);
        assert_eq!(timer_restores.get(), 1);
        assert!(stopped.get());
        assert!(state
            .fatal_error()
            .is_some_and(|error| error.contains("detach failed")));
    }

    #[test]
    fn failed_old_topology_restore_is_fatal_and_preserves_both_causes() {
        let state = test_state();
        let mut candidate = FakeRuntime::default();
        let stopped = Cell::new(false);

        let error = finish_mode_switch_rollback(
            &state,
            &mut candidate,
            DaemonError::reload("candidate collect failed"),
            Err(AdapterError::new(
                AdapterErrorKind::DetachFailed,
                "old restore failed",
            )),
            || Ok(()),
            || stopped.set(true),
        );

        assert!(error.to_string().contains("candidate collect failed"));
        assert!(error.to_string().contains("old restore failed"));
        assert!(stopped.get());
        assert!(state.fatal_error().is_some());
    }

    #[test]
    fn successful_old_topology_restore_returns_plain_reload_error() {
        let state = test_state();
        let mut candidate = FakeRuntime::default();
        let stopped = Cell::new(false);

        let error = finish_mode_switch_rollback(
            &state,
            &mut candidate,
            DaemonError::reload("candidate collect failed"),
            Ok(()),
            || Ok(()),
            || stopped.set(true),
        );

        assert!(error.to_string().contains("candidate collect failed"));
        assert_eq!(candidate.shutdowns, 1);
        assert!(!stopped.get());
        assert!(state.fatal_error().is_none());
    }

    #[test]
    fn cleanup_failures_are_fatal_and_preserve_both_causes() {
        for context in [
            "candidate cleanup",
            "postcommit old runtime cleanup",
            "BPF switch rollback",
            "multi-interface activation rollback",
        ] {
            let fatal = RefCell::new(None);
            let error = record_fatal_cleanup(context, "primary", "cleanup", &fatal);
            let message = error.to_string();
            assert!(message.contains(context));
            assert!(message.contains("primary"));
            assert!(message.contains("cleanup"));
            assert_eq!(
                fatal.borrow().as_deref(),
                Some(message.trim_start_matches("reload: "))
            );
        }
    }

    #[test]
    fn production_version_requires_package_version_and_release() {
        assert_eq!(version_from(Some("1.0.0"), Some("1")), "1.0.0-r1");
        assert_eq!(version_from(Some("1.0.0"), None), "unconfigured");
        assert_eq!(version_from(None, Some("1")), "unconfigured");
    }

    #[test]
    fn conntrack_generation_evidence_reports_real_cta_id_coverage() {
        let snapshot = CollectedSnapshot {
            clients: Vec::new(),
            sample_ms: 1,
            connection_details: Arc::default(),
            connection_counters: Arc::default(),
            counter_source: conntrack::NETLINK_COUNTER_SOURCE,
            stats: conntrack::CollectStats {
                netlink_read: true,
                entries_seen: 5,
                malformed_lines: 1,
                conntrack_ids_present: 3,
                conntrack_zones_present: 4,
                ..conntrack::CollectStats::default()
            },
        };

        let evidence = conntrack_generation_evidence(&snapshot);
        assert_eq!(
            evidence["counter_generation_key"],
            "ctnetlink_cta_id_with_zone_tuple_fallback"
        );
        assert_eq!(evidence["parsed_entries"], 4);
        assert_eq!(evidence["conntrack_ids_present"], 3);
        assert_eq!(evidence["conntrack_zones_present"], 4);
        assert_eq!(evidence["flow_id_coverage_pct"], 75.0);
    }

    #[test]
    fn periodic_collection_does_not_run_blocking_system_probe() {
        assert!(probe_due(0, 0, ProbeMethod::Status));
        assert!(!probe_due(29_999, 30_000, ProbeMethod::Status));
        assert!(probe_due(30_000, 30_000, ProbeMethod::Status));
        assert!(probe_due(1, u64::MAX, ProbeMethod::Reload));
    }

    #[test]
    fn lan_clock_replaces_a_batched_bridge_with_its_physical_members() {
        let masters = BTreeMap::from([
            ("lan1".into(), "br-lan".into()),
            ("lan2".into(), "br-lan".into()),
            ("wlan0".into(), "br-lan".into()),
        ]);

        let selected = independent_lan_boundaries(&["br-lan".into()], &masters).unwrap();

        assert_eq!(selected, vec!["lan1", "lan2", "wlan0"]);
    }

    #[test]
    fn lan_clock_deduplicates_overlapping_roots_and_sums_disjoint_boundaries() {
        let masters = BTreeMap::from([
            ("lan1".into(), "br-lan".into()),
            ("lan2".into(), "br-lan".into()),
        ]);
        let selected = independent_lan_boundaries(
            &["br-lan".into(), "lan2".into(), "br-guest".into()],
            &masters,
        )
        .unwrap();
        assert_eq!(selected, vec!["br-guest", "lan1", "lan2"]);

        let counters = BTreeMap::from([
            (
                "lan1".into(),
                InterfaceCounters {
                    rx_bytes: 100,
                    tx_bytes: 200,
                    rx_packets: 1,
                    tx_packets: 2,
                },
            ),
            (
                "lan2".into(),
                InterfaceCounters {
                    rx_bytes: 300,
                    tx_bytes: 400,
                    rx_packets: 3,
                    tx_packets: 4,
                },
            ),
            (
                "br-guest".into(),
                InterfaceCounters {
                    rx_bytes: 500,
                    tx_bytes: 600,
                    rx_packets: 5,
                    tx_packets: 6,
                },
            ),
        ]);
        assert_eq!(
            sum_interface_counters(&selected, &counters),
            Some(InterfaceCounters {
                rx_bytes: 900,
                tx_bytes: 1_200,
                rx_packets: 9,
                tx_packets: 12,
            })
        );
    }

    #[test]
    fn effective_collector_controls_only_the_nss_timer_floor() {
        assert_eq!(effective_collection_interval_ms(None, 500), 500);
        assert_eq!(
            effective_collection_interval_ms(Some(RateCollector::Bpf), 500),
            500
        );
        assert_eq!(
            effective_collection_interval_ms(Some(RateCollector::NssEcmNode), 500),
            2_000
        );
        assert_eq!(
            effective_collection_interval_ms(Some(RateCollector::NssEcmBpf), 1_000),
            2_000
        );
        assert_eq!(
            effective_collection_interval_ms(Some(RateCollector::NssEcmBpf), 3_000),
            3_000
        );
    }

    #[test]
    fn nss_rate_coverage_publishes_each_current_reportable_direction() {
        let coverage = nss_rate_coverage_values(2_000, 18_000, 34_000, 12_000, 89_000);

        assert_eq!(coverage.quality, "pending");
        assert_eq!(coverage.samples, 1);
        assert_eq!(coverage.window_ms, Some(2_000));
        assert_eq!(coverage.tx_pct, None);
        assert_eq!(coverage.rx_pct, Some(38));
        assert_eq!(coverage.denom_rx_bytes, Some(3_000));
        assert_eq!(coverage.denom_tx_bytes, Some(22_250));
        assert_eq!(coverage.numer_tx_bytes, Some(4_500));
        assert_eq!(coverage.numer_rx_bytes, Some(8_500));
    }

    #[test]
    fn nss_rate_coverage_uses_the_current_interface_window_without_clamping() {
        let coverage =
            nss_rate_coverage_values(2_000, 980_000_000, 970_000_000, 1_000_000_000, 990_000_000);

        assert_eq!(coverage.quality, "ok");
        assert_eq!(coverage.tx_pct, Some(98));
        assert_eq!(coverage.rx_pct, Some(97));

        let idle = nss_rate_coverage_values(2_000, 0, 0, 0, 0);
        assert_eq!(idle.quality, "idle");
        assert_eq!(idle.tx_pct, None);
        assert_eq!(idle.rx_pct, None);
    }

    #[test]
    fn ecm_bpf_high_rate_floor_uses_the_discovered_client_interface() {
        let identity_key = "02:00:00:00:00:01@lan";
        let mut snapshot = coverage_snapshot(1_000, 3_000, &[]);
        snapshot.clients.push(EcmBpfClientSample {
            mac: "02:00:00:00:00:01".into(),
            identity_key: identity_key.into(),
            zone: "lan".into(),
            interface: "bridge-dynamic".into(),
            ips: vec!["192.0.2.1".into()],
            tx_bytes: 0,
            rx_bytes: 0,
            tx_bps: 0,
            rx_bps: 0,
            sample_ms: 3_000,
            last_seen_ms: 3_000,
        });
        let mut clients = ecm_bpf_clients_response(
            Some(&snapshot),
            None,
            false,
            3_000,
            None,
            &IdentityTable::new(4),
            ProbeConfidence::High,
        );
        let mut interfaces = InterfacesResponse {
            interfaces: vec![
                Interface {
                    name: "bridge-dynamic".into(),
                    role: InterfaceRole::Lan,
                    status: InterfaceStatus::Available,
                    rx_bytes: Some(100),
                    tx_bytes: Some(200),
                    rx_bps: Some(0),
                    tx_bps: Some(0),
                    delta_ms: Some(2_000),
                    sample_ms: Some(3_000),
                    source: Some("kernel counters".into()),
                    coverage: None,
                    evidence: None,
                },
                Interface {
                    name: "member-dynamic".into(),
                    role: InterfaceRole::Observe,
                    status: InterfaceStatus::Available,
                    rx_bytes: Some(300),
                    tx_bytes: Some(400),
                    rx_bps: Some(0),
                    tx_bps: Some(0),
                    delta_ms: Some(2_000),
                    sample_ms: Some(3_000),
                    source: Some("kernel counters".into()),
                    coverage: None,
                    evidence: None,
                },
            ],
            monotonic_ms: Some(3_000),
            note: None,
            evidence: None,
        };
        let batch = EcmBpfRateBatch {
            start_ms: 3_000,
            end_ms: 5_000,
            clients: BTreeMap::from([(
                identity_key.into(),
                RateWindowValue {
                    tx_bps: 100_000_000,
                    rx_bps: 50_000_000,
                },
            )]),
            interfaces: BTreeMap::from([
                (
                    "bridge-dynamic".into(),
                    RateWindowValue {
                        rx_bps: 10_000_000,
                        tx_bps: 20_000_000,
                    },
                ),
                (
                    "member-dynamic".into(),
                    RateWindowValue {
                        rx_bps: 30_000_000,
                        tx_bps: 40_000_000,
                    },
                ),
            ]),
            raw_aligned: false,
            fallback_event_gap_filled: true,
            fallback_lan_reconciled: false,
            low_rate: false,
            fresh: true,
            held_age_ms: None,
        };

        apply_ecm_bpf_rate_batch(&mut clients, &mut interfaces, &batch);

        assert_eq!(clients.clients[0].tx_bps, 100_000_000);
        assert_eq!(clients.clients[0].rx_bps, 50_000_000);
        assert_eq!(clients.clients[0].sample_ms, Some(5_000));
        let bridge = &interfaces.interfaces[0];
        assert_eq!(bridge.rx_bps, Some(100_000_000));
        assert_eq!(bridge.tx_bps, Some(50_000_000));
        assert!(bridge
            .source
            .as_deref()
            .is_some_and(|source| source.contains("ECM+BPF high-rate client floor")));
        let member = &interfaces.interfaces[1];
        assert_eq!(member.rx_bps, Some(30_000_000));
        assert_eq!(member.tx_bps, Some(40_000_000));
        assert_eq!(interfaces.monotonic_ms, Some(5_000));
    }

    #[test]
    fn ecm_bpf_computes_one_rate_from_aligned_raw_deltas() {
        let ecm = EcmBpfClientSample {
            mac: "02:00:00:00:00:01".into(),
            identity_key: "02:00:00:00:00:01@lan".into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.1".into()],
            tx_bytes: 10_000,
            rx_bytes: 20_000,
            tx_bps: 100,
            rx_bps: 200,
            sample_ms: 2_000,
            last_seen_ms: 1_900,
        };
        let tc = NssTcClientSample {
            mac: ecm.mac.clone(),
            identity_key: ecm.identity_key.clone(),
            zone: ecm.zone.clone(),
            interface: ecm.interface.clone(),
            ips: ecm.ips.clone(),
            tx_bytes: 3_000,
            rx_bytes: 4_000,
            tx_bps: 150,
            rx_bps: 50,
            last_seen_ms: 2_000,
        };
        let tc_only = NssTcClientSample {
            mac: "02:00:00:00:00:02".into(),
            identity_key: "02:00:00:00:00:02@lan".into(),
            tx_bps: 300,
            rx_bps: 400,
            ..tc.clone()
        };

        let mut ecm_snapshot = coverage_snapshot(
            1_000,
            2_000,
            &[(
                &ecm.identity_key,
                TrafficCounters {
                    tx_bytes: 10_000,
                    rx_bytes: 20_000,
                    tx_packets: 100,
                    rx_packets: 200,
                },
            )],
        );
        ecm_snapshot.clients.push(ecm);
        let mut tc_snapshot = tc_coverage_snapshot(
            1_000,
            2_000,
            &[
                (
                    &tc.identity_key,
                    TrafficCounters {
                        tx_bytes: 3_000,
                        rx_bytes: 4_000,
                        tx_packets: 30,
                        rx_packets: 40,
                    },
                ),
                (
                    &tc_only.identity_key,
                    TrafficCounters {
                        tx_bytes: 5_000,
                        rx_bytes: 6_000,
                        tx_packets: 50,
                        rx_packets: 60,
                    },
                ),
            ],
        );
        tc_snapshot.clients = vec![tc, tc_only];

        let response = ecm_bpf_clients_response(
            Some(&ecm_snapshot),
            Some(&tc_snapshot),
            true,
            2_000,
            None,
            &IdentityTable::new(4),
            ProbeConfidence::High,
        );

        let merged = &response.clients[0];
        assert_eq!((merged.tx_bps, merged.rx_bps), (108_160, 199_680));
        assert_eq!(
            (merged.tx_bytes, merged.rx_bytes),
            (Some(10_000), Some(20_000))
        );
        assert_eq!(merged.sample_ms, Some(2_000));
        assert!(merged.warnings.is_empty());

        let leading = &response.clients[1];
        assert_eq!((leading.tx_bps, leading.rx_bps), (41_600, 49_920));
        assert!(leading.warnings.is_empty());
    }

    fn coverage_snapshot(
        start_ms: u64,
        end_ms: u64,
        values: &[(&str, TrafficCounters)],
    ) -> EcmBpfSnapshot {
        let coverage_deltas = values
            .iter()
            .map(|(identity, counters)| ((*identity).to_owned(), *counters))
            .collect::<BTreeMap<_, _>>();
        let coverage_delta = coverage_deltas.values().copied().fold(
            TrafficCounters::default(),
            |mut total, value| {
                add_traffic_counters(&mut total, value);
                total
            },
        );
        EcmBpfSnapshot {
            coverage_delta,
            coverage_deltas,
            coverage_start_ms: Some(start_ms),
            coverage_end_ms: end_ms,
            sample_ms: end_ms,
            ..EcmBpfSnapshot::default()
        }
    }

    fn tc_coverage_snapshot(
        start_ms: u64,
        end_ms: u64,
        values: &[(&str, TrafficCounters)],
    ) -> NssTcSnapshot {
        NssTcSnapshot {
            coverage_deltas: values
                .iter()
                .map(|(identity, counters)| ((*identity).to_owned(), *counters))
                .collect(),
            coverage_start_ms: Some(start_ms),
            coverage_end_ms: end_ms,
            coverage_ready: true,
            ..NssTcSnapshot::default()
        }
    }

    #[test]
    fn ecm_bpf_misaligned_windows_choose_one_source_per_direction_without_sum() {
        let identity_key = "02:00:00:00:00:01@lan";
        let ecm_client = EcmBpfClientSample {
            mac: "02:00:00:00:00:01".into(),
            identity_key: identity_key.into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.1".into()],
            tx_bytes: 10_000,
            rx_bytes: 20_000,
            tx_bps: 100,
            rx_bps: 200,
            sample_ms: 3_000,
            last_seen_ms: 2_900,
        };
        let tc_client = NssTcClientSample {
            mac: ecm_client.mac.clone(),
            identity_key: identity_key.into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.1".into()],
            tx_bytes: 3_000,
            rx_bytes: 4_000,
            tx_bps: 150,
            rx_bps: 50,
            last_seen_ms: 5_900,
        };
        let mut ecm =
            coverage_snapshot(1_000, 3_000, &[(identity_key, TrafficCounters::default())]);
        ecm.clients.push(ecm_client);
        let mut tc =
            tc_coverage_snapshot(4_000, 6_000, &[(identity_key, TrafficCounters::default())]);
        tc.clients.push(tc_client);

        let response = ecm_bpf_clients_response(
            Some(&ecm),
            Some(&tc),
            true,
            6_000,
            None,
            &IdentityTable::new(4),
            ProbeConfidence::High,
        );

        let client = &response.clients[0];
        assert_eq!((client.tx_bps, client.rx_bps), (150, 200));
        assert_eq!(
            (client.tx_bytes, client.rx_bytes),
            (Some(10_000), Some(20_000))
        );
        assert_eq!(client.sample_ms, Some(6_000));
    }

    #[test]
    fn ecm_bpf_coverage_adds_source_disjoint_hardware_and_slow_path_deltas() {
        let ecm = coverage_snapshot(
            1_000,
            3_000,
            &[(
                "client@lan",
                TrafficCounters {
                    tx_bytes: 10_000,
                    rx_bytes: 20_000,
                    tx_packets: 100,
                    rx_packets: 200,
                },
            )],
        );
        let tc = tc_coverage_snapshot(
            1_010,
            3_010,
            &[(
                "client@lan",
                TrafficCounters {
                    tx_bytes: 9_000,
                    rx_bytes: 22_000,
                    tx_packets: 90,
                    rx_packets: 220,
                },
            )],
        );

        let merged = merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), true);

        assert_eq!(
            merged.merged,
            TrafficCounters {
                tx_bytes: 19_000,
                rx_bytes: 42_000,
                tx_packets: 190,
                rx_packets: 420,
            }
        );
        assert!(merged.tc_contributed);
    }

    #[test]
    fn ecm_bpf_coverage_includes_tc_only_low_traffic_clients() {
        let ecm = coverage_snapshot(
            1_000,
            3_000,
            &[(
                "routed@lan",
                TrafficCounters {
                    tx_bytes: 1_000,
                    tx_packets: 10,
                    ..TrafficCounters::default()
                },
            )],
        );
        let tc = tc_coverage_snapshot(
            1_000,
            3_000,
            &[
                (
                    "routed@lan",
                    TrafficCounters {
                        tx_bytes: 900,
                        tx_packets: 9,
                        ..TrafficCounters::default()
                    },
                ),
                (
                    "slow-path@lan",
                    TrafficCounters {
                        rx_bytes: 2_000,
                        rx_packets: 20,
                        ..TrafficCounters::default()
                    },
                ),
            ],
        );

        let merged = merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), true);

        assert_eq!(merged.merged.tx_bytes, 1_900);
        assert_eq!(merged.merged.tx_packets, 19);
        assert_eq!(merged.merged.rx_bytes, 2_000);
        assert_eq!(merged.merged.rx_packets, 20);
        assert!(merged.tc_contributed);
    }

    #[test]
    fn ecm_bpf_coverage_rejects_stale_or_misaligned_tc_windows() {
        let ecm = coverage_snapshot(
            2_000,
            4_000,
            &[(
                "client@lan",
                TrafficCounters {
                    tx_bytes: 1_000,
                    tx_packets: 10,
                    ..TrafficCounters::default()
                },
            )],
        );
        let tc = tc_coverage_snapshot(
            1_000,
            3_000,
            &[(
                "client@lan",
                TrafficCounters {
                    tx_bytes: 50_000,
                    tx_packets: 500,
                    ..TrafficCounters::default()
                },
            )],
        );

        for merged in [
            merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), false),
            merge_ecm_bpf_coverage_delta(&ecm, Some(&tc), true),
        ] {
            assert_eq!(merged.merged, ecm.coverage_delta);
            assert_eq!(merged.source, "ecm_nss_hardware_delta");
            assert!(!merged.tc_contributed);
        }
    }

    #[test]
    fn pending_coverage_response_uses_the_last_aligned_percentage_without_a_current_direction() {
        let response = coverage_response(&CoverageWindow {
            quality: WindowQuality::Pending,
            reason: "lan_coverage_pending",
            start_ms: 1_000,
            end_ms: 3_000,
            client_raw: TrafficCounters::default(),
            client_normalized: TrafficCounters::default(),
            lan_raw: TrafficCounters::default(),
            lan_normalized: TrafficCounters::default(),
            tx_pct: None,
            rx_pct: None,
            retained_tx_pct: Some(91),
            retained_rx_pct: Some(97),
            aligned: false,
        });

        assert_eq!(response.quality, "pending");
        assert_eq!(response.samples, 1);
        assert_eq!(response.tx_pct, Some(91));
        assert_eq!(response.rx_pct, Some(97));

        let timed_out = coverage_response(&CoverageWindow {
            quality: WindowQuality::CounterSkew,
            reason: "lan_coverage_timeout",
            start_ms: 3_000,
            end_ms: 9_000,
            client_raw: TrafficCounters::default(),
            client_normalized: TrafficCounters::default(),
            lan_raw: TrafficCounters::default(),
            lan_normalized: TrafficCounters::default(),
            tx_pct: None,
            rx_pct: None,
            retained_tx_pct: Some(91),
            retained_rx_pct: Some(97),
            aligned: false,
        });
        assert_eq!(timed_out.quality, "pending");
        assert_eq!(timed_out.tx_pct, Some(91));
        assert_eq!(timed_out.rx_pct, Some(97));

        let low_traffic_wait = coverage_response(&CoverageWindow {
            quality: WindowQuality::LowTraffic,
            reason: "low_traffic_coverage_rebaseline",
            start_ms: 9_000,
            end_ms: 15_000,
            client_raw: TrafficCounters::default(),
            client_normalized: TrafficCounters::default(),
            lan_raw: TrafficCounters::default(),
            lan_normalized: TrafficCounters::default(),
            tx_pct: None,
            rx_pct: None,
            retained_tx_pct: Some(91),
            retained_rx_pct: Some(97),
            aligned: false,
        });
        assert_eq!(low_traffic_wait.quality, "pending");
        assert_eq!(low_traffic_wait.tx_pct, Some(91));
        assert_eq!(low_traffic_wait.rx_pct, Some(97));
    }

    #[test]
    fn pending_coverage_response_prefers_the_current_reportable_direction() {
        let response = coverage_response(&CoverageWindow {
            quality: WindowQuality::Pending,
            reason: "lan_coverage_pending",
            start_ms: 1_000,
            end_ms: 3_000,
            client_raw: TrafficCounters::default(),
            client_normalized: TrafficCounters::default(),
            lan_raw: TrafficCounters::default(),
            lan_normalized: TrafficCounters::default(),
            tx_pct: Some(73),
            rx_pct: None,
            retained_tx_pct: Some(91),
            retained_rx_pct: Some(97),
            aligned: false,
        });

        assert_eq!(response.quality, "pending");
        assert_eq!(response.samples, 1);
        assert_eq!(response.tx_pct, Some(73));
        assert_eq!(response.rx_pct, None);
    }

    #[test]
    fn nss_bpf_handoff_rewarms_without_republishing_the_old_owner_interval() {
        use crate::platform::nss::ecm_node::{NodeCounters, NodeSnapshot, ParseStats};

        let snapshot = |sample_ms, tx_bytes, rx_bytes| NodeSnapshot {
            sample_ms,
            nodes: vec![NodeCounters {
                identity_key: "02:00:00:00:20:11@lan".into(),
                generation: 7,
                counters: TrafficCounters {
                    tx_bytes,
                    rx_bytes,
                    tx_packets: tx_bytes / 1_000,
                    rx_packets: rx_bytes / 1_000,
                },
            }],
            stats: ParseStats::default(),
        };
        let lan = |sample_ms, rx_bytes, tx_bytes| LanClock {
            interface: "br-lan".into(),
            sample_ms,
            counters: TrafficCounters {
                tx_bytes,
                rx_bytes,
                tx_packets: tx_bytes / 1_000,
                rx_packets: rx_bytes / 1_000,
            },
        };
        let mut owner = None;
        let mut nss = NssRuntime::default();

        nss.transition_rate_owner(&mut owner, RateCollector::NssEcmNode);
        assert_eq!(
            nss.node_windows
                .update(&snapshot(1_000, 10_000, 20_000), lan(1_000, 10_000, 20_000))
                .quality,
            WindowQuality::Warmup
        );
        nss.transition_rate_owner(&mut owner, RateCollector::Bpf);

        nss.transition_rate_owner(&mut owner, RateCollector::NssEcmNode);
        let reentry = nss.node_windows.update(
            &snapshot(5_000, 4_010_000, 8_020_000),
            lan(5_000, 4_010_000, 8_020_000),
        );

        assert_eq!(reentry.quality, WindowQuality::Warmup);
        assert!(reentry
            .clients
            .iter()
            .all(|client| client.tx_bps == 0 && client.rx_bps == 0));
        assert_eq!(reentry.coverage.tx_pct, None);
        assert_eq!(reentry.coverage.rx_pct, None);
    }
}
