use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    path::Path,
    rc::Rc,
    sync::Arc,
    time::Instant,
};

use lanspeed_openwrt_sys::{Timer, UbusConnection, UloopGuard};
use serde_json::{json, Value};

use crate::{
    collectors::{
        bpf::{
            runtime::{
                AttachMode, BpfCollectionCheckpoint, BpfRuntime, SystemAyaAdapter, SystemAyaLink,
                FALLBACK_OBJECT_PATH, PRIMARY_OBJECT_PATH,
            },
            snapshot::{
                BpfClientSample, BpfSnapshotCollector, ConnectionCounts, ConnectionOverlay,
            },
        },
        conntrack::{
            self, aggregate::ClientSample as CounterClient, CollectedSnapshot,
            CollectorMode as ConntrackMode,
        },
        nss::{self, ParseLimits},
    },
    config::{ConnectionCollectorMode, InterfaceEligibility, LegacyNameEligibility, RuntimeConfig},
    daemon::UloopSignalBridge,
    error::DaemonError,
    history::{
        coverage::{ByteTotals, CoverageRing, CoverageSample},
        overview::{
            ConnectionTotals, ConnectionTotalsOverride, OverviewClient, OverviewConfig,
            OverviewRing,
        },
    },
    identity::{
        arp,
        filter::IdentityFilter,
        hostname::{HostnameCache, HostnamePaths},
        netlink, IdentityObservation, IdentityTable, LegacyZoneResolver, ObservationSource,
    },
    interfaces::{InterfaceCounterReader, InterfaceRateBook, SysfsInterfaceCounterReader},
    model::{
        Capabilities, Client, ClientsResponse, Confidence, Conflict, Coverage, Evidence,
        HealthResponse, Interface, InterfaceRole, InterfaceStatus, InterfacesResponse, Mode,
        OverviewResponse, OverviewSample, ReloadResponse, StatusResponse, Sysdevice,
        SysdevicesResponse,
    },
    policy::{self, RateCollector},
    probe::{
        collector::{self, ProbeMethod, SystemProbeCollector},
        Confidence as ProbeConfidence, Mode as ProbeMode, ProbeCapabilities, ProbeReport,
        RuntimeHealth,
    },
    rate::{ClientCounters, RateBook},
    state::{ResponseSnapshot, SnapshotStore, CONNECTION_SEMANTICS, OVERVIEW_SAMPLE_SOURCE},
    ubus,
};

const RECONNECT_MS: u32 = 1_000;
const INTERFACE_NOTE: &str = "Per-interface totals from kernel net device counters; reflect hardware-offloaded and hardware-switched traffic too.";

type Bpf = BpfRuntime<SystemAyaLink>;

struct ProductionRuntime {
    config: RuntimeConfig,
    adapter: SystemAyaAdapter,
    bpf: Option<Bpf>,
    bpf_error: Option<String>,
    nss_error: Option<String>,
    bpf_collector: BpfSnapshotCollector,
    probe: SystemProbeCollector,
    probe_report: ProbeReport,
    next_probe_ms: u64,
    overview: OverviewRing,
    coverage: CoverageRing,
    interface_rates: InterfaceRateBook,
    nss_rates: RateBook,
    hostnames: HostnameCache,
    started: Instant,
    shutdown_complete: bool,
}

struct RuntimeCheckpoint {
    bpf: Option<BpfCollectionCheckpoint>,
    overview: OverviewRing,
    coverage: CoverageRing,
    interface_rates: InterfaceRateBook,
    nss_rates: RateBook,
    hostnames: HostnameCache,
    probe_report: ProbeReport,
    next_probe_ms: u64,
    bpf_error: Option<String>,
    nss_error: Option<String>,
}

impl ProductionRuntime {
    fn stage(config: RuntimeConfig) -> Result<Self, DaemonError> {
        let mut runtime = Self::prepare(config)?;
        runtime.activate_new_bpf()?;
        Ok(runtime)
    }

    fn prepare(config: RuntimeConfig) -> Result<Self, DaemonError> {
        let mut probe = collector::system_collector()
            .map_err(|error| DaemonError::platform(error.to_string()))?;
        let preflight = probe.collect(&config, &RuntimeHealth::default(), ProbeMethod::Health);
        Ok(Self {
            bpf_collector: BpfSnapshotCollector::new(
                config.max_clients,
                config.active_client_window_ms,
            ),
            probe,
            probe_report: preflight,
            next_probe_ms: 0,
            nss_rates: RateBook::new(config.max_clients, config.active_client_window_ms),
            hostnames: HostnameCache::new(),
            config,
            adapter: SystemAyaAdapter::new(),
            bpf: None,
            bpf_error: None,
            nss_error: None,
            overview: OverviewRing::new(),
            coverage: CoverageRing::new(),
            interface_rates: InterfaceRateBook::default(),
            started: Instant::now(),
            shutdown_complete: false,
        })
    }

    fn desired_attach_mode(&self) -> AttachMode {
        if self.probe_report.facts.tc.dae_preempts_lan_ingress {
            AttachMode::EarlyPassthrough
        } else {
            AttachMode::Normal
        }
    }

    fn activate_new_bpf(&mut self) -> Result<(), DaemonError> {
        if !self.config.enable_bpf || !self.probe_report.facts.tc.safe_attach {
            return Ok(());
        }
        let mut loaded =
            match BpfRuntime::load(&mut self.adapter, PRIMARY_OBJECT_PATH, FALLBACK_OBJECT_PATH) {
                Ok(runtime) => runtime,
                Err(error) => {
                    self.bpf_error = Some(error.to_string());
                    return Ok(());
                }
            };
        let interfaces = collect_ifnames(&self.config);
        let mode = self.desired_attach_mode();
        if let Err(error) = loaded.attach_interfaces(&mut self.adapter, &interfaces, mode) {
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
        Ok(())
    }

    fn checkpoint(&self) -> RuntimeCheckpoint {
        RuntimeCheckpoint {
            bpf: self
                .bpf
                .as_ref()
                .map(|runtime| runtime.collection_checkpoint(&self.bpf_collector)),
            overview: self.overview.clone(),
            coverage: self.coverage.clone(),
            interface_rates: self.interface_rates.clone(),
            nss_rates: self.nss_rates.clone(),
            hostnames: self.hostnames.clone(),
            probe_report: self.probe_report.clone(),
            next_probe_ms: self.next_probe_ms,
            bpf_error: self.bpf_error.clone(),
            nss_error: self.nss_error.clone(),
        }
    }

    fn restore(&mut self, checkpoint: RuntimeCheckpoint) {
        if let (Some(runtime), Some(checkpoint)) = (self.bpf.as_mut(), checkpoint.bpf) {
            runtime.restore_collection_checkpoint(&mut self.bpf_collector, checkpoint);
        }
        self.overview = checkpoint.overview;
        self.coverage = checkpoint.coverage;
        self.interface_rates = checkpoint.interface_rates;
        self.nss_rates = checkpoint.nss_rates;
        self.hostnames = checkpoint.hostnames;
        self.probe_report = checkpoint.probe_report;
        self.next_probe_ms = checkpoint.next_probe_ms;
        self.bpf_error = checkpoint.bpf_error;
        self.nss_error = checkpoint.nss_error;
    }

    fn collect(&mut self, method: ProbeMethod) -> Result<ResponseSnapshot, DaemonError> {
        let checkpoint = self.checkpoint();
        match self.collect_inner(method) {
            Ok(snapshot) => {
                for method in ubus::Method::ALL {
                    snapshot.response(method)?;
                }
                Ok(snapshot)
            }
            Err(error) => {
                self.restore(checkpoint);
                Err(error)
            }
        }
    }

    fn collect_inner(&mut self, method: ProbeMethod) -> Result<ResponseSnapshot, DaemonError> {
        let now_ms = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let (identities, identity_errors) = read_identities(&self.config, now_ms);
        let conntrack = conntrack::collect(
            conntrack_mode(self.config.conn_collector_mode),
            &identities,
            now_ms,
            self.config.max_clients,
        )
        .ok();
        let overlay = connection_overlay(conntrack.as_ref());
        let bpf_snapshot = match self.bpf.as_mut() {
            Some(runtime) => match runtime.collect_snapshot(
                &mut self.adapter,
                &mut self.bpf_collector,
                &identities,
                &overlay,
                now_ms,
            ) {
                Ok(snapshot) => {
                    self.bpf_error = None;
                    Some(snapshot)
                }
                Err(error) => {
                    self.bpf_error = Some(error.to_string());
                    self.bpf_collector.last_complete().cloned()
                }
            },
            None => None,
        };
        let mut runtime_health = self.runtime_health(now_ms, conntrack.as_ref());
        runtime_health.nss_sync_read_ok = Some(conntrack.is_some());
        if should_refresh_probe(self.next_probe_ms, method) {
            self.probe_report = self.probe.collect(&self.config, &runtime_health, method);
            self.next_probe_ms = u64::MAX;
        }
        let report = self.probe_report.clone();
        let mut decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        let direct = if decision.rate == RateCollector::NssEcmDirect || decision.nss_direct_overlay
        {
            match nss::read_direct_snapshot(
                &identities,
                now_ms,
                self.config.max_clients,
                ParseLimits::default(),
            ) {
                Ok(snapshot) => {
                    self.nss_error = None;
                    runtime_health.nss_direct_read_ok = Some(true);
                    Some(snapshot)
                }
                Err(error) => {
                    self.nss_error = Some(error.to_string());
                    runtime_health.nss_direct_read_ok = Some(false);
                    None
                }
            }
        } else {
            None
        };
        decision = policy::select_collectors(&self.config, &report.facts, &runtime_health);
        let effective = decision.rate.as_str();
        let (mut clients, actual_live, actual_degraded) = if decision.rate == RateCollector::Bpf {
            (
                clients_response(
                    bpf_snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.clients.as_slice()),
                    None,
                    &identities,
                    decision.confidence,
                ),
                bpf_snapshot.is_some(),
                bpf_snapshot.is_none(),
            )
        } else if decision.rate == RateCollector::NssEcmDirect {
            match direct.as_ref() {
                Some(snapshot) => (
                    rate_clients(
                        &mut self.nss_rates,
                        &snapshot.clients,
                        now_ms,
                        &identities,
                        decision.confidence,
                        "nss_ecm_direct",
                    ),
                    true,
                    false,
                ),
                None => (
                    ClientsResponse::empty(evidence(&report, "clients")),
                    false,
                    true,
                ),
            }
        } else if decision.rate == RateCollector::NssConntrackSync {
            match conntrack.as_ref() {
                Some(snapshot) => {
                    let (samples, source) = if let Some(direct) = direct.as_ref() {
                        (
                            overlay_counter_clients(&snapshot.clients, &direct.clients),
                            "nss_ecm_direct+conntrack_ecm_sync",
                        )
                    } else {
                        (snapshot.clients.clone(), "conntrack_ecm_sync")
                    };
                    (
                        rate_clients(
                            &mut self.nss_rates,
                            &samples,
                            now_ms,
                            &identities,
                            decision.confidence,
                            source,
                        ),
                        true,
                        true,
                    )
                }
                None => (
                    ClientsResponse::empty(evidence(&report, "clients")),
                    false,
                    true,
                ),
            }
        } else {
            (
                ClientsResponse::empty(evidence(&report, "clients")),
                false,
                true,
            )
        };
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
        if let Some(snapshot) = direct.as_ref() {
            clients.nss_ecm_direct_flows_seen = Some(snapshot.stats.entries_seen as u64);
            clients.nss_ecm_direct_flows_matched = Some(snapshot.stats.entries_matched as u64);
            clients.nss_ecm_direct_parse_errors = Some(snapshot.stats.malformed_lines as u64);
        }
        if clients.evidence.is_none() {
            clients.evidence = Some(evidence(&report, "clients"));
        }
        if let Some(client_evidence) = clients.evidence.as_mut() {
            apply_decision_evidence(client_evidence, &decision);
        }
        let overview = self.update_overview(now_ms, &clients);
        let interfaces = self.interfaces(now_ms);
        let coverage = self.update_coverage(now_ms, &clients, &interfaces, actual_live);
        let sysdevices = sysdevices(&self.config)?;
        let mut capabilities = capabilities(&report.capabilities, &report);
        capabilities.live_metrics = actual_live;
        capabilities.bpf_runtime_metrics = effective == "bpf" && actual_live;
        capabilities.bpf = capabilities.bpf_runtime_metrics;
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
        apply_decision_evidence(&mut status_evidence, &decision);
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
        if let Some(snapshot) = direct.as_ref() {
            for warning in &snapshot.warnings {
                if !warnings.iter().any(|value| value == warning) {
                    warnings.push((*warning).into());
                }
            }
        }
        if let Some(error) = &self.bpf_error {
            status_evidence
                .details
                .insert("runtime_error".into(), json!(error));
        }
        if let Some(error) = &self.nss_error {
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
        apply_decision_evidence(&mut health_evidence, &decision);
        if let Some(error) = &self.bpf_error {
            health_evidence
                .details
                .insert("runtime_error".into(), json!(error));
        }
        if let Some(error) = &self.nss_error {
            health_evidence
                .details
                .insert("nss_runtime_error".into(), json!(error));
        }
        if !identity_errors.is_empty() {
            health_evidence
                .details
                .insert("identity_errors".into(), json!(identity_errors));
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
        apply_decision_evidence(&mut reload_evidence, &decision);
        let reload = ReloadResponse {
            ok: true,
            mode,
            warnings,
            evidence: reload_evidence,
            version,
        };
        Ok(ResponseSnapshot {
            status,
            clients,
            overview,
            health,
            reload,
            interfaces,
            sysdevices,
        })
    }

    fn runtime_health(&self, now_ms: u64, conntrack: Option<&CollectedSnapshot>) -> RuntimeHealth {
        let mut health = self
            .bpf
            .as_ref()
            .map(|runtime| {
                runtime.runtime_health(now_ms, u64::from(self.config.refresh_interval_ms) * 3)
            })
            .unwrap_or_default();
        health.now_ms = now_ms;
        health.conntrack_netlink_available =
            conntrack.is_some_and(|snapshot| snapshot.stats.netlink_read);
        health.conntrack_procfs_available =
            conntrack.is_some_and(|snapshot| snapshot.stats.procfs_read);
        if health.runtime_error.is_none() {
            health.runtime_error = self.bpf_error.clone();
        }
        health
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

    fn interfaces(&mut self, now_ms: u64) -> InterfacesResponse {
        let mut reader = SysfsInterfaceCounterReader;
        let interfaces = collect_ifnames_with_roles(&self.config)
            .into_iter()
            .map(|(name, role)| match reader.read(&name) {
                Ok(counters) => {
                    let (rx_bps, tx_bps, delta_ms) =
                        self.interface_rates.update(&name, counters, now_ms);
                    Interface {
                        name,
                        role,
                        status: InterfaceStatus::Available,
                        rx_bytes: Some(counters.rx_bytes),
                        tx_bytes: Some(counters.tx_bytes),
                        rx_bps: Some(rx_bps),
                        tx_bps: Some(tx_bps),
                        delta_ms: Some(delta_ms),
                        sample_ms: Some(now_ms),
                        source: Some("/sys/class/net/<if>/statistics".into()),
                        coverage: Some("includes_hardware_offload_and_switch_bridge".into()),
                        evidence: None,
                    }
                }
                Err(_) => Interface {
                    name,
                    role,
                    status: InterfaceStatus::Missing,
                    rx_bytes: Some(0),
                    tx_bytes: Some(0),
                    rx_bps: Some(0),
                    tx_bps: Some(0),
                    delta_ms: Some(0),
                    sample_ms: Some(now_ms),
                    source: Some("/sys/class/net/<if>/statistics".into()),
                    coverage: Some("includes_hardware_offload_and_switch_bridge".into()),
                    evidence: None,
                },
            })
            .collect();
        InterfacesResponse {
            interfaces,
            monotonic_ms: Some(now_ms),
            note: Some(INTERFACE_NOTE.into()),
            evidence: None,
        }
    }

    fn update_coverage(
        &mut self,
        now_ms: u64,
        clients: &ClientsResponse,
        interfaces: &InterfacesResponse,
        supported: bool,
    ) -> Coverage {
        if supported {
            let interface =
                interfaces
                    .interfaces
                    .iter()
                    .fold(ByteTotals::new(0, 0), |total, value| {
                        ByteTotals::new(
                            total.rx_bytes.saturating_add(value.rx_bytes.unwrap_or(0)),
                            total.tx_bytes.saturating_add(value.tx_bytes.unwrap_or(0)),
                        )
                    });
            let client = clients
                .clients
                .iter()
                .fold(ByteTotals::new(0, 0), |total, value| {
                    ByteTotals::new(
                        total.rx_bytes.saturating_add(value.rx_bytes.unwrap_or(0)),
                        total.tx_bytes.saturating_add(value.tx_bytes.unwrap_or(0)),
                    )
                });
            self.coverage
                .push(CoverageSample::valid(now_ms, interface, client));
        } else {
            self.coverage.push(CoverageSample::invalid(now_ms));
        }
        let report = self.coverage.report(supported);
        Coverage {
            quality: report.quality.as_str().into(),
            samples: report.samples as u64,
            window_ms: (report.quality.as_str() != "unsupported").then_some(report.window_ms),
            tx_pct: report.tx_pct,
            rx_pct: report.rx_pct,
            denom_rx_bytes: (report.quality.as_str() != "unsupported")
                .then_some(report.denom_rx_bytes),
            denom_tx_bytes: (report.quality.as_str() != "unsupported")
                .then_some(report.denom_tx_bytes),
            numer_rx_bytes: (report.quality.as_str() != "unsupported")
                .then_some(report.numer_rx_bytes),
            numer_tx_bytes: (report.quality.as_str() != "unsupported")
                .then_some(report.numer_tx_bytes),
        }
    }

    fn shutdown(&mut self) -> Result<(), DaemonError> {
        if self.shutdown_complete {
            return Ok(());
        }
        if let Some(runtime) = self.bpf.as_mut() {
            runtime
                .shutdown(&mut self.adapter)
                .map_err(|error| DaemonError::collection(error.to_string()))?;
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

struct App {
    config: RuntimeConfig,
    runtime: ProductionRuntime,
    snapshots: SnapshotStore,
    ubus: Option<UbusConnection>,
    collection_timer: Option<Timer>,
    reconnect_timer: Option<Timer>,
    reconnect_pending: Cell<bool>,
    last_error: Option<String>,
    fatal_error: RefCell<Option<String>>,
}

impl App {
    fn collection_tick(&mut self) {
        match self.runtime.collect(ProbeMethod::Status) {
            Ok(mut snapshot) => {
                if let Some(error) = self.last_error.take() {
                    add_runtime_error(&mut snapshot, &error);
                }
                self.snapshots.publish(Arc::new(snapshot));
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                self.publish_degraded(error.to_string());
            }
        }
        if let Err(error) = self
            .collection_timer
            .as_ref()
            .unwrap()
            .schedule(self.config.refresh_interval_ms)
        {
            self.last_error = Some(error.to_string());
            self.publish_degraded(error.to_string());
            *self.fatal_error.borrow_mut() = Some(error.to_string());
            UloopGuard::request_stop();
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
            *self.fatal_error.borrow_mut() = Some("failed to schedule ubus reconnect".into());
            UloopGuard::request_stop();
        }
    }
    fn reconnect(&mut self) {
        self.reconnect_pending.set(false);
        let result = self
            .ubus
            .as_mut()
            .unwrap()
            .reconnect(None)
            .and_then(|_| self.ubus.as_mut().unwrap().reregister_objects());
        if let Err(error) = result {
            self.last_error = Some(error.to_string());
            self.publish_degraded(error.to_string());
            self.schedule_reconnect();
        }
    }
    fn reload(&mut self) -> Result<(), DaemonError> {
        let result = self.reload_inner();
        if let Err(error) = &result {
            self.last_error = Some(error.to_string());
            self.publish_degraded(error.to_string());
        }
        result
    }

    fn reload_inner(&mut self) -> Result<(), DaemonError> {
        let config = load_config()?;
        let mut candidate = ProductionRuntime::prepare(config.clone())?;
        let mut handed_off = false;
        if config.enable_bpf && candidate.probe_report.facts.tc.safe_attach {
            if let Some(runtime) = self.runtime.bpf.as_mut() {
                if let Err(error) = runtime.switch_mode(
                    &mut self.runtime.adapter,
                    &collect_ifnames(&config),
                    candidate.desired_attach_mode(),
                ) {
                    let recovery =
                        runtime.ensure_attached(&mut self.runtime.adapter, "reload_rollback");
                    if let Err(recovery) = recovery {
                        return Err(record_fatal_cleanup(
                            "BPF switch rollback",
                            &error.to_string(),
                            &recovery.to_string(),
                            &self.fatal_error,
                        ));
                    }
                    return Err(DaemonError::reload(error.to_string()));
                }
                candidate.adapter = std::mem::take(&mut self.runtime.adapter);
                candidate.bpf = self.runtime.bpf.take();
                candidate.bpf_error = self.runtime.bpf_error.take();
                handed_off = true;
            } else {
                if let Err(error) = candidate.activate_new_bpf() {
                    *self.fatal_error.borrow_mut() = Some(error.to_string());
                    UloopGuard::request_stop();
                    return Err(error);
                }
            }
        }
        let snapshot = match candidate.collect(ProbeMethod::Reload) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                if let Err(rollback) = self.rollback_bpf_handoff(&mut candidate, handed_off) {
                    let combined = format!("{error}; BPF rollback failed: {rollback}");
                    *self.fatal_error.borrow_mut() = Some(combined.clone());
                    UloopGuard::request_stop();
                    return Err(DaemonError::reload(combined));
                }
                if let Err(cleanup) = candidate.shutdown() {
                    return Err(record_fatal_cleanup(
                        "candidate cleanup",
                        &error.to_string(),
                        &cleanup.to_string(),
                        &self.fatal_error,
                    ));
                }
                self.last_error = Some(error.to_string());
                return Err(error);
            }
        };
        if let Err(error) = self
            .collection_timer
            .as_ref()
            .unwrap()
            .schedule(config.refresh_interval_ms)
        {
            if let Err(rollback) = self.rollback_bpf_handoff(&mut candidate, handed_off) {
                let combined = format!("{error}; BPF rollback failed: {rollback}");
                *self.fatal_error.borrow_mut() = Some(combined.clone());
                UloopGuard::request_stop();
                return Err(DaemonError::reload(combined));
            }
            if let Err(cleanup) = candidate.shutdown() {
                return Err(record_fatal_cleanup(
                    "candidate cleanup",
                    &error.to_string(),
                    &cleanup.to_string(),
                    &self.fatal_error,
                ));
            }
            self.last_error = Some(error.to_string());
            return Err(DaemonError::reload(error.to_string()));
        }
        let mut old = std::mem::replace(&mut self.runtime, candidate);
        self.config = config;
        self.snapshots.publish(Arc::new(snapshot));
        if let Err(error) = old.shutdown() {
            let fatal = record_fatal_cleanup(
                "postcommit old runtime cleanup",
                "reload committed",
                &error.to_string(),
                &self.fatal_error,
            );
            self.last_error = Some(fatal.to_string());
            return Err(fatal);
        }
        Ok(())
    }

    fn rollback_bpf_handoff(
        &mut self,
        candidate: &mut ProductionRuntime,
        handed_off: bool,
    ) -> Result<(), DaemonError> {
        if !handed_off {
            return Ok(());
        }
        self.runtime.adapter = std::mem::take(&mut candidate.adapter);
        self.runtime.bpf = candidate.bpf.take();
        self.runtime.bpf_error = candidate.bpf_error.take();
        let old_mode = self.runtime.desired_attach_mode();
        let old_ifnames = collect_ifnames(&self.runtime.config);
        if let Some(runtime) = self.runtime.bpf.as_mut() {
            if let Err(error) =
                runtime.switch_mode(&mut self.runtime.adapter, &old_ifnames, old_mode)
            {
                return Err(DaemonError::reload(error.to_string()));
            }
        }
        Ok(())
    }

    fn publish_degraded(&self, error: String) {
        let mut snapshot = (*self.snapshots.load()).clone();
        add_runtime_error(&mut snapshot, &error);
        self.snapshots.publish(Arc::new(snapshot));
    }
}

pub fn run() -> Result<(), DaemonError> {
    let config = load_config()?;
    let mut runtime = ProductionRuntime::stage(config.clone())?;
    let initial = Arc::new(runtime.collect(ProbeMethod::Status)?);
    let snapshots = SnapshotStore::new(initial);
    let mut event_loop =
        UloopGuard::init().map_err(|error| DaemonError::platform(error.to_string()))?;
    let app = Rc::new(RefCell::new(App {
        config,
        runtime,
        snapshots: snapshots.clone(),
        ubus: None,
        collection_timer: None,
        reconnect_timer: None,
        reconnect_pending: Cell::new(false),
        last_error: None,
        fatal_error: RefCell::new(None),
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
    let object = ubus::object(snapshots, move || {
        weak.upgrade()
            .ok_or_else(|| DaemonError::reload("daemon stopped"))?
            .borrow_mut()
            .reload()
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
    app.borrow()
        .collection_timer
        .as_ref()
        .unwrap()
        .schedule(app.borrow().config.refresh_interval_ms)
        .map_err(|error| DaemonError::transport(error.to_string()))?;
    let _signals = UloopSignalBridge::install()?;
    let run_result = event_loop
        .run()
        .map_err(|error| DaemonError::platform(error.to_string()));
    let shutdown_result = app.borrow_mut().runtime.shutdown();
    let fatal = app.borrow().fatal_error.borrow_mut().take();
    if let Some(error) = fatal {
        return Err(DaemonError::platform(error));
    }
    run_result.and(shutdown_result)
}

fn load_config() -> Result<RuntimeConfig, DaemonError> {
    let mut source = lanspeed_openwrt_sys::UciContext::new()
        .map_err(|error| DaemonError::reload(error.to_string()))?;
    RuntimeConfig::load(&mut source, &LegacyNameEligibility)
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

fn clients_response(
    bpf: Option<&[BpfClientSample]>,
    conntrack: Option<&CollectedSnapshot>,
    identities: &IdentityTable,
    client_confidence: ProbeConfidence,
) -> ClientsResponse {
    let mut clients = if let Some(bpf) = bpf {
        bpf.iter()
            .map(|sample| Client {
                mac: sample.mac.clone(),
                identity_key: sample.identity_key.clone(),
                zone: sample.zone.clone(),
                interface: sample.interface.clone(),
                ips: sample.ips.clone(),
                hostname: identities
                    .by_mac_zone(&sample.mac, &sample.zone)
                    .and_then(|identity| identity.hostname.clone()),
                rx_bps: sample.rx_bps,
                tx_bps: sample.tx_bps,
                last_seen: sample.last_seen_ms,
                sample_ms: Some(sample.sample_ms),
                rx_bytes: Some(sample.rx_bytes),
                tx_bytes: Some(sample.tx_bytes),
                collector_mode: "bpf".into(),
                confidence: confidence(client_confidence),
                warnings: vec![],
                tcp_conns: sample.tcp_conns.map(u64::from),
                udp_conns: sample.udp_conns.map(u64::from),
                udp_dns_conns: sample.udp_dns_conns.map(u64::from),
                udp_other_conns: sample.udp_other_conns.map(u64::from),
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if clients.is_empty() {
        if let Some(snapshot) = conntrack {
            clients = snapshot
                .clients
                .iter()
                .map(|sample| Client {
                    mac: sample.mac.clone(),
                    identity_key: sample.identity_key.clone(),
                    zone: sample.zone.clone(),
                    interface: sample.interface.clone(),
                    ips: sample.ips.clone(),
                    hostname: identities
                        .by_mac_zone(&sample.mac, &sample.zone)
                        .and_then(|identity| identity.hostname.clone()),
                    rx_bps: 0,
                    tx_bps: 0,
                    last_seen: sample.last_seen_ms,
                    sample_ms: Some(sample.last_seen_ms),
                    rx_bytes: Some(sample.rx_bytes),
                    tx_bytes: Some(sample.tx_bytes),
                    collector_mode: snapshot.counter_source.into(),
                    confidence: confidence(client_confidence),
                    warnings: vec!["conntrack_routed_nat_only".into()],
                    tcp_conns: Some(u64::from(sample.tcp_conns)),
                    udp_conns: Some(u64::from(sample.udp_conns)),
                    udp_dns_conns: Some(u64::from(sample.udp_dns_conns)),
                    udp_other_conns: Some(u64::from(sample.udp_other_conns)),
                })
                .collect();
        }
    }
    clients.sort_by(|left, right| left.identity_key.cmp(&right.identity_key));
    let totals = clients
        .iter()
        .fold((0u64, 0u64, 0u64, 0u64), |totals, client| {
            (
                totals.0.saturating_add(client.tcp_conns.unwrap_or(0)),
                totals.1.saturating_add(client.udp_conns.unwrap_or(0)),
                totals.2.saturating_add(client.udp_dns_conns.unwrap_or(0)),
                totals.3.saturating_add(client.udp_other_conns.unwrap_or(0)),
            )
        });
    ClientsResponse {
        clients,
        evidence: None,
        tcp_conns_total: Some(totals.0),
        udp_conns_total: Some(totals.1),
        udp_dns_conns_total: Some(totals.2),
        udp_other_conns_total: Some(totals.3),
        conntrack_entries_seen: conntrack.map(|value| value.stats.entries_seen as u64),
        conntrack_entries_matched: conntrack.map(|value| value.stats.entries_matched as u64),
        conntrack_parse_errors: conntrack.map(|value| value.stats.malformed_lines as u64),
        conn_source: conntrack.map(|value| {
            if value.stats.netlink_read {
                "conntrack_netlink"
            } else {
                "conntrack_procfs"
            }
            .into()
        }),
        nss_ecm_direct_flows_seen: None,
        nss_ecm_direct_flows_matched: None,
        nss_ecm_direct_parse_errors: None,
        conn_collector_mode: None,
        conn_semantics: Some(CONNECTION_SEMANTICS.into()),
    }
}

fn rate_clients(
    rates: &mut RateBook,
    samples: &[CounterClient],
    now_ms: u64,
    identities: &IdentityTable,
    client_confidence: ProbeConfidence,
    collector_mode: &str,
) -> ClientsResponse {
    let update = rates.update(
        now_ms,
        samples.iter().map(|sample| ClientCounters {
            identity_key: sample.identity_key.clone(),
            tx_bytes: sample.tx_bytes,
            rx_bytes: sample.rx_bytes,
            last_seen_ms: sample.last_seen_ms,
        }),
    );
    let by_key = samples
        .iter()
        .map(|sample| (sample.identity_key.as_str(), sample))
        .collect::<BTreeMap<_, _>>();
    let clients = update
        .clients
        .into_iter()
        .filter_map(|rate| {
            let sample = by_key.get(rate.identity_key.as_str())?;
            Some(Client {
                mac: sample.mac.clone(),
                identity_key: sample.identity_key.clone(),
                zone: sample.zone.clone(),
                interface: sample.interface.clone(),
                ips: sample.ips.clone(),
                hostname: identities
                    .by_mac_zone(&sample.mac, &sample.zone)
                    .and_then(|identity| identity.hostname.clone()),
                rx_bps: rate.rx_bps,
                tx_bps: rate.tx_bps,
                last_seen: rate.last_seen_ms,
                sample_ms: Some(rate.sample_ms),
                rx_bytes: Some(rate.rx_bytes),
                tx_bytes: Some(rate.tx_bytes),
                collector_mode: collector_mode.into(),
                confidence: confidence(client_confidence),
                warnings: rate
                    .warnings
                    .iter()
                    .map(|warning| warning.as_str().to_owned())
                    .collect(),
                tcp_conns: Some(u64::from(sample.tcp_conns)),
                udp_conns: Some(u64::from(sample.udp_conns)),
                udp_dns_conns: Some(u64::from(sample.udp_dns_conns)),
                udp_other_conns: Some(u64::from(sample.udp_other_conns)),
            })
        })
        .collect::<Vec<_>>();
    let totals = clients
        .iter()
        .fold((0u64, 0u64, 0u64, 0u64), |totals, client| {
            (
                totals.0.saturating_add(client.tcp_conns.unwrap_or(0)),
                totals.1.saturating_add(client.udp_conns.unwrap_or(0)),
                totals.2.saturating_add(client.udp_dns_conns.unwrap_or(0)),
                totals.3.saturating_add(client.udp_other_conns.unwrap_or(0)),
            )
        });
    ClientsResponse {
        clients,
        evidence: None,
        tcp_conns_total: Some(totals.0),
        udp_conns_total: Some(totals.1),
        udp_dns_conns_total: Some(totals.2),
        udp_other_conns_total: Some(totals.3),
        conntrack_entries_seen: None,
        conntrack_entries_matched: None,
        conntrack_parse_errors: None,
        conn_source: Some(collector_mode.into()),
        nss_ecm_direct_flows_seen: None,
        nss_ecm_direct_flows_matched: None,
        nss_ecm_direct_parse_errors: None,
        conn_collector_mode: None,
        conn_semantics: Some(CONNECTION_SEMANTICS.into()),
    }
}

fn overlay_counter_clients(base: &[CounterClient], direct: &[CounterClient]) -> Vec<CounterClient> {
    let mut merged = base
        .iter()
        .cloned()
        .map(|client| (client.identity_key.clone(), client))
        .collect::<BTreeMap<_, _>>();
    for client in direct {
        merged.insert(client.identity_key.clone(), client.clone());
    }
    merged.into_values().collect()
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
    details.insert("collector".into(), json!({"rate_reason":report.evidence.collector.rate_reason,"connection_reason":report.evidence.collector.connection_reason,
        "primary_source":report.evidence.collector.effective_rate_collector,"mode":report.evidence.collector.mode,"confidence":report.evidence.collector.confidence}));
    details.insert("nss".into(), json!({"present":report.evidence.nss.present,"ecm_active":report.evidence.nss.ecm_active,"ppe_active":report.evidence.nss.ppe_active,
        "direct_state_readable":report.evidence.nss.direct_state_readable}));
    Evidence { details }
}

fn apply_decision_evidence(evidence: &mut Evidence, decision: &policy::PolicyDecision) {
    let effective = decision.rate.as_str();
    evidence
        .details
        .insert("effective_collector".into(), json!(effective));
    if let Some(collector) = evidence
        .details
        .get_mut("collector")
        .and_then(Value::as_object_mut)
    {
        collector.insert("primary_source".into(), json!(effective));
        collector.insert("rate_reason".into(), json!(decision.evidence.rate_reason));
        collector.insert(
            "connection_reason".into(),
            json!(decision.evidence.connection_reason),
        );
        collector.insert("mode".into(), json!(decision.mode.as_str()));
        collector.insert("confidence".into(), json!(decision.confidence.as_str()));
        collector.insert("warnings".into(), json!(decision.warnings));
    }
}

fn capabilities(value: &ProbeCapabilities, report: &ProbeReport) -> Capabilities {
    Capabilities {
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
        nss_ecm_direct: report.facts.nss.direct_state_readable,
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
fn confidence(value: ProbeConfidence) -> Confidence {
    match value {
        ProbeConfidence::High => Confidence::High,
        ProbeConfidence::Medium => Confidence::Medium,
        ProbeConfidence::Low => Confidence::Low,
        ProbeConfidence::Unsupported => Confidence::Unsupported,
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
    config
        .ifnames
        .iter()
        .chain(config.interface_include.iter())
        .cloned()
        .collect()
}
fn collect_ifnames_with_roles(config: &RuntimeConfig) -> Vec<(String, InterfaceRole)> {
    collect_ifnames(config)
        .into_iter()
        .map(|name| (name, InterfaceRole::Lan))
        .chain(
            config
                .observe_ifnames
                .iter()
                .cloned()
                .map(|name| (name, InterfaceRole::Observe)),
        )
        .collect()
}

fn sysdevices(config: &RuntimeConfig) -> Result<SysdevicesResponse, DaemonError> {
    let selected = collect_ifnames(config);
    let observed = config.observe_ifnames.clone();
    let mut devices = Vec::new();
    for entry in fs::read_dir("/sys/class/net")
        .map_err(|error| DaemonError::collection(error.to_string()))?
    {
        let name = entry
            .map_err(|error| DaemonError::collection(error.to_string()))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name == "lo" || name.starts_with("teql") {
            continue;
        }
        let root = Path::new("/sys/class/net").join(&name);
        let speed = fs::read_to_string(root.join("speed"))
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v > 0 && *v < (1 << 31));
        let recommended = LegacyNameEligibility.is_collect_eligible(&name);
        devices.push(Sysdevice {
            name: name.clone(),
            selected: selected.contains(&name),
            observed: observed.contains(&name),
            recommended_lan: recommended,
            is_bridge: root.join("bridge").is_dir(),
            is_bridge_port: root.join("brport").is_dir(),
            is_nss_ifb: name == "nssifb",
            speed_mbps: speed,
        });
    }
    Ok(SysdevicesResponse {
        devices,
        current_ifnames: selected,
        current_observed: observed,
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

fn should_refresh_probe(next_probe_ms: u64, method: ProbeMethod) -> bool {
    next_probe_ms == 0 || method == ProbeMethod::Reload
}

fn add_runtime_error(snapshot: &mut ResponseSnapshot, error: &str) {
    for warning in [&mut snapshot.status.warnings, &mut snapshot.health.warnings] {
        if !warning.iter().any(|value| value == "runtime_error") {
            warning.push("runtime_error".into());
        }
    }
    if snapshot.status.mode != Mode::Unsupported {
        snapshot.status.mode = Mode::Degraded;
        snapshot.status.confidence = Confidence::Low;
    }
    snapshot.status.capabilities.live_metrics = false;
    if snapshot.health.mode != Mode::Unsupported {
        snapshot.health.mode = Mode::Degraded;
        snapshot.health.confidence = Confidence::Low;
    }
    snapshot.health.capabilities.live_metrics = false;
    snapshot
        .status
        .evidence
        .details
        .insert("runtime_error".into(), json!(error));
    snapshot
        .health
        .evidence
        .details
        .insert("runtime_error".into(), json!(error));
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
        assert_eq!(version_from(Some("0.1.7"), Some("2")), "0.1.7-r2");
        assert_eq!(version_from(Some("0.1.7"), None), "unconfigured");
        assert_eq!(version_from(None, Some("2")), "unconfigured");
    }

    #[test]
    fn periodic_collection_does_not_run_blocking_system_probe() {
        assert!(should_refresh_probe(0, ProbeMethod::Status));
        assert!(!should_refresh_probe(u64::MAX, ProbeMethod::Status));
        assert!(should_refresh_probe(u64::MAX, ProbeMethod::Reload));
    }
}
