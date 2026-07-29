use crate::{
    config::RuntimeConfig,
    identity::IdentityTable,
    platform::nss::{
        ecm_bpf::{
            EcmBpfCollectionCheckpoint, EcmBpfRuntime, EcmBpfSnapshot, EcmBpfSnapshotCollector,
        },
        ecm_node::{self, NodeSnapshot},
        window::{EcmBpfRateWindowBook, NssCoverageBook, NssWindowBook},
    },
    policy::RateCollector,
    probe::{ProbeReport, RuntimeHealth},
};

#[cfg(target_arch = "aarch64")]
use crate::{config::RateCollectorMode, platform::nss::ecm_bpf::ECM_BPF_OBJECT_PATH};

pub(crate) struct NssRuntime {
    pub(crate) ecm_bpf: Option<EcmBpfRuntime>,
    pub(crate) ecm_bpf_error: Option<String>,
    pub(crate) ecm_bpf_error_stage: Option<&'static str>,
    pub(crate) node_error: Option<String>,
    pub(crate) ecm_bpf_collector: EcmBpfSnapshotCollector,
    pub(crate) node_windows: NssWindowBook,
    pub(crate) ecm_bpf_coverage: NssCoverageBook,
    pub(crate) ecm_bpf_rates: EcmBpfRateWindowBook,
}

#[derive(Clone)]
pub(crate) struct NssRuntimeCheckpoint {
    ecm_bpf: Option<EcmBpfCollectionCheckpoint>,
    node_windows: NssWindowBook,
    ecm_bpf_coverage: NssCoverageBook,
    ecm_bpf_rates: EcmBpfRateWindowBook,
    ecm_bpf_error: Option<String>,
    ecm_bpf_error_stage: Option<&'static str>,
    node_error: Option<String>,
}

impl Default for NssRuntime {
    fn default() -> Self {
        Self {
            ecm_bpf: None,
            ecm_bpf_error: None,
            ecm_bpf_error_stage: None,
            node_error: None,
            ecm_bpf_collector: EcmBpfSnapshotCollector::default(),
            node_windows: NssWindowBook::default(),
            ecm_bpf_coverage: NssCoverageBook::default(),
            ecm_bpf_rates: EcmBpfRateWindowBook::default(),
        }
    }
}

impl NssRuntime {
    pub(crate) fn activate(&mut self, config: &RuntimeConfig, report: &ProbeReport) {
        #[cfg(target_arch = "aarch64")]
        {
            if !config.enable_bpf
                || !matches!(
                    config.rate_collector_mode,
                    RateCollectorMode::Auto | RateCollectorMode::NssEcmBpf
                )
                || !report.facts.nss.present
                || !report.facts.nss.ecm_active
            {
                return;
            }
            match EcmBpfRuntime::load_and_attach(ECM_BPF_OBJECT_PATH) {
                Ok(runtime) => {
                    self.ecm_bpf = Some(runtime);
                    self.ecm_bpf_error = None;
                    self.ecm_bpf_error_stage = None;
                }
                Err(error) => {
                    self.ecm_bpf_error_stage = Some(error.stage());
                    self.ecm_bpf_error = Some(error.to_string());
                }
            }
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = (config, report);
        }
    }

    pub(crate) fn checkpoint(&self) -> NssRuntimeCheckpoint {
        NssRuntimeCheckpoint {
            ecm_bpf: self
                .ecm_bpf
                .as_ref()
                .map(|runtime| runtime.collection_checkpoint(&self.ecm_bpf_collector)),
            node_windows: self.node_windows.clone(),
            ecm_bpf_coverage: self.ecm_bpf_coverage.clone(),
            ecm_bpf_rates: self.ecm_bpf_rates.clone(),
            ecm_bpf_error: self.ecm_bpf_error.clone(),
            ecm_bpf_error_stage: self.ecm_bpf_error_stage,
            node_error: self.node_error.clone(),
        }
    }

    pub(crate) fn restore(&mut self, checkpoint: NssRuntimeCheckpoint) {
        if let (Some(runtime), Some(runtime_checkpoint)) =
            (self.ecm_bpf.as_mut(), checkpoint.ecm_bpf)
        {
            runtime.restore_collection_checkpoint(&mut self.ecm_bpf_collector, runtime_checkpoint);
        }
        self.node_windows = checkpoint.node_windows;
        self.ecm_bpf_coverage = checkpoint.ecm_bpf_coverage;
        self.ecm_bpf_rates = checkpoint.ecm_bpf_rates;
        self.ecm_bpf_error = checkpoint.ecm_bpf_error;
        self.ecm_bpf_error_stage = checkpoint.ecm_bpf_error_stage;
        self.node_error = checkpoint.node_error;
    }

    pub(crate) fn collect_ecm_bpf(
        &mut self,
        identities: &IdentityTable,
        now_ms: &mut u64,
        freshness_ms: u64,
        runtime_health: &mut RuntimeHealth,
    ) -> (Option<EcmBpfSnapshot>, bool) {
        match self.ecm_bpf.as_mut() {
            Some(runtime) => {
                let (snapshot, fresh) = match runtime.collect_snapshot(
                    &mut self.ecm_bpf_collector,
                    identities,
                    *now_ms,
                ) {
                    Ok(snapshot) => {
                        self.ecm_bpf_error = None;
                        self.ecm_bpf_error_stage = None;
                        (Some(snapshot), true)
                    }
                    Err(error) => {
                        self.ecm_bpf_error_stage = Some(error.stage());
                        self.ecm_bpf_error = Some(error.to_string());
                        (self.ecm_bpf_collector.last_complete().cloned(), false)
                    }
                };
                if let Some(snapshot) = snapshot.as_ref() {
                    *now_ms = (*now_ms).max(snapshot.sample_ms);
                }
                runtime.apply_runtime_health(runtime_health, *now_ms, freshness_ms);
                (snapshot, fresh)
            }
            None => {
                runtime_health.ecm_bpf_freshness_ms = freshness_ms;
                runtime_health.ecm_bpf_error_stage = self.ecm_bpf_error_stage.map(str::to_owned);
                runtime_health.ecm_bpf_runtime_error = self.ecm_bpf_error.clone();
                (None, false)
            }
        }
    }

    pub(crate) fn read_node(
        &mut self,
        identities: &IdentityTable,
        now_ms: u64,
        runtime_health: &mut RuntimeHealth,
    ) -> Option<NodeSnapshot> {
        match ecm_node::read(identities, now_ms) {
            Ok(snapshot) => {
                self.node_error = None;
                runtime_health.nss_node_read_ok = Some(true);
                Some(snapshot)
            }
            Err(error) => {
                self.node_error = Some(error.to_string());
                runtime_health.nss_node_read_ok = Some(false);
                None
            }
        }
    }

    pub(crate) fn transition_rate_owner(
        &mut self,
        current: &mut Option<RateCollector>,
        next: RateCollector,
    ) {
        if *current == Some(next) {
            return;
        }
        if *current != Some(RateCollector::NssEcmNode) || next != RateCollector::NssEcmNode {
            self.node_windows = NssWindowBook::default();
        }
        if *current != Some(RateCollector::NssEcmBpf) || next != RateCollector::NssEcmBpf {
            self.ecm_bpf_coverage = NssCoverageBook::default();
            self.ecm_bpf_rates = EcmBpfRateWindowBook::default();
        }
        *current = Some(next);
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), String> {
        let Some(runtime) = self.ecm_bpf.as_mut() else {
            return Ok(());
        };
        runtime.shutdown().map_err(|error| error.to_string())
    }
}
