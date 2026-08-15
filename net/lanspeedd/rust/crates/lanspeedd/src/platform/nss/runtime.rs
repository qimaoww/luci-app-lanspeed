use crate::{
    config::RuntimeConfig,
    identity::IdentityTable,
    platform::nss::{
        ecm_bpf::{
            EcmBpfCollectionCheckpoint, EcmBpfRuntime, EcmBpfSnapshot, EcmBpfSnapshotCollector,
        },
        ecm_node::{self, NodeSnapshot},
        fast_n_runtime::{FastNRuntime, FastNSnapshot},
        fast_rate_shadow::FastRateShadow,
        fast_s_runtime::{FastSRuntime, FastSSnapshot},
        hardware_verifier::HardwareVerifier,
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
    pub(crate) fast_n: FastNRuntime,
    pub(crate) fast_s: FastSRuntime,
    pub(crate) fast_rate_shadow: FastRateShadow,
    pub(crate) hardware_verifier: HardwareVerifier,
}

#[derive(Clone)]
pub(crate) struct NssRuntimeCheckpoint {
    ecm_bpf: Option<EcmBpfCollectionCheckpoint>,
    node_windows: NssWindowBook,
    ecm_bpf_coverage: NssCoverageBook,
    ecm_bpf_rates: EcmBpfRateWindowBook,
    fast_n: FastNRuntime,
    ecm_bpf_error: Option<String>,
    ecm_bpf_error_stage: Option<&'static str>,
    node_error: Option<String>,
    fast_s: FastSRuntime,
    fast_rate_shadow: FastRateShadow,
    hardware_verifier: HardwareVerifier,
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
            fast_n: FastNRuntime::default(),
            fast_s: FastSRuntime::default(),
            fast_rate_shadow: FastRateShadow::new(),
            hardware_verifier: HardwareVerifier::default(),
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
            match EcmBpfRuntime::load_and_attach_with_max_clients(
                ECM_BPF_OBJECT_PATH,
                config.max_clients,
            ) {
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
            fast_n: self.fast_n.clone(),
            ecm_bpf_error: self.ecm_bpf_error.clone(),
            ecm_bpf_error_stage: self.ecm_bpf_error_stage,
            node_error: self.node_error.clone(),
            fast_s: self.fast_s.clone(),
            fast_rate_shadow: self.fast_rate_shadow.clone(),
            hardware_verifier: self.hardware_verifier.clone(),
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
        self.fast_n = checkpoint.fast_n;
        self.ecm_bpf_error = checkpoint.ecm_bpf_error;
        self.ecm_bpf_error_stage = checkpoint.ecm_bpf_error_stage;
        self.node_error = checkpoint.node_error;
        self.fast_s = checkpoint.fast_s;
        self.fast_rate_shadow = checkpoint.fast_rate_shadow;
        self.hardware_verifier = checkpoint.hardware_verifier;
    }

    pub(crate) fn collect_fast_s(
        &mut self,
        read: crate::platform::fast_counter_map::FastCounterMapRead,
        now_ms: u64,
    ) -> FastSSnapshot {
        self.fast_s.collect(read, now_ms)
    }

    pub(crate) fn collect_fast_n(
        &mut self,
        read: crate::platform::nss::ecm_bpf::EcmFastCounterMapRead,
        now_ms: u64,
    ) -> FastNSnapshot {
        self.fast_n.collect(read, now_ms)
    }

    pub(crate) fn record_fast_n_read_failure(&mut self) {
        self.fast_n.record_read_failure();
    }

    pub(crate) const fn fast_n_read_failures(&self) -> u64 {
        self.fast_n.read_failures()
    }

    pub(crate) fn fast_n_snapshot(&self) -> Option<&FastNSnapshot> {
        self.fast_n.last_snapshot()
    }

    pub(crate) fn record_fast_s_read_failure(&mut self) {
        self.fast_s.record_read_failure();
    }

    pub(crate) fn fast_s_snapshot(&self) -> Option<&FastSSnapshot> {
        self.fast_s.last_snapshot()
    }

    pub(crate) const fn fast_s_read_failures(&self) -> u64 {
        self.fast_s.read_failures()
    }

    pub(crate) const fn fast_s_invalid_reads(&self) -> u64 {
        self.fast_s.invalid_reads()
    }

    pub(crate) const fn fast_s_truncated_reads(&self) -> u64 {
        self.fast_s.truncated_reads()
    }

    pub(crate) const fn fast_s_invalid_abi(&self) -> u64 {
        self.fast_s.invalid_abi()
    }

    pub(crate) const fn fast_s_invalid_sequence(&self) -> u64 {
        self.fast_s.invalid_sequence()
    }

    pub(crate) const fn fast_s_invalid_generation_mismatch(&self) -> u64 {
        self.fast_s.invalid_generation_mismatch()
    }

    pub(crate) const fn fast_s_invalid_value(&self) -> u64 {
        self.fast_s.invalid_value()
    }

    pub(crate) const fn fast_s_invalid_cpu(&self) -> u64 {
        self.fast_s.invalid_cpu()
    }

    pub(crate) const fn fast_s_invalid_no_cpu(&self) -> u64 {
        self.fast_s.invalid_no_cpu()
    }

    pub(crate) const fn fast_s_invalid_cpu_count(&self) -> u64 {
        self.fast_s.invalid_cpu_count()
    }

    pub(crate) const fn fast_s_invalid_cpu_generation(&self) -> u64 {
        self.fast_s.invalid_cpu_generation()
    }

    pub(crate) const fn fast_s_last_cpu_generation_expected(&self) -> Option<u32> {
        self.fast_s.last_cpu_generation_expected()
    }

    pub(crate) const fn fast_s_last_cpu_generation_actual(&self) -> Option<u32> {
        self.fast_s.last_cpu_generation_actual()
    }

    pub(crate) const fn fast_s_reset_generation_changes(&self) -> u64 {
        self.fast_s.reset_generation_changes()
    }

    pub(crate) fn observe_fast_rate_shadow(
        &mut self,
        fast_n: Option<&FastNSnapshot>,
        n_read_begin_ms: u64,
        n_read_end_ms: u64,
        s_read_begin_ms: u64,
        s_read_end_ms: u64,
        edge_bps: Option<u64>,
    ) {
        let fast_s = self.fast_s_snapshot().cloned();
        self.fast_rate_shadow.observe(
            fast_n,
            fast_s.as_ref(),
            n_read_begin_ms,
            n_read_end_ms,
            s_read_begin_ms,
            s_read_end_ms,
            edge_bps,
        );
    }

    pub(crate) const fn fast_rate_shadow_latest(
        &self,
    ) -> Option<crate::platform::nss::fast_rate_store::FastRateSample> {
        self.fast_rate_shadow.latest()
    }

    pub(crate) const fn fast_rate_shadow_telemetry(
        &self,
    ) -> crate::platform::nss::fast_rate_store::FastRateTelemetry {
        self.fast_rate_shadow.telemetry()
    }

    pub(crate) const fn fast_rate_shadow_comparison(
        &self,
    ) -> Option<crate::platform::nss::fast_rate_store::FastShadowComparison> {
        self.fast_rate_shadow.comparison()
    }

    pub(crate) const fn fast_rate_shadow_last_error_code(&self) -> Option<&'static str> {
        match self.fast_rate_shadow.last_error() {
            Some(crate::platform::nss::fast_rate::FastWindowError::InvalidReadInterval) => {
                Some("invalid_read_interval")
            }
            Some(crate::platform::nss::fast_rate::FastWindowError::ReadEndSkew { .. }) => {
                Some("read_end_skew")
            }
            Some(crate::platform::nss::fast_rate::FastWindowError::SampleSkew { .. }) => {
                Some("sample_skew")
            }
            Some(crate::platform::nss::fast_rate::FastWindowError::AttachmentGenerationChanged) => {
                Some("attachment_generation_changed")
            }
            Some(crate::platform::nss::fast_rate::FastWindowError::ResetGenerationChanged) => {
                Some("reset_generation_changed")
            }
            Some(crate::platform::nss::fast_rate::FastWindowError::TimeDidNotAdvance) => {
                Some("time_did_not_advance")
            }
            Some(crate::platform::nss::fast_rate::FastWindowError::CounterReset) => {
                Some("counter_reset")
            }
            None => None,
        }
    }

    pub(crate) fn observe_hardware_verifier(
        &mut self,
        nss: Option<&EcmBpfSnapshot>,
        sample_ms: u64,
        fresh: bool,
    ) {
        self.hardware_verifier.observe(nss, sample_ms, fresh);
    }

    pub(crate) fn hardware_verifier_evidence(&self) -> serde_json::Value {
        self.hardware_verifier.evidence()
    }

    pub(crate) fn collect_ecm_bpf(
        &mut self,
        identities: &IdentityTable,
        now_ms: &mut u64,
        freshness_ms: u64,
        runtime_health: &mut RuntimeHealth,
        read_due: bool,
    ) -> (Option<EcmBpfSnapshot>, bool) {
        match self.ecm_bpf.as_mut() {
            Some(runtime) => {
                if !read_due {
                    runtime.apply_runtime_health(runtime_health, *now_ms, freshness_ms);
                    return (self.ecm_bpf_collector.last_complete().cloned(), false);
                }
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
