use std::sync::Arc;

use crate::{
    config::RuntimeConfig,
    identity::IdentityTable,
    platform::nss::{
        ecm_bpf::{
            EcmBpfCollectionCheckpoint, EcmBpfRuntime, EcmBpfSnapshot, EcmBpfSnapshotCollector,
        },
        ecm_node::{self, NodeSnapshot},
        evidence_lease::{EvidenceLeaseRuntime, LeaseClientObservation, LeaseSourceObservation},
        fast_n_runtime::FastNSnapshot,
        fast_rate_contract::FastRateBaseContract,
        fast_rate_worker::FastRatePublication,
        fast_s_runtime::FastSSnapshot,
        hardware_verifier::HardwareVerifier,
        low_rate_window::NssLowRateWindow,
        rate_mux::{RateMuxRuntime, RateView},
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
    pub(crate) fast_rate: Option<FastRatePublication>,
    pub(crate) fast_rate_contract: Option<Arc<FastRateBaseContract>>,
    pub(crate) low_rate_window: NssLowRateWindow,
    pub(crate) evidence_leases: EvidenceLeaseRuntime,
    pub(crate) rate_mux: RateMuxRuntime,
    pub(crate) hardware_verifier: HardwareVerifier,
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
    fast_rate: Option<FastRatePublication>,
    fast_rate_contract: Option<Arc<FastRateBaseContract>>,
    low_rate_window: NssLowRateWindow,
    evidence_leases: EvidenceLeaseRuntime,
    rate_mux: RateMuxRuntime,
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
            fast_rate: None,
            fast_rate_contract: None,
            low_rate_window: NssLowRateWindow::default(),
            evidence_leases: EvidenceLeaseRuntime::default(),
            rate_mux: RateMuxRuntime::default(),
            hardware_verifier: HardwareVerifier::default(),
        }
    }
}

impl NssRuntime {
    pub(crate) fn activate(&mut self, config: &RuntimeConfig, report: &ProbeReport) {
        #[cfg(target_arch = "aarch64")]
        {
            if !config.enable_bpf
                || (!matches!(
                    config.rate_collector_mode,
                    RateCollectorMode::Auto | RateCollectorMode::NssEcmBpf
                ) && !config.internet_view_mode.uses_fast_rate())
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
            ecm_bpf_error: self.ecm_bpf_error.clone(),
            ecm_bpf_error_stage: self.ecm_bpf_error_stage,
            node_error: self.node_error.clone(),
            fast_rate: self.fast_rate.clone(),
            fast_rate_contract: self.fast_rate_contract.clone(),
            low_rate_window: self.low_rate_window.clone(),
            evidence_leases: self.evidence_leases.clone(),
            rate_mux: self.rate_mux.clone(),
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
        self.ecm_bpf_error = checkpoint.ecm_bpf_error;
        self.ecm_bpf_error_stage = checkpoint.ecm_bpf_error_stage;
        self.node_error = checkpoint.node_error;
        self.fast_rate = checkpoint.fast_rate;
        self.fast_rate_contract = checkpoint.fast_rate_contract;
        self.low_rate_window = checkpoint.low_rate_window;
        self.evidence_leases = checkpoint.evidence_leases;
        self.rate_mux = checkpoint.rate_mux;
        self.hardware_verifier = checkpoint.hardware_verifier;
    }

    pub(crate) fn install_fast_rate_publication(
        &mut self,
        publication: FastRatePublication,
        contract: Arc<FastRateBaseContract>,
    ) {
        self.fast_rate = Some(publication);
        self.fast_rate_contract = Some(contract);
    }

    pub(crate) fn fast_rate_reads_ready(&self, now_ms: u64) -> bool {
        const MAX_AGE_MS: u64 = 2_500;
        self.fast_rate.as_ref().is_some_and(|publication| {
            publication.read_valid
                && publication.observed_ms <= now_ms
                && now_ms.saturating_sub(publication.observed_ms) <= MAX_AGE_MS
                && publication.fast_n.is_some()
                && publication.fast_s.is_some()
        })
    }

    pub(crate) fn fast_n_read_failures(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_n_read_failures)
    }

    pub(crate) fn fast_n_snapshot(&self) -> Option<&FastNSnapshot> {
        self.fast_rate
            .as_ref()
            .and_then(|publication| publication.fast_n.as_ref())
    }

    pub(crate) fn fast_s_snapshot(&self) -> Option<&FastSSnapshot> {
        self.fast_rate
            .as_ref()
            .and_then(|publication| publication.fast_s.as_ref())
    }

    pub(crate) fn fast_s_read_failures(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_read_failures)
    }

    pub(crate) fn fast_s_invalid_reads(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_invalid_reads)
    }

    pub(crate) fn fast_s_truncated_reads(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_truncated_reads)
    }

    pub(crate) fn fast_s_invalid_abi(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_invalid_abi)
    }

    pub(crate) fn fast_s_invalid_sequence(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_invalid_sequence)
    }

    pub(crate) fn fast_s_invalid_generation_mismatch(&self) -> u64 {
        self.fast_rate.as_ref().map_or(0, |publication| {
            publication.fast_s_invalid_generation_mismatch
        })
    }

    pub(crate) fn fast_s_invalid_value(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_invalid_value)
    }

    pub(crate) fn fast_s_invalid_cpu(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_invalid_cpu)
    }

    pub(crate) fn fast_s_invalid_no_cpu(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_invalid_no_cpu)
    }

    pub(crate) fn fast_s_invalid_cpu_count(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_invalid_cpu_count)
    }

    pub(crate) fn fast_s_invalid_cpu_generation(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_invalid_cpu_generation)
    }

    pub(crate) fn fast_s_last_cpu_generation_expected(&self) -> Option<u32> {
        self.fast_rate
            .as_ref()
            .and_then(|publication| publication.fast_s_last_cpu_generation_expected)
    }

    pub(crate) fn fast_s_last_cpu_generation_actual(&self) -> Option<u32> {
        self.fast_rate
            .as_ref()
            .and_then(|publication| publication.fast_s_last_cpu_generation_actual)
    }

    pub(crate) fn fast_s_reset_generation_changes(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.fast_s_reset_generation_changes)
    }

    pub(crate) fn fast_rate_shadow_latest(
        &self,
    ) -> Option<crate::platform::nss::fast_rate_store::FastRateSample> {
        self.fast_rate
            .as_ref()
            .and_then(|publication| publication.sample)
    }

    pub(crate) fn fast_rate_shadow_telemetry(
        &self,
    ) -> crate::platform::nss::fast_rate_store::FastRateTelemetry {
        self.fast_rate
            .as_ref()
            .map_or(Default::default(), |publication| publication.telemetry)
    }

    pub(crate) fn fast_rate_shadow_comparison(
        &self,
    ) -> Option<crate::platform::nss::fast_rate_store::FastShadowComparison> {
        self.fast_rate
            .as_ref()
            .and_then(|publication| publication.comparison)
    }

    pub(crate) fn fast_rate_shadow_client_rate(
        &self,
        mac: [u8; 6],
        direction: u8,
        identity_key: &str,
        attachment_generation: u64,
    ) -> Option<crate::platform::nss::fast_rate_clients::FastClientSample> {
        if !self.fast_rate_contract.as_ref().is_some_and(|contract| {
            contract.client_matches(mac, identity_key, attachment_generation)
        }) {
            return None;
        }
        self.fast_rate
            .as_ref()
            .and_then(|publication| publication.client_rate(mac, direction))
    }

    /// Return the monotonic timestamp of the currently published FastRate
    /// snapshot.  The rate worker may finish its map reads after the runtime
    /// collection clock was sampled; callers use the newer of the two clocks
    /// when checking freshness instead of rejecting that valid window as
    /// future data.
    pub(crate) fn fast_rate_observed_ms(&self) -> Option<u64> {
        self.fast_rate
            .as_ref()
            .map(|publication| publication.observed_ms)
    }

    pub(crate) fn fast_rate_shadow_client_invalid_windows(&self) -> u64 {
        self.fast_rate
            .as_ref()
            .map_or(0, |publication| publication.client_invalid_windows)
    }

    pub(crate) fn fast_rate_shadow_last_error_code(&self) -> Option<&'static str> {
        match self
            .fast_rate
            .as_ref()
            .and_then(|publication| publication.last_error)
        {
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

    pub(crate) fn reconcile_evidence_leases(
        &mut self,
        now_ms: u64,
        runtime_health: &RuntimeHealth,
        fast_reads_ready: bool,
        proof_cycle_ready: bool,
        clients: &[LeaseClientObservation],
    ) {
        let fast_n = self.fast_n_snapshot();
        let fast_s = self.fast_s_snapshot();
        let source = LeaseSourceObservation {
            nss_bpf_object_loaded: runtime_health.ecm_bpf_object_loaded,
            nss_bpf_attached: runtime_health.ecm_bpf_attached,
            nss_map_read_attempted: runtime_health.ecm_bpf_map_read_attempted,
            nss_map_read_ok: runtime_health.ecm_bpf_map_read_ok,
            nss_map_truncated: runtime_health.ecm_bpf_map_iteration_truncated
                || fast_n.is_some_and(|snapshot| snapshot.truncated),
            tc_bpf_object_loaded: runtime_health.bpf_object_loaded,
            tc_bpf_attached: runtime_health.bpf_attached,
            tc_expected_hooks: runtime_health.bpf_expected_hook_count,
            tc_attached_hooks: runtime_health.bpf_attached_hook_count,
            tc_map_read_attempted: runtime_health.bpf_map_read_attempted,
            tc_map_read_ok: runtime_health.bpf_map_read_ok,
            tc_map_truncated: runtime_health.bpf_map_iteration_truncated
                || fast_s.is_some_and(|snapshot| snapshot.truncated),
            tc_self_heal_recoveries: runtime_health.bpf_self_heal_recoveries,
            layout: runtime_health.ecm_bpf_layout,
            fast_n_reset_generation: fast_n.and_then(|snapshot| {
                (snapshot.reset_generation != 0).then_some(snapshot.reset_generation)
            }),
            fast_s_reset_generation: fast_s.map(|snapshot| snapshot.reset_generation),
            fast_integrity_failure: fast_n.is_some_and(|snapshot| snapshot.invalid_entries != 0)
                || fast_s.is_some_and(|snapshot| snapshot.invalid_entries != 0),
            fast_reads_ready,
            proof_cycle_ready,
        };
        self.evidence_leases.reconcile(now_ms, source, clients);
    }

    pub(crate) fn evidence_lease_evidence(&self) -> serde_json::Value {
        self.evidence_leases.evidence()
    }

    pub(crate) fn begin_rate_mux_cycle(&mut self, active: bool) {
        self.rate_mux.begin_cycle(active);
    }

    pub(crate) fn select_rate_view(
        &mut self,
        client_identity: &str,
        direction: crate::platform::access_edge::Direction,
        e: crate::platform::nss::evidence_lease::EUsability,
        fast_window_valid: bool,
        explicit_internet_view: bool,
    ) -> RateView {
        let lease_valid = self.evidence_leases.lease_valid(client_identity, direction);
        self.rate_mux.select(
            client_identity,
            direction,
            e,
            lease_valid,
            fast_window_valid,
            explicit_internet_view,
        )
    }

    pub(crate) fn rate_mux_evidence(&self) -> serde_json::Value {
        self.rate_mux.evidence()
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::NssRuntime;
    use crate::platform::nss::{
        fast_n_runtime::FastNSnapshot,
        fast_rate_contract::{FastRateBaseContract, FastRateClientContract},
        fast_rate_worker::FastRatePublication,
        fast_s_runtime::FastSSnapshot,
    };

    fn contract(generation: u64) -> Arc<FastRateBaseContract> {
        Arc::new(FastRateBaseContract::new(
            3,
            [FastRateClientContract {
                mac: [2, 0, 0, 0, 0, 1],
                identity_key: "client@lan".into(),
                attachment_generation: generation,
            }],
        ))
    }

    #[test]
    fn worker_publication_must_be_valid_complete_and_current_for_a_lease() {
        let mut runtime = NssRuntime::default();
        runtime.install_fast_rate_publication(
            FastRatePublication {
                observed_ms: 2_000,
                read_valid: true,
                fast_n: Some(FastNSnapshot::default()),
                fast_s: Some(FastSSnapshot::default()),
                ..FastRatePublication::default()
            },
            contract(7),
        );
        assert!(runtime.fast_rate_reads_ready(4_500));
        assert!(!runtime.fast_rate_reads_ready(4_501));
        assert!(!runtime.fast_rate_reads_ready(1_999));

        runtime.install_fast_rate_publication(
            FastRatePublication {
                observed_ms: 5_000,
                read_valid: false,
                fast_n: Some(FastNSnapshot::default()),
                fast_s: Some(FastSSnapshot::default()),
                ..FastRatePublication::default()
            },
            contract(7),
        );
        assert!(!runtime.fast_rate_reads_ready(5_000));
    }

    #[test]
    fn client_rate_cannot_cross_an_identity_or_attachment_generation() {
        use crate::platform::nss::{
            fast_rate_clients::{FastClientKey, FastClientSample},
            fast_rate_worker::FastRatePublication,
        };
        use lanspeed_common::DIR_TX;

        let mut runtime = NssRuntime::default();
        runtime.install_fast_rate_publication(
            FastRatePublication {
                client_samples: vec![(
                    FastClientKey {
                        mac: [2, 0, 0, 0, 0, 1],
                        direction: DIR_TX,
                    },
                    FastClientSample {
                        sample_ms: 2_000,
                        window_ms: 1_000,
                        read_end_skew_ms: 0,
                        fast_n_bps: 8_000,
                        fast_s_bps: 0,
                        fast_total_bps: 8_000,
                        routed_l2_with_fcs_bps: 8_000,
                    },
                )],
                ..FastRatePublication::default()
            },
            contract(7),
        );
        assert!(runtime
            .fast_rate_shadow_client_rate([2, 0, 0, 0, 0, 1], DIR_TX, "client@lan", 7)
            .is_some());
        assert!(runtime
            .fast_rate_shadow_client_rate([2, 0, 0, 0, 0, 1], DIR_TX, "replacement@lan", 7)
            .is_none());
        assert!(runtime
            .fast_rate_shadow_client_rate([2, 0, 0, 0, 0, 1], DIR_TX, "client@lan", 8)
            .is_none());
    }
}
