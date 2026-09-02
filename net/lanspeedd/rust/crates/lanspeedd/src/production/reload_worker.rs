//! Runtime-owned reload transaction for the production daemon.
//!
//! Reload preparation, probing, BPF topology changes, rollback, and retired
//! runtime cleanup can all block. The uloop thread transfers the complete
//! runtime into this worker and only publishes the returned outcome.

use std::sync::mpsc::{Receiver, SyncSender};

use super::*;

struct ReloadTask {
    runtime: ProductionRuntime,
}

pub(super) struct ReloadSuccess {
    pub(super) runtime: ProductionRuntime,
    pub(super) config: RuntimeConfig,
    pub(super) snapshot: ResponseSnapshot,
    pub(super) fatal_error: Option<String>,
}

pub(super) struct ReloadFailure {
    pub(super) runtime: ProductionRuntime,
    pub(super) error: DaemonError,
    pub(super) fatal: bool,
}

pub(super) enum ReloadOutcome {
    Success(ReloadSuccess),
    Failure(ReloadFailure),
}

impl ReloadOutcome {
    pub(super) fn into_runtime(self) -> ProductionRuntime {
        match self {
            Self::Success(success) => success.runtime,
            Self::Failure(failure) => failure.runtime,
        }
    }

    fn shutdown(mut self) {
        let runtime = match &mut self {
            Self::Success(success) => &mut success.runtime,
            Self::Failure(failure) => &mut failure.runtime,
        };
        let _ = runtime.shutdown();
    }
}

pub(super) struct ReloadNotice {
    pub(super) outcome: ReloadOutcome,
}

pub(super) struct ProductionReloadWorker {
    worker: RuntimeWorker<ReloadTask>,
}

impl ProductionReloadWorker {
    pub(super) fn spawn(
        capacity: usize,
        notices: SyncSender<ReloadNotice>,
    ) -> Result<Self, std::io::Error> {
        let worker = crate::workers::spawn_runtime_worker(capacity, move |task: ReloadTask| {
            let notice = ReloadNotice {
                outcome: reload_transaction(task.runtime),
            };
            if let Err(error) = notices.send(notice) {
                error.0.outcome.shutdown();
            }
        })?;
        Ok(Self { worker })
    }

    pub(super) fn try_reload(
        &self,
        runtime: ProductionRuntime,
    ) -> Result<(), (QueueError, ProductionRuntime)> {
        self.worker
            .queue()
            .try_send_recover(ReloadTask { runtime })
            .map_err(|(error, task)| (error, task.runtime))
    }

    pub(super) fn join(self) -> std::thread::Result<()> {
        self.worker.join()
    }
}

pub(super) fn notice_channel(
    capacity: usize,
) -> (SyncSender<ReloadNotice>, Receiver<ReloadNotice>) {
    std::sync::mpsc::sync_channel(capacity.max(1))
}

struct PreparedBpfReload {
    transaction: BpfReconfigureTxn,
}

fn reload_transaction(mut current: ProductionRuntime) -> ReloadOutcome {
    let config = match load_config() {
        Ok(config) => config,
        Err(error) => return failure(current, error, false),
    };
    let process_tracker = current.process_tracker.clone();
    #[cfg(feature = "nss-platform")]
    let attachment_generation_floor = current.access_edge.attachment_generation_watermark();
    let mut candidate =
        match ProductionRuntime::prepare_with_process_tracker(config.clone(), process_tracker) {
            Ok(candidate) => candidate,
            Err(error) => return failure(current, error, false),
        };
    #[cfg(all(not(feature = "nss-platform"), feature = "traffic-persistence"))]
    {
        candidate.traffic_ledger = if config.show_client_totals {
            current
                .traffic_ledger
                .as_ref()
                .map(TrafficLedger::fork_for_reload)
        } else {
            None
        };
    }
    #[cfg(feature = "nss-platform")]
    {
        candidate.control.inherit_nss_reload_state(&current.control);
        candidate.control_platform_owner = false;
        candidate
            .access_edge
            .advance_attachment_generation_floor(attachment_generation_floor);
        candidate
            .nss
            .activate(&candidate.config, &candidate.probe_report);
    }

    let wants_bpf = config.enable_bpf
        && matches!(
            config.rate_collector_mode,
            crate::config::RateCollectorMode::Auto
                | crate::config::RateCollectorMode::Bpf
                | crate::config::RateCollectorMode::NssEcmBpf
        )
        && candidate.probe_report.facts.tc.safe_attach;
    let desired_mode = candidate.desired_attach_mode();
    let reconfigure_strategy = if wants_bpf && current.bpf.is_some() {
        let current_bpf = current.bpf.as_ref().unwrap();
        if current_bpf.attach_mode().is_none() {
            return failure_with_candidate(
                current,
                candidate,
                DaemonError::reload("current BPF topology is not healthy enough to reload"),
                false,
            );
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
                let fatal = error.kind() == AdapterErrorKind::DetachFailed;
                return failure_with_candidate(
                    current,
                    candidate,
                    DaemonError::reload(error.to_string()),
                    fatal,
                );
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
            Ok((snapshot, _)) => {
                prepared_bpf = Some(PreparedBpfReload { transaction });
                snapshot
            }
            Err(error) => {
                let rollback = runtime.abort_reconfigure(&mut current.adapter, transaction);
                let fatal = rollback.is_err();
                let error = match rollback {
                    Ok(()) => error,
                    Err(rollback) => DaemonError::reload(format!(
                        "{error}; BPF reconfigure abort failed: {rollback}"
                    )),
                };
                return failure_with_candidate(current, candidate, error, fatal);
            }
        }
    } else {
        if suspended_mode_switch {
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
                return failure_with_candidate(current, candidate, error, true);
            }
        }
        match candidate.collect(ProbeMethod::Reload) {
            Ok(snapshot) => snapshot,
            Err(error) => return failure_with_candidate(current, candidate, error, false),
        }
    };

    if suspended_mode_switch {
        let suspended = {
            let runtime = current.bpf.as_mut().unwrap();
            match runtime.suspend_for_replacement(&mut current.adapter) {
                Ok(suspended) => suspended,
                Err(error) => {
                    let fatal = !runtime.is_attached();
                    return failure_with_candidate(
                        current,
                        candidate,
                        DaemonError::reload(format!("BPF mode-switch suspend failed: {error}")),
                        fatal,
                    );
                }
            }
        };
        candidate.restore(
            mode_switch_checkpoint
                .take()
                .expect("suspended mode switch checkpointed before collection"),
        );
        candidate.bpf_collector.reset_rates();
        let interfaces = collect_ifnames(&config);
        if let Err(error) = current.bpf.as_mut().unwrap().attach_suspended(
            &mut current.adapter,
            &suspended,
            &interfaces,
            desired_mode,
        ) {
            let restore = current
                .bpf
                .as_mut()
                .unwrap()
                .resume_suspended(&mut current.adapter, suspended);
            let fatal = restore.is_err();
            let error = match restore {
                Ok(()) => DaemonError::reload(error.to_string()),
                Err(restore) => DaemonError::reload(format!(
                    "{error}; BPF mode-switch restore failed: {restore}"
                )),
            };
            return failure_with_candidate(current, candidate, error, fatal);
        }
        snapshot = match candidate.collect_with_external_bpf(
            current.bpf.as_mut().unwrap(),
            &mut current.adapter,
            ProbeMethod::Reload,
        ) {
            Ok((snapshot, _)) => snapshot,
            Err(error) => {
                let restore = current
                    .bpf
                    .as_mut()
                    .unwrap()
                    .suspend_for_replacement(&mut current.adapter)
                    .and_then(|_| {
                        current
                            .bpf
                            .as_mut()
                            .unwrap()
                            .resume_suspended(&mut current.adapter, suspended)
                    });
                let fatal = restore.is_err();
                let error = match restore {
                    Ok(()) => error,
                    Err(restore) => DaemonError::reload(format!(
                        "{error}; BPF mode-switch rollback failed: {restore}"
                    )),
                };
                return failure_with_candidate(current, candidate, error, fatal);
            }
        };
        candidate.adapter = std::mem::take(&mut current.adapter);
        candidate.bpf = current.bpf.take();
    }

    let postcommit_cleanup: Option<BpfPostCommitCleanup<SystemAyaLink>> =
        prepared_bpf.take().map(|prepared| {
            let runtime = current.bpf.as_mut().unwrap();
            let cleanup =
                runtime.commit_reconfigure(prepared.transaction, ReconfigureRateBaseline::Prepared);
            candidate.adapter = std::mem::take(&mut current.adapter);
            candidate.bpf = current.bpf.take();
            cleanup
        });

    #[cfg(feature = "nss-platform")]
    {
        candidate.control_platform_owner = true;
        current.control_platform_owner = false;
    }

    #[cfg(all(not(feature = "nss-platform"), feature = "traffic-persistence"))]
    {
        if let Some(ledger) = candidate.traffic_ledger.as_mut() {
            ledger.activate_storage_owner();
        }
        if let Some(ledger) = current.traffic_ledger.as_mut() {
            ledger.deactivate_storage_owner();
        }
        candidate.collection_committed();
    }

    let mut fatal_errors = Vec::new();
    if let Err(error) = current.shutdown() {
        fatal_errors.push(format!(
            "reload committed; postcommit old runtime cleanup failed: {error}"
        ));
    }
    if let Some(cleanup) = postcommit_cleanup {
        let runtime = candidate.bpf.as_mut().unwrap();
        if let Err(error) = runtime.run_postcommit_cleanup(&mut candidate.adapter, cleanup) {
            fatal_errors.push(format!(
                "reload committed; postcommit BPF cleanup failed: {error}"
            ));
        }
    }

    ReloadOutcome::Success(ReloadSuccess {
        runtime: candidate,
        config,
        snapshot,
        fatal_error: (!fatal_errors.is_empty()).then(|| fatal_errors.join("; ")),
    })
}

fn failure(runtime: ProductionRuntime, error: DaemonError, fatal: bool) -> ReloadOutcome {
    ReloadOutcome::Failure(ReloadFailure {
        runtime,
        error,
        fatal,
    })
}

fn failure_with_candidate(
    current: ProductionRuntime,
    mut candidate: ProductionRuntime,
    error: DaemonError,
    fatal: bool,
) -> ReloadOutcome {
    match candidate.shutdown() {
        Ok(()) => failure(current, error, fatal),
        Err(cleanup) => failure(
            current,
            DaemonError::reload(format!("{error}; candidate cleanup failed: {cleanup}")),
            true,
        ),
    }
}
