use std::{
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
};

use super::ProbeReport;

const PROCESS_PROBE_FAILED_WARNING: &str = "dae_process_probe_failed";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DaeProcessState {
    pub dae: bool,
    pub daed: bool,
}

impl DaeProcessState {
    pub const fn active(self) -> bool {
        self.dae || self.daed
    }
}

pub fn scan_dae_processes(proc_root: impl AsRef<Path>) -> io::Result<DaeProcessState> {
    let proc_root = proc_root.as_ref();
    let entries = fs::read_dir(proc_root)?.map(|entry| {
        entry.map(|entry| {
            let name = entry.file_name();
            (name, entry.path())
        })
    });
    scan_dae_process_entries(entries, |path| fs::read(path.join("comm")))
}

fn scan_dae_process_entries(
    entries: impl IntoIterator<Item = io::Result<(OsString, PathBuf)>>,
    mut read_comm: impl FnMut(&Path) -> io::Result<Vec<u8>>,
) -> io::Result<DaeProcessState> {
    let mut state = DaeProcessState::default();
    for entry in entries {
        let (name, path) = entry?;
        if state.dae && state.daed {
            continue;
        }
        let Some(pid) = name.to_str() else {
            continue;
        };
        if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(mut comm) = read_comm(&path) else {
            continue;
        };
        while matches!(comm.last(), Some(b'\n' | b'\r')) {
            comm.pop();
        }
        match comm.as_slice() {
            b"dae" => state.dae = true,
            b"daed" => state.daed = true,
            _ => {}
        }
    }
    Ok(state)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaeProcessTracker {
    state: DaeProcessState,
    last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DaeModeReloadLatch {
    pending: bool,
}

impl DaeModeReloadLatch {
    pub fn observe(
        &mut self,
        has_bpf: bool,
        process_activity_changed: bool,
        attach_mode_mismatch: bool,
    ) -> bool {
        self.pending |= has_bpf && (process_activity_changed || attach_mode_mismatch);
        self.pending
    }

    pub const fn pending(&self) -> bool {
        self.pending
    }

    pub fn complete(&mut self) {
        self.pending = false;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaeModeTickSignals {
    pub has_bpf: bool,
    pub process_activity_changed: bool,
    pub attach_mode_mismatch: bool,
}

impl DaeModeTickSignals {
    pub const fn new(
        has_bpf: bool,
        process_activity_changed: bool,
        attach_mode_mismatch: bool,
    ) -> Self {
        Self {
            has_bpf,
            process_activity_changed,
            attach_mode_mismatch,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaeModeTickOutcome {
    Collected,
    Reloaded,
    RetryScheduled {
        reload_error: String,
    },
    FatalReload {
        reload_error: String,
    },
    RetryScheduleFailed {
        reload_error: String,
        timer_error: String,
    },
}

pub fn run_dae_mode_tick<C>(
    latch: &mut DaeModeReloadLatch,
    context: &mut C,
    signals: DaeModeTickSignals,
    reload: impl FnOnce(&mut C) -> Result<(), String>,
    is_fatal: impl FnOnce(&C) -> bool,
    schedule_retry: impl FnOnce(&mut C) -> Result<(), String>,
    collect: impl FnOnce(&mut C),
) -> DaeModeTickOutcome {
    if !latch.observe(
        signals.has_bpf,
        signals.process_activity_changed,
        signals.attach_mode_mismatch,
    ) {
        collect(context);
        return DaeModeTickOutcome::Collected;
    }

    match reload(context) {
        Ok(()) => {
            latch.complete();
            DaeModeTickOutcome::Reloaded
        }
        Err(reload_error) if is_fatal(context) => DaeModeTickOutcome::FatalReload { reload_error },
        Err(reload_error) => match schedule_retry(context) {
            Ok(()) => DaeModeTickOutcome::RetryScheduled { reload_error },
            Err(timer_error) => DaeModeTickOutcome::RetryScheduleFailed {
                reload_error,
                timer_error,
            },
        },
    }
}

impl DaeProcessTracker {
    pub fn refresh(&mut self, proc_root: impl AsRef<Path>) -> bool {
        let proc_root = proc_root.as_ref();
        let result = scan_dae_processes(proc_root);
        self.apply_scan_result(proc_root, result)
    }

    fn apply_scan_result(&mut self, proc_root: &Path, result: io::Result<DaeProcessState>) -> bool {
        let was_active = self.active();
        match result {
            Ok(state) => {
                self.state = state;
                self.last_error = None;
                was_active != self.active()
            }
            Err(error) => {
                self.last_error = Some(format!("read {}: {error}", proc_root.display()));
                false
            }
        }
    }

    pub const fn state(&self) -> DaeProcessState {
        self.state
    }

    pub const fn active(&self) -> bool {
        self.state.active()
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn overlay_report(&self, report: &mut ProbeReport) {
        let active = self.active();
        let static_dae = has_static_dae_evidence(report);
        let dae_detected = static_dae || active;
        report.facts.proxy.dae_process = self.state.dae;
        report.facts.proxy.daed_process = self.state.daed;
        report.facts.proxy.runtime_active = active;
        report.facts.proxy.dae = dae_detected;
        report.capabilities.dae = dae_detected;

        let dae = &mut report.evidence.proxy.dae;
        dae.dae_process = self.state.dae;
        dae.daed_process = self.state.daed;
        dae.runtime_active = active;
        dae.installed = dae_detected;
        dae.process_probe_error = self.last_error.clone();

        let cached_policy_warnings = std::mem::take(&mut report.evidence.collector.warnings);
        report.warnings.retain(|warning| {
            !cached_policy_warnings.contains(warning)
                && *warning != PROCESS_PROBE_FAILED_WARNING
                && *warning != "dae_detected"
        });
        report.conflicts.retain(|item| item.id != "proxy_stack");
        if dae_detected {
            super::push_unique(&mut report.warnings, "dae_detected");
        }
        if report.facts.proxy.openclash || dae_detected || report.facts.homeproxy {
            report.conflicts.push(super::conflict_item("proxy_stack"));
        }
        if self.last_error.is_some() {
            report.warnings.push(PROCESS_PROBE_FAILED_WARNING);
        }
    }
}

fn has_static_dae_evidence(report: &ProbeReport) -> bool {
    let dae = &report.evidence.proxy.dae;
    dae.dae_config
        || dae.daed_config
        || dae.dae_service
        || dae.daed_service
        || dae.dae_running
        || dae.daed_running
        || dae.dae0
        || dae.dae0peer
        || !dae.tc_filters.is_empty()
        || dae.fwmark_detected
        || dae.route_table_detected
        || dae.dns_udp53_detected
}

#[cfg(test)]
mod source_tests {
    use std::{
        ffi::OsString,
        io,
        path::{Path, PathBuf},
    };

    use super::{scan_dae_process_entries, DaeProcessState, DaeProcessTracker};

    fn entry(pid: &str) -> io::Result<(OsString, PathBuf)> {
        Ok((OsString::from(pid), PathBuf::from(pid)))
    }

    #[test]
    fn read_dir_iterator_error_aborts_the_entire_scan() {
        let entries = vec![
            entry("100"),
            Err(io::Error::other("iterator failed")),
            entry("101"),
        ];

        let error = scan_dae_process_entries(entries, |_| Ok(b"dae\n".to_vec())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("iterator failed"));
    }

    #[test]
    fn iterator_error_after_both_processes_are_found_still_aborts() {
        let entries = vec![
            entry("100"),
            entry("101"),
            Err(io::Error::other("late iterator failure")),
        ];

        let error = scan_dae_process_entries(entries, |path| {
            if path == Path::new("100") {
                Ok(b"dae\n".to_vec())
            } else {
                Ok(b"daed\n".to_vec())
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("late iterator failure"));
    }

    #[test]
    fn tracker_retains_state_when_an_iterator_error_occurs_mid_scan() {
        let mut tracker = DaeProcessTracker::default();
        assert!(tracker.apply_scan_result(
            Path::new("/proc"),
            Ok(DaeProcessState {
                dae: true,
                daed: false,
            }),
        ));
        let partial = scan_dae_process_entries(
            vec![entry("100"), Err(io::Error::other("iterator failed"))],
            |_| Ok(b"daed\n".to_vec()),
        );

        assert!(!tracker.apply_scan_result(Path::new("/proc"), partial));
        assert_eq!(
            tracker.state(),
            DaeProcessState {
                dae: true,
                daed: false,
            }
        );
        assert!(tracker
            .last_error()
            .is_some_and(|error| error.contains("iterator failed")));
    }

    #[test]
    fn non_numeric_proc_entries_never_read_comm() {
        let entries = vec![entry("net"), entry("self"), entry("700")];
        let mut reads = Vec::new();

        let state = scan_dae_process_entries(entries, |path| {
            reads.push(path.to_path_buf());
            Ok(b"dae\n".to_vec())
        })
        .unwrap();

        assert_eq!(reads, [PathBuf::from("700")]);
        assert!(state.dae);
    }

    #[test]
    fn complete_dae_state_skips_remaining_comm_reads() {
        let entries = vec![entry("100"), entry("101"), entry("102")];
        let mut reads = Vec::new();

        let state = scan_dae_process_entries(entries, |path| {
            reads.push(path.to_path_buf());
            Ok(if path == Path::new("100") {
                b"dae\n".to_vec()
            } else if path == Path::new("101") {
                b"daed\n".to_vec()
            } else {
                b"unrelated\n".to_vec()
            })
        })
        .unwrap();

        assert_eq!(
            state,
            DaeProcessState {
                dae: true,
                daed: true
            }
        );
        assert_eq!(reads, [PathBuf::from("100"), PathBuf::from("101")]);
    }
}
