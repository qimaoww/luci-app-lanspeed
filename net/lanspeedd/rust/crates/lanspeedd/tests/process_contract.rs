use std::{collections::VecDeque, fs, path::PathBuf};

use lanspeedd::probe::process::{run_dae_mode_tick, DaeModeTickOutcome, DaeModeTickSignals};
use lanspeedd::{
    config::RuntimeConfig,
    probe::{
        assess,
        process::{scan_dae_processes, DaeModeReloadLatch, DaeProcessState, DaeProcessTracker},
        ProbeObservations, RuntimeHealth,
    },
};

fn proc_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("lanspeedd-process-{name}-{}", std::process::id()))
}

fn write_comm(root: &PathBuf, pid: &str, comm: &str) {
    let directory = root.join(pid);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("comm"), format!("{comm}\n")).unwrap();
}

#[test]
fn proc_scan_recognizes_exact_dae_and_daed_names_only() {
    let root = proc_root("exact");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    write_comm(&root, "100", "dae");
    write_comm(&root, "101", "daed");
    write_comm(&root, "102", "dae-helper");
    write_comm(&root, "not-a-pid", "dae");

    assert_eq!(
        scan_dae_processes(&root).unwrap(),
        DaeProcessState {
            dae: true,
            daed: true,
        }
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn proc_scan_ignores_pid_races_and_unreadable_comm_entries() {
    let root = proc_root("races");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("200")).unwrap();
    fs::write(root.join("201"), "not a process directory").unwrap();
    write_comm(&root, "202", "dae-helper");

    assert_eq!(
        scan_dae_processes(&root).unwrap(),
        DaeProcessState::default()
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tracker_retains_last_good_state_when_the_proc_root_fails() {
    let root = proc_root("retain");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    write_comm(&root, "300", "dae");
    let mut tracker = DaeProcessTracker::default();

    tracker.refresh(&root);
    assert_eq!(
        tracker.state(),
        DaeProcessState {
            dae: true,
            daed: false,
        }
    );
    assert!(tracker.active());
    assert_eq!(tracker.last_error(), None);

    fs::remove_dir_all(&root).unwrap();
    tracker.refresh(&root);
    assert!(
        tracker.active(),
        "a top-level failure must retain the last good state"
    );
    assert!(tracker.last_error().is_some());

    let mut report = assess(
        &RuntimeConfig::default(),
        ProbeObservations::default(),
        &RuntimeHealth::default(),
    );
    tracker.overlay_report(&mut report);
    assert!(report.warnings.contains(&"dae_process_probe_failed"));
    assert_eq!(report.facts.proxy.dae_process, true);
    assert_eq!(report.facts.proxy.runtime_active, true);
    assert_eq!(
        report.evidence.proxy.dae.process_probe_error.as_deref(),
        tracker.last_error()
    );
}

#[test]
fn fresh_process_overlay_overrides_stale_service_running_diagnostics() {
    let root = proc_root("overlay");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let mut tracker = DaeProcessTracker::default();
    tracker.refresh(&root);

    let mut observations = ProbeObservations::default();
    observations.proxy.dae_running = true;
    observations.proxy.daed_running = true;
    let mut report = assess(
        &RuntimeConfig::default(),
        observations,
        &RuntimeHealth::default(),
    );
    tracker.overlay_report(&mut report);

    assert!(report.facts.proxy.dae_running);
    assert!(report.facts.proxy.daed_running);
    assert!(!report.facts.proxy.dae_process);
    assert!(!report.facts.proxy.daed_process);
    assert!(!report.facts.proxy.runtime_active);
    assert!(!report.evidence.proxy.dae.runtime_active);
    assert_eq!(report.evidence.proxy.dae.process_probe_error, None);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tracker_reports_only_runtime_active_edges_for_mode_reload() {
    let root = proc_root("edges");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let mut tracker = DaeProcessTracker::default();

    assert!(!tracker.refresh(&root));
    write_comm(&root, "400", "dae");
    assert!(tracker.refresh(&root), "inactive to active is a mode edge");

    fs::remove_dir_all(root.join("400")).unwrap();
    write_comm(&root, "401", "daed");
    assert!(
        !tracker.refresh(&root),
        "dae to daed keeps the same active attach policy"
    );

    fs::remove_dir_all(root.join("401")).unwrap();
    assert!(tracker.refresh(&root), "active to inactive is a mode edge");

    fs::remove_dir_all(&root).unwrap();
    assert!(
        !tracker.refresh(&root),
        "a failed top-level scan retains state and is not a false edge"
    );
}

#[test]
fn process_overlay_removes_cached_policy_warnings_before_current_cycle_reselection() {
    let root = proc_root("warnings");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let mut tracker = DaeProcessTracker::default();
    tracker.refresh(&root);

    let mut config = RuntimeConfig::default();
    config.enable_bpf = true;
    config.enable_conntrack_fallback = true;
    config.rate_collector_mode = lanspeedd::config::RateCollectorMode::NssConntrackSync;
    let mut observations = ProbeObservations::default();
    observations.commands.tc = true;
    observations.tc.clsact = true;
    observations.tc.bpf = true;
    observations.files.lan_bridge = true;
    observations.files.nf_conntrack_acct_present = true;
    observations.files.nf_conntrack_acct_value = Some("1".into());
    observations.bpf.package = true;
    observations.bpf.object = true;
    observations.nss.present = true;
    observations.nss.ecm_active = true;
    observations.nss.direct_state_readable = true;
    let runtime = RuntimeHealth {
        bpf_object_loaded: true,
        bpf_attached: true,
        bpf_map_read_ok: true,
        ..RuntimeHealth::default()
    };
    let mut report = assess(&config, observations, &runtime);
    let cached = report.evidence.collector.warnings.clone();
    assert!(cached.contains(&"nss_ecm_sync_cadence"));
    assert!(cached.contains(&"nss_prefers_conntrack_sync"));

    tracker.overlay_report(&mut report);

    assert!(report.evidence.collector.warnings.is_empty());
    for warning in cached {
        assert!(!report.warnings.contains(&warning), "stale {warning}");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn dynamic_mode_reload_latch_retries_until_success_clears_it() {
    let mut latch = DaeModeReloadLatch::default();

    assert!(!latch.observe(false, true, true));
    assert!(latch.observe(true, true, false));
    assert!(latch.pending());
    assert!(
        latch.observe(true, false, false),
        "a non-fatal failed reload must still run on the next tick"
    );

    latch.complete();
    assert!(!latch.pending());
    assert!(!latch.observe(true, false, false));
}

#[test]
fn process_only_start_and_stop_synchronize_all_derived_dae_state() {
    let root = proc_root("derived-state");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let mut tracker = DaeProcessTracker::default();
    let mut report = assess(
        &RuntimeConfig::default(),
        ProbeObservations::default(),
        &RuntimeHealth::default(),
    );

    write_comm(&root, "500", "dae");
    assert!(tracker.refresh(&root));
    tracker.overlay_report(&mut report);
    assert!(report.facts.proxy.dae);
    assert!(report.capabilities.dae);
    assert!(report.evidence.proxy.dae.installed);
    assert!(report.warnings.contains(&"dae_detected"));
    assert!(report.conflicts.iter().any(|item| item.id == "proxy_stack"));

    fs::remove_dir_all(root.join("500")).unwrap();
    assert!(tracker.refresh(&root));
    tracker.overlay_report(&mut report);
    assert!(!report.facts.proxy.dae);
    assert!(!report.capabilities.dae);
    assert!(!report.evidence.proxy.dae.installed);
    assert!(!report.warnings.contains(&"dae_detected"));
    assert!(!report.conflicts.iter().any(|item| item.id == "proxy_stack"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_stop_preserves_non_process_dae_detection() {
    let root = proc_root("static-state");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    write_comm(&root, "600", "daed");
    let mut tracker = DaeProcessTracker::default();
    let mut observations = ProbeObservations::default();
    observations.uci.dae = true;
    let mut report = assess(
        &RuntimeConfig::default(),
        observations,
        &RuntimeHealth::default(),
    );

    tracker.refresh(&root);
    tracker.overlay_report(&mut report);
    fs::remove_dir_all(root.join("600")).unwrap();
    tracker.refresh(&root);
    tracker.overlay_report(&mut report);

    assert!(report.facts.proxy.dae);
    assert!(report.capabilities.dae);
    assert!(report.evidence.proxy.dae.installed);
    assert!(report.warnings.contains(&"dae_detected"));
    assert!(report.conflicts.iter().any(|item| item.id == "proxy_stack"));
    fs::remove_dir_all(root).unwrap();
}

#[derive(Default)]
struct TickFake {
    reload_results: VecDeque<Result<(), String>>,
    reload_calls: usize,
    retry_timer_calls: usize,
    collect_calls: usize,
    publish_calls: usize,
    fatal: bool,
    retry_timer_error: Option<String>,
}

fn tick(
    latch: &mut DaeModeReloadLatch,
    fake: &mut TickFake,
    signals: DaeModeTickSignals,
) -> DaeModeTickOutcome {
    run_dae_mode_tick(
        latch,
        fake,
        signals,
        |fake| {
            fake.reload_calls += 1;
            fake.reload_results.pop_front().unwrap_or(Ok(()))
        },
        |fake| fake.fatal,
        |fake| {
            fake.retry_timer_calls += 1;
            match fake.retry_timer_error.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        },
        |fake| {
            fake.collect_calls += 1;
            fake.publish_calls += 1;
        },
    )
}

#[test]
fn dynamic_tick_handles_inactive_active_inactive_without_double_collection() {
    let mut latch = DaeModeReloadLatch::default();
    let mut fake = TickFake::default();

    assert_eq!(
        tick(
            &mut latch,
            &mut fake,
            DaeModeTickSignals::new(true, false, false),
        ),
        DaeModeTickOutcome::Collected
    );
    fake.reload_results.push_back(Ok(()));
    assert_eq!(
        tick(
            &mut latch,
            &mut fake,
            DaeModeTickSignals::new(true, true, true),
        ),
        DaeModeTickOutcome::Reloaded
    );
    fake.reload_results.push_back(Ok(()));
    assert_eq!(
        tick(
            &mut latch,
            &mut fake,
            DaeModeTickSignals::new(true, true, false),
        ),
        DaeModeTickOutcome::Reloaded
    );

    assert_eq!(fake.reload_calls, 2);
    assert_eq!(fake.collect_calls, 1);
    assert_eq!(fake.publish_calls, 1);
    assert!(!latch.pending());
}

#[test]
fn dynamic_tick_retries_nonfatal_reload_then_clears_pending_on_success() {
    let mut latch = DaeModeReloadLatch::default();
    let mut fake = TickFake::default();
    fake.reload_results.push_back(Err("reload failed".into()));
    fake.reload_results.push_back(Ok(()));

    assert_eq!(
        tick(
            &mut latch,
            &mut fake,
            DaeModeTickSignals::new(true, true, false),
        ),
        DaeModeTickOutcome::RetryScheduled {
            reload_error: "reload failed".into(),
        }
    );
    assert!(latch.pending());
    assert_eq!(fake.retry_timer_calls, 1);
    assert_eq!(fake.collect_calls, 0);
    assert_eq!(fake.publish_calls, 0);

    assert_eq!(
        tick(
            &mut latch,
            &mut fake,
            DaeModeTickSignals::new(true, false, false),
        ),
        DaeModeTickOutcome::Reloaded
    );
    assert!(!latch.pending());
    assert_eq!(fake.reload_calls, 2);
    assert_eq!(fake.collect_calls, 0);

    assert_eq!(
        tick(
            &mut latch,
            &mut fake,
            DaeModeTickSignals::new(true, false, false),
        ),
        DaeModeTickOutcome::Collected
    );
    assert_eq!(fake.reload_calls, 2);
    assert_eq!(fake.collect_calls, 1);
    assert_eq!(fake.publish_calls, 1);
}

#[test]
fn dynamic_tick_distinguishes_fatal_reload_and_retry_timer_failure() {
    let mut fatal_latch = DaeModeReloadLatch::default();
    let mut fatal = TickFake {
        fatal: true,
        ..TickFake::default()
    };
    fatal.reload_results.push_back(Err("fatal reload".into()));
    assert_eq!(
        tick(
            &mut fatal_latch,
            &mut fatal,
            DaeModeTickSignals::new(true, true, false),
        ),
        DaeModeTickOutcome::FatalReload {
            reload_error: "fatal reload".into(),
        }
    );
    assert_eq!(fatal.retry_timer_calls, 0);
    assert_eq!(fatal.collect_calls, 0);

    let mut timer_latch = DaeModeReloadLatch::default();
    let mut timer = TickFake {
        retry_timer_error: Some("timer failed".into()),
        ..TickFake::default()
    };
    timer.reload_results.push_back(Err("reload failed".into()));
    assert_eq!(
        tick(
            &mut timer_latch,
            &mut timer,
            DaeModeTickSignals::new(true, true, false),
        ),
        DaeModeTickOutcome::RetryScheduleFailed {
            reload_error: "reload failed".into(),
            timer_error: "timer failed".into(),
        }
    );
    assert_eq!(timer.retry_timer_calls, 1);
    assert_eq!(timer.collect_calls, 0);
}
