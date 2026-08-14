#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        ffi::OsString,
        fs,
        io::ErrorKind,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::{Mutex, OnceLock},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    static PATH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static SIGNAL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_path() -> std::sync::MutexGuard<'static, ()> {
        PATH_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct TestCommand {
        directory: PathBuf,
        original_path: Option<OsString>,
    }

    impl TestCommand {
        fn install(script: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before Unix epoch")
                .as_nanos();
            let directory = env::temp_dir().join(format!(
                "lanspeedd-command-test-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("create command test directory");
            let path = directory.join("tc");
            fs::write(&path, script).expect("write command test script");
            let mut permissions = fs::metadata(&path).expect("stat test script").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("make test script executable");
            let original_path = env::var_os("PATH");
            // SAFETY: command-runner tests serialize all PATH changes with PATH_LOCK.
            unsafe { env::set_var("PATH", &directory) };
            Self {
                directory,
                original_path,
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.directory.join(name)
        }
    }

    impl Drop for TestCommand {
        fn drop(&mut self) {
            if let Some(path) = self.original_path.take() {
                // SAFETY: command-runner tests serialize all PATH changes with PATH_LOCK.
                unsafe { env::set_var("PATH", path) };
            } else {
                // SAFETY: command-runner tests serialize all PATH changes with PATH_LOCK.
                unsafe { env::remove_var("PATH") };
            }
            fs::remove_dir_all(&self.directory).expect("remove command test directory");
        }
    }

    #[test]
    fn parent_exit_kills_pipe_holding_descendant_without_blocking() {
        let _lock = lock_path();
        let command = TestCommand::install(
            "#!/bin/sh\n/bin/sleep 3 &\nprintf '%s %s\\n' \"$$\" \"$!\" > child-pids\nprintf 'parent exited\\n'\n",
        );
        let original_directory = env::current_dir().expect("read current directory");
        env::set_current_dir(&command.directory).expect("enter command test directory");

        let started = Instant::now();
        let result = run_read_only(
            ReadOnlyCommand::TcFilterHelp,
            &[],
            Duration::from_secs(1),
            DEFAULT_OUTPUT_CAP,
        )
        .expect("run test command");
        let elapsed = started.elapsed();
        env::set_current_dir(original_directory).expect("restore current directory");

        assert!(!result.timed_out);
        assert_eq!(result.stdout, "parent exited\n");
        assert!(
            elapsed < Duration::from_secs(1),
            "pipe-holding descendant delayed return by {elapsed:?}"
        );
        let (group, descendant) = read_pids(&command.path("child-pids"));
        assert_process_gone(descendant);
        assert_process_group_gone(group);
    }

    #[test]
    fn timeout_kills_process_group_and_returns_before_descendant_closes_pipes() {
        let _lock = lock_path();
        let command = TestCommand::install(
            "#!/bin/sh\n/bin/sleep 3 &\nprintf '%s %s\\n' \"$$\" \"$!\" > child-pids\nwait\n",
        );
        let original_directory = env::current_dir().expect("read current directory");
        env::set_current_dir(&command.directory).expect("enter command test directory");

        let started = Instant::now();
        let result = run_read_only(
            ReadOnlyCommand::TcFilterHelp,
            &[],
            Duration::from_millis(50),
            DEFAULT_OUTPUT_CAP,
        )
        .expect("run test command");
        let elapsed = started.elapsed();
        env::set_current_dir(original_directory).expect("restore current directory");

        assert!(result.timed_out);
        assert!(
            elapsed < Duration::from_secs(1),
            "timed-out command delayed return by {elapsed:?}"
        );
        let (group, descendant) = read_pids(&command.path("child-pids"));
        assert_process_gone(descendant);
        assert_process_group_gone(group);
    }

    #[test]
    fn stdout_and_stderr_are_collected_with_independent_hard_caps() {
        let _lock = lock_path();
        let _command = TestCommand::install(
            "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 200 ]; do\n  printf x\n  printf y >&2\n  i=$((i + 1))\ndone\n",
        );

        let result = run_read_only(
            ReadOnlyCommand::TcFilterHelp,
            &[],
            Duration::from_secs(1),
            64,
        )
        .expect("run test command");

        assert_eq!(result.stdout.len(), 64);
        assert_eq!(result.stderr.len(), 64);
        assert!(result.output_truncated);
    }

    #[test]
    fn pipe_capture_limits_each_drain_to_sixteen_reads_and_sixty_four_kibibytes() {
        struct BusyReader {
            reads: Cell<usize>,
        }

        impl Read for BusyReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let reads = self.reads.get();
                self.reads.set(reads + 1);
                if reads == 17 {
                    return Err(io::Error::from(ErrorKind::WouldBlock));
                }
                buffer.fill(b'x');
                Ok(buffer.len())
            }
        }

        let mut reader = BusyReader {
            reads: Cell::new(0),
        };
        let mut capture = PipeCapture::new(128 * 1024);

        capture.drain(&mut reader).expect("drain busy reader");

        assert_eq!(reader.reads.get(), 16);
        assert_eq!(capture.kept.len(), 64 * 1024);
        assert!(!capture.done);
    }

    #[test]
    fn continuously_writable_command_still_observes_timeout() {
        let _lock = lock_path();
        let _command = TestCommand::install("#!/bin/sh\nexec /usr/bin/yes x\n");

        let started = Instant::now();
        let result = run_read_only(
            ReadOnlyCommand::TcFilterHelp,
            &[],
            DEFAULT_TIMEOUT,
            DEFAULT_OUTPUT_CAP,
        )
        .expect("run continuously writable command");
        let elapsed = started.elapsed();

        assert!(result.timed_out);
        assert!(result.output_truncated);
        assert!(
            elapsed >= Duration::from_millis(1_800),
            "continuously writable command timed out too early after {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "continuously writable command delayed timeout by {elapsed:?}"
        );
    }

    #[test]
    fn interrupted_poll_does_not_extend_absolute_deadline() {
        unsafe extern "C" fn handle_signal(_: libc::c_int) {}

        let _path_lock = lock_path();
        let _signal_lock = SIGNAL_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let mut old_action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = handle_signal as *const () as usize;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGUSR1, &action, &mut old_action), 0);
        }

        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let target = unsafe { libc::pthread_self() } as usize;
        let sender = thread::spawn(move || {
            let stop = Instant::now() + Duration::from_millis(200);
            while Instant::now() < stop {
                unsafe { libc::pthread_kill(target as libc::pthread_t, libc::SIGUSR1) };
                thread::sleep(Duration::from_millis(1));
            }
        });

        let capture = PipeCapture::new(1);
        let started = Instant::now();
        poll_pipes(
            &capture,
            pipe_fds[0],
            &capture,
            pipe_fds[0],
            started + Duration::from_millis(40),
        )
        .expect("poll interrupted pipe");
        let elapsed = started.elapsed();

        sender.join().expect("join signal sender");
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
            assert_eq!(
                libc::sigaction(libc::SIGUSR1, &old_action, std::ptr::null_mut()),
                0
            );
        }
        assert!(
            elapsed < Duration::from_millis(100),
            "EINTR extended poll deadline to {elapsed:?}"
        );
    }

    #[test]
    fn dropping_child_guard_kills_and_reaps_process_group() {
        let child = Command::new("/bin/sleep")
            .arg("3")
            .process_group(0)
            .spawn()
            .expect("spawn guarded child");
        let pid = child.id() as i32;

        drop(ChildGuard::new(child));

        assert_process_gone(pid);
        assert_process_group_gone(pid);
    }

    #[test]
    fn disarmed_child_guard_misuse_returns_errors_without_panicking() {
        let mut guard = ChildGuard { child: None };
        assert_eq!(
            guard.child_mut().unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        let status = Command::new("/bin/true").status().expect("true status");
        assert_eq!(
            guard.finish(status).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            guard.terminate().unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn expired_poll_deadline_returns_before_poll_or_failure_injection() {
        let capture = PipeCapture::new(1);
        with_test_failure(TestFailure::Poll, || {
            poll_pipes(
                &capture,
                -1,
                &capture,
                -1,
                Instant::now() - Duration::from_millis(1),
            )
        })
        .expect("expired poll deadline");
    }

    #[test]
    fn second_pipe_nonblocking_failure_reaps_spawned_process_group() {
        assert_runner_failure_reaps_process_group(TestFailure::SecondSetNonblocking);
    }

    #[test]
    fn drain_failure_reaps_spawned_process_group() {
        assert_runner_failure_reaps_process_group(TestFailure::Drain);
    }

    #[test]
    fn poll_failure_reaps_spawned_process_group() {
        assert_runner_failure_reaps_process_group(TestFailure::Poll);
    }

    #[test]
    fn pipe_holding_setsid_escape_does_not_leave_reader_threads() {
        let _lock = lock_path();
        let command = TestCommand::install(
            "#!/bin/sh\n/usr/bin/setsid /bin/sleep 3 &\nprintf '%s\\n' \"$!\" > escaped-pid\nprintf 'parent exited\\n'\n",
        );
        let original_directory = env::current_dir().expect("read current directory");
        env::set_current_dir(&command.directory).expect("enter command test directory");
        let thread_count_before = process_thread_count();

        let started = Instant::now();
        let result = run_read_only(
            ReadOnlyCommand::TcFilterHelp,
            &[],
            Duration::from_secs(1),
            DEFAULT_OUTPUT_CAP,
        )
        .expect("run test command");
        let elapsed = started.elapsed();
        let thread_count_after = process_thread_count();
        env::set_current_dir(original_directory).expect("restore current directory");

        let escaped = fs::read_to_string(command.path("escaped-pid"))
            .expect("read escaped pid")
            .trim()
            .parse::<i32>()
            .expect("escaped pid should be numeric");
        unsafe { libc::kill(escaped, libc::SIGKILL) };

        assert!(!result.timed_out);
        assert_eq!(result.stdout, "parent exited\n");
        assert!(
            elapsed < Duration::from_millis(500),
            "escaped pipe holder delayed return by {elapsed:?}"
        );
        assert!(
            thread_count_after <= thread_count_before,
            "reader threads remained after returning: before={thread_count_before}, after={thread_count_after}"
        );
    }

    #[test]
    fn repeated_commands_do_not_increase_thread_count() {
        let _lock = lock_path();
        let _command = TestCommand::install("#!/bin/sh\nprintf 'ok\\n'\n");
        let thread_count_before = process_thread_count();

        for _ in 0..100 {
            let result = run_read_only(
                ReadOnlyCommand::TcFilterHelp,
                &[],
                Duration::from_secs(1),
                DEFAULT_OUTPUT_CAP,
            )
            .expect("run test command");
            assert_eq!(result.stdout, "ok\n");
        }

        let thread_count_after = process_thread_count();
        assert!(
            thread_count_after <= thread_count_before,
            "repeated commands increased thread count: before={thread_count_before}, after={thread_count_after}"
        );
    }

    fn process_thread_count() -> usize {
        fs::read_dir("/proc/self/task")
            .expect("read process thread directory")
            .count()
    }

    fn assert_runner_failure_reaps_process_group(failure: TestFailure) {
        let _lock = lock_path();
        let command = TestCommand::install(
            "#!/bin/sh\n/bin/sleep 3 &\nprintf '%s %s\\n' \"$$\" \"$!\" > child-pids\nwait\n",
        );
        let original_directory = env::current_dir().expect("read current directory");
        env::set_current_dir(&command.directory).expect("enter command test directory");

        let result = with_test_failure(failure, || {
            run_read_only(
                ReadOnlyCommand::TcFilterHelp,
                &[],
                Duration::from_millis(100),
                DEFAULT_OUTPUT_CAP,
            )
        });
        env::set_current_dir(original_directory).expect("restore current directory");

        let error = result.expect_err("runner should return injected error");
        assert!(error.to_string().contains("injected"));
        let (group, descendant) = read_pids(&command.path("child-pids"));
        assert_process_gone(descendant);
        assert_process_group_gone(group);
    }

    fn read_pids(path: &Path) -> (i32, i32) {
        let contents = fs::read_to_string(path).expect("read child pid file");
        let mut pids = contents.split_whitespace().map(|pid| {
            pid.parse::<i32>()
                .expect("child pid file should contain numbers")
        });
        let group = pids.next().expect("missing process group leader");
        let descendant = pids.next().expect("missing descendant pid");
        (group, descendant)
    }

    fn assert_process_gone(pid: i32) {
        assert!(
            wait_until(Duration::from_millis(500), || !process_is_live(pid)),
            "descendant process {pid} is still live"
        );
    }

    fn assert_process_group_gone(group: i32) {
        assert!(
            wait_until(Duration::from_millis(500), || unsafe {
                libc::kill(-group, 0) == -1
                    && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            }),
            "process group {group} is still present"
        );
    }

    fn process_is_live(pid: i32) -> bool {
        let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
            return false;
        };
        !status.lines().any(|line| line.starts_with("State:\tZ"))
    }

    fn wait_until(timeout: Duration, condition: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        condition()
    }
}
