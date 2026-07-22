use std::{
    env,
    io::{self, Read},
    os::fd::{AsRawFd, RawFd},
    os::unix::fs::PermissionsExt,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_OUTPUT_CAP: usize = 4_096;
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const DRAIN_READ_BUDGET: usize = 16;
const DRAIN_BYTE_BUDGET: usize = 64 * 1024;

pub fn command_available(program: &str) -> bool {
    if program.contains('/') {
        return is_executable(Path::new(program));
    }
    env::var_os("PATH")
        .as_deref()
        .and_then(|paths| {
            env::split_paths(paths).find(|directory| is_executable(&directory.join(program)))
        })
        .is_some()
}

fn is_executable(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOnlyCommand {
    Fw4,
    Qosify,
    TcFilterHelp,
    TcQdiscHelp,
    TcQdiscShow,
    TcFilterShow,
    NftListFlowtables,
    NftDaeDnsUdp53,
    IpRuleShow,
    IpRouteShow,
    UbusNetworkLanStatus,
    UbusServiceDae,
    UbusServiceDaed,
}

impl ReadOnlyCommand {
    pub const fn program(self) -> &'static str {
        match self {
            Self::Fw4 => "fw4",
            Self::Qosify => "qosify",
            Self::TcFilterHelp | Self::TcQdiscHelp | Self::TcQdiscShow | Self::TcFilterShow => "tc",
            Self::NftListFlowtables | Self::NftDaeDnsUdp53 => "nft",
            Self::IpRuleShow | Self::IpRouteShow => "ip",
            Self::UbusNetworkLanStatus | Self::UbusServiceDae | Self::UbusServiceDaed => "ubus",
        }
    }

    pub fn fixed_args(self) -> &'static [&'static str] {
        match self {
            Self::Fw4 | Self::Qosify => &[],
            Self::TcFilterHelp => &["filter", "help"],
            Self::TcFilterShow => &["filter", "show"],
            Self::TcQdiscHelp => &["qdisc", "help"],
            Self::TcQdiscShow => &["qdisc", "show"],
            Self::NftListFlowtables => &["list", "flowtables"],
            Self::NftDaeDnsUdp53 => &["list", "ruleset"],
            Self::IpRuleShow => &["rule", "show"],
            Self::UbusNetworkLanStatus => &["call", "network.interface.lan", "status"],
            Self::UbusServiceDae => &["call", "service", "list", "{\"name\":\"dae\"}"],
            Self::UbusServiceDaed => &["call", "service", "list", "{\"name\":\"daed\"}"],
            Self::IpRouteShow => &[],
        }
    }

    pub const fn output_cap(self) -> usize {
        match self {
            Self::NftDaeDnsUdp53 => 128 * 1024,
            _ => DEFAULT_OUTPUT_CAP,
        }
    }

    pub const fn nonzero_exit_is_absence(self) -> bool {
        matches!(self, Self::TcFilterShow | Self::IpRouteShow)
    }

    pub fn evidence_key(self, args: &[&str]) -> String {
        match self {
            Self::Fw4 => "fw4".into(),
            Self::Qosify => "qosify".into(),
            Self::TcFilterHelp => "tc_filter_help".into(),
            Self::TcQdiscHelp => "tc_qdisc_help".into(),
            Self::TcQdiscShow if args.len() == 2 => {
                format!("tc_qdisc_show_{}", snake_component(args[1]))
            }
            Self::TcQdiscShow => "tc_qdisc_show".into(),
            Self::TcFilterShow if args.len() == 3 => {
                format!(
                    "tc_filter_show_{}_{}",
                    snake_component(args[1]),
                    snake_component(args[2])
                )
            }
            Self::TcFilterShow => "tc_filter_show".into(),
            Self::NftListFlowtables => "nft_list_flowtables".into(),
            Self::NftDaeDnsUdp53 => "nft_dae_dns_udp53".into(),
            Self::IpRuleShow => "ip_rule_show".into(),
            Self::IpRouteShow => "ip_route_table_2023".into(),
            Self::UbusNetworkLanStatus => "ubus_network_lan_status".into(),
            Self::UbusServiceDae => "ubus_service_dae".into(),
            Self::UbusServiceDaed => "ubus_service_daed".into(),
        }
    }
}

fn snake_component(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                byte.to_ascii_lowercase() as char
            } else {
                '_'
            }
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResult {
    pub source: String,
    pub program: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub output_truncated: bool,
}

pub fn run_read_only(
    command: ReadOnlyCommand,
    dynamic_args: &[&str],
    timeout: Duration,
    output_cap: usize,
) -> io::Result<CommandResult> {
    let mut args = command
        .fixed_args()
        .iter()
        .copied()
        .chain(dynamic_args.iter().copied())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    validate_read_only_args(command, dynamic_args)?;
    let program = command.program();
    let child = Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()?;
    let mut child = ChildGuard::new(child);
    let mut stdout = child
        .child_mut()?
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("probe stdout pipe missing"))?;
    let mut stderr = child
        .child_mut()?
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("probe stderr pipe missing"))?;
    set_nonblocking(stdout.as_raw_fd())?;
    set_nonblocking(stderr.as_raw_fd())?;
    let mut stdout_capture = PipeCapture::new(output_cap);
    let mut stderr_capture = PipeCapture::new(output_cap);
    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut timed_out = false;
    let mut output_deadline = None;
    loop {
        stdout_capture.drain(&mut stdout)?;
        stderr_capture.drain(&mut stderr)?;

        let now = Instant::now();
        if status.is_none() {
            if let Some(observed_status) = try_wait(child.child_mut()?)? {
                status = Some(child.finish(observed_status)?);
                output_deadline = Some(now + OUTPUT_DRAIN_TIMEOUT);
            } else if now >= deadline {
                status = Some(child.terminate()?);
                timed_out = true;
                output_deadline = Some(now + OUTPUT_DRAIN_TIMEOUT);
            }
        }

        if stdout_capture.done && stderr_capture.done {
            if status.is_some() {
                break;
            }
        }
        if output_deadline.is_some_and(|drain_deadline| Instant::now() >= drain_deadline) {
            stdout_capture.finish_at_deadline();
            stderr_capture.finish_at_deadline();
            break;
        }

        let wake_deadline = output_deadline.unwrap_or(deadline);
        poll_pipes(
            &stdout_capture,
            stdout.as_raw_fd(),
            &stderr_capture,
            stderr.as_raw_fd(),
            wake_deadline,
        )?;
    }
    let status = status.ok_or_else(|| io::Error::other("probe command status missing"))?;
    let (stdout, stdout_truncated) = stdout_capture.finish();
    let (stderr, stderr_truncated) = stderr_capture.finish();
    let source = format!("command:{}", source_key(command, dynamic_args));
    Ok(CommandResult {
        source,
        program: program.into(),
        args: std::mem::take(&mut args),
        exit_code: exit_code(status),
        stdout,
        stderr,
        timed_out,
        output_truncated: stdout_truncated || stderr_truncated,
    })
}

struct ChildGuard {
    child: Option<Child>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestFailure {
    SecondSetNonblocking,
    Drain,
    Poll,
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct TestFailureState {
    failure: TestFailure,
    set_nonblocking_calls: usize,
}

#[cfg(test)]
thread_local! {
    static TEST_FAILURE: std::cell::Cell<Option<TestFailureState>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn with_test_failure<T>(failure: TestFailure, operation: impl FnOnce() -> T) -> T {
    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_FAILURE.set(None);
        }
    }

    TEST_FAILURE.set(Some(TestFailureState {
        failure,
        set_nonblocking_calls: 0,
    }));
    let _reset = Reset;
    operation()
}

#[cfg(test)]
fn inject_test_failure(site: TestFailure) -> io::Result<()> {
    let should_fail = TEST_FAILURE.with(|configured| {
        let Some(mut state) = configured.get() else {
            return false;
        };
        let should_fail = match (state.failure, site) {
            (TestFailure::SecondSetNonblocking, TestFailure::SecondSetNonblocking) => {
                state.set_nonblocking_calls += 1;
                state.set_nonblocking_calls == 2
            }
            (expected, observed) => expected == observed,
        };
        configured.set(Some(state));
        should_fail
    });
    if should_fail {
        std::thread::sleep(Duration::from_millis(50));
        Err(io::Error::other(format!("injected {site:?} failure")))
    } else {
        Ok(())
    }
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> io::Result<&mut Child> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "child guard is disarmed"))
    }

    fn finish(&mut self, observed_status: ExitStatus) -> io::Result<ExitStatus> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "child guard is disarmed"))?;
        finish_child(&mut child, observed_status)
    }

    fn terminate(&mut self) -> io::Result<ExitStatus> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "child guard is disarmed"))?;
        terminate_child(&mut child)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = kill_process_group(child.id());
        let _ = child.kill();
        loop {
            match child.wait() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                _ => break,
            }
        }
    }
}

#[doc(hidden)]
pub fn validate_read_only_args(command: ReadOnlyCommand, args: &[&str]) -> io::Result<()> {
    let valid = match command {
        ReadOnlyCommand::TcFilterShow => {
            args.len() == 3
                && args[0] == "dev"
                && !args[1].is_empty()
                && args[1]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.@".contains(&byte))
                && matches!(args[2], "ingress" | "egress")
        }
        ReadOnlyCommand::TcQdiscShow => {
            args.len() == 2
                && args[0] == "dev"
                && !args[1].is_empty()
                && args[1]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.@".contains(&byte))
        }
        ReadOnlyCommand::IpRouteShow => {
            args.len() == 3
                && args[0] == "show"
                && args[1] == "table"
                && args[2].bytes().all(|byte| byte.is_ascii_digit())
        }
        ReadOnlyCommand::UbusNetworkLanStatus
        | ReadOnlyCommand::UbusServiceDae
        | ReadOnlyCommand::UbusServiceDaed => args.is_empty(),
        _ => args.is_empty(),
    };
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid arguments for read-only probe command",
        ))
    }
}

fn finish_child(child: &mut Child, observed_status: ExitStatus) -> io::Result<ExitStatus> {
    let kill_result = kill_process_group(child.id());
    let wait_result = child.wait();
    kill_result?;
    match wait_result {
        Ok(status) => Ok(status),
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ok(observed_status),
        Err(error) => Err(error),
    }
}

fn terminate_child(child: &mut Child) -> io::Result<ExitStatus> {
    let kill_result = kill_process_group(child.id());
    let child_kill_result = if kill_result.is_err() {
        child.kill()
    } else {
        Ok(())
    };
    let wait_result = child.wait();
    kill_result?;
    child_kill_result?;
    wait_result
}

fn kill_process_group(leader: u32) -> io::Result<()> {
    let leader = i32::try_from(leader)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process id exceeds i32"))?;
    let group = leader
        .checked_neg()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process group id"))?;
    let result = unsafe { libc::kill(group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

fn try_wait(child: &mut Child) -> io::Result<Option<ExitStatus>> {
    loop {
        match child.try_wait() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    #[cfg(test)]
    inject_test_failure(TestFailure::SecondSetNonblocking)?;
    let flags = loop {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 {
            break flags;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    loop {
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

struct PipeCapture {
    kept: Vec<u8>,
    cap: usize,
    truncated: bool,
    done: bool,
}

impl PipeCapture {
    fn new(cap: usize) -> Self {
        Self {
            kept: Vec::with_capacity(cap.min(4_096)),
            cap,
            truncated: false,
            done: false,
        }
    }

    fn drain(&mut self, reader: &mut impl Read) -> io::Result<()> {
        #[cfg(test)]
        inject_test_failure(TestFailure::Drain)?;
        let mut buffer = [0u8; 4_096];
        let mut reads = 0;
        let mut bytes = 0;
        while !self.done && reads < DRAIN_READ_BUDGET && bytes < DRAIN_BYTE_BUDGET {
            let remaining_budget = DRAIN_BYTE_BUDGET - bytes;
            let read_len = remaining_budget.min(buffer.len());
            reads += 1;
            match reader.read(&mut buffer[..read_len]) {
                Ok(0) => self.done = true,
                Ok(count) => {
                    bytes += count;
                    let remaining = self.cap.saturating_sub(self.kept.len());
                    let take = count.min(remaining);
                    self.kept.extend_from_slice(&buffer[..take]);
                    self.truncated |= take != count;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn finish_at_deadline(&mut self) {
        self.truncated |= !self.done;
    }

    fn finish(self) -> (String, bool) {
        (
            String::from_utf8_lossy(&self.kept).into_owned(),
            self.truncated,
        )
    }
}

fn poll_pipes(
    stdout: &PipeCapture,
    stdout_fd: RawFd,
    stderr: &PipeCapture,
    stderr_fd: RawFd,
    deadline: Instant,
) -> io::Result<()> {
    let mut descriptors = [
        poll_descriptor(stdout_fd, stdout.done),
        poll_descriptor(stderr_fd, stderr.done),
    ];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        #[cfg(test)]
        inject_test_failure(TestFailure::Poll)?;
        let timeout = poll_timeout(remaining.min(Duration::from_millis(10)));
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout,
            )
        };
        if result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn poll_descriptor(fd: RawFd, done: bool) -> libc::pollfd {
    libc::pollfd {
        fd: if done { -1 } else { fd },
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    }
}

fn poll_timeout(duration: Duration) -> i32 {
    if duration.is_zero() {
        return 0;
    }
    duration.as_millis().clamp(1, i32::MAX as u128) as i32
}

fn exit_code(status: ExitStatus) -> Option<i32> {
    status.code()
}

fn source_key(command: ReadOnlyCommand, args: &[&str]) -> String {
    command.evidence_key(args)
}

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
