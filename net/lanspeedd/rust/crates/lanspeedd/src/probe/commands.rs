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
    TcQdiscDump,
    TcClassDump,
    TcFilterDump,
    NftListFlowtables,
    NftDaeDnsUdp53,
    IpRuleShow,
    IpRouteShow,
    UbusNetworkLanStatus,
    UbusServiceOpenClash,
    UbusServiceDae,
    UbusServiceDaed,
}

impl ReadOnlyCommand {
    pub const fn program(self) -> &'static str {
        match self {
            Self::Fw4 => "fw4",
            Self::Qosify => "qosify",
            Self::TcFilterHelp
            | Self::TcQdiscHelp
            | Self::TcQdiscShow
            | Self::TcFilterShow
            | Self::TcQdiscDump
            | Self::TcClassDump
            | Self::TcFilterDump => "tc",
            Self::NftListFlowtables | Self::NftDaeDnsUdp53 => "nft",
            Self::IpRuleShow | Self::IpRouteShow => "ip",
            Self::UbusNetworkLanStatus
            | Self::UbusServiceOpenClash
            | Self::UbusServiceDae
            | Self::UbusServiceDaed => "ubus",
        }
    }

    pub fn fixed_args(self) -> &'static [&'static str] {
        match self {
            Self::Fw4 | Self::Qosify => &[],
            Self::TcFilterHelp => &["filter", "help"],
            Self::TcFilterShow => &["-j", "-d", "filter", "show"],
            Self::TcQdiscHelp => &["qdisc", "help"],
            Self::TcQdiscShow => &["-j", "qdisc", "show"],
            Self::TcQdiscDump => &["-j", "-s", "-d", "qdisc", "show"],
            Self::TcClassDump => &["-j", "-s", "-d", "class", "show"],
            Self::TcFilterDump => &["-j", "-s", "-d", "filter", "show"],
            Self::NftListFlowtables => &["list", "flowtables"],
            Self::NftDaeDnsUdp53 => &["list", "ruleset"],
            Self::IpRuleShow => &["rule", "show"],
            Self::UbusNetworkLanStatus => &["call", "network.interface.lan", "status"],
            Self::UbusServiceOpenClash => &["call", "service", "list", "{\"name\":\"openclash\"}"],
            Self::UbusServiceDae => &["call", "service", "list", "{\"name\":\"dae\"}"],
            Self::UbusServiceDaed => &["call", "service", "list", "{\"name\":\"daed\"}"],
            Self::IpRouteShow => &[],
        }
    }

    pub const fn output_cap(self) -> usize {
        match self {
            Self::NftDaeDnsUdp53 => 128 * 1024,
            Self::TcFilterShow => 64 * 1024,
            Self::TcQdiscShow => 16 * 1024,
            Self::TcQdiscDump | Self::TcClassDump => 256 * 1024,
            Self::TcFilterDump => 512 * 1024,
            _ => DEFAULT_OUTPUT_CAP,
        }
    }

    pub fn recognized_capability_help(self, stdout: &str, stderr: &str) -> bool {
        let output = format!("{stdout}\n{stderr}").to_ascii_lowercase();
        match self {
            Self::TcFilterHelp => output.contains("bpf"),
            Self::TcQdiscHelp => output.contains("clsact"),
            _ => false,
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
            Self::TcQdiscDump => "tc_qdisc_dump".into(),
            Self::TcClassDump => "tc_class_dump".into(),
            Self::TcFilterDump => "tc_filter_dump".into(),
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
            Self::UbusServiceOpenClash => "ubus_service_openclash".into(),
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
        | ReadOnlyCommand::UbusServiceOpenClash
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
include!("commands_tests.rs");
