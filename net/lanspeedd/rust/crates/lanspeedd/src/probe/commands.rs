use std::{
    env,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_OUTPUT_CAP: usize = 4_096;
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

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
    TcFilterShow,
    NftListFlowtables,
    NftDaeDnsUdp53,
    IpRuleShow,
    IpRouteShow,
    UbusNetworkLanStatus,
    UbusServiceDae,
    UbusServiceDaed,
    Pidof,
}

impl ReadOnlyCommand {
    pub const fn program(self) -> &'static str {
        match self {
            Self::Fw4 => "fw4",
            Self::Qosify => "qosify",
            Self::TcFilterHelp | Self::TcQdiscHelp | Self::TcFilterShow => "tc",
            Self::NftListFlowtables | Self::NftDaeDnsUdp53 => "nft",
            Self::IpRuleShow | Self::IpRouteShow => "ip",
            Self::UbusNetworkLanStatus | Self::UbusServiceDae | Self::UbusServiceDaed => "ubus",
            Self::Pidof => "pidof",
        }
    }

    pub fn fixed_args(self) -> &'static [&'static str] {
        match self {
            Self::Fw4 | Self::Qosify => &[],
            Self::TcFilterHelp => &["filter", "help"],
            Self::TcQdiscHelp => &["qdisc", "help"],
            Self::NftListFlowtables => &["list", "flowtables"],
            Self::NftDaeDnsUdp53 => &["list", "ruleset"],
            Self::IpRuleShow => &["rule", "show"],
            Self::UbusNetworkLanStatus => &["call", "network.interface.lan", "status"],
            Self::UbusServiceDae => &["call", "service", "list", "{\"name\":\"dae\"}"],
            Self::UbusServiceDaed => &["call", "service", "list", "{\"name\":\"daed\"}"],
            Self::TcFilterShow | Self::IpRouteShow | Self::Pidof => &[],
        }
    }

    pub const fn output_cap(self) -> usize {
        match self {
            Self::NftDaeDnsUdp53 => 128 * 1024,
            _ => DEFAULT_OUTPUT_CAP,
        }
    }

    pub fn evidence_key(self, args: &[&str]) -> String {
        match self {
            Self::Fw4 => "fw4".into(),
            Self::Qosify => "qosify".into(),
            Self::TcFilterHelp => "tc_filter_help".into(),
            Self::TcQdiscHelp => "tc_qdisc_help".into(),
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
            Self::Pidof if args.first() == Some(&"dae") => "pidof_dae".into(),
            Self::Pidof if args.first() == Some(&"daed") => "pidof_daed".into(),
            Self::Pidof => "pidof".into(),
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
    let mut child = Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("probe stdout pipe missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("probe stderr pipe missing"))?;
    let stdout_reader = CappedReader::spawn(stdout, output_cap);
    let stderr_reader = CappedReader::spawn(stderr, output_cap);
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (finish_child(&mut child, status)?, false);
        }
        if Instant::now() >= deadline {
            break (terminate_child(&mut child)?, true);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output_deadline = Instant::now() + OUTPUT_DRAIN_TIMEOUT;
    let (stdout, stdout_truncated) = stdout_reader.collect(output_deadline)?;
    let (stderr, stderr_truncated) = stderr_reader.collect(output_deadline)?;
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
        ReadOnlyCommand::IpRouteShow => {
            args.len() == 3
                && args[0] == "show"
                && args[1] == "table"
                && args[2].bytes().all(|byte| byte.is_ascii_digit())
        }
        ReadOnlyCommand::UbusNetworkLanStatus
        | ReadOnlyCommand::UbusServiceDae
        | ReadOnlyCommand::UbusServiceDaed => args.is_empty(),
        ReadOnlyCommand::Pidof => args.len() == 1 && matches!(args[0], "dae" | "daed"),
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
    let result = unsafe { libc::kill(-(leader as i32), libc::SIGKILL) };
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

struct CappedReader {
    state: Arc<(Mutex<ReaderState>, Condvar)>,
}

struct ReaderState {
    kept: Vec<u8>,
    truncated: bool,
    done: bool,
    error: Option<io::Error>,
}

impl CappedReader {
    fn spawn(mut reader: impl Read + Send + 'static, cap: usize) -> Self {
        let state = Arc::new((
            Mutex::new(ReaderState {
                kept: Vec::with_capacity(cap.min(4_096)),
                truncated: false,
                done: false,
                error: None,
            }),
            Condvar::new(),
        ));
        let thread_state = Arc::clone(&state);
        thread::spawn(move || {
            let mut buffer = [0u8; 1_024];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        let (lock, changed) = &*thread_state;
                        lock.lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .done = true;
                        changed.notify_all();
                        break;
                    }
                    Ok(count) => {
                        let (lock, _) = &*thread_state;
                        let mut state =
                            lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        let remaining = cap.saturating_sub(state.kept.len());
                        let take = count.min(remaining);
                        state.kept.extend_from_slice(&buffer[..take]);
                        state.truncated |= take != count;
                    }
                    Err(error) => {
                        let (lock, changed) = &*thread_state;
                        let mut state =
                            lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        state.error = Some(error);
                        state.done = true;
                        changed.notify_all();
                        break;
                    }
                }
            }
        });
        Self { state }
    }

    fn collect(self, deadline: Instant) -> io::Result<(String, bool)> {
        let (lock, changed) = &*self.state;
        let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !state.done {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(now);
            state = changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
        if let Some(error) = state.error.take() {
            return Err(error);
        }
        let truncated = state.truncated || !state.done;
        Ok((String::from_utf8_lossy(&state.kept).into_owned(), truncated))
    }
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
        ffi::OsString,
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    static PATH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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
        let _lock = PATH_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
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
        let _lock = PATH_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
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
        let _lock = PATH_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
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
