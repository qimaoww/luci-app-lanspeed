use std::{
    env,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_OUTPUT_CAP: usize = 4_096;

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
    NftListRuleset,
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
            Self::NftListFlowtables | Self::NftListRuleset => "nft",
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
            Self::NftListRuleset => &["list", "ruleset"],
            Self::IpRuleShow => &["rule", "show"],
            Self::UbusNetworkLanStatus => &["call", "network.interface.lan", "status"],
            Self::UbusServiceDae => &["call", "service", "list", "{\"name\":\"dae\"}"],
            Self::UbusServiceDaed => &["call", "service", "list", "{\"name\":\"daed\"}"],
            Self::TcFilterShow | Self::IpRouteShow | Self::Pidof => &[],
        }
    }

    pub const fn output_cap(self) -> usize {
        match self {
            Self::NftListRuleset => 128 * 1024,
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
            Self::NftListRuleset => "nft_list_ruleset".into(),
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
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("probe stdout pipe missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("probe stderr pipe missing"))?;
    let stdout_reader = thread::spawn(move || read_capped(stdout, output_cap));
    let stderr_reader = thread::spawn(move || read_capped(stderr, output_cap));
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (status, false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            break (child.wait()?, true);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let (stdout, stdout_truncated) = join_reader(stdout_reader)?;
    let (stderr, stderr_truncated) = join_reader(stderr_reader)?;
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

fn read_capped(mut reader: impl Read, cap: usize) -> io::Result<(String, bool)> {
    let mut kept = Vec::with_capacity(cap.min(4_096));
    let mut buffer = [0u8; 1_024];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = cap.saturating_sub(kept.len());
        let take = count.min(remaining);
        kept.extend_from_slice(&buffer[..take]);
        truncated |= take != count;
    }
    Ok((String::from_utf8_lossy(&kept).into_owned(), truncated))
}

fn join_reader(
    reader: thread::JoinHandle<io::Result<(String, bool)>>,
) -> io::Result<(String, bool)> {
    reader
        .join()
        .map_err(|_| io::Error::other("probe output reader panicked"))?
}

fn exit_code(status: ExitStatus) -> Option<i32> {
    status.code()
}

fn source_key(command: ReadOnlyCommand, args: &[&str]) -> String {
    command.evidence_key(args)
}
