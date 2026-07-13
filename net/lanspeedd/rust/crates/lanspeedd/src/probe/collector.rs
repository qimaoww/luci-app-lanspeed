use super::{
    assess, commands::CommandResult, files::BoundedFile, CollectedEvidence, CommandEvidence,
    FileEvidence, ProbeObservations, ProbeReport, RuntimeHealth, UbusEvidence, UciEvidence,
};
use super::{commands::ReadOnlyCommand, tc};
use crate::config::RuntimeConfig;
use std::{io, path::Path};

const FILE_CAP: usize = 4_096;
const ECM_CONNECTION_COUNT_PATH: &str = "/sys/kernel/debug/ecm/ecm_db/connection_count";
const ECM_CONNECTION_COUNT_SIMPLE_PATH: &str =
    "/sys/kernel/debug/ecm/ecm_db/connection_count_simple";
const ECM_HOST_COUNT_PATH: &str = "/sys/kernel/debug/ecm/ecm_db/host_count";
const ECM_MAPPING_COUNT_PATH: &str = "/sys/kernel/debug/ecm/ecm_db/mapping_count";
pub const PROBE_REFRESH_INTERVAL_MS: u64 = 30_000;
const PACKAGES: [&str; 9] = [
    "firewall",
    "sqm",
    "qosify",
    "openclash",
    "dae",
    "daed",
    "homeproxy",
    "nlbwmon",
    "dhcp",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeMethod {
    Status,
    Health,
    Reload,
}
impl ProbeMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Health => "health",
            Self::Reload => "reload",
        }
    }
}

pub const fn probe_due(now_ms: u64, deadline_ms: u64, method: ProbeMethod) -> bool {
    match method {
        ProbeMethod::Reload => true,
        ProbeMethod::Status | ProbeMethod::Health => now_ms >= deadline_ms,
    }
}

pub const fn probe_deadline(now_ms: u64) -> u64 {
    now_ms.saturating_add(PROBE_REFRESH_INTERVAL_MS)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UciOptionSnapshot {
    pub name: String,
    pub values: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UciSectionSnapshot {
    pub name: String,
    pub kind: String,
    pub options: Vec<UciOptionSnapshot>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UciPackageSnapshot {
    pub name: String,
    pub sections: Vec<UciSectionSnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UbusQuery {
    NetworkLanStatus,
    ServiceDae,
    ServiceDaed,
}
impl UbusQuery {
    pub const fn object(self) -> &'static str {
        match self {
            Self::NetworkLanStatus => "network.interface.lan",
            Self::ServiceDae => "service.dae",
            Self::ServiceDaed => "service.daed",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UbusProbeResult {
    pub query: UbusQuery,
    pub exit_code: i32,
    pub summary: String,
    pub output: String,
    pub truncated: bool,
}

pub trait CommandRunner {
    type Error: ToString;
    fn available(&mut self, command: ReadOnlyCommand) -> Result<bool, Self::Error>;
    fn run(
        &mut self,
        command: ReadOnlyCommand,
        args: &[&str],
    ) -> Result<CommandResult, Self::Error>;
}
pub trait FileSource {
    type Error: ToString;
    fn read(&mut self, path: &str, cap: usize) -> Result<BoundedFile, Self::Error>;
    fn exists(&mut self, path: &str) -> Result<FilePresence, Self::Error>;
    fn dir_has_entries(&mut self, path: &str) -> Result<bool, Self::Error>;
    fn probe_nss_state(&mut self) -> Result<NssStateProbe, Self::Error> {
        Ok(NssStateProbe::default())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilePresence {
    Present,
    Absent,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NssStateProbe {
    pub present: bool,
    pub readable: bool,
    pub errno: i32,
    pub state_major: u32,
    pub source_path: Option<String>,
}
pub trait UciSource {
    type Error: ToString;
    fn load(&mut self, package: &'static str) -> Result<Option<UciPackageSnapshot>, Self::Error>;
}
pub trait UbusSource {
    type Error: ToString;
    fn query(&mut self, query: UbusQuery) -> Result<UbusProbeResult, Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCommandRunner;
impl CommandRunner for SystemCommandRunner {
    type Error = io::Error;
    fn available(&mut self, command: ReadOnlyCommand) -> Result<bool, Self::Error> {
        Ok(super::commands::command_available(command.program()))
    }
    fn run(
        &mut self,
        command: ReadOnlyCommand,
        args: &[&str],
    ) -> Result<CommandResult, Self::Error> {
        super::commands::run_read_only(
            command,
            args,
            super::commands::DEFAULT_TIMEOUT,
            command.output_cap(),
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemFileSource;
impl FileSource for SystemFileSource {
    type Error = String;
    fn read(&mut self, path: &str, cap: usize) -> Result<BoundedFile, Self::Error> {
        super::files::read_bounded(Path::new(path), cap).map_err(|error| error.to_string())
    }
    fn exists(&mut self, path: &str) -> Result<FilePresence, Self::Error> {
        match std::fs::metadata(path) {
            Ok(_) => Ok(FilePresence::Present),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(FilePresence::Absent),
            Err(error) => Err(error.to_string()),
        }
    }
    fn dir_has_entries(&mut self, path: &str) -> Result<bool, Self::Error> {
        let mut entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.to_string()),
        };
        Ok(entries
            .next()
            .transpose()
            .map_err(|error| error.to_string())?
            .is_some())
    }
    fn probe_nss_state(&mut self) -> Result<NssStateProbe, Self::Error> {
        match crate::collectors::nss::open_ecm_state() {
            Ok(opened) => Ok(NssStateProbe {
                present: true,
                readable: true,
                errno: 0,
                state_major: opened.state_major,
                source_path: Some(opened.source_path),
            }),
            Err(error) => Ok(NssStateProbe {
                present: error.errno() != Some(libc::ENOENT),
                readable: false,
                errno: error.errno().unwrap_or(0),
                state_major: error.state_major,
                source_path: None,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemUbusSource;
impl UbusSource for SystemUbusSource {
    type Error = io::Error;
    fn query(&mut self, query: UbusQuery) -> Result<UbusProbeResult, Self::Error> {
        let command = match query {
            UbusQuery::NetworkLanStatus => ReadOnlyCommand::UbusNetworkLanStatus,
            UbusQuery::ServiceDae => ReadOnlyCommand::UbusServiceDae,
            UbusQuery::ServiceDaed => ReadOnlyCommand::UbusServiceDaed,
        };
        let result = super::commands::run_read_only(
            command,
            &[],
            super::commands::DEFAULT_TIMEOUT,
            super::commands::DEFAULT_OUTPUT_CAP,
        )?;
        let exit_code = result.exit_code.unwrap_or(-1);
        Ok(UbusProbeResult {
            query,
            exit_code,
            summary: if exit_code == 0 {
                "status available"
            } else {
                "status unavailable"
            }
            .into(),
            output: result.stdout,
            truncated: result.output_truncated || result.timed_out,
        })
    }
}

#[cfg(feature = "openwrt")]
pub struct SystemUciSource {
    context: lanspeed_openwrt_sys::UciContext,
}
#[cfg(feature = "openwrt")]
impl SystemUciSource {
    pub fn new() -> lanspeed_openwrt_sys::Result<Self> {
        Ok(Self {
            context: lanspeed_openwrt_sys::UciContext::new()?,
        })
    }
}
#[cfg(feature = "openwrt")]
impl UciSource for SystemUciSource {
    type Error = lanspeed_openwrt_sys::Error;
    fn load(&mut self, package: &'static str) -> Result<Option<UciPackageSnapshot>, Self::Error> {
        match self.context.load_package(package) {
            Ok(package) => Ok(Some(UciPackageSnapshot {
                name: package.name,
                sections: package
                    .sections
                    .into_iter()
                    .map(|section| UciSectionSnapshot {
                        name: section.name,
                        kind: section.kind,
                        options: section
                            .options
                            .into_iter()
                            .map(|option| UciOptionSnapshot {
                                name: option.name,
                                values: match option.value {
                                    lanspeed_openwrt_sys::UciValue::String(value) => vec![value],
                                    lanspeed_openwrt_sys::UciValue::List(values) => values,
                                },
                            })
                            .collect(),
                    })
                    .collect(),
            })),
            Err(lanspeed_openwrt_sys::Error::Platform {
                operation: "uci_load",
                code: 3,
            }) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(feature = "openwrt")]
pub type SystemProbeCollector =
    ProbeCollector<SystemCommandRunner, SystemFileSource, SystemUciSource, SystemUbusSource>;

#[cfg(feature = "openwrt")]
pub fn system_collector() -> lanspeed_openwrt_sys::Result<SystemProbeCollector> {
    Ok(ProbeCollector::new(
        SystemCommandRunner,
        SystemFileSource,
        SystemUciSource::new()?,
        SystemUbusSource,
    ))
}

pub struct ProbeCollector<C, F, U, B> {
    commands: C,
    files: F,
    uci: U,
    ubus: B,
}
impl<C, F, U, B> ProbeCollector<C, F, U, B>
where
    C: CommandRunner,
    F: FileSource,
    U: UciSource,
    B: UbusSource,
{
    pub fn new(commands: C, files: F, uci: U, ubus: B) -> Self {
        Self {
            commands,
            files,
            uci,
            ubus,
        }
    }
    pub fn into_parts(self) -> (C, F, U, B) {
        (self.commands, self.files, self.uci, self.ubus)
    }

    pub fn collect(
        &mut self,
        config: &RuntimeConfig,
        runtime: &RuntimeHealth,
        method: ProbeMethod,
    ) -> ProbeReport {
        let mut observations = ProbeObservations::default();
        let mut evidence = CollectedEvidence::default();

        observations.commands.tc = self.availability(
            ReadOnlyCommand::TcFilterHelp,
            "tc",
            &mut evidence,
            &mut observations.probe_error,
        );
        observations.commands.nft = self.availability(
            ReadOnlyCommand::NftListFlowtables,
            "nft",
            &mut evidence,
            &mut observations.probe_error,
        );
        observations.commands.ubus = self.availability(
            ReadOnlyCommand::UbusNetworkLanStatus,
            "ubus",
            &mut evidence,
            &mut observations.probe_error,
        );
        observations.commands.fw4 = self.availability(
            ReadOnlyCommand::Fw4,
            "fw4",
            &mut evidence,
            &mut observations.probe_error,
        );
        observations.commands.qosify = self.availability(
            ReadOnlyCommand::Qosify,
            "qosify",
            &mut evidence,
            &mut observations.probe_error,
        );

        if observations.commands.tc {
            if let Some(result) = self.command(
                ReadOnlyCommand::TcFilterHelp,
                &[],
                "tc filter help",
                &mut evidence,
                &mut observations.probe_error,
            ) {
                observations.commands.tc_filter_help_exit_code = result.exit_code.unwrap_or(-1);
                observations.tc.bpf = format!("{}\n{}", result.stdout, result.stderr)
                    .to_ascii_lowercase()
                    .contains("bpf");
            }
            if let Some(result) = self.command(
                ReadOnlyCommand::TcQdiscHelp,
                &[],
                "tc qdisc help",
                &mut evidence,
                &mut observations.probe_error,
            ) {
                observations.commands.tc_qdisc_help_exit_code = result.exit_code.unwrap_or(-1);
                observations.tc.clsact =
                    result.stdout.contains("clsact") || result.stderr.contains("clsact");
            }
            for ifname in config.ifnames.iter().chain(config.interface_include.iter()) {
                for direction in ["ingress", "egress"] {
                    let args = ["dev", ifname.as_str(), direction];
                    if let Some(result) = self.command(
                        ReadOnlyCommand::TcFilterShow,
                        &args,
                        &format!("tc filter show dev {ifname} {direction}"),
                        &mut evidence,
                        &mut observations.probe_error,
                    ) {
                        let filters = tc::parse_filter_lines(ifname, direction, &result.stdout);
                        observations.tc.existing_filters |= !filters.is_empty();
                        observations.tc.filters.extend(filters);
                    }
                }
            }
        }
        if observations.commands.nft {
            if let Some(result) = self.command(
                ReadOnlyCommand::NftListFlowtables,
                &[],
                "nft list flowtables",
                &mut evidence,
                &mut observations.probe_error,
            ) {
                observations.commands.flowtable_exit_code = result.exit_code.unwrap_or(-1);
                observations.commands.flowtable_counter =
                    result.stdout.contains("flowtable") && result.stdout.contains("counter");
            }
            if let Some(result) = self.command(
                ReadOnlyCommand::NftDaeDnsUdp53,
                &[],
                "nft list ruleset",
                &mut evidence,
                &mut observations.probe_error,
            ) {
                observations.proxy.dae_dns_udp53 = result.stdout.contains("dport 53")
                    && (result.stdout.contains("dae") || result.stdout.contains("0x8000000"));
            }
        }
        if let Some(result) = self.command(
            ReadOnlyCommand::IpRuleShow,
            &[],
            "ip rule show",
            &mut evidence,
            &mut observations.probe_error,
        ) {
            observations.proxy.dae_fwmark = result.stdout.contains("0x8000000");
        }
        if let Some(result) = self.command(
            ReadOnlyCommand::IpRouteShow,
            &["show", "table", "2023"],
            "ip route show table 2023",
            &mut evidence,
            &mut observations.probe_error,
        ) {
            observations.proxy.dae_route_table =
                result.stdout.contains("dae0") || result.stdout.contains("default");
        }

        self.collect_files(config, &mut observations, &mut evidence);
        self.collect_uci(&mut observations, &mut evidence);
        self.collect_ubus(&mut observations, &mut evidence);
        observations.collected_evidence = evidence;
        let mut report = assess(config, observations, runtime);
        report.evidence.method = method.as_str();
        report
    }

    fn availability(
        &mut self,
        command: ReadOnlyCommand,
        name: &str,
        evidence: &mut CollectedEvidence,
        error: &mut bool,
    ) -> bool {
        match self.commands.available(command) {
            Ok(available) => {
                evidence.command.push(CommandEvidence {
                    source: format!("command:{name}"),
                    command: name.into(),
                    available,
                    exit_code: None,
                    supported: None,
                    summary: None,
                });
                available
            }
            Err(_) => {
                *error = true;
                evidence.command.push(CommandEvidence {
                    source: format!("command:{name}"),
                    command: name.into(),
                    available: false,
                    exit_code: None,
                    supported: None,
                    summary: Some("availability probe failed".into()),
                });
                false
            }
        }
    }

    fn command(
        &mut self,
        command: ReadOnlyCommand,
        args: &[&str],
        display: &str,
        evidence: &mut CollectedEvidence,
        error: &mut bool,
    ) -> Option<CommandResult> {
        match self.commands.run(command, args) {
            Ok(result) => {
                let nonzero_is_error = command != ReadOnlyCommand::TcFilterShow;
                let optional_truncation =
                    command == ReadOnlyCommand::NftDaeDnsUdp53 && result.output_truncated;
                let failed = (nonzero_is_error && result.exit_code != Some(0))
                    || result.timed_out
                    || (result.output_truncated && !optional_truncation);
                *error |= failed;
                evidence.command.push(CommandEvidence {
                    source: canonical_command_source(command, args),
                    command: display.into(),
                    available: true,
                    exit_code: result.exit_code,
                    supported: Some(!failed),
                    summary: Some(
                        if optional_truncation {
                            "optional ruleset scan truncated"
                        } else if result.timed_out {
                            "probe timed out"
                        } else if result.output_truncated {
                            "probe output truncated"
                        } else if failed {
                            "probe failed"
                        } else {
                            "probe completed"
                        }
                        .into(),
                    ),
                });
                Some(result)
            }
            Err(_) => {
                *error = true;
                evidence.command.push(CommandEvidence {
                    source: canonical_command_source(command, args),
                    command: display.into(),
                    available: true,
                    exit_code: None,
                    supported: Some(false),
                    summary: Some("probe execution failed".into()),
                });
                None
            }
        }
    }

    fn collect_files(
        &mut self,
        config: &RuntimeConfig,
        o: &mut ProbeObservations,
        evidence: &mut CollectedEvidence,
    ) {
        let acct = "/proc/sys/net/netfilter/nf_conntrack_acct";
        match self.files.read(acct, FILE_CAP) {
            Ok(entry) => {
                o.files.nf_conntrack_acct_present = entry.present;
                o.files.nf_conntrack_acct_value = entry.value.clone();
                o.probe_error |= entry.truncated;
                evidence.file.push(to_file_evidence(entry));
            }
            Err(error) => {
                o.probe_error = true;
                evidence.file.push(file_error(acct, error.to_string()));
            }
        }
        for (path, slot) in [
            ("/proc/net/nf_flowtable", &mut o.files.flowtable_proc),
            (
                "/sys/kernel/debug/netfilter/nf_flowtable",
                &mut o.files.flowtable_debug,
            ),
            ("/sys/class/net/ifb0", &mut o.files.ifb),
            ("/proc/net/vlan/config", &mut o.files.vlan),
            (
                "/usr/share/lanspeed/bpf/collector-model.json",
                &mut o.bpf.package,
            ),
        ] {
            *slot = self.exists(path, evidence, &mut o.probe_error);
        }
        let primary = self.exists(
            crate::collectors::bpf::runtime::PRIMARY_OBJECT_PATH,
            evidence,
            &mut o.probe_error,
        );
        let fallback = self.exists(
            crate::collectors::bpf::runtime::FALLBACK_OBJECT_PATH,
            evidence,
            &mut o.probe_error,
        );
        o.bpf.object = primary && fallback;
        for path in [
            "/etc/config/openclash",
            "/etc/config/dae",
            "/etc/config/daed",
            "/etc/config/homeproxy",
            "/etc/config/nlbwmon",
        ] {
            let _ = self.exists(path, evidence, &mut o.probe_error);
        }
        o.files.wlan = self.dir_entries("/sys/class/ieee80211", evidence, &mut o.probe_error);
        o.files.lan_bridge = config
            .ifnames
            .iter()
            .chain(config.interface_include.iter())
            .any(|ifname| {
                let path = format!("/sys/class/net/{ifname}/bridge");
                self.exists(&path, evidence, &mut o.probe_error)
            });
        o.nss.present = self.any_exists(
            &[
                "/sys/module/qca_nss_drv",
                "/sys/bus/platform/drivers/qca-nss",
                "/sys/kernel/debug/qca-nss-drv",
                "/proc/sys/dev/nss",
            ],
            evidence,
            &mut o.probe_error,
        );
        o.nss.ecm_active = self.any_exists(
            &["/sys/module/ecm", "/sys/kernel/debug/ecm"],
            evidence,
            &mut o.probe_error,
        );
        o.nss.ppe_active = self.any_exists(
            &[
                "/sys/module/qca_nss_ppe",
                "/sys/module/ppe_drv",
                "/sys/kernel/debug/qca-nss-ppe",
                "/sys/kernel/debug/ppe_drv",
            ],
            evidence,
            &mut o.probe_error,
        );
        o.nss.bridge_mgr = self.any_exists(
            &["/sys/module/qca_nss_bridge_mgr"],
            evidence,
            &mut o.probe_error,
        );
        o.nss.ifb_active = self.any_exists(
            &[
                "/sys/class/net/nssifb",
                "/sys/module/nss_ifb",
                "/sys/module/nss-ifb",
            ],
            evidence,
            &mut o.probe_error,
        );
        o.nss.nsm_active = self.any_exists(
            &[
                "/sys/module/qca_nss_nsm",
                "/sys/module/nss_nsm",
                "/sys/kernel/debug/qca-nss-nsm",
            ],
            evidence,
            &mut o.probe_error,
        );
        o.nss.dp_active = self.any_exists(
            &["/sys/module/qca_nss_dp", "/sys/module/nss_dp"],
            evidence,
            &mut o.probe_error,
        );
        o.nss.mcs_active = self.any_exists(
            &["/sys/module/qca_mcs", "/sys/module/mc_snooping"],
            evidence,
            &mut o.probe_error,
        );
        o.nss.present |= o.nss.dp_active;
        match self.files.probe_nss_state() {
            Ok(state) => {
                o.nss.direct_state_present = state.present;
                o.nss.direct_state_readable = state.readable;
                o.nss.direct_state_errno = state.errno;
                o.nss.direct_state_major = state.state_major;
                o.nss.direct_source_path = state.source_path;
            }
            Err(_) => o.probe_error = true,
        }
        self.collect_nss_counts(o, evidence);
    }

    fn collect_nss_counts(&mut self, o: &mut ProbeObservations, evidence: &mut CollectedEvidence) {
        let primary_total = self
            .read_optional_file(ECM_CONNECTION_COUNT_PATH, evidence, &mut o.probe_error)
            .and_then(|value| parse_nonnegative_count(&value));
        let simple = self
            .read_optional_file(
                ECM_CONNECTION_COUNT_SIMPLE_PATH,
                evidence,
                &mut o.probe_error,
            )
            .and_then(|value| parse_simple_connection_counts(&value));
        o.nss.accelerated_connections = primary_total.or_else(|| simple.map(|counts| counts.total));
        o.nss.accelerated_tcp = simple.map(|counts| counts.tcp);
        o.nss.accelerated_udp = simple.map(|counts| counts.udp);
        o.nss.accelerated_other = simple.map(|counts| counts.other);
        o.nss.host_count = self
            .read_optional_file(ECM_HOST_COUNT_PATH, evidence, &mut o.probe_error)
            .and_then(|value| parse_nonnegative_count(&value));
        o.nss.mapping_count = self
            .read_optional_file(ECM_MAPPING_COUNT_PATH, evidence, &mut o.probe_error)
            .and_then(|value| parse_nonnegative_count(&value));
    }

    fn read_optional_file(
        &mut self,
        path: &str,
        evidence: &mut CollectedEvidence,
        error: &mut bool,
    ) -> Option<String> {
        match self.files.read(path, FILE_CAP) {
            Ok(entry) => {
                let truncated = entry.truncated;
                let value = (!truncated && entry.present)
                    .then(|| entry.value.clone())
                    .flatten();
                *error |= truncated;
                let mut file_evidence = to_file_evidence(entry);
                if truncated {
                    file_evidence.status = "truncated";
                    file_evidence.value = None;
                }
                evidence.file.push(file_evidence);
                value
            }
            Err(error_value) => {
                *error = true;
                evidence
                    .file
                    .push(file_error(path, error_value.to_string()));
                None
            }
        }
    }

    fn exists(&mut self, path: &str, evidence: &mut CollectedEvidence, error: &mut bool) -> bool {
        match self.files.exists(path) {
            Ok(presence) => {
                let present = presence == FilePresence::Present;
                evidence.file.push(FileEvidence {
                    source: format!("file:{path}"),
                    path: path.into(),
                    present,
                    value: None,
                    status: if present { "present" } else { "absent" },
                    error: None,
                });
                present
            }
            Err(error_value) => {
                *error = true;
                evidence
                    .file
                    .push(file_error(path, error_value.to_string()));
                false
            }
        }
    }
    fn any_exists(
        &mut self,
        paths: &[&str],
        evidence: &mut CollectedEvidence,
        error: &mut bool,
    ) -> bool {
        let mut present = false;
        for path in paths {
            present |= self.exists(path, evidence, error);
        }
        present
    }
    fn dir_entries(
        &mut self,
        path: &str,
        evidence: &mut CollectedEvidence,
        error: &mut bool,
    ) -> bool {
        match self.files.dir_has_entries(path) {
            Ok(present) => {
                evidence.file.push(FileEvidence {
                    source: format!("file:{path}"),
                    path: path.into(),
                    present,
                    value: None,
                    status: if present { "present" } else { "absent" },
                    error: None,
                });
                present
            }
            Err(error_value) => {
                *error = true;
                evidence
                    .file
                    .push(file_error(path, error_value.to_string()));
                false
            }
        }
    }

    fn collect_uci(&mut self, o: &mut ProbeObservations, evidence: &mut CollectedEvidence) {
        for package in PACKAGES {
            match self.uci.load(package) {
                Ok(snapshot) => {
                    let loaded = snapshot.is_some();
                    evidence.uci.push(UciEvidence {
                        source: format!("uci:{package}"),
                        package: package.into(),
                        loaded,
                        section: None,
                        option: None,
                        present: None,
                        value: None,
                    });
                    match package {
                        "firewall" => o.uci.firewall_loaded = loaded,
                        "sqm" => o.uci.sqm = loaded,
                        "qosify" => o.uci.qosify = loaded,
                        "openclash" => o.uci.openclash = loaded,
                        "dae" => o.uci.dae = loaded,
                        "daed" => o.uci.daed = loaded,
                        "homeproxy" => o.uci.homeproxy = loaded,
                        "nlbwmon" => o.uci.nlbwmon = loaded,
                        "dhcp" => o.proxy.dhcp_loaded = loaded,
                        _ => {}
                    }
                    if let Some(snapshot) = snapshot {
                        self.apply_uci_package(&snapshot, o, evidence);
                    }
                }
                Err(_) => {
                    o.probe_error = true;
                    evidence.uci.push(UciEvidence {
                        source: format!("uci:{package}"),
                        package: package.into(),
                        loaded: false,
                        section: None,
                        option: None,
                        present: None,
                        value: None,
                    });
                }
            }
        }
    }

    fn apply_uci_package(
        &self,
        package: &UciPackageSnapshot,
        o: &mut ProbeObservations,
        evidence: &mut CollectedEvidence,
    ) {
        let openclash_section = (package.name == "openclash")
            .then(|| {
                package
                    .sections
                    .iter()
                    .find(|section| {
                        section.options.iter().any(|option| {
                            matches!(
                                option.name.as_str(),
                                "en_mode"
                                    | "enable_redirect_dns"
                                    | "router_self_proxy"
                                    | "enable_udp_proxy"
                                    | "stack_type"
                                    | "ipv6_enable"
                            )
                        })
                    })
                    .map(|section| section.name.as_str())
            })
            .flatten();
        for section in &package.sections {
            for option in &section.options {
                let value = option.values.first().cloned();
                evidence.uci.push(UciEvidence {
                    source: format!("uci:{}.{}.{}", package.name, section.name, option.name),
                    package: package.name.clone(),
                    loaded: true,
                    section: Some(section.name.clone()),
                    option: Some(option.name.clone()),
                    present: Some(true),
                    value: value.clone(),
                });
                if package.name == "firewall" && section.kind == "defaults" {
                    match option.name.as_str() {
                        "flow_offloading" => o.offload.software |= bool_value(value.as_deref()),
                        "flow_offloading_hw" => o.offload.hardware |= bool_value(value.as_deref()),
                        "fullcone" => o.offload.fullcone |= bool_value(value.as_deref()),
                        _ => {}
                    }
                }
                if package.name == "dhcp"
                    && option
                        .values
                        .iter()
                        .any(|value| value.contains("127.0.0.1#7874"))
                {
                    o.proxy.openclash_dnsmasq_chain = true;
                }
                if package.name == "openclash" && openclash_section == Some(section.name.as_str()) {
                    o.proxy.openclash_section = Some(section.name.clone());
                    match option.name.as_str() {
                        "en_mode" => o.proxy.openclash_en_mode = value,
                        "enable_redirect_dns" => {
                            o.proxy.openclash_redirect_dns = bool_value(value.as_deref())
                        }
                        "router_self_proxy" => {
                            o.proxy.openclash_router_self_proxy = bool_value(value.as_deref())
                        }
                        "enable_udp_proxy" => {
                            o.proxy.openclash_udp_proxy = bool_value(value.as_deref())
                        }
                        "stack_type" => o.proxy.openclash_stack_type = value,
                        "ipv6_enable" => o.proxy.openclash_ipv6 = bool_value(value.as_deref()),
                        _ => {}
                    }
                }
            }
        }
        o.proxy.openclash_installed = o.uci.openclash;
    }

    fn collect_ubus(&mut self, o: &mut ProbeObservations, evidence: &mut CollectedEvidence) {
        for query in [
            UbusQuery::NetworkLanStatus,
            UbusQuery::ServiceDae,
            UbusQuery::ServiceDaed,
        ] {
            match self.ubus.query(query) {
                Ok(result) => {
                    let failed = result.exit_code != 0 || result.truncated;
                    o.probe_error |= failed;
                    if query == UbusQuery::NetworkLanStatus {
                        o.ubus.network_lan_attempted = true;
                        o.ubus.network_lan_exit_code = result.exit_code;
                        o.lan_probe_error |= failed;
                    } else {
                        let present = result.output.contains(if query == UbusQuery::ServiceDae {
                            "dae"
                        } else {
                            "daed"
                        });
                        let running = present
                            && (result.output.contains("\"running\": true")
                                || result.output.contains("\"running\":true"));
                        if query == UbusQuery::ServiceDae {
                            o.proxy.dae_service = present;
                            o.proxy.dae_running = running;
                        } else {
                            o.proxy.daed_service = present;
                            o.proxy.daed_running = running;
                        }
                    }
                    evidence.ubus.push(UbusEvidence {
                        source: format!("ubus:{}", query.object()),
                        object: query.object().into(),
                        attempted: true,
                        exit_code: result.exit_code,
                        summary: result.summary,
                    });
                }
                Err(_) => {
                    o.probe_error = true;
                    o.lan_probe_error |= query == UbusQuery::NetworkLanStatus;
                    evidence.ubus.push(UbusEvidence {
                        source: format!("ubus:{}", query.object()),
                        object: query.object().into(),
                        attempted: true,
                        exit_code: -1,
                        summary: "query failed".into(),
                    });
                }
            }
        }
    }
}

fn canonical_command_source(command: ReadOnlyCommand, args: &[&str]) -> String {
    format!("command:{}", command.evidence_key(args))
}
fn to_file_evidence(entry: BoundedFile) -> FileEvidence {
    FileEvidence {
        source: entry.source,
        path: entry.path,
        present: entry.present,
        value: entry.value,
        status: if entry.present { "present" } else { "absent" },
        error: None,
    }
}
fn file_error(path: &str, error: String) -> FileEvidence {
    FileEvidence {
        source: format!("file:{path}"),
        path: path.into(),
        present: false,
        value: None,
        status: "error",
        error: Some(error),
    }
}
fn bool_value(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true" | "on" | "yes"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SimpleConnectionCounts {
    tcp: u64,
    udp: u64,
    other: u64,
    total: u64,
}

fn parse_nonnegative_count(value: &str) -> Option<u64> {
    value.trim().parse().ok()
}

fn parse_simple_connection_counts(value: &str) -> Option<SimpleConnectionCounts> {
    let mut fields = value.split_whitespace();
    if fields.next()? != "tcp" {
        return None;
    }
    let tcp = fields.next()?;
    if fields.next()? != "udp" {
        return None;
    }
    let udp = fields.next()?;
    if fields.next()? != "other" {
        return None;
    }
    let other = fields.next()?;
    if fields.next()? != "total" {
        return None;
    }
    let total = fields.next()?;
    Some(SimpleConnectionCounts {
        tcp: parse_nonnegative_count(tcp)?,
        udp: parse_nonnegative_count(udp)?,
        other: parse_nonnegative_count(other)?,
        total: parse_nonnegative_count(total)?,
    })
}
