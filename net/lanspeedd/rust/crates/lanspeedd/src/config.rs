use std::{fmt, fs, path::PathBuf};

pub const DEFAULT_REFRESH_INTERVAL_MS: u32 = 1_000;
pub const MIN_REFRESH_INTERVAL_MS: u32 = 500;
pub const DEFAULT_MAX_CLIENTS: usize = 2_048;
pub const DEFAULT_ACTIVE_CLIENT_WINDOW_MS: u64 = 10_000;
pub const MIN_ACTIVE_CLIENT_WINDOW_MS: u64 = 1_000;
pub const DEFAULT_ACTIVE_CLIENT_MIN_BPS: u64 = 1;
pub const DEFAULT_OVERVIEW_WINDOW_SAMPLES: usize = 240;
pub const MIN_OVERVIEW_WINDOW_SAMPLES: usize = 2;
pub const MAX_OVERVIEW_WINDOW_SAMPLES: usize = 240;
pub const MAX_INTERFACE_NAMES: usize = 16;
pub const MAX_INTERFACE_NAME_LEN: usize = 32;

const CONFIG_PREFIX: &str = "lanspeed.main.";
pub const ARPHRD_ETHER: u32 = 1;
pub const AUTO_IGNORED_INTERFACE_PREFIXES: [&str; 10] = [
    "dae",
    "miireg",
    "tun",
    "erspan",
    "gretap",
    "gre",
    "ip6gre",
    "ip6tnl",
    "sit",
    "bonding_masters",
];

pub fn is_auto_ignored_interface(name: &str) -> bool {
    AUTO_IGNORED_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

pub fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < MAX_INTERFACE_NAME_LEN
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\0')
}

pub fn is_sysdevice_candidate(name: &str) -> bool {
    is_valid_interface_name(name)
        && name != "lo"
        && !name.starts_with("teql")
        && !is_auto_ignored_interface(name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateCollectorMode {
    Auto,
    Bpf,
    NssEcmDirect,
    NssConntrackSync,
}

impl RateCollectorMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "bpf" => Some(Self::Bpf),
            "nss_ecm_direct" => Some(Self::NssEcmDirect),
            "nss_conntrack_sync" | "conntrack_ecm_sync" => Some(Self::NssConntrackSync),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Bpf => "bpf",
            Self::NssEcmDirect => "nss_ecm_direct",
            Self::NssConntrackSync => "nss_conntrack_sync",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionCollectorMode {
    Auto,
    ConntrackNetlink,
    ConntrackProcfs,
}

impl ConnectionCollectorMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "conntrack_netlink" => Some(Self::ConntrackNetlink),
            "conntrack_procfs" => Some(Self::ConntrackProcfs),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::ConntrackNetlink => "conntrack_netlink",
            Self::ConntrackProcfs => "conntrack_procfs",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigValue {
    String(String),
    List(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Source(String),
    WrongType {
        option: String,
        expected: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(message) => write!(formatter, "configuration source failed: {message}"),
            Self::WrongType { option, expected } => {
                write!(
                    formatter,
                    "configuration option {option} must be {expected}"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

pub trait ConfigSource {
    fn get(&mut self, path: &str) -> Result<Option<ConfigValue>, ConfigError>;
}

pub trait InterfaceEligibility {
    fn is_collect_eligible(&self, name: &str) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LegacyNameEligibility;

impl InterfaceEligibility for LegacyNameEligibility {
    fn is_collect_eligible(&self, name: &str) -> bool {
        !is_auto_ignored_interface(name)
            && name != "nssifb"
            && !name.starts_with("ppp")
            && !name.starts_with("wg")
            && !name.starts_with("wan")
            && !name.starts_with("pppoe-")
            && !name.starts_with("tap")
            && !name.starts_with("utun")
    }
}

#[derive(Clone, Debug)]
pub struct SysfsInterfaceEligibility {
    root: PathBuf,
}

impl SysfsInterfaceEligibility {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl Default for SysfsInterfaceEligibility {
    fn default() -> Self {
        Self::new("/sys/class/net")
    }
}

impl InterfaceEligibility for SysfsInterfaceEligibility {
    fn is_collect_eligible(&self, name: &str) -> bool {
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\0')
            || !LegacyNameEligibility.is_collect_eligible(name)
        {
            return false;
        }
        let path = self.root.join(name).join("type");
        fs::read_to_string(path)
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .is_some_and(|link_type| link_type == ARPHRD_ETHER)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub refresh_interval_ms: u32,
    pub max_clients: usize,
    pub active_client_window_ms: u64,
    pub active_client_min_bps: u64,
    pub overview_window_samples: usize,
    pub enable_bpf: bool,
    pub enable_conntrack_fallback: bool,
    pub refresh_interval_clamped: bool,
    pub active_client_window_clamped: bool,
    pub active_client_min_bps_clamped: bool,
    pub overview_window_samples_clamped: bool,
    pub rate_collector_mode: RateCollectorMode,
    pub conn_collector_mode: ConnectionCollectorMode,
    pub ifnames: Vec<String>,
    pub interface_include: Vec<String>,
    /// Retained for the LuCI/UCI contract. The legacy daemon does not use it
    /// to alter its attach set.
    pub interface_exclude: Vec<String>,
    pub observe_ifnames: Vec<String>,
    pub rejected_nssifb_collect: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            refresh_interval_ms: DEFAULT_REFRESH_INTERVAL_MS,
            max_clients: DEFAULT_MAX_CLIENTS,
            active_client_window_ms: DEFAULT_ACTIVE_CLIENT_WINDOW_MS,
            active_client_min_bps: DEFAULT_ACTIVE_CLIENT_MIN_BPS,
            overview_window_samples: DEFAULT_OVERVIEW_WINDOW_SAMPLES,
            enable_bpf: false,
            enable_conntrack_fallback: true,
            refresh_interval_clamped: false,
            active_client_window_clamped: false,
            active_client_min_bps_clamped: false,
            overview_window_samples_clamped: false,
            rate_collector_mode: RateCollectorMode::Auto,
            conn_collector_mode: ConnectionCollectorMode::Auto,
            ifnames: Vec::new(),
            interface_include: Vec::new(),
            interface_exclude: Vec::new(),
            observe_ifnames: Vec::new(),
            rejected_nssifb_collect: false,
        }
    }
}

impl RuntimeConfig {
    pub fn runtime_collect_ifnames(&self) -> Vec<String> {
        let mut names = Vec::new();
        for name in self.ifnames.iter().chain(self.interface_include.iter()) {
            if is_valid_interface_name(name)
                && LegacyNameEligibility.is_collect_eligible(name)
                && !names.contains(name)
                && names.len() < MAX_INTERFACE_NAMES
            {
                names.push(name.clone());
            }
        }
        names
    }

    pub fn runtime_observe_ifnames(&self) -> Vec<String> {
        let collected = self.runtime_collect_ifnames();
        let mut names = Vec::new();
        for name in &self.observe_ifnames {
            if is_valid_interface_name(name)
                && !is_auto_ignored_interface(name)
                && !collected.contains(name)
                && !names.contains(name)
                && names.len() < MAX_INTERFACE_NAMES
            {
                names.push(name.clone());
            }
        }
        names
    }

    pub fn load(
        source: &mut impl ConfigSource,
        eligibility: &impl InterfaceEligibility,
    ) -> Result<Self, ConfigError> {
        let mut config = Self::default();

        if let Some(value) = scalar(source, "refresh_interval_ms")? {
            let parsed = parse_c_signed(&value);
            if parsed >= i128::from(MIN_REFRESH_INTERVAL_MS) {
                config.refresh_interval_ms = parsed.min(i128::from(u32::MAX)) as u32;
            } else if parsed > 0 {
                config.refresh_interval_ms = MIN_REFRESH_INTERVAL_MS;
                config.refresh_interval_clamped = true;
            }
        }

        if let Some(value) = scalar(source, "active_client_window_ms")? {
            let parsed = parse_c_unsigned(&value);
            if parsed >= MIN_ACTIVE_CLIENT_WINDOW_MS {
                config.active_client_window_ms = parsed;
            } else if parsed > 0 {
                config.active_client_window_ms = MIN_ACTIVE_CLIENT_WINDOW_MS;
                config.active_client_window_clamped = true;
            }
        }

        if let Some(value) = scalar(source, "active_client_min_bps")? {
            let parsed = parse_c_unsigned(&value);
            if parsed >= DEFAULT_ACTIVE_CLIENT_MIN_BPS {
                config.active_client_min_bps = parsed;
            } else {
                config.active_client_min_bps = DEFAULT_ACTIVE_CLIENT_MIN_BPS;
                config.active_client_min_bps_clamped = true;
            }
        }

        if let Some(value) = scalar(source, "overview_window_samples")? {
            let parsed = parse_c_signed(&value);
            if parsed >= MIN_OVERVIEW_WINDOW_SAMPLES as i128
                && parsed <= MAX_OVERVIEW_WINDOW_SAMPLES as i128
            {
                config.overview_window_samples = parsed as usize;
            } else if parsed > 0 {
                config.overview_window_samples = if parsed < MIN_OVERVIEW_WINDOW_SAMPLES as i128 {
                    MIN_OVERVIEW_WINDOW_SAMPLES
                } else {
                    MAX_OVERVIEW_WINDOW_SAMPLES
                };
                config.overview_window_samples_clamped = true;
            }
        }

        if let Some(value) = scalar(source, "max_clients")? {
            let parsed = parse_c_signed(&value);
            if parsed >= 0 {
                config.max_clients = parsed.min(usize::MAX as i128) as usize;
            }
        }

        if let Some(value) = scalar(source, "collector_mode")? {
            config.apply_legacy_collector_mode(&value);
        }
        if let Some(value) = scalar(source, "rate_collector_mode")? {
            if let Some(mode) = RateCollectorMode::parse(&value) {
                config.rate_collector_mode = mode;
            }
        }
        if let Some(value) = scalar(source, "conn_collector_mode")? {
            if let Some(mode) = ConnectionCollectorMode::parse(&value) {
                config.conn_collector_mode = mode;
            }
        }

        if let Some(value) = scalar(source, "enable_bpf")? {
            config.enable_bpf = legacy_bool(&value);
        }
        if let Some(value) = scalar(source, "enable_conntrack_fallback")? {
            config.enable_conntrack_fallback = legacy_bool(&value);
        }

        let mut collect_count = 0;
        for option in ["ifname", "interface_include"] {
            let values = list(source, option)?;
            for value in values {
                if value == "nssifb" {
                    config.rejected_nssifb_collect = true;
                    continue;
                }
                if !is_valid_interface_name(&value)
                    || !LegacyNameEligibility.is_collect_eligible(&value)
                    || !eligibility.is_collect_eligible(&value)
                    || config.ifnames.contains(&value)
                    || config.interface_include.contains(&value)
                {
                    continue;
                }
                if collect_count == MAX_INTERFACE_NAMES {
                    continue;
                }
                if option == "ifname" {
                    config.ifnames.push(value);
                } else {
                    config.interface_include.push(value);
                }
                collect_count += 1;
            }
        }

        for value in list(source, "interface_exclude")? {
            push_unique_bounded(&mut config.interface_exclude, value);
        }
        for value in list(source, "observe")? {
            if !is_valid_interface_name(&value)
                || is_auto_ignored_interface(&value)
                || config.ifnames.contains(&value)
                || config.interface_include.contains(&value)
            {
                continue;
            }
            push_unique_bounded(&mut config.observe_ifnames, value);
        }

        Ok(config)
    }

    pub fn reload(
        &mut self,
        source: &mut impl ConfigSource,
        eligibility: &impl InterfaceEligibility,
    ) -> Result<(), ConfigError> {
        let candidate = Self::load(source, eligibility)?;
        *self = candidate;
        Ok(())
    }

    fn apply_legacy_collector_mode(&mut self, value: &str) {
        match value {
            "bpf" => self.rate_collector_mode = RateCollectorMode::Bpf,
            "conntrack_netlink" => {
                self.conn_collector_mode = ConnectionCollectorMode::ConntrackNetlink;
            }
            "conntrack_procfs" => {
                self.conn_collector_mode = ConnectionCollectorMode::ConntrackProcfs;
            }
            "auto" => {
                self.rate_collector_mode = RateCollectorMode::Auto;
                self.conn_collector_mode = ConnectionCollectorMode::Auto;
            }
            _ => {}
        }
    }
}

fn scalar(source: &mut impl ConfigSource, option: &str) -> Result<Option<String>, ConfigError> {
    match source.get(&format!("{CONFIG_PREFIX}{option}"))? {
        Some(ConfigValue::String(value)) => Ok(Some(value)),
        Some(ConfigValue::List(_)) => Err(ConfigError::WrongType {
            option: option.to_owned(),
            expected: "a string",
        }),
        None => Ok(None),
    }
}

fn list(source: &mut impl ConfigSource, option: &str) -> Result<Vec<String>, ConfigError> {
    match source.get(&format!("{CONFIG_PREFIX}{option}"))? {
        Some(ConfigValue::String(value)) => Ok(vec![value]),
        Some(ConfigValue::List(values)) => Ok(values),
        None => Ok(Vec::new()),
    }
}

fn legacy_bool(value: &str) -> bool {
    value == "1" || value == "true"
}

fn push_unique_bounded(target: &mut Vec<String>, value: String) {
    if target.len() < MAX_INTERFACE_NAMES
        && is_valid_interface_name(&value)
        && !target.contains(&value)
    {
        target.push(value);
    }
}

fn parse_c_signed(value: &str) -> i128 {
    let value = trim_c_ascii_whitespace(value);
    let (negative, digits) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    let mut parsed = 0i128;
    let mut found_digit = false;
    for digit in digits.bytes() {
        if !digit.is_ascii_digit() {
            break;
        }
        found_digit = true;
        parsed = parsed
            .saturating_mul(10)
            .saturating_add(i128::from(digit - b'0'));
    }
    if !found_digit {
        return 0;
    }
    if negative {
        -parsed
    } else {
        parsed
    }
}

fn parse_c_unsigned(value: &str) -> u64 {
    let value = trim_c_ascii_whitespace(value);
    let (negative, digits) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    let mut parsed = 0u64;
    let mut found_digit = false;
    for digit in digits.bytes() {
        if !digit.is_ascii_digit() {
            break;
        }
        found_digit = true;
        let Some(next) = parsed
            .checked_mul(10)
            .and_then(|number| number.checked_add(u64::from(digit - b'0')))
        else {
            return u64::MAX;
        };
        parsed = next;
    }
    if !found_digit {
        return 0;
    }
    if negative {
        0u64.wrapping_sub(parsed)
    } else {
        parsed
    }
}

fn trim_c_ascii_whitespace(value: &str) -> &str {
    let prefix_len = value
        .as_bytes()
        .iter()
        .take_while(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
        .count();
    &value[prefix_len..]
}

#[cfg(feature = "openwrt")]
impl ConfigSource for lanspeed_openwrt_sys::UciContext {
    fn get(&mut self, path: &str) -> Result<Option<ConfigValue>, ConfigError> {
        // UciContext currently normalizes C strings to UTF-8 String values.
        // Non-UTF-8 UCI bytes require a future byte-preserving wrapper API.
        self.lookup(path)
            .map(|value| {
                value.map(|value| match value {
                    lanspeed_openwrt_sys::UciValue::String(value) => ConfigValue::String(value),
                    lanspeed_openwrt_sys::UciValue::List(values) => ConfigValue::List(values),
                })
            })
            .map_err(|error| ConfigError::Source(error.to_string()))
    }
}
