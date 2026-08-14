use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;

pub(super) const ROOT_HANDLE: &str = "7d00:";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
// Structural observation intentionally runs many short tc/nft/ip reads. A
// coarse poll interval adds its full delay to each already-completed child and
// can stretch one hot clients audit into several seconds on the router.
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(2);
const COMMAND_OUTPUT_CAP: usize = 1024 * 1024;
const ECM_DSCP_ENABLED: &str = "/sys/kernel/debug/ecm/ecm_classifier_dscp/enabled";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OutputCacheKey {
    program: String,
    args: Vec<String>,
}

thread_local! {
    static OBSERVATION_OUTPUT_CACHE: RefCell<Option<BTreeMap<OutputCacheKey, Output>>> =
        RefCell::new(None);
}

struct ObservationCacheGuard {
    previous: Option<BTreeMap<OutputCacheKey, Output>>,
}

impl Drop for ObservationCacheGuard {
    fn drop(&mut self) {
        OBSERVATION_OUTPUT_CACHE.with(|cache| {
            cache.replace(self.previous.take());
        });
    }
}

pub(super) fn with_observation_cache<T>(operation: impl FnOnce() -> T) -> T {
    let previous = OBSERVATION_OUTPUT_CACHE.with(|cache| cache.replace(Some(BTreeMap::new())));
    let _guard = ObservationCacheGuard { previous };
    operation()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct QdiscInfo {
    pub kind: String,
    pub handle: String,
    pub parent: Option<String>,
    pub root: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct TcU32Match {
    pub offset: i64,
    pub value: String,
    pub mask: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TcU32MatchSet {
    pub protocol: String,
    pub pref: u64,
    pub matches: Vec<TcU32Match>,
}

pub(super) fn command_available(program: &str) -> bool {
    crate::probe::commands::command_available(program)
}

pub(super) fn require_program(program: &str) -> Result<(), String> {
    command_available(program)
        .then_some(())
        .ok_or_else(|| format!("missing_{program}"))
}

pub(super) fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

pub(super) fn interface_exists(device: &str) -> bool {
    valid_interface_name(device)
        && fs::read_to_string(format!("/sys/class/net/{device}/ifindex"))
            .ok()
            .is_some_and(|value| valid_ifindex(&value))
}

fn valid_ifindex(value: &str) -> bool {
    value
        .trim()
        .parse::<u32>()
        .ok()
        .is_some_and(|ifindex| ifindex != 0)
}

pub(super) fn interface_names() -> Result<Vec<String>, String> {
    let entries = fs::read_dir("/sys/class/net").map_err(|_| "interface_status_unavailable")?;
    let mut values = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        // Some kernels expose control files such as `bonding_masters` in
        // this directory.  A real netdevice always has a positive ifindex;
        // filename syntax and directory presence alone do not prove that.
        .filter(|name| interface_exists(name))
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    Ok(values)
}

pub(super) fn module_available(module: &str) -> bool {
    fs::metadata(format!("/sys/module/{module}")).is_ok()
        || fs::read_dir("/lib/modules")
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .any(|version| module_tree_contains(&version.path(), module))
}

pub(super) fn module_loaded(module: &str) -> bool {
    fs::metadata(format!("/sys/module/{module}")).is_ok()
}

fn module_tree_contains(root: &Path, module: &str) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if module_tree_contains(&path, module) {
                return true;
            }
            continue;
        }
        let name = entry.file_name().to_string_lossy().replace('-', "_");
        if name == format!("{module}.ko") || name.starts_with(&format!("{module}.ko.")) {
            return true;
        }
    }
    false
}

pub(super) fn load_module(module: &str, reason: &str) -> Result<(), String> {
    if module_loaded(module) {
        return Ok(());
    }
    if !module_available(module) {
        return Err(reason.into());
    }
    run("modprobe", &[module]).map_err(|_| reason.to_owned())
}

pub(super) fn ecm_dscp_enabled() -> bool {
    fs::read_to_string(ECM_DSCP_ENABLED)
        .ok()
        .is_some_and(|value| value.trim() == "1")
}

pub(super) fn run(program: &str, args: &[&str]) -> Result<(), String> {
    // Mutations must never be satisfied by a read-observation cache.
    let output = output_uncached(program, args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(program, &output))
    }
}

pub(super) fn run_ignore_missing(program: &str, args: &[&str]) {
    let _ = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub(super) fn run_script(program: &str, args: &[&str], script: &str) -> Result<(), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| format!("{program}_unavailable"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| format!("{program}_stdin_unavailable"))?;
    stdin
        .write_all(script.as_bytes())
        .map_err(|_| format!("{program}_stdin_failed"))?;
    drop(stdin);
    let output = wait_output(child, program)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(program, &output))
    }
}

pub(super) fn output(program: &str, args: &[&str]) -> Result<Output, String> {
    let key = OutputCacheKey {
        program: program.to_owned(),
        args: args.iter().map(|value| (*value).to_owned()).collect(),
    };
    if let Some(output) = OBSERVATION_OUTPUT_CACHE.with(|cache| {
        cache
            .borrow()
            .as_ref()
            .and_then(|values| values.get(&key).cloned())
    }) {
        return Ok(output);
    }
    let output = output_uncached(program, args)?;
    OBSERVATION_OUTPUT_CACHE.with(|cache| {
        if let Some(values) = cache.borrow_mut().as_mut() {
            values.insert(key, output.clone());
        }
    });
    Ok(output)
}

fn output_uncached(program: &str, args: &[&str]) -> Result<Output, String> {
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| format!("{program}_unavailable"))?;
    wait_output(child, program)
}

fn wait_output(child: Child, program: &str) -> Result<Output, String> {
    wait_output_with_timeout(child, program, COMMAND_TIMEOUT)
}

fn wait_output_with_timeout(
    mut child: Child,
    program: &str,
    timeout: Duration,
) -> Result<Output, String> {
    // Drain both pipes while the command runs. Waiting first can deadlock on
    // a large netifd dump because the child blocks once a pipe buffer fills.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{program}_stdout_unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{program}_stderr_unavailable"))?;
    let stdout_reader = thread::spawn(move || read_capped(stdout));
    let stderr_reader = thread::spawn(move || read_capped(stderr));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(COMMAND_POLL_INTERVAL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("nss_control_command_timeout".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!("{program}_failed"));
            }
        }
    };
    let stdout = join_reader(stdout_reader, program)?;
    let stderr = join_reader(stderr_reader, program)?;
    Ok(Output {
        status: status?,
        stdout,
        stderr,
    })
}

fn read_capped(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(output);
        }
        let remaining = COMMAND_OUTPUT_CAP.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..count.min(remaining)]);
    }
}

fn join_reader(
    reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    program: &str,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| format!("{program}_failed"))?
        .map_err(|_| format!("{program}_failed"))
}

pub(super) fn json_output(program: &str, args: &[&str], reason: &str) -> Result<Value, String> {
    let output = output(program, args)?;
    if !output.status.success() {
        return Err(reason.into());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| reason.into())
}

pub(super) fn tc_filter_values(output: &[u8], reason: &str) -> Result<Vec<Value>, String> {
    let values = serde_json::from_slice::<Vec<Value>>(output).map_err(|_| reason.to_owned())?;
    Ok(values.into_iter().filter(logical_tc_filter_value).collect())
}

pub(super) fn tc_filter_values_at_pref(
    output: &[u8],
    pref: u32,
    reason: &str,
) -> Result<Vec<Value>, String> {
    let mut values = tc_filter_values(output, reason)?;
    for value in &mut values {
        let Some(object) = value.as_object_mut() else {
            continue;
        };
        // QCA tc omits the selector from detailed JSON when the command is
        // already scoped with `pref <value>`. The read command proves this
        // field; every other ownership fingerprint remains kernel-reported.
        object
            .entry("pref".to_owned())
            .or_insert_with(|| Value::from(pref));
    }
    Ok(values)
}

pub(super) fn tc_u32_match_sets(output: &[u8], reason: &str) -> Result<Vec<TcU32MatchSet>, String> {
    let value = LosslessJson::deserialize(&mut serde_json::Deserializer::from_slice(output))
        .map_err(|_| reason.to_owned())?;
    let LosslessJson::Array(values) = value else {
        return Err(reason.into());
    };
    Ok(values
        .iter()
        .filter_map(|value| {
            let object = value.as_object()?;
            if object_string(object, "kind")? != "u32" {
                return None;
            }
            let protocol = object_string(object, "protocol")?.to_owned();
            let pref = object_u64(object, "pref")?;
            let options = object_value(object, "options")?.as_object()?;
            let mut matches = Vec::new();
            collect_u32_matches(options, &mut matches);
            if matches.is_empty() {
                return None;
            }
            matches.sort();
            Some(TcU32MatchSet {
                protocol,
                pref,
                matches,
            })
        })
        .collect())
}

#[derive(Debug)]
enum LosslessJson {
    Null,
    Bool,
    I64(i64),
    U64(u64),
    F64,
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl LosslessJson {
    fn as_object(&self) -> Option<&[(String, Self)]> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(value) => Some(*value),
            Self::I64(value) => u64::try_from(*value).ok(),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(value) => Some(*value),
            Self::U64(value) => i64::try_from(*value).ok(),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for LosslessJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(LosslessJsonVisitor)
    }
}

struct LosslessJsonVisitor;

impl<'de> Visitor<'de> for LosslessJsonVisitor {
    type Value = LosslessJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(LosslessJson::Bool)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(LosslessJson::I64(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(LosslessJson::U64(value))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(LosslessJson::F64)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(LosslessJson::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(LosslessJson::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(LosslessJson::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(LosslessJson::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(LosslessJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some((key, value)) = map.next_entry()? {
            values.push((key, value));
        }
        Ok(LosslessJson::Object(values))
    }
}

fn object_value<'a>(object: &'a [(String, LosslessJson)], name: &str) -> Option<&'a LosslessJson> {
    object
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn object_string<'a>(object: &'a [(String, LosslessJson)], name: &str) -> Option<&'a str> {
    object_value(object, name)?.as_str()
}

fn object_u64(object: &[(String, LosslessJson)], name: &str) -> Option<u64> {
    object_value(object, name)?.as_u64()
}

fn collect_u32_matches(object: &[(String, LosslessJson)], output: &mut Vec<TcU32Match>) {
    for (name, value) in object {
        if name == "match" {
            if let Some(value) = parse_u32_match(value) {
                output.push(value);
            }
            continue;
        }
        match value {
            LosslessJson::Object(value) => collect_u32_matches(value, output),
            LosslessJson::Array(values) => {
                for value in values {
                    if let LosslessJson::Object(value) = value {
                        collect_u32_matches(value, output);
                    }
                }
            }
            _ => {}
        }
    }
}

fn parse_u32_match(value: &LosslessJson) -> Option<TcU32Match> {
    let object = value.as_object()?;
    Some(TcU32Match {
        offset: object_value(object, "off")?.as_i64()?,
        value: normalize_tc_hex(object_string(object, "value")?),
        mask: normalize_tc_hex(object_string(object, "mask")?),
    })
}

fn normalize_tc_hex(value: &str) -> String {
    let value = value
        .strip_prefix("0x")
        .unwrap_or(value)
        .trim_start_matches('0')
        .to_ascii_lowercase();
    if value.is_empty() {
        "0".into()
    } else {
        value
    }
}

fn logical_tc_filter_value(value: &Value) -> bool {
    let kind = value.get("kind").and_then(Value::as_str);
    let options = value.get("options").and_then(Value::as_object);
    match (kind, options) {
        // qca iproute2 emits a header row and a u32 hash-table row before
        // the actual rule. Only those two metadata rows are discarded.
        (Some("u32"), None) | (Some("matchall"), None) => false,
        (Some("u32"), Some(options)) => {
            !options.contains_key("ht_divisor")
                || options.contains_key("order")
                || options.contains_key("match")
                || options.contains_key("actions")
                || options.contains_key("flowid")
        }
        (Some("matchall"), Some(_)) => true,
        // Unknown classifiers remain visible so ownership checks reject them.
        _ => true,
    }
}

fn command_error(program: &str, output: &Output) -> String {
    let diagnostic = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if diagnostic.contains("file exists") || diagnostic.contains("exclusivity flag") {
        return "nss_qdisc_owned_by_external_service".into();
    }
    match program {
        "nft" => "nss_control_firewall_failed".into(),
        "tc" => "nss_qdisc_apply_failed".into(),
        _ => format!("{program}_failed"),
    }
}

pub(super) fn qdiscs(device: &str) -> Result<Vec<QdiscInfo>, String> {
    let output = output("tc", &["qdisc", "show", "dev", device])?;
    if !output.status.success() {
        return Err("qdisc_inspection_invalid".into());
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "qdisc_inspection_invalid")?;
    parse_qdiscs(&text)
}

pub(super) fn owned_root(device: &str) -> Result<bool, String> {
    Ok(qdiscs(device)?
        .iter()
        .any(|value| value.root && value.kind == "nsshtb" && value.handle == ROOT_HANDLE))
}

pub(super) fn ensure_replaceable_root(device: &str) -> Result<(), String> {
    let values = qdiscs(device)?;
    let roots = values.iter().filter(|value| value.root).collect::<Vec<_>>();
    let owned = roots
        .iter()
        .all(|value| value.kind == "nsshtb" && value.handle == ROOT_HANDLE);
    let system_default = roots.is_empty() || roots.iter().all(|value| system_default_root(value));
    if owned || system_default {
        Ok(())
    } else {
        Err("nss_qdisc_owned_by_external_service".into())
    }
}

fn system_default_root(value: &QdiscInfo) -> bool {
    value.handle == "0:" && matches!(value.kind.as_str(), "noqueue" | "mq" | "fq" | "fq_codel")
}

pub(super) fn has_qdisc(device: &str, kind: &str, handle: Option<&str>) -> Result<bool, String> {
    Ok(qdiscs(device)?
        .iter()
        .any(|value| value.kind == kind && handle.is_none_or(|expected| value.handle == expected)))
}

pub(super) fn ensure_clsact(device: &str) -> Result<(), String> {
    let values = qdiscs(device).map_err(|_| "cpu_path_classifier_inspection_failed")?;
    if values.iter().any(|value| value.kind == "clsact") {
        return Ok(());
    }
    if values.iter().any(|value| value.kind == "ingress") {
        return Err("ingress_qdisc_owned_by_external_service".into());
    }
    run("tc", &["qdisc", "add", "dev", device, "clsact"])?;
    let installed = qdiscs(device)
        .map_err(|_| "cpu_path_classifier_inspection_failed")?
        .iter()
        .any(|value| value.kind == "clsact");
    if !installed {
        return Err("cpu_path_classifier_verification_failed".into());
    }
    Ok(())
}

fn parse_qdiscs(text: &str) -> Result<Vec<QdiscInfo>, String> {
    let mut values = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 3 || fields[0] != "qdisc" {
            return Err("qdisc_inspection_invalid".into());
        }
        let parent = fields
            .windows(2)
            .find(|pair| pair[0] == "parent")
            .map(|pair| pair[1].to_owned());
        values.push(QdiscInfo {
            kind: fields[1].to_owned(),
            handle: fields[2].to_owned(),
            parent,
            root: fields.contains(&"root"),
        });
    }
    Ok(values)
}

#[cfg(test)]
include!("system_tests.rs");
