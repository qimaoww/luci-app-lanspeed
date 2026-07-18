use super::MacAddress;
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::UNIX_EPOCH,
};

pub const HOSTNAME_CACHE_MAX: usize = 1024;
pub const HOSTNAME_REFRESH_MS: u64 = 10_000;
pub const HOSTNAME_MAX_LINE_BYTES: usize = 512;
pub const HOSTNAME_MAX_SOURCE_BYTES: usize = 1024 * 1024;
pub const HOSTNAME_MAX_HOST_FILES: usize = HOSTNAME_CACHE_MAX;
pub const HOSTNAME_MAX_DIR_ENTRIES: usize = HOSTNAME_MAX_HOST_FILES * 4;
pub const HOSTNAME_DHCP_CONFIG_PATH: &str = "/etc/config/dhcp";
const HOSTNAME_READ_BUFFER_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub struct HostnamePaths {
    pub leases: PathBuf,
    pub hosts_dir: PathBuf,
    pub etc_hosts: PathBuf,
}

impl Default for HostnamePaths {
    fn default() -> Self {
        Self {
            leases: PathBuf::from("/tmp/dhcp.leases"),
            hosts_dir: PathBuf::from("/tmp/hosts"),
            etc_hosts: PathBuf::from("/etc/hosts"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SourceMtimes {
    leases: u64,
    hosts_dir: u64,
    etc_hosts: u64,
    dhcp_config: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostnameRefreshStats {
    pub bytes_read: usize,
    pub host_files: usize,
    pub directory_entries: usize,
}

#[derive(Clone, Debug)]
pub struct HostnameCache {
    capacity: usize,
    by_mac: Arc<Vec<(String, String)>>,
    by_ip: Arc<Vec<(String, String)>>,
    last_refresh_ms: u64,
    mtimes: SourceMtimes,
    last_refresh_stats: HostnameRefreshStats,
}

impl Default for HostnameCache {
    fn default() -> Self {
        Self::new()
    }
}

impl HostnameCache {
    pub fn new() -> Self {
        Self::with_capacity(HOSTNAME_CACHE_MAX)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            by_mac: Arc::default(),
            by_ip: Arc::default(),
            last_refresh_ms: 0,
            mtimes: SourceMtimes::default(),
            last_refresh_stats: HostnameRefreshStats::default(),
        }
    }

    pub fn refresh_from_paths(&mut self, paths: &HostnamePaths, now_ms: u64, force: bool) -> bool {
        // Avoid walking /tmp/hosts and statting every dnsmasq host fragment on
        // each one-second sampling tick. Hostnames are presentation metadata,
        // so checking their mtimes at the documented refresh cadence is enough.
        if !force
            && self.last_refresh_ms != 0
            && now_ms.wrapping_sub(self.last_refresh_ms) < HOSTNAME_REFRESH_MS
        {
            return false;
        }
        let mtimes = SourceMtimes {
            leases: mtime(&paths.leases),
            hosts_dir: latest_directory_mtime(&paths.hosts_dir),
            etc_hosts: mtime(&paths.etc_hosts),
            dhcp_config: mtime(Path::new(HOSTNAME_DHCP_CONFIG_PATH)),
        };

        self.by_mac = Arc::default();
        self.by_ip = Arc::default();
        self.last_refresh_stats = HostnameRefreshStats::default();
        let mut lease_budget = HOSTNAME_MAX_SOURCE_BYTES;
        self.parse_leases_path(&paths.leases, &mut lease_budget);
        let mut hosts_budget = HOSTNAME_MAX_SOURCE_BYTES;
        if let Ok(directory) = fs::read_dir(&paths.hosts_dir) {
            for result in directory.take(HOSTNAME_MAX_DIR_ENTRIES) {
                self.last_refresh_stats.directory_entries += 1;
                let Ok(entry) = result else { continue };
                let name = entry.file_name();
                if name.to_string_lossy().starts_with('.') {
                    continue;
                }
                if self.last_refresh_stats.host_files == HOSTNAME_MAX_HOST_FILES
                    || hosts_budget == 0
                    || self.by_ip.len() >= self.capacity
                {
                    break;
                }
                self.last_refresh_stats.host_files += 1;
                self.parse_hosts_path(&entry.path(), &mut hosts_budget);
            }
        }
        if self.by_ip.len() < self.capacity {
            let mut etc_hosts_budget = HOSTNAME_MAX_SOURCE_BYTES;
            self.parse_hosts_path(&paths.etc_hosts, &mut etc_hosts_budget);
        }
        // Static DHCP host entries are the administrator's explicit naming
        // source. Parse them last so they override transient lease/hosts names.
        let mut dhcp_budget = HOSTNAME_MAX_SOURCE_BYTES;
        self.parse_dhcp_config_path(Path::new(HOSTNAME_DHCP_CONFIG_PATH), &mut dhcp_budget);
        self.last_refresh_ms = now_ms;
        self.mtimes = mtimes;
        true
    }

    pub fn parse_leases(&mut self, contents: &str) {
        let mut budget = HOSTNAME_MAX_SOURCE_BYTES;
        for_each_bounded_line(contents.as_bytes(), &mut budget, |line| {
            self.parse_lease_line(line);
            self.by_mac.len() < self.capacity || self.by_ip.len() < self.capacity
        });
    }

    pub fn parse_hosts_file(&mut self, contents: &str) {
        let mut budget = HOSTNAME_MAX_SOURCE_BYTES;
        for_each_bounded_line(contents.as_bytes(), &mut budget, |line| {
            self.parse_hosts_line(line);
            self.by_ip.len() < self.capacity
        });
    }

    pub fn parse_dhcp_config(&mut self, contents: &str) {
        let mut budget = HOSTNAME_MAX_SOURCE_BYTES;
        let mut in_host = false;
        let mut macs = Vec::new();
        let mut ip = String::new();
        let mut name = String::new();
        for_each_bounded_line(contents.as_bytes(), &mut budget, |line| {
            let mut fields = line.trim_start().splitn(3, char::is_whitespace);
            let keyword = fields.next().unwrap_or_default();
            match keyword {
                "config" => {
                    if in_host {
                        self.add_dhcp_host(&macs, &ip, &name);
                    }
                    in_host = fields.next().unwrap_or_default() == "host";
                    macs.clear();
                    ip.clear();
                    name.clear();
                }
                "option" | "list" if in_host => {
                    let option = fields.next().unwrap_or_default();
                    let value = fields.next().unwrap_or_default();
                    match option {
                        "mac" => {
                            let values = parse_uci_values(value)
                                .into_iter()
                                .map(|value| bounded_ascii_token(&value, 17).to_ascii_lowercase());
                            if keyword == "option" {
                                macs = values.collect();
                            } else {
                                macs.extend(values);
                            }
                        }
                        "ip" => ip = bounded_ascii_token(&parse_uci_value(value), 45).to_owned(),
                        "name" => {
                            name = bounded_ascii_token(&parse_uci_value(value), 63).to_owned()
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
            true
        });
        if in_host {
            self.add_dhcp_host(&macs, &ip, &name);
        }
    }

    pub fn last_refresh_stats(&self) -> HostnameRefreshStats {
        self.last_refresh_stats
    }

    pub fn lookup<'a>(&'a self, mac: &str, ips: &[&str]) -> Option<&'a str> {
        if mac.parse::<MacAddress>().is_ok() {
            if let Some((_, name)) = self.by_mac.iter().find(|(candidate, _)| candidate == mac) {
                return Some(name);
            }
        }
        ips.iter().find_map(|ip| {
            self.by_ip
                .iter()
                .find(|(candidate, _)| candidate == ip)
                .map(|(_, name)| name.as_str())
        })
    }

    fn add_mac(&mut self, mac: &str, name: &str) {
        if mac.parse::<MacAddress>().is_err() || !hostname_valid(name) {
            return;
        }
        if self.by_mac.len() >= self.capacity {
            return;
        }
        if let Some((_, existing)) = Arc::make_mut(&mut self.by_mac)
            .iter_mut()
            .find(|(candidate, _)| candidate == mac)
        {
            *existing = name.to_owned();
            return;
        }
        Arc::make_mut(&mut self.by_mac).push((mac.to_owned(), name.to_owned()));
    }

    fn add_ip(&mut self, ip: &str, name: &str) {
        if ip.is_empty() || !hostname_valid(name) {
            return;
        }
        if self.by_ip.len() >= self.capacity {
            return;
        }
        if self.by_ip.iter().any(|(candidate, _)| candidate == ip) {
            return;
        }
        Arc::make_mut(&mut self.by_ip).push((ip.to_owned(), name.to_owned()));
    }

    fn add_ip_override(&mut self, ip: &str, name: &str) {
        if ip.is_empty() || !hostname_valid(name) {
            return;
        }
        if let Some((_, existing)) = Arc::make_mut(&mut self.by_ip)
            .iter_mut()
            .find(|(candidate, _)| candidate == ip)
        {
            *existing = name.to_owned();
            return;
        }
        self.add_ip(ip, name);
    }

    fn parse_leases_path(&mut self, path: &Path, budget: &mut usize) {
        if self.by_mac.len() >= self.capacity && self.by_ip.len() >= self.capacity {
            return;
        }
        let Ok(file) = fs::File::open(path) else {
            return;
        };
        let read = for_each_bounded_line(file, budget, |line| {
            self.parse_lease_line(line);
            self.by_mac.len() < self.capacity || self.by_ip.len() < self.capacity
        });
        self.last_refresh_stats.bytes_read += read;
    }

    fn parse_hosts_path(&mut self, path: &Path, budget: &mut usize) {
        if self.by_ip.len() >= self.capacity {
            return;
        }
        let Ok(file) = fs::File::open(path) else {
            return;
        };
        let read = for_each_bounded_line(file, budget, |line| {
            self.parse_hosts_line(line);
            self.by_ip.len() < self.capacity
        });
        self.last_refresh_stats.bytes_read += read;
    }

    fn parse_dhcp_config_path(&mut self, path: &Path, budget: &mut usize) {
        let Ok(file) = fs::File::open(path) else {
            return;
        };
        let mut contents = String::new();
        let read = file
            .take(*budget as u64)
            .read_to_string(&mut contents)
            .unwrap_or(0);
        *budget = (*budget).saturating_sub(read);
        self.last_refresh_stats.bytes_read += read;
        self.parse_dhcp_config(&contents);
    }

    fn add_dhcp_host(&mut self, macs: &[String], ip: &str, name: &str) {
        if !name.is_empty() {
            for mac in macs {
                self.add_mac(mac, name);
            }
            self.add_ip_override(ip, name);
        }
    }

    fn parse_lease_line(&mut self, line: &str) {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 4 || columns[0].parse::<u64>().is_err() {
            return;
        }
        let mac = bounded_ascii_token(columns[1], 17);
        let ip = bounded_ascii_token(columns[2], 45);
        let name = bounded_ascii_token(columns[3], 63);
        let mac = mac.to_ascii_lowercase();
        self.add_mac(&mac, name);
        self.add_ip(ip, name);
    }

    fn parse_hosts_line(&mut self, line: &str) {
        let line = line.split('#').next().unwrap_or_default();
        let mut columns = line.split_whitespace();
        let Some(ip) = columns.next() else { return };
        let Some(name) = columns.next() else { return };
        let ip = bounded_ascii_token(ip, 45);
        let name = bounded_ascii_token(name, 63);
        if ip == "127.0.0.1" || ip == "::1" {
            return;
        }
        self.add_ip(ip, name);
    }
}

fn for_each_bounded_line<R, F>(mut reader: R, budget: &mut usize, mut visit: F) -> usize
where
    R: Read,
    F: FnMut(&str) -> bool,
{
    let mut read_total = 0usize;
    let mut buffer = [0u8; HOSTNAME_READ_BUFFER_BYTES];
    let mut line = Vec::with_capacity(HOSTNAME_MAX_LINE_BYTES);
    let mut overlong = false;
    let mut reached_eof = false;
    let mut keep_reading = true;

    while *budget > 0 && keep_reading {
        let limit = buffer.len().min(*budget);
        let read = match reader.read(&mut buffer[..limit]) {
            Ok(0) => {
                reached_eof = true;
                break;
            }
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        *budget -= read;
        read_total += read;
        for byte in &buffer[..read] {
            if *byte == b'\n' {
                if !overlong {
                    if let Ok(line) = std::str::from_utf8(&line) {
                        if !visit(line.trim_end_matches('\r')) {
                            keep_reading = false;
                            break;
                        }
                    }
                }
                line.clear();
                overlong = false;
            } else if line.len() < HOSTNAME_MAX_LINE_BYTES {
                line.push(*byte);
            } else {
                overlong = true;
            }
        }
    }

    if keep_reading && reached_eof && !line.is_empty() && !overlong {
        if let Ok(line) = std::str::from_utf8(&line) {
            let _ = visit(line.trim_end_matches('\r'));
        }
    }
    read_total
}

fn hostname_valid(name: &str) -> bool {
    !name.is_empty() && name != "*" && name != "-" && !name.chars().any(char::is_whitespace)
}

fn parse_uci_value(value: &str) -> String {
    let value = value.trim();
    let Some(quote) = value.as_bytes().first().copied() else {
        return String::new();
    };
    if quote != b'\'' && quote != b'"' {
        return value
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
    }
    let quote = quote as char;
    let mut result = String::new();
    let mut escaped = false;
    for character in value[1..].chars() {
        if escaped {
            result.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == quote {
            break;
        } else {
            result.push(character);
        }
    }
    result
}

fn parse_uci_values(value: &str) -> Vec<String> {
    let value = value.trim();
    if value.is_empty() {
        return Vec::new();
    }
    let mut values = Vec::new();
    let mut rest = value;
    while !rest.trim_start().is_empty() {
        rest = rest.trim_start();
        if rest.starts_with('\'') || rest.starts_with('"') {
            let quote = rest.as_bytes()[0] as char;
            let mut escaped = false;
            let mut end = None;
            for (index, character) in rest[1..].char_indices() {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == quote {
                    end = Some(index + 1);
                    break;
                }
            }
            let Some(end) = end else { break };
            values.push(parse_uci_value(&rest[..=end]));
            rest = &rest[end + 1..];
        } else {
            let (token, remainder) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            values.push(token.to_owned());
            rest = remainder;
        }
    }
    values
}

fn bounded_ascii_token(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn mtime(path: &Path) -> u64 {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn latest_directory_mtime(path: &Path) -> u64 {
    let mut latest = mtime(path);
    if let Ok(directory) = fs::read_dir(path) {
        let mut visible_files = 0usize;
        for result in directory.take(HOSTNAME_MAX_DIR_ENTRIES) {
            let Ok(entry) = result else { continue };
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            if visible_files == HOSTNAME_MAX_HOST_FILES {
                break;
            }
            visible_files += 1;
            latest = latest.max(mtime(&entry.path()));
        }
    }
    latest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_host_name_uses_mac_without_requiring_ip() {
        let mut cache = HostnameCache::with_capacity(8);
        cache.parse_dhcp_config(
            "config host 'cfg01'\n\toption mac '52:C4:FD:3F:36:EF'\n\toption name 'nas'\n",
        );
        assert_eq!(cache.lookup("52:c4:fd:3f:36:ef", &[]), Some("nas"));
    }

    #[test]
    fn dhcp_host_name_overrides_lease_name_for_mac_and_ip() {
        let mut cache = HostnameCache::with_capacity(8);
        cache.parse_leases("123 52:c4:fd:3f:36:ef 192.0.2.10 lease-name *\n");
        cache.parse_dhcp_config(
            "config host 'cfg01'\n\toption mac '52:C4:FD:3F:36:EF'\n\toption ip '192.0.2.10'\n\toption name 'custom-name'\n",
        );
        assert_eq!(cache.lookup("52:c4:fd:3f:36:ef", &[]), Some("custom-name"));
        assert_eq!(
            cache.lookup("00:11:22:33:44:55", &["192.0.2.10"]),
            Some("custom-name")
        );
    }

    #[test]
    fn dhcp_host_name_applies_to_each_mac_in_a_list() {
        let mut cache = HostnameCache::with_capacity(8);
        cache.parse_dhcp_config(
            "config host 'cfg01'\n\tlist mac '52:c4:fd:3f:36:ef'\n\tlist mac 'fe:25:75:2b:70:7d'\n\toption name 'nas'\n",
        );
        assert_eq!(cache.lookup("fe:25:75:2b:70:7d", &[]), Some("nas"));
    }
}
