use super::MacAddress;
use std::{
    fs,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

pub const HOSTNAME_CACHE_MAX: usize = 1024;
pub const HOSTNAME_REFRESH_MS: u64 = 10_000;

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
}

#[derive(Clone, Debug)]
pub struct HostnameCache {
    capacity: usize,
    by_mac: Vec<(String, String)>,
    by_ip: Vec<(String, String)>,
    last_refresh_ms: u64,
    mtimes: SourceMtimes,
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
            by_mac: Vec::new(),
            by_ip: Vec::new(),
            last_refresh_ms: 0,
            mtimes: SourceMtimes::default(),
        }
    }

    pub fn refresh_from_paths(&mut self, paths: &HostnamePaths, now_ms: u64, force: bool) -> bool {
        let mtimes = SourceMtimes {
            leases: mtime(&paths.leases),
            hosts_dir: latest_directory_mtime(&paths.hosts_dir),
            etc_hosts: mtime(&paths.etc_hosts),
        };
        let changed = force || mtimes != self.mtimes;
        if !changed
            && self.last_refresh_ms != 0
            && now_ms.wrapping_sub(self.last_refresh_ms) < HOSTNAME_REFRESH_MS
        {
            return false;
        }

        self.by_mac.clear();
        self.by_ip.clear();
        if let Ok(contents) = fs::read_to_string(&paths.leases) {
            self.parse_leases(&contents);
        }
        if let Ok(directory) = fs::read_dir(&paths.hosts_dir) {
            for entry in directory.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with('.') {
                    continue;
                }
                if let Ok(contents) = fs::read_to_string(entry.path()) {
                    self.parse_hosts_file(&contents);
                }
            }
        }
        if let Ok(contents) = fs::read_to_string(&paths.etc_hosts) {
            self.parse_hosts_file(&contents);
        }
        self.last_refresh_ms = now_ms;
        self.mtimes = mtimes;
        true
    }

    pub fn parse_leases(&mut self, contents: &str) {
        for line in contents.lines() {
            let columns = line.split_whitespace().collect::<Vec<_>>();
            if columns.len() < 4 || columns[0].parse::<u64>().is_err() {
                continue;
            }
            let mac = bounded_ascii_token(columns[1], 17);
            let ip = bounded_ascii_token(columns[2], 45);
            let name = bounded_ascii_token(columns[3], 63);
            let mac = mac.to_ascii_lowercase();
            self.add_mac(&mac, name);
            self.add_ip(ip, name);
        }
    }

    pub fn parse_hosts_file(&mut self, contents: &str) {
        for line in contents.lines() {
            let line = line.split('#').next().unwrap_or_default();
            let mut columns = line.split_whitespace();
            let Some(ip) = columns.next() else { continue };
            let Some(name) = columns.next() else { continue };
            let ip = bounded_ascii_token(ip, 45);
            let name = bounded_ascii_token(name, 63);
            if ip == "127.0.0.1" || ip == "::1" {
                continue;
            }
            self.add_ip(ip, name);
        }
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
        if let Some((_, existing)) = self
            .by_mac
            .iter_mut()
            .find(|(candidate, _)| candidate == mac)
        {
            *existing = name.to_owned();
            return;
        }
        self.by_mac.push((mac.to_owned(), name.to_owned()));
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
        self.by_ip.push((ip.to_owned(), name.to_owned()));
    }
}

fn hostname_valid(name: &str) -> bool {
    !name.is_empty() && name != "*" && name != "-" && !name.chars().any(char::is_whitespace)
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
        for entry in directory.flatten() {
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            latest = latest.max(mtime(&entry.path()));
        }
    }
    latest
}
