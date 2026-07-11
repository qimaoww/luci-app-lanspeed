use super::MacAddress;
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

pub const HOSTNAME_CACHE_MAX: usize = 1024;
pub const HOSTNAME_REFRESH_MS: u64 = 10_000;
pub const HOSTNAME_MAX_LINE_BYTES: usize = 512;
pub const HOSTNAME_MAX_SOURCE_BYTES: usize = 1024 * 1024;
pub const HOSTNAME_MAX_HOST_FILES: usize = HOSTNAME_CACHE_MAX;
pub const HOSTNAME_MAX_DIR_ENTRIES: usize = HOSTNAME_MAX_HOST_FILES * 4;
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
    by_mac: Vec<(String, String)>,
    by_ip: Vec<(String, String)>,
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
            by_mac: Vec::new(),
            by_ip: Vec::new(),
            last_refresh_ms: 0,
            mtimes: SourceMtimes::default(),
            last_refresh_stats: HostnameRefreshStats::default(),
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
