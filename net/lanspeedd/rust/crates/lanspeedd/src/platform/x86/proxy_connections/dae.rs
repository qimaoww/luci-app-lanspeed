use super::{normalize_ip, ProxyConnectionSample, ProxySource};
use crate::{connection_details::ConnectionProtocol, identity::IdentityTable};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

const PROC_ROOT: &str = "/proc";
const MAX_PROC_ENTRIES: usize = 65_536;
const MAX_DAE_PROCESSES: usize = 4;
const MAX_PROCESS_FDS: usize = 65_536;
const MAX_SOCKET_TABLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROXY_CONNECTIONS: usize = 16_384;

pub(super) fn read_samples(identities: &IdentityTable) -> io::Result<Vec<ProxyConnectionSample>> {
    read_samples_from(Path::new(PROC_ROOT), identities)
}

fn read_samples_from(
    proc_root: &Path,
    identities: &IdentityTable,
) -> io::Result<Vec<ProxyConnectionSample>> {
    let processes = dae_processes(proc_root)?;
    let mut samples = Vec::new();
    let mut emitted_inodes = BTreeSet::new();
    for process in processes {
        let Ok(inodes) = process_socket_inodes(&process) else {
            continue;
        };
        if inodes.is_empty() {
            continue;
        }
        for (name, ipv6) in [("tcp", false), ("tcp6", true)] {
            let path = process.join("net").join(name);
            let Ok(bytes) = read_bounded(&path, MAX_SOCKET_TABLE_BYTES) else {
                continue;
            };
            let sockets = parse_socket_table(&bytes, ipv6)?;
            samples.extend(samples_from_sockets(
                identities,
                &inodes,
                &mut emitted_inodes,
                sockets,
                MAX_PROXY_CONNECTIONS.saturating_sub(samples.len()),
            )?);
        }
    }
    Ok(samples)
}

fn samples_from_sockets(
    identities: &IdentityTable,
    owned_inodes: &BTreeSet<u64>,
    emitted_inodes: &mut BTreeSet<u64>,
    sockets: impl IntoIterator<Item = ProcessTcpSocket>,
    remaining: usize,
) -> io::Result<Vec<ProxyConnectionSample>> {
    let mut samples = Vec::new();
    for socket in sockets {
        if !owned_inodes.contains(&socket.inode) || !emitted_inodes.insert(socket.inode) {
            continue;
        }
        let client_ip = normalize_ip(socket.remote_ip);
        if identities.by_ip(&client_ip.to_string()).is_none() {
            continue;
        }
        if samples.len() >= remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dae connection count exceeds limit",
            ));
        }
        let remote_ip = normalize_ip(socket.local_ip);
        let remote_ip =
            (!remote_ip.is_unspecified() && !remote_ip.is_loopback() && !remote_ip.is_multicast())
                .then_some(remote_ip);
        samples.push(ProxyConnectionSample {
            source: ProxySource::Dae,
            generation: format!("socket:{}", socket.inode),
            client_ip,
            client_port: socket.remote_port,
            remote_ip,
            remote_port: socket.local_port,
            protocol: ConnectionProtocol::Tcp,
            // /proc socket tables prove ownership and endpoints but do not
            // expose cumulative byte counters. Existing conntrack rates are
            // retained when a matching detail is present.
            tx_bytes: None,
            rx_bytes: None,
        });
    }
    Ok(samples)
}

fn dae_processes(proc_root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut processes = Vec::new();
    for (scanned, entry) in fs::read_dir(proc_root)?.enumerate() {
        if scanned >= MAX_PROC_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process table exceeds limit",
            ));
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(pid) = name.to_str() else {
            continue;
        };
        if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(comm) = read_bounded(&entry.path().join("comm"), 64) else {
            continue;
        };
        let comm = trim_ascii(&comm);
        if comm != b"dae" && comm != b"daed" {
            continue;
        }
        processes.push(entry.path());
        if processes.len() >= MAX_DAE_PROCESSES {
            break;
        }
    }
    Ok(processes)
}

fn process_socket_inodes(process: &Path) -> io::Result<BTreeSet<u64>> {
    let mut inodes = BTreeSet::new();
    for (scanned, entry) in fs::read_dir(process.join("fd"))?.enumerate() {
        if scanned >= MAX_PROCESS_FDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dae file descriptor table exceeds limit",
            ));
        }
        let Ok(target) = fs::read_link(entry?.path()) else {
            continue;
        };
        let Some(target) = target.to_str() else {
            continue;
        };
        let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        inodes.insert(inode);
    }
    Ok(inodes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessTcpSocket {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    inode: u64,
}

fn parse_socket_table(bytes: &[u8], ipv6: bool) -> io::Result<Vec<ProcessTcpSocket>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "socket table is not UTF-8"))?;
    let mut sockets = Vec::new();
    for line in text.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 || fields[3] != "01" {
            continue;
        }
        let (local_ip, local_port) = parse_endpoint(fields[1], ipv6)?;
        let (remote_ip, remote_port) = parse_endpoint(fields[2], ipv6)?;
        let inode = fields[9]
            .parse::<u64>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid socket inode"))?;
        if inode == 0 || local_port == 0 || remote_port == 0 {
            continue;
        }
        sockets.push(ProcessTcpSocket {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            inode,
        });
    }
    Ok(sockets)
}

fn parse_endpoint(value: &str, ipv6: bool) -> io::Result<(IpAddr, u16)> {
    let (address, port) = value.split_once(':').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "socket endpoint missing port")
    })?;
    let port = u16::from_str_radix(port, 16)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid socket port"))?;
    let address = if ipv6 {
        if address.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IPv6 socket address",
            ));
        }
        let mut octets = [0u8; 16];
        for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
            let text = std::str::from_utf8(chunk).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid IPv6 socket address")
            })?;
            let word = u32::from_str_radix(text, 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid IPv6 socket address")
            })?;
            octets[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        if address.len() != 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IPv4 socket address",
            ));
        }
        let word = u32::from_str_radix(address, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid IPv4 address"))?;
        IpAddr::V4(Ipv4Addr::from(word.to_le_bytes()))
    };
    Ok((address, port))
}

fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "procfs file exceeds limit",
        ));
    }
    Ok(bytes)
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityObservation, ObservationSource};

    fn identities() -> IdentityTable {
        let mut table = IdentityTable::new(2);
        table
            .observe(IdentityObservation {
                mac: "02:00:00:00:00:01",
                zone: Some("lan"),
                interface: "br-lan",
                ip: Some("192.0.2.10"),
                hostname: None,
                last_seen: 1,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
        table
    }

    #[test]
    fn parses_process_tcp_tables_in_client_direction() {
        let ipv4 = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
          0: 146433C6:01BB 0A0200C0:C3CB 01 00000000:00000000 00:00000000 00000000 0 0 12345\n";
        let sockets = parse_socket_table(ipv4, false).unwrap();
        assert_eq!(sockets.len(), 1);
        assert_eq!(
            sockets[0].local_ip,
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            sockets[0].remote_ip,
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            (sockets[0].local_port, sockets[0].remote_port),
            (443, 50_123)
        );

        let ipv6 = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
          0: B80D0120000000000000000020000000:01BB 0000000000000000FFFF00000A0200C0:C3CB 01 00000000:00000000 00:00000000 00000000 0 0 12346\n";
        let sockets = parse_socket_table(ipv6, true).unwrap();
        assert_eq!(
            normalize_ip(sockets[0].remote_ip),
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_non_established_and_malformed_rows() {
        let header = "sl local_address rem_address st tx rx tr when retr uid timeout inode\n";
        let closed = format!("{header}0: 146433C6:01BB 0A0200C0:C3CB 06 0:0 0:0 0 0 0 123\n");
        assert!(parse_socket_table(closed.as_bytes(), false)
            .unwrap()
            .is_empty());
        let malformed = format!("{header}0: broken 0A0200C0:C3CB 01 0:0 0:0 0 0 0 123\n");
        assert!(parse_socket_table(malformed.as_bytes(), false).is_err());
    }

    #[test]
    fn identity_filter_only_accepts_lan_owned_remote_endpoint() {
        let table = identities();
        let sockets = [
            ProcessTcpSocket {
                local_ip: "198.51.100.20".parse().unwrap(),
                local_port: 443,
                remote_ip: "192.0.2.10".parse().unwrap(),
                remote_port: 50_123,
                inode: 10,
            },
            ProcessTcpSocket {
                local_ip: "198.51.100.30".parse().unwrap(),
                local_port: 443,
                remote_ip: "203.0.113.10".parse().unwrap(),
                remote_port: 50_124,
                inode: 11,
            },
        ];
        let mut emitted = BTreeSet::new();
        let samples =
            samples_from_sockets(&table, &BTreeSet::from([10, 11]), &mut emitted, sockets, 8)
                .unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].source, ProxySource::Dae);
        assert_eq!(
            samples[0].client_ip,
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(samples[0].remote_ip, Some("198.51.100.20".parse().unwrap()));
        assert_eq!(
            (samples[0].client_port, samples[0].remote_port),
            (50_123, 443)
        );
        assert_eq!((samples[0].tx_bytes, samples[0].rx_bytes), (None, None));
    }
}
