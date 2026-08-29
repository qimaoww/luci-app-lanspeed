use super::{normalize_ip, ProxyConnectionSample, ProxySource};
use crate::{connection_details::ConnectionProtocol, identity::IdentityTable};
use aya::maps::{HashMap as BpfHashMap, Map, MapData, MapInfo, MapType};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

const PROC_ROOT: &str = "/proc";
const DAE_NETNS_PATHS: [&str; 2] = ["/var/run/netns/daens", "/run/netns/daens"];
const MAX_PROC_ENTRIES: usize = 65_536;
const MAX_DAE_PROCESSES: usize = 4;
const MAX_PROCESS_FDS: usize = 65_536;
const MAX_PROCESS_MAPS: usize = 1_024;
const MAX_SOCKET_TABLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROXY_CONNECTIONS: usize = 16_384;
const DAE_TUPLE_KEY_SIZE: usize = 40;
const DAE_UDP_STATE_SIZE: usize = 24;
const DAE_ROUTING_RESULT_SIZE: usize = 36;
const DAE_ROUTING_OUTBOUND_OFFSET: usize = 11;
const DAE_OUTBOUND_USER_MIN: u8 = 2;
const DAE_OUTBOUND_USER_MAX: u8 = 0xfb;
const MAX_DAE_UDP_MAP_ENTRIES: u32 = 1_048_576;

pub(super) fn read_samples(identities: &IdentityTable) -> io::Result<Vec<ProxyConnectionSample>> {
    read_samples_from(Path::new(PROC_ROOT), identities)
}

fn read_samples_from(
    proc_root: &Path,
    identities: &IdentityTable,
) -> io::Result<Vec<ProxyConnectionSample>> {
    let processes = dae_processes(proc_root)?;
    if processes.is_empty() {
        return Ok(Vec::new());
    }

    let mut samples = Vec::new();
    let mut emitted_inodes = BTreeSet::new();
    let mut owned_inodes = BTreeSet::new();
    let mut map_ids = BTreeSet::new();
    for process in &processes {
        let Ok(inodes) = process_socket_inodes(process) else {
            continue;
        };
        owned_inodes.extend(inodes);
        if let Ok(current) = process_map_ids(process) {
            map_ids.extend(current);
        }
    }

    // dae accepts transparent TCP sockets inside its dedicated `daens`
    // network namespace. `/proc/<daed-pid>/net/tcp*` follows the daemon's
    // root namespace instead and mostly contains controller and outbound
    // sockets, so it cannot recover LAN-facing logical connections.
    if !owned_inodes.is_empty() {
        for (bytes, ipv6) in read_dae_netns_socket_tables().unwrap_or_default() {
            let sockets = parse_socket_table(&bytes, ipv6)?;
            samples.extend(samples_from_sockets(
                identities,
                &owned_inodes,
                &mut emitted_inodes,
                sockets,
                MAX_PROXY_CONNECTIONS.saturating_sub(samples.len()),
            )?);
        }
    }

    // UDP does not create one process socket per logical flow. dae keeps live
    // UDP tuples in a timer-backed eBPF map. The map is not pinned, so resolve
    // only map IDs held by a running dae/daed process and require the official
    // name and ABI before reading it.
    if samples.len() < MAX_PROXY_CONNECTIONS {
        if let Ok(current) = udp_samples_from_maps(
            identities,
            &map_ids,
            MAX_PROXY_CONNECTIONS.saturating_sub(samples.len()),
        ) {
            samples.extend(current);
        }
    }

    Ok(samples)
}

fn read_dae_netns_socket_tables() -> io::Result<Vec<(Vec<u8>, bool)>> {
    let current =
        File::open("/proc/thread-self/ns/net").or_else(|_| File::open("/proc/self/ns/net"))?;
    let target = DAE_NETNS_PATHS
        .iter()
        .find_map(|path| File::open(path).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "dae network namespace missing"))?;

    set_network_namespace(&target)?;
    let result = [("tcp", false), ("tcp6", true)]
        .into_iter()
        .map(|(name, ipv6)| {
            read_bounded(
                &Path::new("/proc/thread-self/net").join(name),
                MAX_SOCKET_TABLE_BYTES,
            )
            .or_else(|_| {
                read_bounded(
                    &Path::new("/proc/self/net").join(name),
                    MAX_SOCKET_TABLE_BYTES,
                )
            })
            .map(|bytes| (bytes, ipv6))
        })
        .collect::<io::Result<Vec<_>>>();
    let restored = set_network_namespace(&current);
    match (result, restored) {
        (_, Err(error)) => Err(io::Error::new(
            error.kind(),
            format!("failed to restore network namespace: {error}"),
        )),
        (result, Ok(())) => result,
    }
}

fn set_network_namespace(namespace: &File) -> io::Result<()> {
    // SAFETY: `namespace` is an open namespace descriptor and setns only
    // changes the calling OS thread. The caller retains and restores the
    // original namespace descriptor before returning.
    if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn udp_samples_from_maps(
    identities: &IdentityTable,
    map_ids: &BTreeSet<u32>,
    remaining: usize,
) -> io::Result<Vec<ProxyConnectionSample>> {
    let routing_map = dae_map_by_abi::<DAE_ROUTING_RESULT_SIZE>(
        map_ids,
        "routing_tuples",
        &[MapType::LruHash, MapType::Hash],
    )?
    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "dae routing map missing"))?;
    let mut samples = Vec::new();
    let mut emitted = BTreeSet::new();
    for &map_id in map_ids {
        let Ok(info) = MapInfo::from_id(map_id) else {
            continue;
        };
        let name = std::str::from_utf8(info.name()).unwrap_or_default();
        if !name.starts_with("udp_conn_state")
            || info.map_type().ok() != Some(MapType::Hash)
            || info.key_size() != DAE_TUPLE_KEY_SIZE as u32
            || info.value_size() != DAE_UDP_STATE_SIZE as u32
            || info.max_entries() > MAX_DAE_UDP_MAP_ENTRIES
        {
            continue;
        }
        let data = MapData::from_id(map_id).map_err(aya_error)?;
        let map = Map::from_map_data(data).map_err(aya_error)?;
        let map =
            BpfHashMap::<_, [u8; DAE_TUPLE_KEY_SIZE], [u8; DAE_UDP_STATE_SIZE]>::try_from(map)
                .map_err(aya_error)?;
        for key in map.keys() {
            let key = key.map_err(aya_error)?;
            if !emitted.insert(key) {
                continue;
            }
            let Ok(routing) = routing_map.get(&key, 0) else {
                continue;
            };
            if !dae_routing_is_proxied(&routing) {
                continue;
            }
            let tuple = parse_dae_tuple(&key)?;
            if tuple.protocol != ConnectionProtocol::Udp {
                continue;
            }
            let generation = format!(
                "udp:{}:{}>{}:{}",
                tuple.source_ip, tuple.source_port, tuple.destination_ip, tuple.destination_port
            );
            let Some(sample) = sample_from_endpoints(
                identities,
                generation,
                tuple.source_ip,
                tuple.source_port,
                tuple.destination_ip,
                tuple.destination_port,
                tuple.protocol,
            ) else {
                continue;
            };
            if samples.len() >= remaining {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "dae connection count exceeds limit",
                ));
            }
            samples.push(sample);
        }
    }
    Ok(samples)
}

fn dae_map_by_abi<const VALUE_SIZE: usize>(
    map_ids: &BTreeSet<u32>,
    name_prefix: &str,
    map_types: &[MapType],
) -> io::Result<Option<BpfHashMap<MapData, [u8; DAE_TUPLE_KEY_SIZE], [u8; VALUE_SIZE]>>> {
    for &map_id in map_ids {
        let Ok(info) = MapInfo::from_id(map_id) else {
            continue;
        };
        let name = std::str::from_utf8(info.name()).unwrap_or_default();
        if !name.starts_with(name_prefix)
            || !info
                .map_type()
                .is_ok_and(|map_type| map_types.contains(&map_type))
            || info.key_size() != DAE_TUPLE_KEY_SIZE as u32
            || info.value_size() != VALUE_SIZE as u32
            || info.max_entries() > MAX_DAE_UDP_MAP_ENTRIES
        {
            continue;
        }
        let data = MapData::from_id(map_id).map_err(aya_error)?;
        let map = Map::from_map_data(data).map_err(aya_error)?;
        return BpfHashMap::<_, [u8; DAE_TUPLE_KEY_SIZE], [u8; VALUE_SIZE]>::try_from(map)
            .map(Some)
            .map_err(aya_error);
    }
    Ok(None)
}

fn dae_routing_is_proxied(routing: &[u8; DAE_ROUTING_RESULT_SIZE]) -> bool {
    (DAE_OUTBOUND_USER_MIN..=DAE_OUTBOUND_USER_MAX).contains(&routing[DAE_ROUTING_OUTBOUND_OFFSET])
}

fn aya_error(error: aya::maps::MapError) -> io::Error {
    io::Error::other(error.to_string())
}

fn process_map_ids(process: &Path) -> io::Result<BTreeSet<u32>> {
    let mut ids = BTreeSet::new();
    for (scanned, entry) in fs::read_dir(process.join("fdinfo"))?.enumerate() {
        if scanned >= MAX_PROCESS_FDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dae file descriptor table exceeds limit",
            ));
        }
        let Ok(bytes) = read_bounded(&entry?.path(), 4 * 1024) else {
            continue;
        };
        let Some(id) = parse_map_id(&bytes)? else {
            continue;
        };
        ids.insert(id);
        if ids.len() > MAX_PROCESS_MAPS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dae map count exceeds limit",
            ));
        }
    }
    Ok(ids)
}

fn parse_map_id(bytes: &[u8]) -> io::Result<Option<u32>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fdinfo is not UTF-8"))?;
    let Some(value) = text
        .lines()
        .find_map(|line| line.strip_prefix("map_id:").map(str::trim))
    else {
        return Ok(None);
    };
    value
        .parse::<u32>()
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid BPF map id"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DaeTuple {
    source_ip: IpAddr,
    source_port: u16,
    destination_ip: IpAddr,
    destination_port: u16,
    protocol: ConnectionProtocol,
}

fn parse_dae_tuple(key: &[u8; DAE_TUPLE_KEY_SIZE]) -> io::Result<DaeTuple> {
    let source_ip = normalize_ip(IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&key[0..16]).expect("fixed tuple source length"),
    )));
    let destination_ip = normalize_ip(IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&key[16..32]).expect("fixed tuple destination length"),
    )));
    let source_port = u16::from_be_bytes([key[32], key[33]]);
    let destination_port = u16::from_be_bytes([key[34], key[35]]);
    let protocol = match key[36] {
        6 => ConnectionProtocol::Tcp,
        17 => ConnectionProtocol::Udp,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported dae tuple protocol",
            ));
        }
    };
    if source_port == 0 || destination_port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dae tuple has zero port",
        ));
    }
    Ok(DaeTuple {
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
    })
}

fn sample_from_endpoints(
    identities: &IdentityTable,
    generation: String,
    source_ip: IpAddr,
    source_port: u16,
    destination_ip: IpAddr,
    destination_port: u16,
    protocol: ConnectionProtocol,
) -> Option<ProxyConnectionSample> {
    let source_ip = normalize_ip(source_ip);
    let destination_ip = normalize_ip(destination_ip);
    let (client_ip, client_port, remote_ip, remote_port) =
        if identities.by_ip(&source_ip.to_string()).is_some() {
            (source_ip, source_port, destination_ip, destination_port)
        } else if identities.by_ip(&destination_ip.to_string()).is_some() {
            (destination_ip, destination_port, source_ip, source_port)
        } else {
            return None;
        };
    if remote_ip.is_unspecified()
        || remote_ip.is_loopback()
        || remote_ip.is_multicast()
        || remote_ip == client_ip
    {
        return None;
    }
    Some(ProxyConnectionSample {
        source: ProxySource::Dae,
        generation,
        client_ip,
        client_port,
        remote_ip: Some(remote_ip),
        remote_port,
        protocol,
        tx_bytes: None,
        rx_bytes: None,
    })
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
        let Some(sample) = sample_from_endpoints(
            identities,
            format!("socket:{}", socket.inode),
            socket.remote_ip,
            socket.remote_port,
            socket.local_ip,
            socket.local_port,
            ConnectionProtocol::Tcp,
        ) else {
            continue;
        };
        if samples.len() >= remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dae connection count exceeds limit",
            ));
        }
        // Socket tables prove ownership and endpoints but do not expose
        // cumulative byte counters. Existing conntrack rates are retained
        // when a matching detail is present.
        samples.push(sample);
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

    fn tuple_key(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination_port: u16,
        protocol: u8,
    ) -> [u8; DAE_TUPLE_KEY_SIZE] {
        let mut key = [0; DAE_TUPLE_KEY_SIZE];
        let source = match source_ip {
            IpAddr::V4(address) => address.to_ipv6_mapped().octets(),
            IpAddr::V6(address) => address.octets(),
        };
        let destination = match destination_ip {
            IpAddr::V4(address) => address.to_ipv6_mapped().octets(),
            IpAddr::V6(address) => address.octets(),
        };
        key[0..16].copy_from_slice(&source);
        key[16..32].copy_from_slice(&destination);
        key[32..34].copy_from_slice(&source_port.to_be_bytes());
        key[34..36].copy_from_slice(&destination_port.to_be_bytes());
        key[36] = protocol;
        key
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

    #[test]
    fn parses_dae_udp_tuple_abi_and_orients_client_endpoint() {
        let key = tuple_key(
            "192.0.2.10".parse().unwrap(),
            50_123,
            "2001:db8::20".parse().unwrap(),
            4_433,
            17,
        );
        let tuple = parse_dae_tuple(&key).unwrap();
        assert_eq!(tuple.source_ip, "192.0.2.10".parse::<IpAddr>().unwrap());
        assert_eq!(
            tuple.destination_ip,
            "2001:db8::20".parse::<IpAddr>().unwrap()
        );
        assert_eq!((tuple.source_port, tuple.destination_port), (50_123, 4_433));
        assert_eq!(tuple.protocol, ConnectionProtocol::Udp);

        let sample = sample_from_endpoints(
            &identities(),
            "udp:test".into(),
            tuple.destination_ip,
            tuple.destination_port,
            tuple.source_ip,
            tuple.source_port,
            tuple.protocol,
        )
        .unwrap();
        assert_eq!(sample.client_ip, tuple.source_ip);
        assert_eq!(sample.client_port, tuple.source_port);
        assert_eq!(sample.remote_ip, Some(tuple.destination_ip));
        assert_eq!(sample.remote_port, tuple.destination_port);
    }

    #[test]
    fn rejects_non_tcp_udp_dae_tuple_protocol() {
        let key = tuple_key(
            "192.0.2.10".parse().unwrap(),
            50_123,
            "198.51.100.20".parse().unwrap(),
            443,
            1,
        );
        assert!(parse_dae_tuple(&key).is_err());
    }

    #[test]
    fn parses_only_bpf_map_ids_from_fdinfo() {
        assert_eq!(parse_map_id(b"pos:\t0\nflags:\t02000002\n").unwrap(), None);
        assert_eq!(
            parse_map_id(b"pos:\t0\nmap_type:\t1\nmap_id:\t207\n").unwrap(),
            Some(207)
        );
        assert!(parse_map_id(b"map_id:\tnot-a-number\n").is_err());
    }

    #[test]
    fn accepts_only_user_defined_proxy_outbounds() {
        for outbound in [DAE_OUTBOUND_USER_MIN, 8, DAE_OUTBOUND_USER_MAX] {
            let mut routing = [0; DAE_ROUTING_RESULT_SIZE];
            routing[DAE_ROUTING_OUTBOUND_OFFSET] = outbound;
            assert!(dae_routing_is_proxied(&routing));
        }
        for outbound in [0, 1, 0xfc, 0xfd, 0xfe, 0xff] {
            let mut routing = [0; DAE_ROUTING_RESULT_SIZE];
            routing[DAE_ROUTING_OUTBOUND_OFFSET] = outbound;
            assert!(!dae_routing_is_proxied(&routing));
        }
    }
}
