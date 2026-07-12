use lanspeedd::identity::{
    arp::parse_arp_table,
    filter::{IdentityFilter, InterfacePrefix},
    hostname::{
        HostnameCache, HostnamePaths, HOSTNAME_CACHE_MAX, HOSTNAME_MAX_DIR_ENTRIES,
        HOSTNAME_MAX_HOST_FILES, HOSTNAME_MAX_LINE_BYTES, HOSTNAME_MAX_SOURCE_BYTES,
        HOSTNAME_REFRESH_MS,
    },
    netlink::{parse_ipv6_neighbor_dump, parse_ipv6_neighbor_messages, NetlinkParseError},
    FrameKind, IdentityObservation, IdentityPolicy, IdentityTable, LegacyZoneResolver,
    ObservationSource,
};
use serde_json::Value;
use std::{fs, net::IpAddr, path::PathBuf, str::FromStr};

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/../../../../../tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn observe_json(identities: &mut IdentityTable, source: &Value, kind: ObservationSource) {
    identities
        .observe(IdentityObservation {
            mac: source["mac"].as_str().unwrap(),
            zone: source["zone"].as_str(),
            interface: source["interface"].as_str().unwrap(),
            ip: source["ip"].as_str(),
            hostname: source["hostname"].as_str(),
            last_seen: source["last_seen"].as_u64().unwrap_or(0),
            source: kind,
        })
        .unwrap();
}

#[test]
fn fixture_multi_ip_addresses_are_attributes_of_one_mac_zone_identity() {
    let fixture = fixture("lanspeed-identity-multi-ip.json");
    let mut identities = IdentityTable::new(16);

    for router_mac in fixture["router"]["macs"].as_array().unwrap() {
        identities
            .exclude_router_mac(router_mac.as_str().unwrap())
            .unwrap();
    }
    for source in fixture["sources"]["netifd"].as_array().unwrap() {
        if source["role"] == "router" {
            identities
                .exclude_router_mac(source["mac"].as_str().unwrap())
                .unwrap();
            assert!(identities
                .by_mac_zone(
                    source["mac"].as_str().unwrap(),
                    source["zone"].as_str().unwrap(),
                )
                .is_none());
            assert!(!source["interface"].as_str().unwrap().is_empty());
        }
    }
    for source in fixture["sources"]["dhcp_leases"].as_array().unwrap() {
        identities
            .observe(IdentityObservation {
                mac: source["mac"].as_str().unwrap(),
                zone: source["zone"].as_str(),
                interface: source["interface"].as_str().unwrap(),
                ip: source["ip"].as_str(),
                hostname: source["hostname"].as_str(),
                last_seen: source["last_seen"].as_u64().unwrap(),
                source: ObservationSource::DhcpLease,
            })
            .unwrap();
    }
    for source in fixture["sources"]["neighbors"].as_array().unwrap() {
        identities
            .observe(IdentityObservation {
                mac: source["mac"].as_str().unwrap(),
                zone: source["zone"].as_str(),
                interface: source["interface"].as_str().unwrap(),
                ip: source["ip"].as_str(),
                hostname: None,
                last_seen: source["last_seen"].as_u64().unwrap(),
                source: ObservationSource::Neighbor,
            })
            .unwrap();
    }
    for source in fixture["sources"]["wireless"].as_array().unwrap() {
        observe_json(&mut identities, source, ObservationSource::Wireless);
    }

    for traffic in fixture["sources"]["traffic"].as_array().unwrap() {
        if let Some(remote_ip) = traffic["remote_ip"].as_str() {
            identities.exclude_remote_ip(remote_ip);
            assert!(identities.by_ip(remote_ip).is_none());
        }
        assert!(identities
            .traffic_owner(
                traffic["mac"].as_str().unwrap(),
                traffic["zone"].as_str().unwrap(),
                None,
                FrameKind::Unicast,
            )
            .is_some());
    }

    assert_eq!(identities.clients().len(), 1);
    assert_eq!(identities.iter().count(), 1);
    let merged = identities.by_mac_zone("02:11:22:33:44:55", "lan").unwrap();
    assert_eq!(merged, identities.by_ip("192.168.1.42").unwrap());
    assert_eq!(merged, identities.by_ip("fd00:0:0:0:0:0:0:42").unwrap());
    let clients = identities.into_clients();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].key.to_string(), "02:11:22:33:44:55@lan");
    assert_eq!(clients[0].interface, "wlan0");
    assert_eq!(clients[0].hostname.as_deref(), Some("workstation"));
    assert_eq!(clients[0].last_seen, 1_710_000_006);
    assert_eq!(
        clients[0]
            .ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["192.168.1.42", "fd00::42"]
    );
}

#[test]
fn router_fixture_never_creates_a_router_client() {
    let fixture = fixture("lanspeed-identity-router-mac-excluded.json");
    let mut identities = IdentityTable::new(16);
    for mac in fixture["router"]["macs"].as_array().unwrap() {
        identities
            .exclude_router_mac(mac.as_str().unwrap())
            .unwrap();
    }
    for source in fixture["sources"]["netifd"].as_array().unwrap() {
        if source["role"] == "router" {
            identities
                .exclude_router_mac(source["mac"].as_str().unwrap())
                .unwrap();
            assert!(identities
                .by_mac_zone(
                    source["mac"].as_str().unwrap(),
                    source["zone"].as_str().unwrap(),
                )
                .is_none());
            assert!(!source["interface"].as_str().unwrap().is_empty());
        }
    }
    for source in fixture["sources"]["neighbors"].as_array().unwrap() {
        if source["role"] == "router" {
            identities
                .exclude_router_mac(source["mac"].as_str().unwrap())
                .unwrap();
        }
    }
    for source in fixture["sources"]["neighbors"].as_array().unwrap() {
        observe_json(&mut identities, source, ObservationSource::Neighbor);
    }

    for traffic in fixture["sources"]["traffic"].as_array().unwrap() {
        let kind =
            FrameKind::from_str(traffic["frame_type"].as_str().unwrap_or("unicast")).unwrap();
        let owner = identities.traffic_owner(
            traffic["mac"].as_str().unwrap(),
            traffic["zone"].as_str().unwrap(),
            None,
            kind,
        );
        assert_eq!(owner.is_some(), kind == FrameKind::Unicast);
    }

    let clients = identities.into_clients();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].key.to_string(), "02:aa:bb:cc:dd:ee@lan");
    assert_eq!(clients[0].interface, "br-lan");
    assert_eq!(clients[0].hostname, None);
    assert_eq!(clients[0].last_seen, 1_710_000_112);
    assert_eq!(clients[0].ips, ["192.168.1.50", "fe80::2aa:bbff:fecc:ddee"]);
}

#[test]
fn topology_fixture_keeps_same_mac_in_distinct_vlan_zones() {
    let fixture = fixture("lanspeed-topology-vlan.json");
    let mut identities = IdentityTable::new(16);
    let observations = fixture["observations"].as_array().unwrap();
    let mut arp = String::from(
        "IP address       HW type     Flags       HW address            Mask     Device\n",
    );
    for (index, source) in observations.iter().enumerate() {
        arp.push_str(&format!(
            "192.0.2.{} 0x1 0x2 {} * {}\n",
            index + 1,
            source["mac"].as_str().unwrap(),
            source["interface"].as_str().unwrap(),
        ));
    }
    let resolve_zone = |ifname: &str| {
        observations
            .iter()
            .find(|source| source["interface"].as_str() == Some(ifname))
            .and_then(|source| source["zone"].as_str())
            .map(str::to_owned)
    };
    for entry in parse_arp_table(&arp, 16, &IdentityFilter::disabled(), &resolve_zone) {
        let mac = entry.mac.to_string();
        identities
            .observe(IdentityObservation {
                mac: &mac,
                zone: Some(&entry.zone),
                interface: &entry.interface,
                ip: Some(&entry.ip),
                hostname: None,
                last_seen: 0,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
    }
    for source in fixture["uplink_observations"].as_array().unwrap() {
        let identity_key = source["encapsulated_client_identity"].as_str().unwrap();
        let (mac, zone) = identity_key.split_once('@').unwrap();
        assert!(identities.by_mac_zone(mac, zone).is_some());
        assert!(!identities
            .observe(IdentityObservation {
                mac: "02:00:00:00:00:01",
                zone: Some("must-not-exist"),
                interface: source["interface"].as_str().unwrap(),
                ip: Some("203.0.113.1"),
                hostname: None,
                last_seen: 0,
                source: ObservationSource::Neighbor,
            })
            .unwrap());
    }

    assert_eq!(
        identities.warnings(),
        fixture["expected"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    let keys = identities
        .into_clients()
        .into_iter()
        .map(|client| client.key.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        fixture["expected"]["identity_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
}

#[test]
fn control_fixture_only_allows_unicast_client_ownership() {
    let fixture = fixture("lanspeed-identity-excluded-control.json");
    let mut identities = IdentityTable::new(16);
    for mac in fixture["router"]["macs"].as_array().unwrap() {
        identities
            .exclude_router_mac(mac.as_str().unwrap())
            .unwrap();
    }
    for source in fixture["sources"]["dhcp_leases"].as_array().unwrap() {
        observe_json(&mut identities, source, ObservationSource::DhcpLease);
    }

    let eligible = fixture["sources"]["traffic"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            identities
                .traffic_owner(
                    entry["mac"].as_str().unwrap(),
                    entry["zone"].as_str().unwrap(),
                    None,
                    FrameKind::from_str(entry["frame_type"].as_str().unwrap()).unwrap(),
                )
                .is_some()
        })
        .count();
    assert_eq!(eligible, 1);
    let clients = identities.into_clients();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].key.to_string(), "02:66:77:88:99:aa@lan");
    assert_eq!(clients[0].interface, "br-lan");
    assert_eq!(clients[0].hostname.as_deref(), Some("phone"));
    assert_eq!(clients[0].last_seen, 1_710_000_200);
    assert_eq!(clients[0].ips, ["192.168.1.66"]);
}

#[test]
fn interface_filter_splits_legacy_uci_string_values_and_matches_v4_v6_prefixes() {
    let mut filter =
        IdentityFilter::from_uci_values(["br-lan, br-iot\tbr-guest", "dae0 tun0 pppoe-wan wg0"]);
    filter.add_prefix(InterfacePrefix::from_str("br-lan=192.168.1.1/24").unwrap());
    filter.add_prefix(InterfacePrefix::from_str("br-lan=fd00::1/64").unwrap());
    filter.add_prefix(InterfacePrefix::from_str("br-iot=10.20.0.1/16").unwrap());

    assert_eq!(filter.interfaces(), ["br-lan", "br-iot", "br-guest"]);
    assert!(filter.is_enabled());
    assert!(filter.allows("br-lan", "192.168.1.254"));
    assert!(filter.allows("br-lan", "fd00::abcd"));
    assert!(filter.allows("br-iot", "10.20.42.1"));
    assert!(!filter.allows("br-lan", "192.168.2.1"));
    assert!(!filter.allows("br-guest", "10.20.42.1"));
    assert!(!filter.allows("eth0", "192.168.1.2"));
}

#[test]
fn identity_filter_without_prefixes_still_restricts_selected_interfaces() {
    let filter = IdentityFilter::from_uci_values(["br-lan"]);
    assert!(filter.is_enabled());
    assert!(filter.allows("br-lan", "192.168.1.2"));
    assert!(!filter.allows("eth0", "192.168.1.2"));
    assert!(!filter.allows("br-lan", "not-an-ip"));
}

#[test]
fn arp_parser_preserves_legacy_flags_mac_and_interface_rules_without_panics() {
    let input = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.2 0x1 0x2 02:11:22:33:44:55 * br-lan\n\
192.168.1.3 0x1 0 02:11:22:33:44:56 * br-lan\n\
192.168.1.4 0x1 0x2 33:33:00:00:00:01 * br-lan\n\
garbage 0x1 010 02:11:22:33:44:57 * br-lan\n\
192.168.1.5 0x1 0x2 02:11:22:33:44:58 * tun0\n\
192.168.1.6 0x1 0x2junk 02:11:22:33:44:59 * br-lan ignored-tail\n\
short line\n";
    let entries = parse_arp_table(input, 16, &IdentityFilter::disabled(), &LegacyZoneResolver);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].ip, "192.168.1.2");
    assert_eq!(entries[0].mac.to_string(), "02:11:22:33:44:55");
    assert_eq!(entries[1].ip, "garbage");
    assert_eq!(entries[1].mac.to_string(), "02:11:22:33:44:57");
    assert_eq!(entries[2].ip, "192.168.1.6");

    for prefix in 0..input.len() {
        let _ = parse_arp_table(
            &input[..prefix],
            16,
            &IdentityFilter::disabled(),
            &LegacyZoneResolver,
        );
    }
}

fn netlink_attr(kind: u16, payload: &[u8]) -> Vec<u8> {
    let length = 4 + payload.len();
    let aligned = (length + 3) & !3;
    let mut bytes = vec![0; aligned];
    bytes[..2].copy_from_slice(&(length as u16).to_ne_bytes());
    bytes[2..4].copy_from_slice(&kind.to_ne_bytes());
    bytes[4..4 + payload.len()].copy_from_slice(payload);
    bytes
}

fn neighbor_message(state: u16, dst: &[u8], lladdr: &[u8], ifindex: i32) -> Vec<u8> {
    let mut payload = vec![0; 12];
    payload[0] = libc::AF_INET6 as u8;
    payload[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    payload[8..10].copy_from_slice(&state.to_ne_bytes());
    payload.extend(netlink_attr(1, dst));
    payload.extend(netlink_attr(2, lladdr));
    let mut message = vec![0; 16];
    let length = message.len() + payload.len();
    message[..4].copy_from_slice(&(length as u32).to_ne_bytes());
    message[4..6].copy_from_slice(&28u16.to_ne_bytes());
    message.extend(payload);
    message
}

fn netlink_sequence(mut message: Vec<u8>, sequence: u32) -> Vec<u8> {
    message[8..12].copy_from_slice(&sequence.to_ne_bytes());
    message
}

fn netlink_control_message(kind: u16, flags: u16, sequence: u32, error: Option<i32>) -> Vec<u8> {
    let payload_len = match (kind, error) {
        (2, Some(_)) => 20,
        (_, Some(_)) => 4,
        _ => 0,
    };
    let mut message = vec![0; 16 + payload_len];
    let length = message.len() as u32;
    message[..4].copy_from_slice(&length.to_ne_bytes());
    message[4..6].copy_from_slice(&kind.to_ne_bytes());
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
    message[8..12].copy_from_slice(&sequence.to_ne_bytes());
    if let Some(error) = error {
        message[16..20].copy_from_slice(&error.to_ne_bytes());
    }
    message
}

#[test]
fn raw_rtnetlink_parser_handles_ipv6_states_short_attrs_and_unaligned_buffers() {
    let address = IpAddr::from_str("fd00::42").unwrap();
    let IpAddr::V6(address) = address else {
        unreachable!()
    };
    let mut bytes = vec![0xaa];
    bytes.extend(neighbor_message(
        0x01,
        &address.octets(),
        &[0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        7,
    ));
    let resolve_zone = |ifname: &str| (ifname == "br-lan").then(|| "vlan42".to_owned());
    let entries = parse_ipv6_neighbor_messages(
        &bytes[1..],
        16,
        |index| (index == 7).then(|| "br-lan".to_owned()),
        &resolve_zone,
    )
    .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].ip, "fd00::42");
    assert_eq!(entries[0].interface, "br-lan");
    assert_eq!(entries[0].zone, "vlan42");

    for rejected in [0x00, 0x20, 0x40] {
        assert!(parse_ipv6_neighbor_messages(
            &neighbor_message(rejected, &address.octets(), &[2, 1, 2, 3, 4, 5], 9),
            16,
            |_| None,
            &LegacyZoneResolver,
        )
        .unwrap()
        .is_empty());
    }
    let combined_state = parse_ipv6_neighbor_messages(
        &neighbor_message(0x21, &address.octets(), &[2, 1, 2, 3, 4, 5], 9),
        16,
        |_| None,
        &LegacyZoneResolver,
    )
    .unwrap();
    assert_eq!(
        combined_state.len(),
        1,
        "legacy rejects exact state values, not state bitmasks"
    );
    assert_eq!(combined_state[0].interface, "if9");
    assert_eq!(combined_state[0].zone, "if9");
    assert!(parse_ipv6_neighbor_messages(&[1, 2, 3], 16, |_| None, &LegacyZoneResolver).is_err());
    assert!(parse_ipv6_neighbor_messages(
        &neighbor_message(1, &[0; 15], &[2, 1, 2, 3, 4], 9),
        16,
        |_| None,
        &LegacyZoneResolver,
    )
    .unwrap()
    .is_empty());
}

#[test]
fn strict_rtnetlink_dump_validates_sequence_ack_interrupt_error_and_trailing_attrs() {
    let address = "fd00::99".parse::<std::net::Ipv6Addr>().unwrap();
    let neighbor = neighbor_message(1, &address.octets(), &[0x02, 0, 0, 0, 0, 0x99], 9);

    let mismatch = parse_ipv6_neighbor_dump(
        &netlink_sequence(neighbor.clone(), 7),
        42,
        16,
        |_| Some("br-lan".to_owned()),
        &LegacyZoneResolver,
    )
    .unwrap();
    assert!(mismatch.entries.is_empty());
    assert!(!mismatch.done);

    let mut acknowledged = netlink_control_message(2, 0, 42, Some(0));
    acknowledged.extend(netlink_sequence(neighbor.clone(), 42));
    let acknowledged = parse_ipv6_neighbor_dump(
        &acknowledged,
        42,
        16,
        |_| Some("br-lan".to_owned()),
        &LegacyZoneResolver,
    )
    .unwrap();
    assert_eq!(acknowledged.entries.len(), 1);
    assert!(!acknowledged.done);

    assert_eq!(
        parse_ipv6_neighbor_dump(
            &netlink_control_message(2, 0, 42, Some(-2)),
            42,
            16,
            |_| None,
            &LegacyZoneResolver,
        ),
        Err(NetlinkParseError::Kernel(-2))
    );
    assert_eq!(
        parse_ipv6_neighbor_dump(
            &netlink_control_message(3, 0x10, 42, None),
            42,
            16,
            |_| None,
            &LegacyZoneResolver,
        ),
        Err(NetlinkParseError::DumpInterrupted)
    );
    let truncated_error = {
        let mut message = netlink_control_message(2, 0, 42, None);
        message.extend(0i32.to_ne_bytes());
        let length = message.len() as u32;
        message[..4].copy_from_slice(&length.to_ne_bytes());
        message
    };
    assert!(
        parse_ipv6_neighbor_dump(&truncated_error, 42, 16, |_| None, &LegacyZoneResolver,).is_err()
    );
    assert_eq!(
        parse_ipv6_neighbor_dump(
            &netlink_control_message(3, 0, 42, Some(-5)),
            42,
            16,
            |_| None,
            &LegacyZoneResolver,
        ),
        Err(NetlinkParseError::Kernel(-5))
    );
    assert!(
        parse_ipv6_neighbor_dump(
            &netlink_control_message(3, 0, 42, Some(0)),
            42,
            16,
            |_| None,
            &LegacyZoneResolver,
        )
        .unwrap()
        .done
    );
    let malformed_done = {
        let mut message = netlink_control_message(3, 0, 42, None);
        message.push(0);
        let length = message.len() as u32;
        message[..4].copy_from_slice(&length.to_ne_bytes());
        message
    };
    assert!(
        parse_ipv6_neighbor_dump(&malformed_done, 42, 16, |_| None, &LegacyZoneResolver,).is_err()
    );

    let mut malformed = netlink_sequence(neighbor, 42);
    malformed.extend([2, 0, 0, 0]);
    let length = malformed.len() as u32;
    malformed[..4].copy_from_slice(&length.to_ne_bytes());
    assert!(parse_ipv6_neighbor_dump(
        &malformed,
        42,
        16,
        |_| Some("br-lan".to_owned()),
        &LegacyZoneResolver,
    )
    .unwrap()
    .entries
    .is_empty());
}

fn temporary_hostname_paths() -> (PathBuf, HostnamePaths) {
    let root = std::env::temp_dir().join(format!(
        "lanspeedd-identity-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("hosts")).unwrap();
    let paths = HostnamePaths {
        leases: root.join("dhcp.leases"),
        hosts_dir: root.join("hosts"),
        etc_hosts: root.join("etc-hosts"),
    };
    (root, paths)
}

#[test]
fn hostname_cache_preserves_legacy_precedence_case_validation_and_refresh_interval() {
    assert_eq!(HOSTNAME_CACHE_MAX, 1024);
    assert_eq!(HOSTNAME_REFRESH_MS, 10_000);
    let (root, paths) = temporary_hostname_paths();
    fs::write(
        &paths.leases,
        "0 02:11:22:33:44:55 192.168.1.42 WorkStation *\n0 02:11:22:33:44:56 192.168.1.43 * *\n",
    )
    .unwrap();
    fs::write(
        paths.hosts_dir.join("dnsmasq"),
        "192.168.1.42 lower-priority\nfd00::42 IPv6Name\n",
    )
    .unwrap();
    fs::write(
        &paths.etc_hosts,
        "127.0.0.1 localhost\n::1 localhost\nfd00::42 lowest-priority\n",
    )
    .unwrap();

    let mut cache = HostnameCache::new();
    assert!(cache.refresh_from_paths(&paths, 1_000, false));
    assert_eq!(
        cache.lookup("02:11:22:33:44:55", &["fd00::42"]),
        Some("WorkStation")
    );
    assert_eq!(
        cache.lookup("02:11:22:33:44:57", &["fd00::42"]),
        Some("IPv6Name")
    );
    fs::write(
        &paths.leases,
        "0 02:11:22:33:44:55 192.168.1.42 Changed *\n",
    )
    .unwrap();
    assert!(cache.refresh_from_paths(&paths, 1_001, true));
    assert_eq!(cache.lookup("02:11:22:33:44:55", &[]), Some("Changed"));
    assert!(!cache.refresh_from_paths(&paths, 1_002, false));
    assert!(cache.refresh_from_paths(&paths, 11_002, false));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn hostname_cache_checks_capacity_before_updating_duplicate_keys() {
    let mut cache = HostnameCache::with_capacity(2);
    cache.parse_leases(
        "0 02:00:00:00:00:01 192.0.2.1 First *\n\
         0 02:00:00:00:00:02 192.0.2.2 Second *\n\
         0 02:00:00:00:00:01 192.0.2.1 MustNotReplace *\n",
    );
    assert_eq!(cache.lookup("02:00:00:00:00:01", &[]), Some("First"));
}

#[test]
fn hostname_refresh_is_streaming_bounded_and_skips_only_invalid_lines() {
    assert_eq!(HOSTNAME_MAX_LINE_BYTES, 512);
    assert!(HOSTNAME_MAX_SOURCE_BYTES >= HOSTNAME_MAX_LINE_BYTES);
    assert!(HOSTNAME_MAX_HOST_FILES > 0);
    assert!(HOSTNAME_MAX_DIR_ENTRIES >= HOSTNAME_MAX_HOST_FILES);

    let (root, paths) = temporary_hostname_paths();
    let mut leases = b"0 02:00:00:00:00:01 192.0.2.1 First *\n".to_vec();
    leases.extend(b"0 02:00:00:00:00:02 192.0.2.2 ");
    leases.push(0xff);
    leases.extend(b" *\n0 02:00:00:00:00:03 192.0.2.3 Third *\n");
    fs::write(&paths.leases, leases).unwrap();

    let mut cache = HostnameCache::new();
    assert!(cache.refresh_from_paths(&paths, 1, true));
    assert_eq!(cache.lookup("02:00:00:00:00:01", &[]), Some("First"));
    assert_eq!(cache.lookup("02:00:00:00:00:02", &[]), None);
    assert_eq!(cache.lookup("02:00:00:00:00:03", &[]), Some("Third"));

    let mut overlong = vec![b'x'; HOSTNAME_MAX_LINE_BYTES + 1];
    overlong.extend(b"\n192.0.2.42 bounded-host\n");
    fs::write(&paths.etc_hosts, overlong).unwrap();
    assert!(cache.refresh_from_paths(&paths, 2, true));
    assert_eq!(
        cache.lookup("02:00:00:00:00:ff", &["192.0.2.42"]),
        Some("bounded-host")
    );

    let mut oversized = vec![b'#'; HOSTNAME_MAX_SOURCE_BYTES];
    oversized.extend(b"\n192.0.2.99 beyond-budget\n");
    fs::write(&paths.etc_hosts, oversized).unwrap();
    assert!(cache.refresh_from_paths(&paths, 3, true));
    assert_eq!(cache.lookup("02:00:00:00:00:ff", &["192.0.2.99"]), None);

    for index in 0..HOSTNAME_MAX_HOST_FILES + 5 {
        fs::write(
            paths.hosts_dir.join(format!("host-{index:04}")),
            format!("198.51.100.{} host-{index}\n", index % 250 + 1),
        )
        .unwrap();
    }
    assert!(cache.refresh_from_paths(&paths, 4, true));
    assert_eq!(
        cache.last_refresh_stats().host_files,
        HOSTNAME_MAX_HOST_FILES
    );

    let mut small = HostnameCache::with_capacity(1);
    let full_source = format!(
        "0 02:00:00:00:00:10 203.0.113.10 Full *\n{}",
        "# padding\n".repeat(1000)
    );
    fs::write(&paths.leases, &full_source).unwrap();
    assert!(small.refresh_from_paths(&paths, 5, true));
    assert!(small.last_refresh_stats().bytes_read < full_source.len());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn hostname_directory_raw_iteration_is_bounded_even_for_hidden_entries() {
    let (root, paths) = temporary_hostname_paths();
    for index in 0..HOSTNAME_MAX_DIR_ENTRIES + 5 {
        fs::write(
            paths.hosts_dir.join(format!(".hidden-{index:05}")),
            b"ignored\n",
        )
        .unwrap();
    }
    let mut cache = HostnameCache::new();
    assert!(cache.refresh_from_paths(&paths, 1, true));
    assert_eq!(
        cache.last_refresh_stats().directory_entries,
        HOSTNAME_MAX_DIR_ENTRIES
    );
    assert_eq!(cache.last_refresh_stats().host_files, 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn identity_ip_attributes_keep_the_legacy_four_address_bound() {
    let mut identities = IdentityTable::new(1);
    for last_octet in 1..=6 {
        let ip = format!("192.0.2.{last_octet}");
        identities
            .observe(IdentityObservation {
                mac: "02:00:00:00:00:01",
                zone: Some("lan"),
                interface: "br-lan",
                ip: Some(&ip),
                hostname: None,
                last_seen: last_octet,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
    }
    assert_eq!(identities.into_clients()[0].ips.len(), 4);
}

#[test]
fn identity_policy_excludes_router_control_and_remote_ips_from_all_paths() {
    let mut policy = IdentityPolicy::default();
    policy.exclude_router_ip("192.168.1.1");
    policy.exclude_control_ip("224.0.0.1");
    policy.exclude_remote_ip("198.18.0.1");
    let mut identities = IdentityTable::with_policy(8, policy);

    for (index, ip) in ["192.168.1.1", "224.0.0.1", "198.18.0.1"]
        .into_iter()
        .enumerate()
    {
        let mac = format!("02:00:00:00:00:{:02x}", index + 1);
        assert!(!identities
            .observe(IdentityObservation {
                mac: &mac,
                zone: Some("lan"),
                interface: "br-lan",
                ip: Some(ip),
                hostname: None,
                last_seen: 0,
                source: ObservationSource::Neighbor,
            })
            .unwrap());
        assert!(identities.by_ip(ip).is_none());
        assert!(identities
            .traffic_owner(&mac, "lan", Some(ip), FrameKind::Unicast)
            .is_none());
    }

    assert!(identities
        .observe(IdentityObservation {
            mac: "02:00:00:00:00:10",
            zone: Some("lan"),
            interface: "br-lan",
            ip: Some("192.168.1.42"),
            hostname: None,
            last_seen: 0,
            source: ObservationSource::Neighbor,
        })
        .unwrap());
    assert!(identities
        .traffic_owner(
            "02:00:00:00:00:10",
            "lan",
            Some("192.168.1.42"),
            FrameKind::Unicast,
        )
        .is_some());
    identities.exclude_control_ip("192.168.1.42");
    assert!(identities.by_ip("192.168.1.42").is_none());
    assert!(identities.clients().next().unwrap().ips.is_empty());
}

#[test]
fn duplicate_ip_lookup_is_deterministic_by_mac_zone_key_order() {
    let mut identities = IdentityTable::new(2);
    for (mac, zone) in [("02:00:00:00:00:20", "guest"), ("02:00:00:00:00:10", "lan")] {
        identities
            .observe(IdentityObservation {
                mac,
                zone: Some(zone),
                interface: "br-lan",
                ip: Some("192.0.2.42"),
                hostname: None,
                last_seen: 0,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
    }
    assert_eq!(
        identities.by_ip("192.0.2.42").unwrap().key.to_string(),
        "02:00:00:00:00:10@lan"
    );
    for (mac, zone) in [("02:00:00:00:00:20", "guest"), ("02:00:00:00:00:10", "lan")] {
        assert!(identities
            .traffic_owner(mac, zone, Some("192.0.2.42"), FrameKind::Unicast)
            .is_some());
    }
}
