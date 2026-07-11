use lanspeedd::identity::{
    arp::parse_arp_table,
    filter::{IdentityFilter, InterfacePrefix},
    hostname::{HostnameCache, HostnamePaths, HOSTNAME_CACHE_MAX, HOSTNAME_REFRESH_MS},
    netlink::parse_ipv6_neighbor_messages,
    FrameKind, IdentityObservation, IdentityTable, ObservationSource,
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
    for source in fixture["sources"]["neighbors"].as_array().unwrap() {
        observe_json(&mut identities, source, ObservationSource::Neighbor);
    }

    let clients = identities.into_clients();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].key.to_string(), "02:aa:bb:cc:dd:ee@lan");
    assert_eq!(clients[0].ips.len(), 2);
}

#[test]
fn topology_fixture_keeps_same_mac_in_distinct_vlan_zones() {
    let fixture = fixture("lanspeed-topology-vlan.json");
    let mut identities = IdentityTable::new(16);
    for source in fixture["observations"].as_array().unwrap() {
        identities
            .observe(IdentityObservation {
                mac: source["mac"].as_str().unwrap(),
                zone: source["zone"].as_str(),
                interface: source["interface"].as_str().unwrap(),
                ip: None,
                hostname: None,
                last_seen: 0,
                source: ObservationSource::Wireless,
            })
            .unwrap();
    }
    for source in fixture["uplink_observations"].as_array().unwrap() {
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
            identities.traffic_is_client_owned(
                entry["mac"].as_str().unwrap(),
                FrameKind::from_str(entry["frame_type"].as_str().unwrap()).unwrap(),
            )
        })
        .count();
    assert_eq!(eligible, 1);
    assert_eq!(identities.into_clients().len(), 1);
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
fn identity_filter_fails_open_without_a_successfully_collected_prefix() {
    let filter = IdentityFilter::from_uci_values(["br-lan"]);
    assert!(!filter.is_enabled());
    assert!(filter.allows("eth0", "not-an-ip"));
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
    let entries = parse_arp_table(input, 16, &IdentityFilter::disabled());
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].ip, "192.168.1.2");
    assert_eq!(entries[0].mac.to_string(), "02:11:22:33:44:55");
    assert_eq!(entries[1].ip, "garbage");
    assert_eq!(entries[1].mac.to_string(), "02:11:22:33:44:57");
    assert_eq!(entries[2].ip, "192.168.1.6");

    for prefix in 0..input.len() {
        let _ = parse_arp_table(&input[..prefix], 16, &IdentityFilter::disabled());
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
    let entries = parse_ipv6_neighbor_messages(&bytes[1..], 16, |index| {
        (index == 7).then(|| "br-lan".to_owned())
    })
    .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].ip, "fd00::42");
    assert_eq!(entries[0].interface, "br-lan");

    for rejected in [0x00, 0x20, 0x40] {
        assert!(parse_ipv6_neighbor_messages(
            &neighbor_message(rejected, &address.octets(), &[2, 1, 2, 3, 4, 5], 9),
            16,
            |_| None,
        )
        .unwrap()
        .is_empty());
    }
    assert_eq!(
        parse_ipv6_neighbor_messages(
            &neighbor_message(0x21, &address.octets(), &[2, 1, 2, 3, 4, 5], 9),
            16,
            |_| None,
        )
        .unwrap()
        .len(),
        1,
        "legacy rejects exact state values, not state bitmasks"
    );
    assert!(parse_ipv6_neighbor_messages(&[1, 2, 3], 16, |_| None).is_err());
    assert!(parse_ipv6_neighbor_messages(
        &neighbor_message(1, &[0; 15], &[2, 1, 2, 3, 4], 9),
        16,
        |_| None,
    )
    .unwrap()
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
