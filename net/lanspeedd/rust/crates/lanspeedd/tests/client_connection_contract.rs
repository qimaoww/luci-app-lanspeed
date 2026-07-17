use lanspeedd::{
    collectors::conntrack::{
        aggregate::aggregate_flows,
        collect_with,
        netlink::NetlinkSnapshot,
        procfs::{aggregate_reader, ProcfsSnapshot},
        CollectorMode, CollectorReadError, FlowSample, Protocol, TcpState, NETLINK_COUNTER_SOURCE,
        NETLINK_SOURCE_PATH, PROCFS_COUNTER_SOURCE,
    },
    connection_details::{
        ClientConnectionDetail, ConnectionDetailsIndex, ConnectionDirection, ConnectionProtocol,
        ConnectionRateBook, ConnectionState, MAX_CLIENT_CONNECTION_DETAILS,
        MAX_STORED_CONNECTION_DETAILS,
    },
    identity::{IdentityObservation, IdentityTable, ObservationSource},
};
use std::{io::Cursor, net::IpAddr, sync::Arc};

const IDENTITY_KEY: &str = "02:00:00:00:00:01@lan";
const CLIENT_IP: &str = "192.0.2.10";

fn identity_table(observations: &[(&str, &str)]) -> IdentityTable {
    let mut table = IdentityTable::new(observations.len().max(1));
    for &(mac, ip) in observations {
        table
            .observe(IdentityObservation {
                mac,
                zone: Some("lan"),
                interface: "lan",
                ip: Some(ip),
                hostname: None,
                last_seen: 1,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
    }
    table
}

fn identities() -> IdentityTable {
    identity_table(&[("02:00:00:00:00:01", CLIENT_IP)])
}

fn tcp_flow(
    orig_src: Option<&str>,
    orig_dst: Option<&str>,
    reply_src: Option<&str>,
    reply_dst: Option<&str>,
) -> FlowSample {
    FlowSample {
        orig_src: orig_src.map(|ip| ip.parse().unwrap()),
        orig_dst: orig_dst.map(|ip| ip.parse().unwrap()),
        reply_src: reply_src.map(|ip| ip.parse().unwrap()),
        reply_dst: reply_dst.map(|ip| ip.parse().unwrap()),
        orig_bytes: 100,
        reply_bytes: 250,
        orig_sport: 50_123,
        orig_dport: 443,
        reply_sport: 443,
        reply_dport: 50_123,
        protocol: Protocol::Tcp,
        tcp_state: Some(TcpState::Established),
        assured: true,
    }
}

fn outbound_tcp(client_ip: &str, remote_ip: &str) -> FlowSample {
    tcp_flow(
        Some(client_ip),
        Some(remote_ip),
        Some(remote_ip),
        Some(client_ip),
    )
}

fn detail(
    client_ip: &str,
    client_port: u16,
    remote_ip: &str,
    remote_port: u16,
    protocol: ConnectionProtocol,
    state: ConnectionState,
    direction: ConnectionDirection,
) -> ClientConnectionDetail {
    ClientConnectionDetail {
        client_ip: client_ip.parse().unwrap(),
        client_port,
        remote_ip: remote_ip.parse().unwrap(),
        remote_port,
        protocol,
        state,
        direction,
        tx_bps: 0,
        rx_bps: 0,
    }
}

#[test]
fn details_index_owns_totals_caps_truncation_and_stable_sorting() {
    let mut index = ConnectionDetailsIndex::default();
    for offset in 0..=MAX_CLIENT_CONNECTION_DETAILS {
        let remote_ip = match offset {
            0 => "10.0.0.10",
            1 => "10.0.0.2",
            _ => "203.0.113.1",
        };
        index.record(
            IDENTITY_KEY,
            detail(
                CLIENT_IP,
                u16::try_from(offset + 1).unwrap(),
                remote_ip,
                443,
                ConnectionProtocol::Tcp,
                ConnectionState::Established,
                ConnectionDirection::Outbound,
            ),
        );
    }
    let stable_key = "02:00:00:00:00:02@lan";
    index.record(
        stable_key,
        detail(
            CLIENT_IP,
            50_123,
            "198.51.100.1",
            443,
            ConnectionProtocol::Tcp,
            ConnectionState::Assured,
            ConnectionDirection::Outbound,
        ),
    );
    index.record(
        stable_key,
        detail(
            CLIENT_IP,
            50_123,
            "198.51.100.1",
            443,
            ConnectionProtocol::Tcp,
            ConnectionState::Established,
            ConnectionDirection::Outbound,
        ),
    );

    let sets = index.finish();
    let set = &sets[IDENTITY_KEY];
    assert_eq!(set.total_connections, (MAX_CLIENT_CONNECTION_DETAILS + 1) as u64);
    assert_eq!(set.connections.len(), MAX_CLIENT_CONNECTION_DETAILS);
    assert!(set.truncated);
    assert_eq!(
        set.connections[0].remote_ip,
        "10.0.0.2".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        set.connections[1].remote_ip,
        "10.0.0.10".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        sets[stable_key]
            .connections
            .iter()
            .map(|detail| detail.state)
            .collect::<Vec<_>>(),
        [ConnectionState::Assured, ConnectionState::Established]
    );
}

#[test]
fn outbound_established_assured_tcp_populates_detail_and_legacy_count() {
    let flow = outbound_tcp(CLIENT_IP, "1.1.1.1");

    let snapshot = aggregate_flows(&identities(), [&flow], 7_001, 8);

    assert_eq!(snapshot.sample_ms, 7_001);
    assert_eq!(snapshot.clients.len(), 1);
    assert_eq!(snapshot.clients[0].tcp_conns, 1);
    let set = &snapshot.connection_details[IDENTITY_KEY];
    assert_eq!(set.total_connections, 1);
    assert_eq!(set.connections.len(), 1);
    assert!(!set.truncated);
    assert_eq!(
        set.connections[0],
        detail(
            CLIENT_IP,
            50_123,
            "1.1.1.1",
            443,
            ConnectionProtocol::Tcp,
            ConnectionState::Established,
            ConnectionDirection::Outbound,
        )
    );
}

#[test]
fn per_connection_rates_use_adjacent_counters_in_the_client_direction() {
    let table = identities();
    let outbound_first = outbound_tcp(CLIENT_IP, "198.51.100.10");
    let inbound_first = tcp_flow(
        Some("198.51.100.20"),
        Some(CLIENT_IP),
        Some(CLIENT_IP),
        Some("198.51.100.20"),
    );
    let mut first = aggregate_flows(&table, [&outbound_first, &inbound_first], 1_000, 8);
    let mut rates = ConnectionRateBook::default();

    rates.update(
        first.sample_ms,
        &first.connection_counters,
        &mut first.connection_details,
    );

    assert!(first.connection_details[IDENTITY_KEY]
        .connections
        .iter()
        .all(|detail| detail.tx_bps == 0 && detail.rx_bps == 0));

    let mut outbound_second = outbound_first.clone();
    outbound_second.orig_bytes += 300;
    outbound_second.reply_bytes += 700;
    let mut inbound_second = inbound_first.clone();
    inbound_second.orig_bytes += 900;
    inbound_second.reply_bytes += 200;
    let mut second = aggregate_flows(&table, [&outbound_second, &inbound_second], 2_000, 8);

    rates.update(
        second.sample_ms,
        &second.connection_counters,
        &mut second.connection_details,
    );

    let details = &second.connection_details[IDENTITY_KEY].connections;
    let outbound = details
        .iter()
        .find(|detail| detail.direction == ConnectionDirection::Outbound)
        .unwrap();
    assert_eq!((outbound.tx_bps, outbound.rx_bps), (2_400, 5_600));
    let inbound = details
        .iter()
        .find(|detail| detail.direction == ConnectionDirection::Inbound)
        .unwrap();
    assert_eq!((inbound.tx_bps, inbound.rx_bps), (1_600, 7_200));
}

#[test]
fn connection_rate_baselines_reset_on_rollback_absence_and_clear() {
    let table = identities();
    let first_flow = outbound_tcp(CLIENT_IP, "198.51.100.30");
    let mut rates = ConnectionRateBook::default();
    let mut first = aggregate_flows(&table, [&first_flow], 1_000, 8);
    rates.update(
        first.sample_ms,
        &first.connection_counters,
        &mut first.connection_details,
    );

    let mut rollback_flow = first_flow.clone();
    rollback_flow.orig_bytes = first_flow.orig_bytes.saturating_sub(1);
    rollback_flow.reply_bytes += 500;
    let mut rollback = aggregate_flows(&table, [&rollback_flow], 2_000, 8);
    rates.update(
        rollback.sample_ms,
        &rollback.connection_counters,
        &mut rollback.connection_details,
    );
    let rollback_detail = &rollback.connection_details[IDENTITY_KEY].connections[0];
    assert_eq!((rollback_detail.tx_bps, rollback_detail.rx_bps), (0, 4_000));

    let mut absent = aggregate_flows(&table, std::iter::empty(), 3_000, 8);
    rates.update(
        absent.sample_ms,
        &absent.connection_counters,
        &mut absent.connection_details,
    );
    let mut reappeared = aggregate_flows(&table, [&rollback_flow], 4_000, 8);
    rates.update(
        reappeared.sample_ms,
        &reappeared.connection_counters,
        &mut reappeared.connection_details,
    );
    let detail = &reappeared.connection_details[IDENTITY_KEY].connections[0];
    assert_eq!((detail.tx_bps, detail.rx_bps), (0, 0));

    rates.clear();
    let mut after_clear = aggregate_flows(&table, [&rollback_flow], 5_000, 8);
    rates.update(
        after_clear.sample_ms,
        &after_clear.connection_counters,
        &mut after_clear.connection_details,
    );
    let detail = &after_clear.connection_details[IDENTITY_KEY].connections[0];
    assert_eq!((detail.tx_bps, detail.rx_bps), (0, 0));
}

#[test]
fn reusing_the_same_snapshot_generation_preserves_computed_rates() {
    let table = identities();
    let first_flow = outbound_tcp(CLIENT_IP, "198.51.100.40");
    let mut second_flow = first_flow.clone();
    second_flow.orig_bytes += 1_000;
    second_flow.reply_bytes += 2_000;
    let mut rates = ConnectionRateBook::default();
    let mut first = aggregate_flows(&table, [&first_flow], 1_000, 8);
    rates.update(
        first.sample_ms,
        &first.connection_counters,
        &mut first.connection_details,
    );
    let mut second = aggregate_flows(&table, [&second_flow], 2_000, 8);
    rates.update(
        second.sample_ms,
        &second.connection_counters,
        &mut second.connection_details,
    );
    let expected = second.connection_details[IDENTITY_KEY].connections[0].clone();
    let mut cached_details = Arc::clone(&second.connection_details);

    rates.update(
        second.sample_ms,
        &second.connection_counters,
        &mut cached_details,
    );

    assert!(Arc::ptr_eq(&cached_details, &second.connection_details));
    assert_eq!(cached_details[IDENTITY_KEY].connections[0], expected);
    assert_eq!((expected.tx_bps, expected.rx_bps), (8_000, 16_000));
}

#[test]
fn cloned_aggregate_and_collected_snapshots_share_immutable_details() {
    let table = identities();
    let flow = outbound_tcp(CLIENT_IP, "1.1.1.1");
    let aggregate = aggregate_flows(&table, [&flow], 7_002, 8);
    let aggregate_clone = aggregate.clone();
    assert!(Arc::ptr_eq(
        &aggregate.connection_details,
        &aggregate_clone.connection_details
    ));

    let collected = collect_with(
        CollectorMode::Netlink,
        &table,
        7_002,
        8,
        || {
            Ok(NetlinkSnapshot {
                flows: vec![flow],
                source_path: NETLINK_SOURCE_PATH,
                counter_source: NETLINK_COUNTER_SOURCE,
                malformed_entries: 0,
            })
        },
        || -> Result<ProcfsSnapshot, CollectorReadError> { unreachable!() },
    )
    .unwrap();
    let collected_clone = collected.clone();
    assert!(Arc::ptr_eq(
        &collected.connection_details,
        &collected_clone.connection_details
    ));
}

#[test]
fn ownership_priority_normalizes_all_four_endpoints_and_nat_deduplicates() {
    let table = identity_table(&[
        ("02:00:00:00:00:01", CLIENT_IP),
        ("02:00:00:00:00:01", "2001:db8:1::10"),
    ]);
    let cases = [
        (
            tcp_flow(
                Some(CLIENT_IP),
                Some("198.51.100.1"),
                Some("198.51.100.1"),
                Some("203.0.113.10"),
            ),
            detail(
                CLIENT_IP,
                50_123,
                "198.51.100.1",
                443,
                ConnectionProtocol::Tcp,
                ConnectionState::Established,
                ConnectionDirection::Outbound,
            ),
            (100, 250),
        ),
        (
            tcp_flow(
                Some("198.51.100.2"),
                Some(CLIENT_IP),
                Some("203.0.113.20"),
                Some("198.51.100.2"),
            ),
            detail(
                CLIENT_IP,
                443,
                "198.51.100.2",
                50_123,
                ConnectionProtocol::Tcp,
                ConnectionState::Established,
                ConnectionDirection::Inbound,
            ),
            (250, 100),
        ),
        (
            tcp_flow(
                Some("2001:db8:2::30"),
                Some("2001:db8:2::40"),
                Some("2001:db8:1::10"),
                Some("2001:db8:2::3"),
            ),
            detail(
                "2001:db8:1::10",
                443,
                "2001:db8:2::3",
                50_123,
                ConnectionProtocol::Tcp,
                ConnectionState::Established,
                ConnectionDirection::Inbound,
            ),
            (250, 100),
        ),
        (
            tcp_flow(
                Some("198.51.100.4"),
                Some("203.0.113.40"),
                Some("198.51.100.4"),
                Some(CLIENT_IP),
            ),
            detail(
                CLIENT_IP,
                50_123,
                "198.51.100.4",
                443,
                ConnectionProtocol::Tcp,
                ConnectionState::Established,
                ConnectionDirection::Outbound,
            ),
            (100, 250),
        ),
    ];

    for (flow, expected_detail, expected_bytes) in cases {
        let snapshot = aggregate_flows(&table, [&flow], 10, 8);
        assert_eq!(
            snapshot.connection_details[IDENTITY_KEY].connections,
            [expected_detail]
        );
        assert_eq!(
            (snapshot.clients[0].tx_bytes, snapshot.clients[0].rx_bytes),
            expected_bytes
        );
    }

    let nat_deduplicated = tcp_flow(
        Some(CLIENT_IP),
        Some("198.51.100.9"),
        Some("198.51.100.9"),
        Some(CLIENT_IP),
    );
    let snapshot = aggregate_flows(&table, [&nat_deduplicated], 10, 8);
    assert_eq!(snapshot.clients[0].tcp_conns, 1);
    assert_eq!(
        snapshot.connection_details[IDENTITY_KEY].total_connections,
        1
    );
    assert_eq!(
        snapshot.connection_details[IDENTITY_KEY].connections.len(),
        1
    );
    assert_eq!(
        snapshot.connection_details[IDENTITY_KEY].connections[0].remote_ip,
        "198.51.100.9".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn connection_qualification_drives_both_details_and_legacy_counts() {
    let qualified_tcp = outbound_tcp(CLIENT_IP, "198.51.100.1");
    let mut qualified_udp = outbound_tcp(CLIENT_IP, "198.51.100.2");
    qualified_udp.protocol = Protocol::Udp;
    qualified_udp.tcp_state = None;
    qualified_udp.orig_dport = 53;
    qualified_udp.reply_sport = 53;

    let mut tcp_syn = outbound_tcp(CLIENT_IP, "198.51.100.3");
    tcp_syn.tcp_state = Some(TcpState::SynSent);
    let mut tcp_unassured = outbound_tcp(CLIENT_IP, "198.51.100.4");
    tcp_unassured.assured = false;
    let mut udp_unassured = qualified_udp.clone();
    udp_unassured.orig_dst = Some("198.51.100.5".parse().unwrap());
    udp_unassured.reply_src = Some("198.51.100.5".parse().unwrap());
    udp_unassured.assured = false;
    let mut other = outbound_tcp(CLIENT_IP, "198.51.100.6");
    other.protocol = Protocol::Other(1);
    other.tcp_state = None;

    let flows = [
        qualified_tcp,
        qualified_udp,
        tcp_syn,
        tcp_unassured,
        udp_unassured,
        other,
    ];
    let snapshot = aggregate_flows(&identities(), flows.iter(), 22, 8);
    let client = &snapshot.clients[0];

    assert_eq!((client.tcp_conns, client.udp_conns), (1, 1));
    assert_eq!((client.udp_dns_conns, client.udp_other_conns), (1, 0));
    assert_eq!((client.tx_bytes, client.rx_bytes), (600, 1_500));
    assert_eq!(snapshot.stats.entries_seen, 6);
    assert_eq!(snapshot.stats.entries_matched, 6);
    assert_eq!(snapshot.stats.src_lan_flows, 6);
    assert_eq!(snapshot.stats.ipv4_lan_flows, 6);
    let set = &snapshot.connection_details[IDENTITY_KEY];
    assert_eq!(set.total_connections, 2);
    assert_eq!(set.connections.len(), 2);
    assert_eq!(set.connections[0].state, ConnectionState::Established);
    assert_eq!(set.connections[1].state, ConnectionState::Assured);
    assert_eq!(set.connections[1].protocol, ConnectionProtocol::Udp);
}

#[test]
fn dns_split_checks_all_four_conntrack_ports() {
    let mut flows = Vec::new();
    for index in 0..5 {
        let mut flow = outbound_tcp(CLIENT_IP, &format!("198.51.100.{}", index + 1));
        flow.protocol = Protocol::Udp;
        flow.tcp_state = None;
        flow.orig_sport = 10_001;
        flow.orig_dport = 10_002;
        flow.reply_sport = 10_003;
        flow.reply_dport = 10_004;
        if index < 4 {
            match index {
                0 => flow.orig_sport = 53,
                1 => flow.orig_dport = 53,
                2 => flow.reply_sport = 53,
                3 => flow.reply_dport = 53,
                _ => unreachable!(),
            }
        }
        flows.push(flow);
    }

    let snapshot = aggregate_flows(&identities(), flows.iter(), 30, 8);
    let client = &snapshot.clients[0];
    assert_eq!(client.udp_conns, 5);
    assert_eq!(client.udp_dns_conns, 4);
    assert_eq!(client.udp_other_conns, 1);
    assert_eq!(
        snapshot.connection_details[IDENTITY_KEY].total_connections,
        5
    );
}

#[test]
fn lan_to_lan_and_unowned_flows_are_excluded_before_clients_or_details() {
    let table = identity_table(&[
        ("02:00:00:00:00:01", CLIENT_IP),
        ("02:00:00:00:00:02", "192.0.2.20"),
    ]);
    let orig_both_lan = outbound_tcp(CLIENT_IP, "192.0.2.20");
    let reply_both_lan = tcp_flow(
        Some("198.51.100.1"),
        Some("198.51.100.2"),
        Some(CLIENT_IP),
        Some("192.0.2.20"),
    );
    let unowned = outbound_tcp("198.51.100.3", "198.51.100.4");

    let snapshot = aggregate_flows(&table, [&orig_both_lan, &reply_both_lan, &unowned], 40, 8);

    assert!(snapshot.clients.is_empty());
    assert!(snapshot.connection_details.is_empty());
    assert_eq!(snapshot.stats.entries_seen, 3);
    assert_eq!(snapshot.stats.both_lan_flows, 2);
    assert_eq!(snapshot.stats.skipped_no_arp, 1);
    assert_eq!(snapshot.stats.no_lan_flows, 1);
    assert_eq!(snapshot.stats.entries_matched, 0);
}

#[test]
fn incomplete_remote_endpoint_keeps_legacy_accounting_without_fabricating_detail() {
    let incomplete = tcp_flow(Some(CLIENT_IP), None, None, Some(CLIENT_IP));

    let snapshot = aggregate_flows(&identities(), [&incomplete], 45, 8);

    assert_eq!(snapshot.clients[0].tcp_conns, 1);
    assert_eq!(
        (snapshot.clients[0].tx_bytes, snapshot.clients[0].rx_bytes),
        (100, 250)
    );
    assert_eq!(snapshot.stats.entries_matched, 1);
    let set = &snapshot.connection_details[IDENTITY_KEY];
    assert_eq!(set.total_connections, 1);
    assert!(set.connections.is_empty());
    assert!(set.truncated);
}

#[test]
fn per_client_limit_preserves_true_total_and_legacy_count() {
    assert_eq!(MAX_CLIENT_CONNECTION_DETAILS, 2_048);
    let mut flows = Vec::new();
    for port in 1..=MAX_CLIENT_CONNECTION_DETAILS + 1 {
        let mut flow = outbound_tcp(CLIENT_IP, "198.51.100.1");
        flow.orig_sport = u16::try_from(port).unwrap();
        flow.reply_dport = flow.orig_sport;
        flows.push(flow);
    }

    let snapshot = aggregate_flows(&identities(), flows.iter(), 50, 8);
    let set = &snapshot.connection_details[IDENTITY_KEY];

    assert_eq!(snapshot.clients[0].tcp_conns, (MAX_CLIENT_CONNECTION_DETAILS + 1) as u32);
    assert_eq!(set.total_connections, (MAX_CLIENT_CONNECTION_DETAILS + 1) as u64);
    assert_eq!(set.connections.len(), MAX_CLIENT_CONNECTION_DETAILS);
    assert!(set.truncated);
}

#[test]
fn global_limit_counts_stored_details_without_losing_any_client_total() {
    const CLIENTS: usize = 33;
    assert_eq!(MAX_CLIENT_CONNECTION_DETAILS, 2_048);
    assert_eq!(MAX_STORED_CONNECTION_DETAILS, 16_384);
    let observations = (1..=CLIENTS)
        .map(|index| {
            (
                format!("02:00:00:00:00:{index:02x}"),
                format!("10.0.0.{index}"),
            )
        })
        .collect::<Vec<_>>();
    let borrowed = observations
        .iter()
        .map(|(mac, ip)| (mac.as_str(), ip.as_str()))
        .collect::<Vec<_>>();
    let table = identity_table(&borrowed);
    let mut flows = Vec::new();
    for (_, client_ip) in &observations {
        for port in 1..=512 {
            let mut flow = outbound_tcp(client_ip, "203.0.113.1");
            flow.orig_sport = u16::try_from(port).unwrap();
            flow.reply_dport = flow.orig_sport;
            flows.push(flow);
        }
    }

    let snapshot = aggregate_flows(&table, flows.iter(), 60, CLIENTS);
    let stored = snapshot
        .connection_details
        .values()
        .map(|set| set.connections.len())
        .sum::<usize>();
    let total = snapshot
        .connection_details
        .values()
        .map(|set| set.total_connections)
        .sum::<u64>();

    assert_eq!(snapshot.connection_details.len(), CLIENTS);
    assert_eq!(stored, 16_384);
    assert_eq!(total, 16_896);
    for index in 1..=32 {
        let key = format!("02:00:00:00:00:{index:02x}@lan");
        let set = &snapshot.connection_details[&key];
        assert_eq!(set.total_connections, 512, "{key}");
        assert_eq!(set.connections.len(), 512, "{key}");
        assert!(!set.truncated, "{key}");
    }
    let final_set = &snapshot.connection_details["02:00:00:00:00:21@lan"];
    assert_eq!(final_set.total_connections, 512);
    assert!(final_set.connections.is_empty());
    assert!(final_set.truncated);
    assert!(snapshot
        .clients
        .iter()
        .all(|client| client.tcp_conns == 512));
}

#[test]
fn max_clients_rejection_cannot_create_an_orphan_detail_bucket() {
    let table = identity_table(&[
        ("02:00:00:00:00:01", CLIENT_IP),
        ("02:00:00:00:00:02", "192.0.2.20"),
    ]);
    let first = outbound_tcp(CLIENT_IP, "198.51.100.1");
    let dropped = outbound_tcp("192.0.2.20", "198.51.100.2");

    let snapshot = aggregate_flows(&table, [&first, &dropped], 70, 1);

    assert_eq!(snapshot.clients.len(), 1);
    assert_eq!(snapshot.stats.clients_dropped, 1);
    assert_eq!(snapshot.connection_details.len(), 1);
    assert!(snapshot.connection_details.contains_key(IDENTITY_KEY));
    assert!(!snapshot
        .connection_details
        .contains_key("02:00:00:00:00:02@lan"));
}

#[test]
fn finish_sorts_details_by_numeric_endpoints_and_explicit_enum_ranks() {
    let table = identity_table(&[
        ("02:00:00:00:00:01", "192.0.2.2"),
        ("02:00:00:00:00:01", "192.0.2.10"),
    ]);
    let mut numeric_remote_10 = outbound_tcp("192.0.2.2", "10.0.0.10");
    numeric_remote_10.orig_sport = 40_010;
    numeric_remote_10.reply_dport = 40_010;
    let mut numeric_remote_2 = outbound_tcp("192.0.2.2", "10.0.0.2");
    numeric_remote_2.orig_sport = 40_002;
    numeric_remote_2.reply_dport = 40_002;

    let outbound = outbound_tcp("192.0.2.10", "198.51.100.1");
    let mut inbound = tcp_flow(
        Some("198.51.100.1"),
        Some("192.0.2.10"),
        Some("192.0.2.10"),
        Some("198.51.100.1"),
    );
    inbound.orig_sport = 443;
    inbound.orig_dport = 50_123;
    inbound.reply_sport = 50_123;
    inbound.reply_dport = 443;
    let mut udp = outbound.clone();
    udp.protocol = Protocol::Udp;
    udp.tcp_state = None;
    let tcp_lower_client_ip = outbound_tcp("192.0.2.2", "198.51.100.1");
    let mut tcp_lower_client_port = outbound.clone();
    tcp_lower_client_port.orig_sport = 50_000;
    tcp_lower_client_port.reply_dport = 50_000;

    let flows = [
        udp,
        inbound,
        numeric_remote_10,
        outbound,
        tcp_lower_client_port,
        numeric_remote_2,
        tcp_lower_client_ip,
    ];
    let snapshot = aggregate_flows(&table, flows.iter(), 80, 8);
    let actual = snapshot.connection_details[IDENTITY_KEY]
        .connections
        .iter()
        .map(|item| {
            (
                item.remote_ip,
                item.remote_port,
                item.protocol,
                item.client_ip,
                item.client_port,
                item.direction,
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        vec![
            (
                "10.0.0.2".parse().unwrap(),
                443,
                ConnectionProtocol::Tcp,
                "192.0.2.2".parse().unwrap(),
                40_002,
                ConnectionDirection::Outbound,
            ),
            (
                "10.0.0.10".parse().unwrap(),
                443,
                ConnectionProtocol::Tcp,
                "192.0.2.2".parse().unwrap(),
                40_010,
                ConnectionDirection::Outbound,
            ),
            (
                "198.51.100.1".parse().unwrap(),
                443,
                ConnectionProtocol::Tcp,
                "192.0.2.2".parse().unwrap(),
                50_123,
                ConnectionDirection::Outbound,
            ),
            (
                "198.51.100.1".parse().unwrap(),
                443,
                ConnectionProtocol::Tcp,
                "192.0.2.10".parse().unwrap(),
                50_000,
                ConnectionDirection::Outbound,
            ),
            (
                "198.51.100.1".parse().unwrap(),
                443,
                ConnectionProtocol::Tcp,
                "192.0.2.10".parse().unwrap(),
                50_123,
                ConnectionDirection::Outbound,
            ),
            (
                "198.51.100.1".parse().unwrap(),
                443,
                ConnectionProtocol::Tcp,
                "192.0.2.10".parse().unwrap(),
                50_123,
                ConnectionDirection::Inbound,
            ),
            (
                "198.51.100.1".parse().unwrap(),
                443,
                ConnectionProtocol::Udp,
                "192.0.2.10".parse().unwrap(),
                50_123,
                ConnectionDirection::Outbound,
            ),
        ]
    );
}

#[test]
fn finish_sorts_remote_port_before_protocol_and_client_keys() {
    let mut port_443 = outbound_tcp(CLIENT_IP, "198.51.100.1");
    port_443.orig_dport = 443;
    port_443.reply_sport = 443;
    let mut port_53 = outbound_tcp(CLIENT_IP, "198.51.100.1");
    port_53.orig_dport = 53;
    port_53.reply_sport = 53;

    let snapshot = aggregate_flows(&identities(), [&port_443, &port_53], 81, 8);
    assert_eq!(
        snapshot.connection_details[IDENTITY_KEY]
            .connections
            .iter()
            .map(|detail| detail.remote_port)
            .collect::<Vec<_>>(),
        [53, 443]
    );
}

#[test]
fn netlink_procfs_vec_and_streaming_paths_propagate_the_same_snapshot() {
    let table = identities();
    let flow = outbound_tcp(CLIENT_IP, "1.1.1.1");
    let now_ms = 91_337;
    let expected = aggregate_flows(&table, [&flow], now_ms, 8);

    let netlink = collect_with(
        CollectorMode::Netlink,
        &table,
        now_ms,
        8,
        || {
            Ok(NetlinkSnapshot {
                flows: vec![flow.clone()],
                source_path: NETLINK_SOURCE_PATH,
                counter_source: NETLINK_COUNTER_SOURCE,
                malformed_entries: 0,
            })
        },
        || -> Result<ProcfsSnapshot, CollectorReadError> { unreachable!() },
    )
    .unwrap();
    let procfs = collect_with(
        CollectorMode::Procfs,
        &table,
        now_ms,
        8,
        || -> Result<NetlinkSnapshot, CollectorReadError> { unreachable!() },
        || {
            Ok(ProcfsSnapshot {
                flows: vec![flow],
                source_path: "fixture".into(),
                counter_source: PROCFS_COUNTER_SOURCE,
                entries_seen: 1,
                malformed_lines: 0,
            })
        },
    )
    .unwrap();

    assert_eq!(netlink.sample_ms, now_ms);
    assert_eq!(procfs.sample_ms, now_ms);
    assert_eq!(netlink.connection_details, expected.connection_details);
    assert_eq!(procfs.connection_details, expected.connection_details);
    assert_eq!(netlink.connection_details, procfs.connection_details);

    let line = concat!(
        "ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=1.1.1.1 ",
        "sport=50123 dport=443 packets=1 bytes=100 src=1.1.1.1 dst=192.0.2.10 ",
        "sport=443 dport=50123 packets=1 bytes=250 [ASSURED]\n"
    );
    let streaming = aggregate_reader(Cursor::new(line), "fixture", &table, now_ms, 8).unwrap();
    assert_eq!(streaming.aggregate.sample_ms, now_ms);
    assert_eq!(
        streaming.aggregate.connection_details,
        expected.connection_details
    );
}

#[test]
fn connection_detail_json_uses_lowercase_protocol_state_and_direction() {
    let tcp = serde_json::to_value(detail(
        CLIENT_IP,
        50_123,
        "1.1.1.1",
        443,
        ConnectionProtocol::Tcp,
        ConnectionState::Established,
        ConnectionDirection::Outbound,
    ))
    .unwrap();
    assert_eq!(
        tcp,
        serde_json::json!({
            "client_ip": "192.0.2.10",
            "client_port": 50_123,
            "remote_ip": "1.1.1.1",
            "remote_port": 443,
            "protocol": "tcp",
            "state": "established",
            "direction": "outbound",
            "tx_bps": 0,
            "rx_bps": 0
        })
    );

    let udp = serde_json::to_value(detail(
        "2001:db8::10",
        53,
        "2001:db8::53",
        60_000,
        ConnectionProtocol::Udp,
        ConnectionState::Assured,
        ConnectionDirection::Inbound,
    ))
    .unwrap();
    assert_eq!(
        udp,
        serde_json::json!({
            "client_ip": "2001:db8::10",
            "client_port": 53,
            "remote_ip": "2001:db8::53",
            "remote_port": 60_000,
            "protocol": "udp",
            "state": "assured",
            "direction": "inbound",
            "tx_bps": 0,
            "rx_bps": 0
        })
    );
}

#[test]
fn empty_aggregate_still_records_sample_time_and_no_detail_buckets() {
    let snapshot = aggregate_flows(&identities(), std::iter::empty(), 123_456, 8);
    assert_eq!(snapshot.sample_ms, 123_456);
    assert!(snapshot.connection_details.is_empty());
}
