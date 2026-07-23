use lanspeedd::{
    collectors::conntrack::{
        aggregate::aggregate_flows,
        collect_with,
        netlink::{
            aggregate_dump, build_dump_request, parse_dump, parse_dump_detailed,
            parse_dump_for_port, parse_dump_with_limit, read_snapshot as read_netlink_snapshot,
            retry_eintr, snapshot_from_datagrams, validate_received_datagram_len, Datagram,
            DumpError, NetlinkSnapshot, MAX_DATAGRAM_BYTES,
        },
        procfs::{
            aggregate_reader, parse_reader, ProcfsError, ProcfsSnapshot, CONNTRACK_LINE_MAX,
            PROCFS_PARSE_FLOW_CAP,
        },
        CollectorMode, CollectorReadError, FlowSample, Protocol, TcpState, NETLINK_COUNTER_SOURCE,
        NETLINK_SOURCE_PATH,
    },
    identity::{IdentityObservation, IdentityTable, ObservationSource},
};
use std::io::Cursor;

fn identities() -> IdentityTable {
    let mut table = IdentityTable::new(8);
    for (mac, zone, interface, ip) in [
        ("02:11:22:33:44:55", "lan", "br-lan", "192.168.1.42"),
        ("02:11:22:33:44:55", "lan", "br-lan", "fd00::42"),
        ("02:aa:bb:cc:dd:ee", "guest", "br-guest", "192.168.2.8"),
    ] {
        table
            .observe(IdentityObservation {
                mac,
                zone: Some(zone),
                interface,
                ip: Some(ip),
                hostname: None,
                last_seen: 1,
                source: ObservationSource::Neighbor,
            })
            .unwrap();
    }
    table.exclude_router_ip("192.168.1.1");
    table
}

fn flow(src: &str, dst: &str, reply_src: &str, reply_dst: &str) -> FlowSample {
    FlowSample {
        conntrack_id: None,
        conntrack_zone: Some(0),
        orig_src: Some(src.parse().unwrap()),
        orig_dst: Some(dst.parse().unwrap()),
        reply_src: Some(reply_src.parse().unwrap()),
        reply_dst: Some(reply_dst.parse().unwrap()),
        orig_bytes: 100,
        reply_bytes: 250,
        orig_sport: 40_000,
        orig_dport: 443,
        reply_sport: 443,
        reply_dport: 40_000,
        protocol: Protocol::Tcp,
        tcp_state: Some(TcpState::Established),
        assured: true,
    }
}

#[test]
fn aggregate_preserves_all_four_endpoint_directions_and_nat_deduplication() {
    let table = identities();
    let flows = [
        flow("192.168.1.42", "203.0.113.1", "203.0.113.1", "198.51.100.2"),
        flow("203.0.113.1", "192.168.1.42", "198.51.100.2", "203.0.113.1"),
        flow("203.0.113.1", "198.51.100.2", "192.168.1.42", "203.0.113.1"),
        flow("203.0.113.1", "198.51.100.2", "203.0.113.1", "192.168.1.42"),
        flow("192.168.1.42", "203.0.113.1", "203.0.113.1", "192.168.1.42"),
    ];
    let snapshot = aggregate_flows(&table, flows.iter(), 9_000, 8);
    let client = &snapshot.clients[0];
    assert_eq!(client.identity_key, "02:11:22:33:44:55@lan");
    assert_eq!((client.tx_bytes, client.rx_bytes), (800, 950));
    assert_eq!(client.tcp_conns, 5);
    assert_eq!(snapshot.stats.entries_matched, 5);
    assert_eq!(
        (snapshot.stats.src_lan_flows, snapshot.stats.dst_lan_flows),
        (3, 2)
    );
}

#[test]
fn aggregate_skips_both_lan_and_separates_router_local_from_router_originated() {
    let table = identities();
    let flows = [
        flow("192.168.1.42", "192.168.2.8", "192.168.2.8", "192.168.1.42"),
        flow("192.168.1.42", "192.168.1.1", "192.168.1.1", "192.168.1.42"),
        flow("192.168.1.1", "192.168.1.42", "192.168.1.42", "192.168.1.1"),
        flow("192.168.1.1", "203.0.113.1", "203.0.113.1", "192.168.1.1"),
    ];
    let snapshot = aggregate_flows(&table, flows.iter(), 10, 8);
    assert_eq!(snapshot.clients.len(), 1);
    assert_eq!(
        (snapshot.clients[0].tx_bytes, snapshot.clients[0].rx_bytes),
        (350, 350)
    );
    assert_eq!(snapshot.stats.both_lan_flows, 1);
    assert_eq!(snapshot.stats.skipped_no_arp, 1);
    assert_eq!(snapshot.stats.entries_matched, 2);
}

#[test]
fn aggregate_counts_only_established_assured_tcp_and_assured_udp_with_dns_split() {
    let table = identities();
    let mut tcp_unassured = flow("192.168.1.42", "203.0.113.1", "203.0.113.1", "192.168.1.42");
    tcp_unassured.assured = false;
    let mut tcp_syn = tcp_unassured.clone();
    tcp_syn.assured = true;
    tcp_syn.tcp_state = Some(TcpState::SynSent);
    let tcp = flow("192.168.1.42", "203.0.113.1", "203.0.113.1", "192.168.1.42");
    let mut dns = tcp.clone();
    dns.protocol = Protocol::Udp;
    dns.tcp_state = None;
    dns.orig_dport = 53;
    let mut other = dns.clone();
    other.orig_dport = 123;
    let mut udp_unassured = other.clone();
    udp_unassured.assured = false;
    let flows = [tcp_unassured, tcp_syn, tcp, dns, other, udp_unassured];
    let snapshot = aggregate_flows(&table, flows.iter(), 10, 8);
    let client = &snapshot.clients[0];
    assert_eq!(client.tcp_conns, 1);
    assert_eq!(
        (
            client.udp_conns,
            client.udp_dns_conns,
            client.udp_other_conns
        ),
        (2, 1, 1)
    );
}

#[test]
fn aggregate_handles_ipv6_multi_ip_and_max_clients() {
    let table = identities();
    let v6 = flow("fd00::42", "2001:db8::1", "2001:db8::1", "fd00::42");
    let guest = flow("192.168.2.8", "203.0.113.1", "203.0.113.1", "192.168.2.8");
    let snapshot = aggregate_flows(&table, [&v6, &guest], 10, 1);
    assert_eq!(snapshot.clients.len(), 1);
    assert_eq!(snapshot.clients[0].ips, ["192.168.1.42", "fd00::42"]);
    assert_eq!(snapshot.stats.ipv6_lan_flows, 1);
    assert_eq!(snapshot.stats.clients_dropped, 1);
}

#[test]
fn procfs_parser_preserves_orig_reply_nat_state_and_unknown_tokens() {
    let text = concat!(
        "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.42 dst=198.18.0.10 ",
        "sport=41000 dport=443 packets=10 bytes=1000 mystery=yes ",
        "src=198.18.0.10 dst=203.0.113.2 sport=443 dport=41000 packets=20 bytes=2000 ",
        "[ASSURED] mark=0 use=1\n",
        "ipv6 2 udp 17 20 src=fd00::42 dst=2001:db8::53 sport=53000 dport=53 ",
        "packets=2 bytes=300 src=2001:db8::53 dst=fd00::42 sport=53 dport=53000 packets=2 bytes=400 [ASSURED]\n",
    );
    let parsed = parse_reader(Cursor::new(text), "/proc/net/nf_conntrack").unwrap();
    assert_eq!(parsed.source_path, "/proc/net/nf_conntrack");
    assert_eq!(
        parsed.counter_source,
        "procfs_conntrack_acct_orig_reply_bytes"
    );
    assert_eq!(parsed.flows.len(), 2);
    assert_eq!(parsed.flows[0].orig_bytes, 1_000);
    assert_eq!(parsed.flows[0].reply_bytes, 2_000);
    assert_eq!(parsed.flows[0].tcp_state, Some(TcpState::Established));
    assert!(parsed.flows[0].assured);
    assert!(parsed.flows[1].is_dns());
}

#[test]
fn procfs_recovers_assured_state_hidden_by_flow_offload_markers() {
    let text = concat!(
        "ipv4 2 tcp 6 src=192.168.1.42 dst=8.8.8.8 sport=40000 dport=443 ",
        "packets=10 bytes=1000 src=8.8.8.8 dst=192.168.1.42 sport=443 dport=40000 ",
        "packets=20 bytes=2000 [OFFLOAD] mark=0 zone=0 use=3\n",
        "ipv4 2 tcp 6 src=192.168.1.42 dst=1.1.1.1 sport=40001 dport=443 ",
        "packets=10 bytes=1000 src=1.1.1.1 dst=192.168.1.42 sport=443 dport=40001 ",
        "packets=20 bytes=2000 [HW_OFFLOAD] mark=0 zone=0 use=3\n",
        "ipv4 2 udp 17 src=192.168.1.42 dst=8.8.8.8 sport=53000 dport=53 ",
        "packets=2 bytes=300 src=8.8.8.8 dst=192.168.1.42 sport=53 dport=53000 ",
        "packets=2 bytes=400 [OFFLOAD] mark=0 zone=0 use=3\n",
        "ipv4 2 udp 17 src=192.168.1.42 dst=192.0.2.1 sport=53001 dport=123 ",
        "packets=2 bytes=300 src=192.0.2.1 dst=192.168.1.42 sport=123 dport=53001 ",
        "packets=2 bytes=400 [HW_OFFLOAD] mark=0 zone=0 use=3\n",
        "ipv4 2 udp 17 src=192.168.1.42 dst=192.0.2.2 sport=53002 dport=123 ",
        "packets=1 bytes=100 [UNREPLIED] src=192.0.2.2 dst=192.168.1.42 sport=123 dport=53002 ",
        "packets=0 bytes=0 [OFFLOAD] mark=0 zone=0 use=3\n",
        "ipv4 2 tcp 6 10 TIME_WAIT src=192.168.1.42 dst=192.0.2.3 sport=40002 dport=443 ",
        "packets=10 bytes=1000 src=192.0.2.3 dst=192.168.1.42 sport=443 dport=40002 ",
        "packets=20 bytes=2000 [OFFLOAD] mark=0 zone=0 use=3\n",
    );
    let parsed = parse_reader(Cursor::new(text), "/proc/net/nf_conntrack").unwrap();
    assert_eq!(parsed.flows.len(), 6);
    assert!(parsed.flows[..4].iter().all(|flow| flow.assured));
    assert_eq!(parsed.flows[0].tcp_state, Some(TcpState::Established));
    assert_eq!(parsed.flows[1].tcp_state, Some(TcpState::Established));
    assert!(!parsed.flows[4].assured);
    assert_eq!(parsed.flows[5].tcp_state, Some(TcpState::TimeWait));
    assert!(parsed
        .flows
        .iter()
        .all(|flow| flow.conntrack_zone == Some(0)));

    let snapshot = aggregate_flows(&identities(), parsed.flows.iter(), 10, 8);
    assert_eq!(snapshot.stats.conntrack_ids_present, 0);
    assert_eq!(snapshot.stats.conntrack_zones_present, 6);
    let client = &snapshot.clients[0];
    assert_eq!(client.tcp_conns, 2);
    assert_eq!(
        (
            client.udp_conns,
            client.udp_dns_conns,
            client.udp_other_conns
        ),
        (2, 1, 1)
    );
}

#[test]
fn procfs_requires_orig_accounting_accepts_missing_reply_and_strict_numbers() {
    let text = concat!(
        "ipv4 2 udp 17 20 src=192.168.1.42 dst=8.8.8.8 sport=12x dport=53 packets=2 bytes=100 [ASSURED]\n",
        "ipv4 2 tcp 6 20 ESTABLISHED src=192.168.1.42 dst=8.8.8.8 sport=1 dport=443 packets=2 [ASSURED]\n",
    );
    let parsed = parse_reader(Cursor::new(text), "fixture").unwrap();
    assert_eq!(parsed.flows.len(), 1);
    assert_eq!(parsed.flows[0].reply_bytes, 0);
    assert_eq!(parsed.flows[0].orig_sport, 0);
    assert_eq!(parsed.entries_seen, 2);
    assert_eq!(parsed.malformed_lines, 1);
}

#[test]
fn procfs_drains_and_rejects_an_oversized_line_before_parsing_the_next() {
    let mut text = "x".repeat(CONNTRACK_LINE_MAX + 20);
    text.push('\n');
    text.push_str(
        "ipv4 2 udp 17 20 src=192.168.1.42 dst=8.8.8.8 sport=1 dport=2 packets=1 bytes=3\n",
    );
    let parsed = parse_reader(Cursor::new(text), "fixture").unwrap();
    assert_eq!(parsed.malformed_lines, 1);
    assert_eq!(parsed.flows.len(), 1);
}

#[test]
fn procfs_io_errors_are_not_silently_treated_as_eof() {
    struct Broken;
    impl std::io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        }
    }
    assert!(matches!(
        parse_reader(std::io::BufReader::new(Broken), "broken"),
        Err(ProcfsError::Io(_))
    ));
}

const NLM_F_MULTI: u16 = 2;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const CT_NEW: u16 = 1 << 8;

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = 4 + payload.len();
    let mut out = Vec::with_capacity(align4(len));
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align4(len), 0);
    out
}

fn nested(kind: u16, children: &[Vec<u8>]) -> Vec<u8> {
    attr(kind | 0x8000, &children.concat())
}

fn tuple(v6: bool, src: &[u8], dst: &[u8], proto: u8, sport: u16, dport: u16) -> Vec<u8> {
    tuple_parts(v6, Some(src), Some(dst), proto, Some(sport), Some(dport))
}

fn tuple_parts(
    v6: bool,
    src: Option<&[u8]>,
    dst: Option<&[u8]>,
    proto: u8,
    sport: Option<u16>,
    dport: Option<u16>,
) -> Vec<u8> {
    let mut ip_parts = Vec::new();
    if let Some(src) = src {
        ip_parts.push(attr(if v6 { 3 } else { 1 }, src));
    }
    if let Some(dst) = dst {
        ip_parts.push(attr(if v6 { 4 } else { 2 }, dst));
    }
    let ip = nested(1, &ip_parts);
    let mut proto_parts = vec![attr(1, &[proto])];
    if let Some(sport) = sport {
        proto_parts.push(attr(2, &sport.to_be_bytes()));
    }
    if let Some(dport) = dport {
        proto_parts.push(attr(3, &dport.to_be_bytes()));
    }
    let proto = nested(2, &proto_parts);
    nested(1, &[ip, proto])
}

fn nlmsg(kind: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = 16 + payload.len();
    let mut out = Vec::with_capacity(align4(len));
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align4(len), 0);
    out
}

fn data_message(seq: u32, v6: bool, counter32: bool) -> Vec<u8> {
    let (src, dst, reply_src, reply_dst): (&[u8], &[u8], &[u8], &[u8]) = if v6 {
        (
            &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42],
            &[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            &[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42],
        )
    } else {
        (
            &[192, 168, 1, 42],
            &[8, 8, 8, 8],
            &[8, 8, 8, 8],
            &[203, 0, 113, 2],
        )
    };
    data_message_with_tuples(
        seq,
        tuple(v6, src, dst, 17, 53000, 53),
        Some(tuple(v6, reply_src, reply_dst, 17, 53, 53000)),
        counter32,
    )
}

fn data_message_with_tuples(
    seq: u32,
    orig: Vec<u8>,
    reply: Option<Vec<u8>>,
    counter32: bool,
) -> Vec<u8> {
    data_message_with_tuples_and_state(seq, orig, reply, counter32, 1 << 2, None)
}

fn data_message_with_tuples_and_state(
    seq: u32,
    orig: Vec<u8>,
    reply: Option<Vec<u8>>,
    counter32: bool,
    status: u32,
    tcp_protoinfo: Option<Option<u8>>,
) -> Vec<u8> {
    let mut attrs = orig;
    if let Some(mut reply) = reply {
        reply[2..4].copy_from_slice(&(2u16 | 0x8000).to_ne_bytes());
        attrs.extend(reply);
    }
    attrs.extend(attr(3, &status.to_be_bytes()));
    if let Some(tcp_state) = tcp_protoinfo {
        let tcp = tcp_state.map_or_else(Vec::new, |state| vec![nested(1, &[attr(1, &[state])])]);
        attrs.extend(nested(4, &tcp));
    }
    let counter = if counter32 {
        attr(4, &1234u32.to_be_bytes())
    } else {
        attr(2, &1234u64.to_be_bytes())
    };
    attrs.extend(nested(9, &[counter]));
    attrs.extend(nested(10, &[attr(2, &5678u64.to_be_bytes())]));
    attrs.extend(attr(12, &0x1234_5678u32.to_be_bytes()));
    attrs.extend(attr(18, &7u16.to_be_bytes()));
    let mut payload = vec![0, 0, 0, 0];
    payload.extend(attrs);
    nlmsg(CT_NEW, NLM_F_MULTI, seq, &payload)
}

fn done(seq: u32, flags: u16, error: i32) -> Vec<u8> {
    nlmsg(NLMSG_DONE, flags, seq, &error.to_ne_bytes())
}

#[test]
fn netlink_parses_v4_v6_unaligned_attrs_and_be32_be64_counters() {
    let seq = 77;
    let mut bytes = data_message(seq, false, true);
    bytes.extend(data_message(seq, true, false));
    bytes.extend(done(seq, NLM_F_MULTI, 0));
    let flows = parse_dump(&[Datagram::kernel(bytes)], seq).unwrap();
    assert_eq!(flows.len(), 2);
    assert_eq!(flows[0].orig_src.unwrap().to_string(), "192.168.1.42");
    assert_eq!((flows[0].orig_bytes, flows[0].reply_bytes), (1234, 5678));
    assert_eq!(flows[0].conntrack_id, Some(0x1234_5678));
    assert_eq!(flows[0].conntrack_zone, Some(7));
    assert_eq!(flows[1].orig_src.unwrap().to_string(), "fd00::42");
    assert!(flows.iter().all(|flow| flow.assured && flow.is_dns()));
}

#[test]
fn netlink_infers_established_only_for_offloaded_tcp_without_protoinfo() {
    const IPS_ASSURED: u32 = 1 << 2;
    const IPS_OFFLOAD: u32 = 1 << 14;
    const IPS_HW_OFFLOAD: u32 = 1 << 15;
    const TCP_CONNTRACK_TIME_WAIT: u8 = 7;

    let seq = 78;
    let src = [192, 168, 1, 42];
    let dst = [8, 8, 8, 8];
    let make = |status, tcp_protoinfo| {
        data_message_with_tuples_and_state(
            seq,
            tuple(false, &src, &dst, 6, 40_000, 443),
            Some(tuple(false, &dst, &src, 6, 443, 40_000)),
            false,
            status,
            tcp_protoinfo,
        )
    };
    let mut bytes = make(IPS_ASSURED, None);
    bytes.extend(make(IPS_ASSURED | IPS_OFFLOAD, None));
    bytes.extend(make(IPS_ASSURED | IPS_HW_OFFLOAD, None));
    bytes.extend(make(
        IPS_ASSURED | IPS_OFFLOAD,
        Some(Some(TCP_CONNTRACK_TIME_WAIT)),
    ));
    bytes.extend(make(IPS_ASSURED | IPS_OFFLOAD, Some(None)));
    bytes.extend(done(seq, NLM_F_MULTI, 0));

    let flows = parse_dump(&[Datagram::kernel(bytes)], seq).unwrap();
    assert_eq!(flows.len(), 5);
    assert_eq!(flows[0].tcp_state, None);
    assert_eq!(flows[1].tcp_state, Some(TcpState::Established));
    assert_eq!(flows[2].tcp_state, Some(TcpState::Established));
    assert_eq!(flows[3].tcp_state, Some(TcpState::TimeWait));
    assert_eq!(flows[4].tcp_state, None);
    assert!(flows.iter().all(|flow| flow.assured));

    let snapshot = aggregate_flows(&identities(), flows.iter(), 10, 8);
    assert_eq!(snapshot.clients[0].tcp_conns, 2);
}

#[test]
fn netlink_requires_kernel_sender_matching_seq_and_clean_done() {
    let seq = 88;
    let valid = || {
        let mut bytes = data_message(seq, false, false);
        bytes.extend(done(seq, NLM_F_MULTI, 0));
        bytes
    };
    assert!(matches!(
        parse_dump(
            &[Datagram {
                sender_pid: 9,
                bytes: valid()
            }],
            seq
        ),
        Err(DumpError::UnexpectedSender(9))
    ));
    assert!(matches!(
        parse_dump(&[Datagram::kernel(valid())], seq + 1),
        Err(DumpError::UnexpectedSequence { .. })
    ));
    assert!(matches!(
        parse_dump(&[Datagram::kernel(data_message(seq, false, false))], seq),
        Err(DumpError::MissingDone)
    ));
    assert!(matches!(
        parse_dump(
            &[Datagram::kernel(done(
                seq,
                NLM_F_MULTI | NLM_F_DUMP_INTR,
                0
            ))],
            seq
        ),
        Err(DumpError::Interrupted)
    ));
    assert!(matches!(
        parse_dump(&[Datagram::kernel(done(seq, NLM_F_MULTI, -libc::EIO))], seq),
        Err(DumpError::Kernel(_))
    ));

    let mut wrong_type = data_message(seq, false, false);
    wrong_type[4..6].copy_from_slice(&0x7777u16.to_ne_bytes());
    wrong_type.extend(done(seq, NLM_F_MULTI, 0));
    assert!(matches!(
        parse_dump(&[Datagram::kernel(wrong_type)], seq),
        Err(DumpError::Malformed(_))
    ));

    let mut not_multipart = data_message(seq, false, false);
    not_multipart[6..8].copy_from_slice(&0u16.to_ne_bytes());
    not_multipart.extend(done(seq, NLM_F_MULTI, 0));
    assert!(matches!(
        parse_dump(&[Datagram::kernel(not_multipart)], seq),
        Err(DumpError::Malformed(_))
    ));
}

#[test]
fn netlink_batch_parser_keeps_state_across_datagrams() {
    let seq = 0x5a5a;
    let datagrams = [
        Datagram::kernel(data_message(seq, false, false)),
        Datagram::kernel(data_message(seq, true, false)),
        Datagram::kernel(done(seq, NLM_F_MULTI, 0)),
    ];

    let parsed = parse_dump_detailed(&datagrams, seq).unwrap();
    assert_eq!(parsed.flows.len(), 2);
    assert_eq!(
        parsed.flows[0].orig_src.unwrap().to_string(),
        "192.168.1.42"
    );
    assert_eq!(parsed.flows[1].orig_src.unwrap().to_string(), "fd00::42");
    assert_eq!(parsed.malformed_entries, 0);
}

#[test]
fn netlink_streaming_aggregate_matches_vec_snapshot_across_datagrams() {
    let seq = 0x5a5c;
    let mut malformed = data_message(seq, false, false);
    malformed[22..24].copy_from_slice(&2u16.to_ne_bytes());
    let datagrams = [
        Datagram::kernel(data_message(seq, false, false)),
        Datagram::kernel(malformed),
        Datagram::kernel(data_message(seq, true, false)),
        Datagram::kernel(done(seq, NLM_F_MULTI, 0)),
    ];
    let table = identities();
    let now_ms = 91_337;

    let vec_snapshot = snapshot_from_datagrams(&datagrams, seq).unwrap();
    let expected = aggregate_flows(&table, vec_snapshot.flows.iter(), now_ms, 8);
    let streaming = aggregate_dump(&datagrams, seq, &table, now_ms, 8).unwrap();

    assert_eq!(streaming.aggregate, expected);
    assert_eq!(streaming.source_path, NETLINK_SOURCE_PATH);
    assert_eq!(streaming.counter_source, NETLINK_COUNTER_SOURCE);
    assert_eq!(streaming.malformed_entries, 1);
    assert_eq!(streaming.entries_seen, 3);
    assert_eq!(streaming.aggregate.stats.entries_seen, 2);
    assert_eq!(streaming.aggregate.stats.conntrack_ids_present, 2);
    assert_eq!(streaming.aggregate.stats.conntrack_zones_present, 2);
}

#[test]
fn netlink_batch_parser_rejects_duplicate_done_and_later_messages_across_datagrams() {
    let seq = 0x5a5b;
    let duplicate_done = [
        Datagram::kernel(done(seq, NLM_F_MULTI, 0)),
        Datagram::kernel(done(seq, NLM_F_MULTI, 0)),
    ];
    assert!(matches!(
        parse_dump(&duplicate_done, seq),
        Err(DumpError::Malformed("duplicate NLMSG_DONE"))
    ));

    let message_after_done = [
        Datagram::kernel(done(seq, NLM_F_MULTI, 0)),
        Datagram::kernel(data_message(seq, false, false)),
    ];
    assert!(matches!(
        parse_dump(&message_after_done, seq),
        Err(DumpError::Malformed("message after NLMSG_DONE"))
    ));
}

#[test]
fn netlink_rejects_messages_after_done_and_short_control_payloads() {
    let seq = 89;
    let mut after_done_ack = done(seq, NLM_F_MULTI, 0);
    let mut ack_payload = 0i32.to_ne_bytes().to_vec();
    ack_payload.resize(20, 0);
    after_done_ack.extend(nlmsg(NLMSG_ERROR, 0, seq, &ack_payload));
    assert!(matches!(
        parse_dump(&[Datagram::kernel(after_done_ack)], seq),
        Err(DumpError::Malformed(_))
    ));

    let mut after_done_error = done(seq, NLM_F_MULTI, 0);
    let mut error_payload = (-libc::EIO).to_ne_bytes().to_vec();
    error_payload.resize(20, 0);
    after_done_error.extend(nlmsg(NLMSG_ERROR, 0, seq, &error_payload));
    assert!(matches!(
        parse_dump(&[Datagram::kernel(after_done_error)], seq),
        Err(DumpError::Malformed(_))
    ));
    assert!(matches!(
        parse_dump(
            &[Datagram::kernel(nlmsg(NLMSG_DONE, NLM_F_MULTI, seq, &[0]))],
            seq
        ),
        Err(DumpError::Malformed(_))
    ));
    assert!(matches!(
        parse_dump(
            &[Datagram::kernel(nlmsg(
                NLMSG_ERROR,
                0,
                seq,
                &0i32.to_ne_bytes()
            ))],
            seq
        ),
        Err(DumpError::Malformed(_))
    ));
}

#[test]
fn netlink_requires_complete_consistent_orig_and_present_reply_tuples() {
    let seq = 90;
    let v4_src = [192, 168, 1, 42];
    let v4_dst = [8, 8, 8, 8];
    let v4_reply_src = [8, 8, 8, 8];
    let v4_reply_dst = [203, 0, 113, 2];
    let v6_src = [0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let cases = [
        data_message_with_tuples(
            seq,
            tuple_parts(false, Some(&v4_src), None, 17, Some(1), Some(2)),
            None,
            false,
        ),
        data_message_with_tuples(
            seq,
            tuple_parts(false, Some(&v4_src), Some(&v4_dst), 17, None, Some(2)),
            None,
            false,
        ),
        data_message_with_tuples(
            seq,
            tuple_parts(false, Some(&v4_src), Some(&v4_dst), 17, Some(1), None),
            None,
            false,
        ),
        data_message_with_tuples(
            seq,
            tuple(false, &v4_src, &v4_dst, 17, 1, 2),
            Some(tuple_parts(
                false,
                Some(&v4_reply_src),
                None,
                17,
                Some(2),
                Some(1),
            )),
            false,
        ),
        data_message_with_tuples(
            seq,
            tuple(false, &v4_src, &v4_dst, 17, 1, 2),
            Some(tuple(false, &v4_reply_src, &v4_reply_dst, 6, 2, 1)),
            false,
        ),
        data_message_with_tuples(
            seq,
            tuple(false, &v4_src, &v4_dst, 17, 1, 2),
            Some(tuple(true, &v6_src, &v6_src, 17, 2, 1)),
            false,
        ),
    ];
    for mut message in cases {
        message.extend(done(seq, NLM_F_MULTI, 0));
        let parsed = parse_dump_detailed(&[Datagram::kernel(message)], seq).unwrap();
        assert!(parsed.flows.is_empty());
        assert_eq!(parsed.malformed_entries, 1);
    }

    let mut no_reply =
        data_message_with_tuples(seq, tuple(false, &v4_src, &v4_dst, 17, 1, 53), None, false);
    no_reply.extend(done(seq, NLM_F_MULTI, 0));
    assert_eq!(
        parse_dump(&[Datagram::kernel(no_reply)], seq)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn netlink_handles_ack_and_rejects_error_or_malformed_nested_lengths() {
    let seq = 99;
    let mut ack_payload = 0i32.to_ne_bytes().to_vec();
    ack_payload.resize(20, 0);
    let ack = nlmsg(NLMSG_ERROR, 0, seq, &ack_payload);
    let mut bytes = ack;
    bytes.extend(data_message(seq, false, false));
    bytes.extend(done(seq, NLM_F_MULTI, 0));
    assert_eq!(
        parse_dump(&[Datagram::kernel(bytes)], seq).unwrap().len(),
        1
    );

    let mut error_payload = (-libc::EPERM).to_ne_bytes().to_vec();
    error_payload.resize(20, 0);
    assert!(matches!(
        parse_dump(
            &[Datagram::kernel(nlmsg(NLMSG_ERROR, 0, seq, &error_payload))],
            seq
        ),
        Err(DumpError::Kernel(_))
    ));

    let mut malformed = data_message(seq, false, false);
    malformed[22..24].copy_from_slice(&2u16.to_ne_bytes());
    malformed.extend(done(seq, NLM_F_MULTI, 0));
    let parsed = parse_dump_detailed(&[Datagram::kernel(malformed)], seq).unwrap();
    assert!(parsed.flows.is_empty());
    assert_eq!(parsed.malformed_entries, 1);

    let mut no_nested_flag = data_message(seq, false, false);
    no_nested_flag[22..24].copy_from_slice(&1u16.to_ne_bytes());
    no_nested_flag.extend(done(seq, NLM_F_MULTI, 0));
    assert_eq!(
        parse_dump(&[Datagram::kernel(no_nested_flag)], seq)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn netlink_bounds_total_dump_and_rejects_duplicate_known_attributes() {
    let seq = 101;
    let bytes = data_message(seq, false, false);
    assert!(matches!(
        parse_dump_with_limit(&[Datagram::kernel(bytes.clone())], seq, bytes.len() - 1),
        Err(DumpError::LimitExceeded)
    ));

    let mut duplicate = data_message(seq, false, false);
    let extra = nested(9, &[attr(2, &9u64.to_be_bytes())]);
    let old_len = u32::from_ne_bytes(duplicate[0..4].try_into().unwrap()) as usize;
    duplicate.truncate(old_len);
    duplicate.extend(extra);
    let new_len = duplicate.len() as u32;
    duplicate[0..4].copy_from_slice(&new_len.to_ne_bytes());
    duplicate.resize(align4(duplicate.len()), 0);
    duplicate.extend(done(seq, NLM_F_MULTI, 0));
    let parsed = parse_dump_detailed(&[Datagram::kernel(duplicate)], seq).unwrap();
    assert!(parsed.flows.is_empty());
    assert_eq!(parsed.malformed_entries, 1);
}

#[test]
fn netlink_byte_limit_is_cumulative_across_datagrams() {
    let seq = 102;
    let data = data_message(seq, false, false);
    let done = done(seq, NLM_F_MULTI, 0);
    let total = data.len() + done.len();
    let datagrams = [Datagram::kernel(data), Datagram::kernel(done)];

    assert_eq!(
        parse_dump_with_limit(&datagrams, seq, total).unwrap().len(),
        1
    );
    assert!(matches!(
        parse_dump_with_limit(&datagrams, seq, total - 1),
        Err(DumpError::LimitExceeded)
    ));

    let over_limit_with_bad_sender = [
        Datagram {
            sender_pid: 9,
            bytes: vec![0; total],
        },
        Datagram::kernel(vec![0]),
    ];
    assert!(matches!(
        parse_dump_with_limit(&over_limit_with_bad_sender, seq, total),
        Err(DumpError::LimitExceeded)
    ));
}

#[test]
fn netlink_dump_request_matches_minimal_conntrack_uapi() {
    let request = build_dump_request(0x1122_3344, 0x5566_7788);
    assert_eq!(u32::from_ne_bytes(request[0..4].try_into().unwrap()), 20);
    assert_eq!(
        u16::from_ne_bytes(request[4..6].try_into().unwrap()),
        (1 << 8) | 1
    );
    assert_eq!(u16::from_ne_bytes(request[6..8].try_into().unwrap()), 0x301);
    assert_eq!(
        u32::from_ne_bytes(request[8..12].try_into().unwrap()),
        0x1122_3344
    );
    assert_eq!(
        u32::from_ne_bytes(request[12..16].try_into().unwrap()),
        0x5566_7788
    );
    assert_eq!(&request[16..20], &[libc::AF_UNSPEC as u8, 0, 0, 0]);
}

#[test]
fn netlink_response_header_pid_matches_local_port_while_sender_is_kernel() {
    let seq = 0x1234;
    let port_id = 0x5566_7788u32;
    let mut bytes = data_message(seq, false, false);
    bytes[12..16].copy_from_slice(&port_id.to_ne_bytes());
    let mut done_message = done(seq, NLM_F_MULTI, 0);
    done_message[12..16].copy_from_slice(&port_id.to_ne_bytes());
    bytes.extend(done_message);
    assert_eq!(
        parse_dump_for_port(&[Datagram::kernel(bytes)], seq, port_id)
            .unwrap()
            .len(),
        1
    );

    let mut wrong = data_message(seq, false, false);
    wrong[12..16].copy_from_slice(&(port_id + 1).to_ne_bytes());
    let mut done_message = done(seq, NLM_F_MULTI, 0);
    done_message[12..16].copy_from_slice(&port_id.to_ne_bytes());
    wrong.extend(done_message);
    assert!(matches!(
        parse_dump_for_port(&[Datagram::kernel(wrong)], seq, port_id),
        Err(DumpError::UnexpectedPortId { .. })
    ));
}

#[test]
fn netlink_datagram_truncation_is_a_dedicated_resource_error() {
    assert!(matches!(
        validate_received_datagram_len(MAX_DATAGRAM_BYTES + 1, MAX_DATAGRAM_BYTES),
        Err(DumpError::TruncatedDatagram { .. })
    ));
    assert_eq!(
        validate_received_datagram_len(MAX_DATAGRAM_BYTES, MAX_DATAGRAM_BYTES).unwrap(),
        MAX_DATAGRAM_BYTES
    );
}

#[test]
fn netlink_syscall_retry_retries_only_eintr() {
    let mut calls = 0;
    let value = retry_eintr(|| {
        calls += 1;
        if calls == 1 {
            Err(std::io::Error::from_raw_os_error(libc::EINTR))
        } else {
            Ok(7)
        }
    })
    .unwrap();
    assert_eq!((value, calls), (7, 2));

    let mut timeout_calls = 0;
    let error = retry_eintr(|| {
        timeout_calls += 1;
        Err::<(), _>(std::io::Error::from_raw_os_error(libc::EAGAIN))
    })
    .unwrap_err();
    assert_eq!(timeout_calls, 1);
    assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
}

#[test]
#[ignore = "requires an isolated, bounded live conntrack table"]
fn live_host_conntrack_netlink_dump_uses_kernel_sender_and_local_header_pid() {
    match read_netlink_snapshot() {
        Ok(snapshot) => {
            assert_eq!(snapshot.source_path, "netlink:ctnetlink");
            assert_eq!(
                snapshot.counter_source,
                "ctnetlink_conntrack_acct_orig_reply_bytes"
            );
        }
        Err(DumpError::Kernel(error))
            if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {}
        Err(error) => panic!("host conntrack netlink smoke failed: {error}"),
    }
}

#[test]
fn procfs_runtime_aggregation_is_streaming_and_bounded_by_clients() {
    let table = identities();
    let line = concat!(
        "ipv4 2 udp 17 20 src=192.168.1.42 dst=8.8.8.8 sport=53000 dport=53 ",
        "packets=2 bytes=3 src=8.8.8.8 dst=192.168.1.42 sport=53 dport=53000 ",
        "packets=2 bytes=4 [ASSURED]\n"
    );
    let input = line.repeat(20_000);
    let snapshot = aggregate_reader(Cursor::new(input), "fixture", &table, 10, 1).unwrap();
    assert_eq!(snapshot.aggregate.clients.len(), 1);
    assert_eq!(snapshot.entries_seen, 20_000);
    assert_eq!(snapshot.malformed_lines, 0);
    assert_eq!(snapshot.aggregate.stats.entries_matched, 20_000);
    assert_eq!(snapshot.aggregate.clients[0].tx_bytes, 60_000);
    assert_eq!(snapshot.aggregate.clients[0].rx_bytes, 80_000);
    assert_eq!(snapshot.aggregate.clients[0].udp_dns_conns, 20_000);
}

#[test]
fn procfs_vec_snapshot_helper_has_an_explicit_flow_cap() {
    let line = "ipv4 2 udp 17 20 src=192.168.1.42 dst=8.8.8.8 sport=1 dport=2 packets=1 bytes=3\n";
    let input = line.repeat(PROCFS_PARSE_FLOW_CAP + 1);
    assert!(matches!(
        parse_reader(Cursor::new(input), "fixture"),
        Err(ProcfsError::FlowLimit(limit)) if limit == PROCFS_PARSE_FLOW_CAP
    ));
}

#[test]
fn collector_modes_preserve_source_evidence_and_fallback_policy() {
    let table = identities();
    let make_flow = || flow("192.168.1.42", "8.8.8.8", "8.8.8.8", "192.168.1.42");
    let automatic = collect_with(
        CollectorMode::Auto,
        &table,
        10,
        8,
        || {
            Err(CollectorReadError::Netlink(DumpError::Kernel(
                std::io::Error::from_raw_os_error(libc::EPERM),
            )))
        },
        || {
            Ok(ProcfsSnapshot {
                flows: vec![make_flow()],
                source_path: "/proc/net/nf_conntrack".into(),
                counter_source: "procfs_conntrack_acct_orig_reply_bytes",
                entries_seen: 1,
                malformed_lines: 0,
            })
        },
    )
    .unwrap();
    assert!(automatic.stats.netlink_attempted);
    assert_eq!(automatic.stats.netlink_errno, Some(libc::EPERM));
    assert!(automatic.stats.procfs_read);
    assert_eq!(automatic.stats.source_path, "/proc/net/nf_conntrack");
    assert_eq!(
        automatic.counter_source,
        "procfs_conntrack_acct_orig_reply_bytes"
    );

    let no_errno_fallback = collect_with(
        CollectorMode::Auto,
        &table,
        10,
        8,
        || Err(CollectorReadError::Netlink(DumpError::MissingDone)),
        || {
            Ok(ProcfsSnapshot {
                flows: vec![make_flow()],
                source_path: "/proc/net/nf_conntrack".into(),
                counter_source: "procfs_conntrack_acct_orig_reply_bytes",
                entries_seen: 1,
                malformed_lines: 0,
            })
        },
    )
    .unwrap();
    assert!(no_errno_fallback.stats.netlink_attempted);
    assert_eq!(no_errno_fallback.stats.netlink_errno, None);

    let forced_netlink = collect_with(
        CollectorMode::Netlink,
        &table,
        10,
        8,
        || Err(CollectorReadError::Netlink(DumpError::MissingDone)),
        || panic!("forced netlink must not fall back"),
    );
    assert!(matches!(
        forced_netlink,
        Err(CollectorReadError::Netlink(DumpError::MissingDone))
    ));

    let forced_procfs = collect_with(
        CollectorMode::Procfs,
        &table,
        10,
        8,
        || panic!("forced procfs must not attempt netlink"),
        || {
            Ok(ProcfsSnapshot {
                flows: vec![make_flow()],
                source_path: "/proc/net/ip_conntrack".into(),
                counter_source: "procfs_conntrack_acct_orig_reply_bytes",
                entries_seen: 1,
                malformed_lines: 0,
            })
        },
    )
    .unwrap();
    assert!(!forced_procfs.stats.netlink_attempted);
    assert_eq!(forced_procfs.stats.source_path, "/proc/net/ip_conntrack");

    let netlink = collect_with(
        CollectorMode::Auto,
        &table,
        10,
        8,
        || {
            Ok(NetlinkSnapshot {
                flows: vec![make_flow()],
                source_path: "netlink:ctnetlink",
                counter_source: "ctnetlink_conntrack_acct_orig_reply_bytes",
                malformed_entries: 0,
            })
        },
        || panic!("successful netlink must not fall back"),
    )
    .unwrap();
    assert!(netlink.stats.netlink_read);
    assert_eq!(
        netlink.counter_source,
        "ctnetlink_conntrack_acct_orig_reply_bytes"
    );
}

#[test]
fn netlink_collector_entries_seen_includes_malformed_flow_attempts() {
    let table = identities();
    let snapshot = collect_with(
        CollectorMode::Netlink,
        &table,
        10,
        8,
        || {
            Ok(NetlinkSnapshot {
                flows: vec![flow("192.168.1.42", "8.8.8.8", "8.8.8.8", "192.168.1.42")],
                source_path: "netlink:ctnetlink",
                counter_source: "ctnetlink_conntrack_acct_orig_reply_bytes",
                malformed_entries: 1,
            })
        },
        || panic!("forced netlink must not read procfs"),
    )
    .unwrap();

    assert_eq!(snapshot.stats.entries_seen, 2);
    assert_eq!(snapshot.stats.malformed_lines, 1);
    assert_eq!(snapshot.stats.entries_matched, 1);
}
