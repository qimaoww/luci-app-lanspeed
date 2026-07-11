use lanspeed_common::packet::{
    is_valid_client_mac, parse_packet, parse_packet_prefix, vlan_zone, AddressFamily,
    PacketIdentity, ParseError, TransportProtocol,
};

const SRC_MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const DST_MAC: [u8; 6] = [0x0a, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&DST_MAC);
    frame.extend_from_slice(&SRC_MAC);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn ipv4(protocol: u8, ihl_words: u8, transport: &[u8]) -> Vec<u8> {
    let header_len = usize::from(ihl_words) * 4;
    let mut packet = vec![0; header_len.max(20)];
    packet[0] = 0x40 | ihl_words;
    let total_len = header_len.max(20) + transport.len();
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
    packet.extend_from_slice(transport);
    packet
}

fn ipv6(next_header: u8, transport: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(transport.len() as u16).to_be_bytes());
    packet[6] = next_header;
    packet[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    packet.extend_from_slice(transport);
    packet
}

fn tcp(source: u16, destination: u16, header_words: u8) -> Vec<u8> {
    let mut header = vec![0; usize::from(header_words) * 4];
    header[0..2].copy_from_slice(&source.to_be_bytes());
    header[2..4].copy_from_slice(&destination.to_be_bytes());
    header[12] = header_words << 4;
    header
}

fn udp(source: u16, destination: u16) -> [u8; 8] {
    let mut header = [0; 8];
    header[0..2].copy_from_slice(&source.to_be_bytes());
    header[2..4].copy_from_slice(&destination.to_be_bytes());
    header[4..6].copy_from_slice(&8u16.to_be_bytes());
    header
}

#[test]
fn parses_ethernet_ipv4_tcp() {
    let frame = ethernet(0x0800, &ipv4(6, 5, &tcp(12_345, 443, 5)));

    assert_eq!(
        parse_packet(&frame),
        Ok(PacketIdentity {
            src_mac: SRC_MAC,
            dst_mac: DST_MAC,
            family: AddressFamily::Ipv4,
            protocol: TransportProtocol::Tcp,
            src_addr: [192, 0, 2, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_addr: [198, 51, 100, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_port: 12_345,
            dst_port: 443,
        })
    );
}

#[test]
fn parses_ipv4_udp_after_nonstandard_ihl() {
    let frame = ethernet(0x0800, &ipv4(17, 6, &udp(53, 50_000)));

    let identity = parse_packet(&frame).unwrap();
    assert_eq!(identity.protocol, TransportProtocol::Udp);
    assert_eq!(identity.src_port, 53);
    assert_eq!(identity.dst_port, 50_000);
}

#[test]
fn parses_ipv4_tcp_options() {
    let frame = ethernet(0x0800, &ipv4(6, 5, &tcp(22, 60_000, 6)));

    let identity = parse_packet(&frame).unwrap();
    assert_eq!(identity.src_port, 22);
    assert_eq!(identity.dst_port, 60_000);
}

#[test]
fn parses_ethernet_ipv6_tcp_and_udp() {
    for (protocol, transport, expected) in [
        (6, tcp(443, 32_000, 5), TransportProtocol::Tcp),
        (17, udp(5353, 9999).to_vec(), TransportProtocol::Udp),
    ] {
        let frame = ethernet(0x86dd, &ipv6(protocol, &transport));
        let identity = parse_packet(&frame).unwrap();

        assert_eq!(identity.family, AddressFamily::Ipv6);
        assert_eq!(identity.protocol, expected);
        assert_eq!(identity.src_addr[0..4], [0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(identity.dst_addr[15], 2);
    }
}

#[test]
fn rejects_truncated_packets_at_each_layer() {
    assert_eq!(parse_packet(&[0; 13]), Err(ParseError::TruncatedEthernet));

    let short_ipv4 = ethernet(0x0800, &[0x45; 19]);
    assert_eq!(parse_packet(&short_ipv4), Err(ParseError::TruncatedIpv4));

    let short_ipv6 = ethernet(0x86dd, &[0x60; 39]);
    assert_eq!(parse_packet(&short_ipv6), Err(ParseError::TruncatedIpv6));

    let short_tcp = ethernet(0x0800, &ipv4(6, 5, &[0; 19]));
    assert_eq!(parse_packet(&short_tcp), Err(ParseError::TruncatedTcp));

    let short_udp = ethernet(0x86dd, &ipv6(17, &[0; 7]));
    assert_eq!(parse_packet(&short_udp), Err(ParseError::TruncatedUdp));
}

#[test]
fn rejects_invalid_or_truncated_variable_headers() {
    let invalid_ipv4_ihl = ethernet(0x0800, &ipv4(6, 4, &tcp(1, 2, 5)));
    assert_eq!(
        parse_packet(&invalid_ipv4_ihl),
        Err(ParseError::InvalidIpv4HeaderLength)
    );

    let mut truncated_ipv4_options = ipv4(6, 6, &tcp(1, 2, 5));
    truncated_ipv4_options.truncate(23);
    assert_eq!(
        parse_packet(&ethernet(0x0800, &truncated_ipv4_options)),
        Err(ParseError::TruncatedIpv4)
    );

    let mut invalid_total_length = ipv4(17, 5, &udp(1, 2));
    invalid_total_length[2..4].copy_from_slice(&19u16.to_be_bytes());
    assert_eq!(
        parse_packet(&ethernet(0x0800, &invalid_total_length)),
        Err(ParseError::InvalidIpv4TotalLength)
    );

    let mut truncated_total_length = ipv4(17, 5, &udp(1, 2));
    truncated_total_length[2..4].copy_from_slice(&64u16.to_be_bytes());
    assert_eq!(
        parse_packet(&ethernet(0x0800, &truncated_total_length)),
        Err(ParseError::TruncatedIpv4)
    );

    let mut truncated_ipv6_payload = ipv6(17, &udp(1, 2));
    truncated_ipv6_payload[4..6].copy_from_slice(&64u16.to_be_bytes());
    assert_eq!(
        parse_packet(&ethernet(0x86dd, &truncated_ipv6_payload)),
        Err(ParseError::TruncatedIpv6)
    );

    let mut invalid_tcp_header = tcp(1, 2, 4);
    invalid_tcp_header.resize(20, 0);
    let invalid_tcp_options = ethernet(0x0800, &ipv4(6, 5, &invalid_tcp_header));
    assert_eq!(
        parse_packet(&invalid_tcp_options),
        Err(ParseError::InvalidTcpHeaderLength)
    );

    let mut truncated_tcp_options = tcp(1, 2, 6);
    truncated_tcp_options.truncate(20);
    assert_eq!(
        parse_packet(&ethernet(0x86dd, &ipv6(6, &truncated_tcp_options))),
        Err(ParseError::TruncatedTcp)
    );
}

#[test]
fn rejects_unsupported_ethertype_and_transport_protocol() {
    assert_eq!(
        parse_packet(&ethernet(0x0806, &[0; 28])),
        Err(ParseError::UnsupportedEtherType)
    );
    assert_eq!(
        parse_packet(&ethernet(0x0800, &ipv4(1, 5, &[0; 8]))),
        Err(ParseError::UnsupportedTransportProtocol)
    );
    assert_eq!(
        parse_packet(&ethernet(0x86dd, &ipv6(58, &[0; 8]))),
        Err(ParseError::UnsupportedTransportProtocol)
    );
}

#[test]
fn ip_declared_lengths_bound_transport_parsing_despite_ethernet_padding() {
    let mut short_ipv4_payload = ipv4(6, 5, &tcp(1, 2, 5));
    short_ipv4_payload[2..4].copy_from_slice(&22u16.to_be_bytes());
    short_ipv4_payload.extend_from_slice(&[0; 32]);
    assert_eq!(
        parse_packet(&ethernet(0x0800, &short_ipv4_payload)),
        Err(ParseError::TruncatedTcp)
    );

    let mut short_ipv6_payload = ipv6(17, &udp(1, 2));
    short_ipv6_payload[4..6].copy_from_slice(&7u16.to_be_bytes());
    short_ipv6_payload.extend_from_slice(&[0; 32]);
    assert_eq!(
        parse_packet(&ethernet(0x86dd, &short_ipv6_payload)),
        Err(ParseError::TruncatedUdp)
    );
}

#[test]
fn rejects_non_initial_ipv4_fragments() {
    let mut fragment = ipv4(17, 5, &udp(1, 2));
    fragment[6..8].copy_from_slice(&1u16.to_be_bytes());

    assert_eq!(
        parse_packet(&ethernet(0x0800, &fragment)),
        Err(ParseError::NonInitialIpv4Fragment)
    );
}

#[test]
fn rejects_invalid_udp_lengths() {
    let mut zero_length = udp(1, 2);
    zero_length[4..6].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        parse_packet(&ethernet(0x0800, &ipv4(17, 5, &zero_length))),
        Err(ParseError::InvalidUdpLength)
    );

    let mut short_length = udp(1, 2);
    short_length[4..6].copy_from_slice(&7u16.to_be_bytes());
    assert_eq!(
        parse_packet(&ethernet(0x86dd, &ipv6(17, &short_length))),
        Err(ParseError::InvalidUdpLength)
    );

    let mut oversized = udp(1, 2);
    oversized[4..6].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(
        parse_packet(&ethernet(0x0800, &ipv4(17, 5, &oversized))),
        Err(ParseError::InvalidUdpLength)
    );
    assert_eq!(
        parse_packet(&ethernet(0x86dd, &ipv6(17, &oversized))),
        Err(ParseError::InvalidUdpLength)
    );
}

#[test]
fn accepts_exact_udp_length_and_ignores_ip_payload_after_datagram() {
    let mut transport = udp(1, 2).to_vec();
    transport.extend_from_slice(&[0xaa; 4]);

    let identity = parse_packet(&ethernet(0x0800, &ipv4(17, 5, &transport))).unwrap();
    assert_eq!(identity.protocol, TransportProtocol::Udp);
    assert_eq!(identity.src_port, 1);
    assert_eq!(identity.dst_port, 2);
}

#[test]
fn allows_incomplete_udp_only_in_first_ipv4_fragment() {
    let mut first_fragment_udp = udp(1, 2);
    first_fragment_udp[4..6].copy_from_slice(&1200u16.to_be_bytes());
    let mut first_fragment = ipv4(17, 5, &first_fragment_udp);
    first_fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());

    assert!(parse_packet(&ethernet(0x0800, &first_fragment)).is_ok());

    let mut short_header = first_fragment_udp[..7].to_vec();
    short_header[4..6].copy_from_slice(&1200u16.to_be_bytes());
    let mut truncated_first_fragment = ipv4(17, 5, &short_header);
    truncated_first_fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    assert_eq!(
        parse_packet(&ethernet(0x0800, &truncated_first_fragment)),
        Err(ParseError::TruncatedUdp)
    );
}

#[test]
fn extracts_vlan_zone_from_low_twelve_bits() {
    assert_eq!(vlan_zone(0xbabc), 0x0abc);
}

#[test]
fn accepts_only_nonzero_unicast_client_macs() {
    assert!(is_valid_client_mac(SRC_MAC));
    assert!(!is_valid_client_mac([0; 6]));
    assert!(!is_valid_client_mac([0xff; 6]));
    assert!(!is_valid_client_mac([0x01, 0, 0x5e, 0, 0, 1]));
}

#[test]
fn parses_transport_headers_from_a_bounded_ipv4_prefix() {
    let mut frame = ethernet(0x0800, &ipv4(6, 5, &tcp(12_345, 443, 5)));
    frame.extend_from_slice(&[0xaa; 1200]);
    let frame_len = frame.len();
    frame[16..18].copy_from_slice(&((frame_len - 14) as u16).to_be_bytes());
    frame.truncate(96);

    let identity = parse_packet_prefix(&frame, frame_len).unwrap();
    assert_eq!(identity.protocol, TransportProtocol::Tcp);
    assert_eq!(identity.src_port, 12_345);
    assert_eq!(identity.dst_port, 443);
}

#[test]
fn bounded_prefix_still_rejects_lengths_beyond_the_real_packet() {
    let mut frame = ethernet(0x86dd, &ipv6(17, &udp(1, 2)));
    frame[18..20].copy_from_slice(&1200u16.to_be_bytes());

    assert_eq!(
        parse_packet_prefix(&frame, frame.len()),
        Err(ParseError::TruncatedIpv6)
    );
}
