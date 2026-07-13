use lanspeed_common::{
    accounting::{tc_frame_accounting, FrameAccounting},
    packet::gro_repeated_header_len,
    DIR_RX, DIR_TX,
};

#[test]
fn egress_uses_wire_length_and_gso_segment_count() {
    assert_eq!(
        tc_frame_accounting(DIR_RX, 65_536, 68_544, 44, None),
        FrameAccounting {
            bytes: 68_544,
            packets: 44,
        }
    );
}

#[test]
fn egress_falls_back_when_wire_length_is_zero() {
    assert_eq!(
        tc_frame_accounting(DIR_RX, 1_500, 0, 0, None),
        FrameAccounting {
            bytes: 1_500,
            packets: 1,
        }
    );
}

#[test]
fn egress_never_replaces_frame_length_with_a_shorter_wire_length() {
    assert_eq!(
        tc_frame_accounting(DIR_RX, 1_500, 1_400, 1, None),
        FrameAccounting {
            bytes: 1_500,
            packets: 1,
        }
    );
}

#[test]
fn ingress_gro_reconstructs_repeated_headers() {
    assert_eq!(
        tc_frame_accounting(DIR_TX, 65_536, 68_544, 44, Some(66)),
        FrameAccounting {
            bytes: 68_374,
            packets: 44,
        }
    );
}

#[test]
fn ingress_gro_falls_back_when_headers_are_unknown() {
    assert_eq!(
        tc_frame_accounting(DIR_TX, 65_536, 68_544, 44, None),
        FrameAccounting {
            bytes: 65_536,
            packets: 1,
        }
    );
}

#[test]
fn ingress_non_gro_ignores_header_metadata() {
    assert_eq!(
        tc_frame_accounting(DIR_TX, 1_500, 1_500, 1, Some(54)),
        FrameAccounting {
            bytes: 1_500,
            packets: 1,
        }
    );
}

fn ethernet(ethertype: u16) -> Vec<u8> {
    let mut frame = vec![0; 14];
    frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
    frame
}

fn push_ipv4(frame: &mut Vec<u8>, ihl_words: u8, protocol: u8) {
    let header_len = usize::from(ihl_words) * 4;
    let offset = frame.len();
    frame.resize(offset + header_len, 0);
    frame[offset] = 0x40 | ihl_words;
    frame[offset + 9] = protocol;
}

fn push_tcp(frame: &mut Vec<u8>, data_offset_words: u8) {
    let header_len = usize::from(data_offset_words) * 4;
    let offset = frame.len();
    frame.resize(offset + header_len, 0);
    frame[offset + 12] = data_offset_words << 4;
}

fn push_ipv6(frame: &mut Vec<u8>, next_header: u8) {
    let offset = frame.len();
    frame.resize(offset + 40, 0);
    frame[offset] = 0x60;
    frame[offset + 6] = next_header;
}

#[test]
fn gro_header_parser_honors_two_vlans_ipv4_ihl_and_tcp_offset() {
    let mut frame = ethernet(0x88a8);
    frame.extend_from_slice(&[0, 1, 0x81, 0x00]);
    frame.extend_from_slice(&[0, 2, 0x08, 0x00]);
    push_ipv4(&mut frame, 6, 6);
    push_tcp(&mut frame, 8);

    assert_eq!(gro_repeated_header_len(&frame), Some(78));
}

#[test]
fn gro_header_parser_accepts_ipv4_udp() {
    let mut frame = ethernet(0x0800);
    push_ipv4(&mut frame, 5, 17);
    frame.resize(frame.len() + 8, 0);

    assert_eq!(gro_repeated_header_len(&frame), Some(42));
}

#[test]
fn gro_header_parser_walks_bounded_ipv6_extension_headers() {
    let mut frame = ethernet(0x86dd);
    push_ipv6(&mut frame, 0);
    frame.extend_from_slice(&[60, 0, 0, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(&[6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    push_tcp(&mut frame, 5);

    assert_eq!(gro_repeated_header_len(&frame), Some(98));
}

#[test]
fn gro_header_parser_accepts_four_ipv6_extensions_and_udp() {
    let mut frame = ethernet(0x86dd);
    push_ipv6(&mut frame, 0);
    frame.extend_from_slice(&[60, 0, 0, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(&[43, 0, 0, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(&[51, 0, 0, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    frame.resize(frame.len() + 8, 0);

    assert_eq!(gro_repeated_header_len(&frame), Some(94));
}

#[test]
fn gro_header_parser_rejects_a_fifth_ipv6_extension() {
    let mut frame = ethernet(0x86dd);
    push_ipv6(&mut frame, 0);
    for next_header in [60, 43, 51, 0] {
        frame.extend_from_slice(&[next_header, 0, 0, 0, 0, 0, 0, 0]);
    }
    frame.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
    push_tcp(&mut frame, 5);

    assert_eq!(gro_repeated_header_len(&frame), None);
}

#[test]
fn gro_header_parser_rejects_truncated_and_unsupported_layouts() {
    let mut truncated = ethernet(0x0800);
    push_ipv4(&mut truncated, 5, 6);
    truncated.resize(truncated.len() + 19, 0);
    assert_eq!(gro_repeated_header_len(&truncated), None);

    let mut ipv4_non_initial_fragment = ethernet(0x0800);
    push_ipv4(&mut ipv4_non_initial_fragment, 5, 6);
    ipv4_non_initial_fragment[20..22].copy_from_slice(&1u16.to_be_bytes());
    push_tcp(&mut ipv4_non_initial_fragment, 5);
    assert_eq!(gro_repeated_header_len(&ipv4_non_initial_fragment), None);

    let mut non_initial_fragment = ethernet(0x86dd);
    push_ipv6(&mut non_initial_fragment, 44);
    non_initial_fragment.extend_from_slice(&[6, 0, 0, 8, 0, 0, 0, 0]);
    push_tcp(&mut non_initial_fragment, 5);
    assert_eq!(gro_repeated_header_len(&non_initial_fragment), None);

    let mut esp = ethernet(0x86dd);
    push_ipv6(&mut esp, 50);
    assert_eq!(gro_repeated_header_len(&esp), None);
}
