//! Bounded Ethernet/IP transport parsing shared by userspace and eBPF.

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_VLAN_AD: u16 = 0x88a8;
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_ESP: u8 = 50;
const IPPROTO_AH: u8 = 51;
const IPPROTO_NONE: u8 = 59;
const IPPROTO_DSTOPTS: u8 = 60;
const MAX_IPV6_EXTENSION_HEADERS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AddressFamily {
    Ipv4 = 2,
    Ipv6 = 10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransportProtocol {
    Tcp = IPPROTO_TCP,
    Udp = IPPROTO_UDP,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketIdentity {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub family: AddressFamily,
    pub protocol: TransportProtocol,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    TruncatedEthernet,
    UnsupportedEtherType,
    TruncatedIpv4,
    InvalidIpv4HeaderLength,
    InvalidIpv4TotalLength,
    NonInitialIpv4Fragment,
    TruncatedIpv6,
    InvalidIpVersion,
    UnsupportedTransportProtocol,
    TruncatedTcp,
    InvalidTcpHeaderLength,
    TruncatedUdp,
    InvalidUdpLength,
}

pub fn vlan_zone(tci: u16) -> u16 {
    tci & 0x0fff
}

pub fn is_valid_client_mac(mac: [u8; 6]) -> bool {
    mac[0] & 1 == 0 && mac != [0; 6] && mac != [0xff; 6]
}

/// Returns the L2+L3+L4 bytes repeated for each segment represented by a GRO skb.
///
/// The caller supplies a bounded packet prefix. Unsupported or truncated
/// layouts return `None` so accounting can retain the legacy one-skb delta.
pub fn gro_repeated_header_len(frame: &[u8]) -> Option<u16> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }

    let mut network_offset = ETHERNET_HEADER_LEN;
    let mut ethertype = read_u16(frame, 12)?;
    if is_vlan_ethertype(ethertype) {
        ethertype = vlan_inner_ethertype(frame, network_offset)?;
        network_offset += 4;
        if is_vlan_ethertype(ethertype) {
            ethertype = vlan_inner_ethertype(frame, network_offset)?;
            network_offset += 4;
            if is_vlan_ethertype(ethertype) {
                return None;
            }
        }
    }

    let header_len = match ethertype {
        ETHERTYPE_IPV4 => gro_ipv4_header_len(frame, network_offset)?,
        ETHERTYPE_IPV6 => gro_ipv6_header_len(frame, network_offset)?,
        _ => return None,
    };
    u16::try_from(header_len).ok()
}

fn is_vlan_ethertype(ethertype: u16) -> bool {
    ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_VLAN_AD
}

fn vlan_inner_ethertype(frame: &[u8], offset: usize) -> Option<u16> {
    checked_end(frame, offset, 4)?;
    read_u16(frame, offset + 2)
}

fn gro_ipv4_header_len(frame: &[u8], offset: usize) -> Option<usize> {
    checked_end(frame, offset, IPV4_MIN_HEADER_LEN)?;
    let version_ihl = frame[offset];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl_words = version_ihl & 0x0f;
    if ihl_words < 5 {
        return None;
    }
    let transport_offset = offset.checked_add(usize::from(ihl_words) * 4)?;
    if transport_offset > frame.len() {
        return None;
    }
    if read_u16(frame, offset + 6)? & 0x1fff != 0 {
        return None;
    }
    gro_transport_header_end(frame, transport_offset, frame[offset + 9])
}

fn gro_ipv6_header_len(frame: &[u8], offset: usize) -> Option<usize> {
    let mut transport_offset = checked_end(frame, offset, IPV6_HEADER_LEN)?;
    if frame[offset] >> 4 != 6 {
        return None;
    }
    let mut next_header = frame[offset + 6];

    for extension_count in 0..=MAX_IPV6_EXTENSION_HEADERS {
        match next_header {
            IPPROTO_TCP | IPPROTO_UDP => {
                return gro_transport_header_end(frame, transport_offset, next_header);
            }
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                if extension_count == MAX_IPV6_EXTENSION_HEADERS {
                    return None;
                }
                checked_end(frame, transport_offset, 2)?;
                next_header = frame[transport_offset];
                let extension_len = (usize::from(frame[transport_offset + 1]) + 1) * 8;
                transport_offset = checked_end(frame, transport_offset, extension_len)?;
            }
            IPPROTO_FRAGMENT => {
                if extension_count == MAX_IPV6_EXTENSION_HEADERS {
                    return None;
                }
                checked_end(frame, transport_offset, 8)?;
                if read_u16(frame, transport_offset + 2)? & 0xfff8 != 0 {
                    return None;
                }
                next_header = frame[transport_offset];
                transport_offset += 8;
            }
            IPPROTO_AH => {
                if extension_count == MAX_IPV6_EXTENSION_HEADERS {
                    return None;
                }
                checked_end(frame, transport_offset, 2)?;
                next_header = frame[transport_offset];
                let extension_len = (usize::from(frame[transport_offset + 1]) + 2) * 4;
                transport_offset = checked_end(frame, transport_offset, extension_len)?;
            }
            IPPROTO_ESP | IPPROTO_NONE => return None,
            _ => return None,
        }
    }
    None
}

fn gro_transport_header_end(frame: &[u8], offset: usize, protocol: u8) -> Option<usize> {
    match protocol {
        IPPROTO_TCP => {
            checked_end(frame, offset, TCP_MIN_HEADER_LEN)?;
            let data_offset_words = frame[offset + 12] >> 4;
            if data_offset_words < 5 {
                return None;
            }
            checked_end(frame, offset, usize::from(data_offset_words) * 4)
        }
        IPPROTO_UDP => checked_end(frame, offset, UDP_HEADER_LEN),
        _ => None,
    }
}

fn read_u16(frame: &[u8], offset: usize) -> Option<u16> {
    checked_end(frame, offset, 2)?;
    Some(u16::from_be_bytes([frame[offset], frame[offset + 1]]))
}

fn checked_end(frame: &[u8], offset: usize, len: usize) -> Option<usize> {
    let end = offset.checked_add(len)?;
    if end <= frame.len() {
        Some(end)
    } else {
        None
    }
}

pub fn parse_packet(frame: &[u8]) -> Result<PacketIdentity, ParseError> {
    parse_packet_prefix(frame, frame.len())
}

/// Parses transport identity from a bounded packet prefix.
///
/// `frame_len` is the complete skb length. The prefix must contain every
/// header byte used by the parser, while payload bytes after the transport
/// header may be omitted.
pub fn parse_packet_prefix(frame: &[u8], frame_len: usize) -> Result<PacketIdentity, ParseError> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(ParseError::TruncatedEthernet);
    }
    if frame_len < ETHERNET_HEADER_LEN {
        return Err(ParseError::TruncatedEthernet);
    }

    let mut dst_mac = [0; 6];
    dst_mac.copy_from_slice(&frame[0..6]);
    let mut src_mac = [0; 6];
    src_mac.copy_from_slice(&frame[6..12]);

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let payload = &frame[ETHERNET_HEADER_LEN..];
    let payload_len = frame_len - ETHERNET_HEADER_LEN;
    let network = match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(payload, payload_len)?,
        ETHERTYPE_IPV6 => parse_ipv6(payload, payload_len)?,
        _ => return Err(ParseError::UnsupportedEtherType),
    };

    Ok(PacketIdentity {
        src_mac,
        dst_mac,
        family: network.family,
        protocol: network.protocol,
        src_addr: network.src_addr,
        dst_addr: network.dst_addr,
        src_port: network.src_port,
        dst_port: network.dst_port,
    })
}

#[derive(Clone, Copy)]
struct NetworkIdentity {
    family: AddressFamily,
    protocol: TransportProtocol,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
}

fn parse_ipv4(packet: &[u8], packet_len: usize) -> Result<NetworkIdentity, ParseError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(ParseError::TruncatedIpv4);
    }
    if packet[0] >> 4 != 4 {
        return Err(ParseError::InvalidIpVersion);
    }

    let ihl_words = packet[0] & 0x0f;
    if ihl_words < 5 {
        return Err(ParseError::InvalidIpv4HeaderLength);
    }
    let header_len = usize::from(ihl_words) * 4;
    if packet.len() < header_len {
        return Err(ParseError::TruncatedIpv4);
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len {
        return Err(ParseError::InvalidIpv4TotalLength);
    }
    if packet_len < total_len {
        return Err(ParseError::TruncatedIpv4);
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x1fff != 0 {
        return Err(ParseError::NonInitialIpv4Fragment);
    }
    let allow_incomplete_datagram = fragment & 0x2000 != 0;
    let transport_len = total_len - header_len;

    let mut src_addr = [0; 16];
    src_addr[..4].copy_from_slice(&packet[12..16]);
    let mut dst_addr = [0; 16];
    dst_addr[..4].copy_from_slice(&packet[16..20]);
    let (protocol, src_port, dst_port) = parse_transport(
        packet[9],
        packet.get(header_len..).ok_or(ParseError::TruncatedIpv4)?,
        transport_len,
        allow_incomplete_datagram,
    )?;

    Ok(NetworkIdentity {
        family: AddressFamily::Ipv4,
        protocol,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
    })
}

fn parse_ipv6(packet: &[u8], packet_len: usize) -> Result<NetworkIdentity, ParseError> {
    if packet.len() < IPV6_HEADER_LEN {
        return Err(ParseError::TruncatedIpv6);
    }
    if packet[0] >> 4 != 6 {
        return Err(ParseError::InvalidIpVersion);
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let declared_len = IPV6_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(ParseError::TruncatedIpv6)?;
    if packet_len < declared_len {
        return Err(ParseError::TruncatedIpv6);
    }

    let mut src_addr = [0; 16];
    src_addr.copy_from_slice(&packet[8..24]);
    let mut dst_addr = [0; 16];
    dst_addr.copy_from_slice(&packet[24..40]);
    let (protocol, src_port, dst_port) =
        parse_transport(packet[6], &packet[IPV6_HEADER_LEN..], payload_len, false)?;

    Ok(NetworkIdentity {
        family: AddressFamily::Ipv6,
        protocol,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
    })
}

fn parse_transport(
    protocol: u8,
    transport: &[u8],
    transport_len: usize,
    allow_incomplete_datagram: bool,
) -> Result<(TransportProtocol, u16, u16), ParseError> {
    match protocol {
        IPPROTO_TCP => parse_tcp(transport, transport_len),
        IPPROTO_UDP => parse_udp(transport, transport_len, allow_incomplete_datagram),
        _ => Err(ParseError::UnsupportedTransportProtocol),
    }
}

fn parse_tcp(tcp: &[u8], tcp_len: usize) -> Result<(TransportProtocol, u16, u16), ParseError> {
    if tcp_len < TCP_MIN_HEADER_LEN || tcp.len() < TCP_MIN_HEADER_LEN {
        return Err(ParseError::TruncatedTcp);
    }

    let header_words = tcp[12] >> 4;
    if header_words < 5 {
        return Err(ParseError::InvalidTcpHeaderLength);
    }
    let header_len = usize::from(header_words) * 4;
    if tcp_len < header_len || tcp.len() < header_len {
        return Err(ParseError::TruncatedTcp);
    }

    Ok((
        TransportProtocol::Tcp,
        u16::from_be_bytes([tcp[0], tcp[1]]),
        u16::from_be_bytes([tcp[2], tcp[3]]),
    ))
}

fn parse_udp(
    udp: &[u8],
    udp_len: usize,
    allow_incomplete_datagram: bool,
) -> Result<(TransportProtocol, u16, u16), ParseError> {
    if udp_len < UDP_HEADER_LEN || udp.len() < UDP_HEADER_LEN {
        return Err(ParseError::TruncatedUdp);
    }
    let datagram_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if datagram_len < UDP_HEADER_LEN || (!allow_incomplete_datagram && datagram_len > udp_len) {
        return Err(ParseError::InvalidUdpLength);
    }

    Ok((
        TransportProtocol::Udp,
        u16::from_be_bytes([udp[0], udp[1]]),
        u16::from_be_bytes([udp[2], udp[3]]),
    ))
}
