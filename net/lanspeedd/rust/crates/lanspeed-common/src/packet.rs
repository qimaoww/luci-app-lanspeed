//! Bounded Ethernet/IP transport parsing shared by userspace and eBPF.

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

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
}

pub fn vlan_zone(tci: u16) -> u16 {
    tci & 0x0fff
}

pub fn is_valid_client_mac(mac: [u8; 6]) -> bool {
    mac[0] & 1 == 0 && mac != [0; 6] && mac != [0xff; 6]
}

pub fn parse_packet(frame: &[u8]) -> Result<PacketIdentity, ParseError> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(ParseError::TruncatedEthernet);
    }

    let mut dst_mac = [0; 6];
    dst_mac.copy_from_slice(&frame[0..6]);
    let mut src_mac = [0; 6];
    src_mac.copy_from_slice(&frame[6..12]);

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let payload = &frame[ETHERNET_HEADER_LEN..];
    let network = match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(payload)?,
        ETHERTYPE_IPV6 => parse_ipv6(payload)?,
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

fn parse_ipv4(packet: &[u8]) -> Result<NetworkIdentity, ParseError> {
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
    if packet.len() < total_len {
        return Err(ParseError::TruncatedIpv4);
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x1fff != 0 {
        return Err(ParseError::NonInitialIpv4Fragment);
    }

    let mut src_addr = [0; 16];
    src_addr[..4].copy_from_slice(&packet[12..16]);
    let mut dst_addr = [0; 16];
    dst_addr[..4].copy_from_slice(&packet[16..20]);
    let (protocol, src_port, dst_port) =
        parse_transport(packet[9], &packet[header_len..total_len])?;

    Ok(NetworkIdentity {
        family: AddressFamily::Ipv4,
        protocol,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
    })
}

fn parse_ipv6(packet: &[u8]) -> Result<NetworkIdentity, ParseError> {
    if packet.len() < IPV6_HEADER_LEN {
        return Err(ParseError::TruncatedIpv6);
    }
    if packet[0] >> 4 != 6 {
        return Err(ParseError::InvalidIpVersion);
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let packet_len = IPV6_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(ParseError::TruncatedIpv6)?;
    if packet.len() < packet_len {
        return Err(ParseError::TruncatedIpv6);
    }

    let mut src_addr = [0; 16];
    src_addr.copy_from_slice(&packet[8..24]);
    let mut dst_addr = [0; 16];
    dst_addr.copy_from_slice(&packet[24..40]);
    let (protocol, src_port, dst_port) =
        parse_transport(packet[6], &packet[IPV6_HEADER_LEN..packet_len])?;

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
) -> Result<(TransportProtocol, u16, u16), ParseError> {
    match protocol {
        IPPROTO_TCP => parse_tcp(transport),
        IPPROTO_UDP => parse_udp(transport),
        _ => Err(ParseError::UnsupportedTransportProtocol),
    }
}

fn parse_tcp(tcp: &[u8]) -> Result<(TransportProtocol, u16, u16), ParseError> {
    if tcp.len() < TCP_MIN_HEADER_LEN {
        return Err(ParseError::TruncatedTcp);
    }

    let header_words = tcp[12] >> 4;
    if header_words < 5 {
        return Err(ParseError::InvalidTcpHeaderLength);
    }
    if tcp.len() < usize::from(header_words) * 4 {
        return Err(ParseError::TruncatedTcp);
    }

    Ok((
        TransportProtocol::Tcp,
        u16::from_be_bytes([tcp[0], tcp[1]]),
        u16::from_be_bytes([tcp[2], tcp[3]]),
    ))
}

fn parse_udp(udp: &[u8]) -> Result<(TransportProtocol, u16, u16), ParseError> {
    if udp.len() < UDP_HEADER_LEN {
        return Err(ParseError::TruncatedUdp);
    }

    Ok((
        TransportProtocol::Udp,
        u16::from_be_bytes([udp[0], udp[1]]),
        u16::from_be_bytes([udp[2], udp[3]]),
    ))
}
