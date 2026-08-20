use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs, io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

mod counter_extender;

use counter_extender::extend_station_counters;

use super::rate::LinkCounters;

const NETLINK_GENERIC: libc::c_int = 16;
const GENL_ID_CTRL: u16 = 0x10;
const GENL_HEADER_LEN: usize = 4;
const NLMSG_HEADER_LEN: usize = 16;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const CTRL_CMD_NEWFAMILY: u8 = 1;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NL80211_GENL_VERSION: u8 = 1;
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_GET_STATION: u8 = 17;
const NL80211_CMD_NEW_STATION: u8 = 19;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_STA_INFO: u16 = 21;
const NL80211_STA_INFO_RX_BYTES: u16 = 2;
const NL80211_STA_INFO_TX_BYTES: u16 = 3;
const NL80211_STA_INFO_RX_PACKETS: u16 = 9;
const NL80211_STA_INFO_TX_PACKETS: u16 = 10;
const NL80211_STA_INFO_CONNECTED_TIME: u16 = 16;
const NL80211_STA_INFO_RX_BYTES64: u16 = 23;
const NL80211_STA_INFO_TX_BYTES64: u16 = 24;
const NL80211_STA_INFO_ASSOC_AT_BOOTTIME: u16 = 42;
const NLA_TYPE_MASK: u16 = 0x3fff;
const MAX_DUMP_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_INTERFACES: usize = 1_024;
/// A completed station dump can transiently omit an associated peer while
/// firmware statistics are being published. Retain one missing frame as
/// stale topology evidence; a second completed miss confirms disappearance.
const STATION_MISSING_GRACE_READS: u8 = 1;
pub const DEFAULT_MAX_STATIONS: usize = 8_192;
pub const NL80211_IFTYPE_AP: u32 = 3;
pub const NL80211_IFTYPE_WDS: u32 = 5;
pub const NL80211_IFTYPE_MESH_POINT: u32 = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StationByteCounterWidth {
    Bits32,
    Bits64,
}

impl StationByteCounterWidth {
    pub const fn bits(self) -> u8 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WirelessInterface {
    pub ifindex: u32,
    pub ifname: String,
    pub bridge_ifindex: Option<u32>,
    pub vlan_id: Option<u16>,
    pub iftype: Option<u32>,
}

/// One station from a single batched NL80211 station dump.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StationCounterSample {
    pub mac: [u8; 6],
    pub ifindex: u32,
    pub ifname: String,
    pub bridge_ifindex: Option<u32>,
    pub vlan_id: Option<u16>,
    pub iftype: Option<u32>,
    pub association_generation: u64,
    pub association_started_ns: Option<u64>,
    pub connected_time_s: Option<u32>,
    pub counters: LinkCounters,
    pub rx_byte_width: StationByteCounterWidth,
    pub tx_byte_width: StationByteCounterWidth,
}

impl StationCounterSample {
    pub const fn proves_direct_client_interface(&self) -> bool {
        matches!(self.iftype, Some(NL80211_IFTYPE_AP))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StationCounterSnapshot {
    pub stations: Vec<StationCounterSample>,
    pub read_begin_ms: u64,
    pub read_end_ms: u64,
    pub complete: bool,
}

pub trait WifiStationCounterProvider {
    fn read_stations(&mut self) -> io::Result<StationCounterSnapshot>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AssociationState {
    generation: u64,
    interface: WirelessInterface,
    raw: RawStationCounter,
    /// Monotonic counters after extending accepted 32-bit wraps.
    counters: LinkCounters,
    missing_complete_reads: u8,
}

/// Raw Generic Netlink provider. It discovers bridged wireless netdevs from
/// sysfs, resolves the dynamic `nl80211` family id, then performs one dump per
/// interface on a shared socket. It never invokes `iw`.
#[derive(Clone, Debug)]
pub struct SystemNl80211StationProvider {
    configured_interfaces: Option<Vec<WirelessInterface>>,
    family_id: Option<u16>,
    associations: BTreeMap<(u32, [u8; 6]), AssociationState>,
    next_generation: u64,
    max_stations: usize,
}

impl Default for SystemNl80211StationProvider {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_STATIONS)
    }
}

impl SystemNl80211StationProvider {
    pub fn new(max_stations: usize) -> Self {
        Self {
            configured_interfaces: None,
            family_id: None,
            associations: BTreeMap::new(),
            next_generation: 1,
            max_stations: max_stations.max(1),
        }
    }

    pub fn with_interfaces(
        max_stations: usize,
        interfaces: impl IntoIterator<Item = WirelessInterface>,
    ) -> Self {
        let mut provider = Self::new(max_stations);
        provider.configured_interfaces = Some(interfaces.into_iter().collect());
        provider
    }

    fn allocate_generation(&mut self) -> u64 {
        let generation = self.next_generation.max(1);
        self.next_generation = generation.saturating_add(1);
        generation
    }

    fn apply_generations(
        &mut self,
        raw: Vec<(WirelessInterface, RawStationCounter)>,
        read_begin_ms: u64,
        read_end_ms: u64,
    ) -> io::Result<StationCounterSnapshot> {
        let previous = self.associations.clone();
        let mut seen = BTreeSet::new();
        let mut next = BTreeMap::new();
        let mut stations = Vec::with_capacity(raw.len());
        for (interface, raw) in raw {
            let key = (interface.ifindex, raw.mac);
            if !seen.insert(key) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate station in nl80211 snapshot",
                ));
            }
            let continued = previous.get(&key).and_then(|old| {
                if !association_material_continues(old, interface.iftype, raw) {
                    return None;
                }
                extend_station_counters(
                    old.raw.counters,
                    raw.counters,
                    old.counters,
                    raw.rx_byte_width,
                    raw.tx_byte_width,
                )
                .map(|counters| (old.generation, counters))
            });
            let (generation, counters) =
                continued.unwrap_or_else(|| (self.allocate_generation(), raw.counters));
            let association = AssociationState {
                generation,
                interface: interface.clone(),
                raw,
                counters,
                missing_complete_reads: 0,
            };
            stations.push(station_sample(&association));
            next.insert(key, association);
        }

        let mut retained_missing = false;
        for (key, mut association) in previous {
            if seen.contains(&key)
                || association.missing_complete_reads >= STATION_MISSING_GRACE_READS
            {
                continue;
            }
            association.missing_complete_reads =
                association.missing_complete_reads.saturating_add(1);
            stations.push(station_sample(&association));
            next.insert(key, association);
            retained_missing = true;
        }
        self.associations = next;
        stations.sort_by_key(|station| (station.ifindex, station.mac));
        Ok(StationCounterSnapshot {
            stations,
            read_begin_ms,
            read_end_ms,
            // Cached peers preserve only identity/generation. Mark the frame
            // incomplete so Access Edge refuses their old byte counters and
            // RateMux can use a current routed substitute instead.
            complete: !retained_missing,
        })
    }
}

fn station_sample(association: &AssociationState) -> StationCounterSample {
    let interface = &association.interface;
    let raw = association.raw;
    StationCounterSample {
        mac: raw.mac,
        ifindex: interface.ifindex,
        ifname: interface.ifname.clone(),
        bridge_ifindex: interface.bridge_ifindex,
        vlan_id: interface.vlan_id,
        iftype: interface.iftype,
        association_generation: association.generation,
        association_started_ns: raw.association_started_ns,
        connected_time_s: raw.connected_time_s,
        counters: association.counters,
        rx_byte_width: raw.rx_byte_width,
        tx_byte_width: raw.tx_byte_width,
    }
}

impl WifiStationCounterProvider for SystemNl80211StationProvider {
    fn read_stations(&mut self) -> io::Result<StationCounterSnapshot> {
        let read_begin_ms = monotonic_ms()?;
        let mut interfaces = match &self.configured_interfaces {
            Some(interfaces) => interfaces.clone(),
            None => discover_wireless_interfaces(Path::new("/sys/class/net"))?,
        };
        if interfaces.is_empty() {
            self.associations.clear();
            return Ok(StationCounterSnapshot {
                stations: Vec::new(),
                read_begin_ms,
                read_end_ms: monotonic_ms()?,
                complete: true,
            });
        }

        let socket = GenericNetlinkSocket::open()?;
        let family_id = match self.family_id {
            Some(family_id) => family_id,
            None => {
                let family_id = resolve_nl80211_family(&socket)?;
                self.family_id = Some(family_id);
                family_id
            }
        };
        let sequence_base = monotonic_sequence();
        if let Ok(types) =
            dump_interface_types(&socket, family_id, sequence_base, DEFAULT_MAX_INTERFACES)
        {
            for interface in &mut interfaces {
                if let Some(iftype) = types.get(&interface.ifindex) {
                    interface.iftype = Some(*iftype);
                }
            }
        }
        let mut raw = Vec::new();
        for (position, interface) in interfaces.iter().enumerate() {
            let sequence = sequence_base.wrapping_add(position as u32).wrapping_add(1);
            let remaining = self.max_stations.saturating_sub(raw.len());
            match dump_interface_stations(
                &socket,
                family_id,
                interface.ifindex,
                sequence,
                remaining,
            ) {
                Ok(stations) => {
                    raw.extend(
                        stations
                            .into_iter()
                            .map(|station| (interface.clone(), station)),
                    );
                }
                Err(error) => {
                    // A cached dynamic family id can become stale after module
                    // reload. Resolve it again on the next complete attempt.
                    self.family_id = None;
                    return Err(error);
                }
            }
        }
        let read_end_ms = monotonic_ms()?;
        self.apply_generations(raw, read_begin_ms, read_end_ms)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawStationCounter {
    pub mac: [u8; 6],
    pub ifindex: u32,
    pub association_started_ns: Option<u64>,
    pub connected_time_s: Option<u32>,
    pub counters: LinkCounters,
    pub rx_byte_width: StationByteCounterWidth,
    pub tx_byte_width: StationByteCounterWidth,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedStationMessages {
    pub stations: Vec<RawStationCounter>,
    pub done: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedInterfaceMessages {
    pub interfaces: Vec<(u32, u32)>,
    pub done: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Nl80211ParseError {
    TruncatedHeader,
    InvalidMessageLength(u32),
    InvalidGenericHeader,
    InvalidAttribute,
    MissingInterfaceIdentity,
    MissingStationIdentity,
    MissingStationBytes,
    DumpInterrupted,
    Overrun,
    Kernel(i32),
    EntryLimitExceeded,
}

impl fmt::Display for Nl80211ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => formatter.write_str("truncated generic netlink header"),
            Self::InvalidMessageLength(length) => {
                write!(formatter, "invalid generic netlink message length {length}")
            }
            Self::InvalidGenericHeader => formatter.write_str("invalid generic netlink payload"),
            Self::InvalidAttribute => formatter.write_str("invalid nl80211 attribute"),
            Self::MissingInterfaceIdentity => {
                formatter.write_str("nl80211 interface identity missing")
            }
            Self::MissingStationIdentity => formatter.write_str("nl80211 station identity missing"),
            Self::MissingStationBytes => {
                formatter.write_str("nl80211 station byte counter missing")
            }
            Self::DumpInterrupted => formatter.write_str("nl80211 station dump was interrupted"),
            Self::Overrun => formatter.write_str("nl80211 station dump overrun"),
            Self::Kernel(error) => write!(formatter, "generic netlink kernel error {error}"),
            Self::EntryLimitExceeded => formatter.write_str("nl80211 station limit exceeded"),
        }
    }
}

impl std::error::Error for Nl80211ParseError {}

pub fn parse_interface_messages(
    bytes: &[u8],
    expected_sequence: u32,
    family_id: u16,
    max_entries: usize,
) -> Result<ParsedInterfaceMessages, Nl80211ParseError> {
    if bytes.is_empty() {
        return Ok(ParsedInterfaceMessages::default());
    }
    if bytes.len() < NLMSG_HEADER_LEN {
        return Err(Nl80211ParseError::TruncatedHeader);
    }
    let mut parsed = ParsedInterfaceMessages::default();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let header = parse_message_header(bytes, offset)?;
        if header.sequence == expected_sequence {
            if header.flags & NLM_F_DUMP_INTR != 0 {
                return Err(Nl80211ParseError::DumpInterrupted);
            }
            let payload = &bytes[offset + NLMSG_HEADER_LEN..offset + header.length];
            match header.kind {
                NLMSG_ERROR => parse_kernel_error(payload)?,
                NLMSG_DONE => {
                    parse_done(payload)?;
                    parsed.done = true;
                    break;
                }
                NLMSG_OVERRUN => return Err(Nl80211ParseError::Overrun),
                kind if kind == family_id => {
                    if payload.len() < GENL_HEADER_LEN {
                        return Err(Nl80211ParseError::InvalidGenericHeader);
                    }
                    if payload[0] == NL80211_CMD_NEW_INTERFACE {
                        if parsed.interfaces.len() == max_entries {
                            return Err(Nl80211ParseError::EntryLimitExceeded);
                        }
                        parsed
                            .interfaces
                            .push(parse_interface(&payload[GENL_HEADER_LEN..])?);
                    }
                }
                _ => {}
            }
        }
        offset = advance_message(bytes, offset, header.length)?;
    }
    Ok(parsed)
}

fn parse_interface(attributes: &[u8]) -> Result<(u32, u32), Nl80211ParseError> {
    let mut ifindex = None;
    let mut iftype = None;
    for_each_attribute(attributes, |kind, value| {
        match kind {
            NL80211_ATTR_IFINDEX => {
                ifindex = Some(read_exact_u32(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            NL80211_ATTR_IFTYPE => {
                iftype = Some(read_exact_u32(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            _ => {}
        }
        Ok(())
    })?;
    let ifindex = ifindex
        .filter(|value| *value != 0)
        .ok_or(Nl80211ParseError::MissingInterfaceIdentity)?;
    let iftype = iftype.ok_or(Nl80211ParseError::InvalidAttribute)?;
    Ok((ifindex, iftype))
}

/// Parse one multipart station-dump datagram. 64-bit byte attributes take
/// precedence independently in each direction; 32-bit attributes are fallback.
pub fn parse_station_messages(
    bytes: &[u8],
    expected_sequence: u32,
    family_id: u16,
    max_entries: usize,
) -> Result<ParsedStationMessages, Nl80211ParseError> {
    if bytes.is_empty() {
        return Ok(ParsedStationMessages::default());
    }
    if bytes.len() < NLMSG_HEADER_LEN {
        return Err(Nl80211ParseError::TruncatedHeader);
    }
    let mut parsed = ParsedStationMessages::default();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let header = parse_message_header(bytes, offset)?;
        if header.sequence == expected_sequence {
            if header.flags & NLM_F_DUMP_INTR != 0 {
                return Err(Nl80211ParseError::DumpInterrupted);
            }
            let payload = &bytes[offset + NLMSG_HEADER_LEN..offset + header.length];
            match header.kind {
                NLMSG_ERROR => parse_kernel_error(payload)?,
                NLMSG_DONE => {
                    parse_done(payload)?;
                    parsed.done = true;
                    break;
                }
                NLMSG_OVERRUN => return Err(Nl80211ParseError::Overrun),
                kind if kind == family_id => {
                    if payload.len() < GENL_HEADER_LEN {
                        return Err(Nl80211ParseError::InvalidGenericHeader);
                    }
                    if payload[0] == NL80211_CMD_NEW_STATION {
                        if parsed.stations.len() == max_entries {
                            return Err(Nl80211ParseError::EntryLimitExceeded);
                        }
                        parsed
                            .stations
                            .push(parse_station(&payload[GENL_HEADER_LEN..])?);
                    }
                }
                _ => {}
            }
        }
        offset = advance_message(bytes, offset, header.length)?;
    }
    Ok(parsed)
}

fn parse_station(attributes: &[u8]) -> Result<RawStationCounter, Nl80211ParseError> {
    let mut ifindex = None;
    let mut mac = None;
    let mut station_info = None;
    for_each_attribute(attributes, |kind, value| {
        match kind {
            NL80211_ATTR_IFINDEX => {
                ifindex = Some(read_exact_u32(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            NL80211_ATTR_MAC => {
                mac = Some(
                    <[u8; 6]>::try_from(value).map_err(|_| Nl80211ParseError::InvalidAttribute)?,
                )
            }
            NL80211_ATTR_STA_INFO => station_info = Some(value),
            _ => {}
        }
        Ok(())
    })?;
    let ifindex = ifindex
        .filter(|value| *value != 0)
        .ok_or(Nl80211ParseError::MissingStationIdentity)?;
    let mac = mac
        .filter(|value| valid_client_mac(*value))
        .ok_or(Nl80211ParseError::MissingStationIdentity)?;
    let info = parse_station_info(station_info.ok_or(Nl80211ParseError::MissingStationBytes)?)?;
    Ok(RawStationCounter {
        mac,
        ifindex,
        association_started_ns: info.association_started_ns,
        connected_time_s: info.connected_time_s,
        counters: LinkCounters {
            rx_bytes: info.rx_bytes.0,
            tx_bytes: info.tx_bytes.0,
            rx_packets: info.rx_packets,
            tx_packets: info.tx_packets,
        },
        rx_byte_width: info.rx_bytes.1,
        tx_byte_width: info.tx_bytes.1,
    })
}

struct ParsedStationInfo {
    rx_bytes: (u64, StationByteCounterWidth),
    tx_bytes: (u64, StationByteCounterWidth),
    rx_packets: u64,
    tx_packets: u64,
    association_started_ns: Option<u64>,
    connected_time_s: Option<u32>,
}

fn parse_station_info(bytes: &[u8]) -> Result<ParsedStationInfo, Nl80211ParseError> {
    let mut rx32 = None;
    let mut tx32 = None;
    let mut rx64 = None;
    let mut tx64 = None;
    let mut rx_packets = 0;
    let mut tx_packets = 0;
    let mut association_started_ns = None;
    let mut connected_time_s = None;
    for_each_attribute(bytes, |kind, value| {
        match kind {
            NL80211_STA_INFO_RX_BYTES => {
                rx32 = Some(read_exact_u32(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            NL80211_STA_INFO_TX_BYTES => {
                tx32 = Some(read_exact_u32(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            NL80211_STA_INFO_RX_BYTES64 => {
                rx64 = Some(read_exact_u64(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            NL80211_STA_INFO_TX_BYTES64 => {
                tx64 = Some(read_exact_u64(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            NL80211_STA_INFO_RX_PACKETS => {
                rx_packets =
                    u64::from(read_exact_u32(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            NL80211_STA_INFO_TX_PACKETS => {
                tx_packets =
                    u64::from(read_exact_u32(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            NL80211_STA_INFO_CONNECTED_TIME => {
                connected_time_s =
                    Some(read_exact_u32(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            NL80211_STA_INFO_ASSOC_AT_BOOTTIME => {
                association_started_ns =
                    Some(read_exact_u64(value).ok_or(Nl80211ParseError::InvalidAttribute)?)
            }
            _ => {}
        }
        Ok(())
    })?;
    let rx_bytes = rx64
        .map(|value| (value, StationByteCounterWidth::Bits64))
        .or_else(|| rx32.map(|value| (u64::from(value), StationByteCounterWidth::Bits32)))
        .ok_or(Nl80211ParseError::MissingStationBytes)?;
    let tx_bytes = tx64
        .map(|value| (value, StationByteCounterWidth::Bits64))
        .or_else(|| tx32.map(|value| (u64::from(value), StationByteCounterWidth::Bits32)))
        .ok_or(Nl80211ParseError::MissingStationBytes)?;
    Ok(ParsedStationInfo {
        rx_bytes,
        tx_bytes,
        rx_packets,
        tx_packets,
        association_started_ns,
        connected_time_s,
    })
}

fn resolve_nl80211_family(socket: &GenericNetlinkSocket) -> io::Result<u16> {
    let sequence = monotonic_sequence();
    socket.send(&family_request(sequence, "nl80211")?)?;
    let mut total_bytes = 0usize;
    loop {
        let packet = socket.receive()?;
        total_bytes = total_bytes.saturating_add(packet.len());
        if total_bytes > MAX_DUMP_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "generic netlink family response exceeds byte limit",
            ));
        }
        if let Some(family_id) =
            parse_family_id_messages(&packet, sequence).map_err(parse_error_to_io)?
        {
            return Ok(family_id);
        }
    }
}

pub fn parse_family_id_messages(
    bytes: &[u8],
    expected_sequence: u32,
) -> Result<Option<u16>, Nl80211ParseError> {
    if bytes.len() < NLMSG_HEADER_LEN {
        return Err(Nl80211ParseError::TruncatedHeader);
    }
    let mut offset = 0usize;
    while offset < bytes.len() {
        let header = parse_message_header(bytes, offset)?;
        if header.sequence == expected_sequence {
            let payload = &bytes[offset + NLMSG_HEADER_LEN..offset + header.length];
            match header.kind {
                NLMSG_ERROR => parse_kernel_error(payload)?,
                NLMSG_OVERRUN => return Err(Nl80211ParseError::Overrun),
                GENL_ID_CTRL => {
                    if payload.len() < GENL_HEADER_LEN {
                        return Err(Nl80211ParseError::InvalidGenericHeader);
                    }
                    if payload[0] == CTRL_CMD_NEWFAMILY {
                        let mut family_id = None;
                        for_each_attribute(&payload[GENL_HEADER_LEN..], |kind, value| {
                            if kind == CTRL_ATTR_FAMILY_ID {
                                family_id = Some(
                                    read_exact_u16(value)
                                        .ok_or(Nl80211ParseError::InvalidAttribute)?,
                                );
                            }
                            Ok(())
                        })?;
                        if family_id.is_some() {
                            return Ok(family_id);
                        }
                    }
                }
                _ => {}
            }
        }
        offset = advance_message(bytes, offset, header.length)?;
    }
    Ok(None)
}

fn dump_interface_types(
    socket: &GenericNetlinkSocket,
    family_id: u16,
    sequence: u32,
    max_entries: usize,
) -> io::Result<BTreeMap<u32, u32>> {
    socket.send(&interface_dump_request(family_id, sequence))?;
    let mut interfaces = BTreeMap::new();
    let mut total_bytes = 0usize;
    loop {
        let packet = socket.receive()?;
        total_bytes = total_bytes.saturating_add(packet.len());
        if total_bytes > MAX_DUMP_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "nl80211 interface dump exceeds byte limit",
            ));
        }
        let remaining = max_entries.saturating_sub(interfaces.len());
        let parsed = parse_interface_messages(&packet, sequence, family_id, remaining)
            .map_err(parse_error_to_io)?;
        for (ifindex, iftype) in parsed.interfaces {
            if interfaces.insert(ifindex, iftype).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate interface in nl80211 snapshot",
                ));
            }
        }
        if parsed.done {
            return Ok(interfaces);
        }
    }
}

fn dump_interface_stations(
    socket: &GenericNetlinkSocket,
    family_id: u16,
    ifindex: u32,
    sequence: u32,
    max_entries: usize,
) -> io::Result<Vec<RawStationCounter>> {
    socket.send(&station_dump_request(family_id, sequence, ifindex))?;
    let mut stations = Vec::new();
    let mut total_bytes = 0usize;
    loop {
        let packet = socket.receive()?;
        total_bytes = total_bytes.saturating_add(packet.len());
        if total_bytes > MAX_DUMP_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "nl80211 station dump exceeds byte limit",
            ));
        }
        let remaining = max_entries.saturating_sub(stations.len());
        let parsed = parse_station_messages(&packet, sequence, family_id, remaining)
            .map_err(parse_error_to_io)?;
        for station in parsed.stations {
            if station.ifindex != ifindex {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "nl80211 station returned for unexpected interface",
                ));
            }
            stations.push(station);
        }
        if parsed.done {
            return Ok(stations);
        }
    }
}

fn discover_wireless_interfaces(sysfs_root: &Path) -> io::Result<Vec<WirelessInterface>> {
    let mut interfaces = Vec::new();
    for entry in fs::read_dir(sysfs_root)? {
        let entry = entry?;
        let root = entry.path();
        if !root.join("phy80211").exists() && !root.join("wireless").exists() {
            continue;
        }
        // Client access interfaces are bridge members. Ignoring unbridged
        // radios avoids treating an upstream STA/AP peer as a LAN client.
        let master = root.join("master").join("ifindex");
        let bridge_ifindex = match fs::read_to_string(master) {
            Ok(value) => Some(parse_nonzero_u32(&value)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let ifname = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 interface name"))?;
        interfaces.push(WirelessInterface {
            ifindex: parse_nonzero_u32(&fs::read_to_string(root.join("ifindex"))?)?,
            ifname,
            bridge_ifindex,
            vlan_id: None,
            iftype: None,
        });
    }
    interfaces.sort_by_key(|interface| interface.ifindex);
    Ok(interfaces)
}

struct GenericNetlinkSocket {
    fd: OwnedFd,
}

impl GenericNetlinkSocket {
    fn open() -> io::Result<Self> {
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let local = SockAddrNl::new();
        syscall_zero(unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&local as *const SockAddrNl).cast(),
                size_of::<SockAddrNl>() as libc::socklen_t,
            )
        })?;
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        syscall_zero(unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        })?;
        Ok(Self { fd })
    }

    fn send(&self, request: &[u8]) -> io::Result<()> {
        let kernel = SockAddrNl::new();
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&kernel as *const SockAddrNl).cast(),
                size_of::<SockAddrNl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != request.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short generic netlink request",
            ));
        }
        Ok(())
    }

    fn receive(&self) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 64 * 1024];
        let mut sender = SockAddrNl::new();
        let mut sender_len = size_of::<SockAddrNl>() as libc::socklen_t;
        let received = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
                (&mut sender as *mut SockAddrNl).cast(),
                &mut sender_len,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "generic netlink stream ended unexpectedly",
            ));
        }
        let received = received as usize;
        if received > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "generic netlink datagram was truncated",
            ));
        }
        if sender_len < size_of::<SockAddrNl>() as libc::socklen_t
            || sender.family != libc::AF_NETLINK as u16
            || sender.pid != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "generic netlink reply was not sent by the kernel",
            ));
        }
        buffer.truncate(received);
        Ok(buffer)
    }
}

#[repr(C)]
struct SockAddrNl {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

impl SockAddrNl {
    const fn new() -> Self {
        Self {
            family: libc::AF_NETLINK as u16,
            pad: 0,
            pid: 0,
            groups: 0,
        }
    }
}

fn family_request(sequence: u32, family_name: &str) -> io::Result<Vec<u8>> {
    if family_name.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "generic netlink family contains NUL",
        ));
    }
    let mut name = family_name.as_bytes().to_vec();
    name.push(0);
    let attributes = encode_attribute(CTRL_ATTR_FAMILY_NAME, &name);
    Ok(generic_request(
        GENL_ID_CTRL,
        NLM_F_REQUEST,
        sequence,
        CTRL_CMD_GETFAMILY,
        1,
        &attributes,
    ))
}

fn station_dump_request(family_id: u16, sequence: u32, ifindex: u32) -> Vec<u8> {
    let attributes = encode_attribute(NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    generic_request(
        family_id,
        NLM_F_REQUEST | NLM_F_DUMP,
        sequence,
        NL80211_CMD_GET_STATION,
        NL80211_GENL_VERSION,
        &attributes,
    )
}

fn interface_dump_request(family_id: u16, sequence: u32) -> Vec<u8> {
    generic_request(
        family_id,
        NLM_F_REQUEST | NLM_F_DUMP,
        sequence,
        NL80211_CMD_GET_INTERFACE,
        NL80211_GENL_VERSION,
        &[],
    )
}

fn generic_request(
    family_id: u16,
    flags: u16,
    sequence: u32,
    command: u8,
    version: u8,
    attributes: &[u8],
) -> Vec<u8> {
    let length = NLMSG_HEADER_LEN + GENL_HEADER_LEN + attributes.len();
    let mut request = Vec::with_capacity(length);
    request.extend_from_slice(&(length as u32).to_ne_bytes());
    request.extend_from_slice(&family_id.to_ne_bytes());
    request.extend_from_slice(&flags.to_ne_bytes());
    request.extend_from_slice(&sequence.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.extend_from_slice(&[command, version, 0, 0]);
    request.extend_from_slice(attributes);
    request
}

fn encode_attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let length = 4 + value.len();
    let mut bytes = Vec::with_capacity(align4(length));
    bytes.extend_from_slice(&(length as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(align4(length), 0);
    bytes
}

fn for_each_attribute<'a, F>(bytes: &'a [u8], mut visitor: F) -> Result<(), Nl80211ParseError>
where
    F: FnMut(u16, &'a [u8]) -> Result<(), Nl80211ParseError>,
{
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(Nl80211ParseError::InvalidAttribute);
        }
        let length = read_u16(bytes, offset).ok_or(Nl80211ParseError::InvalidAttribute)? as usize;
        let kind =
            read_u16(bytes, offset + 2).ok_or(Nl80211ParseError::InvalidAttribute)? & NLA_TYPE_MASK;
        if length < 4 || length > bytes.len() - offset {
            return Err(Nl80211ParseError::InvalidAttribute);
        }
        visitor(kind, &bytes[offset + 4..offset + length])?;
        let next = offset.saturating_add(align4(length));
        if next > bytes.len() {
            return Err(Nl80211ParseError::InvalidAttribute);
        }
        offset = next;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct MessageHeader {
    length: usize,
    kind: u16,
    flags: u16,
    sequence: u32,
}

fn parse_message_header(bytes: &[u8], offset: usize) -> Result<MessageHeader, Nl80211ParseError> {
    if bytes.len().saturating_sub(offset) < NLMSG_HEADER_LEN {
        return Err(Nl80211ParseError::TruncatedHeader);
    }
    let wire_length = read_u32(bytes, offset).ok_or(Nl80211ParseError::TruncatedHeader)?;
    let length = wire_length as usize;
    if length < NLMSG_HEADER_LEN || length > bytes.len() - offset {
        return Err(Nl80211ParseError::InvalidMessageLength(wire_length));
    }
    Ok(MessageHeader {
        length,
        kind: read_u16(bytes, offset + 4).unwrap_or_default(),
        flags: read_u16(bytes, offset + 6).unwrap_or_default(),
        sequence: read_u32(bytes, offset + 8).unwrap_or_default(),
    })
}

fn parse_kernel_error(payload: &[u8]) -> Result<(), Nl80211ParseError> {
    let error = read_i32(payload, 0).ok_or(Nl80211ParseError::InvalidGenericHeader)?;
    if error == 0 {
        Ok(())
    } else {
        Err(Nl80211ParseError::Kernel(error))
    }
}

fn parse_done(payload: &[u8]) -> Result<(), Nl80211ParseError> {
    if payload.is_empty() {
        return Ok(());
    }
    if payload.len() < 4 {
        return Err(Nl80211ParseError::InvalidGenericHeader);
    }
    parse_kernel_error(payload)
}

fn advance_message(
    bytes: &[u8],
    offset: usize,
    message_len: usize,
) -> Result<usize, Nl80211ParseError> {
    let aligned = align4(message_len);
    if aligned > bytes.len() - offset {
        if message_len == bytes.len() - offset {
            return Ok(bytes.len());
        }
        return Err(Nl80211ParseError::InvalidMessageLength(message_len as u32));
    }
    Ok(offset + aligned)
}

fn association_material_continues(
    previous: &AssociationState,
    iftype: Option<u32>,
    current: RawStationCounter,
) -> bool {
    let association_marker_matches = match (
        previous.raw.association_started_ns,
        current.association_started_ns,
    ) {
        (Some(previous), Some(current)) => previous == current,
        (None, None) => true,
        _ => false,
    };
    let connected_time_advanced = match (previous.raw.connected_time_s, current.connected_time_s) {
        (Some(previous), Some(current)) => current >= previous,
        (None, None) => true,
        _ => false,
    };
    previous.interface.iftype == iftype
        && previous.raw.rx_byte_width == current.rx_byte_width
        && previous.raw.tx_byte_width == current.tx_byte_width
        && association_marker_matches
        && connected_time_advanced
}

fn valid_client_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac != [0xff; 6] && mac[0] & 1 == 0
}

fn parse_nonzero_u32(value: &str) -> io::Result<u32> {
    let value = value
        .trim()
        .parse::<u32>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if value == 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "interface index must be non-zero",
        ))
    } else {
        Ok(value)
    }
}

fn monotonic_ms() -> io::Result<u64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    syscall_zero(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) })?;
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative monotonic time"))?;
    let nanos = u64::try_from(now.tv_nsec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative monotonic time"))?;
    Ok(seconds
        .saturating_mul(1_000)
        .saturating_add(nanos / 1_000_000))
}

fn monotonic_sequence() -> u32 {
    monotonic_ms().map_or(0, |value| (value ^ value.rotate_left(13)) as u32)
}

fn syscall_zero(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn parse_error_to_io(error: Nl80211ParseError) -> io::Error {
    match error {
        Nl80211ParseError::Kernel(error) if error < 0 => {
            io::Error::from_raw_os_error(error.checked_neg().unwrap_or(libc::EINVAL))
        }
        error => io::Error::new(io::ErrorKind::InvalidData, error),
    }
}

const fn align4(value: usize) -> usize {
    value.saturating_add(3) & !3
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_exact_u16(bytes: &[u8]) -> Option<u16> {
    (bytes.len() == 2).then_some(u16::from_ne_bytes(bytes.try_into().ok()?))
}

fn read_exact_u32(bytes: &[u8]) -> Option<u32> {
    (bytes.len() == 4).then_some(u32::from_ne_bytes(bytes.try_into().ok()?))
}

fn read_exact_u64(bytes: &[u8]) -> Option<u64> {
    (bytes.len() == 8).then_some(u64::from_ne_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
include!("nl80211/tests.rs");
