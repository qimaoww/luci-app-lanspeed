use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    net::IpAddr,
    str::FromStr,
};

pub mod arp;
pub mod filter;
pub mod hostname;
pub mod netlink;

pub const MAX_IPS_PER_IDENTITY: usize = 4;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl FromStr for MacAddress {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 17 {
            return Err(IdentityError::InvalidMac(value.to_owned()));
        }
        let bytes = value.as_bytes();
        let mut octets = [0u8; 6];
        for (index, octet) in octets.iter_mut().enumerate() {
            let offset = index * 3;
            if index != 5 && bytes[offset + 2] != b':' {
                return Err(IdentityError::InvalidMac(value.to_owned()));
            }
            *octet = parse_hex_pair(&bytes[offset..offset + 2])
                .ok_or_else(|| IdentityError::InvalidMac(value.to_owned()))?;
        }
        if octets == [0; 6] || octets == [0xff; 6] || octets[0] & 1 != 0 {
            return Err(IdentityError::InvalidMac(value.to_owned()));
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

fn parse_hex_pair(bytes: &[u8]) -> Option<u8> {
    let high = (bytes.first().copied()? as char).to_digit(16)? as u8;
    let low = (bytes.get(1).copied()? as char).to_digit(16)? as u8;
    Some((high << 4) | low)
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityKey {
    pub mac: MacAddress,
    pub zone: String,
}

impl fmt::Display for IdentityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.mac, self.zone)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationSource {
    DhcpLease,
    Neighbor,
    Wireless,
    Netifd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Unicast,
    Broadcast,
    Multicast,
    Arp,
    NeighborDiscovery,
    RouterMac,
}

impl FromStr for FrameKind {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "unicast" => Ok(Self::Unicast),
            "broadcast" => Ok(Self::Broadcast),
            "multicast" => Ok(Self::Multicast),
            "arp" => Ok(Self::Arp),
            "nd" => Ok(Self::NeighborDiscovery),
            "router_mac" => Ok(Self::RouterMac),
            _ => Err("unknown frame kind"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeighborEntry {
    pub ip: String,
    pub mac: MacAddress,
    pub interface: String,
    pub zone: String,
}

#[derive(Clone, Copy, Debug)]
pub struct IdentityObservation<'a> {
    pub mac: &'a str,
    pub zone: Option<&'a str>,
    pub interface: &'a str,
    pub ip: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub last_seen: u64,
    pub source: ObservationSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdentity {
    pub key: IdentityKey,
    pub interface: String,
    pub ips: Vec<String>,
    pub hostname: Option<String>,
    pub last_seen: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum IdentityError {
    InvalidMac(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMac(mac) => write!(formatter, "invalid client MAC address: {mac}"),
        }
    }
}

impl std::error::Error for IdentityError {}

pub struct IdentityTable {
    max_clients: usize,
    router_macs: HashSet<MacAddress>,
    clients: BTreeMap<IdentityKey, ClientIdentity>,
}

impl IdentityTable {
    pub fn new(max_clients: usize) -> Self {
        Self {
            max_clients,
            router_macs: HashSet::new(),
            clients: BTreeMap::new(),
        }
    }

    pub fn exclude_router_mac(&mut self, mac: &str) -> Result<(), IdentityError> {
        let mac = mac.parse()?;
        self.router_macs.insert(mac);
        self.clients.retain(|key, _| key.mac != mac);
        Ok(())
    }

    pub fn observe(&mut self, observation: IdentityObservation<'_>) -> Result<bool, IdentityError> {
        let mac: MacAddress = observation.mac.parse()?;
        if self.router_macs.contains(&mac)
            || filter::ifname_is_excluded_identity_source(observation.interface)
        {
            return Ok(false);
        }
        let zone = observation
            .zone
            .filter(|zone| !zone.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| filter::derive_zone_from_ifname(observation.interface));
        let key = IdentityKey { mac, zone };
        if !self.clients.contains_key(&key) && self.clients.len() >= self.max_clients {
            return Ok(false);
        }
        let client = self
            .clients
            .entry(key.clone())
            .or_insert_with(|| ClientIdentity {
                key,
                interface: observation.interface.to_owned(),
                ips: Vec::new(),
                hostname: None,
                last_seen: 0,
            });
        if let Some(ip) = observation.ip.and_then(normalize_ip_address) {
            if client.ips.len() < MAX_IPS_PER_IDENTITY && !client.ips.contains(&ip) {
                client.ips.push(ip);
            }
        }
        if let Some(hostname) = observation.hostname.filter(|name| !name.is_empty()) {
            client.hostname = Some(hostname.to_owned());
        }
        if observation.last_seen >= client.last_seen {
            client.interface = observation.interface.to_owned();
            client.last_seen = observation.last_seen;
        }
        Ok(true)
    }

    pub fn traffic_is_client_owned(&self, mac: &str, frame: FrameKind) -> bool {
        if frame != FrameKind::Unicast {
            return false;
        }
        mac.parse::<MacAddress>()
            .map(|mac| !self.router_macs.contains(&mac))
            .unwrap_or(false)
    }

    pub fn warnings(&self) -> Vec<&'static str> {
        let mut seen = HashSet::new();
        if self.clients.keys().any(|key| !seen.insert(key.mac)) {
            vec!["duplicate_mac_across_vlans"]
        } else {
            Vec::new()
        }
    }

    pub fn into_clients(self) -> Vec<ClientIdentity> {
        self.clients.into_values().collect()
    }
}

pub fn normalize_ip_address(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    Some(
        value
            .parse::<IpAddr>()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| value.to_owned()),
    )
}
