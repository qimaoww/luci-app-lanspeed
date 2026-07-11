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

pub trait ZoneResolver {
    fn zone_for_ifname(&self, ifname: &str) -> Option<String>;
}

impl<F> ZoneResolver for F
where
    F: Fn(&str) -> Option<String>,
{
    fn zone_for_ifname(&self, ifname: &str) -> Option<String> {
        self(ifname)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LegacyZoneResolver;

impl ZoneResolver for LegacyZoneResolver {
    fn zone_for_ifname(&self, _ifname: &str) -> Option<String> {
        None
    }
}

pub fn resolve_zone(resolver: &impl ZoneResolver, ifname: &str) -> String {
    resolver
        .zone_for_ifname(ifname)
        .filter(|zone| !zone.is_empty())
        .unwrap_or_else(|| filter::derive_zone_from_ifname(ifname))
}

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

#[derive(Clone, Debug, Default)]
pub struct IdentityPolicy {
    router_macs: HashSet<MacAddress>,
    excluded_ips: HashSet<String>,
}

impl IdentityPolicy {
    pub fn exclude_router_mac(&mut self, mac: &str) -> Result<(), IdentityError> {
        self.router_macs.insert(mac.parse()?);
        Ok(())
    }

    pub fn exclude_router_ip(&mut self, ip: &str) {
        self.exclude_ip(ip);
    }

    pub fn exclude_control_ip(&mut self, ip: &str) {
        self.exclude_ip(ip);
    }

    pub fn exclude_remote_ip(&mut self, ip: &str) {
        self.exclude_ip(ip);
    }

    fn exclude_ip(&mut self, ip: &str) {
        if let Some(ip) = normalize_ip_address(ip) {
            self.excluded_ips.insert(ip);
        }
    }

    fn excludes_mac(&self, mac: MacAddress) -> bool {
        self.router_macs.contains(&mac)
    }

    fn excludes_ip(&self, ip: &str) -> bool {
        normalize_ip_address(ip)
            .map(|ip| self.excluded_ips.contains(&ip))
            .unwrap_or(false)
    }
}

pub struct IdentityTable {
    max_clients: usize,
    policy: IdentityPolicy,
    clients: BTreeMap<IdentityKey, ClientIdentity>,
}

impl IdentityTable {
    pub fn new(max_clients: usize) -> Self {
        Self::with_policy(max_clients, IdentityPolicy::default())
    }

    pub fn with_policy(max_clients: usize, policy: IdentityPolicy) -> Self {
        Self {
            max_clients,
            policy,
            clients: BTreeMap::new(),
        }
    }

    pub fn exclude_router_mac(&mut self, mac: &str) -> Result<(), IdentityError> {
        let mac = mac.parse()?;
        self.policy.router_macs.insert(mac);
        self.clients.retain(|key, _| key.mac != mac);
        Ok(())
    }

    pub fn exclude_router_ip(&mut self, ip: &str) {
        self.policy.exclude_router_ip(ip);
        self.remove_excluded_ip(ip);
    }

    pub fn exclude_control_ip(&mut self, ip: &str) {
        self.policy.exclude_control_ip(ip);
        self.remove_excluded_ip(ip);
    }

    pub fn exclude_remote_ip(&mut self, ip: &str) {
        self.policy.exclude_remote_ip(ip);
        self.remove_excluded_ip(ip);
    }

    fn remove_excluded_ip(&mut self, ip: &str) {
        let Some(ip) = normalize_ip_address(ip) else {
            return;
        };
        for client in self.clients.values_mut() {
            client.ips.retain(|candidate| candidate != &ip);
        }
    }

    pub fn observe(&mut self, observation: IdentityObservation<'_>) -> Result<bool, IdentityError> {
        let mac: MacAddress = observation.mac.parse()?;
        if self.policy.excludes_mac(mac)
            || filter::ifname_is_excluded_identity_source(observation.interface)
        {
            return Ok(false);
        }
        let normalized_ip = observation.ip.and_then(normalize_ip_address);
        if normalized_ip
            .as_deref()
            .is_some_and(|ip| self.policy.excludes_ip(ip))
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
        if let Some(ip) = normalized_ip {
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

    pub fn traffic_owner(
        &self,
        mac: &str,
        zone: &str,
        client_ip: Option<&str>,
        frame: FrameKind,
    ) -> Option<&ClientIdentity> {
        if frame != FrameKind::Unicast {
            return None;
        }
        let owner = self.by_mac_zone(mac, zone)?;
        if let Some(client_ip) = client_ip {
            let client_ip = normalize_ip_address(client_ip)?;
            if self.policy.excludes_ip(&client_ip)
                || !owner.ips.iter().any(|candidate| candidate == &client_ip)
            {
                return None;
            }
        }
        Some(owner)
    }

    pub fn clients(&self) -> std::collections::btree_map::Values<'_, IdentityKey, ClientIdentity> {
        self.clients.values()
    }

    pub fn iter(&self) -> std::collections::btree_map::Values<'_, IdentityKey, ClientIdentity> {
        self.clients.values()
    }

    pub fn by_mac_zone(&self, mac: &str, zone: &str) -> Option<&ClientIdentity> {
        let mac = mac.parse::<MacAddress>().ok()?;
        if self.policy.excludes_mac(mac) || zone.is_empty() {
            return None;
        }
        self.clients.get(&IdentityKey {
            mac,
            zone: zone.to_owned(),
        })
    }

    pub fn by_ip(&self, ip: &str) -> Option<&ClientIdentity> {
        let ip = normalize_ip_address(ip)?;
        if self.policy.excludes_ip(&ip) {
            return None;
        }
        self.clients
            .values()
            .find(|client| client.ips.iter().any(|candidate| candidate == &ip))
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
