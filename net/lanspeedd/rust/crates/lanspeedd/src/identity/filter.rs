use std::{net::IpAddr, str::FromStr};

const MAX_INTERFACES: usize = 32;
const MAX_PREFIXES: usize = 64;
const MAX_INTERFACE_LEN: usize = 32;

pub fn ifname_is_excluded_identity_source(ifname: &str) -> bool {
    ifname == "dae0"
        || ifname == "dae0peer"
        || ifname.starts_with("tun")
        || ifname.starts_with("ppp")
        || ifname.starts_with("wg")
}

pub fn derive_zone_from_ifname(ifname: &str) -> String {
    if ifname.is_empty()
        || ifname.starts_with("br-lan")
        || ifname.starts_with("lan")
        || ifname.starts_with("wlan")
    {
        "lan".to_owned()
    } else {
        ifname.to_owned()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfacePrefix {
    interface: String,
    address: IpAddr,
    prefix_len: u8,
}

impl FromStr for InterfacePrefix {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (interface, cidr) = value
            .split_once('=')
            .ok_or_else(|| "interface prefix must contain '='".to_owned())?;
        let (address, prefix_len) = cidr
            .rsplit_once('/')
            .ok_or_else(|| "interface prefix must contain '/'".to_owned())?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|error| format!("invalid prefix address: {error}"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .map_err(|error| format!("invalid prefix length: {error}"))?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if interface.is_empty() || interface.len() >= MAX_INTERFACE_LEN || prefix_len > maximum {
            return Err("invalid interface prefix".to_owned());
        }
        Ok(Self {
            interface: interface.to_owned(),
            address,
            prefix_len,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct IdentityFilter {
    interfaces: Vec<String>,
    prefixes: Vec<InterfacePrefix>,
}

impl IdentityFilter {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn from_uci_values<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        let mut filter = Self::default();
        for value in values {
            let value = legacy_string_window(value);
            for interface in value.split(|character: char| {
                character == ',' || matches!(character, ' ' | '\t' | '\r' | '\n')
            }) {
                filter.add_interface(interface);
            }
        }
        filter
    }

    fn add_interface(&mut self, interface: &str) {
        if interface.is_empty()
            || interface.len() >= MAX_INTERFACE_LEN
            || ifname_is_excluded_identity_source(interface)
            || self.interfaces.len() >= MAX_INTERFACES
            || self.interfaces.iter().any(|existing| existing == interface)
        {
            return;
        }
        self.interfaces.push(interface.to_owned());
    }

    pub fn add_prefix(&mut self, prefix: InterfacePrefix) {
        if self.prefixes.len() < MAX_PREFIXES
            && self
                .interfaces
                .iter()
                .any(|interface| interface == &prefix.interface)
        {
            self.prefixes.push(prefix);
        }
    }

    pub fn interfaces(&self) -> &[String] {
        &self.interfaces
    }

    pub fn is_enabled(&self) -> bool {
        !self.interfaces.is_empty()
    }

    pub fn allows(&self, interface: &str, address: &str) -> bool {
        if !self.is_enabled() {
            return true;
        }
        if !self.interfaces.iter().any(|selected| selected == interface) {
            return false;
        }
        let Ok(address) = address.parse::<IpAddr>() else {
            return false;
        };
        if self.prefixes.is_empty() {
            return true;
        }
        self.prefixes
            .iter()
            .any(|prefix| prefix.interface == interface && prefix_contains(prefix, address))
    }
}

fn legacy_string_window(value: &str) -> &str {
    if value.len() < 256 {
        return value;
    }
    let mut end = 255;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn prefix_contains(prefix: &InterfacePrefix, address: IpAddr) -> bool {
    match (prefix.address, address) {
        (IpAddr::V4(prefix_address), IpAddr::V4(address)) => {
            let bits = prefix.prefix_len;
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            (u32::from(address) & mask) == (u32::from(prefix_address) & mask)
        }
        (IpAddr::V6(prefix_address), IpAddr::V6(address)) => {
            let bits = prefix.prefix_len;
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            (u128::from(address) & mask) == (u128::from(prefix_address) & mask)
        }
        _ => false,
    }
}
