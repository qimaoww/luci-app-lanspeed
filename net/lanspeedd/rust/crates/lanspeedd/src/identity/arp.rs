use super::{
    filter::IdentityFilter, normalize_ip_address, resolve_zone, MacAddress, NeighborEntry,
    ZoneResolver,
};
use std::{fs, io, path::Path};

pub const ARP_PROCFS_PATH: &str = "/proc/net/arp";

pub fn read_arp_table(
    path: impl AsRef<Path>,
    max_entries: usize,
    filter: &IdentityFilter,
    zone_resolver: &impl ZoneResolver,
) -> io::Result<Vec<NeighborEntry>> {
    fs::read_to_string(path)
        .map(|contents| parse_arp_table(&contents, max_entries, filter, zone_resolver))
}

pub fn parse_arp_table(
    contents: &str,
    max_entries: usize,
    filter: &IdentityFilter,
    zone_resolver: &impl ZoneResolver,
) -> Vec<NeighborEntry> {
    let mut entries = Vec::new();
    for line in contents.lines().skip(1) {
        if entries.len() >= max_entries {
            break;
        }
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 6 || parse_c_base_zero(columns[2]) == 0 {
            continue;
        }
        let Ok(mac) = columns[3].parse::<MacAddress>() else {
            continue;
        };
        let interface = columns[5];
        if super::filter::ifname_is_excluded_identity_source(interface) {
            continue;
        }
        let Some(ip) = normalize_ip_address(columns[0]) else {
            continue;
        };
        if !filter.allows(interface, &ip) {
            continue;
        }
        entries.push(NeighborEntry {
            ip,
            mac,
            interface: interface.to_owned(),
            zone: resolve_zone(zone_resolver, interface),
        });
    }
    entries
}

fn parse_c_base_zero(value: &str) -> u64 {
    let (negative, value) = if let Some(value) = value.strip_prefix('-') {
        (true, value)
    } else if let Some(value) = value.strip_prefix('+') {
        (false, value)
    } else {
        (false, value)
    };
    let (digits, radix) = if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (value, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    let digit_count = digits
        .bytes()
        .take_while(|byte| (*byte as char).to_digit(radix).is_some())
        .count();
    if digit_count == 0 {
        return 0;
    }
    let parsed = u64::from_str_radix(&digits[..digit_count], radix).unwrap_or(u64::MAX);
    if negative {
        parsed.wrapping_neg()
    } else {
        parsed
    }
}
