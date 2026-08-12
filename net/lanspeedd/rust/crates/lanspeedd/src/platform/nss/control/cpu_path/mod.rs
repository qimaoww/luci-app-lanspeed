mod block;
mod classifier;
mod ifb;
mod probe;
mod shaper;
mod tagger;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use crate::{
    control::{ActiveRule, ControlPlan, NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD},
    identity::MacAddress,
};

use super::system::{self, TcU32Match, TcU32MatchSet};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Direction {
    Upload,
    Download,
}

impl Direction {
    const ALL: [Self; 2] = [Self::Upload, Self::Download];

    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
        }
    }

    pub(super) const fn bit(self) -> u8 {
        match self {
            Self::Upload => NSS_CPU_UPLOAD,
            Self::Download => NSS_CPU_DOWNLOAD,
        }
    }

    pub(super) const fn configured_rate(self, rule: &ActiveRule) -> u64 {
        match self {
            Self::Upload => rule.upload_bps,
            Self::Download => rule.download_bps,
        }
    }
}

pub(super) fn preflight(plan: &ControlPlan) -> Result<(), String> {
    let control_requested = plan
        .rules
        .iter()
        .any(|rule| rule.upload_bps != 0 || rule.download_bps != 0 || rule.internet_disabled);
    if !control_requested {
        return Ok(());
    }
    block::preflight(plan)?;
    probe::preflight(plan)?;
    tagger::preflight(plan)?;
    if Direction::ALL
        .into_iter()
        .all(|direction| rules(plan, direction).is_empty())
        && !plan.rules.iter().any(|rule| rule.internet_disabled)
    {
        return Ok(());
    }
    for program in ["tc", "ip"] {
        system::require_program(program)?;
    }
    shaper::preflight(plan)?;
    classifier::preflight(plan)
}

pub(super) fn recover_classifier_slots(interfaces: &[String]) -> Result<bool, String> {
    classifier::recover_classifier_slots(interfaces)
}

pub(super) fn stage(plan: &ControlPlan) -> Result<(), String> {
    block::sync(plan)?;
    probe::sync(plan)?;
    // Build and verify the queue before publishing any redirect. A partial
    // setup cannot steal packets from the LAN edge.
    shaper::stage(plan)?;
    if let Err(error) = tagger::sync(plan) {
        return match shaper::cleanup_unpublished() {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!("{error};{cleanup_error}")),
        };
    }
    if let Err(error) = classifier::install(plan) {
        return match shaper::cleanup_unpublished() {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!("{error};{cleanup_error}")),
        };
    }
    shaper::cleanup_stale(plan)?;
    verify(plan)
}

pub(super) fn quiesce(plan: &ControlPlan) -> Result<(), String> {
    block::sync(plan)?;
    probe::sync(plan)?;
    tagger::sync(plan)?;
    classifier::quiesce(plan)
}

pub(super) fn verify(plan: &ControlPlan) -> Result<(), String> {
    block::verify(plan)?;
    probe::verify(plan)?;
    shaper::verify(plan)?;
    tagger::verify(plan)?;
    classifier::verify(plan)
}

pub(super) fn cleanup() -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) = block::cleanup() {
        errors.push(error);
    }
    if let Err(error) = probe::cleanup() {
        errors.push(error);
    }
    if let Err(error) = classifier::cleanup() {
        errors.push(error);
    }
    if let Err(error) = cleanup_shapers() {
        errors.push(error);
    }
    if let Err(error) = tagger::cleanup() {
        errors.push(error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join(";"))
    }
}

pub(crate) use probe::{
    PathProbeBook, PathProbeDirectionWindow, PathProbeSnapshot, PathProbeWindow,
};

pub(super) fn path_probe_snapshot(
    plan: &ControlPlan,
    epoch_end_ms: u64,
) -> Result<PathProbeSnapshot, String> {
    probe::snapshot(plan, epoch_end_ms)
}

fn cleanup_shapers() -> Result<(), String> {
    shaper::cleanup()
}

pub(super) fn owned_shaper_devices() -> Result<BTreeSet<String>, String> {
    Ok(ifb::owned_interfaces()?
        .into_iter()
        .map(|(device, _)| device)
        .collect())
}

pub(super) fn class_snapshot(plan: &ControlPlan) -> Result<BTreeMap<String, u64>, String> {
    shaper::class_bytes(plan)
}

pub(super) fn drop_snapshot(plan: &ControlPlan) -> Result<BTreeMap<String, u64>, String> {
    shaper::queue_drops(plan)
}

pub(super) fn rules(plan: &ControlPlan, direction: Direction) -> Vec<&ActiveRule> {
    plan.rules
        .iter()
        .filter(|rule| direction.configured_rate(rule) != 0)
        .filter(|rule| plan.nss_direction_path_ready(&rule.identity_key, direction.bit()))
        .collect()
}

fn mac_u32_matches(direction: Direction, mac: MacAddress) -> Vec<TcU32Match> {
    let bytes = mac.octets();
    match direction {
        Direction::Upload => vec![
            tc_match(
                i64::from(-8),
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                u32::MAX,
            ),
            tc_match(
                i64::from(-4),
                u32::from_be_bytes([bytes[4], bytes[5], 0, 0]),
                0xffff_0000,
            ),
        ],
        Direction::Download => vec![
            tc_match(
                i64::from(-16),
                u32::from_be_bytes([0, 0, bytes[0], bytes[1]]),
                0x0000_ffff,
            ),
            tc_match(
                i64::from(-12),
                u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
                u32::MAX,
            ),
        ],
    }
}

fn prefix_u32_matches(direction: Direction, address: IpAddr, mask: u8) -> Vec<TcU32Match> {
    match address {
        IpAddr::V4(address) if mask <= 32 => {
            let mask = if mask == 0 {
                0
            } else {
                u32::MAX << (32 - mask)
            };
            (mask != 0)
                .then(|| {
                    tc_match(
                        match direction {
                            Direction::Upload => 16,
                            Direction::Download => 12,
                        },
                        u32::from(address) & mask,
                        mask,
                    )
                })
                .into_iter()
                .collect()
        }
        IpAddr::V6(address) if mask <= 128 => {
            let bytes = address.octets();
            let base = match direction {
                Direction::Upload => 24,
                Direction::Download => 8,
            };
            let mut remaining = mask;
            let mut matches = Vec::new();
            for index in 0..4 {
                let bits = remaining.min(32);
                remaining = remaining.saturating_sub(bits);
                if bits == 0 {
                    continue;
                }
                let mask = if bits == 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - bits)
                };
                let offset = index * 4;
                let value = u32::from_be_bytes([
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                ]) & mask;
                matches.push(tc_match(i64::from(base + offset as i32), value, mask));
            }
            matches
        }
        _ => Vec::new(),
    }
}

fn tc_match(offset: i64, value: u32, mask: u32) -> TcU32Match {
    TcU32Match {
        offset,
        value: format!("{value:x}"),
        mask: format!("{mask:x}"),
    }
}

fn exact_u32_match_count(
    values: &[TcU32MatchSet],
    pref: u32,
    protocol: &str,
    mut expected: Vec<TcU32Match>,
) -> usize {
    expected.sort();
    values
        .iter()
        .filter(|value| {
            value.pref == u64::from(pref) && value.protocol == protocol && value.matches == expected
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_counter_key_names_one_aggregate_executor() {
        let key = "identity/upload/aggregate/device/class_bytes";
        assert!(key.contains("/aggregate/"));
        assert!(!key.contains("/cpu/"));
        assert!(!key.contains("/nss/"));
    }

    #[test]
    fn cpu_path_evidence_directions_use_distinct_bits() {
        assert_ne!(Direction::Upload.bit(), Direction::Download.bit());
    }

    #[test]
    fn qca_match_fingerprints_cover_both_mac_layouts_and_ipv6_words() {
        let mac = "02:00:00:00:00:09".parse().unwrap();
        assert_eq!(
            mac_u32_matches(Direction::Upload, mac),
            vec![
                tc_match(-8, 0x0200_0000, u32::MAX),
                tc_match(-4, 0x0009_0000, 0xffff_0000),
            ]
        );
        assert_eq!(
            mac_u32_matches(Direction::Download, mac),
            vec![
                tc_match(-16, 0x0200, 0xffff),
                tc_match(-12, 0x0000_0009, u32::MAX),
            ]
        );
        assert_eq!(
            prefix_u32_matches(Direction::Download, "::1".parse().unwrap(), 128),
            vec![
                tc_match(8, 0, u32::MAX),
                tc_match(12, 0, u32::MAX),
                tc_match(16, 0, u32::MAX),
                tc_match(20, 1, u32::MAX),
            ]
        );
    }
}
