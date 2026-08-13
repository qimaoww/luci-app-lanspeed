use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
    net::IpAddr,
};

use crate::{
    control::{ActiveRule, ControlPlan, NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD},
    platform::nss::ecm_node,
};

const CONNECTION_OUTPUT_MASK: &str = "1\n";
const MAX_LINE_BYTES: usize = 512;
const MAX_LINES: usize = 262_144;
const NSS_ACCELERATED: u8 = 2;

#[derive(Default)]
struct PendingConnection {
    source: Option<IpAddr>,
    destination: Option<IpAddr>,
    nss_accel_mode: Option<u8>,
    dscp_relevant: bool,
    flow_qos_tag: Option<u32>,
    return_qos_tag: Option<u32>,
}

pub(super) fn tagged_directions(plan: &ControlPlan) -> Result<BTreeMap<String, u8>, String> {
    let file = ecm_node::open_snapshot(CONNECTION_OUTPUT_MASK)
        .map_err(|_| "nss_ecm_qos_snapshot_unavailable".to_owned())?;
    parse(BufReader::new(file), plan)
}

fn parse(reader: impl BufRead, plan: &ControlPlan) -> Result<BTreeMap<String, u8>, String> {
    let mut tagged = BTreeMap::new();
    let mut pending = PendingConnection::default();
    let mut lines = 0usize;
    for line in reader.split(b'\n') {
        lines = lines.saturating_add(1);
        if lines > MAX_LINES {
            return Err("nss_ecm_qos_snapshot_invalid".into());
        }
        let line = line.map_err(|_| "nss_ecm_qos_snapshot_unavailable".to_owned())?;
        if line.len() > MAX_LINE_BYTES {
            return Err("nss_ecm_qos_snapshot_invalid".into());
        }
        let text =
            std::str::from_utf8(&line).map_err(|_| "nss_ecm_qos_snapshot_invalid".to_owned())?;
        let Some((key, value)) = text.split_once('=') else {
            continue;
        };
        if key.ends_with(".serial") {
            finish_connection(&mut pending, plan, &mut tagged);
            continue;
        }
        if key.ends_with(".sip_address") {
            pending.source = value.parse().ok();
        } else if key.ends_with(".dip_address") {
            pending.destination = value.parse().ok();
        } else if (key.contains(".nss_v4.") || key.contains(".nss_v6."))
            && key.ends_with(".accel_mode")
        {
            pending.nss_accel_mode = value.parse().ok();
        } else if key.ends_with(".classifiers.dscp.pr.relevant") {
            pending.dscp_relevant = value == "yes";
        } else if key.ends_with(".classifiers.dscp.pr.flow_qos_tag") {
            pending.flow_qos_tag = value.parse().ok();
        } else if key.ends_with(".classifiers.dscp.pr.return_qos_tag") {
            pending.return_qos_tag = value.parse().ok();
        }
    }
    finish_connection(&mut pending, plan, &mut tagged);
    Ok(tagged)
}

fn finish_connection(
    pending: &mut PendingConnection,
    plan: &ControlPlan,
    tagged: &mut BTreeMap<String, u8>,
) {
    let connection = std::mem::take(pending);
    if connection.nss_accel_mode != Some(NSS_ACCELERATED) || !connection.dscp_relevant {
        return;
    }
    let (Some(source), Some(destination), Some(flow_tag), Some(return_tag)) = (
        connection.source,
        connection.destination,
        connection.flow_qos_tag,
        connection.return_qos_tag,
    ) else {
        return;
    };

    for rule in &plan.rules {
        let expected = u32::from(rule.class_minor) << 16;
        if rule.ips.contains(&source) && !local_address(plan, destination) {
            record_tags(tagged, plan, rule, flow_tag, return_tag, expected);
        } else if rule.ips.contains(&destination) && !local_address(plan, source) {
            record_tags(tagged, plan, rule, return_tag, flow_tag, expected);
        }
    }
}

fn record_tags(
    tagged: &mut BTreeMap<String, u8>,
    plan: &ControlPlan,
    rule: &ActiveRule,
    upload_tag: u32,
    download_tag: u32,
    expected: u32,
) {
    let directions = tagged.entry(rule.identity_key.clone()).or_default();
    if rule.upload_bps != 0
        && plan.nss_direction_proven(&rule.identity_key, NSS_CPU_UPLOAD)
        && upload_tag == expected
    {
        *directions |= NSS_CPU_UPLOAD;
    }
    if rule.download_bps != 0
        && plan.nss_direction_proven(&rule.identity_key, NSS_CPU_DOWNLOAD)
        && download_tag == expected
    {
        *directions |= NSS_CPU_DOWNLOAD;
    }
}

fn local_address(plan: &ControlPlan, address: IpAddr) -> bool {
    plan.local_prefixes
        .iter()
        .any(|(network, mask)| prefix_contains(*network, *mask, address))
}

fn prefix_contains(network: IpAddr, mask: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) if mask <= 32 => {
            let bits = if mask == 0 {
                0
            } else {
                u32::MAX << (32 - mask)
            };
            u32::from(network) & bits == u32::from(address) & bits
        }
        (IpAddr::V6(network), IpAddr::V6(address)) if mask <= 128 => {
            let bits = if mask == 0 {
                0
            } else {
                u128::MAX << (128 - mask)
            };
            u128::from(network) & bits == u128::from(address) & bits
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::identity::MacAddress;

    use super::*;

    fn plan() -> ControlPlan {
        ControlPlan {
            lan_device: "router-lan".into(),
            control_devices: vec!["edge0".into()],
            dae_upload_devices: Vec::new(),
            local_prefixes: vec![("10.0.0.0".parse().unwrap(), 8)],
            nss: crate::control::nss_state::NssControlPlan {
                nss_proven_directions: BTreeMap::from([(
                    "02:00:00:00:00:09@lan".into(),
                    crate::control::NSS_CPU_UPLOAD | crate::control::NSS_CPU_DOWNLOAD,
                )]),
                nss_path_ready_directions: BTreeMap::from([(
                    "02:00:00:00:00:09@lan".into(),
                    crate::control::NSS_CPU_UPLOAD | crate::control::NSS_CPU_DOWNLOAD,
                )]),
                ..Default::default()
            },
            rules: vec![ActiveRule {
                identity_key: "02:00:00:00:00:09@lan".into(),
                mac: "02:00:00:00:00:09".parse::<MacAddress>().unwrap(),
                interface: "edge0".into(),
                upload_before_proxy: false,
                upload_preempted: false,
                ips: vec!["192.0.2.9".parse().unwrap()],
                upload_bps: 10_000_000,
                download_bps: 100_000_000,
                internet_disabled: false,
                class_minor: 0x7c23,
            }],
        }
    }

    fn connection(source: &str, destination: &str, accel: u8, flow: u32, reply: u32) -> String {
        format!(
            "conns.conn.1.serial=1\n\
             conns.conn.1.sip_address={source}\n\
             conns.conn.1.dip_address={destination}\n\
             conns.conn.1.nss_v4.ported.accel_mode={accel}\n\
             conns.conn.1.classifiers.dscp.pr.relevant=yes\n\
             conns.conn.1.classifiers.dscp.pr.flow_qos_tag={flow}\n\
             conns.conn.1.classifiers.dscp.pr.return_qos_tag={reply}\n"
        )
    }

    #[test]
    fn outgoing_accelerated_connection_verifies_both_nss_tags() {
        let expected = 0x7c23_0000;
        let input = connection("192.0.2.9", "198.51.100.7", 2, expected, expected);
        assert_eq!(
            parse(Cursor::new(input), &plan()).unwrap(),
            BTreeMap::from([(
                "02:00:00:00:00:09@lan".into(),
                NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD,
            )])
        );
    }

    #[test]
    fn incoming_connection_maps_flow_and_return_to_client_directions() {
        let expected = 0x7c23_0000;
        let input = connection("198.51.100.7", "192.0.2.9", 2, expected, expected);
        assert_eq!(
            parse(Cursor::new(input), &plan()).unwrap(),
            BTreeMap::from([(
                "02:00:00:00:00:09@lan".into(),
                NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD,
            )])
        );
    }

    #[test]
    fn rejects_slow_path_wrong_download_tag_and_local_connections() {
        let expected = 0x7c23_0000;
        let input = format!(
            "{}{}{}",
            connection("192.0.2.9", "198.51.100.7", 0, expected, expected),
            connection("192.0.2.9", "198.51.100.8", 2, expected, 0),
            connection("192.0.2.9", "10.0.0.8", 2, expected, expected)
        );
        assert_eq!(
            parse(Cursor::new(input), &plan()).unwrap(),
            BTreeMap::from([("02:00:00:00:00:09@lan".into(), NSS_CPU_UPLOAD)])
        );
    }

    #[test]
    fn cpu_path_evidence_does_not_suppress_shared_queue_nss_tag_proof() {
        let expected = 0x7c23_0000;
        let input = connection("192.0.2.9", "198.51.100.7", 2, expected, expected);
        let mut plan = plan();
        plan.nss_cpu_directions
            .insert("02:00:00:00:00:09@lan".into(), NSS_CPU_UPLOAD);
        assert_eq!(
            parse(Cursor::new(input), &plan).unwrap(),
            BTreeMap::from([(
                "02:00:00:00:00:09@lan".into(),
                NSS_CPU_UPLOAD | NSS_CPU_DOWNLOAD,
            )])
        );
    }
}
