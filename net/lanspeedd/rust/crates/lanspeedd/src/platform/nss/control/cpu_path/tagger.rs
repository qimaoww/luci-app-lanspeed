use std::{collections::BTreeSet, fs, net::IpAddr};

use crate::control::ControlPlan;

use super::system;

const CONFIG_PATH: &str = "/sys/module/lanspeed_nss_control/parameters/tag_config";
const MAX_TAG_ADDRESSES: usize = 64;
const MAX_LOCAL_PREFIXES: usize = 64;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Record {
    Local(IpAddr, u8),
    Client(IpAddr, u16),
}

pub(super) fn preflight(plan: &ControlPlan) -> Result<(), String> {
    if !system::module_available("lanspeed_nss_control") {
        return Err("lanspeed_nss_control_unavailable".into());
    }
    let records = expected(plan)?;
    if records
        .iter()
        .filter(|record| matches!(record, Record::Local(_, _)))
        .count()
        > MAX_LOCAL_PREFIXES
        || records
            .iter()
            .filter(|record| matches!(record, Record::Client(_, _)))
            .count()
            > MAX_TAG_ADDRESSES
    {
        return Err("nss_igs_tag_capacity_exceeded".into());
    }
    Ok(())
}

pub(super) fn sync(plan: &ControlPlan) -> Result<(), String> {
    system::load_module("lanspeed_nss_control", "lanspeed_nss_control_unavailable")?;
    let records = expected(plan)?;
    fs::write(CONFIG_PATH, render(&records)).map_err(|_| "nss_igs_tag_config_failed".to_owned())?;
    verify_records(&records)
}

pub(super) fn verify(plan: &ControlPlan) -> Result<(), String> {
    verify_records(&expected(plan)?)
}

pub(super) fn cleanup() -> Result<(), String> {
    if !system::module_available("lanspeed_nss_control") {
        return Ok(());
    }
    system::load_module("lanspeed_nss_control", "lanspeed_nss_control_unavailable")?;
    let records = BTreeSet::new();
    fs::write(CONFIG_PATH, render(&records)).map_err(|_| "nss_igs_tag_config_failed".to_owned())?;
    verify_records(&records)
}

fn expected(plan: &ControlPlan) -> Result<BTreeSet<Record>, String> {
    let mut records = plan
        .local_prefixes
        .iter()
        .map(|(address, mask)| Record::Local(*address, *mask))
        .collect::<BTreeSet<_>>();
    let mut owners = std::collections::BTreeMap::<IpAddr, u16>::new();
    for rule in plan.rules.iter().filter(|rule| rule.upload_bps != 0) {
        for address in &rule.ips {
            if owners
                .insert(*address, rule.class_minor)
                .is_some_and(|owner| owner != rule.class_minor)
            {
                return Err("ambiguous_identity".into());
            }
        }
    }
    records.extend(
        owners
            .into_iter()
            .map(|(address, class_minor)| Record::Client(address, class_minor)),
    );
    Ok(records)
}

fn render(records: &BTreeSet<Record>) -> String {
    let mut output = String::from("v1");
    for record in records {
        match record {
            Record::Local(IpAddr::V4(address), mask) => {
                output.push_str(&format!(";L4,{address},{mask}"));
            }
            Record::Local(IpAddr::V6(address), mask) => {
                output.push_str(&format!(";L6,{address},{mask}"));
            }
            Record::Client(IpAddr::V4(address), class_minor) => {
                output.push_str(&format!(";C4,{address},{class_minor}"));
            }
            Record::Client(IpAddr::V6(address), class_minor) => {
                output.push_str(&format!(";C6,{address},{class_minor}"));
            }
        }
    }
    output.push('\n');
    output
}

fn verify_records(expected: &BTreeSet<Record>) -> Result<(), String> {
    let text = fs::read_to_string(CONFIG_PATH)
        .map_err(|_| "nss_igs_tag_config_inspection_failed".to_owned())?;
    let actual = parse(&text)?;
    if &actual == expected {
        Ok(())
    } else {
        Err("nss_igs_tag_config_verification_failed".into())
    }
}

fn parse(text: &str) -> Result<BTreeSet<Record>, String> {
    let mut fields = text.trim().split(';');
    if fields.next() != Some("v1") {
        return Err("nss_igs_tag_config_inspection_failed".into());
    }
    let mut records = BTreeSet::new();
    for field in fields {
        let parts = field.split(',').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err("nss_igs_tag_config_inspection_failed".into());
        }
        let address = parts[1]
            .parse::<IpAddr>()
            .map_err(|_| "nss_igs_tag_config_inspection_failed")?;
        let record = match (parts[0], address) {
            ("L4", IpAddr::V4(_)) | ("L6", IpAddr::V6(_)) => Record::Local(
                address,
                parts[2]
                    .parse::<u8>()
                    .ok()
                    .filter(|mask| *mask <= if address.is_ipv4() { 32 } else { 128 })
                    .ok_or("nss_igs_tag_config_inspection_failed")?,
            ),
            ("C4", IpAddr::V4(_)) | ("C6", IpAddr::V6(_)) => Record::Client(
                address,
                parts[2]
                    .parse::<u16>()
                    .ok()
                    .filter(|tag| *tag != 0)
                    .ok_or("nss_igs_tag_config_inspection_failed")?,
            ),
            _ => return Err("nss_igs_tag_config_inspection_failed".into()),
        };
        if !records.insert(record) {
            return Err("nss_igs_tag_config_inspection_failed".into());
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_snapshot_round_trips_dual_stack_and_local_bypass() {
        let records = BTreeSet::from([
            Record::Local("10.0.0.0".parse().unwrap(), 8),
            Record::Local("fd00::".parse().unwrap(), 8),
            Record::Client("192.0.2.9".parse().unwrap(), 0x7c23),
            Record::Client("2001:db8::9".parse().unwrap(), 0x7c23),
        ]);
        assert_eq!(parse(&render(&records)).unwrap(), records);
    }

    #[test]
    fn tag_snapshot_rejects_wrong_families_duplicates_and_zero_tags() {
        for invalid in [
            "v1;C4,2001:db8::9,31779\n",
            "v1;L6,192.0.2.0,24\n",
            "v1;C4,192.0.2.9,0\n",
            "v1;L4,10.0.0.0,8;L4,10.0.0.0,8\n",
        ] {
            assert!(parse(invalid).is_err());
        }
    }

    #[test]
    fn configured_upload_bits_remain_the_ingress_tag_direction() {
        assert_eq!(crate::control::NSS_CPU_UPLOAD, 1);
    }
}
