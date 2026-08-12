use std::collections::{BTreeMap, BTreeSet};

use crate::control::{ActiveRule, ApplyResult, ControlPlan, NSS_CPU_DOWNLOAD, NSS_CPU_UPLOAD};

use super::{
    cpu_path, ecm_qos, firewall,
    qdisc::{classid, leaf_handle, Direction},
    system,
    topology::Topology,
};

/// NSS queue counters verify control only. They never feed RateMux or any
/// collector and therefore cannot become another client-rate source.
pub(super) fn observe(plan: &ControlPlan, previous: &ApplyResult) -> ApplyResult {
    if plan.rules.is_empty() {
        return previous.clone();
    }
    let shaping = plan
        .rules
        .iter()
        .any(|rule| rule.upload_bps != 0 || rule.download_bps != 0);
    let Ok(topology) = super::topology::discover(plan) else {
        let mut next = previous.clone();
        next.state = "pending".into();
        next.reason = Some("control_topology_changed".into());
        clear_verification(&mut next);
        return next;
    };
    if firewall::verify(plan, true).is_err()
        || super::qdisc::verify_plan(plan, &topology).is_err()
        || cpu_path::verify(plan).is_err()
    {
        let mut next = previous.clone();
        next.state = "pending".into();
        next.reason = Some("control_topology_changed".into());
        clear_verification(&mut next);
        return next;
    }
    if !shaping {
        return previous.clone();
    }
    let Ok(mut current_drops) = drop_snapshot(plan, &topology) else {
        return queue_stats_unavailable(previous);
    };
    let Ok(mut current_classes) = class_snapshot(plan, &topology) else {
        return queue_stats_unavailable(previous);
    };
    let Ok(cpu_drops) = cpu_path::drop_snapshot(plan) else {
        return queue_stats_unavailable(previous);
    };
    let Ok(cpu_classes) = cpu_path::class_snapshot(plan) else {
        return queue_stats_unavailable(previous);
    };
    current_drops.extend(cpu_drops);
    current_classes.extend(cpu_classes);
    let tagged_directions = if needs_tag_snapshot(plan, previous) {
        ecm_qos::tagged_directions(plan).unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    if previous
        .class_counter_baselines
        .keys()
        .collect::<BTreeSet<_>>()
        != current_classes.keys().collect::<BTreeSet<_>>()
    {
        let mut next = previous.clone();
        next.state = "pending".into();
        next.reason = Some("control_topology_changed".into());
        clear_verification(&mut next);
        return next;
    }
    let mut next = previous.clone();
    next.verification_failures
        .retain(|_, reason| reason != "queue_overflow");
    for rule in &plan.rules {
        let mut directions = previous
            .verified_directions
            .get(&rule.identity_key)
            .copied()
            .unwrap_or(0);
        let mut nss_verified = previous
            .nss_verified_directions
            .get(&rule.identity_key)
            .copied()
            .unwrap_or(0);
        let mut cpu_verified = previous
            .cpu_verified_directions
            .get(&rule.identity_key)
            .copied()
            .unwrap_or(0);
        for (direction, bit) in [(Direction::Upload, 1), (Direction::Download, 2)] {
            if direction.rate(rule) == 0 {
                continue;
            }
            if !plan.nss_direction_path_ready(&rule.identity_key, bit) {
                directions &= !bit;
                nss_verified &= !bit;
                cpu_verified &= !bit;
                continue;
            }
            let active_nss = plan.nss_direction_active_nss(&rule.identity_key, bit);
            let active_cpu = plan.nss_direction_active_cpu(&rule.identity_key, bit);
            let known_nss = plan.nss_direction_proven(&rule.identity_key, bit);
            let known_cpu = plan.nss_direction_uses_cpu(&rule.identity_key, bit);
            let nss_tagged = tagged_directions
                .get(&rule.identity_key)
                .is_some_and(|directions| directions & bit != 0);
            let aggregate_increased = executor_counter_increased(
                &current_classes,
                &previous.class_counter_baselines,
                rule,
                direction,
                "aggregate",
                "class_bytes",
            );
            if active_nss && aggregate_increased && (direction == Direction::Upload || nss_tagged) {
                nss_verified |= bit;
            }
            if active_cpu && aggregate_increased {
                cpu_verified |= bit;
            }
            if known_nss || known_cpu {
                let executors_verified = active_executors_verified(
                    known_nss,
                    known_cpu,
                    nss_verified,
                    cpu_verified,
                    bit,
                );
                if executors_verified {
                    directions |= bit;
                } else {
                    directions &= !bit;
                }
            }
            if direction_counter_increased(
                &current_drops,
                &previous.queue_drop_counters,
                rule,
                direction,
                "queue_drops",
            ) {
                next.verification_failures
                    .insert(rule.identity_key.clone(), "queue_overflow".into());
            }
        }
        if nss_verified != 0 {
            next.nss_verified_directions
                .insert(rule.identity_key.clone(), nss_verified);
        } else {
            next.nss_verified_directions.remove(&rule.identity_key);
        }
        if cpu_verified != 0 {
            next.cpu_verified_directions
                .insert(rule.identity_key.clone(), cpu_verified);
        } else {
            next.cpu_verified_directions.remove(&rule.identity_key);
        }
        if directions != 0 {
            next.verified_directions
                .insert(rule.identity_key.clone(), directions);
        } else {
            next.verified_directions.remove(&rule.identity_key);
        }
    }
    next.class_counter_baselines = current_classes;
    next.queue_drop_counters = current_drops;
    next.queue_overflow = next
        .verification_failures
        .values()
        .any(|reason| reason == "queue_overflow");
    let expected = plan.rules.iter().fold(0usize, |count, rule| {
        count + usize::from(rule.upload_bps != 0) + usize::from(rule.download_bps != 0)
    });
    let verified = plan
        .rules
        .iter()
        .map(|rule| {
            let directions = next
                .verified_directions
                .get(&rule.identity_key)
                .copied()
                .unwrap_or(0);
            usize::from(rule.upload_bps != 0 && directions & 1 != 0)
                + usize::from(rule.download_bps != 0 && directions & 2 != 0)
        })
        .sum::<usize>();
    let path_pending = plan.rules.iter().any(|rule| {
        (rule.upload_bps != 0 && !plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_UPLOAD))
            || (rule.download_bps != 0
                && !plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD))
    });
    if expected != 0 && verified == expected && !next.queue_overflow && !path_pending {
        next.state = "verified".into();
        next.reason = None;
    } else {
        next.state = "pending_new_connections".into();
        next.reason = Some(if path_pending {
            "nss_path_identity_pending".into()
        } else if verified == 0 {
            "traffic_verification_pending".into()
        } else {
            "direction_verification_pending".into()
        });
    }
    next
}

fn queue_stats_unavailable(previous: &ApplyResult) -> ApplyResult {
    let mut next = previous.clone();
    next.state = "pending_new_connections".into();
    next.reason = Some("queue_stats_unavailable".into());
    clear_verification(&mut next);
    next
}

fn clear_verification(result: &mut ApplyResult) {
    result.verified_directions.clear();
    result.nss_verified_directions.clear();
    result.cpu_verified_directions.clear();
    result.queue_overflow = false;
    result
        .verification_failures
        .retain(|_, reason| reason != "queue_overflow");
}

fn needs_tag_snapshot(plan: &ControlPlan, previous: &ApplyResult) -> bool {
    plan.rules.iter().any(|rule| {
        let mut required = 0;
        if rule.download_bps != 0
            && plan.nss_direction_path_ready(&rule.identity_key, NSS_CPU_DOWNLOAD)
            && plan.nss_direction_active_nss(&rule.identity_key, NSS_CPU_DOWNLOAD)
        {
            required |= NSS_CPU_DOWNLOAD;
        }
        let verified = previous
            .nss_verified_directions
            .get(&rule.identity_key)
            .copied()
            .unwrap_or(0);
        required & !verified != 0
    })
}

pub(super) fn drop_snapshot(
    plan: &ControlPlan,
    topology: &Topology,
) -> Result<BTreeMap<String, u64>, String> {
    snapshot(plan, topology, SnapshotKind::Drops)
}

pub(super) fn class_snapshot(
    plan: &ControlPlan,
    topology: &Topology,
) -> Result<BTreeMap<String, u64>, String> {
    snapshot(plan, topology, SnapshotKind::Bytes)
}

#[derive(Clone, Copy)]
enum SnapshotKind {
    Bytes,
    Drops,
}

fn snapshot(
    plan: &ControlPlan,
    topology: &Topology,
    kind: SnapshotKind,
) -> Result<BTreeMap<String, u64>, String> {
    let mut values = BTreeMap::new();
    for rule in &plan.rules {
        for direction in [Direction::Download] {
            if direction.rate(rule) == 0 {
                continue;
            }
            let bit = match direction {
                Direction::Upload => NSS_CPU_UPLOAD,
                Direction::Download => NSS_CPU_DOWNLOAD,
            };
            if !plan.nss_direction_path_ready(&rule.identity_key, bit) {
                continue;
            }
            let suffix = match kind {
                SnapshotKind::Bytes => "class_bytes",
                SnapshotKind::Drops => "queue_drops",
            };
            let devices = topology
                .download_device(&rule.identity_key)
                .into_iter()
                .collect::<Vec<_>>();
            for device in devices {
                let value = counter_for(device, rule.class_minor, kind)?;
                values.insert(snapshot_key(rule, direction, device, suffix), value);
            }
        }
    }
    Ok(values)
}

fn counter_for(device: &str, minor: u16, kind: SnapshotKind) -> Result<u64, String> {
    let object = match kind {
        SnapshotKind::Bytes => "class",
        SnapshotKind::Drops => "qdisc",
    };
    let output = system::output("tc", &["-s", object, "show", "dev", device])?;
    if !output.status.success() {
        return Err("queue_stats_unavailable".into());
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "queue_stats_unavailable")?;
    let class = classid(minor);
    match kind {
        SnapshotKind::Bytes => class_bytes(&text, &class),
        SnapshotKind::Drops => qdisc_drops(&text, &class, &leaf_handle(minor)),
    }
    .ok_or_else(|| "queue_stats_unavailable".into())
}

fn class_bytes(text: &str, class: &str) -> Option<u64> {
    block_counter(
        text,
        |fields| {
            fields.len() >= 3 && fields[0] == "class" && fields[1] == "nsshtb" && fields[2] == class
        },
        "Sent",
    )
}

fn qdisc_drops(text: &str, parent: &str, handle: &str) -> Option<u64> {
    block_counter(
        text,
        |fields| {
            fields.len() >= 3
                && fields[0] == "qdisc"
                && fields[1] == "nssbfifo"
                && fields[2] == handle
                && fields
                    .windows(2)
                    .any(|pair| pair[0] == "parent" && pair[1] == parent)
        },
        "dropped",
    )
}

fn block_counter(
    text: &str,
    header_matches: impl Fn(&[&str]) -> bool,
    counter: &str,
) -> Option<u64> {
    let mut selected = false;
    for line in text.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if matches!(fields.first().copied(), Some("class" | "qdisc")) {
            selected = header_matches(&fields);
            continue;
        }
        if !selected {
            continue;
        }
        if counter == "Sent" && fields.first().copied() == Some("Sent") {
            return fields.get(1)?.parse().ok();
        }
        if counter == "dropped" {
            let value = fields
                .iter()
                .position(|field| *field == "(dropped")
                .and_then(|index| fields.get(index + 1))?;
            return value.trim_end_matches(',').parse().ok();
        }
    }
    None
}

fn snapshot_key(rule: &ActiveRule, direction: Direction, device: &str, suffix: &str) -> String {
    format!(
        "{}/{}/aggregate/{}/{}",
        rule.identity_key,
        direction.name(),
        device,
        suffix
    )
}

fn direction_counter_increased(
    current: &BTreeMap<String, u64>,
    previous: &BTreeMap<String, u64>,
    rule: &ActiveRule,
    direction: Direction,
    suffix: &str,
) -> bool {
    let prefix = format!("{}/{}/", rule.identity_key, direction.name());
    current.iter().any(|(key, count)| {
        key.starts_with(&prefix)
            && key.ends_with(suffix)
            && previous
                .get(key)
                .is_some_and(|previous_count| count > previous_count)
    })
}

fn executor_counter_increased(
    current: &BTreeMap<String, u64>,
    previous: &BTreeMap<String, u64>,
    rule: &ActiveRule,
    direction: Direction,
    executor: &str,
    suffix: &str,
) -> bool {
    let prefix = format!("{}/{}/{executor}/", rule.identity_key, direction.name());
    current.iter().any(|(key, count)| {
        key.starts_with(&prefix)
            && key.ends_with(suffix)
            && previous
                .get(key)
                .is_some_and(|previous_count| count > previous_count)
    })
}

fn active_executors_verified(
    active_nss: bool,
    active_cpu: bool,
    nss_verified: u8,
    cpu_verified: u8,
    bit: u8,
) -> bool {
    (!active_nss || nss_verified & bit != 0) && (!active_cpu || cpu_verified & bit != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_executor_requires_proof_from_each_known_input_path() {
        assert!(active_executors_verified(true, false, 1, 0, 1));
        assert!(active_executors_verified(false, true, 0, 1, 1));
        assert!(!active_executors_verified(true, true, 1, 0, 1));
        assert!(!active_executors_verified(true, true, 0, 1, 1));
        assert!(active_executors_verified(true, true, 1, 1, 1));
    }

    #[test]
    fn parses_nss_text_counters_without_json_support() {
        let classes = "class nsshtb 7d00:123 root leaf 8001:\n\
                       Sent 12345 bytes 9 pkt (dropped 0, overlimits 2 requeues 0)\n";
        let qdiscs = "qdisc nssbfifo 8001: parent 7d00:123 limit 625000b\n\
                      Sent 12345 bytes 9 pkt (dropped 3, overlimits 2 requeues 0)\n";
        assert_eq!(class_bytes(classes, "7d00:123"), Some(12345));
        assert_eq!(qdisc_drops(qdiscs, "7d00:123", "8001:"), Some(3));
    }
}
