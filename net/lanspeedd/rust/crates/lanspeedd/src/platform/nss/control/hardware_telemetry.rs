//! Read-only NSS kmod hardware telemetry.

use std::fs;

use serde_json::{json, Map, Value};

const TELEMETRY_PATH: &str = "/sys/module/lanspeed_nss_control/parameters/telemetry";
const CADENCE_PATH: &str = "/sys/module/lanspeed_nss_control/parameters/telemetry_cadence";
const MAX_TELEMETRY_BYTES: u64 = 4096;

const FIELDS: &[&str] = &[
    "sync_count",
    "last_sync_ns",
    "igs_bytes",
    "igs_packets",
    "igs_drops",
    "peer_generation",
    "peer_reassert",
    "ack_latency_last_ns",
    "ack_latency_max_ns",
    "ack_received",
    "ack_timeout",
    "ack_late",
    "control_generation",
    "hardware_generation",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HardwareTelemetrySample {
    pub control_generation: u64,
    pub hardware_generation: u64,
    pub igs_sync_count: u64,
    pub igs_last_sync_ns: u64,
    pub igs_bytes: u64,
    pub igs_packets: u64,
    pub igs_drops: u64,
    pub igs_active_nodes: u32,
}

pub(super) fn read() -> Value {
    let Ok(metadata) = fs::metadata(TELEMETRY_PATH) else {
        return json!({"state": "unavailable"});
    };
    if metadata.len() > MAX_TELEMETRY_BYTES {
        return json!({"state": "invalid"});
    }
    let Ok(text) = fs::read_to_string(TELEMETRY_PATH) else {
        return json!({"state": "unavailable"});
    };
    let mut value = parse(&text).unwrap_or_else(|| json!({"state": "invalid"}));
    if value["state"] == "ready" {
        if let Some(object) = value.as_object_mut() {
            object.insert("igs_cadence".into(), read_cadence());
        }
        if let Some(runtime) = super::genl::read_runtime() {
            if let Some(object) = value.as_object_mut() {
                if let Some(caps) = runtime.get("caps") {
                    object.insert("genl_caps".into(), caps.clone());
                }
                if let Some(state) = runtime.get("state") {
                    object.insert("genl_state".into(), state.clone());
                }
                if let Some(stats) = runtime.get("stats") {
                    object.insert("genl_stats".into(), stats.clone());
                }
                if let Some(health) = runtime.get("health") {
                    object.insert("genl_health".into(), health.clone());
                }
            }
        }
    }
    value
}

pub(crate) fn sample() -> Option<HardwareTelemetrySample> {
    let telemetry = parse(&fs::read_to_string(TELEMETRY_PATH).ok()?)?;
    let cadence = parse_cadence(&fs::read_to_string(CADENCE_PATH).ok()?)?;
    Some(HardwareTelemetrySample {
        control_generation: telemetry.get("control_generation")?.as_u64()?,
        hardware_generation: telemetry.get("hardware_generation")?.as_u64()?,
        igs_sync_count: telemetry.get("sync_count")?.as_u64()?,
        igs_last_sync_ns: telemetry.get("last_sync_ns")?.as_u64()?,
        igs_bytes: telemetry.get("igs_bytes")?.as_u64()?,
        igs_packets: telemetry.get("igs_packets")?.as_u64()?,
        igs_drops: telemetry.get("igs_drops")?.as_u64()?,
        igs_active_nodes: cadence.get("active_nodes")?.as_u64()?.try_into().ok()?,
    })
}

fn read_cadence() -> Value {
    let Ok(metadata) = fs::metadata(CADENCE_PATH) else {
        return json!({"state": "unavailable"});
    };
    if metadata.len() > MAX_TELEMETRY_BYTES {
        return json!({"state": "invalid"});
    }
    let Ok(text) = fs::read_to_string(CADENCE_PATH) else {
        return json!({"state": "unavailable"});
    };
    parse_cadence(&text).unwrap_or_else(|| json!({"state": "invalid"}))
}

fn parse(text: &str) -> Option<Value> {
    let mut fields = text.split_ascii_whitespace();
    if fields.next()? != "v1" {
        return None;
    }
    let mut values = Map::new();
    for field in fields {
        let (key, value) = field.split_once('=')?;
        if !FIELDS.contains(&key) || values.contains_key(key) {
            return None;
        }
        let value = value.parse::<u64>().ok()?;
        values.insert(key.to_owned(), Value::from(value));
    }
    (values.len() == FIELDS.len()).then(|| {
        let mut result = Map::new();
        result.insert("state".into(), Value::from("ready"));
        result.extend(values);
        Value::Object(result)
    })
}

fn parse_cadence(text: &str) -> Option<Value> {
    const CADENCE_FIELDS: &[&str] = &[
        "samples",
        "last_interval_ns",
        "min_interval_ns",
        "max_interval_ns",
        "active_nodes",
    ];
    let mut fields = text.split_ascii_whitespace();
    if fields.next()? != "v1" {
        return None;
    }
    let mut values = Map::new();
    for field in fields {
        let (key, value) = field.split_once('=')?;
        if !CADENCE_FIELDS.contains(&key) || values.contains_key(key) {
            return None;
        }
        values.insert(key.to_owned(), Value::from(value.parse::<u64>().ok()?));
    }
    (values.len() == CADENCE_FIELDS.len()).then(|| {
        let mut result = Map::new();
        result.insert("state".into(), Value::from("ready"));
        result.extend(values);
        Value::Object(result)
    })
}

#[cfg(test)]
mod tests {
    use super::{parse, parse_cadence, HardwareTelemetrySample};

    #[test]
    fn parses_the_fixed_v1_telemetry_contract() {
        let text = format!(
            "v1 {}",
            [
                "sync_count=1",
                "last_sync_ns=2",
                "igs_bytes=3",
                "igs_packets=4",
                "igs_drops=5",
                "peer_generation=6",
                "peer_reassert=7",
                "ack_latency_last_ns=8",
                "ack_latency_max_ns=9",
                "ack_received=10",
                "ack_timeout=11",
                "ack_late=12",
                "control_generation=13",
                "hardware_generation=14",
            ]
            .join(" ")
        );
        let value = parse(&text).unwrap();
        assert_eq!(value["state"], "ready");
        assert_eq!(value["hardware_generation"], 14);
    }

    #[test]
    fn rejects_unknown_duplicate_and_signed_fields() {
        assert!(parse("v1 sync_count=1 unknown=2").is_none());
        assert!(parse("v1 sync_count=1 sync_count=2").is_none());
        assert!(parse("v1 sync_count=-1").is_none());
    }

    #[test]
    fn parses_per_node_igs_cadence_without_changing_the_v1_counter_contract() {
        let value = parse_cadence(
            "v1 samples=10 last_interval_ns=100 min_interval_ns=90 \
             max_interval_ns=120 active_nodes=2",
        )
        .unwrap();
        assert_eq!(value["state"], "ready");
        assert_eq!(value["samples"], 10);
        assert_eq!(value["active_nodes"], 2);
        assert!(parse_cadence("v1 samples=1 unknown=2").is_none());
    }

    #[test]
    fn typed_sample_keeps_only_verifier_fields() {
        let telemetry = parse(
            "v1 sync_count=1 last_sync_ns=2 igs_bytes=3 igs_packets=4 igs_drops=5 \
             peer_generation=6 peer_reassert=7 ack_latency_last_ns=8 \
             ack_latency_max_ns=9 ack_received=10 ack_timeout=11 ack_late=12 \
             control_generation=13 hardware_generation=14",
        )
        .unwrap();
        let cadence = parse_cadence(
            "v1 samples=10 last_interval_ns=100 min_interval_ns=90 \
             max_interval_ns=120 active_nodes=2",
        )
        .unwrap();
        let sample = HardwareTelemetrySample {
            control_generation: telemetry["control_generation"].as_u64().unwrap(),
            hardware_generation: telemetry["hardware_generation"].as_u64().unwrap(),
            igs_sync_count: telemetry["sync_count"].as_u64().unwrap(),
            igs_last_sync_ns: telemetry["last_sync_ns"].as_u64().unwrap(),
            igs_bytes: telemetry["igs_bytes"].as_u64().unwrap(),
            igs_packets: telemetry["igs_packets"].as_u64().unwrap(),
            igs_drops: telemetry["igs_drops"].as_u64().unwrap(),
            igs_active_nodes: cadence["active_nodes"].as_u64().unwrap() as u32,
        };
        assert_eq!(sample.control_generation, 13);
        assert_eq!(sample.hardware_generation, 14);
        assert_eq!(sample.igs_active_nodes, 2);
    }
}
