use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::{
    error::DaemonError,
    model::{ClientsResponse, Evidence, Interface, InterfaceRole, StatusResponse},
    state::ResponseSnapshot,
};

const COPIED_EVIDENCE_KEYS: &[&str] = &[
    "access_edge",
    "bpf",
    "ecm_bpf_rate_window",
    "effective_collector",
    "nss_window",
    "platform",
    "probe_failures",
];

#[derive(Serialize)]
struct RealtimeResponse<'a> {
    status: StatusResponse,
    clients: ClientsResponse,
    interfaces: RealtimeInterfaces<'a>,
}

#[derive(Serialize)]
struct RealtimeInterfaces<'a> {
    interfaces: Vec<RealtimeInterface<'a>>,
    monotonic_ms: Option<u64>,
}

#[derive(Serialize)]
struct RealtimeInterface<'a> {
    name: &'a str,
    role: InterfaceRole,
    rx_bps: Option<u64>,
    tx_bps: Option<u64>,
    sample_ms: Option<u64>,
}

fn copy_object_fields(
    target: &mut BTreeMap<String, Value>,
    source: &BTreeMap<String, Value>,
    key: &str,
    fields: &[&str],
) {
    let Some(Value::Object(object)) = source.get(key) else {
        return;
    };
    let compact = fields
        .iter()
        .filter_map(|field| {
            object
                .get(*field)
                .map(|value| ((*field).to_owned(), value.clone()))
        })
        .collect();
    target.insert(key.to_owned(), Value::Object(compact));
}

fn compact_evidence(source: &Evidence) -> Evidence {
    let mut details = COPIED_EVIDENCE_KEYS
        .iter()
        .filter_map(|key| {
            source
                .details
                .get(*key)
                .map(|value| ((*key).to_owned(), value.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    copy_object_fields(
        &mut details,
        &source.details,
        "collector",
        &["primary_source"],
    );
    copy_object_fields(
        &mut details,
        &source.details,
        "ecm_bpf",
        &["sample_ms", "last_complete_snapshot_ms"],
    );
    copy_object_fields(&mut details, &source.details, "nss", &["host_count"]);
    Evidence { details }
}

fn realtime_interfaces(snapshot: &ResponseSnapshot) -> RealtimeInterfaces<'_> {
    RealtimeInterfaces {
        interfaces: snapshot
            .interfaces
            .interfaces
            .iter()
            .map(|interface: &Interface| RealtimeInterface {
                name: &interface.name,
                role: interface.role,
                rx_bps: interface.rx_bps,
                tx_bps: interface.tx_bps,
                sample_ms: interface.sample_ms,
            })
            .collect(),
        monotonic_ms: snapshot.interfaces.monotonic_ms,
    }
}

pub fn response(snapshot: &ResponseSnapshot) -> Result<Value, DaemonError> {
    let mut status = snapshot.status.clone();
    status.evidence = compact_evidence(&status.evidence);
    let mut clients = snapshot.clients.clone();
    clients.evidence = clients.evidence.as_ref().map(compact_evidence);

    Ok(serde_json::to_value(RealtimeResponse {
        status,
        clients,
        interfaces: realtime_interfaces(snapshot),
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_evidence_keeps_live_clocks_and_drops_diagnostics() {
        let source = Evidence {
            details: BTreeMap::from([
                (
                    "effective_collector".into(),
                    Value::String("nss_ecm_bpf".into()),
                ),
                (
                    "ecm_bpf".into(),
                    serde_json::json!({
                        "sample_ms": 42,
                        "last_complete_snapshot_ms": 41,
                        "source_stats": {"bytes": 99}
                    }),
                ),
                (
                    "nss_control".into(),
                    serde_json::json!({"state": "verified"}),
                ),
            ]),
        };

        let compact = compact_evidence(&source);
        assert_eq!(compact.details["effective_collector"], "nss_ecm_bpf");
        assert_eq!(compact.details["ecm_bpf"]["sample_ms"], 42);
        assert!(compact.details["ecm_bpf"].get("source_stats").is_none());
        assert!(!compact.details.contains_key("nss_control"));
    }
}
