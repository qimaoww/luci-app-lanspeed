//! Slow connection metadata collection kept outside the rate collection turn.
//!
//! The NSS and x86 rate paths intentionally do not dump conntrack on every
//! refresh.  This worker owns the slower read and publishes a complete
//! connection overlay into the immutable snapshot store when it finishes.

use std::{
    any::Any,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
};

use crate::{
    collectors::conntrack::{self, CollectorMode},
    config::ConnectionCollectorMode,
    connections::{apply_conntrack_failure, apply_conntrack_success},
    identity::{IdentityObservation, IdentityTable, ObservationSource},
    model::ClientsResponse,
    state::SnapshotStore,
    workers::{spawn_runtime_worker, RuntimeWorker},
};

/// Conntrack is diagnostic/connection metadata, not a rate source.  Keep its
/// cadence independent from the one-second UI and NSS rate cadence.
pub const CONNTRACK_WORK_INTERVAL_MS: u64 = 2_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConntrackTask {
    pub now_ms: u64,
    pub max_clients: usize,
    pub mode: ConnectionCollectorMode,
}

pub fn spawn(snapshots: SnapshotStore) -> Result<RuntimeWorker<ConntrackTask>, std::io::Error> {
    spawn_runtime_worker(1, move |task| {
        // A malformed kernel response must not permanently remove the runtime
        // worker. Publish a normal failure snapshot and keep retrying on the
        // next scheduled task instead of letting the thread disappear.
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| run_task(&snapshots, task))) {
            let latest = snapshots.load();
            let error = format!(
                "conntrack worker panic: {}",
                panic_message(payload.as_ref())
            );
            snapshots.publish(Arc::new(apply_conntrack_failure(&latest, &error)));
        }
    })
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_owned();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "unknown panic payload".to_owned()
}

fn run_task(snapshots: &SnapshotStore, task: ConntrackTask) {
    // Build the identity table on the worker from the latest immutable client
    // snapshot.  This keeps both the potentially slow read and identity
    // preparation off the uloop/UBus thread.
    let current = snapshots.load();
    let identities = identities_from_clients(&current.clients, task.max_clients);
    let result = conntrack::collect(
        collector_mode(task.mode),
        &identities,
        task.now_ms,
        task.max_clients,
    );

    // A rate collection may have published while conntrack was being read.
    // Overlay onto the newest generation so the worker never rolls back rate
    // or topology data; only the connection fields are replaced.
    let latest = snapshots.load();
    let overlaid = match result {
        Ok(collected) => apply_conntrack_success(&latest, &collected, task.mode.as_str()),
        Err(error) => apply_conntrack_failure(&latest, &error.to_string()),
    };
    snapshots.publish(Arc::new(overlaid));
}

fn collector_mode(mode: ConnectionCollectorMode) -> CollectorMode {
    match mode {
        ConnectionCollectorMode::Auto => CollectorMode::Auto,
        ConnectionCollectorMode::ConntrackNetlink => CollectorMode::Netlink,
        ConnectionCollectorMode::ConntrackProcfs => CollectorMode::Procfs,
    }
}

fn identities_from_clients(clients: &ClientsResponse, max_clients: usize) -> IdentityTable {
    let mut identities = IdentityTable::new(max_clients);
    for client in &clients.clients {
        if client.ips.is_empty() {
            let _ = identities.observe(IdentityObservation {
                mac: &client.mac,
                zone: Some(&client.zone),
                interface: &client.interface,
                ip: None,
                hostname: client.hostname.as_deref(),
                last_seen: client.last_seen,
                source: ObservationSource::Neighbor,
            });
            continue;
        }
        for ip in &client.ips {
            let _ = identities.observe(IdentityObservation {
                mac: &client.mac,
                zone: Some(&client.zone),
                interface: &client.interface,
                ip: Some(ip),
                hostname: client.hostname.as_deref(),
                last_seen: client.last_seen,
                source: ObservationSource::Neighbor,
            });
        }
    }
    identities
}

#[cfg(test)]
mod tests {
    use super::identities_from_clients;
    use crate::model::{Client, ClientsResponse, Evidence};

    #[test]
    fn worker_identity_snapshot_preserves_mac_zone_and_ips() {
        let mut clients = ClientsResponse::empty(Evidence::default());
        clients.clients.push(Client {
            mac: "02:00:00:00:00:01".into(),
            identity_key: "02:00:00:00:00:01@lan".into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.10".into()],
            hostname: Some("client".into()),
            rx_bps: 0,
            tx_bps: 0,
            last_seen: 10,
            sample_ms: Some(10),
            rx_bytes: None,
            tx_bytes: None,
            collector_mode: "nss_ecm_bpf".into(),
            confidence: crate::model::Confidence::High,
            warnings: Vec::new(),
            tcp_conns: None,
            udp_conns: None,
            udp_dns_conns: None,
            udp_other_conns: None,
            rate_meta: None,
            control: None,
        });

        let table = identities_from_clients(&clients, 4);
        let identity = table.by_ip("192.0.2.10").expect("worker must retain IP");
        assert_eq!(identity.key.to_string(), "02:00:00:00:00:01@lan");
        assert_eq!(identity.hostname.as_deref(), Some("client"));
    }
}
