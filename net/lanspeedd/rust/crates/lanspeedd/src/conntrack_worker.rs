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

#[cfg(not(feature = "nss-platform"))]
use crate::platform::x86::proxy_connections::ProxyConnectionCollector;
use crate::{
    collectors::conntrack::{self, CollectorMode},
    config::ConnectionCollectorMode,
    connection_details::{
        ConnectionCountersSnapshot, ConnectionDetailsSnapshot, ConnectionRateBook,
    },
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
    /// NSS offload counters may be synchronized one worker cycle late. Keep
    /// the same deferred-rate policy used by the in-process collector.
    pub defer_connection_rates: bool,
}

pub fn spawn(snapshots: SnapshotStore) -> Result<RuntimeWorker<ConntrackTask>, std::io::Error> {
    let mut connection_rates = ConnectionRateBook::default();
    #[cfg(not(feature = "nss-platform"))]
    let mut proxy_connections = ProxyConnectionCollector::default();
    spawn_runtime_worker(1, move |task| {
        // A malformed kernel response must not permanently remove the runtime
        // worker. Publish a normal failure snapshot and keep retrying on the
        // next scheduled task instead of letting the thread disappear.
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
            run_task(
                &snapshots,
                task,
                &mut connection_rates,
                #[cfg(not(feature = "nss-platform"))]
                &mut proxy_connections,
            )
        })) {
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

fn update_connection_rates(
    connection_rates: &mut ConnectionRateBook,
    defer: bool,
    sample_ms: u64,
    counters: &ConnectionCountersSnapshot,
    details: &mut ConnectionDetailsSnapshot,
) {
    if defer {
        connection_rates.update_deferred(sample_ms, counters, details);
    } else {
        connection_rates.update(sample_ms, counters, details);
    }
}

fn run_task(
    snapshots: &SnapshotStore,
    task: ConntrackTask,
    connection_rates: &mut ConnectionRateBook,
    #[cfg(not(feature = "nss-platform"))] proxy_connections: &mut ProxyConnectionCollector,
) {
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
        Ok(mut collected) => {
            update_connection_rates(
                connection_rates,
                task.defer_connection_rates,
                collected.sample_ms,
                &collected.connection_counters,
                &mut collected.connection_details,
            );
            #[cfg(not(feature = "nss-platform"))]
            proxy_connections.enrich(&identities, task.now_ms, task.max_clients, &mut collected);
            apply_conntrack_success(&latest, &collected, task.mode.as_str())
        }
        Err(error) => {
            connection_rates.clear();
            apply_conntrack_failure(&latest, &error.to_string())
        }
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
    use std::{collections::BTreeMap, sync::Arc};

    use super::{identities_from_clients, update_connection_rates};
    use crate::connection_details::{
        ClientConnectionDetail, ClientConnectionSet, ConnectionCounters,
        ConnectionCountersSnapshot, ConnectionDetailsSnapshot, ConnectionDirection,
        ConnectionProtocol, ConnectionRateBook, ConnectionRateKey, ConnectionState, RateProtocol,
    };
    use crate::model::{Client, ClientsResponse, Evidence};

    fn details() -> ConnectionDetailsSnapshot {
        Arc::new(BTreeMap::from([(
            "client".into(),
            ClientConnectionSet {
                total_connections: 1,
                connections: vec![ClientConnectionDetail {
                    client_ip: "192.0.2.2".parse().unwrap(),
                    client_port: 12_345,
                    remote_ip: "198.51.100.2".parse().unwrap(),
                    remote_port: 443,
                    protocol: ConnectionProtocol::Tcp,
                    state: ConnectionState::Established,
                    direction: ConnectionDirection::Outbound,
                    tx_bps: 0,
                    rx_bps: 0,
                }],
                truncated: false,
            },
        )]))
    }

    fn counters(tx_bytes: u64, rx_bytes: u64) -> ConnectionCountersSnapshot {
        Arc::new(BTreeMap::from([(
            ConnectionRateKey {
                conntrack_id: Some(7),
                conntrack_zone: Some(0),
                identity_key: "client".into(),
                client_ip: "192.0.2.2".parse().unwrap(),
                client_port: 12_345,
                remote_ip: Some("198.51.100.2".parse().unwrap()),
                remote_port: 443,
                protocol: RateProtocol::Tcp,
                direction: ConnectionDirection::Outbound,
            },
            ConnectionCounters { tx_bytes, rx_bytes },
        )]))
    }

    #[test]
    fn worker_keeps_connection_rates_across_published_snapshots() {
        let mut book = ConnectionRateBook::default();
        let mut first = details();
        update_connection_rates(&mut book, false, 1_000, &counters(100, 200), &mut first);

        let mut second = details();
        update_connection_rates(
            &mut book,
            false,
            2_000,
            &counters(25_100, 10_200),
            &mut second,
        );

        let detail = &second["client"].connections[0];
        assert_eq!(detail.tx_bps, 200_000);
        assert_eq!(detail.rx_bps, 80_000);
    }

    #[test]
    fn worker_uses_deferred_policy_for_nss_counters() {
        let mut book = ConnectionRateBook::default();
        let mut first = details();
        update_connection_rates(&mut book, true, 1_000, &counters(100, 200), &mut first);

        let mut second = details();
        update_connection_rates(
            &mut book,
            true,
            3_000,
            &counters(25_100, 10_200),
            &mut second,
        );

        let detail = &second["client"].connections[0];
        assert_eq!(detail.tx_bps, 100_000);
        assert_eq!(detail.rx_bps, 40_000);
    }

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
