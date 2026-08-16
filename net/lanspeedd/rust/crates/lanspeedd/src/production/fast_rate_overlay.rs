use lanspeed_common::{DIR_RX, DIR_TX};

use crate::{
    identity::MacAddress,
    model::{ByteDomain, RateCoverage, RateDirectionMeta, RateScope, RateSource},
    platform::nss::{fast_rate_clients::FastClientSample, fast_rate_worker::FastRatePublication},
    state::ResponseSnapshot,
};

use super::rate_helpers::fast_client_sample_current;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct FastRateOverlayStats {
    pub clients: usize,
    pub directions: usize,
}

pub(super) fn apply_fast_rate_overlay(
    snapshot: &mut ResponseSnapshot,
    publication: &FastRatePublication,
) -> FastRateOverlayStats {
    if !publication.read_valid {
        return FastRateOverlayStats::default();
    }

    let mut stats = FastRateOverlayStats::default();
    for client in &mut snapshot.clients.clients {
        let Ok(mac) = client.mac.parse::<MacAddress>() else {
            continue;
        };
        let Some(meta) = client.rate_meta.as_mut() else {
            continue;
        };
        let tx = publication.client_rate(mac.octets(), DIR_TX);
        let rx = publication.client_rate(mac.octets(), DIR_RX);
        let mut client_changed = false;

        if direction_uses_fast(meta.tx.source)
            && tx.is_some_and(|sample| fast_client_sample_current(publication.observed_ms, sample))
        {
            let sample = tx.expect("checked FastRate TX sample");
            client.tx_bps = sample.routed_l2_with_fcs_bps;
            apply_direction(&mut meta.tx, sample);
            client_changed = true;
            stats.directions = stats.directions.saturating_add(1);
        }
        if direction_uses_fast(meta.rx.source)
            && rx.is_some_and(|sample| fast_client_sample_current(publication.observed_ms, sample))
        {
            let sample = rx.expect("checked FastRate RX sample");
            client.rx_bps = sample.routed_l2_with_fcs_bps;
            apply_direction(&mut meta.rx, sample);
            client_changed = true;
            stats.directions = stats.directions.saturating_add(1);
        }
        if !client_changed {
            continue;
        }

        stats.clients = stats.clients.saturating_add(1);
        client.tx_bytes = None;
        client.rx_bytes = None;
        client.sample_ms = [
            client.sample_ms,
            tx.map(|sample| sample.sample_ms),
            rx.map(|sample| sample.sample_ms),
        ]
        .into_iter()
        .flatten()
        .max();
        meta.scope = RateScope::RoutedObserved;
        meta.sample_ms = client.sample_ms;
        meta.window_ms = match (tx, rx) {
            (Some(tx), Some(rx)) if tx.window_ms == rx.window_ms => Some(tx.window_ms),
            _ => None,
        };
        meta.stale = false;
        meta.reason_codes.push("fast_rate_worker_overlay".into());
        meta.reason_codes.sort();
        meta.reason_codes.dedup();
    }

    update_latest_overview(snapshot, publication.observed_ms);
    stats
}

fn direction_uses_fast(source: RateSource) -> bool {
    matches!(
        source,
        RateSource::FastRoutedLease | RateSource::FastRoutedInternet
    )
}

fn apply_direction(direction: &mut RateDirectionMeta, sample: FastClientSample) {
    direction.coverage = RateCoverage::Degraded;
    direction.byte_domain = Some(ByteDomain::L2WithFcs);
    direction.sample_ms = Some(sample.sample_ms);
    direction.window_ms = Some(sample.window_ms);
    direction.stale = Some(false);
}

fn update_latest_overview(snapshot: &mut ResponseSnapshot, now_ms: u64) {
    let sample_ms = snapshot
        .clients
        .clients
        .iter()
        .filter_map(|client| client.sample_ms)
        .max()
        .unwrap_or(now_ms);
    let tx_bps = snapshot
        .clients
        .clients
        .iter()
        .fold(0u64, |total, client| total.saturating_add(client.tx_bps));
    let rx_bps = snapshot
        .clients
        .clients
        .iter()
        .fold(0u64, |total, client| total.saturating_add(client.rx_bps));
    let client_count = u32::try_from(snapshot.clients.clients.len()).unwrap_or(u32::MAX);
    let active_clients = u32::try_from(
        snapshot
            .clients
            .clients
            .iter()
            .filter(|client| client_is_active(snapshot, client, now_ms))
            .count(),
    )
    .unwrap_or(u32::MAX);
    let Some(latest) = snapshot.overview.samples.last_mut() else {
        return;
    };
    latest.sample_ms = sample_ms;
    latest.tx_bps = tx_bps;
    latest.rx_bps = rx_bps;
    latest.client_count = client_count;
    latest.active_clients = active_clients;
}

fn client_is_active(
    snapshot: &ResponseSnapshot,
    client: &crate::model::Client,
    now_ms: u64,
) -> bool {
    let rate = client.tx_bps.saturating_add(client.rx_bps);
    if rate < snapshot.status.active_client_min_bps {
        return false;
    }
    let sample_ms = client.sample_ms.unwrap_or_default();
    if matches!(
        client.collector_mode.as_str(),
        "access_edge" | "nss_ecm_node" | "nss_ecm_bpf"
    ) {
        return sample_ms != 0;
    }
    sample_ms != 0
        && client.last_seen != 0
        && client.last_seen <= now_ms
        && now_ms.saturating_sub(client.last_seen) <= snapshot.status.active_client_window_ms
}

#[cfg(test)]
mod tests {
    use super::apply_fast_rate_overlay;
    use crate::{
        model::{
            Client, ClientRateMeta, Confidence, OverviewSample, RateDirectionMeta, RateSource,
        },
        platform::nss::{
            fast_rate_clients::{FastClientKey, FastClientSample},
            fast_rate_worker::FastRatePublication,
        },
        state::ResponseSnapshot,
    };
    use lanspeed_common::{DIR_RX, DIR_TX};

    fn client() -> Client {
        Client {
            mac: "02:00:00:00:00:01".into(),
            identity_key: "lan|02:00:00:00:00:01".into(),
            zone: "lan".into(),
            interface: "br-lan".into(),
            ips: vec!["192.0.2.1".into()],
            hostname: None,
            rx_bps: 20,
            tx_bps: 10,
            last_seen: 2_000,
            sample_ms: Some(2_000),
            rx_bytes: Some(20),
            tx_bytes: Some(10),
            collector_mode: "access_edge".into(),
            confidence: Confidence::High,
            warnings: vec![],
            tcp_conns: None,
            udp_conns: None,
            udp_dns_conns: None,
            udp_other_conns: None,
            rate_meta: Some(ClientRateMeta {
                tx: RateDirectionMeta {
                    source: RateSource::EdgePort,
                    ..RateDirectionMeta::default()
                },
                rx: RateDirectionMeta {
                    source: RateSource::FastRoutedInternet,
                    ..RateDirectionMeta::default()
                },
                ..ClientRateMeta::default()
            }),
            control: None,
        }
    }

    fn publication(read_valid: bool) -> FastRatePublication {
        let sample = |bps| FastClientSample {
            sample_ms: 2_000,
            window_ms: 1_000,
            read_end_skew_ms: 1,
            fast_n_bps: bps / 2,
            fast_s_bps: bps / 2,
            fast_total_bps: bps,
            routed_l2_with_fcs_bps: bps,
        };
        FastRatePublication {
            observed_ms: 2_000,
            read_valid,
            client_samples: vec![
                (
                    FastClientKey {
                        mac: [2, 0, 0, 0, 0, 1],
                        direction: DIR_TX,
                    },
                    sample(800),
                ),
                (
                    FastClientKey {
                        mac: [2, 0, 0, 0, 0, 1],
                        direction: DIR_RX,
                    },
                    sample(1_600),
                ),
            ],
            ..FastRatePublication::default()
        }
    }

    fn snapshot() -> ResponseSnapshot {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.status.active_client_min_bps = 1;
        snapshot.clients.clients.push(client());
        snapshot.overview.samples.push(OverviewSample {
            sample_ms: 1_000,
            tx_bps: 10,
            rx_bps: 20,
            client_count: 1,
            active_clients: 1,
            tcp_conns: None,
            udp_conns: None,
            udp_dns_conns: None,
            udp_other_conns: None,
        });
        snapshot
    }

    #[test]
    fn overlays_only_directions_already_owned_by_fast_rate() {
        let mut snapshot = snapshot();
        let stats = apply_fast_rate_overlay(&mut snapshot, &publication(true));
        let client = &snapshot.clients.clients[0];
        assert_eq!(stats.clients, 1);
        assert_eq!(stats.directions, 1);
        assert_eq!(client.tx_bps, 10);
        assert_eq!(client.rx_bps, 1_600);
        assert_eq!(
            client.rate_meta.as_ref().unwrap().tx.source,
            RateSource::EdgePort
        );
        assert_eq!(
            client.rate_meta.as_ref().unwrap().rx.source,
            RateSource::FastRoutedInternet
        );
        assert_eq!(snapshot.overview.samples[0].tx_bps, 10);
        assert_eq!(snapshot.overview.samples[0].rx_bps, 1_600);
    }

    #[test]
    fn rejects_an_invalid_worker_read_without_reusing_the_previous_window() {
        let mut snapshot = snapshot();
        let before = snapshot.clone();
        assert_eq!(
            apply_fast_rate_overlay(&mut snapshot, &publication(false)),
            Default::default()
        );
        assert_eq!(snapshot, before);
    }
}
