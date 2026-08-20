use std::collections::BTreeMap;

use lanspeed_common::{DIR_RX, DIR_TX};

use crate::{
    identity::MacAddress,
    model::{
        ByteDomain, Client, ClientsResponse, InterfaceRole, InterfacesResponse, RateCoverage,
        RateDirectionMeta, RateScope, RateSource,
    },
    platform::nss::{fast_rate_clients::FastClientSample, fast_rate_worker::FastRatePublication},
    state::ResponseSnapshot,
};

use crate::platform::nss::fast_rate_contract::{FastRateBaseContract, FastRateClientContract};

use super::rate_helpers::fast_client_sample_current;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct FastRateOverlayStats {
    pub clients: usize,
    pub directions: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RoutedInterfaceRate {
    tx_bps: u64,
    rx_bps: u64,
    sample_ms: u64,
    window_ms: u64,
    directions: u32,
}

impl RoutedInterfaceRate {
    fn add(&mut self, direction: u8, sample: FastClientSample) {
        if direction == DIR_TX {
            self.tx_bps = self.tx_bps.saturating_add(sample.routed_l2_with_fcs_bps);
        } else if direction == DIR_RX {
            self.rx_bps = self.rx_bps.saturating_add(sample.routed_l2_with_fcs_bps);
        } else {
            return;
        }
        self.sample_ms = self.sample_ms.max(sample.sample_ms);
        self.window_ms = self.window_ms.max(sample.window_ms);
        self.directions = self.directions.saturating_add(1);
    }
}

pub(super) fn apply_fast_rate_overlay(
    snapshot: &mut ResponseSnapshot,
    publication: &FastRatePublication,
    contract: &FastRateBaseContract,
) -> FastRateOverlayStats {
    if !publication.read_valid {
        return FastRateOverlayStats::default();
    }

    let routed_view = snapshot.status.internet_view_mode == "routed";
    let mut stats = FastRateOverlayStats::default();
    for client in &mut snapshot.clients.clients {
        let Ok(mac) = client.mac.parse::<MacAddress>() else {
            continue;
        };
        let Some(meta) = client.rate_meta.as_mut() else {
            continue;
        };
        if !contract.client_matches(mac.octets(), &client.identity_key, meta.generation) {
            continue;
        }
        let tx = publication.client_rate(mac.octets(), DIR_TX);
        let rx = publication.client_rate(mac.octets(), DIR_RX);
        let tx_current = tx.filter(|sample| {
            (routed_view || direction_uses_fast(meta.tx.source))
                && fast_client_sample_current(publication.observed_ms, *sample)
        });
        let rx_current = rx.filter(|sample| {
            (routed_view || direction_uses_fast(meta.rx.source))
                && fast_client_sample_current(publication.observed_ms, *sample)
        });
        // The worker emits a fixed-timer notice every second even when the
        // NSS hardware keeps the same cumulative batch for another read.
        // Keep the source window and its denominator intact, but advance the
        // response publication clock so LuCI's 1s live-batch alignment does
        // not wait for the next hardware batch. The raw source end remains in
        // the FastRate evidence/window fields.
        let tx_published = tx_current.map(|sample| publish_at(publication.observed_ms, sample));
        let rx_published = rx_current.map(|sample| publish_at(publication.observed_ms, sample));
        let mut client_changed = false;

        if let Some(sample) = tx_published {
            client.tx_bps = sample.routed_l2_with_fcs_bps;
            apply_direction(&mut meta.tx, sample, routed_view);
            client_changed = true;
            stats.directions = stats.directions.saturating_add(1);
        }
        if let Some(sample) = rx_published {
            client.rx_bps = sample.routed_l2_with_fcs_bps;
            apply_direction(&mut meta.rx, sample, routed_view);
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
            tx_published.map(|sample| sample.sample_ms),
            rx_published.map(|sample| sample.sample_ms),
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

    if routed_view {
        // Interface rows are a projection of the client rows actually
        // published to this immutable snapshot. A low-rate direction can
        // legitimately retain its previous still-valid window while the
        // opposite direction advances. Summing only directions updated by
        // this notice makes br-lan/WAN disagree with the visible client sum
        // for one frame. Rebuild from the final client response so overview,
        // client rows, logical LAN, physical edge and WAN all share exactly
        // one published value set.
        apply_routed_interface_rates_from_clients(
            &mut snapshot.interfaces,
            &snapshot.clients,
            publication.observed_ms,
        );
    }
    update_latest_overview(snapshot, publication.observed_ms);
    stats
}

fn publish_at(observed_ms: u64, sample: FastClientSample) -> FastClientSample {
    FastClientSample {
        sample_ms: observed_ms.max(sample.sample_ms),
        ..sample
    }
}

pub(super) fn base_contract(
    snapshot: &ResponseSnapshot,
    base_generation: u64,
) -> FastRateBaseContract {
    FastRateBaseContract::new(
        base_generation,
        snapshot.clients.clients.iter().filter_map(|client| {
            let mac = client.mac.parse::<MacAddress>().ok()?.octets();
            let meta = client.rate_meta.as_ref()?;
            Some(FastRateClientContract {
                mac,
                identity_key: client.identity_key.clone(),
                attachment_generation: meta.generation,
            })
        }),
    )
}

pub(super) fn publication_matches_snapshot(
    snapshot: &ResponseSnapshot,
    publication: &FastRatePublication,
    contract: &FastRateBaseContract,
) -> bool {
    let routed_view = snapshot.status.internet_view_mode == "routed";
    snapshot.clients.clients.iter().any(|client| {
        let Ok(mac) = client.mac.parse::<MacAddress>() else {
            return false;
        };
        let Some(meta) = client.rate_meta.as_ref() else {
            return false;
        };
        if !contract.client_matches(mac.octets(), &client.identity_key, meta.generation) {
            return false;
        }
        [(DIR_TX, meta.tx.source), (DIR_RX, meta.rx.source)]
            .into_iter()
            .any(|(direction, source)| {
                (routed_view || direction_uses_fast(source))
                    && publication
                        .client_rate(mac.octets(), direction)
                        .is_some_and(|sample| {
                            fast_client_sample_current(publication.observed_ms, sample)
                        })
            })
    })
}

/// Route view must use the same per-client FastN+FastS windows as the client
/// rows.  Net-device/Access Edge counters are deliberately not consulted here:
/// a bridge and its wireless child observe the same packet in opposite places
/// and summing those counters is the source of the historical two-times value.
fn apply_routed_interface_rates(
    response: &mut InterfacesResponse,
    logical: &BTreeMap<String, RoutedInterfaceRate>,
    physical: &BTreeMap<String, RoutedInterfaceRate>,
    total: RoutedInterfaceRate,
    observed_ms: u64,
) {
    for interface in &mut response.interfaces {
        let is_wan = interface.name == "wan" || interface.role == InterfaceRole::Wan;
        let rate = if is_wan {
            Some(total)
        } else {
            match interface.role {
                InterfaceRole::Lan => logical.get(&interface.name).copied(),
                InterfaceRole::Observe => physical.get(&interface.name).copied(),
                InterfaceRole::Wan => Some(total),
                InterfaceRole::Excluded | InterfaceRole::Unknown => None,
            }
        }
        .unwrap_or_default();

        // The LuCI table intentionally presents LAN/physical rows in link
        // orientation.  Keep the raw fields in the corresponding orientation
        // so bridge, radio and client columns remain comparable without adding
        // the same routed packet twice.
        let (rx_bps, tx_bps) = if is_wan {
            (rate.rx_bps, rate.tx_bps)
        } else {
            (rate.tx_bps, rate.rx_bps)
        };
        interface.rx_bps = Some(rx_bps);
        interface.tx_bps = Some(tx_bps);
        interface.delta_ms = Some(if rate.directions == 0 {
            0
        } else {
            rate.window_ms
        });
        interface.sample_ms = Some(if rate.directions == 0 {
            observed_ms
        } else {
            rate.sample_ms
        });
        interface.source = Some("NSS FastN+FastS routed client window".into());
        interface.coverage = Some(if rate.directions == 0 {
            "fast_routed_window_pending".into()
        } else {
            format!("fast_routed_client_directions:{}", rate.directions)
        });
        interface.evidence = None;
    }
}

/// Project the rates already selected by the current collection into the
/// interface response. This closes the gap before the independent worker
/// notice is drained, while preserving the exact client-side owner/window.
pub(super) fn apply_routed_interface_rates_from_clients(
    response: &mut InterfacesResponse,
    clients: &ClientsResponse,
    observed_ms: u64,
) {
    let mut logical_rates = BTreeMap::<String, RoutedInterfaceRate>::new();
    let mut physical_rates = BTreeMap::<String, RoutedInterfaceRate>::new();
    let mut total_rate = RoutedInterfaceRate::default();
    for client in &clients.clients {
        let Some(meta) = client.rate_meta.as_ref() else {
            continue;
        };
        add_client_direction(
            &mut logical_rates,
            &mut physical_rates,
            &mut total_rate,
            client,
            meta,
            DIR_TX,
            client.tx_bps,
            meta.tx.window_ms.or(meta.window_ms),
            meta.tx.sample_ms.or(meta.sample_ms),
        );
        add_client_direction(
            &mut logical_rates,
            &mut physical_rates,
            &mut total_rate,
            client,
            meta,
            DIR_RX,
            client.rx_bps,
            meta.rx.window_ms.or(meta.window_ms),
            meta.rx.sample_ms.or(meta.sample_ms),
        );
    }
    apply_routed_interface_rates(
        response,
        &logical_rates,
        &physical_rates,
        total_rate,
        observed_ms,
    );
}

fn add_client_direction(
    logical_rates: &mut BTreeMap<String, RoutedInterfaceRate>,
    physical_rates: &mut BTreeMap<String, RoutedInterfaceRate>,
    total_rate: &mut RoutedInterfaceRate,
    client: &Client,
    meta: &crate::model::ClientRateMeta,
    direction: u8,
    bps: u64,
    window_ms: Option<u64>,
    sample_ms: Option<u64>,
) {
    let source = if direction == DIR_TX {
        meta.tx.source
    } else {
        meta.rx.source
    };
    if !direction_uses_fast(source) {
        return;
    }
    let sample = FastClientSample {
        sample_ms: sample_ms.unwrap_or_default(),
        window_ms: window_ms.unwrap_or_default(),
        read_end_skew_ms: 0,
        fast_n_bps: 0,
        fast_s_bps: 0,
        fast_total_bps: bps,
        routed_l2_with_fcs_bps: bps,
    };
    total_rate.add(direction, sample);
    logical_rates
        .entry(client.interface.clone())
        .or_default()
        .add(direction, sample);
    if let Some(ifname) = meta
        .attachment
        .as_ref()
        .and_then(|value| value.ifname.as_ref())
    {
        physical_rates
            .entry(ifname.clone())
            .or_default()
            .add(direction, sample);
    }
}

fn direction_uses_fast(source: RateSource) -> bool {
    matches!(
        source,
        RateSource::FastRoutedLease | RateSource::FastRoutedInternet
    )
}

fn apply_direction(direction: &mut RateDirectionMeta, sample: FastClientSample, routed_view: bool) {
    if routed_view {
        direction.source = RateSource::FastRoutedInternet;
    }
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
    use super::{
        apply_fast_rate_overlay, apply_routed_interface_rates_from_clients, base_contract,
        publication_matches_snapshot,
    };
    use crate::{
        model::{
            Client, ClientRateMeta, Confidence, Interface, InterfaceRole, InterfaceStatus,
            OverviewSample, RateAttachment, RateDirectionMeta, RateSource,
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

    fn interface(name: &str, role: InterfaceRole) -> Interface {
        Interface {
            name: name.into(),
            role,
            status: InterfaceStatus::Available,
            rx_bytes: Some(10_000),
            tx_bytes: Some(20_000),
            rx_bps: Some(30),
            tx_bps: Some(40),
            delta_ms: Some(1_000),
            sample_ms: Some(2_000),
            source: Some("old source".into()),
            coverage: Some("old coverage".into()),
            evidence: None,
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
        let contract = base_contract(&snapshot, 1);
        let stats = apply_fast_rate_overlay(&mut snapshot, &publication(true), &contract);
        apply_routed_interface_rates_from_clients(
            &mut snapshot.interfaces,
            &snapshot.clients,
            2_000,
        );
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
    fn held_fast_window_advances_the_publication_clock_without_changing_rate() {
        let mut snapshot = snapshot();
        snapshot.status.internet_view_mode = "routed".into();
        let meta = snapshot.clients.clients[0].rate_meta.as_mut().unwrap();
        meta.tx.source = RateSource::FastRoutedInternet;
        meta.rx.source = RateSource::FastRoutedInternet;
        let mut publication = publication(true);
        publication.observed_ms = 3_000;
        let contract = base_contract(&snapshot, 1);

        apply_fast_rate_overlay(&mut snapshot, &publication, &contract);

        let client = &snapshot.clients.clients[0];
        let meta = client.rate_meta.as_ref().unwrap();
        assert_eq!((client.tx_bps, client.rx_bps), (800, 1_600));
        assert_eq!(client.sample_ms, Some(3_000));
        assert_eq!(meta.sample_ms, Some(3_000));
        assert_eq!(meta.window_ms, Some(1_000));
        assert_eq!(meta.tx.sample_ms, Some(3_000));
        assert_eq!(meta.rx.sample_ms, Some(3_000));
    }

    #[test]
    fn rejects_an_invalid_worker_read_without_reusing_the_previous_window() {
        let mut snapshot = snapshot();
        let before = snapshot.clone();
        let contract = base_contract(&snapshot, 1);
        assert_eq!(
            apply_fast_rate_overlay(&mut snapshot, &publication(false), &contract),
            Default::default()
        );
        assert_eq!(snapshot, before);
    }

    #[test]
    fn routed_view_projects_one_fast_window_to_logical_physical_and_wan_rows() {
        let mut snapshot = snapshot();
        snapshot.status.internet_view_mode = "routed".into();
        snapshot.clients.clients[0]
            .rate_meta
            .as_mut()
            .unwrap()
            .tx
            .source = RateSource::FastRoutedInternet;
        snapshot.clients.clients[0]
            .rate_meta
            .as_mut()
            .unwrap()
            .rx
            .source = RateSource::FastRoutedInternet;
        snapshot.clients.clients[0]
            .rate_meta
            .as_mut()
            .unwrap()
            .attachment = Some(RateAttachment {
            kind: crate::model::AttachmentKind::Wifi,
            ifname: Some("phy1-ap0".into()),
            trust: crate::model::AttachmentTrust::AssociatedStation,
        });
        snapshot.interfaces.interfaces = vec![
            interface("br-lan", InterfaceRole::Lan),
            interface("phy1-ap0", InterfaceRole::Observe),
            interface("wan", InterfaceRole::Wan),
        ];

        let contract = base_contract(&snapshot, 1);
        let stats = apply_fast_rate_overlay(&mut snapshot, &publication(true), &contract);
        assert_eq!(stats.directions, 2);
        let rows = &snapshot.interfaces.interfaces;
        // Client TX=800 and RX=1600.  LAN and the physical Wi-Fi row expose
        // link-oriented raw fields; WAN keeps the Internet-facing direction.
        assert_eq!((rows[0].rx_bps, rows[0].tx_bps), (Some(800), Some(1_600)));
        assert_eq!((rows[1].rx_bps, rows[1].tx_bps), (Some(800), Some(1_600)));
        assert_eq!((rows[2].rx_bps, rows[2].tx_bps), (Some(1_600), Some(800)));
        assert_eq!(rows[0].delta_ms, Some(1_000));
        assert_eq!(
            rows[0].source.as_deref(),
            Some("NSS FastN+FastS routed client window")
        );
    }

    #[test]
    fn routed_interfaces_sum_the_final_client_rows_when_one_direction_is_held() {
        let mut snapshot = snapshot();
        snapshot.status.internet_view_mode = "routed".into();
        let meta = snapshot.clients.clients[0].rate_meta.as_mut().unwrap();
        meta.tx.source = RateSource::FastRoutedInternet;
        meta.rx.source = RateSource::FastRoutedInternet;
        meta.rx.sample_ms = Some(2_000);
        meta.rx.window_ms = Some(1_000);
        snapshot.interfaces.interfaces = vec![
            interface("br-lan", InterfaceRole::Lan),
            interface("wan", InterfaceRole::Wan),
        ];

        let mut publication = publication(true);
        publication.observed_ms = 6_000;
        publication.client_samples[0].1.sample_ms = 6_000;
        // RX is older than max(3.5 s, window + 1 s), so the client keeps its
        // previously published 20 bps while TX advances to 800 bps.
        publication.client_samples[1].1.sample_ms = 2_000;
        let contract = base_contract(&snapshot, 1);
        let stats = apply_fast_rate_overlay(&mut snapshot, &publication, &contract);
        assert_eq!(stats.directions, 1);
        assert_eq!(snapshot.clients.clients[0].tx_bps, 800);
        assert_eq!(snapshot.clients.clients[0].rx_bps, 20);
        assert_eq!(
            (
                snapshot.interfaces.interfaces[0].rx_bps,
                snapshot.interfaces.interfaces[0].tx_bps
            ),
            (Some(800), Some(20))
        );
        assert_eq!(
            (
                snapshot.interfaces.interfaces[1].rx_bps,
                snapshot.interfaces.interfaces[1].tx_bps
            ),
            (Some(20), Some(800))
        );
    }

    #[test]
    fn routed_publication_repairs_a_new_base_only_for_the_same_attachment() {
        let mut sampled = snapshot();
        sampled.status.internet_view_mode = "routed".into();
        sampled.clients.clients[0]
            .rate_meta
            .as_mut()
            .unwrap()
            .generation = 7;
        let contract = base_contract(&sampled, 11);

        let mut next = sampled.clone();
        let meta = next.clients.clients[0].rate_meta.as_mut().unwrap();
        meta.tx.source = RateSource::None;
        meta.rx.source = RateSource::None;
        next.clients.clients[0].tx_bps = 0;
        next.clients.clients[0].rx_bps = 0;
        assert!(publication_matches_snapshot(
            &next,
            &publication(true),
            &contract
        ));
        let stats = apply_fast_rate_overlay(&mut next, &publication(true), &contract);
        assert_eq!(stats.directions, 2);
        assert_eq!(next.clients.clients[0].tx_bps, 800);
        assert_eq!(next.clients.clients[0].rx_bps, 1_600);
        assert_eq!(
            next.clients.clients[0]
                .rate_meta
                .as_ref()
                .unwrap()
                .tx
                .source,
            RateSource::FastRoutedInternet
        );

        next.clients.clients[0]
            .rate_meta
            .as_mut()
            .unwrap()
            .generation = 8;
        assert!(!publication_matches_snapshot(
            &next,
            &publication(true),
            &contract
        ));
        let before = next.clone();
        assert_eq!(
            apply_fast_rate_overlay(&mut next, &publication(true), &contract),
            Default::default()
        );
        assert_eq!(next, before);
    }
}
