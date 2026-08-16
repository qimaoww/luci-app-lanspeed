use std::collections::BTreeMap;

use serde_json::json;

use crate::{
    model::{Evidence, InterfaceRole, InterfacesResponse},
    platform::access_edge::{
        AccessEdgeRuntime, AccessEdgeSnapshot, AttachmentKind, ByteDomain, CounterSegment,
        Direction, EdgeClientObservation, RateSource,
    },
};

const RATE_SOURCE: &str = "NSS Access Edge authoritative same-window rate";
const RATE_NOTE: &str = "NSS LAN and client-edge interface rates use authoritative Access Edge segments from one actual sampling window; cumulative interface bytes remain kernel net-device counters.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompleteRate {
    rx_bps: u64,
    tx_bps: u64,
    sample_ms: u64,
    window_ms: u64,
    client_count: u32,
}

#[derive(Clone, Debug)]
struct RateAccumulator {
    client_count: u32,
    complete: bool,
    window: Option<(u64, u64)>,
    rx_bps: u64,
    tx_bps: u64,
}

impl Default for RateAccumulator {
    fn default() -> Self {
        Self {
            client_count: 0,
            complete: true,
            window: None,
            rx_bps: 0,
            tx_bps: 0,
        }
    }
}

impl RateAccumulator {
    fn observe(&mut self, client: &EdgeClientObservation) {
        self.client_count = self.client_count.saturating_add(1);
        let Some((tx, rx)) = authoritative_segments(client) else {
            self.complete = false;
            return;
        };
        let (Some(rx_bps), Some(tx_bps)) = (tx.bps(), rx.bps()) else {
            self.complete = false;
            return;
        };
        let window = (tx.start_ms, tx.end_ms);
        if self.window.is_some_and(|current| current != window) {
            self.complete = false;
            return;
        }
        self.window = Some(window);
        self.rx_bps = self.rx_bps.saturating_add(rx_bps);
        self.tx_bps = self.tx_bps.saturating_add(tx_bps);
    }

    fn complete(&self) -> Option<CompleteRate> {
        let (start_ms, end_ms) = self.window?;
        let window_ms = end_ms.checked_sub(start_ms)?;
        (self.complete && self.client_count != 0 && window_ms != 0).then_some(CompleteRate {
            rx_bps: self.rx_bps,
            tx_bps: self.tx_bps,
            sample_ms: end_ms,
            window_ms,
            client_count: self.client_count,
        })
    }
}

fn authoritative_segments(
    client: &EdgeClientObservation,
) -> Option<(CounterSegment, CounterSegment)> {
    if !client.is_authoritative() {
        return None;
    }
    let tx = client.tx.segment?;
    let rx = client.rx.segment?;
    if tx.direction != Direction::Tx
        || rx.direction != Direction::Rx
        || tx.epoch_id != rx.epoch_id
        || tx.start_ms != rx.start_ms
        || tx.end_ms != rx.end_ms
        || tx.attachment_generation != client.attachment.generation
        || rx.attachment_generation != client.attachment.generation
    {
        return None;
    }
    let semantics_match = match client.attachment.point.kind {
        AttachmentKind::Wifi => {
            tx.source == RateSource::EdgeWifi
                && rx.source == RateSource::EdgeWifi
                && tx.byte_domain == ByteDomain::StationData
                && rx.byte_domain == ByteDomain::StationData
        }
        AttachmentKind::Ethernet => {
            tx.source == RateSource::EdgePort
                && rx.source == RateSource::EdgePort
                && tx.byte_domain == ByteDomain::L2NoFcs
                && rx.byte_domain == ByteDomain::L2NoFcs
        }
    };
    semantics_match.then_some((tx, rx))
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NssInterfaceRates {
    logical: BTreeMap<String, RateAccumulator>,
    physical: BTreeMap<String, RateAccumulator>,
    logical_complete: bool,
}

impl NssInterfaceRates {
    pub(crate) fn from_published_snapshot(
        runtime: &AccessEdgeRuntime,
        snapshot: &AccessEdgeSnapshot,
    ) -> Self {
        Self::from_snapshot(snapshot, |ifindex| {
            runtime.bridge_name(ifindex).map(str::to_owned)
        })
    }

    fn from_snapshot<F>(snapshot: &AccessEdgeSnapshot, mut bridge_name: F) -> Self
    where
        F: FnMut(u32) -> Option<String>,
    {
        let mut rates = Self {
            logical_complete: true,
            ..Self::default()
        };
        for client in &snapshot.clients {
            rates
                .physical
                .entry(client.attachment.point.ifname.clone())
                .or_default()
                .observe(client);
            let logical = client
                .attachment
                .point
                .bridge_ifindex
                .and_then(&mut bridge_name);
            match logical {
                Some(logical) => rates.logical.entry(logical).or_default().observe(client),
                None => rates.logical_complete = false,
            }
        }
        rates
    }

    pub(crate) fn apply(&self, response: &mut InterfacesResponse) {
        let mut applied = false;
        for interface in &mut response.interfaces {
            let (kind, rate) = match interface.role {
                InterfaceRole::Lan if self.logical_complete => (
                    "logical",
                    self.logical
                        .get(&interface.name)
                        .and_then(RateAccumulator::complete)
                        .or_else(|| {
                            self.physical
                                .get(&interface.name)
                                .and_then(RateAccumulator::complete)
                        }),
                ),
                InterfaceRole::Lan => ("logical", None),
                InterfaceRole::Observe => (
                    "physical",
                    self.physical
                        .get(&interface.name)
                        .and_then(RateAccumulator::complete),
                ),
                _ => continue,
            };
            let Some(rate) = rate else {
                continue;
            };
            interface.rx_bps = Some(rate.rx_bps);
            interface.tx_bps = Some(rate.tx_bps);
            interface.delta_ms = Some(rate.window_ms);
            interface.sample_ms = Some(rate.sample_ms);
            interface.source = Some(format!("{RATE_SOURCE}; cumulative bytes: kernel netdev"));
            interface.coverage = Some(format!(
                "access_edge_same_window:{kind}:{}",
                rate.client_count
            ));
            interface.evidence = Some(Evidence {
                details: BTreeMap::from([(
                    "rate_window".to_owned(),
                    json!({
                        "source": "access_edge",
                        "kind": kind,
                        "sample_ms": rate.sample_ms,
                        "window_ms": rate.window_ms,
                        "client_count": rate.client_count,
                        "complete": true
                    }),
                )]),
            });
            applied = true;
        }
        if applied {
            response.note = Some(RATE_NOTE.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{Interface, InterfaceStatus},
        platform::access_edge::{
            Attachment, AttachmentKey, AttachmentPoint, AttachmentTrust, Coverage,
            EdgeDirectionObservation, TrafficScope,
        },
    };

    fn segment(
        direction: Direction,
        bytes: u64,
        start_ms: u64,
        end_ms: u64,
        generation: u64,
    ) -> CounterSegment {
        CounterSegment {
            epoch_id: 7,
            start_ms,
            end_ms,
            read_begin_ms: end_ms.saturating_sub(2),
            read_end_ms: end_ms,
            source: RateSource::EdgeWifi,
            direction,
            bytes,
            packets: 10,
            attachment_generation: generation,
            byte_domain: ByteDomain::StationData,
            uncertainty_ms: 2,
        }
    }

    fn wifi_client(
        ifname: &str,
        bridge_ifindex: Option<u32>,
        generation: u64,
    ) -> EdgeClientObservation {
        let direction = |direction, bytes| EdgeDirectionObservation {
            segment: Some(segment(direction, bytes, 1_000, 2_000, generation)),
            coverage: Coverage::Full,
            scope: TrafficScope::Unicast,
            failure: None,
            reason_codes: Vec::new(),
        };
        EdgeClientObservation {
            attachment: Attachment {
                key: AttachmentKey {
                    mac: [2, 0, 0, 0, 0, generation as u8],
                    bridge_ifindex,
                    vlan_id: None,
                },
                point: AttachmentPoint {
                    kind: AttachmentKind::Wifi,
                    ifindex: 10,
                    ifname: ifname.to_owned(),
                    bridge_ifindex,
                    vlan_id: None,
                },
                trust: AttachmentTrust::AssociatedStation,
                generation,
                source_generation: generation,
                stable_observations: 2,
                ambiguous: false,
            },
            tx: direction(Direction::Tx, 125_000),
            rx: direction(Direction::Rx, 250_000),
        }
    }

    fn interface(name: &str, role: InterfaceRole) -> Interface {
        Interface {
            name: name.to_owned(),
            role,
            status: InterfaceStatus::Available,
            rx_bytes: Some(9_000),
            tx_bytes: Some(10_000),
            rx_bps: Some(9_000),
            tx_bps: Some(10_000),
            delta_ms: Some(2_000),
            sample_ms: Some(2_000),
            source: Some("kernel".into()),
            coverage: Some("kernel".into()),
            evidence: None,
        }
    }

    #[test]
    fn authoritative_wifi_rates_replace_logical_and_physical_rows() {
        let snapshot = AccessEdgeSnapshot {
            sample_ms: 2_000,
            clients: vec![wifi_client("phy1-ap0", Some(7), 3)],
            ..AccessEdgeSnapshot::default()
        };
        let rates = NssInterfaceRates::from_snapshot(&snapshot, |ifindex| {
            (ifindex == 7).then(|| "br-lan".to_owned())
        });
        let mut response = InterfacesResponse {
            interfaces: vec![
                interface("br-lan", InterfaceRole::Lan),
                interface("phy1-ap0", InterfaceRole::Observe),
                interface("wan", InterfaceRole::Observe),
            ],
            monotonic_ms: Some(2_000),
            note: None,
            evidence: None,
        };

        rates.apply(&mut response);

        for index in [0, 1] {
            assert_eq!(response.interfaces[index].rx_bps, Some(1_000_000));
            assert_eq!(response.interfaces[index].tx_bps, Some(2_000_000));
            assert_eq!(response.interfaces[index].delta_ms, Some(1_000));
            assert!(response.interfaces[index]
                .source
                .as_deref()
                .is_some_and(|source| source.contains(RATE_SOURCE)));
        }
        assert_eq!(response.interfaces[2].rx_bps, Some(9_000));
        assert_eq!(response.interfaces[2].tx_bps, Some(10_000));
        assert_eq!(response.interfaces[0].rx_bytes, Some(9_000));
        assert!(response
            .note
            .as_deref()
            .is_some_and(|note| note == RATE_NOTE));
    }

    #[test]
    fn clients_in_one_window_are_summed_without_direction_swaps() {
        let snapshot = AccessEdgeSnapshot {
            clients: vec![
                wifi_client("phy1-ap0", Some(7), 3),
                wifi_client("phy1-ap0", Some(7), 4),
            ],
            ..AccessEdgeSnapshot::default()
        };
        let rates = NssInterfaceRates::from_snapshot(&snapshot, |_| Some("br-lan".into()));
        let logical = rates.logical["br-lan"].complete().unwrap();
        assert_eq!(logical.rx_bps, 2_000_000);
        assert_eq!(logical.tx_bps, 4_000_000);
        assert_eq!(logical.client_count, 2);
    }

    #[test]
    fn mismatched_or_unproved_segments_fail_closed() {
        let mut mismatch = wifi_client("phy1-ap0", Some(7), 3);
        mismatch.rx.segment.as_mut().unwrap().start_ms = 1_001;
        let mut unproved = wifi_client("phy1-ap0", Some(7), 4);
        unproved.attachment.trust = AttachmentTrust::Unknown;
        for client in [mismatch, unproved] {
            let snapshot = AccessEdgeSnapshot {
                clients: vec![client],
                ..AccessEdgeSnapshot::default()
            };
            let rates = NssInterfaceRates::from_snapshot(&snapshot, |_| Some("br-lan".into()));
            assert!(rates.logical["br-lan"].complete().is_none());
            assert!(rates.physical["phy1-ap0"].complete().is_none());
        }
    }

    #[test]
    fn malformed_segment_fails_closed_instead_of_publishing_saturation() {
        let mut client = wifi_client("phy1-ap0", Some(7), 3);
        client.tx.segment.as_mut().unwrap().end_ms = 1_000;
        let snapshot = AccessEdgeSnapshot {
            clients: vec![client],
            ..AccessEdgeSnapshot::default()
        };
        let rates = NssInterfaceRates::from_snapshot(&snapshot, |_| Some("br-lan".into()));

        assert!(rates.logical["br-lan"].complete().is_none());
        assert!(rates.physical["phy1-ap0"].complete().is_none());
    }

    #[test]
    fn unresolved_bridge_identity_blocks_every_logical_override() {
        let snapshot = AccessEdgeSnapshot {
            clients: vec![
                wifi_client("phy1-ap0", Some(7), 3),
                wifi_client("phy2-ap0", None, 4),
            ],
            ..AccessEdgeSnapshot::default()
        };
        let rates = NssInterfaceRates::from_snapshot(&snapshot, |_| Some("br-lan".into()));
        let mut response = InterfacesResponse {
            interfaces: vec![interface("br-lan", InterfaceRole::Lan)],
            monotonic_ms: Some(2_000),
            note: None,
            evidence: None,
        };

        rates.apply(&mut response);

        assert_eq!(response.interfaces[0].rx_bps, Some(9_000));
        assert_eq!(response.interfaces[0].source.as_deref(), Some("kernel"));
    }
}
