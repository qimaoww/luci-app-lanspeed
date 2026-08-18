use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::json;

use crate::{
    interfaces::{InterfaceCounterSnapshot, InterfaceCounters},
    model::{Evidence, InterfaceRole, InterfacesResponse},
    platform::access_edge::{
        AccessEdgeSnapshot, AttachmentKey, CounterSegment, Direction, EdgeClientObservation,
    },
};

const MIN_PUBLISH_WINDOW_MS: u64 = 2_000;
const INTERFACE_WINDOW_SKEW_MS: u64 = 100;
const RATE_SOURCE: &str = "NSS aligned low-rate cumulative window";

type EdgeKey = (AttachmentKey, Direction);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InterfaceWindowRate {
    rx_bps: u64,
    tx_bps: u64,
    sample_ms: u64,
    window_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NssLowRateWindow {
    edge: BTreeMap<EdgeKey, VecDeque<CounterSegment>>,
    interfaces: BTreeMap<String, VecDeque<(InterfaceCounters, u64)>>,
    observe_rates: BTreeMap<String, InterfaceWindowRate>,
    high_rate: bool,
    published_window: Option<(u64, u64)>,
    window_ms: u64,
    high_watermark_bps: u64,
}

impl NssLowRateWindow {
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn observe(
        &mut self,
        raw: &AccessEdgeSnapshot,
        counters: &InterfaceCounterSnapshot,
        interface_sample_ms: u64,
        window_ms: u64,
        high_watermark_bps: u64,
    ) -> AccessEdgeSnapshot {
        self.configure(window_ms, high_watermark_bps);
        self.observe_interfaces(counters, interface_sample_ms);
        self.observe_edge(raw);
        self.observe_rates.clear();
        self.published_window = None;

        let Some(total_bps) = complete_raw_rate(raw) else {
            self.high_rate = false;
            return raw.clone();
        };
        if total_bps >= self.high_watermark_bps {
            self.high_rate = true;
            self.retain_current(raw, counters, interface_sample_ms);
            return raw.clone();
        }
        if self.high_rate {
            self.high_rate = false;
            self.retain_current(raw, counters, interface_sample_ms);
            return raw.clone();
        }

        let Some((start_ms, end_ms)) = self.common_edge_window(raw) else {
            return raw.clone();
        };
        if end_ms.saturating_sub(start_ms) < MIN_PUBLISH_WINDOW_MS {
            return raw.clone();
        }
        let Some(published) = self.aggregate_edge(raw, start_ms, end_ms) else {
            return raw.clone();
        };
        let duration_ms = end_ms.saturating_sub(start_ms);
        self.observe_rates = self.interface_rates(interface_sample_ms, duration_ms);
        self.published_window = Some((start_ms, end_ms));
        published
    }

    fn configure(&mut self, window_ms: u64, high_watermark_bps: u64) {
        let window_ms = window_ms.max(MIN_PUBLISH_WINDOW_MS);
        let high_watermark_bps = high_watermark_bps.max(1);
        if self.window_ms == window_ms && self.high_watermark_bps == high_watermark_bps {
            return;
        }
        self.reset();
        self.window_ms = window_ms;
        self.high_watermark_bps = high_watermark_bps;
    }

    pub(crate) fn apply_observe_rates(&self, response: &mut InterfacesResponse) {
        let Some((start_ms, end_ms)) = self.published_window else {
            return;
        };
        for interface in &mut response.interfaces {
            if !matches!(interface.role, InterfaceRole::Observe | InterfaceRole::Wan) {
                continue;
            }
            let Some(rate) = self.observe_rates.get(&interface.name).copied() else {
                continue;
            };
            interface.rx_bps = Some(rate.rx_bps);
            interface.tx_bps = Some(rate.tx_bps);
            interface.delta_ms = Some(rate.window_ms);
            interface.sample_ms = Some(rate.sample_ms);
            interface.source = Some(RATE_SOURCE.to_owned());
            interface.coverage = Some("aligned_low_rate_observe_window".into());
            interface.evidence = Some(Evidence {
                details: BTreeMap::from([(
                    "rate_window".into(),
                    json!({
                        "source": "nss_low_rate_window",
                        "start_ms": start_ms,
                        "end_ms": end_ms,
                        "window_ms": rate.window_ms,
                        "complete": true
                    }),
                )]),
            });
        }
    }

    fn observe_edge(&mut self, raw: &AccessEdgeSnapshot) {
        let mut active = BTreeSet::new();
        for client in &raw.clients {
            for (direction, observation) in
                [(Direction::Tx, &client.tx), (Direction::Rx, &client.rx)]
            {
                let key = (client.attachment.key, direction);
                active.insert(key);
                let Some(segment) = observation.segment else {
                    self.edge.remove(&key);
                    continue;
                };
                let history = self.edge.entry(key).or_default();
                if history.back().is_some_and(|previous| {
                    previous.end_ms != segment.start_ms
                        || previous.source != segment.source
                        || previous.direction != segment.direction
                        || previous.byte_domain != segment.byte_domain
                        || previous.attachment_generation != segment.attachment_generation
                }) {
                    history.clear();
                }
                if history
                    .back()
                    .is_none_or(|previous| previous.end_ms != segment.end_ms)
                {
                    history.push_back(segment);
                }
                while history.front().is_some_and(|first| {
                    segment.end_ms.saturating_sub(first.start_ms) > self.window_ms
                }) {
                    history.pop_front();
                }
            }
        }
        self.edge.retain(|key, _| active.contains(key));
    }

    fn observe_interfaces(&mut self, counters: &InterfaceCounterSnapshot, sample_ms: u64) {
        self.interfaces
            .retain(|name, _| counters.counters.contains_key(name));
        for (name, current) in &counters.counters {
            let history = self.interfaces.entry(name.clone()).or_default();
            if history.back().is_some_and(|(previous, previous_ms)| {
                sample_ms <= *previous_ms
                    || current.rx_bytes < previous.rx_bytes
                    || current.tx_bytes < previous.tx_bytes
            }) {
                history.clear();
            }
            if history
                .back()
                .is_none_or(|(_, previous_ms)| *previous_ms != sample_ms)
            {
                history.push_back((*current, sample_ms));
            }
            // Keep the nearest sample just outside the configured window. The
            // interface clock follows the real collection cadence (typically
            // about 1001 ms), while Access Edge segments use their own exact
            // boundaries. Dropping that outer sample makes an 18 s Edge window
            // periodically miss the closest interface baseline and fall back
            // to the noisy one-second netdev rate.
            while history.len() > 2
                && history.get(1).is_some_and(|(_, second_ms)| {
                    sample_ms.saturating_sub(*second_ms) >= self.window_ms
                })
            {
                history.pop_front();
            }
        }
    }

    fn retain_current(
        &mut self,
        raw: &AccessEdgeSnapshot,
        counters: &InterfaceCounterSnapshot,
        interface_sample_ms: u64,
    ) {
        self.edge.clear();
        self.interfaces.clear();
        self.observe_edge(raw);
        self.observe_interfaces(counters, interface_sample_ms);
        self.observe_rates.clear();
        self.published_window = None;
    }

    fn common_edge_window(&self, raw: &AccessEdgeSnapshot) -> Option<(u64, u64)> {
        let mut start_ms = 0u64;
        let mut end_ms = None;
        let mut directions = 0usize;
        for client in &raw.clients {
            for direction in [Direction::Tx, Direction::Rx] {
                let history = self.edge.get(&(client.attachment.key, direction))?;
                let first = history.front()?;
                let last = history.back()?;
                start_ms = start_ms.max(first.start_ms);
                match end_ms {
                    Some(current) if current != last.end_ms => return None,
                    None => end_ms = Some(last.end_ms),
                    _ => {}
                }
                directions = directions.saturating_add(1);
            }
        }
        (directions != 0).then_some((start_ms, end_ms?))
    }

    fn aggregate_edge(
        &self,
        raw: &AccessEdgeSnapshot,
        start_ms: u64,
        end_ms: u64,
    ) -> Option<AccessEdgeSnapshot> {
        let mut published = raw.clone();
        for client in &mut published.clients {
            client.tx.segment =
                Some(self.aggregate_direction(client, Direction::Tx, start_ms, end_ms)?);
            client.rx.segment =
                Some(self.aggregate_direction(client, Direction::Rx, start_ms, end_ms)?);
            for observation in [&mut client.tx, &mut client.rx] {
                observation
                    .reason_codes
                    .push("nss_low_rate_rolling_window".into());
                observation.reason_codes.sort();
                observation.reason_codes.dedup();
            }
        }
        published.sample_ms = end_ms;
        Some(published)
    }

    fn aggregate_direction(
        &self,
        client: &EdgeClientObservation,
        direction: Direction,
        start_ms: u64,
        end_ms: u64,
    ) -> Option<CounterSegment> {
        let history = self.edge.get(&(client.attachment.key, direction))?;
        let selected = history
            .iter()
            .copied()
            .filter(|segment| segment.start_ms >= start_ms && segment.end_ms <= end_ms)
            .collect::<Vec<_>>();
        let first = selected.first()?;
        let last = selected.last()?;
        if first.start_ms != start_ms
            || last.end_ms != end_ms
            || selected
                .windows(2)
                .any(|pair| pair[0].end_ms != pair[1].start_ms)
            || selected.iter().any(|segment| {
                segment.source != last.source
                    || segment.direction != direction
                    || segment.byte_domain != last.byte_domain
                    || segment.attachment_generation != last.attachment_generation
            })
        {
            return None;
        }
        Some(CounterSegment {
            epoch_id: last.epoch_id,
            start_ms,
            end_ms,
            read_begin_ms: last.read_begin_ms,
            read_end_ms: last.read_end_ms,
            source: last.source,
            direction,
            bytes: selected
                .iter()
                .fold(0u64, |total, segment| total.saturating_add(segment.bytes)),
            packets: selected
                .iter()
                .fold(0u64, |total, segment| total.saturating_add(segment.packets)),
            attachment_generation: last.attachment_generation,
            byte_domain: last.byte_domain,
            uncertainty_ms: selected
                .iter()
                .map(|segment| segment.uncertainty_ms)
                .max()
                .unwrap_or_default(),
        })
    }

    fn interface_rates(
        &self,
        current_ms: u64,
        target_window_ms: u64,
    ) -> BTreeMap<String, InterfaceWindowRate> {
        self.interfaces
            .iter()
            .filter_map(|(name, history)| {
                let (current, end_ms) = history.back().copied()?;
                let (old, start_ms) = history.iter().copied().min_by_key(|(_, sample_ms)| {
                    current_ms
                        .saturating_sub(*sample_ms)
                        .abs_diff(target_window_ms)
                })?;
                let window_ms = end_ms.checked_sub(start_ms)?;
                if window_ms == 0
                    || window_ms.abs_diff(target_window_ms) > INTERFACE_WINDOW_SKEW_MS
                    || current.rx_bytes < old.rx_bytes
                    || current.tx_bytes < old.tx_bytes
                {
                    return None;
                }
                Some((
                    name.clone(),
                    InterfaceWindowRate {
                        rx_bps: (current.rx_bytes - old.rx_bytes).saturating_mul(8_000) / window_ms,
                        tx_bps: (current.tx_bytes - old.tx_bytes).saturating_mul(8_000) / window_ms,
                        sample_ms: end_ms,
                        window_ms,
                    },
                ))
            })
            .collect()
    }
}

fn complete_raw_rate(raw: &AccessEdgeSnapshot) -> Option<u64> {
    let mut total = 0u64;
    let mut directions = 0usize;
    for client in &raw.clients {
        if !client.is_authoritative() {
            return None;
        }
        for observation in [&client.tx, &client.rx] {
            total = total.saturating_add(observation.segment?.bps()?);
            directions = directions.saturating_add(1);
        }
    }
    (directions != 0).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        interfaces::InterfaceCounterSnapshot,
        model::{Interface, InterfaceStatus},
        platform::access_edge::{
            Attachment, AttachmentKind, AttachmentPoint, AttachmentTrust, ByteDomain, Coverage,
            EdgeDirectionObservation, RateSource, TrafficScope,
        },
    };

    const TEST_WINDOW_MS: u64 = 10_000;
    const TEST_HIGH_WATERMARK_BPS: u64 = 8_000_000;

    fn observe(
        window: &mut NssLowRateWindow,
        snapshot: &AccessEdgeSnapshot,
        counters: &InterfaceCounterSnapshot,
        sample_ms: u64,
    ) -> AccessEdgeSnapshot {
        window.observe(
            snapshot,
            counters,
            sample_ms,
            TEST_WINDOW_MS,
            TEST_HIGH_WATERMARK_BPS,
        )
    }

    fn duplex_client(
        start_ms: u64,
        end_ms: u64,
        up_bytes: u64,
        down_bytes: u64,
    ) -> EdgeClientObservation {
        let direction = |direction, bytes| EdgeDirectionObservation {
            segment: Some(CounterSegment {
                epoch_id: end_ms / 1_000,
                start_ms,
                end_ms,
                read_begin_ms: end_ms.saturating_sub(3),
                read_end_ms: end_ms,
                source: RateSource::EdgeWifi,
                direction,
                bytes,
                packets: 10,
                attachment_generation: 1,
                byte_domain: ByteDomain::StationData,
                uncertainty_ms: 3,
            }),
            coverage: Coverage::Full,
            scope: TrafficScope::Unicast,
            failure: None,
            reason_codes: Vec::new(),
        };
        EdgeClientObservation {
            attachment: Attachment {
                key: AttachmentKey {
                    mac: [2, 0, 0, 0, 0, 1],
                    bridge_ifindex: Some(7),
                    vlan_id: None,
                },
                point: AttachmentPoint {
                    kind: AttachmentKind::Wifi,
                    ifindex: 10,
                    ifname: "phy0-ap0".into(),
                    bridge_ifindex: Some(7),
                    vlan_id: None,
                },
                trust: AttachmentTrust::AssociatedStation,
                generation: 1,
                source_generation: 1,
                stable_observations: 2,
                ambiguous: false,
            },
            tx: direction(Direction::Tx, up_bytes),
            rx: direction(Direction::Rx, down_bytes),
        }
    }

    fn client(start_ms: u64, end_ms: u64, down_bytes: u64) -> EdgeClientObservation {
        duplex_client(start_ms, end_ms, 100, down_bytes)
    }

    fn snapshot(start_ms: u64, end_ms: u64, down_bytes: u64) -> AccessEdgeSnapshot {
        AccessEdgeSnapshot {
            sample_ms: end_ms,
            clients: vec![client(start_ms, end_ms, down_bytes)],
            topology_complete: true,
            ..AccessEdgeSnapshot::default()
        }
    }

    fn counters(wan_rx: u64) -> InterfaceCounterSnapshot {
        duplex_counters(wan_rx, 0)
    }

    fn duplex_counters(wan_rx: u64, wan_tx: u64) -> InterfaceCounterSnapshot {
        InterfaceCounterSnapshot::from_test_counters(BTreeMap::from([(
            "wan".into(),
            InterfaceCounters {
                rx_bytes: wan_rx,
                tx_bytes: wan_tx,
                ..InterfaceCounters::default()
            },
        )]))
    }

    fn interfaces() -> InterfacesResponse {
        InterfacesResponse {
            interfaces: vec![Interface {
                name: "wan".into(),
                role: InterfaceRole::Observe,
                status: InterfaceStatus::Available,
                rx_bytes: Some(0),
                tx_bytes: Some(0),
                rx_bps: Some(0),
                tx_bps: Some(0),
                delta_ms: Some(1_000),
                sample_ms: Some(0),
                source: Some("raw".into()),
                coverage: Some("raw".into()),
                evidence: None,
            }],
            monotonic_ms: Some(0),
            note: None,
            evidence: None,
        }
    }

    #[test]
    fn low_rate_uses_one_contiguous_raw_window_for_edge_and_wan() {
        let mut window = NssLowRateWindow::default();
        observe(
            &mut window,
            &AccessEdgeSnapshot::default(),
            &duplex_counters(0, 0),
            0,
        );
        let first = observe(
            &mut window,
            &AccessEdgeSnapshot {
                sample_ms: 1_000,
                clients: vec![duplex_client(0, 1_000, 25_000, 50_000)],
                topology_complete: true,
                ..AccessEdgeSnapshot::default()
            },
            &duplex_counters(50_000, 25_000),
            1_000,
        );
        assert_eq!(
            first.clients[0].rx.segment.unwrap().window_ms(),
            Some(1_000)
        );

        let published = observe(
            &mut window,
            &AccessEdgeSnapshot {
                sample_ms: 2_000,
                clients: vec![duplex_client(1_000, 2_000, 75_000, 150_000)],
                topology_complete: true,
                ..AccessEdgeSnapshot::default()
            },
            &duplex_counters(200_000, 100_000),
            2_000,
        );
        let edge = published.clients[0].rx.segment.unwrap();
        let edge_up = published.clients[0].tx.segment.unwrap();
        assert_eq!(edge.window_ms(), Some(2_000));
        assert_eq!(edge.bytes, 200_000);
        assert_eq!(edge_up.window_ms(), Some(2_000));
        assert_eq!(edge_up.bytes, 100_000);

        let mut response = interfaces();
        window.apply_observe_rates(&mut response);
        let wan = &response.interfaces[0];
        assert_eq!(wan.rx_bps, Some(800_000));
        assert_eq!(wan.tx_bps, Some(400_000));
        assert_eq!(wan.delta_ms, Some(2_000));
        assert_eq!(edge.bps(), Some(800_000));
        assert_eq!(edge_up.bps(), Some(400_000));
    }

    #[test]
    fn interface_window_keeps_outer_baseline_across_collection_clock_drift() {
        let mut window = NssLowRateWindow::default();
        window.observe(
            &AccessEdgeSnapshot::default(),
            &duplex_counters(0, 0),
            0,
            18_000,
            TEST_HIGH_WATERMARK_BPS,
        );

        for second in 1..=18 {
            let edge_end_ms = second * 1_000;
            let interface_sample_ms = second * 1_001;
            window.observe(
                &AccessEdgeSnapshot {
                    sample_ms: edge_end_ms,
                    clients: vec![duplex_client(
                        edge_end_ms - 1_000,
                        edge_end_ms,
                        25_000,
                        50_000,
                    )],
                    topology_complete: true,
                    ..AccessEdgeSnapshot::default()
                },
                &duplex_counters(second * 50_000, second * 25_000),
                interface_sample_ms,
                18_000,
                TEST_HIGH_WATERMARK_BPS,
            );
        }

        let mut response = interfaces();
        window.apply_observe_rates(&mut response);
        let wan = &response.interfaces[0];
        assert_eq!(wan.source.as_deref(), Some(RATE_SOURCE));
        assert_eq!(
            wan.coverage.as_deref(),
            Some("aligned_low_rate_observe_window")
        );
        assert_eq!(wan.delta_ms, Some(18_018));
        assert_eq!(wan.rx_bps, Some(399_600));
        assert_eq!(wan.tx_bps, Some(199_800));
    }

    #[test]
    fn high_rate_keeps_the_one_second_window_and_resets_low_history() {
        let mut window = NssLowRateWindow::default();
        observe(
            &mut window,
            &snapshot(0, 1_000, 50_000),
            &counters(50_000),
            1_000,
        );
        let high = observe(
            &mut window,
            &snapshot(1_000, 2_000, 2_000_000),
            &counters(2_050_000),
            2_000,
        );
        assert_eq!(high.clients[0].rx.segment.unwrap().window_ms(), Some(1_000));

        let falling = observe(
            &mut window,
            &snapshot(2_000, 3_000, 50_000),
            &counters(2_100_000),
            3_000,
        );
        assert_eq!(
            falling.clients[0].rx.segment.unwrap().window_ms(),
            Some(1_000)
        );
    }

    #[test]
    fn a_generation_change_cannot_merge_old_edge_bytes() {
        let mut window = NssLowRateWindow::default();
        observe(
            &mut window,
            &snapshot(0, 1_000, 50_000),
            &counters(50_000),
            1_000,
        );
        let mut changed = snapshot(1_000, 2_000, 50_000);
        changed.clients[0].attachment.generation = 2;
        changed.clients[0]
            .tx
            .segment
            .as_mut()
            .unwrap()
            .attachment_generation = 2;
        changed.clients[0]
            .rx
            .segment
            .as_mut()
            .unwrap()
            .attachment_generation = 2;

        let published = observe(&mut window, &changed, &counters(100_000), 2_000);
        assert_eq!(
            published.clients[0].rx.segment.unwrap().window_ms(),
            Some(1_000)
        );
    }

    #[test]
    fn changing_low_rate_config_discards_the_previous_window() {
        let mut window = NssLowRateWindow::default();
        observe(
            &mut window,
            &snapshot(0, 1_000, 50_000),
            &counters(50_000),
            1_000,
        );
        let published = window.observe(
            &snapshot(1_000, 2_000, 50_000),
            &counters(100_000),
            2_000,
            TEST_WINDOW_MS * 2,
            TEST_HIGH_WATERMARK_BPS,
        );
        assert_eq!(
            published.clients[0].rx.segment.unwrap().window_ms(),
            Some(1_000)
        );
    }
}
