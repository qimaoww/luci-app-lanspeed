use std::{collections::BTreeMap, collections::BTreeSet, io};

use super::types::{ByteDomain, CounterSegment, Direction, RateSource};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl LinkCounters {
    /// Select counters using client-facing directions: client TX is link RX.
    pub const fn client_direction(self, direction: Direction) -> (u64, u64) {
        match direction {
            Direction::Tx => (self.rx_bytes, self.rx_packets),
            Direction::Rx => (self.tx_bytes, self.tx_packets),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortCounterSample {
    pub ifindex: u32,
    pub ifname: String,
    pub counters: LinkCounters,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PortCounterSnapshot {
    pub samples: Vec<PortCounterSample>,
    pub read_begin_ms: u64,
    pub read_end_ms: u64,
    pub complete: bool,
}

/// Batch input boundary for the existing single-pass netdev snapshot.
pub trait PortCounterProvider {
    fn read_ports(&mut self, ifnames: &BTreeSet<String>) -> io::Result<PortCounterSnapshot>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CumulativeCounterSample {
    pub epoch_id: u64,
    pub sample_ms: u64,
    pub read_begin_ms: u64,
    pub read_end_ms: u64,
    pub source: RateSource,
    pub direction: Direction,
    pub bytes: u64,
    pub packets: u64,
    pub attachment_generation: u64,
    pub byte_domain: ByteDomain,
    pub uncertainty_ms: u64,
}

impl CumulativeCounterSample {
    #[allow(clippy::too_many_arguments)]
    pub fn from_link(
        epoch_id: u64,
        sample_ms: u64,
        read_begin_ms: u64,
        read_end_ms: u64,
        source: RateSource,
        direction: Direction,
        counters: LinkCounters,
        attachment_generation: u64,
        byte_domain: ByteDomain,
        uncertainty_ms: u64,
    ) -> Self {
        let (bytes, packets) = counters.client_direction(direction);
        Self {
            epoch_id,
            sample_ms,
            read_begin_ms,
            read_end_ms,
            source,
            direction,
            bytes,
            packets,
            attachment_generation,
            byte_domain,
            uncertainty_ms,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterResetReason {
    CounterDecreased,
    GenerationChanged,
    SemanticsChanged,
    TimeDidNotAdvance,
    ReadIntervalInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterUpdate {
    Warmup,
    Segment(CounterSegment),
    Reset(CounterResetReason),
}

/// Per-source cumulative baselines. A key must include client, direction and
/// source; callers must never reuse one key across different counter owners.
#[derive(Clone, Debug, Default)]
pub struct CounterRateBook<K> {
    previous: BTreeMap<K, CumulativeCounterSample>,
}

impl<K> CounterRateBook<K>
where
    K: Clone + Ord,
{
    pub fn new() -> Self {
        Self {
            previous: BTreeMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.previous.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.previous.is_empty()
    }

    pub fn remove(&mut self, key: &K) {
        self.previous.remove(key);
    }

    pub fn update(&mut self, key: K, current: CumulativeCounterSample) -> CounterUpdate {
        if current.read_end_ms < current.read_begin_ms {
            self.previous.remove(&key);
            return CounterUpdate::Reset(CounterResetReason::ReadIntervalInvalid);
        }
        let previous = self.previous.insert(key, current);
        let Some(previous) = previous else {
            return CounterUpdate::Warmup;
        };
        if current.attachment_generation != previous.attachment_generation {
            return CounterUpdate::Reset(CounterResetReason::GenerationChanged);
        }
        if current.source != previous.source
            || current.direction != previous.direction
            || current.byte_domain != previous.byte_domain
        {
            return CounterUpdate::Reset(CounterResetReason::SemanticsChanged);
        }
        if current.sample_ms <= previous.sample_ms {
            return CounterUpdate::Reset(CounterResetReason::TimeDidNotAdvance);
        }
        if current.bytes < previous.bytes || current.packets < previous.packets {
            return CounterUpdate::Reset(CounterResetReason::CounterDecreased);
        }

        CounterUpdate::Segment(CounterSegment {
            epoch_id: current.epoch_id,
            start_ms: previous.sample_ms,
            end_ms: current.sample_ms,
            read_begin_ms: current.read_begin_ms,
            read_end_ms: current.read_end_ms,
            source: current.source,
            direction: current.direction,
            bytes: current.bytes - previous.bytes,
            packets: current.packets - previous.packets,
            attachment_generation: current.attachment_generation,
            byte_domain: current.byte_domain,
            uncertainty_ms: current.uncertainty_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        bytes: u64,
        packets: u64,
        sample_ms: u64,
        generation: u64,
    ) -> CumulativeCounterSample {
        CumulativeCounterSample {
            epoch_id: sample_ms / 1_000,
            sample_ms,
            read_begin_ms: sample_ms - 5,
            read_end_ms: sample_ms,
            source: RateSource::EdgePort,
            direction: Direction::Tx,
            bytes,
            packets,
            attachment_generation: generation,
            byte_domain: ByteDomain::L2NoFcs,
            uncertainty_ms: 5,
        }
    }

    #[test]
    fn link_direction_is_from_the_clients_point_of_view() {
        let counters = LinkCounters {
            rx_bytes: 10,
            tx_bytes: 20,
            rx_packets: 1,
            tx_packets: 2,
        };
        assert_eq!(counters.client_direction(Direction::Tx), (10, 1));
        assert_eq!(counters.client_direction(Direction::Rx), (20, 2));
    }

    #[test]
    fn rate_book_warms_then_emits_actual_delta_window() {
        let mut book = CounterRateBook::new();
        assert_eq!(
            book.update("client", sample(100, 1, 1_000, 4)),
            CounterUpdate::Warmup
        );
        let CounterUpdate::Segment(segment) = book.update("client", sample(1_100, 11, 2_250, 4))
        else {
            panic!("expected a counter segment");
        };
        assert_eq!(segment.bytes, 1_000);
        assert_eq!(segment.packets, 10);
        assert_eq!(segment.window_ms(), Some(1_250));
        assert_eq!(segment.bps(), Some(6_400));
    }

    #[test]
    fn generation_change_and_counter_decrease_reset_the_baseline() {
        let mut book = CounterRateBook::new();
        assert_eq!(
            book.update("client", sample(1_000, 10, 1_000, 1)),
            CounterUpdate::Warmup
        );
        assert_eq!(
            book.update("client", sample(2_000, 20, 2_000, 2)),
            CounterUpdate::Reset(CounterResetReason::GenerationChanged)
        );
        assert_eq!(
            book.update("client", sample(1_500, 15, 3_000, 2)),
            CounterUpdate::Reset(CounterResetReason::CounterDecreased)
        );
        let CounterUpdate::Segment(segment) = book.update("client", sample(2_500, 25, 4_000, 2))
        else {
            panic!("reset sample must become the next baseline");
        };
        assert_eq!(segment.bytes, 1_000);
    }

    #[test]
    fn changing_source_never_subtracts_across_counter_owners() {
        let mut book = CounterRateBook::new();
        assert_eq!(
            book.update("client", sample(1_000, 10, 1_000, 1)),
            CounterUpdate::Warmup
        );
        let mut different_source = sample(2_000, 20, 2_000, 1);
        different_source.source = RateSource::EcmBpfFallback;
        assert_eq!(
            book.update("client", different_source),
            CounterUpdate::Reset(CounterResetReason::SemanticsChanged)
        );
    }
}
