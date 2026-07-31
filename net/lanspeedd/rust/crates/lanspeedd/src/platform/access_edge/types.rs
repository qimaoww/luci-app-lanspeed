#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ByteDomain {
    L2NoFcs,
    L2WithFcs,
    StationData,
    EcmData,
}

impl ByteDomain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::L2NoFcs => "l2_no_fcs",
            Self::L2WithFcs => "l2_with_fcs",
            Self::StationData => "station_data",
            Self::EcmData => "ecm_data",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Coverage {
    Full,
    Partial,
    Degraded,
    Unavailable,
}

impl Coverage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TrafficScope {
    AllFrames,
    Unicast,
    RoutedObserved,
    LowerBound,
    None,
}

impl TrafficScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllFrames => "all_frames",
            Self::Unicast => "unicast",
            Self::RoutedObserved => "routed_observed",
            Self::LowerBound => "lower_bound",
            Self::None => "none",
        }
    }
}

/// Direction from the client's point of view.
///
/// `Tx` is client upload (port/station RX); `Rx` is client download
/// (port/station TX).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Direction {
    Tx,
    Rx,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tx => "tx",
            Self::Rx => "rx",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RateSource {
    EdgeWifi,
    EdgePort,
    EcmBpfFallback,
    EcmNssLowerBound,
    TcBpfLowerBound,
}

impl RateSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdgeWifi => "edge_wifi",
            Self::EdgePort => "edge_port",
            Self::EcmBpfFallback => "ecm_bpf_fallback",
            Self::EcmNssLowerBound => "ecm_nss_lower_bound",
            Self::TcBpfLowerBound => "tc_bpf_lower_bound",
        }
    }

    pub(crate) const fn priority(self) -> u8 {
        match self {
            Self::EdgeWifi => 0,
            Self::EdgePort => 1,
            Self::EcmBpfFallback => 2,
            Self::EcmNssLowerBound => 3,
            Self::TcBpfLowerBound => 4,
        }
    }
}

/// A delta from one source over one counter window.
///
/// Segments are never combined merely because their wall-clock timestamps are
/// close. Callers must additionally prove compatible epochs, byte domains,
/// generations and source-disjoint semantics before adding them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterSegment {
    pub epoch_id: u64,
    pub start_ms: u64,
    pub end_ms: u64,
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

impl CounterSegment {
    pub const fn window_ms(self) -> Option<u64> {
        self.end_ms.checked_sub(self.start_ms)
    }

    pub const fn is_well_formed(self) -> bool {
        self.end_ms > self.start_ms && self.read_end_ms >= self.read_begin_ms
    }

    pub fn bps(self) -> Option<u64> {
        if !self.is_well_formed() {
            return None;
        }
        let window_ms = self.window_ms()?;
        let scaled = u128::from(self.bytes).saturating_mul(8_000) / u128::from(window_ms);
        Some(u64::try_from(scaled).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_segment_uses_its_actual_window() {
        let segment = CounterSegment {
            epoch_id: 1,
            start_ms: 1_000,
            end_ms: 2_250,
            read_begin_ms: 2_240,
            read_end_ms: 2_250,
            source: RateSource::EdgePort,
            direction: Direction::Tx,
            bytes: 125_000,
            packets: 100,
            attachment_generation: 7,
            byte_domain: ByteDomain::L2NoFcs,
            uncertainty_ms: 10,
        };

        assert_eq!(segment.window_ms(), Some(1_250));
        assert_eq!(segment.bps(), Some(800_000));
    }

    #[test]
    fn counter_segment_rejects_zero_or_reversed_windows() {
        let mut segment = CounterSegment {
            epoch_id: 1,
            start_ms: 1_000,
            end_ms: 1_000,
            read_begin_ms: 1_000,
            read_end_ms: 1_000,
            source: RateSource::EdgePort,
            direction: Direction::Rx,
            bytes: 1,
            packets: 1,
            attachment_generation: 1,
            byte_domain: ByteDomain::L2NoFcs,
            uncertainty_ms: 0,
        };
        assert_eq!(segment.bps(), None);
        segment.end_ms = 999;
        assert_eq!(segment.bps(), None);
    }
}
