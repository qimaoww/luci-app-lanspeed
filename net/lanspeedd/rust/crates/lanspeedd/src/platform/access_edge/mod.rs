//! Read-only access-edge accounting primitives.
//!
//! This module deliberately contains no production scheduler or policy wiring.
//! It provides the typed counter, topology and source-selection building blocks
//! used by that integration, without requiring libnl, `iw`, SSDK or a custom
//! kernel module.

pub mod classification;
pub mod fdb;
pub mod mux;
pub mod nl80211;
pub mod rate;
pub mod runtime;
pub mod topology;
pub mod types;

pub use classification::{
    normalize_l2_with_fcs, ClassificationBook, ClassificationEpoch, ClassificationResult,
    DirectionClassification, DirectionEpoch, ObservedDelta, CLASSIFIER_READ_END_SKEW_MS,
    COMPARISON_EPOCH_COUNT,
};
pub use fdb::{
    read_bridge_fdb, BridgeFdbEventMonitor, BridgeFdbProvider, BridgeFdbSnapshot, FdbEntry,
    FdbParseError, FdbSource, SystemBridgeFdbProvider,
};
pub use mux::{DirectionRateMux, MuxFailure, MuxResult, MuxState, RateCandidate, SelectedRate};
pub use nl80211::{
    Nl80211ParseError, ParsedInterfaceMessages, ParsedStationMessages, RawStationCounter,
    StationByteCounterWidth, StationCounterSample, StationCounterSnapshot,
    SystemNl80211StationProvider, WifiStationCounterProvider, WirelessInterface, NL80211_IFTYPE_AP,
    NL80211_IFTYPE_MESH_POINT, NL80211_IFTYPE_WDS,
};
pub use rate::{
    CounterRateBook, CounterResetReason, CounterUpdate, CumulativeCounterSample, LinkCounters,
    PortCounterProvider, PortCounterSample, PortCounterSnapshot,
};
pub use runtime::{
    AccessEdgeCheckpoint, AccessEdgeRuntime, AccessEdgeSnapshot, EdgeClientObservation,
    EdgeDirectionObservation, EdgeIdentityHint, FDB_FULL_SYNC_MS,
};
pub use topology::{
    observations_from_fdb, observations_from_stations, Attachment, AttachmentKey, AttachmentKind,
    AttachmentObservation, AttachmentPoint, AttachmentTrust, TopologyTable, TopologyUpdate,
};
pub use types::{ByteDomain, CounterSegment, Coverage, Direction, RateSource, TrafficScope};
