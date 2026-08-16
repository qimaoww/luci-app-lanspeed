//! EvidenceLease and E-authority rules for the production NSS RateMux.

use std::collections::{BTreeMap, BTreeSet};

use lanspeed_common::EcmLayout;
use serde_json::{json, Value};

use crate::{
    model::ClassificationState,
    platform::access_edge::{
        AttachmentKind, AttachmentTrust, ByteDomain, ClassificationResult, Coverage, Direction,
        EdgeClientObservation, MuxFailure, TrafficScope,
    },
};

pub(crate) const EVIDENCE_LEASE_LIFETIME_NS: u64 = 10_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EdgeKind {
    Wifi,
    Port,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EdgeObservation {
    pub kind: EdgeKind,
    pub unique: bool,
    pub sample_available: bool,
    pub coverage: Coverage,
    pub scope: TrafficScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EUsability {
    Authority,
    TransientEUnavailable,
    StructuralEUnavailable,
}

pub(crate) fn e_usability(observation: EdgeObservation) -> EUsability {
    let structurally_owned = observation.unique
        && match observation.kind {
            EdgeKind::Wifi => observation.scope == TrafficScope::Unicast,
            EdgeKind::Port => observation.scope == TrafficScope::AllFrames,
        };
    if !structurally_owned {
        return EUsability::StructuralEUnavailable;
    }
    if !observation.sample_available
        || matches!(
            observation.coverage,
            Coverage::Unavailable | Coverage::Degraded
        )
    {
        return EUsability::TransientEUnavailable;
    }
    let authority = match observation.kind {
        EdgeKind::Wifi => observation.coverage == Coverage::Full,
        EdgeKind::Port => {
            matches!(observation.coverage, Coverage::Full | Coverage::Partial)
        }
    };
    if authority {
        return EUsability::Authority;
    }
    EUsability::StructuralEUnavailable
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LeaseDirectionObservation {
    pub e: EdgeObservation,
    pub classification: ClassificationState,
    pub counter_reset: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LeaseClientObservation {
    pub client_identity: String,
    pub attachment_generation: u64,
    pub byte_domain: ByteDomain,
    pub proof_end_ms: Option<u64>,
    pub tx: LeaseDirectionObservation,
    pub rx: LeaseDirectionObservation,
}

impl LeaseClientObservation {
    pub(crate) fn from_edge(
        client_identity: &str,
        edge: &EdgeClientObservation,
        classification: Option<&ClassificationResult>,
        topology_complete: bool,
    ) -> Self {
        let kind = match edge.attachment.point.kind {
            AttachmentKind::Wifi => EdgeKind::Wifi,
            AttachmentKind::Ethernet => EdgeKind::Port,
        };
        let unique = topology_complete
            && !edge.attachment.ambiguous
            && matches!(
                (edge.attachment.point.kind, edge.attachment.trust),
                (AttachmentKind::Wifi, AttachmentTrust::AssociatedStation)
                    | (AttachmentKind::Ethernet, AttachmentTrust::ObservedExclusive)
            );
        let expected_scope = match kind {
            EdgeKind::Wifi => TrafficScope::Unicast,
            EdgeKind::Port => TrafficScope::AllFrames,
        };
        let direction = |direction: Direction| {
            let edge_direction = match direction {
                Direction::Tx => &edge.tx,
                Direction::Rx => &edge.rx,
            };
            LeaseDirectionObservation {
                e: EdgeObservation {
                    kind,
                    unique,
                    sample_available: edge_direction.segment.is_some(),
                    coverage: edge_direction.coverage,
                    // Scope is part of the attachment contract. A temporarily
                    // missing sample must not turn a proved unique edge into a
                    // structurally ambiguous edge.
                    scope: expected_scope,
                },
                classification: classification.map_or(ClassificationState::Unavailable, |result| {
                    match direction {
                        Direction::Tx => result.tx_state,
                        Direction::Rx => result.rx_state,
                    }
                }),
                counter_reset: edge_direction.failure == Some(MuxFailure::CounterReset),
            }
        };
        Self {
            client_identity: client_identity.to_owned(),
            attachment_generation: edge.attachment.generation,
            byte_domain: match kind {
                EdgeKind::Wifi => ByteDomain::StationData,
                EdgeKind::Port => ByteDomain::L2WithFcs,
            },
            proof_end_ms: classification.and_then(|result| result.window_end_ms),
            tx: direction(Direction::Tx),
            rx: direction(Direction::Rx),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LeaseSourceObservation {
    pub nss_bpf_object_loaded: bool,
    pub nss_bpf_attached: bool,
    pub nss_map_read_attempted: bool,
    pub nss_map_read_ok: bool,
    pub nss_map_truncated: bool,
    pub tc_bpf_object_loaded: bool,
    pub tc_bpf_attached: bool,
    pub tc_expected_hooks: usize,
    pub tc_attached_hooks: usize,
    pub tc_map_read_attempted: bool,
    pub tc_map_read_ok: bool,
    pub tc_map_truncated: bool,
    pub tc_self_heal_recoveries: u64,
    pub layout: Option<EcmLayout>,
    pub fast_n_reset_generation: Option<u32>,
    pub fast_s_reset_generation: Option<u32>,
    pub fast_integrity_failure: bool,
    pub fast_reads_ready: bool,
    pub proof_cycle_ready: bool,
}

impl LeaseSourceObservation {
    fn map_loss(self) -> bool {
        self.nss_map_truncated
            || self.tc_map_truncated
            || (self.nss_map_read_attempted && !self.nss_map_read_ok)
            || (self.tc_map_read_attempted && !self.tc_map_read_ok)
    }

    fn ready(self) -> bool {
        self.nss_bpf_object_loaded
            && self.nss_bpf_attached
            && self.nss_map_read_attempted
            && self.nss_map_read_ok
            && self.tc_bpf_object_loaded
            && self.tc_bpf_attached
            && self.tc_expected_hooks != 0
            && self.tc_expected_hooks == self.tc_attached_hooks
            && self.tc_map_read_attempted
            && self.tc_map_read_ok
            && self.layout.is_some_and(|layout| layout.ready == 1)
            && self.fast_n_reset_generation.is_some()
            && self.fast_s_reset_generation.is_some()
            && self.fast_reads_ready
            && !self.fast_integrity_failure
            && !self.map_loss()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LeaseGenerations {
    pub attachment_generation: u64,
    pub nss_bpf_load_generation: u64,
    pub nss_map_generation: u64,
    pub tc_attach_generation: u64,
    pub layout_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceLease {
    pub client_identity: String,
    pub direction: Direction,
    pub generations: LeaseGenerations,
    pub byte_domain: ByteDomain,
    pub n_s_disjoint: bool,
    pub issued_at_ns: u64,
    pub valid_until_ns: u64,
}

impl EvidenceLease {
    pub(crate) fn is_valid(
        &self,
        now_ns: u64,
        generations: LeaseGenerations,
        byte_domain: ByteDomain,
        n_s_disjoint: bool,
    ) -> bool {
        now_ns >= self.issued_at_ns
            && now_ns <= self.valid_until_ns
            && self.generations == generations
            && self.byte_domain == byte_domain
            && self.n_s_disjoint
            && n_s_disjoint
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseInvalidation {
    ClientIdentity,
    AttachmentGeneration,
    NssBpfLoadGeneration,
    NssMapGeneration,
    TcAttachGeneration,
    LayoutGeneration,
    ByteDomain,
    CounterReset,
    MapLoss,
    IntegrityFailure,
    NsOverlap,
}

pub(crate) fn lease_invalidation(
    lease: &EvidenceLease,
    generations: LeaseGenerations,
    byte_domain: ByteDomain,
    n_s_disjoint: bool,
    counter_reset: bool,
    map_loss: bool,
    integrity_failure: bool,
) -> Option<LeaseInvalidation> {
    if lease.generations.attachment_generation != generations.attachment_generation {
        return Some(LeaseInvalidation::AttachmentGeneration);
    }
    if lease.generations.nss_bpf_load_generation != generations.nss_bpf_load_generation {
        return Some(LeaseInvalidation::NssBpfLoadGeneration);
    }
    if lease.generations.nss_map_generation != generations.nss_map_generation {
        return Some(LeaseInvalidation::NssMapGeneration);
    }
    if lease.generations.tc_attach_generation != generations.tc_attach_generation {
        return Some(LeaseInvalidation::TcAttachGeneration);
    }
    if lease.generations.layout_generation != generations.layout_generation {
        return Some(LeaseInvalidation::LayoutGeneration);
    }
    if lease.byte_domain != byte_domain {
        return Some(LeaseInvalidation::ByteDomain);
    }
    if counter_reset {
        return Some(LeaseInvalidation::CounterReset);
    }
    if map_loss {
        return Some(LeaseInvalidation::MapLoss);
    }
    if integrity_failure {
        return Some(LeaseInvalidation::IntegrityFailure);
    }
    if !lease.n_s_disjoint || !n_s_disjoint {
        return Some(LeaseInvalidation::NsOverlap);
    }
    None
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct EvidenceLeaseBook {
    leases: BTreeMap<(String, Direction), EvidenceLease>,
    issued: u64,
    invalidated: u64,
    expired: u64,
    last_invalidation: Option<LeaseInvalidation>,
}

impl EvidenceLeaseBook {
    pub(crate) fn issue(
        &mut self,
        client_identity: &str,
        direction: Direction,
        generations: LeaseGenerations,
        byte_domain: ByteDomain,
        n_s_disjoint: bool,
        now_ns: u64,
    ) -> bool {
        let key = (client_identity.to_owned(), direction);
        if !n_s_disjoint {
            self.leases.remove(&key);
            return false;
        }
        self.leases.insert(
            key,
            EvidenceLease {
                client_identity: client_identity.to_owned(),
                direction,
                generations,
                byte_domain,
                n_s_disjoint,
                issued_at_ns: now_ns,
                valid_until_ns: now_ns.saturating_add(EVIDENCE_LEASE_LIFETIME_NS),
            },
        );
        self.issued = self.issued.saturating_add(1);
        true
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn permits(
        &mut self,
        client_identity: &str,
        direction: Direction,
        now_ns: u64,
        generations: LeaseGenerations,
        byte_domain: ByteDomain,
        n_s_disjoint: bool,
        counter_reset: bool,
        map_loss: bool,
        integrity_failure: bool,
    ) -> bool {
        let key = (client_identity.to_owned(), direction);
        let Some(lease) = self.leases.get(&key) else {
            return false;
        };
        if let Some(reason) = lease_invalidation(
            lease,
            generations,
            byte_domain,
            n_s_disjoint,
            counter_reset,
            map_loss,
            integrity_failure,
        ) {
            self.leases.remove(&key);
            self.invalidated = self.invalidated.saturating_add(1);
            self.last_invalidation = Some(reason);
            return false;
        }
        if !lease.is_valid(now_ns, generations, byte_domain, n_s_disjoint) {
            self.leases.remove(&key);
            self.expired = self.expired.saturating_add(1);
            return false;
        }
        true
    }

    pub(crate) fn remove(&mut self, client_identity: &str, direction: Direction) {
        self.leases.remove(&(client_identity.to_owned(), direction));
    }

    pub(crate) fn retain_identities(&mut self, identities: &BTreeSet<String>) {
        let before = self.leases.len();
        self.leases
            .retain(|(identity, _), _| identities.contains(identity));
        let removed = before.saturating_sub(self.leases.len());
        if removed != 0 {
            self.invalidated = self.invalidated.saturating_add(removed as u64);
            self.last_invalidation = Some(LeaseInvalidation::ClientIdentity);
        }
    }

    pub(crate) fn invalidate_all(&mut self, reason: LeaseInvalidation) {
        let invalidated = self.leases.len();
        if invalidated == 0 {
            return;
        }
        self.leases.clear();
        self.invalidated = self.invalidated.saturating_add(invalidated as u64);
        self.last_invalidation = Some(reason);
    }

    pub(crate) fn evidence(&self) -> Value {
        json!({
            "active": self.leases.len(),
            "issued": self.issued,
            "invalidated": self.invalidated,
            "expired": self.expired,
            "last_invalidation": self.last_invalidation.map(LeaseInvalidation::as_str),
        })
    }
}

impl LeaseInvalidation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ClientIdentity => "client_identity",
            Self::AttachmentGeneration => "attachment_generation",
            Self::NssBpfLoadGeneration => "nss_bpf_load_generation",
            Self::NssMapGeneration => "nss_map_generation",
            Self::TcAttachGeneration => "tc_attach_generation",
            Self::LayoutGeneration => "layout_generation",
            Self::ByteDomain => "byte_domain",
            Self::CounterReset => "counter_reset",
            Self::MapLoss => "map_loss",
            Self::IntegrityFailure => "integrity_failure",
            Self::NsOverlap => "ns_overlap",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NssBpfSignature {
    object_loaded: bool,
    attached: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TcAttachSignature {
    object_loaded: bool,
    attached: bool,
    expected_hooks: usize,
    attached_hooks: usize,
    self_heal_recoveries: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct LeaseGenerationTracker {
    initialized: bool,
    nss_bpf: NssBpfSignature,
    tc_attach: TcAttachSignature,
    layout: Option<EcmLayout>,
    fast_n_reset_generation: Option<u32>,
    fast_s_reset_generation: Option<u32>,
    generations: LeaseGenerations,
}

impl LeaseGenerationTracker {
    fn observe(&mut self, source: LeaseSourceObservation) -> Option<LeaseInvalidation> {
        let nss_bpf = NssBpfSignature {
            object_loaded: source.nss_bpf_object_loaded,
            attached: source.nss_bpf_attached,
        };
        let tc_attach = TcAttachSignature {
            object_loaded: source.tc_bpf_object_loaded,
            attached: source.tc_bpf_attached,
            expected_hooks: source.tc_expected_hooks,
            attached_hooks: source.tc_attached_hooks,
            self_heal_recoveries: source.tc_self_heal_recoveries,
        };
        if !self.initialized {
            self.initialized = true;
            self.nss_bpf = nss_bpf;
            self.tc_attach = tc_attach;
            self.layout = source.layout;
            self.fast_n_reset_generation = source.fast_n_reset_generation;
            self.fast_s_reset_generation = source.fast_s_reset_generation;
            self.generations = LeaseGenerations {
                attachment_generation: 0,
                nss_bpf_load_generation: 1,
                nss_map_generation: 1,
                tc_attach_generation: 1,
                layout_generation: 1,
            };
            return None;
        }

        let mut invalidation = None;
        if self.nss_bpf != nss_bpf {
            self.nss_bpf = nss_bpf;
            self.generations.nss_bpf_load_generation =
                self.generations.nss_bpf_load_generation.saturating_add(1);
            // The ECM map is owned by this BPF object. A load/attach identity
            // transition therefore changes both explicit generations.
            self.generations.nss_map_generation =
                self.generations.nss_map_generation.saturating_add(1);
            invalidation = Some(LeaseInvalidation::NssBpfLoadGeneration);
        }
        if self.tc_attach != tc_attach {
            self.tc_attach = tc_attach;
            self.generations.tc_attach_generation =
                self.generations.tc_attach_generation.saturating_add(1);
            invalidation.get_or_insert(LeaseInvalidation::TcAttachGeneration);
        }
        if self.layout != source.layout {
            self.layout = source.layout;
            self.generations.layout_generation =
                self.generations.layout_generation.saturating_add(1);
            invalidation.get_or_insert(LeaseInvalidation::LayoutGeneration);
        }
        let n_reset = update_known_generation(
            &mut self.fast_n_reset_generation,
            source.fast_n_reset_generation,
        );
        let s_reset = update_known_generation(
            &mut self.fast_s_reset_generation,
            source.fast_s_reset_generation,
        );
        if n_reset || s_reset {
            invalidation.get_or_insert(LeaseInvalidation::CounterReset);
        }
        invalidation
    }

    fn for_attachment(&self, attachment_generation: u64) -> LeaseGenerations {
        LeaseGenerations {
            attachment_generation,
            ..self.generations
        }
    }
}

fn update_known_generation(current: &mut Option<u32>, observed: Option<u32>) -> bool {
    let Some(observed) = observed else {
        return false;
    };
    let changed = current.is_some_and(|current| current != observed);
    *current = Some(observed);
    changed
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct EvidenceLeaseRuntime {
    generations: LeaseGenerationTracker,
    book: EvidenceLeaseBook,
    last_proof_end_ms: BTreeMap<(String, Direction), u64>,
    current_valid: BTreeSet<(String, Direction)>,
    source_ready: bool,
    fast_reads_ready: bool,
    proof_cycle_ready: bool,
    map_loss: bool,
    fast_integrity_failure: bool,
    e_authority_directions: usize,
    e_transient_directions: usize,
    e_structural_directions: usize,
}

impl EvidenceLeaseRuntime {
    pub(crate) fn reconcile(
        &mut self,
        now_ms: u64,
        source: LeaseSourceObservation,
        clients: &[LeaseClientObservation],
    ) {
        let generation_invalidation = self.generations.observe(source);
        self.source_ready = source.ready();
        self.fast_reads_ready = source.fast_reads_ready;
        self.proof_cycle_ready = source.proof_cycle_ready;
        self.map_loss = source.map_loss();
        self.fast_integrity_failure = source.fast_integrity_failure;
        self.current_valid.clear();
        self.e_authority_directions = 0;
        self.e_transient_directions = 0;
        self.e_structural_directions = 0;

        let identities = clients
            .iter()
            .map(|client| client.client_identity.clone())
            .collect::<BTreeSet<_>>();
        self.book.retain_identities(&identities);
        self.last_proof_end_ms
            .retain(|(identity, _), _| identities.contains(identity));

        if self.map_loss {
            self.book.invalidate_all(LeaseInvalidation::MapLoss);
        } else if source.fast_integrity_failure {
            self.book
                .invalidate_all(LeaseInvalidation::IntegrityFailure);
        } else if let Some(reason) = generation_invalidation {
            self.book.invalidate_all(reason);
        }

        let now_ns = now_ms.saturating_mul(1_000_000);
        for client in clients {
            for (direction, observation) in [(Direction::Tx, client.tx), (Direction::Rx, client.rx)]
            {
                let e = e_usability(observation.e);
                match e {
                    EUsability::Authority => {
                        self.e_authority_directions = self.e_authority_directions.saturating_add(1)
                    }
                    EUsability::TransientEUnavailable => {
                        self.e_transient_directions = self.e_transient_directions.saturating_add(1)
                    }
                    EUsability::StructuralEUnavailable => {
                        self.e_structural_directions =
                            self.e_structural_directions.saturating_add(1)
                    }
                }
                let generations = self
                    .generations
                    .for_attachment(client.attachment_generation);
                let classification_integrity_failure = matches!(
                    observation.classification,
                    ClassificationState::DomainMismatch
                        | ClassificationState::WindowMismatch
                        | ClassificationState::CounterSkew
                );
                let structural_failure = e == EUsability::StructuralEUnavailable;
                let integrity_failure = classification_integrity_failure || structural_failure;
                let counter_reset = observation.counter_reset;
                let valid = self.book.permits(
                    &client.client_identity,
                    direction,
                    now_ns,
                    generations,
                    client.byte_domain,
                    true,
                    counter_reset,
                    self.map_loss,
                    integrity_failure || source.fast_integrity_failure,
                );
                if valid {
                    self.current_valid
                        .insert((client.client_identity.clone(), direction));
                }

                let Some(proof_end_ms) = client.proof_end_ms else {
                    continue;
                };
                let key = (client.client_identity.clone(), direction);
                let proof_is_new = self.last_proof_end_ms.get(&key) != Some(&proof_end_ms);
                let proof_ns = proof_end_ms.saturating_mul(1_000_000);
                let proof_current = proof_ns <= now_ns
                    && now_ns <= proof_ns.saturating_add(EVIDENCE_LEASE_LIFETIME_NS);
                if source.proof_cycle_ready
                    && self.source_ready
                    && e == EUsability::Authority
                    && observation.classification == ClassificationState::Aligned
                    && proof_is_new
                    && proof_current
                {
                    self.last_proof_end_ms.insert(key.clone(), proof_end_ms);
                    if self.book.issue(
                        &client.client_identity,
                        direction,
                        generations,
                        client.byte_domain,
                        true,
                        proof_ns,
                    ) {
                        self.current_valid.insert(key);
                    }
                }
            }
        }
    }

    pub(crate) fn evidence(&self) -> Value {
        let generations = self.generations.generations;
        let mut evidence = self.book.evidence();
        let object = evidence
            .as_object_mut()
            .expect("EvidenceLeaseBook evidence is an object");
        object.insert("mode".into(), json!("shadow"));
        object.insert("formal_rate_owner".into(), json!(false));
        object.insert("current_valid".into(), json!(self.current_valid.len()));
        object.insert("source_ready".into(), json!(self.source_ready));
        object.insert("fast_reads_ready".into(), json!(self.fast_reads_ready));
        object.insert("proof_cycle_ready".into(), json!(self.proof_cycle_ready));
        object.insert("map_loss".into(), json!(self.map_loss));
        object.insert(
            "fast_integrity_failure".into(),
            json!(self.fast_integrity_failure),
        );
        object.insert(
            "generations".into(),
            json!({
                "nss_bpf_load": generations.nss_bpf_load_generation,
                "nss_map": generations.nss_map_generation,
                "tc_attach": generations.tc_attach_generation,
                "layout": generations.layout_generation,
                "fast_n_reset": self.generations.fast_n_reset_generation,
                "fast_s_reset": self.generations.fast_s_reset_generation,
            }),
        );
        object.insert(
            "e_usability".into(),
            json!({
                "authority": self.e_authority_directions,
                "transient_unavailable": self.e_transient_directions,
                "structural_unavailable": self.e_structural_directions,
            }),
        );
        object.insert(
            "lease_lifetime_ms".into(),
            json!(EVIDENCE_LEASE_LIFETIME_NS / 1_000_000),
        );
        evidence
    }

    pub(crate) fn lease_valid(&self, client_identity: &str, direction: Direction) -> bool {
        self.current_valid
            .contains(&(client_identity.to_owned(), direction))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(
        kind: EdgeKind,
        unique: bool,
        coverage: Coverage,
        scope: TrafficScope,
    ) -> EdgeObservation {
        EdgeObservation {
            kind,
            unique,
            sample_available: true,
            coverage,
            scope,
        }
    }

    fn generations() -> LeaseGenerations {
        LeaseGenerations {
            attachment_generation: 1,
            nss_bpf_load_generation: 2,
            nss_map_generation: 3,
            tc_attach_generation: 4,
            layout_generation: 5,
        }
    }

    fn lease() -> EvidenceLease {
        EvidenceLease {
            client_identity: "client".to_owned(),
            direction: Direction::Tx,
            generations: generations(),
            byte_domain: ByteDomain::L2NoFcs,
            n_s_disjoint: true,
            issued_at_ns: 100,
            valid_until_ns: 200,
        }
    }

    #[test]
    fn e_authority_distinguishes_wifi_and_wired_rules() {
        assert_eq!(
            e_usability(edge(
                EdgeKind::Wifi,
                true,
                Coverage::Full,
                TrafficScope::Unicast
            )),
            EUsability::Authority
        );
        assert_eq!(
            e_usability(edge(
                EdgeKind::Wifi,
                true,
                Coverage::Partial,
                TrafficScope::Unicast
            )),
            EUsability::StructuralEUnavailable
        );
        assert_eq!(
            e_usability(edge(
                EdgeKind::Port,
                true,
                Coverage::Partial,
                TrafficScope::AllFrames
            )),
            EUsability::Authority
        );
        assert_eq!(
            e_usability(edge(
                EdgeKind::Port,
                false,
                Coverage::Full,
                TrafficScope::AllFrames
            )),
            EUsability::StructuralEUnavailable
        );
    }

    #[test]
    fn transient_edge_failure_is_not_structural_ambiguity() {
        let mut missing_sample = edge(
            EdgeKind::Port,
            true,
            Coverage::Partial,
            TrafficScope::AllFrames,
        );
        missing_sample.sample_available = false;
        assert_eq!(
            e_usability(missing_sample),
            EUsability::TransientEUnavailable
        );
        assert_eq!(
            e_usability(edge(
                EdgeKind::Port,
                true,
                Coverage::Partial,
                TrafficScope::RoutedObserved
            )),
            EUsability::StructuralEUnavailable
        );
    }

    #[test]
    fn lease_requires_all_generations_domain_disjointness_and_time() {
        let current = generations();
        let value = lease();
        assert!(value.is_valid(150, current, ByteDomain::L2NoFcs, true));
        assert!(!value.is_valid(201, current, ByteDomain::L2NoFcs, true));
        assert!(!value.is_valid(150, current, ByteDomain::EcmData, true));
        assert!(!value.is_valid(150, current, ByteDomain::L2NoFcs, false));
        let mut changed = current;
        changed.tc_attach_generation += 1;
        assert!(!value.is_valid(150, changed, ByteDomain::L2NoFcs, true));
    }

    #[test]
    fn lease_invalidation_is_immediate_for_structural_integrity_changes() {
        let value = lease();
        let mut changed = generations();
        changed.nss_map_generation += 1;
        assert_eq!(
            lease_invalidation(
                &value,
                changed,
                ByteDomain::L2NoFcs,
                true,
                false,
                false,
                false
            ),
            Some(LeaseInvalidation::NssMapGeneration)
        );
        assert_eq!(
            lease_invalidation(
                &value,
                generations(),
                ByteDomain::L2NoFcs,
                true,
                true,
                false,
                false
            ),
            Some(LeaseInvalidation::CounterReset)
        );
        assert_eq!(
            lease_invalidation(
                &value,
                generations(),
                ByteDomain::L2NoFcs,
                false,
                false,
                false,
                false
            ),
            Some(LeaseInvalidation::NsOverlap)
        );
    }

    #[test]
    fn lease_book_issues_expires_and_invalidates_per_identity_direction() {
        let mut book = EvidenceLeaseBook::default();
        assert!(book.issue(
            "client",
            Direction::Tx,
            generations(),
            ByteDomain::L2NoFcs,
            true,
            100,
        ));
        assert!(book.permits(
            "client",
            Direction::Tx,
            150,
            generations(),
            ByteDomain::L2NoFcs,
            true,
            false,
            false,
            false,
        ));
        assert!(!book.permits(
            "client",
            Direction::Rx,
            150,
            generations(),
            ByteDomain::L2NoFcs,
            true,
            false,
            false,
            false,
        ));
        assert!(!book.permits(
            "client",
            Direction::Tx,
            150,
            generations(),
            ByteDomain::L2NoFcs,
            true,
            false,
            true,
            false,
        ));
        assert_eq!(book.evidence()["invalidated"], 1);

        assert!(book.issue(
            "expired",
            Direction::Rx,
            generations(),
            ByteDomain::L2NoFcs,
            true,
            0,
        ));
        assert!(!book.permits(
            "expired",
            Direction::Rx,
            EVIDENCE_LEASE_LIFETIME_NS + 1,
            generations(),
            ByteDomain::L2NoFcs,
            true,
            false,
            false,
            false,
        ));
        assert_eq!(book.evidence()["expired"], 1);

        assert!(book.issue(
            "client",
            Direction::Tx,
            generations(),
            ByteDomain::L2NoFcs,
            true,
            200,
        ));
        assert!(book.issue(
            "retired",
            Direction::Rx,
            generations(),
            ByteDomain::L2NoFcs,
            true,
            200,
        ));
        assert!(!book.issue(
            "overlap",
            Direction::Tx,
            generations(),
            ByteDomain::L2NoFcs,
            false,
            200,
        ));
        book.retain_identities(&BTreeSet::from(["client".to_owned()]));
        assert_eq!(book.evidence()["active"], 1);
        book.remove("client", Direction::Tx);
        assert_eq!(book.evidence()["active"], 0);
    }

    fn ready_source() -> LeaseSourceObservation {
        LeaseSourceObservation {
            nss_bpf_object_loaded: true,
            nss_bpf_attached: true,
            nss_map_read_attempted: true,
            nss_map_read_ok: true,
            tc_bpf_object_loaded: true,
            tc_bpf_attached: true,
            tc_expected_hooks: 2,
            tc_attached_hooks: 2,
            tc_map_read_attempted: true,
            tc_map_read_ok: true,
            layout: Some(EcmLayout {
                ready: 1,
                ..EcmLayout::default()
            }),
            fast_n_reset_generation: Some(1),
            fast_s_reset_generation: Some(2),
            fast_reads_ready: true,
            proof_cycle_ready: true,
            ..LeaseSourceObservation::default()
        }
    }

    fn runtime_client(
        e: EdgeObservation,
        classification: ClassificationState,
        proof_end_ms: u64,
    ) -> LeaseClientObservation {
        let direction = LeaseDirectionObservation {
            e,
            classification,
            counter_reset: false,
        };
        LeaseClientObservation {
            client_identity: "client".to_owned(),
            attachment_generation: 7,
            byte_domain: ByteDomain::L2WithFcs,
            proof_end_ms: Some(proof_end_ms),
            tx: direction,
            rx: direction,
        }
    }

    fn authority_edge() -> EdgeObservation {
        edge(
            EdgeKind::Port,
            true,
            Coverage::Partial,
            TrafficScope::AllFrames,
        )
    }

    #[test]
    fn runtime_issues_only_one_lease_per_direction_for_a_new_aligned_proof() {
        let mut runtime = EvidenceLeaseRuntime::default();
        let client = runtime_client(authority_edge(), ClassificationState::Aligned, 6_000);
        runtime.reconcile(6_000, ready_source(), &[client.clone()]);
        assert_eq!(runtime.evidence()["active"], 2);
        assert_eq!(runtime.evidence()["issued"], 2);
        assert_eq!(runtime.evidence()["current_valid"], 2);
        assert_eq!(runtime.evidence()["source_ready"], true);

        let mut retained = ready_source();
        retained.proof_cycle_ready = false;
        runtime.reconcile(7_000, retained, &[client]);
        assert_eq!(runtime.evidence()["active"], 2);
        assert_eq!(runtime.evidence()["issued"], 2);
    }

    #[test]
    fn stale_fast_snapshots_cannot_sign_a_fresh_classifier_proof() {
        let mut runtime = EvidenceLeaseRuntime::default();
        let client = runtime_client(authority_edge(), ClassificationState::Aligned, 6_000);
        let mut source = ready_source();
        source.fast_reads_ready = false;
        runtime.reconcile(6_000, source, &[client]);
        assert_eq!(runtime.evidence()["active"], 0);
        assert_eq!(runtime.evidence()["issued"], 0);
        assert_eq!(runtime.evidence()["source_ready"], false);
        assert_eq!(runtime.evidence()["proof_cycle_ready"], true);
    }

    #[test]
    fn transient_edge_loss_keeps_a_lease_but_never_refreshes_stale_proof() {
        let mut runtime = EvidenceLeaseRuntime::default();
        let client = runtime_client(authority_edge(), ClassificationState::Aligned, 6_000);
        runtime.reconcile(6_000, ready_source(), &[client]);

        let mut transient = authority_edge();
        transient.sample_available = false;
        let client = runtime_client(transient, ClassificationState::Unavailable, 6_000);
        let mut retained = ready_source();
        retained.proof_cycle_ready = false;
        runtime.reconcile(7_000, retained, &[client.clone()]);
        assert_eq!(runtime.evidence()["active"], 2);
        assert_eq!(
            runtime.evidence()["e_usability"]["transient_unavailable"],
            2
        );

        runtime.reconcile(16_001, retained, &[client]);
        assert_eq!(runtime.evidence()["active"], 0);
        assert_eq!(runtime.evidence()["expired"], 2);
    }

    #[test]
    fn source_generations_map_loss_and_reset_invalidate_immediately() {
        let mut runtime = EvidenceLeaseRuntime::default();
        let client = runtime_client(authority_edge(), ClassificationState::Aligned, 6_000);
        runtime.reconcile(6_000, ready_source(), &[client.clone()]);

        let mut tc_changed = ready_source();
        tc_changed.proof_cycle_ready = false;
        tc_changed.tc_self_heal_recoveries = 1;
        runtime.reconcile(7_000, tc_changed, &[client.clone()]);
        assert_eq!(runtime.evidence()["active"], 0);
        assert_eq!(
            runtime.evidence()["last_invalidation"],
            "tc_attach_generation"
        );

        let client = runtime_client(authority_edge(), ClassificationState::Aligned, 8_000);
        tc_changed.proof_cycle_ready = true;
        runtime.reconcile(8_000, tc_changed, &[client.clone()]);
        assert_eq!(runtime.evidence()["active"], 2);
        let mut map_loss = tc_changed;
        map_loss.proof_cycle_ready = false;
        map_loss.nss_map_read_ok = false;
        runtime.reconcile(8_100, map_loss, &[client.clone()]);
        assert_eq!(runtime.evidence()["active"], 0);
        assert_eq!(runtime.evidence()["last_invalidation"], "map_loss");

        let client = runtime_client(authority_edge(), ClassificationState::Aligned, 10_000);
        tc_changed.proof_cycle_ready = true;
        runtime.reconcile(10_000, tc_changed, &[client.clone()]);
        assert_eq!(runtime.evidence()["active"], 2);
        let mut reset = tc_changed;
        reset.proof_cycle_ready = false;
        reset.fast_n_reset_generation = Some(3);
        runtime.reconcile(10_100, reset, &[client]);
        assert_eq!(runtime.evidence()["active"], 0);
        assert_eq!(runtime.evidence()["last_invalidation"], "counter_reset");
    }

    #[test]
    fn structural_edge_or_domain_mismatch_cannot_hold_or_issue_a_lease() {
        let mut runtime = EvidenceLeaseRuntime::default();
        let client = runtime_client(authority_edge(), ClassificationState::Aligned, 6_000);
        runtime.reconcile(6_000, ready_source(), &[client]);
        assert_eq!(runtime.evidence()["active"], 2);

        let structural = edge(
            EdgeKind::Port,
            false,
            Coverage::Partial,
            TrafficScope::AllFrames,
        );
        let client = runtime_client(structural, ClassificationState::Partial, 6_000);
        let mut retained = ready_source();
        retained.proof_cycle_ready = false;
        runtime.reconcile(7_000, retained, &[client]);
        assert_eq!(runtime.evidence()["active"], 0);
        assert_eq!(runtime.evidence()["last_invalidation"], "integrity_failure");

        let wifi = edge(EdgeKind::Wifi, true, Coverage::Full, TrafficScope::Unicast);
        let mut client = runtime_client(wifi, ClassificationState::DomainMismatch, 8_000);
        client.byte_domain = ByteDomain::StationData;
        runtime.reconcile(8_000, ready_source(), &[client]);
        assert_eq!(runtime.evidence()["active"], 0);
        assert_eq!(runtime.evidence()["issued"], 2);
    }
}
