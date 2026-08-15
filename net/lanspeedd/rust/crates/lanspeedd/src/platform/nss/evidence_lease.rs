//! EvidenceLease and E-authority rules for the production NSS RateMux.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::platform::access_edge::types::{ByteDomain, Coverage, Direction, TrafficScope};

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
        self.leases
            .retain(|(identity, _), _| identities.contains(identity));
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
}
