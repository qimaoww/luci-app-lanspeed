//! EvidenceLease and E-authority rules for the NSS RateMux shadow plane.

use crate::platform::access_edge::types::{ByteDomain, Coverage, Direction, TrafficScope};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EdgeKind {
    Wifi,
    Port,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EdgeObservation {
    pub kind: EdgeKind,
    pub unique: bool,
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
    let authority = match observation.kind {
        EdgeKind::Wifi => {
            observation.coverage == Coverage::Full && observation.scope == TrafficScope::Unicast
        }
        EdgeKind::Port => {
            observation.unique
                && matches!(observation.coverage, Coverage::Full | Coverage::Partial)
                && observation.scope == TrafficScope::AllFrames
        }
    };
    if authority {
        return EUsability::Authority;
    }
    if matches!(
        observation.coverage,
        Coverage::Unavailable | Coverage::Degraded
    ) || matches!(observation.scope, TrafficScope::None)
    {
        EUsability::TransientEUnavailable
    } else {
        EUsability::StructuralEUnavailable
    }
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
        assert_eq!(
            e_usability(edge(
                EdgeKind::Port,
                true,
                Coverage::Unavailable,
                TrafficScope::AllFrames
            )),
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
}
