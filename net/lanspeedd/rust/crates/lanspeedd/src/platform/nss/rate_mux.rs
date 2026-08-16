//! Production RateMux decision rules for E/N/S semantics.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::platform::access_edge::Direction;

use super::evidence_lease::EUsability;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RateView {
    EAuthority,
    RoutedLeaseSubstitute,
    RoutedInternet,
    Unavailable,
}

pub(crate) fn select_rate_view(
    e: EUsability,
    lease_valid: bool,
    fast_window_valid: bool,
    explicit_internet_view: bool,
) -> RateView {
    if explicit_internet_view {
        return if fast_window_valid {
            RateView::RoutedInternet
        } else {
            RateView::Unavailable
        };
    }
    if e == EUsability::Authority {
        return RateView::EAuthority;
    }
    if e == EUsability::TransientEUnavailable && lease_valid && fast_window_valid {
        return RateView::RoutedLeaseSubstitute;
    }
    if e == EUsability::StructuralEUnavailable && explicit_internet_view && fast_window_valid {
        return RateView::RoutedInternet;
    }
    RateView::Unavailable
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RateMuxRuntime {
    active: bool,
    views: BTreeMap<(String, Direction), RateView>,
}

impl RateMuxRuntime {
    pub(crate) fn begin_cycle(&mut self, active: bool) {
        self.active = active;
        self.views.clear();
    }

    pub(crate) fn select(
        &mut self,
        client_identity: &str,
        direction: Direction,
        e: EUsability,
        lease_valid: bool,
        fast_window_valid: bool,
        explicit_internet_view: bool,
    ) -> RateView {
        let view = select_rate_view(e, lease_valid, fast_window_valid, explicit_internet_view);
        self.views
            .insert((client_identity.to_owned(), direction), view);
        view
    }

    pub(crate) fn evidence(&self) -> Value {
        let count = |view| self.views.values().filter(|value| **value == view).count();
        json!({
            "active": self.active,
            "formal_rate_owner": self.active,
            "directions": self.views.len(),
            "views": {
                "e_authority": count(RateView::EAuthority),
                "routed_lease_substitute": count(RateView::RoutedLeaseSubstitute),
                "routed_internet": count(RateView::RoutedInternet),
                "unavailable": count(RateView::Unavailable),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{select_rate_view, RateMuxRuntime, RateView};
    use crate::platform::access_edge::Direction;
    use crate::platform::nss::evidence_lease::EUsability;

    #[test]
    fn edge_authority_always_wins() {
        assert_eq!(
            select_rate_view(EUsability::Authority, false, false, false),
            RateView::EAuthority
        );
    }

    #[test]
    fn explicit_internet_view_is_a_distinct_routed_projection() {
        assert_eq!(
            select_rate_view(EUsability::Authority, false, true, true),
            RateView::RoutedInternet
        );
        assert_eq!(
            select_rate_view(EUsability::Authority, false, false, true),
            RateView::Unavailable
        );
    }

    #[test]
    fn transient_e_can_use_only_a_valid_leased_fast_window() {
        assert_eq!(
            select_rate_view(EUsability::TransientEUnavailable, true, true, false),
            RateView::RoutedLeaseSubstitute
        );
        assert_eq!(
            select_rate_view(EUsability::TransientEUnavailable, false, true, false),
            RateView::Unavailable
        );
        assert_eq!(
            select_rate_view(EUsability::TransientEUnavailable, true, false, false),
            RateView::Unavailable
        );
    }

    #[test]
    fn structural_e_requires_explicit_internet_view() {
        assert_eq!(
            select_rate_view(EUsability::StructuralEUnavailable, true, true, false),
            RateView::Unavailable
        );
        assert_eq!(
            select_rate_view(EUsability::StructuralEUnavailable, false, true, true),
            RateView::RoutedInternet
        );
        assert_eq!(
            select_rate_view(EUsability::StructuralEUnavailable, false, false, true),
            RateView::Unavailable
        );
    }

    #[test]
    fn runtime_records_only_the_current_direction_decisions() {
        let mut runtime = RateMuxRuntime::default();
        runtime.begin_cycle(true);
        assert_eq!(
            runtime.select(
                "client",
                Direction::Tx,
                EUsability::Authority,
                false,
                false,
                false,
            ),
            RateView::EAuthority
        );
        assert_eq!(
            runtime.select(
                "client",
                Direction::Rx,
                EUsability::TransientEUnavailable,
                true,
                true,
                false,
            ),
            RateView::RoutedLeaseSubstitute
        );
        assert_eq!(runtime.evidence()["formal_rate_owner"], true);
        assert_eq!(runtime.evidence()["views"]["e_authority"], 1);
        assert_eq!(runtime.evidence()["views"]["routed_lease_substitute"], 1);

        runtime.begin_cycle(false);
        assert_eq!(runtime.evidence()["directions"], 0);
        assert_eq!(runtime.evidence()["formal_rate_owner"], false);
    }
}
