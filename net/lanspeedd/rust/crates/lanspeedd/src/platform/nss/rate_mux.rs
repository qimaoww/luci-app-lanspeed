//! Shadow RateMux decision rules for E/N/S semantics.

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
    if e == EUsability::Authority {
        return RateView::EAuthority;
    }
    if e == EUsability::TransientEUnavailable && lease_valid && fast_window_valid {
        return RateView::RoutedLeaseSubstitute;
    }
    if e == EUsability::StructuralEUnavailable
        && explicit_internet_view
        && fast_window_valid
    {
        return RateView::RoutedInternet;
    }
    RateView::Unavailable
}

#[cfg(test)]
mod tests {
    use super::{select_rate_view, RateView};
    use crate::platform::nss::evidence_lease::EUsability;

    #[test]
    fn edge_authority_always_wins() {
        assert_eq!(
            select_rate_view(EUsability::Authority, false, false, false),
            RateView::EAuthority
        );
    }

    #[test]
    fn transient_e_can_use_only_a_valid_leased_fast_window() {
        assert_eq!(
            select_rate_view(EUsability::TransientEUnavailable, true, true, false),
            RateView::RoutedLeaseSubstitute
        );
        assert_eq!(
            select_rate_view(EUsability::TransientEUnavailable, false, true, true),
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
}
