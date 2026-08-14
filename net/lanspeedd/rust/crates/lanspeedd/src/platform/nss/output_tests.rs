use super::sample_clock_within;

#[test]
fn active_edge_clock_allows_only_bounded_read_skew() {
    assert!(sample_clock_within(Some(12_004), Some(12_000), 50));
    assert!(sample_clock_within(Some(12_000), Some(12_000), 0));
    assert!(!sample_clock_within(Some(12_051), Some(12_000), 50));
    assert!(sample_clock_within(None, Some(12_000), 50));
    assert!(!sample_clock_within(Some(12_000), None, 50));
}
