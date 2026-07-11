use aya::maps::MapError;
use lanspeedd::counter_value;

#[test]
fn missing_counter_is_zero_but_other_map_errors_propagate() {
    assert_eq!(counter_value(Err(MapError::KeyNotFound)).unwrap(), 0);

    let error = counter_value(Err(MapError::InvalidKeySize {
        size: 1,
        expected: 4,
    }))
    .unwrap_err();
    assert!(matches!(error, MapError::InvalidKeySize { .. }));
}
