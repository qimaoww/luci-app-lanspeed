use aya::maps::MapError;

pub fn counter_value(result: Result<u64, MapError>) -> Result<u64, MapError> {
    match result {
        Ok(value) => Ok(value),
        Err(MapError::KeyNotFound) => Ok(0),
        Err(error) => Err(error),
    }
}
