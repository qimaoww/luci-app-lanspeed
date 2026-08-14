#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_queue_keys_name_one_aggregate_executor() {
        let key = format!(
            "identity/upload/aggregate/{}/class_bytes",
            ifb::device("edge0")
        );
        assert!(key.contains("/upload/aggregate/"));
        assert!(!key.contains("/cpu/"));
        assert!(!key.contains("/nss/"));
    }
}
