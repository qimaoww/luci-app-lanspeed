#[cfg(test)]
mod diagnostics_tests {
    use super::*;

    fn set_bpf_evidence(snapshot: &mut ResponseSnapshot, value: Value, live_metrics: bool) {
        snapshot
            .status
            .evidence
            .details
            .insert("bpf".into(), value.clone());
        snapshot.health.evidence.details.insert("bpf".into(), value);
        snapshot.status.capabilities.bpf_supported = true;
        snapshot.status.capabilities.bpf_package = true;
        snapshot.status.capabilities.bpf_object = true;
        snapshot.status.capabilities.tc = true;
        snapshot.status.capabilities.tc_clsact = true;
        snapshot.status.capabilities.live_metrics = live_metrics;
    }

    #[test]
    fn age_is_recomputed_and_fresh_data_becomes_stale_without_an_error_tick() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.mark_collection_success(7, 1_000, 500);

        let fresh = snapshot.diagnostics_at(2_500);
        assert_eq!(fresh.collection.state, DiagnosticCollectionState::Fresh);
        assert_eq!(fresh.collection.age_ms, Some(1_500));

        let stale = snapshot.diagnostics_at(2_501);
        assert_eq!(stale.collection.state, DiagnosticCollectionState::Stale);
        assert_eq!(stale.collection.generation, 7);
        assert_eq!(stale.service.state, DiagnosticServiceState::Degraded);
        assert!(stale
            .alerts
            .iter()
            .any(|alert| alert.id == "collection_stale"));
    }

    #[cfg(feature = "nss-platform")]
    #[test]
    fn ecm_bpf_operational_status_is_informational() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.status.capabilities.live_metrics = true;
        snapshot.status.warnings = vec![
            "nss_ecm_bpf_active".into(),
            "nss_ecm_bpf_disjoint_ownership".into(),
        ];

        let diagnostics = snapshot.diagnostics_at(0);
        for id in ["nss_ecm_bpf_active", "nss_ecm_bpf_disjoint_ownership"] {
            let alert = diagnostics
                .alerts
                .iter()
                .find(|alert| alert.id == id)
                .unwrap_or_else(|| panic!("missing {id} alert"));
            assert_eq!(alert.severity, "info");
        }
    }

    #[test]
    fn repeated_failures_keep_generation_and_never_publish_the_raw_error() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.mark_collection_success(3, 1_000, 500);
        let error = DaemonError::collection("/private/path token=secret");
        snapshot.mark_collection_failure(1_500, 500, &error);
        snapshot.mark_collection_failure(2_000, 500, &error);

        let diagnostics = snapshot.diagnostics_at(2_000);
        assert_eq!(diagnostics.collection.generation, 3);
        assert_eq!(diagnostics.collection.consecutive_failures, 2);
        assert_eq!(diagnostics.collection.retained, true);
        assert_eq!(
            diagnostics.collection.last_error.as_ref().unwrap().code,
            "collection_error"
        );
        let serialized = serde_json::to_string(&diagnostics).unwrap();
        assert!(!serialized.contains("/private/path"));
        assert!(!serialized.contains("token=secret"));
    }

    #[test]
    fn first_collection_failure_publishes_a_critical_unavailable_alert() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.mark_collection_failure(
            1_000,
            500,
            &DaemonError::collection("/private/path token=secret"),
        );

        let diagnostics = snapshot.diagnostics_at(1_000);
        let alert = diagnostics
            .alerts
            .iter()
            .find(|alert| alert.id == "collection_unavailable")
            .expect("missing collection_unavailable alert");
        assert_eq!(alert.severity, "critical");
        assert_eq!(alert.component, "collection");
        assert!(!alert.message_public.contains("/private/path"));
        assert!(!alert.message_public.contains("token=secret"));
    }

    #[cfg(feature = "nss-platform")]
    #[test]
    fn nss_node_connection_health_uses_node_counters_and_reason() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.clients.conn_source = Some("nss_ecm_node".into());
        snapshot.clients.nss_ecm_nodes_seen = Some(12);
        snapshot.clients.nss_ecm_nodes_matched = Some(9);
        snapshot.clients.nss_ecm_node_parse_errors = Some(2);

        let diagnostics = snapshot.diagnostics_at(0);
        assert_eq!(
            diagnostics.connection.state,
            DiagnosticHealthState::Degraded
        );
        assert_eq!(
            diagnostics.connection.source.as_deref(),
            Some("nss_ecm_node")
        );
        assert_eq!(diagnostics.connection.entries_seen, Some(12));
        assert_eq!(diagnostics.connection.entries_matched, Some(9));
        assert_eq!(diagnostics.connection.parse_errors, Some(2));
        let subsystem = diagnostics
            .subsystems
            .iter()
            .find(|subsystem| subsystem.id == "conntrack")
            .expect("missing connection subsystem");
        assert_eq!(subsystem.state, DiagnosticHealthState::Degraded);
        assert_eq!(subsystem.code.as_deref(), Some("nss_ecm_node_parse_errors"));
    }

    #[cfg(feature = "nss-platform")]
    #[test]
    fn nss_without_a_connection_snapshot_exposes_sampling_reason() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        snapshot.status.evidence.details.insert(
            "effective_collector".into(),
            Value::String("nss_ecm_node".into()),
        );

        let diagnostics = snapshot.diagnostics_at(0);
        let subsystem = diagnostics
            .subsystems
            .iter()
            .find(|subsystem| subsystem.id == "conntrack")
            .expect("missing connection subsystem");
        assert_eq!(subsystem.state, DiagnosticHealthState::Unavailable);
        assert_eq!(subsystem.code.as_deref(), Some("conntrack_not_sampled"));
    }

    #[cfg(feature = "nss-platform")]
    #[test]
    fn nss_control_diagnostic_subsystem_is_not_healthy_without_evidence() {
        let snapshot = ResponseSnapshot::unsupported("test");
        let diagnostics = snapshot.diagnostics_at(0);
        let subsystem = diagnostics
            .subsystems
            .iter()
            .find(|subsystem| subsystem.id == "nss_control")
            .expect("missing NSS control subsystem");
        assert_eq!(subsystem.state, DiagnosticHealthState::Unavailable);
        assert_eq!(
            subsystem.code.as_deref(),
            Some("nss_control_diagnostics_unavailable")
        );
    }

    #[cfg(feature = "nss-platform")]
    #[test]
    fn direct_counters_without_source_metadata_remain_unavailable() {
        let mut response = ClientsResponse::empty(Evidence::default());
        response.nss_ecm_nodes_seen = Some(4);
        response.nss_ecm_nodes_matched = Some(3);
        response.nss_ecm_node_parse_errors = Some(0);

        let connection = diagnostic_connection(&response);
        assert_eq!(connection.state, DiagnosticHealthState::Unavailable);
        assert_eq!(connection.source, None);
        assert_eq!(connection.entries_seen, None);
        assert_eq!(connection.entries_matched, None);
        assert_eq!(connection.parse_errors, None);
    }

    #[test]
    fn bpf_map_failure_severity_tracks_retained_or_missing_live_data() {
        let mut retained = ResponseSnapshot::unsupported("test");
        set_bpf_evidence(
            &mut retained,
            json!({
                "enabled": true, "collect_target_count": 1,
                "expected_hook_count": 2, "attached_hook_count": 2,
                "object_loaded": true, "attach_state": "ready",
                "map_state": "retained", "last_complete_snapshot_ms": 9_000,
                "retained_fresh_snapshot": true, "reason_code": "map_read_failed"
            }),
            true,
        );
        let diagnostics = retained.diagnostics_at(10_000);
        let alert = diagnostics
            .alerts
            .iter()
            .find(|alert| alert.id == "map_read_failed")
            .expect("missing retained map alert");
        assert_eq!(alert.severity, "warning");
        let map = diagnostics
            .subsystems
            .iter()
            .find(|item| item.id == "bpf_map")
            .expect("missing BPF map subsystem");
        assert_eq!(map.state, DiagnosticHealthState::Degraded);

        let mut failed = retained.clone();
        set_bpf_evidence(
            &mut failed,
            json!({
                "enabled": true, "collect_target_count": 1,
                "expected_hook_count": 2, "attached_hook_count": 2,
                "object_loaded": true, "attach_state": "ready",
                "map_state": "failed", "last_complete_snapshot_ms": null,
                "retained_fresh_snapshot": false, "reason_code": "map_read_failed"
            }),
            false,
        );
        let diagnostics = failed.diagnostics_at(10_000);
        let alert = diagnostics
            .alerts
            .iter()
            .find(|alert| alert.id == "map_read_failed")
            .expect("missing failed map alert");
        assert_eq!(alert.severity, "critical");
        let map = diagnostics
            .subsystems
            .iter()
            .find(|item| item.id == "bpf_map")
            .expect("missing BPF map subsystem");
        assert_eq!(map.state, DiagnosticHealthState::Unavailable);
    }

    #[cfg(feature = "nss-platform")]
    #[test]
    fn ecm_bpf_diagnostics_require_both_the_kprobe_and_tc_runtime() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        set_bpf_evidence(
            &mut snapshot,
            json!({
                "enabled": true, "collect_target_count": 1,
                "expected_hook_count": 2, "attached_hook_count": 2,
                "object_loaded": true, "attach_state": "ready",
                "map_state": "ready", "last_complete_snapshot_ms": 1,
                "retained_fresh_snapshot": false, "reason_code": "ready"
            }),
            true,
        );
        snapshot
            .status
            .evidence
            .details
            .insert("effective_collector".into(), json!("nss_ecm_bpf"));
        snapshot.status.evidence.details.insert(
            "ecm_bpf".into(),
            json!({
                "object_loaded": true,
                "attach_state": "ready",
                "map_state": "ready"
            }),
        );
        snapshot.status.capabilities.nss = true;
        snapshot.status.capabilities.nss_ecm_bpf = true;
        snapshot.status.warnings = vec!["bpf_runtime_loader_unavailable".into()];

        let diagnostics = snapshot.diagnostics_at(0);
        let find = |id: &str| {
            diagnostics
                .subsystems
                .iter()
                .find(|item| item.id == id)
                .unwrap_or_else(|| panic!("missing {id} subsystem"))
        };
        assert_eq!(find("bpf").state, DiagnosticHealthState::Healthy);
        assert_eq!(find("bpf").code, None);
        assert_eq!(find("bpf_map").state, DiagnosticHealthState::Healthy);
        assert_eq!(find("bpf_map").code, None);
        assert_eq!(find("tc").state, DiagnosticHealthState::Healthy);
        assert_eq!(find("tc").code, None);

        set_bpf_evidence(
            &mut snapshot,
            json!({
                "enabled": true, "collect_target_count": 1,
                "expected_hook_count": 2, "attached_hook_count": 0,
                "object_loaded": false, "attach_state": "not_attempted",
                "map_state": "not_attempted", "last_complete_snapshot_ms": null,
                "retained_fresh_snapshot": false, "reason_code": "object_load_failed"
            }),
            true,
        );
        let degraded = snapshot.diagnostics_at(0);
        let find_degraded = |id: &str| {
            degraded
                .subsystems
                .iter()
                .find(|item| item.id == id)
                .unwrap_or_else(|| panic!("missing {id} subsystem"))
        };
        assert_eq!(find_degraded("bpf").state, DiagnosticHealthState::Degraded);
        assert_eq!(
            find_degraded("bpf").code.as_deref(),
            Some("nss_ecm_bpf_tc_degraded")
        );
        assert_eq!(
            find_degraded("bpf_map").state,
            DiagnosticHealthState::Degraded
        );
        assert_eq!(find_degraded("tc").state, DiagnosticHealthState::Degraded);
    }

    #[cfg(feature = "nss-platform")]
    #[test]
    fn live_nss_fallback_deduplicates_bpf_failure_without_missing_live_metrics() {
        let mut snapshot = ResponseSnapshot::unsupported("test");
        set_bpf_evidence(
            &mut snapshot,
            json!({
                "enabled": true, "collect_target_count": 1,
                "expected_hook_count": 2, "attached_hook_count": 0,
                "object_loaded": true, "attach_state": "failed",
                "map_state": "not_attempted", "last_complete_snapshot_ms": null,
                "retained_fresh_snapshot": false, "reason_code": "tc_attach_failed"
            }),
            true,
        );
        snapshot.status.warnings = vec![
            "tc_attach_failed".into(),
            "bpf_runtime_loader_unavailable".into(),
        ];
        let diagnostics = snapshot.diagnostics_at(0);
        assert_eq!(
            diagnostics
                .alerts
                .iter()
                .filter(|alert| alert.id == "tc_attach_failed")
                .count(),
            1
        );
        assert!(!diagnostics
            .alerts
            .iter()
            .any(|alert| alert.id == "bpf_runtime_loader_unavailable"));
        assert!(!diagnostics
            .alerts
            .iter()
            .any(|alert| alert.id == "live_metrics_unavailable"));
    }
}
