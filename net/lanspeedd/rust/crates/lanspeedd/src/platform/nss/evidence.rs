use serde_json::{json, Value};

use crate::{
    model::Evidence,
    platform::nss::{
        ecm_bpf::{
            EcmBpfSnapshot, ECM_BPF_OBJECT_PATH, ECM_EVENT_CLOCK_MAX_LAG_MS,
            ECM_EVENT_RATE_MAX_WINDOW_MS, ECM_RATE_HOLD_MS,
        },
        ecm_node,
        fusion::ECM_BPF_RATE_CLOCK_SKEW_MS,
        output::traffic_evidence,
        window::{
            ECM_BPF_EVENT_HIGH_RATE_BPS, ECM_BPF_HIGH_RATE_CONFIRMATION_MS,
            ECM_BPF_LOW_RATE_ROLLING_WINDOW_MS, ECM_BPF_LOW_RATE_STEP_MS,
            ECM_BPF_LOW_RATE_WINDOW_MS,
        },
        COLLECTION_INTERVAL_MS,
    },
    probe::RuntimeHealth,
};

pub(crate) fn apply_nss_snapshot_evidence(
    evidence: &mut Evidence,
    snapshot: Option<&ecm_node::NodeSnapshot>,
) {
    let Some(snapshot) = snapshot else {
        return;
    };
    let Some(nss) = evidence
        .details
        .get_mut("nss")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    nss.insert(
        "sync_barrier_supported".into(),
        json!(snapshot.stats.sync_barrier_supported),
    );
    nss.insert(
        "sync_barrier_wait_ms".into(),
        json!(snapshot.stats.sync_barrier_wait_ms),
    );
    nss.insert(
        "sync_snapshot_retries".into(),
        json!(snapshot.stats.sync_snapshot_retries),
    );
}

pub(crate) fn apply_ecm_bpf_evidence(
    evidence: &mut Evidence,
    runtime: &RuntimeHealth,
    snapshot: Option<&EcmBpfSnapshot>,
) {
    let retained_fresh_snapshot = !runtime.ecm_bpf_map_read_ok
        && runtime
            .ecm_bpf_last_complete_snapshot_ms
            .is_some_and(|sample_ms| {
                crate::is_fresh(runtime.now_ms, sample_ms, runtime.ecm_bpf_freshness_ms)
            });
    let bpf_retained_fresh_snapshot = !runtime.bpf_map_read_ok
        && runtime
            .bpf_last_complete_snapshot_ms
            .is_some_and(|sample_ms| {
                crate::is_fresh(runtime.now_ms, sample_ms, runtime.bpf_freshness_ms)
            });
    let attach_state = if !runtime.ecm_bpf_object_loaded {
        "not_ready"
    } else if runtime.ecm_bpf_attached {
        "ready"
    } else {
        "failed"
    };
    let map_state = if !runtime.ecm_bpf_attached {
        "not_attempted"
    } else if runtime.ecm_bpf_map_read_ok {
        "ready"
    } else if retained_fresh_snapshot {
        "retained"
    } else if runtime.ecm_bpf_map_read_attempted {
        "failed"
    } else {
        "not_attempted"
    };
    let layout = runtime.ecm_bpf_layout.map(|layout| {
        json!({
            "connection_node_offset": layout.connection_node_offset,
            "connection_generation_offset": layout.connection_generation_offset,
            "node_address_offset": layout.node_address_offset,
            "pointer_size": layout.pointer_size,
            "from_index": layout.from_index,
            "to_index": layout.to_index,
            "ready": layout.ready == 1,
        })
    });
    let map_entries = snapshot.map_or(runtime.ecm_bpf_map_entries, |value| value.map_entries);
    let map_capacity = runtime.ecm_bpf_map_capacity;
    let map_occupancy_pct = (map_capacity > 0)
        .then(|| ((map_entries as u128).saturating_mul(100) / map_capacity as u128).min(100) as u8);
    let map_iteration_truncated =
        runtime.ecm_bpf_map_iteration_truncated || snapshot.is_some_and(|value| value.truncated);
    let mut ecm_bpf_details = json!({
            "source": "kprobe:ecm_db_connection_data_totals_update+nss_callback_context",
            "object": ECM_BPF_OBJECT_PATH,
            "target_arch": std::env::consts::ARCH,
            "target_arch_supported": cfg!(target_arch = "aarch64"),
            "source_contract": "nss_hardware_callbacks_plus_tc_bpf_slow_path",
            "coverage": "nss_hardware_deltas_plus_tc_slow_path_deltas",
            "cumulative_bytes": "ecm_hardware_map_only",
            "deduplication": "kernel_call_context_separates_hardware_from_slow_path_before_raw_window_fusion",
            "nss_context_callbacks": runtime.ecm_bpf_nss_context_callbacks,
            "source_stats": {
                "nss_bytes": runtime.ecm_bpf_source_stats.nss_bytes,
                "nss_packets": runtime.ecm_bpf_source_stats.nss_packets,
                "nss_updates": runtime.ecm_bpf_source_stats.nss_updates,
                "slow_path_bytes": runtime.ecm_bpf_source_stats.slow_path_bytes,
                "slow_path_packets": runtime.ecm_bpf_source_stats.slow_path_packets,
                "slow_path_updates": runtime.ecm_bpf_source_stats.slow_path_updates,
            },
            "aggregation_key": "mac+direction",
            "object_loaded": runtime.ecm_bpf_object_loaded,
            "attach_state": attach_state,
            "map_state": map_state,
            "map_entries": map_entries,
            "map_capacity": map_capacity,
            "map_occupancy_pct": map_occupancy_pct,
            "map_pressure": map_occupancy_pct.is_some_and(|value| value >= 90),
            "map_loss": map_iteration_truncated,
            "matched_entries": snapshot.map_or(runtime.ecm_bpf_matched_entries, |value| value.matched_entries),
            "snapshot_clients": snapshot.map_or(runtime.ecm_bpf_snapshot_clients, |value| value.clients.len()),
            "map_iteration_truncated": map_iteration_truncated,
            "sample_ms": snapshot.map(|value| value.sample_ms),
            "last_complete_snapshot_ms": runtime.ecm_bpf_last_complete_snapshot_ms,
            "retained_fresh_snapshot": retained_fresh_snapshot,
            "collector_min_interval_ms": COLLECTION_INTERVAL_MS,
            "rate_window": "per_connection_generation_direction_ecm_event_elapsed_with_collector_fallback",
            "event_clock_max_lag_ms": ECM_EVENT_CLOCK_MAX_LAG_MS,
            "event_clock_max_window_ms": ECM_EVENT_RATE_MAX_WINDOW_MS,
            "rate_filter": "per_connection_generation_median_last_3_windows",
            "rate_hold_ms": ECM_RATE_HOLD_MS,
            "published_rate_window": "shared_client_and_interface_lan_window",
            "low_rate_unaligned_fallback": "shared_raw_deltas_with_event_gap_fill_and_lan_reconciliation",
            "fallback_lan_guard": "directional_proportional_reconciliation_to_physical_lan",
            "fallback_aggregation": "raw_delta_preferred_event_gap_elapsed_ms_weighted_mean",
            "pending_rate_display": "previous_complete_client_and_interface_batch",
            "tc_bpf_overlay": {
                "ready": runtime.bpf_object_loaded
                    && runtime.bpf_attached
                    && (runtime.bpf_map_read_ok || bpf_retained_fresh_snapshot),
                "snapshot_clients": runtime.bpf_snapshot_clients,
                "rate_merge": "aligned_raw_deltas_then_single_rate",
                "misaligned_rate_fallback": "directional_max_single_source_no_sum",
                "rate_clock_skew_limit_ms": ECM_BPF_RATE_CLOCK_SKEW_MS,
                "rate_lan_guard": "raw_fusion_requires_directionally_valid_merged_lan_window",
                "coverage_merge": "aligned_source_disjoint_delta_sum",
            },
            "coverage_delta_raw": snapshot.map(|value| traffic_evidence(value.coverage_delta)),
            "coverage_window": "independent_packet_aware_lan_catchup",
            "coverage_normalization": "client_and_lan_bytes_plus_packets_times_4",
            "btf_layout": layout,
            "error_stage": runtime.ecm_bpf_error_stage,
    });
    if let Some(details) = ecm_bpf_details.as_object_mut() {
        details.insert(
            "published_low_rate_warmup_ms".into(),
            json!(ECM_BPF_LOW_RATE_WINDOW_MS),
        );
        details.insert(
            "published_low_rate_step_ms".into(),
            json!(ECM_BPF_LOW_RATE_STEP_MS),
        );
        details.insert(
            "published_low_rate_rolling_window_ms".into(),
            json!(ECM_BPF_LOW_RATE_ROLLING_WINDOW_MS),
        );
        details.insert(
            "event_high_rate_threshold_bps".into(),
            json!(ECM_BPF_EVENT_HIGH_RATE_BPS),
        );
        details.insert(
            "high_rate_quiet_confirmation_ms".into(),
            json!(ECM_BPF_HIGH_RATE_CONFIRMATION_MS),
        );
        details.insert(
            "high_rate_interface_guard".into(),
            json!("identity_to_discovered_interface_directional_budget"),
        );
    }
    evidence.details.insert("ecm_bpf".into(), ecm_bpf_details);
}
