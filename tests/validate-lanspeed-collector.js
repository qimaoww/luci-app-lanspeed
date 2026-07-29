#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = path.resolve(__dirname, '..');

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function collectFiles(relativePath) {
  const absolute = path.join(root, relativePath);
  const result = [];
  for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
    if (entry.name === 'vendor' || entry.name === 'target') continue;
    const child = path.join(absolute, entry.name);
    if (entry.isDirectory()) {
      result.push(...collectFiles(path.relative(root, child)));
    } else {
      result.push(child);
    }
  }
  return result;
}

function normalized(bytes, packets) {
  return bytes + packets * 4;
}

function overlapReady(clientTx, clientRx, lanRx, lanTx, denominatorOwner) {
  const matched = Math.min(clientTx, lanRx) + Math.min(clientRx, lanTx);
  const denominator = denominatorOwner === 'client' ? clientTx + clientRx : lanRx + lanTx;
  return matched * 100 >= denominator * 90;
}

function alignedWindow(client, lan, windowMs) {
  const clientTx = normalized(client.txBytes, client.txPackets);
  const clientRx = normalized(client.rxBytes, client.rxPackets);
  const lanRx = normalized(lan.rxBytes, lan.rxPackets);
  const lanTx = normalized(lan.txBytes, lan.txPackets);
  const clientClockReady = overlapReady(
    client.txBytes, client.rxBytes, lan.rxBytes, lan.txBytes, 'client'
  ) && overlapReady(
    client.txPackets, client.rxPackets, lan.rxPackets, lan.txPackets, 'client'
  ) && overlapReady(clientTx, clientRx, lanRx, lanTx, 'client');
  const lanOwnershipReady = overlapReady(
    client.txBytes, client.rxBytes, lan.rxBytes, lan.txBytes, 'lan'
  ) && overlapReady(
    client.txPackets, client.rxPackets, lan.rxPackets, lan.txPackets, 'lan'
  ) && overlapReady(clientTx, clientRx, lanRx, lanTx, 'lan');
  if (!clientClockReady || !lanOwnershipReady) {
    return { quality: 'counter_skew', txBps: 0, rxBps: 0, txPct: null, rxPct: null };
  }
  return {
    quality: 'ok',
    txBps: Math.floor(clientTx * 8000 / windowMs),
    rxBps: Math.floor(clientRx * 8000 / windowMs),
    txPct: clientTx > lanRx ? null : Math.floor(clientTx * 100 / lanRx),
    rxPct: clientRx > lanTx ? null : Math.floor(clientRx * 100 / lanTx)
  };
}

const model = readJson('net/lanspeedd/src/collector-model.json');
const schema = readJson('net/lanspeedd/files/usr/share/lanspeed/schema.json');
const ecm = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/ecm_node.rs');
const ecmBpf = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/ecm_bpf.rs');
const ecmBpfProgram = read('net/lanspeedd/rust/crates/lanspeed-ebpf/src/nss/mod.rs');
const windowSource = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/window.rs');
const nssFusion = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/fusion.rs');
const nssOutput = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/output.rs');
const nssEvidence = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/evidence.rs');
const nssRuntime = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/runtime.rs');
const nssModule = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/mod.rs');
const nssBpfCoverage = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/bpf_coverage.rs');
const nssTcSnapshot = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/tc_snapshot.rs');
const x86Coverage = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/x86/coverage.rs');
const x86CoverageState = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/x86/coverage_state.rs');
const counterSource = read('net/lanspeedd/rust/crates/lanspeedd/src/platform/counters.rs');
const x86Sources = collectFiles('net/lanspeedd/rust/crates/lanspeedd/src/platform/x86')
  .map((file) => fs.readFileSync(file, 'utf8')).join('\n');
const nssUserspace = collectFiles('net/lanspeedd/rust/crates/lanspeedd/src/platform/nss')
  .map((file) => fs.readFileSync(file, 'utf8')).join('\n');
const x86Ebpf = collectFiles('net/lanspeedd/rust/crates/lanspeed-ebpf/src/x86')
  .map((file) => fs.readFileSync(file, 'utf8')).join('\n');
const nssEbpf = collectFiles('net/lanspeedd/rust/crates/lanspeed-ebpf/src/nss')
  .map((file) => fs.readFileSync(file, 'utf8')).join('\n');
const production = read('net/lanspeedd/rust/crates/lanspeedd/src/production.rs');
const policy = read('net/lanspeedd/rust/crates/lanspeedd/src/policy.rs');
const config = read('net/lanspeedd/rust/crates/lanspeedd/src/config.rs');
const probeCollector = read('net/lanspeedd/rust/crates/lanspeedd/src/probe/collector.rs');
const ebpfManifest = read('net/lanspeedd/rust/crates/lanspeed-ebpf/Cargo.toml');
const ebpfMain = read('net/lanspeedd/rust/crates/lanspeed-ebpf/src/main.rs');
const buildDriver = read('net/lanspeedd/rust/crates/lanspeed-build/src/lib.rs');
const packageMakefile = read('net/lanspeedd/Makefile');
const init = read('net/lanspeedd/files/etc/init.d/lanspeedd');

assert(model.version === 10, 'collector model must describe fully separated platform backends');
assert(model.module_boundaries.x86_userspace.endsWith('/platform/x86') &&
  model.module_boundaries.nss_userspace.endsWith('/platform/nss') &&
  model.module_boundaries.x86_ebpf.endsWith('/lanspeed-ebpf/src/x86') &&
  model.module_boundaries.nss_ebpf.endsWith('/lanspeed-ebpf/src/nss') &&
  model.module_boundaries.x86_depends_on_nss === false &&
  model.module_boundaries.nss_depends_on_x86 === false &&
  model.module_boundaries.tc_snapshot_bridge ===
    'production_explicit_value_copy_to_nss_owned_contract',
  'collector model must make the bidirectional x86/NSS boundary explicit');
assert(JSON.stringify(model.platform_matrix.x86_64.schemes) === JSON.stringify(['bpf']) &&
  model.platform_matrix.x86_64.nss_modes_exposed === false,
  'x86 platform contract must expose only pure BPF');
assert(JSON.stringify(model.platform_matrix.aarch64_nss.schemes) ===
  JSON.stringify(['bpf', 'nss_ecm_node', 'nss_ecm_bpf']) &&
  model.platform_matrix.aarch64_nss.ecm_bpf_target_arch === 'aarch64',
  'aarch64 NSS platform contract must expose all three isolated schemes');
assert(JSON.stringify(model.ownership.configured_schemes) ===
  JSON.stringify(['bpf', 'nss_ecm_node', 'nss_ecm_bpf']),
  'collector model must expose pure BPF, ECM, and ECM+BPF as independent schemes');
assert(JSON.stringify(model.ownership.auto_preference) ===
  JSON.stringify(['nss_ecm_bpf', 'nss_ecm_node', 'bpf']),
  'automatic selection must prefer ECM+BPF, then ECM, then pure BPF');
assert(model.ownership.pure_bpf_rate_owner === 'tc_lan_edge_map' &&
  model.ownership.ecm_rate_owner === 'ecm_node_adv_stats' &&
  model.ownership.ecm_bpf_rate_owner === 'nss_hardware_kprobe_map_plus_tc_slow_path_map' &&
  model.ownership.ecm_bpf_merge_policy === 'kernel_source_disjoint_raw_delta_fusion',
  'ECM+BPF must combine kernel-classified hardware and slow-path ownership');
assert(model.ownership.overlapping_rate_owners_forbidden === true,
  'overlapping NSS/BPF rate ownership must be forbidden');
assert(model.ownership.manual_fallback_forbidden === true,
  'manual rate schemes must fail closed instead of silently switching');
assert(model.ownership.rate_and_coverage_windows === 'shared_collector_batch_with_lan_catchup' &&
  model.ownership.coverage_can_block_rate === false,
  'LAN coverage must never gate the ECM client-rate window');
assert(model.ecm_node_model.collector_mode === 'nss_ecm_node', 'new collector mode must be nss_ecm_node');
assert(model.ecm_node_model.output_mask === 8, 'ECM state must request node output only');
assert(model.ecm_node_model.counter_merge_policy === 'single_ecm_node_owner', 'ECM node counters must have one owner');
assert(model.ecm_node_model.conntrack_rate_overlay === false, 'conntrack bytes must never overlay ECM rates');
assert(model.ecm_node_model.bpf_rate_overlay === false, 'BPF bytes must never overlay ECM rates');
assert(model.ecm_bpf_model.collector_mode === 'nss_ecm_bpf' &&
  model.ecm_bpf_model.object === '/usr/lib/bpf/lanspeed-ebpf-ecm' &&
  model.ecm_bpf_model.object_role === 'isolated_nss_hardware_context_kprobe' &&
  model.ecm_bpf_model.tc_program_source.endsWith('/lanspeed-ebpf/src/nss/account.rs') &&
  model.ecm_bpf_model.tc_bpf_object === '/usr/lib/bpf/lanspeed-ebpf-fallback' &&
  model.ecm_bpf_model.target_arch === 'aarch64' &&
  model.ecm_bpf_model.attach.totals === 'kprobe:ecm_db_connection_data_totals_update' &&
  model.ecm_bpf_model.attach.nss_context.length === 4,
  'ECM+BPF must use its isolated aarch64 ECM object and the TC slow-path observer');
assert(model.ecm_bpf_model.counter_merge_policy ===
    'aligned_nss_hardware_plus_tc_slow_path_raw_deltas' &&
  model.ecm_bpf_model.tc_bpf_rate_overlay === 'raw_delta_fusion_then_single_rate' &&
  model.ecm_bpf_model.misaligned_rate_fallback === 'directional_max_single_source_no_sum' &&
  model.ecm_bpf_model.cumulative_bytes === 'ecm_hardware_map_only' &&
  model.ecm_bpf_model.ecm_node_rate_overlay === false,
  'ECM+BPF must fuse aligned source-disjoint raw deltas and never overlay ECM nodes');
assert(model.ecm_bpf_window_model.rate_clock ===
    'per_connection_ecm_event_elapsed_with_daemon_fallback' &&
  model.ecm_bpf_window_model.event_timestamp_role ===
    'rate_window_when_monotonic_fresh_and_bounded' &&
  model.ecm_bpf_window_model.torn_event_timestamp_fallback === 'adjacent_daemon_samples' &&
  ecmBpf.includes('previous.last_progress_sample_ms') &&
  ecmBpf.includes('event_window_ms.unwrap_or(collector_window_ms)') &&
  model.ecm_bpf_window_model.hybrid_rate_fusion ===
    'aligned_raw_delta_sum_then_single_rate' &&
  model.ecm_bpf_window_model.hybrid_rate_lan_guard ===
    'directionally_valid_merged_lan_window_required' &&
  model.ecm_bpf_window_model.published_rate_clock ===
    'shared_client_and_interface_lan_window' &&
  model.ecm_bpf_window_model.published_high_rate_min_bytes === 131072 &&
  model.ecm_bpf_window_model.published_low_rate_warmup_ms === 6000 &&
  model.ecm_bpf_window_model.published_low_rate_step_ms === 2000 &&
  model.ecm_bpf_window_model.published_low_rate_rolling_window_ms === 18000 &&
  model.ecm_bpf_window_model.event_high_rate_threshold_bps === 8000000 &&
  model.ecm_bpf_window_model.high_rate_quiet_confirmation_ms === 10000 &&
  model.ecm_bpf_window_model.high_rate_lan_guard ===
    'valid_physical_lan_budget_directional_reconciliation' &&
  model.ecm_bpf_window_model.high_rate_interface_guard ===
    'identity_to_discovered_interface_directional_budget' &&
  model.ecm_bpf_window_model.high_rate_unaligned_priority ===
    'event_clock_first_raw_only_when_event_missing_or_implausible_no_sum' &&
  model.ecm_bpf_window_model.low_rate_unaligned_fallback ===
    'shared_raw_deltas_with_event_gap_fill_and_lan_reconciliation' &&
  model.ecm_bpf_window_model.fallback_aggregation ===
    'raw_delta_preferred_event_gap_elapsed_ms_weighted_mean' &&
  model.ecm_bpf_window_model.fallback_lan_guard ===
    'directional_proportional_reconciliation_to_physical_lan' &&
  model.ecm_bpf_window_model.fallback_priority ===
    'raw_delta_first_event_gap_uses_remaining_lan_budget' &&
  model.ecm_bpf_window_model.pending_rate_display ===
    'retain_previous_complete_client_and_interface_batch' &&
  model.ecm_bpf_window_model.published_sample_timestamp === 'aligned_window_end' &&
  model.ecm_bpf_window_model.precomputed_rate_sum_forbidden === true &&
  nssFusion.includes('aligned_ecm_bpf_window(') &&
  nssOutput.includes('apply_ecm_bpf_rate_batch(') &&
  production.includes('.update_with_client_interfaces(') &&
  windowSource.includes('fallback_rate_window_clients(') &&
  windowSource.includes('high_rate_window_clients(') &&
  windowSource.includes('ECM_BPF_HIGH_RATE_CONFIRMATION_MS') &&
  windowSource.includes('reconcile_high_rate_direction(') &&
  windowSource.includes('reconcile_high_rate_interfaces(') &&
  windowSource.includes('high_rate_direction(') &&
  windowSource.includes('reconcile_rate_direction(') &&
  windowSource.includes('aggregate_low_rate_history(') &&
  windowSource.includes('ECM_BPF_LOW_RATE_ROLLING_WINDOW_MS') &&
  nssOutput.includes('ECM+BPF high-rate client floor') &&
  nssFusion.includes('directional_bps(merged.tx_bytes, merged.tx_packets, window_ms)') &&
  nssFusion.includes('ecm.tx_bps.max(bpf.tx_bps)') &&
  nssFusion.includes('ecm.rx_bps.max(bpf.rx_bps)') &&
  !nssUserspace.includes('client.tx_bps.saturating_add(sample.tx_bps)') &&
  !nssUserspace.includes('client.rx_bps.saturating_add(sample.rx_bps)'),
  'ECM+BPF must roll aligned client/LAN rates together and never add precomputed rates');
assert(model.ecm_bpf_window_model.rate_filter ===
  'per_connection_generation_median_last_3_windows' &&
  model.ecm_bpf_window_model.rate_hold_ms === 2500 &&
  ecmBpf.includes('const RATE_MEDIAN_SAMPLES: usize = 3;') &&
  ecmBpf.includes('.push(raw_bps)') &&
  ecmBpf.includes('now_ms.saturating_sub(rate.end_ms) <= ECM_RATE_HOLD_MS'),
  'ECM+BPF must reject one-off batch spikes and retain the previous rate for one collection cycle');
assert(model.ecm_bpf_model.runtime_layout.time_added_type === 'uint32_t',
  'ECM+BPF must read the real uint32_t time_added field width');
assert(model.ecm_node_model.sync_barrier.quiet_ms === 20,
  'ECM snapshots must wait for a 20 ms quiet synchronization interval');
assert(model.ecm_node_model.sync_barrier.pre_and_post_counter_match_required === true,
  'ECM snapshots must validate synchronization counters before and after each read');
assert(model.ecm_node_model.sync_barrier.continuous_sync_boundary === 'return_on_request_counter_edge',
  'continuous ECM pagination must use the request edge after the previous callback');
const nssWindow = model.nss_window_model;
assert(nssWindow.high_traffic_min_ownership_percent === 90,
  'high-traffic windows must not commit below 90% ownership');
assert(nssWindow.high_traffic_ownership_basis === 'bidirectional_aggregate_overlap' &&
  nssWindow.high_traffic_overlap_counters.includes('fcs_bytes') &&
  nssWindow.high_traffic_overlap_counters.includes('packets'),
'high-traffic ownership must use aggregate byte and real-packet overlap');
assert(nssWindow.rate_clock === 'adjacent_ecm_node_polls' &&
  nssWindow.first_ecm_delta === 'publish_immediately',
  'client rates must publish on the first valid ECM delta');
assert(nssWindow.public_coverage_source ===
    'same_snapshot_displayed_client_and_lan_rates' &&
  nssWindow.raw_coverage_window_role === 'diagnostic_and_rate_fusion_guard_only' &&
  production.includes('nss_rate_coverage(&clients, &interfaces)') &&
  nssOutput.includes('percentage(client_tx_bps, lan_rx_bps)') &&
  nssOutput.includes('percentage(client_rx_bps, lan_tx_bps)'),
  'NSS public coverage must use the same displayed client and LAN rate batch');
assert(nssWindow.rate_filter === 'per_node_generation_median_last_3_windows' &&
  windowSource.includes('const NODE_RATE_MEDIAN_SAMPLES: usize = 3;') &&
  windowSource.includes('.push(rate(normalized.tx_bytes, window_ms))'),
  'ECM node rates must reject one-off synchronization and destroy-batch spikes per generation');
assert(nssWindow.rate_hold_ms === 1500 &&
  nssWindow.inter_batch_publication === 'hold_last_rate_for_one_ecm_cycle_then_zero',
  'old rates must have a bounded one-cycle hold');
assert(nssWindow.coverage_blocks_rate === false &&
  nssWindow.coverage_timeout_origin === 'first_lan_mismatch' &&
  nssWindow.coverage_timeout_reset_on_node_progress === false,
  'coverage mismatch must neither block rates nor extend its timeout on node progress');
assert(nssWindow.pending_display ===
  'publish_current_directional_percentage_retain_last_only_when_no_direction_is_reportable' &&
  windowSource.includes('last_reported: Option<(Option<u8>, Option<u8>)>') &&
  windowSource.includes('percentages_available: bool') &&
  windowSource.includes('"lan_coverage_partial"') &&
  windowSource.includes('if ownership_complete || partial_timed_out') &&
  nssOutput.includes('coverage.retained_tx_pct'),
  'coverage must publish valid partial ownership while retaining the last value only for clock-ahead batches');
assert(model.ecm_node_model.forbidden_writes.includes('defunct_all') &&
  model.ecm_node_model.forbidden_writes.includes('decelerate'), 'ECM collector must remain read-only');
assert(model.lan_clock_model.bridge_and_member_double_count_forbidden === true, 'bridge/member double counting must be forbidden');
assert(nssWindow.client_ahead_of_lan ===
  'rate_published_coverage_pending_or_counter_skew',
'material LAN clock skew must affect coverage without suppressing client rates');
assert(nssWindow.minor_direction_ahead ===
  'preserve_raw_and_return_null_direction_percentage',
'an aggregate-owned asymmetric window must preserve raw evidence without clamping its minor direction');
assert(nssWindow.idle_gap_rate_window === 'adjacent_daemon_samples',
  'new traffic after idle must not use the full idle duration as its rate window');
assert(nssWindow.fcs === 'raw_bytes_plus_real_packets_times_4', 'FCS must use real packets only');
assert(nssWindow.packet_estimation_forbidden === true, 'packet estimation must be forbidden');
assert(nssWindow.percentage_clamp_forbidden === true, 'percentage clamping must be forbidden');
assert(nssWindow.byte_backfill_forbidden === true, 'byte backfill must be forbidden');
assert(nssWindow.interface_rate_copy_forbidden === true, 'interface-rate copying must be forbidden');
assert(model.connection_metadata_model.rate_source === false &&
  model.connection_metadata_model.byte_rate_fallback === false, 'conntrack must be metadata-only');
assert(model.performance_guardrails.target_router_cpu_pct === 5, 'router CPU acceptance threshold must remain 5%');
assert(model.performance_guardrails.ui_refresh_policy.bpf === 'unrestricted_selector' &&
  JSON.stringify(model.performance_guardrails.ui_refresh_policy.nss_ecm_node) ===
    JSON.stringify([2000, 4000, 8000, 10000]) &&
  JSON.stringify(model.performance_guardrails.ui_refresh_policy.nss_ecm_bpf) ===
    JSON.stringify([2000, 4000, 8000, 10000]) &&
  model.performance_guardrails.ui_refresh_policy.auto === 'follow_effective_collector',
  'refresh policy must restrict only the two ECM schemes to the four NSS-safe cadences');
assert(model.performance_guardrails.backend_collection_policy.bpf === 'configured_interval' &&
  model.performance_guardrails.backend_collection_policy.nss_ecm_node_minimum_ms === 2000 &&
  model.performance_guardrails.backend_collection_policy.nss_ecm_bpf_minimum_ms === 2000 &&
  model.performance_guardrails.backend_collection_policy.auto === 'follow_effective_collector' &&
  nssModule.includes('pub const COLLECTION_INTERVAL_MS: u32 = 2_000;') &&
  production.includes('effective_collection_interval_ms(self.rate_owner, configured_ms)'),
  'backend scheduling must restrict only effective ECM collectors to two seconds');
assert(model.performance_guardrails.live_refresh_alignment.nss_sample_clock ===
  'published_shared_rate_window_end' &&
  model.performance_guardrails.live_refresh_alignment.nss_rpc_boundary_retry_count === 1 &&
  model.performance_guardrails.live_refresh_alignment.nss_detail_schedule_anchor ===
    'request_start' &&
  model.performance_guardrails.live_refresh_alignment.bpf_detail_schedule_anchor ===
    'request_completion_unchanged',
  'NSS live pages must avoid four-second double waits without changing x86 detail scheduling');
assert(model.performance_guardrails.animation_interpolation === false,
  'rate values must never be animated or interpolated');

for (const field of [
  'nodes.node.time_added',
  'nodes.node.adv_stats.from_data_total',
  'nodes.node.adv_stats.to_data_total',
  'nodes.node.adv_stats.from_packet_total',
  'nodes.node.adv_stats.to_packet_total'
]) {
  assert(ecm.includes(`"${field}"`), `ECM node parser must consume ${field}`);
}
assert(ecm.includes('const NODE_OUTPUT_MASK: &str = "8\\n";'), 'ECM collector must select node state mask 8');
assert(counterSource.includes('checked_mul(4)'), 'FCS normalization must multiply real packet counters by four');
assert(ecm.includes('unique_mac_owners'), 'ECM nodes must map only to unique MAC owners');
assert(ecm.includes('time_added') && ecm.includes('generation'), 'ECM node generations must be explicit');
assert(ecmBpf.includes('EcmBpfRuntime') &&
  ecmBpf.includes('program.attach(ECM_UPDATE_FUNCTION, 0)') &&
  ecmBpf.includes('ECM_NSS_ENTER_PROGRAM_NAME') &&
  ecmBpf.includes('ECM_NSS_EXIT_PROGRAM_NAME') &&
  ecmBpf.includes('resolve_ecm_layout()'),
  'ECM+BPF userspace must resolve BTF and attach totals plus NSS context probes');
assert(ecmBpfProgram.includes('ecm_db_connection_data_totals_update') &&
  ecmBpfProgram.includes('LANSPEED_ECM_CLIENTS') &&
  ecmBpfProgram.includes('LANSPEED_ECM_NSS_CONTEXT') &&
  ecmBpfProgram.includes('if !nss') &&
  ecmBpfProgram.includes('generation_ptr.cast::<u32>()') &&
  ecmBpfProgram.includes('padding: [0; 4]'),
  'ECM+BPF program must exclude slow-path ECM calls before publishing hardware counters');
assert(ebpfManifest.includes('default = ["x86-tc", "conntrack-kfunc"]') &&
  ebpfManifest.includes('x86-tc = ["tc"]') &&
  ebpfManifest.includes('nss-tc = ["tc"]') &&
  ebpfManifest.includes('nss-ecm = []') &&
  ebpfMain.includes('#[path = "x86/account.rs"]') &&
  ebpfMain.includes('#[path = "nss/account.rs"]') &&
  ebpfMain.includes('x86-tc and nss-tc are mutually exclusive'),
  'x86 TC, NSS TC, and NSS ECM eBPF programs must have separate source features');
assert(buildDriver.includes('LANSPEED_BPF_TARGET_ARCH') &&
  buildDriver.includes('command.env("AYA_BPF_TARGET_ARCH", target_arch.aya_name())') &&
  buildDriver.includes('Self::Aarch64 => "nss-tc"') &&
  buildDriver.includes('Self::X86_64 => "x86-tc"') &&
  buildDriver.includes('"nss-ecm"') && buildDriver.includes('target_arch.builds_ecm()'),
  'build driver must select platform-owned TC sources and compile ECM only for aarch64');
assert(packageMakefile.includes('LANSPEED_BPF_TARGET_ARCH="$(ARCH)"') &&
  packageMakefile.includes('LANSPEED_NSS_ECM_BPF_ENABLED:=$(filter aarch64,$(ARCH))') &&
  packageMakefile.includes('/usr/lib/bpf/lanspeed-ebpf-ecm.o'),
  'OpenWrt packaging must install the isolated ECM object only on aarch64');
assert(nssRuntime.includes('#[cfg(target_arch = "aarch64")]') &&
  nssRuntime.includes('EcmBpfRuntime::load_and_attach(ECM_BPF_OBJECT_PATH)') &&
  !nssRuntime.includes('EcmBpfRuntime::load_and_attach(FALLBACK_OBJECT_PATH)'),
  'runtime must never load ECM from a TC object or on x86');
assert(probeCollector.includes('.with_nss_probe(cfg!(target_arch = "aarch64"))') &&
  probeCollector.includes('if !self.nss_probe'),
  'x86 system probes must skip the NSS/ECM path family entirely');
for (const counterPath of model.ecm_node_model.sync_barrier.request_counter_sources) {
  assert(ecm.includes(`"${counterPath}"`), `ECM sync barrier must read ${counterPath}`);
}
assert(ecm.includes('const SYNC_QUIET_MS: u64 = 20;') &&
  ecm.includes('started.elapsed() >= Duration::from_millis(SYNC_QUIET_MS)'),
  'ECM sync barrier must accept 20 ms without a request-counter change');
assert(ecm.includes('if current != previous') &&
  ecm.includes('ECM submits the next page only after the previous page callback'),
  'ECM sync barrier must align continuous pagination on a request-counter edge');
assert(ecm.includes('let after = read_sync_counters()?;') &&
  ecm.includes('if after == barrier.counters'),
  'ECM snapshot must verify request counters again after reading the state device');
assert(ecm.includes('const SYNC_SNAPSHOT_RETRIES: usize = 2;'),
  'ECM snapshot must retry a read crossed by synchronization');

for (const quality of ['Warmup', 'Pending', 'CounterReset', 'CounterSkew']) {
  assert(windowSource.includes(`WindowQuality::${quality}`) || windowSource.includes(`Self::${quality}`),
    `window state machine must implement ${quality}`);
}
for (const reason of [
  'cold_start',
  'ecm_node_delta_published',
  'ecm_node_batch_pending',
  'lan_coverage_pending',
  'lan_coverage_timeout',
  'lan_counter_reset',
  'ecm_node_counter_reset'
]) {
  assert(windowSource.includes(`"${reason}"`), `window diagnostics must expose ${reason}`);
}
assert(windowSource.includes('const RATE_HOLD_MS: u64 = 1_500;') &&
  windowSource.includes('sample_ms.saturating_sub(published.end_ms) <= RATE_HOLD_MS'),
  'inter-batch rate retention must have a hard age limit');
assert(nssWindow.maximum_rate_window_ms === 5000 &&
  windowSource.includes('const MAX_RATE_WINDOW_MS: u64 = 5_000;') &&
  windowSource.includes('"ecm_sample_gap"'),
  'a stalled collector must rebaseline instead of publishing a long-window average');
assert(windowSource.includes('None => TrafficCounters::default()'),
  'a newly observed ECM generation must establish exactly one baseline');
assert(!windowSource.includes('settled:'),
  'a valid post-baseline node delta must not be discarded for a second settle cycle');
assert(windowSource.includes('if node_deltas.values().any(ClientDelta::progressed)') &&
  windowSource.includes('self.publish_rate('),
  'each fresh ECM node delta must publish independently of LAN coverage');
assert(windowSource.includes('const MIN_OWNERSHIP_PERCENT: u64 = 90;') &&
  windowSource.includes('ownership_ready(client_normalized, lan_normalized)') &&
  windowSource.includes('directional_coverage_ready(client_raw, lan_raw)') &&
  windowSource.includes('directional_coverage_ready(client_normalized, lan_normalized)'),
  'coverage ownership must retain the 90% aggregate threshold');
assert(windowSource.includes('struct NssCoverageBook') &&
  windowSource.includes('pending_since_ms: Option<u64>') &&
  windowSource.includes('.get_or_insert(lan.sample_ms)') &&
  !windowSource.includes('batch_pending_since_ms'),
  'coverage timeout must start once and must not be reset by ECM node progress');
assert(windowSource.includes('aggregate_client_clock_ready') &&
  windowSource.includes('aggregate_lan_ownership_ready') &&
  windowSource.includes('client_tx.min(lan_rx)') && windowSource.includes('client_rx.min(lan_tx)'),
'high-traffic alignment must require bidirectional aggregate overlap for both clock owners');
assert(windowSource.includes('client.tx_packets') && windowSource.includes('lan.rx_packets') &&
  windowSource.includes('client.rx_packets') && windowSource.includes('lan.tx_packets'),
'aggregate alignment must retain real packet ownership checks');
assert(windowSource.includes('if denominator == 0 || numerator > denominator'), 'invalid coverage must return unavailable');
assert(!windowSource.includes('.clamp('), 'NSS windows must not clamp rates or coverage');
assert(!windowSource.includes('.min(100'), 'NSS windows must not cap percentages at 100');

assert(production.includes('interface_master(&name)'), 'LAN clock selection must inspect bridge membership');
assert(production.includes('independent_lan_boundaries(&lan_roots, &masters)'),
  'runtime must expand LAN roots to independent boundaries');
assert(production.includes('interface: boundaries.join("+")'),
  'multiple disjoint LAN boundaries must be explicitly identified');
assert(production.includes('nss_rate_coverage(&clients, &interfaces)') &&
  production.includes('"nss_window".into(), window_evidence(window)') &&
  production.includes('"ecm_bpf_coverage_window".into()'),
  'NSS public coverage must use the live batch while both raw windows remain diagnostic evidence');
assert(nssOutput.includes('let coverage = &window.coverage;') &&
  nssOutput.includes('"rate_and_coverage_decoupled": true'),
  'runtime evidence must expose the decoupled rate and coverage windows');
assert(!production.includes('catch_up_nss_lan_clock') &&
  !production.includes('NSS_LAN_CATCHUP_POLL_MS'),
  'the collection loop must not block while waiting for the LAN packet clock');
assert(nssOutput.includes('"fcs_bytes_per_packet": 4'), 'diagnostics must prove exact FCS normalization');
for (const evidence of ['"raw"', '"fcs_normalized"', '"client_packets"', '"lan_packets"', '"reason"']) {
  assert(nssOutput.includes(evidence), `diagnostics must expose ${evidence}`);
}
for (const evidence of ['"sync_barrier_supported"', '"sync_barrier_wait_ms"', '"sync_snapshot_retries"']) {
  assert(nssEvidence.includes(evidence), `NSS runtime evidence must expose ${evidence}`);
}

assert(!x86Sources.includes('platform::nss') &&
  !/\b(?:Nss|Ecm)[A-Za-z0-9_]*/.test(x86Sources) &&
  !/\b(?:nss|ecm)_(?:bpf|node)::/.test(x86Sources),
  'x86/TC-BPF userspace module must not depend on NSS or ECM internals');
assert(!nssUserspace.includes('platform::x86') &&
  !nssUserspace.includes('x86::') &&
  !/\bBpfSnapshot\b/.test(nssUserspace) &&
  nssTcSnapshot.includes('pub(crate) struct NssTcSnapshot'),
  'NSS userspace must consume only its own TC snapshot contract');
assert(!/(?:ecm|nss)/i.test(x86Ebpf),
  'x86 TC eBPF sources must remain isolated from NSS programs and maps');
assert(!/x86(?:-tc|\/|::)/i.test(nssEbpf),
  'NSS eBPF sources must remain isolated from x86 programs and features');
assert(production.includes('fn nss_tc_snapshot(snapshot: &BpfSnapshot) -> NssTcSnapshot') &&
  production.includes('.map(nss_tc_snapshot)') &&
  production.includes('nss_tc_snapshot.as_ref()'),
  'only production orchestration may convert x86 TC results into the NSS-owned value contract');
assert(model.bpf_model.source_by_platform.x86_64.endsWith('/lanspeed-ebpf/src/x86/account.rs') &&
  model.bpf_model.source_by_platform.aarch64_nss.endsWith('/lanspeed-ebpf/src/nss/account.rs') &&
  model.bpf_model.feature_by_platform.x86_64 === 'x86-tc' &&
  model.bpf_model.feature_by_platform.aarch64_nss === 'nss-tc',
  'collector model must map each platform to its own TC source and feature');

assert(crypto.createHash('sha256').update(x86Coverage).digest('hex') ===
  'deaa49708a03d99dc9b05cba645b14823b52a14f14072a69a9f1aa8498d865dc',
  'x86 coverage engine must stay byte-identical to 0fe46d9');
assert(x86CoverageState.includes('CoverageRateAccumulator') &&
  x86CoverageState.includes('value.rx_bps') && x86CoverageState.includes('value.tx_bps') &&
  !x86CoverageState.includes('value.rx_bytes') && !x86CoverageState.includes('value.tx_bytes'),
  'x86 coverage state must integrate displayed rates exactly as 0fe46d9');
assert(nssBpfCoverage.includes('value.rx_bytes.unwrap_or(0)') &&
  nssBpfCoverage.includes('value.tx_bytes.unwrap_or(0)') &&
  nssBpfCoverage.includes('CoverageQuality::CounterSkew'),
  'NSS pure-BPF coverage must retain its independent cumulative-counter behavior');
assert(production.includes('x86_coverage: X86Coverage') &&
  production.includes('nss_bpf_coverage: NssBpfCoverage') &&
  production.includes('RateCollector::Bpf if report.facts.nss.present'),
  'production must checkpoint and select independent x86 and NSS-BPF coverage states');
for (const removedPath of [
  'net/lanspeedd/rust/crates/lanspeedd/src/collectors/bpf',
  'net/lanspeedd/rust/crates/lanspeedd/src/collectors/ecm_node.rs',
  'net/lanspeedd/rust/crates/lanspeedd/src/nss_window.rs',
  'net/lanspeedd/rust/crates/lanspeed-ebpf/src/ecm.rs'
]) {
  assert(!fs.existsSync(path.join(root, removedPath)), `${removedPath} must not survive the platform split`);
}

assert(policy.includes('RateCollector::NssEcmNode'), 'policy must select the ECM node owner');
assert(policy.includes('RateCollector::NssEcmBpf') && policy.includes('ecm_bpf_ready'),
  'policy must select ECM+BPF from its own kprobe health');
assert(config.includes('"nss_ecm_node" => Some(Self::NssEcmNode)') &&
  config.includes('"nss_ecm_bpf" => Some(Self::NssEcmBpf)'),
  'configuration must parse ECM and ECM+BPF modes');
assert(schema.$defs.rateCollectorMode.enum.includes('nss_ecm_node'), 'schema must publish the new NSS mode');
assert(schema.$defs.rateCollectorMode.enum.includes('nss_ecm_bpf'), 'schema must publish ECM+BPF mode');
assert(!Object.keys(schema.$defs.client.properties).some((key) => key.includes('packet') || key.includes('raw_')),
  'public client API must not expose alignment-only packet counters');

const legacyDirect = ['nss', 'ecm', 'direct'].join('_');
const legacySync = ['nss', 'conntrack', 'sync'].join('_');
const legacyCollector = ['conntrack', 'ecm', 'sync'].join('_');
const runtimeFiles = [path.join(root, 'README.md')]
  .concat(collectFiles('applications'))
  .concat(collectFiles('net/lanspeedd/src'))
  .concat(collectFiles('net/lanspeedd/rust/crates/lanspeedd/src'));
for (const file of runtimeFiles) {
  const source = fs.readFileSync(file, 'utf8');
  for (const token of [legacyDirect, legacySync, legacyCollector]) {
    assert(!source.includes(token), `${path.relative(root, file)} must not retain legacy NSS token ${token}`);
  }
}
for (const fixture of [
  'tests/fixtures/lanspeed-nss-ecm-' + 'direct.json',
  'tests/fixtures/lanspeed-nss-ecm-' + 'sync.json',
  'tests/fixtures/lanspeed-nss-ecm-' + 'sync-bpf-fallback.json'
]) {
  assert(!fs.existsSync(path.join(root, fixture)), `${fixture} must be deleted with the old implementation`);
}

const stable = alignedWindow(
  { txBytes: 98_000_000, rxBytes: 99_000_000, txPackets: 80_000, rxPackets: 81_000 },
  { rxBytes: 100_000_000, txBytes: 100_000_000, rxPackets: 82_000, txPackets: 83_000 },
  2_000
);
assert(stable.quality === 'ok', 'valid aligned traffic must publish coverage');
assert(stable.txPct >= 97 && stable.txPct <= 100, 'valid TX raw coverage must remain in the acceptance band');
assert(stable.rxPct >= 97 && stable.rxPct <= 100, 'valid RX raw coverage must remain in the acceptance band');
const skew = alignedWindow(
  { txBytes: 121_000_000, rxBytes: 1, txPackets: 120_000, rxPackets: 1 },
  { rxBytes: 100_000_000, txBytes: 10, rxPackets: 89_000, txPackets: 1 },
  1_000
);
assert(skew.quality === 'counter_skew', 'material aggregate client clock skew must remain counter_skew');
assert(skew.txBps === 0 && skew.rxBps === 0 && skew.txPct === null && skew.rxPct === null,
  'the isolated coverage model must not fabricate a percentage for counter skew');
const asymmetric = alignedWindow(
  { txBytes: 3_763_764, rxBytes: 109_645_207, txPackets: 39_568, rxPackets: 75_590 },
  { rxBytes: 3_033_545, txBytes: 109_940_744, rxPackets: 38_478, txPackets: 75_542 },
  35_000
);
assert(asymmetric.quality === 'ok', 'aggregate-owned asymmetric download must publish');
assert(asymmetric.txPct === null && asymmetric.rxPct === 99,
  'asymmetric output must keep the minor direction unavailable without clamping the valid direction');
assert(normalized(1_000, 7) === 1_028, 'FCS must add exactly four bytes per real packet');

assert(!/\btc\s+qdisc\s+del\b/.test(init), 'service lifecycle must not delete clsact qdiscs');
assert(model.bpf_model.attach.delete_clsact === false, 'BPF cleanup must preserve clsact');
assert(model.bpf_model.attach.delete_foreign_filters === false, 'BPF cleanup must preserve foreign filters');
assert(model.bpf_model.default_max_clients === 2048, 'BPF map limit must remain bounded');

console.log('lanspeed collector validation passed');
