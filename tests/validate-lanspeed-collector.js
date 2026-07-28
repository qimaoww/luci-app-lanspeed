#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');

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
const ecm = read('net/lanspeedd/rust/crates/lanspeedd/src/collectors/ecm_node.rs');
const ecmBpf = read('net/lanspeedd/rust/crates/lanspeedd/src/collectors/bpf/ecm.rs');
const ecmBpfProgram = read('net/lanspeedd/rust/crates/lanspeed-ebpf/src/ecm.rs');
const windowSource = read('net/lanspeedd/rust/crates/lanspeedd/src/nss_window.rs');
const production = read('net/lanspeedd/rust/crates/lanspeedd/src/production.rs');
const policy = read('net/lanspeedd/rust/crates/lanspeedd/src/policy.rs');
const config = read('net/lanspeedd/rust/crates/lanspeedd/src/config.rs');
const probeCollector = read('net/lanspeedd/rust/crates/lanspeedd/src/probe/collector.rs');
const ebpfManifest = read('net/lanspeedd/rust/crates/lanspeed-ebpf/Cargo.toml');
const ebpfMain = read('net/lanspeedd/rust/crates/lanspeed-ebpf/src/main.rs');
const buildDriver = read('net/lanspeedd/rust/crates/lanspeed-build/src/lib.rs');
const packageMakefile = read('net/lanspeedd/Makefile');
const init = read('net/lanspeedd/files/etc/init.d/lanspeedd');

assert(model.version === 6, 'collector model must describe the architecture-separated rate schemes');
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
  model.ownership.ecm_bpf_rate_owner === 'ecm_totals_update_kprobe_map_with_tc_rate_floor' &&
  model.ownership.ecm_bpf_rate_floor_policy === 'per_client_direction_max_never_sum',
  'ECM+BPF must keep ECM authoritative while using a non-additive TC rate floor');
assert(model.ownership.mixed_rate_owners_forbidden === true, 'mixed NSS/BPF rate ownership must be forbidden');
assert(model.ownership.manual_fallback_forbidden === true,
  'manual rate schemes must fail closed instead of silently switching');
assert(model.ownership.rate_and_coverage_windows === 'independent_with_shared_ecm_numerator' &&
  model.ownership.coverage_can_block_rate === false,
  'LAN coverage must never gate the ECM client-rate window');
assert(model.ecm_node_model.collector_mode === 'nss_ecm_node', 'new collector mode must be nss_ecm_node');
assert(model.ecm_node_model.output_mask === 8, 'ECM state must request node output only');
assert(model.ecm_node_model.counter_merge_policy === 'single_ecm_node_owner', 'ECM node counters must have one owner');
assert(model.ecm_node_model.conntrack_rate_overlay === false, 'conntrack bytes must never overlay ECM rates');
assert(model.ecm_node_model.bpf_rate_overlay === false, 'BPF bytes must never overlay ECM rates');
assert(model.ecm_bpf_model.collector_mode === 'nss_ecm_bpf' &&
  model.ecm_bpf_model.object === '/usr/lib/bpf/lanspeed-ebpf-ecm' &&
  model.ecm_bpf_model.object_role === 'isolated_ecm_kprobe_authoritative' &&
  model.ecm_bpf_model.tc_bpf_object === '/usr/lib/bpf/lanspeed-ebpf-fallback' &&
  model.ecm_bpf_model.target_arch === 'aarch64' &&
  model.ecm_bpf_model.attach === 'kprobe:ecm_db_connection_data_totals_update',
  'ECM+BPF must use its isolated aarch64 ECM object and the TC slow-path observer');
assert(model.ecm_bpf_model.counter_merge_policy ===
    'ecm_update_authoritative_tc_rate_floor_no_sum' &&
  model.ecm_bpf_model.tc_bpf_rate_overlay === 'per_client_direction_max' &&
  model.ecm_bpf_model.ecm_node_rate_overlay === false,
  'ECM+BPF must use TC-BPF only as a non-additive rate floor and never overlay ECM nodes');
assert(model.ecm_bpf_window_model.rate_clock ===
    'per_connection_ecm_event_elapsed_with_daemon_fallback' &&
  model.ecm_bpf_window_model.event_timestamp_role ===
    'rate_window_when_monotonic_fresh_and_bounded' &&
  model.ecm_bpf_window_model.torn_event_timestamp_fallback === 'adjacent_daemon_samples' &&
  ecmBpf.includes('previous.last_progress_sample_ms') &&
  ecmBpf.includes('event_window_ms.unwrap_or(collector_window_ms)') &&
  production.includes('client.tx_bps.max(sample.tx_bps)') &&
  production.includes('client.rx_bps.max(sample.rx_bps)'),
  'ECM+BPF must use bounded ECM event windows and a non-additive TC-BPF rate floor');
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
  'retain_last_aligned_percentage_until_next_aligned_window' &&
  windowSource.includes('last_reported: Option<(Option<u8>, Option<u8>)>') &&
  production.includes('coverage.retained_tx_pct'),
  'pending NSS coverage must retain only the last aligned percentage for display');
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
  model.performance_guardrails.ui_refresh_policy.nss_ecm_node === 2000 &&
  model.performance_guardrails.ui_refresh_policy.nss_ecm_bpf === 2000 &&
  model.performance_guardrails.ui_refresh_policy.auto === 'follow_effective_collector',
  'refresh policy must lock only the two ECM schemes to two seconds');
assert(model.performance_guardrails.backend_collection_policy.bpf === 'configured_interval' &&
  model.performance_guardrails.backend_collection_policy.nss_ecm_node_minimum_ms === 2000 &&
  model.performance_guardrails.backend_collection_policy.nss_ecm_bpf_minimum_ms === 2000 &&
  model.performance_guardrails.backend_collection_policy.auto === 'follow_effective_collector' &&
  production.includes('const NSS_COLLECTION_INTERVAL_MS: u32 = 2_000;') &&
  production.includes('effective_collection_interval_ms(self.rate_owner, configured_ms)'),
  'backend scheduling must restrict only effective ECM collectors to two seconds');
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
assert(ecm.includes('checked_mul(4)'), 'FCS normalization must multiply real packet counters by four');
assert(ecm.includes('unique_mac_owners'), 'ECM nodes must map only to unique MAC owners');
assert(ecm.includes('time_added') && ecm.includes('generation'), 'ECM node generations must be explicit');
assert(ecmBpf.includes('EcmBpfRuntime') &&
  ecmBpf.includes('program.attach(ECM_UPDATE_FUNCTION, 0)') &&
  ecmBpf.includes('resolve_ecm_layout()'),
  'ECM+BPF userspace must resolve BTF, load the object, and attach the ECM kprobe');
assert(ecmBpfProgram.includes('ecm_db_connection_data_totals_update') &&
  ecmBpfProgram.includes('LANSPEED_ECM_CLIENTS') &&
  ecmBpfProgram.includes('generation_ptr.cast::<u32>()') &&
  ecmBpfProgram.includes('padding: [0; 4]'),
  'ECM+BPF program must use uint32_t generation and a fully initialized map key');
assert(ebpfManifest.includes('default = ["tc", "conntrack-kfunc"]') &&
  ebpfManifest.includes('tc = []') && ebpfManifest.includes('ecm = []') &&
  ebpfMain.includes('#[cfg(feature = "tc")]') && ebpfMain.includes('#[cfg(feature = "ecm")]'),
  'TC and ECM eBPF programs must be feature-isolated');
assert(buildDriver.includes('LANSPEED_BPF_TARGET_ARCH') &&
  buildDriver.includes('command.env("AYA_BPF_TARGET_ARCH", target_arch.aya_name())') &&
  buildDriver.includes('"lanspeed-ebpf-ecm"') && buildDriver.includes('target_arch.builds_ecm()'),
  'build driver must compile ECM only for the explicit aarch64 target ABI');
assert(packageMakefile.includes('LANSPEED_BPF_TARGET_ARCH="$(ARCH)"') &&
  packageMakefile.includes('LANSPEED_NSS_ECM_BPF_ENABLED:=$(filter aarch64,$(ARCH))') &&
  packageMakefile.includes('/usr/lib/bpf/lanspeed-ebpf-ecm.o'),
  'OpenWrt packaging must install the isolated ECM object only on aarch64');
assert(production.includes('cfg!(target_arch = "aarch64")') &&
  production.includes('EcmBpfRuntime::load_and_attach(ECM_BPF_OBJECT_PATH)') &&
  !production.includes('EcmBpfRuntime::load_and_attach(FALLBACK_OBJECT_PATH)'),
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
assert(production.includes('if let Some(window) = nss_window.as_ref()') &&
  production.includes('else if let Some(window) = ecm_bpf_coverage_window.as_ref()') &&
  production.includes('coverage_response(window)'),
  'both NSS collectors must consume their independent coverage result');
assert(production.includes('let coverage = &window.coverage;') &&
  production.includes('"rate_and_coverage_decoupled": true'),
  'runtime evidence must expose the decoupled rate and coverage windows');
assert(!production.includes('catch_up_nss_lan_clock') &&
  !production.includes('NSS_LAN_CATCHUP_POLL_MS'),
  'the collection loop must not block while waiting for the LAN packet clock');
assert(production.includes('"fcs_bytes_per_packet": 4'), 'diagnostics must prove exact FCS normalization');
for (const evidence of ['"raw"', '"fcs_normalized"', '"client_packets"', '"lan_packets"', '"reason"']) {
  assert(production.includes(evidence), `diagnostics must expose ${evidence}`);
}
for (const evidence of ['"sync_barrier_supported"', '"sync_barrier_wait_ms"', '"sync_snapshot_retries"']) {
  assert(production.includes(evidence), `NSS runtime evidence must expose ${evidence}`);
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
