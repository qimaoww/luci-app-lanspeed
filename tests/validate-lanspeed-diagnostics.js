#!/usr/bin/env node

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const modulePath = (name) => path.join(root,
  'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed', name);
const readModule = (name) => fs.readFileSync(modulePath(name), 'utf8');
const readFixture = (name) => JSON.parse(fs.readFileSync(path.join(root, 'tests/fixtures', name), 'utf8'));
const clone = (value) => JSON.parse(JSON.stringify(value));

const context = vm.createContext({ setTimeout, clearTimeout, Promise, Date });
vm.runInContext(`
  String.prototype.format = function() {
    var args = Array.prototype.slice.call(arguments);
    var index = 0;
    return String(this).replace(/%(?:\\.(\\d+))?([dfs])/g, function(_match, precision, type) {
      var value = args[index++];
      if (type === 's') return String(value);
      if (type === 'd') return String(Math.trunc(Number(value)));
      return Number(value).toFixed(precision === undefined ? 6 : Number(precision));
    });
  };
`, context);

const translate = (value) => String(value);
const baseclass = { extend: (value) => value };
const warningAliases = {
  software_flow_offload: 'software_flow_offload_enabled',
  fullcone: 'fullcone_detected',
  fullcone_nat_enabled: 'fullcone_detected'
};
const vocab = {
  normalizeWarningId(id) {
    return warningAliases[id] || id;
  },
  hasWarning(id) {
    id = this.normalizeWarningId(id);
    return [ 'live_metrics_unavailable', 'probe_error', 'map_full', 'map_read_failed',
      'software_flow_offload_enabled', 'fullcone_detected', 'bpf_disabled',
      'no_collect_interface', 'package_missing', 'object_missing', 'object_load_failed',
      'tc_unavailable', 'tc_unsupported', 'bpf_unavailable', 'tc_conflict',
      'tc_attach_failed', 'tc_attach_not_ready', 'runtime_not_ready',
      'bpf_runtime_not_ready', 'bpf_not_selected', 'map_not_started',
      'conntrack_unavailable', 'nss_ecm_direct_parse_errors', 'conntrack_parse_errors',
      'nss_not_present', 'lan_topology_probe_error' ].includes(id);
  },
  warningClass(id) {
    id = this.normalizeWarningId(id);
    return id === 'map_full' || id === 'probe_error' ? 'label-danger' : 'label-warning';
  },
  warningText(id) {
    id = this.normalizeWarningId(id);
    return `localized:${id}`;
  }
};
const statusCollector = {
  effectiveCollector(status, clients) {
    return clients && clients.collector ||
      status && status.evidence && status.evidence.effective_collector ||
      status && status.evidence && status.evidence.collector &&
        status.evidence.collector.primary_source || 'unsupported';
  },
  collectorLabel(value) {
    return ({ bpf: 'BPF', conntrack_netlink: 'CT-Netlink', unsupported: '不可用' })[value] || String(value || '-');
  }
};
const model = vm.compileFunction(readModule('diagnosticsModel.js'),
  [ 'baseclass', 'vocab', 'statusCollector', '_' ],
  { filename: 'diagnosticsModel.js', parsingContext: context })(
    baseclass, vocab, statusCollector, translate
  );

function fakeElement(tag, attrs, children) {
  attrs = Object.assign({}, attrs || {});
  const values = Array.isArray(children) ? children.slice() :
    children === undefined || children === null ? [] : [ children ];
  const element = {
    tag,
    attrs,
    children: values,
    parentNode: null,
    style: {},
    className: attrs.class || '',
    textContent: typeof children === 'string' ? children : '',
    listeners: {},
    hidden: Object.prototype.hasOwnProperty.call(attrs, 'hidden'),
    open: false,
    disabled: false,
    setAttribute(name, value) {
      this.attrs[name] = String(value);
      if (name === 'class') this.className = String(value);
    },
    getAttribute(name) {
      return this.attrs[name];
    },
    removeAttribute(name) {
      delete this.attrs[name];
    },
    addEventListener(name, handler) {
      this.listeners[name] = handler;
    }
  };
  values.forEach((child) => {
    if (child && typeof child === 'object') child.parentNode = element;
  });
  return element;
}

function hasClass(node, className) {
  return !!(node && typeof node.className === 'string' &&
    node.className.split(/\s+/).includes(className));
}

function findByClass(node, className) {
  if (!node || typeof node !== 'object') return null;
  if (hasClass(node, className)) return node;
  for (const child of node.children || []) {
    const found = findByClass(child, className);
    if (found) return found;
  }
  return null;
}

function findAllByClass(node, className, output = []) {
  if (!node || typeof node !== 'object') return output;
  if (hasClass(node, className)) output.push(node);
  (node.children || []).forEach((child) => findAllByClass(child, className, output));
  return output;
}

const format = {
  replaceChildren(node, children) {
    node.children = Array.isArray(children) ? children.slice() : [];
    node.children.forEach((child) => {
      if (child && typeof child === 'object') child.parentNode = node;
    });
  },
  formatRate(value) {
    return `${Math.round(Number(value) || 0)} bit/s`;
  }
};

function loadShell() {
  return vm.compileFunction(readModule('diagnosticsShell.js'),
    [ 'baseclass', 'lsTheme', 'diagnosticsStyle', 'E', '_' ],
    { filename: 'diagnosticsShell.js', parsingContext: context })(
      baseclass, { applyRoot() {} }, { CSS: 'diagnostics-css' }, fakeElement, translate
    );
}

function loadVocabulary() {
  return vm.compileFunction(readModule('vocab.js'),
    [ 'baseclass', '_' ],
    { filename: 'vocab.js', parsingContext: context })(baseclass, translate);
}

function loadRefresh(vocabulary) {
  return vm.compileFunction(readModule('diagnosticsRefresh.js'),
    [ 'baseclass', 'fmt', 'vocab', 'lsVersion', 'statusCollector', 'diagnosticsModel', 'E', '_' ],
    { filename: 'diagnosticsRefresh.js', parsingContext: context })(
      baseclass, format, vocabulary || vocab, { FULL_VERSION: '1.1.3-r1' }, statusCollector, model,
      fakeElement, translate
    );
}

function loadView(rpc, shell, refresh, navigatorValue) {
  return vm.compileFunction(readModule('diagnosticsView.js'), [
    'baseclass', 'lsRpc', 'lsVersion', 'diagnosticsModel',
    'diagnosticsShell', 'diagnosticsRefresh', 'navigator', 'document', 'window', '_'
  ], { filename: 'diagnosticsView.js', parsingContext: context })(
    baseclass, rpc, { FULL_VERSION: '1.1.3-r1' }, model,
    shell || loadShell(), refresh || loadRefresh(), navigatorValue || {},
    { body: null }, { setTimeout }, translate
  );
}

function healthyDiagnostics() {
  const value = clone(readFixture('lanspeed-diagnostics.json'));
  Object.assign(value.service, { state: 'running', ubus_connected: true });
  Object.assign(value.collection, {
    state: 'fresh', generation: 7, last_attempt_ms: 10000, last_success_ms: 9500,
    age_ms: 500, refresh_interval_ms: 1000, consecutive_failures: 0,
    retained: false, last_error: null
  });
  Object.assign(value.data_path, {
    configured_rate: 'auto', effective_rate: 'bpf', configured_connection: 'auto',
    effective_connection: 'conntrack_netlink', fallback_active: false,
    reason_code: 'bpf_available'
  });
  Object.assign(value.interfaces, {
    state: 'healthy', total: 1, available: 1, missing: 0, sample_ms: 9500
  });
  Object.assign(value.connection, {
    state: 'healthy', source: 'conntrack_netlink', entries_seen: 100,
    entries_matched: 95, parse_errors: 0
  });
  value.subsystems.forEach((item) => {
    if ([ 'bpf', 'tc', 'bpf_map', 'conntrack', 'identity', 'ubus' ].includes(item.id)) {
      item.state = 'healthy';
      item.code = null;
    }
  });
  value.alerts = [];
  value.config_issues = [];
  return value;
}

function healthyStatus(version = '1.1.3-r1') {
  const value = clone(readFixture('lanspeed-status.json'));
  value.mode = 'Full';
  value.confidence = 'high';
  value.warnings = [];
  value.refresh_interval_ms = 1000;
  value.rate_collector_mode = 'auto';
  value.conn_collector_mode = 'auto';
  value.version = version;
  value.capabilities.bpf = true;
  value.capabilities.bpf_supported = true;
  value.capabilities.bpf_package = true;
  value.capabilities.bpf_object = true;
  value.capabilities.bpf_runtime_metrics = true;
  value.capabilities.live_metrics = true;
  value.evidence = {
    effective_collector: 'bpf',
    collector: {
      primary_source: 'bpf', connection_source: 'conntrack_netlink',
      rate_reason: 'bpf_available', connection_reason: 'netlink_preferred', confidence: 'high'
    },
    probe_failures: { items: [], total: 0, truncated: false },
    bpf: {
      enabled: true, collect_target_count: 1, expected_hook_count: 2,
      attached_hook_count: 2, object_loaded: true, attach_state: 'ready',
      map_state: 'ready', last_complete_snapshot_ms: 9500,
      retained_fresh_snapshot: false, reason_code: 'ready'
    }
  };
  value.coverage = { quality: 'ok', samples: 12, window_ms: 10000, tx_pct: 96, rx_pct: 94 };
  return value;
}

function healthyHealth() {
  const value = clone(readFixture('lanspeed-health.json'));
  value.mode = 'Full';
  value.confidence = 'high';
  value.capabilities = clone(healthyStatus().capabilities);
  value.conflicts = [];
  value.warnings = [];
  value.evidence = {
    probe_failures: { items: [], total: 0, truncated: false },
    bpf: clone(healthyStatus().evidence.bpf)
  };
  return value;
}

function healthyClients() {
  const value = clone(readFixture('lanspeed-clients.json'));
  value.clients[0].sample_ms = 9500;
  value.clients[0].last_seen = 9400;
  value.clients[0].collector_mode = 'bpf';
  value.clients[0].confidence = 'high';
  value.clients[0].warnings = [];
  Object.assign(value, {
    conn_source: 'conntrack_netlink', conntrack_entries_seen: 100,
    conntrack_entries_matched: 95, conntrack_parse_errors: 0,
    tcp_conns_total: 4, udp_conns_total: 2
  });
  return value;
}

function healthyInterfaces() {
  const value = clone(readFixture('lanspeed-interfaces.json'));
  Object.assign(value.interfaces[0], {
    status: 'active', sample_ms: 9500, delta_ms: 1000,
    rx_bps: 2000, tx_bps: 1000
  });
  value.monotonic_ms = 9500;
  return value;
}

function healthyOverview() {
  const value = clone(readFixture('lanspeed-overview.json'));
  value.samples[0].sample_ms = 9500;
  return value;
}

function payloads(version) {
  return {
    diagnostics: healthyDiagnostics(), status: healthyStatus(version), health: healthyHealth(),
    clients: healthyClients(), interfaces: healthyInterfaces(), overview: healthyOverview()
  };
}

async function settled(values, overrides = {}) {
  return Promise.all(model.RPC_KEYS.map((key) => {
    if (overrides[key]) return overrides[key];
    return model.runCall({ key, call: () => Promise.resolve(values[key]) }, 1000);
  }));
}

function applyRefs(state, shell, refresh) {
  const built = shell.buildShell(state);
  state.refs = built.refs;
  refresh.refresh(state);
  return built;
}

function assertInvalid(value, fragment) {
  const result = model.validateDiagnosticsContract(value);
  assert.strictEqual(result.valid, false, `expected invalid contract: ${fragment}`);
  if (fragment) assert(result.reason.includes(fragment), result.reason);
}

async function testStrictContracts() {
  const valid = healthyDiagnostics();
  assert.strictEqual(model.validateDiagnosticsContract(valid).valid, true);

  const stale = clone(valid);
  Object.assign(stale.collection, { state: 'stale', age_ms: 4000 });
  assert.strictEqual(model.validateDiagnosticsContract(stale).valid, true,
    'v1 stale is a valid collection state');

  const degraded = clone(valid);
  Object.assign(degraded.collection, {
    state: 'degraded', retained: true, consecutive_failures: 2,
    last_error: {
      code: 'collection_failed', category: 'collection', stage: 'collect',
      retriable: true, message_public: 'The latest collection failed.'
    }
  });
  assert.strictEqual(model.validateDiagnosticsContract(degraded).valid, true);

  const cases = [
    [ (v) => { v.contract_version = 2; }, 'contract_version' ],
    [ (v) => { v.extra = true; }, '未定义' ],
    [ (v) => { v.collection.state = 'old'; }, 'collection' ],
    [ (v) => { v.collection.last_success_ms = 11000; }, '成功时间' ],
    [ (v) => { v.collection.consecutive_failures = 1; }, 'last_error' ],
    [ (v) => { v.data_path.reason_code = null; v.data_path.effective_rate = 'unsupported'; }, 'reason_code' ],
    [ (v) => { v.interfaces.available = 2; }, '计数关系' ],
    [ (v) => { v.connection.entries_matched = 101; }, '计数关系' ],
    [ (v) => { v.connection.source = null; }, 'connection' ],
    [ (v) => { v.subsystems.push(clone(v.subsystems[0])); }, 'subsystems' ],
    [ (v) => { v.alerts = Array.from({ length: 65 }, (_, i) => ({
      id: `alert_${i}`, severity: 'info', component: 'runtime', state: 'active', message_public: 'safe'
    })); }, 'alerts' ],
    [ (v) => { v.config_issues = Array.from({ length: 17 }, (_, i) => ({
      id: `issue_${i}`, severity: 'info', option: `option_${i}`, state: 'adjusted', message_public: 'safe'
    })); }, 'config_issues' ]
  ];
  cases.forEach(([ mutate, fragment ]) => {
    const value = clone(valid);
    mutate(value);
    assertInvalid(value, fragment);
  });

  const bpfCases = [
    [ (v) => { delete v.status.evidence.bpf; }, 'status.evidence.bpf' ],
    [ (v) => { delete v.health.evidence.bpf; }, 'health.evidence.bpf' ],
    [ (v) => { v.status.evidence.bpf.attached_hook_count = 1; }, 'TC 挂载计数' ],
    [ (v) => { v.status.evidence.bpf.attach_state = 'partial'; v.status.evidence.bpf.attached_hook_count = 2; }, 'TC 部分挂载' ],
    [ (v) => { v.status.evidence.bpf.map_state = 'retained'; }, '保留快照状态' ],
    [ (v) => { v.status.evidence.bpf.map_state = 'failed'; v.status.evidence.bpf.retained_fresh_snapshot = true; }, '保留快照状态' ],
    [ (v) => { v.status.evidence.bpf.attach_state = 'failed'; v.status.evidence.bpf.attached_hook_count = 0; v.status.evidence.bpf.map_state = 'ready'; }, '映射表状态' ]
  ];
  bpfCases.forEach(([ mutate, fragment ]) => {
    const value = payloads();
    mutate(value);
    const key = fragment.startsWith('health') ? 'health' : 'status';
    const result = model.validateRuntimeResponse(value[key], key);
    assert.strictEqual(result.valid, false, `expected invalid BPF contract: ${fragment}`);
    assert(result.reason.includes(fragment), result.reason);
  });

  const runtime = payloads();
  model.RPC_KEYS.filter((key) => key !== 'diagnostics').forEach((key) => {
    assert.strictEqual(model.validateRuntimeResponse(runtime[key], key).valid, true, key);
  });
  assert.strictEqual(model.validateRuntimeResponse({}, 'status').valid, false);
  const badStatus = healthyStatus();
  badStatus.capabilities.bpf = 'yes';
  assert.strictEqual(model.validateRuntimeResponse(badStatus, 'status').valid, false);
  const badClients = healthyClients();
  badClients.conntrack_entries_matched = 101;
  assert.strictEqual(model.validateRuntimeResponse(badClients, 'clients').valid, false);
  const badInterfaces = healthyInterfaces();
  badInterfaces.interfaces[0].status = 'mystery';
  assert.strictEqual(model.validateRuntimeResponse(badInterfaces, 'interfaces').valid, false);
  const badOverview = healthyOverview();
  delete badOverview.samples[0].sample_ms;
  assert.strictEqual(model.validateRuntimeResponse(badOverview, 'overview').valid, false);
  const unknownStatus = healthyStatus();
  unknownStatus.untrusted = true;
  assert.strictEqual(model.validateRuntimeResponse(unknownStatus, 'status').valid, false);
  const missingCapability = healthyStatus();
  delete missingCapability.capabilities.bpf;
  assert.strictEqual(model.validateRuntimeResponse(missingCapability, 'status').valid, false);
  const badCoverage = healthyStatus();
  badCoverage.coverage.tx_pct = 101;
  assert.strictEqual(model.validateRuntimeResponse(badCoverage, 'status').valid, false);
  const badHealthProbe = healthyHealth();
  badHealthProbe.evidence.probe_failures.total = 2;
  badHealthProbe.evidence.probe_failures.truncated = false;
  assert.strictEqual(model.validateRuntimeResponse(badHealthProbe, 'health').valid, false);
  const badClientShape = healthyClients();
  badClientShape.clients[0].private_field = 'must reject';
  assert.strictEqual(model.validateRuntimeResponse(badClientShape, 'clients').valid, false);
  const badInterfaceShape = healthyInterfaces();
  badInterfaceShape.interfaces[0].sample_ms = -1;
  assert.strictEqual(model.validateRuntimeResponse(badInterfaceShape, 'interfaces').valid, false);
  const badOverviewRelation = healthyOverview();
  badOverviewRelation.samples[0].active_clients = badOverviewRelation.samples[0].client_count + 1;
  assert.strictEqual(model.validateRuntimeResponse(badOverviewRelation, 'overview').valid, false);
  assert.strictEqual(model.validateRuntimeResponse({}, 'unknown').valid, false);

  const versionMismatch = payloads('1.1.3-r1');
  versionMismatch.status.version = '1.1.1-r6';
  const mismatchState = model.normalizeResults(await settled(versionMismatch), null, 9000, 1);
  assert.strictEqual(model.versionStateWithRpc(mismatchState, mismatchState.status.version, '1.1.3-r1').state, 'warning');

  const timeout = await model.runCall({ key: 'overview', call: () => new Promise(() => {}) }, 250);
  assert.strictEqual(timeout.ok, false);
  assert.strictEqual(timeout.error.kind, 'timeout');
  assert.strictEqual(timeout.error.code, 'TIMEOUT');
}

async function testResourceStateMachine() {
  const values = payloads();
  const good = model.normalizeResults(await settled(values), null, 10000, 1);
  assert.strictEqual(good.pageState, 'ready');
  model.RPC_KEYS.forEach((key) => assert([ 'success', 'degraded', 'empty' ].includes(good.resources[key].phase)));

  const nssVisibilityLimited = payloads();
  nssVisibilityLimited.status.mode = 'Degraded';
  nssVisibilityLimited.status.confidence = 'low';
  nssVisibilityLimited.health.mode = 'Degraded';
  nssVisibilityLimited.health.confidence = 'low';
  const nssHealthyRpc = model.normalizeResults(await settled(nssVisibilityLimited), null, 10500, 2);
  assert.strictEqual(nssHealthyRpc.resources.status.phase, 'success',
    'counter visibility must not downgrade a valid status RPC');
  assert.strictEqual(nssHealthyRpc.resources.health.phase, 'success',
    'counter visibility must not downgrade a valid health RPC');
  assert.strictEqual(nssHealthyRpc.rpc.status.ok, true);
  assert.strictEqual(nssHealthyRpc.rpc.health.ok, true);

  const emptyValues = payloads();
  emptyValues.clients = { clients: [] };
  emptyValues.interfaces = { interfaces: [] };
  emptyValues.overview = { samples: [] };
  const empty = model.normalizeResults(await settled(emptyValues), null, 11000, 2);
  assert.strictEqual(empty.pageState, 'empty');
  [ 'clients', 'interfaces', 'overview' ].forEach((key) => {
    assert.strictEqual(empty.resources[key].phase, 'empty');
    assert.strictEqual(empty.rpc[key].ok, true);
  });

  const clientFailure = await settled(values, {
    clients: Promise.resolve({ key: 'clients', ok: false,
      error: model.rpcErrorInfo(new Error('clients unavailable'), 'transport') })
  });
  const partial = model.normalizeResults(clientFailure, null, 12000, 3);
  assert.strictEqual(partial.pageState, 'partial');
  assert.strictEqual(partial.resources.clients.phase, 'error');
  assert.strictEqual(model.pathStateWithRpc(partial).state, 'bad');
  assert.strictEqual(model.connectionStateWithRpc(partial).state, 'bad');
  assert.strictEqual(model.qualityState(partial, partial.progress).state, 'good',
    'a client RPC failure does not fabricate a status-quality failure');

  const interfaceFailure = await settled(values, {
    interfaces: Promise.resolve({ key: 'interfaces', ok: false,
      error: model.rpcErrorInfo(new Error('interfaces unavailable'), 'transport') })
  });
  const partialInterfaces = model.normalizeResults(interfaceFailure, null, 13000, 4);
  assert.strictEqual(model.interfaceStateWithRpc(partialInterfaces).state, 'bad');

  const allFailedResults = model.RPC_KEYS.map((key) => ({
    key, ok: false, error: model.rpcErrorInfo(new Error(`${key} failed`), 'transport')
  }));
  const hard = model.normalizeResults(allFailedResults, null, 14000, 5);
  assert.strictEqual(hard.pageState, 'error');
  assert.strictEqual(hard.errors.length, 6);

  const invalidDiagnostics = await settled(values, {
    diagnostics: model.runCall({ key: 'diagnostics', call: () => Promise.resolve({ contract_version: 1 }) }, 1000)
  });
  const invalid = model.normalizeResults(invalidDiagnostics, null, 15000, 6);
  assert.strictEqual(invalid.resources.diagnostics.phase, 'invalid');
  assert.strictEqual(invalid.rpc.diagnostics.ok, false);
  assert.strictEqual(invalid.pageState, 'partial');

  const directInvalid = model.normalizeResults([
    { key: 'diagnostics', ok: true, value: payloads().diagnostics,
      validation: { valid: false, reason: 'synthetic invalid contract' } },
    ...(await settled(values)).filter((item) => item.key !== 'diagnostics')
  ], null, 15500, 6);
  assert.strictEqual(directInvalid.rpc.diagnostics.ok, false,
    'normalizeResults must not trust an ok flag with an invalid validation result');
  const unvalidatedInvalid = model.normalizeResults([
    { key: 'diagnostics', ok: true, value: { contract_version: 1 } },
    ...(await settled(values)).filter((item) => item.key !== 'diagnostics')
  ], null, 15600, 6);
  assert.strictEqual(unvalidatedInvalid.resources.diagnostics.phase, 'invalid',
    'normalizeResults must validate direct successful values defensively');

  const degradedValues = payloads();
  Object.assign(degradedValues.diagnostics.collection, {
    state: 'degraded', retained: true, consecutive_failures: 1,
    last_error: { code: 'collect_failed', category: 'collection', stage: 'collect',
      retriable: true, message_public: 'Collection failed.' }
  });
  const degradedState = model.normalizeResults(await settled(degradedValues), null, 15750, 7);
  assert.strictEqual(model.freshnessState(degradedState).state, 'warning');
  assert.strictEqual(model.freshnessState(degradedState).badge, '沿用旧值');

  const staleValues = payloads();
  staleValues.diagnostics.collection.state = 'stale';
  staleValues.diagnostics.collection.age_ms = 5000;
  const stale = model.normalizeResults(await settled(staleValues), null, 16000, 7);
  assert.strictEqual(stale.resources.diagnostics.phase, 'stale');
  assert.strictEqual(stale.rpc.diagnostics.ok, true, 'server stale is still a successful RPC response');
  assert.strictEqual(model.rpcState(stale, 'diagnostics').state, 'success');
  assert.strictEqual(model.diagnosticsContractState(stale).usable, true);
  assert.strictEqual(model.freshnessState(stale).state, 'warning');
  assert.strictEqual(stale.pageState, 'degraded');

  const failed = allFailedResults;
  const retained = model.normalizeResults(failed, good, 20000, 8);
  model.RPC_KEYS.forEach((key) => {
    assert.strictEqual(retained.resources[key].phase, 'stale');
    assert.strictEqual(retained.resources[key].retained, true);
    assert.strictEqual(retained.resources[key].fetchedAt, 10000);
  });
  assert.strictEqual(retained.pageState, 'degraded');
  assert.strictEqual(model.rpcState(retained, 'status').state, 'retained');
  assert.strictEqual(retained.errors.length, 6);
  assert.strictEqual(model.freshnessState(retained).oldestAgeMs, 10500,
    'retained diagnostic age must include time elapsed since the last successful RPC');

  const expired = model.normalizeResults(failed, good, 50000, 9);
  model.RPC_KEYS.forEach((key) => assert.strictEqual(expired.resources[key].phase, 'error'));
  assert.strictEqual(expired.pageState, 'error');

  const loading = loadView({}).createLoadingState(good, 10);
  assert.strictEqual(loading.pageState, 'loading');
  model.RPC_KEYS.forEach((key) => {
    assert.strictEqual(loading.resources[key].phase, 'loading');
    assert.strictEqual(loading.resources[key].usable, true);
  });
}

async function testRequestOrdering() {
  const queues = {};
  const rpc = {};
  model.RPC_KEYS.forEach((key) => {
    queues[key] = [];
    rpc[key] = () => new Promise((resolve) => queues[key].push(resolve));
  });
  const stubShell = {
    buildShell() {
      const rootNode = fakeElement('div', {}, []);
      return { root: rootNode, refs: {
        root: rootNode, btnRefresh: fakeElement('button'), btnCopy: fakeElement('button'),
        reportPreview: fakeElement('pre'), reportFeedback: fakeElement('span')
      } };
    }
  };
  const stubRefresh = { refresh() {} };
  const view = loadView(rpc, stubShell, stubRefresh);
  const initial = view.createLoadingState(null, 0);
  initial.autoStart = false;
  const rootNode = view.render(initial);
  const state = rootNode.__lanspeedDiagnosticsState;
  const first = state.reload();
  await Promise.resolve();
  await Promise.resolve();
  const second = state.reload();
  await Promise.resolve();
  await Promise.resolve();
  assert.strictEqual(state.refs.btnRefresh.disabled, true);
  assert.strictEqual(state.refs.btnCopy.disabled, true);
  const secondPayload = payloads('1.1.3-r1');
  model.RPC_KEYS.forEach((key) => queues[key][1](secondPayload[key]));
  const secondResult = await second;
  assert.strictEqual(secondResult.ignored, false);
  const firstPayload = payloads('1.1.1-r6');
  firstPayload.diagnostics.versions.daemon = '1.1.1-r6';
  firstPayload.diagnostics.versions.package = '1.1.1-r6';
  model.RPC_KEYS.forEach((key) => queues[key][0](firstPayload[key]));
  const firstResult = await first;
  assert.strictEqual(firstResult.ignored, true);
  assert.strictEqual(state.requestId, 2);
  assert.strictEqual(state.status.version, '1.1.3-r1');
  assert.strictEqual(state.diagnostics.versions.daemon, '1.1.3-r1');
  assert.strictEqual(state.refs.btnRefresh.disabled, false);
  assert.strictEqual(state.refs.root.getAttribute('aria-busy'), 'false');
}

async function testFinallyRestoresControls() {
  const values = payloads();
  const rpc = {};
  model.RPC_KEYS.forEach((key) => { rpc[key] = () => Promise.resolve(values[key]); });
  const stubShell = {
    buildShell() {
      const rootNode = fakeElement('div', {}, []);
      return { root: rootNode, refs: {
        root: rootNode, btnRefresh: fakeElement('button'), btnCopy: fakeElement('button'),
        reportPreview: fakeElement('pre'), reportFeedback: fakeElement('span')
      } };
    }
  };
  let refreshCount = 0;
  const throwingRefresh = {
    refresh() {
      refreshCount++;
      if (refreshCount === 3) throw new Error('synthetic presenter failure');
    }
  };
  const view = loadView(rpc, stubShell, throwingRefresh);
  const initial = view.createLoadingState(null, 0);
  initial.autoStart = false;
  const state = view.render(initial).__lanspeedDiagnosticsState;
  await assert.rejects(state.reload(), /synthetic presenter failure/);
  assert.strictEqual(state.refs.btnRefresh.disabled, false,
    'reload cleanup must run even when the presenter throws');
  assert.strictEqual(state.refs.btnCopy.disabled, false);
  assert.strictEqual(state.refs.root.getAttribute('aria-busy'), 'false');
}

async function testRestartControl() {
  const values = payloads();
  let restartCalls = 0;
  let diagnosticCalls = 0;
  const rpc = { restartService() { restartCalls++; return Promise.resolve(true); } };
  model.RPC_KEYS.forEach((key) => {
    rpc[key] = () => { diagnosticCalls++; return Promise.resolve(values[key]); };
  });
  const ready = model.normalizeResults(await settled(values), null, 18000, 1);
  ready.autoStart = false;
  const state = loadView(rpc).render(ready).__lanspeedDiagnosticsState;
  state.restartDelayMs = 0;
  const first = state.restartService();
  const duplicate = state.restartService();
  assert.strictEqual(first, duplicate, 'duplicate restart clicks must join the same operation');
  assert.strictEqual(state.refs.btnRestart.disabled, true);
  assert.strictEqual(state.refs.btnRefresh.disabled, true);
  assert.strictEqual(state.refs.btnCopy.disabled, true);
  assert.strictEqual(state.refs.root.getAttribute('aria-busy'), 'true');
  assert.strictEqual(state.refs.restartFeedback.hidden, false);
  assert(state.refs.restartFeedbackText.textContent.includes('只重启 LAN Speed 服务'));
  const result = await first;
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.diagnosticsReady, true);
  assert.strictEqual(restartCalls, 1);
  assert.strictEqual(diagnosticCalls, model.RPC_KEYS.length);
  assert.strictEqual(state.refs.btnRestart.disabled, false);
  assert.strictEqual(state.refs.btnRestart.textContent, '重启服务');
  assert.strictEqual(state.refs.btnRefresh.disabled, false);
  assert.strictEqual(state.refs.btnCopy.disabled, false);
  assert.strictEqual(state.refs.root.getAttribute('aria-busy'), 'false');
  assert.strictEqual(state.refs.restartFeedback.getAttribute('data-state'), 'ready');
  assert.strictEqual(state.refs.restartFeedbackTitle.textContent, '服务重启完成');

  let unexpectedDiagnostics = 0;
  const deniedRpc = { restartService() { return Promise.resolve(false); } };
  model.RPC_KEYS.forEach((key) => {
    deniedRpc[key] = () => { unexpectedDiagnostics++; return Promise.resolve(values[key]); };
  });
  ready.autoStart = false;
  const denied = loadView(deniedRpc).render(ready).__lanspeedDiagnosticsState;
  denied.restartDelayMs = 0;
  const deniedResult = await denied.restartService();
  assert.strictEqual(deniedResult.ok, false);
  assert.strictEqual(unexpectedDiagnostics, 0,
    'a rejected init action must not pretend to refresh a successful restart');
  assert.strictEqual(denied.refs.btnRestart.disabled, false);
  assert.strictEqual(denied.refs.restartFeedback.getAttribute('data-state'), 'error');
  assert.strictEqual(denied.refs.restartFeedbackTitle.textContent, '服务重启失败');
}

async function testDomAndPresenter() {
  const shell = loadShell();
  const refresh = loadRefresh(loadVocabulary());
  const view = loadView({});
  const loading = view.createLoadingState(null, 0);
  loading.reload = () => Promise.resolve();
  loading.copyReport = () => Promise.resolve();
  const loadingBuilt = applyRefs(loading, shell, refresh);
  const topSections = loadingBuilt.root.children.filter((child) => hasClass(child, 'cbi-section'));
  assert.strictEqual(topSections.length, 4);
  assert.strictEqual(findAllByClass(loadingBuilt.root, 'cbi-section').length, 4,
    'only four top-level cbi-section siblings are allowed');
  [ 'summary', 'pipeline', 'health', 'support' ].forEach((name) => {
    assert(findByClass(loadingBuilt.root, `lanspeed-diagnostics-${name}-section`));
  });
  assert.strictEqual(findByClass(loadingBuilt.root, 'lanspeed-diagnostic-card'), null);
  assert.strictEqual(findByClass(loadingBuilt.root, 'lanspeed-diagnostic-panel'), null);
  assert.strictEqual(loadingBuilt.refs.root.getAttribute('data-page-state'), 'loading');
  assert.strictEqual(loadingBuilt.refs.root.getAttribute('aria-busy'), 'true');
  assert.strictEqual(loadingBuilt.refs.btnRefresh.disabled, true, 'initial refresh must expose a real loading lock');
  assert.strictEqual(loadingBuilt.refs.btnRestart.disabled, true, 'restart must remain locked until diagnostics finish');
  assert.strictEqual(loadingBuilt.refs.btnCopy.disabled, true, 'report copy must be disabled before a completed check');
  assert.strictEqual(loadingBuilt.refs.rpcBody.children.length, 6);

  const good = model.normalizeResults(await settled(payloads()), null, 20000, 1);
  good.reload = () => Promise.resolve();
  good.copyReport = () => Promise.resolve();
  const goodBuilt = applyRefs(good, shell, refresh);
  assert.strictEqual(goodBuilt.refs.root.getAttribute('data-page-state'), 'ready');
  assert.strictEqual(goodBuilt.refs.root.getAttribute('aria-busy'), 'false');
  assert.strictEqual(goodBuilt.refs.btnRefresh.disabled, false);
  assert.strictEqual(goodBuilt.refs.btnRestart.disabled, false);
  assert.strictEqual(goodBuilt.refs.btnCopy.disabled, false);
  assert.strictEqual(goodBuilt.refs.pageNotice.style.display, 'none');
  assert.strictEqual(goodBuilt.refs.interfacesBody.children.length, 1);
  assert.strictEqual(goodBuilt.refs.subsystemsBody.children.length, 7);
  const nssRow = goodBuilt.refs.subsystemsBody.children.find((row) =>
    row.children[0] && row.children[0].textContent === 'NSS');
  assert(nssRow, 'diagnostics must retain the optional NSS subsystem row');
  assert.strictEqual(nssRow.attrs['data-state'], 'neutral',
    'an unavailable optional platform component must not render as a hard failure');
  assert.strictEqual(nssRow.children[1].textContent, '未启用');
  assert.strictEqual(nssRow.children[2].textContent, '当前设备未检测到 NSS，该组件不适用。',
    'the stable nss_not_present code must render as a localized non-error explanation');
  assert(!goodBuilt.refs.subsystemsBody.children.some((row) =>
    row.children.some((cell) => String(cell.textContent || '').includes('未识别的诊断代码'))),
  'known subsystem codes must never fall through to the unknown-code UI');
  assert(goodBuilt.refs.reportPreview.textContent.includes('运行诊断报告 v1'));
  assert(goodBuilt.refs.versionValue.textContent.includes('一致'));

  const allFailedResults = model.RPC_KEYS.map((key) => ({
    key, ok: false, error: model.rpcErrorInfo(new Error(`${key} failed`), 'transport')
  }));
  const hard = model.normalizeResults(allFailedResults, null, 21000, 2);
  hard.reload = () => Promise.resolve();
  hard.copyReport = () => Promise.resolve();
  const hardBuilt = applyRefs(hard, shell, refresh);
  assert.strictEqual(hardBuilt.refs.root.getAttribute('data-page-state'), 'error');
  assert.strictEqual(hardBuilt.refs.errorDetails.hidden, false);
  assert.strictEqual(hardBuilt.refs.errorList.children.length, 6);
  assert(hardBuilt.refs.summary.textContent.includes('无法'));

  const emptyValues = payloads();
  emptyValues.clients = { clients: [] };
  emptyValues.interfaces = { interfaces: [] };
  emptyValues.overview = { samples: [] };
  const empty = model.normalizeResults(await settled(emptyValues), null, 22000, 3);
  empty.reload = () => Promise.resolve();
  empty.copyReport = () => Promise.resolve();
  const emptyBuilt = applyRefs(empty, shell, refresh);
  assert.strictEqual(emptyBuilt.refs.root.getAttribute('data-page-state'), 'empty');
  assert(emptyBuilt.refs.pageNoticeTitle.textContent.includes('没有可用数据'));
  assert.strictEqual(model.connectionStateWithRpc(empty).state, 'warning');
  assert.strictEqual(model.interfaceStateWithRpc(empty).state, 'bad',
    'an empty interface RPC must not hide a non-empty diagnostic summary');
}

async function testSubsystemCodeContracts() {
  const vocabulary = loadVocabulary();
  const shell = loadShell();
  const refresh = loadRefresh(vocabulary);
  const labels = {
    bpf: 'BPF 运行时', tc: 'TC 挂载', bpf_map: 'BPF 映射表',
    conntrack: '连接跟踪', nss: 'NSS', identity: '客户端归属'
  };
  const cases = [
    { id: 'bpf', state: 'disabled', code: 'bpf_disabled', rowState: 'neutral' },
    { id: 'bpf', state: 'disabled', code: 'no_collect_interface', rowState: 'bad' },
    { id: 'bpf', state: 'unavailable', code: 'package_missing', rowState: 'bad' },
    { id: 'bpf', state: 'unavailable', code: 'object_missing', rowState: 'bad' },
    { id: 'bpf', state: 'unavailable', code: 'object_load_failed', rowState: 'bad' },
    { id: 'tc', state: 'unavailable', code: 'tc_unavailable', rowState: 'bad' },
    { id: 'tc', state: 'unavailable', code: 'tc_unsupported', rowState: 'bad' },
    { id: 'bpf', state: 'unavailable', code: 'bpf_unavailable', rowState: 'bad' },
    { id: 'tc', state: 'degraded', code: 'tc_conflict', rowState: 'warning' },
    { id: 'tc', state: 'degraded', code: 'tc_attach_failed', rowState: 'warning' },
    { id: 'tc', state: 'degraded', code: 'tc_attach_not_ready', rowState: 'warning' },
    { id: 'bpf', state: 'degraded', code: 'runtime_not_ready', rowState: 'warning' },
    { id: 'bpf', state: 'degraded', code: 'bpf_runtime_not_ready', rowState: 'warning' },
    { id: 'bpf', state: 'disabled', code: 'bpf_not_selected', rowState: 'neutral' },
    { id: 'bpf_map', state: 'degraded', code: 'map_read_failed', rowState: 'warning' },
    { id: 'bpf_map', state: 'unavailable', code: 'map_not_started', rowState: 'bad' },
    { id: 'conntrack', state: 'unavailable', code: 'conntrack_unavailable', rowState: 'bad' },
    { id: 'conntrack', state: 'degraded', code: 'nss_ecm_direct_parse_errors', rowState: 'warning' },
    { id: 'conntrack', state: 'degraded', code: 'conntrack_parse_errors', rowState: 'warning' },
    { id: 'nss', state: 'disabled', code: 'nss_not_present', rowState: 'neutral' },
    { id: 'identity', state: 'degraded', code: 'lan_topology_probe_error', rowState: 'warning' }
  ];
  const newlyCoveredText = {
    bpf_unavailable: 'BPF 运行环境不可用，客户端实时速率采集无法启动。',
    bpf_not_selected: '当前未选择 BPF 实时速率采集路径，该组件不参与本次采集。',
    tc_attach_not_ready: 'TC 挂载尚未就绪，BPF 实时采集可能正在启动或恢复。',
    conntrack_parse_errors: '部分 Conntrack 记录无法解析，连接统计可能不完整。',
    nss_not_present: '当前设备未检测到 NSS，该组件不适用。',
    runtime_not_ready: 'BPF 平台能力可用，但当前运行链路仍在启动或恢复。'
  };

  Object.keys(newlyCoveredText).forEach((code) => {
    assert.strictEqual(vocabulary.hasWarning(code), true, `${code} must be a known public diagnostic code`);
    assert.strictEqual(vocabulary.warningText(code), newlyCoveredText[code],
      `${code} must have a readable localized explanation`);
  });

  for (let index = 0; index < cases.length; index++) {
    const itemCase = cases[index];
    assert.strictEqual(vocabulary.hasWarning(itemCase.code), true,
      `backend subsystem code ${itemCase.code} must exist in the frontend vocabulary`);
    const values = payloads();
    const subsystem = values.diagnostics.subsystems.find((item) => item.id === itemCase.id);
    assert(subsystem, `missing fixture subsystem ${itemCase.id}`);
    Object.assign(subsystem, { state: itemCase.state, code: itemCase.code });
    const state = model.normalizeResults(await settled(values), null, 23000 + index, 10 + index);
    const built = applyRefs(state, shell, refresh);
    const row = built.refs.subsystemsBody.children.find((candidate) =>
      candidate.children[0] && candidate.children[0].textContent === labels[itemCase.id]);
    assert(row, `missing rendered subsystem row ${itemCase.id}`);
    assert.strictEqual(row.attrs['data-state'], itemCase.rowState,
      `${itemCase.state} + ${itemCase.code} must render as ${itemCase.rowState}`);
    assert.strictEqual(row.children[2].textContent, vocabulary.warningText(itemCase.code),
      `${itemCase.code} must not fall through to the unknown-code UI`);
    assert(built.refs.reportPreview.textContent.includes(`localized:${itemCase.code}`),
      `${itemCase.code} must have a localized explanation in the redacted report`);
  }

  const futureValues = payloads();
  Object.assign(futureValues.diagnostics.subsystems.find((item) => item.id === 'bpf'), {
    state: 'disabled', code: 'future_disabled_reason'
  });
  const futureState = model.normalizeResults(await settled(futureValues), null, 24000, 40);
  const futureBuilt = applyRefs(futureState, shell, refresh);
  const futureRow = futureBuilt.refs.subsystemsBody.children.find((row) =>
    row.children[0] && row.children[0].textContent === labels.bpf);
  assert.strictEqual(futureRow.attrs['data-state'], 'warning',
    'an unknown disabled reason must require attention instead of being silently neutralized');
  assert(futureRow.children[2].textContent.includes('未识别的诊断代码'));
}

async function testAlertsAndReport() {
  const values = payloads();
  values.status.warnings = [ 'live_metrics_unavailable' ];
  values.diagnostics.alerts = [ {
    id: 'live_metrics_unavailable', severity: 'critical', component: 'runtime',
    state: 'active', message_public: 'host=router.private.example client_ip=10.77.0.20'
  } ];
  values.diagnostics.data_path.configured_rate = 'password=collector-secret';
  values.diagnostics.data_path.reason_code = 'token_secret_reason';
  values.diagnostics.versions.daemon = 'router.private.example';
  values.diagnostics.versions.package = 'router.private.example';
  values.health.evidence.probe_failures = {
    items: [ { kind: 'command', source: 'command:ip_route_private', reason: 'timeout', exit_code: 1 } ],
    total: 1, truncated: false
  };
  values.interfaces.interfaces[0].name = 'secret-lan-interface';
  const state = model.normalizeResults(await settled(values), null, 30000, 1);
  const groups = model.warningGroups(state.status, state.health, state.rpc, state.diagnostics);
  assert.strictEqual(groups.all.filter((item) => item.id === 'live_metrics_unavailable').length, 1,
    'alerts must deduplicate by stable id across RPCs');
  assert.strictEqual(groups.critical.filter((item) => item.id === 'live_metrics_unavailable').length, 1,
    'deduplication must preserve the highest severity');

  const duplicateValues = payloads();
  duplicateValues.status.warnings = [
    'software_flow_offload_enabled', 'fullcone_detected', 'fullcone_nat_enabled'
  ];
  duplicateValues.health.conflicts = [
    { id: 'software_flow_offload', severity: 'info', message: 'duplicate software offload fact' },
    { id: 'fullcone', severity: 'info', message: 'duplicate fullcone fact' }
  ];
  duplicateValues.diagnostics.alerts = [
    { id: 'software_flow_offload_enabled', severity: 'warning', component: 'runtime',
      state: 'active', message_public: 'duplicate software alert' },
    { id: 'fullcone_detected', severity: 'warning', component: 'runtime',
      state: 'active', message_public: 'duplicate fullcone alert' },
    { id: 'fullcone_nat_enabled', severity: 'warning', component: 'runtime',
      state: 'active', message_public: 'duplicate fullcone config alert' }
  ];
  const duplicateState = model.normalizeResults(await settled(duplicateValues), null, 30200, 2);
  const deduplicated = model.warningGroups(duplicateState.status, duplicateState.health,
    duplicateState.rpc, duplicateState.diagnostics);
  assert.deepStrictEqual(Array.from(deduplicated.all, (item) => item.id), [
    'software_flow_offload_enabled', 'fullcone_detected'
  ], 'warning aliases from status, health conflicts and diagnostics must collapse to root causes');
  assert.strictEqual(new Set(Array.from(deduplicated.all, (item) => item.text)).size,
    deduplicated.all.length, 'deduplicated diagnostics must not render repeated warning text');
  const deduplicatedReport = model.buildReport(duplicateState, '1.1.3-r1');
  assert.strictEqual((deduplicatedReport.match(/localized:software_flow_offload_enabled/g) || []).length, 1);
  assert.strictEqual((deduplicatedReport.match(/localized:fullcone_detected/g) || []).length, 1);

  const report = model.buildReport(state, '1.1.3-r1');
  [ 'router.private.example', '10.77.0.20', 'secret-lan-interface',
    'collector-secret', 'token_secret_reason', 'command:ip_route_private', 'ip_route_private' ].forEach((secret) => {
    assert(!report.includes(secret), `report leaked ${secret}`);
  });
  assert(report.includes('接口 1 · LAN · 采集中'));
  assert(report.includes('BPF 映射表'));
  assert(report.includes('白名单状态'));
  assert(report.includes('localized:live_metrics_unavailable'));

  const mapFailureValues = payloads();
  const rawBpfSecret = 'map_read_failed /sys/fs/bpf/private-map eth1 token=bpf-secret';
  mapFailureValues.status.evidence.bpf.map_state = 'failed';
  mapFailureValues.status.evidence.bpf.last_complete_snapshot_ms = null;
  mapFailureValues.status.evidence.bpf.reason_code = 'map_read_failed';
  mapFailureValues.health.evidence.bpf = clone(mapFailureValues.status.evidence.bpf);
  mapFailureValues.diagnostics.subsystems.find((item) => item.id === 'bpf_map').state = 'unavailable';
  mapFailureValues.diagnostics.subsystems.find((item) => item.id === 'bpf_map').code = 'map_read_failed';
  mapFailureValues.diagnostics.alerts = [ {
    id: 'map_read_failed', severity: 'critical', component: 'collector', state: 'active',
    message_public: rawBpfSecret
  } ];
  const mapFailureState = model.normalizeResults(await settled(mapFailureValues), null, 30500, 2);
  const mapFailureReport = model.buildReport(mapFailureState, '1.1.3-r1');
  assert(mapFailureReport.includes('BPF 映射表'));
  assert(mapFailureReport.includes('localized:map_read_failed') || mapFailureReport.includes('映射表'));
  [ rawBpfSecret, '/sys/fs/bpf/private-map', 'eth1', 'bpf-secret' ].forEach((secret) => {
    assert(!mapFailureReport.includes(secret), `BPF report leaked ${secret}`);
  });

  const redacted = model.sanitizeReportText(
    'host=router.lan token="top secret" 192.168.1.2 00:11:22:33:44:55 user@example.com /etc/config/network'
  );
  [ 'router.lan', 'top secret', '192.168.1.2', '00:11:22:33:44:55',
    'user@example.com', '/etc/config/network' ].forEach((secret) => assert(!redacted.includes(secret)));

  let copied = '';
  const navigatorValue = { clipboard: { writeText(text) { copied = text; return Promise.resolve(); } } };
  const view = loadView({}, loadShell(), loadRefresh(), navigatorValue);
  state.autoStart = false;
  const rootNode = view.render(state);
  const viewState = rootNode.__lanspeedDiagnosticsState;
  const copyResult = await viewState.copyReport();
  assert.strictEqual(copyResult, true);
  assert.strictEqual(copied, viewState.refs.reportPreview.textContent);
  assert(copied.includes('运行诊断报告 v1'));
  assert.strictEqual(viewState.refs.btnCopy.disabled, false);
  assert.strictEqual(viewState.refs.btnCopy.getAttribute('data-state'), 'success');

  const secretFailureResults = await settled(payloads(), {
    clients: Promise.resolve({ key: 'clients', ok: false,
      error: model.rpcErrorInfo({ code: 'TOKEN_SECRET', message: 'token=do-not-copy router.private.example' }, 'transport') })
  });
  const secretFailure = model.normalizeResults(secretFailureResults, null, 31000, 2);
  const failureReport = model.buildReport(secretFailure, '1.1.3-r1');
  [ 'TOKEN_SECRET', 'do-not-copy', 'router.private.example' ].forEach((secret) => {
    assert(!failureReport.includes(secret), `RPC report leaked ${secret}`);
  });
  assert(failureReport.includes('RPC_ERROR'));

  let loadingCopy = '';
  const loadingNavigator = { clipboard: { writeText(text) { loadingCopy = text; return Promise.resolve(); } } };
  const loadingView = loadView({}, loadShell(), loadRefresh(), loadingNavigator);
  const loadingState = loadingView.createLoadingState(null, 0);
  loadingState.autoStart = false;
  const loadingRoot = loadingView.render(loadingState);
  assert.strictEqual(await loadingRoot.__lanspeedDiagnosticsState.copyReport(), false);
  assert.strictEqual(loadingCopy, '');

  const rejectingNavigator = { clipboard: { writeText() { return Promise.reject(new Error('denied')); } } };
  const rejectingView = loadView({}, loadShell(), loadRefresh(), rejectingNavigator);
  state.autoStart = false;
  const rejectingState = rejectingView.render(state).__lanspeedDiagnosticsState;
  assert.strictEqual(await rejectingState.copyReport(), false);
  assert.strictEqual(rejectingState.refs.btnCopy.disabled, false);
  assert.strictEqual(rejectingState.refs.btnCopy.getAttribute('data-state'), 'error');
}

async function run() {
  await testStrictContracts();
  await testResourceStateMachine();
  await testRequestOrdering();
  await testFinallyRestoresControls();
  await testRestartControl();
  await testDomAndPresenter();
  await testSubsystemCodeContracts();
  await testAlertsAndReport();
  console.log('validate-lanspeed-diagnostics: PASS');
}

run().catch((error) => {
  console.error(error && error.stack || error);
  process.exitCode = 1;
});
