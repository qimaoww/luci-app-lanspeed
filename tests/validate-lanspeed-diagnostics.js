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
      'conntrack_unavailable', 'conntrack_not_sampled', 'conntrack_read_failed',
      'nss_ecm_node_parse_errors', 'conntrack_parse_errors',
      'nss_not_present', 'nss_control_not_configured', 'nss_control_verification_pending',
	  'nss_control_executor_failed', 'nss_control_no_active_client',
	  'nss_client_control_unavailable', 'nss_control_diagnostics_unavailable',
	  'lan_topology_probe_error' ].includes(id);
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
    return ({ access_edge: '自动精准', bpf: 'BPF', conntrack_netlink: 'CT-Netlink', unsupported: '不可用' })[value] || String(value || '-');
  }
};
const report = vm.compileFunction(readModule('diagnosticsReport.js'),
  [ 'baseclass', '_' ],
  { filename: 'diagnosticsReport.js', parsingContext: context })(
  baseclass, translate
);
function loadLanspeedModule(name, args, dependencies) {
  return vm.compileFunction(readModule(name), args,
    { filename: name, parsingContext: context })(...dependencies);
}
const schema = loadLanspeedModule('diagnosticsSchema.js', [ 'baseclass', '_' ],
  [ baseclass, translate ]);
const resources = loadLanspeedModule('diagnosticsResources.js',
  [ 'baseclass', 'schema', '_' ], [ baseclass, schema, translate ]);
const states = loadLanspeedModule('diagnosticsStates.js',
  [ 'baseclass', 'schema', 'resources', 'vocab', 'statusCollector', '_' ],
  [ baseclass, schema, resources, vocab, statusCollector, translate ]);
const reportModel = loadLanspeedModule('diagnosticsReportModel.js',
  [ 'baseclass', 'schema', 'resources', 'states', 'vocab', 'diagnosticsReport', '_' ],
  [ baseclass, schema, resources, states, vocab, report, translate ]);
const model = loadLanspeedModule('diagnosticsModel.js',
  [ 'baseclass', 'schema', 'resources', 'states', 'reportModel', '_' ],
  [ baseclass, schema, resources, states, reportModel, translate ]);

function createRealBaseclass() {
  function Baseclass() {}
  Baseclass.extend = function(properties) {
    function ClassConstructor() {}
    ClassConstructor.prototype = Object.create(this.prototype);
    Object.keys(properties).forEach((key) => {
      ClassConstructor.prototype[key] = properties[key];
    });
    ClassConstructor.prototype.constructor = ClassConstructor;
    ClassConstructor.extend = this.extend;
    return ClassConstructor;
  };
  return Baseclass;
}

function loadRealLanspeedModule(name, args, dependencies) {
  const ClassConstructor = vm.compileFunction(readModule(name), args,
    { filename: `real-${name}`, parsingContext: context })(...dependencies);
  return new ClassConstructor();
}

function assertRealBaseclassFacade() {
  const realBaseclass = createRealBaseclass();
  const realSchema = loadRealLanspeedModule('diagnosticsSchema.js',
    [ 'baseclass', '_' ], [ realBaseclass, translate ]);
  const realResources = loadRealLanspeedModule('diagnosticsResources.js',
    [ 'baseclass', 'schema', '_' ], [ realBaseclass, realSchema, translate ]);
  const realVocab = loadRealLanspeedModule('vocab.js',
    [ 'baseclass', '_' ], [ realBaseclass, translate ]);
  const realCollector = loadRealLanspeedModule('statusCollector.js',
    [ 'baseclass', '_' ], [ realBaseclass, translate ]);
  const realStates = loadRealLanspeedModule('diagnosticsStates.js',
    [ 'baseclass', 'schema', 'resources', 'vocab', 'statusCollector', '_' ],
    [ realBaseclass, realSchema, realResources, realVocab, realCollector, translate ]);
  const realReport = loadRealLanspeedModule('diagnosticsReport.js',
    [ 'baseclass', '_' ], [ realBaseclass, translate ]);
  const realReportModel = loadRealLanspeedModule('diagnosticsReportModel.js',
    [ 'baseclass', 'schema', 'resources', 'states', 'vocab', 'diagnosticsReport', '_' ],
    [ realBaseclass, realSchema, realResources, realStates, realVocab, realReport, translate ]);
  const realModel = loadRealLanspeedModule('diagnosticsModel.js',
    [ 'baseclass', 'schema', 'resources', 'states', 'reportModel', '_' ],
    [ realBaseclass, realSchema, realResources, realStates, realReportModel, translate ]);
  assert(Array.isArray(realModel.RPC_KEYS), 'diagnostics facade must expose prototype constants on real LuCI instances');
  assert.strictEqual(typeof realModel.normalizeResults, 'function',
    'diagnostics facade must expose prototype methods on real LuCI instances');
}

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
    },
    appendChild(child) {
      if (child && typeof child === 'object') child.parentNode = this;
      this.children.push(child);
      return child;
    },
    insertBefore(child, reference) {
      const index = this.children.indexOf(reference);
      if (child && typeof child === 'object') child.parentNode = this;
      if (index < 0) this.children.push(child);
      else this.children.splice(index, 0, child);
      return child;
    },
    removeChild(child) {
      const index = this.children.indexOf(child);
      if (index >= 0) this.children.splice(index, 1);
      if (child && typeof child === 'object') child.parentNode = null;
      return child;
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

  nssPlatform(status) {
    const platform = status && status.evidence && status.evidence.platform || {};
    if (platform.profile !== undefined && platform.profile !== null && platform.profile !== '')
      return platform.profile === 'nss_aarch64';
    if (platform.target_arch !== undefined && platform.target_arch !== null && platform.target_arch !== '')
      return String(platform.target_arch) === 'aarch64' && platform.nss_compiled !== false &&
        (!status.capabilities || status.capabilities.nss !== false);
    return false;
  },

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
	const sharedReasons = vm.compileFunction(readModule('clientControlReasonsShared.js'),
	  [ 'baseclass', '_' ], { parsingContext: context })(baseclass, translate);
	const x86Reasons = vm.compileFunction(readModule('clientControlReasonsX86.js'),
	  [ 'baseclass', '_' ], { parsingContext: context })(baseclass, translate);
	const nssReasons = vm.compileFunction(readModule('clientControlReasonsNss.js'),
	  [ 'baseclass', '_' ], { parsingContext: context })(baseclass, translate);
	const controlReasons = vm.compileFunction(readModule('clientControlReasons.js'),
	  [ 'baseclass', 'sharedReasons', 'x86Reasons', 'nssReasons', '_' ],
	  { parsingContext: context })(baseclass, sharedReasons, x86Reasons, nssReasons, translate);
	const clientControl = vm.compileFunction(readModule('clientControl.js'),
	  [ 'baseclass', 'ui', 'lsRpc', 'controlReasons', '_' ],
	  { filename: 'clientControl.js', parsingContext: context })(
	    baseclass, {}, {}, controlReasons, translate
	  );
  return vm.compileFunction(readModule('diagnosticsRefresh.js'),
    [ 'baseclass', 'fmt', 'vocab', 'lsVersion', 'statusCollector', 'diagnosticsModel', 'clientControl', 'E', '_' ],
    { filename: 'diagnosticsRefresh.js', parsingContext: context })(
      baseclass, format, vocabulary || vocab, { FULL_VERSION: '1.2.0-r2' }, statusCollector, model,
      clientControl, fakeElement, translate
    );
}

function loadView(rpc, shell, refresh, navigatorValue) {
  return vm.compileFunction(readModule('diagnosticsView.js'), [
    'baseclass', 'lsRpc', 'lsVersion', 'diagnosticsModel',
    'diagnosticsShell', 'diagnosticsRefresh', 'navigator', 'document', 'window', '_'
  ], { filename: 'diagnosticsView.js', parsingContext: context })(
    baseclass, rpc, { FULL_VERSION: '1.2.0-r2' }, model,
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

function healthyStatus(version = '1.2.0-r2') {
  const value = clone(readFixture('lanspeed-status.json'));
  value.mode = 'Full';
  value.confidence = 'high';
  value.warnings = [];
  value.refresh_interval_ms = 1000;
  value.rate_collector_mode = 'auto';
  value.access_edge_mode = 'active';
  value.conn_collector_mode = 'auto';
  value.version = version;
  value.capabilities.bpf = true;
  value.capabilities.bpf_supported = true;
  value.capabilities.bpf_package = true;
  value.capabilities.bpf_object = true;
  value.capabilities.bpf_runtime_metrics = true;
  value.capabilities.live_metrics = true;
  value.evidence = {
	platform: { profile: 'nss_aarch64', target_arch: 'aarch64', nss_compiled: true,
	  access_edge_compiled: true },
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
  value.clients[0].rate_meta = {
    version: 1, scope: 'all_frames',
    tx: { source: 'edge_port', coverage: 'partial', byte_domain: 'l2_no_fcs' },
    rx: { source: 'edge_port', coverage: 'partial', byte_domain: 'l2_no_fcs' },
    attachment: { kind: 'ethernet', ifname: 'lan2', trust: 'observed_exclusive' },
    generation: 1, window_ms: 1000, sample_ms: 9500, stale: false, reason_codes: [],
    classification: {
      state: 'aligned', sample_ms: 9500, window_ms: 2000,
      comparison_window_ms: 6000, tx_coverage_pct: 96, rx_coverage_pct: 94
    }
  };
  Object.assign(value, {
    conn_source: 'conntrack_netlink', conntrack_entries_seen: 100,
    conntrack_entries_matched: 95, conntrack_parse_errors: 0,
    tcp_conns_total: 4, udp_conns_total: 2
  });
  value.evidence.access_edge = {
    coverage: 'full', scope: 'all_frames', active_attachments: 1,
    published_attachments: 1, topology_complete: true, fdb_source: 'rtnetlink_af_bridge',
    sample_ms: 9500, reason_codes: []
  };
  value.evidence.classifier_maps = {
    ecm_nss: { entries: 2, capacity: 4096, occupancy_pct: 0, pressure: false,
      truncated: false, current_truncated: false, map_loss: false },
    tc_bpf: { entries: 1, capacity: 8192, occupancy_pct: 0, pressure: false,
      truncated: false, current_truncated: false, map_loss: false }
  };
  value.evidence.ecm_bpf = { collector_min_interval_ms: 2000 };
	value.clients[0].control = {
	  configured: true, upload_bps: 10_000_000, download_bps: 100_000_000,
	  internet_disabled: true, shaping_supported: true, blocking_supported: true,
	  max_rate_bps: 4_000_000_000, state: 'verified', queue_overflow: false
	};
	value.evidence.nss_control = {
	  state: 'verified', reason_code: null, detail_code: null,
	  shaping_supported: true, blocking_supported: true,
	  configured_clients: 1, active_clients: 1, effective_clients: 1,
	  pending_clients: 0, error_clients: 0, queue_overflow_clients: 0,
	  rate_limited_clients: 1, internet_disabled_clients: 1, block_active_clients: 1,
	  required_directions: 2, verified_directions: 2,
	  nss_verified_directions: 2, cpu_verified_directions: 1,
	  hardware_telemetry: {
	    state: 'ready', sync_count: 1, last_sync_ns: 2, igs_bytes: 3,
	    igs_packets: 4, igs_drops: 5, peer_generation: 6, peer_reassert: 7,
	    ack_latency_last_ns: 8, ack_latency_max_ns: 9, ack_received: 10,
	    ack_timeout: 11, ack_late: 12, control_generation: 13,
	    hardware_generation: 14,
	    igs_cadence: {
	      state: 'ready', samples: 15, last_interval_ns: 16,
	      min_interval_ns: 17, max_interval_ns: 18, active_nodes: 1
	    },
	    genl_caps: {
	      state: 'ready', abi_version: 1, feature_bits: 2, max_igs: 3,
	      max_peers: 4, max_client_tags: 5, supports_wifi_peer: true,
	      supports_igs_stats: true, supports_peer_query: true
	    },
	    genl_state: { state: 'ready', staged: 1, published: 1, degraded: 0 },
	    genl_stats: {
	      state: 'ready', control_generation: 1, hardware_generation: 2,
	      peer_generation: 3, peer_reassert_count: 4, igs_sync_count: 5,
	      igs_last_sync_ns: 6, igs_bytes: 7, igs_packets: 8, igs_drops: 9,
	      igs_active_nodes: 1, igs_cadence_samples: 10,
	      igs_cadence_last_ns: 11, igs_cadence_min_ns: 12,
	      igs_cadence_max_ns: 13, ack_latency_last_ns: 14,
	      ack_latency_max_ns: 15, ack_received: 16, ack_timeout: 17, ack_late: 18
	    },
	    genl_health: {
	      state: 'ready', healthy: true, control_generation: 1,
	      hardware_generation: 2
	    }
	  }
	};
  return value;
}

function healthyInterfaces() {
  const value = clone(readFixture('lanspeed-interfaces.json'));
  Object.assign(value.interfaces[0], {
    status: 'active', sample_ms: 9000, delta_ms: 1000,
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
  if (typeof state.mountPipeline !== 'function') {
    state.mountPipeline = function() {
      if (this.refs.pipelineSection) return this.refs.pipelineSection;
      const section = shell.buildPipelineSection(this.refs);
      this.refs.root.insertBefore(section, this.refs.healthSection);
      return section;
    };
  }
	if (typeof state.mountControl !== 'function') {
	  state.mountControl = function() {
	    if (this.refs.controlSection) return this.refs.controlSection;
	    const section = shell.buildControlSection(this.refs);
	    this.refs.root.insertBefore(section, this.refs.healthSection);
	    return section;
	  };
	}
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
  const unsupportedStatus = healthyStatus();
  unsupportedStatus.mode = 'Unsupported';
  unsupportedStatus.confidence = 'unsupported';
  unsupportedStatus.collector_mode = 'unsupported';
  assert.strictEqual(model.validateRuntimeResponse(unsupportedStatus, 'status').valid, true,
    'an unavailable effective collector remains a valid runtime status contract');
  const futureRateSource = healthyClients();
  futureRateSource.clients[0].rate_meta = {
    version: 1,
    scope: 'routed_observed',
    tx: { source: 'future_read_only_owner', coverage: 'degraded', byte_domain: 'ecm_data' },
    rx: { source: 'none', coverage: 'unavailable' },
    attachment: { kind: 'wifi', ifname: 'phy1-ap0', trust: 'observed_exclusive' },
    generation: 9,
    window_ms: 2000,
    sample_ms: 9500,
    stale: false,
    reason_codes: [ 'classification_domain_mismatch' ],
    classification: {
      state: 'domain_mismatch', sample_ms: 9500, window_ms: 2000,
      comparison_window_ms: 6000
    }
  };
  assert.strictEqual(model.validateRuntimeResponse(futureRateSource, 'clients').valid, true,
    'unknown machine-safe source values and omitted U/coverage must remain forward-compatible');
  const mapLossMeta = clone(futureRateSource);
  mapLossMeta.clients[0].rate_meta.classification = { state: 'map_loss' };
  assert.strictEqual(model.validateRuntimeResponse(mapLossMeta, 'clients').valid, true,
    'map_loss classification must remain valid without fabricated coverage');
  const directionalMeta = clone(futureRateSource);
  directionalMeta.clients[0].rate_meta.stale = true;
  Object.assign(directionalMeta.clients[0].rate_meta.tx, {
    sample_ms: 9000, window_ms: 1800, stale: false
  });
  directionalMeta.clients[0].rate_meta.classification = {
    state: 'counter_skew', tx_state: 'aligned', sample_ms: 9500,
    window_ms: 2000, comparison_window_ms: 6000, tx_coverage_pct: 96
  };
  assert.strictEqual(model.validateRuntimeResponse(directionalMeta, 'clients').valid, true,
    'optional per-direction rate and classification state must override compact client summaries');
  const badDirectionalRate = clone(directionalMeta);
  badDirectionalRate.clients[0].rate_meta.tx.window_ms = 0;
  assert.strictEqual(model.validateRuntimeResponse(badDirectionalRate, 'clients').valid, false,
    'per-direction windows must remain positive');
  directionalMeta.clients[0].rate_meta.classification.tx_state = 'invalid_state';
  assert.strictEqual(model.validateRuntimeResponse(directionalMeta, 'clients').valid, false,
    'per-direction classification state remains a closed machine enum');
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
	const badControlEvidence = healthyClients();
	badControlEvidence.evidence.nss_control.verified_directions = 3;
	assert.strictEqual(model.validateRuntimeResponse(badControlEvidence, 'clients').valid, false,
	  'NSS control verification counts must not exceed required directions');
	const falseVerifiedControl = healthyClients();
	falseVerifiedControl.evidence.nss_control.state = 'verified';
	falseVerifiedControl.evidence.nss_control.pending_clients = 1;
	assert.strictEqual(model.validateRuntimeResponse(falseVerifiedControl, 'clients').valid, false,
	  'a verified NSS control aggregate cannot retain pending clients');
	const badHardwareTelemetry = healthyClients();
	badHardwareTelemetry.evidence.nss_control.hardware_telemetry.genl_stats.unknown = 1;
	assert.strictEqual(model.validateRuntimeResponse(badHardwareTelemetry, 'clients').valid, false,
	  'NSS hardware telemetry must reject undeclared generic-netlink fields');
	const badIgsCadence = healthyClients();
	badIgsCadence.evidence.nss_control.hardware_telemetry.igs_cadence.samples = -1;
	assert.strictEqual(model.validateRuntimeResponse(badIgsCadence, 'clients').valid, false,
	  'NSS hardware telemetry must reject invalid IGS cadence counters');
	const unavailableIgsCadence = healthyClients();
	unavailableIgsCadence.evidence.nss_control.hardware_telemetry.igs_cadence = {
	  state: 'unavailable'
	};
	assert.strictEqual(model.validateRuntimeResponse(unavailableIgsCadence, 'clients').valid, true,
	  'missing optional IGS cadence telemetry must not invalidate the clients response');
  const badRateReason = clone(futureRateSource);
  badRateReason.clients[0].rate_meta.reason_codes = [ 'contains spaces' ];
  assert.strictEqual(model.validateRuntimeResponse(badRateReason, 'clients').valid, false);
  const badInterfaceShape = healthyInterfaces();
  badInterfaceShape.interfaces[0].sample_ms = -1;
  assert.strictEqual(model.validateRuntimeResponse(badInterfaceShape, 'interfaces').valid, false);
  const badOverviewRelation = healthyOverview();
  badOverviewRelation.samples[0].active_clients = badOverviewRelation.samples[0].client_count + 1;
  assert.strictEqual(model.validateRuntimeResponse(badOverviewRelation, 'overview').valid, false);
  assert.strictEqual(model.validateRuntimeResponse({}, 'unknown').valid, false);

  const versionMismatch = payloads('1.2.0-r2');
  versionMismatch.status.version = '1.1.1-r6';
  const mismatchState = model.normalizeResults(await settled(versionMismatch), null, 9000, 1);
  assert.strictEqual(model.versionStateWithRpc(mismatchState, mismatchState.status.version, '1.2.0-r2').state, 'warning');

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
  const goodRate = model.rateOwnerStateWithRpc(good);
  assert.strictEqual(goodRate.source, 'access_edge');
  assert.strictEqual(goodRate.state, 'good');
  assert.strictEqual(goodRate.sourceText, 'Edge-Port 2');
  assert.strictEqual(goodRate.facts.windowMs, 1000);
  assert.strictEqual(goodRate.windowText, '实际窗口约 1 秒');
  assert.strictEqual(model.accessEdgeStateWithRpc(good).value, '1/1 个接入点');
  assert.strictEqual(model.accessEdgeStateWithRpc(good).trustText, '单 MAC 观察 1');

  const routedValues = payloads();
  routedValues.status.access_edge_mode = 'off';
  routedValues.status.internet_view_mode = 'routed';
  routedValues.clients.clients[0].rate_meta.scope = 'routed_observed';
  routedValues.clients.clients[0].rate_meta.window_ms = 2000;
  [ 'tx', 'rx' ].forEach((direction) => {
    Object.assign(routedValues.clients.clients[0].rate_meta[direction], {
      source: 'fast_routed_internet', coverage: 'full', byte_domain: 'ecm_data', window_ms: 2000
    });
  });
  const routed = model.normalizeResults(await settled(routedValues), null, 10000, 1);
  const routedRate = model.rateOwnerStateWithRpc(routed);
  assert.strictEqual(routedRate.routedOwner, true);
  assert.strictEqual(routedRate.edgeOwner, false);
  assert.strictEqual(routedRate.badge, '路由视图');
  assert.strictEqual(routedRate.facts.windowMs, 2000);
  assert.strictEqual(routedRate.windowText, '实际窗口约 2 秒');
  assert(routedRate.meta.includes('实际窗口约 2 秒'),
    'routed diagnostics must expose the observed FastN+FastS batch window');
  const goodClassification = model.classificationStateWithRpc(good);
  assert.strictEqual(goodClassification.state, 'good');
  assert.strictEqual(goodClassification.badge, '运行正常');
  assert.strictEqual(goodClassification.value, '1/1 客户端已分类');
  assert.strictEqual(goodClassification.verificationText, '有线 2/2 方向已核对');
  assert.strictEqual(goodClassification.coverageText, '上行最低 96% · 下行最低 94%');
  assert.strictEqual(model.integrityStateWithRpc(good).state, 'good');
	const goodControl = model.nssControlStateWithRpc(good);
	assert.strictEqual(goodControl.state, 'good');
	assert.strictEqual(goodControl.verifiedDirections, 2);
	assert.strictEqual(goodControl.nssVerifiedDirections, 2);
	assert.strictEqual(goodControl.cpuVerifiedDirections, 1);
	assert.strictEqual(goodControl.blockActiveClients, 1);
	const controlReport = model.buildReport(good, '1.2.0-r2');
	assert(controlReport.includes('NSS 客户端控制') && controlReport.includes('NSS 2 · CPU 1'),
	  'the redacted report must include NSS control executor counts');
	assert(!controlReport.includes(good.clients.clients[0].identity_key),
	  'the NSS control report must not expose client identity');
  assert.strictEqual(model.pathStateWithRpc(good).rateSource, 'access_edge');
  assert.strictEqual(model.pathStateWithRpc(good).classifierSource, 'bpf');

  const nssCadence = payloads();
  nssCadence.diagnostics.data_path.effective_rate = 'nss_ecm_bpf';
  nssCadence.diagnostics.data_path.reason_code = 'nss_ecm_bpf_primary';
  nssCadence.status.evidence.effective_collector = 'nss_ecm_bpf';
  nssCadence.status.evidence.collector.primary_source = 'nss_ecm_bpf';
  nssCadence.status.evidence.collector.rate_reason = 'nss_ecm_bpf_primary';
  nssCadence.status.evidence.collector.effective_interval_ms = 2000;
  nssCadence.diagnostics.collection.refresh_interval_ms = 2000;
  const nssCadenceState = model.normalizeResults(await settled(nssCadence), null, 10200, 2);
  assert(model.pathStateWithRpc(nssCadenceState).meta.includes('总速率周期 1 秒') &&
    model.pathStateWithRpc(nssCadenceState).meta.includes('分类周期 2 秒'),
    'automatic diagnostics must distinguish the one-second Edge total from the two-second classifier');
  assert(model.contractCollectionState(nssCadenceState).meta.includes('刷新间隔 2 秒'),
    'NSS diagnostics collection state must expose the effective two-second timer');

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
  assert.strictEqual(model.qualityState(partial, partial.progress).state, 'bad',
    'automatic precise coverage depends on the clients RPC that carries Access Edge evidence');

  const manualValues = payloads();
  manualValues.status.rate_collector_mode = 'bpf';
  const manualClientFailure = model.normalizeResults(await settled(manualValues, {
    clients: Promise.resolve({ key: 'clients', ok: false,
      error: model.rpcErrorInfo(new Error('clients unavailable'), 'transport') })
  }), null, 12500, 4);
  assert.strictEqual(model.qualityState(manualClientFailure, manualClientFailure.progress).state, 'good',
    'a manual collector keeps using its status coverage when the clients RPC fails');

  const partialEdgeValues = payloads();
  partialEdgeValues.clients.evidence.access_edge.coverage = 'partial';
  const partialEdge = model.normalizeResults(await settled(partialEdgeValues), null, 12750, 4);
  const partialEdgeQuality = model.qualityState(partialEdge, partialEdge.progress);
  assert.strictEqual(partialEdgeQuality.state, 'good');
  assert.strictEqual(partialEdgeQuality.coverage.value, '部分');
  assert.strictEqual(model.rateOwnerStateWithRpc(partialEdge).state, 'good',
    'provable frame-scope limits must not turn a fresh total-rate owner into a fault');
  assert.strictEqual(model.rateOwnerStateWithRpc(partialEdge).badge, '正常');
  assert.strictEqual(model.accessEdgeStateWithRpc(partialEdge).badge, '正常');

  const observedPortEvidence = payloads();
  observedPortEvidence.clients.clients[0].rate_meta.tx.coverage = 'partial';
  observedPortEvidence.clients.clients[0].rate_meta.rx.coverage = 'partial';
  observedPortEvidence.clients.clients[0].rate_meta.attachment.trust = 'observed_exclusive';
  observedPortEvidence.clients.evidence.access_edge.coverage = 'partial';
  observedPortEvidence.clients.evidence.access_edge.reason_codes =
    [ 'ethernet_full_scope_unproven' ];
  const observedPort = model.normalizeResults(await settled(observedPortEvidence), null, 12755, 4);
  const observedPortIntegrity = model.integrityStateWithRpc(observedPort);
  assert(!observedPortIntegrity.reasonText.includes('缺少当前接入 generation'),
    'an observed Edge-Port owner must not be described as missing merely because proof is Partial');
  assert(observedPortIntegrity.reasonText.includes('Edge-Port'),
    'Partial Ethernet proof must say that Edge-Port still owns the displayed total');

  const directionalStaleValues = payloads();
  directionalStaleValues.clients.clients[0].rate_meta.stale = false;
  directionalStaleValues.clients.clients[0].rate_meta.tx.stale = true;
  const directionalStale = model.normalizeResults(await settled(directionalStaleValues), null, 12760, 4);
  const directionalStaleRate = model.rateOwnerStateWithRpc(directionalStale);
  assert.strictEqual(directionalStaleRate.facts.staleDirections, 1);
  assert(directionalStaleRate.description.includes('1 个方向'),
    'diagnostics must preserve which direction is stale');
  assert.strictEqual(model.integrityStateWithRpc(directionalStale).state, 'warning',
    'direction-level stale evidence must not be hidden by a false client summary');

  const missingRateMetaValues = payloads();
  delete missingRateMetaValues.clients.clients[0].rate_meta;
  const missingRateMeta = model.normalizeResults(await settled(missingRateMetaValues), null, 12775, 5);
  const missingRateOwner = model.rateOwnerStateWithRpc(missingRateMeta);
  assert.strictEqual(missingRateOwner.state, 'bad');
  assert.strictEqual(missingRateOwner.sourceText, '无来源 2');
  assert.strictEqual(missingRateOwner.coverageText, '不可用 2');
  assert.strictEqual(model.integrityStateWithRpc(missingRateMeta).unavailableDirections, 2);

  const domainMismatchValues = payloads();
  domainMismatchValues.clients.clients[0].rate_meta.classification = {
    state: 'domain_mismatch', sample_ms: 9500, window_ms: 2000,
    comparison_window_ms: 6000, tx_coverage_pct: 96, rx_coverage_pct: 94
  };
  domainMismatchValues.clients.clients[0].rate_meta.reason_codes = [ 'classification_domain_mismatch' ];
  const domainMismatch = model.normalizeResults(await settled(domainMismatchValues), null, 12800, 5);
  const domainMismatchClassification = model.classificationStateWithRpc(domainMismatch);
  assert.strictEqual(domainMismatchClassification.state, 'warning');
  assert.strictEqual(domainMismatchClassification.coverageText, '-',
    'non-aligned classifier states must not expose stale or incomparable coverage');
  assert(domainMismatchClassification.description.includes('省略未分类和覆盖率'));
  assert.strictEqual(model.integrityStateWithRpc(domainMismatch).state, 'warning');

  const missingClassificationValues = payloads();
  delete missingClassificationValues.clients.clients[0].rate_meta.classification;
  const missingClassification = model.normalizeResults(await settled(missingClassificationValues), null, 12850, 6);
  assert.strictEqual(model.classificationStateWithRpc(missingClassification).value, '0/1 客户端已分类');
  assert(model.classificationStateWithRpc(missingClassification).stateText.includes('不可用 1'));

  const mixedClassificationValues = payloads();
  mixedClassificationValues.clients.clients[0].rate_meta.classification = {
    state: 'counter_skew', tx_state: 'aligned', sample_ms: 9500, window_ms: 2000,
    comparison_window_ms: 6000, tx_coverage_pct: 96
  };
  [ '02:00:00:00:10:01', '02:00:00:00:10:02' ].forEach((mac, index) => {
    const wifi = clone(mixedClassificationValues.clients.clients[0]);
    wifi.mac = mac;
    wifi.identity_key = `${mac}@lan`;
    wifi.hostname = `wifi-${index + 1}`;
    wifi.rate_meta.scope = 'unicast';
    wifi.rate_meta.tx = { source: 'edge_wifi', coverage: 'full', byte_domain: 'station_data' };
    wifi.rate_meta.rx = { source: 'edge_wifi', coverage: 'full', byte_domain: 'station_data' };
    wifi.rate_meta.attachment = { kind: 'wifi', ifname: 'phy1-ap0', trust: 'associated_station' };
    wifi.rate_meta.classification = {
      state: 'domain_mismatch', sample_ms: 9500, window_ms: 2000,
      comparison_window_ms: 6000
    };
    mixedClassificationValues.clients.clients.push(wifi);
  });
  const mixedClassification = model.normalizeResults(await settled(mixedClassificationValues), null, 12875, 6);
  const mixedClassificationState = model.classificationStateWithRpc(mixedClassification);
  assert.strictEqual(mixedClassificationState.state, 'good',
    'expected Wi-Fi domain separation and transient wired skew do not make the classifier unhealthy');
  assert.strictEqual(mixedClassificationState.badge, '运行正常');
  assert.strictEqual(mixedClassificationState.value, '3/3 客户端已分类');
  assert.strictEqual(mixedClassificationState.verificationText,
    '有线 1/2 方向已核对 · Wi-Fi 4 方向仅观察');
  assert.strictEqual(mixedClassificationState.coverageText, '上行最低 96%');
  assert(mixedClassificationState.stateText.includes('字节口径不可比 2'));
  assert(mixedClassificationState.stateText.includes('计数错位 1'));
  assert.strictEqual(mixedClassificationState.maps.text, 'NSS 2 · CPU 1');
  assert.strictEqual(mixedClassificationState.maps.detailText, 'NSS 2/4096 · CPU 1/8192');

  const mapLossValues = payloads();
  mapLossValues.clients.evidence.classifier_maps.ecm_nss.map_loss = true;
  mapLossValues.clients.evidence.classifier_maps.ecm_nss.current_truncated = true;
  const mapLoss = model.normalizeResults(await settled(mapLossValues), null, 12900, 6);
  const mapLossClassification = model.classificationStateWithRpc(mapLoss);
  assert.strictEqual(mapLossClassification.state, 'bad');
  assert.strictEqual(mapLossClassification.badge, '映射丢失');
  assert.strictEqual(mapLossClassification.coverageText, '-',
    'map loss must suppress classification coverage even if an older aligned sample retained percentages');

  const missingMapEvidenceValues = payloads();
  delete missingMapEvidenceValues.clients.evidence.classifier_maps;
  const missingMapEvidence = model.normalizeResults(await settled(missingMapEvidenceValues), null, 12925, 6);
  const unconfirmedClassification = model.classificationStateWithRpc(missingMapEvidence);
  assert.strictEqual(unconfirmedClassification.badge, '映射未确认');
  assert.strictEqual(unconfirmedClassification.coverageText, '-',
    'classification coverage requires map completeness evidence');

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
  const secondPayload = payloads('1.2.0-r2');
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
  assert.strictEqual(state.status.version, '1.2.0-r2');
  assert.strictEqual(state.diagnostics.versions.daemon, '1.2.0-r2');
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
  assert.strictEqual(topSections.length, 3);
  assert.strictEqual(findAllByClass(loadingBuilt.root, 'cbi-section').length, 3,
    'the unclassified loading state must not preconstruct an NSS pipeline');
  [ 'summary', 'health', 'support' ].forEach((name) => {
    assert(findByClass(loadingBuilt.root, `lanspeed-diagnostics-${name}-section`));
  });
  assert.strictEqual(findByClass(loadingBuilt.root, 'lanspeed-diagnostics-pipeline-section'), null);
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
  assert.strictEqual(findAllByClass(goodBuilt.root, 'cbi-section').length, 5,
	'an explicit NSS platform must mount the precise-rate and client-control pipelines');
  assert.strictEqual(goodBuilt.refs.root.getAttribute('data-page-state'), 'ready');
  assert.strictEqual(goodBuilt.refs.root.getAttribute('aria-busy'), 'false');
  assert.strictEqual(goodBuilt.refs.btnRefresh.disabled, false);
  assert.strictEqual(goodBuilt.refs.btnRestart.disabled, false);
  assert.strictEqual(goodBuilt.refs.btnCopy.disabled, false);
  assert.strictEqual(goodBuilt.refs.pageNotice.style.display, 'none');
  assert.strictEqual(goodBuilt.refs.rpcDetails.tag, 'details');
  assert.strictEqual(goodBuilt.refs.reportDetails.tag, 'details');
  assert.strictEqual(goodBuilt.refs.rpcDetails.open, false);
  assert.strictEqual(goodBuilt.refs.reportDetails.open, false);
  assert.strictEqual(goodBuilt.refs.rateDescription.textContent, '');
  assert.strictEqual(goodBuilt.refs.edgeDescription.textContent, '');
  assert.strictEqual(goodBuilt.refs.classificationDescription.textContent, '');
  assert.strictEqual(goodBuilt.refs.integrityDescription, undefined,
    'normal capability boundaries belong only in the folded report');
  assert.strictEqual(goodBuilt.refs.rateEvidence.children.length, 4);
  assert.strictEqual(goodBuilt.refs.rateEvidence.children[0].textContent, '客户端采集覆盖率');
  assert.strictEqual(goodBuilt.refs.rateEvidence.children[1].textContent, '100%');
  assert.strictEqual(goodBuilt.refs.edgeEvidence.children.length, 4);
  assert.strictEqual(goodBuilt.refs.classificationEvidence.children.length, 6);
  assert.strictEqual(goodBuilt.refs.pipeline.children.length, 3);
	assert.strictEqual(goodBuilt.refs.controlPipeline.children.length, 4);
	assert.strictEqual(goodBuilt.refs.controlSummary.textContent, '已验证 · 1/1 个活动客户端已生效');
	assert.strictEqual(goodBuilt.refs.controlPathValue.textContent, '2/2 个方向');
	assert.strictEqual(goodBuilt.refs.controlQueueValue.textContent, '1/1 个客户端已生效');
	assert.strictEqual(goodBuilt.refs.controlBlockValue.textContent, '1/1 个客户端');
  assert.strictEqual(goodBuilt.refs.pipelineSummary.textContent, '总速率 2/2 方向 · 分类 1/1 客户端');
  assert.strictEqual(goodBuilt.refs.interfacesBody.children.length, 1);
  assert.strictEqual(goodBuilt.refs.interfacesBody.children[0].children[3].textContent, '500 毫秒',
    'interface sample timestamps must render as age relative to the interface clock');
  assert.strictEqual(states.sampleAge(9500, 9503), 0,
    'interface samples captured just after the aggregate clock must remain usable');
  assert.strictEqual(states.sampleAge(9500, 9551), null,
    'interface samples beyond the clock skew tolerance must remain unavailable');
  assert.strictEqual(goodBuilt.refs.subsystemsBody.children.length, 8);
  const nssRow = goodBuilt.refs.subsystemsBody.children.find((row) =>
    row.children[0] && row.children[0].textContent === 'NSS 加速识别');
  assert(nssRow, 'diagnostics must retain the optional NSS subsystem row');
  assert.strictEqual(nssRow.attrs['data-state'], 'neutral',
    'an unavailable optional platform component must not render as a hard failure');
  assert.strictEqual(nssRow.children[1].textContent, '未启用');
  assert.strictEqual(nssRow.children[2].textContent, '当前设备未检测到 NSS，该组件不适用。',
    'the stable nss_not_present code must render as a localized non-error explanation');
  assert(!goodBuilt.refs.subsystemsBody.children.some((row) =>
    row.children.some((cell) => String(cell.textContent || '').includes('未识别的诊断代码'))),
  'known subsystem codes must never fall through to the unknown-code UI');
  assert(goodBuilt.refs.reportPreview.textContent.includes('运行诊断报告 v2'));
  assert(goodBuilt.refs.versionValue.textContent.includes('一致'));

  const x86Values = payloads();
  x86Values.status.evidence.platform = {
    profile: 'x86_tc_bpf', target_arch: 'x86_64', nss_compiled: false,
    access_edge_compiled: false
  };
  x86Values.status.access_edge_mode = 'off';
  const x86 = model.normalizeResults(await settled(x86Values), null, 20500, 2);
  x86.reload = () => Promise.resolve();
  x86.copyReport = () => Promise.resolve();
  const x86Built = applyRefs(x86, shell, refresh);
  assert.strictEqual(findAllByClass(x86Built.root, 'cbi-section').length, 3,
    'x86 diagnostics must contain only base diagnostics, interface health, and support sections');
  assert.strictEqual(findByClass(x86Built.root, 'lanspeed-diagnostics-pipeline-section'), null);
	assert.strictEqual(findByClass(x86Built.root, 'lanspeed-diagnostics-control-section'), null);
  assert.strictEqual(x86Built.refs.pipelineSection, null);
	assert.strictEqual(x86Built.refs.controlSection, null);
  assert.strictEqual(x86Built.refs.intro.textContent, 'x86 使用原生 TC-BPF 客户端总速率。');
  assert(x86Built.refs.subsystemsBody.children.some((row) =>
    row.children[0] && row.children[0].textContent === '客户端身份识别') &&
    !x86Built.refs.subsystemsBody.children.some((row) =>
      row.children[0] && row.children[0].textContent === '客户端接入归属') &&
    x86Built.refs.reportPreview.textContent.includes('客户端身份识别') &&
    !x86Built.refs.reportPreview.textContent.includes('客户端接入归属'),
  'x86 diagnostics must label the shared identity subsystem without Access Edge wording');
  assert(!x86Built.refs.subsystemsBody.children.some((row) =>
    row.children[0] && row.children[0].textContent === 'NSS 加速识别'),
  'x86 diagnostics must discard a stale NSS subsystem row');
  assert(!x86Built.refs.reportPreview.textContent.includes('NSS') &&
    !x86Built.refs.reportPreview.textContent.includes('Access Edge'),
  'x86 diagnostic reports must not surface a stale NSS or Access Edge path');

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
    bpf: 'CPU 慢路径检测（BPF）', tc: 'CPU 路径挂载（TC）', bpf_map: '分类映射表',
    conntrack: '连接跟踪', nss: 'NSS 加速识别', nss_control: 'NSS 客户端控制',
	identity: '客户端接入归属'
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
    { id: 'conntrack', state: 'unavailable', code: 'conntrack_read_failed', rowState: 'bad' },
    { id: 'conntrack', state: 'unavailable', code: 'conntrack_not_sampled', rowState: 'bad' },
    { id: 'conntrack', state: 'degraded', code: 'nss_ecm_node_parse_errors', rowState: 'warning' },
    { id: 'conntrack', state: 'degraded', code: 'conntrack_parse_errors', rowState: 'warning' },
    { id: 'nss', state: 'disabled', code: 'nss_not_present', rowState: 'neutral' },
	{ id: 'nss_control', state: 'disabled', code: 'nss_control_not_configured', rowState: 'neutral' },
	{ id: 'nss_control', state: 'degraded', code: 'nss_control_verification_pending', rowState: 'warning' },
	{ id: 'nss_control', state: 'unavailable', code: 'nss_control_executor_failed', rowState: 'bad' },
    { id: 'identity', state: 'degraded', code: 'lan_topology_probe_error', rowState: 'warning' }
  ];
  const newlyCoveredText = {
    bpf_unavailable: 'BPF 运行环境不可用，客户端实时速率采集无法启动。',
    bpf_not_selected: '当前未选择 BPF 实时速率采集路径，该组件不参与本次采集。',
    tc_attach_not_ready: 'TC 挂载尚未就绪，BPF 实时采集可能正在启动或恢复。',
    conntrack_parse_errors: '部分 Conntrack 记录无法解析，连接统计可能不完整。',
    conntrack_not_sampled: 'NSS 速率路径不会在周期采集中读取 Conntrack；诊断请求会单独执行只读检查。',
    conntrack_read_failed: 'Conntrack 读取失败；请检查 ctnetlink、nf_conntrack_netlink 和 Procfs 回退。',
    nss_not_present: '当前设备未检测到 NSS，该组件不适用。',
	nss_control_not_configured: '当前没有配置 NSS 客户端限速或禁网规则。',
	nss_control_verification_pending: 'NSS 客户端控制已建立结构，正在等待实际路径和队列计数验证。',
	nss_control_executor_failed: 'NSS 客户端控制的队列、分类器、nft 或路径验证失败。',
    runtime_not_ready: 'BPF 平台能力可用，但当前运行链路仍在启动或恢复。'
  };

  const nssNotSampledValues = payloads();
  nssNotSampledValues.diagnostics.connection.state = 'unavailable';
  nssNotSampledValues.diagnostics.connection.source = null;
  nssNotSampledValues.diagnostics.subsystems.find((item) => item.id === 'conntrack').code = 'conntrack_not_sampled';
  nssNotSampledValues.data_path = nssNotSampledValues.diagnostics.data_path;
  const nssNotSampled = model.normalizeResults(await settled(nssNotSampledValues), null, 22900, 10);
  assert.strictEqual(model.connectionStateWithRpc(nssNotSampled).reasonCode, 'conntrack_not_sampled');

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
  const deduplicatedReport = model.buildReport(duplicateState, '1.2.0-r2');
  assert.strictEqual((deduplicatedReport.match(/localized:software_flow_offload_enabled/g) || []).length, 1);
  assert.strictEqual((deduplicatedReport.match(/localized:fullcone_detected/g) || []).length, 1);

  const report = model.buildReport(state, '1.2.0-r2');
  [ 'router.private.example', '10.77.0.20', 'secret-lan-interface',
    'collector-secret', 'token_secret_reason', 'command:ip_route_private', 'ip_route_private' ].forEach((secret) => {
    assert(!report.includes(secret), `report leaked ${secret}`);
  });
  assert(report.includes('接口 1 · LAN · 采集中'));
  assert(report.includes('分类映射表'));
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
  const mapFailureReport = model.buildReport(mapFailureState, '1.2.0-r2');
  assert(mapFailureReport.includes('分类映射表'));
  assert(mapFailureReport.includes('localized:map_read_failed') || mapFailureReport.includes('映射表'));
  [ rawBpfSecret, '/sys/fs/bpf/private-map', 'eth1', 'bpf-secret' ].forEach((secret) => {
    assert(!mapFailureReport.includes(secret), `BPF report leaked ${secret}`);
  });

  const redacted = model.sanitizeReportText(
    'host=router.lan token="top secret" 192.168.1.2 00:11:22:33:44:55 user@example.com /etc/config/network'
  );
  [ 'router.lan', 'top secret', '192.168.1.2', '00:11:22:33:44:55',
    'user@example.com', '/etc/config/network' ].forEach((secret) => assert(!redacted.includes(secret)));
  const controlRedacted = model.sanitizeReportText(
    "config client_control 'control_deadbeef' identity_key='00:11:22:33:44:55@lan' ip='192.168.1.9' upload_bps='98765432' password='device-secret'"
  );
  [ 'control_deadbeef', '00:11:22:33:44:55@lan', '192.168.1.9', '98765432', 'device-secret' ].forEach((secret) => {
    assert(!controlRedacted.includes(secret), `client_control report leaked ${secret}`);
  });
  assert.strictEqual(controlRedacted, '[CLIENT CONTROL REDACTED]');
  const longControlRedacted = model.sanitizeReportText(
    'x'.repeat(600) + "\nconfig client_control 'late-marker' identity_key='00:11:22:33:44:55@lan'"
  );
  assert.strictEqual(longControlRedacted, '[CLIENT CONTROL REDACTED]');

  let copied = '';
  const navigatorValue = { clipboard: { writeText(text) { copied = text; return Promise.resolve(); } } };
  const view = loadView({}, loadShell(), loadRefresh(), navigatorValue);
  state.autoStart = false;
  const rootNode = view.render(state);
  const viewState = rootNode.__lanspeedDiagnosticsState;
  const copyResult = await viewState.copyReport();
  assert.strictEqual(copyResult, true);
  assert.strictEqual(copied, viewState.refs.reportPreview.textContent);
  assert(copied.includes('运行诊断报告 v2'));
  assert.strictEqual(viewState.refs.btnCopy.disabled, false);
  assert.strictEqual(viewState.refs.btnCopy.getAttribute('data-state'), 'success');

  const secretFailureResults = await settled(payloads(), {
    clients: Promise.resolve({ key: 'clients', ok: false,
      error: model.rpcErrorInfo({ code: 'TOKEN_SECRET', message: 'token=do-not-copy router.private.example' }, 'transport') })
  });
  const secretFailure = model.normalizeResults(secretFailureResults, null, 31000, 2);
  const failureReport = model.buildReport(secretFailure, '1.2.0-r2');
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
  assertRealBaseclassFacade();
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
