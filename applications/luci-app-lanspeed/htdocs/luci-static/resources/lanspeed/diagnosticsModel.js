'use strict';
'require baseclass';
'require lanspeed.vocab as vocab';
'require lanspeed.statusCollector as statusCollector';

/*
 * Diagnostics is deliberately modelled as evidence, not as a second source
 * of runtime data.  Every RPC gets a Resource record and derived views must
 * account for the state of the resource they consume.
 */
var RPC_KEYS = [ 'diagnostics', 'status', 'health', 'clients', 'interfaces', 'overview' ];
var RPC_LABELS = {
	diagnostics: _('诊断契约'),
	status: _('运行状态'),
	health: _('健康检查'),
	clients: _('客户端数据'),
	interfaces: _('接口数据'),
	overview: _('历史采样')
};
var RESOURCE_PHASES = [ 'loading', 'success', 'empty', 'stale', 'degraded', 'error', 'invalid' ];
var HEALTH_STATES = [ 'healthy', 'degraded', 'unavailable', 'disabled' ];
var RUNTIME_MODES = [ 'Full', 'Degraded', 'Unsupported' ];
var CONFIDENCES = [ 'high', 'medium', 'low', 'unsupported' ];
var MAX_DIAGNOSTIC_ALERTS = 64;
var MAX_CONFIG_ISSUES = 16;
var MAX_SUBSYSTEMS = 16;
var MAX_PROBE_FAILURES = 32;
var DEFAULT_RPC_TIMEOUT_MS = 8000;
var MAX_RPC_TIMEOUT_MS = 60000;
var DEFAULT_RETAIN_MS = 30000;
var MAX_RETAIN_MS = 120000;
var CAPABILITY_KEYS = [
	'bpf', 'bpf_supported', 'bpf_package', 'bpf_object', 'bpf_runtime_metrics', 'conntrack_fallback',
	'live_metrics', 'fw4', 'nft', 'software_flow_offload', 'hardware_flow_offload',
	'nss', 'nss_ecm_offload', 'nss_ppe_offload', 'nss_ecm_direct', 'nss_bridge_mgr',
	'nss_ifb', 'nss_nsm', 'nss_dp', 'nss_mcs', 'fullcone', 'nf_conntrack_acct',
	'flowtable_counter', 'tc', 'tc_clsact', 'existing_tc_filters', 'ifb', 'sqm',
	'qosify', 'openclash', 'openclash_fake_ip', 'openclash_tun_mix',
	'openclash_redirect_dns', 'openclash_dns_chain_complete', 'openclash_router_self_proxy',
	'openclash_udp_proxy', 'openclash_ipv6', 'dae', 'homeproxy', 'lan_bridge', 'vlan',
	'wlan', 'lan_edge', 'safe_attach', 'map_full'
];
var BPF_ATTACH_STATES = [ 'not_attempted', 'ready', 'partial', 'failed' ];
var BPF_MAP_STATES = [ 'not_attempted', 'ready', 'failed', 'retained' ];
var BPF_REASON_CODES = [ 'disabled', 'no_collect_interface', 'package_missing', 'object_missing',
	'object_load_failed', 'tc_unavailable', 'tc_unsupported', 'tc_conflict', 'tc_attach_failed',
	'map_read_failed', 'ready', 'runtime_not_ready' ];
var PROBE_KINDS = [ 'command', 'file', 'uci', 'ubus', 'nss', 'probe' ];
var PROBE_REASONS = [ 'availability_failed', 'execution_failed', 'nonzero_exit', 'timeout',
	'output_truncated', 'read_failed', 'load_failed', 'query_failed', 'state_probe_failed',
	'state_unreadable', 'failed' ];

var REASON_LABELS = {
	bpf_available: _('BPF 运行时可用'),
	netlink_preferred: _('优先使用 Conntrack Netlink'),
	procfs_fallback: _('Conntrack Netlink 不可用，回退 Procfs'),
	nss_direct_available: _('NSS 直接计数可用'),
	nss_sync_available: _('NSS 同步计数可用'),
	forced_bpf: _('配置强制使用 BPF'),
	forced_bpf_unavailable: _('配置强制使用 BPF，但运行时不可用'),
	no_collect_interface: _('没有接口被分配到客户端采集'),
	forced_nss_ecm_direct: _('配置强制使用 NSS 直接计数'),
	forced_direct_fallback_to_sync: _('NSS 直接计数不可用，回退 NSS 同步计数'),
	forced_nss_ecm_direct_unavailable: _('配置强制使用 NSS 直接计数，但数据源不可用'),
	forced_nss_conntrack_sync: _('配置强制使用 NSS 同步计数'),
	forced_nss_conntrack_sync_unavailable: _('配置强制使用 NSS 同步计数，但数据源不可用'),
	dae_runtime_prefers_bpf: _('检测到 dae/daed，优先使用 BPF'),
	bpf_unavailable_nss_sync_fallback: _('BPF 不可用，回退 NSS 同步计数'),
	bpf_unavailable_nss_direct_fallback: _('BPF 不可用，回退 NSS 直接计数'),
	no_live_rate_collector: _('没有可用的实时速率采集器'),
	forced_conntrack_netlink: _('配置强制使用 Conntrack Netlink'),
	forced_conntrack_netlink_unavailable: _('配置强制使用 Conntrack Netlink，但数据源不可用'),
	forced_conntrack_procfs: _('配置强制使用 Conntrack Procfs'),
	forced_conntrack_procfs_unavailable: _('配置强制使用 Conntrack Procfs，但数据源不可用'),
	conntrack_unavailable: _('Conntrack Netlink 与 Procfs 均不可用'),
	state_unavailable_or_unreadable: _('运行状态不可读取'),
	unsupported: _('没有受支持的数据源')
};
var SUBSYSTEM_LABELS = {
	bpf: _('BPF 运行时'), tc: _('TC 挂载'), bpf_map: _('BPF 映射表'),
	conntrack: _('连接跟踪'), nss: _('NSS'), identity: _('客户端归属'), ubus: _('RPC 服务')
};
var HEALTH_REPORT_LABELS = {
	healthy: _('正常'), degraded: _('降级'), unavailable: _('不可用'), disabled: _('未启用')
};

var PROBE_REASON_LABELS = {
	availability_failed: _('组件不可用'),
	execution_failed: _('命令执行失败'),
	nonzero_exit: _('命令返回异常状态'),
	timeout: _('探测超时'),
	output_truncated: _('探测输出被截断'),
	read_failed: _('文件读取失败'),
	load_failed: _('配置读取失败'),
	query_failed: _('系统查询失败'),
	state_probe_failed: _('运行状态探测失败'),
	state_unreadable: _('运行状态不可读取'),
	failed: _('探测失败')
};

var PROBE_KIND_REPORT_LABELS = {
	command: _('命令探测'), file: _('文件探测'), uci: _('配置探测'),
	ubus: _('RPC 探测'), nss: _('NSS 探测'), probe: _('系统探测'),
	process: _('进程探测'), service: _('服务探测'), runtime: _('运行时探测'),
	sysctl: _('系统参数探测')
};
var INTERFACE_ROLE_REPORT_LABELS = {
	lan: _('LAN'), wan: _('WAN'), observe: _('观察'), excluded: _('排除'),
	unknown: _('未知'), off: _('关闭'), disabled: _('关闭')
};
var INTERFACE_STATUS_REPORT_LABELS = {
	available: _('可用'), active: _('采集中'), pending: _('等待采样'),
	missing: _('缺失'), unsupported: _('不支持'), excluded: _('已排除'), unknown: _('未知')
};
var COLLECTOR_REPORT_LABELS = {
	bpf: _('BPF'), nss_ecm_direct: _('NSS-direct'),
	'nss_ecm_direct+conntrack_ecm_sync': _('NSS-direct / NSS sync'),
	conntrack_ecm_sync: _('NSS sync'), nss_conntrack_sync: _('NSS sync'),
	conntrack_netlink: _('CT-Netlink'), conntrack_procfs: _('CT-Procfs'),
	conntrack: _('CT'), unsupported: _('不可用')
};

function asArray(value) { return Array.isArray(value) ? value : []; }
function plainObject(value) {
	return !!value && typeof value === 'object' && !Array.isArray(value);
}
function hasOwn(object, key) {
	return Object.prototype.hasOwnProperty.call(object, key);
}
function finiteNumber(value) {
	if (value === null || value === undefined || typeof value === 'boolean') return null;
	if (typeof value !== 'number' && typeof value !== 'string') return null;
	if (typeof value === 'string' && value.trim() === '') return null;
	var number = Number(value);
	return isFinite(number) ? number : null;
}
function safeInteger(value, minimum, maximum) {
	if (typeof value !== 'number' || !isFinite(value) || Math.floor(value) !== value) return false;
	if (Math.abs(value) > 9007199254740991) return false;
	if (minimum !== undefined && value < minimum) return false;
	if (maximum !== undefined && value > maximum) return false;
	return true;
}
function nonNegativeInteger(value) { return safeInteger(value, 0); }
function boundedString(value, minimum, maximum) {
	return typeof value === 'string' && value.length >= minimum && value.length <= maximum;
}
function codeString(value, nullable) {
	if (nullable && value === null) return true;
	return boundedString(value, 1, 64) && /^[A-Za-z0-9_-]+$/.test(value);
}
function enumValue(value, values) { return values.indexOf(value) !== -1; }
function onlyFields(value, fields) {
	return plainObject(value) && !Object.keys(value).some(function(key) {
		return fields.indexOf(key) === -1;
	});
}
function failure(path, message) {
	return { valid: false, path: path, reason: _('%s：%s').format(path, message) };
}
function requireFields(value, fields, path) {
	for (var i = 0; i < fields.length; i++) {
		if (!hasOwn(value, fields[i])) return failure(path + '.' + fields[i], _('字段缺失'));
	}
	return null;
}
function uniqueIds(items) {
	var seen = Object.create(null);
	return asArray(items).every(function(item) {
		var id = String(item && item.id || '');
		if (!id || seen[id]) return false;
		seen[id] = true;
		return true;
	});
}

function validatePublicError(value, path) {
	if (!plainObject(value)) return failure(path, _('错误对象无效'));
	var required = [ 'code', 'category', 'stage', 'retriable', 'message_public' ];
	var missing = requireFields(value, required, path);
	if (missing) return missing;
	if (Object.keys(value).some(function(key) { return required.indexOf(key) === -1; }))
		return failure(path, _('存在未定义字段'));
	if (!codeString(value.code, false) ||
		!enumValue(value.category, [ 'transport', 'collection', 'reload', 'serialization', 'platform' ]) ||
		!codeString(value.stage, false) || typeof value.retriable !== 'boolean' ||
		!boundedString(value.message_public, 1, 160))
		return failure(path, _('公共错误字段无效'));
	return null;
}

function validateDiagnosticsContract(value) {
	if (!plainObject(value)) return failure('diagnostics', _('响应不是对象'));
	var top = [ 'contract_version', 'service', 'collection', 'data_path', 'interfaces',
		'connection', 'subsystems', 'versions', 'alerts', 'config_issues' ];
	var missing = requireFields(value, top, 'diagnostics');
	if (missing) return missing;
	if (Object.keys(value).some(function(key) { return top.indexOf(key) === -1; }))
		return failure('diagnostics', _('存在未定义字段'));
	if (value.contract_version !== 1) return failure('diagnostics.contract_version', _('仅支持版本 1'));

	var service = value.service;
	if (!plainObject(service) || Object.keys(service).some(function(key) {
		return [ 'state', 'ubus_connected' ].indexOf(key) === -1;
	}) || !enumValue(service.state, [ 'starting', 'running', 'degraded' ]) ||
		typeof service.ubus_connected !== 'boolean')
		return failure('diagnostics.service', _('字段无效'));

	var collection = value.collection;
	var collectionKeys = [ 'state', 'generation', 'last_attempt_ms', 'last_success_ms',
		'age_ms', 'refresh_interval_ms', 'consecutive_failures', 'retained', 'last_error' ];
	if (!plainObject(collection) || Object.keys(collection).some(function(key) {
		return collectionKeys.indexOf(key) === -1;
	}) || !enumValue(collection.state, [ 'fresh', 'stale', 'degraded', 'unavailable' ]) ||
		!nonNegativeInteger(collection.generation) ||
		!(collection.last_attempt_ms === null || nonNegativeInteger(collection.last_attempt_ms)) ||
		!(collection.last_success_ms === null || nonNegativeInteger(collection.last_success_ms)) ||
		!(collection.age_ms === null || nonNegativeInteger(collection.age_ms)) ||
		!safeInteger(collection.refresh_interval_ms, 500) ||
		!safeInteger(collection.consecutive_failures, 0) || typeof collection.retained !== 'boolean')
		return failure('diagnostics.collection', _('字段无效'));
	if (collection.last_attempt_ms !== null && collection.last_success_ms !== null &&
		collection.last_success_ms > collection.last_attempt_ms)
		return failure('diagnostics.collection', _('成功时间不能晚于最近尝试'));
	if ((collection.state === 'fresh' || collection.state === 'stale') &&
		(collection.generation < 1 || collection.last_success_ms === null || collection.age_ms === null))
		return failure('diagnostics.collection', _('新鲜度状态缺少成功采样时间'));
	if (collection.retained && collection.last_success_ms === null)
		return failure('diagnostics.collection.retained', _('沿用旧值必须有成功采样'));
	if (collection.consecutive_failures > 0 && collection.last_error === null)
		return failure('diagnostics.collection.last_error', _('有连续失败时必须提供公共错误'));
	if (collection.last_error !== null) {
		var errorFailure = validatePublicError(collection.last_error, 'diagnostics.collection.last_error');
		if (errorFailure) return errorFailure;
	}

	var path = value.data_path;
	var pathKeys = [ 'configured_rate', 'effective_rate', 'configured_connection',
		'effective_connection', 'fallback_active', 'reason_code' ];
	if (!plainObject(path) || Object.keys(path).some(function(key) { return pathKeys.indexOf(key) === -1; }) ||
		!boundedString(path.configured_rate, 1, 64) || !codeString(path.effective_rate, false) ||
		!boundedString(path.configured_connection, 1, 64) || !codeString(path.effective_connection, false) ||
		typeof path.fallback_active !== 'boolean' || !codeString(path.reason_code, true))
		return failure('diagnostics.data_path', _('字段无效'));
	if ((path.effective_rate === 'unsupported' || path.effective_connection === 'unsupported') &&
		!path.reason_code)
		return failure('diagnostics.data_path.reason_code', _('不可用路径必须有原因'));

	var interfaces = value.interfaces;
	var interfaceKeys = [ 'state', 'total', 'available', 'missing', 'sample_ms' ];
	if (!plainObject(interfaces) || Object.keys(interfaces).some(function(key) {
		return interfaceKeys.indexOf(key) === -1;
	}) || !enumValue(interfaces.state, HEALTH_STATES) ||
		!nonNegativeInteger(interfaces.total) || !nonNegativeInteger(interfaces.available) ||
		!nonNegativeInteger(interfaces.missing) ||
		!(interfaces.sample_ms === null || nonNegativeInteger(interfaces.sample_ms)) ||
		interfaces.available > interfaces.total || interfaces.missing > interfaces.total ||
		interfaces.available + interfaces.missing > interfaces.total)
		return failure('diagnostics.interfaces', _('字段或计数关系无效'));

	var connection = value.connection;
	var connectionKeys = [ 'state', 'source', 'entries_seen', 'entries_matched', 'parse_errors' ];
	if (!plainObject(connection) || Object.keys(connection).some(function(key) {
		return connectionKeys.indexOf(key) === -1;
	}) || !enumValue(connection.state, HEALTH_STATES) ||
		!(connection.source === null || codeString(connection.source, false)) ||
		!(connection.entries_seen === null || nonNegativeInteger(connection.entries_seen)) ||
		!(connection.entries_matched === null || nonNegativeInteger(connection.entries_matched)) ||
		!(connection.parse_errors === null || nonNegativeInteger(connection.parse_errors)) ||
		(connection.entries_seen !== null && connection.entries_matched !== null &&
			connection.entries_matched > connection.entries_seen) ||
		(connection.state === 'healthy' && !connection.source))
		return failure('diagnostics.connection', _('字段或计数关系无效'));

	if (!Array.isArray(value.subsystems) || value.subsystems.length > MAX_SUBSYSTEMS ||
		!uniqueIds(value.subsystems) || !value.subsystems.every(function(item) {
		return plainObject(item) && Object.keys(item).every(function(key) {
			return [ 'id', 'state', 'code' ].indexOf(key) !== -1;
		}) && codeString(item.id, false) && enumValue(item.state, HEALTH_STATES) &&
			(item.code === null || codeString(item.code, false));
	})) return failure('diagnostics.subsystems', _('字段无效'));

	var versions = value.versions;
	var versionKeys = [ 'daemon', 'package', 'contract_version', 'schema_version' ];
	if (!plainObject(versions) || Object.keys(versions).some(function(key) {
		return versionKeys.indexOf(key) === -1;
	}) || !boundedString(versions.daemon, 1, 64) || !boundedString(versions.package, 1, 64) ||
		versions.contract_version !== 1 || versions.schema_version !== 1)
		return failure('diagnostics.versions', _('字段无效'));

	if (!Array.isArray(value.alerts) || value.alerts.length > MAX_DIAGNOSTIC_ALERTS ||
		!uniqueIds(value.alerts) || !value.alerts.every(function(item) {
		return plainObject(item) && Object.keys(item).every(function(key) {
			return [ 'id', 'severity', 'component', 'state', 'message_public' ].indexOf(key) !== -1;
		}) && codeString(item.id, false) && enumValue(item.severity, [ 'info', 'warning', 'critical' ]) &&
			codeString(item.component, false) && item.state === 'active' &&
			boundedString(item.message_public, 1, 160);
	})) return failure('diagnostics.alerts', _('字段无效'));
	if (!Array.isArray(value.config_issues) || value.config_issues.length > MAX_CONFIG_ISSUES ||
		!uniqueIds(value.config_issues) || !value.config_issues.every(function(item) {
		return plainObject(item) && Object.keys(item).every(function(key) {
			return [ 'id', 'severity', 'option', 'state', 'message_public' ].indexOf(key) !== -1;
		}) && codeString(item.id, false) && enumValue(item.severity, [ 'info', 'warning', 'critical' ]) &&
			codeString(item.option, false) && enumValue(item.state,
				[ 'adjusted', 'compatibility_only', 'required', 'ineffective' ]) &&
			boundedString(item.message_public, 1, 160);
	})) return failure('diagnostics.config_issues', _('字段无效'));

	return { valid: true, reason: '', path: '', value: value };
}

function optionalIntegers(value, fields, minimums) {
	return fields.every(function(field) {
		if (!hasOwn(value, field)) return true;
		return safeInteger(value[field], minimums && hasOwn(minimums, field) ? minimums[field] : 0);
	});
}
function validateCapabilities(value, path) {
	if (!onlyFields(value, CAPABILITY_KEYS)) return failure(path, _('能力字段无效'));
	var missing = requireFields(value, CAPABILITY_KEYS, path);
	if (missing) return missing;
	if (!CAPABILITY_KEYS.every(function(key) { return typeof value[key] === 'boolean'; }))
		return failure(path, _('能力值必须是布尔值'));
	return null;
}
function validateProbeFailures(value, path) {
	if (!onlyFields(value, [ 'items', 'total', 'truncated' ])) return failure(path, _('探测失败汇总无效'));
	var missing = requireFields(value, [ 'items', 'total', 'truncated' ], path);
	if (missing) return missing;
	if (!Array.isArray(value.items) || value.items.length > MAX_PROBE_FAILURES ||
		!nonNegativeInteger(value.total) || value.total < value.items.length ||
		typeof value.truncated !== 'boolean' || (value.total > value.items.length && !value.truncated) ||
		!value.items.every(function(item) {
			return onlyFields(item, [ 'kind', 'source', 'reason', 'exit_code' ]) &&
				enumValue(item.kind, PROBE_KINDS) && boundedString(item.source, 1, 160) &&
				/^(command|file|uci|ubus|nss|probe):[A-Za-z0-9_.\/<\>-]+$/.test(item.source) &&
				enumValue(item.reason, PROBE_REASONS) &&
				(!hasOwn(item, 'exit_code') || safeInteger(item.exit_code));
		})) return failure(path, _('探测失败字段无效'));
	return null;
}
function validateBpfEvidence(value, path) {
	var fields = [ 'enabled', 'collect_target_count', 'expected_hook_count', 'attached_hook_count',
		'object_loaded', 'attach_state', 'map_state', 'last_complete_snapshot_ms',
		'retained_fresh_snapshot', 'reason_code' ];
	if (!onlyFields(value, fields)) return failure(path, _('BPF 证据字段无效'));
	var missing = requireFields(value, fields, path);
	if (missing) return missing;
	if (typeof value.enabled !== 'boolean' || typeof value.object_loaded !== 'boolean' ||
		typeof value.retained_fresh_snapshot !== 'boolean' ||
		!nonNegativeInteger(value.collect_target_count) || !nonNegativeInteger(value.expected_hook_count) ||
		!nonNegativeInteger(value.attached_hook_count) || value.attached_hook_count > value.expected_hook_count ||
		!enumValue(value.attach_state, BPF_ATTACH_STATES) || !enumValue(value.map_state, BPF_MAP_STATES) ||
		!enumValue(value.reason_code, BPF_REASON_CODES) ||
		!(value.last_complete_snapshot_ms === null || nonNegativeInteger(value.last_complete_snapshot_ms)))
		return failure(path, _('BPF 证据值无效'));
	if (value.collect_target_count === 0 && value.attach_state !== 'not_attempted')
		return failure(path + '.attach_state', _('无采集接口时不得声明 TC 已挂载'));
	if (value.attach_state === 'ready' && (!value.object_loaded || value.expected_hook_count === 0 ||
		value.attached_hook_count !== value.expected_hook_count))
		return failure(path + '.attach_state', _('TC 挂载计数与状态矛盾'));
	if (value.attach_state === 'partial' && (value.attached_hook_count === 0 ||
		value.attached_hook_count >= value.expected_hook_count))
		return failure(path + '.attach_state', _('TC 部分挂载计数无效'));
	if (value.map_state !== 'not_attempted' && value.attach_state !== 'ready')
		return failure(path + '.map_state', _('映射表状态要求 TC 已就绪'));
	if ((value.map_state === 'ready' || value.map_state === 'retained') &&
		value.last_complete_snapshot_ms === null)
		return failure(path + '.last_complete_snapshot_ms', _('映射表快照时间缺失'));
	if (value.map_state === 'retained' !== value.retained_fresh_snapshot)
		return failure(path + '.retained_fresh_snapshot', _('保留快照状态矛盾'));
	return null;
}
function validateHealthEvidence(value, path) {
	if (!plainObject(value)) return failure(path, _('证据字段无效'));
	if (!hasOwn(value, 'probe_failures')) return failure(path + '.probe_failures', _('字段缺失'));
	if (!hasOwn(value, 'bpf')) return failure(path + '.bpf', _('字段缺失'));
	return validateProbeFailures(value.probe_failures, path + '.probe_failures') ||
		validateBpfEvidence(value.bpf, path + '.bpf');
}
function validateCoverage(value, path) {
	var fields = [ 'quality', 'samples', 'window_ms', 'tx_pct', 'rx_pct', 'denom_rx_bytes',
		'denom_tx_bytes', 'numer_rx_bytes', 'numer_tx_bytes' ];
	if (!onlyFields(value, fields)) return failure(path, _('覆盖率字段无效'));
	var missing = requireFields(value, [ 'quality', 'samples' ], path);
	if (missing) return missing;
	if (!enumValue(value.quality, [ 'warmup', 'idle', 'low_traffic', 'counter_reset', 'ok', 'unsupported' ]) ||
		!nonNegativeInteger(value.samples) || !optionalIntegers(value, fields.slice(2)) ||
		(hasOwn(value, 'tx_pct') && value.tx_pct > 100) ||
		(hasOwn(value, 'rx_pct') && value.rx_pct > 100)) return failure(path, _('覆盖率字段无效'));
	return null;
}
function validateStatusResponse(value) {
	var fields = [ 'mode', 'confidence', 'warnings', 'evidence', 'refresh_interval_ms',
		'active_client_window_ms', 'active_client_min_bps', 'overview_window_samples',
		'collector_mode', 'rate_collector_mode', 'conn_collector_mode', 'version',
		'capabilities', 'coverage' ];
	if (!onlyFields(value, fields)) return failure('status', _('存在未定义字段'));
	var missing = requireFields(value, [ 'mode', 'confidence', 'warnings', 'evidence',
		'refresh_interval_ms', 'rate_collector_mode', 'conn_collector_mode', 'version', 'capabilities' ], 'status');
	if (missing) return missing;
	if (!enumValue(value.mode, RUNTIME_MODES) || !enumValue(value.confidence, CONFIDENCES) ||
		!Array.isArray(value.warnings) || !value.warnings.every(function(item) { return boundedString(item, 1, 160); }) ||
		!safeInteger(value.refresh_interval_ms, 500) ||
		!enumValue(value.rate_collector_mode, [ 'auto', 'bpf', 'nss_ecm_direct', 'nss_conntrack_sync' ]) ||
		!enumValue(value.conn_collector_mode, [ 'auto', 'conntrack_netlink', 'conntrack_procfs' ]) ||
		!boundedString(value.version, 1, 64)) return failure('status', _('字段无效'));
	if (hasOwn(value, 'collector_mode') && !enumValue(value.collector_mode,
		[ 'auto', 'bpf', 'nss_ecm_direct', 'nss_conntrack_sync', 'conntrack_netlink', 'conntrack_procfs' ]))
		return failure('status.collector_mode', _('字段无效'));
	if (!optionalIntegers(value, [ 'active_client_window_ms', 'active_client_min_bps', 'overview_window_samples' ],
		{ active_client_window_ms: 1000, active_client_min_bps: 1, overview_window_samples: 2 }))
		return failure('status', _('窗口字段无效'));
	var issue = validateCapabilities(value.capabilities, 'status.capabilities') ||
		validateHealthEvidence(value.evidence, 'status.evidence');
	if (issue) return issue;
	if (hasOwn(value, 'coverage')) {
		issue = validateCoverage(value.coverage, 'status.coverage');
		if (issue) return issue;
	}
	return null;
}
function validateHealthResponse(value) {
	var fields = [ 'mode', 'confidence', 'capabilities', 'conflicts', 'warnings', 'evidence' ];
	if (!onlyFields(value, fields)) return failure('health', _('存在未定义字段'));
	var missing = requireFields(value, fields, 'health');
	if (missing) return missing;
	if (!enumValue(value.mode, RUNTIME_MODES) || !enumValue(value.confidence, CONFIDENCES) ||
		!Array.isArray(value.warnings) || !value.warnings.every(function(item) { return boundedString(item, 1, 160); }) ||
		!Array.isArray(value.conflicts) || !value.conflicts.every(function(item) {
			return plainObject(item) && boundedString(item.id, 1, 160) &&
				enumValue(item.severity, [ 'info', 'warning', 'critical' ]) && boundedString(item.message, 1, 480);
		})) return failure('health', _('字段无效'));
	return validateCapabilities(value.capabilities, 'health.capabilities') ||
		validateHealthEvidence(value.evidence, 'health.evidence');
}
function validateClientsResponse(value) {
	var fields = [ 'clients', 'evidence', 'tcp_conns_total', 'udp_conns_total',
		'udp_dns_conns_total', 'udp_other_conns_total', 'conntrack_entries_seen',
		'conntrack_entries_matched', 'conntrack_parse_errors', 'conn_source',
		'nss_ecm_direct_flows_seen', 'nss_ecm_direct_flows_matched',
		'nss_ecm_direct_parse_errors', 'conn_collector_mode', 'conn_semantics' ];
	if (!onlyFields(value, fields)) return failure('clients', _('存在未定义字段'));
	if (!hasOwn(value, 'clients')) return failure('clients.clients', _('字段缺失'));
	var clientFields = [ 'mac', 'ips', 'identity_key', 'zone', 'interface', 'hostname', 'rx_bps',
		'tx_bps', 'last_seen', 'sample_ms', 'rx_bytes', 'tx_bytes', 'collector_mode', 'confidence',
		'warnings', 'tcp_conns', 'udp_conns', 'udp_dns_conns', 'udp_other_conns' ];
	var clientRequired = [ 'mac', 'identity_key', 'zone', 'interface', 'ips', 'hostname', 'rx_bps',
		'tx_bps', 'last_seen', 'collector_mode', 'confidence', 'warnings' ];
	if (!Array.isArray(value.clients) || !value.clients.every(function(item) {
		return onlyFields(item, clientFields) && !requireFields(item, clientRequired, 'client') &&
			/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(item.mac || '') &&
			boundedString(item.identity_key, 1, 160) && boundedString(item.zone, 1, 64) &&
			boundedString(item.interface, 1, 160) && Array.isArray(item.ips) &&
			item.ips.every(function(ip) { return boundedString(ip, 1, 160); }) &&
			(item.hostname === null || boundedString(item.hostname, 0, 253)) &&
			nonNegativeInteger(item.rx_bps) && nonNegativeInteger(item.tx_bps) &&
			nonNegativeInteger(item.last_seen) && boundedString(item.collector_mode, 1, 64) &&
			enumValue(item.confidence, CONFIDENCES) && Array.isArray(item.warnings) &&
			item.warnings.every(function(warning) { return boundedString(warning, 1, 160); }) &&
			optionalIntegers(item, [ 'sample_ms', 'rx_bytes', 'tx_bytes', 'tcp_conns', 'udp_conns',
				'udp_dns_conns', 'udp_other_conns' ]);
	})) return failure('clients.clients', _('字段无效'));
	var counters = [ 'tcp_conns_total', 'udp_conns_total', 'udp_dns_conns_total', 'udp_other_conns_total',
		'conntrack_entries_seen', 'conntrack_entries_matched', 'conntrack_parse_errors',
		'nss_ecm_direct_flows_seen', 'nss_ecm_direct_flows_matched', 'nss_ecm_direct_parse_errors' ];
	if (!optionalIntegers(value, counters)) return failure('clients', _('连接计数字段无效'));
	if (hasOwn(value, 'evidence') && !plainObject(value.evidence)) return failure('clients.evidence', _('字段无效'));
	if (hasOwn(value, 'conn_source') &&
		!enumValue(value.conn_source, [ 'conntrack', 'conntrack_netlink', 'conntrack_procfs', 'nss_ecm_direct' ]))
		return failure('clients.conn_source', _('连接数据源无效'));
	if (hasOwn(value, 'conn_collector_mode') &&
		!enumValue(value.conn_collector_mode, [ 'auto', 'conntrack_netlink', 'conntrack_procfs' ]))
		return failure('clients.conn_collector_mode', _('字段无效'));
	if (hasOwn(value, 'conn_semantics') && !boundedString(value.conn_semantics, 1, 160))
		return failure('clients.conn_semantics', _('字段无效'));
	var seen = value.conn_source === 'nss_ecm_direct' ? value.nss_ecm_direct_flows_seen : value.conntrack_entries_seen;
	var matched = value.conn_source === 'nss_ecm_direct' ? value.nss_ecm_direct_flows_matched : value.conntrack_entries_matched;
	if (seen !== undefined && matched !== undefined && matched > seen)
		return failure('clients', _('连接计数关系无效'));
	return null;
}
function validateInterfacesResponse(value) {
	var fields = [ 'interfaces', 'monotonic_ms', 'note', 'evidence' ];
	if (!onlyFields(value, fields)) return failure('interfaces', _('存在未定义字段'));
	if (!hasOwn(value, 'interfaces')) return failure('interfaces.interfaces', _('字段缺失'));
	var itemFields = [ 'name', 'role', 'status', 'rx_bytes', 'tx_bytes', 'rx_bps', 'tx_bps',
		'delta_ms', 'sample_ms', 'source', 'coverage', 'evidence' ];
	if (!Array.isArray(value.interfaces) || !value.interfaces.every(function(item) {
		return onlyFields(item, itemFields) && boundedString(item.name, 1, 160) &&
			enumValue(item.role, [ 'lan', 'observe', 'wan', 'excluded', 'unknown' ]) &&
			enumValue(item.status, [ 'pending', 'active', 'available', 'missing', 'excluded', 'unsupported' ]) &&
			optionalIntegers(item, [ 'rx_bytes', 'tx_bytes', 'rx_bps', 'tx_bps', 'delta_ms', 'sample_ms' ]) &&
			(!hasOwn(item, 'source') || boundedString(item.source, 0, 160)) &&
			(!hasOwn(item, 'coverage') || boundedString(item.coverage, 0, 160)) &&
			(!hasOwn(item, 'evidence') || plainObject(item.evidence));
	})) return failure('interfaces.interfaces', _('字段无效'));
	if (hasOwn(value, 'monotonic_ms') && !nonNegativeInteger(value.monotonic_ms))
		return failure('interfaces.monotonic_ms', _('字段无效'));
	if (hasOwn(value, 'note') && !boundedString(value.note, 0, 480)) return failure('interfaces.note', _('字段无效'));
	if (hasOwn(value, 'evidence') && !plainObject(value.evidence)) return failure('interfaces.evidence', _('字段无效'));
	return null;
}
function validateOverviewResponse(value) {
	var fields = [ 'samples', 'max_samples', 'overview_window_samples', 'active_client_window_ms',
		'active_client_min_bps', 'sample_source', 'conn_semantics' ];
	if (!onlyFields(value, fields)) return failure('overview', _('存在未定义字段'));
	if (!hasOwn(value, 'samples')) return failure('overview.samples', _('字段缺失'));
	var sampleFields = [ 'sample_ms', 'tx_bps', 'rx_bps', 'client_count', 'active_clients',
		'tcp_conns', 'udp_conns', 'udp_dns_conns', 'udp_other_conns' ];
	var required = [ 'sample_ms', 'tx_bps', 'rx_bps', 'client_count', 'active_clients' ];
	if (!Array.isArray(value.samples) || !value.samples.every(function(item) {
		return onlyFields(item, sampleFields) && !requireFields(item, required, 'overview.sample') &&
			optionalIntegers(item, sampleFields) && item.active_clients <= item.client_count;
	})) return failure('overview.samples', _('字段无效'));
	if (!optionalIntegers(value, [ 'max_samples', 'overview_window_samples', 'active_client_window_ms',
		'active_client_min_bps' ], { overview_window_samples: 2, active_client_window_ms: 1000,
		active_client_min_bps: 1 })) return failure('overview', _('窗口字段无效'));
	if (hasOwn(value, 'sample_source') && !boundedString(value.sample_source, 1, 160))
		return failure('overview.sample_source', _('字段无效'));
	if (hasOwn(value, 'conn_semantics') && !boundedString(value.conn_semantics, 1, 160))
		return failure('overview.conn_semantics', _('字段无效'));
	return null;
}
function validateRuntimeResponse(value, key) {
	if (!plainObject(value)) return failure(key, _('响应不是对象'));
	var issue = key === 'status' ? validateStatusResponse(value) :
		key === 'health' ? validateHealthResponse(value) :
		key === 'clients' ? validateClientsResponse(value) :
		key === 'interfaces' ? validateInterfacesResponse(value) :
		key === 'overview' ? validateOverviewResponse(value) : failure(key, _('未知 RPC 契约'));
	return issue || { valid: true, reason: '', path: '', value: value };
}

function emptyValue(key) {
	if (key === 'diagnostics') return {};
	if (key === 'status' || key === 'health') return {};
	if (key === 'clients') return { clients: [] };
	if (key === 'interfaces') return { interfaces: [] };
	if (key === 'overview') return { samples: [] };
	return {};
}
function rpcErrorInfo(error, kind) {
	error = error || {};
	var rawCode = error.code === null || error.code === undefined ? '' : String(error.code);
	var message = error.message || error.statusText || String(error) || _('未知 RPC 失败');
	return {
		kind: kind || 'transport', code: boundedText(rawCode, 64),
		message: boundedText(message, 320), category: error.category || kind || 'transport',
		stage: error.stage || 'rpc', retriable: error.retriable !== false
	};
}

function boundedText(value, limit) {
	var text = String(value === null || value === undefined ? '' : value)
		.replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim();
	return text.length > limit ? text.slice(0, limit) + '…' : text;
}

function phaseForValue(key, value) {
	if (key === 'diagnostics') {
		var collection = value.collection || {};
		if (collection.state === 'stale') return 'stale';
		if (collection.state === 'degraded' || collection.state === 'unavailable') return 'degraded';
	}
	if ((key === 'status' || key === 'health') && value.mode !== 'Full') return 'degraded';
	if ((key === 'clients' && !asArray(value.clients).length) ||
		(key === 'interfaces' && !asArray(value.interfaces).length) ||
		(key === 'overview' && !asArray(value.samples).length)) return 'empty';
	return 'success';
}
function retentionLimit(previous, value) {
	var interval = finiteNumber(value && value.refresh_interval_ms) ||
		finiteNumber(previous && previous.status && previous.status.refresh_interval_ms) || 1000;
	return Math.min(MAX_RETAIN_MS, Math.max(DEFAULT_RETAIN_MS, interval * 10));
}
function usableResource(resource, now, maxAge) {
	if (!resource || !resource.value || resource.phase === 'error' || resource.phase === 'invalid') return false;
	if (resource.phase === 'loading' && resource.usable !== true) return false;
	if (resource.fetchedAt === null || resource.fetchedAt === undefined) return false;
	return now >= resource.fetchedAt && now - resource.fetchedAt <= maxAge;
}
function resourceForResult(result, previousResource, previousState, checkedAt, requestId) {
	var validation;
	if (result.ok) {
		validation = result.validation || (result.key === 'diagnostics'
			? validateDiagnosticsContract(result.value)
			: validateRuntimeResponse(result.value, result.key));
		if (!validation.valid) {
			result = { key: result.key, ok: false, error: rpcErrorInfo({
				code: 'INVALID_CONTRACT', message: validation.reason, retriable: false
			}, 'contract') };
		} else {
			var phase = phaseForValue(result.key, validation.value);
			return {
				key: result.key, phase: phase, value: validation.value,
				usable: true, retained: false, fetchedAt: checkedAt, producedAt: checkedAt,
				retainedFrom: null, ageMs: 0, requestId: requestId, error: null,
				attempt: phase === 'empty' ? 'empty' : 'success'
			};
		}
	}
	var previous = previousResource;
	var maxAge = retentionLimit(previousState, previousState && previousState.status);
	if (usableResource(previous, checkedAt, maxAge)) {
		return {
			key: result.key, phase: 'stale', value: previous.value, usable: true, retained: true,
			fetchedAt: previous.fetchedAt, producedAt: previous.producedAt || previous.fetchedAt,
			retainedFrom: previous.fetchedAt, ageMs: Math.max(0, checkedAt - previous.fetchedAt),
			requestId: requestId, error: result.error || rpcErrorInfo(null, 'transport'), attempt: 'error'
		};
	}
	return {
		key: result.key, phase: result.error && result.error.kind === 'contract' ? 'invalid' : 'error',
		value: emptyValue(result.key), usable: false, retained: false, fetchedAt: null,
		producedAt: null, retainedFrom: null, ageMs: null, requestId: requestId,
		error: result.error || rpcErrorInfo(null, 'transport'), attempt: 'error'
	};
}

function runCall(item, timeoutMs) {
	var requestedTimeout = Number(timeoutMs);
	var timeout = !isFinite(requestedTimeout) || requestedTimeout <= 0
		? DEFAULT_RPC_TIMEOUT_MS : Math.min(MAX_RPC_TIMEOUT_MS, Math.max(250, requestedTimeout));
	return new Promise(function(resolve) {
		var settled = false;
		var timer = setTimeout(function() {
			if (settled) return;
			settled = true;
			resolve({ key: item.key, ok: false, error: rpcErrorInfo({
				code: 'TIMEOUT', message: _('请求超时'), retriable: true
			}, 'timeout') });
		}, timeout);
		Promise.resolve().then(item.call).then(function(value) {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			var validation = item.key === 'diagnostics'
				? validateDiagnosticsContract(value)
				: validateRuntimeResponse(value, item.key);
			if (!validation.valid) {
				resolve({ key: item.key, ok: false, validation: validation,
					error: rpcErrorInfo({ code: 'INVALID_CONTRACT', message: validation.reason,
						retriable: false }, 'contract') });
				return;
			}
			resolve({ key: item.key, ok: true, value: value, validation: validation });
		}, function(error) {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve({ key: item.key, ok: false, error: rpcErrorInfo(error, 'transport') });
		});
	});
}

function sampleClock(data) {
	data = data || {};
	function maxValue(values) {
		return asArray(values).reduce(function(maximum, value) {
			var number = finiteNumber(value);
			return number !== null && number >= 0 && number > maximum ? number : maximum;
		}, 0);
	}
	var interfaces = data.interfaces || {};
	var clients = data.clients || {};
	var overview = data.overview || {};
	var interfaceClock = maxValue([ interfaces.monotonic_ms ].concat(asArray(interfaces.interfaces).map(function(item) {
		return item && item.sample_ms;
	})));
	var clientClock = maxValue(asArray(clients.clients).map(function(item) { return item && item.sample_ms; }));
	var overviewClock = maxValue(asArray(overview.samples).map(function(item) { return item && item.sample_ms; }));
	return { interfaces: interfaceClock, clients: clientClock, overview: overviewClock,
		overall: maxValue([ interfaceClock, clientClock, overviewClock ]) };
}
function rpcResult(viewState, key) {
	return viewState && viewState.rpc && viewState.rpc[key] || null;
}
function rpcState(viewState, key) {
	var resource = viewState && viewState.resources && viewState.resources[key];
	if (resource) {
		var phase = resource.phase || 'loading';
		var retained = resource.retained === true;
		return {
			state: phase === 'stale' ? (retained ? 'retained' : 'success') :
				(phase === 'error' ? 'failed' : phase),
			phase: phase, ok: resource.usable !== false &&
				[ 'loading', 'error', 'invalid' ].indexOf(phase) === -1,
			retained: retained,
			result: resource
		};
	}
	var result = rpcResult(viewState, key);
	if (!result) return { state: 'missing', phase: 'loading', ok: false, retained: false, result: null };
	var resultPhase = result.phase || (result.ok ? 'success' : 'error');
	var resultOk = result.ok === true && [ 'loading', 'error', 'invalid' ].indexOf(resultPhase) === -1;
	return {
		state: resultOk ? 'success' : (result.retained ? 'retained' :
			(resultPhase === 'invalid' || result.error && result.error.kind === 'contract' ? 'invalid' : 'failed')),
		phase: resultPhase, ok: resultOk,
		retained: result.retained === true, result: result
	};
}
function hasPreviousValue(previous, key) {
	var resource = previous && previous.resources && previous.resources[key];
	if (resource) {
		var checkedAt = previous.checkedAt === null || previous.checkedAt === undefined ? Date.now() : previous.checkedAt;
		return usableResource(resource, checkedAt, retentionLimit(previous, previous.status));
	}
	var value = previous && previous[key];
	if (!value) return false;
	if (previous.rpc && previous.rpc[key] && previous.rpc[key].ok !== true && previous.rpc[key].retained !== true)
		return false;
	if (key === 'clients') return Array.isArray(value.clients);
	if (key === 'interfaces') return Array.isArray(value.interfaces);
	if (key === 'overview') return Array.isArray(value.samples);
	return key === 'diagnostics' ? validateDiagnosticsContract(value).valid : plainObject(value);
}

function progressRpcOk(rpc, key) {
	var state = rpcState({ rpc: rpc }, key);
	return state.state === 'success' && state.phase !== 'stale';
}
function assessProgress(previous, current, elapsedMs, refreshIntervalMs, rpc) {
	var elapsed = Math.max(0, finiteNumber(elapsedMs) || 0);
	var refresh = Math.max(500, finiteNumber(refreshIntervalMs) || 1000);
	if (!previous || !current || elapsed < Math.max(750, refresh * .9))
		return { checked: false, stale: false, lagging: false, sources: [] };
	var compared = [], stale = [];
	[ 'interfaces', 'clients', 'overview' ].forEach(function(key) {
		if (!progressRpcOk(rpc, key)) return;
		if (finiteNumber(previous[key]) !== null && finiteNumber(current[key]) !== null &&
			Number(previous[key]) > 0 && Number(current[key]) > 0) {
			compared.push(key);
			if (Number(current[key]) <= Number(previous[key])) stale.push(key);
		}
	});
	return { checked: compared.length > 0, stale: compared.length > 0 && stale.length === compared.length,
		lagging: stale.length > 0 && stale.length < compared.length, sources: stale };
}

function normalizeResults(results, previous, checkedAt, requestId) {
	checkedAt = checkedAt === null || checkedAt === undefined ? Date.now() : checkedAt;
	requestId = requestId || 0;
	var next = { resources: {}, rpc: {}, checkedAt: checkedAt, requestId: requestId };
	var previousState = previous || null;
	RPC_KEYS.forEach(function(key) {
		var result = asArray(results).filter(function(item) { return item && item.key === key; })[0] || {
			key: key, ok: false, error: rpcErrorInfo({ code: 'MISSING', message: _('没有收到检查结果') }, 'missing')
		};
		var previousResource = previousState && previousState.resources && previousState.resources[key];
		if (!previousResource && hasPreviousValue(previousState, key)) {
			previousResource = {
				key: key, phase: phaseForValue(key, previousState[key]), value: previousState[key],
				usable: true, retained: !!(previousState.rpc && previousState.rpc[key] && previousState.rpc[key].retained),
				fetchedAt: previousState.checkedAt, producedAt: previousState.checkedAt,
				retainedFrom: null, ageMs: 0, requestId: previousState.requestId || 0, error: null
			};
		}
		var resource = resourceForResult(result, previousResource, previousState, checkedAt, requestId);
		var resultOk = result.ok === true && !(result.validation && result.validation.valid === false) &&
			resource.error === null;
		next.resources[key] = resource;
		next[key] = resource.value;
		next.rpc[key] = {
			ok: resultOk, retained: resource.retained === true, phase: resource.phase,
			error: resource.error, requestId: requestId, fetchedAt: resource.fetchedAt,
			producedAt: resource.producedAt, ageMs: resource.ageMs
		};
	});
	next.errors = RPC_KEYS.filter(function(key) { return next.rpc[key].ok !== true; }).map(function(key) {
		return { key: key, error: next.rpc[key].error };
	});
	next.error = next.errors.length ? next.errors[0].error : null;
	next.observation = sampleClock(next);
	var previousObservation = previousState && previousState.observation;
	next.progress = assessProgress(previousObservation, next.observation,
		previousState ? checkedAt - previousState.checkedAt : 0,
		next.status && next.status.refresh_interval_ms, next.rpc);
	next.pageState = pageState(next);
	return next;
}

function pageState(viewState) {
	viewState = viewState || {};
	var states = RPC_KEYS.map(function(key) { return rpcState(viewState, key); });
	if (states.some(function(item) { return item.state === 'loading' || item.state === 'missing'; })) return 'loading';
	var hard = states.filter(function(item) { return item.state === 'failed' || item.state === 'invalid'; }).length;
	var usable = states.filter(function(item) { return item.ok || item.retained; }).length;
	if (!usable) return hard === states.length ? 'error' : 'empty';
	if (hard === states.length) return 'error';
	if (hard > 0) return 'partial';
	if (states.some(function(item) { return item.phase === 'degraded' || item.phase === 'stale'; })) return 'degraded';
	if ([ 'clients', 'interfaces', 'overview' ].every(function(key) {
		return rpcState(viewState, key).phase === 'empty';
	})) return 'empty';
	return 'ready';
}

function formatDuration(value) {
	var milliseconds = finiteNumber(value);
	if (milliseconds === null || milliseconds < 0) return '-';
	if (milliseconds < 1000) return _('%d 毫秒').format(Math.round(milliseconds));
	if (milliseconds < 60000) return _('%s 秒').format(String(Math.round(milliseconds / 100) / 10));
	return _('%s 分钟').format(String(Math.round(milliseconds / 6000) / 10));
}
function formatPercent(value) {
	var number = finiteNumber(value);
	return number === null ? '-' : String(Math.round(number * 10) / 10) + '%';
}
function stateRank(state) { return ({ neutral: 0, good: 1, warning: 2, bad: 3 })[state] || 0; }
function worseState(first, second) { return stateRank(second) > stateRank(first) ? second : first; }
function reasonText(reason) {
	var key = String(reason || '');
	return REASON_LABELS[key] || key.replace(/_/g, ' ') || '-';
}
function collectorKey(value) {
	var key = String(value || '').trim().toLowerCase();
	return /^(|auto|unsupported)$/.test(key) ? 'unsupported' : key;
}
function knownCollector(value) { return hasOwn(COLLECTOR_REPORT_LABELS, collectorKey(value)); }
function collectorDisplayLabel(value) {
	var key = collectorKey(value);
	return knownCollector(key) ? statusCollector.collectorLabel(key) : _('未知');
}

function coverageState(status) {
	var coverage = status && status.coverage;
	if (!plainObject(coverage)) return { state: 'warning', badge: _('未知'), value: '-',
		description: _('没有收到覆盖率数据。'), meta: _('覆盖率契约缺失'), quality: '' };
	var quality = String(coverage.quality || '');
	var tx = finiteNumber(coverage.tx_pct), rx = finiteNumber(coverage.rx_pct);
	var minimum = tx !== null && rx !== null ? Math.min(tx, rx) : null;
	var state = 'warning', badge = _('未知'), value = minimum === null ? '-' : formatPercent(minimum);
	var description = _('覆盖率数据不完整。');
	if (quality === 'ok' && minimum !== null) {
		state = minimum < 60 ? 'bad' : (minimum < 85 ? 'warning' : 'good');
		badge = state === 'good' ? _('可信') : (state === 'bad' ? _('缺口较大') : _('存在缺口'));
		description = _('上行 %s · 下行 %s').format(formatPercent(tx), formatPercent(rx));
	} else if (quality === 'idle') { state = 'good'; badge = _('空闲'); value = '-'; description = _('当前没有活动流量。'); }
	else if (quality === 'low_traffic') { state = 'warning'; badge = _('低流量'); value = '-'; description = _('流量过低，暂不判断覆盖率。'); }
	else if (quality === 'warmup') { state = 'warning'; badge = _('采样中'); value = '-'; description = _('正在积累覆盖率样本。'); }
	else if (quality === 'counter_reset') { state = 'warning'; badge = _('重新采样'); description = _('检测到计数器重置，正在重新建立窗口。'); }
	else if (quality === 'unsupported') { state = 'bad'; badge = _('不可用'); value = '-'; description = _('后端没有可用的覆盖率数据源。'); }
	return { state: state, badge: badge, value: value, description: description,
		meta: _('%d 个样本 · %s 窗口').format(Math.round(Number(coverage.samples) || 0),
			formatDuration(coverage.window_ms)), quality: quality, txPct: tx, rxPct: rx, minimumPct: minimum };
}

function freshnessFromContract(viewState) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var collection = contract.data.collection;
	var retained = contract.retained || collection.retained;
	var transportAge = contract.rpcRetained ? finiteNumber(contract.resourceAgeMs) : 0;
	var effectiveAge = collection.age_ms === null ? null : collection.age_ms + Math.max(0, transportAge || 0);
	var state = collection.state === 'fresh' ? 'good' :
		(collection.state === 'unavailable' ? 'bad' : 'warning');
	if (retained && state === 'good') state = 'warning';
	var description = collection.state === 'fresh' ? _('采集循环在刷新窗口内完成。') :
		(collection.state === 'stale' ? _('最近成功采集已超过刷新窗口。') :
			(collection.state === 'degraded' ? _('采集循环完成但存在降级。') : _('没有可用的采集结果。')));
	if (retained) description += ' ' + _('当前显示最近一次成功结果。');
	return { state: state, badge: state === 'good' ? _('新鲜') :
		(state === 'warning' ? (retained ? _('沿用旧值') :
			(collection.state === 'stale' ? _('过期') : _('降级'))) : _('不可用')),
		value: formatDuration(effectiveAge), description: description,
		meta: _('第 %d 代 · 刷新间隔 %s').format(collection.generation, formatDuration(collection.refresh_interval_ms)),
		oldestAgeMs: effectiveAge, clock: collection.last_success_ms,
		failedSources: [], retainedSources: retained ? [ 'diagnostics' ] : [], hardFailedSources: [] };
}
function freshnessState(data, progress) {
	var contract = freshnessFromContract(data);
	if (contract) return contract;
	data = data || {};
	var diagnosticsRpc = rpcState(data, 'diagnostics');
	var clock = sampleClock(data), refresh = Math.max(500, Number(data.status && data.status.refresh_interval_ms) || 1000);
	var ages = [], keys = [ 'interfaces', 'clients', 'overview' ];
	keys.forEach(function(key) {
		var sample = data.observation && data.observation[key] || sampleClock(data)[key];
		if (clock.overall && sample) ages.push(clock.overall - sample);
	});
	var oldest = ages.length ? Math.max.apply(Math, ages) : null;
	var progressChecked = !!(progress && progress.checked);
	var state = oldest === null || !progressChecked ? 'warning' : (progress.stale ? 'bad' :
		(oldest > refresh * 5 ? 'bad' : (oldest > refresh * 2.5 || progress.lagging ? 'warning' : 'good')));
	if (diagnosticsRpc.state === 'loading') state = 'warning';
	return { state: state, badge: state === 'good' ? _('新鲜') : (state === 'bad' ? _('已停滞') : _('待复查')),
		value: oldest === null ? '-' : formatDuration(oldest),
		description: diagnosticsRpc.state === 'loading' ? _('正在等待诊断新鲜度结果。') :
			(oldest === null ? _('没有足够的采样时间信息。') :
			(!progressChecked ? _('需要再次检查才能确认采样时钟持续推进。') :
				(state === 'good' ? _('采样时钟正在推进。') : _('部分采样时钟未按刷新间隔推进。')))),
		meta: _('刷新间隔 %s').format(formatDuration(refresh)), oldestAgeMs: oldest,
		clock: clock, failedSources: [], retainedSources: [], hardFailedSources: [] };
}
function diagnosticsContractState(viewState) {
	var value = viewState && viewState.diagnostics;
	var validation = validateDiagnosticsContract(value);
	var rpc = rpcState(viewState, 'diagnostics');
	var implicit = !viewState || !viewState.rpc;
	var usable = validation.valid && (implicit || rpc.ok || rpc.retained);
	var payloadRetained = usable && value.collection && value.collection.retained === true;
	return { usable: usable, valid: validation.valid,
		state: !validation.valid && rpc.state === 'success' ? 'invalid' : rpc.state,
		retained: rpc.retained === true || payloadRetained, rpcRetained: rpc.retained === true,
		payloadRetained: payloadRetained, resourceAgeMs: rpc.result && rpc.result.ageMs,
		reason: validation.reason, data: usable ? value : null };
}
function contractCollectionState(viewState) { return freshnessFromContract(viewState); }

function dataPathState(status, clients) {
	status = status || {}; clients = clients || {};
	var evidence = status.evidence && status.evidence.collector || {};
	var rate = collectorKey((status.evidence && status.evidence.effective_collector) ||
		statusCollector.effectiveCollector(status, clients));
	var connection = collectorKey(clients.conn_source || clients.conn_collector_mode ||
		evidence.effective_connection_collector || evidence.connection_source);
	var unknown = !knownCollector(rate) || !knownCollector(connection);
	var unavailable = rate === 'unsupported' || connection === 'unsupported';
	var confidence = String(evidence.confidence || status.confidence || 'unknown').toLowerCase();
	var state = unavailable ? 'bad' : (unknown || confidence !== 'high' ? 'warning' : 'good');
	return { state: state, badge: state === 'good' ? _('已确定') : (state === 'bad' ? _('不可用') : _('降级')),
		value: collectorDisplayLabel(rate) + ' / ' + collectorDisplayLabel(connection),
		description: unavailable ? _('速率或连接统计缺少可用数据来源。') :
			(state === 'good' ? _('速率与连接使用可验证的数据来源。') : _('数据路径未完全确认。')),
		meta: reasonText(evidence.rate_reason) + ' · ' + reasonText(evidence.connection_reason),
		rateSource: rate, connectionSource: connection, rateLabel: collectorDisplayLabel(rate),
		connectionLabel: collectorDisplayLabel(connection), rateKnown: knownCollector(rate),
		connectionKnown: knownCollector(connection), configuredRate: status.rate_collector_mode || '-',
		configuredConnection: status.conn_collector_mode || '-', rateReason: evidence.rate_reason || '',
		connectionReason: evidence.connection_reason || '' };
}
function contractPathState(viewState) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var path = contract.data.data_path;
	var rate = collectorKey(path.effective_rate), connection = collectorKey(path.effective_connection);
	var unavailable = rate === 'unsupported' || connection === 'unsupported';
	var state = unavailable ? 'bad' : (path.fallback_active ? 'warning' : 'good');
	if (contract.retained && state === 'good') state = 'warning';
	return { state: state, badge: state === 'good' ? _('已确定') : (state === 'bad' ? _('不可用') : _('降级')),
		value: collectorDisplayLabel(rate) + ' / ' + collectorDisplayLabel(connection),
		description: unavailable ? _('速率或连接统计缺少可用数据来源。') :
			(path.fallback_active ? _('当前使用回退路径。') : _('速率与连接路径已确定。')),
		meta: reasonText(path.reason_code) + (contract.retained ? ' · ' + _('沿用旧值') : ''),
		rateSource: rate, connectionSource: connection, rateLabel: collectorDisplayLabel(rate),
		connectionLabel: collectorDisplayLabel(connection), rateKnown: knownCollector(rate),
		connectionKnown: knownCollector(connection), configuredRate: path.configured_rate,
		configuredConnection: path.configured_connection, rateReason: path.reason_code || '',
		connectionReason: path.reason_code || '' };
}
function connectionState(clients, status) {
	clients = clients || {}; status = status || {};
	var source = clients.conn_source || clients.conn_collector_mode || '';
	var direct = String(source).toLowerCase() === 'nss_ecm_direct';
	var seen = finiteNumber(direct ? clients.nss_ecm_direct_flows_seen : clients.conntrack_entries_seen);
	var matched = finiteNumber(direct ? clients.nss_ecm_direct_flows_matched : clients.conntrack_entries_matched);
	var errors = Math.max(0, finiteNumber(direct ? clients.nss_ecm_direct_parse_errors : clients.conntrack_parse_errors) || 0);
	var pct = seen !== null && seen > 0 && matched !== null ? Math.min(100, matched * 100 / seen) : null;
	var state = !source || source === 'unsupported' ? 'bad' : (!knownCollector(source) ? 'warning' : 'good');
	if (seen !== null && matched !== null && matched > seen) state = 'bad';
	else if (errors > 10) state = 'bad'; else if (errors || pct !== null && pct < 70 || seen === null || matched === null) state = 'warning';
	return { state: state, badge: state === 'good' ? _('正常') : (state === 'bad' ? _('不可用') : _('需关注')),
		value: source ? collectorDisplayLabel(source) : '-',
		description: seen !== null && matched !== null ? _('%d / %d 条已匹配 · %d 个解析错误').format(matched, seen, errors) : _('连接统计不完整。'),
		meta: _('TCP %d · UDP %d').format(Math.max(0, Number(clients.tcp_conns_total) || 0), Math.max(0, Number(clients.udp_conns_total) || 0)),
		source: source, seen: seen, matched: matched, matchPct: pct, parseErrors: errors };
}
function contractConnectionState(viewState) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var connection = contract.data.connection, state = connection.state === 'healthy' ? 'good' :
		(connection.state === 'degraded' ? 'warning' : 'bad');
	if (contract.retained && state === 'good') state = 'warning';
	var seen = connection.entries_seen, matched = connection.entries_matched;
	var pct = seen !== null && seen > 0 && matched !== null ? matched * 100 / seen : null;
	return { state: state, badge: state === 'good' ? _('正常') : (state === 'bad' ? _('不可用') : _('需关注')),
		value: connection.source ? collectorDisplayLabel(connection.source) : '-',
		description: seen !== null && matched !== null ? _('%d / %d 条已匹配').format(matched, seen) : _('后端未返回连接条目统计。'),
		meta: connection.parse_errors ? _('%d 个解析错误').format(connection.parse_errors) : _('诊断契约'),
		source: connection.source || '', seen: seen, matched: matched, matchPct: pct,
		parseErrors: connection.parse_errors || 0 };
}
function connectionStateWithRpc(viewState) {
	var rpc = rpcState(viewState, 'clients'), base = contractConnectionState(viewState) ||
		connectionState(viewState && viewState.clients, viewState && viewState.status);
	var result = Object.assign({}, base, { rpc: rpc.state });
	if (rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing') {
		result.state = 'bad'; result.badge = _('不可用');
		result.description = _('客户端数据接口没有可验证结果。');
	} else if (rpc.state === 'retained') {
		result.state = worseState(result.state, 'warning'); result.badge = _('沿用旧值');
		result.description += ' ' + _('客户端接口本次失败。');
	} else if (rpc.state === 'empty') {
		result.state = worseState(result.state, 'warning'); result.badge = _('无客户端数据');
		result.description = _('客户端接口已响应，但当前没有客户端明细可交叉验证。');
	} else if (rpc.state === 'loading') {
		result.state = 'warning'; result.badge = _('检查中');
		result.description = _('正在等待客户端数据接口。');
	}
	return result;
}
function pathStateWithRpc(viewState) {
	var base = contractPathState(viewState) || dataPathState(viewState && viewState.status, viewState && viewState.clients);
	var clients = rpcState(viewState, 'clients'), status = rpcState(viewState, 'status'), health = rpcState(viewState, 'health');
	var result = Object.assign({}, base, { rpc: { clients: clients.state, status: status.state, health: health.state } });
	if ([ clients, status, health ].some(function(item) { return item.state === 'failed' || item.state === 'invalid' || item.state === 'missing'; })) {
		result.state = clients.state === 'failed' || clients.state === 'invalid' || clients.state === 'missing' ? 'bad' : worseState(result.state, 'warning');
		result.badge = result.state === 'bad' ? _('不可用') : _('未完全确认');
		result.description = _('一个或多个路径依据接口没有可验证结果。');
	} else if ([ clients, status, health ].some(function(item) { return item.state === 'retained'; })) {
		result.state = worseState(result.state, 'warning'); result.badge = _('沿用旧值');
		result.description += ' ' + _('部分路径依据沿用旧值。');
	} else if (clients.state === 'empty') {
		result.state = worseState(result.state, 'warning'); result.badge = _('未完全确认');
		result.description = _('客户端接口没有明细，数据路径缺少一项交叉验证。');
	} else if ([ clients, status, health ].some(function(item) { return item.state === 'loading'; })) {
		result.state = 'warning'; result.badge = _('检查中');
		result.description = _('正在等待路径依据接口。');
	}
	return result;
}
function interfaceState(interfaces) {
	var items = asArray(interfaces && interfaces.interfaces), available = 0, pending = 0, bad = 0, excluded = 0, unknown = 0;
	items.forEach(function(item) {
		var status = String(item && item.status || 'unknown');
		if (status === 'available' || status === 'active') available++; else if (status === 'pending') pending++;
		else if (status === 'missing' || status === 'unsupported') bad++; else if (status === 'excluded') excluded++; else unknown++;
	});
	var state = bad ? 'bad' : (!items.length || pending || unknown || !available ? 'warning' : 'good');
	return { state: state, badge: bad ? _('%d 个异常').format(bad) : (pending ? _('%d 个等待').format(pending) :
		(!items.length ? _('无接口数据') : (unknown ? _('%d 个未知').format(unknown) : _('%d 个可用').format(available)))),
		value: _('%d / %d').format(available, items.length),
		description: bad ? _('存在缺失或不受支持的接口。') : (!items.length ? _('没有接口数据。') :
			(pending ? _('部分接口等待首次采样。') : _('接口列表已返回。'))), items: items, available: available,
		pending: pending, bad: bad, excluded: excluded, unknown: unknown, total: items.length };
}
function contractInterfaceState(viewState, fallback) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var summary = contract.data.interfaces, state = summary.state === 'healthy' ? 'good' :
		(summary.state === 'degraded' ? 'warning' : 'bad');
	if (contract.retained && state === 'good') state = 'warning';
	return { state: state, badge: state === 'good' ? _('%d 个可用').format(summary.available) :
		(state === 'bad' ? _('接口不可用') : _('接口降级')), value: _('%d / %d').format(summary.available, summary.total),
		description: summary.missing ? _('%d 个接口缺失或不可用。').format(summary.missing) : _('接口汇总来自诊断契约。'),
		meta: summary.sample_ms === null ? _('尚无接口采样时间') : _('采样 %s').format(formatDuration(summary.sample_ms)),
		items: fallback && Array.isArray(fallback.items) ? fallback.items : [], available: summary.available,
		pending: 0, bad: summary.missing, excluded: 0, unknown: 0, total: summary.total };
}
function interfaceStateWithRpc(viewState) {
	var base = interfaceState(viewState && viewState.interfaces), contract = contractInterfaceState(viewState, base);
	var result = Object.assign({}, contract || base), rpc = rpcState(viewState, 'interfaces');
	result.rpc = rpc.state;
	if (rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing') {
		result.state = 'bad'; result.badge = _('不可用'); result.description = _('接口数据接口没有可验证结果。');
	} else if (rpc.state === 'retained') { result.state = worseState(result.state, 'warning'); result.badge = _('沿用旧值'); }
	else if (rpc.state === 'empty') {
		result.state = result.total > 0 ? 'bad' : 'warning';
		result.badge = result.state === 'bad' ? _('结果不一致') : _('无接口数据');
		result.description = result.state === 'bad' ? _('诊断汇总声明存在接口，但接口 RPC 返回空列表。') : _('没有配置可采集接口。');
	}
	else if (rpc.ok && result.total !== result.items.length) {
		result.state = 'bad'; result.badge = _('结果不一致');
		result.description = _('诊断汇总与接口 RPC 返回了不同的接口数量。');
	}
	else if (rpc.state === 'loading') { result.state = 'warning'; result.badge = _('检查中'); result.description = _('正在等待接口数据。'); }
	return result;
}
function versionState(backendVersion, frontendVersion, packageVersion) {
	var daemon = String(backendVersion || ''), frontend = String(frontendVersion || ''), pack = String(packageVersion || daemon || '');
	var matches = !!daemon && daemon === frontend && daemon === pack;
	return { state: matches ? 'good' : 'warning', badge: matches ? _('一致') : _('不一致'),
		value: frontend + ' / ' + daemon + ' / ' + pack,
		description: matches ? _('LuCI、软件包与后端版本一致。') : _('LuCI、软件包或后端版本未完全一致。') };
}
function contractVersionState(viewState, frontendVersion) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var versions = contract.data.versions, result = versionState(versions.daemon, frontendVersion, versions.package);
	if (contract.retained && result.state === 'good') { result.state = 'warning'; result.badge = _('沿用旧值'); }
	result.contractVersion = versions.contract_version; result.schemaVersion = versions.schema_version;
	return result;
}
function versionStateWithRpc(viewState, backendVersion, frontendVersion) {
	var contract = diagnosticsContractState(viewState);
	var result = contractVersionState(viewState, frontendVersion) || versionState(backendVersion, frontendVersion);
	var rpc = rpcState(viewState, 'status'); result.rpc = rpc.state;
	if (rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing') {
		result.state = 'warning'; result.badge = _('待确认'); result.description = _('没有成功的 status 结果，版本一致性暂时无法确认。');
	} else if (rpc.state === 'retained' && result.state === 'good') { result.state = 'warning'; result.badge = _('沿用旧值'); }
	else if (rpc.state === 'loading') { result.state = 'warning'; result.badge = _('检查中'); result.description = _('正在等待 status 版本信息。'); }
	else if (contract.usable && backendVersion && String(backendVersion) !== contract.data.versions.daemon) {
		result.state = 'warning'; result.badge = _('不一致');
		result.description = _('status 与诊断契约上报了不同的后端版本。');
	}
	return result;
}

function qualityState(data, progress) {
	var coverage = coverageState(data && data.status), freshness = freshnessState(data, progress);
	var statusRpc = rpcState(data, 'status');
	if (statusRpc.state === 'failed' || statusRpc.state === 'invalid' || statusRpc.state === 'missing') coverage.state = 'bad';
	else if (statusRpc.state === 'loading') { coverage.state = 'warning'; coverage.badge = _('检查中'); }
	var state = worseState(coverage.state, freshness.state);
	return { state: state, badge: state === 'bad' ? _('异常') : (state === 'warning' ? _('需关注') : coverage.badge),
		value: coverage.value, description: coverage.description + ' ' + freshness.description,
		meta: coverage.meta + ' · ' + _('样本年龄 ') + freshness.value, coverage: coverage, freshness: freshness };
}

function probeFailureBundle(health) {
	var raw = health && health.evidence && health.evidence.probe_failures;
	if (Array.isArray(raw)) return { items: raw.slice(0, MAX_PROBE_FAILURES), total: raw.length, truncated: raw.length > MAX_PROBE_FAILURES };
	raw = plainObject(raw) ? raw : {};
	var items = asArray(raw.items).slice(0, MAX_PROBE_FAILURES), total = finiteNumber(raw.total);
	return { items: items, total: total === null ? items.length : Math.max(items.length, Math.round(total)),
		truncated: raw.truncated === true || (total !== null && total > items.length) };
}
function probeFailureKey(item) { return [ item && item.kind, item && item.source, item && item.reason, item && item.exit_code ].join('\x1f'); }
function mergeProbeFailureBundles(first, second) {
	var a = probeFailureBundle(first), b = probeFailureBundle(second), items = [], seen = Object.create(null);
	[ a.items, b.items ].forEach(function(list) { list.forEach(function(item) {
		var key = probeFailureKey(item); if (seen[key]) return; seen[key] = true; if (items.length < MAX_PROBE_FAILURES) items.push(item);
	}); });
	var total = Math.max(a.total, b.total, items.length);
	return { items: items, total: total, truncated: a.truncated || b.truncated || total > items.length };
}
function canonicalWarningId(value) {
	var id = String(value || '');
	if (id && typeof vocab.normalizeWarningId === 'function')
		id = String(vocab.normalizeWarningId(id) || id);
	return id;
}
function warningGroups(status, health, rpc, diagnostics) {
	status = status || {}; health = health || {}; rpc = rpc || {};
	var items = [], seen = Object.create(null), hasRpc = Object.keys(rpc).length > 0;
	var contract = diagnosticsContractState({ diagnostics: diagnostics, rpc: rpc });
	var contractAlertIds = Object.create(null);
	if (contract.usable) asArray(contract.data.alerts).forEach(function(alert) {
		contractAlertIds[canonicalWarningId(alert && alert.id)] = true;
	});
	function severityRank(value) { return ({ info: 0, warning: 1, critical: 2 })[value] || 0; }
	function sourceUsable(key) {
		if (!hasRpc) return true;
		var state = rpcState({ rpc: rpc }, key);
		return state.ok || state.retained;
	}
	function add(item, source, severity, text, id) {
		id = canonicalWarningId(id || item || source || 'unknown');
		severity = enumValue(severity, [ 'info', 'warning', 'critical' ]) ? severity : 'warning';
		var known = typeof vocab.hasWarning === 'function' && vocab.hasWarning(id);
		var publicText = known && typeof vocab.warningText === 'function' ? vocab.warningText(id) : text;
		if (seen[id]) {
			if (source === 'diagnostics') {
				seen[id].source = source;
				seen[id].severity = severity;
				seen[id].text = publicText || seen[id].text;
				seen[id].raw = item;
			} else if (seen[id].source !== 'diagnostics' &&
				severityRank(severity) > severityRank(seen[id].severity)) {
				seen[id].severity = severity;
			}
			return;
		}
		seen[id] = { id: id, source: source, severity: severity, text: publicText || '', raw: item };
		items.push(seen[id]);
	}
	if (sourceUsable('status')) asArray(status.warnings).forEach(function(id) {
		if (id === 'live_metrics_unavailable' && status.capabilities && status.capabilities.live_metrics === true)
			return;
		if (id === 'bpf_runtime_loader_unavailable' && [ 'no_collect_interface', 'package_missing',
			'object_missing', 'object_load_failed', 'tc_unavailable', 'tc_unsupported', 'tc_conflict',
			'tc_attach_failed', 'map_read_failed' ].some(function(specific) { return contractAlertIds[specific]; }))
			return;
		var known = typeof vocab.hasWarning === 'function' && vocab.hasWarning(id);
		add(id, 'status', typeof vocab.warningClass === 'function' && vocab.warningClass(id).indexOf('danger') !== -1 ? 'critical' : 'warning',
			known && typeof vocab.warningText === 'function' ? vocab.warningText(id) : _('检测到未分类运行告警。'), id);
	});
	if (sourceUsable('health')) asArray(health.warnings).forEach(function(id) {
		var known = typeof vocab.hasWarning === 'function' && vocab.hasWarning(id);
		add(id, 'health', known && typeof vocab.warningClass === 'function' && vocab.warningClass(id).indexOf('danger') !== -1 ? 'critical' : 'warning',
			known && typeof vocab.warningText === 'function' ? vocab.warningText(id) : _('检测到未分类环境告警。'), id);
	});
	if (sourceUsable('health')) asArray(health.conflicts).forEach(function(conflict) {
		add(conflict, 'conflict', conflict && conflict.severity || 'warning', boundedText(conflict && conflict.message || '', 480), conflict && conflict.id);
	});
	RPC_KEYS.forEach(function(key) {
		var result = rpc[key];
		if (!result || result.phase === 'loading' || result.ok === true)
			return;
		add(result, 'rpc', result.retained || result.phase === 'degraded' || result.phase === 'stale'
			? 'warning' : 'critical', rpcReportErrorText(result), 'rpc:' + key);
	});
	if (contract.usable) {
		asArray(contract.data.alerts).forEach(function(alert) {
			add(alert, 'diagnostics', alert.severity, alert.message_public, alert.id);
		});
		asArray(contract.data.config_issues).forEach(function(issue) {
			add(issue, 'config', issue.severity, issue.message_public, issue.id);
		});
	}
	var failures = mergeProbeFailureBundles(sourceUsable('status') ? status : null,
		sourceUsable('health') ? health : null);
	failures.items.forEach(function(item) { add(item, 'probe', 'warning', probeFailureText(item), 'probe:' + probeFailureKey(item)); });
	var critical = items.filter(function(item) { return item.severity === 'critical'; });
	var warnings = items.filter(function(item) { return item.severity === 'warning'; });
	var info = items.filter(function(item) { return item.severity === 'info'; });
	return { all: critical.concat(warnings, info), critical: critical, warnings: warnings, info: info,
		important: items.filter(function(item) {
		return item.severity === 'critical' || item.severity === 'warning';
	}), environment: items.filter(function(item) { return item.severity === 'info'; }), conflicts: [],
		probeFailures: failures.items, probeFailuresTotal: failures.total, probeFailuresTruncated: failures.truncated,
		contractAlerts: contract.usable ? contract.data.alerts : [], configIssues: contract.usable ? contract.data.config_issues : [], contract: contract };
}
function probeFailureText(failure) {
	failure = failure || {};
	var kind = PROBE_KIND_REPORT_LABELS[String(failure.kind || '').toLowerCase()] || _('环境探测');
	var reason = PROBE_REASON_LABELS[String(failure.reason || '').toLowerCase()] || _('探测失败');
	return kind + ' · ' + reason + (finiteNumber(failure.exit_code) !== null ? ' · exit ' + Math.round(failure.exit_code) : '');
}
function probeFailureReportText(failure) {
	failure = failure || {};
	var kind = PROBE_KIND_REPORT_LABELS[String(failure.kind || '').toLowerCase()] || _('环境探测');
	var reason = PROBE_REASON_LABELS[String(failure.reason || '').toLowerCase()] || _('探测失败');
	return kind + ' · ' + reason + (finiteNumber(failure.exit_code) !== null ? ' · exit ' + Math.round(failure.exit_code) : '');
}

function rpcReportErrorText(result) {
	var error = result && result.error || {};
	var kind = enumValue(error.kind, [ 'transport', 'timeout', 'contract', 'missing', 'client' ])
		? error.kind : 'transport';
	var labels = {
		transport: _('传输失败'), timeout: _('请求超时'), contract: _('契约无效'),
		missing: _('缺少结果'), client: _('页面处理失败')
	};
	var code = { transport: 'RPC_ERROR', timeout: 'TIMEOUT', contract: 'INVALID_CONTRACT',
		missing: 'MISSING', client: 'CLIENT_ERROR' }[kind];
	return labels[kind] + ' · ' + code + ' · ' + (error.retriable === false ? _('不可重试') : _('可重试'));
}

function redactAssignment(match) {
	var separator = match.search(/[:=]/);
	return separator < 0 ? '[REDACTED]' : match.slice(0, separator) + match.charAt(separator) + '[REDACTED]';
}
function redactSensitiveAssignments(text) {
	var keys = '(?:authorization|auth(?:[_-]?token)?|access[_-]?token|api[_-]?key|apikey|token|password|passwd|passphrase|secret(?:[_-]?key)?|private[_-]?key|public[_-]?key|refresh[_-]?token|csrf[_-]?token|jwt|nonce|session(?:[_-]?id)?|sid|cookie|set-cookie|sysauth|ubus[_-]?rpc[_-]?session|host(?:name)?|remote[_-]?(?:host|ip|address)|domain|client(?:[_-]?(?:name|id|identity|token|ip|mac|host))?|device(?:[_-]?(?:name|id))?|identity(?:[_-]?(?:key|name|id))?|user(?:[_-]?(?:name|id))?|interface(?:[_-]?(?:name|source|id))?|probe(?:[_-]?(?:name|source|id))?|command|cmd|file|path|source|ssid|mac|ip(?:v4|v6)?|address|credential(?:s)?)';
	var quoted = new RegExp('(["\\\']?)\\b' + keys + '\\b\\1\\s*[:=]\\s*(?:"(?:\\\\.|[^"\\\\])*"|\\\'(?:\\\\.|[^\\\'\\\\])*\\\')', 'gi');
	var unquoted = new RegExp('(["\\\']?)\\b' + keys + '\\b\\1\\s*[:=]\\s*[^,;}&\\n]*?(?=\\s*(?:[,;}&\\n]|$)|\\s+["\\\']?[a-z][a-z0-9_.-]*["\\\']?\\s*[:=](?![=]))', 'gi');
	return text.replace(quoted, redactAssignment).replace(unquoted, redactAssignment);
}
function validIpv4(value) {
	var parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(function(part) { return /^\d{1,3}$/.test(part) && Number(part) <= 255; });
}
function validIpv6(value) {
	var address = String(value || '').toLowerCase().replace(/%[a-z0-9_.-]+$/, ''), ipv4Index = address.lastIndexOf(':'), ipv4 = address.indexOf('.') !== -1 ? address.slice(ipv4Index + 1) : '';
	if (ipv4) { if (ipv4Index < 0 || !validIpv4(ipv4)) return false; address = address.slice(0, ipv4Index) + ':v4'; }
	if (address.indexOf(':::') !== -1 || address.indexOf('::') !== address.lastIndexOf('::')) return false;
	var compressed = address.indexOf('::') !== -1, halves = compressed ? address.split('::') : [ address, '' ], groups = [];
	halves.forEach(function(half) { if (half) groups = groups.concat(half.split(':')); });
	var count = 0;
	for (var i = 0; i < groups.length; i++) {
		if (groups[i] === 'v4') count += 2; else if (/^[0-9a-f]{1,4}$/.test(groups[i])) count++; else return false;
	}
	return compressed ? count < 8 : count === 8;
}
function redactIpv6(text) {
	text = text.replace(/\[([0-9a-f:.]+(?:%[a-z0-9_.-]+)?)\](?::\d{1,5})?/gi, function(match, address) {
		return validIpv6(address) ? '[IP]' : match;
	});
	return text.replace(/(^|[^0-9a-f:.])((?:[0-9a-f]{0,4}:){2,}(?:[0-9a-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})?(?:%[a-z0-9_.-]+)?)(?=$|[^0-9a-f:.]|\.(?!\d))/gi, function(match, prefix, address) {
		return validIpv6(address) ? prefix + '[IP]' : match;
	});
}
function sanitizeReportText(value) {
	var text = redactSensitiveAssignments(boundedText(value, 480))
		.replace(/\b(?:command|file|uci|ubus|process|service|sysctl|probe):[^\s\u00b7,;)}\]]+/gi, '[SOURCE]')
		.replace(/(^|[\s("'=])\/(?:[^\s,;)}\]]+)/g, '$1[PATH]')
		.replace(/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi, '[MAC]')
		.replace(/\b(?:[0-9a-f]{2}[:-]){7}[0-9a-f]{2}\b/gi, '[MAC]')
		.replace(/\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b/gi, '[MAC]')
		.replace(/\b[0-9a-f]{12}\b/gi, '[MAC]')
		.replace(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b/gi, '[IDENTITY]');
	return redactIpv6(text).replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP]')
		.replace(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi, '[HOST]');
}
function reportField(value) { return sanitizeReportText(value === null || value === undefined || value === '' ? '-' : value); }
function reportCollectorLabel(value) { var key = collectorKey(value); return COLLECTOR_REPORT_LABELS[key] || _('未知数据源'); }
function reportReasonText(reason) {
	var key = String(reason || '').toLowerCase();
	return hasOwn(REASON_LABELS, key) ? REASON_LABELS[key] : _('未知原因');
}
function reportVersion(value) {
	value = String(value || '');
	return /^[0-9]+(?:\.[0-9]+){1,3}(?:[-+~._][A-Za-z0-9]+)*$/.test(value) ? value : '-';
}
function reportConfiguredMode(value, kind) {
	var rate = [ 'auto', 'bpf', 'nss_ecm_direct', 'nss_conntrack_sync' ];
	var connection = [ 'auto', 'conntrack_netlink', 'conntrack_procfs' ];
	value = String(value || '').toLowerCase();
	return (kind === 'rate' ? rate : connection).indexOf(value) !== -1 ? value : _('未知配置');
}
function rpcReportState(result) {
	if (!result) return _('未检查');
	if (!result.ok) return result.retained ? _('失败，沿用旧值') :
		(result.phase === 'invalid' || result.error && result.error.kind === 'contract' ? _('契约无效') : _('失败'));
	return ({ empty: _('成功，无数据'), stale: _('成功，数据过期'), degraded: _('成功，结果降级') })[result.phase] || _('成功');
}
function reportPageState(value) {
	return ({ loading: _('检查中'), ready: _('完成'), degraded: _('降级'), partial: _('部分失败'),
		empty: _('无数据'), error: _('失败') })[String(value || '')] || _('未确认');
}
function diagnosticSeverity(item) { var value = String(item && item.severity || 'info'); return value === 'critical' ? 'danger' : value === 'warning' ? 'warning' : 'info'; }
function diagnosticPublicText(item, fallback) {
	/* Do not copy arbitrary backend prose. Known warning IDs are translated locally. */
	var id = String(item && item.id || '');
	if (typeof vocab.hasWarning === 'function' && vocab.hasWarning(id) && typeof vocab.warningText === 'function')
		return sanitizeReportText(vocab.warningText(id));
	return sanitizeReportText(fallback || _('检测到一项诊断事件。'));
}
function stateLabel(state) { return state === 'good' ? _('正常') : state === 'bad' ? _('异常') : state === 'warning' ? _('需关注') : _('信息'); }
function interfaceReportRole(value) { return INTERFACE_ROLE_REPORT_LABELS[String(value || '').toLowerCase()] || _('其他'); }
function interfaceReportStatus(value) { return INTERFACE_STATUS_REPORT_LABELS[String(value || '').toLowerCase()] || _('未知'); }
function subsystemReportText(item) {
	item = plainObject(item) ? item : {};
	var id = String(item.id || ''), code = String(item.code || '');
	var label = SUBSYSTEM_LABELS[id] || _('未知组件');
	var state = HEALTH_REPORT_LABELS[String(item.state || '')] || _('未知');
	var detail = '-';
	if (code && typeof vocab.hasWarning === 'function' && vocab.hasWarning(code) &&
		typeof vocab.warningText === 'function') detail = vocab.warningText(code);
	else if (code && hasOwn(REASON_LABELS, code)) detail = REASON_LABELS[code];
	return label + ': ' + state + (detail === '-' ? '' : ' · ' + sanitizeReportText(detail));
}

function buildReport(viewState, frontendVersion) {
	viewState = viewState || {};
	var runtime = viewState.status || {}, quality = qualityState(viewState, viewState.progress), path = pathStateWithRpc(viewState),
		connections = connectionStateWithRpc(viewState), interfaces = interfaceStateWithRpc(viewState),
		versions = versionStateWithRpc(viewState, runtime.version, frontendVersion), groups = warningGroups(viewState.status, viewState.health, viewState.rpc, viewState.diagnostics),
		contract = diagnosticsContractState(viewState), backendVersion = contract.usable ? contract.data.versions.daemon : runtime.version,
		lines = [
			'LAN Speed ' + _('运行诊断报告 v1'), _('页面状态') + ': ' + reportPageState(viewState.pageState || pageState(viewState)),
			_('检查时间') + ': ' + reportField(new Date(viewState.checkedAt || Date.now()).toLocaleString()),
			_('LuCI 版本') + ': ' + reportVersion(frontendVersion), _('后端版本') + ': ' + reportVersion(backendVersion), ''
		];
	if (contract.usable) {
		lines.push(_('诊断契约') + ': v' + reportField(contract.data.contract_version),
			_('服务') + ': ' + reportField(contract.data.service.state) + ' / ubus ' + reportField(contract.data.service.ubus_connected),
			_('采集代次') + ': ' + reportField(contract.data.collection.generation),
			_('采集年龄') + ': ' + reportField(formatDuration(contract.data.collection.age_ms)),
			_('连续失败') + ': ' + reportField(contract.data.collection.consecutive_failures), '');
	}
	lines.push(_('RPC 检查') + ':');
	RPC_KEYS.forEach(function(key) {
		var rpc = rpcResult(viewState, key), text = rpcReportState(rpc);
		lines.push('- ' + RPC_LABELS[key] + ': ' + text +
			(rpc && !rpc.ok ? ' · ' + rpcReportErrorText(rpc) : ''));
	});
	lines.push('', _('采集质量') + ': ' + stateLabel(quality.state) + ' · ' + reportField(quality.value),
		'- ' + reportField(quality.description), _('数据新鲜度') + ': ' + stateLabel(quality.freshness.state) + ' · ' + reportField(quality.freshness.value),
		_('数据路径') + ': ' + stateLabel(path.state) + ' · ' + reportCollectorLabel(path.rateSource) + ' / ' + reportCollectorLabel(path.connectionSource),
		'- ' + reportField(path.description), '- ' + _('路径原因') + ': ' + reportReasonText(path.rateReason || path.connectionReason),
		'- ' + _('配置路径') + ': ' + reportConfiguredMode(path.configuredRate, 'rate') + ' / ' + reportConfiguredMode(path.configuredConnection, 'connection'),
		_('连接健康') + ': ' + stateLabel(connections.state) + ' · ' + reportCollectorLabel(connections.source),
		_('版本一致性') + ': ' + stateLabel(versions.state) + ' · ' + reportField(versions.badge),
		_('接口健康') + ': ' + stateLabel(interfaces.state) + ' · ' + reportField(interfaces.value), '');
	if (contract.usable) {
		lines.push(_('子系统状态') + ':');
		asArray(contract.data.subsystems).forEach(function(item) {
			lines.push('- ' + subsystemReportText(item));
		});
		lines.push('');
	}
	if (groups.all.length) {
		lines.push(_('告警') + ':');
		groups.all.forEach(function(item) {
			var fallback = item.source === 'probe' ? probeFailureReportText(item.raw) :
				(item.source === 'rpc' ? item.text : null);
			lines.push('- [' + reportField(item.severity) + '] ' + diagnosticPublicText(item, fallback));
		});
	} else lines.push(_('告警') + ': -');
	lines.push('', _('接口明细') + ': ' + reportField(interfaces.items.length));
	interfaces.items.forEach(function(item, index) {
		item = plainObject(item) ? item : {};
		lines.push('- ' + _('接口 %d').format(index + 1) + ' · ' + interfaceReportRole(item.role) + ' · ' + interfaceReportStatus(item.status));
	});
	lines.push('', _('隐私说明') + ': ' + _('报告只复制白名单状态、计数和本地化告警；客户端地址、名称、接口名、探针源和原始后端文本不会复制。'));
	return lines.join('\n');
}

return baseclass.extend({
	RPC_KEYS: RPC_KEYS, RPC_LABELS: RPC_LABELS, RESOURCE_PHASES: RESOURCE_PHASES,
	DEFAULT_RPC_TIMEOUT_MS: DEFAULT_RPC_TIMEOUT_MS, MAX_RETAIN_MS: MAX_RETAIN_MS,
	validateDiagnosticsContract: validateDiagnosticsContract, validateRuntimeResponse: validateRuntimeResponse,
	runCall: runCall, emptyValue: emptyValue, normalizeResults: normalizeResults, pageState: pageState,
	hasPreviousValue: hasPreviousValue, rpcErrorInfo: rpcErrorInfo, rpcState: rpcState,
	diagnosticsContractState: diagnosticsContractState, contractCollectionState: contractCollectionState,
	mergeRuntime: function(status, health, rpc, diagnostics) {
		var source = status || {}, fallback = health || {}, contract = diagnosticsContractState({ status: status, health: health, rpc: rpc, diagnostics: diagnostics });
		return Object.assign({}, fallback, source, contract.usable ? { version: contract.data.versions.daemon,
			mode: contract.data.collection.state === 'fresh' ? 'Full' : 'Degraded', confidence: contract.data.collection.state === 'fresh' ? 'high' : 'low',
			collector: contract.data.data_path.effective_rate, capabilities: source.capabilities || fallback.capabilities || {} } : {});
	},
	formatDuration: formatDuration, formatPercent: formatPercent, sampleClock: sampleClock, assessProgress: assessProgress,
	coverageState: coverageState, freshnessState: freshnessState, qualityState: qualityState,
	dataPathState: dataPathState, connectionState: connectionState, interfaceState: interfaceState,
	versionState: versionState, pathStateWithRpc: pathStateWithRpc, connectionStateWithRpc: connectionStateWithRpc,
	interfaceStateWithRpc: interfaceStateWithRpc, versionStateWithRpc: versionStateWithRpc,
	warningGroups: warningGroups, probeFailureText: probeFailureText, probeFailureReportText: probeFailureReportText,
	rpcReportErrorText: rpcReportErrorText,
	probeFailureBundle: probeFailureBundle, sanitizeReportText: sanitizeReportText, diagnosticPublicText: diagnosticPublicText,
	diagnosticSeverity: diagnosticSeverity, interfaceReportRole: interfaceReportRole, interfaceReportStatus: interfaceReportStatus,
	buildReport: buildReport
});
