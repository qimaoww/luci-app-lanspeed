'use strict';
'require baseclass';

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
var NSS_TELEMETRY_FIELDS = [
	'sync_count', 'last_sync_ns', 'igs_bytes', 'igs_packets', 'igs_drops',
	'peer_generation', 'peer_reassert', 'ack_latency_last_ns',
	'ack_latency_max_ns', 'ack_received', 'ack_timeout', 'ack_late',
	'control_generation', 'hardware_generation'
];
var NSS_GENL_CAP_FIELDS = [ 'state', 'abi_version', 'feature_bits', 'max_igs',
	'max_peers', 'max_client_tags', 'supports_wifi_peer', 'supports_igs_stats',
	'supports_peer_query' ];
var NSS_GENL_STATE_FIELDS = [ 'state', 'staged', 'published', 'degraded' ];
var NSS_GENL_STATS_FIELDS = [ 'state', 'control_generation', 'hardware_generation',
	'peer_generation', 'peer_reassert_count', 'igs_sync_count', 'igs_last_sync_ns',
	'igs_bytes', 'igs_packets', 'igs_drops', 'igs_active_nodes', 'igs_cadence_samples',
	'igs_cadence_last_ns', 'igs_cadence_min_ns', 'igs_cadence_max_ns', 'ack_latency_last_ns',
	'ack_latency_max_ns', 'ack_received', 'ack_timeout', 'ack_late' ];
var NSS_GENL_HEALTH_FIELDS = [ 'state', 'healthy', 'control_generation',
	'hardware_generation' ];
var NSS_IGS_CADENCE_FIELDS = [ 'state', 'samples', 'last_interval_ns',
	'min_interval_ns', 'max_interval_ns', 'active_nodes' ];
var CAPABILITY_KEYS = [
	'bpf', 'bpf_supported', 'bpf_package', 'bpf_object', 'bpf_runtime_metrics', 'conntrack_fallback',
	'live_metrics', 'fw4', 'nft', 'software_flow_offload', 'hardware_flow_offload',
	'nss', 'nss_ecm_offload', 'nss_ppe_offload', 'nss_ecm_node', 'nss_ecm_bpf', 'nss_bridge_mgr',
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
	nss_ecm_node_primary: _('NSS ECM node 计数可用'),
	nss_ecm_bpf_primary: _('ECM+BPF 更新链路可用'),
	nss_ecm_node_fallback: _('ECM+BPF 不可用，自动回退到 ECM'),
	nss_collectors_unavailable_bpf_fallback: _('ECM+BPF 与 ECM 不可用，自动回退到 BPF'),
	forced_bpf: _('配置强制使用 BPF'),
	forced_bpf_unavailable: _('配置强制使用 BPF，但运行时不可用'),
	no_collect_interface: _('没有接口被分配到客户端采集'),
	forced_nss_ecm_node: _('配置强制使用 NSS ECM node 计数'),
	forced_nss_ecm_node_unavailable: _('配置强制使用 NSS ECM node，但数据源不可用'),
	forced_nss_ecm_bpf: _('配置强制使用 ECM+BPF 更新链路'),
	forced_nss_ecm_bpf_unavailable: _('配置强制使用 ECM+BPF，但运行链路不可用'),
	no_live_rate_collector: _('没有可用的实时速率采集器'),
	forced_conntrack_netlink: _('配置强制使用 Conntrack Netlink'),
	forced_conntrack_netlink_unavailable: _('配置强制使用 Conntrack Netlink，但数据源不可用'),
	forced_conntrack_procfs: _('配置强制使用 Conntrack Procfs'),
	forced_conntrack_procfs_unavailable: _('配置强制使用 Conntrack Procfs，但数据源不可用'),
	conntrack_unavailable: _('Conntrack Netlink 与 Procfs 均不可用'),
	conntrack_not_sampled: _('NSS 周期采集跳过 Conntrack，诊断请求会单独读取'),
	conntrack_read_failed: _('Conntrack 读取失败，请检查 Netlink、模块和 Procfs 回退'),
	state_unavailable_or_unreadable: _('运行状态不可读取'),
	unsupported: _('没有受支持的数据源')
};
var SUBSYSTEM_LABELS = {
	bpf: _('CPU 慢路径检测（BPF）'), tc: _('CPU 路径挂载（TC）'), bpf_map: _('分类映射表'),
	conntrack: _('连接跟踪'), nss: _('NSS 加速识别'), nss_control: _('NSS 客户端控制'),
	identity: _('客户端接入归属'), ubus: _('RPC 服务')
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
	access_edge: _('自动精准'), bpf: _('BPF'), nss_ecm_node: _('ECM'), nss_ecm_bpf: _('ECM+BPF'),
	conntrack_netlink: _('CT-Netlink'), conntrack_procfs: _('CT-Procfs'),
	conntrack: _('CT'), unsupported: _('不可用')
};
var RATE_SOURCE_LABELS = {
	edge_port: _('Edge-Port'), edge_wifi: _('Edge-WiFi'),
	fast_routed_lease: _('FastN+FastS 租约替代'),
	fast_routed_internet: _('FastN+FastS 互联网路由'),
	ecm_bpf_fallback: _('ECM+BPF 降级'), ecm_nss_lower_bound: _('NSS 下界'),
	tc_bpf_lower_bound: _('CPU 慢路径下界'), none: _('无来源')
};
var RATE_COVERAGE_LABELS = {
	full: _('完整'), partial: _('部分'), degraded: _('降级'), unavailable: _('不可用')
};
var RATE_SCOPE_LABELS = {
	all_frames: _('全部帧'), unicast: _('单播'), routed_observed: _('已观察路由流量'),
	lower_bound: _('下界'), none: _('无')
};
var CLASSIFICATION_STATE_LABELS = {
	warmup: _('预热'), aligned: _('已对齐'), partial: _('部分'), stale: _('已过期'),
	domain_mismatch: _('字节口径不可比'), window_mismatch: _('窗口不一致'),
	counter_skew: _('计数错位'), map_loss: _('映射丢失'), unavailable: _('不可用')
};
var ACCESS_EDGE_REASON_LABELS = {
	active_attachment_unpublished: _('活动接入点尚未发布为客户端'),
	attachment_ambiguous: _('客户端接入点存在歧义'),
	access_edge_shadow: _('精准接入点仅在后台验证，不负责页面总速率'),
	classification_counter_skew: _('分类计数窗口错位，未发布未分类速率和覆盖率'),
	classification_domain_mismatch: _('总速率与分类字节口径不同，不能安全相减'),
	classification_map_loss: _('分类映射读取不完整'),
	classification_partial: _('分类来源不完整'),
	classification_stale: _('分类结果已过期'),
	classification_unavailable: _('当前没有可验证分类结果'),
	classification_warmup: _('分类比较窗口正在预热'),
	classification_window_mismatch: _('分类窗口不一致，不能安全合并'),
	counter_reset: _('接入口计数器重置，正在重新预热'),
	direction_window_mismatch: _('上下行总速率窗口不同'),
	duplicate_client_identity: _('同一接入设备匹配到多个客户端身份'),
	duplicate_mac_attachment: _('同一 MAC 出现在多个接入点'),
	fdb_dump_failed: _('网桥 FDB 完整读取失败'),
	fdb_event_monitor_failed: _('网桥 FDB 事件监听失败'),
	fdb_event_monitor_unavailable: _('网桥 FDB 事件监听不可用'),
	fdb_fallback_incomplete: _('FDB 后备读取无法证明结果完整'),
	fresh_edge_owner_missing: _('部分方向缺少当前接入 generation 的新鲜精准总速率来源'),
	ethernet_full_scope_unproven: _('有线总速率已由 Edge-Port 接管，但当前拓扑最多只能证明 Partial'),
	nl80211_dump_failed: _('无线客户端计数读取失败'),
	nl80211_dump_incomplete: _('无线客户端计数读取不完整'),
	nl80211_station_sample_missing: _('无线客户端缺少本轮计数'),
	port_counter_missing: _('有线接入口缺少本轮计数'),
	rate_owner_unavailable: _('客户端没有可用的总速率来源'),
	shadow_not_rate_owner: _('精准接入点当前不负责页面总速率'),
	shared_or_unproven_port: _('端口为共享下联或无法证明为直连'),
	topology_incomplete: _('接入拓扑读取不完整'),
	warmup: _('接入口计数正在建立基线'),
	wifi_group_traffic_unattributed: _('Wi-Fi 广播和组播无法逐客户端完整归属'),
	wifi_shared_or_unproven_interface: _('无线接口为共享接入，全部帧最多为 Partial')
};
var FDB_SOURCE_LABELS = {
	rtnetlink_af_bridge: _('标准 Bridge Netlink'),
	sysfs_brforward_fallback: _('兼容 brforward 读取')
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

function validNssGenlObject(value, fields, integerFields, booleanFields) {
	if (!plainObject(value) || !onlyFields(value, fields) || value.state !== 'ready')
		return false;
	if (integerFields.some(function(field) { return !hasOwn(value, field) ||
		!nonNegativeInteger(value[field]); })) return false;
	return booleanFields.every(function(field) {
		return typeof value[field] === 'boolean';
	});
}

function validNssIgsCadence(value) {
	if (!plainObject(value) || !onlyFields(value, NSS_IGS_CADENCE_FIELDS) ||
		!enumValue(value.state, [ 'unavailable', 'invalid', 'ready' ])) return false;
	if (value.state !== 'ready') return Object.keys(value).length === 1;
	return NSS_IGS_CADENCE_FIELDS.slice(1).every(function(field) {
		return hasOwn(value, field) && nonNegativeInteger(value[field]);
	});
}

function validNssHardwareTelemetry(value) {
	var fields = [ 'state' ].concat(NSS_TELEMETRY_FIELDS, [
		'igs_cadence', 'genl_caps', 'genl_state', 'genl_stats', 'genl_health'
	]);
	if (!plainObject(value) || !onlyFields(value, fields) ||
		!enumValue(value.state, [ 'unavailable', 'invalid', 'ready' ])) return false;
	if (value.state !== 'ready') return true;
	if (NSS_TELEMETRY_FIELDS.some(function(field) {
		return !hasOwn(value, field) || !nonNegativeInteger(value[field]);
	})) return false;
	if (hasOwn(value, 'igs_cadence') && !validNssIgsCadence(value.igs_cadence))
		return false;
	if (hasOwn(value, 'genl_caps') && !validNssGenlObject(value.genl_caps,
		NSS_GENL_CAP_FIELDS,
		[ 'abi_version', 'feature_bits', 'max_igs', 'max_peers', 'max_client_tags' ],
		[ 'supports_wifi_peer', 'supports_igs_stats', 'supports_peer_query' ])) return false;
	if (hasOwn(value, 'genl_state') && !validNssGenlObject(value.genl_state,
		NSS_GENL_STATE_FIELDS, [ 'staged', 'published', 'degraded' ], [])) return false;
	if (hasOwn(value, 'genl_stats') && !validNssGenlObject(value.genl_stats,
		NSS_GENL_STATS_FIELDS,
		[ 'control_generation', 'hardware_generation', 'peer_generation',
			'peer_reassert_count', 'igs_sync_count', 'igs_last_sync_ns', 'igs_bytes',
			'igs_packets', 'igs_drops', 'igs_active_nodes', 'igs_cadence_samples',
			'igs_cadence_last_ns', 'igs_cadence_min_ns', 'igs_cadence_max_ns',
			'ack_latency_last_ns', 'ack_latency_max_ns',
			'ack_received', 'ack_timeout', 'ack_late' ], [])) return false;
	if (hasOwn(value, 'genl_health') && !validNssGenlObject(value.genl_health,
		NSS_GENL_HEALTH_FIELDS, [ 'control_generation', 'hardware_generation' ],
		[ 'healthy' ])) return false;
	return true;
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
	if (!enumValue(value.quality, [ 'warmup', 'pending', 'idle', 'low_traffic', 'counter_reset',
		'counter_skew', 'ok', 'unsupported' ]) ||
		!nonNegativeInteger(value.samples) || !optionalIntegers(value, fields.slice(2)) ||
		(hasOwn(value, 'tx_pct') && value.tx_pct > 100) ||
		(hasOwn(value, 'rx_pct') && value.rx_pct > 100)) return failure(path, _('覆盖率字段无效'));
	return null;
}
function validateRateDirectionMeta(value, path) {
	if (!onlyFields(value, [ 'source', 'coverage', 'byte_domain', 'sample_ms', 'window_ms', 'stale' ]))
		return failure(path, _('速率方向元数据无效'));
	var missing = requireFields(value, [ 'source', 'coverage' ], path);
	if (missing) return missing;
	/* Source codes are deliberately forward-compatible.  A newer daemon may
	 * publish a source this UI does not know yet; rendering falls back to a
	 * generic label instead of invalidating the complete clients response. */
	if (!boundedString(value.source, 1, 48) || !/^[A-Za-z0-9_-]+$/.test(value.source) ||
		!enumValue(value.coverage, [ 'full', 'partial', 'degraded', 'unavailable' ]) ||
		(hasOwn(value, 'byte_domain') && !enumValue(value.byte_domain,
			[ 'l2_no_fcs', 'l2_with_fcs', 'station_data', 'ecm_data' ])) ||
		!optionalIntegers(value, [ 'sample_ms', 'window_ms' ], { window_ms: 1 }) ||
		(hasOwn(value, 'stale') && typeof value.stale !== 'boolean'))
		return failure(path, _('速率方向元数据无效'));
	return null;
}
function validateRateMeta(value, path) {
	var fields = [ 'version', 'scope', 'tx', 'rx', 'attachment', 'generation', 'window_ms',
		'sample_ms', 'stale', 'reason_codes', 'classification' ];
	if (!onlyFields(value, fields)) return failure(path, _('客户端速率元数据无效'));
	var missing = requireFields(value,
		[ 'version', 'scope', 'tx', 'rx', 'generation', 'stale', 'reason_codes' ], path);
	if (missing) return missing;
	if (value.version !== 1 ||
		!enumValue(value.scope, [ 'all_frames', 'unicast', 'routed_observed', 'lower_bound', 'none' ]) ||
		!nonNegativeInteger(value.generation) || typeof value.stale !== 'boolean' ||
		!optionalIntegers(value, [ 'window_ms', 'sample_ms' ]) ||
		!Array.isArray(value.reason_codes) || value.reason_codes.length > 16 ||
		!value.reason_codes.every(function(reason) {
			return boundedString(reason, 1, 48) && /^[A-Za-z0-9_-]+$/.test(reason);
		})) return failure(path, _('客户端速率元数据无效'));
	var issue = validateRateDirectionMeta(value.tx, path + '.tx') ||
		validateRateDirectionMeta(value.rx, path + '.rx');
	if (issue) return issue;
	if (hasOwn(value, 'attachment')) {
		var attachment = value.attachment;
		if (!onlyFields(attachment, [ 'kind', 'ifname', 'trust' ]))
			return failure(path + '.attachment', _('物理接入点元数据无效'));
		var attachmentMissing = requireFields(attachment, [ 'kind', 'trust' ], path + '.attachment');
		if (attachmentMissing) return attachmentMissing;
		if (!enumValue(attachment.kind, [ 'ethernet', 'wifi', 'unknown' ]) ||
			!enumValue(attachment.trust, [ 'associated_station', 'observed_exclusive', 'shared', 'unknown' ]) ||
			(hasOwn(attachment, 'ifname') && !boundedString(attachment.ifname, 1, 48)))
			return failure(path + '.attachment', _('物理接入点元数据无效'));
	}
	if (hasOwn(value, 'classification')) {
		var classification = value.classification;
		var classificationFields = [ 'state', 'sample_ms', 'window_ms', 'comparison_window_ms',
			'tx_coverage_pct', 'rx_coverage_pct', 'tx_state', 'rx_state' ];
		var classificationStates = [ 'warmup', 'aligned', 'partial', 'stale',
			'domain_mismatch', 'window_mismatch', 'counter_skew', 'map_loss', 'unavailable' ];
		if (!onlyFields(classification, classificationFields) ||
			requireFields(classification, [ 'state' ], path + '.classification') ||
			!enumValue(classification.state, classificationStates) ||
			(hasOwn(classification, 'tx_state') && !enumValue(classification.tx_state, classificationStates)) ||
			(hasOwn(classification, 'rx_state') && !enumValue(classification.rx_state, classificationStates)) ||
			!optionalIntegers(classification, [ 'sample_ms', 'window_ms', 'comparison_window_ms',
				'tx_coverage_pct', 'rx_coverage_pct' ]) ||
			(hasOwn(classification, 'tx_coverage_pct') && classification.tx_coverage_pct > 100) ||
			(hasOwn(classification, 'rx_coverage_pct') && classification.rx_coverage_pct > 100))
			return failure(path + '.classification', _('分类覆盖率元数据无效'));
	}
	return null;
}
function validateStatusResponse(value) {
	var fields = [ 'mode', 'confidence', 'warnings', 'evidence', 'refresh_interval_ms',
		'active_client_window_ms', 'active_client_min_bps', 'overview_window_samples',
		'collector_mode', 'rate_collector_mode', 'internet_view_mode', 'access_edge_mode',
		'conn_collector_mode', 'version',
		'capabilities', 'coverage' ];
	if (!onlyFields(value, fields)) return failure('status', _('存在未定义字段'));
	var missing = requireFields(value, [ 'mode', 'confidence', 'warnings', 'evidence',
		'refresh_interval_ms', 'rate_collector_mode', 'conn_collector_mode', 'version', 'capabilities' ], 'status');
	if (missing) return missing;
	if (!enumValue(value.mode, RUNTIME_MODES) || !enumValue(value.confidence, CONFIDENCES) ||
		!Array.isArray(value.warnings) || !value.warnings.every(function(item) { return boundedString(item, 1, 160); }) ||
			!safeInteger(value.refresh_interval_ms, 500) ||
			!enumValue(value.rate_collector_mode, [ 'auto', 'bpf', 'nss_ecm_node', 'nss_ecm_bpf' ]) ||
			!enumValue(value.conn_collector_mode, [ 'auto', 'conntrack_netlink', 'conntrack_procfs' ]) ||
			!boundedString(value.version, 1, 64)) return failure('status', _('字段无效'));
	if (hasOwn(value, 'access_edge_mode') &&
		!enumValue(value.access_edge_mode, [ 'off', 'shadow', 'active' ]))
		return failure('status.access_edge_mode', _('字段无效'));
	if (hasOwn(value, 'internet_view_mode') &&
		!enumValue(value.internet_view_mode, [ 'off', 'routed' ]))
		return failure('status.internet_view_mode', _('字段无效'));
	if (hasOwn(value, 'collector_mode') && !enumValue(value.collector_mode,
		[ 'auto', 'bpf', 'nss_ecm_node', 'nss_ecm_bpf', 'conntrack_netlink', 'conntrack_procfs', 'unsupported' ]))
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
		'nss_ecm_nodes_seen', 'nss_ecm_nodes_matched',
		'nss_ecm_node_parse_errors', 'conn_collector_mode', 'conn_semantics' ];
	if (!onlyFields(value, fields)) return failure('clients', _('存在未定义字段'));
	if (!hasOwn(value, 'clients')) return failure('clients.clients', _('字段缺失'));
	var clientFields = [ 'mac', 'ips', 'identity_key', 'zone', 'interface', 'hostname', 'rx_bps',
		'tx_bps', 'last_seen', 'sample_ms', 'rx_bytes', 'tx_bytes', 'collector_mode', 'confidence',
		'warnings', 'tcp_conns', 'udp_conns', 'udp_dns_conns', 'udp_other_conns', 'rate_meta', 'control' ];
	var clientRequired = [ 'mac', 'identity_key', 'zone', 'interface', 'ips', 'hostname', 'rx_bps',
		'tx_bps', 'last_seen', 'collector_mode', 'confidence', 'warnings' ];
	if (!Array.isArray(value.clients) || !value.clients.every(function(item, index) {
		var metaIssue = hasOwn(item, 'rate_meta')
			? validateRateMeta(item.rate_meta, 'clients.clients[' + index + '].rate_meta') : null;
		var control = item.control;
		var controlValid = !hasOwn(item, 'control') || plainObject(control) &&
			onlyFields(control, [ 'configured', 'upload_bps', 'download_bps', 'internet_disabled',
				'shaping_supported', 'blocking_supported', 'max_rate_bps', 'state', 'reason', 'queue_overflow' ]) &&
			!requireFields(control, [ 'configured', 'upload_bps', 'download_bps', 'internet_disabled',
				'shaping_supported', 'blocking_supported', 'max_rate_bps', 'state', 'queue_overflow' ], 'control') &&
			typeof control.configured === 'boolean' && typeof control.internet_disabled === 'boolean' &&
			typeof control.shaping_supported === 'boolean' && typeof control.blocking_supported === 'boolean' &&
			typeof control.queue_overflow === 'boolean' && nonNegativeInteger(control.upload_bps) &&
			nonNegativeInteger(control.download_bps) && nonNegativeInteger(control.max_rate_bps) &&
			enumValue(control.state, [ 'inactive', 'applied', 'pending_new_connections', 'verified', 'error', 'unsupported' ]) &&
			(!hasOwn(control, 'reason') || boundedString(control.reason, 1, 160));
		return !metaIssue && controlValid && onlyFields(item, clientFields) && !requireFields(item, clientRequired, 'client') &&
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
		'nss_ecm_nodes_seen', 'nss_ecm_nodes_matched', 'nss_ecm_node_parse_errors' ];
	if (!optionalIntegers(value, counters)) return failure('clients', _('连接计数字段无效'));
	if (hasOwn(value, 'evidence') && !plainObject(value.evidence)) return failure('clients.evidence', _('字段无效'));
	if (plainObject(value.evidence) && hasOwn(value.evidence, 'nss_control')) {
		var controlEvidence = value.evidence.nss_control;
		var controlFields = [ 'state', 'reason_code', 'detail_code', 'shaping_supported',
			'blocking_supported', 'configured_clients', 'active_clients', 'effective_clients',
			'pending_clients', 'error_clients', 'queue_overflow_clients', 'rate_limited_clients',
			'internet_disabled_clients', 'block_active_clients', 'required_directions',
			'verified_directions', 'nss_verified_directions', 'cpu_verified_directions',
			'hardware_telemetry' ];
		var controlRequired = controlFields.filter(function(field) {
			return field !== 'hardware_telemetry';
		});
		var controlCounters = [ 'configured_clients', 'active_clients', 'effective_clients',
			'pending_clients', 'error_clients', 'queue_overflow_clients', 'rate_limited_clients',
			'internet_disabled_clients', 'block_active_clients', 'required_directions',
			'verified_directions', 'nss_verified_directions', 'cpu_verified_directions' ];
		var classifiedClients = controlEvidence && (controlEvidence.effective_clients +
			controlEvidence.pending_clients + controlEvidence.error_clients);
		if (!plainObject(controlEvidence) || !onlyFields(controlEvidence, controlFields) ||
			requireFields(controlEvidence, controlRequired, 'clients.evidence.nss_control') ||
			!enumValue(controlEvidence.state, [ 'inactive', 'pending', 'verified', 'error', 'unavailable' ]) ||
			!(controlEvidence.reason_code === null || codeString(controlEvidence.reason_code, false)) ||
			!(controlEvidence.detail_code === null || codeString(controlEvidence.detail_code, false)) ||
			typeof controlEvidence.shaping_supported !== 'boolean' ||
			typeof controlEvidence.blocking_supported !== 'boolean' ||
			!controlCounters.every(function(field) { return nonNegativeInteger(controlEvidence[field]); }) ||
			(hasOwn(controlEvidence, 'hardware_telemetry') &&
				!validNssHardwareTelemetry(controlEvidence.hardware_telemetry)) ||
			controlEvidence.active_clients > controlEvidence.configured_clients ||
			classifiedClients !== controlEvidence.active_clients ||
			controlEvidence.queue_overflow_clients > controlEvidence.error_clients ||
			controlEvidence.rate_limited_clients > controlEvidence.configured_clients ||
			controlEvidence.internet_disabled_clients > controlEvidence.configured_clients ||
			controlEvidence.block_active_clients > controlEvidence.internet_disabled_clients ||
			controlEvidence.verified_directions > controlEvidence.required_directions ||
			controlEvidence.nss_verified_directions > controlEvidence.required_directions ||
			controlEvidence.cpu_verified_directions > controlEvidence.required_directions ||
			(controlEvidence.state === 'verified' &&
				(controlEvidence.error_clients !== 0 || controlEvidence.pending_clients !== 0 ||
				 controlEvidence.verified_directions !== controlEvidence.required_directions)))
			return failure('clients.evidence.nss_control', _('字段或计数关系无效'));
	}
	if (hasOwn(value, 'conn_source') &&
		!enumValue(value.conn_source, [ 'conntrack', 'conntrack_netlink', 'conntrack_procfs' ]))
		return failure('clients.conn_source', _('连接数据源无效'));
	if (hasOwn(value, 'conn_collector_mode') &&
		!enumValue(value.conn_collector_mode, [ 'auto', 'conntrack_netlink', 'conntrack_procfs' ]))
		return failure('clients.conn_collector_mode', _('字段无效'));
	if (hasOwn(value, 'conn_semantics') && !boundedString(value.conn_semantics, 1, 160))
		return failure('clients.conn_semantics', _('字段无效'));
	var seen = value.conntrack_entries_seen;
	var matched = value.conntrack_entries_matched;
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

return baseclass.extend({
	RPC_KEYS: RPC_KEYS,
	RPC_LABELS: RPC_LABELS,
	RESOURCE_PHASES: RESOURCE_PHASES,
	HEALTH_STATES: HEALTH_STATES,
	RUNTIME_MODES: RUNTIME_MODES,
	CONFIDENCES: CONFIDENCES,
	MAX_DIAGNOSTIC_ALERTS: MAX_DIAGNOSTIC_ALERTS,
	MAX_CONFIG_ISSUES: MAX_CONFIG_ISSUES,
	MAX_SUBSYSTEMS: MAX_SUBSYSTEMS,
	MAX_PROBE_FAILURES: MAX_PROBE_FAILURES,
	DEFAULT_RPC_TIMEOUT_MS: DEFAULT_RPC_TIMEOUT_MS,
	MAX_RPC_TIMEOUT_MS: MAX_RPC_TIMEOUT_MS,
	DEFAULT_RETAIN_MS: DEFAULT_RETAIN_MS,
	MAX_RETAIN_MS: MAX_RETAIN_MS,
	CAPABILITY_KEYS: CAPABILITY_KEYS,
	BPF_ATTACH_STATES: BPF_ATTACH_STATES,
	BPF_MAP_STATES: BPF_MAP_STATES,
	BPF_REASON_CODES: BPF_REASON_CODES,
	PROBE_KINDS: PROBE_KINDS,
	PROBE_REASONS: PROBE_REASONS,
	REASON_LABELS: REASON_LABELS,
	SUBSYSTEM_LABELS: SUBSYSTEM_LABELS,
	HEALTH_REPORT_LABELS: HEALTH_REPORT_LABELS,
	PROBE_REASON_LABELS: PROBE_REASON_LABELS,
	PROBE_KIND_REPORT_LABELS: PROBE_KIND_REPORT_LABELS,
	INTERFACE_ROLE_REPORT_LABELS: INTERFACE_ROLE_REPORT_LABELS,
	INTERFACE_STATUS_REPORT_LABELS: INTERFACE_STATUS_REPORT_LABELS,
	COLLECTOR_REPORT_LABELS: COLLECTOR_REPORT_LABELS,
	RATE_SOURCE_LABELS: RATE_SOURCE_LABELS,
	RATE_COVERAGE_LABELS: RATE_COVERAGE_LABELS,
	RATE_SCOPE_LABELS: RATE_SCOPE_LABELS,
	CLASSIFICATION_STATE_LABELS: CLASSIFICATION_STATE_LABELS,
	ACCESS_EDGE_REASON_LABELS: ACCESS_EDGE_REASON_LABELS,
	FDB_SOURCE_LABELS: FDB_SOURCE_LABELS,
	asArray: asArray,
	plainObject: plainObject,
	hasOwn: hasOwn,
	finiteNumber: finiteNumber,
	safeInteger: safeInteger,
	nonNegativeInteger: nonNegativeInteger,
	boundedString: boundedString,
	codeString: codeString,
	enumValue: enumValue,
	onlyFields: onlyFields,
	failure: failure,
	requireFields: requireFields,
	uniqueIds: uniqueIds,
	validatePublicError: validatePublicError,
	validateDiagnosticsContract: validateDiagnosticsContract,
	optionalIntegers: optionalIntegers,
	validateCapabilities: validateCapabilities,
	validateProbeFailures: validateProbeFailures,
	validateBpfEvidence: validateBpfEvidence,
	validateHealthEvidence: validateHealthEvidence,
	validateCoverage: validateCoverage,
	validateRateDirectionMeta: validateRateDirectionMeta,
	validateRateMeta: validateRateMeta,
	validateStatusResponse: validateStatusResponse,
	validateHealthResponse: validateHealthResponse,
	validateClientsResponse: validateClientsResponse,
	validateInterfacesResponse: validateInterfacesResponse,
	validateOverviewResponse: validateOverviewResponse,
	validateRuntimeResponse: validateRuntimeResponse
});
