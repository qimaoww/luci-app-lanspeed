'use strict';
'require baseclass';

/*
 * The configuration page has two consumers of the same contract: the UCI
 * editor and the runtime/interface capability editor.  Keep normalization and
 * validation here so neither renderer silently invents a different value.
 */

var MAX_INTERFACE_NAMES = 16;
var MAX_INTERFACE_NAME_LEN = 31;
var MAX_RANGE_ITEMS = 32;
var MAX_RANGE_LENGTH = 64;

var DEFAULTS = {
	refresh_interval_ms: 1000,
	active_client_window_ms: 10000,
	active_client_min_bps: 1,
	overview_window_samples: 240,
	rate_collector_mode: 'auto',
	conn_collector_mode: 'auto',
	show_client_status: '0',
	show_ipv6: '1',
	hide_private_ipv6: '0',
	hide_ipv6_ranges: 'fc00::/7 fe80::/10',
	collector_mode: 'auto',
	max_clients: 2048,
	ifname: [],
	interface_include: [],
	interface_exclude: [],
	observe: [],
	enable_bpf: '1',
	enable_conntrack_fallback: '1'
};

var LIMITS = {
	refresh_interval_ms: { min: 500, max: 4294967295, step: 100 },
	active_client_window_ms: { min: 1000, max: 9007199254740991, step: 1000 },
	active_client_min_bps: { min: 1, max: 9007199254740991, step: 1 },
	overview_window_samples: { min: 2, max: 240, step: 1 },
	max_clients: { min: 64, max: 16384, step: 1 }
};

var RATE_MODES = [
	{ value: 'auto', label: _('自动'), capability: null },
	{ value: 'bpf', label: 'BPF', capability: 'bpf' },
	{ value: 'nss_ecm_direct', label: 'NSS-direct', capability: 'nss_ecm_direct' },
	{ value: 'nss_conntrack_sync', label: 'NSS sync', capability: 'nss_conntrack_sync' }
];

var CONNECTION_MODES = [
	{ value: 'auto', label: _('自动'), capability: null },
	{ value: 'conntrack_netlink', label: 'CT-Netlink', capability: 'conntrack_netlink' },
	{ value: 'conntrack_procfs', label: 'CT-Procfs', capability: 'conntrack_procfs' }
];

var FIELD_DEFS = [
	{ name: 'refresh_interval_ms', kind: 'integer', label: _('采样间隔'), unit: 'ms', limits: LIMITS.refresh_interval_ms },
	{ name: 'active_client_window_ms', kind: 'integer', label: _('活跃客户端窗口'), unit: 'ms', limits: LIMITS.active_client_window_ms },
	{ name: 'active_client_min_bps', kind: 'integer', label: _('活跃最小速率'), unit: 'bps', limits: LIMITS.active_client_min_bps },
	{ name: 'overview_window_samples', kind: 'integer', label: _('历史采样点'), unit: _('个'), limits: LIMITS.overview_window_samples },
	{ name: 'rate_collector_mode', kind: 'enum', label: _('速率采集') },
	{ name: 'conn_collector_mode', kind: 'enum', label: _('连接数采集') },
	{ name: 'show_client_status', kind: 'boolean', label: _('显示客户端状态') },
	{ name: 'show_ipv6', kind: 'boolean', label: _('显示 IPv6 地址') },
	{ name: 'hide_private_ipv6', kind: 'boolean', label: _('隐藏私有 IPv6 地址') },
	{ name: 'hide_ipv6_ranges', kind: 'cidr-list', label: _('隐藏 IPv6 范围') },
	{ name: 'collector_mode', kind: 'legacy-enum', label: _('兼容采集模式'), compatibility: true },
	{ name: 'max_clients', kind: 'integer', label: _('客户端上限'), limits: LIMITS.max_clients },
	{ name: 'ifname', kind: 'interface-list', label: _('旧版采集接口'), compatibility: true },
	{ name: 'interface_include', kind: 'interface-list', label: _('采集接口') },
	{ name: 'interface_exclude', kind: 'interface-list', label: _('排除接口'), compatibility: true },
	{ name: 'observe', kind: 'interface-list', label: _('观察接口') },
	{ name: 'enable_bpf', kind: 'boolean', label: _('启用 BPF') },
	{ name: 'enable_conntrack_fallback', kind: 'boolean', label: _('允许连接跟踪回退') }
];

function clone(value) {
	if (Array.isArray(value))
		return value.slice();
	if (value && typeof value === 'object')
		return Object.assign({}, value);
	return value;
}

function asText(value) {
	return value === undefined || value === null ? '' : String(value);
}

function trimAscii(value) {
	return asText(value).replace(/^[\t\n\r\f ]+|[\t\n\r\f ]+$/g, '');
}

function asList(value) {
	if (Array.isArray(value))
		return value.slice();
	if (typeof value === 'string')
		return value.split(/[\s,]+/).filter(Boolean);
	return [];
}

function unique(values) {
	var seen = {};
	var output = [];
	(asList(values)).forEach(function(value) {
		value = asText(value);
		if (!seen[value]) {
			seen[value] = true;
			output.push(value);
		}
	});
	return output;
}

function parseInteger(value, limits) {
	var raw = trimAscii(value);
	var parsed;
	if (!/^[+-]?\d+$/.test(raw))
		return { valid: false, value: null, raw: raw, reason: 'integer_required' };
	parsed = Number(raw);
	if (!isFinite(parsed) || Math.floor(parsed) !== parsed || Math.abs(parsed) > 9007199254740991)
		return { valid: false, value: null, raw: raw, reason: 'integer_out_of_range' };
	if (limits && parsed < limits.min)
		return { valid: false, value: parsed, raw: raw, reason: 'below_min', min: limits.min };
	if (limits && parsed > limits.max)
		return { valid: false, value: parsed, raw: raw, reason: 'above_max', max: limits.max };
	return { valid: true, value: parsed, raw: raw };
}

function parseBoolean(value, fallback) {
	var raw = trimAscii(value).toLowerCase();
	if (raw === '1' || raw === 'true')
		return { valid: true, value: '1', raw: raw };
	if (raw === '0' || raw === 'false')
		return { valid: true, value: '0', raw: raw };
	return { valid: false, value: fallback, raw: raw, reason: 'boolean_required' };
}

function validInterfaceName(value) {
	/* Linux names cannot contain whitespace, slash, NUL, or a comma. */
	return typeof value === 'string' && value.length > 0 && value.length <= MAX_INTERFACE_NAME_LEN &&
		/^[^\s/,\u0000]+$/.test(value);
}

function parseInterfaceList(value) {
	var raw = Array.isArray(value) ? value.slice() : (typeof value === 'string' ? [ value ] : []);
	var valid = [];
	var invalid = [];
	var seen = {};
	raw.forEach(function(item) {
		var name = trimAscii(item);
		/* A scalar UCI list is one value; accept whitespace-separated legacy text. */
		if (raw.length === 1 && typeof value === 'string' && /[\s,]/.test(name)) {
			name.split(/[\s,]+/).filter(Boolean).forEach(function(part) {
				if (!seen[part]) {
					seen[part] = true;
					if (validInterfaceName(part)) valid.push(part); else invalid.push(part);
				}
			});
			return;
		}
		if (!name || seen[name])
			return;
		seen[name] = true;
		if (validInterfaceName(name)) valid.push(name); else invalid.push(name);
	});
	return { valid: valid.slice(0, MAX_INTERFACE_NAMES), invalid: invalid, truncated: valid.length > MAX_INTERFACE_NAMES };
}

function parseIpv6Words(value) {
	var source = trimAscii(value).toLowerCase();
	var parts;
	var head;
	var tail;
	var words = [];
	var missing;
	var i;
	if (!source || source.indexOf('.') >= 0 || source.indexOf(':') < 0)
		return null;
	parts = source.split('::');
	if (parts.length > 2)
		return null;
	head = parts[0] ? parts[0].split(':') : [];
	tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
	missing = parts.length === 2 ? 8 - head.length - tail.length : 0;
	if (missing < 0 || (parts.length === 1 && head.length !== 8))
		return null;
	for (i = 0; i < head.length; i++) {
		if (!/^[0-9a-f]{1,4}$/.test(head[i])) return null;
		words.push(parseInt(head[i], 16));
	}
	for (i = 0; i < missing; i++) words.push(0);
	for (i = 0; i < tail.length; i++) {
		if (!/^[0-9a-f]{1,4}$/.test(tail[i])) return null;
		words.push(parseInt(tail[i], 16));
	}
	return words.length === 8 ? words : null;
}

function parseCidr(value) {
	var source = trimAscii(value).toLowerCase();
	var parts = source.split('/');
	var bits;
	if (parts.length !== 2 || source.length > MAX_RANGE_LENGTH)
		return { valid: false, value: source, reason: 'cidr_required' };
	if (!parseIpv6Words(parts[0]))
		return { valid: false, value: source, reason: 'ipv6_required' };
	if (!/^\d{1,3}$/.test(parts[1]))
		return { valid: false, value: source, reason: 'prefix_required' };
	bits = Number(parts[1]);
	if (bits < 0 || bits > 128)
		return { valid: false, value: source, reason: 'prefix_out_of_range' };
	return { valid: true, value: source };
}

function parseCidrList(value) {
	var raw = Array.isArray(value) ? value.slice() : asList(value);
	var valid = [];
	var invalid = [];
	var seen = {};
	raw.forEach(function(item) {
		var parsed = parseCidr(item);
		if (!parsed.valid) {
			if (trimAscii(item)) invalid.push(trimAscii(item));
		} else if (!seen[parsed.value]) {
			seen[parsed.value] = true;
			valid.push(parsed.value);
		}
	});
	if (valid.length > MAX_RANGE_ITEMS)
		return { valid: valid.slice(0, MAX_RANGE_ITEMS), invalid: invalid, truncated: true };
	return { valid: valid, invalid: invalid, truncated: false };
}

function legacyRate(value) {
	return value === 'bpf' ? 'bpf' : 'auto';
}

function legacyConnection(value) {
	if (value === 'conntrack_netlink' || value === 'conntrack_procfs')
		return value;
	return 'auto';
}

function normalizeEnum(value, allowed, fallback) {
	var raw = trimAscii(value);
	var found = allowed.some(function(item) { return item.value === raw; });
	return { valid: found, value: found ? raw : fallback, raw: raw, reason: found ? null : 'enum_required' };
}

function normalize(raw) {
	raw = raw || {};
	var values = {};
	var errors = {};
	var warnings = [];
	var present = {};
	var issue;
	var numberFields = [ 'refresh_interval_ms', 'active_client_window_ms', 'active_client_min_bps',
		'overview_window_samples', 'max_clients' ];
	var listFields = [ 'ifname', 'interface_include', 'interface_exclude', 'observe' ];

	numberFields.forEach(function(name) {
		var result = parseInteger(raw[name] === undefined ? DEFAULTS[name] : raw[name], LIMITS[name]);
		values[name] = result.valid ? result.value : DEFAULTS[name];
		present[name] = raw[name] !== undefined && raw[name] !== null;
		if (!result.valid && present[name]) errors[name] = result.reason;
	});

	var legacyRaw = raw.collector_mode === undefined ? DEFAULTS.collector_mode : raw.collector_mode;
	var legacy = normalizeEnum(legacyRaw, [
		{ value: 'auto' }, { value: 'bpf' }, { value: 'conntrack_netlink' }, { value: 'conntrack_procfs' }
	], DEFAULTS.collector_mode);
	values.collector_mode = legacy.value;
	present.collector_mode = raw.collector_mode !== undefined && raw.collector_mode !== null;
	if (!legacy.valid && present.collector_mode) errors.collector_mode = legacy.reason;

	var rateRaw = raw.rate_collector_mode;
	var connRaw = raw.conn_collector_mode;
	if (rateRaw === 'conntrack_ecm_sync') {
		rateRaw = 'nss_conntrack_sync';
		warnings.push({ field: 'rate_collector_mode', code: 'legacy_alias_normalized' });
	}
	var rate = normalizeEnum(rateRaw === undefined ? legacyRate(legacy.value) : rateRaw, RATE_MODES, DEFAULTS.rate_collector_mode);
	var conn = normalizeEnum(connRaw === undefined ? legacyConnection(legacy.value) : connRaw, CONNECTION_MODES, DEFAULTS.conn_collector_mode);
	values.rate_collector_mode = rate.value;
	values.conn_collector_mode = conn.value;
	present.rate_collector_mode = rateRaw !== undefined && rateRaw !== null;
	present.conn_collector_mode = connRaw !== undefined && connRaw !== null;
	if (!rate.valid && present.rate_collector_mode) errors.rate_collector_mode = rate.reason;
	if (!conn.valid && present.conn_collector_mode) errors.conn_collector_mode = conn.reason;

	[ 'show_client_status', 'show_ipv6', 'hide_private_ipv6', 'enable_bpf', 'enable_conntrack_fallback' ].forEach(function(name) {
		var result = parseBoolean(raw[name] === undefined ? DEFAULTS[name] : raw[name], DEFAULTS[name]);
		values[name] = result.value;
		present[name] = raw[name] !== undefined && raw[name] !== null;
		if (!result.valid && present[name]) errors[name] = result.reason;
	});

	var ranges = parseCidrList(raw.hide_ipv6_ranges === undefined ? DEFAULTS.hide_ipv6_ranges : raw.hide_ipv6_ranges);
	values.hide_ipv6_ranges = ranges.valid.join(' ');
	present.hide_ipv6_ranges = raw.hide_ipv6_ranges !== undefined && raw.hide_ipv6_ranges !== null;
	if (ranges.invalid.length || ranges.truncated)
		errors.hide_ipv6_ranges = ranges.invalid.length ? 'cidr_invalid' : 'too_many_ranges';

	listFields.forEach(function(name) {
		var result = parseInterfaceList(raw[name]);
		values[name] = result.valid;
		present[name] = raw[name] !== undefined && raw[name] !== null;
		if (result.invalid.length || result.truncated)
			errors[name] = result.invalid.length ? 'interface_invalid' : 'too_many_interfaces';
	});

	if (values.hide_private_ipv6 === '0')
		warnings.push({ field: 'hide_ipv6_ranges', code: 'dependency_disabled' });
	if (values.enable_bpf === '0' && values.rate_collector_mode === 'bpf')
		errors.rate_collector_mode = 'bpf_disabled';
	if (values.enable_conntrack_fallback === '0' && values.rate_collector_mode === 'nss_conntrack_sync')
		errors.rate_collector_mode = 'conntrack_fallback_disabled';
	if (unique(values.ifname.concat(values.interface_include)).length > MAX_INTERFACE_NAMES)
		errors.interface_include = 'too_many_interfaces';
	if (values.observe.length > MAX_INTERFACE_NAMES)
		errors.observe = 'too_many_interfaces';
	if (values.interface_exclude.length > MAX_INTERFACE_NAMES)
		errors.interface_exclude = 'too_many_interfaces';

	/* Legacy field is written from the split rate mode but remains visible as a compatibility fact. */
	if (values.rate_collector_mode === 'bpf' || values.rate_collector_mode === 'nss_ecm_direct' ||
		values.rate_collector_mode === 'nss_conntrack_sync')
		values.collector_mode = 'bpf';
	else if (values.conn_collector_mode !== 'auto' && values.rate_collector_mode === 'auto')
		values.collector_mode = values.conn_collector_mode;
	else
		values.collector_mode = 'auto';

	issue = {
		values: values,
		errors: errors,
		warnings: warnings,
		present: present,
		valid: Object.keys(errors).length === 0
	};
	return issue;
}

function capabilityState(status, values) {
	status = status && typeof status === 'object' ? status : {};
	var caps = status.capabilities && typeof status.capabilities === 'object' ? status.capabilities : {};
	var evidence = status.evidence && typeof status.evidence === 'object' ? status.evidence : {};
	var collector = evidence.collector && typeof evidence.collector === 'object' ? evidence.collector : {};
	var state = {};
	function set(name, allowed, reason, known) {
		state[name] = { allowed: allowed !== false, known: known === true, reason: reason || null };
	}
	function knownFalse(name) { return Object.prototype.hasOwnProperty.call(caps, name) && caps[name] === false; }
	function has(name) { return Object.prototype.hasOwnProperty.call(caps, name); }

	if (values && values.enable_bpf === '0')
		set('bpf', false, 'bpf_disabled', true);
	else if (knownFalse('bpf_supported') || knownFalse('bpf_package') || knownFalse('bpf_object') ||
		knownFalse('tc') || knownFalse('tc_clsact'))
		set('bpf', false, 'bpf_unavailable', true);
	else
		set('bpf', true, null, has('bpf_supported') ||
			[ 'bpf_package', 'bpf_object', 'tc', 'tc_clsact' ].every(has));

	if (knownFalse('nss_ecm_direct') || knownFalse('nss') || knownFalse('nss_ecm_offload'))
		set('nss_ecm_direct', false, 'nss_direct_unavailable', true);
	else
		set('nss_ecm_direct', true, null, Object.prototype.hasOwnProperty.call(caps, 'nss_ecm_direct'));

	if (values && values.enable_conntrack_fallback === '0')
		set('nss_conntrack_sync', false, 'conntrack_fallback_disabled', true);
	else if (knownFalse('nf_conntrack_acct') || knownFalse('conntrack_fallback') || knownFalse('nss'))
		set('nss_conntrack_sync', false, 'nss_sync_unavailable', true);
	else
		set('nss_conntrack_sync', true, null,
			Object.prototype.hasOwnProperty.call(caps, 'conntrack_fallback'));

	[ 'conntrack_netlink', 'conntrack_procfs' ].forEach(function(name) {
		var value = collector[name + '_available'];
		if (value === false)
			set(name, false, name + '_unavailable', true);
		else
			set(name, true, null, typeof value === 'boolean');
	});
	set('auto', true, null, true);
	return state;
}

function validate(values, status, interfaceState) {
	var normalized = normalize(values);
	var capabilities = capabilityState(status, normalized.values);
	var errors = Object.assign({}, normalized.errors);
	var warnings = normalized.warnings.slice();
	var mode;
	[ 'rate_collector_mode', 'conn_collector_mode' ].forEach(function(field) {
		mode = normalized.values[field];
		if (mode !== 'auto' && capabilities[mode] && capabilities[mode].known && !capabilities[mode].allowed)
			errors[field] = capabilities[mode].reason || 'capability_unavailable';
		else if (mode !== 'auto' && capabilities[mode] && !capabilities[mode].known)
			warnings.push({ field: field, code: 'capability_pending' });
	});
	if (normalized.values.rate_collector_mode === 'bpf' && normalized.values.enable_bpf === '1' &&
		unique((normalized.values.ifname || []).concat(normalized.values.interface_include || [])).length === 0)
		errors.rate_collector_mode = 'no_collect_interface';
	else if (normalized.values.rate_collector_mode === 'bpf' && status && status.capabilities &&
		status.capabilities.bpf_runtime_metrics === false && !errors.rate_collector_mode)
		warnings.push({ field: 'rate_collector_mode', code: 'bpf_runtime_not_ready' });
	if (interfaceState && interfaceState.errors)
		Object.keys(interfaceState.errors).forEach(function(field) { errors[field] = interfaceState.errors[field]; });
	return {
		values: normalized.values,
		errors: errors,
		warnings: warnings,
		capabilities: capabilities,
		present: normalized.present,
		valid: Object.keys(errors).length === 0
	};
}

function collectorModeFor(values) {
	values = values || {};
	if (values.rate_collector_mode === 'bpf' || values.rate_collector_mode === 'nss_ecm_direct' ||
		values.rate_collector_mode === 'nss_conntrack_sync')
		return 'bpf';
	if (values.rate_collector_mode === 'auto' && values.conn_collector_mode === 'conntrack_netlink')
		return 'conntrack_netlink';
	if (values.rate_collector_mode === 'auto' && values.conn_collector_mode === 'conntrack_procfs')
		return 'conntrack_procfs';
	return 'auto';
}

function buildUciPatch(values, original) {
	var normalized = normalize(values).values;
	var originalValues = original || {};
	var set = {};
	var unset = [];
	var scalarFields = [
		'refresh_interval_ms', 'active_client_window_ms', 'active_client_min_bps',
		'overview_window_samples', 'rate_collector_mode', 'conn_collector_mode',
		'show_client_status', 'show_ipv6', 'hide_private_ipv6', 'hide_ipv6_ranges',
		'collector_mode', 'max_clients', 'enable_bpf', 'enable_conntrack_fallback'
	];
	var listFields = [ 'ifname', 'interface_include', 'interface_exclude', 'observe' ];
	scalarFields.forEach(function(name) {
		var value = name === 'collector_mode' ? collectorModeFor(normalized) : normalized[name];
		if (value !== undefined && value !== null)
			set[name] = String(value);
	});
	listFields.forEach(function(name) {
		var valuesList = unique(normalized[name]);
		if (valuesList.length)
			set[name] = valuesList;
		else if (Object.prototype.hasOwnProperty.call(originalValues, name) &&
			originalValues[name] !== undefined && originalValues[name] !== null)
			unset.push(name);
	});
	return { set: set, unset: unique(unset) };
}

function modeChoices(kind, status, values) {
	var source = kind === 'rate' ? RATE_MODES : CONNECTION_MODES;
	var caps = capabilityState(status, values || DEFAULTS);
	return source.map(function(item) {
		var cap = item.capability ? caps[item.capability] : caps.auto;
		return {
			value: item.value,
			label: item.label,
			disabled: !!(cap && cap.known && !cap.allowed),
			reason: cap && cap.reason,
			pending: !!(cap && !cap.known)
		};
	});
}

return baseclass.extend({
	DEFAULTS: DEFAULTS,
	LIMITS: LIMITS,
	FIELDS: FIELD_DEFS,
	MAX_INTERFACE_NAMES: MAX_INTERFACE_NAMES,
	MAX_RANGE_ITEMS: MAX_RANGE_ITEMS,
	parseInteger: parseInteger,
	parseBoolean: parseBoolean,
	parseCidr: parseCidr,
	parseCidrList: parseCidrList,
	parseInterfaceList: parseInterfaceList,
	normalize: normalize,
	validate: validate,
	capabilityState: capabilityState,
	modeChoices: modeChoices,
	collectorModeFor: collectorModeFor,
	buildUciPatch: buildUciPatch
});
