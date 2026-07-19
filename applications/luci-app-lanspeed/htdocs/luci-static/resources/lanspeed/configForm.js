'use strict';
'require baseclass';
'require uci';
'require lanspeed.rpc as lsRpc';
'require lanspeed.ifaceConfig as ifaceCfg';
'require lanspeed.configModel as cfgModel';

var FIELD_NAMES = cfgModel.FIELDS.map(function(field) { return field.name; });
var LIST_FIELDS = [ 'ifname', 'interface_include', 'interface_exclude', 'observe' ];
var BOOLEAN_FIELDS = [ 'show_client_status', 'show_ipv6', 'hide_private_ipv6',
	'enable_bpf', 'enable_conntrack_fallback' ];
var NUMBER_FIELDS = [ 'refresh_interval_ms', 'active_client_window_ms',
	'active_client_min_bps', 'overview_window_samples', 'max_clients' ];
var STATUS_RATE_MODES = [ 'auto', 'bpf', 'nss_ecm_direct', 'nss_conntrack_sync' ];
var STATUS_CONNECTION_MODES = [ 'auto', 'conntrack_netlink', 'conntrack_procfs' ];
var STATUS_MODES = [ 'Full', 'Degraded', 'Unsupported' ];
var STATUS_CONFIDENCE = [ 'high', 'medium', 'low', 'unsupported' ];
var REQUIRED_STATUS_CAPABILITIES = [ 'bpf', 'conntrack_fallback' ];

function text(value) {
	return value === undefined || value === null ? '' : String(value);
}

function cloneValues(values) {
	if (Array.isArray(values))
		return values.slice();
	if (!values || typeof values !== 'object')
		return values;
	var result = {};
	Object.keys(values).forEach(function(name) {
		result[name] = Array.isArray(values[name]) ? values[name].slice() : values[name];
	});
	return result;
}

function plainObject(value) {
	return !!value && typeof value === 'object' && !Array.isArray(value);
}

function statusContractIssue(status) {
	var capabilities;
	var evidence;
	var collector;
	if (!plainObject(status))
		return _('响应不是对象');
	if (STATUS_MODES.indexOf(status.mode) === -1)
		return _('运行模式无效');
	if (STATUS_CONFIDENCE.indexOf(status.confidence) === -1)
		return _('置信度字段无效');
	if (!Array.isArray(status.warnings) || status.warnings.some(function(warning) {
		return typeof warning !== 'string';
	}))
		return _('运行告警字段无效');
	if (typeof status.version !== 'string' || !status.version.trim())
		return _('运行版本字段无效');
	if (STATUS_RATE_MODES.indexOf(status.rate_collector_mode) === -1)
		return _('速率采集模式无效');
	if (STATUS_CONNECTION_MODES.indexOf(status.conn_collector_mode) === -1)
		return _('连接采集模式无效');
	if (typeof status.refresh_interval_ms !== 'number' || !isFinite(status.refresh_interval_ms) ||
		Math.floor(status.refresh_interval_ms) !== status.refresh_interval_ms || status.refresh_interval_ms < 500)
		return _('采样周期无效');
	capabilities = status.capabilities;
	if (!plainObject(capabilities) || REQUIRED_STATUS_CAPABILITIES.some(function(name) {
		return !Object.prototype.hasOwnProperty.call(capabilities, name) ||
			typeof capabilities[name] !== 'boolean';
	}) || Object.keys(capabilities).some(function(name) {
		return typeof capabilities[name] !== 'boolean';
	}))
		return _('运行能力字段无效');
	evidence = status.evidence;
	if (!plainObject(evidence))
		return _('运行证据字段无效');
	if (evidence.effective_collector !== undefined && evidence.effective_collector !== null &&
		typeof evidence.effective_collector !== 'string')
		return _('有效速率来源无效');
	if (evidence.collector !== undefined) {
		collector = evidence.collector;
		if (!plainObject(collector))
			return _('采集证据字段无效');
		if ([ 'primary_source', 'effective_connection_collector' ].some(function(name) {
			return collector[name] !== undefined && collector[name] !== null &&
				typeof collector[name] !== 'string';
		}) || [ 'conntrack_netlink_available', 'conntrack_procfs_available' ].some(function(name) {
			return collector[name] !== undefined && typeof collector[name] !== 'boolean';
		}))
			return _('采集证据字段无效');
	}
	return null;
}

function errorMessage(code, field) {
	var limits = cfgModel.LIMITS[field] || {};
	var messages = {
		integer_required: _('请输入完整整数'),
		integer_out_of_range: _('数值超出浏览器可安全处理的范围'),
		below_min: _('数值不得低于 %s').format(limits.min),
		above_max: _('数值不得高于 %s').format(limits.max),
		boolean_required: _('开关值必须是 0 或 1'),
		enum_required: _('当前配置值不受支持，请重新选择'),
		cidr_invalid: _('请输入有效的 IPv6 CIDR，例如 2001:db8::/32'),
		cidr_required: _('请输入带前缀长度的 IPv6 CIDR'),
		ipv6_required: _('这里只接受 IPv6 地址'),
		prefix_required: _('IPv6 前缀长度必须是 0 到 128 的整数'),
		prefix_out_of_range: _('IPv6 前缀长度必须在 0 到 128 之间'),
		too_many_ranges: _('IPv6 范围数量超过上限'),
		interface_invalid: _('接口列表包含无效名称'),
		too_many_interfaces: _('接口数量超过运行时上限'),
		bpf_disabled: _('请先启用 BPF，或改用自动模式'),
		bpf_unavailable: _('当前运行环境不具备完整 BPF 能力'),
		no_collect_interface: _('强制 BPF 模式至少需要一个接口设为“采集”'),
		nss_direct_unavailable: _('当前设备不支持 NSS-direct'),
		nss_sync_unavailable: _('当前设备不支持 NSS sync'),
		conntrack_fallback_disabled: _('请先允许连接跟踪回退，或选择其他速率模式'),
		conntrack_netlink_unavailable: _('当前运行环境不支持 CT-Netlink'),
		conntrack_procfs_unavailable: _('当前运行环境不支持 CT-Procfs'),
		capability_unavailable: _('当前运行能力不支持此值')
	};
	return messages[code] || text(code || _('配置值无效'));
}

function rawUciValues() {
	var values = {};
	FIELD_NAMES.forEach(function(name) {
		values[name] = uci.get('lanspeed', 'main', name);
	});
	return values;
}

function hasMainSection(raw) {
	var found = FIELD_NAMES.some(function(name) {
		return raw[name] !== undefined && raw[name] !== null;
	});
	if (found)
		return true;
	try {
		if (typeof uci.sections === 'function')
			return uci.sections('lanspeed', 'lanspeed').some(function(section) {
				return section && (section['.name'] === 'main' || section.name === 'main');
			});
		var section = uci.get('lanspeed', 'main');
		return !!(section && typeof section === 'object');
	} catch (error) {
		return false;
	}
}

function interfaceConfigFrom(raw) {
	var present = {};
	var result = {};
	LIST_FIELDS.forEach(function(name) {
		result[name] = cfgModel.parseInterfaceList(raw[name]).valid;
		present[name] = raw[name] !== undefined && raw[name] !== null;
	});
	result.present = present;
	return result;
}

function loadStatus(values) {
	return Promise.resolve().then(function() {
		return lsRpc.status();
	}).then(function(status) {
		var issue = statusContractIssue(status);
		if (issue) {
			var invalid = new Error(_('运行状态返回无效数据：%s').format(issue));
			invalid.code = 'INVALID_STATUS_RESPONSE';
			throw invalid;
		}
		values.status = status;
		values.rpc.status = { ok: true, phase: 'success', error: null };
		return values;
	}).catch(function(error) {
		values.status = {};
		values.rpc.status = {
			ok: false,
			phase: error && error.code === 'INVALID_STATUS_RESPONSE' ? 'invalid' : 'error',
			error: error
		};
		values.pageState = 'degraded';
		return values;
	});
}

function loadValues() {
	return Promise.resolve().then(function() {
		return uci.load('lanspeed');
	}).then(function() {
		var raw = rawUciValues();
		var normalized = cfgModel.normalize(raw);
		var sectionPresent = hasMainSection(raw);
		var values = Object.assign({}, normalized.values, {
			raw: raw,
			model: normalized,
			status: {},
			rpc: { uci: { ok: true, error: null } },
			sectionMissing: !sectionPresent,
			pageState: !sectionPresent ? 'empty' : (normalized.valid ? 'ready' : 'degraded'),
			interfaceConfig: interfaceConfigFrom(raw)
		});
		return loadStatus(values);
	});
}

function fieldId(name) {
	return 'lanspeed-config-' + name.replace(/_/g, '-');
}

function numberInput(name, value) {
	var limits = cfgModel.LIMITS[name];
	return E('input', {
		'id': fieldId(name),
		'type': 'number',
		'class': 'cbi-input-text',
		'inputmode': 'numeric',
		'min': String(limits.min),
		'max': String(limits.max),
		'step': String(limits.step),
		'value': String(value),
		'aria-describedby': fieldId(name) + '-hint ' + fieldId(name) + '-error'
	});
}

function toggleInput(name, label, enabled) {
	var input = E('input', {
		'id': fieldId(name),
		'type': 'checkbox',
		'class': 'cbi-input-checkbox lanspeed-switch',
		'role': 'switch',
		'aria-label': label,
		'aria-describedby': fieldId(name) + '-hint ' + fieldId(name) + '-error'
	});
	input.checked = enabled === true;
	return E('label', { 'class': 'lanspeed-toggle cbi-checkbox', 'for': fieldId(name) }, [
		input,
		E('span', { 'class': 'lanspeed-toggle-label' }, enabled ? _('已启用') : _('已停用'))
	]);
}

function choiceSelect(name, choices, value) {
	var select = E('select', {
		'id': fieldId(name),
		'class': 'cbi-input-select',
		'aria-describedby': fieldId(name) + '-hint ' + fieldId(name) + '-error'
	}, choices.map(function(choice) {
		var attrs = { 'value': choice.value };
		if (choice.value === value) attrs.selected = 'selected';
		if (choice.disabled) attrs.disabled = 'disabled';
		if (choice.reason) attrs.title = errorMessage(choice.reason, name);
		return E('option', attrs, choice.label + (choice.pending ? ' · ' + _('待检测') : ''));
	}));
	select.value = value;
	return select;
}

function rowFor(viewState, name, label, control, hint, attrs) {
	var refs = viewState.daemonRefs;
	var error = E('div', {
		'id': fieldId(name) + '-error',
		'class': 'lanspeed-config-field-error',
		'role': 'alert',
		'aria-live': 'polite',
		'hidden': 'hidden'
	}, '');
	var hintNode = E('div', { 'id': fieldId(name) + '-hint', 'class': 'hint' }, hint || '');
	var rowAttrs = Object.assign({ 'class': 'lanspeed-config-field', 'data-field': name }, attrs || {});
	var row = E('tr', rowAttrs, [
		E('th', { 'scope': 'row' }, E('label', { 'for': fieldId(name) }, label)),
		E('td', { 'class': 'value' }, control),
		E('td', {}, [ hintNode, error ])
	]);
	refs.fields[name] = { row: row, controlWrap: control, input: control, error: error, hint: hintNode };
	return row;
}

function inputOf(field) {
	if (!field)
		return null;
	if (field.controlWrap && field.controlWrap.tagName && String(field.controlWrap.tagName).toLowerCase() === 'label')
		return field.controlWrap.querySelector('input');
	return field.input;
}

function rangeValues(refs) {
	return (refs.hideIpv6RangesItems || []).join(' ');
}

function setFieldError(viewState, name, code) {
	var field = viewState.daemonRefs.fields[name];
	var input = inputOf(field);
	if (!field)
		return;
	if (code) {
		field.error.hidden = false;
		field.error.textContent = errorMessage(code, name);
		field.row.setAttribute('data-state', 'invalid');
		if (input) input.setAttribute('aria-invalid', 'true');
	} else {
		field.error.hidden = true;
		field.error.textContent = '';
		field.row.setAttribute('data-state', 'valid');
		if (input) input.removeAttribute('aria-invalid');
	}
}

function setFeedback(viewState, state, message) {
	var refs = viewState.daemonRefs || {};
	viewState.saveState = state;
	if (refs.saveState) {
		refs.saveState.setAttribute('data-state', state);
		refs.saveState.textContent = message || '';
	}
	if (typeof viewState.updatePageState === 'function')
		viewState.updatePageState();
}

function buildRangeList(viewState) {
	var refs = viewState.daemonRefs;
	refs.hideIpv6RangesList.innerHTML = '';
	refs.rangeRemoveButtons = [];
	(refs.hideIpv6RangesItems || []).forEach(function(value) {
		var remove = E('button', {
			'type': 'button',
			'class': 'lanspeed-range-remove cbi-button cbi-button-remove',
			'aria-label': _('删除 IPv6 范围') + ' ' + value,
			'title': _('删除')
		}, '\u00d7');
		remove.addEventListener('click', function() {
			refs.hideIpv6RangesItems = refs.hideIpv6RangesItems.filter(function(item) { return item !== value; });
			buildRangeList(viewState);
			formChanged(viewState);
		});
		refs.rangeRemoveButtons.push(remove);
		refs.hideIpv6RangesList.appendChild(E('div', { 'class': 'lanspeed-range-pill' }, [
			E('code', { 'class': 'lanspeed-range-value' }, value), remove
		]));
	});
	updateDependencies(viewState);
}

function addRange(viewState) {
	var refs = viewState.daemonRefs;
	var raw = refs.hideIpv6RangeInput.value;
	var parsed = cfgModel.parseCidr(raw);
	if (!parsed.valid) {
		setFieldError(viewState, 'hide_ipv6_ranges', parsed.reason);
		refs.hideIpv6RangeInput.setAttribute('aria-invalid', 'true');
		return false;
	}
	if (refs.hideIpv6RangesItems.indexOf(parsed.value) === -1) {
		if (refs.hideIpv6RangesItems.length >= cfgModel.MAX_RANGE_ITEMS) {
			setFieldError(viewState, 'hide_ipv6_ranges', 'too_many_ranges');
			return false;
		}
		refs.hideIpv6RangesItems.push(parsed.value);
	}
	refs.hideIpv6RangeInput.value = '';
	refs.hideIpv6RangeInput.removeAttribute('aria-invalid');
	buildRangeList(viewState);
	formChanged(viewState);
	return true;
}

function readForm(viewState) {
	var refs = viewState.daemonRefs;
	var values = cloneValues(viewState.currentValues || cfgModel.DEFAULTS);
	NUMBER_FIELDS.forEach(function(name) { values[name] = refs.inputs[name].value; });
	values.rate_collector_mode = refs.inputs.rate_collector_mode.value;
	values.conn_collector_mode = refs.inputs.conn_collector_mode.value;
	BOOLEAN_FIELDS.forEach(function(name) { values[name] = refs.inputs[name].checked ? '1' : '0'; });
	values.hide_ipv6_ranges = rangeValues(refs);
	values.collector_mode = cfgModel.collectorModeFor(values);
	LIST_FIELDS.forEach(function(name) {
		values[name] = cloneValues((viewState.ifaceOriginal || {})[name] || []);
	});
	return values;
}

function interfacePlanFor(viewState) {
	var plan = ifaceCfg.prepareSave(viewState);
	return plan || { changed: false, errors: {} };
}

function validateForm(viewState) {
	var values = readForm(viewState);
	var interfacePlan = interfacePlanFor(viewState);
	if (interfacePlan.desired)
		LIST_FIELDS.forEach(function(name) { values[name] = cloneValues(interfacePlan.desired[name] || []); });
	var validation = cfgModel.validate(values, viewState.runtimeStatus || {}, interfacePlan);
	viewState.currentValues = validation.values;
	viewState.currentValidation = validation;
	viewState.currentInterfacePlan = interfacePlan;
	Object.keys(viewState.daemonRefs.fields).forEach(function(name) {
		setFieldError(viewState, name, validation.errors[name]);
	});
	if (interfacePlan.errors && interfacePlan.errors.interfaces)
		setFeedback(viewState, 'invalid', interfacePlan.errors.interfaces);
	else if (!validation.valid)
		setFeedback(viewState, 'invalid', _('请先修正标记的配置项'));
	else if (viewState.localDirty || viewState.ifcfgDirty)
		setFeedback(viewState, 'dirty', _('配置已修改，尚未保存'));
	else if (viewState.saveState === 'invalid' || viewState.saveState === 'dirty')
		setFeedback(viewState, 'ready', '');
	updateDependencies(viewState);
	if (typeof viewState.onValidityChange === 'function')
		viewState.onValidityChange(validation.valid, Boolean(viewState.configSaving));
	return validation;
}

function replaceSelectOptions(select, choices, value, field) {
	select.innerHTML = '';
	choices.forEach(function(choice) {
		var attrs = { value: choice.value };
		if (choice.value === value) attrs.selected = 'selected';
		if (choice.disabled && choice.value !== value) attrs.disabled = 'disabled';
		if (choice.reason) attrs.title = errorMessage(choice.reason, field);
		select.appendChild(E('option', attrs, choice.label + (choice.pending ? ' · ' + _('待检测') : '')));
	});
	select.value = value;
}

function updateDependencies(viewState) {
	var refs = viewState.daemonRefs;
	if (!refs || !refs.inputs)
		return;
	var values = readForm(viewState);
	var busy = Boolean(viewState.configSaving);
	replaceSelectOptions(refs.inputs.rate_collector_mode,
		cfgModel.modeChoices('rate', viewState.runtimeStatus || {}, values), values.rate_collector_mode,
		'rate_collector_mode');
	replaceSelectOptions(refs.inputs.conn_collector_mode,
		cfgModel.modeChoices('connection', viewState.runtimeStatus || {}, values), values.conn_collector_mode,
		'conn_collector_mode');
	var rangesEnabled = !busy && values.show_ipv6 === '1' && values.hide_private_ipv6 === '1';
	refs.inputs.hide_private_ipv6.disabled = busy || values.show_ipv6 !== '1';
	refs.hideIpv6RangeInput.disabled = !rangesEnabled;
	refs.addRangeBtn.disabled = !rangesEnabled;
	(refs.rangeRemoveButtons || []).forEach(function(button) { button.disabled = !rangesEnabled; });
	if (refs.fields.hide_ipv6_ranges)
		refs.fields.hide_ipv6_ranges.row.setAttribute('data-disabled', rangesEnabled ? 'false' : 'true');
	if (refs.fields.hide_private_ipv6)
		refs.fields.hide_private_ipv6.row.setAttribute('data-disabled', values.show_ipv6 === '1' ? 'false' : 'true');
}

function formChanged(viewState) {
	if (viewState.configSaving)
		return;
	if (typeof viewState.markDirty === 'function')
		viewState.markDirty();
	validateForm(viewState);
}

function fillForm(viewState, values) {
	var refs = viewState.daemonRefs;
	values = cfgModel.normalize(values || cfgModel.DEFAULTS).values;
	NUMBER_FIELDS.forEach(function(name) { refs.inputs[name].value = String(values[name]); });
	refs.inputs.rate_collector_mode.value = values.rate_collector_mode;
	refs.inputs.conn_collector_mode.value = values.conn_collector_mode;
	BOOLEAN_FIELDS.forEach(function(name) {
		refs.inputs[name].checked = values[name] === '1';
		var wrap = refs.inputs[name].parentNode;
		var label = wrap && wrap.querySelector && wrap.querySelector('.lanspeed-toggle-label');
		if (label) label.textContent = refs.inputs[name].checked ? _('已启用') : _('已停用');
	});
	refs.hideIpv6RangesItems = cfgModel.parseCidrList(values.hide_ipv6_ranges).valid;
	refs.hideIpv6RangeInput.value = '';
	buildRangeList(viewState);
	viewState.currentValues = cloneValues(values);
	updateDependencies(viewState);
}

function applyRuntimeInfo(viewState, status) {
	var refs = viewState.daemonRefs;
	var evidence = status && status.evidence || {};
	var collector = evidence.collector || {};
	var effectiveRate = collector.primary_source || evidence.effective_collector || _('未知');
	var effectiveConnection = collector.effective_connection_collector || _('未知');
	refs.runtimeInfo.textContent = _('当前运行：速率 %s · 连接 %s').format(effectiveRate, effectiveConnection);
	refs.runtimeInfo.setAttribute('data-state', viewState.loadData && viewState.loadData.rpc.status.ok ? 'ready' : 'degraded');
}

function buildDaemonSection(data, viewState) {
	data = data || {};
	var values = cfgModel.normalize(data.values || data).values;
	var refs = { fields: {}, inputs: {}, rangeRemoveButtons: [] };
	var rows = [];
	viewState = viewState || {};
	viewState.daemonRefs = refs;
	viewState.loadData = data;
	viewState.runtimeStatus = data.status || {};
	viewState.originalRaw = cloneValues(data.raw || data.values || data);
	viewState.initialValues = cloneValues(values);
	viewState.currentValues = cloneValues(values);
	viewState.sectionMissing = data.sectionMissing === true;
	viewState.ifaceOriginal = data.interfaceConfig || interfaceConfigFrom(data.raw || {});
	viewState.initialIfaceOriginal = cloneValues(viewState.ifaceOriginal);
	viewState.initialIfaceOriginal.present = Object.assign({}, viewState.ifaceOriginal.present || {});

	NUMBER_FIELDS.forEach(function(name) { refs.inputs[name] = numberInput(name, values[name]); });
	refs.inputs.rate_collector_mode = choiceSelect('rate_collector_mode',
		cfgModel.modeChoices('rate', viewState.runtimeStatus, values), values.rate_collector_mode);
	refs.inputs.conn_collector_mode = choiceSelect('conn_collector_mode',
		cfgModel.modeChoices('connection', viewState.runtimeStatus, values), values.conn_collector_mode);
	BOOLEAN_FIELDS.forEach(function(name) {
		var field = cfgModel.FIELDS.filter(function(item) { return item.name === name; })[0];
		var wrap = toggleInput(name, field ? field.label : name, values[name] === '1');
		refs.inputs[name] = wrap.querySelector('input');
		refs.toggleWrap = refs.toggleWrap || {};
		refs.toggleWrap[name] = wrap;
	});

	refs.hideIpv6RangesItems = cfgModel.parseCidrList(values.hide_ipv6_ranges).valid;
	refs.hideIpv6RangesList = E('div', { 'class': 'lanspeed-range-list' });
	refs.hideIpv6RangeInput = E('input', {
		'id': fieldId('hide_ipv6_ranges'), 'type': 'text', 'class': 'cbi-input-text',
		'placeholder': '2001:db8::/32', 'aria-label': _('新增隐藏 IPv6 范围'),
		'aria-describedby': fieldId('hide_ipv6_ranges') + '-hint ' + fieldId('hide_ipv6_ranges') + '-error'
	});
	refs.addRangeBtn = E('button', { 'type': 'button', 'class': 'cbi-button', 'aria-label': _('添加 IPv6 范围') }, _('添加'));
	refs.rangeEditor = E('div', { 'class': 'lanspeed-range-stack' }, [
		refs.hideIpv6RangesList,
		E('div', { 'class': 'lanspeed-range-add' }, [ refs.hideIpv6RangeInput, refs.addRangeBtn ])
	]);

	rows.push(rowFor(viewState, 'rate_collector_mode', _('速率采集'), refs.inputs.rate_collector_mode,
		_('根据运行能力选择客户端速率来源；不可用选项会禁用并保留原因。')));
	rows.push(rowFor(viewState, 'conn_collector_mode', _('连接数采集'), refs.inputs.conn_collector_mode,
		_('CT-Netlink 优先；CT-Procfs 仅用于明确的兼容场景。')));
	rows.push(rowFor(viewState, 'enable_bpf', _('启用 BPF'), refs.toggleWrap.enable_bpf,
		_('关闭后 BPF 模式不可选，自动模式会尝试受支持的其他来源。')));
	rows.push(rowFor(viewState, 'enable_conntrack_fallback', _('允许连接跟踪回退'), refs.toggleWrap.enable_conntrack_fallback,
		_('控制 NSS sync 与连接跟踪回退路径。')));
	rows.push(rowFor(viewState, 'refresh_interval_ms', _('采样间隔'), refs.inputs.refresh_interval_ms,
		_('守护进程采集周期，范围 500 到 4294967295 ms。')));
	rows.push(rowFor(viewState, 'overview_window_samples', _('历史采样点'), refs.inputs.overview_window_samples,
		_('内存中保留的概览样本数，范围 2 到 240。')));
	rows.push(rowFor(viewState, 'max_clients', _('客户端上限'), refs.inputs.max_clients,
		_('客户端与连接聚合容量，范围 64 到 16384。')));
	rows.push(rowFor(viewState, 'active_client_window_ms', _('活跃客户端窗口'), refs.inputs.active_client_window_ms,
		_('最后活动后继续标记为活跃的时长，最少 1000 ms。')));
	rows.push(rowFor(viewState, 'active_client_min_bps', _('活跃最小速率'), refs.inputs.active_client_min_bps,
		_('当前收发速率达到该值时才视为活跃。')));
	rows.push(rowFor(viewState, 'show_client_status', _('显示客户端状态'), refs.toggleWrap.show_client_status,
		_('在实时状态中显示采集来源与告警。')));
	rows.push(rowFor(viewState, 'show_ipv6', _('显示 IPv6 地址'), refs.toggleWrap.show_ipv6,
		_('关闭后实时状态只显示 IPv4，并禁用 IPv6 隐藏规则。')));
	rows.push(rowFor(viewState, 'hide_private_ipv6', _('隐藏私有 IPv6 地址'), refs.toggleWrap.hide_private_ipv6,
		_('仅在显示 IPv6 时可用。'), { 'class': 'lanspeed-config-field lanspeed-private-ipv6-row' }));
	rows.push(rowFor(viewState, 'hide_ipv6_ranges', _('隐藏 IPv6 范围'), refs.rangeEditor,
		_('严格 IPv6 CIDR；仅在上项启用时生效。'), { 'class': 'lanspeed-config-field lanspeed-range-row' }));

	refs.runtimeInfo = E('span', { 'class': 'lanspeed-config-runtime', 'role': 'status', 'aria-live': 'polite' }, '');
	refs.saveState = E('span', { 'class': 'lanspeed-config-save-state', 'role': 'status', 'aria-live': 'polite' }, '');
	refs.resetDefaultsBtn = E('button', { 'type': 'button', 'class': 'cbi-button' }, _('恢复运行参数默认值'));
	refs.resetDefaultsBtn.addEventListener('click', function() {
		var defaults = cloneValues(cfgModel.DEFAULTS);
		LIST_FIELDS.forEach(function(name) { defaults[name] = cloneValues((viewState.ifaceOriginal || {})[name] || []); });
		fillForm(viewState, defaults);
		formChanged(viewState);
	});
	refs.addRangeBtn.addEventListener('click', function() { addRange(viewState); });
	refs.hideIpv6RangeInput.addEventListener('keydown', function(event) {
		if (event.key === 'Enter') { event.preventDefault(); addRange(viewState); }
	});
	NUMBER_FIELDS.concat([ 'rate_collector_mode', 'conn_collector_mode' ]).forEach(function(name) {
		refs.inputs[name].addEventListener(name.indexOf('_mode') >= 0 ? 'change' : 'input', function() { formChanged(viewState); });
	});
	BOOLEAN_FIELDS.forEach(function(name) {
		refs.inputs[name].addEventListener('change', function() {
			var label = refs.toggleWrap[name].querySelector('.lanspeed-toggle-label');
			if (label) label.textContent = refs.inputs[name].checked ? _('已启用') : _('已停用');
			formChanged(viewState);
		});
	});

	var section = E('section', { 'class': 'lanspeed-config-subsection lanspeed-config-runtime-section' }, [
		E('div', { 'class': 'lanspeed-config-subheader' }, [
			E('h4', {}, _('运行与显示设置')), E('span', { 'class': 'spacer' }), refs.runtimeInfo
		]),
		E('div', { 'class': 'lanspeed-config-body' }, [
			E('table', { 'class': 'lanspeed-config-table' }, [
				E('thead', {}, E('tr', {}, [ E('th', {}, _('项目')), E('th', { 'class': 'value' }, _('值')), E('th', {}, _('说明')) ])),
				E('tbody', {}, rows)
			]),
			E('div', { 'class': 'lanspeed-config-actions' }, [ refs.resetDefaultsBtn, E('span', { 'class': 'spacer' }), refs.saveState ])
		])
	]);
	buildRangeList(viewState);
	applyRuntimeInfo(viewState, viewState.runtimeStatus);
	Object.keys((data.model || {}).errors || {}).forEach(function(name) {
		setFieldError(viewState, name, data.model.errors[name]);
	});
	updateDependencies(viewState);
	return section;
}

function formControls(viewState) {
	var refs = viewState.daemonRefs || {};
	var controls = [];
	Object.keys(refs.inputs || {}).forEach(function(name) { controls.push(refs.inputs[name]); });
	controls.push(refs.hideIpv6RangeInput, refs.addRangeBtn, refs.resetDefaultsBtn);
	return controls.concat(refs.rangeRemoveButtons || []).filter(Boolean);
}

function setBusy(viewState, busy) {
	viewState.configSaving = busy;
	formControls(viewState).forEach(function(control) { control.disabled = busy; });
	ifaceCfg.setBusy(viewState, busy);
	if (!busy) updateDependencies(viewState);
	if (typeof viewState.onValidityChange === 'function')
		viewState.onValidityChange(viewState.currentValidation ? viewState.currentValidation.valid : true, busy);
}

function ensureSection(viewState) {
	if (!viewState.sectionMissing)
		return;
	if (typeof uci.add !== 'function')
		throw new Error(_('配置缺少 main 节且当前 LuCI 不支持创建节'));
	uci.add('lanspeed', 'lanspeed', 'main');
	viewState.sectionMissing = false;
}

function snapshotOwnedValues() {
	var values = {};
	FIELD_NAMES.forEach(function(name) { values[name] = uci.get('lanspeed', 'main', name); });
	return values;
}

function applyLocalPatch(patch) {
	Object.keys(patch.set || {}).forEach(function(name) {
		uci.set('lanspeed', 'main', name, Array.isArray(patch.set[name]) ? patch.set[name].slice() : patch.set[name]);
	});
	(patch.unset || []).forEach(function(name) { uci.unset('lanspeed', 'main', name); });
}

function restoreOwnedValues(snapshot) {
	FIELD_NAMES.forEach(function(name) {
		if (snapshot[name] === undefined || snapshot[name] === null)
			uci.unset('lanspeed', 'main', name);
		else
			uci.set('lanspeed', 'main', name, Array.isArray(snapshot[name]) ? snapshot[name].slice() : snapshot[name]);
	});
}

function saveLocalChanges() {
	if (typeof uci.save !== 'function')
		return Promise.reject(new Error(_('当前 LuCI 不支持保存本地 UCI 变更')));
	return Promise.resolve(uci.save());
}

function reloadUciCache() {
	if (typeof uci.unload !== 'function' || typeof uci.load !== 'function')
		return Promise.resolve();
	try {
		uci.unload('lanspeed');
		return Promise.resolve(uci.load('lanspeed'));
	} catch (error) {
		return Promise.reject(error);
	}
}

/*
 * uci.save() submits all locally staged calls concurrently.  A rejected
 * request can therefore leave a subset of the owned options on the remote
 * staging area.  Reload this package, restore only our option allow-list and
 * submit the compensating change; unrelated config packages are untouched.
 */
function rollbackOwnedValues(snapshot, sectionMissing) {
	var reloadError = null;
	return reloadUciCache().catch(function(error) {
		reloadError = error;
	}).then(function() {
		if (sectionMissing && typeof uci.remove === 'function')
			uci.remove('lanspeed', 'main');
		else
			restoreOwnedValues(snapshot);
		return saveLocalChanges();
	}).then(function() {
		return { reloadError: reloadError };
	});
}

function prepareSave(viewState) {
	var validation = validateForm(viewState);
	var interfacePlan = viewState.currentInterfacePlan || interfacePlanFor(viewState);
	if (!validation.valid)
		throw new Error(_('配置校验失败，请修正标记字段'));
	var values = cloneValues(validation.values);
	if (interfacePlan.desired)
		LIST_FIELDS.forEach(function(name) { values[name] = cloneValues(interfacePlan.desired[name] || []); });
	return {
		values: values,
		interfacePlan: interfacePlan,
		patch: cfgModel.buildUciPatch(values, viewState.originalRaw || {}),
		viewState: viewState
	};
}

function saveAllSettings(viewState) {
	var plan;
	var snapshot;
	var sectionMissing;
	if (!viewState || !viewState.daemonRefs)
		return Promise.reject(new Error(_('配置页面尚未准备完成')));
	if (viewState.configSaving)
		return Promise.reject(new Error(_('配置保存正在进行中')));
	try {
		plan = prepareSave(viewState);
		sectionMissing = viewState.sectionMissing === true;
		ensureSection(viewState);
		snapshot = snapshotOwnedValues();
		applyLocalPatch(plan.patch);
	} catch (error) {
		if (snapshot) {
			try {
				if (sectionMissing && typeof uci.remove === 'function') uci.remove('lanspeed', 'main');
				else restoreOwnedValues(snapshot);
			} catch (ignored) {}
		}
		if (sectionMissing)
			viewState.sectionMissing = true;
		return Promise.reject(error);
	}
	setBusy(viewState, true);
	setFeedback(viewState, 'saving', _('正在暂存配置…'));
	return saveLocalChanges().then(function() {
		viewState.originalRaw = cloneValues(plan.values);
		viewState.currentValues = cloneValues(plan.values);
		viewState.lastSavePlan = plan;
		viewState.hasStagedSave = true;
		viewState.sectionMissing = false;
		ifaceCfg.markSaved(plan.interfacePlan);
		setFeedback(viewState, 'staged', _('配置已暂存，等待应用'));
		return { ok: true, staged: true, plan: plan };
	}).catch(function(writeError) {
		return rollbackOwnedValues(snapshot, sectionMissing).then(function(rollback) {
			viewState.sectionMissing = sectionMissing;
			throw new Error(_('配置暂存失败：') + text(writeError && writeError.message || writeError) +
				(rollback.reloadError ? _('；暂存状态刷新失败：') + text(rollback.reloadError.message || rollback.reloadError) :
					_('；本页字段已回滚')));
		}, function(rollbackError) {
			viewState.sectionMissing = sectionMissing;
			throw new Error(_('配置暂存失败：') + text(writeError && writeError.message || writeError) +
				_('；本页字段回滚失败：') + text(rollbackError && rollbackError.message || rollbackError));
		});
	}).then(function(result) {
		setBusy(viewState, false);
		return result;
	}, function(error) {
		setBusy(viewState, false);
		setFeedback(viewState, 'error', error.message || text(error));
		throw error;
	});
}

function resetAllSettings(viewState) {
	if (!viewState || !viewState.daemonRefs)
		return Promise.reject(new Error(_('配置页面尚未准备完成')));
	if (viewState.configSaving)
		return Promise.reject(new Error(_('配置保存正在进行中')));
	var values = cloneValues(viewState.initialValues || cfgModel.DEFAULTS);
	var iface = viewState.initialIfaceOriginal || { ifname: [], interface_include: [], interface_exclude: [], observe: [], present: {} };
	var stagedValues = cloneValues(viewState.originalRaw || {});
	var stagedIface = cloneValues(viewState.ifaceOriginal || {});
	LIST_FIELDS.forEach(function(name) { values[name] = cloneValues(iface[name] || []); });
	viewState.ifaceOriginal = {
		ifname: cloneValues(iface.ifname || []),
		interface_include: cloneValues(iface.interface_include || []),
		interface_exclude: cloneValues(iface.interface_exclude || []),
		observe: cloneValues(iface.observe || []),
		present: Object.assign({}, iface.present || {})
	};
	viewState.ifcfgDirty = false;
	viewState.orphanRemovals = {};
	fillForm(viewState, values);
	if (!viewState.hasStagedSave) {
		setFeedback(viewState, 'ready', _('已恢复到页面加载时的值'));
		return ifaceCfg.load(viewState).then(function() { return { ok: true, staged: false }; });
	}
	var patch = cfgModel.buildUciPatch(values, viewState.originalRaw || {});
	var snapshot = snapshotOwnedValues();
	var sectionMissing = viewState.sectionMissing === true;
	try { applyLocalPatch(patch); }
	catch (error) { return Promise.reject(error); }
	setBusy(viewState, true);
	setFeedback(viewState, 'saving', _('正在撤销本页暂存值…'));
	return saveLocalChanges().then(function() {
		viewState.hasStagedSave = false;
		viewState.originalRaw = cloneValues(values);
		setFeedback(viewState, 'ready', _('已撤销本页暂存值'));
		return ifaceCfg.load(viewState).then(function() { return { ok: true, staged: true }; });
	}).catch(function(error) {
		return rollbackOwnedValues(snapshot, sectionMissing).then(function(rollback) {
			viewState.originalRaw = stagedValues;
			viewState.ifaceOriginal = stagedIface;
			viewState.hasStagedSave = true;
			fillForm(viewState, stagedValues);
			throw new Error(_('重置失败：') + text(error && error.message || error) +
				(rollback.reloadError ? _('；暂存状态刷新失败：') + text(rollback.reloadError.message || rollback.reloadError) :
					_('；本页字段已回滚')));
		}, function(rollbackError) {
			throw new Error(_('重置失败：') + text(error && error.message || error) +
				_('；本页字段回滚失败：') + text(rollbackError && rollbackError.message || rollbackError));
		});
	}).then(function(result) {
		setBusy(viewState, false);
		return result;
	}, function(error) {
		setBusy(viewState, false);
		setFeedback(viewState, 'error', error.message || text(error));
		throw error;
	});
}

function statusMatches(status, values) {
	if (statusContractIssue(status)) return false;
	return status.rate_collector_mode === values.rate_collector_mode &&
		status.conn_collector_mode === values.conn_collector_mode &&
		Number(status.refresh_interval_ms) === Number(values.refresh_interval_ms) &&
		Number(status.active_client_window_ms) === Number(values.active_client_window_ms) &&
		Number(status.active_client_min_bps) === Number(values.active_client_min_bps) &&
		(status.overview_window_samples === undefined ||
			Number(status.overview_window_samples) === Number(values.overview_window_samples)) &&
		(status.max_clients === undefined || Number(status.max_clients) === Number(values.max_clients)) &&
		(status.enable_bpf === undefined || String(status.enable_bpf ? '1' : '0') === String(values.enable_bpf)) &&
		(status.enable_conntrack_fallback === undefined ||
			String(status.enable_conntrack_fallback ? '1' : '0') === String(values.enable_conntrack_fallback));
}

function markApplied(viewState) {
	var plan = viewState && viewState.lastSavePlan;
	var values;
	if (!viewState || !plan)
		return false;
	values = plan.values || {};
	viewState.initialValues = cloneValues(values);
	viewState.initialIfaceOriginal = {
		ifname: cloneValues(values.ifname || []),
		interface_include: cloneValues(values.interface_include || []),
		interface_exclude: cloneValues(values.interface_exclude || []),
		observe: cloneValues(values.observe || []),
		present: {
			ifname: Boolean((values.ifname || []).length),
			interface_include: Boolean((values.interface_include || []).length),
			interface_exclude: Boolean((values.interface_exclude || []).length),
			observe: Boolean((values.observe || []).length)
		}
	};
	viewState.hasStagedSave = false;
	viewState.localDirty = false;
	return true;
}

function verifyAll(viewState) {
	var plan = viewState && viewState.lastSavePlan;
	if (!plan)
		return Promise.resolve({ ok: false, skipped: true });
	setFeedback(viewState, 'verifying', _('正在验证守护进程与接口运行态…'));
	return Promise.all([
		Promise.resolve().then(function() { return lsRpc.status(); }).then(function(status) {
			return { ok: statusMatches(status, plan.values), status: status };
			}, function(error) { return { ok: false, error: error }; }),
		Promise.resolve().then(function() {
			return ifaceCfg.verify(viewState, plan.values || (plan.interfacePlan && plan.interfacePlan.desired));
		})
	]).then(function(results) {
		var interfaceResult = results[1] || { ok: false };
		var ok = results[0].ok && (interfaceResult.ok || interfaceResult.skipped);
		if (results[0].status) {
			viewState.runtimeStatus = results[0].status;
			applyRuntimeInfo(viewState, results[0].status);
		}
		setFeedback(viewState, ok ? 'success' : 'degraded', ok
			? _('配置已应用并通过运行态验证')
			: _('配置已应用，但运行态尚未完全匹配；请查看运行诊断'));
		return { ok: ok, status: results[0], interfaces: interfaceResult };
	});
}

return baseclass.extend({
	DEFAULTS: cfgModel.DEFAULTS,
	FIELDS: cfgModel.FIELDS,
	loadValues: loadValues,
	buildDaemonSection: buildDaemonSection,
	readForm: readForm,
	validate: validateForm,
	prepareSave: prepareSave,
	saveAll: saveAllSettings,
	resetAll: resetAllSettings,
	verifyAll: verifyAll,
	markApplied: markApplied,
	setBusy: setBusy,
	setFeedback: setFeedback,
	fillForm: fillForm
});
