'use strict';
'require baseclass';
'require uci';
'require lanspeed.rpc as lsRpc';
'require lanspeed.ifaceConfig as ifaceCfg';

var DEFAULTS = {
	rate_collector_mode: 'auto',
	conn_collector_mode: 'auto',
	active_client_window_ms: 10000,
	active_client_min_bps: 1,
	show_ipv6: '1',
	hide_private_ipv6: '0',
	hide_ipv6_ranges: 'fc00::/7 fe80::/10'
};

var RATE_COLLECTOR_MODES = [
	[ 'auto', _('自动') ],
	[ 'bpf', 'BPF' ]
];

var CONN_COLLECTOR_MODES = [
	[ 'auto', _('自动') ],
	[ 'conntrack_netlink', 'CT-Netlink' ],
	[ 'conntrack_procfs', 'CT-Procfs' ]
];

function intValue(value, fallback, min, max) {
	var n = parseInt(value, 10);
	if (isNaN(n))
		n = fallback;
	if (n < min)
		n = min;
	if (max && n > max)
		n = max;
	return n;
}

function uciInt(option) {
	var min = 1;
	if (option === 'active_client_window_ms')
		min = 1000;

	return intValue(uci.get('lanspeed', 'main', option), DEFAULTS[option], min, 0);
}

function inputNumber(value, min, max, step) {
	var attrs = {
		'type': 'number',
		'class': 'cbi-input-text',
		'value': String(value),
		'min': String(min),
		'step': String(step || 1)
	};
	if (max)
		attrs.max = String(max);
	return E('input', attrs);
}

function rateCollectorModeValue(value) {
	if (value === 'bpf' || value === 'nss_ecm_direct' ||
	    value === 'nss_conntrack_sync')
		return value;
	return DEFAULTS.rate_collector_mode;
}

function connCollectorModeValue(value) {
	if (value === 'conntrack_netlink' || value === 'conntrack_procfs')
		return value;
	return DEFAULTS.conn_collector_mode;
}

function boolValue(value, fallback) {
	if (value === '0')
		return '0';
	if (value === '1')
		return '1';
	return fallback;
}

function stringValue(value, fallback) {
	if (typeof value === 'string')
		return value;
	return fallback;
}

function uciListValue(value) {
	if (Array.isArray(value)) return value.slice();
	if (typeof value === 'string') return value.split(/\s+/).filter(Boolean);
	return [];
}

function splitRanges(value) {
	var raw = stringValue(value, '');
	return raw.split(/[,\s]+/).filter(function(item) {
		return item;
	});
}

function rangeListValue(refs) {
	return refs.hideIpv6RangesItems.join(' ');
}

function buildRangePill(refs, value) {
	var text = E('input', {
		'type': 'text',
		'class': 'lanspeed-range-text cbi-input-text',
		'title': value,
		'value': value,
		'readonly': 'readonly'
	});
	var remove = E('button', {
		'type': 'button',
		'class': 'lanspeed-range-remove cbi-button cbi-button-remove',
		'title': _('删除')
	}, '\u00d7');
	refs.rangeRemoveButtons.push(remove);

	remove.addEventListener('click', function() {
		var items = [];
		for (var i = 0; i < refs.hideIpv6RangesItems.length; i++) {
			if (refs.hideIpv6RangesItems[i] !== value)
				items.push(refs.hideIpv6RangesItems[i]);
		}
		refs.hideIpv6RangesItems = items;
		buildRangeList(refs, rangeListValue(refs));
	});

	return E('div', { 'class': 'lanspeed-range-pill' }, [ text, remove ]);
}

function buildRangeList(refs, value) {
	var items = splitRanges(value);

	refs.hideIpv6RangesItems = items;
	refs.rangeRemoveButtons = [];
	refs.hideIpv6RangesList.innerHTML = '';
	for (var i = 0; i < items.length; i++)
		refs.hideIpv6RangesList.appendChild(buildRangePill(refs, items[i]));
}

function addRangeItem(refs) {
	var values = splitRanges(refs.hideIpv6RangeInput.value);
	var map = {};
	var i;

	for (i = 0; i < refs.hideIpv6RangesItems.length; i++)
		map[refs.hideIpv6RangesItems[i]] = true;

	for (i = 0; i < values.length; i++) {
		if (!map[values[i]]) {
			refs.hideIpv6RangesItems.push(values[i]);
			map[values[i]] = true;
		}
	}

	refs.hideIpv6RangeInput.value = '';
	buildRangeList(refs, rangeListValue(refs));
}

function legacyRateCollectorMode(value) {
	return value === 'bpf' ? 'bpf' : 'auto';
}

function legacyConnCollectorMode(value) {
	if (value === 'conntrack_netlink' || value === 'conntrack_procfs')
		return value;
	return 'auto';
}

function selectMode(value, modes, normalizer) {
	var selected = normalizer(value);
	return E('select', { 'class': 'cbi-input-select' }, modes.map(function(mode) {
		var attrs = { 'value': mode[0] };
		if (mode[0] === selected)
			attrs.selected = 'selected';
		return E('option', attrs, mode[1]);
	}));
}

function statusNssEvidence(status) {
	return status && status.evidence && status.evidence.nss ? status.evidence.nss : {};
}

function statusDaedEvidence(status) {
	var evidence = status && status.evidence || {};
	return Object.assign({}, evidence.proxy || {}, evidence.dae || {});
}

function isNssDevice(status) {
	var caps = status && status.capabilities || {};
	var nss = statusNssEvidence(status);
	var ecmActive = typeof nss.ecm_active === 'boolean'
		? nss.ecm_active : Boolean(nss.ecm_offload_active);
	var ppeActive = typeof nss.ppe_active === 'boolean'
		? nss.ppe_active : Boolean(nss.ppe_offload_active);
	var directSupported = typeof nss.direct_state_readable === 'boolean'
		? nss.direct_state_readable : Boolean(nss.direct_supported);
	var key;

	if (caps.nss === true || nss.present === true)
		return true;
	if (ecmActive || ppeActive || directSupported || nss.direct_enabled ||
	    nss.dp_active || nss.bridge_mgr || nss.ifb_active ||
	    nss.nsm_active || nss.mcs_active)
		return true;
	for (key in caps) {
		if (Object.prototype.hasOwnProperty.call(caps, key) &&
		    key.indexOf('nss') === 0 && caps[key])
			return true;
	}
	return false;
}

function daeRuntimeActive(status) {
	var dae = statusDaedEvidence(status);
	if (typeof dae.runtime_active === 'boolean')
		return dae.runtime_active;
	return !!(dae.dae_running || dae.daed_running || dae.dae_process || dae.daed_process);
}

function rateCollectorModesForStatus(status, currentValue) {
	var currentIsNss = currentValue === 'nss_ecm_direct' ||
		currentValue === 'nss_conntrack_sync';

	if (!isNssDevice(status) && !currentIsNss)
		return RATE_COLLECTOR_MODES;
	return [
		[ 'auto', _('自动') ],
		[ 'bpf', 'BPF' ],
		[ 'nss_ecm_direct', 'NSS-direct' ],
		[ 'nss_conntrack_sync', 'NSS sync' ]
	];
}

function selectRateCollectorMode(value, status) {
	return selectMode(value, rateCollectorModesForStatus(status, value), rateCollectorModeValue);
}

function selectConnCollectorMode(value) {
	return selectMode(value, CONN_COLLECTOR_MODES, connCollectorModeValue);
}

function currentRateSourceText(status) {
	var nss = statusNssEvidence(status);
	var collector = status && status.evidence && status.evidence.collector;
	var source = collector && collector.primary_source;

	if (source === 'bpf')
		return 'BPF';
	if (source === 'nss_ecm_direct')
		return 'NSS-direct';
	if (source === 'nss_conntrack_sync' || nss.counter_source === 'ecm_conntrack_sync' ||
	    nss.counter_source === 'ppe_conntrack_sync')
		return 'NSS sync';
	if (source === 'unsupported')
		return _('不可用');
	return source || _('自动');
}

function nssRateHint(status) {
	if (!isNssDevice(status))
		return _('非 NSS 实时测速只使用 BPF。');
	return _('自动：NSS 设备同样优先使用 BPF；BPF 不可用时回退 NSS sync / NSS-direct。');
}

function applyRuntimeInfo(refs, status) {
	var sourceText = currentRateSourceText(status);
	var rateModeLabel = rateCollectorModesForStatus(status, refs.rateCollectorMode ? refs.rateCollectorMode.value : null);
	var i;

	refs.rateHint.textContent = nssRateHint(status);
	refs.currentRateSource.textContent = sourceText;
	refs.currentRateSourceWrap.title = daeRuntimeActive(status)
		? _('dae/daed 运行中，BPF 使用前置 passthrough 挂载。')
		: _('daemon 当前选择；自动模式默认优先 BPF。');

	if (refs.rateCollectorMode) {
		for (i = 0; i < rateModeLabel.length; i++) {
			if (i >= refs.rateCollectorMode.options.length) {
				refs.rateCollectorMode.appendChild(E('option', {
					'value': rateModeLabel[i][0]
				}, rateModeLabel[i][1]));
			}
			refs.rateCollectorMode.options[i].text = rateModeLabel[i][1];
		}
		refs.rateCollectorMode.value = rateCollectorModeValue(refs.rateCollectorMode.value);
	}

}

function setBusy(viewState, busy) {
	var daemonRefs = viewState.daemonRefs;
	var saveRefs = viewState.saveRefs;
	var controls;

	viewState.configSaving = busy;
	if (saveRefs)
		saveRefs.saveBtn.disabled = busy;
	if (daemonRefs) {
		controls = [
			daemonRefs.rateCollectorMode,
			daemonRefs.connCollectorMode,
			daemonRefs.activeWindow,
			daemonRefs.activeMin,
			daemonRefs.showIpv6,
			daemonRefs.hidePrivateIpv6,
			daemonRefs.hideIpv6RangeInput,
			daemonRefs.addRangeBtn,
			daemonRefs.resetBtn
		].concat(daemonRefs.rangeRemoveButtons || []);
		controls.forEach(function(control) {
			if (control)
				control.disabled = busy;
		});
	}
	ifaceCfg.setBusy(viewState, busy);
}

function readForm(refs) {
	return {
		rate_collector_mode: rateCollectorModeValue(refs.rateCollectorMode.value),
		conn_collector_mode: connCollectorModeValue(refs.connCollectorMode.value),
		active_client_window_ms: intValue(refs.activeWindow.value,
			DEFAULTS.active_client_window_ms, 1000, 0),
		active_client_min_bps: intValue(refs.activeMin.value,
			DEFAULTS.active_client_min_bps, 1, 0),
		show_ipv6: refs.showIpv6.checked ? '1' : '0',
		hide_private_ipv6: refs.hidePrivateIpv6.checked ? '1' : '0',
		hide_ipv6_ranges: rangeListValue(refs)
	};
}

function fillForm(refs, values) {
	refs.rateCollectorMode.value = rateCollectorModeValue(values.rate_collector_mode);
	refs.connCollectorMode.value = connCollectorModeValue(values.conn_collector_mode);
	refs.activeWindow.value = String(values.active_client_window_ms);
	refs.activeMin.value = String(values.active_client_min_bps);
	refs.showIpv6.checked = boolValue(values.show_ipv6, DEFAULTS.show_ipv6) !== '0';
	refs.hidePrivateIpv6.checked = boolValue(values.hide_private_ipv6, DEFAULTS.hide_private_ipv6) !== '0';
	buildRangeList(refs, stringValue(values.hide_ipv6_ranges, DEFAULTS.hide_ipv6_ranges));
	refs.hideIpv6RangeInput.value = '';
}


function prepareDaemonSave(viewState) {
	var refs = viewState.daemonRefs;
	var values = readForm(refs);
	var uciValues = {
		rate_collector_mode: values.rate_collector_mode,
		conn_collector_mode: values.conn_collector_mode,
		collector_mode: values.rate_collector_mode,
		active_client_window_ms: String(values.active_client_window_ms),
		active_client_min_bps: String(values.active_client_min_bps),
		show_ipv6: values.show_ipv6,
		hide_private_ipv6: values.hide_private_ipv6,
		hide_ipv6_ranges: values.hide_ipv6_ranges
	};
	return { refs: refs, values: values, uciValues: uciValues };
}

function applyDaemonSave(plan) {
	return lsRpc.uciSet('lanspeed', 'main', plan.uciValues);
}

function errorText(err) {
	return err && err.message || String(err);
}

function reloadUciCache() {
	try {
		uci.unload('lanspeed');
	} catch (err) {
		return Promise.reject(err);
	}
	return uci.load('lanspeed');
}

function saveAllSettings(viewState) {
	var saveRefs = viewState.saveRefs;
	var daemonPlan;
	var ifacePlan;
	var committed = false;

	if (viewState.configSaving)
		return Promise.resolve(false);
	try {
		daemonPlan = prepareDaemonSave(viewState);
		ifacePlan = ifaceCfg.prepareSave(viewState);
	} catch (err) {
		saveRefs.status.textContent = errorText(err);
		return Promise.resolve(false);
	}

	setBusy(viewState, true);
	saveRefs.status.textContent = _('保存中…');

	return ifaceCfg.applySave(ifacePlan)
		.then(function() { return applyDaemonSave(daemonPlan); })
		.then(function() { return lsRpc.uciCommit('lanspeed'); })
		.then(function() {
			committed = true;
			ifaceCfg.markSaved(ifacePlan);
			var cacheError = null;
			return reloadUciCache().catch(function(err) {
				cacheError = err;
			}).then(function() {
				saveRefs.status.textContent = _('重载 daemon…');
				return lsRpc.reload().then(function() {
					return Promise.all([
						ifaceCfg.load(viewState),
						lsRpc.status().catch(function() { return null; })
					]);
				}, function(err) {
					saveRefs.status.textContent = _('配置已保存，但 daemon 重载失败: ') + errorText(err);
					return null;
				});
			}).then(function(results) {
				if (!results)
					return false;
				fillForm(daemonPlan.refs, daemonPlan.values);
				if (results[1])
					applyRuntimeInfo(daemonPlan.refs, results[1]);
				saveRefs.status.textContent = cacheError
					? _('已应用，但 UCI 缓存刷新失败: ') + errorText(cacheError)
					: _('已应用');
				window.setTimeout(function() {
					if (saveRefs.status.textContent === _('已应用'))
						saveRefs.status.textContent = '';
				}, 3000);
				return true;
			});
		}, function(writeError) {
			return lsRpc.uciRevert('lanspeed').then(function() {
				saveRefs.status.textContent = _('配置写入失败: ') + errorText(writeError);
				return false;
			}, function(revertError) {
				saveRefs.status.textContent = _('配置写入失败: ') + errorText(writeError) +
					_('；暂存回滚失败: ') + errorText(revertError);
				return false;
			});
		}).then(function(result) {
			setBusy(viewState, false);
			return result;
		}, function(error) {
			setBusy(viewState, false);
			saveRefs.status.textContent = (committed
				? _('配置已保存，但后续处理失败: ')
				: _('保存失败: ')) + errorText(error);
			return false;
		});
}

function buildDaemonSection(values, viewState) {
	var refs = {};
	viewState = viewState || {};
	viewState.ifaceOriginal = values.interfaceConfig || {
		ifname: [], interface_include: [], observe: [], present: {}
	};

	refs.rateCollectorMode = selectRateCollectorMode(values.rate_collector_mode, values.status || {});
	refs.connCollectorMode = selectConnCollectorMode(values.conn_collector_mode);
	refs.activeWindow = inputNumber(values.active_client_window_ms, 1000, 0, 1000);
	refs.activeMin = inputNumber(values.active_client_min_bps, 1, 0, 1);
	refs.showIpv6 = E('input', {
		'type': 'checkbox',
		'class': 'cbi-input-checkbox'
	});
	if (boolValue(values.show_ipv6, DEFAULTS.show_ipv6) !== '0')
		refs.showIpv6.checked = 'checked';
	refs.hidePrivateIpv6 = E('input', {
		'type': 'checkbox',
		'class': 'cbi-input-checkbox'
	});
	if (boolValue(values.hide_private_ipv6, DEFAULTS.hide_private_ipv6) !== '0')
		refs.hidePrivateIpv6.checked = 'checked';
	refs.hideIpv6RangesItems = splitRanges(stringValue(values.hide_ipv6_ranges, DEFAULTS.hide_ipv6_ranges));
	refs.hideIpv6RangesList = E('div', { 'class': 'lanspeed-range-list' });
	refs.hideIpv6RangeInput = E('input', {
		'type': 'text',
		'class': 'cbi-input-text',
		'placeholder': '2001:db8::/32'
	});
	refs.addRangeBtn = E('button', {
		'type': 'button',
		'class': 'cbi-button',
		'title': _('添加')
	}, _('添加'));
	refs.rangeEditor = E('div', { 'class': 'lanspeed-range-stack' }, [
		refs.hideIpv6RangesList,
		E('div', { 'class': 'lanspeed-range-add' }, [
			refs.hideIpv6RangeInput,
			refs.addRangeBtn
		])
	]);
	buildRangeList(refs, stringValue(values.hide_ipv6_ranges, DEFAULTS.hide_ipv6_ranges));
	refs.rateHint = E('td', { 'class': 'hint' }, '');
	refs.currentRateSource = E('span', { 'class': 'key' }, '-');
	refs.currentRateSourceWrap = E('span', { 'class': 'lanspeed-current-rate-source' }, [
		E('span', { 'class': 'label' }, _('当前：')),
		refs.currentRateSource
	]);
	refs.resetBtn = E('button', {
		'class': 'cbi-button',
		'type': 'button'
	}, _('恢复默认值'));

	refs.resetBtn.addEventListener('click', function() {
		fillForm(refs, DEFAULTS);
	});
	refs.addRangeBtn.addEventListener('click', function() {
		addRangeItem(refs);
	});
	refs.hideIpv6RangeInput.addEventListener('keydown', function(ev) {
		if (ev.key === 'Enter') {
			ev.preventDefault();
			addRangeItem(refs);
		}
	});

	viewState.daemonRefs = refs;
	applyRuntimeInfo(refs, values.status || {});

	return E('div', { 'class': 'cbi-section' }, [
		E('div', { 'class': 'lanspeed-header' }, [
			E('h3', {}, _('运行参数'))
		]),
		E('div', { 'class': 'lanspeed-config-body' }, [
			E('table', { 'class': 'lanspeed-config-table' }, [
				E('thead', {}, E('tr', {}, [
					E('th', {}, _('项目')),
					E('th', { 'class': 'value' }, _('值')),
					E('th', {}, _('范围'))
				])),
				E('tbody', {}, [
					E('tr', {}, [
						E('td', {}, _('速率采集')),
						E('td', { 'class': 'value rate' }, E('div', { 'class': 'lanspeed-rate-control' }, [
							refs.rateCollectorMode,
							refs.currentRateSourceWrap
						])),
						refs.rateHint
					]),
					E('tr', {}, [
						E('td', {}, _('连接数采集')),
						E('td', { 'class': 'value' }, refs.connCollectorMode),
						E('td', { 'class': 'hint' }, _('CT 只用于连接数和诊断。'))
					]),
					E('tr', {}, [
						E('td', {}, _('活跃客户端窗口')),
						E('td', { 'class': 'value' }, refs.activeWindow),
						E('td', { 'class': 'hint' }, _('1000 ms 以上'))
					]),
					E('tr', {}, [
						E('td', {}, _('活跃最小速率')),
						E('td', { 'class': 'value' }, refs.activeMin),
						E('td', { 'class': 'hint' }, _('1 bps 以上'))
					]),
					E('tr', {}, [
						E('td', {}, _('显示 IPv6 地址')),
						E('td', { 'class': 'value' }, refs.showIpv6),
						E('td', { 'class': 'hint' }, _('关闭后客户端列表只显示 IPv4。'))
					]),
					E('tr', {}, [
						E('td', {}, _('隐藏私有 IPv6 地址')),
						E('td', { 'class': 'value' }, refs.hidePrivateIpv6),
						E('td', { 'class': 'hint' }, _('开启后客户端列表隐藏 fc00::/7 私有 IPv6 地址和 fe80::/10 链路本地地址；公网 IPv6 仍显示。'))
					]),
					E('tr', {}, [
						E('td', {}, _('隐藏 IPv6 范围')),
						E('td', { 'class': 'value range' }, refs.rangeEditor),
						E('td', { 'class': 'hint' }, _('仅在隐藏私有 IPv6 地址开启时生效；用空格或逗号分隔，例如 fc00::/7 fe80::/10。'))
					])
				])
			]),
			E('div', { 'class': 'lanspeed-config-actions' }, [
				refs.resetBtn
			])
		])
	]);
}

function buildSaveSection(viewState) {
	var refs = {};

	refs.saveBtn = E('button', {
		'class': 'cbi-button cbi-button-apply',
		'type': 'button'
	}, _('保存并重载'));
	refs.status = E('span', { 'class': 'status' }, '');
	refs.saveBtn.addEventListener('click', function() {
		saveAllSettings(viewState);
	});
	viewState.saveRefs = refs;

	return E('div', { 'class': 'lanspeed-page-actions' }, [
		refs.status,
		E('span', { 'class': 'spacer' }),
		refs.saveBtn
	]);
}

function loadValues() {
	return uci.load('lanspeed').then(function() {
		var legacy = uci.get('lanspeed', 'main', 'collector_mode');
		var rateMode = uci.get('lanspeed', 'main', 'rate_collector_mode');
		var connMode = uci.get('lanspeed', 'main', 'conn_collector_mode');
		var rawIfname = uci.get('lanspeed', 'main', 'ifname');
		var rawInterfaceInclude = uci.get('lanspeed', 'main', 'interface_include');
		var rawObserve = uci.get('lanspeed', 'main', 'observe');

		return {
			rate_collector_mode: rateCollectorModeValue(rateMode || legacyRateCollectorMode(legacy)),
			conn_collector_mode: connCollectorModeValue(connMode || legacyConnCollectorMode(legacy)),
			active_client_window_ms: uciInt('active_client_window_ms'),
			active_client_min_bps: uciInt('active_client_min_bps'),
			show_ipv6: boolValue(uci.get('lanspeed', 'main', 'show_ipv6'), DEFAULTS.show_ipv6),
			hide_private_ipv6: boolValue(uci.get('lanspeed', 'main', 'hide_private_ipv6'), DEFAULTS.hide_private_ipv6),
			hide_ipv6_ranges: stringValue(uci.get('lanspeed', 'main', 'hide_ipv6_ranges'), DEFAULTS.hide_ipv6_ranges),
			interfaceConfig: {
				ifname: uciListValue(rawIfname),
				interface_include: uciListValue(rawInterfaceInclude),
				observe: uciListValue(rawObserve),
				present: {
					ifname: rawIfname !== null && rawIfname !== undefined,
					interface_include: rawInterfaceInclude !== null && rawInterfaceInclude !== undefined,
					observe: rawObserve !== null && rawObserve !== undefined
				}
			},
			status: {}
		};
	}).then(function(values) {
		return lsRpc.status().then(function(status) {
			values.status = status || {};
			return values;
		}).catch(function() {
			return values;
		});
	});
}

return baseclass.extend({
	DEFAULTS: DEFAULTS,

	loadValues: function() {
		return loadValues();
	},

	buildDaemonSection: function(values, viewState) {
		return buildDaemonSection(values, viewState);
	},

	buildSaveSection: function(viewState) {
		return buildSaveSection(viewState);
	},

	saveAll: function(viewState) {
		return saveAllSettings(viewState);
	},

	isNssDevice: isNssDevice,
	daeRuntimeActive: daeRuntimeActive
});
