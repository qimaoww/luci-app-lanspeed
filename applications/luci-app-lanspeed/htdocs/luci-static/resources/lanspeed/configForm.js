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
	show_client_status: '0',
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

function markDirty(viewState) {
	if (viewState && typeof viewState.markDirty === 'function')
		viewState.markDirty();
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
		markDirty(refs.viewState);
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
	var changed = false;
	var i;

	for (i = 0; i < refs.hideIpv6RangesItems.length; i++)
		map[refs.hideIpv6RangesItems[i]] = true;

	for (i = 0; i < values.length; i++) {
		if (!map[values[i]]) {
			refs.hideIpv6RangesItems.push(values[i]);
			map[values[i]] = true;
			changed = true;
		}
	}

	refs.hideIpv6RangeInput.value = '';
	buildRangeList(refs, rangeListValue(refs));
	if (changed)
		markDirty(refs.viewState);
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
		return _('自动模式使用 BPF 统计客户端实时速率。');
	return _('自动模式优先使用 BPF；BPF 不可用时，后端会选择可用的 NSS 数据源。');
}

function applyRuntimeInfo(refs, status) {
	var sourceText = currentRateSourceText(status);
	var rateModeLabel = rateCollectorModesForStatus(status, refs.rateCollectorMode ? refs.rateCollectorMode.value : null);
	var i;

	refs.rateHint.textContent = nssRateHint(status);
	refs.currentRateSource.textContent = sourceText;
	refs.currentRateSourceWrap.title = _('当前实际生效的数据源，由后端根据设备能力与运行环境选择。');

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
	var controls;

	viewState.configSaving = busy;
	if (daemonRefs) {
		controls = [
			daemonRefs.rateCollectorMode,
			daemonRefs.connCollectorMode,
			daemonRefs.activeWindow,
			daemonRefs.activeMin,
			daemonRefs.showClientStatus,
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
		show_client_status: refs.showClientStatus.checked ? '1' : '0',
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
	refs.showClientStatus.checked = boolValue(values.show_client_status,
		DEFAULTS.show_client_status) !== '0';
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
		show_client_status: values.show_client_status,
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
		return Promise.resolve(uci.load('lanspeed'));
	} catch (err) {
		return Promise.reject(err);
	}
}

function saveAllSettings(viewState) {
	var daemonPlan;
	var ifacePlan;

	if (!viewState || !viewState.daemonRefs)
		return Promise.reject(new Error(_('配置页面尚未准备完成')));
	if (viewState.configSaving)
		return Promise.reject(new Error(_('配置保存正在进行中')));
	try {
		daemonPlan = prepareDaemonSave(viewState);
		ifacePlan = ifaceCfg.prepareSave(viewState);
	} catch (err) {
		return Promise.reject(err);
	}

	setBusy(viewState, true);

	return ifaceCfg.applySave(ifacePlan)
		.then(function() { return applyDaemonSave(daemonPlan); })
		.then(function() { return reloadUciCache(); })
		.then(function() {
			ifaceCfg.markSaved(ifacePlan);
			fillForm(daemonPlan.refs, daemonPlan.values);
			return true;
		})
		.catch(function(writeError) {
			return lsRpc.uciRevert('lanspeed').then(function() {
				return reloadUciCache().then(function() {
					throw new Error(_('配置写入失败：') + errorText(writeError));
				}, function(cacheError) {
					throw new Error(_('配置写入失败：') + errorText(writeError) +
						_('；页面缓存刷新失败：') + errorText(cacheError));
				});
			}, function(revertError) {
				throw new Error(_('配置写入失败：') + errorText(writeError) +
					_('；暂存回滚失败：') + errorText(revertError));
			});
		}).then(function(result) {
			setBusy(viewState, false);
			return result;
		}, function(error) {
			setBusy(viewState, false);
			throw error;
		});
}

function resetAllSettings(viewState) {
	if (!viewState || !viewState.daemonRefs)
		return Promise.reject(new Error(_('配置页面尚未准备完成')));
	if (viewState.configSaving)
		return Promise.reject(new Error(_('配置保存正在进行中')));

	setBusy(viewState, true);
	return lsRpc.uciRevert('lanspeed')
		.then(function() { return reloadUciCache(); })
		.then(function() { return loadValues(); })
		.then(function(values) {
			viewState.ifaceOriginal = values.interfaceConfig;
			viewState.ifcfgDirty = false;
			fillForm(viewState.daemonRefs, values);
			applyRuntimeInfo(viewState.daemonRefs, values.status || {});
			return ifaceCfg.load(viewState).then(function() { return true; });
		})
		.then(function(result) {
			setBusy(viewState, false);
			return result;
		}, function(error) {
			setBusy(viewState, false);
			throw new Error(_('重置失败：') + errorText(error));
		});
}

function buildDaemonSection(values, viewState) {
	var refs = {};
	viewState = viewState || {};
	refs.viewState = viewState;
	viewState.ifaceOriginal = values.interfaceConfig || {
		ifname: [], interface_include: [], observe: [], present: {}
	};

	refs.rateCollectorMode = selectRateCollectorMode(values.rate_collector_mode, values.status || {});
	refs.connCollectorMode = selectConnCollectorMode(values.conn_collector_mode);
	refs.activeWindow = inputNumber(values.active_client_window_ms, 1000, 0, 1000);
	refs.activeMin = inputNumber(values.active_client_min_bps, 1, 0, 1);
	refs.showClientStatus = E('input', {
		'type': 'checkbox',
		'class': 'cbi-input-checkbox'
	});
	if (boolValue(values.show_client_status, DEFAULTS.show_client_status) !== '0')
		refs.showClientStatus.checked = 'checked';
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
		markDirty(viewState);
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
	[
		refs.rateCollectorMode,
		refs.connCollectorMode,
		refs.activeWindow,
		refs.activeMin,
		refs.showClientStatus,
		refs.showIpv6,
		refs.hidePrivateIpv6
	].forEach(function(control) {
		control.addEventListener('change', function() {
			markDirty(viewState);
		});
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
					E('th', {}, _('说明'))
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
						E('td', { 'class': 'hint' }, _('仅统计当前 TCP/UDP 连接，不参与非 NSS 设备的实时测速。'))
					]),
					E('tr', {}, [
						E('td', {}, _('活跃客户端窗口')),
						E('td', { 'class': 'value' }, refs.activeWindow),
						E('td', { 'class': 'hint' }, _('最后一次活动后继续标记为“活跃”的时长，建议保持 10000 ms。'))
					]),
					E('tr', {}, [
						E('td', {}, _('活跃最小速率')),
						E('td', { 'class': 'value' }, refs.activeMin),
						E('td', { 'class': 'hint' }, _('达到此速率才算活跃；保持 1 bps 可避免漏掉低速设备。'))
					]),
					E('tr', {}, [
						E('td', {}, _('显示客户端状态')),
						E('td', { 'class': 'value' }, refs.showClientStatus),
						E('td', { 'class': 'hint' }, _('开启后在实时状态的 LAN 客户端列表中显示采集来源和告警状态；默认隐藏。'))
					]),
					E('tr', {}, [
						E('td', {}, _('显示 IPv6 地址')),
						E('td', { 'class': 'value' }, refs.showIpv6),
						E('td', { 'class': 'hint' }, _('关闭后客户端列表只显示 IPv4。'))
					]),
					E('tr', {}, [
						E('td', {}, _('隐藏私有 IPv6 地址')),
						E('td', { 'class': 'value' }, refs.hidePrivateIpv6),
						E('td', { 'class': 'hint' }, _('隐藏 fc00::/7 私有地址和 fe80::/10 链路本地地址，公网 IPv6 仍会显示。'))
					]),
					E('tr', {}, [
						E('td', {}, _('隐藏 IPv6 范围')),
						E('td', { 'class': 'value range' }, refs.rangeEditor),
						E('td', { 'class': 'hint' }, _('仅在上项开启时生效；可添加一个或多个 IPv6 网段，例如 fc00::/7、fe80::/10。'))
					])
				])
			]),
			E('div', { 'class': 'lanspeed-config-actions' }, [
				refs.resetBtn
			])
		])
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
			show_client_status: boolValue(uci.get('lanspeed', 'main', 'show_client_status'),
				DEFAULTS.show_client_status),
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

	saveAll: function(viewState) {
		return saveAllSettings(viewState);
	},

	resetAll: function(viewState) {
		return resetAllSettings(viewState);
	},

	isNssDevice: isNssDevice,
	daeRuntimeActive: daeRuntimeActive
});
