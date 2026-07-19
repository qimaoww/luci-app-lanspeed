'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';
'require lanspeed.configModel as cfgModel';

var AUTO_IGNORED_INTERFACE_PREFIXES = [
	'dae', 'miireg', 'tun', 'erspan', 'gretap', 'gre', 'ip6gre', 'ip6tnl', 'sit',
	'bonding_masters'
];

function text(value) {
	return value === undefined || value === null ? '' : String(value);
}

function markDirty(viewState) {
	if (viewState && typeof viewState.markDirty === 'function')
		viewState.markDirty();
}

function isAutoIgnored(name) {
	name = text(name);
	return AUTO_IGNORED_INTERFACE_PREFIXES.some(function(prefix) {
		return name.indexOf(prefix) === 0;
	});
}

function visibleDevices(data) {
	return fmt.asArray(data && data.devices).filter(function(device) {
		return device && text(device.name) && !isAutoIgnored(device.name);
	});
}

function cloneList(value) {
	return Array.isArray(value) ? value.slice() : cfgModel.parseInterfaceList(value).valid;
}

function unique(values) {
	var result = [];
	var seen = {};
	(Array.isArray(values) ? values : []).forEach(function(value) {
		value = text(value);
		if (value && !seen[value]) {
			seen[value] = true;
			result.push(value);
		}
	});
	return result;
}

function sameNames(left, right) {
	left = unique(left).sort();
	right = unique(right).sort();
	if (left.length !== right.length)
		return false;
	return left.every(function(value, index) { return value === right[index]; });
}

function originalConfig(viewState) {
	var original = viewState.ifaceOriginal || {};
	return {
		ifname: cloneList(original.ifname),
		interface_include: cloneList(original.interface_include),
		interface_exclude: cloneList(original.interface_exclude),
		observe: cloneList(original.observe),
		present: original.present || {}
	};
}

function normalizeSysdevices(data) {
	var warnings = [];
	var devices;
	var lists = {};
	var listNames = [
		'current_ifnames', 'current_observed', 'current_excluded',
		'configured_ifnames', 'configured_observed', 'configured_excluded', 'orphaned'
	];
	var rawLimits = data && data.limits && typeof data.limits === 'object' ? data.limits : {};
	var maxConfigured = Number(rawLimits.max_configured);
	var maxNameLength = Number(rawLimits.max_name_length);
	if (!data || typeof data !== 'object' || Array.isArray(data)) {
		var invalid = new Error(_('接口扫描返回无效数据'));
		invalid.code = 'INVALID_SYSDEVICES_RESPONSE';
		throw invalid;
	}
	if (!Array.isArray(data.devices)) {
		var malformed = new Error(_('接口扫描缺少设备列表'));
		malformed.code = 'INVALID_SYSDEVICES_RESPONSE';
		throw malformed;
	}
	devices = data.devices.filter(function(device, index) {
		if (device && text(device.name))
			return true;
		warnings.push({ field: 'devices', index: index, code: 'invalid_device' });
		return false;
	}).map(function(device) {
		var copy = Object.assign({}, device);
		[ 'selected', 'observed', 'recommended_lan', 'collect_allowed',
			'is_bridge', 'is_bridge_port', 'is_nss_ifb' ].forEach(function(name) {
			if (typeof copy[name] !== 'boolean') {
				warnings.push({ field: name, device: text(copy.name), code: 'defaulted' });
				copy[name] = false;
			}
		});
		if (typeof copy.collect_reason !== 'string' || !copy.collect_reason) {
			warnings.push({ field: 'collect_reason', device: text(copy.name), code: 'defaulted' });
			copy.collect_reason = 'invalid_contract';
		}
		return copy;
	});
	if (!Object.prototype.hasOwnProperty.call(data, 'contract_version'))
		warnings.push({ field: 'contract_version', code: 'missing_contract_version' });
	else if (data.contract_version !== 1)
		warnings.push({ field: 'contract_version', code: 'unsupported_version', value: data.contract_version });
	listNames.forEach(function(name) {
		if (!Array.isArray(data[name])) {
			warnings.push({ field: name, code: 'defaulted' });
			lists[name] = [];
		} else {
			lists[name] = data[name].filter(function(value) {
				return typeof value === 'string' && value.length > 0;
			});
			if (lists[name].length !== data[name].length)
				warnings.push({ field: name, code: 'invalid_items' });
		}
	});
	if (!isFinite(maxConfigured) || maxConfigured < 1 || maxConfigured > cfgModel.MAX_INTERFACE_NAMES) {
		warnings.push({ field: 'limits.max_configured', code: 'defaulted' });
		maxConfigured = cfgModel.MAX_INTERFACE_NAMES;
	}
	if (!isFinite(maxNameLength) || maxNameLength < 1 || maxNameLength > 255) {
		warnings.push({ field: 'limits.max_name_length', code: 'defaulted' });
		maxNameLength = 31;
	}
	return {
		contract_version: data.contract_version === undefined ? 0 : data.contract_version,
		devices: devices,
		current_ifnames: lists.current_ifnames,
		current_observed: lists.current_observed,
		current_excluded: lists.current_excluded,
		configured_ifnames: lists.configured_ifnames,
		configured_observed: lists.configured_observed,
		configured_excluded: lists.configured_excluded,
		orphaned: lists.orphaned,
		limits: { max_configured: maxConfigured, max_name_length: maxNameLength },
		warnings: warnings
	};
}

function collectAllowed(device) {
	if (!device || device.is_nss_ifb)
		return false;
	if (typeof device.collect_allowed === 'boolean')
		return device.collect_allowed;
	if (device.is_bridge_port)
		return false;
	return device.recommended_lan === true && !/^(wan|ppp|wg|tap|utun)/.test(text(device.name));
}

function collectReason(device) {
	if (!device)
		return _('设备不存在');
	if (device.is_nss_ifb)
		return _('nssifb 只能观察');
	var reasons = {
		eligible_bridge: _('可在 LAN 网桥采集客户端速率'),
		eligible_bridge_port: _('后端允许在此桥成员采集'),
		eligible_ethernet: _('可在此以太网接口采集'),
		nssifb_observe_only: _('nssifb 只能观察'),
		non_ethernet_observe_only: _('非以太网接口只能观察'),
		name_policy_observe_only: _('接口名称策略仅允许观察')
	};
	if (device.collect_reason && reasons[device.collect_reason])
		return reasons[device.collect_reason];
	if (device.is_bridge_port)
		return _('桥成员未获后端采集授权');
	if (!device.recommended_lan)
		return _('后端未确认这是可采集的 LAN 接口');
	if (/^(wan|ppp|wg|tap|utun)/.test(text(device.name)))
		return _('WAN、VPN 或隧道接口只能观察');
	return _('此接口当前不支持客户端采集');
}

function deviceByName(viewState) {
	var map = {};
	visibleDevices(viewState.sysdevices || {}).forEach(function(device) {
		map[device.name] = device;
	});
	return map;
}

function stateForDevice(viewState, device) {
	var original = originalConfig(viewState);
	var collected = unique(original.ifname.concat(original.interface_include));
	if (collected.indexOf(device.name) !== -1)
		return 'collect';
	if (original.observe.indexOf(device.name) !== -1)
		return 'observe';
	return 'off';
}

function setInterfaceStatus(viewState, state, message) {
	var refs = viewState.refs || {};
	var status = refs.ifcfgStatus;
	viewState.interfaceStatus = state;
	if (status) {
		status.setAttribute('data-state', state);
		status.textContent = message || '';
	}
	if (refs.ifcfgRoot)
		refs.ifcfgRoot.setAttribute('data-state', state);
}

function updateScanDisabled(viewState) {
	var refs = viewState.refs || {};
	var busy = Boolean(viewState.configSaving || viewState.ifcfgLoading);
	var disabled = Boolean(busy || viewState.ifcfgDirty);
	if (refs.ifcfgReloadBtn)
		refs.ifcfgReloadBtn.disabled = disabled;
	(viewState.ifcfgButtons || []).forEach(function(button) {
		button.disabled = Boolean(busy || button.ifcfgAlwaysDisabled);
	});
	if (refs.ifcfgOrphans && refs.ifcfgOrphans.querySelectorAll)
		Array.prototype.forEach.call(refs.ifcfgOrphans.querySelectorAll('button'), function(button) {
			button.disabled = busy;
		});
}

function selectedCounts(viewState) {
	var state = viewState.ifcfgState || {};
	var collect = 0;
	var observe = 0;
	Object.keys(state).forEach(function(name) {
		if (state[name] === 'collect') collect++;
		if (state[name] === 'observe') observe++;
	});
	return { collect: collect, observe: observe };
}

function markSelection(viewState, name, mode) {
	var device = deviceByName(viewState)[name];
	var counts;
	if (!device || viewState.configSaving || viewState.ifcfgLoading)
		return false;
	if (mode === 'collect' && !collectAllowed(device)) {
		viewState.ifcfgErrors = { interfaces: collectReason(device) };
		setInterfaceStatus(viewState, 'degraded', collectReason(device));
		return false;
	}
	counts = selectedCounts(viewState);
	if (mode === 'collect' && viewState.ifcfgState[name] !== 'collect' &&
		counts.collect >= ((viewState.ifcfgLimits || {}).max_configured || cfgModel.MAX_INTERFACE_NAMES)) {
		viewState.ifcfgErrors = { interfaces: _('最多只能采集 %d 个接口').format(
			(viewState.ifcfgLimits || {}).max_configured || cfgModel.MAX_INTERFACE_NAMES) };
		setInterfaceStatus(viewState, 'degraded', viewState.ifcfgErrors.interfaces);
		return false;
	}
	viewState.ifcfgState[name] = mode;
	viewState.ifcfgDirty = true;
	viewState.ifcfgErrors = {};
	markDirty(viewState);
	updateScanDisabled(viewState);
	renderIfaceConfig(viewState);
	return true;
}

function orphanEntries(viewState) {
	var original = originalConfig(viewState);
	var visible = {};
	visibleDevices(viewState.sysdevices || {}).forEach(function(device) { visible[device.name] = true; });
	var seen = {};
	var entries = [];
	/* interface_exclude is a legacy compatibility option, not an assignable interface mode. */
	[ 'ifname', 'interface_include', 'observe' ].forEach(function(option) {
		original[option].forEach(function(name) {
			var key = option + ':' + name;
			if (!visible[name] && !seen[key]) {
				seen[key] = true;
				entries.push({ option: option, name: name });
			}
		});
	});
	return entries;
}

function optionLabel(option) {
	return ({
		ifname: _('旧版采集接口'),
		interface_include: _('采集接口'),
		interface_exclude: _('兼容排除'),
		observe: _('观察接口')
	})[option] || option;
}

function removeOrphan(viewState, option, name) {
	if (viewState.configSaving || viewState.ifcfgLoading)
		return false;
	viewState.orphanRemovals = viewState.orphanRemovals || {};
	viewState.orphanRemovals[option + ':' + name] = true;
	viewState.ifcfgDirty = true;
	markDirty(viewState);
	renderIfaceConfig(viewState);
	return true;
}

function buildModeButton(viewState, wrap, name, mode, label, disabled, title) {
	var button = E('button', {
		'type': 'button',
		'class': viewState.ifcfgState[name] === mode ? 'active' : '',
		'role': 'radio',
		'aria-checked': viewState.ifcfgState[name] === mode ? 'true' : 'false',
		'aria-label': name + ' · ' + label,
		'title': title || label,
		'data-mode': mode
	}, label);
	button.disabled = Boolean(disabled || viewState.configSaving || viewState.ifcfgLoading);
	button.ifcfgAlwaysDisabled = Boolean(disabled);
	button.addEventListener('click', function(event) {
		if (event && event.preventDefault) event.preventDefault();
		if (!button.disabled)
			markSelection(viewState, name, mode);
	});
	wrap.appendChild(button);
	(viewState.ifcfgButtons || (viewState.ifcfgButtons = [])).push(button);
}

function buildModeControl(viewState, device) {
	var wrap = E('div', {
		'class': 'lanspeed-ifcfg-seg',
		'role': 'radiogroup',
		'aria-label': text(device.name) + ' · ' + _('接口模式'),
		'data-name': text(device.name)
	});
	var allowed = collectAllowed(device);
	buildModeButton(viewState, wrap, device.name, 'off', _('关闭'), false,
		_('不采集，也不在接口吞吐中显示'));
	buildModeButton(viewState, wrap, device.name, 'observe', _('观察'), false,
		_('只显示接口总吞吐，不统计客户端'));
	buildModeButton(viewState, wrap, device.name, 'collect', _('采集'), !allowed,
		allowed ? _('按客户端统计 LAN 实时速率') : collectReason(device));
	return wrap;
}

function renderOrphans(viewState) {
	var refs = viewState.refs;
	var entries = orphanEntries(viewState).filter(function(entry) {
		return !(viewState.orphanRemovals || {})[entry.option + ':' + entry.name];
	});
	if (!refs.ifcfgOrphans)
		return;
	refs.ifcfgOrphans.innerHTML = '';
	if (!entries.length) {
		refs.ifcfgOrphans.hidden = true;
		return;
	}
	refs.ifcfgOrphans.hidden = false;
	entries.forEach(function(entry) {
		var remove = E('button', {
			'type': 'button',
			'class': 'cbi-button cbi-button-remove',
			'aria-label': _('删除孤立接口') + ' ' + entry.name,
			'title': _('从配置中移除')
		}, _('移除'));
		remove.disabled = Boolean(viewState.configSaving);
		remove.addEventListener('click', function() { removeOrphan(viewState, entry.option, entry.name); });
		refs.ifcfgOrphans.appendChild(E('div', { 'class': 'lanspeed-interface-orphan', 'data-option': entry.option }, [
			E('code', {}, entry.name),
			E('span', { 'class': 'lanspeed-interface-orphan-kind' }, optionLabel(entry.option)),
			remove
		]));
	});
}

function renderIfaceConfig(viewState) {
	var refs = viewState.refs || {};
	var data = viewState.sysdevices || { devices: [] };
	var devices = visibleDevices(data).slice().sort(function(left, right) {
		var l = collectAllowed(left) ? 0 : 1;
		var r = collectAllowed(right) ? 0 : 1;
		return l - r || fmt.compareText(left.name, right.name);
	});
	var state = viewState.ifcfgState;
	viewState.ifcfgButtons = [];
	if (!state) {
		state = {};
		devices.forEach(function(device) { state[device.name] = stateForDevice(viewState, device); });
		viewState.ifcfgState = state;
	}
	if (refs.ifcfgBody) {
		fmt.replaceChildren(refs.ifcfgBody, devices.map(function(device) {
			var tags = [];
			if (device.role) tags.push(text(device.role));
			if (device.is_nss_ifb) tags.push(_('NSS 镜像'));
			if (device.is_bridge) tags.push(_('网桥'));
			if (device.is_bridge_port) tags.push(_('桥成员'));
			if (!collectAllowed(device)) tags.push(_('仅观察'));
			if (device.speed_mbps) tags.push(text(device.speed_mbps) + 'M');
			return E('tr', { 'data-interface': device.name }, [
				E('td', { 'class': 'mono' }, device.name),
				E('td', {}, tags.length ? E('span', { 'class': 'devtags' }, tags.map(function(tag) {
					return E('span', { 'class': 'devtag' }, tag);
				})) : E('span', { 'class': 'muted' }, '-')),
				E('td', { 'class': 'action' }, buildModeControl(viewState, device))
			]);
		}));
	}
	if (refs.ifcfgSummary) {
		var counts = selectedCounts(viewState);
		refs.ifcfgSummary.textContent = _('采集 %d · 观察 %d · 候选 %d').format(
			counts.collect, counts.observe, devices.length);
	}
	if (refs.ifcfgHint) {
		refs.ifcfgHint.setAttribute('data-state', devices.length ? 'ready' : 'empty');
		refs.ifcfgHint.textContent = devices.length
			? _('“采集”用于 LAN 客户端测速；“观察”只显示接口总吞吐。不可采集接口会显示原因。')
			: _('没有发现可配置的网络接口，可重新扫描。');
	}
	if (refs.ifcfgLimit) {
		var count = selectedCounts(viewState).collect;
		var limit = (viewState.ifcfgLimits || {}).max_configured || cfgModel.MAX_INTERFACE_NAMES;
		refs.ifcfgLimit.textContent = _('采集上限 %d/%d').format(count, limit);
		refs.ifcfgLimit.setAttribute('data-state', count >= limit ? 'limit' : 'ready');
	}
	renderOrphans(viewState);
	viewState.ifcfgLoaded = true;
	updateScanDisabled(viewState);
}

function loadIfaceConfig(viewState) {
	var refs = viewState.refs || {};
	var token;
	if (!refs.ifcfgGrid && !refs.ifcfgBody)
		return Promise.resolve(false);
	if (viewState.ifcfgDirty) {
		setInterfaceStatus(viewState, 'degraded', _('存在未保存的接口修改，请先保存后再扫描'));
		return Promise.resolve(false);
	}
	if (viewState.ifcfgLoading && viewState.ifcfgPending)
		return viewState.ifcfgPending;
	token = (viewState.ifcfgRequestToken || 0) + 1;
	viewState.ifcfgRequestToken = token;
	viewState.ifcfgLoading = true;
	setInterfaceStatus(viewState, 'loading', _('正在扫描接口…'));
	updateScanDisabled(viewState);
	viewState.ifcfgPending = Promise.resolve().then(function() {
		return lsRpc.sysdevices();
	}).then(function(data) {
		if (token !== viewState.ifcfgRequestToken)
			return false;
		var normalized = normalizeSysdevices(data);
		viewState.sysdevices = normalized;
		viewState.ifcfgLimits = normalized.limits;
		viewState.ifcfgWarnings = normalized.warnings;
		viewState.ifcfgState = {};
			normalized.devices.forEach(function(device) {
				viewState.ifcfgState[device.name] = stateForDevice(viewState, device);
			});
		viewState.ifcfgDirty = false;
		viewState.ifcfgLoaded = true;
		renderIfaceConfig(viewState);
		setInterfaceStatus(viewState, normalized.devices.length ?
			(normalized.warnings.length ? 'degraded' : 'ready') : 'empty',
			normalized.warnings.length ? _('接口数据部分缺失，已使用安全默认值') : '');
		return true;
	}).catch(function(error) {
		if (token !== viewState.ifcfgRequestToken)
			return false;
		viewState.ifcfgError = error;
		if (viewState.sysdevices && viewState.ifcfgLoaded) {
			setInterfaceStatus(viewState, 'degraded', _('接口扫描失败，正在显示上次成功结果：') + text(error && error.message || error));
		} else {
			viewState.ifcfgLoaded = false;
			setInterfaceStatus(viewState, 'hard-error', _('接口扫描失败：') + text(error && error.message || error));
		}
		return false;
	}).then(function(result) {
		if (token === viewState.ifcfgRequestToken) {
			viewState.ifcfgLoading = false;
			viewState.ifcfgPending = null;
			updateScanDisabled(viewState);
		}
		return result;
	}, function(error) {
		if (token === viewState.ifcfgRequestToken) {
			viewState.ifcfgLoading = false;
			viewState.ifcfgPending = null;
			updateScanDisabled(viewState);
		}
		throw error;
	});
	return viewState.ifcfgPending;
}

function collectSelections(viewState) {
	var attach = [];
	var observe = [];
	var state = viewState.ifcfgState || {};
	Object.keys(state).forEach(function(name) {
		if (state[name] === 'collect') attach.push(name);
		else if (state[name] === 'observe') observe.push(name);
	});
	return { attach: unique(attach), observe: unique(observe) };
}

function prepareIfaceSave(viewState) {
	var original;
	var selection;
	var desired;
	var visible = {};
	var removals = viewState.orphanRemovals || {};
	var option;
	var sourceBoth;
	var changed = false;
	var errors = {};
	if (!viewState.ifcfgLoaded || !viewState.sysdevices || !viewState.ifcfgState)
		return { changed: false, viewState: viewState, errors: {} };
	if (!viewState.ifcfgDirty)
		return { changed: false, viewState: viewState, errors: {} };
	original = originalConfig(viewState);
	selection = collectSelections(viewState);
	var maxConfigured = (viewState.ifcfgLimits || {}).max_configured || cfgModel.MAX_INTERFACE_NAMES;
	if (selection.attach.length > maxConfigured)
		errors.interfaces = _('采集接口超过上限 %d').format(maxConfigured);
	selection.attach.forEach(function(name) {
		var device = deviceByName(viewState)[name];
		if (device && !collectAllowed(device) && !errors.interfaces)
			errors.interfaces = collectReason(device);
	});
	visibleDevices(viewState.sysdevices).forEach(function(device) { visible[device.name] = true; });
	sourceBoth = (original.ifname.length || original.present.ifname) &&
		(original.interface_include.length || original.present.interface_include);
	desired = {
		ifname: [], interface_include: [], interface_exclude: [], observe: []
	};
	[ 'ifname', 'interface_include', 'interface_exclude', 'observe' ].forEach(function(name) {
		original[name].forEach(function(value) {
			if (!removals[name + ':' + value] && (!visible[value] || name === 'interface_exclude'))
				desired[name].push(value);
		});
	});
	if (sourceBoth) {
		desired.ifname = desired.ifname.concat(selection.attach);
		desired.interface_include = desired.interface_include.concat(selection.attach);
	} else if (original.ifname.length || original.present.ifname) {
		desired.ifname = desired.ifname.concat(selection.attach);
	} else {
		desired.interface_include = desired.interface_include.concat(selection.attach);
	}
	desired.observe = desired.observe.concat(selection.observe);
	Object.keys(desired).forEach(function(name) {
		desired[name] = unique(desired[name]);
		if (!sameNames(desired[name], original[name])) changed = true;
	});
	if (errors.interfaces)
		return { changed: false, viewState: viewState, desired: desired, errors: errors };
	return { changed: changed, viewState: viewState, desired: desired, errors: errors };
}

function markSaved(plan) {
	if (!plan || !plan.viewState)
		return;
	var viewState = plan.viewState;
	if (plan.desired) {
		viewState.ifaceOriginal = {
			ifname: plan.desired.ifname.slice(),
			interface_include: plan.desired.interface_include.slice(),
			interface_exclude: plan.desired.interface_exclude.slice(),
			observe: plan.desired.observe.slice(),
			present: {
				ifname: plan.desired.ifname.length > 0,
				interface_include: plan.desired.interface_include.length > 0,
				interface_exclude: plan.desired.interface_exclude.length > 0,
				observe: plan.desired.observe.length > 0
			}
		};
	}
	viewState.ifcfgDirty = false;
	viewState.orphanRemovals = {};
	updateScanDisabled(viewState);
}

function setBusy(viewState, busy) {
	var refs = viewState.refs || {};
	viewState.configSaving = busy;
	(viewState.ifcfgButtons || []).forEach(function(button) {
		button.disabled = Boolean(busy || viewState.ifcfgLoading || button.ifcfgAlwaysDisabled);
	});
	if (refs.ifcfgOrphans && refs.ifcfgOrphans.querySelectorAll)
		Array.prototype.forEach.call(refs.ifcfgOrphans.querySelectorAll('button'), function(button) {
			button.disabled = Boolean(busy);
		});
	updateScanDisabled(viewState);
}

function buildSection(viewState, title) {
	var refs = viewState.refs || {};
	refs.ifcfgSummary = E('span', { 'class': 'sum', 'aria-live': 'polite' }, _('正在扫描…'));
	refs.ifcfgLimit = E('span', { 'class': 'lanspeed-interface-limit', 'role': 'status' }, '');
	refs.ifcfgBody = E('tbody', {});
	refs.ifcfgStatus = E('span', { 'class': 'status', 'role': 'status', 'aria-live': 'polite' }, '');
	refs.ifcfgReloadBtn = E('button', {
		'class': 'cbi-button', 'type': 'button', 'aria-label': _('重新扫描网络接口')
	}, _('扫描设备'));
	refs.ifcfgHint = E('p', { 'class': 'lanspeed-hint', 'aria-live': 'polite' }, '');
	refs.ifcfgOrphans = E('div', {
		'class': 'lanspeed-interface-orphans', 'hidden': 'hidden', 'aria-live': 'polite'
	});
	refs.ifcfgReloadBtn.addEventListener('click', function() { loadIfaceConfig(viewState); });
	refs.ifcfg = E('div', { 'class': 'lanspeed-ifcfg-body' }, [
		E('table', { 'class': 'lanspeed-ifcfg-table' }, [
			E('thead', {}, E('tr', {}, [ E('th', {}, _('接口')), E('th', {}, _('能力')), E('th', { 'class': 'action' }, _('模式')) ])),
			refs.ifcfgBody
		]),
		refs.ifcfgOrphans,
		E('div', { 'class': 'lanspeed-ifcfg-actions' }, [ refs.ifcfgReloadBtn, E('span', { 'class': 'spacer' }), refs.ifcfgLimit, refs.ifcfgStatus ]),
		refs.ifcfgHint
	]);
	refs.ifcfgRoot = E('section', { 'class': 'lanspeed-config-subsection lanspeed-ifcfg', 'data-state': 'loading' }, [
		E('div', { 'class': 'lanspeed-config-subheader' }, [ E('h4', {}, title || _('接口分配')), E('span', { 'class': 'spacer' }), refs.ifcfgSummary ]),
		refs.ifcfg
	]);
	viewState.refs = refs;
	return refs.ifcfgRoot;
}

function verify(viewState, expected) {
	var token;
	var pending;
	if (!viewState || viewState.ifcfgDirty)
		return Promise.resolve({ ok: false, skipped: true });
	if (viewState.ifcfgLoading) {
		if (viewState.ifcfgVerifying && viewState.ifcfgPending)
			return viewState.ifcfgPending;
		if (viewState.ifcfgPending)
			return Promise.resolve(viewState.ifcfgPending).then(function() {
				return verify(viewState, expected);
			});
		return Promise.resolve({ ok: false, skipped: true });
	}
	token = (viewState.ifcfgRequestToken || 0) + 1;
	viewState.ifcfgRequestToken = token;
	viewState.ifcfgLoading = true;
	viewState.ifcfgVerifying = true;
	setInterfaceStatus(viewState, 'loading', _('正在验证运行中的接口…'));
	updateScanDisabled(viewState);
	pending = Promise.resolve().then(function() { return lsRpc.sysdevices(); }).then(function(data) {
		if (token !== viewState.ifcfgRequestToken) return { ok: false, stale: true };
		var normalized = normalizeSysdevices(data);
		var desired = expected || originalConfig(viewState);
		var wanted = unique((desired.ifname || []).concat(desired.interface_include || []))
			.filter(function(name) { return !isAutoIgnored(name); });
		var wantedObserve = unique(desired.observe || []).filter(function(name) {
			return !isAutoIgnored(name) && wanted.indexOf(name) === -1;
		});
		var wantedExcluded = unique(desired.interface_exclude || []);
		var actual = unique(normalized.current_ifnames).filter(function(name) { return !isAutoIgnored(name); });
		var actualObserve = unique(normalized.current_observed).filter(function(name) {
			return !isAutoIgnored(name) && actual.indexOf(name) === -1;
		});
		var actualExcluded = unique(normalized.current_excluded);
		var configuredExcluded = unique(normalized.configured_excluded);
		var ok = normalized.contract_version === 1 && sameNames(actual, wanted) &&
			sameNames(actualObserve, wantedObserve) && sameNames(configuredExcluded, wantedExcluded);
		viewState.sysdevices = normalized;
		setInterfaceStatus(viewState, ok ? 'ready' : 'degraded', ok ? _('运行态已验证') : _('配置已保存，但运行态接口仍未完全匹配'));
		return {
			ok: ok,
			expected: { collect: wanted, observe: wantedObserve, configuredExcluded: wantedExcluded },
			actual: { collect: actual, observe: actualObserve, excluded: actualExcluded,
				configuredExcluded: configuredExcluded }
		};
	}).catch(function(error) {
		if (token !== viewState.ifcfgRequestToken)
			return { ok: false, stale: true, error: error };
		setInterfaceStatus(viewState, 'degraded', _('运行态验证失败：') + text(error && error.message || error));
		return { ok: false, error: error };
	}).then(function(result) {
		if (token === viewState.ifcfgRequestToken) {
			viewState.ifcfgLoading = false;
			viewState.ifcfgPending = null;
			viewState.ifcfgVerifying = false;
			updateScanDisabled(viewState);
		}
		return result;
	});
	viewState.ifcfgPending = pending;
	return pending;
}

return baseclass.extend({
	MAX_INTERFACE_NAMES: cfgModel.MAX_INTERFACE_NAMES,
	buildSection: buildSection,
	load: loadIfaceConfig,
	render: renderIfaceConfig,
	collectSelections: collectSelections,
	prepareSave: prepareIfaceSave,
	markSaved: markSaved,
	setBusy: setBusy,
	verify: verify,
	normalizeSysdevices: normalizeSysdevices,
	isAutoIgnored: isAutoIgnored,
	collectAllowed: collectAllowed
});
