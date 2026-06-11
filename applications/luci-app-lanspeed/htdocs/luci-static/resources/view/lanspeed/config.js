'use strict';
'require view';
'require form';
'require uci';
'require lanspeed.rpc as lsRpc';
'require lanspeed.ifaceConfig as ifaceCfg';
'require lanspeed.theme as lsTheme';

/*
 * LAN Speed configuration view.
 *
 * This page keeps UCI-backed runtime knobs away from the live status view and
 * reuses the shared interface-config panel for collect / observe assignments.
 */

var CONFIG_CSS = [
	'.lanspeed-config-root{font-weight:400}',
	'.lanspeed-config-root .cbi-section{font-weight:400}',
	'.lanspeed-header{display:flex;flex-wrap:wrap;gap:.4em 1em;align-items:baseline;',
	'  padding:1em 1.25em .75em 1.25em;margin:0;',
	'  border-bottom:1px solid var(--border,rgba(128,128,128,.25))}',
	'.lanspeed-header>h3{margin:0;padding:0;border:0;width:auto;display:inline;',
	'  flex:0 0 auto;background:transparent;box-shadow:none;line-height:1.25;font-weight:600}',
	'.lanspeed-header>.spacer{flex:1 1 auto}',
	'.lanspeed-header>.sum{font-size:.85em;opacity:.75;',
	'  font-family:var(--font-monospace,ui-monospace,monospace)}',
	'.lanspeed-config-body,.lanspeed-ifcfg-body{padding:1em 1.25em}',
	'.lanspeed-config-table,.lanspeed-ifcfg-table{width:100%;border-collapse:collapse;margin:0}',
	'.lanspeed-config-table th,.lanspeed-config-table td,',
	'.lanspeed-ifcfg-table th,.lanspeed-ifcfg-table td{padding:.6em .6em;text-align:left;',
	'  border-bottom:1px solid var(--border,rgba(128,128,128,.18));vertical-align:middle}',
	'.lanspeed-config-table tbody tr:last-child td,',
	'.lanspeed-ifcfg-table tbody tr:last-child td{border-bottom:0}',
	'.lanspeed-config-table th:first-child,.lanspeed-config-table td:first-child,',
	'.lanspeed-ifcfg-table th:first-child,.lanspeed-ifcfg-table td:first-child{padding-left:0}',
	'.lanspeed-config-table th:last-child,.lanspeed-config-table td:last-child,',
	'.lanspeed-ifcfg-table th:last-child,.lanspeed-ifcfg-table td:last-child{padding-right:0}',
	'.lanspeed-config-table thead th,.lanspeed-ifcfg-table thead th{font-weight:600;opacity:.85}',
	'.lanspeed-config-table .key,.lanspeed-ifcfg-table .mono{font-family:var(--font-monospace,ui-monospace,monospace);',
	'  font-size:.9em;white-space:nowrap}',
	'.lanspeed-config-table .value{width:12em}',
	'.lanspeed-config-table .value.rate{width:16em}',
	'.lanspeed-config-table .value input{width:100%;max-width:12em}',
	'.lanspeed-config-table .value.range{width:18em}',
	'.lanspeed-config-table .value.range input{max-width:none}',
	'.lanspeed-config-table .hint,.lanspeed-ifcfg-table .muted{font-size:.85em;opacity:.72}',
	'.lanspeed-config-table tr.lanspeed-nss-config-only{display:table-row}',
	'.lanspeed-rate-control{display:flex;flex-wrap:wrap;align-items:center;gap:.45em}',
	'.lanspeed-rate-badge{display:none;padding:.08em .45em;border-radius:.35em;',
	'  border:1px solid var(--border,rgba(128,128,128,.22));',
	'  background:var(--label-surface,rgba(128,128,128,.12));',
	'  font-size:.8em;line-height:1.55;white-space:nowrap}',
	'.lanspeed-range-stack{display:flex;flex-direction:column;gap:.6em;align-items:stretch;max-width:22em}',
	'.lanspeed-range-list{display:flex;flex-direction:column;gap:.6em}',
	'.lanspeed-range-pill{display:flex;align-items:center;justify-content:space-between;',
	'  gap:.5em;box-sizing:border-box}',
	'.lanspeed-range-text{flex:1 1 auto;min-width:0;',
	'  font-family:var(--font-monospace,ui-monospace,monospace)}',
	'.lanspeed-range-remove{flex:0 0 auto}',
	'.lanspeed-range-add{display:flex;gap:.5em;align-items:center}',
	'.lanspeed-range-add input{flex:1 1 auto;min-width:0}',
	'.lanspeed-range-add button{flex:0 0 auto}',
	'.lanspeed-ifcfg-table .action{text-align:right;width:17em}',
	'.lanspeed-ifcfg-table .devtags{font-size:.8em;opacity:.7;display:inline-flex;gap:.4em;flex-wrap:wrap}',
	'.lanspeed-ifcfg-table .devtag{padding:.05em .45em;border-radius:.25em;',
	'  background:var(--label-surface,rgba(128,128,128,.12))}',
	'.lanspeed-config-actions{display:flex;flex-wrap:wrap;gap:.5em;align-items:center;margin:1em 0 0 0}',
	'.lanspeed-config-actions>.spacer{flex:1 1 auto}',
	'.lanspeed-config-actions .status{font-size:.85em;opacity:.75;',
	'  font-family:var(--font-monospace,ui-monospace,monospace)}',
	'.lanspeed-ifcfg{display:flex;flex-direction:column;margin:0}',
	'.lanspeed-ifcfg-seg{display:inline-flex;gap:.35em;align-items:stretch;min-width:16em}',
	'.lanspeed-ifcfg-seg>button{flex:1 1 0;min-width:0;padding:.5em .7em;',
	'  font-size:.9em;border:1px solid var(--border,rgba(128,128,128,.3));',
	'  border-radius:.4em;background:transparent;cursor:pointer;color:inherit;',
	'  transition:background-color .1s ease,border-color .1s ease}',
	'.lanspeed-ifcfg-seg>button:hover{background:var(--label-surface,rgba(128,128,128,.1))}',
	'.lanspeed-ifcfg-seg>button.active{',
	'  background:var(--primary,var(--label-surface,rgba(80,120,200,.15)));',
	'  color:var(--primary-foreground,inherit);',
	'  border-color:var(--primary,var(--border,rgba(128,128,128,.3)));',
	'  font-weight:600}',
	'.lanspeed-ifcfg-actions{display:flex;flex-wrap:wrap;gap:.5em;align-items:center;',
	'  margin:.4em 0 0 0}',
	'.lanspeed-ifcfg-actions>.spacer{flex:1 1 auto}',
	'.lanspeed-ifcfg-actions .status{font-size:.85em;opacity:.75;',
	'  font-family:var(--font-monospace,ui-monospace,monospace)}',
	'.lanspeed-hint{margin:.8em 0 0 0;font-size:.85em;opacity:.75}',

	/* Aurora-specific layout pass.  Aurora owns colours and control
	   rendering; these rules only remove double card padding and shape
	   LAN Speed tables/forms to Aurora's spacing scale. */
	'.lanspeed-theme-aurora{display:flex;flex-direction:column;gap:1rem;margin:0}',
	'.lanspeed-theme-aurora>.cbi-section{margin:0;padding:0;overflow:hidden}',
	'.lanspeed-theme-aurora .lanspeed-header{padding:1rem 1.25rem .85rem}',
	'.lanspeed-theme-aurora .lanspeed-config-body,',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-body{padding:1rem 1.25rem}',
	'.lanspeed-theme-aurora .lanspeed-config-table th,',
	'.lanspeed-theme-aurora .lanspeed-config-table td,',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-table th,',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-table td{padding:.55rem .65rem}',
	'.lanspeed-theme-aurora .lanspeed-config-table th:nth-child(1),',
	'.lanspeed-theme-aurora .lanspeed-config-table td:nth-child(1){width:9rem}',
	'.lanspeed-theme-aurora .lanspeed-config-table th:nth-child(2),',
	'.lanspeed-theme-aurora .lanspeed-config-table td:nth-child(2){width:13rem}',
	'.lanspeed-theme-aurora .lanspeed-config-table th:nth-child(3),',
	'.lanspeed-theme-aurora .lanspeed-config-table td:nth-child(3){width:18rem}',
	'.lanspeed-theme-aurora .lanspeed-config-table .value{width:auto}',
	'.lanspeed-theme-aurora .lanspeed-config-table .value input{max-width:16rem}',
	'.lanspeed-theme-aurora .lanspeed-config-table .value.range input{max-width:none}',
	'.lanspeed-theme-aurora .lanspeed-range-stack{max-width:26rem;gap:.5rem}',
	'.lanspeed-theme-aurora .lanspeed-range-pill{display:grid;grid-template-columns:minmax(0,1fr) auto;',
	'  gap:.5rem;align-items:center}',
	'.lanspeed-theme-aurora .lanspeed-range-remove{width:2.25rem;min-width:2.25rem;',
	'  height:2.25rem;padding:0}',
	'.lanspeed-theme-aurora .lanspeed-range-add{display:grid;grid-template-columns:minmax(0,1fr) auto;',
	'  gap:.5rem;align-items:center}',
	'.lanspeed-theme-aurora .lanspeed-range-add button{height:2.25rem}',
	'.lanspeed-theme-aurora .lanspeed-config-actions,',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-actions{margin:.8rem 0 0 0}',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-table .action{width:19rem}',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-seg{gap:.35rem;min-width:17rem}',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-seg>button{padding:.48rem .7rem;',
	'  border-radius:calc(var(--radius-base, .5rem)*1.5)}',
	'@media (max-width:800px){.lanspeed-theme-aurora .lanspeed-header{padding:.85rem 1rem .7rem}',
	'.lanspeed-theme-aurora .lanspeed-config-body,',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-body{padding:.85rem 1rem}',
	'.lanspeed-theme-aurora .lanspeed-config-table,',
	'.lanspeed-theme-aurora .lanspeed-config-table thead,',
	'.lanspeed-theme-aurora .lanspeed-config-table tbody,',
	'.lanspeed-theme-aurora .lanspeed-config-table tr,',
	'.lanspeed-theme-aurora .lanspeed-config-table th,',
	'.lanspeed-theme-aurora .lanspeed-config-table td{display:block;width:auto}',
	'.lanspeed-theme-aurora .lanspeed-config-table thead{display:none}',
	'.lanspeed-theme-aurora .lanspeed-config-table tr{padding:.7rem 0;border-bottom:1px solid var(--border,rgba(128,128,128,.18))}',
	'.lanspeed-theme-aurora .lanspeed-config-table td{padding:.2rem 0;border-bottom:0}',
	'.lanspeed-theme-aurora .lanspeed-config-table td:nth-child(1),',
	'.lanspeed-theme-aurora .lanspeed-config-table td:nth-child(2),',
	'.lanspeed-theme-aurora .lanspeed-config-table td:nth-child(3){width:auto}',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-table .action{width:auto;text-align:left}',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-seg{min-width:0;width:100%}}'
].join('\n');

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

function statusNssEvidence(status) {
	return status && status.evidence && status.evidence.nss ? status.evidence.nss : {};
}

function statusDaedEvidence(status) {
	return status && status.evidence && status.evidence.dae ? status.evidence.dae : {};
}

function isNssDevice(status) {
	var caps = status && status.capabilities || {};
	var nss = statusNssEvidence(status);
	var key;

	if (caps.nss === true || nss.present === true)
		return true;
	if (nss.ecm_offload_active || nss.ppe_offload_active ||
	    nss.direct_supported || nss.direct_enabled ||
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

function daedRuntimeActive(status) {
	var dae = statusDaedEvidence(status);
	return !!(dae.dae_running || dae.daed_running ||
		dae.dae_process || dae.daed_process);
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
	if (daedRuntimeActive(status))
		return _('自动：BPF 优先，NSS 备用。');
	return _('自动：NSS sync 稳定来源，NSS-direct 有速率时补充。');
}

function applyRuntimeInfo(refs, status) {
	var nss = isNssDevice(status);
	var sourceText = currentRateSourceText(status);
	var rateModeLabel = rateCollectorModesForStatus(status, refs.rateCollectorMode ? refs.rateCollectorMode.value : null);
	var i;

	refs.rateHint.textContent = nssRateHint(status);
	refs.currentRateSource.textContent = sourceText;
	refs.currentRateHint.textContent = daedRuntimeActive(status)
		? _('daed 运行中，BPF 优先。')
		: _('daemon 当前选择。');
	if (refs.nssRows) {
		for (i = 0; i < refs.nssRows.length; i++)
			refs.nssRows[i].style.display = nss ? '' : 'none';
	}

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

	if (refs.rateBadge) {
		refs.rateBadge.style.display = nss ? 'inline-flex' : 'none';
		refs.rateBadge.textContent = daedRuntimeActive(status) ? _('NSS + daed') : 'NSS';
	}
}

function setBusy(refs, busy) {
	refs.saveBtn.disabled = busy;
	refs.resetBtn.disabled = busy;
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

function saveDaemonSettings(refs) {
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

	setBusy(refs, true);
	refs.status.textContent = _('保存中…');

	return lsRpc.uciSet('lanspeed', 'main', uciValues)
		.then(function() { return lsRpc.uciCommit('lanspeed'); })
		.then(function() {
			refs.status.textContent = _('重载 daemon…');
			return lsRpc.reload();
		})
		.then(function() {
			fillForm(refs, values);
			refs.status.textContent = _('已应用');
			window.setTimeout(function() {
				if (refs.status.textContent === _('已应用'))
					refs.status.textContent = '';
			}, 3000);
		})
		.catch(function(err) {
			refs.status.textContent = _('保存失败: ') + (err && err.message || err);
		})
		.then(function() {
			setBusy(refs, false);
		});
}

function buildDaemonSection(values) {
	var refs = {};

	refs.rateCollectorMode = selectRateCollectorMode(values.rate_collector_mode, values.status || {});
	refs.rateBadge = E('span', { 'class': 'lanspeed-rate-badge' }, 'NSS');
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
	refs.status = E('span', { 'class': 'status' }, '');
	refs.rateHint = E('td', { 'class': 'hint' }, '');
	refs.currentRateSource = E('span', { 'class': 'key' }, '-');
	refs.currentRateHint = E('td', { 'class': 'hint' }, '');
	refs.saveBtn = E('button', {
		'class': 'cbi-button cbi-button-apply',
		'type': 'button'
	}, _('保存并重载'));
	refs.resetBtn = E('button', {
		'class': 'cbi-button',
		'type': 'button'
	}, _('恢复默认值'));

	refs.saveBtn.addEventListener('click', function() {
		saveDaemonSettings(refs);
	});
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

	refs.nssRows = [
		E('tr', { 'class': 'lanspeed-nss-config-only' }, [
			E('td', {}, _('当前采集方式')),
			E('td', { 'class': 'key' }, _('运行时')),
			E('td', { 'class': 'value' }, refs.currentRateSource),
			refs.currentRateHint
		])
	];
	applyRuntimeInfo(refs, values.status || {});

	return E('div', { 'class': 'cbi-section' }, [
		E('div', { 'class': 'lanspeed-header' }, [
			E('h3', {}, _('运行参数')),
			E('span', { 'class': 'spacer' }),
			E('span', { 'class': 'sum' }, _('UCI'))
		]),
		E('div', { 'class': 'lanspeed-config-body' }, [
			E('table', { 'class': 'lanspeed-config-table' }, [
				E('thead', {}, E('tr', {}, [
					E('th', {}, _('项目')),
					E('th', {}, _('UCI')),
					E('th', { 'class': 'value' }, _('值')),
					E('th', {}, _('范围'))
				])),
				E('tbody', {}, [
					E('tr', {}, [
						E('td', {}, _('速率采集')),
						E('td', { 'class': 'key' }, 'rate_collector_mode'),
						E('td', { 'class': 'value rate' }, E('div', { 'class': 'lanspeed-rate-control' }, [
							refs.rateCollectorMode,
							refs.rateBadge
						])),
						refs.rateHint
					]),
					refs.nssRows[0],
					E('tr', {}, [
						E('td', {}, _('连接数采集')),
						E('td', { 'class': 'key' }, 'conn_collector_mode'),
						E('td', { 'class': 'value' }, refs.connCollectorMode),
						E('td', { 'class': 'hint' }, _('CT 只用于连接数和诊断。'))
					]),
					E('tr', {}, [
						E('td', {}, _('活跃客户端窗口')),
						E('td', { 'class': 'key' }, 'active_client_window_ms'),
						E('td', { 'class': 'value' }, refs.activeWindow),
						E('td', { 'class': 'hint' }, _('1000 ms 以上'))
					]),
					E('tr', {}, [
						E('td', {}, _('活跃最小速率')),
						E('td', { 'class': 'key' }, 'active_client_min_bps'),
						E('td', { 'class': 'value' }, refs.activeMin),
						E('td', { 'class': 'hint' }, _('1 bps 以上'))
					]),
					E('tr', {}, [
						E('td', {}, _('显示 IPv6 地址')),
						E('td', { 'class': 'key' }, 'show_ipv6'),
						E('td', { 'class': 'value' }, refs.showIpv6),
						E('td', { 'class': 'hint' }, _('关闭后客户端列表只显示 IPv4。'))
					]),
					E('tr', {}, [
						E('td', {}, _('隐藏私有 IPv6 地址')),
						E('td', { 'class': 'key' }, 'hide_private_ipv6'),
						E('td', { 'class': 'value' }, refs.hidePrivateIpv6),
						E('td', { 'class': 'hint' }, _('开启后客户端列表隐藏 fc00::/7 私有 IPv6 地址和 fe80::/10 链路本地地址；公网 IPv6 仍显示。'))
					]),
					E('tr', {}, [
						E('td', {}, _('隐藏 IPv6 范围')),
						E('td', { 'class': 'key' }, 'hide_ipv6_ranges'),
						E('td', { 'class': 'value range' }, refs.rangeEditor),
						E('td', { 'class': 'hint' }, _('仅在隐藏私有 IPv6 地址开启时生效；用空格或逗号分隔，例如 fc00::/7 fe80::/10。'))
					])
				])
			]),
			E('div', { 'class': 'lanspeed-config-actions' }, [
				refs.saveBtn,
				refs.resetBtn,
				E('span', { 'class': 'spacer' }),
				refs.status
			])
		])
	]);
}

return view.extend({
	load: function() {
		return uci.load('lanspeed').then(function() {
			var legacy = uci.get('lanspeed', 'main', 'collector_mode');
			var rateMode = uci.get('lanspeed', 'main', 'rate_collector_mode');
			var connMode = uci.get('lanspeed', 'main', 'conn_collector_mode');

			return {
				rate_collector_mode: rateCollectorModeValue(rateMode || legacyRateCollectorMode(legacy)),
				conn_collector_mode: connCollectorModeValue(connMode || legacyConnCollectorMode(legacy)),
				active_client_window_ms: uciInt('active_client_window_ms'),
				active_client_min_bps: uciInt('active_client_min_bps'),
				show_ipv6: boolValue(uci.get('lanspeed', 'main', 'show_ipv6'), DEFAULTS.show_ipv6),
				hide_private_ipv6: boolValue(uci.get('lanspeed', 'main', 'hide_private_ipv6'), DEFAULTS.hide_private_ipv6),
				hide_ipv6_ranges: stringValue(uci.get('lanspeed', 'main', 'hide_ipv6_ranges'), DEFAULTS.hide_ipv6_ranges),
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
	},

	render: function(values) {
		var viewState = {
			refs: {},
			reload: function() { return Promise.resolve(); }
		};

		var root = E('div', { 'class': 'cbi-map lanspeed-config-root' }, [
			E('style', {}, CONFIG_CSS),
			buildDaemonSection(values || DEFAULTS),
			E('div', { 'class': 'cbi-section' }, [
				ifaceCfg.buildSection(viewState, _('接口配置'))
			])
		]);

		lsTheme.applyRoot(root);

		ifaceCfg.load(viewState);
		return root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
