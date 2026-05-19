'use strict';
'require view';
'require form';
'require uci';
'require lanspeed.rpc as lsRpc';
'require lanspeed.ifaceConfig as ifaceCfg';

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
	'.lanspeed-config-table .value input{width:100%;max-width:12em}',
	'.lanspeed-config-table .hint,.lanspeed-ifcfg-table .muted{font-size:.85em;opacity:.72}',
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
	'.lanspeed-hint{margin:.8em 0 0 0;font-size:.85em;opacity:.75}'
].join('\n');

var DEFAULTS = {
	rate_collector_mode: 'auto',
	conn_collector_mode: 'auto',
	active_client_window_ms: 10000,
	active_client_min_bps: 1
};

var RATE_COLLECTOR_MODES = [
	[ 'auto', _('自动') ],
	[ 'bpf', 'BPF' ]
];

var CONN_COLLECTOR_MODES = [
	[ 'auto', _('自动') ],
	[ 'conntrack_netlink', _('CT-Netlink（连接数）') ],
	[ 'conntrack_procfs', _('CT-Procfs（连接数）') ]
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
	if (value === 'bpf')
		return value;
	return DEFAULTS.rate_collector_mode;
}

function connCollectorModeValue(value) {
	if (value === 'conntrack_netlink' || value === 'conntrack_procfs')
		return value;
	return DEFAULTS.conn_collector_mode;
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

function selectRateCollectorMode(value) {
	return selectMode(value, RATE_COLLECTOR_MODES, rateCollectorModeValue);
}

function selectConnCollectorMode(value) {
	return selectMode(value, CONN_COLLECTOR_MODES, connCollectorModeValue);
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
			DEFAULTS.active_client_min_bps, 1, 0)
	};
}

function fillForm(refs, values) {
	refs.rateCollectorMode.value = rateCollectorModeValue(values.rate_collector_mode);
	refs.connCollectorMode.value = connCollectorModeValue(values.conn_collector_mode);
	refs.activeWindow.value = String(values.active_client_window_ms);
	refs.activeMin.value = String(values.active_client_min_bps);
}

function saveDaemonSettings(refs) {
	var values = readForm(refs);
	var uciValues = {
		rate_collector_mode: values.rate_collector_mode,
		conn_collector_mode: values.conn_collector_mode,
		collector_mode: values.rate_collector_mode,
		active_client_window_ms: String(values.active_client_window_ms),
		active_client_min_bps: String(values.active_client_min_bps)
	};

	setBusy(refs, true);
	refs.status.textContent = _('保存中…');

	return lsRpc.uciSet('lanspeed', 'main', uciValues)
		.then(function() { return lsRpc.uciCommit('lanspeed'); })
		.then(function() {
			refs.status.textContent = _('重载 daemon…');
			return lsRpc.init('lanspeedd', 'reload');
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

	refs.rateCollectorMode = selectRateCollectorMode(values.rate_collector_mode);
	refs.connCollectorMode = selectConnCollectorMode(values.conn_collector_mode);
	refs.activeWindow = inputNumber(values.active_client_window_ms, 1000, 0, 1000);
	refs.activeMin = inputNumber(values.active_client_min_bps, 1, 0, 1);
	refs.status = E('span', { 'class': 'status' }, '');
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
						E('td', { 'class': 'value' }, refs.rateCollectorMode),
						E('td', { 'class': 'hint' }, _('非 NSS 实时测速只使用 BPF；自动模式下 NSS ECM 同步可作为 NSS 设备的测速来源。'))
					]),
					E('tr', {}, [
						E('td', {}, _('连接数采集')),
						E('td', { 'class': 'key' }, 'conn_collector_mode'),
						E('td', { 'class': 'value' }, refs.connCollectorMode),
						E('td', { 'class': 'hint' }, _('CT 只影响连接数和诊断，不作为非 NSS 客户端实时测速来源。'))
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
				active_client_min_bps: uciInt('active_client_min_bps')
			};
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

		ifaceCfg.load(viewState);
		return root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
