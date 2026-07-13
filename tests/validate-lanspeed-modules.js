#!/usr/bin/env node

/*
 * Validates the modular structure of luci-app-lanspeed's resources tree.
 *
 * Contract enforced:
 *   1. Every expected sub-module file exists under
 *      applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/
 *      and the active view entry under resources/view/lanspeed/index_live.js.
 *   2. Each sub-module begins with 'use strict' and declares the expected
 *      'require baseclass' (plus 'require rpc' for rpc.js). NSS panel
 *      additionally requires vocab + format.
 *   3. Each sub-module ends its body with `return baseclass.extend({...})`
 *      so LuCI's module loader receives a class.
 *   4. The status implementation module and config view entry declare their
 *      expected sub-module requires at the top of the file.
 *   5. Boundary hygiene: rpc.declare must only appear in rpc.js. The
 *      vocab/format/nssPanel modules must stay free of RPC declarations.
 *   6. Every expected module and view entry parses as JavaScript
 *      (acorn-free: we use VM compile to catch syntax errors).
 *
 * Output: writes a short PASS summary to stdout and exits 0 on success.
 * On any failure, prints the failing rule and exits 1.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const resDir = path.join(root,
	'applications/luci-app-lanspeed/htdocs/luci-static/resources');
const modDir = path.join(resDir, 'lanspeed');
const viewFile = path.join(resDir, 'view/lanspeed/index_live4.js');
const legacyViewFile = path.join(resDir, 'view/lanspeed/index.js');
const configViewFile = path.join(resDir, 'view/lanspeed/config.js');
const statusViewFile = path.join(modDir, 'statusViewLive.js');
const daemonMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const luciMakefile = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/Makefile'), 'utf8');

const EXPECTED_MODULES = [
	'vocab.js',
	'format.js',
	'rpc.js',
	'ifaceConfig.js',
	'nssPanel.js',
	'theme.js',
	'version.js',
	'statusStyle.js',
	'statusStyleCompatLive.js',
	'statusStyleCompatLive2.js',
	'statusStyleCompatLive3.js',
	'statusViewLive.js',
	'statusViewLive2.js',
	'statusViewLive3.js',
	'statusIp.js',
	'statusCollector.js',
	'statusShell.js',
	'statusRefresh.js',
	'configStyle.js',
	'configForm.js'
];

const EXPECTED_VIEW_REQUIRES = [
	'lanspeed.format',
	'lanspeed.rpc',
	'lanspeed.statusIp',
	'lanspeed.statusShell',
	'lanspeed.statusRefresh',
	'lanspeed.statusStyleCompatLive'
];

const EXPECTED_CONFIG_VIEW_REQUIRES = [
	'form',
	'lanspeed.ifaceConfig',
	'lanspeed.theme',
	'lanspeed.configStyle',
	'lanspeed.configForm'
];

function readMakeVar(source, name, fileLabel) {
	const match = source.match(new RegExp(`^${name}:=(.+)$`, 'm'));
	if (!match) {
		fail(`${fileLabel} must define ${name}`);
		return '';
	}
	return match[1].trim();
}

const MODULE_REQUIRES = {
	'vocab.js':       [ 'baseclass' ],
	'format.js':      [ 'baseclass' ],
	'rpc.js':         [ 'baseclass', 'rpc' ],
	'ifaceConfig.js': [ 'baseclass', 'lanspeed.format', 'lanspeed.rpc' ],
	'nssPanel.js':    [ 'baseclass', 'lanspeed.vocab', 'lanspeed.format' ],
	'theme.js':       [ 'baseclass' ],
	'version.js':     [ 'baseclass' ],
	'statusStyle.js': [ 'baseclass' ],
	'statusStyleCompatLive.js': [ 'baseclass' ],
	'statusStyleCompatLive2.js': [ 'baseclass' ],
	'statusStyleCompatLive3.js': [ 'baseclass' ],
	'statusViewLive.js': [
		'baseclass',
		'lanspeed.format',
		'lanspeed.rpc',
		'lanspeed.statusIp',
		'lanspeed.statusShell',
		'lanspeed.statusRefresh',
		'lanspeed.statusStyleCompatLive'
	],
	'statusViewLive2.js': [
		'baseclass',
		'lanspeed.statusViewLive',
		'lanspeed.statusStyleCompatLive2'
	],
	'statusViewLive3.js': [
		'baseclass',
		'lanspeed.statusViewLive',
		'lanspeed.statusStyleCompatLive3'
	],
	'statusIp.js':    [ 'baseclass', 'lanspeed.format' ],
	'statusCollector.js': [ 'baseclass' ],
	'statusShell.js': [
		'baseclass',
		'lanspeed.format',
		'lanspeed.nssPanel',
		'lanspeed.theme',
		'lanspeed.statusStyle'
	],
	'statusRefresh.js': [
		'baseclass',
		'lanspeed.vocab',
		'lanspeed.format',
		'lanspeed.version',
		'lanspeed.nssPanel',
		'lanspeed.statusIp',
		'lanspeed.statusCollector'
	],
	'configStyle.js': [ 'baseclass' ],
	'configForm.js': [ 'baseclass', 'uci', 'lanspeed.rpc', 'lanspeed.ifaceConfig' ]
};

/* Modules that MUST NOT contain `rpc.declare`. rpc.js is the only file
 * allowed to declare rpc handles. */
const RPC_FREE_MODULES = [
	'vocab.js',
	'format.js',
	'nssPanel.js',
	'statusStyle.js',
	'statusStyleCompatLive.js',
	'statusStyleCompatLive2.js',
	'statusStyleCompatLive3.js',
	'statusViewLive.js',
	'statusViewLive2.js',
	'statusViewLive3.js',
	'statusIp.js',
	'statusCollector.js',
	'statusRefresh.js',
	'configStyle.js'
];

const errors = [];
function fail(msg) { errors.push(msg); }

function assertFileExists(absPath, label) {
	if (!fs.existsSync(absPath)) {
		fail(`${label} missing: ${path.relative(root, absPath)}`);
		return false;
	}
	return true;
}

function readModule(absPath) {
	return fs.readFileSync(absPath, 'utf8');
}

function readModuleByName(name) {
	const p = path.join(modDir, name);
	return fs.existsSync(p) ? readModule(p) : '';
}

function stripComments(src) {
	/* Good enough for our structural checks: drop block comments and
	 * single-line // comments so subsequent regex never matches tokens
	 * inside prose (e.g. the string "rpc.declare" in a design comment). */
	return src
		.replace(/\/\*[\s\S]*?\*\//g, '')
		.replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

function assertStrict(src, label) {
	if (!/^\s*['"]use strict['"]\s*;/.test(src)) {
		fail(`${label} must start with 'use strict'`);
	}
}

function assertRequire(src, modName, requires) {
	requires.forEach(function(req) {
		const re = new RegExp("^\\s*['\"]require\\s+" + req.replace(/\./g, '\\.') + "(?:\\s+as\\s+\\w+)?['\"]\\s*;", 'm');
		if (!re.test(src)) {
			fail(`${modName} must declare 'require ${req}'`);
		}
	});
}

function assertBaseclassExtend(src, modName) {
	/* Must call baseclass.extend() at module scope, and must RETURN its
	 * result so LuCI's loader gets the class. */
	if (!/\breturn\s+baseclass\.extend\s*\(/.test(src)) {
		fail(`${modName} must end with 'return baseclass.extend({...})'`);
	}
}

function assertSyntax(src, modName) {
	/* LuCI view/require modules start at module scope with 'use strict' +
	 * require directives, then plain JS, with a final `return ...;` that
	 * LuCI's loader wraps in a function.  We simulate that wrapper so
	 * vm.compileFunction accepts the `return` at top level.  Any syntax
	 * error in the raw source will still throw here. */
	try {
		vm.compileFunction(src, [], { filename: modName });
	} catch (err) {
		fail(`${modName} failed to parse: ${err.message}`);
	}
}

function loadFormatModule(src) {
	const fakeBaseclass = {
		extend: function(value) {
			return value;
		}
	};
	return vm.compileFunction(src, [ 'baseclass' ], {
		filename: 'resources/lanspeed/format.js'
	})(fakeBaseclass);
}

function fakeElement(tag, attrs, children) {
	const node = {
		tagName: tag,
		attrs: Object.assign({}, attrs || {}),
		children: [],
		listeners: {},
		addEventListener: function(type, handler) { this.listeners[type] = handler; },
		setAttribute: function(name, value) { this.attrs[name] = value; }
	};
	const append = function(child) {
		if (Array.isArray(child)) child.forEach(append);
		else if (child !== null && child !== undefined && child !== '') node.children.push(child);
	};
	append(children);
	Object.defineProperty(node, 'lastChild', {
		get: function() { return this.children[this.children.length - 1]; }
	});
	return node;
}

function findFakeElement(node, className) {
	if (!node || typeof node !== 'object') return null;
	const classes = String(node.attrs && node.attrs.class || '').split(/\s+/);
	if (classes.includes(className)) return node;
	for (const child of node.children || []) {
		const found = findFakeElement(child, className);
		if (found) return found;
	}
	return null;
}

function assertFormatActiveWindow(src) {
	const fmt = loadFormatModule(src);
	const clients = [
		{
			identity_key: 'recent-zero-rate@lan',
			sample_ms: 20000,
			last_seen: 12000,
			tx_bps: 0,
			rx_bps: 0
		},
		{
			identity_key: 'active-low-rate@lan',
			sample_ms: 20000,
			last_seen: 10000,
			tx_bps: 1,
			rx_bps: 0
		},
		{
			identity_key: 'stale-high-rate@lan',
			sample_ms: 20000,
			last_seen: 9999,
			tx_bps: 1000000,
			rx_bps: 0
		}
	];

	if (fmt.ACTIVE_CLIENT_WINDOW_MS !== 10000) {
		fail('format.js must expose a 10000 ms active client window');
	}
	if (fmt.ACTIVE_CLIENT_MIN_BPS !== 1) {
		fail('format.js must expose a 1 bps active client minimum');
	}
	if (typeof fmt.isActiveClient !== 'function') {
		fail('format.js must expose isActiveClient(client, nowMs, config)');
		return;
	}
	if (typeof fmt.activeConfig !== 'function') {
		fail('format.js must expose activeConfig(status, overview)');
		return;
	}
	if (fmt.isActiveClient(clients[0], 20000)) {
		fail('format.js must not count a zero-rate client as active even when seen within 10s');
	}
	if (!fmt.isActiveClient(clients[1], 20000)) {
		fail('format.js must count a nonzero-rate client seen exactly 10s ago as active');
	}
	if (fmt.isActiveClient(clients[1], 20000, { activeWindowMs: 10000, activeMinBps: 2 })) {
		fail('format.js must respect configured active_client_min_bps');
	}
	if (!fmt.isActiveClient(clients[2], 20000, { activeWindowMs: 10001, activeMinBps: 1 })) {
		fail('format.js must respect configured active_client_window_ms');
	}
	if (fmt.isActiveClient(clients[2], 20000)) {
		fail('format.js must not count a nonzero-rate client last seen more than 10s ago as active');
	}
	if (fmt.sumTotals(clients).active !== 1) {
		fail('format.js sumTotals must count active clients by nonzero rate plus last_seen within 10s');
	}
	if (fmt.sumTotals(clients, { activeWindowMs: 10001, activeMinBps: 1 }).active !== 2) {
		fail('format.js sumTotals must honor configured active window');
	}
	if (fmt.activeConfig({ active_client_window_ms: 15000, active_client_min_bps: 4096 }).activeWindowMs !== 15000) {
		fail('format.js activeConfig must read status.active_client_window_ms');
	}
}

function assertFormatSorting(src) {
	const fmt = loadFormatModule(src);
	const clients = [
		{ identity_key: 'zulu@lan', hostname: 'Zulu', mac: '00:00:00:00:00:02', tx_bps: 20, rx_bps: 100, tcp_conns: 2, udp_conns: 4 },
		{ identity_key: 'alpha@lan', hostname: 'Alpha', mac: '00:00:00:00:00:01', tx_bps: 30, rx_bps: 50, tcp_conns: 5, udp_conns: 1 }
	];
	const identities = function(sorted) { return sorted.map(function(client) { return client.identity_key; }).join(','); };

	if (fmt.DEFAULT_PREFS.sortKey !== 'rx' || fmt.DEFAULT_PREFS.sortDir !== 'desc' || fmt.DEFAULT_PREFS.sortCustom !== false) {
		fail('format.js must default the client table to descending download speed');
	}
	if (JSON.stringify(Array.from(fmt.SORT_KEYS)) !== JSON.stringify([ 'hostname', 'mac', 'tx', 'rx', 'tcp_conns', 'udp_conns' ])) {
		fail('format.js must expose exactly the six sortable client columns');
	}
	if (fmt.defaultSortDirection('hostname') !== 'desc' ||
	    fmt.defaultSortDirection('mac') !== 'desc' ||
	    fmt.defaultSortDirection('rx') !== 'desc') {
		fail('format.js must start every sortable column in descending order');
	}
	const first = fmt.nextSort(fmt.DEFAULT_PREFS, 'hostname');
	const second = fmt.nextSort(first, 'hostname');
	const third = fmt.nextSort(second, 'hostname');
	if (first.sortDir !== 'desc' || !first.sortCustom || second.sortDir !== 'asc' ||
	    !second.sortCustom || third.sortKey !== 'rx' || third.sortDir !== 'desc' || third.sortCustom) {
		fail('format.js must cycle sort headers through descending, ascending, then default sorting');
	}
	if (identities(fmt.sortClients(clients, 'rx')) !== 'zulu@lan,alpha@lan' ||
	    identities(fmt.sortClients(clients, 'rx', 'asc')) !== 'alpha@lan,zulu@lan') {
		fail('format.js must sort numeric columns in both directions');
	}
	if (identities(fmt.sortClients(clients, 'hostname', 'asc')) !== 'alpha@lan,zulu@lan' ||
	    identities(fmt.sortClients(clients, 'hostname', 'desc')) !== 'zulu@lan,alpha@lan') {
		fail('format.js must sort client names in both directions');
	}
}

function assertStatusShellInteraction(src) {
	let saved = 0;
	let refreshed = 0;
	const E = fakeElement;
	const fmt = {
		REFRESH_CHOICES: [ { value: 1000, label: '1s' }, { value: 3000, label: '3s' } ],
		MIN_REFRESH_MS: 1000,
		opt: function(value, label, selected) {
			const attrs = { value: String(value) };
			if (selected) attrs.selected = 'selected';
			return E('option', attrs, label);
		},
		nextSort: function(prefs, key) {
			if (!prefs.sortCustom || prefs.sortKey !== key)
				return { sortKey: key, sortDir: 'desc', sortCustom: true };
			if (prefs.sortDir === 'desc')
				return { sortKey: key, sortDir: 'asc', sortCustom: true };
			return { sortKey: 'rx', sortDir: 'desc', sortCustom: false };
		},
		savePrefs: function() { saved++; }
	};
	const fakeBaseclass = { extend: function(value) { return value; } };
	const shell = vm.compileFunction(src,
		[ 'baseclass', 'fmt', 'nssPanel', 'lsTheme', 'statusStyle', 'E', '_' ],
		{ filename: 'resources/lanspeed/statusShell.js' })(
			fakeBaseclass,
			fmt,
			{ build: function() { return E('div', { class: 'nss-test' }); } },
			{ applyRoot: function() {} },
			{ CSS: '' },
			E,
			function(value) { return value; }
		);
	const viewState = {
		prefs: { refreshMs: 3000, unit: 'bit', activeOnly: false, sortKey: 'rx', sortDir: 'desc', sortCustom: false, paused: false },
		filter: '',
		reload: function() {},
		refreshLive: function() { refreshed++; },
		stopTimer: function() {},
		schedule: function() {}
	};
	const built = shell.buildShell(viewState);
	const refs = built.refs;
	const left = findFakeElement(built.root, 'lanspeed-toolbar-left');
	const filter = findFakeElement(built.root, 'lanspeed-toolbar-filter');
	const right = findFakeElement(built.root, 'lanspeed-toolbar-right');

	if (!left || !filter || !right || left.children[1] !== filter ||
	    filter.children[0] !== refs.filterInput || right.children[1] !== refs.btnRefresh ||
	    right.children[2] !== refs.btnPause || refs.sortSel) {
		fail('statusShell.js toolbar DOM must keep unit/filter left and refresh actions right without a sort select');
	}
	refs.sortHeaders.rx.button.listeners.click();
	if (viewState.prefs.sortKey !== 'rx' || viewState.prefs.sortDir !== 'desc' || !viewState.prefs.sortCustom || saved !== 1 || refreshed !== 1) {
		fail('statusShell.js must start an active default sort header in descending order');
	}
	refs.sortHeaders.rx.button.listeners.click();
	if (viewState.prefs.sortKey !== 'rx' || viewState.prefs.sortDir !== 'asc' || !viewState.prefs.sortCustom || saved !== 2 || refreshed !== 2) {
		fail('statusShell.js must switch an active descending header to ascending');
	}
	refs.sortHeaders.rx.button.listeners.click();
	if (viewState.prefs.sortKey !== 'rx' || viewState.prefs.sortDir !== 'desc' || viewState.prefs.sortCustom || saved !== 3 || refreshed !== 3) {
		fail('statusShell.js must restore default sorting after ascending');
	}
	refs.sortHeaders.hostname.button.listeners.click();
	if (viewState.prefs.sortKey !== 'hostname' || viewState.prefs.sortDir !== 'desc' || !viewState.prefs.sortCustom || saved !== 4 || refreshed !== 4) {
		fail('statusShell.js must start a different sort header in descending order');
	}
}

function assertNssPanelSource(src) {
	if (!src.includes('function hasNssSignal(status)')) {
		fail('lanspeed/nssPanel.js must keep the NSS panel signal helper');
	}
	if (!src.includes('function nssDirectFallbackText(reason)') ||
	    !src.includes('collector_mode_bpf') ||
	    !src.includes('当前使用 BPF') ||
	    !src.includes('collector_mode_nss_conntrack_sync') ||
	    !src.includes('当前使用 NSS sync')) {
		fail('lanspeed/nssPanel.js must render NSS-direct collector-mode fallback reasons as user-facing text');
	}
	if (!src.includes('NSS 状态') ||
	    !src.includes('引擎与加速') ||
	    !src.includes('NSS 相关告警')) {
		fail('lanspeed/nssPanel.js must render NSS panel sections');
	}
	if (src.includes('nssInitialized') ||
	    src.includes("setAttribute('open'") ||
	    src.includes("'open': 'open'")) {
		fail('lanspeed/nssPanel.js must leave NSS status collapsed by default');
	}
}

function assertNoRpcDeclare(src, modName) {
	if (/\brpc\s*\.\s*declare\s*\(/.test(src)) {
		fail(`${modName} must not contain rpc.declare (belongs in rpc.js)`);
	}
}

function assertViewRequires(src) {
	EXPECTED_VIEW_REQUIRES.forEach(function(req) {
		const re = new RegExp("^\\s*['\"]require\\s+" + req.replace(/\./g, '\\.') + "\\s+as\\s+\\w+['\"]\\s*;", 'm');
		if (!re.test(src)) {
			fail(`lanspeed/statusView.js must declare 'require ${req} as <alias>'`);
		}
	});
}

function assertStatusViewWrapper(src, label) {
	if (!/^\s*['"]require\s+view['"]\s*;/m.test(src) ||
	    !/^\s*['"]require\s+lanspeed\.statusViewLive3\s+as\s+statusViewLive3['"]\s*;/m.test(src) ||
	    !src.includes('return view.extend({') ||
	    !src.includes('return statusViewLive3.load();') ||
	    !src.includes('return statusViewLive3.render(data);')) {
		fail(`${label} must wrap lanspeed/statusViewLive3.js through a concrete LuCI view.extend() constructor`);
	}
	if (src.includes('statusShell.buildShell(') ||
	    src.includes('statusRefresh.refreshLive(') ||
	    src.includes('loadAll()')) {
		fail(`${label} must remain a cache-busting wrapper, not duplicate status view logic`);
	}
}

function assertConfigViewRequires(src) {
	EXPECTED_CONFIG_VIEW_REQUIRES.forEach(function(req) {
		const re = new RegExp("^\\s*['\"]require\\s+" + req.replace(/\./g, '\\.') + "(?:\\s+as\\s+\\w+)?['\"]\\s*;", 'm');
		if (!re.test(src)) {
			fail(`view/lanspeed/config.js must declare 'require ${req}'`);
		}
	});
}

function assertConfigView(src) {
	if (!src.includes('lanspeed-config-table')) {
		fail('view/lanspeed/config.js must render daemon settings as a compact table');
	}
	if (!src.includes('lanspeed-config-root')) {
		fail('view/lanspeed/config.js must scope local typography to the LAN Speed config root');
	}
	if (!src.includes('lanspeed-config-body')) {
		fail('view/lanspeed/config.js must wrap daemon settings in a padded body for theme compatibility');
	}
	if (!src.includes('lsRpc.status()')) {
		fail('view/lanspeed/config.js must load runtime status for NSS-aware configuration text');
	}
	if (!src.includes('function isNssDevice(') || !src.includes('nss.present === true')) {
		fail('view/lanspeed/config.js must detect NSS devices from status.evidence.nss.present');
	}
	if (src.includes('return !!(status && status.evidence && status.evidence.nss && status.evidence.nss.present);')) {
		fail('view/lanspeed/config.js must not rely only on status.evidence.nss.present for NSS detection');
	}
	if (!src.includes('caps.nss === true') ||
	    !src.includes("key.indexOf('nss') === 0") ||
	    !src.includes('nss.ecm_offload_active') ||
	    !src.includes('nss.direct_supported')) {
		fail('view/lanspeed/config.js must also detect NSS from runtime capabilities and NSS offload evidence');
	}
	if (!src.includes('function daeRuntimeActive(') ||
	    !src.includes('dae.dae_running') ||
	    !src.includes('dae.daed_running')) {
		fail('view/lanspeed/config.js must distinguish running dae/daed from installed config');
	}
	if (src.includes('dae.dae0 || dae.dae0peer') ||
	    src.includes('dae.dae_service || dae.daed_service') ||
	    src.includes('dae.runtime_active')) {
		fail('view/lanspeed/config.js must not treat stopped daed service or leftover dae0 as runtime-active daed');
	}
	if (!src.includes('NSS-direct') ||
	    !src.includes('NSS sync')) {
		fail('view/lanspeed/config.js must explain NSS direct and NSS sync on NSS devices');
	}
	if (!src.includes('function rateCollectorModesForStatus(') ||
	    !src.includes("[ 'nss_ecm_direct', 'NSS-direct' ]") ||
	    !src.includes("[ 'nss_conntrack_sync', 'NSS sync' ]")) {
		fail('view/lanspeed/config.js must show NSS-aware rate_collector_mode labels on NSS devices');
	}
	if (!src.includes('function rateCollectorModesForStatus(status, currentValue)') ||
	    !src.includes("currentValue === 'nss_ecm_direct'") ||
	    !src.includes("currentValue === 'nss_conntrack_sync'")) {
		fail('view/lanspeed/config.js must preserve saved NSS rate_collector_mode values even when runtime NSS detection is unavailable');
	}
	if (!src.includes('lanspeed-current-rate-source') ||
	    !src.includes("_('当前：')") ||
	    !src.includes('nssRateHint(status)')) {
		fail('view/lanspeed/config.js must show the configured and current rate collectors in one row');
	}
	if (src.includes('lanspeed-nss-config-only') || src.includes("_('当前采集方式')")) {
		fail('view/lanspeed/config.js must not render a separate current-collector row');
	}
	if (src.includes('自动（NSS-direct') ||
	    src.includes('自动（BPF') ||
	    src.includes('BPF（LAN 边缘）') ||
	    src.includes('CT-Netlink（连接数）') ||
	    src.includes('CT-Procfs（连接数）') ||
	    src.includes('BPF / NSS-direct / NSS sync') ||
	    src.includes('NSS-direct / NSS sync')) {
		fail('view/lanspeed/config.js rate_collector_mode options must keep explanations out of option labels');
	}
	if (!src.includes("[ 'conntrack_netlink', 'CT-Netlink' ]") ||
	    !src.includes("[ 'conntrack_procfs', 'CT-Procfs' ]")) {
		fail('view/lanspeed/config.js connection collector options must use plain labels');
	}
	if (!src.includes('dae/daed 运行中') || !src.includes('BPF')) {
		fail('view/lanspeed/config.js must explain the dae/daed BPF preference');
	}
	if (src.includes('lanspeed-rate-badge') || src.includes('rateBadge')) {
		fail('view/lanspeed/config.js must not render the removed rate badge');
	}
	if (!src.includes('font-weight:400')) {
		fail('view/lanspeed/config.js must pin normal LAN Speed text weight for Argon compatibility');
	}
	if (!src.includes('active_client_window_ms')) {
		fail('view/lanspeed/config.js must expose active_client_window_ms');
	}
	if (!src.includes('active_client_min_bps')) {
		fail('view/lanspeed/config.js must expose active_client_min_bps');
	}
	if (!src.includes('rate_collector_mode')) {
		fail('view/lanspeed/config.js must expose rate_collector_mode');
	}
	if (!src.includes('conn_collector_mode')) {
		fail('view/lanspeed/config.js must expose conn_collector_mode');
	}
	if (!src.includes('show_ipv6')) {
		fail('view/lanspeed/config.js must expose show_ipv6 for client IP display');
	}
	if (!src.includes('显示 IPv6 地址') || !src.includes('关闭后客户端列表只显示 IPv4。')) {
		fail('view/lanspeed/config.js must explain the IPv6 display toggle');
	}
	if (src.includes('关闭后客户端列表只显示 IPv4；fe80::/10')) {
		fail('view/lanspeed/config.js must keep fe80::/10 wording with the private IPv6 option');
	}
	if (src.includes('fe80::/10 链路本地地址始终隐藏')) {
		fail('view/lanspeed/config.js must not describe fe80::/10 as always hidden');
	}
	if (!src.includes('hide_private_ipv6')) {
		fail('view/lanspeed/config.js must expose hide_private_ipv6 for client IP display');
	}
	if (!src.includes('隐藏私有 IPv6 地址') ||
	    !src.includes('fc00::/7 私有 IPv6 地址和 fe80::/10 链路本地地址')) {
		fail('view/lanspeed/config.js must explain the private IPv6 display toggle');
	}
	if (!src.includes('hide_ipv6_ranges')) {
		fail('view/lanspeed/config.js must expose hide_ipv6_ranges for custom IPv6 hiding');
	}
	if (!src.includes('隐藏 IPv6 范围') ||
	    !src.includes('fc00::/7 fe80::/10') ||
	    !src.includes('用空格或逗号分隔')) {
		fail('view/lanspeed/config.js must explain custom hidden IPv6 ranges');
	}
	if (!src.includes('lanspeed-range-list') ||
	    !src.includes('lanspeed-range-pill') ||
	    !src.includes('function rangeListValue(refs)') ||
	    !src.includes('function buildRangeList(refs, value)')) {
		fail('view/lanspeed/config.js must render hidden IPv6 ranges as removable range pills');
	}
	if (!src.includes("'class': 'lanspeed-range-text cbi-input-text'") ||
	    !src.includes("'readonly': 'readonly'") ||
	    !src.includes("'class': 'lanspeed-range-remove cbi-button cbi-button-remove'")) {
		fail('view/lanspeed/config.js hidden IPv6 range editor must use LuCI theme classes');
	}
	if (/\.lanspeed-range-pill\{[^}]*\b(background|border|border-radius|box-shadow|color)\s*:/s.test(src) ||
	    /\.lanspeed-range-remove\{[^}]*\b(background|border|border-radius|color)\s*:/s.test(src) ||
	    src.includes('.lanspeed-range-remove:hover')) {
		fail('view/lanspeed/config.js hidden IPv6 range editor must not override LuCI theme visual styling');
	}
	if (!src.includes('conntrack_netlink') || !src.includes('conntrack_procfs')) {
		fail('view/lanspeed/config.js must offer CT-Netlink and CT-Procfs connection collector choices');
	}
	if (!src.includes('速率采集') || !src.includes('连接数采集')) {
		fail('view/lanspeed/config.js must split speed and connection collector settings');
	}
	if (!src.includes('非 NSS 实时测速只使用 BPF') || !src.includes('CT 只用于连接数和诊断')) {
		fail('view/lanspeed/config.js must make the non-NSS BPF-only live-rate policy explicit');
	}
	if (!src.includes('ifaceCfg.load(viewState)')) {
		fail('view/lanspeed/config.js must reuse ifaceConfig for interface assignments');
	}
	if (!src.includes('lsRpc.reload()')) {
		fail('view/lanspeed/config.js must call the lanspeed reload ubus method after saving daemon settings');
	}
	const saveLabels = src.match(/_\('保存并重载'\)/g) || [];
	const commits = src.match(/lsRpc\.uciCommit\('lanspeed'\)/g) || [];
	const reloads = src.match(/lsRpc\.reload\(\)/g) || [];
	if (saveLabels.length !== 1 || commits.length !== 1 || reloads.length !== 1 ||
	    !src.includes('configForm.buildSaveSection(viewState)') ||
	    !src.includes('ifaceCfg.prepareSave(viewState)')) {
		fail('view/lanspeed/config.js must use one bottom save button, one commit and one daemon reload for all settings');
	}
	if (src.includes('lsRpc.init(\'lanspeedd\', \'reload\')')) {
		fail('view/lanspeed/config.js must not reload through rc init');
	}
	if (src.includes('overview_window_samples') || src.includes('趋势采样点')) {
		fail('view/lanspeed/config.js must not expose trend sampling after the trend chart is removed');
	}
}

function assertIfaceConfigThemeLayout(src) {
	if (!src.includes('lanspeed-ifcfg-body')) {
		fail('resources/lanspeed/ifaceConfig.js must wrap the interface table in a padded body for theme compatibility');
	}
	if (!src.includes("d.selected && isCollectAllowed(d) ? 'collect'")) {
		fail('resources/lanspeed/ifaceConfig.js must not render unsafe preselected interfaces as collectable');
	}
	if (!src.includes('var values = {};') ||
	    !src.includes('if (sel.attach.length)') ||
	    !src.includes('if (sel.observe.length)') ||
	    src.includes('observe:           sel.observe')) {
		fail('resources/lanspeed/ifaceConfig.js must not send empty UCI list arrays when saving interface assignments');
	}
	if (src.includes('置信度 high')) {
		fail('resources/lanspeed/ifaceConfig.js must not show confidence wording in interface config tooltips');
	}
	const ignoredPrefixes = [
		'dae', 'miireg', 'tun', 'erspan', 'gretap', 'gre', 'ip6gre', 'ip6tnl', 'sit',
		'bonding_masters'
	];
	if (!src.includes('var AUTO_IGNORED_INTERFACE_PREFIXES = [') ||
	    !src.includes('function isAutoIgnoredInterface(name)') ||
	    ignoredPrefixes.some(function(prefix) { return !src.includes("'" + prefix + "'"); }) ||
	    !src.includes('visibleDevices(viewState.sysdevices || {})')) {
		fail('resources/lanspeed/ifaceConfig.js must hide every configured tunnel/proxy interface prefix defensively');
	}
	if (src.includes('ifcfgSaveBtn') || src.includes("lsRpc.uciCommit('lanspeed')") ||
	    src.includes('lsRpc.reload()')) {
		fail('resources/lanspeed/ifaceConfig.js must stage changes for the shared page save flow');
	}
}

function assertStatusViewNoInterfaceConfig(src) {
	if (/^\s*['"]require\s+lanspeed\.ifaceConfig(?:\s+as\s+\w+)?['"]\s*;/m.test(src)) {
		fail('view/lanspeed/index.js must not load ifaceConfig; interface assignments belong on config.js');
	}
	if (src.includes('ifaceCfg.load(viewState)')) {
		fail('view/lanspeed/index.js must not load interface configuration');
	}
	if (src.includes('ifaceCfg.save(viewState)')) {
		fail('view/lanspeed/index.js must not save interface configuration');
	}
	if (src.includes('_(\'接口配置\')') || src.includes('_(\"接口配置\")')) {
		fail('view/lanspeed/index.js must not render the interface configuration section');
	}
	if (src.includes('ifcfgCard')) {
		fail('view/lanspeed/index.js must not include the interface configuration card');
	}
	if (src.includes('lsRpc.reload()') || src.includes('btnReload') ||
	    src.includes('重载 daemon') || src.includes('正在重载')) {
		fail('view/lanspeed/index.js must not expose daemon reload controls on the live status page');
	}
	if (src.includes('lsRpc.init(\'lanspeedd\', \'reload\')')) {
		fail('view/lanspeed/index.js must not reload through rc init');
	}
	if (!src.includes('self.error = error')) {
		fail('view/lanspeed/index.js must surface daemon reload errors instead of swallowing them');
	}
}

function assertNoInlineNavigation(src, label) {
	if (src.includes('lanspeed-tabs')) {
		fail(`${label} must rely on LuCI submenu navigation instead of rendering duplicate inline tabs`);
	}
	if (/admin\/status\/lanspeed\/(?:overview|config)/.test(src)) {
		fail(`${label} must not hard-code LAN Speed submenu links inside the view body`);
	}
}

function assertStatusViewNoTrend(src) {
	if (/lanspeed-trend|trendPath|trendSvg|trendLegend|updateTrend|pointLine|SVG_NS/.test(src)) {
		fail('view/lanspeed/index.js must not render the trend chart');
	}
	if (/lsRpc\.overview\s*\(/.test(src)) {
		fail('view/lanspeed/index.js must not poll overview only for the removed trend chart');
	}
}

function assertStatusViewSourceOnlyState(src) {
	if (!src.includes('lanspeed-root')) {
		fail('view/lanspeed/index.js must scope local typography to the LAN Speed status root');
	}
	if (src.includes('.lanspeed-root{font-size:') ||
	    src.includes('.lanspeed-root button,.lanspeed-root input,.lanspeed-root select{font-size:')) {
		fail('view/lanspeed/index.js must not force LAN Speed root or form control text larger than the theme');
	}
	if (!src.includes('grid-template-columns:repeat(5,12.5em)') ||
	    !src.includes('row-gap:1.1em;column-gap:1.2em;align-items:center;justify-content:start;margin:0') ||
	    !src.includes('@media (max-width:1100px){.lanspeed-metrics{grid-template-columns:repeat(auto-fit,minmax(10em,1fr))}}')) {
		fail('view/lanspeed/index.js must keep overview metrics left-aligned with compact spacing on wide Argon layouts');
	}
	if (src.includes('.lanspeed-metric .caption{font-size:.86em') ||
	    src.includes('.lanspeed-metric .big{font-size:1.7em') ||
	    src.includes('.lanspeed-metric .hint{font-size:.86em') ||
	    src.includes('.lanspeed-table .mono{font-family:var(--font-monospace,ui-monospace,monospace);') &&
	    src.includes('font-size:.95em;white-space:nowrap') ||
	    src.includes('.lanspeed-table td .ipline{display:block;font-size:.86em') ||
	    src.includes('.lanspeed-table td .state .label{display:inline-flex') ||
	    src.includes('padding:.18em .5em;font-size:.95em;line-height:1.35') ||
	    src.includes('.lanspeed-warnings li{margin:.2em 0;font-size:1em}')) {
		fail('view/lanspeed/index.js must keep previous compact text sizes');
	}
	if (!src.includes('align-items:baseline') || !src.includes('white-space:nowrap')) {
		fail('view/lanspeed/index.js header metadata must stay aligned with the section title on Argon');
	}
	if (!src.includes('lanspeed-toolbar-left') || !src.includes('lanspeed-toolbar-filter') || !src.includes('lanspeed-toolbar-right')) {
		fail('view/lanspeed/index.js must group toolbar controls for Argon compatibility');
	}
	if (!src.includes('lanspeed-active-only') ||
	    !src.includes('position:relative;top:auto;right:auto;margin:0') ||
	    !src.includes("E('label', { 'class': 'lanspeed-active-only cbi-checkbox', 'for': 'lanspeed-active' }") ||
	    !src.includes("'class': 'cbi-input-checkbox'") ||
	    !src.includes("'class': 'lanspeed-active-label'")) {
		fail('view/lanspeed/index.js must align the active-only checkbox in the toolbar on Argon');
	}
	if (src.includes('appearance:auto') ||
	    src.includes('-webkit-appearance:checkbox')) {
		fail('view/lanspeed/index.js must let Aurora/LuCI theme draw the active-only checkbox');
	}
	if (!src.includes('.lanspeed-clients-card .lanspeed-table{font-weight:500}')) {
		fail('view/lanspeed/index.js must make the LAN client table weight stronger without enlarging it');
	}
	if (src.includes('.lanspeed-clients-card .lanspeed-table{font-size:') ||
	    src.includes('.lanspeed-clients-card .lanspeed-table>thead>tr>th,.lanspeed-clients-card .lanspeed-table>tbody>tr>td') ||
	    src.includes('.lanspeed-table>thead>tr>th,.lanspeed-table>tbody>tr>td{padding-top:.55em')) {
		fail('view/lanspeed/index.js must not enlarge the LAN client table text or row spacing');
	}
	if (!src.includes('collectorLabel') || src.includes("metaParts.push(_('模式 ')")) {
		fail('view/lanspeed/index.js header must show collector source instead of runtime mode');
	}
	if (!src.includes('function collectorClass(mode)')) {
		fail('view/lanspeed/index.js must style the collector source pill without using confidence text');
	}
	if (!src.includes('function effectiveCollector(status, clientsData)') ||
	    !src.includes('evidence.effective_collector') ||
	    !src.includes('clientEvidence.primary_source') ||
	    !src.includes('clientEvidence.collector_mode')) {
		fail('view/lanspeed/index.js must display the daemon-published collector source before rendering the header');
	}
	if (/for\s*\([^)]*clients\.length[\s\S]{0,260}?collector_mode/.test(src) ||
	    /fmt\.asArray\(clientsData && clientsData\.clients\)/.test(src)) {
		fail('view/lanspeed/index.js must not infer the global collector source from client rows');
	}
	if (!src.includes('refs.collectorPill') ||
	    !(src.includes('refs.collectorPill.className = collectorClass(collector)') ||
	      src.includes('refs.collectorPill.className = statusCollector.collectorClass(collector)')) ||
	    !(src.includes('refs.collectorPill.textContent = collectorLabel(collector)') ||
	      src.includes('refs.collectorPill.textContent = statusCollector.collectorLabel(collector)'))) {
		fail('view/lanspeed/index.js header must show the current collector source in the status pill');
	}
	if (src.includes("metaParts.push(_('采集方式 ')")) {
		fail('view/lanspeed/index.js header metadata must not repeat the collector source');
	}
	if (src.includes("status.collector_mode;")) {
		fail('view/lanspeed/index.js header must not show configured collector_mode as the current collector source');
	}
	if (!src.includes('grid-template-columns:repeat(5,12.5em)') ||
	    !src.includes('justify-content:start') ||
	    !src.includes('column-gap:1.2em')) {
		fail('view/lanspeed/index.js overview metrics must be left-aligned with compact desktop spacing');
	}
	if (!src.includes("return 'NSS sync'")) {
		fail('view/lanspeed/index.js must keep NSS sync as a clear collector label');
	}
	if (!src.includes("return 'CT-Netlink'")) {
		fail('view/lanspeed/index.js must keep conntrack netlink as a clear collector label');
	}
	if (/confPill|_\(['"]置信/.test(src)) {
		fail('view/lanspeed/index.js must not render confidence in overview header');
	}
	if (/modeLabel\s*\+\s*['"]·['"]\s*\+\s*vocab\.confidenceText/.test(src)) {
		fail('view/lanspeed/index.js client state must show collector source without confidence suffix');
	}
	if (src.includes('置信度：')) {
		fail('view/lanspeed/index.js client state tooltip must not expose confidence text');
	}
	if (!src.includes("return 'NSS-direct'")) {
		fail('view/lanspeed/index.js must keep existing nss_ecm_direct label');
	}
	if (!src.includes('function isIpv6Address(ip)') ||
	    !src.includes('function parseIpv6ToWords(ip)') ||
	    !src.includes('function parseIpv6Cidr(range)') ||
	    !src.includes('function isIpInIpv6Ranges(ip, ranges)') ||
	    !src.includes('function displayIpsForClient(ips, showIpv6, hidePrivateIpv6, hideIpv6Ranges)')) {
		fail('view/lanspeed/index.js must filter IPv6 display through custom range helpers');
	}
	if (!src.includes("DEFAULT_HIDE_IPV6_RANGES = 'fc00::/7 fe80::/10'") ||
	    !src.includes('hidePrivateIpv6') ||
	    !src.includes('hideIpv6Ranges')) {
		fail('view/lanspeed/index.js must hide configurable IPv6 ranges when the private IPv6 option is enabled');
	}
	if (!src.includes("lsRpc.uciGet('lanspeed', 'main')") ||
	    !src.includes('show_ipv6') ||
	    !src.includes('hide_private_ipv6') ||
	    !src.includes('hide_ipv6_ranges')) {
		fail('view/lanspeed/index.js must read IPv6 display options before rendering client IPs');
	}
	if (!src.includes('function loadUiConfig()') ||
	    !src.includes(".catch(function() { return {}; })")) {
		fail('view/lanspeed/index.js must keep show_ipv6 reads non-fatal');
	}
	if (/\bvar ips = fmt\.asArray\(c\.ips\);/.test(src)) {
		fail('view/lanspeed/index.js must not render raw client IP arrays directly');
	}
}

function assertThemeModule(src) {
	if (!src.includes('function isAurora') ||
	    !src.includes('/luci-static/aurora/') ||
	    !src.includes('LuCI Aurora') ||
	    !src.includes('data-darkmode') ||
	    !src.includes('data-nav-type') ||
	    !src.includes('lanspeed-theme-aurora') ||
	    !src.includes('data-lanspeed-theme') ||
	    !src.includes('applyRoot: function(root')) {
		fail('resources/lanspeed/theme.js must detect Aurora from theme assets and shell markers before applying the scoped class');
	}
	if (!src.includes('function isArgon') ||
	    !src.includes('/luci-static/argon/') ||
	    !src.includes('menu-argon.js') ||
	    !src.includes('.main-left#mainmenu') ||
	    !src.includes('.darkMask') ||
	    !src.includes('lanspeed-theme-argon')) {
		fail('resources/lanspeed/theme.js must detect Argon from theme assets and shell markers before applying the scoped class');
	}
}

function assertThemeWiring(src, label) {
	if (!/^\s*['"]require\s+lanspeed\.theme\s+as\s+lsTheme['"]\s*;/m.test(src)) {
		fail(`${label} must require the LAN Speed theme helper as lsTheme`);
	}
	if (!src.includes('lsTheme.applyRoot(root)')) {
		fail(`${label} must apply detected theme classes to the LAN Speed root`);
	}
}

function assertStatusThemeMetricAlignment(src) {
	if (!src.includes('.lanspeed-theme-aurora .lanspeed-metrics{grid-template-columns:repeat(auto-fit,minmax(11em,12.5em));')) {
		fail('view/lanspeed/index.js must keep Aurora overview metrics left-aligned with fixed-width columns');
	}
	if (!src.includes('.lanspeed-theme-argon .lanspeed-metrics{grid-template-columns:repeat(auto-fit,minmax(10.5em,12.5em));')) {
		fail('view/lanspeed/index.js must keep Argon overview metrics left-aligned with fixed-width columns');
	}
	if (!src.includes('justify-content:start')) {
		fail('view/lanspeed/index.js must keep overview metric grids left-aligned');
	}
}

function assertStatusThemeMobileOverflow(src) {
	if (!src.includes('.lanspeed-theme-argon .lanspeed-details-body{padding:.85rem 1rem;overflow-x:auto}')) {
		fail('view/lanspeed/index.js must keep Argon mobile status tables horizontally scrollable inside clipped theme cards');
	}
}

function assertStatusStyleModule(src) {
	if (!src.includes('CSS: LAYOUT_CSS') ||
	    !src.includes('.lanspeed-theme-aurora ') ||
	    !src.includes('.lanspeed-theme-argon ') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-metrics{grid-template-columns:repeat(auto-fit,minmax(10.5em,12.5em));') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-details-body{padding:.85rem 1rem;overflow-x:auto}')) {
		fail('lanspeed/statusStyle.js must own status view CSS, including Aurora/Argon theme rules');
	}
	if (!src.includes('.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-body{overflow-x:auto}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-body{overflow-x:auto}')) {
		fail('lanspeed/statusStyle.js must keep client tables scrollable above the narrow stacked breakpoint');
	}
	if (!src.includes('.lanspeed-toolbar{display:flex;flex-wrap:wrap;gap:.7em 1em;') ||
	    !src.includes('.lanspeed-toolbar-left{display:grid;grid-template-columns:auto minmax(14em,1fr);') ||
	    !src.includes('flex:1 1 36em;gap:.5em;align-items:center;min-width:0') ||
	    !src.includes('.lanspeed-toolbar-right{flex:0 0 auto;justify-content:flex-end;margin-left:auto;white-space:nowrap}') ||
	    !src.includes('.lanspeed-toolbar .lanspeed-unit-control select{width:7.5em!important;') ||
	    !src.includes('.lanspeed-toolbar .lanspeed-refresh-control select{width:6.5em!important;') ||
	    !src.includes('@media (max-width:600px){.lanspeed-toolbar-left{grid-template-columns:1fr;flex-basis:100%}')) {
		fail('lanspeed/statusStyle.js must wrap toolbar groups before controls overlap');
	}
	if (!src.includes('.lanspeed-sort-button{appearance:none;background:transparent!important;border:0!important;') ||
	    !src.includes('.lanspeed-sort-button:focus-visible') ||
	    !src.includes('.lanspeed-sort-indicator{')) {
		fail('lanspeed/statusStyle.js must render accessible sortable headers without theme button chrome');
	}
	if (!src.includes('@media (max-width:700px){.lanspeed-clients-card .lanspeed-body{overflow-x:hidden}') ||
	    !src.includes('grid-template-columns:repeat(6,minmax(0,1fr));gap:.25em;') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table tbody>tr{display:grid;') ||
	    !src.includes('grid-template-columns:repeat(2,minmax(0,1fr));gap:.7em 1em;') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table td[data-label]::before{content:attr(data-label);') ||
	    !src.includes('@media (min-width:701px) and (max-width:900px){') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table{table-layout:fixed;min-width:0}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table th:nth-child(7),.lanspeed-clients-card .lanspeed-table td:nth-child(7){width:16%}') ||
	    !src.includes('@media (max-width:480px){.lanspeed-clients-card .lanspeed-table thead>tr{') ||
	    !src.includes('grid-template-columns:repeat(3,minmax(0,1fr));row-gap:.35em}') ||
	    !src.includes('.lanspeed-theme-aurora .lanspeed-toolbar input[type=search]{min-width:0;width:100%;max-width:none}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-toolbar input[type=search]{min-width:0;width:100%;max-width:none}')) {
		fail('lanspeed/statusStyle.js must stack client data without horizontal scrolling on narrow screens');
	}
	if (src.includes('.lanspeed-clients-card .lanspeed-table thead{display:none}')) {
		fail('lanspeed/statusStyle.js must keep direct header sorting available on narrow screens');
	}
	if (!src.includes('.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table td:nth-child(2).mono{font-size:.95rem}')) {
		fail('lanspeed/statusStyle.js must keep Aurora client MAC text readable without changing other themes');
	}
	if (!src.includes('@media (min-width:901px){.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table{table-layout:fixed}') ||
	    !src.includes('.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table th:nth-child(1),.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table td:nth-child(1){width:18rem}')) {
		fail('lanspeed/statusStyle.js must keep Aurora client and MAC columns close on desktop');
	}
	if (!src.includes('.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table th:nth-child(2),.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table td:nth-child(2){width:15rem}')) {
		fail('lanspeed/statusStyle.js must keep Aurora MAC and upload columns comfortably spaced on desktop');
	}
	if (!src.includes('.lanspeed-theme-argon{display:flex;flex-direction:column;gap:1rem;margin:0;font-size:1rem}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-table th,.lanspeed-theme-argon .lanspeed-table td{padding:.65rem .75rem;font-size:1rem;line-height:1.45}')) {
		fail('lanspeed/statusStyle.js must enlarge Argon status page typography without changing other themes');
	}
	if (!src.includes('.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table td:nth-child(2).mono{font-size:.96rem}')) {
		fail('lanspeed/statusStyle.js must keep Argon client MAC text readable without changing other themes');
	}
	if (!src.includes('@media (min-width:901px){.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table{table-layout:fixed}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table th:nth-child(1),.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table td:nth-child(1){width:17rem}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table th:nth-child(2),.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table td:nth-child(2){width:14.5rem}')) {
		fail('lanspeed/statusStyle.js must keep Argon client, MAC and upload columns balanced on desktop');
	}
	if (!src.includes('.lanspeed-theme-argon .lanspeed-table th:first-child,.lanspeed-theme-argon .lanspeed-table td:first-child{padding-left:.35rem}')) {
		fail('lanspeed/statusStyle.js must keep Argon status table text away from the card edge');
	}
	if (!src.includes('.lanspeed-theme-argon .lanspeed-caps{grid-template-columns:repeat(4,12.95rem);max-width:56rem;justify-content:start;align-items:center;gap:.5rem 1rem;margin:.2rem 0 1rem 1.25rem}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-caps .cap{display:grid;grid-template-columns:minmax(0,9.65rem) 2.55rem;') ||
	    !src.includes('  align-items:center;column-gap:.45rem;min-width:0;padding:.18rem 0}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-caps .cap>span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-caps .cap>span:last-child{justify-self:start;min-width:2.25rem;text-align:center}') ||
	    !src.includes('@media (max-width:700px){.lanspeed-theme-argon .lanspeed-caps{grid-template-columns:1fr;max-width:none}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-caps .cap{grid-template-columns:minmax(0,9.65rem) 2.55rem;max-width:12.95rem}}')) {
		fail('lanspeed/statusStyle.js must align Argon capability badges with fixed label/pill slots');
	}
}

function assertStatusStyleCompatModule(src) {
	if (!src.includes('lanspeed-style-argon-caps-compat') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-caps{grid-template-columns:repeat(4,12.95rem);max-width:56rem;justify-content:start;align-items:center;gap:.5rem 1rem;margin:.2rem 0 1rem 1.25rem}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-caps .cap{display:grid;grid-template-columns:minmax(0,9.65rem) 2.55rem;') ||
	    !src.includes('@media (max-width:700px){.lanspeed-theme-argon .lanspeed-caps{grid-template-columns:1fr;max-width:none}') ||
	    !src.includes('install: install')) {
		fail('lanspeed/statusStyleCompatLive.js must install the Argon capability-grid override from a fresh module path');
	}
}

function assertStatusIpModule(src) {
	if (!src.includes('DEFAULT_HIDE_IPV6_RANGES') ||
	    !src.includes('displayIpsForClient: function(') ||
	    !src.includes('hideIpv6RangesValue: function(') ||
	    !src.includes('parseIpv6Cidr')) {
		fail('lanspeed/statusIp.js must own status view IPv6 filtering helpers');
	}
}

function assertStatusCollectorModule(src) {
	if (!src.includes('collectorLabel: function(') ||
	    !src.includes('collectorClass: function(') ||
	    !src.includes('effectiveCollector: function(')) {
		fail('lanspeed/statusCollector.js must own collector label/class/effective-mode helpers');
	}
}

function assertStatusShellModule(src) {
	if (!src.includes('buildShell: function(viewState)') ||
	    !src.includes('statusStyle.CSS') ||
	    !src.includes('lsTheme.applyRoot(root)') ||
	    !src.includes('nssPanel.build(refs)')) {
		fail('lanspeed/statusShell.js must own status page DOM shell construction');
	}
	if (!/refs\.diagnostics\s*=\s*E\('details',\s*\{\s*'class':\s*'lanspeed-details'\s*\}/.test(src) ||
	    /refs\.diagnostics\s*=\s*E\('details',[\s\S]{0,120}['"]open['"]/.test(src)) {
		fail('lanspeed/statusShell.js must leave diagnostics collapsed by default');
	}
	const sortableKeys = [ 'hostname', 'mac', 'tx', 'rx', 'tcp_conns', 'udp_conns' ];
	if (!src.includes('function sortableHeader(viewState, refs, sortKey, label, attrs)') ||
	    sortableKeys.some(function(key) { return !src.includes(`sortableHeader(viewState, refs, '${key}'`); })) {
		fail('lanspeed/statusShell.js must sort directly from all six requested client table headers');
	}
	if (src.includes('refs.sortSel') || src.includes("_('排序')")) {
		fail('lanspeed/statusShell.js must not render a separate sorting control');
	}
	if (!src.includes("E('div', { 'class': 'lanspeed-toolbar-left' }") ||
	    !src.includes("E('div', { 'class': 'lanspeed-toolbar-right' }") ||
	    !src.includes("E('label', { 'class': 'lanspeed-unit-control' }, [ _('单位'), refs.unitSel ])") ||
	    !src.includes("E('label', { 'class': 'lanspeed-refresh-control' }, [ _('刷新'), refs.intervalSel ])")) {
		fail('lanspeed/statusShell.js must place unit/filter controls left and refresh controls right');
	}
}

function assertStatusRefreshModule(src) {
	if (!src.includes('refreshLive: function(viewState)') ||
	    !src.includes('statusIp.displayIpsForClient') ||
	    !src.includes('statusCollector.collectorLabel') ||
	    !src.includes('lsVersion.FULL_VERSION') ||
	    !src.includes('nssPanel.render(refs, status)')) {
		fail('lanspeed/statusRefresh.js must own status page live refresh rendering');
	}
	if (!src.includes('fmt.sortClients(filtered, prefs.sortKey, prefs.sortDir)') ||
	    !src.includes('var active = prefs.sortCustom && prefs.sortKey === sortKey;') ||
	    !src.includes("setAttribute('aria-sort'") ||
	    !src.includes("ascending ? '↑' : '↓'")) {
		fail('lanspeed/statusRefresh.js must only render arrows for an explicit client sort');
	}
	if (!src.includes("'class': 'lanspeed-client-name'") ||
	    !src.includes("'class': 'mono lanspeed-client-mac'") ||
	    !src.includes("'class': 'num lanspeed-client-value'") ||
	    !src.includes("'class': 'lanspeed-client-state-cell'") ||
	    !src.includes("'data-label': _('上行')") ||
	    !src.includes("'data-label': _('下行')") ||
	    !src.includes("'data-label': _('状态')")) {
		fail('lanspeed/statusRefresh.js must label client fields for the narrow stacked layout');
	}
}

function assertConfigStyleModule(src) {
	if (!src.includes('CSS: CONFIG_CSS') ||
	    !src.includes('.lanspeed-theme-aurora ') ||
	    !src.includes('.lanspeed-theme-argon ') ||
	    !src.includes('.lanspeed-config-table')) {
		fail('lanspeed/configStyle.js must own config view CSS, including Aurora/Argon theme rules');
	}
	if (!src.includes('.lanspeed-theme-aurora .lanspeed-ifcfg-body{overflow-x:auto}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-ifcfg-body{overflow-x:auto}')) {
		fail('lanspeed/configStyle.js must keep mobile interface tables horizontally scrollable inside Aurora/Argon cards');
	}
	if (!src.includes('.lanspeed-theme-aurora .lanspeed-config-table td:nth-child(2){width:18rem}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-config-table td:nth-child(2){width:18rem}')) {
		fail('lanspeed/configStyle.js must size the runtime settings value column after hiding the UCI column');
	}
	if (src.includes('.lanspeed-theme-aurora .lanspeed-config-table td:nth-child(3){width:18rem}') ||
	    src.includes('.lanspeed-theme-argon .lanspeed-config-table td:nth-child(3){width:18rem}')) {
		fail('lanspeed/configStyle.js must not keep the old fourth-column width rule after hiding the UCI column');
	}
	if (!src.includes('@media (min-width:801px){') ||
	    !src.includes('grid-template-areas:"label control" "hint control"') ||
	    !src.includes('.lanspeed-theme-aurora .lanspeed-config-table tbody tr,.lanspeed-theme-argon .lanspeed-config-table tbody tr{display:grid;')) {
		fail('lanspeed/configStyle.js must compact runtime settings into a desktop two-column theme layout');
	}
	if (!src.includes('.lanspeed-theme-aurora .lanspeed-range-add button,.lanspeed-theme-argon .lanspeed-range-add button{min-width:4rem;height:2.25rem}')) {
		fail('lanspeed/configStyle.js must keep IPv6 range add controls compact in themed config layouts');
	}
	if (!src.includes('.lanspeed-theme-argon{display:flex;flex-direction:column;gap:1rem;margin:0;font-size:1rem}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-config-table th,.lanspeed-theme-argon .lanspeed-config-table td,.lanspeed-theme-argon .lanspeed-ifcfg-table th,.lanspeed-theme-argon .lanspeed-ifcfg-table td{padding:.68rem .75rem;font-size:1rem;line-height:1.45}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-config-table .hint,.lanspeed-theme-argon .lanspeed-ifcfg-table .muted{font-size:.88rem;line-height:1.45}')) {
		fail('lanspeed/configStyle.js must enlarge Argon config page typography without changing other themes');
	}
	if (!src.includes('.lanspeed-theme-argon .lanspeed-config-table th:first-child,.lanspeed-theme-argon .lanspeed-config-table td:first-child,.lanspeed-theme-argon .lanspeed-ifcfg-table th:first-child,.lanspeed-theme-argon .lanspeed-ifcfg-table td:first-child{padding-left:.35rem}')) {
		fail('lanspeed/configStyle.js must keep Argon config table text away from the card edge');
	}
	if (!src.includes('@media (min-width:801px){.lanspeed-theme-argon .lanspeed-ifcfg-table{table-layout:fixed}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-ifcfg-table th:nth-child(1),.lanspeed-theme-argon .lanspeed-ifcfg-table td:nth-child(1){width:16rem}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-ifcfg-table th:nth-child(3),.lanspeed-theme-argon .lanspeed-ifcfg-table td:nth-child(3){width:21rem}')) {
		fail('lanspeed/configStyle.js must keep Argon interface configuration columns compact on desktop');
	}
}

function assertConfigFormModule(src) {
	if (!src.includes('DEFAULTS: DEFAULTS') ||
	    !src.includes('loadValues: function()') ||
	    !src.includes('buildDaemonSection: function(values, viewState)') ||
	    !src.includes('buildSaveSection: function(viewState)') ||
	    !src.includes('saveAll: function(viewState)') ||
	    !src.includes('applyRuntimeInfo(refs, values.status || {})')) {
		fail('lanspeed/configForm.js must own config defaults, rendering and the shared save flow');
	}
	if (src.includes("E('span', { 'class': 'sum' }, _('UCI'))")) {
		fail('lanspeed/configForm.js must not show a redundant UCI badge in the runtime settings header');
	}
	if (src.includes("E('th', {}, _('UCI'))")) {
		fail('lanspeed/configForm.js must not show a UCI column in the runtime settings table');
	}
	[
		'rate_collector_mode',
		'conn_collector_mode',
		'active_client_window_ms',
		'active_client_min_bps',
		'show_ipv6',
		'hide_private_ipv6',
		'hide_ipv6_ranges'
	].forEach(function(name) {
		if (src.includes("E('td', { 'class': 'key' }, '" + name + "')")) {
			fail('lanspeed/configForm.js must not show UCI option names in the runtime settings table');
		}
	});
}

function assertStatusViewEntryIsThin(src) {
	if (src.includes('var LAYOUT_CSS = [') || src.includes('function buildShell(') ||
	    src.includes('function refreshLive(') || src.includes('function parseIpv6ToWords(')) {
		fail('view/lanspeed/index.js must stay a thin page lifecycle entry and delegate CSS/shell/refresh/IP helpers to modules');
	}
	if (!src.includes('statusShell.buildShell(viewState)') ||
	    !src.includes('statusRefresh.refreshLive(this)') ||
	    !src.includes('statusIp.hideIpv6RangesValue')) {
		fail('view/lanspeed/index.js must delegate shell, refresh, and IPv6 helper work to status modules');
	}
}

function assertConfigViewEntryIsThin(src) {
	if (src.includes('var CONFIG_CSS = [') || src.includes('function buildDaemonSection(') ||
	    src.includes('function saveDaemonSettings(') || src.includes('var DEFAULTS = {')) {
		fail('view/lanspeed/config.js must stay a thin page lifecycle entry and delegate CSS/form logic to modules');
	}
	if (!src.includes('configStyle.CSS') ||
	    !src.includes('configForm.loadValues()') ||
	    !src.includes('configForm.buildDaemonSection(values || configForm.DEFAULTS, viewState)') ||
	    !src.includes('configForm.buildSaveSection(viewState)')) {
		fail('view/lanspeed/config.js must delegate CSS, loading, and form rendering to config modules');
	}
}

function assertVersionModule(src) {
	const daemonVersion = readMakeVar(daemonMakefile, 'PKG_VERSION', 'net/lanspeedd/Makefile');
	const daemonRelease = readMakeVar(daemonMakefile, 'PKG_RELEASE', 'net/lanspeedd/Makefile');
	const luciVersion = readMakeVar(luciMakefile, 'PKG_VERSION', 'applications/luci-app-lanspeed/Makefile');
	const luciRelease = readMakeVar(luciMakefile, 'PKG_RELEASE', 'applications/luci-app-lanspeed/Makefile');

	if (daemonVersion !== luciVersion) {
		fail('daemon and LuCI PKG_VERSION must match');
	}
	if (daemonRelease !== luciRelease) {
		fail('daemon and LuCI PKG_RELEASE must match');
	}
	if (!src.includes(`PACKAGE_VERSION: '${luciVersion}'`)) {
		fail('version.js must expose luci-app-lanspeed PACKAGE_VERSION');
	}
	if (!src.includes(`PACKAGE_RELEASE: '${luciRelease}'`)) {
		fail('version.js must expose luci-app-lanspeed PACKAGE_RELEASE');
	}
	if (!src.includes(`FULL_VERSION: '${luciVersion}-r${luciRelease}'`)) {
		fail('version.js must expose full luci-app-lanspeed version with r suffix');
	}
}

/* ---------- run ---------- */

if (!fs.existsSync(modDir)) {
	fail('resources/lanspeed/ directory missing');
}
if (!assertFileExists(viewFile, 'view entry')) {
	/* keep going, other checks still useful */
}
assertFileExists(legacyViewFile, 'legacy view wrapper');
assertFileExists(configViewFile, 'config view entry');
assertFileExists(statusViewFile, 'status view module');

EXPECTED_MODULES.forEach(function(name) {
	const p = path.join(modDir, name);
	if (!assertFileExists(p, `module ${name}`)) return;
	const src = readModule(p);
	const cleaned = stripComments(src);
	assertStrict(src, `resources/lanspeed/${name}`);
	assertRequire(src, `resources/lanspeed/${name}`, MODULE_REQUIRES[name]);
	assertBaseclassExtend(cleaned, `resources/lanspeed/${name}`);
	assertSyntax(src, `resources/lanspeed/${name}`);
		if (name === 'format.js') {
			assertFormatActiveWindow(src);
			assertFormatSorting(src);
		}
	if (name === 'ifaceConfig.js') {
		assertIfaceConfigThemeLayout(src);
	}
	if (name === 'nssPanel.js') {
		assertNssPanelSource(src);
	}
	if (name === 'theme.js') {
		assertThemeModule(src);
	}
	if (name === 'version.js') {
		assertVersionModule(src);
	}
	if (name === 'statusStyle.js') {
		assertStatusStyleModule(src);
	}
	if (name === 'statusStyleCompatLive.js' || name === 'statusStyleCompatLive2.js' || name === 'statusStyleCompatLive3.js') {
		assertStatusStyleCompatModule(src);
	}
	if (name === 'statusViewLive.js') {
		assertStatusViewEntryIsThin(src);
	}
	if (name === 'statusIp.js') {
		assertStatusIpModule(src);
	}
	if (name === 'statusCollector.js') {
		assertStatusCollectorModule(src);
	}
		if (name === 'statusShell.js') {
			assertStatusShellModule(src);
			assertStatusShellInteraction(src);
		}
	if (name === 'statusRefresh.js') {
		assertStatusRefreshModule(src);
	}
	if (name === 'configStyle.js') {
		assertConfigStyleModule(src);
	}
	if (name === 'configForm.js') {
		assertConfigFormModule(src);
	}
});

RPC_FREE_MODULES.forEach(function(name) {
	const p = path.join(modDir, name);
	if (!fs.existsSync(p)) return;
	const cleaned = stripComments(readModule(p));
	assertNoRpcDeclare(cleaned, `resources/lanspeed/${name}`);
});

if (fs.existsSync(viewFile)) {
	const vsrc = readModule(viewFile);
	const vcleaned = stripComments(vsrc);
	assertStrict(vsrc, 'view/lanspeed/index_live4.js');
	assertStatusViewWrapper(vsrc, 'view/lanspeed/index_live4.js');
	assertSyntax(vsrc, 'view/lanspeed/index_live4.js');
	assertNoRpcDeclare(vcleaned, 'view/lanspeed/index_live4.js');
}

if (fs.existsSync(legacyViewFile)) {
	const lsrc = readModule(legacyViewFile);
	const lcleaned = stripComments(lsrc);
	assertStrict(lsrc, 'view/lanspeed/index.js');
	assertStatusViewWrapper(lsrc, 'view/lanspeed/index.js');
	assertSyntax(lsrc, 'view/lanspeed/index.js');
	assertNoRpcDeclare(lcleaned, 'view/lanspeed/index.js');
}

if (fs.existsSync(statusViewFile)) {
	const vsrc = readModule(statusViewFile);
	const vcleaned = stripComments(vsrc);
	const statusSrc = [
		vsrc,
		readModuleByName('statusStyle.js'),
		readModuleByName('statusStyleCompatLive.js'),
		readModuleByName('statusStyleCompatLive2.js'),
		readModuleByName('statusStyleCompatLive3.js'),
		readModuleByName('statusIp.js'),
		readModuleByName('statusCollector.js'),
		readModuleByName('statusShell.js'),
		readModuleByName('statusRefresh.js')
	].join('\n');
	assertStatusViewNoInterfaceConfig(statusSrc);
	assertNoInlineNavigation(statusSrc, 'lanspeed/statusViewLive.js');
	assertStatusViewNoTrend(statusSrc);
	assertStatusViewSourceOnlyState(statusSrc);
	/* View should no longer declare rpc; it goes through lsRpc */
	assertNoRpcDeclare(vcleaned, 'lanspeed/statusViewLive.js');
}

if (fs.existsSync(configViewFile)) {
	const csrc = readModule(configViewFile);
	const ccleaned = stripComments(csrc);
		const configSrc = [
			csrc,
			readModuleByName('configStyle.js'),
			readModuleByName('configForm.js'),
			readModuleByName('ifaceConfig.js')
		].join('\n');
	assertStrict(csrc, 'view/lanspeed/config.js');
	assertConfigViewRequires(csrc);
	assertThemeWiring(csrc, 'view/lanspeed/config.js');
	assertConfigViewEntryIsThin(csrc);
	assertConfigView(configSrc);
	assertNoInlineNavigation(configSrc, 'view/lanspeed/config.js');
	assertSyntax(csrc, 'view/lanspeed/config.js');
	assertNoRpcDeclare(ccleaned, 'view/lanspeed/config.js');
}

if (errors.length) {
	console.error('validate-lanspeed-modules: FAIL');
	errors.forEach(function(e) { console.error('  - ' + e); });
	process.exit(1);
}

console.log('validate-lanspeed-modules: PASS');
console.log(`  modules checked: ${EXPECTED_MODULES.length} (${EXPECTED_MODULES.join(', ')})`);
console.log(`  view entry: ${path.relative(root, viewFile)}`);
console.log(`  status view: ${path.relative(root, statusViewFile)}`);
