#!/usr/bin/env node

/*
 * Validates the modular structure of luci-app-lanspeed's resources tree.
 *
 * Contract enforced:
 *   1. Every expected sub-module file exists under
 *      applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/
 *      and the view entry under resources/view/lanspeed/index.js.
 *   2. Each sub-module begins with 'use strict' and declares the expected
 *      'require baseclass' (plus 'require rpc' for rpc.js). NSS panel
 *      additionally requires vocab + format.
 *   3. Each sub-module ends its body with `return baseclass.extend({...})`
 *      so LuCI's module loader receives a class.
 *   4. The status and config view entries declare their expected sub-module
 *      requires at the top of the file.
 *   5. Boundary hygiene: rpc.declare must only appear in rpc.js. The
 *      vocab/format/nssPanel modules must stay free of RPC declarations.
 *   6. Every *.js file under resources/lanspeed/ and the view entry parses
 *      as JavaScript (acorn-free: we use VM compile to catch syntax errors).
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
const viewFile = path.join(resDir, 'view/lanspeed/index.js');
const configViewFile = path.join(resDir, 'view/lanspeed/config.js');

const EXPECTED_MODULES = [
	'vocab.js',
	'format.js',
	'rpc.js',
	'ifaceConfig.js',
	'nssPanel.js',
	'version.js'
];

const EXPECTED_VIEW_REQUIRES = [
	'lanspeed.vocab',
	'lanspeed.format',
	'lanspeed.rpc',
	'lanspeed.version',
	'lanspeed.nssPanel'
];

const EXPECTED_CONFIG_VIEW_REQUIRES = [
	'form',
	'lanspeed.rpc',
	'lanspeed.ifaceConfig'
];

const MODULE_REQUIRES = {
	'vocab.js':       [ 'baseclass' ],
	'format.js':      [ 'baseclass' ],
	'rpc.js':         [ 'baseclass', 'rpc' ],
	'ifaceConfig.js': [ 'baseclass', 'lanspeed.format', 'lanspeed.rpc' ],
	'nssPanel.js':    [ 'baseclass', 'lanspeed.vocab', 'lanspeed.format' ],
	'version.js':     [ 'baseclass' ]
};

/* Modules that MUST NOT contain `rpc.declare`. rpc.js is the only file
 * allowed to declare rpc handles. */
const RPC_FREE_MODULES = [ 'vocab.js', 'format.js', 'nssPanel.js' ];

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

function assertNoRpcDeclare(src, modName) {
	if (/\brpc\s*\.\s*declare\s*\(/.test(src)) {
		fail(`${modName} must not contain rpc.declare (belongs in rpc.js)`);
	}
}

function assertViewRequires(src) {
	EXPECTED_VIEW_REQUIRES.forEach(function(req) {
		const re = new RegExp("^\\s*['\"]require\\s+" + req.replace(/\./g, '\\.') + "\\s+as\\s+\\w+['\"]\\s*;", 'm');
		if (!re.test(src)) {
			fail(`view/index.js must declare 'require ${req} as <alias>'`);
		}
	});
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
	if (!src.includes('conntrack_netlink') || !src.includes('conntrack_procfs')) {
		fail('view/lanspeed/config.js must offer CT-Netlink and CT-Procfs connection collector choices');
	}
	if (!src.includes('速率采集') || !src.includes('连接数采集')) {
		fail('view/lanspeed/config.js must split speed and connection collector settings');
	}
	if (!src.includes('非 NSS 实时测速只使用 BPF') || !src.includes('CT 只影响连接数和诊断')) {
		fail('view/lanspeed/config.js must make the non-NSS BPF-only live-rate policy explicit');
	}
	if (!src.includes('ifaceCfg.load(viewState)')) {
		fail('view/lanspeed/config.js must reuse ifaceConfig for interface assignments');
	}
	if (!src.includes('lsRpc.init(\'lanspeedd\', \'reload\')')) {
		fail('view/lanspeed/config.js must reload lanspeedd after saving daemon settings');
	}
	if (src.includes('overview_window_samples') || src.includes('趋势采样点')) {
		fail('view/lanspeed/config.js must not expose trend sampling after the trend chart is removed');
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

function assertVersionModule(src) {
	if (!src.includes("PACKAGE_VERSION: '0.1.1'")) {
		fail('version.js must expose luci-app-lanspeed PACKAGE_VERSION');
	}
	if (!src.includes("PACKAGE_RELEASE: '6'")) {
		fail('version.js must expose luci-app-lanspeed PACKAGE_RELEASE');
	}
	if (!src.includes("FULL_VERSION: '0.1.1-r6'")) {
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
assertFileExists(configViewFile, 'config view entry');

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
	}
	if (name === 'version.js') {
		assertVersionModule(src);
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
	assertStrict(vsrc, 'view/lanspeed/index.js');
	assertViewRequires(vsrc);
	if (!vsrc.includes('lsVersion.FULL_VERSION')) {
		fail('view/lanspeed/index.js must render luci-app-lanspeed full package version');
	}
	assertStatusViewNoInterfaceConfig(vsrc);
	assertNoInlineNavigation(vsrc, 'view/lanspeed/index.js');
	assertStatusViewNoTrend(vsrc);
	assertSyntax(vsrc, 'view/lanspeed/index.js');
	/* View should no longer declare rpc; it goes through lsRpc */
	assertNoRpcDeclare(vcleaned, 'view/lanspeed/index.js');
}

if (fs.existsSync(configViewFile)) {
	const csrc = readModule(configViewFile);
	const ccleaned = stripComments(csrc);
	assertStrict(csrc, 'view/lanspeed/config.js');
	assertConfigViewRequires(csrc);
	assertConfigView(csrc);
	assertNoInlineNavigation(csrc, 'view/lanspeed/config.js');
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
