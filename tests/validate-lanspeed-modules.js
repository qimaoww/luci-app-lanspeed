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

function assertNssPanelSource(src) {
	if (!src.includes('function hasNssSignal(status)') ||
	    !src.includes('function isNssAccelerated(status)')) {
		fail('lanspeed/nssPanel.js must keep NSS panel signal helpers');
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
	if (!src.includes('function daedRuntimeActive(') ||
	    !src.includes('dae.dae_running') ||
	    !src.includes('dae.daed_running')) {
		fail('view/lanspeed/config.js must distinguish running daed from installed daed config');
	}
	if (src.includes('dae.dae0 || dae.dae0peer') ||
	    src.includes('dae.dae_service || dae.daed_service') ||
	    src.includes('dae.runtime_active')) {
		fail('view/lanspeed/config.js must not treat stopped daed service or leftover dae0 as runtime-active daed');
	}
	if (!src.includes('lanspeed-nss-config-only')) {
		fail('view/lanspeed/config.js must render NSS-only configuration guidance separately');
	}
	if (!src.includes('lanspeed-nss-config-only') ||
	    !src.includes('NSS-direct') ||
	    !src.includes('NSS sync')) {
		fail('view/lanspeed/config.js must explain NSS direct and NSS sync only on NSS devices');
	}
	if (!src.includes('function rateCollectorModesForStatus(') ||
	    !src.includes("[ 'nss_ecm_direct', 'NSS-direct' ]") ||
	    !src.includes("[ 'nss_conntrack_sync', 'NSS sync' ]") ||
	    !src.includes('lanspeed-rate-badge')) {
		fail('view/lanspeed/config.js must show NSS-aware rate_collector_mode labels on NSS devices');
	}
	if (!src.includes('function rateCollectorModesForStatus(status, currentValue)') ||
	    !src.includes("currentValue === 'nss_ecm_direct'") ||
	    !src.includes("currentValue === 'nss_conntrack_sync'")) {
		fail('view/lanspeed/config.js must preserve saved NSS rate_collector_mode values even when runtime NSS detection is unavailable');
	}
	if (!src.includes('当前采集方式') || !src.includes('nssRateHint(status)')) {
		fail('view/lanspeed/config.js must keep NSS explanations in hint rows instead of option labels');
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
	if (!src.includes('daed 运行中') || !src.includes('BPF')) {
		fail('view/lanspeed/config.js must explain the NSS+daed BPF preference');
	}
	if (!src.includes('if (refs.nssRows)')) {
		fail('view/lanspeed/config.js must hide NSS-only rows on non-NSS devices');
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
	if (src.includes('border-radius:1.35em') ||
	    src.includes('box-shadow:0 .1em .45em')) {
		fail('view/lanspeed/config.js hidden IPv6 range boxes must match the normal input style, not pill styling');
	}
	if (!src.includes('border-radius:.4em') ||
	    !src.includes('box-shadow:none')) {
		fail('view/lanspeed/config.js hidden IPv6 range boxes must keep the same rectangular frame style as nearby form controls');
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
	if (!src.includes('lsRpc.init(\'lanspeedd\', \'reload\')')) {
		fail('view/lanspeed/config.js must reload lanspeedd after saving daemon settings');
	}
	if (src.includes('overview_window_samples') || src.includes('趋势采样点')) {
		fail('view/lanspeed/config.js must not expose trend sampling after the trend chart is removed');
	}
}

function assertIfaceConfigThemeLayout(src) {
	if (!src.includes('lanspeed-ifcfg-body')) {
		fail('resources/lanspeed/ifaceConfig.js must wrap the interface table in a padded body for theme compatibility');
	}
	if (src.includes('置信度 high')) {
		fail('resources/lanspeed/ifaceConfig.js must not show confidence wording in interface config tooltips');
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
	if (!src.includes('lanspeed-toolbar-left') || !src.includes('lanspeed-toolbar-filter') || !src.includes('lanspeed-toolbar-options')) {
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
	    !src.includes('refs.collectorPill.className = collectorClass(collector)') ||
	    !src.includes('refs.collectorPill.textContent = collectorLabel(collector)')) {
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

function assertVersionModule(src) {
	if (!src.includes("PACKAGE_VERSION: '0.1.5'")) {
		fail('version.js must expose luci-app-lanspeed PACKAGE_VERSION');
	}
	if (!src.includes("PACKAGE_RELEASE: '1'")) {
		fail('version.js must expose luci-app-lanspeed PACKAGE_RELEASE');
	}
	if (!src.includes("FULL_VERSION: '0.1.5-r1'")) {
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
	if (name === 'ifaceConfig.js') {
		assertIfaceConfigThemeLayout(src);
	}
	if (name === 'nssPanel.js') {
		assertNssPanelSource(src);
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
	assertStatusViewSourceOnlyState(vsrc);
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
