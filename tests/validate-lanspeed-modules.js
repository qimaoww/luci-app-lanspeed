#!/usr/bin/env node
/*
 * Validates the modular structure of luci-app-lanspeed's resources tree.
 *
 * Contract enforced:
 *   1. Every expected sub-module file exists under
 *      applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/
 *      and the active view entries under resources/view/lanspeed/.
 *   2. Each sub-module begins with 'use strict' and declares the expected
 *      'require baseclass' (plus 'require rpc' for rpc.js).
 *      additionally requires vocab + format.
 *   3. Each sub-module ends its body with `return baseclass.extend({...})`
 *      so LuCI's module loader receives a class.
 *   4. The status implementation module and config view entry declare their
 *      expected sub-module requires at the top of the file.
 *   5. Boundary hygiene: rpc.declare must only appear in rpc.js. The
 *      shared UI helper modules must stay free of RPC declarations.
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
const crypto = require('crypto');

const root = path.resolve(__dirname, '..');
const resDir = path.join(root,
	'applications/luci-app-lanspeed/htdocs/luci-static/resources');
const modDir = path.join(resDir, 'lanspeed');
const viewDir = path.join(resDir, 'view/lanspeed');
const viewFile = path.join(resDir, 'view/lanspeed/overview.js');
const diagnosticsEntryFile = path.join(resDir, 'view/lanspeed/diagnostics.js');
const configViewFile = path.join(resDir, 'view/lanspeed/config.js');
const statusViewFile = path.join(modDir, 'statusView.js');
const daemonMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const luciMakefile = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/Makefile'), 'utf8');

const EXPECTED_MODULES = [
	'vocab.js',
	'format.js',
	'geoLocation.js',
	'clientConnections.js',
	'clientDetailRefresh.js',
	'clientDetailShell.js',
	'clientDetailView.js',
	'clientDetailStyle.js',
	'clientDetailStyleBase.js',
	'clientDetailStyleAurora.js',
	'clientDetailStyleArgon.js',
	'clientDetailStyleBootstrap.js',
	'clientDetailStyleResponsive.js',
	'diagnosticsRefresh.js',
	'diagnosticsShell.js',
	'diagnosticsStyle.js',
	'diagnosticsStyleBase.js',
	'diagnosticsStyleAurora.js',
	'diagnosticsStyleArgon.js',
	'diagnosticsStyleBootstrap.js',
	'diagnosticsStyleResponsive.js',
	'diagnosticsView.js',
	'rpc.js',
	'ifaceConfig.js',
	'theme.js',
	'version.js',
	'statusStyle.js',
	'statusStyleBase.js',
	'statusStyleAurora.js',
	'statusStyleArgon.js',
	'statusStyleBootstrap.js',
	'statusStyleResponsive.js',
	'statusView.js',
	'statusIp.js',
	'statusCollector.js',
	'statusOverview.js',
	'statusShell.js',
	'statusRefresh.js',
	'configStyle.js',
	'configStyleBase.js',
	'configStyleAurora.js',
	'configStyleArgon.js',
	'configStyleBootstrap.js',
	'configStyleShared.js',
	'configStyleResponsive.js',
	'configForm.js'
];
const EXPECTED_VIEW_ENTRIES = [ 'config.js', 'diagnostics.js', 'overview.js' ];
const VERSIONED_RESOURCE_TOKEN = /(?:Live\d+|_live\d+)/;

const EXPECTED_VIEW_REQUIRES = [
	'lanspeed.clientConnections',
	'lanspeed.clientDetailView',
	'lanspeed.statusOverview'
];

const EXPECTED_CONFIG_VIEW_REQUIRES = [
	'ui',
	'lanspeed.ifaceConfig',
	'lanspeed.theme',
	'lanspeed.configStyle',
	'lanspeed.configForm'
];

const STATUS_STYLE_PARTS = [
	'statusStyleBase.js',
	'statusStyleAurora.js',
	'statusStyleArgon.js',
	'statusStyleBootstrap.js',
	'statusStyleResponsive.js'
];

const CLIENT_DETAIL_STYLE_PARTS = [
	'clientDetailStyleBase.js',
	'clientDetailStyleAurora.js',
	'clientDetailStyleArgon.js',
	'clientDetailStyleBootstrap.js',
	'clientDetailStyleResponsive.js'
];

const DIAGNOSTICS_STYLE_PARTS = [
	'diagnosticsStyleBase.js',
	'diagnosticsStyleAurora.js',
	'diagnosticsStyleArgon.js',
	'diagnosticsStyleBootstrap.js',
	'diagnosticsStyleResponsive.js'
];

const CONFIG_STYLE_PARTS = [
	'configStyleBase.js',
	'configStyleAurora.js',
	'configStyleArgon.js',
	'configStyleBootstrap.js',
	'configStyleShared.js',
	'configStyleResponsive.js'
];

const EXPECTED_STATUS_STYLE_SHA256 = '7efc85957caddd7dbea15cae2776551a7089d204a71d4eefa9883795a110e5ec';
const EXPECTED_DIAGNOSTICS_STYLE_SHA256 = 'f8e8015359f4e3e7aa2870c3d7c334dc527093af3c38ca41c5ad06a4a9372648';
const EXPECTED_CONFIG_STYLE_SHA256 = 'e969a7acddc5ed9bb59bb3493bfd9641787345b0fd57c569c78a51d054e03482';

function readMakeVar(source, name, fileLabel) {
	const match = source.match(new RegExp(`^${name}:=(.+)$`, 'm'));
	if (!match) {
		fail(`${fileLabel} must define ${name}`);
		return '';
	}
	return match[1].trim();
}

const MODULE_REQUIRES = {
	'vocab.js': [ 'baseclass' ],
	'format.js': [ 'baseclass' ],
	'geoLocation.js': [ 'baseclass' ],
	'clientConnections.js': [ 'baseclass', 'lanspeed.format' ],
	'clientDetailRefresh.js': [
		'baseclass',
		'lanspeed.format',
		'lanspeed.clientConnections'
	],
	'clientDetailShell.js': [
		'baseclass',
		'lanspeed.theme',
		'lanspeed.clientDetailStyle'
	],
	'clientDetailView.js': [
		'baseclass',
		'lanspeed.format',
		'lanspeed.rpc',
		'lanspeed.geoLocation',
		'lanspeed.clientDetailShell',
		'lanspeed.clientDetailRefresh'
	],
	'clientDetailStyle.js': [
		'baseclass',
		'lanspeed.statusStyle',
		'lanspeed.clientDetailStyleBase',
		'lanspeed.clientDetailStyleAurora',
		'lanspeed.clientDetailStyleArgon',
		'lanspeed.clientDetailStyleBootstrap',
		'lanspeed.clientDetailStyleResponsive'
	],
	'clientDetailStyleBase.js': [ 'baseclass' ],
	'clientDetailStyleAurora.js': [ 'baseclass' ],
	'clientDetailStyleArgon.js': [ 'baseclass' ],
	'clientDetailStyleBootstrap.js': [ 'baseclass' ],
	'clientDetailStyleResponsive.js': [ 'baseclass' ],
	'diagnosticsRefresh.js': [
		'baseclass',
		'lanspeed.vocab',
		'lanspeed.format',
		'lanspeed.version',
		'lanspeed.statusCollector'
	],
	'diagnosticsShell.js': [
		'baseclass',
		'lanspeed.theme',
		'lanspeed.diagnosticsStyle'
	],
	'diagnosticsStyle.js': [
		'baseclass',
		'lanspeed.diagnosticsStyleBase',
		'lanspeed.diagnosticsStyleAurora',
		'lanspeed.diagnosticsStyleArgon',
		'lanspeed.diagnosticsStyleBootstrap',
		'lanspeed.diagnosticsStyleResponsive'
	],
	'diagnosticsStyleBase.js': [ 'baseclass' ],
	'diagnosticsStyleAurora.js': [ 'baseclass' ],
	'diagnosticsStyleArgon.js': [ 'baseclass' ],
	'diagnosticsStyleBootstrap.js': [ 'baseclass' ],
	'diagnosticsStyleResponsive.js': [ 'baseclass' ],
	'diagnosticsView.js': [
		'baseclass',
		'lanspeed.rpc',
		'lanspeed.diagnosticsShell',
		'lanspeed.diagnosticsRefresh'
	],
	'rpc.js': [ 'baseclass', 'rpc' ],
	'ifaceConfig.js': [ 'baseclass', 'lanspeed.format', 'lanspeed.rpc' ],
	'theme.js': [ 'baseclass' ],
	'version.js': [ 'baseclass' ],
	'statusStyle.js': [
		'baseclass',
		'lanspeed.statusStyleBase',
		'lanspeed.statusStyleAurora',
		'lanspeed.statusStyleArgon',
		'lanspeed.statusStyleBootstrap',
		'lanspeed.statusStyleResponsive'
	],
	'statusStyleBase.js': [ 'baseclass' ],
	'statusStyleAurora.js': [ 'baseclass' ],
	'statusStyleArgon.js': [ 'baseclass' ],
	'statusStyleBootstrap.js': [ 'baseclass' ],
	'statusStyleResponsive.js': [ 'baseclass' ],
	'statusView.js': [
		'baseclass',
		'lanspeed.clientConnections',
		'lanspeed.clientDetailView',
		'lanspeed.statusOverview'
	],
	'statusIp.js': [ 'baseclass', 'lanspeed.format' ],
	'statusCollector.js': [ 'baseclass' ],
	'statusOverview.js': [
		'baseclass',
		'lanspeed.format',
		'lanspeed.rpc',
		'lanspeed.statusIp',
		'lanspeed.statusShell',
		'lanspeed.statusRefresh'
	],
	'statusShell.js': [
		'baseclass',
		'lanspeed.format',
		'lanspeed.theme',
		'lanspeed.statusStyle'
	],
	'statusRefresh.js': [
		'baseclass',
		'lanspeed.vocab',
		'lanspeed.format',
		'lanspeed.clientConnections',
		'lanspeed.version',
		'lanspeed.statusIp',
		'lanspeed.statusCollector'
	],
	'configStyle.js': [
		'baseclass',
		'lanspeed.configStyleBase',
		'lanspeed.configStyleAurora',
		'lanspeed.configStyleArgon',
		'lanspeed.configStyleBootstrap',
		'lanspeed.configStyleShared',
		'lanspeed.configStyleResponsive'
	],
	'configStyleBase.js': [ 'baseclass' ],
	'configStyleAurora.js': [ 'baseclass' ],
	'configStyleArgon.js': [ 'baseclass' ],
	'configStyleBootstrap.js': [ 'baseclass' ],
	'configStyleShared.js': [ 'baseclass' ],
	'configStyleResponsive.js': [ 'baseclass' ],
	'configForm.js': [ 'baseclass', 'uci', 'lanspeed.rpc', 'lanspeed.ifaceConfig' ]
};

const RPC_FREE_MODULES = EXPECTED_MODULES.filter(function(name) {
	return name !== 'rpc.js';
});

const errors = [];
const asyncChecks = [];
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

function styleSources(entryName, parts) {
	return [ readModuleByName(entryName) ]
		.concat(parts.map(readModuleByName))
		.join('\n');
}

function loadStyleLeaf(name) {
	const fakeBaseclass = { extend: function(value) { return value; } };
	return vm.compileFunction(readModuleByName(name), [ 'baseclass' ], {
		filename: `resources/lanspeed/${name}`
	})(fakeBaseclass);
}

function styleHash(css) {
	return crypto.createHash('sha256').update(css).digest('hex');
}

function assertStyleModuleIsolation(name, src) {
	if (/StyleBase\.js$/.test(name) &&
	    (src.includes('lanspeed-theme-aurora') ||
	     src.includes('lanspeed-theme-argon') ||
	     src.includes('lanspeed-theme-bootstrap'))) {
		fail(`${name} must remain theme-neutral`);
	}
	if (/StyleAurora\.js$/.test(name) &&
	    (!src.includes('lanspeed-theme-aurora') ||
	     src.includes('lanspeed-theme-argon') ||
	     src.includes('lanspeed-theme-bootstrap'))) {
		fail(`${name} must contain Aurora selectors only`);
	}
	if (/StyleArgon\.js$/.test(name) &&
	    (!src.includes('lanspeed-theme-argon') ||
	     src.includes('lanspeed-theme-aurora') ||
	     src.includes('lanspeed-theme-bootstrap'))) {
		fail(`${name} must contain Argon selectors only`);
	}
	if (/StyleBootstrap\.js$/.test(name) &&
	    (!src.includes('lanspeed-theme-bootstrap') ||
	     src.includes('lanspeed-theme-aurora') ||
	     src.includes('lanspeed-theme-argon'))) {
		fail(`${name} must contain Bootstrap selectors only`);
	}
	if ((name === 'statusStyleResponsive.js' || name === 'configStyleResponsive.js') &&
	    (!src.includes('lanspeed-theme-aurora') ||
	     !src.includes('lanspeed-theme-argon') ||
	     !src.includes('lanspeed-theme-bootstrap'))) {
		fail(`${name} must retain shared responsive selectors for Aurora, Argon and Bootstrap`);
	}
	if (name === 'configStyleShared.js' &&
	    (!src.includes('lanspeed-theme-aurora') ||
	     !src.includes('lanspeed-theme-argon') ||
	     src.includes('lanspeed-theme-bootstrap'))) {
		fail('configStyleShared.js must remain the explicitly shared Aurora/Argon desktop layer');
	}
}

function assertStyleAggregation() {
	const fakeBaseclass = { extend: function(value) { return value; } };
	const statusBase = loadStyleLeaf('statusStyleBase.js');
	const statusAurora = loadStyleLeaf('statusStyleAurora.js');
	const statusArgon = loadStyleLeaf('statusStyleArgon.js');
	const statusBootstrap = loadStyleLeaf('statusStyleBootstrap.js');
	const statusResponsive = loadStyleLeaf('statusStyleResponsive.js');
	const status = vm.compileFunction(readModuleByName('statusStyle.js'), [
		'baseclass', 'statusStyleBase', 'statusStyleAurora',
		'statusStyleArgon', 'statusStyleBootstrap', 'statusStyleResponsive'
	], { filename: 'resources/lanspeed/statusStyle.js' })(
		fakeBaseclass, statusBase, statusAurora, statusArgon,
		statusBootstrap, statusResponsive
	);
	const expectedStatus = [
		statusBase.CSS, statusAurora.CSS, statusArgon.CSS,
		statusBootstrap.CSS, statusResponsive.CSS
	].join('\n');
	if (status.CSS !== expectedStatus)
		fail('statusStyle.js must aggregate Base, Aurora, Argon, Bootstrap and Responsive CSS in cascade order');
	if (styleHash(status.CSS) !== EXPECTED_STATUS_STYLE_SHA256)
		fail('modular status CSS must match the reviewed stylesheet snapshot');

	const diagnosticsBase = loadStyleLeaf('diagnosticsStyleBase.js');
	const diagnosticsAurora = loadStyleLeaf('diagnosticsStyleAurora.js');
	const diagnosticsArgon = loadStyleLeaf('diagnosticsStyleArgon.js');
	const diagnosticsBootstrap = loadStyleLeaf('diagnosticsStyleBootstrap.js');
	const diagnosticsResponsive = loadStyleLeaf('diagnosticsStyleResponsive.js');
	const diagnostics = vm.compileFunction(readModuleByName('diagnosticsStyle.js'), [
		'baseclass', 'diagnosticsStyleBase', 'diagnosticsStyleAurora',
		'diagnosticsStyleArgon', 'diagnosticsStyleBootstrap', 'diagnosticsStyleResponsive'
	], { filename: 'resources/lanspeed/diagnosticsStyle.js' })(
		fakeBaseclass, diagnosticsBase, diagnosticsAurora, diagnosticsArgon,
		diagnosticsBootstrap, diagnosticsResponsive
	);
	const expectedDiagnostics = [
		diagnosticsBase.CSS, diagnosticsAurora.CSS, diagnosticsArgon.CSS,
		diagnosticsBootstrap.CSS, diagnosticsResponsive.CSS
	].join('\n');
	if (diagnostics.CSS !== expectedDiagnostics)
		fail('diagnosticsStyle.js must aggregate Base, Aurora, Argon, Bootstrap and Responsive CSS in cascade order');
	if (styleHash(diagnostics.CSS) !== EXPECTED_DIAGNOSTICS_STYLE_SHA256)
		fail('modular diagnostics CSS must match the reviewed stylesheet snapshot');

	const configBase = loadStyleLeaf('configStyleBase.js');
	const configAurora = loadStyleLeaf('configStyleAurora.js');
	const configArgon = loadStyleLeaf('configStyleArgon.js');
	const configBootstrap = loadStyleLeaf('configStyleBootstrap.js');
	const configShared = loadStyleLeaf('configStyleShared.js');
	const configResponsive = loadStyleLeaf('configStyleResponsive.js');
	const config = vm.compileFunction(readModuleByName('configStyle.js'), [
		'baseclass', 'configStyleBase', 'configStyleAurora',
		'configStyleArgon', 'configStyleBootstrap', 'configStyleShared',
		'configStyleResponsive'
	], { filename: 'resources/lanspeed/configStyle.js' })(
		fakeBaseclass, configBase, configAurora, configArgon,
		configBootstrap, configShared, configResponsive
	);
	const expectedConfig = [
		configBase.CSS, configAurora.CSS, configArgon.CSS,
		configBootstrap.CSS, configShared.CSS, configResponsive.CSS
	].join('\n');
	if (config.CSS !== expectedConfig)
		fail('configStyle.js must aggregate Base, Aurora, Argon, Bootstrap, Shared and Responsive CSS in cascade order');
	if (styleHash(config.CSS) !== EXPECTED_CONFIG_STYLE_SHA256)
		fail('modular config CSS must match the reviewed stylesheet snapshot');
}

function assertArgonAlignmentContracts() {
	const statusCss = loadStyleLeaf('statusStyleArgon.js').CSS;
	const diagnosticsCss = loadStyleLeaf('diagnosticsStyleArgon.js').CSS;
	const detailCss = loadStyleLeaf('clientDetailStyleArgon.js').CSS;
	const configCss = loadStyleLeaf('configStyleArgon.js').CSS;

	[
		'.lanspeed-theme-argon .lanspeed-details>summary{align-items:center}',
		'.lanspeed-theme-argon .lanspeed-sort-button{height:auto!important',
		'.lanspeed-theme-argon .lanspeed-toolbar label{font-size:1rem;line-height:1.5rem}',
		'.lanspeed-theme-argon .lanspeed-hint:empty{display:none}'
	].forEach(function(rule) {
		if (!statusCss.includes(rule))
			fail(`statusStyleArgon.js must retain reviewed Argon alignment rule: ${rule}`);
	});
	const overviewMetricRules = statusCss.match(
		/\.lanspeed-theme-argon\s+\.lanspeed-metrics?\b[^{}]*\{[^{}]*\}/g
	) || [];
	if (overviewMetricRules.some(function(rule) {
		return /\balign-(?:items|self)\s*:\s*start\b/.test(rule);
	})) {
		fail('statusStyleArgon.js must preserve the original overview metric alignment');
	}

	[
		'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostics-header>h3{font-size:1.35rem;line-height:1.25!important}',
		'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostics-intro{font-size:1rem;padding:0}',
		'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostic-description,',
		'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostic-alerts-title{padding:0!important'
	].forEach(function(rule) {
		if (!diagnosticsCss.includes(rule))
			fail(`diagnosticsStyleArgon.js must retain reviewed Argon alignment rule: ${rule}`);
	});

	[
		'.lanspeed-theme-argon .lanspeed-connection-client-name,',
		'.lanspeed-theme-argon .lanspeed-connection-summary-title{padding:0!important',
		'.lanspeed-theme-argon .lanspeed-connection-summary{align-content:start;align-self:start',
		'.lanspeed-theme-argon .lanspeed-connection-protocol-label{font-size:1rem;line-height:1.5rem}',
		'.lanspeed-theme-argon .lanspeed-connection-protocols .cbi-button{width:100%!important}'
	].forEach(function(rule) {
		if (!detailCss.includes(rule))
			fail(`clientDetailStyleArgon.js must retain reviewed Argon alignment rule: ${rule}`);
	});

	[
		'.lanspeed-theme-argon .lanspeed-header{padding:.95rem 1.25rem .8rem;align-items:center}',
		'.lanspeed-config-root.lanspeed-theme-argon .lanspeed-range-remove{',
		'height:2.5rem;min-height:2.5rem;padding-top:0;padding-bottom:0',
		'display:inline-flex;align-items:center;justify-content:center',
		'.lanspeed-config-root.lanspeed-theme-argon .lanspeed-ifcfg-table td{border-top:0}',
		'.lanspeed-config-root.lanspeed-theme-argon .lanspeed-config-table tbody tr{align-items:start;align-content:start}',
		'.lanspeed-config-root.lanspeed-theme-argon .lanspeed-config-table tbody td:nth-child(3){padding-left:.35rem}',
		'.lanspeed-config-root.lanspeed-theme-argon .lanspeed-config-table tbody tr.lanspeed-range-row{position:relative;min-height:7rem}',
		'.lanspeed-config-root.lanspeed-theme-argon .lanspeed-config-table tbody tr.lanspeed-range-row>td.hint{',
		'margin-top:calc(1.45rem + .2rem);width:min(20rem,calc(50% - 1.125rem))',
		'.lanspeed-config-root.lanspeed-theme-argon .lanspeed-hint:empty{display:none}'
	].forEach(function(rule) {
		if (!configCss.includes(rule))
			fail(`configStyleArgon.js must retain reviewed Argon alignment rule: ${rule}`);
	});
}

function assertConnectionStyleOwnership() {
	const statusBaseCss = loadStyleLeaf('statusStyleBase.js').CSS;
	const clientDetailBaseCss = loadStyleLeaf('clientDetailStyleBase.js').CSS;
	const selectedProtocolRule = '.lanspeed-connection-protocol[aria-pressed="true"]{' +
		'font-weight:600;box-shadow:inset 0 0 0 2px currentColor}';
	const sharedLinkRules = [
		'.lanspeed-connection-link{display:inline-flex;min-width:0;color:inherit;' +
			'text-decoration:none!important}',
		'.lanspeed-connection-link:hover{opacity:.78;text-decoration:none!important}',
		'.lanspeed-connection-link:focus-visible{outline:2px solid currentColor;outline-offset:3px;' +
			'text-decoration:none!important}'
	];

	if (!clientDetailBaseCss.includes(selectedProtocolRule)) {
		fail('clientDetailStyleBase.js must visibly mark the aria-pressed connection protocol');
	}
	sharedLinkRules.forEach(function(rule) {
		if (!statusBaseCss.includes(rule))
			fail('statusStyleBase.js must own the shared connection detail link rules');
	});
	[ 'text-decoration:underline', 'text-underline-offset' ].forEach(function(forbiddenRule) {
		if (statusBaseCss.includes(forbiddenRule))
			fail('statusStyleBase.js must not underline the shared connection detail links');
	});
	if (clientDetailBaseCss.includes('.lanspeed-connection-link')) {
		fail('clientDetailStyleBase.js must not duplicate the shared connection detail link rules');
	}
}

function moduleRequireNames(src) {
	const names = [];
	const re = /^\s*['"]require\s+([^\s'"]+)(?:\s+as\s+\w+)?['"]\s*;/gm;
	let match;
	while ((match = re.exec(src)) !== null)
		names.push(match[1]);
	return names;
}

function jsFilesUnder(dir) {
	if (!fs.existsSync(dir)) return [];
	return fs.readdirSync(dir, { withFileTypes: true }).reduce(function(files, entry) {
		const entryPath = path.join(dir, entry.name);
		if (entry.isDirectory())
			return files.concat(jsFilesUnder(entryPath));
		if (entry.isFile() && entry.name.endsWith('.js'))
			files.push(entryPath);
		return files;
	}, []);
}

function assertSemanticResourceNames() {
	jsFilesUnder(resDir).forEach(function(file) {
		const relative = path.relative(resDir, file).split(path.sep).join('/');
		const src = readModule(file);
		if (VERSIONED_RESOURCE_TOKEN.test(relative))
			fail(`resource filename must use a semantic name without a cache suffix: ${relative}`);
		if (VERSIONED_RESOURCE_TOKEN.test(src))
			fail(`resource source must not reference a LiveN or _liveN cache suffix: ${relative}`);
		moduleRequireNames(src).forEach(function(requireName) {
			if (VERSIONED_RESOURCE_TOKEN.test(requireName))
				fail(`${relative} must require the semantic module name, not ${requireName}`);
		});
	});

	if (VERSIONED_RESOURCE_TOKEN.test(luciMakefile))
		fail('applications/luci-app-lanspeed/Makefile must not package LiveN or _liveN resources');

	Object.keys(MODULE_REQUIRES).forEach(function(name) {
		if (VERSIONED_RESOURCE_TOKEN.test(name))
			fail(`module contract must use a semantic filename: ${name}`);
		MODULE_REQUIRES[name].forEach(function(requireName) {
			if (VERSIONED_RESOURCE_TOKEN.test(requireName))
				fail(`module contract must use a semantic dependency: ${requireName}`);
		});
	});
}

function assertViewEntries() {
	if (!fs.existsSync(viewDir)) return;
	const expected = EXPECTED_VIEW_ENTRIES.slice().sort();
	const actual = fs.readdirSync(viewDir).sort();
	if (JSON.stringify(actual) !== JSON.stringify(expected)) {
		fail(`view/lanspeed must contain only ${expected.join(', ')} (found: ${actual.join(', ') || 'none'})`);
	}

	const packaged = Array.from(luciMakefile.matchAll(
		/\.\/htdocs\/luci-static\/resources\/view\/lanspeed\/([^\s\\]+\.js)\b/g
	), function(match) { return match[1]; }).sort();
	if (JSON.stringify(packaged) !== JSON.stringify(expected)) {
		fail(`Makefile must package each semantic view entry exactly once: ${expected.join(', ')}`);
	}
}

function cssSelectorList(css) {
	const selectors = [];
	const re = /([^{}]+)\{/g;
	let match;
	while ((match = re.exec(css)) !== null) {
		const prelude = match[1].trim();
		if (!prelude || prelude.charAt(0) === '@') continue;
		prelude.split(',').forEach(function(selector) {
			selector = selector.trim();
			if (selector) selectors.push(selector);
		});
	}
	return selectors;
}

function assertClientDetailSelectorScope(name, css, theme) {
	const selectors = cssSelectorList(css);
	if (!selectors.length) {
		fail(`${name} must export non-empty connection-detail CSS`);
		return;
	}
	selectors.forEach(function(selector) {
		if (!selector.includes('.lanspeed-connection-') &&
		    !selector.includes('.lanspeed-connections-card')) {
			fail(`${name} selector must stay connection-detail scoped: ${selector}`);
		}
		if (theme && !selector.startsWith(`.lanspeed-theme-${theme}`)) {
			fail(`${name} selector must stay under .lanspeed-theme-${theme}: ${selector}`);
		}
	});
}

function assertClientDetailStyleLeaf(name, src) {
	if (JSON.stringify(moduleRequireNames(src)) !== JSON.stringify([ 'baseclass' ])) {
		fail(`${name} must require only baseclass`);
	}
	const leaf = loadStyleLeaf(name);
	if (!leaf || typeof leaf.CSS !== 'string' || !leaf.CSS.trim()) {
		fail(`${name} must export a non-empty CSS string`);
		return;
	}
	const css = leaf.CSS;
	const paletteCss = css.replace(
		/var\(--border,rgba\(128,128,128,\.18\)\)/g,
		'var(--border)'
	);
	if (/#[0-9a-f]{3,8}\b|\b(?:rgb|hsl)a?\s*\(/i.test(paletteCss)) {
		fail(`${name} must inherit status theme colors instead of hard-coding a separate palette`);
	}
	let theme = '';
	if (name === 'clientDetailStyleAurora.js') theme = 'aurora';
	if (name === 'clientDetailStyleArgon.js') theme = 'argon';
	if (name === 'clientDetailStyleBootstrap.js') theme = 'bootstrap';
	assertClientDetailSelectorScope(name, css, theme);

	const themeClasses = [
		'lanspeed-theme-aurora',
		'lanspeed-theme-argon',
		'lanspeed-theme-bootstrap'
	];
	if (!theme && themeClasses.some(function(className) { return css.includes(className); })) {
		fail(`${name} must remain theme-neutral`);
	}
	if (theme && themeClasses.some(function(className) {
		return className !== `lanspeed-theme-${theme}` && css.includes(className);
	})) {
		fail(`${name} must not mix selectors from another theme`);
	}

	if (name === 'clientDetailStyleBase.js') {
		[
			'.lanspeed-connection-identity',
			'.lanspeed-connection-summary',
			'.lanspeed-connection-toolbar',
			'.lanspeed-connection-detail-row',
			'.lanspeed-connection-endpoint',
			'.lanspeed-connection-empty'
		].forEach(function(token) {
			if (!css.includes(token))
				fail(`${name} must provide the detail-only ${token} layout hook`);
		});
	}
	if (name === 'clientDetailStyleAurora.js' &&
	    (!css.includes('padding:1rem 1.25rem .85rem') ||
	     !css.includes('var(--label-surface'))) {
		fail(`${name} must align detail padding and label surfaces with the Aurora status page`);
	}
	if (name === 'clientDetailStyleAurora.js' &&
	    !css.includes('@media (max-width:480px){.lanspeed-theme-aurora .lanspeed-connection-toolbar{padding-right:2rem}}')) {
		fail(`${name} must reserve a 2rem phone safe area for Aurora's floating toolbar`);
	}
	if (name === 'clientDetailStyleArgon.js') {
		if (!css.includes('font-size:1rem') || !css.includes('padding:.65rem .75rem'))
			fail(`${name} must retain the Argon status typography and table density`);
		if (!css.includes('@media (max-width:480px){') ||
		    !css.includes('.lanspeed-theme-argon .lanspeed-connection-refresh,') ||
		    !css.includes('.lanspeed-theme-argon .lanspeed-connection-protocols .cbi-button{width:100%!important}')) {
			fail(`${name} must override Argon's width:auto!important so phone refresh and protocol actions fill their toolbar cells`);
		}
		if (!css.includes('.lanspeed-theme-argon .lanspeed-connection-client-name,') ||
		    !css.includes('.lanspeed-theme-argon .lanspeed-connection-summary-title{padding:0!important;') ||
		    !css.includes('line-height:1.25!important') ||
		    !css.includes('line-height:1.35!important')) {
			fail(`${name} must neutralize Argon h4 padding and line-height on client and summary titles`);
		}
	}
	if (name === 'clientDetailStyleBootstrap.js') {
		/* lsTheme.applyRoot() adds both classes to the same root; there is no
		 * descendant .lanspeed-connection-detail node for a spaced selector. */
		const rootClasses = new Set([
			'lanspeed-theme-bootstrap',
			'lanspeed-connection-detail'
		]);
		const expectedRootSelector = '.lanspeed-theme-bootstrap.lanspeed-connection-detail';
		const rootRule = css.match(/([^{}]+)\{gap:\.85em\}/);
		const rootSelector = rootRule && rootRule[1].trim();
		const selectorClasses = rootSelector && !/\s/.test(rootSelector)
			? rootSelector.split('.').filter(Boolean)
			: [];
		const matchesSameRoot = selectorClasses.length === rootClasses.size &&
			selectorClasses.every(function(className) {
				return rootClasses.has(className);
			});
		if (!matchesSameRoot ||
		    rootSelector !== expectedRootSelector ||
		    css.includes('.lanspeed-theme-bootstrap .lanspeed-connection-detail{gap:.85em}') ||
		    !css.includes('padding:.4em .55em')) {
			fail(`${name} must match the Bootstrap and detail classes on the same root while keeping the table compact`);
		}
	}
	if (name === 'clientDetailStyleResponsive.js') {
		const media = Array.from(css.matchAll(/@media\s*\(([^)]+)\)/g), function(match) {
			return match[1].replace(/\s+/g, '');
		});
		const narrowStart = css.indexOf('@media (max-width:700px){');
		const phoneStart = css.indexOf('@media (max-width:480px){');
		const narrowCss = narrowStart >= 0 && phoneStart > narrowStart
			? css.slice(narrowStart, phoneStart)
			: '';
		const forcedRows = narrowCss.indexOf(
			'.lanspeed-connections-card .lanspeed-table tbody>tr{display:grid;'
		);
		const hiddenRows = narrowCss.indexOf(
			'.lanspeed-connections-card .lanspeed-table tbody>tr[hidden]{display:none!important}'
		);
		if (JSON.stringify(media) !== JSON.stringify([
			'max-width:1100px', 'max-width:700px', 'max-width:480px'
		]) ||
		    !css.includes('content:attr(data-label)') ||
		    !css.includes('overflow-wrap:anywhere') ||
		    !css.includes('.lanspeed-connection-refresh{width:100%')) {
			fail(`${name} must provide the 1100px identity, 700px card-table and 480px toolbar breakpoints`);
		}
		if (forcedRows < 0 || hiddenRows <= forcedRows) {
			fail(`${name} must restore display:none!important for hidden group/detail rows after the forced mobile row display`);
		}
		if (!narrowCss.includes('border-bottom:1px solid var(--border,rgba(128,128,128,.18))') ||
		    narrowCss.includes('var(--border,currentColor)')) {
			fail(`${name} must reuse the translucent status table divider fallback on mobile`);
		}
	}
}

function assertClientDetailStyleComposer(src) {
	const expectedRequires = [
		'baseclass',
		'lanspeed.statusStyle',
		'lanspeed.clientDetailStyleBase',
		'lanspeed.clientDetailStyleAurora',
		'lanspeed.clientDetailStyleArgon',
		'lanspeed.clientDetailStyleBootstrap',
		'lanspeed.clientDetailStyleResponsive'
	];
	if (JSON.stringify(moduleRequireNames(src)) !== JSON.stringify(expectedRequires)) {
		fail('clientDetailStyle.js must require status and detail style leaves in cascade order');
	}
	const cleaned = stripComments(src);
	if (/@media|\.lanspeed-connection-|\.lanspeed-connections-card|['"][^'"\n]*\{/.test(cleaned)) {
		fail('clientDetailStyle.js must only compose CSS and must not define its own rules');
	}
	if (!CLIENT_DETAIL_STYLE_PARTS.every(function(name) {
		return fs.existsSync(path.join(modDir, name));
	})) return;

	const fakeBaseclass = { extend: function(value) { return value; } };
	const statusStyle = { CSS: 'status' };
	const Base = { CSS: 'base' };
	const Aurora = { CSS: 'aurora' };
	const Argon = { CSS: 'argon' };
	const Bootstrap = { CSS: 'bootstrap' };
	const Responsive = { CSS: 'responsive' };
	const detail = vm.compileFunction(src, [
		'baseclass', 'statusStyle', 'Base', 'Aurora', 'Argon', 'Bootstrap', 'Responsive'
	], { filename: 'resources/lanspeed/clientDetailStyle.js' })(
		fakeBaseclass, statusStyle, Base, Aurora, Argon, Bootstrap, Responsive
	);
	if (!detail || detail.CSS !== 'status\nbase\naurora\nargon\nbootstrap\nresponsive') {
		fail('clientDetailStyle.js must compose status, Base, Aurora, Argon, Bootstrap and Responsive CSS in exact order');
	}
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
	const context = vm.createContext({});
	vm.runInContext(`
		String.prototype.format = function() {
			var args = Array.prototype.slice.call(arguments);
			var index = 0;
			return String(this).replace(/%(?:\\.(\\d+))?([dfs])/g,
				function(_match, precision, type) {
					var value = args[index++];
					if (type === 's') return String(value);
					if (type === 'd') return String(Math.trunc(Number(value)));
					return Number(value).toFixed(precision === undefined ? 6 : Number(precision));
				});
		};
	`, context);
	return vm.compileFunction(src, [ 'baseclass' ], {
		filename: 'resources/lanspeed/format.js',
		parsingContext: context
	})(fakeBaseclass);
}

function loadClientConnectionsModule(src) {
	const fakeBaseclass = { extend: function(value) { return value; } };
	return vm.compileFunction(src, [ 'baseclass', 'fmt' ], {
		filename: 'resources/lanspeed/clientConnections.js'
	})(fakeBaseclass, loadFormatModule(readModuleByName('format.js')));
}

function loadStatusViewRouter(src, fakeWindow, clientDetailView, statusView) {
	const fakeBaseclass = { extend: function(value) { return value; } };
	return vm.compileFunction(src, [
		'baseclass', 'clientConnections', 'clientDetailView', 'statusView', 'window'
	], { filename: 'resources/lanspeed/statusView.js' })(
		fakeBaseclass,
		loadClientConnectionsModule(readModuleByName('clientConnections.js')),
		clientDetailView,
		statusView,
		fakeWindow
	);
}

function assertStatusViewRouterBehavior(src) {
	const fakeWindow = { location: { search: '' } };
	const calls = {
		status: 0, clients: 0, interfaces: 0, uci: 0,
		overviewRender: 0, detailLoad: [], detailRender: 0
	};
	const statusView = {
		load: function() {
			calls.status++; calls.clients++; calls.interfaces++; calls.uci++;
			return Promise.resolve({ kind: 'overview-data' });
		},
		render: function(data) {
			calls.overviewRender++;
			return { kind: 'overview-root', data: data };
		}
	};
	const clientDetailView = {
		load: function(identityKey) {
			calls.detailLoad.push(identityKey);
			return Promise.resolve({ identityKey: identityKey, response: { available: true } });
		},
		render: function(data) {
			calls.detailRender++;
			return { kind: 'detail-root', data: data };
		}
	};

	asyncChecks.push(Promise.resolve().then(async function() {
		const router = loadStatusViewRouter(src, fakeWindow, clientDetailView, statusView);
		fakeWindow.location.search = '';
		const overview = await router.load();
		fakeWindow.location.search = '?client=30%3Ac5%3A0a%40eth1';
		const overviewRoot = router.render(overview);
		if (!overview || overview.route !== 'overview' ||
		    calls.status !== 1 || calls.clients !== 1 || calls.interfaces !== 1 || calls.uci !== 1 ||
		    calls.detailLoad.length !== 0 || overviewRoot.kind !== 'overview-root' ||
		    calls.overviewRender !== 1 || calls.detailRender !== 0) {
			fail('statusView.js overview route must preserve the status, clients, interfaces, and UCI load and render from its load-time marker');
		}

		fakeWindow.location.search = '?client=30%3Ac5%3A0a%40eth1';
		const detail = await router.load();
		fakeWindow.location.search = '';
		const detailRoot = router.render(detail);
		if (!detail || detail.route !== 'detail' ||
		    JSON.stringify(calls.detailLoad) !== JSON.stringify([ '30:c5:0a@eth1' ]) ||
		    calls.status !== 1 || calls.clients !== 1 || calls.interfaces !== 1 || calls.uci !== 1 ||
		    detailRoot.kind !== 'detail-root' || calls.detailRender !== 1 || calls.overviewRender !== 1) {
			fail('statusView.js detail route must decode identity, avoid overview RPC work, and render from its load-time marker');
		}

		fakeWindow.location.search = '?client=';
		const empty = await router.load();
		if (!empty || empty.route !== 'overview')
			fail('statusView.js must treat a missing or empty client identity as the overview route');
	}).catch(function(err) {
		fail('statusView.js router behavior could not execute: ' + (err && err.message || err));
	}));
}

function assertClientConnectionsSource(src) {
	const cleaned = stripComments(src);
	const requires = [];
	const requireRe = /^\s*['"]require\s+([^\s'"]+)(?:\s+as\s+\w+)?['"]\s*;/gm;
	let match;
	while ((match = requireRe.exec(cleaned)) !== null)
		requires.push(match[1]);
	if (JSON.stringify(requires) !== JSON.stringify([ 'baseclass', 'lanspeed.format' ])) {
		fail('clientConnections.js must require only baseclass and lanspeed.format');
	}
	if (/\b(?:document|window|Node|HTMLElement|setTimeout|setInterval|requestAnimationFrame|rpc)\b|\bE\s*\(|\.(?:innerHTML|textContent|appendChild|createElement)\b/.test(cleaned)) {
		fail('clientConnections.js must remain free of DOM, RPC, and timer APIs');
	}
	if (/\bCSS\b|@media|['"]\s*[.#][A-Za-z][^'"]*\{/.test(cleaned)) {
		fail('clientConnections.js must not embed CSS strings');
	}
}

function assertClientConnectionsModule(src) {
	assertClientConnectionsSource(src);
	const clientConnections = loadClientConnectionsModule(src);
	const methods = [
		'detailHref',
		'formatEndpoint',
		'groupsForResponse',
		'identityFromSearch',
		'portSummary',
		'sortGroups',
		'stateLabel'
	];
	if (!clientConnections) {
		fail('clientConnections.js must return its pure connection-detail helpers');
		return;
	}
	if (JSON.stringify(Object.keys(clientConnections).sort()) !== JSON.stringify(methods) ||
	    methods.some(function(name) { return typeof clientConnections[name] !== 'function'; })) {
		fail('clientConnections.js must expose exactly its seven pure connection-detail helpers');
		return;
	}
	const mod = clientConnections;

	if (mod.identityFromSearch('?client=aa%3Abb%40lan') !== 'aa:bb@lan' ||
	    mod.identityFromSearch('?x=1&client=02%3A00%3A00%3A00%3A00%3A01%40lan&z=2') !==
		'02:00:00:00:00:01@lan' ||
	    mod.identityFromSearch('?client=') !== '' ||
	    mod.identityFromSearch('?x=1') !== '') {
		fail('clientConnections.js must safely read and decode the client query parameter');
	}
	try {
		if (mod.identityFromSearch('?client=%E0%A4%A') !== '')
			fail('clientConnections.js must return an empty identity for malformed percent encoding');
	} catch (err) {
		fail('clientConnections.js must not throw for malformed percent encoding');
	}

	if (mod.detailHref('/admin/status/lanspeed/overview', 'aa:bb@lan') !==
		'/admin/status/lanspeed/overview?client=aa%3Abb%40lan' ||
	    mod.detailHref('/admin/status/lanspeed/overview?tab=clients#connections', 'aa:bb@lan') !==
		'/admin/status/lanspeed/overview?tab=clients&client=aa%3Abb%40lan#connections') {
		fail('clientConnections.js must append an encoded client query without dropping existing query or hash text');
	}

	if (mod.formatEndpoint('240e::1', 443) !== '[240e::1]:443' ||
	    mod.formatEndpoint('[240e::1]', 0) !== '[240e::1]:0' ||
	    mod.formatEndpoint('1.1.1.1', 53) !== '1.1.1.1:53' ||
	    mod.formatEndpoint('1.1.1.1') !== '1.1.1.1') {
		fail('clientConnections.js must format IPv4/IPv6 endpoints and preserve port zero');
	}

	const response = {
		connections: [
			{
				client_ip: '192.0.2.10', client_port: 50001,
				remote_ip: '1.1.1.1', remote_port: 443,
				protocol: 'tcp', state: 'established', tx_bps: 1000, rx_bps: 2000
			},
			{
				client_ip: '192.0.2.10', client_port: 50002,
				remote_ip: '8.8.8.8', remote_port: 53,
				protocol: 'udp', state: 'assured', tx_bps: 3000, rx_bps: 4000
			},
			{
				client_ip: '192.0.2.11', client_port: 50003,
				remote_ip: '1.1.1.1', remote_port: 80,
				protocol: 'udp', state: 'assured', tx_bps: 5000, rx_bps: 6000
			},
			{
				client_ip: '192.0.2.12', client_port: 50004,
				remote_ip: '1.1.1.1', remote_port: 443,
				protocol: 'tcp', state: 'established', tx_bps: 7000, rx_bps: 8000
			},
			{
				client_ip: '192.0.2.13', client_port: 50005,
				remote_ip: '9.9.9.9', remote_port: 853,
				protocol: 'tcp', state: 'established', tx_bps: 9000, rx_bps: 10000
			},
			{
				client_ip: '2001:DB8::10', client_port: 50006,
				remote_ip: '2001:DB8::BEEF', remote_port: 123,
				protocol: 'udp', state: 'assured', tx_bps: 'invalid', rx_bps: -1
			}
		]
	};
	const originalResponse = JSON.stringify(response);
	const groups = mod.groupsForResponse(response, 'all', '');
	if (!Array.isArray(groups) || groups.length !== 4 ||
	    Object.prototype.toString.call(groups[0]) !== '[object Object]' ||
	    !Array.isArray(groups[0].ports) || !Array.isArray(groups[0].connections)) {
		fail('clientConnections.js must return ordinary group objects and arrays');
		return;
	}
	if (groups[0].remoteIp !== '1.1.1.1' ||
	    JSON.stringify(Array.from(groups[0].ports)) !== JSON.stringify([ 80, 443 ]) ||
	    groups[0].portLabel !== '80, 443' ||
	    groups[0].protocolLabel !== 'TCP/UDP' ||
	    groups[0].stateLabel !== '混合' ||
	    groups[0].txBps !== 13000 || groups[0].rxBps !== 16000 ||
	    groups[0].count !== 3 ||
	    JSON.stringify(Array.from(groups[0].connections, function(conn) { return conn.client_port; })) !==
		JSON.stringify([ 50001, 50003, 50004 ])) {
		fail('clientConnections.js must aggregate duplicate destinations without reordering their connections');
	}
	if (groups[1].remoteIp !== '8.8.8.8' || groups[1].protocolLabel !== 'UDP' ||
	    groups[1].stateLabel !== '活跃' || groups[2].remoteIp !== '9.9.9.9' ||
	    groups[2].protocolLabel !== 'TCP' || groups[2].stateLabel !== '已建立') {
		fail('clientConnections.js must preserve first-seen group order and label uniform protocol/state groups');
	}

	const tcpGroups = mod.groupsForResponse(response, 'tcp', '');
	if (JSON.stringify(Array.from(tcpGroups, function(group) { return group.remoteIp; })) !==
		JSON.stringify([ '1.1.1.1', '9.9.9.9' ]) ||
	    tcpGroups[0].count !== 2 ||
	    JSON.stringify(Array.from(tcpGroups[0].ports)) !== JSON.stringify([ 443 ]) ||
	    tcpGroups[0].protocolLabel !== 'TCP' || tcpGroups[0].stateLabel !== '已建立' ||
	    tcpGroups[0].txBps !== 8000 || tcpGroups[0].rxBps !== 10000) {
		fail('clientConnections.js must filter TCP before building group counts and summaries');
	}
	const udpGroups = mod.groupsForResponse(response, 'udp', '');
	if (JSON.stringify(Array.from(udpGroups, function(group) { return group.remoteIp; })) !==
		JSON.stringify([ '8.8.8.8', '1.1.1.1', '2001:DB8::BEEF' ]) ||
	    udpGroups[1].count !== 1 || udpGroups[1].portLabel !== '80' ||
	    udpGroups[1].protocolLabel !== 'UDP' || udpGroups[1].stateLabel !== '活跃' ||
	    udpGroups[1].txBps !== 5000 || udpGroups[1].rxBps !== 6000 ||
	    udpGroups[2].txBps !== 0 || udpGroups[2].rxBps !== 0) {
		fail('clientConnections.js must filter UDP before preserving first-seen group order');
	}
	const unknownGroups = mod.groupsForResponse(response, 'unexpected', '');
	if (JSON.stringify(unknownGroups) !== JSON.stringify(groups)) {
		fail('clientConnections.js must normalize unknown protocol filters to the complete all result');
	}

	const sortableGroups = [
		{
			remoteIp: '10.0.0.1', ports: [ 443 ], portLabel: '443',
			locationLabel: 'Zulu country',
			protocolLabel: 'UDP', stateLabel: 'Zulu', txBps: 10, rxBps: 30,
			count: 2, connections: [ { marker: 'a' } ]
		},
		{
			remoteIp: '10.0.0.2', ports: [ 53 ], portLabel: '53',
			locationLabel: 'Alpha country',
			protocolLabel: 'TCP', stateLabel: 'Alpha', txBps: 30, rxBps: 10,
			count: 1, connections: [ { marker: 'b' } ]
		},
		{
			remoteIp: '10.0.0.3', ports: [ 80 ], portLabel: '80',
			locationLabel: 'Mike country',
			protocolLabel: 'TCP/UDP', stateLabel: 'Mike', txBps: 20, rxBps: 20,
			count: 3, connections: [ { marker: 'c' } ]
		}
	];
	const sortableSnapshot = JSON.stringify(sortableGroups);
	const sortOrders = {
		remote_ip: [ '10.0.0.1', '10.0.0.2', '10.0.0.3' ],
		location: [ '10.0.0.2', '10.0.0.3', '10.0.0.1' ],
		remote_port: [ '10.0.0.2', '10.0.0.3', '10.0.0.1' ],
		protocol: [ '10.0.0.2', '10.0.0.3', '10.0.0.1' ],
		state: [ '10.0.0.2', '10.0.0.3', '10.0.0.1' ],
		tx: [ '10.0.0.1', '10.0.0.3', '10.0.0.2' ],
		rx: [ '10.0.0.2', '10.0.0.3', '10.0.0.1' ],
		count: [ '10.0.0.2', '10.0.0.1', '10.0.0.3' ]
	};
	Object.keys(sortOrders).forEach(function(sortKey) {
		const ascending = mod.sortGroups(sortableGroups, sortKey, 'asc');
		const descending = mod.sortGroups(sortableGroups, sortKey, 'desc');
		const ascIps = Array.from(ascending, function(group) { return group.remoteIp; });
		const descIps = Array.from(descending, function(group) { return group.remoteIp; });
		if (JSON.stringify(ascIps) !== JSON.stringify(sortOrders[sortKey]) ||
		    JSON.stringify(descIps) !== JSON.stringify(sortOrders[sortKey].slice().reverse())) {
			fail(`clientConnections.js must sort grouped destinations by ${sortKey} in both directions`);
		}
		if (ascending === sortableGroups || descending === sortableGroups ||
		    ascending.some(function(group) { return sortableGroups.indexOf(group) === -1; })) {
			fail('clientConnections.js sortGroups must return a new array containing the original group objects');
		}
	});
	if (JSON.stringify(sortableGroups) !== sortableSnapshot ||
	    JSON.stringify(response) !== originalResponse) {
		fail('clientConnections.js sorting must not mutate source groups, nested connections, or the RPC response');
	}

	const tcpSearchedGroups = mod.groupsForResponse(response, 'tcp', '1.1.1.1');
	if (tcpSearchedGroups.length !== 1 || tcpSearchedGroups[0].remoteIp !== '1.1.1.1' ||
	    tcpSearchedGroups[0].count !== 2 ||
	    JSON.stringify(Array.from(tcpSearchedGroups[0].ports)) !== JSON.stringify([ 443 ]) ||
	    tcpSearchedGroups[0].portLabel !== '443' ||
	    JSON.stringify(Array.from(tcpSearchedGroups[0].connections, function(conn) { return conn.client_port; })) !==
		JSON.stringify([ 50001, 50004 ]) ||
	    tcpSearchedGroups[0].protocolLabel !== 'TCP' ||
	    tcpSearchedGroups[0].stateLabel !== '已建立' ||
	    tcpSearchedGroups[0].txBps !== 8000 || tcpSearchedGroups[0].rxBps !== 10000) {
		fail('clientConnections.js must keep TCP filtering active while applying a non-empty search');
	}
	const udpSearchedGroups = mod.groupsForResponse(response, 'udp', '1.1.1.1');
	if (udpSearchedGroups.length !== 1 || udpSearchedGroups[0].remoteIp !== '1.1.1.1' ||
	    udpSearchedGroups[0].count !== 1 ||
	    JSON.stringify(Array.from(udpSearchedGroups[0].ports)) !== JSON.stringify([ 80 ]) ||
	    udpSearchedGroups[0].portLabel !== '80' ||
	    JSON.stringify(Array.from(udpSearchedGroups[0].connections, function(conn) { return conn.client_port; })) !==
		JSON.stringify([ 50003 ]) ||
	    udpSearchedGroups[0].protocolLabel !== 'UDP' ||
	    udpSearchedGroups[0].stateLabel !== '活跃' ||
	    udpSearchedGroups[0].txBps !== 5000 || udpSearchedGroups[0].rxBps !== 6000) {
		fail('clientConnections.js must keep UDP filtering active while applying a non-empty search');
	}

	const remoteSearch = mod.groupsForResponse(response, 'all', '1.1.1.1');
	const clientSearch = mod.groupsForResponse(response, 'all', '192.0.2.11');
	const remotePortSearch = mod.groupsForResponse(response, 'all', '853');
	const clientPortSearch = mod.groupsForResponse(response, 'all', '50002');
	const caseSearch = mod.groupsForResponse(response, 'all', '  db8::beef  ');
	const narrowedSearch = mod.groupsForResponse(response, 'all', '443');
	const locationSearch = mod.groupsForResponse(response, 'all', '美国', function(ip) {
		return ip === '1.1.1.1' ? '美国' : '其他地区';
	});
	if (remoteSearch.length !== 1 || remoteSearch[0].count !== 3 ||
	    clientSearch.length !== 1 || clientSearch[0].count !== 1 ||
	    clientSearch[0].portLabel !== '80' || clientSearch[0].protocolLabel !== 'UDP' ||
	    remotePortSearch.length !== 1 || remotePortSearch[0].remoteIp !== '9.9.9.9' ||
	    clientPortSearch.length !== 1 || clientPortSearch[0].remoteIp !== '8.8.8.8' ||
	    caseSearch.length !== 1 || caseSearch[0].remoteIp !== '2001:DB8::BEEF' ||
	    caseSearch[0].txBps !== 0 || caseSearch[0].rxBps !== 0 ||
	    narrowedSearch.length !== 1 || narrowedSearch[0].count !== 2 ||
	    narrowedSearch[0].portLabel !== '443' || narrowedSearch[0].protocolLabel !== 'TCP' ||
	    narrowedSearch[0].txBps !== 8000 || narrowedSearch[0].rxBps !== 10000 ||
	    locationSearch.length !== 1 || locationSearch[0].remoteIp !== '1.1.1.1' ||
	    locationSearch[0].locationLabel !== '美国' || locationSearch[0].count !== 3) {
		fail('clientConnections.js search must cover endpoint and country/region fields before recomputing group summaries');
	}

	const ports = [ 53, 80, 443, 853, 5353 ];
	const originalPorts = JSON.stringify(ports);
	if (mod.portSummary(ports.slice(0, 3)) !== '53, 80, 443' ||
	    mod.portSummary(ports) !== '53, 80, 443，另有 2 个' ||
	    mod.portSummary([]) !== '-' ||
	    mod.stateLabel([ { state: 'established' }, { state: 'established' } ]) !== '已建立' ||
	    mod.stateLabel([ { state: 'assured' } ]) !== '活跃' ||
	    mod.stateLabel([ { state: 'established' }, { state: 'assured' } ]) !== '混合') {
		fail('clientConnections.js must provide bounded port summaries and Chinese state labels');
	}
	if (JSON.stringify(response) !== originalResponse || JSON.stringify(ports) !== originalPorts) {
		fail('clientConnections.js helpers must not mutate response, connections, or port inputs');
	}

	const emptyResponses = [ undefined, {}, { connections: null }, { connections: {} } ];
	if (emptyResponses.some(function(emptyResponse) {
		const emptyGroups = mod.groupsForResponse(emptyResponse, 'all', '');
		return !Array.isArray(emptyGroups) || emptyGroups.length !== 0;
	})) {
		fail('clientConnections.js must return an empty array for missing, null, or non-array connections');
	}
}

function loadIfaceConfigModule(src, lsRpc) {
	const fakeBaseclass = { extend: function(value) { return value; } };
	const fakeFormat = {
		asArray: function(value) { return Array.isArray(value) ? value : []; },
		compareText: function(a, b) { return String(a || '').localeCompare(String(b || '')); },
		replaceChildren: function() {}
	};
	return vm.compileFunction(src,
		[ 'baseclass', 'fmt', 'lsRpc', 'E', '_' ],
		{ filename: 'resources/lanspeed/ifaceConfig.js' })(
			fakeBaseclass, fakeFormat, lsRpc || {}, fakeElement,
			function(value) { return value; }
		);
}

function loadConfigFormModule(src, uci, lsRpc, ifaceCfg) {
	const fakeBaseclass = { extend: function(value) { return value; } };
	return vm.compileFunction(src,
		[ 'baseclass', 'uci', 'lsRpc', 'ifaceCfg', 'E', '_', 'window' ],
		{ filename: 'resources/lanspeed/configForm.js' })(
			fakeBaseclass, uci, lsRpc, ifaceCfg, fakeElement,
			function(value) { return value; },
			{ setTimeout: function(handler) { handler(); } }
		);
}

function loadConfigViewModule(src, configForm, ui, ifaceCfg) {
	const fakeView = { extend: function(value) { return value; } };
	ifaceCfg = ifaceCfg || {
		buildSection: function() { return fakeElement('div', {}); },
		load: function() { return Promise.resolve(true); }
	};
	return vm.compileFunction(src,
		[ 'view', 'ui', 'ifaceCfg', 'lsTheme', 'configStyle', 'configForm', 'E', '_' ],
		{ filename: 'resources/view/lanspeed/config.js' })(
			fakeView, ui, ifaceCfg, { applyRoot: function() {} },
			{ CSS: '' }, configForm, fakeElement, function(value) { return value; }
		);
}

function loadVocabModule(src) {
	const fakeBaseclass = { extend: function(value) { return value; } };
	return vm.compileFunction(src, [ 'baseclass', '_' ], {
		filename: 'resources/lanspeed/vocab.js'
	})(fakeBaseclass, function(value) { return value; });
}

function fakeTranslate(value) {
	return {
		format: function() {
			const args = Array.from(arguments);
			let index = 0;
			return String(value).replace(/%[sd]/g, function() {
				return index < args.length ? String(args[index++]) : '';
			});
		},
		toString: function() { return String(value); }
	};
}

function nextDetailSort(state, sortKey) {
	if (!state.sortCustom || state.sortKey !== sortKey)
		return { sortKey: sortKey, sortDir: 'desc', sortCustom: true };
	if (state.sortDir === 'desc')
		return { sortKey: sortKey, sortDir: 'asc', sortCustom: true };
	return { sortKey: 'rx', sortDir: 'desc', sortCustom: false };
}

function loadStatusRefreshModule(src, fakeWindow) {
	const fakeBaseclass = { extend: function(value) { return value; } };
	const vocab = loadVocabModule(readModuleByName('vocab.js'));
	return vm.compileFunction(src,
		[ 'baseclass', 'vocab', 'fmt', 'clientConnections', 'lsVersion',
		  'statusIp', 'statusCollector', 'E', '_', 'window' ],
		{ filename: 'resources/lanspeed/statusRefresh.js' })(
			fakeBaseclass, vocab, {},
			loadClientConnectionsModule(readModuleByName('clientConnections.js')),
			{ FULL_VERSION: 'test' }, {}, {}, fakeElement, fakeTranslate,
			fakeWindow || { location: { pathname: '/admin/status/lanspeed/overview' } }
		);
}

const fakeDocument = { activeElement: null };

function fakeElement(tag, attrs, children) {
	const node = {
		tagName: tag,
		attrs: Object.assign({}, attrs || {}),
		children: [],
		listeners: {},
		parentNode: null,
		style: {},
		focus: function() { fakeDocument.activeElement = this; },
		addEventListener: function(type, handler) { this.listeners[type] = handler; },
		setAttribute: function(name, value) {
			this.attrs[name] = String(value);
			if (name === 'class') this._className = String(value);
			if (name === 'hidden') this._hidden = true;
			if (name === 'disabled') this._disabled = true;
			if (name === 'value') this._value = String(value);
		},
		getAttribute: function(name) {
			return Object.prototype.hasOwnProperty.call(this.attrs, name)
				? this.attrs[name] : null;
		},
		removeAttribute: function(name) {
			delete this.attrs[name];
			if (name === 'hidden') this._hidden = false;
			if (name === 'disabled') this._disabled = false;
		},
		appendChild: function(child) {
			if (child === null || child === undefined || child === '') return child;
			if (typeof child === 'object') child.parentNode = this;
			this.children.push(child);
			return child;
		},
		removeChild: function(child) {
			const index = this.children.indexOf(child);
			if (index !== -1) this.children.splice(index, 1);
			if (fakeDocument.activeElement === child)
				fakeDocument.activeElement = null;
			if (child && typeof child === 'object') child.parentNode = null;
			return child;
		}
	};
	node._className = String(node.attrs.class || '');
	node._hidden = Object.prototype.hasOwnProperty.call(node.attrs, 'hidden');
	node._disabled = Object.prototype.hasOwnProperty.call(node.attrs, 'disabled');
	node._value = Object.prototype.hasOwnProperty.call(node.attrs, 'value')
		? String(node.attrs.value) : '';
	const append = function(child) {
		if (Array.isArray(child)) child.forEach(append);
		else if (child && typeof child === 'object' && !child.tagName &&
		         typeof child.toString === 'function') node.appendChild(String(child));
		else node.appendChild(child);
	};
	append(children);
	Object.defineProperty(node, 'firstChild', {
		get: function() { return this.children.length ? this.children[0] : null; }
	});
	Object.defineProperty(node, 'lastChild', {
		get: function() { return this.children[this.children.length - 1]; }
	});
	Object.defineProperty(node, 'textContent', {
		get: function() { return this.children.map(fakeElementText).join(''); },
		set: function(value) {
			this.children.forEach(function(child) {
				if (child && typeof child === 'object') child.parentNode = null;
			});
			this.children = [];
			if (value !== null && value !== undefined && String(value) !== '')
				this.appendChild(String(value));
		}
	});
	Object.defineProperty(node, 'className', {
		get: function() { return this._className; },
		set: function(value) {
			this._className = String(value);
			this.attrs.class = this._className;
		}
	});
	Object.defineProperty(node, 'hidden', {
		get: function() { return this._hidden; },
		set: function(value) {
			this._hidden = Boolean(value);
			if (this._hidden) this.attrs.hidden = 'hidden';
			else delete this.attrs.hidden;
		}
	});
	Object.defineProperty(node, 'disabled', {
		get: function() { return this._disabled; },
		set: function(value) {
			this._disabled = Boolean(value);
			if (this._disabled) this.attrs.disabled = 'disabled';
			else delete this.attrs.disabled;
		}
	});
	Object.defineProperty(node, 'value', {
		get: function() { return this._value; },
		set: function(value) {
			this._value = value === null || value === undefined ? '' : String(value);
			this.attrs.value = this._value;
		}
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

function walkFakeElements(node, visit) {
	if (!node || typeof node !== 'object') return;
	visit(node);
	(node.children || []).forEach(function(child) {
		walkFakeElements(child, visit);
	});
}

function findFakeElementsByClass(node, className) {
	const matches = [];
	walkFakeElements(node, function(child) {
		const classes = String(child.attrs && child.attrs.class || '').split(/\s+/);
		if (classes.includes(className)) matches.push(child);
	});
	return matches;
}

function findFakeElementsByTag(node, tagName) {
	const matches = [];
	walkFakeElements(node, function(child) {
		if (child.tagName === tagName) matches.push(child);
	});
	return matches;
}

function fakeElementText(node) {
	if (node === null || node === undefined) return '';
	if (typeof node !== 'object') return String(node);
	return (node.children || []).map(fakeElementText).join('');
}

function makeDeferred() {
	let resolve, reject;
	const promise = new Promise(function(onResolve, onReject) {
		resolve = onResolve;
		reject = onReject;
	});
	return { promise: promise, resolve: resolve, reject: reject };
}

function fakeGeoLocationModule() {
	return {
		createResolver: function() {
			return {
				peek: function() {
					return { kind: 'reserved', label: '保留/未知', queryable: false };
				},
				resolve: function() {
					return Promise.resolve({ kind: 'unknown', label: '未知', queryable: false });
				},
				dispose: function() {}
			};
		}
	};
}

function fakeUiModule() {
	return {
		showModal: function() {},
		hideModal: function() {},
		addNotification: function() {},
		changes: { apply: function() {} }
	};
}

function fakeDhcpHostnamesModule() {
	return {
		identityMac: function(identityKey) {
			const value = String(identityKey || '').split('@')[0];
			return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(value) ? value.toLowerCase() : '';
		},
		loadForMac: function(mac) {
			return Promise.resolve({ available: Boolean(mac), host: null });
		},
		normalizeName: function(value) {
			const name = String(value === null || value === undefined ? '' : value).trim();
			if (name && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(name))
				throw new Error('invalid hostname');
			return name;
		},
		saveForMac: function(mac, name) {
			return Promise.resolve({ changed: true, name: name });
		}
	};
}

function loadClientDetailViewModule(src, fmt, lsRpc, shell, refresh, fakeWindow, fakeDate, fakeGeo) {
	const fakeBaseclass = { extend: function(value) { return value; } };
	return vm.compileFunction(src, [
		'baseclass', 'ui', 'fmt', 'lsRpc', 'dhcpHostnames', 'geoLocation',
		'clientDetailShell', 'clientDetailRefresh', 'window', 'Date', 'E', '_'
	], { filename: 'resources/lanspeed/clientDetailView.js' })(
		fakeBaseclass, fakeUiModule(), fmt, lsRpc, fakeDhcpHostnamesModule(),
		fakeGeo || fakeGeoLocationModule(), shell, refresh, fakeWindow,
		fakeDate || Date, fakeElement, function(value) { return value; }
	);
}

function assertClientDetailViewSource(src) {
	if (JSON.stringify(moduleRequireNames(src)) !== JSON.stringify([
		'baseclass', 'ui', 'lanspeed.format', 'lanspeed.rpc',
		'lanspeed.dhcpHostnames', 'lanspeed.geoLocation',
		'lanspeed.clientDetailShell', 'lanspeed.clientDetailRefresh'
	])) {
		fail('clientDetailView.js must require UI, format, shared RPC, DHCP hostnames, geolocation, detail shell and detail refresh in dependency order');
	}
	const cleaned = stripComments(src);
	if (/\brpc\s*\.\s*declare\b|innerHTML|\bCSS\b|groupsForResponse|formatEndpoint/.test(cleaned)) {
		fail('clientDetailView.js must own lifecycle and hostname dialog behavior without RPC declarations, CSS, or connection grouping logic');
	}
	if (!src.includes('lsRpc.clientConnections(identityKey)') ||
	    /lsRpc\.(?:status|clients|interfaces|uciGet|overview)\s*\(/.test(cleaned)) {
		fail('clientDetailView.js load/reload must call only the shared clientConnections RPC');
	}
}

function assertClientDetailViewLifecycle(src) {
	const fixture = JSON.parse(fs.readFileSync(
		path.join(root, 'tests/fixtures/lanspeed-client-connections.json'), 'utf8'
	));
	const success = JSON.parse(JSON.stringify(fixture));
	success.sample_ms = 23456;
	const goodB = JSON.parse(JSON.stringify(fixture));
	goodB.connections[0].remote_ip = '2.2.2.2';
	goodB.connections = [ goodB.connections[0] ];
	goodB.total_connections = 1;
	goodB.returned_connections = 1;
	const unavailable = Object.assign({}, fixture, {
		available: false,
		sample_ms: null,
		total_connections: 0,
		returned_connections: 0,
		connections: [],
		warnings: [ 'conntrack_unavailable' ]
	});
	const successDeferred = makeDeferred();
	const rejectDeferred = makeDeferred();
	const unavailableRejectDeferred = makeDeferred();
	const responses = [
		Promise.resolve(fixture),
		successDeferred.promise,
		rejectDeferred.promise,
		Promise.resolve(unavailable),
		unavailableRejectDeferred.promise,
		Promise.resolve(goodB)
	];
	let rpcCount = 0;
	const lsRpc = {
		clientConnections: function(identityKey) {
			rpcCount++;
			if (identityKey !== '30:c5:0a@eth1')
				fail('clientDetailView.js must pass the decoded identity unchanged to every RPC');
			return responses.shift();
		},
		status: function() { throw new Error('unexpected status RPC'); },
		clients: function() { throw new Error('unexpected clients RPC'); },
		interfaces: function() { throw new Error('unexpected interfaces RPC'); },
		uciGet: function() { throw new Error('unexpected uci RPC'); }
	};
	const timers = new Map();
	const listeners = {};
	const events = [];
	let timerId = 0;
	let now = new Date(2026, 0, 2, 3, 4, 5).getTime();
	let storedDetailPrefs = JSON.stringify({ refreshMs: 1000, paused: false });
	const fakeDate = { now: function() { return now; } };
	const fakeWindow = {
		location: {
			pathname: '/cgi-bin/luci/admin/status/lanspeed/overview',
			search: '?client=old',
			assigned: null,
			assign: function(value) { this.assigned = value; }
		},
		setTimeout: function(handler, interval) {
			const id = ++timerId;
			timers.set(id, { handler: handler, interval: interval });
			events.push('timer:' + interval);
			return id;
		},
		clearTimeout: function(id) { timers.delete(id); },
		addEventListener: function(type, handler) { listeners[type] = handler; },
		localStorage: {
			getItem: function(key) {
				return key === 'luci-app-lanspeed.detail-prefs.v1'
					? storedDetailPrefs : null;
			},
			setItem: function(key, value) {
				if (key !== 'luci-app-lanspeed.detail-prefs.v1')
					fail('clientDetailView.js must not overwrite the LAN client preference key');
				storedDetailPrefs = value;
			}
		}
	};
	let shellState = null;
	const shell = {
		buildShell: function(viewState) {
			shellState = viewState;
			return { root: fakeElement('div', {}), refs: { refresh: fakeElement('button', {}) } };
		}
	};
	const renders = [];
	const refresh = {
		render: function(viewState) {
			renders.push({
				state: viewState,
				loading: viewState.loading,
				manualLoading: viewState.manualLoading,
				response: viewState.response,
				error: viewState.error
			});
			events.push('render:' + String(viewState.loading));
		}
	};
	const fmt = {
		MIN_REFRESH_MS: 1000,
		DEFAULT_PREFS: { refreshMs: 3000 },
		REFRESH_CHOICES: [
			{ value: 1000, label: '1s' },
			{ value: 3000, label: '3s' },
			{ value: 5000, label: '5s' }
		],
		nextSort: nextDetailSort,
		loadPrefs: function() { return { refreshMs: 250, paused: false }; }
	};

	asyncChecks.push(Promise.resolve().then(async function() {
		const view = loadClientDetailViewModule(src, fmt, lsRpc, shell, refresh, fakeWindow, fakeDate);
		const loaded = await view.load('30:c5:0a@eth1');
		if (!loaded || loaded.identityKey !== '30:c5:0a@eth1' ||
		    loaded.response !== fixture || loaded.updatedAt !== now ||
		    loaded.error !== null || rpcCount !== 1) {
			fail('clientDetailView.js load must make exactly one clientConnections RPC and stamp a successful initial response with the browser receive time');
		}
		const rootNode = view.render(loaded);
		const state = shellState;
		const requiredFields = [
			'identityKey', 'response', 'lastGood', 'updatedAt', 'protocol', 'filter', 'expanded',
			'sortKey', 'sortDir', 'sortCustom',
			'prefs', 'timer', 'loading', 'manualLoading', 'reload', 'schedule', 'stopTimer',
			'setProtocol', 'setFilter', 'setSort', 'setRefreshMs', 'setPaused',
			'locationLabelFor',
			'requestLocations', 'destroy', 'back'
		];
		if (!rootNode || !state || requiredFields.some(function(name) {
			return !Object.prototype.hasOwnProperty.call(state, name);
		}) || state.lastGood !== fixture || state.protocol !== 'all' ||
		    state.filter !== '' || state.sortKey !== 'rx' || state.sortDir !== 'desc' ||
		    state.sortCustom !== false || state.loading !== false || timers.size !== 1 ||
		    Array.from(timers.values())[0].interval !== 1000) {
			fail('clientDetailView.js render must initialize RX-descending detail sort state and schedule at MIN_REFRESH_MS when detail refresh is enabled');
		}
		state.setRefreshMs(5000);
		state.setPaused();
		if (state.prefs.refreshMs !== 5000 || !state.prefs.paused || timers.size !== 0 ||
		    JSON.stringify(JSON.parse(storedDetailPrefs)) !==
			JSON.stringify({ refreshMs: 5000, paused: true })) {
			fail('clientDetailView.js must persist detail refresh interval and pause state under its independent preference key');
		}
		state.setPaused();
		state.setRefreshMs(1000);
		if (state.prefs.paused || timers.size !== 1 ||
		    Array.from(timers.values())[0].interval !== 1000) {
			fail('clientDetailView.js must resume and reschedule only the detail refresh timer');
		}

		const rendersBeforeInitialSort = renders.length;
		state.setSort('remote_ip');
		if (state.sortKey !== 'remote_ip' || state.sortDir !== 'desc' ||
		    state.sortCustom !== true || renders.length !== rendersBeforeInitialSort + 1 ||
		    rpcCount !== 1 || timers.size !== 1) {
			fail('clientDetailView.js must start a clicked detail column at descending without RPC or timer changes');
		}

		const beforeReloadEvents = events.length;
		const scheduledEntry = Array.from(timers.entries())[0];
		timers.delete(scheduledEntry[0]);
		scheduledEntry[1].handler();
		const firstReload = state.reload(false);
		if (rpcCount !== 2 || timers.size !== 0 || state.loading !== true ||
		    state.manualLoading !== false || renders[renders.length - 1].loading !== true ||
		    renders[renders.length - 1].manualLoading !== false) {
			fail('clientDetailView.js automatic reload must stop its elapsed timer, render loading immediately, and share one pending Promise with duplicate reload calls');
		}
		const manualJoin = state.reload(true);
		const duplicateReload = state.reload(true);
		if (firstReload !== manualJoin || firstReload !== duplicateReload || rpcCount !== 2 ||
		    state.manualLoading !== true || renders[renders.length - 1].manualLoading !== true) {
			fail('clientDetailView.js manual refresh during an automatic request must reuse the pending RPC and only then expose manual loading state');
		}
		if (events.slice(beforeReloadEvents).some(function(event) { return event.indexOf('timer:') === 0; }))
			fail('clientDetailView.js must never schedule the next timer while a reload Promise is pending');
		now = new Date(2026, 0, 2, 3, 5, 6).getTime();
		const successUpdatedAt = now;
		successDeferred.resolve(success);
		await firstReload;
		const settledEvents = events.slice(beforeReloadEvents);
		if (state.loading || state.response !== success || state.lastGood !== success ||
		    state.updatedAt !== successUpdatedAt || state.error !== null ||
		    state.sortKey !== 'remote_ip' || state.sortDir !== 'desc' || !state.sortCustom ||
		    timers.size !== 1 || settledEvents[settledEvents.length - 2] !== 'render:false' ||
		    settledEvents[settledEvents.length - 1] !== 'timer:1000') {
			fail('clientDetailView.js successful automatic reload must retain sorting, replace response/lastGood, render loading=false, then schedule exactly one timer');
		}

		const failedReload = state.reload();
		if (timers.size !== 0) fail('clientDetailView.js must clear the scheduled timer before a transport-failing reload');
		rejectDeferred.reject(new Error('network down'));
		await failedReload;
		if (state.loading || state.lastGood !== success || state.response !== success ||
		    state.updatedAt !== successUpdatedAt || !state.error || timers.size !== 1) {
			fail('clientDetailView.js transport rejection must keep the last good response visible, expose the error, and resume scheduling');
		}

		now = new Date(2026, 0, 2, 3, 6, 7).getTime();
		const unavailableUpdatedAt = now;
		await state.reload();
		if (state.response !== unavailable || state.lastGood !== null ||
		    state.updatedAt !== unavailableUpdatedAt || state.error !== null ||
		    state.loading || timers.size !== 1) {
			fail('clientDetailView.js available:false success must become the current successful response, clear stale lastGood, and update receive time');
		}

		const unavailableFailure = state.reload();
		unavailableRejectDeferred.reject(new Error('still down'));
		await unavailableFailure;
		if (state.response !== unavailable || state.lastGood !== null ||
		    state.updatedAt !== unavailableUpdatedAt || !state.error || timers.size !== 1) {
			fail('clientDetailView.js reject after available:false must retain the unavailable empty response without resurrecting older good rows or changing receive time');
		}

		now = new Date(2026, 0, 2, 3, 7, 8).getTime();
		const goodBUpdatedAt = now;
		await state.reload();
		if (state.response !== goodB || state.lastGood !== goodB ||
		    state.updatedAt !== goodBUpdatedAt || state.error !== null || timers.size !== 1) {
			fail('clientDetailView.js next successful available response must replace the unavailable state with only the new data and receive time');
		}

		const rpcBeforeLocalControls = rpcCount;
		const rendersBeforeLocalControls = renders.length;
		state.setProtocol('tcp');
		state.setFilter('443');
		if (state.protocol !== 'tcp' || state.filter !== '443' ||
		    state.sortKey !== 'remote_ip' || state.sortDir !== 'desc' || !state.sortCustom ||
		    rpcCount !== rpcBeforeLocalControls || renders.length !== rendersBeforeLocalControls + 2) {
			fail('clientDetailView.js protocol/search controls must retain detail sorting and render local state only without issuing RPC');
		}
		state.setSort('remote_ip');
		if (state.sortKey !== 'remote_ip' || state.sortDir !== 'asc' || !state.sortCustom)
			fail('clientDetailView.js must switch an explicit descending detail sort to ascending');
		state.setSort('remote_ip');
		if (state.sortKey !== 'rx' || state.sortDir !== 'desc' || state.sortCustom)
			fail('clientDetailView.js must restore default RX descending after the ascending detail sort');
		state.setSort('rx');
		if (state.sortKey !== 'rx' || state.sortDir !== 'desc' || !state.sortCustom)
			fail('clientDetailView.js must distinguish an explicit RX descending click from default sorting');
		state.setSort('rx');
		if (state.sortKey !== 'rx' || state.sortDir !== 'asc' || !state.sortCustom)
			fail('clientDetailView.js must let the default RX header advance to explicit ascending');
		state.setSort('rx');
		if (state.sortKey !== 'rx' || state.sortDir !== 'desc' || state.sortCustom)
			fail('clientDetailView.js detail header clicks must cycle descending, ascending, then default RX descending');
		if (rpcCount !== rpcBeforeLocalControls)
			fail('clientDetailView.js detail sorting must stay local and issue no RPC');

		state.schedule();
		if (timers.size !== 1) fail('clientDetailView.js schedule must replace, not accumulate, timers');
		listeners.beforeunload();
		if (timers.size !== 0) fail('clientDetailView.js beforeunload must leave no detail refresh timer behind');
		state.schedule();
		state.back();
		if (timers.size !== 0 || fakeWindow.location.assigned !== fakeWindow.location.pathname) {
			fail('clientDetailView.js back must stop the timer and navigate to the current LAN pathname without a client query or hard-coded host');
		}

		let failingCalls = 0;
		const firstFailureView = loadClientDetailViewModule(src, fmt, {
			clientConnections: function() {
				failingCalls++;
				return Promise.reject(new Error('initial network down'));
			}
		}, shell, refresh, fakeWindow, fakeDate);
		const failedInitial = await firstFailureView.load('30:c5:0a@eth1');
		if (!failedInitial || failedInitial.identityKey !== '30:c5:0a@eth1' ||
		    failedInitial.response !== null || failedInitial.updatedAt !== null ||
		    !failedInitial.error || failingCalls !== 1) {
			fail('clientDetailView.js must convert an initial transport rejection into renderable data without crashing the LuCI page');
		}
	}).catch(function(err) {
		fail('clientDetailView.js lifecycle behavior could not execute: ' + (err && err.stack || err));
	}));
}

function assertClientDetailGeoLifecycle(src) {
	const deferred = Object.create(null);
	const cached = Object.create(null);
	const resolveCalls = [];
	let disposeCalls = 0;
	const resolver = {
		peek: function(ip) {
			return cached[ip] || { kind: 'public', label: '查询中…', queryable: true };
		},
		resolve: function(ip) {
			resolveCalls.push(ip);
			deferred[ip] = makeDeferred();
			return deferred[ip].promise.then(function(value) {
				cached[ip] = value;
				return value;
			});
		},
		dispose: function() { disposeCalls++; }
	};
	const geo = { createResolver: function() { return resolver; } };
	const listeners = {};
	const timers = new Map();
	let timerId = 0;
	const fakeWindow = {
		location: { pathname: '/admin/status/lanspeed/overview', assign: function() {} },
		setTimeout: function(handler, interval) {
			const id = ++timerId;
			timers.set(id, { handler: handler, interval: interval });
			return id;
		},
		clearTimeout: function(id) { timers.delete(id); },
		addEventListener: function(type, handler) { listeners[type] = handler; }
	};
	let state = null;
	const shell = { buildShell: function(viewState) {
		state = viewState;
		return { root: fakeElement('div', {}), refs: {} };
	} };
	let renders = 0;
	const refresh = { render: function() { renders++; } };
	const fmt = {
		MIN_REFRESH_MS: 1000,
		DEFAULT_PREFS: { refreshMs: 3000 },
		nextSort: nextDetailSort,
		loadPrefs: function() { return { refreshMs: 1000 }; }
	};
	const view = loadClientDetailViewModule(
		src, fmt, { clientConnections: function() { return Promise.resolve({}); } },
		shell, refresh, fakeWindow, Date, geo
	);

	asyncChecks.push(Promise.resolve().then(async function() {
		view.render({ identityKey: 'geo@lan', response: { available: true } });
		const initialRenders = renders;
		state.requestLocations([ '8.8.8.8', '1.1.1.1', '8.8.8.8' ]);
		state.requestLocations([ '8.8.8.8', '1.1.1.1', '8.8.8.8' ]);
		if (JSON.stringify(resolveCalls) !== JSON.stringify([ '8.8.8.8', '1.1.1.1' ]))
			fail('clientDetailView.js must deduplicate a current-page geolocation batch and reuse it across renders');
		deferred['8.8.8.8'].resolve({ kind: 'country', label: '美国', queryable: false });
		await Promise.resolve();
		await Promise.resolve();
		if (renders !== initialRenders)
			fail('clientDetailView.js must not redraw once per geolocation result');
		deferred['1.1.1.1'].resolve({ kind: 'country', label: '美国', queryable: false });
		await Promise.resolve();
		await Promise.resolve();
		await Promise.resolve();
		if (renders !== initialRenders + 1)
			fail('clientDetailView.js must coalesce a completed current-page geolocation batch into one redraw');

		state.requestLocations([ '9.9.9.9' ]);
		state.requestLocations([]);
		const beforeStaleCompletion = renders;
		deferred['9.9.9.9'].resolve({ kind: 'country', label: '瑞士', queryable: false });
		await Promise.resolve();
		await Promise.resolve();
		await Promise.resolve();
		if (renders !== beforeStaleCompletion + 1)
			fail('clientDetailView.js must redraw after cached results arrive so country/region search can reveal a match');

		state.requestLocations([ '4.4.4.4' ]);
		const beforeUnload = renders;
		listeners.beforeunload();
		deferred['4.4.4.4'].resolve({ kind: 'country', label: '美国', queryable: false });
		await Promise.resolve();
		await Promise.resolve();
		await Promise.resolve();
		if (disposeCalls !== 1 || renders !== beforeUnload || timers.size !== 0)
			fail('clientDetailView.js must dispose geolocation work and suppress late redraws on unload');
	}).catch(function(err) {
		fail('clientDetailView.js geolocation lifecycle could not execute: ' + (err && err.stack || err));
	}));
}

function assertClientDetailIntegratedState(viewSrc) {
	const fixture = JSON.parse(fs.readFileSync(
		path.join(root, 'tests/fixtures/lanspeed-client-connections.json'), 'utf8'
	));
	const goodA = JSON.parse(JSON.stringify(fixture));
	goodA.connections = [ Object.assign({}, goodA.connections[0], { remote_ip: '1.1.1.1' }) ];
	goodA.total_connections = 1;
	goodA.returned_connections = 1;
	const unavailable = Object.assign({}, fixture, {
		available: false,
		sample_ms: null,
		total_connections: 0,
		returned_connections: 0,
		connections: [],
		warnings: [ 'conntrack_unavailable' ]
	});
	const goodB = JSON.parse(JSON.stringify(fixture));
	goodB.connections = [ Object.assign({}, goodB.connections[0], { remote_ip: '2.2.2.2' }) ];
	goodB.total_connections = 1;
	goodB.returned_connections = 1;
	const refresh = loadClientDetailRefreshModule(readModuleByName('clientDetailRefresh.js'));
	let now = new Date(2026, 0, 2, 3, 4, 5).getTime();
	const fakeDate = { now: function() { return now; } };

	function harness(prefs, rpcResponses) {
		const timers = new Map();
		let timerId = 0;
		let state = null;
		let built = null;
		const fakeWindow = {
			location: { pathname: '/admin/status/lanspeed/overview', assign: function() {} },
			setTimeout: function(handler, interval) {
				const id = ++timerId;
				timers.set(id, { handler: handler, interval: interval });
				return id;
			},
			clearTimeout: function(id) { timers.delete(id); },
			addEventListener: function() {}
		};
		const shell = { buildShell: function(viewState) {
			state = viewState;
			built = buildClientDetailShellForRefresh(viewState);
			return built;
		} };
		const queue = rpcResponses.slice();
		const view = loadClientDetailViewModule(viewSrc, {
			MIN_REFRESH_MS: 1000,
			DEFAULT_PREFS: { refreshMs: 3000 },
			nextSort: nextDetailSort,
			loadPrefs: function() { return Object.assign({}, prefs); }
		}, {
			clientConnections: function() { return queue.shift(); }
		}, shell, refresh, fakeWindow, fakeDate);
		return {
			view: view,
			timers: timers,
			state: function() { return state; },
			built: function() { return built; }
		};
	}

	asyncChecks.push(Promise.resolve().then(async function() {
		const sequence = harness({ refreshMs: 1000, paused: false }, [
			Promise.resolve(goodA),
			Promise.resolve(unavailable),
			Promise.reject(new Error('transport still down')),
			Promise.resolve(goodB)
		]);
		const initial = await sequence.view.load('fixture@lan');
		sequence.view.render(initial);
		let tbody = sequence.built().refs.tbody;
		if (!fakeElementText(tbody).includes('1.1.1.1') || fakeElementText(tbody).includes('2.2.2.2'))
			fail('client detail integration must initially render only good response A');

		now = new Date(2026, 0, 2, 3, 5, 6).getTime();
		await sequence.state().reload();
		if (tbody.children.length !== 0 || sequence.state().lastGood !== null)
			fail('client detail integration must clear table rows and stale lastGood after available:false success');
		const unavailableTime = sequence.built().refs.summaryUpdated.textContent;
		await sequence.state().reload();
		if (tbody.children.length !== 0 || fakeElementText(tbody).includes('1.1.1.1') ||
		    sequence.state().response !== unavailable ||
		    sequence.built().refs.summaryUpdated.textContent !== unavailableTime ||
		    !fakeElementText(sequence.built().refs.error).includes('连接数据仍不可用')) {
			fail('client detail integration must keep unavailable rows empty and receive time unchanged after the following transport rejection');
		}

		now = new Date(2026, 0, 2, 3, 6, 7).getTime();
		await sequence.state().reload();
		if (!fakeElementText(tbody).includes('2.2.2.2') || fakeElementText(tbody).includes('1.1.1.1') ||
		    sequence.built().refs.summaryUpdated.textContent !== '03:06:07') {
			fail('client detail integration must replace unavailable state with only good response B and its new browser receive time');
		}

		const recovery = harness({ refreshMs: 1000, paused: false }, [
			Promise.reject(new Error('initial down')),
			Promise.resolve(goodB)
		]);
		const failedInitial = await recovery.view.load('fixture@lan');
		recovery.view.render(failedInitial);
		if (!fakeElementText(recovery.built().refs.empty).includes('首次加载连接详情失败'))
			fail('client detail integration must render an initial transport rejection without stale rows');
		now = new Date(2026, 0, 2, 3, 7, 8).getTime();
		await recovery.state().reload();
		if (!fakeElementText(recovery.built().refs.tbody).includes('2.2.2.2') ||
		    !recovery.built().refs.error.hidden ||
		    recovery.built().refs.summaryUpdated.textContent !== '03:07:08') {
			fail('client detail integration must recover from initial rejection on the next successful response');
		}

		for (const invalid of [ null, 'not-a-number', Infinity, -1 ]) {
			now = new Date(2026, 0, 2, 3, 8, 9).getTime();
			const invalidPrefs = harness({ refreshMs: invalid, paused: false }, []);
			invalidPrefs.view.render({
				identityKey: 'fixture@lan', response: fixture, error: null
			});
			const interval = Array.from(invalidPrefs.timers.values())[0].interval;
			if (invalidPrefs.state().prefs.refreshMs !== 3000 || interval !== 3000 ||
			    !fakeElementText(invalidPrefs.built().refs.footer).includes('每 3 秒自动刷新') ||
			    invalidPrefs.state().updatedAt !== now) {
				fail('clientDetailView.js must normalize invalid refreshMs to 3000ms, schedule when enabled, and stamp direct initial responses');
			}
		}

		const sortA = JSON.parse(JSON.stringify(fixture));
		const sortB = JSON.parse(JSON.stringify(fixture));
		sortB.connections.reverse();
		const sortASnapshot = JSON.stringify(sortA);
		const sortBSnapshot = JSON.stringify(sortB);
		const sortedRefresh = harness({ refreshMs: 1000, paused: false }, [
			Promise.resolve(sortA), Promise.resolve(sortB)
		]);
		const sortedInitial = await sortedRefresh.view.load('fixture@lan');
		sortedRefresh.view.render(sortedInitial);
		sortedRefresh.state().setSort('remote_ip');
		sortedRefresh.state().setSort('remote_ip');
		let sortedIps = findFakeElementsByClass(
			sortedRefresh.built().refs.tbody, 'lanspeed-connection-group'
		).map(function(row) { return row.attrs['data-remote-ip']; });
		if (sortedRefresh.state().sortKey !== 'remote_ip' ||
		    sortedRefresh.state().sortDir !== 'asc' ||
		    !sortedRefresh.state().sortCustom ||
		    JSON.stringify(sortedIps) !== JSON.stringify([
			    '198.51.100.53', '2001:db8:ffff::20'
		    ])) {
			fail('client detail integration must apply an explicit sort before automatic refresh');
		}
		const timerEntry = Array.from(sortedRefresh.timers.entries())[0];
		sortedRefresh.timers.delete(timerEntry[0]);
		const originalReload = sortedRefresh.state().reload;
		let automaticReload = null;
		sortedRefresh.state().reload = function() {
			automaticReload = originalReload.apply(this, arguments);
			return automaticReload;
		};
		timerEntry[1].handler();
		await automaticReload;
		sortedIps = findFakeElementsByClass(
			sortedRefresh.built().refs.tbody, 'lanspeed-connection-group'
		).map(function(row) { return row.attrs['data-remote-ip']; });
		if (sortedRefresh.state().response !== sortB ||
		    sortedRefresh.state().sortKey !== 'remote_ip' ||
		    sortedRefresh.state().sortDir !== 'asc' ||
		    !sortedRefresh.state().sortCustom ||
		    JSON.stringify(sortedIps) !== JSON.stringify([
			    '198.51.100.53', '2001:db8:ffff::20'
		    ]) || JSON.stringify(sortA) !== sortASnapshot ||
		    JSON.stringify(sortB) !== sortBSnapshot) {
			fail('client detail automatic refresh must retain and reapply sorting without mutating either RPC response');
		}
	}).catch(function(err) {
		fail('integrated client detail state behavior could not execute: ' + (err && err.stack || err));
	}));
}

function loadClientDetailRefreshModule(src, fakeDate) {
	const fakeBaseclass = { extend: function(value) { return value; } };
	return vm.compileFunction(src, [
		'baseclass', 'fmt', 'clientConnections', 'E', '_', 'Date', 'document'
	], { filename: 'resources/lanspeed/clientDetailRefresh.js' })(
		fakeBaseclass,
		loadFormatModule(readModuleByName('format.js')),
		loadClientConnectionsModule(readModuleByName('clientConnections.js')),
		fakeElement,
		fakeTranslate,
		fakeDate || Date,
		fakeDocument
	);
}

function buildClientDetailShellForRefresh(viewState) {
	const fakeBaseclass = { extend: function(value) { return value; } };
	const shell = vm.compileFunction(readModuleByName('clientDetailShell.js'), [
		'baseclass', 'lsTheme', 'clientDetailStyle', 'E', '_'
	], { filename: 'resources/lanspeed/clientDetailShell.js' })(
		fakeBaseclass, { applyRoot: function() {} }, { CSS: 'detail-css' },
		fakeElement, function(value) { return value; }
	);
	return shell.buildShell(viewState);
}

function assertClientDetailRefreshSource(src) {
	if (JSON.stringify(moduleRequireNames(src)) !== JSON.stringify([
		'baseclass', 'lanspeed.format', 'lanspeed.clientConnections'
	])) {
		fail('clientDetailRefresh.js must require only baseclass, format and pure client connection helpers in dependency order');
	}
	const cleaned = stripComments(src);
	if (/\brpc\b|set(?:Timeout|Interval)|clear(?:Timeout|Interval)|\bwindow\b|\blocation\s*\.\s*(?:href|assign|pathname|search)|innerHTML|\bCSS\b|clientDetailStyle/.test(cleaned)) {
		fail('clientDetailRefresh.js must remain a refs-only renderer without RPC, timers, location, innerHTML, or CSS responsibilities');
	}
	if (!src.includes('clientConnections.groupsForResponse') ||
	    !src.includes('clientConnections.sortGroups') ||
	    !src.includes('clientConnections.formatEndpoint') ||
	    !src.includes('viewState.requestLocations(pageGroups.map') ||
	    !src.includes("setAttribute('aria-sort'") ||
	    !src.includes("ascending ? '↑' : '↓'") ||
	    !src.includes('.textContent') || !/\bE\s*\(/.test(src)) {
		fail('clientDetailRefresh.js must sort grouped connection detail and refresh accessible sort headers through helpers, E(), and textContent');
	}
}

function assertClientDetailRefreshBehavior(src) {
	fakeDocument.activeElement = null;
	const refresh = loadClientDetailRefreshModule(src);
	if (!refresh || JSON.stringify(Object.keys(refresh).sort()) !== JSON.stringify([ 'render' ]) ||
	    typeof refresh.render !== 'function') {
		fail('clientDetailRefresh.js must export one explicit render(viewState) entry');
		return;
	}
	const fixture = JSON.parse(fs.readFileSync(
		path.join(root, 'tests/fixtures/lanspeed-client-connections.json'), 'utf8'
	));
	const fixtureSnapshot = JSON.stringify(fixture);
	const locationRequests = [];
	const state = {
		identityKey: fixture.client.identity_key,
		response: fixture,
		lastGood: fixture,
		updatedAt: new Date(2026, 0, 2, 3, 4, 5).getTime(),
		error: null,
		protocol: 'all',
		filter: '',
		expanded: {},
		sortKey: 'rx',
		sortDir: 'desc',
		sortCustom: false,
		prefs: { refreshMs: 1000, unit: 'bit' },
		loading: false,
		locationLabelFor: function(ip) {
			return ip === '198.51.100.53' ? '美国' : '保留/未知';
		},
		requestLocations: function(ips) {
			locationRequests.push(Array.from(ips));
		},
		back: function() {},
		setProtocol: function(protocol) { state.protocol = protocol; refresh.render(state); },
		setFilter: function(filter) { state.filter = filter; refresh.render(state); },
		setSort: function(sortKey) {
			if (!state.sortCustom || state.sortKey !== sortKey) {
				state.sortKey = sortKey;
				state.sortDir = 'desc';
				state.sortCustom = true;
			} else if (state.sortDir === 'desc') {
				state.sortDir = 'asc';
			} else {
				state.sortKey = 'rx';
				state.sortDir = 'desc';
				state.sortCustom = false;
			}
			refresh.render(state);
		},
		reload: function() {}
	};
	const built = buildClientDetailShellForRefresh(state);
	state.refs = built.refs;
	const refs = state.refs;
	refresh.render(state);

	const meta = fakeElementText(refs.clientMeta);
	const metaIps = findFakeElementsByClass(
		refs.clientMeta, 'lanspeed-connection-meta-ip'
	).map(fakeElementText);
	const metaFacts = findFakeElementsByClass(
		refs.clientMeta, 'lanspeed-connection-meta-fact'
	).map(fakeElementText);
	const metaCounts = findFakeElementsByClass(
		refs.clientMeta, 'lanspeed-connection-meta-count'
	).map(fakeElementText);
	const footer = fakeElementText(refs.footer);
	const rows = refs.tbody.children;
	const initialGroupOrder = findFakeElementsByClass(
		refs.tbody, 'lanspeed-connection-group'
	).map(function(row) { return row.attrs['data-remote-ip']; });
	if (fakeElementText(refs.clientName) !== 'fixture-client' ||
	    !meta.includes('192.0.2.10') || !meta.includes('02:00:00:00:00:01') ||
	    !meta.includes('br-lan') || meta.includes('区域') ||
	    JSON.stringify(metaIps) !== JSON.stringify([ '192.0.2.10', '2001:db8:1::10' ]) ||
	    JSON.stringify(metaFacts) !== JSON.stringify([
		    'MAC 地址02:00:00:00:00:01', '接口br-lan'
	    ]) ||
	    JSON.stringify(metaCounts) !== JSON.stringify([ '2' ]) ||
	    !fakeElementText(refs.connectionState).includes('有当前连接') ||
	    refs.summaryTargets.textContent !== '2' || refs.summaryConnections.textContent !== '2' ||
	    refs.summaryUpdated.textContent !== '03:04:05' ||
	    refs.summaryUpdated.textContent.includes('12345') || rows.length !== 4 ||
	    JSON.stringify(initialGroupOrder) !== JSON.stringify([
		    '2001:db8:ffff::20', '198.51.100.53'
	    ]) ||
	    refs.table.hidden || !refs.empty.hidden || !refs.error.hidden) {
		fail('clientDetailRefresh.js must render identity/meta, real summaries, and destination groups with highest download speed first by default');
	}
	if (!footer.includes('连接数据') || !footer.includes('Conntrack Netlink') ||
	    !footer.includes('显示 2 / 共 2 条') ||
	    !footer.includes('每 1 秒自动刷新') ||
	    !footer.includes('国家/地区及中国省份按 IP 推测，由浏览器查询并缓存')) {
		fail('clientDetailRefresh.js footer must report source/count/refresh meanings and disclose browser-cached IP inference');
	}
	if (JSON.stringify(locationRequests[0]) !== JSON.stringify([
		'2001:db8:ffff::20', '198.51.100.53'
	])) {
		fail('clientDetailRefresh.js must request geolocation only for the deduplicated groups on the rendered page');
	}
	state.pageSize = 1;
	state.page = 0;
	refresh.render(state);
	state.page = 1;
	refresh.render(state);
	if (JSON.stringify(locationRequests.slice(-2)) !== JSON.stringify([
		[ '2001:db8:ffff::20' ], [ '198.51.100.53' ]
	])) {
		fail('clientDetailRefresh.js must never request geolocation for groups outside the current page');
	}
	state.pageSize = 100;
	state.page = 0;
	refresh.render(state);

	const sortHeaders = refs.sortHeaders;
	const sortKeys = [
		'remote_ip', 'location', 'remote_port', 'protocol', 'state', 'tx', 'rx', 'count'
	];
	if (!sortHeaders || sortKeys.some(function(sortKey) { return !sortHeaders[sortKey]; })) {
		fail('clientDetailRefresh.js requires refs for all eight sortable detail headers');
	} else {
		const indicator = function(sortKey) {
			return sortHeaders[sortKey].button.lastChild.textContent;
		};
		const initialRxTitle = '下行：默认排序，点击开始降序排序';
		if (sortHeaders.rx.th.attrs['aria-sort'] !== 'descending' ||
		    sortHeaders.remote_ip.th.attrs['aria-sort'] !== 'none' ||
		    sortHeaders.rx.button.attrs.title !== initialRxTitle ||
		    sortHeaders.rx.button.attrs['aria-label'] !== initialRxTitle ||
		    indicator('rx') !== '' || indicator('remote_ip') !== '') {
			fail('clientDetailRefresh.js must expose default RX descending to assistive technology without a visual arrow');
		}

		sortHeaders.remote_ip.button.listeners.click();
		let remoteTitle = '目标 IP：当前降序，点击切换为升序';
		let sortedOrder = findFakeElementsByClass(
			refs.tbody, 'lanspeed-connection-group'
		).map(function(row) { return row.attrs['data-remote-ip']; });
		if (state.sortKey !== 'remote_ip' || state.sortDir !== 'desc' || !state.sortCustom ||
		    sortHeaders.remote_ip.th.attrs['aria-sort'] !== 'descending' ||
		    sortHeaders.rx.th.attrs['aria-sort'] !== 'none' || indicator('remote_ip') !== '↓' ||
		    sortHeaders.remote_ip.button.attrs.title !== remoteTitle ||
		    sortHeaders.remote_ip.button.attrs['aria-label'] !== remoteTitle ||
		    JSON.stringify(sortedOrder) !== JSON.stringify([
			    '2001:db8:ffff::20', '198.51.100.53'
		    ])) {
			fail('clientDetailRefresh.js must render an explicit descending detail sort with matching row order, aria-sort, title and indicator');
		}

		sortHeaders.remote_ip.button.listeners.click();
		remoteTitle = '目标 IP：当前升序，点击恢复默认排序';
		sortedOrder = findFakeElementsByClass(
			refs.tbody, 'lanspeed-connection-group'
		).map(function(row) { return row.attrs['data-remote-ip']; });
		if (state.sortDir !== 'asc' || !state.sortCustom ||
		    sortHeaders.remote_ip.th.attrs['aria-sort'] !== 'ascending' ||
		    indicator('remote_ip') !== '↑' ||
		    sortHeaders.remote_ip.button.attrs.title !== remoteTitle ||
		    sortHeaders.remote_ip.button.attrs['aria-label'] !== remoteTitle ||
		    JSON.stringify(sortedOrder) !== JSON.stringify([
			    '198.51.100.53', '2001:db8:ffff::20'
		    ])) {
			fail('clientDetailRefresh.js must render an explicit ascending detail sort with matching row order, aria-sort, title and indicator');
		}

		state.setProtocol('udp');
		if (state.sortKey !== 'remote_ip' || state.sortDir !== 'asc' || !state.sortCustom ||
		    findFakeElementsByClass(refs.tbody, 'lanspeed-connection-group').length !== 1) {
			fail('client detail protocol filtering must retain the selected sorting state');
		}
		state.setProtocol('all');
		state.setFilter('0');
		sortedOrder = findFakeElementsByClass(
			refs.tbody, 'lanspeed-connection-group'
		).map(function(row) { return row.attrs['data-remote-ip']; });
		if (state.sortKey !== 'remote_ip' || state.sortDir !== 'asc' || !state.sortCustom ||
		    JSON.stringify(sortedOrder) !== JSON.stringify([
			    '198.51.100.53', '2001:db8:ffff::20'
		    ])) {
			fail('client detail search must retain and apply the selected sorting state after filtering');
		}
		state.setFilter('');
		sortHeaders.remote_ip.button.listeners.click();
		if (state.sortKey !== 'rx' || state.sortDir !== 'desc' || state.sortCustom ||
		    sortHeaders.rx.th.attrs['aria-sort'] !== 'descending' || indicator('rx') !== '' ||
		    sortHeaders.remote_ip.th.attrs['aria-sort'] !== 'none' ||
		    indicator('remote_ip') !== '') {
			fail('clientDetailRefresh.js must restore the arrowless default RX-descending header after the third click');
		}

		sortHeaders.location.button.listeners.click();
		state.setFilter('美国');
		const locationGroups = findFakeElementsByClass(
			refs.tbody, 'lanspeed-connection-group'
		);
		if (state.sortKey !== 'location' || state.sortDir !== 'desc' || !state.sortCustom ||
		    sortHeaders.location.th.attrs['aria-sort'] !== 'descending' ||
		    indicator('location') !== '↓' || locationGroups.length !== 1 ||
		    locationGroups[0].attrs['data-remote-ip'] !== '198.51.100.53' ||
		    !fakeElementText(locationGroups[0]).includes('美国')) {
			fail('client detail country/region must be a sortable displayed field included in search');
		}
		state.setFilter('');
		sortHeaders.location.button.listeners.click();
		sortHeaders.location.button.listeners.click();
		if (state.sortKey !== 'rx' || state.sortDir !== 'desc' || state.sortCustom)
			fail('client detail country/region sort must use the shared descending/ascending/default cycle');
	}
	if (JSON.stringify(fixture) !== fixtureSnapshot) {
		fail('client detail rendering, sorting, protocol filtering and search must not mutate the RPC response');
	}
	const unorderedIpsResponse = JSON.parse(JSON.stringify(fixture));
	unorderedIpsResponse.client.ips = [
		'192.0.2.10', '2001:db8:1::10', 'fe80::1'
	];
	state.response = unorderedIpsResponse;
	refresh.render(state);
	if (JSON.stringify(findFakeElementsByClass(
		refs.clientMeta, 'lanspeed-connection-meta-ip'
	).map(fakeElementText)) !== JSON.stringify([
		'192.0.2.10', 'fe80::1', '2001:db8:1::10'
	])) {
		fail('clientDetailRefresh.js must place link-local IPv6 before public IPv6 while preserving IPv4 first');
	}
	state.response = fixture;
	refresh.render(state);
	const allCells = findFakeElementsByTag(refs.tbody, 'td');
	if (allCells.length !== 18 || allCells.some(function(cell) {
		return !Object.prototype.hasOwnProperty.call(cell.attrs, 'data-label');
	})) {
		fail('clientDetailRefresh.js must give all eight group cells and the colspan detail cell mobile data-label text');
	}
	const groupRows = findFakeElementsByClass(refs.tbody, 'lanspeed-connection-group');
	const detailRows = findFakeElementsByClass(refs.tbody, 'lanspeed-connection-detail-row');
	if (groupRows.length !== 2 || detailRows.length !== 2 || groupRows.some(function(row) {
		return row.attrs.tabindex !== '0' || row.attrs.role !== 'button' ||
			row.attrs['aria-expanded'] !== 'false';
	}) || detailRows.some(function(row) {
		return !row.hidden || findFakeElementsByTag(row, 'td')[0].attrs.colspan !== '8';
	})) {
		fail('clientDetailRefresh.js group/detail rows must expose button semantics, aria-expanded, colspan=8 and real hidden collapse state');
	}
	const detailCopy = detailRows.map(fakeElementText).join(' ');
	if (!detailCopy.includes('出站') || !detailCopy.includes('UDP') || !detailCopy.includes('活跃') ||
	    !detailCopy.includes('192.0.2.10:53000 → 198.51.100.53:53') ||
	    !detailCopy.includes('入站') || !detailCopy.includes('TCP') || !detailCopy.includes('已建立') ||
	    !detailCopy.includes('[2001:db8:ffff::20]:54001 → [2001:db8:1::10]:443') ||
	    !detailCopy.includes('↑ 上行 8.00 Kbps') || !detailCopy.includes('↓ 下行 16.00 Kbps') ||
	    !detailCopy.includes('↑ 上行 32.00 Kbps') || !detailCopy.includes('↓ 下行 64.00 Kbps')) {
		fail('clientDetailRefresh.js detail rows must render direction/state, endpoints, and each connection upload/download rate');
	}
	const groupCopy = groupRows.map(fakeElementText).join(' ');
	if (!groupCopy.includes('8.00 Kbps') || !groupCopy.includes('16.00 Kbps') ||
	    !groupCopy.includes('32.00 Kbps') || !groupCopy.includes('64.00 Kbps') ||
	    !groupCopy.includes('美国') || !groupCopy.includes('保留/未知')) {
		fail('clientDetailRefresh.js group rows must render country/region and destination rate totals');
	}
	const rateCopy = findFakeElementsByClass(
		refs.tbody, 'lanspeed-connection-detail-rate'
	).map(fakeElementText);
	if (JSON.stringify(rateCopy) !== JSON.stringify([
		'↑ 上行 32.00 Kbps', '↓ 下行 64.00 Kbps',
		'↑ 上行 8.00 Kbps', '↓ 下行 16.00 Kbps'
	])) {
		fail('clientDetailRefresh.js must expose visible direction labels in default descending-download group order');
	}
	if (findFakeElementsByClass(refs.tbody, 'lanspeed-connection-detail-rate').some(function(rate) {
		var spans = findFakeElementsByTag(rate, 'span');
		return spans.length !== 2 || spans[1].attrs['aria-hidden'] !== 'true';
	})) {
		fail('clientDetailRefresh.js must hide decorative rate arrows from assistive technology');
	}

	let prevented = 0;
	const focusedGroup = groupRows[1];
	const focusedDetail = detailRows[1];
	const focusedChildIndex = refs.tbody.children.indexOf(focusedGroup);
	focusedGroup.focus();
	focusedGroup.listeners.keydown({ key: 'Enter', preventDefault: function() { prevented++; } });
	let currentGroups = findFakeElementsByClass(refs.tbody, 'lanspeed-connection-group');
	let currentDetails = findFakeElementsByClass(refs.tbody, 'lanspeed-connection-detail-row');
	if (prevented !== 1 || currentGroups[1] !== focusedGroup || currentDetails[1] !== focusedDetail ||
	    fakeDocument.activeElement !== focusedGroup ||
	    focusedGroup.attrs['aria-expanded'] !== 'true' || focusedDetail.hidden ||
	    state.expanded['198.51.100.53'] !== true) {
		fail('clientDetailRefresh.js Enter must toggle the existing row in place, prevent default, and preserve keyboard focus while expanding');
	}
	focusedGroup.listeners.keydown({ key: ' ', preventDefault: function() { prevented++; } });
	currentGroups = findFakeElementsByClass(refs.tbody, 'lanspeed-connection-group');
	currentDetails = findFakeElementsByClass(refs.tbody, 'lanspeed-connection-detail-row');
	if (prevented !== 2 || currentGroups[1] !== focusedGroup || currentDetails[1] !== focusedDetail ||
	    fakeDocument.activeElement !== focusedGroup ||
	    focusedGroup.attrs['aria-expanded'] !== 'false' || !focusedDetail.hidden ||
	    state.expanded['198.51.100.53'] !== false) {
		fail('clientDetailRefresh.js Space must toggle the existing row in place, prevent default, and preserve keyboard focus while collapsing');
	}
	focusedGroup.listeners.click({ preventDefault: function() { prevented++; } });
	if (prevented !== 3 || refs.tbody.children[focusedChildIndex] !== focusedGroup || focusedDetail.hidden ||
	    state.expanded['198.51.100.53'] !== true) {
		fail('clientDetailRefresh.js click must also toggle the existing group/detail rows without rebuilding the table');
	}
	refresh.render(state);
	currentGroups = findFakeElementsByClass(refs.tbody, 'lanspeed-connection-group');
	currentDetails = findFakeElementsByClass(refs.tbody, 'lanspeed-connection-detail-row');
	if (currentGroups[1] === focusedGroup ||
	    currentGroups[1].attrs['data-remote-ip'] !== '198.51.100.53' ||
	    fakeDocument.activeElement !== currentGroups[1] ||
	    currentGroups[1].attrs['aria-expanded'] !== 'true' || currentDetails[1].hidden) {
		fail('clientDetailRefresh.js refresh renders must restore keyboard focus to the rebuilt row for the same remote IP');
	}

	state.protocol = 'tcp';
	state.filter = '54001';
	refresh.render(state);
	if (state.expanded['198.51.100.53'] !== true ||
	    refs.protocolAll.attrs['aria-pressed'] !== 'false' ||
	    refs.protocolTcp.attrs['aria-pressed'] !== 'true' ||
	    !String(refs.protocolTcp.className).includes('active') ||
	    refs.protocolUdp.attrs['aria-pressed'] !== 'false' || refs.filter.value !== '54001') {
		fail('clientDetailRefresh.js must sync protocol aria/active classes and filter value without pruning temporarily filtered expanded groups');
	}
	state.response = Object.assign({}, fixture, { connections: [ fixture.connections[1] ] });
	state.lastGood = state.response;
	state.protocol = 'all';
	state.filter = '';
	refresh.render(state);
	if (Object.prototype.hasOwnProperty.call(state.expanded, '198.51.100.53'))
		fail('clientDetailRefresh.js must prune expanded destinations only when they disappear from the unfiltered response');

	state.response = fixture;
	state.lastGood = fixture;
	state.updatedAt = new Date(2026, 0, 2, 3, 4, 5).getTime();
	state.error = new Error('<img src=x onerror=alert(1)> network down');
	refresh.render(state);
	if (refs.error.hidden || !fakeElementText(refs.error).includes('刷新连接详情失败') ||
	    refs.tbody.children.length !== 4 || refs.table.hidden ||
	    refs.summaryUpdated.textContent !== '03:04:05' ||
	    findFakeElementsByTag(refs.error, 'img').length !== 0) {
		fail('clientDetailRefresh.js transport error must render the current successful response with safe Chinese error text and unchanged receive time');
	}

	state.error = null;
	state.response = Object.assign({}, fixture, {
		available: false,
		sample_ms: null,
		total_connections: 0,
		returned_connections: 0,
		warnings: [ 'conntrack_unavailable' ]
	});
	state.lastGood = null;
	state.updatedAt = new Date(2026, 0, 2, 3, 5, 6).getTime();
	refresh.render(state);
	if (refs.tbody.children.length !== 0 || !refs.table.hidden || refs.empty.hidden ||
	    !fakeElementText(refs.empty).includes('连接采集当前不可用') ||
	    refs.summaryUpdated.textContent !== '03:05:06') {
		fail('clientDetailRefresh.js available:false success must clear current rows and never leak last-good connection details');
	}
	state.error = new Error('still down');
	refresh.render(state);
	if (refs.tbody.children.length !== 0 || !refs.table.hidden ||
	    !fakeElementText(refs.error).includes('连接数据仍不可用') ||
	    fakeElementText(refs.tbody).includes('198.51.100.53') ||
	    refs.summaryUpdated.textContent !== '03:05:06') {
		fail('clientDetailRefresh.js reject after unavailable must keep the table empty, retain its receive time, and explain that connection data remains unavailable');
	}

	state.error = null;
	state.response = Object.assign({}, fixture, {
		available: false,
		total_connections: 0,
		returned_connections: 0,
		connections: [],
		warnings: [ 'conntrack_snapshot_incomplete' ]
	});
	refresh.render(state);
	const incompleteFooter = fakeElementText(refs.footer);
	if (refs.summaryTargets.textContent !== '—' ||
	    refs.summaryConnections.textContent !== '—' ||
	    fakeElementText(refs.empty) !== '连接快照不完整，无法确认当前连接数量，请稍后重试。' ||
	    !incompleteFooter.includes('告警：连接快照不完整') ||
	    incompleteFooter.includes('显示 0') || incompleteFooter.includes('共 0')) {
		fail('clientDetailRefresh.js incomplete snapshots must render unknown counts, dedicated Chinese guidance, and no definitive zero-count footer');
	}

	state.error = null;
	state.response = Object.assign({}, fixture, {
		client: null, total_connections: 0, returned_connections: 0,
		connections: [], warnings: [ 'client_not_found' ]
	});
	refresh.render(state);
	if (!fakeElementText(refs.empty).includes('未找到该客户端') || refs.tbody.children.length)
		fail('clientDetailRefresh.js must render a distinct cleared not-found state for null client/client_not_found');

	state.response = Object.assign({}, fixture, {
		total_connections: 0, returned_connections: 0, connections: [], warnings: []
	});
	refresh.render(state);
	if (!fakeElementText(refs.empty).includes('当前客户端没有连接') ||
	    !fakeElementText(refs.connectionState).includes('暂无连接')) {
		fail('clientDetailRefresh.js must render zero connections distinctly without claiming the client is offline');
	}

	state.response = null;
	state.lastGood = null;
	state.updatedAt = null;
	state.error = new Error('initial down');
	refresh.render(state);
	if (refs.error.hidden || refs.tbody.children.length || !refs.table.hidden || refs.empty.hidden ||
	    !fakeElementText(refs.empty).includes('首次加载连接详情失败')) {
		fail('clientDetailRefresh.js must render an initial transport failure as a distinct safe empty state');
	}

	state.error = null;
	state.response = Object.assign({}, fixture, {
		total_connections: 5,
		returned_connections: 2,
		truncated: true,
		limit: 2,
		warnings: [ 'backend <warning>' ]
	});
	state.lastGood = state.response;
	state.updatedAt = new Date(2026, 0, 2, 3, 6, 7).getTime();
	state.loading = true;
	state.manualLoading = false;
	refresh.render(state);
	if (refs.refresh.disabled || refs.intervalSel.disabled ||
	    refs.refresh.getAttribute('aria-busy') !== 'false') {
		fail('clientDetailRefresh.js automatic loading must leave the immediate-refresh controls enabled and visually idle');
	}
	state.manualLoading = true;
	refresh.render(state);
	const truncatedFooter = fakeElementText(refs.footer);
	const truncatedRates = findFakeElementsByClass(
		refs.tbody, 'lanspeed-connection-rate-cell'
	).map(fakeElementText);
	if (refs.summaryTargets.textContent !== '至少 2' ||
	    !truncatedFooter.includes('显示 2 / 共 5 条') ||
	    !truncatedFooter.includes('连接较多，仅显示前 2 条') ||
	    !truncatedFooter.includes('分组速率仅汇总已显示连接') ||
	    truncatedRates.length !== 4 || truncatedRates.some(function(rate) {
		return rate.startsWith('≥ ');
	    }) ||
	    !truncatedFooter.includes('backend <warning>') || !refs.refresh.disabled ||
	    !refs.intervalSel.disabled || refs.refresh.getAttribute('aria-busy') !== 'true') {
		fail('clientDetailRefresh.js must keep truncated rates visually numeric, explain their partial aggregation in the footer, and only mark immediate refresh busy during manual loading');
	}
	const hostile = JSON.parse(JSON.stringify(fixture));
	hostile.client.hostname = '<svg onload=alert(1)>';
	state.loading = false;
	state.response = hostile;
	state.lastGood = hostile;
	refresh.render(state);
	if (fakeElementText(refs.clientName) !== '<svg onload=alert(1)>' ||
	    findFakeElementsByTag(built.root, 'svg').length !== 0) {
		fail('clientDetailRefresh.js must keep every backend identity/warning/error string as text rather than markup');
	}
}

function assertClientDetailShellSource(src) {
	const cleaned = stripComments(src);
	if (JSON.stringify(moduleRequireNames(src)) !== JSON.stringify([
		'baseclass', 'lanspeed.theme', 'lanspeed.clientDetailStyle'
	])) {
		fail('clientDetailShell.js must require only baseclass, theme and clientDetailStyle');
	}
	if (/\brpc\b|\bset(?:Timeout|Interval)\b|\binnerHTML\b|\b(?:Promise|fetch|async|await)\b/.test(cleaned)) {
		fail('clientDetailShell.js must remain free of RPC, timers, async work and innerHTML');
	}
	if (/(?:['"]style['"]\s*:|\.style\b)|@media|\b(?:var|let|const)\s+\w*CSS\b|['"][^'"\n]*[.#][\w-]+[^'"\n]*\{/.test(cleaned)) {
		fail('clientDetailShell.js must not inline or assemble CSS');
	}
	const namedFunctions = Array.from(cleaned.matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)/g), function(match) {
		return match[1];
	});
	if (JSON.stringify(namedFunctions) !== JSON.stringify([ 'buildShell' ])) {
		fail('clientDetailShell.js must keep its sortable-header builder local to buildShell and leave sorting state and row ordering outside the shell');
	}
	const sortableKeys = [
		'remote_ip', 'location', 'remote_port', 'protocol', 'state', 'tx', 'rx', 'count'
	];
	if (!src.includes('var sortableHeader = function(sortKey, label, attrs)') ||
	    sortableKeys.some(function(key) {
		return !src.includes(`sortableHeader('${key}'`);
	    })) {
		fail('clientDetailShell.js must construct all eight client-detail headers through one local sortableHeader helper');
	}
	if (!src.includes('clientDetailStyle.CSS') || !src.includes('lsTheme.applyRoot(root)')) {
		fail('clientDetailShell.js must inject the composed detail CSS and apply the existing theme helper');
	}
}

function assertClientDetailShellInteraction(src) {
	const E = fakeElement;
	const fakeBaseclass = { extend: function(value) { return value; } };
	let themedRoot = null;
	const shell = vm.compileFunction(src,
		[ 'baseclass', 'lsTheme', 'clientDetailStyle', 'E', '_' ],
		{ filename: 'resources/lanspeed/clientDetailShell.js' })(
			fakeBaseclass,
			{ applyRoot: function(root) { themedRoot = root; } },
			{ CSS: 'detail-css' },
			E,
			function(value) { return value; }
		);
	const calls = { back: [], protocol: [], filter: [], sort: [], reload: [], interval: [], paused: [] };
	const viewState = {
		prefs: { refreshMs: 3000, paused: false },
		refreshChoices: [ { value: 1000, label: '1s' }, { value: 3000, label: '3s' } ],
		back: function() { calls.back.push(Array.from(arguments)); },
		setProtocol: function() { calls.protocol.push(Array.from(arguments)); },
		setFilter: function() { calls.filter.push(Array.from(arguments)); },
		setSort: function() { calls.sort.push(Array.from(arguments)); },
		reload: function() { calls.reload.push(Array.from(arguments)); },
		setRefreshMs: function() { calls.interval.push(Array.from(arguments)); },
		setPaused: function() { calls.paused.push(Array.from(arguments)); }
	};
	const built = shell.buildShell(viewState);
	if (!built || !built.root || !built.refs) {
		fail('clientDetailShell.js buildShell(viewState) must return { root, refs }');
		return;
	}
	const rootClasses = String(built.root.attrs.class || '').split(/\s+/);
	if (!rootClasses.includes('cbi-map') || !rootClasses.includes('lanspeed-root') ||
	    !rootClasses.includes('lanspeed-connection-detail') || themedRoot !== built.root) {
		fail('clientDetailShell.js root must reuse cbi-map/lanspeed-root, add the detail class and receive theme detection');
	}
	const sections = findFakeElementsByClass(built.root, 'cbi-section');
	if (sections.length !== 2 || sections.some(function(section) {
		return !built.root.children.includes(section);
	}) || !findFakeElement(built.root, 'lanspeed-connection-identity-card') ||
	    !findFakeElement(built.root, 'lanspeed-connections-card')) {
		fail('clientDetailShell.js must render exactly two main sections for identity and connections');
	}
	if (findFakeElementsByClass(built.root, 'lanspeed-header').length !== 2 ||
	    findFakeElementsByClass(built.root, 'lanspeed-body').length !== 2 ||
	    findFakeElementsByClass(built.root, 'lanspeed-toolbar').length !== 1 ||
	    findFakeElementsByClass(built.root, 'lanspeed-table').length !== 1 ||
	    findFakeElementsByClass(built.root, 'big').length) {
		fail('clientDetailShell.js must reuse the compact status header/body/toolbar/table structure without metric cards');
	}

	const allowedSharedClasses = new Set([
		'cbi-map', 'lanspeed-root', 'cbi-section', 'lanspeed-header',
		'lanspeed-body', 'lanspeed-toolbar', 'lanspeed-toolbar-left',
		'lanspeed-toolbar-filter', 'lanspeed-toolbar-right', 'lanspeed-table',
		'cbi-button', 'cbi-input-text', 'cbi-input-select', 'lanspeed-refresh-control',
		'alert-message', 'error', 'label', 'spacer',
		'num', 'lanspeed-sort-button', 'lanspeed-sort-label', 'lanspeed-sort-indicator'
	]);
	walkFakeElements(built.root, function(node) {
		String(node.attrs && node.attrs.class || '').split(/\s+/).filter(Boolean).forEach(function(className) {
			if (!allowedSharedClasses.has(className) &&
			    !className.startsWith('lanspeed-connection-') &&
			    className !== 'lanspeed-connections-card') {
				fail(`clientDetailShell.js must prefix its new class ${className}`);
			}
		});
	});

	const refs = built.refs;
	[
		'error', 'back', 'clientName', 'clientMeta', 'connectionState', 'summary',
		'summaryTargets', 'summaryConnections', 'summaryUpdated', 'protocolAll',
		'protocolTcp', 'protocolUdp', 'filter', 'intervalSel', 'refresh', 'pause',
		'sortHeaders', 'table', 'tbody',
		'empty', 'footer'
	].forEach(function(name) {
		if (!refs[name]) fail(`clientDetailShell.js refs must expose ${name}`);
	});
	if (!refs.table || !refs.tbody) return;

	const copy = fakeElementText(built.root);
	[
		'返回客户端列表', 'LAN Speed 状态 / 客户端连接详情', '无法加载连接详情',
		'客户端身份', '正在加载客户端身份…', 'MAC 与 IP 信息将在加载后显示',
		'等待数据', '连接摘要', '目标 IP 数', '连接数', '更新时间',
		'当前连接', '全部', 'TCP', 'UDP', '立即刷新', '目标 IP', '国家/地区', '目标端口',
		'协议', '状态', '上行', '下行', '暂无连接', '连接数据加载后会显示来源、刷新间隔和 IP 位置说明。'
	].forEach(function(text) {
		if (!copy.includes(text)) fail(`clientDetailShell.js must render Chinese copy: ${text}`);
	});
	const summaryLabels = findFakeElementsByClass(
		built.root, 'lanspeed-connection-summary-label'
	).map(fakeElementText);
	if (JSON.stringify(summaryLabels) !== JSON.stringify([
		'目标 IP 数', '连接数', '更新时间'
	])) {
		fail('clientDetailShell.js must label the grouped destination summary as target IP count');
	}
	const headers = findFakeElementsByTag(refs.table, 'th').map(fakeElementText);
	const headerNodes = findFakeElementsByTag(refs.table, 'th');
	if (JSON.stringify(headers) !== JSON.stringify([
		'目标 IP', '国家/地区', '目标端口', '协议', '状态', '上行', '下行', '连接数'
	]) || headerNodes.some(function(th) {
		return th.attrs.scope !== 'col' || th.attrs['aria-sort'] !== 'none';
	})) {
		fail('clientDetailShell.js must render eight initially-unsorted accessible connection table headers');
	}
	const sortKeys = [
		'remote_ip', 'location', 'remote_port', 'protocol', 'state', 'tx', 'rx', 'count'
	];
	if (!refs.sortHeaders || sortKeys.some(function(sortKey) {
		const ref = refs.sortHeaders[sortKey];
		if (!ref || !ref.th || !ref.button || !ref.button.listeners.click ||
		    ref.button.attrs.type !== 'button' ||
		    !String(ref.button.attrs.class || '').split(/\s+/).includes('lanspeed-sort-button')) {
			return true;
		}
		const indicators = findFakeElementsByClass(ref.button, 'lanspeed-sort-indicator');
		return indicators.length !== 1 || indicators[0].attrs['aria-hidden'] !== 'true';
	})) {
		fail('clientDetailShell.js must expose all eight detail headers as keyboard-clickable sort buttons with decorative indicators');
	}
	if (refs.table.attrs['aria-label'] !== '客户端连接列表' ||
	    refs.filter.attrs['aria-label'] !== '搜索连接' ||
	    refs.filter.attrs.placeholder !== '搜索目标 IP、端口或国家/地区' ||
	    refs.clientMeta.attrs['aria-label'] !== '客户端网络身份' ||
	    refs.error.attrs.role !== 'alert' || refs.error.attrs['aria-live'] !== 'assertive' ||
	    refs.empty.attrs.role !== 'status' || refs.empty.attrs['aria-live'] !== 'polite' ||
	    refs.footer.attrs['aria-live'] !== 'polite') {
		fail('clientDetailShell.js must label the table/search and expose live error, empty and footer states');
	}
	[ refs.back, refs.protocolAll, refs.protocolTcp, refs.protocolUdp, refs.refresh, refs.pause ].forEach(function(button) {
		if (!String(button.attrs.class || '').split(/\s+/).includes('cbi-button') ||
		    button.attrs.type !== 'button') {
			fail('clientDetailShell.js action buttons must use cbi-button and never submit the LuCI page');
		}
	});
	if (Object.values(calls).some(function(entries) { return entries.length; })) {
		fail('clientDetailShell.js must not call viewState actions while constructing the shell');
	}
	refs.back.listeners.click({ target: refs.back });
	refs.protocolAll.listeners.click({ target: refs.protocolAll });
	refs.protocolTcp.listeners.click({ target: refs.protocolTcp });
	refs.protocolUdp.listeners.click({ target: refs.protocolUdp });
	refs.filter.listeners.input({ target: { value: '443' } });
	refs.intervalSel.listeners.change({ target: { value: '1000' } });
	sortKeys.forEach(function(sortKey) {
		refs.sortHeaders[sortKey].button.listeners.click({
			target: refs.sortHeaders[sortKey].button
		});
	});
	let refreshPrevented = 0;
	let refreshStopped = 0;
	refs.refresh.listeners.click({
		target: refs.refresh,
		preventDefault: function() { refreshPrevented++; },
		stopPropagation: function() { refreshStopped++; }
	});
	refs.pause.listeners.click({
		target: refs.pause,
		preventDefault: function() {},
		stopPropagation: function() {}
	});
	if (JSON.stringify(calls.back) !== JSON.stringify([ [] ]) ||
	    JSON.stringify(calls.protocol) !== JSON.stringify([ [ 'all' ], [ 'tcp' ], [ 'udp' ] ]) ||
	    JSON.stringify(calls.filter) !== JSON.stringify([ [ '443' ] ]) ||
	    JSON.stringify(calls.sort) !== JSON.stringify(sortKeys.map(function(sortKey) {
		return [ sortKey ];
	    })) ||
	    JSON.stringify(calls.reload) !== JSON.stringify([ [ true ] ]) ||
	    JSON.stringify(calls.interval) !== JSON.stringify([ [ '1000' ] ]) ||
	    JSON.stringify(calls.paused) !== JSON.stringify([ [] ]) ||
	    refreshPrevented !== 1 || refreshStopped !== 1) {
		fail('clientDetailShell.js events must delegate back/protocol/filter/sort/reload directly to viewState');
	}
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
	if (!fmt.DEFAULT_PREFS || !Array.isArray(fmt.SORT_KEYS) ||
	    typeof fmt.defaultSortDirection !== 'function' ||
	    typeof fmt.nextSort !== 'function') {
		fail('format.js must expose the client sorting state machine');
		return;
	}

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

	const activeIds = {
		a: 'active-a@lan', b: 'active-b@lan', c: 'active-c@lan',
		d: 'active-d@lan', missing: 'active-missing@lan'
	};
	const inactiveIds = {
		a: 'inactive-a@lan', b: 'inactive-b@lan', low: 'inactive-low@lan',
		high: 'inactive-high@lan', missing: 'inactive-missing@lan'
	};
	const mixedActivity = [
		{
			identity_key: inactiveIds.high, hostname: 'zzzz', mac: '00:00:00:00:00:ff',
			sample_ms: 20000, last_seen: 9000, tx_bps: 100, rx_bps: 1000,
			tcp_conns: 9, udp_conns: 9
		},
		{
			identity_key: activeIds.b, hostname: 'Mike', mac: '00:00:00:00:00:30',
			sample_ms: 20000, last_seen: 19000, tx_bps: 30, rx_bps: 200,
			tcp_conns: 3, udp_conns: 1
		},
		{
			identity_key: inactiveIds.low, hostname: 'Aardvark', mac: '00:00:00:00:00:00',
			sample_ms: 20000, last_seen: 9000, tx_bps: 1, rx_bps: 1,
			tcp_conns: 0, udp_conns: 0
		},
		{
			identity_key: activeIds.missing, hostname: 'Tango', mac: '00:00:00:00:00:20',
			sample_ms: 20000, last_seen: 19000, tx_bps: 10, rx_bps: 400
		},
		{
			identity_key: inactiveIds.b, hostname: 'November', mac: '00:00:00:00:00:70',
			sample_ms: 20000, last_seen: 9000, tx_bps: 70, rx_bps: 700,
			tcp_conns: 7, udp_conns: 7
		},
		{
			identity_key: activeIds.c, hostname: 'Alpha', mac: '00:00:00:00:00:40',
			sample_ms: 20000, last_seen: 19000, tx_bps: 20, rx_bps: 300,
			tcp_conns: 1, udp_conns: 3
		},
		{
			identity_key: inactiveIds.missing, hostname: 'Oscar', mac: '00:00:00:00:00:80',
			sample_ms: 20000, last_seen: 9000, tx_bps: 80, rx_bps: 800
		},
		{
			identity_key: activeIds.a, hostname: 'Mike', mac: '00:00:00:00:00:30',
			sample_ms: 20000, last_seen: 19000, tx_bps: 30, rx_bps: 200,
			tcp_conns: 3, udp_conns: 1
		},
		{
			identity_key: inactiveIds.a, hostname: 'November', mac: '00:00:00:00:00:70',
			sample_ms: 20000, last_seen: 9000, tx_bps: 70, rx_bps: 700,
			tcp_conns: 7, udp_conns: 7
		},
		{
			identity_key: activeIds.d, hostname: 'Zulu', mac: '00:00:00:00:00:10',
			sample_ms: 20000, last_seen: 19000, tx_bps: 40, rx_bps: 100,
			tcp_conns: 2, udp_conns: 2
		}
	];
	const activeCfg = { activeWindowMs: 10000, activeMinBps: 1 };
	const activeOrders = {
		hostname: {
			asc: [ activeIds.c, activeIds.a, activeIds.b, activeIds.missing, activeIds.d ],
			desc: [ activeIds.d, activeIds.missing, activeIds.a, activeIds.b, activeIds.c ]
		},
		mac: {
			asc: [ activeIds.d, activeIds.missing, activeIds.a, activeIds.b, activeIds.c ],
			desc: [ activeIds.c, activeIds.a, activeIds.b, activeIds.missing, activeIds.d ]
		},
		tx: {
			asc: [ activeIds.missing, activeIds.c, activeIds.a, activeIds.b, activeIds.d ],
			desc: [ activeIds.d, activeIds.a, activeIds.b, activeIds.c, activeIds.missing ]
		},
		rx: {
			asc: [ activeIds.d, activeIds.a, activeIds.b, activeIds.c, activeIds.missing ],
			desc: [ activeIds.missing, activeIds.c, activeIds.a, activeIds.b, activeIds.d ]
		},
		tcp_conns: {
			asc: [ activeIds.c, activeIds.d, activeIds.a, activeIds.b, activeIds.missing ],
			desc: [ activeIds.a, activeIds.b, activeIds.d, activeIds.c, activeIds.missing ]
		},
		udp_conns: {
			asc: [ activeIds.a, activeIds.b, activeIds.d, activeIds.c, activeIds.missing ],
			desc: [ activeIds.c, activeIds.d, activeIds.a, activeIds.b, activeIds.missing ]
		}
	};
	const inactiveOrders = {
		known: {
			asc: [ inactiveIds.low, inactiveIds.a, inactiveIds.b, inactiveIds.missing, inactiveIds.high ],
			desc: [ inactiveIds.high, inactiveIds.missing, inactiveIds.a, inactiveIds.b, inactiveIds.low ]
		},
		connections: {
			asc: [ inactiveIds.low, inactiveIds.a, inactiveIds.b, inactiveIds.high, inactiveIds.missing ],
			desc: [ inactiveIds.high, inactiveIds.a, inactiveIds.b, inactiveIds.low, inactiveIds.missing ]
		}
	};

	Object.keys(activeOrders).forEach(function(sortKey) {
		[ 'asc', 'desc' ].forEach(function(sortDir) {
			const sorted = fmt.sortClients(mixedActivity, sortKey, sortDir, 20000, activeCfg);
			const connectionSort = sortKey === 'tcp_conns' || sortKey === 'udp_conns';
			const expected = activeOrders[sortKey][sortDir].concat(
				inactiveOrders[connectionSort ? 'connections' : 'known'][sortDir]);
			let sawInactive = false;
			let activeAfterInactive = false;
			sorted.forEach(function(client) {
				if (fmt.isActiveClient(client, 20000, activeCfg)) {
					if (sawInactive) activeAfterInactive = true;
				} else {
					sawInactive = true;
				}
			});
			if (activeAfterInactive) {
				fail(`format.js must keep every active client before inactive clients for ${sortKey} ${sortDir}`);
			}
			if (identities(sorted) !== expected.join(',')) {
				fail(`format.js must sort ${sortKey} ${sortDir} inside activity groups with identity_key tie-breaking`);
			}
		});
	});

	const withMissingConnections = clients.concat([
		{ identity_key: 'missing@lan', hostname: 'Missing', mac: '00:00:00:00:00:03', tx_bps: 10, rx_bps: 10 }
	]);
	if (identities(fmt.sortClients(withMissingConnections, 'tcp_conns', 'asc')) !==
		'zulu@lan,alpha@lan,missing@lan' ||
	    identities(fmt.sortClients(withMissingConnections, 'tcp_conns', 'desc')) !==
		'alpha@lan,zulu@lan,missing@lan' ||
	    identities(fmt.sortClients(withMissingConnections, 'udp_conns', 'asc')) !==
		'alpha@lan,zulu@lan,missing@lan' ||
	    identities(fmt.sortClients(withMissingConnections, 'udp_conns', 'desc')) !==
		'zulu@lan,alpha@lan,missing@lan') {
		fail('format.js must keep missing TCP/UDP counts after known values in both sort directions');
	}
}

function assertStatusRefreshSortingInteraction(src) {
	const mod = loadStatusRefreshModule(src);
	if (!mod || typeof mod.refreshSortHeaders !== 'function') {
		fail('statusRefresh.js must expose its sort-header refresh behavior for validation');
		return;
	}
	if (typeof mod.splitClientWarnings !== 'function') {
		fail('statusRefresh.js must expose client warning classification for validation');
	} else {
		const connectionOnlyState = mod.splitClientWarnings([
			'conntrack_connection_only'
		], {});
		const warningState = mod.splitClientWarnings([
			'conntrack_connection_only',
			'map_read_failed',
			'counter_anomaly',
			'global_warning'
		], { global_warning: true });
		if (JSON.stringify(Array.from(connectionOnlyState.info)) !== JSON.stringify([ 'conntrack_connection_only' ]) ||
		    connectionOnlyState.warnings.length !== 0 ||
		    JSON.stringify(Array.from(warningState.info)) !== JSON.stringify([ 'conntrack_connection_only' ]) ||
		    JSON.stringify(Array.from(warningState.warnings)) !== JSON.stringify([ 'map_read_failed' ])) {
			fail('statusRefresh.js must render connection-only rows as information and keep only actionable client warnings');
		}
	}
	if (typeof mod.setClientStatusVisibility !== 'function' ||
	    typeof mod.clientStateCell !== 'function') {
		fail('statusRefresh.js must expose configured client-status column visibility behavior');
	} else {
		const visibilityRefs = {
			statusHeader: fakeElement('th', {}),
			clientsTable: fakeElement('table', {})
		};
		mod.setClientStatusVisibility(visibilityRefs, false);
		const headerHiddenByDefault = visibilityRefs.statusHeader.hidden;
		const hiddenLayout = visibilityRefs.clientsTable.attrs['data-client-status'];
		const hiddenCell = mod.clientStateCell([ fakeElement('span', {}, 'BPF') ], false);
		mod.setClientStatusVisibility(visibilityRefs, true);
		const shownLayout = visibilityRefs.clientsTable.attrs['data-client-status'];
		const visibleCell = mod.clientStateCell([ fakeElement('span', {}, 'BPF') ], true);
		if (!headerHiddenByDefault || visibilityRefs.statusHeader.hidden ||
		    hiddenLayout !== 'hidden' || shownLayout !== 'shown' ||
		    !hiddenCell.hidden || visibleCell.hidden ||
		    hiddenCell.attrs.class !== 'lanspeed-client-state-cell' ||
		    fakeElementText(visibleCell) !== 'BPF') {
			fail('statusRefresh.js must switch the hidden six-column layout with the status header and cells');
		}
	}

	function makeRef(label, description) {
		return {
			label: label,
			description: description || '',
			th: fakeElement('th', {}),
			button: fakeElement('button', {}, [
				fakeElement('span', {}, label),
				fakeElement('span', {}, '')
			])
		};
	}

	const refs = { sortHeaders: {
		rx: makeRef('下行'),
		tcp_conns: makeRef('TCP', 'TCP 仅统计 ESTABLISHED + ASSURED')
	} };
	mod.refreshSortHeaders(refs, {
		sortKey: 'rx', sortDir: 'desc', sortCustom: false
	});
	if (refs.sortHeaders.rx.th.attrs['aria-sort'] !== 'descending' ||
	    refs.sortHeaders.rx.button.lastChild.textContent !== '' ||
	    !String(refs.sortHeaders.rx.button.attrs['aria-label']).includes('默认排序') ||
	    refs.sortHeaders.tcp_conns.th.attrs['aria-sort'] !== 'none') {
		fail('statusRefresh.js must expose default RX descending to assistive tech without a visual arrow');
	}

	mod.refreshSortHeaders(refs, {
		sortKey: 'tcp_conns', sortDir: 'asc', sortCustom: true
	});
	if (refs.sortHeaders.tcp_conns.th.attrs['aria-sort'] !== 'ascending' ||
	    refs.sortHeaders.tcp_conns.button.lastChild.textContent !== '↑' ||
	    !String(refs.sortHeaders.tcp_conns.button.attrs.title).includes('TCP 仅统计 ESTABLISHED + ASSURED') ||
	    !String(refs.sortHeaders.tcp_conns.button.attrs['aria-label']).includes('升序')) {
		fail('statusRefresh.js must combine TCP/UDP connection semantics with accessible sorting instructions');
	}
}

function assertStatusRefreshClientDetailLink(src) {
	const pathname = '/cgi-bin/luci/admin/status/lanspeed/overview';
	const mod = loadStatusRefreshModule(src, { location: { pathname: pathname } });
	if (!mod || typeof mod.clientNameContent !== 'function') {
		fail('statusRefresh.js must expose its client-name cell builder for behavior validation');
		return;
	}
	const identified = mod.clientNameContent({
		identity_key: '30:c5:0a:11:22:33@eth1',
		hostname: '工作站'
	}, '工作站', [ '192.0.2.30', '2001:db8::30' ]);
	const link = identified && identified[0];
	const ipline = identified && identified[1];
	const expectedHref = pathname + '?client=30%3Ac5%3A0a%3A11%3A22%3A33%40eth1';
	if (!Array.isArray(identified) || !link || link.tagName !== 'a' ||
	    link.attrs.class !== 'lanspeed-connection-link' || link.attrs.href !== expectedHref ||
	    !String(link.attrs.title).includes('查看 工作站 的当前连接') ||
	    !String(link.attrs['aria-label']).includes('查看 工作站 的当前连接') ||
	    fakeElementText(link) !== '工作站' ||
	    !ipline || ipline.parentNode === link || fakeElementText(ipline) !== '192.0.2.30, 2001:db8::30') {
		fail('statusRefresh.js must generate an encoded accessible detail link around only the display name while preserving the IP subline');
	}
	const missing = mod.clientNameContent({ hostname: '无身份' }, '无身份', [ '192.0.2.31' ]);
	if (!Array.isArray(missing) || missing[0] !== '无身份' ||
	    findFakeElementsByTag({ children: missing }, 'a').length !== 0) {
		fail('statusRefresh.js must safely keep clients without identity_key as plain display text');
	}
	const hostile = mod.clientNameContent({
		identity_key: 'safe@lan', hostname: '<img src=x onerror=alert(1)>'
	}, '<img src=x onerror=alert(1)>', []);
	if (!hostile[0] || fakeElementText(hostile[0]) !== '<img src=x onerror=alert(1)>' ||
	    findFakeElementsByTag(hostile[0], 'img').length !== 0) {
		fail('statusRefresh.js must keep backend display names as text inside the detail link');
	}
}

function sortedJson(values) {
	return JSON.stringify((values || []).slice().sort());
}

function assertIfaceSaveBehavior(src) {
	const rpcCalls = [];
	let sysdevicesCalls = 0;
	const rpc = {
		uciDelete: function(config, section, options) {
			rpcCalls.push([ 'delete', config, section, options ]);
			return Promise.resolve();
		},
		uciSet: function(config, section, values) {
			rpcCalls.push([ 'set', config, section, values ]);
			return Promise.resolve();
		},
		sysdevices: function() {
			sysdevicesCalls++;
			return Promise.resolve({ devices: [] });
		}
	};
	const mod = loadIfaceConfigModule(src, rpc);
	if (!mod || typeof mod.prepareSave !== 'function' || typeof mod.applySave !== 'function') {
		fail('ifaceConfig.js must expose testable prepare/apply steps for the shared save flow');
		return;
	}

	const unavailable = mod.prepareSave({ refs: {}, ifaceOriginal: {
		ifname: [ 'tun0' ], interface_include: [ 'dae0' ], observe: [ 'gretap0' ]
	} });
	if (!unavailable || unavailable.changed !== false) {
		fail('ifaceConfig.js must treat an unavailable sysdevices scan as a no-op save plan');
	}

	const modeButtons = [
		{ disabled: false },
		{ disabled: true, ifcfgAlwaysDisabled: true }
	];
	const busyState = {
		refs: { ifcfgReloadBtn: { disabled: false } },
		ifcfgButtons: modeButtons,
		ifcfgDirty: true
	};
	mod.setBusy(busyState, true);
	if (!modeButtons.every(function(button) { return button.disabled; }) ||
	    !busyState.refs.ifcfgReloadBtn.disabled) {
		fail('ifaceConfig.js must lock scan and interface mode controls while the shared save is running');
	}
	mod.setBusy(busyState, false);
	if (modeButtons[0].disabled || !modeButtons[1].disabled ||
	    !busyState.refs.ifcfgReloadBtn.disabled) {
		fail('ifaceConfig.js must unlock valid modes, retain intrinsic disabled modes, and keep scan disabled while edits remain dirty');
	}

	const dirtyScanState = {
		refs: {
			ifcfgGrid: {},
			ifcfgStatus: { textContent: '' }
		},
		ifcfgDirty: true
	};
	asyncChecks.push(Promise.resolve()
		.then(function() { return mod.load(dirtyScanState); })
		.then(function(result) {
			if (result !== false || sysdevicesCalls !== 0 ||
			    dirtyScanState.refs.ifcfgStatus.textContent !== '') {
				fail('ifaceConfig.js must refuse to rescan dirty interface state without rendering a custom unsaved warning');
			}
		}));

	const baseState = {
		refs: {},
		ifcfgLoaded: true,
		ifcfgDirty: true,
		sysdevices: {
			devices: [
				{ name: 'br-lan', recommended_lan: true, selected: true },
				{ name: 'eth1', recommended_lan: true, selected: false }
			],
			current_ifnames: [ 'br-lan', 'tun0', 'gone0', 'dae0' ],
			current_observed: [ 'gretap0' ]
		},
		ifaceOriginal: {
			ifname: [ 'br-lan', 'tun0', 'gone0' ],
			interface_include: [ 'br-lan', 'dae0' ],
			observe: [ 'gretap0' ]
		}
	};

	baseState.ifcfgState = { 'br-lan': 'collect', eth1: 'off' };
	const unchanged = mod.prepareSave(baseState);
	if (!unchanged || unchanged.changed !== false) {
		fail('ifaceConfig.js must not write interface UCI options when visible selections return to their original state');
	}

	baseState.ifcfgState = { 'br-lan': 'off', eth1: 'collect' };
	const changed = mod.prepareSave(baseState);
	if (!changed || !changed.changed ||
	    sortedJson(changed.values && changed.values.ifname) !== sortedJson([ 'tun0', 'gone0', 'eth1' ]) ||
	    sortedJson(changed.values && changed.values.interface_include) !== sortedJson([ 'dae0', 'eth1' ]) ||
	    Object.prototype.hasOwnProperty.call(changed.values || {}, 'observe') ||
	    sortedJson(changed.desired && changed.desired.observe) !== sortedJson([ 'gretap0' ])) {
		fail('ifaceConfig.js must preserve ignored and disappeared configured interfaces while updating visible candidates');
	}

	asyncChecks.push(Promise.resolve()
		.then(function() { return mod.applySave(unavailable); })
		.then(function() {
			if (rpcCalls.length)
				fail('ifaceConfig.js no-op plans must issue no interface UCI RPC writes');
		})
		.catch(function(err) {
			fail('ifaceConfig.js no-op save plan unexpectedly failed: ' + (err && err.message || err));
		}));

	const deleteFailure = new Error('delete failed');
	const failingMod = loadIfaceConfigModule(src, {
		uciDelete: function() { return Promise.reject(deleteFailure); },
		uciSet: function() { return Promise.resolve(); }
	});
	asyncChecks.push(Promise.resolve()
		.then(function() { return failingMod.applySave(changed); })
		.then(function() {
			fail('ifaceConfig.js must reject when deleting staged interface options fails');
		}, function(err) {
			if (err !== deleteFailure)
				fail('ifaceConfig.js must preserve the original interface deletion error');
		}));
}

function daemonRefsForSave() {
	return {
		rateCollectorMode: {
			value: 'auto',
			options: [],
			appendChild: function(option) { this.options.push(option); }
		},
		connCollectorMode: { value: 'auto' },
		activeWindow: { value: '10000' },
		activeMin: { value: '1' },
		showClientStatus: { checked: false },
		showIpv6: { checked: true },
		hidePrivateIpv6: { checked: false },
		hideIpv6RangesItems: [ 'fc00::/7', 'fe80::/10' ],
		hideIpv6RangesList: {
			innerHTML: '',
			appendChild: function() {}
		},
		hideIpv6RangeInput: { value: '', disabled: false },
		addRangeBtn: { disabled: false },
		rangeRemoveButtons: [ { disabled: false } ],
		resetBtn: { disabled: false },
		rateHint: { textContent: '' },
		currentRateSource: { textContent: '' },
		currentRateSourceWrap: { title: '' }
	};
}

function assertConfigCompatibility(src) {
	const noRpc = {
		status: function() { return Promise.resolve({}); }
	};
	const ifaceCfg = { setBusy: function() {} };
	const mod = loadConfigFormModule(src, {}, noRpc, ifaceCfg);
	if (!mod || typeof mod.isNssDevice !== 'function' ||
	    typeof mod.daeRuntimeActive !== 'function') {
		fail('configForm.js must expose NSS and dae runtime compatibility helpers for validation');
		return;
	}

	if (!mod.isNssDevice({ evidence: { nss: { ecm_active: true } } }) ||
	    !mod.isNssDevice({ evidence: { nss: { ecm_offload_active: true } } }) ||
	    !mod.isNssDevice({ evidence: { nss: { direct_state_readable: true } } }) ||
	    !mod.isNssDevice({ evidence: { nss: { direct_supported: true } } })) {
		fail('configForm.js must prefer new Rust NSS evidence names and retain old C aliases');
	}
	if (!mod.daeRuntimeActive({ evidence: { proxy: { dae_running: true } } }) ||
	    !mod.daeRuntimeActive({ evidence: { dae: { daed_running: true } } }) ||
	    !mod.daeRuntimeActive({ evidence: { dae: { dae_process: true } } }) ||
	    !mod.daeRuntimeActive({ evidence: { proxy: { daed_process: true } } })) {
		fail('configForm.js must detect running dae/daed processes from new Rust and old C evidence');
	}
	if (!mod.daeRuntimeActive({ evidence: { dae: { runtime_active: true } } }) ||
	    mod.daeRuntimeActive({ evidence: {
		proxy: { runtime_active: true, daed_running: true },
		dae: { runtime_active: false }
	    } })) {
		fail('configForm.js must prefer the fresh Rust runtime_active boolean over stale legacy process fields');
	}
	if (mod.daeRuntimeActive({ evidence: { collector: { rate_reason: 'dae_runtime_prefers_bpf' } } }) ||
	    mod.daeRuntimeActive({ warnings: [ 'nss_dae_bpf_fallback_may_be_inaccurate' ] }) ||
	    mod.daeRuntimeActive({ evidence: { dae: { dae_service: true, dae0: true } } })) {
		fail('configForm.js must not infer dae runtime activity from decisions, warnings, services, or leftover interfaces');
	}

	const originalLists = {
		ifname: [ 'br-lan', 'tun0' ],
		interface_include: [ 'br-lan', 'dae0' ],
		observe: [ 'gretap0' ]
	};
	const loadMod = loadConfigFormModule(src, {
		load: function() { return Promise.resolve(); },
		get: function(config, section, option) { return originalLists[option]; }
	}, noRpc, ifaceCfg);
	asyncChecks.push(loadMod.loadValues().then(function(values) {
		if (!values ||
		    values.show_client_status !== '0' ||
		    sortedJson(values.interfaceConfig && values.interfaceConfig.ifname) !== sortedJson(originalLists.ifname) ||
		    sortedJson(values.interfaceConfig && values.interfaceConfig.interface_include) !== sortedJson(originalLists.interface_include) ||
		    sortedJson(values.interfaceConfig && values.interfaceConfig.observe) !== sortedJson(originalLists.observe)) {
			fail('configForm.js must load exact raw UCI interface lists as the hidden-interface preservation baseline');
		}
	}).catch(function(err) {
		fail('configForm.js raw interface baseline load failed: ' + (err && err.message || err));
	}));
}

function makeSaveHarness(configSrc, ifaceSrc, overrides) {
	overrides = overrides || {};
	const calls = [];
	let savedDaemonValues = null;
	const rpc = {
		uciSet: overrides.uciSet || function(config, section, values) {
			calls.push('set');
			savedDaemonValues = values;
			return Promise.resolve();
		},
		uciDelete: overrides.uciDelete || function() { calls.push('delete'); return Promise.resolve(); },
		uciRevert: overrides.uciRevert || function() { calls.push('revert'); return Promise.resolve(); },
		status: function() { calls.push('status'); return Promise.resolve(null); },
		sysdevices: function() { calls.push('sysdevices'); return Promise.reject(new Error('scan unavailable')); }
	};
	const uci = {
		unload: overrides.uciUnload || function(config) { calls.push('unload:' + config); },
		load: overrides.uciLoad || function(config) { calls.push('load:' + config); return Promise.resolve(); },
		get: function() { return null; }
	};
	const ifaceCfg = loadIfaceConfigModule(ifaceSrc, rpc);
	const configForm = loadConfigFormModule(configSrc, uci, rpc, ifaceCfg);
	const viewState = {
		refs: {},
		daemonRefs: daemonRefsForSave(),
		ifaceOriginal: { ifname: [], interface_include: [], observe: [] },
		ifcfgButtons: [ { disabled: false }, { disabled: false } ]
	};
	return {
		calls: calls,
		form: configForm,
		state: viewState,
		savedDaemonValues: function() { return savedDaemonValues; }
	};
}

function assertConfigSaveBehavior(configSrc, ifaceSrc) {
	const probe = makeSaveHarness(configSrc, ifaceSrc);
	if (!probe.form || typeof probe.form.saveAll !== 'function' ||
	    typeof probe.form.resetAll !== 'function') {
		fail('configForm.js must expose native-footer save and reset transactions');
		return;
	}

	asyncChecks.push(probe.form.saveAll(probe.state).then(function(result) {
		if (result !== true || probe.calls.filter(function(v) { return v === 'set'; }).length !== 1 ||
		    probe.calls.indexOf('unload:lanspeed') === -1 ||
		    probe.calls.indexOf('load:lanspeed') === -1 ||
		    !probe.savedDaemonValues() || probe.savedDaemonValues().show_client_status !== '0') {
			fail('configForm.js must stage daemon settings for LuCI native apply and refresh the LuCI UCI cache');
		}
	}).catch(function(err) {
		fail('configForm.js sysdevices-isolated save unexpectedly rejected: ' + (err && err.message || err));
	}));

	const writeFailure = makeSaveHarness(configSrc, ifaceSrc, {
		uciSet: function() {
			writeFailure.calls.push('set');
			return Promise.reject(new Error('write failed'));
		}
	});
	asyncChecks.push(writeFailure.form.saveAll(writeFailure.state).then(function() {
		fail('configForm.js must reject a failed native UCI staging transaction');
	}, function(err) {
		if (!String(err && err.message || err).includes('配置写入失败') ||
		    writeFailure.calls.indexOf('revert') === -1 || writeFailure.state.configSaving) {
			fail('configForm.js must revert failed staged UCI changes, unlock controls and reject before native apply');
		}
	}));

	let releaseWrite;
	const busy = makeSaveHarness(configSrc, ifaceSrc, {
		uciSet: function() {
			busy.calls.push('set');
			return new Promise(function(resolve) { releaseWrite = resolve; });
		}
	});
	const busySave = busy.form.saveAll(busy.state);
	asyncChecks.push(Promise.resolve().then(function() {
		const refs = busy.state.daemonRefs;
		const daemonControls = [
			refs.rateCollectorMode, refs.connCollectorMode, refs.activeWindow,
			refs.activeMin, refs.showClientStatus, refs.showIpv6, refs.hidePrivateIpv6,
			refs.hideIpv6RangeInput, refs.addRangeBtn, refs.resetBtn
		].concat(refs.rangeRemoveButtons);
		if (!daemonControls.every(function(control) { return control.disabled; }) ||
		    !busy.state.ifcfgButtons.every(function(button) { return button.disabled; })) {
			fail('configForm.js must lock every editable daemon and interface control while saving');
		}
		releaseWrite();
		return busySave;
	}).then(function() {
		if (busy.state.configSaving || busy.state.daemonRefs.rateCollectorMode.disabled ||
		    busy.state.ifcfgButtons[0].disabled) {
			fail('configForm.js must unlock every control after the save transaction settles');
		}
	}));

	const unexpected = makeSaveHarness(configSrc, ifaceSrc, {
		uciLoad: function() { throw new Error('cache load exploded'); }
	});
	asyncChecks.push(unexpected.form.saveAll(unexpected.state).then(function() {
		fail('configForm.js must reject when staged values cannot be resynchronized');
	}, function(err) {
		if (unexpected.state.configSaving || unexpected.calls.indexOf('revert') === -1 ||
		    !String(err && err.message || err).includes('页面缓存刷新失败')) {
			fail('configForm.js must revert staged values, unlock controls and report cache refresh failures');
		}
	}));

	const reset = makeSaveHarness(configSrc, ifaceSrc);
	asyncChecks.push(reset.form.resetAll(reset.state).then(function(result) {
		if (result !== true || reset.calls.indexOf('revert') === -1 ||
		    reset.calls.indexOf('unload:lanspeed') === -1 ||
		    reset.calls.indexOf('load:lanspeed') === -1 || reset.state.configSaving) {
			fail('configForm.js native Reset handler must revert staged UCI values and reload the page state');
		}
	}).catch(function(err) {
		fail('configForm.js native reset unexpectedly rejected: ' + (err && err.message || err));
	}));
}

function assertConfigViewNativeActions(src) {
	const calls = [];
	const ui = {
		changes: {
			changes: {},
			init: function() { calls.push('init'); return Promise.resolve(); },
			apply: function(checked) { calls.push('apply:' + checked); }
		},
		hideIndicator: function(id) { calls.push('hide:' + id); },
		showIndicator: function() {},
		addNotification: function(title, body, level) {
			calls.push('notify:' + level + ':' + fakeElementText(body));
		}
	};
	const configForm = {
		saveAll: function() { calls.push('save'); return Promise.resolve(true); },
		resetAll: function() { calls.push('reset'); return Promise.resolve(true); }
	};
	const mod = loadConfigViewModule(src, configForm, ui);
	mod.viewState = {};
	asyncChecks.push(mod.handleSave().then(function(result) {
		if (result !== true || calls.join(',') !== 'save,hide:uci-changes,init')
			fail('config view native Save handler must stage without applying');
		return mod.handleSaveApply(null, '0');
	}).then(function() {
		if (calls.join(',') !== 'save,hide:uci-changes,init,save,hide:uci-changes,init,apply:true')
			fail('config view native Save & Apply handler must stage once and invoke checked LuCI apply');
		return mod.handleReset();
	}).then(function(result) {
		if (result !== true || calls.join(',') !==
		    'save,hide:uci-changes,init,save,hide:uci-changes,init,apply:true,reset,hide:uci-changes,init')
			fail('config view native Reset handler must delegate to the shared reset transaction');
	}).catch(function(err) {
		fail('config view native action flow unexpectedly rejected: ' + (err && err.message || err));
	}));

	const failedCalls = [];
	const failed = loadConfigViewModule(src, {
		saveAll: function() { return Promise.reject(new Error('stage failed')); },
		resetAll: function() { return Promise.resolve(true); }
	}, {
		changes: {
			changes: {},
			init: function() { failedCalls.push('init'); return Promise.resolve(); },
			apply: function() { failedCalls.push('apply'); }
		},
		hideIndicator: function() { failedCalls.push('hide'); },
		showIndicator: function() {},
		addNotification: function(title, body, level) {
			failedCalls.push('notify:' + level + ':' + fakeElementText(body));
		}
	});
	failed.viewState = {};
	asyncChecks.push(failed.handleSaveApply(null, '0').then(function(result) {
		if (result !== false || failedCalls.length !== 1 ||
		    failedCalls[0] !== 'notify:error:stage failed') {
			fail('config view must stop native apply and show an error notification when staging fails');
		}
	}).catch(function(err) {
		fail('config view failed-save notification path unexpectedly rejected: ' + (err && err.message || err));
	}));

	const dirtyCalls = [];
	let dirtyHandler = null;
	const dirtyForm = {
		DEFAULTS: {},
		buildDaemonSection: function(values, state) {
			state.daemonRefs = {};
			return fakeElement('div', {});
		},
		saveAll: function() { dirtyCalls.push('save'); return Promise.resolve(true); },
		resetAll: function() { return Promise.resolve(true); }
	};
	const dirty = loadConfigViewModule(src, dirtyForm, {
		changes: {
			changes: { network: [ [ 'set', 'lan', 'proto', 'static' ] ] },
			init: function() { dirtyCalls.push('init'); return Promise.resolve(); },
			displayChanges: function() { dirtyCalls.push('display'); }
		},
		hideIndicator: function(id) { dirtyCalls.push('hide:' + id); },
		showIndicator: function(id, label, handler) {
			dirtyCalls.push('show:' + id + ':' + label);
			dirtyHandler = handler;
		},
		addNotification: function() { dirtyCalls.push('notify'); }
	});
	dirty.render({});
	dirty.viewState.markDirty();
	dirty.viewState.markDirty();
	if (dirtyCalls.join(',') !== 'hide:uci-changes,show:uci-changes:Unsaved Changes: 2' ||
	    typeof dirtyHandler !== 'function' || !dirty.viewState.localDirty) {
		fail('config view must show one immediate LuCI native unsaved indicator for local form edits');
	}
	asyncChecks.push(Promise.resolve().then(function() {
		return dirtyHandler();
	}).then(function() {
		if (dirtyCalls.join(',') !==
		    'hide:uci-changes,show:uci-changes:Unsaved Changes: 2,save,hide:uci-changes,init,display' ||
		    dirty.viewState.localDirty) {
			fail('clicking the local LuCI indicator must stage edits, restore the native change indicator and open its change list');
		}
	}).catch(function(err) {
		fail('config view local dirty indicator flow unexpectedly rejected: ' + (err && err.message || err));
	}));
}

function assertWarningAliases(src) {
	const vocab = loadVocabModule(src);
	if (!vocab || typeof vocab.normalizeWarningId !== 'function') {
		fail('vocab.js must expose warning ID normalization for old daemon compatibility');
		return;
	}
	if (vocab.normalizeWarningId('nss_daed_nss_fallback_may_be_inaccurate') !==
		'nss_dae_bpf_fallback_may_be_inaccurate' ||
	    vocab.normalizeWarningId('nss_dae_bpf_fallback_may_be_inaccurate') !==
		'nss_dae_bpf_fallback_may_be_inaccurate') {
		fail('vocab.js must keep the actionable legacy dae warning alias');
	}
	if (src.includes('nss_daed_prefers_bpf') || src.includes('dae_runtime_prefers_bpf')) {
		fail('vocab.js must not retain obsolete non-actionable dae warning copy');
	}
	if (vocab.warningText('dae_process_probe_failed') === 'dae process probe failed' ||
	    vocab.warningClass('dae_process_probe_failed') !== 'label label-danger') {
		fail('vocab.js must render the Rust /proc dae scan failure as a critical localized warning');
	}
	if (!vocab.warningText('bpf_optional_package_missing').includes('必需的 BPF 软件包') ||
	    vocab.warningText('bpf_optional_package_missing').includes('可选 BPF 软件包')) {
		fail('vocab.js must keep the legacy BPF warning ID but describe the package as mandatory');
	}
	const connectionOnlyText = vocab.warningText('conntrack_connection_only');
	if (!connectionOnlyText.includes('只有连接记录') ||
	    !connectionOnlyText.includes('不是异常') ||
	    connectionOnlyText.includes('仅连接')) {
		fail('vocab.js must explain connection-only rows without rendering a separate connection-only label');
	}
	if (typeof vocab.importantWarnings !== 'function' ||
	    typeof vocab.isImportantWarning !== 'function') {
		fail('vocab.js must expose important-warning filtering for the simplified diagnostics view');
		return;
	}
	const healthyStatus = {
		mode: 'Full',
		capabilities: { live_metrics: true, bpf_runtime_metrics: true },
		evidence: { effective_collector: 'bpf' }
	};
	const filtered = vocab.importantWarnings([
		'existing_tc_filters_detected',
		'software_flow_offload_enabled',
		'fullcone_detected',
		'openclash_detected',
		'probe_error',
		'map_read_failed',
		'map_read_failed'
	], healthyStatus);
	if (JSON.stringify(Array.from(filtered)) !== JSON.stringify([ 'map_read_failed' ]) ||
	    vocab.isImportantWarning('software_flow_offload_enabled') ||
	    !vocab.isImportantWarning('bpf_runtime_loader_unavailable')) {
		fail('vocab.js must hide environment notices, suppress healthy probe noise, and retain actionable failures');
	}
}

function assertStatusShellInteraction(src) {
	let saved = 0;
	let refreshed = 0;
	let reloads = 0;
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
		[ 'baseclass', 'fmt', 'lsTheme', 'statusStyle', 'E', '_' ],
		{ filename: 'resources/lanspeed/statusShell.js' })(
			fakeBaseclass,
			fmt,
			{ applyRoot: function() {} },
			{ CSS: '' },
			E,
			function(value) { return value; }
		);
	const viewState = {
		showClientStatus: false,
		prefs: { refreshMs: 3000, unit: 'bit', activeOnly: false, sortKey: 'rx', sortDir: 'desc', sortCustom: false, paused: false },
		filter: '',
		reload: function(force) { if (force === true) reloads++; },
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
	if (refs.btnRefresh.attrs.type !== 'button' || refs.btnPause.attrs.type !== 'button') {
		fail('statusShell.js refresh actions must never submit or navigate away from the LuCI page');
	}
	let refreshPrevented = 0;
	let refreshStopped = 0;
	refs.btnRefresh.listeners.click({
		preventDefault: function() { refreshPrevented++; },
		stopPropagation: function() { refreshStopped++; }
	});
	if (reloads !== 1 || refreshPrevented !== 1 || refreshStopped !== 1) {
		fail('statusShell.js immediate refresh must stay local without bubbling into client navigation');
	}
	if (!refs.statusHeader || !refs.statusHeader.hidden || refs.showClientStatus ||
	    !refs.clientsTable || refs.clientsTable.attrs['data-client-status'] !== 'hidden') {
		fail('statusShell.js must initialize the hidden six-column layout without a realtime-page toggle');
	}
	const visibleState = Object.assign({}, viewState, {
		showClientStatus: true,
		prefs: Object.assign({}, viewState.prefs)
	});
	const visibleBuilt = shell.buildShell(visibleState);
	if (!visibleBuilt.refs.statusHeader || visibleBuilt.refs.statusHeader.hidden ||
	    !visibleBuilt.refs.clientsTable ||
	    visibleBuilt.refs.clientsTable.attrs['data-client-status'] !== 'shown') {
		fail('statusShell.js must retain the original shown-status layout when configuration enables it');
	}
	if (!refs.sortHeaders || !refs.sortHeaders.rx || !refs.sortHeaders.hostname ||
	    !refs.sortHeaders.rx.button || !refs.sortHeaders.rx.button.listeners.click ||
	    !refs.sortHeaders.hostname.button || !refs.sortHeaders.hostname.button.listeners.click) {
		fail('statusShell.js must expose clickable sortable table headers');
		return;
	}
	if (!refs.sortHeaders.tcp_conns ||
	    refs.sortHeaders.tcp_conns.description !== '当前已建立并确认的 TCP 连接' ||
	    !refs.sortHeaders.udp_conns ||
	    refs.sortHeaders.udp_conns.description !== '当前已确认的 UDP 连接') {
		fail('statusShell.js sortable TCP/UDP headers must retain their connection-statistics semantics');
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

function assertRpcModule(src) {
	if (!src.includes("method: 'revert'") ||
	    !src.includes('uciRevert:') ||
	    !src.includes('callUciRevert')) {
		fail('lanspeed/rpc.js must expose uci.revert so failed raw writes can clear server-side staged deltas');
	}
	if (src.includes('callUciCommit') || src.includes('uciCommit:') ||
	    src.includes('callReload') || src.includes('reload:     callReload')) {
		fail('lanspeed/rpc.js must not retain direct commit or daemon reload calls after adopting native LuCI apply');
	}
	if (!src.includes("method: 'interfaces'") || !src.includes('interfaces: callInterfaces')) {
		fail('lanspeed/rpc.js must expose interface throughput data');
	}
	if (!src.includes("method: 'health'") || !src.includes('health:')) {
		fail('lanspeed/rpc.js must expose the dedicated runtime health method');
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
			fail(`lanspeed/statusOverview.js must declare 'require ${req} as <alias>'`);
		}
	});
}

function assertCacheAwareViewEntry(src, moduleName, label) {
	if (!/^\s*['"]require\s+view['"]\s*;/m.test(src) ||
	    !src.includes("var RESOURCE_VERSION = 'lanspeed-1.1.1-r6';") ||
	    !src.includes('var previousVersion = L.env.resource_version;') ||
	    !src.includes('L.env.resource_version = RESOURCE_VERSION;') ||
	    !src.includes(`L.require('${moduleName}')`) ||
	    !src.includes('L.env.resource_version = previousVersion;') ||
	    !src.includes('return view.extend({') ||
	    !src.includes('return module.load();') ||
	    !src.includes('return pageModule.render(data);')) {
		fail(`${label} must load ${moduleName} through the 1.1.1 resource cache boundary`);
	}
	if (src.includes('buildShell(') || src.includes('refreshLive(') || src.includes('loadAll()')) {
		fail(`${label} must remain a cache-aware entry and not duplicate page logic`);
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
	    !src.includes('nss.ecm_active') ||
	    !src.includes('nss.ecm_offload_active') ||
	    !src.includes('nss.direct_state_readable') ||
	    !src.includes('nss.direct_supported')) {
		fail('view/lanspeed/config.js must also detect NSS from runtime capabilities and NSS offload evidence');
	}
	if (!src.includes('function daeRuntimeActive(') ||
	    !src.includes("typeof dae.runtime_active === 'boolean'") ||
	    !src.includes('dae.dae_running') ||
	    !src.includes('dae.daed_running')) {
		fail('view/lanspeed/config.js must prefer fresh Rust dae runtime state and retain legacy process fallback');
	}
	if (src.includes('dae.dae0 || dae.dae0peer') ||
	    src.includes('dae.dae_service || dae.daed_service')) {
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
	if (!src.includes('自动模式优先使用 BPF') ||
	    !src.includes('后端会选择可用的 NSS 数据源')) {
		fail('view/lanspeed/config.js must explain the NSS auto BPF-first policy and fallback');
	}
	if (!src.includes('当前实际生效的数据源，由后端根据设备能力与运行环境选择')) {
		fail('view/lanspeed/config.js must explain the effective collector without exposing stale attach internals');
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
	if (!src.includes("show_client_status: '0'") ||
	    !src.includes('show_client_status: refs.showClientStatus.checked') ||
	    !src.includes("uci.get('lanspeed', 'main', 'show_client_status')")) {
		fail('view/lanspeed/config.js must persist a default-off show_client_status option');
	}
	if (!src.includes('显示客户端状态') ||
	    !src.includes('显示采集来源和告警状态；默认隐藏。')) {
		fail('view/lanspeed/config.js must explain the default-hidden LAN client status column');
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
	    !src.includes('fc00::/7 私有地址和 fe80::/10 链路本地地址')) {
		fail('view/lanspeed/config.js must explain the private IPv6 display toggle');
	}
	if (!src.includes('hide_ipv6_ranges')) {
		fail('view/lanspeed/config.js must expose hide_ipv6_ranges for custom IPv6 hiding');
	}
	if (!src.includes('隐藏 IPv6 范围') ||
	    !src.includes('fc00::/7 fe80::/10') ||
	    !src.includes('可添加一个或多个 IPv6 网段')) {
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
	if (!src.includes('自动模式使用 BPF 统计客户端实时速率') ||
	    !src.includes('仅统计当前 TCP/UDP 连接，不参与非 NSS 设备的实时测速')) {
		fail('view/lanspeed/config.js must make the non-NSS BPF-only live-rate policy explicit');
	}
	if (!src.includes('ifaceCfg.load(viewState)')) {
		fail('view/lanspeed/config.js must reuse ifaceConfig for interface assignments');
	}
	if (!src.includes('this.viewState = viewState') ||
	    !src.includes('viewState.markDirty = function()') ||
	    !src.includes("ui.showIndicator('uci-changes'") ||
	    !src.includes("ui.hideIndicator('uci-changes')") ||
	    !src.includes('ui.changes.displayChanges()') ||
	    !src.includes('handleSave: function()') ||
	    !src.includes('return stageSettings(this.viewState)') ||
	    !src.includes('handleSaveApply: function(ev, mode)') ||
	    !src.includes("return ui.changes.apply(mode == '0')") ||
	    !src.includes('handleReset: function()') ||
	    !src.includes('return configForm.resetAll(viewState)') ||
	    src.includes('handleSaveApply: null')) {
		fail('view/lanspeed/config.js must use the LuCI native footer, immediate native dirty indicator, apply dialog, and Save/Reset staging handlers');
	}
	if (!src.includes('ui.addNotification') || !src.includes('.catch(notifyError)')) {
		fail('view/lanspeed/config.js must surface native footer transaction failures without applying rejected changes');
	}
	if (src.includes("_('保存并重载')") || src.includes('buildSaveSection') ||
	    src.includes('lanspeed-page-actions') || src.includes("lsRpc.uciCommit('lanspeed')") ||
	    src.includes('lsRpc.reload()')) {
		fail('view/lanspeed/config.js must remove the old custom save bar, direct commit and direct daemon reload flow');
	}
	if (!src.includes('ifaceCfg.prepareSave(viewState)') ||
	    !src.includes("lsRpc.uciRevert('lanspeed')") ||
	    !src.includes("uci.load('lanspeed')")) {
		fail('view/lanspeed/config.js must stage one UCI transaction for LuCI native apply and support native reset');
	}
	if (src.includes('lsRpc.init(\'lanspeedd\', \'reload\')')) {
		fail('view/lanspeed/config.js must not reload through rc init');
	}
	if (src.includes('overview_window_samples') || src.includes('趋势采样点')) {
		fail('view/lanspeed/config.js must not expose trend sampling after the trend chart is removed');
	}
}

function assertIfaceConfigThemeLayout(src) {
	if (src.includes('有未保存的接口修改') ||
	    src.includes('存在未保存的接口修改，请先保存再扫描')) {
		fail('ifaceConfig.js must use LuCI native unsaved-change indication instead of custom inline warnings');
	}
	if (!src.includes('function markDirty(viewState)') ||
	    !src.includes('markDirty(viewState);')) {
		fail('ifaceConfig.js must notify the configuration view immediately when an interface mode changes');
	}
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
	if (src.includes('WAN / WireGuard / TUN / nssifb') ||
	    src.includes('WireGuard/TUN/VPN')) {
		fail('resources/lanspeed/ifaceConfig.js must not recommend auto-hidden TUN interfaces as visible observe candidates');
	}
	if (src.includes('ifcfgSaveBtn') || src.includes("lsRpc.uciCommit('lanspeed')") ||
	    src.includes('lsRpc.reload()')) {
		fail('resources/lanspeed/ifaceConfig.js must stage changes for the shared page save flow');
	}
}

function assertStatusViewNoInterfaceConfig(src) {
	if (/^\s*['"]require\s+lanspeed\.ifaceConfig(?:\s+as\s+\w+)?['"]\s*;/m.test(src)) {
		fail('LAN Speed status modules must not load ifaceConfig; interface assignments belong on config.js');
	}
	if (src.includes('ifaceCfg.load(viewState)')) {
		fail('LAN Speed status modules must not load interface configuration');
	}
	if (src.includes('ifaceCfg.save(viewState)')) {
		fail('LAN Speed status modules must not save interface configuration');
	}
	if (src.includes('_(\'接口配置\')') || src.includes('_(\"接口配置\")')) {
		fail('LAN Speed status modules must not render the interface configuration section');
	}
	if (src.includes('ifcfgCard')) {
		fail('LAN Speed status modules must not include the interface configuration card');
	}
	if (src.includes('lsRpc.reload()') || src.includes('btnReload') ||
	    src.includes('重载 daemon') || src.includes('正在重载')) {
		fail('LAN Speed status modules must not expose daemon reload controls on the live status page');
	}
	if (src.includes('lsRpc.init(\'lanspeedd\', \'reload\')')) {
		fail('LAN Speed status modules must not reload through rc init');
	}
	if (!src.includes('self.error = error')) {
		fail('LAN Speed status modules must surface daemon reload errors instead of swallowing them');
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
		fail('LAN Speed status modules must not render the trend chart');
	}
	if (/lsRpc\.overview\s*\(/.test(src)) {
		fail('LAN Speed status modules must not poll overview only for the removed trend chart');
	}
}

function assertStatusViewSourceOnlyState(src) {
	if (!src.includes('lanspeed-root')) {
		fail('LAN Speed status modules must scope local typography to the LAN Speed status root');
	}
	if (src.includes('.lanspeed-root{font-size:') ||
	    src.includes('.lanspeed-root button,.lanspeed-root input,.lanspeed-root select{font-size:')) {
		fail('LAN Speed status modules must not force LAN Speed root or form control text larger than the theme');
	}
	if (!src.includes('grid-template-columns:repeat(5,12.5em)') ||
	    !src.includes('row-gap:1.1em;column-gap:1.2em;align-items:center;justify-content:start;margin:0') ||
	    !src.includes('@media (max-width:1100px){.lanspeed-metrics{grid-template-columns:repeat(auto-fit,minmax(10em,1fr))}}')) {
		fail('LAN Speed status modules must keep overview metrics left-aligned with compact spacing on wide Argon layouts');
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
		fail('LAN Speed status modules must keep previous compact text sizes');
	}
	if (!src.includes('align-items:baseline') || !src.includes('white-space:nowrap')) {
		fail('LAN Speed status modules header metadata must stay aligned with the section title on Argon');
	}
	if (!src.includes('lanspeed-toolbar-left') || !src.includes('lanspeed-toolbar-filter') || !src.includes('lanspeed-toolbar-right')) {
		fail('LAN Speed status modules must group toolbar controls for Argon compatibility');
	}
	if (!src.includes('lanspeed-active-only') ||
	    !src.includes('position:relative;top:auto;right:auto;margin:0') ||
	    !src.includes("E('label', { 'class': 'lanspeed-active-only cbi-checkbox', 'for': 'lanspeed-active' }") ||
	    !src.includes("'class': 'cbi-input-checkbox'") ||
	    !src.includes("'class': 'lanspeed-active-label'")) {
		fail('LAN Speed status modules must align the active-only checkbox in the toolbar on Argon');
	}
	if (src.includes('appearance:auto') ||
	    src.includes('-webkit-appearance:checkbox')) {
		fail('LAN Speed status modules must let Aurora/LuCI theme draw the active-only checkbox');
	}
	if (!src.includes('.lanspeed-clients-card .lanspeed-table{font-weight:500}')) {
		fail('LAN Speed status modules must make the LAN client table weight stronger without enlarging it');
	}
	if (src.includes('.lanspeed-clients-card .lanspeed-table{font-size:') ||
	    src.includes('.lanspeed-clients-card .lanspeed-table>thead>tr>th,.lanspeed-clients-card .lanspeed-table>tbody>tr>td') ||
	    src.includes('.lanspeed-table>thead>tr>th,.lanspeed-table>tbody>tr>td{padding-top:.55em')) {
		fail('LAN Speed status modules must not enlarge the LAN client table text or row spacing');
	}
	if (!src.includes('collectorLabel') || src.includes("metaParts.push(_('模式 ')")) {
		fail('LAN Speed status modules header must show collector source instead of runtime mode');
	}
	if (!src.includes('function collectorClass(mode)')) {
		fail('LAN Speed status modules must style the collector source pill without using confidence text');
	}
	if (!src.includes('function effectiveCollector(status, clientsData)') ||
	    !src.includes('evidence.effective_collector') ||
	    !src.includes('clientEvidence.primary_source') ||
	    !src.includes('clientEvidence.collector_mode')) {
		fail('LAN Speed status modules must display the daemon-published collector source before rendering the header');
	}
	if (/for\s*\([^)]*clients\.length[\s\S]{0,260}?collector_mode/.test(src) ||
	    /fmt\.asArray\(clientsData && clientsData\.clients\)/.test(src)) {
		fail('LAN Speed status modules must not infer the global collector source from client rows');
	}
	if (!src.includes('refs.collectorPill') ||
	    !(src.includes('refs.collectorPill.className = collectorClass(collector)') ||
	      src.includes('refs.collectorPill.className = statusCollector.collectorClass(collector)')) ||
	    !(src.includes('refs.collectorPill.textContent = collectorLabel(collector)') ||
	      src.includes('refs.collectorPill.textContent = statusCollector.collectorLabel(collector)'))) {
		fail('LAN Speed status modules header must show the current collector source in the status pill');
	}
	if (src.includes("metaParts.push(_('采集方式 ')")) {
		fail('LAN Speed status modules header metadata must not repeat the collector source');
	}
	if (src.includes("status.collector_mode;")) {
		fail('LAN Speed status modules header must not show configured collector_mode as the current collector source');
	}
	if (!src.includes('grid-template-columns:repeat(5,12.5em)') ||
	    !src.includes('justify-content:start') ||
	    !src.includes('column-gap:1.2em')) {
		fail('LAN Speed status modules overview metrics must be left-aligned with compact desktop spacing');
	}
	if (!src.includes("return 'NSS sync'")) {
		fail('LAN Speed status modules must keep NSS sync as a clear collector label');
	}
	if (!src.includes("return 'CT-Netlink'")) {
		fail('LAN Speed status modules must keep conntrack netlink as a clear collector label');
	}
	if (/confPill|_\(['"]置信/.test(src)) {
		fail('LAN Speed status modules must not render confidence in overview header');
	}
	if (/modeLabel\s*\+\s*['"]·['"]\s*\+\s*vocab\.confidenceText/.test(src)) {
		fail('LAN Speed status modules client state must show collector source without confidence suffix');
	}
	if (src.includes('置信度：')) {
		fail('LAN Speed status modules client state tooltip must not expose confidence text');
	}
	if (!src.includes("return 'NSS-direct'")) {
		fail('LAN Speed status modules must keep existing nss_ecm_direct label');
	}
	if (!src.includes('function isIpv6Address(ip)') ||
	    !src.includes('function parseIpv6ToWords(ip)') ||
	    !src.includes('function parseIpv6Cidr(range)') ||
	    !src.includes('function isIpInIpv6Ranges(ip, ranges)') ||
	    !src.includes('function displayIpsForClient(ips, showIpv6, hidePrivateIpv6, hideIpv6Ranges)')) {
		fail('LAN Speed status modules must filter IPv6 display through custom range helpers');
	}
	if (!src.includes("DEFAULT_HIDE_IPV6_RANGES = 'fc00::/7 fe80::/10'") ||
	    !src.includes('hidePrivateIpv6') ||
	    !src.includes('hideIpv6Ranges')) {
		fail('LAN Speed status modules must hide configurable IPv6 ranges when the private IPv6 option is enabled');
	}
	if (!src.includes("lsRpc.uciGet('lanspeed', 'main')") ||
	    !src.includes('show_ipv6') ||
	    !src.includes('hide_private_ipv6') ||
	    !src.includes('hide_ipv6_ranges')) {
		fail('LAN Speed status modules must read IPv6 display options before rendering client IPs');
	}
	if (!src.includes("showClientStatus: uciMain.show_client_status === '1'") ||
	    !src.includes('showClientStatus: false') ||
	    !src.includes('showClientStatus: data.showClientStatus === true') ||
	    !src.includes('self.showClientStatus = next.showClientStatus')) {
		fail('LAN Speed status modules must load show_client_status as a default-off UCI display option');
	}
	if (!src.includes('function loadUiConfig()') ||
	    !src.includes(".catch(function() { return {}; })")) {
		fail('LAN Speed status modules must keep show_ipv6 reads non-fatal');
	}
	if (/\bvar ips = fmt\.asArray\(c\.ips\);/.test(src)) {
		fail('LAN Speed status modules must not render raw client IP arrays directly');
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
	if (!src.includes('function isBootstrap') ||
	    !src.includes('/luci-static/bootstrap/') ||
	    !src.includes('/luci-static/bootstrap-dark/') ||
	    !src.includes('/luci-static/bootstrap-light/') ||
	    !src.includes('lanspeed-theme-bootstrap')) {
		fail('resources/lanspeed/theme.js must detect Bootstrap and its dark/light asset variants before applying the scoped class');
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
		fail('LAN Speed status modules must keep Aurora overview metrics left-aligned with fixed-width columns');
	}
	if (!src.includes('.lanspeed-theme-argon .lanspeed-metrics{grid-template-columns:repeat(auto-fit,minmax(10.5em,12.5em));')) {
		fail('LAN Speed status modules must keep Argon overview metrics left-aligned with fixed-width columns');
	}
	if (!src.includes('justify-content:start')) {
		fail('LAN Speed status modules must keep overview metric grids left-aligned');
	}
}

function assertStatusThemeMobileOverflow(src) {
	if (!src.includes('.lanspeed-theme-argon .lanspeed-details-body{padding:.85rem 1rem;overflow-x:auto}')) {
		fail('LAN Speed status modules must keep Argon mobile status tables horizontally scrollable inside clipped theme cards');
	}
}

function assertStatusStyleModule(src) {
	if (!src.includes('CSS: LAYOUT_CSS') ||
	    !src.includes('.lanspeed-theme-aurora ') ||
	    !src.includes('.lanspeed-theme-argon ') ||
	    !src.includes('.lanspeed-theme-bootstrap') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-metrics{grid-template-columns:repeat(auto-fit,minmax(10.5em,12.5em));') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-details-body{padding:.85rem 1rem;overflow-x:auto}')) {
		fail('lanspeed/statusStyle.js must own status view CSS, including Aurora/Argon theme rules');
	}
	if (!src.includes('.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-body{overflow-x:auto}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-body{overflow-x:auto}')) {
		fail('lanspeed/statusStyle.js must keep client tables scrollable above the narrow stacked breakpoint');
	}
	if (!src.includes('.lanspeed-clients-card .lanspeed-table th[hidden],') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table td[hidden]{display:none!important}')) {
		fail('lanspeed/statusStyle.js must keep configured-hidden status headers and cells hidden in every theme and breakpoint');
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
	if (!src.includes('.lanspeed-clients-card .lanspeed-body{overflow-x:hidden}') ||
	    !src.includes('grid-template-columns:repeat(6,minmax(0,1fr));gap:.25em;') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table tbody>tr{display:grid;') ||
	    !src.includes('grid-template-columns:repeat(2,minmax(0,1fr));gap:.45em .75em;') ||
	    !src.includes('.lanspeed-header,.lanspeed-details>summary{align-items:center}') ||
	    !src.includes('.lanspeed-details-body{max-width:100%;overflow-x:auto}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table td[data-label]::before{content:attr(data-label);') ||
	    !src.includes('@media (min-width:701px) and (max-width:900px){') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table{table-layout:fixed;min-width:0}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table th:nth-child(7),.lanspeed-clients-card .lanspeed-table td:nth-child(7){width:16%}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table thead>tr{') ||
	    !src.includes('grid-template-columns:repeat(3,minmax(0,1fr));row-gap:.35em}') ||
	    !src.includes('.lanspeed-theme-aurora .lanspeed-toolbar input[type=search]{min-width:0;width:100%;max-width:none}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-toolbar input[type=search]{min-width:0;width:100%;max-width:none}')) {
		fail('lanspeed/statusStyle.js must stack client data without horizontal scrolling on narrow screens');
	}
	if (src.includes('.lanspeed-clients-card .lanspeed-table thead{display:none}')) {
		fail('lanspeed/statusStyle.js must keep direct header sorting available on narrow screens');
	}
	if (!src.includes('.lanspeed-clients-card .lanspeed-table[data-client-status="hidden"]{table-layout:fixed}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table[data-client-status="hidden"] td:nth-child(7){width:0}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table[data-client-status="hidden"] td:nth-child(1){width:22%}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table[data-client-status="hidden"] td:nth-child(2){width:26%}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table[data-client-status="hidden"] td:nth-child(6){width:13%}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table[data-client-status="hidden"] td:nth-child(1){width:24%}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table[data-client-status="hidden"] td:nth-child(2){width:20%}') ||
	    !src.includes('.lanspeed-clients-card .lanspeed-table[data-client-status="hidden"] td:nth-child(6){width:14%}') ||
	    src.includes('[data-client-status="shown"]')) {
		fail('lanspeed/statusStyle.js must spread all six visible columns only while client status is hidden');
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
	if (!src.includes('.lanspeed-theme-argon .lanspeed-table .mono{font-size:.96rem}')) {
		fail('lanspeed/statusStyle.js must keep Argon client MAC text readable without changing other themes');
	}
	if (!src.includes('@media (min-width:1201px){.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table{table-layout:fixed}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table th:nth-child(1),.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table td:nth-child(1){width:17rem}') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table th:nth-child(2),.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table td:nth-child(2){width:14.5rem}')) {
		fail('lanspeed/statusStyle.js must keep Argon client, MAC and upload columns balanced on desktop');
	}
	if (!src.includes('.lanspeed-theme-argon .lanspeed-header,') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-details>summary{align-items:center}') ||
	    !src.includes('font-size:1.35rem;line-height:1.25!important') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-sort-button{height:auto!important;') ||
	    !src.includes('.lanspeed-theme-argon .lanspeed-hint{padding:0}')) {
		fail('lanspeed/statusStyle.js must keep Argon headings, sort controls and interface hints optically aligned');
	}
	if (src.includes('align-items:start;justify-content:start;gap:.9rem 1rem') ||
	    src.includes('.lanspeed-theme-argon .lanspeed-metric{align-self:start}')) {
		fail('lanspeed/statusStyle.js must preserve the original Argon overview metric layout');
	}
	if (!src.includes('.lanspeed-theme-argon .lanspeed-table th:first-child,.lanspeed-theme-argon .lanspeed-table td:first-child{padding-left:.35rem}')) {
		fail('lanspeed/statusStyle.js must keep Argon status table text away from the card edge');
	}
	if (/lanspeed-(?:caps|warnings|subhead|strip)/.test(src) || src.includes('CAPS_CSS')) {
		fail('lanspeed/statusStyle.js must not retain obsolete capability or legacy warning styles');
	}
	if (src.includes('.lanspeed-diagnostic-') || src.includes('.lanspeed-diagnostics-')) {
		fail('lanspeed/statusStyle.js must not retain diagnostics-page CSS');
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
	    !src.includes('lsTheme.applyRoot(root)')) {
		fail('lanspeed/statusShell.js must own status page DOM shell construction');
	}
	if (src.includes('能力矩阵') || src.includes('全部告警') ||
	    src.includes('说明与元数据') || src.includes('nssPanel.build(refs)')) {
		fail('lanspeed/statusShell.js must remove the obsolete capability, metadata, and standalone NSS diagnostics');
	}
	if (!src.includes('接口吞吐') || !src.includes('refs.ifacesDetails') ||
	    !src.includes('refs.ifacesBody') || !src.includes('ifacesCard')) {
		fail('lanspeed/statusShell.js must preserve the interface throughput details');
	}
	if (src.includes('运行诊断') || src.includes('diagnosticStatusCard') ||
	    src.includes('lanspeed-diagnostic-') || src.includes('diagnosticsCard')) {
		fail('lanspeed/statusShell.js must not render the dedicated diagnostics page inside realtime status');
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
	if (!src.includes('refs.statusHeader') ||
	    !src.includes('refs.statusHeader.hidden = viewState.showClientStatus !== true') ||
	    src.includes("_('显示客户端状态')")) {
		fail('lanspeed/statusShell.js must apply config-driven status-column visibility without an inline switch');
	}
}

function assertStatusRefreshModule(src) {
	if (!src.includes('refreshLive: function(viewState)') ||
	    !src.includes('statusIp.displayIpsForClient') ||
	    !src.includes('statusCollector.collectorLabel') ||
	    !src.includes('lsVersion.FULL_VERSION')) {
		fail('lanspeed/statusRefresh.js must own status page live refresh rendering');
	}
	if (!src.includes('fmt.sortClients(filtered, prefs.sortKey, prefs.sortDir, latestSample, activeCfg)') ||
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
	if (!src.includes('var showClientStatus = viewState.showClientStatus === true;') ||
	    !src.includes('setClientStatusVisibility(refs, showClientStatus);') ||
	    !src.includes('clientStateCell(stateCells, showClientStatus)') ||
	    !src.includes('cell.hidden = !visible;')) {
		fail('lanspeed/statusRefresh.js must hide or show the complete client status column from UCI state');
	}
	if (src.includes('refreshDiagnostics') || src.includes('lanspeed-diagnostic-') ||
	    src.includes('diagnosticsSummary') || src.includes('importantWarnings(status.warnings')) {
		fail('statusRefresh.js must not refresh diagnostics content on the realtime status page');
	}
	if (!src.includes('viewState.interfaces') || !src.includes('refs.ifacesBody') ||
	    !src.includes('refs.ifacesSummary') || !src.includes('refs.ifacesHint')) {
		fail('statusRefresh.js must refresh the interface throughput details');
	}
	if (!src.includes('splitClientWarnings(rawWarnings, globalWarnings)') ||
	    !src.includes("modeTitle += '\\n' + vocab.warningText('conntrack_connection_only');") ||
	    src.includes("_('仅连接')") ||
	    !src.includes("_('%d 告警').format(specificWarnings.length)")) {
		fail('statusRefresh.js must fold connection-only details into the collector tooltip without rendering another label');
	}
	if (!src.includes("covQuality === 'low_traffic'") ||
	    !src.includes('LAN 流量较低，暂不计算覆盖率') ||
	    !src.includes('LAN 无活动流量')) {
		fail('statusRefresh.js must distinguish low traffic from a truly idle LAN');
	}
	if (!src.includes("'class': 'lanspeed-connection-link'") ||
	    !src.includes('clientConnections.detailHref(window.location.pathname, c.identity_key)') ||
	    !src.includes("'aria-label':") || !src.includes("'title':") ||
	    !src.includes('查看') || !src.includes('当前连接')) {
		fail('statusRefresh.js must wrap only identified client display names in an accessible encoded detail link on the current pathname');
	}
}

function assertDiagnosticsStyleModule(src) {
	if (!src.includes('CSS: DIAGNOSTICS_CSS') ||
	    !src.includes('.lanspeed-diagnostics-root.lanspeed-theme-aurora') ||
	    !src.includes('.lanspeed-diagnostics-root.lanspeed-theme-argon') ||
	    !src.includes('.lanspeed-diagnostics-root.lanspeed-theme-bootstrap') ||
	    !src.includes('.lanspeed-diagnostic-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))') ||
	    !src.includes('@media (max-width:900px){.lanspeed-diagnostics-root .lanspeed-diagnostic-grid{grid-template-columns:minmax(0,1fr)}')) {
		fail('lanspeed/diagnosticsStyle.js must provide dedicated Base, Aurora, Argon, Bootstrap and responsive diagnostics CSS');
	}
}

function assertDiagnosticsShellModule(src) {
	if (!src.includes('buildShell: function(viewState)') ||
	    !src.includes('diagnosticsStyle.CSS') ||
	    !src.includes('lsTheme.applyRoot(root)') ||
	    !src.includes("diagnosticStatusCard(refs, 'plugin'") ||
	    !src.includes("diagnosticStatusCard(refs, 'backend'") ||
	    !src.includes("diagnosticStatusCard(refs, 'bpf'") ||
	    !src.includes("E('h3', {}, _('运行诊断'))")) {
		fail('lanspeed/diagnosticsShell.js must own the independent diagnostics page DOM');
	}
	if (src.includes("E('details'") || src.includes('refs.diagnostics')) {
		fail('lanspeed/diagnosticsShell.js must show the new diagnostics page directly, not retain the old collapsed details panel');
	}
}

function assertDiagnosticsRefreshModule(src) {
	if (!src.includes('refreshStatusCards: refreshStatusCards') ||
	    !src.includes("refs, 'plugin', 'good'") ||
	    !src.includes("refs, 'backend'") ||
	    !src.includes("refs, 'bpf'") ||
	    !src.includes('vocab.importantWarnings(runtime.warnings, runtime)') ||
	    !src.includes('未发现影响实时测速的异常') ||
	    !src.includes('lsVersion.FULL_VERSION')) {
		fail('lanspeed/diagnosticsRefresh.js must render plugin, backend, BPF and actionable warning state');
	}
}

function assertDiagnosticsViewModule(src) {
	if (!src.includes('lsRpc.status()') ||
	    !src.includes('lsRpc.health()') ||
	    !src.includes('lsRpc.clients()') ||
	    !src.includes('diagnosticsShell.buildShell(viewState)') ||
	    !src.includes('diagnosticsRefresh.refresh(viewState)')) {
		fail('lanspeed/diagnosticsView.js must load health data and render the independent diagnostics page');
	}
}

function assertConfigStyleModule(src) {
	if (!src.includes('CSS: CONFIG_CSS') ||
	    !src.includes('.lanspeed-theme-aurora ') ||
	    !src.includes('.lanspeed-theme-argon ') ||
	    !src.includes('.lanspeed-theme-bootstrap') ||
	    !src.includes('.lanspeed-config-table')) {
		fail('lanspeed/configStyle.js must own config view CSS, including Aurora, Argon and Bootstrap theme rules');
	}
	if (src.includes('.lanspeed-page-actions')) {
		fail('lanspeed/configStyle.js must not retain styles for the removed custom save bar');
	}
	if (!src.includes("var ROOT_SCOPE = ':is(.lanspeed-config-root.lanspeed-theme-aurora,'") ||
	    !src.includes("'.lanspeed-config-root.lanspeed-theme-bootstrap)'") ||
	    !src.includes("ROOT_SCOPE + ' .lanspeed-ifcfg-table tbody tr{display:grid;'") ||
	    !src.includes('grid-template-areas:"iface badge" "action action";') ||
	    !src.includes('grid-template-columns:repeat(3,minmax(0,1fr));width:100%;min-width:0;max-width:100%;') ||
	    !src.includes('min-height:2.5rem;box-sizing:border-box;')) {
		fail('lanspeed/configStyle.js must render mobile interface rows and three-state controls within every supported theme width');
	}
	if (!src.includes("'.lanspeed-theme-aurora .lanspeed-config-table td:nth-child(2),'") ||
	    !src.includes("'.lanspeed-theme-argon .lanspeed-config-table td:nth-child(2){width:18rem}'")) {
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
	if (!src.includes("'.lanspeed-theme-argon{display:flex;flex-direction:column;gap:1rem;margin:0}'") ||
	    !src.includes("'.lanspeed-theme-argon{font-size:1rem}'") ||
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
	if (!src.includes('.lanspeed-config-root.lanspeed-theme-argon .lanspeed-range-text,') ||
	    !src.includes('height:2.5rem;min-height:2.5rem;box-sizing:border-box') ||
	    !src.includes('.lanspeed-config-root.lanspeed-theme-argon .cbi-button,') ||
	    !src.includes('display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;') ||
	    !src.includes('.lanspeed-config-root.lanspeed-theme-argon .lanspeed-hint{padding:0}')) {
		fail('lanspeed/configStyle.js must align Argon range inputs, buttons, labels and hint text without changing other themes');
	}
}

function assertConfigFormModule(src) {
	if (!src.includes('DEFAULTS: DEFAULTS') ||
	    !src.includes('loadValues: function()') ||
	    !src.includes('buildDaemonSection: function(values, viewState)') ||
	    !src.includes('saveAll: function(viewState)') ||
	    !src.includes('resetAll: function(viewState)') ||
	    !src.includes('applyRuntimeInfo(refs, values.status || {})')) {
		fail('lanspeed/configForm.js must own config defaults, rendering and native-footer save/reset flows');
	}
	if (src.includes('function buildSaveSection(') || src.includes("_('保存并重载')") ||
	    src.includes('lanspeed-page-actions') || src.includes("lsRpc.uciCommit('lanspeed')") ||
	    src.includes('lsRpc.reload()')) {
		fail('lanspeed/configForm.js must not retain the removed custom save bar or direct apply implementation');
	}
	if (src.includes("E('span', { 'class': 'sum' }, _('UCI'))")) {
		fail('lanspeed/configForm.js must not show a redundant UCI badge in the runtime settings header');
	}
	if (src.includes("E('th', {}, _('UCI'))")) {
		fail('lanspeed/configForm.js must not show a UCI column in the runtime settings table');
	}
	if (!src.includes('viewState.ifaceOriginal = values.interfaceConfig') ||
	    !src.includes("uci.unload('lanspeed')") ||
	    !src.includes("uci.load('lanspeed')") ||
	    !src.includes("lsRpc.uciRevert('lanspeed')")) {
		fail('configForm.js must retain the raw interface baseline, refresh LuCI UCI cache, and revert failed raw writes');
	}
	if (!src.includes('function markDirty(viewState)') ||
	    !src.includes("control.addEventListener('change'") ||
	    !src.includes('markDirty(refs.viewState)')) {
		fail('configForm.js must report daemon, range and default-value edits to the native unsaved indicator');
	}
	if (!src.includes("E('tr', { 'class': 'lanspeed-range-row' }, [")) {
		fail('configForm.js must identify the multi-control IPv6 range row for theme-specific alignment');
	}
	[
		'rate_collector_mode',
		'conn_collector_mode',
		'active_client_window_ms',
		'active_client_min_bps',
		'show_client_status',
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
	const requires = moduleRequireNames(src);
	if (JSON.stringify(requires) !== JSON.stringify([
		'baseclass',
		'lanspeed.clientConnections',
		'lanspeed.clientDetailView',
		'lanspeed.statusOverview'
	])) {
		fail('statusView.js must require only the route parser, detail view, and existing overview view in dependency order');
	}
	const cleaned = stripComments(src);
	if (/\blsRpc\b|\brpc\b|statusShell|statusRefresh|statusStyle|set(?:Timeout|Interval)|clear(?:Timeout|Interval)|buildShell|refreshLive|loadAll|loadUiConfig/.test(cleaned)) {
		fail('statusView.js must remain a thin router without RPC, shell, refresh, style, or timer responsibilities');
	}
	if (!src.includes('clientConnections.identityFromSearch(window.location.search)') ||
	    !src.includes("route: 'overview'") || !src.includes("route: 'detail'") ||
	    !src.includes('statusView.load()') || !src.includes('statusView.render(data.data)') ||
	    !src.includes('clientDetailView.load(identityKey)') ||
	    !src.includes('clientDetailView.render(data.data)')) {
		fail('statusView.js must freeze an explicit load-time route marker and delegate load/render to overview or detail');
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
	    !src.includes('stageSettings(this.viewState)') ||
	    !src.includes("ui.changes.apply(mode == '0')") ||
	    !src.includes('configForm.resetAll(viewState)')) {
		fail('view/lanspeed/config.js must delegate CSS, loading, rendering and native footer actions to config modules');
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
assertFileExists(diagnosticsEntryFile, 'diagnostics view entry');
assertFileExists(configViewFile, 'config view entry');
assertFileExists(statusViewFile, 'status view module');
assertSemanticResourceNames();
assertViewEntries();

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
	if (name === 'clientConnections.js') {
		assertClientConnectionsModule(src);
	}
	if (name === 'clientDetailRefresh.js') {
		assertClientDetailRefreshSource(src);
		assertClientDetailRefreshBehavior(src);
	}
	if (name === 'clientDetailView.js') {
		assertClientDetailViewSource(src);
		assertClientDetailViewLifecycle(src);
		assertClientDetailGeoLifecycle(src);
		assertClientDetailIntegratedState(src);
	}
	if (name === 'clientDetailShell.js') {
		assertClientDetailShellSource(src);
		assertClientDetailShellInteraction(src);
	}
	if (name === 'clientDetailStyle.js') {
		assertClientDetailStyleComposer(src);
	}
	if (name === 'diagnosticsStyle.js') {
		assertDiagnosticsStyleModule(styleSources(name, DIAGNOSTICS_STYLE_PARTS));
	}
	if (CLIENT_DETAIL_STYLE_PARTS.includes(name)) {
		assertClientDetailStyleLeaf(name, src);
	}
	if (name === 'ifaceConfig.js') {
		assertIfaceConfigThemeLayout(src);
		assertIfaceSaveBehavior(src);
	}
	if (name === 'vocab.js') {
		assertWarningAliases(src);
	}
	if (name === 'rpc.js') {
		assertRpcModule(src);
	}
	if (name === 'theme.js') {
		assertThemeModule(src);
	}
	if (name === 'version.js') {
		assertVersionModule(src);
	}
	if (name === 'statusStyle.js') {
		assertStatusStyleModule(styleSources(name, STATUS_STYLE_PARTS));
	}
	if (STATUS_STYLE_PARTS.includes(name) || DIAGNOSTICS_STYLE_PARTS.includes(name) ||
	    CLIENT_DETAIL_STYLE_PARTS.includes(name) ||
	    CONFIG_STYLE_PARTS.includes(name))
		assertStyleModuleIsolation(name, src);
	if (name === 'diagnosticsShell.js') {
		assertDiagnosticsShellModule(src);
	}
	if (name === 'diagnosticsRefresh.js') {
		assertDiagnosticsRefreshModule(src);
	}
	if (name === 'diagnosticsView.js') {
		assertDiagnosticsViewModule(src);
	}
	if (name === 'statusView.js') {
		assertStatusViewEntryIsThin(src);
		assertStatusViewRouterBehavior(src);
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
		assertStatusRefreshSortingInteraction(src);
		assertStatusRefreshClientDetailLink(src);
	}
	if (name === 'configStyle.js') {
		assertConfigStyleModule(styleSources(name, CONFIG_STYLE_PARTS));
	}
	if (name === 'configForm.js') {
		assertConfigFormModule(src);
		assertConfigCompatibility(src);
	}
});

assertStyleAggregation();
assertArgonAlignmentContracts();
assertConnectionStyleOwnership();

assertConfigSaveBehavior(
	readModuleByName('configForm.js'),
	readModuleByName('ifaceConfig.js')
);

RPC_FREE_MODULES.forEach(function(name) {
	const p = path.join(modDir, name);
	if (!fs.existsSync(p)) return;
	const cleaned = stripComments(readModule(p));
	assertNoRpcDeclare(cleaned, `resources/lanspeed/${name}`);
});

if (fs.existsSync(viewFile)) {
	const vsrc = readModule(viewFile);
	const vcleaned = stripComments(vsrc);
	assertStrict(vsrc, 'view/lanspeed/overview.js');
	assertCacheAwareViewEntry(vsrc, 'lanspeed.statusView', 'view/lanspeed/overview.js');
	assertSyntax(vsrc, 'view/lanspeed/overview.js');
	assertNoRpcDeclare(vcleaned, 'view/lanspeed/overview.js');
}

if (fs.existsSync(diagnosticsEntryFile)) {
	const dsrc = readModule(diagnosticsEntryFile);
	const dcleaned = stripComments(dsrc);
	assertStrict(dsrc, 'view/lanspeed/diagnostics.js');
	assertCacheAwareViewEntry(dsrc, 'lanspeed.diagnosticsView', 'view/lanspeed/diagnostics.js');
	assertSyntax(dsrc, 'view/lanspeed/diagnostics.js');
	assertNoRpcDeclare(dcleaned, 'view/lanspeed/diagnostics.js');
}

if (fs.existsSync(statusViewFile)) {
	const vsrc = readModule(statusViewFile);
	const vcleaned = stripComments(vsrc);
	const statusSrc = [
		vsrc,
		readModuleByName('statusOverview.js'),
		readModuleByName('clientDetailView.js'),
		readModuleByName('clientDetailRefresh.js'),
		readModuleByName('statusStyle.js'),
		...STATUS_STYLE_PARTS.map(readModuleByName),
		readModuleByName('statusIp.js'),
		readModuleByName('statusCollector.js'),
		readModuleByName('statusShell.js'),
		readModuleByName('statusRefresh.js'),
		readModuleByName('vocab.js')
	].join('\n');
	assertStatusViewNoInterfaceConfig(statusSrc);
	assertNoInlineNavigation(statusSrc, 'lanspeed/statusView.js');
	assertStatusViewNoTrend(statusSrc);
	assertStatusViewSourceOnlyState(statusSrc);
	/* View should no longer declare rpc; it goes through lsRpc */
	assertNoRpcDeclare(vcleaned, 'lanspeed/statusView.js');
}

if (fs.existsSync(configViewFile)) {
	const csrc = readModule(configViewFile);
	const ccleaned = stripComments(csrc);
		const configSrc = [
			csrc,
			readModuleByName('configStyle.js'),
			...CONFIG_STYLE_PARTS.map(readModuleByName),
			readModuleByName('configForm.js'),
			readModuleByName('ifaceConfig.js')
		].join('\n');
	assertStrict(csrc, 'view/lanspeed/config.js');
	assertConfigViewRequires(csrc);
	assertThemeWiring(csrc, 'view/lanspeed/config.js');
	assertConfigViewEntryIsThin(csrc);
	assertConfigView(configSrc);
	assertConfigViewNativeActions(csrc);
	assertNoInlineNavigation(configSrc, 'view/lanspeed/config.js');
	assertSyntax(csrc, 'view/lanspeed/config.js');
	assertNoRpcDeclare(ccleaned, 'view/lanspeed/config.js');
}

function finish() {
	if (errors.length) {
		console.error('validate-lanspeed-modules: FAIL');
		errors.forEach(function(e) { console.error('  - ' + e); });
		process.exitCode = 1;
		return;
	}

	console.log('validate-lanspeed-modules: PASS');
	console.log(`  modules checked: ${EXPECTED_MODULES.length} (${EXPECTED_MODULES.join(', ')})`);
	console.log(`  view entry: ${path.relative(root, viewFile)}`);
	console.log(`  diagnostics entry: ${path.relative(root, diagnosticsEntryFile)}`);
	console.log(`  status view: ${path.relative(root, statusViewFile)}`);
}

Promise.all(asyncChecks).then(finish, function(err) {
	fail('async module validation failed: ' + (err && err.stack || err));
	finish();
});
