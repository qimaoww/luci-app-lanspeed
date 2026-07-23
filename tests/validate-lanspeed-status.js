#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const moduleDir = path.join(root,
	'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed');

function readModule(name) {
	return fs.readFileSync(path.join(moduleDir, name), 'utf8');
}

function makeDeferred() {
	let resolve;
	let reject;
	const promise = new Promise(function(onResolve, onReject) {
		resolve = onResolve;
		reject = onReject;
	});
	return { promise, resolve, reject };
}

function translate(value) {
	return {
		format: function() {
			const args = Array.from(arguments);
			let index = 0;
			return String(value).replace(/%(?:\.(\d+))?([dfs])/g,
				function(_match, precision, type) {
					const item = args[index++];
					if (type === 's') return String(item);
					if (type === 'd') return String(Math.trunc(Number(item)));
					return Number(item).toFixed(precision === undefined ? 6 : Number(precision));
				});
		},
		toString: function() { return String(value); }
	};
}

function textOf(node) {
	if (node === null || node === undefined) return '';
	if (typeof node !== 'object') return String(node);
	return (node.children || []).map(textOf).join('');
}

function findByClass(node, className) {
	if (!node || typeof node !== 'object') return null;
	const classes = String(node.attrs && node.attrs.class || '').split(/\s+/);
	if (classes.includes(className)) return node;
	for (const child of node.children || []) {
		const found = findByClass(child, className);
		if (found) return found;
	}
	return null;
}

function findAllByClass(node, className, matches) {
	matches = matches || [];
	if (!node || typeof node !== 'object') return matches;
	const classes = String(node.attrs && node.attrs.class || '').split(/\s+/);
	if (classes.includes(className)) matches.push(node);
	(node.children || []).forEach(function(child) {
		findAllByClass(child, className, matches);
	});
	return matches;
}

function fakeElement(tag, attrs, children) {
	const node = {
		tagName: String(tag).toLowerCase(),
		attrs: Object.assign({}, attrs || {}),
		children: [],
		listeners: {},
		parentNode: null,
		style: {},
		isConnected: false,
		addEventListener: function(type, handler) { this.listeners[type] = handler; },
		setAttribute: function(name, value) {
			this.attrs[name] = String(value);
			if (name === 'class') this._className = String(value);
			if (name === 'value') this._value = String(value);
		},
		getAttribute: function(name) {
			return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null;
		},
		removeAttribute: function(name) { delete this.attrs[name]; },
		appendChild: function(child) {
			if (child === null || child === undefined || child === '') return child;
			if (child && typeof child === 'object' && child.parentNode)
				child.parentNode.removeChild(child);
			if (typeof child === 'object') child.parentNode = this;
			this.children.push(child);
			return child;
		},
		insertBefore: function(child, reference) {
			if (child && typeof child === 'object' && child.parentNode)
				child.parentNode.removeChild(child);
			const index = reference === null ? this.children.length : this.children.indexOf(reference);
			this.children.splice(index < 0 ? this.children.length : index, 0, child);
			if (child && typeof child === 'object') child.parentNode = this;
			return child;
		},
		removeChild: function(child) {
			const index = this.children.indexOf(child);
			if (index !== -1) this.children.splice(index, 1);
			if (child && typeof child === 'object') child.parentNode = null;
			return child;
		}
	};
	node._className = String(node.attrs.class || '');
	node._value = Object.prototype.hasOwnProperty.call(node.attrs, 'value')
		? String(node.attrs.value) : '';
	node._hidden = Object.prototype.hasOwnProperty.call(node.attrs, 'hidden');
	node._disabled = Object.prototype.hasOwnProperty.call(node.attrs, 'disabled');
	function append(child) {
		if (Array.isArray(child)) child.forEach(append);
		else if (child && typeof child === 'object' && !child.tagName &&
			typeof child.toString === 'function') node.appendChild(String(child));
		else node.appendChild(child);
	}
	append(children);
	Object.defineProperty(node, 'firstChild', {
		get: function() { return this.children.length ? this.children[0] : null; }
	});
	Object.defineProperty(node, 'lastChild', {
		get: function() { return this.children[this.children.length - 1]; }
	});
	Object.defineProperty(node, 'textContent', {
		get: function() { return this.children.map(textOf).join(''); },
		set: function(value) {
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
			this._value = String(value);
			this.attrs.value = this._value;
		}
	});
	return node;
}

function createContext() {
	const storage = new Map();
	const context = vm.createContext({
		console,
		setTimeout,
		clearTimeout,
		window: {
			location: { pathname: '/cgi-bin/luci/admin/status/lanspeed/overview' },
			localStorage: {
				getItem: function(key) { return storage.has(key) ? storage.get(key) : null; },
				setItem: function(key, value) { storage.set(key, String(value)); }
			}
		},
		document: { createTextNode: function(value) { return String(value); }, body: {} },
		E: fakeElement,
		_: translate
	});
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
	return context;
}

function loadFormat(context) {
	return vm.compileFunction(readModule('format.js'), [ 'baseclass' ], {
		filename: 'resources/lanspeed/format.js', parsingContext: context
	})({ extend: function(value) { return value; } });
}

function loadOverview(context, fmt, rpc, modules) {
	modules = modules || {};
	return vm.compileFunction(readModule('statusOverview.js'), [
		'baseclass', 'fmt', 'lsRpc', 'statusIp', 'statusShell', 'statusRefresh'
	], { filename: 'resources/lanspeed/statusOverview.js', parsingContext: context })(
		{ extend: function(value) { return value; } },
		fmt,
		rpc,
		{
			DEFAULT_HIDE_IPV6_RANGES: '',
			hideIpv6RangesValue: function(value) { return value || ''; }
		},
		modules.shell || { buildShell: function() { return { root: fakeElement('div'), refs: {} }; } },
		modules.refresh || { refreshLive: function() {} }
	);
}

function successRpc(at) {
	return {
		status: { ok: true, retained: false, error: null, checkedAt: at, lastSuccessAt: at },
		clients: { ok: true, retained: false, error: null, checkedAt: at, lastSuccessAt: at },
		interfaces: { ok: true, retained: false, error: null, checkedAt: at, lastSuccessAt: at },
		uci: { ok: true, retained: false, error: null, checkedAt: at, lastSuccessAt: at }
	};
}

function normalizedResult(marker, at) {
	return {
		status: { marker: marker, version: '1.1.3-r2' },
		clients: { clients: [] },
		interfaces: { interfaces: [] },
		uci: {},
		rpc: successRpc(at),
		checkedAt: at
	};
}

async function testIndependentRpcSettlement(context, fmt) {
	let tick = 1000;
	const clock = function() { tick += 10; return tick; };
	const rpc = {
		status: function() { return Promise.resolve({ version: '1.1.3-r2' }); },
		clients: function() { return Promise.reject(new Error('clients down')); },
		interfaces: function() { return Promise.resolve({ interfaces: [ { name: 'br-lan' } ] }); },
		uciGet: function() { return Promise.reject(new Error('uci down')); }
	};
	const overview = loadOverview(context, fmt, rpc);
	const partial = await overview.loadAll(null, clock);
	assert.strictEqual(partial.rpc.status.ok, true);
	assert.strictEqual(partial.rpc.interfaces.ok, true);
	assert.strictEqual(partial.rpc.clients.ok, false);
	assert.strictEqual(partial.rpc.clients.retained, false);
	assert.deepStrictEqual(Array.from(partial.clients.clients), []);
	assert.strictEqual(partial.degraded, true);
	assert.strictEqual(partial.hardFailure, false);

	rpc.clients = function() { return Promise.resolve({ clients: [ { hostname: 'kept' } ] }); };
	rpc.uciGet = function() { return Promise.resolve({ show_client_status: '1' }); };
	const first = await overview.loadAll(null, clock);
	const firstClientSuccess = first.rpc.clients.lastSuccessAt;
	rpc.clients = function() { return Promise.reject(Object.assign(new Error('temporary'), { code: 7 })); };
	rpc.interfaces = function() { return Promise.reject(new Error('interfaces down')); };
	const retained = await overview.loadAll(first, clock);
	assert.strictEqual(retained.clients.clients[0].hostname, 'kept');
	assert.strictEqual(retained.rpc.clients.ok, false);
	assert.strictEqual(retained.rpc.clients.retained, true);
	assert.strictEqual(retained.rpc.clients.lastSuccessAt, firstClientSuccess);
	assert.strictEqual(retained.rpc.clients.error.code, 7);
	assert.strictEqual(retained.rpc.interfaces.retained, true);

	rpc.status = function() { return Promise.reject(new Error('status down')); };
	rpc.clients = function() { return Promise.reject(new Error('clients down')); };
	rpc.interfaces = function() { return Promise.reject(new Error('interfaces down')); };
	rpc.uciGet = function() { throw new Error('uci sync failure'); };
	const hard = await overview.loadAll(null, clock);
	assert.strictEqual(hard.hardFailure, true);
	assert.strictEqual(Object.values(hard.rpc).every(function(item) {
		return item.ok === false && item.retained === false;
	}), true);

	rpc.status = function() { return Promise.resolve({}); };
	rpc.clients = function() { return Promise.resolve({ clients: 'not-an-array' }); };
	rpc.interfaces = function() { return Promise.resolve({ interfaces: [] }); };
	rpc.uciGet = function() { return Promise.resolve({}); };
	const malformed = await overview.loadAll(null, clock);
	assert.strictEqual(malformed.rpc.status.ok, true);
	assert.strictEqual(malformed.rpc.clients.ok, false);
	assert.strictEqual(malformed.rpc.clients.error.code, 'INVALID_RESPONSE');
}

function fakeTimers() {
	let nextId = 1;
	const entries = new Map();
	return {
		setTimeout: function(handler, delay) {
			const id = nextId++;
			entries.set(id, { handler, delay });
			return id;
		},
		clearTimeout: function(id) { entries.delete(id); },
		count: function() { return entries.size; },
		firstDelay: function() { return entries.values().next().value.delay; },
		fireFirst: function() {
			const first = entries.entries().next().value;
			if (!first) return;
			entries.delete(first[0]);
			first[1].handler();
		}
	};
}

async function testControllerLifecycle(context, fmt) {
	const rpc = {
		status: function() { return Promise.resolve({}); },
		clients: function() { return Promise.resolve({ clients: [] }); },
		interfaces: function() { return Promise.resolve({ interfaces: [] }); },
		uciGet: function() { return Promise.resolve({}); }
	};
	const overview = loadOverview(context, fmt, rpc);
	const timers = fakeTimers();
	const events = {};
	const target = {
		addEventListener: function(name, handler) { events[name] = handler; },
		removeEventListener: function(name) { delete events[name]; }
	};
	let refreshes = 0;
	let busyRefreshes = 0;
	let calls = 0;
	let deferred = makeDeferred();
	const state = Object.assign(normalizedResult('initial', 100), {
		prefs: { paused: false, refreshMs: 3000 },
		refreshLive: function() { refreshes++; },
		refreshBusy: function() { busyRefreshes++; },
		loading: false,
		manualBusy: false
	});
	const controller = overview.createController(state, {
		load: function() { calls++; return deferred.promise; },
		timerApi: timers,
		eventTarget: target,
		now: function() { return 500; }
	});

	controller.schedule();
	assert.strictEqual(timers.count(), 1);
	assert.strictEqual(timers.firstDelay(), 3000);
	const automatic = controller.reload(false);
	assert.strictEqual(state.loading, true);
	assert.strictEqual(state.manualBusy, false);
	const manual = controller.reload(true);
	assert.strictEqual(automatic, manual);
	assert.strictEqual(state.loading, true);
	assert.strictEqual(state.manualBusy, true);
	assert.strictEqual(busyRefreshes, 2,
		'loading and duplicate manual joins must update only busy controls without rebuilding client rows');
	assert.strictEqual(timers.count(), 0);
	await Promise.resolve();
	assert.strictEqual(calls, 1);
	deferred.resolve(normalizedResult('fresh', 500));
	await automatic;
	assert.strictEqual(state.status.marker, 'fresh');
	assert.strictEqual(state.loading, false);
	assert.strictEqual(state.manualBusy, false);
	assert.strictEqual(timers.count(), 1);

	state.prefs.paused = true;
	controller.stopTimer();
	controller.schedule();
	assert.strictEqual(timers.count(), 0);
	state.prefs.paused = false;
	controller.schedule();
	controller.schedule();
	assert.strictEqual(timers.count(), 1);

	deferred = makeDeferred();
	timers.fireFirst();
	await Promise.resolve();
	assert.strictEqual(calls, 2);
	assert.strictEqual(timers.count(), 0);
	controller.destroy();
	deferred.resolve(normalizedResult('stale-after-destroy', 900));
	await Promise.resolve();
	await Promise.resolve();
	assert.strictEqual(state.status.marker, 'fresh');
	assert.strictEqual(timers.count(), 0);
	assert.strictEqual(controller.isDestroyed(), true);
	assert.strictEqual(events.pagehide, undefined);
	assert.strictEqual(events.beforeunload, undefined);
	assert.strictEqual(refreshes, 1,
		'only the completed sample may rebuild live client rows');
	assert.ok(busyRefreshes >= 3);
}

function testRenderWiresLiveRefresh(context, fmt) {
	let renderedState = null;
	let refreshes = 0;
	const shell = {
		buildShell: function(state) {
			renderedState = state;
			return { root: fakeElement('div'), refs: {} };
		}
	};
	const refresh = {
		refreshLive: function(state) {
			assert.strictEqual(state, renderedState);
			refreshes++;
		}
	};
	const rpc = {
		status: function() { return Promise.resolve({}); },
		clients: function() { return Promise.resolve({ clients: [] }); },
		interfaces: function() { return Promise.resolve({ interfaces: [] }); },
		uciGet: function() { return Promise.resolve({}); }
	};
	const overview = loadOverview(context, fmt, rpc, { shell: shell, refresh: refresh });
	overview.render(normalizedResult('rendered', 100));
	assert.strictEqual(typeof renderedState.refreshLive, 'function');
	assert.strictEqual(refreshes, 1);
	renderedState.refreshLive();
	assert.strictEqual(refreshes, 2);
	assert.strictEqual(typeof renderedState.reload, 'function');
}

function loadShellAndRefresh(context, fmt) {
	const baseclass = { extend: function(value) { return value; } };
	const shell = vm.compileFunction(readModule('statusShell.js'), [
		'baseclass', 'fmt', 'lsTheme', 'statusStyle', 'E', '_'
	], { filename: 'resources/lanspeed/statusShell.js', parsingContext: context })(
		baseclass, fmt, { applyRoot: function() {} }, { CSS: '' }, fakeElement, translate
	);
	const refresh = vm.compileFunction(readModule('statusRefresh.js'), [
		'baseclass', 'vocab', 'fmt', 'clientConnections', 'lsVersion',
		'statusIp', 'statusCollector', 'E', '_', 'window'
	], { filename: 'resources/lanspeed/statusRefresh.js', parsingContext: context })(
		baseclass,
		{
			CRITICAL_WARNINGS: {},
			normalizeWarningId: function(value) { return value; },
			isImportantWarning: function() { return false; },
			warningText: function(value) { return value; }
		},
		fmt,
		{ detailHref: function(pathname, key) { return pathname + '?client=' + encodeURIComponent(key); } },
		{ FULL_VERSION: '1.1.3-r2' },
		{
			hideIpv6RangesValue: function(value) { return value || ''; },
			displayIpsForClient: function(values) { return Array.isArray(values) ? values : []; }
		},
		{
			effectiveCollector: function() { return 'bpf'; },
			collectorClass: function() { return 'label label-success'; },
			collectorLabel: function() { return 'BPF'; }
		},
		fakeElement,
		translate,
		context.window
	);
	return { shell, refresh };
}

function client(index) {
	return {
		hostname: 'client-' + String(index).padStart(2, '0'),
		mac: '02:00:00:00:00:' + String(index).padStart(2, '0'),
		identity_key: 'client-' + index + '@lan',
		interface: 'br-lan',
		ips: [ '192.0.2.' + index ],
		tx_bps: index * 100,
		rx_bps: index * 200,
		tcp_conns: index,
		udp_conns: index,
		collector_mode: 'bpf',
		sample_ms: 100000,
		last_seen: 100000
	};
}

function testPaginationAndUiStates(context, fmt) {
	const items = Array.from({ length: 63 }, function(_value, index) { return index; });
	const third = fmt.paginate(items, 3, 25);
	assert.deepStrictEqual(Array.from(third.items), items.slice(50));
	assert.strictEqual(third.start, 51);
	assert.strictEqual(third.end, 63);
	assert.strictEqual(fmt.paginate(items, 99, 25).page, 3);
	assert.strictEqual(fmt.paginate([], -5, 25).page, 1);
	assert.strictEqual(fmt.paginate(items, 1, 17).pageSize, 25);
	context.window.localStorage.setItem(fmt.PREF_KEY, JSON.stringify({ pageSize: 17 }));
	assert.strictEqual(fmt.loadPrefs().pageSize, 25);
	context.window.localStorage.setItem(fmt.PREF_KEY, JSON.stringify({ pageSize: 50 }));
	assert.strictEqual(fmt.loadPrefs().pageSize, 50);

	const modules = loadShellAndRefresh(context, fmt);
	let refreshCount = 0;
	const clients = Array.from({ length: 30 }, function(_value, index) { return client(index + 1); });
	const state = {
		status: { version: '1.1.3-r2', coverage: { quality: 'idle' } },
		clients: { clients: clients },
		interfaces: { interfaces: [ { name: 'br-lan', role: 'lan', rx_bps: 100, tx_bps: 200 } ] },
		rpc: successRpc(100000),
		checkedAt: 100000,
		showClientStatus: true,
		showIpv6: true,
		hidePrivateIpv6: false,
		hideIpv6Ranges: '',
		filter: '',
		page: 1,
		prefs: {
			refreshMs: 3000,
			unit: 'bit',
			activeOnly: false,
			sortKey: 'rx',
			sortDir: 'desc',
			sortCustom: false,
			paused: false,
			pageSize: 10
		},
		now: function() { return 101000; },
		reload: function() {},
		stopTimer: function() {},
		schedule: function() {}
	};
	const built = modules.shell.buildShell(state);
	state.refs = built.refs;
	state.refreshLive = function() { refreshCount++; modules.refresh.refreshLive(state); };
	state.refreshLive();
	const toolbarRight = findByClass(built.root, 'lanspeed-toolbar-right');
	assert.strictEqual(toolbarRight.children[1], state.refs.btnRefresh);
	assert.strictEqual(toolbarRight.children[2], state.refs.btnPause);
	assert.strictEqual(state.refs.tbody.children.length, 10);
	assert.ok(textOf(state.refs.tbody.children[0]).includes('client-30'));
	assert.ok(state.refs.collectorPill.className.includes('lanspeed-collector-status'));
	assert.strictEqual(findAllByClass(built.root, 'lanspeed-collector-status').length, 1);
	assert.strictEqual(findAllByClass(built.root, 'lanspeed-service-status').length, 0);
	assert.strictEqual(findAllByClass(built.root, 'lanspeed-freshness-status').length, 0);
	assert.strictEqual(state.refs.servicePill, undefined);
	assert.strictEqual(state.refs.freshnessPill, undefined);
	assert.strictEqual(state.refs.meta.textContent, '后端 1.1.3-r2 · luci 1.1.3-r2');
	assert.ok(!state.refs.meta.textContent.includes('检查于'));
	assert.strictEqual(state.pageCount, 3);
	assert.strictEqual(state.refs.root.attrs['aria-busy'], 'false');
	assert.strictEqual(state.refs.pageNext.attrs['aria-controls'], 'lanspeed-clients-table');
	assert.ok(textOf(state.refs.pageSummary).includes('1 / 3'));
	const stableFirstRow = state.refs.tbody.children[0];
	clients[29].tx_bps = 987654;
	state.refreshLive();
	assert.strictEqual(state.refs.tbody.children[0], stableFirstRow,
		'live refresh must preserve a stable client row so its hover state does not flash');

	state.refs.pageNext.listeners.click({ preventDefault: function() {} });
	assert.strictEqual(state.page, 2);
	assert.strictEqual(state.refs.tbody.children.length, 10);
	assert.ok(textOf(state.refs.tbody.children[0]).includes('client-20'));
	state.refs.sortHeaders.hostname.button.listeners.click();
	assert.strictEqual(state.page, 1);
	state.refs.sortHeaders.hostname.button.listeners.click();
	assert.strictEqual(state.page, 1);
	assert.ok(textOf(state.refs.tbody.children[0]).includes('client-01'));
	state.page = 3;
	state.refs.filterInput.listeners.input({ target: { value: 'client-29' } });
	assert.strictEqual(state.page, 1);
	assert.strictEqual(state.refs.tbody.children.length, 1);
	state.refs.filterInput.listeners.input({ target: { value: '' } });
	state.prefs.pageSize = 10;
	state.refreshLive();
	let prevented = 0;
	state.refs.pageNav.listeners.keydown({
		key: 'End', target: state.refs.pageNav,
		preventDefault: function() { prevented++; }
	});
	assert.strictEqual(state.page, 3);
	assert.strictEqual(prevented, 1);
	state.refs.pageNav.listeners.keydown({
		key: 'Home', target: state.refs.pageNav,
		preventDefault: function() {}
	});
	assert.strictEqual(state.page, 1);
	state.page = 3;
	state.refs.activeChk.listeners.change({ target: { checked: true } });
	assert.strictEqual(state.page, 1);
	state.prefs.activeOnly = false;
	state.refreshLive();
	state.refs.pageSizeSel.listeners.change({ target: { value: '25' } });
	assert.strictEqual(state.prefs.pageSize, 25);
	assert.strictEqual(state.refs.tbody.children.length, 25);
	state.page = 9;
	state.clients = { clients: clients.slice(0, 3) };
	state.refreshLive();
	assert.strictEqual(state.page, 1);
	assert.strictEqual(state.refs.tbody.children.length, 3);
	state.loading = true;
	state.manualBusy = false;
	state.refreshLive();
	assert.strictEqual(state.refs.root.attrs['aria-busy'], 'true');
	assert.strictEqual(state.refs.btnRefresh.disabled, false);
	state.manualBusy = true;
	state.refreshLive();
	assert.strictEqual(state.refs.btnRefresh.disabled, true);
	state.loading = false;
	state.manualBusy = false;

	state.clients = { clients: [] };
	state.rpc.clients = successRpc(100000).clients;
	state.refreshLive();
	assert.ok(textOf(state.refs.empty).includes('当前采样'));
	state.status = {
		mode: 'Unsupported', capabilities: { live_metrics: false },
		evidence: { bpf: { reason_code: 'tc_attach_failed' } }, warnings: []
	};
	state.refreshLive();
	assert.strictEqual(state.refs.root.attrs['data-state'], 'bad');
	assert.ok(textOf(state.refs.empty).includes('TC 挂载未完成'));
	state.status.evidence.bpf.reason_code = 'map_read_failed';
	state.refreshLive();
	assert.ok(textOf(state.refs.empty).includes('映射表读取失败'));
	state.status.evidence.bpf.reason_code = 'no_collect_interface';
	state.refreshLive();
	assert.ok(textOf(state.refs.empty).includes('没有接口设为“采集”'));
	state.rpc.clients = {
		ok: false, retained: false, error: new Error('down'), checkedAt: 102000, lastSuccessAt: 0
	};
	state.refreshLive();
	assert.ok(textOf(state.refs.empty).includes('客户端数据不可用'));
	state.rpc.clients.retained = true;
	state.rpc.clients.lastSuccessAt = 100000;
	state.refreshLive();
	assert.ok(textOf(state.refs.empty).includes('上次成功结果'));

	Object.keys(state.rpc).forEach(function(key) {
		state.rpc[key] = {
			ok: false, retained: false, error: new Error(key + ' down'), checkedAt: 103000, lastSuccessAt: 0
		};
	});
	state.hardFailure = true;
	state.refreshLive();
	assert.strictEqual(state.refs.root.attrs['data-state'], 'bad');
	assert.strictEqual(state.refs.errorBox.attrs['aria-hidden'], 'false');
	assert.ok(textOf(state.refs.errorTitle).includes('实时状态暂不可用'));
	assert.strictEqual(state.refs.errorList.children.length, 4);
	assert.ok(refreshCount >= 10);
}

async function main() {
	const context = createContext();
	const fmt = loadFormat(context);
	await testIndependentRpcSettlement(context, fmt);
	await testControllerLifecycle(context, fmt);
	testRenderWiresLiveRefresh(context, fmt);
	testPaginationAndUiStates(context, fmt);
	console.log('validate-lanspeed-status: PASS');
	console.log('  independent RPC settlement, retained data, hard failure, single-flight refresh');
	console.log('  timer lifecycle, destroy invalidation, pagination, keyboard, ARIA, and empty states');
}

main().catch(function(error) {
	console.error('validate-lanspeed-status: FAIL');
	console.error(error && error.stack || error);
	process.exitCode = 1;
});
