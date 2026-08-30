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
				setItem: function(key, value) { storage.set(key, String(value)); },
				removeItem: function(key) { storage.delete(key); }
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
		'baseclass', 'fmt', 'lsRpc', 'statusIp', 'statusShell', 'statusRefresh', 'statusRateMeta'
	], { filename: 'resources/lanspeed/statusOverview.js', parsingContext: context })(
		{ extend: function(value) { return value; } },
		fmt,
		rpc,
		{
			DEFAULT_HIDE_IPV6_RANGES: '',
			hideIpv6RangesValue: function(value) { return value || ''; }
		},
		modules.shell || { buildShell: function() { return { root: fakeElement('div'), refs: {} }; } },
		modules.refresh || { refreshLive: function() {} },
		modules.rateMeta || { routedCollector: function(meta) {
			if (!meta || meta.scope !== 'routed_observed') return '';
			var tx = meta.tx && meta.tx.source, rx = meta.rx && meta.rx.source;
			var valid = function(source) {
				return source === 'fast_routed_internet' || source === 'fast_routed_lease';
			};
			if (!valid(tx) || !valid(rx)) return '';
			return tx === 'fast_routed_lease' || rx === 'fast_routed_lease'
				? 'fast_routed_lease' : 'fast_routed_internet';
		} }
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
		status: { marker: marker, version: '1.2.0-r3' },
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
		status: function() { return Promise.resolve({ version: '1.2.0-r3' }); },
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

	rpc.status = function() { return new Promise(function() {}); };
	rpc.clients = function() { return Promise.resolve({ clients: [] }); };
	rpc.interfaces = function() { return Promise.resolve({ interfaces: [] }); };
	rpc.uciGet = function() { return Promise.resolve({}); };
	const timedOut = await overview.loadAll(null, clock, 5);
	assert.strictEqual(timedOut.rpc.status.ok, false,
		'a hung live RPC must settle instead of stopping the refresh controller');
	assert.strictEqual(timedOut.rpc.status.error.code, 'TIMEOUT');
	assert.strictEqual(timedOut.rpc.clients.ok, true);
}

async function testAtomicRealtimeSnapshot(context, fmt) {
	let realtimeCalls = 0, uciCalls = 0, legacyCalls = 0;
	let sampleMs = 1000;
	const rpc = {
		realtime: function() {
			realtimeCalls++;
			return Promise.resolve({
				status: {
					access_edge_mode: 'active', rate_collector_mode: 'auto',
					evidence: { platform: { profile: 'nss_aarch64' }, access_edge: { sample_ms: sampleMs } }
				},
				clients: {
					clients: [ {
						identity_key: 'client@lan', interface: 'br-lan',
						collector_mode: 'access_edge', sample_ms: sampleMs,
						tx_bps: sampleMs, rx_bps: sampleMs,
						rate_meta: { tx: { source: 'edge_port' }, rx: { source: 'edge_port' } }
					} ],
					evidence: { access_edge: { sample_ms: sampleMs } }
				},
				interfaces: {
					monotonic_ms: sampleMs,
					interfaces: [ { name: 'br-lan', role: 'lan', sample_ms: sampleMs, rx_bps: 2, tx_bps: 3 } ]
				}
			});
		},
		status: function() { legacyCalls++; return Promise.resolve({}); },
		clients: function() { legacyCalls++; return Promise.resolve({ clients: [] }); },
		interfaces: function() { legacyCalls++; return Promise.resolve({ interfaces: [] }); },
		uciGet: function() { uciCalls++; return Promise.resolve({ show_client_status: '1' }); }
	};
	const overview = loadOverview(context, fmt, rpc);
	let now = 5000;
	const clock = function() { return ++now; };
	const first = await overview.loadAll(null, clock);
	assert.strictEqual(realtimeCalls, 1);
	assert.strictEqual(legacyCalls, 0, 'successful realtime must replace all three legacy live calls');
	assert.strictEqual(uciCalls, 1);
	assert.strictEqual(first.livePair.aligned, true);
	assert.strictEqual(first.clients.clients[0].tx_bps, 1000);
	assert.strictEqual(first.rpc.status.checkedAt, first.rpc.clients.checkedAt);
	assert.strictEqual(first.rpc.clients.checkedAt, first.rpc.interfaces.checkedAt);

	sampleMs = 2000;
	const second = await overview.loadAll(first, clock);
	assert.strictEqual(realtimeCalls, 2);
	assert.strictEqual(legacyCalls, 0);
	assert.strictEqual(uciCalls, 1, 'UCI display settings must be cached after the initial load');
	assert.strictEqual(second.clients.clients[0].tx_bps, 2000);
	assert.strictEqual(second.rpc.uci.cached, true);
}

async function testLiveSamplePairing(context, fmt) {
	let statusSampleMs = 1000;
	let clientSampleMs = 1000;
	let interfaceSampleMs = 1000;
	let coveragePct = 55;
	let clientRate = 111;
	let interfaceRate = 777;
	let emptyClients = false;
	let interfaceSampleQueue = [];
	let collector = 'bpf';
	const rpc = {
		status: function() {
			const rateEvidence = collector === 'nss_ecm_bpf'
				? {
					platform: { profile: 'nss_aarch64' },
					effective_collector: collector,
					ecm_bpf: { sample_ms: statusSampleMs },
					ecm_bpf_rate_window: { window_end_ms: statusSampleMs }
				} : {
					platform: { profile: 'nss_aarch64' },
					effective_collector: collector,
					bpf: { last_complete_snapshot_ms: statusSampleMs }
				};
			return Promise.resolve({
				version: '1.2.0-r3',
				coverage: { quality: 'ok', tx_pct: coveragePct, rx_pct: coveragePct },
				evidence: rateEvidence
			});
		},
		clients: function() {
			const rateEvidence = collector === 'nss_ecm_bpf'
				? {
					effective_collector: collector,
					ecm_bpf: { sample_ms: clientSampleMs },
					ecm_bpf_rate_window: { window_end_ms: clientSampleMs }
				} : { effective_collector: collector };
			return Promise.resolve({
				clients: emptyClients ? [] : [ {
					collector_mode: collector, sample_ms: clientSampleMs,
					tx_bps: clientRate, rx_bps: clientRate
				} ],
				evidence: rateEvidence
			});
		},
		interfaces: function() {
			const sampledAt = interfaceSampleQueue.length
				? interfaceSampleQueue.shift() : interfaceSampleMs;
			return Promise.resolve({
				monotonic_ms: sampledAt,
				interfaces: [ {
					name: 'br-lan', sample_ms: sampledAt,
					rx_bps: interfaceRate, tx_bps: interfaceRate
				} ]
			});
		},
		uciGet: function() { return Promise.resolve({}); }
	};
	const overview = loadOverview(context, fmt, rpc);
	let tick = 10000;
	const clock = function() { return ++tick; };

	const first = await overview.loadAll(null, clock);
	assert.strictEqual(first.livePair.sampleMs, 1000);
	assert.strictEqual(first.livePair.aligned, true);
	assert.strictEqual(first.livePair.coverageSampleMs, 1000);
	assert.strictEqual(first.status.coverage.tx_pct, 55);
	assert.strictEqual(first.clients.clients[0].tx_bps, 111);
	assert.strictEqual(first.interfaces.interfaces[0].rx_bps, 777);

	statusSampleMs = 1500;
	clientSampleMs = 1500;
	interfaceSampleMs = 1500;
	interfaceSampleQueue = [ 1600, 1500 ];
	coveragePct = 60;
	clientRate = 150;
	interfaceRate = 850;
	collector = 'nss_ecm_bpf';
	const recoveredSplit = await overview.loadAll(first, clock);
	assert.strictEqual(recoveredSplit.livePair.sampleMs, 1500);
	assert.strictEqual(recoveredSplit.livePair.aligned, true);
	assert.strictEqual(recoveredSplit.status.coverage.tx_pct, 60);
	assert.strictEqual(recoveredSplit.clients.clients[0].tx_bps, 150);
	assert.strictEqual(recoveredSplit.interfaces.interfaces[0].rx_bps, 850);
	assert.strictEqual(interfaceSampleQueue.length, 0,
		'a one-round RPC boundary split must be re-read inside the same refresh cycle');
	collector = 'bpf';

	statusSampleMs = 2000;
	clientSampleMs = 2000;
	interfaceSampleMs = 3000;
	coveragePct = 66;
	clientRate = 222;
	interfaceRate = 999;
	const straddled = await overview.loadAll(first, clock);
	assert.strictEqual(straddled.status, first.status,
		'a metric RPC boundary split must retain the complete previous status snapshot');
	assert.strictEqual(straddled.status.coverage, first.status.coverage,
		'a status/interface RPC boundary split must retain the previous coverage batch');
	assert.strictEqual(straddled.clients, first.clients,
		'a metric RPC boundary split must retain the previous client batch');
	assert.strictEqual(straddled.interfaces, first.interfaces,
		'a metric RPC boundary split must retain the previous interface batch');
	assert.strictEqual(straddled.status.coverage.tx_pct, 55,
		'retaining a metric set must never rewrite the previous coverage value');
	assert.strictEqual(straddled.clients.clients[0].tx_bps, 111,
		'retaining a metric set must never rewrite the previous client rate');
	assert.strictEqual(straddled.interfaces.interfaces[0].rx_bps, 777,
		'retaining a metric set must never rewrite the previous interface rate');
	assert.strictEqual(straddled.livePair.retained, true);
	assert.strictEqual(straddled.livePair.pendingCoverageSampleMs, 2000);
	assert.strictEqual(straddled.livePair.pendingClientSampleMs, 2000);
	assert.strictEqual(straddled.livePair.pendingInterfaceSampleMs, 3000);

	statusSampleMs = 3000;
	clientSampleMs = 3000;
	coveragePct = 77;
	const aligned = await overview.loadAll(straddled, clock);
	assert.strictEqual(aligned.livePair.sampleMs, 3000);
	assert.strictEqual(aligned.livePair.aligned, true);
	assert.strictEqual(aligned.livePair.retained, false);
	assert.strictEqual(aligned.status.coverage.tx_pct, 77,
		'the next matching coverage batch must publish its untouched backend value');
	assert.strictEqual(aligned.clients.clients[0].tx_bps, 222,
		'the next matching client batch must publish its untouched backend rate');
	assert.strictEqual(aligned.interfaces.interfaces[0].rx_bps, 999,
		'the next matching interface batch must publish its untouched backend rate');

	statusSampleMs = 5000;
	clientSampleMs = 4000;
	interfaceSampleMs = 4000;
	coveragePct = 88;
	clientRate = 333;
	interfaceRate = 1111;
	const coverageStraddled = await overview.loadAll(aligned, clock);
	assert.strictEqual(coverageStraddled.status.coverage.tx_pct, 77);
	assert.strictEqual(coverageStraddled.clients.clients[0].tx_bps, 222);
	assert.strictEqual(coverageStraddled.interfaces.interfaces[0].rx_bps, 999);
	assert.strictEqual(coverageStraddled.livePair.pendingCoverageSampleMs, 5000);
	assert.strictEqual(coverageStraddled.livePair.pendingClientSampleMs, 4000);
	assert.strictEqual(coverageStraddled.livePair.pendingInterfaceSampleMs, 4000);

	const loadStatus = rpc.status;
	rpc.status = function() { return Promise.reject(new Error('status down')); };
	const failedStatus = await overview.loadAll(coverageStraddled, clock);
	assert.strictEqual(failedStatus.status, coverageStraddled.status,
		'a failed status RPC after a boundary split must not pair old coverage with new rates');
	assert.strictEqual(failedStatus.clients, coverageStraddled.clients);
	assert.strictEqual(failedStatus.interfaces, coverageStraddled.interfaces);
	assert.strictEqual(failedStatus.livePair.retained, true);
	rpc.status = loadStatus;

	statusSampleMs = 4000;
	const coherent = await overview.loadAll(failedStatus, clock);
	assert.strictEqual(coherent.status.coverage.tx_pct, 88);
	assert.strictEqual(coherent.clients.clients[0].tx_bps, 333);
	assert.strictEqual(coherent.interfaces.interfaces[0].rx_bps, 1111);
	assert.strictEqual(coherent.livePair.sampleMs, 4000);

	statusSampleMs = 6000;
	clientSampleMs = 6000;
	interfaceSampleMs = 7000;
	coveragePct = 99;
	const coldStraddle = await overview.loadAll(null, clock);
	assert.strictEqual(coldStraddle.status.coverage, null);
	assert.deepStrictEqual(Array.from(coldStraddle.clients.clients), []);
	assert.deepStrictEqual(Array.from(coldStraddle.interfaces.interfaces), []);
	assert.strictEqual(coldStraddle.livePair.retained, false,
		'a cold start must not expose any part of a mismatched metric set');

	const loadNssStatus = rpc.status;
	const loadNssClients = rpc.clients;
	const loadNssInterfaces = rpc.interfaces;
	let nssInterfaceCalls = 0;
	rpc.status = function() {
		return Promise.resolve({
			access_edge_mode: 'active',
			evidence: { platform: { profile: 'nss_aarch64' }, access_edge: { sample_ms: 6000 } },
			coverage: { quality: 'ok', tx_pct: 99, rx_pct: 99 }
		});
	};
	rpc.clients = function() {
		return Promise.resolve({
			clients: [ {
				collector_mode: 'access_edge', sample_ms: 6000,
				tx_bps: 222, rx_bps: 222,
				rate_meta: { tx: { source: 'edge_port' }, rx: { source: 'edge_port' } }
			} ],
			evidence: { access_edge: { sample_ms: 6000 } }
		});
	};
	rpc.interfaces = function() {
		nssInterfaceCalls++;
		return loadNssInterfaces();
	};
	const coldNssEdge = await overview.loadAll(null, clock);
	assert.strictEqual(coldNssEdge.livePair.aligned, false);
	assert.strictEqual(coldNssEdge.livePair.renderable, true,
		'an NSS Access Edge cold start must render its valid client batch while independent clocks align');
	assert.strictEqual(coldNssEdge.clients.clients[0].tx_bps, 222);
	assert.strictEqual(nssInterfaceCalls, 1,
		'a renderable NSS Access Edge batch must not repeat every live RPC before first paint');
	rpc.status = loadNssStatus;
	rpc.clients = loadNssClients;
	rpc.interfaces = loadNssInterfaces;

	emptyClients = true;
	statusSampleMs = 8000;
	interfaceSampleMs = 8000;
	const empty = await overview.loadAll(coherent, clock);
	assert.deepStrictEqual(Array.from(empty.clients.clients), []);
	assert.strictEqual(empty.interfaces.interfaces[0].sample_ms, 8000);
	assert.strictEqual(empty.status.coverage.tx_pct, 99);
	assert.strictEqual(empty.livePair.sampleMs, 8000,
		'a successful empty-client response must not block a new empty live batch');

	emptyClients = false;
	rpc.status = function() {
		return Promise.resolve({
			coverage: { quality: 'ok', tx_pct: 91, rx_pct: 91 },
			evidence: {
				platform: { profile: 'nss_aarch64' },
				effective_collector: 'nss_ecm_bpf',
				ecm_bpf: { sample_ms: 10000 },
				ecm_bpf_rate_window: { window_end_ms: 9000 }
			}
		});
	};
	rpc.clients = function() {
		return Promise.resolve({
			clients: [ {
				collector_mode: 'nss_ecm_bpf', sample_ms: 9000,
				tx_bps: 900, rx_bps: 900
			} ],
			evidence: {
				effective_collector: 'nss_ecm_bpf',
				ecm_bpf: { sample_ms: 10000 },
				ecm_bpf_rate_window: { window_end_ms: 9000 }
			}
		});
	};
	interfaceSampleMs = 9000;
	const heldPublishedWindow = await overview.loadAll(empty, clock);
	assert.strictEqual(heldPublishedWindow.livePair.sampleMs, 9000);
	assert.strictEqual(heldPublishedWindow.livePair.aligned, true);
	assert.strictEqual(heldPublishedWindow.clients.clients[0].tx_bps, 900,
		'ECM+BPF alignment must use the published shared rate window instead of the newer raw collection clock');

	rpc.status = function() {
		return Promise.resolve({
			access_edge_mode: 'active',
			coverage: { quality: 'warmup' },
			evidence: {
				platform: { profile: 'nss_aarch64' },
				effective_collector: 'nss_ecm_bpf',
				ecm_bpf: { sample_ms: 11000 }
			}
		});
	};
	rpc.clients = function() {
		return Promise.resolve({
			clients: [ {
				collector_mode: 'conntrack_netlink', sample_ms: 12004,
				tx_bps: 1200, rx_bps: 1200,
				rate_meta: { tx: { source: 'edge_port' }, rx: { source: 'edge_port' } }
			} ],
			evidence: {
				effective_collector: 'nss_ecm_bpf',
				ecm_bpf: { sample_ms: 11000 },
				access_edge: { sample_ms: 12004 }
			}
		});
	};
	interfaceSampleMs = 12000;
	const activeEdge = await overview.loadAll(heldPublishedWindow, clock);
	assert.strictEqual(activeEdge.livePair.aligned, true);
	assert.strictEqual(activeEdge.livePair.coverageSampleMs, null,
		'the two-second NSS classifier clock must not gate an active one-second Edge batch');
	assert.strictEqual(activeEdge.livePair.clientSampleMs, 12004);
	assert.strictEqual(activeEdge.livePair.interfaceSampleMs, 12000);
	assert.strictEqual(activeEdge.livePair.hasClientRates, true,
		'active Edge rate_meta must remain authoritative during a rolling upgrade with a legacy collector_mode');
	assert.strictEqual(activeEdge.clients.clients[0].tx_bps, 1200,
		'active Edge clients within the 50ms read-end skew must remain visible');

	const routedRpc = {
		status: function() {
			return Promise.resolve({
				access_edge_mode: 'active', internet_view_mode: 'routed', rate_collector_mode: 'auto',
				evidence: { platform: { profile: 'nss_aarch64' }, access_edge: { sample_ms: 14000 } }
			});
		},
		clients: function() {
			return Promise.resolve({
				clients: [ {
					collector_mode: 'access_edge', sample_ms: 14200, tx_bps: 700, rx_bps: 800,
					rate_meta: {
						scope: 'routed_observed',
						tx: { source: 'fast_routed_internet', sample_ms: 14200 },
						rx: { source: 'fast_routed_internet', sample_ms: 14200 }
					}
				} ],
				evidence: { effective_collector: 'nss_ecm_bpf' }
			});
		},
		interfaces: function() {
			return Promise.resolve({ monotonic_ms: 14200,
				interfaces: [ { name: 'br-lan', sample_ms: 14200, rx_bps: 800, tx_bps: 700 } ] });
		},
		uciGet: function() { return Promise.resolve({}); }
	};
	const routedOverview = loadOverview(context, fmt, routedRpc);
	const routedBatch = await routedOverview.loadAll(null, clock);
	assert.strictEqual(routedBatch.livePair.coverageSampleMs, null,
		'explicit routed view must not use the background Access Edge clock');
	assert.strictEqual(routedBatch.livePair.hasClientRates, true,
		'explicit routed view must pair FastN+FastS client metadata even with legacy collector_mode');
	assert.strictEqual(routedBatch.livePair.clientSampleMs, 14200);
	assert.strictEqual(routedBatch.livePair.aligned, true);
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
	const visibility = {
		hidden: false,
		visibilityState: 'visible',
		addEventListener: function(name, handler) { events[name] = handler; },
		removeEventListener: function(name) { delete events[name]; }
	};
	let refreshes = 0;
	let busyRefreshes = 0;
	let calls = 0;
	let deferred = makeDeferred();
	let now = 500;
	const state = Object.assign(normalizedResult('initial', 100), {
		prefs: { paused: false, refreshMs: 3000, nssRefreshMs: 8000 },
		refreshLive: function() { refreshes++; },
		refreshBusy: function() { busyRefreshes++; },
		loading: false,
		manualBusy: false
	});
	const controller = overview.createController(state, {
		load: function() { calls++; return deferred.promise; },
		timerApi: timers,
		eventTarget: target,
		visibilityTarget: visibility,
		now: function() { return now; }
	});

	controller.schedule();
	assert.strictEqual(timers.count(), 1);
	assert.strictEqual(timers.firstDelay(), 3000);
	state.status = {
		capabilities: { nss: true },
		evidence: { platform: { profile: 'nss_aarch64' }, effective_collector: 'bpf' }
	};
	controller.schedule();
	assert.strictEqual(timers.count(), 1);
	assert.strictEqual(timers.firstDelay(), 3000,
		'pure BPF must keep the selected refresh cadence even on an NSS device');
	state.status.evidence.effective_collector = 'nss_ecm_node';
	controller.schedule();
	assert.strictEqual(timers.firstDelay(), 8000,
		'ECM must use the independently selected NSS refresh cadence');
	state.status.evidence.effective_collector = 'nss_ecm_bpf';
	controller.schedule();
	assert.strictEqual(timers.firstDelay(), 8000,
		'ECM+BPF must use the independently selected NSS refresh cadence');
	state.status = normalizedResult('initial', 100).status;
	controller.schedule();
	assert.strictEqual(timers.firstDelay(), 3000,
		'non-NSS status pages must retain the saved refresh preference');
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
	now = 1250;
	deferred.resolve(normalizedResult('fresh', 500));
	await automatic;
	assert.strictEqual(state.status.marker, 'fresh');
	assert.strictEqual(state.loading, false);
	assert.strictEqual(state.manualBusy, false);
	assert.strictEqual(timers.count(), 1);
	assert.strictEqual(timers.firstDelay(), 2250,
		'RPC time must be deducted from the refresh period instead of extending it');

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
	const rateMeta = vm.compileFunction(readModule('statusRateMeta.js'), [
		'baseclass', 'E', '_'
	], { filename: 'resources/lanspeed/statusRateMeta.js', parsingContext: context })(
		baseclass, fakeElement, translate
	);
	const refresh = vm.compileFunction(readModule('statusRefresh.js'), [
		'baseclass', 'vocab', 'fmt', 'clientConnections', 'clientControl', 'lsVersion',
		'statusIp', 'statusCollector', 'statusRateMeta', 'E', '_', 'window'
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
		{ cell: function() { return fakeElement('td', { class: 'lanspeed-client-control' }); } },
		{ FULL_VERSION: '1.2.0-r3' },
		{
			hideIpv6RangesValue: function(value) { return value || ''; },
			displayIpsForClient: function(values) { return Array.isArray(values) ? values : []; }
		},
		{
			effectiveCollector: function() { return 'bpf'; },
			collectorClass: function() { return 'label label-success'; },
			collectorLabel: function(mode) {
				return mode === 'fast_routed_internet' ? 'FastN+FastS routed Internet' : 'BPF';
			}
		}, rateMeta,
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
	context.window.localStorage.setItem(fmt.LEGACY_PREF_KEY, JSON.stringify({
		refreshMs: 3000,
		nssRefreshMs: 2000,
		pageSize: 50
	}));
	const migratedPrefs = fmt.loadPrefs();
	assert.strictEqual(migratedPrefs.refreshMs, 1000,
		'v4 refresh default must migrate to the one-second v5 default');
	assert.strictEqual(migratedPrefs.nssRefreshMs, 1000,
		'v4 NSS refresh default must migrate to the one-second v5 default');
	assert.strictEqual(migratedPrefs.pageSize, 50,
		'v4 migration must preserve explicit non-refresh preferences');
	assert.deepStrictEqual(JSON.parse(context.window.localStorage.getItem(fmt.PREF_KEY)), {
		refreshMs: 1000,
		nssRefreshMs: 1000,
		pageSize: 50
	});
	context.window.localStorage.removeItem(fmt.PREF_KEY);
	context.window.localStorage.setItem(fmt.PREF_KEY, JSON.stringify({ pageSize: 17 }));
	assert.strictEqual(fmt.loadPrefs().pageSize, 25);
	context.window.localStorage.setItem(fmt.PREF_KEY, JSON.stringify({ pageSize: 50 }));
	assert.strictEqual(fmt.loadPrefs().pageSize, 50);
	context.window.localStorage.setItem(fmt.PREF_KEY, JSON.stringify({ nssRefreshMs: 8000 }));
	assert.strictEqual(fmt.loadPrefs().nssRefreshMs, 8000);
	context.window.localStorage.setItem(fmt.PREF_KEY, JSON.stringify({ nssRefreshMs: 3000 }));
	assert.strictEqual(fmt.loadPrefs().nssRefreshMs, 1000,
		'unsupported legacy NSS cadence must normalize to the safe one-second default');

	const modules = loadShellAndRefresh(context, fmt);
	let refreshCount = 0;
	const clients = Array.from({ length: 30 }, function(_value, index) { return client(index + 1); });
	const state = {
		status: { version: '1.2.0-r3', coverage: { quality: 'idle' } },
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
	assert.strictEqual(findByClass(built.root, 'lanspeed-metrics').children.length, 4);
	assert.strictEqual(state.refs.mCoverage, undefined);
	const nssState = Object.assign({}, state, {
		status: {
			capabilities: { nss: true },
			evidence: {
				platform: { profile: 'nss_aarch64' },
				effective_collector: 'nss_ecm_bpf'
			}
		},
		prefs: Object.assign({}, state.prefs, { nssRefreshMs: 8000 })
	});
	const nssBuilt = modules.shell.buildShell(nssState);
	nssState.status.access_edge_mode = 'active';
	nssState.status.rate_collector_mode = 'auto';
	nssState.status.internet_view_mode = 'routed';
	nssState.status.evidence.platform = { profile: 'nss_aarch64' };
	nssState.clients = { clients: [ Object.assign({}, client(1), {
		collector_mode: 'access_edge',
		rate_meta: { scope: 'routed_observed',
			tx: { source: 'fast_routed_internet' }, rx: { source: 'fast_routed_internet' } }
	}) ] };
	nssState.refs = nssBuilt.refs;
	modules.refresh.refreshLive(nssState);
	assert.strictEqual(nssState.refs.collectorPill.textContent, 'FastN+FastS routed Internet',
		'explicit routed view must not be presented as automatic Access Edge');
	assert(String(nssState.refs.collectorPill.title || '').includes('互联网/路由'),
		'explicit routed view must describe its FastN+FastS scope');
	const pendingClient = Object.assign({}, client(2), {
		tx_bps: 0, rx_bps: 0, collector_mode: 'access_edge',
		rate_meta: { scope: 'none',
			tx: { source: 'none', coverage: 'unavailable' },
			rx: { source: 'none', coverage: 'unavailable' } }
	});
	nssState.clients = { clients: [ pendingClient ] };
	nssState.interfaces = { interfaces: [ {
		name: 'br-lan', role: 'lan', rx_bps: 0, tx_bps: 0,
		coverage: 'fast_routed_window_pending'
	} ] };
	nssState.livePair = { pendingClientSampleMs: 14200 };
	modules.refresh.refreshLive(nssState);
	assert.strictEqual(nssState.refs.mTx.textContent, '0');
	assert.strictEqual(nssState.refs.mRx.textContent, '0');
	assert.strictEqual(nssState.refs.mClients.textContent, '1');
	assert(!textOf(nssState.refs.tbody.children[0]).includes('—'),
		'routed rows must retain numeric zero instead of replacing it with a placeholder');
	assert.strictEqual(textOf(nssState.refs.ifacesBody.children[0]), 'br-lan0000',
		'routed interface rows must retain numeric zero values');
	assert.strictEqual(nssState.refs.ifacesSummary.textContent, '↑ 0 · ↓ 0');
	assert.strictEqual(nssBuilt.refs.intervalSel.disabled, false);
	assert.deepStrictEqual(
		Array.from(nssBuilt.refs.intervalSel.children).map(textOf),
		[ '1s', '2s', '4s', '8s', '10s' ],
		'ECM pages must expose only the five NSS-safe refresh cadences');
	modules.refresh.refreshIntervalControl(nssState, nssBuilt.refs, nssState.status);
	assert.strictEqual(nssBuilt.refs.intervalSel.value, '8000');
	nssBuilt.refs.intervalSel.value = '4000';
	nssBuilt.refs.intervalSel.listeners.change({ target: nssBuilt.refs.intervalSel });
	assert.strictEqual(nssState.prefs.nssRefreshMs, 4000);
	assert.strictEqual(nssState.prefs.refreshMs, 3000,
		'NSS selection must not overwrite the BPF refresh preference');
	nssState.status.evidence.effective_collector = 'bpf';
	modules.refresh.refreshIntervalControl(nssState, nssBuilt.refs, nssState.status);
	assert.strictEqual(nssBuilt.refs.intervalSel.disabled, false,
		'pure BPF must unlock the selector even when NSS capability remains true');
	assert.strictEqual(nssBuilt.refs.intervalSel.children.length, 5);
	nssState.status.evidence.effective_collector = 'nss_ecm_node';
	modules.refresh.refreshIntervalControl(nssState, nssBuilt.refs, nssState.status);
	assert.strictEqual(nssBuilt.refs.intervalSel.disabled, false);
	assert.strictEqual(nssBuilt.refs.intervalSel.children.length, 5);
	assert.strictEqual(nssBuilt.refs.intervalSel.value, '4000',
		'automatic recovery to ECM must restore the independent NSS preference');
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
	assert.strictEqual(state.refs.meta.textContent, '后端 1.2.0-r3 · luci 1.2.0-r3');
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
	assert.ok(textOf(stableFirstRow).includes(fmt.formatRate(987654, 'bit')),
		'a changed live rate must render the real backend value immediately without interpolation');
	assert.strictEqual(findByClass(stableFirstRow, 'lanspeed-live-rate'), null,
		'rate rendering must not introduce animation-only DOM');

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
	assert.ok(textOf(state.refs.errorTitle).includes('实时数据暂未更新'));
	assert.ok(!textOf(state.refs.errorBox).includes('不可用'));
	assert.strictEqual(state.refs.errorList.children.length, 4);
	assert.ok(refreshCount >= 10);
}

async function main() {
	const context = createContext();
	const fmt = loadFormat(context);
	await testIndependentRpcSettlement(context, fmt);
	await testAtomicRealtimeSnapshot(context, fmt);
	await testLiveSamplePairing(context, fmt);
	await testControllerLifecycle(context, fmt);
	testRenderWiresLiveRefresh(context, fmt);
	testPaginationAndUiStates(context, fmt);
	console.log('validate-lanspeed-status: PASS');
	console.log('  atomic realtime snapshot, legacy RPC fallback, paired clocks, hard failure, single-flight refresh');
	console.log('  timer lifecycle, destroy invalidation, pagination, keyboard, ARIA, and empty states');
}

main().catch(function(error) {
	console.error('validate-lanspeed-status: FAIL');
	console.error(error && error.stack || error);
	process.exitCode = 1;
});
