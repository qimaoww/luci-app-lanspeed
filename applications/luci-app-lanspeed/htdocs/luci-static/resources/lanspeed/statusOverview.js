'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';
'require lanspeed.statusIp as statusIp';
'require lanspeed.statusShell as statusShell';
'require lanspeed.statusRefresh as statusRefresh';

var SOURCE_KEYS = [ 'status', 'clients', 'interfaces', 'uci' ];
var LIVE_SOURCE_KEYS = [ 'status', 'clients', 'interfaces' ];
var ACCESS_EDGE_SAMPLE_SKEW_MS = 50;
var SOURCE_LABELS = {
	status: 'status',
	clients: 'clients',
	interfaces: 'interfaces',
	uci: 'uci'
};

function emptySource(key) {
	if (key === 'clients') return { clients: [] };
	if (key === 'interfaces') return { interfaces: [] };
	return {};
}

function sourceIsValid(key, value) {
	if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
	if (key === 'clients') return Array.isArray(value.clients);
	if (key === 'interfaces') return Array.isArray(value.interfaces);
	return true;
}

function invalidResponseError(key) {
	var error = new Error('Invalid ' + SOURCE_LABELS[key] + ' response');
	error.code = 'INVALID_RESPONSE';
	return error;
}

function errorObject(error) {
	if (error instanceof Error) return error;
	var wrapped = new Error(error && error.message
		? String(error.message)
		: (error === undefined || error === null ? 'Unknown RPC failure' : String(error)));
	if (error && typeof error === 'object' && error.code !== undefined)
		wrapped.code = error.code;
	return wrapped;
}

function hasPreviousSuccess(previous, key) {
	var state = previous && previous.rpc && previous.rpc[key];
	return !!(state && (state.ok === true || Number(state.lastSuccessAt) > 0));
}

function previousValue(previous, key) {
	if (previous && previous[key] !== undefined && previous[key] !== null)
		return previous[key];
	return emptySource(key);
}

function sampleClock(value) {
	if (value === undefined || value === null || value === '') return null;
	var clock = Number(value);
	return isFinite(clock) && clock >= 0 ? clock : null;
}

function maxSampleClock(items) {
	var latest = null;
	(items || []).forEach(function(item) {
		var clock = sampleClock(item && item.sample_ms);
		if (clock !== null && (latest === null || clock > latest)) latest = clock;
	});
	return latest;
}

function collectorEvidence(data) {
	var evidence = data && data.evidence || {};
	return {
		evidence: evidence,
		collector: evidence.effective_collector ||
			(evidence.collector && evidence.collector.primary_source) || ''
	};
}

function collectorSampleClock(data) {
	var source = collectorEvidence(data);
	var evidence = source.evidence;
	if (source.collector === 'nss_ecm_bpf') {
		var published = sampleClock(evidence.ecm_bpf_rate_window &&
			evidence.ecm_bpf_rate_window.window_end_ms);
		return published !== null ? published
			: sampleClock(evidence.ecm_bpf && evidence.ecm_bpf.sample_ms);
	}
	if (source.collector === 'nss_ecm_node')
		return sampleClock(evidence.nss_window && evidence.nss_window.window_end_ms);
	if (source.collector === 'bpf')
		return sampleClock(evidence.bpf && evidence.bpf.last_complete_snapshot_ms);
	return null;
}

function statusBatch(data) {
	var edgeActive = fmt.nssPlatform(data) && String(data && data.access_edge_mode || '') === 'active';
	var edgeSample = sampleClock(data && data.evidence && data.evidence.access_edge &&
		data.evidence.access_edge.sample_ms);
	return {
		// Active Access Edge owns the one-second client rate. The NSS classifier
		// clock is intentionally two-second and must not gate that live batch.
		sampleMs: edgeSample !== null ? edgeSample : (edgeActive ? null : collectorSampleClock(data)),
		hasCoverage: !!(data && data.coverage && typeof data.coverage === 'object')
	};
}

function clientBatch(data, status) {
	data = data || {};
	var source = collectorEvidence(data);
	var nssPlatform = fmt.nssPlatform(status);
	var collector = source.collector;
	if (!nssPlatform && (collector === 'nss_ecm_node' || collector === 'nss_ecm_bpf'))
		collector = 'bpf';
	var evidenceClock = collectorSampleClock(data);
	var edgeActive = nssPlatform && String(status && status.access_edge_mode || '') === 'active';
	var edgeClock = edgeActive ? sampleClock(data.evidence && data.evidence.access_edge &&
		data.evidence.access_edge.sample_ms) : null;

	var rateModes = nssPlatform
		? { access_edge: true, bpf: true, nss_ecm_node: true, nss_ecm_bpf: true }
		: { bpf: true };
	var rows = Array.isArray(data.clients) ? data.clients : [];
	var rateRows = rows.filter(function(item) {
		var mode = String(item && item.collector_mode || '');
		// rate_meta is authoritative while active Access Edge owns the total.
		// Accept it during a rolling daemon/LuCI upgrade even if a response still
		// carries the identity's old conntrack/NSS collector_mode.
		if (edgeActive)
			return mode === 'access_edge' || !!(item && item.rate_meta);
		return collector ? mode === collector : rateModes[mode] === true;
	});
	return {
		sampleMs: edgeClock !== null ? edgeClock :
			(evidenceClock !== null ? evidenceClock : maxSampleClock(rateRows)),
		hasRates: rateRows.length > 0
	};
}

function interfaceBatch(data) {
	data = data || {};
	var clock = sampleClock(data.monotonic_ms);
	return clock !== null ? clock : maxSampleClock(data.interfaces);
}

function livePair(data) {
	var status = statusBatch(data && data.status);
	var clients = clientBatch(data && data.clients, data && data.status);
	var interfaces = interfaceBatch(data && data.interfaces);
	var clocks = [ status.sampleMs, clients.sampleMs, interfaces ].filter(function(value) {
		return value !== null;
	});
	var comparable = clocks.length > 1;
	var skew = fmt.nssPlatform(data && data.status) && String(data && data.status && data.status.access_edge_mode || '') === 'active'
		? ACCESS_EDGE_SAMPLE_SKEW_MS : 0;
	var aligned = !comparable || clocks.every(function(value) {
		return Math.abs(value - clocks[0]) <= skew;
	});
	return {
		coverageSampleMs: status.sampleMs,
		clientSampleMs: clients.sampleMs,
		interfaceSampleMs: interfaces,
		sampleMs: aligned ? (interfaces !== null ? interfaces :
			(clients.sampleMs !== null ? clients.sampleMs : status.sampleMs)) : null,
		aligned: comparable ? aligned : null,
		hasCoverage: status.hasCoverage,
		hasClientRates: clients.hasRates,
		retained: false
	};
}

/*
 * Coverage, clients, and interfaces are separate ubus calls over one atomic
 * daemon snapshot. A collection may publish between the calls, so hold the
 * last visible metric set whenever their clocks identify different snapshots.
 */
function alignLiveSamples(next, previous) {
	var pair = livePair(next);
	if (pair.aligned !== false) {
		next.livePair = pair;
		return next;
	}

	var oldPair = previous && previous.livePair || livePair(previous);
	var canRetain = !!(previous && oldPair.aligned !== false);
	if (canRetain) {
		next.status = previousValue(previous, 'status');
		next.clients = previousValue(previous, 'clients');
		next.interfaces = previousValue(previous, 'interfaces');
	}
	else {
		var status = Object.assign({}, next.status || {});
		status.coverage = null;
		next.status = status;
		next.clients = emptySource('clients');
		next.interfaces = emptySource('interfaces');
	}
	next.livePair = {
		coverageSampleMs: oldPair.coverageSampleMs,
		clientSampleMs: oldPair.clientSampleMs,
		interfaceSampleMs: oldPair.interfaceSampleMs,
		sampleMs: oldPair.sampleMs,
		aligned: oldPair.aligned,
		hasCoverage: oldPair.hasCoverage,
		hasClientRates: oldPair.hasClientRates,
		retained: canRetain,
		pendingCoverageSampleMs: pair.coverageSampleMs,
		pendingClientSampleMs: pair.clientSampleMs,
		pendingInterfaceSampleMs: pair.interfaceSampleMs
	};
	return next;
}

function sourceSettled(key, loader, previous, clock) {
	var startedAt = clock();
	return Promise.resolve().then(function() {
		return loader();
	}).then(function(value) {
		if (!sourceIsValid(key, value)) throw invalidResponseError(key);
		var checkedAt = clock();
		return {
			key: key,
			value: value,
			rpc: {
				ok: true,
				retained: false,
				error: null,
				checkedAt: checkedAt >= startedAt ? checkedAt : startedAt,
				lastSuccessAt: checkedAt >= startedAt ? checkedAt : startedAt
			}
		};
	}).catch(function(error) {
		var checkedAt = clock();
		var old = previous && previous.rpc && previous.rpc[key];
		var retained = hasPreviousSuccess(previous, key);
		return {
			key: key,
			value: retained ? previousValue(previous, key) : emptySource(key),
			rpc: {
				ok: false,
				retained: retained,
				error: errorObject(error),
				checkedAt: checkedAt >= startedAt ? checkedAt : startedAt,
				lastSuccessAt: retained && old ? Number(old.lastSuccessAt) || 0 : 0
			}
		};
	});
}

function aggregateResults(results, checkedAt) {
	var data = { status: {}, clients: { clients: [] }, interfaces: { interfaces: [] }, uci: {} };
	var rpc = {};
	(results || []).forEach(function(result) {
		data[result.key] = result.value;
		rpc[result.key] = result.rpc;
		if (result.rpc && result.rpc.checkedAt > checkedAt)
			checkedAt = result.rpc.checkedAt;
	});
	return normalizeData({
		status: data.status,
		clients: data.clients,
		interfaces: data.interfaces,
		uci: data.uci,
		rpc: rpc,
		checkedAt: checkedAt
	});
}

function loadUiConfig() {
	return lsRpc.uciGet('lanspeed', 'main');
}

function loadAll(previous, clock) {
	clock = clock || function() { return Date.now(); };
	var loaders = {
		status: function() { return lsRpc.status(); },
		clients: function() { return lsRpc.clients(); },
		interfaces: function() { return lsRpc.interfaces(); },
		uci: loadUiConfig
	};
	var startedAt = clock();
	return Promise.all(SOURCE_KEYS.map(function(key) {
		return sourceSettled(key, loaders[key], previous, clock);
	})).then(function(results) {
		var next = aggregateResults(results, startedAt);
		var pair = livePair(next);
		var liveSucceeded = LIVE_SOURCE_KEYS.every(function(key) {
			return next.rpc[key] && next.rpc[key].ok === true;
		});
		if (pair.aligned !== false || !liveSucceeded)
			return alignLiveSamples(next, previous);

		/* Every collector can publish between the three live RPC replies. Retry the
		 * cheap snapshot reads once so an initial boundary split is not rendered as
		 * an empty page. UCI is retained from the first round. */
		var uciResult = results.filter(function(result) { return result.key === 'uci'; })[0];
		return Promise.all(LIVE_SOURCE_KEYS.map(function(key) {
			return sourceSettled(key, loaders[key], next, clock);
		})).then(function(retried) {
			if (uciResult) retried.push(uciResult);
			var recovered = aggregateResults(retried, startedAt);
			return alignLiveSamples(recovered, previous);
		});
	});
}

function normalizeData(data) {
	data = data || {};
	var uciMain = data.uci || data[3] || {};
	var status = data.status || {};
	var clients = data.clients || { clients: [] };
	var interfaces = data.interfaces || { interfaces: [] };
	var rpc = data.rpc || {};
	var failed = SOURCE_KEYS.filter(function(key) {
		return rpc[key] && rpc[key].ok === false;
	});
	var hardFailure = failed.length === SOURCE_KEYS.length && failed.every(function(key) {
		return !rpc[key].retained;
	});
	var firstError = null;
	failed.some(function(key) {
		if (rpc[key].error) { firstError = rpc[key].error; return true; }
		return false;
	});

	return {
		status: status,
		clients: clients,
		interfaces: interfaces,
		uci: uciMain,
		showClientStatus: uciMain.show_client_status === '1',
		showIpv6: uciMain.show_ipv6 !== '0',
		hidePrivateIpv6: uciMain.hide_private_ipv6 === '1',
		hideIpv6Ranges: statusIp.hideIpv6RangesValue(uciMain.hide_ipv6_ranges),
		rpc: rpc,
		checkedAt: Number(data.checkedAt) || 0,
		error: firstError,
		degraded: failed.length > 0 && !hardFailure,
		hardFailure: hardFailure,
		livePair: data.livePair || null
	};
}

function snapshot(viewState) {
	return {
		status: viewState.status || {},
		clients: viewState.clients || { clients: [] },
		interfaces: viewState.interfaces || { interfaces: [] },
		uci: viewState.uci || {},
		rpc: viewState.rpc || {},
		livePair: viewState.livePair || null
	};
}

function failureData(previous, error, clock) {
	var at = clock();
	var next = aggregateResults(SOURCE_KEYS.map(function(key) {
		var old = previous && previous.rpc && previous.rpc[key];
		var retained = hasPreviousSuccess(previous, key);
		return {
			key: key,
			value: retained ? previousValue(previous, key) : emptySource(key),
			rpc: {
				ok: false,
				retained: retained,
				error: errorObject(error),
				checkedAt: at,
				lastSuccessAt: retained && old ? Number(old.lastSuccessAt) || 0 : 0
			}
		};
	}), at);
	return alignLiveSamples(next, previous);
}

function createController(viewState, options) {
	options = options || {};
	var hostWindow = options.window || (typeof window !== 'undefined' ? window : null);
	var eventTarget = options.eventTarget || hostWindow;
	var timerApi = options.timerApi || hostWindow || {};
	var hostDocument = options.document || (typeof document !== 'undefined' ? document : null);
	var Observer = options.MutationObserver || (hostWindow && hostWindow.MutationObserver) ||
		(typeof MutationObserver !== 'undefined' ? MutationObserver : null);
	var clock = options.now || function() { return Date.now(); };
	var loader = options.load || function(previous) { return loadAll(previous, clock); };
	var pending = null;
	var requestSeq = 0;
	var timer = null;
	var destroyed = false;
	var root = null;
	var observer = null;
	var connected = false;

	function refresh(busyOnly) {
		if (busyOnly && typeof viewState.refreshBusy === 'function') viewState.refreshBusy();
		else if (typeof viewState.refreshLive === 'function') viewState.refreshLive();
	}

	function stopTimer() {
		if (timer !== null && typeof timerApi.clearTimeout === 'function')
			timerApi.clearTimeout(timer);
		timer = null;
	}

	function schedule(anchorAt) {
		stopTimer();
		if (destroyed || pending || (viewState.prefs && viewState.prefs.paused)) return;
		var interval = typeof fmt.effectiveRefreshMs === 'function'
			? fmt.effectiveRefreshMs(viewState.status, viewState.prefs)
			: Math.max(fmt.MIN_REFRESH_MS,
				Number(viewState.prefs && viewState.prefs.refreshMs) || fmt.MIN_REFRESH_MS);
		var now = clock();
		var anchor = Number(anchorAt);
		if (!isFinite(anchor) || anchor < 0 || anchor > now)
			anchor = now;
		var delay = Math.max(0, interval - Math.max(0, now - anchor));
		if (typeof timerApi.setTimeout !== 'function') return;
		timer = timerApi.setTimeout(function() {
			timer = null;
			reload(false);
		}, delay);
	}

	function apply(next) {
		var normalized = normalizeData(next);
		viewState.status = normalized.status;
		viewState.clients = normalized.clients;
		viewState.interfaces = normalized.interfaces;
		viewState.uci = normalized.uci;
		viewState.showClientStatus = normalized.showClientStatus;
		viewState.showIpv6 = normalized.showIpv6;
		viewState.hidePrivateIpv6 = normalized.hidePrivateIpv6;
		viewState.hideIpv6Ranges = normalized.hideIpv6Ranges;
		viewState.rpc = normalized.rpc;
		viewState.checkedAt = normalized.checkedAt;
		viewState.error = normalized.error;
		viewState.degraded = normalized.degraded;
		viewState.hardFailure = normalized.hardFailure;
		viewState.livePair = normalized.livePair;
		return normalized;
	}

	function reload(manual) {
		if (destroyed) return Promise.resolve(null);
		if (pending) {
			if (manual) {
				viewState.manualBusy = true;
				refresh(true);
			}
			return pending;
		}

		stopTimer();
		var startedAt = clock();
		var sequence = ++requestSeq;
		viewState.loading = true;
		viewState.manualBusy = manual === true;
		refresh(true);
		var previous = snapshot(viewState);
		var request = Promise.resolve().then(function() {
			return loader(previous);
		});
		pending = request.then(function(next) {
			if (sequence !== requestSeq || destroyed) return next;
			return apply(next);
		}, function(error) {
			var next = failureData(previous, error, clock);
			if (sequence !== requestSeq || destroyed) return next;
			return apply(next);
		}).then(function(next) {
			if (sequence === requestSeq && !destroyed) {
				viewState.loading = false;
				viewState.manualBusy = false;
				pending = null;
				refresh();
				schedule(startedAt);
			}
			return next;
		});
		return pending;
	}

	function destroy() {
		if (destroyed) return;
		destroyed = true;
		requestSeq++;
		stopTimer();
		pending = null;
		if (observer && typeof observer.disconnect === 'function') observer.disconnect();
		observer = null;
		if (eventTarget && typeof eventTarget.removeEventListener === 'function') {
			eventTarget.removeEventListener('pagehide', destroy);
			eventTarget.removeEventListener('beforeunload', destroy);
		}
		viewState.destroyed = true;
	}

	function attachRoot(nextRoot) {
		root = nextRoot;
		if (!root) return;
		if (Observer && hostDocument && hostDocument.body) {
			observer = new Observer(function() {
				if (root && root.isConnected) connected = true;
				else if (connected) destroy();
			});
			observer.observe(hostDocument.body, { childList: true, subtree: true });
		}
	}

	if (eventTarget && typeof eventTarget.addEventListener === 'function') {
		eventTarget.addEventListener('pagehide', destroy);
		eventTarget.addEventListener('beforeunload', destroy);
	}

	viewState.stopTimer = stopTimer;
	viewState.schedule = schedule;
	viewState.reload = reload;
	viewState.destroy = destroy;
	viewState.attachRoot = attachRoot;
	viewState.isDestroyed = function() { return destroyed; };
	return {
		reload: reload,
		schedule: schedule,
		stopTimer: stopTimer,
		destroy: destroy,
		attachRoot: attachRoot,
		getPending: function() { return pending; },
		isDestroyed: function() { return destroyed; }
	};
}

return baseclass.extend({
	load: function() {
		return loadAll(null).catch(function(error) {
			return failureData(null, error, function() { return Date.now(); });
		});
	},

	render: function(data) {
		var normalized = normalizeData(data);
		var viewState = {
			status: normalized.status,
			clients: normalized.clients,
			interfaces: normalized.interfaces,
			uci: normalized.uci,
			showClientStatus: normalized.showClientStatus,
			showIpv6: normalized.showIpv6,
			hidePrivateIpv6: normalized.hidePrivateIpv6,
				hideIpv6Ranges: normalized.hideIpv6Ranges,
				rpc: normalized.rpc,
				checkedAt: normalized.checkedAt,
				error: normalized.error,
				degraded: normalized.degraded,
				hardFailure: normalized.hardFailure,
				livePair: normalized.livePair,
				filter: '',
			page: 1,
			loading: false,
				manualBusy: false,
				prefs: fmt.loadPrefs(),
				refs: null
			};
			viewState.refreshLive = function() {
				return statusRefresh.refreshLive(viewState);
			};
			viewState.refreshBusy = function() {
				return statusRefresh.refreshAvailability(viewState, viewState.refs);
			};
			var controller = createController(viewState);
			var built = statusShell.buildShell(viewState);
			viewState.refs = built.refs;
			if (viewState.attachRoot) viewState.attachRoot(built.root);
			viewState.refreshLive();
		viewState.schedule();
		return built.root;
	},

	createController: createController,
	normalizeData: normalizeData,
	loadAll: loadAll,
	statusBatch: statusBatch,
	clientBatch: clientBatch,
	interfaceBatch: interfaceBatch,
	alignLiveSamples: alignLiveSamples,

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
