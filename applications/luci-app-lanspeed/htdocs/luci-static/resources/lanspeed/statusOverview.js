'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';
'require lanspeed.statusIp as statusIp';
'require lanspeed.statusShell as statusShell';
'require lanspeed.statusRefresh as statusRefresh';

var SOURCE_KEYS = [ 'status', 'clients', 'interfaces', 'uci' ];
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
		return aggregateResults(results, startedAt);
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
		hardFailure: hardFailure
	};
}

function snapshot(viewState) {
	return {
		status: viewState.status || {},
		clients: viewState.clients || { clients: [] },
		interfaces: viewState.interfaces || { interfaces: [] },
		uci: viewState.uci || {},
		rpc: viewState.rpc || {}
	};
}

function failureData(previous, error, clock) {
	var at = clock();
	return aggregateResults(SOURCE_KEYS.map(function(key) {
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

	function schedule() {
		stopTimer();
		if (destroyed || pending || (viewState.prefs && viewState.prefs.paused)) return;
		var interval = Math.max(fmt.MIN_REFRESH_MS,
			Number(viewState.prefs && viewState.prefs.refreshMs) || fmt.MIN_REFRESH_MS);
		if (typeof timerApi.setTimeout !== 'function') return;
		timer = timerApi.setTimeout(function() {
			timer = null;
			reload(false);
		}, interval);
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
				schedule();
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

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
