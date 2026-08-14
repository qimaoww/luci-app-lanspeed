'use strict';
'require baseclass';
'require lanspeed.diagnosticsSchema as schema';

var RPC_KEYS = schema.RPC_KEYS;
var RPC_LABELS = schema.RPC_LABELS;
var RESOURCE_PHASES = schema.RESOURCE_PHASES;
var HEALTH_STATES = schema.HEALTH_STATES;
var RUNTIME_MODES = schema.RUNTIME_MODES;
var CONFIDENCES = schema.CONFIDENCES;
var MAX_DIAGNOSTIC_ALERTS = schema.MAX_DIAGNOSTIC_ALERTS;
var MAX_CONFIG_ISSUES = schema.MAX_CONFIG_ISSUES;
var MAX_SUBSYSTEMS = schema.MAX_SUBSYSTEMS;
var MAX_PROBE_FAILURES = schema.MAX_PROBE_FAILURES;
var DEFAULT_RPC_TIMEOUT_MS = schema.DEFAULT_RPC_TIMEOUT_MS;
var MAX_RPC_TIMEOUT_MS = schema.MAX_RPC_TIMEOUT_MS;
var DEFAULT_RETAIN_MS = schema.DEFAULT_RETAIN_MS;
var MAX_RETAIN_MS = schema.MAX_RETAIN_MS;
var CAPABILITY_KEYS = schema.CAPABILITY_KEYS;
var BPF_ATTACH_STATES = schema.BPF_ATTACH_STATES;
var BPF_MAP_STATES = schema.BPF_MAP_STATES;
var BPF_REASON_CODES = schema.BPF_REASON_CODES;
var PROBE_KINDS = schema.PROBE_KINDS;
var PROBE_REASONS = schema.PROBE_REASONS;
var REASON_LABELS = schema.REASON_LABELS;
var SUBSYSTEM_LABELS = schema.SUBSYSTEM_LABELS;
var HEALTH_REPORT_LABELS = schema.HEALTH_REPORT_LABELS;
var PROBE_REASON_LABELS = schema.PROBE_REASON_LABELS;
var PROBE_KIND_REPORT_LABELS = schema.PROBE_KIND_REPORT_LABELS;
var INTERFACE_ROLE_REPORT_LABELS = schema.INTERFACE_ROLE_REPORT_LABELS;
var INTERFACE_STATUS_REPORT_LABELS = schema.INTERFACE_STATUS_REPORT_LABELS;
var COLLECTOR_REPORT_LABELS = schema.COLLECTOR_REPORT_LABELS;
var RATE_SOURCE_LABELS = schema.RATE_SOURCE_LABELS;
var RATE_COVERAGE_LABELS = schema.RATE_COVERAGE_LABELS;
var RATE_SCOPE_LABELS = schema.RATE_SCOPE_LABELS;
var CLASSIFICATION_STATE_LABELS = schema.CLASSIFICATION_STATE_LABELS;
var ACCESS_EDGE_REASON_LABELS = schema.ACCESS_EDGE_REASON_LABELS;
var FDB_SOURCE_LABELS = schema.FDB_SOURCE_LABELS;
var asArray = schema.asArray;
var plainObject = schema.plainObject;
var hasOwn = schema.hasOwn;
var finiteNumber = schema.finiteNumber;
var safeInteger = schema.safeInteger;
var nonNegativeInteger = schema.nonNegativeInteger;
var boundedString = schema.boundedString;
var codeString = schema.codeString;
var enumValue = schema.enumValue;
var onlyFields = schema.onlyFields;
var failure = schema.failure;
var requireFields = schema.requireFields;
var uniqueIds = schema.uniqueIds;
var validatePublicError = schema.validatePublicError;
var validateDiagnosticsContract = schema.validateDiagnosticsContract;
var optionalIntegers = schema.optionalIntegers;
var validateCapabilities = schema.validateCapabilities;
var validateProbeFailures = schema.validateProbeFailures;
var validateBpfEvidence = schema.validateBpfEvidence;
var validateHealthEvidence = schema.validateHealthEvidence;
var validateCoverage = schema.validateCoverage;
var validateRateDirectionMeta = schema.validateRateDirectionMeta;
var validateRateMeta = schema.validateRateMeta;
var validateStatusResponse = schema.validateStatusResponse;
var validateHealthResponse = schema.validateHealthResponse;
var validateClientsResponse = schema.validateClientsResponse;
var validateInterfacesResponse = schema.validateInterfacesResponse;
var validateOverviewResponse = schema.validateOverviewResponse;
var validateRuntimeResponse = schema.validateRuntimeResponse;

function emptyValue(key) {
	if (key === 'diagnostics') return {};
	if (key === 'status' || key === 'health') return {};
	if (key === 'clients') return { clients: [] };
	if (key === 'interfaces') return { interfaces: [] };
	if (key === 'overview') return { samples: [] };
	return {};
}
function rpcErrorInfo(error, kind) {
	error = error || {};
	var rawCode = error.code === null || error.code === undefined ? '' : String(error.code);
	var message = error.message || error.statusText || String(error) || _('未知 RPC 失败');
	return {
		kind: kind || 'transport', code: boundedText(rawCode, 64),
		message: boundedText(message, 320), category: error.category || kind || 'transport',
		stage: error.stage || 'rpc', retriable: error.retriable !== false
	};
}

function boundedText(value, limit) {
	var text = String(value === null || value === undefined ? '' : value)
		.replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim();
	return text.length > limit ? text.slice(0, limit) + '…' : text;
}

function phaseForValue(key, value) {
	if (key === 'diagnostics') {
		var collection = value.collection || {};
		if (collection.state === 'stale') return 'stale';
		if (collection.state === 'degraded' || collection.state === 'unavailable') return 'degraded';
	}
	/*
	 * `mode` describes counter visibility/accuracy, not RPC health.  A valid
	 * status or health response is a successful RPC even when NSS acceleration
	 * makes the authoritative counter path `Degraded`.  Accuracy is rendered
	 * separately by the collection-quality and data-path stages.
	 */
	if ((key === 'clients' && !asArray(value.clients).length) ||
		(key === 'interfaces' && !asArray(value.interfaces).length) ||
		(key === 'overview' && !asArray(value.samples).length)) return 'empty';
	return 'success';
}
function retentionLimit(previous, value) {
	var interval = finiteNumber(value && value.refresh_interval_ms) ||
		finiteNumber(previous && previous.status && previous.status.refresh_interval_ms) || 1000;
	return Math.min(MAX_RETAIN_MS, Math.max(DEFAULT_RETAIN_MS, interval * 10));
}
function usableResource(resource, now, maxAge) {
	if (!resource || !resource.value || resource.phase === 'error' || resource.phase === 'invalid') return false;
	if (resource.phase === 'loading' && resource.usable !== true) return false;
	if (resource.fetchedAt === null || resource.fetchedAt === undefined) return false;
	return now >= resource.fetchedAt && now - resource.fetchedAt <= maxAge;
}
function resourceForResult(result, previousResource, previousState, checkedAt, requestId) {
	var validation;
	if (result.ok) {
		validation = result.validation || (result.key === 'diagnostics'
			? validateDiagnosticsContract(result.value)
			: validateRuntimeResponse(result.value, result.key));
		if (!validation.valid) {
			result = { key: result.key, ok: false, error: rpcErrorInfo({
				code: 'INVALID_CONTRACT', message: validation.reason, retriable: false
			}, 'contract') };
		} else {
			var phase = phaseForValue(result.key, validation.value);
			return {
				key: result.key, phase: phase, value: validation.value,
				usable: true, retained: false, fetchedAt: checkedAt, producedAt: checkedAt,
				retainedFrom: null, ageMs: 0, requestId: requestId, error: null,
				attempt: phase === 'empty' ? 'empty' : 'success'
			};
		}
	}
	var previous = previousResource;
	var maxAge = retentionLimit(previousState, previousState && previousState.status);
	if (usableResource(previous, checkedAt, maxAge)) {
		return {
			key: result.key, phase: 'stale', value: previous.value, usable: true, retained: true,
			fetchedAt: previous.fetchedAt, producedAt: previous.producedAt || previous.fetchedAt,
			retainedFrom: previous.fetchedAt, ageMs: Math.max(0, checkedAt - previous.fetchedAt),
			requestId: requestId, error: result.error || rpcErrorInfo(null, 'transport'), attempt: 'error'
		};
	}
	return {
		key: result.key, phase: result.error && result.error.kind === 'contract' ? 'invalid' : 'error',
		value: emptyValue(result.key), usable: false, retained: false, fetchedAt: null,
		producedAt: null, retainedFrom: null, ageMs: null, requestId: requestId,
		error: result.error || rpcErrorInfo(null, 'transport'), attempt: 'error'
	};
}

function runCall(item, timeoutMs) {
	var requestedTimeout = Number(timeoutMs);
	var timeout = !isFinite(requestedTimeout) || requestedTimeout <= 0
		? DEFAULT_RPC_TIMEOUT_MS : Math.min(MAX_RPC_TIMEOUT_MS, Math.max(250, requestedTimeout));
	return new Promise(function(resolve) {
		var settled = false;
		var timer = setTimeout(function() {
			if (settled) return;
			settled = true;
			resolve({ key: item.key, ok: false, error: rpcErrorInfo({
				code: 'TIMEOUT', message: _('请求超时'), retriable: true
			}, 'timeout') });
		}, timeout);
		Promise.resolve().then(item.call).then(function(value) {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			var validation = item.key === 'diagnostics'
				? validateDiagnosticsContract(value)
				: validateRuntimeResponse(value, item.key);
			if (!validation.valid) {
				resolve({ key: item.key, ok: false, validation: validation,
					error: rpcErrorInfo({ code: 'INVALID_CONTRACT', message: validation.reason,
						retriable: false }, 'contract') });
				return;
			}
			resolve({ key: item.key, ok: true, value: value, validation: validation });
		}, function(error) {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve({ key: item.key, ok: false, error: rpcErrorInfo(error, 'transport') });
		});
	});
}

function sampleClock(data) {
	data = data || {};
	function maxValue(values) {
		return asArray(values).reduce(function(maximum, value) {
			var number = finiteNumber(value);
			return number !== null && number >= 0 && number > maximum ? number : maximum;
		}, 0);
	}
	var interfaces = data.interfaces || {};
	var clients = data.clients || {};
	var overview = data.overview || {};
	var interfaceClock = maxValue([ interfaces.monotonic_ms ].concat(asArray(interfaces.interfaces).map(function(item) {
		return item && item.sample_ms;
	})));
	var clientClock = maxValue(asArray(clients.clients).map(function(item) { return item && item.sample_ms; }));
	var overviewClock = maxValue(asArray(overview.samples).map(function(item) { return item && item.sample_ms; }));
	return { interfaces: interfaceClock, clients: clientClock, overview: overviewClock,
		overall: maxValue([ interfaceClock, clientClock, overviewClock ]) };
}
function rpcResult(viewState, key) {
	return viewState && viewState.rpc && viewState.rpc[key] || null;
}
function rpcState(viewState, key) {
	var resource = viewState && viewState.resources && viewState.resources[key];
	if (resource) {
		var phase = resource.phase || 'loading';
		var retained = resource.retained === true;
		return {
			state: phase === 'stale' ? (retained ? 'retained' : 'success') :
				(phase === 'error' ? 'failed' : phase),
			phase: phase, ok: resource.usable !== false &&
				[ 'loading', 'error', 'invalid' ].indexOf(phase) === -1,
			retained: retained,
			result: resource
		};
	}
	var result = rpcResult(viewState, key);
	if (!result) return { state: 'missing', phase: 'loading', ok: false, retained: false, result: null };
	var resultPhase = result.phase || (result.ok ? 'success' : 'error');
	var resultOk = result.ok === true && [ 'loading', 'error', 'invalid' ].indexOf(resultPhase) === -1;
	return {
		state: resultOk ? 'success' : (result.retained ? 'retained' :
			(resultPhase === 'invalid' || result.error && result.error.kind === 'contract' ? 'invalid' : 'failed')),
		phase: resultPhase, ok: resultOk,
		retained: result.retained === true, result: result
	};
}
function hasPreviousValue(previous, key) {
	var resource = previous && previous.resources && previous.resources[key];
	if (resource) {
		var checkedAt = previous.checkedAt === null || previous.checkedAt === undefined ? Date.now() : previous.checkedAt;
		return usableResource(resource, checkedAt, retentionLimit(previous, previous.status));
	}
	var value = previous && previous[key];
	if (!value) return false;
	if (previous.rpc && previous.rpc[key] && previous.rpc[key].ok !== true && previous.rpc[key].retained !== true)
		return false;
	if (key === 'clients') return Array.isArray(value.clients);
	if (key === 'interfaces') return Array.isArray(value.interfaces);
	if (key === 'overview') return Array.isArray(value.samples);
	return key === 'diagnostics' ? validateDiagnosticsContract(value).valid : plainObject(value);
}

function progressRpcOk(rpc, key) {
	var state = rpcState({ rpc: rpc }, key);
	return state.state === 'success' && state.phase !== 'stale';
}
function assessProgress(previous, current, elapsedMs, refreshIntervalMs, rpc) {
	var elapsed = Math.max(0, finiteNumber(elapsedMs) || 0);
	var refresh = Math.max(500, finiteNumber(refreshIntervalMs) || 1000);
	if (!previous || !current || elapsed < Math.max(750, refresh * .9))
		return { checked: false, stale: false, lagging: false, sources: [] };
	var compared = [], stale = [];
	[ 'interfaces', 'clients', 'overview' ].forEach(function(key) {
		if (!progressRpcOk(rpc, key)) return;
		if (finiteNumber(previous[key]) !== null && finiteNumber(current[key]) !== null &&
			Number(previous[key]) > 0 && Number(current[key]) > 0) {
			compared.push(key);
			if (Number(current[key]) <= Number(previous[key])) stale.push(key);
		}
	});
	return { checked: compared.length > 0, stale: compared.length > 0 && stale.length === compared.length,
		lagging: stale.length > 0 && stale.length < compared.length, sources: stale };
}

function normalizeResults(results, previous, checkedAt, requestId) {
	checkedAt = checkedAt === null || checkedAt === undefined ? Date.now() : checkedAt;
	requestId = requestId || 0;
	var next = { resources: {}, rpc: {}, checkedAt: checkedAt, requestId: requestId };
	var previousState = previous || null;
	RPC_KEYS.forEach(function(key) {
		var result = asArray(results).filter(function(item) { return item && item.key === key; })[0] || {
			key: key, ok: false, error: rpcErrorInfo({ code: 'MISSING', message: _('没有收到检查结果') }, 'missing')
		};
		var previousResource = previousState && previousState.resources && previousState.resources[key];
		if (!previousResource && hasPreviousValue(previousState, key)) {
			previousResource = {
				key: key, phase: phaseForValue(key, previousState[key]), value: previousState[key],
				usable: true, retained: !!(previousState.rpc && previousState.rpc[key] && previousState.rpc[key].retained),
				fetchedAt: previousState.checkedAt, producedAt: previousState.checkedAt,
				retainedFrom: null, ageMs: 0, requestId: previousState.requestId || 0, error: null
			};
		}
		var resource = resourceForResult(result, previousResource, previousState, checkedAt, requestId);
		var resultOk = result.ok === true && !(result.validation && result.validation.valid === false) &&
			resource.error === null;
		next.resources[key] = resource;
		next[key] = resource.value;
		next.rpc[key] = {
			ok: resultOk, retained: resource.retained === true, phase: resource.phase,
			error: resource.error, requestId: requestId, fetchedAt: resource.fetchedAt,
			producedAt: resource.producedAt, ageMs: resource.ageMs
		};
	});
	next.errors = RPC_KEYS.filter(function(key) { return next.rpc[key].ok !== true; }).map(function(key) {
		return { key: key, error: next.rpc[key].error };
	});
	next.error = next.errors.length ? next.errors[0].error : null;
	next.observation = sampleClock(next);
	var previousObservation = previousState && previousState.observation;
	next.progress = assessProgress(previousObservation, next.observation,
		previousState ? checkedAt - previousState.checkedAt : 0,
		next.status && next.status.refresh_interval_ms, next.rpc);
	next.pageState = pageState(next);
	return next;
}

function pageState(viewState) {
	viewState = viewState || {};
	var states = RPC_KEYS.map(function(key) { return rpcState(viewState, key); });
	if (states.some(function(item) { return item.state === 'loading' || item.state === 'missing'; })) return 'loading';
	var hard = states.filter(function(item) { return item.state === 'failed' || item.state === 'invalid'; }).length;
	var usable = states.filter(function(item) { return item.ok || item.retained; }).length;
	if (!usable) return hard === states.length ? 'error' : 'empty';
	if (hard === states.length) return 'error';
	if (hard > 0) return 'partial';
	if (states.some(function(item) { return item.phase === 'degraded' || item.phase === 'stale'; })) return 'degraded';
	if ([ 'clients', 'interfaces', 'overview' ].every(function(key) {
		return rpcState(viewState, key).phase === 'empty';
	})) return 'empty';
	return 'ready';
}

return baseclass.extend({
	emptyValue: emptyValue,
	rpcErrorInfo: rpcErrorInfo,
	boundedText: boundedText,
	phaseForValue: phaseForValue,
	retentionLimit: retentionLimit,
	usableResource: usableResource,
	resourceForResult: resourceForResult,
	runCall: runCall,
	sampleClock: sampleClock,
	rpcResult: rpcResult,
	rpcState: rpcState,
	hasPreviousValue: hasPreviousValue,
	progressRpcOk: progressRpcOk,
	assessProgress: assessProgress,
	normalizeResults: normalizeResults,
	pageState: pageState
});
