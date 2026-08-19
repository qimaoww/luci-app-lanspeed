'use strict';
'require baseclass';
'require lanspeed.diagnosticsSchema as schema';
'require lanspeed.diagnosticsResources as resources';
'require lanspeed.vocab as vocab';
'require lanspeed.statusCollector as statusCollector';

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
var emptyValue = resources.emptyValue;
var rpcErrorInfo = resources.rpcErrorInfo;
var boundedText = resources.boundedText;
var phaseForValue = resources.phaseForValue;
var retentionLimit = resources.retentionLimit;
var usableResource = resources.usableResource;
var resourceForResult = resources.resourceForResult;
var runCall = resources.runCall;
var sampleClock = resources.sampleClock;
var rpcResult = resources.rpcResult;
var rpcState = resources.rpcState;
var hasPreviousValue = resources.hasPreviousValue;
var progressRpcOk = resources.progressRpcOk;
var assessProgress = resources.assessProgress;
var normalizeResults = resources.normalizeResults;
var pageState = resources.pageState;

function formatDuration(value) {
	var milliseconds = finiteNumber(value);
	if (milliseconds === null || milliseconds < 0) return '-';
	if (milliseconds < 1000) return _('%d 毫秒').format(Math.round(milliseconds));
	if (milliseconds < 60000) return _('%s 秒').format(String(Math.round(milliseconds / 100) / 10));
	return _('%s 分钟').format(String(Math.round(milliseconds / 6000) / 10));
}

/* The interface aggregate clock is captured before per-interface samples.
 * A small positive skew therefore still describes the same snapshot, rather
 * than an interface with no sample. Keep this within the live-pair tolerance so
 * a genuinely stale or unrelated clock is still reported as unavailable. */
var INTERFACE_SAMPLE_CLOCK_SKEW_MS = 50;
function sampleAge(clockValue, sampleValue) {
	var clock = finiteNumber(clockValue), sample = finiteNumber(sampleValue);
	if (clock === null || sample === null) return null;
	if (sample > clock) return sample - clock <= INTERFACE_SAMPLE_CLOCK_SKEW_MS ? 0 : null;
	return clock - sample;
}
function formatPercent(value) {
	var number = finiteNumber(value);
	return number === null ? '-' : String(Math.round(number * 10) / 10) + '%';
}
function stateRank(state) { return ({ neutral: 0, good: 1, warning: 2, bad: 3 })[state] || 0; }
function worseState(first, second) { return stateRank(second) > stateRank(first) ? second : first; }
function reasonText(reason) {
	var key = String(reason || '');
	return REASON_LABELS[key] || key.replace(/_/g, ' ') || '-';
}
function collectorKey(value) {
	var key = String(value || '').trim().toLowerCase();
	return /^(|auto|unsupported)$/.test(key) ? 'unsupported' : key;
}
function knownCollector(value) { return hasOwn(COLLECTOR_REPORT_LABELS, collectorKey(value)); }
function collectorDisplayLabel(value) {
	var key = collectorKey(value);
	return knownCollector(key) ? statusCollector.collectorLabel(key) : _('未知');
}

function nssPlatform(status) {
	var evidence = status && status.evidence || {};
	var platform = evidence.platform || {};
	if (platform.profile !== undefined && platform.profile !== null && platform.profile !== '')
		return platform.profile === 'nss_aarch64';
	if (platform.target_arch !== undefined && platform.target_arch !== null && platform.target_arch !== '')
		return String(platform.target_arch) === 'aarch64' &&
		(!hasOwn(platform, 'nss_compiled') || platform.nss_compiled !== false) &&
		(!status.capabilities || status.capabilities.nss !== false);
	return false;
}

function currentRateUsesAccessEdge(status) {
	return nssPlatform(status) && String(status && status.rate_collector_mode || '') === 'auto' &&
		String(status && status.access_edge_mode || '') === 'active' &&
		String(status && status.internet_view_mode || '') !== 'routed';
}

function currentRateUsesRoutedInternet(status) {
	return nssPlatform(status) && String(status && status.internet_view_mode || '') === 'routed';
}

function countSummary(counts, labels, preferred) {
	var keys = [], seen = Object.create(null);
	(preferred || []).forEach(function(key) {
		if (counts[key]) { keys.push(key); seen[key] = true; }
	});
	Object.keys(counts || {}).sort().forEach(function(key) {
		if (counts[key] && !seen[key]) keys.push(key);
	});
	return keys.map(function(key) {
		return (labels[key] || _('未知')) + ' ' + counts[key];
	}).join(' · ') || '-';
}

function edgeReasonText(code) {
	return ACCESS_EDGE_REASON_LABELS[String(code || '')] || _('未识别的能力边界');
}

function rateWindowText(facts, fallback) {
	var windowMs = finiteNumber(facts && facts.windowMs);
	if (windowMs === null || windowMs <= 0) return fallback || _('采样窗口未知');
	var range = finiteNumber(facts.windowMinMs) !== null && finiteNumber(facts.windowMaxMs) !== null &&
		facts.windowMinMs !== facts.windowMaxMs ? _('（范围 %s 至 %s）').format(
			formatDuration(facts.windowMinMs), formatDuration(facts.windowMaxMs)) : '';
	return _('实际窗口约 %s%s').format(formatDuration(windowMs), range);
}

function collectRateFacts(clientsResponse) {
	var clients = asArray(clientsResponse && clientsResponse.clients);
	var sourceCounts = Object.create(null), coverageCounts = Object.create(null), scopeCounts = Object.create(null);
	var ownerDirections = 0, unavailableDirections = 0, fallbackDirections = 0;
	var staleClients = 0, staleDirections = 0;
	var attachmentKinds = Object.create(null), attachmentTrust = Object.create(null), reasonCodes = [];
	var windowValues = [];
	clients.forEach(function(client) {
		var meta = client && client.rate_meta;
		if (!plainObject(meta)) {
			sourceCounts.none = (sourceCounts.none || 0) + 2;
			coverageCounts.unavailable = (coverageCounts.unavailable || 0) + 2;
			scopeCounts.none = (scopeCounts.none || 0) + 1;
			unavailableDirections += 2;
			return;
		}
		if (meta.stale === true) staleClients++;
		if (plainObject(meta.attachment)) {
			var kind = String(meta.attachment.kind || 'unknown');
			var trust = String(meta.attachment.trust || 'unknown');
			attachmentKinds[kind] = (attachmentKinds[kind] || 0) + 1;
			attachmentTrust[trust] = (attachmentTrust[trust] || 0) + 1;
		}
		var scope = String(meta.scope || 'none');
		scopeCounts[scope] = (scopeCounts[scope] || 0) + 1;
		asArray(meta.reason_codes).forEach(function(code) {
			code = String(code || '');
			if (code && reasonCodes.indexOf(code) === -1) reasonCodes.push(code);
		});
		var metaWindow = finiteNumber(meta.window_ms);
		[ meta.tx, meta.rx ].forEach(function(direction) {
			var source = plainObject(direction) ? String(direction.source || 'none') : 'none';
			var coverage = plainObject(direction) ? String(direction.coverage || 'unavailable') : 'unavailable';
			var directionStale = plainObject(direction) && typeof direction.stale === 'boolean'
				? direction.stale : meta.stale === true;
			var directionWindow = plainObject(direction) ? finiteNumber(direction.window_ms) : null;
			if (directionWindow === null) directionWindow = metaWindow;
			if (directionWindow !== null && directionWindow > 0 &&
				(source !== 'none' && coverage !== 'unavailable' || metaWindow !== null))
				windowValues.push(directionWindow);
			sourceCounts[source] = (sourceCounts[source] || 0) + 1;
			coverageCounts[coverage] = (coverageCounts[coverage] || 0) + 1;
			if (directionStale) staleDirections++;
			if (source === 'none' || coverage === 'unavailable') unavailableDirections++;
			else ownerDirections++;
			if (source === 'fast_routed_lease' || source === 'ecm_bpf_fallback' ||
				source === 'ecm_nss_lower_bound' || source === 'tc_bpf_lower_bound')
				fallbackDirections++;
		});
	});
	windowValues.sort(function(first, second) { return first - second; });
	var windowMs = null, windowMinMs = null, windowMaxMs = null;
	if (windowValues.length) {
		var middle = Math.floor(windowValues.length / 2);
		windowMs = windowValues.length % 2 ? windowValues[middle] :
			Math.round((windowValues[middle - 1] + windowValues[middle]) / 2);
		windowMinMs = windowValues[0];
		windowMaxMs = windowValues[windowValues.length - 1];
	}
	return {
		clients: clients, totalClients: clients.length, totalDirections: clients.length * 2,
		ownerDirections: ownerDirections, unavailableDirections: unavailableDirections,
		fallbackDirections: fallbackDirections, staleClients: staleClients, staleDirections: staleDirections,
		sourceCounts: sourceCounts, coverageCounts: coverageCounts, scopeCounts: scopeCounts,
		attachmentKinds: attachmentKinds, attachmentTrust: attachmentTrust, reasonCodes: reasonCodes,
		windowMs: windowMs, windowMinMs: windowMinMs, windowMaxMs: windowMaxMs
	};
}

function rateOwnerStateWithRpc(viewState) {
	viewState = viewState || {};
	var status = viewState.status || {}, clients = viewState.clients || {};
	var facts = collectRateFacts(clients), edgeOwner = currentRateUsesAccessEdge(status);
	var routedOwner = currentRateUsesRoutedInternet(status);
	var statusRpc = rpcState(viewState, 'status'), clientsRpc = rpcState(viewState, 'clients');
	var coverage = coverageState(status, clients), source, state, badge, value, description, meta;
	var sourceText = countSummary(facts.sourceCounts, RATE_SOURCE_LABELS,
		[ 'edge_port', 'edge_wifi', 'fast_routed_lease', 'fast_routed_internet', 'ecm_bpf_fallback',
			'ecm_nss_lower_bound', 'tc_bpf_lower_bound', 'none' ]);
	var coverageText = countSummary(facts.coverageCounts, RATE_COVERAGE_LABELS,
		[ 'full', 'partial', 'degraded', 'unavailable' ]);
	if (edgeOwner) {
		source = 'access_edge'; state = coverage.state; badge = coverage.badge;
		value = sourceText === '-' ? _('等待总速率来源') : sourceText;
		description = coverage.description + ' ' +
			_('每个方向只使用一个总速率来源（owner）；NSS/CPU 分类不会与总速率相加。');
		meta = _('%d/%d 个方向已有来源 · %s').format(facts.ownerDirections, facts.totalDirections,
			rateWindowText(facts, _('目标窗口 1 秒')));
		if (facts.unavailableDirections || coverage.quality === 'unavailable') {
			state = 'bad'; badge = _('存在缺失');
			description += ' ' + _('%d 个方向没有可用的总速率 owner。').format(facts.unavailableDirections);
		} else if (facts.fallbackDirections || facts.coverageCounts.degraded || coverage.quality === 'degraded') {
			state = 'warning'; badge = _('降级');
			description += ' ' + _('部分方向正在使用租约替代或分类器降级来源，只能代表已观察到的路由流量。');
		} else if (facts.staleDirections) {
			state = 'warning'; badge = _('存在陈旧值');
			description += ' ' + _('%d 个方向的总速率已标记为陈旧。').format(facts.staleDirections);
		} else if (coverage.quality === 'full' || coverage.quality === 'partial') {
			/* Partial describes the provable frame scope, not a failed rate sample. */
			state = 'good'; badge = _('正常');
			if (facts.coverageCounts.partial)
				description += ' ' + _('全部方向都有新鲜总速率来源；帧归属边界仅在详细报告中说明。');
		}
	} else if (routedOwner) {
		source = 'nss_ecm_bpf';
		value = sourceText === '-' ? _('等待路由速率来源') : sourceText;
		state = facts.unavailableDirections ? 'bad' : facts.staleDirections ? 'warning' : 'good';
		badge = state === 'bad' ? _('存在缺失') : state === 'warning' ? _('存在陈旧值') : _('路由视图');
		description = _('显式互联网/路由视图只显示 FastN+FastS 观察到的路由流量，不代表客户端全部帧。');
		meta = _('%d/%d 个方向已有路由来源 · %s').format(facts.ownerDirections, facts.totalDirections,
			rateWindowText(facts, _('采样窗口未知')));
		if (facts.unavailableDirections)
			description += ' ' + _('%d 个方向没有当前 FastN+FastS 窗口。').format(facts.unavailableDirections);
		else if (facts.staleDirections)
			description += ' ' + _('%d 个方向的路由速率已标记为陈旧。').format(facts.staleDirections);
	} else {
		var evidence = status.evidence && status.evidence.collector || {};
		source = collectorKey((status.evidence && status.evidence.effective_collector) ||
			evidence.primary_source || statusCollector.effectiveCollector(status, clients));
		state = source === 'unsupported' ? 'bad' : coverage.state;
		badge = source === 'unsupported' ? _('不可用') : _('手动路径');
		value = collectorDisplayLabel(source);
		description = source === 'unsupported' ? _('手动网速模式没有可用采集来源。') :
			_('当前只显示所选路径能够观察到的流量，不代表全部客户端帧。');
		meta = _('Access Edge 不负责当前页面总速率 · %s').format(coverage.description);
	}
	if (statusRpc.state === 'failed' || statusRpc.state === 'invalid' || statusRpc.state === 'missing' ||
	    clientsRpc.state === 'failed' || clientsRpc.state === 'invalid' || clientsRpc.state === 'missing') {
		state = 'bad'; badge = _('不可用');
		description = _('状态或客户端 RPC 没有返回可验证的总速率来源。');
	} else if (statusRpc.state === 'loading' || clientsRpc.state === 'loading') {
		state = 'warning'; badge = _('检查中'); description = _('正在等待总速率 owner 证据。');
	} else if (statusRpc.state === 'retained' || clientsRpc.state === 'retained') {
		state = worseState(state, 'warning'); badge = _('沿用旧值');
		description += ' ' + _('当前显示最近一次成功结果。');
	}
	return { state: state, badge: badge, value: value, description: description, meta: meta,
		source: source, sourceText: sourceText, coverageText: coverageText,
		windowText: rateWindowText(facts, routedOwner ? _('采样窗口未知') : _('目标窗口 1 秒')),
		scopeText: countSummary(facts.scopeCounts, RATE_SCOPE_LABELS,
			[ 'all_frames', 'unicast', 'routed_observed', 'lower_bound', 'none' ]),
		facts: facts, edgeOwner: edgeOwner, routedOwner: routedOwner };
}

function accessEdgeStateWithRpc(viewState) {
	viewState = viewState || {};
	var status = viewState.status || {}, clients = viewState.clients || {};
	if (!nssPlatform(status)) return { state: 'neutral', badge: _('不适用'), value: _('x86 TC-BPF'),
		description: _('x86 构建不包含 Access Edge。'), meta: _('编译期已排除'), reasonCodes: [],
		reasonText: '-', topologyComplete: false, activeAttachments: 0, publishedAttachments: 0,
		attachmentText: '-', trustText: '-' };
	var mode = String(status.access_edge_mode || 'off'), owner = currentRateUsesAccessEdge(status);
	var evidence = clients.evidence && clients.evidence.access_edge;
	var facts = collectRateFacts(clients), rpc = rpcState(viewState, 'clients');
	if (mode === 'off') return { state: 'neutral', badge: _('已关闭'), value: _('不参与'),
		description: _('精准接入点采集已关闭；当前总速率只能来自手动采集路径。'),
		meta: _('配置模式 off'), reasonCodes: [], reasonText: '-', topologyComplete: false,
		activeAttachments: 0, publishedAttachments: 0, attachmentText: '-', trustText: '-' };
	if (!plainObject(evidence)) return { state: rpc.state === 'failed' ? 'bad' : 'warning',
		badge: rpc.state === 'loading' ? _('检查中') : _('等待采样'), value: '…',
		description: _('尚未收到精准接入点、FDB 与无线关联覆盖证据。'),
		meta: mode === 'shadow' ? _('仅后台验证') : _('当前总速率来源'), reasonCodes: [],
		reasonText: '-', topologyComplete: false, activeAttachments: null,
		publishedAttachments: null, attachmentText: '-', trustText: '-' };
	var quality = String(evidence.coverage || 'unavailable');
	var active = finiteNumber(evidence.active_attachments), published = finiteNumber(evidence.published_attachments);
	var topologyComplete = evidence.topology_complete === true;
	var reasons = asArray(evidence.reason_codes).map(String).filter(function(code, index, values) {
		return code && values.indexOf(code) === index;
	});
	var publicationComplete = topologyComplete && published !== null && active !== null && published >= active;
	var state = quality === 'unavailable' && owner ? 'bad' :
		(!publicationComplete || (quality === 'degraded' && owner) ? 'warning' : 'good');
	var badge = owner ? (state === 'good' ? _('正常') :
		(state === 'bad' ? _('不可用') : quality === 'degraded' ? _('降级') : _('不完整'))) : _('后台验证');
	var value = active !== null && published !== null ? _('%d/%d 个接入点').format(published, active) : _('接入点未知');
	var description = owner ? _('精准接入点负责当前客户端总速率。') :
		_('精准接入点继续采集核对，但当前网速模式不会采用它的速率。');
	if (reasons.length) description += ' ' + reasons.slice(0, 2).map(edgeReasonText).join('；') + '。';
	var attachmentText = countSummary(facts.attachmentKinds,
		{ ethernet: _('有线'), wifi: _('Wi-Fi'), unknown: _('未知') }, [ 'ethernet', 'wifi', 'unknown' ]);
	var trustText = countSummary(facts.attachmentTrust, {
		associated_station: _('无线关联'),
		observed_exclusive: _('单 MAC 观察'), shared: _('共享'), unknown: _('未知')
	}, [ 'associated_station', 'observed_exclusive', 'shared', 'unknown' ]);
	if (rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing') {
		state = 'bad'; badge = _('不可用'); description = _('客户端 RPC 没有返回精准接入点证据。');
	} else if (rpc.state === 'loading') {
		state = 'warning'; badge = _('检查中'); description = _('正在等待精准接入点证据。');
	} else if (rpc.state === 'retained') {
		state = worseState(state, 'warning'); badge = _('沿用旧值'); description += ' ' + _('本轮 RPC 沿用旧值。');
	}
	return { state: state, badge: badge, value: value, description: description,
		meta: _('拓扑 %s · FDB %s').format(topologyComplete ? _('完整') : _('不完整'),
			FDB_SOURCE_LABELS[String(evidence.fdb_source || '')] || _('未知来源')),
		reasonCodes: reasons, reasonText: reasons.length ? reasons.map(edgeReasonText).join('；') : _('无'),
		topologyComplete: topologyComplete, activeAttachments: active, publishedAttachments: published,
		attachmentText: attachmentText, trustText: trustText, owner: owner, quality: quality };
}

function classifierMapState(clients) {
	var maps = clients && clients.evidence && clients.evidence.classifier_maps;
	var result = { available: false, loss: false, pressure: false, text: '-', detailText: '-' };
	if (!plainObject(maps)) return result;
	var labels = { ecm_nss: _('NSS'), tc_bpf: _('CPU') }, parts = [], details = [];
	[ 'ecm_nss', 'tc_bpf' ].forEach(function(key) {
		var item = maps[key];
		if (!plainObject(item)) return;
		result.available = true;
		if (item.map_loss === true || item.current_truncated === true) result.loss = true;
		if (item.pressure === true || item.truncated === true) result.pressure = true;
		var entries = finiteNumber(item.entries), capacity = finiteNumber(item.capacity);
		var label = labels[key] || key, entryText = entries === null ? '-' : Math.round(entries);
		parts.push(label + ' ' + entryText);
		details.push(label + ' ' + entryText + '/' + (capacity === null ? '-' : Math.round(capacity)));
	});
	result.text = parts.join(' · ') || '-';
	result.detailText = details.join(' · ') || '-';
	return result;
}

function minimumNumber(values) {
	return values.length ? Math.min.apply(Math, values) : null;
}

function classificationStateWithRpc(viewState) {
	viewState = viewState || {};
	if (!nssPlatform(viewState.status || {})) return { state: 'neutral', badge: _('不适用'),
		value: _('x86 TC-BPF'), description: _('x86 构建不包含 NSS/CPU 分类融合。'), meta: _('编译期已排除'),
		counts: {}, stateText: '-', aligned: 0, classified: 0, totalClients: 0,
		txMinimumPct: null, rxMinimumPct: null, coverageText: '-', verificationText: '-',
		comparableDirections: 0, alignedDirections: 0, wifiObservedDirections: 0,
		maps: classifierMapState({}), windowMs: null, comparisonWindowMs: null };
	var clients = viewState.clients || {}, items = asArray(clients.clients), rpc = rpcState(viewState, 'clients');
	var counts = Object.create(null), classified = 0, txCoverage = [], rxCoverage = [];
	var comparableDirections = 0, alignedDirections = 0, wifiObservedDirections = 0;
	var unexpectedDomainMismatch = 0;
	var windowMs = null, comparisonWindowMs = null;
	items.forEach(function(client) {
		var meta = client && client.rate_meta;
		var classification = meta && meta.classification;
		var state = plainObject(classification) ? String(classification.state || 'unavailable') : 'unavailable';
		if (plainObject(classification)) {
			classified++; counts[state] = (counts[state] || 0) + 1;
		}
		[ 'tx', 'rx' ].forEach(function(directionName) {
			var direction = meta && meta[directionName];
			if (!plainObject(direction)) return;
			var source = String(direction.source || ''), domain = String(direction.byte_domain || '');
			if (source === 'edge_wifi' || domain === 'station_data') {
				wifiObservedDirections++;
				return;
			}
			if (source !== 'edge_port' || (domain !== 'l2_no_fcs' && domain !== 'l2_with_fcs'))
				return;
			comparableDirections++;
			if (!plainObject(classification)) return;
			var coverage = finiteNumber(classification[directionName + '_coverage_pct']);
			var explicitState = classification[directionName + '_state'];
			var directionState = String(explicitState || state);
			/* Old v1 payloads can expose one valid percentage without direction states. */
			var directionAligned = directionState === 'aligned' ||
				(!explicitState && state === 'counter_skew' && coverage !== null);
			if (directionAligned) {
				alignedDirections++;
				if (coverage !== null) (directionName === 'tx' ? txCoverage : rxCoverage).push(coverage);
			} else if (directionState === 'domain_mismatch') {
				unexpectedDomainMismatch++;
			}
		});
		if (!plainObject(classification)) return;
		var window = finiteNumber(classification.window_ms), comparison = finiteNumber(classification.comparison_window_ms);
		if (window !== null) windowMs = windowMs === null ? window : Math.max(windowMs, window);
		if (comparison !== null) comparisonWindowMs = comparisonWindowMs === null ? comparison : Math.max(comparisonWindowMs, comparison);
	});
	var missing = Math.max(0, items.length - classified);
	if (missing) counts.unavailable = (counts.unavailable || 0) + missing;
	var aligned = counts.aligned || 0, maps = classifierMapState(clients);
	var pending = missing || counts.warmup || counts.partial || counts.stale ||
		counts.window_mismatch || counts.unavailable || unexpectedDomainMismatch;
	var complete = items.length > 0 && classified === items.length && !pending;
	var state = !classified || pending ? 'warning' : 'good';
	var badge = !classified ? _('等待分类') : (complete ? _('运行正常') : _('等待稳定'));
	if (maps.loss || counts.map_loss) { state = 'bad'; badge = _('映射丢失'); }
	else if (maps.pressure) { state = worseState(state, 'warning'); badge = _('映射压力'); }
	else if (!maps.available) { state = worseState(state, 'warning'); badge = _('映射未确认'); }
	var value = items.length ? _('%d/%d 客户端已分类').format(classified, items.length) : _('尚无分类窗口');
	var stateText = countSummary(counts, CLASSIFICATION_STATE_LABELS,
		[ 'aligned', 'domain_mismatch', 'counter_skew', 'window_mismatch', 'partial', 'warmup', 'stale', 'map_loss', 'unavailable' ]);
	var txMin = maps.loss || !maps.available ? null : minimumNumber(txCoverage);
	var rxMin = maps.loss || !maps.available ? null : minimumNumber(rxCoverage);
	var coverageParts = [];
	if (txMin !== null) coverageParts.push(_('上行最低 %s').format(formatPercent(txMin)));
	if (rxMin !== null) coverageParts.push(_('下行最低 %s').format(formatPercent(rxMin)));
	var coverageText = coverageParts.join(' · ') || '-';
	var verificationParts = [];
	if (comparableDirections)
		verificationParts.push(_('有线 %d/%d 方向已核对').format(alignedDirections, comparableDirections));
	if (wifiObservedDirections)
		verificationParts.push(_('Wi-Fi %d 方向仅观察').format(wifiObservedDirections));
	var verificationText = verificationParts.join(' · ') || _('暂无可核对方向');
	var description = !classified ? _('尚未收到每客户端 NSS/CPU 分类结果。') :
		_('NSS已识别与CPU慢路径已识别只用于分类，不与客户端总速率相加。');
	if (missing) description += ' ' + _('%d 个客户端尚未发布分类窗口。').format(missing);
	if (wifiObservedDirections) description += ' ' + _('Wi-Fi 使用独立站点口径，仅观察分类，不计算未分类或覆盖率。');
	if (unexpectedDomainMismatch) description += ' ' + _('有线字节口径不同，当前省略未分类和覆盖率。');
	if (maps.loss) description = _('分类映射读取不完整；本轮不得标记为完整，也不得推算未分类流量。');
	else if (!maps.available) description += ' ' + _('缺少分类映射容量与完整性证据。');
	if (rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing') {
		state = 'bad'; badge = _('不可用'); description = _('客户端 RPC 没有返回分类元数据。');
	} else if (rpc.state === 'loading') {
		state = 'warning'; badge = _('检查中'); description = _('正在等待 NSS/CPU 分类元数据。');
	} else if (rpc.state === 'retained') {
		state = worseState(state, 'warning'); badge = _('沿用旧值'); description += ' ' + _('本轮 RPC 沿用旧值。');
	}
	return { state: state, badge: badge, value: value, description: description,
		meta: _('分类窗口 %s · 比较窗口 %s').format(formatDuration(windowMs), formatDuration(comparisonWindowMs)),
		counts: counts, stateText: stateText, aligned: aligned, classified: classified,
		totalClients: items.length, txMinimumPct: txMin, rxMinimumPct: rxMin,
		coverageText: coverageText, verificationText: verificationText,
		comparableDirections: comparableDirections, alignedDirections: alignedDirections,
		wifiObservedDirections: wifiObservedDirections, maps: maps, windowMs: windowMs,
		comparisonWindowMs: comparisonWindowMs };
}

function nssControlStateWithRpc(viewState) {
	viewState = viewState || {};
	if (!nssPlatform(viewState.status || {})) return {
		state: 'neutral', badge: _('不适用'), value: _('x86 客户端控制'),
		description: _('x86 构建不包含 NSS 混合路径控制诊断。'), meta: _('编译期已排除'),
		configuredClients: 0, activeClients: 0, effectiveClients: 0, pendingClients: 0,
		errorClients: 0, queueOverflowClients: 0, rateLimitedClients: 0,
		internetDisabledClients: 0, blockActiveClients: 0, requiredDirections: 0,
		verifiedDirections: 0, nssVerifiedDirections: 0, cpuVerifiedDirections: 0,
		reasonCode: null, detailCode: null, shapingSupported: false, blockingSupported: false
	};
	var clients = viewState.clients || {};
	var evidence = clients.evidence && clients.evidence.nss_control;
	var rpc = rpcState(viewState, 'clients');
	if (!plainObject(evidence)) return {
		state: rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing' ? 'bad' : 'warning',
		badge: rpc.state === 'loading' ? _('检查中') : _('证据缺失'), value: _('尚未确认'),
		description: _('尚未收到 NSS 客户端控制的队列、分类器和路径验证汇总。'),
		meta: _('等待 clients 控制证据'), configuredClients: 0, activeClients: 0,
		effectiveClients: 0, pendingClients: 0, errorClients: 0, queueOverflowClients: 0,
		rateLimitedClients: 0, internetDisabledClients: 0, blockActiveClients: 0,
		requiredDirections: 0, verifiedDirections: 0, nssVerifiedDirections: 0,
		cpuVerifiedDirections: 0, reasonCode: 'nss_control_diagnostics_unavailable', detailCode: null,
		shapingSupported: false, blockingSupported: false
	};
	var rawState = String(evidence.state || 'unavailable');
	var state = rawState === 'verified' ? 'good' : rawState === 'error' || rawState === 'unavailable' ? 'bad' :
		rawState === 'inactive' ? 'neutral' : 'warning';
	var badge = ({ verified: _('已验证'), error: _('执行失败'), unavailable: _('不可用'),
		inactive: _('未启用'), pending: _('等待验证') })[rawState] || _('未知');
	var configured = Number(evidence.configured_clients) || 0;
	var active = Number(evidence.active_clients) || 0;
	var effective = Number(evidence.effective_clients) || 0;
	var pending = Number(evidence.pending_clients) || 0;
	var errors = Number(evidence.error_clients) || 0;
	var required = Number(evidence.required_directions) || 0;
	var verified = Number(evidence.verified_directions) || 0;
	var reasonCode = evidence.reason_code === null ? null : String(evidence.reason_code || '');
	var detailCode = evidence.detail_code === null ? null : String(evidence.detail_code || '');
	var description = rawState === 'verified'
		? _('所有活动控制客户端的完整队列、分类器、nft 所有权和真实流量方向均已验证。')
		: rawState === 'inactive' ? (configured
			? _('已保存控制规则，但当前没有可验证的在线客户端。')
			: _('当前没有配置客户端限速或禁网规则。'))
		: rawState === 'pending' ? _('队列结构已观察，仍在等待实际 NSS/CPU 路径及流量计数证明。')
		: _('NSS 客户端控制执行器不完整或校验失败；未把该状态报告为已生效。');
	if (rpc.state === 'retained') {
		state = worseState(state, 'warning'); badge = _('沿用旧值');
		description += ' ' + _('当前显示最近一次成功 RPC 结果。');
	} else if (rpc.state === 'loading') {
		state = 'warning'; badge = _('检查中');
	} else if (rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing') {
		state = 'bad'; badge = _('不可用'); description = _('客户端 RPC 没有返回可验证的控制状态。');
	}
	return {
		state: state, badge: badge,
		value: configured ? _('%d/%d 个活动客户端已生效').format(effective, active) : _('没有控制规则'),
		description: description,
		meta: _('%d/%d 个限速方向已验证 · NSS %d · CPU %d').format(verified, required,
			Number(evidence.nss_verified_directions) || 0, Number(evidence.cpu_verified_directions) || 0),
		configuredClients: configured, activeClients: active, effectiveClients: effective,
		pendingClients: pending, errorClients: errors,
		queueOverflowClients: Number(evidence.queue_overflow_clients) || 0,
		rateLimitedClients: Number(evidence.rate_limited_clients) || 0,
		internetDisabledClients: Number(evidence.internet_disabled_clients) || 0,
		blockActiveClients: Number(evidence.block_active_clients) || 0,
		requiredDirections: required, verifiedDirections: verified,
		nssVerifiedDirections: Number(evidence.nss_verified_directions) || 0,
		cpuVerifiedDirections: Number(evidence.cpu_verified_directions) || 0,
		reasonCode: reasonCode, detailCode: detailCode,
		shapingSupported: evidence.shaping_supported === true,
		blockingSupported: evidence.blocking_supported === true
	};
}

function integrityStateWithRpc(viewState) {
	viewState = viewState || {};
	var clients = viewState.clients || {}, facts = collectRateFacts(clients);
	var evidence = clients.evidence && clients.evidence.access_edge || {};
	var reasons = [];
	asArray(evidence.reason_codes).concat(facts.reasonCodes).forEach(function(code) {
		code = String(code || '');
		if (code && reasons.indexOf(code) === -1) reasons.push(code);
	});
	var rpc = rpcState(viewState, 'clients');
	var state = facts.unavailableDirections ? 'bad' :
		(facts.fallbackDirections || facts.staleDirections || reasons.length ? 'warning' : 'good');
	var badge = state === 'bad' ? _('有缺失') : (state === 'warning' ? _('需关注') : _('正常'));
	var value = reasons.length ? _('%d 项限制').format(reasons.length) : _('无未解释缺口');
	var description = reasons.length ? reasons.slice(0, 3).map(edgeReasonText).join('；') + '。' :
		_('当前没有发现需要解释的总速率降级或分类边界。');
	description += ' ' + _('未分类只在同窗口、同字节口径时计算；计数错位不会钳制为零。');
	if (rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing') {
		state = 'bad'; badge = _('不可用'); description = _('客户端 RPC 失败，无法验证降级与能力边界。');
	} else if (rpc.state === 'loading') {
		state = 'warning'; badge = _('检查中'); description = _('正在汇总降级与能力边界。');
	} else if (rpc.state === 'retained') {
		state = worseState(state, 'warning'); badge = _('沿用旧值'); description += ' ' + _('本轮 RPC 沿用旧值。');
	}
	return { state: state, badge: badge, value: value, description: description,
		meta: _('回退方向 %d · 不可用方向 %d · 陈旧方向 %d').format(
			facts.fallbackDirections, facts.unavailableDirections, facts.staleDirections),
		reasonCodes: reasons, reasonText: reasons.length ? reasons.map(edgeReasonText).join('；') : _('无'),
		fallbackDirections: facts.fallbackDirections, unavailableDirections: facts.unavailableDirections,
		staleClients: facts.staleClients, staleDirections: facts.staleDirections };
}

function accessEdgeCoverageState(clients) {
	var evidence = clients && clients.evidence && clients.evidence.access_edge;
	if (!plainObject(evidence)) return { state: 'warning', badge: _('等待采样'), value: '…',
		description: _('自动精准模式尚未收到接入点覆盖数据。'),
		meta: _('精准总速率 · 覆盖契约缺失'), quality: 'warmup', source: 'access_edge' };
	var quality = String(evidence.coverage || 'unavailable');
	var labels = { full: _('完整'), partial: _('部分'), degraded: _('降级'), unavailable: _('不可用') };
	var active = finiteNumber(evidence.active_attachments);
	var published = finiteNumber(evidence.published_attachments);
	var countText = active !== null && published !== null
		? _('%d/%d 个接入点已识别').format(Math.round(published), Math.round(active)) : _('接入点数量未知');
	var publicationComplete = evidence.topology_complete === true && active !== null && published !== null && published >= active;
	var state = quality === 'unavailable' ? 'bad' :
		(quality === 'degraded' || !publicationComplete ? 'warning' : 'good');
	var description = quality === 'full' ? _('所有活动客户端都有完整总速率来源。') :
		(quality === 'partial' ? _('部分客户端或广播、组播流量无法完整归属。') :
			(quality === 'degraded' ? _('当前仅有 NSS/CPU 分类器降级速率。') :
				_('暂无可用的客户端总速率来源。')));
	return { state: state, badge: state === 'good' ? _('正常') : labels[quality] || labels.unavailable,
		value: labels[quality] || labels.unavailable, description: countText + ' · ' + description,
		meta: _('精准总速率 · %s').format(countText), quality: quality,
		activeAttachments: active, publishedAttachments: published, source: 'access_edge' };
}

function coverageState(status, clients) {
	if (String(status && status.rate_collector_mode || '') === 'auto' &&
	    String(status && status.access_edge_mode || '') === 'active')
		return accessEdgeCoverageState(clients);
	var coverage = status && status.coverage;
	if (!plainObject(coverage)) return { state: 'warning', badge: _('未知'), value: '-',
		description: _('没有收到覆盖率数据。'), meta: _('覆盖率契约缺失'), quality: '', source: 'collector' };
	var quality = String(coverage.quality || '');
	var tx = finiteNumber(coverage.tx_pct), rx = finiteNumber(coverage.rx_pct);
	var minimum = tx !== null && rx !== null ? Math.min(tx, rx) : null;
	var state = 'warning', badge = _('未知'), value = minimum === null ? '-' : formatPercent(minimum);
	var description = _('覆盖率数据不完整。');
	if (quality === 'ok' && minimum !== null) {
		state = minimum < 60 ? 'bad' : (minimum < 85 ? 'warning' : 'good');
		badge = state === 'good' ? _('可信') : (state === 'bad' ? _('缺口较大') : _('存在缺口'));
		description = _('上行 %s · 下行 %s').format(formatPercent(tx), formatPercent(rx));
	} else if (quality === 'idle') { state = 'good'; badge = _('空闲'); value = '-'; description = _('当前没有活动流量。'); }
	else if (quality === 'low_traffic') {
		state = minimum === null ? 'warning' : (minimum < 60 ? 'bad' : (minimum < 85 ? 'warning' : 'good'));
		badge = _('低流量');
		value = minimum === null ? '-' : formatPercent(minimum);
		description = minimum === null ? _('流量过低，暂不判断覆盖率。') :
			_('低流量实测：上行 %s · 下行 %s').format(formatPercent(tx), formatPercent(rx));
	}
	else if (quality === 'warmup') { state = 'warning'; badge = _('采样中'); value = '-'; description = _('正在积累覆盖率样本。'); }
	else if (quality === 'pending') {
		state = 'warning'; badge = _('追平中'); value = minimum === null ? '-' : formatPercent(minimum);
		description = minimum === null ? _('LAN 覆盖率窗口正在追平；客户端速率仍按当前采集增量独立发布。') :
			_('显示上一批覆盖率，正在等待新的对齐窗口。');
	}
	else if (quality === 'counter_reset') { state = 'warning'; badge = _('重新采样'); description = _('检测到计数器重置，正在重新建立窗口。'); }
	else if (quality === 'counter_skew') {
		state = 'warning'; badge = _('重新对齐'); value = minimum === null ? '-' : formatPercent(minimum);
		description = minimum === null ? _('客户端与独立 LAN 计数批次错位，当前窗口未发布。') :
			_('显示上一批覆盖率，正在重新对齐客户端与 LAN 计数。');
	}
	else if (quality === 'unsupported') { state = 'bad'; badge = _('不可用'); value = '-'; description = _('后端没有可用的覆盖率数据源。'); }
	return { state: state, badge: badge, value: value, description: description,
		meta: _('%d 个样本 · %s 窗口').format(Math.round(Number(coverage.samples) || 0),
			formatDuration(coverage.window_ms)), quality: quality, txPct: tx, rxPct: rx,
		minimumPct: minimum, source: 'collector' };
}

function freshnessFromContract(viewState) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var collection = contract.data.collection;
	var retained = contract.retained || collection.retained;
	var transportAge = contract.rpcRetained ? finiteNumber(contract.resourceAgeMs) : 0;
	var effectiveAge = collection.age_ms === null ? null : collection.age_ms + Math.max(0, transportAge || 0);
	var state = collection.state === 'fresh' ? 'good' :
		(collection.state === 'unavailable' ? 'bad' : 'warning');
	if (retained && state === 'good') state = 'warning';
	var description = collection.state === 'fresh' ? _('采集循环在刷新窗口内完成。') :
		(collection.state === 'stale' ? _('最近成功采集已超过刷新窗口。') :
			(collection.state === 'degraded' ? _('采集循环完成但存在降级。') : _('没有可用的采集结果。')));
	if (retained) description += ' ' + _('当前显示最近一次成功结果。');
	return { state: state, badge: state === 'good' ? _('新鲜') :
		(state === 'warning' ? (retained ? _('沿用旧值') :
			(collection.state === 'stale' ? _('过期') : _('降级'))) : _('不可用')),
		value: formatDuration(effectiveAge), description: description,
		meta: _('第 %d 代 · 刷新间隔 %s').format(collection.generation, formatDuration(collection.refresh_interval_ms)),
		oldestAgeMs: effectiveAge, clock: collection.last_success_ms,
		failedSources: [], retainedSources: retained ? [ 'diagnostics' ] : [], hardFailedSources: [] };
}
function freshnessState(data, progress) {
	var contract = freshnessFromContract(data);
	if (contract) return contract;
	data = data || {};
	var diagnosticsRpc = rpcState(data, 'diagnostics');
	var clock = sampleClock(data), refresh = Math.max(500, Number(data.status && data.status.refresh_interval_ms) || 1000);
	var ages = [], keys = [ 'interfaces', 'clients', 'overview' ];
	keys.forEach(function(key) {
		var sample = data.observation && data.observation[key] || sampleClock(data)[key];
		if (clock.overall && sample) ages.push(clock.overall - sample);
	});
	var oldest = ages.length ? Math.max.apply(Math, ages) : null;
	var progressChecked = !!(progress && progress.checked);
	var state = oldest === null || !progressChecked ? 'warning' : (progress.stale ? 'bad' :
		(oldest > refresh * 5 ? 'bad' : (oldest > refresh * 2.5 || progress.lagging ? 'warning' : 'good')));
	if (diagnosticsRpc.state === 'loading') state = 'warning';
	return { state: state, badge: state === 'good' ? _('新鲜') : (state === 'bad' ? _('已停滞') : _('待复查')),
		value: oldest === null ? '-' : formatDuration(oldest),
		description: diagnosticsRpc.state === 'loading' ? _('正在等待诊断新鲜度结果。') :
			(oldest === null ? _('没有足够的采样时间信息。') :
			(!progressChecked ? _('需要再次检查才能确认采样时钟持续推进。') :
				(state === 'good' ? _('采样时钟正在推进。') : _('部分采样时钟未按刷新间隔推进。')))),
		meta: _('刷新间隔 %s').format(formatDuration(refresh)), oldestAgeMs: oldest,
		clock: clock, failedSources: [], retainedSources: [], hardFailedSources: [] };
}
function diagnosticsContractState(viewState) {
	var value = viewState && viewState.diagnostics;
	var validation = validateDiagnosticsContract(value);
	var rpc = rpcState(viewState, 'diagnostics');
	var implicit = !viewState || !viewState.rpc;
	var usable = validation.valid && (implicit || rpc.ok || rpc.retained);
	var payloadRetained = usable && value.collection && value.collection.retained === true;
	return { usable: usable, valid: validation.valid,
		state: !validation.valid && rpc.state === 'success' ? 'invalid' : rpc.state,
		retained: rpc.retained === true || payloadRetained, rpcRetained: rpc.retained === true,
		payloadRetained: payloadRetained, resourceAgeMs: rpc.result && rpc.result.ageMs,
		reason: validation.reason, data: usable ? value : null };
}
function contractCollectionState(viewState) { return freshnessFromContract(viewState); }

function dataPathState(status, clients) {
	status = status || {}; clients = clients || {};
	var evidence = status.evidence && status.evidence.collector || {};
	var rate = collectorKey((status.evidence && status.evidence.effective_collector) ||
		statusCollector.effectiveCollector(status, clients));
	var connection = collectorKey(clients.conn_source || clients.conn_collector_mode ||
		evidence.effective_connection_collector || evidence.connection_source);
	var unknown = !knownCollector(rate) || !knownCollector(connection);
	var unavailable = rate === 'unsupported' || connection === 'unsupported';
	var confidence = String(evidence.confidence || status.confidence || 'unknown').toLowerCase();
	var state = unavailable ? 'bad' : (unknown || confidence !== 'high' ? 'warning' : 'good');
	return { state: state, badge: state === 'good' ? _('已确定') : (state === 'bad' ? _('不可用') : _('降级')),
		value: collectorDisplayLabel(rate) + ' / ' + collectorDisplayLabel(connection),
		description: unavailable ? _('速率或连接统计缺少可用数据来源。') :
			(state === 'good' ? _('速率与连接使用可验证的数据来源。') : _('数据路径未完全确认。')),
		meta: reasonText(evidence.rate_reason) + ' · ' + reasonText(evidence.connection_reason),
		rateSource: rate, connectionSource: connection, rateLabel: collectorDisplayLabel(rate),
		connectionLabel: collectorDisplayLabel(connection), rateKnown: knownCollector(rate),
		connectionKnown: knownCollector(connection), configuredRate: status.rate_collector_mode || '-',
		configuredConnection: status.conn_collector_mode || '-', rateReason: evidence.rate_reason || '',
		connectionReason: evidence.connection_reason || '' };
}
function contractPathState(viewState) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var path = contract.data.data_path;
	var rate = collectorKey(path.effective_rate), connection = collectorKey(path.effective_connection);
	var unavailable = rate === 'unsupported' || connection === 'unsupported';
	var state = unavailable ? 'bad' : (path.fallback_active ? 'warning' : 'good');
	if (contract.retained && state === 'good') state = 'warning';
	return { state: state, badge: state === 'good' ? _('已确定') : (state === 'bad' ? _('不可用') : _('降级')),
		value: collectorDisplayLabel(rate) + ' / ' + collectorDisplayLabel(connection),
		description: unavailable ? _('速率或连接统计缺少可用数据来源。') :
			(path.fallback_active ? _('当前使用回退路径。') : _('速率与连接路径已确定。')),
		meta: reasonText(path.reason_code) + (contract.retained ? ' · ' + _('沿用旧值') : ''),
		rateSource: rate, connectionSource: connection, rateLabel: collectorDisplayLabel(rate),
		connectionLabel: collectorDisplayLabel(connection), rateKnown: knownCollector(rate),
		connectionKnown: knownCollector(connection), configuredRate: path.configured_rate,
		configuredConnection: path.configured_connection, rateReason: path.reason_code || '',
		connectionReason: path.reason_code || '' };
}
function diagnosticConnectionCode(viewState) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var subsystem = asArray(contract.data.subsystems).find(function(item) {
		return item && item.id === 'conntrack';
	});
	if (subsystem && subsystem.code) return String(subsystem.code);
	var clients = viewState && viewState.clients || {};
	if (clients.evidence && clients.evidence.details &&
		clients.evidence.details.conntrack_status === 'unavailable')
		return 'conntrack_read_failed';
	return contract.data.data_path.effective_connection === 'unsupported' ?
		contract.data.data_path.reason_code : null;
}
function connectionState(clients, status) {
	clients = clients || {}; status = status || {};
	var source = clients.conn_source || clients.conn_collector_mode || '';
	var seen = finiteNumber(clients.conntrack_entries_seen);
	var matched = finiteNumber(clients.conntrack_entries_matched);
	var errors = Math.max(0, finiteNumber(clients.conntrack_parse_errors) || 0);
	var pct = seen !== null && seen > 0 && matched !== null && matched <= seen ? matched * 100 / seen : null;
	var state = !source || source === 'unsupported' ? 'bad' : (!knownCollector(source) ? 'warning' : 'good');
	if (seen !== null && matched !== null && matched > seen) state = 'bad';
	else if (errors > 10) state = 'bad'; else if (errors || pct !== null && pct < 70 || seen === null || matched === null) state = 'warning';
	var reasonCode = !source || source === 'unsupported' ?
		(status.evidence && status.evidence.collector && status.evidence.collector.connection_reason) ||
		(clients.evidence && clients.evidence.details && clients.evidence.details.conntrack_status === 'unavailable' ? 'conntrack_read_failed' : null) : null;
	return { state: state, badge: state === 'good' ? _('正常') : (state === 'bad' ? _('不可用') : _('需关注')),
		value: source ? collectorDisplayLabel(source) : '-',
		description: seen !== null && matched !== null ? _('%d / %d 条已匹配 · %d 个解析错误').format(matched, seen, errors) :
			(reasonCode ? reasonText(reasonCode) : _('连接统计不完整。')),
		meta: _('TCP %d · UDP %d').format(Math.max(0, Number(clients.tcp_conns_total) || 0), Math.max(0, Number(clients.udp_conns_total) || 0)),
		source: source, seen: seen, matched: matched, matchPct: pct, parseErrors: errors, reasonCode: reasonCode };
}
function contractConnectionState(viewState) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var connection = contract.data.connection, state = connection.state === 'healthy' ? 'good' :
		(connection.state === 'degraded' ? 'warning' : 'bad');
	var reasonCode = diagnosticConnectionCode(viewState);
	if (contract.retained && state === 'good') state = 'warning';
	var seen = connection.entries_seen, matched = connection.entries_matched;
	var pct = seen !== null && seen > 0 && matched !== null ? matched * 100 / seen : null;
	return { state: state, badge: state === 'good' ? _('正常') : (state === 'bad' ? _('不可用') : _('需关注')),
		value: connection.source ? collectorDisplayLabel(connection.source) : '-',
		description: seen !== null && matched !== null ? _('%d / %d 条已匹配').format(matched, seen) :
			(reasonCode ? reasonText(reasonCode) : _('后端未返回连接条目统计。')),
		meta: connection.parse_errors ? _('%d 个解析错误').format(connection.parse_errors) : _('诊断契约'),
		source: connection.source || '', seen: seen, matched: matched, matchPct: pct,
		parseErrors: connection.parse_errors || 0, reasonCode: reasonCode };
}
function connectionStateWithRpc(viewState) {
	var rpc = rpcState(viewState, 'clients'), base = contractConnectionState(viewState) ||
		connectionState(viewState && viewState.clients, viewState && viewState.status);
	var result = Object.assign({}, base, { rpc: rpc.state });
	if (rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing') {
		result.state = 'bad'; result.badge = _('不可用');
		result.description = _('客户端数据接口没有可验证结果。');
	} else if (rpc.state === 'retained') {
		result.state = worseState(result.state, 'warning'); result.badge = _('沿用旧值');
		result.description += ' ' + _('客户端接口本次失败。');
	} else if (rpc.state === 'empty') {
		result.state = worseState(result.state, 'warning'); result.badge = _('无客户端数据');
		result.description = _('客户端接口已响应，但当前没有客户端明细可交叉验证。');
	} else if (rpc.state === 'loading') {
		result.state = 'warning'; result.badge = _('检查中');
		result.description = _('正在等待客户端数据接口。');
	}
	return result;
}
function pathStateWithRpc(viewState) {
	var base = contractPathState(viewState) || dataPathState(viewState && viewState.status, viewState && viewState.clients);
	var clients = rpcState(viewState, 'clients'), status = rpcState(viewState, 'status'), health = rpcState(viewState, 'health');
	var result = Object.assign({}, base, { rpc: { clients: clients.state, status: status.state, health: health.state } });
	var collectorEvidence = viewState && viewState.status && viewState.status.evidence &&
		viewState.status.evidence.collector || {};
	var classifierSource = result.rateSource;
	var effectiveInterval = finiteNumber(collectorEvidence.effective_interval_ms);
	var classifierEvidence = viewState && viewState.clients && viewState.clients.evidence &&
		viewState.clients.evidence.ecm_bpf || {};
	var classifierInterval = finiteNumber(classifierEvidence.collector_min_interval_ms);
	if (currentRateUsesAccessEdge(viewState && viewState.status)) {
		result.classifierSource = classifierSource;
		result.classifierLabel = collectorDisplayLabel(classifierSource);
		result.rateSource = 'access_edge';
		result.rateLabel = collectorDisplayLabel('access_edge');
		result.value = result.rateLabel + ' / ' + result.connectionLabel;
		result.description = _('客户端总速率来自精准接入点；%s 只负责 NSS/CPU 分类。').format(result.classifierLabel);
		if (classifierInterval === null && (classifierSource === 'nss_ecm_node' || classifierSource === 'nss_ecm_bpf'))
			classifierInterval = 2000;
		result.meta = _('总速率周期 1 秒 · 分类周期 %s').format(formatDuration(classifierInterval));
	} else if ((classifierSource === 'nss_ecm_node' || classifierSource === 'nss_ecm_bpf') &&
		effectiveInterval !== null && effectiveInterval >= 500) {
		result.meta += ' · ' + _('数据周期 %s').format(formatDuration(effectiveInterval));
	}
	if ([ clients, status, health ].some(function(item) { return item.state === 'failed' || item.state === 'invalid' || item.state === 'missing'; })) {
		result.state = clients.state === 'failed' || clients.state === 'invalid' || clients.state === 'missing' ? 'bad' : worseState(result.state, 'warning');
		result.badge = result.state === 'bad' ? _('不可用') : _('未完全确认');
		result.description = _('一个或多个路径依据接口没有可验证结果。');
	} else if ([ clients, status, health ].some(function(item) { return item.state === 'retained'; })) {
		result.state = worseState(result.state, 'warning'); result.badge = _('沿用旧值');
		result.description += ' ' + _('部分路径依据沿用旧值。');
	} else if (clients.state === 'empty') {
		result.state = worseState(result.state, 'warning'); result.badge = _('未完全确认');
		result.description = _('客户端接口没有明细，数据路径缺少一项交叉验证。');
	} else if ([ clients, status, health ].some(function(item) { return item.state === 'loading'; })) {
		result.state = 'warning'; result.badge = _('检查中');
		result.description = _('正在等待路径依据接口。');
	}
	return result;
}
function interfaceState(interfaces) {
	var items = asArray(interfaces && interfaces.interfaces), available = 0, pending = 0, bad = 0, excluded = 0, unknown = 0;
	items.forEach(function(item) {
		var status = String(item && item.status || 'unknown');
		if (status === 'available' || status === 'active') available++; else if (status === 'pending') pending++;
		else if (status === 'missing' || status === 'unsupported') bad++; else if (status === 'excluded') excluded++; else unknown++;
	});
	var state = bad ? 'bad' : (!items.length || pending || unknown || !available ? 'warning' : 'good');
	return { state: state, badge: bad ? _('%d 个异常').format(bad) : (pending ? _('%d 个等待').format(pending) :
		(!items.length ? _('无接口数据') : (unknown ? _('%d 个未知').format(unknown) : _('%d 个可用').format(available)))),
		value: _('%d / %d').format(available, items.length),
		description: bad ? _('存在缺失或不受支持的接口。') : (!items.length ? _('没有接口数据。') :
			(pending ? _('部分接口等待首次采样。') : _('接口列表已返回。'))), items: items, available: available,
		pending: pending, bad: bad, excluded: excluded, unknown: unknown, total: items.length };
}
function contractInterfaceState(viewState, fallback) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var summary = contract.data.interfaces, state = summary.state === 'healthy' ? 'good' :
		(summary.state === 'degraded' ? 'warning' : 'bad');
	var age = sampleAge(viewState && viewState.interfaces && viewState.interfaces.monotonic_ms,
		summary.sample_ms);
	if (contract.retained && state === 'good') state = 'warning';
	return { state: state, badge: state === 'good' ? _('%d 个可用').format(summary.available) :
		(state === 'bad' ? _('接口不可用') : _('接口降级')), value: _('%d / %d').format(summary.available, summary.total),
		description: summary.missing ? _('%d 个接口缺失或不可用。').format(summary.missing) : _('接口汇总来自诊断契约。'),
		meta: age === null ? _('尚无接口采样时间') : _('采样 %s').format(formatDuration(age)),
		items: fallback && Array.isArray(fallback.items) ? fallback.items : [], available: summary.available,
		pending: 0, bad: summary.missing, excluded: 0, unknown: 0, total: summary.total };
}
function interfaceStateWithRpc(viewState) {
	var base = interfaceState(viewState && viewState.interfaces), contract = contractInterfaceState(viewState, base);
	var result = Object.assign({}, contract || base), rpc = rpcState(viewState, 'interfaces');
	result.rpc = rpc.state;
	if (rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing') {
		result.state = 'bad'; result.badge = _('不可用'); result.description = _('接口数据接口没有可验证结果。');
	} else if (rpc.state === 'retained') { result.state = worseState(result.state, 'warning'); result.badge = _('沿用旧值'); }
	else if (rpc.state === 'empty') {
		result.state = result.total > 0 ? 'bad' : 'warning';
		result.badge = result.state === 'bad' ? _('结果不一致') : _('无接口数据');
		result.description = result.state === 'bad' ? _('诊断汇总声明存在接口，但接口 RPC 返回空列表。') : _('没有配置可采集接口。');
	}
	else if (rpc.ok && result.total !== result.items.length) {
		result.state = 'bad'; result.badge = _('结果不一致');
		result.description = _('诊断汇总与接口 RPC 返回了不同的接口数量。');
	}
	else if (rpc.state === 'loading') { result.state = 'warning'; result.badge = _('检查中'); result.description = _('正在等待接口数据。'); }
	return result;
}
function versionState(backendVersion, frontendVersion, packageVersion) {
	var daemon = String(backendVersion || ''), frontend = String(frontendVersion || ''), pack = String(packageVersion || daemon || '');
	var matches = !!daemon && daemon === frontend && daemon === pack;
	return { state: matches ? 'good' : 'warning', badge: matches ? _('一致') : _('不一致'),
		value: frontend + ' / ' + daemon + ' / ' + pack,
		description: matches ? _('LuCI、软件包与后端版本一致。') : _('LuCI、软件包或后端版本未完全一致。') };
}
function contractVersionState(viewState, frontendVersion) {
	var contract = diagnosticsContractState(viewState);
	if (!contract.usable) return null;
	var versions = contract.data.versions, result = versionState(versions.daemon, frontendVersion, versions.package);
	if (contract.retained && result.state === 'good') { result.state = 'warning'; result.badge = _('沿用旧值'); }
	result.contractVersion = versions.contract_version; result.schemaVersion = versions.schema_version;
	return result;
}
function versionStateWithRpc(viewState, backendVersion, frontendVersion) {
	var contract = diagnosticsContractState(viewState);
	var result = contractVersionState(viewState, frontendVersion) || versionState(backendVersion, frontendVersion);
	var rpc = rpcState(viewState, 'status'); result.rpc = rpc.state;
	if (rpc.state === 'failed' || rpc.state === 'invalid' || rpc.state === 'missing') {
		result.state = 'warning'; result.badge = _('待确认'); result.description = _('没有成功的 status 结果，版本一致性暂时无法确认。');
	} else if (rpc.state === 'retained' && result.state === 'good') { result.state = 'warning'; result.badge = _('沿用旧值'); }
	else if (rpc.state === 'loading') { result.state = 'warning'; result.badge = _('检查中'); result.description = _('正在等待 status 版本信息。'); }
	else if (contract.usable && backendVersion && String(backendVersion) !== contract.data.versions.daemon) {
		result.state = 'warning'; result.badge = _('不一致');
		result.description = _('status 与诊断契约上报了不同的后端版本。');
	}
	return result;
}

function qualityState(data, progress) {
	var coverage = coverageState(data && data.status, data && data.clients), freshness = freshnessState(data, progress);
	var statusRpc = rpcState(data, 'status');
	if (statusRpc.state === 'failed' || statusRpc.state === 'invalid' || statusRpc.state === 'missing') coverage.state = 'bad';
	else if (statusRpc.state === 'loading') { coverage.state = 'warning'; coverage.badge = _('检查中'); }
	if (coverage.source === 'access_edge') {
		var clientsRpc = rpcState(data, 'clients');
		if (clientsRpc.state === 'failed' || clientsRpc.state === 'invalid' || clientsRpc.state === 'missing') {
			coverage.state = 'bad'; coverage.badge = _('不可用');
			coverage.description = _('客户端数据接口没有返回当前精准总速率覆盖。');
		} else if (clientsRpc.state === 'loading') {
			coverage.state = 'warning'; coverage.badge = _('检查中');
		} else if (clientsRpc.state === 'retained') {
			coverage.state = worseState(coverage.state, 'warning'); coverage.badge = _('沿用旧值');
			coverage.description += ' ' + _('当前显示最近一次成功覆盖结果。');
		}
	}
	var state = worseState(coverage.state, freshness.state);
	return { state: state, badge: state === 'bad' ? _('异常') : (state === 'warning' ? _('需关注') : coverage.badge),
		value: coverage.value, description: coverage.description + ' ' + freshness.description,
		meta: coverage.meta + ' · ' + _('样本年龄 ') + freshness.value, coverage: coverage, freshness: freshness };
}

function probeFailureBundle(health) {
	var raw = health && health.evidence && health.evidence.probe_failures;
	if (Array.isArray(raw)) return { items: raw.slice(0, MAX_PROBE_FAILURES), total: raw.length, truncated: raw.length > MAX_PROBE_FAILURES };
	raw = plainObject(raw) ? raw : {};
	var items = asArray(raw.items).slice(0, MAX_PROBE_FAILURES), total = finiteNumber(raw.total);
	return { items: items, total: total === null ? items.length : Math.max(items.length, Math.round(total)),
		truncated: raw.truncated === true || (total !== null && total > items.length) };
}
function probeFailureKey(item) { return [ item && item.kind, item && item.source, item && item.reason, item && item.exit_code ].join('\x1f'); }
function mergeProbeFailureBundles(first, second) {
	var a = probeFailureBundle(first), b = probeFailureBundle(second), items = [], seen = Object.create(null);
	[ a.items, b.items ].forEach(function(list) { list.forEach(function(item) {
		var key = probeFailureKey(item); if (seen[key]) return; seen[key] = true; if (items.length < MAX_PROBE_FAILURES) items.push(item);
	}); });
	var total = Math.max(a.total, b.total, items.length);
	return { items: items, total: total, truncated: a.truncated || b.truncated || total > items.length };
}
function canonicalWarningId(value) {
	var id = String(value || '');
	if (id && typeof vocab.normalizeWarningId === 'function')
		id = String(vocab.normalizeWarningId(id) || id);
	return id;
}
function warningGroups(status, health, rpc, diagnostics) {
	status = status || {}; health = health || {}; rpc = rpc || {};
	var items = [], seen = Object.create(null), hasRpc = Object.keys(rpc).length > 0;
	var contract = diagnosticsContractState({ diagnostics: diagnostics, rpc: rpc });
	var contractAlertIds = Object.create(null);
	if (contract.usable) asArray(contract.data.alerts).forEach(function(alert) {
		contractAlertIds[canonicalWarningId(alert && alert.id)] = true;
	});
	function severityRank(value) { return ({ info: 0, warning: 1, critical: 2 })[value] || 0; }
	function sourceUsable(key) {
		if (!hasRpc) return true;
		var state = rpcState({ rpc: rpc }, key);
		return state.ok || state.retained;
	}
	function add(item, source, severity, text, id) {
		id = canonicalWarningId(id || item || source || 'unknown');
		severity = enumValue(severity, [ 'info', 'warning', 'critical' ]) ? severity : 'warning';
		var known = typeof vocab.hasWarning === 'function' && vocab.hasWarning(id);
		var publicText = known && typeof vocab.warningText === 'function' ? vocab.warningText(id) : text;
		if (seen[id]) {
			if (source === 'diagnostics') {
				seen[id].source = source;
				seen[id].severity = severity;
				seen[id].text = publicText || seen[id].text;
				seen[id].raw = item;
			} else if (seen[id].source !== 'diagnostics' &&
				severityRank(severity) > severityRank(seen[id].severity)) {
				seen[id].severity = severity;
			}
			return;
		}
		seen[id] = { id: id, source: source, severity: severity, text: publicText || '', raw: item };
		items.push(seen[id]);
	}
	function nssArtifact(item) {
		var id = String(item && item.id || '').toLowerCase();
		var raw = '';
		try { raw = JSON.stringify(item && item.raw || item || {}).toLowerCase(); } catch (error) {}
		return /^(?:nss|ecm|access[_-]?edge|lan[_-]?topology|classifier|classification)(?:[_:\-.]|$)/.test(id) ||
			/(?:\bnss\b|\becm\b|access[_-]?edge|lan[_-]?topology|classifier|classification)/.test(raw);
	}
	if (sourceUsable('status')) asArray(status.warnings).forEach(function(id) {
		if (id === 'live_metrics_unavailable' && status.capabilities && status.capabilities.live_metrics === true)
			return;
		if (id === 'bpf_runtime_loader_unavailable' && [ 'no_collect_interface', 'package_missing',
			'object_missing', 'object_load_failed', 'tc_unavailable', 'tc_unsupported', 'tc_conflict',
			'tc_attach_failed', 'map_read_failed' ].some(function(specific) { return contractAlertIds[specific]; }))
			return;
		var known = typeof vocab.hasWarning === 'function' && vocab.hasWarning(id);
		add(id, 'status', typeof vocab.warningClass === 'function' && vocab.warningClass(id).indexOf('danger') !== -1 ? 'critical' : 'warning',
			known && typeof vocab.warningText === 'function' ? vocab.warningText(id) : _('检测到未分类运行告警。'), id);
	});
	if (sourceUsable('health')) asArray(health.warnings).forEach(function(id) {
		var known = typeof vocab.hasWarning === 'function' && vocab.hasWarning(id);
		add(id, 'health', known && typeof vocab.warningClass === 'function' && vocab.warningClass(id).indexOf('danger') !== -1 ? 'critical' : 'warning',
			known && typeof vocab.warningText === 'function' ? vocab.warningText(id) : _('检测到未分类环境告警。'), id);
	});
	if (sourceUsable('health')) asArray(health.conflicts).forEach(function(conflict) {
		add(conflict, 'conflict', conflict && conflict.severity || 'warning', boundedText(conflict && conflict.message || '', 480), conflict && conflict.id);
	});
	RPC_KEYS.forEach(function(key) {
		var result = rpc[key];
		if (!result || result.phase === 'loading' || result.ok === true)
			return;
		add(result, 'rpc', result.retained || result.phase === 'degraded' || result.phase === 'stale'
			? 'warning' : 'critical', rpcReportErrorText(result), 'rpc:' + key);
	});
	if (contract.usable) {
		asArray(contract.data.alerts).forEach(function(alert) {
			add(alert, 'diagnostics', alert.severity, alert.message_public, alert.id);
		});
		asArray(contract.data.config_issues).forEach(function(issue) {
			add(issue, 'config', issue.severity, issue.message_public, issue.id);
		});
	}
	var failures = mergeProbeFailureBundles(sourceUsable('status') ? status : null,
		sourceUsable('health') ? health : null);
	failures.items.forEach(function(item) { add(item, 'probe', 'warning', probeFailureText(item), 'probe:' + probeFailureKey(item)); });
	if (!nssPlatform(status)) {
		failures.items = failures.items.filter(function(item) { return !nssArtifact({ raw: item }); });
		failures.total = failures.items.length;
		failures.truncated = false;
		items = items.filter(function(item) { return !nssArtifact(item); });
	}
	var critical = items.filter(function(item) { return item.severity === 'critical'; });
	var warnings = items.filter(function(item) { return item.severity === 'warning'; });
	var info = items.filter(function(item) { return item.severity === 'info'; });
	return { all: critical.concat(warnings, info), critical: critical, warnings: warnings, info: info,
		important: items.filter(function(item) {
		return item.severity === 'critical' || item.severity === 'warning';
	}), environment: items.filter(function(item) { return item.severity === 'info'; }), conflicts: [],
		probeFailures: failures.items, probeFailuresTotal: failures.total, probeFailuresTruncated: failures.truncated,
		contractAlerts: contract.usable ? contract.data.alerts : [], configIssues: contract.usable ? contract.data.config_issues : [], contract: contract };
}
function rpcReportErrorText(result) {
	var error = result && result.error || {};
	var kind = enumValue(error.kind, [ 'transport', 'timeout', 'contract', 'missing', 'client' ])
		? error.kind : 'transport';
	var labels = {
		transport: _('传输失败'), timeout: _('请求超时'), contract: _('契约无效'),
		missing: _('缺少结果'), client: _('页面处理失败')
	};
	var code = { transport: 'RPC_ERROR', timeout: 'TIMEOUT', contract: 'INVALID_CONTRACT',
		missing: 'MISSING', client: 'CLIENT_ERROR' }[kind];
	return labels[kind] + ' · ' + code + ' · ' + (error.retriable === false ? _('不可重试') : _('可重试'));
}
function probeFailureText(failure) {
	failure = failure || {};
	var kind = PROBE_KIND_REPORT_LABELS[String(failure.kind || '').toLowerCase()] || _('环境探测');
	var reason = PROBE_REASON_LABELS[String(failure.reason || '').toLowerCase()] || _('探测失败');
	return kind + ' · ' + reason + (finiteNumber(failure.exit_code) !== null ? ' · exit ' + Math.round(failure.exit_code) : '');
}

return baseclass.extend({
	formatDuration: formatDuration,
	sampleAge: sampleAge,
	formatPercent: formatPercent,
	stateRank: stateRank,
	worseState: worseState,
	reasonText: reasonText,
	collectorKey: collectorKey,
	knownCollector: knownCollector,
	collectorDisplayLabel: collectorDisplayLabel,
	nssPlatform: nssPlatform,
	currentRateUsesAccessEdge: currentRateUsesAccessEdge,
	currentRateUsesRoutedInternet: currentRateUsesRoutedInternet,
	countSummary: countSummary,
	edgeReasonText: edgeReasonText,
	rateWindowText: rateWindowText,
	collectRateFacts: collectRateFacts,
	rateOwnerStateWithRpc: rateOwnerStateWithRpc,
	accessEdgeStateWithRpc: accessEdgeStateWithRpc,
	classifierMapState: classifierMapState,
	minimumNumber: minimumNumber,
	classificationStateWithRpc: classificationStateWithRpc,
	nssControlStateWithRpc: nssControlStateWithRpc,
	integrityStateWithRpc: integrityStateWithRpc,
	accessEdgeCoverageState: accessEdgeCoverageState,
	coverageState: coverageState,
	freshnessFromContract: freshnessFromContract,
	freshnessState: freshnessState,
	diagnosticsContractState: diagnosticsContractState,
	contractCollectionState: contractCollectionState,
	dataPathState: dataPathState,
	contractPathState: contractPathState,
	diagnosticConnectionCode: diagnosticConnectionCode,
	connectionState: connectionState,
	contractConnectionState: contractConnectionState,
	connectionStateWithRpc: connectionStateWithRpc,
	pathStateWithRpc: pathStateWithRpc,
	interfaceState: interfaceState,
	contractInterfaceState: contractInterfaceState,
	interfaceStateWithRpc: interfaceStateWithRpc,
	versionState: versionState,
	contractVersionState: contractVersionState,
	versionStateWithRpc: versionStateWithRpc,
	qualityState: qualityState,
	probeFailureBundle: probeFailureBundle,
	probeFailureKey: probeFailureKey,
	mergeProbeFailureBundles: mergeProbeFailureBundles,
	canonicalWarningId: canonicalWarningId,
	warningGroups: warningGroups
	,
	rpcReportErrorText: rpcReportErrorText
	,
	probeFailureText: probeFailureText
});
