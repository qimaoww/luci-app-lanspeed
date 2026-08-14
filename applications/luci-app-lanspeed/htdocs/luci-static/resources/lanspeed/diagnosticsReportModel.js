'use strict';
'require baseclass';
'require lanspeed.diagnosticsSchema as schema';
'require lanspeed.diagnosticsResources as resources';
'require lanspeed.diagnosticsStates as states';
'require lanspeed.vocab as vocab';
'require lanspeed.diagnosticsReport as diagnosticsReport';

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
var formatDuration = states.formatDuration;
var sampleAge = states.sampleAge;
var formatPercent = states.formatPercent;
var stateRank = states.stateRank;
var worseState = states.worseState;
var reasonText = states.reasonText;
var collectorKey = states.collectorKey;
var knownCollector = states.knownCollector;
var collectorDisplayLabel = states.collectorDisplayLabel;
var nssPlatform = states.nssPlatform;
var currentRateUsesAccessEdge = states.currentRateUsesAccessEdge;
var countSummary = states.countSummary;
var edgeReasonText = states.edgeReasonText;
var collectRateFacts = states.collectRateFacts;
var rateOwnerStateWithRpc = states.rateOwnerStateWithRpc;
var accessEdgeStateWithRpc = states.accessEdgeStateWithRpc;
var classifierMapState = states.classifierMapState;
var minimumNumber = states.minimumNumber;
var classificationStateWithRpc = states.classificationStateWithRpc;
var nssControlStateWithRpc = states.nssControlStateWithRpc;
var integrityStateWithRpc = states.integrityStateWithRpc;
var accessEdgeCoverageState = states.accessEdgeCoverageState;
var coverageState = states.coverageState;
var freshnessFromContract = states.freshnessFromContract;
var freshnessState = states.freshnessState;
var diagnosticsContractState = states.diagnosticsContractState;
var contractCollectionState = states.contractCollectionState;
var dataPathState = states.dataPathState;
var contractPathState = states.contractPathState;
var diagnosticConnectionCode = states.diagnosticConnectionCode;
var connectionState = states.connectionState;
var contractConnectionState = states.contractConnectionState;
var connectionStateWithRpc = states.connectionStateWithRpc;
var pathStateWithRpc = states.pathStateWithRpc;
var interfaceState = states.interfaceState;
var contractInterfaceState = states.contractInterfaceState;
var interfaceStateWithRpc = states.interfaceStateWithRpc;
var versionState = states.versionState;
var contractVersionState = states.contractVersionState;
var versionStateWithRpc = states.versionStateWithRpc;
var qualityState = states.qualityState;
var probeFailureBundle = states.probeFailureBundle;
var probeFailureKey = states.probeFailureKey;
var mergeProbeFailureBundles = states.mergeProbeFailureBundles;
var canonicalWarningId = states.canonicalWarningId;
var warningGroups = states.warningGroups;

function probeFailureText(failure) {
	return states.probeFailureText(failure);
}
function probeFailureReportText(failure) {
	failure = failure || {};
	var kind = PROBE_KIND_REPORT_LABELS[String(failure.kind || '').toLowerCase()] || _('环境探测');
	var reason = PROBE_REASON_LABELS[String(failure.reason || '').toLowerCase()] || _('探测失败');
	return kind + ' · ' + reason + (finiteNumber(failure.exit_code) !== null ? ' · exit ' + Math.round(failure.exit_code) : '');
}

function rpcReportErrorText(result) {
	return states.rpcReportErrorText(result);
}

var sanitizeReportText = diagnosticsReport.sanitizeReportText;
function reportField(value) { return sanitizeReportText(value === null || value === undefined || value === '' ? '-' : value); }
function reportCollectorLabel(value) { var key = collectorKey(value); return COLLECTOR_REPORT_LABELS[key] || _('未知数据源'); }
function reportReasonText(reason) {
	var key = String(reason || '').toLowerCase();
	return hasOwn(REASON_LABELS, key) ? REASON_LABELS[key] : _('未知原因');
}
function reportVersion(value) {
	value = String(value || '');
	return /^[0-9]+(?:\.[0-9]+){1,3}(?:[-+~._][A-Za-z0-9]+)*$/.test(value) ? value : '-';
}
function reportConfiguredMode(value, kind) {
	var rate = [ 'auto', 'bpf', 'nss_ecm_node', 'nss_ecm_bpf' ];
	var connection = [ 'auto', 'conntrack_netlink', 'conntrack_procfs' ];
	value = String(value || '').toLowerCase();
	return (kind === 'rate' ? rate : connection).indexOf(value) !== -1 ? value : _('未知配置');
}
function rpcReportState(result) {
	if (!result) return _('未检查');
	if (!result.ok) return result.retained ? _('失败，沿用旧值') :
		(result.phase === 'invalid' || result.error && result.error.kind === 'contract' ? _('契约无效') : _('失败'));
	return ({ empty: _('成功，无数据'), stale: _('成功，数据过期'), degraded: _('成功，结果降级') })[result.phase] || _('成功');
}
function reportPageState(value) {
	return ({ loading: _('检查中'), ready: _('完成'), degraded: _('降级'), partial: _('部分失败'),
		empty: _('无数据'), error: _('失败') })[String(value || '')] || _('未确认');
}
function diagnosticSeverity(item) { var value = String(item && item.severity || 'info'); return value === 'critical' ? 'danger' : value === 'warning' ? 'warning' : 'info'; }
function diagnosticPublicText(item, fallback) {
	/* Do not copy arbitrary backend prose. Known warning IDs are translated locally. */
	var id = String(item && item.id || '');
	if (typeof vocab.hasWarning === 'function' && vocab.hasWarning(id) && typeof vocab.warningText === 'function')
		return sanitizeReportText(vocab.warningText(id));
	return sanitizeReportText(fallback || _('检测到一项诊断事件。'));
}
function stateLabel(state) { return state === 'good' ? _('正常') : state === 'bad' ? _('异常') : state === 'warning' ? _('需关注') : _('信息'); }
function interfaceReportRole(value) { return INTERFACE_ROLE_REPORT_LABELS[String(value || '').toLowerCase()] || _('其他'); }
function interfaceReportStatus(value) { return INTERFACE_STATUS_REPORT_LABELS[String(value || '').toLowerCase()] || _('未知'); }
function subsystemReportText(item, isNssPlatform) {
	item = plainObject(item) ? item : {};
	var id = String(item.id || ''), code = String(item.code || '');
	var label = !isNssPlatform && id === 'identity'
		? _('客户端身份识别') : SUBSYSTEM_LABELS[id] || _('未知组件');
	var state = HEALTH_REPORT_LABELS[String(item.state || '')] || _('未知');
	var detail = '-';
	if (code && typeof vocab.hasWarning === 'function' && vocab.hasWarning(code) &&
		typeof vocab.warningText === 'function') detail = vocab.warningText(code);
	else if (code && hasOwn(REASON_LABELS, code)) detail = REASON_LABELS[code];
	return label + ': ' + state + (detail === '-' ? '' : ' · ' + sanitizeReportText(detail));
}

function buildReport(viewState, frontendVersion) {
	viewState = viewState || {};
	var runtime = viewState.status || {}, rate = rateOwnerStateWithRpc(viewState), edge = accessEdgeStateWithRpc(viewState),
		classification = classificationStateWithRpc(viewState), control = nssControlStateWithRpc(viewState),
		integrity = integrityStateWithRpc(viewState),
		freshness = freshnessState(viewState, viewState.progress), connections = connectionStateWithRpc(viewState),
		interfaces = interfaceStateWithRpc(viewState),
		versions = versionStateWithRpc(viewState, runtime.version, frontendVersion), groups = warningGroups(viewState.status, viewState.health, viewState.rpc, viewState.diagnostics),
		contract = diagnosticsContractState(viewState), backendVersion = contract.usable ? contract.data.versions.daemon : runtime.version,
		lines = [
			'LAN Speed ' + _('运行诊断报告 v2'), _('页面状态') + ': ' + reportPageState(viewState.pageState || pageState(viewState)),
			_('检查时间') + ': ' + reportField(new Date(viewState.checkedAt || Date.now()).toLocaleString()),
			_('LuCI 版本') + ': ' + reportVersion(frontendVersion), _('后端版本') + ': ' + reportVersion(backendVersion), ''
		];
	if (contract.usable) {
		lines.push(_('诊断契约') + ': v' + reportField(contract.data.contract_version),
			_('服务') + ': ' + reportField(contract.data.service.state) + ' / ubus ' + reportField(contract.data.service.ubus_connected),
			_('采集代次') + ': ' + reportField(contract.data.collection.generation),
			_('采集年龄') + ': ' + reportField(formatDuration(contract.data.collection.age_ms)),
			_('连续失败') + ': ' + reportField(contract.data.collection.consecutive_failures), '');
	}
	lines.push(_('RPC 检查') + ':');
	RPC_KEYS.forEach(function(key) {
		var rpc = rpcResult(viewState, key), text = rpcReportState(rpc);
		lines.push('- ' + RPC_LABELS[key] + ': ' + text +
			(rpc && !rpc.ok ? ' · ' + rpcReportErrorText(rpc) : ''));
	});
	lines.push('', _('客户端总速率') + ': ' + stateLabel(rate.state) + ' · ' + reportCollectorLabel(rate.source),
			'- ' + _('方向唯一来源') + ': ' + reportField(rate.sourceText),
		'- ' + _('方向覆盖') + ': ' + reportField(rate.coverageText),
		'- ' + _('流量范围') + ': ' + reportField(rate.scopeText));
	if (nssPlatform(runtime)) {
		lines.push(
			_('精准接入点') + ': ' + stateLabel(edge.state) + ' · ' + reportField(edge.value),
			'- ' + _('接入类型') + ': ' + reportField(edge.attachmentText),
			'- ' + _('归属信任') + ': ' + reportField(edge.trustText),
			'- ' + _('接入边界') + ': ' + reportField(edge.reasonText),
			_('NSS/CPU 流量分类') + ': ' + stateLabel(classification.state) + ' · ' + reportField(classification.value),
			'- ' + _('分类状态') + ': ' + reportField(classification.stateText),
			'- ' + _('最低分类覆盖率') + ': ' + reportField(classification.coverageText),
			'- ' + _('分类映射') + ': ' + reportField(classification.maps.detailText),
			_('NSS 客户端控制') + ': ' + stateLabel(control.state) + ' · ' + reportField(control.value),
			'- ' + _('控制客户端') + ': ' + reportField(control.configuredClients),
			'- ' + _('限速方向') + ': ' + reportField(control.verifiedDirections) + '/' + reportField(control.requiredDirections),
			'- ' + _('执行器证明') + ': NSS ' + reportField(control.nssVerifiedDirections) + ' · CPU ' + reportField(control.cpuVerifiedDirections),
			'- ' + _('禁网') + ': ' + reportField(control.blockActiveClients) + '/' + reportField(control.internetDisabledClients),
			'- ' + _('等待 / 错误 / 队列溢出') + ': ' + reportField(control.pendingClients) + ' / ' +
				reportField(control.errorClients) + ' / ' + reportField(control.queueOverflowClients),
			'- ' + _('控制诊断码') + ': ' + reportField(control.detailCode || control.reasonCode));
	} else {
		lines.push(
			_('架构路径') + ': x86 TC-BPF');
	}
	lines.push(
		_('降级与能力边界') + ': ' + stateLabel(integrity.state) + ' · ' + reportField(integrity.value),
		'- ' + reportField(integrity.reasonText),
		'- ' + _('安全规则') + ': ' + (nssPlatform(runtime) ? _('N/S 不与 E 相加；不可比较时不生成未分类或覆盖率') : _('x86 仅发布 TC-BPF 单一总速率来源')),
		_('数据新鲜度') + ': ' + stateLabel(freshness.state) + ' · ' + reportField(freshness.value),
		_('连接健康') + ': ' + stateLabel(connections.state) + ' · ' + reportCollectorLabel(connections.source),
		_('版本一致性') + ': ' + stateLabel(versions.state) + ' · ' + reportField(versions.badge),
		_('接口健康') + ': ' + stateLabel(interfaces.state) + ' · ' + reportField(interfaces.value), '');
	if (contract.usable) {
		lines.push(_('子系统状态') + ':');
		asArray(contract.data.subsystems).forEach(function(item) {
			if (!nssPlatform(runtime) && [ 'nss', 'nss_control' ].indexOf(String(item && item.id || '')) !== -1) return;
			lines.push('- ' + subsystemReportText(item, nssPlatform(runtime)));
		});
		lines.push('');
	}
	if (groups.all.length) {
		lines.push(_('告警') + ':');
		groups.all.forEach(function(item) {
			var fallback = item.source === 'probe' ? probeFailureReportText(item.raw) :
				(item.source === 'rpc' ? item.text : null);
			lines.push('- [' + reportField(item.severity) + '] ' + diagnosticPublicText(item, fallback));
		});
	} else lines.push(_('告警') + ': -');
	lines.push('', _('接口明细') + ': ' + reportField(interfaces.items.length));
	interfaces.items.forEach(function(item, index) {
		item = plainObject(item) ? item : {};
		lines.push('- ' + _('接口 %d').format(index + 1) + ' · ' + interfaceReportRole(item.role) + ' · ' + interfaceReportStatus(item.status));
	});
	lines.push('', _('隐私说明') + ': ' + _('报告只复制白名单状态、计数和本地化告警；客户端地址、名称、接口名、探针源和原始后端文本不会复制。'));
	return lines.join('\n');
}

return baseclass.extend({
	sanitizeReportText: sanitizeReportText,
	probeFailureText: probeFailureText,
	probeFailureReportText: probeFailureReportText,
	rpcReportErrorText: rpcReportErrorText,
	reportField: reportField,
	reportCollectorLabel: reportCollectorLabel,
	reportReasonText: reportReasonText,
	reportVersion: reportVersion,
	reportConfiguredMode: reportConfiguredMode,
	rpcReportState: rpcReportState,
	reportPageState: reportPageState,
	diagnosticSeverity: diagnosticSeverity,
	diagnosticPublicText: diagnosticPublicText,
	stateLabel: stateLabel,
	interfaceReportRole: interfaceReportRole,
	interfaceReportStatus: interfaceReportStatus,
	subsystemReportText: subsystemReportText,
	buildReport: buildReport
});
