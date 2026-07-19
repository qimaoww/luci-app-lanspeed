'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.vocab as vocab';
'require lanspeed.version as lsVersion';
'require lanspeed.statusCollector as statusCollector';
'require lanspeed.diagnosticsModel as diagnosticsModel';

function stateClass(state) {
	return state === 'good' ? 'label-success' : state === 'warning' || state === 'degraded' || state === 'partial'
		? 'label-warning' : state === 'bad' || state === 'error' || state === 'invalid' ? 'label-danger' : '';
}

function phaseLabel(phase) {
	return ({
		loading: _('检查中'), success: _('成功'), empty: _('无数据'), stale: _('已过期'),
		degraded: _('降级'), error: _('失败'), invalid: _('契约无效'),
		fresh: _('新鲜'), healthy: _('正常'), unavailable: _('不可用'), disabled: _('未启用')
	})[phase] || _('未检查');
}

var SUBSYSTEM_LABELS = {
	bpf: _('BPF 运行时'), tc: _('TC 挂载'), bpf_map: _('BPF 映射表'),
	conntrack: _('连接跟踪'), nss: _('NSS'), identity: _('客户端归属'), ubus: _('RPC 服务')
};

var NEUTRAL_DISABLED_SUBSYSTEM_CODES = {
	bpf_disabled: true,
	bpf_not_selected: true,
	nss_not_present: true
};

function subsystemCodeText(code) {
	if (!code) return '-';
	if (typeof vocab.hasWarning === 'function' && vocab.hasWarning(code) &&
		typeof vocab.warningText === 'function') return vocab.warningText(code);
	return _('未识别的诊断代码：%s').format(String(code));
}

function subsystemRowState(state, code) {
	if (state === 'healthy') return 'good';
	if (state === 'degraded') return 'warning';
	if (state === 'unavailable') return 'bad';
	if (state === 'disabled') {
		if (code === 'no_collect_interface') return 'bad';
		return NEUTRAL_DISABLED_SUBSYSTEM_CODES[code] ? 'neutral' : 'warning';
	}
	return 'neutral';
}

function setFact(refs, key, state, value, meta) {
	if (!refs[key + 'Fact']) return;
	refs[key + 'Fact'].setAttribute('data-state', state || 'neutral');
	refs[key + 'Value'].textContent = value === null || value === undefined || value === '' ? '-' : String(value);
	refs[key + 'Meta'].textContent = meta || '';
}

function setStage(refs, key, state, badge, value, description, meta, evidence) {
	if (!refs[key + 'Stage']) return;
	refs[key + 'Stage'].setAttribute('data-state', state || 'neutral');
	refs[key + 'Badge'].className = 'label lanspeed-diagnostic-stage-badge ' + stateClass(state);
	refs[key + 'Badge'].textContent = badge || phaseLabel(state);
	refs[key + 'Value'].textContent = value === null || value === undefined || value === '' ? '-' : String(value);
	refs[key + 'Description'].textContent = description || '';
	refs[key + 'Meta'].textContent = meta || '';
	var children = [];
	Object.keys(evidence || {}).forEach(function(label) {
		children.push(E('dt', {}, label), E('dd', {}, evidence[label]));
	});
	fmt.replaceChildren(refs[key + 'Evidence'], children);
}

function rpcErrorText(result) {
	var error = result && result.error;
	if (!error) return _('未知 RPC 失败');
	var prefix = ({ timeout: _('请求超时'), contract: _('契约无效'), missing: _('缺少结果'),
		client: _('页面处理失败'), transport: _('传输失败') })[error.kind] || _('RPC 失败');
	var label = prefix + ' · ' + (error.message || _('未知 RPC 失败'));
	if (error.code) label += ' (' + error.code + ')';
	return String(label);
}

function resource(viewState, key) {
	return viewState && viewState.resources && viewState.resources[key] || null;
}

function displayPhase(viewState, key) {
	var value = resource(viewState, key);
	return value ? value.phase : diagnosticsModel.rpcState(viewState, key).phase;
}

function contract(viewState) {
	return diagnosticsModel.diagnosticsContractState(viewState);
}

function textOrDash(value) {
	return value === null || value === undefined || value === '' ? '-' : String(value);
}

function renderPageState(refs, viewState) {
	var state = diagnosticsModel.pageState(viewState);
	var messages = {
		loading: [ _('正在运行诊断'), _('正在等待各 RPC 独立返回；页面会保留每个接口的实际状态。') ],
		ready: [ _('诊断完成'), _('所有必要接口均返回可用结果。') ],
		degraded: [ _('诊断完成但已降级'), _('部分数据过期、沿用旧值或使用回退路径。') ],
		partial: [ _('部分诊断失败'), _('部分接口可用，失败项会在 RPC 明细中单独列出。') ],
		empty: [ _('没有可用数据'), _('接口已响应但没有可诊断的采样；请检查服务与采集配置。') ],
		error: [ _('诊断无法完成'), _('没有一个必要接口提供可验证结果，请检查 lanspeedd 与 RPC 权限。') ]
	};
	var message = messages[state] || messages.loading;
	refs.summary.className = 'label lanspeed-diagnostics-summary ' + stateClass(state);
	refs.summary.textContent = message[0];
	refs.pageNotice.setAttribute('data-state', state);
	refs.pageNotice.setAttribute('aria-hidden', state === 'ready' ? 'true' : 'false');
	refs.pageNotice.style.display = state === 'ready' ? 'none' : '';
	refs.pageNoticeTitle.textContent = message[0];
	refs.pageNoticeText.textContent = message[1];
	refs.root.setAttribute('data-page-state', state);
	refs.root.setAttribute('aria-busy', state === 'loading' ? 'true' : 'false');
	if (refs.btnRefresh) {
		refs.btnRefresh.disabled = state === 'loading';
		refs.btnRefresh.textContent = state === 'loading' ? _('检查中…') : _('重新检查');
	}
	if (refs.btnCopy) refs.btnCopy.disabled = state === 'loading' || viewState.copyPending === true;
	return state;
}

function renderErrors(refs, viewState) {
	var errors = viewState.errors || [];
	refs.errorDetails.hidden = !errors.length;
	refs.errorDetails.setAttribute('aria-hidden', errors.length ? 'false' : 'true');
	fmt.replaceChildren(refs.errorList, errors.map(function(item) {
		var result = viewState.rpc && viewState.rpc[item.key] || {};
		return E('li', { 'data-state': result.phase || 'error' }, [
			E('strong', {}, diagnosticsModel.RPC_LABELS[item.key] + '：'),
			E('span', {}, phaseLabel(result.phase) + ' · ' + rpcErrorText(result)),
			result.retained ? E('small', {}, _('；显示最近一次成功结果')) : ''
		]);
	}));
}

function refreshStatusCards(refs, status, health, rpcData, collector, diagnostics) {
	var viewState = { status: status || {}, health: health || {}, rpc: rpcData || {}, diagnostics: diagnostics || {} };
	var c = contract(viewState);
	var runtime = diagnosticsModel.mergeRuntime(status, health, rpcData, diagnostics);
	var versions = diagnosticsModel.versionStateWithRpc(viewState,
		status && status.version || health && health.version || runtime.version, lsVersion.FULL_VERSION);
	var path = diagnosticsModel.pathStateWithRpc(viewState);
	var collection = c.usable ? c.data.collection : null;
	var service = c.usable ? c.data.service : null;
	var diagnosticPhase = displayPhase(viewState, 'diagnostics');
	var serviceState = service ? (service.state === 'running' && service.ubus_connected ? 'good' :
		(!service.ubus_connected ? 'bad' : 'warning')) :
		(diagnosticPhase === 'loading' ? 'neutral' : diagnosticPhase === 'error' || diagnosticPhase === 'invalid' ? 'bad' : 'warning');
	var collectionState = collection ? (collection.state === 'fresh' && !collection.retained ? 'good' :
		(collection.state === 'unavailable' ? 'bad' : 'warning')) : serviceState;
	setFact(refs, 'service', serviceState,
		service ? (service.state + (service.ubus_connected ? '' : ' · ubus 断开')) : _('未确认'),
		service ? _('ubus %s').format(service.ubus_connected ? _('已连接') : _('未连接')) : _('等待 status/health'));
	setFact(refs, 'collection', collectionState,
		collection ? phaseLabel(collection.state) : phaseLabel(displayPhase(viewState, 'diagnostics')),
		collection ? _('第 %d 代 · 年龄 %s').format(collection.generation,
			diagnosticsModel.formatDuration(collection.age_ms)) : _('诊断契约未确认'));
	setFact(refs, 'version', versions.state, versions.state === 'good' ? _('一致') : versions.badge, versions.value);
	setFact(refs, 'source', path.state, path.value,
		(path.configuredRate || '-') + ' / ' + (path.configuredConnection || '-'));
	return { states: [ serviceState, collectionState, versions.state, path.state ], version: versions, path: path,
		collector: collector, attention: [ serviceState, collectionState, versions.state, path.state ]
			.filter(function(state) { return state !== 'good'; }).length };
}

function renderPipeline(refs, viewState) {
	var quality = diagnosticsModel.qualityState(viewState, viewState.progress);
	var freshness = quality.freshness || {};
	var path = diagnosticsModel.pathStateWithRpc(viewState);
	var connections = diagnosticsModel.connectionStateWithRpc(viewState);
	var freshnessEvidence = {}, qualityEvidence = {}, pathEvidence = {}, connectionEvidence = {};
	freshnessEvidence[_('诊断 RPC')] = phaseLabel(displayPhase(viewState, 'diagnostics'));
	qualityEvidence[_('覆盖率')] = quality.coverage && quality.coverage.badge || _('未知');
	qualityEvidence[_('状态 RPC')] = phaseLabel(displayPhase(viewState, 'status'));
	pathEvidence[_('速率配置')] = textOrDash(path.configuredRate);
	pathEvidence[_('连接配置')] = textOrDash(path.configuredConnection);
	connectionEvidence[_('数据 RPC')] = phaseLabel(displayPhase(viewState, 'clients'));
	connectionEvidence[_('匹配率')] = connections.matchPct === null || connections.matchPct === undefined
		? '-' : String(Math.round(connections.matchPct * 10) / 10) + '%';
	setStage(refs, 'freshness', freshness.state, freshness.badge, freshness.value,
		freshness.description, freshness.meta, freshnessEvidence);
	setStage(refs, 'quality', quality.state, quality.badge, quality.value,
		quality.description, quality.meta, qualityEvidence);
	setStage(refs, 'path', path.state, path.badge, path.value, path.description, path.meta, pathEvidence);
	setStage(refs, 'connections', connections.state, connections.badge, connections.value,
		connections.description, connections.meta, connectionEvidence);
	refs.pipelineSummary.textContent = [ quality.badge, freshness.badge, path.badge, connections.badge ].join(' · ');
	return { quality: quality, freshness: freshness, path: path, connections: connections };
}

function interfaceRoleLabel(role) {
	return ({ lan: _('LAN'), observe: _('观察'), wan: _('WAN'), excluded: _('排除'), unknown: _('未知') })
		[String(role || 'unknown')] || _('未知');
}

function interfaceStatusLabel(status) {
	return ({ available: _('可用'), active: _('采集中'), pending: _('等待采样'), missing: _('缺失'),
		unsupported: _('不支持'), excluded: _('已排除') })[String(status || 'unknown')] || _('未知');
}

function interfaceRowState(status) {
	return status === 'available' || status === 'active' ? 'good' : status === 'pending' ? 'warning' :
		status === 'missing' || status === 'unsupported' ? 'bad' : 'neutral';
}

function rateText(item) {
	if (!item || (item.rx_bps === undefined && item.tx_bps === undefined)) return '-';
	return _('↓ %s · ↑ %s').format(fmt.formatRate(Number(item.rx_bps) || 0, 'bit'),
		fmt.formatRate(Number(item.tx_bps) || 0, 'bit'));
}

function renderInterfaces(refs, viewState) {
	var result = diagnosticsModel.interfaceStateWithRpc(viewState);
	var rows = (result.items || []).map(function(item) {
		item = item && typeof item === 'object' ? item : {};
		var state = interfaceRowState(item.status);
		return E('tr', { 'data-state': state }, [
			E('td', { 'data-label': _('接口') }, String(item.name || '-')),
			E('td', { 'data-label': _('角色') }, interfaceRoleLabel(item.role)),
			E('td', { 'data-label': _('状态') }, interfaceStatusLabel(item.status)),
			E('td', { 'data-label': _('采样') }, item.sample_ms !== undefined
				? diagnosticsModel.formatDuration(item.sample_ms) : _('未采样')),
			E('td', { 'data-label': _('实时速率'), 'class': 'lanspeed-diagnostic-interface-rate' }, rateText(item))
		]);
	});
	if (!rows.length) rows.push(E('tr', { 'data-state': 'empty' }, [
		E('td', { 'colspan': '5' }, result.rpc === 'loading' ? _('正在等待接口数据。') : _('没有接口数据。'))
	]));
	fmt.replaceChildren(refs.interfacesBody, rows);
	refs.healthSummary.textContent = result.badge + ' · ' + result.value;
	return result;
}

function renderSubsystems(refs, viewState) {
	var c = contract(viewState);
	var rows = (c.usable ? c.data.subsystems : []).map(function(item) {
		var state = subsystemRowState(item.state, item.code);
		return E('tr', { 'data-state': state }, [
			E('td', { 'data-label': _('组件') }, SUBSYSTEM_LABELS[item.id] || _('未知组件')),
			E('td', { 'data-label': _('状态') }, phaseLabel(item.state)),
			E('td', { 'data-label': _('诊断代码') }, subsystemCodeText(item.code))
		]);
	});
	if (!rows.length) rows.push(E('tr', { 'data-state': 'empty' }, [
		E('td', { 'colspan': '3' }, c.valid ? _('后端没有子系统明细。') : _('诊断契约尚未确认。'))
	]));
	fmt.replaceChildren(refs.subsystemsBody, rows);
}

function renderRpcChecks(refs, viewState) {
	var keys = diagnosticsModel.RPC_KEYS;
	var failed = [], attention = 0;
	var rows = keys.map(function(key) {
		var result = viewState.rpc && viewState.rpc[key];
		var phase = result && result.phase || 'loading';
		var state = phase === 'success' ? 'good' : phase === 'empty' || phase === 'stale' || phase === 'degraded'
			? 'warning' : phase === 'loading' ? 'neutral' : 'bad';
		if (state === 'warning') attention++;
		if (state === 'bad') failed.push({ key: key, result: result });
		return E('tr', { 'data-state': state }, [
			E('td', { 'data-label': _('接口') }, diagnosticsModel.RPC_LABELS[key]),
			E('td', { 'data-label': _('状态') }, [ E('span', { 'class': 'label ' + stateClass(state) }, phaseLabel(phase)),
				result && result.retained ? E('small', {}, _('沿用')) : '' ]),
			E('td', { 'data-label': _('数据时间') }, result && result.fetchedAt !== null && result.fetchedAt !== undefined
				? new Date(result.fetchedAt).toLocaleTimeString() : '-'),
			E('td', { 'data-label': _('结果') }, result && result.ok ? _('已返回数据')
				: result && result.error ? rpcErrorText(result) : _('等待结果'))
		]);
	});
	fmt.replaceChildren(refs.rpcBody, rows);
	var issueCount = keys.filter(function(key) {
		var item = viewState.rpc && viewState.rpc[key];
		return !item || !item.ok;
	}).length;
	refs.rpcSummary.textContent = issueCount ? _('%d / %d 个接口失败').format(issueCount, keys.length) :
		(attention ? _('%d 个接口均已响应 · %d 项数据状态需关注').format(keys.length, attention) :
			_('%d 个接口全部成功').format(keys.length));
	return { failed: failed, attention: attention,
		state: issueCount === keys.length ? 'bad' : issueCount || attention ? 'warning' : 'good' };
}

function alertNode(item, empty) {
	return E('li', {
		'class': empty ? 'lanspeed-diagnostic-alert-empty' : 'lanspeed-diagnostic-alert',
		'data-severity': empty ? 'info' : item.severity
	}, [
		E('span', { 'class': 'lanspeed-diagnostic-alert-severity', 'aria-hidden': 'true' },
			empty ? 'i' : item.severity === 'critical' ? '!' : item.severity === 'warning' ? '!' : '·'),
		E('span', { 'class': 'lanspeed-diagnostic-alert-text' }, empty ? item : item.text || _('检测到一项诊断事件。'))
	]);
}

function renderWarnings(refs, status, health, rpcData, diagnostics) {
	var groups = diagnosticsModel.warningGroups(status, health, rpcData, diagnostics);
	var important = groups.important || [];
	var environment = groups.environment || [];
	var criticalCount = important.filter(function(item) { return item.severity === 'critical'; }).length;
	var warningCount = important.length - criticalCount;
	fmt.replaceChildren(refs.importantWarnings, important.length
		? important.map(function(item) { return alertNode(item, false); })
		: [ alertNode(_('未发现严重告警。'), true) ]);
	fmt.replaceChildren(refs.environmentWarnings, environment.length
		? environment.map(function(item) { return alertNode(item, false); })
		: [ alertNode(_('没有额外提示。'), true) ]);
	refs.alertSummary.textContent = criticalCount || warningCount || environment.length
		? _('%d 条严重 · %d 条警告 · %d 条提示').format(criticalCount, warningCount, environment.length)
		: _('无活动告警');
	return { state: criticalCount ? 'bad' : warningCount || environment.length ? 'warning' : 'good',
		criticalCount: criticalCount, warningCount: warningCount,
		importantCount: important.length, environmentCount: environment.length,
		probeFailureCount: groups.probeFailuresTotal || 0 };
}

function refresh(viewState) {
	var refs = viewState && viewState.refs;
	if (!refs) return null;
	var state = renderPageState(refs, viewState);
	var cardState = refreshStatusCards(refs, viewState.status, viewState.health, viewState.rpc,
		statusCollector.effectiveCollector(viewState.status, viewState.clients), viewState.diagnostics);
	var pipeline = renderPipeline(refs, viewState);
	var rpcState = renderRpcChecks(refs, viewState);
	var interfaces = renderInterfaces(refs, viewState);
	renderSubsystems(refs, viewState);
	var warnings = renderWarnings(refs, viewState.status, viewState.health, viewState.rpc, viewState.diagnostics);
	renderErrors(refs, viewState);
	if (refs.reportPreview) refs.reportPreview.textContent = diagnosticsModel.buildReport(viewState, lsVersion.FULL_VERSION);
	refs.checked.textContent = viewState.checkedAt !== null && viewState.checkedAt !== undefined ?
		(state === 'loading' ? _('上次检查 %s · 正在重新检查').format(new Date(viewState.checkedAt).toLocaleTimeString()) :
			_('检查于 %s').format(new Date(viewState.checkedAt).toLocaleTimeString())) : _('尚未完成检查');
	refs.root.setAttribute('aria-busy', state === 'loading' ? 'true' : 'false');
	return { state: state, cardState: cardState, pipeline: pipeline, rpc: rpcState,
		interfaces: interfaces, warnings: warnings };
}

return baseclass.extend({
	refreshStatusCards: refreshStatusCards,
	renderRpcChecks: renderRpcChecks,
	renderWarnings: renderWarnings,
	refresh: function(viewState) { return refresh(viewState); }
});
