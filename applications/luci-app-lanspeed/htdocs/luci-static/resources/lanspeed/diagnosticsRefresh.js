'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.vocab as vocab';
'require lanspeed.version as lsVersion';
'require lanspeed.statusCollector as statusCollector';
'require lanspeed.diagnosticsModel as diagnosticsModel';
'require lanspeed.clientControl as clientControl';

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
	bpf: _('CPU 慢路径检测（BPF）'), tc: _('CPU 路径挂载（TC）'), bpf_map: _('分类映射表'),
	conntrack: _('连接跟踪'), nss: _('NSS 加速识别'), nss_control: _('NSS 客户端控制'),
	identity: _('客户端接入归属'), ubus: _('RPC 服务')
};

function subsystemLabel(id, nssPlatform) {
	if (!nssPlatform && id === 'identity')
		return _('客户端身份识别');
	return SUBSYSTEM_LABELS[id] || _('未知组件');
}

var NEUTRAL_DISABLED_SUBSYSTEM_CODES = {
	bpf_disabled: true,
	bpf_not_selected: true,
	tc_bpf_not_selected: true,
	nss_not_present: true,
	nss_control_not_configured: true,
	nss_control_no_active_client: true
};

function subsystemCodeText(code) {
	if (!code) return '-';
	if (typeof vocab.hasWarning === 'function' && vocab.hasWarning(code) &&
		typeof vocab.warningText === 'function') return vocab.warningText(code);
	if (typeof clientControl.reasonText === 'function') {
		var text = clientControl.reasonText(code);
		if (text && !String(text).startsWith(_('控制不可用：'))) return text;
	}
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
		refs.btnRefresh.disabled = state === 'loading' || viewState.restartPending === true;
		refs.btnRefresh.textContent = state === 'loading' ? _('检查中…') : _('重新检查');
	}
	if (refs.btnRestart) {
		refs.btnRestart.disabled = state === 'loading' || viewState.restartPending === true;
		refs.btnRestart.textContent = viewState.restartPending === true ? _('正在重启…') : _('重启服务');
	}
	if (refs.btnCopy) refs.btnCopy.disabled = state === 'loading' ||
		viewState.copyPending === true || viewState.restartPending === true;
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

function refreshStatusCards(refs, status, health, rpcData, collector, diagnostics, clientsData) {
	var viewState = { status: status || {}, health: health || {}, clients: clientsData || {},
		rpc: rpcData || {}, diagnostics: diagnostics || {} };
	var c = contract(viewState);
	var runtime = diagnosticsModel.mergeRuntime(status, health, rpcData, diagnostics);
	var versions = diagnosticsModel.versionStateWithRpc(viewState,
		status && status.version || health && health.version || runtime.version, lsVersion.FULL_VERSION);
	var connections = diagnosticsModel.connectionStateWithRpc(viewState);
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
	setFact(refs, 'connections', connections.state, connections.value,
		connections.matchPct === null || connections.matchPct === undefined ? connections.description :
			_('匹配率 %s · TCP %d · UDP %d').format(
				diagnosticsModel.formatPercent(connections.matchPct),
				Math.max(0, Number(status && status.tcp_conns_total) || Number(viewState.clients && viewState.clients.tcp_conns_total) || 0),
				Math.max(0, Number(status && status.udp_conns_total) || Number(viewState.clients && viewState.clients.udp_conns_total) || 0)));
	setFact(refs, 'version', versions.state, versions.state === 'good' ? _('一致') : versions.badge, versions.value);
	return { states: [ serviceState, collectionState, connections.state, versions.state ], version: versions,
		connections: connections, collector: collector,
		attention: [ serviceState, collectionState, connections.state, versions.state ]
			.filter(function(state) { return state !== 'good'; }).length };
}

function renderPipeline(refs, viewState) {
	var nssPlatform = fmt.nssPlatform(viewState && viewState.status);
	if (!nssPlatform) {
		if (refs.pipelineSection && refs.pipelineSection.parentNode)
			refs.pipelineSection.parentNode.removeChild(refs.pipelineSection);
		refs.pipelineSection = null;
		return null;
	}
	if (!refs.pipelineSection && viewState && typeof viewState.mountPipeline === 'function')
		viewState.mountPipeline();
	if (!refs.pipelineSection)
		return null;
	var rate = diagnosticsModel.rateOwnerStateWithRpc(viewState);
	var edge = diagnosticsModel.accessEdgeStateWithRpc(viewState);
	var classification = diagnosticsModel.classificationStateWithRpc(viewState);
	var rateEvidence = {}, edgeEvidence = {}, classificationEvidence = {};
	rateEvidence[_('客户端采集覆盖率')] = rate.facts.totalDirections
		? diagnosticsModel.formatPercent(rate.facts.ownerDirections * 100 / rate.facts.totalDirections) : '-';
	rateEvidence[_('范围')] = rate.scopeText;
	edgeEvidence[_('接入')] = edge.attachmentText;
	edgeEvidence[_('归属')] = edge.trustText;
	classificationEvidence[_('核对')] = classification.verificationText;
	if (classification.coverageText !== '-')
		classificationEvidence[_('覆盖率')] = classification.coverageText;
	classificationEvidence[_('映射')] = classification.maps.text;
	setStage(refs, 'rate', rate.state, rate.badge, rate.value,
		'', _('%d/%d 方向 · %s').format(rate.facts.ownerDirections, rate.facts.totalDirections,
			rate.windowText), rateEvidence);
	setStage(refs, 'edge', edge.state, edge.badge, edge.value,
		'', edge.meta, edgeEvidence);
	setStage(refs, 'classification', classification.state, classification.badge, classification.value,
		'', _('分类 %s · 核对 %s').format(
			diagnosticsModel.formatDuration(classification.windowMs),
			diagnosticsModel.formatDuration(classification.comparisonWindowMs)), classificationEvidence);
	refs.pipelineSummary.textContent = _('总速率 %d/%d 方向 · 分类 %d/%d 客户端').format(
		rate.facts.ownerDirections, rate.facts.totalDirections,
		classification.classified, classification.totalClients);
	return { rate: rate, edge: edge, classification: classification };
}

function renderControl(refs, viewState) {
	var nssPlatform = fmt.nssPlatform(viewState && viewState.status);
	if (!nssPlatform) {
		if (refs.controlSection && refs.controlSection.parentNode)
			refs.controlSection.parentNode.removeChild(refs.controlSection);
		refs.controlSection = null;
		return null;
	}
	if (!refs.controlSection && viewState && typeof viewState.mountControl === 'function')
		viewState.mountControl();
	if (!refs.controlSection)
		return null;
	var control = diagnosticsModel.nssControlStateWithRpc(viewState);
	var capabilityState = control.shapingSupported || control.blockingSupported ? 'good' : 'bad';
	var pathState = control.requiredDirections === 0 ? 'neutral' :
		control.verifiedDirections === control.requiredDirections ? 'good' :
		control.errorClients ? 'bad' : 'warning';
	var queueState = control.queueOverflowClients || control.errorClients ? 'bad' :
		control.requiredDirections && control.verifiedDirections < control.requiredDirections ? 'warning' :
		control.requiredDirections ? 'good' : 'neutral';
	var blockState = control.internetDisabledClients === 0 ? 'neutral' :
		control.blockActiveClients === control.internetDisabledClients && !control.errorClients ? 'good' : 'bad';
	/* A failed or retained clients RPC must never leave a green stage behind.
	 * The evidence may be a structurally valid older snapshot, but it is not a
	 * current proof that can be shown as effective. */
	if (control.state === 'bad') {
		capabilityState = pathState = queueState = blockState = 'bad';
	} else if (control.state === 'warning') {
		if (capabilityState === 'good') capabilityState = 'warning';
		if (pathState === 'good') pathState = 'warning';
		if (queueState === 'good') queueState = 'warning';
		if (blockState === 'good') blockState = 'warning';
	}
	var capabilityEvidence = {}, queueEvidence = {}, blockEvidence = {};
	capabilityEvidence[_('限速客户端')] = control.rateLimitedClients;
	capabilityEvidence[_('禁网客户端')] = control.internetDisabledClients;
	queueEvidence[_('等待')] = control.pendingClients;
	queueEvidence[_('错误')] = control.errorClients;
	queueEvidence[_('溢出')] = control.queueOverflowClients;
	blockEvidence[_('诊断码')] = subsystemCodeText(control.detailCode || control.reasonCode);
	setStage(refs, 'controlCapability', capabilityState,
		capabilityState === 'good' ? _('可用') : _('不可用'),
		_('限速 %s · 禁网 %s').format(control.shapingSupported ? _('可用') : _('不可用'),
			control.blockingSupported ? _('可用') : _('不可用')),
		'', _('%d 个规则 · %d 个活动客户端').format(control.configuredClients, control.activeClients),
		capabilityEvidence);
	setStage(refs, 'controlPath', pathState,
		pathState === 'good' ? _('已证明') : pathState === 'bad' ? _('失败') :
			pathState === 'warning' ? _('等待证明') : _('无需证明'),
		_('%d/%d 个方向').format(control.verifiedDirections, control.requiredDirections),
		'', _('每个方向只进入一个聚合执行器'), {
			NSS: control.nssVerifiedDirections,
			CPU: control.cpuVerifiedDirections
		});
	setStage(refs, 'controlQueue', queueState,
		queueState === 'good' ? _('完整') : queueState === 'bad' ? _('异常') :
			queueState === 'warning' ? _('等待计数') : _('未启用'),
		_('%d/%d 个客户端已生效').format(control.effectiveClients, control.activeClients),
		'', _('只以 drops 增长报告队列溢出'), queueEvidence);
	setStage(refs, 'controlBlock', blockState,
		blockState === 'good' ? _('已生效') : blockState === 'bad' ? _('异常') : _('未配置'),
		_('%d/%d 个客户端').format(control.blockActiveClients, control.internetDisabledClients),
		'', _('仅禁用互联网，路由器与 LAN/NAS 先放行'), blockEvidence);
	refs.controlSummary.textContent = control.badge + ' · ' + control.value;
	return control;
}

function renderPlatformIntro(refs, viewState) {
	if (!refs.intro) return;
	var platform = viewState && viewState.status && viewState.status.evidence &&
		viewState.status.evidence.platform || {};
	var known = platform.profile !== undefined || platform.target_arch !== undefined;
	if (!known) {
		refs.intro.textContent = _('正在确认运行平台与采集链路。');
		return;
	}
	var status = viewState && viewState.status;
	refs.intro.textContent = !fmt.nssPlatform(status) ? _('x86 使用原生 TC-BPF 客户端总速率。') :
		diagnosticsModel.currentRateUsesRoutedInternet(status)
			? _('总速率只显示 NSS FastN+FastS 观察到的互联网/路由流量；不代表客户端全部帧。')
			: _('总速率由客户端接入口采集；NSS/CPU 只做分类，不与总速率相加。');
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

var TC_STATE_LABELS = {
	clean: _('无冲突'), coexisting: _('可共存'), conflict: _('检测到冲突'),
	partial: _('扫描不完整'), unavailable: _('不可用')
};
var TC_OWNER_LABELS = {
	lanspeed: _('LAN Speed'), kernel: _('内核默认'), shared: _('共享挂载点'),
	dae: _('DAE / daed'), sqm: _('SQM'), qosify: _('qosify'),
	other: _('其他组件'), unknown: _('未知组件')
};
var TC_CONFLICT_LABELS = {
	reserved_filter_slot: _('其他过滤器占用了 LAN Speed 保留的 pref/handle'),
	reserved_qdisc_handle: _('其他队列占用了 LAN Speed 保留的根句柄'),
	foreign_filter_preemption: _('更高优先级的外部动作可能重定向、丢弃或提前终止数据包'),
	foreign_filter_precedes_lanspeed: _('外部过滤器先于 LAN Speed 执行，请确认其动作会继续放行'),
	foreign_root_qdisc: _('外部根队列会阻止 LAN Speed 在此接口建立客户端整形树'),
	ingress_qdisc_blocks_clsact: _('传统 ingress qdisc 会阻止 LAN Speed 安装共享 clsact 挂载点')
};

function tcOwnerLabel(owner) {
	return TC_OWNER_LABELS[String(owner || 'unknown')] || _('未知组件');
}

function tcDirectionLabel(direction) {
	return ({ ingress: _('入站'), egress: _('出站'), root: _('根队列'), child: _('子队列'),
		unknown: _('未知') })[String(direction || 'unknown')] || String(direction || '-');
}

function tcEvidence(viewState) {
	var value = viewState && viewState.health && viewState.health.evidence &&
		viewState.health.evidence.tc_status;
	if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
	return value;
}

function tcInteger(value) {
	value = Number(value);
	return isFinite(value) && value >= 0 ? Math.floor(value) : 0;
}

function tcCounters(value) {
	value = value && typeof value === 'object' ? value : {};
	var parts = [];
	if (value.packets !== null && value.packets !== undefined)
		parts.push(_('%d 包').format(tcInteger(value.packets)));
	if (value.bytes !== null && value.bytes !== undefined)
		parts.push(_('%d 字节').format(tcInteger(value.bytes)));
	if (value.drops !== null && value.drops !== undefined && tcInteger(value.drops))
		parts.push(_('%d 丢包').format(tcInteger(value.drops)));
	if (value.overlimits !== null && value.overlimits !== undefined && tcInteger(value.overlimits))
		parts.push(_('%d 超限').format(tcInteger(value.overlimits)));
	if (value.backlog !== null && value.backlog !== undefined && tcInteger(value.backlog))
		parts.push(_('积压 %d').format(tcInteger(value.backlog)));
	if (value.requeues !== null && value.requeues !== undefined && tcInteger(value.requeues))
		parts.push(_('%d 次重排队').format(tcInteger(value.requeues)));
	if (value.qlen !== null && value.qlen !== undefined)
		parts.push(_('队列长度 %d').format(tcInteger(value.qlen)));
	if (value.maxpacket !== null && value.maxpacket !== undefined && tcInteger(value.maxpacket))
		parts.push(_('最大包 %d').format(tcInteger(value.maxpacket)));
	return parts.length ? parts.join(' · ') : '-';
}

function tcFilterDetail(item) {
	var parts = [];
	if (item.protocol !== null && item.protocol !== undefined) parts.push(_('协议 %s').format(String(item.protocol)));
	if (item.program_name) parts.push(_('程序 %s').format(String(item.program_name)));
	if (item.program_id !== null && item.program_id !== undefined) parts.push(_('ID %d').format(tcInteger(item.program_id)));
	if (item.direct_action === true) parts.push('direct-action');
	if (item.in_hw === true) parts.push(_('硬件中'));
	else if (item.in_hw === false) parts.push(_('软件中'));
	if (item.action) parts.push(_('动作 %s').format(String(item.action)));
	return parts.length ? parts.join(' · ') : '-';
}

function tcObjectRows(value) {
	var rows = [], conflicts = Array.isArray(value.conflicts) ? value.conflicts : [];
	var conflictInterfaces = {};
	conflicts.forEach(function(item) { if (item && item.interface) conflictInterfaces[item.interface] = true; });
	function cell(label, value, className) {
		var text = value === null || value === undefined || value === '' ? '-' : String(value);
		var attrs = { 'data-label': label, 'title': text };
		if (className) attrs['class'] = className;
		return E('td', attrs, text);
	}
	function push(item, type, location, identity, detail) {
		item = item && typeof item === 'object' ? item : {};
		var owner = String(item.owner || 'unknown');
		var state = conflictInterfaces[item.interface] && owner !== 'lanspeed' ? 'warning' :
			owner === 'lanspeed' ? 'good' : 'neutral';
		rows.push(E('tr', { 'data-state': state }, [
			cell(_('接口'), item.interface, 'lanspeed-diagnostics-tc-interface'),
			cell(_('类型'), type, 'lanspeed-diagnostics-tc-type'),
			cell(_('位置'), location, 'lanspeed-diagnostics-tc-location'),
			cell(_('种类'), item.kind, 'lanspeed-diagnostics-tc-kind'),
			cell(_('标识'), identity, 'lanspeed-diagnostics-tc-identity'),
			cell(_('归属'), tcOwnerLabel(owner), 'lanspeed-diagnostics-tc-owner'),
			cell(_('统计'), tcCounters(item.counters), 'lanspeed-diagnostics-tc-counters'),
			cell(_('明细'), detail, 'lanspeed-diagnostics-tc-detail')
		]));
	}
	(Array.isArray(value.qdiscs) ? value.qdiscs : []).forEach(function(item) {
		push(item, 'qdisc', item.root ? _('root') : String(item.parent || '-'),
			String(item.handle || '-'), String(item.detail || '-'));
	});
	(Array.isArray(value.classes) ? value.classes : []).forEach(function(item) {
		push(item, 'class', String(item.parent || '-'), String(item.handle || '-'), String(item.detail || '-'));
	});
	(Array.isArray(value.filters) ? value.filters : []).forEach(function(item) {
		var location = tcDirectionLabel(item.direction) + ' · chain ' + tcInteger(item.chain);
		push(item, 'filter', location,
			'pref ' + tcInteger(item.pref) + ' / ' + String(item.handle || '-'), tcFilterDetail(item));
	});
	return rows;
}

function renderTcStatus(refs, viewState) {
	if (!refs.tcSummary) return null;
	var value = tcEvidence(viewState);
	var state = value && TC_STATE_LABELS[value.state] ? value.state : 'unavailable';
	var visual = state === 'clean' ? 'good' : state === 'conflict' || state === 'unavailable' ? 'bad' : 'warning';
	var noticeState = state === 'clean' ? 'ready' : state === 'conflict' || state === 'unavailable' ? 'error' : 'degraded';
	var label = TC_STATE_LABELS[state];
	refs.tcSummary.className = 'label lanspeed-diagnostics-tc-summary ' + stateClass(visual);
	refs.tcSummary.textContent = label;
	refs.tcNotice.setAttribute('data-state', noticeState);
	refs.tcNoticeTitle.textContent = label;
	refs.tcNoticeText.textContent = !value ? _('当前后端未提供全机 TC 快照；升级后重新检查。') :
		state === 'clean' ? _('已读取全机 TC，未发现外部对象占用 LAN Speed 保留位置。') :
		state === 'coexisting' ? _('检测到其他 TC 对象，但当前没有证据表明它们占用或抢先于 LAN Speed。') :
		state === 'conflict' ? _('下列对象可能阻止挂载、覆盖保留句柄或先于 LAN Speed 处理数据包。') :
		state === 'partial' ? _('至少一类 TC 对象未能完整读取；现有结果仍显示，不能据此断言没有冲突。') :
		_('无法读取本机 TC 状态，请检查 tc-full 与运行权限。');
	value = value || {};
	var qdiscCount = tcInteger(value.qdisc_count), classCount = tcInteger(value.class_count),
		filterCount = tcInteger(value.filter_count), conflictCount = Array.isArray(value.conflicts) ? value.conflicts.length : 0;
	setFact(refs, 'tcState', visual, label,
		conflictCount ? _('%d 个冲突或抢占风险').format(conflictCount) : _('未发现保留位置冲突'));
	setFact(refs, 'tcScan', value.scan_complete === true ? 'good' : visual === 'bad' ? 'bad' : 'warning',
		value.scan_complete === true ? _('完整') : _('不完整'),
		_('qdisc %s · class %s · filter %s').format(value.qdisc_scan ? _('成功') : _('失败'),
			value.class_scan ? _('成功') : _('失败'), value.filter_scan ? _('成功') : _('失败')));
	setFact(refs, 'tcObjects', value.scan_complete === true ? 'good' : 'warning',
		_('%d 个').format(qdiscCount + classCount + filterCount),
		_('qdisc %d · class %d · filter %d · %d 个接口').format(qdiscCount, classCount,
			filterCount, tcInteger(value.interface_count)));
	setFact(refs, 'tcOwners', conflictCount ? 'warning' : 'good',
		_('LAN Speed %d · 其他 %d').format(tcInteger(value.lanspeed_objects), tcInteger(value.foreign_objects)),
		value.objects_truncated || value.command_output_truncated ? _('输出达到安全上限') :
			tcInteger(value.parse_errors) ? _('%d 个对象解析失败').format(tcInteger(value.parse_errors)) : _('全部对象已归类'));

	var conflictRows = (Array.isArray(value.conflicts) ? value.conflicts : []).map(function(item) {
		item = item && typeof item === 'object' ? item : {};
		var critical = item.severity === 'critical';
		return E('tr', { 'data-state': critical ? 'bad' : 'warning' }, [
			E('td', { 'data-label': _('级别') }, critical ? _('严重') : _('警告')),
			E('td', { 'data-label': _('接口') }, String(item.interface || '-')),
			E('td', { 'data-label': _('位置') }, tcDirectionLabel(item.direction)),
			E('td', { 'data-label': _('对象') }, String(item.object || '-')),
			E('td', { 'data-label': _('归属') }, tcOwnerLabel(item.owner)),
			E('td', { 'data-label': _('判断') }, TC_CONFLICT_LABELS[item.id] || _('未知 TC 冲突'))
		]);
	});
	refs.tcConflictGroup.hidden = !conflictRows.length;
	refs.tcConflictGroup.setAttribute('aria-hidden', conflictRows.length ? 'false' : 'true');
	fmt.replaceChildren(refs.tcConflictBody, conflictRows);
	var objectRows = tcObjectRows(value);
	if (!objectRows.length) objectRows.push(E('tr', { 'data-state': 'empty' }, [
		E('td', { 'colspan': '8' }, state === 'unavailable' ? _('没有可显示的 TC 快照。') : _('本机没有 TC 对象。'))
	]));
	fmt.replaceChildren(refs.tcObjectsBody, objectRows);
	refs.tcObjectsCaption.textContent = _('本机全部 TC 对象：qdisc %d、class %d、filter %d').format(
		qdiscCount, classCount, filterCount);
	refs.tcDetailsMeta.textContent = _('%d 个对象 · %d 个接口').format(
		qdiscCount + classCount + filterCount, tcInteger(value.interface_count));
	return { state: state, conflicts: conflictCount, objects: qdiscCount + classCount + filterCount };
}

function renderInterfaces(refs, viewState) {
	var result = diagnosticsModel.interfaceStateWithRpc(viewState);
	var rows = (result.items || []).map(function(item) {
		item = item && typeof item === 'object' ? item : {};
		var state = interfaceRowState(item.status);
		var sampleAge = diagnosticsModel.sampleAge(viewState && viewState.interfaces &&
			viewState.interfaces.monotonic_ms, item.sample_ms);
		return E('tr', { 'data-state': state }, [
			E('td', { 'data-label': _('接口') }, String(item.name || '-')),
			E('td', { 'data-label': _('角色') }, interfaceRoleLabel(item.role)),
			E('td', { 'data-label': _('状态') }, interfaceStatusLabel(item.status)),
			E('td', { 'data-label': _('采样') }, sampleAge === null
				? _('未采样') : diagnosticsModel.formatDuration(sampleAge)),
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
	var nssPlatform = fmt.nssPlatform(viewState && viewState.status);
	var rows = (c.usable ? c.data.subsystems : []).filter(function(item) {
		return nssPlatform || [ 'nss', 'nss_control' ].indexOf(String(item && item.id || '')) === -1;
	}).map(function(item) {
		var state = subsystemRowState(item.state, item.code);
		return E('tr', { 'data-state': state }, [
			E('td', { 'data-label': _('组件') }, subsystemLabel(item.id, nssPlatform)),
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
	renderPlatformIntro(refs, viewState);
	var cardState = refreshStatusCards(refs, viewState.status, viewState.health, viewState.rpc,
		statusCollector.effectiveCollector(viewState.status, viewState.clients), viewState.diagnostics,
		viewState.clients);
	var pipeline = renderPipeline(refs, viewState);
	var control = renderControl(refs, viewState);
	var rpcState = renderRpcChecks(refs, viewState);
	var tcStatus = renderTcStatus(refs, viewState);
	var interfaces = renderInterfaces(refs, viewState);
	renderSubsystems(refs, viewState);
	var warnings = renderWarnings(refs, viewState.status, viewState.health, viewState.rpc, viewState.diagnostics);
	renderErrors(refs, viewState);
	if (refs.reportPreview) refs.reportPreview.textContent = diagnosticsModel.buildReport(viewState, lsVersion.FULL_VERSION);
	refs.checked.textContent = viewState.checkedAt !== null && viewState.checkedAt !== undefined ?
		(state === 'loading' ? _('上次检查 %s · 正在重新检查').format(new Date(viewState.checkedAt).toLocaleTimeString()) :
			_('检查于 %s').format(new Date(viewState.checkedAt).toLocaleTimeString())) : _('尚未完成检查');
	refs.root.setAttribute('aria-busy', state === 'loading' ? 'true' : 'false');
	return { state: state, cardState: cardState, pipeline: pipeline, control: control, rpc: rpcState, tc: tcStatus,
		interfaces: interfaces, warnings: warnings };
}

return baseclass.extend({
	refreshStatusCards: refreshStatusCards,
	renderRpcChecks: renderRpcChecks,
	renderTcStatus: renderTcStatus,
	renderWarnings: renderWarnings,
	refresh: function(viewState) { return refresh(viewState); }
});
