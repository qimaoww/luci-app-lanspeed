'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.vocab as vocab';
'require lanspeed.version as lsVersion';
'require lanspeed.statusCollector as statusCollector';
'require lanspeed.diagnosticsModel as diagnosticsModel';
'require lanspeed.clientControl as clientControl';

function stateClass(state) {
	return state === 'good' || state === 'ready' ? 'label-success' :
		state === 'warning' || state === 'degraded' || state === 'partial' ? 'label-warning' :
		state === 'bad' || state === 'error' || state === 'invalid' ? 'label-danger' : '';
}

function phaseLabel(phase) {
	return ({
		loading: _('检查中'), success: _('成功'), empty: _('无数据'), stale: _('已过期'),
		degraded: _('降级'), error: _('失败'), invalid: _('契约无效'),
		fresh: _('新鲜'), healthy: _('正常'), unavailable: _('不可用'), disabled: _('未启用')
	})[phase] || _('未检查');
}


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
		if (text && text !== _('控制不可用，请查看诊断信息。') && !String(text).startsWith(_('控制不可用：'))) return text;
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

function contract(viewState) {
	return diagnosticsModel.diagnosticsContractState(viewState);
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

function interfaceRoleLabel(role) {
	return ({ lan: _('LAN'), observe: _('观察'), wan: _('WAN'), excluded: _('排除'), unknown: _('未知') })
		[String(role || 'unknown')] || _('未知');
}

function interfaceStatusLabel(status) {
	return ({ available: _('可用'), active: _('采集中'), pending: _('等待采样'), missing: _('缺失'),
		unsupported: _('不支持'), excluded: _('已排除') })[String(status || 'unknown')] || _('未知');
}

function rateText(item) {
	if (!item || (item.rx_bps === undefined && item.tx_bps === undefined)) return '-';
	function direction(value) {
		return typeof value === 'number' && isFinite(value) && value >= 0
			? fmt.formatRate(value, 'bit') : _('未知');
	}
	return _('↓ %s · ↑ %s').format(direction(item.rx_bps), direction(item.tx_bps));
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
	var hasSnapshot = !!value;
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
	if (!hasSnapshot) {
		setFact(refs, 'tcState', 'bad', _('未知'), _('未取得 TC 快照'));
		setFact(refs, 'tcObjects', 'bad', _('未知'), _('无法确认对象数量'));
		setFact(refs, 'tcOwners', 'bad', _('未知'), _('无法确认对象归属'));
	}

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

function setFact(refs, key, state, value, meta) {
	if (!refs[key + 'Fact']) return;
	refs[key + 'Fact'].setAttribute('data-state', state || 'neutral');
	refs[key + 'Value'].textContent = value || '-';
	refs[key + 'Meta'].textContent = meta || '';
}

function rpcUsable(viewState, key) {
	var state = diagnosticsModel.rpcState(viewState, key);
	return state.ok || state.retained;
}

function rpcFailures(viewState) {
	return diagnosticsModel.RPC_KEYS.filter(function(key) {
		var result = viewState.rpc && viewState.rpc[key];
		return result && result.phase !== 'loading' && result.ok !== true;
	});
}

function rpcErrorText(result) {
	var error = result && result.error || {};
	var prefix = ({ timeout: _('请求超时'), contract: _('数据格式无效'), missing: _('未返回结果'),
		client: _('页面处理失败'), transport: _('请求失败') })[error.kind] || _('请求失败');
	return prefix + (error.message ? '：' + error.message : '');
}

function renderErrors(refs, viewState) {
	var errors = rpcFailures(viewState);
	refs.errorDetails.hidden = !errors.length;
	refs.errorDetails.setAttribute('aria-hidden', errors.length ? 'false' : 'true');
	if (refs.errorSummary) refs.errorSummary.textContent = _('%d 项数据请求失败').format(errors.length);
	fmt.replaceChildren(refs.errorList, errors.map(function(key) {
		var result = viewState.rpc[key];
		return E('li', { 'data-state': result.retained ? 'warning' : 'bad' }, [
			E('strong', {}, diagnosticsModel.RPC_LABELS[key] + '：'),
			E('span', {}, rpcErrorText(result)),
			result.retained ? E('small', {}, _('；暂时显示上次结果')) : ''
		]);
	}));
}

function refreshStatusCards(refs, status, health, rpcData, collector, diagnostics, clientsData, current) {
	var viewState = current || { status: status || {}, health: health || {}, clients: clientsData || {},
		rpc: rpcData || {}, diagnostics: diagnostics || {} };
	var c = diagnosticsModel.diagnosticsContractState(viewState);
	var runtime = diagnosticsModel.mergeRuntime(status, health, rpcData, diagnostics);
	var versions = diagnosticsModel.versionStateWithRpc(viewState,
		status && status.version || health && health.version || runtime.version, lsVersion.FULL_VERSION);
	var connections = diagnosticsModel.connectionStateWithRpc(viewState);
	var freshness = diagnosticsModel.freshnessState(viewState, viewState.progress);
	var service = c.usable ? c.data.service : null;
	var loading = diagnosticsModel.rpcState(viewState, 'diagnostics').state === 'loading';
	var serviceState = service ? (!service.ubus_connected ? 'bad' :
		(service.state === 'running' && !c.retained ? 'good' : 'warning')) : loading ? 'neutral' : 'bad';
	setFact(refs, 'service', serviceState, service ?
		(!service.ubus_connected ? _('连接中断') : service.state === 'running' ? _('运行中') :
			service.state === 'starting' ? _('启动中') : _('运行异常')) : loading ? _('检查中') : _('未确认'),
		c.retained ? _('暂时显示上次结果') : '');
	setFact(refs, 'collection', freshness.state, loading ? _('检查中') :
		freshness.state === 'good' ? _('正常') : freshness.state === 'bad' ? _('暂无数据') :
		c.usable && c.data.collection.state === 'stale' ? _('数据过期') :
		c.retained || c.usable && c.data.collection.retained ? _('沿用旧数据') : _('采集降级'),
		freshness.oldestAgeMs !== null && freshness.oldestAgeMs !== undefined ?
			_('%s 前更新').format(diagnosticsModel.formatDuration(freshness.oldestAgeMs)) : '');
	setFact(refs, 'connections', connections.state, connections.rpc === 'loading' ? _('检查中') :
		connections.state === 'good' ? _('正常') : connections.state === 'bad' ? _('不可用') : _('需关注'),
		connections.state === 'good' ? '' : connections.rpc === 'retained' ? _('暂时显示上次结果') :
		connections.parseErrors ? _('部分连接记录解析失败') : connections.reasonCode ? codeText(connections.reasonCode) :
		connections.rpc === 'empty' ? _('暂无客户端数据') : '');
	setFact(refs, 'version', versions.state, versions.state === 'good' ? lsVersion.FULL_VERSION : versions.badge,
		versions.state === 'good' ? '' : versions.value);
	return { states: [ serviceState, freshness.state, connections.state, versions.state ],
		version: versions, connections: connections, freshness: freshness, service: service, collector: collector };
}

var SUBSYSTEM_LABELS = {
	bpf: _('实时采集'), tc: _('流量采集挂载'), bpf_map: _('客户端映射表'), conntrack: _('连接详情'),
	nss: _('NSS 加速识别'), nss_control: _('客户端控制'), identity: _('客户端识别'), ubus: _('数据服务')
};

/* Only known informational conditions are omitted. Unknown warnings and any
 * explicitly critical alert remain visible, including new backend codes. */
var INFORMATION_ONLY = {
	dae_detected: true, openclash_detected: true, fullcone_detected: true,
	proxy_stack: true, existing_qos: true, existing_tc_filters_detected: true,
	nlbwmon_counter_conflict: true,
	interface_exclude_compatibility_only: true, conntrack_connection_only: true,
	conntrack_routed_nat_only: true, conntrack_not_sampled: true,
	nss_ecm_node_active: true, nss_ecm_node_ecm_flows_only: true,
	nss_ecm_bpf_active: true, nss_ecm_bpf_disjoint_ownership: true, nss_bpf_slow_path_only: true,
	bpf_not_selected: true, tc_bpf_not_selected: true, nss_not_present: true,
	nss_control_not_configured: true, nss_control_no_active_client: true, warmup: true, pending: true
};
var NEUTRAL_DISABLED = {
	bpf_disabled: true, bpf_not_selected: true, tc_bpf_not_selected: true,
	nss_not_present: true, nss_control_not_configured: true, nss_control_no_active_client: true
};
var ISSUE_ALIASES = {
	tc_filter_conflict: 'tc_conflict', dae_tc_preempts_bpf_ingress: 'tc_conflict',
	bpf_object_missing: 'object_missing', bpf_optional_package_missing: 'package_missing',
	tc_missing: 'tc_unavailable', tc_clsact_unsupported: 'tc_unsupported',
	nf_conntrack_acct_disabled: 'conntrack_acct_disabled', conntrack_unavailable: 'conntrack_read_failed',
	lan_edge_missing: 'no_collect_interface', runtime_not_ready: 'bpf_runtime_not_ready'
};

function issueId(value) {
	var id = diagnosticsModel.canonicalWarningId(value);
	return ISSUE_ALIASES[id] || id;
}

function codeText(code) {
	if (vocab.hasWarning(code)) return vocab.warningText(code);
	var text = clientControl.reasonText(code);
	return text && text !== _('控制不可用，请查看诊断信息。') && !String(text).startsWith(_('控制不可用：')) ? text :
		_('诊断代码：%s').format(String(code || _('未知')));
}

function collectIssues(viewState, cards) {
	var groups = diagnosticsModel.warningGroups(viewState.status, viewState.health, viewState.rpc, viewState.diagnostics);
	var items = [], seen = Object.create(null), seenText = Object.create(null);
	function add(id, severity, text) {
		id = issueId(id);
		severity = severity === 'critical' ? 'critical' : 'warning';
		text = text || codeText(id);
		var previous = seen[id] || seenText[text];
		if (previous) {
			if (severity === 'critical') previous.severity = severity;
			seen[id] = previous;
			return;
		}
		var item = { id: id, severity: severity, text: text };
		seen[id] = seenText[text] = item;
		items.push(item);
	}
	(groups.important || []).forEach(function(item) {
		if (item.source === 'rpc') return;
		var id = issueId(item.id);
		if (item.severity !== 'critical' && INFORMATION_ONLY[id]) return;
		/* Probe detail is retained in the copied report; one row per failure kind
		 * is enough here, without dropping a failed scan or unknown probe. */
		if (item.source === 'probe') {
			var raw = item.raw || {};
			id = /^tc full (qdisc|class|filter) dump$/.test(String(raw.source || '')) ? 'tc_scan_failed' :
				'probe:' + String(raw.kind || 'unknown') + ':' + String(raw.reason || 'unknown');
		}
		var text = item.text;
		if (!vocab.hasWarning(item.id) && (!text || /未分类.*告警/.test(text))) text = codeText(item.id);
		add(id, item.severity, text);
	});
	var c = diagnosticsModel.diagnosticsContractState(viewState);
	var nss = fmt.nssPlatform(viewState.status);
	(c.usable ? c.data.subsystems : []).forEach(function(item) {
		if (item.state === 'healthy' || item.state === 'disabled' && NEUTRAL_DISABLED[item.code]) return;
		if (!nss && (item.id === 'nss' || item.id === 'nss_control')) return;
		if (item.state !== 'unavailable' && INFORMATION_ONLY[issueId(item.code)]) return;
		add(item.code || 'subsystem:' + item.id, item.state === 'unavailable' || item.code === 'no_collect_interface'
			? 'critical' : 'warning', (SUBSYSTEM_LABELS[item.id] || _('组件')) + '：' +
			(item.code ? codeText(item.code) : _('运行异常')));
	});
	if (c.usable && cards) {
		if (cards.service && (!cards.service.ubus_connected || cards.service.state === 'degraded'))
			add('service_unavailable', !cards.service.ubus_connected ? 'critical' : 'warning',
				!cards.service.ubus_connected ? _('服务连接中断，请尝试重启服务。') : _('服务运行异常，请检查下方故障。'));
		if (cards.freshness.state !== 'good' &&
			(c.data.collection.state !== 'fresh' || c.data.collection.retained))
			add(c.data.collection.state === 'unavailable' ? 'collection_unavailable' :
				c.data.collection.state === 'degraded' ? 'collection_degraded' : 'collection_stale',
				cards.freshness.state === 'bad' ? 'critical' : 'warning', cards.freshness.description);
	}
	if (cards && rpcUsable(viewState, 'status') && cards.version.badge === _('不一致'))
		add('version_mismatch', 'warning', cards.version.description);
	if (cards && rpcUsable(viewState, 'clients') && cards.connections.state !== 'good' &&
		cards.connections.rpc !== 'empty' && cards.connections.rpc !== 'retained' &&
		(cards.connections.state === 'bad' || !INFORMATION_ONLY[issueId(cards.connections.reasonCode)]))
		add(cards.connections.reasonCode || 'connection_incomplete', cards.connections.state === 'bad' ? 'critical' : 'warning',
			cards.connections.reasonCode ? codeText(cards.connections.reasonCode) :
			cards.connections.parseErrors ? _('部分连接记录解析失败，连接详情可能不完整。') : _('连接详情尚未完整获取。'));
	if (nss && diagnosticsModel.rpcState(viewState, 'status').ok && diagnosticsModel.rpcState(viewState, 'clients').ok) {
		var rate = diagnosticsModel.rateOwnerStateWithRpc(viewState), facts = rate.facts;
		if (rate.state === 'bad' || rate.state === 'warning')
			add('rate_source', rate.state === 'bad' ? 'critical' : 'warning',
				facts.unavailableDirections ? _('%d 个流量方向缺少速率数据，客户端总速率不完整。').format(facts.unavailableDirections) :
				facts.staleDirections ? _('%d 个流量方向的速率数据已过期。').format(facts.staleDirections) :
				facts.fallbackDirections ? _('部分客户端速率使用备用数据源，可能无法覆盖全部流量。') :
				_('客户端总速率：%s').format(rate.badge));
		var edge = diagnosticsModel.accessEdgeStateWithRpc(viewState);
		if (edge.owner && (edge.state === 'bad' || edge.state === 'warning') &&
			(rate.state === 'good' || edge.state === 'bad' && rate.state !== 'bad'))
			add(edge.topologyComplete ? 'access_edge_incomplete' : 'lan_topology_probe_error',
				edge.state === 'bad' ? 'critical' : 'warning',
				_('客户端接入信息不完整，部分设备的流量归属尚未确认。'));
		var control = diagnosticsModel.nssControlStateWithRpc(viewState);
		var hasControlSummary = !!(viewState.clients.evidence && viewState.clients.evidence.nss_control);
		var configured = 0, errors = 0, overflows = 0, pending = 0;
		(viewState.clients.clients || []).forEach(function(item) {
			var value = item.control;
			if (!value) return;
			if (value.configured) configured++;
			if (value.state === 'error' || value.configured && value.state === 'unsupported') errors++;
			if (value.queue_overflow) overflows++;
			if (value.configured && value.state === 'pending_new_connections') pending++;
		});
		configured = Math.max(configured, control.configuredClients);
		errors = Math.max(errors, control.errorClients);
		overflows = Math.max(overflows, control.queueOverflowClients);
		var controlFailed = errors || hasControlSummary && control.state === 'bad';
		if (controlFailed || overflows || pending ||
			(configured || control.activeClients) && (control.state === 'bad' || control.state === 'warning'))
			add(controlFailed || overflows ? 'nss_control_executor_failed' :
				!hasControlSummary ? 'nss_control_diagnostics_unavailable' : 'nss_control_verification_pending',
				controlFailed || overflows ? 'critical' : 'warning',
				overflows ? _('%d 个客户端的限速队列发生丢包。').format(overflows) :
				controlFailed ? _('客户端限速或禁网执行失败，请检查控制规则。') :
				!hasControlSummary ? _('客户端控制状态未完整获取，暂时无法确认是否生效。') :
				_('客户端控制尚未验证生效。'));
		var classification = diagnosticsModel.classificationStateWithRpc(viewState);
		if (classification.maps.loss || classification.counts.map_loss)
			add('map_read_failed', 'critical', _('流量分类映射读取不完整，NSS/CPU 分类不可用。'));
		else if (classification.maps.pressure)
			add('map_full', 'warning', _('流量分类映射容量不足，部分客户端分类可能缺失。'));
	}
	var interfaces = visibleInterfaceState(viewState);
	if (rpcUsable(viewState, 'interfaces') && interfaces.state !== 'good' &&
		(interfaces.rpc !== 'retained' || interfaces.visibleState === 'bad'))
		add('interfaces_unavailable', interfaces.state === 'bad' ? 'critical' : 'warning', interfaces.description);
	var tc = rpcUsable(viewState, 'health') && viewState.health && viewState.health.evidence && viewState.health.evidence.tc_status;
	if (tc && typeof tc === 'object') {
		var conflicts = Array.isArray(tc.conflicts) ? tc.conflicts : [];
		if (tc.state === 'conflict' || conflicts.length) {
			var interfaces = [];
			conflicts.forEach(function(item) {
				if (item.interface && interfaces.indexOf(item.interface) === -1) interfaces.push(item.interface);
			});
			add('tc_conflict', conflicts.some(function(item) { return item.severity === 'critical'; }) ? 'critical' : 'warning',
				interfaces.length ? _('接口 %s 存在流量规则冲突，可能影响采集或限速。').format(interfaces.join('、')) :
				_('检测到流量规则冲突，可能影响采集或限速。'));
		}
		if (tc.state === 'partial' || tc.state === 'unavailable' || tc.scan_complete === false)
			add('tc_scan_failed', tc.state === 'unavailable' ? 'critical' : 'warning',
				_('流量规则检查未完成，暂时无法确认是否存在冲突。'));
	}
	return items.sort(function(a, b) { return (b.severity === 'critical') - (a.severity === 'critical'); });
}

function alertNode(item) {
	return E('li', {
		'class': 'lanspeed-diagnostic-alert', 'data-severity': item.severity
	}, [
		E('span', { 'class': 'lanspeed-diagnostic-alert-severity', 'aria-hidden': 'true' }, '!'),
		E('span', { 'class': 'lanspeed-diagnostic-alert-text' }, item.text)
	]);
}

function renderWarnings(refs, status, health, rpcData, diagnostics, current, cards) {
	var viewState = current || { status: status, health: health, rpc: rpcData, diagnostics: diagnostics };
	var items = collectIssues(viewState, cards);
	var criticalCount = items.filter(function(item) { return item.severity === 'critical'; }).length;
	var failures = rpcFailures(viewState);
	var criticalRpc = failures.some(function(key) { return !viewState.rpc[key].retained; });
	var loading = diagnosticsModel.pageState(viewState) === 'loading';
	fmt.replaceChildren(refs.importantWarnings, items.length ? items.map(alertNode) : [
		E('li', { 'class': 'lanspeed-diagnostic-alert-empty' },
			loading ? _('正在检查…') : failures.length ? _('部分数据未能获取，请查看上方请求失败详情。') : _('未发现需要处理的问题。'))
	]);
	if (refs.environmentWarnings) {
		var environment = diagnosticsModel.warningGroups(status, health, rpcData, diagnostics).environment || [];
		fmt.replaceChildren(refs.environmentWarnings, environment.length ? environment.map(alertNode) : [
			E('li', { 'class': 'lanspeed-diagnostic-alert-empty' }, _('没有额外提示。'))
		]);
	}
	refs.alertSummary.textContent = items.length ? _('%d 项').format(items.length) :
		loading ? _('检查中') : failures.length ? _('数据请求失败') : _('无异常');
	return { state: criticalCount || criticalRpc ? 'bad' : items.length || failures.length ? 'warning' : 'good',
		items: items, important: items, importantCount: items.length, criticalCount: criticalCount,
		warningCount: items.length - criticalCount, rpcCount: failures.length };
}

function interfaceRowState(item) {
	return item.status === 'available' || item.status === 'active' ? 'good' :
		item.status === 'missing' || item.status === 'unsupported' ? 'bad' : 'warning';
}

function visibleInterfaceState(viewState) {
	var result = diagnosticsModel.interfaceStateWithRpc(viewState);
	result.visibleItems = (result.items || []).filter(function(item) {
		return item && item.role !== 'excluded' && item.status !== 'excluded';
	});
	var bad = 0, pending = 0, unknown = 0;
	result.visibleItems.forEach(function(item) {
		if (interfaceRowState(item) === 'bad') bad++;
		else if (item.status === 'pending') pending++;
		else if (interfaceRowState(item) !== 'good') unknown++;
	});
	result.visibleState = bad ? 'bad' : pending || unknown ? 'warning' : 'good';
	if (result.visibleState !== 'good') {
		var previous = result.state;
		result.state = diagnosticsModel.worseState(previous, result.visibleState);
		var details = [];
		if (bad) details.push(_('%d 个接口缺失或不受支持').format(bad));
		if (pending) details.push(_('%d 个接口等待采样').format(pending));
		if (unknown) details.push(_('%d 个接口状态未知').format(unknown));
		var description = details.join('；') + '。';
		result.description = previous === 'good' ? description : result.description + ' ' + description;
		if (previous !== result.state || previous === 'good')
			result.badge = bad ? _('%d 个异常').format(bad) : _('%d 个待确认').format(pending + unknown);
	}
	return result;
}

function renderInterfaces(refs, viewState) {
	var result = visibleInterfaceState(viewState);
	var rows = (result.visibleItems || []).map(function(item) {
		item = item && typeof item === 'object' ? item : {};
		var state = interfaceRowState(item);
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

function renderPageState(refs, viewState, cards, interfaces, warnings) {
	var state = diagnosticsModel.pageState(viewState);
	if (state !== 'loading' && state !== 'error' && state !== 'partial') {
		if (warnings.state === 'bad' || cards.states.indexOf('bad') !== -1 || interfaces.state === 'bad') state = 'error';
		else if (warnings.state === 'warning' || cards.states.indexOf('warning') !== -1 || interfaces.state === 'warning')
			state = state === 'empty' ? 'empty' : 'degraded';
	}
	var messages = {
		loading: [ _('检查中'), _('正在获取运行状态…') ],
		ready: [ _('运行正常'), '' ],
		degraded: [ _('需要关注'), _('请查看下方问题和接口状态。') ],
		partial: [ _('部分检查失败'), _('部分数据未能获取，请查看请求失败详情后重新检查。') ],
		empty: [ _('暂无数据'), _('请检查服务与采集接口配置。') ],
		error: [ _('发现异常'), _('请查看故障信息，处理后重新检查。') ]
	};
	var message = messages[state] || messages.loading;
	refs.summary.className = 'label lanspeed-diagnostics-summary ' + stateClass(state);
	refs.summary.textContent = message[0];
	refs.pageNotice.setAttribute('data-state', state);
	var showNotice = state !== 'ready' && state !== 'degraded';
	refs.pageNotice.setAttribute('aria-hidden', showNotice ? 'false' : 'true');
	refs.pageNotice.style.display = showNotice ? '' : 'none';
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
	if (refs.btnCopy) refs.btnCopy.disabled = state === 'loading' || viewState.copyPending === true || viewState.restartPending === true;
	return state;
}

function refresh(viewState) {
	var refs = viewState && viewState.refs;
	if (!refs) return null;
	var cards = refreshStatusCards(refs, viewState.status, viewState.health, viewState.rpc,
		statusCollector.effectiveCollector(viewState.status, viewState.clients), viewState.diagnostics,
		viewState.clients, viewState);
	var pipeline = renderPipeline(refs, viewState);
	var control = renderControl(refs, viewState);
	var rpcState = renderRpcChecks(refs, viewState);
	var tc = renderTcStatus(refs, viewState);
	renderSubsystems(refs, viewState);
	if (refs.reportPreview) refs.reportPreview.textContent = diagnosticsModel.buildReport(viewState, lsVersion.FULL_VERSION);
	var interfaces = renderInterfaces(refs, viewState);
	var warnings = renderWarnings(refs, viewState.status, viewState.health, viewState.rpc,
		viewState.diagnostics, viewState, cards);
	renderErrors(refs, viewState);
	var state = renderPageState(refs, viewState, cards, interfaces, warnings);
	refs.checked.textContent = viewState.checkedAt !== null && viewState.checkedAt !== undefined ?
		_('检查于 %s').format(new Date(viewState.checkedAt).toLocaleTimeString()) : _('尚未完成检查');
	return { state: state, cardState: cards, pipeline: pipeline, control: control, rpc: rpcState, tc: tc, interfaces: interfaces, warnings: warnings };
}

return baseclass.extend({
	refreshStatusCards: refreshStatusCards,
	renderRpcChecks: renderRpcChecks,
	renderTcStatus: renderTcStatus,
	renderWarnings: renderWarnings,
	refresh: function(viewState) { return refresh(viewState); }
});
