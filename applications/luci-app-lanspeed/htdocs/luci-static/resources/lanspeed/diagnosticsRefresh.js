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
	return text && !String(text).startsWith(_('控制不可用：')) ? text :
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
	var items = result.visibleItems;
	var rows = items.map(function(item) {
		return E('tr', { 'data-state': interfaceRowState(item) }, [
			E('td', { 'data-label': _('接口') }, String(item.name || '-')),
			E('td', { 'data-label': _('角色') },
				({ lan: _('LAN'), observe: _('观察'), wan: _('WAN') })[item.role] || _('未知')),
			E('td', { 'data-label': _('状态') }, ({ available: _('可用'), active: _('采集中'),
				pending: _('等待采样'), missing: _('缺失'), unsupported: _('不支持') })[item.status] || _('未知'))
		]);
	});
	if (!rows.length) rows.push(E('tr', { 'data-state': 'empty' }, [
		E('td', { 'colspan': '3' }, result.rpc === 'loading' ? _('正在检查接口…') :
			result.rpc === 'failed' || result.rpc === 'invalid' ? _('接口数据获取失败。') : _('暂无可采集接口。'))
	]));
	fmt.replaceChildren(refs.interfacesBody, rows);
	refs.healthSummary.textContent = result.state === 'good' ? _('%d 个接口').format(items.length) : result.badge;
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
	if (refs.btnCopy) refs.btnCopy.disabled = state === 'loading' || viewState.copyPending === true || viewState.restartPending === true;
	return state;
}

function refresh(viewState) {
	var refs = viewState && viewState.refs;
	if (!refs) return null;
	var cards = refreshStatusCards(refs, viewState.status, viewState.health, viewState.rpc,
		statusCollector.effectiveCollector(viewState.status, viewState.clients), viewState.diagnostics,
		viewState.clients, viewState);
	var interfaces = renderInterfaces(refs, viewState);
	var warnings = renderWarnings(refs, viewState.status, viewState.health, viewState.rpc,
		viewState.diagnostics, viewState, cards);
	renderErrors(refs, viewState);
	var state = renderPageState(refs, viewState, cards, interfaces, warnings);
	refs.checked.textContent = viewState.checkedAt !== null && viewState.checkedAt !== undefined ?
		_('检查于 %s').format(new Date(viewState.checkedAt).toLocaleTimeString()) : _('尚未完成检查');
	return { state: state, cardState: cards, interfaces: interfaces, warnings: warnings };
}

return baseclass.extend({
	refreshStatusCards: refreshStatusCards,
	renderWarnings: renderWarnings,
	refresh: function(viewState) { return refresh(viewState); }
});
