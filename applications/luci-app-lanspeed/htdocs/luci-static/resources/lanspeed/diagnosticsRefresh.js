'use strict';
'require baseclass';
'require lanspeed.vocab as vocab';
'require lanspeed.format as fmt';
'require lanspeed.version as lsVersion';
'require lanspeed.statusCollector as statusCollector';

function setDiagnosticCard(refs, key, state, badge, value, description, meta) {
	refs[key + 'Card'].setAttribute('data-state', state);
	refs[key + 'Badge'].className = 'label lanspeed-diagnostic-badge ' +
		(state === 'good' ? 'label-success' :
		 state === 'warning' ? 'label-warning' :
		 state === 'bad' ? 'label-danger' : '');
	refs[key + 'Badge'].textContent = badge;
	refs[key + 'Value'].textContent = value;
	refs[key + 'Description'].textContent = description;
	refs[key + 'Meta'].textContent = meta;
}

function refreshIntervalText(value) {
	value = Number(value);
	if (!isFinite(value) || value <= 0)
		return _('刷新间隔未知');
	if (value < 1000)
		return _('%d 毫秒更新').format(Math.round(value));
	return _('每 %s 秒更新').format(String(Math.round(value / 100) / 10));
}

function refreshStatusCards(refs, status, health, error, collector) {
	var runtime = health || status || {};
	var caps = runtime.capabilities || {};
	var backendState = 'good';
	var bpfState = 'good';
	var backendMode = String(runtime.mode || status.mode || '');
	var confidence = String(runtime.confidence || status.confidence || '').toLowerCase();
	var attention = 0;

	setDiagnosticCard(
		refs, 'plugin', 'good', _('正常'), _('界面已加载'),
		_('独立诊断分页与前端模块运行正常。'),
		'luci-app-lanspeed ' + lsVersion.FULL_VERSION
	);

	if (error) {
		backendState = 'bad';
		setDiagnosticCard(
			refs, 'backend', backendState, _('异常'), _('无法连接后端'),
			_('未能读取 lanspeedd 状态，请确认服务正在运行。'),
			_('状态请求失败')
		);
	} else if (!status.version) {
		backendState = 'bad';
		setDiagnosticCard(
			refs, 'backend', backendState, _('异常'), _('后端未响应'),
			_('页面已加载，但后端没有返回有效的运行信息。'),
			'lanspeedd -'
		);
	} else if (collector === 'unsupported' || backendMode === 'Unsupported') {
		backendState = 'bad';
		setDiagnosticCard(
			refs, 'backend', backendState, _('不可用'), _('实时采集不可用'),
			_('后端正在运行，但当前没有可用的实时速率数据源。'),
			'lanspeedd ' + status.version + ' · ' + refreshIntervalText(status.refresh_interval_ms)
		);
	} else if (backendMode === 'Degraded' || confidence === 'low') {
		backendState = 'warning';
		setDiagnosticCard(
			refs, 'backend', backendState, _('降级'), _('后端降级运行'),
			_('后端仍可响应，但部分实时数据可能不完整。'),
			'lanspeedd ' + status.version + ' · ' + refreshIntervalText(status.refresh_interval_ms)
		);
	} else {
		setDiagnosticCard(
			refs, 'backend', backendState, _('正常'), _('服务运行中'),
			_('后端正在持续提供客户端、接口和连接数据。'),
			'lanspeedd ' + status.version + ' · ' + refreshIntervalText(status.refresh_interval_ms)
		);
	}

	var hasBpfStatus = [ 'bpf', 'bpf_package', 'bpf_object', 'bpf_runtime_metrics' ].some(function(key) {
		return Object.prototype.hasOwnProperty.call(caps, key);
	});
	var packageOk = caps.bpf_package === true;
	var objectOk = caps.bpf_object === true;
	var runtimeOk = caps.bpf_runtime_metrics === true ||
		(collector === 'bpf' && caps.bpf === true && caps.live_metrics === true);
	var bpfAvailable = caps.bpf === true && packageOk && objectOk;

	if (!hasBpfStatus) {
		bpfState = 'warning';
		setDiagnosticCard(
			refs, 'bpf', bpfState, _('未知'), _('未上报 BPF 状态'),
			_('当前后端版本没有提供完整的 BPF 运行信息。'),
			_('建议更新后端组件')
		);
	} else if (runtimeOk && collector === 'bpf') {
		setDiagnosticCard(
			refs, 'bpf', bpfState, _('采集中'), _('BPF 正常运行'),
			_('正在按客户端统计实时上下行速率。'),
			_('软件包、对象文件与运行时均正常')
		);
	} else if (runtimeOk || bpfAvailable) {
		setDiagnosticCard(
			refs, 'bpf', bpfState, _('已就绪'), _('BPF 可以使用'),
			_('BPF 组件正常，当前实时速率由 %s 提供。').format(
				statusCollector.collectorLabel(collector)),
			_('当前数据源：%s').format(statusCollector.collectorLabel(collector))
		);
	} else {
		var missing = [];
		bpfState = 'bad';
		if (!packageOk) missing.push(_('BPF 软件包'));
		if (!objectOk) missing.push(_('BPF 对象文件'));
		if (caps.tc === false) missing.push('tc');
		if (caps.lan_edge === false) missing.push(_('LAN 采集接口'));
		setDiagnosticCard(
			refs, 'bpf', bpfState, _('不可用'), _('BPF 未能运行'),
			missing.length
				? _('缺少或未就绪：%s。').format(missing.join('、'))
				: _('BPF 组件已安装，但运行时没有提供实时指标。'),
			_('当前数据源：%s').format(statusCollector.collectorLabel(collector))
		);
	}

	if (backendState !== 'good') attention++;
	if (bpfState !== 'good') attention++;
	return {
		attention: attention,
		hasError: backendState === 'bad' || bpfState === 'bad'
	};
}

function renderWarnings(refs, runtime) {
	var warnings = vocab.importantWarnings(runtime.warnings, runtime);

	if (warnings.length) {
		refs.diagnosticAlertsTitle.textContent = _('重要告警');
		fmt.replaceChildren(refs.importantWarnings, warnings.map(function(w) {
			var dangerous = vocab.warningClass(w).indexOf('danger') !== -1;
			return E('li', {
				'class': 'lanspeed-diagnostic-alert',
				'data-level': dangerous ? 'danger' : 'warning'
			}, [
				E('span', { 'class': 'lanspeed-diagnostic-alert-icon', 'aria-hidden': 'true' }, '!'),
				E('span', { 'class': 'lanspeed-diagnostic-alert-text' }, vocab.warningText(w))
			]);
		}));
	} else {
		refs.diagnosticAlertsTitle.textContent = _('运行检查');
		fmt.replaceChildren(refs.importantWarnings, [E('li', {
			'class': 'lanspeed-diagnostic-alert-empty'
		}, [
			E('span', { 'class': 'lanspeed-diagnostic-alert-icon', 'aria-hidden': 'true' }, '✓'),
			E('span', {}, _('未发现影响实时测速的异常。'))
		])]);
	}

	return warnings;
}

function refresh(viewState) {
	var refs = viewState.refs;
	if (!refs) return;

	var status = viewState.status || {};
	var health = viewState.health || {};
	var runtime = Object.assign({}, status, health, {
		version: status.version || health.version,
		refresh_interval_ms: status.refresh_interval_ms || health.refresh_interval_ms
	});
	var collector = statusCollector.effectiveCollector(status, viewState.clients);
	var cardState = refreshStatusCards(refs, status, health, viewState.error, collector);
	var warnings = renderWarnings(refs, runtime);
	var summary = [];

	refs.errorBox.style.display = viewState.error ? '' : 'none';
	refs.errorPre.textContent = viewState.error
		? ((viewState.error.message || String(viewState.error)) || _('未知 RPC 失败'))
		: '';

	if (cardState.attention)
		summary.push(_('%d 项状态需关注').format(cardState.attention));
	if (warnings.length)
		summary.push(_('%d 条重要告警').format(warnings.length));

	refs.summary.className = 'label lanspeed-diagnostics-summary ' +
		(cardState.hasError ? 'label-danger' :
		 (cardState.attention || warnings.length) ? 'label-warning' : 'label-success');
	refs.summary.textContent = summary.length
		? summary.join(' · ')
		: _('全部正常');

	var meta = [ 'luci ' + lsVersion.FULL_VERSION ];
	if (status.version) meta.push(_('后端 ') + status.version);
	meta.push(_('数据源 ') + statusCollector.collectorLabel(collector));
	meta.push(_('检查于 ') + new Date().toLocaleTimeString());
	refs.meta.textContent = meta.join(' · ');
}

return baseclass.extend({
	refreshStatusCards: refreshStatusCards,
	renderWarnings: renderWarnings,
	refresh: function(viewState) {
		return refresh(viewState);
	}
});
