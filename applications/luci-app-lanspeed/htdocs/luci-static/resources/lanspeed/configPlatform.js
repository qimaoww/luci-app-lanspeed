'use strict';
'require baseclass';
'require lanspeed.configPlatformX86 as x86Platform';
'require lanspeed.configPlatformNss as nssPlatform';

var UNKNOWN = 'unknown';

function profile(status) {
	var platform = status && status.evidence && status.evidence.platform || {};
	if (platform.profile !== undefined && platform.profile !== null && platform.profile !== '') {
		if (platform.profile === x86Platform.PROFILE || platform.profile === nssPlatform.PROFILE)
			return platform.profile;
		return UNKNOWN;
	}
	if (nssPlatform.detect(platform)) return nssPlatform.PROFILE;
	if (x86Platform.detect(platform)) return x86Platform.PROFILE;
	return UNKNOWN;
}

function cloneValues(values) {
	var result = {};
	Object.keys(values || {}).forEach(function(name) {
		result[name] = Array.isArray(values[name]) ? values[name].slice() : values[name];
	});
	return result;
}

function normalizeValues(status, values) {
	var normalized = cloneValues(values);
	if (profile(status) === x86Platform.PROFILE) {
		normalized.access_edge_mode = 'off';
		normalized.internet_view_mode = 'off';
		delete normalized.nss_low_rate_window_ms;
		delete normalized.nss_low_rate_high_watermark_bps;
		delete normalized.nss_fifo_target_delay_ms;
		delete normalized.nss_fifo_min_queue_packets;
		delete normalized.rate_compensation_factor;
		if (!x86Platform.supportsRateMode(normalized.rate_collector_mode))
			normalized.rate_collector_mode = 'bpf';
	}
	return normalized;
}

function formPolicy(status) {
	var value = profile(status);
	if (value === nssPlatform.PROFILE) {
		return {
			showAccessEdge: true,
			showProxyConnections: false,
			rateHint: _('推荐“自动精准”：优先显示每个客户端接入口的总速率；NSS 与 CPU 检测用于流量分类，并在总速率不可用时降级显示。旧版 ECM+BPF 模式保持原有采集语义。'),
			internetViewHint: _('独立于客户端网速模式，仅显示 NSS FastN+FastS 观察到的互联网/路由流量；关闭时保持原有总速率或 ECM+BPF 语义。'),
			accessEdgeHint: _('“精准总速率”在自动模式中使用有线端口或无线客户端计数；“仅后台验证”只采集核对，不改变页面速率；“关闭”完全停用。'),
			connectionHint: _('自动优先使用 CT-Netlink；仅在旧系统不支持时使用 Procfs。此设置只影响连接详情，不参与客户端总速率融合。'),
			bpfHint: _('用于识别经过 CPU 的流量，并作为自动精准模式的降级来源；关闭后相关手动模式不可选。'),
			refreshHint: _('BPF 不限制采样周期；自动精准的接入窗口目标为 1 秒，互联网/路由 FastN+FastS 使用来源实际批次窗口（NSS 硬件通常约 2 秒）。')
		};
	}
	if (value === x86Platform.PROFILE) {
		return {
			showAccessEdge: false,
			showProxyConnections: true,
			rateHint: _('x86 使用原生 TC-BPF 客户端总速率。'),
			connectionHint: _('自动优先使用 CT-Netlink；仅在旧系统不支持时使用 Procfs。此设置只影响连接详情，不参与 TC-BPF 客户端总速率。'),
			bpfHint: _('x86 客户端总速率唯一来源；关闭后实时网速不可用。'),
			refreshHint: _('x86 TC-BPF 按配置周期采样。')
		};
	}
	return {
		showAccessEdge: false,
		showProxyConnections: false,
		rateHint: _('平台状态暂不可用；当前架构专用配置将保持不变。'),
		connectionHint: _('自动优先使用 CT-Netlink；仅在旧系统不支持时使用 Procfs。此设置只影响连接详情。'),
		bpfHint: _('当前平台状态不可用；保持现有 BPF 设置。'),
		refreshHint: _('按当前运行配置采样。')
	};
}

function runtimeInfo(status) {
	var evidence = status && status.evidence || {};
	var collector = evidence.collector || {};
	var effectiveRate = collector.primary_source || evidence.effective_collector || _('未知');
	var effectiveConnection = collector.effective_connection_collector || _('未知');
	var rateLabels = {
		bpf: _('仅 CPU 路径（BPF）'),
		nss_ecm_node: _('仅 NSS 加速（ECM）'),
		nss_ecm_bpf: _('NSS + CPU 路径（ECM+BPF）'),
		unsupported: _('不可用')
	};
	var connectionLabels = {
		conntrack_netlink: _('内核连接接口'),
		conntrack_procfs: _('兼容连接接口'),
		unsupported: _('不可用')
	};
	var rateLabel = rateLabels[String(effectiveRate)] || String(effectiveRate);
	var connectionLabel = connectionLabels[String(effectiveConnection)] || String(effectiveConnection);
	if (profile(status) === nssPlatform.PROFILE &&
		String(status && status.internet_view_mode || '') === 'routed')
		return _('当前运行：互联网/路由 FastN+FastS · 连接 %s').format(connectionLabel);
	if (profile(status) === nssPlatform.PROFILE &&
		String(status && status.rate_collector_mode || '') === 'auto' &&
		String(status && status.access_edge_mode || '') === 'active')
		return _('当前运行：总速率 精准接入点 · 分类 %s · 连接 %s').format(rateLabel, connectionLabel);
	return _('当前运行：网速 %s · 连接 %s').format(rateLabel, connectionLabel);
}

function applyPatchPolicy(status, originalRaw, patch) {
	var value = profile(status);
	var nssOnly = [ 'access_edge_mode', 'internet_view_mode', 'nss_low_rate_window_ms',
		'nss_low_rate_high_watermark_bps', 'nss_fifo_target_delay_ms',
		'nss_fifo_min_queue_packets', 'rate_compensation_factor' ];
	var x86Only = [ 'enable_proxy_connections', 'mihomo_controller_port',
		'mihomo_controller_secret' ];
	if (value !== nssPlatform.PROFILE)
		nssOnly.forEach(function(name) { delete patch.set[name]; });
	if (value === x86Platform.PROFILE &&
		(originalRaw || {}).access_edge_mode !== undefined &&
		patch.unset.indexOf('access_edge_mode') === -1)
		patch.unset.push('access_edge_mode');
	if (value === x86Platform.PROFILE &&
		(originalRaw || {}).internet_view_mode !== undefined &&
		patch.unset.indexOf('internet_view_mode') === -1)
		patch.unset.push('internet_view_mode');
	if (value === x86Platform.PROFILE)
		nssOnly.slice(2).forEach(function(name) {
			if ((originalRaw || {})[name] !== undefined && patch.unset.indexOf(name) === -1)
				patch.unset.push(name);
		});
	if (value !== x86Platform.PROFILE) {
		x86Only.forEach(function(name) { delete patch.set[name]; });
		patch.unset = patch.unset.filter(function(name) { return x86Only.indexOf(name) === -1; });
	}
	return patch;
}

return baseclass.extend({
	UNKNOWN: UNKNOWN,
	profile: profile,
	isX86: function(status) { return profile(status) === x86Platform.PROFILE; },
	isNss: function(status) { return profile(status) === nssPlatform.PROFILE; },
	supportsRateMode: function(status, mode) {
		var value = profile(status);
		if (value === x86Platform.PROFILE) return x86Platform.supportsRateMode(mode);
		if (value === nssPlatform.PROFILE) return nssPlatform.supportsRateMode(mode);
		return mode === 'auto' || mode === 'bpf';
	},
	autoLabel: function(status, defaultLabel) {
		var value = profile(status);
		if (value === x86Platform.PROFILE) return x86Platform.autoLabel(defaultLabel);
		if (value === nssPlatform.PROFILE) return nssPlatform.autoLabel(defaultLabel);
		return _('自动');
	},
	normalizeValues: normalizeValues,
	formPolicy: formPolicy,
	runtimeInfo: runtimeInfo,
	applyPatchPolicy: applyPatchPolicy
});
