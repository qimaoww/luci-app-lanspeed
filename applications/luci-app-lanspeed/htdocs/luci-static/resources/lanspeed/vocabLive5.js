'use strict';
'require baseclass';

/*
 * LAN Speed vocabulary module.
 *
 * Owns warning labels and the small
 * class/text lookup functions that interpret status fields.  Pure data +
 * pure functions only — no DOM, no RPC, no persistent state.
 */

var WARNING_LABELS = {
	tc_filter_conflict: _('TC 挂载点被其它程序占用，BPF 无法安全启动；请检查该 LAN 接口上的 TC filter。'),
	hardware_flow_offload_unsupported: _('硬件流量卸载会绕过 BPF，客户端速率可能明显偏低；请关闭硬件卸载或改用受支持的数据源。'),
	nss_ecm_direct_parse_errors: _('NSS ECM 数据包含无法解析的记录，部分客户端速率可能缺失。'),
	nss_dae_bpf_fallback_may_be_inaccurate: _('NSS 与 dae/daed 同时运行，但 BPF 不可用；当前回退数据源可能导致实时速率不准确。'),
	dae_process_probe_failed: _('无法确认 dae/daed 的运行状态，后端的数据源选择可能暂时不准确。'),
	nssifb_collect_rejected: _('nssifb 是镜像接口，不能用于客户端采集；后端已忽略该配置，请改为“观察”。'),
	conntrack_connection_only: _('该客户端当前只有连接记录，没有新的速率样本；这不是异常。'),
	conntrack_acct_disabled: _('Conntrack 计数未启用，连接数与 NSS sync 数据不可用。'),
	nf_conntrack_acct_disabled: _('nf_conntrack_acct 未启用，连接数与 NSS sync 数据不可用。'),
	bpf_optional_package_missing: _('缺少必需的 BPF 软件包，客户端实时测速不可用。'),
	bpf_object_missing: _('缺少 BPF 对象文件，客户端实时测速不可用。'),
	bpf_runtime_loader_unavailable: _('BPF 组件已安装，但 TC 挂载或映射表读取失败，客户端实时测速未能启动。'),
	unsafe_attach: _('当前 TC 挂载点不安全，后端已停止 BPF 采集以避免影响网络。'),
	map_full: _('BPF 客户端表已满，部分客户端可能不会显示。'),
	map_read_failed: _('BPF 客户端表读取失败，当前速率数据可能不完整。'),
	client_limit_exceeded: _('客户端数量超过后端上限，部分客户端未显示。'),
	live_metrics_unavailable: _('没有可用的实时速率数据，客户端列表可能为空或处于降级状态。'),
	probe_error: _('部分运行环境探测失败，状态判断可能不完整。'),
	tc_missing: _('系统缺少 tc，BPF 客户端实时测速无法启动。'),
	conntrack_unavailable: _('Conntrack 当前不可用，连接数与 NSS sync 数据无法更新。'),
	lan_edge_missing: _('没有可采集的 LAN 接口，客户端实时测速无法启动。'),
	bpf_disabled: _('BPF 已在后端配置中关闭，客户端实时测速不会启动。')
};

var IMPORTANT_WARNINGS = {
	hardware_flow_offload_unsupported: true,
	tc_filter_conflict: true,
	nssifb_collect_rejected: true,
	nss_dae_bpf_fallback_may_be_inaccurate: true,
	nss_ecm_direct_parse_errors: true,
	dae_process_probe_failed: true,
	conntrack_acct_disabled: true,
	nf_conntrack_acct_disabled: true,
	conntrack_unavailable: true,
	bpf_optional_package_missing: true,
	bpf_object_missing: true,
	bpf_runtime_loader_unavailable: true,
	unsafe_attach: true,
	map_full: true,
	map_read_failed: true,
	client_limit_exceeded: true,
	live_metrics_unavailable: true,
	probe_error: true,
	tc_missing: true,
	lan_edge_missing: true,
	bpf_disabled: true
};

var CRITICAL_WARNINGS = {
	hardware_flow_offload_unsupported: true,
	tc_filter_conflict: true,
	nssifb_collect_rejected: true,
	nss_dae_bpf_fallback_may_be_inaccurate: true,
	unsafe_attach: true,
	tc_missing: true,
	lan_edge_missing: true,
	probe_error: true,
	dae_process_probe_failed: true,
	map_read_failed: true,
	live_metrics_unavailable: true,
	bpf_runtime_loader_unavailable: true,
	bpf_optional_package_missing: true,
	bpf_object_missing: true,
	conntrack_acct_disabled: true,
	nf_conntrack_acct_disabled: true,
	map_full: true,
	bpf_disabled: true
};

var WARNING_ALIASES = {
	nss_daed_nss_fallback_may_be_inaccurate: 'nss_dae_bpf_fallback_may_be_inaccurate'
};

function normalizeWarningId(warning) {
	return WARNING_ALIASES[warning] || warning;
}

function coreStatusHealthy(status) {
	var caps = status && status.capabilities || {};
	var evidence = status && status.evidence || {};
	var collector = evidence.effective_collector ||
		(evidence.collector && evidence.collector.primary_source);

	if (!status || status.mode !== 'Full' || collector === 'unsupported')
		return false;
	if (caps.live_metrics !== true)
		return false;
	if (collector === 'bpf' && caps.bpf_runtime_metrics !== true)
		return false;
	return true;
}

function isImportantWarning(warning, status) {
	warning = normalizeWarningId(warning);
	if (!IMPORTANT_WARNINGS[warning])
		return false;
	if (warning === 'probe_error' && coreStatusHealthy(status))
		return false;
	return true;
}

function importantWarnings(warnings, status) {
	var seen = {};
	return (Array.isArray(warnings) ? warnings : []).map(normalizeWarningId).filter(function(warning) {
		if (seen[warning] || !isImportantWarning(warning, status))
			return false;
		seen[warning] = true;
		return true;
	});
}

return baseclass.extend({
	CRITICAL_WARNINGS: CRITICAL_WARNINGS,
	normalizeWarningId: normalizeWarningId,
	isImportantWarning: isImportantWarning,
	importantWarnings: importantWarnings,

	warningText: function(w) {
		w = normalizeWarningId(w);
		return WARNING_LABELS[w] || String(w).replace(/_/g, ' ');
	},

	warningClass: function(w) {
		w = normalizeWarningId(w);
		if (CRITICAL_WARNINGS[w] || /hardware|unsafe|conflict|missing|error|failed|full/.test(w))
			return 'label label-danger';
		return 'label label-warning';
	}
});
