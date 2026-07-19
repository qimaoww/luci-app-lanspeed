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
	nss_ecm_direct_active: _('正在使用 NSS ECM 直接计数，并按 LAN 身份归属客户端流量。'),
	nss_ecm_sync_cadence: _('正在使用 NSS Conntrack 同步计数，刷新节奏可能低于 BPF。'),
	nss_prefers_conntrack_sync: _('配置选择 NSS 同步计数，因此未使用当前可用的 BPF 数据源。'),
	nss_direct_no_data: _('NSS ECM 直接计数当前没有返回可归属的客户端数据。'),
	skip_nss_ecm_direct_flow_without_lan_identity: _('部分 NSS ECM 流量缺少 LAN 身份，已跳过以避免错误归属。'),
	nss_dae_bpf_fallback_may_be_inaccurate: _('NSS 与 dae/daed 同时运行，但 BPF 不可用；当前回退数据源可能导致实时速率不准确。'),
	dae_runtime_prefers_bpf: _('检测到 dae/daed 正在运行，已优先使用 BPF 保持客户端流量归属。'),
	dae_process_probe_failed: _('无法确认 dae/daed 的运行状态，后端的数据源选择可能暂时不准确。'),
	nssifb_collect_rejected: _('nssifb 是镜像接口，不能用于客户端采集；后端已忽略该配置，请改为“观察”。'),
	conntrack_connection_only: _('该客户端当前只有连接记录，没有新的速率样本；这不是异常。'),
	conntrack_acct_disabled: _('Conntrack 计数未启用，连接数与 NSS sync 数据不可用。'),
	nf_conntrack_acct_disabled: _('nf_conntrack_acct 未启用，连接数与 NSS sync 数据不可用。'),
	bpf_optional_package_missing: _('缺少必需的 BPF 软件包，客户端实时测速不可用。'),
	bpf_object_missing: _('缺少 BPF 对象文件，客户端实时测速不可用。'),
	bpf_runtime_loader_unavailable: _('BPF 组件已安装，但 TC 挂载或映射表读取失败，客户端实时测速未能启动。'),
	bpf_unavailable: _('BPF 运行环境不可用，客户端实时速率采集无法启动。'),
	bpf_not_selected: _('当前未选择 BPF 实时速率采集路径，该组件不参与本次采集。'),
	no_collect_interface: _('没有 LAN 接口设为“采集”，客户端实时测速不会启动。'),
	package_missing: _('缺少 BPF 运行组件，客户端实时测速无法启动。'),
	object_missing: _('缺少 BPF 对象文件，客户端实时测速无法启动。'),
	object_load_failed: _('BPF 对象文件已安装，但内核加载失败。'),
	tc_unavailable: _('系统缺少可用的 TC，BPF 挂载无法启动。'),
	tc_unsupported: _('当前 TC 或内核不支持所需的 BPF clsact 挂载。'),
	tc_conflict: _('现有 TC 规则与 LAN Speed 的挂载标识冲突。'),
	tc_attach_failed: _('BPF 对象已加载，但 TC 入口或出口挂载未完成。'),
	tc_attach_not_ready: _('TC 挂载尚未就绪，BPF 实时采集可能正在启动或恢复。'),
	map_not_started: _('TC 挂载尚未完成，因此 BPF 客户端映射表未开始采集。'),
	bpf_runtime_not_ready: _('BPF 平台能力可用，但当前运行链路仍在启动或恢复。'),
	runtime_not_ready: _('BPF 平台能力可用，但当前运行链路仍在启动或恢复。'),
	bpf_unsupported: _('当前内核或系统不支持 LAN Speed 所需的 BPF 能力。'),
	tc_clsact_unsupported: _('当前系统不支持 TC clsact，BPF 客户端采集无法挂载。'),
	bpf_tc_self_heal_failed: _('BPF 的 TC 挂载自愈失败，实时采集可能已经中断。'),
	unsafe_attach: _('当前 TC 挂载点不安全，后端已停止 BPF 采集以避免影响网络。'),
	map_full: _('BPF 客户端表已满，部分客户端可能不会显示。'),
	map_read_failed: _('BPF 客户端表读取失败，当前速率数据可能不完整。'),
	counter_anomaly: _('检测到计数器异常回退，本次速率增量已忽略。'),
	time_rollback: _('检测到采样时钟回退，本次速率增量已忽略。'),
	client_limit_exceeded: _('客户端数量超过后端上限，部分客户端未显示。'),
	live_metrics_unavailable: _('没有可用的实时速率数据，客户端列表可能为空或处于降级状态。'),
	probe_error: _('部分运行环境探测失败，状态判断可能不完整。'),
	tc_missing: _('系统缺少 tc，BPF 客户端实时测速无法启动。'),
	conntrack_unavailable: _('Conntrack 当前不可用，连接数与 NSS sync 数据无法更新。'),
	conntrack_parse_errors: _('部分 Conntrack 记录无法解析，连接统计可能不完整。'),
	lan_edge_missing: _('没有可采集的 LAN 接口，客户端实时测速无法启动。'),
	lan_topology_probe_error: _('LAN 拓扑探测失败，接口边界和客户端归属判断可能不完整。'),
	bpf_disabled: _('BPF 已在后端配置中关闭，客户端实时测速不会启动。'),
	nss_not_present: _('当前设备未检测到 NSS，该组件不适用。'),
	existing_tc_filters_detected: _('检测到现有 TC 过滤器；LAN Speed 会保留非自身规则，请确认它们来自预期的 QoS、代理或流量控制组件。'),
	software_flow_offload_enabled: _('已启用软件流量卸载；部分流量可能绕过常规 CPU 路径，需结合覆盖率判断采集完整性。'),
	flowtable_counter_probe_unavailable: _('无法确认 Flowtable 计数器能力，卸载流量覆盖率判断可能不完整。'),
	flowtable_counter_missing: _('系统缺少 Flowtable 计数器，卸载流量可能无法计入覆盖率。'),
	conntrack_routed_nat_only: _('连接统计仅包含经路由或 NAT 的流量，纯二层 LAN 流量不在此口径内。'),
	fullcone_detected: _('检测到 Fullcone NAT；连接端点可能被重写，解读客户端连接归属时需考虑该路径。'),
	fullcone_nat_enabled: _('防火墙已启用 Fullcone NAT；这属于环境信息，不会单独阻断实时采集。'),
	collection_unavailable: _('尚无任何成功采集结果，实时状态当前不可用。'),
	collection_stale: _('当前显示的是较早或保留的采集结果，请检查服务与数据源。'),
	proxy_stack: _('检测到透明代理组件；客户端归属与远端端点可信度可能降低。'),
	refresh_interval_clamped: _('采样间隔超出支持范围，后端已调整为可用值。'),
	active_client_window_clamped: _('活跃客户端窗口超出支持范围，后端已调整为可用值。'),
	active_client_min_bps_clamped: _('活跃速率阈值超出支持范围，后端已调整为可用值。'),
	overview_window_samples_clamped: _('历史采样点数超出支持范围，后端已调整为可用值。'),
	max_clients_clamped: _('客户端上限超出支持范围，后端已调整为可用值。'),
	interface_exclude_compatibility_only: _('“排除接口”仅为兼容旧配置保留，不会改变当前 TC 挂载集合。'),
	openclash_detected: _('检测到 OpenClash；透明代理可能改变 LAN/WAN 流量路径。'),
	openclash_dns_chain_incomplete: _('OpenClash DNS 转发链不完整，DNS 连接分类可能不准确。'),
	openclash_fake_ip_low_remote_confidence: _('OpenClash Fake-IP 会降低远端地址识别可信度。'),
	openclash_tun_conntrack_low_confidence: _('OpenClash TUN 模式可能降低 Conntrack 连接归属可信度。'),
	openclash_router_self_proxy_detected: _('OpenClash 已代理路由器自身流量，部分本机连接可能进入 LAN 诊断路径。'),
	dae_detected: _('检测到 dae/daed；透明代理可能改变流量路径。'),
	dae_tc_preempts_bpf_ingress: _('dae 的 TC 规则先于 LAN Speed 入口执行，BPF 可见流量可能减少。'),
	existing_qos: _('检测到现有 QoS/SQM 组件；队列或 IFB 路径可能影响采集覆盖率。'),
	nlbwmon_counter_conflict: _('检测到 nlbwmon 计数路径；请避免把不同统计口径直接相加。')
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
	no_collect_interface: true,
	package_missing: true,
	object_missing: true,
	object_load_failed: true,
	tc_unavailable: true,
	tc_unsupported: true,
	tc_conflict: true,
	tc_attach_failed: true,
	map_not_started: true,
	bpf_runtime_not_ready: true,
	bpf_unsupported: true,
	tc_clsact_unsupported: true,
	bpf_tc_self_heal_failed: true,
	unsafe_attach: true,
	map_full: true,
	map_read_failed: true,
	counter_anomaly: true,
	time_rollback: true,
	nss_direct_no_data: true,
	skip_nss_ecm_direct_flow_without_lan_identity: true,
	client_limit_exceeded: true,
	live_metrics_unavailable: true,
	probe_error: true,
	tc_missing: true,
	lan_edge_missing: true,
	lan_topology_probe_error: true,
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
	no_collect_interface: true,
	package_missing: true,
	object_missing: true,
	object_load_failed: true,
	tc_unavailable: true,
	tc_unsupported: true,
	tc_conflict: true,
	tc_attach_failed: true,
	map_not_started: true,
	bpf_unsupported: true,
	tc_clsact_unsupported: true,
	bpf_tc_self_heal_failed: true,
	bpf_optional_package_missing: true,
	bpf_object_missing: true,
	conntrack_acct_disabled: true,
	nf_conntrack_acct_disabled: true,
	map_full: true,
	bpf_disabled: true
};

var WARNING_ALIASES = {
	nss_daed_nss_fallback_may_be_inaccurate: 'nss_dae_bpf_fallback_may_be_inaccurate',
	hardware_flow_offload: 'hardware_flow_offload_unsupported',
	software_flow_offload: 'software_flow_offload_enabled',
	fullcone: 'fullcone_detected',
	fullcone_nat_enabled: 'fullcone_detected'
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
	hasWarning: function(w) {
		w = normalizeWarningId(w);
		return Object.prototype.hasOwnProperty.call(WARNING_LABELS, w);
	},
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
