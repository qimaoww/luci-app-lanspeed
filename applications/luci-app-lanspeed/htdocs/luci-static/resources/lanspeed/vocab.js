'use strict';
'require baseclass';

/*
 * LAN Speed vocabulary module.
 *
 * Owns the label dictionaries (capabilities, warnings) and the small
 * class/text lookup functions that interpret status fields.  Pure data +
 * pure functions only — no DOM, no RPC, no persistent state.
 */

var CAPABILITY_LABELS = {
	bpf: 'BPF',
	bpf_package: _('BPF 软件包'),
	bpf_object: _('BPF 对象'),
	bpf_runtime_metrics: _('BPF 实时指标'),
	conntrack_fallback: _('NSS conntrack 测速'),
	live_metrics: _('实时指标'),
	fw4: 'fw4',
	nft: 'nftables',
	software_flow_offload: _('软件流量卸载'),
	hardware_flow_offload: _('硬件流量卸载'),
	nss: _('Qualcomm NSS'),
	nss_ecm_direct: _('NSS-direct'),
	nss_ecm_offload: _('NSS ECM 硬件加速'),
	nss_ppe_offload: _('NSS PPE 硬件加速'),
	nss_bridge_mgr: _('NSS 网桥管理'),
	nss_ifb: _('NSS IFB 镜像'),
	nss_nsm: _('NSS 统计管理'),
	nss_dp: _('NSS 数据面'),
	nss_mcs: _('NSS 组播 snooping'),
	fullcone: 'Fullcone NAT',
	nf_conntrack_acct: _('conntrack 计数'),
	flowtable_counter: _('flowtable 计数'),
	tc: 'tc',
	tc_clsact: 'TC clsact',
	existing_tc_filters: _('已有 TC filter'),
	ifb: 'IFB',
	sqm: 'SQM',
	qosify: 'qosify',
	openclash: 'OpenClash',
	openclash_fake_ip: 'OpenClash fake-ip',
	openclash_tun_mix: 'OpenClash TUN/mix',
	openclash_redirect_dns: _('OpenClash DNS 劫持'),
	openclash_dns_chain_complete: _('OpenClash DNS 链'),
	openclash_router_self_proxy: 'OpenClash router-self',
	openclash_udp_proxy: 'OpenClash UDP',
	openclash_ipv6: 'OpenClash IPv6',
	dae: 'dae/daed',
	homeproxy: 'HomeProxy',
	lan_bridge: _('LAN 网桥'),
	vlan: 'VLAN',
	wlan: 'Wi-Fi',
	lan_edge: _('LAN 边缘'),
	safe_attach: _('安全 TC 挂载'),
	map_full: _('映射表已满')
};

var CAPABILITY_ORDER = [
	'bpf_runtime_metrics', 'live_metrics', 'bpf', 'bpf_package', 'bpf_object',
	'tc', 'tc_clsact', 'safe_attach', 'lan_edge', 'lan_bridge', 'vlan', 'wlan',
	'conntrack_fallback', 'nf_conntrack_acct', 'flowtable_counter',
	'software_flow_offload', 'hardware_flow_offload',
	'nss', 'nss_dp', 'nss_ecm_direct', 'nss_ecm_offload', 'nss_ppe_offload', 'nss_nsm',
	'nss_bridge_mgr', 'nss_ifb', 'nss_mcs', 'fullcone',
	'existing_tc_filters', 'ifb', 'sqm', 'qosify',
	'openclash', 'openclash_fake_ip', 'openclash_tun_mix', 'openclash_redirect_dns',
	'openclash_dns_chain_complete', 'openclash_router_self_proxy',
	'openclash_udp_proxy', 'openclash_ipv6', 'dae', 'homeproxy',
	'fw4', 'nft', 'map_full'
];

var WARNING_LABELS = {
	openclash_detected: _('已检测到 OpenClash；BPF 客户端测速仍可正常工作。'),
	openclash_fake_ip_low_remote_confidence: _('OpenClash fake-ip 会改写远端地址，目标 IP 仅供参考。'),
	openclash_tun_conntrack_low_confidence: _('OpenClash TUN/mix 会降低连接详情的归属准确度。'),
	openclash_dns_chain_incomplete: _('OpenClash DNS 链不完整，域名相关信息可能不准确。'),
	openclash_router_self_proxy_detected: _('OpenClash 正在代理路由器自身流量，这部分流量不会归属到 LAN 客户端。'),
	openclash_tun_mix_detected: _('OpenClash TUN/mix 已启用，代理接口只作为运行环境信息。'),
	openclash_udp_proxy_detected: _('OpenClash UDP 代理可能降低连接详情的归属准确度。'),
	dae_detected: _('已检测到 dae/daed；代理接口不会被当作 LAN 客户端。'),
	dae_tc_preempts_bpf_ingress: _('dae/daed 占用了 TC ingress，BPF 已切换到兼容挂载方式。'),
	tc_filter_conflict: _('TC 挂载点被其它程序占用，BPF 无法安全启动；请检查该 LAN 接口上的 TC filter。'),
	existing_tc_filters_detected: _('接口上已有其它 TC filter，lanspeedd 会保留现有规则。'),
	sqm_detected: _('已检测到 SQM；IFB 只影响接口方向说明，不影响 LAN 客户端身份。'),
	qosify_detected: _('已检测到 qosify；现有流量分类规则会被保留。'),
	ifb_detected: _('已检测到 IFB；该接口适合“观察”，不适合作为 LAN 客户端采集点。'),
	software_flow_offload_enabled: _('软件流量卸载已启用，BPF 位于卸载前，不影响客户端实时测速。'),
	hardware_flow_offload_unsupported: _('硬件流量卸载会绕过 BPF，客户端速率可能明显偏低；请关闭硬件卸载或改用受支持的数据源。'),
	nss_detected: _('已检测到 Qualcomm NSS；后端会根据硬件加速状态选择合适的数据源。'),
	nss_ecm_offload_active: _('NSS ECM 正在加速连接，客户端速率由 NSS 数据源补充。'),
	nss_ecm_direct_active: _('NSS-direct 已就绪，可直接读取 ECM 流量计数。'),
	nss_prefers_direct: _('NSS 硬件加速已启用，当前使用 NSS-direct 统计客户端速率。'),
	nss_ecm_direct_snapshot_pending: _('NSS-direct 正在完成首次采样，短时间内速率可能为 0。'),
	nss_ecm_direct_unavailable: _('NSS-direct 当前不可用，后端已自动尝试其它数据源。'),
	nss_direct_no_data: _('NSS-direct 暂无有效数据，当前使用 NSS sync。'),
	nss_direct_partial: _('NSS-direct 仅覆盖部分客户端，其余数据由 NSS sync 补齐。'),
	nss_sync_fallback: _('当前使用 NSS sync 作为稳定的客户端速率来源。'),
	nss_ecm_direct_parse_errors: _('NSS ECM 数据包含无法解析的记录，部分客户端速率可能缺失。'),
	skip_nss_ecm_direct_flow_without_lan_identity: _('部分 NSS 流量无法匹配到 LAN 客户端，已跳过以避免错误归属。'),
	nss_ecm_sync_cadence: _('NSS sync 约每 1–2 秒更新一次客户端速率。'),
	nss_prefers_conntrack_sync: _('当前设备使用 NSS sync 统计客户端速率。'),
	dae_runtime_prefers_bpf: _('dae/daed 运行中，当前仍使用 BPF 统计 LAN 客户端速率。'),
	nss_dae_bpf_fallback_may_be_inaccurate: _('NSS 与 dae/daed 同时运行，但 BPF 不可用；当前回退数据源可能导致实时速率不准确。'),
	dae_process_probe_failed: _('无法确认 dae/daed 的运行状态，后端的数据源选择可能暂时不准确。'),
	nss_ifb_detected: _('已检测到 nssifb 镜像接口；该接口只能设为“观察”。'),
	nssifb_collect_rejected: _('nssifb 是镜像接口，不能用于客户端采集；后端已忽略该配置，请改为“观察”。'),
	nss_ppe_offload_active: _('NSS PPE 正在加速连接，客户端速率由 NSS 数据源补充。'),
	fullcone_detected: _('已检测到 Fullcone NAT。'),
	fullcone_nat_enabled: _('Fullcone NAT 已启用。'),
	conntrack_routed_nat_only: _('Conntrack 仅统计经过路由器的连接，不参与非 NSS 实时测速。'),
	conntrack_connection_only: _('该客户端当前只有连接记录，没有新的速率样本；这不是异常。'),
	conntrack_acct_disabled: _('Conntrack 计数未启用，连接数与 NSS sync 数据不可用。'),
	nf_conntrack_acct_disabled: _('nf_conntrack_acct 未启用，连接数与 NSS sync 数据不可用。'),
	flowtable_counter_missing: _('未检测到 flowtable 计数，连接诊断可能不完整。'),
	nlbwmon_counter_conflict: _('已检测到 nlbwmon；lanspeedd 不会修改它的计数。'),
	bpf_optional_package_missing: _('缺少必需的 BPF 软件包，客户端实时测速不可用。'),
	bpf_object_missing: _('缺少 BPF 对象文件，客户端实时测速不可用。'),
	bpf_runtime_loader_unavailable: _('BPF 组件已安装，但 TC 挂载或映射表读取失败，客户端实时测速未能启动。'),
	unsafe_attach: _('当前 TC 挂载点不安全，后端已停止 BPF 采集以避免影响网络。'),
	map_full: _('BPF 客户端表已满，部分客户端可能不会显示。'),
	map_read_failed: _('BPF 客户端表读取失败，当前速率数据可能不完整。'),
	client_limit_exceeded: _('客户端数量超过后端上限，部分客户端未显示。'),
	live_metrics_unavailable: _('没有可用的实时速率数据，客户端列表可能为空或处于降级状态。'),
	lan_to_lan_visibility_limited: _('交换芯片内直接转发的 LAN-to-LAN 流量可能无法按客户端统计。'),
	lan_to_lan_visibility_unknown: _('当前网络拓扑无法确认 LAN-to-LAN 流量是否完整可见。'),
	asymmetric_path_possible: _('部分流量可能走不同路径，上下行数据可能不对称。'),
	duplicate_mac_across_vlans: _('同一 MAC 出现在多个采集接口，会按不同客户端身份分别显示。'),
	probe_error: _('部分运行环境探测失败，状态判断可能不完整。'),
	tc_missing: _('系统缺少 tc，BPF 客户端实时测速无法启动。'),
	conntrack_snapshot_pending: _('连接数正在完成首次采样，请稍后刷新。'),
	conntrack_unavailable: _('Conntrack 当前不可用，连接数与 NSS sync 数据无法更新。'),
	flow_offload_confidence_low: _('流量卸载可能降低连接诊断的准确度。'),
	refresh_interval_below_minimum: _('后端刷新过快，页面将按 1 秒的最小间隔更新。'),
	counter_anomaly: _('检测到异常计数，本次速率已按 0 处理。'),
	time_rollback: _('系统时间回退，本次速率已按 0 处理。'),
	proxy_path_confidence_low: _('代理路径可能降低连接详情的归属准确度。'),
	qos_ifb_confidence_low: _('QoS / IFB 可能降低接口方向判断的准确度。'),
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
	nss_daed_prefers_bpf: 'dae_runtime_prefers_bpf',
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
	CAPABILITY_LABELS: CAPABILITY_LABELS,
	CAPABILITY_ORDER:  CAPABILITY_ORDER,
	WARNING_LABELS:    WARNING_LABELS,
	WARNING_ALIASES:   WARNING_ALIASES,
	IMPORTANT_WARNINGS: IMPORTANT_WARNINGS,
	CRITICAL_WARNINGS: CRITICAL_WARNINGS,
	normalizeWarningId: normalizeWarningId,
	isImportantWarning: isImportantWarning,
	importantWarnings: importantWarnings,

	normalizeConfidence: function(v) {
		return String(v || 'unsupported').toLowerCase();
	},

	confidenceClass: function(v) {
		v = this.normalizeConfidence(v);
		if (v === 'high')   return 'label label-success';
		if (v === 'medium') return 'label label-warning';
		return 'label label-danger';
	},

	confidenceText: function(v) {
		v = this.normalizeConfidence(v);
		if (v === 'high')        return _('高');
		if (v === 'medium')      return _('中');
		if (v === 'low')         return _('低');
		if (v === 'unsupported') return _('不支持');
		return (v === null || v === undefined || v === '') ? '-' : String(v);
	},

	modeClass: function(m) {
		if (m === 'Full')     return 'label label-success';
		if (m === 'Degraded') return 'label label-warning';
		return 'label label-danger';
	},

	modeText: function(m) {
		if (m === 'Full')        return 'Full';
		if (m === 'Degraded')    return 'Degraded';
		if (m === 'Unsupported') return 'Unsupported';
		return (m === null || m === undefined || m === '') ? '-' : String(m);
	},

	warningText: function(w) {
		w = normalizeWarningId(w);
		return WARNING_LABELS[w] || String(w).replace(/_/g, ' ');
	},

	warningClass: function(w) {
		w = normalizeWarningId(w);
		if (CRITICAL_WARNINGS[w] || /hardware|unsafe|conflict|missing|error|failed|full/.test(w))
			return 'label label-danger';
		return 'label label-warning';
	},

	capabilityClass: function(key, enabled) {
		if (!enabled) return 'label';
		if (key === 'hardware_flow_offload' || key === 'map_full') return 'label label-danger';
		if (['software_flow_offload','fullcone','openclash_fake_ip','openclash_tun_mix',
		     'openclash_router_self_proxy','dae','sqm','qosify','ifb','existing_tc_filters']
		    .indexOf(key) !== -1) return 'label label-warning';
		return 'label label-success';
	}
});
