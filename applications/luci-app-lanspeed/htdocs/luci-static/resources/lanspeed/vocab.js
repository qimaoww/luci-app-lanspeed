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
	openclash_detected: _('检测到 OpenClash，代理路径可能改变 LAN/WAN 流量走向。'),
	openclash_fake_ip_low_remote_confidence: _('OpenClash fake-ip 已启用，远端地址只能作为元数据。'),
	openclash_tun_conntrack_low_confidence: _('OpenClash TUN/mix 会降低 conntrack 诊断归因置信度。'),
	openclash_dns_chain_incomplete: _('OpenClash DNS 链路不完整，解析相关归因可能不可靠。'),
	openclash_router_self_proxy_detected: _('OpenClash router-self 代理：路由器自身流量不会归入任一 LAN 客户端。'),
	openclash_tun_mix_detected: _('OpenClash TUN/mix 可能让部分路径绕过 CPU 可见 LAN 边缘指标。'),
	openclash_udp_proxy_detected: _('OpenClash UDP 代理会降低按客户端归因的置信度。'),
	dae_detected: _('检测到 dae/daed，代理或 TUN 接口只作为上行证据，不作为 LAN 客户端身份。'),
	dae_tc_preempts_bpf_ingress: _('dae/daed 的 TC ingress 过滤器先于 lanspeed 运行，lanspeed 已改用前置只读 BPF 采样并继续放行给 dae/daed。'),
	tc_filter_conflict: _('已有 TC filter 与 lanspeed 挂载点冲突，lanspeedd 不会覆盖它。'),
	existing_tc_filters_detected: _('已存在其它 TC filter，lanspeedd 只告警，不删除或重排。'),
	sqm_detected: _('检测到 SQM，IFB 整形可能影响观察到的方向或覆盖范围。'),
	qosify_detected: _('检测到 qosify，已有分类器会被保留，置信度可能受影响。'),
	ifb_detected: _('检测到 IFB，入口整形可能改变 CPU 可见路径。'),
	software_flow_offload_enabled: _('软件流量卸载已启用；tc/BPF 挂载在它之前，客户端粒度仍然可见。'),
	hardware_flow_offload_unsupported: _('硬件流量卸载已启用，硬件转发流量可能绕过 CPU 可见指标。'),
	nss_detected: _('检测到 Qualcomm NSS 网络协处理器。流量被加速的部分不经过 CPU，BPF 仅能看到慢路径。'),
	nss_ecm_offload_active: _('NSS ECM 正在硬件加速连接，客户端数据经 ECM→conntrack 同步得到，置信度受限。'),
	nss_ecm_direct_active: _('NSS-direct 已启用：lanspeed 正在只读 ECM state flow 字节计数，直接聚合客户端速率。'),
	nss_prefers_direct: _('NSS/ECM 硬件卸载中：BPF 只能看到慢路径，已优先使用 NSS-direct 的 ECM state 字节计数。'),
	nss_ecm_direct_snapshot_pending: _('NSS-direct 正在等待第二次 ECM state 采样，速率暂时可能为 0。'),
	nss_ecm_direct_unavailable: _('NSS-direct state 设备不可用或不可读，已尝试回退到 ECM sync / 其它可用来源。'),
	nss_ecm_direct_parse_errors: _('解析 NSS ECM state 时遇到异常行，部分 flow 可能被跳过。'),
	skip_nss_ecm_direct_flow_without_lan_identity: _('部分 NSS ECM flow 没有可匹配的 LAN ARP/neighbor 身份，已跳过以避免误归因。'),
	nss_ecm_sync_cadence: _('NSS 硬件卸载中：客户端计数经 ECM 同步回 conntrack，精度为秒级节拍，不是逐包实时。'),
	nss_prefers_conntrack_sync: _('NSS/ECM 硬件卸载中：BPF 只能看到慢路径，已优先使用 ECM 同步回 conntrack 的客户端字节计数。'),
	nss_ifb_detected: _('检测到 NSS IFB（nssifb）：NSS 硬件 QoS 的镜像接口，其计数是物理口 ingress 的镜像，不应 attach BPF，只能作为观察对象。'),
	nssifb_collect_rejected: _('配置中请求 attach BPF 到 nssifb，daemon 已忽略——nssifb 是 NSS 镜像接口，attach 会重复计数物理口 ingress。请改用"观察"模式。'),
	nss_ppe_offload_active: _('NSS PPE 正在硬件加速连接（IPQ95xx/53xx 新一代硬件加速），BPF 只能看到慢路径。'),
	fullcone_detected: _('检测到 Fullcone NAT，NAT 辅助路径会作为置信度告警展示。'),
	fullcone_nat_enabled: _('Fullcone NAT 已启用，NAT 辅助路径会作为置信度告警展示。'),
	conntrack_routed_nat_only: _('conntrack 诊断仅覆盖路由 / NAT 流量；非 NSS 不用于客户端测速。'),
	conntrack_acct_disabled: _('conntrack 计数未启用，连接数诊断和 NSS ECM 同步测速不可用。'),
	nf_conntrack_acct_disabled: _('nf_conntrack_acct 未启用，连接数诊断和 NSS ECM 同步测速不可用。'),
	flowtable_counter_missing: _('未检测到 flowtable 计数，conntrack 诊断置信度会降低。'),
	nlbwmon_counter_conflict: _('检测到 nlbwmon 计数冲突，lanspeed 不读取或清零 nlbwmon 计数。'),
	bpf_optional_package_missing: _('缺少可选 BPF 软件包，无法使用实时 BPF 指标。'),
	bpf_object_missing: _('缺少 BPF 对象文件，无法使用实时 BPF 指标。'),
	bpf_runtime_loader_unavailable: _('BPF 资产齐备但本次启动没有成功完成 tc 挂载或 map 读取；非 NSS 客户端测速会保持不可用。'),
	unsafe_attach: _('TC 挂载点不安全，因此不会使用实时指标。'),
	map_full: _('BPF 客户端映射表已满，部分客户端可能被省略。'),
	map_read_failed: _('读取 BPF 映射表失败，本次客户端指标可能不完整。'),
	client_limit_exceeded: _('客户端数量超过限制，部分客户端可能未显示。'),
	live_metrics_unavailable: _('实时指标不可用，当前数据可能为空或处于降级状态。'),
	lan_to_lan_visibility_limited: _('LAN-to-LAN 流量绕过路由器 CPU 时，可见性会受限。'),
	lan_to_lan_visibility_unknown: _('当前拓扑下 LAN-to-LAN 可见性无法确认。'),
	asymmetric_path_possible: _('可能存在非对称路径，页面可能只能看到其中一个方向。'),
	duplicate_mac_across_vlans: _('同一 MAC 出现在多个 VLAN 或区域，会按不同身份分别显示。'),
	probe_error: _('运行时探测发生错误，状态信息可能不完整。'),
	tc_missing: _('TC 不可用，BPF LAN 边缘采集不受支持。'),
	conntrack_snapshot_pending: _('conntrack 正在等待第二次采样，速率暂时可能为 0。'),
	conntrack_unavailable: _('conntrack 数据不可用，连接数诊断和 NSS ECM 同步测速不可用。'),
	flow_offload_confidence_low: _('流量卸载会降低 conntrack 诊断置信度。'),
	refresh_interval_below_minimum: _('后端刷新间隔低于 UI 下限，页面会使用至少 1000ms 的刷新间隔。'),
	counter_anomaly: _('检测到计数异常，本窗口速率按 0 处理。'),
	time_rollback: _('检测到时间回退，本窗口速率按 0 处理。'),
	proxy_path_confidence_low: _('代理路径会降低按客户端归因的置信度。'),
	qos_ifb_confidence_low: _('QoS / IFB 整形可能降低采集置信度。'),
	lan_edge_missing: _('未检测到 LAN 边缘接口，实时采集无法工作。'),
	bpf_disabled: _('enable_bpf 已关闭，不会尝试加载 BPF 运行时。')
};

var CRITICAL_WARNINGS = {
	hardware_flow_offload_unsupported: true,
	nss_ecm_offload_active: true,
	nss_ppe_offload_active: true,
	tc_filter_conflict: true,
	nssifb_collect_rejected: true,
	unsafe_attach: true,
	tc_missing: true,
	lan_edge_missing: true,
	probe_error: true,
	map_read_failed: true,
	live_metrics_unavailable: true,
	bpf_runtime_loader_unavailable: true,
	conntrack_acct_disabled: true,
	nf_conntrack_acct_disabled: true,
	map_full: true
};

return baseclass.extend({
	CAPABILITY_LABELS: CAPABILITY_LABELS,
	CAPABILITY_ORDER:  CAPABILITY_ORDER,
	WARNING_LABELS:    WARNING_LABELS,
	CRITICAL_WARNINGS: CRITICAL_WARNINGS,

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
		return WARNING_LABELS[w] || String(w).replace(/_/g, ' ');
	},

	warningClass: function(w) {
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
