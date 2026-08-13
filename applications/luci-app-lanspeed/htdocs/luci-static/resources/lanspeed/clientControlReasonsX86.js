'use strict';
'require baseclass';

return baseclass.extend({
	LABELS: {
		lan_control_interface_unavailable: _('LAN 整形目标接口不可用。'),
		qdisc_owned_by_external_service: _('目标接口正在由其它 QoS 服务管理。'),
		ifb_qdisc_owned_by_external_service: _('上传整形接口正在由其它 QoS 服务管理。'),
		download_qdisc_preflight_conflict: _('LAN 下载方向正在由其它 QoS 服务管理。'),
		download_qdisc_stage_conflict: _('LAN 下载方向的队列状态在应用期间发生变化。'),
		ifb_module_unavailable: _('缺少客户端整形所需的 IFB 内核模块。'),
		ifb_owned_by_external_service: _('LAN Speed 专用 IFB 正在由其它服务使用。'),
		ifb_inspection_failed: _('无法核对 LAN Speed 专用 IFB。'),
		sch_htb_unavailable: _('HTB 队列模块不可用。'),
		sch_fq_unavailable: _('FQ 流队列模块不可用。'),
		cls_u32_unavailable: _('TC 地址分类模块不可用。'),
		cls_matchall_unavailable: _('TC 链跳转分类模块不可用。'),
		act_mirred_unavailable: _('TC IFB 重定向模块不可用。'),
		act_gact_unavailable: _('TC 禁网动作模块不可用。'),
		ingress_qdisc_owned_by_external_service: _('LAN ingress 正在由其它 QoS 服务独占。'),
		ingress_filter_owned_by_external_service: _('上传分类入口与其它 TC 规则冲突。'),
		ingress_chain_owned_by_external_service: _('上传分类链与其它 TC 规则冲突。'),
		ingress_filter_inspection_failed: _('无法读取上传分类规则。'),
		ingress_filter_verification_failed: _('上传 IFB 分类校验失败并已回滚。'),
		ingress_filter_cleanup_failed: _('上传分类回滚校验失败，请重新检查。'),
		block_filter_owned_by_external_service: _('禁网入口与其它 TC 规则冲突。'),
		block_chain_owned_by_external_service: _('禁网分类链与其它 TC 规则冲突。'),
		block_filter_inspection_failed: _('无法读取禁网分类规则。'),
		block_filter_verification_failed: _('禁网分类安装后校验失败并已回滚。'),
		block_filter_cleanup_failed: _('禁网分类回滚校验失败，请重新检查。'),
		control_filter_capacity: _('受控地址数量超过 TC 分类容量。'),
		control_topology_changed: _('整形路径已变化，正在重新应用限速。'),
		qdisc_inspection_failed: _('无法读取目标接口的队列状态。'),
		qdisc_inspection_invalid: _('目标接口返回了无效的队列状态。'),
		queue_tree_verification_failed: _('队列树安装后校验失败，已回滚。'),
		queue_stats_unavailable: _('无法读取整形队列统计。')
	}
});
