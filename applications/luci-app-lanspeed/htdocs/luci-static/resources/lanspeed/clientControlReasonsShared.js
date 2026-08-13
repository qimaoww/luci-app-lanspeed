'use strict';
'require baseclass';

return baseclass.extend({
	LABELS: {
		invalid_identity_key: _('客户端身份参数无效。'),
		unknown_identity: _('客户端已离线或不在当前实时列表中。'),
		ambiguous_identity: _('该地址同时归属于多个客户端，已拒绝操作。'),
		identity_address_unavailable: _('尚未取得唯一的客户端 IP 地址。'),
		identity_interface_unavailable: _('尚未确认该客户端实际经过的 LAN 接口。'),
		invalid_rate: _('速率必须是十进制 bit/s。'),
		missing_rate: _('缺少上传或下载速率。'),
		rate_below_minimum: _('非零速率不能低于 0.008 Mbps。'),
		rate_above_platform_maximum: _('速率超过当前平台安全上限。'),
		invalid_switch: _('禁网开关参数无效。'),
		conntrack_control_unavailable: _('连接跟踪清理工具不可用，无法安全执行即时禁网。'),
		missing_tc: _('TC 队列工具不可用。'),
		missing_ip: _('iproute2 接口管理工具不可用。'),
		missing_nft: _('nftables 工具不可用。'),
		missing_conntrack: _('连接跟踪清理工具不可用。'),
		missing_ubus: _('netifd 接口查询不可用。'),
		conntrack_cleanup_failed: _('无法清理该客户端的现有连接，控制规则已回滚。'),
		invalid_rate_resolution: _('速率必须使用 TC 可精确表示的 8 bit/s 步进。'),
		interface_status_unavailable: _('无法读取系统接口状态。'),
		traffic_verification_pending: _('已安装队列，正在用真实流量核对上传与下载方向。'),
		direction_verification_pending: _('一个方向已验证，另一方向仍等待新连接流量。'),
		queue_overflow: _('整形队列发生溢出，请降低持续负载或提高限速值。'),
		local_network_unavailable: _('无法可靠读取本地网段，未应用可能误限 LAN/NAS 的规则。'),
		control_rollback_failed: _('控制规则应用失败且自动回滚未完整完成，请重新检查。'),
		control_rule_limit: _('客户端控制规则已达到安全上限。'),
		control_apply_failed: _('控制规则应用失败，未启用不完整的数据路径。')
	}
});
