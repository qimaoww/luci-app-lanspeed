'use strict';
'require baseclass';
'require ui';
'require lanspeed.rpc as lsRpc';

function reasonText(reason) {
	var labels = {
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
		conntrack_control_unavailable: _('连接跟踪清理工具不可用，无法安全执行即时禁网。'),
		missing_tc: _('TC 队列工具不可用。'),
		missing_ip: _('iproute2 接口管理工具不可用。'),
		missing_nft: _('nftables 工具不可用。'),
		missing_conntrack: _('连接跟踪清理工具不可用。'),
		missing_ubus: _('netifd 接口查询不可用。'),
		conntrack_cleanup_failed: _('无法清理该客户端的现有连接，控制规则已回滚。'),
		invalid_rate_resolution: _('速率必须使用 TC 可精确表示的 8 bit/s 步进。'),
		interface_status_unavailable: _('无法读取系统接口状态。'),
		queue_tree_verification_failed: _('队列树安装后校验失败，已回滚。'),
		queue_stats_unavailable: _('无法读取整形队列统计。'),
		traffic_verification_pending: _('已安装队列，正在用真实流量核对上传与下载方向。'),
		nss_path_identity_pending: _('正在确认客户端流量的实际执行路径，尚未发布限速分类。'),
		direction_verification_pending: _('一个方向已验证，另一方向仍等待新连接流量。'),
		queue_overflow: _('整形队列发生溢出，请降低持续负载或提高限速值。'),
		local_network_unavailable: _('无法可靠读取本地网段，未应用可能误限 LAN/NAS 的规则。'),
		control_rollback_failed: _('控制规则应用失败且自动回滚未完整完成，请重新检查。'),
		nss_control_rollback_failed: _('NSS 控制应用失败且专用对象未能完整回滚。'),
		nss_control_command_timeout: _('NSS 控制命令执行超时，已停止应用。'),
		nss_ecm_dscp_unavailable: _('ECM QoS 分类器未启用，无法安全写入双向 NSS 标签。'),
		nss_qdisc_unavailable: _('NSS 固件队列模块不可用。'),
		nss_wan_topology_invalid: _('默认路由拓扑数据无效。'),
		nss_netifd_topology_unavailable: _('无法从 netifd 确认实际 WAN 出口。'),
		nss_fw4_topology_unavailable: _('无法从防火墙区域确认互联网出口。'),
		nss_wan_interface_unavailable: _('未找到可安装 NSS 队列的实际 WAN 出口。'),
		nss_download_edge_unavailable: _('尚未由 Access Edge 确认客户端真实下载出口。'),
		nss_download_edge_invalid: _('客户端下载出口与 WAN 冲突，已拒绝应用。'),
		nss_default_class_capacity_exceeded: _('目标接口链路容量超过 NSS 安全整形上限或无法确认。'),
		nss_qdisc_owned_by_external_service: _('目标接口的 NSS 队列正在由其它服务管理。'),
		nss_qdisc_apply_failed: _('NSS 固件队列创建失败，已回滚。'),
		nss_qdisc_inspection_failed: _('无法读取 NSS 固件队列状态。'),
		nss_qdisc_verification_failed: _('NSS 队列树校验失败，未发布分类映射。'),
		nss_control_firewall_owned_by_external_service: _('NSS 分类表正在由其它服务管理。'),
		nss_control_firewall_inspection_failed: _('无法检查 NSS 分类表所有权。'),
		nss_control_firewall_failed: _('NSS 双栈分类映射应用失败。'),
		cpu_path_block_interface_unavailable: _('尚未确认可在代理接管前后保留客户端身份的禁网接口。'),
		cpu_path_block_owned_by_external_service: _('CPU 路径禁网表正在由其它服务管理。'),
		cpu_path_block_inspection_failed: _('无法检查 CPU 路径禁网规则。'),
		cpu_path_block_apply_failed: _('CPU 路径双向禁网规则创建失败。'),
		cpu_path_block_missing: _('CPU 路径双向禁网规则不完整，正在重建。'),
		cpu_path_block_stale: _('发现过期的 CPU 路径禁网规则。'),
		cpu_path_block_cleanup_failed: _('CPU 路径禁网规则清理失败。'),
		cpu_path_probe_interface_unavailable: _('尚未确认可保留客户端身份的 CPU 路径接口。'),
		cpu_path_probe_owned_by_external_service: _('CPU 路径证明表正在由其它服务管理。'),
		cpu_path_probe_inspection_failed: _('无法读取 CPU 路径证明计数。'),
		cpu_path_probe_apply_failed: _('CPU 路径证明规则创建失败。'),
		cpu_path_probe_missing: _('CPU 路径证明规则不完整，正在重建。'),
		cpu_path_probe_stale: _('发现过期的 CPU 路径证明规则。'),
		cpu_path_probe_cleanup_failed: _('CPU 路径证明规则清理失败。'),
		cpu_path_classifier_owned_by_external_service: _('CPU 路径分类链与其它 TC 规则冲突。'),
		cpu_path_classifier_inspection_failed: _('无法读取 CPU 路径分类规则。'),
		cpu_path_classifier_verification_failed: _('CPU 路径分类发布后校验失败。'),
		cpu_path_classifier_missing: _('CPU 路径分类规则不完整，正在重建。'),
		cpu_path_classifier_stale: _('发现过期的 CPU 路径分类规则。'),
		cpu_path_qdisc_owned_by_external_service: _('NSS 专属 CPU 队列正在由其它服务管理。'),
		cpu_path_qdisc_verification_failed: _('NSS 专属 CPU 队列树校验失败。'),
		cpu_path_qdisc_inspection_failed: _('无法读取 NSS 专属 CPU 队列状态。'),
		cpu_path_class_inspection_failed: _('无法读取 NSS 专属 CPU class 状态。'),
		cpu_path_filter_owned_by_external_service: _('NSS 专属 IFB 分类链与其它规则冲突。'),
		cpu_path_filter_inspection_failed: _('无法读取 NSS 专属 IFB 分类规则。'),
		cpu_path_filter_verification_failed: _('NSS 专属 IFB 分类规则校验失败。'),
		control_rule_limit: _('客户端控制规则已达到安全上限。'),
		control_apply_failed: _('控制规则应用失败，未启用不完整的数据路径。')
	};
	return labels[String(reason || '')] || (reason ? _('控制不可用：%s').format(reason) : '');
}

function bpsToMbps(value) {
	value = Number(value) || 0;
	return value > 0 ? (value / 1000000).toFixed(6).replace(/0+$/, '').replace(/\.$/, '') : '';
}

function mbpsToBps(value, maximum) {
	if (value === '' || value === null || value === undefined) return 0;
	var number = Number(value);
	if (!isFinite(number) || number < 0) throw new Error(_('请输入有效的非负速率。'));
	// The daemon and TC contract use an exact 8 bit/s resolution. Convert via
	// 8-bit units so every value emitted by the UI is accepted by the backend.
	var bps = Math.round(number * 125000) * 8;
	if (bps !== 0 && bps < 8000) throw new Error(_('非零速率不能低于 0.008 Mbps。'));
	if (bps > Number(maximum || 0))
		throw new Error(_('超过当前平台上限 %s Mbps。').format(Number(maximum) / 1000000));
	return bps;
}

function ensureOk(response) {
	if (response && response.ok === true) return response;
	var reason = response && response.error || response && response.control && response.control.reason;
	throw new Error(reasonText(reason) || _('控制规则应用失败。'));
}

function run(viewState, identityKey, task) {
	viewState.controlBusy = viewState.controlBusy || {};
	if (viewState.controlBusy[identityKey]) return Promise.resolve(false);
	viewState.controlBusy[identityKey] = true;
	viewState.refreshLive();
	return Promise.resolve().then(task).then(ensureOk).then(function(response) {
		var clients = viewState.clients && viewState.clients.clients;
		if (Array.isArray(clients) && response.control) {
			clients.forEach(function(client) {
				if (client && client.identity_key === identityKey)
					client.control = response.control;
			});
		}
		viewState.refreshLive();
		ui.hideModal();
		return viewState.reload(true);
	}).catch(function(error) {
		var feedback = document.querySelector('.lanspeed-control-feedback');
		if (feedback) {
			feedback.style.display = '';
			feedback.textContent = error && error.message ? error.message : String(error);
		} else {
			ui.addNotification(null, E('p', {}, error && error.message ? error.message : String(error)));
		}
		return false;
	}).finally(function() {
		delete viewState.controlBusy[identityKey];
		viewState.refreshLive();
	});
}

function setRule(viewState, client, upload, download, disabled) {
	return run(viewState, client.identity_key, function() {
		return lsRpc.clientControlSet(
			String(client.identity_key),
			String(upload),
			String(download),
			disabled ? '1' : '0'
		);
	});
}

function clientIdentity(client) {
	client = client || {};
	var ips = Array.isArray(client.ips) ? client.ips.map(function(ip) {
		return String(ip || '').trim();
	}).filter(Boolean) : [];
	var primaryIp = ips.filter(function(ip) { return ip.indexOf(':') < 0; })[0] || ips[0] || '';
	var hostname = String(client.hostname || '').trim();
	var mac = String(client.mac || '').trim();
	var name = hostname || primaryIp || mac || String(client.identity_key || '').trim() || _('未知客户端');
	var details = [];
	if (primaryIp && primaryIp !== name) details.push(primaryIp);
	if (mac && mac !== name) details.push(mac);
	return { name: name, details: details.join(' · ') };
}

function openLimit(viewState, client) {
	var control = client.control || {};
	var identity = clientIdentity(client);
	var upload = E('input', {
		'type': 'number', 'min': '0', 'step': '0.001', 'inputmode': 'decimal',
		'class': 'cbi-input-text', 'value': bpsToMbps(control.upload_bps),
		'placeholder': _('0 表示不限速')
	});
	var download = E('input', {
		'type': 'number', 'min': '0', 'step': '0.001', 'inputmode': 'decimal',
		'class': 'cbi-input-text', 'value': bpsToMbps(control.download_bps),
		'placeholder': _('0 表示不限速')
	});
	var feedback = E('div', {
		'class': 'alert-message error lanspeed-control-feedback', 'style': 'display:none',
		'role': 'alert'
	});
	var save = E('button', {
		'type': 'button', 'class': 'cbi-button cbi-button-positive important'
	}, _('保存'));
	save.addEventListener('click', function() {
		try {
			var up = mbpsToBps(upload.value, control.max_rate_bps);
			var down = mbpsToBps(download.value, control.max_rate_bps);
			setRule(viewState, client, up, down, control.internet_disabled === true);
		} catch (error) {
			feedback.style.display = '';
			feedback.textContent = error.message;
		}
	});
	var cancel = E('button', { 'type': 'button', 'class': 'cbi-button' }, _('取消'));
	cancel.addEventListener('click', ui.hideModal);
	ui.showModal(_('客户端限速'), [
		E('p', { 'class': 'lanspeed-control-client' }, [
			E('span', { 'class': 'lanspeed-control-client-label' }, _('当前客户端')),
			E('strong', { 'class': 'lanspeed-control-client-name' }, identity.name),
			identity.details ? E('span', {
				'class': 'lanspeed-control-client-meta', 'title': identity.details
			}, identity.details) : ''
		]),
		E('p', {}, _('仅限制访问互联网的流量，路由器管理和 LAN/NAS 流量不受影响。正常整形不主动丢包。')),
		E('div', { 'class': 'cbi-section-node lanspeed-control-form' }, [
			E('label', {}, [ E('span', {}, _('上传 Mbps')), upload ]),
			E('label', {}, [ E('span', {}, _('下载 Mbps')), download ])
		]),
		feedback,
		E('div', { 'class': 'right' }, [ cancel, ' ', save ])
	]);
	window.setTimeout(function() { upload.focus(); }, 0);
}

function toggleBlock(viewState, client) {
	var control = client.control || {};
	return setRule(
		viewState,
		client,
		Number(control.upload_bps) || 0,
		Number(control.download_bps) || 0,
		control.internet_disabled !== true
	);
}

function stateLabel(control) {
	if (!control || !control.configured) return '';
	if (control.queue_overflow) return _('队列溢出');
	if (control.state === 'pending_new_connections' && control.reason === 'nss_path_identity_pending')
		return _('等待路径确认');
	if (control.state === 'pending_new_connections' && control.reason === 'traffic_verification_pending')
		return _('等待流量验证');
	if (control.internet_disabled && control.state === 'pending_new_connections')
		return _('禁网已生效 · 限速待验证');
	if (control.internet_disabled && control.state === 'verified')
		return _('禁网与限速已验证');
	if (control.internet_disabled && control.state === 'applied') return _('已禁用上网');
	if (control.state === 'pending_new_connections') return _('新连接生效');
	if (control.state === 'verified') return _('已验证生效');
	if (control.state === 'error' || control.state === 'unsupported') return _('不可用');
	return _('已配置');
}

function cell(viewState, client) {
	var control = client.control || {};
	var busy = !!(viewState.controlBusy && viewState.controlBusy[client.identity_key]);
	var hasLimit = Number(control.upload_bps) > 0 || Number(control.download_bps) > 0;
	var limitAttrs = {
		'type': 'button',
		'class': 'cbi-button cbi-button-neutral lanspeed-control-button',
		'title': control.shaping_supported === true ? _('设置独立上传、下载限速') : reasonText(control.reason)
	};
	if (busy || (control.shaping_supported !== true && !hasLimit)) limitAttrs.disabled = 'disabled';
	var limit = E('button', limitAttrs, busy ? _('处理中…') : _('限速'));
	limit.addEventListener('click', function(event) {
		if (event) event.preventDefault();
		openLimit(viewState, client);
	});
	var blocked = control.internet_disabled === true;
	var blockAttrs = {
		'type': 'button',
		'class': blocked ? 'cbi-button cbi-button-positive lanspeed-control-button' :
			'cbi-button cbi-button-negative lanspeed-control-button',
		'title': control.blocking_supported === true ?
			_('只禁用互联网访问，保留路由器和本地网络访问') : reasonText(control.reason)
	};
	if (busy || (control.blocking_supported !== true && !blocked)) blockAttrs.disabled = 'disabled';
	var block = E('button', blockAttrs, blocked ? _('恢复上网') : _('禁用上网'));
	block.addEventListener('click', function(event) {
		if (event) event.preventDefault();
		toggleBlock(viewState, client);
	});
	var label = stateLabel(control);
	return E('td', { 'class': 'lanspeed-client-control', 'data-label': _('控制') }, [
		E('div', { 'class': 'lanspeed-control-actions' }, [ limit, block ]),
		label ? E('span', {
			'class': control.queue_overflow || control.state === 'error' ?
				'label danger lanspeed-control-state' : 'label lanspeed-control-state',
			'title': reasonText(control.reason)
		}, label) : ''
	]);
}

return baseclass.extend({
	cell: cell,
	openLimit: openLimit,
	toggleBlock: toggleBlock,
	reasonText: reasonText,
	clientIdentity: clientIdentity,
	mbpsToBps: mbpsToBps
});
