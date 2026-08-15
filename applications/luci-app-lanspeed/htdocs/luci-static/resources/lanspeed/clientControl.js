'use strict';
'require baseclass';
'require ui';
'require lanspeed.rpc as lsRpc';
'require lanspeed.clientControlReasons as controlReasons';

function reasonText(reason) {
	return controlReasons.text(reason);
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
	var wasPaused = !!(viewState.prefs && viewState.prefs.paused);
	viewState.controlBusy[identityKey] = true;
	if (!wasPaused && typeof viewState.stopTimer === 'function') viewState.stopTimer();
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
		if (!wasPaused && typeof viewState.schedule === 'function') viewState.schedule();
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
