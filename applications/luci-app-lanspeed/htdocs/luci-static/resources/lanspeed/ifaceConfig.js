'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';

/*
 * LAN Speed interface configuration sub-panel.
 *
 * Owns scanning sysdevices, rendering segmented toggles and staging interface
 * UCI changes. The configuration form commits these changes together with the
 * runtime settings and reloads the daemon once.
 */

var AUTO_IGNORED_INTERFACE_PREFIXES = [
	'dae', 'miireg', 'tun',
	'erspan', 'gretap', 'gre',
	'ip6gre', 'ip6tnl', 'sit',
	'bonding_masters'
];

function isAutoIgnoredInterface(name) {
	name = String(name || '');
	for (var i = 0; i < AUTO_IGNORED_INTERFACE_PREFIXES.length; i++) {
		if (name.indexOf(AUTO_IGNORED_INTERFACE_PREFIXES[i]) === 0)
			return true;
	}
	return false;
}

function visibleDevices(data) {
	return fmt.asArray(data && data.devices).filter(function(dev) {
		return dev && !isAutoIgnoredInterface(dev.name);
	});
}

function renderIfaceConfig(viewState) {
	var refs = viewState.refs;
	var data = viewState.sysdevices || { devices: [] };
	var devs = visibleDevices(data);
	var attachNow = fmt.asArray(data.current_ifnames).filter(function(name) {
		return !isAutoIgnoredInterface(name);
	});
	var observeNow = fmt.asArray(data.current_observed).filter(function(name) {
		return !isAutoIgnoredInterface(name);
	});
	var useTable = refs.ifcfgBody;

	devs.sort(function(a, b) {
		/* recommended LAN devices first, then alphabetical */
		var ra = a.recommended_lan ? 0 : 1;
		var rb = b.recommended_lan ? 0 : 1;
		if (ra !== rb) return ra - rb;
		return fmt.compareText(a.name, b.name);
	});

	refs.ifcfgSummary.textContent = _('采集 %d · 观察 %d · 候选 %d').format(
		attachNow.length, observeNow.length, devs.length);

	function isCollectAllowed(dev) {
		return Boolean(dev && dev.recommended_lan && !dev.is_nss_ifb);
	}

	/* store per-device state in a lookup so segmented toggle can mutate it */
	viewState.ifcfgState = {};
	devs.forEach(function(d) {
		viewState.ifcfgState[d.name] = d.selected && isCollectAllowed(d) ? 'collect'
		                             : (d.observed || d.selected) ? 'observe'
		                             : 'off';
	});

	function makeSeg(name) {
		var wrap = E('div', { 'class': 'lanspeed-ifcfg-seg', 'data-name': name });
		var isCollectable = false;
		var scan = visibleDevices(viewState.sysdevices || {});
		for (var i = 0; i < scan.length; i++) {
			if (scan[i].name === name) {
				isCollectable = isCollectAllowed(scan[i]);
				break;
			}
		}
		var modes = [
			{ k: 'off',     t: _('关闭'), title: _('不挂载、不显示') },
			{ k: 'observe', t: _('观察'), title: _('只读接口计数，不 attach BPF；适合 WAN / WireGuard / nssifb') },
			{ k: 'collect', t: _('采集'),
			  title: !isCollectable
			    ? _('该接口不是推荐的 LAN 二层采集点；WireGuard/TUN/VPN 请改为“观察”。')
			    : _('挂 BPF filter，按客户端拆速率') }
		];
		modes.forEach(function(m) {
			var btn = E('button', {
				'type': 'button',
				'data-mode': m.k,
				'title': m.title,
				'class': viewState.ifcfgState[name] === m.k ? 'active' : ''
			}, m.t);
			if (m.k === 'collect' && !isCollectable)
				btn.disabled = true;
			btn.addEventListener('click', function() {
				var buttons, i;
				if (m.k === 'collect' && !isCollectable)
					return;
				viewState.ifcfgState[name] = m.k;
				buttons = wrap.querySelectorAll('button');
				for (i = 0; i < buttons.length; i++)
					buttons[i].className = (buttons[i].getAttribute('data-mode') === m.k) ? 'active' : '';
			});
			wrap.appendChild(btn);
		});
		return wrap;
	}

	if (useTable) {
		fmt.replaceChildren(refs.ifcfgBody, devs.map(function(d) {
			var tags = [];
			if (d.is_nss_ifb)       tags.push(_('NSS 镜像'));
			if (d.is_bridge)        tags.push(_('网桥'));
			if (d.is_bridge_port)   tags.push(_('桥成员'));
			if (!d.recommended_lan && !d.is_nss_ifb) tags.push(_('非 LAN'));
			if (d.speed_mbps)       tags.push(d.speed_mbps + 'M');

			return E('tr', {}, [
				E('td', { 'class': 'mono' }, d.name),
				E('td', {}, tags.length
					? E('span', { 'class': 'devtags' },
					    tags.map(function(t) { return E('span', { 'class': 'devtag' }, t); }))
					: E('span', { 'class': 'muted' }, '-')),
				E('td', { 'class': 'action' }, makeSeg(d.name))
			]);
		}));
	} else {
		fmt.replaceChildren(refs.ifcfgGrid, devs.map(function(d) {
		var tags = [];
		if (d.is_nss_ifb)       tags.push(_('NSS 镜像'));
		if (d.is_bridge)        tags.push(_('网桥'));
		if (d.is_bridge_port)   tags.push(_('桥成员'));
		if (!d.recommended_lan && !d.is_nss_ifb) tags.push(_('非 LAN'));
		if (d.speed_mbps)       tags.push(d.speed_mbps + 'M');

		return E('div', { 'class': 'lanspeed-ifcfg-card' }, [
			E('div', { 'class': 'lanspeed-ifcfg-card-head' }, [
				E('span', { 'class': 'devname', 'title': d.name }, d.name),
				tags.length
					? E('span', { 'class': 'devtags' },
					    tags.map(function(t) { return E('span', { 'class': 'devtag' }, t); }))
					: ''
			]),
			makeSeg(d.name)
		]);
		}));
	}

	if (!devs.length) {
		refs.ifcfgHint.textContent = _('没有可选设备，请检查 /sys/class/net。');
	} else {
		refs.ifcfgHint.textContent = _('采集 = 挂 BPF 按客户端拆速率。观察 = 只读接口吞吐数字，用于 WAN 展示或对账。');
	}
}

function loadIfaceConfig(viewState) {
	var refs = viewState.refs;
	if (!refs || (!refs.ifcfgGrid && !refs.ifcfgBody)) return Promise.resolve();
	refs.ifcfgStatus.textContent = _('读取中…');
	return lsRpc.sysdevices().then(function(data) {
		viewState.sysdevices = data || { devices: [], current_ifnames: [], current_observed: [] };
		renderIfaceConfig(viewState);
		refs.ifcfgStatus.textContent = '';
	}).catch(function(err) {
		refs.ifcfgStatus.textContent = _('读取失败: ') + (err && err.message || err);
	});
}

function collectIfaceSelections(viewState) {
	var attach = [], observe = [];
	var data = visibleDevices(viewState.sysdevices || {});
	var state = viewState.ifcfgState || {};
	var deviceByName = {};
	var i;

	for (i = 0; i < data.length; i++)
		deviceByName[data[i].name] = data[i];

	Object.keys(state).forEach(function(name) {
		var dev = deviceByName[name];
		if (state[name] === 'collect' && dev && dev.recommended_lan && !dev.is_nss_ifb)
			attach.push(name);
		else if (state[name] === 'observe') observe.push(name);
	});
	return { attach: attach, observe: observe };
}

function prepareIfaceSave(viewState) {
	var sel = collectIfaceSelections(viewState);
	var values = {};
	if (!sel.attach.length && !sel.observe.length) {
		throw new Error(_('请至少选择一个设备'));
	}
	if (sel.attach.length) {
		values.ifname = sel.attach;
		values.interface_include = sel.attach;
	}
	if (sel.observe.length)
		values.observe = sel.observe;

	return { values: values };
}

function applyIfaceSave(plan) {
	/* Delete old lists first so moving every device between modes is atomic at commit. */
	return Promise.resolve()
		.then(function() {
			return lsRpc.uciDelete('lanspeed', 'main',
				['ifname','interface_include','observe']).catch(function(){});
		})
		.then(function() {
			return lsRpc.uciSet('lanspeed', 'main', plan.values);
		});
}

function setBusy(viewState, busy) {
	var refs = viewState.refs;
	if (refs && refs.ifcfgReloadBtn)
		refs.ifcfgReloadBtn.disabled = busy;
}

function buildSection(viewState, title) {
	var refs = viewState.refs || {};

	refs.ifcfgSummary = E('span', { 'class': 'sum' }, _('读取中…'));
	refs.ifcfgBody = E('tbody', {});
	refs.ifcfgStatus = E('span', { 'class': 'status' }, '');
	refs.ifcfgReloadBtn = E('button', {
		'class': 'cbi-button',
		'type': 'button'
	}, _('扫描设备'));
	refs.ifcfgHint = E('p', { 'class': 'lanspeed-hint' }, '');

	refs.ifcfgReloadBtn.addEventListener('click', function() {
		loadIfaceConfig(viewState);
	});

	viewState.refs = refs;

	return E('div', { 'class': 'lanspeed-ifcfg' }, [
		E('div', { 'class': 'lanspeed-header' }, [
			E('h3', {}, title || _('接口配置')),
			E('span', { 'class': 'spacer' }),
			refs.ifcfgSummary
		]),
		E('div', { 'class': 'lanspeed-ifcfg-body' }, [
			E('table', { 'class': 'lanspeed-ifcfg-table' }, [
				E('thead', {}, E('tr', {}, [
					E('th', {}, _('接口')),
					E('th', {}, _('标记')),
					E('th', { 'class': 'action' }, _('模式'))
				])),
				refs.ifcfgBody
			]),
			E('div', { 'class': 'lanspeed-ifcfg-actions' }, [
				refs.ifcfgReloadBtn,
				E('span', { 'class': 'spacer' }),
				refs.ifcfgStatus
			]),
			refs.ifcfgHint
		])
	]);
}

return baseclass.extend({
	buildSection:       buildSection,
	load:              loadIfaceConfig,
	render:            renderIfaceConfig,
	collectSelections: collectIfaceSelections,
	prepareSave:       prepareIfaceSave,
	applySave:         applyIfaceSave,
	setBusy:           setBusy,
	isAutoIgnored:     isAutoIgnoredInterface
});
