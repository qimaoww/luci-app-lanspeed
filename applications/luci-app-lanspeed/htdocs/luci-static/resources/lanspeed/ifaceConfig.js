'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';

/*
 * LAN Speed interface configuration sub-panel.
 *
 * Owns the "scan sysdevices - render segmented toggles - save UCI + reload
 * daemon" flow.  Expects viewState.refs to contain the ifcfg* refs
 * populated by the shell builder or by buildSection(), and viewState.reload()
 * to be wired. The render/save flow owns the contents of refs.ifcfgGrid and
 * status/button state changes.
 */

function renderIfaceConfig(viewState) {
	var refs = viewState.refs;
	var data = viewState.sysdevices || { devices: [] };
	var devs = fmt.asArray(data.devices);
	var attachNow = fmt.asArray(data.current_ifnames);
	var observeNow = fmt.asArray(data.current_observed);
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
		var scan = fmt.asArray((viewState.sysdevices || {}).devices);
		for (var i = 0; i < scan.length; i++) {
			if (scan[i].name === name) {
				isCollectable = isCollectAllowed(scan[i]);
				break;
			}
		}
		var modes = [
			{ k: 'off',     t: _('关闭'), title: _('不挂载、不显示') },
			{ k: 'observe', t: _('观察'), title: _('只读接口计数，不 attach BPF；适合 WAN / WireGuard / TUN / nssifb') },
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
	if (!refs || (!refs.ifcfgGrid && !refs.ifcfgBody)) return;
	refs.ifcfgStatus.textContent = _('读取中…');
	lsRpc.sysdevices().then(function(data) {
		viewState.sysdevices = data || { devices: [], current_ifnames: [], current_observed: [] };
		renderIfaceConfig(viewState);
		refs.ifcfgStatus.textContent = '';
	}).catch(function(err) {
		refs.ifcfgStatus.textContent = _('读取失败: ') + (err && err.message || err);
	});
}

function collectIfaceSelections(viewState) {
	var attach = [], observe = [];
	var data = fmt.asArray((viewState.sysdevices || {}).devices);
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

function saveIfaceConfig(viewState) {
	var refs = viewState.refs;
	if (!refs || viewState.ifcfgSaving) return;
	var sel = collectIfaceSelections(viewState);
	var values = {};
	if (!sel.attach.length && !sel.observe.length) {
		refs.ifcfgStatus.textContent = _('请至少选择一个设备');
		return;
	}
	if (sel.attach.length) {
		values.ifname = sel.attach;
		values.interface_include = sel.attach;
	}
	if (sel.observe.length)
		values.observe = sel.observe;

	viewState.ifcfgSaving = true;
	refs.ifcfgSaveBtn.disabled = true;
	refs.ifcfgReloadBtn.disabled = true;
	refs.ifcfgStatus.textContent = _('保存中…');

	/* delete old lists (tolerate missing options), then set new ones, commit, reload daemon */
	Promise.resolve()
		.then(function() {
			return lsRpc.uciDelete('lanspeed', 'main',
				['ifname','interface_include','observe']).catch(function(){});
		})
		.then(function() {
			return lsRpc.uciSet('lanspeed', 'main', values);
		})
		.then(function() { return lsRpc.uciCommit('lanspeed'); })
		.then(function() {
			refs.ifcfgStatus.textContent = _('重载 daemon…');
			return lsRpc.reload();
		})
		.then(function() {
			return new Promise(function(resolve) { window.setTimeout(resolve, 1000); });
		})
		.then(function() {
			refs.ifcfgStatus.textContent = _('已应用');
			return Promise.all([viewState.reload(true), loadIfaceConfig(viewState)]);
		})
		.catch(function(err) {
			refs.ifcfgStatus.textContent = _('保存失败: ') + (err && err.message || err);
		})
		.then(function() {
			refs.ifcfgSaveBtn.disabled = false;
			refs.ifcfgReloadBtn.disabled = false;
			viewState.ifcfgSaving = false;
			window.setTimeout(function() {
				if (refs.ifcfgStatus.textContent === _('已应用'))
					refs.ifcfgStatus.textContent = '';
			}, 3000);
		});
}

function buildSection(viewState, title) {
	var refs = viewState.refs || {};

	refs.ifcfgSummary = E('span', { 'class': 'sum' }, _('读取中…'));
	refs.ifcfgBody = E('tbody', {});
	refs.ifcfgStatus = E('span', { 'class': 'status' }, '');
	refs.ifcfgSaveBtn = E('button', {
		'class': 'cbi-button cbi-button-apply',
		'type': 'button'
	}, _('保存并重载'));
	refs.ifcfgReloadBtn = E('button', {
		'class': 'cbi-button',
		'type': 'button'
	}, _('扫描设备'));
	refs.ifcfgHint = E('p', { 'class': 'lanspeed-hint' }, '');

	refs.ifcfgSaveBtn.addEventListener('click', function() {
		saveIfaceConfig(viewState);
	});
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
				refs.ifcfgSaveBtn,
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
	save:              saveIfaceConfig
});
