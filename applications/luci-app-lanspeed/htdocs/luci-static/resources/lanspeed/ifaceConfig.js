'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';

/*
 * LAN Speed interface configuration sub-panel.
 *
 * Owns the "scan sysdevices - render segmented toggles - save UCI + reload
 * daemon" flow.  Expects viewState.refs to contain the ifcfg* refs
 * populated by the shell builder, and viewState.reload() / viewState.prefs
 * to be wired.  No DOM construction of section frame here - only the
 * contents of refs.ifcfgGrid and status/button state changes.
 */

function renderIfaceConfig(viewState) {
	var refs = viewState.refs;
	var data = viewState.sysdevices || { devices: [] };
	var devs = fmt.asArray(data.devices);
	var attachNow = fmt.asArray(data.current_ifnames);
	var observeNow = fmt.asArray(data.current_observed);

	devs.sort(function(a, b) {
		/* recommended LAN devices first, then alphabetical */
		var ra = a.recommended_lan ? 0 : 1;
		var rb = b.recommended_lan ? 0 : 1;
		if (ra !== rb) return ra - rb;
		return fmt.compareText(a.name, b.name);
	});

	refs.ifcfgSummary.textContent = _('采集 %d · 观察 %d · 候选 %d').format(
		attachNow.length, observeNow.length, devs.length);

	/* store per-device state in a lookup so segmented toggle can mutate it */
	viewState.ifcfgState = {};
	devs.forEach(function(d) {
		viewState.ifcfgState[d.name] = d.selected ? 'collect'
		                             : d.observed ? 'observe'
		                             : 'off';
	});

	function makeSeg(name) {
		var wrap = E('div', { 'class': 'lanspeed-ifcfg-seg', 'data-name': name });
		var isNssIfb = false;
		var scan = fmt.asArray((viewState.sysdevices || {}).devices);
		for (var i = 0; i < scan.length; i++) {
			if (scan[i].name === name && scan[i].is_nss_ifb) { isNssIfb = true; break; }
		}
		var modes = [
			{ k: 'off',     t: _('关闭'), title: _('不挂载、不显示') },
			{ k: 'observe', t: _('观察'), title: _('只读接口计数，不 attach BPF；适合 WAN / tun / nssifb') },
			{ k: 'collect', t: _('采集'),
			  title: isNssIfb
			    ? _('nssifb 是 NSS 镜像接口，对它 attach BPF 会看到镜像流量而不是真实客户端流量，不推荐。')
			    : _('挂 BPF filter，按客户端拆速率；置信度 high') }
		];
		modes.forEach(function(m) {
			var btn = E('button', {
				'type': 'button',
				'data-mode': m.k,
				'title': m.title,
				'class': viewState.ifcfgState[name] === m.k ? 'active' : ''
			}, m.t);
			btn.addEventListener('click', function() {
				viewState.ifcfgState[name] = m.k;
				wrap.querySelectorAll('button').forEach(function(b) {
					b.className = (b.getAttribute('data-mode') === m.k) ? 'active' : '';
				});
			});
			wrap.appendChild(btn);
		});
		return wrap;
	}

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

	if (!devs.length) {
		refs.ifcfgHint.textContent = _('没有可选设备，请检查 /sys/class/net。');
	} else {
		refs.ifcfgHint.textContent = _('采集 = 挂 BPF 按客户端拆速率。观察 = 只读接口吞吐数字，用于 WAN 展示或对账。');
	}
}

function loadIfaceConfig(viewState) {
	var refs = viewState.refs;
	if (!refs || !refs.ifcfgGrid) return;
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
	var state = viewState.ifcfgState || {};
	Object.keys(state).forEach(function(name) {
		if (state[name] === 'collect') attach.push(name);
		else if (state[name] === 'observe') observe.push(name);
	});
	return { attach: attach, observe: observe };
}

function saveIfaceConfig(viewState) {
	var refs = viewState.refs;
	if (!refs || viewState.ifcfgSaving) return;
	var sel = collectIfaceSelections(viewState);
	if (!sel.attach.length && !sel.observe.length) {
		refs.ifcfgStatus.textContent = _('请至少选择一个设备');
		return;
	}

	viewState.ifcfgSaving = true;
	refs.ifcfgSaveBtn.disabled = true;
	refs.ifcfgReloadBtn.disabled = true;
	refs.ifcfgStatus.textContent = _('保存中…');

	/* Client-side guard: reject nssifb in collect list even if the user
	 * toggled it somehow. daemon also rejects on load, but failing fast
	 * here is friendlier. */
	if (sel.attach.indexOf('nssifb') !== -1) {
		viewState.ifcfgSaving = false;
		refs.ifcfgSaveBtn.disabled = false;
		refs.ifcfgReloadBtn.disabled = false;
		refs.ifcfgStatus.textContent = _('nssifb 不能用作采集接口；请改"观察"');
		return;
	}

	/* delete old lists (tolerate missing options), then set new ones, commit, reload daemon */
	Promise.resolve()
		.then(function() {
			return lsRpc.uciDelete('lanspeed', 'main',
				['ifname','interface_include','observe']).catch(function(){});
		})
		.then(function() {
			return lsRpc.uciSet('lanspeed', 'main', {
				ifname:            sel.attach,
				interface_include: sel.attach,
				observe:           sel.observe
			});
		})
		.then(function() { return lsRpc.uciCommit('lanspeed'); })
		.then(function() {
			refs.ifcfgStatus.textContent = _('重载 daemon…');
			return lsRpc.init('lanspeedd', 'reload').catch(function() {});
		})
		.then(function() {
			return new Promise(function(resolve) { window.setTimeout(resolve, 4000); });
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

return baseclass.extend({
	load:              loadIfaceConfig,
	render:            renderIfaceConfig,
	collectSelections: collectIfaceSelections,
	save:              saveIfaceConfig
});
