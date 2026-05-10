'use strict';
'require view';
'require rpc';

/*
 * LAN Speed LuCI status view.
 *
 * Theming rule: use LuCI-native classes everywhere. The only custom CSS is
 * layout (flex / grid) and tabular numerics. Colours, backgrounds, borders,
 * button styles and form controls inherit from whichever LuCI theme is
 * active (bootstrap / argon / aurora / material / dark / light …).
 *
 * Architecture (kept from v2): buildShell() constructs the DOM once, stashes
 * mutation points in viewState.refs. refreshLive() mutates only the dynamic
 * cells; toolbar controls keep their focus / value across ticks.
 */

var callStatus = rpc.declare({
	object: 'lanspeed',
	method: 'status',
	expect: { '': {} }
});
var callClients = rpc.declare({
	object: 'lanspeed',
	method: 'clients',
	expect: { '': {} }
});
var callInterfaces = rpc.declare({
	object: 'lanspeed',
	method: 'interfaces',
	expect: { '': {} }
});
var callInit = rpc.declare({
	object: 'rc',
	method: 'init',
	params: [ 'name', 'action' ],
	expect: { '': {} }
});
var callSysdevices = rpc.declare({
	object: 'lanspeed',
	method: 'sysdevices',
	expect: { '': {} }
});
var callUciSet = rpc.declare({
	object: 'uci',
	method: 'set',
	params: [ 'config', 'section', 'values' ]
});
var callUciDelete = rpc.declare({
	object: 'uci',
	method: 'delete',
	params: [ 'config', 'section', 'options' ]
});
var callUciCommit = rpc.declare({
	object: 'uci',
	method: 'commit',
	params: [ 'config' ]
});

var MIN_REFRESH_MS = 1000;
var INACTIVE_BPS_THRESHOLD = 1024;
var DELTA_SIGNIFICANT_RATIO = 0.10;
var DELTA_SIGNIFICANT_MIN_BPS = 20000;
var PREF_KEY = 'luci-app-lanspeed.prefs.v3';

var REFRESH_CHOICES = [
	{ value:  1000, label: '1s'  },
	{ value:  2000, label: '2s'  },
	{ value:  3000, label: '3s'  },
	{ value:  5000, label: '5s'  },
	{ value: 10000, label: '10s' }
];

/* ---------- vocabulary ---------- */

var CAPABILITY_LABELS = {
	bpf: 'BPF',
	bpf_package: _('BPF 软件包'),
	bpf_object: _('BPF 对象'),
	bpf_runtime_metrics: _('BPF 实时指标'),
	conntrack_fallback: _('conntrack 降级采集'),
	live_metrics: _('实时指标'),
	fw4: 'fw4',
	nft: 'nftables',
	software_flow_offload: _('软件流量卸载'),
	hardware_flow_offload: _('硬件流量卸载'),
	nss: _('Qualcomm NSS'),
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
	'nss', 'nss_dp', 'nss_ecm_offload', 'nss_ppe_offload', 'nss_nsm',
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
	openclash_tun_conntrack_low_confidence: _('OpenClash TUN/mix 经 conntrack 降级采集时置信度较低。'),
	openclash_dns_chain_incomplete: _('OpenClash DNS 链路不完整，解析相关归因可能不可靠。'),
	openclash_router_self_proxy_detected: _('OpenClash router-self 代理：路由器自身流量不会归入任一 LAN 客户端。'),
	openclash_tun_mix_detected: _('OpenClash TUN/mix 可能让部分路径绕过 CPU 可见 LAN 边缘指标。'),
	openclash_udp_proxy_detected: _('OpenClash UDP 代理会降低按客户端归因的置信度。'),
	dae_detected: _('检测到 dae/daed，代理或 TUN 接口只作为上行证据，不作为 LAN 客户端身份。'),
	tc_filter_conflict: _('已有 TC filter 与 lanspeed 挂载点冲突，lanspeedd 不会覆盖它。'),
	existing_tc_filters_detected: _('已存在其它 TC filter，lanspeedd 只告警，不删除或重排。'),
	sqm_detected: _('检测到 SQM，IFB 整形可能影响观察到的方向或覆盖范围。'),
	qosify_detected: _('检测到 qosify，已有分类器会被保留，置信度可能受影响。'),
	ifb_detected: _('检测到 IFB，入口整形可能改变 CPU 可见路径。'),
	software_flow_offload_enabled: _('软件流量卸载已启用；tc/BPF 挂载在它之前，客户端粒度仍然可见。'),
	hardware_flow_offload_unsupported: _('硬件流量卸载已启用，硬件转发流量可能绕过 CPU 可见指标。'),
	nss_detected: _('检测到 Qualcomm NSS 网络协处理器。流量被加速的部分不经过 CPU，BPF 仅能看到慢路径。'),
	nss_ecm_offload_active: _('NSS ECM 正在硬件加速连接，客户端数据经 ECM→conntrack 同步得到，置信度受限。'),
	nss_ecm_sync_cadence: _('NSS 硬件卸载中：客户端计数经 ECM/PPE 同步回 conntrack，精度为秒级节拍，不是逐包实时。'),
	nss_ifb_detected: _('检测到 NSS IFB（nssifb）：NSS 硬件 QoS 的镜像接口，其计数是物理口 ingress 的镜像，不应 attach BPF，只能作为观察对象。'),
	nssifb_collect_rejected: _('配置中请求 attach BPF 到 nssifb，daemon 已忽略——nssifb 是 NSS 镜像接口，attach 会重复计数物理口 ingress。请改用"观察"模式。'),
	nss_ppe_offload_active: _('NSS PPE 正在硬件加速连接（IPQ95xx/53xx 新一代硬件加速），BPF 只能看到慢路径。'),
	fullcone_detected: _('检测到 Fullcone NAT，NAT 辅助路径会作为置信度告警展示。'),
	fullcone_nat_enabled: _('Fullcone NAT 已启用，NAT 辅助路径会作为置信度告警展示。'),
	conntrack_routed_nat_only: _('conntrack 降级采集仅覆盖路由 / NAT 流量。'),
	conntrack_acct_disabled: _('conntrack 计数未启用，无法使用 conntrack 降级速率采集。'),
	nf_conntrack_acct_disabled: _('nf_conntrack_acct 未启用，conntrack 降级采集不可用。'),
	flowtable_counter_missing: _('未检测到 flowtable 计数，降级采集置信度会降低。'),
	nlbwmon_counter_conflict: _('检测到 nlbwmon 计数冲突，lanspeed 不读取或清零 nlbwmon 计数。'),
	bpf_optional_package_missing: _('缺少可选 BPF 软件包，无法使用实时 BPF 指标。'),
	bpf_object_missing: _('缺少 BPF 对象文件，无法使用实时 BPF 指标。'),
	bpf_runtime_loader_unavailable: _('BPF 资产齐备但本次启动没有成功完成 tc 挂载或 map 读取，已回落到 conntrack 模式。'),
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
	conntrack_unavailable: _('conntrack 数据不可用，无法生成降级采集结果。'),
	flow_offload_confidence_low: _('流量卸载会降低降级采集置信度。'),
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

/* ---------- preferences ---------- */

var DEFAULT_PREFS = {
	refreshMs: 3000,
	unit: 'bit',
	activeOnly: false,
	sortKey: 'speed',
	paused: false,
	ifaceExcluded: []
};
function loadPrefs() {
	try {
		var raw = window.localStorage.getItem(PREF_KEY);
		if (!raw) return Object.assign({}, DEFAULT_PREFS);
		return Object.assign({}, DEFAULT_PREFS, JSON.parse(raw));
	} catch (e) { return Object.assign({}, DEFAULT_PREFS); }
}
function savePrefs(p) { try { window.localStorage.setItem(PREF_KEY, JSON.stringify(p)); } catch (e) {} }

/* ---------- helpers ---------- */

function asArray(v) { return Array.isArray(v) ? v : []; }
function textOrDash(v) { return (v === null || v === undefined || v === '') ? '-' : String(v); }
function identityOf(c) { return c.identity_key || [c.mac, c.zone].filter(Boolean).join('@') || '-'; }
function clientDisplayName(c) { return c.hostname || c.mac || identityOf(c); }

function normalizeConfidence(v) { return String(v || 'unsupported').toLowerCase(); }

function confidenceClass(v) {
	v = normalizeConfidence(v);
	if (v === 'high')   return 'label label-success';
	if (v === 'medium') return 'label label-warning';
	return 'label label-danger';
}
function confidenceText(v) {
	v = normalizeConfidence(v);
	if (v === 'high')        return _('高');
	if (v === 'medium')      return _('中');
	if (v === 'low')         return _('低');
	if (v === 'unsupported') return _('不支持');
	return textOrDash(v);
}

function modeClass(m) {
	if (m === 'Full')        return 'label label-success';
	if (m === 'Degraded')    return 'label label-warning';
	return 'label label-danger';
}
function modeText(m) {
	if (m === 'Full')        return 'Full';
	if (m === 'Degraded')    return 'Degraded';
	if (m === 'Unsupported') return 'Unsupported';
	return textOrDash(m);
}

function warningText(w) { return WARNING_LABELS[w] || String(w).replace(/_/g, ' '); }
function warningClass(w) {
	if (CRITICAL_WARNINGS[w] || /hardware|unsafe|conflict|missing|error|failed|full/.test(w))
		return 'label label-danger';
	return 'label label-warning';
}
function capabilityClass(key, enabled) {
	if (!enabled) return 'label';
	if (key === 'hardware_flow_offload' || key === 'map_full') return 'label label-danger';
	if (['software_flow_offload','fullcone','openclash_fake_ip','openclash_tun_mix',
	     'openclash_router_self_proxy','dae','sqm','qosify','ifb','existing_tc_filters']
	    .indexOf(key) !== -1) return 'label label-warning';
	return 'label label-success';
}

function formatRate(valueBps, unit) {
	var n = Number(valueBps) || 0, units, div;
	if (unit === 'byte') { n /= 8; units = ['B/s','KB/s','MB/s','GB/s','TB/s']; div = 1024; }
	else                 { units = ['bps','Kbps','Mbps','Gbps','Tbps']; div = 1000; }
	if (n < 1) return '0';
	var i = 0;
	while (n >= div && i < units.length - 1) { n /= div; i++; }
	return (i === 0 ? '%d %s' : '%.2f %s').format(n, units[i]);
}

function formatLastSeen(v) {
	var n = Number(v) || 0;
	if (n <= 0) return '-';
	if (n > 1e12) return new Date(n).toLocaleTimeString();
	if (n > 1e9)  return new Date(n * 1000).toLocaleTimeString();
	return _('%d 秒前').format(n);
}

function compareText(a, b) {
	return String(a || '').localeCompare(String(b || ''), undefined, { numeric: true, sensitivity: 'base' });
}
function sumTotals(clients) {
	var tx = 0, rx = 0, active = 0;
	clients.forEach(function(c) {
		var t = Number(c.tx_bps) || 0, r = Number(c.rx_bps) || 0;
		tx += t; rx += r;
		if (t + r >= INACTIVE_BPS_THRESHOLD) active++;
	});
	return { tx: tx, rx: rx, active: active };
}
function sortClients(clients, sortKey) {
	var sorted = clients.slice();
	sorted.sort(function(a, b) {
		var r;
		if (sortKey === 'hostname')       r = compareText(clientDisplayName(a), clientDisplayName(b));
		else if (sortKey === 'mac')       r = compareText(a.mac, b.mac);
		else if (sortKey === 'tx')        r = (Number(b.tx_bps) || 0) - (Number(a.tx_bps) || 0);
		else if (sortKey === 'rx')        r = (Number(b.rx_bps) || 0) - (Number(a.rx_bps) || 0);
		else if (sortKey === 'last_seen') r = (Number(b.last_seen) || 0) - (Number(a.last_seen) || 0);
		else                              r = ((Number(b.tx_bps) || 0) + (Number(b.rx_bps) || 0)) -
		                                      ((Number(a.tx_bps) || 0) + (Number(a.rx_bps) || 0));
		return r || compareText(identityOf(a), identityOf(b));
	});
	return sorted;
}
function matchesFilter(c, term) {
	if (!term) return true;
	var hay = [clientDisplayName(c), c.mac, c.zone, c.interface, asArray(c.ips).join(' ')]
		.filter(Boolean).join(' ').toLowerCase();
	return hay.indexOf(term.toLowerCase()) !== -1;
}

function replaceChildren(node, children) {
	while (node.firstChild) node.removeChild(node.firstChild);
	asArray(children).forEach(function(c) {
		if (c === null || c === undefined || c === '') return;
		node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
	});
}

/*
 * HTML `<option selected="false">` is still selected because the spec treats
 * the attribute as a boolean presence, not a truthy value. LuCI's E() helper
 * setAttribute's whatever you pass, so we must only emit `selected` when it
 * should actually be selected.
 */
function opt(value, label, isSelected) {
	var attrs = { 'value': String(value) };
	if (isSelected) attrs.selected = 'selected';
	return E('option', attrs, label);
}

/* ---------- interface configuration ---------- */

function loadIfaceConfig(viewState) {
	var refs = viewState.refs;
	if (!refs || !refs.ifcfgGrid) return;
	refs.ifcfgStatus.textContent = _('读取中…');
	callSysdevices().then(function(data) {
		viewState.sysdevices = data || { devices: [], current_ifnames: [], current_observed: [] };
		renderIfaceConfig(viewState);
		refs.ifcfgStatus.textContent = '';
	}).catch(function(err) {
		refs.ifcfgStatus.textContent = _('读取失败: ') + (err && err.message || err);
	});
}

function renderIfaceConfig(viewState) {
	var refs = viewState.refs;
	var data = viewState.sysdevices || { devices: [] };
	var devs = asArray(data.devices);
	var attachNow = asArray(data.current_ifnames);
	var observeNow = asArray(data.current_observed);

	devs.sort(function(a, b) {
		/* recommended LAN devices first, then alphabetical */
		var ra = a.recommended_lan ? 0 : 1;
		var rb = b.recommended_lan ? 0 : 1;
		if (ra !== rb) return ra - rb;
		return compareText(a.name, b.name);
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
		var devs = asArray((viewState.sysdevices || {}).devices);
		for (var i = 0; i < devs.length; i++) {
			if (devs[i].name === name && devs[i].is_nss_ifb) { isNssIfb = true; break; }
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

	replaceChildren(refs.ifcfgGrid, devs.map(function(d) {
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
			return callUciDelete('lanspeed', 'main',
				['ifname','interface_include','observe']).catch(function(){});
		})
		.then(function() {
			return callUciSet('lanspeed', 'main', {
				ifname:            sel.attach,
				interface_include: sel.attach,
				observe:           sel.observe
			});
		})
		.then(function() { return callUciCommit('lanspeed'); })
		.then(function() {
			refs.ifcfgStatus.textContent = _('重载 daemon…');
			return callInit('lanspeedd', 'reload').catch(function() {});
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

/* ---------- minimal layout-only CSS ----------
 *
 * NO colours, backgrounds, borders, button styles or card frames are set
 * here. LuCI's active theme paints everything via .cbi-section / .label /
 * .cbi-button* / .cbi-input-*; we only control flex/grid flow and tabular
 * numerics. The only colour we reference is the theme's own --border
 * custom-property for thin divider lines.
 *
 * Alignment strategy: every logical block is wrapped in its own
 * .cbi-section card, so every child (h3, metrics, toolbar, table) shares
 * the same left edge inside the card's 20px inner padding.  The client
 * table deliberately drops `.table` class to avoid card-in-card framing
 * and uses .lanspeed-table with :first-child/:last-child padding overrides
 * so row content stays flush with the section's h3.
 */
var LAYOUT_CSS = [
	/* section header row: h3 + pills on one baseline, meta pushed right */
	'.lanspeed-header{display:flex;flex-wrap:wrap;gap:.4em 1em;align-items:baseline;',
	'  padding-bottom:.65em;margin:0 0 1em 0;',
	'  border-bottom:1px solid var(--border,rgba(128,128,128,.25))}',
	'.lanspeed-header>h3{margin:0;padding:0;border:0;flex:0 0 auto;line-height:1.25}',
	'.lanspeed-header>.spacer{flex:1 1 auto}',
	'.lanspeed-header>.meta{font-size:.85em;opacity:.75;',
	'  font-family:var(--font-monospace,ui-monospace,monospace)}',

	/* metrics row */
	'.lanspeed-metrics{display:flex;flex-wrap:wrap;gap:1em 2.5em;align-items:flex-end;margin:0}',
	'.lanspeed-metric{min-width:9em}',
	'.lanspeed-metric .caption{font-size:.75em;text-transform:uppercase;letter-spacing:.04em;opacity:.7;margin:0}',
	'.lanspeed-metric .big{font-size:1.6em;font-weight:600;font-variant-numeric:tabular-nums;',
	'  line-height:1.2;margin:.1em 0}',
	'.lanspeed-metric .hint{font-size:.8em;opacity:.7;margin:0}',

	/* critical warning strip (inside overview card, under metrics) */
	'.lanspeed-strip{display:flex;flex-wrap:wrap;gap:.3em;margin:1em 0 0 0}',
	'.lanspeed-strip:empty{display:none;margin:0}',

	/* toolbar lives inside the clients card */
	'.lanspeed-toolbar{display:flex;flex-wrap:wrap;gap:.5em;align-items:center;margin:0 0 1em 0}',
	'.lanspeed-toolbar>.spacer{flex:1 1 auto}',
	'.lanspeed-toolbar label{display:inline-flex;gap:.3em;align-items:center;font-size:.9em}',
	'.lanspeed-toolbar input[type=search]{min-width:12em}',

	/* compact, borderless table designed to live INSIDE a .cbi-section.
	   :first-child/:last-child padding overrides keep cells flush with
	   the surrounding h3/toolbar left edge. */
	'.lanspeed-table{width:100%;border-collapse:collapse;margin:0;table-layout:auto}',
	'.lanspeed-table th,.lanspeed-table td{padding:.45em .6em;text-align:left;',
	'  border-bottom:1px solid var(--border,rgba(128,128,128,.18));',
	'  vertical-align:middle;background:transparent}',
	'.lanspeed-table thead th{font-weight:600;opacity:.85}',
	'.lanspeed-table tbody tr:last-child td{border-bottom:0}',
	'.lanspeed-table th:first-child,.lanspeed-table td:first-child{padding-left:0}',
	'.lanspeed-table th:last-child,.lanspeed-table td:last-child{padding-right:0}',
	'.lanspeed-table .num{text-align:left;font-variant-numeric:tabular-nums;white-space:nowrap}',
	'.lanspeed-table .mono{font-family:var(--font-monospace,ui-monospace,monospace);',
	'  font-size:.9em;white-space:nowrap}',
	'.lanspeed-table tr.idle td{opacity:.55}',
	'.lanspeed-table td .ipline{display:block;font-size:.8em;opacity:.7;margin-top:.15em;',
	'  font-family:var(--font-monospace,ui-monospace,monospace);max-width:22em;',
	'  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
	'.lanspeed-table td .state{display:inline-flex;gap:.25em;flex-wrap:wrap;align-items:center}',

	/* capability grid inside diagnostics card */
	'.lanspeed-caps{display:grid;grid-template-columns:repeat(auto-fill,minmax(15em,1fr));',
	'  gap:.3em .8em;margin:.2em 0 1em 0}',
	'.lanspeed-caps .cap{display:flex;justify-content:space-between;align-items:center;',
	'  gap:.5em;padding:.15em 0}',

	/* interface configuration card:
	   each device gets its own small card. Top row: name + tags.
	   Bottom row: segmented 3-way toggle (off / observe / collect). */
	'.lanspeed-ifcfg{display:flex;flex-direction:column;gap:1em;margin:0}',
	'.lanspeed-ifcfg-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(20em,1fr));',
	'  gap:1em;margin:0}',
	'.lanspeed-ifcfg-card{display:flex;flex-direction:column;gap:.9em;',
	'  padding:1em 1.1em;border:1px solid var(--border,rgba(128,128,128,.25));',
	'  border-radius:.5em}',
	'.lanspeed-ifcfg-card-head{display:flex;align-items:baseline;gap:.6em;min-width:0}',
	'.lanspeed-ifcfg-card-head .devname{flex:1 1 auto;min-width:0;font-weight:600;',
	'  font-family:var(--font-monospace,ui-monospace,monospace);',
	'  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
	'.lanspeed-ifcfg-card-head .devtags{flex:0 0 auto;font-size:.75em;opacity:.65;',
	'  display:inline-flex;gap:.4em;flex-wrap:wrap}',
	'.lanspeed-ifcfg-card-head .devtags .devtag{padding:.05em .45em;border-radius:.25em;',
	'  background:var(--label-surface,rgba(128,128,128,.12))}',
	/* segmented toggle: 3 buttons side by side with visible gap between them */
	'.lanspeed-ifcfg-seg{display:flex;gap:.45em;align-items:stretch}',
	'.lanspeed-ifcfg-seg>button{flex:1 1 0;min-width:0;padding:.5em .7em;',
	'  font-size:.9em;border:1px solid var(--border,rgba(128,128,128,.3));',
	'  border-radius:.4em;background:transparent;cursor:pointer;color:inherit;',
	'  transition:background-color .1s ease,border-color .1s ease}',
	'.lanspeed-ifcfg-seg>button:hover{background:var(--label-surface,rgba(128,128,128,.1))}',
	'.lanspeed-ifcfg-seg>button.active{',
	'  background:var(--primary,var(--label-surface,rgba(80,120,200,.15)));',
	'  color:var(--primary-foreground,inherit);',
	'  border-color:var(--primary,var(--border,rgba(128,128,128,.3)));',
	'  font-weight:600}',
	'.lanspeed-ifcfg-actions{display:flex;flex-wrap:wrap;gap:.5em;align-items:center;',
	'  margin:.4em 0 0 0}',
	'.lanspeed-ifcfg-actions>.spacer{flex:1 1 auto}',
	'.lanspeed-ifcfg-actions .status{font-size:.85em;opacity:.75;',
	'  font-family:var(--font-monospace,ui-monospace,monospace)}',

	/* warnings list */
	'.lanspeed-warnings{margin:.2em 0 1em 0;padding-left:1.2em}',
	'.lanspeed-warnings li{margin:.2em 0;font-size:.9em}',
	'.lanspeed-warnings li .key{margin-right:.4em}',

	/* sub-heading used inside diagnostics card */
	'.lanspeed-subhead{margin:.2em 0 .4em 0;font-size:1em;font-weight:600;opacity:.85}',
	'.lanspeed-subhead:first-child{margin-top:0}',

	/* details used as a collapsible card header.  We replace the native
	   list-item marker with our own text triangle (right when closed,
	   down when open) so the summary text and the marker align with the
	   section\'s left edge.  Uses a content swap instead of CSS rotate
	   to avoid being clobbered by aurora\'s transform custom-properties. */
	'.lanspeed-details{margin:0}',
	'.lanspeed-details>summary{cursor:pointer;list-style:none;padding:0;margin:0;',
	'  display:flex;flex-wrap:wrap;gap:.4em 1em;align-items:baseline;',
	'  padding-bottom:.65em;margin-bottom:1em;',
	'  border-bottom:1px solid var(--border,rgba(128,128,128,.25))}',
	'.lanspeed-details>summary::-webkit-details-marker{display:none}',
	'.lanspeed-details>summary::marker{content:""}',
	'.lanspeed-details>summary::before{content:"\u25B8";display:inline-block;',
	'  width:1em;flex:0 0 auto;opacity:.6;font-size:.85em}',
	'.lanspeed-details[open]>summary::before{content:"\u25BE"}',
	'.lanspeed-details>summary>h3{margin:0;padding:0;border:0;flex:0 0 auto;',
	'  line-height:1.25;display:inline}',
	'.lanspeed-details>summary>.spacer{flex:1 1 auto}',
	'.lanspeed-details>summary .sum{font-size:.85em;opacity:.75;',
	'  font-family:var(--font-monospace,ui-monospace,monospace)}',
	'.lanspeed-details-body{margin:0}',

	/* empty and hint text */
	'.lanspeed-empty{padding:1.2em 0;text-align:center;opacity:.7}',
	'.lanspeed-hint{margin:.8em 0 0 0;font-size:.85em;opacity:.75}'
].join('\n');

/* ---------- shell ----------
 *
 * DOM layout (Aurora-aware, but theme-neutral):
 *
 *   <div class="cbi-map">
 *     <style>...</style>
 *     <div class="cbi-section">        overview card
 *       <div class="lanspeed-header"><h3/>…pills…meta</div>
 *       <div class="alert-message error">…</div>    (hidden by default)
 *       <div class="lanspeed-metrics">…</div>
 *       <div class="lanspeed-strip">…critical…</div>
 *     </div>
 *     <div class="cbi-section">        clients card
 *       <div class="lanspeed-header"><h3/>…</div>
 *       <div class="lanspeed-toolbar">…</div>
 *       <table class="lanspeed-table">…</table>
 *       <div class="lanspeed-empty">…</div>
 *     </div>
 *     <div class="cbi-section">        interfaces card (details)
 *       <details class="lanspeed-details">
 *         <summary><h3/>…</summary>
 *         <div class="lanspeed-details-body">…</div>
 *       </details>
 *     </div>
 *     <div class="cbi-section">        diagnostics card (details)
 *       <details class="lanspeed-details">…</details>
 *     </div>
 *   </div>
 *
 * Every visible child inside a .cbi-section starts at the section\'s
 * left inner-padding edge — h3, metrics, toolbar and table cells are all
 * flush to the same vertical line.
 */

function buildShell(viewState) {
	var refs = {};
	var prefs = viewState.prefs;

	/* ---- overview card ---- */
	refs.modePill = E('span', { 'class': 'label' }, '-');
	refs.confPill = E('span', { 'class': 'label' }, '-');
	refs.meta     = E('span', { 'class': 'meta' }, '');
	var overviewHeader = E('div', { 'class': 'lanspeed-header' }, [
		E('h3', {}, _('LAN Speed')),
		refs.modePill,
		refs.confPill,
		E('span', { 'class': 'spacer' }),
		refs.meta
	]);

	refs.errorPre = E('pre', {
		'style': 'white-space:pre-wrap;margin:.4em 0 0 0;font-size:.85em'
	}, '');
	refs.errorBox = E('div', {
		'class': 'alert-message error',
		'style': 'display:none;margin:0 0 1em 0'
	}, [
		E('strong', {}, _('无法加载 LAN Speed 状态')),
		refs.errorPre
	]);

	refs.mTx         = E('div', { 'class': 'big' }, '0');
	refs.mRx         = E('div', { 'class': 'big' }, '0');
	refs.mClients    = E('div', { 'class': 'big' }, '0');
	refs.mClientsSub = E('div', { 'class': 'hint' }, '-');
	refs.mCoverage     = E('div', { 'class': 'big' }, '-');
	refs.mCoverageSub  = E('div', { 'class': 'hint' }, '-');
	var metrics = E('div', { 'class': 'lanspeed-metrics' }, [
		E('div', { 'class': 'lanspeed-metric' }, [
			E('div', { 'class': 'caption' }, _('上行 · tx')),
			refs.mTx,
			E('div', { 'class': 'hint' }, _('客户端 → 路由器 / WAN'))
		]),
		E('div', { 'class': 'lanspeed-metric' }, [
			E('div', { 'class': 'caption' }, _('下行 · rx')),
			refs.mRx,
			E('div', { 'class': 'hint' }, _('路由器 / WAN → 客户端'))
		]),
		E('div', { 'class': 'lanspeed-metric' }, [
			E('div', { 'class': 'caption' }, _('客户端')),
			refs.mClients,
			refs.mClientsSub
		]),
		E('div', {
			'class': 'lanspeed-metric',
			'title': _('客户端合计 ÷ LAN 接口合计。100% 表示所有流量都能按客户端归因；明显低于 100% 说明有硬件卸载 / 桥接 LAN-to-LAN / 广播 / 未归属 MAC。')
		}, [
			E('div', { 'class': 'caption' }, _('覆盖率')),
			refs.mCoverage,
			refs.mCoverageSub
		])
	]);

	refs.strip = E('div', { 'class': 'lanspeed-strip' });

	var overviewCard = E('div', { 'class': 'cbi-section' }, [
		overviewHeader,
		refs.errorBox,
		metrics,
		refs.strip
	]);

	/* ---- clients card ---- */
	refs.btnRefresh = E('button', { 'class': 'cbi-button cbi-button-apply' }, _('立即刷新'));
	refs.btnRefresh.addEventListener('click', function() { viewState.reload(true); });

	refs.btnReload = E('button', { 'class': 'cbi-button cbi-button-reload' }, _('重载 daemon'));
	refs.btnReload.title = _('清理旧 tc filter，重新尝试挂载 BPF 运行时。仅清理 lanspeedd 自己拥有的 filter，不影响 dae / SQM 等共存项。');
	refs.btnReload.addEventListener('click', function() {
		if (viewState.reloading) return;
		viewState.reloading = true;
		var original = refs.btnReload.textContent;
		refs.btnReload.disabled = true;
		refs.btnReload.textContent = _('正在重载…');
		callInit('lanspeedd', 'reload').catch(function() {
			/* rpcd returns ubus error on non-zero exit; init scripts exit 0 normally */
		}).then(function() {
			/* give procd time to respawn and daemon time to re-probe + attach */
			window.setTimeout(function() {
				refs.btnReload.disabled = false;
				refs.btnReload.textContent = original;
				viewState.reloading = false;
				viewState.reload(true);
			}, 4000);
		});
	});

	refs.btnPause = E('button', { 'class': 'cbi-button' }, prefs.paused ? _('恢复') : _('暂停'));
	refs.btnPause.addEventListener('click', function() {
		viewState.prefs.paused = !viewState.prefs.paused;
		refs.btnPause.textContent = viewState.prefs.paused ? _('恢复') : _('暂停');
		savePrefs(viewState.prefs);
		if (viewState.prefs.paused) viewState.stopTimer(); else viewState.schedule();
	});

	refs.filterInput = E('input', {
		'type': 'search',
		'class': 'cbi-input-text',
		'placeholder': _('过滤 MAC / 主机名 / IP'),
		'value': viewState.filter || ''
	});
	refs.filterInput.addEventListener('input', function(ev) {
		viewState.filter = ev.target.value;
		viewState.refreshLive();
	});

	var activeAttrs = { 'type': 'checkbox', 'id': 'lanspeed-active' };
	if (prefs.activeOnly) activeAttrs.checked = 'checked';
	refs.activeChk = E('input', activeAttrs);
	refs.activeChk.addEventListener('change', function(ev) {
		viewState.prefs.activeOnly = ev.target.checked;
		savePrefs(viewState.prefs);
		viewState.refreshLive();
	});

	refs.intervalSel = E('select', { 'class': 'cbi-input-select' }, REFRESH_CHOICES.map(function(c) {
		return opt(c.value, c.label, prefs.refreshMs === c.value);
	}));
	refs.intervalSel.addEventListener('change', function(ev) {
		var v = parseInt(ev.target.value, 10);
		if (!isNaN(v) && v >= MIN_REFRESH_MS) {
			viewState.prefs.refreshMs = v;
			savePrefs(viewState.prefs);
			viewState.schedule();
		}
	});

	refs.unitSel = E('select', { 'class': 'cbi-input-select' }, [
		opt('bit',  'bit/s',  prefs.unit === 'bit'),
		opt('byte', 'Byte/s', prefs.unit === 'byte')
	]);
	refs.unitSel.addEventListener('change', function(ev) {
		viewState.prefs.unit = ev.target.value;
		savePrefs(viewState.prefs);
		viewState.refreshLive();
	});

	refs.sortSel = E('select', { 'class': 'cbi-input-select' },
		[
			{ k: 'speed',     t: _('总速率')   },
			{ k: 'tx',        t: _('上行')     },
			{ k: 'rx',        t: _('下行')     },
			{ k: 'hostname',  t: _('主机名')   },
			{ k: 'mac',       t: 'MAC'         },
			{ k: 'last_seen', t: _('最近可见') }
		].map(function(o) {
			return opt(o.k, o.t, prefs.sortKey === o.k);
		})
	);
	refs.sortSel.addEventListener('change', function(ev) {
		viewState.prefs.sortKey = ev.target.value;
		savePrefs(viewState.prefs);
		viewState.refreshLive();
	});

	var toolbar = E('div', { 'class': 'lanspeed-toolbar' }, [
		refs.btnRefresh, refs.btnReload, refs.btnPause,
		refs.filterInput,
		E('label', { 'for': 'lanspeed-active' }, [ refs.activeChk, _('仅活跃') ]),
		E('span', { 'class': 'spacer' }),
		E('label', {}, [ _('刷新'), refs.intervalSel ]),
		E('label', {}, [ _('单位'), refs.unitSel ]),
		E('label', {}, [ _('排序'), refs.sortSel ])
	]);

	refs.clientsHeaderSummary = E('span', { 'class': 'meta' }, '');
	var clientsHeader = E('div', { 'class': 'lanspeed-header' }, [
		E('h3', {}, _('LAN 客户端')),
		E('span', { 'class': 'spacer' }),
		refs.clientsHeaderSummary
	]);

	refs.tbody = E('tbody', {});
	refs.clientsTable = E('table', { 'class': 'lanspeed-table' }, [
		E('thead', {}, E('tr', {}, [
			E('th', {}, _('客户端')),
			E('th', {}, 'MAC'),
			E('th', { 'class': 'num' }, _('上行')),
			E('th', { 'class': 'num' }, _('下行')),
			E('th', {}, _('状态')),
			E('th', {}, _('最近'))
		])),
		refs.tbody
	]);
	refs.empty = E('div', { 'class': 'lanspeed-empty', 'style': 'display:none' }, '-');

	var clientsCard = E('div', { 'class': 'cbi-section' }, [
		clientsHeader,
		toolbar,
		refs.clientsTable,
		refs.empty
	]);

	/* ---- interfaces card (collapsible) ---- */
	refs.ifacesSummary = E('span', { 'class': 'sum' }, '');
	refs.ifacesBody    = E('tbody', {});
	refs.ifacesHint    = E('p', { 'class': 'lanspeed-hint' }, '');
	refs.ifacesPicker  = E('div', { 'class': 'lanspeed-iface-picker' });
	var ifacesTable = E('table', { 'class': 'lanspeed-table' }, [
		E('thead', {}, E('tr', {}, [
			E('th', {}, _('接口')),
			E('th', { 'class': 'num' }, _('接口 ↑')),
			E('th', { 'class': 'num' }, _('接口 ↓')),
			E('th', { 'class': 'num' }, _('客户端 ↑')),
			E('th', { 'class': 'num' }, _('客户端 ↓')),
			E('th', { 'class': 'num', 'title': _('客户端合计占接口合计的百分比；100% 表示完全覆盖') }, _('覆盖率 ↑')),
			E('th', { 'class': 'num', 'title': _('客户端合计占接口合计的百分比；100% 表示完全覆盖') }, _('覆盖率 ↓'))
		])),
		refs.ifacesBody
	]);
	refs.ifacesDetails = E('details', { 'class': 'lanspeed-details', 'open': 'open' }, [
		E('summary', {}, [
			E('h3', {}, _('接口吞吐')),
			E('span', { 'class': 'spacer' }),
			refs.ifacesSummary
		]),
		E('div', { 'class': 'lanspeed-details-body' }, [
			refs.ifacesPicker,
			ifacesTable,
			refs.ifacesHint
		])
	]);
	var ifacesCard = E('div', { 'class': 'cbi-section' }, [ refs.ifacesDetails ]);

	/* ---- interface configuration card (collapsible) ---- */
	refs.ifcfgGrid      = E('div', { 'class': 'lanspeed-ifcfg-grid' });
	refs.ifcfgStatus    = E('span', { 'class': 'status' }, '');
	refs.ifcfgSaveBtn   = E('button', { 'class': 'cbi-button cbi-button-apply' }, _('保存并重载'));
	refs.ifcfgReloadBtn = E('button', { 'class': 'cbi-button' }, _('扫描设备'));
	refs.ifcfgHint      = E('p', { 'class': 'lanspeed-hint' }, '');
	refs.ifcfgSummary   = E('span', { 'class': 'sum' }, '');

	refs.ifcfgSaveBtn.addEventListener('click', function() {
		if (viewState.ifcfgSaving) return;
		saveIfaceConfig(viewState);
	});
	refs.ifcfgReloadBtn.addEventListener('click', function() {
		loadIfaceConfig(viewState);
	});

	refs.ifcfgDetails = E('details', { 'class': 'lanspeed-details' }, [
		E('summary', {}, [
			E('h3', {}, _('接口配置')),
			E('span', { 'class': 'spacer' }),
			refs.ifcfgSummary
		]),
		E('div', { 'class': 'lanspeed-details-body' }, [
			E('div', { 'class': 'lanspeed-ifcfg' }, [
				refs.ifcfgGrid,
				E('div', { 'class': 'lanspeed-ifcfg-actions' }, [
					refs.ifcfgSaveBtn,
					refs.ifcfgReloadBtn,
					E('span', { 'class': 'spacer' }),
					refs.ifcfgStatus
				]),
				refs.ifcfgHint
			])
		])
	]);
	var ifcfgCard = E('div', { 'class': 'cbi-section' }, [ refs.ifcfgDetails ]);

	/* ---- diagnostics card (collapsible) ---- */
	refs.capsGrid           = E('div', { 'class': 'lanspeed-caps' });
	refs.allWarnings        = E('ul', { 'class': 'lanspeed-warnings' });
	refs.versionLine        = E('p', { 'class': 'lanspeed-hint' }, '');
	refs.diagnosticsSummary = E('span', { 'class': 'sum' }, '');
	refs.diagnostics = E('details', { 'class': 'lanspeed-details' }, [
		E('summary', {}, [
			E('h3', {}, _('诊断详情')),
			E('span', { 'class': 'spacer' }),
			refs.diagnosticsSummary
		]),
		E('div', { 'class': 'lanspeed-details-body' }, [
			E('h4', { 'class': 'lanspeed-subhead' }, _('能力矩阵')),
			refs.capsGrid,
			E('h4', { 'class': 'lanspeed-subhead' }, _('全部告警')),
			refs.allWarnings,
			E('h4', { 'class': 'lanspeed-subhead' }, _('说明与元数据')),
			E('p', { 'style': 'margin:0;font-size:.9em' },
				_('CPU 可见 LAN 边缘客户端吞吐。代理（OpenClash / dae）和软件流量卸载下客户端总流量仍可见；只有硬件流量卸载和同 ASIC 内硬件桥接的 LAN-to-LAN 绕过 CPU。')),
			refs.versionLine
		])
	]);
	var diagnosticsCard = E('div', { 'class': 'cbi-section' }, [ refs.diagnostics ]);

	var root = E('div', { 'class': 'cbi-map' }, [
		E('style', {}, LAYOUT_CSS),
		overviewCard,
		clientsCard,
		ifacesCard,
		ifcfgCard,
		diagnosticsCard
	]);

	return { root: root, refs: refs };
}

/* ---------- live refresh ---------- */

function refreshLive(viewState) {
	var refs = viewState.refs;
	if (!refs) return;
	var status = viewState.status || {};
	var clientsAll = asArray(viewState.clients && viewState.clients.clients);
	var prefs = viewState.prefs;

	/* error */
	if (viewState.error) {
		refs.errorBox.style.display = '';
		refs.errorPre.textContent = (viewState.error && (viewState.error.message || String(viewState.error))) || _('未知 RPC 失败');
	} else {
		refs.errorBox.style.display = 'none';
	}

	/* header pills */
	var mode = status.mode || 'Unsupported';
	refs.modePill.className = modeClass(mode);
	refs.modePill.textContent = modeText(mode);
	refs.confPill.className = confidenceClass(status.confidence);
	refs.confPill.textContent = _('置信 ') + confidenceText(status.confidence);
	var metaParts = [];
	if (status.version) metaParts.push('v' + status.version);
	if (status.refresh_interval_ms) metaParts.push(status.refresh_interval_ms + ' ms');
	if (prefs.paused) metaParts.push(_('已暂停'));
	refs.meta.textContent = metaParts.join(' · ');

	/* metrics */
	var totals = sumTotals(clientsAll);
	refs.mTx.textContent = formatRate(totals.tx, prefs.unit);
	refs.mRx.textContent = formatRate(totals.rx, prefs.unit);
	refs.mClients.textContent = String(clientsAll.length);

	/* cross-check with ECM host_count if available: if ECM knows more
	 * clients than we are reporting, the gap is usually clients whose
	 * traffic is fully hardware-accelerated and whose flows haven't
	 * synced to conntrack yet. Surface this so users aren't confused. */
	var nssEv = status.evidence && status.evidence.nss;
	var subParts = [ _('%d 个活跃').format(totals.active) ];
	if (nssEv && typeof nssEv.host_count === 'number' &&
	    nssEv.host_count > clientsAll.length) {
		subParts.push(_('ECM 知 %d').format(nssEv.host_count));
	}
	refs.mClientsSub.textContent = subParts.join(' · ');

	/* coverage: client sum / LAN interface total.
	 * Computed here (not inside the ifaces details block) so the overview
	 * card metric stays live regardless of details state. */
	var ifacesAll = asArray(viewState.interfaces && viewState.interfaces.interfaces);
	var lanIfUp = 0, lanIfDn = 0;
	ifacesAll.forEach(function(i) {
		if ((i.role || 'lan') !== 'lan') return;
		lanIfUp += Number(i.rx_bps) || 0;
		lanIfDn += Number(i.tx_bps) || 0;
	});
	var lanTotal  = lanIfUp + lanIfDn;
	var liveTotal = totals.tx + totals.rx;
	if (lanTotal < INACTIVE_BPS_THRESHOLD) {
		refs.mCoverage.textContent = '-';
		refs.mCoverageSub.textContent = _('LAN 无活动流量');
	} else {
		var pct = Math.min(100, Math.round((liveTotal / lanTotal) * 100));
		refs.mCoverage.textContent = pct + '%';
		var missingBps = Math.max(0, lanTotal - liveTotal);
		if (pct < 85) {
			refs.mCoverageSub.textContent = _('缺口 ') + formatRate(missingBps, prefs.unit);
		} else {
			refs.mCoverageSub.textContent = _('客户端合计 / 接口合计');
		}
	}

	/* critical strip */
	var critical = asArray(status.warnings).filter(function(w) { return CRITICAL_WARNINGS[w]; });
	replaceChildren(refs.strip, critical.map(function(w) {
		return E('span', { 'class': warningClass(w), 'title': w }, warningText(w));
	}));

	/* client table */
	var filtered = clientsAll.filter(function(c) {
		if (!matchesFilter(c, viewState.filter)) return false;
		if (prefs.activeOnly) {
			var t = Number(c.tx_bps) || 0, r = Number(c.rx_bps) || 0;
			if (t + r < INACTIVE_BPS_THRESHOLD) return false;
		}
		return true;
	});
	var sorted = sortClients(filtered, prefs.sortKey);

	/* clients card header summary (shown to the right of the h3) */
	var summaryParts = [
		_('%d 总').format(clientsAll.length),
		_('%d 活跃').format(totals.active)
	];
	if (viewState.filter || prefs.activeOnly)
		summaryParts.push(_('%d 显示').format(sorted.length));
	refs.clientsHeaderSummary.textContent = summaryParts.join(' · ');

	if (!sorted.length) {
		refs.clientsTable.style.display = 'none';
		refs.empty.style.display = '';
		refs.empty.textContent = (viewState.filter || prefs.activeOnly)
			? _('没有匹配的客户端。')
			: _('lanspeedd 当前未上报 LAN 客户端。请确认 /etc/config/lanspeed 的 ifname 指向实际 LAN 边缘接口。');
	} else {
		refs.clientsTable.style.display = '';
		refs.empty.style.display = 'none';

		/* global warnings are already shown at the top of the page; don\'t
		   repeat them on every client row. Only show what\'s actually
		   specific to this client. */
		var globalWarnings = {};
		asArray(status.warnings).forEach(function(w) { globalWarnings[w] = true; });

		replaceChildren(refs.tbody, sorted.map(function(c) {
			var tx = Number(c.tx_bps) || 0, rx = Number(c.rx_bps) || 0;
			var idle = (tx + rx) < INACTIVE_BPS_THRESHOLD;
			var ips = asArray(c.ips);
			var rawWarnings = asArray(c.warnings);
			var specificWarnings = rawWarnings.filter(function(w) { return !globalWarnings[w]; });
			var critClient = specificWarnings.some(function(w) { return CRITICAL_WARNINGS[w]; });

			/* collector mode: abbreviate + explain via tooltip */
			var mode = String(c.collector_mode || '-');
			var modeLabel, modeTitle;
			if (mode === 'bpf') {
				modeLabel = 'BPF';
				modeTitle = _('采集方式 BPF：tc clsact 挂载的 eBPF 程序按 MAC 直接计数，置信度高。');
			} else if (mode === 'conntrack_ecm_sync') {
				modeLabel = 'ECM';
				modeTitle = _('采集方式 ECM 同步：NSS 硬件加速流的字节计数由 qca-nss-ecm 以秒级节拍同步回 conntrack，再由 lanspeedd 读取。桥接流也覆盖，精度等于 ECM sync 间隔 (≈1-2 秒)。');
			} else if (mode === 'conntrack') {
				modeLabel = 'CT';
				modeTitle = _('采集方式 Conntrack：从 /proc/net/nf_conntrack 按流聚合，仅覆盖路由/NAT 流量，置信度较低。');
			} else {
				modeLabel = mode;
				modeTitle = _('未知采集方式');
			}

			var stateCells = [
				E('span', { 'class': 'label', 'title': modeTitle }, modeLabel),
				E('span', { 'class': confidenceClass(c.confidence),
				            'title': _('置信度：') + confidenceText(c.confidence) +
				                     '。' + _('低 = 路径可能绕过 CPU 可见计数；高 = 直接从内核 filter 采得。') },
				  confidenceText(c.confidence))
			];
			if (specificWarnings.length)
				stateCells.push(E('span', {
					'class': critClient ? 'label label-danger' : 'label label-warning',
					'title': specificWarnings.map(warningText).join('\n')
				}, _('%d 告警').format(specificWarnings.length)));

			/* display name: prefer hostname; otherwise first IP (MAC is already
			   shown in its own column, no need to repeat). */
			var displayName;
			if (c.hostname) {
				displayName = c.hostname;
			} else if (ips.length) {
				displayName = ips[0];
			} else {
				displayName = c.mac || '-';
			}

			return E('tr', idle ? { 'class': 'idle' } : {}, [
				E('td', {}, [
					displayName,
					(c.hostname && ips.length)
						? E('span', { 'class': 'ipline', 'title': ips.join(', ') }, ips.join(', '))
						: (ips.length > 1
							? E('span', { 'class': 'ipline', 'title': ips.join(', ') },
							    ips.slice(1).join(', '))
							: '')
				]),
				E('td', { 'class': 'mono' }, textOrDash(c.mac)),
				E('td', { 'class': 'num' }, formatRate(tx, prefs.unit)),
				E('td', { 'class': 'num' }, formatRate(rx, prefs.unit)),
				E('td', {}, E('span', { 'class': 'state' }, stateCells)),
				E('td', {}, formatLastSeen(c.last_seen))
			]);
		}));
	}

	/* interfaces details */
	var ifaces = asArray(viewState.interfaces && viewState.interfaces.interfaces);
	if (!ifaces.length) {
		refs.ifacesDetails.parentNode.style.display = 'none';
	} else {
		refs.ifacesDetails.parentNode.style.display = '';
		var clientSumByIf = {};
		clientsAll.forEach(function(c) {
			var k = c.interface || '-';
			if (!clientSumByIf[k]) clientSumByIf[k] = { tx: 0, rx: 0 };
			clientSumByIf[k].tx += Number(c.tx_bps) || 0;
			clientSumByIf[k].rx += Number(c.rx_bps) || 0;
		});

		var totalIfTx = 0, totalIfRx = 0, totalClientTx = 0, totalClientRx = 0;
		replaceChildren(refs.ifacesBody, ifaces.map(function(i) {
			var n = i.name || '-';
			/* direction semantics depend on role (LAN ↔ WAN flip counters).
			 * Display is always user-perspective: ↑ = upload, ↓ = download. */
			var isLan = (i.role || 'lan') === 'lan';
			var ifUp = Number(isLan ? i.rx_bps : i.tx_bps) || 0;
			var ifDn = Number(isLan ? i.tx_bps : i.rx_bps) || 0;
			var cs = clientSumByIf[n] || { tx: 0, rx: 0 };

			totalIfTx += ifUp; totalIfRx += ifDn;
			if (isLan) { totalClientTx += cs.tx; totalClientRx += cs.rx; }

			function coverage(part, whole) {
				if (whole < INACTIVE_BPS_THRESHOLD) return '-';
				var pct = Math.min(100, Math.round((part / whole) * 100));
				return pct + '%';
			}

			return E('tr', {}, [
				E('td', {}, n),
				E('td', { 'class': 'num' }, formatRate(ifUp, prefs.unit)),
				E('td', { 'class': 'num' }, formatRate(ifDn, prefs.unit)),
				E('td', { 'class': 'num' }, isLan ? formatRate(cs.tx, prefs.unit) : '-'),
				E('td', { 'class': 'num' }, isLan ? formatRate(cs.rx, prefs.unit) : '-'),
				E('td', { 'class': 'num' }, isLan ? coverage(cs.tx, ifUp) : '-'),
				E('td', { 'class': 'num' }, isLan ? coverage(cs.rx, ifDn) : '-')
			]);
		}));

		var sumBits = [
			'↑ ' + formatRate(totalIfTx, prefs.unit),
			'↓ ' + formatRate(totalIfRx, prefs.unit)
		];
		refs.ifacesSummary.textContent = sumBits.join(' · ');

		/* overall coverage across LAN interfaces */
		function pctOrDash(part, whole) {
			if (whole < INACTIVE_BPS_THRESHOLD) return null;
			return Math.min(100, Math.round((part / whole) * 100));
		}
		var totalLanUp = 0, totalLanDn = 0;
		ifaces.forEach(function(i) {
			if ((i.role || 'lan') !== 'lan') return;
			totalLanUp += Number(i.rx_bps) || 0;
			totalLanDn += Number(i.tx_bps) || 0;
		});
		var covUp = pctOrDash(totalClientTx, totalLanUp);
		var covDn = pctOrDash(totalClientRx, totalLanDn);

		if (covUp === null && covDn === null) {
			refs.ifacesHint.textContent = _('LAN 当前无活动流量。');
		} else if ((covUp !== null && covUp < 85) || (covDn !== null && covDn < 85)) {
			refs.ifacesHint.textContent = _('覆盖率偏低：可能有硬件流量卸载、硬件桥接 LAN-to-LAN、广播/多播或未归属 MAC。');
		} else {
			refs.ifacesHint.textContent = _('覆盖率接近 100%，CPU 可见流量归因完整。');
		}
	}

	/* diagnostics: capability grid */
	var capabilities = status.capabilities || {};
	var capKeys = CAPABILITY_ORDER.filter(function(k) {
		return Object.prototype.hasOwnProperty.call(capabilities, k);
	});
	if (capKeys.length) {
		replaceChildren(refs.capsGrid, capKeys.map(function(k) {
			var enabled = Boolean(capabilities[k]);
			return E('div', { 'class': 'cap' }, [
				E('span', {}, CAPABILITY_LABELS[k] || k),
				E('span', { 'class': capabilityClass(k, enabled), 'title': k },
					enabled ? _('是') : _('否'))
			]);
		}));
	} else {
		replaceChildren(refs.capsGrid, [E('p', {}, _('后端未上报任何能力。'))]);
	}

	/* diagnostics: warnings */
	var warnings = asArray(status.warnings);
	if (warnings.length) {
		replaceChildren(refs.allWarnings, warnings.map(function(w) {
			return E('li', {}, [
				E('span', { 'class': warningClass(w) + ' key' }, w),
				warningText(w)
			]);
		}));
	} else {
		replaceChildren(refs.allWarnings, [E('li', {}, _('当前没有上报告警。'))]);
	}

	var versionParts = [
		_('lanspeedd %s').format(textOrDash(status.version)),
		_('后端刷新 %s ms').format(textOrDash(status.refresh_interval_ms))
	];
	var nssEvidence = status.evidence && status.evidence.nss;
	if (nssEvidence && (nssEvidence.ecm_offload_active || nssEvidence.ppe_offload_active)) {
		var engine = nssEvidence.ppe_offload_active ? 'PPE' : 'ECM';
		var connBits = [];
		if (typeof nssEvidence.accelerated_connections === 'number')
			connBits.push(_('总 %d').format(nssEvidence.accelerated_connections));
		if (typeof nssEvidence.accelerated_tcp === 'number')
			connBits.push('TCP ' + nssEvidence.accelerated_tcp);
		if (typeof nssEvidence.accelerated_udp === 'number')
			connBits.push('UDP ' + nssEvidence.accelerated_udp);
		if (typeof nssEvidence.accelerated_other === 'number' && nssEvidence.accelerated_other > 0)
			connBits.push(_('其它 %d').format(nssEvidence.accelerated_other));
		if (connBits.length)
			versionParts.push(_('NSS %s 加速连接').format(engine) + ' (' + connBits.join(' / ') + ')');
		else
			versionParts.push(_('NSS %s 活跃').format(engine));

		var objectBits = [];
		if (typeof nssEvidence.host_count === 'number')
			objectBits.push(_('host %d').format(nssEvidence.host_count));
		if (typeof nssEvidence.mapping_count === 'number')
			objectBits.push(_('NAT 映射 %d').format(nssEvidence.mapping_count));
		if (objectBits.length)
			versionParts.push(_('ECM 数据库: ') + objectBits.join(' · '));
	}
	if (nssEvidence && Array.isArray(nssEvidence.subsystems) && nssEvidence.subsystems.length)
		versionParts.push(_('NSS 子系统: ') + nssEvidence.subsystems.join(', '));
	refs.versionLine.textContent = versionParts.join(' · ');

	refs.diagnosticsSummary.textContent = warnings.length
		? _('%d 项告警 · %d 项能力').format(warnings.length, capKeys.length)
		: _('无告警 · %d 项能力').format(capKeys.length);
}

/* ---------- view export ---------- */

return view.extend({
	load: function() {
		return Promise.all([callStatus(), callClients(), callInterfaces()]).then(function(d) {
			return { status: d[0] || {}, clients: d[1] || {}, interfaces: d[2] || { interfaces: [] }, error: null };
		}).catch(function(error) {
			return { status: {}, clients: { clients: [] }, interfaces: { interfaces: [] }, error: error };
		});
	},

	render: function(data) {
		var viewState = {
			status: data.status || {},
			clients: data.clients || { clients: [] },
			interfaces: data.interfaces || { interfaces: [] },
			error: data.error,
			filter: '',
			prefs: loadPrefs(),
			timer: null,
			refs: null,

			stopTimer: function() {
				if (this.timer) { window.clearTimeout(this.timer); this.timer = null; }
			},

			schedule: function() {
				var self = this;
				this.stopTimer();
				if (this.prefs.paused) return;
				var interval = Math.max(MIN_REFRESH_MS, this.prefs.refreshMs);
				this.timer = window.setTimeout(function() { self.reload(false); }, interval);
			},

			refreshLive: function() { refreshLive(this); },

			reload: function(force) {
				var self = this;
				if (force) this.stopTimer();
				return Promise.all([callStatus(), callClients(), callInterfaces()]).then(function(r) {
					self.status = r[0] || {};
					self.clients = r[1] || { clients: [] };
					self.interfaces = r[2] || { interfaces: [] };
					self.error = null;
					self.refreshLive();
					self.schedule();
				}).catch(function(error) {
					self.error = error;
					self.refreshLive();
					self.schedule();
				});
			}
		};

		var built = buildShell(viewState);
		viewState.refs = built.refs;
		refreshLive(viewState);
		loadIfaceConfig(viewState);
		viewState.schedule();
		return built.root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
