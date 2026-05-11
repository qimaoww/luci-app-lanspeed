'use strict';
'require view';
'require lanspeed.vocab as vocab';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';
'require lanspeed.ifaceConfig as ifaceCfg';
'require lanspeed.nssPanel as nssPanel';

/*
 * LAN Speed LuCI status view.
 *
 * Theming rule: use LuCI-native classes everywhere. The only custom CSS is
 * layout (flex / grid) and tabular numerics. Colours, backgrounds, borders,
 * button styles and form controls inherit from whichever LuCI theme is
 * active (bootstrap / argon / aurora / material / dark / light …).
 *
 * Architecture: buildShell() constructs the DOM once, stashes mutation
 * points in viewState.refs. refreshLive() mutates only the dynamic cells;
 * toolbar controls keep their focus / value across ticks.
 *
 * Vocabulary, formatting, RPC handles, the iface-config sub-panel and the
 * NSS status card live in resources/lanspeed/*.js modules; this file is the
 * shell + refresh loop + view export.
 */

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
 *     <div class="cbi-section">        clients card
 *     <div class="cbi-section">        interfaces card (details)
 *     <div class="cbi-section">        NSS card (details, hidden unless NSS present)
 *     <div class="cbi-section">        interface configuration card (details)
 *     <div class="cbi-section">        diagnostics card (details)
 *   </div>
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

	refs.mTx          = E('div', { 'class': 'big' }, '0');
	refs.mRx          = E('div', { 'class': 'big' }, '0');
	refs.mClients     = E('div', { 'class': 'big' }, '0');
	refs.mClientsSub  = E('div', { 'class': 'hint' }, '-');
	refs.mCoverage    = E('div', { 'class': 'big' }, '-');
	refs.mCoverageSub = E('div', { 'class': 'hint' }, '-');
	refs.mTcpConns    = E('div', { 'class': 'big' }, '-');
	refs.mUdpConns    = E('div', { 'class': 'big' }, '-');
	refs.mConnsWrap   = E('div', { 'class': 'lanspeed-metric' }, [
		E('div', { 'class': 'caption' }, _('连接数')),
		refs.mTcpConns,
		refs.mUdpConns
	]);
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
		]),
		refs.mConnsWrap
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
		lsRpc.init('lanspeedd', 'reload').catch(function() {
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
		fmt.savePrefs(viewState.prefs);
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
		fmt.savePrefs(viewState.prefs);
		viewState.refreshLive();
	});

	refs.intervalSel = E('select', { 'class': 'cbi-input-select' }, fmt.REFRESH_CHOICES.map(function(c) {
		return fmt.opt(c.value, c.label, prefs.refreshMs === c.value);
	}));
	refs.intervalSel.addEventListener('change', function(ev) {
		var v = parseInt(ev.target.value, 10);
		if (!isNaN(v) && v >= fmt.MIN_REFRESH_MS) {
			viewState.prefs.refreshMs = v;
			fmt.savePrefs(viewState.prefs);
			viewState.schedule();
		}
	});

	refs.unitSel = E('select', { 'class': 'cbi-input-select' }, [
		fmt.opt('bit',  'bit/s',  prefs.unit === 'bit'),
		fmt.opt('byte', 'Byte/s', prefs.unit === 'byte')
	]);
	refs.unitSel.addEventListener('change', function(ev) {
		viewState.prefs.unit = ev.target.value;
		fmt.savePrefs(viewState.prefs);
		viewState.refreshLive();
	});

	refs.sortSel = E('select', { 'class': 'cbi-input-select' },
		[
			{ k: 'speed',     t: _('总速率')   },
			{ k: 'tx',        t: _('上行')     },
			{ k: 'rx',        t: _('下行')     },
			{ k: 'hostname',  t: _('主机名')   },
			{ k: 'mac',       t: 'MAC'         },
			{ k: 'tcp_conns', t: 'TCP'         },
			{ k: 'udp_conns', t: 'UDP'         },
			{ k: 'last_seen', t: _('最近可见') }
		].map(function(o) {
			return fmt.opt(o.k, o.t, prefs.sortKey === o.k);
		})
	);
	refs.sortSel.addEventListener('change', function(ev) {
		viewState.prefs.sortKey = ev.target.value;
		fmt.savePrefs(viewState.prefs);
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
			E('th', { 'class': 'num', 'title': _('TCP 仅统计 ESTABLISHED + ASSURED') }, 'TCP'),
			E('th', { 'class': 'num', 'title': _('conntrack 表中尚未超时的 UDP 条目') }, 'UDP'),
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

	/* ---- NSS card (collapsible; hidden when no NSS signal) ---- */
	var nssCard = nssPanel.build(refs);

	/* ---- interface configuration card (collapsible) ---- */
	refs.ifcfgGrid      = E('div', { 'class': 'lanspeed-ifcfg-grid' });
	refs.ifcfgStatus    = E('span', { 'class': 'status' }, '');
	refs.ifcfgSaveBtn   = E('button', { 'class': 'cbi-button cbi-button-apply' }, _('保存并重载'));
	refs.ifcfgReloadBtn = E('button', { 'class': 'cbi-button' }, _('扫描设备'));
	refs.ifcfgHint      = E('p', { 'class': 'lanspeed-hint' }, '');
	refs.ifcfgSummary   = E('span', { 'class': 'sum' }, '');

	refs.ifcfgSaveBtn.addEventListener('click', function() {
		if (viewState.ifcfgSaving) return;
		ifaceCfg.save(viewState);
	});
	refs.ifcfgReloadBtn.addEventListener('click', function() {
		ifaceCfg.load(viewState);
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
		nssCard,
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
	var clientsAll = fmt.asArray(viewState.clients && viewState.clients.clients);
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
	refs.modePill.className = vocab.modeClass(mode);
	refs.modePill.textContent = vocab.modeText(mode);
	refs.confPill.className = vocab.confidenceClass(status.confidence);
	refs.confPill.textContent = _('置信 ') + vocab.confidenceText(status.confidence);
	var metaParts = [];
	if (status.version) metaParts.push('v' + status.version);
	if (status.refresh_interval_ms) metaParts.push(status.refresh_interval_ms + ' ms');
	if (prefs.paused) metaParts.push(_('已暂停'));
	refs.meta.textContent = metaParts.join(' · ');

	/* metrics */
	var totals = fmt.sumTotals(clientsAll);
	refs.mTx.textContent = fmt.formatRate(totals.tx, prefs.unit);
	refs.mRx.textContent = fmt.formatRate(totals.rx, prefs.unit);
	refs.mClients.textContent = String(clientsAll.length);

	/* TCP/UDP connection counts from clients response top-level */
	var clientsData = viewState.clients || {};
	if (typeof clientsData.tcp_conns_total === 'number' || typeof clientsData.udp_conns_total === 'number') {
		refs.mConnsWrap.style.display = '';
		refs.mTcpConns.textContent = 'TCP ' + (typeof clientsData.tcp_conns_total === 'number' ? clientsData.tcp_conns_total : '-');
		refs.mUdpConns.textContent = 'UDP ' + (typeof clientsData.udp_conns_total === 'number' ? clientsData.udp_conns_total : '-');
	} else {
		refs.mConnsWrap.style.display = 'none';
	}

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

	/* coverage: byte-counter delta over a common time window.
	 *
	 * Both clients and interfaces now expose rx_bytes/tx_bytes/sample_ms.
	 * We keep the previous snapshot in viewState.coveragePrev and compute
	 * delta_client_bytes / delta_iface_bytes over the same wall-clock span.
	 * This eliminates the bps-window-mismatch that caused wild fluctuations
	 * when the two RPC methods used different averaging windows. */
	var ifacesAll = fmt.asArray(viewState.interfaces && viewState.interfaces.interfaces);
	var curIfaceBytes = 0;
	var curIfaceSampleMs = 0;
	ifacesAll.forEach(function(i) {
		if ((i.role || 'lan') !== 'lan') return;
		curIfaceBytes += (Number(i.rx_bytes) || 0) + (Number(i.tx_bytes) || 0);
		if (Number(i.sample_ms) > curIfaceSampleMs)
			curIfaceSampleMs = Number(i.sample_ms);
	});
	var curClientBytes = 0;
	var curClientSampleMs = 0;
	clientsAll.forEach(function(c) {
		curClientBytes += (Number(c.rx_bytes) || 0) + (Number(c.tx_bytes) || 0);
		if (Number(c.sample_ms) > curClientSampleMs)
			curClientSampleMs = Number(c.sample_ms);
	});

	var prev = viewState.coveragePrev;
	var coveragePct = null;
	if (prev && curIfaceSampleMs > prev.ifaceSampleMs && curClientSampleMs > prev.clientSampleMs) {
		var deltaIfaceBytes = curIfaceBytes - prev.ifaceBytes;
		var deltaClientBytes = curClientBytes - prev.clientBytes;
		/* Guard against counter resets (LRU eviction, daemon restart) */
		if (deltaIfaceBytes > 0 && deltaClientBytes >= 0) {
			coveragePct = Math.min(100, Math.round((deltaClientBytes / deltaIfaceBytes) * 100));
		}
	}
	/* Save current snapshot for next tick */
	viewState.coveragePrev = {
		ifaceBytes: curIfaceBytes,
		ifaceSampleMs: curIfaceSampleMs,
		clientBytes: curClientBytes,
		clientSampleMs: curClientSampleMs
	};

	if (coveragePct === null) {
		/* First tick or counter reset — fall back to instantaneous bps ratio */
		var lanTotal = 0, liveTotal = totals.tx + totals.rx;
		ifacesAll.forEach(function(i) {
			if ((i.role || 'lan') !== 'lan') return;
			lanTotal += (Number(i.rx_bps) || 0) + (Number(i.tx_bps) || 0);
		});
		if (lanTotal < fmt.INACTIVE_BPS_THRESHOLD) {
			refs.mCoverage.textContent = '-';
			refs.mCoverageSub.textContent = _('LAN 无活动流量');
		} else {
			var pct = Math.min(100, Math.round((liveTotal / lanTotal) * 100));
			refs.mCoverage.textContent = pct + '%';
			refs.mCoverageSub.textContent = _('首次采样（下次更准）');
		}
	} else {
		refs.mCoverage.textContent = coveragePct + '%';
		var deltaMs = Math.max(curIfaceSampleMs - prev.ifaceSampleMs,
		                       curClientSampleMs - prev.clientSampleMs);
		if (coveragePct < 85) {
			var deltaIfaceBytes = curIfaceBytes - prev.ifaceBytes;
			var deltaClientBytes = curClientBytes - prev.clientBytes;
			var missingBps = deltaMs > 0
				? Math.round(((deltaIfaceBytes - deltaClientBytes) * 8000) / deltaMs)
				: 0;
			refs.mCoverageSub.textContent = _('缺口 ') + fmt.formatRate(missingBps, prefs.unit);
		} else {
			refs.mCoverageSub.textContent = _('客户端合计 / 接口合计');
		}
	}

	/* critical strip */
	var critical = fmt.asArray(status.warnings).filter(function(w) { return vocab.CRITICAL_WARNINGS[w]; });
	fmt.replaceChildren(refs.strip, critical.map(function(w) {
		return E('span', { 'class': vocab.warningClass(w), 'title': w }, vocab.warningText(w));
	}));

	/* client table */
	var filtered = clientsAll.filter(function(c) {
		if (!fmt.matchesFilter(c, viewState.filter)) return false;
		if (prefs.activeOnly) {
			var t = Number(c.tx_bps) || 0, r = Number(c.rx_bps) || 0;
			if (t + r < fmt.INACTIVE_BPS_THRESHOLD) return false;
		}
		return true;
	});
	var sorted = fmt.sortClients(filtered, prefs.sortKey);

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
		fmt.asArray(status.warnings).forEach(function(w) { globalWarnings[w] = true; });

		fmt.replaceChildren(refs.tbody, sorted.map(function(c) {
			var tx = Number(c.tx_bps) || 0, rx = Number(c.rx_bps) || 0;
			var idle = (tx + rx) < fmt.INACTIVE_BPS_THRESHOLD;
			var ips = fmt.asArray(c.ips);
			var rawWarnings = fmt.asArray(c.warnings);
			var specificWarnings = rawWarnings.filter(function(w) { return !globalWarnings[w]; });
			var critClient = specificWarnings.some(function(w) { return vocab.CRITICAL_WARNINGS[w]; });

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
				E('span', { 'class': vocab.confidenceClass(c.confidence),
				            'title': _('置信度：') + vocab.confidenceText(c.confidence) +
				                     '。' + _('低 = 路径可能绕过 CPU 可见计数；高 = 直接从内核 filter 采得。') },
				  vocab.confidenceText(c.confidence))
			];
			if (specificWarnings.length)
				stateCells.push(E('span', {
					'class': critClient ? 'label label-danger' : 'label label-warning',
					'title': specificWarnings.map(vocab.warningText.bind(vocab)).join('\n')
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
				E('td', { 'class': 'mono' }, fmt.textOrDash(c.mac)),
				E('td', { 'class': 'num' }, fmt.formatRate(tx, prefs.unit)),
				E('td', { 'class': 'num' }, fmt.formatRate(rx, prefs.unit)),
				E('td', { 'class': 'num' }, typeof c.tcp_conns === 'number' ? String(c.tcp_conns) : '-'),
				E('td', { 'class': 'num' }, typeof c.udp_conns === 'number' ? String(c.udp_conns) : '-'),
				E('td', {}, E('span', { 'class': 'state' }, stateCells)),
				E('td', {}, fmt.formatLastSeen(c.last_seen))
			]);
		}));
	}

	/* interfaces details */
	var ifaces = fmt.asArray(viewState.interfaces && viewState.interfaces.interfaces);
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
		fmt.replaceChildren(refs.ifacesBody, ifaces.map(function(i) {
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
				if (whole < fmt.INACTIVE_BPS_THRESHOLD) return '-';
				var pct = Math.min(100, Math.round((part / whole) * 100));
				return pct + '%';
			}

			return E('tr', {}, [
				E('td', {}, n),
				E('td', { 'class': 'num' }, fmt.formatRate(ifUp, prefs.unit)),
				E('td', { 'class': 'num' }, fmt.formatRate(ifDn, prefs.unit)),
				E('td', { 'class': 'num' }, isLan ? fmt.formatRate(cs.tx, prefs.unit) : '-'),
				E('td', { 'class': 'num' }, isLan ? fmt.formatRate(cs.rx, prefs.unit) : '-'),
				E('td', { 'class': 'num' }, isLan ? coverage(cs.tx, ifUp) : '-'),
				E('td', { 'class': 'num' }, isLan ? coverage(cs.rx, ifDn) : '-')
			]);
		}));

		var sumBits = [
			'↑ ' + fmt.formatRate(totalIfTx, prefs.unit),
			'↓ ' + fmt.formatRate(totalIfRx, prefs.unit)
		];
		refs.ifacesSummary.textContent = sumBits.join(' · ');

		/* overall coverage across LAN interfaces */
		function pctOrDash(part, whole) {
			if (whole < fmt.INACTIVE_BPS_THRESHOLD) return null;
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

	/* NSS details card (hidden when no NSS signal; only call once status loaded) */
	nssPanel.render(refs, status);

	/* diagnostics: capability grid */
	var capabilities = status.capabilities || {};
	var capKeys = vocab.CAPABILITY_ORDER.filter(function(k) {
		return Object.prototype.hasOwnProperty.call(capabilities, k);
	});
	if (capKeys.length) {
		fmt.replaceChildren(refs.capsGrid, capKeys.map(function(k) {
			var enabled = Boolean(capabilities[k]);
			return E('div', { 'class': 'cap' }, [
				E('span', {}, vocab.CAPABILITY_LABELS[k] || k),
				E('span', { 'class': vocab.capabilityClass(k, enabled), 'title': k },
					enabled ? _('是') : _('否'))
			]);
		}));
	} else {
		fmt.replaceChildren(refs.capsGrid, [E('p', {}, _('后端未上报任何能力。'))]);
	}

	/* diagnostics: warnings */
	var warnings = fmt.asArray(status.warnings);
	if (warnings.length) {
		fmt.replaceChildren(refs.allWarnings, warnings.map(function(w) {
			return E('li', {}, [
				E('span', { 'class': vocab.warningClass(w) + ' key' }, w),
				vocab.warningText(w)
			]);
		}));
	} else {
		fmt.replaceChildren(refs.allWarnings, [E('li', {}, _('当前没有上报告警。'))]);
	}

	var versionParts = [
		_('lanspeedd %s').format(fmt.textOrDash(status.version)),
		_('后端刷新 %s ms').format(fmt.textOrDash(status.refresh_interval_ms))
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
		return Promise.all([lsRpc.status(), lsRpc.clients(), lsRpc.interfaces()]).then(function(d) {
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
			prefs: fmt.loadPrefs(),
			timer: null,
			refs: null,

			stopTimer: function() {
				if (this.timer) { window.clearTimeout(this.timer); this.timer = null; }
			},

			schedule: function() {
				var self = this;
				this.stopTimer();
				if (this.prefs.paused) return;
				var interval = Math.max(fmt.MIN_REFRESH_MS, this.prefs.refreshMs);
				this.timer = window.setTimeout(function() { self.reload(false); }, interval);
			},

			refreshLive: function() { refreshLive(this); },

			reload: function(force) {
				var self = this;
				if (force) this.stopTimer();
				return Promise.all([lsRpc.status(), lsRpc.clients(), lsRpc.interfaces()]).then(function(r) {
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
		ifaceCfg.load(viewState);
		viewState.schedule();
		return built.root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
