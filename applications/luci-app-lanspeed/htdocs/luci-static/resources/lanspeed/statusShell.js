'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.nssPanel as nssPanel';
'require lanspeed.theme as lsTheme';
'require lanspeed.statusStyle as statusStyle';

function sortableHeader(viewState, refs, sortKey, label, attrs) {
	var thAttrs = Object.assign({ 'aria-sort': 'none' }, attrs || {});
	var button = E('button', {
		'type': 'button',
		'class': 'lanspeed-sort-button'
	}, [
		E('span', { 'class': 'lanspeed-sort-label' }, label),
		E('span', { 'class': 'lanspeed-sort-indicator', 'aria-hidden': 'true' }, '')
	]);
	var th = E('th', thAttrs, button);

	refs.sortHeaders[sortKey] = {
		th: th,
		button: button,
		label: label,
		description: attrs && attrs.title || ''
	};
	button.addEventListener('click', function() {
		Object.assign(viewState.prefs, fmt.nextSort(viewState.prefs, sortKey));
		fmt.savePrefs(viewState.prefs);
		viewState.refreshLive();
	});

	return th;
}

function buildShell(viewState) {
	var refs = {};
	var prefs = viewState.prefs;
	refs.sortHeaders = {};

	refs.collectorPill = E('span', { 'class': 'label' }, '-');
	refs.meta     = E('span', { 'class': 'meta' }, '');
	var overviewHeader = E('div', { 'class': 'lanspeed-header' }, [
		E('h3', {}, _('LAN Speed')),
		refs.collectorPill,
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
	refs.mCovTx       = null;
	refs.mCovRx       = null;
	refs.mCoverage    = E('div', { 'class': 'big' }, '-');
	refs.mCoverageSub = E('div', { 'class': 'hint' }, '-');
	refs.mTcpConns    = E('div', { 'class': 'big' }, '-');
	refs.mUdpConns    = E('div', { 'class': 'big' }, '-');
	refs.mUdpConnsSub = E('div', { 'class': 'hint' }, '-');
	refs.mConnsWrap   = E('div', {
		'class': 'lanspeed-metric',
		'title': _('当前 conntrack 项：TCP 仅统计 ESTABLISHED + ASSURED，UDP 仅统计 ASSURED；每条连接只归属一个 LAN 客户端。')
	}, [
		E('div', { 'class': 'caption' }, _('连接数')),
		refs.mTcpConns,
		refs.mUdpConns,
		refs.mUdpConnsSub
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

	var overviewCard = E('div', { 'class': 'cbi-section' }, [
		overviewHeader,
		E('div', { 'class': 'lanspeed-body' }, [
			refs.errorBox,
			metrics
		])
	]);

	refs.btnRefresh = E('button', { 'class': 'cbi-button' }, _('立即刷新'));
	refs.btnRefresh.addEventListener('click', function() { viewState.reload(true); });

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

	var activeAttrs = { 'type': 'checkbox', 'id': 'lanspeed-active', 'class': 'cbi-input-checkbox' };
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

	var toolbar = E('div', { 'class': 'lanspeed-toolbar' }, [
		E('div', { 'class': 'lanspeed-toolbar-left' }, [
			E('label', { 'class': 'lanspeed-unit-control' }, [ _('单位'), refs.unitSel ]),
			E('div', { 'class': 'lanspeed-toolbar-filter' }, [
				refs.filterInput,
				E('label', { 'class': 'lanspeed-active-only cbi-checkbox', 'for': 'lanspeed-active' }, [
					refs.activeChk,
					E('span', { 'class': 'lanspeed-active-label' }, _('仅活跃'))
				])
			])
		]),
		E('div', { 'class': 'lanspeed-toolbar-right' }, [
			E('label', { 'class': 'lanspeed-refresh-control' }, [ _('刷新'), refs.intervalSel ]),
			refs.btnRefresh,
			refs.btnPause
		])
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
			sortableHeader(viewState, refs, 'hostname', _('客户端')),
			sortableHeader(viewState, refs, 'mac', 'MAC'),
			sortableHeader(viewState, refs, 'tx', _('上行'), { 'class': 'num' }),
			sortableHeader(viewState, refs, 'rx', _('下行'), { 'class': 'num' }),
			sortableHeader(viewState, refs, 'tcp_conns', 'TCP', {
				'class': 'num', 'title': _('TCP 仅统计 ESTABLISHED + ASSURED')
			}),
			sortableHeader(viewState, refs, 'udp_conns', 'UDP', {
				'class': 'num', 'title': _('UDP 仅统计 ASSURED conntrack 条目')
			}),
			E('th', {}, _('状态'))
		])),
		refs.tbody
	]);
	refs.empty = E('div', { 'class': 'lanspeed-empty', 'style': 'display:none' }, '-');

	var clientsCard = E('div', { 'class': 'cbi-section lanspeed-clients-card' }, [
		clientsHeader,
		E('div', { 'class': 'lanspeed-body' }, [
			toolbar,
			refs.clientsTable,
			refs.empty
		])
	]);

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
			E('th', { 'class': 'num' }, _('客户端 ↓'))
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

	var nssCard = nssPanel.build(refs);

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

	var root = E('div', { 'class': 'cbi-map lanspeed-root' }, [
		E('style', {}, statusStyle.CSS),
		overviewCard,
		clientsCard,
		ifacesCard,
		nssCard,
		diagnosticsCard
	]);

	lsTheme.applyRoot(root);

	return { root: root, refs: refs };
}

return baseclass.extend({
	buildShell: function(viewState) {
		return buildShell(viewState);
	}
});
