'use strict';
'require baseclass';
'require lanspeed.format as fmt';
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
		viewState.page = 1;
		fmt.savePrefs(viewState.prefs);
		viewState.refreshLive();
	});

	return th;
}

function buildShell(viewState) {
	var refs = {};
	var prefs = viewState.prefs;
	refs.sortHeaders = {};

	refs.collectorPill = E('span', { 'class': 'label lanspeed-collector-status' }, '-');
	refs.meta     = E('span', { 'class': 'meta' }, '');
	var overviewHeader = E('div', { 'class': 'lanspeed-header' }, [
		E('h3', {}, _('LAN Speed')),
		refs.collectorPill,
		E('span', { 'class': 'spacer' }),
		refs.meta
	]);

	refs.errorTitle = E('strong', {}, _('部分实时数据暂不可用'));
	refs.errorPre = E('p', { 'class': 'lanspeed-status-error-summary' }, '');
	refs.errorList = E('ul', { 'class': 'lanspeed-status-error-list' });
	refs.errorBox = E('div', {
		'class': 'alert-message error lanspeed-status-error',
		'role': 'alert',
		'aria-live': 'assertive',
		'aria-atomic': 'true',
		'aria-hidden': 'true',
		'style': 'display:none'
	}, [
		refs.errorTitle,
		refs.errorPre,
		refs.errorList
	]);

	refs.mTx          = E('div', { 'class': 'big' }, '0');
	refs.mRx          = E('div', { 'class': 'big' }, '0');
	refs.mClients     = E('div', { 'class': 'big' }, '0');
	refs.mClientsSub  = E('div', { 'class': 'hint' }, '-');
	refs.mCoverage    = E('div', { 'class': 'big' }, '-');
	refs.mCoverageSub = E('div', { 'class': 'hint' }, '-');
	refs.mTcpConns    = E('span', { 'class': 'lanspeed-connection-number' }, '-');
	refs.mUdpConns    = E('span', { 'class': 'lanspeed-connection-number' }, '-');
	refs.mUdpConnsSub = E('div', { 'class': 'hint' }, '-');
	refs.mConnsValue  = E('div', { 'class': 'big lanspeed-connection-values' }, [
		E('span', { 'class': 'lanspeed-connection-stat' }, [
			E('span', { 'class': 'lanspeed-connection-label' }, 'TCP'),
			refs.mTcpConns
		]),
		E('span', { 'class': 'lanspeed-connection-stat' }, [
			E('span', { 'class': 'lanspeed-connection-label' }, 'UDP'),
			refs.mUdpConns
		])
	]);
	refs.mConnsWrap   = E('div', {
		'class': 'lanspeed-metric',
		'title': _('当前连接来自 conntrack：TCP 统计已建立且确认的连接，UDP 统计已确认的连接。')
	}, [
		E('div', { 'class': 'caption' }, _('连接数')),
		refs.mConnsValue,
		refs.mUdpConnsSub
	]);
	var metrics = E('div', { 'class': 'lanspeed-metrics' }, [
		E('div', { 'class': 'lanspeed-metric' }, [
			E('div', { 'class': 'caption' }, _('上行 · tx')),
			refs.mTx,
			E('div', { 'class': 'hint' }, _('客户端发出'))
		]),
		E('div', { 'class': 'lanspeed-metric' }, [
			E('div', { 'class': 'caption' }, _('下行 · rx')),
			refs.mRx,
			E('div', { 'class': 'hint' }, _('客户端接收'))
		]),
		E('div', { 'class': 'lanspeed-metric' }, [
			E('div', { 'class': 'caption' }, _('客户端')),
			refs.mClients,
			refs.mClientsSub
		]),
		E('div', {
			'class': 'lanspeed-metric',
			'title': _('客户端速率合计与采集接口总速率的比值，用于判断流量是否完整归属到客户端。')
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

	refs.btnRefresh = E('button', {
		'type': 'button',
		'class': 'cbi-button cbi-button-action lanspeed-status-refresh',
		'aria-label': _('立即刷新实时状态')
	}, _('立即刷新'));
	refs.btnRefresh.addEventListener('click', function(event) {
		if (event && event.preventDefault) event.preventDefault();
		if (event && event.stopPropagation) event.stopPropagation();
		viewState.reload(true);
	});

	refs.btnPause = E('button', {
		'type': 'button',
		'class': 'cbi-button'
	}, prefs.paused ? _('恢复') : _('暂停'));
	refs.btnPause.addEventListener('click', function(event) {
		if (event && event.preventDefault) event.preventDefault();
		if (event && event.stopPropagation) event.stopPropagation();
		viewState.prefs.paused = !viewState.prefs.paused;
		refs.btnPause.textContent = viewState.prefs.paused ? _('恢复') : _('暂停');
		fmt.savePrefs(viewState.prefs);
		if (viewState.prefs.paused) viewState.stopTimer(); else viewState.schedule();
	});

	refs.filterInput = E('input', {
		'type': 'search',
		'class': 'cbi-input-text',
		'aria-label': _('过滤客户端'),
		'placeholder': _('过滤 MAC / 主机名 / IP'),
		'value': viewState.filter || ''
	});
	refs.filterInput.addEventListener('input', function(ev) {
		viewState.filter = ev.target.value;
		viewState.page = 1;
		viewState.refreshLive();
	});

	var activeAttrs = { 'type': 'checkbox', 'id': 'lanspeed-active', 'class': 'cbi-input-checkbox' };
	if (prefs.activeOnly) activeAttrs.checked = 'checked';
	refs.activeChk = E('input', activeAttrs);
	refs.activeChk.addEventListener('change', function(ev) {
		viewState.prefs.activeOnly = ev.target.checked;
		viewState.page = 1;
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

	var pageSizeChoices = fmt.PAGE_SIZE_CHOICES || [ 10, 25, 50, 100 ];
	var initialPageSize = pageSizeChoices.indexOf(Number(prefs.pageSize)) !== -1
		? Number(prefs.pageSize) : 25;
	prefs.pageSize = initialPageSize;
	refs.pageSizeSel = E('select', {
		'class': 'cbi-input-select lanspeed-page-size',
		'aria-label': _('每页客户端数'),
		'aria-controls': 'lanspeed-clients-table'
	}, pageSizeChoices.map(function(size) {
		return fmt.opt(size, String(size), initialPageSize === size);
	}));
	refs.pageSizeSel.addEventListener('change', function(ev) {
		var size = parseInt(ev.target.value, 10);
		if (pageSizeChoices.indexOf(size) === -1) return;
		viewState.prefs.pageSize = size;
		viewState.page = 1;
		fmt.savePrefs(viewState.prefs);
		viewState.refreshLive();
	});

	function pageButton(label, text, target) {
		var button = E('button', {
			'type': 'button',
			'class': 'cbi-button lanspeed-page-button',
			'title': label,
			'aria-label': label,
			'aria-controls': 'lanspeed-clients-table'
		}, text);
		button.addEventListener('click', function(event) {
			if (event && event.preventDefault) event.preventDefault();
			viewState.page = target(viewState.page || 1, viewState.pageCount || 1);
			viewState.refreshLive();
		});
		return button;
	}

	refs.pageFirst = pageButton(_('第一页'), '«', function() { return 1; });
	refs.pagePrev = pageButton(_('上一页'), '‹', function(page) { return Math.max(1, page - 1); });
	refs.pageSummary = E('span', {
		'class': 'lanspeed-page-summary',
		'role': 'status',
		'aria-live': 'polite',
		'aria-atomic': 'true'
	}, '-');
	refs.pageNext = pageButton(_('下一页'), '›', function(page, count) {
		return Math.min(count, page + 1);
	});
	refs.pageLast = pageButton(_('最后一页'), '»', function(page, count) { return count; });
	refs.pageNav = E('nav', {
		'class': 'lanspeed-pagination',
		'aria-label': _('客户端分页'),
		'tabindex': '0'
	}, [
		E('label', { 'class': 'lanspeed-page-size-control' }, [
			_('每页'), refs.pageSizeSel
		]),
		E('div', { 'class': 'lanspeed-page-actions' }, [
			refs.pageFirst,
			refs.pagePrev,
			refs.pageSummary,
			refs.pageNext,
			refs.pageLast
		])
	]);
	refs.pageNav.addEventListener('keydown', function(event) {
		if (!event) return;
		var tag = event.target && String(event.target.tagName || '').toLowerCase();
		if (tag === 'select') return;
		var page = viewState.page || 1;
		var count = viewState.pageCount || 1;
		if (event.key === 'ArrowLeft') page = Math.max(1, page - 1);
		else if (event.key === 'ArrowRight') page = Math.min(count, page + 1);
		else if (event.key === 'Home') page = 1;
		else if (event.key === 'End') page = count;
		else return;
		if (event.preventDefault) event.preventDefault();
		viewState.page = page;
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
	refs.statusHeader = E('th', {
		'class': 'lanspeed-client-status-header'
	}, _('状态'));
	refs.statusHeader.hidden = viewState.showClientStatus !== true;
	refs.clientsTable = E('table', {
		'id': 'lanspeed-clients-table',
		'class': 'lanspeed-table',
		'data-client-status': viewState.showClientStatus === true ? 'shown' : 'hidden'
	}, [
		E('thead', {}, E('tr', {}, [
			sortableHeader(viewState, refs, 'hostname', _('客户端')),
			sortableHeader(viewState, refs, 'mac', 'MAC'),
			sortableHeader(viewState, refs, 'tx', _('上行'), { 'class': 'num' }),
			sortableHeader(viewState, refs, 'rx', _('下行'), { 'class': 'num' }),
			sortableHeader(viewState, refs, 'tcp_conns', 'TCP', {
				'class': 'num', 'title': _('当前已建立并确认的 TCP 连接')
			}),
			sortableHeader(viewState, refs, 'udp_conns', 'UDP', {
				'class': 'num', 'title': _('当前已确认的 UDP 连接')
			}),
			refs.statusHeader
		])),
		refs.tbody
	]);
	refs.empty = E('div', { 'class': 'lanspeed-empty', 'style': 'display:none' }, '-');

	var clientsCard = E('div', { 'class': 'cbi-section lanspeed-clients-card' }, [
		clientsHeader,
		E('div', { 'class': 'lanspeed-body' }, [
			toolbar,
			refs.clientsTable,
			refs.empty,
			refs.pageNav
		])
	]);

	refs.ifacesSummary = E('span', { 'class': 'sum' }, '');
	refs.ifacesBody    = E('tbody', {});
	refs.ifacesHint    = E('p', { 'class': 'lanspeed-hint' }, '');
	refs.ifacesPicker  = E('div', { 'class': 'lanspeed-iface-picker' });
	var ifacesTable = E('table', { 'class': 'lanspeed-table lanspeed-ifaces-table' }, [
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

	var root = E('div', {
		'class': 'cbi-map lanspeed-root lanspeed-status-root',
		'aria-busy': 'false'
	}, [
		E('style', {}, statusStyle.CSS),
		overviewCard,
		clientsCard,
		ifacesCard
	]);

	refs.root = root;
	lsTheme.applyRoot(root);

	return { root: root, refs: refs };
}

return baseclass.extend({
	buildShell: function(viewState) {
		return buildShell(viewState);
	}
});
