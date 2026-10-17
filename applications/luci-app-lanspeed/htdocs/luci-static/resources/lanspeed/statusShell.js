'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.theme as lsTheme';
'require lanspeed.statusStyle as statusStyle';

/* Interface throughput is secondary; remember whether the viewer expanded it. */
var IFACES_OPEN_KEY = 'luci-app-lanspeed.ifaces-open.v1';
/* Column widths used to be measured and stored per browser. The table now uses
 * fixed CSS tracks, so drop the obsolete preference instead of leaving it. */
var LEGACY_COLUMN_WIDTHS_KEY = 'luci-app-lanspeed.client-column-widths.v12';

/* Direction keys for every merged column, ordered download first. */
var SORT_KEYS_BY_COLUMN = {
	rate: [ 'rx', 'tx' ],
	totals: [ 'rx_bytes', 'tx_bytes' ],
	conns: [ 'tcp_conns', 'udp_conns' ]
};

function readFlag(key) {
	try { return window.localStorage.getItem(key) === '1'; } catch (e) { return false; }
}

function writeFlag(key, value) {
	try { window.localStorage.setItem(key, value ? '1' : '0'); } catch (e) {}
}

function forgetLegacyColumnWidths() {
	try { window.localStorage.removeItem(LEGACY_COLUMN_WIDTHS_KEY); } catch (e) {}
}

function clientHeader(refs, columnKey, label, attrs) {
	var thAttrs = Object.assign({ 'scope': 'col', 'aria-sort': 'none' }, attrs || {});
	thAttrs['data-column-key'] = columnKey;
	var th = E('th', thAttrs, label);
	refs.sortHeaders[columnKey] = {
		th: th,
		keys: SORT_KEYS_BY_COLUMN[columnKey] || [ columnKey ],
		label: label
	};
	return th;
}

function sortChoices() {
	var fields = [
		[ 'rx', _('下载速度') ], [ 'tx', _('上传速度') ],
		[ 'rx_bytes', _('累计下载') ], [ 'tx_bytes', _('累计上传') ],
		[ 'hostname', _('客户端') ], [ 'mac', 'MAC' ],
		[ 'tcp_conns', _('TCP 连接') ], [ 'udp_conns', _('UDP 连接') ]
	];
	var choices = [ { value: 'default', label: _('默认（下载优先）') } ];
	fields.forEach(function(field) {
		choices.push({ value: field[0] + ':desc', label: field[1] + ' · ' + _('降序') });
		choices.push({ value: field[0] + ':asc', label: field[1] + ' · ' + _('升序') });
	});
	return choices;
}

/* One metric tile: caption, a single value line and one hint line, so every
 * tile keeps the same three-row rhythm across themes. */
function metric(key, caption, value, hint, attrs) {
	return E('div', Object.assign({ 'class': 'lanspeed-metric', 'data-metric': key }, attrs || {}), [
		E('div', { 'class': 'caption' }, caption),
		value,
		hint
	]);
}

function directionCaption(direction, label) {
	return [
		E('span', {
			'class': 'lanspeed-direction-mark',
			'data-direction': direction,
			'aria-hidden': 'true'
		}, direction === 'rx' ? '↓' : '↑'),
		' ', label
	];
}

function stopEvent(event) {
	if (event && event.preventDefault) event.preventDefault();
	if (event && event.stopPropagation) event.stopPropagation();
}

function buildShell(viewState) {
	var refs = {};
	var prefs = viewState.prefs;
	refs.sortHeaders = {};
	forgetLegacyColumnWidths();

	/* --- Status bar: identity, collection state and the page-level refresh actions. */
	refs.collectorPill = E('span', { 'class': 'label lanspeed-collector-status' }, '-');
	refs.liveState = E('span', {
		'class': 'lanspeed-live-state',
		'data-state': 'loading',
		'role': 'status',
		'aria-live': 'polite'
	}, '-');
	refs.meta = E('span', { 'class': 'meta lanspeed-status-version' }, '');

	refs.btnRefresh = E('button', {
		'type': 'button',
		'class': 'cbi-button cbi-button-action lanspeed-status-refresh',
		'aria-label': _('立即刷新实时状态')
	}, _('立即刷新'));
	refs.btnRefresh.addEventListener('click', function(event) {
		stopEvent(event);
		viewState.reload(true);
	});

	refs.btnPause = E('button', {
		'type': 'button',
		'class': 'cbi-button lanspeed-status-pause',
		'aria-pressed': prefs.paused ? 'true' : 'false'
	}, prefs.paused ? _('恢复') : _('暂停'));
	refs.btnPause.addEventListener('click', function(event) {
		stopEvent(event);
		viewState.prefs.paused = !viewState.prefs.paused;
		refs.btnPause.textContent = viewState.prefs.paused ? _('恢复') : _('暂停');
		refs.btnPause.setAttribute('aria-pressed', viewState.prefs.paused ? 'true' : 'false');
		fmt.savePrefs(viewState.prefs);
		if (viewState.prefs.paused) viewState.stopTimer(); else viewState.schedule();
		if (typeof viewState.refreshLive === 'function') viewState.refreshLive();
	});
	var nssRefreshRestricted = typeof fmt.nssRefreshRestricted === 'function' &&
		fmt.nssRefreshRestricted(viewState.status);
	var refreshValue = nssRefreshRestricted
		? fmt.normalizeNssRefreshMs(prefs.nssRefreshMs) : prefs.refreshMs;
	var refreshChoices = nssRefreshRestricted
		? fmt.NSS_REFRESH_CHOICES
		: fmt.REFRESH_CHOICES;
	refs.intervalSel = E('select', {
		'class': 'cbi-input-select',
		'aria-label': _('刷新间隔'),
		'data-refresh-policy': nssRefreshRestricted ? 'nss' : 'default',
		'title': nssRefreshRestricted ? _('ECM 采集方案最低每 2 秒刷新') : ''
	}, refreshChoices.map(function(c) {
		return fmt.opt(c.value, c.label, refreshValue === c.value);
	}));
	refs.intervalSel.addEventListener('change', function(ev) {
		var v = parseInt(ev.target.value, 10);
		var nss = typeof fmt.nssRefreshRestricted === 'function' &&
			fmt.nssRefreshRestricted(viewState.status);
		if (nss && fmt.NSS_REFRESH_CHOICES.some(function(choice) { return choice.value === v; })) {
			viewState.prefs.nssRefreshMs = v;
		} else if (!nss && !isNaN(v) && v >= fmt.MIN_REFRESH_MS) {
			viewState.prefs.refreshMs = v;
		} else {
			return;
		}
		fmt.savePrefs(viewState.prefs);
		viewState.schedule();
		if (typeof viewState.refreshLive === 'function') viewState.refreshLive();
	});

	var statusHeader = E('div', { 'class': 'lanspeed-header lanspeed-status-bar' }, [
		E('div', { 'class': 'lanspeed-status-title' }, [
			E('h3', {}, _('LAN Speed')),
			refs.collectorPill,
			refs.liveState,
			refs.meta
		]),
		E('span', { 'class': 'spacer' }),
		E('div', { 'class': 'lanspeed-status-actions' }, [
			E('label', { 'class': 'lanspeed-refresh-control' }, [ _('刷新'), refs.intervalSel ]),
			refs.btnRefresh,
			refs.btnPause
		])
	]);

	refs.errorTitle = E('strong', {
		'class': 'lanspeed-status-error-title'
	}, _('部分实时数据暂未更新'));
	refs.errorPre = E('p', { 'class': 'lanspeed-status-error-summary' }, '');
	refs.errorList = E('ul', { 'class': 'lanspeed-status-error-list' });
	refs.errorBox = E('div', {
		'class': 'lanspeed-status-error',
		'role': 'status',
		'aria-live': 'polite',
		'aria-atomic': 'true',
		'aria-hidden': 'true',
		'style': 'display:none'
	}, [
		refs.errorTitle,
		refs.errorPre,
		refs.errorList
	]);
	/* --- Core metrics: download, upload, clients, connections. Download comes
	 * first everywhere on the page, matching the per-client columns. */
	refs.mRx          = E('div', { 'class': 'big' }, '—');
	refs.mTx          = E('div', { 'class': 'big' }, '—');
	refs.mClients     = E('div', { 'class': 'big' }, '—');
	refs.mClientsSub  = E('div', { 'class': 'hint' }, '-');
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
	refs.mConnsWrap = metric('conns', _('连接数'), refs.mConnsValue, refs.mUdpConnsSub, {
		'title': _('当前连接来自 conntrack：TCP 统计已建立且确认的连接，UDP 统计已确认的连接。')
	});
	var metrics = E('div', { 'class': 'lanspeed-metrics' }, [
		metric('rx', directionCaption('rx', _('下载')), refs.mRx,
			E('div', { 'class': 'hint' }, _('客户端接收 · rx'))),
		metric('tx', directionCaption('tx', _('上传')), refs.mTx,
			E('div', { 'class': 'hint' }, _('客户端发出 · tx'))),
		metric('clients', _('客户端'), refs.mClients, refs.mClientsSub),
		refs.mConnsWrap
	]);

	var overviewCard = E('div', { 'class': 'cbi-section lanspeed-overview-card' }, [
		statusHeader,
		E('div', { 'class': 'lanspeed-body' }, [
			refs.errorBox,
			metrics
		])
	]);
	/* --- Client toolbar: narrowing (search, active) left, ordering and display right. */
	refs.filterInput = E('input', {
		'type': 'search',
		'class': 'cbi-input-text',
		'aria-label': _('过滤客户端'),
		'aria-controls': 'lanspeed-clients-table',
		'placeholder': _('搜索名称 / IP / MAC / 厂商'),
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

	var sortingChoices = sortChoices();
	var sortValue = prefs.sortCustom ? prefs.sortKey + ':' + prefs.sortDir : 'default';
	refs.sortSelect = E('select', {
		'class': 'cbi-input-select lanspeed-sort-select',
		'aria-label': _('客户端排序'),
		'aria-controls': 'lanspeed-clients-table'
	}, sortingChoices.map(function(choice) {
		return fmt.opt(choice.value, choice.label, choice.value === sortValue);
	}));
	refs.sortSelect.addEventListener('change', function(ev) {
		var value = ev.target.value;
		if (!sortingChoices.some(function(choice) { return choice.value === value; })) return;
		var parts = value.split(':');
		var defaults = fmt.DEFAULT_PREFS || { sortKey: 'rx', sortDir: 'desc' };
		viewState.prefs.sortKey = value === 'default' ? defaults.sortKey : parts[0];
		viewState.prefs.sortDir = value === 'default' ? defaults.sortDir : parts[1];
		viewState.prefs.sortCustom = value !== 'default';
		viewState.page = 1;
		fmt.savePrefs(viewState.prefs);
		viewState.refreshLive();
	});

	refs.unitSel = E('select', { 'class': 'cbi-input-select', 'aria-label': _('速率单位') }, [
		fmt.opt('bit',  'bit/s',  prefs.unit === 'bit'),
		fmt.opt('byte', 'Byte/s', prefs.unit === 'byte')
	]);
	refs.unitSel.addEventListener('change', function(ev) {
		viewState.prefs.unit = ev.target.value;
		fmt.savePrefs(viewState.prefs);
		viewState.refreshLive();
	});

	var toolbar = E('div', { 'class': 'lanspeed-toolbar lanspeed-clients-toolbar' }, [
		E('div', { 'class': 'lanspeed-toolbar-left' }, [
			E('div', { 'class': 'lanspeed-toolbar-filter' }, [
				refs.filterInput,
				E('label', { 'class': 'lanspeed-active-only cbi-checkbox', 'for': 'lanspeed-active' }, [
					refs.activeChk,
					E('span', { 'class': 'lanspeed-active-label' }, _('仅活跃'))
				])
			])
		]),
		E('div', { 'class': 'lanspeed-toolbar-right' }, [
			E('label', { 'class': 'lanspeed-sort-control' }, [ _('排序'), refs.sortSelect ]),
			E('label', { 'class': 'lanspeed-unit-control' }, [ _('单位'), refs.unitSel ])
		])
	]);
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
	refs.pageLast = pageButton(_('最后一页'), '»', function(_page, count) { return count; });
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

	/* --- Client table: identity first, then rate, totals and connections as
	 * right-aligned numeric columns, and row actions last. Column tracks are
	 * fixed in CSS so live values never resize the table between samples. */
	refs.clientsHeaderSummary = E('span', { 'class': 'meta lanspeed-clients-summary' }, '');
	var clientsHeader = E('div', { 'class': 'lanspeed-header' }, [
		E('h3', {}, _('LAN 客户端')),
		E('span', { 'class': 'spacer' }),
		refs.clientsHeaderSummary
	]);

	refs.tbody = E('tbody', {});
	refs.totalHeader = clientHeader(refs, 'totals', _('累计流量'), {
		'class': 'num lanspeed-client-total-header',
		'title': _('启用采集后累计的实际字节数')
	});
	refs.totalHeader.hidden = viewState.showClientTotals !== true;
	refs.controlHeader = E('th', {
		'scope': 'col',
		'class': 'lanspeed-client-control-header',
		'data-column-key': 'control'
	}, _('控制'));
	refs.clientsTable = E('table', {
		'id': 'lanspeed-clients-table',
		'class': 'lanspeed-table lanspeed-clients-table',
		'data-client-totals': viewState.showClientTotals === true ? 'shown' : 'hidden'
	}, [
		E('thead', {}, E('tr', {}, [
			clientHeader(refs, 'hostname', _('客户端')),
			clientHeader(refs, 'mac', _('MAC / OUI 厂商'), {
				'title': _('厂商按 MAC 前缀（OUI）在浏览器本地匹配，表示地址注册机构，可能是网卡或模块厂商')
			}),
			clientHeader(refs, 'rate', _('网速'), { 'class': 'num lanspeed-client-rate-header' }),
			refs.totalHeader,
			clientHeader(refs, 'conns', _('连接'), {
				'class': 'num lanspeed-client-conns-header',
				'title': _('当前已建立并确认的 TCP 连接与已确认的 UDP 连接')
			}),
			refs.controlHeader
		])),
		refs.tbody
	]);
	refs.empty = E('div', {
		'class': 'lanspeed-empty',
		'role': 'status',
		'aria-live': 'polite',
		'aria-atomic': 'true',
		'style': 'display:none'
	}, '-');

	var clientsCard = E('div', { 'class': 'cbi-section lanspeed-clients-card' }, [
		clientsHeader,
		E('div', { 'class': 'lanspeed-body' }, [
			toolbar,
			E('div', { 'class': 'lanspeed-table-scroll' }, [ refs.clientsTable ]),
			refs.empty,
			refs.pageNav
		])
	]);
	/* --- Interface throughput: supporting evidence, collapsed by default with
	 * its LAN summary still visible on the summary line. */
	refs.ifacesSummary = E('span', { 'class': 'sum' }, '');
	refs.ifacesBody    = E('tbody', {});
	refs.ifacesHint    = E('p', { 'class': 'lanspeed-hint' }, '');
	var ifacesTable = E('table', { 'class': 'lanspeed-table lanspeed-ifaces-table' }, [
		E('thead', {}, E('tr', {}, [
			E('th', { 'scope': 'col' }, _('接口')),
			E('th', { 'scope': 'col', 'class': 'num' }, _('接口 ↓')),
			E('th', { 'scope': 'col', 'class': 'num' }, _('接口 ↑')),
			E('th', { 'scope': 'col', 'class': 'num' }, _('客户端 ↓')),
			E('th', { 'scope': 'col', 'class': 'num' }, _('客户端 ↑'))
		])),
		refs.ifacesBody
	]);
	var ifacesAttrs = { 'class': 'lanspeed-details' };
	if (readFlag(IFACES_OPEN_KEY)) ifacesAttrs.open = 'open';
	refs.ifacesDetails = E('details', ifacesAttrs, [
		E('summary', {}, [
			E('h3', {}, _('接口吞吐')),
			E('span', { 'class': 'spacer' }),
			refs.ifacesSummary
		]),
		E('div', { 'class': 'lanspeed-details-body' }, [
			ifacesTable,
			refs.ifacesHint
		])
	]);
	refs.ifacesDetails.addEventListener('toggle', function() {
		writeFlag(IFACES_OPEN_KEY, !!refs.ifacesDetails.open);
	});
	var ifacesCard = E('div', { 'class': 'cbi-section lanspeed-ifaces-card' }, [ refs.ifacesDetails ]);

	var root = E('div', {
		'class': 'cbi-map lanspeed-root lanspeed-status-root',
		'aria-busy': 'true',
		'data-state': 'loading'
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
