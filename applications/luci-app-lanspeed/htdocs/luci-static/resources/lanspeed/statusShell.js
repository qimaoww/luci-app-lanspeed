'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.theme as lsTheme';
'require lanspeed.statusStyle as statusStyle';

/* Interface throughput is secondary evidence: keep whether the viewer expanded
 * it so the page opens the same way on the next visit. */
var IFACES_OPEN_KEY = 'luci-app-lanspeed.ifaces-open.v1';
/* Column widths were once measured per browser. The table now owns its tracks,
 * so drop the obsolete preference instead of leaving it behind. */
var LEGACY_COLUMN_WIDTHS_KEY = 'luci-app-lanspeed.client-column-widths.v12';

/* Columns that stack both directions sort by their download key first. TCP and
 * UDP get one column each so connection counts line up with the headers. */
var SORT_KEYS_BY_COLUMN = {
	rate: [ 'rx', 'tx' ],
	totals: [ 'rx_bytes', 'tx_bytes' ]
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

/* Sortable header cell. The sort control itself lives in the toolbar, so the
 * table only advertises its state through aria-sort. */
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

/* One stat: caption, value line and one hint line. Keeping every stat on the
 * same three-row rhythm is what lets the numbers be compared at a glance. */
function metric(key, caption, value, hint, attrs) {
	return E('div', Object.assign({ 'class': 'lanspeed-metric', 'data-metric': key }, attrs || {}), [
		E('div', { 'class': 'lanspeed-metric-caption' }, caption),
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

	/* --- Page head: identity and collection state on the left, the two global
	 * actions on the right. Per-list controls stay inside the client card. */
	refs.collectorPill = E('span', { 'class': 'label lanspeed-collector-status' }, '-');
	refs.liveState = E('span', {
		'class': 'lanspeed-live-state',
		'data-state': 'loading',
		'role': 'status',
		'aria-live': 'polite'
	}, '-');
	refs.meta = E('span', { 'class': 'lanspeed-status-version meta' }, '');

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
		'class': 'cbi-input-select lanspeed-refresh-select',
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
		E('span', { 'class': 'lanspeed-spacer' }),
		E('div', { 'class': 'lanspeed-status-actions' }, [
			refs.btnPause,
			refs.btnRefresh
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

	/* --- Core stats: download and upload first, then clients and connections.
	 * The four tiles share one row on wide screens and two columns below. */
	refs.mRx          = E('div', { 'class': 'lanspeed-stat-value' }, '—');
	refs.mTx          = E('div', { 'class': 'lanspeed-stat-value' }, '—');
	refs.mClients     = E('div', { 'class': 'lanspeed-stat-value' }, '—');
	refs.mClientsSub  = E('div', { 'class': 'lanspeed-stat-hint' }, '-');
	refs.mTcpConns    = E('span', { 'class': 'lanspeed-connection-number' }, '-');
	refs.mUdpConns    = E('span', { 'class': 'lanspeed-connection-number' }, '-');
	refs.mUdpConnsSub = E('div', { 'class': 'lanspeed-stat-hint' }, '-');
	refs.mConnsValue  = E('div', { 'class': 'lanspeed-stat-value lanspeed-connection-values' }, [
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
			E('div', { 'class': 'lanspeed-stat-hint' }, _('客户端接收'))),
		metric('tx', directionCaption('tx', _('上传')), refs.mTx,
			E('div', { 'class': 'lanspeed-stat-hint' }, _('客户端发出'))),
		metric('clients', _('客户端'), refs.mClients, refs.mClientsSub),
		refs.mConnsWrap
	]);
	var statsCard = E('div', { 'class': 'cbi-section lanspeed-stats-card' }, [
		statusHeader,
		E('div', { 'class': 'lanspeed-body' }, [ refs.errorBox, metrics ])
	]);

	/* --- Client toolbar: narrowing on the left; cadence, ordering and units are
	 * display preferences and stay together on the right. */
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

	refs.unitSel = E('select', { 'class': 'cbi-input-select lanspeed-unit-select', 'aria-label': _('速率单位') }, [
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
			E('div', { 'class': 'lanspeed-toolbar-filter' }, [ refs.filterInput ]),
			E('label', { 'class': 'lanspeed-active-only cbi-checkbox', 'for': 'lanspeed-active' }, [
				refs.activeChk,
				E('span', { 'class': 'lanspeed-active-label' }, _('仅活跃'))
			])
		]),
		E('div', { 'class': 'lanspeed-toolbar-right' }, [
			E('label', { 'class': 'lanspeed-refresh-control' }, [
				E('span', { 'class': 'lanspeed-control-label' }, _('刷新')),
				refs.intervalSel
			]),
			E('label', { 'class': 'lanspeed-sort-control' }, [
				E('span', { 'class': 'lanspeed-control-label' }, _('排序')),
				refs.sortSelect
			]),
			E('label', { 'class': 'lanspeed-unit-control' }, [
				E('span', { 'class': 'lanspeed-control-label' }, _('单位')),
				refs.unitSel
			])
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
			E('span', { 'class': 'lanspeed-control-label' }, _('每页')),
			refs.pageSizeSel
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

	/* --- Client table: identity first, then rate, totals and one numeric column
	 * per transport, with row actions last. Column tracks are fixed in CSS so a
	 * live sample never reflows the table. */
	refs.clientsHeaderSummary = E('span', { 'class': 'lanspeed-clients-summary' }, '');
	var clientsHeader = E('div', { 'class': 'lanspeed-header lanspeed-clients-header' }, [
		E('h3', {}, _('LAN 客户端')),
		E('span', { 'class': 'lanspeed-spacer' }),
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
			clientHeader(refs, 'tcp_conns', 'TCP', {
				'class': 'num lanspeed-client-count-header',
				'title': _('当前已建立并确认的 TCP 连接数')
			}),
			clientHeader(refs, 'udp_conns', 'UDP', {
				'class': 'num lanspeed-client-count-header',
				'title': _('当前已确认的 UDP 连接数，含 DNS 与其它流')
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

	/* --- Interface throughput: supporting evidence, collapsed by default with
	 * its LAN summary still visible on the summary line. */
	refs.ifacesSummary = E('span', { 'class': 'lanspeed-ifaces-summary' }, '');
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
			E('span', { 'class': 'lanspeed-spacer' }),
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
	/* Interface throughput lives inside the client card: it is supporting
	 * evidence for the rates above, not a page of its own. */
	refs.ifacesBlock = E('div', { 'class': 'lanspeed-ifaces-block' }, [ refs.ifacesDetails ]);

	var clientsCard = E('div', { 'class': 'cbi-section lanspeed-clients-card' }, [
		clientsHeader,
		E('div', { 'class': 'lanspeed-body' }, [
			toolbar,
			E('div', { 'class': 'lanspeed-table-scroll' }, [ refs.clientsTable ]),
			refs.empty,
			refs.pageNav,
			refs.ifacesBlock
		])
	]);

	var root = E('div', {
		'class': 'cbi-map lanspeed-root lanspeed-status-root',
		'aria-busy': 'true',
		'data-state': 'loading'
	}, [
		E('style', {}, statusStyle.CSS),
		statsCard,
		clientsCard
	]);

	refs.root = root;
	lsTheme.applyRoot(root);

	return { root: root, refs: refs };
}

return baseclass.extend({
	buildShell: buildShell
});
