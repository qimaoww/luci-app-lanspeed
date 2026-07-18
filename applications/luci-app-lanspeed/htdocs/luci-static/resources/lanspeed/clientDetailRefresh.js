'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.clientConnections as clientConnections';

var CONNECTION_PAGE_SIZE = 100;
var LAZY_DETAIL_THRESHOLD = 32;

function replaceRows(tbody, rows) {
	var activeRow = document.activeElement;
	var activeRemoteIp = activeRow && activeRow.parentNode === tbody
		? activeRow.getAttribute('data-remote-ip') : null;

	while (tbody.firstChild)
		tbody.removeChild(tbody.firstChild);
	rows.forEach(function(row) {
		tbody.appendChild(row);
	});
	if (activeRemoteIp !== null) {
		rows.some(function(row) {
			if (row.getAttribute('data-remote-ip') !== activeRemoteIp)
				return false;
			row.focus();
			return true;
		});
	}
}

function warningLabel(warning) {
	if (warning === 'client_not_found') return _('客户端不存在');
	if (warning === 'conntrack_unavailable') return _('连接跟踪不可用');
	if (warning === 'conntrack_snapshot_incomplete') return _('连接快照不完整');
	return String(warning || '');
}

function sourceLabel(source) {
	if (source === 'conntrack_netlink') return 'Conntrack Netlink';
	if (source === 'conntrack_procfs') return 'Conntrack Procfs';
	if (source === 'nss_ecm_direct') return 'NSS-direct';
	return source ? String(source) : _('未知');
}

function stateLabel(state) {
	var value = String(state || '').toLowerCase();
	if (value === 'established') return _('已建立');
	if (value === 'assured') return _('活跃');
	return value ? String(state) : '-';
}

function directionLabel(direction) {
	return String(direction || '').toLowerCase() === 'inbound'
		? _('入站') : _('出站');
}

function detailEndpoint(connection) {
	var client = clientConnections.formatEndpoint(
		connection && connection.client_ip,
		connection && connection.client_port
	);
	var remote = clientConnections.formatEndpoint(
		connection && connection.remote_ip,
		connection && connection.remote_port
	);
	return String(connection && connection.direction || '').toLowerCase() === 'inbound'
		? remote + ' → ' + client
		: client + ' → ' + remote;
}

function protocolButton(ref, active) {
	ref.setAttribute('aria-pressed', active ? 'true' : 'false');
	ref.className = 'cbi-button lanspeed-connection-protocol' +
		(active ? ' active' : '');
}

function refreshSortHeaders(refs, viewState) {
	Object.keys(refs.sortHeaders || {}).forEach(function(sortKey) {
		var ref = refs.sortHeaders[sortKey];
		var active = viewState.sortCustom && viewState.sortKey === sortKey;
		var sortedColumn = viewState.sortKey === sortKey;
		var ascending = viewState.sortDir === 'asc';
		var title;
		if (!viewState.sortCustom && sortedColumn)
			title = _('%s：默认排序，点击开始降序排序').format(ref.label);
		else if (active && ascending)
			title = _('%s：当前升序，点击恢复默认排序').format(ref.label);
		else if (active)
			title = _('%s：当前降序，点击切换为升序').format(ref.label);
		else
			title = _('按%s降序排序').format(ref.label);

		ref.th.setAttribute('aria-sort', sortedColumn
			? (ascending ? 'ascending' : 'descending')
			: 'none');
		ref.button.setAttribute('title', title);
		ref.button.setAttribute('aria-label', title);
		ref.button.lastChild.textContent = active ? (ascending ? '↑' : '↓') : '';
	});
}

function twoDigits(value) {
	return value < 10 ? '0' + value : String(value);
}

function updatedAtLabel(updatedAt) {
	if (typeof updatedAt !== 'number' || !isFinite(updatedAt)) return '—';
	var received = new Date(updatedAt);
	if (!isFinite(received.getTime())) return '—';
	return twoDigits(received.getHours()) + ':' +
		twoDigits(received.getMinutes()) + ':' +
		twoDigits(received.getSeconds());
}

function ipDisplayRank(value) {
	var address = String(value || '').toLowerCase();
	if (address.indexOf(':') === -1)
		return 0;
	address = address.replace(/^\[/, '').split('%')[0];
	var first = parseInt(address.split(':')[0], 16);
	if (isFinite(first) && first >= 0xfe80 && first <= 0xfebf)
		return 1;
	return 2;
}

function orderedClientIps(values) {
	return fmt.asArray(values).map(function(value, index) {
		return { value: value, index: index, rank: ipDisplayRank(value) };
	}).sort(function(left, right) {
		return left.rank - right.rank || left.index - right.index;
	}).map(function(entry) {
		return entry.value;
	});
}

function clearElement(node) {
	while (node.firstChild)
		node.removeChild(node.firstChild);
}

function metaFact(label, value) {
	return E('span', { 'class': 'lanspeed-connection-meta-fact' }, [
		E('span', { 'class': 'lanspeed-connection-meta-label' }, label),
		E('span', { 'class': 'lanspeed-connection-meta-value' }, value)
	]);
}

function renderClientMeta(ref, client, ips, identityKey) {
	clearElement(ref);

	if (ips.length) {
		ref.appendChild(E('div', {
			'class': 'lanspeed-connection-meta-group lanspeed-connection-meta-addresses'
		}, [
			E('div', { 'class': 'lanspeed-connection-meta-heading' }, [
				E('span', { 'class': 'lanspeed-connection-meta-heading-label' },
					_('IP 地址')),
				E('span', { 'class': 'lanspeed-connection-meta-count' },
					String(ips.length))
			]),
			E('div', { 'class': 'lanspeed-connection-meta-values' },
				ips.map(function(ip) {
					return E('span', {
						'class': 'lanspeed-connection-meta-ip'
					}, ip);
				}))
		]));
	}

	var facts = [];
	if (client && client.mac)
		facts.push(metaFact(_('MAC 地址'), client.mac));
	if (client && client.interface)
		facts.push(metaFact(_('接口'), client.interface));
	if (!ips.length && !facts.length && identityKey)
		facts.push(metaFact(_('身份标识'), identityKey));

	if (facts.length) {
		ref.appendChild(E('div', {
			'class': 'lanspeed-connection-meta-facts',
			'data-count': String(facts.length)
		}, facts));
	}

	if (!ref.firstChild) {
		ref.appendChild(E('span', {
			'class': 'lanspeed-connection-meta-empty'
		}, _('客户端身份不可用')));
	}
}

function detailRate(label, arrow, value, unit) {
	var formatted = fmt.formatRate(value, unit);
	return E('span', {
		'class': 'lanspeed-connection-detail-rate',
		'title': label
	}, [
		E('span', { 'aria-hidden': 'true' }, arrow),
		' ',
		label,
		' ',
		formatted
	]);
}

function buildGroupRows(viewState, group) {
	var expanded = viewState.expanded[group.remoteIp] === true;
	var unit = viewState.prefs && viewState.prefs.unit;
	var groupRow = E('tr', {
		'class': 'lanspeed-connection-group lanspeed-connection-group-row',
		'data-remote-ip': group.remoteIp,
		'tabindex': '0',
		'role': 'button',
		'aria-expanded': expanded ? 'true' : 'false'
	}, [
		E('td', {
			'class': 'lanspeed-connection-target-cell lanspeed-connection-endpoint',
			'data-label': _('目标 IP')
		}, group.remoteIp || '-'),
		E('td', {
			'class': 'lanspeed-connection-location-cell',
			'data-label': _('国家/地区')
		}, group.locationLabel || _('未知')),
		E('td', { 'data-label': _('目标端口') }, group.portLabel),
		E('td', { 'data-label': _('协议') }, group.protocolLabel),
		E('td', { 'data-label': _('状态') }, group.stateLabel),
		E('td', {
			'class': 'num lanspeed-connection-rate-cell',
			'data-label': _('上行')
		}, fmt.formatRate(group.txBps, unit)),
		E('td', {
			'class': 'num lanspeed-connection-rate-cell',
			'data-label': _('下行')
		}, fmt.formatRate(group.rxBps, unit)),
		E('td', { 'data-label': _('连接数') }, String(group.count))
	]);

	function toggle(event) {
		if (event && event.preventDefault) event.preventDefault();
		expanded = !expanded;
		viewState.expanded[group.remoteIp] = expanded;
		if (expanded)
			ensureDetails();
		groupRow.setAttribute('aria-expanded', expanded ? 'true' : 'false');
		detailRow.hidden = !expanded;
	}

	groupRow.addEventListener('click', toggle);
	groupRow.addEventListener('keydown', function(event) {
		if (!event || (event.key !== 'Enter' && event.key !== ' ' && event.key !== 'Spacebar'))
			return;
		toggle(event);
		groupRow.focus();
	});

	function detailItem(connection) {
		return E('div', { 'class': 'lanspeed-connection-detail-item' }, [
			E('span', { 'class': 'lanspeed-connection-endpoint' },
				detailEndpoint(connection)),
			E('span', { 'class': 'lanspeed-connection-detail-meta' }, [
				directionLabel(connection && connection.direction),
				' · ',
				String(connection && connection.protocol || '-').toUpperCase(),
				' · ',
				stateLabel(connection && connection.state)
			]),
			E('span', { 'class': 'lanspeed-connection-detail-rates' }, [
				detailRate(_('上行'), '↑', connection && connection.tx_bps, unit),
				detailRate(_('下行'), '↓', connection && connection.rx_bps, unit)
			])
		]);
	}
	var detailList = E('div', { 'class': 'lanspeed-connection-detail-list' });
	var detailsBuilt = false;
	function ensureDetails() {
		if (detailsBuilt) return;
		detailsBuilt = true;
		group.connections.forEach(function(connection) {
			detailList.appendChild(detailItem(connection));
		});
	}
	var detailRow = E('tr', {
		'class': 'lanspeed-connection-detail-row'
	}, E('td', {
		'class': 'lanspeed-connection-detail-cell',
		'colspan': '8',
		'data-label': _('连接详情')
	}, detailList));
	detailRow.hidden = !expanded;
	if (group.connections.length <= LAZY_DETAIL_THRESHOLD || expanded)
		ensureDetails();

	return [ groupRow, detailRow ];
}

function errorText(error, response) {
	var detail = error && error.message ? error.message : String(error || '');
	var prefix;
	if (!response)
		prefix = _('首次加载连接详情失败，请稍后重试');
	else if (response.available === false)
		prefix = _('刷新连接详情失败，连接数据仍不可用');
	else
		prefix = _('刷新连接详情失败，正在显示上次成功的数据');
	return detail ? prefix + '：' + detail : prefix;
}

function render(viewState) {
	var refs = viewState && viewState.refs;
	if (!refs) return;

	var response = viewState.response || null;
	var warnings = fmt.asArray(response && response.warnings);
	var notFound = Boolean(response) &&
		(!response.client || warnings.indexOf('client_not_found') !== -1);
	var usable = Boolean(response && response.available === true && !notFound);
	var incomplete = Boolean(response && response.available === false &&
		warnings.indexOf('conntrack_snapshot_incomplete') !== -1);
	var client = response && response.client;
	var ips = orderedClientIps(client && client.ips);
	var displayName = client && client.hostname || ips[0] ||
		client && client.mac || viewState.identityKey || '-';
	var locationLookup = typeof viewState.locationLabelFor === 'function'
		? function(ip) { return viewState.locationLabelFor(ip); }
		: null;

	refs.clientName.textContent = displayName;
	renderClientMeta(refs.clientMeta, client, ips, viewState.identityKey);

	if (usable) {
		refs.connectionState.textContent = Number(response.total_connections) > 0
			? _('有当前连接') : _('暂无连接');
		refs.connectionState.setAttribute('data-state',
			Number(response.total_connections) > 0 ? 'active' : 'idle');
	} else if (response && response.available === false) {
		refs.connectionState.textContent = _('数据不可用');
		refs.connectionState.setAttribute('data-state', 'unavailable');
	} else {
		refs.connectionState.textContent = _('等待数据');
		refs.connectionState.setAttribute('data-state', 'pending');
	}

	var allGroups = usable
		? clientConnections.groupsForResponse(response, 'all', '', locationLookup) : [];
	var present = Object.create(null);
	allGroups.forEach(function(group) { present[group.remoteIp] = true; });
	Object.keys(viewState.expanded || {}).forEach(function(remoteIp) {
		if (!present[remoteIp]) delete viewState.expanded[remoteIp];
	});
	var groups = usable
		? clientConnections.groupsForResponse(
			response, viewState.protocol, viewState.filter, locationLookup)
		: [];
	groups = clientConnections.sortGroups(groups, viewState.sortKey, viewState.sortDir);
	var pageSize = Number(viewState.pageSize);
	var interval = viewState.prefs && viewState.prefs.refreshMs;
	if (!isFinite(pageSize) || pageSize < 1)
		pageSize = CONNECTION_PAGE_SIZE;
	pageSize = Math.max(1, Math.floor(pageSize));
	var pageCount = groups.length ? Math.ceil(groups.length / pageSize) : 1;
	var page = Number(viewState.page);
	if (!isFinite(page) || page < 0)
		page = 0;
	page = Math.min(Math.floor(page), pageCount - 1);
	viewState.page = page;
	var pageGroups = groups.slice(page * pageSize, (page + 1) * pageSize);
	if (typeof viewState.requestLocations === 'function') {
		viewState.requestLocations(pageGroups.map(function(group) {
			return group.remoteIp;
		}));
	}

	refs.summaryTargets.textContent = usable
		? (response.truncated ? _('至少 ') : '') + String(allGroups.length)
		: '—';
	refs.summaryConnections.textContent = usable
		? String(Number(response.total_connections) || 0) : '—';
	refs.summaryUpdated.textContent = updatedAtLabel(viewState.updatedAt);

	var rows = [];
	pageGroups.forEach(function(group) {
		rows = rows.concat(buildGroupRows(viewState, group));
	});
	replaceRows(refs.tbody, rows);

	var emptyText = '';
	if (viewState.error && !response)
		emptyText = _('首次加载连接详情失败，请稍后重试。');
	else if (notFound)
		emptyText = _('未找到该客户端，可能已离开 LAN。');
	else if (incomplete)
		emptyText = _('连接快照不完整，无法确认当前连接数量，请稍后重试。');
	else if (response && response.available === false)
		emptyText = _('连接采集当前不可用，请稍后重试。');
	else if (usable && Number(response.total_connections) === 0)
		emptyText = _('当前客户端没有连接。');
	else if (usable && !groups.length)
		emptyText = _('没有匹配当前筛选条件的连接。');
	else if (!response)
		emptyText = _('连接数据尚未加载。');

	refs.table.hidden = rows.length === 0;
	refs.empty.hidden = rows.length !== 0;
	refs.empty.textContent = emptyText;
	refs.error.hidden = !viewState.error;
	if (viewState.error)
		refs.error.lastChild.textContent = errorText(viewState.error, response);

	protocolButton(refs.protocolAll, viewState.protocol === 'all');
	protocolButton(refs.protocolTcp, viewState.protocol === 'tcp');
	protocolButton(refs.protocolUdp, viewState.protocol === 'udp');
	refreshSortHeaders(refs, viewState);
	refs.filter.value = viewState.filter || '';
	if (refs.intervalSel) {
		refs.intervalSel.value = String(interval);
		refs.intervalSel.disabled = viewState.manualLoading === true;
	}
	refs.refresh.disabled = viewState.manualLoading === true;
	refs.refresh.setAttribute('aria-busy',
		viewState.manualLoading === true ? 'true' : 'false');
	if (refs.pause) {
		refs.pause.textContent = viewState.prefs && viewState.prefs.paused
			? _('恢复') : _('暂停');
		refs.pause.setAttribute('aria-pressed',
			viewState.prefs && viewState.prefs.paused ? 'true' : 'false');
	}
	if (refs.pager) {
		refs.pagePrev.disabled = page <= 0 || !usable || viewState.loading === true;
		refs.pageNext.disabled = page >= pageCount - 1 || !usable || viewState.loading === true;
		refs.pageStatus.textContent = usable && groups.length
			? String(page + 1) + ' / ' + String(pageCount) : '—';
		refs.pager.hidden = !usable || pageCount <= 1;
	}

	var footer = [];
	if (response) {
		footer.push(_('连接数据：') + sourceLabel(response.conn_source));
		if (usable) {
			footer.push(_('显示 %d / 共 %d 条').format(
				Number(response.returned_connections) || 0,
				Number(response.total_connections) || 0));
			if (response.truncated)
				footer.push(_('连接较多，仅显示前 %d 条').format(Number(response.limit) || 0));
			if (response.truncated)
				footer.push(_('分组速率仅汇总已显示连接'));
		}
		if (warnings.length)
			footer.push(_('告警：') + warnings.map(warningLabel).join('，'));
	}
	footer.push(viewState.prefs && viewState.prefs.paused
		? _('自动刷新已暂停')
		: _('每 %s 秒自动刷新').format(String(Math.round(Number(interval) / 100) / 10)));
	footer.push(_('国家/地区及中国省份按 IP 推测，由浏览器查询并缓存，结果可能不准确'));
	refs.footer.textContent = footer.join(' · ');
}

return baseclass.extend({
	render: render
});
