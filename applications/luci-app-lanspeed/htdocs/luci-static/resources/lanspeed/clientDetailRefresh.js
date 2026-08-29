'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.clientConnections as clientConnections';

var CONNECTION_PAGE_SIZE = 100;
var LAZY_DETAIL_THRESHOLD = 32;

function effectiveRefreshMs(viewState) {
	return typeof viewState.effectiveRefreshMs === 'function'
		? viewState.effectiveRefreshMs()
		: Number(viewState.prefs && viewState.prefs.refreshMs) || 3000;
}

function refreshIntervalControl(viewState, refs) {
	if (!refs || !refs.intervalSel) return;
	var choices = viewState.refreshChoices || [];
	var restricted = typeof fmt.nssRefreshRestricted === 'function' &&
		fmt.nssRefreshRestricted(viewState.status);
	var policy = restricted ? 'nss' : 'default';
	if (refs.intervalSel.getAttribute('data-refresh-policy') !== policy) {
		while (refs.intervalSel.firstChild)
			refs.intervalSel.removeChild(refs.intervalSel.firstChild);
		choices.forEach(function(choice) {
			refs.intervalSel.appendChild(fmt.opt(
				choice.value,
				choice.label,
				Number(choice.value) === Number(effectiveRefreshMs(viewState))
			));
		});
		refs.intervalSel.setAttribute('data-refresh-policy', policy);
	}
	refs.intervalSel.value = String(effectiveRefreshMs(viewState));
	refs.intervalSel.disabled = viewState.manualLoading === true;
}

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
			try { row.focus({ preventScroll: true }); }
			catch (e) { row.focus(); }
			return true;
		});
	}
}

function captureViewport(refs) {
	var host = document && document.defaultView;
	var state = {
		host: host,
		x: host ? Number(host.scrollX !== undefined ? host.scrollX : host.pageXOffset) || 0 : 0,
		y: host ? Number(host.scrollY !== undefined ? host.scrollY : host.pageYOffset) || 0 : 0,
		containers: []
	};
	var node = refs && refs.root ? refs.root.parentElement : null;
	while (node) {
		var left = Number(node.scrollLeft) || 0;
		var top = Number(node.scrollTop) || 0;
		if (left || top)
			state.containers.push({ node: node, left: left, top: top });
		node = node.parentElement;
	}
	return state;
}

function restoreViewport(state) {
	if (!state) return;
	var host = state.host;
	var x = host ? Number(host.scrollX !== undefined ? host.scrollX : host.pageXOffset) || 0 : 0;
	var y = host ? Number(host.scrollY !== undefined ? host.scrollY : host.pageYOffset) || 0 : 0;
	if (host && typeof host.scrollTo === 'function' && (x !== state.x || y !== state.y))
		host.scrollTo(state.x, state.y);
	state.containers.forEach(function(position) {
		if (!position.node) return;
		if (typeof position.node.scrollTo === 'function')
			position.node.scrollTo(position.left, position.top);
		else {
			position.node.scrollLeft = position.left;
			position.node.scrollTop = position.top;
		}
	});
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
	return source ? String(source) : _('未知');
}

function rateSourceLabel(source) {
	var labels = {
		edge_port: 'Edge-Port',
		edge_wifi: 'Edge-WiFi',
		fast_routed_lease: 'FastN+FastS lease',
		fast_routed_internet: 'FastN+FastS routed Internet',
		ecm_bpf_fallback: 'ECM+BPF fallback',
		ecm_nss_lower_bound: 'ECM NSS lower-bound',
		tc_bpf_lower_bound: 'TC-BPF lower-bound',
		none: _('不可用')
	};
	return labels[String(source || '')] || (source ? String(source) : _('未知'));
}

function collectorLabel(mode) {
	var labels = {
		access_edge: 'Access Edge',
		bpf: 'TC-BPF',
		nss_ecm_node: 'NSS ECM',
		nss_ecm_bpf: 'NSS ECM+BPF',
		conntrack_netlink: 'Conntrack Netlink',
		conntrack_procfs: 'Conntrack Procfs'
	};
	return labels[String(mode || '')] || (mode ? String(mode) : _('未知'));
}

function rateWindowLabel(value) {
	var milliseconds = Number(value);
	if (!isFinite(milliseconds) || milliseconds <= 0) return '';
	var seconds = milliseconds / 1000;
	var precision = seconds >= 10 || Math.floor(seconds) === seconds ? 0 : 1;
	return (Math.round(seconds * Math.pow(10, precision)) / Math.pow(10, precision)) + ' s ' + _('窗口');
}

function clientRateSource(client) {
	var meta = client && client.rate_meta;
	if (meta && typeof meta === 'object') {
		var tx = meta.tx && meta.tx.source;
		var rx = meta.rx && meta.rx.source;
		if (tx || rx) {
			var txLabel = rateSourceLabel(tx);
			var rxLabel = rateSourceLabel(rx);
			return txLabel === rxLabel ? txLabel : '↑ ' + txLabel + ' / ↓ ' + rxLabel;
		}
	}
	return collectorLabel(client && client.rate_collector_mode);
}

function clientRateWindow(client) {
	var meta = client && client.rate_meta;
	if (!meta || typeof meta !== 'object') return '';
	var spanLabel = rateWindowLabel(meta.window_ms);
	if (spanLabel) return spanLabel;
	var txWindow = meta.tx && rateWindowLabel(meta.tx.window_ms);
	var rxWindow = meta.rx && rateWindowLabel(meta.rx.window_ms);
	if (txWindow && txWindow === rxWindow) return txWindow;
	if (txWindow || rxWindow)
		return '↑ ' + (txWindow || '—') + ' / ↓ ' + (rxWindow || '—');
	return '';
}

function rateCoverageLabel(value) {
	var labels = {
		full: _('全覆盖'),
		partial: _('部分覆盖'),
		degraded: _('降级覆盖'),
		unavailable: _('覆盖不可用')
	};
	return labels[String(value || '')] ? String(labels[String(value || '')]) : '';
}

function clientRateCoverage(client) {
	var meta = client && client.rate_meta;
	if (!meta || typeof meta !== 'object') return '';
	var tx = rateCoverageLabel(meta.tx && meta.tx.coverage);
	var rx = rateCoverageLabel(meta.rx && meta.rx.coverage);
	if (tx && tx === rx) return tx;
	if (tx || rx) return '↑ ' + (tx || '—') + ' / ↓ ' + (rx || '—');
	return '';
}

function routedRateView(client, status) {
	if (status && String(status.internet_view_mode || '') === 'routed')
		return true;
	var meta = client && client.rate_meta;
	return !!(meta && typeof meta === 'object' && meta.scope === 'routed_observed' &&
		((meta.tx && (meta.tx.source === 'fast_routed_internet' ||
			meta.tx.source === 'fast_routed_lease')) ||
		 (meta.rx && (meta.rx.source === 'fast_routed_internet' ||
			meta.rx.source === 'fast_routed_lease'))));
}

function clientRateMetaLabel(client, response) {
	if (!client) return '—';
	var parts = [_('总速率采样：') + clientRateSource(client)];
	var meta = client.rate_meta;
	if (meta && meta.attachment && meta.attachment.ifname)
		parts.push(String(meta.attachment.ifname));
	var coverage = clientRateCoverage(client);
	if (coverage) parts.push(coverage);
	var spanLabel = clientRateWindow(client);
	if (spanLabel) parts.push(spanLabel);
	if (meta && meta.stale === true)
		parts.push(_('已过期'));
	if (response && response.conn_source)
		parts.push(_('连接数据独立采样：') + sourceLabel(response.conn_source));
	if (response && response.available === false)
		parts.push(_('连接数据暂不可用'));
	return parts.join(' · ');
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

function clientSummaryRate(client, field, unit) {
	if (!client || client[field] === null || client[field] === undefined)
		return '—';
	return fmt.formatRate(client[field], unit);
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
	var viewport = captureViewport(refs);

	var response = viewState.response || null;
	var warnings = fmt.asArray(response && response.warnings);
	var notFound = Boolean(response) &&
		(!response.client || warnings.indexOf('client_not_found') !== -1);
	var usable = Boolean(response && response.available === true && !notFound);
	var incomplete = Boolean(response && response.available === false &&
		warnings.indexOf('conntrack_snapshot_incomplete') !== -1);
	var client = response && response.client;
	/* The client rate plane is published independently of the conntrack detail
	 * plane.  Keep showing a present client's totals when conntrack is
	 * unavailable, while counts/rows remain explicitly unknown or empty. */
	var rateUsable = Boolean(response && client && !notFound);
	var ips = orderedClientIps(client && client.ips);
	var displayName = viewState.customHostname || client && client.hostname || ips[0] ||
		client && client.mac || viewState.identityKey || '-';
	var locationLookup = typeof viewState.locationLabelFor === 'function'
		? function(ip) { return viewState.locationLabelFor(ip); }
		: null;

	refs.clientName.textContent = displayName;
	renderClientMeta(refs.clientMeta, client, ips, viewState.identityKey);
	if (refs.clientHeading) {
		var hostnameEditable = Boolean(viewState.hostnameMac) &&
			viewState.hostnameOpening !== true;
		refs.clientHeading.setAttribute('aria-disabled',
			hostnameEditable ? 'false' : 'true');
		refs.clientHeading.setAttribute('aria-busy',
			viewState.hostnameOpening === true ? 'true' : 'false');
		refs.clientHeading.setAttribute('title', viewState.hostnameOpening === true
			? _('正在读取 DHCP 主机配置…')
			: !viewState.hostnameMac
				? _('当前无法修改主机名')
				: viewState.hostnameAvailable === false
					? _('点击重试读取 DHCP 主机配置')
					: _('点击修改主机名'));
	}

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
	var interval = effectiveRefreshMs(viewState);
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
	refs.summaryTx.textContent = rateUsable
		? clientSummaryRate(client, 'tx_bps', viewState.prefs && viewState.prefs.unit) : '—';
	refs.summaryRx.textContent = rateUsable
		? clientSummaryRate(client, 'rx_bps', viewState.prefs && viewState.prefs.unit) : '—';
	refs.summaryRateMeta.textContent = rateUsable
		? clientRateMetaLabel(client, response) : '—';
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
	refreshIntervalControl(viewState, refs);
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
		if (rateUsable && fmt.nssPlatform(viewState.status)) {
			footer.push(routedRateView(client, viewState.status)
				? _('NSS：总速率来自 FastN+FastS 互联网/路由观察；连接明细来自独立 Conntrack 窗口，卸载流量可能不出现在逐连接字节中，不能与总速率相加核对')
				: _('NSS：总速率来自接入 Edge；连接明细来自独立 Conntrack 窗口，卸载流量可能不出现在逐连接字节中，不能与总速率相加核对'));
		}
	}
	footer.push(viewState.prefs && viewState.prefs.paused
		? _('自动刷新已暂停')
		: _('每 %s 秒自动刷新').format(String(Math.round(Number(interval) / 100) / 10)));
	footer.push(_('国家/地区及中国省份按 IP 推测，由浏览器查询并缓存，结果可能不准确'));
	refs.footer.textContent = footer.join(' · ');
	restoreViewport(viewport);
}

return baseclass.extend({
	render: render
});
