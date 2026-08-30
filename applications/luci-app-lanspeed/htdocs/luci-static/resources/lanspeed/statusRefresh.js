'use strict';
'require baseclass';
'require lanspeed.vocab as vocab';
'require lanspeed.format as fmt';
'require lanspeed.clientConnections as clientConnections';
'require lanspeed.clientControl as clientControl';
'require lanspeed.version as lsVersion';
'require lanspeed.statusIp as statusIp';
'require lanspeed.statusCollector as statusCollector';
'require lanspeed.statusRateMeta as statusRateMeta';

var CLIENT_INFO_WARNINGS = {
	conntrack_connection_only: true
};

var ERROR_NOTICE_MS = 3000;

var RPC_LABELS = {
	status: _('服务状态'),
	clients: _('客户端数据'),
	interfaces: _('接口吞吐'),
	uci: _('页面配置')
};

function bpfEvidence(status) {
	var evidence = status && status.evidence;
	return evidence && typeof evidence.bpf === 'object' && evidence.bpf || {};
}

function emptyClientText(status) {
	var reason = String(bpfEvidence(status).reason_code || '');
	if (reason === 'no_collect_interface')
		return _('没有接口设为“采集”。请在“LAN Speed 配置”的接口分配中选择实际 LAN 接口。');
	if (reason === 'tc_conflict' || reason === 'tc_attach_failed' || reason === 'tc_unavailable' || reason === 'tc_unsupported')
		return _('BPF 组件已安装，但 TC 挂载未完成。请打开“运行诊断”查看挂载状态。');
	if (reason === 'map_read_failed')
		return _('TC 已挂载，但 BPF 客户端映射表读取失败。请打开“运行诊断”查看映射状态。');
	if (reason === 'package_missing' || reason === 'object_missing' || reason === 'object_load_failed')
		return _('BPF 运行组件不完整或加载失败。请打开“运行诊断”查看安装与内核状态。');
	if (reason === 'disabled')
		return _('BPF 已关闭，客户端实时测速不会启动。');
	if (status && status.capabilities && status.capabilities.live_metrics === false)
		return _('客户端实时采集尚未就绪。请打开“运行诊断”查看数据路径。');
	return _('当前采样中没有 LAN 客户端流量。');
}

function rpcErrorText(result) {
	var error = result && result.error;
	if (!error) return _('未知 RPC 失败');
	var text = error.message || String(error);
	if (error.code !== undefined && error.code !== null && String(error.code) !== '')
		text += ' (' + String(error.code) + ')';
	return text;
}

function sampleSyncPending(viewState) {
	var pair = viewState && viewState.livePair;
	if (!pair || pair.retained === true || pair.aligned === true || pair.renderable === true) return false;
	return [
		'pendingCoverageSampleMs',
		'pendingClientSampleMs',
		'pendingInterfaceSampleMs'
	].some(function(key) {
		return Object.prototype.hasOwnProperty.call(pair, key);
	});
}

function refreshAvailability(viewState, refs) {
	var rpc = viewState.rpc || {};
	var keys = Object.keys(RPC_LABELS);
	var failed = keys.filter(function(key) {
		return rpc[key] && rpc[key].ok === false;
	});
	var hardFailure = viewState.hardFailure === true ||
		(failed.length === keys.length && failed.every(function(key) { return !rpc[key].retained; }));
	var status = viewState.status || {};
	var liveUnavailable = status.capabilities && status.capabilities.live_metrics === false;
	var runtimeUnavailable = liveUnavailable && status.mode === 'Unsupported';
	var samplePending = !failed.length && !liveUnavailable && sampleSyncPending(viewState);

	if (refs.root) {
		refs.root.setAttribute('aria-busy', viewState.loading || samplePending ? 'true' : 'false');
		refs.root.setAttribute('data-state', samplePending ? 'loading' :
			hardFailure || runtimeUnavailable ? 'bad' :
			failed.length || liveUnavailable ? 'warning' : 'good');
	}
	if (refs.btnRefresh) {
		refs.btnRefresh.disabled = viewState.manualBusy === true;
		refs.btnRefresh.textContent = viewState.manualBusy ? _('刷新中…') : _('立即刷新');
	}

	if (!failed.length) {
		viewState.errorNoticeSignature = null;
		viewState.errorNoticeVisible = true;
		viewState.errorNoticeUntil = 0;
		if (typeof viewState.clearErrorNoticeTimer === 'function')
			viewState.clearErrorNoticeTimer();
		refs.errorBox.style.display = 'none';
		refs.errorBox.setAttribute('aria-hidden', 'true');
		refs.errorPre.textContent = '';
		fmt.replaceChildren(refs.errorList, []);
		return { failed: failed, hardFailure: hardFailure, samplePending: samplePending };
	}

	var signature = (hardFailure ? 'hard:' : 'partial:') + failed.join(',');
	if (viewState.errorNoticeSignature !== signature) {
		viewState.errorNoticeSignature = signature;
		if (typeof viewState.triggerErrorNotice === 'function')
			viewState.triggerErrorNotice();
		else {
			viewState.errorNoticeVisible = true;
			viewState.errorNoticeUntil = Date.now() + ERROR_NOTICE_MS;
		}
	}
	var noticeVisible = viewState.errorNoticeVisible !== false &&
		(!Number(viewState.errorNoticeUntil) || Number(viewState.errorNoticeUntil) > Date.now());
	if (!noticeVisible) {
		refs.errorBox.style.display = 'none';
		refs.errorBox.setAttribute('aria-hidden', 'true');
		return { failed: failed, hardFailure: hardFailure, samplePending: false };
	}

	refs.errorBox.style.display = '';
	refs.errorBox.setAttribute('aria-hidden', 'false');
	refs.errorTitle.textContent = hardFailure
		? _('实时数据暂未更新') : _('部分实时数据暂未更新');
	refs.errorPre.textContent = hardFailure
		? _('所有实时请求均失败，请检查服务状态后重试。')
		: _('其余成功数据仍会显示；标为“沿用上次”的内容可能已经过期。');
	fmt.replaceChildren(refs.errorList, failed.map(function(key) {
		var state = rpc[key];
			return E('li', { 'data-state': state.retained ? 'warning' : 'bad' }, [
				E('strong', {}, RPC_LABELS[key] + '：'),
				E('span', {}, rpcErrorText(state)),
				state.retained
					? E('span', { 'class': 'label label-warning' }, _('沿用上次'))
					: E('span', { 'class': 'label label-warning' }, _('暂未更新'))
		]);
	}));
	return { failed: failed, hardFailure: hardFailure, samplePending: false };
}

function refreshIntervalControl(viewState, refs, status) {
	if (!refs || !refs.intervalSel) return;
	var restricted = typeof fmt.nssRefreshRestricted === 'function' &&
		fmt.nssRefreshRestricted(status);
	var state = restricted ? 'nss' : 'default';
	var choices = restricted
		? fmt.NSS_REFRESH_CHOICES
		: fmt.REFRESH_CHOICES;
	var value = restricted
		? fmt.normalizeNssRefreshMs(viewState.prefs.nssRefreshMs)
		: viewState.prefs.refreshMs;
	if (refs.intervalSel.getAttribute('data-refresh-policy') !== state) {
		while (refs.intervalSel.firstChild)
			refs.intervalSel.removeChild(refs.intervalSel.firstChild);
		choices.forEach(function(choice) {
			refs.intervalSel.appendChild(fmt.opt(choice.value, choice.label, value === choice.value));
		});
		refs.intervalSel.setAttribute('data-refresh-policy', state);
	}
	refs.intervalSel.disabled = false;
	refs.intervalSel.title = restricted ? _('ECM 采集方案最低每 2 秒刷新') : '';
	refs.intervalSel.value = String(value);
}

function refreshPagination(viewState, refs, sorted) {
	var page = typeof fmt.paginate === 'function'
		? fmt.paginate(sorted, viewState.page, viewState.prefs.pageSize)
		: {
			items: sorted,
			page: 1,
			pageCount: 1,
			pageSize: sorted.length || 1,
			total: sorted.length,
			start: sorted.length ? 1 : 0,
			end: sorted.length
		};
	viewState.page = page.page;
	viewState.pageCount = page.pageCount;
	if (!refs.pageNav) return page;
	refs.pageNav.style.display = page.total ? '' : 'none';
	var summary = page.total
		? _('%d / %d 页 · %d–%d / %d').format(
			page.page, page.pageCount, page.start, page.end, page.total)
		: _('没有客户端');
	if (refs.pageSummary.textContent !== String(summary))
		refs.pageSummary.textContent = summary;
	refs.pageFirst.disabled = page.page <= 1;
	refs.pagePrev.disabled = page.page <= 1;
	refs.pageNext.disabled = page.page >= page.pageCount;
	refs.pageLast.disabled = page.page >= page.pageCount;
	if (refs.pageSizeSel && String(refs.pageSizeSel.value) !== String(page.pageSize))
		refs.pageSizeSel.value = String(page.pageSize);
	return page;
}

function clientNameContent(c, displayName, ips) {
	var name = displayName;
	var ipText = '';
	if (c.identity_key) {
		var label = _('查看 %s 的当前连接').format(displayName);
		name = E('a', {
			'class': 'lanspeed-connection-link',
			'href': clientConnections.detailHref(window.location.pathname, c.identity_key),
			'title': label,
			'aria-label': label
		}, displayName);
	}

	if (c.hostname && ips.length)
		ipText = ips.join(', ');
	else if (ips.length > 1)
		ipText = ips.slice(1).join(', ');

	if (!ipText)
		return [ name ];

	return [
		name,
		E('span', { 'class': 'ipline', 'title': ips.join(', ') }, ipText)
	];
}

function clientTrafficCell(c, direction, rate, rateUnit) {
	var directionLabel = direction === 'tx' ? _('上行') : _('下行');
	return E('td', {
		'class': 'num lanspeed-client-value',
		'data-label': directionLabel
	}, E('span', { 'class': 'lanspeed-client-rate' }, fmt.formatRate(rate, rateUnit)));
}

function clientTrafficTotalCell(c, direction, showTotal) {
	/* The first rollout is intentionally x86-only. NSS has different counter
	 * ownership semantics and must not gain a second, unverified total here. */
	var isUpload = direction === 'tx';
	var label = isUpload ? _('累计上传') : _('累计下载');
	var field = isUpload ? 'tx_bytes' : 'rx_bytes';
	var total = showTotal && typeof fmt.formatBytes === 'function'
		? fmt.formatBytes(c && c[field]) : null;
	var attrs = {
		'class': 'num lanspeed-client-total-cell ' +
			(isUpload ? 'lanspeed-client-total-upload-cell' : 'lanspeed-client-total-download-cell'),
		'data-label': label,
		'title': showTotal ? label + ' ' + total : ''
	};
	if (!showTotal) attrs.hidden = 'hidden';
	return E('td', attrs, showTotal ? E('span', {
		'class': 'lanspeed-client-total',
		'aria-label': label + ' ' + total
	}, total) : []);
}

function splitClientWarnings(rawWarnings, globalWarnings) {
	var info = [], warnings = [];
	(rawWarnings || []).forEach(function(w) {
		if (CLIENT_INFO_WARNINGS[w])
			info.push(w);
		else if (!(globalWarnings || {})[w] && vocab.isImportantWarning(w))
			warnings.push(w);
	});
	return { info: info, warnings: warnings };
}

function setClientStatusVisibility(refs, visible) {
	if (refs && refs.statusHeader)
		refs.statusHeader.hidden = !visible;
	if (refs && refs.clientsTable)
		refs.clientsTable.setAttribute('data-client-status', visible ? 'shown' : 'hidden');
}

function clientStateCell(stateCells, visible) {
	var cell = E('td', {
		'class': 'lanspeed-client-state-cell',
		'data-label': _('状态')
	}, E('span', { 'class': 'state' }, stateCells));
	cell.hidden = !visible;
	return cell;
}

function captureClientViewport(refs) {
	var host = typeof window !== 'undefined' ? window : null;
	var scrollX = host ? Number(host.scrollX !== undefined ? host.scrollX : host.pageXOffset) || 0 : 0;
	var scrollY = host ? Number(host.scrollY !== undefined ? host.scrollY : host.pageYOffset) || 0 : 0;
	var scrollContainers = [];
	var node = refs && refs.root ? refs.root.parentElement : null;
	while (node) {
		var style = host && typeof host.getComputedStyle === 'function' ? host.getComputedStyle(node) : null;
		var overflowX = style ? String(style.overflowX || '') : '';
		var overflowY = style ? String(style.overflowY || '') : '';
		var left = Number(node.scrollLeft) || 0;
		var top = Number(node.scrollTop) || 0;
		var scrollsX = /^(?:auto|scroll|overlay)$/.test(overflowX) &&
			Number(node.scrollWidth) > Number(node.clientWidth);
		var scrollsY = /^(?:auto|scroll|overlay)$/.test(overflowY) &&
			Number(node.scrollHeight) > Number(node.clientHeight);
		if (left || top || scrollsX || scrollsY) {
			scrollContainers.push({
				node: node,
				left: left,
				top: top
			});
		}
		node = node.parentElement;
	}
	return {
		host: host,
		scrollX: scrollX,
		scrollY: scrollY,
		scrollContainers: scrollContainers
	};
}

function restoreClientViewport(state) {
	if (!state) return;
	var host = state.host;
	var currentX = host ? Number(host.scrollX !== undefined ? host.scrollX : host.pageXOffset) || 0 : 0;
	var currentY = host ? Number(host.scrollY !== undefined ? host.scrollY : host.pageYOffset) || 0 : 0;
	if (host && typeof host.scrollTo === 'function' &&
	    (currentX !== state.scrollX || currentY !== state.scrollY))
		host.scrollTo(state.scrollX, state.scrollY);
	Array.prototype.forEach.call(state.scrollContainers || [], function(position) {
		var node = position && position.node;
		if (!node) return;
		var left = Number(node.scrollLeft) || 0;
		var top = Number(node.scrollTop) || 0;
		if (left === position.left && top === position.top) return;
		if (typeof node.scrollTo === 'function')
			node.scrollTo(position.left, position.top);
		else {
			node.scrollLeft = position.left;
			node.scrollTop = position.top;
		}
	});
}

function nodeContains(parent, target) {
	if (!parent || !target) return false;
	if (parent === target) return true;
	if (typeof parent.contains === 'function') return parent.contains(target);
	return Array.prototype.some.call(parent.children || [], function(child) {
		return child && typeof child === 'object' && nodeContains(child, target);
	});
}

function focusableChildren(root, result) {
	result = result || [];
	Array.prototype.forEach.call(root && root.children || [], function(child) {
		if (!child || typeof child !== 'object') return;
		var tag = String(child.tagName || '').toLowerCase();
		var tabindex = child.getAttribute && child.getAttribute('tabindex');
		if ([ 'a', 'button', 'input', 'select', 'textarea' ].indexOf(tag) !== -1 || tabindex !== null)
			result.push(child);
		focusableChildren(child, result);
	});
	return result;
}

function captureRowFocus(row) {
	var doc = typeof document !== 'undefined' ? document : null;
	var active = doc && doc.activeElement;
	if (!nodeContains(row, active)) return null;
	var focusables = focusableChildren(row);
	return {
		action: active && active.getAttribute && active.getAttribute('data-client-action'),
		index: focusables.indexOf(active)
	};
}

function restoreRowFocus(row, state) {
	if (!state) return;
	var focusables = focusableChildren(row);
	var target = null;
	if (state.action) {
		target = focusables.filter(function(node) {
			return node.getAttribute && node.getAttribute('data-client-action') === state.action;
		})[0] || null;
	}
	if (!target && state.index >= 0)
		target = focusables[state.index] || null;
	if (!target || typeof target.focus !== 'function') return;
	try { target.focus({ preventScroll: true }); }
	catch (e) { target.focus(); }
}

function replaceRowContents(target, source) {
	var focusState = captureRowFocus(target);
	var children = [];
	while (source.firstChild)
		children.push(source.removeChild(source.firstChild));
	while (target.firstChild)
		target.removeChild(target.firstChild);
	target.className = source.className;
	children.forEach(function(child) { target.appendChild(child); });
	restoreRowFocus(target, focusState);
}

/*
 * Keep stable client <tr> nodes alive across samples so live sorting updates
 * contents and order without replacing the complete tbody or losing viewport
 * continuity.
 */
function reconcileClientRows(tbody, rows) {
	var existing = Object.create(null);
	Array.prototype.forEach.call(tbody.children, function(row) {
		var key = row.getAttribute('data-client-key');
		if (key !== null && !Object.prototype.hasOwnProperty.call(existing, key))
			existing[key] = row;
	});

	var desired = rows.map(function(row) {
		var key = row.getAttribute('data-client-key');
		if (key === null || !Object.prototype.hasOwnProperty.call(existing, key))
			return row;
		var current = existing[key];
		delete existing[key];
		replaceRowContents(current, row);
		return current;
	});

	desired.forEach(function(row, index) {
		var current = tbody.children[index] || null;
		if (current !== row)
			tbody.insertBefore(row, current);
	});
	while (tbody.children.length > desired.length)
		tbody.removeChild(tbody.lastChild);
}

function refreshSortHeaders(refs, prefs) {
	Object.keys(refs.sortHeaders || {}).forEach(function(sortKey) {
		var ref = refs.sortHeaders[sortKey];
		var active = prefs.sortCustom && prefs.sortKey === sortKey;
		var sortedColumn = prefs.sortKey === sortKey;
		var ascending = prefs.sortDir === 'asc';
		var title;
		if (!prefs.sortCustom && sortedColumn)
			title = _('%s：默认排序，点击开始降序排序').format(ref.label);
		else if (active && ascending)
			title = _('%s：当前升序，点击恢复默认排序').format(ref.label);
		else if (active)
			title = _('%s：当前降序，点击切换为升序').format(ref.label);
		else
			title = _('按%s降序排序').format(ref.label);

		if (ref.description)
			title = ref.description + ' · ' + title;
		ref.th.setAttribute('aria-sort', sortedColumn
			? (ascending ? 'ascending' : 'descending')
			: 'none');
		ref.button.setAttribute('title', title);
		ref.button.setAttribute('aria-label', title);
		ref.button.lastChild.textContent = active ? (ascending ? '↑' : '↓') : '';
	});
}

function accessEdgeOwnsCurrentRate(status) {
	return fmt.nssPlatform(status) && String(status && status.rate_collector_mode || '') === 'auto' &&
		String(status && status.access_edge_mode || '') === 'active' &&
		String(status && status.internet_view_mode || '') !== 'routed';
}

function routedRate(client, direction) {
	return statusRateMeta.routedSource(client && client.rate_meta, direction)
		? Number(client && client[direction + '_bps']) || 0 : 0;
}

function refreshLive(viewState) {
	var refs = viewState.refs;
	if (!refs) return;
	var viewport = captureClientViewport(refs);
	var status = viewState.status || {};
	var nssProfile = fmt.nssPlatform(status);
	var routedInternet = nssProfile && String(status.internet_view_mode || '') === 'routed';
	var routedCollector = routedInternet && (viewState.clients &&
		Array.isArray(viewState.clients.clients))
		? viewState.clients.clients.reduce(function(current, client) {
			var mode = statusRateMeta.routedCollector(client && client.rate_meta);
			return mode === 'fast_routed_lease' ? mode : current || mode;
		}, '') : '';
	viewState.showClientControl = true;
	if (refs.controlHeader) refs.controlHeader.hidden = false;
	if (refs.totalUploadHeader) refs.totalUploadHeader.hidden = nssProfile;
	if (refs.totalDownloadHeader) refs.totalDownloadHeader.hidden = nssProfile;
	if (refs.clientsTable) {
		refs.clientsTable.setAttribute('data-client-control', 'shown');
		refs.clientsTable.setAttribute('data-client-totals', nssProfile ? 'hidden' : 'shown');
	}
	refreshIntervalControl(viewState, refs, status);
	var clientsAll = fmt.asArray(viewState.clients && viewState.clients.clients);
	var prefs = viewState.prefs;
	var activeCfg = fmt.activeConfig(status);
	var showClientStatus = viewState.showClientStatus === true;
	var showIpv6 = viewState.showIpv6 !== false;
	var hidePrivateIpv6 = viewState.hidePrivateIpv6 === true;
	var hideIpv6Ranges = statusIp.hideIpv6RangesValue(viewState.hideIpv6Ranges);
	setClientStatusVisibility(refs, showClientStatus);
	var availability = refreshAvailability(viewState, refs);

	var collector = routedInternet ? (routedCollector || 'fast_routed_internet') : accessEdgeOwnsCurrentRate(status) ? 'access_edge' :
		statusCollector.effectiveCollector(status, viewState.clients);
	if (!nssProfile && (collector === 'access_edge' || collector === 'nss_ecm_node' || collector === 'nss_ecm_bpf'))
		collector = 'bpf';
	refs.collectorPill.className = statusCollector.collectorClass(collector) +
		' lanspeed-collector-status';
	refs.collectorPill.textContent = statusCollector.collectorLabel(collector);
	refs.collectorPill.title = routedInternet
		? _('当前只显示 NSS FastN+FastS 观察到的互联网/路由流量；不代表客户端全部帧。')
		: accessEdgeOwnsCurrentRate(status)
		? _('当前客户端网速模式；每个方向的真实数据源见客户端元数据')
		: _('当前实时速率数据源');
	if ((viewState.rpc && viewState.rpc.status && viewState.rpc.status.ok === false) ||
	    (viewState.rpc && viewState.rpc.clients && viewState.rpc.clients.ok === false)) {
		refs.collectorPill.className = 'label label-warning lanspeed-collector-status';
		refs.collectorPill.title = _('数据源信息可能来自上次成功结果');
	}

	var metaParts = [];
	if (status.version) metaParts.push(_('后端 ') + status.version);
	metaParts.push('luci ' + lsVersion.FULL_VERSION);
	if (prefs.paused) metaParts.push(_('已暂停'));
	refs.meta.textContent = metaParts.join(' · ');

	var totals = routedInternet ? clientsAll.reduce(function(sum, client) {
		var tx = routedRate(client, 'tx');
		var rx = routedRate(client, 'rx');
		if (tx !== null) sum.tx += tx;
		if (rx !== null) sum.rx += rx;
		if ((tx || 0) + (rx || 0) >= activeCfg.activeMinBps) sum.active++;
		return sum;
	}, { tx: 0, rx: 0, active: 0 }) : fmt.sumTotals(clientsAll, activeCfg);
	// A pending/alignment window means the current contribution is unknown, not
	// that the rate has a special placeholder value.  Keep the numeric zero
	// contract for rate fields; the surrounding busy/"正在同步" state already
	// communicates that the next sample is still being assembled.
	refs.mTx.textContent = fmt.formatRate(totals.tx, prefs.unit);
	refs.mRx.textContent = fmt.formatRate(totals.rx, prefs.unit);
	refs.mClients.textContent = String(clientsAll.length);

	var clientsData = viewState.clients || {};
	var udpSub;
	if (typeof clientsData.tcp_conns_total === 'number' || typeof clientsData.udp_conns_total === 'number') {
		refs.mConnsWrap.style.display = '';
		refs.mTcpConns.textContent = String(typeof clientsData.tcp_conns_total === 'number' ? clientsData.tcp_conns_total : '-');
		refs.mUdpConns.textContent = String(typeof clientsData.udp_conns_total === 'number' ? clientsData.udp_conns_total : '-');
		if (typeof clientsData.udp_dns_conns_total === 'number' || typeof clientsData.udp_other_conns_total === 'number') {
			udpSub = [
				'DNS ' + (typeof clientsData.udp_dns_conns_total === 'number' ? clientsData.udp_dns_conns_total : '-'),
				_('其它 ') + (typeof clientsData.udp_other_conns_total === 'number' ? clientsData.udp_other_conns_total : '-')
			];
			refs.mUdpConnsSub.textContent = udpSub.join(' · ');
		} else {
			refs.mUdpConnsSub.textContent = '-';
		}
	} else {
		refs.mConnsWrap.style.display = 'none';
	}

	if (availability.samplePending) {
		refs.mClientsSub.textContent = _('正在同步实时采样…');
	} else {
		var nssEv = nssProfile && status.evidence && status.evidence.nss;
		var subParts = [ _('%d 个活跃').format(totals.active) ];
		if (nssEv && typeof nssEv.host_count === 'number' &&
		    nssEv.host_count > clientsAll.length) {
			subParts.push(_('NSS 发现 %d 个').format(nssEv.host_count));
		}
		subParts.push(_('活跃判定 %d 秒').format(Math.round(activeCfg.activeWindowMs / 1000)));
		if (activeCfg.activeMinBps > 1)
			subParts.push(_('≥ ') + fmt.formatRate(activeCfg.activeMinBps, prefs.unit));
		refs.mClientsSub.textContent = subParts.join(' · ');
	}

	var latestSample = fmt.latestClientSampleMs(clientsAll);
	var filtered = clientsAll.filter(function(c) {
		if (!fmt.matchesFilter(c, viewState.filter)) return false;
		if (prefs.activeOnly && !fmt.isActiveClient(c, latestSample, activeCfg)) return false;
		return true;
	});
	var sorted = fmt.sortClients(filtered, prefs.sortKey, prefs.sortDir, latestSample, activeCfg);
	var page = refreshPagination(viewState, refs, sorted);
	refreshSortHeaders(refs, prefs);

	var summaryParts = availability.samplePending ? [ _('正在同步') ] : [
		_('%d 总').format(clientsAll.length),
		_('%d 活跃').format(totals.active)
	];
	if (viewState.filter || prefs.activeOnly)
		summaryParts.push(_('%d 显示').format(sorted.length));
	if (page.total)
		summaryParts.push(_('%d–%d 当前页').format(page.start, page.end));
	refs.clientsHeaderSummary.textContent = summaryParts.join(' · ');

	if (!sorted.length) {
		// Keep the table header visible in the empty state so sorting and
		// accessibility affordances remain available before the first client
		// sample arrives.
		refs.clientsTable.style.display = '';
		reconcileClientRows(refs.tbody, []);
		refs.empty.style.display = '';
		refs.empty.setAttribute('data-state', availability.samplePending ? 'loading' : 'empty');
		var clientsRpc = viewState.rpc && viewState.rpc.clients;
		if (availability.samplePending) {
			refs.empty.textContent = _('正在同步实时采样…');
		} else if (viewState.filter || prefs.activeOnly) {
			refs.empty.textContent = _('没有匹配的客户端。');
		} else if (availability.hardFailure || (clientsRpc && clientsRpc.ok === false && !clientsRpc.retained)) {
			refs.empty.textContent = _('客户端数据不可用。请确认 lanspeedd 正在运行后重试。');
			} else if (clientsRpc && clientsRpc.ok === false && clientsRpc.retained) {
				refs.empty.textContent = _('客户端请求失败；上次成功结果中没有客户端。');
			} else {
				refs.empty.textContent = emptyClientText(status);
		}
	} else {
		refs.clientsTable.style.display = '';
		refs.empty.style.display = 'none';
		refs.empty.setAttribute('data-state', 'ready');

		var globalWarnings = {};
		fmt.asArray(status.warnings).forEach(function(w) {
			globalWarnings[vocab.normalizeWarningId(w)] = true;
		});

		reconcileClientRows(refs.tbody, page.items.map(function(c) {
			var tx = routedInternet ? routedRate(c, 'tx') : Number(c.tx_bps) || 0;
			var rx = routedInternet ? routedRate(c, 'rx') : Number(c.rx_bps) || 0;
			var idle = !fmt.isActiveClient(c, latestSample, activeCfg);
			var ips = statusIp.displayIpsForClient(c.ips, showIpv6, hidePrivateIpv6, hideIpv6Ranges);
			var rawWarnings = fmt.asArray(c.warnings).map(function(w) {
				return vocab.normalizeWarningId(w);
			});
			var clientWarningState = splitClientWarnings(rawWarnings, globalWarnings);
			var connectionOnly = clientWarningState.info.indexOf('conntrack_connection_only') !== -1;
			var specificWarnings = clientWarningState.warnings;
			var critClient = specificWarnings.some(function(w) { return vocab.CRITICAL_WARNINGS[w]; });

			var mode = String(c.collector_mode || '-');
			var routedMode = routedInternet && statusRateMeta.routedCollector(c.rate_meta);
			if (routedMode)
				mode = routedMode;
			if (!nssProfile && (mode === 'nss_ecm_node' || mode === 'nss_ecm_bpf'))
				mode = 'unsupported';
			var modeLabel = statusCollector.collectorLabel(mode), modeTitle;
			if (mode === 'access_edge') {
				modeTitle = _('自动精准按客户端、按方向选择唯一总速率来源；具体来源显示在相邻标签中。');
			} else if (mode === 'bpf') {
				modeTitle = _('BPF 在 LAN 接口按 MAC 统计客户端实时速率。');
			} else if (mode === 'nss_ecm_node') {
				modeTitle = _('NSS ECM node 按客户端 MAC 读取真实字节与包计数并立即发布；独立 LAN 窗口只验证覆盖率。');
			} else if (mode === 'nss_ecm_bpf') {
				modeTitle = _('ECM+BPF 按原有 NSS + CPU 路径统计客户端流量。');
			} else if (mode === 'conntrack_netlink') {
				modeTitle = _('CT-Netlink 仅补充当前连接数，不参与非 NSS 设备的实时速率统计。');
			} else if (mode === 'conntrack_procfs') {
				modeTitle = _('CT-Procfs 是连接数的备用来源，不参与非 NSS 设备的实时速率统计。');
			} else if (mode === 'conntrack') {
				modeTitle = _('Conntrack 仅补充当前连接数，不参与非 NSS 设备的实时速率统计。');
			} else {
				modeTitle = _('未知采集方式');
			}
			if (connectionOnly)
				modeTitle += '\n' + vocab.warningText('conntrack_connection_only');

			var stateCells = statusRateMeta.cells(c.rate_meta, nssProfile);
			stateCells.push(E('span', {
				'class': 'label',
				'title': c.rate_meta ? _('采集流水线：') + modeTitle : modeTitle
			}, c.rate_meta ? _('流水线 ') + modeLabel : modeLabel));
			if (specificWarnings.length)
				stateCells.push(E('span', {
					'class': critClient ? 'label danger' : 'label warning',
					'title': specificWarnings.map(vocab.warningText.bind(vocab)).join('\n')
				}, _('%d 告警').format(specificWarnings.length)));
			var stateCell = clientStateCell(stateCells, showClientStatus);

			var displayName;
			if (c.hostname) {
				displayName = c.hostname;
			} else if (ips.length) {
				displayName = ips[0];
			} else {
				displayName = c.mac || '-';
			}

			return E('tr', {
				'class': idle ? 'idle' : '',
				'data-client-key': String(fmt.identityOf(c))
			}, [
				E('td', { 'class': 'lanspeed-client-name' },
					clientNameContent(c, displayName, ips)),
				E('td', {
					'class': 'mono lanspeed-client-mac',
					'data-label': 'MAC'
				}, fmt.textOrDash(c.mac)),
				clientTrafficCell(c, 'tx', tx, prefs.unit),
				clientTrafficCell(c, 'rx', rx, prefs.unit),
				clientTrafficTotalCell(c, 'tx', !nssProfile),
				clientTrafficTotalCell(c, 'rx', !nssProfile),
				E('td', {
					'class': 'num lanspeed-client-value',
					'data-label': 'TCP'
				}, typeof c.tcp_conns === 'number' ? String(c.tcp_conns) : '-'),
				E('td', {
					'class': 'num lanspeed-client-value',
					'data-label': 'UDP',
					'title': (typeof c.udp_dns_conns === 'number' || typeof c.udp_other_conns === 'number')
						? [
							'DNS ' + (typeof c.udp_dns_conns === 'number' ? c.udp_dns_conns : '-'),
							_('其它 ') + (typeof c.udp_other_conns === 'number' ? c.udp_other_conns : '-')
						  ].join(' · ')
						: ''
				}, typeof c.udp_conns === 'number' ? String(c.udp_conns) : '-'),
				stateCell,
				clientControl.cell(viewState, c)
			]);
		}));
	}

	var ifaces = fmt.asArray(viewState.interfaces && viewState.interfaces.interfaces);
	var interfacesRpc = viewState.rpc && viewState.rpc.interfaces;
	if (!ifaces.length) {
		if (interfacesRpc && interfacesRpc.ok === false) {
			refs.ifacesDetails.parentNode.style.display = '';
			fmt.replaceChildren(refs.ifacesBody, []);
			refs.ifacesSummary.textContent = interfacesRpc.retained ? _('上次结果为空') : _('接口数据不可用');
			refs.ifacesHint.textContent = interfacesRpc.retained
				? _('接口请求失败；上次成功结果中没有接口采样。')
				: _('无法读取接口吞吐，请检查服务状态后重试。');
		} else {
			refs.ifacesDetails.parentNode.style.display = 'none';
		}
	} else {
		refs.ifacesDetails.parentNode.style.display = '';
		var clientSumByIf = {};
		clientsAll.forEach(function(c) {
			var k = c.interface || '-';
			if (!clientSumByIf[k]) clientSumByIf[k] = { tx: 0, rx: 0 };
			var tx = routedInternet ? routedRate(c, 'tx') : Number(c.tx_bps) || 0;
			var rx = routedInternet ? routedRate(c, 'rx') : Number(c.rx_bps) || 0;
			clientSumByIf[k].tx += tx;
			clientSumByIf[k].rx += rx;
		});

		var totalIfTx = 0, totalIfRx = 0;
		fmt.replaceChildren(refs.ifacesBody, ifaces.map(function(i) {
			var n = i.name || '-';
			var isLan = (i.role || 'lan') === 'lan';
			var ifUp = Number(isLan ? i.rx_bps : i.tx_bps) || 0;
			var ifDn = Number(isLan ? i.tx_bps : i.rx_bps) || 0;
			var cs = clientSumByIf[n] || { tx: 0, rx: 0 };

			if (isLan) {
				totalIfTx += ifUp;
				totalIfRx += ifDn;
			}

			return E('tr', {}, [
				E('td', { 'data-label': _('接口') }, n),
				E('td', { 'class': 'num', 'data-label': _('接口 ↑') }, fmt.formatRate(ifUp, prefs.unit)),
				E('td', { 'class': 'num', 'data-label': _('接口 ↓') }, fmt.formatRate(ifDn, prefs.unit)),
				E('td', { 'class': 'num', 'data-label': _('客户端 ↑') },
					isLan ? fmt.formatRate(cs.tx, prefs.unit) : '-'),
				E('td', { 'class': 'num', 'data-label': _('客户端 ↓') },
					isLan ? fmt.formatRate(cs.rx, prefs.unit) : '-')
			]);
		}));

		refs.ifacesSummary.textContent = [
			'↑ ' + fmt.formatRate(totalIfTx, prefs.unit),
			'↓ ' + fmt.formatRate(totalIfRx, prefs.unit)
		].join(' · ');

		var covHint = status.coverage || {};
		if (covHint.quality === 'ok' || (covHint.quality === 'low_traffic' &&
		    (typeof covHint.tx_pct === 'number' || typeof covHint.rx_pct === 'number'))) {
			var hintTx = typeof covHint.tx_pct === 'number' ? covHint.tx_pct : 100;
			var hintRx = typeof covHint.rx_pct === 'number' ? covHint.rx_pct : 100;
			refs.ifacesHint.textContent = (hintTx < 85 || hintRx < 85)
				? _('部分接口流量未能归属到客户端，常见原因是硬件卸载、交换芯片内转发或广播流量。')
				: '';
		} else {
			refs.ifacesHint.textContent = '';
		}
		if (interfacesRpc && interfacesRpc.ok === false && interfacesRpc.retained) {
			refs.ifacesHint.textContent = [
				_('接口请求失败，当前显示上次成功结果。'),
				refs.ifacesHint.textContent
			].filter(Boolean).join(' ');
		}
	}
	restoreClientViewport(viewport);

}

return baseclass.extend({
	clientNameContent: clientNameContent,
	clientTrafficCell: clientTrafficCell,
	clientTrafficTotalCell: clientTrafficTotalCell,
	refreshSortHeaders: refreshSortHeaders,
	splitClientWarnings: splitClientWarnings,
	setClientStatusVisibility: setClientStatusVisibility,
	clientStateCell: clientStateCell,
	rateMetaCells: statusRateMeta.cells,
	captureClientViewport: captureClientViewport,
	restoreClientViewport: restoreClientViewport,
	reconcileClientRows: reconcileClientRows,
	sampleSyncPending: sampleSyncPending,
	refreshAvailability: refreshAvailability,
	refreshIntervalControl: refreshIntervalControl,
	refreshPagination: refreshPagination,

	refreshLive: function(viewState) {
		return refreshLive(viewState);
	}
});
