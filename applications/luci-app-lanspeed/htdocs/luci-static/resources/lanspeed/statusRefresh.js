'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.clientConnections as clientConnections';
'require lanspeed.version as lsVersion';
'require lanspeed.statusIp as statusIp';
'require lanspeed.statusCollector as statusCollector';
'require lanspeed.statusRateMeta as statusRateMeta';
'require lanspeed.vendorLogo as vendorLogo';

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
		return _('没有接口设为“采集”。请在“LAN Speed 配置”的接口分配中选择实际局域网接口。');
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
	return _('当前采样中没有局域网客户端流量。');
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
		var platform = status.evidence && status.evidence.platform || {};
		var profile = String(platform.profile || '');
		var platformName = profile === 'x86_tc_bpf' || String(platform.target_arch || '') === 'x86_64' ||
			platform.nss_compiled === false ? 'x86' : fmt.nssPlatform(status) ? 'nss' : 'unknown';
		refs.root.setAttribute('data-lanspeed-platform', platformName);
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

function setText(node, text) {
	if (node && node.textContent !== String(text)) node.textContent = text;
}

/* One compact phrase next to the page title answering "is this live?". It
 * reuses the availability result so it never disagrees with the error box. */
function refreshLiveState(viewState, refs, status, availability) {
	if (!refs.liveState) return;
	var state, text;
	var failed = availability && availability.failed || [];
	if (viewState.prefs && viewState.prefs.paused) {
		state = 'paused'; text = _('已暂停');
	} else if (availability && availability.hardFailure) {
		state = 'bad'; text = _('实时数据不可用');
	} else if (failed.length) {
		state = 'warning'; text = _('部分数据沿用上次');
	} else if (availability && availability.samplePending) {
		state = 'loading'; text = _('正在同步');
	} else {
		state = 'live';
		text = _('实时');
	}
	refs.liveState.setAttribute('data-state', state);
	setText(refs.liveState, text);
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

function clientNameContent(c, displayName, ips, vendor) {
	var name = E('span', {}, displayName);
	var ipText = '';
	if (c.identity_key) {
		var label = _('查看 %s 的连接与设备控制').format(displayName);
		name = E('a', {
			'class': 'lanspeed-connection-link',
			'href': clientConnections.detailHref(window.location.pathname, c.identity_key),
			'title': displayName + ' · ' + label,
			'aria-label': label
		}, displayName);
	}

	if (c.hostname && ips.length)
		ipText = ips.join(', ');
	else if (ips.length > 1)
		ipText = ips.slice(1).join(', ');

	var line = E('span', { 'class': 'lanspeed-client-name-line' }, [ name ]);
	if (vendor && vendorLogo.brand(vendor.vendor)) {
		var label = vendor.label + (vendor.stale ? _('（缓存已过期）') : '');
		var badge = E('span', { 'class': 'lanspeed-vendor-indicator', 'data-vendor-value': vendor.vendor + ':' + label }, [
			E('button', {
				'type': 'button', 'class': 'lanspeed-vendor-trigger',
				'title': label, 'aria-label': _('厂商：') + label,
				'click': function() { this.focus(); },
				'keydown': function(event) { if (event.key === 'Escape') this.blur(); }
			}, [ vendorLogo.logo(vendor.vendor, vendor.kind) ]),
			E('span', { 'class': 'lanspeed-vendor-tooltip', 'aria-hidden': 'true' }, label)
		]);
		line.appendChild(badge);
	}
	return ipText ? [ line, E('span', { 'class': 'ipline', 'title': ips.join(', ') }, ipText) ] : [ line ];
}

function valueParts(value) {
	var match = /^([\d.,]+)(\s*.+)$/.exec(value || '');
	return match ? { number: match[1], unit: match[2] } : null;
}

function valueContent(value, className) {
	var parts = valueParts(value);
	if (!parts) return value;
	return [
		E('span', { 'class': 'lanspeed-value-number' }, parts.number),
		E('span', { 'class': 'lanspeed-value-unit' }, parts.unit)
	];
}

function trafficLine(direction, value, total) {
	var download = direction === 'rx';
	var label = total ? (download ? _('累计下载') : _('累计上传'))
		: (download ? _('下载') : _('上传'));
	var unavailable = value === '-';
	return E('span', {
		'class': 'lanspeed-client-traffic-line ' + (download ? 'lanspeed-client-download' : 'lanspeed-client-upload'),
		'data-direction': direction,
		'title': unavailable ? label + ' · ' + _('暂不可用') : label + ' ' + value
	}, [
		E('span', { 'class': 'lanspeed-client-direction', 'aria-hidden': 'true' }, download ? '↓' : '↑'),
		E('span', { 'class': 'lanspeed-client-direction-label' }, label + (unavailable ? ' ' + _('暂不可用') : '') + ' '),
		E('span', { 'class': total ? 'lanspeed-client-total' : 'lanspeed-client-rate' },
			valueContent(value))
	]);
}

function clientTrafficCell(value, direction, rateUnit) {
	return E('td', {
		'class': 'num lanspeed-client-value lanspeed-client-rate-cell lanspeed-client-rate-' + direction,
		'data-label': direction === 'rx' ? _('下载速度') : _('上传速度')
	}, trafficLine(direction, fmt.formatRate(value, rateUnit), false));
}

function clientTrafficTotalCell(c, direction, showTotal) {
	var attrs = {
		'class': 'num lanspeed-client-total-cell lanspeed-client-total-' + direction,
		'data-label': direction === 'rx' ? _('累计下载') : _('累计上传')
	};
	if (!showTotal) attrs.hidden = 'hidden';
	return E('td', attrs, showTotal ? trafficLine(direction,
		typeof fmt.formatBytes === 'function' ? fmt.formatBytes(c && c[direction + '_bytes']) : '-', true) : []);
}

function clientMacCell(c, vendor) {
	var content = [ E('span', { 'class': 'mono lanspeed-client-mac-value' }, fmt.textOrDash(c && c.mac)) ];
	return E('td', { 'class': 'lanspeed-client-mac', 'data-label': _('MAC') }, content);
}

function countText(value) {
	return typeof value === 'number' ? String(value) : '-';
}

function clientTcpCell(c) {
	return E('td', {
		'class': 'num lanspeed-client-count-cell lanspeed-client-tcp-cell',
		'data-label': _('TCP'),
		'title': _('传输控制协议：统计当前已建立且确认的连接')
	}, countText(c && c.tcp_conns));
}

function clientUdpCell(c) {
	var udpTitle = (typeof c.udp_dns_conns === 'number' || typeof c.udp_other_conns === 'number')
		? [
			_('域名查询 ') + countText(c.udp_dns_conns),
			_('其它 ') + countText(c.udp_other_conns)
		  ].join(' · ')
		: _('用户数据报协议：统计当前已确认的连接');
	return E('td', {
		'class': 'num lanspeed-client-count-cell lanspeed-client-udp-cell',
		'data-label': _('UDP'),
		'title': udpTitle
	}, countText(c && c.udp_conns));
}

function captureClientViewport(refs) {
	var host = typeof window !== 'undefined' ? window : null;
	var scrollX = host ? Number(host.scrollX !== undefined ? host.scrollX : host.pageXOffset) || 0 : 0;
	var scrollY = host ? Number(host.scrollY !== undefined ? host.scrollY : host.pageYOffset) || 0 : 0;
	var scrollContainers = [];
	var tableScroller = refs && refs.clientsTable ? refs.clientsTable.parentElement : null;
	if (tableScroller) {
		scrollContainers.push({
			node: tableScroller,
			left: Number(tableScroller.scrollLeft) || 0,
			top: Number(tableScroller.scrollTop) || 0
		});
	}
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
		if ((left || top || scrollsX || scrollsY) && node !== tableScroller) {
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

/* A cell can be kept when it renders identically and binds no handlers.
 * Control buttons close over the sampled client, so they are always fresh. */
function reusableCell(current, next) {
	return !!current && !!next && typeof current.isEqualNode === 'function' &&
		typeof next.querySelector === 'function' && !next.querySelector('button') &&
		current.isEqualNode(next);
}

/* Patch the badge separately so vendor completion preserves selected names. */
function patchNameCell(current, next) {
	if (!current || !next || current.className !== 'lanspeed-client-name' ||
	    next.className !== 'lanspeed-client-name') return false;
	var oldLine = current.firstChild, newLine = next.firstChild;
	if (!oldLine || !newLine || !oldLine.firstChild.isEqualNode(newLine.firstChild)) return false;
	var oldBadge = oldLine.children[1], newBadge = newLine.children[1];
	if (newBadge && !oldBadge) oldLine.appendChild(newBadge);
	else if (!newBadge && oldBadge) oldLine.removeChild(oldBadge);
	else if (newBadge && oldBadge.getAttribute('data-vendor-value') !== newBadge.getAttribute('data-vendor-value'))
		oldLine.replaceChild(newBadge, oldBadge);
	var oldIp = current.children[1], newIp = next.children[1];
	if (newIp && !oldIp) current.appendChild(newIp);
	else if (!newIp && oldIp) current.removeChild(oldIp);
	else if (newIp && !oldIp.isEqualNode(newIp)) current.replaceChild(newIp, oldIp);
	return true;
}

function replaceRowContents(target, source) {
	var focusState = captureRowFocus(target);
	var children = [];
	while (source.firstChild)
		children.push(source.removeChild(source.firstChild));
	if (target.className !== source.className) target.className = source.className;
	if (target.children && target.children.length === children.length &&
	    typeof target.replaceChild === 'function') {
		/* Patch only cells whose rendering changed so unchanged text, hover
		 * targets and selections stay put between samples. */
		children.forEach(function(child, index) {
			var current = target.children[index];
			if (!reusableCell(current, child) && !patchNameCell(current, child) &&
			    !(current.getAttribute('class') === 'lanspeed-client-mac' && current.firstChild.isEqualNode(child.firstChild)))
				target.replaceChild(child, current);
		});
	} else {
		while (target.firstChild)
			target.removeChild(target.firstChild);
		children.forEach(function(child) { target.appendChild(child); });
	}
	restoreRowFocus(target, focusState);
}

/*
 * Keep stable client <tr> nodes alive across samples so live sorting updates
 * contents and order without replacing the complete tbody or losing viewport
 * continuity.
 */
function reconcileClientRows(tbody, rows) {
	var focused = typeof document !== 'undefined' ? document.activeElement : null;
	var selection = typeof window !== 'undefined' && typeof window.getSelection === 'function'
		? window.getSelection() : null;
	var selected = selection && typeof tbody.contains === 'function' &&
		tbody.contains(selection.anchorNode) && tbody.contains(selection.focusNode)
		? { anchor: selection.anchorNode, start: selection.anchorOffset,
			focus: selection.focusNode, end: selection.focusOffset } : null;
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
		if (current !== row) {
			if (row.parentNode === tbody && typeof tbody.moveBefore === 'function')
				tbody.moveBefore(row, current);
			else tbody.insertBefore(row, current);
		}
	});
	while (tbody.children.length > desired.length)
		tbody.removeChild(tbody.lastChild);
	if (focused && focused.isConnected && typeof tbody.contains === 'function' &&
	    tbody.contains(focused) && document.activeElement !== focused) {
		try { focused.focus({ preventScroll: true }); } catch (e) { focused.focus(); }
	}
	if (selected && selected.anchor.isConnected && selected.focus.isConnected &&
	    typeof selection.setBaseAndExtent === 'function')
		selection.setBaseAndExtent(selected.anchor, selected.start, selected.focus, selected.end);
}

function refreshSortHeaders(refs, prefs) {
	if (refs.sortSelect) refs.sortSelect.value = prefs.sortCustom
		? prefs.sortKey + ':' + prefs.sortDir : 'default';
	Object.keys(refs.sortHeaders || {}).forEach(function(columnKey) {
		var ref = refs.sortHeaders[columnKey];
		var sortedColumn = (ref.keys || [ columnKey ]).indexOf(prefs.sortKey) >= 0;
		ref.th.setAttribute('aria-sort', sortedColumn
			? (prefs.sortDir === 'asc' ? 'ascending' : 'descending') : 'none');
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
	var showClientTotals = viewState.showClientTotals === true;
	if (refs.totalHeader) refs.totalHeader.hidden = !showClientTotals;
	if (refs.totalUploadHeader) refs.totalUploadHeader.hidden = !showClientTotals;
	if (refs.clientsTable)
		refs.clientsTable.setAttribute('data-client-totals', showClientTotals ? 'shown' : 'hidden');
	refreshIntervalControl(viewState, refs, status);
	var clientsAll = fmt.asArray(viewState.clients && viewState.clients.clients);
	var prefs = viewState.prefs;
	var activeCfg = fmt.activeConfig(status);
	var showIpv6 = viewState.showIpv6 !== false;
	var hidePrivateIpv6 = viewState.hidePrivateIpv6 === true;
	var hideIpv6Ranges = statusIp.hideIpv6RangesValue(viewState.hideIpv6Ranges);
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
	metaParts.push(_('前端 ') + lsVersion.FULL_VERSION);
	setText(refs.meta, metaParts.join(' · '));
	refreshLiveState(viewState, refs, status, availability);

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
	setText(refs.mTx, fmt.formatRate(totals.tx, prefs.unit));
	setText(refs.mRx, fmt.formatRate(totals.rx, prefs.unit));
	setText(refs.mClients, String(clientsAll.length));

	var clientsData = viewState.clients || {};
	if (typeof clientsData.tcp_conns_total === 'number' || typeof clientsData.udp_conns_total === 'number') {
		var tcpTotal = typeof clientsData.tcp_conns_total === 'number' ? clientsData.tcp_conns_total : null;
		var udpTotal = typeof clientsData.udp_conns_total === 'number' ? clientsData.udp_conns_total : null;
		var connTotal = (tcpTotal !== null && udpTotal !== null) ? tcpTotal + udpTotal : null;
		refs.mConnsWrap.style.display = '';
		setText(refs.mConnsValue, connTotal !== null ? String(connTotal) : '—');
		var connParts = [
			_('TCP ') + (tcpTotal !== null ? tcpTotal : '—'),
			_('UDP ') + (udpTotal !== null ? udpTotal : '—')
		];
		setText(refs.mConnsTcpHint, connParts[0]);
		setText(refs.mConnsUdpHint, connParts[1]);
		if (typeof clientsData.udp_dns_conns_total === 'number' || typeof clientsData.udp_other_conns_total === 'number') {
			refs.mConnsWrap.title = _('当前连接来自连接跟踪：TCP 统计已建立且确认的传输控制协议连接，UDP 统计已确认的用户数据报协议连接。') +
				_(' · 域名查询 ') + (typeof clientsData.udp_dns_conns_total === 'number' ? clientsData.udp_dns_conns_total : '—') +
				' · ' + _('其它 ') + (typeof clientsData.udp_other_conns_total === 'number' ? clientsData.udp_other_conns_total : '—');
		}
	} else {
		refs.mConnsWrap.style.display = 'none';
	}

	if (availability.samplePending) {
		setText(refs.mClientsSub, _('正在同步实时采样…'));
	} else {
		var nssEv = nssProfile && status.evidence && status.evidence.nss;
		var subParts = [ _('%d 个活跃').format(totals.active) ];
		if (nssEv && typeof nssEv.host_count === 'number' &&
		    nssEv.host_count > clientsAll.length) {
			subParts.push(_('NSS 发现 %d 个').format(nssEv.host_count));
		}
		setText(refs.mClientsSub, subParts.join(' · '));
		var activeWindow = Math.round(activeCfg.activeWindowMs / 1000);
		var activeDetail = _('最近 %d 秒内有流量的客户端计为活跃').format(activeWindow);
		if (activeCfg.activeMinBps > 1)
			activeDetail += ' · ' + _('最低 %s').format(fmt.formatRate(activeCfg.activeMinBps, prefs.unit));
		if (refs.mClientsWrap)
			refs.mClientsWrap.title = activeDetail;
	}

	var latestSample = fmt.latestClientSampleMs(clientsAll);
	var vendorPending = false;
	var vendorUnavailable = false;
	var filtered = clientsAll.filter(function(c) {
		var vendor = viewState.vendorLookup ? viewState.vendorLookup(c.mac) : null;
		if (vendor && vendor.kind === 'loading') vendorPending = true;
		if (vendor && vendor.kind === 'unavailable') vendorUnavailable = true;
		if (!fmt.matchesFilter(c, viewState.filter, vendor && [vendor.vendor, vendor.label].join(' '))) return false;
		if (prefs.activeOnly && !fmt.isActiveClient(c, latestSample, activeCfg)) return false;
		return true;
	});
	var sorted = fmt.sortClients(filtered, prefs.sortKey, prefs.sortDir, latestSample, activeCfg);
	var page = refreshPagination(viewState, refs, sorted);
	refreshSortHeaders(refs, prefs);

	var summaryParts = [];
	if (viewState.filter || prefs.activeOnly)
		summaryParts.push(_('%d 个匹配').format(sorted.length));
	if (viewState.filter && vendorPending)
		summaryParts.push(_('厂商数据加载中'));
	else if (viewState.filter && vendorUnavailable)
		summaryParts.push(_('厂商数据不可用'));
	setText(refs.clientsHeaderSummary, summaryParts.join(' · '));
	if (refs.clearFilters) refs.clearFilters.hidden = !(viewState.filter || prefs.activeOnly);

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
		} else if (viewState.filter && vendorPending) {
			refs.empty.setAttribute('data-state', 'loading');
			refs.empty.textContent = _('正在加载厂商数据，搜索结果尚未完整。');
		} else if (viewState.filter && vendorUnavailable) {
			refs.empty.setAttribute('data-state', 'unavailable');
			refs.empty.textContent = _('厂商数据不可用，无法完整匹配厂商名称。');
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

		reconcileClientRows(refs.tbody, page.items.map(function(c) {
			var tx = routedInternet ? routedRate(c, 'tx') : Number(c.tx_bps) || 0;
			var rx = routedInternet ? routedRate(c, 'rx') : Number(c.rx_bps) || 0;
			var idle = !fmt.isActiveClient(c, latestSample, activeCfg);
			var ips = statusIp.displayIpsForClient(c.ips, showIpv6, hidePrivateIpv6, hideIpv6Ranges);
			var displayName;
			if (c.hostname) {
				displayName = c.hostname;
			} else if (ips.length) {
				displayName = ips[0];
			} else {
				displayName = c.mac || '-';
			}

			var vendor = viewState.vendorLookup ? viewState.vendorLookup(c.mac) : null;

			return E('tr', {
				'class': idle ? 'idle' : '',
				'data-client-key': String(fmt.identityOf(c))
			}, [
				E('td', { 'class': 'lanspeed-client-name' },
					clientNameContent(c, displayName, ips, vendor)),
				clientMacCell(c, vendor),
				clientTrafficCell(rx, 'rx', prefs.unit),
				clientTrafficCell(tx, 'tx', prefs.unit),
				clientTrafficTotalCell(c, 'rx', showClientTotals),
				clientTrafficTotalCell(c, 'tx', showClientTotals),
				clientTcpCell(c),
				clientUdpCell(c)
			]);
		}));
	}

	var ifaces = fmt.asArray(viewState.interfaces && viewState.interfaces.interfaces);
	var interfacesRpc = viewState.rpc && viewState.rpc.interfaces;
	if (!ifaces.length) {
		if (interfacesRpc && interfacesRpc.ok === false) {
			refs.ifacesBlock.style.display = '';
			fmt.replaceChildren(refs.ifacesBody, []);
			setText(refs.ifacesSummary, interfacesRpc.retained ? _('上次结果为空') : _('接口数据不可用'));
			refs.ifacesHint.textContent = interfacesRpc.retained
				? _('接口请求失败；上次成功结果中没有接口采样。')
				: _('无法读取接口吞吐，请检查服务状态后重试。');
		} else {
			refs.ifacesBlock.style.display = 'none';
		}
	} else {
		refs.ifacesBlock.style.display = '';
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
				E('td', { 'class': 'num', 'data-label': _('接口 ↓') }, fmt.formatRate(ifDn, prefs.unit)),
				E('td', { 'class': 'num', 'data-label': _('接口 ↑') }, fmt.formatRate(ifUp, prefs.unit)),
				E('td', { 'class': 'num', 'data-label': _('客户端 ↓') },
					isLan ? fmt.formatRate(cs.rx, prefs.unit) : '-'),
				E('td', { 'class': 'num', 'data-label': _('客户端 ↑') },
					isLan ? fmt.formatRate(cs.tx, prefs.unit) : '-')
			]);
		}));

		refs.ifacesSummary.textContent = [
			'↓ ' + fmt.formatRate(totalIfRx, prefs.unit),
			'↑ ' + fmt.formatRate(totalIfTx, prefs.unit)
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
			setText(refs.ifacesHint, '');
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
	clientMacCell: clientMacCell,
	clientTcpCell: clientTcpCell,
	clientUdpCell: clientUdpCell,
	refreshSortHeaders: refreshSortHeaders,
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
