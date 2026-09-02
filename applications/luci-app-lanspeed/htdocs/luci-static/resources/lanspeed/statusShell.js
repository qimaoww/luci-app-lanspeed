'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.theme as lsTheme';
'require lanspeed.statusStyle as statusStyle';

var COLUMN_WIDTHS_KEY = 'luci-app-lanspeed.client-column-widths.v11';
var RESIZE_MIN_COLUMN_WIDTH = 32;

function isResizeLockedColumn(columns, index) {
	if (!(index >= 0 && index < columns.length)) return false;
	/* The client table is a fixed-width reading surface. Horizontal movement is
	 * reserved for the table viewport, never for individual column tracks. */
	return true;
}

function setImportantTableWidth(table, value) {
	if (!table || !table.style) return;
	if (typeof table.style.setProperty === 'function')
		table.style.setProperty('width', value, 'important');
	else
		table.style.width = value;
}

function clearTableWidth(table) {
	if (!table || !table.style) return;
	if (typeof table.style.removeProperty === 'function')
		table.style.removeProperty('width');
	else
		delete table.style.width;
}

function setImportantTableDisplay(table, value) {
	if (!table || !table.style) return;
	if (typeof table.style.setProperty === 'function')
		table.style.setProperty('display', value, 'important');
	else
		table.style.display = value;
}

function clearTableDisplay(table) {
	if (!table || !table.style) return;
	if (typeof table.style.removeProperty === 'function')
		table.style.removeProperty('display');
	else
		delete table.style.display;
}

function sumColumnWidths(widths) {
	return widths.reduce(function(sum, width) {
		return sum + Math.max(0, Number(width) || 0);
	}, 0);
}

function preferredColumnWidth(key) {
	if (key === 'hostname') return 120;
	if (key === 'mac') return 145;
	if (key === 'control') return 145;
	if (key === 'tcp_conns' || key === 'udp_conns') return 62;
	if (key === 'tx_bytes' || key === 'rx_bytes') return 92;
	return 88;
}

function minimumColumnWidth(key, locked) {
	if (locked) return preferredColumnWidth(key);
	/* Keep a centered value readable while still allowing a useful left drag. */
	if (key === 'mac') return 96;
	if (key === 'tx' || key === 'rx' || key === 'tx_bytes' || key === 'rx_bytes') return 80;
	if (key === 'tcp_conns' || key === 'udp_conns') return 44;
	return RESIZE_MIN_COLUMN_WIDTH;
}

function normalizeColumnWidths(columns, widths) {
	return columns.map(function(column, index) {
		return Math.max(minimumColumnWidth(column.key,
			isResizeLockedColumn(columns, index)), Number(widths[index]) || 0);
	});
}

function equalizeDataColumnWidths(columns, widths, parentWidth) {
	var indexes = [];
	var total = 0;
	var fixedTotal = 0;
	columns.forEach(function(column, index) {
		var width = Math.max(0, Number(widths[index]) || 0);
		if (column.key === 'hostname' || column.key === 'mac' || column.key === 'control') {
			fixedTotal += width;
			return;
		}
		indexes.push(index);
		total += width;
	});
	if (indexes.length < 2 || !(total > 0)) return widths;
	var available = Number(parentWidth) - fixedTotal;
	var equal = available > 0 ? available / indexes.length : total / indexes.length;
	return widths.map(function(width, index) {
		return indexes.indexOf(index) >= 0 ? equal : width;
	});
}

function fixedLayoutWidths(table, columns, widths, parentWidth) {
	if (!(parentWidth > 0)) return equalizeDataColumnWidths(columns, widths, parentWidth);
	var totalsShown = table.getAttribute('data-client-totals') !== 'hidden';
	var controlShown = table.getAttribute('data-client-control') === 'shown';
	var firstRatio = totalsShown ? (controlShown ? .185 : .22) : (controlShown ? .22 : .24);
	var macRatio = totalsShown ? (controlShown ? .195 : .20) : (controlShown ? .20 : .22);
	var controlRatio = controlShown ? (totalsShown ? .16 : .24) : 0;
	var fixed = [
		parentWidth * firstRatio,
		parentWidth * macRatio,
		parentWidth * controlRatio
	];
	var dataIndexes = [];
	columns.forEach(function(column, index) {
		if (column.key !== 'hostname' && column.key !== 'mac' && column.key !== 'control')
			dataIndexes.push(index);
	});
	var dataWidth = parentWidth - fixed[0] - fixed[1] - fixed[2];
	if (dataIndexes.length < 1 || !(dataWidth > 0))
		return equalizeDataColumnWidths(columns, widths, parentWidth);
	var equal = dataWidth / dataIndexes.length;
	return columns.map(function(column, index) {
		if (column.key === 'hostname') return fixed[0];
		if (column.key === 'mac') return fixed[1];
		if (column.key === 'control') return fixed[2];
		return equal;
	});
}

function fitInitialColumnWidths(columns, widths, parentWidth) {
	var values = normalizeColumnWidths(columns, widths);
	var total = sumColumnWidths(values);
	if (!(parentWidth > 0) || total <= parentWidth) return values;
	var minimums = columns.map(function(column, index) {
		return minimumColumnWidth(column.key, isResizeLockedColumn(columns, index));
	});
	var remaining = total - parentWidth;
	for (var round = 0; round < columns.length && remaining > .5; round++) {
		var capacity = values.map(function(width, index) {
			return Math.max(0, width - minimums[index]);
		});
		var totalCapacity = sumColumnWidths(capacity);
		if (!(totalCapacity > 0)) break;
		values = values.map(function(width, index) {
			return width - Math.min(capacity[index], remaining * capacity[index] / totalCapacity);
		});
		remaining = Math.max(0, sumColumnWidths(values) - parentWidth);
	}
	return values;
}

function gridTemplate(widths) {
	if (!widths.length) return '';
	var tracks = widths.slice(0, -1).map(function(width) {
		return Math.max(0, Number(width) || 0).toFixed(2) + 'px';
	});
	/* The flexible spacer keeps the locked terminal column on the card edge
	 * while the other tracks shrink. It collapses to zero for wide layouts. */
	tracks.push('minmax(0,1fr)');
	tracks.push(Math.max(0, Number(widths[widths.length - 1]) || 0).toFixed(2) + 'px');
	return tracks.join(' ');
}

function setColumnLayout(table, columns, widths) {
	if (!table || !table.style || !Array.isArray(columns) || !Array.isArray(widths)) return;
	var parentWidth = table.parentElement ? Number(table.parentElement.clientWidth) || 0 : 0;
	var values = fixedLayoutWidths(table, columns, widths, parentWidth);
	var trackWidth = sumColumnWidths(values);
	var tableWidth = Math.max(parentWidth, trackWidth);
	if (!(tableWidth > 0 && trackWidth > 0 && columns.length === widths.length)) return;
	if (table.classList && typeof table.classList.add === 'function')
		table.classList.add('lanspeed-custom-column-layout');
	if (table.parentElement && table.parentElement.classList) {
		if (parentWidth > 0 && tableWidth > parentWidth + 1)
			table.parentElement.classList.add('lanspeed-column-overflow');
		else {
			table.parentElement.classList.remove('lanspeed-column-overflow');
			/* Once the canvas fits again, an old horizontal offset can leave a
			 * middle column stranded in the viewport while the rest is clipped. */
			if ('scrollLeft' in table.parentElement)
				table.parentElement.scrollLeft = 0;
		}
	}
	setImportantTableDisplay(table, 'block');
	setImportantTableWidth(table, tableWidth.toFixed(2) + 'px');
	table.style.setProperty('--lanspeed-client-grid-template', gridTemplate(values));
	table.style.setProperty('--lanspeed-client-first-column-width',
		Math.max(0, Number(values[0]) || 0).toFixed(2) + 'px');
	table.style.setProperty('--lanspeed-client-second-column-left',
		Math.max(0, Number(values[0]) || 0).toFixed(2) + 'px');
	if (table.parentElement && parentWidth > 0 &&
		tableWidth > parentWidth + 1 && 'scrollLeft' in table.parentElement) {
		var maxScrollLeft = Math.max(0, tableWidth - parentWidth);
		if (Number(table.parentElement.scrollLeft) > maxScrollLeft)
			table.parentElement.scrollLeft = maxScrollLeft;
	}
}

function clearColumnLayout(table) {
	if (!table || !table.style) return;
	if (table.classList && typeof table.classList.remove === 'function')
		table.classList.remove('lanspeed-custom-column-layout');
	if (table.parentElement && table.parentElement.classList)
		table.parentElement.classList.remove('lanspeed-column-overflow');
	if (typeof table.style.removeProperty === 'function') {
		table.style.removeProperty('--lanspeed-client-grid-template');
		table.style.removeProperty('--lanspeed-client-first-column-width');
		table.style.removeProperty('--lanspeed-client-second-column-left');
	}
	clearTableWidth(table);
	clearTableDisplay(table);
}

function columnLayoutKey(table) {
	return [ 'totals', 'control' ].map(function(name) {
		return name + '=' + (table.getAttribute('data-client-' + name) || 'shown');
	}).join('|');
}

function visibleColumnHeaders(refs) {
	return (refs.clientColumnHeaders || []).filter(function(column) {
		return column.th && !column.th.hidden;
	}).slice().sort(function(left, right) {
		/* sortableHeader() is also used to create the optional headers before
		 * the table row is assembled. Always use the final DOM order here so
		 * cumulative columns cannot receive another column's width. */
		return Number(left.th.cellIndex) - Number(right.th.cellIndex);
	});
}

function syncColumnResizeHandles(refs) {
	var visible = visibleColumnHeaders(refs);
	(refs.clientColumnHeaders || []).forEach(function(column) {
		var th = column.th;
		var handle = column.resizeHandle;
		if (!th || !handle) return;
		var index = visible.indexOf(column);
		var locked = isResizeLockedColumn(visible, index);
		var attached = handle.parentNode === th;
		if (locked && attached && typeof th.removeChild === 'function')
			th.removeChild(handle);
		else if (!locked && !attached && typeof th.appendChild === 'function')
			th.appendChild(handle);
	});
}

function loadColumnWidths(viewState) {
	if (viewState.clientColumnWidthsLoaded) return viewState.clientColumnWidths;
	var stored = {};
	try {
		var raw = window.localStorage.getItem(COLUMN_WIDTHS_KEY);
		var parsed = raw ? JSON.parse(raw) : null;
		if (parsed && typeof parsed === 'object' && !Array.isArray(parsed))
			stored = parsed;
	} catch (e) {}
	viewState.clientColumnWidths = stored;
	viewState.clientColumnWidthsLoaded = true;
	return stored;
}

function saveColumnWidths(viewState) {
	try {
		window.localStorage.setItem(COLUMN_WIDTHS_KEY,
			JSON.stringify(viewState.clientColumnWidths || {}));
	} catch (e) {}
}

function resizeColumnTracks(columns, startWidths, index, delta) {
	if (!columns.length || index < 0 || index >= columns.length ||
		isResizeLockedColumn(columns, index)) return null;
	var widths = normalizeColumnWidths(columns, startWidths);
	widths[index] = Math.max(RESIZE_MIN_COLUMN_WIDTH,
		widths[index] + (Number(delta) || 0));
	return widths;
}

function applyStoredColumnWidths(viewState, refs) {
	var table = refs && refs.clientsTable;
	if (!table) return;
	/* During render() LuCI builds the table in a detached fragment. Its parent
	 * can report the table's intrinsic width rather than the final card width;
	 * never freeze that transient measurement as the persisted canvas. */
	if (table.isConnected === false) return;
	var columns = visibleColumnHeaders(refs);
	var layoutKey = columnLayoutKey(table);
	var layoutActive = table.classList &&
		table.classList.contains('lanspeed-custom-column-layout');
	var stored = loadColumnWidths(viewState)[layoutKey];
	/* Refreshes replace rows, not headers. Reapplying the layout on every poll
	 * briefly exposes native table sizing and makes the columns visibly jump.
	 * Keep an already-applied layout untouched until the visible-column state
	 * actually changes. */
	var parentWidth = table.parentElement ? Number(table.parentElement.clientWidth) || 0 : 0;
	if (!(parentWidth > 0) || !columns.length) return;
	if (viewState.clientColumnLayoutKey === layoutKey && layoutActive &&
		Math.abs((Number(viewState.clientColumnViewportWidth) || 0) - parentWidth) < 1) return;
	var values;
	if (stored && typeof stored === 'object' && !Array.isArray(stored) &&
		stored.columns && typeof stored.columns === 'object') {
		values = columns.map(function(column) {
			var value = Number(stored.columns[column.key]);
			return isFinite(value) && value > 0 ? value : 0;
		});
	}
	if (!values || !(sumColumnWidths(values) > 0)) {
		values = columns.map(function(column) {
			return Number(column.th.getBoundingClientRect().width) ||
				preferredColumnWidth(column.key);
		});
		values = fitInitialColumnWidths(columns, values, parentWidth);
	} else {
		values = normalizeColumnWidths(columns, values);
	}
	values = fixedLayoutWidths(table, columns, values, parentWidth);
	clearColumnLayout(table);
	setColumnLayout(table, columns, values);
	viewState.clientColumnLayoutKey = layoutKey;
	viewState.clientColumnViewportWidth = parentWidth;
}

function persistCurrentColumnWidths(viewState, refs) {
	var table = refs && refs.clientsTable;
	if (!table || typeof table.getBoundingClientRect !== 'function') return;
	var values = {};
	var columns = visibleColumnHeaders(refs);
	columns.forEach(function(column) {
		if (!column.th || typeof column.th.getBoundingClientRect !== 'function') return;
		var width = Number(column.th.getBoundingClientRect().width);
		if (width > 0) values[column.key] = width;
	});
	if (!Object.keys(values).length) return;
	var stored = loadColumnWidths(viewState);
	stored[columnLayoutKey(table)] = {
		version: 11,
		columns: values
	};
	viewState.clientColumnWidths = stored;
	saveColumnWidths(viewState);
}

function setupColumnResize(viewState, refs) {
	var table = refs && refs.clientsTable;
	if (!table) return;
	loadColumnWidths(viewState);
	(refs.clientColumnHeaders || []).forEach(function(column) {
		var th = column.th;
		if (!th || th.getAttribute('data-column-resize-ready') === '1') return;
		if (isResizeLockedColumn(visibleColumnHeaders(refs),
			visibleColumnHeaders(refs).indexOf(column))) {
			/* Every visible column is intentionally fixed; the table viewport scrolls. */
			th.setAttribute('data-column-resize-ready', '1');
			return;
		}
		th.setAttribute('data-column-resize-ready', '1');
		th.className = String(th.className || '') + ' lanspeed-resizable-column';
		var handle = E('span', {
			'class': 'lanspeed-column-resize-handle',
			'role': 'separator',
			'aria-orientation': 'vertical',
			'aria-label': _('拖动调整列宽'),
			'tabindex': '0'
		});
		handle.addEventListener('click', function(event) {
			if (event && event.preventDefault) event.preventDefault();
			if (event && event.stopPropagation) event.stopPropagation();
		});
		handle.addEventListener('pointerdown', function(event) {
			if (!event || (event.button !== undefined && event.button !== 0)) return;
			var visible = visibleColumnHeaders(refs);
			var index = visible.indexOf(column);
			if (index < 0) return;
			/* The rightmost visible column is fixed in every totals/control display
			 * combination. Its identity is dynamic (control or UDP). */
			if (isResizeLockedColumn(visible, index)) return;
			if (typeof th.getBoundingClientRect !== 'function') return;
			var parentWidth = table.parentElement ? Number(table.parentElement.clientWidth) || 0 : 0;
			if (!(parentWidth > 0)) return;
			/* LuCI may dispatch the first pointer event before the root has completed
			 * its initial attachment. Establish the canvas before measuring tracks so
			 * a first drag can never fall back to native table redistribution. */
			applyStoredColumnWidths(viewState, refs);
			if (!table.classList || !table.classList.contains('lanspeed-custom-column-layout')) return;
			var startWidths = visible.map(function(item) {
				return Number(item.th.getBoundingClientRect().width) || 0;
			});
			var firstWidth = startWidths[index];
			if (!(firstWidth > 0)) return;
			setColumnLayout(table, visible, startWidths);
			viewState.clientColumnResizeActive = true;
			var startX = Number(event.clientX);
			var dragging = false;
			var hostDocument = typeof document !== 'undefined' ? document : null;
			function move(moveEvent) {
				var delta = Number(moveEvent && moveEvent.clientX) - startX;
				if (!isFinite(delta)) return;
				var widths = resizeColumnTracks(visible, startWidths, index, delta);
				if (!widths) return;
				setColumnLayout(table, visible, widths);
				dragging = true;
				if (moveEvent && moveEvent.preventDefault) moveEvent.preventDefault();
			}
			function finish() {
				if (hostDocument && typeof hostDocument.removeEventListener === 'function') {
					hostDocument.removeEventListener('pointermove', move);
					hostDocument.removeEventListener('pointerup', finish);
					hostDocument.removeEventListener('pointercancel', finish);
				}
				viewState.clientColumnResizeActive = false;
				if (dragging)
					persistCurrentColumnWidths(viewState, refs);
				else
					applyStoredColumnWidths(viewState, refs);
			}
			if (event.preventDefault) event.preventDefault();
			if (event.stopPropagation) event.stopPropagation();
			if (hostDocument && typeof hostDocument.addEventListener === 'function') {
				hostDocument.addEventListener('pointermove', move);
				hostDocument.addEventListener('pointerup', finish);
				hostDocument.addEventListener('pointercancel', finish);
			}
			if (typeof handle.setPointerCapture === 'function' && event.pointerId !== undefined) {
				try { handle.setPointerCapture(event.pointerId); } catch (e) {}
			}
		});
		column.resizeHandle = handle;
		th.appendChild(handle);
	});
	refs.syncClientColumnWidths = function() {
		if (viewState.clientColumnResizeActive === true) return;
		syncColumnResizeHandles(refs);
		applyStoredColumnWidths(viewState, refs);
	};
	/* The first attachment can resize the card after the table has been
	 * measured (notably when LuCI's content grid settles). Follow the body
	 * itself so the canvas is corrected without requiring a manual refresh. */
	if (typeof ResizeObserver === 'function' && table.parentElement &&
		!viewState.clientColumnResizeObserver) {
		viewState.clientColumnResizeObserver = new ResizeObserver(function() {
			if (viewState.destroyed !== true && viewState.clientColumnResizeActive !== true)
				applyStoredColumnWidths(viewState, refs);
		});
		viewState.clientColumnResizeObserver.observe(table.parentElement);
	}
	syncColumnResizeHandles(refs);
	applyStoredColumnWidths(viewState, refs);
}

function sortableHeader(viewState, refs, sortKey, label, attrs) {
	var thAttrs = Object.assign({ 'aria-sort': 'none' }, attrs || {});
	thAttrs['data-column-key'] = sortKey;
	var button = E('button', {
		'type': 'button',
		'class': 'lanspeed-sort-button'
	}, [
		E('span', { 'class': 'lanspeed-sort-label' }, label),
		E('span', { 'class': 'lanspeed-sort-indicator', 'aria-hidden': 'true' }, '')
	]);
	var th = E('th', thAttrs, button);
	if (refs.clientColumnHeaders)
		refs.clientColumnHeaders.push({ key: sortKey, th: th });

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
	refs.clientColumnHeaders = [];

	refs.collectorPill = E('span', { 'class': 'label lanspeed-collector-status' }, '-');
	refs.meta     = E('span', { 'class': 'meta' }, '');
	var overviewHeader = E('div', { 'class': 'lanspeed-header' }, [
		E('h3', {}, _('LAN Speed')),
		refs.collectorPill,
		E('span', { 'class': 'spacer' }),
		refs.meta
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

	refs.mTx          = E('div', { 'class': 'big' }, '—');
	refs.mRx          = E('div', { 'class': 'big' }, '—');
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

	var nssRefreshRestricted = typeof fmt.nssRefreshRestricted === 'function' &&
		fmt.nssRefreshRestricted(viewState.status);
	var refreshValue = nssRefreshRestricted
		? fmt.normalizeNssRefreshMs(prefs.nssRefreshMs) : prefs.refreshMs;
	var refreshChoices = nssRefreshRestricted
		? fmt.NSS_REFRESH_CHOICES
		: fmt.REFRESH_CHOICES;
	var refreshAttrs = {
		'class': 'cbi-input-select',
		'data-refresh-policy': nssRefreshRestricted ? 'nss' : 'default',
		'title': nssRefreshRestricted ? _('ECM 采集方案最低每 2 秒刷新') : ''
	};
	refs.intervalSel = E('select', refreshAttrs, refreshChoices.map(function(c) {
		return fmt.opt(c.value, c.label, refreshValue === c.value);
	}));
	refs.intervalSel.addEventListener('change', function(ev) {
		var v = parseInt(ev.target.value, 10);
		var nss = typeof fmt.nssRefreshRestricted === 'function' &&
			fmt.nssRefreshRestricted(viewState.status);
		if (nss && fmt.NSS_REFRESH_CHOICES.some(function(choice) { return choice.value === v; })) {
			viewState.prefs.nssRefreshMs = v;
			fmt.savePrefs(viewState.prefs);
			viewState.schedule();
		} else if (!nss && !isNaN(v) && v >= fmt.MIN_REFRESH_MS) {
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
	refs.totalUploadHeader = sortableHeader(viewState, refs, 'tx_bytes', _('累计上传'), {
		'class': 'num lanspeed-client-total-header lanspeed-client-total-upload-header'
	});
	refs.totalUploadHeader.hidden = viewState.showClientTotals !== true;
	refs.totalDownloadHeader = sortableHeader(viewState, refs, 'rx_bytes', _('累计下载'), {
		'class': 'num lanspeed-client-total-header lanspeed-client-total-download-header'
	});
	refs.totalDownloadHeader.hidden = viewState.showClientTotals !== true;
	refs.controlHeader = E('th', {
		'class': 'lanspeed-client-control-header',
		'data-column-key': 'control'
	}, _('控制'));
	refs.controlHeader.hidden = false;
	refs.clientsTable = E('table', {
		'id': 'lanspeed-clients-table',
		'class': 'lanspeed-table',
		'data-client-totals': viewState.showClientTotals === true ? 'shown' : 'hidden',
		'data-client-control': 'shown'
	}, [
		E('thead', {}, E('tr', {}, [
			sortableHeader(viewState, refs, 'hostname', _('客户端')),
			sortableHeader(viewState, refs, 'mac', 'MAC'),
			sortableHeader(viewState, refs, 'tx', _('上行'), { 'class': 'num' }),
			sortableHeader(viewState, refs, 'rx', _('下行'), { 'class': 'num' }),
			refs.totalUploadHeader,
			refs.totalDownloadHeader,
			sortableHeader(viewState, refs, 'tcp_conns', 'TCP', {
				'class': 'num', 'title': _('当前已建立并确认的 TCP 连接')
			}),
			sortableHeader(viewState, refs, 'udp_conns', 'UDP', {
				'class': 'num', 'title': _('当前已确认的 UDP 连接')
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
			E('div', { 'class': 'lanspeed-table-scroll' }, [
				refs.clientsTable
			]),
			refs.empty,
			refs.pageNav
		])
	]);
	refs.clientColumnHeaders.push({ key: 'control', th: refs.controlHeader });
	setupColumnResize(viewState, refs);

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
