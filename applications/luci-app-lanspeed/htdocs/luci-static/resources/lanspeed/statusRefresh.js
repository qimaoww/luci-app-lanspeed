'use strict';
'require baseclass';
'require lanspeed.vocab as vocab';
'require lanspeed.format as fmt';
'require lanspeed.clientConnections as clientConnections';
'require lanspeed.version as lsVersion';
'require lanspeed.statusIp as statusIp';
'require lanspeed.statusCollector as statusCollector';

var CLIENT_INFO_WARNINGS = {
	conntrack_connection_only: true
};

function clientNameContent(c, displayName, ips) {
	var name = displayName;
	if (c.identity_key) {
		var label = _('查看 %s 的当前连接').format(displayName);
		name = E('a', {
			'class': 'lanspeed-connection-link',
			'href': clientConnections.detailHref(window.location.pathname, c.identity_key),
			'title': label,
			'aria-label': label
		}, displayName);
	}

	return [
		name,
		(c.hostname && ips.length)
			? E('span', { 'class': 'ipline', 'title': ips.join(', ') }, ips.join(', '))
			: (ips.length > 1
				? E('span', { 'class': 'ipline', 'title': ips.join(', ') },
				    ips.slice(1).join(', '))
				: '')
	];
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

function refreshLive(viewState) {
	var refs = viewState.refs;
	if (!refs) return;
	var status = viewState.status || {};
	var clientsAll = fmt.asArray(viewState.clients && viewState.clients.clients);
	var prefs = viewState.prefs;
	var activeCfg = fmt.activeConfig(status);
	var showClientStatus = viewState.showClientStatus === true;
	var showIpv6 = viewState.showIpv6 !== false;
	var hidePrivateIpv6 = viewState.hidePrivateIpv6 === true;
	var hideIpv6Ranges = statusIp.hideIpv6RangesValue(viewState.hideIpv6Ranges);
	setClientStatusVisibility(refs, showClientStatus);

	if (viewState.error) {
		refs.errorBox.style.display = '';
		refs.errorPre.textContent = (viewState.error && (viewState.error.message || String(viewState.error))) || _('未知 RPC 失败');
	} else {
		refs.errorBox.style.display = 'none';
	}

	var collector = statusCollector.effectiveCollector(status, viewState.clients);
	refs.collectorPill.className = statusCollector.collectorClass(collector);
	refs.collectorPill.textContent = statusCollector.collectorLabel(collector);
	refs.collectorPill.title = _('当前实时速率数据源');

	var metaParts = [];
	if (status.version) metaParts.push(_('后端 ') + status.version);
	metaParts.push('luci ' + lsVersion.FULL_VERSION);
	if (prefs.paused) metaParts.push(_('已暂停'));
	refs.meta.textContent = metaParts.join(' · ');

	var totals = fmt.sumTotals(clientsAll, activeCfg);
	refs.mTx.textContent = fmt.formatRate(totals.tx, prefs.unit);
	refs.mRx.textContent = fmt.formatRate(totals.rx, prefs.unit);
	refs.mClients.textContent = String(clientsAll.length);

	var clientsData = viewState.clients || {};
	var udpSub;
	if (typeof clientsData.tcp_conns_total === 'number' || typeof clientsData.udp_conns_total === 'number') {
		refs.mConnsWrap.style.display = '';
		refs.mTcpConns.textContent = 'TCP ' + (typeof clientsData.tcp_conns_total === 'number' ? clientsData.tcp_conns_total : '-');
		refs.mUdpConns.textContent = 'UDP ' + (typeof clientsData.udp_conns_total === 'number' ? clientsData.udp_conns_total : '-');
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

	var nssEv = status.evidence && status.evidence.nss;
	var subParts = [ _('%d 个活跃').format(totals.active) ];
	if (nssEv && typeof nssEv.host_count === 'number' &&
	    nssEv.host_count > clientsAll.length) {
		subParts.push(_('NSS 发现 %d 个').format(nssEv.host_count));
	}
	subParts.push(_('活跃判定 %d 秒').format(Math.round(activeCfg.activeWindowMs / 1000)));
	if (activeCfg.activeMinBps > 1)
		subParts.push(_('≥ ') + fmt.formatRate(activeCfg.activeMinBps, prefs.unit));
	refs.mClientsSub.textContent = subParts.join(' · ');

	var cov = status.coverage || {};
	var covQuality = cov.quality || 'warmup';
	if (covQuality === 'ok') {
		var txPct = typeof cov.tx_pct === 'number' ? cov.tx_pct : null;
		var rxPct = typeof cov.rx_pct === 'number' ? cov.rx_pct : null;
		var minPct = null;
		if (txPct !== null && rxPct !== null) minPct = Math.min(txPct, rxPct);
		else if (rxPct !== null) minPct = rxPct;
		else if (txPct !== null) minPct = txPct;
		refs.mCoverage.textContent = minPct !== null ? (minPct + '%') : '-';
		if ((rxPct !== null && rxPct < 85) || (txPct !== null && txPct < 85)) {
			var missingBps = 0;
			var denomTotal = (Number(cov.denom_rx_bytes) || 0) + (Number(cov.denom_tx_bytes) || 0);
			var numerTotal = (Number(cov.numer_rx_bytes) || 0) + (Number(cov.numer_tx_bytes) || 0);
			if (denomTotal > numerTotal && cov.window_ms > 0)
				missingBps = Math.round(((denomTotal - numerTotal) * 8000) / cov.window_ms);
			refs.mCoverageSub.textContent = '↑' + (txPct !== null ? txPct : '-') +
				' ↓' + (rxPct !== null ? rxPct : '-') +
				' · ' + _('缺口 ') + fmt.formatRate(missingBps, prefs.unit);
		} else if (txPct !== null && rxPct !== null && Math.abs(txPct - rxPct) <= 2) {
			refs.mCoverageSub.textContent = _('上下行均衡');
		} else {
			refs.mCoverageSub.textContent = '↑' + (txPct !== null ? txPct : '-') +
				' ↓' + (rxPct !== null ? rxPct : '-');
		}
	} else if (covQuality === 'idle') {
		refs.mCoverage.textContent = '-';
		refs.mCoverageSub.textContent = _('LAN 无活动流量');
	} else if (covQuality === 'low_traffic') {
		refs.mCoverage.textContent = '-';
		refs.mCoverageSub.textContent = _('LAN 流量较低，暂不计算覆盖率');
	} else if (covQuality === 'warmup' || covQuality === 'counter_reset') {
		refs.mCoverage.textContent = '…';
		refs.mCoverageSub.textContent = _('采样中');
	} else {
		refs.mCoverage.textContent = '-';
		refs.mCoverageSub.textContent = _('不支持');
	}

	var latestSample = fmt.latestClientSampleMs(clientsAll);
	var filtered = clientsAll.filter(function(c) {
		if (!fmt.matchesFilter(c, viewState.filter)) return false;
		if (prefs.activeOnly && !fmt.isActiveClient(c, latestSample, activeCfg)) return false;
		return true;
	});
	var sorted = fmt.sortClients(filtered, prefs.sortKey, prefs.sortDir, latestSample, activeCfg);
	refreshSortHeaders(refs, prefs);

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
			: _('暂未发现 LAN 客户端。请在“LAN Speed 配置”中选择实际 LAN 接口并设为“采集”。');
	} else {
		refs.clientsTable.style.display = '';
		refs.empty.style.display = 'none';

		var globalWarnings = {};
		fmt.asArray(status.warnings).forEach(function(w) {
			globalWarnings[vocab.normalizeWarningId(w)] = true;
		});

		fmt.replaceChildren(refs.tbody, sorted.map(function(c) {
			var tx = Number(c.tx_bps) || 0, rx = Number(c.rx_bps) || 0;
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
			var modeLabel = statusCollector.collectorLabel(mode), modeTitle;
			if (mode === 'bpf') {
				modeTitle = _('BPF 在 LAN 接口按 MAC 统计客户端实时速率。');
			} else if (mode === 'nss_ecm_direct') {
				modeTitle = _('NSS-direct 直接读取 ECM 流量计数，并归属到对应 LAN 客户端。');
			} else if (mode === 'nss_ecm_direct+conntrack_ecm_sync') {
				modeTitle = _('NSS-direct 提供实时数据，NSS sync 补齐未覆盖的客户端。');
			} else if (mode === 'conntrack_ecm_sync' || mode === 'nss_conntrack_sync') {
				modeTitle = _('NSS sync 从 conntrack 读取硬件加速流量，更新精度约为 1–2 秒。');
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

			var stateCells = [
				E('span', { 'class': 'label', 'title': modeTitle }, modeLabel)
			];
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

			return E('tr', idle ? { 'class': 'idle' } : {}, [
				E('td', { 'class': 'lanspeed-client-name' },
					clientNameContent(c, displayName, ips)),
				E('td', {
					'class': 'mono lanspeed-client-mac',
					'data-label': 'MAC'
				}, fmt.textOrDash(c.mac)),
				E('td', {
					'class': 'num lanspeed-client-value',
					'data-label': _('上行')
				}, fmt.formatRate(tx, prefs.unit)),
				E('td', {
					'class': 'num lanspeed-client-value',
					'data-label': _('下行')
				}, fmt.formatRate(rx, prefs.unit)),
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
				stateCell
			]);
		}));
	}

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

		var totalIfTx = 0, totalIfRx = 0;
		fmt.replaceChildren(refs.ifacesBody, ifaces.map(function(i) {
			var n = i.name || '-';
			var isLan = (i.role || 'lan') === 'lan';
			var ifUp = Number(isLan ? i.rx_bps : i.tx_bps) || 0;
			var ifDn = Number(isLan ? i.tx_bps : i.rx_bps) || 0;
			var cs = clientSumByIf[n] || { tx: 0, rx: 0 };

			totalIfTx += ifUp; totalIfRx += ifDn;

			return E('tr', {}, [
				E('td', {}, n),
				E('td', { 'class': 'num' }, fmt.formatRate(ifUp, prefs.unit)),
				E('td', { 'class': 'num' }, fmt.formatRate(ifDn, prefs.unit)),
				E('td', { 'class': 'num' }, isLan ? fmt.formatRate(cs.tx, prefs.unit) : '-'),
				E('td', { 'class': 'num' }, isLan ? fmt.formatRate(cs.rx, prefs.unit) : '-')
			]);
		}));

		refs.ifacesSummary.textContent = [
			'↑ ' + fmt.formatRate(totalIfTx, prefs.unit),
			'↓ ' + fmt.formatRate(totalIfRx, prefs.unit)
		].join(' · ');

		var covHint = status.coverage || {};
		if (covHint.quality === 'ok') {
			var hintTx = typeof covHint.tx_pct === 'number' ? covHint.tx_pct : 100;
			var hintRx = typeof covHint.rx_pct === 'number' ? covHint.rx_pct : 100;
			refs.ifacesHint.textContent = (hintTx < 85 || hintRx < 85)
				? _('部分接口流量未能归属到客户端，常见原因是硬件卸载、交换芯片内转发或广播流量。')
				: '';
		} else {
			refs.ifacesHint.textContent = '';
		}
	}

}

return baseclass.extend({
	clientNameContent: clientNameContent,
	refreshSortHeaders: refreshSortHeaders,
	splitClientWarnings: splitClientWarnings,
	setClientStatusVisibility: setClientStatusVisibility,
	clientStateCell: clientStateCell,

	refreshLive: function(viewState) {
		return refreshLive(viewState);
	}
});
