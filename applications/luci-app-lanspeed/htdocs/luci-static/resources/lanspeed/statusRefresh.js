'use strict';
'require baseclass';
'require lanspeed.vocab as vocab';
'require lanspeed.format as fmt';
'require lanspeed.version as lsVersion';
'require lanspeed.nssPanel as nssPanel';
'require lanspeed.statusIp as statusIp';
'require lanspeed.statusCollector as statusCollector';

function refreshLive(viewState) {
	var refs = viewState.refs;
	if (!refs) return;
	var status = viewState.status || {};
	var clientsAll = fmt.asArray(viewState.clients && viewState.clients.clients);
	var prefs = viewState.prefs;
	var activeCfg = fmt.activeConfig(status);
	var showIpv6 = viewState.showIpv6 !== false;
	var hidePrivateIpv6 = viewState.hidePrivateIpv6 === true;
	var hideIpv6Ranges = statusIp.hideIpv6RangesValue(viewState.hideIpv6Ranges);

	if (viewState.error) {
		refs.errorBox.style.display = '';
		refs.errorPre.textContent = (viewState.error && (viewState.error.message || String(viewState.error))) || _('未知 RPC 失败');
	} else {
		refs.errorBox.style.display = 'none';
	}

	var collector = statusCollector.effectiveCollector(status, viewState.clients);
	refs.collectorPill.className = statusCollector.collectorClass(collector);
	refs.collectorPill.textContent = statusCollector.collectorLabel(collector);
	refs.collectorPill.title = _('当前采集方式');

	var metaParts = [];
	if (status.version) metaParts.push('daemon ' + status.version);
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
		subParts.push(_('ECM 知 %d').format(nssEv.host_count));
	}
	subParts.push(_('活跃窗 %d 秒').format(Math.round(activeCfg.activeWindowMs / 1000)));
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
	var sorted = fmt.sortClients(filtered, prefs.sortKey);

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
			: _('lanspeedd 当前未上报 LAN 客户端。请确认 /etc/config/lanspeed 的 ifname 指向实际 LAN 边缘接口。');
	} else {
		refs.clientsTable.style.display = '';
		refs.empty.style.display = 'none';

		var globalWarnings = {};
		fmt.asArray(status.warnings).forEach(function(w) { globalWarnings[w] = true; });

		fmt.replaceChildren(refs.tbody, sorted.map(function(c) {
			var tx = Number(c.tx_bps) || 0, rx = Number(c.rx_bps) || 0;
			var idle = !fmt.isActiveClient(c, latestSample, activeCfg);
			var ips = statusIp.displayIpsForClient(c.ips, showIpv6, hidePrivateIpv6, hideIpv6Ranges);
			var rawWarnings = fmt.asArray(c.warnings);
			var specificWarnings = rawWarnings.filter(function(w) { return !globalWarnings[w]; });
			var critClient = specificWarnings.some(function(w) { return vocab.CRITICAL_WARNINGS[w]; });

			var mode = String(c.collector_mode || '-');
			var modeLabel = statusCollector.collectorLabel(mode), modeTitle;
			if (mode === 'bpf') {
				modeTitle = _('采集方式 BPF：tc clsact 挂载的 eBPF 程序按 MAC 直接计数。');
			} else if (mode === 'nss_ecm_direct') {
				modeTitle = _('采集方式 NSS-direct：只读 qca-nss-ecm state 设备，直接按 ECM flow 字节计数聚合到 LAN 客户端，不等待 ECM 同步回 conntrack。');
			} else if (mode === 'nss_ecm_direct+conntrack_ecm_sync') {
				modeTitle = _('采集方式 NSS-direct / NSS sync：NSS sync 提供稳定来源，NSS-direct 覆盖有有效速率的 ECM flow。');
			} else if (mode === 'conntrack_ecm_sync' || mode === 'nss_conntrack_sync') {
				modeTitle = _('采集方式 NSS 同步：NSS 硬件加速流的字节计数以秒级节拍同步回 conntrack，再由 lanspeedd 读取。桥接流也覆盖，精度等于同步间隔 (≈1-2 秒)。');
			} else if (mode === 'conntrack_netlink') {
				modeTitle = _('采集方式 Netlink Conntrack：非 NSS 仅用于连接数与诊断，不作为客户端实时测速来源。');
			} else if (mode === 'conntrack') {
				modeTitle = _('采集方式 Conntrack：非 NSS 仅用于连接数与诊断，不作为客户端实时测速来源。');
			} else {
				modeTitle = _('未知采集方式');
			}

			var stateCells = [
				E('span', { 'class': 'label', 'title': modeTitle }, modeLabel)
			];
			if (specificWarnings.length)
				stateCells.push(E('span', {
					'class': critClient ? 'label danger' : 'label warning',
					'title': specificWarnings.map(vocab.warningText.bind(vocab)).join('\n')
				}, _('%d 告警').format(specificWarnings.length)));

			var displayName;
			if (c.hostname) {
				displayName = c.hostname;
			} else if (ips.length) {
				displayName = ips[0];
			} else {
				displayName = c.mac || '-';
			}

			return E('tr', idle ? { 'class': 'idle' } : {}, [
				E('td', {}, [
					displayName,
					(c.hostname && ips.length)
						? E('span', { 'class': 'ipline', 'title': ips.join(', ') }, ips.join(', '))
						: (ips.length > 1
							? E('span', { 'class': 'ipline', 'title': ips.join(', ') },
							    ips.slice(1).join(', '))
							: '')
				]),
				E('td', { 'class': 'mono' }, fmt.textOrDash(c.mac)),
				E('td', { 'class': 'num' }, fmt.formatRate(tx, prefs.unit)),
				E('td', { 'class': 'num' }, fmt.formatRate(rx, prefs.unit)),
				E('td', { 'class': 'num' }, typeof c.tcp_conns === 'number' ? String(c.tcp_conns) : '-'),
				E('td', {
					'class': 'num',
					'title': (typeof c.udp_dns_conns === 'number' || typeof c.udp_other_conns === 'number')
						? [
							'DNS ' + (typeof c.udp_dns_conns === 'number' ? c.udp_dns_conns : '-'),
							_('其它 ') + (typeof c.udp_other_conns === 'number' ? c.udp_other_conns : '-')
						  ].join(' · ')
						: ''
				}, typeof c.udp_conns === 'number' ? String(c.udp_conns) : '-'),
				E('td', {}, E('span', { 'class': 'state' }, stateCells))
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
				? _('覆盖率偏低：可能有硬件流量卸载、硬件桥接 LAN-to-LAN、广播/多播或未归属 MAC。')
				: '';
		} else {
			refs.ifacesHint.textContent = '';
		}
	}

	nssPanel.render(refs, status);

	var capabilities = status.capabilities || {};
	var capKeys = vocab.CAPABILITY_ORDER.filter(function(k) {
		return Object.prototype.hasOwnProperty.call(capabilities, k);
	});
	if (capKeys.length) {
		fmt.replaceChildren(refs.capsGrid, capKeys.map(function(k) {
			var enabled = Boolean(capabilities[k]);
			return E('div', { 'class': 'cap' }, [
				E('span', {}, vocab.CAPABILITY_LABELS[k] || k),
				E('span', { 'class': vocab.capabilityClass(k, enabled), 'title': k },
					enabled ? _('是') : _('否'))
			]);
		}));
	} else {
		fmt.replaceChildren(refs.capsGrid, [E('p', {}, _('后端未上报任何能力。'))]);
	}

	var warnings = fmt.asArray(status.warnings);
	if (warnings.length) {
		fmt.replaceChildren(refs.allWarnings, warnings.map(function(w) {
			return E('li', {}, [
				E('span', { 'class': vocab.warningClass(w) + ' key' }, w),
				vocab.warningText(w)
			]);
		}));
	} else {
		fmt.replaceChildren(refs.allWarnings, [E('li', {}, _('当前没有上报告警。'))]);
	}

	var versionParts = [
		_('lanspeedd %s').format(fmt.textOrDash(status.version)),
		_('luci-app-lanspeed %s').format(lsVersion.FULL_VERSION),
		_('后端刷新 %s ms').format(fmt.textOrDash(status.refresh_interval_ms))
	];
	var nssEvidence = status.evidence && status.evidence.nss;
	if (nssEvidence && (nssEvidence.ecm_offload_active || nssEvidence.ppe_offload_active)) {
		var engine = nssEvidence.ppe_offload_active ? 'PPE' : 'ECM';
		var connBits = [];
		if (typeof nssEvidence.accelerated_connections === 'number')
			connBits.push(_('总 %d').format(nssEvidence.accelerated_connections));
		if (typeof nssEvidence.accelerated_tcp === 'number')
			connBits.push('TCP ' + nssEvidence.accelerated_tcp);
		if (typeof nssEvidence.accelerated_udp === 'number')
			connBits.push('UDP ' + nssEvidence.accelerated_udp);
		if (typeof nssEvidence.accelerated_other === 'number' && nssEvidence.accelerated_other > 0)
			connBits.push(_('其它 %d').format(nssEvidence.accelerated_other));
		if (connBits.length)
			versionParts.push(_('NSS %s 加速连接').format(engine) + ' (' + connBits.join(' / ') + ')');
		else
			versionParts.push(_('NSS %s 活跃').format(engine));

		var objectBits = [];
		if (typeof nssEvidence.host_count === 'number')
			objectBits.push(_('host %d').format(nssEvidence.host_count));
		if (typeof nssEvidence.mapping_count === 'number')
			objectBits.push(_('NAT 映射 %d').format(nssEvidence.mapping_count));
		if (objectBits.length)
			versionParts.push(_('ECM 数据库: ') + objectBits.join(' · '));
	}
	if (nssEvidence && Array.isArray(nssEvidence.subsystems) && nssEvidence.subsystems.length)
		versionParts.push(_('NSS 子系统: ') + nssEvidence.subsystems.join(', '));
	refs.versionLine.textContent = versionParts.join(' · ');

	refs.diagnosticsSummary.textContent = warnings.length
		? _('%d 项告警 · %d 项能力').format(warnings.length, capKeys.length)
		: _('无告警 · %d 项能力').format(capKeys.length);
}

return baseclass.extend({
	refreshLive: function(viewState) {
		return refreshLive(viewState);
	}
});
