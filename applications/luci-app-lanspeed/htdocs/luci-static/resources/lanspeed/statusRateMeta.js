'use strict';
'require baseclass';

var RATE_SOURCE_LABELS = {
	edge_port: 'Edge-Port',
	edge_wifi: 'Edge-WiFi',
	ecm_bpf_fallback: 'ECM+BPF fallback',
	ecm_nss_lower_bound: 'ECM NSS lower-bound',
	tc_bpf_lower_bound: 'TC-BPF lower-bound',
	none: _('不可用')
};
var RATE_COVERAGE_LABELS = {
	full: 'Full', partial: 'Partial', degraded: 'Degraded', unavailable: _('不可用')
};
var RATE_COVERAGE_RANK = { unavailable: 0, degraded: 1, partial: 2, full: 3 };
var ATTACHMENT_TRUST_LABELS = {
	observed_exclusive: _('观测独占'),
	associated_station: _('已关联终端'),
	shared: _('共享下联'), unknown: _('接入关系未知')
};

function sourceLabel(source) {
	return RATE_SOURCE_LABELS[String(source || '')] || _('其他来源');
}

function combinedDirectionLabel(tx, rx, labelFor) {
	var txValue = labelFor(tx || {});
	var rxValue = labelFor(rx || {});
	return txValue === rxValue ? txValue : '↑ ' + txValue + ' / ↓ ' + rxValue;
}

function cells(meta, nssProfile) {
	if (!meta || typeof meta !== 'object') return [];
	if (nssProfile === undefined) nssProfile = true;
	if (nssProfile !== true) return [];
	var tx = meta.tx || {}, rx = meta.rx || {};
	var sourceTitle = [
		_('当前速率 owner'),
		_('上行：') + sourceLabel(tx.source),
		_('下行：') + sourceLabel(rx.source)
	].join('\n');
	var result = [ E('span', {
		'class': 'label lanspeed-rate-owner',
		'title': sourceTitle
	}, combinedDirectionLabel(tx, rx, function(direction) {
		return sourceLabel(direction.source);
	})) ];

	var txCoverage = String(tx.coverage || 'unavailable');
	var rxCoverage = String(rx.coverage || 'unavailable');
	var worst = (RATE_COVERAGE_RANK[txCoverage] || 0) <= (RATE_COVERAGE_RANK[rxCoverage] || 0)
		? txCoverage : rxCoverage;
	var coverageText = combinedDirectionLabel(tx, rx, function(direction) {
		return RATE_COVERAGE_LABELS[String(direction.coverage || '')] || _('未知覆盖');
	});
	result.push(E('span', {
		'class': worst === 'full' ? 'label success' :
			worst === 'unavailable' ? 'label warning' : 'label',
		'title': _('总速率覆盖语义，与 NSS 分类覆盖率相互独立')
	}, coverageText));

	var attachment = meta.attachment;
	if (attachment && attachment.ifname) {
		result.push(E('span', {
			'class': 'label lanspeed-rate-attachment',
			'title': _('物理接入点：') + String(attachment.ifname) + '\n' +
				(ATTACHMENT_TRUST_LABELS[String(attachment.trust || '')] || _('接入关系未知'))
		}, String(attachment.ifname)));
	}

	var classification = meta.classification;
	if (classification && typeof classification === 'object') {
		var txPct = typeof classification.tx_coverage_pct === 'number'
			? classification.tx_coverage_pct : null;
		var rxPct = typeof classification.rx_coverage_pct === 'number'
			? classification.rx_coverage_pct : null;
		if (txPct !== null || rxPct !== null) {
			var minimum = txPct === null ? rxPct : rxPct === null ? txPct : Math.min(txPct, rxPct);
			result.push(E('span', {
				'class': classification.state === 'aligned' ? 'label success' : 'label warning',
				'title': _('NSS分类覆盖率') + '\n' +
					_('上行：') + (txPct === null ? '—' : txPct + '%') + '\n' +
					_('下行：') + (rxPct === null ? '—' : rxPct + '%')
			}, _('NSS分类覆盖率 ') + minimum + '%'));
		}
	}
	var summaryStale = meta.stale === true;
	var txStale = typeof tx.stale === 'boolean' ? tx.stale : summaryStale;
	var rxStale = typeof rx.stale === 'boolean' ? rx.stale : summaryStale;
	if (txStale || rxStale) {
		result.push(E('span', {
			'class': 'label warning',
			'title': _('当前保留的是旧采样值') + '\n' +
				_('上行：') + (txStale ? _('已过期') : _('新鲜')) + '\n' +
				_('下行：') + (rxStale ? _('已过期') : _('新鲜'))
		}, txStale && rxStale ? _('已过期') : _('部分过期')));
	}
	return result;
}

return baseclass.extend({
	sourceLabel: sourceLabel,
	combinedDirectionLabel: combinedDirectionLabel,
	cells: cells
});
