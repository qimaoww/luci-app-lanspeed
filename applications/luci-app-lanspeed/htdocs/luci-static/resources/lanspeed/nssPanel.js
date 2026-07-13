'use strict';
'require baseclass';
'require lanspeed.vocab as vocab';
'require lanspeed.format as fmt';

/*
 * NSS status collapsible card.
 *
 * Aggregates Qualcomm NSS information that is otherwise scattered across
 * diagnostic card, capability grid and warnings list.  Intentionally a
 * read-only aggregate view — other cards keep their nss_* entries too, so
 * this panel is never the single source of truth.
 *
 * Visibility rule: only render when capabilities or evidence contain a true
 * NSS signal. Rust status always includes a false-filled evidence object on
 * non-NSS devices, which must not make the panel visible.
 *
 * Default open state: closed. Refreshes never touch the open attribute, so
 * the user's manual expand/collapse choice remains stable on this page.
 */

function hasNssSignal(status) {
	if (!status) return false;
	var caps = status.capabilities || {};
	if (caps.nss === true) return true;
	var ev = status.evidence && status.evidence.nss;
	if (ev && typeof ev === 'object') {
		var state = nssEvidenceState(ev);
		if (ev.present === true || state.ecmActive || state.ppeActive ||
		    state.directSupported || ev.direct_enabled || ev.bridge_mgr ||
		    ev.ifb_active || ev.nsm_active || ev.dp_active || ev.mcs_active ||
		    (Array.isArray(ev.subsystems) && ev.subsystems.length))
			return true;
	}
	/* any nss_* capability (even if base "nss" missing) still warrants showing */
	for (var key in caps) {
		if (key.indexOf('nss') === 0 && caps[key]) return true;
	}
	return false;
}

function nssEvidenceState(ev) {
	return {
		ecmActive: typeof ev.ecm_active === 'boolean'
			? ev.ecm_active : Boolean(ev.ecm_offload_active),
		ppeActive: typeof ev.ppe_active === 'boolean'
			? ev.ppe_active : Boolean(ev.ppe_offload_active),
		directSupported: typeof ev.direct_state_readable === 'boolean'
			? ev.direct_state_readable : Boolean(ev.direct_supported)
	};
}

function nssDirectFallbackText(reason) {
	reason = vocab.normalizeWarningId(reason);
	if (reason === 'collector_mode_bpf')
		return _('当前使用 BPF');
	if (reason === 'collector_mode_nss_conntrack_sync')
		return _('当前使用 NSS sync');
	if (reason === 'dae_runtime_prefers_bpf')
		return _('dae/daed 运行中，当前优先使用 BPF');
	if (reason === 'state_unavailable_or_unreadable')
		return _('ECM state 设备不可用或不可读');
	if (reason === 'not_selected')
		return _('当前未选择 NSS-direct');
	return reason || '';
}

function build(refs) {
	refs.nssEngine    = E('span', { 'class': 'label' }, '-');
	refs.nssSummary   = E('span', { 'class': 'sum' }, '');

	refs.nssEngineLine    = E('p', { 'class': 'lanspeed-hint' }, '');
	refs.nssConnectionsLn = E('p', { 'class': 'lanspeed-hint' }, '');
	refs.nssDatabaseLn    = E('p', { 'class': 'lanspeed-hint' }, '');
	refs.nssSubsystems    = E('div', { 'class': 'lanspeed-caps' });
	refs.nssCaps          = E('div', { 'class': 'lanspeed-caps' });
	refs.nssWarnings      = E('ul', { 'class': 'lanspeed-warnings' });

	refs.nssDetails = E('details', { 'class': 'lanspeed-details' }, [
		E('summary', {}, [
			E('h3', {}, _('NSS 状态')),
			refs.nssEngine,
			E('span', { 'class': 'spacer' }),
			refs.nssSummary
		]),
		E('div', { 'class': 'lanspeed-details-body' }, [
			E('h4', { 'class': 'lanspeed-subhead' }, _('引擎与加速')),
			refs.nssEngineLine,
			refs.nssConnectionsLn,
			refs.nssDatabaseLn,
			E('h4', { 'class': 'lanspeed-subhead' }, _('NSS 子系统')),
			refs.nssSubsystems,
			E('h4', { 'class': 'lanspeed-subhead' }, _('NSS 能力')),
			refs.nssCaps,
			E('h4', { 'class': 'lanspeed-subhead' }, _('NSS 相关告警')),
			refs.nssWarnings
		])
	]);

	refs.nssSection = E('div', { 'class': 'cbi-section', 'style': 'display:none' }, [
		refs.nssDetails
	]);

	return refs.nssSection;
}

function render(refs, status) {
	if (!refs || !refs.nssSection) return;

	status = status || {};
	if (!hasNssSignal(status)) {
		refs.nssSection.style.display = 'none';
		return;
	}
	refs.nssSection.style.display = '';

	var ev = (status.evidence && status.evidence.nss) || {};
	var caps = status.capabilities || {};
	var warnings = fmt.asArray(status.warnings).map(function(w) {
		return vocab.normalizeWarningId(w);
	});
	var evidenceState = nssEvidenceState(ev);
	var ecmActive = evidenceState.ecmActive;
	var ppeActive = evidenceState.ppeActive;
	var directSupported = evidenceState.directSupported;

	/* engine pill + summary */
	var engineLabel, engineCls;
	if (ppeActive) {
		engineLabel = _('PPE 活跃');
		engineCls = 'label label-danger';
	} else if (ecmActive) {
		engineLabel = _('ECM 活跃');
		engineCls = 'label label-danger';
	} else if (caps.nss) {
		engineLabel = _('未激活');
		engineCls = 'label label-warning';
	} else {
		engineLabel = _('不支持');
		engineCls = 'label';
	}
	refs.nssEngine.className = engineCls;
	refs.nssEngine.textContent = engineLabel;

	var summaryBits = [];
	if (typeof ev.accelerated_connections === 'number')
		summaryBits.push(_('%d 加速连接').format(ev.accelerated_connections));
	if (ev.direct_enabled)
		summaryBits.push('Direct');
	if (typeof ev.host_count === 'number')
		summaryBits.push(_('host %d').format(ev.host_count));
	refs.nssSummary.textContent = summaryBits.join(' · ');

	/* engine line */
	var engine = ppeActive ? 'PPE'
	           : ecmActive ? 'ECM'
	           : '-';
	var directParts = [];
	if (ev.direct_enabled) {
		directParts.push(_('NSS-direct 已启用'));
	} else if (directSupported) {
		directParts.push(_('NSS-direct 可用'));
	} else {
		directParts.push(_('NSS-direct 未启用'));
	}
	if (ev.fallback_reason && !ev.direct_enabled)
		directParts.push(nssDirectFallbackText(ev.fallback_reason));
	refs.nssEngineLine.textContent = _('引擎: %s').format(engine) + ' · ' + directParts.join(' · ');

	/* connections line */
	if (typeof ev.accelerated_connections === 'number' ||
	    typeof ev.accelerated_tcp === 'number' ||
	    typeof ev.accelerated_udp === 'number' ||
	    typeof ev.accelerated_other === 'number') {
		var parts = [];
		if (typeof ev.accelerated_connections === 'number')
			parts.push(_('总 %d').format(ev.accelerated_connections));
		if (typeof ev.accelerated_tcp === 'number')
			parts.push('TCP ' + ev.accelerated_tcp);
		if (typeof ev.accelerated_udp === 'number')
			parts.push('UDP ' + ev.accelerated_udp);
		if (typeof ev.accelerated_other === 'number' && ev.accelerated_other > 0)
			parts.push(_('其它 %d').format(ev.accelerated_other));
		refs.nssConnectionsLn.textContent = _('加速连接: ') + parts.join(' · ');
		refs.nssConnectionsLn.style.display = '';
	} else {
		refs.nssConnectionsLn.textContent = '';
		refs.nssConnectionsLn.style.display = 'none';
	}

	/* database line */
	if (typeof ev.host_count === 'number' || typeof ev.mapping_count === 'number') {
		var dbParts = [];
		if (typeof ev.host_count === 'number')
			dbParts.push(_('host %d').format(ev.host_count));
		if (typeof ev.mapping_count === 'number')
			dbParts.push(_('NAT 映射 %d').format(ev.mapping_count));
		refs.nssDatabaseLn.textContent = _('ECM 数据库: ') + dbParts.join(' · ');
		refs.nssDatabaseLn.style.display = '';
	} else {
		refs.nssDatabaseLn.textContent = '';
		refs.nssDatabaseLn.style.display = 'none';
	}

	/* subsystems */
	var subs = Array.isArray(ev.subsystems) ? ev.subsystems : [];
	if (subs.length) {
		fmt.replaceChildren(refs.nssSubsystems, subs.map(function(s) {
			return E('div', { 'class': 'cap' }, [
				E('span', {}, String(s)),
				E('span', { 'class': 'label label-success' }, _('已加载'))
			]);
		}));
	} else {
		fmt.replaceChildren(refs.nssSubsystems, [
			E('div', { 'class': 'cap' }, [
				E('span', { 'style': 'opacity:.65' }, _('后端未报告 NSS 子系统'))
			])
		]);
	}

	/* capabilities subset */
	var NSS_CAP_KEYS = [
		'nss', 'nss_dp', 'nss_ecm_direct', 'nss_ecm_offload', 'nss_ppe_offload',
		'nss_nsm', 'nss_bridge_mgr', 'nss_ifb', 'nss_mcs'
	];
	var nssCapKeys = NSS_CAP_KEYS.filter(function(k) {
		return Object.prototype.hasOwnProperty.call(caps, k);
	});
	if (nssCapKeys.length) {
		fmt.replaceChildren(refs.nssCaps, nssCapKeys.map(function(k) {
			var enabled = Boolean(caps[k]);
			return E('div', { 'class': 'cap' }, [
				E('span', {}, vocab.CAPABILITY_LABELS[k] || k),
				E('span', { 'class': vocab.capabilityClass(k, enabled), 'title': k },
					enabled ? _('是') : _('否'))
			]);
		}));
	} else {
		fmt.replaceChildren(refs.nssCaps, [
			E('div', { 'class': 'cap' }, [
				E('span', { 'style': 'opacity:.65' }, _('后端未报告 NSS 能力'))
			])
		]);
	}

	/* Keep NSS-specific warnings plus the active dae/daed collector decision. */
	var nssWarnings = warnings.filter(function(w) {
		return w.indexOf('nss') === 0 || w === 'nssifb_collect_rejected' ||
			w === 'dae_runtime_prefers_bpf';
	});
	if (nssWarnings.length) {
		fmt.replaceChildren(refs.nssWarnings, nssWarnings.map(function(w) {
			w = vocab.normalizeWarningId(w);
			return E('li', {}, [
				E('span', { 'class': vocab.warningClass(w) + ' key' }, w),
				vocab.warningText(w)
			]);
		}));
	} else {
		fmt.replaceChildren(refs.nssWarnings, [
			E('li', { 'style': 'opacity:.65' }, _('无 NSS 相关告警'))
		]);
	}
}

return baseclass.extend({
	build:  build,
	render: render,

	/* Exposed for validators / tests. */
	hasNssSignal: hasNssSignal
});
