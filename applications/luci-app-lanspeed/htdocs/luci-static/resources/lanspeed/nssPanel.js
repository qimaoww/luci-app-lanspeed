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
 * Visibility rule: only render when status.capabilities.nss === true OR
 * status.evidence.nss is a non-empty object.  Otherwise the whole section
 * is hidden.
 *
 * Default open state: open when ecm_offload_active or ppe_offload_active;
 * closed otherwise.  User may toggle manually; render() does NOT override
 * an existing <details open> attribute after first pass, only sets the
 * initial state.
 */

function hasNssSignal(status) {
	if (!status) return false;
	var caps = status.capabilities || {};
	if (caps.nss === true) return true;
	var ev = status.evidence && status.evidence.nss;
	if (ev && typeof ev === 'object') {
		for (var k in ev) {
			if (Object.prototype.hasOwnProperty.call(ev, k)) return true;
		}
	}
	/* any nss_* capability (even if base "nss" missing) still warrants showing */
	for (var key in caps) {
		if (key.indexOf('nss') === 0 && caps[key]) return true;
	}
	return false;
}

function isNssAccelerated(status) {
	var ev = status && status.evidence && status.evidence.nss;
	if (!ev) return false;
	return Boolean(ev.ecm_offload_active || ev.ppe_offload_active);
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
	refs.nssInitialized = false;

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

	/* First render: decide default open/close based on whether NSS is
	 * actively offloading.  Do NOT override on subsequent renders so the
	 * user's manual toggle sticks. */
	if (!refs.nssInitialized) {
		if (isNssAccelerated(status)) {
			refs.nssDetails.setAttribute('open', 'open');
		} else {
			refs.nssDetails.removeAttribute('open');
		}
		refs.nssInitialized = true;
	}

	var ev = (status.evidence && status.evidence.nss) || {};
	var caps = status.capabilities || {};
	var warnings = fmt.asArray(status.warnings);

	/* engine pill + summary */
	var engineLabel, engineCls;
	if (ev.ppe_offload_active) {
		engineLabel = _('PPE 活跃');
		engineCls = 'label label-danger';
	} else if (ev.ecm_offload_active) {
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
	var engine = ev.ppe_offload_active ? 'PPE'
	           : ev.ecm_offload_active ? 'ECM'
	           : '-';
	var directParts = [];
	if (ev.direct_enabled) {
		directParts.push(_('NSS-direct 已启用'));
	} else if (ev.direct_supported) {
		directParts.push(_('NSS-direct 可用'));
	} else {
		directParts.push(_('NSS-direct 未启用'));
	}
	if (ev.fallback_reason && !ev.direct_enabled)
		directParts.push(_('回退原因: %s').format(ev.fallback_reason));
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

	/* warnings subset: anything starting with "nss" plus nssifb_collect_rejected */
	var nssWarnings = warnings.filter(function(w) {
		return w.indexOf('nss') === 0 || w === 'nssifb_collect_rejected';
	});
	if (nssWarnings.length) {
		fmt.replaceChildren(refs.nssWarnings, nssWarnings.map(function(w) {
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
	hasNssSignal:     hasNssSignal,
	isNssAccelerated: isNssAccelerated
});
