'use strict';
'require baseclass';
'require lanspeed.theme as lsTheme';
'require lanspeed.diagnosticsStyle as diagnosticsStyle';

function diagnosticStatusCard(refs, key, title, initialText) {
	refs[key + 'Card'] = E('div', {
		'class': 'lanspeed-diagnostic-card',
		'data-state': 'pending'
	}, [
		E('div', { 'class': 'lanspeed-diagnostic-card-head' }, [
			E('span', { 'class': 'lanspeed-diagnostic-card-title' }, title),
			refs[key + 'Badge'] = E('span', {
				'class': 'label lanspeed-diagnostic-badge'
			}, _('检测中'))
		]),
		refs[key + 'Value'] = E('div', {
			'class': 'lanspeed-diagnostic-value'
		}, initialText),
		refs[key + 'Description'] = E('p', {
			'class': 'lanspeed-diagnostic-description'
		}, ''),
		refs[key + 'Meta'] = E('p', {
			'class': 'lanspeed-diagnostic-meta'
		}, '')
	]);

	return refs[key + 'Card'];
}

function buildShell(viewState) {
	var refs = {};

	refs.summary = E('span', {
		'class': 'label lanspeed-diagnostics-summary'
	}, _('检测中'));
	refs.meta = E('span', { 'class': 'lanspeed-diagnostics-meta' }, '');
	refs.errorPre = E('pre', {}, '');
	refs.errorBox = E('div', {
		'class': 'alert-message error lanspeed-diagnostics-error'
	}, [
		E('strong', {}, _('无法完成运行诊断')),
		refs.errorPre
	]);

	refs.btnRefresh = E('button', {
		'type': 'button',
		'class': 'cbi-button cbi-button-action lanspeed-diagnostics-refresh'
	}, _('重新检查'));
	refs.btnRefresh.addEventListener('click', function() {
		viewState.reload();
	});

	refs.importantWarnings = E('ul', { 'class': 'lanspeed-diagnostic-alerts' });
	refs.diagnosticAlertsTitle = E('h4', {
		'class': 'lanspeed-diagnostic-alerts-title'
	}, _('运行检查'));

	var card = E('div', { 'class': 'cbi-section' }, [
		E('div', { 'class': 'lanspeed-diagnostics-header' }, [
			E('h3', {}, _('运行诊断')),
			refs.summary,
			E('span', { 'class': 'spacer' }),
			refs.meta
		]),
		E('div', { 'class': 'lanspeed-diagnostics-body' }, [
			E('div', { 'class': 'lanspeed-diagnostics-toolbar' }, [
				E('p', { 'class': 'lanspeed-diagnostics-intro' },
					_('集中检查 LuCI 页面、lanspeedd 后端与 BPF 实时采集状态，只显示会影响测速结果的重要告警。')),
				refs.btnRefresh
			]),
			refs.errorBox,
			E('div', { 'class': 'lanspeed-diagnostic-grid' }, [
				diagnosticStatusCard(refs, 'plugin', _('插件状态'), _('正在检查界面组件')),
				diagnosticStatusCard(refs, 'backend', _('后端状态'), _('正在连接 lanspeedd')),
				diagnosticStatusCard(refs, 'bpf', _('BPF 状态'), _('正在检查实时采集'))
			]),
			E('div', { 'class': 'lanspeed-diagnostic-alerts-section' }, [
				refs.diagnosticAlertsTitle,
				refs.importantWarnings
			])
		])
	]);

	var root = E('div', { 'class': 'cbi-map lanspeed-root lanspeed-diagnostics-root' }, [
		E('style', {}, diagnosticsStyle.CSS),
		card
	]);

	lsTheme.applyRoot(root);
	return { root: root, refs: refs };
}

return baseclass.extend({
	buildShell: function(viewState) {
		return buildShell(viewState);
	}
});
