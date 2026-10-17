'use strict';
'require baseclass';
'require lanspeed.theme as lsTheme';
'require lanspeed.diagnosticsStyle as diagnosticsStyle';

function sectionHeader(title, summary, extraClass, actions) {
	return E('div', { 'class': 'lanspeed-header ' + (extraClass || '') }, [
		E('h3', {}, title),
		summary,
		E('span', { 'class': 'spacer' }),
	].concat(actions || []));
}

function fact(refs, key, label) {
	refs[key + 'Fact'] = E('div', {
		'class': 'lanspeed-diagnostic-fact',
		'data-state': 'loading'
	}, [
		E('dt', { 'class': 'lanspeed-diagnostic-fact-label' }, label),
		refs[key + 'Value'] = E('dd', { 'class': 'lanspeed-diagnostic-fact-value' }, _('检查中…')),
		refs[key + 'Meta'] = E('dd', { 'class': 'lanspeed-diagnostic-fact-meta' }, '')
	]);
	return refs[key + 'Fact'];
}

function tableHead(columns) {
	return E('thead', {}, [ E('tr', {}, columns.map(function(column) {
		return E('th', { 'scope': 'col' }, column);
	})) ]);
}

function buildSummarySection(refs, viewState) {
	refs.summary = E('span', {
		'class': 'label lanspeed-diagnostics-summary',
		'role': 'status',
		'aria-live': 'polite',
		'aria-atomic': 'true'
	}, _('检查中'));
	refs.checked = E('span', { 'class': 'meta lanspeed-diagnostics-checked' }, _('尚未完成检查'));
	refs.btnRefresh = E('button', {
		'type': 'button',
		'class': 'cbi-button cbi-button-action lanspeed-diagnostics-refresh',
		'disabled': 'disabled',
		'aria-label': _('重新运行全部诊断')
	}, _('重新检查'));
	refs.btnRefresh.addEventListener('click', function(event) {
		if (event && event.preventDefault) event.preventDefault();
		viewState.reload();
	});
	refs.btnRestart = E('button', {
		'type': 'button',
		'class': 'cbi-button cbi-button-action lanspeed-diagnostics-restart',
		'disabled': 'disabled',
		'aria-label': _('重启 LAN Speed 服务'),
		'aria-describedby': 'lanspeed-diagnostics-restart-feedback'
	}, _('重启服务'));
	refs.btnRestart.addEventListener('click', function(event) {
		if (event && event.preventDefault) event.preventDefault();
		viewState.restartService();
	});
	refs.btnCopy = E('button', {
		'type': 'button',
		'class': 'cbi-button cbi-button-action lanspeed-diagnostics-copy',
		'disabled': 'disabled',
		'aria-describedby': 'lanspeed-diagnostics-report-feedback'
	}, _('复制脱敏报告'));
	refs.btnCopy.addEventListener('click', function(event) {
		if (event && event.preventDefault) event.preventDefault();
		viewState.copyReport();
	});
	refs.reportFeedback = E('span', {
		'id': 'lanspeed-diagnostics-report-feedback',
		'class': 'lanspeed-diagnostics-report-feedback',
		'role': 'status',
		'aria-live': 'polite'
	}, '');

	refs.restartFeedbackTitle = E('strong', {}, '');
	refs.restartFeedbackText = E('span', {}, '');
	refs.restartFeedback = E('div', {
		'id': 'lanspeed-diagnostics-restart-feedback',
		'class': 'lanspeed-diagnostics-state lanspeed-diagnostics-restart-feedback',
		'data-state': 'loading',
		'role': 'status',
		'aria-live': 'polite',
		'aria-atomic': 'true',
		'hidden': 'hidden'
	}, [ refs.restartFeedbackTitle, refs.restartFeedbackText ]);

	refs.pageNoticeTitle = E('strong', {}, _('正在运行诊断'));
	refs.pageNoticeText = E('span', {}, _('正在检查服务和采集状态。'));
	refs.pageNotice = E('div', {
		'class': 'lanspeed-diagnostics-state',
		'data-state': 'loading',
		'role': 'status',
		'aria-live': 'polite',
		'aria-atomic': 'true'
	}, [ refs.pageNoticeTitle, refs.pageNoticeText ]);

	refs.errorList = E('ul', { 'class': 'lanspeed-diagnostics-error-list' });
	refs.errorSummary = E('strong', {}, _('数据读取失败'));
	refs.errorDetails = E('div', {
		'class': 'lanspeed-diagnostics-error-details',
		'role': 'alert',
		'hidden': 'hidden'
	}, [ refs.errorSummary, refs.errorList ]);

	refs.summaryFacts = E('dl', { 'class': 'lanspeed-diagnostics-facts' }, [
		fact(refs, 'service', _('服务状态')),
		fact(refs, 'collection', _('数据采集')),
		fact(refs, 'connections', _('连接详情')),
		fact(refs, 'version', _('版本'))
	]);

	return E('section', { 'class': 'cbi-section lanspeed-diagnostics-summary-section' }, [
		sectionHeader(_('运行诊断'), refs.summary, 'lanspeed-diagnostics-primary-header', [
			refs.checked,
			refs.btnRestart,
			refs.btnCopy,
			refs.btnRefresh
		]),
		E('div', { 'class': 'lanspeed-body lanspeed-diagnostics-summary-body' }, [
			refs.restartFeedback,
			refs.pageNotice,
			refs.errorDetails,
			refs.summaryFacts,
			refs.reportFeedback
		])
	]);
}

function buildHealthSection(refs) {
	refs.healthSummary = E('span', { 'class': 'sum lanspeed-diagnostics-health-summary' }, _('等待接口数据'));
	refs.interfacesBody = E('tbody', {});
	refs.healthSection = E('section', { 'class': 'cbi-section lanspeed-diagnostics-health-section' }, [
		sectionHeader(_('接口状态'), refs.healthSummary, '', []),
		E('div', { 'class': 'lanspeed-body lanspeed-diagnostics-health-body' }, [
			E('div', { 'class': 'lanspeed-diagnostics-table-wrap' }, [
				E('table', { 'class': 'table lanspeed-diagnostics-health-table' }, [
					tableHead([ _('接口'), _('角色'), _('状态') ]),
					refs.interfacesBody
				])
			])
		])
	]);
	return refs.healthSection;
}

function buildSupportSection(refs) {
	refs.alertSummary = E('span', { 'class': 'sum lanspeed-diagnostics-alert-summary' }, _('检查中'));
	refs.importantWarnings = E('ul', {
		'class': 'lanspeed-diagnostic-alerts lanspeed-diagnostic-important-alerts'
	});
	return E('section', { 'class': 'cbi-section lanspeed-diagnostics-support-section' }, [
		sectionHeader(_('需要关注'), refs.alertSummary, '', []),
		E('div', { 'class': 'lanspeed-body lanspeed-diagnostics-support-body' }, [ refs.importantWarnings ])
	]);
}

function buildShell(viewState) {
	var refs = {};
	var root = E('div', {
		'class': 'cbi-map lanspeed-root lanspeed-diagnostics-root',
		'aria-busy': 'true'
	}, [
		E('style', {}, diagnosticsStyle.CSS),
		buildSummarySection(refs, viewState),
		buildSupportSection(refs),
		buildHealthSection(refs)
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
