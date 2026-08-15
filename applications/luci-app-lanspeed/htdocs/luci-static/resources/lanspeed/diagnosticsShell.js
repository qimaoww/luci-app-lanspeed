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

function stage(refs, key, title) {
	refs[key + 'Stage'] = E('li', {
		'class': 'lanspeed-diagnostic-stage',
		'data-state': 'loading'
	}, [
		E('div', { 'class': 'lanspeed-diagnostic-stage-heading' }, [
			E('h4', {}, title),
			refs[key + 'Badge'] = E('span', {
				'class': 'label lanspeed-diagnostic-stage-badge',
				'aria-live': 'polite'
			}, _('检查中'))
		]),
		refs[key + 'Value'] = E('div', { 'class': 'lanspeed-diagnostic-stage-value' }, _('等待数据')),
		refs[key + 'Description'] = E('p', { 'class': 'lanspeed-diagnostic-stage-description' }, ''),
		refs[key + 'Meta'] = E('p', { 'class': 'lanspeed-diagnostic-stage-meta' }, ''),
		refs[key + 'Evidence'] = E('dl', { 'class': 'lanspeed-diagnostic-stage-evidence' })
	]);
	return refs[key + 'Stage'];
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
	refs.pageNoticeText = E('span', {}, _('正在读取服务、采集链路和数据接口。'));
	refs.pageNotice = E('div', {
		'class': 'lanspeed-diagnostics-state',
		'data-state': 'loading',
		'role': 'status',
		'aria-live': 'polite',
		'aria-atomic': 'true'
	}, [ refs.pageNoticeTitle, refs.pageNoticeText ]);

	refs.errorList = E('ul', { 'class': 'lanspeed-diagnostics-error-list' });
	refs.errorSummary = E('strong', {}, _('RPC 错误'));
	refs.errorDetails = E('div', {
		'class': 'lanspeed-diagnostics-error-details',
		'role': 'alert',
		'hidden': 'hidden'
	}, [ refs.errorSummary, refs.errorList ]);

	refs.summaryFacts = E('dl', { 'class': 'lanspeed-diagnostics-facts' }, [
		fact(refs, 'service', _('服务与 RPC')),
		fact(refs, 'collection', _('采集循环')),
		fact(refs, 'connections', _('连接详情')),
		fact(refs, 'version', _('版本一致性'))
	]);

	return E('section', { 'class': 'cbi-section lanspeed-diagnostics-summary-section' }, [
		sectionHeader(_('运行诊断'), refs.summary, 'lanspeed-diagnostics-primary-header', [
			refs.checked,
			refs.btnRestart,
			refs.btnRefresh
		]),
		E('div', { 'class': 'lanspeed-body lanspeed-diagnostics-summary-body' }, [
			refs.intro = E('p', { 'class': 'lanspeed-diagnostics-intro' },
				_('正在确认运行平台与采集链路。')),
			refs.restartFeedback,
			refs.pageNotice,
			refs.errorDetails,
			refs.summaryFacts
		])
	]);
}

function buildPipelineSection(refs) {
	refs.pipelineSummary = E('span', { 'class': 'sum lanspeed-diagnostics-pipeline-summary' }, _('等待精准速率证据'));
	refs.pipeline = E('ol', { 'class': 'lanspeed-diagnostics-pipeline' }, [
		stage(refs, 'rate', _('总速率')),
		stage(refs, 'edge', _('接入归属')),
		stage(refs, 'classification', _('NSS / CPU 分类'))
	]);
	var section = E('section', { 'class': 'cbi-section lanspeed-diagnostics-pipeline-section' }, [
		sectionHeader(_('精准速率'), refs.pipelineSummary, '', []),
		E('div', { 'class': 'lanspeed-body lanspeed-diagnostics-pipeline-body' }, [ refs.pipeline ])
	]);
	refs.pipelineSection = section;
	return section;
}

function buildControlSection(refs) {
	refs.controlSummary = E('span', { 'class': 'sum lanspeed-diagnostics-control-summary' }, _('等待 NSS 控制证据'));
	refs.controlPipeline = E('ol', { 'class': 'lanspeed-diagnostics-pipeline lanspeed-diagnostics-control-pipeline' }, [
		stage(refs, 'controlCapability', _('控制能力')),
		stage(refs, 'controlPath', _('混合路径证明')),
		stage(refs, 'controlQueue', _('聚合整形队列')),
		stage(refs, 'controlBlock', _('互联网禁用'))
	]);
	var section = E('section', { 'class': 'cbi-section lanspeed-diagnostics-control-section' }, [
		sectionHeader(_('NSS 客户端控制'), refs.controlSummary, '', []),
		E('div', { 'class': 'lanspeed-body lanspeed-diagnostics-pipeline-body' }, [ refs.controlPipeline ])
	]);
	refs.controlSection = section;
	return section;
}

function buildHealthSection(refs) {
	refs.healthSummary = E('span', { 'class': 'sum lanspeed-diagnostics-health-summary' }, _('等待接口响应'));
	refs.interfacesBody = E('tbody', {});
	refs.subsystemsBody = E('tbody', {});
	refs.rpcBody = E('tbody', {});
	refs.rpcSummary = E('span', { 'class': 'sum lanspeed-diagnostics-rpc-summary' }, _('等待 RPC 响应'));
	refs.rpcDetails = E('details', { 'class': 'lanspeed-diagnostics-health-group lanspeed-diagnostics-rpc-group' }, [
		E('summary', {}, [
			E('span', { 'class': 'lanspeed-diagnostics-summary-label' }, _('RPC 请求明细')),
			refs.rpcSummary
		]),
		E('div', { 'class': 'lanspeed-diagnostics-table-wrap' }, [
			E('table', { 'class': 'table lanspeed-diagnostics-rpc-table' }, [
				E('caption', {}, _('本轮各诊断接口的独立结果')),
				tableHead([ _('接口'), _('状态'), _('数据时间'), _('结果') ]),
				refs.rpcBody
			])
		])
	]);

	var section = E('section', { 'class': 'cbi-section lanspeed-diagnostics-health-section' }, [
		sectionHeader(_('基础接口与 RPC 健康'), refs.healthSummary, '', []),
		E('div', { 'class': 'lanspeed-body lanspeed-diagnostics-health-body' }, [
				E('div', { 'class': 'lanspeed-diagnostics-health-group' }, [
					E('h4', {}, _('逻辑接口吞吐')),
					E('div', { 'class': 'lanspeed-diagnostics-table-wrap' }, [
						E('table', { 'class': 'table lanspeed-diagnostics-health-table' }, [
							E('caption', {}, _('逻辑接口健康与吞吐，仅用于交叉验证，不代表客户端总速率来源')),
						tableHead([ _('接口'), _('角色'), _('状态'), _('采样'), _('实时速率') ]),
						refs.interfacesBody
					])
				])
			]),
			E('div', { 'class': 'lanspeed-diagnostics-health-group lanspeed-diagnostics-subsystems-group' }, [
				E('h4', {}, _('运行子系统')),
				E('div', { 'class': 'lanspeed-diagnostics-table-wrap' }, [
					E('table', { 'class': 'table lanspeed-diagnostics-subsystem-table' }, [
						E('caption', {}, _('采集链路所依赖组件的健康状态')),
						tableHead([ _('组件'), _('状态'), _('诊断代码') ]),
						refs.subsystemsBody
					])
				])
			]),
			refs.rpcDetails
		])
	]);
	refs.healthSection = section;
	return section;
}

function buildSupportSection(refs, viewState) {
	refs.alertSummary = E('span', { 'class': 'sum lanspeed-diagnostics-alert-summary' }, _('等待告警数据'));
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
	refs.importantWarnings = E('ul', {
		'class': 'lanspeed-diagnostic-alerts lanspeed-diagnostic-important-alerts'
	});
	refs.environmentWarnings = E('ul', {
		'class': 'lanspeed-diagnostic-alerts lanspeed-diagnostic-environment-alerts'
	});
	refs.reportPreview = E('pre', {
		'class': 'lanspeed-diagnostics-report-preview',
		'tabindex': '0'
	}, _('报告将在诊断数据返回后生成。'));
	refs.reportFeedback = E('span', {
		'id': 'lanspeed-diagnostics-report-feedback',
		'class': 'lanspeed-diagnostics-report-feedback',
		'role': 'status',
		'aria-live': 'polite'
	}, _('报告仅包含白名单状态与计数，不复制客户端或接口身份。'));
	refs.reportDetails = E('details', {
		'class': 'lanspeed-diagnostics-report-details',
		'role': 'region',
		'aria-label': _('脱敏报告预览')
	}, [
		E('summary', {}, _('详细诊断报告（脱敏）')),
		refs.reportPreview
	]);

	return E('section', { 'class': 'cbi-section lanspeed-diagnostics-support-section' }, [
		sectionHeader(_('告警与支持报告'), refs.alertSummary, '', [ refs.btnCopy ]),
		E('div', { 'class': 'lanspeed-body lanspeed-diagnostics-support-body' }, [
			E('div', { 'class': 'lanspeed-diagnostics-alert-group' }, [
				E('h4', {}, _('严重与警告')),
				refs.importantWarnings
			]),
			E('div', { 'class': 'lanspeed-diagnostics-alert-group' }, [
				E('h4', {}, _('提示')),
				refs.environmentWarnings
			]),
			refs.reportDetails,
			refs.reportFeedback
		])
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
		buildHealthSection(refs),
		buildSupportSection(refs, viewState)
	]);
	refs.root = root;
	lsTheme.applyRoot(root);
	return { root: root, refs: refs };
}

return baseclass.extend({
	buildPipelineSection: buildPipelineSection,
	buildControlSection: buildControlSection,
	buildShell: function(viewState) {
		return buildShell(viewState);
	}
});
