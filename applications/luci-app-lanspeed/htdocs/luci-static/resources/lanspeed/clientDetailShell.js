'use strict';
'require baseclass';
'require lanspeed.theme as lsTheme';
'require lanspeed.clientDetailStyle as clientDetailStyle';

function buildShell(viewState) {
	var refs = {};
	var prefs = viewState.prefs || {};
	refs.sortHeaders = {};

	var sortableHeader = function(sortKey, label, attrs) {
		var thAttrs = Object.assign({
			'scope': 'col',
			'aria-sort': 'none'
		}, attrs || {});
		var button = E('button', {
			'type': 'button',
			'class': 'lanspeed-sort-button'
		}, [
			E('span', { 'class': 'lanspeed-sort-label' }, label),
			E('span', {
				'class': 'lanspeed-sort-indicator',
				'aria-hidden': 'true'
			}, '')
		]);
		var th = E('th', thAttrs, button);
		refs.sortHeaders[sortKey] = {
			th: th,
			button: button,
			label: label
		};
		button.addEventListener('click', function() {
			viewState.setSort(sortKey);
		});
		return th;
	};

	refs.back = E('button', {
		'type': 'button',
		'class': 'cbi-button lanspeed-connection-back'
	}, _('返回客户端列表'));
	refs.back.addEventListener('click', function() {
		viewState.back();
	});
	var breadcrumb = E('nav', {
		'class': 'lanspeed-connection-breadcrumb',
		'aria-label': _('当前位置')
	}, [
		refs.back,
		E('span', { 'class': 'lanspeed-connection-breadcrumb-current' },
			_('LAN Speed 状态 / 客户端连接详情'))
	]);

	refs.error = E('div', {
		'class': 'alert-message error lanspeed-connection-error',
		'role': 'alert',
		'aria-live': 'assertive',
		'hidden': 'hidden'
	}, [
		E('strong', {}, _('无法加载连接详情')),
		E('span', { 'class': 'lanspeed-connection-error-message' }, _('请稍后重试。'))
	]);

	refs.clientName = E('h4', {
		'class': 'lanspeed-connection-client-name'
	}, _('正在加载客户端身份…'));
	var clientHeading = E('div', {
		'class': 'lanspeed-connection-client-heading'
	}, [
		E('span', {
			'class': 'lanspeed-connection-client-avatar',
			'aria-hidden': 'true'
		}, E('span', {
			'class': 'lanspeed-connection-client-device'
		})),
		E('div', { 'class': 'lanspeed-connection-client-title' }, [
			E('span', {
				'class': 'lanspeed-connection-client-kicker'
			}, _('LAN 客户端')),
			refs.clientName
		])
	]);
	refs.clientMeta = E('div', {
		'class': 'lanspeed-connection-client-meta',
		'aria-label': _('客户端网络身份')
	}, E('span', {
		'class': 'lanspeed-connection-meta-empty'
	}, _('MAC 与 IP 信息将在加载后显示')));
	refs.connectionState = E('span', {
		'class': 'label lanspeed-connection-state'
	}, _('等待数据'));

	refs.summaryTargets = E('span', {
		'class': 'lanspeed-connection-summary-value'
	}, '—');
	refs.summaryConnections = E('span', {
		'class': 'lanspeed-connection-summary-value'
	}, '—');
	refs.summaryUpdated = E('span', {
		'class': 'lanspeed-connection-summary-value'
	}, '—');
	refs.summary = E('div', {
		'class': 'lanspeed-connection-summary',
		'aria-label': _('连接摘要')
	}, [
		E('h4', { 'class': 'lanspeed-connection-summary-title' }, _('连接摘要')),
		E('div', { 'class': 'lanspeed-connection-summary-item' }, [
			E('span', { 'class': 'lanspeed-connection-summary-label' }, _('目标 IP 数')),
			refs.summaryTargets
		]),
		E('div', { 'class': 'lanspeed-connection-summary-item' }, [
			E('span', { 'class': 'lanspeed-connection-summary-label' }, _('连接数')),
			refs.summaryConnections
		]),
		E('div', { 'class': 'lanspeed-connection-summary-item' }, [
			E('span', { 'class': 'lanspeed-connection-summary-label' }, _('更新时间')),
			refs.summaryUpdated
		])
	]);

	var identityCard = E('div', {
		'class': 'cbi-section lanspeed-connection-identity-card'
	}, [
		E('div', { 'class': 'lanspeed-header' }, [
			E('h3', {}, _('客户端身份')),
			E('span', { 'class': 'spacer' }),
			refs.connectionState
		]),
		E('div', { 'class': 'lanspeed-body' }, [
			E('div', { 'class': 'lanspeed-connection-identity' }, [
				E('div', { 'class': 'lanspeed-connection-client' }, [
					clientHeading,
					refs.clientMeta
				]),
				refs.summary
			])
		])
	]);

	refs.protocolAll = E('button', {
		'type': 'button',
		'class': 'cbi-button lanspeed-connection-protocol',
		'aria-pressed': 'true'
	}, _('全部'));
	refs.protocolAll.addEventListener('click', function() {
		viewState.setProtocol('all');
	});
	refs.protocolTcp = E('button', {
		'type': 'button',
		'class': 'cbi-button lanspeed-connection-protocol',
		'aria-pressed': 'false'
	}, 'TCP');
	refs.protocolTcp.addEventListener('click', function() {
		viewState.setProtocol('tcp');
	});
	refs.protocolUdp = E('button', {
		'type': 'button',
		'class': 'cbi-button lanspeed-connection-protocol',
		'aria-pressed': 'false'
	}, 'UDP');
	refs.protocolUdp.addEventListener('click', function() {
		viewState.setProtocol('udp');
	});

	refs.filter = E('input', {
		'type': 'search',
		'class': 'cbi-input-text lanspeed-connection-filter-input',
		'aria-label': _('搜索连接'),
		'placeholder': _('搜索目标 IP、端口或国家/地区')
	});
	refs.filter.addEventListener('input', function(ev) {
		viewState.setFilter(ev.target.value);
	});
	refs.intervalSel = E('select', {
		'class': 'cbi-input-select lanspeed-connection-interval',
		'aria-label': _('刷新')
	}, (viewState.refreshChoices || []).map(function(choice) {
		var attrs = { 'value': String(choice.value) };
		if (Number(choice.value) === Number(viewState.prefs.refreshMs))
			attrs.selected = 'selected';
		return E('option', attrs, choice.label);
	}));
	refs.intervalSel.addEventListener('change', function(ev) {
		viewState.setRefreshMs(ev.target.value);
	});
	refs.refresh = E('button', {
		'type': 'button',
		'class': 'cbi-button lanspeed-connection-refresh'
	}, _('立即刷新'));
	refs.refresh.addEventListener('click', function(event) {
		if (event && event.preventDefault) event.preventDefault();
		if (event && event.stopPropagation) event.stopPropagation();
		viewState.reload();
	});
	refs.pause = E('button', {
		'type': 'button',
		'class': 'cbi-button lanspeed-connection-pause'
	}, prefs.paused ? _('恢复') : _('暂停'));
	refs.pause.addEventListener('click', function(event) {
		if (event && event.preventDefault) event.preventDefault();
		if (event && event.stopPropagation) event.stopPropagation();
		viewState.setPaused();
	});
	refs.pagePrev = E('button', {
		'type': 'button',
		'class': 'cbi-button lanspeed-connection-page-button',
		'title': _('上一页'),
		'aria-label': _('上一页')
	}, '‹');
	refs.pagePrev.addEventListener('click', function() {
		viewState.setPage(-1);
	});
	refs.pageStatus = E('span', {
		'class': 'lanspeed-connection-page-status',
		'aria-live': 'polite'
	}, '—');
	refs.pageNext = E('button', {
		'type': 'button',
		'class': 'cbi-button lanspeed-connection-page-button',
		'title': _('下一页'),
		'aria-label': _('下一页')
	}, '›');
	refs.pageNext.addEventListener('click', function() {
		viewState.setPage(1);
	});
	refs.pager = E('div', {
		'class': 'lanspeed-connection-pager',
		'hidden': 'hidden',
		'role': 'navigation',
		'aria-label': _('连接分页')
	}, [ refs.pagePrev, refs.pageStatus, refs.pageNext ]);

	var toolbar = E('div', {
		'class': 'lanspeed-toolbar lanspeed-connection-toolbar'
	}, [
		E('div', {
			'class': 'lanspeed-toolbar-left lanspeed-connection-toolbar-left'
		}, [
			E('div', {
				'class': 'lanspeed-connection-protocols',
				'role': 'group',
				'aria-label': _('协议筛选')
			}, [
				E('span', { 'class': 'lanspeed-connection-protocol-label' }, _('协议')),
				refs.protocolAll,
				refs.protocolTcp,
				refs.protocolUdp
			]),
			E('div', {
				'class': 'lanspeed-toolbar-filter lanspeed-connection-filter'
			}, refs.filter)
		]),
		E('div', {
			'class': 'lanspeed-toolbar-right lanspeed-connection-toolbar-right'
		}, [
			E('label', {
				'class': 'lanspeed-refresh-control lanspeed-connection-interval-control'
			}, [ _('刷新'), refs.intervalSel ]),
			refs.refresh,
			refs.pause
		])
	]);

	refs.tbody = E('tbody', {});
	refs.table = E('table', {
		'class': 'lanspeed-table lanspeed-connection-table',
		'aria-label': _('客户端连接列表')
	}, [
		E('thead', {}, E('tr', {}, [
			sortableHeader('remote_ip', _('目标 IP')),
			sortableHeader('location', _('国家/地区')),
			sortableHeader('remote_port', _('目标端口')),
			sortableHeader('protocol', _('协议')),
			sortableHeader('state', _('状态')),
			sortableHeader('tx', _('上行'), { 'class': 'num' }),
			sortableHeader('rx', _('下行'), { 'class': 'num' }),
			sortableHeader('count', _('连接数'), { 'class': 'num' })
		])),
		refs.tbody
	]);
	refs.empty = E('div', {
		'class': 'lanspeed-connection-empty',
		'role': 'status',
		'aria-live': 'polite',
		'hidden': 'hidden'
	}, _('暂无连接'));
	refs.footer = E('p', {
		'class': 'lanspeed-connection-footer',
		'aria-live': 'polite'
	}, _('连接数据加载后会显示来源、刷新间隔和 IP 位置说明。'));

	var connectionsCard = E('div', {
		'class': 'cbi-section lanspeed-connections-card'
	}, [
		E('div', { 'class': 'lanspeed-header' }, E('h3', {}, _('当前连接'))),
			E('div', { 'class': 'lanspeed-body' }, [
				toolbar,
				refs.table,
				refs.pager,
				refs.empty,
				refs.footer
		])
	]);

	var root = E('div', {
		'class': 'cbi-map lanspeed-root lanspeed-connection-detail'
	}, [
		E('style', {}, clientDetailStyle.CSS),
		breadcrumb,
		refs.error,
		identityCard,
		connectionsCard
	]);

	lsTheme.applyRoot(root);

	return { root: root, refs: refs };
}

return baseclass.extend({
	buildShell: buildShell
});
