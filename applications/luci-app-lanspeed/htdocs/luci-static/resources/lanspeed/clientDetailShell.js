'use strict';
'require baseclass';
'require lanspeed.theme as lsTheme';
'require lanspeed.clientDetailStyle as clientDetailStyle';

function buildShell(viewState) {
	var refs = {};

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
	refs.clientMeta = E('p', {
		'class': 'lanspeed-connection-client-meta'
	}, _('MAC 与 IP 信息将在加载后显示'));
	refs.connectionState = E('span', {
		'class': 'label lanspeed-connection-state'
	}, _('连接状态：等待加载'));

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
					refs.clientName,
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
		'placeholder': _('搜索目标 IP 或端口')
	});
	refs.filter.addEventListener('input', function(ev) {
		viewState.setFilter(ev.target.value);
	});
	refs.refresh = E('button', {
		'type': 'button',
		'class': 'cbi-button lanspeed-connection-refresh'
	}, _('立即刷新'));
	refs.refresh.addEventListener('click', function() {
		viewState.reload();
	});

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
		}, refs.refresh)
	]);

	refs.tbody = E('tbody', {});
	refs.table = E('table', {
		'class': 'lanspeed-table lanspeed-connection-table',
		'aria-label': _('客户端连接列表')
	}, [
		E('thead', {}, E('tr', {}, [
			E('th', { 'scope': 'col' }, _('目标 IP')),
			E('th', { 'scope': 'col' }, _('目标端口')),
			E('th', { 'scope': 'col' }, _('协议')),
			E('th', { 'scope': 'col' }, _('状态')),
			E('th', { 'scope': 'col' }, _('连接数'))
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
	}, _('连接数据将在加载后显示。'));

	var connectionsCard = E('div', {
		'class': 'cbi-section lanspeed-connections-card'
	}, [
		E('div', { 'class': 'lanspeed-header' }, E('h3', {}, _('当前连接'))),
		E('div', { 'class': 'lanspeed-body' }, [
			toolbar,
			refs.table,
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
