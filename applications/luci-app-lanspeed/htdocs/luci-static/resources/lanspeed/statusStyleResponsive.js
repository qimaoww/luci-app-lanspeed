'use strict';
'require baseclass';

/*
 * Responsive rules for the realtime status page.
 *
 * The client list stays a fixed-track table only while its own card is wide
 * enough to show every column; below that each row becomes a card. The switch
 * follows the card width (a container query), so a LuCI sidebar or a narrow
 * theme column behaves like a narrow phone. Engines without container queries
 * use the viewport fallback.
 */
var CARD_MAX = '64rem';

var CARD_RULES = [
	'.lanspeed-clients-table{display:block;min-width:0;table-layout:auto}',
	'.lanspeed-clients-table thead{display:none}',
	'.lanspeed-clients-table tbody{display:block}',
	/* Identity and address precede labelled traffic and connection readings. */
	'.lanspeed-root .lanspeed-clients-table tbody>tr{display:grid;line-height:1.4;',
	'  grid-template-columns:repeat(4,minmax(0,1fr));',
	'  column-gap:12px;row-gap:8px;padding:10px 0;',
	'  border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-clients-table tbody>tr:last-child{border-bottom:0}',
	'.lanspeed-root .lanspeed-clients-table tbody td{display:block;min-width:0;padding:0;border:0;',
	'  text-align:left;white-space:normal;overflow-wrap:anywhere}',
	'.lanspeed-root .lanspeed-clients-table tbody td.num{text-align:left}',
	'.lanspeed-root .lanspeed-clients-table td[data-label]::before{content:attr(data-label);display:block;',
	'  margin-bottom:1px;font-size:12px;font-weight:600;letter-spacing:.04em;',
	'  color:var(--lanspeed-text-subtle)}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-name{grid-area:1/1/2/5}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-mac{grid-area:2/1/3/5}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-mac[data-label]::before{display:none}',
	'.lanspeed-root .lanspeed-clients-table .lanspeed-client-mac-value{display:block;font-size:13px;',
	'  white-space:normal;overflow-wrap:anywhere}',


	/* Two directions per row, then totals and transport counts. */
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-rate-rx{grid-area:3/1/4/3}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-rate-tx{grid-area:3/3/4/5}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-total-rx{grid-area:4/1/5/3}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-total-tx{grid-area:4/3/5/5}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-tcp-cell{grid-area:5/1/6/3}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-udp-cell{grid-area:5/3/6/5}',
	'.lanspeed-root .lanspeed-clients-table[data-client-totals="hidden"] td.lanspeed-client-tcp-cell{grid-row:4}',
	'.lanspeed-root .lanspeed-clients-table[data-client-totals="hidden"] td.lanspeed-client-udp-cell{grid-row:4}',
].join('\n');

var NARROW_RULES = [
	'.lanspeed-root .lanspeed-clients-table tbody>tr{padding:9px 0;row-gap:7px}',
	'.lanspeed-root .lanspeed-clients-table .lanspeed-client-rate,',
	'.lanspeed-root .lanspeed-clients-table .lanspeed-client-total{font-size:13px}'
].join('\n');

return baseclass.extend({
	CSS: [
		'.lanspeed-vendor-logo[data-vendor-logo="placeholder"]{background:none;box-shadow:none}',
		'.lanspeed-root .lanspeed-connection-link{white-space:normal;overflow-wrap:anywhere}',
		'.lanspeed-list-help{font-size:12px;margin:8px 0 0;border-top:1px solid var(--lanspeed-border);padding-top:4px;color:var(--lanspeed-text-muted)}',
		'.lanspeed-list-help summary{cursor:pointer;min-height:32px;display:flex;align-items:center}',
		'.lanspeed-list-help p{line-height:1.6;margin:0 0 8px}',
		'.lanspeed-list-help summary:focus-visible{outline:2px solid var(--lanspeed-focus-color)}',
		'@media(pointer:coarse){.lanspeed-root :is(button,select,input[type=search],summary,.lanspeed-active-only),',
		'.lanspeed-root .lanspeed-toolbar :is(select,input[type=search]),',
		'.lanspeed-root .lanspeed-pagination select.lanspeed-page-size{min-height:44px!important;height:44px!important}',
		'.lanspeed-root .lanspeed-page-button{width:44px}',
		'.lanspeed-root .lanspeed-connection-link{min-height:44px;display:flex;align-items:center}}',
		'.lanspeed-clients-card>.lanspeed-body{container:lanspeed-clients/inline-size}',

		'@container lanspeed-clients (max-width:' + CARD_MAX + '){' + CARD_RULES + '}',

	/* The toolbar follows the same breakpoint as the table: once rows become
	 * cards the controls stack into a two-column grid instead of wrapping
	 * unevenly. */
	'@container lanspeed-clients (max-width:' + CARD_MAX + '){',
	'.lanspeed-root .lanspeed-toolbar{flex-direction:column;align-items:stretch;gap:12px}',
	'.lanspeed-root .lanspeed-toolbar-left{flex:0 0 auto;width:100%;flex-wrap:wrap;gap:8px}',
	'.lanspeed-root .lanspeed-toolbar-right{flex:0 0 auto;width:100%;display:grid;',
	'  grid-template-columns:minmax(0,12rem) 7rem;gap:8px;justify-content:start}',
	'.lanspeed-root .lanspeed-toolbar-filter{flex:1 1 auto;min-width:0}',
	'.lanspeed-root .lanspeed-toolbar-left input[type="search"]{max-width:none;width:100%;min-width:0}',
	'.lanspeed-root .lanspeed-toolbar-right>label{display:flex;align-items:center;',
	'  justify-content:space-between;gap:8px;min-width:0;margin:0}',
	'.lanspeed-root .lanspeed-sort-control{grid-column:1;order:1}',
	'.lanspeed-root .lanspeed-unit-control{grid-column:2;order:2}',
	'.lanspeed-root .lanspeed-toolbar-right select{flex:1 1 auto;width:auto;min-width:0;',
	'  max-width:none}}',

	/* Tablets keep the four traffic readings together, then connection counts. */
	'@container lanspeed-clients (min-width:34rem) and (max-width:' + CARD_MAX + '){',
	'.lanspeed-root .lanspeed-clients-table tbody>tr{grid-template-columns:repeat(8,minmax(0,1fr));row-gap:10px}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-name{grid-area:1/1/2/9}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-mac{grid-area:2/1/3/9}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-rate-rx{grid-area:3/1/4/3}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-rate-tx{grid-area:3/3/4/5}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-total-rx{grid-area:3/5/4/7}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-total-tx{grid-area:3/7/4/9}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-tcp-cell{grid-area:4/1/5/3}',
	'.lanspeed-root .lanspeed-clients-table td.lanspeed-client-udp-cell{grid-area:4/3/5/5}',
	'.lanspeed-root .lanspeed-clients-table[data-client-totals="hidden"] td.lanspeed-client-tcp-cell{grid-area:3/5/4/7}',
	'.lanspeed-root .lanspeed-clients-table[data-client-totals="hidden"] td.lanspeed-client-udp-cell{grid-area:3/7/4/9}}',

	/* Theme-scoped card tweaks: Aurora keeps its generous padding, Argon drops
	 * its row stripe inside cards, Bootstrap strengthens the card border. */
	'@container lanspeed-clients (max-width:' + CARD_MAX + '){',
	'.lanspeed-theme-aurora .lanspeed-clients-table tbody>tr{padding:12px 0}',
	'.lanspeed-theme-argon .lanspeed-clients-table tbody>tr:nth-child(even){background:transparent}',
	'.lanspeed-theme-bootstrap .lanspeed-clients-table tbody>tr{border-bottom-color:var(--lanspeed-border-strong)}}',

		/* Very narrow phones: the readings spread over two lines so the rate
		 * never truncates and the actions stay at full size. */
		'@container lanspeed-clients (max-width:26em){' + NARROW_RULES + '}',

		/* Older engines without container queries fall back on viewport width. */
		'@supports not (container-type:inline-size){',
		'@media (max-width:1200px){' + CARD_RULES + '}}',

		'@media (max-width:1100px){',
		'.lanspeed-root .lanspeed-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}',
		'.lanspeed-root .lanspeed-metric{padding-left:14px}',
		'.lanspeed-root .lanspeed-metric:nth-child(odd){padding-left:0;',
		'  border-left:0}',
		'.lanspeed-root .lanspeed-metric:nth-child(even){border-left:1px solid var(--lanspeed-border)}}',

		'@media (max-width:700px){',
		'.lanspeed-root .lanspeed-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}',
		'.lanspeed-root .lanspeed-metric{padding-left:12px}',
		'.lanspeed-root .lanspeed-metric:nth-child(odd){padding-left:0;',
		'  border-left:0}',
		'.lanspeed-root .lanspeed-metric:nth-child(even){border-left:1px solid var(--lanspeed-border)}',
		'.lanspeed-root .lanspeed-status-bar{flex-wrap:wrap;align-items:flex-start}',
		'.lanspeed-root .lanspeed-status-title{flex:1 1 100%}',
		'.lanspeed-root .lanspeed-status-actions{flex:1 1 100%;justify-content:stretch}',
		'.lanspeed-root .lanspeed-status-actions>.cbi-button{flex:1 1 0;white-space:nowrap;',
		'  min-width:0}',
		'.lanspeed-root .lanspeed-toolbar{flex-direction:column;align-items:stretch;gap:12px}',
		'.lanspeed-root .lanspeed-clients-card>.lanspeed-body{overflow-x:hidden}',
		'.lanspeed-root .lanspeed-toolbar-left{flex-wrap:wrap;gap:8px}',
		'.lanspeed-root .lanspeed-toolbar-right{flex:1 1 100%;display:grid;',
		'  grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);gap:8px}',
		'.lanspeed-root .lanspeed-toolbar-filter{flex:1 1 auto;min-width:0}',
		'.lanspeed-root .lanspeed-toolbar-left input[type="search"]{max-width:none;width:100%;min-width:0}',
		'.lanspeed-root .lanspeed-toolbar-right>label{display:flex;align-items:center;',
		'  justify-content:space-between;gap:8px;min-width:0;margin:0}',
		'.lanspeed-root .lanspeed-sort-control{grid-column:1;order:1}',
		'.lanspeed-root .lanspeed-unit-control{grid-column:2;order:2}',
		'.lanspeed-root .lanspeed-toolbar-right select{flex:1 1 auto;width:auto;min-width:0;max-width:none}',
		'.lanspeed-root .lanspeed-pagination{flex-wrap:wrap;gap:8px}',
		'.lanspeed-root .lanspeed-page-actions{margin-left:auto}',
		'.lanspeed-root .lanspeed-ifaces-table tbody>tr{display:grid;',
		'  grid-template-columns:minmax(0,1fr) minmax(0,1fr);column-gap:8px;row-gap:2px}',
		'.lanspeed-root .lanspeed-ifaces-table tbody td{border:0;padding:2px 0}',
		'.lanspeed-root .lanspeed-ifaces-table tbody td:first-child{grid-column:1/-1}}',

		'@media (max-width:480px){',
		/* A one-line hint keeps the four readings on one rhythm; the full text
		 * stays reachable through the metric title. */
		'.lanspeed-root .lanspeed-stat-hint{white-space:normal;word-break:keep-all;overflow-wrap:anywhere}',
		'.lanspeed-root .lanspeed-stat-value{font-size:16px}',
		'.lanspeed-root .lanspeed-metric{padding:6px 10px;justify-content:flex-start}',
		'.lanspeed-root .lanspeed-metric:nth-child(odd){padding-left:0}',
		'.lanspeed-root .lanspeed-status-title h3{font-size:16px}',
		/* First screen belongs to the readings and the client list. */

		'.lanspeed-root .lanspeed-status-actions .lanspeed-refresh-control{flex:0 0 auto}',
		'.lanspeed-root .lanspeed-status-actions .lanspeed-refresh-select{width:4.5rem}',
		'.lanspeed-root .lanspeed-toolbar-left{flex-wrap:nowrap;gap:8px}',
		'.lanspeed-root .lanspeed-toolbar-filter{flex:1 1 auto;min-width:0;max-width:none}',
		'.lanspeed-root .lanspeed-active-only{flex:0 0 auto}',
		/* The selects carry aria-labels; hiding the visible labels gives the
		 * longer sort wording room without another toolbar row. */
		'.lanspeed-root .lanspeed-toolbar-right .lanspeed-control-label{display:none}}',
		/* Share the same two-column gutter with the client readings. */
		'@media(max-width:700px){',
		'.lanspeed-root .lanspeed-metrics{column-gap:12px;row-gap:16px}',
		'.lanspeed-root .lanspeed-metric:nth-child(n){padding:0;min-height:0;position:relative;',
		'justify-content:flex-start;border-left:0}',
		'.lanspeed-root .lanspeed-metric:nth-child(even)::before{content:"";position:absolute;',
		'left:-6px;top:0;bottom:0;border-left:1px solid var(--lanspeed-border)}}'
	].join('\n')
});
