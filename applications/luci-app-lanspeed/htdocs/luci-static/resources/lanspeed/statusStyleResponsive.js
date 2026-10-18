'use strict';
'require baseclass';

/*
 * Responsive rules for the realtime status page.
 *
 * The client list stays a fixed-track table only while its own card is wide
 * enough to show every column; below that each row becomes a card. The switch
 * follows the card width (container query), so a LuCI sidebar or a narrow
 * theme column behaves like a narrow phone. Engines without container queries
 * use the viewport fallback.
 */
var CARD_MAX = '60em';

var CARD_RULES = [
	'.lanspeed-clients-table{display:block;min-width:0;table-layout:auto}',
	'.lanspeed-clients-table thead{display:none}',
	'.lanspeed-clients-table tbody{display:block}',
	'.lanspeed-clients-table tbody>tr{display:grid;',
	'  grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);',
	'  column-gap:16px;row-gap:6px;padding:10px 14px;',
	'  border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-clients-table tbody>tr:last-child{border-bottom:0}',
	'.lanspeed-clients-table tbody>tr:hover{background:transparent}',
	'.lanspeed-clients-table tbody td{display:block;min-width:0;padding:0;border:0;',
	'  text-align:left;white-space:normal;overflow-wrap:anywhere}',
	'.lanspeed-clients-table tbody td.num{text-align:left}',
	'.lanspeed-clients-table td[data-label]::before{content:attr(data-label);display:block;',
	'  margin-bottom:3px;font-size:10.5px;font-weight:500;letter-spacing:.02em;',
	'  color:var(--lanspeed-text-subtle)}',
	'.lanspeed-clients-table td.lanspeed-client-name{grid-area:1/1/2/2}',
	'.lanspeed-clients-table td.lanspeed-client-control{grid-area:1/2/2/3;justify-self:start}',
	'.lanspeed-clients-table td.lanspeed-client-mac{grid-area:2/1/3/3}',
	'.lanspeed-clients-table td.lanspeed-client-mac[data-label]::before{display:none}',
	'.lanspeed-clients-table td.lanspeed-client-value{grid-area:3/1/4/2}',
	'.lanspeed-clients-table td.lanspeed-client-total-cell{grid-area:3/2/4/3}',
	'.lanspeed-clients-table td.lanspeed-client-tcp-cell{grid-area:4/1/5/2}',
	'.lanspeed-clients-table td.lanspeed-client-udp-cell{grid-area:4/2/5/3}',
	'.lanspeed-clients-table td.lanspeed-client-count-cell{text-align:left;font-size:14px}',
	'.lanspeed-clients-table .lanspeed-connection-link,',
	'.lanspeed-clients-table .ipline,',
	'.lanspeed-clients-table .lanspeed-client-mac-value,',
	'.lanspeed-clients-table .lanspeed-client-vendor{white-space:normal;overflow-wrap:anywhere}',
	'.lanspeed-clients-table .lanspeed-client-traffic-stack{max-width:none;justify-items:start}',
	'.lanspeed-clients-table .lanspeed-client-rate,',
	'.lanspeed-clients-table .lanspeed-client-total{text-align:left}',
	'.lanspeed-clients-table .lanspeed-control-actions{flex-wrap:nowrap;gap:6px;justify-content:flex-start}',
	'.lanspeed-clients-table .lanspeed-control-button{height:28px;min-height:28px;padding:0 9px}'
].join('\n');

var RESPONSIVE_CSS = [
	'.lanspeed-clients-card>.lanspeed-body{container:lanspeed-clients/inline-size}',

	'@container lanspeed-clients (max-width:' + CARD_MAX + '){' + CARD_RULES + '}',
	'@container lanspeed-clients (max-width:40em){',
	'.lanspeed-clients-table tbody>tr{padding:12px}',
	'.lanspeed-clients-table td.lanspeed-client-value{grid-area:3/1/4/3}',
	'.lanspeed-clients-table td.lanspeed-client-total-cell{grid-area:4/1/5/3}',
	'.lanspeed-clients-table td.lanspeed-client-tcp-cell{grid-area:5/1/6/2}',
	'.lanspeed-clients-table td.lanspeed-client-udp-cell{grid-area:5/2/6/3}',
	'.lanspeed-clients-table .lanspeed-control-button{font-size:11px;padding:0 7px}',

	'}',

	/* Older engines without container queries fall back on viewport width. */
	'@supports not (container-type:inline-size){',
	'@media (max-width:700px){' + CARD_RULES + '}}',

	'@media (max-width:1100px){',
	'.lanspeed-root .lanspeed-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}',
	'.lanspeed-root .lanspeed-metric[data-metric="clients"]{border-left:0}',
	'.lanspeed-root .lanspeed-metric[data-metric="conns"]{border-left:1px solid var(--lanspeed-border)}}',

	/* A narrow window keeps the toolbar readable before the card fallback. */
	'@media (max-width:900px){.lanspeed-toolbar-right{width:100%;justify-content:flex-start}}',
	'.lanspeed-clients-card>.lanspeed-body{overflow-x:hidden}',
	'.lanspeed-theme-aurora .lanspeed-table-scroll,.lanspeed-theme-argon .lanspeed-table-scroll,',
	'.lanspeed-theme-bootstrap .lanspeed-table-scroll{overflow-x:auto;overscroll-behavior-x:contain}',

	'@media (max-width:700px){',
	'.lanspeed-header,.lanspeed-status-bar{align-items:flex-start}',
	'.lanspeed-status-actions{width:100%;justify-content:flex-end}',
	'.lanspeed-status-actions .cbi-button{flex:0 0 auto}',
	'.lanspeed-refresh-control{flex:0 0 auto}',
	'.lanspeed-refresh-select{flex:0 1 6.5em;width:auto;min-width:0}',
	'.lanspeed-toolbar-left{flex:1 1 100%;flex-wrap:wrap;gap:8px}',
	'.lanspeed-toolbar-filter{flex:1 1 100%;flex-wrap:wrap;gap:8px}',
	'.lanspeed-toolbar-filter input[type="search"]{flex:1 1 100%;max-width:none;min-width:0}',
	'.lanspeed-active-only{flex:0 0 auto;padding-left:0}',
	'.lanspeed-toolbar-right{flex:1 1 100%;flex-direction:column;align-items:stretch;gap:8px}',
	'.lanspeed-toolbar-right>label{display:flex;align-items:center;justify-content:space-between;',
	'  width:100%;gap:8px}',
	'.lanspeed-sort-control,.lanspeed-unit-control{flex:1 1 100%;min-width:0}',
	'.lanspeed-sort-select,.lanspeed-unit-select{flex:0 1 62%;width:auto;min-width:0}',
	'.lanspeed-connection-values{flex-wrap:wrap;gap:10px}',
	'.lanspeed-stat-hint{white-space:normal;overflow:visible;text-overflow:clip}',
	'.lanspeed-page-actions{flex:1 1 100%;justify-content:space-between}',
	'.lanspeed-page-summary{flex:1 1 auto}',

	/* Interface throughput: name across, four labelled values in a 2x2 grid. */
	'.lanspeed-ifaces-table,.lanspeed-ifaces-table tbody{display:block;width:100%;min-width:0}',
	'.lanspeed-ifaces-table thead{display:none}',
	'.lanspeed-ifaces-table tbody>tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));',
	'  gap:4px 12px;padding:10px 0;border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-ifaces-table tbody>tr:last-child{border-bottom:0}',
	'.lanspeed-ifaces-table tbody td{display:block;min-width:0;padding:0;border:0;',
	'  text-align:left;white-space:normal;overflow-wrap:anywhere}',
	'.lanspeed-ifaces-table tbody td:first-child{grid-column:1/-1;font-weight:600}',
	'.lanspeed-ifaces-table tbody td[data-label]::before{content:attr(data-label);display:block;',
	'  margin-bottom:2px;font-size:10.5px;font-weight:500;color:var(--lanspeed-text-subtle)}',
	'.lanspeed-ifaces-table tbody td:first-child::before{display:none}',
	'.lanspeed-control-form{grid-template-columns:minmax(0,1fr)}}',

	'@media (max-width:480px){',
	'.lanspeed-stat-value{font-size:17px}',
	'.lanspeed-connection-number{font-size:15px}',
	'.lanspeed-connection-values{gap:10px}',
	'.lanspeed-metric{min-height:4.2rem}',
	'.lanspeed-toolbar-right{gap:8px}',
	'.lanspeed-unit-select{width:auto;flex:0 1 62%}',
	'.lanspeed-sort-control{flex:1 1 100%}',
	'.lanspeed-details>summary{display:grid;grid-template-columns:1em minmax(0,1fr);',
	'  column-gap:6px;row-gap:2px}',
	'.lanspeed-details>summary::before{grid-column:1;grid-row:1}',
	'.lanspeed-details>summary>h3{grid-column:2;grid-row:1}',
	'.lanspeed-details>summary>.lanspeed-spacer{display:none}',
	'.lanspeed-details>summary .lanspeed-ifaces-summary{grid-column:2;grid-row:2;',
	'  text-align:left;white-space:normal;overflow-wrap:anywhere}',
	'.lanspeed-clients-table .lanspeed-control-button{flex:1 1 0}}'
].join('\n');

return baseclass.extend({
	CSS: RESPONSIVE_CSS
});
