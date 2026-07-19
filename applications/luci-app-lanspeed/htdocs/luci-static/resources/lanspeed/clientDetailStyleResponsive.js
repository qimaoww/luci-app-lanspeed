'use strict';
'require baseclass';

var CSS = [
	'@media (max-width:1100px){',
	'.lanspeed-connection-identity{grid-template-columns:minmax(0,1fr)}',
	'.lanspeed-connection-summary{padding:1.25em 0 0;border-left:0;border-top:1px solid var(--lanspeed-border)}',
	'}',
	'@media (max-width:700px){',
	'.lanspeed-connections-card .lanspeed-body{overflow-x:hidden}',
	'.lanspeed-connections-card .lanspeed-table,.lanspeed-connections-card .lanspeed-table thead,.lanspeed-connections-card .lanspeed-table tbody{display:block;width:100%;min-width:0}',
	'.lanspeed-connections-card .lanspeed-table thead>tr{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.25em;padding:0 0 .6em;border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-connections-card .lanspeed-table thead th{display:block;width:auto!important;min-width:0;padding:.25em .15em!important;border:0}',
	'.lanspeed-connections-card .lanspeed-sort-button{width:100%;max-width:100%;justify-content:center}',
	'.lanspeed-connections-card .lanspeed-sort-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
	'.lanspeed-connections-card .lanspeed-table tbody>tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.45em .75em;padding:.7em 0;border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-connections-card .lanspeed-table tbody>tr[hidden]{display:none!important}',
	'.lanspeed-connections-card .lanspeed-table tbody>tr:last-child{border-bottom:0}',
	'.lanspeed-connections-card .lanspeed-table tbody td{display:block;min-width:0;padding:0!important;border:0!important}',
	'.lanspeed-connections-card .lanspeed-table tbody td.num{text-align:left}',
	'.lanspeed-connections-card .lanspeed-table td[data-label]::before{content:attr(data-label);display:block;margin:0 0 .15em;font-size:.72em;font-weight:600;line-height:1.2;opacity:.62}',
	'.lanspeed-connection-target-cell{grid-column:1/-1}',
	'.lanspeed-connection-location-cell{min-width:0;overflow-wrap:anywhere;word-break:break-word}',
	'.lanspeed-connection-endpoint,.lanspeed-connection-target-cell{min-width:0;max-width:100%;overflow-wrap:anywhere;word-break:break-word;white-space:normal}',
	'.lanspeed-connection-detail-row{display:block!important}',
	'.lanspeed-connection-detail-cell{display:block!important;width:100%;max-width:100%}',
	'.lanspeed-connection-detail-item{grid-template-columns:minmax(0,1fr)}',
	'.lanspeed-connection-detail-meta{white-space:normal}',
	'.lanspeed-connection-detail-rates{justify-content:flex-start}',
	'.lanspeed-connection-meta-facts{grid-template-columns:minmax(0,1.6fr) minmax(0,1fr)}',
	'}',
	'@media (max-width:480px){',
	'.lanspeed-connection-toolbar{align-items:stretch}',
	'.lanspeed-connection-toolbar-left,.lanspeed-connection-toolbar-right{display:flex;flex:1 1 100%;width:100%;min-width:0;flex-wrap:wrap}',
	'.lanspeed-connection-protocols{display:grid;grid-template-columns:auto repeat(3,minmax(0,1fr));width:100%;white-space:normal}',
	'.lanspeed-connection-protocols .cbi-button{width:100%;min-width:0}',
	'.lanspeed-connection-filter{width:100%}',
	'.lanspeed-connection-filter input[type=search]{width:100%;max-width:none;min-width:0;box-sizing:border-box}',
	'.lanspeed-connection-refresh{width:100%;box-sizing:border-box}',
	'.lanspeed-connection-pager{justify-content:center}',
	'.lanspeed-connection-summary{grid-template-columns:minmax(0,1fr)}',
	'.lanspeed-connection-meta-facts{grid-template-columns:minmax(0,1fr)}',
	'.lanspeed-connection-client-avatar{width:3em;height:3em;flex-basis:3em;border-radius:.85em}',
	'.lanspeed-connections-card .lanspeed-table thead>tr{grid-template-columns:repeat(2,minmax(0,1fr));row-gap:.35em}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
