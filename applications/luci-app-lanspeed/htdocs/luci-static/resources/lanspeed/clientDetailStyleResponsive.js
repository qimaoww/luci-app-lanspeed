'use strict';
'require baseclass';

var CSS = [
	'@media (max-width:700px){',
	'.lanspeed-connection-identity{grid-template-columns:minmax(0,1fr)}',
	'.lanspeed-connections-card .lanspeed-body{overflow-x:hidden}',
	'.lanspeed-connections-card .lanspeed-table,.lanspeed-connections-card .lanspeed-table tbody,.lanspeed-connections-card .lanspeed-table tr{display:block;width:100%;min-width:0}',
	'.lanspeed-connections-card .lanspeed-table thead{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}',
	'.lanspeed-connections-card .lanspeed-table tbody>tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.45em .75em;padding:.7em 0;border-bottom:1px solid var(--border,rgba(128,128,128,.18))}',
	'.lanspeed-connections-card .lanspeed-table tbody>tr[hidden]{display:none!important}',
	'.lanspeed-connections-card .lanspeed-table tbody>tr:last-child{border-bottom:0}',
	'.lanspeed-connections-card .lanspeed-table tbody td{display:block;min-width:0;padding:0!important;border:0!important}',
	'.lanspeed-connections-card .lanspeed-table td[data-label]::before{content:attr(data-label);display:block;margin:0 0 .15em;font-size:.72em;font-weight:600;line-height:1.2;opacity:.62}',
	'.lanspeed-connection-target-cell{grid-column:1/-1}',
	'.lanspeed-connection-endpoint,.lanspeed-connection-target-cell{min-width:0;max-width:100%;overflow-wrap:anywhere;word-break:break-word;white-space:normal}',
	'.lanspeed-connection-detail-row{display:block!important}',
	'.lanspeed-connection-detail-cell{display:block!important;width:100%;max-width:100%}',
	'.lanspeed-connection-detail-item{grid-template-columns:minmax(0,1fr)}',
	'}',
	'@media (max-width:480px){',
	'.lanspeed-connection-toolbar{align-items:stretch}',
	'.lanspeed-connection-toolbar-left,.lanspeed-connection-toolbar-right{display:flex;flex:1 1 100%;width:100%;min-width:0;flex-wrap:wrap}',
	'.lanspeed-connection-protocols{display:grid;grid-template-columns:auto repeat(3,minmax(0,1fr));width:100%;white-space:normal}',
	'.lanspeed-connection-protocols .cbi-button{width:100%;min-width:0}',
	'.lanspeed-connection-filter{width:100%}',
	'.lanspeed-connection-filter input[type=search]{width:100%;max-width:none;min-width:0;box-sizing:border-box}',
	'.lanspeed-connection-refresh{width:100%;box-sizing:border-box}',
	'.lanspeed-connection-summary{grid-template-columns:minmax(0,1fr)}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
