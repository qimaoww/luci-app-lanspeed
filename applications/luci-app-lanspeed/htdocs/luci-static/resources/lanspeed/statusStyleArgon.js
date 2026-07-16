'use strict';
'require baseclass';

/* Argon-only status layout overrides. Every selector stays Argon-scoped. */
var ARGON_CSS = [
	'.lanspeed-theme-argon{display:flex;flex-direction:column;gap:1rem;margin:0;font-size:1rem}',
	'.lanspeed-theme-argon>.cbi-section{margin:0;padding:0;overflow:hidden}',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-body{overflow-x:auto}',
	'.lanspeed-theme-argon .lanspeed-header,',
	'.lanspeed-theme-argon .lanspeed-details>summary{padding:.95rem 1.25rem .8rem}',
	'.lanspeed-theme-argon .lanspeed-header,',
	'.lanspeed-theme-argon .lanspeed-details>summary{align-items:center}',
	'.lanspeed-theme-argon .lanspeed-details>summary::before{align-self:center;line-height:1}',
	'.lanspeed-theme-argon .lanspeed-body,',
	'.lanspeed-theme-argon .lanspeed-details-body{padding:1rem 1.25rem}',
	'.lanspeed-theme-argon .lanspeed-metrics{grid-template-columns:repeat(auto-fit,minmax(10.5em,12.5em));',
	'  justify-content:start;gap:.9rem 1rem}',
	'.lanspeed-theme-argon .lanspeed-metric .big{font-size:1.5rem}',
	'.lanspeed-theme-argon .lanspeed-toolbar{gap:.65rem .85rem;margin-bottom:.9rem}',
	'.lanspeed-theme-argon .lanspeed-toolbar label{font-size:1rem;line-height:1.5rem}',
	'.lanspeed-theme-argon .lanspeed-active-label{line-height:1.5rem}',
	'.lanspeed-theme-argon .lanspeed-toolbar input[type=search]{min-width:13rem;max-width:22rem}',
	'.lanspeed-theme-argon .lanspeed-header>h3,',
	'.lanspeed-theme-argon .lanspeed-details>summary>h3{font-size:1.35rem;line-height:1.25!important}',
	'.lanspeed-theme-argon .label{display:inline-flex;align-items:center;justify-content:center;',
	'  min-height:1.75rem;padding:.3rem .7rem!important;box-sizing:border-box;line-height:1.15!important}',
	'.lanspeed-theme-argon .lanspeed-toolbar button,',
	'.lanspeed-theme-argon .lanspeed-toolbar select,',
	'.lanspeed-theme-argon .lanspeed-toolbar input{font-size:1rem}',
	'.lanspeed-theme-argon .lanspeed-table th,.lanspeed-theme-argon .lanspeed-table td{padding:.65rem .75rem;font-size:1rem;line-height:1.45}',
	'.lanspeed-theme-argon .lanspeed-sort-button{height:auto!important;min-height:0!important;line-height:1.35!important}',
	'.lanspeed-theme-argon .lanspeed-table th:first-child,.lanspeed-theme-argon .lanspeed-table td:first-child{padding-left:.35rem}',
	'.lanspeed-theme-argon .lanspeed-table th:last-child,',
	'.lanspeed-theme-argon .lanspeed-table td:last-child{padding-right:0}',
	'.lanspeed-theme-argon .lanspeed-table .mono{font-size:.96rem}',
	'@media (min-width:701px){.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table tbody td{vertical-align:top}}',
	'.lanspeed-theme-argon .lanspeed-hint{padding:0}',
	'.lanspeed-theme-argon .lanspeed-hint:empty{display:none}',
	'@media (min-width:1201px){.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table{table-layout:fixed}',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table th:nth-child(1),.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table td:nth-child(1){width:17rem}',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table th:nth-child(2),.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table td:nth-child(2){width:14.5rem}}',
	'.lanspeed-theme-argon .lanspeed-table td .ipline{max-width:18rem}',
	'@media (max-width:700px){.lanspeed-theme-argon .lanspeed-header,',
	'.lanspeed-theme-argon .lanspeed-details>summary{padding:.85rem 1rem .7rem}',
	'.lanspeed-theme-argon .lanspeed-body,',
	'.lanspeed-theme-argon .lanspeed-details-body{padding:.85rem 1rem;overflow-x:auto}',
	'.lanspeed-theme-argon .lanspeed-toolbar-right{justify-content:flex-start}',
	'.lanspeed-theme-argon .lanspeed-toolbar input[type=search]{min-width:0;width:100%;max-width:none}}',
	'@media (max-width:480px){.lanspeed-theme-argon .lanspeed-metrics{',
	'  grid-template-columns:repeat(auto-fit,minmax(9rem,1fr))}}'
].join('\n');

return baseclass.extend({
	CSS: ARGON_CSS
});
