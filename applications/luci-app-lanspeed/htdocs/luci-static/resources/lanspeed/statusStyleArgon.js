'use strict';
'require baseclass';

/* Argon uses a flatter, denser rhythm with its runtime primary color as the status cue. */
var ARGON_CSS = [
	'.lanspeed-root.lanspeed-theme-argon{gap:var(--lanspeed-page-gap);font-size:1rem}',
	'.lanspeed-root.lanspeed-theme-argon>.cbi-section{padding:0}',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-body{overflow-x:auto}',
	'.lanspeed-theme-argon :is(.lanspeed-header,.lanspeed-details>summary){padding:.95rem 1.25rem .8rem}',
	'.lanspeed-theme-argon :is(.lanspeed-body,.lanspeed-details-body){padding:1rem 1.25rem}',
	'.lanspeed-theme-argon :is(.lanspeed-header,.lanspeed-details>summary) h3{',
		'font-size:1.3rem;line-height:1.25!important}',
	'.lanspeed-theme-argon .lanspeed-header>.meta,',
	'.lanspeed-theme-argon .lanspeed-details>summary .sum{padding-left:.55rem;',
		'border-left:.18rem solid var(--lanspeed-accent)}',
	'.lanspeed-theme-argon .lanspeed-metrics{grid-template-columns:repeat(5,minmax(0,1fr));',
		'gap:.85rem 1rem}',
	'.lanspeed-theme-argon .lanspeed-metric{border-left-width:.18rem}',
	'.lanspeed-theme-argon .lanspeed-metric .big{font-size:1.5rem}',
	'.lanspeed-theme-argon .lanspeed-toolbar{gap:.65rem .85rem;margin-bottom:.9rem}',
	'.lanspeed-theme-argon .lanspeed-toolbar label{font-size:.95rem;line-height:1.5rem}',
	'.lanspeed-root.lanspeed-theme-argon .lanspeed-active-only>input[type="checkbox"]{',
		'position:static;top:auto;right:auto;bottom:auto;left:auto;vertical-align:middle}',
	'.lanspeed-theme-argon .lanspeed-toolbar input[type="search"]{min-width:13rem;max-width:22rem}',
	'.lanspeed-theme-argon .lanspeed-table :is(th,td){padding:.62rem .72rem;font-size:.96rem;line-height:1.45}',
	'.lanspeed-theme-argon .lanspeed-sort-button{height:auto!important;min-height:0!important;line-height:1.35!important}',
	'.lanspeed-theme-argon .lanspeed-table :is(th,td):first-child{padding-left:.35rem}',
	'.lanspeed-theme-argon .lanspeed-table :is(th,td):last-child{padding-right:0}',
	'.lanspeed-theme-argon .lanspeed-table .mono{font-size:.94rem}',
	'.lanspeed-theme-argon .lanspeed-table tbody tr:hover,',
	'.lanspeed-theme-argon .lanspeed-table tbody tr.lanspeed-client-hover-lock{background:var(--lanspeed-hover)}',
	'.lanspeed-theme-argon .lanspeed-connection-link:link,',
	'.lanspeed-theme-argon .lanspeed-connection-link:visited,',
	'.lanspeed-theme-argon .lanspeed-connection-link:active,',
	'.lanspeed-theme-argon .lanspeed-connection-link:hover{',
		'color:var(--lanspeed-link-safe,var(--lanspeed-accent))!important;',
		'text-decoration:none!important}',
	'.lanspeed-theme-argon .lanspeed-hint:empty{display:none}',
	'@media (min-width:1201px){',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table{table-layout:fixed}',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table :is(th,td):nth-child(1){width:17rem}',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-table :is(th,td):nth-child(2){width:14.5rem}}',
	'.lanspeed-theme-argon .lanspeed-table td .ipline{max-width:18rem}',
	'@media (max-width:1100px){.lanspeed-theme-argon .lanspeed-metrics{',
		'grid-template-columns:repeat(3,minmax(0,1fr))}}',
	'@media (max-width:700px){',
	'.lanspeed-theme-argon :is(.lanspeed-header,.lanspeed-details>summary){padding:.85rem 1rem .7rem}',
	'.lanspeed-theme-argon :is(.lanspeed-body,.lanspeed-details-body){padding:.85rem 1rem}',
	'.lanspeed-theme-argon .lanspeed-toolbar input[type="search"]{min-width:0;width:100%;max-width:none}}',
	'@media (max-width:480px){.lanspeed-theme-argon .lanspeed-metrics{',
		'grid-template-columns:repeat(2,minmax(0,1fr))}',
	'.lanspeed-theme-argon .lanspeed-metric .big{font-size:1.3rem}',
	'.lanspeed-theme-argon .lanspeed-metric:last-child{grid-column:1/-1}}'
].join('\n');

return baseclass.extend({
	CSS: ARGON_CSS
});
