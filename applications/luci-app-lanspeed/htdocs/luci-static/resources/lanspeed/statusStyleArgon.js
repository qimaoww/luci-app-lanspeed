'use strict';
'require baseclass';

/* Argon uses a flatter, denser rhythm with its runtime primary color as the status cue. */
var ARGON_CSS = [
	'.lanspeed-root.lanspeed-theme-argon{gap:var(--lanspeed-page-gap);font-size:1rem}',
	'.lanspeed-root.lanspeed-theme-argon>.cbi-section{padding:0}',
	'.lanspeed-theme-argon :is(.lanspeed-header,.lanspeed-details>summary){padding:.95rem 1.25rem .8rem}',
	'.lanspeed-theme-argon .lanspeed-details:not([open])>summary{padding-bottom:.95rem}',
	'.lanspeed-theme-argon :is(.lanspeed-body,.lanspeed-details-body){padding:1rem 1.25rem}',
	'.lanspeed-theme-argon :is(.lanspeed-header,.lanspeed-details>summary) h3{',
		'font-size:1.3rem;line-height:1.25!important}',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-header>.meta,',
	'.lanspeed-theme-argon .lanspeed-details>summary .sum{padding-left:.55rem;',
		'border-left:.18rem solid var(--lanspeed-accent)}',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-body{overflow-x:auto}',
	'.lanspeed-theme-argon .lanspeed-metrics{grid-template-columns:repeat(4,minmax(0,1fr));',
		'gap:.85rem 1rem}',
	'.lanspeed-theme-argon .lanspeed-metric{border-left-width:.18rem}',
	'.lanspeed-theme-argon .lanspeed-metric .big{font-size:1.5rem}',
	'.lanspeed-theme-argon .lanspeed-toolbar{gap:.65rem .85rem;margin-bottom:.9rem;',
		'border-bottom-color:var(--lanspeed-border-strong)}',
	'.lanspeed-theme-argon .lanspeed-toolbar label{font-size:.95rem;line-height:1.5rem}',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-header{',
		'background:var(--lanspeed-surface-raised);border-bottom-color:var(--lanspeed-border-strong)}',
	'.lanspeed-root.lanspeed-theme-argon .lanspeed-active-only>input[type="checkbox"]{',
		'position:static;top:auto;right:auto;bottom:auto;left:auto;vertical-align:middle}',
	'.lanspeed-theme-argon .lanspeed-toolbar input[type="search"]{min-width:13rem;max-width:22rem}',
	'.lanspeed-theme-argon .lanspeed-table :is(th,td){padding:.62rem .72rem;font-size:.96rem;line-height:1.45}',
	'.lanspeed-theme-argon .lanspeed-table thead th{',
		'background:var(--lanspeed-surface-sunken);color:var(--lanspeed-text);',
		'border-bottom:1px solid var(--lanspeed-border-strong);font-size:.82rem;',
		'font-weight:650;line-height:1.3;white-space:nowrap}',
	'.lanspeed-theme-argon .lanspeed-table :is(th,td):first-child{padding-left:.35rem}',
	'.lanspeed-theme-argon .lanspeed-table :is(th,td):last-child{padding-right:.35rem}',
	'.lanspeed-theme-argon .lanspeed-table .mono,.lanspeed-theme-argon .lanspeed-client-mac-value{font-size:.9rem}',
	'.lanspeed-theme-argon .lanspeed-client-name .ipline{font-size:.8rem;line-height:1.3}',
	'.lanspeed-theme-argon .lanspeed-pagination{border-top-color:var(--lanspeed-border-strong);padding-top:.8rem}',
	/* Argon surfaces are translucent; stripe whole rows through one token so
	 * every cell in a row shares the same composited background. */
	'.lanspeed-theme-argon .lanspeed-table tbody tr,',
	'.lanspeed-theme-argon .lanspeed-table tbody tr:nth-child(odd):hover{',
		'background:transparent!important;background-image:none!important}',
	'.lanspeed-theme-argon .lanspeed-table tbody tr:nth-child(even),',
	'.lanspeed-theme-argon .lanspeed-table tbody tr:nth-child(even):hover{',
		'background:var(--lanspeed-native-row-stripe)!important;background-image:none!important}',
	'.lanspeed-theme-argon .lanspeed-table tbody td{border-bottom:0!important}',
	'.lanspeed-theme-argon .lanspeed-connection-link:link,',
	'.lanspeed-theme-argon .lanspeed-connection-link:visited,',
	'.lanspeed-theme-argon .lanspeed-connection-link:active,',
	'.lanspeed-theme-argon .lanspeed-connection-link:hover{',
		'color:var(--lanspeed-link-safe,var(--lanspeed-accent))!important;',
		'text-decoration:none!important}',
	'.lanspeed-theme-argon .lanspeed-hint:empty{display:none}',
	'@media (max-width:1100px){.lanspeed-theme-argon .lanspeed-metrics{',
		'grid-template-columns:repeat(2,minmax(0,1fr))}}',
	'@media (max-width:700px){',
	'.lanspeed-theme-argon :is(.lanspeed-header,.lanspeed-details>summary){padding:.85rem 1rem .7rem}',
	'.lanspeed-theme-argon .lanspeed-details:not([open])>summary{padding-bottom:.85rem}',
	'.lanspeed-theme-argon :is(.lanspeed-body,.lanspeed-details-body){padding:.85rem 1rem}',
	'.lanspeed-theme-argon .lanspeed-toolbar input[type="search"]{min-width:0;width:100%;max-width:none}',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-header>.meta{white-space:normal;text-align:right}}',
	'@media (max-width:480px){.lanspeed-theme-argon .lanspeed-metric .big{font-size:1.3rem}}'
].join('\n');

return baseclass.extend({
	CSS: ARGON_CSS
});
