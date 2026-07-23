'use strict';
'require baseclass';

/* Aurora keeps a spacious, softly elevated status hierarchy. */
var AURORA_CSS = [
	'.lanspeed-root.lanspeed-theme-aurora{gap:var(--lanspeed-page-gap)}',
	'.lanspeed-root.lanspeed-theme-aurora>.cbi-section{padding:0}',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-body{overflow-x:auto}',
	'.lanspeed-theme-aurora :is(.lanspeed-header,.lanspeed-details>summary){',
		'padding:1rem 1.25rem .85rem;gap:.45rem .75rem}',
	'.lanspeed-theme-aurora :is(.lanspeed-body,.lanspeed-details-body){padding:1rem 1.25rem}',
	'.lanspeed-theme-aurora :is(.lanspeed-header,.lanspeed-details>summary) h3{font-size:1.2rem}',
	'.lanspeed-theme-aurora .lanspeed-header>.meta{padding:0}',
	'.lanspeed-theme-aurora .lanspeed-details>summary .sum{padding:.22rem .6rem;',
		'border-radius:var(--lanspeed-radius-badge);background:var(--lanspeed-surface-sunken)}',
	'.lanspeed-theme-aurora .lanspeed-page-size{width:calc(var(--spacing,.25rem)*28)!important;',
		'min-width:calc(var(--spacing,.25rem)*28);max-width:calc(var(--spacing,.25rem)*28);',
		'padding-right:calc(var(--spacing,.25rem)*11)!important;text-overflow:clip}',
	'.lanspeed-theme-aurora .lanspeed-pagination{padding-right:.25rem}',
	'.lanspeed-theme-aurora .lanspeed-metrics{grid-template-columns:repeat(5,minmax(0,1fr));',
		'gap:0;align-items:stretch}',
	'.lanspeed-theme-aurora .lanspeed-metric{display:flex;flex-direction:column;justify-content:center;',
		'min-height:5.8rem;padding:.28rem 1.15rem .22rem;border-left:1px solid var(--lanspeed-border)}',
	'.lanspeed-theme-aurora .lanspeed-metric:first-child{padding-left:0;border-left:0}',
	'.lanspeed-theme-aurora .lanspeed-metric .big{font-size:1.45rem}',
	'.lanspeed-theme-aurora .lanspeed-toolbar{gap:.65rem 1rem;margin-bottom:.85rem;padding-bottom:.85rem}',
	'.lanspeed-theme-aurora .lanspeed-toolbar input[type="search"]{min-width:14rem;max-width:22rem}',
	'.lanspeed-theme-aurora .lanspeed-table :is(th,td){padding:.58rem .65rem}',
	'.lanspeed-theme-aurora .lanspeed-table thead th{background:var(--lanspeed-surface-sunken);',
		'font-size:.78rem;text-transform:uppercase}',
	'.lanspeed-theme-aurora .lanspeed-table tbody tr:hover,',
	'.lanspeed-theme-aurora .lanspeed-table tbody tr.lanspeed-client-hover-lock{background:var(--lanspeed-hover)}',
	'.lanspeed-theme-aurora .lanspeed-table .mono{font-size:.85em}',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table td:nth-child(2).mono{font-size:.95rem}',
	'@media (min-width:901px){',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table{table-layout:fixed}',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table :is(th,td):nth-child(1){width:18rem}',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table :is(th,td):nth-child(2){width:15rem}}',
	'.lanspeed-theme-aurora .lanspeed-table td .ipline{max-width:18rem}',
	'@media (max-width:1100px){.lanspeed-theme-aurora .lanspeed-metrics{',
		'grid-template-columns:repeat(3,minmax(0,1fr));gap:.8rem 0}',
	'.lanspeed-theme-aurora .lanspeed-metric:nth-child(4){padding-left:0;border-left:0}}',
	'@media (max-width:700px){',
	'.lanspeed-theme-aurora :is(.lanspeed-header,.lanspeed-details>summary){padding:.85rem 1rem .7rem}',
	'.lanspeed-theme-aurora :is(.lanspeed-body,.lanspeed-details-body){padding:.85rem 1rem}',
	'.lanspeed-theme-aurora .lanspeed-metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:.7rem 0}',
	'.lanspeed-theme-aurora .lanspeed-metric{min-height:5.1rem;padding:.2rem .75rem}',
	'.lanspeed-theme-aurora .lanspeed-metric:nth-child(odd){padding-left:0;border-left:0}',
	'.lanspeed-theme-aurora .lanspeed-metric:nth-child(even){border-left:1px solid var(--lanspeed-border)}',
	'.lanspeed-theme-aurora .lanspeed-metric:last-child{grid-column:1/-1;padding-left:0;border-left:0}',
	'.lanspeed-theme-aurora .lanspeed-toolbar input[type="search"]{min-width:0;width:100%;max-width:none}}',
	'@media (max-width:480px){.lanspeed-theme-aurora .lanspeed-metric .big{font-size:1.3rem}}'
].join('\n');

return baseclass.extend({
	CSS: AURORA_CSS
});
