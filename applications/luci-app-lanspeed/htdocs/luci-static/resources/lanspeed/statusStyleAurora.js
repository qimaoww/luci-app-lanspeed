'use strict';
'require baseclass';

/* Aurora keeps a spacious, softly elevated status hierarchy. */
var AURORA_CSS = [
	'.lanspeed-root.lanspeed-theme-aurora{gap:var(--lanspeed-page-gap)}',
	'.lanspeed-root.lanspeed-theme-aurora>.cbi-section{padding:var(--lanspeed-section-x);overflow:visible}',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-body{overflow-x:auto}',
	'.lanspeed-theme-aurora :is(.lanspeed-header,.lanspeed-details>summary){',
		'margin:0 0 var(--lanspeed-section-y);padding:0 0 var(--lanspeed-section-y);',
		'background:transparent;gap:.45rem .75rem}',
	'.lanspeed-theme-aurora :is(.lanspeed-body,.lanspeed-details-body){padding:0}',
	'.lanspeed-theme-aurora .lanspeed-details:not([open])>summary{margin-bottom:0;padding-bottom:0;border-bottom:0}',
	'.lanspeed-theme-aurora :is(.lanspeed-header,.lanspeed-details>summary) h3{font-size:1.2rem}',
	'.lanspeed-theme-aurora .lanspeed-header>.meta{padding:0}',
	'.lanspeed-theme-aurora .lanspeed-details>summary .sum{padding:.22rem .6rem;',
		'border-radius:var(--lanspeed-radius-badge);background:var(--lanspeed-surface-sunken)}',
	'.lanspeed-theme-aurora .lanspeed-page-size{width:calc(var(--spacing,.25rem)*28)!important;',
		'min-width:calc(var(--spacing,.25rem)*28);max-width:calc(var(--spacing,.25rem)*28);',
		'padding-right:calc(var(--spacing,.25rem)*11)!important;text-overflow:clip}',
	'.lanspeed-theme-aurora .lanspeed-pagination{padding-right:.25rem}',
	'.lanspeed-theme-aurora .lanspeed-metrics{grid-template-columns:repeat(4,minmax(0,1fr));',
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
	'.lanspeed-theme-aurora .lanspeed-table tbody tr:hover{',
		'background:transparent!important;background-image:none!important}',
	'.lanspeed-theme-aurora .lanspeed-table .mono{font-size:.85em}',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table td:nth-child(2).mono{font-size:.95rem}',
	'.lanspeed-theme-aurora .lanspeed-table td .ipline{max-width:18rem}',
	'@media (max-width:1100px){.lanspeed-theme-aurora .lanspeed-metrics{',
		'grid-template-columns:repeat(2,minmax(0,1fr));gap:.8rem 0}',
	'.lanspeed-theme-aurora .lanspeed-metric:nth-child(odd){padding-left:0;border-left:0}}',
	'@media (max-width:700px){',
	'.lanspeed-root.lanspeed-theme-aurora>.cbi-section{padding:calc(var(--spacing,.25rem)*4)}',
	'.lanspeed-theme-aurora :is(.lanspeed-header,.lanspeed-details>summary){',
		'margin-bottom:.85rem;padding:0 0 .7rem}',
	'.lanspeed-theme-aurora :is(.lanspeed-body,.lanspeed-details-body){padding:0}',
	'.lanspeed-theme-aurora .lanspeed-metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:.7rem 0}',
	'.lanspeed-theme-aurora .lanspeed-metric{min-height:5.1rem;padding:.2rem .75rem}',
	'.lanspeed-theme-aurora .lanspeed-metric:nth-child(odd){padding-left:0;border-left:0}',
	'.lanspeed-theme-aurora .lanspeed-metric:nth-child(even){border-left:1px solid var(--lanspeed-border)}',
	'.lanspeed-theme-aurora .lanspeed-toolbar input[type="search"]{min-width:0;width:100%;max-width:none}}',
	'@media (max-width:480px){.lanspeed-theme-aurora .lanspeed-metric .big{font-size:1.3rem}}'
].join('\n');

return baseclass.extend({
	CSS: AURORA_CSS
});
