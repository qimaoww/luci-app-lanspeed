'use strict';
'require baseclass';

/* shadcn keeps an airy card rhythm with soft borders and one surface per row. */
var SHADCN_CSS = [
	'.lanspeed-root.lanspeed-theme-shadcn{gap:var(--lanspeed-page-gap);font-size:.94rem}',
	'.lanspeed-root.lanspeed-theme-shadcn>.cbi-section{padding:0}',
	'.lanspeed-theme-shadcn :is(.lanspeed-header,.lanspeed-details>summary){',
		'padding:.85rem 1.15rem .72rem;border-bottom-color:var(--lanspeed-border)}',
	'.lanspeed-theme-shadcn :is(.lanspeed-body,.lanspeed-details-body){padding:.85rem 1.15rem 1rem}',
	'.lanspeed-theme-shadcn :is(.lanspeed-header,.lanspeed-details>summary) h3{font-size:1.05rem}',
	'.lanspeed-theme-shadcn .lanspeed-header>.meta,',
	'.lanspeed-theme-shadcn .lanspeed-details>summary .sum{font-size:.76rem}',
	'.lanspeed-theme-shadcn .lanspeed-metrics{grid-template-columns:repeat(4,minmax(0,1fr));',
		'gap:0;align-items:stretch}',
	'.lanspeed-theme-shadcn .lanspeed-metric{display:flex;flex-direction:column;justify-content:center;',
		'min-width:0;min-height:5.4rem;padding:.35rem 1.1rem;',
		'border-left:1px solid var(--lanspeed-border)}',
	'.lanspeed-theme-shadcn .lanspeed-metric:first-child{padding-left:0;border-left:0}',
	'.lanspeed-theme-shadcn .lanspeed-metric .caption{font-size:.72rem}',
	'.lanspeed-theme-shadcn .lanspeed-metric .big{font-size:1.4rem;font-weight:650}',
	'.lanspeed-theme-shadcn .lanspeed-toolbar{gap:.6rem .9rem;margin-bottom:.85rem;padding-bottom:.8rem}',
	'.lanspeed-theme-shadcn .lanspeed-toolbar label{font-size:.86rem}',
	'.lanspeed-theme-shadcn .lanspeed-table :is(th,td){padding:.55rem .65rem;font-size:.86rem}',
	'.lanspeed-theme-shadcn .lanspeed-table thead th{background:var(--lanspeed-surface-muted);',
		'font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:.02em}',
	'.lanspeed-theme-shadcn .lanspeed-table tbody tr:hover{',
		'background:transparent!important;background-image:none!important}',
	'.lanspeed-theme-shadcn .lanspeed-table .mono{font-size:.86em}',
	'.lanspeed-theme-shadcn .lanspeed-table td .ipline{max-width:20rem}',
	'.lanspeed-theme-shadcn .lanspeed-control-button{width:5.5em;min-width:5.5em}',
	'@media (max-width:1100px){.lanspeed-theme-shadcn .lanspeed-metrics{',
		'grid-template-columns:repeat(2,minmax(0,1fr));gap:0}',
	'.lanspeed-theme-shadcn .lanspeed-metric:nth-child(odd){padding-left:0;border-left:0}}',
	'@media (max-width:700px){',
	'.lanspeed-root.lanspeed-theme-shadcn>.cbi-section,.lanspeed-theme-shadcn .lanspeed-details{min-width:0;max-width:100%}',
	'.lanspeed-theme-shadcn :is(.lanspeed-header,.lanspeed-details>summary){padding:.7rem .85rem .6rem}',
	'.lanspeed-theme-shadcn :is(.lanspeed-body,.lanspeed-details-body){padding:.7rem .85rem .85rem}',
	'.lanspeed-theme-shadcn .lanspeed-metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:0}',
	'.lanspeed-theme-shadcn .lanspeed-metric:nth-child(odd){padding-left:0;border-left:0}',
	'.lanspeed-theme-shadcn .lanspeed-metric:nth-child(even){border-left:1px solid var(--lanspeed-border)}}',
	'@media (max-width:480px){.lanspeed-theme-shadcn .lanspeed-metric{padding:.6rem .7rem}',
	'.lanspeed-theme-shadcn .lanspeed-metric .big{font-size:1.25rem}}'
].join('\n');

return baseclass.extend({
	CSS: SHADCN_CSS
});
