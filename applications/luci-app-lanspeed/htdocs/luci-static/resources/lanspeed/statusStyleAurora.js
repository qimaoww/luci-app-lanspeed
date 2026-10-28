'use strict';
'require baseclass';
/*
 * Aurora: the section is the surface and owns the page padding, so the head is
 * flush with the card edge exactly like the configuration and diagnostics
 * pages. Metrics keep the theme's hairline dividers and the table head sits on
 * the sunken surface.
 */
return baseclass.extend({
	__name__: 'LuCILanspeedStatusStyleAurora',
	CSS: [
		'.lanspeed-root.lanspeed-theme-aurora>.cbi-section{padding:var(--lanspeed-section-x);overflow:visible}',
		'.lanspeed-root.lanspeed-theme-aurora .lanspeed-header{margin:0 0 var(--lanspeed-section-y);',
			'padding:0 0 var(--lanspeed-section-y);background:transparent;gap:.45rem .75rem}',
		'.lanspeed-root.lanspeed-theme-aurora .lanspeed-header h3{font-size:1.2rem!important;line-height:1.25!important;letter-spacing:normal!important}',
		'.lanspeed-theme-aurora .lanspeed-body{padding:0}',
		'.lanspeed-theme-aurora .lanspeed-stats-card>.lanspeed-body{padding:4px 0 2px}',
		'.lanspeed-theme-aurora .lanspeed-metric{display:flex;flex-direction:column;justify-content:center;',
			'min-height:4rem;padding:8px 16px}',
		'.lanspeed-theme-aurora .lanspeed-metric:first-child{padding-left:0}',
		'.lanspeed-theme-aurora .lanspeed-metric:last-child{padding-right:0}',
		'.lanspeed-theme-aurora .lanspeed-stat-value{font-size:20px}',
		'.lanspeed-theme-aurora .lanspeed-toolbar,.lanspeed-theme-aurora .lanspeed-pagination,',
		'.lanspeed-theme-aurora .lanspeed-details>summary{padding-left:0;padding-right:0}',
		'.lanspeed-theme-aurora .lanspeed-details-body{padding-left:0;padding-right:0}',
		'.lanspeed-theme-aurora .lanspeed-empty{margin-left:0;margin-right:0}',
		'.lanspeed-theme-aurora .lanspeed-status-error{margin-left:0;margin-right:0}',
		'.lanspeed-theme-aurora .lanspeed-table :is(th,td){padding:6px 10px}',
		'.lanspeed-theme-aurora .lanspeed-table thead th{background:transparent}',
		'.lanspeed-theme-aurora .lanspeed-metrics{grid-template-columns:repeat(4,minmax(0,1fr))}',
		'.lanspeed-theme-aurora .lanspeed-page-size{width:5.6em!important;min-width:5.2em;max-width:6.4em;',
			'padding-right:1.6em}',
		'.lanspeed-theme-aurora .lanspeed-header>.meta{background:transparent;border-radius:0;box-shadow:none}',
		'@media (max-width:1100px){.lanspeed-theme-aurora .lanspeed-metrics{',
			'grid-template-columns:repeat(2,minmax(0,1fr))}',
			'.lanspeed-theme-aurora .lanspeed-metric:nth-child(odd){padding-left:0;border-left:0}',
			'.lanspeed-theme-aurora .lanspeed-metric:nth-child(even){border-left:1px solid var(--lanspeed-border)}}',
		'@media (max-width:800px){',
			'.lanspeed-root.lanspeed-theme-aurora>.cbi-section{padding:calc(var(--spacing,.25rem)*4)}',
			'.lanspeed-root.lanspeed-theme-aurora .lanspeed-header{margin:0 0 8px;padding:0 0 .7rem}',
			'.lanspeed-theme-aurora .lanspeed-metric{min-height:3.6rem;padding:6px 12px}',
			'.lanspeed-theme-aurora .lanspeed-metric:first-child{padding-left:0}',
			'.lanspeed-theme-aurora .lanspeed-stat-value{font-size:18px}',
		'}'
	].join('\n')
});
