'use strict';
'require baseclass';
/*
 * shadcn: quiet borders, airy rows and hairline metric dividers.
 */
return baseclass.extend({
	__name__: 'LuCILanspeedStatusStyleShadcn',
	CSS: [
		'.lanspeed-root.lanspeed-theme-shadcn{gap:var(--lanspeed-page-gap);font-size:.94rem}',
		'.lanspeed-root.lanspeed-theme-shadcn>.cbi-section{padding:0}',
		'.lanspeed-root.lanspeed-theme-shadcn .lanspeed-header{gap:.4em 1em;',
			'padding:.85rem 1.15rem .72rem;border-bottom-color:var(--lanspeed-border)}',
		'.lanspeed-root.lanspeed-theme-shadcn .lanspeed-header h3{font-size:1.125rem!important;line-height:1.25!important;letter-spacing:normal!important}',
		'.lanspeed-theme-shadcn .lanspeed-status-actions .cbi-button{transition:none!important}',
		'.lanspeed-theme-shadcn .lanspeed-body{padding:.65rem 1.15rem .75rem}',
		'.lanspeed-theme-shadcn .lanspeed-stats-card>.lanspeed-body{padding:4px 0 2px}',
		'.lanspeed-theme-shadcn .lanspeed-clients-card>.lanspeed-body,',
		'.lanspeed-theme-shadcn .lanspeed-ifaces-card>.lanspeed-body{padding:0}',
		'.lanspeed-theme-shadcn .lanspeed-metric{min-height:4rem;padding:8px 16px}',
		'.lanspeed-theme-shadcn .lanspeed-metric:first-child{padding-left:0}',
		'.lanspeed-theme-shadcn .lanspeed-metric:last-child{padding-right:0}',
		'.lanspeed-theme-shadcn .lanspeed-stat-value{font-size:20px}',
		'.lanspeed-theme-shadcn .lanspeed-toolbar,.lanspeed-theme-shadcn .lanspeed-pagination{',
			'padding-left:0;padding-right:0}',
		'.lanspeed-theme-shadcn .lanspeed-details>summary{padding-left:0;padding-right:0}',
		'.lanspeed-theme-shadcn .lanspeed-details-body{padding-left:0;padding-right:0}',
		'.lanspeed-theme-shadcn .lanspeed-empty{margin-left:0;margin-right:0}',
		'.lanspeed-theme-shadcn .lanspeed-table :is(th,td){padding:6px 10px}',
		'.lanspeed-theme-shadcn .lanspeed-table thead th{background:transparent;',
			'font-weight:600}',
		'@media (max-width:800px){',
			'.lanspeed-root.lanspeed-theme-shadcn .lanspeed-header{padding:.7rem .85rem .6rem}',
			'.lanspeed-theme-shadcn .lanspeed-body{padding:.6rem .85rem .7rem}',
			'.lanspeed-theme-shadcn .lanspeed-stats-card>.lanspeed-body{padding:4px 0 2px}',
			'.lanspeed-theme-shadcn .lanspeed-metric{min-height:3.6rem;padding:6px 12px}',
			'.lanspeed-theme-shadcn .lanspeed-stat-value{font-size:18px}',
		'}'
	].join('\n')
});
