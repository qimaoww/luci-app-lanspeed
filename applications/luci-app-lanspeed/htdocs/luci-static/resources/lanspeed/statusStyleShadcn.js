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
		'.lanspeed-root.lanspeed-theme-shadcn .lanspeed-header h3{font-size:1.05rem!important;letter-spacing:normal!important}',
		'.lanspeed-theme-shadcn .lanspeed-body{padding:.75rem 1.15rem .9rem}',
		'.lanspeed-theme-shadcn .lanspeed-stats-card>.lanspeed-body{padding:6px 0 4px}',
		'.lanspeed-theme-shadcn .lanspeed-clients-card>.lanspeed-body,',
		'.lanspeed-theme-shadcn .lanspeed-ifaces-card>.lanspeed-body{padding:0}',
		'.lanspeed-theme-shadcn .lanspeed-metric{min-height:5.4rem;padding:10px 18px}',
		'.lanspeed-theme-shadcn .lanspeed-metric:first-child{padding-left:0}',
		'.lanspeed-theme-shadcn .lanspeed-stat-value{font-size:21px}',
		'.lanspeed-theme-shadcn .lanspeed-toolbar,.lanspeed-theme-shadcn .lanspeed-pagination{',
			'padding-left:0;padding-right:0}',
		'.lanspeed-theme-shadcn .lanspeed-details>summary{padding-left:0;padding-right:0}',
		'.lanspeed-theme-shadcn .lanspeed-details-body{padding-left:0;padding-right:0}',
		'.lanspeed-theme-shadcn .lanspeed-empty{margin-left:0;margin-right:0}',
		'.lanspeed-theme-shadcn .lanspeed-table :is(th,td){padding:7px 10px}',
		'.lanspeed-theme-shadcn .lanspeed-table thead th{background:transparent;',
			'font-weight:600}',
		'@media (max-width:800px){',
			'.lanspeed-root.lanspeed-theme-shadcn .lanspeed-header{padding:.7rem .85rem .6rem}',
			'.lanspeed-theme-shadcn .lanspeed-body{padding:.65rem .85rem .8rem}',
			'.lanspeed-theme-shadcn .lanspeed-stats-card>.lanspeed-body{padding:6px 0 4px}',
		'}'
	].join('\n')
});
