'use strict';
'require baseclass';
/*
 * Argon: dense, flat and link-forward. The head keeps the theme's own padding
 * so the overview reads with the same rhythm as the configuration page.
 */
return baseclass.extend({
	__name__: 'LuCILanspeedStatusStyleArgon',
	CSS: [
		'.lanspeed-root.lanspeed-theme-argon{gap:1rem;font-size:1rem}',
		'.lanspeed-root.lanspeed-theme-argon>.cbi-section{padding:0;overflow:visible}',
		'.lanspeed-root.lanspeed-theme-argon .lanspeed-header{gap:.4em 1em;padding:.95rem 1.25rem .8rem}',
		'.lanspeed-root.lanspeed-theme-argon .lanspeed-header h3{font-size:1.3rem;line-height:1.25!important}',
		'.lanspeed-theme-argon .lanspeed-body{padding:.85rem 1.25rem}',
		'.lanspeed-theme-argon .lanspeed-stats-card>.lanspeed-body{padding:4px 1.25rem 2px}',
		'.lanspeed-theme-argon .lanspeed-clients-card>.lanspeed-body,',
		'.lanspeed-theme-argon .lanspeed-ifaces-card>.lanspeed-body{padding:0}',
		'.lanspeed-theme-argon .lanspeed-metric{padding:8px 16px;border-left-width:1px}',
		'.lanspeed-theme-argon .lanspeed-metric:first-child{padding-left:0;border-left:0}',
		'.lanspeed-theme-argon .lanspeed-metric:last-child{padding-right:0}',
		'.lanspeed-theme-argon .lanspeed-stat-value{font-size:20px}',
		'.lanspeed-theme-argon .lanspeed-toolbar,.lanspeed-theme-argon .lanspeed-pagination{padding-left:0;padding-right:0}',
		'.lanspeed-theme-argon .lanspeed-details-body{padding-left:0;padding-right:0}',
		'.lanspeed-theme-argon .lanspeed-empty{margin-left:0;margin-right:0}',
		'.lanspeed-theme-argon .lanspeed-table{font-size:13px}',
		'.lanspeed-theme-argon .lanspeed-table :is(th,td){padding:6px 10px;border-bottom:0}',
		'.lanspeed-theme-argon .lanspeed-table thead th{background:transparent;',
			'letter-spacing:.04em}',
		'.lanspeed-theme-argon .lanspeed-table tbody tr:nth-child(even){',
			'background:color-mix(in srgb,currentColor 3%,transparent)!important}',
		'.lanspeed-theme-argon .lanspeed-connection-link{font-weight:600;',
			'color:var(--lanspeed-link-safe,var(--lanspeed-accent))!important;',
			'text-decoration:none!important}',
		'.lanspeed-theme-argon :is(.lanspeed-header,.lanspeed-details>summary){padding:.95rem 1.25rem .8rem}',
		'.lanspeed-theme-argon .lanspeed-metrics{grid-template-columns:repeat(4,minmax(0,1fr));gap:0}',
		'@media (max-width:1100px){.lanspeed-theme-argon .lanspeed-metrics{',
			'grid-template-columns:repeat(2,minmax(0,1fr))}',
			'.lanspeed-theme-argon .lanspeed-metric:nth-child(odd){padding-left:0;border-left:0}',
			'.lanspeed-theme-argon .lanspeed-metric:nth-child(even){border-left:1px solid var(--lanspeed-border)}}',
		'.lanspeed-theme-argon .lanspeed-toolbar label{font-size:.95rem;line-height:1.5rem}',
		'.lanspeed-root.lanspeed-theme-argon .lanspeed-active-only>input[type="checkbox"]{',
			'position:static;margin:0}',
		'.lanspeed-theme-argon .lanspeed-hint:empty{display:none}',
		'@media (max-width:800px){',
			'.lanspeed-root.lanspeed-theme-argon .lanspeed-header{padding:.85rem 1rem .7rem}',
			'.lanspeed-root.lanspeed-theme-argon .lanspeed-header h3{font-size:1.3rem;line-height:1.25!important}',
			'.lanspeed-theme-argon .lanspeed-body{padding:.7rem 1rem}',
			'.lanspeed-theme-argon .lanspeed-stats-card>.lanspeed-body{padding:4px 1rem 2px}',
			'.lanspeed-theme-argon .lanspeed-clients-card>.lanspeed-body,',
			'.lanspeed-theme-argon .lanspeed-ifaces-card>.lanspeed-body{padding:0}',
			'.lanspeed-theme-argon .lanspeed-metric{min-height:3.6rem;padding:6px 12px}',
			'.lanspeed-theme-argon .lanspeed-stat-value{font-size:18px}',
		'}'
	].join('\n')
});
