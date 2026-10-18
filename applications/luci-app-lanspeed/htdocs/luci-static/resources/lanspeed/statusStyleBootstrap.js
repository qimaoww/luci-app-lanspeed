'use strict';
'require baseclass';
/*
 * Bootstrap: native borders, banded rows and one card per metric. The head and
 * the section body spacing mirror the configuration and diagnostics pages.
 */
return baseclass.extend({
	__name__: 'LuCILanspeedStatusStyleBootstrap',
	CSS: [
		'.lanspeed-root.lanspeed-theme-bootstrap{gap:.75rem;font-size:.92rem}',
		'.lanspeed-root.lanspeed-theme-bootstrap .lanspeed-header{gap:.4em 1em;',
			'padding:.72rem 1rem .58rem;border-bottom-color:var(--lanspeed-border-strong)}',
		'.lanspeed-root.lanspeed-theme-bootstrap .lanspeed-header h3{font-size:1.08rem!important;letter-spacing:normal!important}',
		'.lanspeed-theme-bootstrap .lanspeed-body{padding:.62rem 1rem .82rem}',
		'.lanspeed-theme-bootstrap .lanspeed-stats-card>.lanspeed-body{padding:6px 0 4px}',
		'.lanspeed-theme-bootstrap .lanspeed-clients-card>.lanspeed-body,',
		'.lanspeed-theme-bootstrap .lanspeed-ifaces-card>.lanspeed-body{padding:0}',
		'.lanspeed-theme-bootstrap .lanspeed-metrics{grid-template-columns:repeat(4,minmax(0,1fr));',
			'align-items:stretch}',
		'.lanspeed-theme-bootstrap .lanspeed-metric{min-height:5.35rem;padding:8px 10px;',
			'border:1px solid var(--lanspeed-border-strong);border-top:2px solid var(--lanspeed-accent);',
			'border-left:1px solid var(--lanspeed-border-strong);border-radius:var(--lanspeed-radius-control);',
			'background:var(--lanspeed-surface);box-shadow:none}',
		'.lanspeed-theme-bootstrap .lanspeed-metric:first-child{',
			'border-left:1px solid var(--lanspeed-border-strong)}',
		'.lanspeed-theme-bootstrap .lanspeed-stat-value{font-size:20px}',
		'.lanspeed-theme-bootstrap .lanspeed-toolbar{padding:8px 0}',
		'.lanspeed-theme-bootstrap .lanspeed-pagination{padding:8px 0}',
		'.lanspeed-theme-bootstrap .lanspeed-details>summary{padding-left:0;padding-right:0}',
		'.lanspeed-theme-bootstrap .lanspeed-details-body{padding-left:0;padding-right:0}',
		'.lanspeed-theme-bootstrap .lanspeed-empty{margin-left:0;margin-right:0}',
		'.lanspeed-theme-bootstrap .lanspeed-table :is(th,td){padding:6px 8px}',
		'.lanspeed-theme-bootstrap .lanspeed-table thead th{background:var(--lanspeed-surface-muted)}',
		'.lanspeed-theme-bootstrap .lanspeed-table tbody tr:nth-child(even){',
			'background:var(--lanspeed-surface-muted)}',
		'@media (max-width:800px){',
			'.lanspeed-root.lanspeed-theme-bootstrap .lanspeed-header{padding:.65rem .72rem .55rem}',
			'.lanspeed-theme-bootstrap .lanspeed-body{padding:.55rem .72rem .7rem}',
			'.lanspeed-theme-bootstrap .lanspeed-stats-card>.lanspeed-body{padding:6px 0 4px}',
		'}'
	].join('\n')
});
