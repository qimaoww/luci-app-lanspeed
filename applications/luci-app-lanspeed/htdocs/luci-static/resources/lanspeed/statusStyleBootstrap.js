'use strict';
'require baseclass';

/* Bootstrap keeps the classic compact table and banded-header treatment. */
var BOOTSTRAP_CSS = [
	'.lanspeed-root.lanspeed-theme-bootstrap{gap:var(--lanspeed-page-gap);font-size:.92rem}',
	'.lanspeed-root.lanspeed-theme-bootstrap>.cbi-section{padding:0}',
	'.lanspeed-theme-bootstrap :is(.lanspeed-header,.lanspeed-details>summary){',
		'padding:.72rem 1rem .58rem;border-bottom-color:var(--lanspeed-border-strong)}',
	'.lanspeed-theme-bootstrap :is(.lanspeed-body,.lanspeed-details-body){padding:.72rem 1rem .85rem}',
	'.lanspeed-theme-bootstrap :is(.lanspeed-header,.lanspeed-details>summary) h3{font-size:1.08rem}',
	'.lanspeed-theme-bootstrap .lanspeed-header>.meta,',
	'.lanspeed-theme-bootstrap .lanspeed-details>summary .sum{font-size:.72rem}',
	'.lanspeed-theme-bootstrap .lanspeed-metrics{grid-template-columns:repeat(5,minmax(0,1fr));',
		'align-items:stretch;gap:.6rem}',
	'.lanspeed-theme-bootstrap .lanspeed-metric{display:grid;grid-template-rows:.9rem 1.85rem minmax(1rem,auto);',
		'align-content:start;align-self:stretch;min-width:0;min-height:5.35rem;padding:.58rem .65rem;',
		'border:1px solid var(--lanspeed-border-strong);border-top:2px solid var(--lanspeed-accent);',
		'border-left-color:var(--lanspeed-border-strong);border-radius:var(--lanspeed-radius-control);',
		'background:var(--lanspeed-surface);box-shadow:none}',
	'.lanspeed-theme-bootstrap .lanspeed-metric:first-child{border-left-color:var(--lanspeed-border-strong)}',
	'.lanspeed-theme-bootstrap .lanspeed-metric .caption{font-size:.7rem;letter-spacing:.02em}',
	'.lanspeed-theme-bootstrap .lanspeed-metric .big{display:flex;align-items:center;min-width:0;',
		'font-size:1.25rem;font-weight:650;line-height:1.18;white-space:nowrap}',
	'.lanspeed-theme-bootstrap .lanspeed-metric .hint{align-self:end;min-width:0;overflow:hidden;',
		'font-size:.72rem;text-overflow:ellipsis;white-space:nowrap}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-values{flex-wrap:nowrap;gap:.6rem}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-label{font-size:.52em}',
	'.lanspeed-theme-bootstrap .lanspeed-toolbar{gap:.5rem .75rem;margin-bottom:.65rem;padding-bottom:.62rem}',
	'.lanspeed-theme-bootstrap .lanspeed-toolbar label{font-size:.8rem}',
	'.lanspeed-theme-bootstrap .lanspeed-table :is(th,td){padding:.4rem .5rem;font-size:.82rem}',
	'.lanspeed-theme-bootstrap .lanspeed-table thead th{background:var(--lanspeed-surface-muted)}',
	'.lanspeed-theme-bootstrap .lanspeed-table tbody tr:nth-child(even){background:var(--lanspeed-surface-muted)}',
	'.lanspeed-theme-bootstrap .lanspeed-table tbody tr:nth-child(odd):hover{',
		'background:transparent!important;background-image:none!important}',
	'.lanspeed-theme-bootstrap .lanspeed-table tbody tr:nth-child(even):hover{',
		'background:var(--lanspeed-surface-muted)!important;background-image:none!important}',
	'@media (max-width:1100px){.lanspeed-theme-bootstrap .lanspeed-metrics{grid-template-columns:repeat(3,minmax(0,1fr));gap:.55rem}',
	'.lanspeed-theme-bootstrap .lanspeed-metric:nth-child(n){grid-column:auto}}',
	'@media (max-width:700px){',
	'.lanspeed-theme-bootstrap>.cbi-section,.lanspeed-theme-bootstrap .lanspeed-details{min-width:0;max-width:100%}',
	'.lanspeed-theme-bootstrap :is(.lanspeed-header,.lanspeed-details>summary){padding:.65rem .72rem .55rem}',
	'.lanspeed-theme-bootstrap :is(.lanspeed-body,.lanspeed-details-body){padding:.65rem .72rem .75rem}',
	'.lanspeed-theme-bootstrap .lanspeed-metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:.5rem}',
	'.lanspeed-theme-bootstrap .lanspeed-metric:nth-child(n){grid-column:auto;padding:.65rem .68rem}',
	'.lanspeed-theme-bootstrap .lanspeed-metric:last-child{grid-column:1/-1}}',
	'@media (max-width:480px){.lanspeed-theme-bootstrap .lanspeed-metric{padding:.58rem .55rem}',
	'.lanspeed-theme-bootstrap .lanspeed-metric .big{font-size:1.12rem}}'
].join('\n');

return baseclass.extend({
	CSS: BOOTSTRAP_CSS
});
