'use strict';
'require baseclass';

/* Aurora-only status layout overrides. Every selector stays Aurora-scoped. */
var AURORA_CSS = [
	'.lanspeed-theme-aurora{display:flex;flex-direction:column;gap:1rem;margin:0}',
	'.lanspeed-theme-aurora>.cbi-section{margin:0;padding:0;overflow:hidden}',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-body{overflow-x:auto}',
	'.lanspeed-theme-aurora .lanspeed-header,',
	'.lanspeed-theme-aurora .lanspeed-details>summary{padding:1rem 1.25rem .85rem;align-items:center}',
	'.lanspeed-theme-aurora .lanspeed-details>summary::before{align-self:center;line-height:1}',
	'.lanspeed-theme-aurora .lanspeed-body,',
	'.lanspeed-theme-aurora .lanspeed-details-body{padding:1rem 1.25rem}',
	'.lanspeed-theme-aurora .lanspeed-metrics{grid-template-columns:repeat(auto-fit,minmax(11em,12.5em));',
	'  justify-content:start;column-gap:1rem;row-gap:.9rem}',
	'.lanspeed-theme-aurora .lanspeed-metric .big{font-size:1.45rem}',
	'.lanspeed-theme-aurora .lanspeed-toolbar{gap:.65rem .9rem;margin-bottom:.85rem}',
	'.lanspeed-theme-aurora .lanspeed-toolbar input[type=search]{min-width:14rem;max-width:22rem}',
	'.lanspeed-theme-aurora .lanspeed-table th,',
	'.lanspeed-theme-aurora .lanspeed-table td{padding:.48rem .6rem}',
	'.lanspeed-theme-aurora .lanspeed-table .mono{font-size:.85em}',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table td:nth-child(2).mono{font-size:.95rem}',
	'.lanspeed-theme-aurora .label{display:inline-flex;align-items:center;',
	'  justify-content:center;vertical-align:middle}',
	'.lanspeed-theme-aurora .label.label-success{background-color:var(--success-surface);color:var(--success)}',
	'.lanspeed-theme-aurora .label.label-warning{background-color:var(--warning-surface);color:var(--warning)}',
	'.lanspeed-theme-aurora .label.label-danger{background-color:var(--danger-surface);color:var(--danger)}',
	'@media (min-width:901px){.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table{table-layout:fixed}',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table th:nth-child(1),.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table td:nth-child(1){width:18rem}',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table th:nth-child(2),.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-table td:nth-child(2){width:15rem}}',
	'.lanspeed-theme-aurora .lanspeed-table td .ipline{max-width:18rem}',
	'@media (max-width:700px){.lanspeed-theme-aurora .lanspeed-header,',
	'.lanspeed-theme-aurora .lanspeed-details>summary{padding:.85rem 1rem .7rem}',
	'.lanspeed-theme-aurora .lanspeed-body,',
	'.lanspeed-theme-aurora .lanspeed-details-body{padding:.85rem 1rem}',
	'.lanspeed-theme-aurora .lanspeed-toolbar-right{justify-content:flex-start}',
	'.lanspeed-theme-aurora .lanspeed-toolbar input[type=search]{min-width:0;width:100%;max-width:none}}',
	'@media (max-width:480px){.lanspeed-theme-aurora .lanspeed-metrics{',
	'  grid-template-columns:repeat(auto-fit,minmax(9rem,1fr))}}'
].join('\n');

return baseclass.extend({
	CSS: AURORA_CSS
});
