'use strict';
'require baseclass';

/* Shared compact-screen rules.  Rows become labelled records before the page
 * reaches phone width, so no diagnostic table can widen the viewport. */
var ROOT = '.lanspeed-diagnostics-root';
var TABLE_NAMES = [
	'.lanspeed-diagnostics-health-table',
	'.lanspeed-diagnostics-subsystem-table',
	'.lanspeed-diagnostics-rpc-table'
];

function tableSelectors(suffix) {
	return TABLE_NAMES.map(function(name) {
		return ROOT + ' ' + name + (suffix ? ' ' + suffix : '');
	}).join(',');
}

var TABLES = tableSelectors('');
var TABLE_CAPTIONS = tableSelectors('caption');
var TABLE_HEADS = tableSelectors('thead');
var TABLE_BODIES = tableSelectors('tbody');
var TABLE_ROWS = tableSelectors('tbody>tr');
var TABLE_LAST_ROWS = tableSelectors('tbody>tr:last-child');
var TABLE_CELLS = tableSelectors('tbody>tr>td');
var TABLE_LABELLED_CELLS = tableSelectors('tbody>tr>td[data-label]::before');
var TABLE_SPANNING_CELLS = tableSelectors('tbody>tr>td[colspan]');
var RESPONSIVE_CSS = [
	'@media (max-width:1100px){',
		ROOT + ' .lanspeed-diagnostics-facts,' + ROOT + ' .lanspeed-diagnostics-pipeline{grid-template-columns:repeat(2,minmax(0,1fr))}',
		ROOT + ' .lanspeed-diagnostic-fact:nth-child(odd),' + ROOT + ' .lanspeed-diagnostic-stage:nth-child(odd){padding-left:0;border-left:0}',
		ROOT + ' .lanspeed-diagnostic-stage:nth-child(3){padding-left:0}',
		ROOT + ' .lanspeed-diagnostic-fact:nth-child(n+3),' + ROOT + ' .lanspeed-diagnostic-stage:nth-child(n+3){border-top:1px solid var(--lanspeed-border);padding-top:.75em}',
	'}',
	'@media (max-width:900px){',
		ROOT + ' .lanspeed-diagnostic-stage-evidence{grid-template-columns:minmax(0,1fr)}',
		ROOT + ' .lanspeed-diagnostic-stage-evidence dd{text-align:left}',
	'}',
	'@media (max-width:700px){',
		ROOT + '{width:100%;min-width:0;max-width:100%;overflow-x:hidden}',
		ROOT + '>.cbi-section{min-width:0;max-width:100%}',
		ROOT + ' .lanspeed-header{align-items:flex-start;gap:.5em}',
		ROOT + ' .lanspeed-header>.sum,' + ROOT + ' .lanspeed-header>.meta{flex:1 1 100%;text-align:left}',
		ROOT + ' .lanspeed-header>.cbi-button{margin-left:auto}',
		ROOT + ' .lanspeed-diagnostics-facts,' + ROOT + ' .lanspeed-diagnostics-pipeline{grid-template-columns:minmax(0,1fr)}',
		ROOT + ' .lanspeed-diagnostic-fact,' + ROOT + ' .lanspeed-diagnostic-stage{min-height:0;padding:.75em 0;',
			'border-left:0;border-top:1px solid var(--lanspeed-border)}',
		ROOT + ' .lanspeed-diagnostic-fact:first-child,' + ROOT + ' .lanspeed-diagnostic-stage:first-child{padding-top:0;border-top:0}',
		ROOT + ' .lanspeed-diagnostics-table-wrap{overflow-x:hidden}',
		TABLES + '{display:block;width:100%;min-width:0;max-width:100%}',
		TABLE_CAPTIONS + '{display:block;width:100%}',
		TABLE_HEADS + '{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);',
			'clip-path:inset(50%);white-space:nowrap}',
		TABLE_BODIES + '{display:block;width:100%;min-width:0}',
		TABLE_ROWS + '{display:grid;grid-template-columns:minmax(0,1fr);gap:.35em;',
			'width:100%;min-width:0;padding:.7em 0;border-bottom:1px solid var(--lanspeed-border)}',
		TABLE_LAST_ROWS + '{border-bottom:0}',
		TABLE_CELLS + '{display:grid;grid-template-columns:minmax(5em,.42fr) minmax(0,1fr);gap:.65em;',
			'width:100%;min-width:0;padding:.12em 0;border:0;text-align:left;overflow-wrap:anywhere}',
		TABLE_LABELLED_CELLS + '{content:attr(data-label);color:var(--lanspeed-text-muted);',
			'font-size:.78em;font-weight:650;line-height:1.35}',
		TABLE_SPANNING_CELLS + '{display:block;text-align:left}',
		ROOT + ' .lanspeed-diagnostics-rpc-details .lanspeed-diagnostics-table-wrap{padding-top:.55em}',
	'}',
	'@media (max-width:480px){',
		ROOT + ' .lanspeed-header>.cbi-button{width:100%;margin-left:0}',
		ROOT + ' .lanspeed-diagnostics-state{display:block}',
		ROOT + ' .lanspeed-diagnostics-state strong{display:block;margin-bottom:.2em}',
		ROOT + ' .lanspeed-diagnostic-stage-heading{align-items:flex-start}',
		ROOT + ' .lanspeed-diagnostic-stage-badge{white-space:normal;text-align:right}',
		ROOT + ' .lanspeed-diagnostic-stage-evidence{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}',
		ROOT + ' .lanspeed-diagnostic-stage-evidence dd{text-align:right}',
		ROOT + ' .lanspeed-diagnostics-report-preview{font-size:.7em}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: RESPONSIVE_CSS
});
