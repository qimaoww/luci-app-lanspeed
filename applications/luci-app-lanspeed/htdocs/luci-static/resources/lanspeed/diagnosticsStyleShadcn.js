'use strict';
'require baseclass';

/* shadcn: one bordered card per task with banded facts, stages and tables. */
var ROOT = '.lanspeed-diagnostics-root.lanspeed-theme-shadcn';
var SHADCN_CSS = [
	ROOT + '{gap:var(--lanspeed-page-gap);font-size:.94rem}',
	ROOT + '>.cbi-section{padding:0}',
	ROOT + ' .lanspeed-header{gap:.4em 1em;padding:.85rem 1.15rem .72rem;',
		'border-bottom-color:var(--lanspeed-border)}',
	ROOT + ' .lanspeed-header>h3{font-size:1.05rem}',
	ROOT + ' .lanspeed-body{padding:.85rem 1.15rem 1rem}',
	ROOT + ' .lanspeed-diagnostics-state{border-radius:var(--lanspeed-radius-control);',
		'box-shadow:var(--lanspeed-shadow-raised)}',
	ROOT + ' .lanspeed-diagnostic-fact{min-height:4.7rem;padding:.15rem .85rem;',
		'border-left:1px solid var(--lanspeed-border)}',
	ROOT + ' .lanspeed-diagnostic-fact:first-child{padding-left:0;border-left:0}',
	ROOT + ' .lanspeed-diagnostic-fact-label{font-size:.72rem}',
	ROOT + ' .lanspeed-diagnostic-fact-value{font-size:1.05rem}',
	ROOT + ' .lanspeed-diagnostic-stage{min-height:8rem;padding:.15rem .85rem;',
		'border-left:1px solid var(--lanspeed-border)}',
	ROOT + ' .lanspeed-diagnostic-stage:first-child{padding-left:0;border-left:0}',
	ROOT + ' .lanspeed-diagnostic-stage-heading>h4{font-size:.72rem}',
	ROOT + ' .lanspeed-diagnostic-stage-heading>h4,' + ROOT + ' .lanspeed-diagnostic-alert-text{',
		'color:var(--lanspeed-text)}',
	ROOT + ' .lanspeed-diagnostic-stage-value{font-size:1rem}',
	ROOT + ' .lanspeed-diagnostics-health-body,' + ROOT + ' .lanspeed-diagnostics-support-body{gap:.9rem}',
	ROOT + ' .lanspeed-diagnostics-health-group>h4,' + ROOT + ' .lanspeed-diagnostics-alert-group>h4{',
		'font-size:.82rem}',
	ROOT + ' .lanspeed-diagnostics-health-table,' + ROOT + ' .lanspeed-diagnostics-subsystem-table,',
	ROOT + ' .lanspeed-diagnostics-rpc-table,' + ROOT + ' .lanspeed-diagnostics-tc-conflict-table,',
	ROOT + ' .lanspeed-diagnostics-tc-table{font-size:.8rem}',
	ROOT + ' .lanspeed-diagnostics-health-table :is(th,td),' + ROOT + ' .lanspeed-diagnostics-subsystem-table :is(th,td),',
	ROOT + ' .lanspeed-diagnostics-rpc-table :is(th,td),' + ROOT + ' .lanspeed-diagnostics-tc-conflict-table :is(th,td),',
	ROOT + ' .lanspeed-diagnostics-tc-table :is(th,td){padding:.5rem .58rem}',
	ROOT + ' .lanspeed-diagnostics-health-table thead th,' + ROOT + ' .lanspeed-diagnostics-subsystem-table thead th,',
	ROOT + ' .lanspeed-diagnostics-rpc-table thead th,' + ROOT + ' .lanspeed-diagnostics-tc-conflict-table thead th,',
	ROOT + ' .lanspeed-diagnostics-tc-table thead th{background:var(--lanspeed-surface-muted)}',
	ROOT + ' .lanspeed-diagnostic-alert,' + ROOT + ' .lanspeed-diagnostic-alert-empty{',
		'padding:.55rem .68rem;border-radius:var(--lanspeed-radius-control);',
		'box-shadow:var(--lanspeed-shadow-raised);font-size:.82rem}',
	ROOT + ' .lanspeed-diagnostics-report-preview{border-radius:var(--lanspeed-radius-compact);',
		'box-shadow:var(--lanspeed-shadow-raised)}',
	'@media (max-width:900px){' + ROOT + ' .lanspeed-diagnostic-fact:nth-child(odd),',
		ROOT + ' .lanspeed-diagnostic-stage:nth-child(odd){padding-left:0;border-left:0}}',
	'@media (max-width:700px){',
		ROOT + ' .lanspeed-header{padding:.7rem .85rem .6rem}',
		ROOT + ' .lanspeed-body{padding:.7rem .85rem .85rem}',
		ROOT + ' .lanspeed-diagnostic-fact,' + ROOT + ' .lanspeed-diagnostic-stage{padding:.65rem 0;',
			'border-left:0;border-top:1px solid var(--lanspeed-border)}',
		ROOT + ' .lanspeed-diagnostic-fact:first-child,' + ROOT + ' .lanspeed-diagnostic-stage:first-child{padding-top:0;border-top:0}',
		ROOT + ' .lanspeed-diagnostic-alert,' + ROOT + ' .lanspeed-diagnostic-alert-empty{box-shadow:none}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: SHADCN_CSS
});
