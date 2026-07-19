'use strict';
'require baseclass';

/* Aurora: open, spacious bands on the native elevated section surface. */
var ROOT = '.lanspeed-diagnostics-root.lanspeed-theme-aurora';
var AURORA_CSS = [
	ROOT + '{gap:var(--lanspeed-page-gap)}',
	ROOT + ' .lanspeed-header{padding:1rem 1.25rem .85rem;gap:.45rem .75rem}',
	ROOT + ' .lanspeed-header>h3{font-size:1.2rem}',
	ROOT + ' .lanspeed-body{padding:1rem 1.25rem 1.2rem}',
	ROOT + ' .lanspeed-diagnostics-summary-body{gap:.9rem}',
	ROOT + ' .lanspeed-diagnostics-intro{font-size:.9rem}',
	ROOT + ' .lanspeed-diagnostics-state{border-radius:var(--lanspeed-radius-control);box-shadow:var(--lanspeed-shadow-raised)}',
	ROOT + ' .lanspeed-diagnostic-fact{min-height:5rem;padding:.2rem 1.1rem}',
	ROOT + ' .lanspeed-diagnostic-fact:first-child{padding-left:0}',
	ROOT + ' .lanspeed-diagnostic-fact-label{font-size:.72rem}',
	ROOT + ' .lanspeed-diagnostic-fact-value{font-size:1.1rem}',
	ROOT + ' .lanspeed-diagnostic-stage{min-height:9rem;padding:.2rem 1.1rem}',
	ROOT + ' .lanspeed-diagnostic-stage:first-child{padding-left:0}',
	ROOT + ' .lanspeed-diagnostic-stage-heading>h4{font-size:.76rem}',
	ROOT + ' .lanspeed-diagnostic-stage-value{font-size:1.04rem}',
	ROOT + ' .lanspeed-diagnostics-health-body,' + ROOT + ' .lanspeed-diagnostics-support-body{gap:1.15rem}',
	ROOT + ' .lanspeed-diagnostics-health-group>h4,' + ROOT + ' .lanspeed-diagnostics-alert-group>h4{font-size:.88rem}',
	ROOT + ' .lanspeed-diagnostics-health-table,' + ROOT + ' .lanspeed-diagnostics-subsystem-table,',
	ROOT + ' .lanspeed-diagnostics-rpc-table{font-size:.84rem}',
	ROOT + ' .lanspeed-diagnostics-health-table :is(th,td),' + ROOT + ' .lanspeed-diagnostics-subsystem-table :is(th,td),',
	ROOT + ' .lanspeed-diagnostics-rpc-table :is(th,td){padding:.56rem .62rem}',
	ROOT + ' .lanspeed-diagnostic-alert,' + ROOT + ' .lanspeed-diagnostic-alert-empty{',
		'border-radius:var(--lanspeed-radius-section);box-shadow:var(--lanspeed-shadow-raised)}',
	ROOT + ' .lanspeed-diagnostics-report-preview{border-radius:var(--lanspeed-radius-compact);box-shadow:var(--lanspeed-shadow-raised)}',
	'@media (max-width:900px){' + ROOT + ' .lanspeed-diagnostic-fact:nth-child(odd),',
		ROOT + ' .lanspeed-diagnostic-stage:nth-child(odd){padding-left:0;border-left:0}}',
	'@media (max-width:700px){',
		ROOT + ' .lanspeed-header{padding:.85rem 1rem .7rem}',
		ROOT + ' .lanspeed-body{padding:.85rem 1rem 1rem}',
		ROOT + ' .lanspeed-diagnostic-fact,' + ROOT + ' .lanspeed-diagnostic-stage{padding:.75rem 0;',
			'border-left:0;border-top:1px solid var(--lanspeed-border)}',
		ROOT + ' .lanspeed-diagnostic-fact:first-child,' + ROOT + ' .lanspeed-diagnostic-stage:first-child{padding-top:0;border-top:0}',
		ROOT + ' .lanspeed-diagnostics-health-table,' + ROOT + ' .lanspeed-diagnostics-subsystem-table,',
		ROOT + ' .lanspeed-diagnostics-rpc-table{font-size:.82rem}',
		ROOT + ' .lanspeed-diagnostic-alert,' + ROOT + ' .lanspeed-diagnostic-alert-empty{border-radius:var(--lanspeed-radius-control)}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: AURORA_CSS
});
