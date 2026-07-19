'use strict';
'require baseclass';

/* Argon: dense, flat rows with a primary rail and no extra elevation. */
var ROOT = '.lanspeed-diagnostics-root.lanspeed-theme-argon';
var ARGON_CSS = [
	ROOT + '{gap:1rem;font-size:1rem}',
	ROOT + ' .lanspeed-header{padding:.95rem 1.25rem .8rem}',
	ROOT + ' .lanspeed-header>h3{font-size:1.3rem;line-height:1.25!important}',
	ROOT + ' .lanspeed-header{gap:.4em 1em}',
	ROOT + ' .lanspeed-header>.sum{padding-left:.55rem;border-left:.18rem solid var(--lanspeed-accent-safe)}',
	ROOT + ' .lanspeed-body{padding:1rem 1.25rem 1.1rem}',
	ROOT + ' .lanspeed-diagnostics-state{border-radius:var(--lanspeed-radius-control);box-shadow:none}',
	ROOT + ' .lanspeed-diagnostic-fact{min-height:4.8rem;padding:.15rem .9rem;border-left:.18rem solid var(--lanspeed-border-strong)}',
	ROOT + ' .lanspeed-diagnostic-fact:first-child{padding-left:0;border-left:0}',
	ROOT + ' .lanspeed-diagnostic-fact[data-state="good"]{border-left-color:var(--lanspeed-normal)}',
	ROOT + ' .lanspeed-diagnostic-fact[data-state="warning"]{border-left-color:var(--lanspeed-warning)}',
	ROOT + ' .lanspeed-diagnostic-fact[data-state="bad"]{border-left-color:var(--lanspeed-danger)}',
	ROOT + ' .lanspeed-diagnostic-stage{min-height:8.7rem;padding:.15rem .9rem;border-left:.18rem solid var(--lanspeed-border-strong)}',
	ROOT + ' .lanspeed-diagnostic-stage:first-child{padding-left:0;border-left:0}',
	ROOT + ' .lanspeed-diagnostic-stage[data-state="good"]{border-left-color:var(--lanspeed-normal)}',
	ROOT + ' .lanspeed-diagnostic-stage[data-state="warning"]{border-left-color:var(--lanspeed-warning)}',
	ROOT + ' .lanspeed-diagnostic-stage[data-state="bad"]{border-left-color:var(--lanspeed-danger)}',
	ROOT + ' .lanspeed-diagnostic-stage-heading>h4{font-size:.74rem;line-height:1.3!important}',
	ROOT + ' .lanspeed-diagnostic-stage-value{font-size:1.05rem}',
	ROOT + ' .lanspeed-diagnostics-health-group>h4,' + ROOT + ' .lanspeed-diagnostics-alert-group>h4{line-height:1.35!important}',
	ROOT + ' .lanspeed-diagnostics-health-group>h4,' + ROOT + ' .lanspeed-diagnostics-subheading>h4,' +
		ROOT + ' .lanspeed-diagnostics-report-details>h4{',
		'color:var(--lanspeed-text)!important}',
	ROOT + ' .lanspeed-diagnostics-health-body,' + ROOT + ' .lanspeed-diagnostics-support-body{gap:.9rem}',
	ROOT + ' .lanspeed-diagnostics-health-table,' + ROOT + ' .lanspeed-diagnostics-subsystem-table,',
	ROOT + ' .lanspeed-diagnostics-rpc-table{font-size:.84rem}',
	ROOT + ' .lanspeed-diagnostics-health-table :is(th,td),' + ROOT + ' .lanspeed-diagnostics-subsystem-table :is(th,td),',
	ROOT + ' .lanspeed-diagnostics-rpc-table :is(th,td){padding:.52rem .62rem}',
	ROOT + ' .lanspeed-diagnostic-alert,' + ROOT + ' .lanspeed-diagnostic-alert-empty{border-radius:var(--lanspeed-radius-control);box-shadow:none}',
	ROOT + ' .lanspeed-diagnostics-report-preview{border-radius:var(--lanspeed-radius-compact);box-shadow:none}',
	'@media (max-width:900px){' + ROOT + ' .lanspeed-diagnostic-fact:nth-child(odd),',
		ROOT + ' .lanspeed-diagnostic-stage:nth-child(odd){padding-left:0;border-left:0}}',
	'@media (max-width:700px){',
		ROOT + ' .lanspeed-header{padding:.85rem 1rem .7rem}',
		ROOT + ' .lanspeed-header{gap:.4em 1em}',
		ROOT + ' .lanspeed-body{padding:.8rem 1rem .9rem}',
		ROOT + ' .lanspeed-diagnostic-fact,' + ROOT + ' .lanspeed-diagnostic-stage{padding:.7rem 0;',
			'border-left:0;border-top:1px solid var(--lanspeed-border)}',
		ROOT + ' .lanspeed-diagnostic-fact:first-child,' + ROOT + ' .lanspeed-diagnostic-stage:first-child{padding-top:0;border-top:0}',
		ROOT + ' .lanspeed-header>.sum{padding-left:.45rem}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: ARGON_CSS
});
