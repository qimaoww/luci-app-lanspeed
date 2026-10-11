'use strict';
'require baseclass';

/* Argon: compact flat rows with a primary rail. */
var ROOT = '.lanspeed-diagnostics-root.lanspeed-theme-argon';
var ARGON_CSS = [
	ROOT + '{gap:1rem;font-size:1rem}',
	ROOT + ' .lanspeed-header{padding:.95rem 1.25rem .8rem;gap:.4em 1em}',
	ROOT + ' .lanspeed-header>h3{font-size:1.3rem;line-height:1.25!important}',
	ROOT + ' .lanspeed-header>.sum{padding-left:.55rem;border-left:.18rem solid var(--lanspeed-accent-safe)}',
	ROOT + ' .lanspeed-body{padding:.85rem 1.25rem 1rem}',
	ROOT + ' .lanspeed-diagnostics-state{border-radius:var(--lanspeed-radius-control);box-shadow:none}',
	ROOT + ' .lanspeed-diagnostic-fact{padding:.15rem .9rem;border-left:.18rem solid var(--lanspeed-border-strong)}',
	ROOT + ' .lanspeed-diagnostic-fact:first-child{padding-left:0;border-left:0}',
	ROOT + ' .lanspeed-diagnostic-fact[data-state="good"]{border-left-color:var(--lanspeed-normal)}',
	ROOT + ' .lanspeed-diagnostic-fact[data-state="warning"]{border-left-color:var(--lanspeed-warning)}',
	ROOT + ' .lanspeed-diagnostic-fact[data-state="bad"]{border-left-color:var(--lanspeed-danger)}',
	ROOT + ' .lanspeed-diagnostics-health-table{font-size:.84rem}',
	ROOT + ' .lanspeed-diagnostics-health-table :is(th,td){padding:.52rem .62rem}',
	ROOT + ' .lanspeed-diagnostic-alert{border-radius:var(--lanspeed-radius-control);box-shadow:none}',
	'@media (max-width:700px){',
		ROOT + ' .lanspeed-header{padding:.8rem 1rem .65rem}',
		ROOT + ' .lanspeed-body{padding:.75rem 1rem .85rem}',
		ROOT + ' .lanspeed-diagnostic-fact{padding:.1rem .65rem}',
		ROOT + ' .lanspeed-header>.sum{padding-left:.45rem}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: ARGON_CSS
});
