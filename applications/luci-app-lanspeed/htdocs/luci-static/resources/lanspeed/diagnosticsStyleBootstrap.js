'use strict';
'require baseclass';

/* Bootstrap: compact, bordered tables and native banded surfaces. */
var ROOT = '.lanspeed-diagnostics-root.lanspeed-theme-bootstrap';
var BOOTSTRAP_CSS = [
	ROOT + '{gap:.75rem;font-size:.92rem}',
	ROOT + ' .lanspeed-header{gap:.4em 1em;padding:.72rem 1rem .58rem;border-bottom-color:var(--lanspeed-border-strong)}',
	ROOT + ' .lanspeed-header>h3{font-size:1.08rem}',
	ROOT + ' .lanspeed-body{padding:.62rem 1rem .82rem}',
	ROOT + ' .lanspeed-diagnostics-state{border-radius:var(--lanspeed-radius-control);box-shadow:var(--lanspeed-shadow-raised)}',
	ROOT + ' .lanspeed-diagnostic-fact{padding:.15rem .7rem;border-left:1px solid var(--lanspeed-border-strong)}',
	ROOT + ' .lanspeed-diagnostic-fact:first-child{padding-left:0;border-left:0}',
	ROOT + ' .lanspeed-diagnostic-fact-label{font-size:.69rem}',
	ROOT + ' .lanspeed-diagnostic-fact-value{font-size:1rem}',
	ROOT + ' .lanspeed-diagnostic-alert-text{color:var(--lanspeed-text)}',
	ROOT + ' .lanspeed-diagnostics-health-table{font-size:.76rem}',
	ROOT + ' .lanspeed-diagnostics-health-table :is(th,td){padding:.4rem .48rem}',
	ROOT + ' .lanspeed-diagnostics-health-table thead th{background:var(--lanspeed-surface-muted)}',
	ROOT + ' .lanspeed-diagnostic-alert{',
		'padding:.52rem .6rem;border-radius:var(--lanspeed-radius-control);box-shadow:var(--lanspeed-shadow-raised);font-size:.78rem}',
	'@media (max-width:700px){',
		ROOT + ' .lanspeed-header{padding:.65rem .72rem .55rem}',
		ROOT + ' .lanspeed-body{padding:.62rem .72rem .75rem}',
		ROOT + ' .lanspeed-diagnostic-fact{padding:.1rem .6rem}',
		ROOT + ' .lanspeed-diagnostic-alert{box-shadow:none}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: BOOTSTRAP_CSS
});
