'use strict';
'require baseclass';

/* shadcn: bordered sections with compact facts and interface rows. */
var ROOT = '.lanspeed-diagnostics-root.lanspeed-theme-shadcn';
var SHADCN_CSS = [
	ROOT + '{gap:var(--lanspeed-page-gap);font-size:.94rem}',
	ROOT + '>.cbi-section{padding:0}',
	ROOT + ' .lanspeed-header{gap:.4em 1em;padding:.85rem 1.15rem .72rem;',
		'border-bottom-color:var(--lanspeed-border)}',
	ROOT + ' .lanspeed-header>h3{font-size:1.05rem}',
	ROOT + ' .lanspeed-body{padding:.75rem 1.15rem .9rem}',
	ROOT + ' .lanspeed-diagnostics-state{border-radius:var(--lanspeed-radius-control);',
		'box-shadow:var(--lanspeed-shadow-raised)}',
	ROOT + ' .lanspeed-diagnostic-fact{padding:.15rem .85rem;',
		'border-left:1px solid var(--lanspeed-border)}',
	ROOT + ' .lanspeed-diagnostic-fact:first-child{padding-left:0;border-left:0}',
	ROOT + ' .lanspeed-diagnostic-fact-label{font-size:.72rem}',
	ROOT + ' .lanspeed-diagnostic-fact-value{font-size:1.05rem}',
	ROOT + ' .lanspeed-diagnostic-alert-text{color:var(--lanspeed-text)}',
	ROOT + ' .lanspeed-diagnostics-health-table{font-size:.8rem}',
	ROOT + ' .lanspeed-diagnostics-health-table :is(th,td){padding:.5rem .58rem}',
	ROOT + ' .lanspeed-diagnostics-health-table thead th{background:var(--lanspeed-surface-muted)}',
	ROOT + ' .lanspeed-diagnostic-alert{',
		'padding:.55rem .68rem;border-radius:var(--lanspeed-radius-control);',
		'box-shadow:var(--lanspeed-shadow-raised);font-size:.82rem}',
	'@media (max-width:700px){',
		ROOT + ' .lanspeed-header{padding:.7rem .85rem .6rem}',
		ROOT + ' .lanspeed-body{padding:.65rem .85rem .8rem}',
		ROOT + ' .lanspeed-diagnostic-fact{padding:.1rem .65rem}',
		ROOT + ' .lanspeed-diagnostic-alert{box-shadow:none}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: SHADCN_CSS
});
