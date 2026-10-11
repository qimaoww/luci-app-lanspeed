'use strict';
'require baseclass';

/* Aurora: open bands on the native elevated section surface. */
var ROOT = '.lanspeed-diagnostics-root.lanspeed-theme-aurora';
var AURORA_CSS = [
	ROOT + '{gap:var(--lanspeed-page-gap)}',
	ROOT + '>.cbi-section{padding:var(--lanspeed-section-x);overflow:visible}',
	ROOT + ' .lanspeed-header{margin:0 0 var(--lanspeed-section-y);',
		'padding:0 0 var(--lanspeed-section-y);background:transparent;gap:.45rem .75rem}',
	ROOT + ' .lanspeed-header>h3{font-size:1.2rem}',
	ROOT + ' .lanspeed-body{padding:0}',
	ROOT + ' .lanspeed-diagnostics-state{border-radius:var(--lanspeed-radius-control);box-shadow:var(--lanspeed-shadow-raised)}',
	ROOT + ' .lanspeed-diagnostic-fact{padding:.2rem 1rem}',
	ROOT + ' .lanspeed-diagnostic-fact:first-child{padding-left:0}',
	ROOT + ' .lanspeed-diagnostic-fact-label{font-size:.72rem}',
	ROOT + ' .lanspeed-diagnostic-fact-value{font-size:1.1rem}',
	ROOT + ' .lanspeed-diagnostics-health-table{font-size:.84rem}',
	ROOT + ' .lanspeed-diagnostics-health-table :is(th,td){padding:.56rem .62rem}',
	ROOT + ' .lanspeed-diagnostic-alert{',
		'border-radius:var(--lanspeed-radius-section);box-shadow:var(--lanspeed-shadow-raised)}',
	'@media (max-width:700px){',
		ROOT + '>.cbi-section{padding:calc(var(--spacing,.25rem)*4)}',
		ROOT + ' .lanspeed-header{margin-bottom:.8rem;padding:0 0 .65rem}',
		ROOT + ' .lanspeed-body{padding:0}',
		ROOT + ' .lanspeed-diagnostic-fact{padding:.1rem .7rem}',
		ROOT + ' .lanspeed-diagnostics-health-table{font-size:.82rem}',
		ROOT + ' .lanspeed-diagnostic-alert{border-radius:var(--lanspeed-radius-control)}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: AURORA_CSS
});
