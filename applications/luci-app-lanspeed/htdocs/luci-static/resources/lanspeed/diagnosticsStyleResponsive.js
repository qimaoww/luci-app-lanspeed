'use strict';
'require baseclass';

/* Keep the four facts in two columns on phones. The three-column interface
 * table remains a table, avoiding repeated labels and tall mobile records. */
var ROOT = '.lanspeed-diagnostics-root';
var RESPONSIVE_CSS = [
	'@media (max-width:1100px){',
		ROOT + ' .lanspeed-diagnostics-facts{grid-template-columns:repeat(2,minmax(0,1fr));row-gap:.65em}',
		ROOT + ' .lanspeed-diagnostic-fact:nth-child(odd){padding-left:0;border-left:0}',
		ROOT + ' .lanspeed-diagnostic-fact:nth-child(even){padding-right:0}',
		ROOT + ' .lanspeed-diagnostic-fact:nth-child(n+3){border-top:1px solid var(--lanspeed-border);padding-top:.65em}',
	'}',
	'@media (max-width:700px){',
		ROOT + '{flex:1 1 auto;width:auto;min-width:0;max-width:100%}',
		ROOT + '>.cbi-section{min-width:0;max-width:100%}',
		ROOT + ' .lanspeed-header>.sum{flex:0 1 auto}',
		ROOT + ' .lanspeed-diagnostics-primary-header>h3{flex:1 1 auto}',
		ROOT + ' .lanspeed-diagnostics-primary-header>.label{flex:0 0 auto}',
		ROOT + ' .lanspeed-diagnostics-primary-header>.spacer{display:none}',
		ROOT + ' .lanspeed-diagnostics-primary-header>.meta{flex:0 0 100%;text-align:left;font-size:.72em}',
		ROOT + ' .lanspeed-diagnostics-primary-header>.cbi-button{flex:1 1 auto;width:auto;min-width:0;',
			'box-sizing:border-box;padding-left:.45em;padding-right:.45em}',
	'}',
	'@media (max-width:480px){',
		ROOT + ' .lanspeed-diagnostics-state{display:block}',
		ROOT + ' .lanspeed-diagnostics-state strong{display:block;margin-bottom:.2em}',
		ROOT + ' .lanspeed-diagnostics-health-table :is(th,td){padding:.45em .35em}',
	'}'
].join('\n');

return baseclass.extend({
	CSS: RESPONSIVE_CSS
});
