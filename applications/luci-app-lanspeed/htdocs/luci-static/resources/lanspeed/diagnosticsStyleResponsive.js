'use strict';
'require baseclass';

/* Shared narrow-screen rules for every supported LuCI theme. */
var RESPONSIVE_CSS = [
	'@media (max-width:900px){.lanspeed-diagnostics-root .lanspeed-diagnostic-grid{grid-template-columns:minmax(0,1fr)}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostic-card,',
	'.lanspeed-diagnostics-root .lanspeed-diagnostic-card:first-child,',
	'.lanspeed-diagnostics-root .lanspeed-diagnostic-card:last-child{min-height:0;padding:.85em 0;',
	'  border-right:0;border-bottom:1px solid var(--border,rgba(128,128,128,.18))}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostic-card:first-child{padding-top:0}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostic-card:last-child{padding-bottom:0;border-bottom:0}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostic-description{min-height:0}}',
	'@media (max-width:700px){.lanspeed-diagnostics-root .lanspeed-diagnostics-header{padding:.85rem 1rem .7rem}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostics-body{padding:.85rem 1rem}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostics-toolbar{align-items:stretch}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostics-intro{flex:1 1 100%}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostics-refresh{margin-left:auto}}',
	'@media (max-width:480px){.lanspeed-diagnostics-root .lanspeed-diagnostics-header{display:grid;',
	'  grid-template-columns:minmax(0,1fr) auto;gap:.45em .7em}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostics-header>h3{grid-column:1}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostics-header>.spacer{display:none}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostics-summary{grid-column:2;grid-row:1}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostics-meta{grid-column:1/-1;white-space:normal}',
	'.lanspeed-diagnostics-root .lanspeed-diagnostics-refresh{width:100%;margin:0}}'
].join('\n');

return baseclass.extend({
	CSS: RESPONSIVE_CSS
});
