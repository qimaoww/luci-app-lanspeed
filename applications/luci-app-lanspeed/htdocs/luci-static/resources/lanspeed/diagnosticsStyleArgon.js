'use strict';
'require baseclass';

/* Argon-only diagnostics overrides. */
var ARGON_CSS = [
	'.lanspeed-diagnostics-root.lanspeed-theme-argon{gap:1rem;font-size:1rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostics-header{padding:.95rem 1.25rem .8rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostics-body{padding:1rem 1.25rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostics-header>h3{font-size:1.35rem;line-height:1.25!important}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostics-toolbar{align-items:center}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostics-intro{font-size:1rem;padding:0}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostics-refresh{font-size:1rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .label{display:inline-flex;align-items:center;justify-content:center;',
	'  min-height:1.75rem;padding:.3rem .7rem!important;box-sizing:border-box;line-height:1.15!important}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostic-card{padding-top:.25rem;padding-bottom:.25rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostic-value{font-size:1.2rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostic-description,',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostic-meta{padding:0}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostic-alerts-title{padding:0!important;',
	'  border:0!important;width:auto!important;background:transparent!important;box-shadow:none!important;',
	'  color:inherit!important;font-size:.9rem!important;line-height:1.35!important}',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostic-alert,',
	'.lanspeed-diagnostics-root.lanspeed-theme-argon .lanspeed-diagnostic-alert-empty{font-size:.92rem}'
].join('\n');

return baseclass.extend({
	CSS: ARGON_CSS
});
