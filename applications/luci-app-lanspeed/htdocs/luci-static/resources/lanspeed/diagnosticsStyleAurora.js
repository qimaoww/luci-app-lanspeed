'use strict';
'require baseclass';

/* Aurora-only diagnostics overrides. */
var AURORA_CSS = [
	'.lanspeed-diagnostics-root.lanspeed-theme-aurora{gap:1rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-aurora .lanspeed-diagnostics-header{padding:1rem 1.25rem .85rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-aurora .lanspeed-diagnostics-body{padding:1rem 1.25rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-aurora .lanspeed-diagnostic-card{padding-top:.2rem;padding-bottom:.2rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-aurora .lanspeed-diagnostic-alert,',
	'.lanspeed-diagnostics-root.lanspeed-theme-aurora .lanspeed-diagnostic-alert-empty{border-radius:.75rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-aurora .label{display:inline-flex;align-items:center;',
	'  justify-content:center;vertical-align:middle}',
	'.lanspeed-diagnostics-root.lanspeed-theme-aurora .label.label-success{background-color:var(--success-surface);color:var(--success)}',
	'.lanspeed-diagnostics-root.lanspeed-theme-aurora .label.label-warning{background-color:var(--warning-surface);color:var(--warning)}',
	'.lanspeed-diagnostics-root.lanspeed-theme-aurora .label.label-danger{background-color:var(--danger-surface);color:var(--danger)}'
].join('\n');

return baseclass.extend({
	CSS: AURORA_CSS
});
