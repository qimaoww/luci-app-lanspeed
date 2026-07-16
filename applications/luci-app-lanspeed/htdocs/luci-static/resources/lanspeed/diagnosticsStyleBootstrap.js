'use strict';
'require baseclass';

/* Bootstrap-family diagnostics overrides. */
var BOOTSTRAP_CSS = [
	'.lanspeed-diagnostics-root.lanspeed-theme-bootstrap .lanspeed-diagnostic-card{padding-top:.15rem;padding-bottom:.15rem}',
	'.lanspeed-diagnostics-root.lanspeed-theme-bootstrap .lanspeed-diagnostic-alert,',
	'.lanspeed-diagnostics-root.lanspeed-theme-bootstrap .lanspeed-diagnostic-alert-empty{border-radius:.3rem}'
].join('\n');

return baseclass.extend({
	CSS: BOOTSTRAP_CSS
});
