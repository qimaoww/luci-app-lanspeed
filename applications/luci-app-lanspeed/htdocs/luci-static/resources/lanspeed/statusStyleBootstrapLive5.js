'use strict';
'require baseclass';

/* Bootstrap-only status overrides. Keep the existing desktop presentation intact. */
var BOOTSTRAP_CSS = [
	'.lanspeed-theme-bootstrap .lanspeed-diagnostic-card{padding-top:.1rem;padding-bottom:.1rem}',
	'.lanspeed-theme-bootstrap .lanspeed-diagnostic-alert,',
	'.lanspeed-theme-bootstrap .lanspeed-diagnostic-alert-empty{border-radius:.3rem}',
	'@media (max-width:700px){.lanspeed-theme-bootstrap>.cbi-section,',
	'.lanspeed-theme-bootstrap .lanspeed-details{min-width:0;max-width:100%}}'
].join('\n');

return baseclass.extend({
	CSS: BOOTSTRAP_CSS
});
