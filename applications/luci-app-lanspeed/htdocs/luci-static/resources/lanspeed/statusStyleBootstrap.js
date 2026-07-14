'use strict';
'require baseclass';

/* Bootstrap-only status overrides. Keep the existing desktop presentation intact. */
var BOOTSTRAP_CSS = [
	'@media (max-width:700px){.lanspeed-theme-bootstrap>.cbi-section,',
	'.lanspeed-theme-bootstrap .lanspeed-details{min-width:0;max-width:100%}}'
].join('\n');

return baseclass.extend({
	CSS: BOOTSTRAP_CSS
});
