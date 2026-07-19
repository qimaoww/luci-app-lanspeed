'use strict';
'require baseclass';

/* Only non-visual shell behavior is shared; each theme owns its density and treatment. */
var SHARED_CSS = [
	'.lanspeed-config-root>.cbi-section{padding:0}',
	'.lanspeed-config-root .lanspeed-ifcfg-body{overflow-x:auto}'
].join('\n');

return baseclass.extend({
	CSS: SHARED_CSS
});
