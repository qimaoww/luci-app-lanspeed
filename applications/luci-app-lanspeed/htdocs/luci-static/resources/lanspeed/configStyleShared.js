'use strict';
'require baseclass';

/* Only non-visual shell behavior is shared; each theme owns its layout. */
var SHARED_CSS = [
	'.lanspeed-theme-aurora,',
	'.lanspeed-theme-argon{display:flex;flex-direction:column;gap:1rem;margin:0}',
	'.lanspeed-theme-aurora>.cbi-section,',
	'.lanspeed-theme-argon>.cbi-section{margin:0;padding:0;overflow:hidden}',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-body,',
	'.lanspeed-theme-argon .lanspeed-ifcfg-body{overflow-x:auto}',
].join('\n');

return baseclass.extend({
	CSS: SHARED_CSS
});
