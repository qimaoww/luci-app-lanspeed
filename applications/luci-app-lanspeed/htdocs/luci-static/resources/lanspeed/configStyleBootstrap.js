'use strict';
'require baseclass';

/* Bootstrap keeps its desktop defaults; only compact-screen visual tuning lives here. */
var BOOTSTRAP_CSS = [
	'@media (max-width:800px){.lanspeed-theme-bootstrap{',
	'  --lanspeed-mobile-config-row-padding:.65rem 0;',
	'  --lanspeed-mobile-ifcfg-row-padding:.65rem 0;',
	'  --lanspeed-mobile-seg-padding:.5rem .3rem}',
	'.lanspeed-theme-bootstrap>.cbi-section{overflow:hidden}',
	'.lanspeed-theme-bootstrap .lanspeed-header{padding:.8rem .75rem .65rem;align-items:center}',
	'.lanspeed-theme-bootstrap .lanspeed-config-body,',
	'.lanspeed-theme-bootstrap .lanspeed-ifcfg-body{padding:.75rem}',
	'.lanspeed-theme-bootstrap .lanspeed-ifcfg-seg>button{border-radius:.25rem;line-height:1.25}}'
].join('\n');

return baseclass.extend({
	CSS: BOOTSTRAP_CSS
});
