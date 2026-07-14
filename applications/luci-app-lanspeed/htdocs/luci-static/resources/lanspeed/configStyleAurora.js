'use strict';
'require baseclass';

/* Aurora-only configuration layout overrides. Every selector stays Aurora-scoped. */
var AURORA_CSS = [
	'.lanspeed-theme-aurora .lanspeed-header{padding:1rem 1.25rem .85rem;align-items:center}',
	'.lanspeed-theme-aurora .lanspeed-config-body,',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-body{padding:1rem 1.25rem}',
	'.lanspeed-theme-aurora .lanspeed-config-table th,',
	'.lanspeed-theme-aurora .lanspeed-config-table td,',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-table th,',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-table td{padding:.55rem .65rem}',
	'.lanspeed-theme-aurora .lanspeed-range-stack{gap:.5rem}',
	'.lanspeed-theme-aurora .lanspeed-config-actions,',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-actions{margin:.8rem 0 0 0}',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-seg>button{padding:.48rem .7rem;',
	'  border-radius:calc(var(--radius-base, .5rem)*1.5)}',
	'@media (max-width:800px){.lanspeed-theme-aurora{',
	'  --lanspeed-mobile-config-row-padding:.7rem 0;',
	'  --lanspeed-mobile-ifcfg-row-padding:.7rem 0}',
	'.lanspeed-theme-aurora .lanspeed-header{padding:.85rem 1rem .7rem}',
	'.lanspeed-theme-aurora .lanspeed-config-body,',
	'.lanspeed-theme-aurora .lanspeed-ifcfg-body{padding:.85rem 1rem}}',

].join('\n');

return baseclass.extend({
	CSS: AURORA_CSS
});
