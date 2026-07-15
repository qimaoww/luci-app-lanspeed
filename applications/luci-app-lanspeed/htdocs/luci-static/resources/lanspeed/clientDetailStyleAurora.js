'use strict';
'require baseclass';

var CSS = [
	'.lanspeed-theme-aurora.lanspeed-connection-detail{gap:1rem}',
	'.lanspeed-theme-aurora .lanspeed-connection-identity-card .lanspeed-header,.lanspeed-theme-aurora .lanspeed-connections-card .lanspeed-header{padding:1rem 1.25rem .85rem;align-items:center}',
	'.lanspeed-theme-aurora .lanspeed-connection-state{display:inline-flex;align-items:center;padding:.2rem .55rem;border-radius:999px;background:var(--label-surface,inherit);color:inherit}',
	'.lanspeed-theme-aurora .lanspeed-connection-summary-item{padding:.2rem 0}',
	'@media (max-width:480px){.lanspeed-theme-aurora .lanspeed-connection-toolbar{padding-right:2rem}}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
