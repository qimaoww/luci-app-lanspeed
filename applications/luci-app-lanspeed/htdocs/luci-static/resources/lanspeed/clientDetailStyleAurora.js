'use strict';
'require baseclass';

var CSS = [
	'.lanspeed-theme-aurora.lanspeed-connection-detail{gap:1rem}',
	'.lanspeed-theme-aurora .lanspeed-connection-identity-card .lanspeed-header,.lanspeed-theme-aurora .lanspeed-connections-card .lanspeed-header{padding:1rem 1.25rem .85rem;align-items:center}',
	'.lanspeed-theme-aurora .lanspeed-connection-state{background:var(--label-surface,color-mix(in srgb,currentColor 5%,transparent))!important}',
	'.lanspeed-theme-aurora .lanspeed-connection-client-avatar{border-radius:1rem;box-shadow:inset 0 0 0 1px color-mix(in srgb,currentColor 3%,transparent)}',
	'.lanspeed-theme-aurora .lanspeed-connection-meta-ip,.lanspeed-theme-aurora .lanspeed-connection-meta-fact{border-radius:.75rem}',
	'.lanspeed-theme-aurora .lanspeed-connection-summary-item{padding:.95rem 1rem;border-radius:.85rem;box-shadow:0 1px 0 color-mix(in srgb,currentColor 3%,transparent)}',
	'@media (max-width:480px){.lanspeed-theme-aurora .lanspeed-connection-toolbar{padding-right:2rem}}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
