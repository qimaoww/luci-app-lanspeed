'use strict';
'require baseclass';

var CSS = [
	'.lanspeed-theme-aurora.lanspeed-connection-detail{gap:1rem}',
	'.lanspeed-theme-aurora .lanspeed-connection-identity-card .lanspeed-header,.lanspeed-theme-aurora .lanspeed-connections-card .lanspeed-header{padding:1rem 1.25rem .85rem;align-items:center}',
	'.lanspeed-theme-aurora .lanspeed-connection-state{border-radius:var(--lanspeed-radius-badge)!important}',
	'.lanspeed-theme-aurora .lanspeed-connection-client-avatar{border-radius:var(--lanspeed-radius-section);box-shadow:var(--lanspeed-shadow-raised)}',
	'.lanspeed-theme-aurora .lanspeed-connection-meta-ip,.lanspeed-theme-aurora .lanspeed-connection-meta-fact{border-radius:.75rem}',
	'.lanspeed-theme-aurora .lanspeed-connection-summary-item{padding:.95rem 1rem;border-radius:var(--lanspeed-radius-section);box-shadow:var(--lanspeed-shadow-raised)}',
	'@media (max-width:480px){.lanspeed-theme-aurora .lanspeed-connection-toolbar{padding-right:2rem}}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
