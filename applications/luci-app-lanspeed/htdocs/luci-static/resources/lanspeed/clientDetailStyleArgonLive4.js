'use strict';
'require baseclass';

var CSS = [
	'.lanspeed-theme-argon.lanspeed-connection-detail{gap:1rem;font-size:1rem}',
	'.lanspeed-theme-argon .lanspeed-connection-client-heading{margin-bottom:.9rem}',
	'.lanspeed-theme-argon .lanspeed-connection-client-avatar{border-radius:.7rem}',
	'.lanspeed-theme-argon .lanspeed-connection-state{border-radius:.45rem!important;background:color-mix(in srgb,currentColor 5%,transparent)!important;color:inherit!important}',
	'.lanspeed-theme-argon .lanspeed-connection-meta-ip,.lanspeed-theme-argon .lanspeed-connection-meta-fact{border-radius:.5rem}',
	'.lanspeed-theme-argon .lanspeed-connection-summary{gap:.65rem}',
	'.lanspeed-theme-argon .lanspeed-connection-summary-item{min-height:5.1rem;padding:.8rem .9rem;border-radius:.55rem}',
	'.lanspeed-theme-argon .lanspeed-connection-protocols{gap:.4rem}',
	'.lanspeed-theme-argon .lanspeed-connections-card .lanspeed-table th,.lanspeed-theme-argon .lanspeed-connections-card .lanspeed-table td{padding:.65rem .75rem;font-size:1rem;line-height:1.45}',
	'@media (max-width:480px){.lanspeed-theme-argon .lanspeed-connection-refresh{width:100%!important}}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
