'use strict';
'require baseclass';

var CSS = [
	'.lanspeed-theme-argon.lanspeed-connection-detail{gap:1rem;font-size:1rem}',
	'.lanspeed-theme-argon .lanspeed-connection-identity{align-items:start}',
	'.lanspeed-theme-argon .lanspeed-connection-client-heading{margin-bottom:.9rem}',
	'.lanspeed-theme-argon .lanspeed-connection-client-avatar{border-radius:.7rem}',
	'.lanspeed-theme-argon .lanspeed-connection-client-name,',
	'.lanspeed-theme-argon .lanspeed-connection-summary-title{padding:0!important;border:0!important;',
	'  width:auto!important;background:transparent!important;box-shadow:none!important;color:inherit!important}',
	'.lanspeed-theme-argon .lanspeed-connection-client-name{font-size:1.28rem!important;line-height:1.25!important}',
	'.lanspeed-theme-argon .lanspeed-connection-summary-title{font-size:.9rem!important;line-height:1.35!important}',
	'.lanspeed-theme-argon .lanspeed-connection-state{border-radius:.45rem!important;background:color-mix(in srgb,currentColor 5%,transparent)!important;color:inherit!important}',
	'.lanspeed-theme-argon .lanspeed-connection-meta-ip,.lanspeed-theme-argon .lanspeed-connection-meta-fact{border-radius:.5rem}',
	'.lanspeed-theme-argon .lanspeed-connection-summary{align-content:start;align-self:start;gap:.65rem}',
	'.lanspeed-theme-argon .lanspeed-connection-summary-item{min-height:5.1rem;padding:.8rem .9rem;border-radius:.55rem}',
	'.lanspeed-theme-argon .lanspeed-connection-protocols{gap:.4rem}',
	'.lanspeed-theme-argon .lanspeed-connection-protocol-label{font-size:1rem;line-height:1.5rem}',
	'.lanspeed-theme-argon .lanspeed-connection-footer{padding:0}',
	'.lanspeed-theme-argon .lanspeed-connections-card .lanspeed-table th,.lanspeed-theme-argon .lanspeed-connections-card .lanspeed-table td{padding:.65rem .75rem;font-size:1rem;line-height:1.45}',
	'@media (min-width:701px){.lanspeed-theme-argon .lanspeed-connections-card .lanspeed-table tbody td{vertical-align:top}}',
	'@media (max-width:480px){.lanspeed-theme-argon .lanspeed-connection-refresh,',
	'.lanspeed-theme-argon .lanspeed-connection-protocols .cbi-button{width:100%!important}}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
