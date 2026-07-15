'use strict';
'require baseclass';

var CSS = [
	'.lanspeed-theme-argon.lanspeed-connection-detail{gap:1rem;font-size:1rem}',
	'.lanspeed-theme-argon .lanspeed-connection-summary{gap:.5rem 1rem}',
	'.lanspeed-theme-argon .lanspeed-connection-protocols{gap:.4rem}',
	'.lanspeed-theme-argon .lanspeed-connections-card .lanspeed-table th,.lanspeed-theme-argon .lanspeed-connections-card .lanspeed-table td{padding:.65rem .75rem;font-size:1rem;line-height:1.45}',
	'@media (max-width:480px){.lanspeed-theme-argon .lanspeed-connection-refresh{width:100%!important}}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
