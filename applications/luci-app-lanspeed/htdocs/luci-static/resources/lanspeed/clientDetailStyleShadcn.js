'use strict';
'require baseclass';

var CSS = [
	'.lanspeed-theme-shadcn.lanspeed-connection-detail{gap:1em;font-size:.94rem}',
	'.lanspeed-theme-shadcn .lanspeed-connection-identity{gap:1.4em 2em}',
	'.lanspeed-theme-shadcn .lanspeed-connection-client-heading{gap:.9em;margin-bottom:.7em}',
	'.lanspeed-theme-shadcn .lanspeed-connection-client-avatar{width:3.2em;height:3.2em;flex-basis:3.2em;',
		'border-radius:var(--lanspeed-radius-control)}',
	'.lanspeed-theme-shadcn .lanspeed-connection-client-name{font-size:1.2em}',
	'.lanspeed-theme-shadcn .lanspeed-connection-state{border-radius:var(--lanspeed-radius-badge)!important}',
	'.lanspeed-theme-shadcn .lanspeed-connection-meta-ip{padding:.36em .58em;',
		'border-radius:var(--lanspeed-radius-control)}',
	'.lanspeed-theme-shadcn .lanspeed-connection-meta-facts{gap:.5em}',
	'.lanspeed-theme-shadcn .lanspeed-connection-meta-fact{padding:.55em .68em;',
		'border-radius:var(--lanspeed-radius-control)}',
	'.lanspeed-theme-shadcn .lanspeed-connection-summary{gap:.65em;padding-left:1.75em}',
	'.lanspeed-theme-shadcn .lanspeed-connection-summary-item{min-height:5.1em;padding:.75em .85em;',
		'border-radius:var(--lanspeed-radius-control)}',
	'.lanspeed-theme-shadcn .lanspeed-connection-summary-value{font-size:1.2em}',
	'.lanspeed-theme-shadcn .lanspeed-connections-card .lanspeed-table th,',
	'.lanspeed-theme-shadcn .lanspeed-connections-card .lanspeed-table td{padding:.5em .6em}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
