'use strict';
'require baseclass';

var CSS = [
	'.lanspeed-theme-bootstrap.lanspeed-connection-detail{gap:.85em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-identity{gap:1.25em 1.75em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-client-heading{gap:.8em;margin-bottom:.8em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-client-avatar{width:3em;height:3em;flex-basis:3em;border-radius:.5em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-client-name{font-size:1.18em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-state{border-radius:var(--lanspeed-radius-control)!important}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-meta-ip{padding:.34em .55em;border-radius:.4em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-meta-facts{gap:.4em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-meta-fact{padding:.5em .62em;border-radius:.4em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-summary{gap:.5em;padding-left:1.5em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-summary-item{min-height:4.8em;padding:.68em .75em;border-radius:.4em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-summary-value{font-size:1.25em}',
	'.lanspeed-theme-bootstrap .lanspeed-connections-card .lanspeed-table th,.lanspeed-theme-bootstrap .lanspeed-connections-card .lanspeed-table td{padding:.4em .55em}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
