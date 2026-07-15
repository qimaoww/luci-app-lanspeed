'use strict';
'require baseclass';

var CSS = [
	'.lanspeed-theme-bootstrap.lanspeed-connection-detail{gap:.85em}',
	'.lanspeed-theme-bootstrap .lanspeed-connection-summary{gap:.4em .9em}',
	'.lanspeed-theme-bootstrap .lanspeed-connections-card .lanspeed-table th,.lanspeed-theme-bootstrap .lanspeed-connections-card .lanspeed-table td{padding:.4em .55em}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
