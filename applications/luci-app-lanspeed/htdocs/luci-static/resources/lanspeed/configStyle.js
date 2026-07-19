'use strict';
'require baseclass';
'require lanspeed.configStyleBase as configStyleBase';
'require lanspeed.configStyleShared as configStyleShared';
'require lanspeed.configStyleAurora as configStyleAurora';
'require lanspeed.configStyleArgon as configStyleArgon';
'require lanspeed.configStyleBootstrap as configStyleBootstrap';
'require lanspeed.configStyleResponsive as configStyleResponsive';

/* Shared shell precedes theme visuals; responsive structure must win last. */
var CONFIG_CSS = [
	configStyleBase.CSS,
	configStyleShared.CSS,
	configStyleAurora.CSS,
	configStyleArgon.CSS,
	configStyleBootstrap.CSS,
	configStyleResponsive.CSS
].join('\n');

return baseclass.extend({
	CSS: CONFIG_CSS
});
