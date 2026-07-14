'use strict';
'require baseclass';
'require lanspeed.configStyleBase as configStyleBase';
'require lanspeed.configStyleAurora as configStyleAurora';
'require lanspeed.configStyleArgon as configStyleArgon';
'require lanspeed.configStyleBootstrap as configStyleBootstrap';
'require lanspeed.configStyleShared as configStyleShared';
'require lanspeed.configStyleResponsive as configStyleResponsive';

/* Theme modules precede shared layers; responsive structure must win last. */
var CONFIG_CSS = [
	configStyleBase.CSS,
	configStyleAurora.CSS,
	configStyleArgon.CSS,
	configStyleBootstrap.CSS,
	configStyleShared.CSS,
	configStyleResponsive.CSS
].join('\n');

return baseclass.extend({
	CSS: CONFIG_CSS
});
