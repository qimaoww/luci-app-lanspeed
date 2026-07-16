'use strict';
'require baseclass';
'require lanspeed.statusStyleBase as statusStyleBase';
'require lanspeed.statusStyleAurora as statusStyleAurora';
'require lanspeed.statusStyleArgon as statusStyleArgon';
'require lanspeed.statusStyleBootstrap as statusStyleBootstrap';
'require lanspeed.statusStyleResponsive as statusStyleResponsive';

/* Theme modules precede shared responsive rules so mobile fixes win the cascade. */
var LAYOUT_CSS = [
	statusStyleBase.CSS,
	statusStyleAurora.CSS,
	statusStyleArgon.CSS,
	statusStyleBootstrap.CSS,
	statusStyleResponsive.CSS
].join('\n');

return baseclass.extend({
	CSS: LAYOUT_CSS
});
