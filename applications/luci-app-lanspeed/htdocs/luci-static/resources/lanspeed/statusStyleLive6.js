'use strict';
'require baseclass';
'require lanspeed.statusStyleBaseLive6 as statusStyleBase';
'require lanspeed.statusStyleAuroraLive5 as statusStyleAurora';
'require lanspeed.statusStyleArgonLive5 as statusStyleArgon';
'require lanspeed.statusStyleBootstrapLive5 as statusStyleBootstrap';
'require lanspeed.statusStyleResponsiveLive5 as statusStyleResponsive';

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
