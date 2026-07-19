'use strict';
'require baseclass';
'require lanspeed.designSystemBase as designSystemBase';
'require lanspeed.designSystemAurora as designSystemAurora';
'require lanspeed.designSystemArgon as designSystemArgon';
'require lanspeed.designSystemBootstrap as designSystemBootstrap';

var DESIGN_SYSTEM_CSS = [
	designSystemBase.CSS,
	designSystemAurora.CSS,
	designSystemArgon.CSS,
	designSystemBootstrap.CSS
].join('\n');

return baseclass.extend({
	CSS: DESIGN_SYSTEM_CSS
});
