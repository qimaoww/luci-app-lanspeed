'use strict';
'require baseclass';
'require lanspeed.statusStyleLive6 as statusStyle';
'require lanspeed.clientDetailStyleBaseLive4 as Base';
'require lanspeed.clientDetailStyleAuroraLive4 as Aurora';
'require lanspeed.clientDetailStyleArgonLive4 as Argon';
'require lanspeed.clientDetailStyleBootstrapLive4 as Bootstrap';
'require lanspeed.clientDetailStyleResponsiveLive4 as Responsive';

var CSS = [
	statusStyle.CSS,
	Base.CSS,
	Aurora.CSS,
	Argon.CSS,
	Bootstrap.CSS,
	Responsive.CSS
].join('\n');

return baseclass.extend({
	CSS: CSS
});
