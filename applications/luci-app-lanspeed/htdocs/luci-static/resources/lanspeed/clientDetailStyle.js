'use strict';
'require baseclass';
'require lanspeed.designSystem as DesignSystem';
'require lanspeed.statusStyle as statusStyle';
'require lanspeed.clientDetailStyleBase as Base';
'require lanspeed.clientDetailStyleAurora as Aurora';
'require lanspeed.clientDetailStyleArgon as Argon';
'require lanspeed.clientDetailStyleBootstrap as Bootstrap';
'require lanspeed.clientDetailStyleResponsive as Responsive';

var CSS = [
	DesignSystem.CSS,
	statusStyle.LAYOUT_CSS,
	Base.CSS,
	Aurora.CSS,
	Argon.CSS,
	Bootstrap.CSS,
	Responsive.CSS
].join('\n');

return baseclass.extend({
	CSS: CSS
});
