'use strict';
'require baseclass';
'require lanspeed.designSystem as designSystem';
'require lanspeed.diagnosticsStyleBase as diagnosticsStyleBase';
'require lanspeed.diagnosticsStyleAurora as diagnosticsStyleAurora';
'require lanspeed.diagnosticsStyleArgon as diagnosticsStyleArgon';
'require lanspeed.diagnosticsStyleBootstrap as diagnosticsStyleBootstrap';
'require lanspeed.diagnosticsStyleShadcn as diagnosticsStyleShadcn';
'require lanspeed.diagnosticsStyleResponsive as diagnosticsStyleResponsive';
'require lanspeed.pageLayout as pageLayout';
'require lanspeed.diagnosticsStyleLayout as diagnosticsStyleLayout';

var DIAGNOSTICS_LAYOUT_CSS = [
	diagnosticsStyleBase.CSS,
	diagnosticsStyleAurora.CSS,
	diagnosticsStyleArgon.CSS,
	diagnosticsStyleBootstrap.CSS,
	diagnosticsStyleShadcn.CSS,
	pageLayout.CSS,
	diagnosticsStyleResponsive.CSS,
	diagnosticsStyleLayout.CSS
].join('\n');

var DIAGNOSTICS_CSS = [
	designSystem.CSS,
	DIAGNOSTICS_LAYOUT_CSS
].join('\n');

return baseclass.extend({
	CSS: DIAGNOSTICS_CSS,
	LAYOUT_CSS: DIAGNOSTICS_LAYOUT_CSS
});
