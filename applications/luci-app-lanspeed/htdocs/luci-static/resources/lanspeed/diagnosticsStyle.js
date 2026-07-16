'use strict';
'require baseclass';
'require lanspeed.diagnosticsStyleBase as diagnosticsStyleBase';
'require lanspeed.diagnosticsStyleAurora as diagnosticsStyleAurora';
'require lanspeed.diagnosticsStyleArgon as diagnosticsStyleArgon';
'require lanspeed.diagnosticsStyleBootstrap as diagnosticsStyleBootstrap';
'require lanspeed.diagnosticsStyleResponsive as diagnosticsStyleResponsive';

var DIAGNOSTICS_CSS = [
	diagnosticsStyleBase.CSS,
	diagnosticsStyleAurora.CSS,
	diagnosticsStyleArgon.CSS,
	diagnosticsStyleBootstrap.CSS,
	diagnosticsStyleResponsive.CSS
].join('\n');

return baseclass.extend({
	CSS: DIAGNOSTICS_CSS
});
