'use strict';
'require baseclass';

/*
 * One manifest is the source of truth for the browser resource graph.  The
 * package Makefile consumes the same groups, while the module validator checks
 * that every file belongs to exactly one domain.
 */
var MODULE_GROUPS = {
	core: [ 'moduleManifest.js', 'vocab.js', 'format.js', 'rpc.js', 'theme.js', 'version.js' ],
	design: [
		'designSystem.js', 'designSystemBase.js', 'designSystemAurora.js',
		'designSystemArgon.js', 'designSystemBootstrap.js'
	],
	status: [
			'statusCollector.js', 'statusIp.js', 'statusRateMeta.js', 'statusRefresh.js', 'statusShell.js',
		'statusStyle.js', 'statusStyleBase.js', 'statusStyleAurora.js',
		'statusStyleArgon.js', 'statusStyleBootstrap.js', 'statusStyleResponsive.js',
		'statusOverview.js', 'statusView.js'
	],
	client: [
		'clientConnections.js', 'clientControl.js', 'clientControlReasons.js',
		'clientControlReasonsShared.js', 'clientControlReasonsX86.js',
		'clientControlReasonsNss.js', 'dhcpHostnames.js', 'geoLocation.js',
		'clientDetailShell.js', 'clientDetailStyle.js', 'clientDetailStyleBase.js',
		'clientDetailStyleAurora.js', 'clientDetailStyleArgon.js',
		'clientDetailStyleBootstrap.js', 'clientDetailStyleResponsive.js',
		'clientDetailRefresh.js', 'clientDetailView.js'
	],
	diagnostics: [
		'diagnosticsRefresh.js', 'diagnosticsShell.js', 'diagnosticsStyle.js',
		'diagnosticsStyleBase.js', 'diagnosticsStyleAurora.js',
		'diagnosticsStyleArgon.js', 'diagnosticsStyleBootstrap.js',
		'diagnosticsStyleResponsive.js', 'diagnosticsSchema.js', 'diagnosticsResources.js',
		'diagnosticsStates.js', 'diagnosticsModel.js', 'diagnosticsReport.js',
		'diagnosticsReportModel.js', 'diagnosticsView.js'
	],
	config: [
		'ifaceConfig.js', 'configPlatform.js', 'configPlatformX86.js', 'configPlatformNss.js',
		'configStyle.js', 'configStyleBase.js', 'configStyleShared.js',
		'configStyleAurora.js', 'configStyleArgon.js', 'configStyleBootstrap.js',
		'configStyleResponsive.js', 'configModel.js', 'configForm.js', 'configView.js'
	]
};

function all() {
	var files = [];
	Object.keys(MODULE_GROUPS).forEach(function(group) {
		MODULE_GROUPS[group].forEach(function(file) {
			if (files.indexOf(file) < 0) files.push(file);
		});
	});
	return files;
}

return baseclass.extend({
	GROUPS: MODULE_GROUPS,
	all: all
});
