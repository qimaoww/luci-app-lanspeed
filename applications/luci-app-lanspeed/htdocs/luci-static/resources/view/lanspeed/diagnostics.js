'use strict';
'require view';

var RESOURCE_VERSION = 'lanspeed-1.1.0-r4';
var pageModule;

function loadPageModule() {
	var previousVersion = L.env.resource_version;
	L.env.resource_version = RESOURCE_VERSION;
	return L.require('lanspeed.diagnosticsView').then(function(module) {
		pageModule = module;
		return module;
	}).finally(function() {
		L.env.resource_version = previousVersion;
	});
}

return view.extend({
	load: function() {
		return loadPageModule().then(function(module) {
			return module.load();
		});
	},

	render: function(data) {
		return pageModule.render(data);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
