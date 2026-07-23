'use strict';
'require view';

var RESOURCE_VERSION = 'lanspeed-1.1.3-r2';
var pageModule;

function loadPageModule() {
	var previousVersion = L.env.resource_version;
	L.env.resource_version = RESOURCE_VERSION;
	return L.require('lanspeed.configView').then(function(module) {
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

	addFooter: function() {
		return pageModule.decorateFooter(this.super('addFooter', []));
	},

	handleSave: function() {
		return pageModule.handleSave();
	},

	handleSaveApply: function(ev, mode) {
		return pageModule.handleSaveApply(ev, mode);
	},

	handleReset: function() {
		return pageModule.handleReset();
	}
});
