'use strict';
'require baseclass';
'require lanspeed.statusViewLive as statusViewLive';
'require lanspeed.statusStyleCompatLive3 as statusStyleCompatLive3';

return baseclass.extend({
	load: function() {
		return statusViewLive.load();
	},

	render: function(data) {
		var root = statusViewLive.render(data);
		statusStyleCompatLive3.install(root);
		return root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
