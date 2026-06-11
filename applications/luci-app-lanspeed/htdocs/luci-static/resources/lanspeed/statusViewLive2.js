'use strict';
'require baseclass';
'require lanspeed.statusViewLive as statusViewLive';
'require lanspeed.statusStyleCompatLive2 as statusStyleCompatLive2';

return baseclass.extend({
	load: function() {
		return statusViewLive.load();
	},

	render: function(data) {
		var root = statusViewLive.render(data);
		statusStyleCompatLive2.install(root);
		return root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
