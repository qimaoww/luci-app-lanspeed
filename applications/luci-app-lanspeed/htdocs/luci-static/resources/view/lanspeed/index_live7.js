'use strict';
'require view';
'require lanspeed.statusViewLive6 as statusViewLive6';

return view.extend({
	load: function() {
		return statusViewLive6.load();
	},

	render: function(data) {
		return statusViewLive6.render(data);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
