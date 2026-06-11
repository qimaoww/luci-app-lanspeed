'use strict';
'require view';
'require lanspeed.statusViewLive3 as statusViewLive3';

return view.extend({
	load: function() {
		return statusViewLive3.load();
	},

	render: function(data) {
		return statusViewLive3.render(data);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
