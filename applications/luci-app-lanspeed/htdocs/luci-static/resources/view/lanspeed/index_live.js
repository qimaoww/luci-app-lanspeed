'use strict';
'require view';
'require lanspeed.statusViewLive2 as statusViewLive2';

return view.extend({
	load: function() {
		return statusViewLive2.load();
	},

	render: function(data) {
		return statusViewLive2.render(data);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
