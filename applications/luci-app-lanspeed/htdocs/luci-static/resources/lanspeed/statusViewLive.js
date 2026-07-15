'use strict';
'require baseclass';
'require lanspeed.clientConnections as clientConnections';
'require lanspeed.clientDetailView as clientDetailView';
'require lanspeed.statusView as statusView';

return baseclass.extend({
	load: function() {
		var identityKey = clientConnections.identityFromSearch(window.location.search);
		if (identityKey) {
			return clientDetailView.load(identityKey).then(function(data) {
				return { route: 'detail', data: data };
			});
		}
		return statusView.load().then(function(data) {
			return { route: 'overview', data: data };
		});
	},

	render: function(data) {
		if (data && data.route === 'detail')
			return clientDetailView.render(data.data);
		return statusView.render(data.data);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
