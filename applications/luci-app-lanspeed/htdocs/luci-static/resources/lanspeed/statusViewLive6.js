'use strict';
'require baseclass';
'require lanspeed.clientConnectionsLive4 as clientConnections';
'require lanspeed.clientDetailViewLive6 as clientDetailView';
'require lanspeed.statusOverviewLive6 as statusView';

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
