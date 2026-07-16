'use strict';
'require baseclass';
'require lanspeed.rpc as lsRpc';
'require lanspeed.diagnosticsShell as diagnosticsShell';
'require lanspeed.diagnosticsRefresh as diagnosticsRefresh';

function loadAll() {
	return Promise.all([
		lsRpc.status(),
		lsRpc.health(),
		lsRpc.clients()
	]);
}

function normalizeData(data) {
	return {
		status: data[0] || {},
		health: data[1] || {},
		clients: data[2] || { clients: [] },
		error: null
	};
}

return baseclass.extend({
	load: function() {
		return loadAll().then(normalizeData).catch(function(error) {
			return {
				status: {},
				health: {},
				clients: { clients: [] },
				error: error
			};
		});
	},

	render: function(data) {
		var viewState = {
			status: data.status || {},
			health: data.health || {},
			clients: data.clients || { clients: [] },
			error: data.error,
			refs: null,
			reload: function() {
				var self = this;
				if (self.refs) {
					self.refs.btnRefresh.disabled = true;
					self.refs.btnRefresh.textContent = _('检查中…');
				}
				return loadAll().then(function(result) {
					var next = normalizeData(result);
					self.status = next.status;
					self.health = next.health;
					self.clients = next.clients;
					self.error = null;
				}).catch(function(error) {
					self.error = error;
				}).then(function() {
					diagnosticsRefresh.refresh(self);
					if (self.refs) {
						self.refs.btnRefresh.disabled = false;
						self.refs.btnRefresh.textContent = _('重新检查');
					}
				});
			}
		};

		var built = diagnosticsShell.buildShell(viewState);
		viewState.refs = built.refs;
		diagnosticsRefresh.refresh(viewState);
		return built.root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
