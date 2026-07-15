'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';
'require lanspeed.clientDetailShell as clientDetailShell';
'require lanspeed.clientDetailRefresh as clientDetailRefresh';

function loadClient(identityKey) {
	return lsRpc.clientConnections(identityKey).then(function(response) {
		return {
			identityKey: identityKey,
			response: response,
			error: null
		};
	}, function(error) {
		return {
			identityKey: identityKey,
			response: null,
			error: error
		};
	});
}

return baseclass.extend({
	load: function(identityKey) {
		return loadClient(identityKey);
	},

	render: function(data) {
		var initialResponse = data && data.response || null;
		var pending = null;
		var viewState = {
			identityKey: data && data.identityKey || '',
			response: initialResponse,
			lastGood: initialResponse && initialResponse.available
				? initialResponse : null,
			error: data && data.error || null,
			protocol: 'all',
			filter: '',
			expanded: {},
			prefs: fmt.loadPrefs(),
			timer: null,
			loading: false,
			refs: null,

			stopTimer: function() {
				if (this.timer !== null) {
					window.clearTimeout(this.timer);
					this.timer = null;
				}
			},

			schedule: function() {
				var self = this;
				this.stopTimer();
				var interval = Math.max(fmt.MIN_REFRESH_MS,
					Number(this.prefs && this.prefs.refreshMs) || 0);
				this.timer = window.setTimeout(function() {
					self.timer = null;
					self.reload();
				}, interval);
			},

			reload: function() {
				var self = this;
				var request;
				if (pending) return pending;

				this.stopTimer();
				this.loading = true;
				clientDetailRefresh.render(this);
				try {
					request = lsRpc.clientConnections(this.identityKey);
				} catch (error) {
					request = Promise.reject(error);
				}

				pending = Promise.resolve(request).then(function(response) {
					self.response = response;
					if (response && response.available)
						self.lastGood = response;
					self.error = null;
				}, function(error) {
					self.response = self.lastGood;
					self.error = error;
				}).then(function() {
					self.loading = false;
					clientDetailRefresh.render(self);
					self.schedule();
					pending = null;
					return self.response;
				});
				return pending;
			},

			setProtocol: function(protocol) {
				this.protocol = protocol === 'tcp' || protocol === 'udp'
					? protocol : 'all';
				clientDetailRefresh.render(this);
			},

			setFilter: function(filter) {
				this.filter = filter === null || filter === undefined
					? '' : String(filter);
				clientDetailRefresh.render(this);
			},

			back: function() {
				this.stopTimer();
				if (window.location && typeof window.location.assign === 'function')
					window.location.assign(window.location.pathname);
				else
					window.location.href = window.location.pathname;
			}
		};

		var built = clientDetailShell.buildShell(viewState);
		viewState.refs = built.refs;
		clientDetailRefresh.render(viewState);
		viewState.schedule();
		window.addEventListener('beforeunload', function() {
			viewState.stopTimer();
		});
		return built.root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
