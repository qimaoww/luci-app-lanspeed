'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';
'require lanspeed.geoLocation as geoLocation';
'require lanspeed.clientDetailShell as clientDetailShell';
'require lanspeed.clientDetailRefresh as clientDetailRefresh';

function loadClient(identityKey) {
	return lsRpc.clientConnections(identityKey).then(function(response) {
		return {
			identityKey: identityKey,
			response: response,
			updatedAt: Date.now(),
			error: null
		};
	}, function(error) {
		return {
			identityKey: identityKey,
			response: null,
			updatedAt: null,
			error: error
		};
	});
}

function normalizedPrefs() {
	var prefs = Object.assign({}, fmt.loadPrefs() || {});
	var fallback = fmt.DEFAULT_PREFS && fmt.DEFAULT_PREFS.refreshMs;
	if (typeof fallback !== 'number' || !isFinite(fallback) || fallback <= 0)
		fallback = 3000;
	if (typeof prefs.refreshMs !== 'number' ||
	    !isFinite(prefs.refreshMs) || prefs.refreshMs <= 0) {
		prefs.refreshMs = fallback;
	}
	prefs.refreshMs = Math.max(fmt.MIN_REFRESH_MS, prefs.refreshMs);
	return prefs;
}

return baseclass.extend({
	load: function(identityKey) {
		return loadClient(identityKey);
	},

	render: function(data) {
		var initialResponse = data && data.response || null;
		var initialUpdatedAt = data && data.updatedAt;
		if (initialResponse && (typeof initialUpdatedAt !== 'number' ||
		    !isFinite(initialUpdatedAt))) {
			initialUpdatedAt = Date.now();
		}
		var pending = null;
		var geoResolver = geoLocation.createResolver();
		var viewState = {
			identityKey: data && data.identityKey || '',
			response: initialResponse,
			lastGood: initialResponse && initialResponse.available
				? initialResponse : null,
				updatedAt: initialUpdatedAt || null,
				error: data && data.error || null,
				protocol: 'all',
				filter: '',
				expanded: {},
				page: 0,
				pageSize: 100,
			sortKey: 'rx',
			sortDir: 'desc',
			sortCustom: false,
			prefs: normalizedPrefs(),
			timer: null,
			loading: false,
			refs: null,
			geoBatch: null,
			geoPageSignature: '',
			destroyed: false,

			stopTimer: function() {
				if (this.timer !== null) {
					window.clearTimeout(this.timer);
					this.timer = null;
				}
			},

			schedule: function() {
				var self = this;
				this.stopTimer();
				if (this.destroyed)
					return;
				var interval = this.prefs.refreshMs;
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
					self.lastGood = response && response.available
						? response : null;
					self.updatedAt = Date.now();
					self.error = null;
				}, function(error) {
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
				this.page = 0;
				clientDetailRefresh.render(this);
			},

			setFilter: function(filter) {
				this.filter = filter === null || filter === undefined
					? '' : String(filter);
				this.page = 0;
				clientDetailRefresh.render(this);
			},

			setSort: function(sortKey) {
				Object.assign(this, fmt.nextSort(this, sortKey));
				this.page = 0;
				clientDetailRefresh.render(this);
			},

			setPage: function(delta) {
				var value = Number(delta);
				if (!isFinite(value)) value = 0;
				this.page = Math.max(0, Math.floor(Number(this.page) || 0) + Math.trunc(value));
				clientDetailRefresh.render(this);
			},

			locationLabelFor: function(ip) {
				var location = geoResolver.peek(ip);
				return location && location.label || '未知';
			},

			requestLocations: function(ips) {
				var self = this;
				var seen = Object.create(null);
				var values = [];
				var requests = [];
				var signature;
				var batch;
				if (this.destroyed)
					return;
				(ips || []).forEach(function(ip) {
					var value = String(ip === null || ip === undefined ? '' : ip).toLowerCase();
					if (!value || seen[value])
						return;
					seen[value] = true;
					values.push(value);
				});
				signature = values.join('\n');
				this.geoPageSignature = signature;
				if (this.geoBatch && this.geoBatch.signature === signature)
					return;
				values.forEach(function(ip) {
					if (geoResolver.peek(ip).queryable)
						requests.push(geoResolver.resolve(ip));
				});
				if (!requests.length) {
					this.geoBatch = null;
					return;
				}
				batch = { signature: signature, promise: null };
				this.geoBatch = batch;
				batch.promise = Promise.all(requests).then(function() {
					if (self.destroyed)
						return;
					if (self.geoBatch === batch)
						self.geoBatch = null;
					clientDetailRefresh.render(self);
				});
			},

			destroy: function() {
				if (this.destroyed)
					return;
				this.destroyed = true;
				this.stopTimer();
				this.geoBatch = null;
				this.geoPageSignature = '';
				geoResolver.dispose();
			},

			back: function() {
				this.destroy();
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
			viewState.destroy();
		});
		return built.root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
