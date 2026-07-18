'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';
'require lanspeed.geoLocation as geoLocation';
'require lanspeed.clientDetailShell as clientDetailShell';
'require lanspeed.clientDetailRefresh as clientDetailRefresh';

var DETAIL_PREF_KEY = 'luci-app-lanspeed.detail-prefs.v1';

function detailStorage() {
	try {
		return typeof window !== 'undefined' ? window.localStorage : null;
	} catch (e) {
		return null;
	}
}

function detailPrefs(shared) {
	var defaults = {
		refreshMs: 3000,
		paused: false
	};
	var storage = detailStorage();
	var raw, stored, choices, allowed;
	if (storage && typeof storage.getItem === 'function') {
		try {
			raw = storage.getItem(DETAIL_PREF_KEY);
			stored = raw ? JSON.parse(raw) : null;
			if (stored && typeof stored === 'object')
				defaults = Object.assign(defaults, stored);
		} catch (e) {}
	} else if (shared) {
		/* Non-browser callers keep deterministic defaults without a storage API. */
		defaults.refreshMs = shared.refreshMs;
		defaults.paused = shared.paused === true;
	}
	choices = fmt.REFRESH_CHOICES || [];
	allowed = choices.map(function(choice) { return Number(choice.value); });
	if (allowed.length && allowed.indexOf(Number(defaults.refreshMs)) === -1)
		defaults.refreshMs = 3000;
	else {
		defaults.refreshMs = Number(defaults.refreshMs);
		if (!isFinite(defaults.refreshMs) || defaults.refreshMs <= 0)
			defaults.refreshMs = 3000;
	}
	defaults.paused = defaults.paused === true;
	return defaults;
}

function saveDetailPrefs(prefs) {
	var storage = detailStorage();
	if (!storage || typeof storage.setItem !== 'function')
		return;
	try {
		storage.setItem(DETAIL_PREF_KEY, JSON.stringify({
			refreshMs: Number(prefs.refreshMs) || 3000,
			paused: prefs.paused === true
		}));
	} catch (e) {}
}

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
	var detail = detailPrefs(prefs);
	prefs.refreshMs = Math.max(fmt.MIN_REFRESH_MS, detail.refreshMs);
	prefs.paused = detail.paused;
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
			refreshChoices: fmt.REFRESH_CHOICES || [],
			timer: null,
			loading: false,
			manualLoading: false,
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
				if (this.destroyed || this.prefs.paused)
					return;
				var interval = this.prefs.refreshMs;
				this.timer = window.setTimeout(function() {
					self.timer = null;
					self.reload(false);
				}, interval);
			},

			reload: function(manual) {
				var self = this;
				var request;
				var requestedManually = manual === true;
				if (pending) {
					if (requestedManually && !this.manualLoading) {
						this.manualLoading = true;
						clientDetailRefresh.render(this);
					}
					return pending;
				}

				this.stopTimer();
				this.loading = true;
				this.manualLoading = requestedManually;
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
					self.manualLoading = false;
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

			setRefreshMs: function(value) {
				var selected = Number(value);
				var allowed = (this.refreshChoices || []).map(function(choice) {
					return Number(choice.value);
				});
				if (allowed.indexOf(selected) === -1)
					return;
				this.prefs.refreshMs = selected;
				saveDetailPrefs(this.prefs);
				clientDetailRefresh.render(this);
				if (!this.loading)
					this.schedule();
			},

			setPaused: function(paused) {
				this.prefs.paused = paused === undefined
					? !this.prefs.paused : paused === true;
				saveDetailPrefs(this.prefs);
				if (this.prefs.paused)
					this.stopTimer();
				clientDetailRefresh.render(this);
				if (!this.prefs.paused && !this.loading)
					this.schedule();
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
