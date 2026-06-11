'use strict';
'require baseclass';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';
'require lanspeed.statusIp as statusIp';
'require lanspeed.statusShell as statusShell';
'require lanspeed.statusRefresh as statusRefresh';
'require lanspeed.statusStyleCompat as statusStyleCompat';

/*
 * Shared LuCI status view implementation.
 *
 * The files under resources/view/lanspeed/ are intentionally tiny wrappers so
 * the active entry path can change when a browser-side resource cache needs a
 * fresh URL.
 */

function loadUiConfig() {
	return lsRpc.uciGet('lanspeed', 'main')
		.catch(function() { return {}; });
}

function normalizeData(data) {
	var uciMain = data[3] || {};

	return {
		status: data[0] || {},
		clients: data[1] || {},
		interfaces: data[2] || { interfaces: [] },
		showIpv6: uciMain.show_ipv6 !== '0',
		hidePrivateIpv6: uciMain.hide_private_ipv6 === '1',
		hideIpv6Ranges: statusIp.hideIpv6RangesValue(uciMain.hide_ipv6_ranges),
		error: null
	};
}

function loadAll() {
	return Promise.all([
		lsRpc.status(),
		lsRpc.clients(),
		lsRpc.interfaces(),
		loadUiConfig()
	]);
}

return baseclass.extend({
	load: function() {
		return loadAll().then(normalizeData).catch(function(error) {
			return {
				status: {},
				clients: { clients: [] },
				interfaces: { interfaces: [] },
				showIpv6: true,
				hidePrivateIpv6: false,
				hideIpv6Ranges: statusIp.DEFAULT_HIDE_IPV6_RANGES,
				error: error
			};
		});
	},

	render: function(data) {
		statusStyleCompat.install();

		var viewState = {
			status: data.status || {},
			clients: data.clients || { clients: [] },
			interfaces: data.interfaces || { interfaces: [] },
			showIpv6: data.showIpv6 !== false,
			hidePrivateIpv6: data.hidePrivateIpv6 === true,
			hideIpv6Ranges: statusIp.hideIpv6RangesValue(data.hideIpv6Ranges),
			error: data.error,
			filter: '',
			prefs: fmt.loadPrefs(),
			timer: null,
			refs: null,

			stopTimer: function() {
				if (this.timer) { window.clearTimeout(this.timer); this.timer = null; }
			},

			schedule: function() {
				var self = this;
				this.stopTimer();
				if (this.prefs.paused) return;
				var interval = Math.max(fmt.MIN_REFRESH_MS, this.prefs.refreshMs);
				this.timer = window.setTimeout(function() { self.reload(false); }, interval);
			},

			refreshLive: function() {
				statusRefresh.refreshLive(this);
			},

			reload: function(force) {
				var self = this;
				if (force) this.stopTimer();
				return loadAll().then(function(r) {
					var next = normalizeData(r);
					self.status = next.status;
					self.clients = next.clients;
					self.interfaces = next.interfaces;
					self.showIpv6 = next.showIpv6;
					self.hidePrivateIpv6 = next.hidePrivateIpv6;
					self.hideIpv6Ranges = next.hideIpv6Ranges;
					self.error = null;
					self.refreshLive();
					self.schedule();
				}).catch(function(error) {
					self.error = error;
					self.refreshLive();
					self.schedule();
				});
			}
		};

		var built = statusShell.buildShell(viewState);
		viewState.refs = built.refs;
		statusRefresh.refreshLive(viewState);
		viewState.schedule();
		return built.root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
