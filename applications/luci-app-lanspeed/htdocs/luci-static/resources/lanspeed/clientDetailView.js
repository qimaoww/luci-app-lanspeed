'use strict';
'require baseclass';
'require ui';
'require lanspeed.format as fmt';
'require lanspeed.rpc as lsRpc';
'require lanspeed.dhcpHostnames as dhcpHostnames';
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
	return Promise.all([
		lsRpc.clientConnections(identityKey),
		dhcpHostnames.loadForMac(dhcpHostnames.identityMac(identityKey))
	]).then(function(data) {
		return {
			identityKey: identityKey,
			response: data[0],
			customHostname: data[1] && data[1].host && data[1].host.name || '',
			hostnameAvailable: data[1] && data[1].available !== false,
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

function hostnameError(error) {
	return error && error.message ? error.message : String(error || _('未知错误'));
}

function showHostnameDialog(viewState, mac, currentName) {
	var originalName = String(currentName || '').trim();
	var input = E('input', {
		'id': 'lanspeed-hostname-modal-input',
		'type': 'text',
		'class': 'cbi-input-text lanspeed-connection-hostname-modal-input',
		'value': originalName,
		'maxlength': '63',
		'autocomplete': 'off',
		'spellcheck': 'false',
		'placeholder': _('留空使用客户端上报的名称'),
		'aria-describedby': 'lanspeed-hostname-modal-hint lanspeed-hostname-modal-status'
	});
	var status = E('p', {
		'id': 'lanspeed-hostname-modal-status',
		'class': 'lanspeed-connection-hostname-modal-status',
		'role': 'status',
		'aria-live': 'polite',
		'hidden': 'hidden'
	}, '');
	var cancelButton = E('button', {
		'type': 'button',
		'class': 'btn cbi-button'
	}, _('取消'));
	var saveButton = E('button', {
		'type': 'button',
		'class': 'cbi-button cbi-button-positive important'
	}, _('保存'));

	function setStatus(message, state) {
		status.textContent = message || '';
		status.hidden = !message;
		status.setAttribute('data-state', state || 'info');
		input.setAttribute('aria-invalid', state === 'error' ? 'true' : 'false');
	}

	function normalizedInput(showError) {
		try {
			var value = dhcpHostnames.normalizeName(input.value);
			if (showError)
				setStatus('', 'info');
			return value;
		} catch (error) {
			if (showError)
				setStatus(hostnameError(error), 'error');
			return null;
		}
	}

	function updateSaveState(showError) {
		var value = normalizedInput(showError);
		saveButton.disabled = viewState.hostnameSaving === true ||
			value === null || value === originalName;
	}

	function setSaving(saving) {
		viewState.hostnameSaving = saving === true;
		input.disabled = viewState.hostnameSaving;
		cancelButton.disabled = viewState.hostnameSaving;
		saveButton.disabled = viewState.hostnameSaving;
		saveButton.setAttribute('aria-busy', viewState.hostnameSaving ? 'true' : 'false');
		if (!viewState.hostnameSaving)
			updateSaveState(false);
	}

	function save() {
		var name = normalizedInput(true);
		if (name === null) {
			input.focus();
			return;
		}
		if (name === originalName) {
			ui.hideModal();
			return;
		}

		setSaving(true);
		setStatus(_('正在保存并应用 DHCP 配置…'), 'info');
		dhcpHostnames.saveForMac(mac, name).then(function(result) {
			if (result.changed)
				ui.changes.apply(false);
			return result;
		}).then(function(result) {
			viewState.customHostname = result && result.name !== undefined
				? String(result.name) : name;
			viewState.hostnameAvailable = true;
			setSaving(false);
			clientDetailRefresh.render(viewState);
			ui.hideModal();
			ui.addNotification(null, E('p', {}, viewState.customHostname
				? _('客户端主机名已保存。')
				: _('自定义主机名已清除。')), 'info');
			return viewState.reload(true);
		}, function(error) {
			setSaving(false);
			setStatus(_('保存失败：') + hostnameError(error), 'error');
			input.focus();
		});
	}

	cancelButton.addEventListener('click', function() {
		if (!viewState.hostnameSaving)
			ui.hideModal();
	});
	saveButton.addEventListener('click', save);
	input.addEventListener('input', function() {
		updateSaveState(true);
	});
	input.addEventListener('keydown', function(event) {
		if (event.key !== 'Enter')
			return;
		event.preventDefault();
		if (!saveButton.disabled)
			save();
	});

	ui.showModal(_('修改客户端主机名'), [
		E('div', { 'class': 'lanspeed-connection-hostname-modal-form' }, [
			E('label', {
				'class': 'lanspeed-connection-hostname-modal-label',
				'for': 'lanspeed-hostname-modal-input'
			}, _('自定义主机名')),
			input,
			E('p', {
				'id': 'lanspeed-hostname-modal-hint',
				'class': 'lanspeed-connection-hostname-modal-hint'
			}, _('保存到 /etc/config/dhcp，仅绑定 MAC，不固定 IP；留空可清除自定义名称。')),
			status
		]),
		E('div', { 'class': 'right lanspeed-connection-hostname-modal-actions' }, [
			cancelButton,
			' ',
			saveButton
		])
	], 'lanspeed-connection-hostname-modal');
	updateSaveState(false);
	input.focus();
	input.select();
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
			customHostname: data && data.customHostname || '',
			hostnameAvailable: data && data.hostnameAvailable !== false,
			hostnameMac: dhcpHostnames.identityMac(data && data.identityKey || ''),
			hostnameOpening: false,
			hostnameSaving: false,
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

			openHostnameDialog: function() {
				var self = this;
				var mac = this.hostnameMac;
				if (this.hostnameOpening || this.hostnameSaving)
					return Promise.resolve(false);
				if (!mac) {
					ui.addNotification(null,
						E('p', {}, _('无法确定客户端 MAC 地址。')), 'danger');
					return Promise.resolve(false);
				}
				this.hostnameOpening = true;
				clientDetailRefresh.render(this);
				return dhcpHostnames.loadForMac(mac).then(function(data) {
					self.hostnameOpening = false;
					if (!data.available) {
						self.hostnameAvailable = false;
						clientDetailRefresh.render(self);
						ui.addNotification(null, E('p', {},
							_('无法读取 /etc/config/dhcp：') + hostnameError(data.error)), 'danger');
						return false;
					}
					self.hostnameAvailable = true;
					self.customHostname = data.host && data.host.name || '';
					clientDetailRefresh.render(self);
					showHostnameDialog(self, mac, self.customHostname);
					return true;
				}, function(error) {
					self.hostnameOpening = false;
					self.hostnameAvailable = false;
					clientDetailRefresh.render(self);
					ui.addNotification(null, E('p', {},
						_('无法读取 /etc/config/dhcp：') + hostnameError(error)), 'danger');
					return false;
				});
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
				/* Keep one lookup batch alive across live-data refreshes. A changing
				 * connection list must not multiply requests while the previous page
				 * is still being resolved. */
				if (this.geoBatch)
					return;
				this.geoPageSignature = signature;
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
