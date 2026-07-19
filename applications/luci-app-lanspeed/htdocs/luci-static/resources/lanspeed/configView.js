'use strict';
'require baseclass';
'require ui';
'require lanspeed.ifaceConfig as ifaceCfg';
'require lanspeed.theme as lsTheme';
'require lanspeed.configStyle as configStyle';
'require lanspeed.configForm as configForm';

function errorText(error) {
	return error && error.message || String(error);
}

function notifyError(error) {
	ui.addNotification(null, E('p', {}, errorText(error)), 'error');
	return false;
}

function stagedChangeCount() {
	var changes = ui.changes && ui.changes.changes || {};
	var count = 0;
	Object.keys(changes).forEach(function(config) {
		if (Array.isArray(changes[config])) count += changes[config].length;
	});
	return count;
}

function refreshNativeChanges(viewState) {
	if (viewState) viewState.localDirty = false;
	if (ui.hideIndicator) ui.hideIndicator('uci-changes');
	if (!ui.changes || typeof ui.changes.init !== 'function') return Promise.resolve(true);
	return Promise.resolve(ui.changes.init()).then(function() { return true; });
}

function showNativeDirtyIndicator(viewState) {
	if (!viewState || viewState.localDirty || viewState.configSaving) return;
	viewState.localDirty = true;
	var count = stagedChangeCount() + 1;
	if (ui.hideIndicator) ui.hideIndicator('uci-changes');
	if (ui.showIndicator) {
		ui.showIndicator('uci-changes', String(_('Unsaved Changes')) + ': ' + count, function() {
			return configForm.saveAll(viewState).then(function(result) {
				if (!result)
					return result;
				return refreshNativeChanges(viewState).then(function() {
					if (ui.changes && typeof ui.changes.displayChanges === 'function')
						return ui.changes.displayChanges();
					return result;
				});
			}).catch(notifyError);
		});
	}
}

function setNativeActionState(viewState, valid, busy) {
	var doc = typeof document !== 'undefined' ? document : null;
	if (!doc || !doc.querySelectorAll) return;
	var saveButtons = doc.querySelectorAll('.cbi-page-actions .cbi-button-save, .cbi-page-actions .cbi-button-apply');
	var resetButtons = doc.querySelectorAll('.cbi-page-actions .cbi-button-reset');
	Array.prototype.forEach.call(saveButtons, function(button) {
		button.disabled = Boolean(busy || !valid);
		button.setAttribute('aria-disabled', button.disabled ? 'true' : 'false');
	});
	Array.prototype.forEach.call(resetButtons, function(button) {
		button.disabled = Boolean(busy);
		button.setAttribute('aria-disabled', button.disabled ? 'true' : 'false');
	});
}

function nativeActionContainer(container) {
	var actions = container && container.querySelector && container.querySelector('.cbi-page-actions');
	if (!actions && container && container.matches && container.matches('.cbi-page-actions'))
		actions = container;
	return actions;
}

function setNativeActionFailureState(container, failed) {
	var actions = nativeActionContainer(container);
	if (!actions) return container;
	if (failed) {
		actions.setAttribute('data-lanspeed-state', 'hard-error');
		actions.setAttribute('aria-hidden', 'true');
		actions.hidden = true;
		var buttons = actions.querySelectorAll ? actions.querySelectorAll('.cbi-button,button') : [];
		Array.prototype.forEach.call(buttons, function(button) {
			button.disabled = true;
			button.setAttribute('aria-disabled', 'true');
		});
	} else if (actions.getAttribute && actions.getAttribute('data-lanspeed-state') === 'hard-error') {
		actions.removeAttribute('data-lanspeed-state');
		actions.removeAttribute('aria-hidden');
		actions.hidden = false;
	}
	return container;
}

function scopeNativeActions(container, root) {
	var doc = typeof document !== 'undefined' ? document : null;
	var actions = nativeActionContainer(container);
	root = root || doc && doc.querySelector && doc.querySelector('.lanspeed-config-root');
	if (!actions || !root || !root.getAttribute)
		return container;
	if (actions.__lanspeedThemeRoot && actions.__lanspeedThemeListener &&
	    typeof actions.__lanspeedThemeRoot.removeEventListener === 'function') {
		actions.__lanspeedThemeRoot.removeEventListener('lanspeed-theme-update',
			actions.__lanspeedThemeListener);
	}
	var sync = function() {
		var attributes = {
			'data-lanspeed-theme': root.getAttribute('data-lanspeed-theme') || '',
			'data-lanspeed-color-mode': root.getAttribute('data-lanspeed-color-mode') || ''
		};
		Object.keys(attributes).forEach(function(name) {
			if (actions.getAttribute(name) !== attributes[name])
				actions.setAttribute(name, attributes[name]);
		});
		if (!doc || !doc.defaultView || !doc.defaultView.getComputedStyle || !actions.style)
			return;
		var style = doc.defaultView.getComputedStyle(root);
		var values = {
			'--lanspeed-footer-action':
				style.getPropertyValue('--lanspeed-filled-action-safe').trim() ||
				style.getPropertyValue('--lanspeed-accent-safe').trim(),
			'--lanspeed-footer-action-text':
				style.getPropertyValue('--lanspeed-filled-action-text-safe').trim(),
			'--lanspeed-footer-danger':
				style.getPropertyValue('--lanspeed-danger-safe').trim()
		};
		Object.keys(values).forEach(function(name) {
			var current = actions.style.getPropertyValue(name).trim();
			if (values[name] && current !== values[name])
				actions.style.setProperty(name, values[name]);
			else if (!values[name] && current)
				actions.style.removeProperty(name);
		});
	};
	sync();
	if (typeof root.addEventListener === 'function') {
		root.addEventListener('lanspeed-theme-update', sync);
		actions.__lanspeedThemeRoot = root;
		actions.__lanspeedThemeListener = sync;
	}
	return container;
}

function updatePageState(viewState) {
	var root = viewState.root;
	var daemon = viewState.loadData || {};
	var ifaceState = viewState.interfaceStatus || 'loading';
	var state = daemon.pageState || 'ready';
	if (ifaceState === 'loading' && !viewState.ifcfgLoaded) state = 'loading';
	else if (ifaceState === 'hard-error' && !viewState.ifcfgLoaded) state = 'hard-error';
	else if (ifaceState === 'degraded' || daemon.pageState === 'degraded') state = 'degraded';
	else if (ifaceState === 'empty') state = 'empty';
	if (root) {
		root.setAttribute('data-state', state);
		root.setAttribute('aria-busy', viewState.configSaving || viewState.ifcfgLoading ? 'true' : 'false');
	}
	if (viewState.refs && viewState.refs.pageState) {
		var labels = {
			loading: _('正在加载'), ready: _('可编辑'), empty: _('等待配置'),
			degraded: _('部分降级'), 'hard-error': _('不可用')
		};
		viewState.refs.pageState.className = 'label lanspeed-config-page-state ' +
			(state === 'ready' ? 'label-success' : state === 'loading' || state === 'empty' || state === 'degraded'
				? 'label-warning' : 'label-danger');
		viewState.refs.pageState.textContent = labels[state] || labels.loading;
	}
}

function retryButton() {
	var button = E('button', { 'class': 'cbi-button cbi-button-action', 'type': 'button' }, _('重新加载'));
	button.addEventListener('click', function() { window.location.reload(); });
	return button;
}

function failureRoot(error) {
	var root = E('div', { 'class': 'cbi-map lanspeed-config-root', 'data-state': 'hard-error' }, [
		E('style', {}, configStyle.CSS),
		E('section', { 'class': 'cbi-section lanspeed-page-failure', 'role': 'alert', 'aria-live': 'assertive' }, [
			E('div', { 'class': 'lanspeed-header' }, [ E('h3', {}, _('LAN Speed 配置不可用')) ]),
			E('div', { 'class': 'lanspeed-config-body' }, [
				E('p', { class: 'lanspeed-state-message', 'data-state': 'error' }, errorText(error)),
				retryButton()
			])
		])
	]);
	lsTheme.applyRoot(root);
	return root;
}

function applyAndVerify(viewState) {
	var retryDelays = [ 500, 750, 1000, 1500, 2000 ];
	var attempt = 0;
	function run() {
		return configForm.verifyAll(viewState).then(function(result) {
			if (result && result.ok) return result;
			if (attempt < retryDelays.length) {
				configForm.setFeedback(viewState, 'verifying',
					_('配置已应用，正在等待守护进程与接口就绪…'));
				var delay = retryDelays[attempt++];
				return new Promise(function(resolve) { setTimeout(resolve, delay); }).then(run);
			}
			return result;
		});
	}
	return run();
}

return baseclass.extend({
	load: function() {
		return configForm.loadValues().then(function(values) {
			return { values: values, error: null };
		}, function(error) {
			return { values: null, error: error };
		});
	},

	render: function(data) {
		var loadError = data && data.error;
		if (loadError) {
			this.viewState = { failed: true };
			return failureRoot(loadError);
		}
		var values = data && Object.prototype.hasOwnProperty.call(data, 'values') ? data.values : data;
		var viewState = {
			refs: {},
			loadData: values || {},
			interfaceStatus: 'loading',
			localDirty: false,
			configSaving: false
		};
		viewState.markDirty = function() {
			showNativeDirtyIndicator(viewState);
			if (typeof configForm.validate === 'function') configForm.validate(viewState);
			updatePageState(viewState);
		};
		viewState.updatePageState = function() { updatePageState(viewState); };
		viewState.onValidityChange = function(valid, busy) {
			setNativeActionState(viewState, valid, busy);
		};
		this.viewState = viewState;
		viewState.refs.pageState = E('span', {
			'class': 'label label-warning lanspeed-config-page-state',
			'role': 'status', 'aria-live': 'polite'
		}, _('正在加载'));
		var runtimeSection = configForm.buildDaemonSection(values || configForm.DEFAULTS, viewState);
		var interfaceSection = ifaceCfg.buildSection(viewState, _('接口分配'));
		var pageSection = E('section', { 'class': 'cbi-section lanspeed-config-page-section' }, [
			E('div', { 'class': 'lanspeed-header lanspeed-config-primary-header' }, [
				E('h3', {}, _('LAN Speed 配置')),
				viewState.refs.pageState
			]),
			E('div', { 'class': 'lanspeed-config-page-body' }, [ runtimeSection, interfaceSection ])
		]);
		var root = E('div', {
			'class': 'cbi-map lanspeed-config-root',
			'aria-busy': 'true',
			'data-state': values && values.pageState || 'loading'
		}, [
			E('style', {}, configStyle.CSS),
			pageSection
		]);
		viewState.root = root;
		lsTheme.applyRoot(root);
		if (values && values.model && !values.model.valid)
			configForm.setFeedback(viewState, 'degraded', _('部分 UCI 值无效，已显示安全默认值，请确认后保存'));
		else if (values && values.rpc && values.rpc.status && !values.rpc.status.ok)
			configForm.setFeedback(viewState, 'degraded', _('运行状态读取失败，能力选项将在重新检查后更新'));
		else
			configForm.setFeedback(viewState, values && values.pageState === 'empty' ? 'empty' : 'ready', '');
		updatePageState(viewState);
		ifaceCfg.load(viewState).then(function() {
			updatePageState(viewState);
			if (typeof configForm.validate === 'function') configForm.validate(viewState);
		});
		return root;
	},

	handleSave: function() {
		var viewState = this.viewState;
		if (!viewState || viewState.failed) return Promise.resolve(false);
		return configForm.saveAll(viewState).then(function(result) {
			return refreshNativeChanges(viewState).then(function() { return result; });
		}).catch(notifyError);
	},

	handleSaveApply: function(ev, mode) {
		var viewState = this.viewState;
		if (!viewState || viewState.failed) return Promise.resolve(false);
		return configForm.saveAll(viewState).then(function(result) {
			if (!result || !result.ok) return result;
			return refreshNativeChanges(viewState).then(function() {
				if (!ui.changes || typeof ui.changes.apply !== 'function') return result;
				return Promise.resolve(ui.changes.apply(mode == '0')).then(function() {
					if (typeof configForm.markApplied === 'function')
						configForm.markApplied(viewState);
					return applyAndVerify(viewState);
				});
			});
		}).catch(notifyError);
	},

	handleReset: function() {
		var viewState = this.viewState;
		if (!viewState || viewState.failed) return Promise.resolve(false);
		return configForm.resetAll(viewState).then(function(result) {
			return refreshNativeChanges(viewState).then(function() { return result; });
		}).catch(notifyError);
	},

	decorateFooter: function(footer) {
		var scoped = scopeNativeActions(footer);
		return setNativeActionFailureState(scoped, Boolean(this.viewState && this.viewState.failed));
	}
});
