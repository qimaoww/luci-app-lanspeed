'use strict';
'require view';
'require ui';
'require lanspeed.ifaceConfig as ifaceCfg';
'require lanspeed.theme as lsTheme';
'require lanspeed.configStyle as configStyle';
'require lanspeed.configForm as configForm';

/*
 * Thin LuCI configuration view entry.
 *
 * Runtime daemon form logic lives in configForm.js, layout CSS lives in
 * configStyle.js, and interface controls stay in ifaceConfig.js.
 */

function notifyError(error) {
	ui.addNotification(null, E('p', {}, error && error.message || String(error)), 'error');
	return false;
}

function stagedChangeCount() {
	var changes = ui.changes.changes || {};
	var count = 0;
	var config;

	for (config in changes) {
		if (Object.prototype.hasOwnProperty.call(changes, config) &&
		    Array.isArray(changes[config]))
			count += changes[config].length;
	}
	return count;
}

function refreshNativeChanges(viewState) {
	if (viewState)
		viewState.localDirty = false;
	ui.hideIndicator('uci-changes');
	return Promise.resolve(ui.changes.init()).then(function() { return true; });
}

function stageSettings(viewState) {
	return configForm.saveAll(viewState).then(function(saved) {
		if (!saved)
			return false;
		return refreshNativeChanges(viewState);
	});
}

function showNativeDirtyIndicator(viewState) {
	var count;

	if (!viewState || viewState.localDirty || viewState.configSaving)
		return;

	viewState.localDirty = true;
	count = stagedChangeCount() + 1;
	ui.hideIndicator('uci-changes');
	ui.showIndicator('uci-changes', String(_('Unsaved Changes')) + ': ' + count, function() {
		return stageSettings(viewState).then(function(saved) {
			if (saved)
				return ui.changes.displayChanges();
		}).catch(notifyError);
	});
}

return view.extend({
	load: function() {
		return configForm.loadValues();
	},

	render: function(values) {
		var viewState = {
			refs: {}
		};
		viewState.markDirty = function() {
			showNativeDirtyIndicator(viewState);
		};
		this.viewState = viewState;

		var root = E('div', { 'class': 'cbi-map lanspeed-config-root' }, [
			E('style', {}, configStyle.CSS),
			configForm.buildDaemonSection(values || configForm.DEFAULTS, viewState),
			E('div', { 'class': 'cbi-section' }, [
				ifaceCfg.buildSection(viewState, _('接口分配'))
			])
		]);

		lsTheme.applyRoot(root);

		ifaceCfg.load(viewState);
		return root;
	},

	handleSave: function() {
		return stageSettings(this.viewState).catch(notifyError);
	},

	handleSaveApply: function(ev, mode) {
		return stageSettings(this.viewState).then(function(saved) {
			if (saved)
				return ui.changes.apply(mode == '0');
		}).catch(notifyError);
	},

	handleReset: function() {
		var viewState = this.viewState;
		return configForm.resetAll(viewState).then(function(reset) {
			if (!reset)
				return false;
			return refreshNativeChanges(viewState);
		}).catch(notifyError);
	}
});
