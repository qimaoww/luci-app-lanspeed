'use strict';
'require view';
'require form';
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

return view.extend({
	load: function() {
		return configForm.loadValues();
	},

	render: function(values) {
		var viewState = {
			refs: {}
		};

		var root = E('div', { 'class': 'cbi-map lanspeed-config-root' }, [
			E('style', {}, configStyle.CSS),
			configForm.buildDaemonSection(values || configForm.DEFAULTS, viewState),
			E('div', { 'class': 'cbi-section' }, [
				ifaceCfg.buildSection(viewState, _('接口分配'))
			]),
			configForm.buildSaveSection(viewState)
		]);

		lsTheme.applyRoot(root);

		ifaceCfg.load(viewState);
		return root;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
