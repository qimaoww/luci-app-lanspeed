'use strict';
'require baseclass';

var PROFILE = 'nss_aarch64';

return baseclass.extend({
	PROFILE: PROFILE,
	detect: function(platform) {
		platform = platform || {};
		return String(platform.target_arch || '') === 'aarch64' && platform.nss_compiled !== false;
	},
	supportsRateMode: function(mode) {
		return [ 'auto', 'bpf', 'nss_ecm_node', 'nss_ecm_bpf' ].indexOf(mode) !== -1;
	},
	autoLabel: function(defaultLabel) {
		return defaultLabel;
	}
});
