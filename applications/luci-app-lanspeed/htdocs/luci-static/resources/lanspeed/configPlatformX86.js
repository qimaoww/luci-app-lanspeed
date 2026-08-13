'use strict';
'require baseclass';

var PROFILE = 'x86_tc_bpf';

return baseclass.extend({
	PROFILE: PROFILE,
	detect: function(platform) {
		platform = platform || {};
		return String(platform.target_arch || '') === 'x86_64' || platform.nss_compiled === false;
	},
	supportsRateMode: function(mode) {
		return mode === 'auto' || mode === 'bpf';
	},
	autoLabel: function() {
		return _('自动（TC-BPF 推荐）');
	}
});
