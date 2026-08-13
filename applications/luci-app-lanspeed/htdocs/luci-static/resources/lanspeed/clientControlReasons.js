'use strict';
'require baseclass';
'require lanspeed.clientControlReasonsShared as sharedReasons';
'require lanspeed.clientControlReasonsX86 as x86Reasons';
'require lanspeed.clientControlReasonsNss as nssReasons';

var LABELS = Object.assign({}, sharedReasons.LABELS, x86Reasons.LABELS, nssReasons.LABELS);

return baseclass.extend({
	LABELS: LABELS,
	text: function(reason) {
		return LABELS[String(reason || '')] ||
			(reason ? _('控制不可用：%s').format(reason) : '');
	}
});
