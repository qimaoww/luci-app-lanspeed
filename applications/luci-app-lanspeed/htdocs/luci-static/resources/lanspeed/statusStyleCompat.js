'use strict';
'require baseclass';
'require lanspeed.statusStyleArgon as statusStyleArgon';

var STYLE_ID = 'lanspeed-style-argon-caps-compat';
var ARGON_CAPS_CSS = statusStyleArgon.CAPS_CSS;

function install() {
	if (document.getElementById(STYLE_ID)) return;

	var style = document.createElement('style');
	style.id = STYLE_ID;
	style.textContent = ARGON_CAPS_CSS;
	document.head.appendChild(style);
}

return baseclass.extend({
	CSS: ARGON_CAPS_CSS,
	install: install
});
