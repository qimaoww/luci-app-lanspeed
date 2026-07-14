'use strict';
'require baseclass';
'require lanspeed.statusStyleArgon as statusStyleArgon';

var STYLE_ID = 'lanspeed-style-argon-caps-compat-live2';
var ARGON_CAPS_CSS = statusStyleArgon.CAPS_CSS;

function install(root) {
	var host = root || document.head;
	var oldStyle = document.getElementById(STYLE_ID);
	if (oldStyle && oldStyle.parentNode === host) return oldStyle;
	if (oldStyle && oldStyle.parentNode) oldStyle.parentNode.removeChild(oldStyle);

	var style = document.createElement('style');
	style.id = STYLE_ID;
	style.textContent = ARGON_CAPS_CSS;
	host.appendChild(style);
	return style;
}

return baseclass.extend({
	CSS: ARGON_CAPS_CSS,
	install: install
});
