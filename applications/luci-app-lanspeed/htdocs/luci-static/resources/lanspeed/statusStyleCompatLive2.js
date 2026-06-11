'use strict';
'require baseclass';

var STYLE_ID = 'lanspeed-style-argon-caps-compat-live2';

var ARGON_CAPS_CSS = [
	'.lanspeed-theme-argon .lanspeed-caps{grid-template-columns:max-content 2.55rem max-content 2.55rem max-content 2.55rem max-content 2.55rem;',
	'  max-width:none;justify-content:start;align-items:center;column-gap:.9rem;row-gap:.5rem}',
	'.lanspeed-theme-argon .lanspeed-caps .cap{display:contents}',
	'.lanspeed-theme-argon .lanspeed-caps .cap>span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
	'.lanspeed-theme-argon .lanspeed-caps .cap>span:last-child{justify-self:start;min-width:2.25rem;text-align:center}',
	'@media (max-width:700px){.lanspeed-theme-argon .lanspeed-caps{grid-template-columns:minmax(0,max-content) 2.55rem;max-width:none}}'
].join('\n');

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
