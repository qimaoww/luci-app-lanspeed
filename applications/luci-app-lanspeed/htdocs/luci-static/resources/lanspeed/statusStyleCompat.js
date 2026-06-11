'use strict';
'require baseclass';

var STYLE_ID = 'lanspeed-style-argon-caps-compat';

var ARGON_CAPS_CSS = [
	'.lanspeed-theme-argon .lanspeed-caps{grid-template-columns:max-content 2.55rem max-content 2.55rem max-content 2.55rem max-content 2.55rem;',
	'  max-width:none;justify-content:start;align-items:center;column-gap:.9rem;row-gap:.5rem}',
	'.lanspeed-theme-argon .lanspeed-caps .cap{display:contents}',
	'.lanspeed-theme-argon .lanspeed-caps .cap>span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
	'.lanspeed-theme-argon .lanspeed-caps .cap>span:last-child{justify-self:start;min-width:2.25rem;text-align:center}',
	'@media (max-width:700px){.lanspeed-theme-argon .lanspeed-caps{grid-template-columns:minmax(0,max-content) 2.55rem;max-width:none}}'
].join('\n');

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
