'use strict';
'require baseclass';

var STYLE_ID = 'lanspeed-style-argon-caps-compat';

var ARGON_CAPS_CSS = [
	'.lanspeed-theme-argon .lanspeed-caps{grid-template-columns:repeat(4,12.95rem);max-width:56rem;justify-content:start;align-items:center;gap:.5rem 1rem;margin:.2rem 0 1rem 1.25rem}',
	'.lanspeed-theme-argon .lanspeed-caps .cap{display:grid;grid-template-columns:minmax(0,9.65rem) 2.55rem;',
	'  align-items:center;column-gap:.45rem;min-width:0;padding:.18rem 0}',
	'.lanspeed-theme-argon .lanspeed-caps .cap>span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
	'.lanspeed-theme-argon .lanspeed-caps .cap>span:last-child{justify-self:start;min-width:2.25rem;text-align:center}',
	'@media (max-width:700px){.lanspeed-theme-argon .lanspeed-caps{grid-template-columns:1fr;max-width:none}',
	'.lanspeed-theme-argon .lanspeed-caps .cap{grid-template-columns:minmax(0,9.65rem) 2.55rem;max-width:12.95rem}}'
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
