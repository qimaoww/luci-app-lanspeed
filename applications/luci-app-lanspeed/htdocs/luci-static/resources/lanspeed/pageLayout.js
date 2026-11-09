'use strict';
'require baseclass';

/* Shared geometry only. Colors, fonts and state colors come from the active
 * LuCI theme; each page owns its content layout and platform behavior. */
var ROOT = '.lanspeed-page.cbi-map';
var CSS = [
	ROOT + '{width:100%;max-width:100rem;min-width:0;margin:0 auto;gap:20px;',
		'--lanspeed-radius-section:12px;--lanspeed-radius-control:8px;',
		'--lanspeed-radius-input:8px;--lanspeed-radius-button:8px;',
		'--lanspeed-shadow-section:none;--lanspeed-section-x:20px;--lanspeed-section-y:20px;',
		'--lanspeed-control-height:38px;font-size:14px;line-height:1.5}',
	ROOT + ' .lanspeed-page-header{display:flex;align-items:center;justify-content:space-between;',
		'flex-wrap:wrap;gap:16px 24px;min-width:0;padding:2px 0 0;margin:0;border:0;background:transparent;color:inherit;',
		/* Native themes style all header elements as site navigation. Page
		 * headings must stay in content flow when that navigation sticks. */
		'position:static;inset:auto;z-index:auto}',
	ROOT + ' .lanspeed-page-header::before,' + ROOT + ' .lanspeed-page-header::after{display:none;content:none}',
	ROOT + ' .lanspeed-page-heading{min-width:0}',
	ROOT + ' .lanspeed-page-title-line{display:flex;align-items:center;flex-wrap:wrap;gap:12px}',
	ROOT + ' .lanspeed-page-header h2{width:auto;margin:0;padding:0;border:0;background:none;box-shadow:none;',
		'font-size:22px;font-weight:650;line-height:1.4;letter-spacing:0;color:var(--lanspeed-text)}',
	ROOT + ' .lanspeed-page-description{margin:4px 0 0;color:var(--lanspeed-text-muted);font-size:13px;line-height:1.5}',
	ROOT + ' :is(h3,h4){color:var(--lanspeed-text)}',
	ROOT + ' .lanspeed-header-actions{display:flex;flex-wrap:wrap;align-items:center;gap:8px}',
	ROOT + ' .cbi-button{min-height:36px;padding:7px 14px;font-size:13px;line-height:1.4;',
		'border-radius:var(--lanspeed-radius-button);box-shadow:none}',
	ROOT + ' :is(input:not([type="checkbox"]):not([type="radio"]),select,textarea){box-shadow:none}',
	ROOT + ' .label{font-size:12px;font-weight:500;padding:3px 8px;box-shadow:none}',
	ROOT + '>:is(.cbi-section,.lanspeed-config-subsection,.lanspeed-ifcfg){padding:20px;border-radius:12px;box-shadow:none!important}',
	'.cbi-page-actions[data-lanspeed-theme]{width:100%;max-width:100rem;margin-left:auto;margin-right:auto}',
	'@media(max-width:600px){' + ROOT + '{gap:16px;--lanspeed-section-x:16px;--lanspeed-section-y:16px}',
	ROOT + ' .lanspeed-page-header{gap:12px}',
	ROOT + ' .lanspeed-page-header h2{font-size:20px}',
	ROOT + '>:is(.cbi-section,.lanspeed-config-subsection,.lanspeed-ifcfg){padding:16px}',
	ROOT + ' .lanspeed-header-actions{width:100%}',
	ROOT + ' .lanspeed-header-actions>.cbi-button{flex:1 1 auto}}',
	'@media(pointer:coarse){' + ROOT + ' .cbi-button{min-height:44px}',
	ROOT + ' :is(input:not([type="checkbox"]):not([type="radio"]),select){min-height:44px!important}}'
].join('\n');

return baseclass.extend({ CSS: CSS });
