'use strict';
'require baseclass';

/* Theme-neutral layout for the dedicated runtime diagnostics page. */
var BASE_CSS = [
	'.lanspeed-diagnostics-root{display:flex;flex-direction:column;gap:1em;margin:0}',
	'.lanspeed-diagnostics-root>.cbi-section{margin:0;padding:0;overflow:hidden;font-weight:400}',
	'.lanspeed-diagnostics-header{display:flex;flex-wrap:wrap;gap:.45em 1em;align-items:center;',
	'  padding:1em 1.25em .8em;border-bottom:1px solid var(--border,rgba(128,128,128,.25))}',
	'.lanspeed-diagnostics-header>h3{margin:0;padding:0;border:0;width:auto;display:inline;',
	'  flex:0 0 auto;background:transparent;box-shadow:none;line-height:1.25;font-weight:600}',
	'.lanspeed-diagnostics-header>.spacer{flex:1 1 auto}',
	'.lanspeed-diagnostics-summary{margin:0;white-space:nowrap}',
	'.lanspeed-diagnostics-meta{font-size:.82em;line-height:1.4;opacity:.7;white-space:nowrap;',
	'  font-family:var(--font-monospace,ui-monospace,monospace)}',
	'.lanspeed-diagnostics-body{padding:1.1em 1.25em}',
	'.lanspeed-diagnostics-toolbar{display:flex;flex-wrap:wrap;align-items:center;',
	'  justify-content:space-between;gap:.7em 1em;margin:0 0 1.1em}',
	'.lanspeed-diagnostics-intro{margin:0;max-width:56em;font-size:.9em;line-height:1.55;opacity:.75}',
	'.lanspeed-diagnostics-refresh{flex:0 0 auto;white-space:nowrap}',
	'.lanspeed-diagnostics-error{display:none;margin:0 0 1em}',
	'.lanspeed-diagnostics-error pre{white-space:pre-wrap;margin:.4em 0 0;font-size:.85em}',

	'.lanspeed-diagnostic-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0;margin:0}',
	'.lanspeed-diagnostic-card{min-width:0;min-height:8em;padding:.15em 1.5em;',
	'  border:0;border-right:1px solid var(--border,rgba(128,128,128,.2));',
	'  border-radius:0;background:transparent;box-sizing:border-box}',
	'.lanspeed-diagnostic-card:first-child{padding-left:0}',
	'.lanspeed-diagnostic-card:last-child{padding-right:0;border-right:0}',
	'.lanspeed-diagnostic-card-head{display:flex;align-items:center;justify-content:space-between;',
	'  gap:.75em;margin:0 0 .65em}',
	'.lanspeed-diagnostic-card-title{font-size:.78em;font-weight:600;letter-spacing:.03em;opacity:.65}',
	'.lanspeed-diagnostic-badge{margin:0;font-size:.74em;white-space:nowrap}',
	'.lanspeed-diagnostic-value{font-size:1.15em;font-weight:650;line-height:1.3;margin:0 0 .3em}',
	'.lanspeed-diagnostic-description{margin:0;min-height:2.7em;padding:0;font-size:.86em;line-height:1.55;opacity:.76}',
	'.lanspeed-diagnostic-meta{margin:.55em 0 0;padding:0;font-size:.74em;line-height:1.4;opacity:.55;',
	'  font-family:var(--font-monospace,ui-monospace,monospace);overflow-wrap:anywhere}',
	'.lanspeed-diagnostic-alerts-section{margin:1.15em 0 0;padding:1em 0 0;',
	'  border-top:1px solid var(--border,rgba(128,128,128,.18))}',
	'.lanspeed-diagnostic-alerts-title{margin:0 0 .65em;padding:0;border:0;width:auto;',
	'  background:transparent;box-shadow:none;font-size:.9em;font-weight:650;line-height:1.35;opacity:.78}',
	'.lanspeed-diagnostic-alerts{display:grid;gap:.55em;margin:0;padding:0;list-style:none}',
	'.lanspeed-diagnostic-alert,.lanspeed-diagnostic-alert-empty{display:grid;',
	'  grid-template-columns:1.7em minmax(0,1fr);align-items:start;gap:.65em;padding:.72em .8em;',
	'  border:1px solid var(--border,rgba(128,128,128,.2));border-radius:.6em;font-size:.86em;line-height:1.5}',
	'.lanspeed-diagnostic-alert{background:rgba(197,138,22,.07)}',
	'.lanspeed-diagnostic-alert[data-level="danger"]{background:rgba(214,69,69,.07)}',
	'.lanspeed-diagnostic-alert-empty{background:rgba(46,157,99,.07)}',
	'.lanspeed-diagnostic-alert-icon{display:inline-flex;align-items:center;justify-content:center;',
	'  width:1.7em;height:1.7em;border-radius:999px;font-size:.78em;font-weight:700;',
	'  color:var(--warning,#c58a16);background:rgba(197,138,22,.14)}',
	'.lanspeed-diagnostic-alert[data-level="danger"] .lanspeed-diagnostic-alert-icon{',
	'  color:var(--danger,#d64545);background:rgba(214,69,69,.14)}',
	'.lanspeed-diagnostic-alert-empty .lanspeed-diagnostic-alert-icon{',
	'  color:var(--success,#2e9d63);background:rgba(46,157,99,.14)}',
	'.lanspeed-diagnostic-alert-text{min-width:0;overflow-wrap:anywhere}'
].join('\n');

return baseclass.extend({
	CSS: BASE_CSS
});
