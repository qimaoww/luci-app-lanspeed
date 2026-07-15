'use strict';
'require baseclass';

var CSS = [
	'.lanspeed-connection-detail{display:flex;flex-direction:column;gap:1em;margin:0}',
	'.lanspeed-connection-breadcrumb{display:flex;flex-wrap:wrap;align-items:center;gap:.65em}',
	'.lanspeed-connection-breadcrumb-current{font-size:.9em;opacity:.72}',
	'.lanspeed-connection-back{flex:0 0 auto}',
	'.lanspeed-connection-error{display:flex;align-items:baseline;gap:.5em;margin:0}',
	'.lanspeed-connection-error[hidden],.lanspeed-connection-empty[hidden]{display:none!important}',
	'.lanspeed-connection-identity{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(18em,1fr);gap:1em 2em;align-items:start}',
	'.lanspeed-connection-client{min-width:0}',
	'.lanspeed-connection-client-name{margin:0 0 .25em;font-size:1.1em;font-weight:600;overflow-wrap:anywhere}',
	'.lanspeed-connection-client-meta{margin:0;font-size:.88em;opacity:.72;overflow-wrap:anywhere}',
	'.lanspeed-connection-state{white-space:nowrap}',
	'.lanspeed-connection-summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.5em 1em;min-width:0}',
	'.lanspeed-connection-summary-title{grid-column:1/-1;margin:0;font-size:.9em;font-weight:600}',
	'.lanspeed-connection-summary-item{display:flex;flex-direction:column;min-width:0}',
	'.lanspeed-connection-summary-label{font-size:.75em;opacity:.68}',
	'.lanspeed-connection-summary-value{font-variant-numeric:tabular-nums;overflow-wrap:anywhere}',
	'.lanspeed-connection-toolbar{align-items:center}',
	'.lanspeed-connection-toolbar-left{grid-template-columns:auto minmax(12em,1fr)}',
	'.lanspeed-connection-protocols{display:inline-flex;align-items:center;gap:.35em;white-space:nowrap}',
	'.lanspeed-connection-protocol[aria-pressed="true"]{font-weight:600;box-shadow:inset 0 0 0 2px currentColor}',
	'.lanspeed-connection-protocol-label{font-size:.9em;margin-right:.1em}',
	'.lanspeed-connection-filter{min-width:0}',
	'.lanspeed-connection-filter-input{min-width:10em;max-width:24em;width:100%}',
	'.lanspeed-connections-card .lanspeed-body{min-width:0}',
	'.lanspeed-connection-table{table-layout:auto}',
	'.lanspeed-connection-endpoint{font-family:var(--font-monospace,ui-monospace,monospace);overflow-wrap:anywhere;word-break:break-word}',
	'.lanspeed-connection-group-row{cursor:default}',
	'.lanspeed-connection-expand{display:inline-flex;align-items:center;gap:.35em}',
	'.lanspeed-connection-detail-row>td{padding-top:0}',
	'.lanspeed-connection-detail-cell{min-width:0}',
	'.lanspeed-connection-detail-list{display:grid;gap:.35em;margin:0;padding:.25em 0 .5em}',
	'.lanspeed-connection-detail-item{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.5em 1em;min-width:0}',
	'.lanspeed-connection-empty{padding:1.2em 0;text-align:center;opacity:.7}',
	'.lanspeed-connection-footer{margin:.8em 0 0;font-size:.85em;opacity:.72}'
].join('\n');

return baseclass.extend({
	CSS: CSS
});
