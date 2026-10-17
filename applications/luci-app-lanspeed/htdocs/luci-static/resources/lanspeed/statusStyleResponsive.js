'use strict';
'require baseclass';

/*
 * Shared tablet and mobile layout rules, kept after theme overrides so they
 * win the cascade.
 *
 * The client list is a fixed-track table only while its own card is wide
 * enough to show every column. Below that it becomes one card per client.
 * The switch follows the card width (a container query), so a LuCI sidebar
 * or a narrow theme content column is handled the same as a narrow phone.
 * Browsers without container queries use the viewport fallback and, between
 * the two, scroll the table inside its own viewport.
 *
 * Nothing is pinned with position:sticky: several themes paint translucent
 * section surfaces, and a pinned cell cannot match them while content
 * scrolls underneath.
 */
var CARD_MAX = '50em';
var CARD_WIDE_MIN = '34em';

/* One client per card: identity and MAC/vendor span the card, the two-line
 * rate/total/connection stacks follow, and actions close the card. */
var CARD_RULES = [
	'.lanspeed-clients-card .lanspeed-table-scroll{overflow-x:visible}',
	'.lanspeed-clients-card .lanspeed-clients-table,',
	'.lanspeed-clients-card .lanspeed-clients-table tbody{display:block;width:100%;min-width:0;table-layout:auto}',
	'.lanspeed-clients-card .lanspeed-clients-table thead{display:none}',
	'.lanspeed-clients-card .lanspeed-clients-table tbody>tr{display:grid;',
	'  grid-template-columns:repeat(2,minmax(0,1fr));gap:.55em .9em;align-items:start;',
	'  padding:.75em 0;border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-clients-card .lanspeed-clients-table tbody>tr:last-child{border-bottom:0}',
	'.lanspeed-clients-card .lanspeed-clients-table tbody td,',
	'.lanspeed-status-root .lanspeed-clients-card .lanspeed-clients-table tbody td.num{display:block;width:auto;min-width:0;',
	'  padding:0!important;border:0!important;text-align:left;overflow:visible}',
	'.lanspeed-clients-card .lanspeed-client-name,',
	'.lanspeed-clients-card .lanspeed-client-mac{grid-column:1/-1}',
	/* Long hostnames, IPv6 lists and vendor names wrap instead of clipping. */
	'.lanspeed-clients-card .lanspeed-connection-link{font-size:1.05em;white-space:normal;overflow-wrap:anywhere}',
	'.lanspeed-clients-card .lanspeed-client-name .ipline{white-space:normal;overflow-wrap:anywhere}',
	'.lanspeed-clients-card .lanspeed-client-mac{display:flex!important;flex-wrap:wrap;gap:.15em .7em;align-items:baseline}',
	'.lanspeed-clients-card .lanspeed-client-mac-value{flex:0 0 auto}',
	'.lanspeed-clients-card .lanspeed-client-vendor{flex:1 1 10em;margin:0;white-space:normal;overflow-wrap:anywhere}',
	'.lanspeed-clients-card .lanspeed-clients-table td:is(.lanspeed-client-rate-cell,.lanspeed-client-total-cell,',
	'  .lanspeed-client-conns-cell)[data-label]::before{content:attr(data-label);',
	'  display:block;margin:0 0 .2em;font-size:.72em;font-family:inherit;font-weight:600;',
	'  line-height:1.2;color:var(--lanspeed-text-muted)}',
	'.lanspeed-clients-card .lanspeed-client-traffic-stack{width:auto;max-width:10.5em}',
	'.lanspeed-clients-card .lanspeed-client-conns-cell .lanspeed-client-traffic-stack{max-width:none}',
	'.lanspeed-clients-card .lanspeed-client-conns-cell .lanspeed-client-conn-line{grid-template-columns:auto auto;gap:.35em}',
	'.lanspeed-clients-card .lanspeed-client-control{align-self:center}',
	/* Connections are short; let them share the last row with the actions. */
	'.lanspeed-clients-card .lanspeed-client-conns-cell .lanspeed-client-traffic-stack{grid-template-columns:repeat(2,max-content);column-gap:1.1em}',
	'.lanspeed-clients-card .lanspeed-client-conns-cell[data-label]::before{grid-column:1/-1}',
	'.lanspeed-clients-card .lanspeed-clients-table[data-client-totals="hidden"] .lanspeed-client-control{grid-column:1/-1}',
	'.lanspeed-clients-card .lanspeed-control-actions{flex-wrap:wrap;justify-content:flex-end}'
];

/* Wider cards (tablet, split view) keep all live numbers on one line. */
var WIDE_CARD_RULES = [
	'.lanspeed-clients-card .lanspeed-clients-table tbody>tr{',
	'  grid-template-columns:minmax(0,1fr) minmax(0,1fr) minmax(0,.75fr) auto}',
	'.lanspeed-clients-card .lanspeed-clients-table[data-client-totals="hidden"] tbody>tr{',
	'  grid-template-columns:minmax(0,1fr) minmax(0,.75fr) auto}',
	'.lanspeed-clients-card .lanspeed-clients-table[data-client-totals] .lanspeed-client-control{grid-column:auto}'
];

var RESPONSIVE_CSS = [
	'.lanspeed-clients-card>.lanspeed-body{container:lanspeed-clients/inline-size}',
	'@media (max-width:1100px){.lanspeed-root .lanspeed-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}',
	'@media (max-width:900px){.lanspeed-root .lanspeed-toolbar-right{justify-content:flex-start;margin-left:0}',
	'.lanspeed-root .lanspeed-status-bar>.spacer{display:none}',
	'.lanspeed-root .lanspeed-status-actions{flex:1 1 100%;justify-content:flex-start}}',

	'@container lanspeed-clients (max-width:' + CARD_MAX + '){' + CARD_RULES.join('\n') + '}',
	'@container lanspeed-clients (min-width:' + CARD_WIDE_MIN + ') and (max-width:' + CARD_MAX + '){' +
		WIDE_CARD_RULES.join('\n') + '}',
	'@supports not (container-type:inline-size){@media (max-width:700px){' + CARD_RULES.join('\n') + '}}',

	'@media (max-width:700px){',
	'.lanspeed-header,.lanspeed-details>summary{align-items:center}',
	'.lanspeed-root .lanspeed-status-actions{gap:.45em}',
	'.lanspeed-root .lanspeed-status-actions .cbi-button{flex:1 1 0;min-width:0}',
	'.lanspeed-root .lanspeed-status-actions .lanspeed-refresh-control{flex:0 0 auto}',
	'.lanspeed-root .lanspeed-toolbar-left{flex-basis:100%}',
	'.lanspeed-root .lanspeed-toolbar-right{flex:1 1 100%;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.5em}',
	'.lanspeed-root .lanspeed-toolbar .lanspeed-unit-control select{width:6.5em!important;min-width:6.5em;max-width:6.5em}',
	'.lanspeed-root .lanspeed-toolbar-filter{min-width:0;flex:1 1 100%}',
	'.lanspeed-root .lanspeed-toolbar input[type="search"]{min-width:0;max-width:none}',
	'.lanspeed-root .lanspeed-toolbar .lanspeed-sort-control{flex:1 1 auto;min-width:0}',
	'.lanspeed-root .lanspeed-toolbar .lanspeed-sort-control select{flex:1 1 auto;width:100%!important;min-width:0;max-width:none}',
	'.lanspeed-status-error{grid-template-columns:minmax(0,1fr);gap:.25em}',
	'.lanspeed-status-error-title{white-space:normal}',
	'.lanspeed-status-error-list{grid-column:auto;grid-template-columns:minmax(0,1fr)}',
	'.lanspeed-details-body{max-width:100%;overflow-x:hidden}',
	'.lanspeed-clients-card .lanspeed-body,',
	'.lanspeed-theme-aurora .lanspeed-clients-card .lanspeed-body,',
	'.lanspeed-theme-argon .lanspeed-clients-card .lanspeed-body,',
	'.lanspeed-theme-bootstrap .lanspeed-clients-card .lanspeed-body,',
	'.lanspeed-theme-shadcn .lanspeed-clients-card .lanspeed-body{overflow-x:hidden}',

	/* Interface rows: name across, four labelled values in a 2x2 grid. */
	'.lanspeed-ifaces-table,.lanspeed-ifaces-table tbody{display:block;width:100%;min-width:0}',
	'.lanspeed-ifaces-table thead{display:none}',
	'.lanspeed-ifaces-table tbody>tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));',
	'  gap:.5em .8em;padding:.7em 0;border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-ifaces-table tbody>tr:last-child{border-bottom:0}',
	'.lanspeed-ifaces-table tbody td{display:block;min-width:0;padding:0!important;',
	'  border:0!important;text-align:left;white-space:normal;overflow-wrap:anywhere}',
	'.lanspeed-ifaces-table tbody td:first-child{grid-column:1/-1}',
	'.lanspeed-ifaces-table tbody td[data-label]::before{content:attr(data-label);display:block;',
	'  margin:0 0 .15em;font-size:.72em;font-family:inherit;font-weight:600;',
	'  line-height:1.2;color:var(--lanspeed-text-muted)}',
	'.lanspeed-ifaces-table tbody td:first-child::before{display:none}',
	'.lanspeed-control-form{grid-template-columns:minmax(0,1fr)}}',

	'@media (max-width:480px){.lanspeed-details>summary{display:grid;',
	'  grid-template-columns:1em max-content minmax(0,1fr);column-gap:.6em;row-gap:.25em}',
	'.lanspeed-details>summary::before{grid-column:1;grid-row:1}',
	'.lanspeed-details>summary>h3{grid-column:2;grid-row:1}',
	'.lanspeed-details>summary>.spacer{display:none}',
	'.lanspeed-details>summary .sum{grid-column:3;grid-row:1;min-width:0;',
	'  text-align:right;white-space:normal;overflow-wrap:anywhere}',
	'.lanspeed-root .lanspeed-metric .big{font-size:1.3em}',
	'.lanspeed-clients-card .lanspeed-client-control{grid-column:1/-1}',
	'.lanspeed-clients-card .lanspeed-control-button{flex:1 1 0}',
	'.lanspeed-pagination{display:grid;grid-template-columns:minmax(0,1fr);justify-items:stretch}',
	'.lanspeed-page-size-control{justify-content:space-between}',
	'.lanspeed-page-actions{justify-content:space-between}',
	'.lanspeed-page-summary{flex:1 1 auto}}'
].join('\n');

return baseclass.extend({
	CSS: RESPONSIVE_CSS
});
