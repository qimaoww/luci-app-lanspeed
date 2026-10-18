'use strict';
'require baseclass';

/*
 * Structural styles for the realtime status page.
 *
 * Everything that defines the page skeleton lives in this leaf: spacing, type
 * scale, table tracks, row rhythm and the responsive cards. Theme leaves only
 * tune density and a handful of surface details, so all four themes share one
 * layout and one accessibility contract.
 *
 * Page order: page head, core stats, the client list as the main surface, then
 * the collapsible interface throughput evidence.
 */
var MONO = 'var(--font-mono,var(--font-monospace,ui-monospace,monospace))';

var BASE_CSS = [
	'.lanspeed-client-direction-label{position:absolute;width:1px;height:1px;padding:0;margin:-1px;',
		'overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}',

	/* ---------- Page skeleton ---------- */
	'.lanspeed-root{display:flex;flex-direction:column;gap:var(--lanspeed-page-gap);margin:0;min-width:0}',
	'.lanspeed-root .cbi-section{font-weight:400}',
	'.lanspeed-root>.cbi-section{padding:0;min-width:0}',
	'.lanspeed-root :is(button,select,input,a):focus-visible{outline:2px solid var(--lanspeed-focus-color);',
		'outline-offset:2px}',

	/* ---------- Page head ---------- */
	/* Section heads deliberately match the config and diagnostics pages: the
	 * three pages must keep one header rhythm across every theme. */
	'.lanspeed-root .lanspeed-header{display:flex;flex-wrap:wrap;align-items:center;gap:.4em 1em;',
		'margin:0;padding:var(--lanspeed-section-y) var(--lanspeed-section-x) .78em;',
		'border-bottom:1px solid var(--lanspeed-border);min-width:0;',
		'min-height:calc(var(--lanspeed-control-height) + .78em + 4px)}',
	'.lanspeed-root .lanspeed-header h3{display:inline;flex:0 0 auto;width:auto;margin:0;padding:0;',
		'border:0;background:transparent;box-shadow:none;color:var(--lanspeed-text);font-weight:600;',
		'letter-spacing:0;line-height:1.25}',
	'.lanspeed-root .lanspeed-header>.lanspeed-spacer{flex:1 1 auto}',
	'.lanspeed-spacer{flex:1 1 auto}',
	'.lanspeed-status-title{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;min-width:0}',
	'.lanspeed-status-actions{display:flex;flex-wrap:wrap;align-items:center;gap:8px}',
	'.lanspeed-control-label{font-size:12px;color:var(--lanspeed-text-muted);white-space:nowrap}',
	'.lanspeed-refresh-control{display:inline-flex;align-items:center;gap:6px}',
	'.lanspeed-refresh-select{width:6em}',
	'.lanspeed-status-actions .cbi-button{height:var(--lanspeed-control-height);padding:0 14px;',
		'font-size:13px;line-height:1}',
	/* Keep the only filled control off the page: nothing competes with the
	 * readings for the first glance. */
	'.lanspeed-root .lanspeed-status-actions .lanspeed-status-refresh{background:none!important;',
		'box-shadow:none!important;border:1px solid var(--lanspeed-border-strong)!important;',
		'color:var(--lanspeed-text)!important}',
	'.lanspeed-root .lanspeed-status-actions .lanspeed-status-refresh:hover{',
		'background:var(--lanspeed-surface-muted)!important}',
	'.lanspeed-collector-status{font-size:11px;font-weight:500;letter-spacing:.02em;',
		'padding:1px 6px;border-radius:4px}',
	'.lanspeed-status-version{font-size:12px;color:var(--lanspeed-text-subtle);',
		'font-variant-numeric:tabular-nums}',

	/* Live badge: one dot carries the collection state, the text stays quiet. */
	'.lanspeed-live-state{display:inline-flex;align-items:center;gap:6px;font-size:12px;',
		'color:var(--lanspeed-text-muted);white-space:nowrap}',
	'.lanspeed-live-state::before{content:"";flex:0 0 auto;width:6px;height:6px;border-radius:50%;',
		'background:var(--lanspeed-text-subtle)}',
	'.lanspeed-live-state[data-state="live"]{color:var(--lanspeed-normal-text,var(--lanspeed-normal))}',
	'.lanspeed-live-state[data-state="live"]::before{background:var(--lanspeed-normal)}',
	'.lanspeed-live-state[data-state="warning"]{color:var(--lanspeed-warning)}',
	'.lanspeed-live-state[data-state="warning"]::before{background:var(--lanspeed-warning)}',
	'.lanspeed-live-state[data-state="bad"]{color:var(--lanspeed-danger)}',
	'.lanspeed-live-state[data-state="bad"]::before{background:var(--lanspeed-danger)}',
	'.lanspeed-live-state[data-state="paused"]::before{background:var(--lanspeed-text-muted)}',
	'.lanspeed-live-state[data-state="loading"]::before{animation:lanspeed-pulse 1.4s ease-in-out infinite}',
	'@keyframes lanspeed-pulse{0%,100%{opacity:.35}50%{opacity:1}}',
	'@media (prefers-reduced-motion:reduce){',
	'.lanspeed-live-state[data-state="loading"]::before{animation:none}}',

	/* ---------- Core stats ---------- */
	/* One compact strip: four readings on a single baseline, separated by
	 * hairlines, sized so the numbers stay comparable at a glance. */
	'.lanspeed-body{padding:var(--lanspeed-section-y) var(--lanspeed-section-x)}',
	'.lanspeed-stats-card>.lanspeed-body{padding:0}',
	'.lanspeed-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0}',
	'.lanspeed-metric{display:flex;flex-direction:column;justify-content:center;min-width:0;',
		'padding:12px 16px;border-left:1px solid var(--lanspeed-border)}',
	'.lanspeed-metric:first-child{padding-left:var(--lanspeed-section-x);border-left:0}',
	'.lanspeed-metric-caption{display:flex;align-items:center;gap:5px;font-size:11.5px;',
		'font-weight:500;color:var(--lanspeed-text-muted);white-space:nowrap}',
	'.lanspeed-direction-mark{font-size:11px;font-weight:600;color:var(--lanspeed-accent)}',
	'.lanspeed-stat-value{font-size:20px;font-weight:600;line-height:1.25;letter-spacing:-.01em;',
		'font-variant-numeric:tabular-nums;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
	'.lanspeed-stat-hint{margin-top:1px;font-size:11px;color:var(--lanspeed-text-subtle);',
		'white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
	'.lanspeed-connection-values{display:flex;align-items:baseline;gap:12px;font-size:20px;',
		'line-height:1.25;min-height:1.25em;align-self:start}',
	'.lanspeed-connection-stat{display:inline-flex;align-items:baseline;gap:4px}',
	'.lanspeed-connection-label{font-size:11px;font-weight:500;color:var(--lanspeed-text-muted)}',
	'.lanspeed-connection-number{font-size:16px;font-weight:600;font-variant-numeric:tabular-nums;',
		'line-height:1.2;min-width:3.2ch;text-align:right}',

	/* ---------- Partial failure notice ---------- */
	'.lanspeed-status-error{display:grid;gap:4px;margin:12px var(--lanspeed-section-x);padding:10px 12px;',
		'border:1px solid var(--lanspeed-warning-border);border-radius:var(--lanspeed-radius-control);',
		'background:var(--lanspeed-warning-soft)}',
	'.lanspeed-status-error-title{font-size:12px;font-weight:600;color:var(--lanspeed-warning)}',
	'.lanspeed-status-error-summary{margin:0;font-size:12px;color:var(--lanspeed-text-muted)}',
	'.lanspeed-status-error-list{margin:0;padding-left:16px;font-size:12px;',
		'color:var(--lanspeed-text-muted)}',

	/* ---------- Client card: head, toolbar, table, footer ---------- */

	'.lanspeed-clients-summary{font-size:12px;color:var(--lanspeed-text-muted);',
		'font-variant-numeric:tabular-nums;white-space:nowrap}',
	'.lanspeed-clients-card>.lanspeed-body{padding:0}',
	'.lanspeed-toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:8px;',
		'padding:10px var(--lanspeed-section-x);border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-toolbar-left{display:flex;flex:1 1 20rem;align-items:center;gap:10px;min-width:0}',
	'.lanspeed-toolbar-filter{display:flex;flex:1 1 auto;min-width:11rem;max-width:18rem}',
	'.lanspeed-toolbar-left input[type="search"]{flex:1 1 auto;width:100%;min-width:0;max-width:none}',
	'.lanspeed-toolbar :is(select,input[type="search"]){min-width:0}',
	'.lanspeed-toolbar-right{display:flex;flex-wrap:wrap;align-items:center;gap:18px}',
	'.lanspeed-toolbar :is(select,input[type="search"]){height:var(--lanspeed-control-height)}',
	'.lanspeed-active-only{display:inline-flex;align-items:center;gap:6px;font-size:12px;',
		'color:var(--lanspeed-text-muted);white-space:nowrap}',
	'.lanspeed-active-only input[type="checkbox"]{width:14px;height:14px;margin:0}',
	'.lanspeed-sort-control,.lanspeed-unit-control,.lanspeed-refresh-control{',
		'display:inline-flex;align-items:center;gap:6px}',
	'.lanspeed-sort-select{width:11rem!important;flex:0 0 auto}',
	'.lanspeed-unit-select,.lanspeed-refresh-select{width:5.5rem!important;flex:0 0 auto}',
	'.lanspeed-refresh-select{width:6rem!important}',

	/* Fixed readings, flexible identity: numbers keep one tight track each so
	 * they never drift, while the name column absorbs whatever space is left. */
	'.lanspeed-table-scroll{overflow-x:auto;overscroll-behavior-x:contain}',
	'.lanspeed-table{width:100%;border-collapse:collapse;font-size:13px;line-height:1.4}',
	'.lanspeed-table :is(th,td){padding:7px 12px;text-align:left;vertical-align:middle;',
		'border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-table thead th{background:transparent;padding-top:11px;padding-bottom:11px;',
		'font-size:12px;font-weight:600;color:var(--lanspeed-text-subtle);letter-spacing:.02em;',
		'white-space:nowrap;border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-table tbody tr:last-child td{border-bottom:0}',
	'.lanspeed-table .num{text-align:right;font-variant-numeric:tabular-nums}',
	'.lanspeed-clients-table{table-layout:fixed;min-width:54rem}',
	'.lanspeed-clients-table [data-column-key="hostname"]{width:auto;min-width:13rem}',
	'.lanspeed-clients-table [data-column-key="mac"]{width:17rem}',
	'.lanspeed-clients-table [data-column-key="rate"]{width:9rem}',
	'.lanspeed-clients-table [data-column-key="totals"]{width:7rem}',
	'.lanspeed-clients-table [data-column-key="tcp_conns"],',
	'.lanspeed-clients-table [data-column-key="udp_conns"]{width:4rem;text-align:right}',
	'.lanspeed-clients-table [data-column-key="control"]{width:9rem;text-align:right}',
	'.lanspeed-clients-table thead th{position:relative}',
	'.lanspeed-clients-table thead th[aria-sort="ascending"]::after,',
	'.lanspeed-clients-table thead th[aria-sort="descending"]::after{content:"";position:absolute;',
		'right:2px;top:50%;margin-top:-3px;border:4px solid transparent}',
	'.lanspeed-clients-table thead th[aria-sort="ascending"]::after{border-bottom-color:currentColor;',
		'margin-top:-6px}',
	'.lanspeed-clients-table thead th[aria-sort="descending"]::after{border-top-color:currentColor}',

	/* Client cells: one primary line over one quiet line, numbers flush right. */
	'.lanspeed-client-name{min-width:0}',
	'.lanspeed-connection-link{display:block;font-weight:500;color:var(--lanspeed-text);',
		'text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
	'.lanspeed-connection-link:hover{text-decoration:underline}',
	'.lanspeed-client-name .ipline{display:block;margin-top:1px;font-family:' + MONO + ';',
		'font-size:11px;line-height:1.35;color:var(--lanspeed-text-subtle);overflow:hidden;',
		'text-overflow:ellipsis;white-space:nowrap}',
	'.lanspeed-client-mac{min-width:0}',
	'.lanspeed-client-mac-value{display:block;font-family:' + MONO + ';font-size:11.5px;',
		'line-height:1.5;color:var(--lanspeed-text-muted);overflow:hidden;text-overflow:ellipsis;',
		'white-space:nowrap}',
	'.lanspeed-client-vendor{display:flex;align-items:center;gap:6px;margin-top:2px;',
		'font-size:11px;line-height:1.35;color:var(--lanspeed-text-subtle);min-width:0}',
	'.lanspeed-client-vendor-name{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
	/* Square mark in front of an organisation name: brand glyph, letter fallback.
	 * The chip tints itself from the brand colour and mixes it back towards the
	 * theme text colour so the glyph stays legible in both light and dark UIs. */
	'.lanspeed-vendor-logo{display:inline-flex;flex:0 0 auto;align-items:center;justify-content:center;',
		'width:18px;height:18px;border-radius:5px;overflow:hidden;',
		'background:color-mix(in srgb,var(--vendor-brand,var(--lanspeed-text-subtle)) 14%,transparent);',
		'box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--vendor-brand,var(--lanspeed-text-subtle)) 24%,transparent);',
		'color:color-mix(in srgb,var(--vendor-brand,var(--lanspeed-text-subtle)) 68%,var(--lanspeed-text))}',
	'.lanspeed-vendor-logo svg{display:block;width:13px;height:13px;fill:currentColor}',
	/* Near-black marks have no tint of their own; they follow the theme text. */
	'.lanspeed-vendor-logo[data-vendor-tone="mono"]{background:var(--lanspeed-surface-muted);',
		'color:var(--lanspeed-text);box-shadow:inset 0 0 0 1px var(--lanspeed-border)}',
	'.lanspeed-vendor-logo[data-vendor-tone="ink"]{color:color-mix(in srgb,',
		'var(--vendor-brand,var(--lanspeed-text-subtle)) 46%,var(--lanspeed-text))}',
	'.lanspeed-vendor-logo--text{font-size:10px;font-weight:700;line-height:1;letter-spacing:0}',
	'.lanspeed-client-vendor[data-vendor-state="local"],',
	'.lanspeed-client-vendor[data-vendor-state="unknown"],',
	'.lanspeed-client-vendor[data-vendor-state="loading"],',
	'.lanspeed-client-vendor[data-vendor-state="unavailable"]{font-style:italic}',
	'.lanspeed-client-vendor[data-vendor-stale="true"]{color:var(--lanspeed-warning)}',
	'.lanspeed-client-traffic-stack{display:grid;gap:1px}',
	'.lanspeed-value-unit{font-size:.82em;font-weight:400;margin-left:.18em;',
		'color:var(--lanspeed-text-muted);letter-spacing:0}',
	'.lanspeed-client-traffic-line{display:grid;grid-template-columns:9px minmax(0,1fr);',
		'align-items:baseline;gap:5px;min-width:0;line-height:1.5;font-variant-numeric:tabular-nums}',
	'.lanspeed-client-direction{font-size:10px;line-height:1.5;text-align:center;',
		'color:var(--lanspeed-text-subtle)}',
	'.lanspeed-client-rate{text-align:right;font-weight:500;white-space:nowrap;',
		'overflow:hidden;text-overflow:ellipsis}',
	'.lanspeed-client-total{text-align:right;font-size:12px;color:var(--lanspeed-text-muted);',
		'white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
	'.lanspeed-client-traffic-line[data-direction="tx"] :is(.lanspeed-client-rate,.lanspeed-client-total){',
		'color:var(--lanspeed-text-subtle)}',
	'.lanspeed-client-count-cell{text-align:right;font-variant-numeric:tabular-nums;',
		'font-weight:500;color:var(--lanspeed-text-muted);padding-left:10px}',
	'.lanspeed-clients-table tbody tr.idle .lanspeed-client-count-cell{font-weight:400;',
		'color:var(--lanspeed-text-subtle)}',
	'.lanspeed-client-control{text-align:right;padding-left:20px}',
	'.lanspeed-control-actions{display:flex;flex-wrap:nowrap;justify-content:flex-end;gap:12px}',
	/* Actions stay quiet until the row is in focus: no colour noise per row. */
	'.lanspeed-root .lanspeed-control-actions .lanspeed-control-button{height:auto;min-height:0;',
		'padding:0;font-size:12px;font-weight:500;line-height:1.7;white-space:nowrap;',
		'background-color:transparent!important;background-image:none!important;',
		'border:0!important;box-shadow:none!important;color:var(--lanspeed-text-subtle)}',
	'.lanspeed-root .lanspeed-control-actions .lanspeed-control-button.cbi-button-negative,',
	'.lanspeed-root .lanspeed-control-actions .lanspeed-control-button.cbi-button-positive{',
		'color:var(--lanspeed-text-subtle)}',
	'.lanspeed-root .lanspeed-control-actions .lanspeed-control-button:hover,',
	'.lanspeed-root .lanspeed-control-actions .lanspeed-control-button:focus-visible{',
		'background:none!important;color:var(--lanspeed-accent);text-decoration:underline}',
	'.lanspeed-root .lanspeed-control-actions .lanspeed-control-button.cbi-button-negative:hover,',
	'.lanspeed-root .lanspeed-control-actions .lanspeed-control-button.cbi-button-negative:focus-visible{',
		'color:var(--lanspeed-danger)}',
	'.lanspeed-root .lanspeed-control-actions .lanspeed-control-button.cbi-button-positive:hover,',
	'.lanspeed-root .lanspeed-control-actions .lanspeed-control-button.cbi-button-positive:focus-visible{',
		'color:var(--lanspeed-normal-text,var(--lanspeed-normal))}',
	'.lanspeed-root .lanspeed-control-actions .lanspeed-control-button[disabled]{',
		'opacity:var(--lanspeed-disabled-opacity);text-decoration:none}',
	'.lanspeed-clients-table tr.idle :is(.lanspeed-connection-link,.lanspeed-client-mac-value){',
		'color:var(--lanspeed-text-muted)}',

	/* ---------- Pagination ---------- */
	'.lanspeed-pagination{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;',
		'gap:8px 16px;padding:10px 16px;border-top:1px solid var(--lanspeed-border)}',
	'.lanspeed-page-size-control{display:inline-flex;align-items:center;gap:6px}',
	'.lanspeed-page-size{width:4.5em;height:28px}',
	'.lanspeed-page-actions{display:flex;align-items:center;gap:2px}',
	'.lanspeed-page-button{width:28px;height:28px;padding:0;font-size:13px;line-height:1}',
	'.lanspeed-page-summary{min-width:9em;text-align:center;font-size:12px;',
		'color:var(--lanspeed-text-muted);font-variant-numeric:tabular-nums}',

	/* ---------- Empty state, hints and the collapsible evidence ---------- */
	'.lanspeed-empty{margin:var(--lanspeed-section-y) var(--lanspeed-section-x);padding:28px 16px;border:1px dashed var(--lanspeed-border);',
		'border-radius:var(--lanspeed-radius-control);text-align:center;font-size:13px;',
		'color:var(--lanspeed-text-muted)}',
	'.lanspeed-hint{margin:8px 0 0;font-size:12px;color:var(--lanspeed-text-muted)}',
	'.lanspeed-hint:empty{display:none}',
	'.lanspeed-ifaces-block{border-top:1px solid var(--lanspeed-border)}',
	'.lanspeed-details>summary h3{display:inline;margin:0;padding:0;border:0;background:none;',
		'font-size:13px;font-weight:600;color:var(--lanspeed-text);letter-spacing:0;line-height:1.25}',
	'.lanspeed-details>summary{display:flex;align-items:center;gap:10px;',
		'padding:10px var(--lanspeed-section-x);cursor:pointer;list-style:none}',
	'.lanspeed-details>summary::-webkit-details-marker{display:none}',
	'.lanspeed-details>summary::before{content:"▸";flex:0 0 auto;font-size:11px;',
		'color:var(--lanspeed-text-subtle)}',
	'.lanspeed-details[open]>summary::before{content:"▾"}',
	'.lanspeed-details[open]>summary{border-bottom:1px solid var(--lanspeed-border)}',
	'.lanspeed-details-body{padding:0 var(--lanspeed-section-x) var(--lanspeed-section-y)}',
	'.lanspeed-details-body .lanspeed-table :is(th,td):first-child{padding-left:0}',
	'.lanspeed-ifaces-summary{font-size:12px;color:var(--lanspeed-text-muted);',
		'font-variant-numeric:tabular-nums}',
	'.lanspeed-ifaces-table{margin-top:8px}',
	'.lanspeed-ifaces-table td:first-child{font-weight:500}',

	/* Narrow viewports that cannot run container queries still fold sensibly. */
	'@media (max-width:700px){',
	'.lanspeed-status-bar{flex-direction:column;align-items:stretch}',
	'.lanspeed-status-actions{justify-content:flex-start}',
	'.lanspeed-status-actions .cbi-button{flex:1 1 8em}',
	'.lanspeed-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}',
	'.lanspeed-metric{min-height:4.6rem;padding:10px 12px}',
	'.lanspeed-metric{padding-left:12px}',
	'.lanspeed-metric:nth-child(odd){padding-left:var(--lanspeed-section-x)}',
	'.lanspeed-metric:nth-child(even){border-left:1px solid var(--lanspeed-border)}',
	'.lanspeed-toolbar{padding:10px 12px}',
	'.lanspeed-toolbar-left{flex:1 1 100%}',
	'.lanspeed-toolbar-left input[type="search"]{max-width:none}',
	'.lanspeed-toolbar-right{flex:1 1 100%;justify-content:space-between}',
	'.lanspeed-sort-select{flex:1 1 auto;width:auto!important}',
	'.lanspeed-clients-header{padding:12px}',
	'.lanspeed-pagination{padding:10px 12px}',
	'.lanspeed-status-error{margin:12px}',
	'.lanspeed-empty{margin:12px}}',
].join('\n');

return baseclass.extend({
	CSS: BASE_CSS
});
