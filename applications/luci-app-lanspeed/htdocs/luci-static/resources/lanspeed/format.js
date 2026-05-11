'use strict';
'require baseclass';

/*
 * LAN Speed format/helper module.
 *
 * Pure functions: formatting, sorting, filtering, light DOM helpers, and
 * preferences (localStorage).  No RPC, no module-level mutable state.
 *
 * INACTIVE_BPS_THRESHOLD is re-exported so clients that need the same
 * "active" boundary (refreshLive, coverage calculation) don't duplicate it.
 */

var PREF_KEY                  = 'luci-app-lanspeed.prefs.v3';
var MIN_REFRESH_MS            = 1000;
var INACTIVE_BPS_THRESHOLD    = 1024;
var DELTA_SIGNIFICANT_RATIO   = 0.10;
var DELTA_SIGNIFICANT_MIN_BPS = 20000;

var REFRESH_CHOICES = [
	{ value:  1000, label: '1s'  },
	{ value:  2000, label: '2s'  },
	{ value:  3000, label: '3s'  },
	{ value:  5000, label: '5s'  },
	{ value: 10000, label: '10s' }
];

var DEFAULT_PREFS = {
	refreshMs: 3000,
	unit: 'bit',
	activeOnly: false,
	sortKey: 'speed',
	paused: false,
	ifaceExcluded: []
};

function asArray(v) { return Array.isArray(v) ? v : []; }
function textOrDash(v) { return (v === null || v === undefined || v === '') ? '-' : String(v); }
function identityOf(c) { return c.identity_key || [c.mac, c.zone].filter(Boolean).join('@') || '-'; }
function clientDisplayName(c) { return c.hostname || c.mac || identityOf(c); }

function compareText(a, b) {
	return String(a || '').localeCompare(String(b || ''), undefined, { numeric: true, sensitivity: 'base' });
}

function formatRate(valueBps, unit) {
	var n = Number(valueBps) || 0, units, div;
	if (unit === 'byte') { n /= 8; units = ['B/s','KB/s','MB/s','GB/s','TB/s']; div = 1024; }
	else                 { units = ['bps','Kbps','Mbps','Gbps','Tbps']; div = 1000; }
	if (n < 1) return '0';
	var i = 0;
	while (n >= div && i < units.length - 1) { n /= div; i++; }
	return (i === 0 ? '%d %s' : '%.2f %s').format(n, units[i]);
}

function formatLastSeen(v) {
	var n = Number(v) || 0;
	if (n <= 0) return '-';
	if (n > 1e12) return new Date(n).toLocaleTimeString();
	if (n > 1e9)  return new Date(n * 1000).toLocaleTimeString();
	return _('%d 秒前').format(n);
}

function sumTotals(clients) {
	var tx = 0, rx = 0, active = 0;
	clients.forEach(function(c) {
		var t = Number(c.tx_bps) || 0, r = Number(c.rx_bps) || 0;
		tx += t; rx += r;
		if (t + r >= INACTIVE_BPS_THRESHOLD) active++;
	});
	return { tx: tx, rx: rx, active: active };
}

function sortClients(clients, sortKey) {
	var sorted = clients.slice();
	sorted.sort(function(a, b) {
		var r;
		if (sortKey === 'hostname')       r = compareText(clientDisplayName(a), clientDisplayName(b));
		else if (sortKey === 'mac')       r = compareText(a.mac, b.mac);
		else if (sortKey === 'tx')        r = (Number(b.tx_bps) || 0) - (Number(a.tx_bps) || 0);
		else if (sortKey === 'rx')        r = (Number(b.rx_bps) || 0) - (Number(a.rx_bps) || 0);
		else if (sortKey === 'tcp_conns') r = (Number(b.tcp_conns) || -1) - (Number(a.tcp_conns) || -1);
		else if (sortKey === 'udp_conns') r = (Number(b.udp_conns) || -1) - (Number(a.udp_conns) || -1);
		else if (sortKey === 'last_seen') r = (Number(b.last_seen) || 0) - (Number(a.last_seen) || 0);
		else                              r = ((Number(b.tx_bps) || 0) + (Number(b.rx_bps) || 0)) -
		                                      ((Number(a.tx_bps) || 0) + (Number(a.rx_bps) || 0));
		return r || compareText(identityOf(a), identityOf(b));
	});
	return sorted;
}

function matchesFilter(c, term) {
	if (!term) return true;
	var hay = [clientDisplayName(c), c.mac, c.zone, c.interface, asArray(c.ips).join(' ')]
		.filter(Boolean).join(' ').toLowerCase();
	return hay.indexOf(term.toLowerCase()) !== -1;
}

function replaceChildren(node, children) {
	while (node.firstChild) node.removeChild(node.firstChild);
	asArray(children).forEach(function(c) {
		if (c === null || c === undefined || c === '') return;
		node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
	});
}

/*
 * HTML `<option selected="false">` is still selected because the spec treats
 * the attribute as a boolean presence, not a truthy value. LuCI's E() helper
 * setAttribute's whatever you pass, so we must only emit `selected` when it
 * should actually be selected.
 */
function opt(value, label, isSelected) {
	var attrs = { 'value': String(value) };
	if (isSelected) attrs.selected = 'selected';
	return E('option', attrs, label);
}

function loadPrefs() {
	try {
		var raw = window.localStorage.getItem(PREF_KEY);
		if (!raw) return Object.assign({}, DEFAULT_PREFS);
		return Object.assign({}, DEFAULT_PREFS, JSON.parse(raw));
	} catch (e) { return Object.assign({}, DEFAULT_PREFS); }
}

function savePrefs(p) {
	try { window.localStorage.setItem(PREF_KEY, JSON.stringify(p)); } catch (e) {}
}

return baseclass.extend({
	PREF_KEY:                  PREF_KEY,
	MIN_REFRESH_MS:            MIN_REFRESH_MS,
	INACTIVE_BPS_THRESHOLD:    INACTIVE_BPS_THRESHOLD,
	DELTA_SIGNIFICANT_RATIO:   DELTA_SIGNIFICANT_RATIO,
	DELTA_SIGNIFICANT_MIN_BPS: DELTA_SIGNIFICANT_MIN_BPS,
	REFRESH_CHOICES:           REFRESH_CHOICES,
	DEFAULT_PREFS:             DEFAULT_PREFS,

	asArray:           asArray,
	textOrDash:        textOrDash,
	identityOf:        identityOf,
	clientDisplayName: clientDisplayName,
	compareText:       compareText,
	formatRate:        formatRate,
	formatLastSeen:    formatLastSeen,
	sumTotals:         sumTotals,
	sortClients:       sortClients,
	matchesFilter:     matchesFilter,
	replaceChildren:   replaceChildren,
	opt:               opt,
	loadPrefs:         loadPrefs,
	savePrefs:         savePrefs
});
