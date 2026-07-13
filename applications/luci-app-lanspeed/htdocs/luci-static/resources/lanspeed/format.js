'use strict';
'require baseclass';

/*
 * LAN Speed format/helper module.
 *
 * Pure functions: formatting, sorting, filtering, light DOM helpers, and
 * preferences (localStorage).  No RPC, no module-level mutable state.
 *
 * Active-client defaults are re-exported so older daemons keep the same
 * behavior when they do not publish the UCI-backed active threshold fields.
 */

var PREF_KEY                  = 'luci-app-lanspeed.prefs.v4';
var MIN_REFRESH_MS            = 1000;
var ACTIVE_CLIENT_WINDOW_MS   = 10000;
var ACTIVE_CLIENT_MIN_BPS     = 1;
var DELTA_SIGNIFICANT_RATIO   = 0.10;
var DELTA_SIGNIFICANT_MIN_BPS = 20000;

var REFRESH_CHOICES = [
	{ value:  1000, label: '1s'  },
	{ value:  2000, label: '2s'  },
	{ value:  3000, label: '3s'  },
	{ value:  5000, label: '5s'  },
	{ value: 10000, label: '10s' }
];

var SORT_KEYS = [ 'hostname', 'mac', 'tx', 'rx', 'tcp_conns', 'udp_conns' ];

var DEFAULT_PREFS = {
	refreshMs: 3000,
	unit: 'bit',
	activeOnly: false,
	sortKey: 'rx',
	sortDir: 'desc',
	sortCustom: false,
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

function defaultSortDirection() {
	return 'desc';
}

function nextSort(prefs, sortKey) {
	if (!prefs.sortCustom || prefs.sortKey !== sortKey)
		return { sortKey: sortKey, sortDir: 'desc', sortCustom: true };
	if (prefs.sortDir === 'desc')
		return { sortKey: sortKey, sortDir: 'asc', sortCustom: true };
	return {
		sortKey: DEFAULT_PREFS.sortKey,
		sortDir: DEFAULT_PREFS.sortDir,
		sortCustom: false
	};
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

function clientSampleMs(c) {
	var v = Number(c && c.sample_ms) || 0;
	return v > 0 ? v : 0;
}

function latestClientSampleMs(clients) {
	var latest = 0;
	asArray(clients).forEach(function(c) {
		var sample = clientSampleMs(c);
		if (sample > latest) latest = sample;
	});
	return latest;
}

function positiveNumber(v, fallback) {
	var n = Number(v);
	return n > 0 ? n : fallback;
}

function activeConfig(status, overview) {
	return {
		activeWindowMs: positiveNumber(
			status && status.active_client_window_ms,
			positiveNumber(overview && overview.active_client_window_ms,
				ACTIVE_CLIENT_WINDOW_MS)),
		activeMinBps: positiveNumber(
			status && status.active_client_min_bps,
			positiveNumber(overview && overview.active_client_min_bps,
				ACTIVE_CLIENT_MIN_BPS))
	};
}

function isActiveClient(c, nowMs, config) {
	var sample = Number(nowMs) || clientSampleMs(c);
	var last = Number(c && c.last_seen) || 0;
	var rate = (Number(c && c.tx_bps) || 0) + (Number(c && c.rx_bps) || 0);
	var cfg = config || activeConfig();
	var windowMs = positiveNumber(cfg.activeWindowMs, ACTIVE_CLIENT_WINDOW_MS);
	var minBps = positiveNumber(cfg.activeMinBps, ACTIVE_CLIENT_MIN_BPS);
	if (rate < minBps)
		return false;
	if (sample <= 0 || last <= 0 || last > sample)
		return false;
	return sample - last <= windowMs;
}

function sumTotals(clients, config) {
	var tx = 0, rx = 0, active = 0;
	var latestSample = latestClientSampleMs(clients);
	clients.forEach(function(c) {
		var t = Number(c.tx_bps) || 0, r = Number(c.rx_bps) || 0;
		tx += t; rx += r;
		if (isActiveClient(c, latestSample, config)) active++;
	});
	return { tx: tx, rx: rx, active: active };
}

function sortClients(clients, sortKey, sortDir, nowMs, config) {
	var sorted = clients.slice();
	var latestSample = Number(nowMs) || latestClientSampleMs(sorted);
	var direction = sortDir === 'asc' || sortDir === 'desc'
		? sortDir
		: defaultSortDirection(sortKey);
	sorted.sort(function(a, b) {
		var aActive = isActiveClient(a, latestSample, config);
		var bActive = isActiveClient(b, latestSample, config);
		var r, av, bv;
		if (aActive !== bActive)
			return aActive ? -1 : 1;
		if (sortKey === 'hostname')       r = compareText(clientDisplayName(a), clientDisplayName(b));
		else if (sortKey === 'mac')       r = compareText(a.mac, b.mac);
		else if (sortKey === 'tx')        r = (Number(a.tx_bps) || 0) - (Number(b.tx_bps) || 0);
		else if (sortKey === 'rx')        r = (Number(a.rx_bps) || 0) - (Number(b.rx_bps) || 0);
		else if (sortKey === 'tcp_conns' || sortKey === 'udp_conns') {
			av = typeof a[sortKey] === 'number' ? a[sortKey] : null;
			bv = typeof b[sortKey] === 'number' ? b[sortKey] : null;
			if (av === null || bv === null) {
				if (av === null && bv !== null) return 1;
				if (av !== null && bv === null) return -1;
				r = 0;
			} else {
				r = av - bv;
			}
		} else                            r = ((Number(a.tx_bps) || 0) + (Number(a.rx_bps) || 0)) -
		                                      ((Number(b.tx_bps) || 0) + (Number(b.rx_bps) || 0));
		if (r) return direction === 'desc' ? -r : r;
		return compareText(identityOf(a), identityOf(b));
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
		var stored = JSON.parse(raw);
		var prefs = Object.assign({}, DEFAULT_PREFS, stored);
		if (SORT_KEYS.indexOf(prefs.sortKey) === -1)
			prefs.sortKey = DEFAULT_PREFS.sortKey;
		if (stored.sortDir !== 'asc' && stored.sortDir !== 'desc')
			prefs.sortDir = defaultSortDirection(prefs.sortKey);
		if (typeof stored.sortCustom !== 'boolean')
			prefs.sortCustom = prefs.sortKey !== DEFAULT_PREFS.sortKey ||
				prefs.sortDir !== DEFAULT_PREFS.sortDir;
		if (!prefs.sortCustom) {
			prefs.sortKey = DEFAULT_PREFS.sortKey;
			prefs.sortDir = DEFAULT_PREFS.sortDir;
		}
		return prefs;
	} catch (e) { return Object.assign({}, DEFAULT_PREFS); }
}

function savePrefs(p) {
	try { window.localStorage.setItem(PREF_KEY, JSON.stringify(p)); } catch (e) {}
}

return baseclass.extend({
	PREF_KEY:                  PREF_KEY,
	MIN_REFRESH_MS:            MIN_REFRESH_MS,
	ACTIVE_CLIENT_WINDOW_MS:   ACTIVE_CLIENT_WINDOW_MS,
	ACTIVE_CLIENT_MIN_BPS:     ACTIVE_CLIENT_MIN_BPS,
	DELTA_SIGNIFICANT_RATIO:   DELTA_SIGNIFICANT_RATIO,
	DELTA_SIGNIFICANT_MIN_BPS: DELTA_SIGNIFICANT_MIN_BPS,
	REFRESH_CHOICES:           REFRESH_CHOICES,
	SORT_KEYS:                 SORT_KEYS,
	DEFAULT_PREFS:             DEFAULT_PREFS,

	asArray:           asArray,
	textOrDash:        textOrDash,
	identityOf:        identityOf,
	clientDisplayName: clientDisplayName,
	compareText:       compareText,
	defaultSortDirection: defaultSortDirection,
	nextSort:          nextSort,
	formatRate:        formatRate,
	clientSampleMs:    clientSampleMs,
	latestClientSampleMs: latestClientSampleMs,
	activeConfig:      activeConfig,
	isActiveClient:    isActiveClient,
	sumTotals:         sumTotals,
	sortClients:       sortClients,
	matchesFilter:     matchesFilter,
	replaceChildren:   replaceChildren,
	opt:               opt,
	loadPrefs:         loadPrefs,
	savePrefs:         savePrefs
});
