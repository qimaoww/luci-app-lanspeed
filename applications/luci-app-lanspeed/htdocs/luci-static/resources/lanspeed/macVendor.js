'use strict';
'require baseclass';
'require request';

/* Wireshark's generated manuf list carries the full IEEE registry (24, 28 and
 * 36 bit blocks) in one static file. Matching stays in the browser: neither a
 * device MAC nor its prefix is ever sent to the data source. */
var DATABASE_URL = 'https://www.wireshark.org/download/automated/data/manuf';
var CACHE_KEY = 'lanspeed.mac-vendors.v2';
var CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
var STALE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
var RETRY_MS = 60 * 1000;
var REQUEST_TIMEOUT_MS = 15000;
var PREFIX_LENGTHS = [ 36, 28, 24 ];
var database = null;
var pending = null;
var nextRetryAt = 0;
var cacheChecked = false;
var cacheFresh = false;

function normalizeMac(value) {
	var mac = String(value === null || value === undefined ? '' : value).trim();
	if (/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac) ||
	    /^(?:[0-9a-f]{2}-){5}[0-9a-f]{2}$/i.test(mac))
		return mac.replace(/[:-]/g, '').toLowerCase();
	if (/^[0-9a-f]{12}$/i.test(mac))
		return mac.toLowerCase();
	return '';
}

/* manuf lines are "OUI<TAB>short<TAB>long"; the OUI block is a dashed hex
 * prefix, optionally suffixed with "/28" or "/36" for sub-allocations. */
function parseManuf(text) {
	var entries = [];
	var lines = String(text === null || text === undefined ? '' : text).split('\n');
	for (var i = 0; i < lines.length; i++) {
		var line = lines[i];
		if (!line || line.charAt(0) === '#')
			continue;
		var columns = line.split('\t');
		if (columns.length < 3)
			continue;
		var raw = columns[0].trim();
		var vendor = (columns[2] || '').trim() || (columns[1] || '').trim();
		if (!raw || !vendor || vendor.length > 512)
			continue;
		var bits = 24;
		var hex = raw;
		var slash = raw.indexOf('/');
		if (slash !== -1) {
			bits = parseInt(raw.slice(slash + 1), 10);
			hex = raw.slice(0, slash);
		}
		if (PREFIX_LENGTHS.indexOf(bits) === -1)
			continue;
		hex = hex.replace(/[:-]/g, '').toLowerCase();
		if (!/^[0-9a-fx]+$/.test(hex))
			continue;
		hex = hex.replace(/x/g, '').slice(0, bits / 4);
		if (hex.length < bits / 4)
			continue;
		entries.push(hex, bits, vendor);
	}
	return entries;
}

function indexDatabase(entries) {
	if (!Array.isArray(entries) || !entries.length || entries.length % 3 ||
	    entries.length > 300000)
		throw new Error('Invalid OUI database');
	var index = { 24: Object.create(null), 28: Object.create(null), 36: Object.create(null) };
	for (var i = 0; i < entries.length; i += 3) {
		var prefix = entries[i], bits = entries[i + 1], vendor = entries[i + 2];
		if (typeof prefix !== 'string' || PREFIX_LENGTHS.indexOf(bits) === -1 ||
		    typeof vendor !== 'string' || !vendor.trim() || vendor.length > 512)
			throw new Error('Invalid OUI entry');
		prefix = prefix.toLowerCase().slice(0, bits / 4);
		if (prefix.length !== bits / 4 || !/^[0-9a-f]+$/.test(prefix))
			throw new Error('Invalid OUI prefix');
		index[bits][prefix] = vendor.trim();
	}
	return index;
}

function storage() {
	try { return window.localStorage; } catch (error) { return null; }
}

function readCache() {
	if (cacheChecked) return;
	cacheChecked = true;
	try {
		var cacheStorage = storage();
		var cached = cacheStorage && JSON.parse(cacheStorage.getItem(CACHE_KEY));
		var age = cached && Date.now() - cached.savedAt;
		if (!cached || !Number.isFinite(cached.savedAt) || age < 0 || age > STALE_TTL_MS)
			return;
		database = indexDatabase(cached.entries);
		cacheFresh = age <= CACHE_TTL_MS;
	} catch (error) { /* Corrupt or unavailable browser storage is optional. */ }
}

function load() {
	readCache();
	if (cacheFresh || Date.now() < nextRetryAt)
		return Promise.resolve();
	if (pending) return pending;
	pending = Promise.resolve().then(function() {
		return request.get(DATABASE_URL, { cache: true, timeout: REQUEST_TIMEOUT_MS });
	}).then(function(response) {
		if (!response || !response.ok)
			throw new Error('OUI database unavailable');
		return response.text();
	}).then(function(text) {
		var entries = parseManuf(text);
		database = indexDatabase(entries);
		cacheFresh = true;
		try {
			var cacheStorage = storage();
			if (cacheStorage)
				cacheStorage.setItem(CACHE_KEY, JSON.stringify({ savedAt: Date.now(), entries: entries }));
		} catch (error) { /* Quota errors must not discard the in-memory database. */ }
	}).catch(function() {
		nextRetryAt = Date.now() + RETRY_MS;
	}).then(function() { pending = null; });
	return pending;
}

/* True when a view should (re)start the shared download: no fresh database,
 * nothing in flight, and the failure backoff has elapsed. */
function needsLoad() {
	readCache();
	return !cacheFresh && !pending && Date.now() >= nextRetryAt;
}

function lookup(value) {
	var mac = normalizeMac(value);
	if (!mac || mac === '000000000000' || (parseInt(mac.slice(0, 2), 16) & 1))
		return { kind: 'invalid', vendor: '', label: _('未知厂商'),
			title: _('MAC 地址无效，无法查询 OUI') };
	if (parseInt(mac.slice(0, 2), 16) & 2)
		return { kind: 'local', vendor: '', label: _('随机 / 本地 MAC'),
			title: _('本地管理地址（常见于隐私随机 MAC），不对应 OUI 注册厂商') };
	if (database) {
		for (var i = 0; i < PREFIX_LENGTHS.length; i++) {
			var bits = PREFIX_LENGTHS[i];
			var vendor = database[bits][mac.slice(0, bits / 4)];
			if (vendor) return {
				kind: 'vendor', vendor: vendor, label: vendor, stale: !cacheFresh,
				title: _('OUI 注册厂商：') + vendor +
					(cacheFresh ? '' : ' · ' + _('缓存已过期，等待更新'))
			};
		}
		return { kind: 'unknown', vendor: '', label: _('未知厂商'), stale: !cacheFresh,
			title: _('OUI 数据库中没有该前缀') +
				(cacheFresh ? '' : ' · ' + _('缓存已过期，等待更新')) };
	}
	/* Before the first download settles the honest state is "loading", not
	 * "unavailable": the page has only just started the shared request. */
	return (pending || needsLoad())
		? { kind: 'loading', vendor: '', label: _('查询中…'), title: _('正在下载 OUI 数据库') }
		: { kind: 'unavailable', vendor: '', label: _('厂商查询不可用'),
			title: _('OUI 数据库下载失败，稍后自动重试') };
}

/* One per page: starts the shared download when needed, or joins one that
 * another page already started, and re-renders once it settles while the page
 * is still active. Callers invoke the returned function on every render; it
 * is a cheap no-op while a download is joined or not needed. */
function watch(isActive, rerender) {
	var waiting = false;
	return function ensure() {
		if (waiting || !(pending || needsLoad())) return;
		waiting = true;
		load().then(function() {
			waiting = false;
			if (isActive()) rerender();
		});
	};
}

return baseclass.extend({
	load: load,
	lookup: lookup,
	needsLoad: needsLoad,
	watch: watch
});
