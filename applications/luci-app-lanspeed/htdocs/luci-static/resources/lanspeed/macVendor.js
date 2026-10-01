'use strict';
'require baseclass';
'require request';

/* Same complete OUI export used by luci-app-nlbwmon. Matching stays in the
 * browser: neither a device MAC nor its prefix is sent to the data source. */
var DATABASE_URL = 'https://raw.githubusercontent.com/jow-/oui-database/master/oui.json';
var CACHE_KEY = 'lanspeed.mac-vendors.v1';
var CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
var STALE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
var RETRY_MS = 60 * 1000;
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

function indexDatabase(entries) {
	if (!Array.isArray(entries) || !entries.length || entries.length % 3 ||
	    entries.length > 300000)
		throw new Error('Invalid OUI database');
	var index = { 24: Object.create(null), 28: Object.create(null), 36: Object.create(null) };
	for (var i = 0; i < entries.length; i += 3) {
		var prefix = entries[i], bits = entries[i + 1], vendor = entries[i + 2];
		if (typeof prefix !== 'string' || !/^[0-9a-f]{1,12}$/i.test(prefix) ||
		    PREFIX_LENGTHS.indexOf(bits) === -1 || typeof vendor !== 'string' ||
		    !vendor.trim() || vendor.length > 512)
			throw new Error('Invalid OUI entry');
		prefix = ('000000000000' + prefix.toLowerCase()).slice(-12);
		if (!/^0+$/.test(prefix.slice(bits / 4)))
			throw new Error('Unaligned OUI prefix');
		index[bits][prefix.slice(0, bits / 4)] = vendor.trim();
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
		return request.get(DATABASE_URL, { cache: true, timeout: 5000 });
	}).then(function(response) {
		if (!response || !response.ok)
			throw new Error('OUI database unavailable');
		return response.json();
	}).then(function(entries) {
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

function lookup(value) {
	var mac = normalizeMac(value);
	if (!mac || mac === '000000000000' || (parseInt(mac.slice(0, 2), 16) & 1))
		return { kind: 'invalid', vendor: '', label: _('未知厂商') };
	if (parseInt(mac.slice(0, 2), 16) & 2)
		return { kind: 'local', vendor: '', label: _('随机 / 本地 MAC') };
	if (database) {
		for (var i = 0; i < PREFIX_LENGTHS.length; i++) {
			var bits = PREFIX_LENGTHS[i];
			var vendor = database[bits][mac.slice(0, bits / 4)];
			if (vendor) return { kind: 'vendor', vendor: vendor, label: vendor };
		}
		return { kind: 'unknown', vendor: '', label: _('未知厂商') };
	}
	return { kind: pending ? 'loading' : 'unavailable', vendor: '',
		label: pending ? _('查询中…') : _('厂商查询不可用') };
}

return baseclass.extend({
	load: load,
	lookup: lookup
});
