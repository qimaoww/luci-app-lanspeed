'use strict';
'require baseclass';
'require request';
'require lanspeed.vendorNames as vendorNames';
'require lanspeed.vendorDatabase as vendorDatabase';
'require lanspeed.vendorSeed as vendorSeed';

/* Full static registries are shared across views and matched locally. Each
 * source ages/retries independently, so a failed supplement cannot erase data. */
var CACHE_KEY = 'lanspeed.mac-vendors.v3';
var LEGACY_CACHE_KEY = 'lanspeed.mac-vendors.v2';
var STALE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
var RETRY_MS = 60 * 1000;
var REQUEST_TIMEOUT_MS = 15000;
var PREFIX_LENGTHS = [ 36, 28, 24 ];
var pending = null;
var cacheChecked = false;
var states = vendorDatabase.sources.map(function(source) {
	return { source: source, entries: null, index: null, savedAt: null,
		nextRetryAt: 0, failedKind: 'load', url: '', busy: false };
});

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
		if (typeof prefix !== 'string' || PREFIX_LENGTHS.indexOf(bits) === -1 ||
		    typeof vendor !== 'string' || !vendor.trim() || vendor.length > 512)
			throw new Error('Invalid OUI entry');
		prefix = prefix.toLowerCase();
		if (prefix.length !== bits / 4 || !/^[0-9a-f]+$/.test(prefix))
			throw new Error('Invalid OUI prefix');
		index[bits][prefix] = vendor.trim();
	}
	return index;
}

function storage() {
	try { return window.localStorage; } catch (error) { return null; }
}

function ageOf(state) { return state.savedAt === null ? Infinity : Date.now() - state.savedAt; }
function fresh(state) { var age = ageOf(state); return !!state.index && age >= 0 && age <= state.source.ttl; }
function due(state) { return !fresh(state) && !state.busy && Date.now() >= state.nextRetryAt; }
function install(state, entries, timestamp, url) {
	var ambiguous = entries.ambiguous || {};
	Object.keys(ambiguous).forEach(function(prefix) {
		if (!/^(?:[0-9a-f]{6}|[0-9a-f]{7}|[0-9a-f]{9})$/.test(prefix) ||
		    !Array.isArray(ambiguous[prefix]) || ambiguous[prefix].length > 10 ||
		    ambiguous[prefix].some(function(name) { return typeof name !== 'string' || !name || name.length > 512; }))
			throw new Error('Invalid shared registry entry');
	});
	state.ambiguous = ambiguous;
	state.index = indexDatabase(entries); state.entries = entries;
	state.savedAt = timestamp; state.url = url;
}

function readCache() {
	if (!cacheChecked) {
		cacheChecked = true;
		try {
			var cacheStorage = storage();
			var cached = cacheStorage && JSON.parse(cacheStorage.getItem(CACHE_KEY));
			if (cached && Array.isArray(cached.names) && Array.isArray(cached.records) &&
			    cached.records.length <= 800000 && cached.records.length % 3 === 0) {
				var entries = states.map(function() { return []; });
				for (var i = 0; i < cached.records.length; i += 3) {
					var prefix = cached.records[i], name = cached.names[cached.records[i + 1]], codes = cached.records[i + 2];
					if (typeof prefix !== 'string' || [6, 7, 9].indexOf(prefix.length) === -1 ||
					    typeof name !== 'string' || typeof codes !== 'string') throw new Error('Invalid registry cache');
					states.forEach(function(state, n) {
						if (codes.indexOf(state.source.code) !== -1) entries[n].push(prefix, prefix.length * 4, name);
					});
				}
				states.forEach(function(state, n) {
					var meta = cached.sources && cached.sources[state.source.id];
					if (meta && Number.isFinite(meta.savedAt) && entries[n].length) {
						try { entries[n].ambiguous = meta.ambiguous; install(state, entries[n], meta.savedAt,
							state.source.urls.indexOf(meta.url) !== -1 ? meta.url : state.source.urls[0]); } catch (error) {}
					}
				});
			} else {
				var legacy = cacheStorage && JSON.parse(cacheStorage.getItem(LEGACY_CACHE_KEY));
				if (legacy && Number.isFinite(legacy.savedAt)) install(states[0], legacy.entries, legacy.savedAt, states[0].source.urls[0]);
			}
		} catch (error) { /* Corrupt or unavailable storage is optional. */ }
	}
	states.forEach(function(state) {
		var age = ageOf(state);
		if (age < 0 || age > STALE_TTL_MS) { state.index = null; state.entries = null; }
		if (state.nextRetryAt - Date.now() > RETRY_MS) state.nextRetryAt = 0;
	});
}

/* Share registrant strings and identical source records to fit browser quotas.
 * Provenance remains separate, including disagreements for the same prefix. */
function saveCache() {
	if (!states.some(function(state) { return !!state.index; })) return;
	try {
		var names = [], nameIds = Object.create(null), records = [], offsets = Object.create(null), sources = {};
		states.forEach(function(state) {
			if (!state.index) return;
			sources[state.source.id] = { savedAt: state.savedAt, url: state.url, ambiguous: state.ambiguous };
			for (var i = 0; i < state.entries.length; i += 3) {
				var prefix = state.entries[i], name = state.entries[i + 2];
				if (nameIds[name] === undefined) { nameIds[name] = names.length; names.push(name); }
				var key = prefix + ':' + nameIds[name], offset = offsets[key];
				if (offset === undefined) {
					offsets[key] = records.length; records.push(prefix, nameIds[name], state.source.code);
				} else records[offset + 2] += state.source.code;
			}
		});
		var cacheStorage = storage();
		if (cacheStorage) {
			// Free the former single-source entry before writing the merged cache.
			if (cacheStorage.removeItem) cacheStorage.removeItem(LEGACY_CACHE_KEY);
			cacheStorage.setItem(CACHE_KEY, JSON.stringify({ names: names, records: records, sources: sources }));
		}
	} catch (error) { /* Quota errors must not discard in-memory registries. */ }
}

function fetchSource(state, attempt) {
	var url = state.source.urls[attempt];
	return Promise.resolve().then(function() {
		return request.get(url, { cache: true, timeout: REQUEST_TIMEOUT_MS });
	}).then(function(response) {
		if (!response || !response.ok) throw new Error('Registry unavailable');
		return response.text();
	}).then(function(text) {
		state.failedKind = 'query';
		var entries = vendorDatabase.parse(text, state.source);
		install(state, entries, Date.now(), url); state.nextRetryAt = 0;
	}).catch(function(error) {
		if (attempt + 1 < state.source.urls.length) return fetchSource(state, attempt + 1);
		throw error;
	});
}

function load() {
	readCache();
	if (pending) return pending;
	var requested = states.filter(due);
	if (!requested.length) return Promise.resolve();
	requested.forEach(function(state) { state.busy = true; state.failedKind = 'load'; });
	pending = Promise.all(requested.map(function(state) {
		return fetchSource(state, 0).catch(function() {
			state.nextRetryAt = Date.now() + RETRY_MS;
		}).then(function() { state.busy = false; });
	})).then(function() { saveCache(); pending = null; });
	return pending;
}

function needsLoad() { readCache(); return states.some(due); }

function lookup(value) {
	readCache();
	var mac = normalizeMac(value);
	if (!mac || mac === '000000000000' || (parseInt(mac.slice(0, 2), 16) & 1))
		return { kind: 'invalid', vendor: '', label: _('未知厂商'), title: _('MAC无效，无法查询注册机构') };
	if (parseInt(mac.slice(0, 2), 16) & 2)
		return { kind: 'local', vendor: '', label: _('本地管理地址'), title: _('本地管理地址，不对应全球注册前缀；不能据此确认是随机地址') };
	for (var i = 0; i < PREFIX_LENGTHS.length; i++) {
		var bits = PREFIX_LENGTHS[i], selected = null;
		var shared = states.find(function(state) { return state.index &&
			state.ambiguous && state.ambiguous[mac.slice(0, bits / 4)]; });
		if (shared) return { kind: 'ambiguous', vendor: shared.ambiguous[mac.slice(0, bits / 4)].join(' / '),
			stale: !fresh(shared), label: _('注册机构存在多个记录'), title: _('该地址前缀有多个注册机构，无法确认厂商'),
			source: shared.source.label, sourceUrl: shared.url, prefixBits: bits };
		states.forEach(function(state) {
			if (!state.index || !state.index[bits][mac.slice(0, bits / 4)]) return;
			// Specificity first, then fresh data, then current IEEE CSV over manuf.
			if (!selected || fresh(state) && !fresh(selected) ||
			    fresh(state) === fresh(selected) && state.source.rank > selected.source.rank) selected = state;
		});
		if (selected) {
			var vendor = selected.index[bits][mac.slice(0, bits / 4)], translated = vendorNames.resolve(vendor);
			return { kind: 'vendor', vendor: vendor, label: translated ? translated.label : _('中文名称待补充'),
				stale: !fresh(selected), source: selected.source.label, sourceUrl: selected.url, prefixBits: bits,
				title: _('地址前缀注册机构：') + (translated ? translated.label : _('中文名称待补充')) +
					(fresh(selected) ? '' : ' · ' + _('缓存已过期，等待更新')) };
		}
		// A bundled narrow prefix still outranks a broader online allocation.
		// At the same prefix length any usable online record wins over the seed.
		var offline = vendorSeed.lookup(mac, bits);
		if (offline) {
			var mapped = vendorNames.resolve(offline);
			return { kind: 'vendor', vendor: offline, label: mapped ? mapped.label : _('中文名称待补充'),
				bundled: true, stale: false, prefixBits: bits, source: _('离线基础数据'),
				sourceRevision: vendorSeed.metadata.revision,
				title: _('地址前缀注册机构：') + (mapped ? mapped.label : _('中文名称待补充')) +
					' · ' + _('离线基础数据') + ' · ' +
					(states.some(function(state) { return state.busy || due(state); }) ?
						_('正在检查在线更新') : states.some(function(state) { return state.nextRetryAt > Date.now(); }) ?
						_('在线更新暂不可用') : _('该前缀仅在离线基础数据中收录')) };
		}
	}
	if (states.some(function(state) { return state.busy || due(state); }))
		return { kind: 'loading', vendor: '', label: _('厂商数据库加载中…'), title: _('正在加载本地匹配所需的厂商数据库') };
	if (states.some(function(state) { return !state.index; })) {
		var queryFailed = states.some(function(state) { return !state.index && state.failedKind === 'query'; });
		return { kind: 'unavailable', vendor: '', label: queryFailed ? _('厂商查询失败') : _('厂商数据库加载失败'),
			title: _('部分厂商数据库不可用，稍后自动重试') };
	}
	var stale = states.some(function(state) { return !fresh(state); });
	return { kind: 'unknown', vendor: '', label: _('未知厂商'), stale: stale,
		title: _('厂商数据库中没有该地址前缀') + (stale ? ' · ' + _('缓存已过期，等待更新') : '') };
}

function sourceStatus() {
	readCache();
	return states.map(function(state) { return { id: state.source.id, fresh: fresh(state),
		entries: state.entries ? state.entries.length / 3 : 0, busy: state.busy, url: state.url }; });
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
	sourceStatus: sourceStatus,
	lookup: lookup,
	needsLoad: needsLoad,
	watch: watch
});
