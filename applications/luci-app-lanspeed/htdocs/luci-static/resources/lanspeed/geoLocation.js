'use strict';
'require baseclass';

var CACHE_KEY = 'lanspeed.geo-location.v6';
var CACHE_VERSION = 6;
var LOOKUP_ENDPOINT = 'https://free.freeipapi.com/api/json/';
var SECONDARY_SOURCES = [
	{
		name: 'geolocation-db.com',
		url: function(ip) {
			return 'https://geolocation-db.com/json/' + encodeURIComponent(ip);
		}
	},
	{
		name: 'ipapi.co',
		url: function(ip) {
			return 'https://ipapi.co/' + encodeURIComponent(ip) + '/json/';
		}
	},
	{
		name: 'ipinfo.io',
		url: function(ip) {
			return 'https://ipinfo.io/' + encodeURIComponent(ip) + '/json';
		}
	},
	{
		name: 'DB-IP',
		url: function(ip) {
			return 'https://api.db-ip.com/v2/free/' + encodeURIComponent(ip);
		}
	},
	{
		name: 'ipwho.is',
		url: function(ip) {
			return 'https://ipwho.is/' + encodeURIComponent(ip);
		}
	}
];
var MAX_CACHE_ENTRIES = 4096;
var POSITIVE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
var NEGATIVE_TTL_MS = 30 * 1000;
var MAX_CONCURRENCY = 4;
var REQUEST_TIMEOUT_MS = 8000;

var CHINA_PROVINCES = {
	AH: '安徽', BJ: '北京', CQ: '重庆', FJ: '福建', GS: '甘肃', GD: '广东',
	GX: '广西', GZ: '贵州', HI: '海南', HE: '河北', HL: '黑龙江', HA: '河南',
	HB: '湖北', HN: '湖南', NM: '内蒙古', JS: '江苏', JX: '江西', JL: '吉林',
	LN: '辽宁', NX: '宁夏', QH: '青海', SN: '陕西', SD: '山东', SH: '上海',
	SX: '山西', SC: '四川', TJ: '天津', XJ: '新疆', XZ: '西藏', YN: '云南',
	ZJ: '浙江'
};

var CHINA_PROVINCE_NAMES = {
	anhui: '安徽', beijing: '北京', chongqing: '重庆', fujian: '福建',
	gansu: '甘肃', guangdong: '广东', guangxi: '广西', guizhou: '贵州',
	hainan: '海南', hebei: '河北', heilongjiang: '黑龙江', henan: '河南',
	hubei: '湖北', hunan: '湖南', 'inner mongolia': '内蒙古', 'nei mongol': '内蒙古',
	jiangsu: '江苏', jiangxi: '江西', jilin: '吉林', liaoning: '辽宁',
	ningxia: '宁夏', qinghai: '青海', shaanxi: '陕西', shandong: '山东',
	shanghai: '上海', shanxi: '山西', sichuan: '四川', tianjin: '天津',
	xinjiang: '新疆', tibet: '西藏', xizang: '西藏', yunnan: '云南', zhejiang: '浙江',
	'guangxi zhuangzu zizhiqu': '广西', 'ningxia huizu zizhiqu': '宁夏',
	'xinjiang uygur zizhiqu': '新疆', 'xinjiang weiwuer zizhiqu': '新疆',
	'xizang zizhiqu': '西藏'
};

function result(kind, label, queryable) {
	return {
		kind: kind,
		label: label,
		queryable: queryable === true
	};
}

function cleanIp(ip) {
	var value = String(ip === null || ip === undefined ? '' : ip).trim();
	var zone;
	if (value.charAt(0) === '[' && value.charAt(value.length - 1) === ']')
		value = value.slice(1, -1);
	zone = value.indexOf('%');
	if (zone !== -1)
		value = value.slice(0, zone);
	return value.toLowerCase();
}

function parseIpv4(ip) {
	var parts = String(ip || '').split('.');
	var bytes = [];
	var i, value;
	if (parts.length !== 4)
		return null;
	for (i = 0; i < parts.length; i++) {
		if (!/^(?:0|[1-9][0-9]{0,2})$/.test(parts[i]))
			return null;
		value = Number(parts[i]);
		if (!isFinite(value) || value < 0 || value > 255)
			return null;
		bytes.push(value);
	}
	return bytes;
}

function classifyIpv4(bytes) {
	var a = bytes[0], b = bytes[1], c = bytes[2];

	if (a === 10 || a === 127 ||
	    (a === 100 && b >= 64 && b <= 127) ||
	    (a === 169 && b === 254) ||
	    (a === 172 && b >= 16 && b <= 31) ||
	    (a === 192 && b === 168)) {
		return result('local', '本地/内网', false);
	}
	if (a === 198 && (b === 18 || b === 19))
		return result('fake', '代理 Fake-IP', false);
	if (a === 0 || a >= 224 ||
	    (a === 192 && b === 0 && c === 0) ||
	    (a === 192 && b === 0 && c === 2) ||
	    (a === 192 && b === 88 && c === 99) ||
	    (a === 198 && b === 51 && c === 100) ||
	    (a === 203 && b === 0 && c === 113)) {
		return result('reserved', '保留/未知', false);
	}
	return result('public', '查询中…', true);
}

function parseIpv6(ip) {
	var value = String(ip || '').toLowerCase();
	var dot = value.indexOf('.');
	var lastColon, ipv4, parts, head, tail, missing;
	var words = [];
	var i, word;

	if (!value || value.indexOf(':') === -1)
		return null;
	if (dot !== -1) {
		lastColon = value.lastIndexOf(':');
		if (lastColon === -1)
			return null;
		ipv4 = parseIpv4(value.slice(lastColon + 1));
		if (!ipv4)
			return null;
		value = value.slice(0, lastColon + 1) +
			((ipv4[0] << 8) | ipv4[1]).toString(16) + ':' +
			((ipv4[2] << 8) | ipv4[3]).toString(16);
	}

	parts = value.split('::');
	if (parts.length > 2)
		return null;
	head = parts[0] ? parts[0].split(':') : [];
	tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
	missing = 8 - head.length - tail.length;
	if ((parts.length === 1 && missing !== 0) ||
	    (parts.length === 2 && missing < 1))
		return null;

	for (i = 0; i < head.length; i++) {
		if (!/^[0-9a-f]{1,4}$/.test(head[i]))
			return null;
		word = parseInt(head[i], 16);
		words.push(word);
	}
	for (i = 0; i < missing; i++)
		words.push(0);
	for (i = 0; i < tail.length; i++) {
		if (!/^[0-9a-f]{1,4}$/.test(tail[i]))
			return null;
		word = parseInt(tail[i], 16);
		words.push(word);
	}
	return words.length === 8 ? words : null;
}

function allZero(words, end) {
	var i;
	for (i = 0; i < end; i++) {
		if (words[i] !== 0)
			return false;
	}
	return true;
}

function classifyIpv6(words) {
	var mapped;
	if (allZero(words, 7) && words[7] === 1)
		return result('local', '本地/内网', false);
	if (allZero(words, 8))
		return result('reserved', '保留/未知', false);
	if (allZero(words, 5) && words[5] === 0xffff) {
		mapped = [ words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255 ];
		return classifyIpv4(mapped);
	}
	if ((words[0] & 0xfe00) === 0xfc00 ||
	    (words[0] & 0xffc0) === 0xfe80) {
		return result('local', '本地/内网', false);
	}
	if ((words[0] & 0xff00) === 0xff00 ||
	    (words[0] & 0xffc0) === 0xfec0 ||
	    (words[0] === 0x2001 && words[1] === 0x0db8) ||
	    (words[0] === 0x2001 && words[1] === 0x0002) ||
	    (words[0] === 0x2001 && words[1] >= 0x0010 && words[1] <= 0x002f) ||
	    (words[0] === 0x3fff && (words[1] & 0xf000) === 0)) {
		return result('reserved', '保留/未知', false);
	}
	if (words[0] >= 0x2000 && words[0] <= 0x3fff)
		return result('public', '查询中…', true);
	return result('reserved', '保留/未知', false);
}

function classify(ip) {
	var value = cleanIp(ip);
	var ipv4 = parseIpv4(value);
	var ipv6;
	if (ipv4)
		return classifyIpv4(ipv4);
	ipv6 = parseIpv6(value);
	if (ipv6)
		return classifyIpv6(ipv6);
	return result('reserved', '保留/未知', false);
}

function lookupKey(ip) {
	var value = cleanIp(ip);
	var bytes = parseIpv4(value);
	if (bytes)
		return bytes[0] + '.' + bytes[1] + '.0.0/16';
	return value;
}

function safeStorage(options) {
	if (Object.prototype.hasOwnProperty.call(options, 'storage'))
		return options.storage;
	try {
		return typeof window !== 'undefined' ? window.localStorage : null;
	} catch (e) {
		return null;
	}
}

function readCache(storage, maxEntries, now) {
	var cache = Object.create(null);
	var raw, parsed, entries, keys, i, entry;
	if (!storage || typeof storage.getItem !== 'function')
		return cache;
	try {
		raw = storage.getItem(CACHE_KEY);
		if (!raw || raw.length > 2 * 1024 * 1024)
			return cache;
		parsed = JSON.parse(raw);
		entries = parsed && parsed.version === CACHE_VERSION && parsed.entries;
		if (!entries || typeof entries !== 'object' || Array.isArray(entries))
			return cache;
		keys = Object.keys(entries);
		for (i = 0; i < keys.length; i++) {
			entry = entries[keys[i]];
			if (!entry || (entry.status !== 'ok' && entry.status !== 'fail') ||
			    typeof entry.expiresAt !== 'number' || entry.expiresAt <= now)
				continue;
			if (entry.status === 'ok' &&
			    typeof entry.code !== 'string' && typeof entry.country !== 'string')
				continue;
			if ((entry.regionCode !== undefined && typeof entry.regionCode !== 'string') ||
			    (entry.region !== undefined && typeof entry.region !== 'string'))
				continue;
			cache[keys[i]] = entry;
		}
	} catch (e) {
		return Object.create(null);
	}
	trimCache(cache, maxEntries);
	return cache;
}

function trimCache(cache, maxEntries) {
	var keys = Object.keys(cache);
	var remove, i;
	if (keys.length <= maxEntries)
		return;
	keys.sort(function(left, right) {
		return (Number(cache[left].storedAt) || 0) -
			(Number(cache[right].storedAt) || 0);
	});
	remove = keys.length - maxEntries;
	for (i = 0; i < remove; i++)
		delete cache[keys[i]];
}

function createDisplayNames(options) {
	if (options.displayNames)
		return options.displayNames;
	try {
		if (typeof Intl !== 'undefined' && typeof Intl.DisplayNames === 'function')
			return new Intl.DisplayNames(options.locales, { type: 'region' });
	} catch (e) {}
	return null;
}

function chinaProvince(regionCode, region) {
	var code = String(regionCode || '').trim().toUpperCase();
	var name = String(region || '').trim().toLowerCase()
		.replace(/[_.-]+/g, ' ')
		.replace(/\s+/g, ' ');
	var chineseName;
	var keys, i;
	if (CHINA_PROVINCES[code])
		return CHINA_PROVINCES[code];
	if (!name)
		return '';
	keys = Object.keys(CHINA_PROVINCES);
	chineseName = name.replace(/\s+/g, '');
	for (i = 0; i < keys.length; i++) {
		if (chineseName.indexOf(CHINA_PROVINCES[keys[i]]) === 0)
			return CHINA_PROVINCES[keys[i]];
	}
	if (CHINA_PROVINCE_NAMES[name])
		return CHINA_PROVINCE_NAMES[name];
	name = name.replace(/\s+(?:sheng|shi)$/, '');
	return CHINA_PROVINCE_NAMES[name] || '';
}

function countryFields(payload) {
	var data = payload && typeof payload === 'object' ? payload : {};
	var location = data.location && typeof data.location === 'object'
		? data.location : {};
	var network = data.network && typeof data.network === 'object'
		? data.network : {};
	var autonomousSystem = network.autonomous_system &&
		typeof network.autonomous_system === 'object'
		? network.autonomous_system : {};
	var code = location.country_code || location.countryCode ||
		location.country_a2 || autonomousSystem.country ||
		data.country_code || data.countryCode || data.country_a2 || '';
	var country = location.country || location.country_name ||
		location.countryName || data.country || data.country_name ||
		data.countryName || '';
	var regionCode = location.region_code || location.regionCode ||
		location.subdivision_code || data.region_code || data.regionCode ||
		data.subdivision_code || data.state_prov_code || data.stateProvCode || '';
	var region = location.region || location.region_name || location.regionName ||
		location.subdivision || data.region || data.region_name || data.regionName ||
		data.subdivision || data.state_prov || data.stateProv || data.state || '';
	var normalizedCountry;
	code = String(code || '').trim().toUpperCase();
	country = String(country || '').trim();
	normalizedCountry = country.toLowerCase().replace(/[\s_.-]+/g, ' ');
	if (/^(?:hong kong|hong kong sar|香港|中國香港|中国香港)$/.test(normalizedCountry))
		code = 'HK';
	else if (/^(?:taiwan|taiwan province of china|台灣|台湾|中國台灣|中国台湾)$/.test(normalizedCountry))
		code = 'TW';
	else if (/^(?:macao|macau|macao sar|macau sar|澳門|澳门|中國澳門|中国澳门)$/.test(normalizedCountry))
		code = 'MO';
	if (!/^[A-Z]{2}$/.test(code)) {
		if (/^[A-Za-z]{2}$/.test(country))
			code = country.toUpperCase();
		else
			code = '';
	}
	return {
		code: code,
		country: country,
		regionCode: String(regionCode || '').trim().toUpperCase(),
		region: String(region || '').trim()
	};
}

function countryResult(entry, displayNames) {
	var label = '';
	var province;
	if (entry.code && displayNames && typeof displayNames.of === 'function') {
		try { label = displayNames.of(entry.code) || ''; } catch (e) {}
	}
	if (!label)
		label = entry.country || entry.code || '';
	if (entry.code === 'CN') {
		province = chinaProvince(entry.regionCode, entry.region);
		if (province)
			label = '中国·' + province;
	}
	return label
		? result('country', String(label), false)
		: result('unknown', '未知', false);
}

function createResolver(options) {
	options = options || {};
	var now = typeof options.now === 'function' ? options.now : Date.now;
	var fetcher = options.fetch;
	var storage = safeStorage(options);
	var maxEntries = Math.max(1, Math.min(MAX_CACHE_ENTRIES,
		Math.floor(Number(options.maxEntries) || MAX_CACHE_ENTRIES)));
	var concurrency = Math.max(1, Math.min(MAX_CONCURRENCY,
		Math.floor(Number(options.concurrency) || MAX_CONCURRENCY)));
	var schedule = options.schedule;
	var cancel = options.cancel;
	var requestSchedule = options.requestSchedule;
	var requestCancel = options.requestCancel;
	var displayNames = createDisplayNames(options);
	var secondarySources = Array.isArray(options.secondarySources)
		? options.secondarySources : SECONDARY_SOURCES;
	var cache = readCache(storage, maxEntries, now());
	var pending = Object.create(null);
	var queue = [];
	var activeRequests = [];
	var active = 0;
	var disposed = false;
	var persistTimer = null;

	if (!fetcher) {
		try {
			if (typeof window !== 'undefined' && typeof window.fetch === 'function')
				fetcher = window.fetch.bind(window);
		} catch (e) {}
	}
	if (typeof schedule !== 'function') {
		schedule = function(handler) {
			return typeof window !== 'undefined' && typeof window.setTimeout === 'function'
				? window.setTimeout(handler, 0) : setTimeout(handler, 0);
		};
	}
	if (typeof cancel !== 'function') {
		cancel = function(timer) {
			if (typeof window !== 'undefined' && typeof window.clearTimeout === 'function')
				window.clearTimeout(timer);
			else
				clearTimeout(timer);
		};
	}
	if (typeof requestSchedule !== 'function') {
		requestSchedule = function(handler, delay) {
			return typeof window !== 'undefined' && typeof window.setTimeout === 'function'
				? window.setTimeout(handler, delay) : setTimeout(handler, delay);
		};
	}
	if (typeof requestCancel !== 'function') {
		requestCancel = function(timer) {
			if (typeof window !== 'undefined' && typeof window.clearTimeout === 'function')
				window.clearTimeout(timer);
			else
				clearTimeout(timer);
		};
	}

	function persist() {
		persistTimer = null;
		if (disposed || !storage || typeof storage.setItem !== 'function')
			return;
		trimCache(cache, maxEntries);
		try {
			storage.setItem(CACHE_KEY, JSON.stringify({ version: CACHE_VERSION, entries: cache }));
		} catch (e) {}
	}

	function persistSoon() {
		if (disposed || persistTimer !== null)
			return;
		try { persistTimer = schedule(persist); } catch (e) { persistTimer = null; }
	}

	function cached(ip) {
		var key = lookupKey(ip);
		var entry = cache[key];
		if (!entry)
			return null;
		if (entry.expiresAt <= now()) {
			delete cache[key];
			persistSoon();
			return null;
		}
		return entry.status === 'ok'
			? countryResult(entry, displayNames)
			: result('unknown', '未知', false);
	}

	function peek(ip) {
		var value = cleanIp(ip);
		var classification = classify(value);
		var hit;
		if (!classification.queryable)
			return classification;
		hit = cached(value);
		return hit || classification;
	}

	function storeSuccess(ip, fields) {
		var stamp = now();
		var key = lookupKey(ip);
		cache[key] = {
			status: 'ok',
			code: fields.code,
			country: fields.country,
			regionCode: fields.regionCode,
			region: fields.region,
			storedAt: stamp,
			expiresAt: stamp + POSITIVE_TTL_MS
		};
		trimCache(cache, maxEntries);
		persistSoon();
		return countryResult(cache[key], displayNames);
	}

	function storeFailure(ip) {
		var stamp = now();
		cache[lookupKey(ip)] = {
			status: 'fail',
			storedAt: stamp,
			expiresAt: stamp + NEGATIVE_TTL_MS
		};
		trimCache(cache, maxEntries);
		persistSoon();
		return result('unknown', '未知', false);
	}

	function lookupSource(source, ip, requestOptions) {
		var endpoint = source && typeof source.url === 'function'
			? source.url(ip) : '';
		if (!endpoint)
			return Promise.reject(new Error('geolocation source endpoint missing'));
		return Promise.resolve().then(function() {
			if (typeof fetcher !== 'function')
				throw new Error('fetch unavailable');
			return fetcher(endpoint, requestOptions);
		}).then(function(response) {
			if (!response || response.ok === false || typeof response.json !== 'function')
				throw new Error('geolocation request failed');
			return response.json();
		}).then(function(payload) {
			var fields;
			if (payload && payload.success === false)
				throw new Error('geolocation request rejected');
			fields = countryFields(payload);
			if (!fields.code && !fields.country)
				throw new Error('country missing');
			return {
				source: source && source.name ? String(source.name) : '',
				fields: fields
			};
		});
	}

	function fallbackLookup(ip, requestOptions, index) {
		if (index >= secondarySources.length)
			return Promise.reject(new Error('geolocation providers unavailable'));
		return lookupSource(secondarySources[index], ip, requestOptions).then(
			function(entry) { return entry.fields; },
			function() { return fallbackLookup(ip, requestOptions, index + 1); }
		);
	}

	function fetchOne(ip) {
		var controller = null;
		var requestRecord = { controller: null, timer: null, reject: null, done: false };
		var requestOptions = {
			credentials: 'omit',
			/* ipapi.co varies CORS headers by Origin; no-referrer suppresses it. */
			referrerPolicy: 'origin',
			headers: { Accept: 'application/json' }
		};
		if (typeof AbortController !== 'undefined') {
			try {
				controller = new AbortController();
				requestOptions.signal = controller.signal;
			} catch (e) { controller = null; }
		}
		requestRecord.controller = controller;
		activeRequests.push(requestRecord);

		function cleanup() {
			var index;
			if (requestRecord.done)
				return;
			requestRecord.done = true;
			if (requestRecord.timer !== null) {
				try { requestCancel(requestRecord.timer); } catch (e) {}
				requestRecord.timer = null;
			}
			index = activeRequests.indexOf(requestRecord);
			if (index !== -1)
				activeRequests.splice(index, 1);
		}

		var timeout = new Promise(function(resolveTimeout, rejectTimeout) {
			requestRecord.reject = rejectTimeout;
			try {
				requestRecord.timer = requestSchedule(function() {
					if (requestRecord.done)
						return;
					if (controller) {
						try { controller.abort(); } catch (e) {}
					}
					rejectTimeout(new Error('geolocation request timed out'));
				}, REQUEST_TIMEOUT_MS);
			} catch (e) {
				rejectTimeout(e);
			}
		});
		var primary = {
			name: 'FreeIPAPI',
			url: function(value) {
				return LOOKUP_ENDPOINT + encodeURIComponent(value);
			}
		};
		var request = lookupSource(primary, ip, requestOptions).then(function(entry) {
			return entry.fields;
		}, function() {
			return fallbackLookup(ip, requestOptions, 0);
		});
		return Promise.race([ request, timeout ]).then(function(fields) {
			return disposed ? result('unknown', '未知', false) : storeSuccess(ip, fields);
		}, function() {
			return disposed ? result('unknown', '未知', false) : storeFailure(ip);
		}).then(function(value) {
			cleanup();
			return value;
		}, function() {
			cleanup();
			return disposed
				? result('unknown', '未知', false)
				: storeFailure(ip);
		});
	}

	function pump() {
		var item;
		while (!disposed && active < concurrency && queue.length) {
			item = queue.shift();
			active++;
			(function(task) {
				fetchOne(task.ip).then(function(value) {
					task.resolve(value);
				}, function() {
					task.resolve(result('unknown', '未知', false));
				}).then(function() {
					active--;
					delete pending[task.key];
					pump();
				});
			})(item);
		}
	}

	function resolve(ip) {
		var value = cleanIp(ip);
		var key = lookupKey(value);
		var immediate = peek(value);
		var resolvePromise;
		var promise;
		if (disposed)
			return Promise.resolve(result('unknown', '未知', false));
		if (!immediate.queryable)
			return Promise.resolve(immediate);
		if (pending[key])
			return pending[key];
		promise = new Promise(function(resolveTask) {
			resolvePromise = resolveTask;
		});
		pending[key] = promise;
		queue.push({ ip: value, key: key, resolve: resolvePromise });
		pump();
		return promise;
	}

	function dispose() {
		var item;
		if (disposed)
			return;
		disposed = true;
		if (persistTimer !== null) {
			cancel(persistTimer);
			persistTimer = null;
		}
		activeRequests.slice().forEach(function(request) {
			if (request.timer !== null) {
				try { requestCancel(request.timer); } catch (e) {}
				request.timer = null;
			}
			if (request.controller) {
				try { request.controller.abort(); } catch (e) {}
			}
			request.done = true;
			if (request.reject)
				request.reject(new Error('geolocation resolver disposed'));
		});
		activeRequests = [];
		while (queue.length) {
			item = queue.shift();
			delete pending[item.key];
			item.resolve(result('unknown', '未知', false));
		}
	}

	return {
		peek: peek,
		resolve: resolve,
		dispose: dispose
	};
}

return baseclass.extend({
	classify: classify,
	createResolver: createResolver
});
