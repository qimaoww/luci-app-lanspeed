#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const modulePath = path.join(root,
	'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/geoLocation.js');
const source = fs.readFileSync(modulePath, 'utf8');

function assert(condition, message) {
	if (!condition) throw new Error(message);
}

function loadGeo(abortController) {
	return vm.compileFunction(source, [
		'baseclass', 'window', 'Intl', 'Date', 'AbortController',
		'setTimeout', 'clearTimeout'
	], { filename: 'resources/lanspeed/geoLocation.js' })(
		{ extend: (value) => value }, undefined, Intl, Date, abortController,
		setTimeout, clearTimeout
	);
}

function memoryStorage(initial) {
	let value = initial || null;
	let writes = 0;
	return {
		getItem: () => value,
		setItem: (key, next) => { value = next; writes++; },
		value: () => value,
		writes: () => writes
	};
}

function scheduler() {
	let nextId = 0;
	const handlers = new Map();
	return {
		schedule: (handler) => {
			const id = ++nextId;
			handlers.set(id, handler);
			return id;
		},
		cancel: (id) => handlers.delete(id),
		flush: () => {
			const pending = Array.from(handlers.values());
			handlers.clear();
			pending.forEach((handler) => handler());
		},
		size: () => handlers.size
	};
}

async function flushMicrotasks(rounds = 12) {
	for (let i = 0; i < rounds; i++) await Promise.resolve();
}

function response(payload) {
	return { ok: true, json: () => Promise.resolve(payload) };
}

async function main() {
	const geo = loadGeo();
	assert(geo && typeof geo.classify === 'function' &&
		typeof geo.createResolver === 'function' &&
		JSON.stringify(Object.keys(geo).sort()) ===
			JSON.stringify([ 'classify', 'createResolver' ]),
		'geoLocation.js must expose only classify and createResolver');
	assert(source.includes('MAX_CACHE_ENTRIES = 4096') &&
		source.includes("CACHE_KEY = 'lanspeed.geo-location.v3'") &&
		source.includes("LOOKUP_ENDPOINT = 'https://ipwho.is/'") &&
		source.includes("https://ipinfo.io/") &&
		source.includes("https://api.db-ip.com/v2/free/") &&
		source.includes('POSITIVE_TTL_MS = 7 * 24 * 60 * 60 * 1000') &&
		source.includes('NEGATIVE_TTL_MS = 5 * 60 * 1000') &&
		source.includes('MAX_CONCURRENCY = 4') &&
		source.includes('REQUEST_TIMEOUT_MS = 8000'),
		'geoLocation.js must retain the 4096/7-day/5-minute/4-request/8-second bounds');

	for (const ip of [
		'10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.2.3',
		'172.16.0.1', '172.31.255.255', '192.168.1.1', '::1',
		'fe80::1%br-lan', 'fc00::1', 'fdff::1', '::ffff:192.168.1.2'
	]) {
		const value = geo.classify(ip);
		assert(value.kind === 'local' && value.label === '本地/内网' && !value.queryable,
			`${ip} must be classified as local/private without lookup`);
	}
	for (const ip of [ '198.18.0.0', '198.19.255.255', '::ffff:198.18.2.3' ]) {
		const value = geo.classify(ip);
		assert(value.kind === 'fake' && value.label === '代理 Fake-IP' && !value.queryable,
			`${ip} must be classified as proxy Fake-IP without lookup`);
	}
	for (const ip of [
		'0.0.0.0', '192.0.2.1', '198.51.100.9', '203.0.113.1',
		'224.0.0.1', '255.255.255.255', '::', '2001:db8::1',
		'3fff::1', 'ff02::1', 'not-an-ip'
	]) {
		const value = geo.classify(ip);
		assert(value.kind === 'reserved' && value.label === '保留/未知' && !value.queryable,
			`${ip} must be classified as documentation/multicast/reserved`);
	}
	for (const ip of [ '1.1.1.1', '8.8.8.8', '198.20.0.1', '2001:4860:4860::8888' ]) {
		const value = geo.classify(ip);
		assert(value.kind === 'public' && value.queryable,
			`${ip} must be eligible for public-IP lookup`);
	}

	let publicFetches = 0;
	const publicOnly = geo.createResolver({
		storage: null,
		fetch: (url, options) => {
			publicFetches++;
			assert(url === 'https://ipwho.is/8.8.8.8',
				'lookups must use the encoded https://ipwho.is/<ip> endpoint');
			assert(options.credentials === 'omit' && options.referrerPolicy === 'no-referrer',
				'lookups must omit credentials and referrer data');
			return response({
				success: true,
				country_code: 'CN',
				country: 'China',
				region_code: 'ZJ',
				region: 'Zhejiang Sheng'
			});
		},
		displayNames: { of: (code) => code === 'CN' ? '中国' : code }
	});
	for (const ip of [ '192.168.1.1', '198.18.1.1', '192.0.2.1', 'ff02::1' ])
		await publicOnly.resolve(ip);
	assert(publicFetches === 0, 'non-public addresses must never reach the network');
	const localized = await publicOnly.resolve('8.8.8.8');
	assert(publicFetches === 1 && localized.kind === 'country' && localized.label === '中国·浙江',
		'Chinese public IPs must include the localized province');
	publicOnly.dispose();

	let chinaCalls = [];
	const chinaSingleSource = geo.createResolver({
		storage: null,
		fetch: (url) => {
			chinaCalls.push(url);
			return response({
				success: true, country_code: 'CN', country: 'China',
				region_code: 'ZJ', region: 'Zhejiang'
			});
		},
		displayNames: { of: (code) => code === 'CN' ? '中国' : code }
	});
	assert((await chinaSingleSource.resolve('8.8.8.8')).label === '中国·浙江' &&
		chinaCalls.length === 1 && chinaCalls[0] === 'https://ipwho.is/8.8.8.8',
		'Chinese IPs must use only ipwho.is so province data stays single-source');
	chinaSingleSource.dispose();

	let foreignCalls = [];
	const foreignMajority = geo.createResolver({
		storage: null,
		fetch: (url, options) => {
			foreignCalls.push({ url, options });
			assert(options.credentials === 'omit' && options.referrerPolicy === 'no-referrer',
				'all foreign providers must omit credentials and referrer data');
			if (url === 'https://ipwho.is/8.8.8.8')
				return response({ country_code: 'US', country: 'United States', region: 'California' });
			if (url === 'https://ipinfo.io/8.8.8.8/json')
				return response({ country: 'US', region: 'California' });
			if (url === 'https://api.db-ip.com/v2/free/8.8.8.8')
				return response({ countryCode: 'CA', countryName: 'Canada', stateProvCode: 'ON' });
			throw new Error(`unexpected provider URL: ${url}`);
		},
		displayNames: { of: (code) => ({ US: '美国', CA: '加拿大' })[code] || code }
	});
	assert((await foreignMajority.resolve('8.8.8.8')).label === '美国' &&
		foreignCalls.map((item) => item.url).sort().join('|') === [
			'https://api.db-ip.com/v2/free/8.8.8.8',
			'https://ipinfo.io/8.8.8.8/json',
			'https://ipwho.is/8.8.8.8'
		].sort().join('|'),
		'foreign IPs must use ipwho.is, ipinfo.io and DB-IP and display the majority country');
	foreignMajority.dispose();

	let providerFallbackCalls = [];
	const providerFallback = geo.createResolver({
		storage: null,
		fetch: (url) => {
			providerFallbackCalls.push(url);
			if (url === 'https://ipwho.is/9.9.9.9')
				return response({ success: false });
			if (url === 'https://ipinfo.io/9.9.9.9/json')
				return response({ country: 'DE', region: 'Hesse' });
			return response({ countryCode: 'DE', countryName: 'Germany' });
		},
		displayNames: { of: (code) => code === 'DE' ? '德国' : code }
	});
	assert((await providerFallback.resolve('9.9.9.9')).label === '德国' &&
		providerFallbackCalls.length === 3,
		'a failed primary provider must fall back to both secondary providers');
	providerFallback.dispose();

	const provincePayloads = [
		{ success: true, country_code: 'CN', country: 'China', region_code: 'BJ', region: 'Beijing' },
		{ success: true, country_code: 'CN', country: 'China', region_code: 'XJ', region: 'Xinjiang Uygur Zizhiqu' },
		{ success: true, country_code: 'CN', country: 'China', region: '广西壮族自治区' },
		{ success: true, country_code: 'CN', country: 'China' }
	];
	const provinces = geo.createResolver({
		storage: null,
		fetch: () => response(provincePayloads.shift()),
		displayNames: { of: (code) => code === 'CN' ? '中国' : code }
	});
	assert((await provinces.resolve('17.0.0.1')).label === '中国·北京' &&
		(await provinces.resolve('17.0.0.2')).label === '中国·新疆' &&
		(await provinces.resolve('17.0.0.3')).label === '中国·广西' &&
		(await provinces.resolve('17.0.0.4')).label === '中国',
		'China province rendering must cover municipalities, autonomous regions, name fallback and missing data');
	provinces.dispose();

	const specialPayloads = [
		{ network: { autonomous_system: { country: 'CN' } }, location: { country: 'Hong Kong' } },
		{ network: { autonomous_system: { country: 'CN' } }, location: { country: 'Taiwan' } },
		{ network: { autonomous_system: { country: 'CN' } }, location: { country: 'Macao' } }
	];
	const special = geo.createResolver({
		storage: null,
		secondarySources: [],
		fetch: () => response(specialPayloads.shift()),
		displayNames: {
			of: (code) => ({ HK: '香港', TW: '台湾', MO: '澳门', CN: '中国' })[code] || code
		}
	});
	assert((await special.resolve('15.0.0.1')).label === '香港' &&
		(await special.resolve('15.0.0.2')).label === '台湾' &&
		(await special.resolve('15.0.0.3')).label === '澳门',
		'location names for Hong Kong, Taiwan and Macao must override an ASN registration country');
	special.dispose();

	const fallback = geo.createResolver({
		storage: null,
		secondarySources: [],
		fetch: () => response({ location: { country: 'Fallback Country' } }),
		displayNames: { of: () => { throw new Error('unsupported locale'); } }
	});
	assert((await fallback.resolve('9.9.9.9')).label === 'Fallback Country',
		'location.country must be used when a localized country code is unavailable');
	fallback.dispose();

	let now = 1_000_000;
	const positiveStorage = memoryStorage();
	const positiveSchedule = scheduler();
	let positiveFetches = 0;
	const resolverA = geo.createResolver({
		storage: positiveStorage,
		secondarySources: [],
		now: () => now,
		schedule: positiveSchedule.schedule,
		cancel: positiveSchedule.cancel,
		fetch: () => {
			positiveFetches++;
			return response({ location: { country_code: 'US', country: 'United States' } });
		},
		displayNames: { of: (code) => code === 'US' ? '美国' : code }
	});
	assert((await resolverA.resolve('1.1.1.1')).label === '美国',
		'a successful lookup must return its localized country');
	positiveSchedule.flush();
	assert(positiveStorage.writes() === 1, 'successful lookups must be batched into browser cache writes');
	resolverA.dispose();

	const resolverB = geo.createResolver({
		storage: positiveStorage,
		secondarySources: [],
		now: () => now + 7 * 24 * 60 * 60 * 1000 - 1,
		fetch: () => { positiveFetches++; return response({}); },
		displayNames: { of: () => '美国' }
	});
	assert(resolverB.peek('1.1.1.1').label === '美国' &&
		(await resolverB.resolve('1.1.1.1')).label === '美国' && positiveFetches === 1,
		'positive cache entries must be reused for seven days without a network call');
	resolverB.dispose();

	const expirySchedule = scheduler();
	const resolverC = geo.createResolver({
		storage: positiveStorage,
		secondarySources: [],
		now: () => now + 7 * 24 * 60 * 60 * 1000,
		schedule: expirySchedule.schedule,
		cancel: expirySchedule.cancel,
		fetch: () => {
			positiveFetches++;
			return response({ location: { country: 'Expired Refresh' } });
		},
		displayNames: { of: (code) => code }
	});
	assert((await resolverC.resolve('1.1.1.1')).label === 'Expired Refresh' && positiveFetches === 2,
		'positive entries must expire at the seven-day boundary');
	resolverC.dispose();

	const legacyStorage = memoryStorage(JSON.stringify({
		version: 2,
		entries: {
			'18.0.0.1': {
				status: 'ok', code: 'CN', country: 'China', storedAt: now,
				expiresAt: now + 7 * 24 * 60 * 60 * 1000
			}
		}
	}));
	let legacyFetches = 0;
	const legacy = geo.createResolver({
		storage: legacyStorage,
		secondarySources: [],
		now: () => now,
		fetch: () => {
			legacyFetches++;
			return response({
				success: true, country_code: 'CN', country: 'China',
				region_code: 'GD', region: 'Guangdong Sheng'
			});
		},
		displayNames: { of: () => '中国' }
	});
	assert((await legacy.resolve('18.0.0.1')).label === '中国·广东' && legacyFetches === 1,
		'v2 country-only cache entries must be invalidated so China can use the new provider set');
	legacy.dispose();

	let failureNow = 2_000_000;
	const failureStorage = memoryStorage();
	const failureSchedule = scheduler();
	let failureFetches = 0;
	const failedA = geo.createResolver({
		storage: failureStorage,
		secondarySources: [],
		now: () => failureNow,
		schedule: failureSchedule.schedule,
		cancel: failureSchedule.cancel,
		fetch: () => { failureFetches++; throw new Error('offline'); }
	});
	const failedResult = await failedA.resolve('8.8.4.4');
	assert(failedResult.kind === 'unknown' && failedResult.label === '未知',
		'network failures must resolve to unknown instead of rejecting the page');
	failureSchedule.flush();
	failedA.dispose();
	const failedB = geo.createResolver({
		storage: failureStorage,
		secondarySources: [],
		now: () => failureNow + 5 * 60 * 1000 - 1,
		fetch: () => { failureFetches++; return response({}); }
	});
	assert((await failedB.resolve('8.8.4.4')).label === '未知' && failureFetches === 1,
		'negative cache entries must suppress retries for five minutes');
	failedB.dispose();
	const failedC = geo.createResolver({
		storage: failureStorage,
		secondarySources: [],
		now: () => failureNow + 5 * 60 * 1000,
		fetch: () => {
			failureFetches++;
			return response({ location: { country: 'Recovered' } });
		}
	});
	assert((await failedC.resolve('8.8.4.4')).label === 'Recovered' && failureFetches === 2,
		'negative entries must be retried after five minutes');
	failedC.dispose();

	let active = 0;
	let maxActive = 0;
	let concurrencyFetches = 0;
	const controls = [];
	const concurrent = geo.createResolver({
		storage: null,
		secondarySources: [],
		concurrency: 99,
		fetch: () => {
			active++;
			maxActive = Math.max(maxActive, active);
			concurrencyFetches++;
			return new Promise((resolve) => {
				controls.push(() => {
					active--;
					resolve(response({ location: { country: 'Concurrent' } }));
				});
			});
		}
	});
	const concurrentPromises = [];
	for (let i = 1; i <= 9; i++)
		concurrentPromises.push(concurrent.resolve(`11.0.0.${i}`));
	const merged = concurrent.resolve('11.0.0.1');
	assert(merged === concurrentPromises[0], 'simultaneous requests for the same IP must share one Promise');
	await flushMicrotasks();
	assert(concurrencyFetches === 4 && maxActive === 4,
		'the resolver must start no more than four network requests');
	let released = 0;
	while (released < controls.length || concurrencyFetches < 9) {
		while (released < controls.length) controls[released++]();
		await flushMicrotasks();
	}
	await Promise.all(concurrentPromises.concat(merged));
	assert(concurrencyFetches === 9 && maxActive <= 4,
		'the full queue must complete with a hard concurrency ceiling of four');
	concurrent.dispose();

	class FakeAbortController {
		constructor() { this.signal = { aborted: false }; }
		abort() { this.signal.aborted = true; }
	}
	const timeoutGeo = loadGeo(FakeAbortController);
	let timeoutId = 0;
	let timeoutFetches = 0;
	const timeoutHandlers = new Map();
	const timeoutSignals = [];
	const hanging = timeoutGeo.createResolver({
		storage: null,
		secondarySources: [],
		requestSchedule: (handler, delay) => {
			assert(delay === 8000, 'each public-IP lookup must receive an eight-second timeout');
			const id = ++timeoutId;
			timeoutHandlers.set(id, handler);
			return id;
		},
		requestCancel: (id) => timeoutHandlers.delete(id),
		fetch: (url, options) => {
			timeoutFetches++;
			timeoutSignals.push(options.signal);
			return new Promise(() => {});
		}
	});
	const hangingRequests = [];
	for (let i = 1; i <= 5; i++) hangingRequests.push(hanging.resolve(`16.0.0.${i}`));
	await flushMicrotasks();
	assert(timeoutFetches === 4 && timeoutHandlers.size === 4,
		'four hanging requests must occupy the initial bounded slots');
	const firstTimeout = timeoutHandlers.values().next().value;
	firstTimeout();
	assert((await hangingRequests[0]).label === '未知',
		'a timed-out lookup must safely resolve to unknown');
	await flushMicrotasks();
	assert(timeoutSignals[0].aborted && timeoutFetches === 5 && timeoutHandlers.size === 4,
		'timeout must abort the fetch, release its slot and start the next queued lookup');
	hanging.dispose();
	const remainingHanging = await Promise.all(hangingRequests.slice(1));
	assert(remainingHanging.every((entry) => entry.label === '未知') &&
		timeoutHandlers.size === 0 && timeoutSignals.every((signal) => signal.aborted),
		'disposal must abort hanging lookups and clear every request timeout');

	const boundedNow = 3_000_000;
	const oversized = { version: 3, entries: {} };
	for (let i = 0; i < 4100; i++) {
		oversized.entries[`12.0.${Math.floor(i / 256)}.${i % 256}`] = {
			status: 'ok', code: 'US', country: 'United States', storedAt: i,
			expiresAt: boundedNow + 100000
		};
	}
	const boundedStorage = memoryStorage(JSON.stringify(oversized));
	const boundedSchedule = scheduler();
	const bounded = geo.createResolver({
		storage: boundedStorage,
		secondarySources: [],
		now: () => boundedNow,
		schedule: boundedSchedule.schedule,
		cancel: boundedSchedule.cancel,
		fetch: () => response({ location: { country: 'New Entry' } })
	});
	await bounded.resolve('13.0.0.1');
	boundedSchedule.flush();
	const persistedEntries = Object.keys(JSON.parse(boundedStorage.value()).entries);
	assert(persistedEntries.length === 4096,
		'the persisted positive/negative cache must never exceed 4096 entries');
	bounded.dispose();

	const disposeStorage = memoryStorage();
	const disposeSchedule = scheduler();
	let finishDisposed;
	const disposed = geo.createResolver({
		storage: disposeStorage,
		secondarySources: [],
		schedule: disposeSchedule.schedule,
		cancel: disposeSchedule.cancel,
		fetch: () => new Promise((resolve) => { finishDisposed = resolve; })
	});
	const disposedRequest = disposed.resolve('14.0.0.1');
	await flushMicrotasks();
	disposed.dispose();
	finishDisposed(response({ location: { country: 'Too Late' } }));
	assert((await disposedRequest).label === '未知',
		'in-flight requests completing after disposal must not update the view');
	disposeSchedule.flush();
	assert(disposeStorage.writes() === 0 && disposeSchedule.size() === 0,
		'disposal must cancel deferred cache writes and prevent unload writeback');

	console.log('validate-lanspeed-geo: PASS');
}

main().catch((error) => {
	console.error(`validate-lanspeed-geo: FAIL\n  - ${error && error.stack || error}`);
	process.exit(1);
});
