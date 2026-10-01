#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const moduleDir = path.resolve(__dirname,
	'../applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed');
const source = fs.readFileSync(path.join(moduleDir, 'macVendor.js'), 'utf8');
const database = [
	'001122000000', 24, 'Example Network Cards',
	'001122300000', 28, 'Example Modules',
	'001122334000', 36, 'Example Devices',
	'001124000000', 24, '<img src=x onerror=alert(1)>'
];
const day = 24 * 60 * 60 * 1000;

function resolver(options = {}) {
	let now = options.now || 100 * day;
	let saved = options.cache === undefined ? null : options.cache;
	let requests = 0;
	const urls = [];
	const storage = {
		getItem: () => saved,
		setItem: (_key, value) => {
			if (options.quotaError) throw new Error('quota exceeded');
			saved = value;
		}
	};
	const instance = vm.compileFunction(source, [ 'baseclass', 'request', 'window', 'Date', '_' ])(
		{ extend: value => value },
		{ get: (url, requestOptions) => {
			requests++;
			urls.push(url);
			assert.strictEqual(requestOptions.timeout, 5000);
			assert.strictEqual(requestOptions.cache, true);
			return options.request ? options.request() : Promise.resolve({
				ok: true, json: () => database
			});
		} },
		{ get localStorage() {
			if (options.storageError) throw new Error('storage unavailable');
			return storage;
		} },
		{ now: () => now }, value => value
	);
	return { instance, requests: () => requests, urls, saved: () => saved,
		advance: delta => { now += delta; } };
}

function cache(age) {
	return JSON.stringify({ savedAt: 100 * day - age, entries: database });
}

async function main() {
	let complete;
	const deferred = new Promise(resolve => { complete = resolve; });
	const active = resolver({ request: () => deferred });
	const first = active.instance.load();
	assert.strictEqual(active.instance.load(), first, 'concurrent views share one database download');
	assert.strictEqual(active.instance.lookup('00:11:22:33:44:55').kind, 'loading');
	await Promise.resolve();
	assert.strictEqual(active.requests(), 1);
	complete({ ok: true, json: () => database });
	await first;
	for (const mac of [ '00:11:22:33:44:55', '00-11-22-33-44-55', '001122334455' ]) {
		assert.strictEqual(active.instance.lookup(mac).vendor, 'Example Devices',
			'36-bit registration must take precedence over overlapping 28/24-bit registrations');
	}
	assert.strictEqual(active.instance.lookup(' 00:11:22:3F:00:00 ').vendor, 'Example Modules');
	assert.strictEqual(active.instance.lookup('00:11:22:40:00:00').vendor, 'Example Network Cards');
	assert.strictEqual(active.instance.lookup('00:11:22:33:3f:ff').vendor, 'Example Modules');
	assert.strictEqual(active.instance.lookup('00:11:23:00:00:00').kind, 'unknown');
	assert.strictEqual(active.instance.lookup('00:11:24:00:00:00').label, '<img src=x onerror=alert(1)>');
	for (const mac of [ '02:11:22:33:44:55', '06:11:22:33:44:55', 'da:11:22:33:44:55' ]) {
		assert.strictEqual(active.instance.lookup(mac).kind, 'local');
		assert.strictEqual(active.instance.lookup(mac).vendor, '');
	}
	for (const mac of [ '', null, 'not-a-mac', '00:11-22:33:44:55', '00:11:22',
		'00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff', '01:11:22:33:44:55' ]) {
		assert.strictEqual(active.instance.lookup(mac).kind, 'invalid');
	}
	await active.instance.load();
	assert.strictEqual(active.requests(), 1, 'refreshing rows never downloads per-client data');
	assert.deepStrictEqual(active.urls, [
		'https://raw.githubusercontent.com/jow-/oui-database/master/oui.json'
	], 'the database request must contain no device MAC or prefix');
	assert.deepStrictEqual(JSON.parse(active.saved()).entries, database);
	assert(!active.saved().includes('001122334455'), 'cache stores registrations, not queried devices');

	const fresh = resolver({ cache: cache(7 * day) });
	await fresh.instance.load();
	assert.strictEqual(fresh.requests(), 0);
	assert.strictEqual(fresh.instance.lookup('00:11:22:33:44:55').vendor, 'Example Devices');
	const offline = resolver({ request: () => Promise.reject(new Error('offline')) });
	await offline.instance.load();
	assert.strictEqual(offline.instance.lookup('00:11:22:33:44:55').kind, 'unavailable');
	assert.strictEqual(offline.instance.lookup('02:11:22:33:44:55').kind, 'local');
	await offline.instance.load();
	assert.strictEqual(offline.requests(), 1, 'a failed request must back off');
	offline.advance(60000);
	await offline.instance.load();
	assert.strictEqual(offline.requests(), 2);
	const stale = resolver({ cache: cache(30 * day), request: () => Promise.reject(new Error('offline')) });
	const reload = stale.instance.load();
	assert.strictEqual(stale.instance.lookup('00:11:22:33:44:55').vendor, 'Example Devices');
	await reload;
	assert.strictEqual(stale.requests(), 1);
	assert.strictEqual(stale.instance.lookup('00:11:22:33:44:55').vendor, 'Example Devices');
	for (const cached of [ cache(30 * day + 1), cache(-1), '{broken',
		JSON.stringify({ savedAt: 'invalid', entries: database }) ]) {
		const expired = resolver({ cache: cached, request: () => Promise.reject(new Error('offline')) });
		await expired.instance.load();
		assert.strictEqual(expired.instance.lookup('00:11:22:33:44:55').kind, 'unavailable');
	}
	for (const entries of [ [], {}, [ '001122000000', 24 ],
		[ '001122000001', 24, 'Unaligned' ], [ '001122000000', 25, 'Unsupported' ],
		[ '001122000000', 24, '' ], [ 'ZZ1122000000', 24, 'Invalid' ] ]) {
		const invalid = resolver({ request: () => Promise.resolve({ ok: true, json: () => entries }) });
		await invalid.instance.load();
		assert.strictEqual(invalid.instance.lookup('00:11:22:33:44:55').kind, 'unavailable');
		assert.strictEqual(invalid.saved(), null, 'invalid responses must never poison the cache');
	}
	for (const request of [ () => Promise.resolve({ ok: false }),
		() => Promise.resolve({ ok: true, json: () => { throw new Error('bad JSON'); } }),
		() => { throw new Error('request unavailable'); } ]) {
		const invalid = resolver({ request });
		await invalid.instance.load();
		assert.strictEqual(invalid.instance.lookup('00:11:22:33:44:55').kind, 'unavailable');
	}
	for (const options of [ { storageError: true }, { quotaError: true } ]) {
		const noStorage = resolver(options);
		await noStorage.instance.load();
		assert.strictEqual(noStorage.instance.lookup('00:11:22:33:44:55').vendor, 'Example Devices');
	}
	// Optional verification against a downloaded complete upstream export.
	if (process.env.LANSPEED_OUI_DATABASE) {
		const entries = JSON.parse(fs.readFileSync(process.env.LANSPEED_OUI_DATABASE, 'utf8'));
		const real = resolver({ request: () => Promise.resolve({ ok: true, json: () => entries }) });
		await real.instance.load();
		assert.strictEqual(real.instance.lookup('00:00:0c:00:00:01').kind, 'vendor');
		assert(/Cisco/i.test(real.instance.lookup('00:00:0c:00:00:01').vendor));
	}
	console.log('validate-lanspeed-mac-vendor: PASS');
	console.log('  longest prefix, MAC validation, shared download, fresh/stale cache, offline recovery');
}

main().catch(error => {
	console.error('validate-lanspeed-mac-vendor: FAIL\n' + error.stack);
	process.exitCode = 1;
});
