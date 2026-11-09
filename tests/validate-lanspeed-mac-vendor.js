#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const moduleDir = path.resolve(__dirname,
	'../applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed');
const source = fs.readFileSync(path.join(moduleDir, 'macVendor.js'), 'utf8');
let databaseText = [
	'# manuf fixture',
	'00:11:22\tExampleCards\tExample Network Cards',
	'00:11:22:30/28\tExampleModules\tExample Modules',
	'00:11:22:33:40/36\tExampleDevices\tExample Devices',
	'00:11:24\tUnsafe\t<img src=x onerror=alert(1)>'
].join('\n');
const database = [
	'001122', 24, 'Example Network Cards',
	'0011223', 28, 'Example Modules',
	'001122334', 36, 'Example Devices',
	'001124', 24, '<img src=x onerror=alert(1)>'
];
// A network export must be large enough to reject small or truncated responses.
for (let i = 0; i < 1000; i++) {
	const prefix = (0x100000 + i).toString(16);
	database.push(prefix, 24, 'Fixture registrant');
	databaseText += '\n' + prefix + '\tFixture\tFixture registrant';
}
databaseText += '\n';
const names = vm.compileFunction(fs.readFileSync(path.join(moduleDir, 'vendorNames.js'), 'utf8'), ['baseclass'])(
	{ extend: value => value });
const db = vm.compileFunction(fs.readFileSync(path.join(moduleDir, 'vendorDatabase.js'), 'utf8'), ['baseclass'])({extend: value => value});
const seed = new Function('baseclass', fs.readFileSync(path.join(moduleDir, 'vendorSeed.js'), 'utf8'))({extend: value => value});
const singleSource = {sources: [Object.assign({}, db.sources[0], {minimum: 1000})], parse: db.parse};
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
	const instance = vm.compileFunction(source, [ 'baseclass', 'request', 'window', 'Date', '_', 'vendorNames', 'vendorDatabase', 'vendorSeed' ])(
		{ extend: value => value },
		{ get: (url, requestOptions) => {
			requests++;
			urls.push(url);
			assert.strictEqual(requestOptions.timeout, 15000);
			assert.strictEqual(requestOptions.cache, true);
			return options.request ? options.request(url) : Promise.resolve({
				ok: true, text: () => databaseText
			});
		} },
		{ get localStorage() {
			if (options.storageError) throw new Error('storage unavailable');
			return storage;
		} },
		{ now: () => now }, value => value, names, options.vendorDatabase || singleSource, options.seed || {lookup: () => null}
	);
	return { instance, requests: () => requests, urls, saved: () => saved,
		advance: delta => { now += delta; } };
}

function cache(age) {
	return JSON.stringify({ savedAt: 100 * day - age, entries: database });
}

function csv(registry, prefix, name) {
	return 'Registry,Assignment,Organization Name,Organization Address\n' +
		registry + ',' + prefix + ',"' + name.replace(/"/g, '""') + '","Address, with\nnewline"\n';
}

async function testMultipleSources() {
	const multiDb = {sources: db.sources.map(s => Object.assign({}, s, {minimum: 1})), parse: db.parse};
	const bodies = {
		wireshark: databaseText,
		oui: csv('MA-L', '001122', 'Apple, Inc.'),
		mam: csv('MA-M', '0011223', 'Huawei Technologies Co., Ltd.'),
		oui36: csv('MA-S', '001122334', 'ASUSTek COMPUTER INC.'),
		iab: csv('IAB', '001125001', 'Intel Corporate')
	};
	function reply(url) {
		const source = multiDb.sources.find(s => s.urls.includes(url));
		assert(source, 'only fixed whole-database URLs are requested');
		return Promise.resolve({ok: true, text: () => bodies[source.id]});
	}
	const multi = resolver({vendorDatabase: multiDb, request: reply});
	await multi.instance.load();
	assert.strictEqual(multi.requests(), 5);
	assert.strictEqual(multi.instance.lookup('00:11:22:33:44:55').label, '华硕');
	assert.strictEqual(multi.instance.lookup('00:11:22:3f:00:00').label, '华为');
	assert.strictEqual(multi.instance.lookup('00:11:22:40:00:00').label, '苹果');
	assert.strictEqual(multi.instance.lookup('00:11:25:00:10:01').label, '英特尔', 'IAB supplements missing entries');
	assert.strictEqual(multi.instance.lookup('00:11:24:00:00:00').kind, 'vendor', 'secondary-only prefix retained');
	assert.strictEqual(multi.instance.lookup('00:11:23:00:00:00').kind, 'unknown');
	assert.strictEqual(multi.instance.lookup('00:11:22:33:44:55').source, 'IEEE MA-S');
	assert.strictEqual(multi.instance.lookup('02:11:22:33:44:55').kind, 'local');
	const restored = resolver({vendorDatabase: multiDb, cache: multi.saved()});
	await restored.instance.load();
	assert.strictEqual(restored.requests(), 0, 'merged cache restores each source without downloads');
	assert.strictEqual(restored.instance.lookup('00:11:22:33:44:55').label, '华硕');
	restored.advance(2 * day);
	assert.strictEqual(restored.instance.lookup('00:11:22:33:44:55').vendor, 'Example Devices',
		'fresh manuf wins over stale IEEE at the same specificity');

	const retrying = resolver({vendorDatabase: multiDb, cache: multi.saved(), request: url => {
		if (url.includes('oui36.csv')) return Promise.reject(Error('offline'));
		return reply(url);
	}});
	retrying.advance(2 * day);
	await retrying.instance.load();
	assert.strictEqual(retrying.requests(), 5, 'only four expired IEEE registries reload, including one fallback');
	assert.strictEqual(retrying.instance.lookup('00:11:22:33:44:55').vendor, 'Example Devices');
	const requests = retrying.requests();
	await retrying.instance.load();
	assert.strictEqual(retrying.requests(), requests, 'failed source backs off independently');
	retrying.advance(60000);
	await retrying.instance.load();
	assert.strictEqual(retrying.requests(), requests + 2, 'retry only the failed registry');

	const fallback = resolver({vendorDatabase: multiDb, request: url =>
		url.includes('raw.githubusercontent') ? Promise.reject(Error('CORS blocked')) : reply(url)});
	await fallback.instance.load();
	assert.strictEqual(fallback.requests(), 9);
	assert(fallback.instance.lookup('00:11:22:33:44:55').sourceUrl.startsWith('https://standards-oui.ieee.org/'));

	const partial = resolver({vendorDatabase: multiDb, request: url =>
		url.includes('wireshark.org') ? reply(url) : Promise.reject(Error('offline'))});
	await partial.instance.load();
	assert.strictEqual(partial.instance.lookup('00:11:22:33:44:55').vendor, 'Example Devices');
	assert.strictEqual(partial.instance.lookup('00:11:25:00:10:01').kind, 'unavailable',
		'failed supplements must not turn an unresolved prefix into a confirmed unknown');

	const spec = multiDb.sources[1];
	assert.deepStrictEqual(db.parse('\uFEFF' + csv('MA-L', '001122', 'Name "quoted", Ltd.'), spec),
		['001122', 24, 'Name "quoted", Ltd.']);
	for (const invalid of [csv('MA-S', '001122', 'Apple'), csv('MA-L', '00112X', 'Apple'),
		csv('MA-L', '001122', 'Apple').slice(0, -1), '<html>blocked</html>\n',
		'Registry,Assignment,Organization Name,Organization Address\nMA-L,001122,"Unclosed\n'])
		assert.throws(() => db.parse(invalid, spec));
	assert.deepStrictEqual(db.parse(csv('MA-L', '001122', 'IEEE Registration Authority') +
		csv('MA-L', '001124', 'Vendor').split('\n').slice(1).join('\n'), spec), ['001124',24,'Vendor']);
	const duplicate = csv('MA-L', '001122', 'First') + csv('MA-L', '001122', 'Second').split('\n').slice(1).join('\n');
	const shared = db.parse(duplicate, spec);
	assert.strictEqual(shared.length, 0);
	assert.deepStrictEqual(shared.ambiguous['001122'], ['First','Second'], 'shared assignments retain original records');
}

async function testOfflineSeed() {
	assert(seed.metadata.count >= 10000);
	assert.strictEqual(seed.metadata.sources.length, 4);
	for (const source of seed.metadata.sources) {
		assert(source.url.includes(seed.metadata.revision));
		assert(/^[a-f0-9]{64}$/.test(source.sha256));
	}
	const offline = resolver({seed, quotaError: true, request: () => Promise.reject(new Error('offline'))});
	for (const [mac, label] of [['10:7c:61:b2:07:01', '华硕'], ['5c:e5:0c:d3:3e:e0', '小米']]) {
		const result = offline.instance.lookup(mac);
		assert.strictEqual(result.label, label);
		assert.strictEqual(result.bundled, true);
		assert.strictEqual(result.stale, false);
		assert(result.title.includes('离线基础数据'));
	}
	assert.strictEqual(offline.requests(), 0, 'offline lookup does not initiate a network request');
	assert.strictEqual(offline.instance.lookup('02:7c:61:b2:07:01').kind, 'local');
	assert.strictEqual(offline.instance.lookup('11:7c:61:b2:07:01').kind, 'invalid');
	assert.strictEqual(offline.instance.lookup('10:7c:61').kind, 'invalid');
	await offline.instance.load();
	assert.strictEqual(offline.instance.lookup('10:7c:61:b2:07:01').label, '华硕');
	assert(offline.instance.lookup('10:7c:61:b2:07:01').title.includes('在线更新暂不可用'));
	offline.advance(60 * day);
	assert.strictEqual(offline.instance.lookup('10:7c:61:b2:07:01').label, '华硕', 'packaged seed survives cache expiry');
	const noStorage = resolver({seed, storageError: true});
	assert.strictEqual(noStorage.instance.lookup('10:7c:61:b2:07:01').label, '华硕');
	offline.advance(-365 * day);
	assert.strictEqual(offline.instance.lookup('10:7c:61:b2:07:01').label, '华硕', 'wall clock changes do not expire installed data');
	const liveDb = {sources: [Object.assign({}, db.sources[1], {minimum: 1})], parse: db.parse};
	const recovering = resolver({seed, vendorDatabase: liveDb, request: () => Promise.resolve({ok: true,
		text: () => csv('MA-L', '107C61', 'Intel Corporate')})});
	assert.strictEqual(recovering.instance.lookup('10:7c:61:b2:07:01').label, '华硕');
	await recovering.instance.load();
	assert.strictEqual(recovering.instance.lookup('10:7c:61:b2:07:01').label, '英特尔', 'online exact prefix replaces offline record');
	assert(!recovering.instance.lookup('10:7c:61:b2:07:01').bundled);
	assert(!recovering.saved().includes('ASUSTek'), 'bundled data must not be copied to the expiring network cache');
	const specificSeed = {metadata: seed.metadata, lookup: (mac, bits) =>
		mac.startsWith('107c61b20') && bits === 36 ? 'Apple, Inc.' : null};
	const narrower = resolver({seed: specificSeed, vendorDatabase: liveDb, request: () => Promise.resolve({ok: true,
		text: () => csv('MA-L', '107C61', 'Intel Corporate')})});
	await narrower.instance.load();
	assert.strictEqual(narrower.instance.lookup('10:7c:61:b2:00:01').label, '苹果', 'offline narrow allocation outranks online parent');
	// Every generated record is reachable at its own prefix and retains an exact registrant alias.
	const generated = fs.readFileSync(path.join(moduleDir, 'vendorSeed.js'), 'utf8');
	for (const bits of [24, 28, 36]) {
		const table = JSON.parse(generated.match(new RegExp('var T' + bits + ' = (.*);'))[1]);
		let previous = '';
		for (let i = 0; i < table.v.length; i++) {
			const prefix = table.p.slice(i * bits / 4, (i + 1) * bits / 4);
			assert(prefix > previous, 'prefixes must be unique and sorted');
			assert(names.resolve(seed.lookup(prefix.padEnd(12, '0'), bits)));
			previous = prefix;
		}
	}
}

async function main() {
	await testOfflineSeed();
	await testMultipleSources();
	let complete;
	const deferred = new Promise(resolve => { complete = resolve; });
	const active = resolver({ request: () => deferred });
	const first = active.instance.load();
	assert.strictEqual(active.instance.load(), first, 'concurrent views share one database download');
	assert.strictEqual(active.instance.lookup('00:11:22:33:44:55').kind, 'loading');
	await Promise.resolve();
	assert.strictEqual(active.requests(), 1);
	complete({ ok: true, text: () => databaseText });
	await first;
	for (const mac of [ '00:11:22:33:44:55', '00-11-22-33-44-55', '001122334455' ]) {
		assert.strictEqual(active.instance.lookup(mac).vendor, 'Example Devices',
			'36-bit registration must take precedence over overlapping 28/24-bit registrations');
	}
	assert.strictEqual(active.instance.lookup(' 00:11:22:3F:00:00 ').vendor, 'Example Modules');
	assert.strictEqual(active.instance.lookup('00:11:22:40:00:00').vendor, 'Example Network Cards');
	assert.strictEqual(active.instance.lookup('00:11:22:33:3f:ff').vendor, 'Example Modules');
	assert.strictEqual(active.instance.lookup('00:11:23:00:00:00').kind, 'unknown');
	assert.strictEqual(active.instance.lookup('00:11:24:00:00:00').label, '中文名称待补充');
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
		'https://www.wireshark.org/download/automated/data/manuf'
	], 'the database request must contain no device MAC or prefix');
	assert(JSON.parse(active.saved()).records.length > 0);
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
	for (const text of [ '', 'not a manuf line', '# comment only',
		'00:11/28\tShort\tVendor', '00:11:22\t\t' ]) {
		const invalid = resolver({ request: () => Promise.resolve({ ok: true, text: () => text }) });
		await invalid.instance.load();
		assert.strictEqual(invalid.instance.lookup('00:11:22:33:44:55').kind, 'unavailable');
		assert.strictEqual(invalid.saved(), null, 'invalid responses must never poison the cache');
	}
	for (const request of [ () => Promise.resolve({ ok: false }),
		() => Promise.resolve({ ok: true, text: () => { throw new Error('bad payload'); } }),
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
	// A page keeps one watcher: it joins a shared download, re-renders once,
	// retries only after the failure backoff, and never repaints a closed page.
	let attempt = 0;
	let release;
	const flaky = resolver({ request: () => {
		attempt++;
		if (attempt === 1) return Promise.reject(new Error('offline'));
		return new Promise(resolve => { release = () => resolve({ ok: true, text: () => databaseText }); });
	} });
	let open = true;
	let renders = 0;
	const ensure = flaky.instance.watch(() => open, () => { renders++; });
	ensure();
	ensure();
	assert.strictEqual(flaky.instance.lookup('00:11:22:33:44:55').kind, 'loading');
	await new Promise(resolve => setTimeout(resolve, 0));
	assert.strictEqual(renders, 1, 'a failed download re-renders once to show the unavailable state');
	assert.strictEqual(flaky.instance.lookup('00:11:22:33:44:55').kind, 'unavailable');
	assert.strictEqual(flaky.instance.lookup('00:11:22:33:44:55').title.includes('重试'), true);
	ensure();
	assert.strictEqual(flaky.requests(), 1, 'refreshes inside the backoff must not re-download');
	flaky.advance(60000);
	ensure();
	ensure();
	await Promise.resolve();
	assert.strictEqual(flaky.requests(), 2, 'the next refresh after backoff retries once');
	open = false;
	release();
	await new Promise(resolve => setTimeout(resolve, 0));
	assert.strictEqual(renders, 1, 'a page closed during the download must not repaint');
	assert.strictEqual(flaky.instance.lookup('00:11:22:33:44:55').vendor, 'Example Devices');
	ensure();
	assert.strictEqual(flaky.requests(), 2, 'a fresh database needs no further downloads');
	const local = flaky.instance.lookup('02:11:22:33:44:55');
	assert(/注册/.test(local.title) && local.kind === 'local', 'random MACs explain why no registration applies');
	const registered = flaky.instance.lookup('00:11:22:33:44:55');
	assert(registered.title.startsWith('地址前缀注册机构：'), 'registered names are described as OUI registrants');

	const stalePage = resolver({ cache: cache(8 * day), request: () => Promise.reject(new Error('offline')) });
	await stalePage.instance.load();
	assert.strictEqual(stalePage.instance.lookup('00:11:22:33:44:55').stale, true,
		'stale cache results are flagged until a refresh succeeds');
	assert(stalePage.instance.lookup('00:11:22:33:44:55').title.includes('缓存已过期'));

	const resident = resolver({cache: cache(day), request: () => Promise.reject(new Error('offline'))});
	await resident.instance.load();
	resident.advance(7 * day);
	assert(resident.instance.needsLoad(), 'an open page ages its in-memory cache');
	assert(resident.instance.lookup('00:11:22:33:44:55').stale);
	await resident.instance.load();
	resident.advance(31 * day);
	assert.strictEqual(resident.instance.lookup('00:11:22:33:44:55').vendor, '', 'expired memory is no longer trusted');
	const reversed = resolver({cache: cache(day)});
	await reversed.instance.load();
	reversed.advance(-2 * day);
	assert(reversed.instance.needsLoad(), 'clock rollback invalidates freshness');
	assert.strictEqual(reversed.instance.lookup('00:11:22:33:44:55').vendor, '');
	for (const badText of ['00:11:22\tApple\tApple Inc.\n', databaseText.slice(0, -1)]) {
		const partial = resolver({request: () => Promise.resolve({ok:true,text: () => badText})});
		await partial.instance.load();
		assert.strictEqual(partial.saved(), null);
		assert.strictEqual(partial.instance.lookup('00:11:22:33:44:55').label, '厂商查询失败');
	}
	for (const [raw, expected] of [
		['Apple, Inc.', '苹果'], [' ASUSTek COMPUTER INC. ', '华硕'],
		['Intel Corporation', '英特尔'], ['Intel Corporate', '英特尔'],
		['Tp-Link Technologies Co.,Ltd.', '普联'], ['Realtek Semiconductor Corp.', '瑞昱'],
		['Broadcom Limited', '博通'], ['Hewlett-Packard', '惠普'],
		['MediaTek Inc', '联发科'], ['Samsung Electronics. Co. LTD', '三星'],
		['QUALCOMM Incorporated', '高通'], ['Huawei Device Co., Ltd.', '华为'],
		['Dell Inc.', '戴尔'], ['Lenovo (Beijing) Limited.', '联想'],
		['Sony Corporation', '索尼'], ['Cisco Systems, Inc', '思科'],
		['Xiaomi Communications Co Ltd', '小米']
	]) assert.strictEqual(names.resolve(raw)?.label, expected, raw);
	for (const raw of ['Pineapple Networks', 'Apple Tree Inc.', 'Cisco-Linksys, LLC',
		'DellKing Industrial Co., Ltd', 'Intelbras', 'Huawei Symantec Technologies Co.,Ltd.',
		'Jiangsu Ruichi Broadcom Communications Technoligy Co., Ltd.', '', null, {}, '<img>'])
		assert.strictEqual(names.resolve(raw), null, 'never infer a brand from ' + String(raw));
	// Real icon matching shares exactly the same identity rules as text mapping.
	const logo = vm.compileFunction(fs.readFileSync(path.join(moduleDir, 'vendorLogo.js'), 'utf8'),
		['baseclass', 'vendorNames'])({extend: value => value}, names);
	assert(logo.brand('Apple, Inc.'));
	assert.strictEqual(logo.brand('Apple Tree Inc.'), null);
	assert.strictEqual(logo.brand('Cisco-Linksys, LLC'), null);
	for (const [raw, expected] of [ ['Midea Group Co., Ltd.', '美的'],
		['GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD', 'OPPO'],
		["Micro-Star INT'L CO., LTD.", '微星'],
		['OnePlus Technology (Shenzhen) Co., Ltd', '一加'],
		['Brother Industries, LTD.', '兄弟'], ['Seiko Epson Corporation', '爱普生'] ])
		assert.strictEqual(names.resolve(raw)?.label, expected);
	for (const raw of ['Brother, Brother & Sons ApS', 'Amazon Robotics MTAC Matrix NPI',
		'LG Chem', 'OPPO Digital, Inc.', 'Sharp Software Services'])
		assert.strictEqual(names.resolve(raw), null, 'related words must not identify a brand');
	assert(logo.brand('OnePlus Technology (Shenzhen) Co., Ltd'));
	assert(logo.brand('Seiko Epson Corporation'));
	assert.strictEqual(logo.brand('SHARP CORPORATION'), null, 'the sharp image-processing software logo is not Sharp Electronics');


	// Optional verification against a downloaded complete upstream export.
	if (process.env.LANSPEED_OUI_DATABASE) {
		const text = fs.readFileSync(process.env.LANSPEED_OUI_DATABASE, 'utf8');
		const real = resolver({ request: () => Promise.resolve({ ok: true, text: () => text }) });
		await real.instance.load();
		assert.strictEqual(real.instance.lookup('00:00:0c:00:00:01').kind, 'vendor');
		assert(/Cisco/i.test(real.instance.lookup('00:00:0c:00:00:01').vendor));
	}
	if (process.env.LANSPEED_IEEE_DATABASE_DIR) {
		const real = resolver({vendorDatabase: db, request: url => {
			const spec = db.sources.find(s => s.urls.includes(url));
			const file = spec.id === 'wireshark' ? process.env.LANSPEED_OUI_DATABASE :
				path.join(process.env.LANSPEED_IEEE_DATABASE_DIR, spec.id + '.csv');
			return Promise.resolve({ok: true, text: () => fs.readFileSync(file, 'utf8')});
		}});
		await real.instance.load();
		assert(real.instance.sourceStatus().every(s => s.fresh && s.entries > 1000));
		assert.strictEqual(real.instance.lookup('08:00:30:00:00:01').kind, 'ambiguous');
		assert.strictEqual(real.instance.lookup('00:01:c8:00:00:01').kind, 'ambiguous');
		assert.strictEqual(real.instance.lookup('00:00:0c:00:00:01').label, '思科');
		const restored = resolver({vendorDatabase: db, cache: real.saved()});
		await restored.instance.load();
		assert.strictEqual(restored.requests(), 0);
		assert.strictEqual(restored.instance.lookup('08:00:30:00:00:01').kind, 'ambiguous');
		assert(real.saved().length * 2 < 5 * 1024 * 1024, 'merged cache should fit a normal 5 MiB quota');
		console.log('  real registries: ' + JSON.stringify(real.instance.sourceStatus()) + ', cache characters=' + real.saved().length);
	}
	console.log('validate-lanspeed-mac-vendor: PASS');
	console.log('  multi-source merge, provenance, longest prefix, CSV parsing, ambiguity, cache, fallback, recovery');
}

main().catch(error => {
	console.error('validate-lanspeed-mac-vendor: FAIL\n' + error.stack);
	process.exitCode = 1;
});
