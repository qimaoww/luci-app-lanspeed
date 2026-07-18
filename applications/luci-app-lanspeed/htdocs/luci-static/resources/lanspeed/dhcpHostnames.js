'use strict';
'require baseclass';
'require uci';
'require lanspeed.rpc as lsRpc';

/* Read and edit one native ImmortalWrt DHCP host entry.  The editor owns only
 * `mac` and `name`; an existing host section's ip and other options remain
 * untouched. */

var MAC_PATTERN = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
var HOSTNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

function stringValue(value) {
	return value === null || value === undefined ? '' : String(value);
}

function normalizeMac(value) {
	var mac = stringValue(value).trim().toLowerCase();
	return MAC_PATTERN.test(mac) ? mac : '';
}

function normalizeMacs(value) {
	var values = Array.isArray(value) ? value : stringValue(value).split(/[\s,]+/);
	return values.map(normalizeMac).filter(function(mac) { return mac; });
}

function normalizeName(value) {
	var name = stringValue(value).trim();
	if (!name) return '';
	if (!HOSTNAME_PATTERN.test(name))
		throw new Error(_('主机名只能使用字母、数字、点、下划线和连字符，最长 63 个字符，且必须以字母或数字开头。'));
	return name;
}

function identityMac(identityKey) {
	var value = stringValue(identityKey).split('@')[0];
	return normalizeMac(value);
}

function hostSections() {
	var sections;
	try {
		sections = uci.sections('dhcp', 'host') || [];
	} catch (error) {
		sections = [];
	}
	return sections.map(function(section) {
		var macs = normalizeMacs(section.mac);
		return {
			section: stringValue(section['.name']),
			mac: macs[0] || '',
			macs: macs,
			name: stringValue(section.name).trim(),
			ip: stringValue(section.ip).trim()
		};
	}).filter(function(host) {
		return host.section;
	});
}

function loadForMac(mac) {
	var normalized = normalizeMac(mac);
	if (!normalized)
		return Promise.resolve({ available: false, mac: '', host: null });
	return uci.load('dhcp').then(function() {
		var hosts = hostSections();
		var host = hosts.filter(function(entry) {
			return entry.macs.indexOf(normalized) !== -1;
		})[0] || null;
		return { available: true, mac: normalized, host: host };
	}).catch(function(error) {
		return { available: false, mac: normalized, host: null, error: error };
	});
}

function addedSection(result) {
	if (result && typeof result === 'object' && result.section)
		return String(result.section);
	return stringValue(result);
}

function saveForMac(mac, name) {
	var normalized = normalizeMac(mac);
	if (!normalized)
		return Promise.reject(new Error(_('无法确定客户端 MAC 地址。')));
	var normalizedName;
	try {
		normalizedName = normalizeName(name);
	} catch (error) {
		return Promise.reject(error);
	}

	return loadForMac(normalized).then(function(data) {
		if (!data.available)
			throw data.error || new Error(_('无法读取 /etc/config/dhcp。'));
		var host = data.host;
		if (!host && !normalizedName)
			return { changed: false, name: '' };
		if (!host) {
			return lsRpc.uciAdd('dhcp', 'host').then(function(result) {
				var section = addedSection(result);
				if (!section)
					throw new Error(_('无法创建 DHCP 主机条目。'));
				return lsRpc.uciSet('dhcp', section, {
					mac: normalized,
					name: normalizedName
				}).then(function() {
					return { changed: true, name: normalizedName, section: section };
				});
			});
		}

		var values = {};
		if (normalizedName) values.name = normalizedName;
		var pending = Object.keys(values).length
			? lsRpc.uciSet('dhcp', host.section, values)
			: Promise.resolve();
		if (!normalizedName && host.name) {
			pending = pending.then(function() {
				return lsRpc.uciDelete('dhcp', host.section, [ 'name' ]);
			});
		}
		return pending.then(function() {
			return { changed: host.macs.indexOf(normalized) === -1 || host.name !== normalizedName,
				name: normalizedName, section: host.section };
		});
	});
}

return baseclass.extend({
	identityMac: identityMac,
	loadForMac: loadForMac,
	saveForMac: saveForMac,
	normalizeMac: normalizeMac,
	normalizeName: normalizeName
});
