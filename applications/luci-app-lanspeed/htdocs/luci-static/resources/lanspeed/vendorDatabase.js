'use strict';
'require baseclass';

/* Registry snapshots only, never per-device APIs. IEEE is authoritative, but
 * its public endpoint is not consistently accessible with browser CORS.
 * runZero data/ieee contains current IEEE CSVs, not its historical/VM tables.
 * https://github.com/runZeroInc/mac-tracker#updates
 * https://www.wireshark.org/download/automated/data/manuf */
var DAY = 24 * 60 * 60 * 1000;
var SOURCES = [ {
	id: 'wireshark', code: 'w', label: 'Wireshark', ttl: 7 * DAY, rank: 1,
	urls: [ 'https://www.wireshark.org/download/automated/data/manuf' ],
	format: 'manuf', minimum: 30000
} ];
[ [ 'oui', 'MA-L', 24, 30000 ], [ 'mam', 'MA-M', 28, 2000 ],
  [ 'oui36', 'MA-S', 36, 2000 ], [ 'iab', 'IAB', 36, 3000 ] ].forEach(function(spec) {
	var path = { oui: 'oui', mam: 'oui28', oui36: 'oui36', iab: 'iab' }[spec[0]];
	SOURCES.push({
		id: spec[0], code: String(SOURCES.length), label: 'IEEE ' + spec[1], ttl: DAY, rank: 2,
		urls: [ 'https://raw.githubusercontent.com/runZeroInc/mac-tracker/main/data/ieee/' + spec[0] + '.csv',
			'https://standards-oui.ieee.org/' + path + '/' + spec[0] + '.csv' ],
		format: 'csv', registry: spec[1], bits: spec[2], minimum: spec[3]
	});
});

/* RFC 4180 quotes, embedded newlines and escaped quotes. Reject truncated
 * quotes, unexpected columns and HTML/error documents. */
function csvRows(text) {
	var rows = [], row = [], value = '', quoted = false, closed = false;
	for (var i = 0; i < text.length; i++) {
		var c = text.charAt(i);
		if (quoted) {
			if (c === '"') {
				if (text.charAt(i + 1) === '"') { value += '"'; i++; }
				else { quoted = false; closed = true; }
			} else value += c;
		} else if (c === '"') {
			if (value || closed) throw new Error('Invalid CSV quoting');
			quoted = true;
		} else if (c === ',' || c === '\n') {
			row.push(value.replace(/\r$/, '')); value = ''; closed = false;
			if (c === '\n') { rows.push(row); row = []; }
		} else {
			if (closed && c !== '\r') throw new Error('Invalid CSV delimiter');
			value += c;
		}
	}
	if (quoted || row.length || value) throw new Error('Truncated CSV');
	return rows;
}

function parse(text, source) {
	if (typeof text !== 'string' || text.length > 16000000 || !/\n\s*$/.test(text))
		throw new Error('Incomplete registry export');
	var entries = [], seen = Object.create(null), counts = 0, ambiguous = Object.create(null);
	function add(prefix, bits, name) {
		name = name.trim(); prefix = prefix.toLowerCase();
		if (!/^[0-9a-f]+$/.test(prefix) || prefix.length !== bits / 4 ||
		    !name || name.length > 512 || /[\x00-\x1f\x7f]/.test(name))
			throw new Error('Invalid registry entry');
		var key = bits + ':' + prefix;
		if (seen[key] !== undefined) {
			// IEEE has a few historically shared OUIs. Do not choose a company.
			if (seen[key] !== name) {
				if (!ambiguous[prefix]) ambiguous[prefix] = [ seen[key] ];
				if (ambiguous[prefix].indexOf(name) === -1) ambiguous[prefix].push(name);
				seen[key] = null;
			}
			return;
		}
		seen[key] = name; counts++;
		/* RA parent allocations and Private are not manufacturers. */
		if (/^IEEE Registration Authority\b/i.test(name) || /^private$/i.test(name) ||
		    (parseInt(prefix.slice(0, 2), 16) & 3)) return;
		entries.push(prefix, bits, name);
	}
	if (source.format === 'csv') {
		var rows = csvRows(text.replace(/^\uFEFF/, ''));
		if (!rows.length || rows[0].join(',') !== 'Registry,Assignment,Organization Name,Organization Address')
			throw new Error('Invalid registry header');
		for (var i = 1; i < rows.length; i++) {
			var row = rows[i];
			if (row.length === 1 && !row[0]) continue;
			if (row.length !== 4 || row[0] !== source.registry) throw new Error('Wrong registry');
			add(row[1], source.bits, row[2]);
		}
	} else {
		text.split('\n').forEach(function(line) {
			if (!line.trim() || /^\s*#/.test(line)) return;
			var columns = line.split('\t');
			if (columns.length !== 3) throw new Error('Invalid manuf row');
			var raw = columns[0].trim(), match = raw.match(/^([0-9a-f:-]+)(?:\/(24|28|36))?$/i);
			if (!match) throw new Error('Invalid manuf prefix');
			var bits = Number(match[2] || 24), hex = match[1].replace(/[:-]/g, '');
			if (hex.length !== Math.ceil(bits / 8) * 2 || bits % 8 && hex.charAt(hex.length - 1) !== '0')
				throw new Error('Invalid manuf mask');
			add(hex.slice(0, bits / 4), bits, columns[2]);
		});
	}
	if (counts < source.minimum || !entries.length) throw new Error('Incomplete registry export');
	var result = [];
	for (var j = 0; j < entries.length; j += 3)
		if (seen[entries[j + 1] + ':' + entries[j]] !== null)
			result.push(entries[j], entries[j + 1], entries[j + 2]);
	if (Object.keys(ambiguous).length) result.ambiguous = ambiguous;
	return result;
}

return baseclass.extend({ sources: SOURCES, parse: parse });
