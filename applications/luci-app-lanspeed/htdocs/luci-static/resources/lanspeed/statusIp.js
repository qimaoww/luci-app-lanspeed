'use strict';
'require baseclass';
'require lanspeed.format as fmt';

var DEFAULT_HIDE_IPV6_RANGES = 'fc00::/7 fe80::/10';

function isIpv6Address(ip) {
	return String(ip || '').indexOf(':') >= 0;
}

function parseIpv6ToWords(ip) {
	var s = String(ip || '').toLowerCase();
	var zone = s.indexOf('%');
	var parts, head, tail, missing, words = [];
	var i, n;

	if (zone >= 0)
		s = s.slice(0, zone);

	if (s.charAt(0) === '[' && s.charAt(s.length - 1) === ']')
		s = s.slice(1, -1);

	if (!s || s.indexOf(':') < 0)
		return null;

	if (s.indexOf('.') >= 0)
		return null;

	parts = s.split('::');
	if (parts.length > 2)
		return null;

	head = parts[0] ? parts[0].split(':') : [];
	tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
	missing = 8 - head.length - tail.length;
	if (parts.length === 1)
		missing = 0;
	if (missing < 0)
		return null;

	for (i = 0; i < head.length; i++) {
		if (!/^[0-9a-f]{1,4}$/.test(head[i]))
			return null;
		n = parseInt(head[i], 16);
		if (isNaN(n) || n < 0 || n > 0xffff)
			return null;
		words.push(n);
	}
	for (i = 0; i < missing; i++)
		words.push(0);
	for (i = 0; i < tail.length; i++) {
		if (!/^[0-9a-f]{1,4}$/.test(tail[i]))
			return null;
		n = parseInt(tail[i], 16);
		if (isNaN(n) || n < 0 || n > 0xffff)
			return null;
		words.push(n);
	}

	return words.length === 8 ? words : null;
}

function parseIpv6Cidr(range) {
	var parts = String(range || '').trim().split('/');
	var prefix = parts[0];
	var bits = parts.length > 1 ? parseInt(parts[1], 10) : 128;
	var words = parseIpv6ToWords(prefix);

	if (!words || isNaN(bits) || bits < 0 || bits > 128)
		return null;

	return { words: words, bits: bits };
}

function parseIpv6Ranges(ranges) {
	return String(ranges).split(/[,\s]+/).map(parseIpv6Cidr).filter(function(r) {
		return !!r;
	});
}

function hideIpv6RangesValue(value) {
	return typeof value === 'string' ? value : DEFAULT_HIDE_IPV6_RANGES;
}

function isIpInIpv6Ranges(ip, ranges) {
	var words = parseIpv6ToWords(ip);
	var parsed = parseIpv6Ranges(ranges);
	var i, wordIndex, remaining, mask;

	if (!words)
		return false;

	for (i = 0; i < parsed.length; i++) {
		wordIndex = 0;
		remaining = parsed[i].bits;
		while (remaining > 0) {
			if (remaining >= 16) {
				if (words[wordIndex] !== parsed[i].words[wordIndex])
					break;
			} else {
				mask = (0xffff << (16 - remaining)) & 0xffff;
				if ((words[wordIndex] & mask) !== (parsed[i].words[wordIndex] & mask))
					break;
			}
			wordIndex++;
			remaining -= 16;
		}
		if (remaining <= 0)
			return true;
	}

	return false;
}

function displayIpsForClient(ips, showIpv6, hidePrivateIpv6, hideIpv6Ranges) {
	return fmt.asArray(ips).filter(function(ip) {
		if (hidePrivateIpv6 && isIpInIpv6Ranges(ip, hideIpv6Ranges))
			return false;
		return showIpv6 || !isIpv6Address(ip);
	});
}

return baseclass.extend({
	DEFAULT_HIDE_IPV6_RANGES: DEFAULT_HIDE_IPV6_RANGES,

	hideIpv6RangesValue: function(value) {
		return hideIpv6RangesValue(value);
	},

	displayIpsForClient: function(ips, showIpv6, hidePrivateIpv6, hideIpv6Ranges) {
		return displayIpsForClient(ips, showIpv6, hidePrivateIpv6, hideIpv6Ranges);
		}
});
