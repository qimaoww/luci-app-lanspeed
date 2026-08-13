'use strict';
'require baseclass';

function boundedText(value, limit) {
	var text = String(value == null ? '' : value);
	return text.length > limit ? text.slice(0, limit) + '…' : text;
}

function redactAssignment(match) {
	var separator = match.search(/[:=]/);
	return separator < 0 ? '[REDACTED]' : match.slice(0, separator) + match.charAt(separator) + '[REDACTED]';
}

function redactSensitiveAssignments(text) {
	var keys = '(?:authorization|auth(?:[_-]?token)?|access[_-]?token|api[_-]?key|apikey|token|password|passwd|passphrase|secret(?:[_-]?key)?|private[_-]?key|public[_-]?key|refresh[_-]?token|csrf[_-]?token|jwt|nonce|session(?:[_-]?id)?|sid|cookie|set-cookie|sysauth|ubus[_-]?rpc[_-]?session|host(?:name)?|remote[_-]?(?:host|ip|address)|domain|client(?:[_-]?(?:name|id|identity|token|ip|mac|host))?|device(?:[_-]?(?:name|id))?|identity(?:[_-]?(?:key|name|id))?|user(?:[_-]?(?:name|id))?|interface(?:[_-]?(?:name|source|id))?|probe(?:[_-]?(?:name|source|id))?|command|cmd|file|path|source|ssid|mac|ip(?:v4|v6)?|address|credential(?:s)?)';
	var quoted = new RegExp('(["\\\']?)\\b' + keys + '\\b\\1\\s*[:=]\\s*(?:"(?:\\\\.|[^"\\\\])*"|\\\'(?:\\\\.|[^\\\'\\\\])*\\\')', 'gi');
	var unquoted = new RegExp('(["\\\']?)\\b' + keys + '\\b\\1\\s*[:=]\\s*[^,;}&\\n]*?(?=\\s*(?:[,;}&\\n]|$)|\\s+["\\\']?[a-z][a-z0-9_.-]*["\\\']?\\s*[:=](?![=]))', 'gi');
	return text.replace(quoted, redactAssignment).replace(unquoted, redactAssignment);
}

function validIpv4(value) {
	var parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(function(part) {
		return /^\d{1,3}$/.test(part) && Number(part) <= 255;
	});
}

function validIpv6(value) {
	var address = String(value || '').toLowerCase().replace(/%[a-z0-9_.-]+$/, ''),
		ipv4Index = address.lastIndexOf(':'),
		ipv4 = address.indexOf('.') !== -1 ? address.slice(ipv4Index + 1) : '';
	if (ipv4) {
		if (ipv4Index < 0 || !validIpv4(ipv4)) return false;
		address = address.slice(0, ipv4Index) + ':v4';
	}
	if (address.indexOf(':::') !== -1 || address.indexOf('::') !== address.lastIndexOf('::')) return false;
	var compressed = address.indexOf('::') !== -1,
		halves = compressed ? address.split('::') : [ address, '' ], groups = [];
	halves.forEach(function(half) { if (half) groups = groups.concat(half.split(':')); });
	var count = 0;
	for (var i = 0; i < groups.length; i++) {
		if (groups[i] === 'v4') count += 2;
		else if (/^[0-9a-f]{1,4}$/.test(groups[i])) count++;
		else return false;
	}
	return compressed ? count < 8 : count === 8;
}

function redactIpv6(text) {
	text = text.replace(/\[([0-9a-f:.]+(?:%[a-z0-9_.-]+)?)\](?::\d{1,5})?/gi, function(match, address) {
		return validIpv6(address) ? '[IP]' : match;
	});
	return text.replace(/(^|[^0-9a-f:.])((?:[0-9a-f]{0,4}:){2,}(?:[0-9a-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})?(?:%[a-z0-9_.-]+)?)(?=$|[^0-9a-f:.]|\.(?!\d))/gi, function(match, prefix, address) {
		return validIpv6(address) ? prefix + '[IP]' : match;
	});
}

function sanitizeReportText(value) {
	var raw = String(value == null ? '' : value);
	if (/(?:^|\W)client_control(?:\W|$)/i.test(raw))
		return '[CLIENT CONTROL REDACTED]';
	var text = redactSensitiveAssignments(boundedText(raw, 480))
		.replace(/\b(?:command|file|uci|ubus|process|service|sysctl|probe):[^\s\u00b7,;)}\]]+/gi, '[SOURCE]')
		.replace(/(^|[\s("'=])\/(?:[^\s,;)}\]]+)/g, '$1[PATH]')
		.replace(/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi, '[MAC]')
		.replace(/\b(?:[0-9a-f]{2}[:-]){7}[0-9a-f]{2}\b/gi, '[MAC]')
		.replace(/\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b/gi, '[MAC]')
		.replace(/\b[0-9a-f]{12}\b/gi, '[MAC]')
		.replace(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b/gi, '[IDENTITY]');
	return redactIpv6(text).replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP]')
		.replace(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi, '[HOST]');
}

return baseclass.extend({
	boundedText: boundedText,
	sanitizeReportText: sanitizeReportText
});
