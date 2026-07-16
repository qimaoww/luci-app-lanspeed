'use strict';
'require baseclass';
'require lanspeed.format as fmt';

function identityFromSearch(search) {
	var query = search === null || search === undefined ? '' : String(search);
	var hashAt = query.indexOf('#');
	if (hashAt !== -1)
		query = query.slice(0, hashAt);
	if (query.charAt(0) === '?')
		query = query.slice(1);

	var parts = query.split('&');
	for (var i = 0; i < parts.length; i++) {
		var equalsAt = parts[i].indexOf('=');
		var rawName = equalsAt === -1 ? parts[i] : parts[i].slice(0, equalsAt);
		var rawValue = equalsAt === -1 ? '' : parts[i].slice(equalsAt + 1);
		var name;
		try {
			name = decodeURIComponent(rawName.replace(/\+/g, ' '));
		} catch (e) {
			continue;
		}
		if (name !== 'client')
			continue;
		try {
			return decodeURIComponent(rawValue.replace(/\+/g, ' '));
		} catch (e) {
			return '';
		}
	}
	return '';
}

function detailHref(basePath, identity) {
	var href = basePath === null || basePath === undefined ? '' : String(basePath);
	var hashAt = href.indexOf('#');
	var hash = hashAt === -1 ? '' : href.slice(hashAt);
	var path = hashAt === -1 ? href : href.slice(0, hashAt);
	var separator = path.indexOf('?') === -1 ? '?' : /[?&]$/.test(path) ? '' : '&';
	var value = identity === null || identity === undefined ? '' : String(identity);
	return path + separator + 'client=' + encodeURIComponent(value) + hash;
}

function formatEndpoint(ip, port) {
	var host = ip === null || ip === undefined ? '' : String(ip);
	if (host.indexOf(':') !== -1 &&
	    !(host.charAt(0) === '[' && host.charAt(host.length - 1) === ']')) {
		host = '[' + host + ']';
	}
	if (port === null || port === undefined || port === '')
		return host;
	return host + ':' + String(port);
}

function portSummary(ports) {
	var values = fmt.asArray(ports);
	if (!values.length)
		return '-';
	var label = values.slice(0, 3).map(function(port) {
		return String(port);
	}).join(', ');
	if (values.length > 3)
		label += '，另有 ' + (values.length - 3) + ' 个';
	return label;
}

function stateLabel(connections) {
	var values = fmt.asArray(connections);
	if (!values.length)
		return '-';
	var states = values.map(function(conn) {
		return String(conn && conn.state || '').toLowerCase();
	});
	if (states.every(function(state) { return state === 'established'; }))
		return '已建立';
	if (states.every(function(state) { return state === 'assured'; }))
		return '活跃';
	return '混合';
}

function protocolLabel(connections) {
	var hasTcp = false;
	var hasUdp = false;
	fmt.asArray(connections).forEach(function(conn) {
		var protocol = String(conn && conn.protocol || '').toLowerCase();
		if (protocol === 'tcp') hasTcp = true;
		if (protocol === 'udp') hasUdp = true;
	});
	if (hasTcp && hasUdp) return 'TCP/UDP';
	if (hasTcp) return 'TCP';
	if (hasUdp) return 'UDP';
	return '-';
}

function portsForConnections(connections) {
	var seen = Object.create(null);
	var ports = [];
	fmt.asArray(connections).forEach(function(conn) {
		var value = conn && conn.remote_port;
		if (value === null || value === undefined || value === '')
			return;
		var port = Number(value);
		if (!isFinite(port) || Math.floor(port) !== port)
			return;
		var key = String(port);
		if (seen[key])
			return;
		seen[key] = true;
		ports.push(port);
	});
	ports.sort(function(a, b) { return a - b; });
	return ports;
}

function matchesSearch(conn, term) {
	return [
		conn && conn.remote_ip,
		conn && conn.client_ip,
		conn && conn.remote_port,
		conn && conn.client_port
	].some(function(value) {
		if (value === null || value === undefined)
			return false;
		return String(value).toLowerCase().indexOf(term) !== -1;
	});
}

function groupsForResponse(response, protocol, search) {
	var wanted = protocol === null || protocol === undefined
		? 'all'
		: String(protocol).toLowerCase();
	if (wanted !== 'tcp' && wanted !== 'udp')
		wanted = 'all';

	var filtered = fmt.asArray(response && response.connections).filter(function(conn) {
		return wanted === 'all' ||
			String(conn && conn.protocol || '').toLowerCase() === wanted;
	});
	var term = search === null || search === undefined
		? ''
		: String(search).trim().toLowerCase();
	if (term) {
		filtered = filtered.filter(function(conn) {
			return matchesSearch(conn, term);
		});
	}

	var groups = [];
	var byRemoteIp = Object.create(null);
	filtered.forEach(function(conn) {
		var remoteIp = conn && conn.remote_ip !== null && conn.remote_ip !== undefined
			? String(conn.remote_ip)
			: '';
		var group = byRemoteIp[remoteIp];
		if (!group) {
			group = {
				remoteIp: remoteIp,
				ports: [],
				portLabel: '',
				protocolLabel: '',
				stateLabel: '',
				count: 0,
				connections: []
			};
			byRemoteIp[remoteIp] = group;
			groups.push(group);
		}
		group.connections.push(conn);
	});

	groups.forEach(function(group) {
		group.ports = portsForConnections(group.connections);
		group.portLabel = portSummary(group.ports);
		group.protocolLabel = protocolLabel(group.connections);
		group.stateLabel = stateLabel(group.connections);
		group.count = group.connections.length;
	});
	return groups;
}

return baseclass.extend({
	identityFromSearch: identityFromSearch,
	detailHref: detailHref,
	formatEndpoint: formatEndpoint,
	groupsForResponse: groupsForResponse,
	portSummary: portSummary,
	stateLabel: stateLabel
});
