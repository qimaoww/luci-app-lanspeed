#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const evidenceDir = path.join(root, '.sisyphus', 'evidence');

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), 'utf8'));
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function normalizeMac(mac) {
  assert(typeof mac === 'string', 'MAC must be a string');
  return mac.toLowerCase();
}

function identityKey(mac, zone) {
  return `${normalizeMac(mac)}@${zone}`;
}

function isBroadcast(mac) {
  return normalizeMac(mac) === 'ff:ff:ff:ff:ff:ff';
}

function isMulticast(mac) {
  if (isBroadcast(mac)) {
    return false;
  }
  const firstOctet = Number.parseInt(normalizeMac(mac).slice(0, 2), 16);
  return (firstOctet & 1) === 1;
}

function isExcludedTraffic(entry, routerMacs) {
  const mac = normalizeMac(entry.mac);
  return routerMacs.has(mac) || isBroadcast(mac) || isMulticast(mac) || ['arp', 'nd', 'broadcast', 'multicast', 'router_mac'].includes(entry.frame_type);
}

function ensureClient(clients, source) {
  const zone = source.zone || 'lan';
  const key = identityKey(source.mac, zone);
  if (!clients.has(key)) {
    clients.set(key, {
      mac: normalizeMac(source.mac),
      identity_key: key,
      zone,
      interface: source.interface || 'unknown',
      ips: [],
      hostname: null,
      rx_bps: 0,
      tx_bps: 0,
      last_seen: 0,
      collector_mode: 'identity_fixture',
      confidence: 'medium',
      warnings: []
    });
  }
  return clients.get(key);
}

function attachAddress(client, ip) {
  if (ip && !client.ips.includes(ip)) {
    client.ips.push(ip);
  }
}

function mergeTimedFields(client, source) {
  if (source.hostname !== undefined && source.hostname !== null && source.hostname !== '') {
    client.hostname = source.hostname;
  }
  if (source.interface) {
    client.interface = source.interface;
  }
  if (Number.isInteger(source.last_seen) && source.last_seen > client.last_seen) {
    client.last_seen = source.last_seen;
  }
}

function buildClients(fixture) {
  const clients = new Map();
  const routerMacs = new Set((fixture.router.macs || []).map(normalizeMac));
  const debugCounters = {
    broadcast_bps: 0,
    multicast_bps: 0,
    arp_bps: 0,
    nd_bps: 0
  };

  for (const source of fixture.sources.netifd || []) {
    if (source.role === 'router' && source.mac) {
      routerMacs.add(normalizeMac(source.mac));
    }
  }

  for (const source of fixture.sources.dhcp_leases || []) {
    if (routerMacs.has(normalizeMac(source.mac))) {
      continue;
    }
    const client = ensureClient(clients, source);
    attachAddress(client, source.ip);
    mergeTimedFields(client, source);
  }

  for (const source of fixture.sources.neighbors || []) {
    if (routerMacs.has(normalizeMac(source.mac)) || source.role === 'router') {
      continue;
    }
    const client = ensureClient(clients, source);
    attachAddress(client, source.ip);
    mergeTimedFields(client, source);
  }

  for (const source of fixture.sources.wireless || []) {
    if (routerMacs.has(normalizeMac(source.mac))) {
      continue;
    }
    mergeTimedFields(ensureClient(clients, source), source);
  }

  for (const entry of fixture.sources.traffic || []) {
    if (entry.frame_type === 'broadcast' || isBroadcast(entry.mac)) {
      debugCounters.broadcast_bps += entry.client_originated_bps || 0;
    }
    if (entry.frame_type === 'multicast' || isMulticast(entry.mac)) {
      debugCounters.multicast_bps += entry.client_originated_bps || 0;
    }
    if (entry.frame_type === 'arp') {
      debugCounters.arp_bps += entry.client_originated_bps || 0;
    }
    if (entry.frame_type === 'nd') {
      debugCounters.nd_bps += entry.client_originated_bps || 0;
    }
    if (isExcludedTraffic(entry, routerMacs)) {
      continue;
    }

    const client = ensureClient(clients, entry);
    client.tx_bps += entry.client_originated_bps || 0;
    client.rx_bps += entry.to_client_bps || 0;
    assert(!entry.remote_ip || !client.ips.includes(entry.remote_ip), 'fake-ip or remote destinations must not become client identity IPs');
  }

  const result = Array.from(clients.values()).sort((left, right) => left.identity_key.localeCompare(right.identity_key));
  for (const client of result) {
    client.ips.sort();
  }
  return {
    clients: result,
    debug_counters: debugCounters,
    evidence: {
      source: 'lanspeedd_identity_fixture',
      identity_primary_key: 'mac+zone',
      sources: ['dhcp_lease', 'arp_nd_neighbor', 'hostapd_nl80211', 'netifd_ubus'],
      source_priority: ['netifd_ubus_router_exclusions', 'dhcp_lease_hostname_ipv4', 'arp_nd_neighbor_ip_liveness', 'hostapd_nl80211_attachment'],
      direction: {
        tx_bps: 'client-originated traffic from the client point of view',
        rx_bps: 'traffic to client from the client point of view'
      },
      excluded_from_clients: ['router_mac', 'broadcast', 'multicast', 'arp', 'nd'],
      fake_ip_identity: 'remote fake-ip destinations are not client identity keys'
    }
  };
}

function assertClientShape(client, pathName) {
  for (const field of ['mac', 'identity_key', 'zone', 'interface', 'ips', 'hostname', 'rx_bps', 'tx_bps', 'last_seen', 'collector_mode', 'confidence', 'warnings']) {
    assert(Object.prototype.hasOwnProperty.call(client, field), `${pathName}.${field} is required`);
  }
  assert(client.identity_key === `${client.mac}@${client.zone}`, `${pathName}.identity_key must be normalized MAC plus zone`);
  assert(Array.isArray(client.ips) && client.ips.length > 0, `${pathName}.ips must include observed addresses`);
  assert(typeof client.hostname === 'string' || client.hostname === null, `${pathName}.hostname must be string or null`);
  assert(Number.isInteger(client.rx_bps) && Number.isInteger(client.tx_bps), `${pathName} rates must be integer bps`);
}

function assertClientsEqual(actual, expected, scenarioName) {
  assert(JSON.stringify(actual.clients) === JSON.stringify(expected.clients), `${scenarioName} clients did not match expected identity merge`);
  for (const [index, client] of actual.clients.entries()) {
    assertClientShape(client, `${scenarioName}.clients[${index}]`);
  }
}

function writeEvidence(fileName, payload) {
  fs.writeFileSync(path.join(evidenceDir, fileName), `${JSON.stringify(payload, null, 2)}\n`);
}

fs.mkdirSync(evidenceDir, { recursive: true });

const multiIpFixture = readJson('tests/fixtures/lanspeed-identity-multi-ip.json');
const routerExcludedFixture = readJson('tests/fixtures/lanspeed-identity-router-mac-excluded.json');
const controlExcludedFixture = readJson('tests/fixtures/lanspeed-identity-excluded-control.json');

const multiIp = buildClients(multiIpFixture);
const routerExcluded = buildClients(routerExcludedFixture);
const controlExcluded = buildClients(controlExcludedFixture);

assertClientsEqual(multiIp, multiIpFixture.expected, multiIpFixture.name);
assert(multiIp.clients.length === 1, 'multi-ip fixture must merge IPv4 and IPv6 into one client');
assert(multiIp.clients[0].ips.includes('192.168.1.42') && multiIp.clients[0].ips.includes('fd00::42'), 'multi-ip client must contain both IPv4 and IPv6 addresses');
assert(multiIp.clients[0].tx_bps === 1200 && multiIp.clients[0].rx_bps === 3400, 'direction semantics must be client tx/rx perspective');

assertClientsEqual(routerExcluded, routerExcludedFixture.expected, routerExcludedFixture.name);
assert(routerExcluded.clients.length === 1, 'router MAC fixture must return only the real client');
assert(routerExcludedFixture.sources.dhcp_leases.length === 0, 'static IP fixture must not rely on a DHCP lease hostname source');
assert(routerExcluded.clients[0].hostname === null, 'static IP without hostname must remain visible with hostname null');
assert(!routerExcluded.clients.some((client) => client.mac === 'aa:bb:cc:00:00:01'), 'router bridge MAC must not appear in clients[]');

assertClientsEqual(controlExcluded, controlExcludedFixture.expected, controlExcludedFixture.name);
assert(JSON.stringify(controlExcluded.debug_counters) === JSON.stringify(controlExcludedFixture.expected.debug_counters), 'broadcast/multicast/ARP/ND must only appear in debug counters');
assert(controlExcluded.clients[0].tx_bps === 7000 && controlExcluded.clients[0].rx_bps === 9000, 'control frames must not inflate client rates');

writeEvidence('task-5-multi-ip.json', multiIp);
writeEvidence('task-5-router-mac-excluded.json', routerExcluded);

console.log('lanspeed identity validation passed');
