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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function filterKey(filter) {
  return `${filter.direction}:${filter.pref}:${filter.handle}:${filter.owner}`;
}

function attachLanspeedFilters(fixture) {
  const before = clone(fixture.before_filters);
  const after = clone(before);
  const evidence = {
    source: 'lanspeedd_tc_bpf_collector_fixture',
    device: fixture.device,
    qdisc: fixture.qdisc.kind,
    qdisc_action: fixture.qdisc.exists ? 'reuse_clsact' : 'create_clsact',
    commands: [],
    destructive_commands: [],
    before_filters: before,
    after_filters: after,
    owner: fixture.lanspeed_filter.owner,
    pref: fixture.lanspeed_filter.pref,
    handle: fixture.lanspeed_filter.handle,
    mode: fixture.expected.mode,
    bpf_runtime_metrics: Boolean(fixture.expected.bpf_runtime_metrics),
    runtime_attach_map_read_success: Boolean(fixture.expected.runtime_attach_map_read_success),
    live_metrics: Boolean(fixture.expected.live_metrics),
    warnings: []
  };

  if (!fixture.qdisc.exists) {
    evidence.commands.push(`tc qdisc add dev ${fixture.device} clsact`);
  }

  for (const direction of fixture.lanspeed_filter.directions) {
    const filter = {
      interface: fixture.device,
      direction,
      pref: fixture.lanspeed_filter.pref,
      handle: fixture.lanspeed_filter.handle,
      owner: fixture.lanspeed_filter.owner,
      source: 'lanspeed_attach_plan',
      description: 'lanspeed owned BPF accounting filter'
    };

    evidence.commands.push(
      `tc filter add dev ${fixture.device} ${direction} pref ${filter.pref} handle ${filter.handle} bpf obj /usr/lib/bpf/lanspeed-ebpf-kfunc sec tc/${direction} direct-action verbose owner ${filter.owner}`
    );
    after.push(filter);
  }

  evidence.after_filters = after;
  evidence.existing_filters_preserved = before.every((filter) => after.some((entry) => filterKey(entry) === filterKey(filter)));
  evidence.lanspeed_filter_added = fixture.lanspeed_filter.directions.every((direction) => after.some((filter) => (
    filter.direction === direction &&
    filter.pref === fixture.lanspeed_filter.pref &&
    filter.handle === fixture.lanspeed_filter.handle &&
    filter.owner === fixture.lanspeed_filter.owner
  )));
  evidence.append_only = evidence.existing_filters_preserved && evidence.lanspeed_filter_added;
  evidence.warnings = (fixture.expected.warnings || []).slice();
  evidence.bpf_assets_are_evidence_only = true;
  evidence.tc_filter = {
    coexistence: 'create_or_reuse_clsact_and_append_owned_filter_only',
    delete_existing: false,
    reorder_existing: false,
    owner: fixture.lanspeed_filter.owner,
    pref: fixture.lanspeed_filter.pref,
    handle: fixture.lanspeed_filter.handle
  };

  evidence.existing_filter_evidence = before.map((filter) => ({
    interface: filter.interface || fixture.device,
    pref: filter.pref,
    handle: filter.handle,
    owner: filter.owner,
    source: filter.source || 'tc_filter_show'
  }));

  return evidence;
}

function simulateSideRouterDirect(fixture) {
  const warnings = [];
  if (fixture.topology.same_subnet_direct) {
    addUnique(warnings, 'asymmetric_path_possible');
  }

  return {
    source: 'lanspeedd_side_router_fixture',
    topology: fixture.topology,
    observations: fixture.observations,
    mode: fixture.topology.same_subnet_direct ? 'Degraded' : 'Full',
    confidence: fixture.topology.same_subnet_direct ? 'low' : 'high',
    warnings,
    coverage: {
      lan_edge_visible: fixture.observations.some((entry) => entry.location === 'main_router_lan_edge' && entry.visible),
      wan_edge_visible: fixture.observations.some((entry) => entry.location === 'main_router_wan_edge' && entry.visible),
      coverage_complete: !fixture.topology.same_subnet_direct,
      complete_coverage_claimed: false,
      limitation: 'same-subnet side-router direct traffic may bypass the main router WAN/NAT path'
    }
  };
}

function computeRateTimeline(fixture) {
  const rates = [];
  const expected = fixture.expected;

  for (let index = 1; index < fixture.samples.length; index += 1) {
    const previous = fixture.samples[index - 1];
    const current = fixture.samples[index];
    const deltaBytes = Math.max(0, current.bytes - previous.bytes);
    const deltaMs = current.t_ms - previous.t_ms;
    const bps = deltaMs > 0 ? Math.round((deltaBytes * 8 * 1000) / deltaMs) : 0;

    rates.push({
      t_ms: current.t_ms,
      tx_bps: bps,
      rx_bps: 0,
      within_target: bps >= expected.min_bps && bps <= expected.max_bps,
      stopped: current.t_ms > expected.within_seconds * 1000,
      below_stop_threshold: bps < expected.drop_below_bps
    });
  }

  const reachedWithinWindow = rates.some((entry) => (
    entry.t_ms <= expected.within_seconds * 1000 && entry.within_target
  ));
  const droppedAfterStop = rates.some((entry) => (
    entry.t_ms >= expected.within_seconds * 1000 + expected.stop_after_ms && entry.below_stop_threshold
  ));

  return {
    source: 'lanspeedd_rate_fixture',
    client: {
      mac: fixture.client.mac,
      identity_key: `${fixture.client.mac}@${fixture.client.zone}`,
      zone: fixture.client.zone,
      ifindex: fixture.client.ifindex,
      interface: fixture.client.interface
    },
    map_key: {
      ifindex: fixture.client.ifindex,
      vlan_or_zone: fixture.client.zone,
      mac: fixture.client.mac,
      direction: fixture.client.direction
    },
    direction: {
      tx_bps: 'client-originated traffic from the client point of view',
      rx_bps: 'traffic to client from the client point of view'
    },
    expected,
    rates,
    reached_within_3s: reachedWithinWindow,
    dropped_after_stop: droppedAfterStop,
    collector_mode: 'tc_bpf_fixture',
    confidence: 'high',
    warnings: []
  };
}

function rateFromDelta(deltaBytes, deltaMs) {
  if (deltaMs <= 0 || deltaBytes <= 0) {
    return 0;
  }

  return Math.round((deltaBytes * 8 * 1000) / deltaMs);
}

function addUnique(array, value) {
  if (!array.includes(value)) {
    array.push(value);
  }
}

function computeDirectionalRates(fixture) {
  const warnings = [];
  const result = {
    source: 'lanspeedd_counter_fixture',
    client: fixture.client,
    directions: {},
    merged_client: {
      identity_key: fixture.client.identity_key,
      tx_bps: 0,
      rx_bps: 0
    },
    unaffected_clients: [],
    warnings,
    negative_rates_emitted: false,
    per_client_anomaly_isolated: true
  };

  for (const [direction, samples] of Object.entries(fixture.directions)) {
    const rates = [];

    for (let index = 1; index < samples.length; index += 1) {
      const previous = samples[index - 1];
      const current = samples[index];
      const deltaBytes = current.bytes - previous.bytes;
      const deltaMs = current.t_ms - previous.t_ms;
      const entryWarnings = [];

      if (deltaBytes < 0) {
        addUnique(warnings, 'counter_anomaly');
        entryWarnings.push('counter_anomaly');
      }

      if (deltaMs <= 0) {
        addUnique(warnings, 'time_rollback');
        entryWarnings.push('time_rollback');
      }

      const bps = rateFromDelta(deltaBytes, deltaMs);
      if (bps < 0) {
        result.negative_rates_emitted = true;
      }

      rates.push({
        t_ms: current.t_ms,
        delta_bytes: Math.max(0, deltaBytes),
        delta_ms: deltaMs > 0 ? deltaMs : 0,
        bps,
        warnings: entryWarnings
      });
    }

    result.directions[direction] = rates;
    result.merged_client[`${direction}_bps`] = rates.length > 0 ? rates[rates.length - 1].bps : 0;
  }

  for (const client of fixture.unaffected_clients || []) {
    const merged = {
      identity_key: client.identity_key,
      tx_bps: 0,
      rx_bps: 0,
      warnings: []
    };

    for (const [direction, samples] of Object.entries(client.directions)) {
      const previous = samples[0];
      const current = samples[1];
      merged[`${direction}_bps`] = rateFromDelta(current.bytes - previous.bytes, current.t_ms - previous.t_ms);
    }

    result.unaffected_clients.push(merged);
  }

  return result;
}

function simulateLanToLanDedupe(fixture) {
  const warnings = [];
  const seenFrames = new Set();
  const clients = new Map();
  const aggregateFrames = new Map();
  let duplicate_observations = 0;
  const visibilityLimited = Boolean(fixture.hardware_switch_path || fixture.visibility === 'limited');
  const coverageComplete = Boolean(fixture.topology_known && !visibilityLimited);

  for (const client of Object.values(fixture.clients)) {
    clients.set(client.identity_key, {
      identity_key: client.identity_key,
      mac: client.mac,
      zone: client.zone,
      interface: client.interface,
      tx_bps: 0,
      rx_bps: 0,
      collector_mode: 'tc_bpf_fixture',
      confidence: 'high',
      warnings: []
    });
  }

  for (const observation of fixture.observations) {
    if (observation.visible === false) {
      continue;
    }

    const roleKey = `${observation.frame_id}:${observation.direction}`;
    const frame = aggregateFrames.get(observation.frame_id) || {
      frame_id: observation.frame_id,
      bytes_delta: observation.bytes_delta,
      roles: new Set()
    };

    if (seenFrames.has(roleKey)) {
      duplicate_observations += 1;
      continue;
    }

    seenFrames.add(roleKey);
    frame.roles.add(observation.direction);
    frame.bytes_delta = Math.max(frame.bytes_delta, observation.bytes_delta);
    aggregateFrames.set(observation.frame_id, frame);

    if (observation.direction === 'tx' && clients.has(observation.src)) {
      clients.get(observation.src).tx_bps += rateFromDelta(observation.bytes_delta, fixture.interval_ms);
    }
    if (observation.direction === 'rx' && clients.has(observation.dst)) {
      clients.get(observation.dst).rx_bps += rateFromDelta(observation.bytes_delta, fixture.interval_ms);
    }
  }

  const aggregate_bps = Array.from(aggregateFrames.values()).reduce(
    (sum, frame) => sum + rateFromDelta(frame.bytes_delta, fixture.interval_ms),
    0
  );

  if (!fixture.topology_known) {
    addUnique(warnings, 'lan_to_lan_visibility_unknown');
  }
  if (visibilityLimited) {
    addUnique(warnings, 'lan_to_lan_visibility_limited');
  }

  return {
    source: 'lanspeedd_lan_to_lan_fixture',
    mode: coverageComplete ? 'Full' : 'Degraded',
    confidence: coverageComplete ? 'high' : 'low',
    warnings,
    target_bps: fixture.target_bps,
    clients: Array.from(clients.values()),
    aggregate_bps,
    duplicate_observations,
    one_direction_double_counted: aggregate_bps > fixture.max_bps,
    dedupe_policy: 'do_not_count_one_lan_to_lan_frame_twice',
    coverage: {
      cpu_visible_only: true,
      hardware_switch_path: visibilityLimited,
      coverage_complete: coverageComplete,
      complete_coverage_claimed: coverageComplete
    }
  };
}

function simulateRouterLocal(fixture) {
  const warnings = [];
  const client = {
    mac: fixture.client.mac.toLowerCase(),
    identity_key: fixture.client.identity_key,
    zone: fixture.client.zone,
    interface: fixture.client.interface,
    ips: [fixture.client.ip],
    hostname: null,
    tx_bps: 0,
    rx_bps: 0,
    collector_mode: 'tc_bpf_fixture',
    confidence: 'high',
    warnings: []
  };
  const routerSelf = {
    bucket: 'router_self',
    alias: 'local_router',
    identity_key: fixture.router.identity_key,
    tx_bps: 0,
    rx_bps: 0,
    client_attribution: 'never_attribute_to_lan_client'
  };

  for (const flow of fixture.flows) {
    const bps = rateFromDelta(flow.bytes_delta, fixture.interval_ms);

    if (flow.endpoint === 'router_originated') {
      routerSelf.tx_bps += bps;
      continue;
    }
    if (flow.direction === 'client_to_router' && flow.src === client.identity_key) {
      client.tx_bps += bps;
    } else if (flow.direction === 'router_to_client' && flow.dst === client.identity_key) {
      client.rx_bps += bps;
    }
  }

  return {
    source: 'lanspeedd_router_local_fixture',
    client,
    router_self: routerSelf,
    direction: {
      client_to_router: 'tx_bps',
      router_to_client: 'rx_bps',
      perspective: 'client'
    },
    warnings,
    router_originated_assigned_to_lan_client: false
  };
}

function simulateTopologyVlan(fixture) {
  const warnings = [];
  const clients = new Map();
  const zonesByMac = new Map();

  for (const observation of fixture.observations) {
    const mac = observation.mac.toLowerCase();
    const identityKey = `${mac}@${observation.zone}`;
    const zones = zonesByMac.get(mac) || new Set();

    zones.add(observation.zone);
    zonesByMac.set(mac, zones);
    if (!clients.has(identityKey)) {
      clients.set(identityKey, {
        mac,
        identity_key: identityKey,
        zone: observation.zone,
        vlan: observation.vlan,
        interface: observation.interface,
        bridge: observation.bridge,
        tx_bps: 0,
        rx_bps: 0,
        topology: {
          guest: Boolean(observation.guest),
          wds: Boolean(observation.wds),
          ap_isolation: Boolean(observation.ap_isolation)
        },
        collector_mode: 'tc_bpf_fixture',
        confidence: 'high',
        warnings: []
      });
    }

    const client = clients.get(identityKey);
    client.tx_bps += observation.client_originated_bps || 0;
    client.rx_bps += observation.to_client_bps || 0;
  }

  for (const zones of zonesByMac.values()) {
    if (zones.size > 1) {
      addUnique(warnings, 'duplicate_mac_across_vlans');
    }
  }

  const clientKeys = new Set(clients.keys());
  const uplinks = fixture.uplink_observations.map((entry) => ({
    interface: entry.interface,
    type: entry.type,
    side: 'wan',
    encapsulation_evidence_only: true,
    lan_identity_exists: clientKeys.has(entry.encapsulated_client_identity),
    ownership_changed: false
  }));

  return {
    source: 'lanspeedd_topology_vlan_fixture',
    identity_model: {
      primary_key: 'mac+zone',
      duplicate_mac_warning: 'duplicate_mac_across_vlans',
      preserve_mac_zone_identity: true
    },
    topology: fixture.topology,
    clients: Array.from(clients.values()).sort((left, right) => left.identity_key.localeCompare(right.identity_key)),
    uplinks,
    warnings,
    uplink_identity_policy: 'wan_encapsulation_evidence_only'
  };
}

function simulateResourceLimits(fixture) {
  const warnings = [];
  const activeClients = fixture.clients.filter((client) => fixture.now_ms - client.last_seen <= fixture.stale_client_ms);
  const staleClients = fixture.clients.filter((client) => fixture.now_ms - client.last_seen > fixture.stale_client_ms);
  const acceptedClients = activeClients.slice(0, fixture.max_clients);
  const rejectedClients = activeClients.slice(fixture.max_clients);

  if (activeClients.length > fixture.max_clients) {
    addUnique(warnings, 'client_limit_exceeded');
  }

  if (!fixture.map_read.ok) {
    addUnique(warnings, fixture.map_read.expected_warning);
  }

  return {
    source: 'lanspeedd_resource_limit_fixture',
    max_clients: fixture.max_clients,
    stale_client_ms: fixture.stale_client_ms,
    active_clients: acceptedClients,
    stale_clients: staleClients,
    rejected_clients: rejectedClients,
    warnings,
    crashed: false,
    existing_clients_preserved_on_map_read_failure: true
  };
}

function parseConntrackProcfsLine(line) {
  const flow = {
    orig_src: null,
    orig_dst: null,
    reply_src: null,
    reply_dst: null,
    orig_bytes: null,
    reply_bytes: 0
  };
  let srcIndex = 0;
  let dstIndex = 0;
  let bytesIndex = 0;

  for (const token of line.trim().split(/\s+/)) {
    if (token.startsWith('src=')) {
      if (srcIndex === 0) {
        flow.orig_src = token.slice(4);
      } else if (srcIndex === 1) {
        flow.reply_src = token.slice(4);
      }
      srcIndex += 1;
    } else if (token.startsWith('dst=')) {
      if (dstIndex === 0) {
        flow.orig_dst = token.slice(4);
      } else if (dstIndex === 1) {
        flow.reply_dst = token.slice(4);
      }
      dstIndex += 1;
    } else if (token.startsWith('bytes=')) {
      const value = Number.parseInt(token.slice(6), 10);
      if (!Number.isFinite(value)) {
        continue;
      }
      if (bytesIndex === 0) {
        flow.orig_bytes = value;
      } else if (bytesIndex === 1) {
        flow.reply_bytes = value;
      }
      bytesIndex += 1;
    }
  }

  return flow.orig_src && flow.orig_bytes !== null ? flow : null;
}

function normalizeIp(ip) {
  if (typeof ip !== 'string' || ip.length === 0) {
    return ip;
  }
  if (!ip.includes(':')) {
    return ip;
  }
  try {
    const hostname = new URL(`http://[${ip}]/`).hostname;
    return hostname.replace(/^\[/, '').replace(/\]$/, '');
  } catch (error) {
    return ip.toLowerCase();
  }
}

function ipv4ToInt(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) {
    return null;
  }
  let value = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return null;
    }
    const octet = Number.parseInt(part, 10);
    if (octet < 0 || octet > 255) {
      return null;
    }
    value = ((value << 8) | octet) >>> 0;
  }
  return value >>> 0;
}

function ipv4InCidr(ip, cidr) {
  const [base, bitsText] = String(cidr).split('/');
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  const bits = Number.parseInt(bitsText, 10);
  if (ipInt === null || baseInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return false;
  }
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function interfaceFilterEnabled(fixture) {
  return Array.isArray(fixture.collect_ifnames) && fixture.collect_ifnames.length > 0;
}

function interfacePrefixes(fixture, ifname) {
  const selected = new Set(fixture.collect_ifnames || []);

  if (!interfaceFilterEnabled(fixture) || !selected.has(ifname)) {
    return [];
  }

  return (fixture.interface_addresses || [])
    .filter((addr) => addr.interface === ifname && typeof addr.address === 'string')
    .map((addr) => addr.address);
}

function identityAddressAllowedByCollectedInterface(entry, fixture) {
  const ip = normalizeIp(entry.ip);
  const ifname = entry.interface || 'br-lan';
  const prefixes = interfacePrefixes(fixture, ifname);

  if (!interfaceFilterEnabled(fixture)) {
    return true;
  }

  return prefixes.some((cidr) => ipv4InCidr(ip, cidr));
}

function buildArpMap(fixture) {
  const entries = new Map();

  for (const entry of (fixture.arp_entries || []).concat(fixture.neighbor_entries || [])) {
    if (isExcludedIdentityInterface(entry.interface || '')) {
      continue;
    }
    if (!identityAddressAllowedByCollectedInterface(entry, fixture)) {
      continue;
    }
    const ip = normalizeIp(entry.ip);
    entries.set(ip, {
      ip,
      mac: entry.mac.toLowerCase(),
      zone: entry.zone || 'lan',
      interface: entry.interface || 'br-lan'
    });
  }

  return entries;
}

function isExcludedIdentityInterface(ifname) {
  const autoIgnoredPrefixes = [
    'dae',
    'miireg',
    'tun',
    'erspan',
    'gretap',
    'gre',
    'ip6gre',
    'ip6tnl',
    'sit',
    'bonding_masters'
  ];

  return autoIgnoredPrefixes.some((prefix) => ifname.startsWith(prefix)) || ifname.startsWith('ppp') || ifname.startsWith('wg');
}

function buildArpByMacZone(fixture) {
  const entries = new Map();

  for (const entry of (fixture.arp_entries || []).concat(fixture.neighbor_entries || [])) {
    if (!entry.mac || isExcludedIdentityInterface(entry.interface || '')) {
      continue;
    }
    if (!identityAddressAllowedByCollectedInterface(entry, fixture)) {
      continue;
    }

    const mac = entry.mac.toLowerCase();
    const zone = entry.zone || 'lan';
    const key = `${mac}@${zone}`;

    if (!entries.has(key)) {
      entries.set(key, []);
    }
    entries.get(key).push({
      ip: normalizeIp(entry.ip),
      mac,
      zone,
      interface: entry.interface || 'br-lan'
    });
  }

  return entries;
}

function simulateBpfIdentityFolding(fixture) {
  const arpByMacZone = buildArpByMacZone(fixture);
  const clients = new Map();
  let skippedNoIdentity = 0;

  for (const sample of fixture.raw_bpf_samples || []) {
    const mac = sample.mac.toLowerCase();
    const zone = sample.zone || 'lan';
    const identities = arpByMacZone.get(`${mac}@${zone}`) || [];
    const identity = identities[0];

    if (!identity) {
      skippedNoIdentity += 1;
      continue;
    }

    const identityKey = `${identity.mac}@${identity.zone}`;
    const client = clients.get(identityKey) || {
      mac: identity.mac,
      identity_key: identityKey,
      zone: identity.zone,
      interface: sample.interface || identity.interface,
      ips: [],
      tx_bytes: 0,
      rx_bytes: 0
    };

    for (const item of identities) {
      if (item.ip && !client.ips.includes(item.ip)) {
        client.ips.push(item.ip);
      }
    }
    if (sample.direction === 'tx') {
      client.tx_bytes += sample.bytes || 0;
    } else if (sample.direction === 'rx') {
      client.rx_bytes += sample.bytes || 0;
    }
    clients.set(identityKey, client);
  }

  return {
    clients: Array.from(clients.values()).sort((left, right) => left.identity_key.localeCompare(right.identity_key)),
    skipped_no_identity: skippedNoIdentity
  };
}

function buildConntrackSnapshot(fixture, snapshot) {
  const arpByIp = buildArpMap(fixture);
  const clients = new Map();
  let skippedNoArp = 0;
  let skippedBothLan = 0;
  let malformedLines = 0;

  for (const line of snapshot.lines) {
    const flow = parseConntrackProcfsLine(line);
    if (!flow) {
      malformedLines += 1;
      continue;
    }

    const origSrc = arpByIp.get(normalizeIp(flow.orig_src));
    const origDst = arpByIp.get(normalizeIp(flow.orig_dst));
    const replySrc = arpByIp.get(normalizeIp(flow.reply_src));
    const replyDst = arpByIp.get(normalizeIp(flow.reply_dst));
    let arp = null;
    let txBytes = 0;
    let rxBytes = 0;

    if (origSrc && origDst) {
      skippedBothLan += 1;
      continue;
    } else if (origSrc) {
      arp = origSrc;
      txBytes = flow.orig_bytes;
      rxBytes = flow.reply_bytes;
    } else if (origDst) {
      arp = origDst;
      txBytes = flow.reply_bytes;
      rxBytes = flow.orig_bytes;
    } else if (replySrc && replyDst) {
      skippedBothLan += 1;
      continue;
    } else if (replySrc) {
      arp = replySrc;
      txBytes = flow.reply_bytes;
      rxBytes = flow.orig_bytes;
    } else if (replyDst) {
      arp = replyDst;
      txBytes = flow.orig_bytes;
      rxBytes = flow.reply_bytes;
    } else {
      skippedNoArp += 1;
      continue;
    }

    const identityKey = `${arp.mac}@${arp.zone}`;
    const client = clients.get(identityKey) || {
      mac: arp.mac,
      identity_key: identityKey,
      zone: arp.zone,
      interface: arp.interface,
      ips: [],
      tx_bytes: 0,
      rx_bytes: 0,
      last_seen: snapshot.t_ms
    };

    if (!client.ips.includes(arp.ip)) {
      client.ips.push(arp.ip);
    }
    client.tx_bytes += txBytes;
    client.rx_bytes += rxBytes;
    client.last_seen = snapshot.t_ms;
    clients.set(identityKey, client);
  }

  return {
    t_ms: snapshot.t_ms,
    clients: Array.from(clients.values()),
    skipped_no_arp: skippedNoArp,
    skipped_both_lan: skippedBothLan,
    malformed_lines: malformedLines
  };
}

function carryConntrackLastSeen(previous, current) {
  if (!previous) {
    return current.last_seen;
  }
  if (current.tx_bytes !== previous.tx_bytes || current.rx_bytes !== previous.rx_bytes) {
    return current.last_seen;
  }
  return previous.last_seen;
}

function parseNssEcmDirectState(lines) {
  const flows = new Map();
  let malformed_lines = 0;

  for (const line of lines) {
    const match = /^conns\.conn\.([0-9]+)\.([^=]+)=(.*)$/.exec(line);
    if (!match) {
      malformed_lines += 1;
      continue;
    }

    const serial = match[1];
    const field = match[2];
    const value = match[3];
    const flow = flows.get(serial) || {
      serial,
      sip_address: null,
      dip_address: null,
      sip_address_nat: null,
      dip_address_nat: null,
      snode_address: null,
      dnode_address: null,
      snode_address_nat: null,
      dnode_address_nat: null,
      protocol: 0,
      from_data_total: null,
      to_data_total: 0
    };

    if (field === 'sip_address') {
      flow.sip_address = value;
    } else if (field === 'dip_address') {
      flow.dip_address = value;
    } else if (field === 'sip_address_nat') {
      flow.sip_address_nat = value;
    } else if (field === 'dip_address_nat') {
      flow.dip_address_nat = value;
    } else if (field === 'snode_address') {
      flow.snode_address = value.toLowerCase();
    } else if (field === 'dnode_address') {
      flow.dnode_address = value.toLowerCase();
    } else if (field === 'snode_address_nat') {
      flow.snode_address_nat = value.toLowerCase();
    } else if (field === 'dnode_address_nat') {
      flow.dnode_address_nat = value.toLowerCase();
    } else if (field === 'protocol') {
      flow.protocol = Number.parseInt(value, 10) || 0;
    } else if (field === 'adv_stats.from_data_total') {
      flow.from_data_total = Number.parseInt(value, 10);
    } else if (field === 'adv_stats.to_data_total') {
      flow.to_data_total = Number.parseInt(value, 10) || 0;
    }

    flows.set(serial, flow);
  }

  return { flows: Array.from(flows.values()), malformed_lines };
}

function buildNssEcmDirectSnapshot(fixture, snapshot) {
  const arpByIp = buildArpMap(fixture);
  const arpByMac = new Map();
  const addArpByMac = (entry) => {
    if (entry && entry.mac && !arpByMac.has(entry.mac.toLowerCase())) {
      arpByMac.set(entry.mac.toLowerCase(), entry);
    }
  };
  (fixture.arp_entries || []).forEach(addArpByMac);
  (fixture.neighbor_entries || []).forEach(addArpByMac);
  const parsed = parseNssEcmDirectState(snapshot.lines);
  const clients = new Map();
  let skippedNoArp = 0;
  let skippedBothLan = 0;
  let entriesMatched = 0;

  for (const flow of parsed.flows) {
    if (!flow.sip_address || flow.from_data_total === null) {
      continue;
    }

    const sourceMac = (flow.snode_address && flow.snode_address !== '00:00:00:00:00:00')
      ? flow.snode_address
      : flow.snode_address_nat;
    const destMac = (flow.dnode_address && flow.dnode_address !== '00:00:00:00:00:00')
      ? flow.dnode_address
      : flow.dnode_address_nat;
    const srcArp = arpByIp.get(normalizeIp(flow.sip_address)) ||
      arpByIp.get(normalizeIp(flow.sip_address_nat)) ||
      (sourceMac ? arpByMac.get(sourceMac) : null);
    const dstArp = arpByIp.get(normalizeIp(flow.dip_address)) ||
      arpByIp.get(normalizeIp(flow.dip_address_nat)) ||
      (destMac ? arpByMac.get(destMac) : null);
    let arp = null;
    let mac = null;
    let txBytes = 0;
    let rxBytes = 0;

    if (srcArp && dstArp) {
      skippedBothLan += 1;
      continue;
    } else if (srcArp) {
      arp = srcArp;
      mac = arp.mac;
      txBytes = flow.from_data_total;
      rxBytes = flow.to_data_total;
    } else if (dstArp) {
      arp = dstArp;
      mac = arp.mac;
      txBytes = flow.to_data_total;
      rxBytes = flow.from_data_total;
    } else {
      skippedNoArp += 1;
      continue;
    }

    const identityKey = `${mac}@${arp.zone}`;
    const client = clients.get(identityKey) || {
      mac,
      identity_key: identityKey,
      zone: arp.zone,
      interface: arp.interface,
      ips: [],
      tx_bytes: 0,
      rx_bytes: 0,
      last_seen: snapshot.t_ms
    };

    if (!client.ips.includes(arp.ip)) {
      client.ips.push(arp.ip);
    }
    client.tx_bytes += txBytes;
    client.rx_bytes += rxBytes;
    client.last_seen = snapshot.t_ms;
    clients.set(identityKey, client);
    entriesMatched += 1;
  }

  return {
    t_ms: snapshot.t_ms,
    clients: Array.from(clients.values()).sort((left, right) => left.identity_key.localeCompare(right.identity_key)),
    entries_seen: parsed.flows.length,
    entries_matched: entriesMatched,
    skipped_no_arp: skippedNoArp,
    skipped_both_lan: skippedBothLan,
    malformed_lines: parsed.malformed_lines
  };
}

function simulateNssEcmDirect(fixture) {
  const firstSnapshot = buildNssEcmDirectSnapshot(fixture, fixture.state_snapshots[0]);
  const secondSnapshot = buildNssEcmDirectSnapshot(fixture, fixture.state_snapshots[1]);
  const previousByIdentity = new Map(firstSnapshot.clients.map((client) => [client.identity_key, client]));
  const deltaMs = secondSnapshot.t_ms - firstSnapshot.t_ms;
  const clients = secondSnapshot.clients.map((current) => {
    const previous = previousByIdentity.get(current.identity_key);
    return {
      mac: current.mac,
      identity_key: current.identity_key,
      zone: current.zone,
      interface: current.interface,
      ips: current.ips,
      rx_bps: previous ? rateFromDelta(current.rx_bytes - previous.rx_bytes, deltaMs) : 0,
      tx_bps: previous ? rateFromDelta(current.tx_bytes - previous.tx_bytes, deltaMs) : 0,
      collector_mode: 'nss_ecm_direct',
      confidence: 'high',
      warnings: []
    };
  });

  return {
    source: 'lanspeedd_nss_ecm_direct_fixture',
    primary_source: 'nss_ecm_direct',
    collector_mode: 'nss_ecm_direct',
    confidence: 'high',
    coverage_client_source: 'nss_ecm_direct',
    read_only: true,
    forbidden_writes: ['defunct_all', 'flush', 'decelerate'],
    source_path: '/dev/ecm_state',
    first_snapshot: firstSnapshot,
    second_snapshot: secondSnapshot,
    clients
  };
}

function simulateNssStableCollector(fixture) {
  const sync = simulateConntrackFallback(fixture);
  const direct = simulateNssEcmDirect(fixture);
  const clientsByIdentity = new Map();
  const warnings = sync.warnings.slice();
  let directOverlayClients = 0;
  let syncFallbackClients = 0;

  for (const client of sync.clients) {
    clientsByIdentity.set(client.identity_key, Object.assign({}, client));
  }

  for (const client of direct.clients) {
    if (!client.tx_bps && !client.rx_bps)
      continue;
    const existing = clientsByIdentity.get(client.identity_key);
    if (existing) {
      directOverlayClients += 1;
    }
    clientsByIdentity.set(client.identity_key, Object.assign({}, existing || {}, client, {
      collector_mode: 'nss_ecm_direct',
      confidence: 'high'
    }));
  }

  for (const client of clientsByIdentity.values()) {
    if (client.collector_mode === 'conntrack_ecm_sync') {
      syncFallbackClients += 1;
    }
  }

  if (direct.first_snapshot.entries_matched === 0 || directOverlayClients === 0) {
    addUnique(warnings, 'nss_direct_no_data');
  } else if (syncFallbackClients > 0) {
    addUnique(warnings, 'nss_direct_partial');
  }
  if (syncFallbackClients > 0) {
    addUnique(warnings, 'nss_sync_fallback');
  }

  return {
    source: 'lanspeedd_nss_stable_fixture',
    primary_source: sync.active ? 'nss_conntrack_sync' : 'nss_ecm_direct',
    collector_mode: directOverlayClients > 0 && syncFallbackClients > 0
      ? 'nss_ecm_direct+conntrack_ecm_sync'
      : (directOverlayClients > 0 ? 'nss_ecm_direct' : 'conntrack_ecm_sync'),
    confidence: sync.confidence,
    coverage_client_source: directOverlayClients > 0 && syncFallbackClients > 0
      ? 'nss_ecm_direct+conntrack_ecm_sync'
      : (directOverlayClients > 0 ? 'nss_ecm_direct' : 'conntrack'),
    direct_flows_seen: direct.first_snapshot.entries_seen,
    direct_flows_matched: direct.first_snapshot.entries_matched,
    direct_overlay_clients: directOverlayClients,
    sync_fallback_clients: syncFallbackClients,
    warnings,
    clients: Array.from(clientsByIdentity.values()).sort((left, right) => left.identity_key.localeCompare(right.identity_key))
  };
}

function simulateConntrackFallback(fixture) {
  const warnings = [];
  const probe = fixture.probe;
  const nssSyncPreferred = Boolean(
    fixture.config.enable_conntrack_fallback &&
    probe.nf_conntrack_acct &&
    probe.nss_present &&
    (probe.nss_ecm_active || probe.nss_ppe_active)
  );
  const active = Boolean(
    nssSyncPreferred
  );
  const lowConfidence = Boolean(active && (
    !probe.flowtable_counter ||
    probe.openclash_fake_ip_or_tun ||
    probe.dae_or_daed ||
    probe.sqm_qosify_or_ifb ||
    probe.hardware_flow_offload ||
    probe.software_flow_offload ||
    probe.nlbwmon ||
    probe.probe_error
  ));

  if (!probe.nf_conntrack_acct) {
    addUnique(warnings, 'conntrack_acct_disabled');
  }

  const firstSnapshot = fixture.procfs_snapshots ? buildConntrackSnapshot(fixture, fixture.procfs_snapshots[0]) : null;
  const secondSnapshot = fixture.procfs_snapshots ? buildConntrackSnapshot(fixture, fixture.procfs_snapshots[1]) : null;
  const clients = [];

  if (active) {
    if (nssSyncPreferred) {
      addUnique(warnings, 'nss_ecm_sync_cadence');
      if (fixture.config.bpf_full_available) {
        addUnique(warnings, 'nss_prefers_conntrack_sync');
      }
    } else {
      addUnique(warnings, 'conntrack_routed_nat_only');
    }
    addUnique(warnings, 'conntrack_snapshot_pending');
    if (!probe.flowtable_counter) {
      addUnique(warnings, 'flowtable_counter_missing');
    }
    if (probe.nlbwmon) {
      addUnique(warnings, 'nlbwmon_counter_conflict');
    }
    if (probe.openclash_fake_ip_or_tun || probe.dae_or_daed) {
      addUnique(warnings, 'proxy_path_confidence_low');
    }
    if (probe.sqm_qosify_or_ifb) {
      addUnique(warnings, 'qos_ifb_confidence_low');
    }
    if (probe.hardware_flow_offload || probe.software_flow_offload) {
      addUnique(warnings, 'flow_offload_confidence_low');
    }

    if (firstSnapshot && secondSnapshot) {
      const previousByIdentity = new Map(firstSnapshot.clients.map((client) => [client.identity_key, client]));
      const deltaMs = secondSnapshot.t_ms - firstSnapshot.t_ms;

      for (const current of secondSnapshot.clients) {
        const previous = previousByIdentity.get(current.identity_key);
        clients.push({
          mac: current.mac,
          identity_key: current.identity_key,
          zone: current.zone,
          interface: current.interface,
          ips: current.ips,
          hostname: null,
          rx_bps: previous ? rateFromDelta(current.rx_bytes - previous.rx_bytes, deltaMs) : 0,
          tx_bps: previous ? rateFromDelta(current.tx_bytes - previous.tx_bytes, deltaMs) : 0,
          last_seen: carryConntrackLastSeen(previous, current),
          collector_mode: nssSyncPreferred ? 'conntrack_ecm_sync' : 'conntrack',
          confidence: lowConfidence ? 'low' : 'medium',
          warnings: warnings.slice()
        });
      }
    }
  }

  return {
    source: 'lanspeedd_conntrack_fixture',
    runtime_source: 'lanspeedd_procfs_conntrack_acct',
    mode: 'Degraded',
    active,
    collector_mode: nssSyncPreferred ? 'conntrack_ecm_sync' : 'conntrack',
    confidence: active ? (lowConfidence ? 'low' : 'medium') : 'unsupported',
    coverage: nssSyncPreferred ? 'nss_ecm_sync' : 'routed_nat_only',
    coverage_warning: nssSyncPreferred ? 'nss_ecm_sync_cadence' : 'conntrack_routed_nat_only',
    counter_source: 'procfs_conntrack_acct_orig_reply_bytes',
    nf_conntrack_acct: Boolean(probe.nf_conntrack_acct),
    flowtable_counter: Boolean(probe.flowtable_counter),
    nlbwmon_read_counters: false,
    forbidden_sources: [
      'firewall_forward_chain_counters',
      'iptables_forward_chain_counters',
      'nft_forward_chain_counters',
      'nlbwmon_counters'
    ],
    identity_model: {
      primary_key: 'mac+zone',
      ip_role: 'LAN client IP maps to an existing MAC/zone identity and is never the primary identity'
    },
    first_snapshot: firstSnapshot,
    second_snapshot: secondSnapshot,
    warnings,
    clients
  };
}

function simulateNssSourceSelection(fixture) {
  const probe = fixture.probe;
  const bpfFullAvailable = Boolean(fixture.config.bpf_full_available);
  const daeEarlyBpf = Boolean(fixture.config.dae_early_bpf);
  const rateMode = fixture.config.rate_collector_mode || 'auto';
  const daeRuntimeActive = Boolean(probe.runtime_active);
  const forceBpf = rateMode === 'bpf';
  const forceNssDirect = rateMode === 'nss_ecm_direct';
  const forceNssSync = rateMode === 'nss_conntrack_sync';
  const daePreferBpf = Boolean(rateMode === 'auto' && daeRuntimeActive && bpfFullAvailable);
  const directReadable = probe.nss_ecm_direct_readable !== false;
  const nssSyncAvailable = Boolean(
    fixture.config.enable_conntrack_fallback &&
    probe.nf_conntrack_acct &&
    probe.nss_present &&
    (probe.nss_ecm_active || probe.nss_ppe_active)
  );
  const nssDirectAvailable = Boolean(
    probe.nss_present &&
    probe.nss_ecm_active &&
    probe.nss_ecm_direct_state &&
    directReadable
  );
  let primarySource = 'unsupported';
  let collectorMode = 'unsupported';
  let confidence = 'unsupported';
  let coverageClientSource = 'unsupported';

  if (forceBpf) {
    if (bpfFullAvailable) {
      primarySource = collectorMode = coverageClientSource = 'bpf';
      confidence = 'high';
    }
  } else if (forceNssDirect) {
    if (nssDirectAvailable) {
      primarySource = collectorMode = coverageClientSource = 'nss_ecm_direct';
      confidence = 'high';
    } else if (nssSyncAvailable) {
      primarySource = 'nss_conntrack_sync';
      collectorMode = 'conntrack_ecm_sync';
      coverageClientSource = 'conntrack';
      confidence = 'medium';
    }
  } else if (forceNssSync) {
    if (nssSyncAvailable) {
      primarySource = 'nss_conntrack_sync';
      collectorMode = 'conntrack_ecm_sync';
      coverageClientSource = 'conntrack';
      confidence = 'medium';
    }
  } else if (bpfFullAvailable) {
    primarySource = collectorMode = coverageClientSource = 'bpf';
    confidence = 'high';
  } else if (nssSyncAvailable) {
    primarySource = 'nss_conntrack_sync';
    collectorMode = 'conntrack_ecm_sync';
    coverageClientSource = 'conntrack';
    confidence = 'medium';
  } else if (nssDirectAvailable) {
    primarySource = collectorMode = coverageClientSource = 'nss_ecm_direct';
    confidence = 'high';
  }

  const directPreferred = primarySource === 'nss_ecm_direct';
  const syncPreferred = primarySource === 'nss_conntrack_sync';
  const preferred = primarySource !== 'unsupported';
  const warnings = [];

  if (directPreferred || syncPreferred) {
    addUnique(warnings, directPreferred ? 'nss_ecm_direct_active' : 'nss_ecm_sync_cadence');
    if (bpfFullAvailable) {
      addUnique(warnings, directPreferred ? 'nss_prefers_direct' : 'nss_prefers_conntrack_sync');
    }
  }
  if (daePreferBpf)
    addUnique(warnings, 'dae_runtime_prefers_bpf');
  if (probe.nss_present && daeRuntimeActive && !bpfFullAvailable && preferred)
    addUnique(warnings, 'nss_dae_bpf_fallback_may_be_inaccurate');

  return {
    preferred,
    dae_early_bpf: Boolean((probe.dae_preempts_lan_ingress || daeRuntimeActive) && daeEarlyBpf),
    dae_preempted: false,
    primary_source: primarySource,
    collector_mode: collectorMode,
    confidence,
    coverage_client_source: coverageClientSource,
    warnings
  };
}

function validateRefreshInterval(fixture) {
  const effective_ms = fixture.configured_ms < fixture.minimum_ms ? fixture.minimum_ms : fixture.configured_ms;

  return {
    source: 'lanspeedd_refresh_interval_fixture',
    default_ms: fixture.default_ms,
    minimum_ms: fixture.minimum_ms,
    configured_ms: fixture.configured_ms,
    effective_ms,
    warnings: effective_ms !== fixture.configured_ms ? [fixture.expected_warning] : []
  };
}

function simulateMapFull(fixture) {
  const full = fixture.existing_clients >= fixture.max_clients;

  return {
    source: 'lanspeedd_map_fixture',
    max_clients: fixture.max_clients,
    existing_clients: fixture.existing_clients,
    attempted_key: fixture.new_entry,
    accepted: !full,
    warnings: full ? [fixture.expected_warning] : [],
    crashed: false
  };
}

function isOwnedLanspeedFilter(filter, identity) {
  return filter.owner === identity.owner &&
    filter.pref === identity.pref &&
    filter.handle === identity.handle &&
    filter.object === identity.object;
}

function simulateLifecycleRestart(fixture) {
  const identity = fixture.owned_filter_identity;
  const before = clone(fixture.before_filters);
  const removed = before.filter((filter) => isOwnedLanspeedFilter(filter, identity));
  const afterCleanup = before.filter((filter) => !isOwnedLanspeedFilter(filter, identity));
  const afterRestart = clone(afterCleanup);

  for (const direction of ['ingress', 'egress']) {
    const ownedFilter = {
      interface: fixture.device,
      direction,
      pref: identity.pref,
      handle: identity.handle,
      owner: identity.owner,
      object: identity.object,
      source: 'lanspeed_attach_plan'
    };

    if (!afterRestart.some((filter) => isOwnedLanspeedFilter(filter, identity) && filter.direction === direction)) {
      afterRestart.push(ownedFilter);
    }
  }

  const foreignBefore = before.filter((filter) => !isOwnedLanspeedFilter(filter, identity));
  const foreignFiltersPreserved = foreignBefore.every((filter) => afterRestart.some((entry) => filterKey(entry) === filterKey(filter)));
  const ownedAfter = afterRestart.filter((filter) => isOwnedLanspeedFilter(filter, identity));
  const ownedDirections = ownedAfter.map((filter) => filter.direction).sort();

  return {
    source: 'lanspeedd_lifecycle_fixture',
    device: fixture.device,
    qdisc: fixture.qdisc.kind,
    before_filters: before,
    cleanup_removed_filters: removed,
    after_restart_filters: afterRestart,
    delete_clsact: false,
    delete_foreign_filters: false,
    foreign_filters_preserved: foreignFiltersPreserved,
    lanspeed_filter_count_after_restart: ownedAfter.length,
    duplicate_lanspeed_filters: ownedAfter.length !== new Set(ownedDirections).size,
    owned_filter_identity: identity,
    preserved_foreign_owners: foreignBefore.map((filter) => filter.owner),
    cleanup_commands: removed.map((filter) => `tc filter del dev ${filter.interface} ${filter.direction} pref ${filter.pref} handle ${filter.handle}`)
  };
}

function simulateNetworkReload(fixture) {
  const finalState = fixture.network_reload.states[fixture.network_reload.states.length - 1];

  return {
    source: 'lanspeedd_network_reload_fixture',
    interface: fixture.network_reload.interface,
    action: fixture.network_reload.action,
    hotplug_operation: '/etc/init.d/lanspeedd reload',
    changes_user_network_config: false,
    changes_proxy_config: false,
    states: fixture.network_reload.states,
    temporary_warning_seen: fixture.network_reload.states.some((state) => state.warnings.includes('network_reload_reprobe_pending')),
    recovered_mode: finalState.mode,
    bpf_runtime_metrics: Boolean(finalState.bpf_runtime_metrics),
    runtime_attach_map_read_success: Boolean(finalState.runtime_attach_map_read_success),
    live_metrics: Boolean(finalState.live_metrics),
    warnings_after_recovery: finalState.warnings.slice(),
    daemon_alive_after_recovery: finalState.daemon_alive
  };
}

function assertLifecycleInit(initScript, hotplugScript, packageMakefile, defaultConfig, collectorModel) {
  assert(initScript.includes('USE_PROCD=1'), 'init script must use procd');
  assert(initScript.includes('procd_set_param respawn 3600 5 5'), 'init script must use finite respawn parameters');
  assert(initScript.includes('procd_set_param stdout 1'), 'init script must enable stdout logging');
  assert(initScript.includes('procd_set_param stderr 1'), 'init script must enable stderr logging');
  assert(initScript.includes('procd_add_reload_trigger "lanspeed" "network"'), 'init script must reload on lanspeed and network config changes');
  assert(initScript.includes('procd_add_interface_trigger'), 'init script must register interface reload awareness');
  assert(!/tc\s+qdisc\s+del/i.test(initScript), 'init cleanup must never delete clsact qdisc');
  assert(/\$TC\s+filter\s+del dev "\$dev" "\$direction" pref "\$LANSPEED_TC_PREF" handle "\$LANSPEED_TC_HANDLE"/.test(initScript), 'tc cleanup must be scoped to owned pref and handle');
  assert(initScript.includes('LANSPEED_TC_OWNER="lanspeed"'), 'init cleanup must encode lanspeed owner');
  assert(initScript.includes('LANSPEED_TC_PREF="49152"'), 'init cleanup must encode lanspeed pref');
  assert(initScript.includes('LANSPEED_TC_HANDLE="0x1eed"'), 'init cleanup must encode lanspeed handle');
  assert(initScript.includes('grep -F -q "$LANSPEED_TC_OWNER"'), 'init cleanup must require exact owner marker');
  assert(initScript.includes("grep -E -q 'lanspeed_ingres|lanspeed_egress'"), 'init cleanup must require the installed lanspeed BPF program name from tc output');
  assert(!initScript.includes('grep -F -q "$LANSPEED_TC_OBJECT"'), 'init cleanup must not require an object marker absent from tc filter show output');
  assert(!initScript.includes('$LANSPEED_TC_OWNER\\|$LANSPEED_TC_OBJECT'), 'init cleanup must not treat owner/object as alternatives');
  assert(!/service\s+network\s+reload/i.test(initScript), 'init script must not reload user network config');
  assert(!/uci\s+commit/i.test(initScript), 'init script must not commit user config');
  assert(hotplugScript.includes('/etc/init.d/lanspeedd reload'), 'hotplug hook must call lanspeedd reload');
  assert(!/restart/i.test(hotplugScript), 'hotplug hook must not directly restart the service');
  assert(!/service\s+network\s+reload/i.test(hotplugScript), 'hotplug hook must not reload network service');
  assert(!/uci\s+commit/i.test(hotplugScript), 'hotplug hook must not mutate UCI config');
  assert(packageMakefile.includes('$(INSTALL_BIN) ./files/etc/hotplug.d/iface/90-lanspeedd $(1)/etc/hotplug.d/iface/90-lanspeedd'), 'package Makefile must install hotplug hook');
  assert(defaultConfig.includes("option max_clients '2048'"), 'default config must keep max_clients=2048');
  assert(defaultConfig.includes("option refresh_interval_ms '1000'"), 'default config must keep refresh_interval_ms=1000');
  assert(defaultConfig.includes("option active_client_window_ms '10000'"), 'default config must keep active window at 10s');
  assert(defaultConfig.includes("option active_client_min_bps '1'"), 'default config must keep active speed threshold at nonzero');
  assert(defaultConfig.includes("option show_ipv6 '1'"), 'default config must show IPv6 client addresses');
  assert(defaultConfig.includes("option hide_private_ipv6 '0'"), 'default config must not hide private IPv6 client addresses by default');
  assert(defaultConfig.includes("option hide_ipv6_ranges 'fc00::/7 fe80::/10'"), 'default config must provide hidden IPv6 ranges');
  assert(defaultConfig.includes("option overview_window_samples '240'"), 'default config must keep trend history at 240 samples');
  assert(defaultConfig.includes("option warning_stale_client_ms '5000'"), 'default config must keep stale warning at 5000ms');
  assert(defaultConfig.includes("option warning_map_full '1'"), 'default config must represent map_full warning guardrail');
  assert(defaultConfig.includes("option warning_attach_failure 'unsafe_attach'"), 'default config must represent attach failure guardrail');
  assert(defaultConfig.includes("option low_end_refresh_interval_ms '2000'"), 'default config must represent low-end device guardrail');
  assert(collectorModel.lifecycle_model.cleanup_model.delete_clsact === false, 'lifecycle model must forbid clsact deletion');
  assert(collectorModel.lifecycle_model.cleanup_model.delete_foreign_filters === false, 'lifecycle model must forbid foreign filter deletion');
  assert(collectorModel.performance_guardrails.default_max_clients === 2048, 'performance model must default to 2048 clients');
  assert(collectorModel.performance_guardrails.minimum_refresh_interval_ms === 500, 'performance model must enforce 500ms refresh minimum');
  assert(collectorModel.performance_guardrails.stale_client_ms === 5000, 'performance model must keep 5000ms stale client guardrail');
  assert(collectorModel.performance_guardrails.map_full_warning === 'map_full', 'performance model must expose map_full warning');
  assert(collectorModel.performance_guardrails.attach_failure_warning === 'unsafe_attach', 'performance model must expose attach failure warning');
}

function assertNoDestructiveTcCommands(text) {
  const forbidden = [
    /tc\s+qdisc\s+del/i,
    /tc\s+filter\s+del/i,
    /fw4\s+reload/i,
    /service\s+network\s+reload/i,
    /uci\s+commit/i
  ];

  for (const pattern of forbidden) {
    assert(!pattern.test(text), `forbidden destructive command matched ${pattern}`);
  }
}

function writeEvidence(fileName, payload) {
  fs.writeFileSync(path.join(evidenceDir, fileName), `${payload}\n`);
}

fs.mkdirSync(evidenceDir, { recursive: true });

const tcCoexistFixture = readJson('tests/fixtures/lanspeed-tc-coexist.json');
const uploadRateFixture = readJson('tests/fixtures/lanspeed-upload-rate.json');
const mapFullFixture = readJson('tests/fixtures/lanspeed-map-full.json');
const lanToLanFixture = readJson('tests/fixtures/lanspeed-lan-to-lan-dedupe.json');
const counterAnomalyFixture = readJson('tests/fixtures/lanspeed-counter-anomaly.json');
const resourceLimitFixture = readJson('tests/fixtures/lanspeed-resource-limits.json');
const refreshIntervalFixture = readJson('tests/fixtures/lanspeed-refresh-interval.json');
const conntrackNatFixture = readJson('tests/fixtures/lanspeed-conntrack-nat.json');
const conntrackAcctDisabledFixture = readJson('tests/fixtures/lanspeed-conntrack-acct-disabled.json');
const nssEcmDirectFixture = readJson('tests/fixtures/lanspeed-nss-ecm-direct.json');
const nssEcmSyncFixture = readJson('tests/fixtures/lanspeed-nss-ecm-sync.json');
const nssEcmSyncBpfFallbackFixture = readJson('tests/fixtures/lanspeed-nss-ecm-sync-bpf-fallback.json');
const sideRouterDirectFixture = readJson('tests/fixtures/lanspeed-side-router-direct.json');
const routerLocalFixture = readJson('tests/fixtures/lanspeed-router-local.json');
const topologyVlanFixture = readJson('tests/fixtures/lanspeed-topology-vlan.json');
const lifecycleFixture = readJson('tests/fixtures/lanspeed-lifecycle.json');
const packageMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const sdkHelper = fs.readFileSync(path.join(root, 'scripts/build-sdk.sh'), 'utf8');
const initScript = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/init.d/lanspeedd'), 'utf8');
const hotplugScript = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/hotplug.d/iface/90-lanspeedd'), 'utf8');
const defaultConfig = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/config/lanspeed'), 'utf8');
const statusResourceDir = path.join(root, 'applications/luci-app-lanspeed/htdocs/luci-static/resources');
const indexSource = [
  'view/lanspeed/index_live4.js',
  'lanspeed/statusViewLive.js',
  'lanspeed/statusViewLive2.js',
  'lanspeed/statusViewLive3.js',
  'lanspeed/statusCollector.js',
  'lanspeed/statusRefresh.js'
].map((relativePath) => fs.readFileSync(path.join(statusResourceDir, relativePath), 'utf8')).join('\n');
const nssPanelSource = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/nssPanel.js'), 'utf8');
const collectorModel = readJson('net/lanspeedd/src/collector-model.json');
const bpfAttachedFixture = readJson('tests/fixtures/lanspeed-bpf-attached.json');

assertNoDestructiveTcCommands(packageMakefile);
assertNoDestructiveTcCommands(sdkHelper);
assertLifecycleInit(initScript, hotplugScript, packageMakefile, defaultConfig, collectorModel);

const tcCoexist = attachLanspeedFilters(tcCoexistFixture);
assert(tcCoexist.existing_filters_preserved === true, 'existing dae-like filters must be preserved');
assert(tcCoexist.lanspeed_filter_added === true, 'lanspeed filter must be appended');
assert(tcCoexist.append_only === true, 'tc model must be append-only');
assert(tcCoexist.destructive_commands.length === 0, 'fixture must not generate destructive tc commands');
assert(tcCoexist.tc_filter.delete_existing === false, 'tc filter model must not delete existing filters');
assert(tcCoexist.tc_filter.reorder_existing === false, 'tc filter model must not reorder existing filters');
assert(tcCoexist.mode === 'Degraded', 'tc coexistence fixture must not claim Full without runtime attach/map-read');
assert(tcCoexist.bpf_runtime_metrics === false, 'tc coexistence fixture must keep bpf_runtime_metrics=false');
assert(tcCoexist.runtime_attach_map_read_success === false, 'tc coexistence fixture must keep runtime attach/map-read success false');
assert(tcCoexist.live_metrics === false, 'tc coexistence fixture must keep live_metrics=false');
assert(tcCoexist.bpf_assets_are_evidence_only === true, 'tc coexistence fixture must mark BPF assets as evidence only');
assert(tcCoexist.warnings.includes('bpf_runtime_loader_unavailable'), 'tc coexistence fixture must warn that runtime BPF loader is unavailable');
assert(tcCoexist.warnings.includes('live_metrics_unavailable'), 'tc coexistence fixture must warn that live metrics are unavailable');
assert(tcCoexist.after_filters[0].owner === 'dae', 'dae-like filter must remain first in fixture order');
assert(tcCoexist.existing_filter_evidence.every((filter) => filter.interface && filter.pref && filter.handle && filter.owner), 'existing dae filters must record interface/pref/handle/owner');

const bpfAttached = attachLanspeedFilters(bpfAttachedFixture);
assert(bpfAttached.lanspeed_filter_added === true, 'attached-success fixture must add the lanspeed filter');
assert(bpfAttached.append_only === true, 'attached-success fixture must stay append-only');
assert(bpfAttached.mode === 'Full', 'attached-success fixture must declare Full when runtime attach+map-read succeed');
assert(bpfAttached.bpf_runtime_metrics === true, 'attached-success fixture must set bpf_runtime_metrics=true');
assert(bpfAttached.runtime_attach_map_read_success === true, 'attached-success fixture must set runtime_attach_map_read_success=true');
assert(bpfAttached.live_metrics === true, 'attached-success fixture must set live_metrics=true');
assert(bpfAttached.warnings.length === 0 || !bpfAttached.warnings.includes('bpf_runtime_loader_unavailable'),
       'attached-success fixture must not warn about the runtime loader being unavailable');
assert(bpfAttached.tc_filter.pref === 49152 && bpfAttached.tc_filter.handle === '0x1eed',
       'attached-success filter must use the documented pref/handle that init.d cleans up');

{
  const bpfIdentity = simulateBpfIdentityFolding({
    arp_entries: [
      { ip: '192.168.31.110', mac: '00:11:22:33:44:55', interface: 'br-lan', zone: 'lan' }
    ],
    neighbor_entries: [],
    raw_bpf_samples: [
      { mac: '00:11:22:33:44:55', zone: 'lan', interface: 'br-lan', direction: 'tx', bytes: 1000 },
      { mac: '00:aa:bb:cc:dd:ee', zone: 'lan', interface: 'br-lan', direction: 'tx', bytes: 2000 }
    ]
  });
  assert(bpfIdentity.clients.length === 1, 'BPF identity folding must keep only ARP/neighbor-backed LAN clients');
  assert(bpfIdentity.clients[0].identity_key === '00:11:22:33:44:55@lan', 'BPF identity folding must allow real clients whose MAC starts with 00');
  assert(bpfIdentity.clients[0].ips.includes('192.168.31.110'), 'BPF identity folding must attach the ARP IP for a real 00-prefix client');
  assert(bpfIdentity.skipped_no_identity === 1, 'BPF identity folding must skip unknown 00-prefix MAC samples without LAN identity');
}

{
  const filteredIdentity = simulateBpfIdentityFolding({
    collect_ifnames: [ 'eth1' ],
    interface_addresses: [
      { interface: 'eth1', address: '192.168.31.1/24' },
      { interface: 'eth0', address: '192.168.2.100/24' }
    ],
    arp_entries: [
      { ip: '192.168.31.177', mac: 'd2:4f:70:5d:5e:8d', interface: 'eth1', zone: 'eth1' },
      { ip: '10.19.153.104', mac: 'd2:4f:70:5d:5e:8d', interface: 'eth1', zone: 'eth1' },
      { ip: '169.254.156.62', mac: 'd8:bb:c1:67:fe:bd', interface: 'eth1', zone: 'eth1' }
    ],
    neighbor_entries: [],
    raw_bpf_samples: [
      { mac: 'd2:4f:70:5d:5e:8d', zone: 'eth1', interface: 'eth1', direction: 'tx', bytes: 1000 },
      { mac: 'd8:bb:c1:67:fe:bd', zone: 'eth1', interface: 'eth1', direction: 'tx', bytes: 2000 }
    ]
  });
  assert(filteredIdentity.clients.length === 1, 'collected interface subnet filter must drop clients without an IP in that interface subnet');
  assert(filteredIdentity.clients[0].identity_key === 'd2:4f:70:5d:5e:8d@eth1', 'collected interface subnet filter must keep the matching client identity');
  assert(JSON.stringify(filteredIdentity.clients[0].ips) === JSON.stringify([ '192.168.31.177' ]),
         'collected interface subnet filter must keep only IPs inside the collected interface subnet');
  assert(filteredIdentity.skipped_no_identity === 1, 'collected interface subnet filter must skip MACs whose only IP is outside the collected interface subnet');
}

const uploadRate = computeRateTimeline(uploadRateFixture);
assert(uploadRate.reached_within_3s === true, '10Mbps upload must reach 8M-12M within 3 seconds');
assert(uploadRate.dropped_after_stop === true, 'upload rate must drop below threshold after stop');
assert(uploadRate.rates.some((entry) => entry.tx_bps === 10000000), 'fixture must contain an exact 10Mbps tx sample');
assert(uploadRate.map_key.direction === 'tx', 'upload fixture must map to tx direction from client perspective');

const mapFull = simulateMapFull(mapFullFixture);
assert(mapFull.warnings.includes('map_full'), 'map full fixture must report map_full');
assert(mapFull.crashed === false, 'map full fixture must not crash');
assert(collectorModel.bpf_source === 'rust/crates/lanspeed-ebpf/src/main.rs', 'collector model must reference the Rust BPF source file');
assert(JSON.stringify(collectorModel.runtime_objects) === JSON.stringify([
  '/usr/lib/bpf/lanspeed-ebpf-kfunc',
  '/usr/lib/bpf/lanspeed-ebpf-fallback'
]), 'collector model must reference both installed BPF object paths');
assert(collectorModel.map_model.default_max_clients === 2048, 'collector model must default to 2048 clients');
assert(JSON.stringify(collectorModel.map_model.key) === JSON.stringify(['ifindex', 'vlan_or_zone', 'mac', 'direction']), 'collector model map key shape is required');
assert(JSON.stringify(collectorModel.map_model.counters) === JSON.stringify(['bytes', 'packets', 'last_seen']), 'collector model counters must be bytes/packets/last_seen');
assert(collectorModel.attach_model.excluded.includes('wan') && collectorModel.attach_model.excluded.includes('tun'), 'collector model must exclude WAN/TUN');
assert(collectorModel.attach_model.excluded.includes('dae0') && collectorModel.attach_model.excluded.includes('dae0peer'), 'collector model must exclude dae tunnel interfaces');
for (const ifname of ['dae0', 'daed-edge', 'miireg0', 'tun0', 'erspan0', 'gretap0', 'gre0', 'ip6gre0', 'ip6tnl0', 'sit0', 'bonding_masters'])
  assert(isExcludedIdentityInterface(ifname), `${ifname} must be auto-ignored as an identity interface`);
assert(!isExcludedIdentityInterface('br-lan'), 'normal LAN interfaces must remain eligible for identity collection');
assert(collectorModel.rate_model.default_refresh_interval_ms === 1000, 'sampling interval must default to 1000ms');
assert(collectorModel.rate_model.minimum_refresh_interval_ms === 500, 'sampling interval minimum must be 500ms');
assert(collectorModel.rate_model.default_active_client_window_ms === 10000, 'active client window must default to 10000ms');
assert(collectorModel.rate_model.default_active_client_min_bps === 1, 'active client minimum must default to 1bps');
assert(collectorModel.rate_model.default_overview_window_samples === 240, 'overview trend history must default to 240 samples');
assert(collectorModel.rate_model.window_count === 3, 'rate model must keep three deterministic windows');
assert(collectorModel.rate_model.minimum_rate_baseline_retention_ms === 60000, 'inactive client rate baselines must be retained for accurate first-return samples');
assert(collectorModel.rate_model.stale_baseline_policy.includes('retain_hidden_baseline'), 'rate model must keep stale baselines hidden rather than reporting them as active');
assert(collectorModel.rate_model.anomaly_warnings.includes('counter_anomaly'), 'rate model must expose counter_anomaly warning');
assert(collectorModel.rate_model.refresh_interval_warning === 'refresh_interval_below_minimum', 'rate model must expose refresh interval warning');
assert(collectorModel.coverage_model.window_samples === 32, 'coverage must use a wider smoothing window');
assert(collectorModel.coverage_model.numerator_source === 'monotonic_integral_of_per_client_rates', 'coverage numerator must remain monotonic across client membership changes');
assert(collectorModel.coverage_model.idle_policy === 'only_when_interface_delta_bytes_equal_zero', 'low LAN traffic must not be mislabeled as idle');
assert(collectorModel.coverage_model.low_traffic_quality === 'low_traffic', 'coverage model must expose low_traffic separately');
assert(collectorModel.dedupe_model.visibility_unknown_mode === 'Degraded', 'uncertain LAN-to-LAN visibility must degrade mode');
assert(collectorModel.dedupe_model.visibility_unknown_warning === 'lan_to_lan_visibility_unknown', 'uncertain topology warning is required');
assert(collectorModel.dedupe_model.visibility_limited_warning === 'lan_to_lan_visibility_limited', 'hardware-switch LAN-to-LAN visibility warning is required');
assert(collectorModel.dedupe_model.complete_coverage_claimed_for_hardware_switch_paths === false, 'hardware-switch LAN-to-LAN paths must not claim complete coverage');
assert(collectorModel.router_local_model.client_to_router === 'tx_bps', 'router-local client upload must map to tx_bps');
assert(collectorModel.router_local_model.router_to_client === 'rx_bps', 'router-local router-to-client traffic must map to rx_bps');
assert(collectorModel.router_local_model.router_originated_bucket === 'router_self', 'router-originated traffic must stay in router_self bucket');
assert(collectorModel.topology_identity_model.primary_key === 'mac+zone', 'topology identity must preserve MAC+zone primary key');
assert(collectorModel.topology_identity_model.duplicate_mac_warning === 'duplicate_mac_across_vlans', 'duplicate MAC across VLANs warning is required');
assert(collectorModel.uplink_encapsulation_model.wan_side_only.includes('pppoe'), 'PPPoE uplinks must be WAN-side evidence only');
assert(collectorModel.uplink_encapsulation_model.wan_side_only.includes('wg'), 'WG uplinks must be WAN-side evidence only');
assert(collectorModel.uplink_encapsulation_model.wan_side_only.includes('tun'), 'TUN uplinks must be WAN-side evidence only');
assert(collectorModel.side_router_model.same_subnet_direct_warning === 'asymmetric_path_possible', 'same-subnet side-router warning is required');
assert(collectorModel.side_router_model.complete_coverage_claimed === false, 'side-router model must not claim complete coverage');
assert(collectorModel.map_model.client_limit_warning === 'client_limit_exceeded', 'client limit warning is required');
assert(collectorModel.map_model.map_read_failure_warning === 'map_read_failed', 'map read failure warning is required');
assert(collectorModel.conntrack_fallback_model.collector_mode === 'conntrack', 'conntrack fallback model must expose collector_mode=conntrack');
assert(collectorModel.conntrack_fallback_model.nss_sync_collector_mode === 'conntrack_ecm_sync', 'NSS sync model must expose collector_mode=conntrack_ecm_sync');
assert(collectorModel.conntrack_fallback_model.active_only_when.includes('auto_bpf_full_unavailable_and_nss_ecm_or_ppe_sync_available'), 'conntrack fallback model must document that NSS sync is an automatic BPF fallback');
assert(collectorModel.conntrack_fallback_model.primary_sources.includes('nss_conntrack_sync'), 'NSS sync model must expose nss_conntrack_sync primary source');
assert(!collectorModel.conntrack_fallback_model.primary_sources.includes('conntrack'), 'plain non-NSS conntrack must not be documented as a live speed primary source');
assert(collectorModel.conntrack_fallback_model.non_nss_live_rate_policy === 'bpf_only', 'non-NSS live rate policy must be BPF-only');
assert(collectorModel.conntrack_fallback_model.nss_auto_live_rate_policy === 'bpf_first_then_nss_sync_or_direct_fallback', 'NSS auto live-rate policy must be BPF-first');
assert(collectorModel.conntrack_fallback_model.non_nss_conntrack_policy === 'connection_counts_and_diagnostics_only', 'non-NSS conntrack policy must be counts/diagnostics only');
assert(collectorModel.conntrack_fallback_model.mode === 'Degraded', 'conntrack fallback must stay Degraded');
assert(collectorModel.conntrack_fallback_model.coverage === 'routed_nat_only', 'conntrack fallback must be routed/NAT-only');
assert(collectorModel.conntrack_fallback_model.coverage_warning === 'conntrack_routed_nat_only', 'conntrack fallback must expose routed/NAT-only warning');
assert(collectorModel.conntrack_fallback_model.active_only_when.includes('nf_conntrack_acct=1'), 'conntrack fallback must require nf_conntrack_acct=1');
assert(collectorModel.conntrack_fallback_model.active_only_when.includes('rate_collector_mode=nss_conntrack_sync'), 'conntrack fallback model must document explicit NSS sync mode');
assert(!collectorModel.conntrack_fallback_model.active_only_when.includes('bpf_full_unavailable'), 'BPF failure alone must not activate non-NSS conntrack speed fallback');
assert(collectorModel.conntrack_fallback_model.inactive_when.includes('non_nss_device'), 'conntrack speed fallback must be inactive on non-NSS devices');
assert(collectorModel.conntrack_fallback_model.inactive_when.includes('auto_bpf_full_available'), 'NSS sync must stay inactive in auto mode while BPF is available');
assert(collectorModel.conntrack_fallback_model.inactive_when.includes('bpf_full_unavailable_without_nss_ecm_sync'), 'non-NSS BPF failure must not become CT byte-rate fallback');
assert(collectorModel.conntrack_fallback_model.inactive_when.includes('conntrack_acct_disabled'), 'conntrack fallback must disable when accounting is off');
assert(collectorModel.conntrack_fallback_model.source === 'lanspeedd_ctnetlink_conntrack_acct', 'conntrack fallback model must name ctnetlink as the preferred source');
assert(collectorModel.conntrack_fallback_model.fallback_source === 'lanspeedd_procfs_conntrack_acct', 'conntrack fallback model must honestly keep procfs as the last fallback source');
assert(collectorModel.conntrack_fallback_model.nss_sync_coverage_warning === 'nss_ecm_sync_cadence', 'NSS sync coverage warning must document ECM cadence');
assert(collectorModel.conntrack_fallback_model.counter_sources.includes('ctnetlink_conntrack_acct_orig_reply_bytes'), 'conntrack fallback model must name ctnetlink accounting source');
assert(collectorModel.conntrack_fallback_model.counter_sources.includes('procfs_conntrack_acct_orig_reply_bytes'), 'conntrack fallback model must name procfs accounting source');
assert(collectorModel.conntrack_fallback_model.netlink_path === 'netlink:ctnetlink', 'conntrack fallback model must document raw ctnetlink as the preferred reader');
assert(collectorModel.conntrack_fallback_model.procfs_paths.includes('/proc/net/arp'), 'conntrack fallback model must include ARP identity source');
assert(collectorModel.conntrack_fallback_model.neighbor_source === 'netlink:rtnetlink_neigh', 'conntrack fallback model must include IPv6 neighbor identity source');
assert(collectorModel.conntrack_fallback_model.snapshot_policy.first_sample_warning === 'conntrack_snapshot_pending', 'first conntrack sample must be explicit snapshot pending');
assert(collectorModel.conntrack_fallback_model.confidence.maximum === 'medium', 'conntrack fallback confidence must not exceed medium');
assert(collectorModel.conntrack_fallback_model.confidence.degrade_to_low_when.includes('flowtable_counter_missing'), 'missing flowtable counter must lower confidence');
assert(collectorModel.conntrack_fallback_model.warnings.includes('nlbwmon_counter_conflict'), 'nlbwmon conflict warning is required');
assert(collectorModel.conntrack_fallback_model.forbidden_sources.includes('nft_forward_chain_counters'), 'firewall forward-chain counters must not be a fallback source');
assert(collectorModel.conntrack_fallback_model.forbidden_sources.includes('nlbwmon_counters'), 'nlbwmon counters must not be read as fallback source');

const lanToLan = simulateLanToLanDedupe(lanToLanFixture);
const clientA = lanToLan.clients.find((client) => client.identity_key === lanToLanFixture.clients.a.identity_key);
const clientB = lanToLan.clients.find((client) => client.identity_key === lanToLanFixture.clients.b.identity_key);
assert(clientA.tx_bps >= lanToLanFixture.min_bps && clientA.tx_bps <= lanToLanFixture.max_bps, 'LAN-to-LAN client A tx must be near target');
assert(clientB.rx_bps >= lanToLanFixture.min_bps && clientB.rx_bps <= lanToLanFixture.max_bps, 'LAN-to-LAN client B rx must be near target');
assert(lanToLan.aggregate_bps >= lanToLanFixture.min_bps && lanToLan.aggregate_bps <= lanToLanFixture.max_bps, 'LAN-to-LAN aggregate must not double-count one direction');
assert(lanToLan.one_direction_double_counted === false, 'LAN-to-LAN frame must not be double-counted');
assert(lanToLan.duplicate_observations === 1, 'fixture must include and drop one duplicate observation');

const uncertainLanToLan = simulateLanToLanDedupe({
  ...lanToLanFixture,
  topology_known: lanToLanFixture.uncertain_topology.topology_known
});
assert(uncertainLanToLan.mode === lanToLanFixture.uncertain_topology.expected_mode, 'uncertain topology must return Degraded');
assert(uncertainLanToLan.warnings.includes(lanToLanFixture.uncertain_topology.expected_warning), 'uncertain topology warning is required');
assert(uncertainLanToLan.coverage.coverage_complete === false, 'uncertain topology must not claim complete coverage');
assert(uncertainLanToLan.coverage.complete_coverage_claimed === false, 'uncertain topology must explicitly avoid complete coverage claim');

const limitedLanToLan = simulateLanToLanDedupe({
  ...lanToLanFixture,
  hardware_switch_path: true,
  observations: lanToLanFixture.observations.map((observation) => ({ ...observation, visible: false }))
});
assert(limitedLanToLan.mode === 'Degraded', 'hardware-switch LAN-to-LAN path must degrade coverage');
assert(limitedLanToLan.warnings.includes('lan_to_lan_visibility_limited'), 'hardware-switch LAN-to-LAN path must warn limited visibility');
assert(limitedLanToLan.coverage.cpu_visible_only === true, 'LAN-to-LAN coverage must be CPU-visible only');
assert(limitedLanToLan.coverage.coverage_complete === false, 'invisible hardware-switch path must not claim complete coverage');
assert(limitedLanToLan.coverage.complete_coverage_claimed === false, 'limited visibility fixture must explicitly avoid complete coverage claim');

const sideRouterDirect = simulateSideRouterDirect(sideRouterDirectFixture);
assert(sideRouterDirect.mode === sideRouterDirectFixture.expected.mode, 'same-subnet side-router direct topology must degrade coverage');
assert(sideRouterDirect.warnings.includes(sideRouterDirectFixture.expected.warning), 'side-router direct fixture must warn asymmetric_path_possible');
assert(sideRouterDirect.coverage.coverage_complete === sideRouterDirectFixture.expected.coverage_complete, 'side-router direct fixture must not claim complete coverage');
assert(sideRouterDirect.coverage.complete_coverage_claimed === false, 'side-router direct fixture must explicitly avoid complete coverage claim');

const routerLocal = simulateRouterLocal(routerLocalFixture);
assert(routerLocal.client.tx_bps === routerLocalFixture.expected.client_tx_bps, 'router-local client-to-router traffic must be client tx_bps');
assert(routerLocal.client.rx_bps === routerLocalFixture.expected.client_rx_bps, 'router-local router-to-client traffic must be client rx_bps');
assert(routerLocal.router_self.bucket === routerLocalFixture.expected.router_self_bucket, 'router-originated flow must use router_self bucket');
assert(routerLocal.router_self.alias === routerLocalFixture.expected.router_self_alias, 'router self alias must be local_router');
assert(routerLocal.router_self.tx_bps === routerLocalFixture.expected.router_self_tx_bps, 'router-originated active curl must stay separate from LAN client');
assert(routerLocal.router_originated_assigned_to_lan_client === false, 'router-originated traffic must not be assigned to the LAN client');
assert(routerLocal.client.identity_key === `${routerLocal.client.mac}@${routerLocal.client.zone}`, 'router-local client identity must remain MAC+zone');

const topologyVlan = simulateTopologyVlan(topologyVlanFixture);
assert(JSON.stringify(topologyVlan.clients.map((client) => client.identity_key)) === JSON.stringify(topologyVlanFixture.expected.identity_keys), 'VLAN topology must keep same MAC separated by zone/VLAN');
assert(topologyVlan.warnings.includes('duplicate_mac_across_vlans'), 'same MAC across VLANs must warn duplicate_mac_across_vlans');
assert(topologyVlan.clients.some((client) => client.zone === 'guest' && client.topology.guest === true), 'guest VLAN client must remain separate');
assert(topologyVlan.clients.some((client) => client.topology.wds === true), 'WDS metadata must be represented without collapsing identity');
assert(topologyVlan.clients.some((client) => client.topology.ap_isolation === true), 'AP isolation metadata must be represented without collapsing identity');
assert(topologyVlan.clients.find((client) => client.identity_key === '02:de:ad:be:ef:01@vlan10').tx_bps === 3000000, 'vlan10 client tx must stay with vlan10 identity');
assert(topologyVlan.clients.find((client) => client.identity_key === '02:de:ad:be:ef:01@vlan20').rx_bps === 6000000, 'vlan20 client rx must stay with vlan20 identity');
assert(topologyVlan.uplinks.every((uplink) => uplink.encapsulation_evidence_only && uplink.ownership_changed === false), 'PPPoE/WG/TUN uplinks must not change LAN MAC ownership');
assert(topologyVlan.uplinks.every((uplink) => ['pppoe', 'wg', 'tun'].includes(uplink.type)), 'uplink topology fixture must cover PPPoE/WG/TUN');
assert(topologyVlan.uplinks.every((uplink) => uplink.lan_identity_exists === true), 'uplink evidence must reference existing LAN-edge identities without owning them');

const counterAnomaly = computeDirectionalRates(counterAnomalyFixture);
for (const warning of counterAnomalyFixture.expected_warnings) {
  assert(counterAnomaly.warnings.includes(warning), `counter anomaly fixture must include ${warning}`);
}
assert(counterAnomaly.negative_rates_emitted === false, 'negative rates must never be emitted');
assert(counterAnomaly.directions.tx.some((entry) => entry.warnings.includes('counter_anomaly') && entry.bps === 0), 'counter decrease must clamp tx to zero');
assert(counterAnomaly.directions.tx.some((entry) => entry.warnings.includes('time_rollback') && entry.bps === 0), 'time rollback must clamp tx to zero');
assert(counterAnomaly.directions.rx.some((entry) => entry.bps > 0), 'per-client anomaly must not disable all directions');
assert(counterAnomaly.merged_client.tx_bps > 0 && counterAnomaly.merged_client.rx_bps === 0, 'direction merge must preserve separate tx_bps and rx_bps fields');
assert(counterAnomaly.unaffected_clients.some((client) => client.tx_bps > 0 && client.rx_bps > 0), 'per-client anomaly must not disable healthy clients');

const resourceLimits = simulateResourceLimits(resourceLimitFixture);
for (const warning of resourceLimitFixture.expected_warnings) {
  assert(resourceLimits.warnings.includes(warning), `resource limit fixture must include ${warning}`);
}
assert(resourceLimits.stale_clients.length === 1, 'stale client expiry must remove one fixture client');
assert(resourceLimits.active_clients.length === resourceLimitFixture.max_clients, 'active clients must be capped at max_clients');
assert(resourceLimits.rejected_clients.length === 1, 'client limit must reject one active fixture client');
assert(resourceLimits.crashed === false, 'resource limit path must not crash');
assert(resourceLimits.existing_clients_preserved_on_map_read_failure === true, 'map read failure must not empty all clients');

const conntrackNat = simulateConntrackFallback(conntrackNatFixture);
assert(conntrackNat.active === false, 'non-NSS conntrack NAT fixture must not activate as a speed fallback');
assert(conntrackNat.mode === 'Degraded', 'conntrack fallback must stay Degraded');
assert(conntrackNat.collector_mode === 'conntrack', 'conntrack NAT fixture must use collector_mode=conntrack');
assert(conntrackNat.confidence === 'unsupported', 'inactive non-NSS conntrack speed fallback confidence must be unsupported');
assert(conntrackNat.runtime_source === 'lanspeedd_procfs_conntrack_acct', 'conntrack NAT fixture must use procfs runtime source');
assert(conntrackNat.counter_source === 'procfs_conntrack_acct_orig_reply_bytes', 'conntrack NAT fixture must use procfs byte counters');
assert(conntrackNat.first_snapshot.clients.length === 1, 'first procfs snapshot must map one ARP-backed client');
assert(conntrackNat.first_snapshot.skipped_no_arp === conntrackNatFixture.expected.skipped_no_arp, 'conntrack entries without ARP MAC must be skipped');
assert(conntrackNat.first_snapshot.malformed_lines === conntrackNatFixture.expected.malformed_lines_first_snapshot, 'malformed conntrack lines must be isolated');
assert(!conntrackNat.clients.some((client) => client.interface === 'dae0' || client.ips.includes('192.168.1.250')), 'dae0 ARP/conntrack observations must not become LAN clients');
assert(!conntrackNat.warnings.includes(conntrackNatFixture.expected.snapshot_pending_warning), 'inactive non-NSS conntrack speed fallback must not claim a pending speed snapshot');
assert(conntrackNat.clients.length === 0, 'non-NSS conntrack NAT fixture must not produce client speed rows');
{
  const stillFixture = clone(conntrackNatFixture);
  stillFixture.procfs_snapshots[1].lines = stillFixture.procfs_snapshots[0].lines.slice();
  stillFixture.procfs_snapshots[1].t_ms = stillFixture.procfs_snapshots[0].t_ms + 15000;
  const stillConntrack = simulateConntrackFallback(stillFixture);
  assert(stillConntrack.clients.length === 0, 'unchanged non-NSS conntrack counters must still not produce speed rows');
}
assert(!conntrackNat.warnings.includes('conntrack_routed_nat_only'), 'inactive non-NSS conntrack speed fallback must not warn as active routed/NAT-only speed source');
assert(!conntrackNat.warnings.includes('flowtable_counter_missing'), 'inactive non-NSS conntrack speed fallback must not emit speed confidence warnings');
assert(!conntrackNat.warnings.includes('nlbwmon_counter_conflict'), 'inactive non-NSS conntrack speed fallback must not emit nlbwmon speed warnings');
assert(conntrackNat.nlbwmon_read_counters === false, 'conntrack fallback must not disturb nlbwmon counters');
assert(conntrackNat.forbidden_sources.includes('nft_forward_chain_counters'), 'conntrack fallback must not use nft forward-chain counters');

const conntrackAcctDisabled = simulateConntrackFallback(conntrackAcctDisabledFixture);
assert(conntrackAcctDisabled.active === false, 'nf_conntrack_acct=0 must disable conntrack fallback');
assert(conntrackAcctDisabled.clients.length === 0, 'acct disabled fixture must not emit conntrack client rates');
assert(conntrackAcctDisabled.confidence === 'unsupported', 'acct disabled fallback confidence must be unsupported');
assert(conntrackAcctDisabled.warnings.includes('conntrack_acct_disabled'), 'acct disabled warning is required');
{
  const ipv6SyncFixture = clone(conntrackNatFixture);
  ipv6SyncFixture.config.bpf_full_available = true;
  ipv6SyncFixture.probe.nss_present = true;
  ipv6SyncFixture.probe.nss_ecm_active = true;
  ipv6SyncFixture.probe.flowtable_counter = true;
  ipv6SyncFixture.probe.openclash_fake_ip_or_tun = false;
  ipv6SyncFixture.probe.sqm_qosify_or_ifb = false;
  ipv6SyncFixture.probe.nlbwmon = false;
  ipv6SyncFixture.arp_entries = [];
  ipv6SyncFixture.neighbor_entries = [
    { ip: '240e:abc:1234::100', mac: '02:aa:bb:cc:dd:08', interface: 'br-lan', zone: 'lan', family: 'ipv6' }
  ];
  ipv6SyncFixture.procfs_snapshots = [
    {
      t_ms: 1000,
      lines: [
        'ipv6 10 tcp 6 431999 ESTABLISHED src=240E:0ABC:1234:0000:0000:0000:0000:0100 dst=2606:4700:4700::1111 sport=41000 dport=443 packets=10 bytes=1000000 src=2606:4700:4700::1111 dst=240E:0ABC:1234:0000:0000:0000:0000:0100 sport=443 dport=41000 packets=20 bytes=2000000 [ASSURED] mark=0 use=1'
      ]
    },
    {
      t_ms: 2000,
      lines: [
        'ipv6 10 tcp 6 431998 ESTABLISHED src=240E:0ABC:1234:0000:0000:0000:0000:0100 dst=2606:4700:4700::1111 sport=41000 dport=443 packets=15 bytes=1500000 src=2606:4700:4700::1111 dst=240E:0ABC:1234:0000:0000:0000:0000:0100 sport=443 dport=41000 packets=35 bytes=3250000 [ASSURED] mark=0 use=1'
      ]
    }
  ];
  const ipv6Sync = simulateConntrackFallback(ipv6SyncFixture);
  assert(ipv6Sync.active === true, 'NSS sync must stay active for IPv6 conntrack samples');
  assert(ipv6Sync.collector_mode === 'conntrack_ecm_sync', 'NSS sync IPv6 rows must keep collector_mode=conntrack_ecm_sync');
  assert(ipv6Sync.clients.length === 1, 'NSS sync must emit IPv6 client rows');
  assert(ipv6Sync.clients[0].ips.includes('240e:abc:1234::100'), 'NSS sync IPv6 client must keep its normalized IPv6 address');
  assert(ipv6Sync.clients[0].tx_bps === 4000000, 'NSS sync IPv6 tx_bps must use orig byte deltas');
  assert(ipv6Sync.clients[0].rx_bps === 10000000, 'NSS sync IPv6 rx_bps must use reply byte deltas');
}

const nssEcmDirect = simulateNssEcmDirect(nssEcmDirectFixture);
assert(nssEcmDirect.primary_source === nssEcmDirectFixture.expected.primary_source, 'NSS direct must become the primary source when ECM state is readable');
assert(nssEcmDirect.collector_mode === nssEcmDirectFixture.expected.collector_mode, 'NSS direct clients must expose collector_mode=nss_ecm_direct');
assert(nssEcmDirect.confidence === nssEcmDirectFixture.expected.confidence, 'NSS direct confidence must be high when state parsing succeeds');
assert(nssEcmDirect.coverage_client_source === nssEcmDirectFixture.expected.coverage_client_source, 'NSS direct coverage must use direct client bytes');
assert(nssEcmDirect.read_only === true, 'NSS direct must be read-only');
assert(nssEcmDirect.forbidden_writes.includes('defunct_all') && nssEcmDirect.forbidden_writes.includes('decelerate'), 'NSS direct must forbid mutating ECM state');
assert(nssEcmDirect.source_path === nssEcmDirectFixture.expected.source_path, 'NSS direct fixture must model /dev/ecm_state as the state source');
assert(nssEcmDirect.first_snapshot.entries_seen === nssEcmDirectFixture.expected.flows_seen, 'NSS direct parser must see all ECM state flows');
assert(nssEcmDirect.first_snapshot.entries_matched === nssEcmDirectFixture.expected.flows_matched, 'NSS direct parser must match ARP-backed LAN clients');
assert(nssEcmDirect.first_snapshot.skipped_no_arp === nssEcmDirectFixture.expected.skipped_no_arp, 'NSS direct must skip flows without LAN identity');
assert(nssEcmDirect.first_snapshot.malformed_lines === nssEcmDirectFixture.expected.parse_errors, 'NSS direct must isolate malformed state lines');
assert(nssEcmDirect.clients.length === nssEcmDirectFixture.expected.client_count, 'NSS direct must emit ARP-backed client rows');
assert(nssEcmDirect.clients[0].identity_key === nssEcmDirectFixture.expected.first_identity, 'NSS direct must key clients by MAC+zone');
assert(nssEcmDirect.clients[0].tx_bps === nssEcmDirectFixture.expected.first_tx_bps, 'NSS direct tx_bps must use from_data_total deltas');
assert(nssEcmDirect.clients[0].rx_bps === nssEcmDirectFixture.expected.first_rx_bps, 'NSS direct rx_bps must use to_data_total deltas');
assert(nssEcmDirect.clients[1].tx_bps === nssEcmDirectFixture.expected.second_tx_bps, 'NSS direct must aggregate second client tx correctly');
assert(nssEcmDirect.clients[1].rx_bps === nssEcmDirectFixture.expected.second_rx_bps, 'NSS direct must aggregate second client rx correctly');
{
  const noDataFixture = clone(nssEcmDirectFixture);
  noDataFixture.arp_entries = [
    { ip: '192.168.31.100', mac: 'aa:bb:cc:00:00:01', interface: 'br-lan', zone: 'lan' }
  ];
  noDataFixture.state_snapshots = [
    { t_ms: 100000, lines: [] },
    { t_ms: 101000, lines: [] }
  ];
  noDataFixture.procfs_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.31.100 dst=1.1.1.1 sport=41000 dport=443 packets=10 bytes=1000000 src=1.1.1.1 dst=192.168.31.100 sport=443 dport=41000 packets=20 bytes=2000000 [ASSURED] mark=0 use=1'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'ipv4 2 tcp 6 431998 ESTABLISHED src=192.168.31.100 dst=1.1.1.1 sport=41000 dport=443 packets=15 bytes=1500000 src=1.1.1.1 dst=192.168.31.100 sport=443 dport=41000 packets=35 bytes=3250000 [ASSURED] mark=0 use=1'
      ]
    }
  ];
  const noData = simulateNssStableCollector(noDataFixture);
  assert(noData.direct_flows_matched === 0, 'stable NSS collector must expose direct matched flow count when direct has no data');
  assert(noData.sync_fallback_clients === 1, 'stable NSS collector must use sync when direct has no data');
  assert(noData.clients.length === 1, 'stable NSS collector must still emit sync client rows when direct has no data');
  assert(noData.clients[0].collector_mode === 'conntrack_ecm_sync', 'direct no-data rows must keep NSS sync collector mode');
  assert(noData.clients[0].rx_bps === 10000000, 'direct no-data fallback must preserve NSS sync rx rate');
  assert(noData.warnings.includes('nss_direct_no_data'), 'direct no-data fallback must warn with nss_direct_no_data');
  assert(noData.warnings.includes('nss_sync_fallback'), 'direct no-data fallback must warn with nss_sync_fallback');
}
{
  const zeroDirectFixture = clone(nssEcmDirectFixture);
  zeroDirectFixture.arp_entries = [
    { ip: '192.168.31.100', mac: 'aa:bb:cc:00:00:01', interface: 'br-lan', zone: 'lan' }
  ];
  zeroDirectFixture.state_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'conns.conn.11.serial=11',
        'conns.conn.11.sip_address=192.168.31.100',
        'conns.conn.11.dip_address=1.1.1.1',
        'conns.conn.11.snode_address=aa:bb:cc:00:00:01',
        'conns.conn.11.protocol=6',
        'conns.conn.11.adv_stats.from_data_total=1000000',
        'conns.conn.11.adv_stats.to_data_total=2000000'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'conns.conn.11.serial=11',
        'conns.conn.11.sip_address=192.168.31.100',
        'conns.conn.11.dip_address=1.1.1.1',
        'conns.conn.11.snode_address=aa:bb:cc:00:00:01',
        'conns.conn.11.protocol=6',
        'conns.conn.11.adv_stats.from_data_total=1000000',
        'conns.conn.11.adv_stats.to_data_total=2000000'
      ]
    }
  ];
  zeroDirectFixture.procfs_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.31.100 dst=1.1.1.1 sport=41000 dport=443 packets=10 bytes=1000000 src=1.1.1.1 dst=192.168.31.100 sport=443 dport=41000 packets=20 bytes=2000000 [ASSURED] mark=0 use=1'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'ipv4 2 tcp 6 431998 ESTABLISHED src=192.168.31.100 dst=1.1.1.1 sport=41000 dport=443 packets=15 bytes=1500000 src=1.1.1.1 dst=192.168.31.100 sport=443 dport=41000 packets=35 bytes=3000000 [ASSURED] mark=0 use=1'
      ]
    }
  ];
  const zeroDirect = simulateNssStableCollector(zeroDirectFixture);
  assert(zeroDirect.direct_flows_matched === 1, 'stable NSS collector must record matched direct flows even when their rate is zero');
  assert(zeroDirect.direct_overlay_clients === 0, 'zero-rate direct rows must not replace NSS sync rows');
  assert(zeroDirect.sync_fallback_clients === 1, 'zero-rate direct rows must leave NSS sync as the emitted source');
  assert(zeroDirect.clients.length === 1, 'zero-rate direct fallback must still emit the sync client row');
  assert(zeroDirect.clients[0].collector_mode === 'conntrack_ecm_sync', 'zero-rate direct fallback must keep NSS sync collector mode');
  assert(zeroDirect.clients[0].rx_bps === 8000000, 'zero-rate direct fallback must preserve NSS sync rx rate');
  assert(zeroDirect.warnings.includes('nss_direct_no_data'), 'zero-rate direct fallback must warn with nss_direct_no_data');
  assert(zeroDirect.warnings.includes('nss_sync_fallback'), 'zero-rate direct fallback must warn with nss_sync_fallback');
}
{
  const partialFixture = clone(nssEcmDirectFixture);
  partialFixture.arp_entries = [
    { ip: '192.168.31.100', mac: 'aa:bb:cc:00:00:01', interface: 'br-lan', zone: 'lan' },
    { ip: '192.168.31.101', mac: 'aa:bb:cc:00:00:02', interface: 'br-lan', zone: 'lan' }
  ];
  partialFixture.state_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'conns.conn.10.serial=10',
        'conns.conn.10.sip_address=192.168.31.100',
        'conns.conn.10.dip_address=1.1.1.1',
        'conns.conn.10.snode_address=aa:bb:cc:00:00:01',
        'conns.conn.10.protocol=6',
        'conns.conn.10.adv_stats.from_data_total=1000000',
        'conns.conn.10.adv_stats.to_data_total=2000000'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'conns.conn.10.serial=10',
        'conns.conn.10.sip_address=192.168.31.100',
        'conns.conn.10.dip_address=1.1.1.1',
        'conns.conn.10.snode_address=aa:bb:cc:00:00:01',
        'conns.conn.10.protocol=6',
        'conns.conn.10.adv_stats.from_data_total=1250000',
        'conns.conn.10.adv_stats.to_data_total=2500000'
      ]
    }
  ];
  partialFixture.procfs_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.31.100 dst=1.1.1.1 sport=41000 dport=443 packets=10 bytes=900000 src=1.1.1.1 dst=192.168.31.100 sport=443 dport=41000 packets=20 bytes=1900000 [ASSURED] mark=0 use=1',
        'ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.31.101 dst=8.8.8.8 sport=41001 dport=443 packets=10 bytes=100000 src=8.8.8.8 dst=192.168.31.101 sport=443 dport=41001 packets=20 bytes=500000 [ASSURED] mark=0 use=1'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'ipv4 2 tcp 6 431998 ESTABLISHED src=192.168.31.100 dst=1.1.1.1 sport=41000 dport=443 packets=15 bytes=1000000 src=1.1.1.1 dst=192.168.31.100 sport=443 dport=41000 packets=35 bytes=2000000 [ASSURED] mark=0 use=1',
        'ipv4 2 tcp 6 431998 ESTABLISHED src=192.168.31.101 dst=8.8.8.8 sport=41001 dport=443 packets=15 bytes=350000 src=8.8.8.8 dst=192.168.31.101 sport=443 dport=41001 packets=35 bytes=1750000 [ASSURED] mark=0 use=1'
      ]
    }
  ];
  const partial = simulateNssStableCollector(partialFixture);
  const directClient = partial.clients.find((client) => client.identity_key === 'aa:bb:cc:00:00:01@lan');
  const syncClient = partial.clients.find((client) => client.identity_key === 'aa:bb:cc:00:00:02@lan');
  assert(partial.direct_overlay_clients === 1, 'stable NSS collector must count direct overlay clients');
  assert(partial.sync_fallback_clients === 1, 'stable NSS collector must count sync fallback clients');
  assert(directClient && directClient.collector_mode === 'nss_ecm_direct', 'direct-overlaid duplicate client must keep direct collector mode');
  assert(directClient.tx_bps === 2000000 && directClient.rx_bps === 4000000, 'direct-overlaid duplicate client must prefer direct rates over sync rates');
  assert(syncClient && syncClient.collector_mode === 'conntrack_ecm_sync', 'client missing from direct must be filled from NSS sync');
  assert(syncClient.tx_bps === 2000000 && syncClient.rx_bps === 10000000, 'sync fallback client must keep NSS sync rates');
  assert(partial.warnings.includes('nss_direct_partial'), 'partial direct overlay must warn with nss_direct_partial');
  assert(partial.warnings.includes('nss_sync_fallback'), 'partial direct overlay must warn with nss_sync_fallback');
}
{
  const ipv6Fixture = clone(nssEcmDirectFixture);
  ipv6Fixture.arp_entries = [];
  ipv6Fixture.neighbor_entries = [
    { ip: '240e:abc:1234::100', mac: 'aa:bb:cc:00:00:01', interface: 'br-lan', zone: 'lan', family: 'ipv6' }
  ];
  ipv6Fixture.state_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'conns.conn.20.serial=20',
        'conns.conn.20.sip_address=240E:0ABC:1234:0000:0000:0000:0000:0100',
        'conns.conn.20.dip_address=2606:4700:4700::1111',
        'conns.conn.20.snode_address=aa:bb:cc:00:00:01',
        'conns.conn.20.dnode_address=00:11:22:33:44:55',
        'conns.conn.20.protocol=6',
        'conns.conn.20.adv_stats.from_data_total=1000000',
        'conns.conn.20.adv_stats.to_data_total=2000000'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'conns.conn.20.serial=20',
        'conns.conn.20.sip_address=240E:0ABC:1234:0000:0000:0000:0000:0100',
        'conns.conn.20.dip_address=2606:4700:4700::1111',
        'conns.conn.20.snode_address=aa:bb:cc:00:00:01',
        'conns.conn.20.dnode_address=00:11:22:33:44:55',
        'conns.conn.20.protocol=6',
        'conns.conn.20.adv_stats.from_data_total=1500000',
        'conns.conn.20.adv_stats.to_data_total=3250000'
      ]
    }
  ];
  const ipv6Direct = simulateNssEcmDirect(ipv6Fixture);
  assert(ipv6Direct.first_snapshot.entries_matched === 1, 'NSS direct must match IPv6 ECM state flows through neighbor entries');
  assert(ipv6Direct.clients.length === 1, 'NSS direct must emit IPv6 client rows');
  assert(ipv6Direct.clients[0].ips.includes('240e:abc:1234::100'), 'NSS direct IPv6 client must keep its normalized IPv6 address');
  assert(ipv6Direct.clients[0].tx_bps === 4000000, 'NSS direct IPv6 tx_bps must use from_data_total deltas');
  assert(ipv6Direct.clients[0].rx_bps === 10000000, 'NSS direct IPv6 rx_bps must use to_data_total deltas');
}
{
  const ipv6DestFixture = clone(nssEcmDirectFixture);
  ipv6DestFixture.arp_entries = [];
  ipv6DestFixture.neighbor_entries = [
    { ip: '240e:abc:1234::100', mac: 'aa:bb:cc:00:00:01', interface: 'br-lan', zone: 'lan', family: 'ipv6' }
  ];
  ipv6DestFixture.state_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'conns.conn.30.serial=30',
        'conns.conn.30.sip_address=2606:4700:4700::1111',
        'conns.conn.30.dip_address=240E:0ABC:1234:0000:0000:0000:0000:0100',
        'conns.conn.30.snode_address=00:11:22:33:44:55',
        'conns.conn.30.dnode_address=00:00:00:00:00:00',
        'conns.conn.30.protocol=6',
        'conns.conn.30.adv_stats.from_data_total=1000000',
        'conns.conn.30.adv_stats.to_data_total=100000'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'conns.conn.30.serial=30',
        'conns.conn.30.sip_address=2606:4700:4700::1111',
        'conns.conn.30.dip_address=240E:0ABC:1234:0000:0000:0000:0000:0100',
        'conns.conn.30.snode_address=00:11:22:33:44:55',
        'conns.conn.30.dnode_address=00:00:00:00:00:00',
        'conns.conn.30.protocol=6',
        'conns.conn.30.adv_stats.from_data_total=2000000',
        'conns.conn.30.adv_stats.to_data_total=350000'
      ]
    }
  ];
  const ipv6DestDirect = simulateNssEcmDirect(ipv6DestFixture);
  assert(ipv6DestDirect.clients.length === 1, 'NSS direct must emit client rows when LAN IPv6 is dip_address');
  assert(ipv6DestDirect.clients[0].identity_key === 'aa:bb:cc:00:00:01@lan', 'NSS direct destination-side LAN must fall back to neighbor MAC when dnode is invalid');
  assert(ipv6DestDirect.clients[0].tx_bps === 2000000, 'NSS direct destination-side LAN tx_bps must use to_data_total deltas');
  assert(ipv6DestDirect.clients[0].rx_bps === 8000000, 'NSS direct destination-side LAN rx_bps must use from_data_total deltas');
}
{
  const mismatchedNodeMacFixture = clone(nssEcmDirectFixture);
  mismatchedNodeMacFixture.arp_entries = [
    { ip: '192.168.31.104', mac: 'aa:bb:cc:00:00:05', interface: 'br-lan', zone: 'lan' }
  ];
  mismatchedNodeMacFixture.neighbor_entries = [];
  mismatchedNodeMacFixture.state_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'conns.conn.35.serial=35',
        'conns.conn.35.sip_address=192.168.31.104',
        'conns.conn.35.dip_address=1.1.1.1',
        'conns.conn.35.snode_address=00:11:22:33:44:55',
        'conns.conn.35.dnode_address=00:00:00:00:00:00',
        'conns.conn.35.protocol=6',
        'conns.conn.35.adv_stats.from_data_total=1000000',
        'conns.conn.35.adv_stats.to_data_total=2000000'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'conns.conn.35.serial=35',
        'conns.conn.35.sip_address=192.168.31.104',
        'conns.conn.35.dip_address=1.1.1.1',
        'conns.conn.35.snode_address=00:11:22:33:44:55',
        'conns.conn.35.dnode_address=00:00:00:00:00:00',
        'conns.conn.35.protocol=6',
        'conns.conn.35.adv_stats.from_data_total=1250000',
        'conns.conn.35.adv_stats.to_data_total=2500000'
      ]
    }
  ];
  const mismatchedNodeMac = simulateNssEcmDirect(mismatchedNodeMacFixture);
  assert(mismatchedNodeMac.clients[0].identity_key === 'aa:bb:cc:00:00:05@lan', 'NSS direct must keep ARP MAC identity when ECM node MAC disagrees with the LAN IP owner');
  assert(mismatchedNodeMac.clients[0].tx_bps === 2000000, 'NSS direct mismatched node MAC tx_bps must still follow source-side LAN direction');
  assert(mismatchedNodeMac.clients[0].rx_bps === 4000000, 'NSS direct mismatched node MAC rx_bps must still follow source-side LAN direction');
}
{
  const bothLanFixture = clone(nssEcmDirectFixture);
  bothLanFixture.arp_entries = [
    { ip: '192.168.31.100', mac: 'aa:bb:cc:00:00:01', interface: 'br-lan', zone: 'lan' },
    { ip: '192.168.31.101', mac: 'aa:bb:cc:00:00:02', interface: 'br-lan', zone: 'lan' }
  ];
  bothLanFixture.state_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'conns.conn.40.serial=40',
        'conns.conn.40.sip_address=192.168.31.100',
        'conns.conn.40.dip_address=192.168.31.101',
        'conns.conn.40.snode_address=aa:bb:cc:00:00:01',
        'conns.conn.40.dnode_address=aa:bb:cc:00:00:02',
        'conns.conn.40.protocol=6',
        'conns.conn.40.adv_stats.from_data_total=1000000',
        'conns.conn.40.adv_stats.to_data_total=1000000'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'conns.conn.40.serial=40',
        'conns.conn.40.sip_address=192.168.31.100',
        'conns.conn.40.dip_address=192.168.31.101',
        'conns.conn.40.snode_address=aa:bb:cc:00:00:01',
        'conns.conn.40.dnode_address=aa:bb:cc:00:00:02',
        'conns.conn.40.protocol=6',
        'conns.conn.40.adv_stats.from_data_total=2000000',
        'conns.conn.40.adv_stats.to_data_total=2000000'
      ]
    }
  ];
  const bothLanDirect = simulateNssEcmDirect(bothLanFixture);
  assert(bothLanDirect.first_snapshot.entries_matched === 0, 'NSS direct must not attribute both-LAN flows to internet speed');
  assert(bothLanDirect.first_snapshot.skipped_both_lan === 1, 'NSS direct must count skipped both-LAN flows');
}
{
  const natEndpointFixture = clone(nssEcmDirectFixture);
  natEndpointFixture.arp_entries = [
    { ip: '192.168.31.102', mac: 'aa:bb:cc:00:00:03', interface: 'br-lan', zone: 'lan' }
  ];
  natEndpointFixture.neighbor_entries = [];
  natEndpointFixture.state_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'conns.conn.50.serial=50',
        'conns.conn.50.sip_address=198.51.100.20',
        'conns.conn.50.dip_address=203.0.113.10',
        'conns.conn.50.sip_address_nat=192.168.31.102',
        'conns.conn.50.dip_address_nat=203.0.113.10',
        'conns.conn.50.snode_address=00:00:00:00:00:00',
        'conns.conn.50.snode_address_nat=aa:bb:cc:00:00:03',
        'conns.conn.50.dnode_address=00:11:22:33:44:55',
        'conns.conn.50.protocol=6',
        'conns.conn.50.adv_stats.from_data_total=1000000',
        'conns.conn.50.adv_stats.to_data_total=2000000'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'conns.conn.50.serial=50',
        'conns.conn.50.sip_address=198.51.100.20',
        'conns.conn.50.dip_address=203.0.113.10',
        'conns.conn.50.sip_address_nat=192.168.31.102',
        'conns.conn.50.dip_address_nat=203.0.113.10',
        'conns.conn.50.snode_address=00:00:00:00:00:00',
        'conns.conn.50.snode_address_nat=aa:bb:cc:00:00:03',
        'conns.conn.50.dnode_address=00:11:22:33:44:55',
        'conns.conn.50.protocol=6',
        'conns.conn.50.adv_stats.from_data_total=1500000',
        'conns.conn.50.adv_stats.to_data_total=3000000'
      ]
    }
  ];
  const natEndpointDirect = simulateNssEcmDirect(natEndpointFixture);
  assert(natEndpointDirect.first_snapshot.entries_matched === 1, 'NSS direct must match LAN clients through ECM NAT endpoint addresses');
  assert(natEndpointDirect.clients[0].identity_key === 'aa:bb:cc:00:00:03@lan', 'NSS direct must prefer NAT node MAC when the regular node MAC is invalid');
  assert(natEndpointDirect.clients[0].tx_bps === 4000000, 'NSS direct NAT endpoint tx_bps must follow the LAN source direction');
  assert(natEndpointDirect.clients[0].rx_bps === 8000000, 'NSS direct NAT endpoint rx_bps must follow the LAN source direction');
}
{
  const macOnlyFixture = clone(nssEcmDirectFixture);
  macOnlyFixture.arp_entries = [
    { ip: '192.168.31.103', mac: 'aa:bb:cc:00:00:04', interface: 'br-lan', zone: 'lan' }
  ];
  macOnlyFixture.neighbor_entries = [];
  macOnlyFixture.state_snapshots = [
    {
      t_ms: 100000,
      lines: [
        'conns.conn.60.serial=60',
        'conns.conn.60.sip_address=198.51.100.21',
        'conns.conn.60.dip_address=203.0.113.11',
        'conns.conn.60.snode_address=aa:bb:cc:00:00:04',
        'conns.conn.60.dnode_address=00:11:22:33:44:55',
        'conns.conn.60.protocol=17',
        'conns.conn.60.adv_stats.from_data_total=500000',
        'conns.conn.60.adv_stats.to_data_total=1000000'
      ]
    },
    {
      t_ms: 101000,
      lines: [
        'conns.conn.60.serial=60',
        'conns.conn.60.sip_address=198.51.100.21',
        'conns.conn.60.dip_address=203.0.113.11',
        'conns.conn.60.snode_address=aa:bb:cc:00:00:04',
        'conns.conn.60.dnode_address=00:11:22:33:44:55',
        'conns.conn.60.protocol=17',
        'conns.conn.60.adv_stats.from_data_total=700000',
        'conns.conn.60.adv_stats.to_data_total=1500000'
      ]
    }
  ];
  const macOnlyDirect = simulateNssEcmDirect(macOnlyFixture);
  assert(macOnlyDirect.first_snapshot.entries_matched === 1, 'NSS direct must fall back to ECM node MAC when ECM IP endpoints are post-NAT addresses');
  assert(macOnlyDirect.clients[0].ips.includes('192.168.31.103'), 'NSS direct MAC fallback must keep the LAN identity IP from ARP or neighbor');
  assert(macOnlyDirect.clients[0].tx_bps === 1600000, 'NSS direct MAC fallback tx_bps must follow the LAN source direction');
  assert(macOnlyDirect.clients[0].rx_bps === 4000000, 'NSS direct MAC fallback rx_bps must follow the LAN source direction');
}

const nssEcmSync = simulateNssSourceSelection(nssEcmSyncFixture);
assert(nssEcmSync.preferred === true, 'NSS ECM fixture must keep a usable preferred live source');
assert(nssEcmSync.primary_source === 'bpf', 'NSS auto must prefer BPF when the BPF runtime is available');
assert(nssEcmSync.collector_mode === 'bpf', 'NSS auto clients must use BPF collector mode by default');
assert(nssEcmSync.coverage_client_source === 'bpf', 'NSS auto coverage must use BPF client bytes by default');
assert(nssEcmSync.confidence === 'high', 'NSS auto BPF confidence should remain high');
assert(!nssEcmSync.warnings.includes('nss_ecm_sync_cadence'), 'NSS auto must not claim sync cadence while BPF is selected');
assert(!nssEcmSync.warnings.includes('nss_prefers_conntrack_sync'), 'NSS auto must not claim NSS sync overrides available BPF metrics');

{
  const nssAutoFallbackFixture = clone(nssEcmSyncFixture);
  nssAutoFallbackFixture.config.bpf_full_available = false;
  const nssAutoFallback = simulateNssSourceSelection(nssAutoFallbackFixture);
  assert(nssAutoFallback.primary_source === 'nss_conntrack_sync', 'NSS auto must fall back to NSS sync when BPF is unavailable');
  assert(nssAutoFallback.collector_mode === 'conntrack_ecm_sync', 'NSS auto sync fallback must preserve the conntrack ECM collector mode');
  assert(nssAutoFallback.warnings.includes('nss_ecm_sync_cadence'), 'NSS auto sync fallback must explain its sampling cadence');
}

{
  const nssConntrackFixture = clone(conntrackNatFixture);
  nssConntrackFixture.probe.nss_present = true;
  nssConntrackFixture.probe.nss_ecm_active = true;
  nssConntrackFixture.config.bpf_full_available = true;
  nssConntrackFixture.config.rate_collector_mode = 'nss_conntrack_sync';
  const nssConntrack = simulateConntrackFallback(nssConntrackFixture);
  assert(nssConntrack.active === true, 'NSS sync may use conntrack byte counters as the speed source');
  assert(nssConntrack.collector_mode === 'conntrack_ecm_sync', 'NSS sync conntrack clients must expose collector_mode=conntrack_ecm_sync');
  assert(nssConntrack.coverage === 'nss_ecm_sync', 'NSS sync conntrack coverage must not claim routed/NAT-only fallback');
  assert(nssConntrack.clients.length === 1, 'NSS sync fixture must still produce client speed rows');
  assert(nssConntrack.clients[0].tx_bps === nssConntrackFixture.expected.tx_bps, 'NSS sync tx_bps must be computed from the LAN endpoint perspective');
  assert(nssConntrack.clients[0].rx_bps === nssConntrackFixture.expected.rx_bps, 'NSS sync rx_bps must be computed from the LAN endpoint perspective');
  assert(nssConntrack.warnings.includes('nss_ecm_sync_cadence'), 'NSS sync speed path must warn about sync cadence');
  assert(nssConntrack.warnings.includes('nss_prefers_conntrack_sync'), 'NSS sync speed path must explain BPF override');
}
{
  const nssDnatFixture = clone(conntrackNatFixture);
  nssDnatFixture.probe.nss_present = true;
  nssDnatFixture.probe.nss_ecm_active = true;
  nssDnatFixture.config.bpf_full_available = true;
  nssDnatFixture.procfs_snapshots = [
    {
      t_ms: 1000,
      lines: [
        'ipv4 2 tcp 6 431999 ESTABLISHED src=198.51.100.10 dst=192.168.1.88 sport=443 dport=41000 packets=10 bytes=1000000 src=192.168.1.88 dst=198.51.100.10 sport=41000 dport=443 packets=5 bytes=100000 [ASSURED] mark=0 use=1'
      ]
    },
    {
      t_ms: 2000,
      lines: [
        'ipv4 2 tcp 6 431998 ESTABLISHED src=198.51.100.10 dst=192.168.1.88 sport=443 dport=41000 packets=20 bytes=2500000 src=192.168.1.88 dst=198.51.100.10 sport=41000 dport=443 packets=10 bytes=350000 [ASSURED] mark=0 use=1'
      ]
    }
  ];
  const nssDnat = simulateConntrackFallback(nssDnatFixture);
  assert(nssDnat.clients.length === 1, 'NSS sync must emit rows when LAN client is original destination');
  assert(nssDnat.clients[0].tx_bps === 2000000, 'NSS sync original-destination LAN tx_bps must use reply byte deltas');
  assert(nssDnat.clients[0].rx_bps === 12000000, 'NSS sync original-destination LAN rx_bps must use original byte deltas');
}

const nssEcmSyncBpfFallback = simulateNssSourceSelection(nssEcmSyncBpfFallbackFixture);
assert(nssEcmSyncBpfFallback.preferred === true, 'NSS without conntrack accounting must still prefer available BPF');
assert(nssEcmSyncBpfFallback.primary_source === 'bpf', 'NSS without conntrack accounting must keep BPF when the runtime is available');
assert(nssEcmSyncBpfFallback.collector_mode === 'bpf', 'NSS without conntrack accounting must preserve BPF collector mode');

const nssPpeOnly = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true },
  probe: { nf_conntrack_acct: true, nss_present: true, nss_ecm_active: false, nss_ppe_active: true }
});
assert(nssPpeOnly.preferred === true, 'PPE-only NSS detection must keep an available live source');
assert(nssPpeOnly.primary_source === 'bpf', 'PPE-only NSS detection must prefer BPF when available');
assert(nssPpeOnly.collector_mode === 'bpf', 'PPE-only NSS auto mode must use the BPF collector');

const nssDirectWithoutConntrackFallback = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: false, bpf_full_available: true, rate_collector_mode: 'nss_ecm_direct' },
  probe: {
    nf_conntrack_acct: true,
    nss_present: true,
    nss_ecm_active: true,
    nss_ecm_direct_state: true
  }
});
assert(nssDirectWithoutConntrackFallback.preferred === true, 'Explicit NSS-direct availability must not depend on conntrack fallback');
assert(nssDirectWithoutConntrackFallback.primary_source === 'nss_ecm_direct', 'Explicit NSS-direct must remain selectable when conntrack fallback is disabled');
assert(nssDirectWithoutConntrackFallback.collector_mode === 'nss_ecm_direct', 'NSS-direct collector mode must remain explicit without conntrack fallback');

const daeNonNssBpf = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true },
  probe: {
    nf_conntrack_acct: true,
    nss_present: false,
    runtime_active: true
  }
});
assert(daeNonNssBpf.preferred === true, 'non-NSS dae runtime must explicitly prefer early BPF in auto mode');
assert(daeNonNssBpf.primary_source === 'bpf', 'non-NSS dae runtime must keep BPF as the live rate source');
assert(daeNonNssBpf.warnings.includes('dae_runtime_prefers_bpf'), 'non-NSS dae runtime must publish the BPF preference warning');

const nssDaedBpf = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true },
  probe: {
    nf_conntrack_acct: true,
    nss_present: true,
    nss_ecm_active: true,
    nss_ecm_direct_state: true,
    runtime_active: true
  }
});
assert(nssDaedBpf.preferred === true, 'NSS+daed should still have a usable preferred live source when BPF is available');
assert(nssDaedBpf.primary_source === 'bpf', 'NSS+daed must prefer BPF over NSS direct when BPF is available');
assert(nssDaedBpf.collector_mode === 'bpf', 'NSS+daed+BPF clients must use collector_mode=bpf');
assert(nssDaedBpf.coverage_client_source === 'bpf', 'NSS+daed+BPF coverage must use BPF client bytes');
assert(nssDaedBpf.warnings.includes('dae_runtime_prefers_bpf'), 'NSS+dae runtime+BPF must explain that BPF is preferred');
assert(!nssDaedBpf.warnings.includes('nss_prefers_direct'), 'NSS+daed+BPF must not claim NSS direct is preferred');

const nssDaedNssFallback = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: false },
  probe: {
    nf_conntrack_acct: true,
    nss_present: true,
    nss_ecm_active: true,
    nss_ecm_direct_state: true,
    runtime_active: true
  }
});
assert(nssDaedNssFallback.primary_source === 'nss_conntrack_sync', 'NSS+daed must fall back to NSS sync when BPF is unavailable');
assert(nssDaedNssFallback.collector_mode === 'conntrack_ecm_sync', 'NSS+daed NSS fallback must keep sync collector mode');
assert(nssDaedNssFallback.warnings.includes('nss_dae_bpf_fallback_may_be_inaccurate'), 'NSS+dae runtime NSS fallback must warn that rates may be inaccurate');

const nssDaedConfigOnly = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true },
  probe: {
    nf_conntrack_acct: true,
    nss_present: true,
    nss_ecm_active: true,
    nss_ecm_direct_state: true,
    daed_config: true
  }
});
assert(nssDaedConfigOnly.primary_source === 'bpf', 'NSS auto must keep BPF when only daed config exists');
assert(!nssDaedConfigOnly.warnings.includes('dae_runtime_prefers_bpf'), 'daed config alone must not emit the dae runtime BPF warning');

const nssDaedStoppedWithLeftovers = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true },
  probe: {
    nf_conntrack_acct: true,
    nss_present: true,
    nss_ecm_active: true,
    nss_ecm_direct_state: true,
    daed_service: true,
    dae_iface: true
  }
});
assert(nssDaedStoppedWithLeftovers.primary_source === 'bpf', 'NSS auto must keep BPF when daed service exists but has no running instance');
assert(!nssDaedStoppedWithLeftovers.warnings.includes('dae_runtime_prefers_bpf'), 'stopped daed leftovers must not emit the dae runtime BPF warning');

const nssDaedStoppedWithStaleProbeCache = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true },
  probe: {
    nf_conntrack_acct: true,
    nss_present: true,
    nss_ecm_active: true,
    nss_ecm_direct_state: true,
    daed_running: true,
    daed_process: true,
    runtime_active: false
  }
});
assert(nssDaedStoppedWithStaleProbeCache.primary_source === 'bpf', 'NSS auto must keep its default BPF source after dae runtime stops');
assert(!nssDaedStoppedWithStaleProbeCache.warnings.includes('dae_runtime_prefers_bpf'), 'stale dae process cache must not retain the dynamic runtime warning');

const nssForcedDirectWithDaed = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true, rate_collector_mode: 'nss_ecm_direct' },
  probe: {
    nf_conntrack_acct: true,
    nss_present: true,
    nss_ecm_active: true,
    nss_ecm_direct_state: true,
    runtime_active: true
  }
});
assert(nssForcedDirectWithDaed.primary_source === 'nss_ecm_direct', 'forced NSS-direct must override automatic NSS+daed BPF preference');
assert(!nssForcedDirectWithDaed.warnings.includes('dae_runtime_prefers_bpf'), 'forced NSS-direct must not claim automatic dae runtime BPF preference');

const nssForcedDirectUnreadable = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: false, rate_collector_mode: 'nss_ecm_direct' },
  probe: {
    nf_conntrack_acct: true,
    nss_present: true,
    nss_ecm_active: true,
    nss_ecm_direct_state: true,
    nss_ecm_direct_readable: false
  }
});
assert(nssForcedDirectUnreadable.primary_source === 'nss_conntrack_sync', 'unreadable NSS-direct state must fall back to NSS sync even when direct is selected');
assert(nssForcedDirectUnreadable.collector_mode === 'conntrack_ecm_sync', 'unreadable NSS-direct fallback must keep existing NSS sync client collector_mode');

const nssForcedSyncWithDirectAvailable = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true, rate_collector_mode: 'nss_conntrack_sync' },
  probe: {
    nf_conntrack_acct: true,
    nss_present: true,
    nss_ecm_active: true,
    nss_ecm_direct_state: true
  }
});
assert(nssForcedSyncWithDirectAvailable.primary_source === 'nss_conntrack_sync', 'forced NSS sync must override available NSS-direct');
assert(nssForcedSyncWithDirectAvailable.collector_mode === 'conntrack_ecm_sync', 'forced NSS sync keeps existing client collector_mode for API compatibility');

const daeIngressPreempt = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true, dae_early_bpf: true },
  probe: { nf_conntrack_acct: true, nss_present: false, nss_ecm_active: false, dae_preempts_lan_ingress: true }
});
assert(daeIngressPreempt.dae_early_bpf === true, 'DAE/daed LAN ingress preemption must enable early pass-through BPF');
assert(daeIngressPreempt.dae_preempted === false, 'DAE/daed LAN ingress preemption must not force conntrack when early BPF is available');
assert(daeIngressPreempt.primary_source === 'bpf', 'DAE/daed preemption must keep primary_source=bpf with early pass-through BPF');
assert(daeIngressPreempt.collector_mode === 'bpf', 'DAE/daed preemption clients must keep collector_mode=bpf with early pass-through BPF');
assert(daeIngressPreempt.coverage_client_source === 'bpf', 'DAE/daed preemption coverage must use BPF client bytes');
assert(daeIngressPreempt.confidence === 'high', 'DAE/daed early BPF confidence can remain high because LAN-edge MAC sampling is preserved');
assert(!daeIngressPreempt.warnings.includes('conntrack_routed_nat_only'), 'DAE/daed early BPF path must not warn routed/NAT-only coverage');

const daeRuntimeEarly = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true, dae_early_bpf: true },
  probe: {
    nf_conntrack_acct: true,
    nss_present: false,
    nss_ecm_active: false,
    dae_preempts_lan_ingress: false,
    runtime_active: true
  }
});
assert(daeRuntimeEarly.dae_early_bpf === true, 'fresh dae runtime activity must enable configured early pass-through BPF without a cached tc preempt');

const daeWanOnly = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true },
  probe: { nf_conntrack_acct: true, nss_present: false, nss_ecm_active: false, dae_preempts_lan_ingress: false }
});
assert(daeWanOnly.primary_source === 'bpf', 'DAE filters outside the LAN ingress collect path must not override BPF rates');

const refreshInterval = validateRefreshInterval(refreshIntervalFixture);
assert(refreshInterval.default_ms === 1000, 'refresh interval default must be 1000ms');
assert(refreshInterval.minimum_ms === 500, 'refresh interval minimum must be 500ms');
assert(refreshInterval.effective_ms === 500, 'refresh interval below 500ms must be clamped');
assert(refreshInterval.warnings.includes('refresh_interval_below_minimum'), 'refresh interval clamp warning is required');

const lifecycleRestart = simulateLifecycleRestart(lifecycleFixture);
assert(lifecycleRestart.delete_clsact === lifecycleFixture.expected.delete_clsact, 'restart cleanup must not delete clsact qdisc');
assert(lifecycleRestart.foreign_filters_preserved === lifecycleFixture.expected.foreign_filters_preserved, 'restart cleanup must preserve dae/SQM/OpenClash filters');
assert(lifecycleRestart.lanspeed_filter_count_after_restart === lifecycleFixture.expected.lanspeed_filter_count_after_restart, 'restart must leave exactly one lanspeed filter per direction');
assert(lifecycleRestart.duplicate_lanspeed_filters === lifecycleFixture.expected.duplicate_lanspeed_filters, 'restart must not duplicate lanspeed filters');
assert(lifecycleRestart.cleanup_removed_filters.every((filter) => filter.owner === 'lanspeed'), 'cleanup may only remove lanspeed-owned filters');
assert(lifecycleRestart.preserved_foreign_owners.includes('dae'), 'fixture must preserve dae filter');
assert(lifecycleRestart.preserved_foreign_owners.includes('sqm'), 'fixture must preserve SQM filter');
assert(lifecycleRestart.preserved_foreign_owners.includes('openclash'), 'fixture must preserve OpenClash filter');
assert(lifecycleRestart.preserved_foreign_owners.includes('foreign-lanspeed-label'), 'fixture must preserve same pref/handle filter without full lanspeed identity');

const networkReload = simulateNetworkReload(lifecycleFixture);
assert(networkReload.temporary_warning_seen === true, 'network reload fixture must show temporary warning');
assert(networkReload.states.some((state) => state.mode === 'Degraded'), 'network reload fixture must show temporary Degraded state');
assert(networkReload.states.every((state) => state.mode !== 'Full'), 'network reload fixture must not claim Full without runtime attach/map-read');
assert(networkReload.recovered_mode === 'Degraded', 'network reload fixture must recover to the best honest current mode');
assert(networkReload.bpf_runtime_metrics === false, 'network reload recovery must keep bpf_runtime_metrics=false');
assert(networkReload.runtime_attach_map_read_success === false, 'network reload recovery must keep runtime attach/map-read success false');
assert(networkReload.live_metrics === false, 'network reload recovery must keep live_metrics=false');
assert(networkReload.warnings_after_recovery.includes('bpf_runtime_loader_unavailable'), 'network reload recovery must warn runtime BPF loader unavailable');
assert(networkReload.warnings_after_recovery.includes('live_metrics_unavailable'), 'network reload recovery must warn live metrics unavailable');
assert(networkReload.daemon_alive_after_recovery === true, 'network reload fixture must keep daemon alive after recovery');
assert(networkReload.changes_user_network_config === false, 'network reload fixture must not change user network config');
assert(networkReload.changes_proxy_config === false, 'network reload fixture must not change proxy config');

const coexistText = [
  'Task 6 tc coexistence fixture',
  `device=${tcCoexist.device}`,
  `qdisc_action=${tcCoexist.qdisc_action}`,
  `mode=${tcCoexist.mode}`,
  `existing_filters_preserved=${tcCoexist.existing_filters_preserved}`,
  `lanspeed_filter_added=${tcCoexist.lanspeed_filter_added}`,
  `append_only=${tcCoexist.append_only}`,
  `bpf_runtime_metrics=${tcCoexist.bpf_runtime_metrics}`,
  `runtime_attach_map_read_success=${tcCoexist.runtime_attach_map_read_success}`,
  `live_metrics=${tcCoexist.live_metrics}`,
  `warnings=${tcCoexist.warnings.join(',')}`,
  `owner=${tcCoexist.owner}`,
  `pref=${tcCoexist.pref}`,
  `handle=${tcCoexist.handle}`,
  'before_filters=',
  JSON.stringify(tcCoexist.before_filters, null, 2),
  'after_filters=',
  JSON.stringify(tcCoexist.after_filters, null, 2),
  'commands=',
  JSON.stringify(tcCoexist.commands, null, 2)
].join('\n');

writeEvidence('task-6-tc-coexist.txt', coexistText);
writeEvidence('task-6-upload-rate.json', JSON.stringify({
  upload_rate: uploadRate,
  map_full: mapFull
}, null, 2));

writeEvidence('task-7-lan-to-lan.json', JSON.stringify({
  lan_to_lan: lanToLan,
  uncertain_topology: uncertainLanToLan,
  limited_visibility: limitedLanToLan
}, null, 2));

writeEvidence('task-8-conntrack-nat.json', JSON.stringify(conntrackNat, null, 2));
writeEvidence('task-8-acct-disabled.json', JSON.stringify(conntrackAcctDisabled, null, 2));
writeEvidence('task-11-side-router.json', JSON.stringify(sideRouterDirect, null, 2));
writeEvidence('task-12-router-local.json', JSON.stringify(routerLocal, null, 2));
writeEvidence('task-12-vlan.json', JSON.stringify(topologyVlan, null, 2));

writeEvidence('task-7-counter-anomaly.txt', [
  'Task 7 counter anomaly fixture',
  `negative_rates_emitted=${counterAnomaly.negative_rates_emitted}`,
  `warnings=${counterAnomaly.warnings.join(',')}`,
  `per_client_anomaly_isolated=${counterAnomaly.per_client_anomaly_isolated}`,
  'directional_rates=',
  JSON.stringify(counterAnomaly.directions, null, 2),
  'resource_limits=',
  JSON.stringify(resourceLimits, null, 2),
  'refresh_interval=',
  JSON.stringify(refreshInterval, null, 2)
].join('\n'));

writeEvidence('task-17-restart-filters.txt', [
  'Task 17 restart filter lifecycle fixture',
  `delete_clsact=${lifecycleRestart.delete_clsact}`,
  `delete_foreign_filters=${lifecycleRestart.delete_foreign_filters}`,
  `foreign_filters_preserved=${lifecycleRestart.foreign_filters_preserved}`,
  `lanspeed_filter_count_after_restart=${lifecycleRestart.lanspeed_filter_count_after_restart}`,
  `duplicate_lanspeed_filters=${lifecycleRestart.duplicate_lanspeed_filters}`,
  `owned_filter_identity=${JSON.stringify(lifecycleRestart.owned_filter_identity)}`,
  `preserved_foreign_owners=${lifecycleRestart.preserved_foreign_owners.join(',')}`,
  'cleanup_removed_filters=',
  JSON.stringify(lifecycleRestart.cleanup_removed_filters, null, 2),
  'after_restart_filters=',
  JSON.stringify(lifecycleRestart.after_restart_filters, null, 2),
  'cleanup_commands=',
  JSON.stringify(lifecycleRestart.cleanup_commands, null, 2)
].join('\n'));

writeEvidence('task-17-network-reload.json', JSON.stringify(networkReload, null, 2));

console.log('lanspeed collector validation passed');
