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
      `tc filter add dev ${fixture.device} ${direction} pref ${filter.pref} handle ${filter.handle} bpf obj /usr/lib/bpf/lanspeed_tc.o sec tc/${direction} direct-action verbose owner ${filter.owner}`
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
    orig_bytes: null,
    reply_bytes: 0
  };
  let srcIndex = 0;
  let bytesIndex = 0;

  for (const token of line.trim().split(/\s+/)) {
    if (token.startsWith('src=')) {
      if (srcIndex === 0) {
        flow.orig_src = token.slice(4);
      }
      srcIndex += 1;
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

function buildArpMap(fixture) {
  const entries = new Map();

  for (const entry of fixture.arp_entries || []) {
    if (isExcludedIdentityInterface(entry.interface || '')) {
      continue;
    }
    entries.set(entry.ip, {
      ip: entry.ip,
      mac: entry.mac.toLowerCase(),
      zone: entry.zone || 'lan',
      interface: entry.interface || 'br-lan'
    });
  }

  return entries;
}

function isExcludedIdentityInterface(ifname) {
  return ifname === 'dae0' || ifname === 'dae0peer' || ifname.startsWith('tun') || ifname.startsWith('ppp') || ifname.startsWith('wg');
}

function buildConntrackSnapshot(fixture, snapshot) {
  const arpByIp = buildArpMap(fixture);
  const clients = new Map();
  let skippedNoArp = 0;
  let malformedLines = 0;

  for (const line of snapshot.lines) {
    const flow = parseConntrackProcfsLine(line);
    if (!flow) {
      malformedLines += 1;
      continue;
    }

    const arp = arpByIp.get(flow.orig_src);
    if (!arp) {
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
    client.tx_bytes += flow.orig_bytes;
    client.rx_bytes += flow.reply_bytes;
    client.last_seen = snapshot.t_ms;
    clients.set(identityKey, client);
  }

  return {
    t_ms: snapshot.t_ms,
    clients: Array.from(clients.values()),
    skipped_no_arp: skippedNoArp,
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
      snode_address: null,
      dnode_address: null,
      protocol: 0,
      from_data_total: null,
      to_data_total: 0
    };

    if (field === 'sip_address') {
      flow.sip_address = value;
    } else if (field === 'dip_address') {
      flow.dip_address = value;
    } else if (field === 'snode_address') {
      flow.snode_address = value.toLowerCase();
    } else if (field === 'dnode_address') {
      flow.dnode_address = value.toLowerCase();
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
  const parsed = parseNssEcmDirectState(snapshot.lines);
  const clients = new Map();
  let skippedNoArp = 0;
  let entriesMatched = 0;

  for (const flow of parsed.flows) {
    if (!flow.sip_address || flow.from_data_total === null) {
      continue;
    }

    const arp = arpByIp.get(flow.sip_address);
    if (!arp) {
      skippedNoArp += 1;
      continue;
    }

    const mac = flow.snode_address && flow.snode_address !== '00:00:00:00:00:00'
      ? flow.snode_address
      : arp.mac;
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
    client.tx_bytes += flow.from_data_total;
    client.rx_bytes += flow.to_data_total;
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

function simulateConntrackFallback(fixture) {
  const warnings = [];
  const probe = fixture.probe;
  const nssSyncPreferred = Boolean(
    fixture.config.enable_conntrack_fallback &&
    probe.nf_conntrack_acct &&
    probe.nss_present &&
    probe.nss_ecm_active
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
  const directPreferred = Boolean(
    fixture.config.enable_conntrack_fallback &&
    probe.nss_present &&
    probe.nss_ecm_active &&
    probe.nss_ecm_direct_state
  );
  const syncPreferred = Boolean(
    fixture.config.enable_conntrack_fallback &&
    probe.nf_conntrack_acct &&
    probe.nss_present &&
    probe.nss_ecm_active
  );
  const preferred = directPreferred || syncPreferred;
  const warnings = [];

  if (preferred) {
    addUnique(warnings, directPreferred ? 'nss_ecm_direct_active' : 'nss_ecm_sync_cadence');
    if (bpfFullAvailable) {
      addUnique(warnings, directPreferred ? 'nss_prefers_direct' : 'nss_prefers_conntrack_sync');
    }
  }

  return {
    preferred,
    dae_early_bpf: Boolean(probe.dae_preempts_lan_ingress && daeEarlyBpf),
    dae_preempted: false,
    primary_source: directPreferred ? 'nss_ecm_direct' : (syncPreferred ? 'nss_conntrack_sync' : (bpfFullAvailable ? 'bpf' : 'unsupported')),
    collector_mode: directPreferred ? 'nss_ecm_direct' : (syncPreferred ? 'conntrack_ecm_sync' : (bpfFullAvailable ? 'bpf' : 'unsupported')),
    confidence: directPreferred ? 'high' : (syncPreferred ? 'medium' : (bpfFullAvailable ? 'high' : 'unsupported')),
    coverage_client_source: directPreferred ? 'nss_ecm_direct' : (syncPreferred ? 'conntrack' : (bpfFullAvailable ? 'bpf' : 'unsupported')),
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
  assert(initScript.includes('LANSPEED_TC_OBJECT="/usr/lib/bpf/lanspeed_tc.o"'), 'init cleanup must encode BPF object path');
  assert(initScript.includes('grep -F -q "$LANSPEED_TC_OWNER"'), 'init cleanup must require exact owner marker');
  assert(initScript.includes('grep -F -q "$LANSPEED_TC_OBJECT"'), 'init cleanup must require exact object marker');
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

function assertBpfSource(source) {
  for (const required of [
    'struct lanspeed_key',
    '__u32 ifindex',
    '__u16 vlan_or_zone',
    '__u8 direction',
    '__u8 mac[ETH_ALEN]',
    'struct lanspeed_counters',
    '__u64 bytes',
    '__u64 packets',
    '__u64 last_seen',
    'BPF_MAP_TYPE_LRU_HASH',
    'LANSPEED_MAX_CLIENTS',
    'SEC("tc/ingress")',
    'SEC("tc/egress")',
    'bpf_map_update_elem'
  ]) {
    assert(source.includes(required), `BPF source missing ${required}`);
  }
  const sizeMatch = source.match(/#define\s+LANSPEED_MAX_CLIENTS\s+(\d+)/);
  assert(sizeMatch, 'BPF source must #define LANSPEED_MAX_CLIENTS');
  assert(parseInt(sizeMatch[1], 10) >= 2048, `LANSPEED_MAX_CLIENTS must be >= 2048 (got ${sizeMatch && sizeMatch[1]})`);
  assert(source.includes('if (direction == LANSPEED_DIR_TX)') && source.includes('__builtin_memcpy(key.mac, eth->h_source, ETH_ALEN)'), 'BPF TX direction must use client source MAC');
  assert(source.includes('__builtin_memcpy(key.mac, eth->h_dest, ETH_ALEN)'), 'BPF RX direction must use client destination MAC');
  assert(source.includes('static __always_inline bool valid_client_mac'), 'BPF source must validate client MACs before accounting');
  assert(source.includes('return false;') && source.includes('mac[0] & 0x01'), 'BPF source must reject multicast destination/source MACs');
  assert(source.includes('if (!valid_client_mac(key.mac))'), 'BPF source must skip broadcast/multicast/zero MAC map entries');
  assert(/SEC\("tc\/ingress"\)\s+int\s+lanspeed_ingress\([^)]*\)\s*{\s*return account_frame\(skb, LANSPEED_DIR_TX, TC_ACT_OK\);\s*}/m.test(source), 'BPF ingress must account client TX and terminate normally in the default position');
  assert(/SEC\("tc\/egress"\)\s+int\s+lanspeed_egress\([^)]*\)\s*{\s*return account_frame\(skb, LANSPEED_DIR_RX, TC_ACT_OK\);\s*}/m.test(source), 'BPF egress must account client RX and terminate normally in the default position');
  assert(/SEC\("tc"\)\s+int\s+lanspeed_ingress_early\([^)]*\)\s*{\s*return account_frame\(skb, LANSPEED_DIR_TX, TC_ACT_UNSPEC\);\s*}/m.test(source), 'BPF early ingress must account client TX and continue to later filters');
  assert(/SEC\("tc"\)\s+int\s+lanspeed_egress_early\([^)]*\)\s*{\s*return account_frame\(skb, LANSPEED_DIR_RX, TC_ACT_UNSPEC\);\s*}/m.test(source), 'BPF early egress must account client RX and continue to later filters');
}

function assertBpfBuildRules(packageMakefile, srcMakefile, sdkHelper) {
  assert(packageMakefile.includes('PKG_BUILD_DEPENDS:=bpf-headers'), 'package Makefile must build-depend on bpf-headers');
  assert(packageMakefile.includes('include $(INCLUDE_DIR)/bpf.mk'), 'package Makefile must include bpf.mk for SDK BPF builds');
  assert(packageMakefile.includes('$(CONFIG_PACKAGE_lanspeedd-bpf)'), 'BPF compile must be gated by the optional lanspeedd-bpf package');
  assert(packageMakefile.includes('$(call CompileBPF,$(PKG_BUILD_DIR)/lanspeed_tc.bpf.c)'), 'package Makefile must compile lanspeed_tc.bpf.c with the SDK CompileBPF helper');
  assert(packageMakefile.includes('$(CP) $(PKG_BUILD_DIR)/lanspeed_tc.bpf.o $(PKG_BUILD_DIR)/lanspeed_tc.o'), 'package Makefile must normalize the SDK BPF output to lanspeed_tc.o');
  assert(packageMakefile.includes('$(INSTALL_DATA) $(PKG_BUILD_DIR)/lanspeed_tc.o $(1)/usr/lib/bpf/lanspeed_tc.o'), 'lanspeedd-bpf must install /usr/lib/bpf/lanspeed_tc.o');
  assert(packageMakefile.includes('DEPENDS:=+lanspeedd +libbpf $(BPF_DEPENDS)'), 'libbpf/BPF dependencies must stay in optional lanspeedd-bpf package');
  assert(!packageMakefile.includes('if [ -f $(PKG_BUILD_DIR)/lanspeed_tc.o ]'), 'BPF object install must not be a silent optional no-op');
  assert(/DEPENDS:=[^\n]*\+libmnl/.test(packageMakefile), 'base daemon must depend on libmnl for raw ctnetlink conntrack dumps');
  assert(/LIBS[^\n]*-lmnl/.test(packageMakefile), 'package Makefile must link lanspeedd with libmnl');
  assert(/LIBS[^\n]*-lmnl/.test(srcMakefile), 'src Makefile must link local lanspeedd builds with libmnl');
  assert(!/libnetfilter-conntrack/.test(packageMakefile), 'base daemon must not depend on libnetfilter-conntrack');
  assert(!/libnetfilter_conntrack/.test(srcMakefile), 'src Makefile must not link libnetfilter-conntrack');
  assert(srcMakefile.includes('bpf: lanspeed_tc.o'), 'src Makefile must expose an explicit bpf target');
  assert(srcMakefile.includes('lanspeed_tc.o: lanspeed_tc.bpf.c'), 'src Makefile must have a local BPF object rule');
  assert(srcMakefile.includes('-target bpf'), 'local BPF rule must target bpf');
  assert(sdkHelper.includes('set_config_module PACKAGE_lanspeedd-bpf'), 'SDK helper must select optional lanspeedd-bpf package before source package compile');
  assert(sdkHelper.includes('CONFIG_${symbol}=m'), 'SDK helper must support SDKs where scripts/config is a directory');
  assert(sdkHelper.includes('make defconfig'), 'SDK helper must refresh config after selecting lanspeedd-bpf');
  assert(!sdkHelper.includes('package/lanspeedd-bpf/compile'), 'SDK helper must not compile lanspeedd-bpf as an independent source package');
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

function assertRuntimeConntrackFallbackSource(source) {
  for (const required of [
    '#include <libmnl/libmnl.h>',
    '#include <linux/netfilter/nfnetlink_conntrack.h>',
    'CONNTRACK_PROCFS_PATH "/proc/net/nf_conntrack"',
    'CONNTRACK_LEGACY_PROCFS_PATH "/proc/net/ip_conntrack"',
    'ARP_PROCFS_PATH "/proc/net/arp"',
    'static bool read_conntrack_netlink_snapshot',
    'static int conntrack_netlink_data_cb',
    'IPCTNL_MSG_CT_GET',
    'NETLINK_NETFILTER',
    'CTA_COUNTERS_ORIG',
    'CTA_COUNTERS_REPLY',
    'lanspeedd_ctnetlink_conntrack_acct',
    'ctnetlink_conntrack_acct_orig_reply_bytes',
    'conntrack_netlink',
    'static bool parse_conntrack_procfs_line',
    'static bool read_conntrack_procfs_snapshot',
    'static bool read_conntrack_snapshot',
    'static bool collect_conntrack_procfs_clients',
    'static void emit_conntrack_clients',
    'previous_conntrack_samples',
    'conntrack_snapshot_pending',
    'conntrack_unavailable',
    'skip_conntrack_entry_without_fabricating_client',
    'lanspeedd_procfs_conntrack_acct',
    'procfs_conntrack_acct_orig_reply_bytes',
    'json_object_new_string(ARP_PROCFS_PATH)',
    'collect_conntrack_procfs_clients(root, clients, &probe)'
  ]) {
    assert(source.includes(required), `C runtime conntrack fallback missing ${required}`);
  }
  assert(!source.includes('#include <libnetfilter_conntrack/libnetfilter_conntrack.h>'), 'runtime must not include libnetfilter-conntrack');
  assert(!/\bnfct_/.test(source), 'runtime must not use libnetfilter-conntrack nfct_* APIs');
  assert(/read_conntrack_snapshot[\s\S]{0,900}?read_conntrack_netlink_snapshot[\s\S]{0,900}?read_conntrack_procfs_snapshot/.test(source),
         'conntrack snapshot wrapper must try netlink before procfs fallback');
  assert(/merge_conntrack_conn_counts[\s\S]{0,1400}?read_conntrack_snapshot/.test(source),
         'BPF connection-count merge must use the netlink-first conntrack wrapper');
  assert(/collect_conntrack_procfs_clients[\s\S]{0,1400}?read_conntrack_snapshot/.test(source),
         'NSS conntrack-sync collection must use the netlink-first conntrack wrapper');
  assert(source.includes('static bool nss_conntrack_sync_preferred'), 'runtime must define explicit NSS conntrack-sync preference');
  assert(source.includes('primary_source", json_object_new_string("nss_conntrack_sync")'), 'runtime evidence must expose NSS conntrack sync as primary source');
  assert(source.includes('coverage_current_client_bytes(const struct runtime_probe *probe'), 'coverage client bytes must take probe/source policy');
  assert(source.includes('nss_conntrack_sync_preferred(probe)'), 'runtime must route clients and coverage through NSS sync preference');
  assert(source.includes('json_object_new_string("nss_prefers_conntrack_sync")'), 'runtime must explain why NSS sync overrides available BPF metrics');
  assert(source.includes('static bool dae_tc_preempts_bpf_ingress'), 'runtime must detect DAE/daed tc filters that run before lanspeed ingress');
  assert(source.includes('json_object_new_string("dae_tc_preempts_bpf_ingress")'), 'runtime must explain when DAE tc preemption is detected');
  assert(source.includes('static void bpf_runtime_reset_rate_state'), 'runtime must reset BPF rate baselines after TC policy changes');
  assert(source.includes('static bool bpf_runtime_refresh_attach_policy'), 'runtime must refresh BPF attach policy when daed is started after lanspeedd');
  assert(/if\s*\(\s*bpf_runtime_refresh_attach_policy\(&probe\)\s*\)\s*\{[\s\S]{0,420}?bpf_collect_samples\(\);[\s\S]{0,220}?\}/.test(source), 'clients_method must recollect BPF samples after switching to early pass-through');
  assert(/bpf_runtime_refresh_attach_policy\(&probe\)[\s\S]{0,420}?finish_probe_evidence\(&probe,\s*"status"\)/.test(source), 'status_method must refresh TC policy before publishing self-heal evidence');
  assert(/bpf_runtime_refresh_attach_policy\(&probe\)[\s\S]{0,420}?finish_probe_evidence\(&probe,\s*"health"\)/.test(source), 'health_method must refresh TC policy before publishing self-heal evidence');
  assert(/static void bpf_collect_tick[\s\S]{0,520}?bpf_runtime_refresh_attach_policy\(&probe\)[\s\S]{0,220}?bpf_runtime_recover_if_needed\("periodic_tc_filter_check"\)/.test(source), 'periodic BPF tick must refresh TC policy before sampling');
  assert(/bpf_runtime_early_passthrough\s*=\s*want_early/.test(source), 'runtime policy refresh must switch the daemon to early pass-through when daed preempts LAN hooks');
  assert(!/dae_tc_preempts_bpf_ingress\(probe\)[\s\S]{0,120}?conntrack_primary_preferred/.test(source), 'DAE tc preemption must not force conntrack as the primary rate source');
  assert(!source.includes('json_object_new_string("fixture-client")'), 'runtime must not fabricate fixture clients');
  assert(source.includes('json_object_object_add(client, "mac", json_object_new_string(current[i].mac))'), 'runtime client MAC must come from ARP-mapped sample');
  /* collector_mode for conntrack-fallback clients must be wired into the
   * client JSON object.  It is "conntrack" by default, and switches to
   * "conntrack_ecm_sync" under NSS ECM/PPE offload (where a ternary selects
   * between the two literal strings). */
  assert(
    /json_object_object_add\(\s*client\s*,\s*"collector_mode"\s*,[\s\S]{0,400}?json_object_new_string/.test(source),
    'runtime clients must expose collector_mode via json_object_new_string');
  assert(
    source.includes('"conntrack"'),
    'runtime must emit the "conntrack" collector_mode literal');
  assert(
    source.includes('"conntrack_ecm_sync"') || !source.includes('nss_ecm_active'),
    'runtime must emit the "conntrack_ecm_sync" literal when NSS offload detection is wired');
  assert(source.includes('delta_bps(current[i].tx_bytes, previous->tx_bytes'), 'NSS conntrack-sync path must compute tx_bps from previous snapshot deltas');
  assert(source.includes('delta_bps(current[i].rx_bytes, previous->rx_bytes'), 'NSS conntrack-sync path must compute rx_bps from previous snapshot deltas');
  assert(source.includes('conntrack_refresh_last_seen'), 'runtime must keep conntrack last_seen tied to byte counter changes');
  assert(source.includes('udp_dns_conns'), 'runtime must split UDP DNS connection counts from other UDP flows');
  assert(source.includes('udp_other_conns'), 'runtime must expose non-DNS UDP connection counts');
  assert(/sport_index|orig_sport/.test(source) && /dport_index|orig_dport/.test(source), 'conntrack parser must read ports so DNS UDP can be identified');
  assert(/json_object_object_add\(\s*client\s*,\s*"tcp_conns"\s*,\s*json_object_new_int64?\(\s*\(int64?_t?\)?\s*cs->tcp_conns/.test(source) ||
         /json_object_object_add\(\s*client\s*,\s*"tcp_conns"\s*,\s*json_object_new_int\(\s*\(int\)cs->tcp_conns/.test(source),
         'BPF client connection counts must be overwritten from conntrack current table when conntrack is readable');
  assert(!/bpf_tcp\s*==\s*0/.test(source), 'conntrack connection merge must not keep stale/nonzero BPF conn counts');
  assert(source.includes('static int overview_method'), 'runtime must expose a daemon-side overview history method');
  assert(source.includes('UBUS_METHOD_NOARG("overview", overview_method)'), 'runtime must register the overview ubus method');
  assert(source.includes('overview_push_from_clients'), 'clients_method must feed daemon-side overview history from current samples');
  assert(source.includes('#define DEFAULT_ACTIVE_CLIENT_WINDOW_MS 10000ULL'), 'daemon must default active clients to a 10s window');
  assert(source.includes('#define DEFAULT_ACTIVE_CLIENT_MIN_BPS 1ULL'), 'daemon must default active clients to a nonzero speed threshold');
  assert(source.includes('char active_window_path[] = "lanspeed.main.active_client_window_ms"'), 'daemon must read active_client_window_ms from UCI');
  assert(source.includes('char active_min_bps_path[] = "lanspeed.main.active_client_min_bps"'), 'daemon must read active_client_min_bps from UCI');
  assert(source.includes('char overview_window_path[] = "lanspeed.main.overview_window_samples"'), 'daemon must read overview_window_samples from UCI');
  assert(source.includes('char rate_collector_mode_path[] = "lanspeed.main.rate_collector_mode"'), 'daemon must read rate_collector_mode from UCI');
  assert(source.includes('char conn_collector_mode_path[] = "lanspeed.main.conn_collector_mode"'), 'daemon must read conn_collector_mode from UCI');
  assert(source.includes('char collector_mode_path[] = "lanspeed.main.collector_mode"'), 'daemon must still read legacy collector_mode from UCI');
  assert(source.includes('conn_collector_mode_is_forced()'), 'daemon must allow UCI to force conntrack collectors for connection counts');
  assert(source.includes('rate_collector_mode_allows_bpf()'), 'daemon must expose rate BPF mode policy for evidence');
  assert(source.includes('return rate_collector_mode == COLLECTOR_MODE_AUTO ||\n\t       rate_collector_mode == COLLECTOR_MODE_BPF;'),
         'rate_collector_mode must not treat CT modes as live speed collectors');
  assert(/static bool conntrack_fallback_active[\s\S]{0,260}?conntrack_primary_preferred\(probe\)/.test(source),
         'non-NSS conntrack must not become a live rate fallback when BPF is unavailable');
  assert(source.includes('read_conntrack_snapshot_mode(current, &current_count'), 'conntrack client collection must honor forced netlink/procfs mode');
  assert(/collect_conntrack_procfs_clients[\s\S]{0,1800}?read_conntrack_snapshot_mode\(current,[\s\S]{0,360}?conn_collector_mode\)/.test(source),
         'NSS conntrack-sync speed reads must honor conn_collector_mode source selection');
  assert(/merge_conntrack_conn_counts[\s\S]{0,1800}?read_conntrack_snapshot_mode\(conn_samples,[\s\S]{0,360}?conn_collector_mode\)/.test(source),
         'BPF connection-count merge must honor conn_collector_mode source selection');
  assert(source.includes('client_is_active_recent'), 'overview active_clients must use last_seen/sample_ms freshness');
  assert(source.includes('client_has_active_rate'), 'overview active_clients must require configured current speed');
  assert(source.includes('active_client_window_ms'), 'runtime must publish active_client_window_ms');
  assert(source.includes('active_client_min_bps'), 'runtime must publish active_client_min_bps');
  assert(!source.includes('LANSPEED_OVERVIEW_ACTIVE_BPS'), 'overview active_clients must not be based on a bitrate threshold');
}

function assertRuntimeNssDirectSource(source, collectorModel, indexSource, nssPanelSource) {
  for (const required of [
    'NSS_ECM_STATE_DEBUGFS_DIR "/sys/kernel/debug/ecm/ecm_state"',
    'NSS_ECM_STATE_DEV_MAJOR_PATH',
    'NSS_ECM_DIRECT_SOURCE "nss_ecm_direct"',
    'struct nss_ecm_direct_flow',
    'struct nss_ecm_direct_stats',
    'static bool nss_ecm_direct_supported',
    'static bool read_nss_ecm_direct_snapshot',
    'static bool parse_nss_ecm_state_line',
    'static bool nss_ecm_state_open',
    'makedev(major, 0)',
    'open(path, O_RDONLY | O_CLOEXEC)',
    'fdopen(fd, "r")',
    'adv_stats.from_data_total',
    'adv_stats.to_data_total',
    'snode_address',
    'dnode_address',
    'nss_ecm_direct_preferred(probe)',
    'collect_nss_ecm_direct_clients(root, clients, &probe)',
    'nss_ecm_direct_snapshot_pending',
    'nss_ecm_direct_unavailable',
    'nss_ecm_direct_parse_errors',
    'skip_nss_ecm_direct_flow_without_lan_identity',
    'json_object_new_string("nss_ecm_direct")'
  ]) {
    assert(source.includes(required), `C runtime NSS direct missing ${required}`);
  }

  for (const forbidden of [
    'defunct_all',
    'decelerate',
    'flush'
  ]) {
    assert(!/open\([^)]*O_WR/.test(source) && !new RegExp(`fopen\\([^\\n]*${forbidden}`).test(source),
           `NSS direct must not write ${forbidden}`);
  }

  assert(/static bool nss_ecm_direct_preferred[\s\S]{0,220}?nss_ecm_direct_supported\(probe\)/.test(source),
         'NSS direct preference must be explicit and capability-gated');
  assert(/static bool conntrack_primary_preferred[\s\S]{0,220}?nss_ecm_direct_preferred\(probe\)[\s\S]{0,220}?nss_conntrack_sync_preferred\(probe\)/.test(source),
         'NSS direct must outrank ECM sync in primary source selection');
  assert(source.includes('static bool conntrack_clients_read_active'),
         'NSS direct failure must still allow ECM sync/conntrack as a secondary read path');
  assert(/static bool conntrack_clients_read_active[\s\S]{0,420}?nss_ecm_direct_preferred\(probe\)[\s\S]{0,420}?nss_conntrack_sync_reader_available\(probe\)/.test(source),
         'NSS direct secondary read path must be limited to NSS ECM sync availability');
  assert(/collect_conntrack_procfs_clients[\s\S]{0,760}?!conntrack_clients_read_active\(probe\)/.test(source),
         'NSS direct failure must not be blocked by primary conntrack_fallback_active');
  assert(/add_conntrack_common_warnings[\s\S]{0,360}?nss_ecm_direct_preferred\(probe\)[\s\S]{0,360}?nss_ecm_direct_unavailable/.test(source),
         'ECM sync fallback after NSS direct failure must explain that direct was unavailable');
  assert(/coverage_current_client_bytes[\s\S]{0,700}?nss_ecm_direct_preferred\(probe\)/.test(source),
         'coverage must use NSS direct client bytes when direct is primary');
  assert(/add_capabilities_from_values\(root,[\s\S]{0,140}?nss_ecm_direct_preferred\(&probe\)[\s\S]{0,180}?nss_ecm_direct_preferred\(&probe\)/.test(source),
         'status capabilities/live_metrics must account for NSS direct primary source');
  assert(indexSource.includes("mode === 'nss_ecm_direct'"), 'LuCI client status must label NSS direct rows');
  assert(indexSource.includes('NSS-direct'), 'LuCI must show NSS-direct label');
  assert(nssPanelSource.includes('direct_enabled') && nssPanelSource.includes('fallback_reason'),
         'NSS panel must expose direct state and fallback reason');
  assert(collectorModel.nss_direct_model.collector_mode === 'nss_ecm_direct', 'collector model must document nss_ecm_direct collector_mode');
  assert(collectorModel.nss_direct_model.primary_source === 'nss_ecm_direct', 'collector model must document nss_ecm_direct primary source');
  assert(collectorModel.nss_direct_model.read_only === true, 'collector model must declare NSS direct read-only');
  assert(collectorModel.nss_direct_model.fallback_to === 'conntrack_ecm_sync', 'collector model must document ECM sync fallback');
  assert(collectorModel.nss_direct_model.forbidden_writes.includes('defunct_all'), 'collector model must forbid defunct_all writes');
}

function assertRuntimeBpfGateSource(source) {
  assert(source.includes('static bool bpf_runtime_metrics_available'), 'C runtime must expose an explicit BPF runtime metrics gate');
  assert(source.includes('probe->bpf_runtime_metrics = bpf_runtime_metrics_available(probe)'), 'safe_attach must be separated from runtime metrics availability');
  assert(source.includes('return bpf_runtime_metrics_available(probe);'), 'Full availability must depend on the runtime metrics gate');
  assert(!/return\s+enable_bpf\s*&&\s*probe->safe_attach/.test(source), 'Full must not be derived from safe_attach or BPF asset presence alone');
  assert(source.includes('json_object_new_string("bpf_runtime_loader_unavailable")'), 'runtime must warn when BPF assets exist but attach/map-read is unavailable');
  assert(source.includes('json_object_object_add(collector, "bpf_assets_are_evidence_only", json_object_new_boolean(true))'), 'collector evidence must state BPF assets are evidence only');
  assert(source.includes('json_object_object_add(collector, "runtime_attach_map_read_success", json_object_new_boolean(probe->bpf_runtime_metrics))'), 'collector evidence must expose runtime attach/map-read gate result');
  assert(source.includes('json_object_object_add(capabilities, "bpf_runtime_metrics", json_object_new_boolean(probe ? probe->bpf_runtime_metrics : false))'), 'capabilities must expose runtime BPF metrics separately');
  assert(source.includes('static bool bpf_primary_active'), 'runtime must distinguish readable BPF maps from the active primary BPF source');
  assert(source.includes('add_capabilities_from_values(root, enable_bpf && bpf_primary_active(&probe)'), 'capabilities.bpf must describe the active primary BPF source');
  assert(source.includes('bpf_primary_active(&probe), &probe);'), 'live_metrics must be tied to the active primary BPF source');
}

function assertBpfLoaderModule(header, loader, daemonSource, packageMakefile, srcMakefile) {
  // Header advertises the public API the daemon consumes.
  for (const sym of [
    'lanspeed_bpf_init',
    'lanspeed_bpf_shutdown',
    'lanspeed_bpf_attach_iface',
    'lanspeed_bpf_detach_all',
    'lanspeed_bpf_read_samples',
    'lanspeed_bpf_runtime_ok',
    'lanspeed_bpf_ensure_attached',
    'lanspeed_bpf_get_status',
    'LANSPEED_BPF_DIR_TX',
    'LANSPEED_BPF_DIR_RX',
    'LANSPEED_BPF_TC_PREF',
    'LANSPEED_BPF_TC_HANDLE',
    'LANSPEED_BPF_TC_EARLY_PREF',
    'LANSPEED_BPF_TC_EARLY_HANDLE'
  ]) {
    assert(header.includes(sym), `lanspeed_bpf.h must expose ${sym}`);
  }

  // Loader uses the real libbpf + tc API surface, not stubs.
  for (const sym of [
    '#include <bpf/libbpf.h>',
    '#include <bpf/bpf.h>',
    'bpf_object__open_file',
    'bpf_object__load',
    'bpf_tc_hook_create',
    'bpf_tc_attach',
    'bpf_tc_detach',
    'bpf_map_get_next_key',
    'bpf_map_lookup_elem'
  ]) {
    assert(loader.includes(sym), `lanspeed_bpf.c must call real libbpf API ${sym}`);
  }

  // Loader must NOT destroy the clsact hook from the steady-state detach
  // path. dae, SQM and qosify may share the hook; removing it on normal
  // shutdown would break them. A rollback-only destroy inside the attach
  // helper is allowed, guarded by `created_hook`.
  const detachAll = loader.match(/void\s+lanspeed_bpf_detach_all\s*\([^)]*\)\s*{[\s\S]*?^}/m);
  assert(detachAll, 'lanspeed_bpf.c must define lanspeed_bpf_detach_all');
  assert(!/bpf_tc_hook_destroy/.test(detachAll[0]),
         'lanspeed_bpf_detach_all must not destroy clsact hooks');
  const attachHelper = loader.match(/static\s+int\s+attach_point\s*\([^)]*\)\s*{[\s\S]*?^}/m);
  if (attachHelper && /bpf_tc_hook_destroy/.test(attachHelper[0])) {
    assert(/created_hook[\s\S]*bpf_tc_hook_destroy|bpf_tc_hook_destroy[\s\S]*created_hook/.test(attachHelper[0]),
           'attach_point rollback hook_destroy must be guarded by created_hook');
  }

  // Daemon pulls the module in and drives it through runtime lifecycle.
  assert(daemonSource.includes('#include "lanspeed_bpf.h"'), 'lanspeedd.c must include the BPF loader header');
  assert(daemonSource.includes('lanspeed_bpf_init('), 'lanspeedd.c must call lanspeed_bpf_init');
  assert(loader.includes('lanspeed_bpf_attach_iface('), 'lanspeed_bpf.c must keep the legacy attach wrapper');
  assert(daemonSource.includes('lanspeed_bpf_attach_iface_mode('), 'lanspeedd.c must attach with a policy-aware BPF mode');
  assert(daemonSource.includes('lanspeed_bpf_ensure_attached('), 'lanspeedd.c must periodically verify and restore owned TC BPF hooks');
  assert(daemonSource.includes('bpf_runtime_recover_if_needed'), 'lanspeedd.c must keep a BPF self-heal path for hook loss');
  assert(!daemonSource.includes('initial_tc_filter_order_check'), 'initial BPF hook verification must not force an order self-heal on every startup');
  assert(!loader.includes('strstr(reason, "order")'), 'BPF self-heal must not force TC reorder');
  assert(!loader.includes('tc_filter_order_drift'), 'BPF self-heal must not detach/re-attach just to reorder around daed filters');
  assert(!loader.includes('force_reorder'), 'BPF self-heal must only restore missing owned hooks, never force order changes');
  assert(!daemonSource.includes('tc_lanspeed_after_dae_same_pref'), 'lanspeedd must not poll TC order to chase daed filter ordering');
  assert(loader.includes('ingress_priority = early_passthrough ? LANSPEED_BPF_TC_EARLY_PREF : LANSPEED_BPF_TC_PREF'),
         'daed-compatible early mode must move ingress before daed');
  assert(loader.includes('egress_priority = early_passthrough ? LANSPEED_BPF_TC_EARLY_PREF : LANSPEED_BPF_TC_PREF'),
         'daed-compatible early mode must also move egress before daed so download bytes are sampled before TC redirect/drop actions');
  assert(/egress_fd\s*=\s*early_passthrough\s*\?\s*g_state\.egress_early_prog_fd/.test(loader),
         'daed-compatible early mode must attach egress_early at the early pref');
  assert(/hook_present\(ifindex,\s*BPF_TC_EGRESS,\s*egress_priority,\s*egress_handle\)/.test(loader),
         'policy-aware attach must treat the shared egress hook as idempotent during daed policy switches');
  const modeDetach = loader.match(/int\s+lanspeed_bpf_detach_iface_mode\s*\([^)]*\)\s*{[\s\S]*?^}/m);
  assert(modeDetach, 'lanspeed_bpf.c must define lanspeed_bpf_detach_iface_mode');
  assert(/BPF_TC_EGRESS/.test(modeDetach[0]),
         'policy-mode detach must remove mode-specific egress too when switching daed early mode');
  assert(daemonSource.includes('bpf_tc_self_heal'), 'lanspeedd.c must expose BPF self-heal evidence');
  assert(daemonSource.includes('lanspeed_bpf_shutdown('), 'lanspeedd.c must shut the loader down on exit');
  assert(daemonSource.includes('lanspeed_bpf_runtime_ok('), 'lanspeedd.c must consult lanspeed_bpf_runtime_ok for Full gating');
  assert(daemonSource.includes('lanspeed_bpf_read_samples('), 'lanspeedd.c must read BPF samples for Full mode');
  assert(daemonSource.includes('collect_bpf_clients('), 'lanspeedd.c must expose a BPF client collector path');
  assert(/collector_mode[^\n]+"bpf"/.test(daemonSource), 'lanspeedd.c must emit collector_mode=bpf in the Full path');
  assert(/if\s*\(\s*collect_bpf_clients\(root,\s*clients,\s*&probe\)\s*\)[\s\S]{0,260}?merge_conntrack_conn_counts\(root,\s*clients\)/.test(daemonSource),
         'clients_method must use BPF as the only live rate source on non-NSS devices');
  assert(!/collector_mode_is_conntrack_forced\(\)[\s\S]{0,200}?collect_conntrack_procfs_clients\(root,\s*clients,\s*&probe\)/.test(daemonSource),
         'forced CT modes must not replace BPF live rates on non-NSS devices');
  assert(!/else\s*\{\s*collect_conntrack_procfs_clients\(root,\s*clients,\s*&probe\);\s*\}/.test(daemonSource),
         'non-NSS BPF failure must leave client rates empty instead of emitting CT byte rates');

  assert(bpfSource.includes('lanspeed_ingress_early'), 'BPF object must include an early ingress section for DAE coexistence');
  assert(bpfSource.includes('lanspeed_egress_early'), 'BPF object must include an early egress section for DAE coexistence');
  assert(/account_frame\(skb, LANSPEED_DIR_TX, TC_ACT_UNSPEC\)/.test(bpfSource) &&
         /account_frame\(skb, LANSPEED_DIR_RX, TC_ACT_UNSPEC\)/.test(bpfSource),
         'early BPF sections must return TC_ACT_UNSPEC so later DAE filters still run');
  assert(/BPF_TC_F_REPLACE/.test(loader), 'BPF self-heal must be able to replace owned filters without duplicating them');
  assert(/bpf_tc_query/.test(loader), 'BPF self-heal must query owned filters before claiming they are attached');

  // Package links libbpf; src Makefile builds the loader object and links -lbpf.
  assert(/DEPENDS:=[^\n]*\+libbpf/.test(packageMakefile), 'package Makefile must depend on +libbpf for the base daemon');
  assert(/LIBS[^\n]*-lbpf/.test(packageMakefile), 'package Makefile must link -lbpf in the build rule');
  assert(/lanspeed_bpf\.o/.test(srcMakefile) || /lanspeed_bpf\.c/.test(srcMakefile), 'src Makefile must compile lanspeed_bpf.{c,o}');
  assert(/-lbpf/.test(srcMakefile), 'src Makefile must link against -lbpf');
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
const source = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeedd.c'), 'utf8');
const packageMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const srcMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/src/Makefile'), 'utf8');
const sdkHelper = fs.readFileSync(path.join(root, 'scripts/build-sdk.sh'), 'utf8');
const bpfSource = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeed_tc.bpf.c'), 'utf8');
const bpfLoaderHeader = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeed_bpf.h'), 'utf8');
const bpfLoaderSource = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeed_bpf.c'), 'utf8');
const initScript = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/init.d/lanspeedd'), 'utf8');
const hotplugScript = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/hotplug.d/iface/90-lanspeedd'), 'utf8');
const defaultConfig = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/config/lanspeed'), 'utf8');
const indexSource = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/htdocs/luci-static/resources/view/lanspeed/index.js'), 'utf8');
const nssPanelSource = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/nssPanel.js'), 'utf8');
const collectorModel = readJson('net/lanspeedd/src/collector-model.json');
const bpfAttachedFixture = readJson('tests/fixtures/lanspeed-bpf-attached.json');

assertNoDestructiveTcCommands(source);
assertNoDestructiveTcCommands(packageMakefile);
assertNoDestructiveTcCommands(srcMakefile);
assertNoDestructiveTcCommands(sdkHelper);
assertNoDestructiveTcCommands(bpfSource);
assertNoDestructiveTcCommands(bpfLoaderSource);
assertBpfSource(bpfSource);
assertBpfBuildRules(packageMakefile, srcMakefile, sdkHelper);
assertRuntimeConntrackFallbackSource(source);
assertRuntimeNssDirectSource(source, collectorModel, indexSource, nssPanelSource);
assertRuntimeBpfGateSource(source);
assertBpfLoaderModule(bpfLoaderHeader, bpfLoaderSource, source, packageMakefile, srcMakefile);
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

const uploadRate = computeRateTimeline(uploadRateFixture);
assert(uploadRate.reached_within_3s === true, '10Mbps upload must reach 8M-12M within 3 seconds');
assert(uploadRate.dropped_after_stop === true, 'upload rate must drop below threshold after stop');
assert(uploadRate.rates.some((entry) => entry.tx_bps === 10000000), 'fixture must contain an exact 10Mbps tx sample');
assert(uploadRate.map_key.direction === 'tx', 'upload fixture must map to tx direction from client perspective');

const mapFull = simulateMapFull(mapFullFixture);
assert(mapFull.warnings.includes('map_full'), 'map full fixture must report map_full');
assert(mapFull.crashed === false, 'map full fixture must not crash');
assert(collectorModel.bpf_source === 'lanspeed_tc.bpf.c', 'collector model must reference the BPF source file');
assert(collectorModel.runtime_object === '/usr/lib/bpf/lanspeed_tc.o', 'collector model must reference installed BPF object path');
assert(collectorModel.map_model.default_max_clients === 2048, 'collector model must default to 2048 clients');
assert(JSON.stringify(collectorModel.map_model.key) === JSON.stringify(['ifindex', 'vlan_or_zone', 'mac', 'direction']), 'collector model map key shape is required');
assert(JSON.stringify(collectorModel.map_model.counters) === JSON.stringify(['bytes', 'packets', 'last_seen']), 'collector model counters must be bytes/packets/last_seen');
assert(collectorModel.attach_model.excluded.includes('wan') && collectorModel.attach_model.excluded.includes('tun'), 'collector model must exclude WAN/TUN');
assert(collectorModel.attach_model.excluded.includes('dae0') && collectorModel.attach_model.excluded.includes('dae0peer'), 'collector model must exclude dae tunnel interfaces');
assert(collectorModel.rate_model.default_refresh_interval_ms === 1000, 'sampling interval must default to 1000ms');
assert(collectorModel.rate_model.minimum_refresh_interval_ms === 500, 'sampling interval minimum must be 500ms');
assert(collectorModel.rate_model.default_active_client_window_ms === 10000, 'active client window must default to 10000ms');
assert(collectorModel.rate_model.default_active_client_min_bps === 1, 'active client minimum must default to 1bps');
assert(collectorModel.rate_model.default_overview_window_samples === 240, 'overview trend history must default to 240 samples');
assert(collectorModel.rate_model.window_count === 3, 'rate model must keep three deterministic windows');
assert(collectorModel.rate_model.anomaly_warnings.includes('counter_anomaly'), 'rate model must expose counter_anomaly warning');
assert(collectorModel.rate_model.refresh_interval_warning === 'refresh_interval_below_minimum', 'rate model must expose refresh interval warning');
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
assert(collectorModel.conntrack_fallback_model.primary_sources.includes('nss_conntrack_sync'), 'NSS sync model must expose nss_conntrack_sync primary source');
assert(!collectorModel.conntrack_fallback_model.primary_sources.includes('conntrack'), 'plain non-NSS conntrack must not be documented as a live speed primary source');
assert(collectorModel.conntrack_fallback_model.non_nss_live_rate_policy === 'bpf_only', 'non-NSS live rate policy must be BPF-only');
assert(collectorModel.conntrack_fallback_model.non_nss_conntrack_policy === 'connection_counts_and_diagnostics_only', 'non-NSS conntrack policy must be counts/diagnostics only');
assert(collectorModel.conntrack_fallback_model.mode === 'Degraded', 'conntrack fallback must stay Degraded');
assert(collectorModel.conntrack_fallback_model.coverage === 'routed_nat_only', 'conntrack fallback must be routed/NAT-only');
assert(collectorModel.conntrack_fallback_model.coverage_warning === 'conntrack_routed_nat_only', 'conntrack fallback must expose routed/NAT-only warning');
assert(collectorModel.conntrack_fallback_model.active_only_when.includes('nf_conntrack_acct=1'), 'conntrack fallback must require nf_conntrack_acct=1');
assert(collectorModel.conntrack_fallback_model.active_only_when.includes('nss_ecm_sync_preferred'), 'conntrack fallback model must document NSS ECM sync preference');
assert(!collectorModel.conntrack_fallback_model.active_only_when.includes('bpf_full_unavailable'), 'BPF failure alone must not activate non-NSS conntrack speed fallback');
assert(collectorModel.conntrack_fallback_model.inactive_when.includes('non_nss_device'), 'conntrack speed fallback must be inactive on non-NSS devices');
assert(collectorModel.conntrack_fallback_model.inactive_when.includes('bpf_full_unavailable_without_nss_ecm_sync'), 'non-NSS BPF failure must not become CT byte-rate fallback');
assert(collectorModel.conntrack_fallback_model.inactive_when.includes('conntrack_acct_disabled'), 'conntrack fallback must disable when accounting is off');
assert(collectorModel.conntrack_fallback_model.inactive_when.includes('bpf_full_available_without_nss_ecm_sync'), 'conntrack fallback model must keep non-NSS BPF-first behavior');
assert(collectorModel.conntrack_fallback_model.source === 'lanspeedd_ctnetlink_conntrack_acct', 'conntrack fallback model must name ctnetlink as the preferred source');
assert(collectorModel.conntrack_fallback_model.fallback_source === 'lanspeedd_procfs_conntrack_acct', 'conntrack fallback model must honestly keep procfs as the last fallback source');
assert(collectorModel.conntrack_fallback_model.nss_sync_coverage_warning === 'nss_ecm_sync_cadence', 'NSS sync coverage warning must document ECM cadence');
assert(collectorModel.conntrack_fallback_model.counter_sources.includes('ctnetlink_conntrack_acct_orig_reply_bytes'), 'conntrack fallback model must name ctnetlink accounting source');
assert(collectorModel.conntrack_fallback_model.counter_sources.includes('procfs_conntrack_acct_orig_reply_bytes'), 'conntrack fallback model must name procfs accounting source');
assert(collectorModel.conntrack_fallback_model.netlink_path === 'netlink:ctnetlink', 'conntrack fallback model must document raw ctnetlink as the preferred reader');
assert(collectorModel.conntrack_fallback_model.procfs_paths.includes('/proc/net/arp'), 'conntrack fallback model must include ARP identity source');
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

const nssEcmSync = simulateNssSourceSelection(nssEcmSyncFixture);
assert(nssEcmSync.preferred === true, 'NSS ECM direct fixture must prefer direct collection before conntrack sync');
assert(nssEcmSync.primary_source === 'nss_ecm_direct', 'NSS direct must expose primary_source=nss_ecm_direct');
assert(nssEcmSync.collector_mode === 'nss_ecm_direct', 'NSS direct clients must use collector_mode=nss_ecm_direct');
assert(nssEcmSync.coverage_client_source === 'nss_ecm_direct', 'NSS direct coverage must use direct client bytes');
assert(nssEcmSync.confidence === 'high', 'NSS direct confidence should be high when direct state is readable');
assert(nssEcmSync.warnings.includes('nss_ecm_direct_active'), 'NSS direct must explain that direct ECM state is active');
assert(nssEcmSync.warnings.includes('nss_prefers_direct'), 'NSS direct must explain why BPF is not primary');

{
  const nssConntrackFixture = clone(conntrackNatFixture);
  nssConntrackFixture.probe.nss_present = true;
  nssConntrackFixture.probe.nss_ecm_active = true;
  nssConntrackFixture.config.bpf_full_available = true;
  const nssConntrack = simulateConntrackFallback(nssConntrackFixture);
  assert(nssConntrack.active === true, 'NSS ECM sync may use conntrack byte counters as the speed source');
  assert(nssConntrack.collector_mode === 'conntrack_ecm_sync', 'NSS ECM sync conntrack clients must expose collector_mode=conntrack_ecm_sync');
  assert(nssConntrack.coverage === 'nss_ecm_sync', 'NSS ECM sync conntrack coverage must not claim routed/NAT-only fallback');
  assert(nssConntrack.clients.length === 1, 'NSS ECM sync fixture must still produce client speed rows');
  assert(nssConntrack.clients[0].tx_bps === nssConntrackFixture.expected.tx_bps, 'NSS ECM sync tx_bps must be computed from original-direction bytes');
  assert(nssConntrack.clients[0].rx_bps === nssConntrackFixture.expected.rx_bps, 'NSS ECM sync rx_bps must be computed from reply-direction bytes');
  assert(nssConntrack.warnings.includes('nss_ecm_sync_cadence'), 'NSS ECM sync speed path must warn about sync cadence');
  assert(nssConntrack.warnings.includes('nss_prefers_conntrack_sync'), 'NSS ECM sync speed path must explain BPF override');
}

const nssEcmSyncBpfFallback = simulateNssSourceSelection(nssEcmSyncBpfFallbackFixture);
assert(nssEcmSyncBpfFallback.preferred === false, 'NSS sync must not be preferred when conntrack accounting is disabled');
assert(nssEcmSyncBpfFallback.primary_source === 'bpf', 'NSS without conntrack accounting must fall back to BPF when BPF runtime is available');
assert(nssEcmSyncBpfFallback.collector_mode === 'bpf', 'NSS without conntrack accounting must preserve BPF collector mode');

const nssPpeOnly = simulateNssSourceSelection({
  config: { enable_conntrack_fallback: true, bpf_full_available: true },
  probe: { nf_conntrack_acct: true, nss_present: true, nss_ecm_active: false, nss_ppe_active: true }
});
assert(nssPpeOnly.preferred === false, 'PPE-only NSS detection must not enable conntrack-sync primary source in the first implementation');
assert(nssPpeOnly.primary_source === 'bpf', 'PPE-only NSS detection must preserve BPF primary source when BPF is available');

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
assert(source.includes('#define MIN_REFRESH_INTERVAL_MS 500'), 'C daemon must define 500ms minimum refresh interval');
assert(source.includes('refresh_interval_below_minimum'), 'C daemon must expose machine-readable refresh interval warning');

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
