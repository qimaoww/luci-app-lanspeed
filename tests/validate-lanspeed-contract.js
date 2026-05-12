#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');

function readJson(relativePath) {
  const absolutePath = path.join(root, relativePath);
  return JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertObject(value, pathName) {
  assert(value && typeof value === 'object' && !Array.isArray(value), `${pathName} must be an object`);
}

function assertArray(value, pathName) {
  assert(Array.isArray(value), `${pathName} must be an array`);
}

function assertRequired(object, fields, pathName) {
  assertObject(object, pathName);
  for (const field of fields) {
    assert(Object.prototype.hasOwnProperty.call(object, field), `${pathName}.${field} is required`);
  }
}

function assertSchemaRequired(schema, defName, fields) {
  const definition = schema.$defs && schema.$defs[defName];
  assertObject(definition, `$defs.${defName}`);
  assertArray(definition.required, `$defs.${defName}.required`);
  for (const field of fields) {
    assert(definition.required.includes(field), `schema $defs.${defName} must require ${field}`);
  }
}

function resolveSchema(schema, fragment) {
  const prefix = '#/$defs/';
  assert(fragment.startsWith(prefix), `unsupported schema ref ${fragment}`);
  const definition = schema.$defs && schema.$defs[fragment.slice(prefix.length)];
  assertObject(definition, fragment);
  return definition;
}

function validateValue(schema, definition, value, pathName) {
  if (definition.$ref) {
    validateValue(schema, resolveSchema(schema, definition.$ref), value, pathName);
    return;
  }

  if (Array.isArray(definition.type)) {
    if (value === null && definition.type.includes('null')) {
      return;
    }
    for (const type of definition.type.filter((entry) => entry !== 'null')) {
      try {
        validateValue(schema, { ...definition, type }, value, pathName);
        return;
      } catch (error) {
        // Try the next allowed type before reporting the union failure.
      }
    }
    throw new Error(`${pathName} must be one of ${definition.type.join(', ')}`);
  }

  if (definition.type === 'object') {
    assertObject(value, pathName);
    const properties = definition.properties || {};
    for (const field of definition.required || []) {
      assert(Object.prototype.hasOwnProperty.call(value, field), `${pathName}.${field} is required by schema`);
    }
    if (definition.additionalProperties === false) {
      for (const field of Object.keys(value)) {
        assert(Object.prototype.hasOwnProperty.call(properties, field), `${pathName}.${field} is not allowed by schema`);
      }
    }
    for (const [field, childDefinition] of Object.entries(properties)) {
      if (Object.prototype.hasOwnProperty.call(value, field)) {
        validateValue(schema, childDefinition, value[field], `${pathName}.${field}`);
      }
    }
    return;
  }

  if (definition.type === 'array') {
    assertArray(value, pathName);
    if (definition.items) {
      for (const [index, item] of value.entries()) {
        validateValue(schema, definition.items, item, `${pathName}[${index}]`);
      }
    }
    return;
  }

  if (definition.type === 'string') {
    assert(typeof value === 'string', `${pathName} must be a string`);
    if (definition.minLength !== undefined) {
      assert(value.length >= definition.minLength, `${pathName} must have length >= ${definition.minLength}`);
    }
    if (definition.enum) {
      assert(definition.enum.includes(value), `${pathName} must be one of ${definition.enum.join(', ')}`);
    }
    if (definition.pattern) {
      assert(new RegExp(definition.pattern).test(value), `${pathName} must match ${definition.pattern}`);
    }
    return;
  }

  if (definition.type === 'integer') {
    assert(Number.isInteger(value), `${pathName} must be an integer`);
    if (definition.minimum !== undefined) {
      assert(value >= definition.minimum, `${pathName} must be >= ${definition.minimum}`);
    }
    return;
  }

  if (definition.type === 'boolean') {
    assert(typeof value === 'boolean', `${pathName} must be a boolean`);
  }
}

function validateRootSchema(schema) {
  assertArray(schema.oneOf, 'schema.oneOf');
  const refs = schema.oneOf.map((entry) => entry.$ref).sort();
  const expectedRefs = ['#/$defs/clients', '#/$defs/health', '#/$defs/interfaces', '#/$defs/status'].sort();
  assert(JSON.stringify(refs) === JSON.stringify(expectedRefs), 'root schema must validate single ubus method responses');
  assert(!schema.$defs.status.properties.mode.enum.includes('Stub'), 'mode enum must not introduce Stub outside Full/Degraded/Unsupported contract');
}

function validateFixture(fixture) {
  assertRequired(fixture.status, [
    'mode',
    'confidence',
    'warnings',
    'evidence',
    'refresh_interval_ms',
    'version',
    'capabilities'
  ], 'status');
  assertArray(fixture.status.warnings, 'status.warnings');
  assertObject(fixture.status.evidence, 'status.evidence');
  assertObject(fixture.status.capabilities, 'status.capabilities');
  assert(fixture.status.mode === 'Unsupported', 'status fixture must use planned Unsupported mode for stub stage');
  assert(fixture.status.capabilities.bpf === false, 'status fixture must not claim BPF is available in stub stage');
  assert(fixture.status.capabilities.live_metrics === false, 'status fixture must not pretend live metrics exist');

  assertRequired(fixture.clients, ['clients'], 'clients response');
  assertArray(fixture.clients.clients, 'clients.clients');
  assert(fixture.clients.clients.length > 0, 'clients fixture must include at least one client for field validation');
  for (const [index, client] of fixture.clients.clients.entries()) {
    assertRequired(client, [
      'mac',
      'identity_key',
      'zone',
      'interface',
      'ips',
      'hostname',
      'rx_bps',
      'tx_bps',
      'last_seen',
      'collector_mode',
      'confidence',
      'warnings'
    ], `clients.clients[${index}]`);
    assertArray(client.ips, `clients.clients[${index}].ips`);
    assertArray(client.warnings, `clients.clients[${index}].warnings`);
    assert(client.identity_key === `${client.mac.toLowerCase()}@${client.zone}`, 'client identity_key must be MAC plus zone');
    assert(client.interface.length > 0, 'client interface must identify the observed LAN attachment');
    assert(client.rx_bps === 0 && client.tx_bps === 0, 'stub fixture rates must be deterministic zero values');
  }

  assertRequired(fixture.health, ['mode', 'confidence', 'capabilities', 'conflicts', 'warnings', 'evidence'], 'health');
  assert(['Full', 'Degraded', 'Unsupported'].includes(fixture.health.mode), 'health mode must stay within supported runtime modes');
  assertObject(fixture.health.capabilities, 'health.capabilities');
  assertArray(fixture.health.conflicts, 'health.conflicts');
  assertArray(fixture.health.warnings, 'health.warnings');
  assertObject(fixture.health.evidence, 'health.evidence');

  assertRequired(fixture.interfaces, ['interfaces'], 'interfaces response');
  assertArray(fixture.interfaces.interfaces, 'interfaces.interfaces');
  assert(fixture.interfaces.interfaces.length > 0, 'interfaces fixture must include at least one interface placeholder');
  for (const [index, iface] of fixture.interfaces.interfaces.entries()) {
    assertRequired(iface, ['name', 'role', 'status', 'evidence'], `interfaces.interfaces[${index}]`);
    assertObject(iface.evidence, `interfaces.interfaces[${index}].evidence`);
  }
}

function validateMethodFixtures(schema, fixtures) {
  validateValue(schema, schema.$defs.status, fixtures.status, 'status method response');
  validateValue(schema, schema.$defs.clients, fixtures.clients, 'clients method response');
  validateValue(schema, schema.$defs.health, fixtures.health, 'health method response');
  validateValue(schema, schema.$defs.interfaces, fixtures.interfaces, 'interfaces method response');
}

function validateAcl(acl) {
  const app = acl['luci-app-lanspeed'];
  assertObject(app, 'luci-app-lanspeed ACL');
  assertObject(app.read, 'ACL read');
  assertObject(app.read.ubus, 'ACL read.ubus');
  assertArray(app.read.ubus.lanspeed, 'ACL read.ubus.lanspeed');
  assertArray(app.read.uci, 'ACL read.uci');

  /* The read side exposes every ubus method on the lanspeed object, including
   * sysdevices (added for the interface-config UI).  Read UCI access is
   * restricted to the lanspeed config. */
  const expectedReadMethods = ['status', 'clients', 'health', 'interfaces', 'sysdevices'];
  assert(app.read.ubus.lanspeed.length === expectedReadMethods.length,
    `ACL must grant exactly ${expectedReadMethods.length} lanspeed read methods, got ${app.read.ubus.lanspeed.length}`);
  for (const method of expectedReadMethods) {
    assert(app.read.ubus.lanspeed.includes(method), `ACL must grant read ubus method ${method}`);
  }
  assert(app.read.uci.length === 1 && app.read.uci[0] === 'lanspeed', 'ACL must only grant read UCI access to lanspeed');

  /* The write side is intentionally narrow: the LuCI page writes the lanspeed
   * UCI config (to persist interface assignments), commits it via uci.*, and
   * triggers `rc init lanspeedd reload`.  Anything broader would be a bug. */
  if (Object.prototype.hasOwnProperty.call(app, 'write')) {
    assertObject(app.write, 'ACL write');
    assertObject(app.write.ubus, 'ACL write.ubus');

    assertArray(app.write.ubus.rc, 'ACL write.ubus.rc');
    assert(app.write.ubus.rc.length === 1 && app.write.ubus.rc[0] === 'init',
      'ACL write.ubus.rc must grant only the init method');

    assertArray(app.write.ubus.uci, 'ACL write.ubus.uci');
    const allowedUciMethods = ['set', 'delete', 'add', 'commit', 'apply'];
    for (const method of app.write.ubus.uci) {
      assert(allowedUciMethods.includes(method), `ACL write.ubus.uci must only include ${allowedUciMethods.join(', ')}, got ${method}`);
    }

    assertArray(app.write.uci, 'ACL write.uci');
    assert(app.write.uci.length === 1 && app.write.uci[0] === 'lanspeed',
      'ACL write.uci must only grant the lanspeed config');
  }
}

function validateSource(source) {
  for (const method of ['status', 'clients', 'health', 'interfaces']) {
    assert(source.includes(`UBUS_METHOD_NOARG("${method}"`), `C stub must register ${method} ubus method`);
    assert(source.includes(`"${method}"`), `C stub must represent ${method} response`);
  }
  for (const library of [
    '<json-c/json.h>',
    '<libubox/blobmsg_json.h>',
    '<libubox/uloop.h>',
    '<libubus.h>',
    '<uci.h>'
  ]) {
    assert(source.includes(`#include ${library}`), `C stub must include planned OpenWrt library ${library}`);
  }
  assert(source.includes('finish_probe_evidence(&probe, "status")'), 'C status method must expose runtime probe evidence');
  assert(source.includes('finish_probe_evidence(&probe, "health")'), 'C health method must expose runtime probe evidence');
  assert(source.includes('static void inspect_runtime(struct runtime_probe *probe)'), 'C daemon must include runtime health probe orchestration');
  assert(source.includes('add_warning(probe, "tc_missing")'), 'C health probe must warn when tc is missing');
  assert(source.includes('hardware_flow_offload_unsupported'), 'C health probe must warn on unsupported hardware flow offload');
  assert(source.includes('fullcone_nat_enabled'), 'C health probe must expose fullcone_nat_enabled warning or evidence');
  assert(source.includes('"read_only", json_object_new_boolean(true)'), 'C health probe evidence must declare read-only probing');
  assert(source.includes('"probe_error"'), 'C health probe must expose structured probe_error evidence');
  assert(source.includes('json_object_new_string(enabled_state(probe->software_flow_offload))'), 'C health evidence must expose software flow offload as enabled/disabled');
  assert(source.includes('json_object_new_string(enabled_state(probe->hardware_flow_offload))'), 'C health evidence must expose hardware flow offload as enabled/disabled');
  assert(source.includes('json_object_new_string(enabled_state(probe->fullcone))'), 'C health evidence must expose fullcone as enabled/disabled');
  assert(source.includes('json_object_new_string(present_state(probe->flowtable_counter))'), 'C health evidence must expose flowtable counter as present/missing');
  assert(!source.includes('"mode", json_object_new_string("Stub")'), 'C stub must not introduce Stub mode');
  assert(!source.includes('fixture-client'), 'C runtime stub must not fabricate a fixture hostname');
  assert(!source.includes('192.0.2.10'), 'C runtime stub must not fabricate a fixture IP address');
  assert(source.includes('json_object_object_add(root, "clients", clients);'), 'C clients method must still return top-level clients array');
  assert(source.includes('static void add_clients_identity_evidence(struct json_object *parent)'), 'C clients method must expose identity model evidence without fabricated clients');
  assert(source.includes('"primary_key"'), 'C clients evidence must document MAC plus zone identity semantics');
  assert(source.includes('"client-originated traffic from the client point of view"'), 'C clients evidence must document tx_bps client perspective');
  assert(source.includes('LANSPEED_BPF_PACKAGE_MARKER'), 'C daemon must probe optional lanspeedd-bpf package marker');
  assert(source.includes('LANSPEED_BPF_OBJECT_PATH'), 'C daemon must probe runtime BPF object separately');
  assert(source.includes('"bpf_optional_package_missing"'), 'C health probe must warn when optional BPF package marker is missing');
  assert(source.includes('"bpf_object_missing"'), 'C health probe must warn when runtime BPF object is missing');
  assert(source.includes('"unsafe_attach"'), 'C health probe must report unsafe attach as structured warning');
  assert(source.includes('"map_full"'), 'C health probe must report map_full without crashing');
  assert(source.includes('char max_clients_path[] = "lanspeed.main.max_clients"'), 'C daemon must read max_clients for the BPF map guard');
  assert(source.includes('"lan_bridge_members"') && source.includes('"vlan_subinterfaces"') && source.includes('"wlan_interfaces"'), 'C collector model must target CPU-visible LAN edges');
  assert(source.includes('"wan"') && source.includes('"tun"'), 'C collector model must exclude WAN/TUN-side MAC ownership');
  assert(source.includes('"delete_existing", json_object_new_boolean(false)'), 'C collector evidence must forbid deleting existing tc filters');
  assert(source.includes('"reorder_existing", json_object_new_boolean(false)'), 'C collector evidence must forbid reordering existing tc filters');
  assert(source.includes('"ifindex"') && source.includes('"vlan_or_zone"') && source.includes('"direction"'), 'C collector map key must include ifindex, VLAN/zone, MAC, and direction');
  assert(source.includes('"bytes"') && source.includes('"packets"') && source.includes('"last_seen"'), 'C collector map model must include bytes, packets, and last_seen counters');
  assert(source.includes('LANSPEED_BPF_SOURCE'), 'C collector evidence must expose the BPF source name');
  assert(source.includes('#define DEFAULT_REFRESH_INTERVAL_MS 1000'), 'C daemon must default refresh interval to 1000ms');
  assert(source.includes('#define MIN_REFRESH_INTERVAL_MS 500'), 'C daemon must enforce 500ms minimum refresh interval');
  assert(source.includes('refresh_interval_below_minimum'), 'C daemon must expose refresh interval clamp warning');
  assert(source.includes('"rate_model"'), 'C collector evidence must expose rate model');
  assert(source.includes('"dedupe_model"'), 'C collector evidence must expose LAN-to-LAN dedupe model');
  assert(source.includes('"counter_anomaly"'), 'C collector evidence must document counter anomaly warning');
  assert(source.includes('"client_limit_exceeded"'), 'C collector evidence must document client limit warning');
  assert(source.includes('"map_read_failed"'), 'C collector evidence must document map read failure warning');
  assert(source.includes('"lan_to_lan_visibility_unknown"'), 'C collector evidence must document LAN-to-LAN unknown visibility warning');
  assert(source.includes('"lan_to_lan_visibility_limited"'), 'C collector evidence must document hardware-switch LAN-to-LAN limited visibility warning');
  assert(source.includes('"complete_coverage_claimed_for_hardware_switch_paths", json_object_new_boolean(false)'), 'C collector evidence must not claim complete hardware-switch LAN-to-LAN coverage');
  assert(source.includes('"router_local_model"'), 'C collector evidence must expose router-local model');
  assert(source.includes('"client_to_router", json_object_new_string("tx_bps")'), 'C router-local model must map client-to-router traffic to tx_bps');
  assert(source.includes('"router_to_client", json_object_new_string("rx_bps")'), 'C router-local model must map router-to-client traffic to rx_bps');
  assert(source.includes('"never_attribute_router_originated_traffic_to_lan_client"'), 'C router-local model must keep router-originated traffic out of LAN clients');
  assert(source.includes('"topology_identity_model"'), 'C collector evidence must expose topology identity model');
  assert(source.includes('"duplicate_mac_across_vlans"'), 'C topology model must expose duplicate MAC across VLAN warning');
  assert(source.includes('"wifi_wds_ap_isolation"'), 'C topology model must represent Wi-Fi/WDS/AP isolation semantics');
  assert(source.includes('"uplink_encapsulation_model"'), 'C collector evidence must expose uplink encapsulation model');
  assert(source.includes('"pppoe"') && source.includes('"wg"') && source.includes('"tun"'), 'C uplink model must cover PPPoE/WG/TUN');
  assert(source.includes('conntrack_fallback_active'), 'C daemon must define conntrack fallback activation rules');
  assert(source.includes('"collector_mode", json_object_new_string("conntrack")'), 'C conntrack fallback evidence must expose collector_mode=conntrack');
  assert(source.includes('"mode", json_object_new_string("Degraded")'), 'C conntrack fallback must not claim Full');
  assert(source.includes('"coverage", json_object_new_string("routed_nat_only")'), 'C conntrack fallback must be routed/NAT-only');
  assert(source.includes('"conntrack_acct_disabled"'), 'C daemon must report conntrack_acct_disabled');
  assert(source.includes('"flowtable_counter_missing"'), 'C daemon must report missing flowtable counter');
  assert(source.includes('"nlbwmon_counter_conflict"'), 'C daemon must report nlbwmon counter conflict');
  assert(source.includes('"openclash_fake_ip_low_remote_confidence"'), 'C daemon must report OpenClash fake-ip remote confidence warning');
  assert(source.includes('"openclash_tun_conntrack_low_confidence"'), 'C daemon must report OpenClash TUN/mix conntrack confidence warning');
  assert(source.includes('"openclash_dns_chain_incomplete"'), 'C daemon must report OpenClash DNS chain mismatch warning');
  assert(source.includes('"router_self@local_router"'), 'C daemon must keep router self proxy traffic in a separate local router bucket');
  assert(source.includes('"do_not_disable_lan_edge_bpf_when_openclash_is_present"'), 'C daemon must not disable LAN-edge BPF just because OpenClash is present');
  assert(source.includes('127.0.0.1#7874'), 'C daemon must probe dnsmasq forwarding to OpenClash DNS read-only');
  assert(source.includes('DAE_FWMARK "0x8000000"'), 'C daemon must detect dae fwmark 0x8000000 evidence');
  assert(source.includes('DAE_ROUTE_TABLE "2023"'), 'C daemon must detect dae route table 2023 evidence');
  assert(source.includes('"dae0"') && source.includes('"dae0peer"'), 'C daemon must explicitly exclude dae0/dae0peer identity sources');
  assert(source.includes('"tc_filter_conflict"'), 'C daemon must expose stable tc_filter_conflict warning');
  assert(source.includes('create_or_reuse_clsact_and_append_owned_filter_only'), 'C daemon must preserve append-only tc attach model');
  assert(source.includes('"nft_forward_chain_counters"'), 'C conntrack fallback must forbid firewall forward-chain counters');
  assert(source.includes('"nlbwmon_read_counters", json_object_new_boolean(false)'), 'C conntrack fallback must not read nlbwmon counters');
  assert(source.includes('CONNTRACK_PROCFS_PATH "/proc/net/nf_conntrack"'), 'C runtime fallback must read procfs conntrack table');
  assert(source.includes('CONNTRACK_LEGACY_PROCFS_PATH "/proc/net/ip_conntrack"'), 'C runtime fallback must support legacy procfs conntrack path');
  assert(source.includes('ARP_PROCFS_PATH "/proc/net/arp"'), 'C runtime fallback must map LAN IPs to MACs through ARP');
  assert(source.includes('static bool parse_conntrack_procfs_line'), 'C runtime fallback must parse conntrack procfs lines');
  assert(source.includes('static bool collect_conntrack_procfs_clients'), 'C runtime clients method must have real conntrack collector plumbing');
  assert(source.includes('collect_conntrack_procfs_clients(root, clients, &probe)'), 'clients_method must invoke conntrack fallback collector');
  assert(source.includes('previous_conntrack_samples'), 'C runtime fallback must keep previous snapshots for rates');
  assert(source.includes('"conntrack_snapshot_pending"'), 'C runtime fallback must expose first-sample pending warning');
  assert(source.includes('"conntrack_unavailable"'), 'C runtime fallback must report unavailable procfs/accounting paths');
  assert(source.includes('"lanspeedd_procfs_conntrack_acct"'), 'C runtime fallback must honestly name procfs source');
  assert(source.includes('"procfs_conntrack_acct_orig_reply_bytes"'), 'C runtime fallback must name procfs accounting counters');
}

function validateBpfSource(source) {
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
    'SEC("tc")'
  ]) {
    assert(source.includes(required), `BPF source missing ${required}`);
  }
  /* Default map size must stay at 2048 or larger; small ceilings recreated
   * the original "map_full" symptom that prompted the LRU switch. */
  const sizeMatch = source.match(/#define\s+LANSPEED_MAX_CLIENTS\s+(\d+)/);
  assert(sizeMatch, 'BPF source must #define LANSPEED_MAX_CLIENTS');
  assert(parseInt(sizeMatch[1], 10) >= 2048, `LANSPEED_MAX_CLIENTS must be >= 2048 (got ${sizeMatch && sizeMatch[1]})`);

  assert(/SEC\("tc\/ingress"\)\s+int\s+lanspeed_ingress\([^)]*\)\s*{\s*return account_frame\(skb, LANSPEED_DIR_TX, TC_ACT_OK\);\s*}/m.test(source), 'BPF ingress must account client TX');
  assert(/SEC\("tc\/egress"\)\s+int\s+lanspeed_egress\([^)]*\)\s*{\s*return account_frame\(skb, LANSPEED_DIR_RX, TC_ACT_OK\);\s*}/m.test(source), 'BPF egress must account client RX');
  assert(/SEC\("tc"\)\s+int\s+lanspeed_ingress_early\([^)]*\)\s*{\s*return account_frame\(skb, LANSPEED_DIR_TX, TC_ACT_UNSPEC\);\s*}/m.test(source), 'BPF early ingress must account client TX and continue to later filters');
  assert(/SEC\("tc"\)\s+int\s+lanspeed_egress_early\([^)]*\)\s*{\s*return account_frame\(skb, LANSPEED_DIR_RX, TC_ACT_UNSPEC\);\s*}/m.test(source), 'BPF early egress must account client RX and continue to later filters');
}

function validatePackageMakefile(makefile) {
  assert(makefile.includes('PKG_BUILD_DEPENDS:=bpf-headers'), 'package Makefile must build-depend on bpf-headers');
  assert(makefile.includes('include $(INCLUDE_DIR)/bpf.mk'), 'package Makefile must include bpf.mk');
  assert(makefile.includes('$(CONFIG_PACKAGE_lanspeedd-bpf)'), 'BPF build must be gated by optional lanspeedd-bpf selection');
  assert(makefile.includes('$(call CompileBPF,$(PKG_BUILD_DIR)/lanspeed_tc.bpf.c)'), 'package Makefile must build BPF object from BPF source with CompileBPF');
  assert(makefile.includes('$(CP) $(PKG_BUILD_DIR)/lanspeed_tc.bpf.o $(PKG_BUILD_DIR)/lanspeed_tc.o'), 'package Makefile must normalize SDK BPF output name');
  assert(makefile.includes('$(INSTALL_DATA) $(PKG_BUILD_DIR)/lanspeed_tc.o $(1)/usr/lib/bpf/lanspeed_tc.o'), 'package Makefile must install BPF object');
  assert(makefile.includes('DEPENDS:=+lanspeedd +libbpf $(BPF_DEPENDS)'), 'optional BPF package must carry libbpf and BPF dependencies');
  assert(!makefile.includes('if [ -f $(PKG_BUILD_DIR)/lanspeed_tc.o ]'), 'package Makefile must not silently skip missing BPF object');
}

function validateUci(config) {
  for (const required of [
    "option enabled '1'",
    "option refresh_interval_ms '1000'",
    "option max_clients '2048'",
    "list ifname 'br-lan'",
    "list interface_include 'br-lan'",
    "list interface_exclude 'wan'",
    "option enable_bpf '1'",
    "option enable_conntrack_fallback '1'",
    "option warning_confidence_below 'medium'",
    "option warning_stale_client_ms '5000'",
    "option warning_high_client_count '1536'",
    "option warning_collector_lag_ms '3000'"
  ]) {
    assert(config.includes(required), `UCI config missing ${required}`);
  }
}

const schema = readJson('net/lanspeedd/files/usr/share/lanspeed/schema.json');
const fixture = readJson('tests/fixtures/lanspeed-api.json');
const methodFixtures = {
  status: readJson('tests/fixtures/lanspeed-status.json'),
  clients: readJson('tests/fixtures/lanspeed-clients.json'),
  health: readJson('tests/fixtures/lanspeed-health.json'),
  interfaces: readJson('tests/fixtures/lanspeed-interfaces.json')
};
const acl = readJson('applications/luci-app-lanspeed/root/usr/share/rpcd/acl.d/luci-app-lanspeed.json');
const source = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeedd.c'), 'utf8');
const bpfSource = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeed_tc.bpf.c'), 'utf8');
const packageMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const uciConfig = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/config/lanspeed'), 'utf8');

assertSchemaRequired(schema, 'status', ['mode', 'confidence', 'warnings', 'evidence', 'refresh_interval_ms', 'version', 'capabilities']);
assertSchemaRequired(schema, 'client', ['mac', 'identity_key', 'zone', 'interface', 'ips', 'hostname', 'rx_bps', 'tx_bps', 'last_seen', 'collector_mode', 'confidence', 'warnings']);
assertSchemaRequired(schema, 'health', ['mode', 'confidence', 'capabilities', 'conflicts', 'warnings', 'evidence']);
assertSchemaRequired(schema, 'interface', ['name', 'role', 'status']);
validateRootSchema(schema);
assert(schema.$defs.status.properties.refresh_interval_ms.minimum === 500, 'schema must reject/clamp refresh_interval_ms below 500ms');
validateFixture(fixture);
validateMethodFixtures(schema, methodFixtures);
validateAcl(acl);
validateSource(source);
validateBpfSource(bpfSource);
validatePackageMakefile(packageMakefile);
validateUci(uciConfig);

console.log('lanspeed contract validation passed');
