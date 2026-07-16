#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const UBUS_METHODS = Object.freeze([
  'status',
  'clients',
  'overview',
  'health',
  'reload',
  'interfaces',
  'sysdevices',
  'client_connections'
]);

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

function assertSchemaExactObject(schema, defName, fields) {
  const definition = schema.$defs && schema.$defs[defName];
  assertObject(definition, `$defs.${defName}`);
  assert(definition.type === 'object', `schema $defs.${defName} must be an object schema`);
  assert(definition.additionalProperties === false,
    `schema $defs.${defName} must reject additional properties`);
  assert(sameStringSet(Object.keys(definition.properties || {}), fields),
    `schema $defs.${defName} properties must be exactly ${fields.join(', ')}`);
  assertArray(definition.required, `$defs.${defName}.required`);
  assert(sameStringSet(definition.required, fields),
    `schema $defs.${defName}.required must be exactly ${fields.join(', ')}`);
}

function sameStringSet(actual, expected) {
  const left = [...actual].sort();
  const right = [...expected].sort();
  return JSON.stringify(left) === JSON.stringify(right);
}

function readRustCapabilityKeys() {
  const source = fs.readFileSync(
    path.join(root, 'net/lanspeedd/rust/crates/lanspeedd/tests/json_contract.rs'),
    'utf8'
  );
  const match = source.match(/const\s+CAPABILITY_KEYS\s*:\s*\[&str;\s*(\d+)\]\s*=\s*\[([\s\S]*?)\];/);
  assert(match, 'Rust json contract must expose CAPABILITY_KEYS');
  const declaredCount = Number(match[1]);
  const keys = [...match[2].matchAll(/"([^"]+)"/g)].map((entry) => entry[1]);
  assert(keys.length === declaredCount,
    `Rust CAPABILITY_KEYS declares ${declaredCount} entries but contains ${keys.length}`);
  return keys;
}

function readPackageVersion() {
  const source = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
  const readAssignment = (name) => {
    const match = source.match(new RegExp(`^${name}:=([^\\s#]+)\\s*$`, 'm'));
    assert(match, `net/lanspeedd/Makefile must define ${name}`);
    return match[1];
  };
  return `${readAssignment('PKG_VERSION')}-r${readAssignment('PKG_RELEASE')}`;
}

function validateRustSchemaParity(schema, rustCapabilityKeys) {
  const errors = [];
  const expect = (condition, message) => {
    if (!condition) {
      errors.push(message);
    }
  };
  const expectedRefs = UBUS_METHODS.map((method) => `#/$defs/${method}`);
  const actualRefs = Array.isArray(schema.oneOf) ? schema.oneOf.map((entry) => entry.$ref) : [];
  expect(sameStringSet(actualRefs, expectedRefs),
    `root oneOf must expose all ${UBUS_METHODS.length} Rust methods; got ${actualRefs.join(', ')}`);

  const capabilityProperties = schema.$defs?.capabilities?.properties || {};
  const schemaCapabilityKeys = Object.keys(capabilityProperties);
  expect(schemaCapabilityKeys.length === rustCapabilityKeys.length,
    `schema capabilities must define ${rustCapabilityKeys.length} Rust keys; got ${schemaCapabilityKeys.length}`);
  expect(sameStringSet(schemaCapabilityKeys, rustCapabilityKeys),
    `schema capability keys differ from Rust: ${schemaCapabilityKeys.join(', ')}`);
  const requiredCapabilityKeys = schema.$defs?.capabilities?.required || [];
  expect(sameStringSet(requiredCapabilityKeys, rustCapabilityKeys),
    `schema capabilities.required must equal all Rust keys; got ${requiredCapabilityKeys.join(', ')}`);

  const roles = schema.$defs?.interface?.properties?.role?.enum || [];
  expect(roles.includes('observe'), 'schema interface.role must allow Rust value observe');

  const interfaceProperties = schema.$defs?.interfaces?.properties || {};
  expect(Object.prototype.hasOwnProperty.call(interfaceProperties, 'monotonic_ms'),
    'schema interfaces must allow Rust field monotonic_ms');
  expect(Object.prototype.hasOwnProperty.call(interfaceProperties, 'note'),
    'schema interfaces must allow Rust field note');

  expect(Boolean(schema.$defs?.reload), 'schema must define the Rust reload response for its fixture');

  assert(errors.length === 0, `schema/Rust contract mismatch:\n- ${errors.join('\n- ')}`);
}

function resolveSchema(schema, fragment) {
  const prefix = '#/$defs/';
  assert(fragment.startsWith(prefix), `unsupported schema ref ${fragment}`);
  const definition = schema.$defs && schema.$defs[fragment.slice(prefix.length)];
  assertObject(definition, fragment);
  return definition;
}

function validateValue(schema, definition, value, pathName) {
  if (Array.isArray(definition.anyOf)) {
    for (const candidate of definition.anyOf) {
      try {
        validateValue(schema, candidate, value, pathName);
        return;
      } catch (error) {
        // Try the next allowed shape before reporting the union failure.
      }
    }
    throw new Error(`${pathName} must match one of its allowed schemas`);
  }

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
    if (definition.maxItems !== undefined) {
      assert(value.length <= definition.maxItems,
        `${pathName} must contain <= ${definition.maxItems} items`);
    }
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
    if (definition.maximum !== undefined) {
      assert(value <= definition.maximum, `${pathName} must be <= ${definition.maximum}`);
    }
    return;
  }

  if (definition.type === 'boolean') {
    assert(typeof value === 'boolean', `${pathName} must be a boolean`);
    return;
  }

  if (definition.type === 'null') {
    assert(value === null, `${pathName} must be null`);
    return;
  }

  const schemaType = definition.type === undefined ? 'missing' : definition.type;
  throw new Error(`${pathName} uses unsupported schema type ${String(schemaType)}`);
}

function validateValidatorSelfTests() {
  let maximumError;
  try {
    validateValue({}, { type: 'integer', maximum: 100 }, 101, 'integer maximum self-test');
  } catch (error) {
    maximumError = error;
  }
  assert(maximumError?.message === 'integer maximum self-test must be <= 100',
    'validator must reject integers above schema maximum');

  let maxItemsError;
  try {
    validateValue({}, { type: 'array', maxItems: 512 }, Array(513).fill(null), 'array maxItems self-test');
  } catch (error) {
    maxItemsError = error;
  }
  assert(maxItemsError?.message === 'array maxItems self-test must contain <= 512 items',
    'validator must reject arrays above schema maxItems');

  const nullableObject = {
    anyOf: [
      { type: 'object', additionalProperties: false, properties: {}, required: [] },
      { type: 'null' }
    ]
  };
  validateValue({}, nullableObject, null, 'nullable object self-test');

  const failures = [];
  for (const [label, value] of [
    ['number', 7],
    ['string', 'wrong'],
    ['array', []],
    ['boolean', false]
  ]) {
    let error;
    try {
      validateValue({}, nullableObject, value, `nullable object ${label} self-test`);
    } catch (caught) {
      error = caught;
    }
    if (!error) {
      failures.push(`nullable object schema accepted ${label}`);
    }
  }

  let unsupportedTypeError;
  try {
    validateValue({}, { type: 'unsupported' }, 'value', 'unsupported type self-test');
  } catch (error) {
    unsupportedTypeError = error;
  }
  if (!unsupportedTypeError) {
    failures.push('unknown schema type was accepted');
  }
  assert(failures.length === 0, `validator self-tests failed:\n- ${failures.join('\n- ')}`);
}

function validateRootSchema(schema) {
  assertArray(schema.oneOf, 'schema.oneOf');
  const refs = schema.oneOf.map((entry) => entry.$ref).sort();
  const expectedRefs = UBUS_METHODS.map((method) => `#/$defs/${method}`).sort();
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
    'rate_collector_mode',
    'conn_collector_mode',
    'version',
    'capabilities'
  ], 'status');
  assertArray(fixture.status.warnings, 'status.warnings');
  assertObject(fixture.status.evidence, 'status.evidence');
  assertObject(fixture.status.capabilities, 'status.capabilities');
  assert(fixture.status.mode === 'Unsupported', 'status fixture must use planned Unsupported mode for stub stage');
  assert(fixture.status.version === packageVersion,
    `status fixture version must match net/lanspeedd/Makefile (${packageVersion})`);
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

  assertRequired(fixture.overview, ['samples'], 'overview response');
  assertArray(fixture.overview.samples, 'overview.samples');
  assert(fixture.overview.active_client_window_ms === 10000, 'overview fixture must expose active_client_window_ms');
  assert(fixture.overview.active_client_min_bps === 1, 'overview fixture must expose active_client_min_bps');
  assert(fixture.overview.max_samples === 240, 'overview fixture must expose max_samples');
  if (fixture.overview.samples.length > 0) {
    assertRequired(fixture.overview.samples[0], [
      'sample_ms',
      'tx_bps',
      'rx_bps',
      'client_count',
      'active_clients'
    ], 'overview.samples[0]');
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

  assertRequired(fixture.sysdevices, ['devices', 'current_ifnames', 'current_observed'], 'sysdevices response');
  assertArray(fixture.sysdevices.devices, 'sysdevices.devices');
  assertArray(fixture.sysdevices.current_ifnames, 'sysdevices.current_ifnames');
  assertArray(fixture.sysdevices.current_observed, 'sysdevices.current_observed');
  assert(fixture.sysdevices.devices.length > 0, 'sysdevices fixture must include at least one network device');
  for (const [index, dev] of fixture.sysdevices.devices.entries()) {
    assertRequired(dev, [
      'name',
      'selected',
      'observed',
      'recommended_lan',
      'is_bridge',
      'is_bridge_port',
      'is_nss_ifb'
    ], `sysdevices.devices[${index}]`);
  }

  validateClientConnectionsFixture(fixture.client_connections, 'client_connections response');
}

function validateClientConnectionsFixture(response, pathName) {
  const envelopeFields = [
    'available',
    'sample_ms',
    'client',
    'total_connections',
    'returned_connections',
    'truncated',
    'limit',
    'conn_source',
    'conn_semantics',
    'connections',
    'warnings'
  ];
  const summaryFields = ['identity_key', 'hostname', 'mac', 'ips', 'interface', 'zone'];
  const detailFields = [
    'client_ip',
    'client_port',
    'remote_ip',
    'remote_port',
    'protocol',
    'state',
    'direction'
  ];

  assertRequired(response, envelopeFields, pathName);
  assert(sameStringSet(Object.keys(response), envelopeFields),
    `${pathName} must keep the exact Rust envelope key set`);
  assertRequired(response.client, summaryFields, `${pathName}.client`);
  assert(sameStringSet(Object.keys(response.client), summaryFields),
    `${pathName}.client must keep the exact Rust summary key set`);
  assertArray(response.client.ips, `${pathName}.client.ips`);
  assertArray(response.connections, `${pathName}.connections`);
  assertArray(response.warnings, `${pathName}.warnings`);
  assert(response.connections.length >= 2,
    `${pathName}.connections must include IPv4 UDP and IPv6 TCP examples`);
  for (const [index, connection] of response.connections.entries()) {
    assertRequired(connection, detailFields, `${pathName}.connections[${index}]`);
    assert(sameStringSet(Object.keys(connection), detailFields),
      `${pathName}.connections[${index}] must keep the exact Rust detail key set`);
  }

  const ipv4Udp = response.connections.find((connection) =>
    connection.protocol === 'udp' &&
    !connection.client_ip.includes(':') &&
    !connection.remote_ip.includes(':')
  );
  const ipv6Tcp = response.connections.find((connection) =>
    connection.protocol === 'tcp' &&
    connection.client_ip.includes(':') &&
    connection.remote_ip.includes(':')
  );
  assert(ipv4Udp && ipv4Udp.state === 'assured' && ipv4Udp.direction === 'outbound',
    `${pathName} must include an outbound assured IPv4 UDP example`);
  assert(ipv6Tcp && ipv6Tcp.state === 'established' && ipv6Tcp.direction === 'inbound',
    `${pathName} must include an inbound established IPv6 TCP example`);
  assert(response.total_connections === response.connections.length,
    `${pathName}.total_connections must match the complete fixture`);
  assert(response.returned_connections === response.connections.length,
    `${pathName}.returned_connections must match connections.length`);
  assert(response.truncated === false && response.limit === 512,
    `${pathName} must demonstrate an untruncated response with the Rust limit`);
}

function validateClientConnectionsArrayLimit(schema, response) {
  const detail = response.connections[0];
  const atLimit = {
    ...response,
    total_connections: 512,
    returned_connections: 512,
    truncated: false,
    connections: Array.from({ length: 512 }, () => ({ ...detail }))
  };
  validateValue(schema, schema.$defs.client_connections, atLimit,
    'client_connections 512-item response');

  const aboveLimit = {
    ...atLimit,
    total_connections: 513,
    returned_connections: 512,
    truncated: true,
    connections: [...atLimit.connections, { ...detail }]
  };
  let maxItemsError;
  try {
    validateValue(schema, schema.$defs.client_connections, aboveLimit,
      'client_connections 513-item response');
  } catch (error) {
    maxItemsError = error;
  }
  assert(maxItemsError?.message ===
    'client_connections 513-item response.connections must contain <= 512 items',
    'schema must reject client_connections connections above 512 items via maxItems');
}

function validateMethodFixtures(schema, fixtures) {
  for (const method of UBUS_METHODS) {
    validateValue(schema, schema.$defs[method], fixtures[method], `${method} method response`);
  }
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
  const expectedReadMethods = UBUS_METHODS.filter((method) => method !== 'reload');
  assert(app.read.ubus.lanspeed.length === expectedReadMethods.length,
    `ACL must grant exactly ${expectedReadMethods.length} lanspeed read methods, got ${app.read.ubus.lanspeed.length}`);
  for (const method of expectedReadMethods) {
    assert(app.read.ubus.lanspeed.includes(method), `ACL must grant read ubus method ${method}`);
  }
  assert(app.read.uci.length === 1 && app.read.uci[0] === 'lanspeed', 'ACL must only grant read UCI access to lanspeed');

  /* The write side is intentionally narrow: the LuCI page writes the lanspeed
   * UCI config (to persist interface assignments), commits it via uci.*, and
   * triggers lanspeed.reload.  Routing this through rc.init is both broader
   * than needed and rejected by some rpcd rc implementations. */
  if (Object.prototype.hasOwnProperty.call(app, 'write')) {
    assertObject(app.write, 'ACL write');
    assertObject(app.write.ubus, 'ACL write.ubus');

    assertArray(app.write.ubus.lanspeed, 'ACL write.ubus.lanspeed');
    assert(app.write.ubus.lanspeed.length === 1 && app.write.ubus.lanspeed[0] === 'reload',
      'ACL write.ubus.lanspeed must grant only the reload method');
    assert(!Object.prototype.hasOwnProperty.call(app.write.ubus, 'rc'),
      'ACL write.ubus must not grant rc methods');

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

function validateRpc(rpcSource) {
  const declarations = [];
  const exported = Function('baseclass', 'rpc', rpcSource)(
    { extend: (value) => value },
    {
      declare: (specification) => {
        const callable = function declaredRpcCall() {};
        declarations.push({ specification, callable });
        return callable;
      }
    }
  );
  const matches = declarations.filter(({ specification }) =>
    specification.object === 'lanspeed' && specification.method === 'client_connections'
  );
  assert(matches.length === 1, 'rpc.js must declare client_connections exactly once');
  const declaration = matches[0];
  assert(sameStringSet(Object.keys(declaration.specification), ['object', 'method', 'params', 'expect']),
    'client_connections RPC declaration must contain only object, method, params and expect');
  assert(JSON.stringify(declaration.specification.params) === JSON.stringify(['identity_key']),
    'client_connections RPC declaration must pass identity_key');
  assert(JSON.stringify(declaration.specification.expect) === JSON.stringify({ '': {} }),
    'client_connections RPC declaration must keep the empty-object response contract');
  assert(exported.clientConnections === declaration.callable,
    'rpc.js must export client_connections as clientConnections');
}

function validateMenu(menu) {
  assertObject(menu['admin/status/lanspeed'], 'status menu parent entry');
  assert(menu['admin/status/lanspeed'].action.type === 'firstchild',
    'status menu parent must route to its first child so config can navigate back');
  assertObject(menu['admin/status/lanspeed/overview'], 'status overview menu entry');
  assert(menu['admin/status/lanspeed/overview'].action.path === 'lanspeed/overview',
    'status overview menu must point to the cache-aware lanspeed/overview entry');
  assert(menu['admin/status/lanspeed/overview'].depends.acl.includes('luci-app-lanspeed'),
    'status overview menu must require luci-app-lanspeed ACL');
  assertObject(menu['admin/status/lanspeed/diagnostics'], 'status diagnostics menu entry');
  assert(menu['admin/status/lanspeed/diagnostics'].action.path === 'lanspeed/diagnostics',
    'status diagnostics menu must point to the dedicated lanspeed/diagnostics entry');
  assert(menu['admin/status/lanspeed/diagnostics'].depends.acl.includes('luci-app-lanspeed'),
    'status diagnostics menu must require luci-app-lanspeed ACL');
  assertObject(menu['admin/status/lanspeed/config'], 'config menu entry');
  assert(menu['admin/status/lanspeed/config'].action.path === 'lanspeed/config',
    'config menu must point to the cache-busting lanspeed/config entry');
  assert(menu['admin/status/lanspeed/config'].depends.acl.includes('luci-app-lanspeed'),
    'config menu must require luci-app-lanspeed ACL');
}

function validateUci(config) {
  for (const required of [
    "option enabled '1'",
    "option refresh_interval_ms '1000'",
    "option active_client_window_ms '10000'",
    "option active_client_min_bps '1'",
    "option overview_window_samples '240'",
    "option rate_collector_mode 'auto'",
    "option conn_collector_mode 'auto'",
    "option show_client_status '0'",
    "option show_ipv6 '1'",
    "option hide_private_ipv6 '0'",
    "option hide_ipv6_ranges 'fc00::/7 fe80::/10'",
    "option collector_mode 'auto'",
    "option max_clients '2048'",
    "list ifname 'br-lan'",
    "list interface_include 'br-lan'",
    "list interface_exclude 'wan'",
    "list observe 'wan'",
    "option enable_bpf '1'",
    "option enable_conntrack_fallback '1'",
    "option warning_confidence_below 'medium'",
    "option warning_stale_client_ms '5000'",
    "option warning_high_client_count '1536'",
    "option warning_collector_lag_ms '3000'"
  ]) {
    assert(config.includes(required), `UCI config missing ${required}`);
  }

  const defaultAssignments = config.split('\n').filter((line) =>
    /^\s*list (?:ifname|interface_include|observe) /.test(line)
  ).map((line) => line.trim());
  assert(defaultAssignments.length === 3 &&
    defaultAssignments.includes("list ifname 'br-lan'") &&
    defaultAssignments.includes("list interface_include 'br-lan'") &&
    defaultAssignments.includes("list observe 'wan'"),
  'default interfaces must collect br-lan, observe wan and leave every other interface off');
}

const schema = readJson('net/lanspeedd/files/usr/share/lanspeed/schema.json');
const rustCapabilityKeys = readRustCapabilityKeys();
const packageVersion = readPackageVersion();
const fixture = readJson('tests/fixtures/lanspeed-api.json');
const methodFixtures = Object.fromEntries(UBUS_METHODS.map((method) => [
  method,
  readJson(`tests/fixtures/lanspeed-${method.replaceAll('_', '-')}.json`)
]));
const acl = readJson('applications/luci-app-lanspeed/root/usr/share/rpcd/acl.d/luci-app-lanspeed.json');
const rpcSource = fs.readFileSync(
  path.join(root, 'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/rpc.js'),
  'utf8'
);
const menu = readJson('applications/luci-app-lanspeed/root/usr/share/luci/menu.d/luci-app-lanspeed.json');
const uciConfig = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/config/lanspeed'), 'utf8');

validateRustSchemaParity(schema, rustCapabilityKeys);
validateValidatorSelfTests();
assert(methodFixtures.status.version === packageVersion,
  `status fixture version must match net/lanspeedd/Makefile (${packageVersion})`);
assert(methodFixtures.reload.version === packageVersion,
  `reload fixture version must match net/lanspeedd/Makefile (${packageVersion})`);
assertSchemaRequired(schema, 'status', ['mode', 'confidence', 'warnings', 'evidence', 'refresh_interval_ms', 'version', 'capabilities']);
assertSchemaRequired(schema, 'client', ['mac', 'identity_key', 'zone', 'interface', 'ips', 'hostname', 'rx_bps', 'tx_bps', 'last_seen', 'collector_mode', 'confidence', 'warnings']);
assertSchemaRequired(schema, 'health', ['mode', 'confidence', 'capabilities', 'conflicts', 'warnings', 'evidence']);
assertSchemaRequired(schema, 'reload', ['ok', 'mode', 'warnings', 'evidence', 'version']);
assertSchemaRequired(schema, 'interface', ['name', 'role', 'status']);
assertSchemaRequired(schema, 'sysdevice', ['name', 'selected', 'observed', 'recommended_lan', 'is_bridge', 'is_bridge_port', 'is_nss_ifb']);
assertSchemaRequired(schema, 'sysdevices', ['devices', 'current_ifnames', 'current_observed']);
assertSchemaExactObject(schema, 'clientConnectionDetail', [
  'client_ip',
  'client_port',
  'remote_ip',
  'remote_port',
  'protocol',
  'state',
  'direction'
]);
assertSchemaExactObject(schema, 'clientConnectionSummary', [
  'identity_key',
  'hostname',
  'mac',
  'ips',
  'interface',
  'zone'
]);
assertSchemaExactObject(schema, 'client_connections', [
  'available',
  'sample_ms',
  'client',
  'total_connections',
  'returned_connections',
  'truncated',
  'limit',
  'conn_source',
  'conn_semantics',
  'connections',
  'warnings'
]);
assert(Array.isArray(schema.$defs.client_connections.properties.client.anyOf) &&
  sameStringSet(
    schema.$defs.client_connections.properties.client.anyOf.map((entry) => entry.$ref || entry.type),
    ['#/$defs/clientConnectionSummary', 'null']
  ), 'schema client_connections.client must allow exactly a summary object or null');
assert(schema.$defs.client_connections.properties.connections.maxItems === 512,
  'schema client_connections.connections must cap arrays at 512 items');
validateRootSchema(schema);
assert(schema.$defs.status.properties.refresh_interval_ms.minimum === 500, 'schema must reject/clamp refresh_interval_ms below 500ms');
assert(schema.$defs.status.properties.active_client_window_ms.minimum === 1000, 'schema must reject/clamp active_client_window_ms below 1000ms');
assert(schema.$defs.status.properties.active_client_min_bps.minimum === 1, 'schema must reject/clamp active_client_min_bps below 1bps');
assert(schema.$defs.status.properties.collector_mode.$ref === '#/$defs/collectorMode', 'schema status.collector_mode must reuse collectorMode enum');
assert(schema.$defs.status.properties.rate_collector_mode.$ref === '#/$defs/rateCollectorMode', 'schema status.rate_collector_mode must reuse rateCollectorMode enum');
assert(schema.$defs.status.properties.conn_collector_mode.$ref === '#/$defs/connCollectorMode', 'schema status.conn_collector_mode must reuse connCollectorMode enum');
assert(schema.$defs.collectorMode.enum.includes('auto'), 'schema must allow status.collector_mode=auto');
assert(schema.$defs.collectorMode.enum.includes('bpf'), 'schema must allow status.collector_mode=bpf');
assert(schema.$defs.collectorMode.enum.includes('nss_ecm_direct'), 'schema must allow status.collector_mode=nss_ecm_direct');
assert(schema.$defs.collectorMode.enum.includes('nss_conntrack_sync'), 'schema must allow status.collector_mode=nss_conntrack_sync');
assert(schema.$defs.collectorMode.enum.includes('conntrack_netlink'), 'schema must allow status.collector_mode=conntrack_netlink');
assert(schema.$defs.collectorMode.enum.includes('conntrack_procfs'), 'schema must allow status.collector_mode=conntrack_procfs');
assert(schema.$defs.rateCollectorMode.enum.includes('auto'), 'schema must allow rate_collector_mode=auto');
assert(schema.$defs.rateCollectorMode.enum.includes('bpf'), 'schema must allow rate_collector_mode=bpf');
assert(schema.$defs.rateCollectorMode.enum.includes('nss_ecm_direct'), 'schema must allow rate_collector_mode=nss_ecm_direct');
assert(schema.$defs.rateCollectorMode.enum.includes('nss_conntrack_sync'), 'schema must allow rate_collector_mode=nss_conntrack_sync');
assert(!schema.$defs.rateCollectorMode.enum.includes('conntrack_netlink'), 'schema must not offer CT-Netlink as a non-NSS live speed mode');
assert(schema.$defs.connCollectorMode.enum.includes('auto'), 'schema must allow conn_collector_mode=auto');
assert(schema.$defs.connCollectorMode.enum.includes('conntrack_netlink'), 'schema must allow conn_collector_mode=conntrack_netlink');
assert(schema.$defs.connCollectorMode.enum.includes('conntrack_procfs'), 'schema must allow conn_collector_mode=conntrack_procfs');
assert(schema.$defs.overview.properties.overview_window_samples.minimum === 2, 'schema must expose overview_window_samples for trend rendering');
assert(schema.$defs.clients.properties.conn_source.enum.includes('conntrack_netlink'), 'schema must allow conn_source=conntrack_netlink');
assert(schema.$defs.clients.properties.conn_source.enum.includes('conntrack_procfs'), 'schema must allow conn_source=conntrack_procfs');
assert(schema.$defs.clients.properties.conn_source.enum.includes('nss_ecm_direct'), 'schema must allow conn_source=nss_ecm_direct');
assert(schema.$defs.clients.properties.conn_collector_mode.$ref === '#/$defs/connCollectorMode', 'schema clients.conn_collector_mode must reuse connCollectorMode enum');
validateFixture(fixture);
validateMethodFixtures(schema, methodFixtures);
validateClientConnectionsFixture(methodFixtures.client_connections, 'client_connections method fixture');
validateClientConnectionsArrayLimit(schema, methodFixtures.client_connections);
validateRpc(rpcSource);
validateAcl(acl);
validateMenu(menu);
validateUci(uciConfig);

console.log('lanspeed contract validation passed');
