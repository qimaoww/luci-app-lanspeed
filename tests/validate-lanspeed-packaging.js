#!/usr/bin/env node

const fs = require('fs');
const childProcess = require('child_process');
const os = require('os');
const path = require('path');

const root = path.resolve(__dirname, '..');
const pkgMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const nssControlKmodMakefile = fs.readFileSync(path.join(root,
  'net/lanspeed-nss-control/Makefile'), 'utf8');
const nssControlSourceRoot = path.join(root, 'net/lanspeed-nss-control/src');
const nssControlSourceMakefile = fs.readFileSync(path.join(nssControlSourceRoot,
  'Makefile'), 'utf8');
const nssControlKmodSource = [
  'lanspeed_nss_control_core.c',
  'lanspeed_nss_control_ack.c',
  'lanspeed_nss_control_telemetry.c',
  'lanspeed_nss_control_genl.c',
  'lanspeed_nss_control_tags.c',
  'lanspeed_nss_control_trusted_ingress.c',
  'lanspeed_nss_control_nexthop.c',
  'lanspeed_nss_control_peer.c',
  'lanspeed_nss_control_igs.c'
].map((name) => fs.readFileSync(path.join(nssControlSourceRoot, name), 'utf8'))
  .join('\n');
const buildDriver = fs.readFileSync(
  path.join(root, 'net/lanspeedd/rust/crates/lanspeed-build/src/lib.rs'),
  'utf8'
);
const cargoConfig = fs.readFileSync(path.join(root, 'net/lanspeedd/rust/.cargo/config.toml'), 'utf8');
const x86ProfileMigration = fs.readFileSync(
  path.join(root, 'net/lanspeedd/files/etc/uci-defaults/95-lanspeed-x86-profile'),
  'utf8'
);
const nssShapingMigration = fs.readFileSync(
  path.join(root, 'net/lanspeedd/files/etc/uci-defaults/94-lanspeed-nss-shaping'),
  'utf8'
);
const initScript = fs.readFileSync(
  path.join(root, 'net/lanspeedd/files/etc/init.d/lanspeedd'),
  'utf8'
);
const luciMakefile = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/Makefile'), 'utf8');
const luciStaticRoot = path.join(
  root,
  'applications/luci-app-lanspeed/htdocs/luci-static/resources'
);
const luciResourceRoot = path.join(luciStaticRoot, 'lanspeed');
const luciViewRoot = path.join(luciStaticRoot, 'view/lanspeed');
const luciMenuPath = path.join(
  root,
  'applications/luci-app-lanspeed/root/usr/share/luci/menu.d/luci-app-lanspeed.json'
);
const luciMenuSource = fs.readFileSync(luciMenuPath, 'utf8');
const readmeLanding = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
const readme = [
  readmeLanding,
  'usage.md',
  'platforms.md',
  'operations.md',
  'development.md'
].map((source, index) => index === 0
  ? source
  : fs.readFileSync(path.join(root, 'docs/guide', source), 'utf8'))
  .join('\n');
const qaDevicePath = path.join(root, 'tests/qa-device.sh');
const qaDevice = fs.readFileSync(qaDevicePath, 'utf8');

const luciResources = [
	'moduleManifest.js',
	'configForm.js',
  'configModel.js',
  'configPlatform.js',
  'configPlatformX86.js',
  'configPlatformNss.js',
  'configStyle.js',
  'configStyleArgon.js',
  'configStyleAurora.js',
  'configStyleBase.js',
  'configStyleBootstrap.js',
  'configStyleResponsive.js',
  'configStyleShared.js',
	'configView.js',
	'designSystem.js',
	'designSystemArgon.js',
	'designSystemAurora.js',
	'designSystemBase.js',
	'designSystemBootstrap.js',
  'diagnosticsRefresh.js',
  'diagnosticsShell.js',
  'diagnosticsStyle.js',
  'diagnosticsStyleArgon.js',
  'diagnosticsStyleAurora.js',
  'diagnosticsStyleBase.js',
  'diagnosticsStyleBootstrap.js',
  'diagnosticsStyleResponsive.js',
	'diagnosticsSchema.js',
	'diagnosticsResources.js',
	'diagnosticsStates.js',
	'diagnosticsModel.js',
	'diagnosticsReport.js',
	'diagnosticsReportModel.js',
	'diagnosticsView.js',
	'clientConnections.js',
	'clientControl.js',
	'clientControlReasons.js',
	'clientControlReasonsShared.js',
	'clientControlReasonsX86.js',
	'clientControlReasonsNss.js',
	'dhcpHostnames.js',
	'clientDetailShell.js',
  'clientDetailStyle.js',
  'clientDetailStyleBase.js',
  'clientDetailStyleBootstrap.js',
  'clientDetailStyleArgon.js',
  'clientDetailStyleAurora.js',
  'clientDetailStyleResponsive.js',
  'clientDetailRefresh.js',
  'clientDetailView.js',
  'format.js',
  'geoLocation.js',
  'ifaceConfig.js',
  'rpc.js',
  'statusCollector.js',
  'statusIp.js',
  'statusRateMeta.js',
  'statusRefresh.js',
  'statusShell.js',
  'statusStyle.js',
  'statusStyleArgon.js',
  'statusStyleAurora.js',
  'statusStyleBase.js',
  'statusStyleBootstrap.js',
  'statusStyleResponsive.js',
  'statusOverview.js',
  'statusView.js',
  'theme.js',
  'vocab.js'
];
const luciViews = [ 'config.js', 'diagnostics.js', 'overview.js' ];
const clientDetailResources = [
	'clientConnections.js',
	'dhcpHostnames.js',
	'clientDetailShell.js',
  'clientDetailStyle.js',
  'clientDetailStyleBase.js',
  'clientDetailStyleBootstrap.js',
  'clientDetailStyleArgon.js',
  'clientDetailStyleAurora.js',
  'clientDetailStyleResponsive.js',
  'clientDetailRefresh.js',
  'clientDetailView.js',
  'geoLocation.js'
];
const clientConnectionsConntrackSemantics =
  'TCP 仅统计 ESTABLISHED + ASSURED，UDP 仅统计 ASSURED';
const versionedCachePattern = /(?:Live\d+|_live\d+)/;

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertMatch(source, pattern, message) {
  assert(pattern.test(source), message);
}

function assertNoMatch(source, pattern, message) {
  assert(!pattern.test(source), message);
}

function countLiteral(source, value) {
  return source.split(value).length - 1;
}

function assertExactNames(actual, expected, message) {
  const actualSorted = [...actual].sort();
  const expectedSorted = [...expected].sort();
  assert(JSON.stringify(actualSorted) === JSON.stringify(expectedSorted), message);
  assert(new Set(actual).size === actual.length, `${message}: entries must be unique`);
}

function walkFiles(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkFiles(entryPath));
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
  return files;
}

function assertNoVersionedCacheRequire(file, source) {
  const requires = [...source.matchAll(
    /(?:['"]require\s+([^'"]+)['"]|\brequire\s*\(\s*['"]([^'"]+)['"]\s*\))/g
  )].map((match) => match[1] || match[2]);
  requires.forEach((dependency) => {
    assertNoMatch(
      dependency,
      versionedCachePattern,
      `${path.relative(root, file)} must not require a numbered cache module: ${dependency}`
    );
  });
}

function assertNoVersionedCacheFiles(directory, label) {
  walkFiles(directory).forEach((file) => {
    const relative = path.relative(directory, file);
    assertNoMatch(relative, versionedCachePattern,
      `${label} must not contain numbered cache file ${relative}`);
    if (path.extname(file) === '.js') {
      assertNoVersionedCacheRequire(file, fs.readFileSync(file, 'utf8'));
    }
  });
}

function validateBuiltLuciApk() {
  const apkPath = process.env.LANSPEED_LUCI_APK;
  if (!apkPath) {
    return;
  }

  assert(fs.existsSync(apkPath), `LANSPEED_LUCI_APK does not exist: ${apkPath}`);
  const sdkRoot = process.env.IMMORTALWRT_ROOT || process.env.SDK_DIR;
  const apkTool = process.env.LANSPEED_APK_TOOL ||
    (sdkRoot ? path.join(sdkRoot, 'staging_dir/host/bin/apk') : null);
  if (!apkTool) {
    throw new Error('APK content validation requires LANSPEED_APK_TOOL or IMMORTALWRT_ROOT');
  }
  try {
    fs.accessSync(apkTool, fs.constants.X_OK);
  } catch (_error) {
    throw new Error(`APK content validation requires an executable apk tool: ${apkTool}`);
  }

  const extractRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lanspeed-luci-apk-'));
  try {
    childProcess.execFileSync(apkTool, [
      '--allow-untrusted',
      'extract',
      '--no-chown',
      '--destination', extractRoot,
      apkPath
    ], { encoding: 'utf8', stdio: [ 'ignore', 'pipe', 'pipe' ] });
    walkFiles(extractRoot).forEach((file) => {
      const relative = path.relative(extractRoot, file);
      assertNoMatch(relative, versionedCachePattern,
        `APK must not contain numbered cache file ${relative}`);
      assertNoMatch(fs.readFileSync(file).toString('utf8'), versionedCachePattern,
        `APK file ${relative} must not contain numbered cache references`);
    });
  } finally {
    fs.rmSync(extractRoot, { recursive: true, force: true });
  }
}

function hasExactClientConnectionsSemantics(source) {
  const paragraph = /^`client_connections`[^\n]*$/m.exec(source);
  return Boolean(paragraph && paragraph[0].includes(clientConnectionsConntrackSemantics));
}

function validateReadmeSemanticsSelfTest() {
  const valid = `\`client_connections\` 返回当前连接；${clientConnectionsConntrackSemantics}。`;
  assert(hasExactClientConnectionsSemantics(valid),
    'README semantics validator self-test must accept the complete conntrack contract');
  const missingTcpAssured = valid.replace('ESTABLISHED + ASSURED', 'ESTABLISHED');
  assert(missingTcpAssured !== valid,
    'README semantics validator mutation must remove TCP ASSURED');
  assert(!hasExactClientConnectionsSemantics(missingTcpAssured),
    'README semantics validator must reject a mutation that removes TCP ASSURED');
}

function writeExecutable(file, source) {
  fs.writeFileSync(file, source, { mode: 0o755 });
}

function readIfPresent(file) {
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
}

function nonEmptyLines(source) {
  return source.trim().split('\n').filter(Boolean);
}

function writeQaScenarioTools(fakeBin, jshnFixture, includeJsonfilter) {
  fs.mkdirSync(fakeBin);

  writeExecutable(path.join(fakeBin, 'sshpass'), `#!/bin/sh
printf '%s|%s|%s\\n' "$1" "$2" "$3" >> "$QA_SSHPASS_LOG"
[ "$1" = '-e' ] || exit 96
shift
exec "$@"
`);
  writeExecutable(path.join(fakeBin, 'ssh'), `#!/bin/sh
for remote_command do :; done
case "$remote_command" in
  *'clients_json=$(ubus call lanspeed clients)'*)
    replacement=". '$QA_JSHN_FIXTURE'"
    remote_command=$(printf '%s\\n' "$remote_command" | /usr/bin/sed "s#\\. /usr/share/libubox/jshn.sh#$replacement#")
    PATH="$QA_FAKE_BIN" /bin/sh -c "$remote_command"
    ;;
  *)
    exit 0
    ;;
esac
`);
  writeExecutable(path.join(fakeBin, 'ubus'), `#!/bin/sh
printf '%s|%s|%s|%s\\n' "\${1:-}" "\${2:-}" "\${3:-}" "\${4:-}" >> "$QA_UBUS_LOG"
case "\${3:-}" in
  clients)
    printf '%s\\n' "$QA_CLIENTS_JSON"
    exit "\${QA_CLIENTS_STATUS:-0}"
    ;;
  client_connections)
    printf '%s\\n' '{}'
    exit "\${QA_DETAIL_STATUS:-0}"
    ;;
  *)
    printf '%s\\n' '{}'
    ;;
esac
`);
  if (includeJsonfilter) {
    writeExecutable(path.join(fakeBin, 'jsonfilter'), `#!/bin/sh
/bin/cat >/dev/null
printf '%s\\n' 'jsonfilter' >> "$QA_JSONFILTER_LOG"
if [ "\${QA_JSONFILTER_STATUS:-0}" -eq 0 ] && [ -n "\${QA_IDENTITY:-}" ]; then
  printf '%s\\n' "$QA_IDENTITY"
fi
exit "\${QA_JSONFILTER_STATUS:-0}"
`);
  }

  writeExecutable(jshnFixture, `#!/bin/sh
printf '%s\\n' 'source' >> "$QA_JSHN_LOG"
if [ "\${QA_JSHN_SOURCE_STATUS:-0}" -ne 0 ]; then
  return "$QA_JSHN_SOURCE_STATUS"
fi

json_init() {
  printf '%s\\n' 'json_init' >> "$QA_JSHN_LOG"
  if [ "\${QA_JSON_INIT_STATUS:-0}" -ne 0 ]; then
    return "$QA_JSON_INIT_STATUS"
  fi
  QA_JSHN_IDENTITY=
}

json_add_string() {
  printf 'json_add_string|%s|%s\\n' "$1" "$2" >> "$QA_JSHN_LOG"
  if [ "\${QA_JSON_ADD_STATUS:-0}" -ne 0 ]; then
    return "$QA_JSON_ADD_STATUS"
  fi
  QA_JSHN_IDENTITY=$2
}

json_dump() {
  printf '%s\\n' 'json_dump' >> "$QA_JSHN_LOG"
  if [ "\${QA_JSON_DUMP_STATUS:-0}" -ne 0 ]; then
    return "$QA_JSON_DUMP_STATUS"
  fi
  [ "$QA_JSHN_IDENTITY" = "$QA_EXPECTED_IDENTITY" ] || return 34
  printf '%s\\n' "$QA_EXPECTED_PAYLOAD"
}
`);
}

function runQaDeviceScenario(tempRoot, scenario) {
  const scenarioRoot = path.join(tempRoot, 'scenarios', scenario.id);
  const fakeBin = path.join(scenarioRoot, 'bin');
  const output = path.join(scenarioRoot, 'output');
  const sshpassLog = path.join(scenarioRoot, 'sshpass.log');
  const ubusLog = path.join(scenarioRoot, 'ubus.log');
  const jsonfilterLog = path.join(scenarioRoot, 'jsonfilter.log');
  const jshnLog = path.join(scenarioRoot, 'jshn.log');
  const jshnFixture = path.join(scenarioRoot, 'jshn.sh');
  const secret = `scenario-secret-${scenario.id}`;
  const identity = scenario.identity || '';
  const expectedPayload = scenario.expectedPayload || JSON.stringify({ identity_key: identity });
  const clientsJson = scenario.clientsJson !== undefined
    ? scenario.clientsJson
    : JSON.stringify({ clients: identity ? [{ identity_key: identity }] : [] });

  fs.mkdirSync(scenarioRoot, { recursive: true });
  writeQaScenarioTools(fakeBin, jshnFixture, scenario.includeJsonfilter !== false);

  const stdout = childProcess.execFileSync('sh', [qaDevicePath, 'collect'], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${fakeBin}:${process.env.PATH}`,
      TARGET: 'root@192.0.2.1',
      DRY_RUN: '0',
      OUT_DIR: output,
      SSHPASS: secret,
      QA_FAKE_BIN: fakeBin,
      QA_SSHPASS_LOG: sshpassLog,
      QA_UBUS_LOG: ubusLog,
      QA_JSONFILTER_LOG: jsonfilterLog,
      QA_JSHN_LOG: jshnLog,
      QA_JSHN_FIXTURE: jshnFixture,
      QA_CLIENTS_JSON: clientsJson,
      QA_CLIENTS_STATUS: String(scenario.clientsStatus || 0),
      QA_JSONFILTER_STATUS: String(scenario.jsonfilterStatus || 0),
      QA_IDENTITY: identity,
      QA_JSHN_SOURCE_STATUS: String(scenario.jshnSourceStatus || 0),
      QA_JSON_INIT_STATUS: String(scenario.jsonInitStatus || 0),
      QA_JSON_ADD_STATUS: String(scenario.jsonAddStatus || 0),
      QA_JSON_DUMP_STATUS: String(scenario.jsonDumpStatus || 0),
      QA_EXPECTED_IDENTITY: identity,
      QA_EXPECTED_PAYLOAD: expectedPayload,
      QA_DETAIL_STATUS: String(scenario.detailStatus || 0)
    }
  });

  const evidence = fs.readFileSync(path.join(output, 'task-16-device-dry-run.txt'), 'utf8');
  const ubusLines = nonEmptyLines(readIfPresent(ubusLog));
  const clientCalls = ubusLines.filter((line) => line.startsWith('call|lanspeed|clients|'));
  const detailCalls = ubusLines.filter((line) => line.startsWith('call|lanspeed|client_connections|'));
  const commandExits = [...evidence.matchAll(/^command_exit=(\d+)$/gm)].map((match) => Number(match[1]));
  const jsonfilterCalls = nonEmptyLines(readIfPresent(jsonfilterLog));
  const jshnCalls = nonEmptyLines(readIfPresent(jshnLog));
  const sshpassCalls = nonEmptyLines(readIfPresent(sshpassLog));
  const artifacts = [
    stdout,
    evidence,
    readIfPresent(ubusLog),
    readIfPresent(jsonfilterLog),
    readIfPresent(jshnLog),
    readIfPresent(sshpassLog)
  ].join('\n');

  assert(clientCalls.length === 1, `${scenario.id}: clients must be called exactly once`);
  assert(
    detailCalls.length === scenario.expectedDetailCalls,
    `${scenario.id}: expected ${scenario.expectedDetailCalls} client_connections calls, got ${detailCalls.length}`
  );
  assert(
    jsonfilterCalls.length === scenario.expectedJsonfilterCalls,
    `${scenario.id}: expected ${scenario.expectedJsonfilterCalls} jsonfilter calls, got ${jsonfilterCalls.length}`
  );
  assert(
    JSON.stringify(commandExits) === JSON.stringify(scenario.expectedCommandExits),
    `${scenario.id}: expected command_exit ${JSON.stringify(scenario.expectedCommandExits)}, got ${JSON.stringify(commandExits)}`
  );
  assert(
    JSON.stringify(jshnCalls) === JSON.stringify(scenario.expectedJshnCalls),
    `${scenario.id}: unexpected jshn call sequence ${JSON.stringify(jshnCalls)}`
  );
  assert(
    evidence.includes('client_connections skipped: no client identity_key') === Boolean(scenario.expectedSkip),
    `${scenario.id}: skip evidence did not match expectation`
  );
  if (scenario.expectedDetailCalls === 1) {
    assert(
      detailCalls[0] === `call|lanspeed|client_connections|${expectedPayload}`,
      `${scenario.id}: detail payload must be the exact json_dump output`
    );
  }
  assert(sshpassCalls.length > 0, `${scenario.id}: non-empty SSHPASS must invoke sshpass`);
  assert(
    sshpassCalls.every((line) => line === '-e|ssh|root@192.0.2.1'),
    `${scenario.id}: every remote call must use sshpass -e ssh before the target`
  );
  assert(!artifacts.includes(secret), `${scenario.id}: SSHPASS must not leak into output or logs`);
}

function validateQaDeviceContract() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lanspeed-qa-contract-'));
  const fakeBin = path.join(tempRoot, 'dry-bin');
  const dryOutput = path.join(tempRoot, 'dry-output');
  const forbiddenLog = path.join(tempRoot, 'dry-forbidden.log');
  fs.mkdirSync(fakeBin);

  try {
    for (const command of ['ssh', 'sshpass', 'ubus']) {
      writeExecutable(path.join(fakeBin, command), `#!/bin/sh\nprintf '%s\\n' '${command}' >> "$QA_FORBIDDEN_LOG"\nexit 97\n`);
    }

    const dryPlaceholder = 'dry-run-placeholder';
    childProcess.execFileSync('sh', [qaDevicePath, 'collect'], {
      cwd: root,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${fakeBin}:${process.env.PATH}`,
        TARGET: 'root@192.0.2.1',
        DRY_RUN: '1',
        OUT_DIR: dryOutput,
        SSHPASS: dryPlaceholder,
        QA_FORBIDDEN_LOG: forbiddenLog
      }
    });

    assert(readIfPresent(forbiddenLog) === '', 'DRY_RUN=1 must not execute ssh, sshpass, or ubus');
    const dryEvidencePath = path.join(dryOutput, 'task-16-device-dry-run.txt');
    assert(fs.existsSync(dryEvidencePath), 'qa-device dry-run must write task-16-device-dry-run.txt');
    const dryEvidence = fs.readFileSync(dryEvidencePath, 'utf8');
    assert(!dryEvidence.includes(dryPlaceholder), 'qa-device dry-run evidence must never expose SSHPASS');
    assert(
      dryEvidence.includes('coverage=ubus 十个方法: realtime, status, clients, overview, health, diagnostics, reload, interfaces, sysdevices, client_connections'),
      'qa-device evidence header must state all ten read/diagnostic ubus methods'
    );
    for (const method of [
      'realtime',
      'status',
      'clients',
      'overview',
      'health',
      'reload',
      'interfaces',
      'sysdevices',
      'client_connections'
    ]) {
      assert(
        dryEvidence.includes(`ubus call lanspeed ${method}`),
        `qa-device dry-run evidence must include the ${method} command template`
      );
    }
    assert(
      countLiteral(dryEvidence, 'ubus call lanspeed clients') === 1,
      'qa-device dry-run must capture the clients response exactly once'
    );
    assert(
      dryEvidence.includes("jsonfilter -e '@.clients[0].identity_key'"),
      'qa-device dry-run must extract the first client identity_key with jsonfilter'
    );
    assert(
      dryEvidence.includes('json_add_string identity_key "$identity_key"') &&
        dryEvidence.includes('client_payload=$(json_dump)'),
      'qa-device dry-run must show jshn payload construction for client_connections'
    );
    assert(
      /safety=.*reload.*(?:不修改|不会修改|不改).*UCI.*(?:网络|防火墙|代理)/.test(dryEvidence),
      'qa-device safety header must explain reload without claiming that collect is entirely read-only'
    );

    assertMatch(
      qaDevice,
      /if \[ -n "\$\{SSHPASS:-\}" \]; then\s+sshpass -e ssh \$SSH_OPTS "\$TARGET" "\$remote_command"\s+else\s+ssh \$SSH_OPTS "\$TARGET" "\$remote_command"\s+fi/,
      'qa-device remote_shell must use sshpass -e only when SSHPASS is non-empty and preserve plain ssh otherwise'
    );
    assert(
      countLiteral(qaDevice, 'remote_shell "$command" < /dev/null') === 2,
      'qa-device collect and iperf loops must detach remote ssh stdin so every planned command runs'
    );
    assert(
      countLiteral(qaDevice, 'for dev in $(uci -q get lanspeed.main.ifname)') === 3,
      'qa-device tc evidence must follow the configured LAN collection interfaces'
    );
    assertNoMatch(
      qaDevice,
      /tc (?:filter|qdisc) show dev br-lan/,
      'qa-device must not hard-code br-lan for real-device tc evidence'
    );
    assertNoMatch(qaDevice, /sshpass\s+-p/, 'qa-device must never pass a password on the sshpass command line');
    assertNoMatch(qaDevice, /\beval\b/, 'qa-device must not eval remote commands or JSON payloads');
    assertNoMatch(qaDevice, /\{["']identity_key["']\s*:/, 'qa-device must not build client_connections JSON with a raw string literal');
    assert(qaDevice.includes('. /usr/share/libubox/jshn.sh'), 'qa-device must load the remote jshn helper');
    assert(qaDevice.includes('json_init'), 'qa-device must initialize the remote jshn payload');
    assert(qaDevice.includes('json_add_string identity_key "$identity_key"'), 'qa-device must add identity_key through jshn');
    assert(qaDevice.includes('client_payload=$(json_dump)'), 'qa-device must serialize the detail payload through jshn');

    const plainIdentity = '02:00:00:00:00:42@eth1';
    const specialIdentity = 'client"quoted\\path@br-lan';
    const successfulJshnCalls = (identity) => [
      'source',
      'json_init',
      `json_add_string|identity_key|${identity}`,
      'json_dump'
    ];
    const scenarios = [
      {
        id: 'clients-ubus-failure-41',
        clientsStatus: 41,
        identity: plainIdentity,
        expectedDetailCalls: 0,
        expectedJsonfilterCalls: 0,
        expectedCommandExits: [41],
        expectedJshnCalls: []
      },
      {
        id: 'empty-clients-jsonfilter-no-match-1',
        clientsJson: '{"clients":[]}',
        jsonfilterStatus: 1,
        expectedDetailCalls: 0,
        expectedJsonfilterCalls: 1,
        expectedCommandExits: [],
        expectedJshnCalls: [],
        expectedSkip: true
      },
      {
        id: 'empty-output-jsonfilter-success-0',
        clientsJson: '{"clients":[]}',
        expectedDetailCalls: 0,
        expectedJsonfilterCalls: 1,
        expectedCommandExits: [],
        expectedJshnCalls: [],
        expectedSkip: true
      },
      {
        id: 'malformed-clients-jsonfilter-126',
        clientsJson: '{malformed',
        jsonfilterStatus: 126,
        expectedDetailCalls: 0,
        expectedJsonfilterCalls: 1,
        expectedCommandExits: [126],
        expectedJshnCalls: []
      },
      {
        id: 'jsonfilter-tool-failure-41',
        jsonfilterStatus: 41,
        expectedDetailCalls: 0,
        expectedJsonfilterCalls: 1,
        expectedCommandExits: [41],
        expectedJshnCalls: []
      },
      {
        id: 'jsonfilter-tool-missing-127',
        includeJsonfilter: false,
        expectedDetailCalls: 0,
        expectedJsonfilterCalls: 0,
        expectedCommandExits: [127],
        expectedJshnCalls: []
      },
      {
        id: 'jshn-source-failure-30',
        identity: plainIdentity,
        jshnSourceStatus: 30,
        expectedDetailCalls: 0,
        expectedJsonfilterCalls: 1,
        expectedCommandExits: [30],
        expectedJshnCalls: ['source']
      },
      {
        id: 'json-init-failure-31',
        identity: plainIdentity,
        jsonInitStatus: 31,
        expectedDetailCalls: 0,
        expectedJsonfilterCalls: 1,
        expectedCommandExits: [31],
        expectedJshnCalls: ['source', 'json_init']
      },
      {
        id: 'json-add-string-failure-32',
        identity: plainIdentity,
        jsonAddStatus: 32,
        expectedDetailCalls: 0,
        expectedJsonfilterCalls: 1,
        expectedCommandExits: [32],
        expectedJshnCalls: ['source', 'json_init', `json_add_string|identity_key|${plainIdentity}`]
      },
      {
        id: 'json-dump-failure-33',
        identity: plainIdentity,
        jsonDumpStatus: 33,
        expectedDetailCalls: 0,
        expectedJsonfilterCalls: 1,
        expectedCommandExits: [33],
        expectedJshnCalls: successfulJshnCalls(plainIdentity)
      },
      {
        id: 'quoted-backslash-identity-success',
        identity: specialIdentity,
        expectedPayload: JSON.stringify({ identity_key: specialIdentity }),
        expectedDetailCalls: 1,
        expectedJsonfilterCalls: 1,
        expectedCommandExits: [],
        expectedJshnCalls: successfulJshnCalls(specialIdentity)
      },
      {
        id: 'detail-ubus-failure-42',
        identity: plainIdentity,
        detailStatus: 42,
        expectedDetailCalls: 1,
        expectedJsonfilterCalls: 1,
        expectedCommandExits: [42],
        expectedJshnCalls: successfulJshnCalls(plainIdentity)
      }
    ];

    scenarios.forEach((scenario) => runQaDeviceScenario(tempRoot, scenario));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

try {
  validateBuiltLuciApk();
  validateReadmeSemanticsSelfTest();
  validateQaDeviceContract();
  const compileMatch = /^define Build\/Compile\n([\s\S]*?)^endef$/m.exec(pkgMakefile);
  assert(compileMatch, 'net/lanspeedd/Makefile must define Build/Compile');
  const compileBody = compileMatch[1];
  const bpfConditional = compileBody.indexOf('ifneq ($(LANSPEED_BPF_ENABLED),)');
  const userspaceBuild = compileBody.indexOf('build-userspace');
  const ebpfBuild = compileBody.indexOf('build-ebpf');

  assertMatch(
    pkgMakefile,
    /^PKG_BUILD_DEPENDS:=rust\/host$/m,
    'Rust Cargo workspace build is required'
  );
  assertMatch(pkgMakefile, /^PKG_BUILD_PARALLEL:=1$/m, 'Rust package build must enable OpenWrt parallel builds');
  assertMatch(pkgMakefile, /^RUST_PKG_LOCKED:=1$/m, 'Rust package build must keep Cargo.lock immutable');
  assertMatch(
    pkgMakefile,
    /LANSPEED_X86_CONTROL_DEPENDS:=\+TARGET_x86:tc-full \+TARGET_x86:ip \+TARGET_x86:nftables \+TARGET_x86:conntrack \+TARGET_x86:kmod-ifb \+TARGET_x86:kmod-sched-core \+TARGET_x86:kmod-sched/,
    'x86 client control must request the IFB and scheduler modules only behind the x86 architecture gate'
  );
  assertMatch(
    pkgMakefile,
    /LANSPEED_NSS_CONTROL_DEPENDS:=\+TARGET_qualcommax:tc-full \+TARGET_qualcommax:ip \+TARGET_qualcommax:nftables \+TARGET_qualcommax:conntrack \+TARGET_qualcommax:kmod-ifb \+TARGET_qualcommax:kmod-sched-core \+TARGET_qualcommax:kmod-qca-nss-drv-igs \+TARGET_qualcommax:kmod-lanspeed-nss-control/,
    'NSS client control must request its CPU-path modules only behind the qualcommax architecture gate'
  );
  assertMatch(nssControlKmodMakefile, /^PKG_VERSION:=1\.2\.0$/m,
    'NSS control kmod must stay on the daemon version');
  assertMatch(nssControlKmodMakefile, /^PKG_RELEASE:=2$/m,
    'NSS control kmod must stay on release 2');
  assertMatch(nssControlKmodMakefile,
    /^  DEPENDS:=@TARGET_qualcommax \+kmod-ifb \+kmod-qca-nss-drv \+kmod-qca-nss-drv-igs$/m,
    'NSS control kmod must be packaged only for qualcommax with verified IGS dependencies');
  assertMatch(nssControlKmodMakefile, /^  SOURCE:=lanspeed-nss-control$/m,
    'NSS control kmod package metadata must not expose a local build path');
  assertMatch(nssControlSourceMakefile,
    /^lanspeed_nss_control-objs := lanspeed_nss_control_core\.o lanspeed_nss_control_ack\.o lanspeed_nss_control_telemetry\.o lanspeed_nss_control_genl\.o lanspeed_nss_control_tags\.o lanspeed_nss_control_trusted_ingress\.o lanspeed_nss_control_nexthop\.o lanspeed_nss_control_peer\.o lanspeed_nss_control_igs\.o$/m,
    'NSS control kmod must link separate responsibility objects into one module');
  assertMatch(nssControlKmodMakefile,
    /define Package\/kmod-lanspeed-nss-control\/postinst[\s\S]*chown 0:0[\s\S]*kmod-lanspeed-nss-control\.list[\s\S]*lanspeed_nss_control\.ko[\s\S]*chmod 0644/,
    'NSS control kmod must normalize installed module metadata to root-owned mode 0644');
  assertNoMatch(nssControlKmodMakefile, /TARGET_x86|platform\/x86/,
    'NSS control kmod must not change or import the x86 platform');
  const nssPublishEntry = nssControlKmodSource.match(
    /static int lanspeed_igs_publish_entry[\s\S]*?(?=\nstatic int lanspeed_igs_unpublish_entry)/
  )?.[0] || '';
  const nssUnpublishEntry = nssControlKmodSource.match(
    /static int lanspeed_igs_unpublish_entry[\s\S]*?(?=\nstatic void lanspeed_igs_forget_edge)/
  )?.[0] || '';
  assert(nssControlKmodSource.includes('module_param_cb(stage') &&
    nssControlKmodSource.includes('module_param_cb(publish') &&
    nssControlKmodSource.includes('module_param_cb(unpublish') &&
    nssControlKmodSource.includes('module_param_cb(unstage') &&
    nssControlKmodSource.includes('LANSPEED_IGS_DEGRADED') &&
    nssPublishEntry.indexOf('NSS_IF_SET_IGS_NODE') <
      nssPublishEntry.indexOf('status = lanspeed_set_nexthop') &&
    nssUnpublishEntry.indexOf('lanspeed_reset_nexthop') <
      nssUnpublishEntry.indexOf('NSS_IF_CLEAR_IGS_NODE'),
    'NSS control kmod must stage queues before transactional publish and reset before clear');
  assert(
    nssControlKmodSource.includes('NSS_DYNAMIC_INTERFACE_TYPE_VAP') &&
      nssControlKmodSource.includes('NSS_WIFI_VDEV_SET_NEXT_HOP') &&
      nssControlKmodSource.includes('lanspeed_ack_callback') &&
      nssControlKmodSource.includes('wait_for_completion_timeout(&txn->done') &&
      nssControlKmodSource.includes('txn->response == NSS_CMN_RESPONSE_ACK'),
    'NSS control kmod must use the acknowledged Wi-Fi vdev nexthop transaction for dynamic VAP edges'
  );
  assert(
    nssControlKmodSource.includes('rtnl_dereference(entry->dev->qdisc)') &&
      nssControlKmodSource.includes('rtnl_dereference(queue->qdisc_sleeping)') &&
      nssControlKmodSource.includes('qdisc->handle') &&
      nssControlKmodSource.includes('error = -EBUSY'),
    'NSS control kmod must reject unstage while a device-root or queue-root qdisc still owns the IGS device'
  );
  assertNoMatch(
    pkgMakefile,
    /\+kmod-(?:qca-nss-drv-qdisc|qca-nss-ecm)\b|sqm-scripts|qosify/,
    'the x86 client shaper must not leak NSS dependencies or take ownership from external SQM/QoS services'
  );
  assert(
    (pkgMakefile.match(/^\s*SOURCE:=lanspeedd$/gm) || []).length === 2,
    'daemon and BPF package metadata must use a stable origin without leaking the build path'
  );
  assertMatch(
    luciMakefile,
    /^\s*SOURCE:=luci-app-lanspeed$/m,
    'LuCI package metadata must use a stable origin without leaking the build path'
  );
  assertMatch(
    pkgMakefile,
    /include \$\(TOPDIR\)\/feeds\/packages\/lang\/rust\/rust-package\.mk/,
    'net/lanspeedd/Makefile must use the ImmortalWrt rust-package integration'
  );
  assertMatch(
    pkgMakefile,
    /\$\(CP\) \.\/rust\/Cargo\.toml \.\/rust\/Cargo\.lock \$\(PKG_BUILD_DIR\)\//,
    'Build/Prepare must copy the Cargo workspace manifests'
  );
  for (const directory of ['.cargo', 'crates', 'vendor']) {
    assert(
      pkgMakefile.includes(`$(CP) ./rust/${directory} $(PKG_BUILD_DIR)/`),
      `Build/Prepare must copy rust/${directory}`
    );
  }
  assertNoMatch(pkgMakefile, /\.\/rust\/(?:\.\s|\*|target)/, 'Build/Prepare must not copy local Cargo target artifacts');
  assertMatch(
    pkgMakefile,
    /cd \$\(PKG_BUILD_DIR\) &&[\s\S]*cargo build -v --manifest-path Cargo\.toml -p lanspeed-build --release --target \$\(RUSTC_HOST_ARCH\) --locked --offline/,
    'Build/Compile must run the pinned host build inside PKG_BUILD_DIR so Cargo loads the vendored-source config'
  );
  assertMatch(pkgMakefile, /LANSPEED_USERSPACE_TARGET="\$\(RUSTC_TARGET_ARCH\)"/, 'userspace target must come from the SDK');
  assertMatch(pkgMakefile, /LANSPEED_VERSION="\$\(PKG_VERSION\)"/, 'Cargo build must receive PKG_VERSION');
  assertMatch(pkgMakefile, /LANSPEED_RELEASE="\$\(PKG_RELEASE\)"/, 'Cargo build must receive PKG_RELEASE');
  assertNoMatch(pkgMakefile, /OPENWRT_STAGING_LIB/, 'pure Rust userspace must not receive a target library link directory');
  assertMatch(pkgMakefile, /build-userspace/, 'base package pass must invoke the userspace build driver');
  assertMatch(pkgMakefile, /build-ebpf/, 'BPF package pass must invoke the eBPF build driver');
  assert(userspaceBuild >= 0 && bpfConditional >= 0 && userspaceBuild < bpfConditional,
    'userspace must always build before the separate eBPF package step');
  assert(ebpfBuild > bpfConditional, 'eBPF build must be conditional and additive');
  assertMatch(pkgMakefile, /^\s*FILE:=bpf-linker-0\.10\.3-x86_64-unknown-linux-musl\.tar\.gz$/m, 'bpf-linker cache name must include its pinned version');
  assertMatch(pkgMakefile, /^\s*URL_FILE:=bpf-linker-x86_64-unknown-linux-musl\.tar\.gz$/m, 'bpf-linker remote archive name must remain official');
  assertMatch(
    pkgMakefile,
    /^\s*URL:=https:\/\/github\.com\/aya-rs\/bpf-linker\/releases\/download\/v0\.10\.3\/$/m,
    'bpf-linker 0.10.3 download URL must be official'
  );
  assertMatch(
    pkgMakefile,
    /^\s*HASH:=0fa4645d2dfbb5cafe6231b0aa9fad4f1430bd0871e3bd7319e82d827bf6262c$/m,
    'bpf-linker archive SHA256 must be pinned'
  );
  assertMatch(
    pkgMakefile,
    /ifneq \(\$\(LANSPEED_BPF_ENABLED\),\)\s*ifeq \(\$\(HOST_ARCH\),x86_64\)\s*\$\(eval \$\(call Download,bpf-linker\)\)\s*endif\s*endif/,
    'bpf-linker download must be registered only for BPF builds on its supported host architecture'
  );
  assertMatch(
    pkgMakefile,
    /test "\$\(HOST_ARCH\)" = "x86_64" \|\|/,
    'BPF Build/Prepare must reject unsupported build hosts without breaking package metadata expansion'
  );
  assertMatch(pkgMakefile, /BPF_LINKER="\$\(BPF_LINKER\)"/, 'eBPF build must use the extracted pinned linker');
	assertMatch(pkgMakefile, /LANSPEED_BPF_TARGET_ARCH="\$\(ARCH\)"/,
		'eBPF build must receive the OpenWrt target architecture explicitly');
	assert(buildDriver.includes('PINNED_BPF_LINKER: &str = "0.10.3"'), 'build driver must retain the packaged bpf-linker version');
	assert(buildDriver.includes('MINIMUM_BPF_LINKER: &str = PINNED_BPF_LINKER') &&
		buildDriver.includes('MAXIMUM_BPF_LINKER_EXCLUSIVE: &str = "0.11.0"') &&
		buildDriver.includes('validate_version_range('),
		'build driver must accept the compatible stable bpf-linker 0.10.x range');
  assert(buildDriver.includes('"--locked"') && buildDriver.includes('"--offline"'), 'build driver must use locked offline Cargo');
	assert(buildDriver.includes('BPF_TARGET_ARCH_ENV: &str = "LANSPEED_BPF_TARGET_ARCH"') &&
		buildDriver.includes('command.env("AYA_BPF_TARGET_ARCH", target_arch.aya_name())') &&
		buildDriver.includes('target_arch.builds_ecm()'),
		'build driver must separate x86 TC objects from the aarch64 ECM object ABI');
  assert(cargoConfig.includes('replace-with = "vendored-sources"'), 'Cargo must use vendored sources');
  assert(cargoConfig.includes('offline = true'), 'Cargo config must forbid network dependency resolution');
  assertMatch(
    cargoConfig,
    /\[target\.bpfel-unknown-none\][\s\S]*linker = "bpf-linker"[\s\S]*rustflags = \["-C", "debuginfo=2", "-C", "link-arg=--btf"\]/,
    'the Cargo config copied into PKG_BUILD_DIR must make production eBPF objects retain BTF'
  );
  assertMatch(
    pkgMakefile,
    /\$\(INSTALL_BIN\) \$\(PKG_BUILD_DIR\)\/target\/\$\(RUSTC_TARGET_ARCH\)\/release\/lanspeedd \$\(1\)\/usr\/sbin\/lanspeedd/,
    'base package must install the Rust daemon'
  );
  for (const object of ['lanspeed-ebpf-kfunc', 'lanspeed-ebpf-fallback']) {
    assert(
      pkgMakefile.includes(`$(INSTALL_DATA) $(PKG_BUILD_DIR)/target/bpfel-unknown-none/release/${object} $(1)/usr/lib/bpf/${object}.o`),
      `lanspeedd-bpf must install ${object} with an .o suffix so OpenWrt does not target-strip the eBPF ELF`
    );
    assert(
      pkgMakefile.includes(`$(LN) ${object}.o $(1)/usr/lib/bpf/${object}`),
      `lanspeedd-bpf must preserve the runtime path for ${object} through a relative symlink`
    );
  }
	assertMatch(pkgMakefile, /LANSPEED_NSS_ECM_BPF_ENABLED:=\$\(filter aarch64,\$\(ARCH\)\)/,
		'ECM object packaging must be gated to aarch64');
	assert(
		pkgMakefile.includes('target/bpfel-unknown-none/release/lanspeed-ebpf-ecm $(1)/usr/lib/bpf/lanspeed-ebpf-ecm.o') &&
		pkgMakefile.includes('$(LN) lanspeed-ebpf-ecm.o $(1)/usr/lib/bpf/lanspeed-ebpf-ecm'),
		'aarch64 BPF package must install the isolated ECM object and runtime symlink'
	);
  assertMatch(
    pkgMakefile,
    /if \[ "\$\(ARCH\)" = "x86_64" \]; then \\\s*\$\(INSTALL_DIR\) \$\(1\)\/etc\/uci-defaults; \\\s*\$\(INSTALL_BIN\) \.\/files\/etc\/uci-defaults\/95-lanspeed-x86-profile \$\(1\)\/etc\/uci-defaults\/95-lanspeed-x86-profile; \\\s*fi/,
    'x86 package must install its profile migration only behind the architecture gate'
  );
  assertMatch(
    pkgMakefile,
    /if \[ "\$\(CONFIG_TARGET_qualcommax\)" = "y" \]; then \\\s*\$\(INSTALL_DIR\) \$\(1\)\/etc\/uci-defaults; \\\s*\$\(INSTALL_BIN\) \.\/files\/etc\/uci-defaults\/94-lanspeed-nss-shaping \$\(1\)\/etc\/uci-defaults\/94-lanspeed-nss-shaping; \\\s*fi/,
    'only the qualcommax package may install the NSS shaping migration'
  );
  assertMatch(
    pkgMakefile,
    /if \[ "\$\(CONFIG_TARGET_qualcommax\)" = "y" \]; then \\\s*\$\(SED\) '\/procd_set_param respawn\/a\\\tprocd_set_param term_timeout 15' \$\(1\)\/etc\/init\.d\/lanspeedd; \\\s*fi/,
    'only the qualcommax package may extend procd shutdown for NSS cleanup and BPF RCU detach'
  );
  assertMatch(
    pkgMakefile,
    /if \[ "\$\(CONFIG_TARGET_qualcommax\)" != "y" \]; then \\\s*\$\(INSTALL_DIR\) \$\(1\)\/etc\/hotplug\.d\/iface; \\\s*\$\(INSTALL_BIN\) \.\/files\/etc\/hotplug\.d\/iface\/90-lanspeedd \$\(1\)\/etc\/hotplug\.d\/iface\/90-lanspeedd; \\\s*fi/,
    'qualcommax must use only procd reload triggers while x86 retains its existing hotplug entry'
  );
  assertNoMatch(initScript, /procd_set_param term_timeout/,
    'the shared init source must retain the x86 default termination timeout');
  assertMatch(x86ProfileMigration, /uci -q delete lanspeed\.main\.access_edge_mode/,
    'x86 migration must remove a retained Access Edge option');
  for (const option of [ 'nss_fifo_target_delay_ms', 'nss_fifo_min_queue_packets',
    'rate_compensation_factor', 'nss_low_rate_window_ms',
    'nss_low_rate_high_watermark_bps' ]) {
    assert(x86ProfileMigration.includes(option),
      `x86 migration must remove retained NSS-only shaping option ${option}`);
    assert(nssShapingMigration.includes(`set_default ${option}`),
      `NSS migration must initialize missing shaping option ${option}`);
  }
  assertMatch(nssShapingMigration, /if ! uci -q get "lanspeed\.main\.\$option"/,
    'NSS shaping migration must not overwrite an existing user value');
  assertMatch(x86ProfileMigration, /uci -q delete lanspeed\.main\.single_client_ports/,
    'x86 migration must remove the retired single-client-port option');
  assertMatch(x86ProfileMigration, /uci -q delete lanspeed\.main\.dedicated_port/,
    'x86 migration must remove the legacy dedicated-port option used by older releases');
  assertMatch(x86ProfileMigration, /nss_ecm_node\|nss_ecm_bpf[\s\S]*rate_collector_mode='bpf'/,
    'x86 migration must normalize retained forced NSS modes to BPF');
  assertMatch(pkgMakefile, /LANSPEED_X86_CONTROL_DEPENDS:=\+TARGET_x86:tc-full \+TARGET_x86:ip \+TARGET_x86:nftables \+TARGET_x86:conntrack \+TARGET_x86:kmod-ifb \+TARGET_x86:kmod-sched-core \+TARGET_x86:kmod-sched/,
    'client-control userspace tools and kernel queue modules must be requested only by the x86 package');
  assertMatch(pkgMakefile, /LANSPEED_NSS_CONTROL_DEPENDS:=\+TARGET_qualcommax:tc-full \+TARGET_qualcommax:ip \+TARGET_qualcommax:nftables \+TARGET_qualcommax:conntrack \+TARGET_qualcommax:kmod-ifb \+TARGET_qualcommax:kmod-sched-core \+TARGET_qualcommax:kmod-qca-nss-drv-igs \+TARGET_qualcommax:kmod-lanspeed-nss-control/,
    'NSS client control must package only its verified CPU-path kernel dependencies');
  assertMatch(pkgMakefile, /DEPENDS:=@\(aarch64\|\|x86_64\) \+libgcc \+kmod-nf-conntrack-netlink \$\(LANSPEED_X86_CONTROL_DEPENDS\) \$\(LANSPEED_NSS_CONTROL_DEPENDS\)/,
    'base daemon must retain collector dependencies and append isolated platform controls');
  assertNoMatch(pkgMakefile, /\+libubox|\+libubus|\+libuci|\+libblobmsg-json/,
    'pure Rust userspace must not retain versioned OpenWrt library dependencies');
  assertNoMatch(
    pkgMakefile,
    /DEPENDS:=\$\(RUST_ARCH_DEPENDS\)/,
    'base daemon must not advertise unverified 32-bit Rust targets'
  );
  assertMatch(pkgMakefile, /define Package\/lanspeedd-bpf[\s\S]*DEPENDS:=@!BIG_ENDIAN \+lanspeedd \+tc-full \+kmod-sched-bpf/, 'BPF package must retain the original daemon, tc, and TC-BPF dependencies');
  for (const packageName of [ 'lanspeedd', 'lanspeedd-bpf' ]) {
    const postinstMatch = new RegExp(
      `^define Package\\/${packageName}\\/postinst\\n([\\s\\S]*?)^endef$`,
      'm'
    ).exec(pkgMakefile);
    assert(postinstMatch, `${packageName} must define a post-install restart contract`);
    const postinst = postinstMatch[1];
    assertMatch(postinst, /\[ -n "\$\$\{IPKG_INSTROOT:-\}" \] && exit 0/,
      `${packageName} staged-root installation must stay inert`);
    assertMatch(postinst, /token_file=\/var\/run\/lanspeedd\.postinst-restart/,
      `${packageName} restart debounce token must use root-owned runtime state`);
    assertMatch(postinst, /sleep 2/,
      `${packageName} must defer restart until the APK transaction has settled`);
    assertMatch(postinst, /cat "\$\$\{token_file\}"[\s\S]*= "\$\$\{token\}"/,
      `${packageName} must let only the final transaction hook restart the daemon`);
    assertMatch(postinst, /\/etc\/init\.d\/lanspeedd restart/,
      `${packageName} live installation must restart the daemon`);
  }
  assertNoMatch(pkgMakefile, /\+tc-tiny/, 'BPF package must not conflict with packages that depend on tc-full');
  assertMatch(
    luciMakefile,
    /DEPENDS:=\+lanspeedd \+lanspeedd-bpf \+luci-base/,
    'LuCI package must require the daemon and BPF runtime package'
  );
  assertNoMatch(pkgMakefile, /TITLE:=Optional BPF assets/, 'BPF package must not be described as optional');
  assertNoMatch(pkgMakefile, /DEFAULT:=y if PACKAGE_luci-app-lanspeed/, 'hard LuCI dependency makes the old conditional BPF default obsolete');
  for (const resource of [
    './files/etc/init.d/lanspeedd',
    './files/etc/hotplug.d/iface/90-lanspeedd',
    './files/etc/config/lanspeed',
    './files/usr/share/lanspeed/schema.json',
    './src/collector-model.json'
  ]) {
    assert(pkgMakefile.includes(resource), `package must preserve ${resource}`);
  }
  for (const legacy of [
    'CompileBPF',
    'bpf.mk',
    'lanspeed_bpf_plugin.so',
    'lanspeed_tc.bpf.c',
    'LANSPEED_WITH_BPF',
    './src/Makefile',
    './src/*.c',
    './src/*.h',
    '+libbpf',
    '+libmnl',
    '+libjson-c',
    '+tc-bpf'
  ]) {
    assert(!pkgMakefile.includes(legacy), `Rust packaging must not retain ${legacy}`);
  }
  assertNoMatch(pkgMakefile, /\$\(error\s+[^)]*lanspeedd-bpf/s, 'BPF package metadata must remain expandable');

  luciResources.forEach((name) => {
    assert(
      luciMakefile.includes(`htdocs/luci-static/resources/lanspeed/${name}`),
      `luci-app-lanspeed/Makefile must install resources/lanspeed/${name}`
    );
  });

  const resourceInstall = /\t\$\(INSTALL_DIR\) \$\(1\)\/www\/luci-static\/resources\/lanspeed\n\t\$\(INSTALL_DATA\) \\\n([\s\S]*?)\n\t\t\$\(1\)\/www\/luci-static\/resources\/lanspeed\/\n/.exec(luciMakefile);
  assert(resourceInstall, 'LuCI package must keep an explicit INSTALL_DATA block for resources/lanspeed');
  assertNoMatch(resourceInstall[1], /[?*\[]/,
    'LuCI resources/lanspeed INSTALL_DATA block must not use wildcard or glob entries');
  const installedResources = [...resourceInstall[1].matchAll(
    /\.\/htdocs\/luci-static\/resources\/lanspeed\/([^\s\\/]+\.js)/g
  )].map((match) => match[1]);
  assertExactNames(installedResources, luciResources,
    'LuCI package resources/lanspeed install list must exactly match active semantic resources');
  luciResources.forEach((name) => {
    assert(countLiteral(resourceInstall[1],
      `./htdocs/luci-static/resources/lanspeed/${name}`) === 1,
    `LuCI package must install resources/lanspeed/${name} exactly once`);
  });

  const viewInstall = /\t\$\(INSTALL_DIR\) \$\(1\)\/www\/luci-static\/resources\/view\/lanspeed\n\t\$\(INSTALL_DATA\) \\\n([\s\S]*?)\n\t\t\$\(1\)\/www\/luci-static\/resources\/view\/lanspeed\/\n/.exec(luciMakefile);
  assert(viewInstall, 'LuCI package must keep an explicit INSTALL_DATA block for view/lanspeed');
  assertNoMatch(viewInstall[1], /[?*\[]/,
    'LuCI view/lanspeed INSTALL_DATA block must not use wildcard or glob entries');
  const installedViews = [...viewInstall[1].matchAll(
    /\.\/htdocs\/luci-static\/resources\/view\/lanspeed\/([^\s\\/]+\.js)/g
  )].map((match) => match[1]);
  assertExactNames(installedViews, luciViews,
    'LuCI package view/lanspeed install list must be exactly config.js, diagnostics.js and overview.js');

  assertExactNames(
    fs.readdirSync(luciResourceRoot, { withFileTypes: true })
      .filter((entry) => entry.isFile()).map((entry) => entry.name),
    [ ...luciResources, 'version.js' ],
    'resources/lanspeed source directory must contain only active semantic modules'
  );
  assertExactNames(
    fs.readdirSync(luciViewRoot, { withFileTypes: true })
      .filter((entry) => entry.isFile()).map((entry) => entry.name),
    luciViews,
    'view/lanspeed source directory must contain only config.js, diagnostics.js and overview.js'
  );

  assertNoMatch(luciMakefile, versionedCachePattern,
    'LuCI Makefile must not contain numbered cache resource names');
  assertNoMatch(luciMenuSource, versionedCachePattern,
    'LuCI menu must not contain numbered cache view names');
  assertNoVersionedCacheFiles(luciResourceRoot, 'resources/lanspeed');
  assertNoVersionedCacheFiles(luciViewRoot, 'view/lanspeed');

  const luciMenu = JSON.parse(luciMenuSource);
  const menuViewPaths = Object.values(luciMenu)
    .filter((entry) => entry.action && entry.action.type === 'view')
    .map((entry) => entry.action.path);
  assertExactNames(menuViewPaths, [ 'lanspeed/config', 'lanspeed/diagnostics', 'lanspeed/overview' ],
    'LuCI menu view actions must use config, diagnostics and overview views');
  assert(luciMenu['admin/status/lanspeed/overview'].action.path === 'lanspeed/overview',
    'LuCI overview menu must use the semantic overview view');
  assert(luciMenu['admin/status/lanspeed/diagnostics'].action.path === 'lanspeed/diagnostics',
    'LuCI diagnostics menu must use the dedicated diagnostics view');
  assert(luciMenu['admin/status/lanspeed/config'].action.path === 'lanspeed/config',
    'LuCI config menu must use the semantic config view');

	const installedClientDetailResources = installedResources.filter((name) =>
		/^(?:clientConnections|dhcpHostnames|clientDetail|geoLocation)/.test(name));
  assertExactNames(installedClientDetailResources, clientDetailResources,
    'LuCI package must install exactly the active client detail resources');

  const documentedMethods = [
    'realtime',
    'status',
    'clients',
    'overview',
    'health',
    'diagnostics',
    'reload',
    'interfaces',
    'sysdevices',
    'client_connections'
  ];
  documentedMethods.forEach((method) => {
    assert(
      readme.includes(`ubus call lanspeed ${method}`),
      `README must document the lanspeed ${method} ubus method`
    );
  });
  assert(
    readme.includes("ubus call lanspeed client_connections \\\n  '{\"identity_key\":\"02:00:00:00:00:42@br-lan\"}'"),
    'README must provide the copyable client_connections identity_key command'
  );
  assert(
    hasExactClientConnectionsSemantics(readme),
    'README client_connections paragraph must state: TCP only ESTABLISHED + ASSURED, UDP only ASSURED'
  );
  assert(
    /(?:详情页|连接详情)/.test(readme),
    'README must explain the client detail page entry'
  );

  console.log('validate-lanspeed-packaging: PASS');
} catch (error) {
  console.error('validate-lanspeed-packaging: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
