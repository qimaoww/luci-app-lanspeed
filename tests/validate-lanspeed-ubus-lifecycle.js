#!/usr/bin/env node

const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const initScriptPath = path.join(root, 'net/lanspeedd/files/etc/init.d/lanspeedd');
const processBarrierPath = path.join(root,
  'net/lanspeedd/files/usr/libexec/lanspeed/process-barrier');
const daemonLauncherPath = path.join(root,
  'net/lanspeedd/files/usr/libexec/lanspeed/start-daemon');
const initScript = fs.readFileSync(initScriptPath, 'utf8');
const processBarrier = fs.readFileSync(processBarrierPath, 'utf8');
const daemonLauncher = fs.readFileSync(daemonLauncherPath, 'utf8');
const hotplugScript = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/hotplug.d/iface/90-lanspeedd'), 'utf8');
const production = fs.readFileSync(
  path.join(root, 'net/lanspeedd/rust/crates/lanspeedd/src/production.rs'),
  'utf8'
);
const reloadWorker = fs.readFileSync(
  path.join(root, 'net/lanspeedd/rust/crates/lanspeedd/src/production/reload_worker.rs'),
  'utf8'
);
const fixture = JSON.parse(fs.readFileSync(path.join(root, 'tests/fixtures/lanspeed-lifecycle.json'), 'utf8'));

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertThrows(fn, message) {
  let threw = false;
  try {
    fn();
  } catch (_error) {
    threw = true;
  }
  assert(threw, message);
}

function runInitBarrierProbe(source) {
  const result = childProcess.spawnSync('sh', [
    '-s', initScriptPath, processBarrierPath, daemonLauncherPath
  ], {
    input: source,
    encoding: 'utf8'
  });
  assert(result.status === 0,
    `init restart barrier probe failed: ${result.stderr || result.stdout}`);
  return result.stdout.trim();
}

function shellFunctionBody(source, name) {
  const match = source.match(new RegExp(`^${name}\\(\\)[ \\t]+\\{[ \\t]*\\n([\\s\\S]*?)^\\}`, 'm'));
  assert(match, `${name} must exist`);
  return match[1];
}

function isOwnedFilter(filter, identity) {
  return filter.owner === identity.owner
    && filter.pref === identity.pref
    && filter.handle === identity.handle
    && filter.object === identity.object;
}

function filterIdentity(filter) {
  return [
    filter.interface,
    filter.direction,
    filter.pref,
    filter.handle,
    filter.owner,
    filter.object,
    filter.source
  ].join('\u0000');
}

function identityMultiset(filters) {
  return filters.map(filterIdentity).sort();
}

function multisetsEqual(left, right) {
  return left.length === right.length && left.every((identity, index) => identity === right[index]);
}

const reloadContract = /^(?:\s*load_platform_control_modules\s*\n)?\s*if ubus call lanspeed reload >\/dev\/null 2>&1; then[ \t]*\n[ \t]*return 0[ \t]*\n[ \t]*fi[\s\S]*if \[ -d \/sys\/module\/lanspeed_nss_control \]; then[\s\S]*return 1[ \t]*\n[ \t]*fi[ \t]*\n[ \t]*restart[ \t]*\s*$/;
const destructiveTcCommand = /cleanup_|(?:\btc|\$TC)\s+filter\s+del\b|\bqdisc\s+del\b/i;

function validateReloadService(source) {
  const body = shellFunctionBody(source, 'reload_service');
  return reloadContract.test(body) && !destructiveTcCommand.test(body);
}

const reloadWithIgnoredFailure = `reload_service() {
\tif ubus call lanspeed reload >/dev/null 2>&1 || true; then
\t\treturn 0
\tfi
\trestart
}`;
const reloadWithPipeline = `reload_service() {
\tif ubus call lanspeed reload >/dev/null 2>&1 | logger; then
\t\treturn 0
\tfi
\trestart
}`;

assert(!validateReloadService(reloadWithIgnoredFailure), 'reload validation must reject an ignored ubus failure');
assert(!validateReloadService(reloadWithPipeline), 'reload validation must reject a piped ubus command');
assertThrows(
  () => shellFunctionBody(`not_reload_service() {
\tif ubus call lanspeed reload >/dev/null 2>&1; then
\t\treturn 0
\tfi
\trestart
}`, 'reload_service'),
  'shell function extraction must match the complete function name'
);

assert(initScript.includes('USE_PROCD=1'), 'lanspeedd must remain supervised by procd');
assert(initScript.includes('LANSPEED_STOP_WAIT_LOOPS="20"') &&
  initScript.includes('LANSPEED_STOP_WAIT_INTERVAL="1"'),
  'the bounded exit barrier must use the integer sleep interval supported by OpenWrt BusyBox');
assert(initScript.includes('procd_add_reload_trigger "lanspeed" "network"'), 'procd must trigger in-process reload for config/network changes');
assert(validateReloadService(initScript), 'reload must preserve a failed NSS transaction and retain the historical x86 restart fallback');
assert(initScript.includes('transactional NSS reload failed; preserving current dataplane'),
  'NSS reload failure must be observable without restarting the proven dataplane');
assert(/fn before_reply\(&mut self, method: ubus::Method\)[\s\S]*if method == ubus::Method::Reload[\s\S]*self\.reload_bounded\(\)/.test(production) &&
  production.includes('recv_timeout(remaining)') &&
  production.includes('self.wait_for_runtime_ownership(deadline)') &&
  production.includes('while self.runtime_collection_pending || self.control_pending_generation.is_some()') &&
  production.includes('self.reload_requested = true') &&
  reloadWorker.includes('spawn_runtime_worker') &&
  reloadWorker.includes('reload_transaction(task.runtime)') &&
  !production.includes('refresh_clients_control_state') &&
  !production.includes('fn reload_inner'),
  'ordinary RPCs must remain cache-only while bounded reload work stays on its runtime worker');
const stopBody = shellFunctionBody(initScript, 'stop_service');
const stoppedBody = shellFunctionBody(initScript, 'service_stopped');
const restartBody = shellFunctionBody(initScript, 'restart');
assert(stopBody.includes('"$LANSPEED_PROCESS_BARRIER" snapshot "$PROG"'),
  'stop_service must snapshot the exact supervised process generations before procd sends SIGTERM');
assert(stoppedBody.includes('"$LANSPEED_PROCESS_BARRIER" wait "$LANSPEED_STOP_IDENTITIES"') &&
  stoppedBody.indexOf('"$LANSPEED_PROCESS_BARRIER" wait') < stoppedBody.indexOf('cleanup_lanspeed_tc_filters'),
  'service_stopped must wait for the previous process generation before reclaiming owned TC filters');
assert(restartBody.includes('if ! stop "$@"') &&
  restartBody.indexOf('stop "$@"') < restartBody.indexOf('start "$@"'),
  'restart must not launch a replacement when the previous process exit barrier fails');
const delayedExitProbe = runInitBarrierProbe(`
. "$1"
LANSPEED_PROCESS_BARRIER="$2"
LANSPEED_STOP_WAIT_LOOPS=50
LANSPEED_STOP_WAIT_INTERVAL=0.01
sleep 5 & old_pid=$!
LANSPEED_STOP_IDENTITIES=$(awk '{ print $1 ":" $22 }' "/proc/$old_pid/stat")
cleanup_lanspeed_tc_filters() {
  [ ! -r "/proc/$old_pid/stat" ] || return 1
  printf '%s\\n' cleanup_after_exit
}
( sleep 0.1; kill "$old_pid" 2>/dev/null || true ) &
service_stopped
wait "$old_pid" 2>/dev/null || true
`);
assert(delayedExitProbe === 'cleanup_after_exit',
  'service_stopped must defer TC cleanup until the captured process generation exits');
const timeoutProbe = runInitBarrierProbe(`
. "$1"
LANSPEED_PROCESS_BARRIER="$2"
LANSPEED_STOP_WAIT_LOOPS=2
LANSPEED_STOP_WAIT_INTERVAL=0.01
sleep 5 & old_pid=$!
LANSPEED_STOP_IDENTITIES=$(awk '{ print $1 ":" $22 }' "/proc/$old_pid/stat")
cleanup_lanspeed_tc_filters() { printf '%s\\n' unexpected_cleanup; }
if service_stopped; then
  printf '%s\\n' unexpected_success
else
  printf '%s\\n' exit_barrier_failed
fi
kill "$old_pid" 2>/dev/null || true
wait "$old_pid" 2>/dev/null || true
`);
assert(timeoutProbe === 'exit_barrier_failed',
  'an exit barrier timeout must fail without cleaning TC under a live process');
const blockedRestartProbe = runInitBarrierProbe(`
. "$1"
stop() { return 1; }
start() { printf '%s\\n' unexpected_start; }
if restart; then
  printf '%s\\n' unexpected_success
else
  printf '%s\\n' restart_blocked
fi
`);
assert(blockedRestartProbe === 'restart_blocked',
  'restart must propagate a failed stop barrier without starting a replacement');
const startBody = shellFunctionBody(initScript, 'start_service');
assert(startBody.includes('"$LANSPEED_PROCESS_BARRIER" snapshot "$PROG"') &&
  startBody.indexOf('snapshot "$PROG"') < startBody.indexOf('procd_open_instance'),
  'every direct procd set must snapshot the previous process generations before replacement');
assert(startBody.includes('procd_set_param command "$LANSPEED_DAEMON_LAUNCHER" "$PROG"') &&
  startBody.includes('"LANSPEED_PREVIOUS_IDENTITIES=$previous_identities"'),
  'procd must launch the daemon through the process-generation barrier');
assert(/^\s*load_platform_control_modules\s*$/m.test(startBody) &&
  /^\s*load_platform_control_modules\s*$/m.test(shellFunctionBody(initScript, 'reload_service')),
  'startup and reload must invoke only the installed platform module loader');
assert(startBody.includes('procd_set_param term_timeout 15'),
  'procd must allow graceful TC-BPF and NSS dataplane shutdown on every platform');
assert(processBarrier.includes('print $1 ":" $22') &&
  processBarrier.includes('pidof "$name"') &&
  processBarrier.includes('readlink "/proc/$pid/exe"') &&
  processBarrier.includes('"$executable (deleted)"') &&
  processBarrier.includes('[ "$confirmed" = "$identity" ]') &&
  processBarrier.includes('[ "$current" = "$identity" ]'),
  'the process barrier must stabilize snapshots around executable checks and distinguish later PID reuse');
assert(processBarrier.includes('$3 != "Z"'),
  'the process barrier must treat a zombie as exited after kernel resources are released');
assert(processBarrier.includes('sleep "$interval"') && processBarrier.includes('return 1'),
  'the process barrier must wait with a bounded failure path');
assert(processBarrier.indexOf('[ "$remaining" -gt 0 ] || break') <
  processBarrier.indexOf('sleep "$interval"'),
  'the process barrier must perform a final liveness check after the last bounded sleep');
assert(daemonLauncher.indexOf('"$barrier" wait') <
  daemonLauncher.indexOf('"$cleanup_command" cleanup_lanspeed_tc_filters') &&
  daemonLauncher.indexOf('"$cleanup_command" cleanup_lanspeed_tc_filters') <
  daemonLauncher.indexOf('exec "$daemon" "$@"'),
  'the launcher must wait, reclaim stale owned TC slots, then exec the daemon in order');
const directStartProbe = runInitBarrierProbe(`
sleep 5 & old_pid=$!
identity=$(awk '{ print $1 ":" $22 }' "/proc/$old_pid/stat")
( sleep 0.1; kill "$old_pid" 2>/dev/null || true ) &
LANSPEED_PROCESS_BARRIER="$2" \\
LANSPEED_CLEANUP_COMMAND=/bin/true \\
LANSPEED_PREVIOUS_IDENTITIES="$identity" \\
LANSPEED_STOP_WAIT_LOOPS=50 \\
LANSPEED_STOP_WAIT_INTERVAL=0.01 \\
  "$3" /bin/true
[ ! -r "/proc/$old_pid/stat" ]
wait "$old_pid" 2>/dev/null || true
printf '%s\\n' direct_start_after_exit
`);
assert(directStartProbe === 'direct_start_after_exit',
  'a direct procd set must not exec the replacement before the previous generation exits');
const tcDeleteBody = shellFunctionBody(initScript, 'lanspeed_tc_delete_owned');
assert(tcDeleteBody.includes('2>/dev/null') &&
  tcDeleteBody.includes('lanspeed_tc_filter_present') &&
  tcDeleteBody.indexOf('lanspeed_tc_filter_present') < tcDeleteBody.indexOf('daemon.warn'),
  'owned tc cleanup must suppress a raced delete error, recheck the exact filter, and warn only if it remains');
assert(hotplugScript.includes('/etc/init.d/lanspeedd reload'), 'hotplug must request reload rather than restart');
assert(!/restart/i.test(hotplugScript), 'hotplug must not restart the daemon');

assert(Array.isArray(fixture.before_filters), 'lifecycle fixture must describe filters before reload');
assert(Array.isArray(fixture.after_filters), 'lifecycle fixture must describe filters after reload');
assert(fixture.after_qdisc && typeof fixture.after_qdisc === 'object', 'lifecycle fixture must describe qdisc after reload');

const ownedBefore = fixture.before_filters.filter((filter) => isOwnedFilter(filter, fixture.owned_filter_identity));
const ownedAfter = fixture.after_filters.filter((filter) => isOwnedFilter(filter, fixture.owned_filter_identity));
const foreignBefore = fixture.before_filters.filter((filter) => !isOwnedFilter(filter, fixture.owned_filter_identity));
const foreignAfter = fixture.after_filters.filter((filter) => !isOwnedFilter(filter, fixture.owned_filter_identity));
const ownedFiltersPreserved = multisetsEqual(identityMultiset(ownedBefore), identityMultiset(ownedAfter));
const foreignFiltersPreserved = multisetsEqual(identityMultiset(foreignBefore), identityMultiset(foreignAfter));
const clsactDeleted = fixture.qdisc.kind === 'clsact'
  && fixture.qdisc.exists === true
  && !(fixture.after_qdisc.kind === 'clsact' && fixture.after_qdisc.exists === true);
const ownedAttachmentCount = new Set(
  ownedAfter.map((filter) => `${filter.interface}\u0000${filter.direction}`)
).size;
const duplicateOwnedFilters = ownedAttachmentCount !== ownedAfter.length;

assert(fixture.expected.pid_unchanged_on_healthy_reload === true, 'healthy in-process reload must preserve the daemon pid');
assert(fixture.expected.cleanup_after_daemon_exit === true, 'stop lifecycle must clean owned filters only after daemon exit');
assert(foreignBefore.some((filter) => filter.owner === 'foreign-lanspeed-label'), 'foreign-lanspeed-label must not be classified as an owned filter');
assert(fixture.expected.foreign_filters_preserved === true, 'reload lifecycle must preserve foreign filters');
assert(foreignFiltersPreserved === fixture.expected.foreign_filters_preserved, 'after reload must retain every foreign filter identity');
assert(fixture.expected.delete_clsact === false, 'reload lifecycle must preserve clsact');
assert(clsactDeleted === fixture.expected.delete_clsact, 'after reload qdisc state must match the clsact deletion contract');
assert(ownedFiltersPreserved, 'reload must preserve the complete owned filter attachment multiset');
assert(ownedAfter.length === fixture.expected.lanspeed_filter_count_after_restart, 'after reload owned filter count must match the lifecycle contract');
assert(fixture.expected.duplicate_lanspeed_filters === false, 'reload lifecycle must not duplicate owned filters');
assert(duplicateOwnedFilters === fixture.expected.duplicate_lanspeed_filters, 'after reload owned filter identities must not be duplicated');
assert(Array.isArray(fixture.network_reload.states), 'network reload fixture must describe observable states');
assert(fixture.network_reload.states.every((state) => state.daemon_alive === true), 'in-process reload must keep the daemon alive');

console.log('validate-lanspeed-ubus-lifecycle: PASS');
