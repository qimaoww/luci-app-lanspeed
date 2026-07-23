#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const initScript = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/init.d/lanspeedd'), 'utf8');
const hotplugScript = fs.readFileSync(path.join(root, 'net/lanspeedd/files/etc/hotplug.d/iface/90-lanspeedd'), 'utf8');
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

const reloadContract = /^\s*if ubus call lanspeed reload >\/dev\/null 2>&1; then[ \t]*\n[ \t]*return 0[ \t]*\n[ \t]*fi[ \t]*\n[ \t]*restart[ \t]*\s*$/;
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
assert(initScript.includes('procd_add_reload_trigger "lanspeed" "network"'), 'procd must trigger in-process reload for config/network changes');
assert(validateReloadService(initScript), 'reload must immediately return after a successful ubus reload and restart only on failure');
assert(!/^stop_service\(\)/m.test(initScript), 'owned tc cleanup must not race a daemon that has not stopped yet');
assert(/^\s*cleanup_lanspeed_tc_filters\s*$/m.test(shellFunctionBody(initScript, 'service_stopped')),
  'service_stopped must remove owned tc filters after procd has stopped the daemon');
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
