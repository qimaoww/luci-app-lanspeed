#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root,
  'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/clientControl.js'), 'utf8');
const ebpfMain = fs.readFileSync(path.join(root,
  'net/lanspeedd/rust/crates/lanspeed-ebpf/src/main.rs'), 'utf8');
const x86ControlDir = path.join(root,
  'net/lanspeedd/rust/crates/lanspeedd/src/platform/x86/control');
const x86ControlModules = [ 'mod.rs', 'classifier.rs', 'dae.rs', 'firewall.rs', 'ifb.rs', 'shaper.rs', 'system.rs' ];
const x86ControlByModule = Object.fromEntries(x86ControlModules.map((name) => [
  name, fs.readFileSync(path.join(x86ControlDir, name), 'utf8')
]));
const x86Control = Object.values(x86ControlByModule).join('\n');
const control = fs.readFileSync(path.join(root,
  'net/lanspeedd/rust/crates/lanspeedd/src/control.rs'), 'utf8');
const production = fs.readFileSync(path.join(root,
  'net/lanspeedd/rust/crates/lanspeedd/src/production.rs'), 'utf8');
const nssModule = fs.readFileSync(path.join(root,
  'net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/mod.rs'), 'utf8');
const statusOverview = fs.readFileSync(path.join(root,
  'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/statusOverview.js'), 'utf8');
const statusRefresh = fs.readFileSync(path.join(root,
  'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/statusRefresh.js'), 'utf8');

function translate(value) {
  const text = String(value);
  return {
    toString: () => text,
    format: (...args) => {
      let index = 0;
      return text.replace(/%[sd]/g, () => String(args[index++]));
    }
  };
}

function element(tag, attrs, children) {
  const node = {
    tag, attrs: Object.assign({}, attrs || {}), children: [], listeners: {},
    addEventListener(type, callback) { this.listeners[type] = callback; },
    focus() { this.focused = true; }
  };
  const append = (child) => {
    if (Array.isArray(child)) child.forEach(append);
    else if (child !== null && child !== undefined && child !== '') node.children.push(child);
  };
  append(children);
  return node;
}

function textOf(value) {
  if (value === null || value === undefined) return '';
  if (Array.isArray(value)) return value.map(textOf).join('');
  if (typeof value !== 'object') return String(value);
  if (!Array.isArray(value.children) && typeof value.toString === 'function') return value.toString();
  return (value.children || []).map(textOf).join('');
}

async function main() {
  assert(!ebpfMain.includes('lanspeed_control_ingress') && !ebpfMain.includes('x86/control.rs'),
    'x86 client control must not add a BPF program to the existing rate object');
  assert(!fs.existsSync(path.join(root,
    'net/lanspeedd/rust/crates/lanspeedd/src/platform/x86/control.rs')) &&
    fs.readdirSync(x86ControlDir).filter((name) => name.endsWith('.rs')).sort().join(',') ===
      x86ControlModules.slice().sort().join(','),
    'x86 client control must be a fixed modular implementation rather than a monolithic source file');
  for (const name of [ 'classifier', 'dae', 'firewall', 'ifb', 'shaper', 'system' ])
    assert(x86ControlByModule['mod.rs'].includes(`mod ${name};`), `control/mod.rs must declare ${name}`);
  assert(x86ControlByModule['ifb.rs'].includes('pub(crate) const DEVICE: &str = "ifb-lanspeed"') &&
    x86ControlByModule['ifb.rs'].includes('lanspeedd:x86-client-control:v1') &&
    x86ControlByModule['ifb.rs'].includes('ifb_owned_by_external_service'),
    'the dedicated IFB must have a stable name and explicit ownership marker');
  assert(x86ControlByModule['classifier.rs'].includes('"mirred"') &&
    x86ControlByModule['classifier.rs'].includes('"redirect"') &&
    x86ControlByModule['classifier.rs'].includes('ifb::DEVICE') &&
    x86ControlByModule['classifier.rs'].includes('hook.local_field') === false &&
    !x86ControlByModule['classifier.rs'].includes('pub(crate) fn install_egress') &&
    x86ControlByModule['classifier.rs'].includes('cleanup_legacy_dae_egress') &&
    x86ControlByModule['classifier.rs'].includes('verify_chain(hook, lan_device, rules)?') &&
    x86ControlByModule['classifier.rs'].includes('activate_on(hook, lan_device)'),
    'direct upload classification must redirect to IFB only after the inactive chain verifies, while legacy DAE redirects remain cleanup-only');
  assert(x86ControlByModule['classifier.rs'].includes('const JUMP_PREF: u32 = 0xd020') &&
    x86ControlByModule['firewall.rs'].includes('const JUMP_PREF: u32 = 0xd01f') &&
    ebpfMain.includes('return account_frame(ctx, DIR_RX, TC_ACT_UNSPEC)') &&
    x86ControlByModule['classifier.rs'].includes('rate-monitor BPF owns normal priority 0xc000'),
    'x86 accounting must continue and run before block/redirect control filters');
  assert(x86ControlByModule['classifier.rs'].includes('"dst"') &&
    x86ControlByModule['classifier.rs'].includes('&["action", "pass"]') &&
    x86ControlByModule['classifier.rs'].includes('"src"') &&
    x86ControlByModule['classifier.rs'].includes('"ether"') &&
    x86ControlByModule['shaper.rs'].includes('Direction::Download => "dst"') &&
    x86ControlByModule['shaper.rs'].includes('"ether"') &&
    !x86ControlByModule['shaper.rs'].includes('"cls_flower"'),
    'LAN/local destinations must pass before MAC-based dual-stack control redirects to IFB');
  assert(x86ControlByModule['shaper.rs'].includes('Self::Upload => UPLOAD_HANDLE') &&
    x86ControlByModule['shaper.rs'].includes('Self::Download => DOWNLOAD_HANDLE') &&
    x86ControlByModule['shaper.rs'].includes('"htb"') &&
    x86ControlByModule['shaper.rs'].includes('"fq"') &&
    !x86ControlByModule['shaper.rs'].includes('"bfifo"') &&
    !x86ControlByModule['shaper.rs'].includes('legacy_upload_tree') &&
    !x86Control.includes('lanspeed_control_io') &&
    !x86ControlByModule['shaper.rs'].includes('wan_devices'),
    'x86 must use HTB/FQ for direct upload and independent LAN download trees');
  assert(x86ControlByModule['shaper.rs'].includes('DAE_UPLOAD_COMPENSATION_NUMERATOR: u64 = 110') &&
    x86ControlByModule['shaper.rs'].includes('Self::Upload if rule.upload_before_proxy') &&
    x86ControlByModule['shaper.rs'].includes('Self::Download => rule.download_bps'),
    'DAE pre-proxy upload must compensate wire overhead without changing direct upload or download');
  assert(x86ControlByModule['dae.rs'].includes('/sys/class/net/{bridge}/brif') &&
    x86ControlByModule['dae.rs'].includes('resolve_upload_devices(bridges, bridge_members)') &&
    x86ControlByModule['dae.rs'].includes('return BTreeSet::new()') &&
    !x86ControlByModule['shaper.rs'].includes('stage_native_upload') &&
    !x86ControlByModule['dae.rs'].includes('mirred') &&
    !x86ControlByModule['dae.rs'].includes('ifb::DEVICE'),
    'DAE upload must resolve every bridge slave and must never queue or redirect on dae0');
  assert(/Direction::Upload => \{[\s\S]*?ensure_owned_virtual_root\(device, handle\)\?;[\s\S]*?cleanup_owned_root\(device, handle\)\?;[\s\S]*?"replace"/
    .test(x86ControlByModule['shaper.rs']),
    'updating an active upload rate must remove the owned HTB tree before replace can retain stale classes');
  assert(x86ControlByModule['mod.rs'].indexOf('shaper::stage_upload(&upload)?') <
    x86ControlByModule['mod.rs'].indexOf('classifier::install(device, &plan.local_prefixes, rules)?') &&
    x86ControlByModule['mod.rs'].indexOf('shaper::stage_download(&plan.lan_device, &download)?') <
      x86ControlByModule['mod.rs'].indexOf('firewall::install(plan)?') &&
    x86ControlByModule['mod.rs'].indexOf('firewall::install(plan)?') <
      x86ControlByModule['mod.rs'].indexOf('shaper::activate_download(&plan.lan_device') &&
    x86ControlByModule['mod.rs'].includes('fn rollback('),
    'queue trees must stage before block/download/upload activation with rollback');
  assert(control.includes('pub interface: Option<String>') &&
    control.includes('valid_control_interface(&client.interface)') &&
    control.includes('control_devices.extend(rules.iter().map(|rule| rule.interface.clone()))') &&
    x86ControlByModule['mod.rs'].includes('fn upload_rules_by_device') &&
    x86ControlByModule['mod.rs'].includes('for (device, rules) in &upload_by_device'),
    'upload shaping must bind each rule to the client interface observed by the rate collector');
  assert(production.includes('observe_preempted_upload_devices(dae_preempted_devices)') &&
    production.includes('observe_dae_upload_devices(dae_upload_devices)') &&
    x86ControlByModule['mod.rs'].includes('rule.upload_before_proxy') &&
    x86ControlByModule['mod.rs'].includes('for device in &plan.dae_upload_devices') &&
    x86ControlByModule['mod.rs'].includes('cleanup_legacy_dae_upload_objects') &&
    x86ControlByModule['dae.rs'].includes('classifier::legacy_dae_egress_owned(&device)?') &&
    !x86ControlByModule['mod.rs'].includes('const LEGACY_DEVICE') &&
    !x86ControlByModule['mod.rs'].includes('stage_native_upload') &&
    !x86ControlByModule['mod.rs'].includes('classifier::install_egress') &&
    !x86ControlByModule['mod.rs'].includes('plan.upload_preempted && !upload.is_empty()') &&
    control.includes('dae_upload_preempts_control') &&
    !source.includes('dae_upload_preempts_control'),
    'DAE upload must shape once on bridge slaves before both direct and proxy branches without a fallback UI label');
  assert(x86ControlByModule['firewall.rs'].includes('Hook::Ingress') &&
    x86ControlByModule['firewall.rs'].includes('Hook::Egress') &&
    x86ControlByModule['firewall.rs'].includes('"ether"') &&
    x86ControlByModule['firewall.rs'].includes('&rule.mac.to_string()') &&
    x86ControlByModule['firewall.rs'].includes('clear_conntrack_address') &&
    x86ControlByModule['firewall.rs'].includes('"drop"') &&
    x86ControlByModule['firewall.rs'].includes('NFT_OWNER_COMMENT') &&
    x86ControlByModule['firewall.rs'].includes('block_nft_owned_by_external_service') &&
    !x86ControlByModule['firewall.rs'].includes('fn delete_nft_tables'),
    'block rules must cover proxy ingress and client egress while retaining targeted conntrack cleanup');
  assert(x86ControlByModule['system.rs'].includes('Command::new(program)') &&
    !x86ControlByModule['system.rs'].includes('sh -c') &&
    !x86Control.includes('meta mark set') && !x86Control.includes('UPLOAD_MARK') &&
    !x86Control.includes('nsshtb') && !x86Control.includes('qos_tag'),
    'the modular x86 path must use argv-safe commands and contain no old WAN marks or NSS controls');
  assert((x86ControlByModule['classifier.rs'].match(/if !output\.status\.success\(\)/g) || []).length >= 3 &&
    x86ControlByModule['classifier.rs'].includes('return Err("ingress_filter_inspection_failed".into())') &&
    (x86ControlByModule['firewall.rs'].match(/if !output\.status\.success\(\)/g) || []).length >= 2 &&
    x86ControlByModule['firewall.rs'].includes('return Err("block_filter_inspection_failed".into())'),
    'failed TC ownership queries must stop apply and cleanup instead of being treated as absent objects');
  assert(control.includes('verification_failures') &&
    x86ControlByModule['mod.rs'].includes('upload_class_bytes') &&
    x86ControlByModule['mod.rs'].includes('download_class_bytes'),
    'verification must use each direction\'s owned queue counters');
  assert(control.includes('CONTROL_DHCP_LEASES_PATH') &&
    control.includes('fn lease_addresses_from(') &&
    control.includes('merge_control_lease_addresses(&mut next'),
    'persistent controls must recover safe address-dependent rules from unexpired DHCP leases');
  assert(!production.includes('x86_control_bpf_unavailable') &&
    !production.includes('replace_control_maps'),
    'x86 client control availability must be independent of the rate-monitor BPF runtime');
  assert(!fs.existsSync(path.join(root,
    'net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/control.rs')) &&
    !nssModule.includes('mod control') &&
    production.includes('#[cfg(not(feature = "nss-platform"))]\n    control: ControlManager') &&
    statusOverview.includes('showClientControl: !fmt.nssPlatform(normalized.status)') &&
    statusRefresh.includes("nssProfile ? [] : [ clientControl.cell(viewState, c) ]"),
    'NSS builds and status rows must not expose the x86-only client-control implementation');
  const hotRefresh = production.match(/fn refresh_connections[\s\S]*?\n    fn collect\(/)?.[0] || '';
  assert(hotRefresh.includes('self.decorate_controls(&mut snapshot.clients);') &&
    !hotRefresh.includes('self.refresh_controls(&mut snapshot.clients);'),
    'hot clients overlay must decorate rows without mutating the authoritative control inventory');
  const calls = [];
  const modals = [];
  const context = vm.createContext({
    console,
    E: element,
    _: translate,
    document: { querySelector: () => null },
    window: { setTimeout: (callback) => callback() }
  });
  const module = vm.compileFunction(source,
    [ 'baseclass', 'ui', 'lsRpc', 'E', '_', 'document', 'window' ],
    { filename: 'resources/lanspeed/clientControl.js', parsingContext: context })(
      { extend: (value) => value },
      {
        hideModal() {},
        showModal(title, body) { modals.push({ title, body }); },
        addNotification() {}
      },
      {
        clientControlSet(identity, upload, download, disabled) {
          calls.push([identity, upload, download, disabled]);
          return Promise.resolve({ ok: true });
        }
      },
      element,
      translate,
      context.document,
      context.window
    );

  assert.strictEqual(module.mbpsToBps('4000', 4_000_000_000), 4_000_000_000);
  assert(String(module.reasonText('ifb_module_unavailable')).includes('IFB'));
  assert(!String(module.reasonText('dae_upload_preempts_control')).includes('DAE 当前'));
  assert(String(module.reasonText('identity_interface_unavailable')).includes('LAN'));
  assert.throws(() => module.mbpsToBps('4000.1', 4_000_000_000));
  assert.throws(() => module.mbpsToBps('0.001', 4_000_000_000));
  assert.strictEqual(module.mbpsToBps('', 4_000_000_000), 0);

  module.openLimit({}, {
    identity_key: '02:00:00:00:00:01@lan',
    hostname: 'client-demo',
    ips: [ '2001:db8::1', '192.0.2.44' ],
    mac: '02:00:00:00:00:01',
    control: {
      upload_bps: 0,
      download_bps: 100_000_000,
      internet_disabled: false,
      max_rate_bps: 4_000_000_000
    }
  });
  const modalText = textOf(modals[0].body);
  assert(textOf(modals[0].title).includes('客户端限速'));
  assert(modalText.includes('当前客户端') && modalText.includes('client-demo') &&
    modalText.includes('192.0.2.44') && modalText.includes('02:00:00:00:00:01'),
    'limit modal must identify the selected client by name, preferred IP, and MAC');
  assert(modalText.includes('上传 Mbps') && modalText.includes('下载 Mbps'));
  assert(!source.includes('Mbit' + '/s'), 'client control UI must consistently use Mbps');

  let reloads = 0;
  const viewState = {
    refreshLive() {},
    reload() { reloads += 1; return Promise.resolve(); }
  };
  const client = {
    identity_key: '02:00:00:00:00:01@lan',
    control: {
      configured: false,
      upload_bps: 0,
      download_bps: 0,
      internet_disabled: false,
      shaping_supported: true,
      blocking_supported: true,
      max_rate_bps: 4_000_000_000,
      state: 'inactive',
      queue_overflow: false
    }
  };
  const cell = module.cell(viewState, client);
  assert(textOf(cell).includes('限速'));
  assert(textOf(cell).includes('禁用上网'));
  const buttons = cell.children[0].children;
  await buttons[1].listeners.click({ preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepStrictEqual(calls[0], [client.identity_key, '0', '0', '1']);
  assert.strictEqual(reloads, 1);

  const unavailable = module.cell(viewState, {
    identity_key: client.identity_key,
    control: Object.assign({}, client.control, {
      shaping_supported: false,
      blocking_supported: false,
      reason: 'ambiguous_identity'
    })
  });
  assert.strictEqual(unavailable.children[0].children[0].attrs.disabled, 'disabled');
  assert.strictEqual(unavailable.children[0].children[1].attrs.disabled, 'disabled');

  console.log('validate-lanspeed-client-control: PASS');
}

main().catch((error) => {
  console.error('validate-lanspeed-client-control: FAIL');
  console.error(error && error.stack || error);
  process.exitCode = 1;
});
