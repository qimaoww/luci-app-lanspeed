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
const x86Control = fs.readFileSync(path.join(root,
  'net/lanspeedd/rust/crates/lanspeedd/src/platform/x86/control.rs'), 'utf8');
const control = fs.readFileSync(path.join(root,
  'net/lanspeedd/rust/crates/lanspeedd/src/control.rs'), 'utf8');
const production = fs.readFileSync(path.join(root,
  'net/lanspeedd/rust/crates/lanspeedd/src/production.rs'), 'utf8');

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
  assert(x86Control.includes('add table netdev {CONTROL_NETDEV_TABLE}') &&
    x86Control.includes('hook ingress device') &&
    x86Control.includes('fn append_upload_mark_rules(') &&
    x86Control.includes('meta mark 0 {family} saddr {address} meta mark set 0x{mark:08x}') &&
    x86Control.includes('"match",') && x86Control.includes('"mark",') &&
    x86Control.includes('UPLOAD_MARK_MASK'),
    'x86 upload control must carry an isolated ingress mark into a WAN egress HTB filter');
  assert(!x86Control.includes('upload_ingress meta priority set'),
    'x86 upload control must not rely on skb priority surviving routing, flow offload, and PPPoE');
  assert(x86Control.indexOf('nft_ingress_supported(&plan.lan_device)?') <
    x86Control.indexOf('preflight_upload(&wan)?'),
    'x86 upload control must preflight the nft ingress hook before replacing any qdisc');
  assert(x86Control.includes('fn add_u32_filter(') && x86Control.includes('"dst"') &&
    x86Control.includes('fn add_mark_filter('),
    'x86 upload and download control must classify at their owned egress HTB trees');
  assert(x86Control.includes('"quantum", &quantum') &&
    x86Control.includes('fn control_quantum_from_mtu(') &&
    x86Control.includes('MIN_CONTROL_QUANTUM_BYTES: u64 = 1_514'),
    'x86 controlled HTB classes must use an MTU-sized quantum instead of the bursty default rate/r2q value');
  assert(x86Control.includes('UPLOAD_QUEUE_WINDOW_SECONDS: u64 = 4') &&
    x86Control.includes('fn x86_queue_bytes('),
    'x86 upload BFIFO must absorb startup bursts without changing the NSS queue policy');
  assert(control.includes('CONTROL_DHCP_LEASES_PATH') &&
    control.includes('fn lease_addresses_from(') &&
    control.includes('merge_control_lease_addresses(&mut next'),
    'persistent controls must preinstall from an unexpired DHCP lease before the client sends traffic');
  assert(!x86Control.includes('bpf_redirect') && !x86Control.toLowerCase().includes('ifb'),
    'x86 client control must not contain BPF redirect or IFB paths');
  assert(!production.includes('x86_control_bpf_unavailable') &&
    !production.includes('replace_control_maps'),
    'x86 client control availability must be independent of the rate-monitor BPF runtime');
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
