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
const ecmNode = fs.readFileSync(path.join(root,
  'net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/ecm_node.rs'), 'utf8');
const nssControlDir = path.join(root,
  'net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/control');
const nssControlModules = [
  'mod.rs', 'capability.rs', 'classifier.rs', 'ecm_qos.rs', 'firewall.rs', 'legacy.rs', 'qdisc.rs',
  'rollback.rs', 'shaper.rs', 'state.rs', 'system.rs', 'telemetry.rs', 'topology.rs'
];
const nssControlByModule = Object.fromEntries(nssControlModules.map((name) => [
  name, fs.readFileSync(path.join(nssControlDir, name), 'utf8')
]));
const nssControl = Object.values(nssControlByModule).join('\n');
const nssProductionControl = Object.values(nssControlByModule)
  .map((value) => value.split('#[cfg(test)]')[0]).join('\n');
const nssCpuPathDir = path.join(nssControlDir, 'cpu_path');
const nssCpuPathModules = [
  'mod.rs', 'block.rs', 'classifier.rs', 'ifb.rs', 'probe.rs', 'shaper.rs', 'tagger.rs'
];
const nssCpuPathByModule = Object.fromEntries(nssCpuPathModules.map((name) => [
  name, fs.readFileSync(path.join(nssCpuPathDir, name), 'utf8')
]));
const nssCpuPath = Object.values(nssCpuPathByModule).join('\n');
const nssCpuPathProduction = Object.values(nssCpuPathByModule)
  .map((value) => value.split('#[cfg(test)]')[0]).join('\n');
const nssKmodSource = fs.readFileSync(path.join(root,
  'net/lanspeed-nss-control/src/lanspeed_nss_control.c'), 'utf8');
const nssCpuBlockProduction = nssCpuPathByModule['block.rs'].split('#[cfg(test)]')[0];
const nssCpuProbeProduction = nssCpuPathByModule['probe.rs'].split('#[cfg(test)]')[0];
const daemonMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
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
    x86ControlByModule['classifier.rs'].includes('CONTROL_PROTOCOLS: [&str; 2] = ["ip", "ipv6"]') &&
    x86ControlByModule['shaper.rs'].includes('Direction::Download => "dst"') &&
    x86ControlByModule['shaper.rs'].includes('"ether"') &&
    x86ControlByModule['shaper.rs'].includes('CONTROL_PROTOCOLS: [&str; 2] = ["ip", "ipv6"]') &&
    !x86ControlByModule['shaper.rs'].includes('"cls_flower"'),
    'LAN/local destinations and non-IP control frames must pass before dual-stack client shaping');
  assert(x86ControlByModule['shaper.rs'].includes('Self::Upload => UPLOAD_HANDLE') &&
    x86ControlByModule['shaper.rs'].includes('Self::Download => DOWNLOAD_HANDLE') &&
    x86ControlByModule['shaper.rs'].includes('"htb"') &&
    x86ControlByModule['shaper.rs'].includes('"fq"') &&
    !x86ControlByModule['shaper.rs'].includes('"bfifo"') &&
    !x86ControlByModule['shaper.rs'].includes('legacy_upload_tree') &&
    !x86Control.includes('lanspeed_control_io') &&
    !x86ControlByModule['shaper.rs'].includes('wan_devices'),
    'x86 must use HTB/FQ for direct upload and independent LAN download trees');
  assert(x86ControlByModule['shaper.rs'].includes('APPLICATION_RATE_NUMERATOR: u64 = 110') &&
    x86ControlByModule['shaper.rs'].includes('fn application_rate(') &&
    x86ControlByModule['shaper.rs'].includes('fn htb_burst_bytes(') &&
    x86ControlByModule['shaper.rs'].includes('HTB_BURST_WINDOW_MILLIS: u64 = 10') &&
    x86ControlByModule['shaper.rs'].includes('"burst"') &&
    x86ControlByModule['shaper.rs'].includes('"cburst"'),
    'x86 HTB must translate application Mbps and use an explicit bounded token budget');
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
    x86ControlByModule['mod.rs'].indexOf('shaper::stage_download(device, rules)?') <
      x86ControlByModule['mod.rs'].indexOf('firewall::install(plan)?') &&
    x86ControlByModule['mod.rs'].indexOf('firewall::install(plan)?') <
      x86ControlByModule['mod.rs'].indexOf('shaper::activate_download(device, rules') &&
    x86ControlByModule['mod.rs'].includes('fn rollback('),
    'queue trees must stage before block/download/upload activation with rollback');
  assert(control.includes('pub interface: Option<String>') &&
    control.includes('valid_control_interface(&client.interface)') &&
    control.includes('control_devices.extend(rules.iter().map(|rule| rule.interface.clone()))') &&
    x86ControlByModule['mod.rs'].includes('fn upload_rules_by_device') &&
    x86ControlByModule['mod.rs'].includes('for (device, rules) in &upload_by_device'),
    'upload shaping must bind each rule to the client interface observed by the rate collector');
  assert(production.includes('observe_dae_topology(') &&
    production.includes('dae_preempted_devices,') &&
    production.includes('dae_upload_devices,') &&
    production.includes('observe_dae_topology_failure(') &&
    x86ControlByModule['mod.rs'].includes('rule.upload_before_proxy') &&
    x86ControlByModule['mod.rs'].includes('for device in &plan.dae_upload_devices') &&
    x86ControlByModule['mod.rs'].includes('cleanup_legacy_dae_upload_objects') &&
    x86ControlByModule['mod.rs'].includes('cleanup_obsolete_upload_classifiers(&active_upload_devices)?') &&
    x86ControlByModule['dae.rs'].includes('cleanup_obsolete_ingress_objects') &&
    x86ControlByModule['dae.rs'].includes('classifier::ingress_owned(&device)?') &&
    x86ControlByModule['dae.rs'].includes('fs::read_dir("/sys/class/net")') &&
    x86ControlByModule['dae.rs'].includes('classifier::legacy_dae_egress_owned(&device)?') &&
    !x86ControlByModule['mod.rs'].includes('const LEGACY_DEVICE') &&
    !x86ControlByModule['mod.rs'].includes('stage_native_upload') &&
    !x86ControlByModule['mod.rs'].includes('classifier::install_egress') &&
    !x86ControlByModule['mod.rs'].includes('plan.upload_preempted && !upload.is_empty()') &&
    control.includes('dae_upload_preempts_control') &&
    !source.includes('dae_upload_preempts_control'),
    'DAE upload must shape once on discovered bridge slaves and clean obsolete owned hooks after topology changes');
  assert(x86ControlByModule['firewall.rs'].includes('Hook::Ingress') &&
    x86ControlByModule['firewall.rs'].includes('Hook::Egress') &&
    x86ControlByModule['firewall.rs'].includes('"ether"') &&
    x86ControlByModule['firewall.rs'].includes('&rule.mac.to_string()') &&
    x86ControlByModule['firewall.rs'].includes('clear_conntrack_address') &&
    x86ControlByModule['firewall.rs'].includes('"drop"') &&
    x86ControlByModule['firewall.rs'].includes('NFT_OWNER_COMMENT') &&
    x86ControlByModule['firewall.rs'].includes('block_nft_owned_by_external_service') &&
    x86ControlByModule['firewall.rs'].includes('CONTROL_PROTOCOLS: [&str; 2] = ["ip", "ipv6"]') &&
    x86ControlByModule['firewall.rs'].includes('fn ingress_rules_by_device') &&
    x86ControlByModule['firewall.rs'].includes('fn egress_rules_by_device') &&
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
    control.includes('merge_control_lease_addresses(&mut next') &&
    control.includes('"224.0.0.0"') &&
    control.includes('"255.255.255.255"') &&
    control.includes('"ff00::"'),
    'persistent controls must recover safe addresses and keep LAN multicast out of shaping');
  assert(!production.includes('x86_control_bpf_unavailable') &&
    !production.includes('replace_control_maps'),
    'x86 client control availability must be independent of the rate-monitor BPF runtime');
  assert(!fs.existsSync(path.join(root,
    'net/lanspeedd/rust/crates/lanspeedd/src/platform/nss/control.rs')) &&
    fs.readdirSync(nssControlDir).filter((name) => name.endsWith('.rs')).sort().join(',') ===
      nssControlModules.slice().sort().join(','),
    'NSS client control must be a fixed modular implementation rather than a monolithic source file');
  for (const name of [
    'capability', 'classifier', 'cpu_path', 'ecm_qos', 'firewall', 'legacy', 'qdisc', 'rollback', 'shaper',
    'state', 'system', 'telemetry', 'topology'
  ])
    assert(nssControlByModule['mod.rs'].includes(`mod ${name};`),
      `NSS control/mod.rs must declare ${name}`);
  assert(ecmNode.includes('pub(crate) fn open_snapshot') &&
    ecmNode.includes('OUTPUT_MASK_LOCK') &&
    nssControlByModule['ecm_qos.rs'].includes('NSS_ACCELERATED') &&
    nssControlByModule['ecm_qos.rs'].includes('flow_qos_tag') &&
    nssControlByModule['ecm_qos.rs'].includes('return_qos_tag') &&
    nssControlByModule['telemetry.rs'].includes('ecm_qos::tagged_directions(plan)') &&
    nssControlByModule['telemetry.rs'].includes('directions & bit != 0') &&
    nssControlByModule['telemetry.rs'].includes('direction_counter_increased('),
    'NSS verification must combine accelerated ECM QoS tags with owned class counters');
  assert(nssModule.includes('#[cfg(feature = "nss-platform")]\npub(crate) mod control;') &&
    production.includes('control: ControlManager') &&
    !production.includes('client_control_x86_only') &&
    statusOverview.includes('showClientControl: true') &&
    statusRefresh.includes('clientControl.cell(viewState, c)') &&
    !statusRefresh.includes("nssProfile ? [] : [ clientControl.cell(viewState, c) ]"),
    'NSS builds and real-time status rows must expose their isolated client-control implementation');
  assert(nssControlByModule['qdisc.rs'].includes('"nsshtb"') &&
    nssControlByModule['qdisc.rs'].includes('"nssbfifo"') &&
    nssControlByModule['qdisc.rs'].includes('"accel_mode",\n            "0"') &&
    nssControlByModule['firewall.rs'].includes('meta priority set ip saddr map @upload4') &&
    nssControlByModule['firewall.rs'].includes('meta priority set ip daddr map @download4') &&
    nssControlByModule['firewall.rs'].includes('meta priority set ip6 saddr map @upload6') &&
    nssControlByModule['firewall.rs'].includes('meta priority set ip6 daddr map @download6') &&
    !nssControlByModule['qdisc.rs'].includes('"htb"') &&
    !nssControlByModule['qdisc.rs'].includes('"fq_codel"'),
    'NSS-visible directions must retain NSSHTB/NSSBFIFO and dual-stack QoS tags');
  assert(fs.readdirSync(nssCpuPathDir).filter((name) => name.endsWith('.rs')).sort().join(',') ===
      nssCpuPathModules.slice().sort().join(',') &&
    nssCpuPathByModule['ifb.rs'].includes('DEVICE_PREFIX') &&
    nssCpuPathByModule['ifb.rs'].includes('lanspeedd:nss-igs-upload:v3:') &&
    nssCpuPathByModule['ifb.rs'].includes('IgsState::Published') &&
    nssCpuPathByModule['ifb.rs'].includes('IgsState::Degraded') &&
    !nssCpuPathByModule['ifb.rs'].includes('ifb-nss-lsu') &&
    !nssCpuPathByModule['ifb.rs'].includes('ifb-nss-lsd') &&
    nssCpuPathByModule['classifier.rs'].includes('Direction::Upload => "ingress"') === false &&
    nssCpuPathByModule['mod.rs'].includes('shaper::stage(plan)') &&
	    nssCpuPathByModule['mod.rs'].includes('classifier::install(plan)') &&
	    nssCpuPathByModule['classifier.rs'].includes('ifb::publish') &&
	    !nssCpuPathByModule['classifier.rs'].includes('"action",\n            "nssmirred"') &&
	    nssCpuPathByModule['classifier.rs'].includes('const UPLOAD_CHAIN: u32 = 0x7e22') &&
	    nssCpuPathByModule['classifier.rs'].includes('fn edge_ingress_mac_matches') &&
	    nssCpuPathByModule['classifier.rs'].includes('mac_u32_matches(Direction::Download, rule.mac)') &&
	    nssCpuPathByModule['classifier.rs'].includes('"action", "skbedit", "priority"') &&
	    nssCpuPathByModule['classifier.rs'].includes('"action", "mirred", "egress"') &&
	    nssCpuPathByModule['classifier.rs'].includes('exact_upload_redirect_actions') &&
	    nssCpuPathByModule['classifier.rs'].indexOf('add_upload_prefix_pass(edge') <
	      nssCpuPathByModule['classifier.rs'].indexOf('add_upload_redirect(edge') &&
			nssCpuPathByModule['classifier.rs'].includes('"gact"') &&
			nssCpuPathByModule['classifier.rs'].includes('"skbedit"') &&
		nssCpuProbeProduction.includes('hook prerouting') &&
		nssCpuProbeProduction.includes('hook postrouting') &&
		nssCpuProbeProduction.includes('ip daddr @local4 return') &&
		nssCpuProbeProduction.includes('ip saddr @local4 return') &&
		nssCpuProbeProduction.includes('counter comment') &&
		!nssCpuProbeProduction.includes(' redirect ') &&
		!nssCpuProbeProduction.includes(' drop') &&
		!nssCpuProbeProduction.includes(' reject') &&
		nssCpuBlockProduction.includes('hook prerouting priority -30') &&
		nssCpuBlockProduction.includes('hook postrouting priority -30') &&
		nssCpuBlockProduction.indexOf('ip daddr @local4 return') <
			nssCpuBlockProduction.indexOf('counter drop comment') &&
		nssCpuBlockProduction.indexOf('ip saddr @local4 return') <
			nssCpuBlockProduction.indexOf('counter drop comment') &&
		nssCpuBlockProduction.includes('ether {mac_field}') &&
		nssCpuBlockProduction.includes('{address_set} counter drop comment') &&
		!nssCpuBlockProduction.includes(' reject') &&
		!nssCpuBlockProduction.includes(' redirect ') &&
	    nssCpuPathByModule['shaper.rs'].includes('"nsshtb"') &&
	    nssCpuPathByModule['shaper.rs'].includes('"nssbfifo"') &&
	    nssCpuPathByModule['shaper.rs'].includes('sync_igs_tree') &&
	    nssCpuPathByModule['tagger.rs'].includes('tag_config') &&
	    nssCpuPathByModule['tagger.rs'].includes('Record::Local') &&
	    nssCpuPathByModule['tagger.rs'].includes('Record::Client') &&
	    !nssCpuPathProduction.includes('police') &&
	    !nssCpuPathProduction.includes('nft limit') &&
    !nssCpuPathProduction.includes('platform::x86::control') &&
    nssKmodSource.includes('NSS_IF_SET_IGS_NODE') &&
    nssKmodSource.includes('nss_if_set_nexthop') &&
    nssKmodSource.includes('NSS_IF_CLEAR_IGS_NODE') &&
    nssKmodSource.includes('nss_if_reset_nexthop') &&
    nssKmodSource.includes('LANSPEED_IGS_DEGRADED') &&
    nssKmodSource.includes('igs_flow_qos_tag') &&
    nssKmodSource.includes('igs_reply_qos_tag') &&
	    nssKmodSource.includes('NF_IP_PRI_CONNTRACK + 2') &&
	    nssControlByModule['capability.rs'].includes('"act_mirred"') &&
	    nssKmodSource.indexOf('lanspeed_igs_config(edge, NSS_IF_SET_IGS_NODE') <
      nssKmodSource.indexOf('nss_if_set_nexthop') &&
    nssKmodSource.indexOf('nss_if_reset_nexthop') <
      nssKmodSource.indexOf('lanspeed_igs_config(entry->edge, NSS_IF_CLEAR_IGS_NODE'),
    'NSS CPU path must use one aggregate NSS IGS queue with transactional edge publication');
  assert(control.includes('nss_proven_directions') &&
    control.includes('nss_cpu_directions') &&
    control.includes('nss_active_nss_directions') &&
    control.includes('nss_active_cpu_directions') &&
    production.includes('observe_nss_paths(nss_control_path_observations(') &&
    nssControlByModule['telemetry.rs'].includes('plan.nss_direction_proven') &&
    nssControlByModule['telemetry.rs'].includes('plan.nss_direction_uses_cpu') &&
    nssControlByModule['telemetry.rs'].includes('active_executors_verified(') &&
    nssControlByModule['telemetry.rs'].includes('cpu_path::verify(plan)') &&
    nssControlByModule['telemetry.rs'].includes('firewall::verify(plan, true)'),
    'each observed packet path must select one executor and reverify all owned objects');
  const nssApply = nssControlByModule['mod.rs'];
  const firstConntrackRefresh = nssApply.indexOf('classifier::refresh_connections(plan)');
  const secondConntrackRefresh = nssApply.indexOf(
    'classifier::refresh_connections(plan)', firstConntrackRefresh + 1);
  assert(nssControlByModule['capability.rs'].includes('if needs_aggregate_executor(plan)') &&
    nssControlByModule['firewall.rs'].includes('nss_direction_enabled(plan, rule') &&
    nssApply.indexOf('classifier::preflight(plan)') < firstConntrackRefresh &&
    nssApply.indexOf('cpu_path::quiesce(plan)') < firstConntrackRefresh &&
    firstConntrackRefresh < nssApply.indexOf('shaper::stage(plan, topology)') &&
    nssApply.indexOf('classifier::commit(plan)') < secondConntrackRefresh,
    'NSS must clear old tags before queue mutation and refresh new flows after QoS maps commit');
  assert(!nssProductionControl.includes('daed') && !nssProductionControl.includes('dae_') &&
    production.includes('#[cfg(not(feature = "nss-platform"))]\n    fn refresh_controls') &&
    production.includes('#[cfg(feature = "nss-platform")]\n    fn refresh_controls'),
    'NSS control must remain independent of the x86 DAE topology and lifecycle path');
  const nssTopologyProduction = nssControlByModule['topology.rs'].split('#[cfg(test)]')[0];
  assert(nssTopologyProduction.includes('fn nss_edge_device') &&
    nssTopologyProduction.includes('/sys/class/net/{device}/device') &&
    nssTopologyProduction.includes('/sys/class/net/{device}/phy80211') &&
    !nssTopologyProduction.includes('"wan"') &&
    !nssTopologyProduction.includes('"br-lan"') &&
    daemonMakefile.includes('LANSPEED_NSS_CONTROL_DEPENDS:=+TARGET_qualcommax:tc-full') &&
    daemonMakefile.includes('TARGET_qualcommax:kmod-ifb') &&
    daemonMakefile.includes('TARGET_qualcommax:kmod-sched-core') &&
    daemonMakefile.includes('LANSPEED_X86_CONTROL_DEPENDS:=+TARGET_x86:tc-full +TARGET_x86:ip +TARGET_x86:nftables +TARGET_x86:conntrack +TARGET_x86:kmod-ifb +TARGET_x86:kmod-sched-core +TARGET_x86:kmod-sched'),
    'NSS targets and hook devices must be dynamic while scheduler dependencies stay platform-scoped');
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
  assert.strictEqual(module.mbpsToBps('0.008', 4_000_000_000), 8_000);
  assert.strictEqual(module.mbpsToBps('10.1234567', 4_000_000_000) % 8, 0);

  module.openLimit({}, {
    identity_key: '02:00:00:00:00:01@lan',
    hostname: 'client-demo',
    ips: [ '2001:db8::1', '192.0.2.44' ],
    mac: '02:00:00:00:00:01',
    control: {
      upload_bps: 8_000,
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
  const modalInputs = modals[0].body[2].children.map((label) => label.children[1]);
  assert.strictEqual(modalInputs[0].attrs.value, '0.008');
  assert.strictEqual(modalInputs[1].attrs.value, '100');
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

  const recoverable = module.cell(viewState, {
    identity_key: client.identity_key,
    control: Object.assign({}, client.control, {
      configured: true,
      upload_bps: 8_000,
      internet_disabled: true,
      shaping_supported: false,
      blocking_supported: false,
      reason: 'control_apply_failed'
    })
  });
  assert.strictEqual(recoverable.children[0].children[0].attrs.disabled, undefined,
    'an existing limit must remain removable after an apply failure');
  assert.strictEqual(recoverable.children[0].children[1].attrs.disabled, undefined,
    'an existing block must remain restorable after an apply failure');

  console.log('validate-lanspeed-client-control: PASS');
}

main().catch((error) => {
  console.error('validate-lanspeed-client-control: FAIL');
  console.error(error && error.stack || error);
  process.exitCode = 1;
});
