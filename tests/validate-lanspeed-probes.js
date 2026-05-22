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

function addUnique(array, value) {
  if (!array.includes(value)) {
    array.push(value);
  }
}

function enabledState(enabled) {
  return enabled ? 'enabled' : 'disabled';
}

function presentState(present) {
  return present ? 'present' : 'missing';
}

function commandEvidence(name, available) {
  return {
    source: `command:${name}`,
    available
  };
}

function commandProbeEvidence(key, command, exitCode, supported, summary) {
  return {
    source: `command:${key}`,
    command,
    exit_code: exitCode,
    supported,
    summary
  };
}

function uciEvidence(name, loaded) {
  return {
    source: `uci:${name}`,
    package: name,
    loaded
  };
}

function uciOptionEvidence(packageName, section, option, value) {
  const present = value !== undefined && value !== null;

  return {
    source: `uci:${packageName}.${section}.${option}`,
    package: packageName,
    section,
    option,
    present,
    ...(present ? { value: String(value) } : {})
  };
}

function fileEvidence(pathName, present, value) {
  const result = {
    source: `file:${pathName}`,
    path: pathName,
    present
  };

  if (value !== undefined) {
    result.value = value;
  }

  return result;
}

function ubusEvidence(object, state) {
  return {
    source: `ubus:${object}`,
    object,
    attempted: Boolean(state.attempted),
    exit_code: state.exit_code,
    summary: state.exit_code === 0 ? 'status available' : 'status unavailable'
  };
}

function getOpenClashConfig(fixture) {
  if (!fixture.openclash) {
    return {};
  }

  return fixture.openclash;
}

function isOpenClashFakeIp(openclash) {
  return String(openclash.en_mode || '').includes('fake-ip') || String(openclash.en_mode || '').includes('fake_ip');
}

function isOpenClashTunMix(openclash) {
  const enMode = String(openclash.en_mode || '').toLowerCase();
  const stackType = String(openclash.stack_type || '').toLowerCase();

  return enMode.includes('tun') || enMode.includes('mix') || stackType.includes('tun') || stackType.includes('mix');
}

function buildOpenClashEvidence(fixture) {
  const openclash = getOpenClashConfig(fixture);
  const installed = Boolean(fixture.uci.openclash);
  const redirectDns = Boolean(openclash.enable_redirect_dns);
  const dnsmasqChain = Boolean(openclash.dnsmasq_to_openclash_dns);

  return {
    installed,
    en_mode: openclash.en_mode || 'unknown',
    fake_ip: installed && isOpenClashFakeIp(openclash),
    tun_mix: installed && isOpenClashTunMix(openclash),
    enable_redirect_dns: installed && redirectDns,
    dnsmasq_to_127_0_0_1_7874: installed && dnsmasqChain,
    dns_chain_complete: !installed || !redirectDns || dnsmasqChain,
    router_self_proxy: installed && Boolean(openclash.router_self_proxy),
    enable_udp_proxy: installed && Boolean(openclash.enable_udp_proxy),
    stack_type: openclash.stack_type || 'unknown',
    ipv6_enable: installed && Boolean(openclash.ipv6_enable),
    remote_identity_policy: 'fake-ip and proxy remote addresses are metadata only, never LAN client identity',
    primary_bpf_policy: 'do_not_disable_lan_edge_bpf_when_openclash_is_present',
    router_self_bucket: 'router_self'
  };
}

function getDaeConfig(fixture) {
  return fixture.dae || {};
}

function normalizeTcFilters(fixture) {
  return (fixture.tc.filters || []).map((filter) => ({
    interface: filter.interface || fixture.tc.device || 'br-lan',
    direction: filter.direction || 'ingress',
    pref: String(filter.pref),
    handle: String(filter.handle),
    owner: filter.owner || 'unknown',
    source: filter.source || 'tc_filter_show'
  }));
}

function hasTcFilterConflict(filters) {
  return filters.some((filter) => (
    Number(filter.pref) === 49152 &&
    filter.handle === '0x1eed' &&
    filter.owner !== 'lanspeed'
  ));
}

function daePreemptsLanIngress(filters) {
  return filters.some((filter) => (
    filter.interface === 'eth1' &&
    filter.direction === 'ingress' &&
    filter.owner === 'dae' &&
    Number(filter.pref) > 0 &&
    Number(filter.pref) < 49152
  ));
}

function buildDaeEvidence(fixture, tcFilters) {
  const dae = getDaeConfig(fixture);
  const installed = Boolean(
    fixture.uci.dae ||
    fixture.uci.daed ||
    dae.dae_service ||
    dae.daed_service ||
    dae.dae0 ||
    dae.dae0peer ||
    dae.fwmark_detected ||
    dae.route_table_detected ||
    dae.dns_udp53_detected ||
    tcFilters.some((filter) => filter.owner === 'dae')
  );

  return {
    installed,
    dae_config: Boolean(fixture.uci.dae),
    daed_config: Boolean(fixture.uci.daed),
    dae_service: Boolean(dae.dae_service),
    daed_service: Boolean(dae.daed_service),
    dae0: Boolean(dae.dae0),
    dae0peer: Boolean(dae.dae0peer),
    tc_filters: tcFilters.filter((filter) => filter.owner === 'dae'),
    fwmark: '0x8000000',
    fwmark_detected: Boolean(dae.fwmark_detected),
    route_table: '2023',
    route_table_detected: Boolean(dae.route_table_detected),
    dns_udp53_detected: Boolean(dae.dns_udp53_detected),
    uplink_evidence_policy: 'TUN/PPP/WG/dae interfaces are proxy/uplink evidence only, never LAN client identity sources',
    identity_policy: 'dae0 and dae0peer MAC/IP observations are excluded from LAN clients'
  };
}

function addSourceFromEvidence(probeSources, kind, evidence) {
  addUnique(probeSources[kind], evidence.source);
}

function buildHealth(fixture) {
  const warnings = [];
  const conflicts = [];
  const commands = {};
  const uci = {};
  const files = {};
  const ubus = {};
  const probeSources = {
    command: [],
    file: [],
    uci: [],
    ubus: []
  };
  const tcFilters = normalizeTcFilters(fixture);
  const daeEvidence = buildDaeEvidence(fixture, tcFilters);
  const tcFilterConflict = Boolean(fixture.tc.conflict || hasTcFilterConflict(tcFilters));
  const daeIngressPreempted = daePreemptsLanIngress(tcFilters);
  const openclashEvidence = buildOpenClashEvidence(fixture);

  for (const name of ['fw4', 'nft', 'tc', 'ubus', 'qosify']) {
    commands[name] = commandEvidence(name, Boolean(fixture.commands[name]));
    addSourceFromEvidence(probeSources, 'command', commands[name]);
  }

  const firewall = fixture.uci.firewall;
  uci.firewall = uciEvidence('firewall', Boolean(firewall.loaded));
  addSourceFromEvidence(probeSources, 'uci', uci.firewall);
  for (const packageName of ['sqm', 'qosify', 'openclash', 'dae', 'daed', 'homeproxy', 'nlbwmon']) {
    uci[packageName] = uciEvidence(packageName, Boolean(fixture.uci[packageName]));
    addSourceFromEvidence(probeSources, 'uci', uci[packageName]);
  }
  if (fixture.uci.openclash) {
    const openclash = getOpenClashConfig(fixture);
    const openclashOptions = {
      openclash_en_mode: ['en_mode', openclash.en_mode],
      openclash_enable_redirect_dns: ['enable_redirect_dns', openclash.enable_redirect_dns ? '1' : '0'],
      openclash_router_self_proxy: ['router_self_proxy', openclash.router_self_proxy ? '1' : '0'],
      openclash_enable_udp_proxy: ['enable_udp_proxy', openclash.enable_udp_proxy ? '1' : '0'],
      openclash_stack_type: ['stack_type', openclash.stack_type],
      openclash_ipv6_enable: ['ipv6_enable', openclash.ipv6_enable ? '1' : '0']
    };

    for (const [key, [option, value]] of Object.entries(openclashOptions)) {
      uci[key] = uciOptionEvidence('openclash', openclash.section || 'config', option, value);
      addSourceFromEvidence(probeSources, 'uci', uci[key]);
    }
    uci.dhcp = uciEvidence('dhcp', Boolean(openclash.dhcp_loaded ?? true));
    addSourceFromEvidence(probeSources, 'uci', uci.dhcp);
  }

  const nfAcct = fixture.files.nf_conntrack_acct;
  files.nf_conntrack_acct = fileEvidence('/proc/sys/net/netfilter/nf_conntrack_acct', Boolean(nfAcct.present), nfAcct.value);
  files.flowtable_proc = fileEvidence('/proc/net/nf_flowtable', Boolean(fixture.files.flowtable_proc));
  files.flowtable_debug = fileEvidence('/sys/kernel/debug/netfilter/nf_flowtable', Boolean(fixture.files.flowtable_debug));
  files.ifb0 = fileEvidence('/sys/class/net/ifb0', Boolean(fixture.files.ifb));
  files.lan_bridge = fileEvidence('/sys/class/net/br-lan/bridge', Boolean(fixture.files.lan_bridge));
  files.vlan = fileEvidence('/proc/net/vlan/config', Boolean(fixture.files.vlan));
  files.wlan = fileEvidence('/sys/class/ieee80211', Boolean(fixture.files.wlan));
  files.lanspeedd_bpf_package = fileEvidence('/usr/share/lanspeed/bpf/collector-model.json', Boolean(fixture.files.bpf_package));
  files.lanspeedd_bpf_object = fileEvidence('/usr/lib/bpf/lanspeed_tc.o', Boolean(fixture.files.bpf_object));
  files.openclash_config = fileEvidence('/etc/config/openclash', Boolean(fixture.uci.openclash));
  files.dae_config = fileEvidence('/etc/config/dae', Boolean(fixture.uci.dae));
  files.daed_config = fileEvidence('/etc/config/daed', Boolean(fixture.uci.daed));
  files.homeproxy_config = fileEvidence('/etc/config/homeproxy', Boolean(fixture.uci.homeproxy));
  files.nlbwmon_config = fileEvidence('/etc/config/nlbwmon', Boolean(fixture.uci.nlbwmon));
  for (const entry of Object.values(files)) {
    addSourceFromEvidence(probeSources, 'file', entry);
  }

  const tcFilterExit = fixture.tc.filter_help_exit_code ?? 0;
  const tcQdiscExit = fixture.tc.qdisc_help_exit_code ?? 0;
  const tcShowExit = fixture.tc.filter_show_exit_code ?? 0;
  commands.tc_filter_help = commandProbeEvidence(
    'tc_filter_help',
    'tc filter help',
    tcFilterExit,
    Boolean(fixture.tc.bpf),
    fixture.tc.bpf ? 'bpf filter support advertised' : 'bpf filter support not advertised'
  );
  commands.tc_qdisc_help = commandProbeEvidence(
    'tc_qdisc_help',
    'tc qdisc help',
    tcQdiscExit,
    Boolean(fixture.tc.clsact),
    fixture.tc.clsact ? 'clsact qdisc support advertised' : 'clsact qdisc support not advertised'
  );
  commands.tc_filter_show_br_lan = commandProbeEvidence(
    'tc_filter_show_br_lan',
    'tc filter show dev br-lan ingress',
    tcShowExit,
    Boolean(fixture.tc.existing_filters),
    fixture.tc.existing_filters ? 'existing ingress filters detected' : 'no existing ingress filters detected'
  );
  for (const key of ['tc_filter_help', 'tc_qdisc_help', 'tc_filter_show_br_lan']) {
    addSourceFromEvidence(probeSources, 'command', commands[key]);
  }

  const nftRulesetExit = fixture.commands.nft_ruleset_exit_code ?? 0;
  const flowtableCounter = Boolean(fixture.commands.nft && fixture.commands.nft_ruleset_has_flowtable_counter && nftRulesetExit === 0);
  commands.nft_list_ruleset = commandProbeEvidence(
    'nft_list_ruleset',
    'nft list ruleset',
    nftRulesetExit,
    flowtableCounter,
    flowtableCounter ? 'flowtable counter detected' : 'flowtable counter not detected'
  );
  addSourceFromEvidence(probeSources, 'command', commands.nft_list_ruleset);

  ubus.network_lan = ubusEvidence('network.interface.lan', fixture.ubus.network_lan);
  addSourceFromEvidence(probeSources, 'ubus', ubus.network_lan);

  if (!fixture.commands.tc) {
    addUnique(warnings, 'tc_missing');
  }
  if (fixture.commands.tc && !fixture.tc.bpf) {
    addUnique(warnings, 'bpf_unsupported');
  }
  if (fixture.commands.tc && !fixture.tc.clsact) {
    addUnique(warnings, 'tc_clsact_unsupported');
  }
  if (fixture.tc.existing_filters) {
    addUnique(warnings, 'existing_tc_filters_detected');
  }
  if (tcFilterConflict) {
    addUnique(warnings, 'tc_filter_conflict');
    conflicts.push({
      id: 'tc_filter_conflict',
      severity: 'warning',
      message: 'An existing tc filter already uses lanspeed pref/handle; lanspeedd will not overwrite it.'
    });
  }
  if (daeIngressPreempted) {
    addUnique(warnings, 'dae_tc_preempts_bpf_ingress');
  }
  if (!fixture.config.enable_bpf) {
    addUnique(warnings, 'bpf_disabled');
  }
  if (!fixture.files.bpf_package) {
    addUnique(warnings, 'bpf_optional_package_missing');
  }
  if (!fixture.files.bpf_object) {
    addUnique(warnings, 'bpf_object_missing');
  }
  if (!fixture.commands.nft) {
    addUnique(warnings, 'flowtable_counter_probe_unavailable');
    addUnique(warnings, 'flowtable_counter_missing');
  }
  if (fixture.commands.nft && nftRulesetExit === 0 && !flowtableCounter) {
    addUnique(warnings, 'flowtable_counter_missing');
  }
  if (nfAcct.present && nfAcct.value !== '1') {
    addUnique(warnings, 'nf_conntrack_acct_disabled');
    addUnique(warnings, 'conntrack_acct_disabled');
  }
  if (fixture.uci.nlbwmon) {
    addUnique(warnings, 'nlbwmon_counter_conflict');
    conflicts.push({
      id: 'nlbwmon_counter_conflict',
      severity: 'warning',
      message: 'nlbwmon may use zero-on-read counters; lanspeedd does not read or disturb nlbwmon counters.'
    });
  }
  if (firewall.hardware_flow_offload) {
    addUnique(warnings, 'hardware_flow_offload_unsupported');
    conflicts.push({
      id: 'hardware_flow_offload',
      severity: 'warning',
      message: 'Hardware flow offload hides traffic from CPU-visible collectors.'
    });
  }
  if (firewall.software_flow_offload) {
    addUnique(warnings, 'software_flow_offload_enabled');
    conflicts.push({
      id: 'software_flow_offload',
      severity: 'info',
      message: 'Software flow offload may reduce counter confidence for some flows.'
    });
  }
  if (firewall.fullcone) {
    addUnique(warnings, 'fullcone_detected');
    addUnique(warnings, 'fullcone_nat_enabled');
    conflicts.push({
      id: 'fullcone',
      severity: 'info',
      message: 'Fullcone NAT is present and should be considered when interpreting flow ownership.'
    });
  }
  if (fixture.uci.sqm || fixture.uci.qosify || fixture.files.ifb) {
    conflicts.push({
      id: 'existing_qos',
      severity: 'warning',
      message: 'Existing QoS/IFB components may already own tc hooks.'
    });
  }
  if (fixture.uci.openclash || daeEvidence.installed || fixture.uci.homeproxy) {
    if (fixture.uci.openclash) {
      addUnique(warnings, 'openclash_detected');
    }
    if (daeEvidence.installed) {
      addUnique(warnings, 'dae_detected');
    }
    conflicts.push({
      id: 'proxy_stack',
      severity: 'info',
      message: 'Local proxy stacks can alter LAN/WAN flow paths.'
    });
  }
  if (openclashEvidence.fake_ip) {
    addUnique(warnings, 'openclash_fake_ip_low_remote_confidence');
  }
  if (openclashEvidence.tun_mix) {
    addUnique(warnings, 'openclash_tun_conntrack_low_confidence');
  }
  if (!openclashEvidence.dns_chain_complete) {
    addUnique(warnings, 'openclash_dns_chain_incomplete');
  }
  if (openclashEvidence.router_self_proxy) {
    addUnique(warnings, 'openclash_router_self_proxy_detected');
  }

  const probeError = fixture.ubus.network_lan.exit_code !== 0 || nftRulesetExit !== 0 || tcFilterExit !== 0 || tcQdiscExit !== 0;
  if (probeError) {
    addUnique(warnings, 'probe_error');
  }
  if (fixture.ubus.network_lan.exit_code !== 0) {
    addUnique(warnings, 'lan_topology_probe_error');
  }

  const lanEdge = Boolean(fixture.files.lan_bridge || fixture.files.vlan || fixture.files.wlan);
  const mapFull = fixture.config.max_clients === 0;
  const nssPresent = Boolean(fixture.nss && fixture.nss.present);
  const nssEcmActive = Boolean(fixture.nss && fixture.nss.ecm_active);
  const nssConntrackSyncPreferred = Boolean(
    fixture.config.enable_conntrack_fallback &&
    nfAcct.present &&
    nfAcct.value === '1' &&
    nssPresent &&
    nssEcmActive
  );
  const safeAttach = Boolean(
    fixture.config.enable_bpf &&
    fixture.commands.tc &&
    fixture.tc.clsact &&
    fixture.tc.bpf &&
    fixture.files.bpf_package &&
    fixture.files.bpf_object &&
    lanEdge &&
    !mapFull &&
    !tcFilterConflict
  );
  if (!lanEdge) {
    addUnique(warnings, 'lan_edge_missing');
  }
  if (mapFull) {
    addUnique(warnings, 'map_full');
  }
  if (fixture.config.enable_bpf && !safeAttach) {
    addUnique(warnings, 'unsafe_attach');
  }

  const bpfRuntimeMetrics = false;
  if (fixture.config.enable_bpf && safeAttach && !bpfRuntimeMetrics) {
    addUnique(warnings, 'bpf_runtime_loader_unavailable');
    addUnique(warnings, 'live_metrics_unavailable');
  }

  const bpfFullAvailable = Boolean(bpfRuntimeMetrics && !firewall.hardware_flow_offload);
  const conntrackPrimaryPreferred = nssConntrackSyncPreferred;
  const conntrackFallbackActive = Boolean(
    fixture.config.enable_conntrack_fallback &&
    conntrackPrimaryPreferred &&
    nfAcct.present &&
    nfAcct.value === '1'
  );
  const bpfPrimaryActive = Boolean(bpfFullAvailable && !conntrackPrimaryPreferred);
  if (conntrackFallbackActive) {
    addUnique(warnings, 'conntrack_routed_nat_only');
  }

  let mode = 'Full';
  if (!fixture.commands.tc && !conntrackFallbackActive) {
    mode = 'Unsupported';
  } else if (!bpfFullAvailable || probeError) {
    mode = 'Degraded';
  }
  if (mode !== 'Full') {
    addUnique(warnings, 'live_metrics_unavailable');
  }

  const conntrackLowConfidence = Boolean(conntrackFallbackActive && (
    !flowtableCounter ||
    firewall.software_flow_offload ||
    firewall.hardware_flow_offload ||
    openclashEvidence.fake_ip ||
    openclashEvidence.tun_mix ||
    openclashEvidence.router_self_proxy ||
    openclashEvidence.enable_udp_proxy ||
    daeEvidence.installed ||
    fixture.uci.homeproxy ||
    fixture.uci.sqm ||
    fixture.uci.qosify ||
    fixture.files.ifb ||
    fixture.uci.nlbwmon ||
    probeError
  ));
  const confidence = mode === 'Full' ? 'high' : probeError ? 'low' : mode === 'Unsupported' ? 'unsupported' : conntrackLowConfidence ? 'low' : 'medium';

  return {
    mode,
    confidence,
    capabilities: {
      bpf: Boolean(fixture.config.enable_bpf && bpfPrimaryActive),
      bpf_package: Boolean(fixture.files.bpf_package),
      bpf_object: Boolean(fixture.files.bpf_object),
      bpf_runtime_metrics: bpfRuntimeMetrics,
      conntrack_fallback: conntrackFallbackActive,
      live_metrics: bpfPrimaryActive,
      fw4: Boolean(fixture.commands.fw4),
      nft: Boolean(fixture.commands.nft),
      software_flow_offload: Boolean(firewall.software_flow_offload),
      hardware_flow_offload: Boolean(firewall.hardware_flow_offload),
      fullcone: Boolean(firewall.fullcone),
      nf_conntrack_acct: Boolean(nfAcct.present && nfAcct.value === '1'),
      flowtable_counter: flowtableCounter,
      tc: Boolean(fixture.commands.tc),
      tc_clsact: Boolean(fixture.tc.clsact),
      existing_tc_filters: Boolean(fixture.tc.existing_filters),
      ifb: Boolean(fixture.files.ifb),
      sqm: Boolean(fixture.uci.sqm),
      qosify: Boolean(fixture.uci.qosify || fixture.commands.qosify),
      openclash: Boolean(fixture.uci.openclash),
      openclash_fake_ip: openclashEvidence.fake_ip,
      openclash_tun_mix: openclashEvidence.tun_mix,
      openclash_redirect_dns: openclashEvidence.enable_redirect_dns,
      openclash_dns_chain_complete: openclashEvidence.dns_chain_complete,
      openclash_router_self_proxy: openclashEvidence.router_self_proxy,
      openclash_udp_proxy: openclashEvidence.enable_udp_proxy,
      openclash_ipv6: openclashEvidence.ipv6_enable,
      dae: daeEvidence.installed,
      homeproxy: Boolean(fixture.uci.homeproxy),
      lan_bridge: Boolean(fixture.files.lan_bridge),
      vlan: Boolean(fixture.files.vlan),
      wlan: Boolean(fixture.files.wlan),
      lan_edge: lanEdge,
      safe_attach: safeAttach,
      map_full: mapFull
    },
    conflicts,
    warnings,
    evidence: {
      source: 'lanspeedd_runtime_probe_fixture',
      method: 'health',
      read_only: true,
      software_flow_offload: enabledState(Boolean(firewall.software_flow_offload)),
      hardware_flow_offload: enabledState(Boolean(firewall.hardware_flow_offload)),
      fullcone: enabledState(Boolean(firewall.fullcone)),
      fullcone_nat_enabled: Boolean(firewall.fullcone),
      flowtable_counter: presentState(flowtableCounter),
      openclash: openclashEvidence,
      dae: daeEvidence,
      probe_sources: probeSources,
      commands,
      files,
      uci,
      ubus,
      probe_error: probeError,
      collector: {
        source: 'lanspeedd_tc_bpf_collector',
        runtime_safe: true,
        enabled: Boolean(fixture.config.enable_bpf),
        bpf_source: 'lanspeed_tc.bpf.c',
        runtime_object: '/usr/lib/bpf/lanspeed_tc.o',
        optional_package_present: Boolean(fixture.files.bpf_package),
        bpf_object_present: Boolean(fixture.files.bpf_object),
        safe_attach: safeAttach,
        bpf_assets_are_evidence_only: true,
        runtime_attach_map_read_success: bpfRuntimeMetrics,
        live_metrics: bpfPrimaryActive,
        primary_source: conntrackPrimaryPreferred ? 'nss_conntrack_sync' : (bpfPrimaryActive ? 'bpf' : 'unsupported'),
        runtime_gate_warning: 'bpf_runtime_loader_unavailable',
        map_full: mapFull,
        attach_model: {
          cpu_visible_lan_edges_only: true,
          detected_lan_edge: lanEdge,
          allowed: ['lan_bridge_members', 'vlan_subinterfaces', 'wlan_interfaces'],
          excluded: ['wan', 'tun', 'ppp', 'wg', 'dae0', 'dae0peer']
        },
        tc_filter: {
          qdisc: 'clsact',
          coexistence: 'create_or_reuse_clsact_and_append_owned_filter_only',
          delete_existing: false,
          reorder_existing: false,
          owner: 'lanspeed',
          pref: 49152,
          handle: '0x1eed',
          existing_filters_detected: Boolean(fixture.tc.existing_filters),
          existing_filters: tcFilters,
          conflict: tcFilterConflict,
          conflict_warning: 'tc_filter_conflict',
          dae_preempts_bpf_ingress: daeIngressPreempted,
          preempt_warning: 'dae_tc_preempts_bpf_ingress'
        },
        map_model: {
          key: ['ifindex', 'vlan_or_zone', 'mac', 'direction'],
          counters: ['bytes', 'packets', 'last_seen'],
          default_max_clients: 512,
          configured_max_clients: fixture.config.max_clients ?? 512,
          full_warning: 'map_full',
          directions: {
            tx_bps: 'client-originated traffic from the client point of view',
            rx_bps: 'traffic to client from the client point of view'
          }
        },
        dedupe_model: {
          lan_to_lan: 'merge matching frame observations before aggregate totals',
          visibility_unknown_warning: 'lan_to_lan_visibility_unknown',
          visibility_limited_warning: 'lan_to_lan_visibility_limited',
          cpu_visible_only: true,
          complete_coverage_claimed_for_hardware_switch_paths: false,
          duplicate_policy: 'do_not_count_one_lan_to_lan_frame_twice'
        },
        router_local_model: {
          client_perspective: true,
          client_to_router: 'tx_bps',
          router_to_client: 'rx_bps',
          router_originated_bucket: 'router_self',
          router_originated_alias: 'local_router',
          client_attribution: 'never_attribute_router_originated_traffic_to_lan_client'
        },
        topology_identity_model: {
          primary_key: 'mac+zone',
          preserve_mac_zone_identity: true,
          guest_vlan: 'separate zone identity',
          multi_bridge: 'bridge zone participates in identity key',
          wifi_wds_ap_isolation: 'wireless attachment metadata must not collapse MAC+zone identity',
          duplicate_mac_warning: 'duplicate_mac_across_vlans'
        },
        uplink_encapsulation_model: {
          wan_side_only: ['pppoe', 'wg', 'tun'],
          identity_policy: 'PPPoE/WG/TUN evidence never changes LAN-edge client MAC ownership'
        },
        conntrack_fallback_model: {
          source: 'lanspeedd_procfs_conntrack_acct',
          enabled: Boolean(fixture.config.enable_conntrack_fallback),
          active: conntrackFallbackActive,
          collector_mode: 'conntrack',
          primary_source: conntrackPrimaryPreferred ? 'nss_conntrack_sync' : (bpfPrimaryActive ? 'bpf' : 'unsupported'),
          mode: 'Degraded',
          confidence: conntrackFallbackActive ? (conntrackLowConfidence ? 'low' : 'medium') : 'unsupported',
          bpf_full_blocked_by_runtime_gate: !bpfRuntimeMetrics,
          non_nss_live_rate_policy: 'bpf_only',
          non_nss_conntrack_policy: 'connection_counts_and_diagnostics_only',
          coverage: 'routed_nat_only',
          coverage_warning: 'conntrack_routed_nat_only',
          nf_conntrack_acct: Boolean(nfAcct.present && nfAcct.value === '1'),
          flowtable_counter: flowtableCounter,
          flowtable_counter_state: presentState(flowtableCounter),
          nlbwmon_read_counters: false,
          router_self: {
            bucket: 'router_self',
            alias: 'local_router',
            enabled: openclashEvidence.router_self_proxy,
            identity_key: 'router_self@local_router',
            client_attribution: 'never_attribute_to_lan_client'
          },
          forbidden_sources: [
            'firewall_forward_chain_counters',
            'iptables_forward_chain_counters',
            'nft_forward_chain_counters',
            'nlbwmon_counters'
          ],
          warnings: warnings.filter((warning) => [
            'conntrack_routed_nat_only',
            'conntrack_acct_disabled',
            'dae_tc_preempts_bpf_ingress',
            'flowtable_counter_missing',
            'nlbwmon_counter_conflict',
            'proxy_path_confidence_low',
            'openclash_fake_ip_low_remote_confidence',
            'openclash_tun_conntrack_low_confidence',
            'openclash_dns_chain_incomplete'
          ].includes(warning))
        },
        router_self_model: {
          bucket: 'router_self',
          alias: 'local_router',
          enabled: openclashEvidence.router_self_proxy,
          client_attribution: 'never_attribute_to_lan_client',
          identity_key: 'router_self@local_router',
          warning: 'openclash_router_self_proxy_detected'
        },
        warnings: warnings.filter((warning) => [
          'bpf_disabled',
          'bpf_optional_package_missing',
          'bpf_object_missing',
          'lan_edge_missing',
          'map_full',
          'unsafe_attach',
          'bpf_runtime_loader_unavailable',
          'live_metrics_unavailable',
          'tc_filter_conflict',
          'dae_tc_preempts_bpf_ingress'
        ].includes(warning))
      }
    }
  };
}

function validateHealth(name, health) {
  for (const field of ['mode', 'confidence', 'capabilities', 'conflicts', 'warnings', 'evidence']) {
    assert(Object.prototype.hasOwnProperty.call(health, field), `${name}.${field} is required`);
  }
  assert(['Full', 'Degraded', 'Unsupported'].includes(health.mode), `${name}.mode must be a supported runtime mode`);
  assert(Array.isArray(health.conflicts), `${name}.conflicts must be an array`);
  assert(Array.isArray(health.warnings), `${name}.warnings must be an array`);
  assert(health.evidence.read_only === true, `${name}.evidence must declare read_only`);
  assert(typeof health.evidence.probe_error === 'boolean', `${name}.evidence.probe_error must be boolean`);
  for (const sourceKind of ['command', 'file', 'uci', 'ubus']) {
    assert(Array.isArray(health.evidence.probe_sources[sourceKind]), `${name}.evidence.probe_sources.${sourceKind} must be an array`);
    assert(health.evidence.probe_sources[sourceKind].length > 0, `${name}.evidence.probe_sources.${sourceKind} must not be empty`);
  }
  for (const capability of [
    'fw4',
    'nft',
    'bpf',
    'bpf_package',
    'bpf_object',
    'bpf_runtime_metrics',
    'live_metrics',
    'software_flow_offload',
    'hardware_flow_offload',
    'fullcone',
    'nf_conntrack_acct',
    'flowtable_counter',
    'tc',
    'tc_clsact',
    'existing_tc_filters',
    'ifb',
    'sqm',
    'qosify',
    'openclash',
    'openclash_fake_ip',
    'openclash_tun_mix',
    'openclash_redirect_dns',
    'openclash_dns_chain_complete',
    'openclash_router_self_proxy',
    'openclash_udp_proxy',
    'openclash_ipv6',
    'dae',
    'homeproxy',
    'lan_bridge',
    'vlan',
    'wlan',
    'lan_edge',
    'safe_attach',
    'map_full'
  ]) {
    assert(typeof health.capabilities[capability] === 'boolean', `${name}.capabilities.${capability} must be boolean`);
  }
  assert(Object.prototype.hasOwnProperty.call(health.evidence.commands, 'nft_list_ruleset'), `${name} must include nft ruleset evidence`);
  assert(Object.prototype.hasOwnProperty.call(health.evidence.files, 'flowtable_proc'), `${name} must include flowtable proc presence evidence`);
  assert(Object.prototype.hasOwnProperty.call(health.evidence.files, 'flowtable_debug'), `${name} must include flowtable debug presence evidence`);
  assert(['enabled', 'disabled'].includes(health.evidence.software_flow_offload), `${name}.evidence.software_flow_offload must be enabled or disabled`);
  assert(['enabled', 'disabled'].includes(health.evidence.hardware_flow_offload), `${name}.evidence.hardware_flow_offload must be enabled or disabled`);
  assert(['enabled', 'disabled'].includes(health.evidence.fullcone), `${name}.evidence.fullcone must be enabled or disabled`);
  assert(['present', 'missing'].includes(health.evidence.flowtable_counter), `${name}.evidence.flowtable_counter must be present or missing`);
  assert(typeof health.evidence.openclash.installed === 'boolean', `${name}.evidence.openclash.installed must be boolean`);
  assert(typeof health.evidence.openclash.dns_chain_complete === 'boolean', `${name}.evidence.openclash.dns_chain_complete must be boolean`);
  assert(typeof health.evidence.dae.installed === 'boolean', `${name}.evidence.dae.installed must be boolean`);
  assert(Array.isArray(health.evidence.dae.tc_filters), `${name}.evidence.dae.tc_filters must be an array`);
  assert(health.evidence.dae.fwmark === '0x8000000', `${name}.evidence.dae.fwmark must be stable`);
  assert(health.evidence.dae.route_table === '2023', `${name}.evidence.dae.route_table must be stable`);
  assert(typeof health.evidence.fullcone_nat_enabled === 'boolean', `${name}.evidence.fullcone_nat_enabled must be boolean`);
  assert(typeof health.capabilities.flowtable_counter === 'boolean', `${name}.capabilities.flowtable_counter must remain boolean`);
  assert(health.evidence.collector.runtime_safe === true, `${name}.evidence.collector.runtime_safe must be true`);
  assert(health.evidence.collector.bpf_source === 'lanspeed_tc.bpf.c', `${name}.collector must expose the BPF source`);
  assert(health.evidence.collector.runtime_object === '/usr/lib/bpf/lanspeed_tc.o', `${name}.collector must expose installed BPF object path`);
  assert(health.evidence.collector.bpf_assets_are_evidence_only === true, `${name}.collector must mark BPF assets as evidence only`);
  assert(health.evidence.collector.runtime_attach_map_read_success === health.capabilities.bpf_runtime_metrics, `${name}.collector runtime gate must match capability`);
  assert(health.evidence.collector.live_metrics === health.capabilities.live_metrics, `${name}.collector live_metrics must match capability`);
  assert(health.capabilities.live_metrics === false, `${name}.capabilities.live_metrics must stay false without runtime attach/map-read`);
  assert(health.capabilities.bpf === false, `${name}.capabilities.bpf must not mean live metrics from package/object evidence`);
  if (health.capabilities.safe_attach) {
    assert(health.warnings.includes('bpf_runtime_loader_unavailable'), `${name}.safe_attach without runtime gate must warn bpf_runtime_loader_unavailable`);
  }
  assert(health.evidence.collector.attach_model.cpu_visible_lan_edges_only === true, `${name}.collector must target CPU-visible LAN edges only`);
  assert(health.evidence.collector.attach_model.excluded.includes('wan'), `${name}.collector must exclude WAN-side MAC ownership`);
  assert(health.evidence.collector.attach_model.excluded.includes('tun'), `${name}.collector must exclude TUN-side MAC ownership`);
  assert(health.evidence.collector.attach_model.excluded.includes('dae0'), `${name}.collector must exclude dae0 from LAN identity`);
  assert(health.evidence.collector.attach_model.excluded.includes('dae0peer'), `${name}.collector must exclude dae0peer from LAN identity`);
  assert(health.evidence.collector.tc_filter.delete_existing === false, `${name}.collector must not delete existing tc filters`);
  assert(health.evidence.collector.tc_filter.reorder_existing === false, `${name}.collector must not reorder existing tc filters`);
  assert(health.evidence.collector.tc_filter.owner === 'lanspeed', `${name}.collector must mark owned filters`);
  assert(Array.isArray(health.evidence.collector.tc_filter.existing_filters), `${name}.collector must expose existing filter evidence`);
  assert(JSON.stringify(health.evidence.collector.map_model.key) === JSON.stringify(['ifindex', 'vlan_or_zone', 'mac', 'direction']), `${name}.collector map key must use ifindex/vlan/MAC/direction`);
  assert(JSON.stringify(health.evidence.collector.map_model.counters) === JSON.stringify(['bytes', 'packets', 'last_seen']), `${name}.collector counters must be bytes/packets/last_seen`);
  assert(health.evidence.collector.map_model.default_max_clients === 512, `${name}.collector map must default to 512 clients`);
  assert(health.evidence.collector.dedupe_model.visibility_limited_warning === 'lan_to_lan_visibility_limited', `${name}.collector must expose LAN-to-LAN limited visibility warning`);
  assert(health.evidence.collector.dedupe_model.complete_coverage_claimed_for_hardware_switch_paths === false, `${name}.collector must not claim complete hardware-switch LAN-to-LAN coverage`);
  assert(health.evidence.collector.router_local_model.client_to_router === 'tx_bps', `${name}.collector router-local upload must be tx_bps`);
  assert(health.evidence.collector.router_local_model.router_to_client === 'rx_bps', `${name}.collector router-local download must be rx_bps`);
  assert(health.evidence.collector.topology_identity_model.duplicate_mac_warning === 'duplicate_mac_across_vlans', `${name}.collector must expose duplicate MAC across VLAN warning`);
  assert(health.evidence.collector.uplink_encapsulation_model.wan_side_only.includes('pppoe'), `${name}.collector must represent PPPoE as WAN-side evidence`);
  assert(health.evidence.collector.uplink_encapsulation_model.wan_side_only.includes('wg'), `${name}.collector must represent WG as WAN-side evidence`);
  assert(health.evidence.collector.uplink_encapsulation_model.wan_side_only.includes('tun'), `${name}.collector must represent TUN as WAN-side evidence`);
}

function writeEvidence(fileName, health) {
  fs.writeFileSync(path.join(evidenceDir, fileName), `${JSON.stringify(health, null, 2)}\n`);
}

function assertNoForbiddenRuntimePatterns(source, conntrackHeader, conntrackSource, identitySource) {
  const forbidden = [
    /uci\s+commit/i,
    /fw4\s+reload/i,
    /service\s+network\s+reload/i,
    /disable\s+software\s+flow\s+offload/i,
    /software\s+flow\s+offload\s+should\s+be\s+disabled/i
  ];

  for (const pattern of forbidden) {
    assert(!pattern.test(source), `forbidden runtime pattern matched ${pattern}`);
  }

  assert(conntrackHeader.includes('CONNTRACK_PROCFS_PATH "/proc/net/nf_conntrack"'), 'fallback must read procfs conntrack accounting');
  assert(conntrackHeader.includes('CONNTRACK_LEGACY_PROCFS_PATH "/proc/net/ip_conntrack"'), 'fallback must support legacy procfs conntrack accounting');
  assert(conntrackSource.includes('procfs_conntrack_acct_orig_reply_bytes') || source.includes('json_object_new_string("procfs_conntrack_acct_orig_reply_bytes")'), 'fallback counter source must be procfs conntrack accounting');
  assert(source.includes('openclash_fake_ip_low_remote_confidence'), 'OpenClash fake-ip warning must be implemented');
  assert(source.includes('openclash_tun_conntrack_low_confidence'), 'OpenClash TUN/mix warning must be implemented');
  assert(source.includes('openclash_dns_chain_incomplete'), 'OpenClash DNS chain warning must be implemented');
  assert(source.includes('127.0.0.1#7874'), 'OpenClash DNS chain probe must look for dnsmasq forwarding to 127.0.0.1#7874');
  assert(source.includes('router_self@local_router'), 'router self proxy traffic must have a separate local router identity bucket');
  assert(source.includes('DAE_FWMARK "0x8000000"'), 'dae fwmark constant must be implemented');
  assert(source.includes('DAE_ROUTE_TABLE "2023"'), 'dae route table constant must be implemented');
  assert(source.includes('dae0peer') || identitySource.includes('dae0peer'), 'dae0peer must be handled explicitly');
  assert(source.includes('tc_filter_conflict'), 'tc filter pref/handle conflict warning must be implemented');
  assert(source.includes('ifname_is_excluded_identity_source') || identitySource.includes('ifname_is_excluded_identity_source'), 'runtime clients must exclude proxy/uplink interface identity sources');
  assert(source.includes('lan_to_lan_visibility_limited'), 'runtime collector evidence must expose hardware-switch LAN-to-LAN limited visibility warning');
  assert(source.includes('duplicate_mac_across_vlans'), 'runtime collector evidence must expose duplicate MAC across VLAN warning');
  assert(source.includes('never_attribute_router_originated_traffic_to_lan_client'), 'runtime collector evidence must keep router-originated traffic separate from LAN clients');
  assert(source.includes('PPPoE/WG/TUN evidence never changes LAN-edge client MAC ownership'), 'runtime collector evidence must keep PPPoE/WG/TUN as WAN-side evidence only');
  assert(!/"counter_source"\s*,\s*json_object_new_string\("(?:firewall|iptables|nft)_forward_chain_counters"\)/.test(source), 'fallback must not use firewall forward-chain counters as counter_source');
}

fs.mkdirSync(evidenceDir, { recursive: true });

const runtimeSource = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeedd.c'), 'utf8');
const conntrackHeader = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeed_conntrack.h'), 'utf8');
const conntrackSource = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeed_conntrack.c'), 'utf8');
const identitySource = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeed_identity.c'), 'utf8');
assertNoForbiddenRuntimePatterns(runtimeSource, conntrackHeader, conntrackSource, identitySource);

const baseHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-base.json'));
const softwareFlowOffloadHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-software-flow-offload.json'));
const missingTcHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-missing-tc.json'));
const hardwareFlowOffloadHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-hardware-flow-offload.json'));
const probeErrorHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-error.json'));
const flowtableMissingNlbwmonHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-flowtable-missing-nlbwmon.json'));
const conntrackAcctDisabledHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-conntrack-acct-disabled.json'));
const openclashFakeIpHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-openclash-fakeip.json'));
const openclashRouterSelfHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-openclash-router-self.json'));
const daeTcPreserveHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-dae-tc-preserve.json'));
const daeTcConflictHealth = buildHealth(readJson('tests/fixtures/lanspeed-probe-dae-tc-conflict.json'));

validateHealth('baseHealth', baseHealth);
validateHealth('softwareFlowOffloadHealth', softwareFlowOffloadHealth);
validateHealth('missingTcHealth', missingTcHealth);
validateHealth('hardwareFlowOffloadHealth', hardwareFlowOffloadHealth);
validateHealth('probeErrorHealth', probeErrorHealth);
validateHealth('flowtableMissingNlbwmonHealth', flowtableMissingNlbwmonHealth);
validateHealth('conntrackAcctDisabledHealth', conntrackAcctDisabledHealth);
validateHealth('openclashFakeIpHealth', openclashFakeIpHealth);
validateHealth('openclashRouterSelfHealth', openclashRouterSelfHealth);
validateHealth('daeTcPreserveHealth', daeTcPreserveHealth);
validateHealth('daeTcConflictHealth', daeTcConflictHealth);

assert(baseHealth.mode === 'Degraded', 'base probe fixture must degrade until runtime BPF attach/map-read is implemented');
assert(baseHealth.capabilities.live_metrics === false, 'base probe fixture must not allow live metrics from BPF assets alone');
assert(baseHealth.warnings.includes('bpf_runtime_loader_unavailable'), 'base probe fixture must warn BPF runtime loader unavailable');
assert(baseHealth.capabilities.flowtable_counter === true, 'base probe fixture should detect nft flowtable counter support');
assert(baseHealth.evidence.commands.nft_list_ruleset.supported === true, 'base evidence must prove nft ruleset counter support');
assert(baseHealth.evidence.software_flow_offload === 'disabled', 'base evidence must expose disabled software flow offload state');
assert(baseHealth.evidence.flowtable_counter === 'present', 'base evidence must expose present flowtable counter state');

assert(softwareFlowOffloadHealth.mode === 'Degraded', 'software flow offload fixture must still degrade without runtime BPF attach/map-read');
assert(softwareFlowOffloadHealth.capabilities.software_flow_offload === true, 'software flow offload capability must be true');
assert(softwareFlowOffloadHealth.capabilities.hardware_flow_offload === false, 'software flow offload fixture must not imply hardware flow offload');
assert(softwareFlowOffloadHealth.evidence.software_flow_offload === 'enabled', 'software flow offload evidence must be enabled');
assert(softwareFlowOffloadHealth.evidence.hardware_flow_offload === 'disabled', 'hardware flow offload evidence must remain disabled');
assert(softwareFlowOffloadHealth.evidence.fullcone === 'enabled', 'fullcone evidence must be enabled');
assert(softwareFlowOffloadHealth.evidence.fullcone_nat_enabled === true, 'fullcone_nat_enabled evidence must be true');
assert(softwareFlowOffloadHealth.warnings.includes('software_flow_offload_enabled'), 'software flow offload warning is required');
assert(softwareFlowOffloadHealth.warnings.includes('fullcone_nat_enabled'), 'fullcone_nat_enabled warning is required');
assert(softwareFlowOffloadHealth.conflicts.some((conflict) => conflict.id === 'fullcone'), 'fullcone conflict is required');

assert(missingTcHealth.mode === 'Degraded' || missingTcHealth.mode === 'Unsupported', 'missing tc must not claim Full');
assert(missingTcHealth.warnings.includes('tc_missing'), 'missing tc must include tc_missing warning');
assert(missingTcHealth.capabilities.tc === false, 'missing tc capabilities.tc must be false');

assert(hardwareFlowOffloadHealth.mode !== 'Full', 'hardware flow offload must not claim Full');
assert(hardwareFlowOffloadHealth.warnings.includes('hardware_flow_offload_unsupported'), 'hardware flow offload warning is required');
assert(hardwareFlowOffloadHealth.conflicts.some((conflict) => conflict.id === 'hardware_flow_offload'), 'hardware flow offload conflict is required');
assert(hardwareFlowOffloadHealth.evidence.hardware_flow_offload === 'enabled', 'hardware flow offload evidence must be enabled');

assert(probeErrorHealth.mode !== 'Full', 'probe error must not claim Full');
assert(probeErrorHealth.warnings.includes('probe_error'), 'probe error warning is required');
assert(probeErrorHealth.evidence.probe_error === true, 'probe error evidence must be true');
assert(probeErrorHealth.capabilities.flowtable_counter === false, 'failed nft probe must not claim flowtable counter support');

assert(flowtableMissingNlbwmonHealth.mode === 'Degraded', 'flowtable missing fixture should remain Degraded while BPF runtime metrics are unavailable');
assert(flowtableMissingNlbwmonHealth.confidence === 'medium', 'non-NSS missing flowtable/nlbwmon must not lower live-rate confidence through CT speed fallback');
assert(flowtableMissingNlbwmonHealth.warnings.includes('flowtable_counter_missing'), 'missing flowtable counter warning is required');
assert(flowtableMissingNlbwmonHealth.evidence.flowtable_counter === 'missing', 'missing flowtable counter evidence is required');
assert(flowtableMissingNlbwmonHealth.warnings.includes('nlbwmon_counter_conflict'), 'nlbwmon conflict warning is required');
assert(flowtableMissingNlbwmonHealth.evidence.collector.conntrack_fallback_model.active === false, 'non-NSS conntrack fallback must stay inactive for speed when BPF Full is unavailable');
assert(flowtableMissingNlbwmonHealth.evidence.collector.conntrack_fallback_model.non_nss_live_rate_policy === 'bpf_only', 'non-NSS live-rate policy must be BPF-only in probe evidence');
assert(flowtableMissingNlbwmonHealth.evidence.collector.conntrack_fallback_model.nlbwmon_read_counters === false, 'health model must not read nlbwmon counters');

assert(conntrackAcctDisabledHealth.capabilities.conntrack_fallback === false, 'acct disabled health must disable conntrack fallback capability');
assert(conntrackAcctDisabledHealth.warnings.includes('conntrack_acct_disabled'), 'acct disabled health warning is required');
assert(conntrackAcctDisabledHealth.evidence.collector.conntrack_fallback_model.active === false, 'acct disabled health must keep fallback inactive');

assert(openclashFakeIpHealth.mode === 'Degraded', 'OpenClash fake-ip fixture must not claim Full without runtime BPF attach/map-read');
assert(openclashFakeIpHealth.confidence === 'medium', 'OpenClash fake-ip must not lower live-rate confidence through non-NSS CT speed fallback');
assert(openclashFakeIpHealth.capabilities.openclash === true, 'OpenClash fake-ip fixture must detect OpenClash');
assert(openclashFakeIpHealth.capabilities.openclash_fake_ip === true, 'OpenClash fake-ip capability is required');
assert(openclashFakeIpHealth.capabilities.safe_attach === true, 'OpenClash fake-ip fixture must preserve safe_attach');
assert(openclashFakeIpHealth.capabilities.live_metrics === false, 'OpenClash fake-ip fixture must not preserve fake BPF live metrics');
assert(openclashFakeIpHealth.warnings.includes('openclash_fake_ip_low_remote_confidence'), 'OpenClash fake-ip warning is required');
assert(!openclashFakeIpHealth.warnings.includes('unsafe_attach'), 'OpenClash fake-ip must not mark LAN-edge BPF unsafe by itself');
assert(openclashFakeIpHealth.evidence.openclash.primary_bpf_policy === 'do_not_disable_lan_edge_bpf_when_openclash_is_present', 'OpenClash evidence must preserve primary BPF policy');
assert(openclashFakeIpHealth.evidence.openclash.remote_identity_policy.includes('metadata only'), 'fake-ip remote identity policy must be explicit');
assert(openclashFakeIpHealth.evidence.collector.conntrack_fallback_model.confidence === 'unsupported', 'non-NSS CT speed fallback remains unsupported when BPF runtime gate is unavailable');

assert(openclashRouterSelfHealth.mode === 'Degraded', 'OpenClash router-self fixture should degrade when BPF object is unavailable');
assert(openclashRouterSelfHealth.confidence === 'medium', 'OpenClash router-self/TUN/DNS mismatch must not lower live-rate confidence through non-NSS CT speed fallback');
assert(openclashRouterSelfHealth.capabilities.openclash_tun_mix === true, 'OpenClash TUN/mix capability is required');
assert(openclashRouterSelfHealth.capabilities.openclash_router_self_proxy === true, 'router_self_proxy capability is required');
assert(openclashRouterSelfHealth.capabilities.openclash_dns_chain_complete === false, 'DNS mismatch must be represented as incomplete chain');
assert(openclashRouterSelfHealth.warnings.includes('openclash_tun_conntrack_low_confidence'), 'OpenClash TUN warning is required');
assert(openclashRouterSelfHealth.warnings.includes('openclash_dns_chain_incomplete'), 'OpenClash DNS chain warning is required');
assert(openclashRouterSelfHealth.warnings.includes('openclash_router_self_proxy_detected'), 'router self proxy warning is required');
assert(openclashRouterSelfHealth.evidence.collector.conntrack_fallback_model.router_self.client_attribution === 'never_attribute_to_lan_client', 'router-self traffic must not be attributed to LAN clients');
assert(openclashRouterSelfHealth.evidence.collector.router_self_model.bucket === 'router_self', 'router-self bucket must be represented consistently');

assert(daeTcPreserveHealth.mode === 'Degraded', 'dae tc coexistence must still degrade without runtime BPF attach/map-read');
assert(daeTcPreserveHealth.capabilities.dae === true, 'dae preserve fixture must detect dae/daed');
assert(daeTcPreserveHealth.warnings.includes('dae_detected'), 'dae preserve fixture must include dae_detected warning');
assert(daeTcPreserveHealth.warnings.includes('dae_tc_preempts_bpf_ingress'), 'dae preserve fixture must warn when daed runs before lanspeed ingress');
assert(daeTcPreserveHealth.evidence.collector.tc_filter.dae_preempts_bpf_ingress === true, 'dae preserve fixture must expose tc preemption evidence');
assert(daeTcPreserveHealth.evidence.collector.conntrack_fallback_model.active === false, 'dae tc preemption must not activate non-NSS CT speed fallback');
assert(daeTcPreserveHealth.evidence.collector.conntrack_fallback_model.primary_source === 'unsupported', 'dae tc preemption must not select CT as non-NSS speed primary source');
assert(!daeTcPreserveHealth.warnings.includes('tc_filter_conflict'), 'dae preserve fixture must not warn conflict without pref/handle collision');
assert(daeTcPreserveHealth.evidence.dae.dae0 === true && daeTcPreserveHealth.evidence.dae.dae0peer === true, 'dae interfaces must be represented as evidence');
assert(daeTcPreserveHealth.evidence.dae.fwmark_detected === true, 'dae fwmark 0x8000000 evidence is required');
assert(daeTcPreserveHealth.evidence.dae.route_table_detected === true, 'dae route table 2023 evidence is required');
assert(daeTcPreserveHealth.evidence.dae.dns_udp53_detected === true, 'dae deterministic DNS/UDP53 evidence is required when fixture provides it');
assert(daeTcPreserveHealth.evidence.collector.tc_filter.existing_filters.length === 3, 'dae existing tc filters must be recorded');
assert(daeTcPreserveHealth.evidence.collector.tc_filter.existing_filters.every((filter) => filter.interface && filter.pref && filter.handle && filter.owner), 'dae tc filter evidence must include interface/pref/handle/owner');
assert(daeTcPreserveHealth.evidence.collector.tc_filter.delete_existing === false, 'dae tc coexistence must not delete existing filters');
assert(daeTcPreserveHealth.evidence.collector.tc_filter.reorder_existing === false, 'dae tc coexistence must not reorder existing filters');

assert(daeTcConflictHealth.mode !== 'Full', 'tc pref/handle conflict must not claim Full');
assert(daeTcConflictHealth.warnings.includes('tc_filter_conflict'), 'tc conflict fixture must include stable tc_filter_conflict warning');
assert(daeTcConflictHealth.evidence.collector.tc_filter.conflict === true, 'tc conflict evidence must mark conflict=true');
assert(daeTcConflictHealth.conflicts.some((conflict) => conflict.id === 'tc_filter_conflict'), 'tc conflict must be included in conflicts');

writeEvidence('task-4-health-base.json', baseHealth);
writeEvidence('task-9-software-offload.json', softwareFlowOffloadHealth);
writeEvidence('task-4-health-missing-tc.json', missingTcHealth);
writeEvidence('task-4-health-hardware-flow-offload.json', hardwareFlowOffloadHealth);
writeEvidence('task-9-hardware-offload.json', hardwareFlowOffloadHealth);
writeEvidence('task-4-health-probe-error.json', probeErrorHealth);
writeEvidence('task-8-health-flowtable-missing-nlbwmon.json', flowtableMissingNlbwmonHealth);
writeEvidence('task-8-health-acct-disabled.json', conntrackAcctDisabledHealth);
writeEvidence('task-10-openclash-fakeip.json', openclashFakeIpHealth);
writeEvidence('task-10-router-self.json', openclashRouterSelfHealth);
writeEvidence('task-11-dae-tc-preserve.txt', {
  dae_tc_preserve: daeTcPreserveHealth,
  dae_tc_conflict: daeTcConflictHealth
});

console.log('lanspeed probe validation passed');
