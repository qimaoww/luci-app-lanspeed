# LAN Speed Architecture

This document defines the intended architecture for `lanspeedd` and
`luci-app-lanspeed`. It is also the refactoring target for the current code.

LAN Speed measures traffic that is visible at the LAN edge of an OpenWrt
router. It is not a full traffic accounting or audit system. Hardware offload,
switch forwarding, side routers, bridge-local forwarding, proxy tunnels, and
driver-specific paths can bypass or reshape what the CPU sees. The software must
surface those limits instead of hiding them behind fake precision.

## Source Of Truth

The ubus contract is the public API. The schema at
`net/lanspeedd/files/usr/share/lanspeed/schema.json` is the source of truth for
stable response shapes.

The daemon may expose extra evidence fields, but stable top-level fields and
documented semantics must remain backward compatible. A field rename, removed
field, changed unit, changed direction, or changed collector meaning is a
contract change and must update the schema, fixtures, validators, README, and
this document.

## Goals

- Report per-client LAN-edge upload and download rates using explicit
  `tx_bps` and `rx_bps` semantics.
- Report TCP, UDP, DNS UDP, and non-DNS UDP connection counts with a named
  collector semantic.
- Explain degraded or unsupported modes with machine-readable warnings and
  evidence.
- Preserve OpenWrt compatibility across supported releases and optional BPF
  packaging.
- Coexist with NSS, dae/daed, OpenClash, SQM/qosify/IFB, flow offload, VLAN,
  Wi-Fi, and bridge topologies without taking ownership of components that do
  not belong to LAN Speed.

## Non-Goals

- Do not claim full network accounting when traffic is not CPU-visible.
- Do not mutate NSS state to force better numbers.
- Do not destroy shared `clsact` qdiscs or filters owned by other software.
- Do not use conntrack as real-time rate source for non-NSS devices.
- Do not make the LuCI UI infer hidden collector behavior that the daemon did
  not publish.

## Core Data Model

The implementation should converge on these internal units.

### Client Identity

`client_identity` is the stable key for a LAN client observation:

- `mac`: normalized lowercase MAC address.
- `zone`: logical LAN attachment zone derived from bridge/VLAN/interface
  context.
- `identity_key`: `mac@zone`.
- `interface`: the observed LAN edge interface.
- `ips`: bounded list of IP addresses associated through ARP or neighbor data.

Client identity is a best-effort observation, not ownership proof. When an IP or
MAC cannot be tied to a LAN identity, the sample must be skipped or emitted with
explicit low-confidence evidence. Do not silently bucket unknown traffic under a
real client.

### Collector Snapshot

Each collector should produce a `collector_snapshot`:

- monotonic `sample_ms`.
- collector name and semantic name.
- zero or more client samples.
- aggregate counters.
- warnings and evidence specific to this collector run.

Collectors should not emit ubus JSON directly. They should return structured
snapshots that the ubus layer serializes.

### Client Sample

A client sample contains:

- identity fields.
- cumulative byte counters when available.
- calculated `tx_bps` and `rx_bps` when a previous compatible sample exists.
- connection counts when the active semantic supports them.
- `last_seen`, `collector_mode`, `confidence`, and warnings.

Rate math belongs near the snapshot cache for that collector. UI code must not
calculate collector semantics.

### Runtime Probe

The runtime probe describes environment capability and risk:

- installed commands and kernel features.
- configured and observed interfaces.
- BPF object/runtime state.
- NSS/ECM/PPE availability.
- OpenClash, dae/daed, SQM/qosify/IFB, flow offload, and fullcone indicators.
- warnings and conflicts.

The probe is not a collector. It must not own rate samples. It should answer:
"which collectors are possible, what can go wrong, and what should be reported
to the user?"

### Ubus Response

The ubus layer is a serializer and policy coordinator. It should:

- choose the active collector from config and probe result.
- merge connection-count data only where the semantic explicitly allows it.
- convert snapshots and probes into schema-compliant JSON.
- own json-c reference lifetimes in one place.

The ubus layer should not parse `/proc`, scan `tc`, inspect UCI packages, or
iterate BPF maps directly.

## Module Boundaries

The current monolithic daemon should be split toward these modules.

### `config`

Responsibility: read UCI, clamp values, normalize legacy options, and publish a
plain configuration struct.

Rules:

- All defaults and clamps live here.
- Legacy options are translated once.
- Runtime modules receive normalized config, not raw UCI strings.

### `identity`

Responsibility: build the LAN identity table from ARP, IPv6 neighbor netlink,
interface names, and exclusion policy.

Rules:

- Normalize MAC and IP strings at input boundaries.
- Keep identity lookup independent from BPF, conntrack, NSS, and ubus.
- Preserve confidence and skip reasons for unmatched endpoints.

### `probe`

Responsibility: inspect runtime capabilities and conflicts.

Rules:

- Prefer direct APIs and filesystem probes over shell commands.
- Shell commands are allowed only during startup, reload, or explicit diagnostic
  recovery paths. Normal `status`, `clients`, and `overview` responses must use
  cached probe data or direct APIs.
- Probe results should be cached and refreshed on daemon startup, config reload,
  explicit health/status calls, or attach-policy changes.

### `collector_bpf`

Responsibility: load BPF object, attach/detach LAN-edge filters, read BPF maps,
and produce byte-rate snapshots.

Rules:

- BPF is the primary real-time rate source for non-NSS and daed-preferred paths.
- BPF map values are cumulative counters; userspace calculates rates.
- BPF fast path should count bytes and packets. Do not expand BPF into a
  complicated policy engine.
- BPF tuple counters are diagnostic-only. They must not populate stable
  `tcp_conns` or `udp_conns` fields unless they match the same semantic as
  conntrack.

### `collector_conntrack`

Responsibility: read CT-Netlink or CT-Procfs, parse flow counters, and produce
connection-count snapshots. It may produce NSS sync rates only when the NSS sync
policy explicitly allows conntrack accounting as the source.

Rules:

- Non-NSS conntrack is not a real-time rate source.
- TCP counts are established and assured only.
- UDP counts represent currently tracked conntrack entries and must split DNS
  UDP from other UDP when available.
- CT-Netlink is preferred over procfs when both are usable.

### `collector_nss`

Responsibility: read-only NSS ECM/PPE evidence and, when supported, NSS direct
or NSS sync snapshots.

Rules:

- Do not write `defunct_all`, `flush`, `decelerate`, or any NSS state-changing
  command.
- NSS direct may overlay NSS sync only for clients with valid direct deltas.
- Missing or zero direct flows must degrade to NSS sync with explicit warnings.

### `coverage`

Responsibility: maintain daemon-side sliding-window coverage. It compares
current collector byte counters with LAN interface byte counters.

Rules:

- Coverage is diagnostic evidence, not billing-grade accounting.
- Direction semantics must remain: `tx` is client upload; `rx` is client
  download.
- Counter reset or insufficient denominator data must produce a quality state,
  not misleading percentages.

### `ubus_api`

Responsibility: expose `status`, `clients`, `overview`, `health`, `interfaces`,
and `sysdevices`.

Rules:

- JSON ownership is explicit. When an object is attached to a parent, either the
  parent owns it or the child reference is incremented intentionally.
- Every response must validate against the schema or a documented schema
  extension.
- Ubus methods should be thin. Heavy collection logic belongs to collectors.

### `frontend`

Responsibility: render daemon state through LuCI.

Rules:

- The UI displays published daemon fields. It must not invent collector policy.
- Formatting helpers may sort, filter, and format values.
- LuCI modules should stay small enough to review. Status-page shell, NSS panel,
  interface config, and pure format helpers should remain separate.

## Collector Selection Policy

The daemon chooses a rate collector and a connection collector separately.

Rate collector:

- `auto`: use BPF for ordinary devices; use NSS sync/direct policy when NSS
  hardware offload is active; prefer BPF on NSS devices when daed makes NSS
  counters misleading and BPF is usable.
- `bpf`: use BPF only.
- `nss_ecm_direct`: try NSS direct, with NSS sync fallback when direct data is
  absent or incomplete.
- `nss_conntrack_sync`: use NSS sync through conntrack accounting.

Connection collector:

- `auto`: prefer CT-Netlink, then CT-Procfs.
- `conntrack_netlink`: require CT-Netlink.
- `conntrack_procfs`: require CT-Procfs.

Collector selection must publish the effective collector and semantic in
evidence. Do not make users guess which path produced a number.

## Ubus Method Semantics

`status` reports health, capability, collector policy, warnings, evidence,
coverage, config-derived timings, and version.

`clients` reports the current client list, rates, counters, connection totals,
collector modes, confidence, and per-client warnings.

`overview` reports daemon-maintained historical samples. It should not rescan
collectors on its own.

`health` reports warnings, conflicts, capabilities, and evidence for diagnostics.

`interfaces` reports kernel netdev byte counters and derived rates for selected
or observed interfaces.

`sysdevices` reports candidate system network devices and current interface
selection state for configuration UI. It is part of the stable ubus schema.

## Refactoring Sequence

Refactor in small, testable cuts:

1. Extract schema/contract helpers and JSON ownership rules.
2. Extract config parsing into a normalized config module.
3. Extract identity table loading and endpoint lookup.
4. Extract conntrack parser and collector state.
5. Extract BPF snapshot folding from ubus response code.
6. Extract NSS direct/sync logic.
7. Reduce ubus methods to policy coordination and serialization.
8. Slim the LuCI status view after backend semantics are stable.

Do not start by rewriting everything. A full rewrite would just produce a new
large bug with a cleaner file tree.

## Design Rules

- Data structures come first. If a feature cannot be expressed as clear structs
  and state transitions, the feature is not ready.
- Prefer explicit semantic names over comments that apologize for ambiguity.
- Every degraded path must carry a warning or evidence field.
- Add abstractions only when they remove duplicated policy or isolate a real
  dependency.
- Keep hot paths boring: no shell, no repeated expensive probes, no JSON
  construction inside collectors.
- Document compatibility limits in code, schema, fixtures, and user docs
  together.
