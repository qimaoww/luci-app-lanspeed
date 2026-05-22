# Contributing To LAN Speed

This project runs on small routers, weird kernels, patched OpenWrt builds, and
user networks full of offload and proxy edge cases. The standard is simple:
make the data model clear, keep runtime behavior cheap, and do not fake
precision.

## Required Reading

- `docs/ARCHITECTURE.md`
- `README.md`
- `net/lanspeedd/files/usr/share/lanspeed/schema.json`
- `tests/run.sh`

## Change Policy

Every change must answer four questions:

- What data model or ubus contract does this change?
- What runtime path does this affect?
- What compatibility case could this break?
- What test or fixture proves the behavior?

If you cannot answer those questions, the change is not ready.

## C Daemon Rules

Keep C code direct and explicit.

- Prefer small structs with clear ownership over huge state bags.
- Keep parsing, probing, collection, and serialization in separate modules.
- Do not add new responsibilities to `lanspeedd.c` unless the change is part of
  a planned extraction.
- Use `snprintf` and bounded arrays consistently.
- Check return values from syscalls, libmnl, libubus, libuci, libbpf, and json-c
  allocation paths where failure changes behavior.
- Use monotonic time for sample deltas.
- Treat counter rollback as a state, not as a negative rate.

### JSON Ownership

json-c ownership must be obvious from the code.

- If a function returns a new `json_object *`, the caller owns it.
- If a function attaches an object to a parent, document whether ownership moved
  or whether `json_object_get()` was used.
- Do not partially free struct-owned json-c members after transferring some of
  them. Set transferred pointers to `NULL` or use a single cleanup function that
  understands ownership.
- Do not store borrowed `json_object *` pointers beyond the lifetime of the
  parent.

### Shell Commands

Shell commands are a last resort.

- No `popen()`, `system()`, `pidof`, `tc`, `ubus`, or other shell command in
  periodic sampling paths.
- Prefer netlink, libubus, libuci, libbpf, procfs, sysfs, or debugfs reads.
- If a shell probe remains necessary, run it on startup, config reload, or a
  documented explicit diagnostic recovery path. Normal `status`, `clients`, and
  `overview` responses must not run shell commands.
- Shell command strings must never include unvalidated user-controlled
  interface names.

### Error Handling

- Return explicit status codes or booleans with evidence.
- Preserve `errno` when reporting syscall failures.
- Emit warnings for degraded collector behavior.
- Do not hide parser failures. Count malformed entries and expose the count in
  evidence when it can affect user-visible data.

## BPF Rules

BPF code must stay small and verifier-friendly.

- BPF should count bytes, packets, and simple metadata only.
- Userspace calculates rates from cumulative counters.
- Do not move topology policy, collector selection, warning generation, NSS
  policy, or UI semantics into BPF.
- If parsing Ethernet payloads, handle VLAN tags and document unsupported packet
  forms.
- If parsing IPv6 L4 headers, either handle extension headers or explicitly
  mark the feature as unsupported for those packets.
- Do not label approximate BPF tuple observations as exact conntrack semantics.
  They may only be exposed as explicitly named diagnostic evidence such as
  `bpf_approx_*`.

## Conntrack Rules

- CT-Netlink is the preferred source.
- CT-Procfs is a fallback and parser behavior must be covered by fixtures.
- Non-NSS conntrack must not be used as a real-time rate source.
- TCP connection counts mean established and assured.
- UDP connection counts mean currently tracked conntrack entries.
- DNS UDP and non-DNS UDP must remain split when the source supports ports.

## NSS Rules

- NSS direct paths are read-only.
- Never write to NSS state controls to improve metrics.
- Direct ECM/PPE data may supplement NSS sync only when it has valid deltas.
- NSS sync through conntrack must publish cadence and confidence warnings.
- BPF is preferred for daed-on-NSS cases only when it is actually attached and
  producing fresh samples.

## LuCI Rules

- The frontend renders daemon contract fields. It must not duplicate collector
  selection policy.
- Formatting, sorting, filtering, and user preferences belong in helper modules.
- Do not add large blocks of new logic to the status view. Extract a helper or
  panel module when behavior is independent.
- UI labels must preserve daemon direction semantics: `tx` is client upload and
  `rx` is client download.
- New warnings or capabilities need vocabulary entries and fixture coverage.

## Contract And Compatibility

The ubus schema is a compatibility boundary.

Changing any of the following requires schema, fixture, validator, and
documentation updates:

- top-level ubus fields.
- field units.
- direction semantics.
- collector mode names.
- confidence names.
- warning names that the UI displays.
- connection-count semantics.
- coverage quality names.

Additive evidence fields are allowed when they do not change existing semantics.
Even additive fields should be documented if users or the UI rely on them.

## Tests

Run the narrowest test first, then the full relevant suite.

Common commands:

```sh
sh tests/run.sh unit
sh tests/run.sh probe-fixtures
sh tests/run.sh all
```

For JavaScript-only edits, at least run:

```sh
node --check tests/validate-lanspeed-contract.js
node --check tests/validate-lanspeed-identity.js
node --check tests/validate-lanspeed-collector.js
node --check tests/validate-lanspeed-probes.js
node --check tests/validate-lanspeed-modules.js
node tests/validate-lanspeed-contract.js
node tests/validate-lanspeed-modules.js
```

For ubus contract changes:

- Update `net/lanspeedd/files/usr/share/lanspeed/schema.json`.
- Update affected fixtures in `tests/fixtures/`.
- Update validators in `tests/`.
- Run `sh tests/run.sh unit`.

For collector semantic changes:

- Add or update a fixture that demonstrates the semantic.
- Validate edge cases: missing accounting, malformed input, counter rollback,
  absent identity, and unsupported runtime.
- Run `sh tests/run.sh probe-fixtures`.

For packaging or SDK changes:

- Update the package Makefile or scripts.
- Run `sh tests/run.sh unit`.
- Add release-version checks when version strings change.

## Refactoring Rules

Refactoring must be behavior-preserving unless the behavior change is explicit.

- Write or update tests before changing behavior.
- Move code first, change behavior second.
- Keep commits small enough to review.
- Do not rename public fields while moving code.
- Do not mix formatting churn with logic changes.
- Do not introduce a generic abstraction unless two real call sites need it.

## Git Commit Rules

Commit messages must match the existing repository style.

- Use the package prefix used by nearby history, such as `lanspeed:` or
  `lanspeedd:`.
- Use a concise Chinese summary after the prefix.
- Do not introduce unrelated English conventional-commit prefixes such as
  `refactor:` unless the repository history has already adopted that style for
  the same package.
- Version bumps, packaging fixes, and daemon changes should say what user or
  runtime behavior changed, not just that files moved.

## Pull Request Checklist

Before submitting a change, verify:

- The ubus schema still matches emitted responses.
- Fixtures cover new warnings, collector modes, or evidence relied on by the UI.
- Hot paths do not run shell commands.
- JSON ownership is clear.
- BPF changes keep verifier complexity low.
- NSS changes remain read-only.
- OpenWrt/ImmortalWrt compatibility impact is documented.
- `sh tests/run.sh unit` passes for code, contract, collector, packaging, and UI
  changes. Documentation-only changes may use `git diff --check` plus targeted
  validator runs when relevant.
