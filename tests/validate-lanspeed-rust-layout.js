#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const lanspeeddRoot = path.join(root, 'net/lanspeedd');
const vendorRoot = path.join(lanspeeddRoot, 'rust/vendor');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function collectProjectEntries(directory, entries = { sources: [], symlinks: [] }) {
  if (!fs.existsSync(directory) || path.resolve(directory) === vendorRoot) {
    return entries;
  }

  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entryPath === vendorRoot) {
      continue;
    }

    if (entry.isSymbolicLink()) {
      entries.symlinks.push(path.relative(root, entryPath));
    } else if (entry.isDirectory()) {
      collectProjectEntries(entryPath, entries);
    } else if (entry.isFile() && /\.(?:c|h)$/.test(entry.name)) {
      entries.sources.push(path.relative(root, entryPath));
    }
  }
  return entries;
}

try {
  const required = [
    'net/lanspeedd/rust/Cargo.toml',
    'net/lanspeedd/rust/Cargo.lock',
    'net/lanspeedd/rust/crates/lanspeed-common/Cargo.toml',
    'net/lanspeedd/rust/crates/lanspeed-ebpf/Cargo.toml',
    'net/lanspeedd/rust/crates/lanspeed-openwrt-sys/Cargo.toml',
    'net/lanspeedd/rust/crates/lanspeed-openwrt-sys/tests/fixtures/README.md',
    'net/lanspeedd/rust/crates/lanspeed-openwrt-sys/tests/fixtures/blobmsg-json.hex',
    'net/lanspeedd/rust/crates/lanspeed-openwrt-sys/tests/fixtures/ubus-add-object.hex',
    'net/lanspeedd/rust/crates/lanspeedd/Cargo.toml',
    'net/lanspeedd/rust/crates/lanspeed-build/Cargo.toml',
    'tests/validate-lanspeed-openwrt-compile.sh',
    'tests/validate-lanspeed-rust-linking.sh'
  ];

  for (const file of required) {
    const filePath = path.join(root, file);
    let fileStats;
    try {
      fileStats = fs.lstatSync(filePath);
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new Error(`${file} is required`);
      }
      throw error;
    }
    assert(fileStats.isFile(), `${file} must be a regular file`);
  }

  const projectEntries = collectProjectEntries(lanspeeddRoot);
  assert(
    projectEntries.symlinks.length === 0,
    `symbolic links are forbidden below net/lanspeedd: ${projectEntries.symlinks.join(', ')}`
  );
  assert(
    projectEntries.sources.length === 0,
    `project-owned C/H sources are forbidden: ${projectEntries.sources.join(', ')}`
  );

  const packageMakefile = fs.readFileSync(path.join(lanspeeddRoot, 'Makefile'), 'utf8');
  for (const legacyBuildRule of ['lanspeed_bpf_plugin.so', 'CompileBPF', 'lanspeed_tc.bpf.c']) {
    assert(
      !packageMakefile.includes(legacyBuildRule),
      `net/lanspeedd/Makefile must not reference ${legacyBuildRule}`
    );
  }

  const bpfRuntime = fs.readFileSync(
    path.join(lanspeeddRoot, 'rust/crates/lanspeedd/src/collectors/bpf/runtime.rs'),
    'utf8'
  );
  assert(
    !/\[0i8;\s*libc::IF_NAMESIZE\]/.test(bpfRuntime),
    'BPF interface-name buffers must not hard-code signed i8 for target-dependent C char'
  );
  assert(
    /\[0 as libc::c_char;\s*libc::IF_NAMESIZE\]/.test(bpfRuntime),
    'BPF interface-name buffers must use libc::c_char for aarch64 and x86_64 portability'
  );

  const codecSource = fs.readFileSync(
    path.join(lanspeeddRoot, 'rust/crates/lanspeed-openwrt-sys/src/codec.rs'),
    'utf8'
  );
  const ubusSource = fs.readFileSync(
    path.join(lanspeeddRoot, 'rust/crates/lanspeed-openwrt-sys/src/pure_ubus.rs'),
    'utf8'
  );
  const uloopSource = fs.readFileSync(
    path.join(lanspeeddRoot, 'rust/crates/lanspeed-openwrt-sys/src/pure_uloop.rs'),
    'utf8'
  );
  assert(
    codecSource.includes('json_encoding_matches_libubox_golden_fixture') &&
      codecSource.includes('integer_boundaries_match_signed_blobmsg_json_semantics'),
    'pure Rust blobmsg must retain libubox golden and signed integer-boundary tests'
  );
  for (const requiredUbusTest of [
    'add_object_frame_matches_libubus_golden_fixture',
    'backpressure_rejects_frame_without_queuing_or_leaking_pending_request',
    'disconnected_enqueue_does_not_leave_pending_request',
    'request_timeout_removes_pending_request',
    'malformed_wire_frame_closes_connection_and_notifies_loss_once'
  ]) {
    assert(
      ubusSource.includes(requiredUbusTest),
      `pure Rust ubus must retain ${requiredUbusTest}`
    );
  }
  assert(
    ubusSource.includes('fn encode_object_registration(') &&
      ubusSource.includes('fn encode_frame(') &&
      ubusSource.includes('fn wait_pending_until('),
    'pure Rust ubus must expose deterministic registration/frame encoders and deadline testing seam'
  );
  for (const requiredUloopTest of [
    'canceled_timer_stays_idle_and_can_be_rearmed',
    'timer_panic_is_returned_as_event_loop_error_and_state_resets',
    'sigusr1_callback_is_dispatched',
    'signal_panic_is_returned_as_event_loop_error'
  ]) {
    assert(
      uloopSource.includes(requiredUloopTest),
      `pure Rust event loop must retain ${requiredUloopTest}`
    );
  }

  const testRunner = fs.readFileSync(path.join(root, 'tests/run.sh'), 'utf8');
  const openwrtCompileValidator = fs.readFileSync(
    path.join(root, 'tests/validate-lanspeed-openwrt-compile.sh'),
    'utf8'
  );
  const linkingValidator = fs.readFileSync(
    path.join(root, 'tests/validate-lanspeed-rust-linking.sh'),
    'utf8'
  );
  const normalizedTestRunner = testRunner.replace(/\\\r?\n[ \t]*/g, ' ');
  const normalizedLinkingValidator = linkingValidator.replace(/\\\r?\n[ \t]*/g, ' ');
  assert(
    testRunner.includes('validate-lanspeed-openwrt-compile.sh'),
    'tests/run.sh must compile the production pure Rust OpenWrt path when the 25.12 SDK is available'
  );
  assert(
    openwrtCompileValidator.includes('--target aarch64-unknown-linux-musl') &&
      openwrtCompileValidator.includes('-Z build-std=std,panic_abort'),
    'the OpenWrt compile validator must cross-check the aarch64 musl target'
  );
  assert(
    testRunner.includes('RUST_CARGO') && testRunner.includes('rust_cargo'),
    'tests/run.sh must select the pinned Rust cargo explicitly instead of depending on the login PATH'
  );
  assert(
    /run_logged "rust-openwrt-sys-ubus" sh [^\n]*validate-lanspeed-rust-linking\.sh[^\n]*IMMORTALWRT_ROOT/.test(
      normalizedTestRunner
    ),
    'tests/run.sh must run the OpenWrt-target ubus tests as rust-openwrt-sys-ubus'
  );
  assert(
    /append_unit_evidence "coverage=[^"]*\bopenwrt_sys_ubus_tests\b/.test(testRunner),
    'tests/run.sh unit evidence coverage must include openwrt_sys_ubus_tests'
  );
  assert(
    normalizedTestRunner.includes(
      '--workspace --exclude lanspeed-ebpf --exclude lanspeed-openwrt-sys'
    ),
    'tests/run.sh must retain the workspace exclusions handled by OpenWrt-target validation'
  );
  assert(
    normalizedTestRunner.includes(
      '--locked --offline -- --test-threads=1'
    ),
    'tests/run.sh must serialize Rust workspace tests that share process-global state'
  );
  assert(
    (linkingValidator.match(/--no-run/g) || []).length === 2,
    'the OpenWrt linking validator must retain both --no-run link checks'
  );
  assert(
    /CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER=[^\n]*LANSPEED_OPENWRT_ROOTFS=[^\n]*"\$cargo" test [^\n]*--target x86_64-unknown-linux-musl [^\n]*--locked --offline/.test(
      normalizedLinkingValidator
    ),
    'the OpenWrt linking validator must run pure Rust wire tests against a real ubusd'
  );
  for (const forbidden of ['libubus', 'libubox', 'libblobmsg_json', 'libuci']) {
    assert(linkingValidator.includes(forbidden), `linking validator must reject ${forbidden}`);
  }

  console.log('validate-lanspeed-rust-layout: PASS');
} catch (error) {
  console.error('validate-lanspeed-rust-layout: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
