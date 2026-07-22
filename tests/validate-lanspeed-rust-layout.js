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
    'net/lanspeedd/rust/crates/lanspeed-ebpf/src/atomics.rs',
    'scripts/sdk-rust-identity.sh',
    'scripts/build-sdk.sh',
    'tests/validate-lanspeed-openwrt-compile.sh',
    'tests/validate-lanspeed-rust-linking.sh',
    'tests/run-rust-compat.sh',
    'tests/validate-rust-ebpf-objects.sh',
    'tests/validate-sdk-apks.sh',
    '.github/workflows/rust-compat.yml'
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
    if (file === 'scripts/sdk-rust-identity.sh') {
      assert((fileStats.mode & 0o111) !== 0, `${file} must be executable`);
    }
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
  const workspaceCargo = fs.readFileSync(path.join(lanspeeddRoot, 'rust/Cargo.toml'), 'utf8');
  const cargoLock = fs.readFileSync(path.join(lanspeeddRoot, 'rust/Cargo.lock'), 'utf8');
  const sdkIdentityScript = fs.readFileSync(path.join(root, 'scripts/sdk-rust-identity.sh'), 'utf8');
  const sdkBuildScript = fs.readFileSync(path.join(root, 'scripts/build-sdk.sh'), 'utf8');
  assert(
    /\[workspace\.package\][\s\S]*?rust-version\s*=\s*"1\.87\.0"/.test(workspaceCargo),
    'workspace rust-version must declare the measured 1.87.0 MSRV'
  );
  for (const crate of [
    'lanspeed-common',
    'lanspeed-ebpf',
    'lanspeed-openwrt-sys',
    'lanspeedd',
    'lanspeed-build'
  ]) {
    const manifest = fs.readFileSync(
      path.join(lanspeeddRoot, 'rust/crates', crate, 'Cargo.toml'),
      'utf8'
    );
    assert(
      manifest.includes('rust-version.workspace = true'),
      `${crate} must inherit the workspace rust-version`
    );
  }
  assert(
    /name = "cargo-platform"[\s\S]*?version = "0\.3\.1"/.test(cargoLock),
    'Cargo.lock must retain the audited cargo-platform 0.3.1 dependency'
  );
  const atomicsSource = fs.readFileSync(
    path.join(lanspeeddRoot, 'rust/crates/lanspeed-ebpf/src/atomics.rs'),
    'utf8'
  );
  for (const marker of [
    'rustversion::before(1.89)',
    'rustversion::before(1.91)',
    'rustversion::since(1.91)',
    'atomic_xadd_relaxed',
    'AtomicOrdering::Relaxed'
  ]) {
    assert(atomicsSource.includes(marker), `eBPF atomic compatibility layer must retain ${marker}`);
  }
  assert(
    sdkIdentityScript.includes('usage: $0 <pin|measure>') &&
      sdkIdentityScript.includes("./scripts/feeds list -s -d '|'") &&
      sdkIdentityScript.includes('must use a ^commit pin; branch sources are not reusable') &&
      sdkIdentityScript.includes('[ "$configured_revision" = "$feed_revision" ]'),
    'SDK identity must measure real feed heads and accept only matching caret commit pins'
  );
  const measureFunction = sdkIdentityScript.slice(
    sdkIdentityScript.indexOf('measure_identity()'),
    sdkIdentityScript.indexOf('pin_feeds()')
  );
  assert(
    measureFunction.includes('read_feed_listing 0') && !measureFunction.includes('read_feed_listing 1'),
    'SDK identity measurement must remain caret-only after feed preparation'
  );
  const verifyFunction = sdkBuildScript.slice(
    sdkBuildScript.indexOf('verify_prepared_feeds()'),
    sdkBuildScript.indexOf('configure_packages()')
  );
  assert(
    verifyFunction.includes('measure_sdk_identity') &&
      sdkBuildScript.includes('update_and_pin_sdk_feeds') &&
      sdkBuildScript.indexOf('verify_prepared_feeds') < sdkBuildScript.indexOf('compile_package'),
    'SDK builds must remeasure feed and Rust identity before compiling or reusing cached tools'
  );
  for (const legacyBuildRule of ['lanspeed_bpf_plugin.so', 'CompileBPF', 'lanspeed_tc.bpf.c']) {
    assert(
      !packageMakefile.includes(legacyBuildRule),
      `net/lanspeedd/Makefile must not reference ${legacyBuildRule}`
    );
  }
  assert(
    /\[profile\.release\][\s\S]*?panic\s*=\s*"unwind"/.test(workspaceCargo),
    'production userspace must retain unwinding so callback panic guards remain effective'
  );
  assert(
    packageMakefile.includes('CARGO_PROFILE_RELEASE_PANIC=abort'),
    'the no_std eBPF build must override the userspace unwind profile with panic=abort'
  );

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
  const uciSource = fs.readFileSync(
    path.join(lanspeeddRoot, 'rust/crates/lanspeed-openwrt-sys/src/pure_uci.rs'),
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
    'malformed_wire_frame_closes_connection_and_notifies_loss_once',
    'invoke_without_data_returns_invalid_argument_without_dropping_connection',
    'fragmented_frame_is_retained_until_complete',
    'large_frame_crosses_read_byte_budget_without_disconnect',
    'frame_budget_yields_and_buffered_work_runs_without_new_readiness',
    'continuous_small_frames_exceed_receive_limit_without_false_disconnect',
    'receive_limit_ignores_consumed_prefix',
    'hup_after_frame_budget_drains_buffer_before_notifying_loss'
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
  assert(
    uciSource.includes('DEFAULT_CONF2DIR: &str = "/var/run/uci"') &&
      uciSource.includes('DEFAULT_SAVEDIR: &str = "/tmp/.uci"') &&
      uciSource.includes('conf2_override_and_saved_delta_match_libuci_read_semantics') &&
      uciSource.includes('non_utf8_values_match_the_former_libuci_lossy_string_contract') &&
      uciSource.includes('command_abbreviations_and_empty_arguments_match_libuci') &&
      uciSource.includes('bounded_reader_rejects_fifos_and_files_over_the_limit') &&
      uciSource.includes('multiline_delta_and_strict_single_argument_rules_match_libuci') &&
      uciSource.includes('delta_rename_allows_duplicates_and_makes_sections_named') &&
      uciSource.includes('delta_list_index_removal_matches_sscanf_prefix_semantics'),
    'pure Rust UCI must retain libuci syntax, overlay, bounded-read, delta, and legacy byte compatibility tests'
  );

  const testRunner = fs.readFileSync(path.join(root, 'tests/run.sh'), 'utf8');
  const openwrtCompileValidator = fs.readFileSync(
    path.join(root, 'tests/validate-lanspeed-openwrt-compile.sh'),
    'utf8'
  );
  const linkingValidator = fs.readFileSync(
    path.join(root, 'tests/validate-lanspeed-rust-linking.sh'),
    'utf8'
  );
  const sdkApkValidator = fs.readFileSync(
    path.join(root, 'tests/validate-sdk-apks.sh'),
    'utf8'
  );
  const compatRunner = fs.readFileSync(path.join(root, 'tests/run-rust-compat.sh'), 'utf8');
  const compatWorkflow = fs.readFileSync(path.join(root, '.github/workflows/rust-compat.yml'), 'utf8');
  const ebpfObjectValidator = fs.readFileSync(
    path.join(root, 'tests/validate-rust-ebpf-objects.sh'),
    'utf8'
  );
  const normalizedTestRunner = testRunner.replace(/\\\r?\n[ \t]*/g, ' ');
  const normalizedLinkingValidator = linkingValidator.replace(/\\\r?\n[ \t]*/g, ' ');
  assert(
    testRunner.includes('validate-lanspeed-openwrt-compile.sh'),
    'tests/run.sh must compile the production pure Rust OpenWrt path when the 25.12 SDK is available'
  );
  assert(
    /run_logged "rust-openwrt-sys-host" env[\s\S]*?-p lanspeed-openwrt-sys --locked --offline/.test(
      testRunner
    ),
    'tests/run.sh must always run the pure Rust OpenWrt host suite'
  );
  assert(
    openwrtCompileValidator.includes('--target aarch64-unknown-linux-musl') &&
      openwrtCompileValidator.includes('-Z build-std=std,panic_unwind') &&
      openwrtCompileValidator.includes('--release'),
    'the OpenWrt compile validator must cross-check the production aarch64 unwind target'
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
    normalizedTestRunner.includes('--workspace --exclude lanspeed-ebpf --exclude lanspeed-openwrt-sys') &&
      normalizedTestRunner.includes('--features lanspeedd/openwrt'),
    'tests/run.sh must retain the workspace exclusions and production feature handled by OpenWrt-target validation'
  );
  assert(
    normalizedTestRunner.includes(
      '--locked --offline -- --test-threads=1'
    ),
    'tests/run.sh must serialize Rust workspace tests that share process-global state'
  );
  assert(
    compatRunner.includes('--features lanspeedd/openwrt') &&
      compatRunner.includes('--ignored --exact') &&
      compatRunner.includes('RUST_COMPAT_LIVE_CONNTRACK'),
    'Rust compatibility runner must cover the production feature and isolate the live smoke contract'
  );
  assert(
    (compatWorkflow.match(/deep_ebpf: 1/g) || []).length === 12 &&
      compatWorkflow.includes('sudo unshare -n -- true') &&
      compatWorkflow.includes('sudo unshare -n -- env') &&
      compatWorkflow.includes('RUST_COMPAT_LIVE_CONNTRACK=1') &&
      compatWorkflow.includes('Conntrack smoke skipped') &&
      !compatWorkflow.includes('unshare -Urn'),
    'Rust compatibility CI must deeply validate every supported version, isolate live conntrack without user namespaces, and retain a capability-gated fallback'
  );
  for (let minor = 87; minor <= 96; minor += 1) {
    const version = `1.${minor}.0`;
    assert(
      compatWorkflow.includes(`toolchain: ${version}`) &&
        compatWorkflow.includes(`expected: ${version}`),
      `Rust compatibility CI must retain an exact matrix point for ${version}`
    );
  }
  assert(
    compatWorkflow.includes('toolchain: 1.97.1') &&
      compatWorkflow.includes('expected: 1.97.1'),
    'Rust compatibility CI must retain an exact matrix point for 1.97.1'
  );
  assert(
    /toolchain: stable[\s\S]*?expected: stable/.test(compatWorkflow),
    'Rust compatibility CI must retain a moving stable probe above the exact matrix'
  );
  for (const marker of [
    'Class:[[:space:]]+ELF64',
    'little endian',
    'license_size',
    '47504c00',
    '\\+= r[0-9]+'
  ]) {
    assert(ebpfObjectValidator.includes(marker), `eBPF object validator must retain ${marker}`);
  }
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
    assert(sdkApkValidator.includes(forbidden), `SDK APK validator must reject ${forbidden}`);
  }
  assert(
    sdkApkValidator.includes('apk_tool') &&
      sdkApkValidator.includes('adbdump --format json') &&
      sdkApkValidator.includes('validate-rust-ebpf-objects.sh'),
    'SDK APK validator must inspect real APK metadata and delegate the complete BPF object contract'
  );

  console.log('validate-lanspeed-rust-layout: PASS');
} catch (error) {
  console.error('validate-lanspeed-rust-layout: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
