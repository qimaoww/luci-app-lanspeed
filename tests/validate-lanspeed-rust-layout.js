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
    'net/lanspeedd/rust/crates/lanspeedd/Cargo.toml',
    'net/lanspeedd/rust/crates/lanspeed-build/Cargo.toml',
    'tests/validate-lanspeed-openwrt-compile.sh'
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

  const testRunner = fs.readFileSync(path.join(root, 'tests/run.sh'), 'utf8');
  assert(
    testRunner.includes('validate-lanspeed-openwrt-compile.sh'),
    'tests/run.sh must compile the production OpenWrt/FFI feature path when the 25.12 SDK is available'
  );
  assert(
    testRunner.includes('RUST_CARGO') && testRunner.includes('rust_cargo'),
    'tests/run.sh must select the pinned Rust cargo explicitly instead of depending on the login PATH'
  );

  console.log('validate-lanspeed-rust-layout: PASS');
} catch (error) {
  console.error('validate-lanspeed-rust-layout: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
