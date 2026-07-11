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

function collectProjectSources(directory) {
  if (!fs.existsSync(directory) || path.resolve(directory) === vendorRoot) {
    return [];
  }

  const sources = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      sources.push(...collectProjectSources(entryPath));
    } else if (entry.isFile() && /\.(?:c|h)$/.test(entry.name)) {
      sources.push(path.relative(root, entryPath));
    }
  }
  return sources;
}

try {
  const required = [
    'net/lanspeedd/rust/Cargo.toml',
    'net/lanspeedd/rust/Cargo.lock',
    'net/lanspeedd/rust/crates/lanspeed-common/Cargo.toml',
    'net/lanspeedd/rust/crates/lanspeed-ebpf/Cargo.toml',
    'net/lanspeedd/rust/crates/lanspeed-openwrt-sys/Cargo.toml',
    'net/lanspeedd/rust/crates/lanspeedd/Cargo.toml',
    'net/lanspeedd/rust/crates/lanspeed-build/Cargo.toml'
  ];

  for (const file of required) {
    assert(fs.existsSync(path.join(root, file)), `${file} is required`);
  }

  const projectSources = collectProjectSources(lanspeeddRoot);
  assert(
    projectSources.length === 0,
    `project-owned C/H sources are forbidden: ${projectSources.join(', ')}`
  );

  const packageMakefile = fs.readFileSync(path.join(lanspeeddRoot, 'Makefile'), 'utf8');
  for (const legacyBuildRule of ['lanspeed_bpf_plugin.so', 'CompileBPF', 'lanspeed_tc.bpf.c']) {
    assert(
      !packageMakefile.includes(legacyBuildRule),
      `net/lanspeedd/Makefile must not reference ${legacyBuildRule}`
    );
  }

  console.log('validate-lanspeed-rust-layout: PASS');
} catch (error) {
  console.error('validate-lanspeed-rust-layout: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
