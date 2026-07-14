#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const pkgMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const buildDriver = fs.readFileSync(
  path.join(root, 'net/lanspeedd/rust/crates/lanspeed-build/src/lib.rs'),
  'utf8'
);
const cargoConfig = fs.readFileSync(path.join(root, 'net/lanspeedd/rust/.cargo/config.toml'), 'utf8');
const luciMakefile = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/Makefile'), 'utf8');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertMatch(source, pattern, message) {
  assert(pattern.test(source), message);
}

function assertNoMatch(source, pattern, message) {
  assert(!pattern.test(source), message);
}

try {
  const compileMatch = /^define Build\/Compile\n([\s\S]*?)^endef$/m.exec(pkgMakefile);
  assert(compileMatch, 'net/lanspeedd/Makefile must define Build/Compile');
  const compileBody = compileMatch[1];
  const bpfConditional = compileBody.indexOf('ifneq ($(LANSPEED_BPF_ENABLED),)');
  const userspaceBuild = compileBody.indexOf('build-userspace');
  const ebpfBuild = compileBody.indexOf('build-ebpf');

  assertMatch(
    pkgMakefile,
    /^PKG_BUILD_DEPENDS:=rust\/host$/m,
    'Rust Cargo workspace build is required'
  );
  assertMatch(pkgMakefile, /^PKG_BUILD_PARALLEL:=1$/m, 'Rust package build must enable OpenWrt parallel builds');
  assertMatch(pkgMakefile, /^RUST_PKG_LOCKED:=1$/m, 'Rust package build must keep Cargo.lock immutable');
  assertMatch(
    pkgMakefile,
    /include \$\(TOPDIR\)\/feeds\/packages\/lang\/rust\/rust-package\.mk/,
    'net/lanspeedd/Makefile must use the ImmortalWrt rust-package integration'
  );
  assertMatch(
    pkgMakefile,
    /\$\(CP\) \.\/rust\/Cargo\.toml \.\/rust\/Cargo\.lock \$\(PKG_BUILD_DIR\)\//,
    'Build/Prepare must copy the Cargo workspace manifests'
  );
  for (const directory of ['.cargo', 'crates', 'vendor']) {
    assert(
      pkgMakefile.includes(`$(CP) ./rust/${directory} $(PKG_BUILD_DIR)/`),
      `Build/Prepare must copy rust/${directory}`
    );
  }
  assertNoMatch(pkgMakefile, /\.\/rust\/(?:\.\s|\*|target)/, 'Build/Prepare must not copy local Cargo target artifacts');
  assertMatch(
    pkgMakefile,
    /cd \$\(PKG_BUILD_DIR\) &&[\s\S]*cargo build -v --manifest-path Cargo\.toml -p lanspeed-build --release --target \$\(RUSTC_HOST_ARCH\) --locked --offline/,
    'Build/Compile must run the pinned host build inside PKG_BUILD_DIR so Cargo loads the vendored-source config'
  );
  assertMatch(pkgMakefile, /LANSPEED_USERSPACE_TARGET="\$\(RUSTC_TARGET_ARCH\)"/, 'userspace target must come from the SDK');
  assertMatch(pkgMakefile, /LANSPEED_VERSION="\$\(PKG_VERSION\)"/, 'Cargo build must receive PKG_VERSION');
  assertMatch(pkgMakefile, /LANSPEED_RELEASE="\$\(PKG_RELEASE\)"/, 'Cargo build must receive PKG_RELEASE');
  assertMatch(pkgMakefile, /OPENWRT_STAGING_LIB="\$\(STAGING_DIR\)\/usr\/lib"/, 'Cargo build must receive the target staging library directory');
  assertMatch(pkgMakefile, /build-userspace/, 'base package pass must invoke the userspace build driver');
  assertMatch(pkgMakefile, /build-ebpf/, 'BPF package pass must invoke the eBPF build driver');
  assert(userspaceBuild >= 0 && bpfConditional >= 0 && userspaceBuild < bpfConditional,
    'userspace must always build before the separate eBPF package step');
  assert(ebpfBuild > bpfConditional, 'eBPF build must be conditional and additive');
  assertMatch(pkgMakefile, /^\s*FILE:=bpf-linker-0\.10\.3-x86_64-unknown-linux-musl\.tar\.gz$/m, 'bpf-linker cache name must include its pinned version');
  assertMatch(pkgMakefile, /^\s*URL_FILE:=bpf-linker-x86_64-unknown-linux-musl\.tar\.gz$/m, 'bpf-linker remote archive name must remain official');
  assertMatch(
    pkgMakefile,
    /^\s*URL:=https:\/\/github\.com\/aya-rs\/bpf-linker\/releases\/download\/v0\.10\.3\/$/m,
    'bpf-linker 0.10.3 download URL must be official'
  );
  assertMatch(
    pkgMakefile,
    /^\s*HASH:=0fa4645d2dfbb5cafe6231b0aa9fad4f1430bd0871e3bd7319e82d827bf6262c$/m,
    'bpf-linker archive SHA256 must be pinned'
  );
  assertMatch(
    pkgMakefile,
    /ifneq \(\$\(LANSPEED_BPF_ENABLED\),\)\s*ifeq \(\$\(HOST_ARCH\),x86_64\)\s*\$\(eval \$\(call Download,bpf-linker\)\)\s*endif\s*endif/,
    'bpf-linker download must be registered only for BPF builds on its supported host architecture'
  );
  assertMatch(
    pkgMakefile,
    /test "\$\(HOST_ARCH\)" = "x86_64" \|\|/,
    'BPF Build/Prepare must reject unsupported build hosts without breaking package metadata expansion'
  );
  assertMatch(pkgMakefile, /BPF_LINKER="\$\(BPF_LINKER\)"/, 'eBPF build must use the extracted pinned linker');
  assert(buildDriver.includes('EXPECTED_BPF_LINKER: &str = "0.10.3"'), 'build driver must enforce bpf-linker 0.10.3');
  assert(buildDriver.includes('"--locked"') && buildDriver.includes('"--offline"'), 'build driver must use locked offline Cargo');
  assert(cargoConfig.includes('replace-with = "vendored-sources"'), 'Cargo must use vendored sources');
  assert(cargoConfig.includes('offline = true'), 'Cargo config must forbid network dependency resolution');
  assertMatch(
    pkgMakefile,
    /\$\(INSTALL_BIN\) \$\(PKG_BUILD_DIR\)\/target\/\$\(RUSTC_TARGET_ARCH\)\/release\/lanspeedd \$\(1\)\/usr\/sbin\/lanspeedd/,
    'base package must install the Rust daemon'
  );
  for (const object of ['lanspeed-ebpf-kfunc', 'lanspeed-ebpf-fallback']) {
    assert(
      pkgMakefile.includes(`$(INSTALL_DATA) $(PKG_BUILD_DIR)/target/bpfel-unknown-none/release/${object} $(1)/usr/lib/bpf/${object}.o`),
      `lanspeedd-bpf must install ${object} with an .o suffix so OpenWrt does not target-strip the eBPF ELF`
    );
    assert(
      pkgMakefile.includes(`$(LN) ${object}.o $(1)/usr/lib/bpf/${object}`),
      `lanspeedd-bpf must preserve the runtime path for ${object} through a relative symlink`
    );
  }
  assertMatch(
    pkgMakefile,
    /DEPENDS:=@\(aarch64\|\|x86_64\).*\+libubox.*\+libubus.*\+libuci.*\+libblobmsg-json/,
    'base daemon must restrict its generated OpenWrt FFI bindings to verified LP64 targets'
  );
  assertNoMatch(
    pkgMakefile,
    /DEPENDS:=\$\(RUST_ARCH_DEPENDS\)/,
    'base daemon must not advertise unverified 32-bit Rust targets'
  );
  assertMatch(pkgMakefile, /define Package\/lanspeedd-bpf[\s\S]*DEPENDS:=@!BIG_ENDIAN \+lanspeedd \+tc-tiny \+kmod-sched-bpf/, 'BPF package must depend on the base daemon, tc inspection, and TC BPF kernel support');
  assertMatch(
    luciMakefile,
    /DEPENDS:=\+lanspeedd \+lanspeedd-bpf \+luci-base/,
    'LuCI package must require the daemon and BPF runtime package'
  );
  assertNoMatch(pkgMakefile, /TITLE:=Optional BPF assets/, 'BPF package must not be described as optional');
  assertNoMatch(pkgMakefile, /DEFAULT:=y if PACKAGE_luci-app-lanspeed/, 'hard LuCI dependency makes the old conditional BPF default obsolete');
  for (const resource of [
    './files/etc/init.d/lanspeedd',
    './files/etc/hotplug.d/iface/90-lanspeedd',
    './files/etc/config/lanspeed',
    './files/usr/share/lanspeed/schema.json',
    './src/collector-model.json'
  ]) {
    assert(pkgMakefile.includes(resource), `package must preserve ${resource}`);
  }
  for (const legacy of [
    'CompileBPF',
    'bpf.mk',
    'lanspeed_bpf_plugin.so',
    'lanspeed_tc.bpf.c',
    'LANSPEED_WITH_BPF',
    './src/Makefile',
    './src/*.c',
    './src/*.h',
    '+libbpf',
    '+libmnl',
    '+libjson-c',
    '+tc-bpf'
  ]) {
    assert(!pkgMakefile.includes(legacy), `Rust packaging must not retain ${legacy}`);
  }
  assertNoMatch(pkgMakefile, /\$\(error\s+[^)]*lanspeedd-bpf/s, 'BPF package metadata must remain expandable');

  [
    'configStyle.js',
    'configStyleArgon.js',
    'configStyleAurora.js',
    'configStyleBase.js',
    'configStyleBootstrap.js',
    'configStyleResponsive.js',
    'configStyleShared.js',
    'statusStyle.js',
    'statusStyleArgon.js',
    'statusStyleAurora.js',
    'statusStyleBase.js',
    'statusStyleBootstrap.js',
    'statusStyleCompat.js',
    'statusStyleCompatLive.js',
    'statusStyleCompatLive2.js',
    'statusStyleCompatLive3.js',
    'statusStyleResponsive.js',
    'statusViewLive.js',
    'statusViewLive2.js',
    'statusViewLive3.js'
  ].forEach((name) => {
    assert(
      luciMakefile.includes(`htdocs/luci-static/resources/lanspeed/${name}`),
      `luci-app-lanspeed/Makefile must install resources/lanspeed/${name}`
    );
  });

  console.log('validate-lanspeed-packaging: PASS');
} catch (error) {
  console.error('validate-lanspeed-packaging: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
