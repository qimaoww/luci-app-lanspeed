#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const pkgMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const srcMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/src/Makefile'), 'utf8');

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
  assertNoMatch(
    pkgMakefile,
    /^PKG_BUILD_DEPENDS:=bpf-headers$/m,
    'net/lanspeedd/Makefile must not require bpf-headers unconditionally'
  );
  assertMatch(
    pkgMakefile,
    /^PKG_BUILD_DEPENDS:=\$\(if \$\(CONFIG_PACKAGE_lanspeedd-bpf\),bpf-headers\)$/m,
    'net/lanspeedd/Makefile must tie bpf-headers to lanspeedd-bpf selection'
  );
  assertMatch(
    pkgMakefile,
    /ifneq \(\$\(CONFIG_PACKAGE_lanspeedd-bpf\),\)\s*include \$\(INCLUDE_DIR\)\/bpf\.mk\s*endif/s,
    'net/lanspeedd/Makefile must include bpf.mk only when lanspeedd-bpf is selected'
  );
  assertNoMatch(
    pkgMakefile,
    /DEPENDS:=\+libubox \+libubus \+libuci \+libblobmsg-json \+libjson-c \+libbpf \+libmnl \+kmod-nf-conntrack-netlink \+tc-tiny/,
    'base lanspeedd package must not hard-depend on libbpf'
  );
  assertNoMatch(
    pkgMakefile,
    /DEPENDS:=\+libubox \+libubus \+libuci \+libblobmsg-json \+libjson-c \+libmnl \+kmod-nf-conntrack-netlink \+PACKAGE_lanspeedd-bpf:libbpf \+PACKAGE_lanspeedd-bpf:tc-tiny/,
    'base lanspeedd package must not expose optional BPF dependencies through its own metadata'
  );
  assertMatch(
    pkgMakefile,
    /DEPENDS:=\+libubox \+libubus \+libuci \+libblobmsg-json \+libjson-c \+libmnl \+kmod-nf-conntrack-netlink/,
    'base lanspeedd package must keep only non-BPF runtime dependencies'
  );
  assertMatch(
    pkgMakefile,
    /LANSPEED_WITH_BPF="\$\(if \$\(CONFIG_PACKAGE_lanspeedd-bpf\),1,0\)"/,
    'Build/Compile must pass a conditional LANSPEED_WITH_BPF switch'
  );
  assertMatch(
    pkgMakefile,
    /\$\(PKG_BUILD_DIR\)\/linux\/kconfig\.h/,
    'BPF builds must provide a linux/kconfig.h fallback for older SDK bpf-headers'
  );
  assertMatch(
    pkgMakefile,
    /\$\(PKG_BUILD_DIR\)\/asm_goto_workaround\.h/,
    'BPF builds must provide an asm_goto_workaround.h fallback for older SDK bpf-headers'
  );
  assertMatch(
    pkgMakefile,
    /LIBS="-lubox -lubus -luci -lblobmsg_json -ljson-c -lmnl \$\(if \$\(CONFIG_PACKAGE_lanspeedd-bpf\),-lbpf,\)"/,
    'Build/Compile must only link libbpf when lanspeedd-bpf is selected'
  );
  assertMatch(
    srcMakefile,
    /^LANSPEED_WITH_BPF \?= 0$/m,
    'net/lanspeedd/src/Makefile must default LANSPEED_WITH_BPF to 0'
  );
  assertMatch(
    srcMakefile,
    /^BPF_IMPL_OBJ := lanspeed_bpf_stub\.o$/m,
    'src Makefile must default to the stub BPF runtime object'
  );
  assertMatch(
    srcMakefile,
    /^BPF_IMPL_OBJ := lanspeed_bpf\.o$/m,
    'src Makefile must switch to the real libbpf runtime object when enabled'
  );

  console.log('validate-lanspeed-packaging: PASS');
} catch (error) {
  console.error('validate-lanspeed-packaging: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
