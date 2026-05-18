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
    /^PKG_BUILD_DEPENDS:=PACKAGE_lanspeedd-bpf:bpf-headers$/m,
    'net/lanspeedd/Makefile must tie bpf-headers to the optional BPF package in source metadata'
  );
  assertMatch(
    pkgMakefile,
    /^LANSPEED_BUILD_BPF \?= \$\(if \$\(CONFIG_PACKAGE_lanspeedd-bpf\),1,0\)$/m,
    'net/lanspeedd/Makefile must default BPF builds from lanspeedd-bpf selection'
  );
  assertMatch(
    pkgMakefile,
    /^LANSPEED_BPF_ENABLED:=\$\(filter 1,\$\(LANSPEED_BUILD_BPF\)\)$/m,
    'net/lanspeedd/Makefile must normalize the explicit BPF build switch'
  );
  assertMatch(
    pkgMakefile,
    /^PKG_BUILD_DIR:=\$\(BUILD_DIR\)\/\$\(PKG_NAME\)-\$\(PKG_VERSION\)\$\(if \$\(LANSPEED_BPF_ENABLED\),-bpf,\)$/m,
    'base and BPF builds must use separate build directories so OpenWrt stamps cannot reuse a non-BPF build for BPF packaging'
  );
  assertNoMatch(
    pkgMakefile,
    /^PKG_BUILD_DEPENDS:=\$\(if \$\(LANSPEED_BPF_ENABLED\),bpf-headers\)$/m,
    'net/lanspeedd/Makefile must not hide bpf-headers from OpenWrt package metadata'
  );
  assertMatch(
    pkgMakefile,
    /ifneq \(\$\(LANSPEED_BPF_ENABLED\),\)\s*include \$\(INCLUDE_DIR\)\/bpf\.mk\s*endif/s,
    'net/lanspeedd/Makefile must include bpf.mk only for explicit BPF builds'
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
    /DEPENDS:=\+lanspeedd \+libbpf \+tc-tiny @HAS_BPF_TOOLCHAIN \+@NEED_BPF_TOOLCHAIN/,
    'optional BPF package must carry libbpf, tc-tiny and BPF dependencies'
  );
  assertMatch(
    pkgMakefile,
    /DEPENDS:=\+libubox \+libubus \+libuci \+libblobmsg-json \+libjson-c \+libmnl \+kmod-nf-conntrack-netlink/,
    'base lanspeedd package must keep only non-BPF runtime dependencies'
  );
  assertMatch(
    pkgMakefile,
    /LANSPEED_WITH_BPF="0"/,
    'Build/Compile must keep the base daemon on the runtime wrapper so it does not depend on libbpf'
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
    /LIBS="-lubox -lubus -luci -lblobmsg_json -ljson-c -lmnl -ldl"/,
    'Build/Compile must link the base daemon only with non-BPF runtime libraries'
  );
  assertMatch(
    pkgMakefile,
    /\$\(call CompileBPF,\$\(PKG_BUILD_DIR\)\/lanspeed_tc\.bpf\.c,-I\$\(STAGING_DIR\)\/usr\/include -DKBUILD_MODNAME=\\?"lanspeed\\?"\)/,
    'BPF builds must add staged libbpf headers and KBUILD_MODNAME to the CompileBPF include path'
  );
  assertMatch(
    pkgMakefile,
    /\$\(if \$\(LANSPEED_BPF_ENABLED\),\$\(MAKE\) -C \$\(PKG_BUILD_DIR\)[\s\S]*LIBBPF_LIBS="-lbpf"[\s\S]*\n\s*plugin,:\)/,
    'BPF builds must compile the libbpf runtime as an optional plugin'
  );
  assertMatch(
    pkgMakefile,
    /\$\(INSTALL_DATA\) \$\(PKG_BUILD_DIR\)\/lanspeed_bpf_plugin\.so \$\(1\)\/usr\/lib\/lanspeed\/lanspeed_bpf_plugin\.so/,
    'lanspeedd-bpf must install the optional libbpf runtime plugin'
  );
  assertNoMatch(
    pkgMakefile,
    /\$\(error\s+[^)]*lanspeedd-bpf/s,
    'optional BPF packaging must not use make-time errors because OpenWrt expands install rules while creating package metadata'
  );
  assertMatch(
    srcMakefile,
    /^LANSPEED_WITH_BPF \?= 0$/m,
    'net/lanspeedd/src/Makefile must default LANSPEED_WITH_BPF to 0'
  );
  assertMatch(
    srcMakefile,
    /^BPF_IMPL_OBJ := lanspeed_bpf_stub\.o$/m,
    'src Makefile must build the base daemon with the dynamic BPF runtime wrapper'
  );
  assertMatch(
    srcMakefile,
    /^plugin: lanspeed_bpf_plugin\.so$/m,
    'src Makefile must expose an explicit plugin target for the optional libbpf runtime'
  );
  assertMatch(
    srcMakefile,
    /lanspeed_bpf_plugin\.so: lanspeed_bpf\.c lanspeed_bpf\.h/,
    'src Makefile must build the optional plugin from the real libbpf loader'
  );

  console.log('validate-lanspeed-packaging: PASS');
} catch (error) {
  console.error('validate-lanspeed-packaging: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
