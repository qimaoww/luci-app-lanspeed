#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
EVIDENCE_DIR="$ROOT/.sisyphus/evidence"
MISSING_EVIDENCE="$EVIDENCE_DIR/task-3-missing-sdk.txt"
DRY_RUN_EVIDENCE="$EVIDENCE_DIR/task-3-sdk-dry-run.txt"
FAKE_SDK_EVIDENCE="$EVIDENCE_DIR/task-3-sdk-fake-config-dir.txt"

mkdir -p "$EVIDENCE_DIR"

if SDK_DIR=/nonexistent "$ROOT/scripts/build-sdk.sh" luci-app-lanspeed > "$MISSING_EVIDENCE" 2>&1; then
	printf '%s\n' "expected missing SDK_DIR scenario to fail" >&2
	exit 1
fi

grep -F "SDK_DIR" "$MISSING_EVIDENCE" >/dev/null
grep -F "does not exist" "$MISSING_EVIDENCE" >/dev/null
grep -F "ImmortalWrt/OpenWrt 25.12 SDK" "$MISSING_EVIDENCE" >/dev/null

if DRY_RUN=1 "$ROOT/scripts/build-sdk.sh" all >> "$MISSING_EVIDENCE" 2>&1; then
	printf '%s\n' "expected omitted SDK_DIR scenario to fail" >&2
	exit 1
fi

grep -F "SDK_DIR is required" "$MISSING_EVIDENCE" >/dev/null
grep -F "ImmortalWrt/OpenWrt 25.12 SDK" "$MISSING_EVIDENCE" >/dev/null

if SDK_DIR="$ROOT" DRY_RUN=1 "$ROOT/scripts/build-sdk.sh" all >> "$MISSING_EVIDENCE" 2>&1; then
	printf '%s\n' "expected local feed as SDK_DIR scenario to fail" >&2
	exit 1
fi

grep -F "local feed repository" "$MISSING_EVIDENCE" >/dev/null
grep -F "ImmortalWrt/OpenWrt 25.12 SDK" "$MISSING_EVIDENCE" >/dev/null

if SDK_DIR=/tmp/fake-sdk DRY_RUN=1 ENABLE_BPF=0 "$ROOT/scripts/build-sdk.sh" all > "$DRY_RUN_EVIDENCE" 2>&1; then
	printf '%s\n' "expected LuCI build without mandatory BPF to fail" >&2
	exit 1
fi
grep -F "ENABLE_BPF=0 is only supported with the lanspeedd target" "$DRY_RUN_EVIDENCE" >/dev/null

SDK_DIR=/tmp/fake-sdk DRY_RUN=1 ENABLE_BPF=0 "$ROOT/scripts/build-sdk.sh" lanspeedd > "$DRY_RUN_EVIDENCE" 2>&1
SDK_DIR=/tmp/fake-sdk DRY_RUN=1 "$ROOT/scripts/build-sdk.sh" all >> "$DRY_RUN_EVIDENCE" 2>&1
SDK_DIR=/tmp/fake-sdk DRY_RUN=1 SDK_RELEASE=23.05 "$ROOT/scripts/build-sdk.sh" all >> "$DRY_RUN_EVIDENCE" 2>&1
SDK_DIR=/tmp/fake-sdk DRY_RUN=1 SDK_RELEASE=23.05 SDK_BASE_FEED_REF=5804844cf812c07b2d66d513bec2e36e7a8270ee "$ROOT/scripts/build-sdk.sh" all >> "$DRY_RUN_EVIDENCE" 2>&1

grep -F "ImmortalWrt/OpenWrt 25.12" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "ImmortalWrt/OpenWrt 23.05" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "SDK_RELEASE: 23.05" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "SDK_BASE_FEED_REF: 5804844cf812c07b2d66d513bec2e36e7a8270ee" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "pin base feed to commit 5804844cf812c07b2d66d513bec2e36e7a8270ee" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "src-link lanspeed $ROOT" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "./scripts/feeds update -a" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "./scripts/feeds install -p lanspeed lanspeedd" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "./scripts/feeds install -p lanspeed luci-app-lanspeed" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "make defconfig" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "make package/lanspeedd/compile V=s" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "make package/luci-app-lanspeed/compile V=s" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "./scripts/feeds install -p lanspeed lanspeedd-bpf" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "select CONFIG_PACKAGE_lanspeedd=m before compiling package/lanspeedd/compile" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "disable CONFIG_PACKAGE_lanspeedd-bpf before compiling package/lanspeedd/compile" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "select CONFIG_PACKAGE_lanspeedd-bpf=m before compiling package/lanspeedd/compile" "$DRY_RUN_EVIDENCE" >/dev/null
if [ "$(grep -Fc "disable CONFIG_PACKAGE_lanspeedd-bpf before compiling package/lanspeedd/compile" "$DRY_RUN_EVIDENCE")" -lt 2 ]; then
	printf '%s\n' "explicit base-only dry-run must disable lanspeedd-bpf before feeds update and before defconfig" >&2
	exit 1
fi
if [ "$(grep -Fc "select CONFIG_PACKAGE_lanspeedd-bpf=m before compiling package/lanspeedd/compile" "$DRY_RUN_EVIDENCE")" -lt 2 ]; then
	printf '%s\n' "default dry-run must select lanspeedd-bpf before feeds update and before defconfig" >&2
	exit 1
fi
grep -F "make package/lanspeedd/compile V=s LANSPEED_BUILD_BPF=0 CONFIG_PACKAGE_lanspeedd=m CONFIG_PACKAGE_lanspeedd-bpf=" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "make package/lanspeedd/compile V=s LANSPEED_BUILD_BPF=1 CONFIG_PACKAGE_lanspeedd= CONFIG_PACKAGE_lanspeedd-bpf=m" "$DRY_RUN_EVIDENCE" >/dev/null
grep -F "make package/lanspeedd/compile V=s" "$DRY_RUN_EVIDENCE" >/dev/null
if grep -F "make package/lanspeedd-bpf/compile V=s" "$DRY_RUN_EVIDENCE" >/dev/null; then
	printf '%s\n' "lanspeedd-bpf must be selected, not compiled as an independent source package" >&2
	exit 1
fi

TMP_SDK=$(mktemp -d "${TMPDIR:-/tmp}/lanspeed-sdk.XXXXXX")
trap 'rm -rf "$TMP_SDK"' EXIT
mkdir -p "$TMP_SDK/bin" "$TMP_SDK/scripts/config"
printf '%s\n' '25.12 fake sdk' > "$TMP_SDK/version.buildinfo"
printf '%s\n' 'all:' > "$TMP_SDK/Makefile"
cat > "$TMP_SDK/scripts/feeds" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> feeds.log
EOF
chmod +x "$TMP_SDK/scripts/feeds"
cat > "$TMP_SDK/bin/make" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> make.log
EOF
chmod +x "$TMP_SDK/bin/make"

PATH="$TMP_SDK/bin:$PATH" SDK_DIR="$TMP_SDK" ENABLE_BPF=0 "$ROOT/scripts/build-sdk.sh" lanspeedd > "$FAKE_SDK_EVIDENCE" 2>&1
grep -F "defconfig" "$TMP_SDK/make.log" >/dev/null
grep -F "package/lanspeedd/compile V=s LANSPEED_BUILD_BPF=0 CONFIG_PACKAGE_lanspeedd=m CONFIG_PACKAGE_lanspeedd-bpf=" "$TMP_SDK/make.log" >/dev/null
if grep -F "package/luci-app-lanspeed/compile V=s" "$TMP_SDK/make.log" >/dev/null; then
	printf '%s\n' "base-only daemon pass must not build the LuCI package" >&2
	exit 1
fi
grep -F "CONFIG_PACKAGE_lanspeedd=m" "$TMP_SDK/.config" >/dev/null
grep -F "# CONFIG_PACKAGE_lanspeedd-bpf is not set" "$TMP_SDK/.config" >/dev/null
if grep -F "CONFIG_PACKAGE_lanspeedd-bpf=m" "$TMP_SDK/.config" >/dev/null 2>&1; then
	printf '%s\n' "fake SDK base run selected lanspeedd-bpf" >&2
	exit 1
fi
rm -f "$TMP_SDK/.config" "$TMP_SDK/make.log" "$TMP_SDK/feeds.log"

PATH="$TMP_SDK/bin:$PATH" SDK_DIR="$TMP_SDK" "$ROOT/scripts/build-sdk.sh" all > "$FAKE_SDK_EVIDENCE" 2>&1
grep -F "CONFIG_PACKAGE_lanspeedd=m" "$TMP_SDK/.config" >/dev/null
grep -F "CONFIG_PACKAGE_lanspeedd-bpf=m" "$TMP_SDK/.config" >/dev/null
grep -F "update -a" "$TMP_SDK/feeds.log" >/dev/null
grep -F "install -p lanspeed lanspeedd-bpf" "$TMP_SDK/feeds.log" >/dev/null
grep -F "defconfig" "$TMP_SDK/make.log" >/dev/null
grep -F "package/lanspeedd/compile V=s LANSPEED_BUILD_BPF=1 CONFIG_PACKAGE_lanspeedd= CONFIG_PACKAGE_lanspeedd-bpf=m" "$TMP_SDK/make.log" >/dev/null
grep -F "package/luci-app-lanspeed/compile V=s" "$TMP_SDK/make.log" >/dev/null
if grep -F "package/lanspeedd-bpf/compile V=s" "$TMP_SDK/make.log" >/dev/null; then
	printf '%s\n' "fake SDK run compiled lanspeedd-bpf independently" >&2
	exit 1
fi

rm -f "$TMP_SDK/.config" "$TMP_SDK/make.log" "$TMP_SDK/feeds.log" "$TMP_SDK/feeds.conf"
printf '%s\n' '23.05 fake sdk' > "$TMP_SDK/version.buildinfo"
cat > "$TMP_SDK/feeds.conf.default" <<'EOF'
src-git base https://github.com/immortalwrt/immortalwrt.git;openwrt-23.05
src-git packages https://github.com/immortalwrt/packages.git^668eee47c1588bfd79172c53e03ba807e5c91c22
EOF
PATH="$TMP_SDK/bin:$PATH" SDK_DIR="$TMP_SDK" SDK_RELEASE=23.05 SDK_BASE_FEED_REF=5804844cf812c07b2d66d513bec2e36e7a8270ee "$ROOT/scripts/build-sdk.sh" all > "$FAKE_SDK_EVIDENCE" 2>&1
grep -F "src-git base https://github.com/immortalwrt/immortalwrt.git^5804844cf812c07b2d66d513bec2e36e7a8270ee" "$TMP_SDK/feeds.conf" >/dev/null
grep -F "src-git packages https://github.com/immortalwrt/packages.git^668eee47c1588bfd79172c53e03ba807e5c91c22" "$TMP_SDK/feeds.conf" >/dev/null

printf '%s\n' "build-sdk validation passed"
