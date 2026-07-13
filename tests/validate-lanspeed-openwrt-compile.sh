#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
SDK_ROOT=${1:-${IMMORTALWRT_ROOT:-/openwrt/immortalwrt}}
TARGET_ROOT="$SDK_ROOT/staging_dir/target-x86_64_musl"
CARGO="$TARGET_ROOT/host/bin/cargo"

if [ ! -x "$CARGO" ]; then
	printf 'missing ImmortalWrt 25.12 Rust cargo: %s\n' "$CARGO" >&2
	exit 1
fi

if [ ! -d "$TARGET_ROOT/usr/lib" ]; then
	printf 'missing ImmortalWrt target libraries: %s\n' "$TARGET_ROOT/usr/lib" >&2
	exit 1
fi

PATH="$TARGET_ROOT/host/bin:$PATH" \
OPENWRT_STAGING_LIB="$TARGET_ROOT/usr/lib" \
"$CARGO" check \
	--manifest-path "$ROOT/net/lanspeedd/rust/Cargo.toml" \
	-p lanspeedd \
	--features openwrt \
	--target x86_64-unknown-linux-musl \
	--locked \
	--offline
