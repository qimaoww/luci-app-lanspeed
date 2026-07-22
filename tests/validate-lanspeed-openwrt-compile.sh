#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
SDK_ROOT=${1:-${IMMORTALWRT_ROOT:-/openwrt/immortalwrt}}
TARGET_ROOT="$SDK_ROOT/staging_dir/target-x86_64_musl"
CARGO="$TARGET_ROOT/host/bin/cargo"
RUSTC="$TARGET_ROOT/host/bin/rustc"
RUST_SOURCE="$TARGET_ROOT/host/lib/rustlib/src/rust/library/Cargo.toml"

if [ ! -x "$CARGO" ]; then
	printf 'missing ImmortalWrt 25.12 Rust cargo: %s\n' "$CARGO" >&2
	exit 1
fi

if [ ! -x "$RUSTC" ]; then
	printf 'missing ImmortalWrt 25.12 rustc: %s\n' "$RUSTC" >&2
	exit 1
fi

if [ ! -f "$RUST_SOURCE" ]; then
	printf 'missing ImmortalWrt 25.12 Rust source: %s\n' "$RUST_SOURCE" >&2
	exit 1
fi

if [ ! -d "$TARGET_ROOT/usr/lib" ]; then
	printf 'missing ImmortalWrt target libraries: %s\n' "$TARGET_ROOT/usr/lib" >&2
	exit 1
fi

PATH="$TARGET_ROOT/host/bin:$PATH" \
RUSTC="$RUSTC" \
"$CARGO" check \
	--release \
	--manifest-path "$ROOT/net/lanspeedd/rust/Cargo.toml" \
	-p lanspeedd \
	--features openwrt \
	--target x86_64-unknown-linux-musl \
	--locked \
	--offline

PATH="$TARGET_ROOT/host/bin:$PATH" \
RUSTC="$RUSTC" \
RUSTC_BOOTSTRAP=1 \
"$CARGO" check \
	--release \
	-j "${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')}" \
	-Z build-std=std,panic_unwind \
	--manifest-path "$ROOT/net/lanspeedd/rust/Cargo.toml" \
	-p lanspeedd \
	--lib \
	--features openwrt \
	--target aarch64-unknown-linux-musl \
	--locked \
	--offline
