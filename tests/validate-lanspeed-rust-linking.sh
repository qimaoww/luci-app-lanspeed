#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	printf 'usage: %s <immortalwrt-root>\n' "$0" >&2
	exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
sdk_root=$1
target_root="$sdk_root/staging_dir/target-x86_64_musl"
cargo="$target_root/host/bin/cargo"
musl_loader="$target_root/root-x86/lib/ld-musl-x86_64.so.1"
target_library_path="$target_root/usr/lib:$target_root/root-x86/lib"
toolchain_root=$(find "$sdk_root/staging_dir" -maxdepth 1 -type d \
	-name 'toolchain-x86_64_gcc-*_musl' -print | LC_ALL=C sort)

if [ ! -x "$cargo" ]; then
	printf 'validate-lanspeed-rust-linking: FAIL\n  missing SDK cargo: %s\n' "$cargo" >&2
	exit 1
fi

if [ ! -x "$musl_loader" ]; then
	printf 'validate-lanspeed-rust-linking: FAIL\n  missing SDK musl loader: %s\n' \
		"$musl_loader" >&2
	exit 1
fi

if [ ! -d "$target_root/usr/lib" ] || [ ! -d "$target_root/root-x86/lib" ]; then
	printf 'validate-lanspeed-rust-linking: FAIL\n  missing SDK target libraries\n' >&2
	exit 1
fi

if [ -z "$toolchain_root" ] || [ "$(printf '%s\n' "$toolchain_root" | wc -l)" -ne 1 ]; then
	printf 'validate-lanspeed-rust-linking: FAIL\n  expected one x86_64 musl toolchain\n' >&2
	exit 1
fi

target_dirs=$(mktemp -d)
trap 'rm -rf "$target_dirs"' EXIT HUP INT TERM

unset OPENWRT_STAGING_LIB STAGING_DIR
PATH="$toolchain_root/bin:$target_root/host/bin:$PATH"
export PATH

(
	cd "$repo_root"
	CARGO_TARGET_DIR="$target_dirs/repo-root" cargo test \
		--manifest-path net/lanspeedd/rust/Cargo.toml \
		-p lanspeed-openwrt-sys --no-run \
		--target x86_64-unknown-linux-musl --locked --offline
)

(
	cd "$repo_root/net/lanspeedd/rust"
	CARGO_TARGET_DIR="$target_dirs/rust-dir" cargo test \
		-p lanspeed-openwrt-sys --no-run \
		--target x86_64-unknown-linux-musl --locked --offline
)

PATH="$toolchain_root/bin:$target_root/host/bin:$PATH" \
CARGO_TARGET_DIR="$target_dirs/ubus" \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="$musl_loader --library-path $target_library_path" \
"$cargo" test \
	--manifest-path "$repo_root/net/lanspeedd/rust/Cargo.toml" \
	-p lanspeed-openwrt-sys --target x86_64-unknown-linux-musl \
	--locked --offline ubus

printf 'validate-lanspeed-rust-linking: PASS\n'
