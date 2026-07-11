#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	printf 'usage: %s <immortalwrt-root>\n' "$0" >&2
	exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
sdk_root=$1
target_root="$sdk_root/staging_dir/target-x86_64_musl"
toolchain_root=$(find "$sdk_root/staging_dir" -maxdepth 1 -type d \
	-name 'toolchain-x86_64_gcc-*_musl' -print | LC_ALL=C sort)

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

printf 'validate-lanspeed-rust-linking: PASS\n'
