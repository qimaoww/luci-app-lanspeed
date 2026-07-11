#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	printf 'usage: %s <immortalwrt-root>\n' "$0" >&2
	exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
committed="$repo_root/net/lanspeedd/rust/crates/lanspeed-openwrt-sys/src/raw.rs"
generated=$(mktemp)
trap 'rm -f "$generated"' EXIT HUP INT TERM

for config in "$repo_root/.cargo/config.toml" "$repo_root/net/lanspeedd/rust/.cargo/config.toml"; do
	grep -Fq '[target.x86_64-unknown-linux-musl]' "$config" || {
		printf 'validate-lanspeed-rust-bindings: FAIL\n  missing musl target config: %s\n' "$config" >&2
		exit 1
	}
	grep -Fq 'linker = "x86_64-openwrt-linux-musl-gcc"' "$config" || {
		printf 'validate-lanspeed-rust-bindings: FAIL\n  wrong musl linker config: %s\n' "$config" >&2
		exit 1
	}
	grep -Fq 'rustflags = ["-C", "target-feature=-crt-static"]' "$config" || {
		printf 'validate-lanspeed-rust-bindings: FAIL\n  missing dynamic musl rustflags: %s\n' "$config" >&2
		exit 1
	}
done

if [ ! -f "$committed" ]; then
	printf 'validate-lanspeed-rust-bindings: FAIL\n  committed bindings are missing: %s\n' "$committed" >&2
	exit 1
fi

"$repo_root/net/lanspeedd/rust/tools/generate-openwrt-bindings.sh" "$1" "$generated"

for forbidden in ubus_add_uloop uloop_run uloop_end uci_lookup_option_string; do
	if grep -Eq "(^|[^[:alnum:]_])${forbidden}([^[:alnum:]_]|$)" "$generated"; then
		printf 'validate-lanspeed-rust-bindings: FAIL\n  generated bindings contain header-only symbol: %s\n' "$forbidden" >&2
		exit 1
	fi
done

if ! cmp -s "$committed" "$generated"; then
	printf 'validate-lanspeed-rust-bindings: FAIL\n  raw.rs differs from bindgen 0.72.1 output\n' >&2
	diff -u "$committed" "$generated" >&2 || true
	exit 1
fi

printf 'validate-lanspeed-rust-bindings: PASS\n'
