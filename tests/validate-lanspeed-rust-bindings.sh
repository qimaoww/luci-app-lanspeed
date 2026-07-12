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

root_config="$repo_root/.cargo/config.toml"
nested_config="$repo_root/net/lanspeedd/rust/.cargo/config.toml"
grep -Fq '[target.x86_64-unknown-linux-musl]' "$root_config" || {
	printf 'validate-lanspeed-rust-bindings: FAIL\n  missing root musl target config\n' >&2
	exit 1
}
grep -Fq 'linker = "x86_64-openwrt-linux-musl-gcc"' "$root_config" || {
	printf 'validate-lanspeed-rust-bindings: FAIL\n  wrong root musl linker config\n' >&2
	exit 1
}
grep -Fq 'rustflags = ["-C", "target-feature=-crt-static"]' "$root_config" || {
	printf 'validate-lanspeed-rust-bindings: FAIL\n  missing root dynamic musl rustflags\n' >&2
	exit 1
}
if grep -Eq '^\[target\.' "$nested_config"; then
	printf 'validate-lanspeed-rust-bindings: FAIL\n  nested Cargo config duplicates target settings\n' >&2
	exit 1
fi

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
