#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
manifest="$repo_root/net/lanspeedd/rust/Cargo.toml"
mode=${1:-${RUST_COMPAT_MODE:-}}
expected=${RUST_COMPAT_EXPECTED:-}
deep_ebpf=${RUST_COMPAT_DEEP_EBPF:-0}
live_conntrack=${RUST_COMPAT_LIVE_CONNTRACK:-0}

usage() {
	printf 'usage: RUST_COMPAT_EXPECTED=<version|stable> %s {success|below-msrv}\n' "$0" >&2
}

fail() {
	printf 'rust compatibility: FAIL: %s\n' "$*" >&2
	exit 1
}

resolve_executable() {
	local requested=$1
	local resolved

	resolved=$(command -v -- "$requested" 2>/dev/null) || return 1
	if [[ $resolved != /* ]]; then
		resolved=$(CDPATH= cd -- "$(dirname -- "$resolved")" && pwd -P)/$(basename -- "$resolved")
	fi
	printf '%s\n' "$resolved"
}

case "$mode" in
	success|below-msrv) ;;
	*)
		usage
		exit 2
		;;
esac

[[ -n $expected ]] || fail 'RUST_COMPAT_EXPECTED is required'
[[ $deep_ebpf == 0 || $deep_ebpf == 1 ]] || fail 'RUST_COMPAT_DEEP_EBPF must be 0 or 1'
[[ $live_conntrack == 0 || $live_conntrack == 1 ]] || fail 'RUST_COMPAT_LIVE_CONNTRACK must be 0 or 1'

cargo_request=${RUST_COMPAT_CARGO:-${CARGO:-cargo}}
rustc_request=${RUST_COMPAT_RUSTC:-${RUSTC:-rustc}}
cargo_bin=$(resolve_executable "$cargo_request") || fail "cargo executable not found: $cargo_request"
rustc_bin=$(resolve_executable "$rustc_request") || fail "rustc executable not found: $rustc_request"

rustc_release=$(
	"$rustc_bin" -vV | sed -n 's/^release: //p'
)
cargo_release=$(
	"$cargo_bin" --version | awk 'NR == 1 { print $2 }'
)

[[ $rustc_release =~ ^1\.[0-9]+\.[0-9]+$ ]] || fail "rustc must be a stable release, found $rustc_release"
[[ $cargo_release == "$rustc_release" ]] || fail "cargo $cargo_release is not paired with rustc $rustc_release"
if [[ $expected != stable && $rustc_release != "$expected" ]]; then
	fail "expected Rust $expected, found $rustc_release"
fi

temporary_target=0
if [[ -z ${CARGO_TARGET_DIR:-} ]]; then
	CARGO_TARGET_DIR=$(mktemp -d "${TMPDIR:-/tmp}/lanspeed-rust-compat.XXXXXX")
	temporary_target=1
else
	mkdir -p -- "$CARGO_TARGET_DIR"
	CARGO_TARGET_DIR=$(CDPATH= cd -- "$CARGO_TARGET_DIR" && pwd -P)
fi
export CARGO_TARGET_DIR

cleanup() {
	if [[ $temporary_target == 1 ]]; then
		rm -rf -- "$CARGO_TARGET_DIR"
	fi
}
trap cleanup EXIT HUP INT TERM

toolchain_path="$(dirname -- "$cargo_bin"):$(dirname -- "$rustc_bin"):$PATH"

run_cargo() {
	env \
		PATH="$toolchain_path" \
		CARGO="$cargo_bin" \
		RUSTC="$rustc_bin" \
		CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
		CARGO_TERM_COLOR=never \
		"$cargo_bin" "$@"
}

printf 'Rust compatibility target: rustc=%s cargo=%s mode=%s target=%s\n' \
	"$rustc_release" "$cargo_release" "$mode" "$CARGO_TARGET_DIR"

if [[ $mode == below-msrv ]]; then
	log="$CARGO_TARGET_DIR/below-msrv.log"
	set +e
	run_cargo check \
		--manifest-path "$manifest" \
		--workspace --features lanspeedd/openwrt --locked --offline >"$log" 2>&1
	status=$?
	set -e

	[[ $status -ne 0 ]] || fail "Rust $rustc_release unexpectedly passed the MSRV check"
	grep -F 'aya@0.14.0 requires rustc 1.87.0' "$log" >/dev/null || {
		sed -n '1,160p' "$log" >&2
		fail 'failure did not identify the Aya 1.87 dependency boundary'
	}
	grep -E 'requires rustc 1\.87(\.0)?' "$log" >/dev/null || {
		sed -n '1,160p' "$log" >&2
		fail 'failure was not the declared rust-version = 1.87.0 boundary'
	}
	printf 'Rust compatibility: PASS: %s is explicitly rejected by the 1.87.0 MSRV\n' "$rustc_release"
	exit 0
fi

bpf_linker_request=${RUST_COMPAT_BPF_LINKER:-${BPF_LINKER:-bpf-linker}}
bpf_linker_bin=$(resolve_executable "$bpf_linker_request") || \
	fail "bpf-linker executable not found: $bpf_linker_request"
[[ $("$bpf_linker_bin" --version) == 'bpf-linker 0.10.3' ]] || \
	fail "expected bpf-linker 0.10.3, found $("$bpf_linker_bin" --version)"
export BPF_LINKER=$bpf_linker_bin

run_cargo run \
	--manifest-path "$manifest" \
	-p lanspeed-build --release --locked --offline -- build-ebpf

object_dir="$CARGO_TARGET_DIR/bpfel-unknown-none/release"
kfunc_object="$object_dir/lanspeed-ebpf-kfunc"
fallback_object="$object_dir/lanspeed-ebpf-fallback"
[[ -s $kfunc_object ]] || fail "missing kfunc eBPF object: $kfunc_object"
[[ -s $fallback_object ]] || fail "missing fallback eBPF object: $fallback_object"

export LANSPEED_EBPF_OBJECT=$kfunc_object
export LANSPEED_EBPF_FALLBACK_OBJECT=$fallback_object

if [[ $deep_ebpf == 1 ]]; then
	"$script_dir/validate-rust-ebpf-objects.sh" "$kfunc_object" "$fallback_object"
	run_cargo test \
		--manifest-path "$manifest" \
		-p lanspeedd --test ebpf_object_contract \
		--locked --offline -- --test-threads=1
fi

# Keep the pure ubus/uloop/uci host suite visible instead of hiding it behind
# the workspace exclusion used for the remaining user-space crates.
run_cargo test \
	--manifest-path "$manifest" \
	-p lanspeed-openwrt-sys \
	--locked --offline -- --test-threads=1

run_cargo test \
	--manifest-path "$manifest" \
	--workspace \
	--features lanspeedd/openwrt \
	--exclude lanspeed-ebpf \
	--exclude lanspeed-openwrt-sys \
	--locked --offline -- --test-threads=1

if [[ $live_conntrack == 1 && $mode == success ]]; then
	run_cargo test \
		--manifest-path "$manifest" \
		-p lanspeedd --test conntrack_contract \
		--locked --offline live_host_conntrack_netlink_dump_uses_kernel_sender_and_local_header_pid \
		-- --ignored --exact --test-threads=1
else
	printf 'Rust compatibility: live conntrack smoke not run (requires RUST_COMPAT_LIVE_CONNTRACK=1 in an isolated network namespace)\n'
fi

printf 'Rust compatibility: PASS: Rust %s completed both eBPF builds and all user-space tests\n' \
	"$rustc_release"
