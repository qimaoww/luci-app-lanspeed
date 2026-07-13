#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
EVIDENCE_DIR="$ROOT/.sisyphus/evidence"
UNIT_EVIDENCE="$EVIDENCE_DIR/task-15-unit-fixtures.txt"
LOG_DIR="$EVIDENCE_DIR/task-15-logs"
RUN_ID=$(date -u '+%Y%m%dT%H%M%SZ')-$$
IMMORTALWRT_ROOT=${IMMORTALWRT_ROOT:-/openwrt/immortalwrt}
rust_cargo=${RUST_CARGO:-}

if [ -z "$rust_cargo" ]; then
	if [ -x "$IMMORTALWRT_ROOT/staging_dir/target-x86_64_musl/host/bin/cargo" ]; then
		rust_cargo="$IMMORTALWRT_ROOT/staging_dir/target-x86_64_musl/host/bin/cargo"
	else
		rust_cargo=cargo
	fi
fi

rust_cargo_path=$(command -v "$rust_cargo")
rust_toolchain_bin=$(dirname "$rust_cargo_path")
rustc_bin=${RUSTC:-$rust_toolchain_bin/rustc}

if [ ! -x "$rustc_bin" ]; then
	printf 'missing rustc paired with cargo: %s\n' "$rustc_bin" >&2
	exit 1
fi

cd "$ROOT"

mkdir -p "$EVIDENCE_DIR" "$LOG_DIR"

usage() {
	cat <<EOF
Usage: $0 {unit|probe-fixtures|network|all}

Subcommands:
  unit            Run syntax checks, Rust backend contracts, fixtures, and build-sdk validations.
  probe-fixtures  Run fixture validators covering OpenClash, dae, QoS/IFB, offload, and conntrack fallback.
  network         Run a defensive VM/veth cleanup check, or write explicit SKIP evidence.
  all             Run unit, probe-fixtures, and network.
EOF
}

append_unit_evidence() {
	printf '%s\n' "$*" >> "$UNIT_EVIDENCE"
}

reset_unit_evidence() {
	{
		printf '%s\n' "Task 15 unit/probe fixture regression evidence"
		printf '%s\n' "root=$ROOT"
		printf '%s\n' "log_dir=$LOG_DIR"
		printf '%s\n' "run_id=$RUN_ID"
		printf '%s\n' "started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		printf '%s\n' ""
	} > "$UNIT_EVIDENCE"
}

ensure_unit_evidence() {
	if [ -f "$UNIT_EVIDENCE" ]; then
		return 0
	fi

	{
		printf '%s\n' "Task 15 unit/probe fixture regression evidence"
		printf '%s\n' "root=$ROOT"
		printf '%s\n' "log_dir=$LOG_DIR"
		printf '%s\n' "run_id=$RUN_ID"
		printf '%s\n' "started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		printf '%s\n' "unit_section=not_run_before_probe_fixtures"
		printf '%s\n' ""
	} > "$UNIT_EVIDENCE"
}

run_logged() {
	scenario=$1
	shift
	log_file="$LOG_DIR/${scenario}.log"

	printf '%s\n' "RUN $scenario: $*"
	append_unit_evidence "RUN $scenario: $*"
	if "$@" > "$log_file" 2>&1; then
		printf '%s\n' "PASS $scenario (log: $log_file)"
		append_unit_evidence "PASS $scenario log=$log_file"
		return 0
	else
		status=$?
		printf '%s\n' "FAIL $scenario exit=$status log=$log_file" >&2
		append_unit_evidence "FAIL $scenario exit=$status log=$log_file"
		if [ -s "$log_file" ]; then
			printf '%s\n' "--- $scenario output ---" >&2
			sed 's/^/  /' "$log_file" >&2
		fi
		return "$status"
	fi
}

run_node_check() {
	for validator in \
		"$SCRIPT_DIR/validate-lanspeed-rust-layout.js" \
		"$SCRIPT_DIR/validate-lanspeed-contract.js" \
		"$SCRIPT_DIR/validate-lanspeed-identity.js" \
		"$SCRIPT_DIR/validate-lanspeed-collector.js" \
		"$SCRIPT_DIR/validate-lanspeed-probes.js" \
		"$SCRIPT_DIR/validate-lanspeed-packaging.js" \
		"$SCRIPT_DIR/validate-lanspeed-ubus-lifecycle.js" \
		"$SCRIPT_DIR/validate-release-version.js" \
		"$SCRIPT_DIR/validate-lanspeed-modules.js"; do
		name=$(basename "$validator" .js)
		run_logged "node-check-$name" node --check "$validator" || return $?
	done
}

resolve_bpf_linker() {
	if [ -n "${BPF_LINKER:-}" ]; then
		candidate=$(command -v "$BPF_LINKER" 2>/dev/null || true)
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			printf '%s\n' "$candidate"
			return 0
		fi
	fi

	candidate=$(command -v bpf-linker 2>/dev/null || true)
	if [ -n "$candidate" ] && [ -x "$candidate" ]; then
		printf '%s\n' "$candidate"
		return 0
	fi

	candidate=$(find "$IMMORTALWRT_ROOT/build_dir" -type f \
		-path '*/host-tools/bin/bpf-linker' -perm -u+x -print 2>/dev/null \
		| sort | head -n 1)
	if [ -n "$candidate" ]; then
		printf '%s\n' "$candidate"
		return 0
	fi

	archive="$IMMORTALWRT_ROOT/dl/bpf-linker-0.10.3-x86_64-unknown-linux-musl.tar.gz"
	expected=0fa4645d2dfbb5cafe6231b0aa9fad4f1430bd0871e3bd7319e82d827bf6262c
	if [ ! -f "$archive" ]; then
		printf 'missing pinned bpf-linker archive: %s\n' "$archive" >&2
		return 1
	fi
	actual=$(sha256sum "$archive" | awk '{print $1}')
	if [ "$actual" != "$expected" ]; then
		printf 'bpf-linker archive hash mismatch: expected %s, found %s\n' \
			"$expected" "$actual" >&2
		return 1
	fi

	tool_dir="$ROOT/net/lanspeedd/rust/target/test-tools/bpf-linker-0.10.3"
	mkdir -p "$tool_dir"
	tar -C "$tool_dir" -xzf "$archive"
	candidate=$(find "$tool_dir" -type f -name bpf-linker -perm -u+x -print | head -n 1)
	if [ -z "$candidate" ]; then
		printf 'pinned archive did not contain an executable bpf-linker\n' >&2
		return 1
	fi
	printf '%s\n' "$candidate"
}

build_ebpf_objects() {
	bpf_linker_path=$(resolve_bpf_linker) || return $?
	env \
		PATH="$rust_toolchain_bin:$PATH" \
		RUSTC="$rustc_bin" \
		CARGO="$rust_cargo_path" \
		BPF_LINKER="$bpf_linker_path" \
		"$rust_cargo_path" run \
		--manifest-path "$ROOT/net/lanspeedd/rust/Cargo.toml" \
		-p lanspeed-build --release --locked --offline -- build-ebpf
}

run_unit() {
	reset_unit_evidence
	append_unit_evidence "BEGIN unit run_id=$RUN_ID"
	append_unit_evidence "command=unit"
	append_unit_evidence "scenarios=node syntax, Rust backend contracts, fixtures, packaging, lanspeed modules, build-sdk"
	run_node_check || return $?
	run_logged "rust-layout" node "$SCRIPT_DIR/validate-lanspeed-rust-layout.js" || return $?
	append_unit_evidence "rust_cargo=$rust_cargo_path"
	append_unit_evidence "rustc=$rustc_bin"
	run_logged "rust-ebpf-objects" build_ebpf_objects || return $?
	run_logged "rust-workspace" env \
		PATH="$rust_toolchain_bin:$PATH" \
		RUSTC="$rustc_bin" \
		"$rust_cargo_path" test \
		--manifest-path "$ROOT/net/lanspeedd/rust/Cargo.toml" \
		--workspace --exclude lanspeed-ebpf --exclude lanspeed-openwrt-sys \
		--locked --offline || return $?
	if [ -x "$IMMORTALWRT_ROOT/staging_dir/target-x86_64_musl/host/bin/cargo" ]; then
		run_logged "rust-openwrt-compile" sh \
			"$SCRIPT_DIR/validate-lanspeed-openwrt-compile.sh" \
			"$IMMORTALWRT_ROOT" || return $?
		append_unit_evidence "openwrt_feature_ffi=compiled sdk=$IMMORTALWRT_ROOT"
	else
		append_unit_evidence "openwrt_feature_ffi=SKIP sdk_unavailable=$IMMORTALWRT_ROOT"
	fi
	run_logged "contract" node "$SCRIPT_DIR/validate-lanspeed-contract.js" || return $?
	run_logged "identity" node "$SCRIPT_DIR/validate-lanspeed-identity.js" || return $?
	run_logged "collector" node "$SCRIPT_DIR/validate-lanspeed-collector.js" || return $?
	run_logged "probes" node "$SCRIPT_DIR/validate-lanspeed-probes.js" || return $?
	run_logged "packaging" node "$SCRIPT_DIR/validate-lanspeed-packaging.js" || return $?
	run_logged "ubus-lifecycle" node "$SCRIPT_DIR/validate-lanspeed-ubus-lifecycle.js" || return $?
	run_logged "release-version" env RUST_CARGO="$rust_cargo_path" \
		node "$SCRIPT_DIR/validate-release-version.js" || return $?
	run_logged "lanspeed-modules" node "$SCRIPT_DIR/validate-lanspeed-modules.js" || return $?
	run_logged "build-sdk" sh "$SCRIPT_DIR/validate-build-sdk.sh" || return $?
	append_unit_evidence "coverage=rust_workspace openwrt_feature_ffi contract identity collector lifecycle probes lanspeed-modules build-sdk"
	append_unit_evidence "completed=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	append_unit_evidence "END unit run_id=$RUN_ID"
	printf '%s\n' "unit validations passed; evidence: $UNIT_EVIDENCE"
}

run_probe_fixtures() {
	ensure_unit_evidence
	append_unit_evidence ""
	append_unit_evidence "BEGIN probe-fixtures run_id=$RUN_ID"
	append_unit_evidence "command=probe-fixtures"
	append_unit_evidence "scenarios=OpenClash fake-ip/router-self, dae/daed tc preserve/conflict, SQM/qosify/ifb, software/hardware offload, conntrack fallback"
	run_logged "probe-fixtures-probes" node "$SCRIPT_DIR/validate-lanspeed-probes.js" || return $?
	run_logged "probe-fixtures-collector" node "$SCRIPT_DIR/validate-lanspeed-collector.js" || return $?
	append_unit_evidence "fixture_coverage=openclash_fakeip openclash_router_self dae_tc_preserve dae_tc_conflict sqm_qosify_ifb software_offload hardware_offload conntrack_nat conntrack_acct_disabled flowtable_missing_nlbwmon"
	append_unit_evidence "completed_probe_fixtures=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	append_unit_evidence "END probe-fixtures run_id=$RUN_ID"
	printf '%s\n' "probe fixture validations passed; evidence: $UNIT_EVIDENCE"
}

run_network() {
	sh "$SCRIPT_DIR/validate-lanspeed-network.sh"
}

command=${1:-}
case "$command" in
	unit)
		run_unit
		;;
	probe-fixtures)
		run_probe_fixtures
		;;
	network)
		run_network
		;;
	all)
		run_unit && run_probe_fixtures && run_network
		;;
	-h|--help|help|'')
		usage
		[ -n "$command" ]
		;;
	*)
		usage >&2
		exit 2
		;;
esac
