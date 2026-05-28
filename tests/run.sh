#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
EVIDENCE_DIR="$ROOT/.sisyphus/evidence"
UNIT_EVIDENCE="$EVIDENCE_DIR/task-15-unit-fixtures.txt"
LOG_DIR="$EVIDENCE_DIR/task-15-logs"
RUN_ID=$(date -u '+%Y%m%dT%H%M%SZ')-$$

mkdir -p "$EVIDENCE_DIR" "$LOG_DIR"

usage() {
	cat <<EOF
Usage: $0 {unit|probe-fixtures|network|all}

Subcommands:
  unit            Run syntax checks and contract/identity/collector/probe/build-sdk validations.
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

run_unit() {
	reset_unit_evidence
	append_unit_evidence "BEGIN unit run_id=$RUN_ID"
	append_unit_evidence "command=unit"
	append_unit_evidence "scenarios=node syntax, contract, identity, collector lifecycle, probes, lanspeed modules, build-sdk"
	run_node_check || return $?
	run_logged "contract" node "$SCRIPT_DIR/validate-lanspeed-contract.js" || return $?
	run_logged "identity" node "$SCRIPT_DIR/validate-lanspeed-identity.js" || return $?
	run_logged "collector" node "$SCRIPT_DIR/validate-lanspeed-collector.js" || return $?
	run_logged "probes" node "$SCRIPT_DIR/validate-lanspeed-probes.js" || return $?
	run_logged "packaging" node "$SCRIPT_DIR/validate-lanspeed-packaging.js" || return $?
	run_logged "ubus-lifecycle" node "$SCRIPT_DIR/validate-lanspeed-ubus-lifecycle.js" || return $?
	run_logged "release-version" node "$SCRIPT_DIR/validate-release-version.js" || return $?
	run_logged "lanspeed-modules" node "$SCRIPT_DIR/validate-lanspeed-modules.js" || return $?
	run_logged "build-sdk" sh "$SCRIPT_DIR/validate-build-sdk.sh" || return $?
	append_unit_evidence "coverage=contract identity collector lifecycle probes lanspeed-modules build-sdk"
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
