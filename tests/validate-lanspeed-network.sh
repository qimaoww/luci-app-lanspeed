#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
EVIDENCE_DIR="$ROOT/.sisyphus/evidence"
EVIDENCE="$EVIDENCE_DIR/task-15-network-cleanup.txt"
PREFIX="lanspeedtest"
BRIDGE="${PREFIX}br"
VETH_A="${PREFIX}a"
VETH_B="${PREFIX}b"
CREATED=0

mkdir -p "$EVIDENCE_DIR"

write_evidence() {
	printf '%s\n' "$*" >> "$EVIDENCE"
}

reset_evidence() {
	{
		printf '%s\n' "Task 15 network cleanup evidence"
		printf '%s\n' "started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		printf '%s\n' "prefix=$PREFIX"
	} > "$EVIDENCE"
}

have_command() {
	command -v "$1" >/dev/null 2>&1
}

list_stale_interfaces() {
	if ! have_command ip; then
		return 0
	fi
	ip -o link show 2>/dev/null | while IFS= read -r line; do
		name=${line#*: }
		name=${name%%:*}
		name=${name%%@*}
		case "$name" in
			${PREFIX}*) printf '%s\n' "$name" ;;
		esac
	done
}

cleanup() {
	if have_command tc && have_command ip; then
		tc qdisc del dev "$VETH_A" clsact >/dev/null 2>&1 || true
	fi
	if have_command ip; then
		ip link set "$VETH_A" nomaster >/dev/null 2>&1 || true
		ip link set "$VETH_B" nomaster >/dev/null 2>&1 || true
		ip link del "$VETH_A" >/dev/null 2>&1 || true
		ip link del "$BRIDGE" >/dev/null 2>&1 || true
	fi
}

finish() {
	status=$?
	if [ "$CREATED" -eq 1 ]; then
		cleanup
	fi
	stale=$(list_stale_interfaces | tr '\n' ' ')
	if [ -n "$stale" ]; then
		write_evidence "cleanup=FAIL stale_interfaces=$stale"
		printf '%s\n' "FAIL network cleanup stale_interfaces=$stale evidence=$EVIDENCE" >&2
		exit 1
	fi
	write_evidence "cleanup=PASS stale_interfaces=none"
	write_evidence "finished=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	if [ "$status" -eq 0 ]; then
		printf '%s\n' "network validation completed; evidence: $EVIDENCE"
	fi
	exit "$status"
}

skip() {
	reason=$1
	write_evidence "result=SKIP"
	write_evidence "reason=$reason"
	if [ "$CREATED" -eq 1 ]; then
		write_evidence "cleanup=DEFERRED_TO_TRAP"
	else
		stale=$(list_stale_interfaces | tr '\n' ' ')
		if [ -n "$stale" ]; then
			write_evidence "cleanup=FAIL stale_interfaces=$stale"
			printf '%s\n' "FAIL network cleanup stale_interfaces=$stale evidence=$EVIDENCE" >&2
			exit 1
		fi
		write_evidence "cleanup=PASS stale_interfaces=none"
	fi
	write_evidence "finished=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	printf '%s\n' "SKIP network validation: $reason evidence=$EVIDENCE"
	exit 0
}

reset_evidence

if [ "$(id -u)" != "0" ]; then
	skip "requires root privileges to create bridge/veth/qdisc"
fi
if ! have_command ip; then
	skip "ip command is unavailable"
fi
if ! have_command tc; then
	skip "tc command is unavailable"
fi

preexisting=$(list_stale_interfaces | tr '\n' ' ')
if [ -n "$preexisting" ]; then
	write_evidence "result=FAIL"
	write_evidence "reason=preexisting stale test interfaces: $preexisting"
	printf '%s\n' "FAIL network validation: preexisting stale test interfaces: $preexisting evidence=$EVIDENCE" >&2
	exit 1
fi

trap finish EXIT INT TERM

if ! ip link add "$BRIDGE" type bridge >> "$EVIDENCE" 2>&1; then
	skip "kernel or capability does not allow creating a test bridge"
fi
CREATED=1

if ! ip link add "$VETH_A" type veth peer name "$VETH_B" >> "$EVIDENCE" 2>&1; then
	skip "kernel or capability does not allow creating a veth pair"
fi

if ! ip link set "$VETH_A" master "$BRIDGE" >> "$EVIDENCE" 2>&1; then
	skip "kernel or capability does not allow enslaving veth to bridge"
fi
if ! ip link set "$BRIDGE" up >> "$EVIDENCE" 2>&1; then
	skip "kernel or capability does not allow bringing bridge up"
fi
if ! ip link set "$VETH_A" up >> "$EVIDENCE" 2>&1; then
	skip "kernel or capability does not allow bringing veth up"
fi
if ! ip link set "$VETH_B" up >> "$EVIDENCE" 2>&1; then
	skip "kernel or capability does not allow bringing peer veth up"
fi
if ! tc qdisc add dev "$VETH_A" clsact >> "$EVIDENCE" 2>&1; then
	skip "kernel or capability does not allow clsact qdisc"
fi

write_evidence "result=PASS"
write_evidence "created_interfaces=$BRIDGE $VETH_A $VETH_B"
write_evidence "created_qdisc=$VETH_A clsact"
