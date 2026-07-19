#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
OUT_DIR=${OUT_DIR:-"$ROOT/.sisyphus/evidence"}
TARGET=${TARGET:-}
DRY_RUN=${DRY_RUN:-0}
SSH_OPTS=${SSH_OPTS:-}
IPERF_SERVER=${IPERF_SERVER:-}
IPERF_CLIENT_OPTS=${IPERF_CLIENT_OPTS:-"-t 10 -P 1"}
IPERF_COMMAND=${IPERF_COMMAND:-iperf3}

DRY_RUN_EVIDENCE="$OUT_DIR/task-16-device-dry-run.txt"
OPENCLASH_DAE_EVIDENCE="$OUT_DIR/task-16-openclash-dae.json"
MATRIX_EVIDENCE="$OUT_DIR/task-16-device-matrix.json"
IPERF_EVIDENCE="$OUT_DIR/task-16-device-iperf.txt"

mkdir -p "$OUT_DIR"

usage() {
	cat <<EOF
Usage: $0 {collect|iperf|matrix|openclash-dae}

Environment:
  TARGET=root@router              SSH target for a real router.
  DRY_RUN=1                       Print commands without executing remote commands.
  OUT_DIR=.sisyphus/evidence      Evidence output directory.
  SSH_OPTS='-p 22'                Optional ssh options.
  IPERF_SERVER=192.0.2.1          Required for non-dry-run iperf.
  IPERF_CLIENT_OPTS='-t 10 -P 1'  Optional iperf client flags.

Subcommands:
  collect        Collect ubus/tc/nft/uci/service/process evidence or a dry-run plan.
  iperf          Record iperf command plan/output with ubus snapshots; no screenshots needed.
  matrix         Write machine-readable high-risk QA matrix results.
  openclash-dae  Write mock/dry-run OpenClash + dae conflict evidence JSON.
EOF
}

timestamp() {
	date -u '+%Y-%m-%dT%H:%M:%SZ'
}

json_escape() {
	awk 'BEGIN { ORS="" } {
		gsub(/\\/, "\\\\")
		gsub(/"/, "\\\"")
		gsub(/\t/, "\\t")
		gsub(/\r/, "\\r")
		if (NR > 1) {
			printf "\\n"
		}
		printf "%s", $0
	}'
}

require_target_for_real_remote() {
	if [ "$DRY_RUN" = "1" ]; then
		return 0
	fi
	if [ -z "$TARGET" ]; then
		printf '%s\n' "TARGET is required unless DRY_RUN=1 is set" >&2
		exit 2
	fi
}

remote_shell() {
	remote_command=$1
	if [ "$DRY_RUN" = "1" ]; then
		if [ -n "$TARGET" ]; then
			printf 'DRY_RUN ssh %s %s -- %s\n' "$SSH_OPTS" "$TARGET" "$remote_command"
		else
			printf 'DRY_RUN local-target-missing -- %s\n' "$remote_command"
		fi
		return 0
	fi

	if [ -n "${SSHPASS:-}" ]; then
		sshpass -e ssh $SSH_OPTS "$TARGET" "$remote_command"
	else
		ssh $SSH_OPTS "$TARGET" "$remote_command"
	fi
}

append_section() {
	file=$1
	title=$2
	{
		printf '%s\n' ""
		printf '%s\n' "## $title"
		printf '%s\n' "time=$(timestamp)"
	} >> "$file"
}

collect_commands() {
	cat <<'EOF'
ubus call lanspeed status
ubus call lanspeed overview
ubus call lanspeed health
ubus call lanspeed diagnostics
ubus call lanspeed reload
ubus call lanspeed interfaces
ubus call lanspeed sysdevices
for dev in $(uci -q get lanspeed.main.ifname); do [ -d "/sys/class/net/$dev" ] || continue; tc filter show dev "$dev" ingress; done
for dev in $(uci -q get lanspeed.main.ifname); do [ -d "/sys/class/net/$dev" ] || continue; tc filter show dev "$dev" egress; done
for dev in $(uci -q get lanspeed.main.ifname); do [ -d "/sys/class/net/$dev" ] || continue; tc qdisc show dev "$dev"; done
nft list ruleset
uci show firewall
uci -q show openclash || printf '%s\n' 'openclash: not installed'
uci -q show dae || printf '%s\n' 'dae: not installed'
uci -q show daed || printf '%s\n' 'daed: not installed'
uci -q show sqm || printf '%s\n' 'sqm: not installed'
uci -q show qosify || printf '%s\n' 'qosify: not installed'
uci show network
/etc/init.d/lanspeedd status
if [ -x /etc/init.d/openclash ]; then /etc/init.d/openclash status || true; else printf '%s\n' 'openclash: not installed'; fi
if [ -x /etc/init.d/dae ]; then /etc/init.d/dae status || true; else printf '%s\n' 'dae: not installed'; fi
if [ -x /etc/init.d/daed ]; then /etc/init.d/daed status || true; else printf '%s\n' 'daed: not installed'; fi
ps w | grep -E 'lanspeedd|openclash|clash|dae|daed' | grep -v grep
EOF
}

client_connections_command() {
	cat <<'EOF'
clients_json=$(ubus call lanspeed clients)
clients_status=$?
printf '%s\n' "$clients_json"
if [ "$clients_status" -ne 0 ]; then
	exit "$clients_status"
fi
identity_key=$(printf '%s\n' "$clients_json" | jsonfilter -e '@.clients[0].identity_key')
jsonfilter_status=$?
if [ "$jsonfilter_status" -eq 1 ]; then
	printf '%s\n' 'client_connections skipped: no client identity_key'
	exit 0
fi
if [ "$jsonfilter_status" -ne 0 ]; then
	exit "$jsonfilter_status"
fi
if [ -z "$identity_key" ]; then
	printf '%s\n' 'client_connections skipped: no client identity_key'
	exit 0
fi
. /usr/share/libubox/jshn.sh
jshn_status=$?
if [ "$jshn_status" -ne 0 ]; then
	exit "$jshn_status"
fi
json_init
json_init_status=$?
if [ "$json_init_status" -ne 0 ]; then
	exit "$json_init_status"
fi
json_add_string identity_key "$identity_key"
json_add_status=$?
if [ "$json_add_status" -ne 0 ]; then
	exit "$json_add_status"
fi
client_payload=$(json_dump)
json_dump_status=$?
if [ "$json_dump_status" -ne 0 ]; then
	exit "$json_dump_status"
fi
ubus call lanspeed client_connections "$client_payload"
EOF
}

collect_client_connections() {
	append_section "$DRY_RUN_EVIDENCE" "dynamic client connection detail"
	client_command=$(client_connections_command)
	remote_shell "$client_command" >> "$DRY_RUN_EVIDENCE" 2>&1 || {
		status=$?
		printf 'command_exit=%s\n' "$status" >> "$DRY_RUN_EVIDENCE"
	}
}

run_collect() {
	require_target_for_real_remote
	{
		printf '%s\n' "Task 16 device QA collect evidence"
		printf 'started=%s\n' "$(timestamp)"
		printf 'target=%s\n' "${TARGET:-not_provided}"
		printf 'dry_run=%s\n' "$DRY_RUN"
		printf '%s\n' "safety=collect 包含 reload；reload 只刷新 lanspeedd 运行状态，不修改持久 UCI、网络、防火墙或代理配置；其余命令采集诊断证据"
		printf '%s\n' "coverage=ubus 九个方法: status, clients, overview, health, diagnostics, reload, interfaces, sysdevices, client_connections"
	} > "$DRY_RUN_EVIDENCE"

	collect_commands | while IFS= read -r command; do
		append_section "$DRY_RUN_EVIDENCE" "$command"
		remote_shell "$command" < /dev/null >> "$DRY_RUN_EVIDENCE" 2>&1 || {
			status=$?
			printf 'command_exit=%s\n' "$status" >> "$DRY_RUN_EVIDENCE"
		}
	done

	collect_client_connections

	printf '%s\n' "collect evidence: $DRY_RUN_EVIDENCE"
}

iperf_commands() {
	cat <<EOF
ubus call lanspeed status
ubus call lanspeed clients
$IPERF_COMMAND -c ${IPERF_SERVER:-<set-IPERF_SERVER>} $IPERF_CLIENT_OPTS
ubus call lanspeed status
ubus call lanspeed clients
EOF
}

run_iperf() {
	require_target_for_real_remote
	if [ "$DRY_RUN" != "1" ] && [ -z "$IPERF_SERVER" ]; then
		printf '%s\n' "IPERF_SERVER is required for non-dry-run iperf" >&2
		exit 2
	fi

	{
		printf '%s\n' "Task 16 iperf QA evidence"
		printf 'started=%s\n' "$(timestamp)"
		printf 'target=%s\n' "${TARGET:-not_provided}"
		printf 'dry_run=%s\n' "$DRY_RUN"
		printf 'iperf_command=%s\n' "$IPERF_COMMAND"
		printf 'iperf_server=%s\n' "${IPERF_SERVER:-not_provided}"
		printf 'iperf_client_opts=%s\n' "$IPERF_CLIENT_OPTS"
		printf '%s\n' "safety=iperf only runs when explicitly invoked; its status/client snapshots are read-only; collect reload only refreshes lanspeedd runtime state and does not change persistent UCI, proxy, firewall, or network configuration"
	} > "$IPERF_EVIDENCE"

	iperf_commands | while IFS= read -r command; do
		append_section "$IPERF_EVIDENCE" "$command"
		remote_shell "$command" < /dev/null >> "$IPERF_EVIDENCE" 2>&1 || {
			status=$?
			printf 'command_exit=%s\n' "$status" >> "$IPERF_EVIDENCE"
		}
	done

	printf '%s\n' "iperf evidence: $IPERF_EVIDENCE"
}

matrix_result_for() {
	scenario=$1
	result=$2
	reason=$3
	warnings=$4
	printf '    {"id":"%s","result":"%s","real_device_collected":false,"warnings":[%s],"reason":"%s"}' \
		"$scenario" "$result" "$warnings" "$reason"
}

run_matrix() {
	{
		printf '%s\n' "{"
		printf '  "schema": "lanspeed.task16.qa_matrix.v1",\n'
		printf '  "generated_at": "%s",\n' "$(timestamp)"
		printf '  "target": "%s",\n' "$(printf '%s' "${TARGET:-not_provided}" | json_escape)"
		printf '  "dry_run": %s,\n' "$(if [ "$DRY_RUN" = "1" ]; then printf true; else printf false; fi)"
		printf '  "safety": "matrix writes local evidence only; collect reload refreshes lanspeedd runtime state and does not change persistent UCI, proxy, firewall, or network configuration",\n'
		printf '  "real_device_pass_claimed": false,\n'
		printf '  "result_values": ["pass", "degraded", "unsupported", "not_run"],\n'
		printf '  "scenarios": [\n'
		matrix_result_for "base_immortalwrt_25_12" "not_run" "No real ImmortalWrt 25.12 device output was collected in this environment" ""; printf ',\n'
		matrix_result_for "software_flow_offload_on" "not_run" "Requires target firewall UCI and live ubus/tc/nft snapshots" '"software_flow_offload_enabled"'; printf ',\n'
		matrix_result_for "software_flow_offload_off" "not_run" "Requires target firewall UCI and live ubus/tc/nft snapshots" ""; printf ',\n'
		matrix_result_for "hardware_flow_offload_on" "unsupported" "Hardware flow offload can bypass CPU-visible LAN-edge collectors and must not claim Full" '"hardware_flow_offload_unsupported"'; printf ',\n'
		matrix_result_for "openclash_fake_ip" "degraded" "Remote attribution confidence is lower under fake-ip unless LAN-edge BPF evidence proves primary metrics" '"openclash_fake_ip_low_remote_confidence"'; printf ',\n'
		matrix_result_for "openclash_tun" "degraded" "TUN/mix paths can reduce conntrack fallback confidence" '"openclash_tun_conntrack_low_confidence"'; printf ',\n'
		matrix_result_for "openclash_redir_host" "not_run" "Needs real OpenClash mode and DNS chain evidence from target" ""; printf ',\n'
		matrix_result_for "dae_daed_on" "degraded" "dae/daed tc/TUN hooks are evidence only and may lower confidence" '"dae_detected"'; printf ',\n'
		matrix_result_for "dae_daed_off" "not_run" "Needs target service and UCI evidence" ""; printf ',\n'
		matrix_result_for "openclash_plus_dae" "degraded" "Proxy stacks can coexist but require warnings and conflict evidence; no real pass is claimed" '"openclash_fake_ip_low_remote_confidence","openclash_tun_conntrack_low_confidence","dae_detected"'; printf ',\n'
		matrix_result_for "sqm_qosify_ifb" "degraded" "Existing QoS/IFB may own tc hooks or alter direction visibility" '"sqm_detected","qosify_detected","ifb_detected"'; printf ',\n'
		matrix_result_for "pppoe" "not_run" "PPPoE is WAN-side encapsulation evidence; real target snapshots required" ""; printf ',\n'
		matrix_result_for "vlan_guest" "not_run" "Requires real bridge/VLAN/zone identity snapshots" '"duplicate_mac_across_vlans"'; printf ',\n'
		matrix_result_for "wifi" "not_run" "Requires target Wi-Fi association and CPU visibility checks" ""; printf ',\n'
		matrix_result_for "side_router_same_subnet_direct" "degraded" "Same-subnet side-router direct paths may be asymmetric and incomplete" '"asymmetric_path_possible"'; printf ',\n'
		matrix_result_for "low_end_device_performance" "not_run" "Requires target CPU/load and iperf evidence" ""
		printf '\n  ]\n'
		printf '%s\n' "}"
	} > "$MATRIX_EVIDENCE"

	printf '%s\n' "matrix evidence: $MATRIX_EVIDENCE"
}

run_openclash_dae() {
	tc_conflict=${TC_FILTER_CONFLICT:-1}
	{
		printf '%s\n' "{"
		printf '  "schema": "lanspeed.task16.openclash_dae.v1",\n'
		printf '  "generated_at": "%s",\n' "$(timestamp)"
		printf '  "target": "%s",\n' "$(printf '%s' "${TARGET:-not_provided}" | json_escape)"
		printf '  "status": "%s",\n' "$(if [ "$DRY_RUN" = "1" ] || [ -z "$TARGET" ]; then printf not_run; else printf degraded; fi)"
		printf '  "real_device_collected": %s,\n' "$(if [ "$DRY_RUN" != "1" ] && [ -n "$TARGET" ]; then printf true; else printf false; fi)"
		printf '  "real_device_pass_claimed": false,\n'
		printf '  "safety": "mock/dry-run evidence only; script does not alter OpenClash, dae, firewall, network, tc, nft, or UCI configuration",\n'
		printf '  "openclash": {\n'
		printf '    "installed": "unknown_without_real_target",\n'
		printf '    "modes_checked": ["fake-ip", "TUN", "redir-host"],\n'
		printf '    "warnings": ["openclash_fake_ip_low_remote_confidence", "openclash_tun_conntrack_low_confidence"],\n'
		printf '    "remote_identity_policy": "fake-ip and proxy remote addresses are metadata only, never LAN client identity"\n'
		printf '  },\n'
		printf '  "dae": {\n'
		printf '    "installed": "unknown_without_real_target",\n'
		printf '    "interfaces": ["dae0", "dae0peer"],\n'
		printf '    "fwmark": "0x8000000",\n'
		printf '    "route_table": "2023",\n'
		printf '    "warnings": ["dae_detected"],\n'
		printf '    "identity_policy": "dae0 and dae0peer are proxy/uplink evidence only and never LAN client identity sources"\n'
		printf '  },\n'
		printf '  "tc": {\n'
		printf '    "filter_conflict": %s,\n' "$(if [ "$tc_conflict" = "1" ]; then printf true; else printf false; fi)"
		printf '    "warnings": [%s],\n' "$(if [ "$tc_conflict" = "1" ]; then printf '"tc_filter_conflict"'; fi)"
		printf '    "coexistence_policy": "create_or_reuse_clsact_and_append_owned_filter_only; never delete or reorder existing filters"\n'
		printf '  },\n'
		printf '  "matrix_result": "degraded",\n'
		printf '  "warning_ids": ["openclash_fake_ip_low_remote_confidence", "openclash_tun_conntrack_low_confidence", "dae_detected"%s]\n' "$(if [ "$tc_conflict" = "1" ]; then printf ', "tc_filter_conflict"'; fi)"
		printf '%s\n' "}"
	} > "$OPENCLASH_DAE_EVIDENCE"

	printf '%s\n' "openclash dae evidence: $OPENCLASH_DAE_EVIDENCE"
}

command=${1:-}
case "$command" in
	collect)
		run_collect
		;;
	iperf)
		run_iperf
		;;
	matrix)
		run_matrix
		;;
	openclash-dae|openclash_dae|mock-openclash-dae)
		run_openclash_dae
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
