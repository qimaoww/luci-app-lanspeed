#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
README="$ROOT_DIR/README.md"
EVIDENCE_DIR="$ROOT_DIR/.sisyphus/evidence"
EVIDENCE="$EVIDENCE_DIR/task-14-doc-check.txt"

mkdir -p "$EVIDENCE_DIR"
: > "$EVIDENCE"

log() {
	printf '%s\n' "$*" >> "$EVIDENCE"
}

require_phrase() {
	phrase="$1"
	if grep -Fq "$phrase" "$README"; then
		log "ok: $phrase"
	else
		log "missing: $phrase"
		printf 'missing required README phrase: %s\n' "$phrase" >&2
		exit 1
	fi
}

reject_phrase() {
	phrase="$1"
	if grep -Fq "$phrase" "$README"; then
		log "forbidden: $phrase"
		printf 'forbidden README phrase present: %s\n' "$phrase" >&2
		exit 1
	else
		log "absent: $phrase"
	fi
}

log "README documentation checklist"
log "file: $README"

require_phrase "CPU 可见 LAN 边缘流量"
require_phrase "不是完整流量审计系统"
require_phrase "不声明全流量绝对准确"
require_phrase "luci-app-lanspeed"
require_phrase "lanspeedd"
require_phrase "lanspeedd-bpf"
require_phrase "ImmortalWrt 25.12"
require_phrase "23.05"
require_phrase "21.02 及更早版本"
require_phrase "Full"
require_phrase "Degraded"
require_phrase "Unsupported"
require_phrase "high"
require_phrase "medium"
require_phrase "low"
require_phrase "unsupported"
require_phrase "tx_bps"
require_phrase "rx_bps"
require_phrase "MAC + zone/VLAN"
require_phrase "router_self"
require_phrase "scripts/build-sdk.sh"
require_phrase "SDK_DIR"
require_phrase "ENABLE_BPF"
require_phrase "DRY_RUN"
require_phrase "ABI"
require_phrase "/etc/init.d/lanspeedd enable"
require_phrase "ubus call lanspeed status"
require_phrase "ubus call lanspeed clients"
require_phrase "ubus call lanspeed health"
require_phrase "ubus call lanspeed interfaces"
require_phrase "uci set lanspeed.main.enabled"
require_phrase "OpenClash fake-ip"
require_phrase "OpenClash TUN/mix"
require_phrase "dae/daed"
require_phrase "SQM/qosify/ifb"
require_phrase "hardware flow offload"
require_phrase "software flow offload"
require_phrase "fullcone NAT"
require_phrase "same-subnet side-router direct"
require_phrase "router-local"
require_phrase "LAN-to-LAN"
require_phrase "VLAN/Wi-Fi"
require_phrase "PPPoE/WG/TUN"
require_phrase "openclash_fake_ip_low_remote_confidence"
require_phrase "openclash_tun_conntrack_low_confidence"
require_phrase "openclash_dns_chain_incomplete"
require_phrase "hardware_flow_offload_unsupported"
require_phrase "software_flow_offload_enabled"
require_phrase "fullcone_nat_enabled"
require_phrase "dae_detected"
require_phrase "tc_filter_conflict"
require_phrase "sqm_detected"
require_phrase "qosify_detected"
require_phrase "ifb_detected"
require_phrase "conntrack_routed_nat_only"
require_phrase "flowtable_counter_missing"
require_phrase "nlbwmon_counter_conflict"
require_phrase "lan_to_lan_visibility_limited"
require_phrase "asymmetric_path_possible"
require_phrase "duplicate_mac_across_vlans"
require_phrase "map_full"
require_phrase "SDK 缺失"
require_phrase "缺少 BPF 包或对象"
require_phrase '缺少 `tc`'
require_phrase "nf_conntrack_acct"
require_phrase "没有客户端"
require_phrase "速率长时间为 0"
require_phrase "OpenClash 或 dae/daed 共存"
require_phrase "本地环境只能运行确定性检查脚本"
require_phrase "真实 SDK 编译"
require_phrase "目标设备"

log "result: pass"
printf 'documentation checklist passed: %s\n' "$EVIDENCE"
