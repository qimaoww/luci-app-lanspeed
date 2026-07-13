#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
README="$ROOT_DIR/README.md"
DAEMON_MAKEFILE="$ROOT_DIR/net/lanspeedd/Makefile"
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

require_block() {
	block="$1"
	if BLOCK="$block" awk 'BEGIN { block = ENVIRON["BLOCK"] } { text = text $0 ORS } END { exit(index(text, block) == 0) }' "$README"; then
		log "ok: required block"
	else
		log "missing: required block"
		printf '%s\n' 'missing required README block' >&2
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

read_make_var() {
	name="$1"
	value="$(awk -v name="$name" '
		index($0, name ":=") == 1 {
			value = substr($0, length(name) + 3)
			gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
			print value
			exit
		}
	' "$DAEMON_MAKEFILE")"
	if [ -z "$value" ]; then
		printf 'missing required Makefile variable: %s\n' "$name" >&2
		exit 1
	fi
	printf '%s\n' "$value"
}

package_version="$(read_make_var PKG_VERSION)"
package_release="$(read_make_var PKG_RELEASE)"
current_full_version="${package_version}-r${package_release}"

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
require_phrase "OpenWrt 23.05 | 不支持"
require_phrase "Rust 1.94.0"
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
require_phrase "本地环境可以运行确定性检查脚本"
require_phrase "真实 SDK 编译"
require_phrase "目标设备"
require_phrase "/openwrt/immortalwrt"
reject_phrase "/openwrt/25"".12"
require_block "apk add --force-reinstall --allow-untrusted \\
	/tmp/lanspeedd-${current_full_version}.apk \\
	/tmp/lanspeedd-bpf-${current_full_version}.apk \\
	/tmp/luci-app-lanspeed-${current_full_version}.apk"
require_block "apk add --force-reinstall --allow-untrusted \\
	/tmp/legacy/lanspeedd-0.1.7-r1.apk \\
	/tmp/legacy/lanspeedd-bpf-0.1.7-r1.apk \\
	/tmp/legacy/luci-app-lanspeed-0.1.6-r1.apk
cp /tmp/legacy/lanspeed /etc/config/lanspeed
/etc/init.d/lanspeedd restart"
require_phrase "同一个 APK 事务"
require_phrase "同版本包不替换"
require_phrase "人为分步安装造成短暂混合版本"
require_phrase "以升级前保存的文件名为准"
require_phrase "目标机当前已安装的 lanspeed APK"
require_phrase "若使用 BPF"
require_phrase "三个匹配包放在同一次"
require_phrase "不使用 BPF 时"
require_phrase "不应安装 BPF 包"
require_phrase "本次 x86_64 实测示例"
require_phrase 'aarch64 Release 文件名带 `-aarch64`'
require_phrase "按实际产物替换路径"
require_phrase "本次 x86_64 实测设备备份"

log "result: pass"
printf 'documentation checklist passed: %s\n' "$EVIDENCE"
