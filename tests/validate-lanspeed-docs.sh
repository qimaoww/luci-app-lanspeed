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
	if grep -Fq -- "$phrase" "$README"; then
		log "ok: $phrase"
	else
		log "missing: $phrase"
		printf 'missing required README phrase: %s\n' "$phrase" >&2
		exit 1
	fi
}

reject_phrase() {
	phrase="$1"
	if grep -Fq -- "$phrase" "$README"; then
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
require_phrase "## 安装与编译"
require_phrase "# 在 feeds.conf 中添加 lanspeed feed"
require_phrase "src-git lanspeed https://github.com/qimaoww/luci-app-lanspeed.git"
require_phrase "# 更新并安装"
require_phrase "./scripts/feeds update lanspeed"
require_phrase "./scripts/feeds install -a -p lanspeed"
require_phrase "# 在 menuconfig 中选中 LuCI -> Applications -> luci-app-lanspeed"
require_phrase "# BPF 是必选依赖，会自动选择 Network -> lanspeedd-bpf 和 lanspeedd"
require_phrase "LuCI -> Applications -> luci-app-lanspeed"
require_phrase "make menuconfig"
require_phrase "# 多线程编译"
require_phrase 'make -j"$(nproc)"'
require_phrase "package/lanspeedd/compile"
require_phrase "package/luci-app-lanspeed/compile"
require_phrase "ImmortalWrt 25.12"
require_phrase "23.05"
require_phrase "OpenWrt 23.05 | 不支持"
require_phrase "Rust >= 1.94.0"
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
require_phrase "ENABLE_BPF=1"
require_phrase "DRY_RUN"
require_phrase "ABI"
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
require_phrase "所有设备（包括 NSS ECM/PPE）优先使用 BPF"
require_phrase "显式选择 NSS 模式或 BPF 运行时不可用时"
require_phrase '强制依赖 `lanspeedd-bpf`'
require_phrase "低流量与真正无流量分开显示"
require_phrase "恢复流量时首个样本不再固定显示为 0"
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
reject_phrase "git clone https://github.com/qimaoww/luci-app-lanspeed.git package/lanspeed"
reject_phrase "package/lanspeed/lanspeedd/compile"
reject_phrase "package/lanspeed/luci-app-lanspeed/compile"
reject_phrase "make package/lanspeedd-bpf/compile"
reject_phrase "lanspeedd-bpf（可选）"
reject_phrase "### 基础包与 BPF 可选包"
reject_phrase "ENABLE_BPF=0"
reject_phrase "## 安装、启动与回滚"
reject_phrase "--force-reinstall"
reject_phrase "/tmp/legacy/lanspeedd"

log "result: pass"
printf 'documentation checklist passed: %s\n' "$EVIDENCE"
