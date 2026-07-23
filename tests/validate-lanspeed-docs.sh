#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
README="$ROOT_DIR/README.md"
MATRIX="$ROOT_DIR/docs/rust-compatibility-matrix.md"
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

check_png() {
	path="$1"
	width="$2"
	height="$3"
	if [ ! -f "$path" ]; then
		log "missing screenshot: $path"
		printf 'missing README screenshot: %s\n' "$path" >&2
		exit 1
	fi
	node - "$path" "$width" "$height" <<'NODE'
const fs = require('fs');
const [path, expectedWidth, expectedHeight] = process.argv.slice(2);
const png = fs.readFileSync(path);
const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
if (png.length < 33 || !png.subarray(0, 8).equals(signature))
  throw new Error(`${path}: invalid PNG signature`);
const width = png.readUInt32BE(16);
const height = png.readUInt32BE(20);
if (width !== Number(expectedWidth) || height !== Number(expectedHeight))
  throw new Error(`${path}: expected ${expectedWidth}x${expectedHeight}, got ${width}x${height}`);
let offset = 8;
const chunks = [];
while (offset < png.length) {
  if (offset + 12 > png.length) throw new Error(`${path}: truncated PNG chunk`);
  const length = png.readUInt32BE(offset);
  const type = png.toString('ascii', offset + 4, offset + 8);
  const end = offset + 12 + length;
  if (end > png.length) throw new Error(`${path}: invalid ${type} chunk length`);
  chunks.push(type);
  offset = end;
  if (type === 'IEND') break;
}
if (offset !== png.length || chunks[0] !== 'IHDR' || chunks[chunks.length - 1] !== 'IEND' ||
    chunks.some((type) => !['IHDR', 'IDAT', 'IEND'].includes(type)))
  throw new Error(`${path}: unexpected PNG chunks or trailing data: ${chunks.join(',')}`);
NODE
	log "ok screenshot: $path (${width}x${height}, metadata-free PNG)"
}

log "README documentation checklist"
log "file: $README"

if [ ! -f "$MATRIX" ]; then
	log "missing compatibility matrix: $MATRIX"
	printf 'missing Rust compatibility matrix: %s\n' "$MATRIX" >&2
	exit 1
fi
log "compatibility matrix: $MATRIX"

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
require_phrase "## 支持范围"
require_phrase '`x86_64` LP64'
require_phrase '`aarch64` LP64'
require_phrase "对应 SDK 重建"
require_phrase "交叉编译通过不等于具体设备已完成真机验证"
require_phrase "Rust >= 1.87.0"
require_phrase '`1.87.0` 到 `1.97.1` 的每个稳定版'
require_phrase "低于 MSRV"
require_phrase "内部 atomic intrinsic 的版本转折点"

for matrix_phrase in \
	"1.87.0" \
	"1.97.1 |" \
	"aya@0.14.0 requires rustc 1.87.0" \
	"EM_BPF" \
	"aarch64-musl"; do
	if grep -Fq -- "$matrix_phrase" "$MATRIX"; then
		log "ok matrix: $matrix_phrase"
	else
		log "missing matrix phrase: $matrix_phrase"
		printf 'missing required compatibility matrix phrase: %s\n' "$matrix_phrase" >&2
		exit 1
	fi
done
require_phrase "32 位 ARM、i386 和 MIPS"
reject_phrase "ImmortalWrt 25.12"
reject_phrase "2025-07"
reject_phrase "OpenWrt 23.05"
reject_phrase "OpenWrt 21.02"
reject_phrase "Linux 6.12.94"
reject_phrase "IPQ807x"
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
require_phrase "ubus call lanspeed diagnostics"
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
require_phrase "非 NSS 设备以 BPF 为实时来源"
require_phrase "NSS ECM/PPE 活跃时 BPF 继续挂载观测慢路径"
require_phrase "客户端总速率以 NSS Conntrack 同步计数为准"
require_phrase "绝不把两套累计值相加"
require_phrase 'NSS-direct 是显式选择 `nss_ecm_direct`'
require_phrase "NSS sync 不可用时的后备来源"
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
require_phrase "六个 RPC 请求"
require_phrase "九个 ubus 方法"
require_phrase '02:00:00:00:00:42@br-lan'
require_phrase "确定性合成数据"
require_phrase "文档保留地址"
require_phrase "本地管理 MAC"
require_phrase "PNG 元数据"
require_phrase "docs/screenshots/lanspeed-overview-aurora-desktop.png"
require_phrase "docs/screenshots/lanspeed-diagnostics-aurora-desktop.png"
require_phrase "docs/screenshots/lanspeed-config-aurora-desktop.png"
require_phrase "docs/screenshots/lanspeed-overview-aurora-mobile.png"
require_phrase "docs/screenshots/lanspeed-overview-argon-desktop.png"
require_phrase "docs/screenshots/lanspeed-diagnostics-argon-desktop.png"
require_phrase "docs/screenshots/lanspeed-config-argon-desktop.png"
require_phrase "docs/screenshots/lanspeed-overview-argon-mobile.png"
require_phrase "docs/screenshots/lanspeed-overview-bootstrap-desktop.png"
require_phrase "docs/screenshots/lanspeed-diagnostics-bootstrap-desktop.png"
require_phrase "docs/screenshots/lanspeed-config-bootstrap-desktop.png"
require_phrase "docs/screenshots/lanspeed-overview-bootstrap-mobile.png"
reject_phrase "/openwrt/25"".12"
reject_phrase "五个 RPC 请求"
reject_phrase "八个 ubus 方法"
reject_phrase "02:00:00:00:00:42@eth1"
reject_phrase "uci set lanspeed.main.enabled"
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

for theme in aurora argon bootstrap; do
	for page in overview diagnostics config; do
		check_png "$ROOT_DIR/docs/screenshots/lanspeed-$page-$theme-desktop.png" 1920 1080
	done
	check_png "$ROOT_DIR/docs/screenshots/lanspeed-overview-$theme-mobile.png" 390 844
done

for obsolete in \
	lanspeed-overview-desktop.png \
	lanspeed-overview-desktop-argon.png \
	client-connections-desktop.png \
	client-connections-desktop-argon.png \
	client-connections-mobile.png \
	client-connections-mobile-argon.png; do
	if [ -e "$ROOT_DIR/docs/screenshots/$obsolete" ]; then
		log "obsolete screenshot remains: $obsolete"
		printf 'obsolete README screenshot remains: %s\n' "$obsolete" >&2
		exit 1
	fi
done

log "result: pass"
printf 'documentation checklist passed: %s\n' "$EVIDENCE"
