#!/bin/sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
. "$SCRIPT_DIR/test-output.sh"
lanspeed_test_output_init
trap 'lanspeed_test_output_cleanup' EXIT

README="$ROOT_DIR/README.md"
LICENSE="$ROOT_DIR/LICENSE"
GUIDE_DIR="$ROOT_DIR/docs/guide"
GUIDE_FILES="$GUIDE_DIR/usage.md $GUIDE_DIR/platforms.md $GUIDE_DIR/operations.md $GUIDE_DIR/development.md"
DOCUMENTATION="$README $GUIDE_FILES"
MATRIX="$ROOT_DIR/docs/rust-compatibility-matrix.md"
EVIDENCE_DIR="$LANSPEED_TEST_OUTPUT_DIR"
EVIDENCE="$EVIDENCE_DIR/task-14-doc-check.txt"

mkdir -p "$EVIDENCE_DIR"
: > "$EVIDENCE"

log() {
	printf '%s\n' "$*" >> "$EVIDENCE"
}

require_phrase() {
	phrase="$1"
	if grep -Fq -- "$phrase" $DOCUMENTATION; then
		log "ok: $phrase"
	else
		log "missing documentation phrase: $phrase"
		printf 'missing required documentation phrase: %s\n' "$phrase" >&2
		exit 1
	fi
}

reject_phrase() {
	phrase="$1"
	if grep -Fq -- "$phrase" $DOCUMENTATION; then
		log "forbidden: $phrase"
		printf 'forbidden documentation phrase present: %s\n' "$phrase" >&2
		exit 1
	fi
	log "absent: $phrase"
}

check_png() {
	path="$1"
	width="$2"
	height="$3"
	test -f "$path" || {
		printf 'missing README screenshot: %s\n' "$path" >&2
		exit 1
	}
	node - "$path" "$width" "$height" <<'NODE'
const fs = require('fs');
const [path, expectedWidth, expectedHeight] = process.argv.slice(2);
const png = fs.readFileSync(path);
const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
if (png.length < 33 || !png.subarray(0, 8).equals(signature))
  throw new Error(path + ': invalid PNG signature');
if (png.readUInt32BE(16) !== Number(expectedWidth) ||
    png.readUInt32BE(20) !== Number(expectedHeight))
  throw new Error(path + ': unexpected dimensions');
let offset = 8;
const chunks = [];
while (offset < png.length) {
  if (offset + 12 > png.length) throw new Error(path + ': truncated PNG chunk');
  const length = png.readUInt32BE(offset);
  const type = png.toString('ascii', offset + 4, offset + 8);
  offset += length + 12;
  if (offset > png.length) throw new Error(path + ': invalid ' + type + ' chunk');
  chunks.push(type);
  if (type === 'IEND') break;
}
if (offset !== png.length || chunks[0] !== 'IHDR' || chunks.at(-1) !== 'IEND' ||
    chunks.some((type) => !['IHDR', 'IDAT', 'IEND'].includes(type)))
  throw new Error(path + ': metadata or trailing data present');
NODE
	log "ok screenshot: $path"
}

log "multi-page documentation checklist"

test -f "$LICENSE" || {
	printf 'missing root LICENSE file\n' >&2
	exit 1
}

license_sha256="$(sha256sum "$LICENSE" | awk '{print $1}')"
test "$license_sha256" = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30" || {
	printf 'root LICENSE is not the canonical Apache License 2.0 text\n' >&2
	exit 1
}

grep -Fq -- '[Apache License 2.0](LICENSE)' "$README" || {
	printf 'README missing root license link\n' >&2
	exit 1
}

grep -Fq -- '第三方依赖保留各自随附的许可证' "$README" || {
	printf 'README missing third-party license boundary\n' >&2
	exit 1
}

log "ok: canonical Apache License 2.0 and documented license boundaries"

for page in $GUIDE_FILES; do
	test -f "$page" || {
		printf 'missing guide page: %s\n' "$page" >&2
		exit 1
	}
done

readme_lines="$(wc -l < "$README")"
test "$readme_lines" -le 120 || {
	printf 'README landing page is too long: %s lines\n' "$readme_lines" >&2
	exit 1
}

for link in \
	"docs/guide/usage.md" \
	"docs/guide/platforms.md" \
	"docs/guide/operations.md" \
	"docs/guide/development.md"; do
	grep -Fq -- "$link" "$README" || {
		printf 'README missing guide link: %s\n' "$link" >&2
		exit 1
	}
done

for phrase in \
	"## 平台模块" \
	'`platform/x86/`' \
	'`platform/nss/`' \
	'`lanspeed-ebpf/src/x86/`' \
	'`lanspeed-ebpf/src/nss/`' \
	'`platform/x86` 与 `platform/nss` 双向零引用' \
	'NSS 融合层不接收 x86 类型' \
	'`x86-tc` 与 `nss-tc`' \
	"x86_64 构建不会安装 ECM 对象" \
	"非 NSS 设备由 BPF tc" \
	"x86_64 的自动模式只能落到 BPF" \
	"Qualcomm aarch64 NSS 设备自动按 ECM+BPF、ECM、BPF" \
	"AYA_BPF_TARGET_ARCH=aarch64" \
	"不叠加已经计算过的速率" \
	'`nss_ecm_node`' \
	'`nss_ecm_bpf`' \
	'`1/2/3/5/10`' \
	'`2/4/8/10`' \
	'首次快照保持 `warmup/0`' \
	'覆盖率进入 `pending`，不会阻塞逐客户端速率' \
	"物理 LAN MIB 只负责覆盖率验证" \
	"## 安装与编译" \
	"src-git lanspeed https://github.com/qimaoww/luci-app-lanspeed.git" \
	"./scripts/feeds update lanspeed" \
	"./scripts/feeds install -a -p lanspeed" \
	"LuCI -> Applications -> luci-app-lanspeed" \
	'package/lanspeedd/compile' \
	'package/luci-app-lanspeed/compile' \
	'强制依赖 `lanspeedd-bpf`' \
	"scripts/build-sdk.sh" \
	"SDK_DIR=/openwrt/immortalwrt" \
	"ENABLE_BPF=1" \
	"DRY_RUN=1" \
	"## 支持范围" \
	'`x86_64` LP64' \
	'`aarch64` LP64' \
	"32 位 ARM、i386 和 MIPS" \
	"Rust >= 1.87.0" \
	'`1.87.0` 到 `1.97.1`' \
	"低于 MSRV" \
	"内部 atomic intrinsic 的版本转折点" \
	"交叉编译通过不等于具体设备已完成真机验证" \
	"十一个 ubus 方法" \
	"六个 RPC 请求" \
	"ubus call lanspeed status" \
	"ubus call lanspeed clients" \
	"ubus call lanspeed health" \
	"ubus call lanspeed interfaces" \
	"ubus call lanspeed diagnostics" \
	'02:00:00:00:00:42@br-lan' \
	"Full" \
	"Degraded" \
	"Unsupported" \
	"high" \
	"medium" \
	"low" \
	"unsupported" \
	"tx_bps" \
	"rx_bps" \
	"MAC + zone/VLAN" \
	"OpenClash fake-ip" \
	"OpenClash TUN/mix" \
	"dae/daed" \
	"SQM/qosify/ifb" \
	"hardware flow offload" \
	"software flow offload" \
	"fullcone NAT" \
	"same-subnet side-router direct" \
	"router-local" \
	"LAN-to-LAN" \
	"VLAN/Wi-Fi" \
	"PPPoE/WG/TUN" \
	"openclash_fake_ip_low_remote_confidence" \
	"openclash_tun_conntrack_low_confidence" \
	"openclash_dns_chain_incomplete" \
	"hardware_flow_offload_unsupported" \
	"software_flow_offload_enabled" \
	"fullcone_nat_enabled" \
	"dae_detected" \
	"tc_filter_conflict" \
	"sqm_detected" \
	"qosify_detected" \
	"ifb_detected" \
	"conntrack_routed_nat_only" \
	"flowtable_counter_missing" \
	"nlbwmon_counter_conflict" \
	"lan_to_lan_visibility_limited" \
	"asymmetric_path_possible" \
	"duplicate_mac_across_vlans" \
	"map_full" \
	"SDK 缺失" \
	"缺少 BPF 包或对象" \
	'缺少 `tc`' \
	"nf_conntrack_acct" \
	"没有客户端" \
	"速率长时间为 0" \
	"OpenClash 或 dae/daed 共存" \
	"本地环境可以运行确定性检查脚本" \
	"真实 SDK 编译" \
	"目标设备" \
	"确定性合成数据" \
	"文档保留地址" \
	"本地管理 MAC" \
	"PNG 元数据"; do
	require_phrase "$(printf '%s' "$phrase" | tr '`' '\140')"
done

for forbidden in \
	"collectors/bpf/" \
	"collectors/ecm_node.rs" \
	"lanspeed-ebpf/src/ecm.rs" \
	"旧代码" \
	"旧版" \
	"legacy daemon" \
	"former libuci" \
	"回滚时三个包" \
	"参考验收中" \
	"本仓库所有代码及文档" \
	"lanspeedd-bpf（可选）" \
	"ENABLE_BPF=0" \
	"--force-reinstall"; do
	reject_phrase "$forbidden"
done

test -f "$MATRIX" || {
	printf 'missing Rust compatibility matrix: %s\n' "$MATRIX" >&2
	exit 1
}
for phrase in "1.87.0" "1.97.1 |" "aya@0.14.0 requires rustc 1.87.0" "EM_BPF" "aarch64-musl"; do
	grep -Fq -- "$phrase" "$MATRIX" || {
		printf 'missing compatibility matrix phrase: %s\n' "$phrase" >&2
		exit 1
	}
done

for theme in aurora argon bootstrap; do
	for page in overview diagnostics config; do
		check_png "$ROOT_DIR/docs/screenshots/lanspeed-$page-$theme-desktop.png" 1920 1080
	done
	check_png "$ROOT_DIR/docs/screenshots/lanspeed-overview-$theme-mobile.png" 390 844
done

log "result: pass"
printf '%s\n' "documentation checklist passed"
