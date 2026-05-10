# luci-lanspeed feed

`luci-lanspeed` 是一个独立的 ImmortalWrt/OpenWrt 本地 feed，用于在路由器上查看按客户端归属的 LAN 侧吞吐状态。它的统计边界是 **CPU 可见 LAN 边缘流量**，不是完整流量审计系统，也不声明全流量绝对准确，不会声称所有硬件交换、所有卸载路径或全部 LAN-to-LAN 流量都绝对可见。

## 包组成

- `luci-app-lanspeed`：LuCI 状态页，读取 `lanspeed.status` 与 `lanspeed.clients`，展示模式、置信度、能力、告警和客户端速率。
- `lanspeedd`：C daemon，提供只读 ubus 方法 `status`、`clients`、`health`、`interfaces`，并负责运行时探测、客户端身份合并和降级采集。
- `lanspeedd-bpf`：可选子包，在 SDK 构建阶段编译 tc/eBPF 对象并安装到 `/usr/lib/bpf/lanspeed_tc.o`。设备端不需要 clang/LLVM。

## 支持矩阵

| 系统 | 支持级别 | 说明 |
| --- | --- | --- |
| ImmortalWrt 25.12 | 一等目标 | README、SDK helper 与本地验证都以 25.12 为当前目标。 |
| OpenWrt/ImmortalWrt 23.05 | 次级验证 | 包结构和只读 ubus 合同尽量保持兼容，但需要目标设备复核。 |
| OpenWrt/ImmortalWrt 21.02 及更早版本 | 不支持 | 不承诺 LuCI JS、firewall4、tc/eBPF 或 ubus 行为兼容。 |

当前仓库是本地 feed，不是完整 SDK/buildroot。本地环境只能运行确定性检查脚本，真实 SDK 编译、真实路由器 ubus/tc/nft 行为和浏览器呈现必须在目标设备上验收。

## 准确性模式和置信度

### 模式

- `Full`：daemon 已通过 libbpf 在 LAN 边缘接口上成功 attach tc/eBPF 程序，并且近期完成了一次 BPF map 读取。`enable_bpf=1` 且 `lanspeedd-bpf` 子包提供的 `/usr/lib/bpf/lanspeed_tc.o` 存在时，daemon 会在启动阶段尝试 attach 并开启 1 秒级轮询；任何环节失败（对象缺失、attach 被拒、map 读失败）都会在运行期持续回落到 `Degraded`。Full 仍只表示 CPU 可见 LAN 边缘流量，不表示硬件不可见路径也被统计。
- `Degraded`：BPF runtime 不可用或被安全检测拦截时进入该模式，基于 `/proc/net/nf_conntrack` + `/proc/net/arp` 读取 routed/NAT 流量。覆盖范围较窄，通常只覆盖 routed/NAT 或部分可见路径。
- `Unsupported`：缺少关键能力（无 `tc`、无 conntrack accounting、无 LAN 边缘接口），或检测到会破坏安全挂载、采集对象或覆盖边界的条件。此时不应把页面数值当作可用实时指标。

### 置信度

- `high`：采集路径和客户端归属证据较完整。
- `medium`：指标可用，但存在代理、整形、拓扑或卸载因素，需要结合告警阅读。
- `low`：只能作为排查线索，不适合做精确计量。
- `unsupported`：当前状态不支持可用采集。

## 方向和身份语义

- 方向按客户端视角定义。
- `tx_bps` 表示客户端上传，也就是客户端发出或发起的流量。
- `rx_bps` 表示客户端下载，也就是流向客户端的流量。
- 客户端身份以规范化 MAC + zone/VLAN 为主，`identity_key` 不从 IP 派生。
- IP 地址和 hostname 是属性，不是唯一身份。静态 IP 无 hostname 时可以显示 `null` 或空值。
- `router_self` 与 `local_router` 单独表达路由器自身流量，不归属到任一 LAN 客户端。
- 同一 MAC 出现在不同 VLAN 或 zone 时会按不同身份显示，并可能报告 `duplicate_mac_across_vlans`。

## 安装和 SDK 构建

请先准备 ImmortalWrt 25.12 SDK，并通过 `SDK_DIR` 指向该 SDK。脚本不会自动下载 SDK、toolchain 或源码包。

脚本会在 SDK 内把本仓库注入为本地 feed：

```sh
src-link lanspeed /root/luci
```

常用命令：

```sh
# 只查看将要执行的 feed/update/install/compile 命令，不写入 SDK、不编译
SDK_DIR=/tmp/fake-sdk DRY_RUN=1 ./scripts/build-sdk.sh all

# 构建 LuCI 包；luci-app-lanspeed 依赖 lanspeedd，因此会先安装本地 feed 中的 daemon 包定义
SDK_DIR=/path/to/immortalwrt-25.12-sdk TARGET_ARCH=x86_64 ENABLE_BPF=0 ./scripts/build-sdk.sh luci-app-lanspeed

# 构建 daemon 基础包，不启用 BPF 子包选择
SDK_DIR=/path/to/immortalwrt-25.12-sdk TARGET_ARCH=x86_64 ENABLE_BPF=0 ./scripts/build-sdk.sh lanspeedd

# 构建两个当前包目标
SDK_DIR=/path/to/immortalwrt-25.12-sdk TARGET_ARCH=x86_64 ENABLE_BPF=0 ./scripts/build-sdk.sh all

# 选择并编译可选 lanspeedd-bpf 子包；BPF 对象在 SDK 构建阶段生成，设备端不需要 clang/LLVM
SDK_DIR=/path/to/immortalwrt-25.12-sdk TARGET_ARCH=x86_64 ENABLE_BPF=1 ./scripts/build-sdk.sh all
```

安全验证命令：

```sh
# SDK 不存在时必须清晰失败，并且错误信息包含 SDK_DIR
SDK_DIR=/nonexistent ./scripts/build-sdk.sh luci-app-lanspeed

# 本地验收：生成 .sisyphus/evidence/task-3-missing-sdk.txt 与 task-3-sdk-dry-run.txt
./tests/validate-build-sdk.sh
```

脚本会检查常见 SDK release metadata，例如 `version.buildinfo`、`.vermagic`、`feeds.conf.default`、`include/version.mk`。发现明显不是 25.12 的 SDK 时会拒绝继续，以降低 master/25.12 ABI 混用风险。

安装生成的 `.ipk` 后，按常规方式在目标路由器上安装包：

```sh
opkg install /tmp/lanspeedd_*.ipk /tmp/luci-app-lanspeed_*.ipk
# 如需 Full 模式（libbpf attach + map read），再安装可选子包并确保 /usr/lib/bpf/lanspeed_tc.o 存在
opkg install /tmp/lanspeedd-bpf_*.ipk
```

## 运行和调试

服务命令：

```sh
/etc/init.d/lanspeedd enable
/etc/init.d/lanspeedd start
/etc/init.d/lanspeedd restart
/etc/init.d/lanspeedd reload
```

ubus 只读调试命令：

```sh
ubus call lanspeed status
ubus call lanspeed clients
ubus call lanspeed health
ubus call lanspeed interfaces
```

UCI 示例：

```sh
uci set lanspeed.main.enabled='1'
uci set lanspeed.main.refresh_interval_ms='1000'
uci set lanspeed.main.max_clients='512'
uci add_list lanspeed.main.ifname='br-lan'
uci add_list lanspeed.main.interface_include='br-lan'
uci add_list lanspeed.main.interface_exclude='wan'
uci set lanspeed.main.enable_bpf='1'
uci set lanspeed.main.enable_conntrack_fallback='1'
uci commit lanspeed
/etc/init.d/lanspeedd restart
```

默认配置位于 `/etc/config/lanspeed`。`refresh_interval_ms` 控制刷新周期，`max_clients` 控制客户端表容量，`ifname` 与 `interface_include` 用于声明 LAN 边缘接口，`interface_exclude` 用于排除 WAN、TUN、PPP、WG 等不应作为 LAN 客户端身份来源的接口。

## 兼容性和限制

| 场景 | 结果 | 说明 |
| --- | --- | --- |
| OpenClash fake-ip | Degraded；BPF LAN-edge 仍可在有安全挂载条件时切到 Full | fake-ip 远端地址只作为元数据，不进入客户端身份。可能出现 `openclash_fake_ip_low_remote_confidence`。 |
| OpenClash TUN/mix | 常见为 Degraded 或 low confidence | TUN/mix 会改变路径，conntrack fallback 下可能出现 `openclash_tun_conntrack_low_confidence`。 |
| OpenClash DNS 劫持 | 可能降低解析相关归因 | DNS 链不完整时报告 `openclash_dns_chain_incomplete`。 |
| dae/daed | 可能 Degraded | 代理或 TUN 接口只作为 evidence，不作为 LAN 客户端身份来源。 |
| SQM/qosify/ifb | 可能 medium 或 low confidence | 入口整形、IFB 或已有分类器可能改变可见方向或挂载安全性。 |
| hardware flow offload | Full 不支持 | 硬件转发可能绕过 CPU 可见路径，会报告 `hardware_flow_offload_unsupported`。 |
| software flow offload | 不默认关闭 | 软件卸载会被告警，但不会被本工具自动禁用，也不是默认建议的解决办法。 |
| fullcone NAT | 告警显示 | NAT 辅助路径作为置信度因素显示，不读取 firewall/NAT counter 作为主要数据源。 |
| same-subnet side-router direct | Degraded | 同网段旁路由直连可能产生非对称路径，报告 `asymmetric_path_possible`。 |
| router-local | 单独建模 | 客户端访问路由器服务可按客户端方向计入，路由器自身主动流量归入 `router_self`。 |
| LAN-to-LAN | 可见性有限 | CPU 不可见的硬件交换路径不会被声明完整覆盖，可能出现 `lan_to_lan_visibility_limited`。 |
| VLAN/Wi-Fi | 支持按 zone/VLAN 建模 | 同 MAC 跨 VLAN 会拆成不同身份。Wi-Fi/WDS/AP isolation 仍需真机确认路径。 |
| PPPoE/WG/TUN | 作为上行或隧道 evidence | 不用这些接口的 MAC/IP 生成 LAN 客户端身份。 |

## 重要告警说明

| 告警 ID | 含义 |
| --- | --- |
| `openclash_fake_ip_low_remote_confidence` | OpenClash fake-ip 已启用，远端地址只适合作为元数据。 |
| `openclash_tun_conntrack_low_confidence` | OpenClash TUN/mix 与 conntrack fallback 同时存在时，部分代理路径可能不可见。 |
| `openclash_dns_chain_incomplete` | DNS 劫持配置与可见 DNS 链不一致，解析相关归因可能不可靠。 |
| `hardware_flow_offload_unsupported` | 硬件流量卸载会绕过 CPU 可见指标，Full 模式不支持。 |
| `software_flow_offload_enabled` | 软件流量卸载已启用，部分加速路径的可见性可能受限。 |
| `fullcone_nat_enabled` | Fullcone NAT 已启用，作为 NAT 辅助路径告警展示。 |
| `dae_detected` | 检测到 dae/daed，代理或 TUN 接口不作为 LAN 客户端身份来源。 |
| `tc_filter_conflict` | 已有 TC filter 与 lanspeed 挂载点冲突，daemon 不会覆盖或重排它。 |
| `bpf_runtime_loader_unavailable` | BPF 资产齐备但本次启动没有成功完成 tc 挂载或 map 读取（例如对象缺失、内核缺 BPF 能力、接口非 LAN 边缘、pref/handle 冲突），daemon 会回落到 conntrack 模式，不声明 Full。 |
| `live_metrics_unavailable` | 当前没有可用实时指标；状态应保持 Degraded 或 Unsupported，`capabilities.live_metrics=false`。 |
| `sqm_detected` | 检测到 SQM，IFB 整形可能影响方向或覆盖范围。 |
| `qosify_detected` | 检测到 qosify，已有分类器会保留，指标置信度可能受影响。 |
| `ifb_detected` | 检测到 IFB，入口整形可能改变 CPU 可见路径。 |
| `conntrack_routed_nat_only` | conntrack fallback 只覆盖路由/NAT 流量，不代表全部 LAN-to-LAN。 |
| `flowtable_counter_missing` | 未检测到 flowtable counter，降级采集置信度会降低。 |
| `nlbwmon_counter_conflict` | 检测到 nlbwmon 计数冲突，lanspeed 不读取或清零 nlbwmon counter。 |
| `lan_to_lan_visibility_limited` | LAN-to-LAN 流量如果绕过路由器 CPU，可见性有限。 |
| `asymmetric_path_possible` | 可能存在非对称路径，页面可能只能看到其中一个方向。 |
| `duplicate_mac_across_vlans` | 同一 MAC 出现在多个 VLAN 或区域，页面会按不同身份显示。 |
| `map_full` | BPF 客户端映射表已满，部分客户端可能被省略。 |

## 故障排查

### SDK 缺失或版本不匹配

- 现象：`scripts/build-sdk.sh` 提示 `SDK_DIR` 缺失、不存在或不是 25.12。
- 处理：确认 `SDK_DIR` 指向 ImmortalWrt 25.12 SDK 根目录，而不是本地 feed 目录。使用 `DRY_RUN=1` 先检查命令，不要跳过 ABI guardrail。

### 缺少 BPF 包或对象

- 现象：状态中有 `bpf_optional_package_missing`、`bpf_object_missing`，或 `capabilities.live_metrics=false` 不能进入 Full。
- 处理：用 `ENABLE_BPF=1 ./scripts/build-sdk.sh all` 在 SDK 中构建并安装 `lanspeedd-bpf`，确认目标设备存在 `/usr/lib/bpf/lanspeed_tc.o`。安装后 daemon 启动时会通过 libbpf 在 `/etc/config/lanspeed` 的 `ifname` / `interface_include` 接口上 attach tc ingress+egress，并按 `refresh_interval_ms` 周期读取 BPF map。attach/map-read 成功后才会进入 Full；`tc` 缺失、接口不是 LAN 边缘、和现有 dae/SQM filter 冲突、内核缺 BPF 能力等情况下仍会降级到 `Degraded`。

### 缺少 `tc`

- 现象：`health` 或 LuCI 页面显示 `tc_missing`，BPF LAN-edge 采集不可用。
- 处理：安装提供 `tc` 的 iproute2 相关包，并在目标路由器上重新启动 `lanspeedd`。

### `nf_conntrack_acct` 未启用

- 现象：`conntrack_acct_disabled` 或 `nf_conntrack_acct_disabled`，conntrack fallback 不可用或速率为 0。
- 处理：在目标系统上启用 conntrack accounting 后重启服务。不同固件的启用方式可能不同，需按目标固件配置。

### 没有客户端

- 现象：`ubus call lanspeed clients` 返回空数组，LuCI 显示当前未上报 LAN 客户端。
- 处理：确认 `/etc/config/lanspeed` 的 `ifname`、`interface_include` 指向真实 LAN 边缘，例如 `br-lan`。检查 ARP/ND、DHCP lease、Wi-Fi 客户端和 bridge 成员是否可见。

### 速率长时间为 0 或数据陈旧

- 现象：首次 conntrack fallback 采样后速率为 0，或出现 stale、counter anomaly、time rollback 相关告警。
- 处理：等待第二次采样，确认 `refresh_interval_ms` 合理。若仍为 0，检查流量是否绕过 CPU、是否硬件交换、是否启用了硬件 offload，或是否走 TUN/PPPoE/WG 等排除路径。

### OpenClash 或 dae/daed 共存

- 现象：出现 fake-ip、TUN、DNS 链、dae/daed 相关告警，远端或客户端归因置信度降低。
- 处理：阅读 `health.evidence` 中的 OpenClash/dae 字段，确认代理模式、DNS 链和 TUN 接口。不要把 fake-ip 或 TUN 接口地址当作 LAN 客户端身份。

## 本地文档检查

```sh
./tests/validate-lanspeed-docs.sh
```

该脚本只检查 README 是否包含本任务要求的关键说明，并把结果写入 `.sisyphus/evidence/task-14-doc-check.txt`。它不替代真实 SDK 编译或目标路由器 QA。

## 本地回归和真机 QA 入口

本地回归入口来自 Task 15：

```sh
./tests/run.sh unit
./tests/run.sh probe-fixtures
./tests/run.sh network
./tests/run.sh all
```

`unit` 和 `probe-fixtures` 运行确定性 schema、probe、collector、OpenClash、dae、offload、conntrack 和 SDK dry-run 检查。`network` 只做本地 veth/bridge/clsact 创建清理或安全 SKIP，不代表真实路由器吞吐验收。

真机 QA 入口来自 Task 16：

```sh
# 只生成命令计划，不连接设备
DRY_RUN=1 ./tests/qa-device.sh collect
DRY_RUN=1 ./tests/qa-device.sh iperf
DRY_RUN=1 ./tests/qa-device.sh matrix
DRY_RUN=1 ./tests/qa-device.sh openclash-dae

# 有真实设备时再提供 TARGET，脚本会通过 ssh 收集只读证据
TARGET=root@router ./tests/qa-device.sh collect
```

当前仓库里的 Task 16 证据是 dry-run/mock 语义，不声明真实 ImmortalWrt 25.12 路由器、真实 OpenClash/dae 或真实 iperf 场景已经通过。真实设备验收需要在目标路由器上收集 `ubus`、`tc`、`nft`、UCI、服务状态和测速输出后再判定。
