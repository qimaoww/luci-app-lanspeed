# luci-lanspeed

> 本仓库所有代码及文档（包括本 README）均由 AI 生成。

LAN 侧按客户端实时吞吐监控 + TCP/UDP 连接数统计，当前面向 ImmortalWrt 25.12。

后端用户态 daemon 与 tc/eBPF 程序均使用 Rust 实现；OpenWrt 的 ubus、uloop 和 UCI 通过 Rust FFI 调用系统 ABI，仓库不再保留项目自有 C 后端。

本项目的定位是观察 CPU 可见 LAN 边缘流量：它不是完整流量审计系统，不声明全流量绝对准确。硬件加速、旁路网关、同网段直连、桥内转发、驱动 offload、代理 TUN/IFB 等路径可能让部分流量绕过 CPU 或改变可见方向。

## 特性

- **实时速率**：BPF tc 按 MAC + zone/VLAN 直接计数，字段为 `tx_bps` / `rx_bps`；非 NSS / x86 场景测速只使用 BPF；`auto` 模式检测到 dae/daed 进程后立即优先使用 BPF。
- **连接数统计**：优先 CT-Netlink 读取 conntrack accounting，失败自动回退 CT-Procfs；TCP、UDP、DNS UDP 分开统计。
- **NSS 兼容**：Qualcomm NSS 设备自动展示 ECM/PPE 状态；NSS 设备默认以 NSS sync / CT-Netlink 作为稳定来源，NSS-direct 只在读到有效 ECM state flow 时补充；IPv4 通过 ARP、IPv6 通过 neighbor 表匹配客户端，并兼容 ECM NAT 端点。
- **活跃客户端**：默认只把 10 秒内仍有有效速率的客户端计为 active，可通过 UCI 调整。
- **覆盖率**：daemon 侧滑动窗口计算上下行覆盖率，避免前端采样窗口错位。
- **配置页面**：LuCI 内置“实时状态”和“LAN Speed 配置”两个页签，速率采集、连接数采集、活跃客户端阈值和接口配置可分开调整，并由页面底部的统一按钮一次保存、提交和重载；NSS 设备会显示 NSS 专属说明。
- **接口配置**：采集 / 观察 / 关闭 三态切换，默认采集 `br-lan`、观察 `wan`；自动忽略 `dae*`、`miireg*`、`tun*`、`erspan*`、`gretap*`、`gre*`、`ip6gre*`、`ip6tnl*`、`sit*`、`bonding_masters*`，拒绝 nssifb 采集并可观察 WAN / ifb 计数。
- **告警体系**：OpenClash / dae/daed / SQM/qosify/ifb / flow offload / fullcone NAT 等场景自动识别并提示。
- **版本显示**：LuCI 状态页显示完整版本，例如 `1.0.0-r1`。

## 采集策略

### 速率采集

`rate_collector_mode` 控制客户端实时速率：

| 值 | 行为 |
|---|---|
| `auto` | 默认模式。普通设备优先 BPF；NSS ECM/PPE 设备使用 NSS sync / CT-Netlink 作为稳定来源，NSS-direct 有有效 flow 时补充；检测到 dae/daed 正在运行且 BPF 可用时优先使用 BPF。 |
| `bpf` | 只使用 BPF 测速；非 NSS / x86 / dae/daed 推荐保持此模式或 auto。 |
| `nss_ecm_direct` | 手动尝试 NSS-direct；direct 没有有效速率时仍使用 NSS sync 后备，避免显示 0。 |
| `nss_conntrack_sync` | 强制使用 NSS sync；只适合 NSS ECM/PPE 设备排查或 direct 不可用时使用。 |

非 NSS 设备不会把 CT 当作实时测速来源。CT 只能用于连接数、诊断和 NSS ECM/PPE sync 这类明确标注的 fallback。

daemon 每个采样周期都由 Rust 直接扫描 `/proc/<pid>/comm`，只把精确名称为 `dae` 或 `daed` 的进程视为运行态，不依赖 `pidof` 或慢速环境探测缓存。检测到运行态后会把 LAN BPF 从 Normal（pref `49152`）事务切换到 Early passthrough（pref `1`），进程停止后切回 Normal；切换复用 reload 的 suspend/attach/rollback 流程并保留外部 tc filter。自动模式选择 BPF 时显示 `dae_runtime_prefers_bpf`；NSS 设备在 BPF 不可用时回退 NSS sync，并显示 `nss_dae_bpf_fallback_may_be_inaccurate`。

NSS-direct 指 daemon 只读 qca-nss-ecm 的 state 设备（`/dev/ecm_state` 或 debugfs major 在 `/dev` 下创建的临时只读节点），解析 ECM flow 的 `adv_stats.from_data_total` / `adv_stats.to_data_total`，再按两端 IP、NAT IP 和 node MAC 匹配 LAN 客户端。它不写 `defunct_all`、`flush`、`decelerate`，也不修改 NSS 状态。部分固件的 ECM state 可能没有活跃 flow、计数为 0 或覆盖不完整，此时会显示 `nss_direct_no_data` / `nss_direct_partial`，并用 NSS sync 补齐。

NSS ECM/PPE sync 指 NSS 硬件加速 flow 的字节计数同步回 conntrack 后，daemon 再读取 CT-Netlink / CT-Procfs 的 accounting 计数。这个路径会匹配 conntrack 原始方向和回复方向的源/目的端点，按 LAN 客户端视角换算上下行；只在 NSS ECM/PPE 场景作为实时速率来源，非 NSS 设备不会把 conntrack 当作实时测速来源。

### 连接数采集

`conn_collector_mode` 控制 TCP/UDP 连接数来源：

| 值 | 行为 |
|---|---|
| `auto` | 优先 CT-Netlink，失败回退 CT-Procfs。 |
| `conntrack_netlink` | 强制使用 CT-Netlink。 |
| `conntrack_procfs` | 强制使用 `/proc/net/nf_conntrack`。 |

连接数语义为 `conntrack_current_tcp_established_assured_udp_assured_dns_split`：TCP 统计已建立/确认连接，UDP 只统计已确认（ASSURED）的 conntrack 项，并把 DNS UDP 单独拆分。

## 包组成

| 包 | 说明 |
|---|---|
| `lanspeedd` | Rust/Aya daemon，暴露 ubus 方法（status / clients / overview / health / interfaces / sysdevices / reload）；不选 BPF 包时也会完整编译用户态后端 |
| `lanspeedd-bpf` | 可选，安装 Rust 编译的 kfunc 与 fallback 两套 tc/eBPF 对象（含 ct_lookup + seen_tuples 去重 map）；选择 LuCI 应用且构建配置提供 `HAS_BPF_TOOLCHAIN` 时默认选中 |
| `luci-app-lanspeed` | LuCI 状态页和配置页，模块化前端（vocab / format / rpc / ifaceConfig / nssPanel / version） |

## 编译

### 获取源码

```sh
git clone https://github.com/qimaoww/luci-app-lanspeed.git package/lanspeed
```

### 版本支持

| OpenWrt / ImmortalWrt | 说明 |
|---|---|
| ImmortalWrt 25.12 | 支持。当前构建、打包和路由器实测目标。 |
| OpenWrt 23.05 | 不支持。官方 SDK 的 Rust 版本和 libubox ABI 不满足当前完整 Rust 后端。 |
| OpenWrt 21.02 及更早版本 | 不支持。BPF/BTF、Rust 工具链、OpenWrt ABI 和 LuCI 运行时差异过大。 |

构建驱动固定要求 `Rust 1.94.0`，并校验 `bpf-linker 0.10.3`。不要用较旧 SDK 的 `rust/host` 绕过版本检查；即使能编译，ubus/uloop/UCI 的目标 ABI 也可能不兼容。

### 基础包与 BPF 可选包

- `lanspeedd` 基础包始终编译 Rust 用户态 daemon，不要求 BPF 对象、`bpf-linker` 或 `libbpf` 运行时，适合 NSS-direct / 只看 conntrack 的路由器。
- 只有选中 `lanspeedd-bpf` 时，才会使用固定版本的 `bpf-linker` 构建两套 Rust eBPF 对象；目标机需要 `tc-tiny` 和 `kmod-sched-bpf`。
- 当前固定的 `bpf-linker` 发布包要求 x86_64 编译主机，目标路由器架构仍由 OpenWrt SDK 决定。
- 非 NSS / x86 / dae/daed 场景如果要实时测速，仍然需要 `lanspeedd-bpf`；否则只保留连接数、环境检查和 NSS/conntrack 诊断能力。

### 内核与包配置要求（仅 `lanspeedd-bpf`）

```
CONFIG_DEVEL=y
CONFIG_KERNEL_DEBUG_INFO=y
CONFIG_KERNEL_DEBUG_INFO_BTF=y
CONFIG_KERNEL_BPF_EVENTS=y
CONFIG_PACKAGE_kmod-nf-conntrack=y
CONFIG_PACKAGE_kmod-nf-conntrack-netlink=y
CONFIG_PACKAGE_kmod-sched-bpf=y
CONFIG_PACKAGE_tc-tiny=y
```

不启用 `lanspeedd-bpf` 时，daemon 仍可显示连接数与环境诊断；NSS 设备仍可走 NSS-direct / ECM/PPE sync 相关路径，但普通非 NSS 设备不会把 conntrack 当成实时客户端测速。

### 运行时依赖

| 包 | 必需 | 说明 |
|---|---|---|
| `libubox` | yes | ubus / uloop 基础库 |
| `libubus` | yes | ubus 通信 |
| `libuci` | yes | UCI 配置读取 |
| `libblobmsg-json` | yes | Rust JSON 与 ubus blobmsg 的桥接 |
| `kmod-nf-conntrack` | yes | conntrack 表访问 |
| `kmod-nf-conntrack-netlink` | yes | CT-Netlink 连接数读取 |
| `tc-tiny` (iproute2) | `lanspeedd-bpf` | tc clsact 挂载 |
| `kmod-sched-bpf` | `lanspeedd-bpf` | 内核 tc BPF classifier 支持 |
| `luci-base` | LuCI 页面 | LuCI 框架 |

用户态 JSON 使用 `serde_json`，CT-Netlink 使用 Rust 原始 netlink 实现，eBPF 对象由 Aya 加载，不直接依赖 `libjson-c`、`libmnl` 或 `libbpf`。NSS-direct 不额外依赖用户态库，但需要内核侧 qca-nss-ecm 暴露 ECM state 设备；不可用或没有可匹配 flow 时会使用 NSS sync。IPv6 客户端匹配依赖内核 neighbor 表；前端隐藏 IPv6 只影响显示，不影响采集匹配。

### 编译命令

```sh
make menuconfig
# Network -> lanspeedd
# Network -> lanspeedd-bpf   # LuCI + HAS_BPF_TOOLCHAIN 时默认选中，也可按需关闭
# LuCI -> Applications -> luci-app-lanspeed

make package/lanspeed/lanspeedd/compile V=s   # 选中 lanspeedd-bpf 时会一并产出 BPF 对象
make package/lanspeed/luci-app-lanspeed/compile V=s
```

也可以使用仓库脚本：

```sh
SDK_DIR=/openwrt/immortalwrt ENABLE_BPF=0 DRY_RUN=1 scripts/build-sdk.sh
SDK_DIR=/openwrt/immortalwrt ENABLE_BPF=0 scripts/build-sdk.sh
SDK_DIR=/openwrt/immortalwrt ENABLE_BPF=1 scripts/build-sdk.sh
```

ABI 注意点：包必须用目标固件对应的 25.12 SDK 编译，不能混用其他分支的 libubox/libubus/libuci 或 kernel ABI，也不能把 `lanspeedd-bpf` 安装到不同内核构建上。

当前只声明支持并验证 x86_64 和 aarch64 两类 LP64 目标；32 位 ARM、i386 和 MIPS 不在支持范围内。GitHub Actions 在 `v*` tag 发布时会编译这两类产物，aarch64 产物使用官方 `armsr/armv8` SDK 编译，Release 文件名带 `aarch64` 后缀。

## 安装、启动与回滚

升级前保存目标机当前已安装的 lanspeed APK 与 `/etc/config/lanspeed`；本地测试包未被目标机信任时需要 `--allow-untrusted`。若使用 BPF，把 daemon、BPF、LuCI 三个匹配包放在同一次 `apk add` 中；不使用 BPF 时，只把本次需要升级的匹配包放在同一事务中，不应安装 BPF 包。`--force-reinstall` 避免同版本包不替换，单事务避免人为分步安装造成短暂混合版本。下列无架构后缀的文件名是本次 x86_64 实测示例；aarch64 Release 文件名带 `-aarch64`，应按实际产物替换路径。

```sh
apk add --force-reinstall --allow-untrusted \
	/tmp/lanspeedd-1.0.0-r1.apk \
	/tmp/lanspeedd-bpf-1.0.0-r1.apk \
	/tmp/luci-app-lanspeed-1.0.0-r1.apk
```

```sh
/etc/init.d/lanspeedd enable
/etc/init.d/lanspeedd restart
```

回滚时也要在同一个 APK 事务中强制重新安装已保存的匹配 legacy APK，然后恢复配置并重启服务；不要只回滚 daemon 而保留不匹配的 BPF 包。下列三个文件名对应本次 x86_64 实测设备备份的已安装旧包，不代表它们属于同一 release；实际回滚应以升级前保存的文件名为准。例如旧包和配置分别保存在 `/tmp/legacy` 下：

```sh
apk add --force-reinstall --allow-untrusted \
	/tmp/legacy/lanspeedd-0.1.7-r1.apk \
	/tmp/legacy/lanspeedd-bpf-0.1.7-r1.apk \
	/tmp/legacy/luci-app-lanspeed-0.1.6-r1.apk
cp /tmp/legacy/lanspeed /etc/config/lanspeed
/etc/init.d/lanspeedd restart
```

LuCI 入口：

- `状态 -> 客户端网速 -> 实时状态`
- `状态 -> 客户端网速 -> LAN Speed 配置`

## 配置

`/etc/config/lanspeed`：

```uci
config lanspeed 'main'
    option enabled '1'
    option refresh_interval_ms '1000'
    option active_client_window_ms '10000'
    option active_client_min_bps '1'
    option overview_window_samples '240'
    option rate_collector_mode 'auto'
    option conn_collector_mode 'auto'
    option show_ipv6 '1'
    option hide_private_ipv6 '0'
    option hide_ipv6_ranges 'fc00::/7 fe80::/10'
    option collector_mode 'auto'
    option max_clients '2048'
    list ifname 'br-lan'
    list interface_include 'br-lan'
    list interface_exclude 'wan'
    list observe 'wan'
    option enable_bpf '1'
    option enable_conntrack_fallback '1'
```

常用 UCI：

```sh
uci set lanspeed.main.enabled='1'
uci set lanspeed.main.rate_collector_mode='auto'
uci set lanspeed.main.conn_collector_mode='auto'
uci set lanspeed.main.active_client_window_ms='10000'
uci set lanspeed.main.active_client_min_bps='1'
uci set lanspeed.main.show_ipv6='1'
uci set lanspeed.main.hide_private_ipv6='0'
uci set lanspeed.main.hide_ipv6_ranges='fc00::/7 fe80::/10'
uci commit lanspeed
/etc/init.d/lanspeedd restart
```

配置说明：

| 选项 | 默认 | 说明 |
|---|---:|---|
| `refresh_interval_ms` | `1000` | daemon 采样间隔。 |
| `active_client_window_ms` | `10000` | 活跃客户端最近可见窗口，低于 1000 会被钳制。 |
| `active_client_min_bps` | `1` | 活跃客户端最低当前速率，低于 1 会被钳制。 |
| `overview_window_samples` | `240` | 趋势/概览样本窗口。 |
| `rate_collector_mode` | `auto` | 速率采集：`auto` / `bpf` / `nss_ecm_direct` / `nss_conntrack_sync`。 |
| `conn_collector_mode` | `auto` | 连接数采集：`auto` / `conntrack_netlink` / `conntrack_procfs`。 |
| `show_ipv6` | `1` | 客户端列表是否显示 IPv6 地址。 |
| `hide_private_ipv6` | `0` | 是否隐藏 `fc00::/7` 私有 IPv6 地址和 `fe80::/10` 链路本地地址；公网 IPv6 不受影响。 |
| `hide_ipv6_ranges` | `fc00::/7 fe80::/10` | 自定义隐藏 IPv6 CIDR，空格或逗号分隔；仅在 `hide_private_ipv6=1` 时生效。 |
| `collector_mode` | `auto` | 旧配置兼容字段，新配置页会同步到速率模式。 |
| `enable_bpf` | `1` | 是否启用 BPF 速率采集。 |
| `enable_conntrack_fallback` | `1` | 是否允许 conntrack 连接数和 NSS sync fallback。 |

## ubus 调试

```sh
ubus call lanspeed status       # Full / Degraded / Unsupported、high / medium / low / unsupported、能力、告警、版本
ubus call lanspeed clients      # 客户端 tx_bps/rx_bps + TCP/UDP/DNS 连接数
ubus call lanspeed overview     # 总速率、客户端数、active_clients、连接数窗口
ubus call lanspeed health       # 健康检查 + 冲突检测
ubus call lanspeed interfaces   # 接口吞吐 + 覆盖率
ubus call lanspeed sysdevices   # 系统网络设备列表
```

关键字段：

| 字段 | 说明 |
|---|---|
| `mode` | `Full` / `Degraded` / `Unsupported`。 |
| `confidence` | `high` / `medium` / `low` / `unsupported`。 |
| `collector_mode` | 兼容旧字段，当前等价于速率配置视角。 |
| `rate_collector_mode` | 实时速率配置。 |
| `conn_collector_mode` | 连接数配置。 |
| `conn_source` | 实际连接数来源：`nss_ecm_direct` / `conntrack_netlink` / `conntrack_procfs` / `conntrack`。 |
| `conn_semantics` | 连接数统计语义。 |
| `coverage` | daemon 侧滑动窗口覆盖率。 |
| `active_client_window_ms` | 活跃客户端窗口。 |
| `active_client_min_bps` | 活跃客户端最小速率。 |
| `router_self` | 路由器自身流量/代理链路的识别提示。 |

## 兼容性与边界

| 场景 | 影响 |
|---|---|
| OpenClash fake-ip | 远端地址置信度降低，可能出现 `openclash_fake_ip_low_remote_confidence`。 |
| OpenClash TUN/mix | TUN/mix 会改变 hook 顺序，可能出现 `openclash_tun_conntrack_low_confidence`。 |
| OpenClash DNS 链 | DNS 重定向链不完整时会提示 `openclash_dns_chain_incomplete`。 |
| dae/daed | 代理接口不作为客户端身份，探测到时提示 `dae_detected`；运行态每个采样周期由 `/proc/<pid>/comm` 刷新，自动模式在 BPF 可用时提示 `dae_runtime_prefers_bpf` 并切到 Early passthrough，BPF 不可用时提示 `nss_dae_bpf_fallback_may_be_inaccurate`。 |
| SQM/qosify/ifb | 可能影响方向判断或覆盖范围，对应 `sqm_detected`、`qosify_detected`、`ifb_detected`。 |
| hardware flow offload | 硬件转发绕过 CPU，BPF 不可见，提示 `hardware_flow_offload_unsupported`。 |
| software flow offload | 告警但不阻止采集，提示 `software_flow_offload_enabled`。 |
| fullcone NAT | 连接语义可能受影响，提示 `fullcone_nat_enabled`。 |
| NSS ECM / PPE | NSS sync / CT-Netlink 是稳定来源；NSS-direct 有有效 ECM state flow 时补充；PPE direct 第一版只探测状态，不写 NSS 状态。 |
| nssifb | 只能观察，不允许作为 BPF 采集接口，避免镜像接口重复计数。 |
| same-subnet side-router direct | 同网段旁路由直连可能绕过主路由，提示 `same-subnet side-router direct` 相关风险。 |
| router-local | 路由器本机进程流量不会自然映射成 LAN 客户端。 |
| LAN-to-LAN | 桥内或交换芯片内转发 CPU 不可见，可能提示 `lan_to_lan_visibility_limited`。 |
| VLAN/Wi-Fi | 使用 MAC + zone/VLAN 区分身份；重复 MAC 可能提示 `duplicate_mac_across_vlans`。 |
| PPPoE/WG/TUN | PPPoE/WG 外层接口可观察，TUN 配置候选自动忽略；客户端身份仍以 LAN 边缘为准，路径不对称时可能提示 `asymmetric_path_possible`。 |
| flowtable counter | 缺失计数会提示 `flowtable_counter_missing`。 |
| nlbwmon | 同类计数器共存可能提示 `nlbwmon_counter_conflict`。 |
| conntrack fallback | 非 NSS 不用于实时测速，只用于连接数和诊断；NAT-only 可提示 `conntrack_routed_nat_only`。 |
| tc 冲突 | 发现外部 tc filter 可能提示 `tc_filter_conflict`。 |
| BPF map 满 | 客户端超过容量可能提示 `map_full`。 |

## 故障排查

| 现象 | 检查 |
|---|---|
| SDK 缺失 | 确认 `SDK_DIR` 指向真实 SDK，例如 `/openwrt/immortalwrt`。 |
| 缺少 BPF 包或对象 | 安装 `lanspeedd-bpf`，检查 `/usr/lib/bpf/lanspeed-ebpf-kfunc` 和 `/usr/lib/bpf/lanspeed-ebpf-fallback`。 |
| 缺少 `tc` | 安装 `tc-tiny` 或完整 iproute2。 |
| 连接数全 0 | 检查 `nf_conntrack_acct`、`kmod-nf-conntrack-netlink`、`conn_collector_mode`。 |
| 没有客户端 | 检查 LAN 接口配置、桥设备、BPF 是否 attach 成功。 |
| 速率长时间为 0 | 检查 `rate_collector_mode`、BPF 包、tc filter、硬件 flow offload；NSS 设备还要看 `nss_ecm_direct_unavailable` / `nss_ecm_direct_snapshot_pending`；IPv6 场景同时检查客户端是否出现在 neighbor 表。 |
| OpenClash 或 dae/daed 共存 | 优先确认 BPF attach 在 LAN 边缘，观察 health 里的 warning；NSS+daed 回退 NSS 时会提示速率可能不准。 |
| 覆盖率低 | 检查硬件 offload、旁路网关、LAN-to-LAN、IFB/TUN 等 CPU 不可见路径。 |

## 项目结构

```
applications/luci-app-lanspeed/
  htdocs/luci-static/resources/
    lanspeed/                      模块 (vocab/format/rpc/ifaceConfig/nssPanel/version)
    view/lanspeed/index.js         实时状态入口
    view/lanspeed/config.js        LAN Speed 配置页面
net/lanspeedd/
  rust/crates/lanspeedd/           Rust daemon、采集器、状态机和 ubus 逻辑
  rust/crates/lanspeed-ebpf/       Rust/Aya eBPF 程序 (tc ingress/egress + ct_lookup)
  rust/crates/lanspeed-common/     用户态与 eBPF 共用 ABI
  rust/crates/lanspeed-openwrt-sys/ OpenWrt ubus/uloop/UCI FFI
  rust/crates/lanspeed-build/      OpenWrt 用户态与 eBPF 构建驱动
  src/collector-model.json         采集模型说明
  files/                           设备端文件 (init.d / UCI config / schema)
scripts/build-sdk.sh               SDK 编译辅助脚本
.github/workflows/build-sdk.yml    GitHub Actions 自动编译
tests/                             本地回归测试
```

## 测试

本地环境可以运行确定性检查脚本和不依赖目标 ABI 的 Rust 单元/合约测试；`./tests/run.sh unit` 覆盖 `lanspeedd`、共享 ABI、构建驱动和 fixtures。`lanspeed-openwrt-sys` 直接链接目标端 ubus/uloop/UCI，不在 glibc host 上执行，其绑定通过可重复生成检查，并由真实 SDK 编译（ImmortalWrt 25.12）和目标设备（路由器）测试覆盖。构建使用固定的 Rust 1.94.0。

```sh
./tests/run.sh unit
sh tests/validate-lanspeed-docs.sh
```

## License

Apache-2.0
