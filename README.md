# luci-app-lanspeed

`luci-app-lanspeed` 为 ImmortalWrt / OpenWrt 提供 LAN 客户端实时速率、接口吞吐、连接数、逐连接速率、诊断与配置页面。用户态服务 `lanspeedd` 使用 Rust/Aya，提供九个 ubus 方法；`lanspeedd-bpf` 安装目标架构对应的 eBPF 对象。

速率结果表示采集器可观察到的流量。TC-BPF 观察 CPU 可见 LAN 边缘流量，Qualcomm NSS/ECM 路径观察硬件卸载统计。旁路网关、same-subnet side-router direct、LAN-to-LAN、交换芯片桥内转发、驱动 offload 与 PPPoE/WG/TUN/IFB 等路径可能绕过采集点。本项目不是完整流量审计系统，不声明全流量绝对准确。

## 界面预览

截图由真实 Chromium 使用确定性合成数据渲染。客户端使用文档保留地址、虚构主机名与本地管理 MAC，不包含目标设备数据；PNG 元数据已移除。

| 主题 | 实时状态 | 运行诊断 | LAN Speed 配置 |
|---|---|---|---|
| Aurora | [桌面](docs/screenshots/lanspeed-overview-aurora-desktop.png) / [移动](docs/screenshots/lanspeed-overview-aurora-mobile.png) | [桌面](docs/screenshots/lanspeed-diagnostics-aurora-desktop.png) | [桌面](docs/screenshots/lanspeed-config-aurora-desktop.png) |
| Argon | [桌面](docs/screenshots/lanspeed-overview-argon-desktop.png) / [移动](docs/screenshots/lanspeed-overview-argon-mobile.png) | [桌面](docs/screenshots/lanspeed-diagnostics-argon-desktop.png) | [桌面](docs/screenshots/lanspeed-config-argon-desktop.png) |
| Bootstrap | [桌面](docs/screenshots/lanspeed-overview-bootstrap-desktop.png) / [移动](docs/screenshots/lanspeed-overview-bootstrap-mobile.png) | [桌面](docs/screenshots/lanspeed-diagnostics-bootstrap-desktop.png) | [桌面](docs/screenshots/lanspeed-config-bootstrap-desktop.png) |

## 平台模块

x86/TC-BPF 与 Qualcomm NSS 是两个独立源码模块，公共生产循环只负责选择后端并发布统一 RPC 契约。

| 模块 | 用户态源码 | eBPF 源码 | 速率来源 |
|---|---|---|---|
| x86/TC-BPF | `platform/x86/` | `lanspeed-ebpf/src/x86/` | LAN ingress/egress TC map，按 MAC + zone/VLAN 聚合 |
| Qualcomm NSS | `platform/nss/` | `lanspeed-ebpf/src/nss/` | NSS 自有 TC 慢路径、ECM node 与 ECM totals-update kprobe |
| 公共层 | `platform/counters.rs`、`production.rs` | `lanspeed-common` | 无平台计数结构、后端选择、统一响应发布 |

`platform/x86` 与 `platform/nss` 双向零引用。公共调度层把 TC 结果逐字段复制为 NSS 自有 `NssTcSnapshot`，NSS 融合层不接收 x86 类型；两个平台的覆盖率状态、快照、输出、运行时和测试分别归属各自目录。eBPF 构建也分别启用 `x86-tc` 与 `nss-tc` 源入口。x86_64 构建不会安装 ECM 对象，运行时也不会探测 NSS 文件族；aarch64 仅在检测到 Qualcomm NSS/ECM 后开放 NSS 模式。

### x86/TC-BPF

- 非 NSS 设备由 BPF tc 提供客户端速率，x86_64 的自动模式只能落到 BPF。
- 两个对象为 `/usr/lib/bpf/lanspeed-ebpf-kfunc` 与 `/usr/lib/bpf/lanspeed-ebpf-fallback`。
- TC hook 使用固定 owner、pref 和 handle，只管理自身 filter，不删除 clsact 或外部 filter。
- BPF 刷新选择为 `1/2/3/5/10` 秒，daemon 采样使用配置的 `refresh_interval_ms`。
- hardware flow offload 会绕过 CPU TC hook，不能靠 conntrack 字节补齐客户端总速率。

### Qualcomm NSS

Qualcomm aarch64 NSS 设备自动按 ECM+BPF、ECM、BPF 选择健康后端，手动模式失败时不静默切换。

- `nss_ecm_node` 读取 ECM node advanced statistics，使用 `time_added` 区分计数代次。
- `nss_ecm_bpf` 使用 `AYA_BPF_TARGET_ARCH=aarch64` 构建的 `/usr/lib/bpf/lanspeed-ebpf-ecm`，解析 `/sys/kernel/btf/vmlinux` 与 `/sys/kernel/btf/ecm` 后挂载 totals-update 与 NSS callback context kprobe。
- ECM+BPF 将内核已区分的 NSS 硬件增量与 NSS 自有 TC-BPF 慢路径原始增量放入同一采样窗口，只合并一次原始增量并计算一次速率；不叠加已经计算过的速率，也不使用 ECM node totals。
- ECM node、ECM+BPF 最低每 2 秒采样，页面刷新选择为 `2/4/8/10` 秒；自动模式跟随 `effective_collector`。
- 首次快照保持 `warmup/0`。有效相邻计数推进后发布速率，停顿时短暂保留上一完整批次，再明确归零；空闲数分钟后恢复流量也不会产生跨整段空闲期的低速平均值。
- 覆盖率、客户端速率和接口速率使用同一发布批次与 `sample_ms`。覆盖率进入 `pending`，不会阻塞逐客户端速率。
- 物理 LAN MIB 只负责覆盖率验证和窗口预算，不复制客户端速率，不使用插值、动画、钳制或假值。

## 功能

- 实时客户端上行/下行 `tx_bps`、`rx_bps`、累计字节、主机名、地址和连接数。
- LAN 与观察接口吞吐；bridge 与 member 同时配置时只统计独立边界，避免重复计数。
- CT-Netlink 连接统计，失败时回退 CT-Procfs；conntrack 只提供连接数、逐连接详情和目标 IP 元数据。
- 客户端详情按远端 IP 聚合 TCP/UDP 连接，可展开实际连接并排序、分页、暂停刷新。
- 浏览器按当前页查询公网 IP 地理位置；私网、保留地址和 Fake-IP 在本地分类。
- 实时状态、运行诊断、LAN Speed 配置和客户端详情使用同一后端版本与 RPC 契约。
- LuCI 显示完整包版本，例如 `1.1.4-r3`，并使用同一版本作为静态资源缓存键。
- 诊断页独立校验 status、health、clients、interfaces、overview、diagnostics 六个 RPC 请求。
- 配置页支持速率模式、连接模式、采样、活动阈值、IPv6 显示、接口采集/观察和严格输入校验。
- OpenClash、dae/daed、SQM/qosify/ifb、flow offload 与 fullcone NAT 探测和机器可读告警。

## 安装与编译

在 ImmortalWrt / OpenWrt 源码根目录执行：

```sh
# 在 feeds.conf 中添加 lanspeed feed
echo "src-git lanspeed https://github.com/qimaoww/luci-app-lanspeed.git" >> feeds.conf

# 更新并安装
./scripts/feeds update lanspeed
./scripts/feeds install -a -p lanspeed

# 在 menuconfig 中选中 LuCI -> Applications -> luci-app-lanspeed
# BPF 是必选依赖，会自动选择 Network -> lanspeedd-bpf 和 lanspeedd
make menuconfig

# 多线程编译
make -j"$(nproc)" package/lanspeedd/compile
make -j"$(nproc)" package/luci-app-lanspeed/compile
```

`luci-app-lanspeed` 强制依赖 `lanspeedd-bpf`，`lanspeedd-bpf` 依赖 `lanspeedd`。同一个 `package/lanspeedd/compile` 目标根据 SDK 架构生成 TC 对象，并只在 aarch64 生成 ECM 对象。

本地 checkout 可使用：

```sh
SDK_DIR=/openwrt/immortalwrt ENABLE_BPF=1 DRY_RUN=1 scripts/build-sdk.sh
SDK_DIR=/openwrt/immortalwrt ENABLE_BPF=1 scripts/build-sdk.sh
```

`DRY_RUN` 只输出构建步骤；正式产物必须由对应 SDK 重建并在目标设备验证。SDK 缺失时先确认 `SDK_DIR` 指向真实 OpenWrt/ImmortalWrt SDK 或源码树。

## 包组成

| 包 | 内容 |
|---|---|
| `lanspeedd` | Rust daemon、UCI 读取、ubus、采集调度、连接与历史状态 |
| `lanspeedd-bpf` | TC-BPF 对象；aarch64 包额外包含独立 NSS ECM kprobe 对象 |
| `luci-app-lanspeed` | LuCI 实时状态、运行诊断、配置和客户端详情模块 |

运行依赖包括 `libgcc`、`kmod-nf-conntrack-netlink`、`tc-full` 与 `kmod-sched-bpf`。daemon 的 ubus/blobmsg、uloop、UCI 与 CT-Netlink 用户态实现为 Rust，不要求目标固件提供相应客户端库 ABI；APK 架构、musl、内核 BPF/BTF 和 LuCI ABI 仍必须与目标固件匹配。

## 支持范围

| 目标 | 支持 |
|---|---|
| `x86_64` LP64 | TC-BPF；自动与 BPF 模式，不构建或安装 ECM 对象 |
| `aarch64` LP64 | TC-BPF；检测到 Qualcomm NSS/ECM 时提供 ECM 与 ECM+BPF |
| 32 位 ARM、i386 和 MIPS | Unsupported |

用户态和 eBPF workspace 要求稳定版 `Rust >= 1.87.0`。兼容矩阵逐版验证了 `1.87.0` 到 `1.97.1` 的每个稳定版，并覆盖低于 MSRV 的拒绝、内部 atomic intrinsic 的版本转折点、`EM_BPF` 与 aarch64-musl。完整证据见 [Rust compatibility matrix](docs/rust-compatibility-matrix.md)。

交叉编译通过不等于具体设备已完成真机验证。x86_64、aarch64_generic、aarch64_cortex-a53、aarch64_cortex-a72 与 aarch64_cortex-a76 产物必须使用声明的包架构和对应 SDK。

## 内核配置

```text
CONFIG_DEVEL=y
CONFIG_KERNEL_DEBUG_INFO=y
CONFIG_KERNEL_DEBUG_INFO_BTF=y
CONFIG_KERNEL_BPF_EVENTS=y
CONFIG_PACKAGE_kmod-nf-conntrack=y
CONFIG_PACKAGE_kmod-nf-conntrack-netlink=y
CONFIG_PACKAGE_kmod-sched-bpf=y
CONFIG_PACKAGE_tc-full=y
```

ECM+BPF 还要求可读的 `/sys/kernel/btf/ecm` 和受支持的 `ecm_db_connection_data_totals_update` / NSS callback symbol。ECM node 要求可读 `/dev/ecm_state` 与对应 debugfs 控制文件。

## 配置

LuCI 入口：

- `状态 -> 客户端网速 -> 实时状态`
- 点击客户端名称进入客户端详情
- `状态 -> 客户端网速 -> 运行诊断`
- `状态 -> 客户端网速 -> LAN Speed 配置`

核心 UCI：

```uci
config lanspeed 'main'
    option refresh_interval_ms '1000'
    option active_client_window_ms '10000'
    option active_client_min_bps '1'
    option overview_window_samples '240'
    option rate_collector_mode 'auto'
    option conn_collector_mode 'auto'
    option show_client_status '0'
    option show_ipv6 '1'
    option hide_private_ipv6 '0'
    option hide_ipv6_ranges 'fc00::/7 fe80::/10'
    option max_clients '2048'
    list interface_include 'br-lan'
    list observe 'wan'
    option enable_bpf '1'
    option enable_conntrack_fallback '1'
```

| 选项 | 默认 | 当前行为 |
|---|---:|---|
| `refresh_interval_ms` | `1000` | BPF daemon 采样周期；NSS 实际周期不低于 2000 ms |
| `active_client_window_ms` | `10000` | 活跃客户端最近可见窗口 |
| `active_client_min_bps` | `1` | 活跃客户端最低速率 |
| `overview_window_samples` | `240` | 概览历史样本数 |
| `rate_collector_mode` | `auto` | `auto` / `bpf` / `nss_ecm_node` / `nss_ecm_bpf`，NSS 选项按运行能力显示 |
| `conn_collector_mode` | `auto` | `auto` / `conntrack_netlink` / `conntrack_procfs` |
| `max_clients` | `2048` | 客户端与聚合容量，范围 64 到 16384 |
| `interface_include` | `br-lan` | 客户端速率采集接口 |
| `observe` | `wan` | 仅显示接口吞吐 |
| `enable_bpf` | `1` | BPF 运行开关，不改变包依赖 |
| `enable_conntrack_fallback` | `1` | 连接元数据回退，不参与客户端总速率 |

客户端详情中的主机名编辑按 MAC 写入 `/etc/config/dhcp` 的 `option mac` 与 `option name`，不强制静态 IP。

## ubus 调试

```sh
ubus call lanspeed status
ubus call lanspeed clients
ubus call lanspeed overview
ubus call lanspeed health
ubus call lanspeed diagnostics
ubus call lanspeed reload
ubus call lanspeed interfaces
ubus call lanspeed sysdevices
ubus call lanspeed client_connections \
  '{"identity_key":"02:00:00:00:00:42@br-lan"}'
```

九个 ubus 方法返回统一版本和结构化 evidence。状态 `mode` 为 `Full`、`Degraded` 或 `Unsupported`，`confidence` 为 `high`、`medium`、`low` 或 `unsupported`。`router_self` 标识路由器自身流量语义；连接详情的方向始终以客户端为准。

`client_connections` 返回当前 conntrack 快照：TCP 仅统计 ESTABLISHED + ASSURED，UDP 仅统计 ASSURED。每条连接的 `tx_bps` / `rx_bps` 使用相邻累计字节快照计算，新连接、计数器回退或时间回退不会生成虚假速率。

## 可见性与告警

| 场景 | 当前行为或告警 |
|---|---|
| OpenClash fake-ip | `openclash_fake_ip_low_remote_confidence` |
| OpenClash TUN/mix | `openclash_tun_conntrack_low_confidence` |
| OpenClash DNS 链不完整 | `openclash_dns_chain_incomplete` |
| dae/daed | `dae_detected`；TC-BPF 可事务切换 Early passthrough |
| SQM/qosify/ifb | `sqm_detected`、`qosify_detected`、`ifb_detected` |
| hardware flow offload | `hardware_flow_offload_unsupported` |
| software flow offload | `software_flow_offload_enabled` |
| fullcone NAT | `fullcone_nat_enabled` |
| 外部 TC filter | `tc_filter_conflict` |
| conntrack NAT-only 行 | `conntrack_routed_nat_only` |
| flowtable / nlbwmon | `flowtable_counter_missing`、`nlbwmon_counter_conflict` |
| LAN-to-LAN | `lan_to_lan_visibility_limited` |
| 不对称路径 | `asymmetric_path_possible` |
| VLAN/Wi-Fi 重复 MAC | `duplicate_mac_across_vlans` |
| BPF map 容量耗尽 | `map_full` |
| router-local | 不自然归属为 LAN 客户端 |
| PPPoE/WG/TUN | 外层可观察，客户端身份仍由 LAN 边缘决定 |

## 故障排查

| 现象 | 检查 |
|---|---|
| SDK 缺失 | 检查 `SDK_DIR` 与目标架构 |
| 缺少 BPF 包或对象 | 确认 `lanspeedd-bpf` 及 `/usr/lib/bpf/lanspeed-ebpf-*` |
| 缺少 `tc` | 安装 `tc-full` 并检查 clsact/filter |
| 连接数为 0 | 检查 `nf_conntrack_acct`、Netlink 模块和连接采集模式 |
| 没有客户端 | 检查 LAN 接口分配、BPF attach、ECM node MAC 映射 |
| 速率长时间为 0 | 检查 `effective_collector`、map/state 可读性和 `sample_ms` |
| OpenClash 或 dae/daed 共存 | 检查 TC hook 模式、NSS state 和诊断 evidence |
| 覆盖率低 | 检查 offload、旁路路径、LAN-to-LAN、IFB/TUN 和接口边界 |

## 项目结构

```text
applications/luci-app-lanspeed/
  htdocs/luci-static/resources/lanspeed/      状态、诊断、配置、客户端详情
net/lanspeedd/rust/crates/lanspeedd/src/
  platform/x86/                              x86/TC-BPF 覆盖率、运行时、快照、输出
  platform/nss/                              NSS-BPF 覆盖率、TC 契约、ECM、窗口、融合、输出
  collectors/conntrack/                      连接元数据
  production.rs                              公共调度与统一 RPC 发布
net/lanspeedd/rust/crates/lanspeed-ebpf/src/
  x86/                                       x86 TC accounting 与 conntrack kfunc
  nss/                                       NSS TC accounting、conntrack kfunc 与 ECM kprobe
net/lanspeedd/rust/crates/lanspeed-common/    用户态/eBPF ABI
net/lanspeedd/rust/crates/lanspeed-build/     OpenWrt 构建驱动
tests/                                       单元、契约、打包和浏览器回归
```

## 测试

本地环境可以运行确定性检查脚本：

```sh
./tests/run.sh unit
./tests/run.sh probe-fixtures
cargo test -p lanspeedd --features openwrt
sh tests/validate-lanspeed-docs.sh
```

这些检查覆盖平台模块边界、Rust 单元测试、eBPF 对象、RPC/schema、LuCI 模块、探针 fixtures 与打包契约。最终验收还需要真实 SDK 编译、目标设备安装，以及真实浏览器检查实时状态、运行诊断、配置和客户端详情。

## 发布

`main` 分支上的 `net/lanspeedd/Makefile` 或 `applications/luci-app-lanspeed/Makefile` 完整版本发生变化时，发布 workflow 为 x86_64 和四种 aarch64 包架构构建三个 APK。Rust 主机工具链按 runner 操作系统与架构、目标架构、SDK SHA256、feeds 实际 revision、Rust 配方版本和内容哈希隔离缓存，后续相同 SDK 不再从头编译 Rust。

workflow 先创建草稿 Release，校验全部架构资产后再发布。失败的草稿可由同一版本提交通过 `workflow_dispatch` 自动重建；手动运行也可补发缺失的 tag/Release。维护者不得预先创建 `v*` tag。

## License

Apache-2.0
