# luci-lanspeed

> 本仓库所有代码及文档（包括本 README）均由 AI 生成。

LAN 侧按客户端实时吞吐监控 + TCP/UDP 连接数统计，适用于 ImmortalWrt 25.12 / OpenWrt 23.05 等路由器环境。

本项目的定位是观察 CPU 可见 LAN 边缘流量：它不是完整流量审计系统，不声明全流量绝对准确。硬件加速、旁路网关、同网段直连、桥内转发、驱动 offload、代理 TUN/IFB 等路径可能让部分流量绕过 CPU 或改变可见方向。

## 特性

- **实时速率**：BPF tc 按 MAC + zone/VLAN 直接计数，字段为 `tx_bps` / `rx_bps`；非 NSS / x86 / daed 场景测速只使用 BPF。
- **连接数统计**：优先 CT-Netlink 读取 conntrack accounting，失败自动回退 CT-Procfs；TCP、UDP、DNS UDP 分开统计。
- **NSS 兼容**：Qualcomm NSS 设备自动展示 ECM/PPE 状态；NSS ECM 可用时优先 NSS-direct 只读 ECM state flow 字节计数，失败再回退 ECM sync。
- **活跃客户端**：默认只把 10 秒内仍有有效速率的客户端计为 active，可通过 UCI 调整。
- **覆盖率**：daemon 侧滑动窗口计算上下行覆盖率，避免前端采样窗口错位。
- **配置页面**：LuCI 内置“实时状态”和“LAN Speed 配置”两个页签，速率采集、连接数采集、活跃客户端阈值和接口配置可分开调整。
- **接口配置**：采集 / 观察 / 关闭 三态切换，自动拒绝 nssifb 采集并可观察 WAN / tun / ifb 计数。
- **告警体系**：OpenClash / dae/daed / SQM/qosify/ifb / flow offload / fullcone NAT 等场景自动识别并提示。
- **版本显示**：LuCI 状态页显示完整版本，例如 `0.1.1-r6`。

## 采集策略

### 速率采集

`rate_collector_mode` 控制客户端实时速率：

| 值 | 行为 |
|---|---|
| `auto` | 默认模式。普通设备优先 BPF；NSS ECM 设备优先 NSS-direct，失败再允许 ECM sync 兜底。 |
| `bpf` | 只使用 BPF 测速；非 NSS / x86 / daed 推荐保持此模式或 auto。 |

非 NSS 设备不会把 CT 当作实时测速来源。CT 只能用于连接数、诊断和 NSS ECM sync 这类明确标注的 fallback。

NSS-direct 指 daemon 只读 qca-nss-ecm 的 state 设备（`/dev/ecm_state` 或 debugfs major 创建的临时只读节点），解析每条 ECM flow 的 `adv_stats.from_data_total` / `adv_stats.to_data_total`，再按 `sip_address` + ARP/neighbor 与 `snode_address` 聚合到 `mac@zone` 客户端。它不写 `defunct_all`、`flush`、`decelerate`，也不修改 NSS 状态；第一轮采样会出现 `nss_ecm_direct_snapshot_pending`，第二轮开始计算速率。

### 连接数采集

`conn_collector_mode` 控制 TCP/UDP 连接数来源：

| 值 | 行为 |
|---|---|
| `auto` | 优先 CT-Netlink，失败回退 CT-Procfs。 |
| `conntrack_netlink` | 强制使用 CT-Netlink。 |
| `conntrack_procfs` | 强制使用 `/proc/net/nf_conntrack`。 |

连接数语义为 `conntrack_current_tcp_established_assured_udp_tracked_dns_split`：TCP 统计已建立/确认连接，UDP 统计当前 conntrack 项，并把 DNS UDP 单独拆分。

## 包组成

| 包 | 说明 |
|---|---|
| `lanspeedd` | C daemon，暴露 ubus 只读方法（status / clients / overview / health / interfaces / sysdevices） |
| `lanspeedd-bpf` | 可选，SDK 编译的 tc/eBPF 对象（含 ct_lookup + seen_tuples 去重 map） |
| `luci-app-lanspeed` | LuCI 状态页和配置页，模块化前端（vocab / format / rpc / ifaceConfig / nssPanel / version） |

## 编译

### 获取源码

```sh
git clone https://github.com/qimaoww/luci-app-lanspeed.git package/lanspeed
```

### 版本支持

| OpenWrt / ImmortalWrt | 说明 |
|---|---|
| ImmortalWrt 25.12 | 当前主要验证目标。 |
| OpenWrt 23.05 | 基础 daemon / LuCI 可用；BPF 取决于 SDK、内核 BTF 和工具链。 |
| OpenWrt 21.02 及更早版本 | 不推荐，BPF、libbpf、ctnetlink 和 LuCI 运行时差异较大。 |

### 内核配置要求（BPF 模式）

```
CONFIG_DEVEL=y
CONFIG_KERNEL_DEBUG_INFO=y
CONFIG_KERNEL_DEBUG_INFO_BTF=y
CONFIG_KERNEL_BPF_EVENTS=y
CONFIG_BPF_TOOLCHAIN_HOST=y
CONFIG_PACKAGE_kmod-nf-conntrack=y
CONFIG_PACKAGE_kmod-nf-conntrack-netlink=y
```

不启用 `lanspeedd-bpf` 时，daemon 仍可显示连接数与环境诊断；但普通非 NSS 设备不会用 conntrack 伪装成实时客户端测速。

### 运行时依赖

| 包 | 必需 | 说明 |
|---|---|---|
| `libubox` | yes | ubus / uloop 基础库 |
| `libubus` | yes | ubus 通信 |
| `libuci` | yes | UCI 配置读取 |
| `libblobmsg-json` | yes | JSON 序列化 |
| `libjson-c` | yes | JSON 处理 |
| `libmnl` | yes | raw ctnetlink / CT-Netlink dump |
| `tc-tiny` (iproute2) | yes | tc clsact 挂载 |
| `kmod-nf-conntrack` | yes | conntrack 表访问 |
| `kmod-nf-conntrack-netlink` | yes | CT-Netlink 连接数读取 |
| `libbpf` | BPF 模式 | BPF 对象加载 |
| `luci-base` | LuCI 页面 | LuCI 框架 |

NSS-direct 不额外依赖用户态库，但需要内核侧 qca-nss-ecm 暴露 ECM state 设备；不可用时会自动显示 `nss_ecm_direct_unavailable` 并回退。

### 编译命令

```sh
make menuconfig
# Network -> lanspeedd
# Network -> lanspeedd-bpf
# LuCI -> Applications -> luci-app-lanspeed

make package/lanspeed/lanspeedd/compile V=s
make package/lanspeed/lanspeedd-bpf/compile V=s
make package/lanspeed/luci-app-lanspeed/compile V=s
```

也可以使用仓库脚本：

```sh
SDK_DIR=/openwrt/25.12 ENABLE_BPF=1 DRY_RUN=1 scripts/build-sdk.sh
SDK_DIR=/openwrt/25.12 ENABLE_BPF=1 scripts/build-sdk.sh
```

常见 ABI 注意点：包必须用目标 SDK 编译，APK/IPK 格式跟固件分支一致，不能混用不同 kernel ABI 的 `lanspeedd-bpf`。

## 安装与启动

```sh
/etc/init.d/lanspeedd enable
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
    option collector_mode 'auto'
    option max_clients '2048'
    list ifname 'br-lan'
    list interface_include 'br-lan'
    list interface_exclude 'wan'
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
| `rate_collector_mode` | `auto` | 速率采集：`auto` / `bpf`。 |
| `conn_collector_mode` | `auto` | 连接数采集：`auto` / `conntrack_netlink` / `conntrack_procfs`。 |
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
| dae/daed | 代理接口不作为客户端身份，前置 BPF 尽量兼容后启动 daed；可能提示 `dae_detected`。 |
| SQM/qosify/ifb | 可能影响方向判断或覆盖范围，对应 `sqm_detected`、`qosify_detected`、`ifb_detected`。 |
| hardware flow offload | 硬件转发绕过 CPU，BPF 不可见，提示 `hardware_flow_offload_unsupported`。 |
| software flow offload | 告警但不阻止采集，提示 `software_flow_offload_enabled`。 |
| fullcone NAT | 连接语义可能受影响，提示 `fullcone_nat_enabled`。 |
| NSS ECM / PPE | ECM direct 可优先读取 ECM state；失败后 ECM sync 可为 NSS 自动模式兜底；PPE direct 第一版只探测状态，不写 NSS 状态。 |
| nssifb | 只能观察，不允许作为 BPF 采集接口，避免镜像接口重复计数。 |
| same-subnet side-router direct | 同网段旁路由直连可能绕过主路由，提示 `same-subnet side-router direct` 相关风险。 |
| router-local | 路由器本机进程流量不会自然映射成 LAN 客户端。 |
| LAN-to-LAN | 桥内或交换芯片内转发 CPU 不可见，可能提示 `lan_to_lan_visibility_limited`。 |
| VLAN/Wi-Fi | 使用 MAC + zone/VLAN 区分身份；重复 MAC 可能提示 `duplicate_mac_across_vlans`。 |
| PPPoE/WG/TUN | 外层接口可观察，但客户端身份仍以 LAN 边缘为准；路径不对称时可能提示 `asymmetric_path_possible`。 |
| flowtable counter | 缺失计数会提示 `flowtable_counter_missing`。 |
| nlbwmon | 同类计数器共存可能提示 `nlbwmon_counter_conflict`。 |
| conntrack fallback | 非 NSS 不用于实时测速，只用于连接数和诊断；NAT-only 可提示 `conntrack_routed_nat_only`。 |
| tc 冲突 | 发现外部 tc filter 可能提示 `tc_filter_conflict`。 |
| BPF map 满 | 客户端超过容量可能提示 `map_full`。 |

## 故障排查

| 现象 | 检查 |
|---|---|
| SDK 缺失 | 确认 `SDK_DIR` 指向真实 SDK，例如 `/openwrt/25.12`。 |
| 缺少 BPF 包或对象 | 安装 `lanspeedd-bpf`，检查 `/usr/lib/bpf/lanspeed_tc.o`。 |
| 缺少 `tc` | 安装 `tc-tiny` 或完整 iproute2。 |
| 连接数全 0 | 检查 `nf_conntrack_acct`、`kmod-nf-conntrack-netlink`、`conn_collector_mode`。 |
| 没有客户端 | 检查 LAN 接口配置、桥设备、BPF 是否 attach 成功。 |
| 速率长时间为 0 | 检查 `rate_collector_mode`、BPF 包、tc filter、硬件 flow offload；NSS 设备还要看 `nss_ecm_direct_unavailable` / `nss_ecm_direct_snapshot_pending`。 |
| OpenClash 或 dae/daed 共存 | 优先确认 BPF attach 在 LAN 边缘，观察 health 里的 warning。 |
| 覆盖率低 | 检查硬件 offload、旁路网关、LAN-to-LAN、IFB/TUN 等 CPU 不可见路径。 |

## 项目结构

```
applications/luci-app-lanspeed/
  htdocs/luci-static/resources/
    lanspeed/                      模块 (vocab/format/rpc/ifaceConfig/nssPanel/version)
    view/lanspeed/index.js         实时状态入口
    view/lanspeed/config.js        LAN Speed 配置页面
net/lanspeedd/
  src/lanspeedd.c                  daemon 主程序
  src/lanspeed_tc.bpf.c            eBPF 程序 (tc ingress/egress + ct_lookup)
  src/lanspeed_bpf.c/.h            libbpf loader
  src/collector-model.json         采集模型说明
  files/                           设备端文件 (init.d / UCI config / schema)
scripts/build-sdk.sh               SDK 编译辅助脚本
tests/                             本地回归测试
```

## 测试

本地环境只能运行确定性检查脚本；真实 SDK 编译和目标设备验证仍需要在对应 SDK/路由器上执行。

```sh
./tests/run.sh unit
sh tests/validate-lanspeed-docs.sh
```

## License

Apache-2.0
