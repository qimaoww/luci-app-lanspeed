# luci-app-lanspeed

> 本仓库所有代码及文档（包括本 README）均由 AI 生成。

LAN 侧按客户端实时吞吐监控 + TCP/UDP 连接数统计，当前面向 ImmortalWrt 25.12。

后端用户态 daemon 与 tc/eBPF 程序均使用 Rust 实现；OpenWrt 的 ubus、uloop 和 UCI 通过 Rust FFI 调用系统 ABI，仓库不再保留项目自有 C 后端。

本项目的定位是观察 CPU 可见 LAN 边缘流量：它不是完整流量审计系统，不声明全流量绝对准确。硬件加速、旁路网关、同网段直连、桥内转发、驱动 offload、代理 TUN/IFB 等路径可能让部分流量绕过 CPU 或改变可见方向。

## 界面预览

以下截图分别使用 **Aurora** 与 **Argon** 主题；六张图片均由虚构客户端、文档保留地址和示例连接数据生成，不包含真实设备、主机名、MAC、内网地址或路由器运行信息。连接详情示例同时展示八列表头，以及中国目标按省级行政区显示（如 `中国·浙江`）。点击链接可查看完整原图。

- **Aurora**
  - [实时状态](docs/screenshots/lanspeed-overview-desktop.png)
  - [连接详情（桌面端）](docs/screenshots/client-connections-desktop.png)
  - [连接详情（移动端）](docs/screenshots/client-connections-mobile.png)
- **Argon**
  - [实时状态](docs/screenshots/lanspeed-overview-desktop-argon.png)
  - [连接详情（桌面端）](docs/screenshots/client-connections-desktop-argon.png)
  - [连接详情（移动端）](docs/screenshots/client-connections-mobile-argon.png)

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

`luci-app-lanspeed` 强制依赖 `lanspeedd-bpf`，后者会带上 `lanspeedd`；BPF 对象随 `lanspeedd` 源包一起编译，不需要单独执行 `package/lanspeedd-bpf/compile`。

## 特性

- **实时速率**：BPF tc 按 MAC + zone/VLAN 直接计数，字段为 `tx_bps` / `rx_bps`；生产运行默认加载只做流量统计的低开销对象，不再在每个转发包上计算未被响应使用的近似连接数；BPF 是所有设备（包括 NSS）的默认实时速率来源，`auto` 模式会首先选择 BPF；短时静默客户端会保留隐藏计数基线，恢复流量时首个样本不再固定显示为 0。
- **连接数统计**：优先 CT-Netlink 读取 conntrack accounting，失败自动回退 CT-Procfs；TCP、UDP、DNS UDP 分开统计。
- **逐连接实时速率**：点击客户端名称进入连接详情后，按目标 IP 汇总并显示上行/下行速率；八列表头均可排序，默认把下行速度最高的目标放在最上面；展开目标可查看每条 TCP/UDP 连接各自的客户端视角 `tx_bps` / `rx_bps`。详情页提供与 LAN 客户端相同的 1/2/3/5/10 秒刷新选项和暂停按钮，但刷新设置独立保存，不影响客户端列表。单客户端详情最多返回 2048 条连接，仍保留全局 16384 条存储保护。
- **国家/地区**：详情页只对当前分页中去重后的公网目标 IP 由浏览器查询 GeoIP 源。先查询 `ipwho.is`；中国结果直接采用其省级行政区（例如 `中国·浙江`），不再请求其他源。非中国地址再并行查询 `ipinfo.io` 与 DB-IP，并按国家代码多数票显示；主源或单个备用源失败时仍可回退到其余结果。最多 4 个 IP 查询并发，并在浏览器本地保存有界的 7 天正缓存和 5 分钟负缓存。内网、代理 Fake-IP 与保留地址在本地直接分类，不增加 daemon CPU。显示结果是 IP 位置推测，可能受 CDN、Anycast、VPN 或代理影响；各公共源也可能有额度和限流策略。
- **NSS 兼容**：Qualcomm NSS 设备自动展示 ECM/PPE 状态，默认仍使用 LAN 边缘 BPF；显式选择 NSS 模式或 BPF 运行时不可用时，才使用 NSS sync / CT-Netlink 或 NSS-direct。NSS 硬件加速流量可能绕过 CPU，因此 BPF 只能看到慢路径；IPv4 通过 ARP、IPv6 通过 neighbor 表匹配客户端，并兼容 ECM NAT 端点。
- **活跃客户端**：默认只把 10 秒内仍有有效速率的客户端计为 active，可通过 UCI 调整。
- **覆盖率**：daemon 侧使用 32 个样本的滑动窗口，并按客户端实时速率生成单调累计分子，避免客户端离线/重新出现导致覆盖率跳回“采样中”；低流量与真正无流量分开显示。
- **独立诊断**：LuCI 内置“实时状态”“运行诊断”和“LAN Speed 配置”三个页签；诊断页集中检查插件、后端与 BPF，只展示会影响实时测速的重要告警，实时状态页不再混入旧诊断面板。
- **配置页面**：速率采集、连接数采集、活跃客户端阈值和接口配置可分开调整，并使用 LuCI 原生“保存并应用 / 保存 / 重置”页脚；修改后会立即显示原生未保存配置指示，点击可进入原生变更列表，应用配置时由 procd 触发后端重载，NSS 设备会显示 NSS 专属说明。
- **接口配置**：采集 / 观察 / 关闭 三态切换，默认采集 `br-lan`、观察 `wan`；自动忽略 `dae*`、`miireg*`、`tun*`、`erspan*`、`gretap*`、`gre*`、`ip6gre*`、`ip6tnl*`、`sit*`、`bonding_masters*`，拒绝 nssifb 采集并可观察 WAN / ifb 计数。
- **告警体系**：OpenClash / dae/daed / SQM/qosify/ifb / flow offload / fullcone NAT 等场景自动识别并提示。
- **客户端状态列**：默认隐藏 LAN 客户端的采集来源与告警状态，可在“LAN Speed 配置”中开启。
- **版本显示**：LuCI 状态页显示完整版本，例如 `1.1.0-r12`。

## 采集策略

### 速率采集

`rate_collector_mode` 控制客户端实时速率：

| 值 | 行为 |
|---|---|
| `auto` | 默认模式。所有设备（包括 NSS ECM/PPE）优先使用 BPF；BPF 运行时不可用时，NSS 设备才按可用性回退 NSS sync / CT-Netlink 或 NSS-direct。 |
| `bpf` | 强制只使用 BPF 测速；BPF 不可用时不回退 NSS，适合确认 LAN 边缘 BPF 路径。 |
| `nss_ecm_direct` | 手动尝试 NSS-direct；direct 没有有效速率时仍使用 NSS sync 后备，避免显示 0。 |
| `nss_conntrack_sync` | 强制使用 NSS sync；只适合 NSS ECM/PPE 设备排查或 direct 不可用时使用。 |

非 NSS 设备不会把 CT 当作实时测速来源。CT 只能用于连接数、诊断和 NSS ECM/PPE sync 这类明确标注的 fallback。

daemon 启动时立即由 Rust 扫描 `/proc/<pid>/comm`，之后至多每 5 秒扫描一次，只把精确名称为 `dae` 或 `daed` 的进程视为运行态，不依赖 `pidof` 或慢速环境探测缓存。自动模式在所有设备上都优先选择 BPF；检测到 dae/daed 运行状态变化后，仍会立即把 LAN BPF 从 Normal（pref `49152`）事务切换到 Early passthrough（pref `1`），进程停止后切回 Normal。切换复用 reload 的 suspend/attach/rollback 流程并保留外部 tc filter，同时显示 `dae_runtime_prefers_bpf`；NSS 设备只有在 BPF 不可用时才回退 NSS sync，并显示 `nss_dae_bpf_fallback_may_be_inaccurate`。

NSS-direct 是显式选择 `nss_ecm_direct` 或 BPF 不可用时的后备来源。daemon 只读 qca-nss-ecm 的 state 设备（`/dev/ecm_state` 或 debugfs major 在 `/dev` 下创建的临时只读节点），解析 ECM flow 的 `adv_stats.from_data_total` / `adv_stats.to_data_total`，再按两端 IP、NAT IP 和 node MAC 匹配 LAN 客户端。它不写 `defunct_all`、`flush`、`decelerate`，也不修改 NSS 状态。部分固件的 ECM state 可能没有活跃 flow、计数为 0 或覆盖不完整，此时会显示 `nss_direct_no_data` / `nss_direct_partial`，并用 NSS sync 补齐。

NSS ECM/PPE sync 是显式选择 `nss_conntrack_sync`、NSS-direct 的补齐来源或 BPF 不可用时的后备来源。NSS 硬件加速 flow 的字节计数同步回 conntrack 后，daemon 再读取 CT-Netlink / CT-Procfs 的 accounting 计数。这个路径会匹配 conntrack 原始方向和回复方向的源/目的端点，按 LAN 客户端视角换算上下行；只在 NSS ECM/PPE 场景作为实时速率来源，非 NSS 设备不会把 conntrack 当作实时测速来源。

### 连接数采集

`conn_collector_mode` 控制 TCP/UDP 连接数来源：

| 值 | 行为 |
|---|---|
| `auto` | 优先 CT-Netlink，失败回退 CT-Procfs。 |
| `conntrack_netlink` | 强制使用 CT-Netlink。 |
| `conntrack_procfs` | 强制使用 `/proc/net/nf_conntrack`。 |

连接数语义为 `conntrack_current_tcp_established_assured_udp_assured_dns_split`：TCP 统计已建立/确认连接，UDP 只统计已确认（ASSURED）的 conntrack 项，并把 DNS UDP 单独拆分。内核对 flow-offload 项会隐藏普通 TCP 状态或 `[ASSURED]` 文本，CT-Netlink 和 CT-Procfs 会按 offload 状态恢复等价语义，避免后备路径漏计。

顶部汇总、overview 和客户端表使用同一份完整的当前连接快照。已退出 `active_client_window_ms` 速率窗口但仍有连接的客户端会保留为 `CT-Netlink` / `CT-Procfs` 行，速率显示为 0 并提示 `conntrack_connection_only`；因此未启用搜索或“仅活跃”过滤时，表格 TCP/UDP 行合计与顶部严格一致，活跃客户端数仍只由实时速率判断。

## 包组成

| 包 | 说明 |
|---|---|
| `lanspeedd` | Rust/Aya daemon，暴露八个 ubus 方法（status / clients / overview / health / reload / interfaces / sysdevices / client_connections） |
| `lanspeedd-bpf` | LuCI 应用的必选依赖，安装 Rust 编译的低开销字节统计对象与 kfunc 兼容对象；生产运行默认使用低开销对象，精确连接数统一来自 conntrack，并依赖 `lanspeedd` |
| `luci-app-lanspeed` | LuCI 实时状态、独立诊断和配置页，强制依赖 `lanspeedd-bpf`，模块化前端（status / diagnostics / config / client detail） |

## 编译要求与高级用法

### 版本支持

| OpenWrt / ImmortalWrt | 说明 |
|---|---|
| ImmortalWrt 25.12 | 支持。当前构建、打包和路由器实测目标。 |
| OpenWrt 23.05 | 不支持。官方 SDK 的 Rust 版本和 libubox ABI 不满足当前完整 Rust 后端。 |
| OpenWrt 21.02 及更早版本 | 不支持。BPF/BTF、Rust 工具链、OpenWrt ABI 和 LuCI 运行时差异过大。 |

构建驱动要求稳定版 `Rust >= 1.94.0`，外部提供的 `BPF_LINKER` 接受稳定版 `bpf-linker >= 0.10.3, < 0.11.0`。OpenWrt 包构建仍下载并校验固定的 `bpf-linker 0.10.3` 发布归档及 SHA256，以保证离线构建可复现。Rust 1.94.0、1.95.0 和 1.96.0 已验证可离线构建；更高稳定版不再被版本门禁先行拒绝，但若 eBPF `build-std` 的标准库锁定依赖发生变化，仍需同步 `vendor`。Rust 与 `bpf-linker` 的预发布版本仍会被拒绝。不要用较旧 SDK 的 `rust/host` 绕过最低版本检查；即使能编译，ubus/uloop/UCI 的目标 ABI 也可能不兼容。

### 用户态与 BPF 必选包

- `luci-app-lanspeed` 必须依赖 `lanspeedd-bpf`，`lanspeedd-bpf` 再依赖用户态 daemon `lanspeedd`；在 menuconfig 中选择 LuCI 应用会自动选中完整依赖链。
- `lanspeedd-bpf` 的标准 OpenWrt 包构建使用固定的 `bpf-linker 0.10.3` 构建两套 Rust eBPF 对象；显式传入兼容版本的 `BPF_LINKER` 时，构建驱动按上述版本范围校验。目标机必须提供 `tc-tiny` 和 `kmod-sched-bpf`。
- 当前固定的 `bpf-linker` 发布包要求 x86_64 编译主机，目标路由器架构仍由 OpenWrt SDK 决定。
- NSS-direct 与 NSS sync 保留为显式模式和 BPF 运行时不可用时的后备来源，但不能替代 LuCI 应用对 `lanspeedd-bpf` 的安装依赖。

### 内核与包配置要求

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

缺少 `lanspeedd-bpf`、tc 或内核 BPF 支持时属于不完整安装，默认实时速率不可用。daemon 仍可能显示连接数与环境诊断；NSS 设备也可能在 BPF 运行失败后使用 NSS-direct / ECM/PPE sync 后备，但这不取代必选 BPF 依赖。

### 运行时依赖

| 包 | 必需 | 说明 |
|---|---|---|
| `libubox` | yes | ubus / uloop 基础库 |
| `libubus` | yes | ubus 通信 |
| `libuci` | yes | UCI 配置读取 |
| `libblobmsg-json` | yes | Rust JSON 与 ubus blobmsg 的桥接 |
| `kmod-nf-conntrack` | yes | conntrack 表访问 |
| `kmod-nf-conntrack-netlink` | yes | CT-Netlink 连接数读取 |
| `tc-tiny` (iproute2) | yes | `lanspeedd-bpf` 的 tc clsact 挂载依赖 |
| `kmod-sched-bpf` | yes | `lanspeedd-bpf` 的内核 tc BPF classifier 依赖 |
| `luci-base` | LuCI 页面 | LuCI 框架 |

用户态 JSON 使用 `serde_json`，CT-Netlink 使用 Rust 原始 netlink 实现，eBPF 对象由 Aya 加载，不直接依赖 `libjson-c`、`libmnl` 或 `libbpf`。NSS 默认仍使用 BPF；NSS-direct 仅在显式模式或 BPF 不可用时启用，不额外依赖用户态库，但需要内核侧 qca-nss-ecm 暴露 ECM state 设备；不可用或没有可匹配 flow 时会使用 NSS sync。IPv6 客户端匹配依赖内核 neighbor 表；前端隐藏 IPv6 只影响显示，不影响采集匹配。

### 本地 checkout / SDK 辅助脚本

仓库内的 `scripts/build-sdk.sh` 适合贡献者在本地 checkout 上重复验证。它使用 `src-link` 临时接入现有 SDK，自动选择包并执行相同的 `package/lanspeedd/compile` 和 `package/luci-app-lanspeed/compile` 目标：

```sh
SDK_DIR=/openwrt/immortalwrt ENABLE_BPF=1 DRY_RUN=1 scripts/build-sdk.sh
SDK_DIR=/openwrt/immortalwrt ENABLE_BPF=1 scripts/build-sdk.sh
```

辅助脚本的 `ENABLE_BPF` 默认值为 `1`，正常 LuCI 应用构建应保持启用。

普通用户从 GitHub 构建时优先使用前面的 `src-git lanspeed` feed 流程；辅助脚本不会下载 SDK 或工具链。

ABI 注意点：包必须用目标固件对应的 25.12 SDK 编译，不能混用其他分支的 libubox/libubus/libuci 或 kernel ABI，也不能把 `lanspeedd-bpf` 安装到不同内核构建上。

当前只声明支持并验证 x86_64 和 aarch64 两类 LP64 目标；32 位 ARM、i386 和 MIPS 不在支持范围内。普通代码 push 和 pull request 由独立 CI workflow 执行完整单元校验。当 `main` 分支上的 `net/lanspeedd/Makefile` 或 `applications/luci-app-lanspeed/Makefile` 改动导致完整版本发生变化时，发布 workflow 会自动编译这两类产物；aarch64 产物使用官方 `armsr/armv8` SDK 编译，Release 文件名带 `aarch64` 后缀。每个架构先构建 base 包，再把已安装的 Rust/Cargo 主机工具链复用于 BPF 构建；该工具链按操作系统、架构和 SDK SHA256 缓存，后续相同 SDK 不再从头编译 Rust。workflow 会先创建草稿 Release，上传并校验六个 APK 的名称、状态和 SHA256，再发布对应的 `v*` tag 和 GitHub Release，维护者不得预先创建 `v*` tag。构建或上传失败时保留的草稿 Release 可由同一版本提交使用 `workflow_dispatch` 自动重建；手动运行也可补发没有 tag/Release 的当前版本，无需通过 `HEAD^1` 制造新的版本变化。

## 配置

LuCI 入口：

- `状态 -> 客户端网速 -> 实时状态`
- `状态 -> 客户端网速 -> 实时状态 -> 点击客户端名称进入连接详情页`
- `状态 -> 客户端网速 -> 运行诊断`
- `状态 -> 客户端网速 -> LAN Speed 配置`

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
| `rate_collector_mode` | `auto` | 速率采集：`auto` 默认在所有设备上优先 BPF；也可显式选择 `bpf` / `nss_ecm_direct` / `nss_conntrack_sync`。 |
| `conn_collector_mode` | `auto` | 连接数采集：`auto` / `conntrack_netlink` / `conntrack_procfs`。 |
| `show_client_status` | `0` | 是否在 LAN 客户端列表中显示采集来源和告警状态。 |
| `show_ipv6` | `1` | 客户端列表是否显示 IPv6 地址。 |
| `hide_private_ipv6` | `0` | 是否隐藏 `fc00::/7` 私有 IPv6 地址和 `fe80::/10` 链路本地地址；公网 IPv6 不受影响。 |
| `hide_ipv6_ranges` | `fc00::/7 fe80::/10` | 自定义隐藏 IPv6 CIDR，空格或逗号分隔；仅在 `hide_private_ipv6=1` 时生效。 |
| `collector_mode` | `auto` | 旧配置兼容字段，新配置页会同步到速率模式。 |
| `enable_bpf` | `1` | 旧配置兼容字段；BPF 是必选组件，受支持配置必须保持 `1`。 |
| `enable_conntrack_fallback` | `1` | 是否允许 conntrack 连接数和 NSS sync fallback。 |

## ubus 调试

```sh
ubus call lanspeed status       # Full / Degraded / Unsupported、high / medium / low / unsupported、能力、告警、版本
ubus call lanspeed clients      # 客户端 tx_bps/rx_bps + TCP/UDP/DNS 连接数
ubus call lanspeed overview     # 总速率、客户端数、active_clients、连接数窗口
ubus call lanspeed health       # 健康检查 + 冲突检测
ubus call lanspeed reload       # 刷新 lanspeedd 运行状态，不写持久 UCI 配置
ubus call lanspeed interfaces   # 接口吞吐 + 覆盖率
ubus call lanspeed sysdevices   # 系统网络设备列表
ubus call lanspeed client_connections \
  '{"identity_key":"30:c5:99:a7:bb:2d@eth1"}'
```

`client_connections` 的 `identity_key` 来自 `clients` 响应。它返回该客户端当前 conntrack 快照：TCP 仅统计 ESTABLISHED + ASSURED，UDP 仅统计 ASSURED；这不是历史连接记录。每条连接的 `tx_bps` / `rx_bps` 由相邻 conntrack 累计字节快照计算，方向始终以客户端为准；新连接首个样本为 0，计数器回退时对应方向为 0，时间回退时本次速率为 0。响应中的 `limit`、`returned_connections` 和 `truncated` 用于说明截断情况。LuCI 实时状态表中点击客户端名称即可进入连接详情页，目标行显示聚合速率，展开后显示每条实际连接的速率；发生截断时，速率仍直接显示数值，页脚会说明分组速率仅汇总已返回的连接子集。

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
| `connections[].tx_bps` / `rx_bps` | 当前连接的客户端视角上行 / 下行速率；依赖 conntrack accounting 的连续快照。 |
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
| dae/daed | 代理接口不作为客户端身份，探测到时提示 `dae_detected`；运行态启动时立即扫描、之后至多每 5 秒由 `/proc/<pid>/comm` 刷新，状态变化仍触发事务 reload；自动模式继续优先 BPF，并提示 `dae_runtime_prefers_bpf`、切到 Early passthrough；NSS 设备只有在 BPF 不可用时才提示 `nss_dae_bpf_fallback_may_be_inaccurate` 并回退 NSS。 |
| SQM/qosify/ifb | 可能影响方向判断或覆盖范围，对应 `sqm_detected`、`qosify_detected`、`ifb_detected`。 |
| hardware flow offload | 硬件转发绕过 CPU，BPF 不可见，提示 `hardware_flow_offload_unsupported`。 |
| software flow offload | 告警但不阻止采集，提示 `software_flow_offload_enabled`。 |
| fullcone NAT | 连接语义可能受影响，提示 `fullcone_nat_enabled`。 |
| NSS ECM / PPE | 默认优先使用 BPF，但硬件加速流量可能绕过 CPU，BPF 只能看到慢路径；显式 NSS 模式或 BPF 不可用时可使用 NSS sync / CT-Netlink、NSS-direct，PPE direct 第一版只探测状态且不写 NSS 状态。 |
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
| 缺少 BPF 包或对象 | `lanspeedd-bpf` 是 LuCI 应用的必选依赖；检查包依赖和 `/usr/lib/bpf/lanspeed-ebpf-kfunc`、`/usr/lib/bpf/lanspeed-ebpf-fallback`。 |
| 缺少 `tc` | 安装 `tc-tiny` 或完整 iproute2。 |
| 连接数全 0 | 检查 `nf_conntrack_acct`、`kmod-nf-conntrack-netlink`、`conn_collector_mode`。 |
| 没有客户端 | 检查 LAN 接口配置、桥设备、BPF 是否 attach 成功。 |
| 速率长时间为 0 | 所有设备先检查 `rate_collector_mode`、BPF 包、tc filter、硬件 flow offload；NSS 设备仅在显式 NSS 模式或 BPF 后备生效时再看 `nss_ecm_direct_unavailable` / `nss_ecm_direct_snapshot_pending`；IPv6 场景同时检查客户端是否出现在 neighbor 表。 |
| OpenClash 或 dae/daed 共存 | 优先确认 BPF attach 在 LAN 边缘，观察 health 里的 warning；NSS+daed 只有在 BPF 不可用而回退 NSS 时才会提示速率可能不准。 |
| 覆盖率低 | 检查硬件 offload、旁路网关、LAN-to-LAN、IFB/TUN 等 CPU 不可见路径。 |

## 项目结构

```
applications/luci-app-lanspeed/
  htdocs/luci-static/resources/
    lanspeed/                      状态、诊断、配置与客户端详情模块
    view/lanspeed/overview.js      实时状态入口
    view/lanspeed/diagnostics.js   独立运行诊断入口
    view/lanspeed/config.js        LAN Speed 配置页面
net/lanspeedd/
  rust/crates/lanspeedd/           Rust daemon、采集器、状态机和 ubus 逻辑
  rust/crates/lanspeed-ebpf/       Rust/Aya eBPF 程序（默认 tc 字节统计；保留 ct_lookup 兼容对象）
  rust/crates/lanspeed-common/     用户态与 eBPF 共用 ABI
  rust/crates/lanspeed-openwrt-sys/ OpenWrt ubus/uloop/UCI FFI
  rust/crates/lanspeed-build/      OpenWrt 用户态与 eBPF 构建驱动
  src/collector-model.json         采集模型说明
  files/                           设备端文件 (init.d / UCI config / schema)
scripts/build-sdk.sh               SDK 编译辅助脚本
.github/workflows/ci.yml           普通 push / pull request 单元校验
.github/workflows/build-sdk.yml    GitHub Actions 自动编译
tests/                             本地回归测试
```

## 测试

本地环境可以运行确定性检查脚本和不依赖目标 ABI 的 Rust 单元/合约测试；`./tests/run.sh unit` 覆盖 `lanspeedd`、共享 ABI、构建驱动和 fixtures。`lanspeed-openwrt-sys` 直接链接目标端 ubus/uloop/UCI，不在 glibc host 上执行，其绑定通过可重复生成检查，并由真实 SDK 编译（ImmortalWrt 25.12）和目标设备（路由器）测试覆盖。构建要求稳定版 `Rust >= 1.94.0`。

```sh
./tests/run.sh unit
sh tests/validate-lanspeed-docs.sh
```

后续设备验证可先运行 dry-run 审阅八个 ubus 方法及动态详情命令模板；确认目标设备和 SSH 参数后，再采集真实 evidence。`collect` 中的 `reload` 只刷新 lanspeedd 运行状态，不修改持久 UCI、网络、防火墙或代理配置。

```sh
DRY_RUN=1 TARGET=root@router OUT_DIR="$(mktemp -d)" sh tests/qa-device.sh collect
```

## License

Apache-2.0
