# luci-app-lanspeed

`luci-app-lanspeed` 为 ImmortalWrt / OpenWrt 提供 LAN 客户端实时速率、连接详情、运行诊断与配置页面。当前版本为 `1.1.6-r1`。

x86_64 使用独立 TC-BPF 路径，并支持客户端限速与禁网；Qualcomm aarch64 NSS 使用 Access Edge 提供客户端总速率，ECM/NSS 与 TC-BPF 只做路径分类。两套平台代码独立编译，不交叉探测或展示。

## 快速导航

| 层级 | 页面 | 主要内容 |
|---|---|---|
| 使用 | [使用指南](docs/guide/usage.md) | [界面入口](docs/guide/usage.md#界面入口) · [客户端控制](docs/guide/usage.md#x86-客户端控制) · [配置](docs/guide/usage.md#配置) · [ubus](docs/guide/usage.md#ubus-调试) |
| 原理 | [平台与采集](docs/guide/platforms.md) | [平台边界](docs/guide/platforms.md#平台模块) · [x86](docs/guide/platforms.md#x86tc-bpf) · [NSS](docs/guide/platforms.md#qualcomm-nss) · [融合语义](docs/guide/platforms.md#access-edge-与分类语义) |
| 运维 | [部署与排障](docs/guide/operations.md) | [依赖](docs/guide/operations.md#运行依赖) · [内核配置](docs/guide/operations.md#内核配置) · [告警](docs/guide/operations.md#可见性与告警) · [排障](docs/guide/operations.md#故障排查) |
| 开发 | [构建与发布](docs/guide/development.md) | [源码编译](docs/guide/development.md#安装与编译) · [测试](docs/guide/development.md#测试) · [项目结构](docs/guide/development.md#项目结构) · [发布](docs/guide/development.md#发布) |

## 核心功能

- 实时显示客户端上行、下行、连接数、主机名、地址和物理接入点。
- 连接详情按远端 IP 聚合 TCP/UDP，可展开、排序、分页和暂停刷新。
- x86 实时状态页支持独立上传/下载限速及禁用上网，LAN/NAS 和路由器管理流量不受影响。
- NSS 总速率由 Access Edge 提供；ECM/NSS 与 TC-BPF 分类值不与总速率相加。
- CT-Netlink 连接采集失败时回退 CT-Procfs；连接计数不参与客户端总速率。
- 诊断页检查 RPC、BPF、ECM、Access Edge、接口和版本契约，并给出机器可读原因。
- Aurora、Argon、Bootstrap 三主题支持桌面和移动端布局。

## 平台一览

| 目标 | 客户端总速率 | 客户端控制 | NSS/ECM |
|---|---|---|---|
| `x86_64` | 原生 TC-BPF | HTB + FQ；上传使用自有 IFB | 不编译、不探测、不展示 |
| Qualcomm `aarch64` | Access Edge，必要时使用严格同窗回退 | 当前不提供 | ECM/NSS 与 TC-BPF 只做分类 |
| 32 位 ARM、i386、MIPS | Unsupported | 不支持 | 不支持 |

详细边界、采样窗口和融合公式见[平台与采集](docs/guide/platforms.md)。

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

SDK 构建与发布说明见[构建与发布](docs/guide/development.md)。

## 界面预览

截图由真实 Chromium 使用确定性合成数据渲染。客户端使用文档保留地址、虚构主机名与本地管理 MAC，不包含目标设备数据；PNG 元数据已移除。

| 主题 | 实时状态 | 运行诊断 | LAN Speed 配置 |
|---|---|---|---|
| Aurora | [桌面](docs/screenshots/lanspeed-overview-aurora-desktop.png) / [移动](docs/screenshots/lanspeed-overview-aurora-mobile.png) | [桌面](docs/screenshots/lanspeed-diagnostics-aurora-desktop.png) | [桌面](docs/screenshots/lanspeed-config-aurora-desktop.png) |
| Argon | [桌面](docs/screenshots/lanspeed-overview-argon-desktop.png) / [移动](docs/screenshots/lanspeed-overview-argon-mobile.png) | [桌面](docs/screenshots/lanspeed-diagnostics-argon-desktop.png) | [桌面](docs/screenshots/lanspeed-config-argon-desktop.png) |
| Bootstrap | [桌面](docs/screenshots/lanspeed-overview-bootstrap-desktop.png) / [移动](docs/screenshots/lanspeed-overview-bootstrap-mobile.png) | [桌面](docs/screenshots/lanspeed-diagnostics-bootstrap-desktop.png) | [桌面](docs/screenshots/lanspeed-config-bootstrap-desktop.png) |

## 重要限制

- hardware flow offload 会绕过 x86 CPU TC hook，无法靠 conntrack 字节补齐客户端总速率。
- Wi-Fi station 与以太网计数口径不兼容时保留 `domain_mismatch`，不生成虚假覆盖率。
- WDS、Mesh、共享下联和未验证组播只声明 Partial，不伪装为完整覆盖。
- x86 控制不会覆盖外部 qdisc、IFB 或 nft 对象；冲突时拒绝应用并显示原因。
- 正常整形不主动丢包，但有限队列不能承诺任意持续超速下绝对零丢包；`drops` 增长会报告队列溢出。

## 包组成

| 包 | 内容 |
|---|---|
| `lanspeedd` | Rust daemon、UCI、ubus、连接采集与平台调度 |
| `lanspeedd-bpf` | 对应架构的 TC-BPF 对象；aarch64 包额外包含 ECM kprobe 对象 |
| `luci-app-lanspeed` | 实时状态、运行诊断、配置和连接详情页面 |

安装依赖、内核选项及服务冲突处理见[部署与排障](docs/guide/operations.md)。

## License

Apache-2.0
