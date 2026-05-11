# luci-lanspeed

> 本仓库代码由 AI 生成。

ImmortalWrt/OpenWrt 本地 feed：按客户端归属的 LAN 侧实时吞吐 + TCP/UDP 连接数统计。

统计边界：**CPU 可见 LAN 边缘流量**。不是完整流量审计系统，也不声明全流量绝对准确，不声明硬件交换或所有卸载路径绝对可见。

## 功能概览

- 按客户端实时速率（BPF tc 直接计数 / conntrack 降级采集）
- 按客户端 TCP 连接数 + UDP 条目数（BPF `bpf_skb_ct_lookup` 优先，procfs conntrack 兜底）
- 全局覆盖率指标（字节差分，分子分母共用时间窗）
- NSS 状态折叠区（Qualcomm IPQ 设备自动显示）
- 接口配置面板（采集 / 观察 / 关闭三态切换）
- 模式 / 置信度 / 告警体系

## 包组成

| 包 | 说明 |
|---|---|
| `luci-app-lanspeed` | LuCI 状态页（模块化 JS：vocab/format/rpc/ifaceConfig/nssPanel + 入口） |
| `lanspeedd` | C daemon，ubus 只读方法：`status` `clients` `health` `interfaces` `sysdevices` |
| `lanspeedd-bpf` | 可选子包，SDK 编译 tc/eBPF 对象 + seen_tuples 连接去重 map |

## 支持矩阵

| 系统 | 级别 |
|---|---|
| ImmortalWrt 25.12（kernel 6.6+） | 一等目标 |
| OpenWrt/ImmortalWrt 23.05 | 次级 |
| 21.02 及更早 | 不支持 |

## 准确性模式

| 模式 | 条件 | 数据源 |
|---|---|---|
| Full | BPF attach 成功 + map 可读 | tc/eBPF 按 MAC 直接计数 |
| Degraded | BPF 不可用，conntrack 可读 | `/proc/net/nf_conntrack` + ARP |
| Unsupported | 缺少关键能力 | 无可用采集 |

置信度：`high` / `medium` / `low` / `unsupported`

## 连接数统计

BPF 模式下使用 `bpf_skb_ct_lookup()` kfunc（Linux 6.1+）在每个包经过时查 conntrack 状态，配合 `seen_tuples` LRU map 去重，实现按客户端的实时 TCP/UDP 连接数统计。

- TCP：仅统计 conntrack 中 tracked 的 TCP 连接（ct_lookup 成功即计入）
- UDP：统计所有 tracked UDP 条目
- IPv4 + IPv6 均支持
- kfunc 不可用时（老内核 / `nf_conntrack` 未加载）自动 fallback 到 procfs conntrack 扫描

## 编译

### 1. 获取源码

```sh
git clone https://github.com/qimaoww/luci-app-lanspeed package/lanspeed
```

### 2. 内核配置要求

lanspeedd 的 BPF 实时采集依赖 eBPF 和 conntrack BPF kfunc。请确保内核配置包含：

```
CONFIG_DEVEL=y
CONFIG_KERNEL_DEBUG_INFO=y
CONFIG_KERNEL_DEBUG_INFO_BTF=y
CONFIG_KERNEL_BPF_EVENTS=y
CONFIG_BPF_TOOLCHAIN_HOST=y
CONFIG_PACKAGE_kmod-nf-conntrack=y
```

> 如果不启用 BPF 子包（`lanspeedd-bpf`），daemon 会自动 fallback 到 conntrack procfs 采集，此时只需要 `kmod-nf-conntrack` 和 `nf_conntrack_acct` 即可。

### 3. 运行时依赖

| 包 | 必需 | 说明 |
|---|---|---|
| `libubox` | ✓ | ubus/uloop 基础库 |
| `libubus` | ✓ | ubus 通信 |
| `libuci` | ✓ | UCI 配置读取 |
| `libblobmsg-json` | ✓ | JSON 序列化 |
| `libjson-c` | ✓ | JSON 处理 |
| `tc-tiny` (iproute2) | ✓ | tc clsact 挂载 |
| `libbpf` | BPF 模式 | BPF 对象加载 |
| `kmod-nf-conntrack` | ✓ | conntrack 表访问 |
| `luci-base` | LuCI 页面 | LuCI 框架 |

### 4. 编译

```sh
make menuconfig
# 路径: Network -> lanspeedd
#       LuCI -> Applications -> luci-app-lanspeed

make package/lanspeed/lanspeedd/compile V=s
make package/lanspeed/luci-app-lanspeed/compile V=s
```

## UCI 配置

默认配置 `/etc/config/lanspeed`：

```
config lanspeed 'main'
    option enabled '1'
    option refresh_interval_ms '1000'
    option max_clients '2048'
    list ifname 'br-lan'
    list interface_include 'br-lan'
    list interface_exclude 'wan'
    option enable_bpf '1'
    option enable_conntrack_fallback '1'
```

## ubus 调试

```sh
ubus call lanspeed status      # 模式/置信度/能力/告警
ubus call lanspeed clients     # 客户端列表 + TCP/UDP 连接数
ubus call lanspeed health      # 健康检查 + 冲突
ubus call lanspeed interfaces  # 接口吞吐 + 覆盖率
ubus call lanspeed sysdevices  # 系统设备列表（配置面板用）
```

## 方向语义

- `tx_bps` = 客户端上传（客户端 → 路由器）
- `rx_bps` = 客户端下载（路由器 → 客户端）
- 身份 = 规范化 MAC + zone/VLAN，IP 和 hostname 是属性不是 key

## 本地测试

```sh
./tests/run.sh unit            # 语法 + 合约 + 身份 + 采集器 + 探测 + 模块结构 + SDK
./tests/run.sh probe-fixtures  # OpenClash/dae/QoS/offload/conntrack fixtures
./tests/run.sh all             # 全部
```

## 兼容性

| 场景 | 影响 |
|---|---|
| OpenClash fake-ip / TUN | 置信度降低，远端地址仅作元数据 |
| dae/daed | 代理接口不作为客户端身份 |
| hardware flow offload | Full 不支持，硬件转发绕过 CPU |
| software flow offload | 告警但不阻止 |
| NSS ECM/PPE | 连接数经 ECM sync 回 conntrack，精度为秒级 |
| SQM/qosify/IFB | 可能影响方向或覆盖范围 |
| LAN-to-LAN 硬件桥接 | 可见性有限 |

## 项目结构

```
applications/luci-app-lanspeed/   LuCI 状态页
  htdocs/luci-static/resources/
    lanspeed/                     子模块 (vocab/format/rpc/ifaceConfig/nssPanel)
    view/lanspeed/index.js        入口
net/lanspeedd/                    C daemon + BPF 程序
  src/lanspeedd.c                 主程序
  src/lanspeed_tc.bpf.c           eBPF (tc ingress/egress + ct_lookup)
  src/lanspeed_bpf.c/.h           libbpf loader
  files/                          设备端文件 (init.d/config/schema)
scripts/build-sdk.sh              SDK 编译 helper
tests/                            本地回归套件
```

## License

Apache-2.0
