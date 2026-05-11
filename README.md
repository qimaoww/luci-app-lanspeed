# luci-lanspeed

> 本仓库所有代码及文档（包括本 README）均由 AI 生成。

LAN 侧按客户端实时吞吐监控 + TCP/UDP 连接数统计，适用于 ImmortalWrt / OpenWrt 路由器。

## 特性

- **实时速率**：BPF tc 按 MAC 直接计数（Full 模式），或 conntrack 降级采集（Degraded 模式）
- **连接数统计**：BPF `bpf_skb_ct_lookup()` kfunc 实时去重计数，不可用时 fallback 到 procfs
- **覆盖率**：基于字节差分的统一时间窗计算，消除采样窗口错位抖动
- **NSS 状态卡**：Qualcomm IPQ 设备自动展示 ECM/PPE 加速状态
- **接口配置**：采集 / 观察 / 关闭 三态切换，支持 nssifb 安全拦截
- **告警体系**：OpenClash / dae / SQM / flow offload 等场景自动识别并提示

## 包组成

| 包 | 说明 |
|---|---|
| `lanspeedd` | C daemon，暴露 ubus 只读方法（status / clients / health / interfaces / sysdevices） |
| `lanspeedd-bpf` | 可选，SDK 编译的 tc/eBPF 对象（含 ct_lookup + seen_tuples 去重 map） |
| `luci-app-lanspeed` | LuCI 状态页，模块化前端（vocab / format / rpc / ifaceConfig / nssPanel） |

## 编译

### 获取源码

```sh
git clone https://github.com/qimaoww/luci-app-lanspeed.git package/lanspeed
```

### 内核配置要求（BPF 模式）

```
CONFIG_DEVEL=y
CONFIG_KERNEL_DEBUG_INFO=y
CONFIG_KERNEL_DEBUG_INFO_BTF=y
CONFIG_KERNEL_BPF_EVENTS=y
CONFIG_BPF_TOOLCHAIN_HOST=y
CONFIG_PACKAGE_kmod-nf-conntrack=y
```

> 不启用 `lanspeedd-bpf` 时无需上述 BPF 配置，daemon 自动 fallback 到 conntrack procfs 采集。

### 运行时依赖

| 包 | 必需 | 说明 |
|---|---|---|
| `libubox` | ✓ | ubus / uloop 基础库 |
| `libubus` | ✓ | ubus 通信 |
| `libuci` | ✓ | UCI 配置读取 |
| `libblobmsg-json` | ✓ | JSON 序列化 |
| `libjson-c` | ✓ | JSON 处理 |
| `tc-tiny` (iproute2) | ✓ | tc clsact 挂载 |
| `kmod-nf-conntrack` | ✓ | conntrack 表访问 |
| `libbpf` | BPF 模式 | BPF 对象加载 |
| `luci-base` | LuCI 页面 | LuCI 框架 |

### 编译命令

```sh
make menuconfig
# Network -> lanspeedd
# LuCI -> Applications -> luci-app-lanspeed

make package/lanspeed/lanspeedd/compile V=s
make package/lanspeed/luci-app-lanspeed/compile V=s
```

## 配置

`/etc/config/lanspeed`：

```uci
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

## 调试

```sh
ubus call lanspeed status       # 模式 / 置信度 / 能力 / 告警
ubus call lanspeed clients      # 客户端速率 + TCP/UDP 连接数
ubus call lanspeed health       # 健康检查 + 冲突检测
ubus call lanspeed interfaces   # 接口吞吐 + 覆盖率
ubus call lanspeed sysdevices   # 系统网络设备列表
```

## 兼容性

| 场景 | 影响 |
|---|---|
| OpenClash fake-ip / TUN | 置信度降低，远端地址仅作元数据 |
| dae / daed | 代理接口不作为客户端身份 |
| hardware flow offload | 硬件转发绕过 CPU，Full 模式不支持 |
| software flow offload | 告警但不阻止采集 |
| NSS ECM / PPE | 连接数经 ECM sync 回 conntrack，精度秒级 |
| SQM / qosify / IFB | 可能影响方向判断或覆盖范围 |
| LAN-to-LAN 硬件桥接 | CPU 不可见，覆盖率有限 |

## 项目结构

```
applications/luci-app-lanspeed/
  htdocs/luci-static/resources/
    lanspeed/                      模块 (vocab/format/rpc/ifaceConfig/nssPanel)
    view/lanspeed/index.js         视图入口
net/lanspeedd/
  src/lanspeedd.c                  daemon 主程序
  src/lanspeed_tc.bpf.c            eBPF 程序 (tc ingress/egress + ct_lookup)
  src/lanspeed_bpf.c/.h            libbpf loader
  files/                           设备端文件 (init.d / UCI config / schema)
scripts/build-sdk.sh               SDK 编译辅助脚本
tests/                             本地回归测试
```

## License

Apache-2.0
