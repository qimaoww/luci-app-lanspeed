# 使用指南

[首页](../../README.md) · **使用指南** · [平台与采集](platforms.md) · [部署与排障](operations.md) · [构建与发布](development.md)

## 界面入口

- `状态 -> 客户端网速 -> 实时状态`
- 点击客户端名称进入连接详情
- `状态 -> 客户端网速 -> 运行诊断`
- `状态 -> 客户端网速 -> LAN Speed 配置`

实时状态显示客户端 `tx_bps`、`rx_bps`、连接数、主机名、地址、接入点和总速率 owner。连接详情按远端 IP 聚合 TCP/UDP，可展开实际连接并排序、分页、暂停刷新。浏览器只对当前页公网地址查询地理位置；私网、保留地址与 Fake-IP 在本地分类。

诊断页独立校验六个 RPC 请求。NSS 页面分开展示总速率 owner、精准接入拓扑和 NSS/CPU 分类；x86 页面只展示 TC-BPF 与连接详情健康。

## 客户端控制

实时客户端行可以设置独立上传、下载 Mbps，或禁用/恢复上网。规则永久保存；设备离线后不提供额外管理页，再次出现时可以继续修改，后台也可使用 `client_control_delete` 删除。

- x86 上传从 LAN ingress 重定向到自有 `ifb-lanspeed`，下载在 LAN egress 整形；两个方向使用 HTB + FQ。
- NSS 先用实时 N/S 分类分别确认上传、下载的真实数据路径；每个方向只进入一个整形执行器。
- NSS 下载在真实客户端出口使用 NSSHTB + NSSBFIFO，上传在真实客户端入口的 NSS IGS IFB 使用 NSSHTB + NSSBFIFO；透明代理/CPU 流量只被分类到同一个客户端方向队列，不按代理或 TUN 接口名适配。
- 路由器管理和 LAN/NAS 流量优先放行。
- 正常整形不使用 police 主动丢包；队列 `drops` 增长会报告 `queue_overflow`。
- 单纯禁网不安装整形队列；最后一条限速解除后会清理对应平台的自有分类器和根队列。
- 地址归属不唯一时返回 `ambiguous_identity`，不会清理可能属于其他设备的 conntrack。
- NSS 新规则先显示“等待路径确认”；实际 hook 和唯一执行器证明后才创建队列，随后以对应 class counter 增长确认“已验证生效”。缺少完整路径、唯一地址或可信客户端出口时不显示已生效。

控制与测速 BPF 相互独立：测速 BPF 先计数，控制分类器随后处理，因此重定向不会破坏 RateMux 或客户端实时速率。

## 配置

核心 UCI：

```uci
config lanspeed 'main'
    option refresh_interval_ms '1000'
    option active_client_window_ms '10000'
    option active_client_min_bps '1'
    option overview_window_samples '240'
    option rate_collector_mode 'auto'
    option access_edge_mode 'active'
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

| 选项 | 默认 | 行为 |
|---|---:|---|
| `refresh_interval_ms` | `1000` | BPF daemon 采样周期；NSS 不低于 2000 ms |
| `active_client_window_ms` | `10000` | 活跃客户端最近可见窗口 |
| `active_client_min_bps` | `1` | 活跃客户端最低速率 |
| `overview_window_samples` | `240` | 概览历史样本数 |
| `rate_collector_mode` | `auto` | x86 只能落到 BPF；NSS 可选自动、BPF、ECM 或 ECM+BPF |
| `access_edge_mode` | NSS: `active` | 仅 NSS 构建使用，x86 配置不包含该项 |
| `conn_collector_mode` | `auto` | `auto` / `conntrack_netlink` / `conntrack_procfs` |
| `max_clients` | `2048` | 客户端容量，范围 64 到 16384 |
| `interface_include` | `br-lan` | 客户端速率采集接口 |
| `observe` | `wan` | 只显示接口吞吐 |
| `enable_bpf` | `1` | BPF 运行开关，不改变包依赖 |
| `enable_conntrack_fallback` | `1` | 连接元数据回退，不参与总速率 |

历史配置中的 `dedicated_port` 已停用；配置页保存时会自动清理该遗留项。客户端详情中的主机名按 MAC 写入 `/etc/config/dhcp`，不会强制配置静态 IP。

## ubus 调试

```sh
ubus call lanspeed realtime
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
ubus call lanspeed client_control_set \
  '{"identity_key":"02:00:00:00:00:42@br-lan","upload_bps":"20000000","download_bps":"50000000","internet_disabled":"0"}'
ubus call lanspeed client_control_delete \
  '{"identity_key":"02:00:00:00:00:42@br-lan"}'
```

十二个 ubus 方法返回统一版本和结构化 evidence；`realtime` 是实时页使用的原子轻量快照，完整诊断仍由原方法提供。状态 `mode` 为 `Full`、`Degraded` 或 `Unsupported`，`confidence` 为 `high`、`medium`、`low` 或 `unsupported`；`router_self` 表示路由器自身流量语义。

`client_control_set` 只接受十进制 bit/s 和 `0`/`1` 开关。两个方向分别观察自有 class counter，只有对应计数增长后才标记已验证。

`client_connections` 返回当前 conntrack 快照：TCP 仅统计 ESTABLISHED + ASSURED，UDP 仅统计 ASSURED。`client.rx_bps`/`client.tx_bps` 是该客户端当前已发布快照的下行/上行总速率，不从受限的连接明细列表求和；因此即使明细被截断，摘要总速率仍保持完整。`client.rate_sample_ms`、`client.rate_collector_mode` 和 `client.rate_meta` 同时给出这组总速率的采样时间、采集器和方向级来源/窗口，不能与响应顶层的 conntrack `sample_ms` 混用。

连接跟踪快照不可用或不完整时，`client_connections` 仍可能返回客户端总速率；此时连接数量和明细必须按不可用处理，前端会明确标注“连接数据暂不可用”，不会把缺失的连接明细当成零速率或与总速率相加。

每条连接的速率由相邻累计字节快照计算；新连接、计数器回退或时间回退不会生成虚假速率。NSS 的客户端总速率通常来自接入 Edge（有线端口或 Wi-Fi station）滚动窗口，而逐连接速率来自独立 Conntrack 窗口；硬件卸载同步可能使 Conntrack 延迟或漏记连接级字节，所以连接行可用于识别目标和观察趋势，不能按连接行求和反推或校准总速率。页面会明确显示这两个采样面，不使用比例摊分伪造单连接精度。
