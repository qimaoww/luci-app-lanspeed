# 使用指南

[首页](../../README.md) · **使用指南** · [平台与采集](platforms.md) · [部署与排障](operations.md) · [构建与发布](development.md)

## 界面入口

- `状态 -> 客户端网速 -> 实时状态`
- 点击客户端名称进入连接详情
- `状态 -> 客户端网速 -> 运行诊断`
- `状态 -> 客户端网速 -> LAN Speed 配置`
- `状态 -> 客户端网速 -> NSS 配置`（仅检测到 NSS 的设备显示）

实时状态显示客户端 `tx_bps`、`rx_bps`、连接数、主机名、地址、接入点和总速率 owner。连接详情按远端 IP 聚合 TCP/UDP，可展开实际连接并排序、分页、暂停刷新。浏览器只对当前页公网地址查询地理位置；私网、保留地址与 Fake-IP 在本地分类。

实时状态页按状态区、紧凑指标区、客户端主列表、辅助接口信息组织。刷新间隔、“立即刷新”和“暂停”集中在状态区；下载、上传、客户端和连接数各显示一次。列表通过搜索和“仅活跃”筛选，支持设备名、网络地址、MAC、中文厂商名及原始注册名称；MAC可使用冒号、短横线、点分或无分隔符格式。排序统一使用下拉框，方向标为“升序”“降序”，手机端也能操作；“清除筛选”同时清除搜索及仅活跃条件。客户端、MAC、下载速度、上传速度、累计下载、累计上传、TCP、UDP 各占一列，按下载在前、上传在后的顺序均衡铺满表格；表头与数据共享左边缘，内容垂直居中。隐藏累计流量时同时隐藏两个方向并重新分配列宽；中宽使用紧凑卡片，手机端下载与上传成对排列，按内容宽度自然换行。MAC完整显示；有明确匹配图标的厂商以 Logo 显示在客户端名称后，悬停、键盘聚焦或触摸图标可查看中文厂商名称。未知或未收录图标的厂商不显示空徽章。点击设备名进入连接详情和设备控制，“列表说明”集中解释入口与统计口径。接口吞吐默认折叠并记住展开状态。

累计流量从启用采集后开始，按客户端身份持续保存，正常重启服务或设备后继续累计。x86 和 NSS 均使用实际计数字节，不对显示速率积分；没有可靠数据的方向显示 `-`，真实零值显示 `0 B`。NSS 按当前选中的采集源记账，采集源切换或计数器重置时重新建立基线；未观测到的间隔不估算，历史流量不补算。手动 ECM 模式无法提供可靠累计差值时，仅保留已保存历史。关闭“显示客户端累计流量”后停止累计，已保存的历史保留。

累计数据保存在 `/etc/lanspeed/traffic.db`，每五分钟批量写入，正常停止服务时立即保存。突然断电可能丢失最后五分钟尚未保存的数据；固件重刷或清理该数据库也会丢失历史，升级前应单独备份。

诊断页保留完整排障信息：服务、采集、连接详情与版本概况，严重告警和环境提示，本机 TC 冲突结论、扫描完整性、全部对象与归属，逻辑接口的角色、状态、采样时间和吞吐，以及各运行子系统和六个 RPC 请求的独立结果。NSS 平台另显示精准速率采集链路与客户端控制证据。TC 对象、RPC 明细和脱敏报告可展开查看，窄屏表格可通过触摸或键盘横向滚动；重新检查、重启服务和复制脱敏报告集中在页首。

列表只显示名称后的厂商图标，连接详情保留“厂商”信息及查询状态。安装包附带可离线使用的厂商基础表，首次打开也能识别表内厂商；外网可用时再更新完整注册表，相同前缀优先使用在线数据，仍以更长前缀优先。离线结果保留来源说明，不会因浏览器缓存过期而消失。图标由本地共享 SVG 图库提供，横向字标按实际比例调整尺寸，不逐设备下载图片。浏览器合并 [Wireshark manuf 列表](https://www.wireshark.org/download/automated/data/manuf) 与 [runZero 每日同步的 IEEE 原始 CSV](https://github.com/runZeroInc/mac-tracker/tree/main/data/ieee)，覆盖 MA-L、MA-M、MA-S 和历史 IAB 分配；镜像访问失败时尝试对应 IEEE 官方 CSV。仅下载固定的完整注册表，不发送设备MAC或前缀。先按 36、28、24 位依次匹配，同一前缀优先新鲜数据，再优先 IEEE CSV，保留来源用于排查。不把 IEEE 注册局父前缀、Private、虚拟网卡约定或本地管理地址推断成厂商品牌；同一 IEEE 前缀存在多个注册机构时提示“注册机构存在多个记录”。首页、详情、搜索与图标共用本地中文对照表；原始注册名称保留作查询及排查，界面及厂商悬浮提示不回退显示英文公司名称。已查到注册机构但未收录中文名称时显示“中文名称待补充”，数据库无前缀时显示“未知厂商”，本地管理地址显示“本地管理地址”，不据此断言是随机地址。下载失败显示“厂商数据库加载失败”，响应无法用于查询时显示“厂商查询失败”；不影响实时测速。Wireshark 缓存新鲜期 7 天，IEEE CSV 为 1 天；各注册表独立重试，某个来源失败时继续使用其他有效来源，可在刷新失败时使用 30 天以内的数据；长时间打开页面也会重新检查期限，过期结果明确标为“缓存已过期”。各来源失败后 60 秒内不重复下载，慢速加载或不可用时搜索会提示厂商匹配尚不完整。识别结果仅代表地址前缀注册机构，可能是网卡或模块厂商，图标不能确认整机品牌。

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

“LAN Speed 配置”管理通用采集、连接、显示与接口设置。“NSS 配置”单独管理客户端总速率、互联网/路由视图、低速对齐窗口、队列和速率补偿。两个页面的保存、恢复默认值和重置只影响本页设置。

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

x86 配置页额外提供透明代理连接补全：

| 选项 | 默认 | 行为 |
|---|---:|---|
| `enable_proxy_connections` | `1` | 启用本机 Mihomo/OpenClash API 与 dae/daed 连接补全 |
| `mihomo_controller_port` | `0` | `0` 自动读取 OpenClash `cn_port`，否则覆盖本机控制器端口 |
| `mihomo_controller_secret` | 空 | 空值自动读取 OpenClash `dashboard_password`，否则使用手动认证码 |

Mihomo 控制器始终只连接 `127.0.0.1`。认证码字段使用密码输入框；手动值保存在 `/etc/config/lanspeed`，自动模式不会把 OpenClash 原认证码复制到 LAN Speed 配置。

dae/daed 没有逐连接 API。x86 后端只读取运行中 dae/daed 进程实际持有的数据：TCP 来自 `daens` 网络命名空间中的 ESTABLISHED socket，并通过内核 SOCK_DIAG/TCP_INFO 累计字节计算逐连接速率；UDP 在 dae 1.x 上同时校验 `udp_conn_state_map` 与 `routing_tuples_map`，在 dae main 及跟踪 main 的第三方构建（如 kenzok8/openwrt-daede）上读取合并后的 `conn_state_map` 内嵌路由，仅接收用户定义代理 outbound，排除 direct、block 和中间路由状态。UDP 条目生命周期由上游状态定时器决定；内核诊断或 BPF map 名称、类型、ABI 尺寸不匹配时该适配器直接跳过，不猜测解析。 OpenWrt 包与 daed 镜像把上游二进制重命名为 `daed`，dae-wing 镜像和未覆盖 `APPNAME`/`OUTPUT` 的本地构建保留 `dae-wing`；后端同时识别 `dae`、`daed`、`dae-wing` 三种进程名，并在容器不共享宿主 `/run` 时通过进程根目录解析 `daens`。

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

`client_connections` 以当前 conntrack 快照为基础：TCP 仅统计 ESTABLISHED + ASSURED，UDP 仅统计 ASSURED；x86 启用透明代理补全后，还会合并上述 Mihomo 或 dae/daed 逻辑连接。`client.rx_bps`/`client.tx_bps` 是该客户端当前已发布快照的下行/上行总速率，不从受限的连接明细列表求和；因此即使明细被截断，摘要总速率仍保持完整。`client.rate_sample_ms`、`client.rate_collector_mode` 和 `client.rate_meta` 同时给出这组总速率的采样时间、采集器和方向级来源/窗口，不能与响应顶层的 conntrack `sample_ms` 混用。

连接跟踪快照不可用或不完整时，`client_connections` 仍可能返回客户端总速率；此时连接数量和明细必须按不可用处理，前端会明确标注“连接数据暂不可用”，不会把缺失的连接明细当成零速率或与总速率相加。

每条连接的速率由相邻累计字节快照计算；新连接、计数器回退或时间回退不会生成虚假速率。NSS 的客户端总速率通常来自接入 Edge（有线端口或 Wi-Fi station）滚动窗口，而逐连接速率来自独立 Conntrack 窗口；硬件卸载同步可能使 Conntrack 延迟或漏记连接级字节，所以连接行可用于识别目标和观察趋势，不能按连接行求和反推或校准总速率。页面会明确显示这两个采样面，不使用比例摊分伪造单连接精度。
