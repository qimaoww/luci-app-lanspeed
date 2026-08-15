# 部署与排障

[首页](../../README.md) · [使用指南](usage.md) · [平台与采集](platforms.md) · **部署与排障** · [构建与发布](development.md)

## 运行依赖

原有实时统计依赖为 `libgcc`、`kmod-nf-conntrack-netlink`、`tc-full` 和 `kmod-sched-bpf`。

x86 客户端控制额外依赖 `ip`、`nftables`、`conntrack`、`kmod-ifb`、`kmod-sched-core` 与 `kmod-sched`；这些依赖保持原有 x86 条件，不被 NSS 实现复用。缺少能力或目标钩子被其他服务占用时，控制按钮会显示结构化原因，不会覆盖外部对象。

NSS 客户端控制依赖 `tc-full`、`ip`、`nftables`、`conntrack`、`kmod-ifb`、`kmod-sched-core`、`kmod-qca-nss-drv-igs` 与 NSS 专属 `kmod-lanspeed-nss-control`。直连方向还要求固件已有 `qca_nss_qdisc`、NSSHTB/NSSBFIFO 和已启用的 ECM DSCP classifier；`platform/nss/control/cpu_path/` 只负责证明身份、建立每边一个聚合 IGS IFB、上传 MAC 分类和下载 egress classid，不导入或调用 x86 控制代码。CPU/透明代理流量与 NSS 直连流量进入同一客户端方向队列。

Qualcomm NSSHTB 根不接受 TC filter。直连 class 只能由 nft `meta priority` 与 ECM QoS tag 选择；u32/mirred 仅安装在已证明保留客户端 MAC 的普通边缘 clsact 与 LAN Speed 专属 IFB。不要在 NSSHTB 根追加 matchall/u32 链。

三个安装包的职责：

| 包 | 内容 |
|---|---|
| `lanspeedd` | daemon、UCI、ubus、采集与状态 |
| `lanspeedd-bpf` | 目标架构对应的 TC-BPF/ECM 对象 |
| `luci-app-lanspeed` | LuCI 页面与 RPC 权限 |

`luci-app-lanspeed` 强制依赖 `lanspeedd-bpf`，后者依赖 `lanspeedd`。

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
CONFIG_NET_SCH_HTB=y
```

ECM+BPF 还要求可读的 `/sys/kernel/btf/ecm` 和受支持的 `ecm_db_connection_data_totals_update` / NSS callback symbol；ECM node 要求可读 `/dev/ecm_state` 与对应 debugfs 文件。

## 可见性与告警

| 场景 | 当前行为或告警 |
|---|---|
| OpenClash fake-ip | `openclash_fake_ip_low_remote_confidence` |
| OpenClash TUN/mix | `openclash_tun_conntrack_low_confidence` |
| OpenClash DNS 链不完整 | `openclash_dns_chain_incomplete` |
| dae/daed | `dae_detected`；只报告活动状态，不改变 NSS 自动回退策略 |
| SQM/qosify/ifb | `sqm_detected`、`qosify_detected`、`ifb_detected` |
| hardware flow offload | `hardware_flow_offload_unsupported` |
| software flow offload | `software_flow_offload_enabled` |
| fullcone NAT | `fullcone_nat_enabled` |
| 外部 TC filter | `tc_filter_conflict` |
| conntrack NAT-only 行 | `conntrack_routed_nat_only` |
| flowtable / nlbwmon | `flowtable_counter_missing`、`nlbwmon_counter_conflict` |
| same-subnet side-router direct | 同网段客户端与旁路网关直连可能绕过采集点 |
| LAN-to-LAN | `lan_to_lan_visibility_limited` |
| 不对称路径 | `asymmetric_path_possible` |
| VLAN/Wi-Fi 重复 MAC | `duplicate_mac_across_vlans` |
| BPF map 容量耗尽 | `map_full` |
| FDB/NL80211 不完整 | 降级为 Partial/Unavailable，并发布原因 |
| ECM/TC ByteDomain 不兼容 | `domain_mismatch`，不计算虚假的未分类速率 |
| router-local | 不自然归属为 LAN 客户端 |
| PPPoE/WG/TUN | 外层可观察，客户端身份仍由 LAN 边缘决定 |

## 故障排查

| 现象 | 检查 |
|---|---|
| SDK 缺失 | 检查 `SDK_DIR` 与目标架构 |
| 缺少 BPF 包或对象 | 检查 `lanspeedd-bpf` 和 `/usr/lib/bpf/lanspeed-ebpf-*` |
| 缺少 `tc` | 安装 `tc-full`，检查 clsact/filter |
| 连接数为 0 | 检查 `nf_conntrack_acct`、Netlink 模块和连接采集模式 |
| 没有客户端 | 检查 LAN 接口、BPF attach 与 ECM node MAC 映射 |
| 速率长时间为 0 | 检查 `effective_collector`、map/state 和 `sample_ms` |
| OpenClash 或 dae/daed 共存 | 检查 TC hook、NSS state 和诊断 evidence |
| 覆盖率低 | 检查 offload、旁路路径、LAN-to-LAN、IFB/TUN 和接口边界 |
| x86 限速应用失败 | 检查外部 qdisc/IFB 所有权及 HTB、FQ、u32、mirred 模块 |
| NSS 限速应用失败 | 检查路径确认状态、真实 WAN/Access Edge、NSS 根或专属 IFB 队列所有权和结构化原因 |
| `queue_overflow` | 检查自有 qdisc 的 drops、链路拥塞和队列容量 |

### SDK 基础配置缺失

如果同版 SDK 的标准 `package/.../compile` 在基础包依赖阶段报告目标内核 `.config` 不存在，说明 SDK 的外部构建树尚未准备完整。不得为了 LAN Speed 测试重建、修改或替换外部内核及基础组件；应保留该阻塞证据，先用 LAN Speed 自身的离线契约、对象和包内容校验完成可验证范围，待 SDK 基础构建树由其维护流程准备好后再重跑目标编译。

控制失败后，具体错误会保持到规则或拓扑发生变化，不会被“等待流量验证”覆盖。清理只匹配本服务的平台专用 handle、chain、IFB alias 与 nft comment。
