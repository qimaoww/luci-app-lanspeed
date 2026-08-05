# 部署与排障

[首页](../../README.md) · [使用指南](usage.md) · [平台与采集](platforms.md) · **部署与排障** · [构建与发布](development.md)

## 运行依赖

原有实时统计依赖为 `libgcc`、`kmod-nf-conntrack-netlink`、`tc-full` 和 `kmod-sched-bpf`。

x86 客户端控制额外依赖 `ip`、`nftables`、`conntrack`、`kmod-ifb`、`kmod-sched-core` 与 `kmod-sched`；架构门保证这些依赖不进入 aarch64/NSS 包。缺少能力或目标钩子被其他服务占用时，控制按钮会显示结构化原因，不会覆盖外部对象。

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
| 限速应用失败 | 检查外部 qdisc/IFB 所有权及 HTB、FQ、u32、mirred 模块 |
| `queue_overflow` | 检查自有 qdisc 的 drops、链路拥塞和队列容量 |

控制失败后，具体错误会保持到规则或拓扑发生变化，不会被“等待流量验证”覆盖。清理只匹配本服务的 handle、chain、IFB alias 与 nft comment。
