# 平台与采集

[首页](../../README.md) · [使用指南](usage.md) · **平台与采集** · [部署与排障](operations.md) · [构建与发布](development.md)

## 平台模块

x86/TC-BPF 与 Qualcomm NSS 使用独立编译配置和生产采集循环，只共享稳定 RPC 模型与平台无关组件。

| 模块 | 用户态源码 | eBPF 源码 | 速率来源 |
|---|---|---|---|
| x86/TC-BPF | `platform/x86/` | `lanspeed-ebpf/src/x86/` | LAN ingress/egress TC map，按 MAC + zone/VLAN 聚合 |
| Qualcomm NSS | `platform/nss/` | `lanspeed-ebpf/src/nss/` | NSS TC 慢路径、ECM node 与 totals-update kprobe |
| Access Edge | `platform/access_edge/` | 无 | Bridge FDB、NL80211 station 与 netdev 计数 |
| 公共层 | `platform/counters.rs`、RPC 模型 | `lanspeed-common` | 无平台计数结构与统一响应契约 |

`platform/x86` 与 `platform/nss` 双向零引用。x86_64 用户态构建不包含 NSS、ECM、Access Edge、分类窗口或 RateMux；NSS 融合层不接收 x86 类型。客户端控制分别位于 `platform/x86/control/` 与 `platform/nss/control/`；NSS 的 CPU 执行器只位于 `platform/nss/control/cpu_path/`，不导入、调用或编译 x86 控制。eBPF 分别启用 `x86-tc` 与 `nss-tc` 源入口，x86_64 构建不会安装 ECM 对象，也不会探测 NSS 文件族。

## Access Edge 与分类语义

NSS 平台每个客户端、每个方向只有一个总速率 owner：Wi-Fi station、稳定有线端口、严格同窗 ECM+TC fallback、单源 lower-bound 或 unavailable。候选源独立维护累计基线；移动、重关联、计数回退和来源切换都会重新 warmup。

```text
E = Access Edge 权威总量
N = ECM/NSS 已识别硬件流量
S = TC-BPF 已识别 CPU 慢路径流量
U = E - (N + S)，仅在同窗口且 ByteDomain 兼容时发布
```

主表总速率显示 `E`，`N`、`S` 只做分类，不与 `E` 相加。分类器只在严格同窗且口径兼容时合并原始增量，不叠加已经计算过的速率。不同 ByteDomain、map loss、attachment 变化或 `N+S>E` 时保留 N/S，但省略 U 和覆盖率。

Edge 每 1 秒采样，ECM/TC 每 2 秒采样，连续三个稳定 epoch 形成 6 秒比较窗。Wi-Fi station 的 802.11 字节无法通过标准接口精确还原为以太网口径，因此保持 `domain_mismatch`。

## x86/TC-BPF

- 非 NSS 设备由 BPF tc 提供客户端速率，x86_64 的自动模式只能落到 BPF。
- BPF 对象为 `/usr/lib/bpf/lanspeed-ebpf-kfunc` 和 `/usr/lib/bpf/lanspeed-ebpf-fallback`。
- TC hook 使用固定 owner、pref 和 handle，只管理自身 filter，不删除 clsact 或外部 filter。
- 页面刷新选择为 `1/2/3/5/10` 秒，daemon 按 `refresh_interval_ms` 采样。
- hardware flow offload 会绕过 CPU TC hook，conntrack 只提供连接信息，不能补齐总速率。

### 客户端控制链路

上传先绕过路由器/LAN/NAS 目标，再从 LAN ingress 重定向到自有 IFB；下载在 LAN egress 按唯一客户端地址分类。两个方向使用独立 HTB + FQ 树，不使用 skb mark、WAN 根队列、NSS qdisc、ECM QoS tag、TUN 或 police。

应用时先校验依赖、接口和对象所有权，再停用流量入口、创建并验证完整队列树，最后启用分类器。失败时只删除带有 lanspeedd owner 的对象。活动规则更新会先删除已确认属于本服务的旧 HTB 根，避免 `tc qdisc replace` 保留旧 class。

## Qualcomm NSS

Qualcomm aarch64 NSS 设备自动按 ECM+BPF、ECM、BPF 选择健康后端，手动模式失败时不静默切换。

- `nss_ecm_node` 读取 ECM node advanced statistics，使用 `time_added` 区分计数代次。
- `nss_ecm_bpf` 使用 `AYA_BPF_TARGET_ARCH=aarch64` 构建的 `/usr/lib/bpf/lanspeed-ebpf-ecm`，读取内核与 ECM BTF 后挂载 totals-update 和 NSS callback context kprobe。
- ECM 热 map 按 MAC 与方向聚合；容量至少为 `2 × max_clients`，TC map 至少为 `4 × max_clients`，并发布 pressure、truncation 与 map-loss 证据。
- NSS callback 上下文按 `pid_tgid` 记录嵌套深度，避免任务迁核产生 per-CPU 泄漏。
- ECM node、ECM+BPF 最低每 2 秒采样，页面刷新选择为 `2/4/8/10` 秒。
- 首次快照保持 `warmup/0`；只有有效相邻计数推进才发布速率，计数停顿后明确归零。
- 覆盖率进入 `pending`，不会阻塞逐客户端速率。
- 物理 LAN MIB 只负责覆盖率验证和窗口预算，不复制客户端速率，也不插值或生成假值。

### 客户端控制链路

NSS 控制使用实时 Access Edge 与严格同窗 N/S 分类为每个客户端、每个方向选择一个聚合执行器。窗口完整且流量足够时，下载树安装到 Access Edge 确认的真实客户端出口，直连 ECM classid 与 CPU egress `skbedit` 共同选择同一 NSSHTB + NSSBFIFO 根树；上传在真实客户端入口建立一个每边共享的 NSS IGS IFB，按源 MAC 在同一 NSSHTB + NSSBFIFO 树内分 class，NSS 直连和透明代理接管前后的入口流量不再各自拥有独立上限。透明代理新建的 WAN socket 不再携带客户端身份，因此从不在 WAN 侧把它反推为某个客户端。

路径未证明时保持 `nss_path_identity_pending`，不创建 class、不重定向，也不写 QoS map。应用按“能力与所有权预检 → 暂停旧 QoS tag → 创建并验证唯一队列 → 发布边缘重定向或原子 nft 映射 → 精确清理所需客户端 conntrack”执行。每次状态观察都会重新核验自有 nft、队列与 filter；对象被删除后立即撤销 verified 并事务重建。失败只回滚带专用 handle、chain、IFB alias 或 nft comment 的对象。

本地目的前缀在上传 ingress 先放行，本地来源前缀在下载 egress 先放行；路由器管理、LAN/NAS、客户端间与非 IP 流量不进入整形。禁网在实际客户端边缘的 ingress/egress 都安装 drop，并由 nft forward 规则补强；限速不使用 police、nft limit 或丢包模拟。NSS/CPU class counter 与 queue drops 只验证控制，不进入 Access Edge、RateMux 或客户端总速率。

## 支持范围

| 目标 | 支持 |
|---|---|
| `x86_64` LP64 | 独立 TC-BPF；不编译 NSS/ECM/Access Edge |
| Qualcomm `aarch64` LP64 | Access Edge 总速率与 NSS/ECM/TC 分类融合 |
| 32 位 ARM、i386 和 MIPS | Unsupported |

用户态与 eBPF workspace 要求稳定版 `Rust >= 1.87.0`。兼容矩阵覆盖 `1.87.0` 到 `1.97.1`、低于 MSRV 的拒绝、内部 atomic intrinsic 的版本转折点、`EM_BPF` 与 aarch64-musl，详见 [Rust compatibility matrix](../rust-compatibility-matrix.md)。

交叉编译通过不等于具体设备已完成真机验证；产物仍须匹配目标架构、musl、内核 BPF/BTF 和 LuCI ABI。
