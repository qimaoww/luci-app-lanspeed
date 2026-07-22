# Rust 兼容矩阵

这份记录描述源码、构建驱动和 eBPF 对象在稳定版 Rust 上的实际结果。它不把编译通过扩展解释为任意固件、内核或设备的运行验收。

## 稳定版矩阵

测试条件：每个 Rust 版本使用独立 `CARGO_TARGET_DIR`，固定 `bpf-linker 0.10.3`，`--locked --offline`，eBPF 使用 `-Z build-std=core`。两个对象均检查 ELF64 little-endian、EM_BPF、`classifier`、`maps`、`license`、`.BTF`、`.BTF.ext`，并检查反汇编中的 BPF 原子加法。

CI 对 `1.87.0` 至 `1.96.0` 以及 `1.97.1` 逐个使用精确 toolchain，并额外运行 `stable` 探测后续稳定版；每个成功点都执行生产 `lanspeedd/openwrt` feature、两个 eBPF 对象深检和离线用户态测试。

| Rust | 用户态测试（合并汇总） | kfunc 对象 | fallback 对象 | 备注 |
|---|---:|---:|---:|---|
| 1.87.0 | 446 passed, 0 failed, 1 remaining ignored | PASS, 178160 B, u64=4/u32=1 | PASS, 117424 B, u64=4 | MSRV |
| 1.88.0 | 446 passed, 0 failed, 1 remaining ignored | PASS, 178184 B, u64=4/u32=1 | PASS, 117440 B, u64=4 | 旧 intrinsic API |
| 1.89.0 | 446 passed, 0 failed, 1 remaining ignored | PASS, 178392 B, u64=4/u32=1 | PASS, 118168 B, u64=4 | atomic_xadd 两泛型 |
| 1.90.0 | 446 passed, 0 failed, 1 remaining ignored | PASS, 178392 B, u64=4/u32=1 | PASS, 118168 B, u64=4 | atomic_xadd 两泛型 |
| 1.91.0 | 446 passed, 0 failed, 1 remaining ignored | PASS, 181320 B, u64=4/u32=1 | PASS, 121808 B, u64=4 | atomic_xadd 三泛型 |
| 1.92.0 | 446 passed, 0 failed, 1 remaining ignored | PASS, 181216 B, u64=4/u32=1 | PASS, 124712 B, u64=2 | 三泛型 |
| 1.93.0 | 446 passed, 0 failed, 1 remaining ignored | PASS, 182168 B, u64=4/u32=1 | PASS, 123992 B, u64=2 | 三泛型 |
| 1.94.0 | 446 passed, 0 failed, 1 remaining ignored | PASS, 181088 B, u64=4/u32=1 | PASS, 124736 B, u64=2 | 三泛型 |
| 1.95.0 | 446 passed, 0 failed, 1 remaining ignored | PASS, 181120 B, u64=4/u32=1 | PASS, 124544 B, u64=2 | 三泛型 |
| 1.96.0 | 446 passed, 0 failed, 1 remaining ignored | PASS, 181704 B, u64=4/u32=1 | PASS, 125176 B, u64=2 | 固定发布基线 |
| 1.97.1 | 446 passed, 0 failed, 1 remaining ignored | PASS, 183960 B, u64=4/u32=1 | PASS, 127288 B, u64=2 | 本次最高已验证 |

用户态测试包含 daemon、共享 ABI、构建驱动，以及纯 Rust `lanspeed-openwrt-sys` 的 host ubus/UCI/uloop 测试。普通兼容运行的原始输出为 `445 passed, 0 failed, 2 ignored`：一个 ignored 测试需要 root、veth 和新 BPF 对象，另一个是宿主 conntrack smoke。CI 在 runner 提供 root 网络命名空间能力时，用 `--ignored --exact` 在隔离网络命名空间中执行 conntrack smoke，输出 `1 passed, 0 failed, 0 ignored`；若 runner 拒绝创建该命名空间，则明确输出 warning 并跳过这个单项 smoke，其他编译、eBPF 和用户态门禁仍继续执行。因此表中的 `446 passed, 0 failed, 1 remaining ignored` 是按完整隔离运行的唯一测试合并后的汇总，不是单次 Cargo 命令的输出；宿主表超过安全字节上限不会被当成 Rust 失败。

## 下界证据

Rust 1.86.0 的 `cargo check --workspace --locked --offline` 明确失败，报告 `aya@0.14.0`、`aya-build@0.2.0`、`aya-ebpf@0.2.1` 和 workspace crate 均要求 Rust 1.87.0。这个失败发生在 Cargo 的 MSRV 解析阶段，而不是运行时或单个 host 测试，因此将 1.87.0 作为连续 MSRV。

原始门禁输出包含：`aya@0.14.0 requires rustc 1.87.0`。

1.91.0 的第一次 BPF 尝试还暴露了 `atomic_xadd` 从二泛型变为三泛型的编译器 API 转折；兼容层按 `<1.89`、`1.89-1.90` 和 `>=1.91` 分段后，1.91.0 及以上全部重跑通过。1.96.0 的一次失败仅由共享临时文件系统空间不足造成，迁移到隔离缓存后通过。

## SDK 层级

Rust 矩阵不替代 SDK 门禁。SDK 构建必须另外记录：

- x86_64-musl daemon 的真实链接和 `DT_NEEDED` 检查；
- aarch64-musl 的真实 SDK 交叉链接，而不是 x86_64 host `cargo check` 冒充；
- 两种架构的 APK 元数据架构、依赖、daemon ELF、BPF ELF/BTF 和禁止的 OpenWrt 版本化库依赖。

这些结果只适用于实际使用的 SDK 和目标 ABI。未经对应设备运行验收的交叉产物不得标记为设备已验证。
