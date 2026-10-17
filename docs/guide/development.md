# 构建与发布

[首页](../../README.md) · [使用指南](usage.md) · [平台与采集](platforms.md) · [部署与排障](operations.md) · **构建与发布**

## 安装与编译

在 ImmortalWrt / OpenWrt 源码根目录执行：

```sh
echo "src-git lanspeed https://github.com/qimaoww/luci-app-lanspeed.git" >> feeds.conf
./scripts/feeds update lanspeed
./scripts/feeds install -a -p lanspeed

# LuCI -> Applications -> luci-app-lanspeed -> NSS hardware acceleration support
make menuconfig
make -j"$(nproc)" package/lanspeedd/compile
make -j"$(nproc)" package/luci-app-lanspeed/compile
```

`luci-app-lanspeed` 强制依赖 `lanspeedd-bpf`。同一 `package/lanspeedd/compile` 目标按 SDK 架构生成 TC 对象，并只在 aarch64 生成 ECM 对象。

`luci-app-lanspeed` 在 menuconfig 中提供 `NSS hardware acceleration support` 子菜单开关（`CONFIG_LUCI_APP_LANSPEED_NSS`），默认在 `TARGET_qualcommax` 上启用。它同时控制 daemon 的 Rust `nss-platform` feature、NSS 专用的 ECM eBPF 对象与 `kmod-lanspeed-nss-control`/`kmod-qca-nss-drv-igs` 依赖、NSS 内核模块加载器与整形迁移脚本，以及 NSS 配置页面和菜单入口；关闭后仅保留 TC-BPF 路径，适合无 NSS 引擎的设备。

本地 checkout：

```sh
SDK_DIR=/path/to/immortalwrt-sdk ENABLE_BPF=1 DRY_RUN=1 scripts/build-sdk.sh
SDK_DIR=/path/to/immortalwrt-sdk ENABLE_BPF=1 scripts/build-sdk.sh
```

`DRY_RUN` 只显示步骤；正式产物必须由目标 SDK 重建并在实机验证。

## 项目结构

```text
applications/luci-app-lanspeed/               LuCI 页面、模型和 RPC
net/lanspeedd/rust/crates/lanspeedd/src/
  platform/access_edge/                        NSS 接入拓扑、Edge 计数和 RateMux
  platform/x86/                                x86 TC-BPF 与独立客户端控制
  platform/nss/                                NSS/ECM 分类、融合与独立混合路径控制
  collectors/conntrack/                        连接元数据
net/lanspeedd/rust/crates/lanspeed-ebpf/src/
  x86/                                         x86 TC accounting
  nss/                                         NSS TC 与 ECM kprobe
net/lanspeedd/rust/crates/lanspeed-common/     用户态/eBPF ABI
net/lanspeedd/rust/crates/lanspeed-build/      OpenWrt 构建驱动
tests/                                         单元、契约、打包和浏览器回归
```

## 测试

本地环境可以运行确定性检查脚本：

```sh
./tests/run.sh unit
./tests/run.sh probe-fixtures
cargo test -p lanspeedd --features openwrt
sh tests/validate-lanspeed-docs.sh
```

测试覆盖平台边界、Rust 单元测试、eBPF 对象、RPC/schema、LuCI、探针 fixtures 和打包契约。最终验收还需要真实 SDK 编译、目标设备安装及真实浏览器检查。

测试输出默认进入每次运行唯一的临时目录并在退出时清理。只有显式设置 `LANSPEED_TEST_OUTPUT_DIR=/path` 才保留日志；实机 `qa-device.sh` 必须显式提供 `OUT_DIR`。

只读实机基准可用于部署前后对照，无需安装额外设备依赖：

```sh
python3 tests/benchmark-device.py root@192.0.2.1 --output /tmp/lanspeed-before.json
# 部署待测版本并等待采集窗口稳定后，使用相同采样参数再次运行
python3 tests/benchmark-device.py root@192.0.2.1 --output /tmp/lanspeed-after.json
```

脚本需要 Python 3.9+ 和已有 SSH 密钥认证；默认对八个只读 RPC 各采样五次，同时记录 RSS 与 CPU。输出只保存延迟、计数和白名单状态，不保存客户端原始响应，也不触发 reload 或修改配置。RPC 延迟包含 SSH 与网络开销，报告另列空命令基线；真实流量不同会影响结果，不能仅由一次对比推断性能提升。

## 发布

发布 workflow 默认禁用，不监听 `main`、tag 或 pull request；仓库内仅保留 `workflow_dispatch` 手动触发。需要发布时，由仓库管理员临时启用 `Build SDK Packages` 并手动运行，只为 x86_64 构建 `lanspeedd`、`lanspeedd-bpf`、`luci-app-lanspeed` 三个 APK 和一个整合归档，完成后重新禁用该 workflow。

Qualcomm NSS 不发布通用预编译包。NSS 控制依赖专属 `kmod-lanspeed-nss-control`，必须与目标设备的内核 ABI、NSS 驱动和固件编译配置保持一致；建议使用目标固件的同版源码或 SDK 自行编译，不能混用其他固件生成的 kmod。

Rust 主机工具链按 runner 操作系统与架构、目标架构、SDK SHA256、feeds 实际 revision、Rust 配方版本和内容哈希隔离缓存，后续相同 SDK 不再从头编译 Rust。

workflow 先创建草稿 Release，精确校验四个 x86_64 资产后再发布。失败草稿可由同一版本提交再次手动运行以重建，也可补发缺失的 tag/Release。维护者不得预先创建 `v*` tag。
