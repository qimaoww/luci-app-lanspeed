# 优化与实机验证记录（2026-10-11）

本次基于上游 `3e8f66c`，在已有 OpenWrt 工作区完成优化并部署到授权的 Qualcomm NSS / aarch64 设备。保留工作区原有的 `interfaces.rs` VLAN 计数修改。包版本仍为 `1.2.1-r2`，属于本地重建，尚未创建 GitHub 发布。

## 修改

- 连接采集与周期速率采集通过可重试的原子合并发布，避免慢连接采集用旧快照覆盖较新的速率、拓扑或 FastRate 数据。
- Conntrack procfs 解析复用有界行缓冲，取消逐连接 token 数组，并兼容旧版 `/proc/net/ip_conntrack` 格式。
- 总览和客户端详情隐藏时停止轮询，恢复可见时立即刷新；用户手动暂停仍然有效。页面卸载清理定时器、监听和 Geo 请求，忽略迟到响应；往返缓存恢复后继续刷新。
- 主机名及配置保存交给 LuCI 原生 Apply 流程处理确认、错误与刷新，修复把返回 `void` 的接口误当 Promise、提前报成功的问题。
- Geo 请求超时或页面销毁后不再继续请求备用服务，兼容缺少 AbortController 的环境。
- 声明 `/etc/config/lanspeed` 为包配置文件，生成配置保留与固件备份元数据。
- 测试运行器自动查找 BPF linker 时校验固定版本，避免误选旧构建目录中的无效程序。
- 新增只读、输出脱敏摘要的 `tests/benchmark-device.py`，使用方法见[开发指南](guide/development.md)。

上游已有的 Shadcn 支持随本次 LuCI 包部署。设备旧包缺少该适配导致的主题识别、按钮对比度和桌面宽布局问题，部署后均通过浏览器审计。

## 验证

| 检查 | 结果 |
| --- | --- |
| `tests/run.sh unit` | 通过；Rust workspace 533 项、OpenWrt wire/host 35 项通过，前端、RPC、打包、版本及 SDK 契约通过 |
| NSS feature 测试 | 838 项通过；文档测试使用同一 SDK Rust 工具链补跑通过 |
| Probe fixtures、文档、差异格式 | 通过 |
| OpenWrt 目标构建 | `qualcommax/ipq60xx` 的 daemon、BPF、LuCI APK 均生成成功 |
| APK 内容检查 | LuCI 资源检查通过；daemon APK 包含配置文件列表与校验和 |
| 实机安装 | 安装本次 daemon 与 LuCI APK；已有 BPF、NSS 内核模块继续使用 |
| 配置保留 | LAN Speed、network、firewall、dhcp 四个配置的 SHA256 部署前后相同 |
| 实机 RPC 基准 | 8 个只读 RPC 各 10 次，80 次全部成功，中位延迟约 13–27 ms（含 SSH） |
| 持续并发采样 | 28 秒内 45 次 RPC 全成功；采集代数前进 28，采样时间前进 27,997 ms，进程身份稳定，probe failure 为 0 |
| 浏览器 | 真实 Chromium、Shadcn 亮色，桌面 1920×1080 与手机 390×844 的总览/诊断/配置共 6 个场景全部通过 |
| 页面生命周期 | 实机页面总览/详情隐藏 3.2 秒均 0 次 RPC，恢复后继续刷新，移除 DOM 后 3 秒均 0 次；无页面异常或写请求 |

生命周期检查使用浏览器中的 `document.hidden` / `visibilityState` getter 与事件注入；有头 Chromium 的标签切换未触发隐藏状态，因此不将其计作真实标签隐藏测试。往返缓存的 `pagehide/pageshow` 同样使用合成事件验证。

两项依赖隔离 veth/BPF 和有界宿主机 conntrack 表的测试沿用原有 `ignored` 设置。未在生产网络上改动客户端限速、禁用上网或提交配置表单；这些写路径的异步边界使用行为回归验证。

解析微基准使用优化编译的相同输入，重复处理 100 × 10,000 条连接：每次 dump 的堆分配从 50,003 次降到 4 次，耗时从 3.318 ms 降到 2.463 ms，约减少 26%。该数据仅衡量解析环节，不代表整机 CPU 或链路吞吐提升。实机流量与启动后的历史窗口不同，因此没有依据单次前后 RPC/CPU 数字宣称整体性能百分比。

设备仍报告原有的 `Degraded` 状态，包含 DAE hook 抢占与 ECM BPF 回退到 `nss_ecm_node` 等环境限制。TC BPF 的 4/4 hooks 已就绪；本次没有更改这些告警语义或尝试替换无线/NSS 驱动。

## 产物与备份

工作区产物目录为 `bin/packages/aarch64_cortex-a53/lanspeed/`：

| 已部署包 | SHA256 |
| --- | --- |
| `lanspeedd-1.2.1-r2.apk` | `4ba5eab8d75e4f8f3cf4b1a4fe819179b006343090d37660a4f1c37afd8522c7` |
| `luci-app-lanspeed-1.2.1-r2.apk` | `0d9854a89368e0f8d5e5f80d09994aabdaeb5492756633fa4285deb4970172a4` |

本次安装使用 `apk add --force-reinstall` 处理相同版本的本地重建。主机旧 APK 与设备文件备份位于 `/tmp/lanspeed-optimization/backup/`；设备另存 `/tmp/lanspeed-opt-20261011/device-files.tar.gz`。测试日志、脱敏摘要与私有浏览器证据位于主机 `/tmp/lanspeed-optimization/`。这些临时目录可能在重启或清理时消失，应在需要长期保留时另行归档。
