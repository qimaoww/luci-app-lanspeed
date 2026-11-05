# LAN Speed 数据页融合度优化（2026-10-28）

## 范围

- 基线：PR #32 最新分支（`380ae9e`），并合并此前已部署的 7 个优化提交（当前基线 `01713d7`）。
- 页面：实时状态页（`/admin/status/lanspeed/overview`）的状态区、指标区、客户端列表、接口吞吐与分页。
- 目标：降低页面与 LuCI 主题的割裂感，压缩首屏高度，让客户端列表成为主界面；不改变 RPC、厂商查询、筛选、排序、分页、限速/禁用等既有功能。

## 主要调整

### 状态区

- 刷新间隔从客户端工具栏移到状态区，与暂停/立即刷新组成一组；工具栏只保留搜索、仅活跃、排序、单位。
- 状态标题、BPF 标记、采集状态与版本信息统一为安静的单行层级。
- 指标区改为四等分紧凑布局：统一标签/数值/单位/基线，数值 19–20px，辅助说明 10–11px，技术性活跃窗口说明收进客户端指标的 title 提示。
- 收敛方向箭头、彩色强调条和重复分隔线；沿用主题自身背景、字体、圆角、边框与阴影 token。

### 客户端列表

- 名称 14px/600 为主信息；IP、MAC、厂商为次级信息；表头、单元格和行高按桌面密度收紧。
- 统一左右边界：指标首项、表头首列、数据首列与卡片标题/工具栏左缘对齐；末列与卡片右缘对齐；客户端列表按 34/26/14/14/6/6 分配列宽，避免名称列吞掉所有余量。
- 响应式按客户端卡片自身宽度切换：50rem 以下才进入卡片模式，1280/1366 等常见桌面宽度保持表格；中宽卡片把网速、累计流量、TCP、UDP 排成一行。
- 连接数指标改为“总数主值 + TCP/UDP 副值”，与下载、上传、客户端三项共用同一数值基线。
- 方向箭头改为按设计令牌着色的 SVG mask 矢量图标（非字体 emoji），统一 10px 尺寸并贴合数值；客户端行改为 4px 纵向内边距的紧凑密度。
- 速率、累计流量、TCP/UDP 采用一致的对齐、方向符号和等宽数字。
- 客户端列表移除“控制”列，限速与禁用上网操作收进设备详情页的“设备控制”条；详情页通过 `client_connections` 返回的 `client.control` 渲染按钮与状态，列表只保留设备身份/流量信息。
- 搜索、仅活跃、排序、单位保持统一 32px 控件高度；手机端隐藏重复的“排序/单位”可见标签（select 仍带 aria-label），让排序值完整显示。
- 移动端卡片模式按“名称 / IP / MAC+厂商 / 速率+累计 / TCP+UDP”分组，减少重复标签和过长卡片；接口吞吐保持可折叠证据。

### 主题与响应式

- Aurora、Argon、Bootstrap、Shadcn 各自使用自己的间距、字体、强调色、圆角和边框规则；共享结构只保留语义 token，不写死主题色。
- 修复状态页与配置/诊断页的表头 gap/padding/字号一致性（三页样式一致性审计已覆盖）。
- 桌面 1920、平板 768、手机 390 三档验证；无横向溢出。

## 验证

### 回归

- `tests/run.sh unit`：PASS（Rust workspace、lanspeedd、前端 contract、identity、collector、probes、packaging、diagnostics、status、client-control、ubus-lifecycle、release-version、geo、mac-vendor、modules、build-sdk）。
- OpenWrt SDK 两项 SKIP：运行环境未设置 `IMMORTALWRT_ROOT`，由构建机补跑。
- 浏览器审计（Playwright，6 场景/主题）：
  - Aurora light：279/279 PASS
  - Argon light：270/270 PASS
  - Argon dark：270/270 PASS
  - Bootstrap light：269/269 PASS
  - Bootstrap dark：269/269 PASS
  - Shadcn light：267/267 PASS（临时挂载主题资源验证后已移除并恢复 Aurora）
- Shadcn dark：仅做截图验证（主题未预装，未跑自动审计）。

### 截图

历史截图及预览附件已按用户要求移除，不再随 PR 发布。后续截图仅保存在本地输出目录。

## 未覆盖/说明

- 未推送 GitHub、未改版本号；需用户在实际路由器验证后再决定提交与发版。
- Shadcn 主题未安装于路由器；本次为临时挂载验证，验证后已删除临时资源、恢复 `luci.main.mediaurlbase=/luci-static/aurora` 与 `argon.@global[0].mode=light`。
- 平板仅覆盖亮色；手机/桌面覆盖四主题亮色，其中 Aurora/Argon/Bootstrap 还覆盖暗色自动审计。
