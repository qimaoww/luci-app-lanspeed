# LAN Speed 真实浏览器验收

本目录提供可重复执行的 Playwright CLI 验收工具，面向已经部署到路由器的
LAN Speed 实时状态、运行诊断和配置页面。工具只读取并断言当前主题、亮暗模式和
计算样式，不会切换主题、修改 UCI 配置或提交表单。

## 覆盖范围

每次运行固定检查 6 个场景：

- 实时状态、运行诊断、配置页；
- 桌面 `1920x1080` 和移动 `390x844`；
- 当前主题 class、主题属性、颜色模式和设计系统 token；
- 页面内容、横向溢出、元素越界、重叠、文字裁切和可见控件；
- 文本对比度、按钮悬停、键盘焦点和页面特有交互；
- 控制台错误、页面异常、失败响应和失败请求；
- Argon 的 `--primary` / `--dark-primary` 动态强调色。

每个场景都会生成完整页面截图和 JSON 证据。单个场景失败不会中断矩阵，其余场景
仍会继续执行，最终由 `summary.json` 和进程退出码汇总结果。

## 前置条件

1. 路由器已经部署待验收版本，并能从执行机访问。
2. 已安装 Node.js 和 Codex Playwright CLI wrapper。
3. 提供已登录的 Playwright storage state，或复用一个已登录的 CLI session。

默认 wrapper 路径为：

```sh
${CODEX_HOME:-$HOME/.codex}/skills/playwright/scripts/playwright_cli.sh
```

如需手工建立登录状态，可先在可见浏览器中登录，再保存状态。不要把密码写入脚本或
提交到仓库：

```sh
PWCLI="${CODEX_HOME:-$HOME/.codex}/skills/playwright/scripts/playwright_cli.sh"
"$PWCLI" -s=lanspeed-auth open http://192.0.2.1 --headed \
  --config="$PWD/tests/browser/playwright-cli.json"
# 在浏览器中完成登录
"$PWCLI" -s=lanspeed-auth state-save /absolute/private/lanspeed-auth.json
"$PWCLI" -s=lanspeed-auth close
```

## 运行

Aurora 示例：

```sh
LANSPEED_BASE_URL=http://192.0.2.1 \
LANSPEED_AUTH_STATE=/absolute/private/lanspeed-auth.json \
tests/browser/run-lanspeed-browser-audit.sh \
  --theme aurora \
  --mode light
```

Argon 自定义主题色示例：

```sh
LANSPEED_BASE_URL=http://192.0.2.1 \
LANSPEED_AUTH_STATE=/absolute/private/lanspeed-auth.json \
tests/browser/run-lanspeed-browser-audit.sh \
  --theme argon \
  --mode dark \
  --argon-primary '#5e72e4' \
  --argon-dark-primary '#8b9cff'
```

`--expected-accent` 可用于任意主题，并优先于 Argon 的模式专用参数：

```sh
tests/browser/run-lanspeed-browser-audit.sh \
  --base-url http://192.0.2.1 \
  --auth-state /absolute/private/lanspeed-auth.json \
  --theme bootstrap \
  --mode dark \
  --expected-accent 'rgb(51, 122, 183)'
```

`--theme` 和 `--mode` 都是预期值，不是切换指令。如果路由器当前页面与预期不符，
验收会在 `theme-class`、`theme-attribute` 或 `color-mode` 检查中失败。

复用已认证 session 时，工具不会加载 storage state，也不会在结束时关闭该 session：

```sh
LANSPEED_BASE_URL=http://192.0.2.1 \
LANSPEED_REUSE_SESSION=1 \
PLAYWRIGHT_CLI_SESSION=lanspeed-auth \
tests/browser/run-lanspeed-browser-audit.sh \
  --theme aurora \
  --mode dark
```

诊断环境本身允许处于严重状态、但仍需验收错误界面时，可增加
`--allow-bad-state` 或设置 `LANSPEED_ALLOW_BAD_STATE=1`。这只放宽当前状态断言，
不会忽略页面异常、网络失败、布局或可访问性失败。

## 参数与环境变量

| 名称 | 用途 |
| --- | --- |
| `LANSPEED_BASE_URL` | 必填的路由器 origin，也可用 `--base-url` |
| `LANSPEED_AUTH_STATE` | 可选 storage state JSON，也可用 `--auth-state` |
| `PLAYWRIGHT_CLI` | 自定义 Playwright CLI wrapper 路径 |
| `PLAYWRIGHT_CLI_CONFIG` | 自定义 CLI 配置，默认使用本目录配置 |
| `PLAYWRIGHT_CLI_SESSION` | 自定义 session 名称，也可用 `--session` |
| `LANSPEED_REUSE_SESSION` | 设为 `1` 时复用并保留现有 session |
| `LANSPEED_OUTPUT_DIR` | 输出根目录，也可用 `--output-dir` |
| `LANSPEED_RUN_ID` | 固定本次运行目录名，默认使用 UTC 时间和 PID |
| `LANSPEED_EXPECTED_ACCENT` | 任意主题的预期强调色 |
| `LANSPEED_ARGON_PRIMARY` | Argon 亮色模式预期 `primary` |
| `LANSPEED_ARGON_DARK_PRIMARY` | Argon 暗色模式预期 `dark-primary` |
| `LANSPEED_AUDIT_TIMEOUT_MS` | 页面和交互超时，默认 `30000` |
| `LANSPEED_AUDIT_SETTLE_MS` | 页面稳定等待，默认 `600` |

## 输出与判定

默认输出结构：

```text
output/playwright/lanspeed-audit/<run-id>/<theme>/<mode>/
  overview-desktop.png
  overview-desktop-evidence.json
  overview-mobile.png
  overview-mobile-evidence.json
  diagnostics-desktop.png
  diagnostics-desktop-evidence.json
  diagnostics-mobile.png
  diagnostics-mobile-evidence.json
  config-desktop.png
  config-desktop-evidence.json
  config-mobile.png
  config-mobile-evidence.json
  summary.json
  cli.log
```

只有以下条件同时满足时退出码为 `0`：证据矩阵恰好包含 6 个场景、所有 JSON 可解析、
所有场景 `ok: true`、所有证据属于同一预期主题和模式。否则退出码为 `1`；启动参数、
依赖或 session 配置错误使用退出码 `2`。

可单独重新汇总已有证据：

```sh
node tests/browser/summarize-lanspeed-browser-audit.js \
  /absolute/output/run/theme/mode \
  /absolute/output/run/theme/mode/summary.json
```

## 本地静态检查

本地不连接路由器时只执行语法检查：

```sh
node --check tests/browser/lanspeed-browser-audit.js
node --check tests/browser/summarize-lanspeed-browser-audit.js
sh -n tests/browser/run-lanspeed-browser-audit.sh
```
