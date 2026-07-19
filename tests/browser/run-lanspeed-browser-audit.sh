#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)

BASE_URL=${LANSPEED_BASE_URL:-}
AUTH_STATE=${LANSPEED_AUTH_STATE:-}
PLAYWRIGHT_CLI=${PLAYWRIGHT_CLI:-"${CODEX_HOME:-$HOME/.codex}/skills/playwright/scripts/playwright_cli.sh"}
PLAYWRIGHT_CONFIG=${PLAYWRIGHT_CLI_CONFIG:-"$SCRIPT_DIR/playwright-cli.json"}
SESSION=${PLAYWRIGHT_CLI_SESSION:-}
REUSE_SESSION=${LANSPEED_REUSE_SESSION:-0}
OUTPUT_ROOT=${LANSPEED_OUTPUT_DIR:-"$ROOT/output/playwright/lanspeed-audit"}
RUN_ID=${LANSPEED_RUN_ID:-"$(date -u '+%Y%m%dT%H%M%SZ')-$$"}
THEME=${LANSPEED_THEME:-}
MODE=${LANSPEED_MODE:-}
EXPECTED_ACCENT=${LANSPEED_EXPECTED_ACCENT:-}
ARGON_PRIMARY=${LANSPEED_ARGON_PRIMARY:-}
ARGON_DARK_PRIMARY=${LANSPEED_ARGON_DARK_PRIMARY:-}
ALLOW_BAD_STATE=${LANSPEED_ALLOW_BAD_STATE:-0}
TIMEOUT_MS=${LANSPEED_AUDIT_TIMEOUT_MS:-30000}
SETTLE_MS=${LANSPEED_AUDIT_SETTLE_MS:-600}

usage() {
	cat <<EOF
Usage: $0 --theme {aurora|argon|bootstrap} --mode {light|dark} [options]

Required environment:
  LANSPEED_BASE_URL            Router origin, for example http://192.0.2.1.

Authentication and Playwright:
  LANSPEED_AUTH_STATE          Optional absolute Playwright storage-state JSON path.
  PLAYWRIGHT_CLI               Optional playwright_cli.sh path.
  PLAYWRIGHT_CLI_CONFIG        Optional Playwright CLI config path.
  PLAYWRIGHT_CLI_SESSION       Optional session name.
  LANSPEED_REUSE_SESSION=1     Reuse an existing authenticated session; do not close it.

Audit options:
  --theme NAME                 Expected current theme; does not switch the router theme.
  --mode MODE                  Expected light or dark mode.
  --expected-accent COLOR      Expected resolved theme accent CSS color.
  --argon-primary COLOR        Expected Argon light-mode primary color.
  --argon-dark-primary COLOR   Expected Argon dark-mode primary color.
  --allow-bad-state            Permit current hard-failure status while auditing UI behavior.
  --base-url URL               Override LANSPEED_BASE_URL.
  --auth-state PATH            Override LANSPEED_AUTH_STATE.
  --output-dir PATH            Override LANSPEED_OUTPUT_DIR.
  --session NAME               Override PLAYWRIGHT_CLI_SESSION.
  --reuse-session              Same as LANSPEED_REUSE_SESSION=1.
  -h, --help                   Show this help.

Output:
  output/playwright/lanspeed-audit/<run-id>/<theme>/<mode>/
EOF
}

die() {
	printf '%s\n' "lanspeed browser audit: $*" >&2
	exit 2
}

need_value() {
	[ "$#" -ge 2 ] || die "missing value for $1"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--theme)
			need_value "$@"
			THEME=$2
			shift 2
			;;
		--mode)
			need_value "$@"
			MODE=$2
			shift 2
			;;
		--expected-accent)
			need_value "$@"
			EXPECTED_ACCENT=$2
			shift 2
			;;
		--argon-primary)
			need_value "$@"
			ARGON_PRIMARY=$2
			shift 2
			;;
		--argon-dark-primary)
			need_value "$@"
			ARGON_DARK_PRIMARY=$2
			shift 2
			;;
		--base-url)
			need_value "$@"
			BASE_URL=$2
			shift 2
			;;
		--auth-state)
			need_value "$@"
			AUTH_STATE=$2
			shift 2
			;;
		--output-dir)
			need_value "$@"
			OUTPUT_ROOT=$2
			shift 2
			;;
		--session)
			need_value "$@"
			SESSION=$2
			shift 2
			;;
		--allow-bad-state)
			ALLOW_BAD_STATE=1
			shift
			;;
		--reuse-session)
			REUSE_SESSION=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			die "unknown option: $1"
			;;
	esac
done

case "$THEME" in
	aurora|argon|bootstrap) ;;
	*) die "--theme must be aurora, argon, or bootstrap" ;;
esac

case "$MODE" in
	light|dark) ;;
	*) die "--mode must be light or dark" ;;
esac

case "$ALLOW_BAD_STATE" in
	0|1) ;;
	*) die "LANSPEED_ALLOW_BAD_STATE must be 0 or 1" ;;
esac

case "$REUSE_SESSION" in
	0|1) ;;
	*) die "LANSPEED_REUSE_SESSION must be 0 or 1" ;;
esac

case "$TIMEOUT_MS:$SETTLE_MS" in
	*[!0-9:]*|:*|*:) die "audit timeout and settle values must be non-negative integers" ;;
esac

[ -n "$BASE_URL" ] || die "LANSPEED_BASE_URL or --base-url is required"
[ -x "$PLAYWRIGHT_CLI" ] || die "Playwright CLI wrapper is not executable: $PLAYWRIGHT_CLI"
[ -f "$PLAYWRIGHT_CONFIG" ] || die "Playwright CLI config not found: $PLAYWRIGHT_CONFIG"
[ -f "$SCRIPT_DIR/lanspeed-browser-audit.js" ] || die "audit function not found"
[ -f "$SCRIPT_DIR/summarize-lanspeed-browser-audit.js" ] || die "audit summarizer not found"

if [ -n "$AUTH_STATE" ] && [ ! -f "$AUTH_STATE" ]; then
	die "authentication state not found: $AUTH_STATE"
fi

if [ "$THEME" = "argon" ] && [ -z "$EXPECTED_ACCENT" ]; then
	if [ "$MODE" = "dark" ] && [ -n "$ARGON_DARK_PRIMARY" ]; then
		EXPECTED_ACCENT=$ARGON_DARK_PRIMARY
	elif [ "$MODE" = "light" ] && [ -n "$ARGON_PRIMARY" ]; then
		EXPECTED_ACCENT=$ARGON_PRIMARY
	fi
fi

BASE_URL=${BASE_URL%/}
case "$OUTPUT_ROOT" in
	/*) ;;
	*) OUTPUT_ROOT="$PWD/$OUTPUT_ROOT" ;;
esac

case "$PLAYWRIGHT_CONFIG" in
	/*) ;;
	*) PLAYWRIGHT_CONFIG="$PWD/$PLAYWRIGHT_CONFIG" ;;
esac

if [ -n "$AUTH_STATE" ]; then
	case "$AUTH_STATE" in
		/*) ;;
		*) AUTH_STATE="$PWD/$AUTH_STATE" ;;
	esac
fi

if [ -z "$SESSION" ]; then
	SESSION="lanspeed-audit-$RUN_ID"
fi
case "$SESSION" in
	*[!A-Za-z0-9._-]*) die "session name may contain only letters, digits, dot, underscore, and dash" ;;
esac

RUN_DIR="$OUTPUT_ROOT/$RUN_ID/$THEME/$MODE"
CLI_LOG="$RUN_DIR/cli.log"
SUMMARY_PATH="$RUN_DIR/summary.json"
mkdir -p "$RUN_DIR"
: > "$CLI_LOG"

cli() {
	(
		CDPATH= cd -- "$RUN_DIR"
		"$PLAYWRIGHT_CLI" -s="$SESSION" "$@"
	)
}

SESSION_OWNED=0
cleanup() {
	if [ "$SESSION_OWNED" = "1" ]; then
		cli close >> "$CLI_LOG" 2>&1 || true
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

if [ "$REUSE_SESSION" = "1" ]; then
	if ! cli tab-list >> "$CLI_LOG" 2>&1; then
		die "unable to reuse Playwright session: $SESSION"
	fi
else
	if ! cli open about:blank --config="$PLAYWRIGHT_CONFIG" >> "$CLI_LOG" 2>&1; then
		die "unable to open Playwright session; see $CLI_LOG"
	fi
	SESSION_OWNED=1
	if [ -n "$AUTH_STATE" ]; then
		if ! cli state-load "$AUTH_STATE" >> "$CLI_LOG" 2>&1; then
			die "unable to load authentication state; see $CLI_LOG"
		fi
	fi
fi

write_failure_evidence() {
	evidence_path=$1
	page_name=$2
	viewport_name=$3
	viewport_width=$4
	viewport_height=$5
	page_path=$6
	screenshot_path=$7
	reason=$8

	node -e '
		const fs = require("fs");
		const [output, pageName, viewportName, width, height, pagePath, screenshot,
			theme, mode, accent, reason] = process.argv.slice(1);
		const failure = { name: "audit-runner", ok: false, details: reason };
		const evidence = {
			schemaVersion: 1,
			ok: false,
			startedAt: new Date().toISOString(),
			finishedAt: new Date().toISOString(),
			page: pageName,
			expected: {
				theme,
				mode,
				accent: accent || null,
				viewport: { name: viewportName, width: Number(width), height: Number(height) },
				urlPath: pagePath
			},
			checks: [failure],
			failures: [failure],
			observations: {},
			interactions: {},
			browserSignals: { console: [], pageErrors: [], responses: [], requests: [] },
			screenshot,
			screenshotSaved: false
		};
		fs.writeFileSync(output, JSON.stringify(evidence, null, 2) + "\n");
	' "$evidence_path" "$page_name" "$viewport_name" "$viewport_width" \
		"$viewport_height" "$page_path" "$screenshot_path" "$THEME" "$MODE" \
		"$EXPECTED_ACCENT" "$reason"
}

make_audit_config() {
	page_name=$1
	page_path=$2
	root_selector=$3
	busy_selector=$4
	minimum_controls=$5
	viewport_name=$6
	viewport_width=$7
	viewport_height=$8
	screenshot_path=$9
	shift 9

	node -e '
		const [pageName, expectedTheme, expectedMode, expectedAccent, viewportName,
			width, height, expectedUrlPath, rootSelector, busySelector, minimumControls,
			timeoutMs, settleMs, allowBadState, screenshotPath, ...expectedTexts] = process.argv.slice(1);
		const consistencyKey = [
			"lanspeed.browser.consistency.v1", expectedTheme, expectedMode, viewportName
		].join(".");
		process.stdout.write(JSON.stringify({
			pageName,
			expectedTheme,
			expectedMode,
			expectedAccent: expectedAccent || null,
			viewport: { name: viewportName, width: Number(width), height: Number(height) },
			expectedUrlPath,
			rootSelector,
			busySelector: busySelector || null,
			minimumControls: Number(minimumControls),
			timeoutMs: Number(timeoutMs),
			settleMs: Number(settleMs),
			allowBadState: allowBadState === "1",
			screenshotPath,
			consistencyKey,
			consistencyReset: pageName === "overview",
			consistencyFinal: pageName === "config",
			expectedTexts
		}));
	' "$page_name" "$THEME" "$MODE" "$EXPECTED_ACCENT" "$viewport_name" \
		"$viewport_width" "$viewport_height" "$page_path" "$root_selector" \
		"$busy_selector" "$minimum_controls" "$TIMEOUT_MS" "$SETTLE_MS" \
		"$ALLOW_BAD_STATE" "$screenshot_path" "$@"
}

run_case() {
	page_name=$1
	page_path=$2
	root_selector=$3
	busy_selector=$4
	minimum_controls=$5
	viewport_name=$6
	viewport_width=$7
	viewport_height=$8
	shift 8

	case_name="$page_name-$viewport_name"
	evidence_path="$RUN_DIR/$case_name-evidence.json"
	screenshot_path="$RUN_DIR/$case_name.png"
	raw_path="$RUN_DIR/$case_name-raw.txt"
	page_url="$BASE_URL$page_path"
	reason=

	printf '%s\n' "[$case_name] $page_url" | tee -a "$CLI_LOG"
	if ! cli goto "$page_url" >> "$CLI_LOG" 2>&1; then
		reason="Playwright navigation failed"
	elif ! cli resize "$viewport_width" "$viewport_height" >> "$CLI_LOG" 2>&1; then
		reason="Playwright viewport resize failed"
	else
		audit_config=$(make_audit_config "$page_name" "$page_path" "$root_selector" \
			"$busy_selector" "$minimum_controls" "$viewport_name" "$viewport_width" \
			"$viewport_height" "$screenshot_path" "$@")
		if ! cli localstorage-set lanspeed.browser.audit.v1 "$audit_config" >> "$CLI_LOG" 2>&1; then
			reason="Unable to install browser audit configuration"
		elif ! cli --raw run-code --filename="$SCRIPT_DIR/lanspeed-browser-audit.js" \
			> "$raw_path" 2>> "$CLI_LOG"; then
			reason="Browser audit function failed to execute"
		elif ! node -e '
			const fs = require("fs");
			const [source, output] = process.argv.slice(1);
			const value = JSON.parse(fs.readFileSync(source, "utf8"));
			fs.writeFileSync(output, JSON.stringify(value, null, 2) + "\n");
		' "$raw_path" "$evidence_path" >> "$CLI_LOG" 2>&1; then
			reason="Browser audit returned invalid JSON"
		fi
	fi

	if [ -n "$reason" ]; then
		write_failure_evidence "$evidence_path" "$page_name" "$viewport_name" \
			"$viewport_width" "$viewport_height" "$page_path" "$screenshot_path" "$reason"
		printf '%s\n' "[$case_name] ERROR: $reason" | tee -a "$CLI_LOG" >&2
	else
		rm -f "$raw_path"
		printf '%s\n' "[$case_name] evidence: $evidence_path" | tee -a "$CLI_LOG"
	fi
}

for viewport_name in desktop mobile; do
	case "$viewport_name" in
		desktop)
			viewport_width=1920
			viewport_height=1080
			;;
		mobile)
			viewport_width=390
			viewport_height=844
			;;
	esac

	run_case overview \
		/cgi-bin/luci/admin/status/lanspeed/overview \
		.lanspeed-status-root .lanspeed-status-root 3 \
		"$viewport_name" "$viewport_width" "$viewport_height" \
		"LAN Speed" "LAN 客户端" "立即刷新"

	run_case diagnostics \
		/cgi-bin/luci/admin/status/lanspeed/diagnostics \
		.lanspeed-diagnostics-root .lanspeed-diagnostics-root 2 \
		"$viewport_name" "$viewport_width" "$viewport_height" \
		"运行诊断" "重新检查" "复制脱敏报告"

	run_case config \
		/cgi-bin/luci/admin/status/lanspeed/config \
		.lanspeed-config-root '' 1 \
		"$viewport_name" "$viewport_width" "$viewport_height" \
		"LAN Speed 配置"
done

set +e
node "$SCRIPT_DIR/summarize-lanspeed-browser-audit.js" "$RUN_DIR" "$SUMMARY_PATH"
summary_status=$?
set -e

printf '%s\n' "Artifacts: $RUN_DIR"
printf '%s\n' "Summary: $SUMMARY_PATH"
exit "$summary_status"
