#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const daemonMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const luciMakefile = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/Makefile'), 'utf8');
const daemonSource = fs.readFileSync(path.join(root, 'net/lanspeedd/src/lanspeedd.c'), 'utf8');
const versionJs = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/version.js'), 'utf8');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/build-sdk.yml'), 'utf8');
const releaseScript = fs.readFileSync(path.join(root, 'scripts/release-version.sh'), 'utf8');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function readMakeVar(source, name, fileLabel) {
  const match = source.match(new RegExp(`^${name}:=(.+)$`, 'm'));
  assert(match, `${fileLabel} must define ${name}`);
  return match[1].trim();
}

function assertBefore(source, left, right, message) {
  const leftIndex = source.indexOf(left);
  const rightIndex = source.indexOf(right);
  assert(leftIndex !== -1, `${message}: missing left marker`);
  assert(rightIndex !== -1, `${message}: missing right marker`);
  assert(leftIndex < rightIndex, message);
}

try {
  const daemonVersion = readMakeVar(daemonMakefile, 'PKG_VERSION', 'net/lanspeedd/Makefile');
  const daemonRelease = readMakeVar(daemonMakefile, 'PKG_RELEASE', 'net/lanspeedd/Makefile');
  const luciVersion = readMakeVar(luciMakefile, 'PKG_VERSION', 'applications/luci-app-lanspeed/Makefile');
  const luciRelease = readMakeVar(luciMakefile, 'PKG_RELEASE', 'applications/luci-app-lanspeed/Makefile');
  const fullVersion = `${daemonVersion}-r${daemonRelease}`;

  assert(daemonVersion === luciVersion, 'daemon and LuCI PKG_VERSION must match for releases');
  assert(daemonRelease === luciRelease, 'daemon and LuCI PKG_RELEASE must match for releases');
  assert(versionJs.includes(`FULL_VERSION: '${fullVersion}'`), 'version.js FULL_VERSION must match package version and release');
  assert(/-DLANSPEED_VERSION=.*\$\(PKG_VERSION\)/.test(daemonMakefile), 'daemon package must pass PKG_VERSION into lanspeedd status.version');
  assert(daemonSource.includes('#ifndef LANSPEED_VERSION\n#define LANSPEED_VERSION "0.0.0"\n#endif'), 'lanspeedd.c must use package-provided LANSPEED_VERSION with a neutral fallback');
  assert(daemonSource.includes('#define LANSPEED_FULL_VERSION LANSPEED_VERSION "-r" LANSPEED_RELEASE'), 'lanspeedd.c must compose status.version from package version and release');
  assert(!luciMakefile.includes('./htdocs/luci-static/resources/lanspeed/*.js'), 'LuCI package must not install stale static version.js via wildcard');
  assert(luciMakefile.includes("PACKAGE_VERSION: '$(PKG_VERSION)'"), 'LuCI package must generate version.js from PKG_VERSION during install');
  assert(luciMakefile.includes("PACKAGE_RELEASE: '$(PKG_RELEASE)'"), 'LuCI package must generate version.js from PKG_RELEASE during install');
  assert(luciMakefile.includes("FULL_VERSION: '$(PKG_VERSION)-r$(PKG_RELEASE)'"), 'LuCI package must generate full version.js from package metadata');
  [
    'configForm.js',
    'configStyle.js',
    'format.js',
    'ifaceConfig.js',
    'nssPanel.js',
    'rpc.js',
    'statusCollector.js',
    'statusIp.js',
    'statusRefresh.js',
    'statusShell.js',
    'statusStyle.js',
    'theme.js',
    'vocab.js'
  ].forEach((name) => {
    assert(luciMakefile.includes(`./htdocs/luci-static/resources/lanspeed/${name}`),
           `LuCI package must install resources/lanspeed/${name}`);
  });
  assert(releaseScript.includes('printf \'%s\\n\' "${daemon_version}-r${daemon_release}"'), 'scripts/release-version.sh must print the full code version');
  assert(releaseScript.includes('[ "$daemon_version" = "$luci_version" ]'), 'scripts/release-version.sh must verify daemon and LuCI PKG_VERSION match');
  assert(releaseScript.includes('[ "$daemon_release" = "$luci_release" ]'), 'scripts/release-version.sh must verify daemon and LuCI PKG_RELEASE match');
  assert(workflow.includes('code_version="$(sh ./scripts/release-version.sh)"'), 'workflow must read the code version through sh scripts/release-version.sh');
  assert(workflow.includes('ipk_version="${code_version%-r*}-${code_version##*-r}"'), 'workflow must convert the release version to the native IPK package version');
  assert(workflow.includes('expected_tag="v${code_version}"'), 'workflow must require a v-prefixed tag that matches the code version');
  assert(workflow.includes('"${GITHUB_REF_NAME}" != "$expected_tag"'), 'workflow must fail when the release tag does not match the code version');
  assert(workflow.includes('name: ${{ steps.meta.outputs.code_version }}'), 'GitHub Release name must match the code version');
  assert(!/^      [A-Z_]+:\s*\$\{\{\s*env\./m.test(workflow), 'workflow job env must not reference the env context');
  assert(workflow.includes('$APK_SDK_URL'), 'workflow APK SDK download must read the SDK URL as a runner environment variable');
  assert(workflow.includes('$IPK_SDK_URL'), 'workflow IPK SDK download must read the SDK URL as a runner environment variable');
  assert(workflow.includes('$APK_AARCH64_SDK_URL'), 'workflow APK aarch64 SDK download must read the SDK URL as a runner environment variable');
  assert(workflow.includes('$IPK_AARCH64_SDK_URL'), 'workflow IPK aarch64 SDK download must read the SDK URL as a runner environment variable');
  assert(/on:\n  push:\n    tags:\n      - 'v\*'/.test(workflow), 'workflow must only run from v* release tags');
  assert(!/branches:/.test(workflow), 'workflow must not run from branch pushes');
  assert(!/pull_request:/.test(workflow), 'workflow must not run from pull requests');
  assert(!/workflow_dispatch:/.test(workflow), 'workflow must not expose a manual build trigger');
  assert(!/inputs\./.test(workflow), 'workflow must not depend on manual workflow inputs');
  assert(!/actions\/upload-artifact/.test(workflow), 'workflow must not upload Actions artifacts');
  assert(!/actions\/download-artifact/.test(workflow), 'workflow must not download Actions artifacts');
  assert(workflow.includes('uses: softprops/action-gh-release@v2.6.2'), 'workflow must publish package files through GitHub Releases');
  assert(workflow.includes('APK_SDK_URL:'), 'workflow must define a dedicated APK SDK URL');
  assert(workflow.includes('IPK_SDK_URL:'), 'workflow must define a dedicated IPK SDK URL');
  assert(workflow.includes('APK_AARCH64_SDK_URL:'), 'workflow must define a dedicated APK aarch64 SDK URL');
  assert(workflow.includes('IPK_AARCH64_SDK_URL:'), 'workflow must define a dedicated IPK aarch64 SDK URL');
  assert(workflow.includes('https://downloads.immortalwrt.org/releases/25.12.0-rc2/targets/armsr/armv8/immortalwrt-sdk-25.12.0-rc2-armsr-armv8_gcc-14.3.0_musl.Linux-x86_64.tar.zst'), 'workflow must use the official APK aarch64 SDK URL');
  assert(workflow.includes('8fd6e4177ad99b567035cbc2825dd060773556249831fad5560cb1ef9eb1e290'), 'workflow must pin the official APK aarch64 SDK checksum');
  assert(workflow.includes('https://downloads.immortalwrt.org/releases/23.05.6/targets/armsr/armv8/immortalwrt-sdk-23.05.6-armsr-armv8_gcc-12.3.0_musl.Linux-x86_64.tar.xz'), 'workflow must use the official IPK aarch64 SDK URL');
  assert(workflow.includes('a56748c4d70b956102d4a728418d9b7bcf1208b526816221b4389597a24238fa'), 'workflow must pin the official IPK aarch64 SDK checksum');
  assert(workflow.includes('IPK_BASE_FEED_REF:'), 'workflow must pin the IPK SDK base feed to the release source commit');
  assert(workflow.includes('SDK_BASE_FEED_REF="$base_feed_ref"'), 'workflow must pass the pinned base feed commit into the SDK helper');
  assert(workflow.includes('Download public SDKs'), 'workflow must download separate APK and IPK SDKs');
  assert(workflow.includes('sdk-apk-base'), 'workflow must keep a separate APK SDK for base builds');
  assert(workflow.includes('sdk-apk-bpf'), 'workflow must keep a separate APK SDK for BPF builds');
  assert(workflow.includes('sdk-ipk-base'), 'workflow must keep a separate IPK SDK for base builds');
  assert(workflow.includes('sdk-ipk-bpf'), 'workflow must keep a separate IPK SDK for BPF builds');
  assert(workflow.includes('sdk-apk-aarch64-base'), 'workflow must keep a separate APK aarch64 SDK for base builds');
  assert(workflow.includes('sdk-apk-aarch64-bpf'), 'workflow must keep a separate APK aarch64 SDK for BPF builds');
  assert(workflow.includes('sdk-ipk-aarch64-base'), 'workflow must keep a separate IPK aarch64 SDK for base builds');
  assert(workflow.includes('sdk-ipk-aarch64-bpf'), 'workflow must keep a separate IPK aarch64 SDK for BPF builds');
  assert(workflow.includes('run_build apk-base'), 'workflow must build APK base packages');
  assert(workflow.includes('run_build apk-bpf'), 'workflow must build APK BPF packages');
  assert(workflow.includes('run_build ipk-base'), 'workflow must build IPK base packages');
  assert(workflow.includes('run_build ipk-bpf'), 'workflow must build IPK BPF packages');
  assert(workflow.includes('run_build apk-aarch64-base'), 'workflow must build APK aarch64 base packages');
  assert(workflow.includes('run_build apk-aarch64-bpf'), 'workflow must build APK aarch64 BPF packages');
  assert(workflow.includes('run_build ipk-aarch64-base'), 'workflow must build IPK aarch64 base packages');
  assert(workflow.includes('run_build ipk-aarch64-bpf'), 'workflow must build IPK aarch64 BPF packages');
  assert(workflow.includes('run_build apk-base "$RUNNER_TEMP/sdk-apk-base" 0 25.12'), 'APK base builds must use the 25.12 SDK release guard');
  assert(workflow.includes('run_build apk-bpf "$RUNNER_TEMP/sdk-apk-bpf" 1 25.12'), 'APK BPF builds must use the 25.12 SDK release guard');
  assert(workflow.includes('run_build ipk-base "$RUNNER_TEMP/sdk-ipk-base" 0 23.05 "$IPK_BASE_FEED_REF"'), 'IPK base builds must use the 23.05 SDK release guard and pinned base feed');
  assert(workflow.includes('run_build ipk-bpf "$RUNNER_TEMP/sdk-ipk-bpf" 1 23.05 "$IPK_BASE_FEED_REF"'), 'IPK BPF builds must use the 23.05 SDK release guard and pinned base feed');
  assert(workflow.includes('run_build apk-aarch64-base "$RUNNER_TEMP/sdk-apk-aarch64-base" 0 25.12'), 'APK aarch64 base builds must use the 25.12 SDK release guard');
  assert(workflow.includes('run_build apk-aarch64-bpf "$RUNNER_TEMP/sdk-apk-aarch64-bpf" 1 25.12'), 'APK aarch64 BPF builds must use the 25.12 SDK release guard');
  assert(workflow.includes('run_build ipk-aarch64-base "$RUNNER_TEMP/sdk-ipk-aarch64-base" 0 23.05 "$IPK_BASE_FEED_REF"'), 'IPK aarch64 base builds must use the 23.05 SDK release guard and pinned base feed');
  assert(workflow.includes('run_build ipk-aarch64-bpf "$RUNNER_TEMP/sdk-ipk-aarch64-bpf" 1 23.05 "$IPK_BASE_FEED_REF"'), 'IPK aarch64 BPF builds must use the 23.05 SDK release guard and pinned base feed');
  assert(!/-name '\*\.apk'/.test(workflow), 'workflow must not collect every APK from the SDK output');
  assert(!/-name '\*\.ipk'/.test(workflow), 'workflow must not collect every IPK from the SDK output');
  assert(workflow.includes("lanspeedd-${code_version}.apk"), 'workflow must collect only the matching lanspeedd APK package');
  assert(workflow.includes("lanspeedd-bpf-${code_version}.apk"), 'workflow must collect only the matching lanspeedd-bpf APK package');
  assert(workflow.includes("luci-app-lanspeed-${code_version}.apk"), 'workflow must collect only the matching LuCI APK package');
  assert(workflow.includes("lanspeedd_${ipk_version}_*.ipk"), 'workflow must collect only the matching lanspeedd IPK package');
  assert(workflow.includes("lanspeedd-bpf_${ipk_version}_*.ipk"), 'workflow must collect only the matching lanspeedd-bpf IPK package');
  assert(workflow.includes("luci-app-lanspeed_${ipk_version}_*.ipk"), 'workflow must collect only the matching LuCI IPK package');
  assert(workflow.includes('"lanspeedd-${code_version}-aarch64.apk"'), 'workflow must add an aarch64 suffix to APK daemon release assets');
  assert(workflow.includes('"lanspeedd-bpf-${code_version}-aarch64.apk"'), 'workflow must add an aarch64 suffix to APK BPF release assets');
  assert(workflow.includes('"luci-app-lanspeed-${code_version}-aarch64.apk"'), 'workflow must add an aarch64 suffix to APK LuCI release assets');
  assert(workflow.includes('"lanspeedd_${ipk_version}_aarch64.ipk"'), 'workflow must add an aarch64 suffix to IPK daemon release assets');
  assert(workflow.includes('"lanspeedd-bpf_${ipk_version}_aarch64.ipk"'), 'workflow must add an aarch64 suffix to IPK BPF release assets');
  assert(workflow.includes('"luci-app-lanspeed_${ipk_version}_aarch64.ipk"'), 'workflow must add an aarch64 suffix to IPK LuCI release assets');
  assert(!workflow.includes('ramips'), 'workflow must not add non-aarch64 ramips SDK targets');
  assert(!workflow.includes('ath79'), 'workflow must not add non-aarch64 ath79 SDK targets');
  assert(!workflow.includes('ipq40xx'), 'workflow must not add non-aarch64 ipq40xx SDK targets');
  assert(!workflow.includes('qualcommax'), 'workflow must not split aarch64 into Qualcomm SDK targets');
  assert(!workflow.includes('mediatek'), 'workflow must not split aarch64 into MediaTek SDK targets');
  assert(!workflow.includes('rockchip'), 'workflow must not split aarch64 into Rockchip SDK targets');
  assertBefore(workflow, 'file_list="$RUNNER_TEMP/release/files.txt"', 'collect_one "$RUNNER_TEMP/sdk-apk-base" "lanspeedd-${code_version}.apk"', 'workflow must create the release file list before collecting files');
  assertBefore(workflow, 'collect_one "$RUNNER_TEMP/sdk-apk-base" "lanspeedd-${code_version}.apk"', 'collect_one "$RUNNER_TEMP/sdk-apk-bpf" "lanspeedd-bpf-${code_version}.apk"', 'APK base package must be listed before APK BPF package');
  assertBefore(workflow, 'collect_one "$RUNNER_TEMP/sdk-apk-bpf" "lanspeedd-bpf-${code_version}.apk"', 'collect_one "$RUNNER_TEMP/sdk-apk-base" "luci-app-lanspeed-${code_version}.apk"', 'APK BPF package must be listed before APK LuCI package');
  assertBefore(workflow, 'collect_one "$RUNNER_TEMP/sdk-ipk-base" "lanspeedd_${ipk_version}_*.ipk"', 'collect_one "$RUNNER_TEMP/sdk-ipk-bpf" "lanspeedd-bpf_${ipk_version}_*.ipk"', 'IPK base package must be listed before IPK BPF package');
  assertBefore(workflow, 'collect_one "$RUNNER_TEMP/sdk-ipk-bpf" "lanspeedd-bpf_${ipk_version}_*.ipk"', 'collect_one "$RUNNER_TEMP/sdk-ipk-base" "luci-app-lanspeed_${ipk_version}_*.ipk"', 'IPK BPF package must be listed before IPK LuCI package');
  assert(!workflow.includes('find "$release_dir" -type f | sort > "$file_list"'), 'workflow must not reorder release files by temporary paths');

  console.log('validate-release-version: PASS');
} catch (error) {
  console.error('validate-release-version: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
