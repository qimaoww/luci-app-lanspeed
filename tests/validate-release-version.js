#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const root = path.resolve(__dirname, '..');
const daemonMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const luciMakefile = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/Makefile'), 'utf8');
const versionJs = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/version.js'), 'utf8');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/build-sdk.yml'), 'utf8');
const releaseScriptPath = path.join(root, 'scripts/release-version.sh');
const releaseScript = fs.readFileSync(releaseScriptPath, 'utf8');
const rustRoot = path.join(root, 'net/lanspeedd/rust');
const cargoToml = fs.readFileSync(path.join(rustRoot, 'Cargo.toml'), 'utf8');
const buildCargoToml = fs.readFileSync(path.join(rustRoot, 'crates/lanspeed-build/Cargo.toml'), 'utf8');
const projectCrates = new Map([
  ['lanspeedd', path.join(rustRoot, 'crates/lanspeedd/Cargo.toml')],
  ['lanspeed-common', path.join(rustRoot, 'crates/lanspeed-common/Cargo.toml')],
  ['lanspeed-ebpf', path.join(rustRoot, 'crates/lanspeed-ebpf/Cargo.toml')],
  ['lanspeed-openwrt-sys', path.join(rustRoot, 'crates/lanspeed-openwrt-sys/Cargo.toml')],
  ['lanspeed-build', path.join(rustRoot, 'crates/lanspeed-build/Cargo.toml')]
]);

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

function validateWorkspacePackages(metadata, expectedVersion) {
  const packagesById = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const members = metadata.workspace_members.map((id) => packagesById.get(id));
  assert(members.every(Boolean), 'every cargo workspace member must resolve to a package');
  const memberNames = members.map((pkg) => pkg.name);
  assert(new Set(memberNames).size === memberNames.length, 'cargo workspace member names must be unique');
  assert(memberNames.length === projectCrates.size &&
    memberNames.every((name) => projectCrates.has(name)),
  'cargo workspace member names must exactly match project crates');
  members.forEach((pkg) => {
    assert(pkg.source === null, `${pkg.name} workspace member must be a local package`);
    assert(pkg.manifest_path === projectCrates.get(pkg.name), `${pkg.name} workspace member manifest_path must match the project crate`);
    assert(pkg.version === expectedVersion, `${pkg.name} cargo metadata version must match daemon PKG_VERSION`);
  });
}

function runWorkspaceMetadataSelfTest(expectedVersion) {
  const packages = [...projectCrates].map(([name, manifestPath], index) => ({
    id: `local-${index}`,
    name,
    version: expectedVersion,
    source: null,
    manifest_path: manifestPath
  }));
  const valid = { packages, workspace_members: packages.map((pkg) => pkg.id) };
  validateWorkspacePackages(valid, expectedVersion);

  const imposter = { ...packages[0], id: 'registry-imposter', source: 'registry+https://example.invalid' };
  const missingMember = {
    packages: [...packages, imposter],
    workspace_members: [imposter.id, ...valid.workspace_members.slice(1)]
  };
  assertThrows(() => validateWorkspacePackages(missingMember, expectedVersion),
    'a same-name non-workspace/local imposter must not replace a workspace member');

  const wrongManifestPackages = packages.map((pkg, index) => index === 0 ?
    { ...pkg, manifest_path: path.join(rustRoot, 'wrong/Cargo.toml') } : pkg);
  assertThrows(() => validateWorkspacePackages({
    packages: wrongManifestPackages,
    workspace_members: valid.workspace_members
  }, expectedVersion), 'a workspace member with the wrong manifest must be rejected');
}

function assertThrows(callback, message) {
  let threw = false;
  try {
    callback();
  } catch (_error) {
    threw = true;
  }
  assert(threw, message);
}

try {
  const daemonVersion = readMakeVar(daemonMakefile, 'PKG_VERSION', 'net/lanspeedd/Makefile');
  const daemonRelease = readMakeVar(daemonMakefile, 'PKG_RELEASE', 'net/lanspeedd/Makefile');
  const luciVersion = readMakeVar(luciMakefile, 'PKG_VERSION', 'applications/luci-app-lanspeed/Makefile');
  const luciRelease = readMakeVar(luciMakefile, 'PKG_RELEASE', 'applications/luci-app-lanspeed/Makefile');
  const fullVersion = `${daemonVersion}-r${daemonRelease}`;
  const workspaceVersion = cargoToml.match(/^version = "([^"]+)"$/m);
  const buildVersion = buildCargoToml.match(/^version = "([^"]+)"$/m);
  const immortalwrtRoot = process.env.IMMORTALWRT_ROOT || '/openwrt/immortalwrt';
  const sdkCargo = path.join(immortalwrtRoot, 'staging_dir/target-x86_64_musl/host/bin/cargo');
  let sdkCargoExecutable = false;
  try {
    fs.accessSync(sdkCargo, fs.constants.X_OK);
    sdkCargoExecutable = true;
  } catch (_error) {
    // Fall back to cargo on PATH when the SDK cargo is absent or not executable.
  }
  const cargo = process.env.RUST_CARGO || (sdkCargoExecutable ? sdkCargo : 'cargo');
  const metadata = JSON.parse(childProcess.execFileSync(cargo, [
    'metadata', '--format-version=1', '--locked', '--offline'
  ], { cwd: rustRoot, encoding: 'utf8' }));
  runWorkspaceMetadataSelfTest(daemonVersion);

  assert(daemonVersion === luciVersion, 'daemon and LuCI PKG_VERSION must match for releases');
  assert(daemonRelease === luciRelease, 'daemon and LuCI PKG_RELEASE must match for releases');
  assert(workspaceVersion, 'Cargo workspace must define package.version');
  assert(workspaceVersion[1] === daemonVersion, 'Cargo workspace package.version must match daemon PKG_VERSION');
  assert(buildVersion, 'lanspeed-build must define an independent package.version');
  assert(buildVersion[1] === daemonVersion, 'lanspeed-build package.version must match daemon PKG_VERSION');
  validateWorkspacePackages(metadata, daemonVersion);
  assert(versionJs.includes(`PACKAGE_VERSION: '${daemonVersion}'`), 'version.js PACKAGE_VERSION must match daemon PKG_VERSION');
  assert(versionJs.includes(`PACKAGE_RELEASE: '${daemonRelease}'`), 'version.js PACKAGE_RELEASE must match daemon PKG_RELEASE');
  assert(versionJs.includes(`FULL_VERSION: '${fullVersion}'`), 'version.js FULL_VERSION must match package version and release');
  assert(daemonMakefile.includes('LANSPEED_VERSION="$(PKG_VERSION)"'), 'daemon package must pass PKG_VERSION into Rust status.version');
  assert(daemonMakefile.includes('LANSPEED_RELEASE="$(PKG_RELEASE)"'), 'daemon package must pass PKG_RELEASE into Rust status.version');
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
  const releaseVersion = childProcess.execFileSync('sh', [releaseScriptPath], {
    cwd: root,
    encoding: 'utf8'
  }).trim();
  assert(releaseVersion === fullVersion, 'scripts/release-version.sh output must match daemon package version and release');
  assert(workflow.includes('code_version="$(sh ./scripts/release-version.sh)"'), 'workflow must read the code version through sh scripts/release-version.sh');
  assert(!workflow.includes('ipk_version='), 'Rust release workflow must not prepare unsupported IPK version names');
  assert(workflow.includes('expected_tag="v${code_version}"'), 'workflow must require a v-prefixed tag that matches the code version');
  assert(workflow.includes('"${GITHUB_REF_NAME}" != "$expected_tag"'), 'workflow must fail when the release tag does not match the code version');
  assert(workflow.includes('name: ${{ steps.meta.outputs.code_version }}'), 'GitHub Release name must match the code version');
  assert(!/^      [A-Z_]+:\s*\$\{\{\s*env\./m.test(workflow), 'workflow job env must not reference the env context');
  assert(workflow.includes('$APK_SDK_URL'), 'workflow APK SDK download must read the SDK URL as a runner environment variable');
  assert(workflow.includes('$APK_AARCH64_SDK_URL'), 'workflow APK aarch64 SDK download must read the SDK URL as a runner environment variable');
  assert(/on:\n  push:\n    tags:\n      - 'v\*'/.test(workflow), 'workflow must only run from v* release tags');
  assert(!/branches:/.test(workflow), 'workflow must not run from branch pushes');
  assert(!/pull_request:/.test(workflow), 'workflow must not run from pull requests');
  assert(!/workflow_dispatch:/.test(workflow), 'workflow must not expose a manual build trigger');
  assert(!/inputs\./.test(workflow), 'workflow must not depend on manual workflow inputs');
  assert(!/actions\/upload-artifact/.test(workflow), 'workflow must not upload Actions artifacts');
  assert(!/actions\/download-artifact/.test(workflow), 'workflow must not download Actions artifacts');
  assert(workflow.includes('uses: softprops/action-gh-release@v2.6.2'), 'workflow must publish package files through GitHub Releases');
  assert(workflow.includes('APK_SDK_URL:'), 'workflow must define a dedicated APK SDK URL');
  assert(workflow.includes('APK_AARCH64_SDK_URL:'), 'workflow must define a dedicated APK aarch64 SDK URL');
  assert(!workflow.includes('IPK_SDK_URL:'), 'workflow must not advertise an unsupported OpenWrt 23.05 SDK');
  assert(!workflow.includes('IPK_AARCH64_SDK_URL:'), 'workflow must not advertise unsupported aarch64 IPK builds');
  assert(workflow.includes('https://downloads.immortalwrt.org/releases/25.12.0-rc2/targets/armsr/armv8/immortalwrt-sdk-25.12.0-rc2-armsr-armv8_gcc-14.3.0_musl.Linux-x86_64.tar.zst'), 'workflow must use the official APK aarch64 SDK URL');
  assert(workflow.includes('8fd6e4177ad99b567035cbc2825dd060773556249831fad5560cb1ef9eb1e290'), 'workflow must pin the official APK aarch64 SDK checksum');
  assert(!workflow.includes('23.05.6'), 'workflow must not schedule the unsupported 23.05 release line');
  assert(!workflow.includes('IPK_BASE_FEED_REF:'), 'workflow must not retain an unused IPK feed pin');
  assert(workflow.includes('Download public SDKs'), 'workflow must download the supported APK SDKs');
  assert(workflow.includes('sdk-apk-base'), 'workflow must keep a separate APK SDK for base builds');
  assert(workflow.includes('sdk-apk-bpf'), 'workflow must keep a separate APK SDK for BPF builds');
  assert(workflow.includes('sdk-apk-aarch64-base'), 'workflow must keep a separate APK aarch64 SDK for base builds');
  assert(workflow.includes('sdk-apk-aarch64-bpf'), 'workflow must keep a separate APK aarch64 SDK for BPF builds');
  assert(!workflow.includes('sdk-ipk-'), 'workflow must not create unsupported IPK SDK copies');
  assert(workflow.includes('run_build apk-base'), 'workflow must build APK base packages');
  assert(workflow.includes('run_build apk-bpf'), 'workflow must build APK BPF packages');
  assert(workflow.includes('run_build apk-aarch64-base'), 'workflow must build APK aarch64 base packages');
  assert(workflow.includes('run_build apk-aarch64-bpf'), 'workflow must build APK aarch64 BPF packages');
  assert(!workflow.includes('run_build ipk-'), 'workflow must not run unsupported IPK builds');
  assert(workflow.includes('run_build apk-base "$RUNNER_TEMP/sdk-apk-base" 0 25.12 lanspeedd'), 'APK base builds must use the 25.12 SDK release guard and daemon-only target');
  assert(workflow.includes('run_build apk-bpf "$RUNNER_TEMP/sdk-apk-bpf" 1 25.12 all'), 'APK BPF builds must use the 25.12 SDK release guard and full target');
  assert(workflow.includes('run_build apk-aarch64-base "$RUNNER_TEMP/sdk-apk-aarch64-base" 0 25.12 lanspeedd'), 'APK aarch64 base builds must use the 25.12 SDK release guard and daemon-only target');
  assert(workflow.includes('run_build apk-aarch64-bpf "$RUNNER_TEMP/sdk-apk-aarch64-bpf" 1 25.12 all'), 'APK aarch64 BPF builds must use the 25.12 SDK release guard and full target');
  assert(!/-name '\*\.apk'/.test(workflow), 'workflow must not collect every APK from the SDK output');
  assert(!/-name '\*\.ipk'/.test(workflow), 'workflow must not collect every IPK from the SDK output');
  assert(workflow.includes("lanspeedd-${code_version}.apk"), 'workflow must collect only the matching lanspeedd APK package');
  assert(workflow.includes("lanspeedd-bpf-${code_version}.apk"), 'workflow must collect only the matching lanspeedd-bpf APK package');
  assert(workflow.includes("luci-app-lanspeed-${code_version}.apk"), 'workflow must collect only the matching LuCI APK package');
  assert(!workflow.includes('.ipk"'), 'workflow must not collect unsupported IPK assets');
  assert(workflow.includes('"lanspeedd-${code_version}-aarch64.apk"'), 'workflow must add an aarch64 suffix to APK daemon release assets');
  assert(workflow.includes('"lanspeedd-bpf-${code_version}-aarch64.apk"'), 'workflow must add an aarch64 suffix to APK BPF release assets');
  assert(workflow.includes('"luci-app-lanspeed-${code_version}-aarch64.apk"'), 'workflow must add an aarch64 suffix to APK LuCI release assets');
  assert(!workflow.includes('ramips'), 'workflow must not add non-aarch64 ramips SDK targets');
  assert(!workflow.includes('ath79'), 'workflow must not add non-aarch64 ath79 SDK targets');
  assert(!workflow.includes('ipq40xx'), 'workflow must not add non-aarch64 ipq40xx SDK targets');
  assert(!workflow.includes('qualcommax'), 'workflow must not split aarch64 into Qualcomm SDK targets');
  assert(!workflow.includes('mediatek'), 'workflow must not split aarch64 into MediaTek SDK targets');
  assert(!workflow.includes('rockchip'), 'workflow must not split aarch64 into Rockchip SDK targets');
  assertBefore(workflow, 'file_list="$RUNNER_TEMP/release/files.txt"', 'collect_one "$RUNNER_TEMP/sdk-apk-base" "lanspeedd-${code_version}.apk"', 'workflow must create the release file list before collecting files');
  assertBefore(workflow, 'collect_one "$RUNNER_TEMP/sdk-apk-base" "lanspeedd-${code_version}.apk"', 'collect_one "$RUNNER_TEMP/sdk-apk-bpf" "lanspeedd-bpf-${code_version}.apk"', 'APK base package must be listed before APK BPF package');
  assertBefore(workflow, 'collect_one "$RUNNER_TEMP/sdk-apk-bpf" "lanspeedd-bpf-${code_version}.apk"', 'collect_one "$RUNNER_TEMP/sdk-apk-bpf" "luci-app-lanspeed-${code_version}.apk"', 'APK BPF package must be listed before its mandatory-BPF LuCI package');
  assert(workflow.includes('collect_one "$RUNNER_TEMP/sdk-apk-aarch64-bpf" "luci-app-lanspeed-${code_version}.apk" "luci-app-lanspeed-${code_version}-aarch64.apk"'), 'aarch64 LuCI package must come from the mandatory-BPF build');
  assert(!workflow.includes('find "$release_dir" -type f | sort > "$file_list"'), 'workflow must not reorder release files by temporary paths');

  console.log('validate-release-version: PASS');
} catch (error) {
  console.error('validate-release-version: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
