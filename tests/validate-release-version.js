#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const daemonMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const luciMakefile = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/Makefile'), 'utf8');
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

const expectedSdkEntries = [
  {
    id: 'apk-x86-64',
    format: 'apk',
    suffix: 'x86-64',
    release: '25.12',
    archive: 'tar.zst',
    url: 'https://downloads.immortalwrt.org/releases/25.12.0-rc2/targets/x86/64/immortalwrt-sdk-25.12.0-rc2-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
    sha256: 'fb665aabb627d3b3a7d98cd426ee90febdb84ceffa6ce4c18fbda934c46053d5'
  },
  {
    id: 'apk-qualcommax-ipq60xx',
    format: 'apk',
    suffix: 'qualcommax-ipq60xx',
    release: '25.12',
    archive: 'tar.zst',
    url: 'https://downloads.immortalwrt.org/releases/25.12.0-rc2/targets/qualcommax/ipq60xx/immortalwrt-sdk-25.12.0-rc2-qualcommax-ipq60xx_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
    sha256: '00ca445b6dd94ae370dddbc27722c21328ca3191f7781792d3de292347370fe1'
  },
  {
    id: 'apk-qualcommax-ipq807x',
    format: 'apk',
    suffix: 'qualcommax-ipq807x',
    release: '25.12',
    archive: 'tar.zst',
    url: 'https://downloads.immortalwrt.org/releases/25.12.0-rc2/targets/qualcommax/ipq807x/immortalwrt-sdk-25.12.0-rc2-qualcommax-ipq807x_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
    sha256: '865b718966bd6e197155f6e76c30f5958f1d3207eb14d69469c1e4f6056a028f'
  },
  {
    id: 'apk-mediatek-filogic',
    format: 'apk',
    suffix: 'mediatek-filogic',
    release: '25.12',
    archive: 'tar.zst',
    url: 'https://downloads.immortalwrt.org/releases/25.12.0-rc2/targets/mediatek/filogic/immortalwrt-sdk-25.12.0-rc2-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
    sha256: 'afe3b64caac160bbe5c2ec8948768210dc75068a26c9c8ff1b77735200a52611'
  },
  {
    id: 'apk-rockchip-armv8',
    format: 'apk',
    suffix: 'rockchip-armv8',
    release: '25.12',
    archive: 'tar.zst',
    url: 'https://downloads.immortalwrt.org/releases/25.12.0-rc2/targets/rockchip/armv8/immortalwrt-sdk-25.12.0-rc2-rockchip-armv8_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
    sha256: '757b6382b0dc540849e8a62f8b1df5520ef24b663f911cbb4add36eaa475be92'
  },
  {
    id: 'apk-ramips-mt7621',
    format: 'apk',
    suffix: 'ramips-mt7621',
    release: '25.12',
    archive: 'tar.zst',
    url: 'https://downloads.immortalwrt.org/releases/25.12.0-rc2/targets/ramips/mt7621/immortalwrt-sdk-25.12.0-rc2-ramips-mt7621_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
    sha256: '1c1af00794dddd47b3ec69bc925f5e86a78c12aca2ad5b2bdc4e90cf8eb7ae4c'
  },
  {
    id: 'apk-ath79-generic',
    format: 'apk',
    suffix: 'ath79-generic',
    release: '25.12',
    archive: 'tar.zst',
    url: 'https://downloads.immortalwrt.org/releases/25.12.0-rc2/targets/ath79/generic/immortalwrt-sdk-25.12.0-rc2-ath79-generic_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
    sha256: '0ec0c7622883625a71bdb3f02182071c9184e7902292d4210c015873d3e81188'
  },
  {
    id: 'apk-ipq40xx-generic',
    format: 'apk',
    suffix: 'ipq40xx-generic',
    release: '25.12',
    archive: 'tar.zst',
    url: 'https://downloads.immortalwrt.org/releases/25.12.0-rc2/targets/ipq40xx/generic/immortalwrt-sdk-25.12.0-rc2-ipq40xx-generic_gcc-14.3.0_musl_eabi.Linux-x86_64.tar.zst',
    sha256: 'c8b381e5dda9246fc9eec8af1206ef662871523035cf4dba74bf5a7464aed101'
  },
  {
    id: 'ipk-x86-64',
    format: 'ipk',
    suffix: 'x86-64',
    release: '23.05',
    archive: 'tar.xz',
    url: 'https://downloads.immortalwrt.org/releases/23.05.6/targets/x86/64/immortalwrt-sdk-23.05.6-x86-64_gcc-12.3.0_musl.Linux-x86_64.tar.xz',
    sha256: '4dc46a6a612031f14d7d64ca9717895cd8907da7fd01b85f0edee18cb895dc77'
  },
  {
    id: 'ipk-ipq807x-generic',
    format: 'ipk',
    suffix: 'ipq807x-generic',
    release: '23.05',
    archive: 'tar.xz',
    url: 'https://downloads.immortalwrt.org/releases/23.05.6/targets/ipq807x/generic/immortalwrt-sdk-23.05.6-ipq807x-generic_gcc-12.3.0_musl.Linux-x86_64.tar.xz',
    sha256: '4133a2d227edd7af4795509bfc1a5efad877301dceccbf8f3c6034b5e3422f42'
  },
  {
    id: 'ipk-mediatek-filogic',
    format: 'ipk',
    suffix: 'mediatek-filogic',
    release: '23.05',
    archive: 'tar.xz',
    url: 'https://downloads.immortalwrt.org/releases/23.05.6/targets/mediatek/filogic/immortalwrt-sdk-23.05.6-mediatek-filogic_gcc-12.3.0_musl.Linux-x86_64.tar.xz',
    sha256: 'e5e0531023995604be605e6539cd508ae8a9a12c033ee8237c2b85d5457cd1d3'
  },
  {
    id: 'ipk-rockchip-armv8',
    format: 'ipk',
    suffix: 'rockchip-armv8',
    release: '23.05',
    archive: 'tar.xz',
    url: 'https://downloads.immortalwrt.org/releases/23.05.6/targets/rockchip/armv8/immortalwrt-sdk-23.05.6-rockchip-armv8_gcc-12.3.0_musl.Linux-x86_64.tar.xz',
    sha256: 'a803f50e25ba72929131de0b9181243fa1676fa1d9a3b1c7a63dc2e8d4846343'
  },
  {
    id: 'ipk-ramips-mt7621',
    format: 'ipk',
    suffix: 'ramips-mt7621',
    release: '23.05',
    archive: 'tar.xz',
    url: 'https://downloads.immortalwrt.org/releases/23.05.6/targets/ramips/mt7621/immortalwrt-sdk-23.05.6-ramips-mt7621_gcc-12.3.0_musl.Linux-x86_64.tar.xz',
    sha256: 'b1f63c2591979a19132e1af20896e366a0ecf84490601bcb9266c51782a6ba94'
  },
  {
    id: 'ipk-ath79-generic',
    format: 'ipk',
    suffix: 'ath79-generic',
    release: '23.05',
    archive: 'tar.xz',
    url: 'https://downloads.immortalwrt.org/releases/23.05.6/targets/ath79/generic/immortalwrt-sdk-23.05.6-ath79-generic_gcc-12.3.0_musl.Linux-x86_64.tar.xz',
    sha256: '150faaa4e8aabd1f17e8100e6d44b552f7653b354feee805c09c3d76f6fc4aae'
  },
  {
    id: 'ipk-ipq40xx-generic',
    format: 'ipk',
    suffix: 'ipq40xx-generic',
    release: '23.05',
    archive: 'tar.xz',
    url: 'https://downloads.immortalwrt.org/releases/23.05.6/targets/ipq40xx/generic/immortalwrt-sdk-23.05.6-ipq40xx-generic_gcc-12.3.0_musl_eabi.Linux-x86_64.tar.xz',
    sha256: '22359425ea59fa03030fbd33d32bd0560823baf01e0caa940c37268de6726d49'
  }
];

try {
  const daemonVersion = readMakeVar(daemonMakefile, 'PKG_VERSION', 'net/lanspeedd/Makefile');
  const daemonRelease = readMakeVar(daemonMakefile, 'PKG_RELEASE', 'net/lanspeedd/Makefile');
  const luciVersion = readMakeVar(luciMakefile, 'PKG_VERSION', 'applications/luci-app-lanspeed/Makefile');
  const luciRelease = readMakeVar(luciMakefile, 'PKG_RELEASE', 'applications/luci-app-lanspeed/Makefile');
  const fullVersion = `${daemonVersion}-r${daemonRelease}`;

  assert(daemonVersion === luciVersion, 'daemon and LuCI PKG_VERSION must match for releases');
  assert(daemonRelease === luciRelease, 'daemon and LuCI PKG_RELEASE must match for releases');
  assert(versionJs.includes(`FULL_VERSION: '${fullVersion}'`), 'version.js FULL_VERSION must match package version and release');
  assert(releaseScript.includes('printf \'%s\\n\' "${daemon_version}-r${daemon_release}"'), 'scripts/release-version.sh must print the full code version');
  assert(releaseScript.includes('[ "$daemon_version" = "$luci_version" ]'), 'scripts/release-version.sh must verify daemon and LuCI PKG_VERSION match');
  assert(releaseScript.includes('[ "$daemon_release" = "$luci_release" ]'), 'scripts/release-version.sh must verify daemon and LuCI PKG_RELEASE match');
  assert(workflow.includes('code_version="$(sh ./scripts/release-version.sh)"'), 'workflow must read the code version through sh scripts/release-version.sh');
  assert(workflow.includes('ipk_version="${code_version%-r*}-${code_version##*-r}"'), 'workflow must convert the release version to the native IPK package version');
  assert(workflow.includes('expected_tag="v${code_version}"'), 'workflow must require a v-prefixed tag that matches the code version');
  assert(workflow.includes('"${GITHUB_REF_NAME}" != "$expected_tag"'), 'workflow must fail when the release tag does not match the code version');
  assert(workflow.includes('name: ${{ needs.release-init.outputs.code_version }}'), 'GitHub Release name must match the code version');
  assert(workflow.includes('gh release create "$GITHUB_REF_NAME" --title "$code_version" --generate-notes'), 'workflow must create the release with the code version as the title');
  assert(!/^      [A-Z_]+:\s*\$\{\{\s*env\./m.test(workflow), 'workflow job env must not reference the env context');
  assert(/on:\n  push:\n    tags:\n      - 'v\*'/.test(workflow), 'workflow must only run from v* release tags');
  assert(!/branches:/.test(workflow), 'workflow must not run from branch pushes');
  assert(!/pull_request:/.test(workflow), 'workflow must not run from pull requests');
  assert(!/workflow_dispatch:/.test(workflow), 'workflow must not expose a manual build trigger');
  assert(!/inputs\./.test(workflow), 'workflow must not depend on manual workflow inputs');
  assert(!/actions\/upload-artifact/.test(workflow), 'workflow must not upload Actions artifacts');
  assert(!/actions\/download-artifact/.test(workflow), 'workflow must not download Actions artifacts');
  assert(workflow.includes('uses: softprops/action-gh-release@v2.6.2'), 'workflow must publish package files through GitHub Releases');
  assert(workflow.includes('gh release create "$GITHUB_REF_NAME" --title "$code_version" --generate-notes --draft'), 'workflow must keep the release as a draft before all SDK targets finish');
  assert(workflow.includes('draft: true'), 'matrix uploads must target the draft release');
  assert(workflow.includes('release-finish:'), 'workflow must publish the release only after all matrix builds pass');
  assert(workflow.includes('gh release edit "$GITHUB_REF_NAME" --draft=false'), 'workflow must publish the draft release after all SDK targets pass');
  assert(workflow.includes('IPK_BASE_FEED_REF:'), 'workflow must pin the IPK SDK base feed to the release source commit');
  assert(workflow.includes('SDK_BASE_FEED_REF="$base_feed_ref"'), 'workflow must pass the pinned base feed commit into the SDK helper');
  assert(workflow.includes('strategy:'), 'workflow must use a build matrix for common router SDK targets');
  assert(workflow.includes('fail-fast: false'), 'multi-arch builds must not cancel remaining SDK targets after one failure');
  assert(workflow.includes('id: apk-x86-64'), 'workflow must include the x86/64 APK SDK target');
  assert(workflow.includes('id: ipk-x86-64'), 'workflow must include the x86/64 IPK SDK target');
  assert(workflow.includes('sdk_base="$RUNNER_TEMP/sdk-${SDK_ID}-base"'), 'workflow must keep a separate SDK directory for base builds');
  assert(workflow.includes('sdk_bpf="$RUNNER_TEMP/sdk-${SDK_ID}-bpf"'), 'workflow must keep a separate SDK directory for BPF builds');
  assert(workflow.includes('run_build "${SDK_ID}-base" "$sdk_base" 0 "$SDK_RELEASE" "$base_feed_ref"'), 'workflow must build base packages for every SDK target');
  assert(workflow.includes('run_build "${SDK_ID}-bpf" "$sdk_bpf" 1 "$SDK_RELEASE" "$base_feed_ref"'), 'workflow must build BPF packages for every SDK target');
  assert(workflow.includes('if [ "$SDK_FORMAT" = "ipk" ]; then'), 'workflow must only pass the pinned base feed for IPK SDKs');
  assert(workflow.includes('base_feed_ref="$IPK_BASE_FEED_REF"'), 'workflow must pass the pinned IPK base feed commit into IPK builds');
  assert(workflow.includes('Download public SDK'), 'workflow must download each public SDK target');
  assert(workflow.includes('tar --zstd -xf'), 'workflow must unpack APK SDK tar.zst archives');
  assert(workflow.includes('tar -xJf'), 'workflow must unpack IPK SDK tar.xz archives');
  for (const entry of expectedSdkEntries) {
    assert(workflow.includes(`id: ${entry.id}`), `workflow must build SDK target ${entry.id}`);
    assert(workflow.includes(`format: ${entry.format}`), `workflow must set package format for ${entry.id}`);
    assert(workflow.includes(`asset_suffix: ${entry.suffix}`), `workflow must set release asset suffix for ${entry.id}`);
    assert(workflow.includes(`sdk_release: "${entry.release}"`), `workflow must set release guard for ${entry.id}`);
    assert(workflow.includes(`archive: ${entry.archive}`), `workflow must set archive type for ${entry.id}`);
    assert(workflow.includes(`sdk_url: ${entry.url}`), `workflow must use the official SDK URL for ${entry.id}`);
    assert(workflow.includes(`sdk_sha256: ${entry.sha256}`), `workflow must pin the official SDK checksum for ${entry.id}`);
  }
  assert(!/-name '\*\.apk'/.test(workflow), 'workflow must not collect every APK from the SDK output');
  assert(!/-name '\*\.ipk'/.test(workflow), 'workflow must not collect every IPK from the SDK output');
  assert(workflow.includes("lanspeedd-${code_version}.apk"), 'workflow must collect only the matching lanspeedd APK package');
  assert(workflow.includes("lanspeedd-bpf-${code_version}.apk"), 'workflow must collect only the matching lanspeedd-bpf APK package');
  assert(workflow.includes("luci-app-lanspeed-${code_version}.apk"), 'workflow must collect only the matching LuCI APK package');
  assert(workflow.includes("lanspeedd_${ipk_version}_*.ipk"), 'workflow must collect only the matching lanspeedd IPK package');
  assert(workflow.includes("lanspeedd-bpf_${ipk_version}_*.ipk"), 'workflow must collect only the matching lanspeedd-bpf IPK package');
  assert(workflow.includes("luci-app-lanspeed_${ipk_version}_*.ipk"), 'workflow must collect only the matching LuCI IPK package');
  assert(workflow.includes('"lanspeedd-${code_version}-${ASSET_SUFFIX}.apk"'), 'workflow must add a target suffix to APK daemon release assets');
  assert(workflow.includes('"lanspeedd-bpf-${code_version}-${ASSET_SUFFIX}.apk"'), 'workflow must add a target suffix to APK BPF release assets');
  assert(workflow.includes('"luci-app-lanspeed-${code_version}-${ASSET_SUFFIX}.apk"'), 'workflow must add a target suffix to APK LuCI release assets');
  assert(workflow.includes('"lanspeedd_${ipk_version}_${ASSET_SUFFIX}.ipk"'), 'workflow must add a target suffix to IPK daemon release assets');
  assert(workflow.includes('"lanspeedd-bpf_${ipk_version}_${ASSET_SUFFIX}.ipk"'), 'workflow must add a target suffix to IPK BPF release assets');
  assert(workflow.includes('"luci-app-lanspeed_${ipk_version}_${ASSET_SUFFIX}.ipk"'), 'workflow must add a target suffix to IPK LuCI release assets');
  assertBefore(workflow, 'file_list="$RUNNER_TEMP/release/files.txt"', 'collect_one "$sdk_base" "lanspeedd-${code_version}.apk"', 'workflow must create the release file list before collecting APK files');
  assertBefore(workflow, 'collect_one "$sdk_base" "lanspeedd-${code_version}.apk"', 'collect_one "$sdk_bpf" "lanspeedd-bpf-${code_version}.apk"', 'APK base package must be listed before APK BPF package');
  assertBefore(workflow, 'collect_one "$sdk_bpf" "lanspeedd-bpf-${code_version}.apk"', 'collect_one "$sdk_base" "luci-app-lanspeed-${code_version}.apk"', 'APK BPF package must be listed before APK LuCI package');
  assertBefore(workflow, 'collect_one "$sdk_base" "lanspeedd_${ipk_version}_*.ipk"', 'collect_one "$sdk_bpf" "lanspeedd-bpf_${ipk_version}_*.ipk"', 'IPK base package must be listed before IPK BPF package');
  assertBefore(workflow, 'collect_one "$sdk_bpf" "lanspeedd-bpf_${ipk_version}_*.ipk"', 'collect_one "$sdk_base" "luci-app-lanspeed_${ipk_version}_*.ipk"', 'IPK BPF package must be listed before IPK LuCI package');
  assert(!workflow.includes('find "$release_dir" -type f | sort > "$file_list"'), 'workflow must not reorder release files by temporary paths');

  console.log('validate-release-version: PASS');
} catch (error) {
  console.error('validate-release-version: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
