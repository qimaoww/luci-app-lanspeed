#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const root = path.resolve(__dirname, '..');
const daemonMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const luciMakefile = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/Makefile'), 'utf8');
const luciMenuSource = fs.readFileSync(path.join(
  root,
  'applications/luci-app-lanspeed/root/usr/share/luci/menu.d/luci-app-lanspeed.json'
), 'utf8');
const versionJs = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/version.js'), 'utf8');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/build-sdk.yml'), 'utf8');
const sdkIdentityScript = fs.readFileSync(path.join(root, 'scripts/sdk-rust-identity.sh'), 'utf8');
const ciWorkflow = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
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
const luciResources = [
  'configForm.js',
  'configModel.js',
  'configStyle.js',
  'configStyleArgon.js',
  'configStyleAurora.js',
  'configStyleBase.js',
  'configStyleBootstrap.js',
  'configStyleResponsive.js',
  'configStyleShared.js',
	'configView.js',
	'designSystem.js',
	'designSystemArgon.js',
	'designSystemAurora.js',
	'designSystemBase.js',
	'designSystemBootstrap.js',
  'diagnosticsRefresh.js',
  'diagnosticsShell.js',
  'diagnosticsStyle.js',
  'diagnosticsStyleArgon.js',
  'diagnosticsStyleAurora.js',
  'diagnosticsStyleBase.js',
  'diagnosticsStyleBootstrap.js',
  'diagnosticsStyleResponsive.js',
  'diagnosticsModel.js',
  'diagnosticsView.js',
	'clientConnections.js',
	'dhcpHostnames.js',
	'clientDetailShell.js',
  'clientDetailStyle.js',
  'clientDetailStyleBase.js',
  'clientDetailStyleBootstrap.js',
  'clientDetailStyleArgon.js',
  'clientDetailStyleAurora.js',
  'clientDetailStyleResponsive.js',
  'clientDetailRefresh.js',
  'clientDetailView.js',
  'format.js',
  'geoLocation.js',
  'ifaceConfig.js',
  'rpc.js',
  'statusCollector.js',
  'statusIp.js',
  'statusRefresh.js',
  'statusShell.js',
  'statusStyle.js',
  'statusStyleArgon.js',
  'statusStyleAurora.js',
  'statusStyleBase.js',
  'statusStyleBootstrap.js',
  'statusStyleResponsive.js',
  'statusOverview.js',
  'statusView.js',
  'theme.js',
  'vocab.js'
];
const luciViews = [ 'config.js', 'diagnostics.js', 'overview.js' ];
const versionedCachePattern = /(?:Live\d+|_live\d+)/;

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

function extractYamlBlock(source, key, indent) {
  const lines = source.split('\n');
  const marker = `${' '.repeat(indent)}${key}:`;
  const start = lines.findIndex((line) => line === marker);
  assert(start !== -1, `workflow must define ${key} at indentation ${indent}`);
  let end = start + 1;
  while (end < lines.length) {
    const line = lines[end];
    if (line.trim() === '') {
      end += 1;
      continue;
    }
    const leadingSpaces = line.match(/^ */)[0].length;
    if (leadingSpaces <= indent) {
      break;
    }
    end += 1;
  }
  return lines.slice(start, end).join('\n');
}

function extractNamedStep(jobBlock, stepName) {
  const lines = jobBlock.split('\n');
  const marker = `      - name: ${stepName}`;
  const start = lines.findIndex((line) => line === marker);
  assert(start !== -1, `workflow job must define step ${stepName}`);
  let end = start + 1;
  while (end < lines.length) {
    const line = lines[end];
    if (line.trim() === '') {
      end += 1;
      continue;
    }
    const leadingSpaces = line.match(/^ */)[0].length;
    if (leadingSpaces <= 6) {
      break;
    }
    end += 1;
  }
  return lines.slice(start, end).join('\n');
}

function readJobNeeds(jobBlock, jobName) {
  const lines = jobBlock.split('\n');
  const needsLines = lines.filter((line) => /^    needs(?::|: )/.test(line));
  assert(needsLines.length === 1, `${jobName} job must define needs exactly once`);
  const scalar = needsLines[0].match(/^    needs: ([a-z0-9_-]+)$/);
  if (scalar) {
    return [scalar[1]];
  }
  assert(needsLines[0] === '    needs:', `${jobName} job needs must be a scalar or list`);
  const start = lines.indexOf(needsLines[0]);
  const needs = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    const match = lines[index].match(/^      - ([a-z0-9_-]+)$/);
    if (!match) {
      break;
    }
    needs.push(match[1]);
  }
  return needs;
}

function assertExactList(actual, expected, message) {
  assert(JSON.stringify(actual) === JSON.stringify(expected), message);
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

  assert(daemonVersion === '1.1.2', 'daemon PKG_VERSION must remain exactly 1.1.2 for this release');
  assert(luciVersion === '1.1.2', 'LuCI PKG_VERSION must remain exactly 1.1.2 for this release');
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
  const resourceInstall = /\t\$\(INSTALL_DIR\) \$\(1\)\/www\/luci-static\/resources\/lanspeed\n\t\$\(INSTALL_DATA\) \\\n([\s\S]*?)\n\t\t\$\(1\)\/www\/luci-static\/resources\/lanspeed\/\n/.exec(luciMakefile);
  assert(resourceInstall, 'LuCI package must keep an explicit resources/lanspeed install block');
  assert(!/[?*\[]/.test(resourceInstall[1]),
    'LuCI resources/lanspeed install block must not use wildcards');
  const installedResources = [...resourceInstall[1].matchAll(
    /\.\/htdocs\/luci-static\/resources\/lanspeed\/([^\s\\/]+\.js)/g
  )].map((match) => match[1]);
  assertExactList(installedResources, luciResources,
    'LuCI release must install the exact ordered semantic resource list');

  const viewInstall = /\t\$\(INSTALL_DIR\) \$\(1\)\/www\/luci-static\/resources\/view\/lanspeed\n\t\$\(INSTALL_DATA\) \\\n([\s\S]*?)\n\t\t\$\(1\)\/www\/luci-static\/resources\/view\/lanspeed\/\n/.exec(luciMakefile);
  assert(viewInstall, 'LuCI package must keep an explicit view/lanspeed install block');
  assert(!/[?*\[]/.test(viewInstall[1]),
    'LuCI view/lanspeed install block must not use wildcards');
  const installedViews = [...viewInstall[1].matchAll(
    /\.\/htdocs\/luci-static\/resources\/view\/lanspeed\/([^\s\\/]+\.js)/g
  )].map((match) => match[1]);
  assertExactList(installedViews, luciViews,
    'LuCI release views must be exactly config.js, diagnostics.js and overview.js');

  assert(!versionedCachePattern.test(luciMakefile),
    'LuCI release Makefile must not contain LiveN or _liveN cache names');
  assert(!versionedCachePattern.test(luciMenuSource),
    'LuCI release menu must not contain LiveN or _liveN cache names');
  const luciMenu = JSON.parse(luciMenuSource);
  const menuViewPaths = Object.values(luciMenu)
    .filter((entry) => entry.action && entry.action.type === 'view')
    .map((entry) => entry.action.path)
    .sort();
  assertExactList(menuViewPaths, [ 'lanspeed/config', 'lanspeed/diagnostics', 'lanspeed/overview' ],
    'LuCI release menu must use the semantic config, diagnostics and overview views');
  assert(releaseScript.includes('printf \'%s\\n\' "${daemon_version}-r${daemon_release}"'), 'scripts/release-version.sh must print the full code version');
  assert(releaseScript.includes('[ "$daemon_version" = "$luci_version" ]'), 'scripts/release-version.sh must verify daemon and LuCI PKG_VERSION match');
  assert(releaseScript.includes('[ "$daemon_release" = "$luci_release" ]'), 'scripts/release-version.sh must verify daemon and LuCI PKG_RELEASE match');
  const releaseVersion = childProcess.execFileSync('sh', [releaseScriptPath], {
    cwd: root,
    encoding: 'utf8'
  }).trim();
  assert(releaseVersion === fullVersion, 'scripts/release-version.sh output must match daemon package version and release');
  assert(/on:\n  push:\n    branches:\n      - main\n    paths:/.test(workflow),
    'release workflow must run from selected main-branch paths');
  [
    'net/lanspeedd/Makefile',
    'applications/luci-app-lanspeed/Makefile',
    'scripts/release-version.sh',
    '.github/workflows/build-sdk.yml'
  ].forEach((triggerPath) => {
    assert(workflow.includes(`      - ${triggerPath}`), `release workflow must watch ${triggerPath}`);
  });
  assert(workflow.includes('  workflow_dispatch:'), 'release workflow must expose workflow_dispatch recovery');
  assert(!/tags:/.test(workflow), 'workflow must not run from tag pushes');
  assert(!/pull_request:/.test(workflow), 'workflow must not run from pull requests');
  assert(workflow.includes('concurrency:\n  group: lanspeed-release\n  cancel-in-progress: false'),
    'release workflow must serialize releases without cancelling an active publish');
  const jobsBlock = extractYamlBlock(workflow, 'jobs', 0);
  const jobNames = [...jobsBlock.matchAll(/^  ([a-z0-9_-]+):$/gm)].map((match) => match[1]);
  assertExactList(jobNames, ['detect', 'validate', 'build', 'publish'],
    'workflow jobs must be exactly detect, validate, build, and publish in order');
  const detectJob = extractYamlBlock(workflow, 'detect', 2);
  const validateJob = extractYamlBlock(workflow, 'validate', 2);
  const buildJob = extractYamlBlock(workflow, 'build', 2);
  const publishJob = extractYamlBlock(workflow, 'publish', 2);
  assertExactList(readJobNeeds(validateJob, 'validate'), ['detect'], 'validate job must need only detect');
  assertExactList(readJobNeeds(buildJob, 'build'), ['detect', 'validate'], 'build job must need detect then validate');
  assertExactList(readJobNeeds(publishJob, 'publish'), ['detect', 'build'], 'publish job must need detect then build');
  assert(/^    if: needs\.detect\.outputs\.changed == 'true'$/m.test(validateJob), 'validate job must use the changed gate');
  assert(/^    if: needs\.detect\.outputs\.changed == 'true'$/m.test(buildJob), 'build job must use the changed gate');
  assert(/^    if: needs\.detect\.outputs\.changed == 'true'$/m.test(publishJob), 'publish job must use the changed gate');
  assert((workflow.match(/^permissions:$/gm) || []).length === 1 &&
    workflow.includes('permissions:\n  contents: read\n\njobs:'), 'workflow must grant global contents read only');
  assert((workflow.match(/^    permissions:$/gm) || []).length === 1,
    'only one job may override workflow permissions');
  assert(!/^    permissions:$/m.test(detectJob), 'detect job must use global read permissions');
  assert(!/^    permissions:$/m.test(validateJob), 'validate job must use global read permissions');
  assert(!/^    permissions:$/m.test(buildJob), 'build job must use global read permissions');
  assert(extractYamlBlock(publishJob, 'permissions', 4).trimEnd() === '    permissions:\n      contents: write',
    'publish job alone must grant contents write');
  assert((workflow.match(/^\s+contents: read$/gm) || []).length === 1, 'workflow must have exactly one contents read grant');
  assert((workflow.match(/^\s+contents: write$/gm) || []).length === 1, 'workflow must have exactly one contents write grant');
  const checkoutAction = 'actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0';
  const setupNodeAction = 'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020';
  const uploadArtifactAction = 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a';
  const downloadArtifactAction = 'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c';
  const cacheRestoreAction = 'actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9';
  const cacheSaveAction = 'actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9';
  assert((workflow.match(new RegExp(checkoutAction, 'g')) || []).length === 4,
    'each release job must use the SHA-pinned checkout v7 action exactly once');
  assert((workflow.match(/persist-credentials: false/g) || []).length === 4,
    'release jobs must not persist the workflow token in Git credentials');
  assert((validateJob.match(new RegExp(setupNodeAction, 'g')) || []).length === 1,
    'release validation must use the SHA-pinned setup-node v7 action once');
  assert((buildJob.match(new RegExp(uploadArtifactAction, 'g')) || []).length === 1,
    'build job must use the SHA-pinned upload-artifact v7.0.1 action once');
  assert((buildJob.match(new RegExp(cacheRestoreAction, 'g')) || []).length === 1,
    'build job must restore the SHA-pinned SDK Rust cache once');
  assert((buildJob.match(new RegExp(cacheSaveAction, 'g')) || []).length === 1,
    'build job must save the SHA-pinned SDK Rust cache once');
  assert((publishJob.match(new RegExp(downloadArtifactAction, 'g')) || []).length === 1,
    'publish job must use the SHA-pinned download-artifact v8.0.1 action once');
  assert(!workflow.includes('softprops/action-gh-release'),
    'release publishing must not depend on a third-party mutable release action');
  const detectStep = extractNamedStep(detectJob, 'Detect release state');
  assert(detectStep.includes('code_version="$(sh ./scripts/release-version.sh)"'), 'workflow must read the code version through sh scripts/release-version.sh');
  assert(detectStep.includes("grep -Eq '^[0-9]+\\.[0-9]+\\.[0-9]+-r[0-9]+$'"), 'detect job must validate the complete code version format');
  assert(!detectStep.includes('github.event.before'),
    'release reconciliation must not depend on a possibly unavailable push predecessor');
  assert(!detectStep.includes('version_changed'),
    'release reconciliation must use current remote state instead of commit-diff heuristics');
  assert(!detectStep.includes('git archive'),
    'release detection must not archive and execute scripts from an old commit');
  assert(detectStep.includes('release_tag="v${code_version}"'), 'detect job must derive the v-prefixed release tag');
  assert(!detectStep.includes('&& tag_exists=true'), 'detect job must not treat every git ls-remote failure as a missing tag');
  assert(detectStep.includes('tag_query_status=0'), 'detect job must capture the git ls-remote status');
  assert(detectStep.includes('git ls-remote --exit-code --tags origin'),
    'detect job must query the remote release tag');
  assert(detectStep.includes('"refs/tags/${release_tag}" "refs/tags/${release_tag}^{}"'),
    'detect job must resolve lightweight and annotated release tags');
  assert(detectStep.includes('case "$tag_query_status" in'), 'detect job must branch on the git ls-remote exit status');
  assert(detectStep.includes('tag_exists=true'), 'git ls-remote status 0 must mean the tag exists');
  assert(detectStep.includes('2) tag_exists=false ;;'), 'git ls-remote status 2 must mean the tag is absent');
  assert(detectStep.includes('*)'), 'unexpected git ls-remote statuses must use a catch-all branch');
  assert(detectStep.includes('error: failed to query remote tag ${release_tag}: git ls-remote exit ${tag_query_status}'),
    'unexpected git ls-remote statuses must emit a diagnostic');
  assert(detectStep.includes('exit "$tag_query_status"'), 'unexpected git ls-remote failures must fail closed');
  assert(detectStep.includes('elif [ "$tag_exists" = true ] && [ "$tag_target" != "$GITHUB_SHA" ]; then'),
    'detect job must reject an incomplete release tag pointing at another commit');
  assert(detectStep.includes('gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100"'), 'detect job must inspect all GitHub Releases');
  const releaseArchitectures = [
    {
      id: 'x86_64',
      packageArch: 'x86_64',
      assetArch: 'x86_64',
      suffix: '',
      artifact: 'lanspeed-apk-x86_64',
      sdkPath: 'x86/64/immortalwrt-sdk-25.12.1-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
      sdkSha256: '02ad8cfc775001ccae8e9282d19696de54e3ab3963f005737ad61f8698263edd'
    },
    {
      id: 'aarch64_generic',
      packageArch: 'aarch64_generic',
      assetArch: 'aarch64_generic',
      suffix: '-aarch64_generic',
      artifact: 'lanspeed-apk-aarch64_generic',
      sdkPath: 'armsr/armv8/immortalwrt-sdk-25.12.1-armsr-armv8_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
      sdkSha256: '1ac4a0940328ebbb71c5e2e44bd798d9acc06b99dc417178fe9868e5e91a0ef5'
    },
    {
      id: 'aarch64_cortex_a53',
      packageArch: 'aarch64_cortex-a53',
      assetArch: 'aarch64_cortex-a53',
      suffix: '-aarch64_cortex-a53',
      artifact: 'lanspeed-apk-aarch64_cortex-a53',
      sdkPath: 'qualcommax/ipq807x/immortalwrt-sdk-25.12.1-qualcommax-ipq807x_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
      sdkSha256: '2abfafc35ab11e9291552577e1d415dbd7c306d05083feca732e3c500d03771e'
    },
    {
      id: 'aarch64_cortex_a72',
      packageArch: 'aarch64_cortex-a72',
      assetArch: 'aarch64_cortex-a72',
      suffix: '-aarch64_cortex-a72',
      artifact: 'lanspeed-apk-aarch64_cortex-a72',
      sdkPath: 'bcm27xx/bcm2711/immortalwrt-sdk-25.12.1-bcm27xx-bcm2711_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
      sdkSha256: '8af293943f9feb1d831a53d6e1b8c1367a8feb186f08f058cebf3ef530e9e68b'
    },
    {
      id: 'aarch64_cortex_a76',
      packageArch: 'aarch64_cortex-a76',
      assetArch: 'aarch64_cortex-a76',
      suffix: '-aarch64_cortex-a76',
      artifact: 'lanspeed-apk-aarch64_cortex-a76',
      sdkPath: 'bcm27xx/bcm2712/immortalwrt-sdk-25.12.1-bcm27xx-bcm2712_gcc-14.3.0_musl.Linux-x86_64.tar.zst',
      sdkSha256: '70d0100420fc65ca7d5f10d308282749259d71f472b607392bd421ad5de1c44a'
    }
  ];
  const completeReleaseAssets = releaseArchitectures.flatMap(({ assetArch, suffix }) => [
    `lanspeedd-\\($version)${suffix}.apk`,
    `lanspeedd-bpf-\\($version)${suffix}.apk`,
    `luci-app-lanspeed-\\($version)${suffix}.apk`,
    `lanspeed-\\($version)-${assetArch}.tar.gz`
  ]);
  assert(detectStep.includes('expected_assets_json="$(jq -nc --arg version "$code_version"'),
    'detect job must build the exact expected asset set from the complete code version');
  completeReleaseAssets.forEach((asset) => {
    assert(detectStep.includes(`"${asset}"`), `detect job must require complete Release asset ${asset}`);
  });
  assert(detectStep.includes('--argjson expected "$expected_assets_json"'),
    'detect job must pass the exact expected asset set into the Release validator');
  assert(detectStep.includes('select(([.assets[].name] | sort) == $expected)'),
    'detect job must reject missing, extra, or duplicate Release asset names');
  assert(detectStep.includes('select(all(.assets[]; .state == "uploaded"))'),
    'detect job must require every Release asset to be uploaded');
  assert(detectStep.includes('select(all(.assets[]; ((.digest // "") | test("^sha256:[0-9a-f]{64}$"))))'),
    'detect job must require every Release asset to have a lowercase SHA256 digest');
  assert(detectStep.includes('complete_count='), 'detect job must count only complete Releases');
  assert(detectStep.includes('[ "$release_count" -eq 0 ]'), 'a missing Release must request publication');
  assert(detectStep.includes('[ "$tag_exists" = true ] && [ "$release_count" -eq 0 ]'),
    'a current orphan tag must be recoverable without another version change');
  assert(detectStep.includes('[ "$tag_exists" = true ] && [ "$release_count" -eq 1 ] && [ "$complete_count" -eq 1 ]'),
    'only one tag plus one complete published non-prerelease Release may skip rebuilding');
  assertBefore(detectStep,
    '[ "$tag_exists" = true ] && [ "$release_count" -eq 1 ] && [ "$complete_count" -eq 1 ]',
    '[ "$tag_exists" = true ] && [ "$tag_target" != "$GITHUB_SHA" ]',
    'an already complete version must remain valid after later non-version commits');
  assert(detectStep.includes('[ "$draft_count" -eq 1 ]'),
    'one draft Release must be recognized as a recoverable retry state');
  assert((detectStep.match(/changed=true/g) || []).length >= 3,
    'missing, orphan-tag, and draft states must all request a rebuild');
  assert(!detectStep.includes('ready_count='), 'published flags alone must not mark a partial Release complete');
  assert(detectStep.includes('error: unrecoverable release state for ${release_tag}'),
    'duplicate or incomplete published release state must fail clearly');
  assert((workflow.match(/if: needs\.detect\.outputs\.changed == 'true'/g) || []).length === 3,
    'validate, build, and publish must all run only for changed == true');
  assert(workflow.includes('Acquire::Retries=3'), 'APT network operations must retry transient failures');
  assert(workflow.includes('RUSTUP_MAX_RETRIES=3'), 'Rust toolchain downloads must retry transient failures');
  assert(workflow.includes('rustup toolchain install 1.96.0 --profile minimal --component rust-src'), 'validation must install Rust 1.96.0 with rust-src');
  assert(workflow.includes('https://github.com/aya-rs/bpf-linker/releases/download/v0.10.3/bpf-linker-x86_64-unknown-linux-musl.tar.gz'),
    'validation must download the official bpf-linker 0.10.3 archive');
  assert(workflow.includes('0fa4645d2dfbb5cafe6231b0aa9fad4f1430bd0871e3bd7319e82d827bf6262c'),
    'validation must pin the official bpf-linker 0.10.3 archive checksum');
  assert(workflow.includes('printf \'%s  %s\\n\' "$bpf_linker_sha256" "$bpf_linker_archive" | sha256sum -c -'),
    'validation must verify bpf-linker before extraction');
  assert(!workflow.includes('cargo install bpf-linker'), 'workflow must not compile an unpinned bpf-linker dependency graph');
  assert(workflow.includes("test \"$(bpf-linker --version)\" = 'bpf-linker 0.10.3'"), 'validation must verify the installed bpf-linker version');
  assert(workflow.includes('./tests/run.sh unit'), 'validate job must run the complete unit suite');
  assert(!workflow.includes('ipk_version='), 'Rust release workflow must not prepare unsupported IPK version names');
  assert(!/^      [A-Z_]+:\s*\$\{\{\s*env\./m.test(workflow), 'workflow job env must not reference the env context');
  assert(!/inputs\./.test(workflow), 'workflow must not depend on manual workflow inputs');
  assert(/^    timeout-minutes: 360$/m.test(buildJob),
    'SDK builds must use the GitHub-hosted runner maximum timeout');
  assert(/^      fail-fast: false$/m.test(buildJob), 'build matrix must keep fail-fast disabled');
  const matrixIds = [...buildJob.matchAll(/^          - id: ([a-z0-9_]+)$/gm)].map((match) => match[1]);
  assertExactList(matrixIds, releaseArchitectures.map(({ id }) => id),
    'build matrix include must contain x86_64 and every distinct ImmortalWrt aarch64 package architecture');
  releaseArchitectures.forEach(({ id, packageArch, assetArch, suffix, artifact, sdkPath, sdkSha256 }) => {
    assert(buildJob.includes(`package_arch: ${packageArch}`), `${id} matrix entry must declare APK architecture ${packageArch}`);
    assert(buildJob.includes(`asset_arch: ${assetArch}`), `${id} matrix entry must declare asset architecture ${assetArch}`);
    assert(buildJob.includes(`sdk_url: https://downloads.immortalwrt.org/releases/25.12.1/targets/${sdkPath}`),
      `${id} matrix entry must use its exact ImmortalWrt 25.12.1 SDK URL`);
    assert(buildJob.includes(`sdk_sha256: ${sdkSha256}`), `${id} matrix entry must pin its exact SDK checksum`);
    assert(buildJob.includes(suffix === '' ? "suffix: ''" : `suffix: ${suffix}`),
      `${id} matrix entry must declare its exact release asset suffix`);
    assert(buildJob.includes(`artifact: ${artifact}`), `${id} matrix entry must use its unique artifact name`);
  });
  assert((buildJob.match(/target_arch: aarch64/g) || []).length === 4,
    'all four ARM64 package architecture entries must use the aarch64 Rust target');
  const curlLines = workflow.split('\n').map((line) => line.trim()).filter((line) => line.startsWith('curl '));
  assert(curlLines.length === 2, 'workflow must contain exactly the bpf-linker and SDK curl downloads');
  curlLines.forEach((line) => {
    assert(/(?:^|\s)--fail(?:\s|$)/.test(line), `curl download must include --fail: ${line}`);
    assert(/(?:^|\s)--location(?:\s|$)/.test(line), `curl download must include --location: ${line}`);
    assert(/(?:^|\s)--retry\s+3(?:\s|$)/.test(line), `curl download must include --retry 3: ${line}`);
    assert(/(?:^|\s)--retry-all-errors(?:\s|$)/.test(line), `curl download must include --retry-all-errors: ${line}`);
  });
  const sdkDownloadStep = extractNamedStep(buildJob, 'Download and verify SDK');
  const sdkChecksumMarker = 'printf \'%s  %s\\n\' "$SDK_SHA256" "$sdk_archive" | sha256sum -c -';
  const sdkTarMarker = 'tar --zstd -xf "$sdk_archive" -C "$base_sdk" --strip-components=1';
  assertBefore(sdkDownloadStep, sdkChecksumMarker, sdkTarMarker,
    'the exact SDK checksum verification must precede the SDK extraction');
  assert(!sdkDownloadStep.includes('sdk_source='), 'matrix build must not retain a third full SDK source tree');
  assert(sdkDownloadStep.includes('base_sdk="$RUNNER_TEMP/sdk-base-${{ matrix.id }}"'), 'matrix build must use a dedicated base SDK directory');
  assert(!sdkDownloadStep.includes('bpf_sdk='), 'SDK download must not clone an unprepared tree for BPF');
  assert(sdkDownloadStep.includes('mkdir -p "$base_sdk"'), 'matrix build must create the base SDK tree');
  assert(sdkDownloadStep.includes(sdkTarMarker), 'matrix build must extract the SDK directly into the base tree');
  assert(sdkDownloadStep.includes('rm -f "$sdk_archive"'), 'matrix build must delete the verified SDK archive after extraction');
  const sdkIdentityStep = extractNamedStep(buildJob, 'Resolve SDK feed and Rust identity');
  assert(sdkIdentityStep.includes('./scripts/build-sdk.sh prepare-feeds'),
    'SDK identity must be measured after one explicit pinned-feed preparation');
  assert(sdkIdentityStep.includes('./scripts/sdk-rust-identity.sh measure "$base_sdk"'),
    'workflow must invoke the shared SDK identity measurement script');
  assert(workflow.includes('scripts/sdk-rust-identity.sh'),
    'SDK identity changes must trigger the release workflow');
  assert(sdkIdentityScript.includes("./scripts/feeds list -s -d '|'"),
    'SDK identity must inspect actual checked-out feed revisions');
  assert(sdkIdentityScript.includes('field[2] == "--root=package"') &&
    sdkIdentityScript.includes('field[3] == "base"') &&
    sdkIdentityScript.includes('printf \'%s %s %s %s\\n\''),
  'SDK identity must accept and preserve only the official SDK base-feed root flag');
  assert(sdkIdentityScript.includes('[ "$feed_revision" = local ]') &&
    sdkIdentityScript.includes('[ "$feed_name" = base ] && [ "$feed_flags" = --root=package ]'),
  'SDK identity must accept only the official SDK-local rooted base feed');
  assert(sdkIdentityStep.includes('^${{') === false,
    'SDK identity must derive feed and Rust values instead of substituting workflow expressions into shell checks');
  assert(sdkIdentityScript.includes('[ "${#feed_revision}" -eq 40 ]'),
    'SDK identity must reject branch, local, or unresolved external feed revisions');
  assert(sdkIdentityScript.includes('must use a ^commit pin; branch sources are not reusable') &&
    sdkIdentityScript.includes('configured_revision=${feed_source#*^}') &&
    sdkIdentityScript.includes('[ "$configured_revision" = "$feed_revision" ]'),
    'SDK identity must require caret pins that match each actual feed HEAD');
  assert(sdkIdentityScript.includes('feeds/packages/lang/rust') &&
    sdkIdentityScript.includes("sed -n 's/^PKG_VERSION:="),
  'SDK identity must derive the host compiler version from the actual packages Rust recipe');
  assert(sdkIdentityScript.includes('find . -type f -print0') &&
    sdkIdentityScript.includes('rust_recipe_hash=') &&
    sdkIdentityScript.includes('feeds_hash='),
  'SDK identity must hash the complete Rust recipe and sorted feed manifest');
  ['feeds_hash', 'rust_version', 'rust_recipe_hash'].forEach((output) => {
    assert(sdkIdentityScript.includes(`printf '${output}=%s\\n'`),
      `SDK identity must export ${output} for the cache key`);
  });
  const rustCacheRestoreStep = extractNamedStep(buildJob, 'Restore SDK Rust host cache');
  const rustCacheSaveStep = extractNamedStep(buildJob, 'Save SDK Rust host cache');
  const rustCacheKey = 'lanspeed-sdk-rust-v2-${{ runner.os }}-${{ runner.arch }}-${{ matrix.target_arch }}-${{ matrix.sdk_sha256 }}-feeds-${{ steps.sdk-identity.outputs.feeds_hash }}-rust-${{ steps.sdk-identity.outputs.rust_version }}-recipe-${{ steps.sdk-identity.outputs.rust_recipe_hash }}';
  assert(rustCacheRestoreStep.includes(`key: ${rustCacheKey}`),
    'Rust cache restore must be isolated by runner, target, SDK, feeds, and exact Rust recipe');
  assert(rustCacheSaveStep.includes(`key: ${rustCacheKey}`),
    'Rust cache save must use the exact restore key');
  assert(!rustCacheRestoreStep.includes('restore-keys:'),
    'Rust cache must not fall back across incompatible SDK checksums');
  [
    '/dl/cargo',
    '/dl/rustc',
    '/dl/rustc-*.tar.xz',
    '/staging_dir/hostpkg/stamp/.rust_installed',
    '/staging_dir/target-*/host',
    '/build_dir/target-*/host/rustc-*/.built*',
    '/build_dir/target-*/host/rustc-*/.configured',
    '/build_dir/target-*/host/rustc-*/.prepared*'
  ].forEach((cachePath) => {
    assert(rustCacheRestoreStep.includes(cachePath), `Rust cache restore must include ${cachePath}`);
    assert(rustCacheSaveStep.includes(cachePath), `Rust cache save must include ${cachePath}`);
  });
  assert(rustCacheSaveStep.includes("if: steps.sdk-rust-cache.outputs.cache-hit != 'true'"),
    'Rust cache save must run only after a cache miss');

  const baseBuildStep = extractNamedStep(buildJob, 'Build base package');
  assert(baseBuildStep.includes('ENABLE_BPF=0 SDK_RELEASE=25.12 SDK_DIR="$base_sdk"'),
    'base SDK must build the non-BPF daemon first');
  assert(baseBuildStep.includes('./scripts/build-sdk.sh lanspeedd'),
    'base SDK must build only the daemon target');
  assert(baseBuildStep.includes('SDK_FEEDS_PREPARED=1') &&
    baseBuildStep.includes('SDK_FEEDS_HASH=') &&
    baseBuildStep.includes('SDK_RUST_VERSION=') &&
    baseBuildStep.includes('SDK_RUST_RECIPE_HASH=') &&
    baseBuildStep.includes('TARGET_ARCH="${{ matrix.target_arch }}"'),
  'base SDK build must reuse the measured feed tree for the explicit target architecture');
  const pruneRustStep = extractNamedStep(buildJob, 'Prune SDK Rust build tree');
  assert(pruneRustStep.includes("-path '*/host/bin/rustc'"),
    'Rust pruning must first verify the installed rustc');
  assert(pruneRustStep.includes("-path '*/host/bin/cargo'"),
    'Rust pruning must first verify the installed cargo');
  assert(pruneRustStep.includes('steps.sdk-identity.outputs.rust_version') &&
    pruneRustStep.includes('rustc release $rustc_release does not match recipe $expected_rust'),
  'cache restore must be rejected unless the installed rustc matches the measured SDK recipe');
  assert(pruneRustStep.includes('! -name \'.built\''), 'Rust pruning must retain the built stamp');
  assert(pruneRustStep.includes('! -name \'.configured\''), 'Rust pruning must retain the configured stamp');
  assert(pruneRustStep.includes('! -name \'.prepared*\''), 'Rust pruning must retain prepared stamps');
  assert(pruneRustStep.includes('-exec rm -rf {} +'),
    'Rust pruning must remove the large compiler source and build products');

  const clonePreparedStep = extractNamedStep(buildJob, 'Clone prepared SDK for BPF build');
  assert(clonePreparedStep.includes('cp -a "$base_sdk/." "$bpf_sdk/"'),
    'BPF SDK must be cloned only after the base Rust toolchain is prepared');
  const bpfBuildStep = extractNamedStep(buildJob, 'Build BPF packages');
  assert(bpfBuildStep.includes('ENABLE_BPF=1 SDK_RELEASE=25.12 SDK_DIR="$bpf_sdk"'),
    'BPF SDK must reuse the prepared clone with BPF enabled');
  assert(bpfBuildStep.includes('./scripts/build-sdk.sh all'),
    'BPF SDK must build both daemon and LuCI targets');
  assert(bpfBuildStep.includes('SDK_FEEDS_PREPARED=1') &&
    bpfBuildStep.includes('SDK_FEEDS_HASH=') &&
    bpfBuildStep.includes('SDK_RUST_VERSION=') &&
    bpfBuildStep.includes('SDK_RUST_RECIPE_HASH=') &&
    bpfBuildStep.includes('TARGET_ARCH="${{ matrix.target_arch }}"'),
  'BPF SDK build must reuse the same measured feed tree and target architecture');
  assert(!buildJob.includes('Build base and BPF packages concurrently'),
    'base and BPF builds must not compile the Rust host toolchain concurrently');
  assertBefore(buildJob, 'name: Restore SDK Rust host cache', 'name: Build base package',
    'cache restore must precede the base build');
  assertBefore(buildJob, 'name: Download and verify SDK', 'name: Resolve SDK feed and Rust identity',
    'SDK extraction must precede feed and Rust identity measurement');
  assertBefore(buildJob, 'name: Resolve SDK feed and Rust identity', 'name: Restore SDK Rust host cache',
    'the complete SDK identity must be known before cache restore');
  assertBefore(buildJob, 'name: Build base package', 'name: Prune SDK Rust build tree',
    'base build must finish before pruning');
  assertBefore(buildJob, 'name: Prune SDK Rust build tree', 'name: Save SDK Rust host cache',
    'pruning must precede cache save');
  assertBefore(buildJob, 'name: Save SDK Rust host cache', 'name: Clone prepared SDK for BPF build',
    'the first successful base build must save its cache before the BPF phase');
  assertBefore(buildJob, 'name: Clone prepared SDK for BPF build', 'name: Build BPF packages',
    'the prepared SDK clone must precede the BPF build');
  assert(!/-name '\*\.apk'/.test(workflow), 'workflow must not collect every APK from the SDK output');
  assert(!/-name '\*\.ipk'/.test(workflow), 'workflow must not collect every IPK from the SDK output');
  assert(workflow.includes("lanspeedd-${code_version}.apk"), 'workflow must collect only the matching lanspeedd APK package');
  assert(workflow.includes("lanspeedd-bpf-${code_version}.apk"), 'workflow must collect only the matching lanspeedd-bpf APK package');
  assert(workflow.includes("luci-app-lanspeed-${code_version}.apk"), 'workflow must collect only the matching LuCI APK package');
  assert(!workflow.includes('.ipk"'), 'workflow must not collect unsupported IPK assets');
  assert(!workflow.includes('ramips'), 'workflow must not add non-aarch64 ramips SDK targets');
  assert(!workflow.includes('ath79'), 'workflow must not add non-aarch64 ath79 SDK targets');
  assert(!workflow.includes('ipq40xx'), 'workflow must not add non-aarch64 ipq40xx SDK targets');
  assert(workflow.includes('collect_one "$base_sdk" "lanspeedd-${code_version}.apk" "lanspeedd-${code_version}${suffix}.apk"'),
    'matrix artifact must collect exactly the base daemon package');
  assert(workflow.includes('collect_one "$bpf_sdk" "lanspeedd-bpf-${code_version}.apk" "lanspeedd-bpf-${code_version}${suffix}.apk"'),
    'matrix artifact must collect exactly the BPF daemon package');
  assert(workflow.includes('collect_one "$bpf_sdk" "luci-app-lanspeed-${code_version}.apk" "luci-app-lanspeed-${code_version}${suffix}.apk"'),
    'matrix artifact must collect the LuCI package from the mandatory-BPF tree');
  const apkValidationStep = extractNamedStep(buildJob, 'Validate architecture APK contracts');
  assert(apkValidationStep.includes('./tests/validate-sdk-apks.sh'),
    'each matrix artifact must pass the shared APK contract validator');
  assert(apkValidationStep.includes('"${{ matrix.package_arch }}"'),
    'APK validation must use the architecture declared by the matrix');
  assertBefore(buildJob, 'name: Collect architecture artifact', 'name: Validate architecture APK contracts',
    'all three exact APKs must be collected before contract validation');
  const bundleStep = extractNamedStep(buildJob, 'Create architecture bundle');
  assert(bundleStep.includes('asset_arch="${{ matrix.asset_arch }}"'),
    'bundle name must use the exact package architecture label');
  assert(bundleStep.includes('bundle_name="lanspeed-${code_version}-${asset_arch}.tar.gz"'),
    'each matrix entry must create one architecture-specific tar.gz bundle');
  assert(bundleStep.includes('tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner'),
    'architecture bundles must use reproducible tar metadata');
  assert(bundleStep.includes('tar -tzf "$artifact_dir/$bundle_name" | sort > "$actual_members"') &&
    bundleStep.includes('diff -u "$expected_members" "$actual_members"'),
  'bundle validation must require exactly the same three APK members');
  assert(bundleStep.includes('[ "$file_count" -ne 4 ]'),
    'each architecture artifact must contain three APKs and one bundle');
  assertBefore(buildJob, 'name: Validate architecture APK contracts', 'name: Create architecture bundle',
    'APK metadata, dependencies, ELF, and BPF objects must pass before bundling');
  assertBefore(buildJob, 'name: Create architecture bundle', 'name: Upload architecture artifact',
    'the validated bundle must exist before artifact upload');
  assert(workflow.includes('name: ${{ matrix.artifact }}'), 'matrix upload must use the architecture-specific artifact name');
  assert(workflow.includes('path: ${{ runner.temp }}/artifact-${{ matrix.id }}/*'),
    'matrix upload must include the three APKs and architecture bundle');
  assert(workflow.includes('retention-days: 1'), 'matrix artifacts must be retained for one day');
  assert(workflow.includes('compression-level: 0'), 'matrix APK artifacts must disable redundant compression');
  assert(workflow.includes('if-no-files-found: error'), 'matrix upload must fail if any artifact collection failed');
  assert(publishJob.includes('pattern: lanspeed-apk-*') && publishJob.includes('merge-multiple: true'),
    'publish job must download and merge every architecture artifact from the same run');
  const expectedAssets = releaseArchitectures.flatMap(({ assetArch, suffix }) => [
    `lanspeedd-${'${CODE_VERSION}'}${suffix}.apk`,
    `lanspeedd-bpf-${'${CODE_VERSION}'}${suffix}.apk`,
    `luci-app-lanspeed-${'${CODE_VERSION}'}${suffix}.apk`,
    `lanspeed-${'${CODE_VERSION}'}-${assetArch}.tar.gz`
  ]);
  expectedAssets.forEach((asset) => {
    assert(workflow.includes(asset), `publish job must require exact release asset ${asset}`);
  });
  assert(workflow.includes('find "$release_dir" -maxdepth 1 -type f -printf \'%f\\n\' | sort > "$actual_files"'),
    'publish job must enumerate only the 20 downloaded release files');
  assert(workflow.includes('diff -u "$expected_files" "$actual_files"'), 'publish job must reject missing or extra release files');
  assertBefore(workflow, 'diff -u "$expected_files" "$actual_files"', 'name: Publish recoverable GitHub Release',
    'publish job must validate all 20 files before creating a draft Release');
  const recoverablePublishStep = extractNamedStep(publishJob, 'Publish recoverable GitHub Release');
  assert(recoverablePublishStep.includes('RELEASE_TAG: ${{ needs.detect.outputs.release_tag }}'),
    'publish step must use the exact tag emitted by detection');
  assert(recoverablePublishStep.includes('target_commitish: $sha'),
    'draft Release creation must target the workflow commit');
  assert(recoverablePublishStep.includes('draft: true'),
    'assets must be uploaded to a draft Release');
  assert(recoverablePublishStep.includes('gh api --method DELETE "repos/${GITHUB_REPOSITORY}/releases/${existing_id}"'),
    'a failed draft must be deleted before a clean retry');
  assert(recoverablePublishStep.includes('if [ "$existing_draft" != true ]; then'),
    'an incomplete published Release must never be replaced');
  assert(recoverablePublishStep.includes('gh release upload "$RELEASE_TAG" "${files[@]}"'),
    'all exact APK and bundle files must be uploaded without clobbering existing assets');
  assert(recoverablePublishStep.includes('mapfile -t files < <(find "$release_dir"') &&
    recoverablePublishStep.includes('[ "${#files[@]}" -ne 20 ]'),
  'publish must upload the complete validated 20-file set');
  assert(recoverablePublishStep.includes('for attempt in $(seq 1 12); do'),
    'publish must wait for GitHub to expose asset digests');
  assert(recoverablePublishStep.includes("jq -nc '{draft: false}'"),
    'the Release must only be published after asset validation');
  assert(recoverablePublishStep.includes('published_complete='),
    'the published Release must receive a final exact validation');
  assert(recoverablePublishStep.includes('final_tag_target='),
    'the final published tag must be verified against the workflow commit');
  assert(!workflow.includes('git push origin "refs/tags/'),
    'release creation must let the GitHub Release API create or reuse the tag');
  assert(!workflow.includes('--force'), 'workflow must never force a tag or release operation');
  assert(!workflow.includes('--clobber'), 'workflow must never overwrite an existing release asset');
  assert(!workflow.includes('gh release delete-asset'), 'workflow must never edit individual existing release assets');

  assert(ciWorkflow.includes('name: Continuous Integration'), 'repository must define a separate CI workflow');
  assert(ciWorkflow.includes('  pull_request:'), 'CI must validate pull requests');
  assert(ciWorkflow.includes('  push:\n    branches:\n      - main'), 'CI must validate main-branch pushes');
  [
    '.github/workflows/**',
    'applications/**',
    'net/**',
    'scripts/**',
    'tests/**'
  ].forEach((triggerPath) => {
    assert(ciWorkflow.includes(`      - ${triggerPath}`), `CI workflow must watch ${triggerPath}`);
  });
  assert(ciWorkflow.includes('cancel-in-progress: true'), 'CI must cancel superseded runs for the same ref');
  assert((ciWorkflow.match(new RegExp(checkoutAction, 'g')) || []).length === 1,
    'CI must use the SHA-pinned checkout v7 action once');
  assert((ciWorkflow.match(/persist-credentials: false/g) || []).length === 1,
    'CI must not persist its workflow token in Git credentials');
  assert((ciWorkflow.match(new RegExp(setupNodeAction, 'g')) || []).length === 1,
    'CI must use the SHA-pinned setup-node v7 action once');
  assert(ciWorkflow.includes('./tests/run.sh unit'), 'CI must run the complete unit suite');
  assert(ciWorkflow.includes('timeout-minutes: 45'), 'CI must have a finite validation timeout');

  assert(readme.includes('`main` 分支'), 'README must describe the main-branch automatic release trigger');
  assert(readme.includes('`net/lanspeedd/Makefile`') &&
    readme.includes('`applications/luci-app-lanspeed/Makefile`'),
  'README must name both version-bearing Makefiles');
  assert(readme.includes('完整版本发生变化'), 'README must explain that the complete version change triggers the workflow');
  assert(readme.includes('按 runner 操作系统与架构、目标架构、SDK SHA256、feeds 实际 revision、Rust 配方版本和内容哈希隔离缓存'),
    'README must document the complete Rust host toolchain cache identity');
  assert(readme.includes('后续相同 SDK 不再从头编译 Rust'),
    'README must explain the cache benefit');
  assert(readme.includes('草稿 Release'), 'README must describe draft-first publication');
  assert(readme.includes('`workflow_dispatch` 自动重建'), 'README must document automatic draft recovery');
  assert(readme.includes('手动运行也可补发'), 'README must document missing-release recovery');
  assert(readme.includes('不得预先创建 `v*` tag'), 'README must forbid maintainers from pre-creating release tags');
  assert(!readme.includes('GitHub Actions 在 `v*` tag 发布时'), 'README must not retain the obsolete tag-trigger description');
  assert(readme.includes('`1.1.2-r5`'), 'README full-version example must match the 1.1.2 release');
	assert(!/1\.1\.2-r(?:0|1|2|3|4|[6-9]|[1-9][0-9]+)/.test(readme),
	  'README must keep the 1.1.2 release at r5');

	assert(daemonRelease === '5', 'daemon PKG_RELEASE must be exactly 5 for the automatic release workflow');
	assert(luciRelease === '5', 'LuCI PKG_RELEASE must be exactly 5 for the automatic release workflow');

  console.log('validate-release-version: PASS');
} catch (error) {
  console.error('validate-release-version: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
