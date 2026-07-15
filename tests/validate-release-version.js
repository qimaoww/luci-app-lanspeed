#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const root = path.resolve(__dirname, '..');
const daemonMakefile = fs.readFileSync(path.join(root, 'net/lanspeedd/Makefile'), 'utf8');
const luciMakefile = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/Makefile'), 'utf8');
const versionJs = fs.readFileSync(path.join(root, 'applications/luci-app-lanspeed/htdocs/luci-static/resources/lanspeed/version.js'), 'utf8');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/build-sdk.yml'), 'utf8');
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

function runGit(cwd, args) {
  return childProcess.execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  }).trim();
}

function writeVersionFixture(fixtureRoot, release) {
  const daemonDir = path.join(fixtureRoot, 'net/lanspeedd');
  const luciDir = path.join(fixtureRoot, 'applications/luci-app-lanspeed');
  const scriptsDir = path.join(fixtureRoot, 'scripts');
  fs.mkdirSync(daemonDir, { recursive: true });
  fs.mkdirSync(luciDir, { recursive: true });
  fs.mkdirSync(scriptsDir, { recursive: true });
  const makefile = `PKG_VERSION:=1.0.0\nPKG_RELEASE:=${release}\n`;
  fs.writeFileSync(path.join(daemonDir, 'Makefile'), makefile);
  fs.writeFileSync(path.join(luciDir, 'Makefile'), makefile);
  fs.writeFileSync(path.join(scriptsDir, 'release-version.sh'), `#!/bin/sh
set -eu
daemon_version="$(sed -n 's/^PKG_VERSION:=//p' net/lanspeedd/Makefile)"
daemon_release="$(sed -n 's/^PKG_RELEASE:=//p' net/lanspeedd/Makefile)"
luci_version="$(sed -n 's/^PKG_VERSION:=//p' applications/luci-app-lanspeed/Makefile)"
luci_release="$(sed -n 's/^PKG_RELEASE:=//p' applications/luci-app-lanspeed/Makefile)"
[ "$daemon_version" = "$luci_version" ]
[ "$daemon_release" = "$luci_release" ]
printf '%s\\n' "\${daemon_version}-r\${daemon_release}"
`);
}

function runForcePushBeforeFetchSelfTest() {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lanspeed-before-fetch-'));
  try {
    const source = path.join(fixtureRoot, 'source');
    const origin = path.join(fixtureRoot, 'origin.git');
    const checkout = path.join(fixtureRoot, 'checkout');
    const beforeDir = path.join(fixtureRoot, 'before');
    fs.mkdirSync(source);
    runGit(source, ['init', '-q', '-b', 'main']);
    runGit(source, ['config', 'user.name', 'Lanspeed Test']);
    runGit(source, ['config', 'user.email', 'lanspeed@example.invalid']);
    writeVersionFixture(source, 2);
    runGit(source, ['add', '.']);
    runGit(source, ['commit', '-q', '-m', 'fixture r2']);
    const beforeSha = runGit(source, ['rev-parse', 'HEAD']);

    runGit(fixtureRoot, ['clone', '-q', '--bare', source, origin]);
    runGit(origin, ['config', 'uploadpack.allowAnySHA1InWant', 'true']);
    writeVersionFixture(source, 3);
    runGit(source, ['add', '.']);
    runGit(source, ['commit', '-q', '--amend', '--no-edit']);
    runGit(origin, ['fetch', '-q', '--no-tags', `file://${source}`, 'HEAD']);
    const replacementSha = runGit(origin, ['rev-parse', 'FETCH_HEAD']);
    runGit(origin, ['update-ref', 'refs/heads/main', replacementSha]);

    runGit(fixtureRoot, ['clone', '-q', '--depth=1', '--branch', 'main', `file://${origin}`, checkout]);
    const beforeMissing = childProcess.spawnSync('git', ['cat-file', '-e', `${beforeSha}^{commit}`], {
      cwd: checkout,
      stdio: 'ignore'
    });
    assert(beforeMissing.status !== 0, 'force-push fixture must begin without the old before object');

    runGit(checkout, ['fetch', '-q', '--no-tags', '--depth=1', 'origin', beforeSha]);
    runGit(checkout, ['cat-file', '-e', `${beforeSha}^{commit}`]);
    fs.mkdirSync(beforeDir);
    const archivePath = path.join(fixtureRoot, 'before.tar');
    runGit(checkout, [
      'archive', '--format=tar', `--output=${archivePath}`, beforeSha, '--',
      'scripts/release-version.sh', 'net/lanspeedd/Makefile',
      'applications/luci-app-lanspeed/Makefile'
    ]);
    childProcess.execFileSync('tar', ['-xf', archivePath, '-C', beforeDir]);
    const beforeVersion = childProcess.execFileSync('sh', ['scripts/release-version.sh'], {
      cwd: beforeDir,
      encoding: 'utf8'
    }).trim();
    const currentVersion = childProcess.execFileSync('sh', ['scripts/release-version.sh'], {
      cwd: checkout,
      encoding: 'utf8'
    }).trim();
    assert(beforeVersion === '1.0.0-r2', 'raw before fetch must recover the old complete version');
    assert(currentVersion === '1.0.0-r3', 'force-push fixture HEAD must retain the new complete version');
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
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
  runForcePushBeforeFetchSelfTest();

  assert(daemonVersion === '1.0.0', 'daemon PKG_VERSION must remain exactly 1.0.0 for this release');
  assert(luciVersion === '1.0.0', 'LuCI PKG_VERSION must remain exactly 1.0.0 for this release');
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
    'configStyleArgon.js',
    'configStyleAurora.js',
    'configStyleBase.js',
    'configStyleBootstrap.js',
    'configStyleResponsive.js',
    'configStyleShared.js',
    'format.js',
    'ifaceConfig.js',
    'nssPanel.js',
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
    'statusStyleCompat.js',
    'statusStyleCompatLive.js',
    'statusStyleCompatLive2.js',
    'statusStyleCompatLive3.js',
    'statusStyleResponsive.js',
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
  assert(/on:\n  push:\n    branches:\n      - main\n    paths:\n      - net\/lanspeedd\/Makefile\n      - applications\/luci-app-lanspeed\/Makefile\n  workflow_dispatch:/.test(workflow),
    'workflow must run for main pushes changing either package Makefile and expose workflow_dispatch');
  assert(!/tags:/.test(workflow), 'workflow must not run from tag pushes');
  assert(!/pull_request:/.test(workflow), 'workflow must not run from pull requests');
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
  assert((workflow.match(/uses: actions\/checkout@v7/g) || []).length === 4, 'each job must use actions/checkout v7 exactly once');
  assert((validateJob.match(/uses: actions\/setup-node@v7/g) || []).length === 1, 'validate job must use actions/setup-node v7 once');
  assert((buildJob.match(/uses: actions\/upload-artifact@v7\.0\.1/g) || []).length === 1,
    'build job must use actions/upload-artifact v7.0.1 once');
  assert((publishJob.match(/uses: actions\/download-artifact@v8\.0\.1/g) || []).length === 2,
    'publish job must download both architecture artifacts with actions/download-artifact v8.0.1');
  assert((publishJob.match(/uses: softprops\/action-gh-release@v3\.0\.2/g) || []).length === 1,
    'publish job must pin action-gh-release v3.0.2 once');
  const detectStep = extractNamedStep(detectJob, 'Detect version change and release state');
  assert(detectStep.includes('code_version="$(sh ./scripts/release-version.sh)"'), 'workflow must read the code version through sh scripts/release-version.sh');
  assert(detectStep.includes("grep -Eq '^[0-9]+\\.[0-9]+\\.[0-9]+-r[0-9]+$'"), 'detect job must validate the complete code version format');
  assert(detectStep.includes('EVENT_NAME: ${{ github.event_name }}'), 'detect job must receive the event name');
  assert(detectStep.includes('BEFORE_SHA: ${{ github.event.before }}'), 'detect job must receive github.event.before for push comparisons');
  assert(detectStep.includes('before="${GITHUB_SHA}^1"'), 'workflow_dispatch must compare HEAD^1 with HEAD');
  assert(detectStep.includes('before="$BEFORE_SHA"'), 'push detection must compare github.event.before with HEAD');
  assert(detectStep.includes('0000000000000000000000000000000000000000'), 'detect job must handle a zero push base SHA');
  const beforeObjectCheck = '            if ! git cat-file -e "${before}^{commit}" 2>/dev/null; then';
  const dispatchMissingGuard = '              if [ "$EVENT_NAME" != push ]; then';
  const beforeFetch = '              git fetch --no-tags --depth=1 origin "$before"';
  const postFetchCheck = '            git cat-file -e "${before}^{commit}"';
  const beforeArchive = '            git archive "$before" -- scripts/release-version.sh net/lanspeedd/Makefile applications/luci-app-lanspeed/Makefile | tar -x -C "$before_dir"';
  assert(detectStep.includes(beforeObjectCheck), 'nonzero before must be checked for a commit object before archive');
  assert(detectStep.includes(dispatchMissingGuard), 'a missing dispatch parent must fail instead of fetching');
  assert(detectStep.includes('error: comparison commit ${before} is unavailable for ${EVENT_NAME}'),
    'missing non-push comparison commits must emit a clear error');
  assert((detectStep.match(/git fetch --no-tags --depth=1 origin "\$before"/g) || []).length === 1,
    'detect job must fetch a missing push before SHA exactly once');
  assert(detectStep.includes(beforeFetch), 'detect job must fetch the raw missing before SHA');
  assert((detectStep.split('git cat-file -e "${before}^{commit}"').length - 1) === 2,
    'detect job must verify the before object before and after a possible fetch');
  assert(detectStep.includes(postFetchCheck), 'detect job must verify the fetched before commit');
  assertBefore(detectStep, beforeObjectCheck, dispatchMissingGuard, 'before object check must precede the event guard');
  assertBefore(detectStep, dispatchMissingGuard, beforeFetch, 'dispatch failure guard must precede push-only fetch');
  assertBefore(detectStep, beforeFetch, postFetchCheck, 'raw before fetch must precede post-fetch verification');
  assertBefore(detectStep, postFetchCheck, beforeArchive, 'before commit verification must precede archive');
  assert(detectStep.includes(beforeArchive),
    'detect job must read the complete previous version from an archived base commit');
  assert(detectStep.includes('before_version="$(sh "$before_dir/scripts/release-version.sh")"'), 'detect job must calculate the previous complete version');
  assert(detectStep.includes('release_tag="v${code_version}"'), 'detect job must derive the v-prefixed release tag');
  assert(!detectStep.includes('&& tag_exists=true'), 'detect job must not treat every git ls-remote failure as a missing tag');
  assert(detectStep.includes('tag_query_status=0'), 'detect job must capture the git ls-remote status');
  assert(detectStep.includes('git ls-remote --exit-code --tags origin "refs/tags/${release_tag}" >/dev/null || tag_query_status=$?'),
    'detect job must preserve the git ls-remote exit status');
  assert(detectStep.includes('case "$tag_query_status" in'), 'detect job must branch on the git ls-remote exit status');
  assert(detectStep.includes('0) tag_exists=true ;;'), 'git ls-remote status 0 must mean the tag exists');
  assert(detectStep.includes('2) tag_exists=false ;;'), 'git ls-remote status 2 must mean the tag is absent');
  assert(detectStep.includes('*)'), 'unexpected git ls-remote statuses must use a catch-all branch');
  assert(detectStep.includes('error: failed to query remote tag ${release_tag}: git ls-remote exit ${tag_query_status}'),
    'unexpected git ls-remote statuses must emit a diagnostic');
  assert(detectStep.includes('exit "$tag_query_status"'), 'unexpected git ls-remote failures must fail closed');
  assert(detectStep.includes('gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100"'), 'detect job must inspect all GitHub Releases');
  const completeReleaseAssets = [
    'lanspeedd-\\($version).apk',
    'lanspeedd-bpf-\\($version).apk',
    'luci-app-lanspeed-\\($version).apk',
    'lanspeedd-\\($version)-aarch64.apk',
    'lanspeedd-bpf-\\($version)-aarch64.apk',
    'luci-app-lanspeed-\\($version)-aarch64.apk'
  ];
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
  assert(detectStep.includes('[ "$tag_exists" = false ] && [ "$release_count" -eq 0 ]'), 'missing tag and Release state must use the version change gate');
  assert(detectStep.includes('[ "$tag_exists" = true ] && [ "$release_count" -eq 1 ] && [ "$complete_count" -eq 1 ]'),
    'only one tag plus one complete published non-prerelease Release may skip rebuilding');
  assert(!detectStep.includes('ready_count='), 'published flags alone must not mark a partial Release complete');
  assert(detectStep.includes('error: incomplete or inconsistent release state for ${release_tag}'),
    'partial, missing, extra, digest-less, draft, prerelease, or duplicate release state must fail clearly');
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
  assert(/^      fail-fast: false$/m.test(buildJob), 'build matrix must keep fail-fast disabled');
  const matrixIds = [...buildJob.matchAll(/^          - id: ([a-z0-9_]+)$/gm)].map((match) => match[1]);
  assertExactList(matrixIds, ['x86_64', 'aarch64'], 'build matrix include must contain exactly x86_64 and aarch64');
  assert(buildJob.includes('sdk_url: https://downloads.immortalwrt.org/releases/25.12.1/targets/x86/64/immortalwrt-sdk-25.12.1-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst'),
    'x86_64 matrix entry must use the exact ImmortalWrt 25.12.1 SDK URL');
  assert(buildJob.includes('sdk_sha256: 02ad8cfc775001ccae8e9282d19696de54e3ab3963f005737ad61f8698263edd'),
    'x86_64 matrix entry must pin the exact SDK checksum');
  assert(buildJob.includes("suffix: ''"), 'x86_64 matrix entry must not add an asset suffix');
  assert(buildJob.includes('artifact: lanspeed-apk-x86_64'), 'x86_64 matrix entry must use its unique artifact name');
  assert(buildJob.includes('sdk_url: https://downloads.immortalwrt.org/releases/25.12.1/targets/armsr/armv8/immortalwrt-sdk-25.12.1-armsr-armv8_gcc-14.3.0_musl.Linux-x86_64.tar.zst'),
    'aarch64 matrix entry must use the exact ImmortalWrt 25.12.1 SDK URL');
  assert(buildJob.includes('sdk_sha256: 1ac4a0940328ebbb71c5e2e44bd798d9acc06b99dc417178fe9868e5e91a0ef5'),
    'aarch64 matrix entry must pin the exact SDK checksum');
  assert(buildJob.includes('suffix: -aarch64'), 'aarch64 matrix entry must add the release asset suffix');
  assert(buildJob.includes('artifact: lanspeed-apk-aarch64'), 'aarch64 matrix entry must use its unique artifact name');
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
  assert(sdkDownloadStep.includes('bpf_sdk="$RUNNER_TEMP/sdk-bpf-${{ matrix.id }}"'), 'matrix build must use a dedicated BPF SDK directory');
  assert(sdkDownloadStep.includes('mkdir -p "$base_sdk" "$bpf_sdk"'), 'matrix build must create only base and BPF SDK trees');
  assert(sdkDownloadStep.includes(sdkTarMarker), 'matrix build must extract the SDK directly into the base tree');
  assert(sdkDownloadStep.includes('rm -f "$sdk_archive"'), 'matrix build must delete the verified SDK archive after extraction');
  assert((sdkDownloadStep.match(/cp -a /g) || []).length === 1 &&
    sdkDownloadStep.includes('cp -a "$base_sdk/." "$bpf_sdk/"'),
  'matrix build must copy the extracted base SDK exactly once into the BPF tree');
  const concurrentBuildStep = extractNamedStep(buildJob, 'Build base and BPF packages concurrently');
  const baseLaunch = `          (
            set -o pipefail
            ENABLE_BPF=0 SDK_RELEASE=25.12 SDK_DIR="$base_sdk" ./scripts/build-sdk.sh lanspeedd 2>&1 | sed -u 's/^/[base] /'
          ) &
          base_pid=$!`;
  const bpfLaunch = `          (
            set -o pipefail
            ENABLE_BPF=1 SDK_RELEASE=25.12 SDK_DIR="$bpf_sdk" ./scripts/build-sdk.sh all 2>&1 | sed -u 's/^/[bpf] /'
          ) &
          bpf_pid=$!`;
  const baseWait = `          if ! wait "$base_pid"; then
            printf '%s\\n' 'error: base SDK build failed' >&2
            status=1
          fi`;
  const bpfWait = `          if ! wait "$bpf_pid"; then
            printf '%s\\n' 'error: BPF SDK build failed' >&2
            status=1
          fi`;
  assert(concurrentBuildStep.includes(baseLaunch), 'base build must use its own pipefail background pipeline and PID');
  assert(concurrentBuildStep.includes(bpfLaunch), 'BPF build must use its own pipefail background pipeline and PID');
  assert((concurrentBuildStep.match(/set -o pipefail/g) || []).length === 2,
    'the two build pipelines must each enable pipefail');
  assert((concurrentBuildStep.match(/^\s+\) &$/gm) || []).length === 2,
    'both build pipelines must start in the background');
  assert(concurrentBuildStep.includes(baseWait), 'base build PID must be waited and aggregate failures');
  assert(concurrentBuildStep.includes(bpfWait), 'BPF build PID must be waited and aggregate failures');
  assert((concurrentBuildStep.match(/status=1/g) || []).length === 2,
    'either build failure must set the aggregate status');
  assertBefore(concurrentBuildStep, 'status=0', baseWait, 'aggregate status must be initialized before waiting for base');
  assertBefore(concurrentBuildStep, baseWait, bpfWait, 'base and BPF PIDs must both be waited');
  assertBefore(concurrentBuildStep, bpfWait, 'exit "$status"', 'workflow must exit with aggregate build status after both waits');
  assert(!/-name '\*\.apk'/.test(workflow), 'workflow must not collect every APK from the SDK output');
  assert(!/-name '\*\.ipk'/.test(workflow), 'workflow must not collect every IPK from the SDK output');
  assert(workflow.includes("lanspeedd-${code_version}.apk"), 'workflow must collect only the matching lanspeedd APK package');
  assert(workflow.includes("lanspeedd-bpf-${code_version}.apk"), 'workflow must collect only the matching lanspeedd-bpf APK package');
  assert(workflow.includes("luci-app-lanspeed-${code_version}.apk"), 'workflow must collect only the matching LuCI APK package');
  assert(!workflow.includes('.ipk"'), 'workflow must not collect unsupported IPK assets');
  assert(!workflow.includes('ramips'), 'workflow must not add non-aarch64 ramips SDK targets');
  assert(!workflow.includes('ath79'), 'workflow must not add non-aarch64 ath79 SDK targets');
  assert(!workflow.includes('ipq40xx'), 'workflow must not add non-aarch64 ipq40xx SDK targets');
  assert(!workflow.includes('qualcommax'), 'workflow must not split aarch64 into Qualcomm SDK targets');
  assert(!workflow.includes('mediatek'), 'workflow must not split aarch64 into MediaTek SDK targets');
  assert(!workflow.includes('rockchip'), 'workflow must not split aarch64 into Rockchip SDK targets');
  assert(workflow.includes('collect_one "$base_sdk" "lanspeedd-${code_version}.apk" "lanspeedd-${code_version}${suffix}.apk"'),
    'matrix artifact must collect exactly the base daemon package');
  assert(workflow.includes('collect_one "$bpf_sdk" "lanspeedd-bpf-${code_version}.apk" "lanspeedd-bpf-${code_version}${suffix}.apk"'),
    'matrix artifact must collect exactly the BPF daemon package');
  assert(workflow.includes('collect_one "$bpf_sdk" "luci-app-lanspeed-${code_version}.apk" "luci-app-lanspeed-${code_version}${suffix}.apk"'),
    'matrix artifact must collect the LuCI package from the mandatory-BPF tree');
  assert(workflow.includes('name: ${{ matrix.artifact }}'), 'matrix upload must use the architecture-specific artifact name');
  assert(workflow.includes('retention-days: 1'), 'matrix artifacts must be retained for one day');
  assert(workflow.includes('compression-level: 0'), 'matrix APK artifacts must disable redundant compression');
  assert(workflow.includes('if-no-files-found: error'), 'matrix upload must fail if any artifact collection failed');
  assert(workflow.includes('name: lanspeed-apk-x86_64'), 'publish job must download the x86_64 artifact separately');
  assert(workflow.includes('name: lanspeed-apk-aarch64'), 'publish job must download the aarch64 artifact separately');
  const expectedAssets = [
    'lanspeedd-${CODE_VERSION}.apk',
    'lanspeedd-bpf-${CODE_VERSION}.apk',
    'luci-app-lanspeed-${CODE_VERSION}.apk',
    'lanspeedd-${CODE_VERSION}-aarch64.apk',
    'lanspeedd-bpf-${CODE_VERSION}-aarch64.apk',
    'luci-app-lanspeed-${CODE_VERSION}-aarch64.apk'
  ];
  expectedAssets.forEach((asset) => {
    assert(workflow.includes(asset), `publish job must require exact release asset ${asset}`);
  });
  assert(workflow.includes('find "$release_dir" -maxdepth 1 -type f -printf \'%f\\n\' | sort > "$actual_files"'),
    'publish job must enumerate only the six downloaded release files');
  assert(workflow.includes('diff -u "$expected_files" "$actual_files"'), 'publish job must reject missing or extra release files');
  assertBefore(workflow, 'diff -u "$expected_files" "$actual_files"', 'git tag "$release_tag" "$GITHUB_SHA"',
    'publish job must validate all six files before creating the tag');
  assert(workflow.includes('git tag "$release_tag" "$GITHUB_SHA"'), 'publish job must create a lightweight tag at GITHUB_SHA');
  assert(workflow.includes('git push origin "refs/tags/${release_tag}"'), 'publish job must push only the new release tag');
  assert(!workflow.includes('git tag -a'), 'publish job must not create an annotated tag');
  assert(!workflow.includes('--force'), 'workflow must never force a tag or release operation');
  assert(workflow.includes('name: ${{ needs.detect.outputs.code_version }}'), 'GitHub Release name must match the complete code version');
  assert(workflow.includes('tag_name: v${{ needs.detect.outputs.code_version }}'), 'GitHub Release must use the detected v-prefixed tag');
  assert(workflow.includes('draft: false'), 'GitHub Release must be published, not drafted');
  assert(workflow.includes('prerelease: false'), 'GitHub Release must not be marked prerelease');
  assert(workflow.includes('fail_on_unmatched_files: true'), 'GitHub Release must fail on missing files');
  assert(workflow.includes('overwrite_files: false'), 'GitHub Release must never overwrite existing assets');
  assert(!workflow.includes('gh release delete-asset'), 'workflow must never delete existing release assets');

  assert(readme.includes('`main` 分支'), 'README must describe the main-branch automatic release trigger');
  assert(readme.includes('`net/lanspeedd/Makefile`') &&
    readme.includes('`applications/luci-app-lanspeed/Makefile`'),
  'README must name both version-bearing Makefiles');
  assert(readme.includes('完整版本发生变化'), 'README must explain that the complete version change triggers the workflow');
  assert(readme.includes('自动创建对应的 `v*` tag 和 GitHub Release'), 'README must state that the workflow creates the tag and Release');
  assert(readme.includes('`workflow_dispatch` 重试'), 'README must document the manual retry trigger');
  assert(readme.includes('清理任何不完整的 tag/Release 状态'), 'README must require cleanup of partial remote state before retry');
  assert(readme.includes('不得预先创建 `v*` tag'), 'README must forbid maintainers from pre-creating release tags');
  assert(!readme.includes('GitHub Actions 在 `v*` tag 发布时'), 'README must not retain the obsolete tag-trigger description');
  assert(readme.includes('`1.0.0-r3`'), 'README full-version example must remain r3');
  assert(!/1\.0\.0-r[45]/.test(readme), 'README must not advance the release beyond r3');

  assert(daemonRelease === '3', 'daemon PKG_RELEASE must be exactly 3 for the automatic release workflow');
  assert(luciRelease === '3', 'LuCI PKG_RELEASE must be exactly 3 for the automatic release workflow');

  console.log('validate-release-version: PASS');
} catch (error) {
  console.error('validate-release-version: FAIL');
  console.error(`  ${error.message}`);
  process.exit(1);
}
