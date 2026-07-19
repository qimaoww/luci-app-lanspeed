#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');

const evidenceRoot = path.resolve(process.argv[2] || '.');
const summaryPath = path.resolve(process.argv[3] || path.join(evidenceRoot, 'summary.json'));
const expectedPages = ['overview', 'diagnostics', 'config'];
const expectedViewports = ['desktop', 'mobile'];
const expectedKeys = expectedPages.flatMap((pageName) =>
	expectedViewports.map((viewportName) => `${pageName}:${viewportName}`));

function walk(directory) {
	return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
		const entryPath = path.join(directory, entry.name);
		return entry.isDirectory() ? walk(entryPath) : [entryPath];
	});
}

function filenameIdentity(filePath) {
	const match = path.basename(filePath).match(
		/^(overview|diagnostics|config)-(desktop|mobile)-evidence\.json$/);
	return match ? { page: match[1], viewport: match[2] } : { page: null, viewport: null };
}

if (!fs.existsSync(evidenceRoot) || !fs.statSync(evidenceRoot).isDirectory()) {
	console.error(`Evidence directory not found: ${evidenceRoot}`);
	process.exit(2);
}

const evidenceFiles = walk(evidenceRoot)
	.filter((filePath) => filePath.endsWith('-evidence.json'))
	.sort();
const cases = [];

for (const filePath of evidenceFiles) {
	const identity = filenameIdentity(filePath);
	const relativeFile = path.relative(evidenceRoot, filePath);
	try {
		const evidence = JSON.parse(fs.readFileSync(filePath, 'utf8'));
		const viewport = evidence.expected && evidence.expected.viewport || {};
		const pageName = evidence.page || identity.page;
		const viewportName = viewport.name || identity.viewport;
		const failures = Array.isArray(evidence.failures) ? evidence.failures : [];
		const checks = Array.isArray(evidence.checks) ? evidence.checks : [];
		cases.push({
			file: relativeFile,
			key: pageName && viewportName ? `${pageName}:${viewportName}` : null,
			page: pageName,
			viewport: viewportName,
			theme: evidence.expected && evidence.expected.theme || null,
			mode: evidence.expected && evidence.expected.mode || null,
			url: evidence.url || null,
			ok: evidence.ok === true && failures.length === 0,
			invalid: false,
			checkCount: checks.length,
			failureCount: failures.length,
			failures,
			screenshot: evidence.screenshot || null,
			screenshotSaved: evidence.screenshotSaved === true
		});
	} catch (error) {
		cases.push({
			file: relativeFile,
			key: identity.page && identity.viewport ? `${identity.page}:${identity.viewport}` : null,
			page: identity.page,
			viewport: identity.viewport,
			theme: null,
			mode: null,
			url: null,
			ok: false,
			invalid: true,
			checkCount: 0,
			failureCount: 1,
			failures: [{ name: 'evidence-json', ok: false, details: String(error.message || error) }],
			screenshot: null,
			screenshotSaved: false
		});
	}
}

const observedKeys = cases.map((item) => item.key).filter(Boolean);
const missingCases = expectedKeys.filter((key) => !observedKeys.includes(key));
const unexpectedCases = observedKeys.filter((key) => !expectedKeys.includes(key));
const duplicateCases = observedKeys.filter((key, index) => observedKeys.indexOf(key) !== index)
	.filter((key, index, values) => values.indexOf(key) === index);
const themes = [...new Set(cases.map((item) => item.theme).filter(Boolean))];
const modes = [...new Set(cases.map((item) => item.mode).filter(Boolean))];
const invalidCount = cases.filter((item) => item.invalid).length;
const failedCases = cases.filter((item) => !item.ok);
const failedChecks = cases.reduce((total, item) => total + item.failureCount, 0);
const checkCount = cases.reduce((total, item) => total + item.checkCount, 0);
const matrixComplete = evidenceFiles.length === expectedKeys.length &&
	missingCases.length === 0 && unexpectedCases.length === 0 && duplicateCases.length === 0;
const ok = matrixComplete && invalidCount === 0 && failedCases.length === 0 &&
	themes.length === 1 && modes.length === 1;

const summary = {
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	evidenceRoot,
	ok,
	theme: themes.length === 1 ? themes[0] : null,
	mode: modes.length === 1 ? modes[0] : null,
	expectedCaseCount: expectedKeys.length,
	discoveredCaseCount: evidenceFiles.length,
	matrix: {
		complete: matrixComplete,
		expected: expectedKeys,
		missing: missingCases,
		unexpected: unexpectedCases,
		duplicates: duplicateCases
	},
	counts: {
		passedCases: cases.length - failedCases.length,
		failedCases: failedCases.length,
		invalidEvidence: invalidCount,
		checks: checkCount,
		failedChecks
	},
	cases
};

fs.mkdirSync(path.dirname(summaryPath), { recursive: true });
fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2) + '\n');

console.log(`LAN Speed browser audit: ${ok ? 'PASS' : 'FAIL'}`);
console.log(`Theme/mode: ${summary.theme || '-'} / ${summary.mode || '-'}`);
console.log(`Cases: ${summary.counts.passedCases}/${summary.expectedCaseCount} passed`);
console.log(`Checks: ${summary.counts.checks - summary.counts.failedChecks}/${summary.counts.checks} passed`);
if (!matrixComplete) {
	console.error(`Matrix mismatch: missing=${missingCases.join(',') || '-'} ` +
		`unexpected=${unexpectedCases.join(',') || '-'} duplicates=${duplicateCases.join(',') || '-'}`);
}
for (const item of failedCases) {
	const names = item.failures.map((failure) => failure.name || 'unknown').join(', ');
	console.error(`FAIL ${item.key || item.file}: ${names}`);
}
console.log(`Summary: ${summaryPath}`);

process.exitCode = ok ? 0 : 1;
