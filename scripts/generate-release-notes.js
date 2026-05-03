#!/usr/bin/env node
/**
 * Generates per-version Release Notes pages for Docusaurus from changelog.json.
 * Each version gets its own release-notes.md showing only that version's content.
 *
 * Usage: node scripts/generate-release-notes.js [repo-root]
 * Example: node scripts/generate-release-notes.js .
 * Run from repo root, or pass path to noxtls repo (where docs/ and versioned_docs/ live).
 *
 * Prerequisites:
 *   - docs/changelog.json (releases[].version, date, changes[], fixed[], known_issues[])
 *   - docs/versions.json (list of version strings)
 *
 * Writes:
 *   - docs/release-notes.md (current/latest version's notes, for "Next" and default)
 *   - versioned_docs/version-<X.Y.Z>/release-notes.md for each version that has a changelog entry
 */

const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const docsDir = path.join(repoRoot, 'docs');
const versionedDocsDir = path.join(docsDir, 'versioned_docs');
const changelogPath = path.join(docsDir, 'changelog.json');
const versionsPath = path.join(docsDir, 'versions.json');

if (!fs.existsSync(changelogPath)) {
  console.error('changelog.json not found at', changelogPath);
  process.exit(1);
}
if (!fs.existsSync(versionsPath)) {
  console.error('versions.json not found at', versionsPath);
  process.exit(1);
}

const changelog = JSON.parse(fs.readFileSync(changelogPath, 'utf8'));
const versions = JSON.parse(fs.readFileSync(versionsPath, 'utf8'));
const byVersion = new Map((changelog.releases || []).map((r) => [r.version, r]));

function renderList(items, prefix = '- ') {
  if (!items || items.length === 0) return '';
  return items.map((item) => `${prefix}${item}`).join('\n');
}

function buildMarkdown(version, release, options = {}) {
  const { onlyThisVersion = true } = options;
  const lines = [
    '---',
    'sidebar_position: 8',
    'title: Release Notes',
    '---',
    '',
    '# Release Notes',
    '',
  ];
  if (onlyThisVersion) {
    lines.push(`This page describes changes, fixes, and known issues for **NoxTLS ${version}**.`);
    lines.push('');
    lines.push('For source and binary artifacts, see [Releases on GitHub](https://github.com/argenox/noxtls/releases).');
    lines.push('');
    lines.push('Use the **version dropdown** in the navbar to view docs (and release notes) for other versions.');
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push(`## ${version}`);
    lines.push('');
    lines.push(`**Release date:** ${release.date || 'TBD'}`);
    lines.push('');
    lines.push('### Changes');
    lines.push('');
    lines.push(release.changes && release.changes.length ? renderList(release.changes) : '- (No changes recorded.)');
    lines.push('');
    lines.push('### Fixed / Resolved');
    lines.push('');
    lines.push(release.fixed && release.fixed.length ? renderList(release.fixed) : '- (None recorded.)');
    lines.push('');
    lines.push('### Known issues / Open');
    lines.push('');
    lines.push(release.known_issues && release.known_issues.length ? renderList(release.known_issues) : '- (None recorded.)');
  }
  return lines.join('\n');
}

let written = 0;

// Main docs: show latest version's notes (for "Next" and default)
const latestVersion = versions[0];
const latestRelease = byVersion.get(latestVersion);
if (latestRelease) {
  const mainReleasePath = path.join(docsDir, 'docs', 'release-notes.md');
  const mainContent = buildMarkdown(latestVersion, latestRelease, { onlyThisVersion: true });
  fs.mkdirSync(path.dirname(mainReleasePath), { recursive: true });
  fs.writeFileSync(mainReleasePath, mainContent, 'utf8');
  console.log('Written', mainReleasePath, `(${latestVersion})`);
  written++;
}

// Versioned docs: one release-notes.md per version that has a changelog entry and a versioned_docs folder
for (const version of versions) {
  const release = byVersion.get(version);
  const versionedDir = path.join(versionedDocsDir, `version-${version}`);
  if (!release) continue;
  if (!fs.existsSync(versionedDir)) {
    console.warn('Skipping', version, '(versioned_docs/version-' + version + '/ not found)');
    continue;
  }
  const outPath = path.join(versionedDir, 'release-notes.md');
  const content = buildMarkdown(version, release, { onlyThisVersion: true });
  fs.writeFileSync(outPath, content, 'utf8');
  console.log('Written', outPath);
  written++;
}

console.log('Done. Generated', written, 'release-notes page(s).');
