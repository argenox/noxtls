#!/usr/bin/env node
/**
 * Generates API reference and application Markdown from C source (Doxygen-style comments).
 * Usage: node scripts/generate-api-docs-from-source.js [repo-root] [api-output-dir]
 * Example: node scripts/generate-api-docs-from-source.js . docs/docs/api
 * Also writes application docs to docs/docs/applications when applications dir exists.
 */

const fs = require('fs');
const path = require('path');

const repoRoot = process.argv[2] || path.join(__dirname, '..');
const apiOutDir = process.argv[3] || path.join(__dirname, '..', 'docs', 'docs', 'api');
const applicationsOutDir = path.join(path.dirname(apiOutDir), 'applications');
/** Optional per-page content (prepended before ## API). Place e.g. docs/api-page-overrides/md4.md; not overwritten by generator. */
const apiPageOverridesDir = path.join(repoRoot, 'docs', 'api-page-overrides');

// Escape < and > in prose so MDX does not treat them as JSX
function escapeMdxProse(text) {
  if (!text || typeof text !== 'string') return '';
  return text.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Subgroups: slug (filename), title, and file name prefixes for separate pages
const SUBGROUPS = {
  mdigest: [
    { slug: 'md4', title: 'MD4', prefixes: ['noxtls_md4'] },
    { slug: 'md5', title: 'MD5', prefixes: ['noxtls_md5'] },
    { slug: 'sha1', title: 'SHA-1', prefixes: ['noxtls_sha1'] },
    { slug: 'sha256', title: 'SHA-256', prefixes: ['noxtls_sha256'] },
    { slug: 'sha512', title: 'SHA-512', prefixes: ['noxtls_sha512'] },
    { slug: 'sha3', title: 'SHA-3', prefixes: ['noxtls_sha3'] },
    { slug: 'blake2', title: 'BLAKE2', prefixes: ['noxtls_blake2'] },
    { slug: 'ripemd160', title: 'RIPEMD-160', prefixes: ['noxtls_ripemd160'] },
    { slug: 'hash', title: 'Common hash API', prefixes: ['noxtls_hash', 'noxtls_sha'] },
  ],
  encryption: [
    /* AES modes (order matters: more specific prefix first) */
    { slug: 'aes_ecb', title: 'AES ECB', prefixes: ['noxtls_aes_ecb'] },
    { slug: 'aes_cbc', title: 'AES CBC', prefixes: ['noxtls_aes_cbc'] },
    { slug: 'aes_ctr', title: 'AES CTR', prefixes: ['noxtls_aes_ctr'] },
    { slug: 'aes_cfb', title: 'AES CFB', prefixes: ['noxtls_aes_cfb'] },
    { slug: 'aes_ofb', title: 'AES OFB', prefixes: ['noxtls_aes_ofb'] },
    { slug: 'aes_gcm', title: 'AES GCM', prefixes: ['noxtls_aes_gcm'] },
    { slug: 'aes_ccm', title: 'AES CCM', prefixes: ['noxtls_aes_ccm'] },
    { slug: 'aes_xts', title: 'AES XTS', prefixes: ['noxtls_aes_xts'] },
    { slug: 'aes', title: 'AES (shared)', prefixes: ['noxtls_aes'] },
    { slug: 'aria', title: 'ARIA', prefixes: ['noxtls_aria'] },
    { slug: 'camellia', title: 'Camellia', prefixes: ['noxtls_camellia'] },
    /* ChaCha20: AEAD first so noxtls_chacha20_poly1305 matches before noxtls_chacha20 */
    { slug: 'chacha20_poly1305', title: 'ChaCha20-Poly1305', prefixes: ['noxtls_chacha20_poly1305'] },
    { slug: 'chacha20', title: 'ChaCha20', prefixes: ['noxtls_chacha20'] },
  ],
};

const API_GROUPS = [
  { slug: 'common', title: 'Common', brief: 'Memory, debug, and shared utilities.', dirs: ['noxtls-lib/common'] },
  { slug: 'encryption', title: 'Encryption', brief: 'Block and stream ciphers by mode: AES (ECB, CBC, CTR, CFB, OFB, GCM, CCM, XTS), ARIA, Camellia, ChaCha20, ChaCha20-Poly1305.', dirs: ['noxtls-lib/encryption'], subgroups: SUBGROUPS.encryption },
  { slug: 'mdigest', title: 'Message digest', brief: 'SHA, MD5, SHA-3, BLAKE2, etc.', dirs: ['noxtls-lib/mdigest'], subgroups: SUBGROUPS.mdigest },
  { slug: 'pkc', title: 'Public key crypto', brief: 'RSA, ECC, ECDSA, ECDH.', dirs: ['noxtls-lib/pkc'] },
  { slug: 'certs', title: 'Certificates', brief: 'X.509 and certificate handling.', dirs: ['noxtls-lib/certs'] },
  { slug: 'utility', title: 'Utility', brief: 'Base64, file I/O.', dirs: ['utility'] },
];

const INTERNAL_FILE_PATTERN = /_ut\.(c|h)$|_internal\.(c|h)$|_debug\.(c|h)$/i;

function collectFiles(repoRoot, dirs) {
  const files = [];
  function walk(dir) {
    if (!fs.existsSync(dir)) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isFile() && /\.(c|h)$/i.test(e.name) && !INTERNAL_FILE_PATTERN.test(e.name)) files.push(full);
      if (e.isDirectory() && e.name !== 'ut' && !e.name.startsWith('.')) walk(full);
    }
  }
  for (const d of dirs) walk(path.join(repoRoot, d));
  return files;
}

function parseCommentBlock(block) {
  const brief = block.match(/@brief\s+([\s\S]*?)(?=@param|@return|@|\*\/|$)/)?.[1]?.replace(/\s*\*\s*/g, ' ').trim() || '';
  const params = [];
  /* Support @param name desc and @param[in] / @param[out] / @param[in,out] name desc (no space before bracket) */
  const paramRe = /@param\s*(?:\[[^\]]+\]\s+)?(\S+)\s+([\s\S]*?)(?=@param|@return|@|\*\/|$)/g;
  let m;
  while ((m = paramRe.exec(block)) !== null) params.push({ name: m[1], desc: m[2].replace(/\s*\*\s*/g, ' ').trim() });
  const returnBlock = block.match(/@return\s+([\s\S]*?)(?=@param|@|\*\/|$)/)?.[1];
  const returns = returnBlock ? returnBlock.replace(/\s*\*\s*/g, ' ').trim() : '';
  return { brief, params, returns };
}

function extractFunctionName(decl) {
  const beforeParen = decl.replace(/\s*\([\s\S]*$/, '').trim();
  const tokens = beforeParen.split(/\s+/).filter(Boolean);
  let name = tokens[tokens.length - 1] || 'unknown';
  if (name.startsWith('*')) name = name.replace(/^\*+/, '') || (tokens[tokens.length - 2] || name);
  return name;
}

function isLikelyFunctionSignature(signature) {
  if (!signature || signature.length > 300) return false;
  if (/#define|#include|#ifdef|#endif/.test(signature)) return false;
  if (!/\([^)]*\)\s*;?\s*$/.test(signature)) return false;
  return true;
}

function extractDocBlocks(content, filePath) {
  const blocks = [];
  const re = /\/\*\*([\s\S]*?)\*\/([\s\S]*?)(?=\/\*\*|$)/g;
  let match;
  while ((match = re.exec(content)) !== null) {
    const comment = match[1];
    let after = match[2];
    if (!/@brief/.test(comment)) continue;
    if (/@internal\b/.test(comment)) continue;
    after = after.replace(/^\s+/, '');
    if (/^\s*static\s+/.test(after)) continue;
    const parenStart = after.indexOf('(');
    if (parenStart === -1) continue;
    let signature = '';
    const declSemi = after.indexOf(');');
    const bodyMatch = after.match(/\)\s*\{/);
    const bodyStart = bodyMatch ? bodyMatch.index : -1;
    if (bodyStart !== -1 && (declSemi === -1 || bodyStart < declSemi)) {
      signature = after.slice(0, bodyStart + 1).replace(/\s+/g, ' ').trim() + ';';
    } else if (declSemi !== -1) {
      signature = after.slice(0, declSemi + 2).replace(/\s+/g, ' ').trim();
    }
    if (!signature || !isLikelyFunctionSignature(signature)) continue;
    const parsed = parseCommentBlock(comment);
    const name = extractFunctionName(signature);
    blocks.push({ name, signature, ...parsed, _file: filePath });
  }
  return blocks;
}

/* Prefer block with more params/returns; prefer .h when doc quality is equal */
function mergeMembers(members) {
  const byName = new Map();
  for (const m of members) {
    const existing = byName.get(m.name);
    const file = m._file || '';
    const isHeader = file.endsWith('.h');
    const paramCount = m.params?.length || 0;
    const hasReturn = m.returns ? 1 : 0;
    const score = (paramCount * 20) + (hasReturn * 10) + (isHeader ? 1 : 0);
    if (!existing) {
      byName.set(m.name, { ...m, _score: score });
      continue;
    }
    const existingScore = existing._score || 0;
    if (score > existingScore) {
      byName.set(m.name, { ...m, _score: score });
    }
  }
  return Array.from(byName.values()).map(({ _score, ...rest }) => rest);
}

function getSubgroupForFile(filePath, subgroups) {
  if (!subgroups) return null;
  const base = path.basename(filePath, path.extname(filePath));
  for (const sg of subgroups) {
    if (sg.prefixes.some((p) => base === p || base.startsWith(p + '_'))) return sg;
  }
  return null;
}

/** Map encryption API function names to subgroup slugs so mode-specific APIs land on the right page when declared in a shared header. */
function getEncryptionSubgroupByName(functionName, subgroups) {
  if (!subgroups || !functionName) return null;
  const name = functionName;
  const aesModeSlugs = {
    noxtls_aes_encrypt_ecb: 'aes_ecb', noxtls_aes_decrypt_ecb: 'aes_ecb',
    noxtls_aes_encrypt_cbc: 'aes_cbc', noxtls_aes_decrypt_cbc: 'aes_cbc',
    noxtls_aes_encrypt_ctr: 'aes_ctr', noxtls_aes_decrypt_ctr: 'aes_ctr',
    noxtls_aes_encrypt_cfb: 'aes_cfb', noxtls_aes_decrypt_cfb: 'aes_cfb',
    noxtls_aes_encrypt_ofb: 'aes_ofb', noxtls_aes_decrypt_ofb: 'aes_ofb',
    noxtls_aes_gcm_encrypt: 'aes_gcm', noxtls_aes_gcm_decrypt: 'aes_gcm',
    noxtls_aes_ccm_encrypt: 'aes_ccm', noxtls_aes_ccm_decrypt: 'aes_ccm',
    noxtls_aes_encrypt_xts: 'aes_xts',
  };
  const slug = aesModeSlugs[name];
  if (slug) {
    const sg = subgroups.find((s) => s.slug === slug);
    if (sg) return sg;
  }
  return null;
}

function generateOverviewMarkdown(group, subgroups, position) {
  const safeTitle = group.title.replace(/"/g, '\\"');
  let md = `---
sidebar_position: ${position}
title: "${safeTitle}"
---

# ${group.title}

${escapeMdxProse(group.brief)}

## Pages

`;
  for (const sg of subgroups) {
    md += `- [**${sg.title}**](/docs/api/${sg.slug}) — API for ${sg.title}\n`;
  }
  return md;
}

function generateSingleGroupMarkdown(group, members, position) {
  const safeTitle = group.title.replace(/"/g, '\\"');
  let md = `---
sidebar_position: ${position}
title: "${safeTitle}"
---

# ${group.title}

${escapeMdxProse(group.brief)}

## API

`;
  const seen = new Set();
  for (const m of members) {
    if (seen.has(m.name)) continue;
    seen.add(m.name);
    md += emitMember(m);
  }
  return md;
}

function generateSubgroupPageMarkdown(sg, members, position) {
  const safeTitle = sg.title.replace(/"/g, '\\"');
  const overridePath = path.join(apiPageOverridesDir, sg.slug + '.md');
  let intro = '';
  if (fs.existsSync(overridePath)) {
    intro = fs.readFileSync(overridePath, 'utf8').trim();
    if (intro) intro += '\n\n';
  }
  let md = `---
sidebar_position: ${position}
title: "${safeTitle}"
---

# ${sg.title}

${intro}## API

`;
  const seen = new Set();
  for (const m of members) {
    if (seen.has(m.name)) continue;
    seen.add(m.name);
    md += emitMember(m);
  }
  return md;
}

function emitMember(m) {
  let md = `### \`${m.name}\`

\`\`\`c
${m.signature}
\`\`\`

${escapeMdxProse(m.brief)}

`;
  if (m.params && m.params.length > 0) {
    md += `**Parameters:**

`;
    for (const p of m.params) md += `- \`${p.name}\` — ${escapeMdxProse(p.desc || '')}\n`;
    md += '\n';
  }
  if (m.returns) md += `**Returns:** ${escapeMdxProse(m.returns)}\n\n`;
  return md;
}

// --- API docs
if (!fs.existsSync(apiOutDir)) fs.mkdirSync(apiOutDir, { recursive: true });

let position = 1;
for (const group of API_GROUPS) {
  const files = collectFiles(repoRoot, group.dirs);
  const allMembers = [];
  for (const f of files) {
    const content = fs.readFileSync(f, 'utf8');
    const blocks = extractDocBlocks(content, f);
    allMembers.push(...blocks);
  }
  const merged = mergeMembers(allMembers);
  const subgroups = group.subgroups;

  if (subgroups && subgroups.length > 0) {
    const bySubgroup = new Map();
    for (const sg of subgroups) bySubgroup.set(sg.slug, []);
    for (const m of merged) {
      let sg = null;
      if (group.slug === 'encryption') {
        sg = getEncryptionSubgroupByName(m.name, subgroups) || getSubgroupForFile(m._file || '', subgroups);
      } else {
        sg = getSubgroupForFile(m._file || '', subgroups);
      }
      if (sg) bySubgroup.set(sg.slug, (bySubgroup.get(sg.slug) || []).concat(m));
    }
    const overviewMd = generateOverviewMarkdown(group, subgroups, position++);
    fs.writeFileSync(path.join(apiOutDir, `${group.slug}.md`), overviewMd, 'utf8');
    console.log('Wrote', path.join(apiOutDir, `${group.slug}.md`), '(overview)');
    for (const sg of subgroups) {
      const list = bySubgroup.get(sg.slug) || [];
      const md = generateSubgroupPageMarkdown(sg, list, position++);
      const outPath = path.join(apiOutDir, `${sg.slug}.md`);
      fs.writeFileSync(outPath, md, 'utf8');
      console.log('Wrote', outPath, list.length ? `(${list.length} items)` : '(no items)');
    }
  } else {
    const md = generateSingleGroupMarkdown(group, merged, position++);
    const outPath = path.join(apiOutDir, `${group.slug}.md`);
    fs.writeFileSync(outPath, md, 'utf8');
    console.log('Wrote', outPath, `(${merged.length} items)`);
  }
}

// --- Application docs (from applications/*/main.c or similar)
const applicationsDir = path.join(repoRoot, 'applications');
if (fs.existsSync(applicationsDir) && fs.existsSync(applicationsOutDir)) {
  const appDirs = fs.readdirSync(applicationsDir, { withFileTypes: true }).filter((e) => e.isDirectory());
  const appConfig = [
    { slug: 'app_aes', title: 'AES utility', dir: 'aes', mainFile: 'aes_main.c' },
    { slug: 'app_base64', title: 'Base64 utility', dir: 'base64', mainFile: 'main.c' },
    { slug: 'app_cert', title: 'Cert utility', dir: 'cert', mainFile: 'main.c' },
    { slug: 'app_certificate', title: 'Certificate application', dir: 'certificate', mainFile: 'main.c' },
    { slug: 'app_certgen', title: 'Certgen utility', dir: 'certgen', mainFile: 'main.c' },
    { slug: 'app_dtls_psk_demo', title: 'DTLS PSK demo', dir: 'dtls_psk_demo', mainFile: 'main.c' },
    { slug: 'app_dtls_psk_test', title: 'DTLS PSK test', dir: 'dtls_psk_test', mainFile: 'main.c' },
    { slug: 'app_https_client', title: 'HTTPS client', dir: 'https_client', mainFile: 'main.c' },
    { slug: 'app_https_server', title: 'HTTPS server', dir: 'https_server', mainFile: 'main.c' },
    { slug: 'app_noxtls', title: 'NoxTLS CLI', dir: 'noxtls', mainFile: 'main.c' },
    { slug: 'app_pkc', title: 'PKC utility', dir: 'pkc', mainFile: 'main.c' },
    { slug: 'app_prime', title: 'Prime utility', dir: 'prime', mainFile: 'main.c' },
    { slug: 'app_sha', title: 'SHA utility', dir: 'sha', mainFile: 'main.c' },
    { slug: 'app_tls_test', title: 'TLS test', dir: 'tls_test', mainFile: 'main.c' },
  ];
  let appPos = 1;
  for (const app of appConfig) {
    const mainPath = path.join(applicationsDir, app.dir, app.mainFile);
    if (!fs.existsSync(mainPath)) continue;
    const content = fs.readFileSync(mainPath, 'utf8');
    const briefMatch = content.match(/@brief\s+([^\n*]+)/);
    const brief = briefMatch ? briefMatch[1].replace(/\s*\*\s*/g, ' ').trim() : '';
    const defgroupMatch = content.match(/@defgroup\s+\S+\s+([^\n*]+)/);
    const defgroupDesc = defgroupMatch ? defgroupMatch[1].replace(/\s*\*\s*/g, ' ').trim() : '';
    const desc = (brief || defgroupDesc || app.title).trim();
    const detailsMatch = content.match(/@details\s+([\s\S]*?)(?=@\w+| \*\/)/);
    let details = detailsMatch ? detailsMatch[1].replace(/\s*\*\s?/g, '\n').trim() : '';
    const exampleMatch = content.match(/@example\s+([\s\S]*?)(?=@\w+| \*\/)/);
    let exampleBlock = exampleMatch ? exampleMatch[1].replace(/\s*\*\s?/g, '\n').trim() : '';
    if (details) details = escapeMdxProse(details);
    if (exampleBlock) exampleBlock = escapeMdxProse(exampleBlock);
    const appDir = path.join(applicationsDir, app.dir);
    const readmePath = path.join(appDir, 'README.md');
    let readmeBody = '';
    if (fs.existsSync(readmePath)) {
      readmeBody = fs.readFileSync(readmePath, 'utf8');
      readmeBody = readmeBody.replace(/^\s*#\s+[^\n]+\n?/, '').trim();
    }
    let body = escapeMdxProse(desc);
    if (details) body += '\n\n' + details;
    if (readmeBody) body += '\n\n' + readmeBody;
    if (exampleBlock) body += '\n\n## Examples\n\n' + exampleBlock;
    const md = `---
sidebar_position: ${appPos}
title: "${app.title.replace(/"/g, '\\"')}"
---

# ${app.title}

${body}

`;
    const outPath = path.join(applicationsOutDir, `${app.slug}.md`);
    fs.writeFileSync(outPath, md, 'utf8');
    console.log('Wrote', outPath);
    appPos++;
  }
}

console.log('Done. API docs in', apiOutDir, '; applications in', applicationsOutDir);
