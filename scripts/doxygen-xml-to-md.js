#!/usr/bin/env node
/**
 * Converts Doxygen XML output (groups) to Docusaurus Markdown under website/docs/api/.
 * Usage: node scripts/doxygen-xml-to-md.js <path-to-doxygen-xml> <path-to-output-dir>
 * Example: node scripts/doxygen-xml-to-md.js build/doxygen/xml website/docs/api
 */

const fs = require('fs');
const path = require('path');

const xmlDir = process.argv[2] || path.join(__dirname, '..', 'build', 'doxygen', 'xml');
const apiOutDir = process.argv[3] || path.join(__dirname, '..', 'docs', 'docs', 'api');
const outDirBase = path.dirname(apiOutDir);
const applicationsOutDir = path.join(outDirBase, 'applications');

if (!fs.existsSync(xmlDir)) {
  console.error('Doxygen XML directory not found:', xmlDir);
  process.exit(1);
}

// Map group refid to output filename (strip group__noxtls_ or group__noxtls prefix)
function groupRefIdToSlug(refid) {
  const m = refid.match(/^group__(?:noxtls_)?(.+)$/);
  return m ? m[1] : refid.replace(/^group__/, '');
}

// Strip XML tags and decode basic entities for plain text
function stripXml(html) {
  if (!html || typeof html !== 'string') return '';
  return html
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .trim();
}

// Parse a simple XML string for <tag>content</tag> and return content
function getText(xml, tagName) {
  const re = new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)</${tagName}>`, 'i');
  const m = xml.match(re);
  return m ? stripXml(m[1]) : '';
}

// Get all direct child elements with tag name
function getElements(xml, tagName) {
  const re = new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)</${tagName}>`, 'gi');
  const results = [];
  let m;
  while ((m = re.exec(xml)) !== null) results.push(m[1]);
  return results;
}

// Extract member refids from a group XML content (inner refs)
function getMemberRefs(xml) {
  const refs = [];
  const re = /<member\s+refid="([^"]+)"/g;
  let m;
  while ((m = re.exec(xml)) !== null) refs.push(m[1]);
  return refs;
}

// Extract params from <parameterlist> inside a memberdef block
function getParamList(block) {
  const params = [];
  const paramItemRe = /<parameteritem>([\s\S]*?)<\/parameteritem>/gi;
  let m;
  while ((m = paramItemRe.exec(block)) !== null) {
    const name = getText(m[1], 'parametername');
    const desc = getText(m[1], 'parameterdescription');
    if (name) params.push({ name, desc });
  }
  return params;
}

// Extract return description (simplesect kind="return" or type)
function getReturnDescription(block) {
  const re = /<simplesect[^>]*kind="return"[^>]*>([\s\S]*?)<\/simplesect>/i;
  const m = block.match(re);
  return m ? stripXml(m[1]) : '';
}

// Extract inline <memberdef> elements from group or file XML (Doxygen often embeds these in groups)
// Attribute order can vary (kind= and id= in any order)
function getInlineMemberDefs(xml) {
  const members = [];
  const re = /<memberdef\s+[^>]*>([\s\S]*?)<\/memberdef>/gi;
  const kindRe = /kind="(function|variable|typedef|define|enum|struct)"/i;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const openTag = m[0].indexOf('>') >= 0 ? m[0].slice(0, m[0].indexOf('>') + 1) : '';
    if (!kindRe.test(openTag)) continue;
    const block = m[1];
    const name = getText(block, 'name');
    if (!name) continue;
    const brief = getText(block, 'briefdescription');
    const detailed = getText(block, 'detaileddescription');
    const argsString = getText(block, 'argsstring');
    const params = getParamList(block);
    const returns = getReturnDescription(block);
    members.push({ kind: 'function', name, brief, argsString, detailed, params, returns });
  }
  return members;
}

function processGroupFile(refid, xmlPath) {
  const raw = fs.readFileSync(xmlPath, 'utf8');
  const compound = raw.match(/<compounddef[^>]*kind="group"[^>]*>([\s\S]*?)<\/compounddef>/);
  if (!compound) return null;

  const block = compound[1];
  const name = getText(block, 'compoundname') || getText(block, 'title') || refid;
  const title = getText(block, 'title') || name;
  const brief = getText(block, 'briefdescription');
  const detailed = getText(block, 'detaileddescription');
  const memberRefs = getMemberRefs(block);
  const inlineMembers = getInlineMemberDefs(block);
  const innerFileRefs = getInnerFileRefs(block);
  const allRefIds = getAllRefIds(block);

  return { refid, name, title, brief, detailed, memberRefs, inlineMembers, innerFileRefs, allRefIds };
}

// Group XML may list files via <innerfile refid="...">; we can collect members from those file compounds
function getInnerFileRefs(xml) {
  const refs = [];
  const re = /<innerfile\s+refid="([^"]+)"/g;
  let m;
  while ((m = re.exec(xml)) !== null) refs.push(m[1]);
  return refs;
}

// Any refid="..." in the block (Doxygen may use different tags); used to find file refs that are in fileToMemberIds
function getAllRefIds(xml) {
  const refs = [];
  const re = /\brefid="([^"]+)"/g;
  let m;
  while ((m = re.exec(xml)) !== null) refs.push(m[1]);
  return refs;
}

// Load groups from index.xml - refid and kind can be in any order; name may be on same or next line
function loadIndexGroups(indexPath) {
  const raw = fs.readFileSync(indexPath, 'utf8');
  const groups = [];
  // Match <compound ...>...</compound> blocks, then extract refid, kind, name
  const compoundRe = /<compound\s+([^>]+)>([\s\S]*?)<\/compound>/gi;
  let m;
  while ((m = compoundRe.exec(raw)) !== null) {
    const attrs = m[1];
    const inner = m[2];
    const kindM = attrs.match(/\bkind="([^"]+)"/i);
    const refidM = attrs.match(/\brefid="([^"]+)"/i);
    if (!kindM || kindM[1].toLowerCase() !== 'group') continue;
    if (!refidM || !refidM[1].startsWith('group__')) continue;
    const nameM = inner.match(/<name>([^<]*)<\/name>/i);
    groups.push({ refid: refidM[1], name: nameM ? nameM[1] : refidM[1] });
  }
  return groups;
}

// Fallback: discover group XML files directly (if index.xml has different structure)
function discoverGroupFiles(xmlDir) {
  const groups = [];
  const files = fs.readdirSync(xmlDir);
  for (const f of files) {
    if (!f.startsWith('group__') || !f.endsWith('.xml')) continue;
    const refid = f.slice(0, -4);
    groups.push({ refid, name: refid });
  }
  return groups;
}

// Extract enum value names and descriptions from a memberdef block (kind=enum)
function getEnumValues(block) {
  const values = [];
  const enumValueBlocks = getElements(block, 'enumvalue');
  for (const ev of enumValueBlocks) {
    const ename = getText(ev, 'name');
    if (!ename) continue;
    const ebrief = getText(ev, 'briefdescription');
    values.push({ name: ename, brief: ebrief });
  }
  return values;
}

// Build a refid -> full member info from all compound files (for member refs)
// Doxygen may output attributes in any order; match <memberdef ...>...</memberdef> then parse id/kind
function buildMemberMap(xmlDir) {
  const memberMap = {};
  const files = fs.readdirSync(xmlDir);
  const kindRe = /kind="(function|variable|typedef|define|enum|struct)"/i;
  const idRe = /\bid="([^"]+)"/;
  for (const f of files) {
    if (!f.endsWith('.xml') || f === 'index.xml') continue;
    const raw = fs.readFileSync(path.join(xmlDir, f), 'utf8');
    const blocks = raw.matchAll(/<memberdef\s+[^>]*>([\s\S]*?)<\/memberdef>/gi);
    for (const m of blocks) {
      const openTag = m[0].indexOf('>') >= 0 ? m[0].slice(0, m[0].indexOf('>') + 1) : '';
      const kindM = openTag.match(kindRe);
      const idM = openTag.match(idRe);
      if (!kindM || !idM) continue;
      const kind = kindM[1];
      const id = idM[1];
      const block = m[1];
      const name = getText(block, 'name');
      const brief = getText(block, 'briefdescription');
      const detailed = getText(block, 'detaileddescription');
      const argsString = getText(block, 'argsstring');
      const params = getParamList(block);
      const returns = getReturnDescription(block);
      const entry = { kind, name, brief, argsString, detailed, params, returns };
      if (kind === 'enum') {
        entry.enumvalues = getEnumValues(block);
      }
      memberMap[id] = entry;
    }
  }
  return memberMap;
}

// Build group refid -> [member id] by scanning file compounds for memberdefs that list this group in <membergroups>
function buildGroupToMembers(xmlDir) {
  const groupToMembers = {};
  const files = fs.readdirSync(xmlDir);
  const kindRe = /kind="(function|variable|typedef|define|enum|struct)"/i;
  const idRe = /\bid="([^"]+)"/;
  const refRe = /<ref\s+refid="(group__[^"]+)"/g;
  for (const f of files) {
    if (!f.endsWith('.xml') || f === 'index.xml') continue;
    const raw = fs.readFileSync(path.join(xmlDir, f), 'utf8');
    const blocks = raw.matchAll(/<memberdef\s+[^>]*>([\s\S]*?)<\/memberdef>/gi);
    for (const m of blocks) {
      const openTag = m[0].indexOf('>') >= 0 ? m[0].slice(0, m[0].indexOf('>') + 1) : '';
      const kindM = openTag.match(kindRe);
      const idM = openTag.match(idRe);
      if (!kindM || !idM) continue;
      const id = idM[1];
      const block = m[1];
      const membergroups = block.match(/<membergroups>([\s\S]*?)<\/membergroups>/i);
      if (!membergroups) continue;
      refRe.lastIndex = 0;
      let refM;
      while ((refM = refRe.exec(membergroups[1])) !== null) {
        const gref = refM[1];
        if (!groupToMembers[gref]) groupToMembers[gref] = [];
        if (!groupToMembers[gref].includes(id)) groupToMembers[gref].push(id);
      }
    }
  }
  return groupToMembers;
}

// Build file refid -> [member id] for file compounds (so we can add members from group's innerfile refs)
// Doxygen uses *_8h.xml (headers) and *_8c.xml (C source). Be permissive: any non-group XML with memberdefs counts as a file.
function buildFileToMemberIds(xmlDir) {
  const fileToMemberIds = {};
  const files = fs.readdirSync(xmlDir);
  const kindRe = /kind="(function|variable|typedef|define|enum|struct)"/i;
  const idRe = /\bid="([^"]+)"/;
  for (const f of files) {
    if (!f.endsWith('.xml') || f === 'index.xml' || f.startsWith('group__')) continue;
    const raw = fs.readFileSync(path.join(xmlDir, f), 'utf8');
    const isFileCompound =
      /<compounddef[^>]*kind="file"/i.test(raw) ||
      /_8[ch]\.xml$/i.test(f) ||
      /\.8[ch]\.xml$/i.test(f) ||
      /<memberdef\s+[^>]*kind="function"/i.test(raw);
    if (!isFileCompound) continue;
    const refid = f.slice(0, -4);
    const ids = [];
    const blocks = raw.matchAll(/<memberdef\s+[^>]*>([\s\S]*?)<\/memberdef>/gi);
    for (const m of blocks) {
      const openTag = m[0].indexOf('>') >= 0 ? m[0].slice(0, m[0].indexOf('>') + 1) : '';
      if (!kindRe.test(openTag)) continue;
      const idM = openTag.match(idRe);
      if (idM) ids.push(idM[1]);
    }
    if (ids.length > 0) fileToMemberIds[refid] = ids;
  }
  return fileToMemberIds;
}

function generateGroupMarkdown(group, memberMap, groupToMembers, fileToMemberIds, position) {
  const slug = groupRefIdToSlug(group.refid);
  if (slug === 'noxtls' || slug === '') return null; // skip root group

  const safeTitle = group.title.replace(/"/g, '\\"');
  let md = `---
sidebar_position: ${position}
title: "${safeTitle}"
---

# ${group.title}

`;

  if (group.brief) md += `\n${group.brief}\n\n`;
  if (group.detailed) md += `\n${group.detailed}\n\n`;

  const seenNames = new Set();
  const seenIds = new Set();
  const emitMember = (m) => {
    if (!m || !m.name || seenNames.has(m.name)) return;
    seenNames.add(m.name);
    md += `### \`${m.name}\`\n\n`;
    if (m.argsString) md += `\`\`\`c\n${m.name}${m.argsString}\n\`\`\`\n\n`;
    if (m.brief) md += `${m.brief}\n\n`;
    if (m.detailed) md += `${m.detailed}\n\n`;
    if (m.kind === 'enum' && m.enumvalues && m.enumvalues.length > 0) {
      md += `| Code | Description |\n|------|-------------|\n`;
      for (const ev of m.enumvalues) {
        const desc = ev.brief ? ev.brief.replace(/\|/g, '\\|') : '—';
        md += `| **${ev.name}** | ${desc} |\n`;
      }
      md += '\n';
    }
    if (m.params && m.params.length > 0) {
      md += `**Parameters:**\n\n`;
      for (const p of m.params) {
        md += `- \`${p.name}\` — ${p.desc || '(no description)'}\n`;
      }
      md += '\n';
    }
    if (m.returns) md += `**Returns:** ${m.returns}\n\n`;
  };

  const addMembersByIds = (ids) => {
    for (const id of ids) {
      if (seenIds.has(id)) continue;
      seenIds.add(id);
      const m = memberMap[id];
      if (m) emitMember(m);
    }
  };

  // Refids from group can be member ids or file compound refids; expand file refs to their member ids
  const addRefIds = (refids) => {
    for (const refid of refids) {
      if (memberMap[refid]) {
        addMembersByIds([refid]);
      } else if (fileToMemberIds[refid]) {
        addMembersByIds(fileToMemberIds[refid]);
      }
    }
  };

  const inlineMembers = group.inlineMembers || [];
  const memberRefIds = group.memberRefs || [];
  const groupMemberIds = groupToMembers[group.refid] || [];
  // Inner files: explicit innerfile refs + any refid in group XML that points to a file compound
  let innerFileIds = (group.innerFileRefs || []).flatMap((refid) => fileToMemberIds[refid] || []);
  const refIdsThatAreFiles = (group.allRefIds || []).filter((refid) => fileToMemberIds[refid]);
  innerFileIds = innerFileIds.concat(refIdsThatAreFiles.flatMap((refid) => fileToMemberIds[refid] || []));

  // Fallback: for API groups, include members from files that match known module prefixes (Doxygen may not list innerfile)
  const slugToFilePrefixes = {
    common: ['noxtls_memory', 'noxtls_debug_printf', 'string_common', 'getopt_win', 'handlers', 'noxtls_memory_compat'],
    return_codes: ['noxtls_common'],
    encryption: ['noxtls_aes', 'noxtls_aria', 'noxtls_camellia', 'noxtls_chacha20'],
    mdigest: ['noxtls_hash', 'noxtls_sha', 'noxtls_md5', 'noxtls_sha1', 'noxtls_sha256', 'noxtls_sha512', 'noxtls_sha3', 'noxtls_blake2', 'noxtls_ripemd160', 'noxtls_md4'],
    pkc: ['noxtls_pkc', 'noxtls_rsa', 'noxtls_bignum', 'noxtls_ecc', 'noxtls_ecdsa', 'noxtls_ecdh', 'noxtls_ed25519'],
    certs: ['noxtls_x509', 'asn1', 'certificates', 'oids'],
    utility: ['utility', 'base64'],
  };
  const prefixFallbackIds = [];
  if (slugToFilePrefixes[slug]) {
    for (const fileRefId of Object.keys(fileToMemberIds)) {
      const base = fileRefId.replace(/_8[ch](_1)?$/i, '').replace(/\.8[ch]$/i, '');
      if (slugToFilePrefixes[slug].some((p) => base === p || base.startsWith(p + '_'))) {
        prefixFallbackIds.push(...(fileToMemberIds[fileRefId] || []));
      }
    }
  }

  const hasAny =
    inlineMembers.length > 0 ||
    memberRefIds.length > 0 ||
    groupMemberIds.length > 0 ||
    innerFileIds.length > 0 ||
    prefixFallbackIds.length > 0;

  if (hasAny) {
    md += `## API\n\n`;
    if (inlineMembers.length) for (const m of inlineMembers) emitMember(m);
    addRefIds(memberRefIds);
    addMembersByIds(groupMemberIds);
    addMembersByIds(innerFileIds);
    addMembersByIds(prefixFallbackIds);
  }

  return { slug, md };
}

// Main
const indexPath = path.join(xmlDir, 'index.xml');
if (!fs.existsSync(indexPath)) {
  console.error('index.xml not found in', xmlDir);
  process.exit(1);
}

let indexGroups = loadIndexGroups(indexPath);
if (indexGroups.length === 0) {
  console.warn('No groups found in index.xml; discovering group__*.xml files...');
  indexGroups = discoverGroupFiles(xmlDir);
}
console.log('Found', indexGroups.length, 'group(s)');

const memberMap = buildMemberMap(xmlDir);
const groupToMembers = buildGroupToMembers(xmlDir);
const fileToMemberIds = buildFileToMemberIds(xmlDir);
console.log('Member map has', Object.keys(memberMap).length, 'entries');
console.log('Group→members map has', Object.keys(groupToMembers).length, 'groups');
console.log('File→members map has', Object.keys(fileToMemberIds).length, 'file compounds');
const totalFromFiles = Object.values(fileToMemberIds).reduce((s, arr) => s + arr.length, 0);
console.log('Total member ids from file compounds:', totalFromFiles);
if (Object.keys(fileToMemberIds).length === 0 && Object.keys(memberMap).length > 0) {
  console.warn('No file compounds found; API pages may be empty. Sample XML files:', fs.readdirSync(xmlDir).filter((x) => x.endsWith('.xml')).slice(0, 15));
}

if (!fs.existsSync(apiOutDir)) fs.mkdirSync(apiOutDir, { recursive: true });
if (!fs.existsSync(applicationsOutDir)) fs.mkdirSync(applicationsOutDir, { recursive: true });
if (!fs.existsSync(outDirBase)) fs.mkdirSync(outDirBase, { recursive: true });

let apiPosition = 1;
let appPosition = 1;
let writtenApi = 0;
let writtenApp = 0;
let wroteReturnCodes = false;
for (const g of indexGroups) {
  const slug = groupRefIdToSlug(g.refid);
  if (slug === 'noxtls' || slug === '') continue;

  const xmlPath = path.join(xmlDir, `${g.refid}.xml`);
  if (!fs.existsSync(xmlPath)) {
    console.warn('Group XML not found:', xmlPath);
    continue;
  }

  const group = processGroupFile(g.refid, xmlPath);
  if (!group) {
    console.warn('Could not parse group file:', xmlPath);
    continue;
  }

  const isApp = slug.startsWith('app_');
  const isReturnCodes = slug === 'return_codes' || slug === 'return__codes';
  const position = isReturnCodes ? 7 : (isApp ? appPosition++ : apiPosition++);
  const result = generateGroupMarkdown(group, memberMap, groupToMembers, fileToMemberIds, position);
  if (!result) continue;

  let outDir = isApp ? applicationsOutDir : apiOutDir;
  let fileName = `${result.slug}.md`;
  if (isReturnCodes) {
    outDir = outDirBase;
    fileName = 'return-codes.md';
    wroteReturnCodes = true;
  }
  const outPath = path.join(outDir, fileName);
  fs.writeFileSync(outPath, result.md, 'utf8');
  if (isApp) writtenApp++; else writtenApi++;
  console.log('Wrote', outPath);
}

// Fallback: if return_codes group was not in index (e.g. different Doxygen index layout), try group XML files directly
const returnCodesPath = path.join(outDirBase, 'return-codes.md');
if (!wroteReturnCodes) {
  const returnCodesRefIds = ['group__return_codes', 'group__return__codes', 'group__noxtls_return_codes'];
  for (const refid of returnCodesRefIds) {
    const xmlPath = path.join(xmlDir, `${refid}.xml`);
    if (!fs.existsSync(xmlPath)) continue;
    const group = processGroupFile(refid, xmlPath);
    if (!group) continue;
    const result = generateGroupMarkdown(group, memberMap, groupToMembers, fileToMemberIds, 7);
    const slug = result ? groupRefIdToSlug(group.refid) : '';
    if (result && (slug === 'return_codes' || slug === 'return__codes')) {
      fs.writeFileSync(returnCodesPath, result.md, 'utf8');
      console.log('Wrote', returnCodesPath, '(from', refid + '.xml)');
      wroteReturnCodes = true;
      writtenApi++;
      break;
    }
  }
}
if (!wroteReturnCodes) {
  console.error('ERROR: return-codes.md was not generated. Ensure noxtls_common.h (with @defgroup return_codes) is in Doxygen INPUT and that group XML exists in', xmlDir);
  process.exit(1);
}

console.log('Done. Generated', writtenApi, 'API doc(s) in', apiOutDir, 'and', writtenApp, 'application(s) in', applicationsOutDir);
