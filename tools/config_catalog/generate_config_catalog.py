#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
"""
Generate noxtls_config_catalog.xml from noxtls_config.h and manual overlays.

Usage:
  python generate_config_catalog.py              # write catalog XML
  python generate_config_catalog.py --check      # validate catalog vs headers
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
NOXTLS_ROOT = SCRIPT_DIR.parent.parent
CONFIG_H = NOXTLS_ROOT / "noxtls_config.h"
VERSION_H = NOXTLS_ROOT / "noxtls_version.h"
OVERRIDES_JSON = SCRIPT_DIR / "config_catalog_overrides.json"
OUTPUT_XML = NOXTLS_ROOT / "noxtls_config_catalog.xml"

PROFILE_BLOCK_START = re.compile(r"#if defined\(NOXTLS_PROFILE_(\w+)\)")
DEFINE_RE = re.compile(r"^#define\s+(\w+)\s+(.+)$")
UNDEF_RE = re.compile(r"^#undef\s+(\w+)$")
VERSION_STRING_RE = re.compile(r'#define\s+NOXTLS_VERSION_STRING\s+"([^"]+)"')

PREREQ_RE = re.compile(
    r"Prereq:\s*(.+?)(?:\.|$)", re.IGNORECASE
)
REQUIRED_BY_RE = re.compile(
    r"Required by:\s*(.+?)(?:\.|$)", re.IGNORECASE
)
DEP_MACRO_RE = re.compile(r"(NOXTLS_[A-Z0-9_]+)\s*=\s*([01])")
LEGACY_NOTE_RE = re.compile(r"legacy", re.IGNORECASE)

# End of canonical defaults (before profile preset overrides section).
DEFAULTS_SECTION_END_MARKER = "Profile presets (override defaults above)"


@dataclass
class Setting:
    id: str
    value: str
    description: str = ""
    prereq_text: str = ""
    required_by_text: str = ""
    line: int = 0
    in_ifndef: bool = False
    profile_overrides: dict[str, str] = field(default_factory=dict)
    # enriched
    name: str = ""
    category: str = ""
    parent: str = ""
    legacy: bool = False
    type: str = "boolean"
    dependencies_all: list[dict[str, str]] = field(default_factory=list)
    dependencies_any: list[dict[str, str]] = field(default_factory=list)
    constraints: list[dict[str, str]] = field(default_factory=list)
    required_by: list[str] = field(default_factory=list)
    todos: list[str] = field(default_factory=list)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_version(version_h: Path) -> str:
    text = read_text(version_h)
    m = VERSION_STRING_RE.search(text)
    if not m:
        raise SystemExit(f"Could not parse NOXTLS_VERSION_STRING from {version_h}")
    return m.group(1)


def normalize_value(raw: str) -> str:
    return raw.strip().rstrip("\\").strip()


def is_boolean_value(value: str) -> bool:
    v = value.strip()
    return v in ("0", "1")


def default_enabled(value: str) -> str:
    v = value.strip()
    if v in ("0", "1"):
        return "enabled" if v == "1" else "disabled"
    return v


def infer_type(macro_id: str, value: str) -> str:
    if macro_id.startswith("NOXTLS_PROFILE_") or macro_id.startswith(
        "NOXTLS_SIDECHANNEL_PROFILE_"
    ):
        return "profile"
    if is_boolean_value(value):
        return "boolean"
    return "integer"


def friendly_name(macro_id: str) -> str:
    s = macro_id
    for prefix in (
        "NOXTLS_FEATURE_",
        "NOXTLS_CFG_",
        "NOXTLS_HAVE_",
        "NOXTLS_PROFILE_",
        "NOXTLS_SIDECHANNEL_PROFILE_",
    ):
        if s.startswith(prefix):
            s = s[len(prefix) :]
            break
    if s.startswith("NOXTLS_"):
        s = s[7:]
    return s.replace("_", " ").title()


def infer_category(macro_id: str) -> str:
    if macro_id.startswith("NOXTLS_PROFILE_"):
        return "profiles"
    if macro_id.startswith("NOXTLS_SIDECHANNEL_PROFILE_") or macro_id == "NOXTLS_CT_COMPARE":
        return "sidechannel"
    if macro_id in (
        "NOXTLS_FEATURE_HASH",
        "NOXTLS_FEATURE_ENCRYPTION",
        "NOXTLS_FEATURE_DRBG",
        "NOXTLS_FEATURE_PKC",
        "NOXTLS_FEATURE_CERT",
        "NOXTLS_FEATURE_TLS",
    ):
        return "core"
    if macro_id.startswith("NOXTLS_FEATURE_MD") or macro_id.startswith("NOXTLS_FEATURE_SHA"):
        return "hash"
    if macro_id in ("NOXTLS_FEATURE_RIPEMD160", "NOXTLS_FEATURE_BLAKE2"):
        return "hash"
    if macro_id.startswith("NOXTLS_FEATURE_AES") or macro_id in (
        "NOXTLS_FEATURE_ARIA",
        "NOXTLS_FEATURE_CAMELLIA",
        "NOXTLS_FEATURE_CHACHA20_POLY1305",
        "NOXTLS_FEATURE_DES",
        "NOXTLS_FEATURE_RC4",
    ):
        return "encryption"
    if macro_id.startswith("NOXTLS_FEATURE_RSA") or macro_id.startswith("NOXTLS_FEATURE_ECC"):
        return "pkc"
    if macro_id in (
        "NOXTLS_FEATURE_ECDSA",
        "NOXTLS_FEATURE_ECDH",
        "NOXTLS_FEATURE_DH",
        "NOXTLS_FEATURE_X25519",
        "NOXTLS_FEATURE_X448",
        "NOXTLS_FEATURE_ED25519",
        "NOXTLS_FEATURE_ED448",
        "NOXTLS_FEATURE_DSA",
        "NOXTLS_FEATURE_ML_KEM",
        "NOXTLS_FEATURE_ML_DSA",
    ):
        return "pkc"
    if macro_id.startswith("NOXTLS_FEATURE_TLS") or macro_id == "NOXTLS_FEATURE_DTLS":
        return "tls"
    if macro_id.startswith("NOXTLS_TLS") or macro_id.startswith("NOXTLS_CFG_TLS"):
        return "tls"
    if macro_id.startswith("NOXTLS_X509") or macro_id.startswith("NOXTLS_HAVE_CERT"):
        return "cert"
    if macro_id.startswith("NOXTLS_MAX_CERT"):
        return "cert"
    if macro_id.startswith("NOXTLS_USE_STATIC") or macro_id == "NOXTLS_STATIC_BUFFER_SIZE":
        return "memory"
    if macro_id.startswith("NOXTLS_RSA_") and not macro_id.startswith("NOXTLS_FEATURE_RSA"):
        return "rsa-tuning"
    if macro_id.startswith("NOXTLS_ECC_"):
        return "ecc-tuning"
    if macro_id == "NOXTLS_HAVE_TIME":
        return "system"
    if macro_id.startswith("NOXTLS_CFG_ENABLE"):
        return "observability"
    return "other"


def infer_parent(macro_id: str) -> str:
    parents = {
        "hash": "NOXTLS_FEATURE_HASH",
        "encryption": "NOXTLS_FEATURE_ENCRYPTION",
        "pkc": "NOXTLS_FEATURE_PKC",
        "tls": "NOXTLS_FEATURE_TLS",
        "cert": "NOXTLS_FEATURE_CERT",
    }
    cat = infer_category(macro_id)
    if macro_id in parents.values():
        return ""
    if cat in parents and macro_id != parents[cat]:
        return parents[cat]
    if macro_id.startswith("NOXTLS_FEATURE_AES_") or (
        macro_id.startswith("NOXTLS_FEATURE_AES") and macro_id != "NOXTLS_FEATURE_AES"
    ):
        return "NOXTLS_FEATURE_AES"
    if macro_id in (
        "NOXTLS_TLS12_ENABLE_LEGACY_CIPHER_SUITES",
        "NOXTLS_CFG_TLS13_ALLOW_RSA_PKCS1_CERTVERIFY",
    ):
        return "NOXTLS_FEATURE_TLS"
    if macro_id.startswith("NOXTLS_HAVE_CERT"):
        return "NOXTLS_FEATURE_CERT"
    if macro_id.startswith("NOXTLS_X509"):
        return "NOXTLS_FEATURE_CERT"
    return ""


def parse_dependencies(prereq_text: str) -> list[dict[str, str]]:
    deps: list[dict[str, str]] = []
    if not prereq_text.strip() or prereq_text.strip().lower() == "none":
        return deps
    for part in re.split(r"\s+and\s+", prereq_text, flags=re.IGNORECASE):
        part = part.strip().rstrip(".")
        for m in DEP_MACRO_RE.finditer(part):
            deps.append({"ref": m.group(1), "value": m.group(2)})
        if not DEP_MACRO_RE.search(part) and part:
            # unresolved fragment kept as note via todo in overlay
            pass
    return deps


def parse_required_by(text: str) -> list[str]:
    if not text.strip():
        return []
    items = re.split(r",|\band\b", text)
    refs: list[str] = []
    for item in items:
        item = item.strip().rstrip(".")
        if not item:
            continue
        for m in DEP_MACRO_RE.finditer(item):
            refs.append(m.group(1))
        # free-text references (certificates, TLS stacks) — not macro IDs
    return refs


def parse_config_header(path: Path) -> tuple[dict[str, Setting], list[str]]:
    lines = read_text(path).splitlines()
    settings: dict[str, Setting] = {}
    profiles: list[str] = []

    in_defaults = False
    past_defaults = False
    in_profile_block = False
    comment_buf: list[str] = []
    current_profile: str | None = None
    ifndef_depth = 0
    profile_if_depth = 0

    def add_setting(
        macro_id: str,
        raw_val: str,
        desc: str,
        prereq_text: str,
        required_by_text: str,
        line_no: int,
    ) -> None:
        if macro_id not in settings:
            settings[macro_id] = Setting(
                id=macro_id,
                value=raw_val,
                description=desc,
                prereq_text=prereq_text,
                required_by_text=required_by_text,
                line=line_no,
                in_ifndef=ifndef_depth > 0,
            )

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        if DEFAULTS_SECTION_END_MARKER in line:
            past_defaults = True
            current_profile = None
            in_profile_block = False

        pm = PROFILE_BLOCK_START.match(stripped)
        if pm:
            current_profile = f"NOXTLS_PROFILE_{pm.group(1)}"
            in_profile_block = True
            profile_if_depth = 1
            if current_profile not in profiles:
                profiles.append(current_profile)
            continue

        if stripped.startswith("#if defined(NOXTLS_PROFILE_"):
            in_profile_block = True
            profile_if_depth += 1
            continue

        if stripped.startswith("#endif"):
            if profile_if_depth > 0:
                profile_if_depth -= 1
                if profile_if_depth == 0:
                    in_profile_block = False
                    current_profile = None
            ifndef_depth = max(0, ifndef_depth - 1)
            continue

        if stripped.startswith("/*") or stripped.startswith("*"):
            if "====" in stripped:
                comment_buf.clear()
                continue
            text = stripped.lstrip("/*").rstrip("*/").strip()
            if text and not text.startswith("="):
                comment_buf.append(text)
            continue

        if stripped.startswith("#ifndef "):
            ifndef_depth += 1
            continue

        if not in_defaults and "Feature Configuration (defaults)" in line:
            in_defaults = True
            continue

        dm = DEFINE_RE.match(stripped)
        if dm:
            macro_id, raw_val = dm.group(1), normalize_value(dm.group(2))
            if not macro_id.startswith("NOXTLS_"):
                comment_buf.clear()
                continue

            desc = " ".join(comment_buf).strip()
            prereq_m = PREREQ_RE.search(desc)
            req_m = REQUIRED_BY_RE.search(desc)
            prereq_text = prereq_m.group(1).strip() if prereq_m else ""
            required_by_text = req_m.group(1).strip() if req_m else ""

            if in_profile_block and current_profile:
                if macro_id in settings:
                    settings[macro_id].profile_overrides[current_profile] = raw_val
                comment_buf.clear()
                continue

            # Post-profile tunables (memory, TLS limits, RSA, ECC, etc.)
            if past_defaults and not in_profile_block:
                add_setting(
                    macro_id, raw_val, desc, prereq_text, required_by_text, i
                )
                comment_buf.clear()
                continue

            if past_defaults:
                comment_buf.clear()
                continue

            add_setting(
                macro_id, raw_val, desc, prereq_text, required_by_text, i
            )
            comment_buf.clear()
            continue

        if stripped.startswith("#") and not stripped.startswith("#define"):
            if not stripped.startswith("#if"):
                comment_buf.clear()

    # Side-channel default profile is defined without value in some cases — capture profiles
    for ln in lines:
        m = re.match(r"^#define\s+(NOXTLS_SIDECHANNEL_PROFILE_\w+)\s+1$", ln.strip())
        if m and m.group(1) not in settings:
            mid = m.group(1)
            settings[mid] = Setting(
                id=mid,
                value="1",
                description="Mutually exclusive side-channel profile selector.",
                type="profile",
                category="sidechannel",
            )

    profile_names = [
        "NOXTLS_PROFILE_MINIMAL_TLS_CLIENT",
        "NOXTLS_PROFILE_TLS_SERVER_PKI",
        "NOXTLS_PROFILE_CRYPTO_ONLY",
        "NOXTLS_PROFILE_FIPS_LIKE",
        "NOXTLS_PROFILE_UT_ALL_FEATURES",
    ]
    for p in profile_names:
        if p not in settings:
            settings[p] = Setting(
                id=p,
                value="undefined",
                description="Build profile preset; define at most one.",
                type="profile",
                category="profiles",
            )

    sidechannel_profiles = [
        "NOXTLS_SIDECHANNEL_PROFILE_PERFORMANCE",
        "NOXTLS_SIDECHANNEL_PROFILE_BALANCED",
        "NOXTLS_SIDECHANNEL_PROFILE_CONSTANT_TIME_STRICT",
    ]
    for p in sidechannel_profiles:
        if p not in settings:
            settings[p] = Setting(
                id=p,
                value="undefined",
                description="Side-channel profile preset; define at most one.",
                type="profile",
                category="sidechannel",
            )

    return settings, profiles


def load_overrides(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"settings": {}, "categories": {}, "constraints": {}}
    data = json.loads(read_text(path))
    return data


def apply_overrides(settings: dict[str, Setting], overrides: dict[str, Any]) -> None:
    for macro_id, s in settings.items():
        s.name = friendly_name(macro_id)
        s.category = infer_category(macro_id)
        s.parent = infer_parent(macro_id)
        s.type = infer_type(macro_id, s.value)
        s.legacy = bool(LEGACY_NOTE_RE.search(s.description))
        s.dependencies_all = parse_dependencies(s.prereq_text)
        s.required_by = parse_required_by(s.required_by_text)

    for macro_id, o in overrides.get("settings", {}).items():
        if macro_id not in settings:
            settings[macro_id] = Setting(id=macro_id, value=o.get("default", "0"))
        s = settings[macro_id]
        for key in ("name", "category", "parent", "legacy", "type", "description"):
            if key in o:
                setattr(s, key, o[key])
        if "dependencies_all" in o:
            s.dependencies_all = o["dependencies_all"]
        if "dependencies_any" in o:
            s.dependencies_any = o["dependencies_any"]
        if "constraints" in o:
            s.constraints = o["constraints"]
        if "required_by" in o:
            s.required_by = o["required_by"]
        if "todos" in o:
            s.todos = o["todos"]
        if "default" in o:
            s.value = str(o["default"])
        if "profile_overrides" in o:
            s.profile_overrides.update(
                {k: str(v) for k, v in o["profile_overrides"].items()}
            )

    # global constraints keyed by macro
    for macro_id, constraint_list in overrides.get("constraints", {}).items():
        if macro_id in settings:
            settings[macro_id].constraints.extend(constraint_list)


def indent(elem: ET.Element, level: int = 0) -> None:
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        for child in elem:
            indent(child, level + 1)
        if not child.tail or not child.tail.strip():  # noqa: F821 — child from loop
            child.tail = i
    if level and (not elem.tail or not elem.tail.strip()):
        elem.tail = i


def add_text(parent: ET.Element, tag: str, text: str) -> ET.Element:
    el = ET.SubElement(parent, tag)
    el.text = text
    return el


def build_xml(
    version: str, settings: dict[str, Setting], profiles: list[str], overrides: dict
) -> ET.ElementTree:
    root = ET.Element("noxtls-config-catalog")
    root.set("version", version)

    meta = ET.SubElement(root, "metadata")
    add_text(meta, "noxtls-version", version)
    add_text(meta, "source-header", "noxtls/noxtls_config.h")
    add_text(meta, "version-header", "noxtls/noxtls_version.h")
    add_text(
        meta,
        "generated-at",
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    add_text(
        meta,
        "generator",
        "noxtls/tools/config_catalog/generate_config_catalog.py",
    )

    prof_el = ET.SubElement(root, "profiles")
    profile_meta = overrides.get("profiles", {})
    for pid in sorted(profiles):
        p = ET.SubElement(prof_el, "profile")
        p.set("id", pid)
        info = profile_meta.get(pid, {})
        p.set("name", info.get("name", friendly_name(pid)))
        if info.get("description"):
            add_text(p, "description", info["description"])

    # Global parent/child map (supports cross-category suboptions)
    child_by_parent: dict[str, list[Setting]] = {}
    for s in settings.values():
        if s.parent:
            child_by_parent.setdefault(s.parent, []).append(s)

    by_cat: dict[str, list[Setting]] = {}
    for s in settings.values():
        by_cat.setdefault(s.category, []).append(s)

    cats_el = ET.SubElement(root, "categories")
    cat_order = overrides.get("category_order", [])
    all_cats = sorted(by_cat.keys(), key=lambda c: (cat_order.index(c) if c in cat_order else 999, c))

    category_names = overrides.get("categories", {})

    def append_setting(parent: ET.Element, s: Setting) -> None:
        st = ET.SubElement(parent, "setting")
        st.set("id", s.id)
        st.set("name", s.name or friendly_name(s.id))
        st.set("type", s.type)
        st.set("default", default_enabled(s.value) if s.type == "boolean" else s.value)
        if s.type == "boolean":
            st.set("default-value", "1" if s.value.strip() == "1" else "0")
        st.set("legacy", "true" if s.legacy else "false")
        if s.line:
            st.set("source-line", str(s.line))

        if s.description:
            add_text(st, "description", s.description)

        if s.dependencies_all or s.dependencies_any:
            deps = ET.SubElement(st, "dependencies")
            if s.dependencies_all:
                allof = ET.SubElement(deps, "allOf")
                for d in s.dependencies_all:
                    dep = ET.SubElement(allof, "dependency")
                    dep.set("ref", d["ref"])
                    dep.set("value", d.get("value", "1"))
            if s.dependencies_any:
                anyof = ET.SubElement(deps, "anyOf")
                for d in s.dependencies_any:
                    dep = ET.SubElement(anyof, "dependency")
                    dep.set("ref", d["ref"])
                    dep.set("value", d.get("value", "1"))

        if s.constraints:
            cons = ET.SubElement(st, "constraints")
            for c in s.constraints:
                ce = ET.SubElement(cons, "constraint")
                ce.set("kind", c.get("kind", "custom"))
                if c.get("description"):
                    add_text(ce, "description", c["description"])
                if c.get("refs"):
                    refs_el = ET.SubElement(ce, "refs")
                    for ref in c["refs"]:
                        r = ET.SubElement(refs_el, "ref")
                        r.text = ref

        if s.required_by:
            rb = ET.SubElement(st, "required-by")
            for ref in s.required_by:
                r = ET.SubElement(rb, "ref")
                r.text = ref

        if s.profile_overrides:
            po = ET.SubElement(st, "profile-overrides")
            for prof_id in sorted(s.profile_overrides.keys()):
                ov = ET.SubElement(po, "override")
                ov.set("profile", prof_id)
                val = s.profile_overrides[prof_id]
                ov.set(
                    "value",
                    default_enabled(val) if is_boolean_value(val) else val,
                )
                if is_boolean_value(val):
                    ov.set("default-value", val)

        if s.todos:
            todos_el = ET.SubElement(st, "todos")
            for t in s.todos:
                add_text(todos_el, "todo", t)

        children = sorted(child_by_parent.get(s.id, []), key=lambda x: x.id)
        if children:
            sub = ET.SubElement(st, "suboptions")
            for ch in children:
                append_setting(sub, ch)

    for cat_id in all_cats:
        cat_settings = sorted(by_cat[cat_id], key=lambda s: s.id)
        cat_elem = ET.SubElement(cats_el, "category")
        cat_elem.set("id", cat_id)
        cat_elem.set("name", category_names.get(cat_id, cat_id.replace("-", " ").title()))

        top_level = [
            s
            for s in cat_settings
            if not s.parent or s.parent not in settings
        ]
        for s in top_level:
            append_setting(cat_elem, s)

    indent(root)
    return ET.ElementTree(root)


def write_xml(tree: ET.ElementTree, path: Path) -> None:
    xml_bytes = ET.tostring(tree.getroot(), encoding="utf-8", xml_declaration=True)
    # Pretty-print via minidom for stable output
    try:
        import xml.dom.minidom as minidom

        parsed = minidom.parseString(xml_bytes)
        pretty = parsed.toprettyxml(indent="  ", encoding="utf-8")
        # drop extra blank line after declaration
        lines = pretty.decode("utf-8").splitlines()
        out_lines = [lines[0]]
        for ln in lines[1:]:
            if ln.strip():
                out_lines.append(ln)
        path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    except Exception:
        path.write_bytes(xml_bytes)


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def collect_setting_ids(tree: ET.ElementTree) -> set[str]:
    ids: set[str] = set()
    for el in tree.getroot().iter():
        if _local_tag(el.tag) in ("setting", "profile"):
            sid = el.get("id", "")
            if sid:
                ids.add(sid)
    return ids


def validate(
    settings: dict[str, Setting],
    tree: ET.ElementTree,
    version: str,
    xml_path: Path,
) -> list[str]:
    errors: list[str] = []
    xml_ids = collect_setting_ids(tree)
    header_ids = set(settings.keys())

    missing = header_ids - xml_ids
    if missing:
        errors.append(f"Settings missing from XML: {sorted(missing)}")

    root_ver = tree.getroot().get("version", "")
    if root_ver != version:
        errors.append(
            f"XML version '{root_ver}' does not match noxtls_version.h '{version}'"
        )

    known = xml_ids | header_ids
    for el in tree.getroot().iter("dependency"):
        ref = el.get("ref", "")
        if ref and ref not in known:
            errors.append(f"Unknown dependency ref: {ref}")

    if xml_path.is_file():
        on_disk = ET.parse(xml_path)
        disk_ver = on_disk.getroot().get("version", "")
        if disk_ver != version and xml_path == OUTPUT_XML:
            pass  # will be rewritten

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate catalog against headers without writing",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_XML,
        help="Output XML path",
    )
    args = parser.parse_args()

    if not CONFIG_H.is_file():
        print(f"Missing {CONFIG_H}", file=sys.stderr)
        return 1

    version = parse_version(VERSION_H)
    settings, profiles = parse_config_header(CONFIG_H)
    overrides = load_overrides(OVERRIDES_JSON)
    apply_overrides(settings, overrides)

    tree = build_xml(version, settings, profiles, overrides)
    errors = validate(settings, tree, version, args.output)

    if args.check:
        if not args.output.is_file():
            errors.append(f"Catalog file not found: {args.output}")
        else:
            disk = ET.parse(args.output)
            disk_ids = collect_setting_ids(disk)
            header_ids = set(settings.keys())
            extra = disk_ids - header_ids
            missing = header_ids - disk_ids
            if missing:
                errors.append(f"On-disk XML missing settings: {sorted(missing)}")
            if extra:
                errors.append(f"On-disk XML has unknown ids: {sorted(extra)}")
            if disk.getroot().get("version") != version:
                errors.append("On-disk XML version mismatch")

        if errors:
            for e in errors:
                print(f"ERROR: {e}", file=sys.stderr)
            return 1
        print("OK: catalog is synchronized with noxtls_config.h")
        return 0

    if errors:
        for e in errors:
            print(f"WARNING: {e}", file=sys.stderr)

    write_xml(tree, args.output)
    print(f"Wrote {args.output} ({len(settings)} settings, version {version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
