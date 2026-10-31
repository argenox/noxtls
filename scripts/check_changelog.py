#!/usr/bin/env python3
"""Validate docs/changelog.json against docs/changelog.schema.json.

Also checks what the schema cannot express: releases are newest first with
unique versions, quality-record IDs are unique, and the newest release matches
noxtls_version.h.
"""
import json
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
changelog = json.loads((root / "docs/changelog.json").read_text(encoding="utf-8"))
schema = json.loads((root / "docs/changelog.schema.json").read_text(encoding="utf-8"))
errors = []

try:
    import jsonschema
except ImportError:
    jsonschema = None
if jsonschema is not None:
    validator = jsonschema.Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(changelog), key=lambda e: list(e.path)):
        where = "/".join(str(p) for p in err.path)
        errors.append(f"schema: {where}: {err.message}")
else:
    print("note: jsonschema not installed; running structural checks only")

releases = changelog.get("releases", [])


def version_key(v):
    return tuple(int(x) for x in v.split("."))


versions = [r.get("version", "") for r in releases]
if len(set(versions)) != len(versions):
    errors.append("duplicate versions in releases[]")
valid = [v for v in versions if re.fullmatch(r"\d+\.\d+\.\d+", v)]
if valid != sorted(valid, key=version_key, reverse=True):
    errors.append("releases[] is not ordered newest first")

# From 0.3.15 on, every release carries the quality-record fields used by
# release packaging (noxtls-oem) and an ISO date.
QUALITY_FROM = (0, 3, 15)
QUALITY_FIELDS = ("summary", "anomalies", "resolved", "security", "security_recommendations")
for rel in releases:
    v = rel.get("version", "")
    if re.fullmatch(r"\d+\.\d+\.\d+", v) and version_key(v) >= QUALITY_FROM:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", rel.get("date", "")):
            errors.append(f"{v}: date must be YYYY-MM-DD")
        for field in QUALITY_FIELDS:
            if field not in rel:
                errors.append(f"{v}: missing quality-record field '{field}'")

ids = set()
for rel in releases:
    for field in ("anomalies", "resolved", "security"):
        for item in rel.get(field, []):
            item_id = item.get("id")
            if item_id in ids:
                errors.append(f"{rel.get('version')}: duplicate id {item_id}")
            ids.add(item_id)

header = (root / "noxtls_version.h").read_text(encoding="utf-8")
parts = [re.search(rf"#define\s+NOXTLS_VERSION_{k}\s+(\d+)", header) for k in ("MAJOR", "MINOR", "PATCH")]
if all(parts) and releases:
    lib_version = ".".join(p.group(1) for p in parts)
    if releases[0].get("version") != lib_version:
        errors.append(f"newest changelog release {releases[0].get('version')} != noxtls_version.h {lib_version}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"changelog: PASS ({len(releases)} releases)")
