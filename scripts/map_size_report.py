#!/usr/bin/env python3
"""Aggregate flash/RAM contributions per object file from a GNU ld map file."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path


MAP_MARKER = "Linker script and memory map"

FLASH_SECTIONS = {
    ".text",
    ".rodata",
    ".isr_vector",
    ".ARM.exidx",
    ".ARM.extab",
    ".init",
    ".fini",
    ".data",
}

RAM_SECTIONS = {".data", ".bss"}

SECTION_HEADER_RE = re.compile(
    r"^\.([A-Za-z0-9_.]+)\s+0x[0-9A-Fa-f]+\s+0x[0-9A-Fa-f]+",
)
SECTION_NAME_ONLY_RE = re.compile(r"^\s+(\.[\w.]+)\s*$")
CONTRIBUTION_RE = re.compile(
    r"^\s+(\.[\w.]+)\s+0x[0-9A-Fa-f]+\s+(0x[0-9A-Fa-f]+)\s+(.+)$",
)
CONTRIBUTION_LINE2_RE = re.compile(
    r"^\s+0x[0-9A-Fa-f]+\s+(0x[0-9A-Fa-f]+)\s+(.+)$",
)


def _member_to_source_name(member: str) -> str:
    if member.endswith(".obj"):
        return member[:-4]
    if member.endswith(".o"):
        return member[:-2] + ".c"
    return member


def normalize_object_path(raw_path: str) -> str:
    path = raw_path.strip().replace("\\", "/")
    if "fill*" in path:
        return ""

    if "/libc.a(" in path or path.endswith("libc.a("):
        member = path.split("libc.a(", 1)[-1].rstrip(")")
        return f"toolchain/libc/{_member_to_source_name(member)}"
    if "/libgcc.a(" in path:
        member = path.split("libgcc.a(", 1)[-1].rstrip(")")
        return f"toolchain/libgcc/{_member_to_source_name(member)}"
    if "/libm.a(" in path:
        member = path.split("libm.a(", 1)[-1].rstrip(")")
        return f"toolchain/libm/{_member_to_source_name(member)}"
    if "/libnosys.a(" in path:
        member = path.split("libnosys.a(", 1)[-1].rstrip(")")
        return f"toolchain/libnosys/{_member_to_source_name(member)}"
    if "thumb/v7e-m/nofp/libc/" in path:
        member = path.rsplit("/", 1)[-1]
        return f"toolchain/libc/{_member_to_source_name(member)}"
    if "libgcc.a/" in path or "/libgcc/" in path:
        member = path.rsplit("/", 1)[-1]
        return f"toolchain/libgcc/{_member_to_source_name(member)}"

    marker = ".dir/"
    if marker in path:
        path = path.split(marker, 1)[1]
        return _member_to_source_name(path)

    if ".a(" in path:
        archive, member = path.rsplit("/", 1)[-1].split(".a(", 1)
        member = _member_to_source_name(member.rstrip(")"))
        if "/" in path:
            prefix = path.rsplit("/", 1)[0]
            repo_markers = ("noxtls-lib/", "utility/", "benchmarks/", "scripts/", "noxtls/")
            for marker_path in repo_markers:
                idx = prefix.find(marker_path)
                if idx >= 0:
                    prefix = prefix[idx:]
                    break
            return f"{prefix}/{archive}/{member}"
        return f"{archive}/{member}"

    return _member_to_source_name(path)


def rollup_category(normalized_path: str) -> str:
    if not normalized_path:
        return "other"
    if normalized_path.startswith("benchmarks/"):
        return "benchmark-shim"
    if normalized_path.startswith("utility/"):
        return "noxtls-utility"
    if normalized_path.startswith("noxtls-lib/tls/"):
        return "noxtls-tls"
    if normalized_path.startswith("noxtls-lib/certs/"):
        return "noxtls-certs"
    if normalized_path.startswith("noxtls-lib/pkc/"):
        return "noxtls-pkc"
    if normalized_path.startswith("noxtls-lib/encryption/"):
        return "noxtls-encryption"
    if normalized_path.startswith("noxtls-lib/mdigest/"):
        return "noxtls-hash"
    if normalized_path.startswith("noxtls-lib/mac/"):
        return "noxtls-mac"
    if normalized_path.startswith("noxtls-lib/kdf/"):
        return "noxtls-kdf"
    if normalized_path.startswith("noxtls-lib/drbg/"):
        return "noxtls-drbg"
    if normalized_path.startswith("noxtls-lib/common/"):
        return "noxtls-common"
    if normalized_path.startswith("toolchain/libc/"):
        return "libc"
    if normalized_path.startswith("toolchain/libgcc/"):
        return "libgcc"
    if normalized_path.startswith("toolchain/libm/"):
        return "libm"
    if normalized_path.startswith("toolchain/libnosys/"):
        return "libnosys"
    return "other"


def parse_map_file(map_path: Path):
    lines = map_path.read_text(encoding="utf-8", errors="replace").splitlines()
    try:
        start = lines.index(MAP_MARKER)
    except ValueError as exc:
        raise ValueError(f"Map file missing '{MAP_MARKER}' section: {map_path}") from exc

    pending_section_name = ""
    per_file = defaultdict(lambda: defaultdict(int))

    for line in lines[start + 1 :]:
        if line.startswith("LOAD "):
            continue

        header = SECTION_HEADER_RE.match(line)
        if header:
            pending_section_name = ""
            continue

        if line.strip().startswith("*"):
            continue

        name_only = SECTION_NAME_ONLY_RE.match(line)
        if name_only:
            pending_section_name = name_only.group(1)
            continue

        section_name = ""
        size = 0
        raw_path = ""

        match = CONTRIBUTION_RE.match(line)
        if match:
            section_name = match.group(1)
            size = int(match.group(2), 16)
            raw_path = match.group(3)
            pending_section_name = ""
        else:
            match2 = CONTRIBUTION_LINE2_RE.match(line)
            if match2 and pending_section_name:
                section_name = pending_section_name
                size = int(match2.group(1), 16)
                raw_path = match2.group(2)
                pending_section_name = ""
            else:
                continue

        if size <= 0:
            continue

        normalized = normalize_object_path(raw_path)
        if not normalized:
            continue

        base_section = "." + section_name.lstrip(".").split(".")[0]
        if base_section not in FLASH_SECTIONS and base_section not in RAM_SECTIONS:
            continue

        entry = per_file[normalized]
        if base_section in FLASH_SECTIONS:
            entry["flash"] += size
            if base_section == ".text":
                entry["text"] += size
            elif base_section == ".rodata":
                entry["rodata"] += size
            elif base_section == ".data":
                entry["data_flash"] += size
            else:
                entry["other_flash"] += size

        if base_section in RAM_SECTIONS:
            entry["ram"] += size
            if base_section == ".data":
                entry["data_ram"] += size
            elif base_section == ".bss":
                entry["bss"] += size

    rows = []
    for path, sizes in per_file.items():
        flash = sizes.get("flash", 0)
        ram = sizes.get("ram", 0)
        if flash == 0 and ram == 0:
            continue
        rows.append(
            {
                "file": path,
                "category": rollup_category(path),
                "flash_bytes": flash,
                "ram_bytes": ram,
                "text_bytes": sizes.get("text", 0),
                "rodata_bytes": sizes.get("rodata", 0),
                "data_flash_bytes": sizes.get("data_flash", 0),
                "bss_bytes": sizes.get("bss", 0),
            }
        )

    rows.sort(key=lambda row: (row["flash_bytes"] + row["ram_bytes"]), reverse=True)
    return rows


def summarize_categories(rows):
    totals = defaultdict(lambda: defaultdict(int))
    for row in rows:
        cat = row["category"]
        totals[cat]["flash_bytes"] += row["flash_bytes"]
        totals[cat]["ram_bytes"] += row["ram_bytes"]
        totals[cat]["file_count"] += 1

    summary = [
        {
            "category": cat,
            "flash_bytes": values["flash_bytes"],
            "ram_bytes": values["ram_bytes"],
            "file_count": values["file_count"],
        }
        for cat, values in totals.items()
    ]
    summary.sort(key=lambda item: item["flash_bytes"], reverse=True)
    return summary


def to_markdown(target: str, profile: str, opt_level: str, rows, categories, top_n: int) -> str:
    total_flash = sum(row["flash_bytes"] for row in rows)
    total_ram = sum(row["ram_bytes"] for row in rows)

    lines = [
        f"## Per-File Size Report: {target} ({profile}, {opt_level})",
        "",
        f"- Total flash attributed: **{total_flash}** bytes",
        f"- Total RAM attributed: **{total_ram}** bytes",
        "",
        "### By category",
        "",
        "| Category | Flash (B) | RAM (B) | Files |",
        "| --- | ---: | ---: | ---: |",
    ]

    for item in categories:
        lines.append(
            f"| {item['category']} | {item['flash_bytes']} | {item['ram_bytes']} | {item['file_count']} |"
        )

    lines.extend(
        [
            "",
            f"### Top {top_n} object files (flash + RAM)",
            "",
            "| File | Category | Flash (B) | RAM (B) | text | rodata | bss |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )

    for row in rows[:top_n]:
        lines.append(
            f"| `{row['file']}` | {row['category']} | {row['flash_bytes']} | {row['ram_bytes']} | "
            f"{row['text_bytes']} | {row['rodata_bytes']} | {row['bss_bytes']} |"
        )

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Per-file flash/RAM report from GNU ld map output.")
    parser.add_argument("--map", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--opt-level", required=False, default="O3")
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-md", required=True)
    parser.add_argument("--top", type=int, default=40)
    args = parser.parse_args()

    map_path = Path(args.map)
    rows = parse_map_file(map_path)
    categories = summarize_categories(rows)

    payload = {
        "target": args.target,
        "profile": args.profile,
        "opt_level": args.opt_level,
        "map": str(map_path),
        "totals": {
            "flash_bytes": sum(row["flash_bytes"] for row in rows),
            "ram_bytes": sum(row["ram_bytes"] for row in rows),
            "file_count": len(rows),
        },
        "categories": categories,
        "files": rows,
    }

    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    out_md.write_text(
        to_markdown(args.target, args.profile, args.opt_level, rows, categories, args.top),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
