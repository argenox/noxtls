#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
from pathlib import Path


SECTION_RE = re.compile(
    r"^\s*\d+\s+(\S+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+[0-9A-Fa-f]+\s+2\*\*[0-9]+"
)


def parse_sections(elf_path: Path, objdump_cmd: str):
    cmd = [objdump_cmd, "-h", str(elf_path)]
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    lines = proc.stdout.splitlines()

    sections = []
    for index, line in enumerate(lines):
        match = SECTION_RE.match(line)
        if not match:
            continue

        name = match.group(1)
        size = int(match.group(2), 16)
        vma = int(match.group(3), 16)
        lma = int(match.group(4), 16)
        flags = ""
        if index + 1 < len(lines):
            flags = lines[index + 1].strip()

        sections.append(
            {
                "name": name,
                "size": size,
                "vma": vma,
                "lma": lma,
                "flags": flags,
            }
        )

    return sections


def in_range(addr: int, base: int, size: int):
    return base <= addr < (base + size)


def summarize(sections, flash_base, flash_size, ram_base, ram_size):
    flash_used = 0
    ram_used = 0
    section_rows = []

    for section in sections:
        if section["size"] == 0:
            continue
        if "ALLOC" not in section["flags"]:
            continue

        location = "other"
        if in_range(section["lma"], flash_base, flash_size):
            flash_used += section["size"]
            location = "flash"
        if in_range(section["vma"], ram_base, ram_size):
            ram_used += section["size"]
            if location == "flash":
                location = "flash+ram"
            else:
                location = "ram"

        section_rows.append(
            {
                "name": section["name"],
                "size": section["size"],
                "location": location,
                "vma": section["vma"],
                "lma": section["lma"],
            }
        )

    section_rows.sort(key=lambda row: row["size"], reverse=True)
    return flash_used, ram_used, section_rows


def pct(used: int, total: int):
    if total <= 0:
        return 0.0
    return (used * 100.0) / total


def to_markdown(target, profile, opt_level, elf_name, flash_used, flash_total, ram_used, ram_total, rows):
    lines = []
    lines.append(f"## NoxTLS Size Report: {target} ({profile}, {opt_level})")
    lines.append("")
    lines.append(f"- ELF: `{elf_name}`")
    lines.append(f"- Flash: **{flash_used} / {flash_total} bytes** ({pct(flash_used, flash_total):.2f}%)")
    lines.append(f"- RAM: **{ram_used} / {ram_total} bytes** ({pct(ram_used, ram_total):.2f}%)")
    lines.append("")
    lines.append("| Section | Bytes | Placement |")
    lines.append("| --- | ---: | --- |")

    for row in rows[:20]:
        lines.append(f"| `{row['name']}` | {row['size']} | {row['location']} |")

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Generate flash/RAM size report for NoxTLS benchmark ELF.")
    parser.add_argument("--elf", required=True)
    parser.add_argument("--objdump", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--opt-level", required=False, default="O3")
    parser.add_argument("--flash-base", required=True, type=lambda x: int(x, 0))
    parser.add_argument("--flash-size", required=True, type=lambda x: int(x, 0))
    parser.add_argument("--ram-base", required=True, type=lambda x: int(x, 0))
    parser.add_argument("--ram-size", required=True, type=lambda x: int(x, 0))
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-md", required=True)
    args = parser.parse_args()

    elf_path = Path(args.elf)
    sections = parse_sections(elf_path, args.objdump)
    flash_used, ram_used, rows = summarize(
        sections,
        args.flash_base,
        args.flash_size,
        args.ram_base,
        args.ram_size,
    )

    payload = {
        "target": args.target,
        "profile": args.profile,
        "opt_level": args.opt_level,
        "elf": str(elf_path),
        "flash": {
            "used_bytes": flash_used,
            "total_bytes": args.flash_size,
            "utilization_percent": round(pct(flash_used, args.flash_size), 4),
        },
        "ram": {
            "used_bytes": ram_used,
            "total_bytes": args.ram_size,
            "utilization_percent": round(pct(ram_used, args.ram_size), 4),
        },
        "sections": rows,
    }

    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    out_md.write_text(
        to_markdown(
            args.target,
            args.profile,
            args.opt_level,
            elf_path.name,
            flash_used,
            args.flash_size,
            ram_used,
            args.ram_size,
            rows,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
