#!/usr/bin/env python3
"""Aggregate NoxTLS size reports across target/profile matrix."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def collect_reports(input_dir: Path):
    size_files = sorted(input_dir.rglob("*.size.json"))
    map_files = sorted(input_dir.rglob("*.files.json"))
    if not size_files:
        raise SystemExit(f"No *.size.json files found under: {input_dir}")

    size_reports = [load_json(path) for path in size_files]
    map_reports = [load_json(path) for path in map_files]
    return size_reports, map_reports


def _combo_label(profile: str, opt_level: str):
    return f"{profile}@{opt_level}"


def make_profile_target_table(size_reports):
    combos = sorted({_combo_label(item["profile"], item.get("opt_level", "O3")) for item in size_reports})
    targets = sorted({item["target"] for item in size_reports})
    lookup = {}
    for item in size_reports:
        combo = _combo_label(item["profile"], item.get("opt_level", "O3"))
        lookup[(combo, item["target"])] = item
    return combos, targets, lookup


def category_rollup_by_profile_opt(map_reports):
    totals = defaultdict(lambda: defaultdict(int))
    combos = set()
    for report in map_reports:
        combo = _combo_label(report["profile"], report.get("opt_level", "O3"))
        combos.add(combo)
        for cat in report.get("categories", []):
            name = cat["category"]
            totals[name][combo] += int(cat["flash_bytes"])
    categories = sorted(totals.keys())
    return sorted(combos), categories, totals


def to_markdown(size_reports, map_reports):
    combos, targets, lookup = make_profile_target_table(size_reports)

    lines = [
        "## Embedded Size Benchmark Summary",
        "",
        "### Profile totals by optimization level",
        "",
    ]

    header = ["Profile", "Opt"]
    for target in targets:
        header.append(f"{target} Flash (B)")
        header.append(f"{target} RAM (B)")
    lines.append("| " + " | ".join(header) + " |")
    lines.append("| " + " | ".join(["---"] + ["---:"] * (len(header) - 1)) + " |")

    for combo in combos:
        profile, opt_level = combo.split("@", 1)
        row = [profile, opt_level]
        for target in targets:
            item = lookup.get((combo, target))
            if item is None:
                row.extend(["-", "-"])
            else:
                row.append(str(item["flash"]["used_bytes"]))
                row.append(str(item["ram"]["used_bytes"]))
        lines.append("| " + " | ".join(row) + " |")

    if map_reports:
        cat_combos, categories, totals = category_rollup_by_profile_opt(map_reports)
        lines.extend(
            [
                "",
                "### Module rollup (flash bytes, all targets combined)",
                "",
            ]
        )
        cat_header = ["Category"] + cat_combos
        lines.append("| " + " | ".join(cat_header) + " |")
        lines.append("| " + " | ".join(["---"] + ["---:"] * len(cat_combos)) + " |")
        for category in categories:
            row = [category]
            for combo in cat_combos:
                row.append(str(totals[category].get(combo, 0)))
            lines.append("| " + " | ".join(row) + " |")

    lines.append("")
    return "\n".join(lines)


def to_payload(size_reports, map_reports):
    combos, targets, lookup = make_profile_target_table(size_reports)
    rows = []
    for combo in combos:
        profile, opt_level = combo.split("@", 1)
        row = {"profile": profile, "opt_level": opt_level}
        for target in targets:
            item = lookup.get((combo, target))
            if item is None:
                row[target] = None
            else:
                row[target] = {
                    "flash_bytes": int(item["flash"]["used_bytes"]),
                    "ram_bytes": int(item["ram"]["used_bytes"]),
                }
        rows.append(row)

    payload = {
        "profile_opt_levels": combos,
        "targets": targets,
        "matrix": rows,
    }

    if map_reports:
        cat_combos, categories, totals = category_rollup_by_profile_opt(map_reports)
        payload["module_rollup_flash"] = {
            "profile_opt_levels": cat_combos,
            "categories": categories,
            "rows": [
                {
                    "category": category,
                    **{combo: int(totals[category].get(combo, 0)) for combo in cat_combos},
                }
                for category in categories
            ],
        }
    return payload


def main():
    parser = argparse.ArgumentParser(description="Aggregate NoxTLS size benchmark reports.")
    parser.add_argument("--input-dir", required=True, help="Directory containing *.size.json and *.files.json outputs")
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-md", required=True)
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    size_reports, map_reports = collect_reports(input_dir)

    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    payload = to_payload(size_reports, map_reports)
    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    out_md.write_text(to_markdown(size_reports, map_reports), encoding="utf-8")


if __name__ == "__main__":
    main()
