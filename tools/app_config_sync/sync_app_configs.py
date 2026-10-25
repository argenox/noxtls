#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
"""Keep applications/*/noxtls_config.h in sync with the top-level noxtls_config.h.

Project policy: application code does not include the top-level config; each
application ships a self-contained copy so it can be tuned and built on its
own. The library archives are built from the top-level config, so every
setting that changes a structure layout (feature switches, size limits, table
modes) must be identical in the application copy. A stale copy compiles
application translation units against different struct layouts than the
library, which is memory-unsafe.

Each application copy is therefore generated: the top-level config with the
application's own block (the "Application-local configuration" comment and
NOXTLS_APP_STATIC_BUFFER_SIZE) inserted right after the include guard.

Usage:
  sync_app_configs.py [--root DIR]          rewrite every application copy
  sync_app_configs.py [--root DIR] --check  exit 1 if any copy is out of date
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

GUARD = "#define NOXTLS_CONFIG_H_\n"
BLOCK_START_RE = re.compile(r"^/\* =+\n \* Application-local configuration for:", re.M)
BLOCK_END_RE = re.compile(
    r"#ifndef NOXTLS_APP_STATIC_BUFFER_SIZE\n#define NOXTLS_APP_STATIC_BUFFER_SIZE [^\n]*\n#endif\n")


def read_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8-sig")
    return text.replace("\r\n", "\n")


def extract_app_block(app_text: str, path: Path) -> str:
    start = BLOCK_START_RE.search(app_text)
    if start is None:
        raise SystemExit(f"{path}: application-local block not found")
    end = BLOCK_END_RE.search(app_text, start.start())
    if end is None:
        raise SystemExit(f"{path}: NOXTLS_APP_STATIC_BUFFER_SIZE block not found")
    return app_text[start.start():end.end()]


def generate(root_text: str, app_block: str) -> str:
    index = root_text.find(GUARD)
    if index < 0:
        raise SystemExit("top-level noxtls_config.h: include guard not found")
    index += len(GUARD)
    return root_text[:index] + "\n" + app_block + root_text[index:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[2]),
                        help="NoxTLS source root (default: this script's repository)")
    parser.add_argument("--check", action="store_true", help="report stale copies, do not write")
    args = parser.parse_args()

    root = Path(args.root)
    root_text = read_text(root / "noxtls_config.h")
    app_configs = sorted((root / "applications").glob("*/noxtls_config.h"))
    if not app_configs:
        raise SystemExit(f"no application configs found under {root / 'applications'}")

    stale = []
    for path in app_configs:
        current = read_text(path)
        wanted = generate(root_text, extract_app_block(current, path))
        if current != wanted or path.read_bytes().startswith(b"\xef\xbb\xbf"):
            stale.append(path)
            if not args.check:
                # Native line endings: git normalizes on commit (core.autocrlf).
                path.write_text(wanted, encoding="utf-8", newline=None)

    if args.check:
        for path in stale:
            print(f"out of date: {path.relative_to(root)}")
        if stale:
            print("run tools/app_config_sync/sync_app_configs.py to regenerate")
            return 1
        print(f"{len(app_configs)} application configs match noxtls_config.h")
        return 0

    print(f"updated {len(stale)} of {len(app_configs)} application configs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
