#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
"""Prove that a NOXTLS_CONFIG_STATIC_MEMORY build cannot reach the C heap.

Runs nm on every NoxTLS static library of the build and fails if any object
has an undefined reference to a C library allocator. With static memory the
NOXTLS_MALLOC/CALLOC/REALLOC macros resolve to the region allocator, so no
object may import malloc, calloc, realloc, free or their relatives.

Usage:
  check_static_memory_symbols.py --nm NM LIB [LIB ...]
  check_static_memory_symbols.py --self-test
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys

FORBIDDEN = {
    'malloc', 'calloc', 'realloc', 'free', 'reallocarray', 'aligned_alloc',
    'posix_memalign', 'memalign', 'valloc', 'pvalloc', 'strdup', 'strndup',
    '_aligned_malloc', '_aligned_free', '_strdup', '_malloca', '_freea',
}
# nm prints "   U symbol" (optionally with a leading underscore or __imp_ prefix).
UNDEFINED = re.compile(r'^\s*U\s+(?:__imp_)?_?([A-Za-z_][A-Za-z0-9_]*)\s*$')


def forbidden_references(nm_output: str) -> list[str]:
    """Return the forbidden allocator names referenced in nm output."""
    found = []
    member = '?'
    for line in nm_output.splitlines():
        if line.endswith(':') and not line.startswith(' '):
            member = line[:-1]
            continue
        match = UNDEFINED.match(line)
        if match and match.group(1) in FORBIDDEN:
            found.append(f'{member}: {match.group(1)}')
    return found


def self_test() -> int:
    sample = ('noxtls_memory.c.obj:\n                 U calloc\n                 U noxtls_secure_zero\n'
              'x.obj:\n                 U __imp_malloc\n00000000 T noxtls_malloc\n')
    assert forbidden_references(sample) == ['noxtls_memory.c.obj: calloc', 'x.obj: malloc']
    assert forbidden_references('a.obj:\n                 U noxtls_free\n') == []
    print('static memory symbol checker self-test: PASS')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--nm', help='nm executable')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('libs', nargs='*')
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.nm or not args.libs:
        parser.error('--nm and at least one library are required')
    failures = []
    for lib in args.libs:
        result = subprocess.run([args.nm, lib], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f'{lib}: nm failed: {result.stderr.strip()}', file=sys.stderr)
            return 1
        failures.extend(f'{lib}: {ref}' for ref in forbidden_references(result.stdout))
    if failures:
        print('C heap references in a static-memory build:', file=sys.stderr)
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'Static memory: no C heap references in {len(args.libs)} libraries: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
