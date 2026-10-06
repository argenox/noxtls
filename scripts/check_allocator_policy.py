#!/usr/bin/env python3
"""Keep host allocation calls inside the library's allocator implementation."""
from pathlib import Path
import re
import sys

root = Path(__file__).resolve().parents[1]
# Match comments and literals first so examples/documentation cannot be calls.
tokens = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|\b(?:malloc|calloc|realloc|free)\s*\(', re.S)
allowed = {root / 'noxtls-lib/common/noxtls_memory.c',
           root / 'noxtls-lib/common/noxtls_memory_stdlib.c'}
failures = []
for path in sorted((root / 'noxtls-lib').rglob('*.c')):
    if path in allowed:
        continue
    source = path.read_text(encoding='utf-8')
    for match in tokens.finditer(source):
        if re.match(r'(malloc|calloc|realloc|free)\s*\(', match.group()):
            line = source.count('\n', 0, match.start()) + 1
            failures.append(f'{path.relative_to(root)}:{line}: raw allocator call')
if failures:
    print('\n'.join(failures), file=sys.stderr)
    sys.exit(1)
print('Allocator policy: PASS')
