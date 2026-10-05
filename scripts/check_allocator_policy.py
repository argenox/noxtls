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

def violations(source):
    """Recognize only unconditional inclusion of our verified allocator map.

    Conditional headers are not proof that all builds route allocations.
    Any subsequent allocator undef/define invalidates that name, including
    conditional directives: rejecting an uncertain path is conservative.
    """
    comments = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27', re.S)
    clean = comments.sub(lambda m: '\n' * m.group().count('\n')
                         if m.group().startswith(('/', '/*')) else m.group(), source)
    mapped = set()
    depth = 0
    included_map = False
    bad = []
    offset = 0
    states = [(0, frozenset())]
    for line in clean.splitlines(keepends=True):
        directive = re.match(r'^\s*#\s*(\w+)\b(.*)', line)
        if directive:
            op, value = directive.groups()
            if op in ('if', 'ifdef', 'ifndef'):
                depth += 1
            elif op == 'endif':
                depth = max(0, depth - 1)
            elif op == 'include' and re.fullmatch(
                    r'\s*["<](?:common/)?noxtls_memory_compat\.h[">]\s*', value):
                if depth == 0 and not included_map:
                    mapped.update(('malloc', 'calloc', 'realloc', 'free'))
                included_map = True  # The header has an include guard.
            elif op in ('undef', 'define'):
                name = re.match(r'\s*(\w+)', value)
                if name:
                    mapped.discard(name.group(1))
        if frozenset(mapped) != states[-1][1]:
            states.append((offset, frozenset(mapped)))
        offset += len(line)
    # Scan the complete source so whitespace between a name and '(' can
    # include newlines. Mapping state applies at the name's source offset.
    state_index = 0
    for match in tokens.finditer(clean):
        while state_index + 1 < len(states) and states[state_index + 1][0] <= match.start():
            state_index += 1
        call = re.match(r'(malloc|calloc|realloc|free)\s*\(', match.group())
        if call and call.group(1) not in states[state_index][1]:
            bad.append(clean.count('\n', 0, match.start()) + 1)
    return bad

def self_test():
    header = '#include "common/noxtls_memory_compat.h"\n'
    fixtures = [
        ('malloc(8);', True),
        (header + 'malloc(8); free(p);', False),
        ('#if ENABLE_MAP\n' + header + '#endif\nmalloc(8);', True),
        (header + '#undef malloc\nmalloc(8);', True),
        (header + '#define malloc(x) rogue_alloc(x)\nmalloc(8);', True),
        ('/* ' + header + ' */\nmalloc(8);', True),
        (header + '#if OTHER\n#undef malloc\n#endif\nmalloc(8);', True),
        (header + '#undef malloc\n' + header + 'malloc(8);', True),
        ('puts("/* not a comment");\nmalloc(8);', True),
        ('malloc\n(8);', True),
        (header + 'malloc\n(8); free\n(p);', False),
        (header + '#undef malloc\nmalloc\n(8);', True),
        (header + '#define free(x) rogue_free(x)\nfree\n(p);', True),
        ('#if ENABLE_MAP\n' + header + '#endif\ncalloc\n(1, 8);', True),
    ]
    for source, rejected in fixtures:
        if bool(violations(source)) != rejected:
            raise AssertionError(source)
    if violations('/* first\nsecond */\nmalloc\n(8);') != [3]:
        raise AssertionError('split-line diagnostic must point to allocator name')
    if violations('malloc\n(8);\n' + header + 'malloc\n(8);') != [1]:
        raise AssertionError('mapping must apply at the call offset')
    print('Allocator checker negative/positive fixtures: PASS')

if '--self-test' in sys.argv:
    self_test()
    sys.exit(0)

# Do not trust a similarly named header unless its actual mapping is intact.
mapping = (root / 'noxtls-lib/common/noxtls_memory_compat.h').read_text(encoding='utf-8')
for name in ('malloc', 'calloc', 'realloc', 'free'):
    if not re.search(r'^#define\s+' + name + r'\([^\n]+\)\s+noxtls_' + name + r'\(', mapping, re.M):
        sys.exit('Allocator mapping changed: ' + name)
failures = []
for path in sorted((root / 'noxtls-lib').rglob('*.c')):
    if path in allowed:
        continue
    source = path.read_text(encoding='utf-8')
    for line in violations(source):
        failures.append(f'{path.relative_to(root)}:{line}: unmapped allocator call')
if failures:
    print('\n'.join(failures), file=sys.stderr)
    sys.exit(1)
print('Allocator policy: PASS')
