#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
"""Print the NOXTLS_CONFIG_STATIC_MEMORY footprint of one target configuration.

Compiles noxtls_static_footprint.c with the given compiler and flags (host or
cross), extracts the constant table from the object with objdump and prints the
per-profile block, steady and released sizes. A Zephyr prj.conf can supply the
feature switches (CONFIG_NOXTLS_FEATURE_*=y/n, CONFIG_NOXTLS_TLS_MAX_RECORD_SIZE).

Example (CC1354 node, Cortex-M4F):
  static_memory_footprint.py --cc arm-none-eabi-gcc --objdump arm-none-eabi-objdump \\
      --cflags "-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -Os" \\
      --profile profiles/static_memory/noxtls_static_profile_node.h \\
      --kconfig path/to/prj.conf
"""
from __future__ import annotations

import argparse
import re
import shlex
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent / 'noxtls_static_footprint.c'
INCLUDES = ['', 'utility', 'noxtls-lib', 'noxtls-lib/common', 'noxtls-lib/mdigest', 'noxtls-lib/mdigest/sha256',
            'noxtls-lib/mdigest/sha512', 'noxtls-lib/mdigest/sha3', 'noxtls-lib/mac', 'noxtls-lib/kdf',
            'noxtls-lib/encryption', 'noxtls-lib/certs', 'noxtls-lib/pkc', 'noxtls-lib/pkc/rsa', 'noxtls-lib/pkc/ecc',
            'noxtls-lib/pkc/ecdsa', 'noxtls-lib/pkc/ecdh', 'noxtls-lib/pkc/mlkem', 'noxtls-lib/pkc/mldsa',
            'noxtls-lib/pkc/slhdsa', 'noxtls-lib/pkc/falcon', 'noxtls-lib/pkc/lms', 'noxtls-lib/pkc/xmss',
            'noxtls-lib/drbg', 'noxtls-lib/pake', 'noxtls-lib/tls']
NAMES = ['magic',
         'TLS13_PSK block', 'TLS13_PSK steady', 'TLS13_PSK released',
         'DTLS13_PSK block', 'DTLS13_PSK steady', 'DTLS13_PSK released',
         'TLS13_CERT block', 'TLS13_CERT steady', 'TLS13_CERT released',
         'DTLS13_CERT block', 'DTLS13_CERT steady', 'DTLS13_CERT released',
         'sizeof(tls13_context_t)', 'sizeof(tls13_hs_state_t)', 'connection header',
         'record TX buffer', 'DTLS record workspace', 'handshake workspace', 'DTLS flight',
         'handshake arena TLS PSK', 'handshake arena DTLS PSK', 'handshake arena TLS cert',
         'steady arena TLS', 'steady arena DTLS', 'global arena', 'trust store',
         'record size', 'pointer size']
KCONFIG = re.compile(r'^CONFIG_(NOXTLS_(?:FEATURE_[A-Z0-9_]+|HAVE_CERT_WRITE|SHA256_UNROLL_8|TLS12_ENABLE_[A-Z0-9_]+))=([yn])\s*$')
KCONFIG_VALUE = re.compile(r'^CONFIG_(NOXTLS_TLS_MAX_RECORD_SIZE)=(\d+)\s*$')


def kconfig_defines(path: Path) -> list[str]:
    """Translate the NoxTLS switches of a Zephyr prj.conf into -D flags."""
    defines = []
    for line in path.read_text(encoding='utf-8').splitlines():
        match = KCONFIG.match(line)
        if match:
            defines.append(f'-D{match.group(1)}={1 if match.group(2) == "y" else 0}')
            continue
        match = KCONFIG_VALUE.match(line)
        if match:
            defines.append(f'-D{match.group(1)}={match.group(2)}U')
    return defines


def read_table(objdump: str, obj: Path) -> list[int]:
    out = subprocess.run([objdump, '-s', '-j', '.rodata.noxtls_footprint', str(obj)],
                         capture_output=True, text=True, check=True).stdout
    data = bytearray()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r'[0-9a-f]{4,}', parts[0]):
            for word in parts[1:5]:
                if re.fullmatch(r'[0-9a-f]{2,8}', word):
                    data.extend(bytes.fromhex(word))
    values = list(struct.unpack('<%dI' % (len(data) // 4), bytes(data[:len(data) // 4 * 4])))
    if not values or values[0] != 0x4E584650:
        raise SystemExit('footprint table not found (little-endian target expected)')
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--objdump', default='objdump')
    parser.add_argument('--cflags', default='')
    parser.add_argument('--profile', help='static-memory profile header (relative to the repository root)')
    parser.add_argument('--kconfig', type=Path, help='Zephyr prj.conf with CONFIG_NOXTLS_* switches')
    parser.add_argument('-D', dest='defines', action='append', default=[], help='extra preprocessor definition')
    args = parser.parse_args()

    cmd = [args.cc, '-c', '-std=c99'] + shlex.split(args.cflags)
    cmd += ['-I' + str(ROOT / inc) for inc in INCLUDES]
    cmd += ['-DNOXTLS_CONFIG_STATIC_MEMORY=1']
    if args.profile:
        cmd += [f'-DNOXTLS_STATIC_MEMORY_PROFILE="{args.profile}"']
    if args.kconfig:
        cmd += kconfig_defines(args.kconfig)
    cmd += ['-D' + d for d in args.defines]
    with tempfile.TemporaryDirectory() as tmp:
        obj = Path(tmp) / 'footprint.o'
        subprocess.run(cmd + [str(SOURCE), '-o', str(obj)], check=True)
        values = read_table(args.objdump, obj)
    for name, value in zip(NAMES[1:], values[1:]):
        print(f'{name:28s} {value:8d}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
