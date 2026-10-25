#!/usr/bin/env python3
"""Generate the RSA prime-search wheel table used by noxtls-lib/pkc/rsa/noxtls_rsa.c.

The wheel modulo 2310 = 2 * 3 * 5 * 7 * 11 skips every candidate divisible by one of
those primes. Its residues are the 480 values r in [1, 2310) coprime to 2310; the table
holds the gaps between consecutive residues (the last gap wraps to 1 + 2310), starting
at residue 1, so residue i = 1 + sum(gaps[0:i]). Every gap fits in one byte.

This replaces the two 480-entry uint16_t RAM tables that rsa_wheel_init() used to build
at run time (1920 B of .bss) with a 480-byte const table in flash.

Usage: python scripts/gen_rsa_wheel_tables.py  > (paste the printed array into noxtls_rsa.c)
       python scripts/gen_rsa_wheel_tables.py --check noxtls-lib/pkc/rsa/noxtls_rsa.c
"""
import re
import sys

WHEEL = 2 * 3 * 5 * 7 * 11


def wheel_residues():
    return [r for r in range(1, WHEEL)
            if r % 2 and r % 3 and r % 5 and r % 7 and r % 11]


def wheel_gaps():
    res = wheel_residues()
    gaps = [res[i + 1] - res[i] for i in range(len(res) - 1)]
    gaps.append(res[0] + WHEEL - res[-1])
    return gaps


def c_table(gaps):
    lines = []
    for i in range(0, len(gaps), 20):
        lines.append("    " + ", ".join("%2uU" % g for g in gaps[i:i + 20]) + ",")
    lines[-1] = lines[-1].rstrip(",")
    return "\n".join(lines)


def main():
    gaps = wheel_gaps()
    assert len(gaps) == 480 and max(gaps) < 256 and sum(gaps) == WHEEL
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        src = open(sys.argv[2], encoding="utf-8").read()
        m = re.search(r"s_rsa_wheel_gaps\[RSA_WHEEL_COUNT\]\s*=\s*\{([^}]*)\}", src)
        if m is None:
            print("table not found")
            return 1
        found = [int(v.strip().rstrip("U")) for v in m.group(1).split(",") if v.strip()]
        if found != gaps:
            print("MISMATCH: table in %s differs from the generated one" % sys.argv[2])
            return 1
        print("OK: %d gaps match" % len(found))
        return 0
    print(c_table(gaps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
