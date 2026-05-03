#!/usr/bin/env python3
"""Decode RFC 7919 FFDHE PEM and output C arrays for noxtls_ffdhe_params.c"""
import base64

def decode_dh_pem(pem):
    lines = [l for l in pem.splitlines() if l and not l.startswith('-----')]
    der = base64.b64decode(''.join(lines))
    i = 0
    assert der[i] == 0x30
    i += 1
    seq_len = der[i]
    i += 1
    if seq_len & 0x80:
        n = seq_len & 0x7F
        seq_len = 0
        for _ in range(n):
            seq_len = (seq_len << 8) | der[i]
            i += 1
    assert der[i] == 0x02
    i += 1
    plen = der[i]
    i += 1
    if plen & 0x80:
        n = plen & 0x7F
        plen = 0
        for _ in range(n):
            plen = (plen << 8) | der[i]
            i += 1
    if der[i] == 0:
        i += 1
        plen -= 1
    return bytes(der[i:i+plen])

PEMS = {
    2048: """-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----""",
    3072: """-----BEGIN DH PARAMETERS-----
MIIBiAKCAYEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3
7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32
nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZsYu
N///////////AgEC
-----END DH PARAMETERS-----""",
    4096: """-----BEGIN DH PARAMETERS-----
MIICCAKCAgEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3
7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32
nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZp4e
8W5vUsMWTfT7eTDp5OWIV7asfV9C1p9tGHdjzx1VA0AEh/VbpX4xzHpxNciG77Qx
iu1qHgEtnmgyqQdgCpGBMMRtx3j5ca0AOAkpmaMzy4t6Gh25PXFAADwqTs6p+Y0K
zAqCkc3OyX3Pjsm1Wn+IpGtNtahR9EGC4caKAH5eZV9q//////////8CAQI=
-----END DH PARAMETERS-----""",
}

def main():
    with open("noxtls_ffdhe_params.c", "w", encoding="utf-8") as f:
        f.write("""/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_ffdhe_params.c
* Summary: RFC 7919 FFDHE group parameters (p, g=2)
*/

#include <stdint.h>
#include "noxtls_ffdhe_params.h"
#include <string.h>

""")
        for bits, pem in PEMS.items():
            p = decode_dh_pem(pem)
            name = "noxtls_ffdhe%d_p" % bits
            f.write("/* ffdhe%d p: %d bytes, RFC 7919 */\n" % (bits, len(p)))
            f.write("const uint8_t %s[%d] = {\n" % (name, len(p)))
            for j in range(0, len(p), 12):
                chunk = p[j:j+12]
                f.write("    " + ", ".join("0x%02X" % b for b in chunk) + ",\n")
            f.write("};\n\n")
        # Generator g=2 for each group (p_len bytes, last byte 0x02)
        for bits in (2048, 3072, 4096):
            size = {2048: 256, 3072: 384, 4096: 512}[bits]
            name = "noxtls_ffdhe_g_%d" % bits
            g_arr = [0] * size
            g_arr[-1] = 2
            f.write("/* g=2 for ffdhe%d */\n" % bits)
            f.write("const uint8_t %s[%d] = {\n" % (name, size))
            for j in range(0, size, 12):
                chunk = g_arr[j:j+12]
                f.write("    " + ", ".join("0x%02X" % b for b in chunk) + ",\n")
            f.write("};\n\n")
    print("Wrote noxtls_ffdhe_params.c")

if __name__ == "__main__":
    main()
