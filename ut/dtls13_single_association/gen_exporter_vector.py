#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
"""Independent TLS-Exporter vectors for dtls13_single_association_test.c (sa_exporter_vector).

RFC 8446 Section 7.5 with the HKDF-Expand-Label of RFC 8446 Section 7.1. DTLS 1.3 uses
the label prefix "dtls13" (no trailing space, RFC 9147 Section 5.9); TLS 1.3 uses "tls13 ".
Only the Python standard library (hmac, hashlib) is used, not NoxTLS.
"""
import hashlib
import hmac


def hkdf_expand(prk, info, length):
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def expand_label(prefix, secret, label, context, length):
    full = prefix + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length)


def exporter(prefix, ems, label, context, length):
    derived = expand_label(prefix, ems, label, hashlib.sha256(b"").digest(), 32)
    return expand_label(prefix, derived, b"exporter", hashlib.sha256(context).digest(), length)


def c_array(data):
    return ", ".join("0x%02XU" % b for b in data)


if __name__ == "__main__":
    ems = bytes(range(0x40, 0x60))                       # exporter_master_secret (32 bytes)
    label = b"EXPORTER-NoxMux-elevate-v1"
    # node_uuid(16) || association_serial(8) || counter(4) || scopes(4)
    context = bytes(range(16)) + (0x0102030405060708).to_bytes(8, "big") + (1).to_bytes(4, "big") + (0x0F).to_bytes(4, "big")
    print("dtls13:", c_array(exporter(b"dtls13", ems, label, context, 32)))
    print("tls13 :", c_array(exporter(b"tls13 ", ems, label, context, 32)))
