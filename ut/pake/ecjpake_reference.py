#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# Copyright (c) [2019] - [2026], Argenox Technologies LLC
"""Independent EC-JPAKE reference model and test-vector generator.

Pure-Python P-256 arithmetic plus hashlib, written from the specification
text only and sharing no code with the C implementation:

- RFC 8236 section 3.2 (EC J-PAKE rounds and key computation),
- RFC 8235 section 3.2 (Schnorr NIZK over an elliptic curve),
- draft-cragie-tls-ecjpake-01 sections 7 (wire structures), 8.1 (identities),
  8.2 (ZKP hash with 4-octet length prefixes), 8.3 (password mapping and
  the section 8.3.1 example), 8.5 / 8.6 (round-two generators) and 8.7
  (premaster secret).

No public known-answer vectors exist for the full exchange; this model
produces self-consistent vectors from fixed scalars and checks every ZKP and
the shared premaster on both sides. The C test injects the same scalars
through the internal random-source hook and must reproduce every octet.

Usage:
  python ecjpake_reference.py            # check the model and regenerate the header
  python ecjpake_reference.py --check    # check only; fail if the header is stale
"""
import argparse
import hashlib
import sys
from pathlib import Path

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

ID_CLIENT = b"client"   # draft section 8.1
ID_SERVER = b"server"
CURVE_TYPE_NAMED = 3     # RFC 4492 section 5.4
SECP256R1 = 23           # RFC 4492 section 5.1.1


def on_curve(pt):
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def mul(k, pt):
    result = None
    addend = pt
    k %= N
    while k:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        k >>= 1
    return result


def enc(pt):
    """SEC 1 v2.0 section 2.3.3 uncompressed encoding."""
    return b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def zkp_hash(gen, v_pt, x_pt, ident):
    """draft section 8.2: SHA-256 over 4-octet length-prefixed items, then mod n."""
    data = b""
    for item in (enc(gen), enc(v_pt), enc(x_pt), ident):
        data += len(item).to_bytes(4, "big") + item
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % N


def prove(gen, x, v, ident):
    """RFC 8235 section 3.2: V = gen*v, r = v - x*h mod n."""
    x_pt = mul(x, gen)
    v_pt = mul(v, gen)
    h = zkp_hash(gen, v_pt, x_pt, ident)
    return x_pt, v_pt, (v - x * h) % N


def verify(gen, x_pt, v_pt, r, ident):
    assert x_pt is not None and on_curve(x_pt)
    assert v_pt is not None and on_curve(v_pt)
    h = zkp_hash(gen, v_pt, x_pt, ident)
    return add(mul(r, gen), mul(h, x_pt)) == v_pt


def r_bytes(r):
    """Minimal big-endian encoding, at least one octet (r<1..2^8-1>)."""
    length = max(1, (r.bit_length() + 7) // 8)
    return r.to_bytes(length, "big")


def key_kp(x_pt, v_pt, r):
    """draft sections 7.1.1 / 7.1.2: ECPoint X || ECPoint V || opaque r."""
    rb = r_bytes(r)
    return bytes([65]) + enc(x_pt) + bytes([65]) + enc(v_pt) + bytes([len(rb)]) + rb


def scalar(label):
    """Fixed test scalar in [1, n-1] derived from a label (not a spec value)."""
    return (int.from_bytes(hashlib.sha256(b"noxtls-ecjpake-ut-" + label).digest(), "big") % (N - 1)) + 1


def run(password, labels):
    s = int.from_bytes(password, "big") % N   # draft section 8.3
    assert s != 0
    x1, v1, x2, v2 = (scalar(labels + b"x1"), scalar(labels + b"v1"),
                      scalar(labels + b"x2"), scalar(labels + b"v2"))
    x3, v3, x4, v4 = (scalar(labels + b"x3"), scalar(labels + b"v3"),
                      scalar(labels + b"x4"), scalar(labels + b"v4"))
    vs, vc = scalar(labels + b"vs"), scalar(labels + b"vc")

    # Round one (draft 8.4): client X1, X2; server X3, X4, each with a ZKP over G.
    X1, V1, r1 = prove(G, x1, v1, ID_CLIENT)
    X2, V2, r2 = prove(G, x2, v2, ID_CLIENT)
    X3, V3, r3 = prove(G, x3, v3, ID_SERVER)
    X4, V4, r4 = prove(G, x4, v4, ID_SERVER)
    for (xp, vp, rp, ident) in ((X1, V1, r1, ID_CLIENT), (X2, V2, r2, ID_CLIENT),
                                (X3, V3, r3, ID_SERVER), (X4, V4, r4, ID_SERVER)):
        assert verify(G, xp, vp, rp, ident)
    client_r1 = key_kp(X1, V1, r1) + key_kp(X2, V2, r2)
    server_r1 = key_kp(X3, V3, r3) + key_kp(X4, V4, r4)

    # Server round two (draft 8.5): GB = X1 + X2 + X3, xs = x4*s, Xs = GB*xs.
    GB = add(add(X1, X2), X3)
    Xs, Vs, rs = prove(GB, x4 * s % N, vs, ID_SERVER)
    assert verify(GB, Xs, Vs, rs, ID_SERVER)
    server_r2 = bytes([CURVE_TYPE_NAMED, 0, SECP256R1]) + key_kp(Xs, Vs, rs)

    # Client round two (draft 8.6): GA = X1 + X3 + X4, xc = x2*s, Xc = GA*xc.
    GA = add(add(X1, X3), X4)
    Xc, Vc, rc = prove(GA, x2 * s % N, vc, ID_CLIENT)
    assert verify(GA, Xc, Vc, rc, ID_CLIENT)
    client_r2 = key_kp(Xc, Vc, rc)

    # Premaster (draft 8.7): server (Xc - X2*x4*s)*x4, client (Xs - X4*x2*s)*x2.
    k_server = mul(x4, add(Xc, neg(mul(x4 * s % N, X2))))
    k_client = mul(x2, add(Xs, neg(mul(x2 * s % N, X4))))
    assert k_server == k_client and k_client is not None
    pms = hashlib.sha256(k_client[0].to_bytes(32, "big")).digest()

    return {
        "x1": x1, "v1": v1, "x2": x2, "v2": v2,
        "x3": x3, "v3": v3, "x4": x4, "v4": v4,
        "vs": vs, "vc": vc,
        "client_r1": client_r1, "server_r1": server_r1,
        "server_r2": server_r2, "client_r2": client_r2, "pms": pms,
    }


def c_array(name, data):
    lines = [f"static const uint8_t {name}[{len(data)}] = {{"]
    for i in range(0, len(data), 12):
        chunk = ", ".join(f"0x{b:02X}" for b in data[i:i + 12])
        lines.append(f"    {chunk},")
    lines[-1] = lines[-1].rstrip(",")
    lines.append("};")
    return "\n".join(lines)


def render(vec, password):
    out = []
    out.append("/* Generated by ecjpake_reference.py - do not edit. SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial */")
    out.append("/**")
    out.append(" * @file ecjpake_test_vectors.h")
    out.append(" * @brief EC-JPAKE vectors from the independent Python model (fixed scalars; not spec vectors).")
    out.append(" * @ingroup noxtls_ecjpake")
    out.append(" */")
    out.append("#ifndef ECJPAKE_TEST_VECTORS_H_")
    out.append("#define ECJPAKE_TEST_VECTORS_H_")
    out.append("")
    out.append("#include <stdint.h>")
    out.append("")
    out.append("/** @brief Password octets. */")
    out.append(c_array("k_ecj_password", password))
    out.append("")
    out.append("/** @brief Random scalars in draw order: x1, v1, x2, v2, x3, v3, x4, v4, vs, vc. */")
    order = ["x1", "v1", "x2", "v2", "x3", "v3", "x4", "v4", "vs", "vc"]
    data = b"".join(vec[k].to_bytes(32, "big") for k in order)
    out.append(c_array("k_ecj_scalars", data))
    for key, doc in (("client_r1", "Client round one (ClientHello ecjpake_key_kp_pair)."),
                     ("server_r1", "Server round one (ServerHello ecjpake_key_kp_pair)."),
                     ("server_r2", "Server round two (ServerKeyExchange body)."),
                     ("client_r2", "Client round two (ClientKeyExchange body)."),
                     ("pms", "Premaster secret.")):
        out.append("")
        out.append(f"/** @brief {doc} */")
        out.append(c_array(f"k_ecj_{key}", vec[key]))
    out.append("")
    out.append("#endif /* ECJPAKE_TEST_VECTORS_H_ */")
    out.append("")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    # draft-cragie-tls-ecjpake-01 section 8.3.1 example.
    assert int.from_bytes(b"d45yj8e", "big") % N == 0x643435796a3865

    password = b"J01NME"
    good = run(password, b"a")
    text = render(good, password)

    header = Path(__file__).with_name("ecjpake_test_vectors.h")
    if args.check:
        if not header.exists() or header.read_text(encoding="utf-8") != text:
            print("ecjpake_test_vectors.h is stale", file=sys.stderr)
            return 1
        print("ecjpake reference model OK; header up to date")
        return 0

    header.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {header}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
