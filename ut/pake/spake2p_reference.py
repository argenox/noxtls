#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# Copyright (c) [2019] - [2026], Argenox Technologies LLC
"""Independent SPAKE2+ / Matter PASE reference model and test-vector generator.

Pure-Python P-256 arithmetic plus hashlib/hmac; shares no code with the C
implementation. It:

1. checks the transcribed RFC 9383 Appendix C vector set and the
   draft-bar-cfrg-spake2plus-01 vector (used by connectedhomeip) for internal
   consistency (points prove the scalars, the hash chain proves the key
   schedule), and
2. writes spake2p_test_vectors.h for the NoxTLS unit tests.

Usage:
  python spake2p_reference.py            # check and regenerate the header
  python spake2p_reference.py --check    # check only; fail if header is stale
"""
import argparse
import hashlib
import hmac
import struct
import sys
from pathlib import Path

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
# RFC 9383 section 4 (P-256).
M = (0x886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f,
     0x5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20)
N = (0xd8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49,
     0x07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7)


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


def mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


def neg(pt):
    return (pt[0], (-pt[1]) % P)


def enc(pt):
    return b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def be32(v):
    return v.to_bytes(32, "big")


def lp(data):
    return struct.pack("<Q", len(data)) + data


def hkdf(ikm, info, length, salt=b""):
    prk = hmac.new(salt if salt else b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def exchange(ctx, id_p, id_v, w0, w1, x, y):
    """Run both roles; return dict of group values and TT."""
    L = mul(w1, G)
    X = add(mul(x, G), mul(w0, M))
    Y = add(mul(y, G), mul(w0, N))
    Zp = mul(x, add(Y, neg(mul(w0, N))))
    Vp = mul(w1, add(Y, neg(mul(w0, N))))
    Zv = mul(y, add(X, neg(mul(w0, M))))
    Vv = mul(y, L)
    assert Zp == Zv and Vp == Vv
    tt = (lp(ctx) + lp(id_p) + lp(id_v) + lp(enc(M)) + lp(enc(N)) + lp(enc(X)) +
          lp(enc(Y)) + lp(enc(Zp)) + lp(enc(Vp)) + lp(be32(w0)))
    return dict(L=enc(L), X=enc(X), Y=enc(Y), Z=enc(Zp), V=enc(Vp), TT=tt)


def schedule_rfc9383(tt, X, Y):
    k_main = hashlib.sha256(tt).digest()
    kc = hkdf(k_main, b"ConfirmationKeys", 64)
    return dict(digest=k_main, kcp=kc[:32], kcv=kc[32:],
                confirm_p=hmac.new(kc[:32], Y, hashlib.sha256).digest(),
                confirm_v=hmac.new(kc[32:], X, hashlib.sha256).digest(),
                shared=hkdf(k_main, b"SharedKey", 32))


def schedule_matter(tt, X, Y):
    kae = hashlib.sha256(tt).digest()
    kc = hkdf(kae[:16], b"ConfirmationKeys", 32)
    return dict(digest=kae, kcp=kc[:16], kcv=kc[16:],
                confirm_p=hmac.new(kc[:16], Y, hashlib.sha256).digest(),
                confirm_v=hmac.new(kc[16:], X, hashlib.sha256).digest(),
                shared=kae[16:])


def expect(name, got, want_hex, failures):
    if got != bytes.fromhex(want_hex):
        failures.append("%s: computed %s, transcribed %s" % (name, got.hex(), want_hex))


RFC = dict(
    ctx=b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors", idp=b"client", idv=b"server",
    w0=0xbb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3,
    w1=0x7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba,
    x=0xd1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539,
    y=0x717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3)

# Transcribed RFC 9383 Appendix C outputs (checked against the model).
RFC_EXPECTED = dict(
    L="04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc00f00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd",
    X="04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727",
    Y="04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048",
    Z="04bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d50091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c41839",
    V="0458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b68",
    digest="4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29",
    kcp="871ae3f7b78445e34438fb284504240239031c39d80ac23eb5ab9be5ad6db58a",
    kcv="ccd53c7c1fa37b64a462b40db8be101cedcf838950162902054e644b400f1680",
    confirm_p="926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527",
    confirm_v="9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68",
    shared="0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7")

D01 = dict(
    ctx=b"SPAKE2+-P256-SHA256-HKDF draft-01", idp=b"client", idv=b"server",
    w0=0xe6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c,
    w1=0x24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512,
    x=0x8b0f3f383905cf3a3bb955ef8fb62e24849dd349a05ca79aafb18041d30cbdb6,
    y=0x2e0895b0e763d6d5a9564433e64ac3cac74ff897f6c3445247ba1bab40082a91)

# Transcribed draft-bar-cfrg-spake2plus-01 outputs (as used by connectedhomeip).
D01_EXPECTED = dict(
    L="0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9",
    X="04af09987a593d3bac8694b123839422c3cc87e37d6b41c1d630f000dd64980e537ae704bcede04ea3bec9b7475b32fa2ca3b684be14d11645e38ea6609eb39e7e",
    Y="04417592620aebf9fd203616bbb9f121b730c258b286f890c5f19fea833a9c900cbe9057bc549a3e19975be9927f0e7614f08d1f0a108eede5fd7eb5624584a4f4",
    Z="0471a35282d2026f36bf3ceb38fcf87e3112a4452f46e9f7b47fd769cfb570145b62589c76b7aa1eb6080a832e5332c36898426912e29c40ef9e9c742eee82bf30",
    kcp="0d248d7d19234f1486b2efba5179c52d",
    kcv="556291df26d705a2caedd6474dd0079b",
    confirm_p="d4376f2da9c72226dd151b77c2919071155fc22a2068d90b5faa6c78c11e77dd",
    confirm_v="0660a680663e8c5695956fb22dff298b1d07a526cf3cc591adfecd1f6ef6e02e",
    digest="f9cab9adcc0ed8e5a4db11a8505914b2801db297654816eb4f02868129b9dc89",
    shared="801db297654816eb4f02868129b9dc89")

# Matter PASE (Matter Core 3.10 / 4.14.1) using the common SDK test passcode.
PASE = dict(passcode=20202021, salt=b"SPAKE2P Key Salt", iterations=1000,
            request=bytes.fromhex("1530012000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff250201002403002804001818"),
            response=bytes.fromhex("1530012000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff300120a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf25030200350424040100"),
            x=RFC["x"], y=RFC["y"])


def build():
    failures = []
    out = {}

    r = exchange(RFC["ctx"], RFC["idp"], RFC["idv"], RFC["w0"], RFC["w1"], RFC["x"], RFC["y"])
    rk = schedule_rfc9383(r["TT"], r["X"], r["Y"])
    for k in ("L", "X", "Y", "Z", "V"):
        expect("RFC9383 " + k, r[k], RFC_EXPECTED[k], failures)
    for k in ("digest", "kcp", "kcv", "confirm_p", "confirm_v", "shared"):
        expect("RFC9383 " + k, rk[k], RFC_EXPECTED[k], failures)
    out["rfc"] = (r, rk)
    # Cross-profile: RFC 9383 inputs under the Matter key schedule.
    out["rfc_as_matter"] = schedule_matter(r["TT"], r["X"], r["Y"])

    d = exchange(D01["ctx"], D01["idp"], D01["idv"], D01["w0"], D01["w1"], D01["x"], D01["y"])
    dk = schedule_matter(d["TT"], d["X"], d["Y"])
    for k in ("L", "X", "Y", "Z"):
        expect("draft-01 " + k, d[k], D01_EXPECTED[k], failures)
    for k in ("digest", "kcp", "kcv", "confirm_p", "confirm_v", "shared"):
        expect("draft-01 " + k, dk[k], D01_EXPECTED[k], failures)
    out["d01"] = (d, dk)

    ws = hashlib.pbkdf2_hmac("sha256", struct.pack("<I", PASE["passcode"]), PASE["salt"],
                             PASE["iterations"], 80)
    w0 = int.from_bytes(ws[:40], "big") % N_ORDER
    w1 = int.from_bytes(ws[40:], "big") % N_ORDER
    context = hashlib.sha256(b"CHIP PAKE V1 Commissioning" + PASE["request"] + PASE["response"]).digest()
    p = exchange(context, b"", b"", w0, w1, PASE["x"], PASE["y"])
    pk = schedule_matter(p["TT"], p["X"], p["Y"])
    sk = hkdf(pk["shared"], b"SessionKeys", 48)
    out["pase"] = dict(w0=be32(w0), w1=be32(w1), L=p["L"], context=context, X=p["X"], Y=p["Y"],
                       confirm_p=pk["confirm_p"], confirm_v=pk["confirm_v"], ke=pk["shared"],
                       i2r=sk[:16], r2i=sk[16:32], challenge=sk[32:])

    ff = b"\xff" * 40
    out["reduce_ff"] = be32(int.from_bytes(ff, "big") % N_ORDER)
    out["reduce_ws"] = ws
    return out, failures


def c_array(name, data):
    lines = ["SPAKE2P_UT_MAYBE_UNUSED static const uint8_t %s[%d] = {" % (name, len(data))]
    for i in range(0, len(data), 12):
        chunk = ", ".join("0x%02x" % b for b in data[i:i + 12])
        lines.append("    " + chunk + ("," if i + 12 < len(data) else ""))
    lines.append("};")
    return "\n".join(lines)


def c_string(name, data):
    return 'SPAKE2P_UT_MAYBE_UNUSED static const char %s[] = "%s";' % (
        name, data.decode("ascii"))


HEADER_TOP = """/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    spake2p_test_vectors.h
* Summary: SPAKE2+ and Matter PASE known-answer vectors (generated)
*
*
*****************************************************************************/

/**
 * @file spake2p_test_vectors.h
 * @brief Generated by spake2p_reference.py; do not edit by hand.
 * @ingroup noxtls_spake2p
 *
 * - RFC 9383 Appendix C (P256-SHA256-HKDF-SHA256-HMAC-SHA256).
 * - draft-bar-cfrg-spake2plus-01 test vector (Matter profile).
 * - RFC 9383 inputs run through the Matter key schedule (cross-profile).
 * - Matter PASE: passcode 20202021, salt "SPAKE2P Key Salt", 1000 iterations.
 */

#ifndef SPAKE2P_TEST_VECTORS_H
#define SPAKE2P_TEST_VECTORS_H

#include <stdint.h>

/* Each test file uses a subset of the vectors. */
#if defined(__GNUC__) || defined(__clang__)
#define SPAKE2P_UT_MAYBE_UNUSED __attribute__((unused))
#else
#define SPAKE2P_UT_MAYBE_UNUSED
#endif
"""


def render(v):
    r, rk = v["rfc"]
    d, dk = v["d01"]
    x = v["rfc_as_matter"]
    p = v["pase"]
    parts = [HEADER_TOP,
             "/* RFC 9383 Appendix C. */",
             c_string("k_rfc_context", RFC["ctx"]),
             c_string("k_rfc_id_prover", RFC["idp"]),
             c_string("k_rfc_id_verifier", RFC["idv"]),
             c_array("k_rfc_w0", be32(RFC["w0"])), c_array("k_rfc_w1", be32(RFC["w1"])),
             c_array("k_rfc_L", r["L"]), c_array("k_rfc_x", be32(RFC["x"])),
             c_array("k_rfc_share_p", r["X"]), c_array("k_rfc_y", be32(RFC["y"])),
             c_array("k_rfc_share_v", r["Y"]), c_array("k_rfc_Z", r["Z"]), c_array("k_rfc_V", r["V"]),
             c_array("k_rfc_k_main", rk["digest"]), c_array("k_rfc_k_confirm_p", rk["kcp"]),
             c_array("k_rfc_k_confirm_v", rk["kcv"]), c_array("k_rfc_confirm_p", rk["confirm_p"]),
             c_array("k_rfc_confirm_v", rk["confirm_v"]), c_array("k_rfc_k_shared", rk["shared"]),
             "",
             "/* RFC 9383 inputs through the Matter (draft-01) key schedule. */",
             c_array("k_cross_confirm_p", x["confirm_p"]), c_array("k_cross_confirm_v", x["confirm_v"]),
             c_array("k_cross_shared", x["shared"]),
             "",
             "/* draft-bar-cfrg-spake2plus-01 (Matter profile). */",
             c_string("k_d01_context", D01["ctx"]),
             c_array("k_d01_w0", be32(D01["w0"])), c_array("k_d01_w1", be32(D01["w1"])),
             c_array("k_d01_L", d["L"]), c_array("k_d01_x", be32(D01["x"])), c_array("k_d01_X", d["X"]),
             c_array("k_d01_y", be32(D01["y"])), c_array("k_d01_Y", d["Y"]), c_array("k_d01_Z", d["Z"]),
             c_array("k_d01_V", d["V"]), c_array("k_d01_ka_ke", dk["digest"]),
             c_array("k_d01_kca", dk["kcp"]), c_array("k_d01_kcb", dk["kcv"]),
             c_array("k_d01_ca", dk["confirm_p"]), c_array("k_d01_cb", dk["confirm_v"]),
             c_array("k_d01_ke", dk["shared"]),
             "",
             "/* Matter PASE. */",
             "#define K_PASE_PASSCODE (%dUL)" % PASE["passcode"],
             "#define K_PASE_ITERATIONS (%dU)" % PASE["iterations"],
             c_string("k_pase_salt", PASE["salt"]),
             c_array("k_pase_request", PASE["request"]), c_array("k_pase_response", PASE["response"]),
             c_array("k_pase_ws", v["reduce_ws"]),
             c_array("k_pase_w0", p["w0"]), c_array("k_pase_w1", p["w1"]), c_array("k_pase_L", p["L"]),
             c_array("k_pase_context", p["context"]), c_array("k_pase_X", p["X"]), c_array("k_pase_Y", p["Y"]),
             c_array("k_pase_ca", p["confirm_p"]), c_array("k_pase_cb", p["confirm_v"]),
             c_array("k_pase_ke", p["ke"]), c_array("k_pase_i2r", p["i2r"]), c_array("k_pase_r2i", p["r2i"]),
             c_array("k_pase_challenge", p["challenge"]),
             "",
             "/* (2^320 - 1) mod n: registration reduction edge case. */",
             c_array("k_reduce_all_ff", v["reduce_ff"]),
             "",
             "#endif /* SPAKE2P_TEST_VECTORS_H */",
             ""]
    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not (on_curve(M) and on_curve(N)):
        print("M/N not on curve")
        return 1
    vectors, failures = build()
    for f in failures:
        print("MISMATCH " + f)
    if failures:
        return 1
    text = render(vectors)
    path = Path(__file__).with_name("spake2p_test_vectors.h")
    if args.check:
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            print("spake2p_test_vectors.h is stale")
            return 1
        print("OK: transcribed vectors consistent; header up to date")
        return 0
    path.write_text(text, encoding="utf-8", newline="\n")
    print("OK: transcribed vectors consistent; wrote " + path.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
