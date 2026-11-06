#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
"""Generate ut_wb_vectors.c for the STM32WB host tests.

Reference results come from the `cryptography` package (OpenSSL) for AES and
from textbook affine P-256 arithmetic / Python big integers for the PKA
operations. Run: python gen_vectors.py > ut_wb_vectors.c
"""
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM

P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def det(n, label):
    """Deterministic pseudo-random bytes."""
    out = bytearray()
    c = 0
    while len(out) < n:
        out += hashlib.sha256(("%s/%d" % (label, c)).encode()).digest()
        c += 1
    return bytes(out[:n])


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, P) % P
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


def be(v, n=32):
    return v.to_bytes(n, "big")


lines = []
tables = []


def arr(name, data):
    if not data:
        lines.append("static const uint8_t %s[1] = { 0U };" % name)
        return
    items = ["0x%02XU" % b for b in data]
    rows = [", ".join(items[i:i + 12]) for i in range(0, len(items), 12)]
    lines.append("static const uint8_t %s[%d] = {\n    %s\n};" % (name, len(data), ",\n    ".join(rows)))


def cipher(mode_name, key, iv, data):
    if mode_name == "ecb":
        m = modes.ECB()
    elif mode_name == "cbc":
        m = modes.CBC(iv)
    else:
        m = modes.CTR(iv)
    x = Cipher(algorithms.AES(key), m).encryptor()
    return x.update(data) + x.finalize()


# ---- ECB / CBC / CTR
modes_tab = []
idx = 0
for klen in (16, 32):
    for mname, lens in (("ecb", (16, 32, 64, 160)), ("cbc", (16, 48, 160)),
                        ("ctr", (1, 15, 16, 17, 31, 33, 100))):
        for ln in lens:
            key = det(klen, "k%d%s%d" % (klen, mname, ln))
            iv = det(16, "iv%d%s%d" % (klen, mname, ln)) if mname != "ecb" else b""
            pt = det(ln, "pt%d%s%d" % (klen, mname, ln))
            ct = cipher(mname, key, iv, pt)
            n = "mode%d" % idx
            arr(n + "_key", key)
            arr(n + "_iv", iv)
            arr(n + "_pt", pt)
            arr(n + "_ct", ct)
            modes_tab.append("    { %d, %d, %s_key, %s_iv, %s_pt, %s_ct, %dU }," % (
                {"ecb": 0, "cbc": 1, "ctr": 2}[mname], klen, n, n, n, n, ln))
            idx += 1
# CTR counter carry vectors: low word 0xFFFFFFFE / 0xFFFFFFFF / 64-bit carry / all ones
for tag, ivhex in (("lo2", "000102030405060708090A0BFFFFFFFE"), ("lo1", "000102030405060708090A0BFFFFFFFF"),
                   ("c64", "0001020304050607FFFFFFFFFFFFFFFF"), ("ones", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")):
    for klen in (16, 32):
        key = det(klen, "kc%d%s" % (klen, tag))
        iv = bytes.fromhex(ivhex)
        pt = det(70, "ptc%d%s" % (klen, tag))
        ct = cipher("ctr", key, iv, pt)
        n = "mode%d" % idx
        arr(n + "_key", key)
        arr(n + "_iv", iv)
        arr(n + "_pt", pt)
        arr(n + "_ct", ct)
        modes_tab.append("    { 2, %d, %s_key, %s_iv, %s_pt, %s_ct, 70U }," % (klen, n, n, n, n))
        idx += 1
tables.append(("ut_wb_mode_vec_t", "k_ut_wb_modes", modes_tab))

# ---- GCM
gcm_tab = []
idx = 0
for klen in (16, 32):
    for al, pl in ((0, 0), (20, 0), (0, 16), (16, 16), (1, 1), (13, 31), (32, 64), (5, 17), (0, 100)):
        lab = "%d_%d_%d" % (klen, al, pl)
        key = det(klen, "gk" + lab)
        nonce = det(12, "gn" + lab)
        aad = det(al, "ga" + lab)
        pt = det(pl, "gp" + lab)
        r = AESGCM(key).encrypt(nonce, pt, aad if al else None)
        ct, tag = r[:-16], r[-16:]
        n = "gcm%d" % idx
        arr(n + "_key", key)
        arr(n + "_nonce", nonce)
        arr(n + "_aad", aad)
        arr(n + "_pt", pt)
        arr(n + "_ct", ct)
        arr(n + "_tag", tag)
        gcm_tab.append("    { %d, %s_key, %s_nonce, %s_aad, %dU, %s_pt, %s_ct, %dU, %s_tag }," % (
            klen, n, n, n, al, n, n, pl, n))
        idx += 1
tables.append(("ut_wb_gcm_vec_t", "k_ut_wb_gcm", gcm_tab))

# ---- CCM
ccm_tab = []
idx = 0
for klen in (16, 32):
    for nl, tl, al, pl in ((7, 4, 0, 1), (12, 8, 20, 24), (13, 16, 0, 0), (13, 10, 16, 31), (11, 12, 5, 16),
                           (8, 6, 32, 17), (7, 16, 1, 64), (10, 14, 40, 0)):
        lab = "%d_%d_%d_%d_%d" % (klen, nl, tl, al, pl)
        key = det(klen, "ck" + lab)
        nonce = det(nl, "cn" + lab)
        aad = det(al, "ca" + lab)
        pt = det(pl, "cp" + lab)
        r = AESCCM(key, tag_length=tl).encrypt(nonce, pt, aad if al else None)
        ct, tag = r[:-tl], r[-tl:]
        n = "ccm%d" % idx
        arr(n + "_key", key)
        arr(n + "_nonce", nonce)
        arr(n + "_aad", aad)
        arr(n + "_pt", pt)
        arr(n + "_ct", ct)
        arr(n + "_tag", tag)
        ccm_tab.append("    { %d, %s_key, %s_nonce, %dU, %s_aad, %dU, %s_pt, %s_ct, %dU, %s_tag, %dU }," % (
            klen, n, n, nl, n, al, n, n, pl, n, tl))
        idx += 1
tables.append(("ut_wb_ccm_vec_t", "k_ut_wb_ccm", ccm_tab))

# ---- P-256
G = (GX, GY)
d = int.from_bytes(det(32, "d"), "big") % (N - 1) + 1
Q = mul(d, G)
mul_tab = []
mul_cases = ((1, G), (2, G), (int.from_bytes(det(32, "k1"), "big") % N, G), (d, Q), (0xFF, Q),
             (int.from_bytes(det(32, "k2"), "big") % N, Q))
for i, (k, pt) in enumerate(mul_cases):
    r = mul(k, pt)
    n = "mul%d" % i
    arr(n + "_k", be(k))
    arr(n + "_px", be(pt[0]))
    arr(n + "_py", be(pt[1]))
    arr(n + "_rx", be(r[0]))
    arr(n + "_ry", be(r[1]))
    mul_tab.append("    { %s_k, %s_px, %s_py, %s_rx, %s_ry }," % (n, n, n, n, n))
tables.append(("ut_wb_mul_vec_t", "k_ut_wb_mul", mul_tab))
arr("p256_d", be(d))
arr("p256_qx", be(Q[0]))
arr("p256_qy", be(Q[1]))
sign_tab = []
ver_tab = []
for i in range(3):
    k = int.from_bytes(det(32, "sk%d" % i), "big") % (N - 1) + 1
    e = int.from_bytes(det(32, "se%d" % i), "big") % N
    R = mul(k, G)
    r = R[0] % N
    s = pow(k, -1, N) * (e + r * d) % N
    n = "sig%d" % i
    arr(n + "_k", be(k))
    arr(n + "_e", be(e))
    arr(n + "_r", be(r))
    arr(n + "_s", be(s))
    sign_tab.append("    { p256_d, %s_k, %s_e, %s_r, %s_s }," % (n, n, n, n))
    ver_tab.append("    { p256_qx, p256_qy, %s_e, %s_r, %s_s }," % (n, n, n))
tables.append(("ut_wb_sign_vec_t", "k_ut_wb_sign", sign_tab))
tables.append(("ut_wb_verify_vec_t", "k_ut_wb_verify", ver_tab))
arr("p256_bad_x", be(Q[0] ^ 1))

# ---- modexp
mx_tab = []


def modexp_vec(i, mod_len, exp_len, lead_zero=0):
    m = int.from_bytes(det(mod_len, "m%d" % i), "big") | 1
    m |= 1 << (mod_len * 8 - 1)
    mb = be(m, mod_len)
    if lead_zero:
        mb = bytes(lead_zero) + mb[lead_zero:]
        m = int.from_bytes(mb, "big") | 1
        mb = be(m, mod_len)
    base = int.from_bytes(det(mod_len, "b%d" % i), "big") % m
    ex = int.from_bytes(det(exp_len, "e%d" % i), "big")
    r = pow(base, ex, m)
    n = "mx%d" % i
    arr(n + "_m", mb)
    arr(n + "_b", be(base, mod_len))
    arr(n + "_e", be(ex, exp_len))
    arr(n + "_r", be(r, mod_len))
    mx_tab.append("    { %s_m, %s_b, %s_e, %s_r, %dU, %dU }," % (n, n, n, n, mod_len, exp_len))


modexp_vec(0, 8, 2)
modexp_vec(1, 32, 4)
modexp_vec(2, 33, 8, lead_zero=1)
modexp_vec(3, 64, 3)
modexp_vec(4, 128, 3)
modexp_vec(5, 392, 3)
modexp_vec(6, 11, 8)
tables.append(("ut_wb_modexp_vec_t", "k_ut_wb_modexp", mx_tab))

print("/* Generated by gen_vectors.py - do not edit. */")
print("#include \"ut_wb_vectors.h\"")
print()
exported = ("p256_d", "p256_qx", "p256_qy", "p256_bad_x")
for ln in lines:
    name = ln.split("[", 1)[0].split()[-1]
    print(ln if name not in exported else ln.replace("static ", "", 1))
print()
for typ, name, rows in tables:
    print("const %s %s[] = {" % (typ, name))
    print(chr(10).join(rows))
    print("};")
    print("const uint32_t %s_count = (uint32_t)(sizeof(%s) / sizeof(%s[0]));" % (name, name, name))
    print()
