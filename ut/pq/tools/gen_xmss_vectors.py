"""Generate ut/pq/vectors/xmss_kat_vectors.h.

usage: python -I gen_xmss_vectors.py --ref-kats REF_KATS [--ref-kats REF_KATS2 ...]
                                     --ref-vectors REF_VECTORS
                                     [--pyref-max-th TH] [--jobs N] --out HEADER

Inputs (treated as untrusted text; every field is validated):
  REF_KATS     output of ut/pq/tools/xmss_refdrv.c linked against the XMSS
               reference implementation (https://github.com/XMSS/xmss-reference,
               commit 171ccbd26f098542a67eb5d2b128281c80bd71a6, 2021-03-16,
               non-BDS core xmss_core.c, SHA-2 from OpenSSL, with the LLP64
               index-truncating cast removed as described in xmss_refdrv.c),
               one line per vector:
               KAT <name> <idx> <msglen> OID=<hex> PK=<hex> SK=<hex>
                   SIGLEN=<n> SIGSHA256=<hex> [SIG=<hex>]
               seed = SK_SEED || SK_PRF || PUB_SEED with byte i = (i*mul + add) & 0xff,
               message byte i = (i*7 + 37) & 0xff.  Vectors per parameter set with
               subtree height <= 16 (driver arguments "name idx msglen mul add full"):
                 A: idx 0,          msglen 0,  seed (1, 0)
                 B: idx 2^h - 2,    msglen 33, seed (13, 101)
                 C: idx 2^(h-1),    msglen 1,  seed (1, 0)    (h/d <= 10; = test/vectors.c)
                 D: idx 2^(h/d),    msglen 5,  seed (3, 7)    (XMSS^MT, h/d <= 10: first
                                                               leaf of the 2nd layer-0 tree)
  REF_VECTORS  unmodified output of the reference's test/vectors.c (SHAKE128-80
               digests of pk and signature for one set per hash family).

Every vector whose subtree height is <= --pyref-max-th is recomputed with the
independent Python implementation ut/pq/tools/xmss_pyref.py (written from the
RFC 8391 / SP 800-208 pseudo-code); any mismatch aborts.  Full signatures
present in REF_KATS are verified with xmss_pyref as well.

The reference implementation's signature for the last index (idx = 2^h - 1)
is invalid: xmss_core.c wipes the private key (index set to 0xff.., seeds to
zero) before it computes that signature.  Such lines are dropped and the
last-index vectors (E: idx 2^h - 1, msglen 33, seed (13, 101)) come from
xmss_pyref only, for every set with h/d <= 5 and the XMSS h = 10 sets.
"""

import argparse
import hashlib
import multiprocessing
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pqvec_common as pv  # noqa: E402
import xmss_pyref as X  # noqa: E402

REF_COMMIT = "171ccbd26f098542a67eb5d2b128281c80bd71a6"
LINE_RE = re.compile(r"^KAT (\S+) (\d+) (\d+) OID=([0-9a-f]{8}) PK=([0-9a-f]+) SK=([0-9a-f]+) "
                     r"SIGLEN=(\d+) SIGSHA256=([0-9a-f]{64})( SIG=([0-9a-f]+))?$")
SEEDS = {"A": (1, 0), "B": (13, 101), "C": (1, 0), "D": (3, 7), "E": (13, 101)}
# Full signatures emitted (one per SP 800-208 hash family, XMSS and XMSS^MT).
FULL_SIGS = ["XMSS-SHA2_10_256", "XMSS-SHAKE256_10_192", "XMSSMT-SHA2_20/4_192", "XMSSMT-SHAKE256_20/4_256"]


def c_param(p):
    name = p.name.replace("XMSSMT-", "XMSSMT_").replace("XMSS-", "XMSS_").replace("/", "_")
    return "NOXTLS_" + name


def seed_tag(p, idx, mlen):
    if idx == 0 and mlen == 0:
        return "A"
    if idx == (1 << p.h) - 2 and mlen == 33:
        return "B"
    if idx == (1 << (p.h - 1)) and mlen == 1:
        return "C"
    if p.is_mt and idx == (1 << p.tree_h) and mlen == 5:
        return "D"
    if idx == (1 << p.h) - 1 and mlen == 33:
        return "E"
    raise ValueError("unexpected vector %s %d %d" % (p.name, idx, mlen))


def gen_bytes(n, mul, add):
    return bytes(((i * mul) + add) & 0xFF for i in range(n))


def gen_msg(n):
    return bytes(((i * 7) + 37) & 0xFF for i in range(n))


def parse_ref_kats(path, skipped):
    out = []
    with open(path, "rb") as f:
        for raw in f.read().decode("ascii").splitlines():
            if not raw.strip():
                continue
            m = LINE_RE.match(raw.strip())
            if not m:
                raise ValueError("bad line: %r" % raw[:80])
            name = m.group(1)
            p = X.params(name)
            idx = int(m.group(2))
            mlen = int(m.group(3))
            if int(m.group(4), 16) != p.oid or idx >= (1 << p.h) or mlen > 64:
                raise ValueError("bad header %s" % name)
            pk = pv.unhex(m.group(5), p.pk_len, "pk")
            sk = pv.unhex(m.group(6), p.sk_len, "sk")
            if int(m.group(7)) != p.sig_len:
                raise ValueError("bad siglen %s" % name)
            sig_digest = pv.unhex(m.group(8), 32, "sigsha256")
            sig = pv.unhex(m.group(10), p.sig_len, "sig") if m.group(10) else None
            if sig is not None and hashlib.sha256(sig).digest() != sig_digest:
                raise ValueError("sig digest mismatch %s" % name)
            tag = seed_tag(p, idx, mlen)
            if tag == "E":
                skipped.append(name)
                continue
            mul, add = SEEDS[tag]
            seed = gen_bytes(3 * p.n, mul, add)
            # The reference secret key with the index set: OID | idx | SK_SEED | SK_PRF | root | PUB_SEED.
            exp_sk = (X.to_byte(p.oid, 4) + X.to_byte(idx, p.idx_bytes) + seed[:2 * p.n] + pk[4:4 + p.n] +
                      seed[2 * p.n:])
            if sk != exp_sk or pk[4 + p.n:] != seed[2 * p.n:] or pk[:4] != X.to_byte(p.oid, 4):
                raise ValueError("unexpected key layout %s" % name)
            out.append(dict(p=p, idx=idx, mlen=mlen, mul=mul, add=add, pk=pk, sig_digest=sig_digest, sig=sig,
                            src=1))
    return out


def parse_ref_vectors(path):
    rows = []
    with open(path, "rb") as f:
        for raw in f.read().decode("ascii").splitlines():
            parts = raw.split()
            if len(parts) == 4 and parts[0] in ("XMSS", "XMSSMT"):
                oid = int(parts[1])
                is_mt = parts[0] == "XMSSMT"
                p = X.params([q.name for q in X.all_params() if q.is_mt == is_mt and q.oid == oid][0])
                rows.append((p, pv.unhex(parts[2], 10, "pkh"), pv.unhex(parts[3], 10, "sigh")))
    return rows


def pyref_check(v):
    p = v["p"]
    seed = gen_bytes(3 * p.n, v["mul"], v["add"])
    pk, key = X.keygen(p, seed[:p.n], seed[p.n:2 * p.n], seed[2 * p.n:])
    msg = gen_msg(v["mlen"])
    sig = X.sign(p, key, msg, v["idx"])
    ok = (pk == v["pk"] and hashlib.sha256(sig).digest() == v["sig_digest"] and X.verify(p, pk, msg, sig))
    return (p.name, v["idx"], ok)


def pyref_last(name):
    p = X.params(name)
    mul, add = SEEDS["E"]
    seed = gen_bytes(3 * p.n, mul, add)
    pk, key = X.keygen(p, seed[:p.n], seed[p.n:2 * p.n], seed[2 * p.n:])
    idx = (1 << p.h) - 1
    msg = gen_msg(33)
    sig = X.sign(p, key, msg, idx)
    if not X.verify(p, pk, msg, sig):
        raise ValueError("xmss_pyref last-index signature does not verify: %s" % name)
    return dict(p=p, idx=idx, mlen=33, mul=mul, add=add, pk=pk, sig_digest=hashlib.sha256(sig).digest(), sig=None,
                src=3)


def c_hexstr(name, data, per_line=64):
    name = pv.c_ident(name)
    h = data.hex()
    lines = ['    "%s"' % h[i:i + per_line] for i in range(0, len(h), per_line)]
    return "static const char %s[%d] =\n%s;\n" % (name, len(h) + 1, "\n".join(lines))


def c_list(data):
    return ", ".join("0x%02x" % b for b in data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref-kats", required=True, action="append")
    ap.add_argument("--ref-vectors", required=True)
    ap.add_argument("--pyref-max-th", type=int, default=5)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    skipped = []
    kats = []
    for path in a.ref_kats:
        kats.extend(parse_ref_kats(path, skipped))
    refvec = parse_ref_vectors(a.ref_vectors)

    # vectors.c lines are the tag-C vectors: cross-check the two reference outputs.
    for (p, pkh, sigh) in refvec:
        c = [v for v in kats if v["p"].name == p.name and seed_tag(p, v["idx"], v["mlen"]) == "C"]
        if len(c) != 1 or hashlib.shake_128(c[0]["pk"][4:]).digest(10) != pkh:
            raise ValueError("vectors.c pk mismatch %s" % p.name)

    # Independent Python recomputation, and xmss_pyref-only last-index vectors.
    todo = [v for v in kats if v["p"].tree_h <= a.pyref_max_th]
    last_sets = [p.name for p in X.all_params() if p.tree_h <= 5 or (not p.is_mt and p.h == 10)]
    with multiprocessing.Pool(a.jobs) as pool:
        res = pool.map(pyref_check, todo)
        last = pool.map(pyref_last, last_sets)
    bad = [r for r in res if not r[2]]
    if bad:
        raise ValueError("xmss_pyref mismatch: %r" % bad[:5])
    for v in todo:
        v["src"] = 2
    full_checked = 0
    for v in kats:
        if v["sig"] is not None:
            if not X.verify(v["p"], v["pk"], gen_msg(v["mlen"]), v["sig"]):
                raise ValueError("full signature does not verify: %s" % v["p"].name)
            full_checked += 1
    nref = len(kats)
    kats.extend(last)
    print("reference vectors: %d (dropped %d invalid last-index outputs of the reference); cross-checked with "
          "xmss_pyref: %d; xmss_pyref-only last-index vectors: %d; vectors.c lines: %d; full sigs verified: %d" %
          (nref, len(skipped), len(todo), len(last), len(refvec), full_checked))

    body = []
    body.append("/* All RFC 8391 / SP 800-208 parameter sets with their sizes (from xmss_pyref). */\n")
    body.append("typedef struct\n{\n    uint32_t param;\n    const char *name;\n    uint32_t oid;\n"
                "    uint32_t pk_len;\n    uint32_t sk_len;\n    uint32_t sig_len;\n    uint8_t is_mt;\n"
                "    uint8_t n;\n    uint8_t h;\n    uint8_t d;\n    uint8_t sp800_208;\n} xmss_param_row_t;\n\n")
    body.append("static const xmss_param_row_t g_xmss_params[] = {\n")
    for p in X.all_params():
        approved = 1 if (p.hname in ("sha256", "shake256") and p.n in (24, 32)) else 0
        body.append("    { %s, \"%s\", 0x%02xU, %dU, %dU, %dU, %dU, %dU, %dU, %dU, %dU },\n" % (
            c_param(p), p.name, p.oid, p.pk_len, p.sk_len, p.sig_len, 1 if p.is_mt else 0, p.n, p.h, p.d, approved))
    body.append("};\n\n")

    body.append("typedef struct\n{\n    uint32_t param;\n    const char *name;\n    uint64_t idx;\n"
                "    uint32_t msg_len;\n    uint8_t seed_mul;\n    uint8_t seed_add;\n"
                "    uint8_t src;           /* 1 xmss-reference, 2 xmss-reference + xmss_pyref, 3 xmss_pyref */\n"
                "    uint8_t pk_sha256[32]; /* SHA-256 of the OID-prefixed public key */\n"
                "    uint8_t sig_sha256[32];\n} xmss_kat_t;\n\n")
    body.append("static const xmss_kat_t g_xmss_kats[] = {\n")
    for v in kats:
        p = v["p"]
        body.append("    { %s, \"%s\", %dULL, %dU, %dU, %dU, %dU,\n      { %s },\n      { %s } },\n" % (
            c_param(p), p.name, v["idx"], v["mlen"], v["mul"], v["add"], v["src"],
            c_list(hashlib.sha256(v["pk"]).digest()), c_list(v["sig_digest"])))
    body.append("};\n\n")

    body.append("/* Unmodified xmss-reference test/vectors.c output: SHAKE128(pk[4:], 80 bits) and\n"
                " * SHAKE128(sig, 80 bits) for seed byte i = i, idx = 2^(h-1), message {37}. */\n")
    body.append("typedef struct\n{\n    uint32_t param;\n    uint8_t pk_shake[10];\n    uint8_t sig_shake[10];\n"
                "} xmss_refvec_t;\n\nstatic const xmss_refvec_t g_xmss_refvec[] = {\n")
    for (p, pkh, sigh) in refvec:
        body.append("    { %s, { %s }, { %s } },\n" % (c_param(p), c_list(pkh), c_list(sigh)))
    body.append("};\n\n")

    body.append("/* Complete reference signatures (idx = 2^h - 2, 33-byte message, seed (13, 101)). */\n")
    body.append("typedef struct\n{\n    uint32_t param;\n    const char *pk;\n    const char *sig;\n} xmss_fullsig_t;\n\n")
    names = []
    for i, name in enumerate(FULL_SIGS):
        v = [k for k in kats if k["p"].name == name and k["sig"] is not None][0]
        body.append(c_hexstr("g_xmss_full_pk_%d" % i, v["pk"]))
        body.append(c_hexstr("g_xmss_full_sig_%d" % i, v["sig"]))
        names.append((c_param(v["p"]), i))
    body.append("\nstatic const xmss_fullsig_t g_xmss_full[] = {\n")
    for (cp, i) in names:
        body.append("    { %s, g_xmss_full_pk_%d, g_xmss_full_sig_%d },\n" % (cp, i, i))
    body.append("};\n")

    prov = [
        "XMSS / XMSS^MT known-answer vectors (RFC 8391, NIST SP 800-208).",
        "Generated by ut/pq/tools/gen_xmss_vectors.py from the output of",
        "ut/pq/tools/xmss_refdrv.c linked against the XMSS reference implementation",
        "  https://github.com/XMSS/xmss-reference commit %s" % REF_COMMIT,
        "  (fetched 2026-10-24; xmss_core.c, i.e. without BDS, SHA-2 from OpenSSL; the",
        "  LLP64-truncating (unsigned long) index cast removed, see xmss_refdrv.c),",
        "and the reference's own test/vectors.c output: %d reference vectors, %d of them" % (nref, len(todo)),
        "(all with subtree height <= %d) independently recomputed with ut/pq/tools/xmss_pyref.py," % a.pyref_max_th,
        "plus %d last-index (idx = 2^h - 1) vectors from xmss_pyref only (the reference" % len(last),
        "implementation's last-index output is invalid, see gen_xmss_vectors.py).",
        "Seeds/messages are derived as described in gen_xmss_vectors.py; public keys and",
        "signatures are stored as SHA-256 digests except for the g_xmss_full entries.",
    ]
    pv.write_header(a.out, "NOXTLS_XMSS_KAT_VECTORS_H_", prov, "".join(body))


if __name__ == "__main__":
    main()
