"""Generate ut/pq/vectors/mldsa_kat_vectors.h from NIST ACVP ML-DSA vectors.

usage: python -I gen_mldsa_vectors.py <acvp_dir> <out_header>

<acvp_dir> must contain ML-DSA-keyGen-FIPS204/, ML-DSA-sigGen-FIPS204/ and
ML-DSA-sigVer-FIPS204/ each holding internalProjection.json from
https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
(downloaded 2026-10-24).  The inputs are untrusted: every field is validated
(hex, lengths, enumerations) before it is emitted.

Selection (kept small): per parameter set two keyGen cases; four sigGen
cases (deterministic external/pure with context, hedged external/pure,
deterministic internal with external mu, deterministic HashML-DSA) and three
sigVer cases (valid external/pure, modified hint), plus for ML-DSA-44 a valid
internal external-mu case, a HashML-DSA case and a modified-z internal case.  For HashML-DSA the generator
computes PH(M) with Python's hashlib, because the library API takes the
digest.  Expected keys/signatures of generation tests are stored as SHA3-256
digests; sigVer inputs are stored as hex strings decoded by the test.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pqvec_common as pc  # noqa: E402

PARAMS = {
    "ML-DSA-44": ("NOXTLS_MLDSA_44", 1312, 2560, 2420),
    "ML-DSA-65": ("NOXTLS_MLDSA_65", 1952, 4032, 3309),
    "ML-DSA-87": ("NOXTLS_MLDSA_87", 2592, 4896, 4627),
}

PREHASH = {
    "SHA2-224": ("NOXTLS_MLDSA_PH_SHA2_224", lambda m: hashlib.sha224(m).digest()),
    "SHA2-256": ("NOXTLS_MLDSA_PH_SHA2_256", lambda m: hashlib.sha256(m).digest()),
    "SHA2-384": ("NOXTLS_MLDSA_PH_SHA2_384", lambda m: hashlib.sha384(m).digest()),
    "SHA2-512": ("NOXTLS_MLDSA_PH_SHA2_512", lambda m: hashlib.sha512(m).digest()),
    "SHA2-512/224": ("NOXTLS_MLDSA_PH_SHA2_512_224", lambda m: hashlib.new("sha512_224", m).digest()),
    "SHA2-512/256": ("NOXTLS_MLDSA_PH_SHA2_512_256", lambda m: hashlib.new("sha512_256", m).digest()),
    "SHA3-224": ("NOXTLS_MLDSA_PH_SHA3_224", lambda m: hashlib.sha3_224(m).digest()),
    "SHA3-256": ("NOXTLS_MLDSA_PH_SHA3_256", lambda m: hashlib.sha3_256(m).digest()),
    "SHA3-384": ("NOXTLS_MLDSA_PH_SHA3_384", lambda m: hashlib.sha3_384(m).digest()),
    "SHA3-512": ("NOXTLS_MLDSA_PH_SHA3_512", lambda m: hashlib.sha3_512(m).digest()),
    "SHAKE-128": ("NOXTLS_MLDSA_PH_SHAKE128", lambda m: hashlib.shake_128(m).digest(32)),
    "SHAKE-256": ("NOXTLS_MLDSA_PH_SHAKE256", lambda m: hashlib.shake_256(m).digest(64)),
}

KIND = {
    "pure": "MLDSA_KAT_EXT_PURE",
    "preHash": "MLDSA_KAT_EXT_PREHASH",
    "mu": "MLDSA_KAT_INT_MU",
    "msg": "MLDSA_KAT_INT_MSG",
}


def c_hexstr(data):
    """Emit a C string literal of upper-case hex, split into 128-char chunks."""
    h = data.hex().upper()
    if not h:
        return '""'
    parts = ['"%s"' % h[i:i + 128] for i in range(0, len(h), 128)]
    return "\n        ".join(parts)


def c_digest(d):
    return "{ " + ", ".join("0x%02x" % b for b in d) + " }"


def group_kind(g):
    iface = g["signatureInterface"]
    if iface == "external":
        if g["preHash"] not in ("pure", "preHash"):
            raise ValueError("bad preHash")
        return g["preHash"]
    if iface != "internal":
        raise ValueError("bad interface")
    return "mu" if g["externalMu"] is True else "msg"


def message_fields(kind, t):
    """Return (payload bytes, ctx bytes, ph macro) for a test case."""
    if kind == "mu":
        return pc.unhex(t["mu"], 64, "mu"), b"", "0U"
    msg = pc.unhex(t["message"], None, "message")
    ctx = b""
    if kind in ("pure", "preHash"):
        ctx = pc.unhex(t.get("context", ""), None, "context")
        if len(ctx) > 255:
            raise ValueError("context too long")
    if kind == "preHash":
        ph = t["hashAlg"]
        if ph not in PREHASH:
            raise ValueError("unknown hashAlg %r" % ph)
        return PREHASH[ph][1](msg), ctx, PREHASH[ph][0]
    return msg, ctx, "0U"


def main():
    src = sys.argv[1]
    out = sys.argv[2]
    kg = pc.load_json(os.path.join(src, "ML-DSA-keyGen-FIPS204", "internalProjection.json"))
    sg = pc.load_json(os.path.join(src, "ML-DSA-sigGen-FIPS204", "internalProjection.json"))
    sv = pc.load_json(os.path.join(src, "ML-DSA-sigVer-FIPS204", "internalProjection.json"))
    used = {"keyGen": [], "sigGen": [], "sigVer": []}
    body = []

    # ---- keyGen
    rows = []
    for g in kg["testGroups"]:
        name, pkl, skl, _ = PARAMS[g["parameterSet"]]
        for t in g["tests"][:2]:
            seed = pc.unhex(t["seed"], 32, "seed")
            pk = pc.unhex(t["pk"], pkl, "pk")
            sk = pc.unhex(t["sk"], skl, "sk")
            used["keyGen"].append(t["tcId"])
            rows.append("    { %s, %du,\n      %s,\n      %s,\n      %s },"
                        % (name, int(t["tcId"]), c_digest(seed), c_digest(pc.sha3_256(pk)),
                           c_digest(pc.sha3_256(sk))))
    body.append("static const mldsa_keygen_vec_t g_mldsa_keygen_vecs[] = {\n%s\n};\n" % "\n".join(rows))

    # ---- sigGen
    wanted = [(True, "pure"), (False, "pure"), (True, "mu"), (True, "preHash")]
    rows = []
    for pset in PARAMS:
        for det, kind in wanted:
            groups = [g for g in sg["testGroups"]
                      if g["parameterSet"] == pset and g["deterministic"] is det and group_kind(g) == kind]
            if len(groups) != 1:
                raise ValueError("group selection failed for %s %s %s" % (pset, det, kind))
            tests = groups[0]["tests"]
            # smallest message keeps the header small
            t = min(tests, key=lambda x: len(x.get("message", x.get("mu", ""))))
            name, _pkl, skl, sigl = PARAMS[pset]
            sk = pc.unhex(t["sk"], skl, "sk")
            sig = pc.unhex(t["signature"], sigl, "signature")
            payload, ctx, ph = message_fields(kind, t)
            rnd = None if det else pc.unhex(t["rnd"], 32, "rnd")
            used["sigGen"].append(t["tcId"])
            rows.append("    { %s, %s, %du, %s, %du,\n      /* sk */ %s,\n      /* msg */ %s, %du,\n"
                        "      /* ctx */ %s, %du,\n      /* rnd */ %s,\n      %s },"
                        % (name, KIND[kind], int(t["tcId"]), ph, len(sk), c_hexstr(sk),
                           c_hexstr(payload), len(payload), c_hexstr(ctx), len(ctx),
                           "NULL" if rnd is None else c_hexstr(rnd), c_digest(pc.sha3_256(sig))))
    body.append("static const mldsa_siggen_vec_t g_mldsa_siggen_vecs[] = {\n%s\n};\n" % "\n".join(rows))

    # ---- sigVer
    rows = []

    def pick(pset, kind, passed, reason_part):
        groups = [g for g in sv["testGroups"] if g["parameterSet"] == pset and group_kind(g) == kind]
        if len(groups) != 1:
            raise ValueError("sigVer group selection failed")
        cands = [t for t in groups[0]["tests"]
                 if t["testPassed"] is passed and reason_part in t.get("reason", "")]
        if not cands:
            raise ValueError("no sigVer candidate")
        return min(cands, key=lambda x: len(x.get("message", x.get("mu", ""))))

    for pset in PARAMS:
        sel = [("pure", True, "valid"), ("pure", False, "modified signature - hint")]
        if pset == "ML-DSA-44":
            sel.append(("mu", True, "valid"))
            sel.append(("preHash", True, "valid"))
            sel.append(("msg", False, "modified signature - z"))
        for kind, passed, reason in sel:
            t = pick(pset, kind, passed, reason)
            name, pkl, _skl, sigl = PARAMS[pset]
            pk = pc.unhex(t["pk"], pkl, "pk")
            sig = pc.unhex(t["signature"], sigl, "signature")
            payload, ctx, ph = message_fields(kind, t)
            used["sigVer"].append(t["tcId"])
            rows.append("    { %s, %s, %du, %s, %du,\n      /* pk */ %s,\n      /* msg */ %s, %du,\n"
                        "      /* ctx */ %s, %du,\n      /* sig */ %s },"
                        % (name, KIND[kind], int(t["tcId"]), ph, 1 if passed else 0, c_hexstr(pk),
                           c_hexstr(payload), len(payload), c_hexstr(ctx), len(ctx), c_hexstr(sig)))
    body.append("static const mldsa_sigver_vec_t g_mldsa_sigver_vecs[] = {\n%s\n};\n" % "\n".join(rows))

    types = """#include "pkc/mldsa/noxtls_mldsa.h"

#define MLDSA_KAT_EXT_PURE    0U
#define MLDSA_KAT_EXT_PREHASH 1U
#define MLDSA_KAT_INT_MU      2U
#define MLDSA_KAT_INT_MSG     3U

typedef struct {
    noxtls_mldsa_param_t param;
    uint32_t tc_id;
    uint8_t seed[32];
    uint8_t pk_sha3_256[32];
    uint8_t sk_sha3_256[32];
} mldsa_keygen_vec_t;

typedef struct {
    noxtls_mldsa_param_t param;
    uint32_t kind;
    uint32_t tc_id;
    noxtls_mldsa_prehash_t ph;
    uint32_t sk_len;
    const char *sk_hex;
    const char *msg_hex;   /* message, mu, or PH(M) for HashML-DSA */
    uint32_t msg_len;
    const char *ctx_hex;
    uint32_t ctx_len;
    const char *rnd_hex;   /* NULL: deterministic (rnd = 0^32) */
    uint8_t sig_sha3_256[32];
} mldsa_siggen_vec_t;

typedef struct {
    noxtls_mldsa_param_t param;
    uint32_t kind;
    uint32_t tc_id;
    noxtls_mldsa_prehash_t ph;
    uint32_t expect_valid;
    const char *pk_hex;
    const char *msg_hex;
    uint32_t msg_len;
    const char *ctx_hex;
    uint32_t ctx_len;
    const char *sig_hex;
} mldsa_sigver_vec_t;

"""
    prov = [
        "ML-DSA (FIPS 204) known-answer vectors.",
        "Source: NIST ACVP-Server, https://github.com/usnistgov/ACVP-Server",
        "  gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json",
        "  gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json",
        "  gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json",
        "Downloaded 2026-10-24. Generated by ut/pq/tools/gen_mldsa_vectors.py.",
        "keyGen tcIds: %s" % ", ".join(str(x) for x in used["keyGen"]),
        "sigGen tcIds: %s" % ", ".join(str(x) for x in used["sigGen"]),
        "sigVer tcIds: %s" % ", ".join(str(x) for x in used["sigVer"]),
        "HashML-DSA entries carry PH(M) (computed by the generator) instead of M.",
    ]
    pc.write_header(out, "NOXTLS_MLDSA_KAT_VECTORS_H_", prov, types + "\n".join(body))
    print("wrote", out, os.path.getsize(out), "bytes;", {k: len(v) for k, v in used.items()})


if __name__ == "__main__":
    main()
