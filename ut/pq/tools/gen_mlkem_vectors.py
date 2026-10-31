"""Generate ut/pq/vectors/mlkem_kat_vectors.h from NIST ACVP-Server ML-KEM data.

Source (downloaded 2026-10-24):
  https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/
      ML-KEM-keyGen-FIPS203/internalProjection.json
      ML-KEM-encapDecap-FIPS203/internalProjection.json

usage: python -I gen_mlkem_vectors.py <acvp_dir> <out_header> [--all]

<acvp_dir> contains the two ACVP directories above.  By default a small subset
(the first N vectors of every parameter set / function, see PER_GROUP) is
emitted; --all emits every vector (used once to validate the full set, not
checked in).  Large expected outputs of keyGen are stored as SHA3-256 digests.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pqvec_common as pv  # noqa: E402

PARAMS = {
    "ML-KEM-512": ("NOXTLS_MLKEM_512", 2, 800, 1632, 768),
    "ML-KEM-768": ("NOXTLS_MLKEM_768", 3, 1184, 2400, 1088),
    "ML-KEM-1024": ("NOXTLS_MLKEM_1024", 4, 1568, 3168, 1568),
}

PER_GROUP = {
    "keyGen": 3,
    "encapsulation": 2,
    "decapsulation": 2,   # one valid + one modified ciphertext (balanced below)
    "encapsulationKeyCheck": 2,
    "decapsulationKeyCheck": 2,
}


def c_str(hexstr):
    """Emit a hex string as a C string literal split over lines."""
    if len(hexstr) == 0:
        return '""'
    parts = [hexstr[i:i + 96] for i in range(0, len(hexstr), 96)]
    return "\n        ".join('"%s"' % p for p in parts)


def pick(tests, n, key):
    """Pick up to n tests, balancing over the values of key (e.g. reason)."""
    if n is None:
        return tests
    buckets = {}
    for t in tests:
        buckets.setdefault(str(t.get(key)), []).append(t)
    out = []
    while len(out) < n and any(buckets.values()):
        for k in sorted(buckets):
            if buckets[k] and len(out) < n:
                out.append(buckets[k].pop(0))
    return out


def main():
    acvp = sys.argv[1]
    out_path = sys.argv[2]
    full = "--all" in sys.argv[3:]
    lim = (lambda f: None) if full else (lambda f: PER_GROUP[f])

    kg = pv.load_json(os.path.join(acvp, "ML-KEM-keyGen-FIPS203", "internalProjection.json"))
    ed = pv.load_json(os.path.join(acvp, "ML-KEM-encapDecap-FIPS203", "internalProjection.json"))
    if kg.get("algorithm") != "ML-KEM" or ed.get("algorithm") != "ML-KEM":
        raise ValueError("unexpected algorithm field")

    body = []
    used = []

    # keyGen ----------------------------------------------------------------
    rows = []
    for g in kg["testGroups"]:
        ps = PARAMS[g["parameterSet"]]
        for t in pick(g["tests"], lim("keyGen"), "tcId"):
            d = pv.unhex(t["d"], 32, "d")
            z = pv.unhex(t["z"], 32, "z")
            ek = pv.unhex(t["ek"], ps[2], "ek")
            dk = pv.unhex(t["dk"], ps[3], "dk")
            rows.append("    { %s, %du,\n        %s,\n        %s,\n        %s,\n        %s }," % (
                ps[0], int(t["tcId"]), c_str(d.hex()), c_str(z.hex()),
                c_str(pv.sha3_256(ek).hex()), c_str(pv.sha3_256(dk).hex())))
            used.append("keyGen tcId %s" % t["tcId"])
    body.append("static const mlkem_kat_keygen_t g_mlkem_kat_keygen[] = {\n%s\n};\n" % "\n".join(rows))

    # encapDecap -----------------------------------------------------------
    enc_rows, dec_rows, ekc_rows, dkc_rows = [], [], [], []
    for g in ed["testGroups"]:
        ps = PARAMS[g["parameterSet"]]
        fn = g["function"]
        if fn == "encapsulation":
            for t in pick(g["tests"], lim(fn), "tcId"):
                ek = pv.unhex(t["ek"], ps[2], "ek")
                m = pv.unhex(t["m"], 32, "m")
                c = pv.unhex(t["c"], ps[4], "c")
                k = pv.unhex(t["k"], 32, "k")
                enc_rows.append("    { %s, %du,\n        %s,\n        %s,\n        %s,\n        %s }," % (
                    ps[0], int(t["tcId"]), c_str(ek.hex()), c_str(m.hex()),
                    c_str(pv.sha3_256(c).hex()), c_str(k.hex())))
                used.append("encap tcId %s" % t["tcId"])
        elif fn == "decapsulation":
            for t in pick(g["tests"], lim(fn), "reason"):
                ek = pv.unhex(t["ek"], ps[2], "ek")
                dk = pv.unhex(t["dk"], ps[3], "dk")
                c = pv.unhex(t["c"], ps[4], "c")
                k = pv.unhex(t["k"], 32, "k")
                if dk[ps[1] * 384: ps[1] * 384 + ps[2]] != ek:
                    raise ValueError("dk does not embed ek")
                rejected = 1 if t.get("reason") == "modified ciphertext" else 0
                dec_rows.append("    { %s, %du, %du,\n        %s,\n        %s,\n        %s }," % (
                    ps[0], int(t["tcId"]), rejected, c_str(dk.hex()), c_str(c.hex()), c_str(k.hex())))
                used.append("decap tcId %s (%s)" % (t["tcId"], t.get("reason")))
        elif fn == "encapsulationKeyCheck":
            for t in pick(g["tests"], lim(fn), "testPassed"):
                ek = pv.unhex(t["ek"], ps[2], "ek")
                ekc_rows.append("    { %s, %du, %du,\n        %s }," % (
                    ps[0], int(t["tcId"]), 1 if t["testPassed"] else 0, c_str(ek.hex())))
                used.append("ekCheck tcId %s" % t["tcId"])
        elif fn == "decapsulationKeyCheck":
            for t in pick(g["tests"], lim(fn), "testPassed"):
                dk = pv.unhex(t["dk"], ps[3], "dk")
                dkc_rows.append("    { %s, %du, %du,\n        %s }," % (
                    ps[0], int(t["tcId"]), 1 if t["testPassed"] else 0, c_str(dk.hex())))
                used.append("dkCheck tcId %s" % t["tcId"])
        else:
            raise ValueError("unknown function %r" % fn)

    body.append("static const mlkem_kat_encaps_t g_mlkem_kat_encaps[] = {\n%s\n};\n" % "\n".join(enc_rows))
    body.append("static const mlkem_kat_decaps_t g_mlkem_kat_decaps[] = {\n%s\n};\n" % "\n".join(dec_rows))
    body.append("static const mlkem_kat_keycheck_t g_mlkem_kat_ek_check[] = {\n%s\n};\n" % "\n".join(ekc_rows))
    body.append("static const mlkem_kat_keycheck_t g_mlkem_kat_dk_check[] = {\n%s\n};\n" % "\n".join(dkc_rows))

    types = """typedef struct { uint32_t param; uint32_t tc_id; const char *d; const char *z;
                 const char *ek_sha3_256; const char *dk_sha3_256; } mlkem_kat_keygen_t;
typedef struct { uint32_t param; uint32_t tc_id; const char *ek; const char *m;
                 const char *c_sha3_256; const char *k; } mlkem_kat_encaps_t;
typedef struct { uint32_t param; uint32_t tc_id; uint32_t implicit_reject; const char *dk;
                 const char *c; const char *k; } mlkem_kat_decaps_t;
typedef struct { uint32_t param; uint32_t tc_id; uint32_t valid; const char *key; } mlkem_kat_keycheck_t;

"""
    prov = [
        "ML-KEM (FIPS 203) known-answer vectors.",
        "Source: NIST ACVP-Server, https://github.com/usnistgov/ACVP-Server",
        "  gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json",
        "  gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json",
        "  (downloaded 2026-10-24).",
        "Generated by ut/pq/tools/gen_mlkem_vectors.py%s." % (" --all" if full else ""),
        "Values are hex strings; keyGen ek/dk and encaps c are SHA3-256 digests.",
        "Vectors: " + ("all" if full else ", ".join(used)),
    ]
    pv.write_header(out_path, "NOXTLS_MLKEM_KAT_VECTORS_H_", prov, types + "\n".join(body))
    print("wrote", out_path, len(used), "vectors")


if __name__ == "__main__":
    main()
