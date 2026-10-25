"""Generate ut/pq/vectors/lms_kat_vectors.h (LMS / HSS known-answer vectors).

usage: python -I gen_lms_vectors.py <rfc8554.txt> <draft-fluhrer-lms-more-parm-sets-15.txt>
                                    <acvp_json_root> <out_header>

Inputs (untrusted downloads, parsed as text / JSON only and validated):
  * RFC 8554 (https://www.rfc-editor.org/rfc/rfc8554.txt), Appendix F test
    cases 1 and 2 (HSS L=2; test case 2 also lists SEED and I per level).
  * draft-fluhrer-lms-more-parm-sets-15
    (https://www.ietf.org/archive/id/draft-fluhrer-lms-more-parm-sets-15.txt),
    Appendix A test cases 1-4 (SHA-256/192, SHAKE256/192, SHAKE256/256 and
    SHA-256/192 H20/W4; HSS L=1 with SEED and I).
  * NIST ACVP-Server LMS vector sets
    (https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files)
    LMS-keyGen-1.0, LMS-sigVer-1.0, LMS-sigVer-SP800-208, LMS-sigGen-1.0,
    LMS-sigGen-SP800-208 (internalProjection.json).  keyGen and sigVer are
    emitted completely (sigVer: messages up to 1024 bytes); for sigGen, whose
    signatures depend on the generator's private key state, the first
    vector of each group is emitted as an additional valid signature.
All files were fetched 2026-10-24.  Every value is checked for hex syntax and
for the RFC 8554 length implied by its typecodes before it is emitted.
"""

import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pqvec_common as pv  # noqa: E402

LMS_TYPES = {}
for _fam, (_hname, _m) in enumerate([("SHA256", 32), ("SHA256", 24), ("SHAKE", 32), ("SHAKE", 24)]):
    for _k, _h in enumerate([5, 10, 15, 20, 25]):
        LMS_TYPES[5 + 5 * _fam + _k] = ("LMS_%s_M%d_H%d" % (_hname, _m, _h), _m, _h)
OTS_P = {32: {1: 265, 2: 133, 4: 67, 8: 34}, 24: {1: 200, 2: 101, 4: 51, 8: 26}}
OTS_TYPES = {}
for _fam, (_hname, _n) in enumerate([("SHA256", 32), ("SHA256", 24), ("SHAKE", 32), ("SHAKE", 24)]):
    for _k, _w in enumerate([1, 2, 4, 8]):
        OTS_TYPES[1 + 4 * _fam + _k] = ("LMOTS_%s_N%d_W%d" % (_hname, _n, _w), _n, OTS_P[_n][_w])
LMS_BY_NAME = {v[0]: k for k, v in LMS_TYPES.items()}
OTS_BY_NAME = {v[0]: k for k, v in OTS_TYPES.items()}

RFC_URL = "https://www.rfc-editor.org/rfc/rfc8554.txt"
DRAFT_URL = "https://www.ietf.org/archive/id/draft-fluhrer-lms-more-parm-sets-15.txt"
ACVP_URL = "https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files"

HEX_TOKEN = re.compile(r"^[0-9a-fA-F]+$")
SECTION = re.compile(r"^\s+Test Case (\d+) (Private Key|Public Key|Message|Signature)\b")
END = re.compile(r"^(\d+\.|Appendix [B-Z]\.|Acknowledgements|Authors' Addresses|Contributors)")


def u32(b, off):
    return int.from_bytes(b[off:off + 4], "big")


def lms_pk_len(b, off):
    t = u32(b, off)
    if t not in LMS_TYPES:
        raise ValueError("unknown LMS type %#x" % t)
    return 24 + LMS_TYPES[t][1]


def lms_sig_len(pk, sig, off):
    """Length of the LMS signature at sig[off] under LMS public key pk (validates types)."""
    lt, ot = u32(pk, 0), u32(pk, 4)
    _name, m, h = LMS_TYPES[lt]
    _oname, n, p = OTS_TYPES[ot]
    if u32(sig, off + 4) != ot:
        raise ValueError("OTS type mismatch")
    ln = 4 + 4 + n * (p + 1) + 4 + m * h
    if u32(sig, off + 8 + n * (p + 1)) != lt:
        raise ValueError("LMS type mismatch")
    return ln


def check_hss(pk, sig, fmt_hss=True):
    """Structural RFC 8554 check of an HSS (or bare LMS) key / signature pair."""
    if fmt_hss:
        levels = u32(pk, 0)
        cur = pk[4:]
        if u32(sig, 0) != levels - 1:
            raise ValueError("Nspk mismatch")
        off = 4
    else:
        levels = 1
        cur = pk
        off = 0
    if len(cur) != lms_pk_len(cur, 0):
        raise ValueError("public key length")
    for _ in range(levels - 1):
        ln = lms_sig_len(cur, sig, off)
        off += ln
        nl = lms_pk_len(sig, off)
        cur = sig[off:off + nl]
        off += nl
    ln = lms_sig_len(cur, sig, off)
    if off + ln != len(sig):
        raise ValueError("signature length %d != %d" % (len(sig), off + ln))
    return levels


def parse_testcases(path):
    """Return {case: {section: [(context, label, bytes)]}} from an RFC-style text."""
    raw = open(path, "rb").read()
    text = raw.decode("ascii")
    cases = {}
    cur = None
    context = ""
    for line in text.replace("\f", "\n").split("\n"):
        line = line.rstrip("\r")
        m = SECTION.match(line)
        if m:
            cur = cases.setdefault(int(m.group(1)), {}).setdefault(m.group(2), [])
            context = ""
            continue
        if cur is None:
            continue
        if END.match(line):
            cur = None
            continue
        if not line.startswith("   ") or "----" in line:
            continue
        body = line
        if "|" in body:
            body = body[:body.index("|")]
        if "#" in body:
            body = body[:body.index("#")]
        toks = body.split()
        if not toks:
            continue
        if "level" in line and "tree" in line:
            context = "top" if "Top" in line else "second"
            continue
        val = toks[-1]
        if len(toks) == 1 and not HEX_TOKEN.match(val):
            continue
        if not HEX_TOKEN.match(val) or len(val) % 2 != 0 or len(val) < 2:
            continue
        label = " ".join(toks[:-1])
        data = bytes.fromhex(val)
        if label == "" and cur:
            c, lab, prev = cur[-1]
            cur[-1] = (c, lab, prev + data)
        else:
            cur.append((context, label, data))
    return cases, hashlib.sha256(raw).hexdigest()


def concat(entries):
    return b"".join(e[2] for e in entries)


def field(entries, context, label):
    for c, lab, data in entries:
        if c == context and lab == label:
            return data
    raise ValueError("missing %s/%s" % (context, label))


def c_hexstr(name, data, per_line=64):
    name = pv.c_ident(name)
    h = data.hex().upper()
    if not h:
        return 'static const char %s[1] = "";\n' % name
    lines = ['    "%s"' % h[i:i + per_line] for i in range(0, len(h), per_line)]
    return "static const char %s[%d] =\n%s;\n" % (name, len(h) + 1, "\n".join(lines))


def lms_sig_at(pk_lms, sig, off):
    ln = lms_sig_len(pk_lms, sig, off)
    return sig[off:off + ln], off + ln


def main():
    rfc_path, draft_path, acvp_root, out = sys.argv[1:5]
    body = []
    prov = [
        "LMS / HSS (RFC 8554, NIST SP 800-208) known-answer vectors.",
        "Generated by ut/pq/tools/gen_lms_vectors.py from (fetched 2026-10-24):",
    ]

    # ---- RFC 8554 Appendix F ----------------------------------------------
    rfc, rfc_sha = parse_testcases(rfc_path)
    prov.append("  %s (Appendix F) sha256=%s" % (RFC_URL, rfc_sha))
    hss_rows = []
    for tc in (1, 2):
        pk = concat(rfc[tc]["Public Key"])
        msg = concat(rfc[tc]["Message"])
        sig = concat(rfc[tc]["Signature"])
        check_hss(pk, sig, True)
        pre = "lms_rfc_tc%d" % tc
        body.append(c_hexstr(pre + "_pk", pk))
        body.append(c_hexstr(pre + "_msg", msg))
        body.append(c_hexstr(pre + "_sig", sig))
        hss_rows.append((pre, len(pk), len(msg), len(sig), "RFC 8554 Appendix F test case %d" % tc))
    # Test case 2 private keys: top and second-level (I, SEED) and the LMS
    # signatures / public key embedded in the HSS signature.
    priv = rfc[2]["Private Key"]
    pk = concat(rfc[2]["Public Key"])
    sig = concat(rfc[2]["Signature"])
    top_pk = pk[4:]
    sig0, off = lms_sig_at(top_pk, sig, 4)
    nl = lms_pk_len(sig, off)
    pub1 = sig[off:off + nl]
    sig1 = sig[off + nl:]
    if lms_sig_len(pub1, sig, off + nl) != len(sig1):
        raise ValueError("tc2 split")
    rfc_kg = [
        ("lms_rfc_tc2_l0", field(priv, "top", "SEED"), field(priv, "top", "I"), top_pk, sig0, pub1),
        ("lms_rfc_tc2_l1", field(priv, "second", "SEED"), field(priv, "second", "I"), pub1, sig1,
         concat(rfc[2]["Message"])),
    ]

    # ---- draft-fluhrer-lms-more-parm-sets ---------------------------------
    dr, dr_sha = parse_testcases(draft_path)
    prov.append("  %s (Appendix A) sha256=%s" % (DRAFT_URL, dr_sha))
    for tc in sorted(dr.keys()):
        pk = concat(dr[tc]["Public Key"])
        msg = concat(dr[tc]["Message"])
        sig = concat(dr[tc]["Signature"])
        check_hss(pk, sig, True)
        seed = field(dr[tc]["Private Key"], "", "SEED")
        ident = field(dr[tc]["Private Key"], "", "I")
        pre = "lms_drf_tc%d" % tc
        body.append(c_hexstr(pre + "_pk", pk))
        body.append(c_hexstr(pre + "_msg", msg))
        body.append(c_hexstr(pre + "_sig", sig))
        hss_rows.append((pre, len(pk), len(msg), len(sig), "draft-fluhrer-lms-more-parm-sets-15 test case %d" % tc))
        rfc_kg.append((pre + "_l0", seed, ident, pk[4:], sig[4:], msg))

    body.append("\n/* HSS (L-prefixed) public key / message / signature triples. */\n")
    body.append("typedef struct\n{\n    const char *pk;\n    uint32_t pk_len;\n    const char *msg;\n"
                "    uint32_t msg_len;\n    const char *sig;\n    uint32_t sig_len;\n    const char *what;\n"
                "} lms_kat_hss_t;\n\n")
    body.append("static const lms_kat_hss_t g_lms_kat_hss[] = {\n")
    for pre, a, b, c, what in hss_rows:
        body.append('    { %s_pk, %dU, %s_msg, %dU, %s_sig, %dU, "%s" },\n' % (pre, a, pre, b, pre, c, what))
    body.append("};\n\n")

    # One LMS tree from (I, SEED): its public key and one signature at the
    # embedded q over `msg` (C is derived pseudo-randomly from SEED).
    for pre, seed, ident, lpk, lsig, msg in rfc_kg:
        if len(ident) != 16 or len(seed) != LMS_TYPES[u32(lpk, 0)][1]:
            raise ValueError("bad I/SEED for %s" % pre)
        if lms_sig_len(lpk, lsig, 0) != len(lsig):
            raise ValueError("bad LMS signature for %s" % pre)
        body.append(c_hexstr(pre + "_seed", seed))
        body.append(c_hexstr(pre + "_id", ident))
        body.append(c_hexstr(pre + "_lpk", lpk))
        body.append(c_hexstr(pre + "_lsig", lsig))
        if not pre.startswith("lms_drf"):
            body.append(c_hexstr(pre + "_lmsg", msg))
    body.append("\n/* LMS trees given by (SEED, I): bare LMS public key and one LMS signature. */\n")
    body.append("typedef struct\n{\n    const char *seed;\n    uint32_t seed_len;\n    const char *id;\n"
                "    const char *lpk;\n    uint32_t lpk_len;\n    const char *lsig;\n    uint32_t lsig_len;\n"
                "    const char *msg;\n    uint32_t msg_len;\n    uint32_t slow;\n    const char *what;\n"
                "} lms_kat_tree_t;\n\n")
    body.append("static const lms_kat_tree_t g_lms_kat_tree[] = {\n")
    for pre, seed, ident, lpk, lsig, msg in rfc_kg:
        h = LMS_TYPES[u32(lpk, 0)][2]
        msg_name = (pre[:-3] + "_msg") if pre.startswith("lms_drf") else (pre + "_lmsg")
        body.append('    { %s_seed, %dU, %s_id, %s_lpk, %dU, %s_lsig, %dU, %s, %dU, %dU, "%s %s" },\n'
                    % (pre, len(seed), pre, pre, len(lpk), pre, len(lsig), msg_name, len(msg),
                       1 if h > 10 else 0, pre, LMS_TYPES[u32(lpk, 0)][0]))
    body.append("};\n\n")

    # ---- ACVP --------------------------------------------------------------
    used = []
    kg = pv.load_json(os.path.join(acvp_root, "LMS-keyGen-1.0", "internalProjection.json"))
    rows = []
    for g in kg["testGroups"]:
        lt, ot = LMS_BY_NAME[g["lmsMode"]], OTS_BY_NAME[g["lmOtsMode"]]
        m = LMS_TYPES[lt][1]
        for t in g["tests"]:
            seed = pv.unhex(t["seed"], m, "seed")
            ident = pv.unhex(t["i"], 16, "i")
            pk = pv.unhex(t["publicKey"], 24 + m, "publicKey")
            if u32(pk, 0) != lt or u32(pk, 4) != ot or pk[8:24] != ident:
                raise ValueError("keyGen public key header")
            name = "lms_acvp_kg_%d" % t["tcId"]
            body.append(pv.c_bytes(name + "_seed", seed))
            body.append(pv.c_bytes(name + "_id", ident))
            body.append(pv.c_bytes(name + "_pk", pk))
            rows.append((name, lt, ot, m))
            used.append("keyGen %s/%s tcId %d" % (g["lmsMode"], g["lmOtsMode"], t["tcId"]))
    body.append("\ntypedef struct\n{\n    uint32_t lms_type;\n    uint32_t ots_type;\n    const uint8_t *seed;\n"
                "    uint32_t seed_len;\n    const uint8_t *id;\n    const uint8_t *pk;\n    uint32_t pk_len;\n"
                "} lms_kat_keygen_t;\n\n")
    body.append("static const lms_kat_keygen_t g_lms_kat_keygen[] = {\n")
    for name, lt, ot, m in rows:
        body.append("    { 0x%02xU, 0x%02xU, %s_seed, %dU, %s_id, %s_pk, %dU },\n" % (lt, ot, name, m, name, name, 24 + m))
    body.append("};\n\n")

    rows = []
    for vs, sel in (("LMS-sigVer-1.0", "all"), ("LMS-sigVer-SP800-208", "all"),
                    ("LMS-sigGen-1.0", "first"), ("LMS-sigGen-SP800-208", "first")):
        j = pv.load_json(os.path.join(acvp_root, vs, "internalProjection.json"))
        tag = "sv" if "sigVer" in vs else "sg"
        tag += "1" if vs.endswith("1.0") else "2"
        for g in j["testGroups"]:
            lt, ot = LMS_BY_NAME[g["lmsMode"]], OTS_BY_NAME[g["lmOtsMode"]]
            m = LMS_TYPES[lt][1]
            pk = pv.unhex(g["publicKey"], 24 + m, "publicKey")
            pk_name = "lms_acvp_%s_g%d_pk" % (tag, g["tgId"])
            emitted_pk = False
            tests = g["tests"] if sel == "all" else g["tests"][:1]
            for t in tests:
                msg = pv.unhex(t["message"], None, "message")
                if len(msg) > 1024:
                    continue
                sig = pv.unhex(t["signature"], None, "signature")
                passed = bool(t.get("testPassed", True))
                if passed:
                    check_hss(pk, sig, False)
                if not emitted_pk:
                    body.append(c_hexstr(pk_name, pk))
                    emitted_pk = True
                name = "lms_acvp_%s_%d" % (tag, t["tcId"])
                body.append(c_hexstr(name + "_msg", msg))
                body.append(c_hexstr(name + "_sig", sig))
                reason = t.get("reason", "sigGen sample")
                if not re.match(r"^[A-Za-z0-9 ._-]*$", reason):
                    raise ValueError("odd reason text")
                rows.append((pk_name, 24 + m, name, len(msg), len(sig), 1 if passed else 0,
                             "%s tcId %d (%s)" % (vs, t["tcId"], reason)))
                used.append("%s %s/%s tcId %d (%s)" % (vs, g["lmsMode"], g["lmOtsMode"], t["tcId"], reason))
    body.append("\n/* ACVP sigVer (expected result) and sigGen samples (valid), bare LMS format. */\n")
    body.append("typedef struct\n{\n    const char *pk;\n    uint32_t pk_len;\n    const char *msg;\n"
                "    uint32_t msg_len;\n    const char *sig;\n    uint32_t sig_len;\n    uint32_t valid;\n"
                "    const char *what;\n} lms_kat_sigver_t;\n\n")
    body.append("static const lms_kat_sigver_t g_lms_kat_sigver[] = {\n")
    for pk_name, pkl, name, ml, sl, ok, what in rows:
        body.append('    { %s, %dU, %s_msg, %dU, %s_sig, %dU, %dU, "%s" },\n' % (pk_name, pkl, name, ml, name, sl, ok, what))
    body.append("};\n")

    for vs in ("LMS-keyGen-1.0", "LMS-sigVer-1.0", "LMS-sigVer-SP800-208", "LMS-sigGen-1.0", "LMS-sigGen-SP800-208"):
        data = open(os.path.join(acvp_root, vs, "internalProjection.json"), "rb").read()
        prov.append("  %s/%s/internalProjection.json sha256=%s" % (ACVP_URL, vs, hashlib.sha256(data).hexdigest()))
    prov.append("ACVP vectors used:")
    prov.extend("  " + u for u in used)
    pv.write_header(out, "NOXTLS_LMS_KAT_VECTORS_H_", prov, "".join(body))


if __name__ == "__main__":
    main()
