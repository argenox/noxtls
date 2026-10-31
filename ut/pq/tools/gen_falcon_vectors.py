"""Generate ut/pq/vectors/falcon_kat_vectors.h from the official Falcon KATs.

Source: falcon512-KAT.rsp / falcon1024-KAT.rsp from the Falcon round-3 NIST
submission package (https://falcon-sign.info/falcon-round3.zip, directory
falcon-round3/KAT/).  Usage:

    python -I gen_falcon_vectors.py <falcon512-KAT.rsp> <falcon1024-KAT.rsp> <out.h>

The .rsp "sm" field uses the NIST signed-message layout
    sig_len (2 bytes, big endian) || nonce (40) || msg (mlen) || esig
where esig = (0x20 + logn) || compressed(s2).  NoxTLS uses the Falcon
"padded" signature format of the specification (header 0x30 + logn, the
40-byte salt, the compressed s2 and zero padding to 666 / 1280 bytes), so
the generator re-frames each KAT signature into that format.  Vectors whose
compressed signature does not fit the padded length are skipped.  The secret
key (sk) uses the specification's encoding and is emitted for the vectors
used by the signing round-trip test.
"""

import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pqvec_common as pv  # noqa: E402

PARAMS = {
    9: {"name": "512", "pk_len": 897, "sk_len": 1281, "sig_len": 666},
    10: {"name": "1024", "pk_len": 1793, "sk_len": 2305, "sig_len": 1280},
}
VERIFY_PER_SET = 3
SK_PER_SET = 1


class NistKatDrbg:
    """AES-256 CTR_DRBG of the NIST PQC KAT generator (rng.c, no derivation function)."""

    def __init__(self, entropy48):
        self.key = bytes(32)
        self.v = bytes(16)
        self._update(entropy48)

    def _aes(self, block):
        enc = Cipher(algorithms.AES(self.key), modes.ECB()).encryptor()
        return enc.update(block) + enc.finalize()

    def _inc(self):
        self.v = ((int.from_bytes(self.v, "big") + 1) % (1 << 128)).to_bytes(16, "big")

    def _update(self, provided):
        temp = b""
        for _ in range(3):
            self._inc()
            temp += self._aes(self.v)
        if provided is not None:
            temp = bytes(a ^ b for a, b in zip(temp, provided))
        self.key = temp[:32]
        self.v = temp[32:48]

    def randombytes(self, n):
        out = b""
        while len(out) < n:
            self._inc()
            out += self._aes(self.v)
        self._update(None)
        return out[:n]


def parse_rsp(path):
    entries = []
    cur = {}
    with open(path, "r", encoding="ascii") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError("unexpected line in %s" % path)
            k, v = [x.strip() for x in line.split("=", 1)]
            if k == "count":
                if cur:
                    entries.append(cur)
                cur = {"count": int(v)}
            else:
                cur[k] = v
    if cur:
        entries.append(cur)
    return entries


def reframe(entry, logn):
    p = PARAMS[logn]
    msg = pv.unhex(entry["msg"], int(entry["mlen"]), "msg")
    pk = pv.unhex(entry["pk"], p["pk_len"], "pk")
    sk = pv.unhex(entry["sk"], p["sk_len"], "sk")
    sm = pv.unhex(entry["sm"], int(entry["smlen"]), "sm")
    if pk[0] != logn or sk[0] != 0x50 + logn:
        raise ValueError("bad key header")
    sig_len = (sm[0] << 8) | sm[1]
    nonce = sm[2:42]
    if sm[42:42 + len(msg)] != msg:
        raise ValueError("sm does not embed msg")
    esig = sm[42 + len(msg):]
    if len(esig) != sig_len or esig[0] != 0x20 + logn:
        raise ValueError("bad esig framing")
    comp = esig[1:]
    body_len = p["sig_len"] - 1 - 40
    if len(comp) > body_len:
        return None
    sig = bytes([0x30 + logn]) + nonce + comp + bytes(body_len - len(comp))
    # Replay the KAT generator: keygen draws 48 bytes, crypto_sign draws the
    # 40-byte nonce and then the 48-byte signing seed.
    drbg = NistKatDrbg(pv.unhex(entry["seed"], 48, "seed"))
    drbg.randombytes(48)
    if drbg.randombytes(40) != nonce:
        raise ValueError("DRBG replay does not reproduce the KAT nonce")
    sign_seed = drbg.randombytes(48)
    return {"count": entry["count"], "msg": msg, "pk": pk, "sk": sk, "sig": sig,
            "sign_seed": sign_seed, "comp_len": len(comp)}


def main():
    src512, src1024, out = sys.argv[1], sys.argv[2], sys.argv[3]
    body = []
    for logn, src in ((9, src512), (10, src1024)):
        name = PARAMS[logn]["name"]
        vecs = []
        for e in parse_rsp(src):
            v = reframe(e, logn)
            if v is not None:
                vecs.append(v)
            if len(vecs) == VERIFY_PER_SET:
                break
        if len(vecs) != VERIFY_PER_SET:
            raise ValueError("not enough vectors")
        rows = []
        for i, v in enumerate(vecs):
            tag = "falcon%s_kat%d" % (name, i)
            body.append("/* falcon%s-KAT.rsp count = %d */\n" % (name, v["count"]))
            body.append(pv.c_bytes(tag + "_msg", v["msg"]))
            body.append(pv.c_bytes(tag + "_pk", v["pk"]))
            body.append(pv.c_bytes(tag + "_sig", v["sig"]))
            if i < SK_PER_SET:
                body.append(pv.c_bytes(tag + "_sk", v["sk"]))
                body.append(pv.c_bytes(tag + "_sign_seed", v["sign_seed"]))
            rows.append("    { %d, %s_msg, %d, %s_pk, %s_sig, %s, %s, %d },\n" % (
                v["count"], tag, len(v["msg"]), tag, tag,
                (tag + "_sk") if i < SK_PER_SET else "NULL",
                (tag + "_sign_seed") if i < SK_PER_SET else "NULL",
                v["comp_len"]))
        body.append("\nstatic const falcon_kat_vector_t falcon%s_kats[%d] = {\n%s};\n\n" % (
            name, len(rows), "".join(rows)))
    typedef = ("typedef struct\n{\n    uint32_t count;\n    const uint8_t *msg;\n"
               "    uint32_t msg_len;\n    const uint8_t *pk;\n    const uint8_t *sig;\n"
               "    const uint8_t *sk;        /* NULL when not emitted */\n"
               "    const uint8_t *sign_seed; /* 48-byte crypto_sign seed (with sk) */\n"
               "    uint32_t comp_len;        /* compressed s2 length inside sig */\n"
               "} falcon_kat_vector_t;\n\n")
    prov = [
        "Falcon-512 / Falcon-1024 known-answer vectors.",
        "Source: Falcon round-3 NIST submission KAT files falcon512-KAT.rsp and",
        "falcon1024-KAT.rsp (https://falcon-sign.info/falcon-round3.zip, KAT/).",
        "Downloaded 2026-10-24; generated by ut/pq/tools/gen_falcon_vectors.py.",
        "First %d vectors per set whose signature fits the padded format;" % VERIFY_PER_SET,
        "signatures re-framed from the NIST sm layout into the padded format",
        "(0x30+logn || nonce || compressed s2 || zero padding).",
        "sign_seed is the 48-byte crypto_sign RNG seed obtained by replaying the",
        "NIST AES-256 CTR_DRBG from the KAT seed (the replay is checked against",
        "the KAT nonce); with it the KAT signature can be reproduced bit-exactly.",
    ]
    pv.write_header(out, "NOXTLS_FALCON_KAT_VECTORS_H_", prov,
                    "#include <stddef.h>\n\n" + typedef + "".join(body))


if __name__ == "__main__":
    main()
