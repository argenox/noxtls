#!/usr/bin/env python3
"""Reference model of the NIST SP 800-90A Rev.1 CTR_DRBG (AES) and a CAVP .rsp runner.

Independent of the C code under test: written from the text of SP 800-90A Rev.1
section 10.2.1 (CTR_DRBG_Update, Instantiate, Reseed, Generate, with and without
derivation function), section 10.3.2 (Block_Cipher_df / BCC) and section 9.3.1
(Generate function with prediction resistance). AES is the `cryptography`
package (OpenSSL). ctr_len = blocklen (128), as used by the CAVP vectors.

Used by:
  * gen_drbg_cavp_vectors.py  - validates this model against the official NIST
    CAVP CTR_DRBG response files before emitting the C header subset;
  * ../gen_crypto_sym_vectors.py - derives the crypto_sym_drbg_test.c
    regression values from this (CAVP-validated) model.

Standalone use (runs every AES CTR_DRBG vector of the given .rsp files):
    python -I sp800_90a_ctr_drbg.py <dir>/pr_false/CTR_DRBG.rsp ...
"""

import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCKLEN = 16


def aes_ecb(key, block):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def inc128(v):
    return ((int.from_bytes(v, "big") + 1) % (1 << 128)).to_bytes(16, "big")


def bcc(key, data):
    """SP 800-90A 10.3.3 BCC (CBC-MAC with zero IV)."""
    assert len(data) % BLOCKLEN == 0
    chaining = b"\x00" * BLOCKLEN
    for i in range(0, len(data), BLOCKLEN):
        chaining = aes_ecb(key, xor(chaining, data[i:i + BLOCKLEN]))
    return chaining


def block_cipher_df(keylen, input_string, nbytes):
    """SP 800-90A 10.3.2 Block_Cipher_df(input_string, no_of_bits_to_return = 8 * nbytes)."""
    s = len(input_string).to_bytes(4, "big") + nbytes.to_bytes(4, "big") + input_string + b"\x80"
    while len(s) % BLOCKLEN:
        s += b"\x00"
    temp = b""
    k = bytes(range(32))[:keylen]
    i = 0
    while len(temp) < keylen + BLOCKLEN:
        iv = i.to_bytes(4, "big") + b"\x00" * (BLOCKLEN - 4)
        temp += bcc(k, iv + s)
        i += 1
    k = temp[:keylen]
    x = temp[keylen:keylen + BLOCKLEN]
    temp = b""
    while len(temp) < nbytes:
        x = aes_ecb(k, x)
        temp += x
    return temp[:nbytes]


class CtrDrbg:
    """CTR_DRBG for AES-128/192/256 (keylen 16/24/32), seedlen = keylen + 16."""

    def __init__(self, keylen, use_df):
        self.keylen = keylen
        self.seedlen = keylen + BLOCKLEN
        self.use_df = use_df
        self.key = b"\x00" * keylen
        self.v = b"\x00" * BLOCKLEN
        self.reseed_counter = 0

    def update(self, provided):
        """10.2.1.2 CTR_DRBG_Update."""
        assert len(provided) == self.seedlen
        temp = b""
        v = self.v
        while len(temp) < self.seedlen:
            v = inc128(v)
            temp += aes_ecb(self.key, v)
        temp = xor(temp[:self.seedlen], provided)
        self.key, self.v = temp[:self.keylen], temp[self.keylen:]

    def _pad(self, data):
        data = data or b""
        assert len(data) <= self.seedlen, "no-df input longer than seedlen"
        return data + b"\x00" * (self.seedlen - len(data))

    def instantiate(self, entropy, nonce=b"", pers=b""):
        """10.2.1.3.1 (no df) / 10.2.1.3.2 (df)."""
        if self.use_df:
            seed = block_cipher_df(self.keylen, entropy + (nonce or b"") + (pers or b""), self.seedlen)
        else:
            assert len(entropy) == self.seedlen
            seed = xor(entropy, self._pad(pers))
        self.key = b"\x00" * self.keylen
        self.v = b"\x00" * BLOCKLEN
        self.update(seed)
        self.reseed_counter = 1

    def reseed(self, entropy, add=b""):
        """10.2.1.4.1 (no df) / 10.2.1.4.2 (df)."""
        if self.use_df:
            seed = block_cipher_df(self.keylen, entropy + (add or b""), self.seedlen)
        else:
            assert len(entropy) == self.seedlen
            seed = xor(entropy, self._pad(add))
        self.update(seed)
        self.reseed_counter = 1

    def generate(self, nbits, add=b""):
        """10.2.1.5.1 (no df) / 10.2.1.5.2 (df). Returns leftmost nbits, packed MSB first."""
        if add:
            add = block_cipher_df(self.keylen, add, self.seedlen) if self.use_df else self._pad(add)
            self.update(add)
        else:
            add = b"\x00" * self.seedlen
        nbytes = (nbits + 7) // 8
        temp = b""
        while len(temp) < nbytes:
            self.v = inc128(self.v)
            temp += aes_ecb(self.key, self.v)
        out = bytearray(temp[:nbytes])
        self.update(add)
        self.reseed_counter += 1
        if nbits & 7:
            out[-1] &= (0xFF << (8 - (nbits & 7))) & 0xFF
        return bytes(out)

    def generate_pr(self, nbits, entropy_pr, add=b""):
        """9.3.1 Generate function with prediction_resistance_request: reseed(entropy, add), then generate(Null)."""
        self.reseed(entropy_pr, add)
        return self.generate(nbits, b"")


# ---------------------------------------------------------------------------
# CAVP CTR_DRBG.rsp parsing (CAVS 14.3 format)
# ---------------------------------------------------------------------------
KEYLEN = {"AES-128": 16, "AES-192": 24, "AES-256": 32}


def parse_rsp(path):
    """Yield dict(alg, keylen, use_df, pr, returned_bits_len, entropy, nonce, pers, steps, expected).

    steps is the ordered list of ("reseed", entropy, add) / ("generate", add, entropy_pr or None).
    Only AES sections are returned (3KeyTDEA is not implemented by NoxTLS).
    """
    cases = []
    section = None
    params = {}
    case = None
    with open(path, "r", encoding="ascii") as f:
        lines = f.read().splitlines()
    for raw in lines + ["[END]"]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        is_header = line.startswith("[") and line.endswith("]")
        if (line.startswith("COUNT") or (is_header and "=" not in line)) and case is not None:
            if section[0] in KEYLEN:
                cases.append(case)
            case = None
        if is_header:
            body = line[1:-1]
            if "=" in body:
                k, v = (x.strip() for x in body.split("=", 1))
                params[k] = v
            else:
                alg, _, dfs = body.partition(" ")
                section = (alg, dfs == "use df")
                params = {}
            continue
        k, _, v = (x.strip() for x in line.partition("="))
        if k == "COUNT":
            case = {"alg": section[0], "keylen": KEYLEN.get(section[0]), "use_df": section[1],
                    "pr": params.get("PredictionResistance") == "True",
                    "returned_bits_len": int(params["ReturnedBitsLen"]), "count": int(v),
                    "entropy": b"", "nonce": b"", "pers": b"", "steps": [], "expected": None}
            continue
        v = bytes.fromhex(v)
        if k == "EntropyInput":
            case["entropy"] = v
        elif k == "Nonce":
            case["nonce"] = v
        elif k == "PersonalizationString":
            case["pers"] = v
        elif k == "EntropyInputReseed":
            case["steps"].append(["reseed", v, b""])
        elif k == "AdditionalInputReseed":
            case["steps"][-1][2] = v
        elif k == "AdditionalInput":
            case["steps"].append(["generate", v, None])
        elif k == "EntropyInputPR":
            case["steps"][-1][2] = v
        elif k == "ReturnedBits":
            case["expected"] = v
        else:
            raise ValueError("%s: unknown key %r" % (path, k))
    return cases


def run_case(c):
    d = CtrDrbg(c["keylen"], c["use_df"])
    d.instantiate(c["entropy"], c["nonce"], c["pers"])
    out = None
    for step in c["steps"]:
        if step[0] == "reseed":
            d.reseed(step[1], step[2])
        elif step[2] is not None:
            out = d.generate_pr(c["returned_bits_len"], step[2], step[1])
        else:
            out = d.generate(c["returned_bits_len"], step[1])
    return out


def main(paths):
    total = 0
    bad = 0
    for p in paths:
        cases = parse_rsp(p)
        for c in cases:
            total += 1
            if run_case(c) != c["expected"]:
                bad += 1
                print("MISMATCH %s [%s %s] COUNT=%d" % (p, c["alg"], "use df" if c["use_df"] else "no df", c["count"]))
        print("%s: %d AES CTR_DRBG vectors" % (p, len(cases)))
    print("model: %d/%d vectors pass" % (total - bad, total))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
