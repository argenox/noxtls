"""Small, independent XMSS / XMSS^MT reference written from the specifications.

Written directly from the pseudo-code of RFC 8391 (Algorithms 1-16) and the
NIST SP 800-208 additions (SHA-256/192, SHAKE256/256, SHAKE256/192 parameter
sets, 4-byte toByte() padding for n = 24, and the PRF_keygen based WOTS+
private key derivation of SP 800-208 Section 7.2.1).  It shares no code with
the C implementation in noxtls-lib/pkc/xmss/ or with the XMSS reference
implementation and is used only offline (by gen_xmss_vectors.py) to produce /
cross-check the expected values checked into ut/pq/vectors/.

It is deliberately simple (whole trees are computed with treeHash, no
traversal algorithm) and therefore only practical for subtree heights <= 10.

usage as a library:
    p = params("XMSS-SHA2_10_256")
    pk, sk = keygen(p, sk_seed, sk_prf, pub_seed)
    sig = sign(p, sk, msg, idx)
    assert verify(p, pk, msg, sig)
"""

import hashlib

W = 16
LOG_W = 4

# name: (is_mt, oid, hash, n, h, d)
#   hash: "sha256", "sha512", "shake128", "shake256"
_XMSS = [
    ("XMSS-SHA2_10_256", 0x01, "sha256", 32, 10), ("XMSS-SHA2_16_256", 0x02, "sha256", 32, 16),
    ("XMSS-SHA2_20_256", 0x03, "sha256", 32, 20), ("XMSS-SHA2_10_512", 0x04, "sha512", 64, 10),
    ("XMSS-SHA2_16_512", 0x05, "sha512", 64, 16), ("XMSS-SHA2_20_512", 0x06, "sha512", 64, 20),
    ("XMSS-SHAKE_10_256", 0x07, "shake128", 32, 10), ("XMSS-SHAKE_16_256", 0x08, "shake128", 32, 16),
    ("XMSS-SHAKE_20_256", 0x09, "shake128", 32, 20), ("XMSS-SHAKE_10_512", 0x0a, "shake256", 64, 10),
    ("XMSS-SHAKE_16_512", 0x0b, "shake256", 64, 16), ("XMSS-SHAKE_20_512", 0x0c, "shake256", 64, 20),
    ("XMSS-SHA2_10_192", 0x0d, "sha256", 24, 10), ("XMSS-SHA2_16_192", 0x0e, "sha256", 24, 16),
    ("XMSS-SHA2_20_192", 0x0f, "sha256", 24, 20), ("XMSS-SHAKE256_10_256", 0x10, "shake256", 32, 10),
    ("XMSS-SHAKE256_16_256", 0x11, "shake256", 32, 16), ("XMSS-SHAKE256_20_256", 0x12, "shake256", 32, 20),
    ("XMSS-SHAKE256_10_192", 0x13, "shake256", 24, 10), ("XMSS-SHAKE256_16_192", 0x14, "shake256", 24, 16),
    ("XMSS-SHAKE256_20_192", 0x15, "shake256", 24, 20),
]

# XMSS^MT OIDs (RFC 8391 Section 5.4 and SP 800-208 Table 11/12): per hash
# family the (h, d) order is 20/2 20/4 40/2 40/4 40/8 60/3 60/6 60/12.
_MT_HD = [(20, 2), (20, 4), (40, 2), (40, 4), (40, 8), (60, 3), (60, 6), (60, 12)]
_MT_FAMILIES = [
    (0x01, "SHA2", "_256", "sha256", 32), (0x09, "SHA2", "_512", "sha512", 64),
    (0x11, "SHAKE", "_256", "shake128", 32), (0x19, "SHAKE", "_512", "shake256", 64),
    (0x21, "SHA2", "_192", "sha256", 24), (0x29, "SHAKE256", "_256", "shake256", 32),
    (0x31, "SHAKE256", "_192", "shake256", 24),
]


class Params(object):
    def __init__(self, name, is_mt, oid, hname, n, h, d):
        self.name = name
        self.is_mt = is_mt
        self.oid = oid
        self.hname = hname
        self.n = n
        self.h = h
        self.d = d
        self.tree_h = h // d
        # SP 800-208: the 192-bit sets use a 4-byte domain separator.
        self.pad = 4 if n == 24 else n
        self.len1 = (8 * n) // LOG_W
        # len_2 = floor(log2(len_1 * (w - 1)) / log2(w)) + 1
        v = self.len1 * (W - 1)
        bits = v.bit_length() - 1
        self.len2 = bits // LOG_W + 1
        self.len = self.len1 + self.len2
        self.idx_bytes = ((h + 7) // 8) if is_mt else 4
        self.sig_len = self.idx_bytes + n + d * self.len * n + h * n
        self.pk_len = 4 + 2 * n
        self.sk_len = 4 + self.idx_bytes + 4 * n


def all_params():
    out = []
    for (name, oid, hname, n, h) in _XMSS:
        out.append(Params(name, False, oid, hname, n, h, 1))
    for (base, fam, suffix, hname, n) in _MT_FAMILIES:
        for k, (h, d) in enumerate(_MT_HD):
            out.append(Params("XMSSMT-%s_%d/%d%s" % (fam, h, d, suffix), True, base + k, hname, n, h, d))
    return out


_BY_NAME = dict((p.name, p) for p in all_params())


def params(name):
    return _BY_NAME[name]


def to_byte(x, length):
    return x.to_bytes(length, "big")


def _hash(p, data):
    if p.hname == "sha256":
        return hashlib.sha256(data).digest()[:p.n]
    if p.hname == "sha512":
        return hashlib.sha512(data).digest()
    if p.hname == "shake128":
        return hashlib.shake_128(data).digest(p.n)
    return hashlib.shake_256(data).digest(p.n)


class Adrs(object):
    """32-byte hash address (RFC 8391 Section 2.5)."""

    def __init__(self):
        self.w = [0] * 8

    def copy(self):
        a = Adrs()
        a.w = list(self.w)
        return a

    def set_layer(self, v):
        self.w[0] = v

    def set_tree(self, v):
        self.w[1] = (v >> 32) & 0xFFFFFFFF
        self.w[2] = v & 0xFFFFFFFF

    def set_type(self, t):
        # Changing the type word resets all following words.
        self.w[3] = t
        self.w[4] = self.w[5] = self.w[6] = self.w[7] = 0

    def set_ots(self, v):
        self.w[4] = v

    def set_chain(self, v):
        self.w[5] = v

    def set_hash(self, v):
        self.w[6] = v

    def set_ltree(self, v):
        self.w[4] = v

    def set_tree_height(self, v):
        self.w[5] = v

    def get_tree_height(self):
        return self.w[5]

    def set_tree_index(self, v):
        self.w[6] = v

    def get_tree_index(self):
        return self.w[6]

    def set_key_and_mask(self, v):
        self.w[7] = v

    def bytes(self):
        return b"".join(to_byte(x, 4) for x in self.w)


class Ctx(object):
    """Hash functions F, H, H_msg, PRF, PRF_keygen of one parameter set."""

    def __init__(self, p, seed):
        self.p = p
        self.seed = seed
        self._prf_prefix = to_byte(3, p.pad) + seed
        self._mid = None
        if p.hname == "sha256" and p.pad + p.n == 64:
            self._mid = hashlib.sha256(self._prf_prefix)

    def prf_seed(self, adrs_bytes):
        """PRF(SEED, ADRS) used for keys and bitmasks."""
        if self._mid is not None:
            h = self._mid.copy()
            h.update(adrs_bytes)
            return h.digest()[:self.p.n]
        return _hash(self.p, self._prf_prefix + adrs_bytes)

    def prf(self, key, m32):
        return _hash(self.p, to_byte(3, self.p.pad) + key + m32)

    def prf_keygen(self, key, m):
        return _hash(self.p, to_byte(4, self.p.pad) + key + m)

    def f(self, key, m):
        return _hash(self.p, to_byte(0, self.p.pad) + key + m)

    def h(self, key, m):
        return _hash(self.p, to_byte(1, self.p.pad) + key + m)

    def h_msg(self, key, m):
        return _hash(self.p, to_byte(2, self.p.pad) + key + m)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# --- WOTS+ (RFC 8391 Section 3.1) ---------------------------------------

def base_w(x, out_len):
    """Algorithm 1."""
    out = []
    i = 0
    total = 0
    bits = 0
    for _ in range(out_len):
        if bits == 0:
            total = x[i]
            i += 1
            bits += 8
        bits -= LOG_W
        out.append((total >> bits) & (W - 1))
    return out


def chain(ctx, x, i, s, adrs):
    """Algorithm 2 (iterative form)."""
    if s == 0:
        return x
    if i + s > W - 1:
        raise ValueError("chain out of range")
    tmp = x
    for j in range(i, i + s):
        adrs.set_hash(j)
        adrs.set_key_and_mask(0)
        key = ctx.prf_seed(adrs.bytes())
        adrs.set_key_and_mask(1)
        bm = ctx.prf_seed(adrs.bytes())
        tmp = ctx.f(key, _xor(tmp, bm))
    return tmp


def wots_sk(ctx, sk_seed, adrs):
    """SP 800-208 Section 7.2.1: sk[i] = PRF_keygen(S, SEED || ADRS)."""
    out = []
    for i in range(ctx.p.len):
        a = adrs.copy()
        a.set_chain(i)
        a.set_hash(0)
        a.set_key_and_mask(0)
        out.append(ctx.prf_keygen(sk_seed, ctx.seed + a.bytes()))
    return out


def wots_gen_pk(ctx, sk, adrs):
    """Algorithm 4."""
    pk = []
    for i in range(ctx.p.len):
        adrs.set_chain(i)
        pk.append(chain(ctx, sk[i], 0, W - 1, adrs))
    return pk


def _msg_digits(p, m):
    msg = base_w(m, p.len1)
    csum = sum(W - 1 - v for v in msg)
    csum <<= (8 - ((p.len2 * LOG_W) % 8))
    len2_bytes = (p.len2 * LOG_W + 7) // 8
    return msg + base_w(to_byte(csum, len2_bytes), p.len2)


def wots_sign(ctx, m, sk, adrs):
    """Algorithm 5."""
    digits = _msg_digits(ctx.p, m)
    sig = []
    for i in range(ctx.p.len):
        adrs.set_chain(i)
        sig.append(chain(ctx, sk[i], 0, digits[i], adrs))
    return sig


def wots_pk_from_sig(ctx, sig, m, adrs):
    """Algorithm 6."""
    digits = _msg_digits(ctx.p, m)
    pk = []
    for i in range(ctx.p.len):
        adrs.set_chain(i)
        pk.append(chain(ctx, sig[i], digits[i], W - 1 - digits[i], adrs))
    return pk


# --- XMSS trees (RFC 8391 Section 4.1) ----------------------------------

def rand_hash(ctx, left, right, adrs):
    """Algorithm 7."""
    adrs.set_key_and_mask(0)
    key = ctx.prf_seed(adrs.bytes())
    adrs.set_key_and_mask(1)
    bm0 = ctx.prf_seed(adrs.bytes())
    adrs.set_key_and_mask(2)
    bm1 = ctx.prf_seed(adrs.bytes())
    return ctx.h(key, _xor(left, bm0) + _xor(right, bm1))


def ltree(ctx, pk, adrs):
    """Algorithm 8."""
    pk = list(pk)
    lp = ctx.p.len
    adrs.set_tree_height(0)
    while lp > 1:
        for i in range(lp // 2):
            adrs.set_tree_index(i)
            pk[i] = rand_hash(ctx, pk[2 * i], pk[2 * i + 1], adrs)
        if lp % 2 == 1:
            pk[lp // 2] = pk[lp - 1]
        lp = (lp + 1) // 2
        adrs.set_tree_height(adrs.get_tree_height() + 1)
    return pk[0]


def leaf(ctx, sk_seed, layer, tree, idx):
    a = Adrs()
    a.set_layer(layer)
    a.set_tree(tree)
    a.set_type(0)
    a.set_ots(idx)
    pk = wots_gen_pk(ctx, wots_sk(ctx, sk_seed, a), a)
    b = Adrs()
    b.set_layer(layer)
    b.set_tree(tree)
    b.set_type(1)
    b.set_ltree(idx)
    return ltree(ctx, pk, b)


def tree_levels(ctx, sk_seed, layer, tree):
    """All nodes of one (sub)tree, levels[j][i] = node i at height j (treeHash, Algorithm 9)."""
    p = ctx.p
    levels = [[leaf(ctx, sk_seed, layer, tree, i) for i in range(1 << p.tree_h)]]
    for j in range(p.tree_h):
        nxt = []
        for i in range(len(levels[j]) // 2):
            a = Adrs()
            a.set_layer(layer)
            a.set_tree(tree)
            a.set_type(2)
            a.set_tree_height(j)
            a.set_tree_index(i)
            nxt.append(rand_hash(ctx, levels[j][2 * i], levels[j][2 * i + 1], a))
        levels.append(nxt)
    return levels


def auth_path(levels, idx):
    return [levels[j][(idx >> j) ^ 1] for j in range(len(levels) - 1)]


def root_from_sig(ctx, idx_leaf, sig_ots, auth, m, layer, tree):
    """Algorithm 13 (XMSS_rootFromSig)."""
    p = ctx.p
    a = Adrs()
    a.set_layer(layer)
    a.set_tree(tree)
    a.set_type(0)
    a.set_ots(idx_leaf)
    pk = wots_pk_from_sig(ctx, sig_ots, m, a)
    b = Adrs()
    b.set_layer(layer)
    b.set_tree(tree)
    b.set_type(1)
    b.set_ltree(idx_leaf)
    node = ltree(ctx, pk, b)
    c = Adrs()
    c.set_layer(layer)
    c.set_tree(tree)
    c.set_type(2)
    c.set_tree_index(idx_leaf)
    for k in range(p.tree_h):
        c.set_tree_height(k)
        if ((idx_leaf >> k) & 1) == 0:
            c.set_tree_index(c.get_tree_index() // 2)
            node = rand_hash(ctx, node, auth[k], c)
        else:
            c.set_tree_index((c.get_tree_index() - 1) // 2)
            node = rand_hash(ctx, auth[k], node, c)
    return node


# --- key generation / signing / verification ----------------------------

class Key(object):
    def __init__(self, p, sk_seed, sk_prf, pub_seed):
        self.p = p
        self.sk_seed = sk_seed
        self.sk_prf = sk_prf
        self.pub_seed = pub_seed
        self.ctx = Ctx(p, pub_seed)
        self._trees = {}
        top = self.tree(p.d - 1, 0)
        self.root = top[-1][0]

    def tree(self, layer, tree):
        k = (layer, tree)
        if k not in self._trees:
            self._trees[k] = tree_levels(self.ctx, self.sk_seed, layer, tree)
        return self._trees[k]

    def public_key(self):
        return to_byte(self.p.oid, 4) + self.root + self.pub_seed

    def secret_key(self, idx=0):
        """Serialized private key: OID || idx || SK_SEED || SK_PRF || root || SEED."""
        return (to_byte(self.p.oid, 4) + to_byte(idx, self.p.idx_bytes) + self.sk_seed +
                self.sk_prf + self.root + self.pub_seed)


def keygen(p, sk_seed, sk_prf, pub_seed):
    k = Key(p, sk_seed, sk_prf, pub_seed)
    return k.public_key(), k


def sign(p, key, msg, idx):
    """Algorithms 12 / 16 for an explicit index (the caller manages the state)."""
    ctx = key.ctx
    n = p.n
    r = ctx.prf(key.sk_prf, to_byte(idx, 32))
    mp = ctx.h_msg(r + key.root + to_byte(idx, n), msg)
    out = [to_byte(idx, p.idx_bytes), r]
    idx_tree = idx >> p.tree_h
    idx_leaf = idx & ((1 << p.tree_h) - 1)
    m = mp
    for layer in range(p.d):
        a = Adrs()
        a.set_layer(layer)
        a.set_tree(idx_tree)
        a.set_type(0)
        a.set_ots(idx_leaf)
        sk = wots_sk(ctx, key.sk_seed, a)
        sig_ots = wots_sign(ctx, m, sk, a)
        levels = key.tree(layer, idx_tree)
        out.extend(sig_ots)
        out.extend(auth_path(levels, idx_leaf))
        m = levels[-1][0]
        idx_leaf = idx_tree & ((1 << p.tree_h) - 1)
        idx_tree >>= p.tree_h
    return b"".join(out)


def verify(p, pk, msg, sig):
    """Algorithms 14 / 17."""
    n = p.n
    if len(pk) != p.pk_len or len(sig) != p.sig_len:
        return False
    if int.from_bytes(pk[:4], "big") != p.oid:
        return False
    root = pk[4:4 + n]
    seed = pk[4 + n:]
    ctx = Ctx(p, seed)
    idx = int.from_bytes(sig[:p.idx_bytes], "big")
    if idx >= (1 << p.h):
        return False
    r = sig[p.idx_bytes:p.idx_bytes + n]
    m = ctx.h_msg(r + root + to_byte(idx, n), msg)
    off = p.idx_bytes + n
    idx_tree = idx >> p.tree_h
    idx_leaf = idx & ((1 << p.tree_h) - 1)
    for layer in range(p.d):
        sig_ots = [sig[off + i * n:off + (i + 1) * n] for i in range(p.len)]
        off += p.len * n
        auth = [sig[off + i * n:off + (i + 1) * n] for i in range(p.tree_h)]
        off += p.tree_h * n
        m = root_from_sig(ctx, idx_leaf, sig_ots, auth, m, layer, idx_tree)
        idx_leaf = idx_tree & ((1 << p.tree_h) - 1)
        idx_tree >>= p.tree_h
    return m == root
