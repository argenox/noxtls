---
sidebar_position: 35
title: XMSS / XMSS^MT
description: "NoxTLS XMSS and XMSS^MT (RFC 8391, NIST SP 800-208) stateful hash-based signatures: verification, key generation, BDS traversal and fail-closed stateful signing."
keywords:
  - noxtls
  - xmss
  - xmss^mt
  - rfc 8391
  - sp 800-208
  - stateful hash-based signatures
  - firmware signing
---

# XMSS / XMSS^MT

eXtended Merkle Signature Scheme (XMSS) and its multi-tree variant XMSS^MT.
Header: `pkc/xmss/noxtls_xmss.h`.

## Overview

XMSS is a **stateful** hash-based signature scheme. A key is a Merkle tree of height h whose 2^h
leaves are WOTS+ one-time keys (Winternitz parameter w = 16); each leaf may sign exactly one message.
XMSS^MT stacks d layers of trees of height h/d: each tree signs the root of a tree in the layer below,
and the bottom layer signs messages. A key gives 2^h signatures (2^h - 1 for the XMSS^MT h = 40 sets,
see [Exhaustion](#state-management-read-this-first)).

Security rests only on the hash function. The price is state: the signer must never use a one-time
key twice.

Standards:

- RFC 8391 (XMSS and XMSS^MT, SHA-2 and SHAKE with n = 32 and n = 64);
- NIST SP 800-208 (approves the SHA-256 and SHAKE256 sets with n = 32 and adds n = 24 sets).

### Parameter sets

A parameter set is a `noxtls_xmss_param_t`. For XMSS the value is the RFC 8391 / SP 800-208 OID.
For XMSS^MT it is the XMSS^MT OID ORed with `NOXTLS_XMSS_PARAM_MT_FLAG` (0x10000), because the two
OID spaces overlap.

XMSS (h = 10, 16, 20):

| Constants | OIDs | Hash | n | SP 800-208 | Needs |
| --- | --- | --- | ---: | --- | --- |
| `NOXTLS_XMSS_SHA2_{10,16,20}_256` | 0x01..0x03 | SHA-256 | 32 | yes | `NOXTLS_XMSS_ENABLE_SHA2` |
| `NOXTLS_XMSS_SHA2_{10,16,20}_512` | 0x04..0x06 | SHA-512 | 64 | no | `NOXTLS_XMSS_ENABLE_N64`, `NOXTLS_XMSS_ENABLE_SHA2`, `NOXTLS_FEATURE_SHA512` |
| `NOXTLS_XMSS_SHAKE_{10,16,20}_256` | 0x07..0x09 | SHAKE128 | 32 | no | `NOXTLS_XMSS_ENABLE_SHAKE`, `NOXTLS_FEATURE_SHA3` |
| `NOXTLS_XMSS_SHAKE_{10,16,20}_512` | 0x0a..0x0c | SHAKE256 | 64 | no | `NOXTLS_XMSS_ENABLE_N64`, `NOXTLS_XMSS_ENABLE_SHAKE`, `NOXTLS_FEATURE_SHA3` |
| `NOXTLS_XMSS_SHA2_{10,16,20}_192` | 0x0d..0x0f | SHA-256/192 | 24 | yes | `NOXTLS_XMSS_ENABLE_SHA2` |
| `NOXTLS_XMSS_SHAKE256_{10,16,20}_256` | 0x10..0x12 | SHAKE256 | 32 | yes | `NOXTLS_XMSS_ENABLE_SHAKE`, `NOXTLS_FEATURE_SHA3` |
| `NOXTLS_XMSS_SHAKE256_{10,16,20}_192` | 0x13..0x15 | SHAKE256/192 | 24 | yes | `NOXTLS_XMSS_ENABLE_SHAKE`, `NOXTLS_FEATURE_SHA3` |

XMSS^MT families, each with the eight (h, d) pairs 20/2, 20/4, 40/2, 40/4, 40/8, 60/3, 60/6, 60/12 in
that OID order (for example `NOXTLS_XMSSMT_SHA2_20_2_256` = 0x10001, `NOXTLS_XMSSMT_SHA2_20_4_256` =
0x10002, `NOXTLS_XMSSMT_SHA2_60_12_256` = 0x10008):

| Constants | OIDs (without the flag) | Hash | n | SP 800-208 | Needs |
| --- | --- | --- | ---: | --- | --- |
| `NOXTLS_XMSSMT_SHA2_<h>_<d>_256` | 0x01..0x08 | SHA-256 | 32 | yes | as XMSS SHA2_256 |
| `NOXTLS_XMSSMT_SHA2_<h>_<d>_512` | 0x09..0x10 | SHA-512 | 64 | no | as XMSS SHA2_512 |
| `NOXTLS_XMSSMT_SHAKE_<h>_<d>_256` | 0x11..0x18 | SHAKE128 | 32 | no | as XMSS SHAKE_256 |
| `NOXTLS_XMSSMT_SHAKE_<h>_<d>_512` | 0x19..0x20 | SHAKE256 | 64 | no | as XMSS SHAKE_512 |
| `NOXTLS_XMSSMT_SHA2_<h>_<d>_192` | 0x21..0x28 | SHA-256/192 | 24 | yes | as XMSS SHA2_192 |
| `NOXTLS_XMSSMT_SHAKE256_<h>_<d>_256` | 0x29..0x30 | SHAKE256 | 32 | yes | as XMSS SHAKE256_256 |
| `NOXTLS_XMSSMT_SHAKE256_<h>_<d>_192` | 0x31..0x38 | SHAKE256/192 | 24 | yes | as XMSS SHAKE256_192 |

Sets with h above `NOXTLS_XMSS_MAX_HEIGHT` are also refused. A set that is not compiled in behaves as
unsupported: the size functions return 0 and the other functions return `NOXTLS_RETURN_NOT_SUPPORTED`.
`noxtls_xmss_get_param_info()` reports the `sp800_208` flag per set.

SP 800-208 also requires key generation and signing to run in a hardware cryptographic module that
does not export private keys. The library implements the algorithms and the state handling; meeting
that deployment requirement is up to the integrator.

### Sizes

- Public key: `4 + 2n` bytes (u32 OID, root, PUB_SEED).
- Private key: `4 + idx_len + 4n` bytes, with `idx_len` = 4 for XMSS and ceil(h/8) for XMSS^MT.
- Signature: `idx_len + n + d * len * n + h * n` bytes, with `len` = 2n + 3 WOTS+ chains.

XMSS:

| n | Public key | Private key | Signature h=10 | h=16 | h=20 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 24 | 52 | 104 | 1492 | 1636 | 1732 |
| 32 | 68 | 136 | 2500 | 2692 | 2820 |
| 64 | 132 | 264 | 9092 | 9476 | 9732 |

XMSS^MT signatures:

| n | 20/2 | 20/4 | 40/2 | 40/4 | 40/8 | 60/3 | 60/6 | 60/12 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 24 | 2955 | 5403 | 3437 | 5885 | 10781 | 5144 | 8816 | 16160 |
| 32 | 4963 | 9251 | 5605 | 9893 | 18469 | 8392 | 14824 | 27688 |
| 64 | 18115 | 34883 | 19397 | 36165 | 69701 | 29064 | 54216 | 104520 |

XMSS^MT public keys are the same as for XMSS. Private keys are 103 / 105 / 108 bytes (n = 24),
135 / 137 / 140 (n = 32) and 263 / 265 / 268 (n = 64) for h = 20 / 40 / 60.

The compile-time maxima follow the configuration:

| Macro | n = 64 disabled (default) | `NOXTLS_XMSS_ENABLE_N64` = 1 |
| --- | ---: | ---: |
| `NOXTLS_XMSS_MAX_N` | 32 | 64 |
| `NOXTLS_XMSS_MAX_PUBLIC_KEY_LEN` | 68 | 132 |
| `NOXTLS_XMSS_MAX_SECRET_KEY_LEN` | 140 | 268 |
| `NOXTLS_XMSS_MAX_SIGNATURE_LEN`, `NOXTLS_XMSS_MAX_HEIGHT` <= 15 | 2500 | 9092 |
| ... <= 19 | 2692 | 9476 |
| ... <= 39 | 9251 | 34883 |
| ... <= 59 | 18469 | 69701 |
| ... = 60 (default) | 27688 | 104520 |

## State management (read this first)

Signing with XMSS is only safe if every one-time key (leaf) is used at most once, across resets,
power loss, firmware updates and restores. The library enforces this as follows; the integrator is
responsible for the storage side.

- **One-time keys.** The private key holds an index: the next one-time key to use. Each signature
  consumes one index.
- **Mandatory persistence callback.** `noxtls_xmss_signer_init()` requires a
  `noxtls_xmss_persist_cb_t`. Signing is impossible without one.
- **Persist before sign.** Before the signature with index i is computed, the signer stores through
  the callback an image of the private key whose index is at least i + 1 (i + reserve, capped at the
  end of the key). Only after the callback returns `NOXTLS_RETURN_SUCCESS` is the signature computed
  and released. Return success only once the data is committed to non-volatile storage (written and
  read back), not when it is queued.
- **Fail closed.** If the callback returns anything else, no signature is released (the output
  buffer is wiped), the index is not consumed and the callback's error code is returned. Retrying is
  safe.
- **Index consumed first.** After the persist succeeds, the in-RAM key moves to i + 1 before any
  signature material is computed. Any later failure burns index i.
- **Reservations (reserve-N).** The `reserve` argument of `noxtls_xmss_signer_init()` makes one
  persist call cover the next `reserve` indices (one flash write per `reserve` signatures). After a
  reset up to `reserve - 1` indices are skipped. That loses signatures but never reuses one.
- **Exhaustion.** When the last index has been used, the signer wipes SK_SEED and SK_PRF in the
  caller's buffer, sets the index to the end marker and persists that image. Later calls return
  `NOXTLS_RETURN_KEY_EXHAUSTED`. `noxtls_xmss_signer_remaining()` and
  `noxtls_xmss_secret_key_remaining()` report the signatures left. The XMSS^MT h = 40 sets give
  2^40 - 1 signatures: their 5-byte index field cannot hold 2^40, so the last one-time key is never
  used and an all-0xff index marks exhaustion.
- **Rollback hazard.** Never restore an older copy of the private key. Restoring a backup, a cloned
  flash image, a factory image or a VM snapshot rewinds the index, and the next signatures reuse
  one-time keys, which can let an attacker forge signatures. Do not back up signing keys; if a key is
  generated off-device, destroy the generator's copy after provisioning. The library cannot detect a
  rollback.
- **Torn writes.** The XMSS private key has no checksum; the library only checks the OID and the
  index range. Add your own integrity check (for example a CRC per record) and keep two slots (A/B)
  that you write alternately, so that one good copy always survives a power loss. On boot, use the
  valid slot with the highest index (fewest signatures remaining).
- **Confidentiality.** The private key contains SK_SEED and SK_PRF. Store it in protected storage.
- **Fault protection.** With `NOXTLS_XMSS_SIGN_SELF_CHECK` (default 1) each signature is verified
  before it is released, at the cost of about one verification. In XMSS^MT every signature re-signs
  the upper-layer roots, so a fault in a WOTS+ chain or tree node could otherwise publish a second
  message under an upper-layer one-time key. A failed check returns `NOXTLS_RETURN_FAILED`, wipes
  the output and burns the index.
- **One signer per key.** Do not use the same private key from two signers, and do not sign while a
  previous persist is still in flight.

### Why `noxtls_xmss_sign()` returns `NOXTLS_RETURN_NOT_SUPPORTED`

`noxtls_xmss_sign()` takes a `const` private key. It cannot advance the index, so every call would
reuse the same one-time key. It therefore always fails closed with `NOXTLS_RETURN_NOT_SUPPORTED`.
Sign with `noxtls_xmss_signer_init()` and `noxtls_xmss_sign_stateful()`.

## Pros and cons

**Pros**

- Security depends only on the hash function.
- Small public keys (52 to 68 bytes for the SP 800-208 sets) and fast verification.
- Verification is stateless, uses no heap and can stream the message.
- A verify-only build (`NOXTLS_XMSS_ENABLE_SIGN` = 0) is small, suitable for boot loaders.
- Standardized (RFC 8391) and approved by NIST SP 800-208.

**Cons**

- Stateful: the signer must persist state reliably and must never be rolled back.
- Limited number of signatures per key.
- Key generation costs 2^(h/d) leaf computations; single-tree XMSS signing without the BDS traversal
  costs 2^h leaf computations per signature.
- Signatures of 1.5 to 28 KB for the SP 800-208 sets.

## When to use

- Firmware and software image signing, where the device only verifies.
- Signers that run in a controlled place, such as a build server or HSM, with reliable state
  storage.
- Do not use it where state cannot be guaranteed (cloned images, snapshots, no durable storage), or
  for high-volume online signing such as TLS handshakes. Use ML-DSA or SLH-DSA there.

## Types

### `noxtls_xmss_param_info_t`

Filled by `noxtls_xmss_get_param_info()`:

| Field | Meaning |
| --- | --- |
| `oid` | RFC 8391 / SP 800-208 OID (the u32 prefix of keys) |
| `public_key_len`, `secret_key_len`, `signature_len` | Encoded sizes in bytes |
| `is_mt` | 1 for XMSS^MT |
| `hash` | `NOXTLS_XMSS_HASH_SHA256`, `_SHA512`, `_SHAKE128` or `_SHAKE256` |
| `n` | Hash output / node size in bytes |
| `w` | Winternitz parameter (16) |
| `wots_len` | WOTS+ chains (2n + 3) |
| `height`, `layers`, `tree_height` | h, d (1 for XMSS) and h/d |
| `index_len` | Bytes of the index in signatures and private keys |
| `sp800_208` | 1 when approved by NIST SP 800-208 |

### `noxtls_xmss_verify_ctx_t`

Streaming verification context: about 250 bytes plus the largest enabled hash context. It uses no
heap, holds no secrets and may live anywhere. Its fields are private.

### `noxtls_xmss_persist_cb_t`

```c
typedef noxtls_return_t (*noxtls_xmss_persist_cb_t)(void *user, const uint8_t *secret_key,
                                                    uint32_t secret_key_len);
```

Store the `secret_key_len` bytes durably and return `NOXTLS_RETURN_SUCCESS` only once they are
committed. The image is the complete serialized private key; its index field already holds the next
index that may be used after a restart. `secret_key` points into the signer's buffer, which changes
after the callback returns, so copy the bytes before returning.

### `noxtls_xmss_signer_t`

Stateful signer. Its fields are private; use the `noxtls_xmss_signer_*` functions. The serialized
private key stays in the caller's buffer and is updated in place; the optional BDS traversal state
lives in a caller buffer too.

## Parameter queries

```c
uint32_t noxtls_xmss_public_key_len(noxtls_xmss_param_t param);
uint32_t noxtls_xmss_secret_key_len(noxtls_xmss_param_t param);
uint32_t noxtls_xmss_signature_len(noxtls_xmss_param_t param);
uint64_t noxtls_xmss_max_signatures(noxtls_xmss_param_t param);
noxtls_return_t noxtls_xmss_get_param_info(noxtls_xmss_param_t param, noxtls_xmss_param_info_t *info);
noxtls_return_t noxtls_xmss_param_from_oid(uint32_t oid, uint8_t is_mt, noxtls_xmss_param_t *param);
```

- The length functions and `noxtls_xmss_max_signatures()` return 0 for a set that is not supported
  in this build.
- `noxtls_xmss_max_signatures()` returns 2^h, or 2^h - 1 for the XMSS^MT h = 40 sets.
- `noxtls_xmss_param_from_oid()` maps an OID from a key prefix (with `is_mt` 0 or 1) to a set that
  is enabled in this build, or returns `NOXTLS_RETURN_NOT_SUPPORTED`.

## Verification

Verification is stateless and uses no heap. Stack is about 1.8 KB on Cortex-M4 with the default
configuration (`NOXTLS_XMSS_ENABLE_N64` doubles the node buffers).

### `noxtls_xmss_verify`

```c
noxtls_return_t noxtls_xmss_verify(noxtls_xmss_param_t param,
                                   const uint8_t *public_key,
                                   const uint8_t *message,
                                   uint32_t message_len,
                                   const uint8_t *signature,
                                   uint32_t signature_len);
```

`public_key` is the RFC 8391 encoding with the 4-byte OID prefix, `noxtls_xmss_public_key_len(param)`
bytes; its OID must match `param`. `signature_len` must equal `noxtls_xmss_signature_len(param)`.

- `NOXTLS_RETURN_SUCCESS`: the signature is valid.
- `NOXTLS_RETURN_FAILED`: the signature is invalid.
- `NOXTLS_RETURN_BAD_DATA`: malformed input, such as a wrong signature length, an OID mismatch or an
  index beyond the tree.
- `NOXTLS_RETURN_NOT_SUPPORTED`: the set is not compiled in.
- `NOXTLS_RETURN_INVALID_PARAM`, `NOXTLS_RETURN_NULL`: bad arguments.

Treat every result other than `NOXTLS_RETURN_SUCCESS` as "not verified".

### Streaming: `noxtls_xmss_verify_init` / `_update` / `_final`

```c
noxtls_return_t noxtls_xmss_verify_init(noxtls_xmss_verify_ctx_t *ctx,
                                        noxtls_xmss_param_t param,
                                        const uint8_t *public_key,
                                        uint32_t public_key_len,
                                        const uint8_t *signature,
                                        uint32_t signature_len);
noxtls_return_t noxtls_xmss_verify_update(noxtls_xmss_verify_ctx_t *ctx, const uint8_t *data, uint32_t data_len);
noxtls_return_t noxtls_xmss_verify_final(noxtls_xmss_verify_ctx_t *ctx, const uint8_t *signature, uint32_t signature_len);
```

`init()` parses the public key and the signature header (index and r). `update()` absorbs the
message in chunks of any size, so a firmware image can be verified straight from flash. `final()`
checks the rest of the signature and wipes the context. Pass the same signature to `final()` as to
`init()`; its header is checked again and a different one gives `NOXTLS_RETURN_BAD_DATA`. `init()`
returns the same codes as `noxtls_xmss_verify()`, plus `NOXTLS_RETURN_INVALID_KEY_SIZE` for a wrong
`public_key_len`. After `final()` the context returns `NOXTLS_RETURN_NOT_INITIALIZED` until `init()`
is called again.

```c
/* Application code: returns the next chunk of the image, NULL at the end. */
extern const uint8_t *next_image_chunk(uint32_t *chunk_len);

noxtls_xmss_verify_ctx_t ctx;
const uint8_t *chunk = NULL;
uint32_t chunk_len = 0U;
noxtls_return_t rc = noxtls_xmss_verify_init(&ctx, NOXTLS_XMSS_SHA2_10_256, pk,
                                             noxtls_xmss_public_key_len(NOXTLS_XMSS_SHA2_10_256),
                                             sig, sig_len);

while((rc == NOXTLS_RETURN_SUCCESS) && ((chunk = next_image_chunk(&chunk_len)) != NULL)) {
    rc = noxtls_xmss_verify_update(&ctx, chunk, chunk_len);
}
if(rc == NOXTLS_RETURN_SUCCESS) {
    rc = noxtls_xmss_verify_final(&ctx, sig, sig_len);
}
/* boot only if rc == NOXTLS_RETURN_SUCCESS */
```

## Key generation

Key generation needs `NOXTLS_XMSS_ENABLE_SIGN` = 1; otherwise these functions return
`NOXTLS_RETURN_NOT_SUPPORTED`.

```c
noxtls_return_t noxtls_xmss_keygen(noxtls_xmss_param_t param,
                                   uint8_t *public_key,
                                   uint32_t public_key_len,
                                   uint8_t *secret_key,
                                   uint32_t secret_key_len);
noxtls_return_t noxtls_xmss_keygen_from_seed(noxtls_xmss_param_t param,
                                             const uint8_t *seed,
                                             uint32_t seed_len,
                                             uint8_t *public_key,
                                             uint32_t public_key_len,
                                             uint8_t *secret_key,
                                             uint32_t secret_key_len);
```

- `noxtls_xmss_keygen()` draws the seeds from an AES-256 CTR_DRBG seeded from the configured entropy
  source (see [DRBG](/docs/api/drbg)). Use it in production.
- `noxtls_xmss_keygen_from_seed()` is deterministic, for known answer tests: `seed` = SK_SEED ||
  SK_PRF || PUB_SEED, n bytes each (`seed_len` = 3n), as in the XMSS reference implementation. Never
  reuse a seed for a second key.

The buffers must be at least the public and secret key lengths of the set. The secret key receives
the private key with index 0; store it before the first signature. Cost: one tree of 2^(h/d) leaves
(the top layer). Stack about 2.1 KB on Cortex-M4, no heap.

### Private key format

The private key uses the layout of the XMSS reference implementation, big-endian:

| Field | Size |
| --- | ---: |
| OID | 4 |
| index | 4 (XMSS) or ceil(h/8) (XMSS^MT) |
| SK_SEED | n |
| SK_PRF | n |
| root | n |
| PUB_SEED | n |

For example, XMSS-SHA2_10_256 keys are 136 bytes.

### Key helpers

```c
noxtls_return_t noxtls_xmss_public_key_from_secret(noxtls_xmss_param_t param,
                                                   const uint8_t *secret_key,
                                                   uint32_t secret_key_len,
                                                   uint8_t *public_key,
                                                   uint32_t public_key_len);
noxtls_return_t noxtls_xmss_secret_key_remaining(noxtls_xmss_param_t param,
                                                 const uint8_t *secret_key,
                                                 uint32_t secret_key_len,
                                                 uint64_t *remaining);
```

- `noxtls_xmss_public_key_from_secret()` extracts OID || root || PUB_SEED.
- `noxtls_xmss_secret_key_remaining()` returns the signatures a stored key can still produce (0 when
  exhausted). Both return `NOXTLS_RETURN_INVALID_KEY_SIZE` for a wrong length and
  `NOXTLS_RETURN_BAD_DATA` for a wrong OID or an index beyond the end marker.

## Stateful signing

Signing needs `NOXTLS_XMSS_ENABLE_SIGN` = 1 and follows SP 800-208 section 8.

### `noxtls_xmss_signer_init`

```c
noxtls_return_t noxtls_xmss_signer_init(noxtls_xmss_signer_t *signer,
                                        noxtls_xmss_param_t param,
                                        uint8_t *secret_key,
                                        uint32_t secret_key_len,
                                        noxtls_xmss_persist_cb_t persist,
                                        void *persist_user,
                                        uint32_t reserve);
```

Binds a signer to a private key held in the caller's buffer. `secret_key_len` must equal
`noxtls_xmss_secret_key_len(param)`, `persist` is mandatory and `reserve` must be at least 1. The
buffer must stay valid for the signer's lifetime; the signer updates its index in place, so it always
holds the next unused index. Persist only through the callback; do not write this buffer to storage
yourself. `init()` itself does not call the callback.

### BDS traversal (optional)

```c
uint32_t noxtls_xmss_traversal_state_len(noxtls_xmss_param_t param, uint32_t bds_k);
noxtls_return_t noxtls_xmss_signer_attach_traversal(noxtls_xmss_signer_t *signer,
                                                    uint8_t *state,
                                                    uint32_t state_len,
                                                    uint32_t bds_k);
```

Without a traversal, each signature recomputes its trees: about d * 2^(h/d) leaf computations. The
BDS traversal keeps authentication-path state in a caller buffer and cuts this to about
(h/d - bds_k)/2 + d leaf computations per signature.

- `noxtls_xmss_traversal_state_len()` returns the buffer size, or 0 when the combination is invalid.
  `bds_k` must satisfy 0 <= bds_k <= h/d with (h/d - bds_k) even. Larger k keeps more nodes
  (2^k - k - 1 per tree) and does fewer leaf computations per signature.
- `noxtls_xmss_signer_attach_traversal()` attaches the buffer and builds the state for the key's
  current index. That costs about (2d - 1) * 2^(h/d) leaf computations, roughly one key generation.
  It returns `NOXTLS_RETURN_INVALID_PARAM` for an invalid `bds_k`, `NOXTLS_RETURN_INVALID_BLOCK_SIZE`
  for a short buffer, `NOXTLS_RETURN_KEY_EXHAUSTED` for an exhausted key and
  `NOXTLS_RETURN_BAD_DATA` if the seeds do not produce the stored root (corrupt key).

The state holds only public tree nodes. It is a RAM-only cache: it is not persisted and is rebuilt on
every attach, so attach once after each boot. If it does not match the key's index (for example
after a failed signature), the signer rebuilds it automatically.

State sizes for the n = 32 SHA-256 sets:

| Set | bds_k | State |
| --- | ---: | ---: |
| XMSS h = 10 | 2 | 1214 bytes |
| XMSS h = 20 | 2 | 2414 bytes |
| XMSS^MT 20/2 | 2 | 3632 bytes |
| XMSS^MT 40/4 | 2 | 8468 bytes |
| XMSS^MT 60/12 | 1 | 13805 bytes |

### `noxtls_xmss_sign_stateful`

```c
noxtls_return_t noxtls_xmss_sign_stateful(noxtls_xmss_signer_t *signer,
                                          const uint8_t *message,
                                          uint32_t message_len,
                                          uint8_t *signature,
                                          uint32_t *signature_len);
```

Signs with the next one-time key. `*signature_len` is the capacity of `signature` on input and the
signature length on output. On any error `*signature_len` is 0 and no signature material is left in
the output buffer. Stack about
2.5 KB on Cortex-M4 without a traversal, about 1.9 KB with BDS.

- `NOXTLS_RETURN_SUCCESS`: signature written.
- `NOXTLS_RETURN_KEY_EXHAUSTED`: no signatures left.
- The persistence callback's error code: nothing was signed and the index is still available.
- `NOXTLS_RETURN_FAILED`: the self-check failed; the index is burned.
- `NOXTLS_RETURN_INVALID_BLOCK_SIZE`: the capacity is smaller than `noxtls_xmss_signature_len()`.
- `NOXTLS_RETURN_NULL`, `NOXTLS_RETURN_NOT_INITIALIZED`, `NOXTLS_RETURN_BAD_DATA`: bad arguments, a
  signer that is not initialized, or a corrupt key buffer.

### Status and cleanup

```c
noxtls_return_t noxtls_xmss_signer_remaining(const noxtls_xmss_signer_t *signer, uint64_t *remaining);
void noxtls_xmss_signer_free(noxtls_xmss_signer_t *signer);
```

- `noxtls_xmss_signer_remaining()` counts from the in-RAM index, so reserved but unused indices count
  as available.
- `noxtls_xmss_signer_free()` wipes the traversal state and the signer. It does not touch the
  caller's key buffer; wipe that with `noxtls_secure_zero()` when done.

### Example: signer with A/B flash records

The flash and CRC functions are application code. `app_flash_write()` must erase, program and read
back the record, and return 0 only when the data is stored.

```c
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "pkc/xmss/noxtls_xmss.h"
#include "common/noxtls_ct.h"

#define APP_XMSS_PARAM NOXTLS_XMSS_SHA2_10_256 /* 136-byte key, 2500-byte signatures, 1024 signatures */
#define APP_BDS_K      2U

extern int app_flash_write(uint32_t slot, const void *data, uint32_t len);
extern int app_flash_read(uint32_t slot, void *data, uint32_t len);
extern uint32_t app_crc32(const void *data, uint32_t len);

/* The XMSS key has no checksum: each flash record adds one. */
typedef struct
{
    uint8_t sk[NOXTLS_XMSS_MAX_SECRET_KEY_LEN];
    uint32_t crc;
} app_xmss_record_t;

typedef struct
{
    uint32_t next_slot; /* slot (0 or 1) the next persist overwrites */
} app_store_t;

static app_store_t g_store;
static uint8_t g_sk[NOXTLS_XMSS_MAX_SECRET_KEY_LEN]; /* RAM copy, updated in place by the signer */
static uint8_t g_bds[1214];                          /* noxtls_xmss_traversal_state_len(APP_XMSS_PARAM, APP_BDS_K) */
static noxtls_xmss_signer_t g_signer;

static noxtls_return_t app_persist(void *user, const uint8_t *secret_key, uint32_t secret_key_len)
{
    app_store_t *store = (app_store_t *)user;
    app_xmss_record_t rec;
    noxtls_return_t rc = NOXTLS_RETURN_FAILED;

    if(secret_key_len <= sizeof(rec.sk)) {
        (void)memset(&rec, 0, sizeof(rec));
        (void)memcpy(rec.sk, secret_key, secret_key_len); /* copy now: the buffer changes later */
        rec.crc = app_crc32(&rec, (uint32_t)offsetof(app_xmss_record_t, crc));
        if(app_flash_write(store->next_slot, &rec, (uint32_t)sizeof(rec)) == 0) {
            store->next_slot ^= 1U; /* the other slot keeps the previous good copy */
            rc = NOXTLS_RETURN_SUCCESS;
        }
    }
    noxtls_secure_zero(&rec, sizeof(rec));
    return rc; /* anything but SUCCESS: nothing is signed */
}

noxtls_return_t app_xmss_open(void)
{
    app_xmss_record_t rec[2];
    uint64_t rem[2] = { 0U, 0U };
    uint32_t ok[2] = { 0U, 0U };
    uint32_t sk_len = noxtls_xmss_secret_key_len(APP_XMSS_PARAM);
    uint32_t pick = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_BAD_DATA;

    /* Pick the valid record with the fewest signatures remaining (the newest one). */
    for(i = 0U; i < 2U; i++) {
        if((app_flash_read(i, &rec[i], (uint32_t)sizeof(rec[i])) == 0) &&
           (rec[i].crc == app_crc32(&rec[i], (uint32_t)offsetof(app_xmss_record_t, crc))) &&
           (noxtls_xmss_secret_key_remaining(APP_XMSS_PARAM, rec[i].sk, sk_len, &rem[i]) ==
            NOXTLS_RETURN_SUCCESS)) {
            ok[i] = 1U;
        }
    }
    if((ok[0] != 0U) || (ok[1] != 0U)) {
        pick = ((ok[1] != 0U) && ((ok[0] == 0U) || (rem[1] < rem[0]))) ? 1U : 0U;
        g_store.next_slot = pick ^ 1U;
        (void)memcpy(g_sk, rec[pick].sk, sk_len);
        /* reserve 16: one flash write per 16 signatures */
        rc = noxtls_xmss_signer_init(&g_signer, APP_XMSS_PARAM, g_sk, sk_len, app_persist, &g_store, 16U);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_xmss_signer_attach_traversal(&g_signer, g_bds, (uint32_t)sizeof(g_bds), APP_BDS_K);
    }
    noxtls_secure_zero(rec, sizeof(rec));
    return rc;
}

noxtls_return_t app_xmss_sign(const uint8_t *msg, uint32_t msg_len,
                              uint8_t *sig, uint32_t sig_cap, uint32_t *sig_len)
{
    noxtls_return_t rc;

    *sig_len = sig_cap; /* in: capacity, out: signature length */
    rc = noxtls_xmss_sign_stateful(&g_signer, msg, msg_len, sig, sig_len);
    if(rc == NOXTLS_RETURN_KEY_EXHAUSTED) {
        /* no one-time keys left: provision a new key pair */
    }
    return rc;
}

void app_xmss_close(void)
{
    noxtls_xmss_signer_free(&g_signer);
    noxtls_secure_zero(g_sk, sizeof(g_sk));
}
```

## Performance and memory

- **Key generation.** Cost is 2^(h/d) leaf computations: 2^h for single-tree XMSS. Each leaf is a
  full WOTS+ public key (67 chains of 15 steps for n = 32) plus its L-tree. Generate h = 16 and
  h = 20 keys off-device.
- **Signing.** Without BDS, single-tree XMSS recomputes the whole tree for every signature, so use
  the traversal for h >= 16. Attaching it costs about one key generation per boot.
- **Hash choice.** The SHAKE sets are several times slower than SHA-256 in this library.
- **Stack (Cortex-M4, default configuration):** verify about 1.8 KB; keygen about 2.1 KB; sign about
  2.5 KB without traversal, about 1.9 KB with BDS. No heap.
- **Flash (Cortex-M4):** verify only (`NOXTLS_XMSS_ENABLE_SIGN` = 0) about 3.4 KB of XMSS code;
  full module about 10.1 KB.

## Configuration

Set these in `noxtls_config.h` or with `-D`.

| Macro | Default | Meaning |
| --- | --- | --- |
| `NOXTLS_FEATURE_XMSS` | 0 | Enables the XMSS/XMSS^MT API (CMake: `-DNOXTLS_CFG_FEATURE_XMSS=ON`) |
| `NOXTLS_XMSS_ENABLE_SHA2` | 1 | SHA-256 sets (RFC 8391 n = 32, SP 800-208 n = 24) |
| `NOXTLS_XMSS_ENABLE_SHAKE` | 1 | SHAKE sets (SP 800-208 SHAKE256 n = 32 / 24, RFC 8391 SHAKE128 n = 32); effective only with `NOXTLS_FEATURE_SHA3` |
| `NOXTLS_XMSS_ENABLE_N64` | 0 | RFC 8391 n = 64 sets (SHA-512 ones also need `NOXTLS_FEATURE_SHA512`); not SP 800-208 approved; doubles node buffers (verify stack, traversal state) |
| `NOXTLS_XMSS_MAX_HEIGHT` | 60 | Largest total tree height accepted (10..60); taller sets are refused and `NOXTLS_XMSS_MAX_SIGNATURE_LEN` shrinks |
| `NOXTLS_XMSS_ENABLE_SIGN` | 1 | 0 builds a verification-only module |
| `NOXTLS_XMSS_SIGN_SELF_CHECK` | 1 | Verify every signature before it is released |

With `NOXTLS_FEATURE_XMSS` enabled, the build fails unless `NOXTLS_XMSS_ENABLE_SHA2` is set, or
`NOXTLS_XMSS_ENABLE_SHAKE` is set together with `NOXTLS_FEATURE_SHA3`. It also fails for a
`NOXTLS_XMSS_MAX_HEIGHT` outside 10..60.

A small firmware verifier, for example, uses `NOXTLS_XMSS_ENABLE_SIGN` = 0,
`NOXTLS_XMSS_ENABLE_SHAKE` = 0 and `NOXTLS_XMSS_MAX_HEIGHT` = 20.

## Migrating from 0.3.14

- The XMSS^MT constants now encode the OIDs: `NOXTLS_XMSSMT_SHA2_20_2_256` = 0x10001,
  `NOXTLS_XMSSMT_SHA2_20_4_256` = 0x10002, and so on. Do not store or compare the old numeric values.
- The secret key length now follows the parameter set (136 bytes for XMSS-SHA2_10_256). Size buffers
  with `noxtls_xmss_secret_key_len()`.
- `NOXTLS_XMSS_MAX_PUBLIC_KEY_LEN`, `NOXTLS_XMSS_MAX_SECRET_KEY_LEN` and
  `NOXTLS_XMSS_MAX_SIGNATURE_LEN` now depend on `NOXTLS_XMSS_ENABLE_N64` and
  `NOXTLS_XMSS_MAX_HEIGHT`.
- The XMSS^MT h = 40 sets give 2^40 - 1 signatures (`noxtls_xmss_max_signatures()`).
- Sign with `noxtls_xmss_signer_init()` + `noxtls_xmss_sign_stateful()`; `noxtls_xmss_sign()`
  returns `NOXTLS_RETURN_NOT_SUPPORTED`.

## X.509 and TLS status

- XMSS/XMSS^MT is not wired into X.509 certificate parsing or the TLS stack. Use the API directly,
  for example for firmware signatures.
- The realistic future use is certificate-chain verification: RFC 9802 defines XMSS and XMSS^MT
  identifiers for X.509 certificates.
- Stateful keys are unsuitable for TLS handshake signing. Every handshake would consume a one-time
  key and need a persistent write, and server clusters or snapshots would risk index reuse.
