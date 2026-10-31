---
sidebar_position: 34
title: LMS / HSS
description: "NoxTLS LMS and HSS (RFC 8554, NIST SP 800-208) stateful hash-based signatures: verification, key generation and fail-closed stateful signing."
keywords:
  - noxtls
  - lms
  - hss
  - rfc 8554
  - sp 800-208
  - stateful hash-based signatures
  - firmware signing
---

# LMS / HSS

Leighton-Micali signatures (LMS) and the Hierarchical Signature System (HSS) built from them.
Header: `pkc/lms/noxtls_lms.h`.

## Overview

LMS is a **stateful** hash-based signature scheme. A key is a Merkle tree of height `h` whose
2^h leaves are LM-OTS one-time keys; each leaf may sign exactly one message. HSS stacks up to 8 LMS
trees: each tree signs the root of the tree below it, and the bottom tree signs messages. The total
number of signatures is 2^(h_0 + ... + h_(L-1)).

Security rests only on the hash function, so LMS is quantum resistant without new number-theoretic
assumptions. The price is state: the signer must never use a one-time key twice.

Standards:

- RFC 8554 (LMS, LM-OTS, HSS, SHA-256 with n = 32);
- NIST SP 800-208 (adds SHA-256/192, SHAKE256/256 and SHAKE256/192).

The library supports every LMS and LM-OTS typecode of RFC 8554 and SP 800-208: tree heights H5,
H10, H15, H20, H25 and Winternitz parameters W1, W2, W4, W8, for four hash functions:

| Hash (n) | LMS typecodes (H5..H25) | LM-OTS typecodes (W1, W2, W4, W8) | Defined in | Build requirement |
| --- | --- | --- | --- | --- |
| SHA-256 (32) | `NOXTLS_LMS_TYPE_SHA256_M32_H5..H25` = `0x05..0x09` | `NOXTLS_LMOTS_TYPE_SHA256_N32_W1..W8` = `0x01..0x04` | RFC 8554, SP 800-208 | always |
| SHA-256/192 (24) | `NOXTLS_LMS_TYPE_SHA256_M24_H5..H25` = `0x0A..0x0E` | `NOXTLS_LMOTS_TYPE_SHA256_N24_W1..W8` = `0x05..0x08` | SP 800-208 | always |
| SHAKE256/256 (32) | `NOXTLS_LMS_TYPE_SHAKE_M32_H5..H25` = `0x0F..0x13` | `NOXTLS_LMOTS_TYPE_SHAKE_N32_W1..W8` = `0x09..0x0C` | SP 800-208 | `NOXTLS_FEATURE_SHA3` |
| SHAKE256/192 (24) | `NOXTLS_LMS_TYPE_SHAKE_M24_H5..H25` = `0x14..0x18` | `NOXTLS_LMOTS_TYPE_SHAKE_N24_W1..W8` = `0x0D..0x10` | SP 800-208 | `NOXTLS_FEATURE_SHA3` |

All of these parameter sets are approved by SP 800-208. Without `NOXTLS_FEATURE_SHA3` the SHAKE
typecodes are rejected as unsupported. An LMS typecode and its LM-OTS typecode must use the same hash
function and output length.

SP 800-208 also requires key generation and signing to run in a hardware cryptographic module that
does not export private keys. The library implements the algorithms and the state handling; meeting
that deployment requirement is up to the integrator.

### Sizes

- Public key: `24 + n` bytes for bare LMS, `4 + 24 + n` for HSS (56 / 60 bytes for n = 32).
- LM-OTS signature: `4 + n * (p + 1)` bytes. LMS signature: `4 + LM-OTS signature + 4 + n * h`.
- HSS signature: `4 + (sum of the L LMS signatures) + (L - 1) * (24 + n)` bytes.
- Private key: always `NOXTLS_HSS_PRIVATE_KEY_LEN` = 168 bytes.

| W | p (n = 32) | p (n = 24) | Hashes per leaf (n = 32, about p * (2^W - 1)) |
| --- | ---: | ---: | ---: |
| 1 | 265 | 200 | 265 |
| 2 | 133 | 101 | 399 |
| 4 | 67 | 51 | 1005 |
| 8 | 34 | 26 | 8670 |

Larger W gives smaller signatures and slower leaves. Examples (n = 32):

| Parameters | Public key | Signature | Signatures per key |
| --- | ---: | ---: | ---: |
| LMS H5 / W8 | 56 | 1292 | 32 |
| LMS H10 / W8 | 56 | 1452 | 1024 |
| LMS H10 / W4 | 56 | 2508 | 1024 |
| LMS H20 / W8 | 56 | 1772 | 2^20 |
| HSS L=2, H10/H10, W8 | 60 | 2964 | 2^20 |
| LMS H25 / W1 (largest single LMS signature) | 56 | 9324 | 2^25 |

Use the size functions below rather than hard-coded numbers.

## State management (read this first)

Signing with LMS is only safe if every one-time key (leaf) is used at most once, across resets,
power loss, firmware updates and restores. The library enforces this as follows; the integrator is
responsible for the storage side.

- **One-time keys.** Each signature consumes one global index. The private key blob holds a 64-bit
  counter: the first index that has *not* been reserved yet.
- **Mandatory persistence callback.** `noxtls_hss_key_load()` requires a
  `noxtls_hss_persist_fn`. Signing is impossible without one.
- **Persist before sign.** Before an index is used it must be covered by the persisted counter. When
  the in-RAM reservation runs out, `noxtls_hss_sign()` writes a new blob (counter = next index +
  reserve) through the callback and only continues when the callback returns
  `NOXTLS_RETURN_SUCCESS`. Return success only once the data is durably stored (written and read
  back), not when it is queued.
- **Fail closed.** If the callback returns anything else, nothing is signed, the output buffer is not
  touched, the index is not consumed and the callback's error code is returned. Retrying is safe.
- **Index consumed first.** Once persisted, the index is consumed in RAM before any signature
  material is computed. Any later failure burns the index; it is never handed out again.
- **Reservations (reserve-N).** `noxtls_hss_key_set_reserve(key, N)` makes each persist cover N
  indices (one flash write per N signatures); `noxtls_hss_key_reserve(key, N)` persists N more indices
  now. After a reset, reserved but unused indices are skipped. That loses signatures but never
  reuses one.
- **Exhaustion.** When all indices are used, `noxtls_hss_sign()` and `noxtls_hss_key_reserve()`
  return `NOXTLS_RETURN_KEY_EXHAUSTED`. `noxtls_hss_key_remaining()` and
  `noxtls_hss_private_key_info()` report how many signatures are left. Plan the key size and monitor
  the remaining count.
- **Rollback hazard.** Never restore an older copy of the private key blob. Restoring a backup, a
  cloned flash image, a factory image or a VM snapshot rewinds the counter, and the next signatures
  reuse one-time keys, which can let an attacker forge signatures. Do not back up signing keys; if a
  key is generated off-device, destroy the generator's copy after provisioning. The library can only
  detect a rollback in one case: a reused workspace (`NOXTLS_HSS_LOAD_REUSE_WORKSPACE`) whose index
  is ahead of the blob counter is refused with `NOXTLS_RETURN_BAD_DATA`.
- **Torn writes.** A power loss during the write can leave a half-written blob. The blob carries a
  checksum (first 8 bytes of SHA-256 over the rest), so a torn blob is detected on load
  (`NOXTLS_RETURN_BAD_DATA`) and refused. The checksum detects corruption; it is not a MAC. Keep two
  slots (A/B) and alternate writes, or use an atomic-replace file system, so that one good copy
  always survives. On boot, use the valid slot with the highest counter.
- **Confidentiality.** The blob contains the secret SEED. Store it in protected storage.
- **Fault protection.** Each signature is verified against the public key before it is released.
  A fault that corrupts the computation therefore never publishes a bad or key-leaking signature;
  `noxtls_hss_sign()` returns `NOXTLS_RETURN_FAILED`, wipes the output and burns the index.
  `NOXTLS_HSS_KEY_NO_SELF_VERIFY` disables the check (not recommended).
  `NOXTLS_HSS_KEY_FAULT_HARDENING` also computes every new lower-level root twice before the parent
  tree signs it.
- **One signer per key.** A working key is not thread-safe; serialize calls. Never load the same
  key on two devices or in two working keys.

### Why `noxtls_lms_sign()` returns `NOXTLS_RETURN_NOT_SUPPORTED`

`noxtls_lms_sign()` takes a `const` secret key. It has no way to record that a one-time key was
used, so every call would reuse the same leaf. It therefore always fails closed with
`NOXTLS_RETURN_NOT_SUPPORTED`. Sign with `noxtls_hss_key_load()` and `noxtls_hss_sign()`.

## Pros and cons

**Pros**

- Security depends only on the hash function (SHA-256 or SHAKE256).
- Small public keys (48 to 60 bytes) and fast verification.
- Verification is stateless, uses no heap, needs little stack and can stream the message.
- Small verify-only code, suitable for boot loaders.
- Standardized (RFC 8554) and approved by NIST SP 800-208.

**Cons**

- Stateful: the signer must persist state reliably and must never be rolled back.
- Limited number of signatures per key.
- Key generation and key loading cost 2^h leaf computations per tree.
- Signatures of about 0.8 to 9.3 KB per tree level, larger than classical signatures.

## When to use

- Firmware and software image signing, where the device only verifies. Build the device with the
  verify API only.
- Signers that run in a controlled place, such as a build server or HSM, with reliable state
  storage.
- Do not use it where state cannot be guaranteed (cloned images, snapshots, no durable storage), or
  for high-volume online signing such as TLS handshakes. Use ML-DSA or SLH-DSA there.

## Types

### `noxtls_hss_params_t`

```c
typedef struct
{
    uint32_t format;
    uint32_t levels;
    uint32_t lms_type[NOXTLS_HSS_MAX_LEVELS];
    uint32_t ots_type[NOXTLS_HSS_MAX_LEVELS];
} noxtls_hss_params_t;
```

- `format`: `NOXTLS_LMS_FORMAT_LMS` (0, bare RFC 8554 section 5 encoding, requires `levels == 1`)
  or `NOXTLS_LMS_FORMAT_HSS` (1, RFC 8554 section 6 encoding with the 4-byte L prefix).
- `levels`: L, 1 to `NOXTLS_HSS_MAX_LEVELS` (8).
- `lms_type[i]`, `ots_type[i]`: typecodes of level i (0 = top).

Verification accepts any valid combination, including different hash functions per level. Key
generation and signing also require the same hash function and output length on every level and a
total tree height of at most 63 (the counter is 64 bits).

### `noxtls_hss_key_t`

The in-RAM working signing key. It contains secrets: release it with `noxtls_hss_key_free()`, which
wipes it. Its fields are internal; use the API functions.

### `noxtls_hss_verify_ctx_t`

Streaming verification context. The public key and signature buffers passed to
`noxtls_hss_verify_init()` must stay valid and unchanged until `noxtls_hss_verify_final()`.

### `noxtls_hss_persist_fn`

```c
typedef noxtls_return_t (*noxtls_hss_persist_fn)(void *user, const uint8_t *private_key,
                                                 uint32_t private_key_len);
```

Store `private_key_len` (`NOXTLS_HSS_PRIVATE_KEY_LEN`) bytes durably and return
`NOXTLS_RETURN_SUCCESS` only when that succeeded. Any other value aborts the signature and is
returned to the caller of `noxtls_hss_sign()` or `noxtls_hss_key_reserve()`.

### Constants

| Macro | Value | Meaning |
| --- | ---: | --- |
| `NOXTLS_HSS_MAX_LEVELS` | 8 | Largest L |
| `NOXTLS_HSS_PRIVATE_KEY_LEN` | 168 | Serialized private key |
| `NOXTLS_HSS_MAX_PUBLIC_KEY_LEN` | 60 | Largest HSS public key |
| `NOXTLS_LMS_MAX_LMS_SIGNATURE_LEN` | 9324 | Largest single LMS signature (n = 32, W1, H25) |
| `NOXTLS_HSS_DEFAULT_SUBTREE_HEIGHT` | 5 | Traversal sublevel height used when 0 is passed |

There is no compile-time maximum for HSS signatures, which can exceed 70 KB for L = 8. Size buffers
with `noxtls_hss_signature_len()`.

## Parameter sets and sizes

```c
noxtls_return_t noxtls_hss_params_check(const noxtls_hss_params_t *params, uint32_t for_signing);
uint32_t noxtls_hss_public_key_len(const noxtls_hss_params_t *params);
uint32_t noxtls_hss_signature_len(const noxtls_hss_params_t *params);
uint64_t noxtls_hss_max_signatures(const noxtls_hss_params_t *params);
uint32_t noxtls_hss_workspace_len(const noxtls_hss_params_t *params, uint32_t subtree_height);
uint32_t noxtls_lms_type_signature_len(uint32_t lms_type, uint32_t ots_type);
```

- `noxtls_hss_params_check()` returns `NOXTLS_RETURN_SUCCESS`, `NOXTLS_RETURN_NULL` or
  `NOXTLS_RETURN_INVALID_PARAM`. A non-zero `for_signing` also applies the key generation / signing
  restrictions.
- The length functions return 0 for an invalid set. `noxtls_hss_max_signatures()` returns
  2^(sum of heights), or 0 if that is above 2^63.
- `noxtls_hss_workspace_len()` returns the traversal workspace size for a signing key (see
  [Traversal workspace](#traversal-workspace)).
- `noxtls_lms_type_signature_len()` returns the length of one LMS signature for a typecode pair.

## Verification

Verification is stateless, uses no heap, and its stack use does not depend on the parameter set:
about 1.0 to 1.3 KB on Cortex-M4. The public key is trusted input. The signature is untrusted and
parsed strictly: exact length, typecodes equal to the public key's, q < 2^h, and Nspk = L - 1.

### `noxtls_hss_verify`

```c
noxtls_return_t noxtls_hss_verify(uint32_t format,
                                  const uint8_t *public_key, uint32_t public_key_len,
                                  const uint8_t *message, uint32_t message_len,
                                  const uint8_t *signature, uint32_t signature_len);
```

Verifies an LMS (`NOXTLS_LMS_FORMAT_LMS`) or HSS (`NOXTLS_LMS_FORMAT_HSS`) signature. The public key
must be exactly its encoded length.

- `NOXTLS_RETURN_SUCCESS`: the signature is valid.
- `NOXTLS_RETURN_FAILED`: the signature is invalid or malformed (including a wrong length).
- `NOXTLS_RETURN_INVALID_PARAM`: malformed or unsupported public key, or wrong format.
- `NOXTLS_RETURN_NULL`: missing arguments.

Treat every result other than `NOXTLS_RETURN_SUCCESS` as "not verified".

### Streaming: `noxtls_hss_verify_init` / `_update` / `_final`

```c
noxtls_return_t noxtls_hss_verify_init(noxtls_hss_verify_ctx_t *ctx, uint32_t format,
                                       const uint8_t *public_key, uint32_t public_key_len,
                                       const uint8_t *signature, uint32_t signature_len);
noxtls_return_t noxtls_hss_verify_update(noxtls_hss_verify_ctx_t *ctx, const uint8_t *data, uint32_t len);
noxtls_return_t noxtls_hss_verify_final(noxtls_hss_verify_ctx_t *ctx);
```

`init()` parses the signature and verifies all signed lower-level public keys; it returns the same
codes as `noxtls_hss_verify()`. `update()` absorbs the message in chunks of any size, so a firmware
image can be verified straight from flash without a second copy. `final()` returns
`NOXTLS_RETURN_SUCCESS` or `NOXTLS_RETURN_FAILED` and wipes the context. After `final()` or after an
`update()` error, the context returns `NOXTLS_RETURN_NOT_INITIALIZED` until `init()` is called again.

```c
/* Application code: returns the next chunk of the image, NULL at the end. */
extern const uint8_t *next_image_chunk(uint32_t *chunk_len);

noxtls_hss_verify_ctx_t ctx;
const uint8_t *chunk = NULL;
uint32_t chunk_len = 0U;
noxtls_return_t rc = noxtls_hss_verify_init(&ctx, NOXTLS_LMS_FORMAT_HSS, pk, pk_len, sig, sig_len);

while((rc == NOXTLS_RETURN_SUCCESS) && ((chunk = next_image_chunk(&chunk_len)) != NULL)) {
    rc = noxtls_hss_verify_update(&ctx, chunk, chunk_len);
}
if(rc == NOXTLS_RETURN_SUCCESS) {
    rc = noxtls_hss_verify_final(&ctx);
}
/* boot only if rc == NOXTLS_RETURN_SUCCESS */
```

## Key generation

```c
noxtls_return_t noxtls_hss_keygen(const noxtls_hss_params_t *params,
                                  const uint8_t *seed, const uint8_t *id,
                                  uint8_t *public_key, uint32_t public_key_len,
                                  uint8_t *private_key, uint32_t private_key_len);
```

Generates a key pair. The top tree is derived from I and SEED as in RFC 8554 Appendix A.

- `seed`: SEED (n bytes of the level-0 hash), or NULL to draw it from the DRBG.
- `id`: I (16 bytes), or NULL to draw it from the DRBG.
- `public_key`: at least `noxtls_hss_public_key_len(params)` bytes.
- `private_key`: at least `NOXTLS_HSS_PRIVATE_KEY_LEN` bytes; receives the blob with counter 0.

Pass NULL for both in production; the library then uses an AES-256 CTR_DRBG seeded from the
configured entropy source (see [DRBG](/docs/api/drbg)). Explicit `seed` and `id` exist for known
answer tests (RFC 8554 and ACVP vectors). Never reuse a seed for a second key: the same seed gives the
same one-time keys.

Cost: 2^h_0 leaf computations (the top tree only), for example about 9 x 10^9 hashes for H20/W8.
Stack about 2.1 KB on Cortex-M4, no heap. Store the new blob before using it.

```c
noxtls_hss_params_t p = { 0 };
uint8_t pk[NOXTLS_HSS_MAX_PUBLIC_KEY_LEN];
uint8_t sk[NOXTLS_HSS_PRIVATE_KEY_LEN];
noxtls_return_t rc;

p.format = NOXTLS_LMS_FORMAT_HSS;
p.levels = 2U;
p.lms_type[0] = NOXTLS_LMS_TYPE_SHA256_M32_H10;
p.ots_type[0] = NOXTLS_LMOTS_TYPE_SHA256_N32_W4;
p.lms_type[1] = NOXTLS_LMS_TYPE_SHA256_M32_H10;
p.ots_type[1] = NOXTLS_LMOTS_TYPE_SHA256_N32_W4;
rc = noxtls_hss_keygen(&p, NULL, NULL, pk, (uint32_t)sizeof(pk), sk, (uint32_t)sizeof(sk));
/* pk: 60 bytes (noxtls_hss_public_key_len(&p)); sk: 168 bytes, counter 0 */
```

### Private key format

The private key is a NoxTLS-specific 168-byte blob (big-endian). It is not interchangeable with
other LMS implementations; public keys and signatures use the standard RFC 8554 encodings.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | `"NXHS"` |
| 4 | 1 | version (1) |
| 5 | 1 | format |
| 6 | 1 | L |
| 7 | 1 | 0 |
| 8 | 64 | 8 x (u32 `lms_type`, u32 `ots_type`) |
| 72 | 8 | counter: first index not yet reserved |
| 80 | 16 | I |
| 96 | 32 | SEED (n bytes, zero padded) |
| 128 | 32 | T[1], the top root (n bytes, zero padded) |
| 160 | 8 | first 8 bytes of SHA-256(bytes 0..159) |

The lower-level trees are derived from the parent's I, SEED and leaf index (the hash-sigs
convention), and the LM-OTS randomizer C is pseudo-random. The whole HSS state is therefore the
single 64-bit counter.

### `noxtls_hss_private_key_info`

```c
noxtls_return_t noxtls_hss_private_key_info(const uint8_t *private_key, uint32_t private_key_len,
                                            noxtls_hss_params_t *params, uint64_t *next_index,
                                            uint64_t *remaining);
```

Checks a blob and reads its parameter set, its counter and the signatures left after it. Each output
may be NULL. Returns `NOXTLS_RETURN_BAD_DATA` for a corrupt blob (checksum, header, parameters, or a
counter beyond the key size). Use it to pick the newest valid slot at boot.

## Stateful signing

### `noxtls_hss_key_load`

```c
noxtls_return_t noxtls_hss_key_load(noxtls_hss_key_t *key,
                                    const uint8_t *private_key, uint32_t private_key_len,
                                    uint8_t *workspace, uint32_t workspace_len,
                                    uint32_t subtree_height, uint32_t flags,
                                    noxtls_hss_persist_fn persist, void *persist_user);
```

Loads a blob into a working key. The library copies what it needs; it does not write to
`private_key`.

- `workspace`: caller buffer, 4-byte aligned, at least
  `noxtls_hss_workspace_len(params, subtree_height)` bytes. NULL allocates it with `NOXTLS_MALLOC`;
  `noxtls_hss_key_free()` then frees it.
- `subtree_height`: traversal sublevel height s, 0 for the default 5, at most 25.
- `flags`: `NOXTLS_HSS_LOAD_REUSE_WORKSPACE`, `NOXTLS_HSS_KEY_FAULT_HARDENING`,
  `NOXTLS_HSS_KEY_NO_SELF_VERIFY`.
- `persist`, `persist_user`: the mandatory persistence callback and its context.

Unless a valid workspace is reused, loading rebuilds the traversal state. That costs about
sum(2^h_i) leaf computations, which is at least the cost of key generation. Stack at most 1.7 KB on
Cortex-M4.

Returns `NOXTLS_RETURN_NULL` (including a missing callback), `NOXTLS_RETURN_INVALID_PARAM`,
`NOXTLS_RETURN_INVALID_KEY_SIZE`, `NOXTLS_RETURN_BAD_DATA` (corrupt blob, a root that does not match
the SEED, or a detected rollback) or `NOXTLS_RETURN_NOT_ENOUGH_MEMORY` (short workspace or failed
allocation).

| Flag | Effect |
| --- | --- |
| `NOXTLS_HSS_LOAD_REUSE_WORKSPACE` | Keep a valid workspace from an earlier session instead of rebuilding it |
| `NOXTLS_HSS_KEY_FAULT_HARDENING` | Compute each new child root twice before signing it |
| `NOXTLS_HSS_KEY_NO_SELF_VERIFY` | Skip verifying each signature before release (not recommended) |

### `noxtls_hss_sign`

```c
noxtls_return_t noxtls_hss_sign(noxtls_hss_key_t *key,
                                const uint8_t *message, uint32_t message_len,
                                uint8_t *signature, uint32_t signature_cap,
                                uint32_t *signature_len);
```

Signs with the next one-time key, persisting state first when needed. `signature_cap` must be at
least `noxtls_hss_signature_len()`; `*signature_len` is set to the length on success and 0 otherwise.
Stack at most 1.5 KB on Cortex-M4.

- `NOXTLS_RETURN_SUCCESS`: signature written.
- `NOXTLS_RETURN_KEY_EXHAUSTED`: no signatures left.
- The persistence callback's error code: persisting failed; nothing was signed, the output is
  untouched and the index is still available.
- `NOXTLS_RETURN_FAILED`: the self-check failed. The output is wiped, the index is burned, and the
  workspace is rebuilt on the next call.
- `NOXTLS_RETURN_INVALID_PARAM`: `signature_cap` too small (no index is consumed).
- `NOXTLS_RETURN_NULL` / `NOXTLS_RETURN_NOT_INITIALIZED`: bad arguments or a key that is not loaded.

When a signature uses the last leaf of a lower-level tree, the same call builds the next tree
(about 2^h leaf computations for that level). Expect that latency spike once every 2^h_(L-1)
signatures.

### Reservation and status

```c
noxtls_return_t noxtls_hss_key_reserve(noxtls_hss_key_t *key, uint32_t count);
noxtls_return_t noxtls_hss_key_set_reserve(noxtls_hss_key_t *key, uint32_t count);
uint64_t noxtls_hss_key_remaining(const noxtls_hss_key_t *key);
noxtls_return_t noxtls_hss_key_public_key(const noxtls_hss_key_t *key, uint8_t *public_key,
                                          uint32_t public_key_cap, uint32_t *public_key_len);
void noxtls_hss_key_free(noxtls_hss_key_t *key);
```

- `noxtls_hss_key_reserve()`: persist a reservation of `count` (>= 1) more indices now. The
  reservation is capped at the key size. Returns the callback's error code on failure, or
  `NOXTLS_RETURN_KEY_EXHAUSTED`.
- `noxtls_hss_key_set_reserve()`: number of indices `noxtls_hss_sign()` reserves per persist
  (default 1, `count` >= 1).
- `noxtls_hss_key_remaining()`: signatures left, 0 if exhausted or not loaded.
- `noxtls_hss_key_public_key()`: write the public key of a loaded key.
- `noxtls_hss_key_free()`: wipe the working key and free a library-allocated workspace. A caller
  workspace is left in place (it holds only public data).

### Example: signer with A/B flash slots

The flash functions are application code. `app_flash_write()` must erase, program and read back the
slot, and return 0 only when the data is stored.

```c
#include <stdint.h>
#include "pkc/lms/noxtls_lms.h"
#include "common/noxtls_ct.h"

extern int app_flash_write(uint32_t slot, const uint8_t *data, uint32_t len);
extern int app_flash_read(uint32_t slot, uint8_t *data, uint32_t len);

typedef struct
{
    uint32_t next_slot; /* slot (0 or 1) the next persist overwrites */
} app_key_store_t;

static app_key_store_t g_store;
static noxtls_hss_key_t g_key;
/* 4-byte aligned workspace; 8 KB covers e.g. LMS H10/W4 with s = 5 (6568 bytes). */
static uint32_t g_ws[8192U / 4U];

static noxtls_return_t app_persist(void *user, const uint8_t *private_key, uint32_t private_key_len)
{
    app_key_store_t *store = (app_key_store_t *)user;

    if(app_flash_write(store->next_slot, private_key, private_key_len) != 0) {
        return NOXTLS_RETURN_FAILED; /* nothing is signed */
    }
    store->next_slot ^= 1U; /* the other slot keeps the previous good copy */
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t app_signer_open(void)
{
    uint8_t blob[2][NOXTLS_HSS_PRIVATE_KEY_LEN];
    uint64_t next[2] = { 0U, 0U };
    uint32_t ok[2] = { 0U, 0U };
    uint32_t pick = 0U;
    uint32_t i = 0U;
    noxtls_return_t rc = NOXTLS_RETURN_BAD_DATA;

    /* Pick the valid slot (checksum OK) with the highest counter. */
    for(i = 0U; i < 2U; i++) {
        if((app_flash_read(i, blob[i], NOXTLS_HSS_PRIVATE_KEY_LEN) == 0) &&
           (noxtls_hss_private_key_info(blob[i], NOXTLS_HSS_PRIVATE_KEY_LEN, NULL, &next[i], NULL) ==
            NOXTLS_RETURN_SUCCESS)) {
            ok[i] = 1U;
        }
    }
    if((ok[0] != 0U) || (ok[1] != 0U)) {
        pick = ((ok[1] != 0U) && ((ok[0] == 0U) || (next[1] > next[0]))) ? 1U : 0U;
        g_store.next_slot = pick ^ 1U;
        rc = noxtls_hss_key_load(&g_key, blob[pick], NOXTLS_HSS_PRIVATE_KEY_LEN,
                                 (uint8_t *)g_ws, (uint32_t)sizeof(g_ws),
                                 5U, 0U, app_persist, &g_store);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_hss_key_set_reserve(&g_key, 16U); /* one flash write per 16 signatures */
    }
    noxtls_secure_zero(blob, sizeof(blob));
    return rc;
}

noxtls_return_t app_sign(const uint8_t *msg, uint32_t msg_len,
                         uint8_t *sig, uint32_t sig_cap, uint32_t *sig_len)
{
    noxtls_return_t rc = noxtls_hss_sign(&g_key, msg, msg_len, sig, sig_cap, sig_len);

    if(rc == NOXTLS_RETURN_KEY_EXHAUSTED) {
        /* no one-time keys left: provision a new key pair */
    }
    return rc; /* anything but SUCCESS: no signature was produced */
}

void app_signer_close(void)
{
    noxtls_hss_key_free(&g_key);
}
```

## Traversal workspace

The signer keeps a workspace with the tree nodes it needs for authentication paths. Each LMS tree is
split into sublevels of height s (`subtree_height`). For every sublevel the workspace holds the active
subtree and the next one, which is built incrementally (one leaf per signature and sublevel).

- Cost per signature: about ceil(h/s) leaf computations per tree.
- Memory: about `2 * ceil(h/s) * 2^(s+1) * n` bytes per tree. `noxtls_hss_workspace_len()` gives the
  exact size.
- s = h keeps the whole tree: fastest, largest.

Examples (n = 32):

| Parameters | s | Workspace |
| --- | ---: | ---: |
| LMS H5 / W8 | 5 | about 2.4 KB (2376 bytes) |
| LMS H10 / W4 | 5 | 6.5 KB (6568 bytes) |
| LMS H10 / W4 | 2 | 2.9 KB (2920 bytes) |
| HSS L=2, H10/H10, W4 | 5 | 15.3 KB |

The workspace holds only public data. It may be kept across resets, for example in retained RAM, and
passed back with `NOXTLS_HSS_LOAD_REUSE_WORKSPACE` to skip the rebuild. The library checks that it
belongs to the key and is consistent; otherwise it rebuilds it. A workspace whose index is ahead of
the blob counter is reported as a rollback (`NOXTLS_RETURN_BAD_DATA`).

## Performance and memory

- **Key generation and loading.** Keygen costs 2^h_0 leaf computations, a cold load sum(2^h_i). Each
  leaf costs about p * (2^W - 1) hashes (see [Sizes](#sizes)). For H15 and larger, or W8, generate
  keys off-device and keep the workspace in retained RAM where possible.
- **Hash choice.** The SHAKE sets are several times slower than SHA-256 in this library.
- **Stack (Cortex-M4):** verify about 1.0 to 1.3 KB; keygen about 2.1 KB; sign at most 1.5 KB; key
  load at most 1.7 KB. No heap, except the optional workspace allocation in `noxtls_hss_key_load()`.
- **Flash (Cortex-M4):** verify only about 3.9 KB of LMS code (10.7 KB linked, with SHA-256);
  verify, keygen and sign about 15 KB of LMS code.

## Configuration

| Macro | Default | Meaning |
| --- | --- | --- |
| `NOXTLS_FEATURE_LMS_HSS` | 0 | Enables the LMS/HSS API (CMake: `-DNOXTLS_CFG_FEATURE_LMS_HSS=ON`) |
| `NOXTLS_FEATURE_SHA3` | Profile dependent (CMake: ON) | Required for the SHAKE256 parameter sets |

LMS has no other build-time knobs. Self-verification, fault hardening and the traversal height are
chosen per key at load time.

## Legacy preset API

A small preset API covers the RFC 8554 SHA-256 sets with LMOTS_SHA256_N32_W8.

| Preset | Parameters | Public key | Secret key | Signature |
| --- | --- | ---: | ---: | ---: |
| `NOXTLS_LMS_SHA256_M32_H5` | LMS H5 / W8 | 56 | 168 | 1292 |
| `NOXTLS_LMS_SHA256_M32_H10` | LMS H10 / W8 | 56 | 168 | 1452 |
| `NOXTLS_LMS_SHA256_M32_H15` | LMS H15 / W8 | 56 | 168 | 1612 |
| `NOXTLS_HSS_SHA256_M32_H10_D2` | HSS L=2, H10/H10, W8 | 60 | 168 | 2964 |
| `NOXTLS_HSS_SHA256_M32_H15_D2` | HSS L=2, H15/H15, W8 | 60 | 168 | 3284 |

```c
noxtls_return_t noxtls_hss_params_from_preset(noxtls_lms_param_t param, noxtls_hss_params_t *params);
uint32_t noxtls_lms_public_key_len(noxtls_lms_param_t param);
uint32_t noxtls_lms_secret_key_len(noxtls_lms_param_t param);
uint32_t noxtls_lms_signature_len(noxtls_lms_param_t param);
noxtls_return_t noxtls_lms_keygen(noxtls_lms_param_t param,
                                  uint8_t *public_key, uint32_t public_key_len,
                                  uint8_t *secret_key, uint32_t secret_key_len);
noxtls_return_t noxtls_lms_sign(noxtls_lms_param_t param, const uint8_t *secret_key,
                                const uint8_t *message, uint32_t message_len,
                                uint8_t *signature, uint32_t *signature_len);
noxtls_return_t noxtls_lms_verify(noxtls_lms_param_t param, const uint8_t *public_key,
                                  const uint8_t *message, uint32_t message_len,
                                  const uint8_t *signature, uint32_t signature_len);
```

- `noxtls_lms_keygen()`: random key pair (`noxtls_hss_keygen()` with DRBG SEED and I). The buffer
  lengths must equal `noxtls_lms_public_key_len()` and `NOXTLS_HSS_PRIVATE_KEY_LEN`. Load the secret
  key with `noxtls_hss_key_load()` to sign.
- `noxtls_lms_sign()`: always `NOXTLS_RETURN_NOT_SUPPORTED` (see
  [above](#why-noxtls_lms_sign-returns-noxtls_return_not_supported)).
- `noxtls_lms_verify()`: the public key must be `noxtls_lms_public_key_len(param)` bytes, and every
  level of the key and signature must use the preset's typecodes. Returns `NOXTLS_RETURN_SUCCESS`,
  `NOXTLS_RETURN_FAILED`, or `NOXTLS_RETURN_INVALID_PARAM` for a key of another parameter set.

`NOXTLS_LMS_MAX_PUBLIC_KEY_LEN` (64), `NOXTLS_LMS_MAX_SECRET_KEY_LEN` (256) and
`NOXTLS_LMS_MAX_SIGNATURE_LEN` (8192) bound the presets only.

## Migrating from 0.3.14

- `noxtls_lms_sign()` now always returns `NOXTLS_RETURN_NOT_SUPPORTED`. Move signers to
  `noxtls_hss_key_load()` + `noxtls_hss_sign()` with a persistence callback.
- `noxtls_lms_keygen()` and `noxtls_lms_verify()` now work (they were stubs).
- `noxtls_lms_secret_key_len()` now returns 168 (`NOXTLS_HSS_PRIVATE_KEY_LEN`); it was 128. Resize
  stored key slots.

## X.509 and TLS status

- LMS/HSS is not wired into X.509 certificate parsing or the TLS stack. Use the API directly, for
  example for firmware signatures.
- The realistic future use is certificate-chain verification: RFC 9802 defines HSS/LMS identifiers
  for X.509 certificates and RFC 9708 for CMS. Both use the HSS encoding, also for L = 1.
- Stateful keys are unsuitable for TLS handshake signing. Every handshake would consume a one-time
  key and need a persistent write, and server clusters or snapshots would risk index reuse.
