---
sidebar_position: 10
title: CC13xx Accelerator Callbacks
description: "NoxTLS documentation: selecting and binding the CC13xx AES and P-256 accelerator callback ports, and the concurrency contract."
---

# CC13xx accelerator callbacks

NoxTLS can use the CC13xx AES engine and public-key accelerator (PKA) through
callbacks that your application supplies. NoxTLS has no vendor SDK, driver or
scheduler dependency: your callbacks drive the hardware, and NoxTLS decides
when to call them and what to do with the result.

The callbacks share two independently guarded engines:

| Port | What it accelerates | Software path used when |
|------|---------------------|-------------------------|
| AES/SHA | AES block encrypt/decrypt (128/192/256-bit keys), bounded batches used by CTR DRBG, optional whole-record GCM/CCM, and SHA-224/256 and SHA-384/512 compression. Other modes use block composition. | the selected callback is unbound, the shared engine is busy, or the callback returns `NOXTLS_RETURN_NOT_SUPPORTED` before progress |
| P-256 | secp256r1 scalar multiplication behind `noxtls_ecc_point_multiply()` (ECDH, ECDSA, SPAKE2+, BLE pairing, ...) | no P-256 callback is bound, the PKA is busy, the curve is not P-256, or the callback returns `NOXTLS_RETURN_NOT_SUPPORTED` |
| X25519 | RFC 7748 public-key/shared-secret operations, sharing the P-256 guard | no X25519 callback is bound, the PKA is busy, or the callback declines before progress |

## Selecting the ports

| CMake option | Header macro | Effect |
|--------------|--------------|--------|
| `NOXTLS_CFG_FEATURE_CC13XX_AES_ACCEL` | `NOXTLS_FEATURE_CC13XX_AES_ACCEL` | Compiles the AES port. Needs `NOXTLS_CFG_FEATURE_AES`. |
| `NOXTLS_CFG_FEATURE_CC13XX_P256_ACCEL` | `NOXTLS_FEATURE_CC13XX_P256_ACCEL` | Compiles the P-256 port. Needs `NOXTLS_CFG_FEATURE_ECC`. |
| `NOXTLS_CFG_FEATURE_CC13XX_X25519_ACCEL` | `NOXTLS_FEATURE_CC13XX_X25519_ACCEL` | Selects the optional X25519 hook. Needs X25519 for algorithm calls. |
| `NOXTLS_CFG_FEATURE_CC13XX_HW_ACCEL` | `NOXTLS_FEATURE_CC13XX_HW_ACCEL` | Umbrella: enables AES/SHA, P-256 and X25519 hooks. Unbound callbacks retain software behavior. |

All four are `OFF` by default. The shared binding
(`noxtls-lib/common/noxtls_cc13xx_crypto.c`) is compiled when any port is.
A port that is not selected is replaced by the default no-accelerator port, so
its engine always uses software, even if your binding supplies a callback for
it.

For example, an image that only wants the PKA for P-256:

```bash
cmake -S noxtls -B build -DNOXTLS_CFG_FEATURE_CC13XX_P256_ACCEL=ON
```

When the umbrella is `ON` it turns all three selections on, overriding a per-engine
option set to `OFF` at the same time. On the C side,
`NOXTLS_FEATURE_CC13XX_HW_ACCEL=1` has the same effect for builds that define
the macros directly (Kconfig, custom build systems).

Each port excludes other accelerator backends for the same engine:
`noxtls_check_config.h` rejects the AES port together with nRF52, STM32, NoxV or
nRF54 acceleration, and the P-256 port together with NoxV or nRF54
acceleration. CMake also rejects either port on ESP-IDF, and the P-256 port
together with the Nordic CC310/CC312/CRACEN P-256 backends.

## Binding the callbacks

```c
#include "noxtls_cc13xx_crypto.h"

static noxtls_return_t my_aes(void *ctx, bool decrypt, const uint8_t *key,
    uint32_t key_length, const uint8_t in[16], uint8_t out[16]);
static noxtls_return_t my_p256(void *ctx, const uint8_t scalar[32],
    const uint8_t x[32], const uint8_t y[32], uint8_t rx[32], uint8_t ry[32]);

const noxtls_cc13xx_crypto_binding_t binding = {
    .context = &my_driver,
    .aes_block = my_aes,       /* or NULL: AES stays in software */
    .p256_multiply = my_p256,  /* or NULL: P-256 stays in software */
};
noxtls_return_t rc = noxtls_cc13xx_crypto_bind(&binding);
```

`noxtls_cc13xx_crypto_bind()` copies the structure. Pass `NULL` to unbind. The
`context` pointer must stay valid until you unbind.

AES and PKA drivers with different owners can bind independently:

```c
noxtls_cc13xx_crypto_bind_aes(my_aes, &aes_driver);
noxtls_cc13xx_crypto_bind_p256(my_p256, &pka_driver);
```

These functions replace only their selected callback/context and require only that
engine to be idle. Passing a NULL callback unbinds just that callback. Existing
`noxtls_cc13xx_crypto_bind()` behavior remains whole-binding replacement, including
clearing the GCM, CCM, SHA and X25519 bindings after a successful replacement.

`noxtls_cc13xx_crypto_bind_gcm()` installs an optional whole-record GCM callback
with its own persistent context. It shares the AES guard with block and batch
operations. The AES port passes 12-byte nonces and 16-byte tags in
`noxtls_cc13xx_gcm_request_t`. A decrypt callback must verify `expected_tag` in
constant time before returning success. Native failures and authentication errors
clear output; encryption failures clear the output tag too. NOT_SUPPORTED is only
permitted before modifying output, so the existing GCM implementation can safely
handle an unbound, busy or deliberately declined request in software. NoxTLS adds
no record or DMA buffers for this hook and has no vendor driver dependency.

`noxtls_cc13xx_crypto_bind_ccm()` adds a separate whole-record CCM callback and
context. Its request carries nonce and tag lengths alongside the input, output
and authentication fields. The callback must verify the received tag before
reporting decryption success and erase unauthenticated plaintext. It shares the
AES guard and adds no record workspace.

`noxtls_cc13xx_crypto_bind_sha256()` binds compression of eight numeric chaining
words and complete 64-byte blocks. NoxTLS handles SHA-224/256 initial values and
padding. Candidate chaining words are published only on success; an admitted
hardware error propagates through the SHA core. Unbound or declined requests use
software. The callback shares the AES guard.

`noxtls_cc13xx_crypto_bind_x25519()` installs an independent callback/context
under the PKA guard. It receives 32-byte little-endian scalar and u values and
must implement RFC 7748 decoding, clamping and low-order rejection. Output is
staged until success and erased on hard error. The hook adds no persistent
arithmetic buffers and leaves the P-256 binding intact.

## Binding contract

### Engines and concurrency

- The AES engine and the PKA are independent. Each has its own busy guard, so
  an AES request can run while a P-256 multiplication is in progress, for
  example from another task while the PKA callback waits.
- The same engine is never entered twice. A request that finds its engine
  busy does not call your callback; it returns `NOXTLS_RETURN_NOT_SUPPORTED`
  and the AES or ECC core computes that request in software. Nothing ever
  waits for an engine.
- The busy guards are atomic test-and-set flags (C11 `atomic_flag`, or the
  GCC/Clang or MSVC equivalent when the library is compiled as C99), so two
  tasks, or a task and an interrupt handler, can never both own one engine.
- A batch of AES blocks (used by the CTR DRBG) holds the AES engine for the
  whole batch, so it can only be refused before any block is processed.

### Callbacks

- Callbacks are synchronous: return only after the hardware has finished or
  the job has been cancelled.
- Callbacks may block or yield to other tasks while waiting. They should not
  disable interrupts for the duration of the operation.
- A callback may call back into NoxTLS. A request for its own engine falls back
  to software; a request for the other engine may use the hardware.
- Never log keys, scalars or intermediate values.

### Return codes

| Callback returns | NoxTLS does |
|------------------|-------------|
| `NOXTLS_RETURN_SUCCESS` | Uses the output. P-256 outputs are first checked to be valid curve points. |
| `NOXTLS_RETURN_NOT_SUPPORTED` | Computes the request in software. Return it only when the operation was not started, for example a key size the hardware does not support. |
| Any other value | Returns that error to the caller and erases the output. No software result is substituted, so a hardware fault or timeout is never reported as success. |

In a batch, `NOXTLS_RETURN_NOT_SUPPORTED` from any block after the first is
reported as `NOXTLS_RETURN_FAILED`, because in-place input may already have
been overwritten.

### Threads, interrupts and binding

- Requests may come from any task. A request from an interrupt handler is safe
  (it either runs or falls back to software), but a callback that blocks must
  not be reached from interrupt context.
- `noxtls_cc13xx_crypto_bind()` succeeds only while both engines are idle.
  While either engine is in use, including from inside a callback, it returns
  `NOXTLS_RETURN_NOT_INITIALIZED` and leaves the binding unchanged. Requests
  made during a bind fall back to software.
- `noxtls_cc13xx_crypto_has_p256()` reports whether a P-256 callback is bound,
  not whether the PKA is free or working.

### Diagnostics

With the P-256 port, `noxtls_ecc_accel_operation_count()` counts multiplications
completed by the PKA and `noxtls_ecc_accel_fallback_count()` counts every
multiplication done in software, including requests that found the PKA busy or
unbound. Both are updated atomically and saturate at `UINT32_MAX`.
`noxtls_ecc_accel_last_rc()` reports the last port result.

## Upgrading from 0.3.2

- Builds that set `NOXTLS_CFG_FEATURE_CC13XX_HW_ACCEL` get the existing AES and
  P-256 ports plus the optional X25519 hook. New callbacks remain unbound until
  the application installs them; existing applications retain software behavior.
- A request that finds its engine busy now returns `NOXTLS_RETURN_NOT_SUPPORTED`
  (software fallback) instead of `NOXTLS_RETURN_NOT_INITIALIZED`, and AES and
  P-256 no longer block each other. Code that called
  `noxtls_cc13xx_aes_block()` or `noxtls_cc13xx_p256_multiply()` directly and
  expected `NOXTLS_RETURN_NOT_INITIALIZED` for reentry must treat
  `NOXTLS_RETURN_NOT_SUPPORTED` as "use software" instead.
- An image that binds only the PKA no longer needs to remove the AES port from
  its build: select `NOXTLS_CFG_FEATURE_CC13XX_P256_ACCEL` alone.
- `noxtls_cc13xx_aes_blocks()` is new; it runs a batch while holding the AES
  engine.

## Optional SHA-384/512 callback

Select the CC13xx AES/SHA port and bind `noxtls_cc13xx_crypto_bind_sha512()`
with a synchronous raw-block callback. It receives eight numerical 64-bit
chaining words and complete 128-byte blocks. NoxTLS supplies padding and
retains the buffered bytes and message length. The same hook supports SHA-384,
SHA-512, SHA-512/224 and SHA-512/256 through their different initial states.

SHA-512 shares the existing AES/SHA guard. The binding stages 64 bytes of
chaining state on the stack and publishes them only on success. An unbound or
busy callback uses software. An admitted failure is returned without software
substitution; finalization erases the failed digest. Whole-binding unbind also
clears the SHA-512 callback. No driver or DMA buffer is allocated by NoxTLS.

The CC1354 driver was checked on silicon with single-block, multi-block,
batch-boundary and resumed SHA-512 known answers. A separate SRAM test using
the application adapter and its actual NoxTLS libraries covers startup and all
four hash variants. This does not accelerate Ed25519 point arithmetic.
