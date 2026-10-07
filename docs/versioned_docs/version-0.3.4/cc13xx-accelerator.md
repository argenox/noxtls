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

There are two independent ports:

| Port | What it accelerates | Software path used when |
|------|---------------------|-------------------------|
| AES | AES block encrypt/decrypt (128/192/256-bit keys), and bounded batches used by CTR DRBG. AES modes (CBC, CTR, GCM, CCM, ...) run in software on top of it. | no AES callback is bound, the AES engine is busy, or the callback returns `NOXTLS_RETURN_NOT_SUPPORTED` |
| P-256 | secp256r1 scalar multiplication behind `noxtls_ecc_point_multiply()` (ECDH, ECDSA, SPAKE2+, BLE pairing, ...) | no P-256 callback is bound, the PKA is busy, the curve is not P-256, or the callback returns `NOXTLS_RETURN_NOT_SUPPORTED` |

## Selecting the ports

| CMake option | Header macro | Effect |
|--------------|--------------|--------|
| `NOXTLS_CFG_FEATURE_CC13XX_AES_ACCEL` | `NOXTLS_FEATURE_CC13XX_AES_ACCEL` | Compiles the AES port. Needs `NOXTLS_CFG_FEATURE_AES`. |
| `NOXTLS_CFG_FEATURE_CC13XX_P256_ACCEL` | `NOXTLS_FEATURE_CC13XX_P256_ACCEL` | Compiles the P-256 port. Needs `NOXTLS_CFG_FEATURE_ECC`. |
| `NOXTLS_CFG_FEATURE_CC13XX_HW_ACCEL` | `NOXTLS_FEATURE_CC13XX_HW_ACCEL` | Umbrella: enables both ports. Existing builds that use it are unchanged. |

All three are `OFF` by default. The shared binding
(`noxtls-lib/common/noxtls_cc13xx_crypto.c`) is compiled when either port is.
A port that is not selected is replaced by the default no-accelerator port, so
its engine always uses software, even if your binding supplies a callback for
it.

For example, an image that only wants the PKA for P-256:

```bash
cmake -S noxtls -B build -DNOXTLS_CFG_FEATURE_CC13XX_P256_ACCEL=ON
```

When the umbrella is `ON` it turns both ports on, overriding a per-engine
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

- Builds that set `NOXTLS_CFG_FEATURE_CC13XX_HW_ACCEL` get both ports, as before.
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
