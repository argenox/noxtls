---
sidebar_position: 24
title: DRBG
description: "NoxTLS DRBG C API reference for embedded TLS, DTLS, and cryptography."
---

# DRBG

AES CTR_DRBG per NIST SP 800-90A Rev.1, section 10.2.1. Header: `noxtls_drbg.h`.

## Algorithm overview

This module implements CTR_DRBG with AES-128, AES-192 or AES-256. A DRBG expands entropy input into a stream of pseudorandom output, with controlled reseeding. Its security depends on the entropy source, correct instantiation and the reseed policy.

Security strength equals the AES key length. `seedlen` = key length + 16 bytes (32, 40 or 48 bytes).

Two variants are available:

| Variant | Selected by | Entropy input | Nonce / personalization / additional input |
|---|---|---|---|
| With derivation function (`Block_Cipher_df`, §10.3.2) | `drbg_instantiate()`, or `drbg_instantiate_ex()` with flags 0 | At least the security strength, and entropy + nonce at least 1.5 × the security strength | Any length |
| Without derivation function | `drbg_instantiate_ex(..., DRBG_FLAG_NO_DF, ...)` | Exactly `seedlen` bytes of **full** entropy | No nonce; personalization string and additional input at most `seedlen` bytes (zero padded) |

Use the derivation-function variant unless the entropy source is a validated full-entropy source.

The implementation is validated against all 4,320 AES CTR_DRBG vectors in the NIST CAVP `drbgtestvectors.zip` (CAVS 14.3) files:

- no reseed, prediction resistance false, prediction resistance true;
- each with and without the derivation function.

The unit test `crypto_sym_drbg_sp800_90a_test` runs a 72-vector subset by default. Pass the CAVP `.rsp` files as arguments to run the full set.

### Reseeding and prediction resistance

`drbg_generate()` reseeds from the entropy source before generating when:

- the reseed counter exceeds `DRBG_RESEED_INTERVAL` (2^48 by default, the SP 800-90A maximum; can be lowered with `-D`);
- the instance was instantiated with `DRBG_FLAG_PREDICTION_RESISTANCE`; every request then reseeds with that request's additional input;
- on hosted POSIX systems with `NOXTLS_DRBG_FORK_DETECT`, the call runs in a forked child process. A child never repeats its parent's output.

A single request is limited to `DRBG_MAX_BITS_PER_REQUEST` (2^19 bits, 65,536 bytes).

### Error states

- **AES failure:** the output buffer and the whole state are zeroed, and the instance must be instantiated again.
- **Entropy source failure:** during a reseed this leaves the state unchanged and the call returns an error. During instantiation the state stays zeroed.
- **`noxtls_drbg_uninstantiate()`:** zeroes the whole state (§9.4).

### Shared PKC DRBG

Public-key operations that draw randomness from the shared PKC DRBG (`noxtls_pkc_rng.c`), such as ECDSA nonces, use one instance per slot. That instance is instantiated with internally drawn entropy and a personalization string. It also reseeds every `NOXTLS_PKC_RNG_RESEED_INTERVAL` requests (default 1024; 0 leaves only the 2^48 limit).

Other DRBG users create a fresh instance from platform entropy for each use. These include TLS randoms, session IDs and tickets, CBC IVs, DH, DSA, ML-KEM, ML-DSA and SLH-DSA.

## Pros and cons

**Pros**

- Standardized design with a clear security model, validated against NIST CAVP vectors.
- Deterministic generation is efficient for repeated key material requests.
- Selectable entropy source, with a documented contract for custom callbacks.
- Small: `drbg_state_t` is 64 bytes, with no heap use.

**Cons**

- Not a replacement for true entropy: weak entropy input undermines security.
- Noise-source health tests (SP 800-90B) are the port's responsibility.
- More complex than calling the OS CSPRNG directly when no portability policy requires DRBG control.

## When to use

- Use it when you need a portable internal CSPRNG with explicit lifecycle control.
- It fits embedded and controlled environments where the integrator manages the entropy plumbing.
- If a trusted platform CSPRNG is available, calling the OS random APIs directly may be simpler.

## Types

### `drbg_aes_type_t`

DRBG security strength:

- `DRBG_AES128`
- `DRBG_AES192`
- `DRBG_AES256`

### Instantiation flags

Flags passed to `drbg_instantiate_ex()` are fixed for the life of the instantiation:

- `DRBG_FLAG_NO_DF`: no derivation function (§10.2.1.3.1, 10.2.1.4.1, 10.2.1.5.1).
- `DRBG_FLAG_PREDICTION_RESISTANCE`: every `drbg_generate()` first reseeds (§9.3.1).

### `noxtls_entropy_source_t`

Entropy source selection:

- `NOXTLS_ENTROPY_SOURCE_AUTO`
- `NOXTLS_ENTROPY_SOURCE_WINDOWS_CSPRNG`
- `NOXTLS_ENTROPY_SOURCE_UNIX_URANDOM`
- `NOXTLS_ENTROPY_SOURCE_CUSTOM`
- `NOXTLS_ENTROPY_SOURCE_DUMMY`

### `noxtls_entropy_cb_t`

```c
typedef noxtls_return_t (*noxtls_entropy_cb_t)(uint8_t *entropy_cb_out, uint32_t entropy_cb_out_len);
```

Custom entropy callback. It is used for `NOXTLS_ENTROPY_SOURCE_CUSTOM`, and as the AUTO source on Zephyr and in `NOXTLS_CUSTOM_ENTROPY_ONLY` builds.

Contract for ports:

- **Exact output.** Fill exactly `entropy_cb_out_len` bytes and return `NOXTLS_RETURN_SUCCESS`, or return another code; the DRBG then fails closed. Never report success for fewer, stale or repeated bytes.
- **Full entropy per byte.** Every byte must carry 8 bits of min-entropy. Suitable sources are:
  - an OS CSPRNG;
  - an SP 800-90B validated conditioned source;
  - a raw TRNG that the port conditions or oversamples.
- **Request sizes:**
  - instantiation: 1.5 × the security strength (entropy input and nonce in one request, as SP 800-90C allows);
  - reseed: the security strength;
  - no-df variant: `seedlen` bytes.
- **Health tests.** Noise-source health tests are the port's job: the SP 800-90B §4.4 repetition count and adaptive proportion tests, and start-up tests. The library only rejects a block whose bytes are all equal (a stuck source).
- **Thread safety.** The callback may be called from any context that draws random bits, such as TLS handshakes, key generation, signing and reseeds. It must be thread-safe if those are.

### `drbg_state_t`

DRBG runtime state, 64 bytes:

- `V`
- `Key`
- 64-bit reseed counter
- AES variant
- instantiated flag
- instantiation flags
- the fork id recorded at the last (re)seed

## Configuration

| Macro | Default | Meaning |
|---|---|---|
| `DRBG_RESEED_INTERVAL` | `2^48` | Generate requests between automatic reseeds |
| `NOXTLS_PKC_RNG_RESEED_INTERVAL` | `1024` | Requests between reseeds of the shared PKC DRBG (0 = only `DRBG_RESEED_INTERVAL`) |
| `NOXTLS_DRBG_FORK_DETECT` | 1 on hosted POSIX, else 0 | Reseed in a forked child before its first output |

## API

### `noxtls_drbg_get_entropy`

```c
noxtls_return_t noxtls_drbg_get_entropy(uint8_t *entropy_out, uint32_t entropy_out_len);
```

Fills the buffer from the configured entropy source. It returns `NOXTLS_RETURN_FAILED` when the source cannot deliver, and never falls back to predictable bytes. `/dev/urandom` reads loop on short reads and `EINTR`.

### `noxtls_drbg_set_entropy_source` / `noxtls_drbg_get_entropy_source`

```c
void noxtls_drbg_set_entropy_source(noxtls_entropy_source_t source);
noxtls_entropy_source_t noxtls_drbg_get_entropy_source(void);
```

Select or query the entropy source backend.

### `noxtls_drbg_set_entropy_callback` / `noxtls_drbg_get_entropy_callback`

```c
void noxtls_drbg_set_entropy_callback(noxtls_entropy_cb_t cb);
noxtls_entropy_cb_t noxtls_drbg_get_entropy_callback(void);
```

Set or query the custom entropy callback.

### `drbg_instantiate`

```c
noxtls_return_t drbg_instantiate(drbg_state_t *state,
                                 drbg_aes_type_t aes_type,
                                 const uint8_t *entropy_input,
                                 uint32_t entropy_input_len,
                                 const uint8_t *nonce,
                                 uint32_t nonce_len,
                                 const uint8_t *personalization_string,
                                 uint32_t pers_len);
```

Instantiates the derivation-function variant without prediction resistance (§10.2.1.3.2). This is equivalent to `drbg_instantiate_ex(state, aes_type, 0U, ...)`.

- Pass `entropy_input = NULL` and length 0 to draw entropy internally (recommended).
- Caller-supplied entropy must be at least the security strength (key length in bytes). Entropy plus nonce must be at least 1.5 × the security strength. Shorter input returns `NOXTLS_RETURN_NOT_ENOUGH_ENTROPY`.

On failure the state is zeroed.

### `drbg_instantiate_ex`

```c
noxtls_return_t drbg_instantiate_ex(drbg_state_t *state,
                                    drbg_aes_type_t aes_type,
                                    uint32_t flags,
                                    const uint8_t *entropy_input,
                                    uint32_t entropy_input_len,
                                    const uint8_t *nonce,
                                    uint32_t nonce_len,
                                    const uint8_t *personalization_string,
                                    uint32_t pers_len);
```

Instantiates with flags (`0`, `DRBG_FLAG_NO_DF`, `DRBG_FLAG_PREDICTION_RESISTANCE`).

With `DRBG_FLAG_NO_DF`:

- the entropy input must be either NULL (seedlen bytes are then drawn from the entropy source, which must be a full-entropy source) or exactly `seedlen` bytes;
- the nonce must be NULL;
- the personalization string must be at most `seedlen` bytes.

### `drbg_generate`

```c
noxtls_return_t drbg_generate(drbg_state_t *state,
                              uint8_t *output_buffer,
                              uint32_t requested_bits,
                              const uint8_t *additional_input,
                              uint32_t add_input_len);
```

Generates `requested_bits` bits into `(requested_bits + 7) / 8` bytes (§10.2.1.5 inside the §9.3.1 Generate function). A partial last byte holds the trailing bits in its most significant bits.

May reseed first (see [Reseeding and prediction resistance](#reseeding-and-prediction-resistance)).

Returns:

- `NOXTLS_RETURN_FAILED` if the state is not instantiated, or if a required reseed could not get entropy (state unchanged);
- `NOXTLS_RETURN_INVALID_PARAM` if the request is too large, or the additional input is too long for the no-df variant;
- the AES error after an AES failure (output and state zeroed).

### `drbg_reseed`

```c
noxtls_return_t drbg_reseed(drbg_state_t *state,
                            const uint8_t *entropy_input,
                            uint32_t entropy_input_len,
                            const uint8_t *additional_input,
                            uint32_t add_input_len);
```

Reseeds the instance (§10.2.1.4).

- Pass `entropy_input = NULL` to draw entropy internally.
- Caller entropy must be at least the key length (df variant) or exactly `seedlen` bytes (no-df variant).
- A length error or entropy failure leaves the state unchanged.

### `drbg_update`

```c
noxtls_return_t drbg_update(drbg_state_t *state,
                            const uint8_t *provided_data,
                            uint32_t provided_data_len);
```

Low-level `CTR_DRBG_Update` (§10.2.1.2) on an instantiated state. `provided_data` may be at most `seedlen` bytes; shorter data is zero padded and NULL means all zero. Applications normally do not call it.

### `noxtls_drbg_uninstantiate`

```c
noxtls_return_t noxtls_drbg_uninstantiate(drbg_state_t *state);
```

Zeroes the whole state (§9.4). Call it when an instance is no longer needed.

## Migrating from 0.3.14 and earlier

- **Output bytes change for the same inputs.** The update, generate and derivation steps now follow SP 800-90A exactly. Code that seeds the DRBG deterministically, for example in tests, sees different output. Take expected values from NIST CAVP vectors.
- **Short entropy is rejected.** `drbg_instantiate()` used to replace caller entropy shorter than `seedlen` with platform entropy silently. It now returns `NOXTLS_RETURN_NOT_ENOUGH_ENTROPY` when the input is below the SP 800-90A minimum.
- **Additional input is no longer truncated** to `seedlen` in the derivation-function variant.
- **`drbg_update()` needs an instantiated state** and at most `seedlen` bytes.
- **Automatic reseeding.** `drbg_generate()` may now reseed from the entropy source by itself, so a custom entropy callback can be called during generate.
