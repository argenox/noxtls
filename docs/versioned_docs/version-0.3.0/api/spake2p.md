---
sidebar_position: 26
title: SPAKE2+ and Matter PASE
description: "NoxTLS SPAKE2+ (RFC 9383 and Matter draft-01 profiles) and Matter PASE C API reference."
keywords:
  - noxtls
  - spake2+
  - rfc 9383
  - matter
  - pase
  - pake
---

# SPAKE2+ and Matter PASE API

Headers: `pake/noxtls_spake2p.h` and `pake/noxtls_matter_pase.h`. Library: `noxtls_pake`. New in 0.3.0. All of it is **off by default**.

For the protocol overview, the differences between the two profiles, configuration knobs, message flow, and test vectors, see the guide [SPAKE2+, Matter PASE and PBKDF2](../spake2p.md). This page lists the public declarations.

## Enablement

| CMake knob | Default | Requires |
|---|---|---|
| `NOXTLS_CFG_FEATURE_SPAKE2P` | OFF | PKC, ECC, SHA-256, HMAC, HKDF, DRBG; at least one profile |
| `NOXTLS_CFG_FEATURE_SPAKE2P_RFC9383` | ON (effective with SPAKE2P) | SPAKE2P |
| `NOXTLS_CFG_FEATURE_SPAKE2P_MATTER` | OFF | SPAKE2P |
| `NOXTLS_CFG_FEATURE_MATTER_PASE` | OFF | SPAKE2P, SPAKE2P_MATTER, [PBKDF2](./kdf.md) |

## Constants

| Macro | Value |
|---|---|
| `NOXTLS_SPAKE2P_SCALAR_SIZE` | 32 (big-endian scalars w0, w1) |
| `NOXTLS_SPAKE2P_POINT_SIZE` | 65 (uncompressed SEC 1 point) |
| `NOXTLS_SPAKE2P_CONFIRMATION_SIZE` | 32 |
| `NOXTLS_SPAKE2P_WS_SIZE` | 80 (w0s ‖ w1s registration input) |
| `NOXTLS_MATTER_PASE_VERIFIER_SIZE` | 97 (w0 ‖ L) |
| `NOXTLS_MATTER_PASE_CONTEXT_SIZE` | 32 |
| `NOXTLS_MATTER_PASE_SESSION_KEY_SIZE` / `NOXTLS_MATTER_PASE_ATTESTATION_CHALLENGE_SIZE` | 16 |
| `NOXTLS_MATTER_PASE_PBKDF_ITERATIONS_MIN` / `_MAX` | 1000 / 100000 |
| `NOXTLS_MATTER_PASE_SALT_MIN_SIZE` / `_MAX_SIZE` | 16 / 32 |

## Types

### `noxtls_spake2p_profile_t`

- `NOXTLS_SPAKE2P_PROFILE_RFC9383`: the RFC 9383 key schedule (standard, default).
- `NOXTLS_SPAKE2P_PROFILE_MATTER`: the draft-bar-cfrg-spake2plus-01 key schedule. Use it only for Matter interoperability.

The two profiles are not interchangeable.

### `noxtls_spake2p_params_t`

Transcript binding inputs: `context`/`context_len`, `id_prover`/`id_prover_len`, `id_verifier`/`id_verifier_len`. A pointer may be `NULL` when its length is 0.

### `noxtls_spake2p_ctx_t`

A caller-allocated exchange context of about 1 KB, which embeds a SHA-256 state. Its fields are private. Release it with `noxtls_spake2p_free()`, which erases every secret.

## SPAKE2+ functions

```c
noxtls_return_t noxtls_spake2p_derive_w0_w1(const uint8_t *ws, uint32_t ws_len,
                                            uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                            uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE]);
noxtls_return_t noxtls_spake2p_compute_L(const uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                         uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE]);

noxtls_return_t noxtls_spake2p_prover_init(noxtls_spake2p_ctx_t *ctx,
                                           noxtls_spake2p_profile_t profile,
                                           const noxtls_spake2p_params_t *params,
                                           const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                           const uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE]);
noxtls_return_t noxtls_spake2p_verifier_init(noxtls_spake2p_ctx_t *ctx,
                                             noxtls_spake2p_profile_t profile,
                                             const noxtls_spake2p_params_t *params,
                                             const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                             const uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE]);

noxtls_return_t noxtls_spake2p_generate_share(noxtls_spake2p_ctx_t *ctx,
                                              uint8_t *share, uint32_t *share_len);
noxtls_return_t noxtls_spake2p_generate_share_with_scalar(noxtls_spake2p_ctx_t *ctx,
                                                          const uint8_t scalar[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                          uint8_t *share, uint32_t *share_len);
noxtls_return_t noxtls_spake2p_process_peer_share(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t *peer_share,
                                                  uint32_t peer_share_len);
noxtls_return_t noxtls_spake2p_get_confirmation(const noxtls_spake2p_ctx_t *ctx,
                                                uint8_t *confirmation,
                                                uint32_t *confirmation_len);
noxtls_return_t noxtls_spake2p_verify_peer_confirmation(noxtls_spake2p_ctx_t *ctx,
                                                        const uint8_t *confirmation,
                                                        uint32_t confirmation_len);
noxtls_return_t noxtls_spake2p_get_shared_key(const noxtls_spake2p_ctx_t *ctx,
                                              uint8_t *key, uint32_t *key_len);
noxtls_return_t noxtls_spake2p_free(noxtls_spake2p_ctx_t *ctx);

const uint8_t *noxtls_spake2p_p256_M(void);
const uint8_t *noxtls_spake2p_p256_N(void);
```

| Function | Notes | Typical errors |
|---|---|---|
| `derive_w0_w1` | Reduces the 80-byte registration output (w0s ‖ w1s) mod n in constant time. | `INVALID_PARAM` (length), `FAILED` (reduced value is zero) |
| `compute_L` | L = w1·G for the verifier record. | `INVALID_PARAM` |
| `prover_init` / `verifier_init` | Erase the context, then absorb Context, the identities, M, and N into the transcript. | `NOT_SUPPORTED` (profile not compiled in), `INVALID_PARAM` (w0/w1 out of range), `BAD_DATA` (L invalid) |
| `generate_share` | Own share from a DRBG ephemeral scalar. | `NOT_INITIALIZED` (wrong state), `INVALID_PARAM` (buffer too small) |
| `generate_share_with_scalar` | Caller-supplied scalar, for known-answer tests or an external TRNG. | as above |
| `process_peer_share` | Validates the peer point, computes Z and V, and derives keys. | `BAD_DATA` (invalid share, or identity Z/V). The context is aborted. |
| `get_confirmation` | Own 32-byte confirmation MAC. | `INVALID_PARAM` (buffer too small) |
| `verify_peer_confirmation` | Constant-time compare. On mismatch the context is aborted, with no retry. | `FAILED` |
| `get_shared_key` | Only after the peer has been confirmed. | `NOT_INITIALIZED` |
| `free` | Erases all secrets and returns the context to EMPTY. | `NULL` |
| `p256_M` / `p256_N` | RFC 9383 section 4 constants in static read-only storage. | n/a |

## Matter PASE functions

```c
int noxtls_matter_pase_passcode_is_valid(uint32_t passcode);

noxtls_return_t noxtls_matter_pase_compute_w0_w1(uint32_t passcode,
                                                 const uint8_t *salt, uint32_t salt_len,
                                                 uint32_t iterations,
                                                 uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                 uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE]);
noxtls_return_t noxtls_matter_pase_compute_verifier(uint32_t passcode,
                                                    const uint8_t *salt, uint32_t salt_len,
                                                    uint32_t iterations,
                                                    uint8_t verifier[NOXTLS_MATTER_PASE_VERIFIER_SIZE]);
noxtls_return_t noxtls_matter_pase_parse_verifier(const uint8_t *verifier, uint32_t verifier_len,
                                                  uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                  uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE]);
noxtls_return_t noxtls_matter_pase_compute_context(const uint8_t *pbkdf_param_request, uint32_t request_len,
                                                   const uint8_t *pbkdf_param_response, uint32_t response_len,
                                                   uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE]);
noxtls_return_t noxtls_matter_pase_initiator_init(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE],
                                                  const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                  const uint8_t w1[NOXTLS_SPAKE2P_SCALAR_SIZE]);
noxtls_return_t noxtls_matter_pase_responder_init(noxtls_spake2p_ctx_t *ctx,
                                                  const uint8_t context[NOXTLS_MATTER_PASE_CONTEXT_SIZE],
                                                  const uint8_t w0[NOXTLS_SPAKE2P_SCALAR_SIZE],
                                                  const uint8_t L[NOXTLS_SPAKE2P_POINT_SIZE]);
noxtls_return_t noxtls_matter_pase_derive_session_keys(const noxtls_spake2p_ctx_t *ctx,
                                                       uint8_t i2r_key[NOXTLS_MATTER_PASE_SESSION_KEY_SIZE],
                                                       uint8_t r2i_key[NOXTLS_MATTER_PASE_SESSION_KEY_SIZE],
                                                       uint8_t attestation_challenge[NOXTLS_MATTER_PASE_ATTESTATION_CHALLENGE_SIZE]);
```

- `passcode_is_valid()` returns 1 for passcodes allowed by Matter Core section 5.1.7.1, otherwise 0.
- `compute_w0_w1()` runs on the commissioner. It computes PBKDF2-HMAC-SHA256 over the passcode encoded as 4 little-endian bytes, with a 16 to 32 byte salt and 1000 to 100000 iterations. Outputs are erased on failure.
- `compute_verifier()` runs at manufacturing and produces w0 ‖ L. `parse_verifier()` runs on the device: it splits a stored verifier and validates it.
- `compute_context()` computes SHA-256("CHIP PAKE V1 Commissioning" ‖ PBKDFParamRequest ‖ PBKDFParamResponse). Pass the exact TLV payload bytes.
- `initiator_init()` / `responder_init()` start a Matter-profile SPAKE2+ exchange with empty identities. After that, use the generic SPAKE2+ calls above.
- `derive_session_keys()` requires a Matter-profile context in the CONFIRMED state. It produces I2RKey, R2IKey, and AttestationChallenge, each 16 bytes, and erases the outputs on failure.

Matter TLV encoding, session IDs, MRP, and the session table belong to the Matter stack, not NoxTLS.
