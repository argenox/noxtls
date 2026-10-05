---
sidebar_position: 9
title: SPAKE2+ and Matter PASE
description: "NoxTLS documentation: SPAKE2+ (RFC 9383), the Matter draft-01 profile, Matter PASE helpers and PBKDF2."
---

# SPAKE2+, Matter PASE and PBKDF2 in NoxTLS

NoxTLS provides:

- **SPAKE2+** augmented PAKE for the ciphersuite **P256-SHA256-HKDF-SHA256-HMAC-SHA256**, with two key-schedule profiles selected per context:
  - `NOXTLS_SPAKE2P_PROFILE_RFC9383`: **RFC 9383**, the standard and the default.
  - `NOXTLS_SPAKE2P_PROFILE_MATTER`: the **draft-bar-cfrg-spake2plus-01** key schedule referenced by the Matter Core specification for PASE. It exists **only for Matter interoperability**.
- **Matter PASE helpers** built on the Matter profile: passcode verifier generation, the PASE context hash and session-key derivation.
- **PBKDF2** (RFC 8018 section 5.2) over HMAC-SHA1/SHA-256/SHA-384/SHA-512.

All of these are **off by default**.

## Configuration

| CMake knob | `noxtls_config.h` macro | Default | Requires |
|---|---|---|---|
| `NOXTLS_CFG_FEATURE_PBKDF2` | `NOXTLS_FEATURE_PBKDF2` | OFF | HMAC |
| `NOXTLS_CFG_FEATURE_SPAKE2P` | `NOXTLS_FEATURE_SPAKE2P` | OFF | PKC, ECC, SHA-256, HMAC, HKDF, DRBG; at least one profile |
| `NOXTLS_CFG_FEATURE_SPAKE2P_RFC9383` | `NOXTLS_FEATURE_SPAKE2P_RFC9383` | ON (effective with SPAKE2P) | SPAKE2P |
| `NOXTLS_CFG_FEATURE_SPAKE2P_MATTER` | `NOXTLS_FEATURE_SPAKE2P_MATTER` | OFF | SPAKE2P |
| `NOXTLS_CFG_FEATURE_MATTER_PASE` | `NOXTLS_FEATURE_MATTER_PASE` | OFF | SPAKE2P, SPAKE2P_MATTER, PBKDF2 |

```bash
# Standard SPAKE2+ only
cmake -S . -B build -D NOXTLS_CFG_FEATURE_SPAKE2P=ON

# Matter commissioning (Matter profile + PASE helpers); RFC 9383 may be kept or dropped
cmake -S . -B build -D NOXTLS_CFG_FEATURE_PBKDF2=ON -D NOXTLS_CFG_FEATURE_SPAKE2P=ON \
      -D NOXTLS_CFG_FEATURE_SPAKE2P_MATTER=ON -D NOXTLS_CFG_FEATURE_MATTER_PASE=ON \
      -D NOXTLS_CFG_FEATURE_SPAKE2P_RFC9383=OFF
```

Dependencies are enforced by both CMake and `noxtls_check_config.h`. The code builds into the `noxtls_pake` library (`noxtls-lib/pake`); PBKDF2 is part of `noxtls_kdf`.

## The two SPAKE2+ profiles

Both profiles share the group operations and the protocol transcript:

- M and N are the RFC 9383 section 4 P-256 points; cofactor h = 1.
- shareP = X = x\*G + w0\*M, shareV = Y = y\*G + w0\*N.
- Prover: Z = x\*(Y - w0\*N), V = w1\*(Y - w0\*N). Verifier: Z = y\*(X - w0\*M), V = y\*L.
- TT = Context, idProver, idVerifier, M, N, shareP, shareV, Z, V, w0, each preceded by an 8-byte little-endian length (empty identities are encoded as a zero length).

They differ in the key schedule:

| Step | RFC 9383 (section 3.4) | Matter / draft-01 (section 3.4) |
|---|---|---|
| Transcript digest | K_main = SHA-256(TT) | Ka \|\| Ke = SHA-256(TT) (16 + 16 bytes) |
| Confirmation keys | K_confirmP \|\| K_confirmV = HKDF(nil, K_main, "ConfirmationKeys"), 32 + 32 bytes | KcA \|\| KcB = HKDF(nil, Ka, "ConfirmationKeys"), 16 + 16 bytes |
| Prover confirmation | confirmP = HMAC(K_confirmP, shareV) | cA = HMAC(KcA, Y) |
| Verifier confirmation | confirmV = HMAC(K_confirmV, shareP) | cB = HMAC(KcB, X) |
| Shared secret | K_shared = HKDF(nil, K_main, "SharedKey"), 32 bytes | Ke, 16 bytes |

The profiles are therefore **not interchangeable**: the same inputs produce different confirmations and keys, and a peer using one profile fails key confirmation with a peer using the other. Use RFC 9383 for new protocols; select the Matter profile only to interoperate with Matter commissioners and devices.

## SPAKE2+ API (`pake/noxtls_spake2p.h`)

| Function | Purpose |
|---|---|
| `noxtls_spake2p_derive_w0_w1(ws, 80, w0, w1)` | Registration: reduce the KDF output w0s \|\| w1s (40 + 40 bytes) mod n (constant time). The password KDF is application-chosen. |
| `noxtls_spake2p_compute_L(w1, L)` | Registration: L = w1\*G for the verifier record. |
| `noxtls_spake2p_prover_init(ctx, profile, params, w0, w1)` | Prover (Matter: commissioner / initiator). |
| `noxtls_spake2p_verifier_init(ctx, profile, params, w0, L)` | Verifier (Matter: device / responder). |
| `noxtls_spake2p_generate_share(ctx, share, &len)` | Own share with a DRBG ephemeral scalar. |
| `noxtls_spake2p_generate_share_with_scalar(...)` | Own share with a caller-supplied scalar (known-answer tests, external TRNG). |
| `noxtls_spake2p_process_peer_share(ctx, peer, 65)` | Validate the peer share, compute Z and V, derive keys. |
| `noxtls_spake2p_get_confirmation(ctx, mac, &len)` | Own confirmation MAC (32 bytes). |
| `noxtls_spake2p_verify_peer_confirmation(ctx, mac, 32)` | Constant-time check; on mismatch the context is aborted (no retry). |
| `noxtls_spake2p_get_shared_key(ctx, key, &len)` | Shared secret after the peer is confirmed. |
| `noxtls_spake2p_free(ctx)` | Erase all secrets. |

`noxtls_spake2p_params_t` carries Context, idProver and idVerifier. Shares are 65-byte uncompressed SEC 1 points.

```c
noxtls_spake2p_params_t params = { ctx_bytes, ctx_len, id_p, id_p_len, id_v, id_v_len };
static noxtls_spake2p_ctx_t prover;            /* about 1 KB: keep off small stacks */
uint8_t share_p[65], confirm_p[32];
uint32_t len = sizeof(share_p);

noxtls_spake2p_prover_init(&prover, NOXTLS_SPAKE2P_PROFILE_RFC9383, &params, w0, w1);
noxtls_spake2p_generate_share(&prover, share_p, &len);          /* send shareP */
/* ... receive shareV and confirmV ... */
noxtls_spake2p_process_peer_share(&prover, share_v, 65);
if (noxtls_spake2p_verify_peer_confirmation(&prover, confirm_v, 32) == NOXTLS_RETURN_SUCCESS) {
    len = sizeof(confirm_p);
    noxtls_spake2p_get_confirmation(&prover, confirm_p, &len);  /* send confirmP */
    /* noxtls_spake2p_get_shared_key(...) */
}
noxtls_spake2p_free(&prover);
```

The verifier calls `generate_share` before `process_peer_share(shareP)`, sends shareV and confirmV, then verifies confirmP.

## Matter PASE helpers (`pake/noxtls_matter_pase.h`)

| Function | Matter Core reference |
|---|---|
| `noxtls_matter_pase_passcode_is_valid(passcode)` | 5.1.7.1 setup passcode rules |
| `noxtls_matter_pase_compute_w0_w1(passcode, salt, salt_len, iterations, w0, w1)` | 3.10: PBKDF2-HMAC-SHA256(passcode as 4-byte LE, salt 16-32 bytes, 1000-100000 iterations, 80 bytes) |
| `noxtls_matter_pase_compute_verifier(...)` / `noxtls_matter_pase_parse_verifier(...)` | Serialized verifier w0 \|\| L (97 bytes) |
| `noxtls_matter_pase_compute_context(request, request_len, response, response_len, ctx)` | 4.14.1.2: SHA-256("CHIP PAKE V1 Commissioning" \|\| PBKDFParamRequest \|\| PBKDFParamResponse) |
| `noxtls_matter_pase_initiator_init(...)` / `noxtls_matter_pase_responder_init(...)` | Matter-profile SPAKE2+ with empty identities |
| `noxtls_matter_pase_derive_session_keys(ctx, i2r, r2i, challenge)` | 4.14.1.3: HKDF(Ke, salt = [], "SessionKeys") into I2RKey, R2IKey and AttestationChallenge (16 bytes each) |

Pake1 carries pA (shareP), Pake2 carries pB (shareV) and cB, and Pake3 carries cA.

**Boundary.** NoxTLS takes and returns raw bytes only. Matter TLV encoding of PBKDFParamRequest/Response and Pake1/2/3, session IDs, MRP and the session table stay in the Matter stack. The caller passes the exact PBKDFParamRequest/Response payload bytes to `noxtls_matter_pase_compute_context()`.

## Security notes

- Received shares must be uncompressed, have coordinates below p, lie on the curve and not be the identity. T = peer - w0\*{M|N}, Z and V must not be the identity. Every failure aborts the exchange and erases the context.
- Confirmations are compared in constant time, and a mismatch is final (no retry).
- Secret scalars are range checked and reduced mod n in constant time. w0, w1, L and the ephemeral scalar are erased as soon as the keys are derived.
- Every scalar multiplication goes through `noxtls_ecc_point_multiply()`, so a bound platform P-256 accelerator port (for example the CC13xx PKA callbacks, `NOXTLS_CFG_FEATURE_CC13XX_HW_ACCEL`) is used automatically. Accelerator errors other than "not supported" abort the exchange. Point addition uses the generic NoxTLS helpers, which are not constant-time.
- The HMAC module keeps a single SHA-256 inner context, so do not interleave SPAKE2+ or PBKDF2 calls with another live HMAC-SHA256 computation.

## Tests and vectors

Enable with `-D BUILD_TESTS=ON -D NOXTLS_BUILD_PAKE_TESTS=ON -D NOXTLS_ERROR_UTNOX=<utnox checkout>` and the feature knobs above, then run `ctest`. The tests in `ut/pake` cover:

- RFC 9383 Appendix C (both roles: shares, Z, V, K_main, confirmation keys, confirmations, K_shared).
- The draft-bar-cfrg-spake2plus-01 vector for the Matter profile.
- A cross-profile non-interchangeability check, random round trips, and wrong-password, invalid-point, identity, wrong-confirmation, state-machine, NULL-argument and zeroization checks.
- Matter PASE (passcode 20202021, salt "SPAKE2P Key Salt", 1000 iterations).
- RFC 7914 and RFC 6070 PBKDF2 vectors.
- With `NOXTLS_CFG_FEATURE_CC13XX_HW_ACCEL=ON`, a test that routes every multiplication through a bound accelerator callback.

`ut/pake/spake2p_reference.py` is an independent Python model that regenerates `spake2p_test_vectors.h` and checks the transcribed published vectors for consistency (`--check` also runs under `ctest`).
