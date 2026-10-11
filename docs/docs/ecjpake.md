---
sidebar_position: 10
title: EC-JPAKE and DTLS-ECJPAKE
description: "NoxTLS documentation: EC-JPAKE (RFC 8236 / RFC 8235) and the TLS_ECJPAKE_WITH_AES_128_CCM_8 DTLS 1.2 suite used by Thread MeshCoP."
---

# EC-JPAKE and the DTLS 1.2 EC-JPAKE cipher suite

NoxTLS provides:

- **EC-JPAKE** over NIST P-256 with SHA-256 Schnorr zero-knowledge proofs
  (`noxtls-lib/pake/noxtls_ecjpake.h`).
- **TLS_ECJPAKE_WITH_AES_128_CCM_8** (`0xC0FF`) for the TLS 1.2 / DTLS 1.2
  engine, with the `ecjpake_key_kp_pair` extension (type `256`) and the
  EC-JPAKE ServerKeyExchange / ClientKeyExchange
  (`noxtls-lib/tls/noxtls_tls12_ecjpake.h`).

This is the handshake Thread uses for MeshCoP commissioning: Commissioner
to Border Agent with the PSKc, and Joiner to Joiner Router / Commissioner
with the PSKd. Both features are **off by default**.

## Specifications

| Topic | Source |
|---|---|
| EC J-PAKE rounds and key computation | RFC 8236 (September 2017) section 3.2 |
| Schnorr NIZK over an elliptic curve | RFC 8235 (September 2017) sections 3.2, 3.3 |
| TLS structures, identities, ZKP hash, password mapping, premaster secret | draft-cragie-tls-ecjpake-01 (June 2016) sections 5, 7, 8 |
| AES-128-CCM-8 record protection | RFC 6655 section 3, RFC 6347 (DTLS 1.2) |
| PRF, master secret, key block, Finished | RFC 5246 sections 5, 6.3, 7.4.9, 8.1 |

The draft leaves the cipher suite and extension code points "TBD". NoxTLS
uses the values Thread uses on the wire: cipher suite `0xC0FF` and extension
type `256`.

## Configuration

| CMake knob | `noxtls_config.h` macro | Default | Requires |
|---|---|---|---|
| `NOXTLS_CFG_FEATURE_ECJPAKE` | `NOXTLS_FEATURE_ECJPAKE` | OFF | PKC, ECC, SHA-256, DRBG |
| `NOXTLS_CFG_FEATURE_DTLS_ECJPAKE` | `NOXTLS_FEATURE_DTLS_ECJPAKE` | OFF | ECJPAKE, TLS, TLS12, DTLS, AES_CCM |

```bash
cmake -S . -B build -D NOXTLS_CFG_FEATURE_ECJPAKE=ON -D NOXTLS_CFG_FEATURE_DTLS_ECJPAKE=ON
```

Tunables in `noxtls_ecjpake_config.h` (define before inclusion to override):
`NOXTLS_ECJPAKE_PASSWORD_MAX_LEN` (64) and `NOXTLS_ECJPAKE_MAX_RANDOM_RETRIES` (8).

## Protocol summary

Local keys are `xm1`, `xm2`; peer public keys are `Xp1`, `Xp2`. For the
client these are the draft's `x1`, `x2` / `X3`, `X4`; for the server
`x3`, `x4` / `X1`, `X2`.

| Step | Computation | Carried in |
|---|---|---|
| Password | `s = int(password) mod n`, `s != 0` (draft 8.3) | not sent |
| Round one | `Xm1 = G*xm1`, `Xm2 = G*xm2`, ZKP for each with generator `G` | ClientHello / ServerHello `ecjpake_key_kp_pair` |
| Round two | `Gm = Xm1 + Xp1 + Xp2`, `xs = xm2*s mod n`, `Xm = Gm*xs`, ZKP over `Gm` | ServerKeyExchange / ClientKeyExchange |
| Key | `K = (Xp - Xp2*xs)*xm2` | not sent |
| Premaster | `PMS = SHA-256(str(32, K.x))` (draft 8.7) | not sent |

ZKP (RFC 8235 section 3.2, hash per draft section 8.2):
`h = int(SHA-256(len(Gen)||Gen || len(V)||V || len(X)||X || len(ID)||ID)) mod n`
with 4-octet big-endian lengths, uncompressed 65-octet points and
`ID = "client"` or `"server"` (the sender's role, draft section 8.1).
`r = v - x*h mod n`; the verifier checks `V == Gen*r + X*h`.

Wire structures (draft section 7):

```
ECPoint        = opaque point<1..2^8-1>            (always 65 octets, 0x04||X||Y)
ECSchnorrZKP   = ECPoint V || opaque r<1..2^8-1>   (r minimal big-endian, 1..32 octets)
ECJPAKEKeyKP   = ECPoint X || ECSchnorrZKP zkp
round one      = ECJPAKEKeyKP || ECJPAKEKeyKP      (identity field elided)
ServerKeyExchange body = ECParameters(named_curve=3, secp256r1=23) || ECJPAKEKeyKP
ClientKeyExchange body = ECJPAKEKeyKP
```

## Primitive API (`noxtls_ecjpake.h`)

| Function | Purpose |
|---|---|
| `noxtls_ecjpake_init(ctx, role, password, len)` | Map the password, set the role |
| `noxtls_ecjpake_write_round_one(ctx, out, size, &len)` | Generate (first call) or repeat the round-one message |
| `noxtls_ecjpake_read_round_one(ctx, in, len)` | Parse and verify the peer round one |
| `noxtls_ecjpake_write_round_two(ctx, out, size, &len)` | ServerECJPAKEParams or ClientECJPAKEParams |
| `noxtls_ecjpake_read_round_two(ctx, in, len)` | Parse and verify the peer round two |
| `noxtls_ecjpake_derive_premaster(ctx, out, size, &len)` | 32-octet premaster secret; erases the secrets |
| `noxtls_ecjpake_get_state(ctx)` / `noxtls_ecjpake_free(ctx)` | Diagnostics / erase |

Errors: malformed encodings return `NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR`;
invalid points, wrong curve or a failed ZKP return
`NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER`; calls out of order return
`NOXTLS_RETURN_NOT_INITIALIZED`. Any verification failure moves the context
to `NOXTLS_ECJPAKE_STATE_FAILED` and erases its secrets.

## DTLS 1.2 API (`noxtls_tls12_ecjpake.h`)

| Function | Purpose |
|---|---|
| `noxtls_tls12_set_ecjpake_password(ctx, password, len)` | Enable the EC-JPAKE suite on a TLS 1.2 / DTLS 1.2 context |
| `noxtls_tls12_ecjpake_negotiated(ctx)` | 1 when the handshake selected `0xC0FF` |
| `noxtls_tls12_ecjpake_export_key_block(ctx, out, size, &len)` | 40-octet key block (input to the Thread KEK) |

With a password set:

- the **client** offers only `TLS_ECJPAKE_WITH_AES_128_CCM_8`, a
  `supported_groups` list with only secp256r1 (draft section 7.2.1),
  `ec_point_formats` = uncompressed and `ecjpake_key_kp_pair`. After a
  DTLS HelloVerifyRequest the same round-one octets are resent.
- the **server** selects only `TLS_ECJPAKE_WITH_AES_128_CCM_8`, verifies the
  client round one after the cookie exchange, answers with ServerHello
  (with its round one), ServerKeyExchange and ServerHelloDone, and sends no
  Certificate or CertificateRequest. Session resumption and tickets are not
  offered for EC-JPAKE sessions.
- A missing `ecjpake_key_kp_pair` extension or a failed ZKP aborts the
  handshake with an `illegal_parameter` / `decode_error` alert (draft
  section 6). A wrong password fails the Finished check
  (`NOXTLS_RETURN_TLS_FINISHED_VERIFY_FAILED`).

The rest of the session (`noxtls_tls12_connect_poll`, `noxtls_tls12_accept_poll`,
`noxtls_tls12_send`, `noxtls_tls12_recv`, `noxtls_tls12_close`,
`noxtls_tls12_context_free`) is the regular TLS 1.2 / DTLS 1.2 API.

## Security notes

- Received points must be uncompressed, have coordinates below p, lie on
  the curve and not be the identity. The round-two generators must not be
  the identity (RFC 8236 section 3.2).
- Secret scalars are drawn as 320 random bits reduced modulo n and handled
  with constant-time scalar code; all point multiplications use
  `noxtls_ecc_point_multiply()`, so a bound P-256 accelerator port (for
  example CC13xx PKA) is used automatically.
- Secrets are erased on completion, on any failure and in `free`.
- No public known-answer vectors exist for this construction (neither RFC
  8236 nor the draft include EC test vectors). The unit tests use a
  self-checking independent Python reference (`ut/pake/ecjpake_reference.py`)
  plus full in-memory DTLS handshakes.
