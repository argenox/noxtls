---
sidebar_position: 29
title: Diffie-Hellman (FFDHE)
description: "NoxTLS Diffie-Hellman (FFDHE) C API reference for embedded TLS, DTLS, and cryptography."
---

# Diffie-Hellman (FFDHE)

Finite-field Diffie-Hellman helpers, including TLS FFDHE group parameter lookup. Header: `pkc/dh/noxtls_dh.h`.

## Algorithm overview

FFDHE (finite-field Diffie-Hellman ephemeral) performs key agreement in multiplicative groups modulo a large prime. In TLS usage, peers use standardized groups (for example ffdhe2048/3072/4096) and derive a shared secret that is then passed to key derivation.

## Pros and cons

**Pros**

- Well-studied and standardized, especially in older and regulated environments.
- Standardized RFC 7919 groups simplify interoperability and avoid unsafe custom parameters.
- Ephemeral mode provides forward secrecy.

**Cons**

- Slower and heavier than modern elliptic-curve key agreement at similar practical security.
- Larger key material and handshake payloads.
- Parameter validation mistakes can be dangerous if non-standard groups are used.

## When to use

- Use when interoperability/policy requires finite-field DH groups.
- Prefer RFC 7919 named FFDHE groups over custom parameters.
- For performance-first modern deployments, X25519 is usually the default alternative.

## API

### `noxtls_dh_ffdhe_params`

```c
noxtls_return_t noxtls_dh_ffdhe_params(uint16_t named_group,
                                       const uint8_t **p,
                                       const uint8_t **g,
                                       uint32_t *p_len);
```

Get FFDHE group parameters (`p`, `g`) for named groups like ffdhe2048/3072/4096.

### `noxtls_dh_generate_key`

```c
noxtls_return_t noxtls_dh_generate_key(const uint8_t *p, uint32_t p_len,
                                       const uint8_t *g, uint32_t g_len,
                                       uint8_t *private_out,
                                       uint8_t *public_out);
```

Generate ephemeral DH private/public key pair for a given group.

### `noxtls_dh_shared_secret`

```c
noxtls_return_t noxtls_dh_shared_secret(const uint8_t *private_key,
                                        uint32_t private_len,
                                        const uint8_t *peer_public,
                                        uint32_t peer_len,
                                        const uint8_t *p,
                                        uint32_t p_len,
                                        uint8_t *secret_out);
```

Compute DH shared secret from local private key and peer public key.

