---
sidebar_position: 29
title: "Diffie-Hellman (FFDHE)"
---

# Diffie-Hellman (FFDHE)

Finite-field Diffie-Hellman helpers, including TLS FFDHE group parameter lookup. Header: `pkc/dh/noxtls_dh.h`.

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

