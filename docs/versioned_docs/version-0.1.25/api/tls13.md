---
sidebar_position: 16
title: "TLS 1.3"
---

# TLS 1.3

TLS 1.3 implementation with optional 0-RTT, PSK, session resumption, and client authentication. Header: `noxtls_tls13.h`. Context extends [dtls_context_t](/docs/api/dtls#dtls_context_t).

## Enablement

- Base TLS 1.3: `NOXTLS_CFG_FEATURE_TLS=ON` and `NOXTLS_CFG_FEATURE_TLS13=ON`
- PQ key exchange/signatures: `NOXTLS_CFG_FEATURE_ML_KEM=ON` and `NOXTLS_CFG_FEATURE_ML_DSA=ON`
- Hybrid groups require `NOXTLS_CFG_FEATURE_X25519=ON`

## Types

### tls13_key_share_entry_t

Single key share: `group` (named group), `key_exchange_len`, `key_exchange` (public key bytes).

### tls13_context_t

TLS 1.3 context: base DTLS/TLS context plus handshake state, key derivation (early/handshake/master and traffic secrets), keys/IVs and record number encryption keys, certificate fields, handshake buffer, key shares, extensions, SNI, optional server RSA or crypto provider, client auth (cert, keys, provider handle), external PSK and session ticket/resumption state, 0-RTT early data state, Connection ID (RFC 9147), workspace buffers, channel binding, and record size limit. Initialized with [tls13_context_init](#tls13_context_init), freed with [tls13_context_free](#tls13_context_free).

## Constants

- **TLS13_PSK_KE_MODE_PSK_KE** (0) — PSK-only key establishment.
- **TLS13_PSK_KE_MODE_PSK_DHE_KE** (1) — PSK with (EC)DHE.
- **NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE** (1) — Channel binding: first Finished verify_data.
- **NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT** (2) — Channel binding: hash of server cert.

### PQ / hybrid constants

PQC keyshare groups and signature scheme IDs are defined in [TLS (common)](/docs/api/tls) (`noxtls_tls_common.h`) and documented in [TLS 1.3 PQC](/docs/next/api/tls13_pqc).

## API

### Context

### `tls13_context_init`

```c
noxtls_return_t tls13_context_init(tls13_context_t *ctx, tls_role_t role);
```

Initialize TLS 1.3 context. Set I/O callbacks on the base context before connect/accept.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls13_context_init`

```c
noxtls_return_t dtls13_context_init(tls13_context_t *ctx, tls_role_t role);
```

Initialize for DTLS 1.3 (RFC 9147). Use DTLS options (MTU, retransmit, etc.) as needed.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls13_context_free`

```c
noxtls_return_t tls13_context_free(tls13_context_t *ctx);
```

Free TLS 1.3 context and owned resources.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Handshake and data

### `tls13_connect`

```c
noxtls_return_t tls13_connect(tls13_context_t *ctx);
```

Run full client handshake. Optionally set SNI, client cert (for mTLS), and PSK/session ticket before calling.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls13_accept`

```c
noxtls_return_t tls13_accept(tls13_context_t *ctx);
```

Run full server handshake. Set server certificate and private key (or crypto provider) before calling; optionally request client auth.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls13_send`

```c
noxtls_return_t tls13_send(tls13_context_t *ctx, const uint8_t *data, uint32_t len);
```

Send application data. Call after handshake (and after EndOfEarlyData if 0-RTT was used).

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls13_recv`

```c
noxtls_return_t tls13_recv(tls13_context_t *ctx, uint8_t *data, uint32_t *len);
```

Receive application data. `len` is in/out: max size in, bytes read out.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls13_close`

```c
noxtls_return_t tls13_close(tls13_context_t *ctx);
```

Send close_notify and transition to closing/closed state.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### 0-RTT early data

### `tls13_send_early_data`

```c
noxtls_return_t tls13_send_early_data(tls13_context_t *ctx, const uint8_t *data, uint32_t len);
```

Send 0-RTT early data (only when resuming, before handshake completes). Must send EndOfEarlyData when done with early data.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Server key and certificate

### `tls13_set_server_private_rsa`

```c
void tls13_set_server_private_rsa(tls13_context_t *ctx, void *rsa_key);
```

Set server RSA private key (`rsa_key_t*`) for CertificateVerify. Call before handshake when using server auth with RSA.

### `tls13_set_server_private_mldsa`

```c
noxtls_return_t tls13_set_server_private_mldsa(tls13_context_t *ctx, noxtls_mldsa_param_t param, const uint8_t *private_key);
```

Set server ML-DSA private key for CertificateVerify. Call before handshake.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls13_set_crypto_provider_server`

```c
void tls13_set_crypto_provider_server(tls13_context_t *ctx, const noxtls_crypto_provider_t *provider, noxtls_crypto_key_handle_t server_key_handle);
```

Use crypto provider for server CertificateVerify instead of `server_private_rsa`. Call before handshake.

### Client authentication (mTLS)

### `tls13_request_client_auth`

```c
void tls13_request_client_auth(tls13_context_t *ctx, int request);
```

Server: request client certificate (send CertificateRequest). Call before [tls13_accept](#tls13_accept).

### `tls13_set_client_cert`

```c
noxtls_return_t tls13_set_client_cert(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, void *rsa_key);
```

Client: set client certificate (DER) and RSA private key (`rsa_key_t*`) for CertificateVerify. Call before connect.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls13_set_client_cert_ecdsa`

```c
noxtls_return_t tls13_set_client_cert_ecdsa(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, void *ecc_key);
```

Client: set client certificate and ECDSA private key (`ecc_key_t*`). Call before connect.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls13_set_client_cert_ed25519`

```c
noxtls_return_t tls13_set_client_cert_ed25519(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_32);
```

Client: set client certificate and Ed25519 private key (32-byte seed). Call before connect.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls13_set_client_cert_ed448`

```c
noxtls_return_t tls13_set_client_cert_ed448(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len, const uint8_t *private_key_57);
```

Client: set client certificate and Ed448 private key (57-byte seed). Call before connect.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls13_set_client_cert_mldsa`

```c
noxtls_return_t tls13_set_client_cert_mldsa(tls13_context_t *ctx, const uint8_t *cert_der, uint32_t cert_len,
                                            noxtls_mldsa_param_t param, const uint8_t *private_key);
```

Client: set client certificate and ML-DSA private key for mTLS CertificateVerify. Call before connect.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Cipher preference

### `tls13_set_prefer_chacha20`

```c
void tls13_set_prefer_chacha20(tls13_context_t *ctx, int prefer_chacha20);
```

Set runtime preference: 0 = prefer AES-GCM (default), 1 = prefer ChaCha20-Poly1305. Call before handshake.

### PSK

### `tls13_set_external_psk`

```c
noxtls_return_t tls13_set_external_psk(tls13_context_t *ctx,
                                       const uint8_t *identity, uint16_t identity_len,
                                       const uint8_t *psk_key, uint16_t psk_key_len,
                                       uint8_t preferred_mode);
```

Configure external PSK identity and key for PSK or ECDHE-PSK. `preferred_mode`: `TLS13_PSK_KE_MODE_PSK_KE` or `TLS13_PSK_KE_MODE_PSK_DHE_KE`. Call before connect (client) or accept (server) as applicable.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Debug

### `tls13_set_keylog_file`

```c
void tls13_set_keylog_file(const char *path);
```

Set file path for NSS-style key log (e.g. for Wireshark decryption). Global.

### Channel binding (RFC 5929)

### `noxtls_tls13_get_channel_binding`

```c
noxtls_return_t noxtls_tls13_get_channel_binding(tls13_context_t *ctx, uint32_t binding_type, uint8_t *out, uint32_t *out_len);
```

Get channel binding data after handshake. `binding_type`: `NOXTLS_TLS_CHANNEL_BINDING_TLS_UNIQUE` (first Finished verify_data) or `NOXTLS_TLS_CHANNEL_BINDING_TLS_SERVER_END_POINT` (hash of server cert). `out_len`: in = buffer size, out = bytes written.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Record size limit (RFC 8449)

### `tls13_set_record_size_limit`

```c
void tls13_set_record_size_limit(tls13_context_t *ctx, uint16_t limit);
```

Set the record size limit advertised to peer (maximum plaintext record size this side accepts). Call before handshake. Set `0` to use default limit.

### Client handshake steps (optional)

- **tls13_send_client_hello**, **tls13_recv_server_hello**, **tls13_recv_encrypted_extensions**, **tls13_recv_certificate_request**, **tls13_recv_certificate**, **tls13_recv_certificate_verify**, **tls13_recv_finished**
- **tls13_send_client_certificate**, **tls13_send_client_certificate_verify**, **tls13_send_finished**

### Server handshake steps (optional)

- **tls13_recv_client_hello**, **tls13_send_server_hello**, **tls13_send_encrypted_extensions**, **tls13_send_certificate_request**, **tls13_send_certificate**, **tls13_send_certificate_verify**, **tls13_send_finished_server**, **tls13_recv_finished_client**

Record encryption/decryption (including DTLS 1.3 and early data) is available via the [TLS common API](/docs/api/tls#record-encryptiondecryption-tls-13).

## See also

- [TLS 1.3 PQC](/docs/next/api/tls13_pqc)
- [ML-KEM](/docs/next/api/mlkem)
- [ML-DSA](/docs/next/api/mldsa)
