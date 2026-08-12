---
sidebar_position: 15
title: TLS 1.2
description: "NoxTLS TLS 1.2 and DTLS 1.2 API: cipher suites, handshake, session tickets, OCSP stapling, and record-layer APIs."
keywords:
  - noxtls
  - tls 1.2
  - dtls 1.2
  - ecdhe
  - aes-gcm
  - embedded tls
---

# TLS 1.2

:::warning
TLS 1.2 is a legacy protocol version. New deployments should use TLS 1.3 where possible, and existing TLS 1.2 deployments should plan an upgrade path to TLS 1.3.
:::

TLS 1.0, 1.1, and 1.2 implementation. Header: `noxtls_tls12.h`. Context extends [dtls_context_t](./dtls#dtls_context_t) (which contains [tls_context_t](./tls#tls_context_t)).

## Types

### tls12_context_t

TLS 1.2 context: base DTLS/TLS context plus handshake state (client/server random, cipher suite, keys, IVs, MAC keys, sequence numbers), server certificate, optional server RSA private key or crypto provider handle, key exchange (premaster secret, master secret, ECDHE/DHE context), handshake message buffer, client/server extensions, SNI, renegotiation and RFC 6066 max fragment length, RPK (RFC 7250) options, and workspace buffers. Initialized with [noxtls_tls12_context_init](#noxtls_tls12_context_init) or [noxtls_tls12_context_init_with_version](#noxtls_tls12_context_init_with_version), freed with [noxtls_tls12_context_free](#noxtls_tls12_context_free).

## API

### Context

### `noxtls_tls12_context_init`

```c
noxtls_return_t noxtls_tls12_context_init(tls12_context_t *ctx, tls_role_t role);
```

Initialize TLS 1.2 context (default TLS 1.2). Set I/O callbacks on `ctx->base.base` before connect/accept.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_tls12_context_init_with_version`

```c
noxtls_return_t noxtls_tls12_context_init_with_version(tls12_context_t *ctx, tls_role_t role, uint16_t version);
```

Initialize for a specific version: `TLS_VERSION_1_0`, `TLS_VERSION_1_1`, or `TLS_VERSION_1_2`.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_dtls12_context_init`

```c
noxtls_return_t noxtls_dtls12_context_init(tls12_context_t *ctx, tls_role_t role);
```

Initialize for DTLS 1.2. Use [noxtls_dtls_set_mtu](./dtls#noxtls_dtls_set_mtu) and related DTLS options as needed.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_tls12_context_free`

```c
noxtls_return_t noxtls_tls12_context_free(tls12_context_t *ctx);
```

Free TLS 1.2 context and owned resources.

**Returns:** [noxtls_return_t](./return_codes).

### Handshake and data

### `noxtls_tls12_connect`

```c
noxtls_return_t noxtls_tls12_connect(tls12_context_t *ctx);
```

Run full client handshake (Client Hello through Finished). Set server certificate verification expectations and optional SNI before calling.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_tls12_accept`

```c
noxtls_return_t noxtls_tls12_accept(tls12_context_t *ctx);
```

Run full server handshake. Set server certificate and, for ECDHE-RSA/DHE-RSA, the server private key (or crypto provider) before calling.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_tls12_send`

```c
noxtls_return_t noxtls_tls12_send(tls12_context_t *ctx, const uint8_t *data, uint32_t len);
```

Send application data (encrypted records). Call after handshake completes.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_tls12_recv`

```c
noxtls_return_t noxtls_tls12_recv(tls12_context_t *ctx, uint8_t *data, uint32_t *len);
```

Receive application data. `len` is in/out: maximum buffer size in, actual bytes read out.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_tls12_close`

```c
noxtls_return_t noxtls_tls12_close(tls12_context_t *ctx);
```

Send close_notify and transition to closing/closed state.

**Returns:** [noxtls_return_t](./return_codes).

### Server renegotiation

### `noxtls_tls12_send_hello_request`

```c
noxtls_return_t noxtls_tls12_send_hello_request(tls12_context_t *ctx);
```

Send HelloRequest to ask the client to renegotiate (RFC 5746).

**Returns:** [noxtls_return_t](./return_codes).

### Server key and certificate

### `noxtls_tls12_set_server_private_rsa`

```c
void noxtls_tls12_set_server_private_rsa(tls12_context_t *ctx, void *rsa_key);
```

Set server RSA private key (`rsa_key_t*`) for Server Key Exchange signature. Call before handshake when using ECDHE_RSA or DHE_RSA.

### `noxtls_tls12_set_crypto_provider_server`

```c
void noxtls_tls12_set_crypto_provider_server(tls12_context_t *ctx, const noxtls_crypto_provider_t *provider, noxtls_crypto_key_handle_t server_key_handle);
```

Use a crypto provider (e.g. HSM/TPM) for server signing and decrypting Client Key Exchange instead of `server_private_rsa`. Call before handshake.

### Raw Public Key (RFC 7250)

### `noxtls_tls12_set_server_use_rpk`

```c
void noxtls_tls12_set_server_use_rpk(tls12_context_t *ctx, int use_rpk);
```

Server: send Raw Public Key. Set `server_cert`/`server_cert_len` to SubjectPublicKeyInfo (DER). Call before handshake.

### `noxtls_tls12_set_client_accept_server_rpk`

```c
void noxtls_tls12_set_client_accept_server_rpk(tls12_context_t *ctx, int accept);
```

Client: advertise acceptance of server RPK (server_certificate_type extension). Call before connect.

### `noxtls_tls12_set_client_offer_client_rpk`

```c
void noxtls_tls12_set_client_offer_client_rpk(tls12_context_t *ctx, int offer);
```

Client: offer to send RPK for client auth (client_certificate_type extension). Call before connect.

### Max fragment length (RFC 6066)

### `noxtls_tls12_set_max_fragment_length`

```c
void noxtls_tls12_set_max_fragment_length(tls12_context_t *ctx, uint8_t code);
```

Set max fragment length: 0 = disabled; 1 = 512, 2 = 1024, 3 = 2048, 4 = 4096 bytes. Call before handshake.

### Key derivation (internal use)

### `tls12_compute_master_secret`

```c
noxtls_return_t tls12_compute_master_secret(tls12_context_t *ctx, const uint8_t *premaster_secret, uint32_t premaster_secret_len);
```

Compute master secret from premaster secret. Used internally during handshake.

**Returns:** [noxtls_return_t](./return_codes).

### `tls12_derive_keys`

```c
noxtls_return_t tls12_derive_keys(tls12_context_t *ctx);
```

Derive record protection keys from master secret. Used internally.

**Returns:** [noxtls_return_t](./return_codes).

### Client handshake steps (optional fine-grained control)

- **noxtls_tls12_send_client_hello**, **noxtls_tls12_recv_server_hello**, **noxtls_tls12_recv_certificate**, **noxtls_tls12_recv_server_key_exchange**, **noxtls_tls12_recv_server_hello_done**
- **noxtls_tls12_send_client_key_exchange**, **noxtls_tls12_send_change_cipher_spec**, **noxtls_tls12_send_finished**
- **noxtls_tls12_recv_change_cipher_spec**, **noxtls_tls12_recv_finished**

### Server handshake steps (optional fine-grained control)

- **noxtls_tls12_recv_client_hello**, **noxtls_tls12_send_server_hello**, **noxtls_tls12_send_certificate**, **noxtls_tls12_send_server_key_exchange**, **noxtls_tls12_send_server_hello_done**
- **noxtls_tls12_recv_client_key_exchange**, **noxtls_tls12_recv_change_cipher_spec_client**, **noxtls_tls12_recv_finished_client**
- **noxtls_tls12_send_change_cipher_spec_server**, **noxtls_tls12_send_finished_server**

Record encryption/decryption is available via [noxtls_tls12_encrypt_record](./tls#record-encryptiondecryption-tls-12) and [noxtls_tls12_decrypt_record](./tls#record-encryptiondecryption-tls-12) from the common TLS API.
