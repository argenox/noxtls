---
sidebar_position: 14
title: "TLS (unified)"
---

# TLS (unified)

Unified TLS API: a single connection type for TLS 1.2 or 1.3 with automatic version negotiation. Header: `noxtls_tls_unified.h`. Available when at least one of `NOXTLS_FEATURE_TLS12` or `NOXTLS_FEATURE_TLS13` is enabled.

## Types

### noxtls_tls_connection_t

Unified TLS connection: one context for either TLS 1.2 or TLS 1.3. The server uses [noxtls_tls_connection_accept](#noxtls_tls_connection_accept) (version is detected from the Client Hello); the client uses [noxtls_tls_connection_connect](#noxtls_tls_connection_connect) (tries TLS 1.3 first, then 1.2). Only one of `u.tls12` or `u.tls13` is active per connection. Contains:

- **base** — [tls_context_t](/docs/api/tls#tls_context_t) for I/O and first-record receive (server version detection).
- **negotiated_version** — `0` before handshake; `TLS_VERSION_1_2` or `TLS_VERSION_1_3` after.
- **is_tls13** — `1` if the active context is TLS 1.3.
- **fixed_version** — `1` if [noxtls_tls_connection_init_version](#noxtls_tls_connection_init_version) was used.
- **server_cert**, **server_cert_len**, **server_private_rsa** — Server config (applied at accept).
- **server_name**, **server_name_len** — Client SNI (applied at connect).
- **u** — Union of [tls12_context_t](/docs/api/tls12#tls12_context_t) and [tls13_context_t](/docs/api/tls13#tls13_context_t); only one is used per connection.

Initialized with [noxtls_tls_connection_init](#noxtls_tls_connection_init) or [noxtls_tls_connection_init_version](#noxtls_tls_connection_init_version), freed with [noxtls_tls_connection_free](#noxtls_tls_connection_free).

## API

### Initialization and cleanup

### noxtls_tls_connection_init

```c
noxtls_return_t noxtls_tls_connection_init(noxtls_tls_connection_t *conn, tls_role_t role);
```

Initialize for automatic version negotiation (client or server). Set I/O and, for server, cert/key; for client, optional SNI; then call accept or connect.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_init_version

```c
noxtls_return_t noxtls_tls_connection_init_version(noxtls_tls_connection_t *conn, tls_role_t role, uint16_t version);
```

Initialize for a fixed TLS version only: `TLS_VERSION_1_2` or `TLS_VERSION_1_3`. The corresponding feature must be enabled.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_free

```c
noxtls_return_t noxtls_tls_connection_free(noxtls_tls_connection_t *conn);
```

Free the active version context and clear the connection struct.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Configuration

### noxtls_tls_connection_set_io_callbacks

```c
noxtls_return_t noxtls_tls_connection_set_io_callbacks(noxtls_tls_connection_t *conn,
                                                         tls_send_callback_t send_cb,
                                                         tls_recv_callback_t recv_cb,
                                                         void *user_data);
```

Set send/recv callbacks and user_data on the base context. Required before accept or connect.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_set_time_callback

```c
noxtls_return_t noxtls_tls_connection_set_time_callback(noxtls_tls_connection_t *conn, tls_time_callback_t time_cb);
```

Set optional time callback (e.g. for DTLS or ticket age).

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_set_server_cert

```c
noxtls_return_t noxtls_tls_connection_set_server_cert(noxtls_tls_connection_t *conn, const uint8_t *cert, uint32_t cert_len);
```

Server: set certificate (DER). Applied to the chosen TLS 1.2 or 1.3 context at accept.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_set_server_private_key

```c
noxtls_return_t noxtls_tls_connection_set_server_private_key(noxtls_tls_connection_t *conn, void *rsa_key);
```

Server: set RSA private key for Server Key Exchange / CertificateVerify. Applied at accept.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_set_sni

```c
noxtls_return_t noxtls_tls_connection_set_sni(noxtls_tls_connection_t *conn, const char *name, uint16_t name_len);
```

Client: set SNI hostname. Applied at connect.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Handshake and data

### noxtls_tls_connection_accept

```c
noxtls_return_t noxtls_tls_connection_accept(noxtls_tls_connection_t *conn);
```

Server: receive the first record (Client Hello), detect version, initialize the appropriate TLS 1.2 or 1.3 context, and complete the handshake.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_connect

```c
noxtls_return_t noxtls_tls_connection_connect(noxtls_tls_connection_t *conn);
```

Client: run handshake. With auto negotiation, tries TLS 1.3 first, then TLS 1.2. With fixed version (init_version), uses only that version.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_send

```c
noxtls_return_t noxtls_tls_connection_send(noxtls_tls_connection_t *conn, const uint8_t *data, uint32_t len);
```

Send application data. Call after handshake completes.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_recv

```c
noxtls_return_t noxtls_tls_connection_recv(noxtls_tls_connection_t *conn, uint8_t *buf, uint32_t *len);
```

Receive application data. `len` is in/out: maximum buffer size in, bytes read out.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_close

```c
noxtls_return_t noxtls_tls_connection_close(noxtls_tls_connection_t *conn);
```

Send close_notify and transition to closing state.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### noxtls_tls_connection_get_version

```c
uint16_t noxtls_tls_connection_get_version(const noxtls_tls_connection_t *conn);
```

Return negotiated version: `TLS_VERSION_1_2`, `TLS_VERSION_1_3`, or `0` if not yet negotiated.

**Returns:** Version code or 0.
