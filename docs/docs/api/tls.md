---
sidebar_position: 14
title: "TLS (common)"
---

# TLS (common)

Shared types, constants, I/O callbacks, record handling, version detection, and extension parsing used by TLS 1.0–1.3 and DTLS. Headers: `noxtls_tls_common.h`, `noxtls_tls.h`.

## Types

### tls_context_t

Base TLS context: role (client/server), version, state, user_data, send/recv/time callbacks, I/O mode, and optional pending Client Hello for version negotiation. Initialized with [noxtls_tls_context_init](#noxtls_tls_context_init), freed with [noxtls_tls_context_free](#noxtls_tls_context_free). TLS 1.2/1.3 contexts extend the DTLS base, which contains a `tls_context_t base`.

### tls_record_t

Record container: `type`, `version`, `length`, `data`. Filled by [noxtls_tls_recv_record](#noxtls_tls_recv_record).

### tls_record_header_t

Packed wire-format record header: `type`, `version[2]`, `length[2]`.

### tls_state_t

Connection state: `TLS_STATE_INIT`, `TLS_STATE_HANDSHAKING`, `TLS_STATE_CONNECTED`, `TLS_STATE_CLOSING`, `TLS_STATE_CLOSED`, `TLS_STATE_ERROR`.

### tls_role_t

Role: `TLS_ROLE_CLIENT`, `TLS_ROLE_SERVER`.

### tls_io_mode_t

I/O mode: `TLS_IO_MODE_BLOCKING`, `TLS_IO_MODE_NON_BLOCKING`.

### tls_cipher_suite_t

Cipher suite info: `suite` (ID), `name`, `key_size`, `iv_size`, `mac_size`.

### tls_send_callback_t

```c
typedef int32_t (*tls_send_callback_t)(void *user_data, const uint8_t *data, uint32_t len);
```

Send callback: send `len` bytes from `data` over the transport. Return bytes sent, or negative on error.

### tls_recv_callback_t

```c
typedef int32_t (*tls_recv_callback_t)(void *user_data, uint8_t *data, uint32_t len);
```

Receive callback: read up to `len` bytes into `data`. Return bytes received, or negative on error.

### tls_time_callback_t

```c
typedef uint64_t (*tls_time_callback_t)(void *user_data);
```

Optional monotonic time in milliseconds (e.g. for DTLS timeouts and TLS 1.3 ticket age).

### Extension types

- **tls_extension_t** — Generic extension: `type`, `length`, `data`.
- **tls_sni_extension_t** — SNI: `name_type`, `name_len`, `hostname`.
- **tls_supported_groups_extension_t** — Supported groups: `groups`, `count`.
- **tls_key_share_extension_t** — Single key share: `group`, `key_exchange_len`, `key_exchange`.
- **tls_key_share_list_extension_t** — Key share list: `entries`, `count`.
- **tls_signature_algorithms_extension_t** — Signature algorithms: `algorithms`, `count`.
- **tls_alpn_extension_t** — ALPN: `protocols`, `count`.
- **tls_supported_versions_extension_t** — Supported versions: `versions`, `count`.
- **tls_extensions_t** — Parsed extensions container: `extensions`, `count`, plus optional parsed pointers (sni, supported_groups, key_share, signature_algorithms, alpn, supported_versions). Freed with [noxtls_tls_extensions_free](#extension-parsing).

## Constants (summary)

- **Versions:** `TLS_VERSION_1_0` (0x0301) … `TLS_VERSION_1_3` (0x0304).
- **Record types:** `TLS_RECORD_CHANGE_CIPHER_SPEC`, `TLS_RECORD_ALERT`, `TLS_RECORD_HANDSHAKE`, `TLS_RECORD_APPLICATION_DATA`, `TLS_RECORD_ACK`.
- **Handshake types:** e.g. `TLS_HANDSHAKE_CLIENT_HELLO`, `TLS_HANDSHAKE_SERVER_HELLO`, `TLS_HANDSHAKE_CERTIFICATE`, `TLS_HANDSHAKE_FINISHED`, etc.
- **Named groups:** `TLS_NAMED_GROUP_SECP256R1`, `SECP384R1`, `SECP521R1`, `X25519`, `X448`, `TLS_NAMED_GROUP_FFDHE2048`, etc.
- **Cipher suites:** e.g. `TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_CIPHER_SUITE_AES_128_GCM_SHA256`, `TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256`, and many others (see header).
- **Alerts:** `TLS_ALERT_LEVEL_WARNING`, `TLS_ALERT_LEVEL_FATAL`; description codes e.g. `TLS_ALERT_CLOSE_NOTIFY`, `TLS_ALERT_UNEXPECTED_MESSAGE`, `TLS_ALERT_HANDSHAKE_FAILURE`, etc.
- **Extension types:** `TLS_EXTENSION_SERVER_NAME`, `TLS_EXTENSION_KEY_SHARE`, `TLS_EXTENSION_SUPPORTED_VERSIONS`, `TLS_EXTENSION_PRE_SHARED_KEY`, etc.
- **Sizes:** `TLS_MAX_RECORD_SIZE`, `TLS_MAX_HANDSHAKE_SIZE`, `TLS_HANDSHAKE_WORKSPACE_SIZE` (configurable via `noxtls_config.h`).

## API

### `noxtls_tls_context_init`

```c
noxtls_return_t noxtls_tls_context_init(tls_context_t *ctx, tls_role_t role, uint16_t version);
```

Initialize base TLS context. `version` is e.g. `TLS_VERSION_1_2` or `TLS_VERSION_1_3`.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `noxtls_tls_context_free`

```c
noxtls_return_t noxtls_tls_context_free(tls_context_t *ctx);
```

Free base TLS context and any resources it owns.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `noxtls_tls_set_io_callbacks`

```c
noxtls_return_t noxtls_tls_set_io_callbacks(tls_context_t *ctx,
                                             tls_send_callback_t send_cb,
                                             tls_recv_callback_t recv_cb,
                                             void *user_data);
```

Set send and receive callbacks and user data. Required before handshake or record I/O.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `noxtls_tls_set_time_callback`

```c
noxtls_return_t noxtls_tls_set_time_callback(tls_context_t *ctx, tls_time_callback_t time_cb);
```

Set optional monotonic time callback (milliseconds).

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `noxtls_tls_send_record`

```c
noxtls_return_t noxtls_tls_send_record(tls_context_t *ctx, uint8_t type, const uint8_t *data, uint32_t len);
```

Send one TLS record with the given content type and payload. Uses the context’s send callback.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `noxtls_tls_recv_record`

```c
noxtls_return_t noxtls_tls_recv_record(tls_context_t *ctx, tls_record_t *record);
```

Receive one TLS record into `record`. Caller must not free `record->data` when it is owned by the library’s internal buffer; see implementation for ownership.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `noxtls_tls_send_alert`

```c
noxtls_return_t noxtls_tls_send_alert(tls_context_t *ctx, uint8_t level, uint8_t description);
```

Send an alert record. `level`: `TLS_ALERT_LEVEL_WARNING` or `TLS_ALERT_LEVEL_FATAL`; `description`: e.g. `TLS_ALERT_CLOSE_NOTIFY`.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `noxtls_tls_set_record_dump_file`

```c
void noxtls_tls_set_record_dump_file(const char *path);
```

Set a file path for debugging record dump (optional). Global or per-context depending on implementation.

### `noxtls_tls_detect_version`

```c
noxtls_return_t noxtls_tls_detect_version(tls_context_t *base_ctx, uint16_t *detected_version,
                                           uint8_t **client_hello_data, uint32_t *client_hello_len);
```

Inspect the first received record (Client Hello) and detect TLS version. Optionally return a pointer to the Client Hello data and length. Used by servers for version negotiation.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `tls_accept_auto`

```c
noxtls_return_t tls_accept_auto(tls_context_t *base_ctx,
                                void *tls10_ctx, void *tls11_ctx,
                                tls12_context_t *tls12_ctx, tls13_context_t *tls13_ctx,
                                uint16_t *negotiated_version);
```

Accept a connection with automatic version negotiation. The first record (Client Hello) must already be in the base context (e.g. via recv). Optional `tls10_ctx`/`tls11_ctx` may be NULL; `tls12_ctx` and `tls13_ctx` must be initialized and configured. On success, the appropriate context (TLS 1.2 or 1.3) has completed the handshake; `negotiated_version` is set.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `noxtls_tls_verify_certificate_signature`

```c
noxtls_return_t noxtls_tls_verify_certificate_signature(void *cert, void *issuer);
```

Verify certificate signature against issuer. Requires X.509 support. `cert` and `issuer` are parsed certificate pointers (e.g. `x509_certificate_t*`).

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Record encryption/decryption (TLS 1.2)

Declared in `noxtls_tls_common.h`, implemented when using TLS 1.2:

- **noxtls_tls12_encrypt_record** — Encrypt plaintext into an encrypted record.
- **noxtls_tls12_decrypt_record** — Decrypt an encrypted record to plaintext.

See [TLS 1.2 API](/docs/api/tls12) for context and usage.

### Record encryption/decryption (TLS 1.3)

Declared in `noxtls_tls_common.h`, implemented when using TLS 1.3:

- **noxtls_tls13_encrypt_record** — Encrypt application/handshake plaintext.
- **noxtls_tls13_encrypt_record_early** — Encrypt 0-RTT early data.
- **noxtls_tls13_decrypt_record** — Decrypt a TLS 1.3 record.
- **noxtls_tls13_decrypt_record_early** — Decrypt 0-RTT early data.
- **noxtls_tls13_send_dtls13_encrypted_record** — Send one DTLS 1.3 encrypted record (unified header).
- **noxtls_tls13_decrypt_dtls13_record** — Decrypt one DTLS 1.3 record.
- **noxtls_tls13_dtls13_record_size** — Length of first DTLSCiphertext in a buffer.

See [TLS 1.3 API](/docs/api/tls13) for context and usage.

### Extension parsing

```c
noxtls_return_t noxtls_tls_parse_extensions(const uint8_t *data, uint32_t data_len, tls_extensions_t *extensions);
noxtls_return_t noxtls_tls_extensions_free(tls_extensions_t *extensions);
noxtls_return_t noxtls_tls_find_extension(tls_extensions_t *extensions, uint16_t type, tls_extension_t **extension);
```

Parse extension list into `tls_extensions_t`; free with `noxtls_tls_extensions_free`. Find one extension by type with `noxtls_tls_find_extension`.

Single-extension parsers (return parsed data into the given struct):

- **noxtls_tls_parse_extension_sni** — SNI.
- **noxtls_tls_parse_extension_supported_groups** — Supported groups.
- **noxtls_tls_parse_extension_key_share** — Key share list.
- **noxtls_tls_parse_extension_signature_algorithms** — Signature algorithms.
- **noxtls_tls_parse_extension_alpn** — ALPN.
- **noxtls_tls_parse_extension_supported_versions** — Supported versions.

**Returns:** [noxtls_return_t](/docs/api/return_codes).
