---
sidebar_position: 15
title: TLS 1.0
description: "NoxTLS TLS 1.0 C API reference for embedded TLS, DTLS, and cryptography."
---

# TLS 1.0

TLS 1.0 API wrappers over the shared TLS 1.2-style context. Header: `noxtls_tls10.h`.

:::danger Deprecated and insecure
TLS 1.0 is deprecated and should not be used for new deployments. It is considered cryptographically weak by modern security standards and fails many compliance baselines.
:::

## Usage guidance

- Use TLS 1.0 only for controlled legacy interoperability where migration is not yet possible.
- Restrict exposure (segmented networks, allowlisted peers, short-term exception windows).
- Prefer upgrading peers to TLS 1.2 or TLS 1.3 as the primary remediation path.

## Types

### `tls10_context_t`

Alias of `tls12_context_t` specialized for TLS 1.0 operation.

## API

### Core lifecycle and I/O

- `noxtls_tls10_context_init`
- `noxtls_tls10_context_free`
- `noxtls_tls10_connect`
- `noxtls_tls10_accept`
- `noxtls_tls10_send`
- `noxtls_tls10_recv`
- `noxtls_tls10_close`

### Client handshake steps

- `noxtls_tls10_send_client_hello`
- `noxtls_tls10_recv_server_hello`
- `noxtls_tls10_recv_certificate`
- `noxtls_tls10_recv_server_key_exchange`
- `noxtls_tls10_recv_server_hello_done`
- `noxtls_tls10_send_client_key_exchange`
- `noxtls_tls10_send_change_cipher_spec`
- `noxtls_tls10_send_finished`
- `noxtls_tls10_recv_change_cipher_spec`
- `noxtls_tls10_recv_finished`

### Server handshake steps

- `noxtls_tls10_recv_client_hello`
- `noxtls_tls10_send_server_hello`
- `noxtls_tls10_send_certificate`
- `noxtls_tls10_send_server_key_exchange`
- `noxtls_tls10_send_server_hello_done`
- `noxtls_tls10_recv_client_key_exchange`
- `noxtls_tls10_recv_change_cipher_spec_client`
- `noxtls_tls10_recv_finished_client`
- `noxtls_tls10_send_change_cipher_spec_server`
- `noxtls_tls10_send_finished_server`

For shared structures and record constants, see [TLS (common)](/docs/api/tls).

