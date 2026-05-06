---
sidebar_position: 15
title: "TLS 1.0"
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

- `tls10_context_init`
- `tls10_context_free`
- `tls10_connect`
- `tls10_accept`
- `tls10_send`
- `tls10_recv`
- `tls10_close`

### Client handshake steps

- `tls10_send_client_hello`
- `tls10_recv_server_hello`
- `tls10_recv_certificate`
- `tls10_recv_server_key_exchange`
- `tls10_recv_server_hello_done`
- `tls10_send_client_key_exchange`
- `tls10_send_change_cipher_spec`
- `tls10_send_finished`
- `tls10_recv_change_cipher_spec`
- `tls10_recv_finished`

### Server handshake steps

- `tls10_recv_client_hello`
- `tls10_send_server_hello`
- `tls10_send_certificate`
- `tls10_send_server_key_exchange`
- `tls10_send_server_hello_done`
- `tls10_recv_client_key_exchange`
- `tls10_recv_change_cipher_spec_client`
- `tls10_recv_finished_client`
- `tls10_send_change_cipher_spec_server`
- `tls10_send_finished_server`

For shared structures and record constants, see [TLS (common)](/docs/api/tls).

