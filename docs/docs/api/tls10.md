---
sidebar_position: 15
title: "TLS 1.0"
---

# TLS 1.0

TLS 1.0 API wrappers over the shared TLS 1.2-style context. Header: `noxtls_tls10.h`.

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

