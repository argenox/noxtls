---
sidebar_position: 16
title: "TLS 1.1"
---

# TLS 1.1

TLS 1.1 API wrappers over the shared TLS 1.2-style context. Header: `noxtls_tls11.h`.

## Types

### `tls11_context_t`

Alias of `tls12_context_t` specialized for TLS 1.1 operation.

## API

### Core lifecycle and I/O

- `tls11_context_init`
- `tls11_context_free`
- `tls11_connect`
- `tls11_accept`
- `tls11_send`
- `tls11_recv`
- `tls11_close`

### Client handshake steps

- `tls11_send_client_hello`
- `tls11_recv_server_hello`
- `tls11_recv_certificate`
- `tls11_recv_server_key_exchange`
- `tls11_recv_server_hello_done`
- `tls11_send_client_key_exchange`
- `tls11_send_change_cipher_spec`
- `tls11_send_finished`
- `tls11_recv_change_cipher_spec`
- `tls11_recv_finished`

### Server handshake steps

- `tls11_recv_client_hello`
- `tls11_send_server_hello`
- `tls11_send_certificate`
- `tls11_send_server_key_exchange`
- `tls11_send_server_hello_done`
- `tls11_recv_client_key_exchange`
- `tls11_recv_change_cipher_spec_client`
- `tls11_recv_finished_client`
- `tls11_send_change_cipher_spec_server`
- `tls11_send_finished_server`

For shared structures and record constants, see [TLS (common)](/docs/api/tls).

