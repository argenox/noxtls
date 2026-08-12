---
sidebar_position: 19
title: DTLS 1.3
description: "NoxTLS DTLS 1.3 API: unified header, connection ID, and TLS 1.3 datagram handshake initialization."
keywords:
  - noxtls
  - dtls 1.3
  - rfc 9147
---

# DTLS 1.3

DTLS 1.3 uses the TLS 1.3 context and APIs over the RFC 9147 datagram record layer. Header: `noxtls_tls13.h` with shared DTLS declarations in `noxtls_dtls_common.h`.

Use [noxtls_dtls13_context_init](#noxtls_dtls13_context_init) to initialize a [tls13_context_t](./tls13#tls13_context_t) for datagram transport. Configure MTU, retransmission, ACK limits, replay handling, and anti-amplification settings with the shared [DTLS API](./dtls).

## Features

| Area | Support |
|------|---------|
| Record layer | DTLS 1.3 unified header with optional Connection ID and length fields |
| Handshake | TLS 1.3 handshake over datagrams |
| Key schedule | DTLS 1.3 `dtls13` HKDF labels |
| ACKs | ACK record parsing, ACK range tracking, and retransmission suppression |
| Fragmentation | MTU-aware handshake fragmentation and reassembly |
| Replay protection | Per-epoch replay windows and sequence reconstruction |
| Connection ID | RequestConnectionId and NewConnectionId handling through TLS 1.3 state |
| KeyUpdate | DTLS epoch tracking for application traffic updates |
| 0-RTT and PSK | TLS 1.3 PSK, resumption, and early-data paths where configured |

## API

### `noxtls_dtls13_context_init`

```c
noxtls_return_t noxtls_dtls13_context_init(tls13_context_t *ctx, tls_role_t role);
```

Initialize a TLS 1.3 context for DTLS 1.3 operation.

**Returns:** [noxtls_return_t](./return_codes).

## Handshake and Data

After initialization, use the TLS 1.3 handshake and data functions on the same context:

- [noxtls_tls13_connect](./tls13#noxtls_tls13_connect)
- [noxtls_tls13_accept](./tls13#noxtls_tls13_accept)
- [noxtls_tls13_send](./tls13#noxtls_tls13_send)
- [noxtls_tls13_recv](./tls13#noxtls_tls13_recv)
- [noxtls_tls13_close](./tls13#noxtls_tls13_close)

## Typical Setup

```c
tls13_context_t ctx;

noxtls_dtls13_context_init(&ctx, TLS_ROLE_CLIENT);
noxtls_tls_set_io_callbacks(&ctx.base.base, send_cb, recv_cb, user_data);
noxtls_dtls_set_mtu(&ctx.base, 1200);
noxtls_dtls_set_ack_range_limit(&ctx.base, 16);
dtls_set_retransmit(&ctx.base, 1000, 2000, 5);

noxtls_tls13_connect(&ctx);
```

See the [DTLS 1.3 guide](../dtls13) for the feature overview and [DTLS common API](./dtls) for base DTLS configuration.
