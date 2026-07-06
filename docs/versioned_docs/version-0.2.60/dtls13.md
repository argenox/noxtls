---
sidebar_position: 8
title: "DTLS 1.3"
description: DTLS 1.3 guide for NoxTLS — RFC 9147 unified header, Connection ID, ACKs, retransmission, and TLS 1.3 handshake over UDP.
keywords:
  - noxtls
  - dtls 1.3
  - rfc 9147
  - udp tls
  - connection id
---

# DTLS 1.3

DTLS 1.3 brings the TLS 1.3 handshake model to datagram transports such as UDP. NoxTLS exposes DTLS 1.3 through the TLS 1.3 context and send/receive APIs, with DTLS-specific record handling, retransmission, replay protection, ACKs, and Connection ID support underneath.

Use [noxtls_dtls13_context_init](./api/dtls13#noxtls_dtls13_context_init) to initialize a [tls13_context_t](./api/tls13#tls13_context_t) for datagram operation, then configure the shared [DTLS API](./api/dtls) before calling the normal TLS 1.3 client or server handshake functions.

## Features

| Area | Support |
|------|---------|
| Handshake | TLS 1.3 client and server handshake over datagram records |
| Key schedule | DTLS 1.3 HKDF labels using the `dtls13` prefix |
| Record layer | RFC 9147 unified header with optional length and Connection ID fields |
| Record number protection | Truncated wire sequence numbers with full number reconstruction |
| AEAD protection | TLS 1.3 AEAD ciphers over DTLS epochs |
| ACK handling | ACK record parsing, ACK range tracking, and retransmission suppression |
| Loss recovery | Flight buffering, retransmission timers, RTT estimation, and final ACK retention |
| Fragmentation | MTU-aware handshake fragmentation and reassembly |
| Replay protection | Per-epoch replay windows for received records |
| Connection ID | RequestConnectionId and NewConnectionId support in the TLS 1.3 implementation |
| KeyUpdate | Independent read and write epoch tracking during application traffic |
| Anti-amplification | Configurable server-side response limits until the peer is validated |

## Typical Setup

```c
tls13_context_t ctx;

noxtls_dtls13_context_init(&ctx, TLS_ROLE_CLIENT);
noxtls_tls_set_io_callbacks(&ctx.base.base, send_cb, recv_cb, user_data);
noxtls_dtls_set_mtu(&ctx.base, 1200);
dtls_set_retransmit(&ctx.base, 1000, 2000, 5);

noxtls_tls13_connect(&ctx);
noxtls_tls13_send(&ctx, data, data_len);
```

Servers use the same DTLS initialization call with `TLS_ROLE_SERVER`, configure certificate and key material as they would for TLS 1.3, and then call [noxtls_tls13_accept](./api/tls13#noxtls_tls13_accept).

## Transport Model

NoxTLS keeps transport ownership with the caller. The DTLS stack calls the configured send and receive callbacks with complete datagram payloads and expects the application to preserve peer association in `user_data`, such as a connected UDP socket or a socket plus peer address.

Before the peer is validated, servers can use [noxtls_dtls_set_anti_amplification_limit](./api/dtls#noxtls_dtls_set_anti_amplification_limit). A peer is considered validated after cookie validation or by explicitly calling [noxtls_dtls_mark_validated](./api/dtls#noxtls_dtls_mark_validated) when the application has out-of-band address validation.

## API References

- [DTLS common API](./api/dtls) — MTU, retransmission, ACK limits, cookies, replay helpers, and base context.
- [DTLS 1.3 API](./api/dtls13) — DTLS 1.3 initialization and the TLS 1.3 APIs used with datagram transport.
- [TLS 1.3 API](./api/tls13) — handshake, data, PSK, 0-RTT, session tickets, ALPN, SNI, and certificate APIs.
