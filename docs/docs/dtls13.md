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
| Key schedule | DTLS 1.3 HKDF labels using the `dtls13` prefix (RFC 9147 Section 5.9), PSK binders and resumption secrets included; DTLS 1.3 peers that derived binders with `tls13 ` labels (NoxTLS before this change) cannot complete a PSK handshake with this version |
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

## Single-Association Servers

A server that holds one association at a time and admits clients itself (for example a
device that must not lose its current session to a stray ClientHello) can take the
admission decision outside the context. The calls are in `noxtls_tls13.h`; none of them
allocates.

| Call | Purpose | Reference |
|------|---------|-----------|
| `noxtls_dtls13_set_own_connection_id()` | Server: send its own CID in the ServerHello instead of echoing the client's; incoming records are parsed with its length | RFC 9146 Section 3, RFC 9147 Sections 4 and 9 |
| `noxtls_dtls13_last_record_is_newest()` | After `accept`/`recv`: the last record authenticated and is newer in epoch and record number than any before (the condition for a peer address update) | RFC 9146 Section 6 |
| `noxtls_dtls13_set_cookie_exchange()` | Server: skip the NoxTLS cookie HelloRetryRequest, so a ClientHello is answered with the ServerHello at once | RFC 9147 Section 5.1 |
| `noxtls_dtls13_client_hello_hash()` | SHA-256 of a ClientHello datagram as the transcript's `message_hash` holds it | RFC 8446 Section 4.4.1, RFC 9147 Section 5.2 |
| `noxtls_dtls13_stateless_hrr()` | Build a HelloRetryRequest datagram with a cookie, without a context | RFC 9147 Section 5.1, RFC 8446 Sections 4.1.4 and 4.2.2 |
| `noxtls_dtls13_ch2_binder_check()` | Verify the second ClientHello's PSK binder over `message_hash(CH1)`, the HelloRetryRequest and CH2, in caller scratch | RFC 8446 Sections 4.2.11.2 and 4.4.1 |
| `noxtls_dtls13_accept_after_stateless_hrr()` | Continue a fresh server context from the second ClientHello | RFC 8446 Section 4.1.4 |
| `noxtls_dtls13_set_hrr_observer()` | Client: see the cookie of a HelloRetryRequest before the second ClientHello is sent | RFC 9147 Section 5.1 |
| `noxtls_tls13_release_handshake_state()` | Release the handshake state of a connected context now; traffic keys and `exporter_master_secret` stay | RFC 8446 Section 7.5 |
| `noxtls_tls13_selected_psk_identity()` | The selected PSK identity, before and after the release | RFC 8446 Section 4.2.11 |
| `noxtls_dtls13_set_legacy_psk_labels()` | Binders and resumption secrets with the pre-RFC 9147 `tls13 ` labels, for NoxTLS peers built before them (not for the stateless binder check) | RFC 9147 Section 5.9 |
| `noxtls_dtls13_context_init_static_record()` | Static memory: record buffers sized for a smaller record budget than `NOXTLS_TLS_MAX_RECORD_SIZE` (see Static Memory) | RFC 8449 |

The stateless HelloRetryRequest is a function of the echoed `legacy_session_id`, the
cookie, the cipher suite (a SHA-256 TLS 1.3 suite) and the group (0 for none), so the
binder check and the accept rebuild it from the second ClientHello: pass them the same
suite and group as `noxtls_dtls13_stateless_hrr()`. The cookie format and its checks
(expiry, address binding, single use) belong to the application.

```c
/* First ClientHello (no cookie): answer statelessly. */
noxtls_dtls13_client_hello_hash(ch1, ch1_len, ch1_hash);
/* ... build a cookie that carries ch1_hash and binds the peer address ... */
noxtls_dtls13_stateless_hrr(ch1, ch1_len, cookie, cookie_len, suite, 0U, hrr, sizeof(hrr), &hrr_len);

/* Second ClientHello: check the cookie, then the binder, then hand it to a fresh context. */
if(noxtls_dtls13_ch2_binder_check(ch2, ch2_len, ch1_hash, suite, 0U, identity, identity_len,
                                  psk, psk_len, scratch, sizeof(scratch)) == NOXTLS_RETURN_SUCCESS) {
    noxtls_dtls13_set_own_connection_id(&ctx, cid, sizeof(cid));
    rc = noxtls_dtls13_accept_after_stateless_hrr(&ctx, ch1_hash, suite, 0U, ch2, ch2_len);
    /* then noxtls_tls13_accept(&ctx) until connected, as usual */
}
```

## API References

- [DTLS common API](./api/dtls) — MTU, retransmission, ACK limits, cookies, replay helpers, and base context.
- [DTLS 1.3 API](./api/dtls13) — DTLS 1.3 initialization and the TLS 1.3 APIs used with datagram transport.
- [TLS 1.3 API](./api/tls13) — handshake, data, PSK, 0-RTT, session tickets, ALPN, SNI, and certificate APIs.
