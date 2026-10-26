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

## Invalid Records and Alerts

RFC 9147 (April 2022) Section 4.5.2: an invalid DTLS 1.3 record is silently discarded and the association is kept. `noxtls_tls13_recv` and the handshake functions treat every invalid record the same way: no plaintext, no alert, no change to replay or record-number state, and no effect on retransmission timers. A receive call that only discarded records returns `NOXTLS_RETURN_TIMEOUT` with a zero length, like a read that found no data.

| Record | Result |
|--------|--------|
| DTLSCiphertext that fails AEAD deprotection, in the handshake or the application epoch | Discarded and counted (Section 4.5.3) |
| Malformed unified header: wrong fixed bits, CID bit without a negotiated CID, length that overruns the datagram, too short for the record-number sample or tag, longer than 2^14 + 256 | Discarded |
| Duplicate or stale record (Section 4.5.1), records of an epoch whose keys are not installed (Sections 4.2.1, 5.8.1) | Discarded |
| DTLSPlaintext of an unexpected epoch or with an invalid length | Discarded |
| Any unprotected record other than ACK after the handshake, including a plaintext alert | Discarded |
| More deprotection failures under one read key than the AEAD integrity limit | Fatal `bad_record_mac` (20), `NOXTLS_RETURN_TLS_RECORD_AUTH_FAILED` |
| Authentic record without a content type (RFC 8446 Section 5.4) | Fatal `unexpected_message` (10) |
| Authentic but invalid handshake content, for example a legacy_cookie or a KeyUpdate during the handshake (RFC 9147 Sections 5.1, 5.3, RFC 8446 Section 6) | Fatal alert for the error |

The integrity limits (Section 4.5.3, Appendix B) are 2^36 for AES-GCM and ChaCha20-Poly1305, 2^23.5 (11863283) for AES-128-CCM and 2^7 for AES-128-CCM-8. They are set in `noxtls_tls13_config.h` (`NOXTLS_DTLS13_INTEGRITY_LIMIT_*`) and may be lowered; `noxtls_dtls13_integrity_limit()` returns the limit for a cipher suite. The count restarts when the read epoch changes.

`close_notify` is sent protected with the current write keys.

### Reading alerts

```c
noxtls_return_t noxtls_tls_get_last_alert_received(const tls_context_t *ctx, noxtls_tls_alert_info_t *alert);
noxtls_return_t noxtls_tls_get_last_alert_sent(const tls_context_t *ctx, noxtls_tls_alert_info_t *alert);
```

Pass `&ctx.base.base`. `alert->valid` is 0 until an alert was received or generated; `level` and `description` hold the RFC 8446 Section 6 AlertLevel and AlertDescription. A peer's `close_notify` makes `noxtls_tls13_recv` return success with zero bytes and reads back as level 1, description 0; a fatal alert makes it return `NOXTLS_RETURN_FAILED` and reads back as level 2 with its description, for example 20 (`bad_record_mac`) or 10 (`unexpected_message`). The accessors take any `tls_context_t`: TLS 1.3 contexts record alerts in both directions throughout the connection; TLS 1.2 and DTLS 1.2 contexts record the alerts they send and the alerts received after the handshake.

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
