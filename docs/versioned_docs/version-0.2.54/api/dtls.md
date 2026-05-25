---
sidebar_position: 17
title: DTLS
description: "NoxTLS DTLS common API: MTU, retransmission, cookies, replay windows, ACK handling, and connection ID helpers."
keywords:
  - noxtls
  - dtls api
  - rfc 6347
  - rfc 9147
  - udp tls
---

# DTLS

Datagram TLS common definitions and base context used by DTLS 1.2 and 1.3. Header: `noxtls_dtls_common.h`. TLS 1.2 and 1.3 datagram operation use [tls12_context_t](./tls12#tls12_context_t) and [tls13_context_t](./tls13#tls13_context_t) initialized with [noxtls_dtls12_context_init](./dtls12#noxtls_dtls12_context_init) and [noxtls_dtls13_context_init](./dtls13#noxtls_dtls13_context_init) respectively.

## Constants

- **DTLS versions:** `DTLS_VERSION_1_0` (0xFEFF), `DTLS_VERSION_1_2` (0xFEFD), `DTLS_VERSION_1_3` (0xFEFC); `DTLS_1_3_LEGACY_RECORD_VERSION` (0xFEFD).
- **DTLS 1.3 unified header (RFC 9147):** `DTLS13_UNIFIED_FIXED_BITS`, `DTLS13_UNIFIED_CID_BIT`, `DTLS13_UNIFIED_S_BIT`, `DTLS13_UNIFIED_L_BIT`, `DTLS13_UNIFIED_EPOCH_MASK`, `DTLS13_UNIFIED_MIN_HEADER`, `DTLS13_UNIFIED_HEADER_WITH_LEN`, `DTLS13_RECORD_NUMBER_ENC_LEN`.
- **Record header:** `DTLS_RECORD_TYPE_OFFSET`, `DTLS_RECORD_VERSION_OFFSET`, `DTLS_RECORD_EPOCH_OFFSET`, `DTLS_RECORD_SEQUENCE_OFFSET`, `DTLS_RECORD_LENGTH_OFFSET`, `DTLS_RECORD_DATA_OFFSET`, `DTLS_RECORD_HEADER_SIZE` (13).
- **Handshake:** `DTLS_HANDSHAKE_HELLO_VERIFY_REQUEST`, handshake header offsets, `DTLS_HANDSHAKE_BODY_OFFSET`, `DTLS_HANDSHAKE_HEADER_SIZE`.
- **Sizes:** `DTLS_MAX_FRAGMENT_SIZE` (1500), `DTLS_MIN_FRAGMENT_SIZE` (256), `DTLS_MAX_HANDSHAKE_SIZE`, `DTLS_REPLAY_WINDOW_SIZE`, `DTLS_MAX_ACK_RANGES`.
- **Epochs:** `DTLS_EPOCH_UNENCRYPTED` (0), `DTLS_EPOCH_ENCRYPTED` (1), `DTLS_EPOCH_APPLICATION` (2).

## Types

### dtls_record_t

DTLS record: `type`, `version`, `epoch`, `sequence_number` (48-bit as 64-bit), `length`, `data`.

### dtls_handshake_fragment_t

Handshake fragment: `msg_type`, `length`, `message_seq`, `fragment_offset`, `fragment_length`, `fragment_seq`, `data`.

### dtls_replay_window_t

Replay protection: `window_bitmap`, `last_seq`.

### dtls_context_t

DTLS base context: contains [tls_context_t](./tls#tls_context_t) plus epoch, read/write sequence numbers, DTLS message sequence, MTU, max fragment size, anti-amplification factor, replay window, handshake reassembly buffer, flight buffer for retransmission, ACK state, retransmit timeout/backoff, and cookie. Initialized with [noxtls_dtls_context_init](#noxtls_dtls_context_init), freed with [noxtls_dtls_context_free](#noxtls_dtls_context_free). **tls12_context_t** and **tls13_context_t** use this as their `base` (e.g. `ctx->base`).

## API

### Context

### `noxtls_dtls_context_init`

```c
noxtls_return_t noxtls_dtls_context_init(dtls_context_t *ctx, tls_role_t role, uint16_t version);
```

Initialize DTLS base context. Usually you use [noxtls_dtls12_context_init](./dtls12#noxtls_dtls12_context_init) or [noxtls_dtls13_context_init](./dtls13#noxtls_dtls13_context_init) instead, which set up the version-specific context including this base.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_dtls_context_free`

```c
noxtls_return_t noxtls_dtls_context_free(dtls_context_t *ctx);
```

Free DTLS base context. Prefer [noxtls_tls12_context_free](./tls12#noxtls_tls12_context_free) or [noxtls_tls13_context_free](./tls13#noxtls_tls13_context_free) when using the full TLS 1.2/1.3 DTLS stack.

**Returns:** [noxtls_return_t](./return_codes).

### Configuration

### `noxtls_dtls_set_mtu`

```c
noxtls_return_t noxtls_dtls_set_mtu(dtls_context_t *ctx, uint16_t mtu);
```

Set MTU for fragmentation (e.g. 1500). Call before handshake.

**Returns:** [noxtls_return_t](./return_codes).

### `dtls_set_retransmit`

```c
noxtls_return_t dtls_set_retransmit(dtls_context_t *ctx, uint32_t timeout_ms, uint32_t backoff_ms, uint32_t max_attempts);
```

Set retransmission parameters: initial timeout, backoff multiplier, max attempts per receive.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_dtls_set_anti_amplification_limit`

```c
noxtls_return_t noxtls_dtls_set_anti_amplification_limit(dtls_context_t *ctx, uint8_t factor);
```

Set anti-amplification limit (RFC 6347). Call before handshake on server.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_dtls_set_ack_range_limit`

```c
noxtls_return_t noxtls_dtls_set_ack_range_limit(dtls_context_t *ctx, uint8_t max_ranges);
```

Set maximum ACK ranges for DTLS 1.3 ACK handling.

**Returns:** [noxtls_return_t](./return_codes).

### Record layer

### `noxtls_dtls_send_record`

```c
noxtls_return_t noxtls_dtls_send_record(dtls_context_t *ctx, uint8_t type, const uint8_t *data, uint32_t len);
```

Send one DTLS record (type and payload). Used internally by the TLS 1.2/1.3 DTLS implementations.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_dtls_recv_record`

```c
noxtls_return_t noxtls_dtls_recv_record(dtls_context_t *ctx, dtls_record_t *record);
```

Receive one DTLS record into `record`. Used internally.

**Returns:** [noxtls_return_t](./return_codes).

### Handshake fragmentation

### `dtls_send_handshake_fragment`

```c
noxtls_return_t dtls_send_handshake_fragment(dtls_context_t *ctx, uint8_t msg_type, const uint8_t *data, uint32_t len, uint16_t message_seq);
```

Send a handshake fragment. Used internally.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_dtls_recv_handshake_fragment`

```c
noxtls_return_t noxtls_dtls_recv_handshake_fragment(dtls_context_t *ctx, dtls_handshake_fragment_t *fragment);
```

Receive a handshake fragment. Used internally.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_dtls_reassemble_handshake`

```c
noxtls_return_t noxtls_dtls_reassemble_handshake(dtls_context_t *ctx, dtls_handshake_fragment_t *fragment, uint8_t **complete_msg, uint32_t *complete_len);
```

Reassemble fragments into a complete handshake message. Caller must free `*complete_msg` when done (if allocated by this function).

**Returns:** [noxtls_return_t](./return_codes).

### Replay protection

### `noxtls_dtls_check_replay`

```c
noxtls_return_t noxtls_dtls_check_replay(dtls_context_t *ctx, uint64_t sequence_number);
```

Check if sequence number is within replay window (reject duplicates). Used internally.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_dtls_update_replay_window`

```c
noxtls_return_t noxtls_dtls_update_replay_window(dtls_context_t *ctx, uint64_t sequence_number);
```

Update replay window after accepting a record. Used internally.

**Returns:** [noxtls_return_t](./return_codes).

### Cookie (Hello Verify Request)

### `noxtls_dtls_generate_cookie`

```c
noxtls_return_t noxtls_dtls_generate_cookie(dtls_context_t *ctx, const uint8_t *client_hello, uint32_t client_hello_len, uint8_t *cookie, uint32_t *cookie_len);
```

Generate a cookie for Hello Verify Request. Server uses this to validate client address before committing state.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_dtls_verify_cookie`

```c
noxtls_return_t noxtls_dtls_verify_cookie(const dtls_context_t *ctx, const uint8_t *cookie, uint32_t cookie_len);
```

Verify cookie from client’s second Client Hello. Used internally.

**Returns:** [noxtls_return_t](./return_codes).

### `noxtls_dtls_mark_validated`

```c
void noxtls_dtls_mark_validated(dtls_context_t *ctx);
```

Mark peer as validated (e.g. after cookie verification). Used internally.

## Using DTLS 1.2 or 1.3

- **DTLS 1.2:** Use [noxtls_dtls12_context_init](./dtls12#noxtls_dtls12_context_init), then [noxtls_dtls_set_mtu](#noxtls_dtls_set_mtu), [dtls_set_retransmit](#dtls_set_retransmit), and optionally [noxtls_dtls_set_anti_amplification_limit](#noxtls_dtls_set_anti_amplification_limit). Call [noxtls_tls12_connect](./tls12#noxtls_tls12_connect) or [noxtls_tls12_accept](./tls12#noxtls_tls12_accept) and then [noxtls_tls12_send](./tls12#noxtls_tls12_send) / [noxtls_tls12_recv](./tls12#noxtls_tls12_recv).
- **DTLS 1.3:** Use [noxtls_dtls13_context_init](./dtls13#noxtls_dtls13_context_init), set DTLS options on the base, then [noxtls_tls13_connect](./tls13#noxtls_tls13_connect) or [noxtls_tls13_accept](./tls13#noxtls_tls13_accept) and [noxtls_tls13_send](./tls13#noxtls_tls13_send) / [noxtls_tls13_recv](./tls13#noxtls_tls13_recv). Connection ID and unified header are handled by the TLS 1.3 implementation.
