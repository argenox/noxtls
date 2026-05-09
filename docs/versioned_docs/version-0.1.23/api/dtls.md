---
sidebar_position: 17
title: "DTLS"
---

# DTLS

Datagram TLS common definitions and base context used by DTLS 1.2 and 1.3. Header: `noxtls_dtls_common.h`. TLS 1.2 and 1.3 datagram operation use [tls12_context_t](/docs/api/tls12#tls12_context_t) and [tls13_context_t](/docs/api/tls13#tls13_context_t) initialized with [dtls12_context_init](/docs/api/tls12#dtls12_context_init) and [dtls13_context_init](/docs/api/tls13#dtls13_context_init) respectively.

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

DTLS base context: contains [tls_context_t](/docs/api/tls#tls_context_t) plus epoch, read/write sequence numbers, DTLS message sequence, MTU, max fragment size, anti-amplification factor, replay window, handshake reassembly buffer, flight buffer for retransmission, ACK state, retransmit timeout/backoff, and cookie. Initialized with [dtls_context_init](#dtls_context_init), freed with [dtls_context_free](#dtls_context_free). **tls12_context_t** and **tls13_context_t** use this as their `base` (e.g. `ctx->base`).

## API

### Context

### `dtls_context_init`

```c
noxtls_return_t dtls_context_init(dtls_context_t *ctx, tls_role_t role, uint16_t version);
```

Initialize DTLS base context. Usually you use [dtls12_context_init](/docs/api/tls12#dtls12_context_init) or [dtls13_context_init](/docs/api/tls13#dtls13_context_init) instead, which set up the version-specific context including this base.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls_context_free`

```c
noxtls_return_t dtls_context_free(dtls_context_t *ctx);
```

Free DTLS base context. Prefer [tls12_context_free](/docs/api/tls12#tls12_context_free) or [tls13_context_free](/docs/api/tls13#tls13_context_free) when using the full TLS 1.2/1.3 DTLS stack.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Configuration

### `dtls_set_mtu`

```c
noxtls_return_t dtls_set_mtu(dtls_context_t *ctx, uint16_t mtu);
```

Set MTU for fragmentation (e.g. 1500). Call before handshake.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls_set_retransmit`

```c
noxtls_return_t dtls_set_retransmit(dtls_context_t *ctx, uint32_t timeout_ms, uint32_t backoff_ms, uint32_t max_attempts);
```

Set retransmission parameters: initial timeout, backoff multiplier, max attempts per receive.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls_set_anti_amplification_limit`

```c
noxtls_return_t dtls_set_anti_amplification_limit(dtls_context_t *ctx, uint8_t factor);
```

Set anti-amplification limit (RFC 6347). Call before handshake on server.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls_set_ack_range_limit`

```c
noxtls_return_t dtls_set_ack_range_limit(dtls_context_t *ctx, uint8_t max_ranges);
```

Set maximum ACK ranges for DTLS 1.3 ACK handling.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Record layer

### `dtls_send_record`

```c
noxtls_return_t dtls_send_record(dtls_context_t *ctx, uint8_t type, const uint8_t *data, uint32_t len);
```

Send one DTLS record (type and payload). Used internally by the TLS 1.2/1.3 DTLS implementations.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls_recv_record`

```c
noxtls_return_t dtls_recv_record(dtls_context_t *ctx, dtls_record_t *record);
```

Receive one DTLS record into `record`. Used internally.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Handshake fragmentation

### `dtls_send_handshake_fragment`

```c
noxtls_return_t dtls_send_handshake_fragment(dtls_context_t *ctx, uint8_t msg_type, const uint8_t *data, uint32_t len, uint16_t message_seq);
```

Send a handshake fragment. Used internally.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls_recv_handshake_fragment`

```c
noxtls_return_t dtls_recv_handshake_fragment(dtls_context_t *ctx, dtls_handshake_fragment_t *fragment);
```

Receive a handshake fragment. Used internally.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls_reassemble_handshake`

```c
noxtls_return_t dtls_reassemble_handshake(dtls_context_t *ctx, dtls_handshake_fragment_t *fragment, uint8_t **complete_msg, uint32_t *complete_len);
```

Reassemble fragments into a complete handshake message. Caller must free `*complete_msg` when done (if allocated by this function).

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Replay protection

### `dtls_check_replay`

```c
noxtls_return_t dtls_check_replay(dtls_context_t *ctx, uint64_t sequence_number);
```

Check if sequence number is within replay window (reject duplicates). Used internally.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls_update_replay_window`

```c
noxtls_return_t dtls_update_replay_window(dtls_context_t *ctx, uint64_t sequence_number);
```

Update replay window after accepting a record. Used internally.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### Cookie (Hello Verify Request)

### `dtls_generate_cookie`

```c
noxtls_return_t dtls_generate_cookie(dtls_context_t *ctx, const uint8_t *client_hello, uint32_t client_hello_len, uint8_t *cookie, uint32_t *cookie_len);
```

Generate a cookie for Hello Verify Request. Server uses this to validate client address before committing state.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls_verify_cookie`

```c
noxtls_return_t dtls_verify_cookie(const dtls_context_t *ctx, const uint8_t *cookie, uint32_t cookie_len);
```

Verify cookie from client’s second Client Hello. Used internally.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

### `dtls_mark_validated`

```c
void dtls_mark_validated(dtls_context_t *ctx);
```

Mark peer as validated (e.g. after cookie verification). Used internally.

## Using DTLS 1.2 or 1.3

- **DTLS 1.2:** Use [dtls12_context_init](/docs/api/tls12#dtls12_context_init), then [dtls_set_mtu](#dtls_set_mtu), [dtls_set_retransmit](#dtls_set_retransmit), and optionally [dtls_set_anti_amplification_limit](#dtls_set_anti_amplification_limit). Call [tls12_connect](/docs/api/tls12#tls12_connect) or [tls12_accept](/docs/api/tls12#tls12_accept) and then [tls12_send](/docs/api/tls12#tls12_send) / [tls12_recv](/docs/api/tls12#tls12_recv).
- **DTLS 1.3:** Use [dtls13_context_init](/docs/api/tls13#dtls13_context_init), set DTLS options on the base, then [tls13_connect](/docs/api/tls13#tls13_connect) or [tls13_accept](/docs/api/tls13#tls13_accept) and [tls13_send](/docs/api/tls13#tls13_send) / [tls13_recv](/docs/api/tls13#tls13_recv). Connection ID and unified header are handled by the TLS 1.3 implementation.
