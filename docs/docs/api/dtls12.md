---
sidebar_position: 18
title: "DTLS 1.2"
---

# DTLS 1.2

DTLS 1.2 uses the TLS 1.2 handshake and cipher suite implementation over the DTLS datagram record layer. Header: `noxtls_tls12.h` with shared DTLS declarations in `noxtls_dtls_common.h`.

Use [noxtls_dtls12_context_init](#noxtls_dtls12_context_init) to initialize a [tls12_context_t](/docs/api/tls12#tls12_context_t) for datagram transport. Configure MTU, retransmission, cookies, replay handling, and anti-amplification settings with the shared [DTLS API](/docs/api/dtls).

## Features

| Area | Support |
|------|---------|
| Record layer | DTLS 1.2 13-byte record header with epoch and 48-bit sequence number |
| Handshake | TLS 1.2 handshake over datagrams |
| Fragmentation | Handshake fragmentation and reassembly |
| Loss recovery | Flight buffering and retransmission timer configuration |
| Replay protection | Sliding replay window |
| DoS mitigation | HelloVerifyRequest cookie generation and verification |
| Transport | Callback-based datagram I/O using the TLS common callback API |

## API

### `noxtls_dtls12_context_init`

```c
noxtls_return_t noxtls_dtls12_context_init(tls12_context_t *ctx, tls_role_t role);
```

Initialize a TLS 1.2 context for DTLS 1.2 operation.

**Returns:** [noxtls_return_t](/docs/api/return_codes).

## Handshake and Data

After initialization, use the TLS 1.2 handshake and data functions on the same context:

- [noxtls_tls12_connect](/docs/api/tls12#noxtls_tls12_connect)
- [noxtls_tls12_accept](/docs/api/tls12#noxtls_tls12_accept)
- [noxtls_tls12_send](/docs/api/tls12#noxtls_tls12_send)
- [noxtls_tls12_recv](/docs/api/tls12#noxtls_tls12_recv)
- [noxtls_tls12_close](/docs/api/tls12#noxtls_tls12_close)

## Typical Setup

```c
tls12_context_t ctx;

noxtls_dtls12_context_init(&ctx, TLS_ROLE_CLIENT);
noxtls_tls_set_io_callbacks(&ctx.base.base, send_cb, recv_cb, user_data);
noxtls_dtls_set_mtu(&ctx.base, 1200);
dtls_set_retransmit(&ctx.base, 1000, 2000, 5);

noxtls_tls12_connect(&ctx);
```

See [DTLS common API](/docs/api/dtls) for record, fragmentation, cookie, and replay helper functions.
