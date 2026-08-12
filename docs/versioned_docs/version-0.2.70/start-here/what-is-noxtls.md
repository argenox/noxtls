---
sidebar_position: 1
title: What is NoxTLS?
description: Overview of NoxTLS — embedded TLS 1.2/1.3, DTLS, cryptography, and X.509 for resource-constrained C systems.
keywords:
  - noxtls
  - embedded tls
  - introduction
  - overview
---

# What is NoxTLS?

NoxTLS is a **C99 cryptography and TLS/DTLS library** aimed at embedded systems, gateways, and other environments where you need strong security without dragging in a full desktop TLS stack.

You integrate a single library (or a trimmed subset via [configuration](../configuration-guide)) and drive I/O through your own sockets or callbacks — the same model whether you are on Linux, Zephyr, or a bare-metal RTOS with a custom network stack.

## What you get

| Area | Highlights |
|------|------------|
| **TLS** | TLS 1.2 and 1.3 (1-RTT, resumption, PSK, mTLS, ALPN, record size limits) |
| **DTLS** | DTLS 1.2 and 1.3 for UDP (cookies, retransmission, CID, RFC 9147 record layer) |
| **Crypto** | AES, ChaCha20-Poly1305, SHA-2/SHA-3, RSA, ECC, X25519, Ed25519, and more |
| **Certificates** | X.509 parse, verify, and TLS integration |
| **Post-quantum** | ML-KEM, ML-DSA, SLH-DSA (optional, feature-gated) |

## Who it is for

- Firmware teams shipping **HTTPS or MQTTS-style** connectivity from constrained devices
- Products that need **DTLS** over UDP (industrial IoT, VoIP-style control channels, custom protocols)
- Engineers who want **one codebase** for host development (unit tests, OpenSSL interop) and target deployment (Zephyr, custom CMake)

## How it is organized

```text
noxtls/
├── noxtls-lib/     Core crypto, TLS/DTLS, certs
├── applications/   Reference clients, servers, and utilities
├── ports/          Platform-specific acceleration and hooks
└── docs/           This documentation site
```

The [Architecture](../architecture) page goes deeper on modules and dependencies. The [Crypto API](../api) and [TLS component](../tls) guides are the long-form references once you are past the tutorials in this section.

## Two ways to work

1. **Host / CI** — Build the library and sample apps with CMake on Linux, macOS, or Windows. Use this for fast iteration and regression tests.
2. **Embedded** — Add NoxTLS as a CMake subdirectory (for example on Zephyr), tune [feature flags](../configuration-guide), and wire memory, entropy, and sockets to your platform. See [Port NoxTLS to Your Platform](./port-to-platform).

## Next step

If you want to see something running in minutes, continue to [5 Minute Quickstart](./quickstart). If you already know you need TLS on a device, jump to [Build Your First TLS Client](./tls-client) or [Run DTLS on Embedded Devices](./dtls-embedded).
