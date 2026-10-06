---
sidebar_position: 5
title: Run DTLS on Embedded Devices
description: Use NoxTLS DTLS 1.2 and 1.3 on UDP for embedded and IoT systems.
keywords:
  - dtls
  - embedded
  - udp
  - iot
  - tutorial
---

# Run DTLS on Embedded Devices

DTLS secures **UDP** transports — the usual choice for sensors, industrial gateways, and real-time control where TCP is too heavy or unsuitable. NoxTLS ships **DTLS 1.2** (RFC 6347) and **DTLS 1.3** (RFC 9147) alongside TLS.

## When to use DTLS

| Use DTLS | Use TLS instead |
|----------|-----------------|
| CoAP, MQTT-SN, custom UDP protocols | HTTPS, MQTT over TCP |
| Lossy links with application-level retry | Reliable streaming APIs |
| Multicast/broadcast-adjacent designs (unicast DTLS) | Browser-grade HTTPS |

## Start with the in-process demo

The fastest way to validate your build is `dtls_psk_demo` — no sockets required:

```bash
cmake -S . -B build -D BUILD_TESTS=OFF
cmake --build build --config Release
./binary/dtls_psk_demo
./binary/dtls_psk_demo 1.3
./binary/dtls_psk_demo --chacha 1.2
```

This exercises PSK handshakes for DTLS 1.2 and 1.3. See [DTLS PSK demo](../applications/app_dtls_psk_demo) for OpenSSL interop commands when you add real UDP.

## DTLS on real UDP (embedded pattern)

NoxTLS does **not** own your socket API. You:

1. Open a UDP socket (or RTOS datagram endpoint).
2. Initialize `dtls_context_t` via `noxtls_dtls12_context_init` or `noxtls_dtls13_context_init`.
3. Feed incoming datagrams to the DTLS record layer; send outbound records on the same socket.
4. Tune MTU, retransmit, and CID options on the shared DTLS base — see [DTLS API](../api/dtls).

### MTU and fragmentation

Embedded links often have small MTUs (1500 down to 576 or lower). Set MTU explicitly:

- `noxtls_dtls_set_mtu` — accounts for IP/UDP overhead and DTLS header variants
- Handshake fragmentation and reassembly are handled inside the stack (DTLS 1.2 flights; DTLS 1.3 unified header + ACK/retransmit)

### Loss and replay

| Mechanism | DTLS 1.2 | DTLS 1.3 |
|-----------|----------|----------|
| Retransmission | Flight timers, flight buffers | ACK ranges, RTT-aware resend |
| Replay protection | Epoch + sequence window | Per-epoch replay window |
| DoS mitigation | Cookie exchange (HelloVerifyRequest) | Cookie + anti-amplification limits |

Deep dive: [DTLS 1.3 guide](../dtls13) and [TLS component — DTLS sections](../tls).

## PSK vs certificate handshakes

| Mode | Best for | Sample |
|------|----------|--------|
| **PSK** | Closed device fleets with pre-shared keys | `dtls_psk_demo`, [DTLS PSK test](../applications/app_dtls_psk_test) |
| **Certificates** | Interop with standard PKI or cloud brokers | Same cert tooling as TLS — [Configure Certificates](./configure-certificates) |

PSK is the quickest path on constrained MCUs. Certificate-based DTLS uses the same X.509 stack as TLS once UDP I/O is wired.

## Connection ID (DTLS 1.3)

For NAT-heavy cellular networks, enable **Connection ID** negotiation so datagrams can be routed after address/port changes. APIs live under [DTLS API](../api/dtls) (`RequestConnectionId`, `NewConnectionId`, rotation hooks). See [DTLS 1.3](../dtls13).

:::caution RFC 9147 alignment
DTLS 1.3 wire format and key derivation follow RFC 9147. Peers must use compatible NoxTLS builds; older experimental DTLS 1.3 peers are not interoperable.
:::

## Embedded build tips

```bash
cmake -S . -B build \
  -D NOXTLS_PROFILE=minimal_tls_client \
  -D BUILD_APPLICATIONS=OFF \
  -D BUILD_TESTS=OFF
```

Then enable only the DTLS/TLS versions you need in [Configuration Guide](../configuration-guide). Trim SHA algorithms, PKC, and PQC features you will not use to save flash.

On **Zephyr**, add NoxTLS with `add_subdirectory`, set `NOXTLS_OMIT_UT_SOURCES ON`, link `zephyr_interface`, and implement entropy + UDP send/recv — see [Port NoxTLS to Your Platform](./port-to-platform).

## OpenSSL interop sanity check

When your UDP path works, verify against OpenSSL 3.x using the commands in [DTLS PSK demo](../applications/app_dtls_psk_demo) (DTLS 1.2/1.3 PSK examples). Swap PSK identity and cipher suite names to match your configuration.

## Next steps

- TCP/HTTPS path: [Build Your First TLS Client](./tls-client)
- Certificates: [Configure Certificates](./configure-certificates)
- Platform port: [Port NoxTLS to Your Platform](./port-to-platform)
