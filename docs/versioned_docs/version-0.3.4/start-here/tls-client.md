---
sidebar_position: 3
title: Build Your First TLS Client
description: Integrate a NoxTLS TLS 1.2 or TLS 1.3 client using the unified API and sample applications.
keywords:
  - tls client
  - tutorial
  - tls13
  - connect
---

# Build Your First TLS Client

This guide walks through the **client path** for TLS over a reliable byte stream (TCP). NoxTLS uses callback-based record I/O: you send and receive TLS records on whatever transport you already have.

## Before you start

- Complete [5 Minute Quickstart](./quickstart) so the library and apps build.
- Read the [TLS component](../tls) overview for protocol scope (TLS 1.2/1.3, optional DTLS is separate).
- API reference: [TLS unified API](../api/tls_unified), [TLS 1.3](../api/tls13), [TLS 1.2](../api/tls12).

## Learn from the sample HTTPS client

The `https_client` application is the closest end-to-end example:

```bash
cmake -S . -B build -D BUILD_TESTS=OFF
cmake --build build --config Release
./binary/https_client https://example.com/ 443 tls13
```

Arguments (see [HTTPS client app](../applications/app_https_client)):

- URL (required)
- Port (optional, overrides URL port)
- `tls12`, `tls13`, or `auto` for version selection
- Optional key log path for debugging with Wireshark

Study `applications/https_client/` for:

- Loading trust material and server name (SNI)
- Driving `noxtls_tls13_connect` or the unified connect helper
- Reading/writing application data after the handshake completes

## Typical integration steps

### 1. Configure the build

For a minimal TLS **client** firmware image:

```bash
cmake -S . -B build \
  -D NOXTLS_PROFILE=minimal_tls_client \
  -D BUILD_APPLICATIONS=OFF \
  -D BUILD_TESTS=OFF
```

See [Configuration Guide](../configuration-guide) for what each profile enables.

### 2. Create a TLS context

- **TLS 1.3:** `tls13_context_t` — initialize with `noxtls_tls13_context_init`, set SNI, ALPN, and trust anchors as needed.
- **Unified:** `noxtls_tls_unified` helpers negotiate version when both 1.2 and 1.3 are enabled.

### 3. Wire transport callbacks

Implement send/receive (or use your socket layer) so the TLS stack can exchange records. The stack does not open sockets for you on embedded targets.

### 4. Run the handshake

Call `noxtls_tls13_connect` (or unified equivalent), check the return code, then use `noxtls_tls13_send` / `noxtls_tls13_recv` for application data.

### 5. Verify the server

Configure trusted CAs or certificate pins. For development, you can use the [Cert utility](../applications/app_cert) to inspect server chains:

```bash
./binary/cert verify -i server.der
```

Production devices should use a minimal trust store and proper hostname verification (SNI + certificate name checks).

## TLS 1.2 vs TLS 1.3

| Topic | TLS 1.3 | TLS 1.2 |
|-------|---------|---------|
| Handshake | 1-RTT (faster) | Often 2-RTT |
| Cipher suites | AEAD only (AES-GCM, ChaCha20-Poly1305) | Also legacy CBC if explicitly enabled |
| APIs | [tls13](../api/tls13) | [tls12](../api/tls12) |

Prefer **TLS 1.3** for new designs unless you must interop with legacy servers.

## Post-quantum key exchange (optional)

When `NOXTLS_CFG_FEATURE_ML_KEM=ON`, TLS 1.3 can offer ML-KEM and X25519 hybrid groups. See [TLS 1.3 PQC](../api/tls13_pqc) and [Quantum crypto](../quantum-crypto).

## Related samples

| Application | Purpose |
|-------------|---------|
| [HTTPS client](../applications/app_https_client) | Full HTTPS fetch over TLS |
| [TLS test](../applications/app_tls_test) | Lower-level TLS exercise harness |

## Next steps

- Server on the other end: [Build Your First HTTPS Server](./https-server)
- UDP and packet loss: [Run DTLS on Embedded Devices](./dtls-embedded)
- Platform hooks: [Port NoxTLS to Your Platform](./port-to-platform)
