---
sidebar_position: 4
title: Build Your First HTTPS Server
description: Run and integrate a NoxTLS TLS server with certificates using the HTTPS server sample.
keywords:
  - tls server
  - https
  - tutorial
  - certificate
---

# Build Your First HTTPS Server

This guide covers standing up a **TLS server** that terminates HTTPS-style traffic over TCP. You will use the bundled `https_server` sample, then map the same ideas into your firmware or service.

## Before you start

- [5 Minute Quickstart](./quickstart) — build environment ready
- [Configure Certificates](./configure-certificates) — if you need to generate or convert PEM/DER material
- API references: [TLS 1.3](../api/tls13), [TLS 1.2](../api/tls12), [Certificates](../api/certs)

## Run the sample HTTPS server

```bash
cmake -S . -B build -D BUILD_TESTS=OFF
cmake --build build --config Release
```

Generate or obtain a server certificate and private key (PEM). For local testing, OpenSSL can create a self-signed pair:

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
```

Start the server:

```bash
./binary/https_server 8443 --cert server.crt --key server.key
```

Connect with the sample client or any TLS client:

```bash
./binary/https_client https://127.0.0.1:8443 tls13
```

See [HTTPS server app](../applications/app_https_server) for all CLI options.

## Server build profile

For PKI-heavy server deployments (RSA/ECDSA, cert parsing, TLS 1.2+1.3):

```bash
cmake -S . -B build \
  -D NOXTLS_PROFILE=tls_server_pki \
  -D BUILD_APPLICATIONS=OFF \
  -D BUILD_TESTS=OFF
```

`tls_server_pki` keeps TLS and certificate features needed for typical HTTPS while trimming unrelated algorithms. Details are in [Configuration Guide](../configuration-guide).

## Integration outline

### 1. Load server credentials

- Install the end-entity certificate chain the server will present.
- Load the private key (RSA, ECDSA, or Ed25519 depending on suite and config).
- For TLS 1.3 with ML-DSA (optional), use `noxtls_tls13_set_server_private_mldsa` — see [TLS 1.3 PQC](../api/tls13_pqc).

Use [Cert utility](../applications/app_cert) to validate material before wiring it into TLS:

```bash
./binary/cert info -i server.crt
./binary/cert keyinfo -i server.key
```

### 2. Initialize server context

Create `tls13_context_t` (or TLS 1.2 context), set cipher/policy options, session ticket hooks if needed, and listening-oriented ALPN defaults.

### 3. Accept connections

On each incoming TCP connection:

1. Associate a fresh or pooled TLS context with the connection.
2. Call `noxtls_tls13_accept` (handshake as server).
3. Read/write application data with `noxtls_tls13_send` / `noxtls_tls13_recv`.

### 4. Client authentication (optional)

Enable mTLS by requiring a client certificate and registering verify callbacks. Documented under [TLS component](../tls) and [Certificates API](../api/certs).

## Operational tips

| Topic | Recommendation |
|-------|----------------|
| Cipher preference | Prefer TLS 1.3 + AEAD suites; disable legacy CBC unless required |
| Session tickets | Enable for resumed handshakes on busy servers |
| OCSP stapling | Supported on TLS 1.2 path; see [TLS component](../tls) |
| Debug | Compare against `https_server` and optional TLS key logs from `https_client` |

## Related samples

| Application | Role |
|-------------|------|
| [HTTPS server](../applications/app_https_server) | Minimal page over TLS |
| [Certificate app](../applications/app_certificate) | Broader cert tooling |
| [Certgen](../applications/app_certgen) | Generation helpers (when enabled in build) |

## Next steps

- Embedded UDP services: [Run DTLS on Embedded Devices](./dtls-embedded)
- Trust stores and chains: [Configure Certificates](./configure-certificates)
- RTOS integration: [Port NoxTLS to Your Platform](./port-to-platform)
