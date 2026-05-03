---
sidebar_position: 7
title: "TLS component"
---

# TLS component

The NoxTLS TLS component implements **Transport Layer Security (TLS)** and **Datagram TLS (DTLS)** for secure client and server connections. It supports TLS 1.0, 1.1, 1.2, and 1.3, and DTLS 1.2 and 1.3.

## Supported versions and features

| Protocol   | Versions   | Key exchange              | Ciphers                          |
|-----------|------------|---------------------------|----------------------------------|
| TLS       | 1.0–1.3    | RSA, ECDHE, DHE, PSK, ECDHE-PSK | AES-GCM/CCM, ChaCha20-Poly1305, AES-CBC, ARIA |
| DTLS      | 1.2, 1.3   | Same as TLS               | Same as TLS                      |

- **TLS 1.3:** Full handshake, session resumption (tickets), 0-RTT early data, PSK and ECDHE-PSK, client authentication (mTLS), ALPN, SNI.
- **TLS 1.2:** ECDHE-RSA, DHE-RSA, ECDHE-ECDSA cipher suites; renegotiation (RFC 5746); Encrypt-then-MAC, Extended Master Secret.
- **DTLS:** Fragmentation, retransmission, cookie exchange (Hello Verify Request), replay protection; DTLS 1.3 uses the unified header and connection ID (RFC 9147).

## Architecture

- **Base context** ([tls_context_t](/docs/api/tls#tls_context_t)) holds role (client/server), I/O callbacks, and state. TLS 1.2 and 1.3 use version-specific contexts that extend the DTLS/TLS base.
- **I/O is callback-based:** you provide [tls_send_callback_t](/docs/api/tls#tls_send_callback_t) and [tls_recv_callback_t](/docs/api/tls#tls_recv_callback_t) so the library sends and receives records over your transport (sockets, etc.).
- **Server version negotiation:** use [tls_accept_auto](/docs/api/tls#tls_accept_auto) to accept a Client Hello and route to the right TLS 1.2 or 1.3 handler.

## Typical usage

### TLS client (TLS 1.2 or 1.3)

1. Create a version-specific context: [tls12_context_init](/docs/api/tls12#tls12_context_init) or [tls13_context_init](/docs/api/tls13#tls13_context_init).
2. Set I/O callbacks with [noxtls_tls_set_io_callbacks](/docs/api/tls#noxtls_tls_set_io_callbacks) (and optional time callback).
3. **(Optional)** Set SNI: `ctx->base.server_name` / `server_name_len` (TLS 1.2) or same for TLS 1.3.
4. **(Optional)** For mutual TLS (TLS 1.3): [tls13_set_client_cert](/docs/api/tls13#tls13_set_client_cert) (or ECDSA/Ed25519 variants).
5. Call [tls12_connect](/docs/api/tls12#tls12_connect) or [tls13_connect](/docs/api/tls13#tls13_connect) to run the handshake.
6. Use [tls12_send](/docs/api/tls12#tls12_send) / [tls12_recv](/docs/api/tls12#tls12_recv) or [tls13_send](/docs/api/tls13#tls13_send) / [tls13_recv](/docs/api/tls13#tls13_recv) for application data.
7. Shut down with [tls12_close](/docs/api/tls12#tls12_close) or [tls13_close](/docs/api/tls13#tls13_close), then [tls12_context_free](/docs/api/tls12#tls12_context_free) or [tls13_context_free](/docs/api/tls13#tls13_context_free).

### TLS server (TLS 1.2 or 1.3)

1. Create a context with [tls12_context_init](/docs/api/tls12#tls12_context_init) or [tls13_context_init](/docs/api/tls13#tls13_context_init).
2. Set I/O callbacks (and optional time callback).
3. Set server certificate: assign `server_cert` / `server_cert_len` (DER), and for TLS 1.2 with ECDHE-RSA/DHE-RSA set the server private key with [tls12_set_server_private_rsa](/docs/api/tls12#tls12_set_server_private_rsa); for TLS 1.3 use [tls13_set_server_private_rsa](/docs/api/tls13#tls13_set_server_private_rsa).
4. Call [tls12_accept](/docs/api/tls12#tls12_accept) or [tls13_accept](/docs/api/tls13#tls13_accept) to run the handshake.
5. Use send/recv for application data; close and free when done.

### Server with automatic version negotiation

1. Allocate a [tls_context_t](/docs/api/tls#tls_context_t) plus [tls12_context_t](/docs/api/tls12#tls12_context_t) and [tls13_context_t](/docs/api/tls13#tls13_context_t).
2. Set I/O on the base context; initialize both TLS 1.2 and TLS 1.3 contexts and configure certificates/keys for each.
3. Read the first record (Client Hello); call [tls_accept_auto](/docs/api/tls#tls_accept_auto) with the base context and the two version-specific contexts. It detects the version and completes the handshake on the appropriate context.
4. Use the negotiated context (TLS 1.2 or 1.3) for send/recv and close.

### DTLS

Use [dtls12_context_init](/docs/api/dtls#dtls12_context_init) or [dtls13_context_init](/docs/api/tls13#dtls13_context_init). Set MTU and retransmission with [dtls_set_mtu](/docs/api/dtls#dtls_set_mtu) and [dtls_set_retransmit](/docs/api/dtls#dtls_set_retransmit). Then use the same connect/accept and send/recv pattern as TLS; the library handles fragmentation and retransmission.

## Configuration

- **Certificates:** Supply server (and optionally client) certificate as DER in the context. Chain verification uses the library’s X.509 and PKC support; ensure [NOXTLS_FEATURE_CERT](/docs/configuration-guide) and required algorithms are enabled.
- **Cipher preference:** TLS 1.3 supports [tls13_set_prefer_chacha20](/docs/api/tls13#tls13_set_prefer_chacha20) to prefer ChaCha20-Poly1305 over AES-GCM.
- **Fragment length:** TLS 1.2 supports [tls12_set_max_fragment_length](/docs/api/tls12#tls12_set_max_fragment_length) (RFC 6066).
- **PSK (TLS 1.3):** [tls13_set_external_psk](/docs/api/tls13#tls13_set_external_psk) configures identity and key for PSK or ECDHE-PSK.
- **Record size limits:** Configure [NOXTLS_TLS_MAX_RECORD_SIZE](/docs/configuration-guide) and [NOXTLS_TLS_MAX_HANDSHAKE_SIZE](/docs/configuration-guide) in `noxtls_config.h` so the largest message (e.g. certificate chain) fits.

## API reference

- **[TLS API (common)](/docs/api/tls)** — Base context, I/O callbacks, record types, constants, version detection, and extension parsing.
- **[TLS 1.2 API](/docs/api/tls12)** — TLS 1.2 context, connect/accept, send/recv, handshake steps, and server key/certificate setup.
- **[TLS 1.3 API](/docs/api/tls13)** — TLS 1.3 context, connect/accept, early data, PSK, client auth, and session resumption.
- **[DTLS API](/docs/api/dtls)** — DTLS context, MTU, retransmission, fragmentation, and cookie handling.

## Sample applications

- [HTTPS client](/docs/applications/app_https_client) and [HTTPS server](/docs/applications/app_https_server) — TLS over TCP.
- [TLS test](/docs/applications/app_tls_test) — Test and demo usage.
- [DTLS PSK demo](/docs/applications/app_dtls_psk_demo) and [DTLS PSK test](/docs/applications/app_dtls_psk_test) — DTLS with pre-shared keys.
