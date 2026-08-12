---
sidebar_position: 6
title: DTLS PSK demo
description: "NoxTLS DTLS PSK demo sample application: build, usage, and command-line options."
---

# DTLS PSK demo

DTLS 1.2/1.3 PSK handshake demo.

Runs an in-process DTLS server and client with PSK. Optional arguments:
--chacha use ChaCha20-Poly1305; --aes use AES-GCM; 1.2 or 12 for DTLS 1.2;
1.3 or 13 for DTLS 1.3. Default is AES-GCM and DTLS 1.2.

DTLS PSK Demo

This demo exercises the DTLS 1.2/1.3 handshake plumbing with PSK.
It is intended as a functional smoke test and a starting point for interop checks.

Build
- Configure and build the demo target via the top-level CMake.
- The target name is `dtls_psk_demo`.

Interop Test Hooks (OpenSSL)
The demo itself does not open sockets; it is a logic-level handshake example.
For wire-level interop, use the library in your own UDP transport and verify
against OpenSSL:

DTLS 1.2 server (OpenSSL):
`openssl s_server -dtls1_2 -psk 0102030405060708 -psk_identity test -cipher PSK-AES128-CCM8 -accept 4444`

DTLS 1.2 client (OpenSSL):
`openssl s_client -dtls1_2 -psk 0102030405060708 -psk_identity test -cipher PSK-AES128-CCM8 -connect 127.0.0.1:4444`

DTLS 1.3 server (OpenSSL 3.x):
`openssl s_server -dtls1_3 -psk 0102030405060708 -psk_identity test -ciphersuites TLS_AES_128_GCM_SHA256 -accept 4444`

DTLS 1.3 client (OpenSSL 3.x):
`openssl s_client -dtls1_3 -psk 0102030405060708 -psk_identity test -ciphersuites TLS_AES_128_GCM_SHA256 -connect 127.0.0.1:4444`

Runtime cipher preference (TLS/DTLS 1.3)
- `dtls_psk_demo --chacha [1.2|1.3]` — prefer ChaCha20-Poly1305.
- `dtls_psk_demo --aes [1.2|1.3]` — prefer AES-GCM (default).
When using the full handshake API (`tls13_context_t`, `noxtls_tls13_connect` / `noxtls_tls13_accept`), call `noxtls_tls13_set_prefer_chacha20(ctx, 1)` before the handshake to prefer ChaCha, or `noxtls_tls13_set_prefer_chacha20(ctx, 0)` for AES-GCM.

DTLS Configuration APIs
The DTLS context exposes tuning functions (timeouts, MTU, ACK ranges,
anti-amplification limits). See `noxtls-lib/tls/noxtls_dtls_common.h`.

## Examples

dtls_psk_demo
dtls_psk_demo 1.3
dtls_psk_demo --chacha 1.2
dtls_psk_demo --aes 1.3

