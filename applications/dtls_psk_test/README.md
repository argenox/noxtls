# DTLS PSK Test Application

Single-process test: a DTLS server and client (PSK) exchange application data over in-memory UDP and verify that the payloads received match what was sent.

## What it does

1. Creates server and client DTLS contexts (DTLS 1.2, pre-shared key).
2. Simulates UDP with two buffers (server↔client, client↔server).
3. Performs a minimal handshake (ClientHello, ServerHello).
4. **Server → Client:** sends `MSG_SERVER_TO_CLIENT`; client receives and verifies.
5. **Client → Server:** sends `MSG_CLIENT_TO_SERVER`; server receives and verifies.
6. Exits 0 if all checks pass, 1 otherwise.

## Build

From the project root (with DTLS enabled, default):

```bash
cmake -B build -DBUILD_DTLS=ON .
cmake --build build
```

Then run:

```bash
./build/applications/dtls_psk_test/dtls_psk_test   # Unix
build\applications\dtls_psk_test\Debug\dtls_psk_test.exe   # Windows VS
```

## Usage

No arguments. Output is pass/fail per step and a final exit code (0 = success, 1 = failure).

## Requirements

- `BUILD_DTLS=ON` when building the NoxTLS library (default in `noxtls-lib/tls`).
