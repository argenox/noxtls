# HTTPS Server

Example HTTPS server using the NoxTLS TLS library.

## Building

Built as part of the main project when `BUILD_APPLICATIONS` is ON. Target name: `https_server`.

## Usage

`https_server [port] [options]`

Key options:

- `-if <ip>` or `--interface <ip>` to bind a specific IPv4 interface (default: `127.0.0.1`)
- `-v` for standard debug output
- `-vv` for full debug output (including verbose TLS13 traces)
- `--cert <file>` and `--cert-format auto|pem|der`
- `--key <file>` and `--key-format auto|pem|der`
- `--tls12-cert <file>` and `--tls12-key <file>` to enable RSA-based TLS 1.2 fallback when primary key is non-RSA
- `--tls12-cert-format auto|pem|der` and `--tls12-key-format auto|pem|der`
- `--cipher-suites <suite1,suite2,...>` where suites are names like `TLS_AES_128_GCM_SHA256` or hex ids like `0x1303`
- `--debug-log <file>` to append noxtls debug output to a log file
- `--unified` to use the unified TLS API path

Private key algorithms:

- RSA (TLS 1.2 and TLS 1.3 paths)
- ECDSA, Ed25519, Ed448 (TLS 1.3 path)

The server returns an HTTP 200 page that includes the negotiated TLS version, ciphersuite, key exchange, bulk cipher, and handshake hash details.
