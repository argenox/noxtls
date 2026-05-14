# tlscurl

HTTPS test utility with **curl-like** request options and **verbose TLS diagnostics** (negotiated cipher, TLS 1.3 key exchange group, 0-RTT / session ticket fields, optional record dump and NSS key log).

## Build

From the `noxtls` tree (with `BUILD_APPLICATIONS=ON`):

```bash
cmake -B build -D BUILD_TESTS=OFF
cmake --build build --target tlscurl
```

The executable is placed under `noxtls/binary/` when using the default `NOXTLS_APPLICATIONS_BINARY_DIR`.

## Usage

```text
tlscurl <https://host[:port]/path> [options]
```

### Request options

| Option | Description |
|--------|-------------|
| `-X`, `--method` | HTTP method (default `GET`). |
| `-H`, `--header` | Add a header line `Name: value` (repeatable). |
| `-d`, `--data` | Small request body from string. |
| `--data-file` | Request body from file (max 1 MiB). |
| `-o`, `--output` | Write response body to file (`-` = stdout). |

### TLS options

| Option | Description |
|--------|-------------|
| `--ca` | Trust anchors from a PEM bundle or single PEM/DER certificate (required unless host is `localhost` / `127.0.0.1` and `server.crt` exists). |
| `--crl` | Optional CRL file (PEM/DER). Enables certificate revocation checks during chain validation. |
| `--pin-sha256` | Optional SPKI pin check for the leaf certificate (`sha256/<base64>` or raw base64 digest). |
| `--tls12`, `--tls13`, `--auto` | Force TLS 1.2, TLS 1.3, or try 1.3 then fall back to 1.2 (default: `--tls12`). |
| `--keylog` | NSS key log path for TLS 1.3 (Wireshark). If unset, `SSLKEYLOGFILE` is honored when set. |
| `--tlsdump` | Append TLS record hex dump (see `noxtls_tls_set_record_dump_file`). |
| `--prefer-chacha` | Set TLS 1.3 context `prefer_chacha20` so ClientHello prefers ChaCha20-Poly1305. |

### Diagnostics

| Option | Description |
|--------|-------------|
| `-v`, `--verbose` | Log platform, compile-time TLS feature flags, and response boundaries. Use twice (`-vv`) for extra TLS fields (e.g. handshake buffer sizes). |

On failure, `tlscurl` prints the NoxTLS return code and, for certificate-related errors, calls `noxtls_cert_verify_failure_get()` to print subject DN, expected hostname, validity window, and chain index when populated.

### Examples

```bash
# Verbose GET with system CA bundle (example path)
./binary/tlscurl https://example.com/ --ca /path/to/ca-bundle.pem -v --auto

# POST JSON
./binary/tlscurl https://api.example.com/v1/foo --ca ca.pem --tls13 \
  -X POST -H "Content-Type: application/json" \
  -d '{"ok":true}' -o -

# Record dump + key log for test captures
./binary/tlscurl https://example.com/ --ca ca.pem --tls13 \
  --tlsdump /tmp/tls_records.hex --keylog /tmp/sslkeylog.txt
```

## Notes

- **0-RTT**: After a successful TLS 1.3 handshake, negotiated state is printed (`ticket_stored`, `early_data_accepted`, `early_data_sent`, etc.). Sending 0-RTT application data requires a resumed session inside the library’s handshake flow; this tool focuses on **observability** and standard HTTPS without extra library APIs.
- **TLS record dump** is global to the process (one dump file path at a time), matching `noxtls_tls_set_record_dump_file` behavior.
