# NoxTLS HTTPS server (ESP-IDF)

Minimal HTTPS server that runs a TLS 1.3 handshake against any modern browser or `curl`, then returns a small HTML page describing the negotiated cipher suite.

## What it does

1. Connects to WiFi as a station (`CONFIG_NOXTLS_HTTPS_SERVER_WIFI_SSID`).
2. Parses an embedded server certificate and private key (PEM, in `certs/`).
3. Listens on `CONFIG_NOXTLS_HTTPS_SERVER_PORT` (default 8443).
4. For each client: runs `noxtls_tls13_accept()` (with ALPN `http/1.1` / `h2`), reads the HTTP request, returns a static `HTTP/1.0 200 OK` page, closes the connection.

## Generate a server certificate

The example ships with **placeholder** files in `certs/`. The TLS parser will reject them — replace with a real cert and key before flashing.

For a quick self-signed demo cert (RSA-2048, 1-year validity, CN=`esp32.local`):

```sh
cd certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj '/CN=esp32.local' \
    -keyout server_key.pem -out server_cert.pem
```

ECDSA P-256 alternative:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out server_key.pem
openssl req -new -x509 -days 365 -key server_key.pem -out server_cert.pem \
    -subj '/CN=esp32.local'
```

**Recommended on ESP32 (faster handshake):** Ed25519 — software signing is much faster than ECDSA P-256, so browsers are less likely to time out during `CertificateVerify`:

```sh
cd certs
openssl genpkey -algorithm ED25519 -out server_key.pem
openssl req -new -x509 -days 365 -key server_key.pem -out server_cert.pem \
    -subj '/CN=esp32.local'
```

Or with NoxTLS certgen (from repo root): `certgen gened25519 -out server` then copy/rename outputs into `certs/`.

Both RSA, ECDSA, and Ed25519 keys are supported; the example picks the signing path from the parsed key type.

### `handshake failed: FAILED (1)` with `peer_alert=1`

That pattern means the **client** aborted (usually a fatal alert) while the server was still handshaking — very often because the first **ECDSA P-256 CertificateVerify** takes several seconds on the CPU and Chrome/curl closes the connection first. Switch to **Ed25519** certs (above), rebuild/flash, and retry. Optional: enable **Verbose NoxTLS handshake logging** in menuconfig to see the exact step on UART.

## Configure WiFi

```sh
idf.py menuconfig
# NoxTLS HTTPS server example -> WiFi SSID / password
# (or set CONFIG_NOXTLS_HTTPS_SERVER_USE_WIFI=n and bring the network up yourself)
```

You can also set the values directly in `sdkconfig.defaults`:

```ini
CONFIG_NOXTLS_HTTPS_SERVER_WIFI_SSID="myssid"
CONFIG_NOXTLS_HTTPS_SERVER_WIFI_PASSWORD="mypassword"
CONFIG_NOXTLS_HTTPS_SERVER_PORT=8443
```

## Build and flash

```sh
cd noxtls/ports/esp-idf/examples/https_server
idf.py set-target esp32
idf.py build flash monitor
```

Once the device prints `got ip: <address>` and `listening on TCP port 8443`, connect from a host on the same network:

```sh
curl -k https://<device-ip>:8443/
```

The `-k` is required because the self-signed certificate is untrusted by default. For production, add the cert to your client trust store or sign with a real CA.

## NoxTLS configuration

This example uses **`main/noxtls_config.h`**, not the shared [`noxtls/noxtls_config.h`](../../../../noxtls_config.h) at the repo root. Feature flags and buffer sizes come from **menuconfig** (`Component config → NoxTLS`); the build generates `noxtls_config_features.h` from your `sdkconfig`. Edit `sdkconfig.defaults` for checked-in defaults (e.g. DTLS off, record buffer sizes).

## Footprint and tuning

The example uses the `default` NoxTLS profile (`CONFIG_NOXTLS_PROFILE_DEFAULT=y`). The narrower `tls_server_pki` profile would be a better fit for production — it drops PQC, legacy ciphers, MD5, SHA1, DH, AES-CCM, and enables `NOXTLS_HAVE_CERT_WRITE=ON` — but the library currently still references the disabled primitives from runtime-selected branches in TLS / RSA / ECDSA code, which fails to link with the profile's stricter source-file gating. See [parent README → Known limitation](../../README.md#known-limitation-non-default-profiles) for details.

To reduce RAM, override per-buffer values in `sdkconfig.defaults` — see the [parent README → Tuning RAM](../../README.md#tuning-ram-usage-buffer-sizes).

This example disables DTLS (`CONFIG_NOXTLS_FEATURE_DTLS` off in `sdkconfig.defaults`): TLS 1.3 over TCP only, links the DTLS stub instead of `noxtls_dtls_common.c`.

The main task stack is 24 KB (`CONFIG_ESP_MAIN_TASK_STACK_SIZE=24576`); `tls13_context_t` is heap-allocated per connection.

The first TLS handshake runs software ECDSA P-256 for `CertificateVerify` (often 1–3 seconds on ESP32-S3). After changing `sdkconfig.defaults`, run **`idf.py fullclean build`** so `CONFIG_ESP_TASK_WDT_TIMEOUT_S=30` is applied (a plain `build` keeps an old 5 s timeout in `sdkconfig`).

Do **not** call `esp_task_wdt_add(NULL)` on the task that blocks in `accept()` — only IDLE tasks are watched by default, which is correct for this example. Subscribing `main` without feeding the watchdog in the accept loop causes a WDT error every 5 seconds while idle.

### Handshake failed with only `rc=1`

`1` is `NOXTLS_RETURN_FAILED` (generic). After a failed accept the example logs cipher suite, heap, and key type. For the failing step (e.g. `send_certificate_verify`), enable **NoxTLS HTTPS server example → Verbose NoxTLS handshake logging** in `menuconfig`, rebuild, and retry — UART will show `[TLS_DEBUG] tls13_accept: …` lines.

## Caveats

- This is a single-threaded one-client-at-a-time example. For concurrent clients use FreeRTOS tasks and one `tls13_context_t` per task.
- The server skips client-cert authentication. To require mTLS, set the appropriate fields on `tls13_context_t` before calling `noxtls_tls13_accept()`.
- The placeholder cert/key files only contain comments; the parser will fail with a clear log message until you generate real ones.

## Further reading

- [ESP-IDF port README](../../README.md)
- [Porting Guide](../../../../docs/docs/porting-guide.md) — entropy, time, and transport
