# NoxTLS secure OTA (ESP-IDF)

Reference secure firmware update flow:

1. HTTPS download via NoxTLS TLS 1.3.
2. Stream image into OTA partition.
3. Compute SHA-256 while downloading.
4. Optionally enforce expected SHA-256 from config.
5. Mark next boot partition on success.

## Build

```sh
cd noxtls/ports/esp-idf/examples/secure_ota
idf.py set-target esp32s3
idf.py build flash monitor -p COM34
```

## Important

- Replace `main/certs/root_ca.pem` with the CA for your OTA server.
- Set `NOXTLS_SECURE_OTA_EXPECTED_SHA256_HEX` for integrity pinning. A non-empty value that is not exactly 64 hex characters makes every update fail, so a typo cannot silently disable the pin.
- The update is staged only when the server ends the download with an authenticated `close_notify`; a cut or forged stream aborts it.
- Secure Boot and Flash Encryption are controlled by ESP-IDF bootloader/security config; this app logs whether those configs are enabled.
