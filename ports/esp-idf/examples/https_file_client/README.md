# NoxTLS HTTPS file client (ESP-IDF)

Downloads a file over HTTPS using `noxtls_tls13_connect` + HTTP GET and stores the response body into SPIFFS.

## Build

```sh
cd noxtls/ports/esp-idf/examples/https_file_client
idf.py set-target esp32s3
idf.py build flash monitor -p COM34
```

## Notes

- Configure Wi-Fi, host, and path in `menuconfig` under **NoxTLS HTTPS file client example**.
- Replace `main/certs/root_ca.pem` with the CA certificate for your HTTPS endpoint.
- Output path defaults to `/spiffs/download.bin`.
- The body is written to `<output path>.part` and renamed into place only after a `200` response whose body length matches `Content-Length` (when sent) has ended with an authenticated `close_notify`. A TCP close, a record that fails authentication or a write error deletes the partial file and reports failure.
