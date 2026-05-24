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
