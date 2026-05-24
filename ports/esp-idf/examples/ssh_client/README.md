# NoxTLS SSH client (ESP-IDF)

Runs SSH client flow using `argenox/noxssh` common API when `noxssh_common.h` is available in the ESP-IDF build.

## Build

```sh
cd noxtls/ports/esp-idf/examples/ssh_client
idf.py set-target esp32s3
idf.py build flash monitor -p COM34
```

## Dependency

Add `argenox/noxssh` (common module) as an ESP-IDF component include path so this example can compile the active SSH path.
Without it, the app builds and prints an integration warning at runtime.
