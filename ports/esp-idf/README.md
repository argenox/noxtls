# NoxTLS on ESP-IDF

This directory contains the ESP-IDF component wrapper for [NoxTLS](https://github.com/argenox/noxtls). The core library stays in the repository root; this port only provides `idf_component_register()`, Kconfig, and ESP32 platform glue.

Other RTOS ports live alongside this one under `ports/` (for example `ports/zephyr/`).

## Add the component to your project

### Option A: `EXTRA_COMPONENT_DIRS` (local checkout)

Clone or submodule NoxTLS into your project, then in your app `CMakeLists.txt` **before** `project()`:

```cmake
list(APPEND EXTRA_COMPONENT_DIRS "/path/to/noxtls/ports/esp-idf")
```

Or set it from the example layout:

```cmake
list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../path/to/noxtls/ports/esp-idf")
```

### Option B: ESP-IDF Component Manager

When published to the registry:

```sh
idf.py add-dependency "argenox/noxtls"
```

Until then, use Option A with a git submodule or `EXTRA_COMPONENT_DIRS`.

## Enable in your application

In `sdkconfig.defaults` or `menuconfig`:

```ini
CONFIG_NOXTLS=y
CONFIG_NOXTLS_PROFILE_MINIMAL_TLS_CLIENT=y
CONFIG_NOXTLS_USE_ESP_ENTROPY=y
CONFIG_NOXTLS_ESP_HW_ECC=y
CONFIG_NOXTLS_ESP_HW_ECDSA=y
CONFIG_NOXTLS_ESP_HW_MPI=y
CONFIG_NOXTLS_ESP_HW_AES=y
CONFIG_NOXTLS_ESP_HW_SHA=y
CONFIG_MBEDTLS_HARDWARE_MPI=y
CONFIG_MBEDTLS_HARDWARE_SHA=y
CONFIG_MBEDTLS_HARDWARE_AES=y
```

Link from application components with `REQUIRES esp-idf` (component folder name).

Entropy is registered automatically via a GCC constructor in `src/noxtls_esp_idf_glue.c` when `CONFIG_NOXTLS_USE_ESP_ENTROPY` is set. You may also call `noxtls_esp_idf_init()` explicitly (see `include/noxtls_esp_idf.h`).

### ESP hardware crypto toggles

- `CONFIG_NOXTLS_ESP_HW_ECC`: Enables ECC point multiply offload via ESP HAL for supported targets/curves (currently NIST P-256).
- `CONFIG_NOXTLS_ESP_HW_ECDSA`: Enables ECDSA to use the ECC hardware multiply path when available.
- `CONFIG_NOXTLS_ESP_HW_MPI`: Registers NoxTLS bignum hooks for P-256 `mod` / `mod_exp` via the ESP MPI (PKC) layer. Requires `CONFIG_MBEDTLS_HARDWARE_MPI=y` in the **application** sdkconfig (NoxTLS does not use mbedTLS for TLS).
- `CONFIG_NOXTLS_ESP_HW_AES`: Enables AES block operations via ESP HAL (`esp_aes_*`).
- `CONFIG_NOXTLS_ESP_HW_SHA`: Enables SHA-224/SHA-256 block processing via ESP HAL (`esp_sha_*`).

These options are safe across multiple targets: unsupported SoCs automatically fall back to software paths.

Target note:
- `esp32s3` / `esp32c3`: no ECC peripheral (`SOC_ECC_SUPPORTED=0`), so `CONFIG_NOXTLS_ESP_HW_ECC` falls back to software ECC.
- `esp32c6` (and other SoCs with `SOC_ECC_SUPPORTED=1`): P-256 ECC offload is used when enabled.

`noxtls_esp_idf_init()` registers MPI hooks when enabled (also called from the entropy constructor when `CONFIG_NOXTLS_USE_ESP_ENTROPY=y`).

### Certificate validity (`NOXTLS_HAVE_TIME`)

X.509 validity checks use standard `time()` when `CONFIG_NOXTLS_HAVE_TIME` is enabled. On ESP-IDF, initialize SNTP (or set the RTC) before verifying certificates in production.

## Examples

Ready-to-build projects live under `ports/esp-idf/examples/`:

| Example | What it does |
|---------|--------------|
| [`tls_client`](examples/tls_client/) | TLS 1.3 client. Init-only by default; optional live handshake against a public host (`CONFIG_NOXTLS_SAMPLE_TLS_CONNECT=y`). |
| [`https_server`](examples/https_server/) | TLS 1.3 HTTPS server with embedded PEM cert/key, returns an HTML page over Wi-Fi STA on `CONFIG_NOXTLS_HTTPS_SERVER_PORT` (default 8443). |
| [`https_file_client`](examples/https_file_client/) | HTTPS file retrieval client: downloads an HTTP resource over NoxTLS TLS 1.3 and stores body bytes into SPIFFS. |
| [`benchmark`](examples/benchmark/) | No networking. Reports MB/s for SHA-256, AES-GCM, ChaCha20-Poly1305, HMAC-SHA-256, CTR-DRBG, plus ops/s for ECDSA P-256 sign / verify. |
| [`tls_library_compare`](examples/tls_library_compare/) | Side-by-side crypto benchmark for NoxTLS and mbedTLS (and wolfSSL when available) on one firmware image. |
| [`secure_ota`](examples/secure_ota/) | Secure OTA flow over NoxTLS HTTPS: stream firmware into OTA partition, hash while downloading, optional digest pin, switch boot partition on success. |
| [`ssh_client`](examples/ssh_client/) | SSH client integration example using `argenox/noxssh` transport API when that component is available in the ESP-IDF project. |
| [`ssh_server`](examples/ssh_server/) | SSH server integration scaffold (documents future wiring once upstream `noxssh` server APIs are available). |
| [`sftp_client`](examples/sftp_client/) | SFTP integration scaffold (documents future subsystem wiring once upstream `noxssh` exposes SFTP APIs). |

Build any of them with:

```sh
cd ports/esp-idf/examples/<name>
idf.py set-target esp32
idf.py build flash monitor
```

The `tls_client` sample prints `NoxTLS TLS sample ready` by default (TLS context init only). For a live TLS 1.3 handshake, configure Wi-Fi/Ethernet in your project and add to `sdkconfig.defaults`:

```ini
CONFIG_NOXTLS_SAMPLE_TLS_CONNECT=y
CONFIG_NOXTLS_SAMPLE_TLS_HOST="example.com"
```

You must configure a trust anchor (X.509 CA) for production handshakes; see the [Porting Guide](../../docs/docs/porting-guide.md).

## Kconfig and `noxtls_config.h`

ESP-IDF examples do **not** use the repository-root [`noxtls_config.h`](../../noxtls_config.h) (that file is for desktop apps and the default CMake build). Each example owns a local header, for example [`examples/https_server/main/noxtls_config.h`](examples/https_server/main/noxtls_config.h).

Configuration flow:

1. **menuconfig / `sdkconfig`** — `CONFIG_NOXTLS_*` symbols (from [`noxtls_config_catalog.xml`](../../noxtls_config_catalog.xml)).
2. **Generated `noxtls_config_features.h`** — written under the NoxTLS component build directory from `sdkconfig` via [`noxtls_esp_idf_config_header.cmake`](noxtls_esp_idf_config_header.cmake) (generated).
3. **Example `main/noxtls_config.h`** — includes the generated features header and `noxtls_check_config.h`; may add example-only macros (e.g. `NOXTLS_APP_STATIC_BUFFER_SIZE`).

Set `NOXTLS_APPLICATION_CONFIG_DIR` to your example’s `main/` directory in the project `CMakeLists.txt` **before** `project()` (see the bundled examples).

[`noxtls_esp_idf_kconfig.cmake`](noxtls_esp_idf_kconfig.cmake) (generated) also maps each `CONFIG_NOXTLS_*` symbol to:

- a **`NOXTLS_CFG_*` CMake cache variable** (controls which `.c` files are compiled), and/or
- **`target_compile_definitions(${COMPONENT_LIB} PUBLIC …)`** for header-only macros (buffer sizes, `NOXTLS_HAVE_TIME`, RSA tuning, and similar).

### Profile vs per-option tuning

| Profile in menuconfig | Effect |
|----------------------|--------|
| **default** | Individual Kconfig booleans/integers are applied to the build. |
| **minimal_tls_client**, **crypto_only**, etc. | Root [`CMakeLists.txt`](../../CMakeLists.txt) applies the same preset matrix as desktop builds; many per-option Kconfig values are overridden. |

Use profile **default** when you want `menuconfig` to drive every feature flag.

### Known limitation: non-default profiles

Some library call sites (e.g. `noxtls_hmac_init()` in `noxtls_tls_kdf.c`, key-share handling in `noxtls_tls13.c`, record protection in `noxtls_tls_record.c`, signature hashing in `noxtls_rsa.c` / `noxtls_ecdsa.c`) select primitives by **runtime** branch only and are not yet wrapped in `#if NOXTLS_FEATURE_*` preprocessor guards. As a result, picking a profile that drops e.g. SHA1, MD5, DH, or AES-CCM (`minimal_tls_client`, `tls_server_pki`, `fips_like_profile`) currently causes undefined-reference errors at link time when the TLS code is linked in.

Workaround: select `CONFIG_NOXTLS_PROFILE_DEFAULT=y` for any application that links against `noxtls_tls` and tune individual `NOXTLS_FEATURE_*` options manually. The included `https_server` example uses this approach. Crypto-only applications that never reference TLS objects (such as the `benchmark` example) are unaffected.

### Tuning RAM usage (buffer sizes)

Integer tunables are grouped under **Component config → NoxTLS → NoxTLS library options → Buffer sizes and limits (RAM tuning)**.

Example `sdkconfig.defaults` snippet for a footprint-conscious TLS 1.3 client:

```ini
CONFIG_NOXTLS=y
CONFIG_NOXTLS_PROFILE_MINIMAL_TLS_CLIENT=y

CONFIG_NOXTLS_TLS_MAX_RECORD_SIZE=4096
CONFIG_NOXTLS_TLS_MAX_WIRE_RECORD_LENGTH=4480
CONFIG_NOXTLS_TLS_MAX_HANDSHAKE_SIZE=4096
CONFIG_NOXTLS_MAX_CERT_SIZE=4096
CONFIG_NOXTLS_MAX_CERT_CHAIN_DEPTH=4
CONFIG_NOXTLS_STATIC_BUFFER_SIZE=16384
CONFIG_NOXTLS_ECC_POINT_MUL_WINDOW_SIZE=0
```

### Regenerating Kconfig from the catalog

After editing [`noxtls_config.h`](../../noxtls_config.h), refresh the catalog and port Kconfig files:

```sh
python noxtls/tools/config_catalog/generate_config_catalog.py
python noxtls/tools/kconfig_gen/generate_kconfig.py
```

Commit the updated `noxtls_config_catalog.xml`, `ports/zephyr/Kconfig.noxtls.generated`, `ports/zephyr/noxtls_zephyr_kconfig.cmake`, `ports/esp-idf/Kconfig.noxtls.generated`, `ports/esp-idf/noxtls_esp_idf_kconfig.cmake`, and `ports/esp-idf/noxtls_esp_idf_config_header.cmake`.

To verify generated files are current:

```sh
python noxtls/tools/kconfig_gen/generate_kconfig.py --check
```

## Further reading

- [Porting Guide](../../docs/docs/porting-guide.md) — memory, entropy, and TLS transport
- [Configuration Guide](../../docs/docs/configuration-guide.md) — feature macros and footprint tuning
- [Zephyr port](../zephyr/README.md) — parallel integration for Zephyr RTOS
