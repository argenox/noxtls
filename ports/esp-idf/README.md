# NoxTLS Embedded Crypto

[NoxTLS](https://noxtls.com) is a lightweight embedded TLS and cryptography library designed for constrained systems and IoT devices.

The ESP-IDF port provides native integration with Espressif's ESP-IDF framework, including optional hardware acceleration support for cryptographic operations on supported ESP32 targets.

## Overview

This library enables you to add security and TLS support for viarios Espressif SoCs. It provde

- **Fast**: Highly optimized math and cryptographic algorithms, with hardware acceleration where available, allow NoxTLS to outperform many other libraries in speed and efficiency.
- **Broad Support**: NoxTLS is designed for seamless integration with a wide array of Espressif SoCs and ESP-IDF versions.
- **Supported Features**:
    - TLS 1.2 and 1.3
    - X.509 certificate parsing and validation
    - Elliptic Curve Cryptography (ECDSA, ECDH) and X25519/Ed25519
    - RSA (sign, verify, encrypt, decrypt)
    - SHA-256, SHA-512, and other hashing algorithms
    - AES (ECB, CBC, CTR, GCM, CCM)
    - HMAC, HKDF
    - Hardware acceleration support (on capable chips)
    - Non-blocking I/O and small RAM footprint
    - Secure random number generation (hardware-backed if available)    
- **RAM Download and Execution**: Capability to load binaries into RAM and execute them for flexible firmware updates and testing.
- **Registers and Control**: Supports direct read/write access to device registers, changing transmission rates, and hardware reset functionalities.



### Supported Target Devices (ESP device being flashed)

| Target          | Status |
|:---------------:|:------:|
| ESP32-S2        |  🔶    |
| ESP32-S3        |  ✅    |
| ESP32-C2        |  ❌    |
| ESP32-C3        |  ❌    |
| ESP32-H2        |  ❌    |
| ESP32-C6        |  🚧    |
| ESP32-C5        |  🚧    |
| ESP32-P4        |  🚧    |
| ESP32-C61       |  🚧    |

**Legend**: ✅ Supported | ❌ Not supported | 🚧 Under development | 🔶 Compiles but Untested


## Running the Demo

> **Warning:**  
> **Currently, only the `examples/https_server` demo is fully tested and functional.**  
> All other examples are a work in progress and may not build or run correctly yet.


* Install ESP-IDF **5.0+** or **6.x** (tested with v5.5 and v6.0.1)
* Start
* Go to the `https_server` folder

    idf.py set-target esp32s3

We need to configure the SSID and Passphrase for your Access Point (AP) using menu config

    idf.py menuconfig

Go to `NoxTLS HTTPS server example` and modify the WiFI SSID and WiFi password


Exit and save the settings. Then we can build and flash

    idf.py build
    idf.py flash monitor

Once it runs you will see:


    I (1214) wifi:connected with TEST_AP, aid = 1, channel 6, BW20, bssid = 2c:14:af:43:0f:14
    I (1214) wifi:security: WPA3-SAE, phy: bgn, rssi: -57
    I (1224) wifi:pm start, type: 1

    I (1224) wifi:dp: 1, bi: 102400, li: 3, scale listen interval from 307200 us to 307200 us
    I (1224) wifi:set rx beacon pti, rx_bcn_pti: 0, bcn_timeout: 25000, mt_pti: 0, mt_time: 10000
    I (1294) wifi:AP's beacon interval = 102400 us, DTIM period = 1
    I (1814) wifi:<ba-add>idx:0 (ifx:0, 3c:64:cf:42:9f:94), tid:0, ssn:0, winSize:64
    I (2834) esp_netif_handlers: sta ip: 192.168.68.59, mask: 255.255.252.0, gw: 192.168.68.1
    I (2834) noxtls_https_server: got ip: 192.168.68.59
    I (2834) wifi:Set ps type: 0, coexist: 0

    I (3024) noxtls_https_server: listening on TCP port 443
    I (268524) wifi:<ba-add>idx:1 (ifx:0, 3c:64:cf:42:9f:94), tid:6, ssn:2, winSize:64


## Adding the component to an existing project

To add NoxTLS to another project, add it as an ESP-IDF dependency.
We recommend using the latest version as it will always contain the latest features and fixes.

```sh
idf.py add-dependency "argenox/noxtls"
```

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

`CONFIG_NOXTLS_ESP_HW_AES`, `CONFIG_NOXTLS_ESP_HW_SHA`, and the matching `CONFIG_MBEDTLS_HARDWARE_*` options depend on SoC capabilities (`SOC_AES_SUPPORTED`, `SOC_SHA_SUPPORTED`). Kconfig enables them by default only when the selected target has the peripheral. **Do not pin them in `sdkconfig.defaults` for multi-target projects** — use `idf.py set-target` and let Kconfig apply the right defaults, or add target-specific files such as `sdkconfig.defaults.esp32s3`.

Link from application components with `REQUIRES esp-idf` (component folder name).

Entropy is registered automatically via a GCC constructor in `src/noxtls_esp_idf_glue.c` when `CONFIG_NOXTLS_USE_ESP_ENTROPY` is set. You may also call `noxtls_esp_idf_init()` explicitly (see `include/noxtls_esp_idf.h`).

### ESP hardware crypto toggles

- `CONFIG_NOXTLS_ESP_HW_ECC`: Enables ECC point multiply offload via ESP HAL for supported targets/curves (currently NIST P-256).
- `CONFIG_NOXTLS_ESP_HW_ECDSA`: Enables ECDSA to use the ECC hardware multiply path when available.
- `CONFIG_NOXTLS_ESP_HW_MPI`: Registers NoxTLS bignum hooks for P-256 `mod` / `mod_exp` via the ESP MPI (PKC) layer. Requires `CONFIG_MBEDTLS_HARDWARE_MPI=y` in the **application** sdkconfig (NoxTLS does not use mbedTLS for TLS).
- `CONFIG_NOXTLS_ESP_HW_AES`: Enables AES block operations via ESP HAL (`esp_aes_*`).
- `CONFIG_NOXTLS_ESP_HW_SHA`: Enables SHA-224/SHA-256 block processing via ESP HAL (`esp_sha_*`).

These options fall back to software when a peripheral is absent, but the port glue must compile on every target you build for. After changing target, run `idf.py fullclean build` if you previously forced HW options in `sdkconfig`.

Target note:
- `esp32h2` / `esp32c2`: no AES hardware (`SOC_AES_SUPPORTED=0`); use software AES (Kconfig omits `CONFIG_NOXTLS_ESP_HW_AES`).
- `esp32s3` / `esp32c3`: no ECC peripheral (`SOC_ECC_SUPPORTED=0`), so `CONFIG_NOXTLS_ESP_HW_ECC` falls back to software ECC.
- `esp32c6` (and other SoCs with `SOC_ECC_SUPPORTED=1`): P-256 ECC offload is used when enabled.

`noxtls_esp_idf_init()` registers MPI hooks when enabled (also called from the entropy constructor when `CONFIG_NOXTLS_USE_ESP_ENTROPY=y`).

### Certificate validity (`NOXTLS_HAVE_TIME`)

X.509 validity checks use standard `time()` when `CONFIG_NOXTLS_HAVE_TIME` is enabled. On ESP-IDF, initialize SNTP (or set the RTC) before verifying certificates in production.

## Examples

Ready-to-build projects live under `ports/esp-idf/examples/`:

| Example | What it does |
|---------|--------------|
| [`https_server`](examples/https_server/) | TLS 1.3 HTTPS server with embedded PEM cert/key, returns an HTML page over Wi-Fi STA on `CONFIG_NOXTLS_HTTPS_SERVER_PORT` (default 8443). |

Build any of them with:

```sh
cd ports/esp-idf/examples/<name>
idf.py set-target <esp32 variant>
idf.py build flash monitor
```

The `tls_client` sample prints `NoxTLS TLS sample ready` by default (TLS context init only). For a live TLS 1.3 handshake, configure Wi-Fi/Ethernet in your project and add to `sdkconfig.defaults`:

```ini
CONFIG_NOXTLS_SAMPLE_TLS_CONNECT=y
CONFIG_NOXTLS_SAMPLE_TLS_HOST="example.com"
```

You must configure a trust anchor (X.509 CA) for production handshakes; see the [Porting Guide](../../docs/docs/porting-guide.md).

## Kconfig and `noxtls_config.h`

Each example includes its own configuration file for example [`examples/https_server/main/noxtls_config.h`](examples/https_server/main/noxtls_config.h), which can be overriden by the menuconfig.

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


## Further reading
- [NoxTLS Website](https://noxtls.com) — Main Project Website and information
- [NoxTLS Documentation](https://docs.noxtls.com) — Documentation on the NoxTLS Library
- [Argenox](https://www.argenox.com) — 
- [Porting Guide](../../docs/docs/porting-guide.md) — memory, entropy, and TLS transport
- [Configuration Guide](../../docs/docs/configuration-guide.md) — feature macros and footprint tuning

