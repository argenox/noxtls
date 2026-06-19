---
sidebar_position: 1
title: ESP32
description: Run NoxTLS on ESP32 with ESP-IDF, hardware acceleration, and benchmark examples.
keywords:
  - esp32
  - esp-idf
  - espressif
  - demo
  - embedded
---

# NoxTLS ESP32 Support

NoxTLS provides robust fast TLS and cryptographic capabilities for ESP32 and other Espressif microcontrollers through a dedicated ESP-IDF component. The library is designed for portability, efficient resource use, and hardware acceleration on supported ESP chips.

With ESP-IDF integration, NoxTLS enables secure communications with TLS 1.3, TLS 1.2, and DTLS (Datagram TLS), supporting a broad set of cipher suites, modern algorithms (AES-GCM, ChaCha20-Poly1305, ECDHE, Ed25519/Ed448, X25519/X448), and X.509 certificate handling.

**Key features and benefits:**

- **ESP-IDF compatibility:** Works with ESP-IDF 5.x and 6.x, supporting all mainstream ESP32 variations (ESP32, S2, S3, C3, C2, C5, C6, C61).
- **Hardware acceleration:** Utilizes chip-specific accelerators for significant performance improvements in AES, SHA-256, ECC, and ECDSA, while retaining portable fallbacks for unsupported operations.
- **Compact and configurable:** Feature selection is highly customizable via Kconfig or project-local `noxtls_config.h`, letting you optimize for footprint and memory constraints.
- **Reference examples:** In-tree ESP-IDF examples (benchmark, TLS client/server, etc.) demonstrate setup, acceleration, and integration with ESP-IDF build tooling.
- **Component registry:** NoxTLS is available via the ESP Component Registry, enabling simple integration into projects via `idf.py` and manifest (`idf_component.yml`).

This makes NoxTLS an excellent choice for secure embedded applications requiring high assurance, performance, and maintainability on ESP32 hardware, from IoT products to development and test tools.


## NoxTLS ESP32 Component

NoxTLS integrates with **ESP-IDF** as an extra component. On ESP32 targets the library can use on-chip accelerators for AES, SHA-256, ECC, and ECDSA when enabled in your build.

## Prerequisites

- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/) installed (v5.x to v6.0.1 and above)
- USB serial port for `idf.py flash monitor`
- Target chip selected with `idf.py set-target` (e.g. `esp32`, `esp32s3`)


## HTTPS Server Demo

The NoxTLS repository includes a full-featured **HTTPS server demo** designed for ESP32 and other supported targets using ESP-IDF. This application demonstrates modern TLS 1.3 server mode (with fallback to TLS 1.2), certificate/key provisioning, and secure HTTP endpoint delivery with TLS diagnostics.

**Location:**  
[`applications/https_server`](../../../applications/https_server/README.md)

**Key features of the demo:**
- Listens for incoming HTTPS connections using NoxTLS on your selected ESP32 variant
- Supports standard TLS 1.3 cipher suites, including AES-GCM and ChaCha20-Poly1305, with on-chip acceleration if available
- Accepts configurable certificate and private key files (PEM or DER), enabling both ECDSA and RSA authentication
- Diagnostic webpage includes negotiated cipher, protocol, and handshake details, showcasing NoxTLS library output
- Start/stop via ESP-IDF project console (`idf.py flash monitor`)

**See demo build and usage details in [applications/https_server/README.md](../../../applications/https_server/README.md)**

This README includes step-by-step instructions for compiling, flashing, configuring network/port, and supplying certificates and private keys suited for your ESP32 board and network.


### Add NoxTLS as a component to your project

The easiest way to integrate NoxTLS to your project is to use the [NoxTLS ESP Component](https://components.espressif.com/components/argenox/noxtls) from the ESP-IDF Registry

1. **Create (or update) `idf_component.yml` in your ESP-IDF project root:**

    ```yaml
    dependencies:
      argenox/noxtls: "^0.2.56"
    ```

    This instructs ESP-IDF to fetch and integrate NoxTLS automatically at build time.

2. **(Re)configure your project:**

    ```bash
    idf.py reconfigure
    ```

3. **Include NoxTLS headers and link as needed:**

    ```c
    #include <noxtls/noxtls.h>
    // Use library as described in the main API docs
    ```

4. **Configure features:**  
   Provide a project-local `noxtls_config.h` (copy from [example](https://github.com/argenox/noxtls/blob/main/noxtls_config.h)), or set options using Kconfig menu (`idf.py menuconfig`) if available.

For more, see the [ESP Registry page](https://components.espressif.com/components/argenox/noxtls) and the in-tree component [README](../../../ports/esp-idf/README.md).


Provide a project-local `noxtls_config.h` (or use Kconfig-generated settings) to trim features for flash and RAM — see [Configuration Guide](../configuration-guide).



## ESP32 acceleration (default)

NoxTLS is built by default to use accelerataion components that are available. When building for ESP-IDF, PKC and AES paths will link:

- `noxtls_esp32_aes_accel.c` — hardware GCM/AES where supported
- `noxtls_esp32_sha256_accel.c` — hardware SHA with size thresholds
- `noxtls_esp32_ecc_accel.c` / `noxtls_esp32_ecdsa_accel.c` — MPI and ECDSA helpers
- `noxtls_esp32_bignum_mpi.c` — big-number acceleration

These are selected automatically when the ESP-IDF build defines the appropriate SoC capabilities. Portable fallbacks remain if a primitive is unavailable.

## TLS / network on ESP32

Use ESP-IDF **lwIP** sockets (or your network stack) to send and receive TLS records. NoxTLS does not replace lwIP; wire `send`/`recv` (or the TLS transport callbacks) to your socket handles after `connect` or `accept`.

For development:

1. Prove crypto with the in-tree benchmark firmware.
2. Add TLS client or server logic using the same APIs as on the host ([TLS component](../tls)).
3. Trim `noxtls_config.h` to the cipher suites and protocol versions you ship.

## Troubleshooting

| Symptom | Suggestion |
|---------|------------|
| Component not found | Verify `EXTRA_COMPONENT_DIRS` path to `noxtls/ports/esp-idf` |
| Flash size warning | Align `sdkconfig` flash size with your module (see benchmark notes in internal perf logs) |
| Task watchdog during long AES loops | Expected on heavy benchmarks; increase WDT timeout or yield in test loops |

## Related guides

- [Port NoxTLS to Your Platform](../start-here/port-to-platform)
- [Run DTLS on Embedded Devices](../start-here/dtls-embedded)
- [Host Computer](./host-computer) — validate algorithms before flashing
