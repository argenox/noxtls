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

# ESP32 Demo

NoxTLS integrates with **ESP-IDF** as an extra component. On ESP32 targets the library can use on-chip accelerators for AES, SHA-256, ECC, and ECDSA when enabled in your build.

## Prerequisites

- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/) installed (v5.x recommended; v5.5.1 used in internal benchmarks)
- USB serial port for `idf.py flash monitor`
- Target chip selected with `idf.py set-target` (e.g. `esp32`, `esp32s3`)

## Add NoxTLS to your ESP-IDF project

Point ESP-IDF at the NoxTLS ESP-IDF component directory:

```cmake
# In your project CMakeLists.txt
list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/path/to/noxtls/ports/esp-idf")
```

Your application component then depends on the NoxTLS component (same pattern as the compare example below). The component pulls sources from `noxtls-lib/` and links ESP32-specific acceleration under `ports/esp-idf/target/esp32/`.

Provide a project-local `noxtls_config.h` (or use Kconfig-generated settings) to trim features for flash and RAM — see [Configuration Guide](../configuration-guide).

## Example: TLS library compare (repository)

A full firmware image that benchmarks NoxTLS against mbedTLS (and optionally wolfSSL) lives in the OEM tree:

```text
performance/apps/esp32/tls_library_compare/
```

Build and flash:

```bash
cd performance/apps/esp32/tls_library_compare
idf.py set-target esp32s3
idf.py build flash monitor -p COM34
```

Replace `COM34` with your port. See the example [README](https://github.com/argenox/noxtls/blob/main/performance/apps/esp32/tls_library_compare/README.md) for optional wolfSSL Component Manager setup.

## Example: ESP-IDF benchmark app (in-tree)

When present in your NoxTLS checkout:

```text
noxtls/ports/esp-idf/examples/benchmark
```

This image reports SHA-256, AES-GCM, ChaCha20-Poly1305, HMAC, DRBG, and ECDSA throughput on the device. Typical workflow:

```bash
cd noxtls/ports/esp-idf/examples/benchmark
idf.py set-target esp32s3
idf.py build flash monitor
```

## ESP32 acceleration (optional)

When building for ESP-IDF, PKC and AES paths can link:

- `noxtls_esp32_aes_accel.c` — hardware GCM/AES where supported
- `noxtls_esp32_sha256_accel.c` — hardware SHA with size thresholds
- `noxtls_esp32_ecc_accel.c` / `noxtls_esp32_ecdsa_accel.c` — MPI and ECDSA helpers
- `noxtls_esp32_bignum_mpi.c` — big-number acceleration

These are selected automatically when the ESP-IDF build defines the appropriate SoC capabilities. Portable fallbacks remain if a primitive is unavailable.

## TLS / network on ESP32

Use ESP-IDF **lwIP** sockets (or your network stack) to send and receive TLS records. NoxTLS does not replace lwIP; wire `send`/`recv` (or the TLS transport callbacks) to your socket handles after `connect` or `accept`.

For development:

1. Prove crypto with the benchmark or compare firmware.
2. Add TLS client or server logic using the same APIs as on the host ([TLS component](../tls)).
3. Trim `noxtls_config.h` to the cipher suites and protocol versions you ship.

## Troubleshooting

| Symptom | Suggestion |
|---------|------------|
| Component not found | Verify `EXTRA_COMPONENT_DIRS` path to `noxtls/ports/esp-idf` |
| Flash size warning | Align `sdkconfig` flash size with your module (see benchmark notes in internal perf logs) |
| Task watchdog during long AES loops | Expected on heavy benchmarks; increase WDT timeout or yield in test loops |
| mbedTLS much faster than NoxTLS in compare app | Compare uses mbedTLS’s ESP optimized paths; enable NoxTLS ESP accel and profile your production config |

## Related guides

- [Port NoxTLS to Your Platform](../start-here/port-to-platform)
- [Run DTLS on Embedded Devices](../start-here/dtls-embedded)
- [Host Computer](./host-computer) — validate algorithms before flashing
