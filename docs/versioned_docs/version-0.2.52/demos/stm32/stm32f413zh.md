---
sidebar_position: 1
title: STM32F413ZH
description: Run NoxTLS on STM32F413ZH (STM32F4) with Cube HAL, optional CRYP acceleration, and UTNox on-target tests.
keywords:
  - stm32
  - stm32f413
  - stm32f4
  - nucleo
  - demo
  - embedded
---

# STM32F413ZH Demo

The **STM32F413ZH** (STM32F4 family, Cortex-M4) is a common Nucleo and custom-board target. NoxTLS runs as a **library linked into your STM32CubeIDE / CMake firmware**; you provide HAL initialization, entropy, time, and network I/O.

:::info Board coverage
This guide applies to **STM32F413xx** and closely related **STM32F4** parts. Additional STM32 boards will get their own pages under **Demos → STM32** as they are documented.
:::

## What you need

| Item | Notes |
|------|--------|
| Board | NUCLEO-F413ZH or equivalent |
| Toolchain | GNU Arm Embedded (`arm-none-eabi-gcc`) |
| HAL | STM32CubeF4 HAL from ST |
| Programmer | ST-LINK (on-board on Nucleo) |

## Overview

```text
Your firmware
├── STM32Cube HAL / startup / linker script
├── Network stack (lwIP, Ethernet, Wi-Fi module, etc.)
└── NoxTLS (noxtls-lib + optional vendor/stm32 accel)
```

NoxTLS does not ship a full CubeMX project for every board; you add the library to an existing or new Cube project.

## 1. Create or open a Cube project

1. Generate a project for **STM32F413ZHTx** (or your exact part number) in STM32CubeMX / CubeIDE.
2. Enable clocks, UART (for logs), and any Ethernet/Wi-Fi peripheral you use for TLS.
3. Ensure **enough RAM** for TLS buffers and handshake state (start with a minimal TLS 1.3 client profile).

## 2. Add NoxTLS sources

**Option A — CMake subdirectory** (if your firmware uses CMake):

```cmake
add_subdirectory(path/to/noxtls)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE noxtls_tls noxtls_pkc noxtls_common)
```

**Option B — CubeIDE**: Add `noxtls-lib/` sources and include paths manually, mirroring the groups in `noxtls/CMakeLists.txt`.

Set `NOXTLS_OMIT_UT_SOURCES ON` for firmware builds so unit-test-only files are excluded.

## 3. Configure features for MCU flash

Use a constrained profile in `noxtls_config.h` or CMake:

```bash
-D NOXTLS_PROFILE=minimal_tls_client
-D BUILD_APPLICATIONS=OFF
-D BUILD_TESTS=OFF
```

Enable only TLS/DTLS versions and algorithms your product needs. See [Configuration Guide](../../configuration-guide).

## 4. STM32F4 hardware acceleration (optional)

NoxTLS includes STM32 family backends under `noxtls/vendor/st/`:

| Family | Typical use |
|--------|-------------|
| STM32F2 | CRYP/AES via HAL where available |
| STM32F4 | AES block acceleration for F4-class parts |
| STM32F7 / H7 / L4+ | Additional backends as enabled in your build |

For **STM32F413**, define the family macros your build expects (for example `NOXTLS_STM32_FAMILY_F4`) and link the matching `noxtls_stm32f4_accel.c` (and shared `noxtls_stm32_accel.c`) when integrating vendor sources. Include STM32 HAL CRYP/AES headers and enable `HAL_CRYP_MODULE_ENABLED` in `stm32f4xx_hal_conf.h` if you rely on hardware AES.

If acceleration is disabled or HAL is unavailable, NoxTLS falls back to portable C implementations.

## 5. Platform hooks

| Hook | STM32 approach |
|------|----------------|
| **Entropy** | TRNG (`RNG` peripheral) if present on your variant; otherwise seed DRBG from a secure bootloader or hybrid TRNG+CRC |
| **Time** | RTC for certificate validity; or disable time checks only in bring-up builds (`NOXTLS_HAVE_TIME`) |
| **Memory** | Static pools or `malloc` from newlib; avoid fragmentation in long-running TLS sessions |
| **TLS I/O** | Send/receive callbacks on top of lwIP sockets, AT modem TLS offload, or raw Ethernet driver |

See [Porting Guide](../../porting-guide) and [Port NoxTLS to Your Platform](../../start-here/port-to-platform).

## 6. Validate on the board

Suggested bring-up order:

1. **Crypto smoke test** — Run a small self-test (AES-GCM + SHA-256 known answer) on the target before enabling TLS.
2. **TLS client** — Connect to a host HTTPS server using the same flow as [Host Computer](../host-computer) `https_client`, with your socket layer.
3. **DTLS** (if used) — Tune MTU and retransmit for your link; see [DTLS on embedded](../../start-here/dtls-embedded).

### UTNox on-target tests (optional)

The repository **UTNox** driver supports an **stm32f4xx** target profile (GNU Arm + ST-LINK flash). Use it to run registered unit tests over UART/SPI from a host PC:

- Target definition: `utnox/driver/targets.json` → `stm32f4xx`
- Flash via `st-flash` at `0x08000000` per target steps

This is ideal for regression on real silicon without porting the full host `ctest` suite.

## 7. Example integration checklist

- [ ] `noxtls_config.h` matches shipped features (no unused RSA/legacy ciphers)
- [ ] Stack size and heap sized for peak handshake usage
- [ ] Trust store and device cert stored in flash (DER)
- [ ] SNI and hostname verification configured for production servers
- [ ] Debug logging disabled in release builds

## Adding more STM32 boards

New pages under **Demos → STM32** will document other parts (for example F7, H7, L4) with part-specific clock, accelerator, and memory notes. If you need a page for your MCU, use the same structure as this guide: Cube setup → NoxTLS link → config profile → hooks → validation.

## Related guides

- [ESP32](../esp32)
- [Host Computer](../host-computer)
- [Configure Certificates](../../start-here/configure-certificates)
