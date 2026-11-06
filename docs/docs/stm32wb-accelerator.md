---
sidebar_position: 11
title: STM32WB5x Hardware Backend
description: "NoxTLS documentation: the STM32WB55 (P-NUCLEO-WB55) AES1, PKA and RNG backend, its HSEM locking against the CPU2 wireless stack, and the settings an application must provide."
---

# STM32WB5x hardware backend

NoxTLS can run AES, P-256 ECC, ECDSA, modular exponentiation and the DRBG entropy
source on the crypto peripherals of the STM32WB5x (STM32WB50, WB55, WB5M) CPU1
(Cortex-M4F). The code is in `noxtls-lib/vendor/st/stm32wb`. SHA stays in software:
the STM32WB55 has no HASH peripheral.

:::caution Not yet verified on hardware
The backend is checked on the host against a register-level model of the peripherals and
is cross-built for Cortex-M4 hard-float. The hardware verification checklist is in the pull
request that introduced it.
:::

## What is accelerated

| Peripheral | NoxTLS functions | Software path used when |
|------------|------------------|-------------------------|
| AES1 | AES block, ECB, CBC, CTR (128-bit counter), GCM and GMAC, CCM; 128- and 256-bit keys | AES-192, a length the engine cannot take, AES1 busy, or a hardware error |
| PKA | P-256 point multiplication (key generation and ECDH), ECDSA P-256 sign and verify, point-on-curve check, modular exponentiation of odd 8..392 byte moduli | another curve, PKA busy or owned by CPU2, or a hardware error |
| RNG | entropy input of the CTR-DRBG (`NOXTLS_ENTROPY_SOURCE_AUTO`) | RNG owned by CPU2 or unhealthy: the next source is used, never predictable bytes |

A hardware error on a request with separate input and output buffers is answered by the
software implementation. A hardware error on an in-place request is returned as
`NOXTLS_RETURN_FAILED`, because the input is already overwritten.

## Build

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-none-eabi-cortex-m4.cmake \
  -DNOXTLS_CFG_FEATURE_STM32WB_HW_ACCEL=ON \
  "-DCMAKE_C_FLAGS=-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -DSTM32WB55xx"
```

The header macro is `NOXTLS_FEATURE_STM32WB_HW_ACCEL`; Zephyr and ESP-IDF Kconfig expose
`CONFIG_NOXTLS_FEATURE_STM32WB_HW_ACCEL`. The option excludes every other hardware backend
and needs `NOXTLS_FEATURE_AES`. The device define (`STM32WB55xx`, `STM32WB50xx` or
`STM32WB5Mxx`) is recognised by `vendor/st/noxtls_target_detect.h`.

## Settings the application provides

All settings are in `noxtls_stm32wb_config.h` and can be overridden with `-D` options
(`NOXTLS_STM32WB_EXTRA_DEFINITIONS` in CMake).

| Setting | Default | Meaning |
|---------|---------|---------|
| `NOXTLS_STM32WB_CONFIG_HSEM_ID_RNG` | 0 | HSEM semaphore guarding the RNG; must equal `CFG_HW_RNG_SEMID` of the CPU2 firmware |
| `NOXTLS_STM32WB_CONFIG_HSEM_ID_PKA` | 1 | HSEM semaphore guarding the PKA (`CFG_HW_PKA_SEMID`) |
| `NOXTLS_STM32WB_CONFIG_HSEM_ID_AES1` | none | AES1 belongs to CPU1; set a semaphore only if your CPU2 firmware shares it |
| `NOXTLS_STM32WB_CONFIG_*_BASE` | RM0434 memory map | peripheral base addresses |
| `NOXTLS_STM32WB_CONFIG_*_POLL_LIMIT` | see header | status poll budgets (loop iterations) |

The application must also enable the peripheral clocks (RCC `AHB2ENR.AES1EN`,
`AHB3ENR.PKAEN`, `AHB3ENR.RNGEN`, `AHB4ENR.HSEMEN`) and the CLK48 source of the RNG,
taking the RCC semaphore when CPU2 is running, and call `noxtls_stm32wb_bn_register()`
once if RSA, DH or DSA exponentiations should use the PKA.

## Sharing with CPU2

CPU1 takes the HSEM one-step lock before using the PKA or the RNG and releases it
afterwards (RM0434 HSEM chapter, AN5289). A semaphore held by CPU2, or a nested use from
CPU1 itself, makes the request fall back to software instead of waiting. The PKA RAM and
the AES key and IV registers are wiped after every operation.

## RNG health checks

The RNG driver recovers from a seed error by clearing the flag and discarding 12 words
(RM0434 RNG chapter), treats a persistent clock error as a failure, and applies a
continuous test that rejects repeated words. All thresholds are settings in
`noxtls_stm32wb_config.h`; counters are available from `noxtls_stm32wb_rng_health()`.

## Tests

`ut/stm32wb` holds the UTNox host tests with a functional register model. See the header of
`ut/stm32wb/CMakeLists.txt` for the build and coverage commands.
