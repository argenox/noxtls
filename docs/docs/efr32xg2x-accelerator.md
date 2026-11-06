---
sidebar_position: 11
title: EFR32xG2x Accelerator
description: "NoxTLS documentation: the Silicon Labs EFR32xG2x (EFR32MG26) hardware backend, which algorithms it accelerates, sharing the AES engine and Secure Engine with the BlueNox link layer, and bench validation."
---

# EFR32xG2x accelerator

The EFR32xG2x backend runs AES, SHA-2, entropy and NIST P-256/P-384 operations
on two engines of Silicon Labs Series 2 parts (first target: EFR32MG26B510F3200IM68,
Cortex-M33 at 78 MHz). The drivers are register-level Argenox code in
`noxtls-lib/vendor/silabs/efr32xg2x`. **No Silicon Labs source, header, SDK,
PSA Crypto or `se_manager` is compiled or included**; register maps and command
encodings are Argenox definitions (`noxtls_efr32_regs.h`), cross-checked against the
reference manual and the Zlib-licensed Simplicity SDK 2025.6.3 sources, which were
read only. A target build needs only the Arm GNU toolchain.

| Engine | Peripheral | Used for |
|--------|------------|----------|
| AES (RADIOAES) | BA411E behind a scatter/gather fetcher/pusher DMA | AES-ECB, CBC, CTR, CCM |
| Secure Engine (SEMAILBOX_HOST) | HSE mailbox | TRNG, SHA-256/512 block compression, P-256/P-384 point multiply, ECDH, ECDSA |

## Selecting the backend

| CMake option | Header macro | Effect |
|--------------|--------------|--------|
| `NOXTLS_CFG_FEATURE_EFR32XG2X_HW_ACCEL` | `NOXTLS_FEATURE_EFR32XG2X_HW_ACCEL` | Compiles the drivers and all ports. Needs `NOXTLS_CFG_FEATURE_AES`. `OFF` by default. |

It cannot be combined with another hardware backend (CMake error, and an
`#error` in `noxtls_check_config.h`). Tunables (timeouts, bounce size, secure or
non-secure aliases, minimum SHA blocks, ...) are `NOXTLS_EFR32_CONFIG_*` macros in
`noxtls_efr32_config.h`; pass overrides with `NOXTLS_EFR32_EXTRA_DEFINITIONS`.

```bash
cmake -S noxtls -B build -G Ninja \
  -DCMAKE_SYSTEM_NAME=Generic -DCMAKE_SYSTEM_PROCESSOR=arm \
  -DCMAKE_C_COMPILER=arm-none-eabi-gcc \
  -DCMAKE_C_FLAGS="-mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard" \
  -DNOXTLS_CFG_FEATURE_EFR32XG2X_HW_ACCEL=ON
```

`benchmarks/cortex-m33-efr32xg26` provides start-up code and a linker script
(3200 KB flash, 512 KB SRAM) for size and speed measurements
(`-DNOXTLS_BUILD_SIZE_BENCHMARKS=ON -DNOXTLS_BENCH_TARGET=cortex-m33-efr32xg26`).

## What is accelerated

| Algorithm | Path | Why |
|-----------|------|-----|
| AES-128/256 ECB, CBC, CTR | RADIOAES | The EFR32MG26 BA411E reports modes ECB, CBC, CTR, CCM, CMAC and 128/256-bit keys (`BA411E_HW_CFG_1` reset value `0x05010127`). |
| AES-192 | software | No 192-bit key support in the engine. |
| AES-CCM (4..16 byte tags, 7..13 byte nonces, any AAD up to 70 000 bytes) | RADIOAES, whole record in one job | Native BA411E mode. |
| AES-GCM | software; the CTR keystream blocks and H still use the hardware block hook | The BA411E of this part has no GCM mode, and the CPU does GHASH. A whole-record GCM (hardware CTR + CPU GHASH) is an open item. |
| AES-CMAC, CFB, OFB, XTS | software over the block hook | Not wired to the engine. |
| SHA-224/256, SHA-384/512 | Secure Engine `HASHUPDATE` block compression | Fewer than `NOXTLS_EFR32_CONFIG_SE_HASH_MIN_BLOCKS` (default 2) blocks per call stay in software because a mailbox round trip costs more. SHA-384/512 need the Vault-High feature set (MG26B5xx). |
| SHA-1, SHA-3, MD5 | software | No SE hook. |
| DRBG entropy | Secure Engine TRNG | `noxtls_drbg_entropy_accel_port()`. |
| P-256, P-384 point multiply / ECDH / key generation | Secure Engine `DH` command (returns the full point) | Any other curve uses software. |
| ECDSA P-256/P-384 sign and verify | Secure Engine | Verify: an SE "invalid signature" verdict is final; other errors fall back. Sign: the SE draws the nonce from its TRNG, so signatures are not deterministic (`NOXTLS_EFR32_CONFIG_SE_ECDSA_SIGN=0` keeps software signing). |
| Ed25519 verify | software | The NoxTLS hook passes `SHA-512(R\|\|A\|\|M)`; the SE `EDDSA_VERIFY` hashes the message itself. |
| X25519, X448, RSA, DH, ML-KEM/ML-DSA, ... | software | No hook matches an SE command. |

Any request the hardware cannot take (mode, key size, request larger than
`NOXTLS_EFR32_CONFIG_AES_MAX_REQUEST`, unreachable buffer, busy engine, disabled unit,
SE error) returns `NOXTLS_RETURN_NOT_SUPPORTED` to NoxTLS and is computed in software.
A hardware error after output was written is `NOXTLS_RETURN_FAILED` (the input may have
been overwritten in place). Authentication failures are `NOXTLS_RETURN_BAD_DATA` and no
plaintext is released.

## Sharing the engines with the BlueNox link layer

The BlueNox LL uses RADIOAES for CCM between packets (interrupt context, deadline) and
the SE mailbox for TRNG/P-256. Both sides follow one ownership contract
(`nox-driver-lib/platforms/efr32xg2x/EFR32XG2X_PORT_DESIGN.md`, section 8):

```c
#include "noxtls_efr32_accel.h"

static const noxtls_efr32_engine_lock_t locks = {
    .aes_try_acquire = noxdrv_efr32_radioaes_try_acquire,
    .aes_release     = noxdrv_efr32_radioaes_release,
    .se_try_acquire  = noxdrv_efr32_semailbox_try_acquire,
    .se_release      = noxdrv_efr32_semailbox_release,
};

(void)noxtls_efr32_engine_lock_bind(&locks);   /* once, before the first crypto call */
```

* Each pair is a lock-free, ISR-safe flag that never blocks. Unbound, NoxTLS uses its own
  internal flags (a partial binding keeps the internal flag for the other engine).
* **RADIOAES: noxtls never waits.** One try-acquire; if the engine is owned the request is
  served by software. The lock is held for one whole request (at most about
  `NOXTLS_EFR32_CONFIG_AES_MAX_REQUEST` bytes; larger requests use software), so the LL can
  miss at most one event per collision and reports it as missed per its own policy.
* **Secure Engine: bounded retry.** `NOXTLS_EFR32_CONFIG_SE_ACQUIRE_TRIES` attempts
  `NOXTLS_EFR32_CONFIG_SE_ACQUIRE_SPINS` polls apart, then software. Every wait is a bounded
  poll loop (`NOXTLS_EFR32_CONFIG_SPINS_PER_US`, `*_TIMEOUT_US`).
* A Secure Engine command that does not answer may still be writing into the module's
  buffers. The mailbox is then declared hung (`noxtls_efr32_se_set_hung(1)`) and every
  further SE request goes to software until the application clears it.
* While not owner, the other driver must keep `SEMAILBOX.CONFIGURATION.RXINTEN` cleared,
  otherwise its interrupt consumes NoxTLS responses. NoxTLS polls and never touches the bit.
* NoxTLS leaves the bus clocks it enables (`CMU.CLKEN0.RADIOAES`, `RADIOCLKCTRL.EN`,
  `CLKEN1.SEMAILBOXHOST`) on; they are shared with the other driver.
* TrustZone: build with `NOXTLS_EFR32_CONFIG_NONSECURE=1` for the non-secure aliases of RADIOAES
  and the CMU. The SE mailbox has one alias.
* DMA reach: the engines read flash and SRAM and write SRAM. Caller buffers outside
  (or misaligned when `NOXTLS_EFR32_CONFIG_DMA_ALIGN > 1`) are bounced through
  `NOXTLS_EFR32_CONFIG_BOUNCE_SIZE` byte module buffers when they fit, otherwise software
  serves the request. The module's own descriptors and staging buffers are in `.bss`.

## Self-test and bench validation

`noxtls_efr32_selftest(&result, disable_failed)` runs published vectors through the
hardware drivers (not through software): FIPS 197 C.1/C.3, SP 800-38A F.2.1/F.5.1, SP 800-38C
Example 1, FIPS 180-4 "abc" for SHA-256/512, 2*G on P-256 and a 3*(2G) = 2*(3G) ECDH
agreement, an RFC 6979 A.2.5 ECDSA verify (accept and reject), an ECDSA sign/verify round trip,
and a TRNG sanity check. With `disable_failed` set, a failing operation is switched off and
NoxTLS uses software for it.

Bench steps (board and probe are a later phase; nothing in this backend has run on silicon yet):

1. Read `RADIOAES->INCL_IPS_HW_CFG`, `BA411E_HW_CFG_1/2` and compare with
   `noxtls_efr32_aes_caps()` (expected `modes = 0x127`, `keys = 5`, `ctr_bits = 128`,
   no masking, no hash engine).
2. Call `noxtls_efr32_selftest()`. Items to watch, because they could not be confirmed
   from public sources alone: CBC through the engine (set `noxtls_efr32_aes_set_cbc_native(0)` or
   rely on `disable_failed` if it fails), the exact DH output layout (`x || y`), and SHA-512 /
   P-384 availability on the part.
3. Run a TLS 1.2/1.3 handshake with `NOXTLS_FEATURE_EFR32XG2X_HW_ACCEL` on and off and compare
   time and size with `benchmarks/cortex-m33-efr32xg26`. Tune
   `NOXTLS_EFR32_CONFIG_SE_HASH_MIN_BLOCKS` and `NOXTLS_EFR32_CONFIG_AES_BLOCK_HOOK` from the
   measurements.
4. Run it concurrently with a BlueNox connection to check the ownership contract
   (`noxtls_efr32_stats()` counts `aes_busy` and `se_busy`).

## Tests

`ut/efr32xg2x` is a standalone UTNox suite against a functional register mock. The mock decodes
the descriptors and mailbox messages, checks the wire format, and computes with the NoxTLS
software implementation, so results through the hardware path are compared with the FIPS/NIST
vectors and with software for lengths from 0 to the largest request.

```bash
cmake -S ut/efr32xg2x -B build/efr32_ut -G Ninja -DCMAKE_C_COMPILER=gcc -DENABLE_COVERAGE=ON
cmake --build build/efr32_ut && ctest --test-dir build/efr32_ut --output-on-failure
```
